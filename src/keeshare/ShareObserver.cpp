/*
 *  Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ShareObserver.h"
#include "core/AsyncTask.h"
#include "core/Group.h"
#include "crypto/CryptoHash.h"
#include "keeshare/KeeShare.h"
#include "keeshare/ShareExport.h"
#include "keeshare/ShareImport.h"

#include <QDir>
#include <QScopeGuard>
#include <QScopedValueRollback>
#include <QSaveFile>

namespace
{
    QString resolvePath(const QString& path, QSharedPointer<Database> database)
    {
        const QFileInfo info(database->filePath());
        return info.absoluteDir().absoluteFilePath(path);
    }

    struct FileContents
    {
        QByteArray data;
        QByteArray digest;
        QString error;
    };

    // These functions must only run on workers. Even open()/exists() can block for
    // minutes while the operating system tries to reconnect an offline share.
    FileContents readShareFile(const QString& resolvedPath)
    {
        QFile file(resolvedPath);
        if (!file.open(QIODevice::ReadOnly)) {
            return {{}, {}, file.errorString()};
        }
        const auto data = file.readAll();
        if (file.error() != QFileDevice::NoError) {
            return {{}, {}, file.errorString()};
        }
        return {data, CryptoHash::hash(data, CryptoHash::Sha256), {}};
    }

    QString writeShareFile(const QString& path,
                           const QByteArray& data,
                           const QByteArray& expectedDigest,
                           const QSharedPointer<std::atomic_bool>& enabled)
    {
        if (!enabled->load()) {
            return {};
        }
        // Do not overwrite a concurrent remote update while preparing the export.
        const auto current = readShareFile(path);
        if (!enabled->load()) {
            return {};
        }
        if (current.digest != expectedDigest) {
            return ShareObserver::tr("The share changed during export. Retry synchronization.");
        }
        QSaveFile file(path);
        if (!file.open(QIODevice::WriteOnly) || file.write(data) != data.size()) {
            return file.errorString();
        }
        if (!enabled->load()) {
            file.cancelWriting();
            return {};
        }
        if (!file.commit()) {
            return file.errorString();
        }
        return {};
    }

    constexpr int FileWatchPeriod = 30;
} // End Namespace

ShareObserver::ShareObserver(QSharedPointer<Database> db, QObject* parent)
    : QObject(parent)
    , m_db(std::move(db))
{
    connect(this, &ShareObserver::importFinished, this, &ShareObserver::handleImportFinished, Qt::QueuedConnection);
    connect(&m_pollTimer, &QTimer::timeout, this, &ShareObserver::pollShares);
    m_pollTimer.setInterval(FileWatchPeriod * 1000);

    connect(KeeShare::instance(), &KeeShare::activeChanged, this, &ShareObserver::handleDatabaseChanged);

    connect(m_db.data(), &Database::groupDataChanged, this, &ShareObserver::handleDatabaseChanged);
    connect(m_db.data(), &Database::groupAdded, this, &ShareObserver::handleDatabaseChanged);
    connect(m_db.data(), &Database::groupRemoved, this, &ShareObserver::handleDatabaseChanged);

    connect(m_db.data(), &Database::modified, this, &ShareObserver::handleDatabaseChanged);
    connect(m_db.data(), &Database::databaseSaved, this, &ShareObserver::handleDatabaseSaved);

    handleDatabaseChanged();
}

ShareObserver::~ShareObserver()
{
    for (const auto& token : m_exportTokens) {
        token->store(false);
    }
    m_db->disconnect(this);
}

void ShareObserver::setEnabled(bool enabled)
{
    m_enabled = enabled;
    handleDatabaseChanged();
}

void ShareObserver::pollShares()
{
    m_pendingExports.unite(m_retryExports);
    // Import first after reconnecting, before retrying failed exports.
    for (auto it = m_shareToGroup.cbegin(); it != m_shareToGroup.cend(); ++it) {
        if (it.value() && KeeShare::referenceOf(it.value()).isImporting()) {
            m_pendingImports.insert(it.key());
            triggerImport(it.key());
        }
    }
    processPendingExports();
}

void ShareObserver::deinitialize()
{
    for (const auto& token : m_exportTokens) {
        token->store(false);
    }
    m_exportTokens.clear();
    ++m_generation;
    m_pollTimer.stop();
    m_busyPaths.clear();
    m_pendingExports.clear();
    m_retryExports.clear();
    m_pendingImports.clear();
    m_reinitializePending = false;
    m_groupToReference.clear();
    m_shareToGroup.clear();
    m_shareStates.clear();
}

void ShareObserver::reinitialize()
{
    if (m_inReinitialize || m_inImport || m_inExport) {
        m_reinitializePending = true;
        return;
    }
    auto finished = qScopeGuard([this] { emit importFinished(); });
    QScopedValueRollback reinitializeGuard(m_inReinitialize, true);

    QList<QPair<QPointer<Group>, KeeShareSettings::Reference>> shares;
    for (Group* group : m_db->rootGroup()->groupsRecursive(true)) {
        auto oldReference = m_groupToReference.value(group);
        auto newReference = KeeShare::referenceOf(group);
        if (oldReference == newReference) {
            continue;
        }

        const auto oldResolvedPath = resolvePath(oldReference.path, m_db);
        const auto token = m_exportTokens.value(oldResolvedPath);
        if (token) {
            token->store(false);
        }
        m_groupToReference.remove(group);
        m_shareToGroup.remove(oldResolvedPath);
        m_pendingExports.remove(oldResolvedPath);
        m_retryExports.remove(oldResolvedPath);
        m_shareStates.remove(oldResolvedPath);

        if (!newReference.isValid()) {
            continue;
        }
        m_groupToReference[group] = newReference;
        const auto newResolvedPath = resolvePath(newReference.path, m_db);
        m_shareToGroup[newResolvedPath] = group;
        m_shareStates.remove(newResolvedPath);
        shares.append({group, newReference});
    }

    QStringList success;
    QStringList warning;
    QStringList error;
    QMap<QString, QStringList> imported;
    QMap<QString, QStringList> exported;

    for (const auto& share : shares) {
        auto group = share.first;
        auto& reference = share.second;
        // Check group validity, it may have been deleted by a merge action
        if (!group) {
            continue;
        }

        if (reference.isExporting()) {
            exported[reference.path] << group->name();
            // export is only on save
        }

        if (reference.isImporting()) {
            imported[reference.path] << group->name();
            // Queue the initial import without touching the filesystem on the UI thread.
            handleFileUpdated(resolvePath(reference.path, m_db));
        }
    }

    for (auto it = imported.cbegin(); it != imported.cend(); ++it) {
        if (it.value().count() > 1) {
            warning << tr("Multiple import source path to %1 in %2").arg(it.key(), it.value().join(", "));
        }
    }

    for (auto it = exported.cbegin(); it != exported.cend(); ++it) {
        if (it.value().count() > 1) {
            error << tr("Conflicting export target path %1 in %2").arg(it.key(), it.value().join(", "));
        }
    }

    if (!m_shareToGroup.isEmpty() && !m_pollTimer.isActive()) {
        m_pollTimer.start();
    } else if (m_shareToGroup.isEmpty()) {
        m_pollTimer.stop();
    }
    notifyAbout(success, warning, error);
}

void ShareObserver::notifyAbout(const QStringList& success, const QStringList& warning, const QStringList& error)
{
    QStringList messages;
    MessageWidget::MessageType type = MessageWidget::Positive;
    if (!(success.isEmpty() || config()->get(Config::KeeShare_QuietSuccess).toBool())) {
        messages += success;
    }
    if (!warning.isEmpty()) {
        type = MessageWidget::Warning;
        messages += warning;
    }
    if (!error.isEmpty()) {
        type = MessageWidget::Error;
        messages += error;
    }
    if (!messages.isEmpty()) {
        emit sharingMessage(messages.join("\n"), type);
    }
}

void ShareObserver::handleDatabaseChanged()
{
    if (!m_db) {
        Q_ASSERT(m_db);
        return;
    }
    const auto active = KeeShare::active();
    if (!m_enabled || (!active.out && !active.in)) {
        deinitialize();
    } else {
        reinitialize();
    }
}

void ShareObserver::handleImportFinished()
{
    if (m_inImport || m_inExport || m_inReinitialize) {
        return;
    }
    if (m_reinitializePending) {
        m_reinitializePending = false;
        handleDatabaseChanged();
    }
    const auto pendingImports = m_pendingImports;
    for (const auto& path : pendingImports) {
        triggerImport(path);
    }
    processPendingExports();
}

void ShareObserver::handleFileUpdated(QString path)
{
    path = resolvePath(path, m_db);
    if (m_pendingImports.contains(path)) {
        return;
    }
    m_pendingImports.insert(path);
    if (m_inImport || m_inExport || m_inReinitialize) {
        return;
    }
    QTimer::singleShot(100, this, [this, path] { triggerImport(path); });
}

void ShareObserver::triggerImport(const QString& path)
{
    if (!m_pendingImports.remove(path)) {
        return;
    }
    if (m_inImport || m_inExport || m_inReinitialize || m_busyPaths.contains(path)) {
        m_pendingImports.insert(path);
        return;
    }
    if (!m_shareToGroup.value(path)) {
        return;
    }
    importShare(path);
}

void ShareObserver::notifyAbout(const Result& result, bool importing)
{
    if (!result.isValid()) {
        return;
    }
    QStringList success;
    QStringList warning;
    QStringList error;
    if (result.isError()) {
        error << (importing ? tr("Import from %1 failed (%2)") : tr("Export to %1 failed (%2)"))
                     .arg(result.path, result.message);
    } else if (result.isWarning()) {
        warning << (importing ? tr("Import from %1 failed (%2)") : tr("Export to %1 failed (%2)"))
                       .arg(result.path, result.message);
    } else if (result.isInfo()) {
        success << (importing ? tr("Import from %1 successful (%2)") : tr("Export to %1 successful (%2)"))
                       .arg(result.path, result.message);
    } else {
        success << (importing ? tr("Imported from %1") : tr("Export to %1")).arg(result.path);
    }
    notifyAbout(success, warning, error);
}

void ShareObserver::importShare(const QString& path)
{
    if (m_inImport || !KeeShare::active().in) {
        return;
    }
    const auto changePath = resolvePath(path, m_db);
    auto shareGroup = m_shareToGroup.value(changePath);
    if (!shareGroup) {
        qWarning("Group for %s does not exist", qPrintable(path));
        return;
    }
    const auto reference = KeeShare::referenceOf(shareGroup);
    if (reference.type == KeeShareSettings::Inactive) {
        // changes of inactive references are ignored
        return;
    }
    if (reference.type == KeeShareSettings::ExportTo) {
        // changes of export only references are ignored
        return;
    }

    Q_ASSERT(shareGroup->database() == m_db);
    Q_ASSERT(shareGroup == m_db->rootGroup()->findGroupByUuid(shareGroup->uuid()));
    const auto resolvedPath = resolvePath(reference.path, m_db);

    const auto generation = m_generation;
    m_busyPaths.insert(resolvedPath);
    AsyncTask::runThenCallback(
        [resolvedPath] { return readShareFile(resolvedPath); },
        this,
        [this, resolvedPath, reference, shareGroup, generation](const FileContents& contents) {
            if (generation != m_generation) {
                return;
            }
            auto finished = qScopeGuard([this, resolvedPath] {
                m_busyPaths.remove(resolvedPath);
                emit importFinished();
            });
            // A database can be locked or its sharing configuration changed while I/O is pending.
            if (!m_enabled || !KeeShare::active().in || !shareGroup
                || !(KeeShare::referenceOf(shareGroup) == reference)
                || m_shareToGroup.value(resolvedPath) != shareGroup) {
                return;
            }
            if (m_inImport || m_inExport || m_inReinitialize) {
                m_pendingImports.insert(resolvedPath);
                return;
            }
            if (!contents.error.isEmpty()) {
                notifyAbout({reference.path, Result::Error, contents.error}, true);
                return;
            }
            const auto state = m_shareStates.value(resolvedPath);
            if (contents.digest == state.fileDigest && !state.fingerprint.isEmpty()) {
                return;
            }
            QScopedValueRollback importGuard(m_inImport, true);
            auto fingerprint = state.fingerprint;
            const auto result = ShareImport::containerInto(contents.data, reference, shareGroup, &fingerprint);
            rememberFingerprint(resolvedPath, fingerprint, contents.digest);
            notifyAbout(result, true);
        });
}

void ShareObserver::rememberFingerprint(const QString& resolvedPath,
                                        const QByteArray& fingerprint,
                                        const QByteArray& digest)
{
    if (fingerprint.isEmpty() || digest.isEmpty()) {
        m_shareStates.remove(resolvedPath);
        return;
    }
    m_shareStates.insert(resolvedPath, {fingerprint, digest});
}

QSharedPointer<Database> ShareObserver::database()
{
    return m_db;
}

void ShareObserver::handleDatabaseSaved()
{
    if (!m_enabled || !KeeShare::active().out) {
        return;
    }
    for (const auto* group : m_db->rootGroup()->groupsRecursive(true)) {
        const auto reference = KeeShare::referenceOf(group);
        if (reference.isExporting()) {
            m_pendingExports.insert(resolvePath(reference.path, m_db));
        }
    }
    processPendingExports();
}

void ShareObserver::processPendingExports()
{
    if (m_inImport || m_inExport || m_inReinitialize || !m_enabled || !KeeShare::active().out) {
        return;
    }
    const auto pending = m_pendingExports;
    for (const auto& path : pending) {
        if (!m_busyPaths.contains(path) && !m_pendingImports.contains(path)) {
            m_pendingExports.remove(path);
            exportShare(path);
        }
    }
}

void ShareObserver::exportShare(const QString& path)
{
    QPointer<Group> group;
    QStringList groupNames;
    for (auto* candidate : m_db->rootGroup()->groupsRecursive(true)) {
        const auto reference = KeeShare::referenceOf(candidate);
        if (reference.isExporting() && resolvePath(reference.path, m_db) == path) {
            group = candidate;
            groupNames << candidate->name();
        }
    }
    if (!group || groupNames.size() != 1) {
        m_retryExports.remove(path);
        if (group) {
            notifyAbout({path, Result::Error,
                         tr("Conflicting export target path %1 in %2").arg(path, groupNames.join(", "))}, false);
        }
        emit exportFinished();
        return;
    }
    const auto reference = KeeShare::referenceOf(group);
    const auto generation = m_generation;
    const auto enabled = QSharedPointer<std::atomic_bool>::create(true);
    m_exportTokens.insert(path, enabled);
    m_busyPaths.insert(path);
    AsyncTask::runThenCallback(
        [path] { return readShareFile(path); },
        this,
        [this, path, reference, group, generation, enabled](const FileContents& contents) {
            if (generation != m_generation) {
                return;
            }
            bool writing = false;
            auto finished = qScopeGuard([this, path, &writing] {
                if (!writing) {
                    m_busyPaths.remove(path);
                    m_exportTokens.remove(path);
                    emit exportFinished();
                }
                emit importFinished();
            });
            if (!enabled->load() || !m_enabled || !KeeShare::active().out || !group
                || !(KeeShare::referenceOf(group) == reference)) {
                return;
            }
            if (m_inImport || m_inExport || m_inReinitialize) {
                m_pendingExports.insert(path);
                return;
            }
            QScopedValueRollback exportGuard(m_inExport, true);
            const auto state = m_shareStates.value(path);
            auto fingerprint = contents.digest == state.fileDigest ? state.fingerprint : QByteArray();
            QByteArray data;
            // Snapshot/serialize on the database thread; the worker never touches live groups or config.
            const auto result = ShareExport::containerFrom(data, reference, group, &fingerprint);
            if (!result.isValid()) {
                m_retryExports.remove(path);
                return;
            }
            if (result.isError()) {
                notifyAbout(result, false);
                return;
            }
            writing = true;
            const auto digest = CryptoHash::hash(data, CryptoHash::Sha256);
            AsyncTask::runThenCallback(
                [path, data, expectedDigest = contents.digest, enabled] {
                    return writeShareFile(path, data, expectedDigest, enabled);
                },
                this,
                [this, path, reference, group, generation, fingerprint, digest, enabled](const QString& error) {
                    if (generation != m_generation) {
                        return;
                    }
                    auto finished = qScopeGuard([this, path] {
                        m_busyPaths.remove(path);
                        m_exportTokens.remove(path);
                        emit exportFinished();
                        emit importFinished();
                    });
                    if (!enabled->load() || !group || !(KeeShare::referenceOf(group) == reference)) {
                        return;
                    }
                    if (!error.isEmpty()) {
                        m_retryExports.insert(path);
                        notifyAbout({reference.path, Result::Error, error}, false);
                    } else {
                        m_retryExports.remove(path);
                        rememberFingerprint(path, fingerprint, digest);
                        notifyAbout({reference.path}, false);
                    }
                });
        });
}

ShareObserver::Result::Result(const QString& path, ShareObserver::Result::Type type, const QString& message)
    : path(path)
    , type(type)
    , message(message)
{
}

bool ShareObserver::Result::isValid() const
{
    return !path.isEmpty() || !message.isEmpty();
}

bool ShareObserver::Result::isError() const
{
    return !message.isEmpty() && type == Error;
}

bool ShareObserver::Result::isInfo() const
{
    return !message.isEmpty() && type == Info;
}

bool ShareObserver::Result::isWarning() const
{
    return !message.isEmpty() && type == Warning;
}
