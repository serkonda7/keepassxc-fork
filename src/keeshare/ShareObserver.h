/*
 *  Copyright (C) 2018 KeePassXC Team <team@keepassxc.org>
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

#ifndef KEEPASSXC_SHAREOBSERVER_H
#define KEEPASSXC_SHAREOBSERVER_H

#include <QHash>
#include <QMap>
#include <QObject>
#include <QSet>
#include <QTimer>
#include <atomic>

#include "gui/MessageWidget.h"
#include "keeshare/KeeShareSettings.h"

class Group;
class Database;

class ShareObserver : public QObject
{
    Q_OBJECT

public:
    explicit ShareObserver(QSharedPointer<Database> db, QObject* parent = nullptr);
    ~ShareObserver();

    QSharedPointer<Database> database();
    void setEnabled(bool enabled);

    struct Result
    {
        enum Type
        {
            Success,
            Info,
            Warning,
            Error
        };

        QString path;
        Type type;
        QString message;

        Result(const QString& path = QString(), Type type = Success, const QString& message = QString());

        bool isValid() const;
        bool isError() const;
        bool isWarning() const;
        bool isInfo() const;
    };

signals:
    void importFinished();
    void exportFinished();
    void sharingMessage(QString, MessageWidget::MessageType);

private slots:
    void handleDatabaseChanged();
    void handleDatabaseSaved();
    void handleImportFinished();
    void handleFileUpdated(QString path);
    void pollShares();

private:
    void triggerImport(const QString& path);
    void importShare(const QString& path);
    void exportShare(const QString& path);
    void processPendingExports();
    void notifyAbout(const Result& result, bool importing);

    void deinitialize();
    void reinitialize();
    void notifyAbout(const QStringList& success, const QStringList& warning, const QStringList& error);

    void rememberFingerprint(const QString& resolvedPath, const QByteArray& fingerprint, const QByteArray& digest);

private:
    QSharedPointer<Database> m_db;
    QMap<QPointer<Group>, KeeShareSettings::Reference> m_groupToReference;
    QMap<QString, QPointer<Group>> m_shareToGroup;
    QTimer m_pollTimer;
    QSet<QString> m_busyPaths;
    QSet<QString> m_pendingImports;
    QSet<QString> m_pendingExports;
    QSet<QString> m_retryExports;
    QHash<QString, QSharedPointer<std::atomic_bool>> m_exportTokens;
    quint64 m_generation = 0;

    // Content last imported from or exported to a share file, keyed by resolved path
    struct ShareState
    {
        QByteArray fingerprint; // see ShareFingerprint
        QByteArray fileDigest; // digest of the file bytes the fingerprint belongs to
    };
    QHash<QString, ShareState> m_shareStates;
    bool m_reinitializePending = false;
    bool m_inReinitialize = false;
    bool m_inImport = false;
    bool m_inExport = false;
    bool m_enabled = true;
};

#endif // KEEPASSXC_SHAREOBSERVER_H
