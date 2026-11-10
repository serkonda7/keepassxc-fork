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

#include "TestSharing.h"

#include <QTemporaryDir>
#include <QSemaphore>
#include <QSignalSpy>
#include <QTest>
#include <QtConcurrent>
#include <QXmlStreamReader>

#include "core/Config.h"
#include "core/CustomData.h"
#include "core/Database.h"
#include "core/FileWatcher.h"
#include "core/Group.h"
#include "crypto/Crypto.h"
#include "crypto/Random.h"
#include "crypto/kdf/AesKdf.h"
#include "keeshare/KeeShare.h"
#include "keeshare/KeeShareSettings.h"
#include "keeshare/ShareObserver.h"
#include "keys/CompositeKey.h"
#include "keys/PasswordKey.h"
#include "util/TemporaryFile.h"

#include <botan/rsa.h>

QTEST_GUILESS_MAIN(TestSharing)

Q_DECLARE_METATYPE(KeeShareSettings::Type)
Q_DECLARE_METATYPE(KeeShareSettings::Key)
Q_DECLARE_METATYPE(KeeShareSettings::Certificate)

namespace
{
    // Keep file jobs queued to deterministically simulate an unresponsive filesystem,
    // without relying on a real SMB server or the platform's network timeout.
    class BlockFileJobs
    {
    public:
        BlockFileJobs()
            : m_previousMax(QThreadPool::globalInstance()->maxThreadCount())
        {
            QThreadPool::globalInstance()->setMaxThreadCount(1);
            m_future = QtConcurrent::run([this] {
                m_started.release();
                m_release.acquire();
            });
            m_started.acquire();
        }

        ~BlockFileJobs()
        {
            release();
            QThreadPool::globalInstance()->setMaxThreadCount(m_previousMax);
        }

        void release()
        {
            if (!m_future.isFinished()) {
                m_release.release();
                m_future.waitForFinished();
            }
        }

    private:
        int m_previousMax;
        QSemaphore m_started;
        QSemaphore m_release;
        QFuture<void> m_future;
    };

    bool exportDatabase(const QSharedPointer<Database>& db, ShareObserver& observer)
    {
        QSignalSpy finished(&observer, &ShareObserver::exportFinished);
        emit db->databaseSaved();
        return !finished.isEmpty() || finished.wait(10000);
    }
} // namespace

void TestSharing::initTestCase()
{
    QVERIFY(Crypto::init());
    QLocale::setDefault(QLocale::c());
    Config::createConfigFromFile(TemporaryFile::createTempConfigFile(), {});
    KeeShare::init(this);
}

void TestSharing::testNullObjects()
{
    const QString empty;
    QXmlStreamReader reader(empty);

    const auto nullKey = KeeShareSettings::Key();
    QVERIFY(nullKey.isNull());
    const auto xmlKey = KeeShareSettings::Key::deserialize(reader);
    QVERIFY(xmlKey.isNull());

    const auto certificate = KeeShareSettings::Certificate();
    QVERIFY(certificate.isNull());
    const auto xmlCertificate = KeeShareSettings::Certificate::deserialize(reader);
    QVERIFY(xmlCertificate.isNull());

    const auto own = KeeShareSettings::Own();
    QVERIFY(own.isNull());
    const auto xmlOwn = KeeShareSettings::Own::deserialize(empty);
    QVERIFY(xmlOwn.isNull());

    const auto active = KeeShareSettings::Active();
    QVERIFY(active.isNull());
    const auto xmlActive = KeeShareSettings::Active::deserialize(empty);
    QVERIFY(xmlActive.isNull());

    const auto reference = KeeShareSettings::Reference();
    QVERIFY(reference.isNull());
    const auto xmlReference = KeeShareSettings::Reference::deserialize(empty);
    QVERIFY(xmlReference.isNull());
}

void TestSharing::testKeySerialization()
{
    auto key = stubkey();
    KeeShareSettings::Key original;
    original.key = key;

    QString buffer;
    QXmlStreamWriter writer(&buffer);
    writer.writeStartDocument();
    writer.writeStartElement("Key");
    KeeShareSettings::Key::serialize(writer, original);
    writer.writeEndElement();
    writer.writeEndDocument();
    QXmlStreamReader reader(buffer);
    reader.readNextStartElement();
    QVERIFY(reader.name().toString() == "Key");
    KeeShareSettings::Key restored = KeeShareSettings::Key::deserialize(reader);

    QCOMPARE(restored.key->private_key_bits(), original.key->private_key_bits());
    QCOMPARE(restored.key->algo_name(), original.key->algo_name());
}

void TestSharing::testReferenceSerialization()
{
    QFETCH(QString, password);
    QFETCH(QString, path);
    QFETCH(QUuid, uuid);
    QFETCH(int, type);
    KeeShareSettings::Reference original;
    original.password = password;
    original.path = path;
    original.uuid = uuid;
    original.type = static_cast<KeeShareSettings::Type>(type);

    const QString serialized = KeeShareSettings::Reference::serialize(original);
    const KeeShareSettings::Reference restored = KeeShareSettings::Reference::deserialize(serialized);

    QCOMPARE(restored.password, original.password);
    QCOMPARE(restored.path, original.path);
    QCOMPARE(restored.uuid, original.uuid);
    QCOMPARE(int(restored.type), int(original.type));
}

void TestSharing::testReferenceSerialization_data()
{
    QTest::addColumn<QString>("password");
    QTest::addColumn<QString>("path");
    QTest::addColumn<QUuid>("uuid");
    QTest::addColumn<int>("type");
    QTest::newRow("1") << "Password" << "/some/path" << QUuid::createUuid() << int(KeeShareSettings::Inactive);
    QTest::newRow("2") << "" << "" << QUuid() << int(KeeShareSettings::SynchronizeWith);
    QTest::newRow("3") << "" << "/some/path" << QUuid() << int(KeeShareSettings::ExportTo);
}

void TestSharing::testReferenceGroupUuid_data()
{
    QTest::addColumn<QString>("groupElement");
    QTest::addColumn<QUuid>("expectedUuid");

    QTest::newRow("missing") << "" << QUuid();
    QTest::newRow("empty") << "<Group/>" << QUuid();
    QTest::newRow("invalid-base64") << "<Group>!!!</Group>" << QUuid();
    QTest::newRow("wrong-length") << "<Group>YWJj</Group>" << QUuid();
    QTest::newRow("null") << "<Group>AAAAAAAAAAAAAAAAAAAAAA==</Group>" << QUuid();
    const QUuid uuid("{01234567-89ab-cdef-0123-456789abcdef}");
    QTest::newRow("valid") << QString("<Group>%1</Group>").arg(QString::fromLatin1(uuid.toRfc4122().toBase64()))
                           << uuid;
}

void TestSharing::testReferenceGroupUuid()
{
    QFETCH(QString, groupElement);
    QFETCH(QUuid, expectedUuid);

    const QString xml = QString("<KeeShare><Type><Import/></Type>%1"
                                "<Path>c2hhcmUua2RieA==</Path><Password>cG9jLXNoYXJl</Password>"
                                "<KeepGroups>False</KeepGroups></KeeShare>")
                            .arg(groupElement);
    Group group;
    group.customData()->set("KeeShare/Reference", xml.toUtf8().toBase64());
    const auto first = KeeShare::referenceOf(&group);
    const auto second = KeeShare::referenceOf(&group);

    QCOMPARE(first.uuid, expectedUuid);
    QCOMPARE(first.path, QString("share.kdbx"));
    QCOMPARE(first.password, QString("poc-share"));
    QCOMPARE(first.type, KeeShareSettings::Type(KeeShareSettings::ImportFrom));
    QVERIFY(!first.keepGroups);
    QCOMPARE(first.isValid(), !expectedUuid.isNull());
    // Parsing the same reference must not generate a new identity on each scan.
    QVERIFY(first == second);
}

void TestSharing::testReferenceValidity_data()
{
    QTest::addColumn<int>("type");
    QTest::addColumn<QString>("path");
    QTest::addColumn<QUuid>("uuid");
    QTest::addColumn<bool>("valid");

    const auto uuid = QUuid::createUuid();
    QTest::newRow("inactive") << int(KeeShareSettings::Inactive) << "share.kdbx" << uuid << false;
    QTest::newRow("empty-path") << int(KeeShareSettings::ImportFrom) << "" << uuid << false;
    QTest::newRow("null-uuid") << int(KeeShareSettings::ImportFrom) << "share.kdbx" << QUuid() << false;
    QTest::newRow("import") << int(KeeShareSettings::ImportFrom) << "share.kdbx" << uuid << true;
    QTest::newRow("export") << int(KeeShareSettings::ExportTo) << "share.kdbx" << uuid << true;
    QTest::newRow("synchronize") << int(KeeShareSettings::SynchronizeWith) << "share.kdbx" << uuid << true;
}

void TestSharing::testReferenceValidity()
{
    QFETCH(int, type);
    QFETCH(QString, path);
    QFETCH(QUuid, uuid);
    QFETCH(bool, valid);

    KeeShareSettings::Reference reference;
    reference.type = static_cast<KeeShareSettings::Type>(type);
    reference.path = path;
    reference.uuid = uuid;
    QCOMPARE(reference.isValid(), valid);
}

void TestSharing::testObserverRejectsInvalidReference()
{
    auto db = QSharedPointer<Database>::create();
    KeeShareSettings::Reference reference;
    reference.type = KeeShareSettings::ImportFrom;
    reference.path = "share.kdbx";
    reference.uuid = QUuid();
    KeeShare::setReferenceTo(db->rootGroup(), reference);

    KeeShareSettings::Active active;
    active.in = true;
    KeeShare::setActive(active);
    ShareObserver observer(db);
    int messages = 0;
    connect(&observer, &ShareObserver::sharingMessage, this, [&messages] { ++messages; });
    emit db->groupDataChanged(db->rootGroup());
    QCOMPARE(messages, 0);
    QVERIFY(observer.findChildren<FileWatcher*>().isEmpty());
}

void TestSharing::testObserverReinitializeReentry()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    auto db = QSharedPointer<Database>::create();
    db->setFilePath(directory.filePath("outer.kdbx"));

    KeeShareSettings::Active active;
    active.in = true;
    KeeShare::setActive(active);
    ShareObserver observer(db);

    KeeShareSettings::Reference reference;
    reference.type = KeeShareSettings::ImportFrom;
    reference.path = "missing-first.kdbx";
    KeeShare::setReferenceTo(db->rootGroup(), reference);

    int messages = 0;
    connect(&observer, &ShareObserver::sharingMessage, this, [&] {
        if (++messages == 1) {
            // Change the reference so a nested scan would attempt another import.
            reference.path = "missing-second.kdbx";
            KeeShare::setReferenceTo(db->rootGroup(), reference);
            emit db->groupDataChanged(db->rootGroup());
        }
    });

    emit db->groupDataChanged(db->rootGroup());
    QTRY_VERIFY(messages >= 1);
    // Retry the blocked reference change without another notification.
    QTRY_COMPARE(messages, 2);
}

void TestSharing::testObserverDeferredImport()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    Database source;
    auto kdf = QSharedPointer<AesKdf>::create();
    QVERIFY(kdf->setRounds(1));
    source.setKdf(kdf);
    auto key = QSharedPointer<CompositeKey>::create();
    key->addKey(QSharedPointer<PasswordKey>::create("share-password"));
    QVERIFY(source.setKey(key));
    const auto sharePath = directory.filePath("share.kdbx");
    QVERIFY(source.saveAs(sharePath));

    auto db = QSharedPointer<Database>::create();
    KeeShareSettings::Reference reference;
    reference.type = KeeShareSettings::ImportFrom;
    reference.password = "share-password";
    reference.path = sharePath;
    KeeShare::setReferenceTo(db->rootGroup(), reference);
    auto* second = new Group();
    second->setUuid(QUuid::createUuid());
    second->setParent(db->rootGroup());
    reference.uuid = QUuid::createUuid();
    reference.path = directory.filePath("missing.kdbx");
    KeeShare::setReferenceTo(second, reference);
    KeeShareSettings::Active active;
    active.in = true;
    KeeShare::setActive(active);
    ShareObserver observer(db);
    QSignalSpy initialMessages(&observer, &ShareObserver::sharingMessage);
    QTRY_VERIFY(!initialMessages.isEmpty());
    QTRY_VERIFY(observer.findChildren<QFutureWatcherBase*>().isEmpty());

    QPointer<Group> victim = new Group();
    victim->setUuid(QUuid::createUuid());
    victim->setParent(db->rootGroup());
    source.addDeletedObject({victim->uuid(), QDateTime::currentDateTimeUtc().addSecs(1)});
    QVERIFY(source.save());
    QStringList messages;
    connect(&observer, &ShareObserver::sharingMessage, this, [&](const QString& message) { messages << message; });
    connect(victim, &Group::groupAboutToRemove, this, [&] {
        // Another share's update must wait until this merge has finished.
        QVERIFY(QMetaObject::invokeMethod(&observer, "handleFileUpdated", Q_ARG(QString, reference.path)));
        QTest::qWait(150);
        QVERIFY(messages.isEmpty());
    });
    QVERIFY(QMetaObject::invokeMethod(&observer, "handleFileUpdated", Q_ARG(QString, sharePath)));
    QTRY_VERIFY(victim.isNull());
    QTRY_VERIFY(messages.join('\n').contains("missing.kdbx"));
}

void TestSharing::testObserverUnresponsiveShare_data()
{
    QTest::addColumn<bool>("importing");
    QTest::newRow("import") << true;
    QTest::newRow("export") << false;
}

void TestSharing::testObserverUnresponsiveShare()
{
    QFETCH(bool, importing);
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    auto db = QSharedPointer<Database>::create();
    db->setFilePath(directory.filePath("local.kdbx"));
    KeeShareSettings::Reference reference;
    reference.type = importing ? KeeShareSettings::ImportFrom : KeeShareSettings::ExportTo;
    reference.path = directory.filePath("unreachable/share.kdbx");
    KeeShare::setReferenceTo(db->rootGroup(), reference);
    KeeShareSettings::Active active;
    active.in = active.out = true;
    KeeShare::setActive(active);

    BlockFileJobs blocked;
    ShareObserver observer(db);
    QSignalSpy messages(&observer, &ShareObserver::sharingMessage);
    if (!importing) {
        emit db->databaseSaved();
    }
    QTRY_COMPARE(observer.findChildren<QFutureWatcherBase*>().size(), 1);

    // Polls and repeated saves must not enqueue unbounded jobs for the same path.
    for (int i = 0; i < 5; ++i) {
        QVERIFY(QMetaObject::invokeMethod(&observer, "pollShares"));
        emit db->databaseSaved();
    }
    QCOMPARE(observer.findChildren<QFutureWatcherBase*>().size(), 1);
    bool responsive = false;
    QTimer::singleShot(0, this, [&] { responsive = true; });
    QTRY_VERIFY(responsive);
    QVERIFY(messages.isEmpty());

    // Locking/disabling the database invalidates the outstanding result, without waiting for I/O.
    observer.setEnabled(false);
    blocked.release();
    QTRY_VERIFY(observer.findChildren<QFutureWatcherBase*>().isEmpty());
    QVERIFY(messages.isEmpty());
    QVERIFY(!QFile::exists(reference.path));

    // Destroying the observer while a job is queued is safe as well.
    {
        BlockFileJobs blockedAgain;
        auto transient = new ShareObserver(db);
        emit db->databaseSaved();
        QTRY_COMPARE(transient->findChildren<QFutureWatcherBase*>().size(), 1);
        delete transient;
    }
    QThreadPool::globalInstance()->waitForDone();
}

void TestSharing::testObserverRetriesOfflineExport()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    auto db = QSharedPointer<Database>::create();
    db->setFilePath(directory.filePath("local.kdbx"));
    auto* entry = new Entry();
    entry->setUuid(QUuid::createUuid());
    entry->setTitle("Offline edit");
    entry->setGroup(db->rootGroup());
    KeeShareSettings::Reference reference;
    reference.type = KeeShareSettings::SynchronizeWith;
    reference.password = "share-password";
    reference.path = directory.filePath("offline/share.kdbx");
    KeeShare::setReferenceTo(db->rootGroup(), reference);
    KeeShareSettings::Active active;
    active.in = active.out = true;
    KeeShare::setActive(active);
    ShareObserver observer(db);
    QVERIFY(exportDatabase(db, observer));
    QVERIFY(!QFile::exists(reference.path));

    // Simulate reconnecting. No second local save is needed to retry the failed export.
    QVERIFY(QDir(directory.path()).mkdir("offline"));
    QSignalSpy finished(&observer, &ShareObserver::exportFinished);
    QVERIFY(QMetaObject::invokeMethod(&observer, "pollShares"));
    QTRY_VERIFY(!finished.isEmpty());
    QVERIFY(QFile::exists(reference.path));
    Database readBack;
    auto key = QSharedPointer<CompositeKey>::create();
    key->addKey(QSharedPointer<PasswordKey>::create(reference.password));
    QVERIFY(readBack.open(reference.path, key));
    QVERIFY(readBack.rootGroup()->findEntryByUuid(entry->uuid()));
}

void TestSharing::testObserverRetriesOfflineImport()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    auto db = QSharedPointer<Database>::create();
    db->setFilePath(directory.filePath("local.kdbx"));
    KeeShareSettings::Reference reference;
    reference.type = KeeShareSettings::ImportFrom;
    reference.password = "share-password";
    reference.path = directory.filePath("share.kdbx");
    KeeShare::setReferenceTo(db->rootGroup(), reference);
    KeeShareSettings::Active active;
    active.in = true;
    KeeShare::setActive(active);
    ShareObserver observer(db);
    QSignalSpy messages(&observer, &ShareObserver::sharingMessage);
    QTRY_VERIFY(!messages.isEmpty());

    Database source;
    auto key = QSharedPointer<CompositeKey>::create();
    key->addKey(QSharedPointer<PasswordKey>::create(reference.password));
    auto kdf = QSharedPointer<AesKdf>::create();
    QVERIFY(kdf->setRounds(1));
    source.setKdf(kdf);
    QVERIFY(source.setKey(key));
    auto* entry = new Entry();
    entry->setUuid(QUuid::createUuid());
    entry->setTitle("Available again");
    entry->setGroup(source.rootGroup());
    QVERIFY(source.saveAs(reference.path));
    QVERIFY(QMetaObject::invokeMethod(&observer, "pollShares"));
    QTRY_VERIFY(db->rootGroup()->findEntryByUuid(entry->uuid()));
    QCOMPARE(db->rootGroup()->findEntryByUuid(entry->uuid())->title(), entry->title());
}

void TestSharing::testObserverImportsBeforeExport()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    KeeShareSettings::Reference reference;
    reference.type = KeeShareSettings::SynchronizeWith;
    reference.password = "share-password";
    reference.path = directory.filePath("share.kdbx");

    Database source;
    auto key = QSharedPointer<CompositeKey>::create();
    key->addKey(QSharedPointer<PasswordKey>::create(reference.password));
    auto kdf = QSharedPointer<AesKdf>::create();
    QVERIFY(kdf->setRounds(1));
    source.setKdf(kdf);
    QVERIFY(source.setKey(key));
    auto* remote = new Entry();
    remote->setUuid(QUuid::createUuid());
    remote->setTitle("Remote entry");
    remote->setGroup(source.rootGroup());
    QVERIFY(source.saveAs(reference.path));

    auto db = QSharedPointer<Database>::create();
    db->setFilePath(directory.filePath("local.kdbx"));
    auto* local = new Entry();
    local->setUuid(QUuid::createUuid());
    local->setTitle("Local entry");
    local->setGroup(db->rootGroup());
    KeeShare::setReferenceTo(db->rootGroup(), reference);
    KeeShareSettings::Active active;
    active.in = active.out = true;
    KeeShare::setActive(active);
    ShareObserver observer(db);

    // A save immediately after unlocking must not overwrite the not-yet-imported master.
    QVERIFY(exportDatabase(db, observer));
    QVERIFY(db->rootGroup()->findEntryByUuid(remote->uuid()));
    Database readBack;
    QVERIFY(readBack.open(reference.path, key));
    QVERIFY(readBack.rootGroup()->findEntryByUuid(remote->uuid()));
    QVERIFY(readBack.rootGroup()->findEntryByUuid(local->uuid()));
}

void TestSharing::testObserverSkipsUnchangedExport_data()
{
    QTest::addColumn<bool>("keepGroups");
    QTest::addColumn<bool>("outOfScopeReference");
    QTest::newRow("Entries") << false << false;
    QTest::newRow("Subgroups") << true << false;
    QTest::newRow("Reference") << false << true;
}

void TestSharing::testObserverSkipsUnchangedExport()
{
    QFETCH(bool, keepGroups);
    QFETCH(bool, outOfScopeReference);
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    auto db = QSharedPointer<Database>::create();
    db->setFilePath(directory.filePath("outer.kdbx"));

    auto* shared = new Group();
    shared->setUuid(QUuid::createUuid());
    shared->setName("Shared");
    shared->setParent(db->rootGroup());
    auto* entry = new Entry();
    entry->setUuid(QUuid::createUuid());
    entry->setTitle("Original");
    entry->setGroup(shared);

    if (keepGroups) {
        auto* subgroup = new Group();
        subgroup->setUuid(QUuid::createUuid());
        subgroup->setName("Subgroup");
        subgroup->setParent(shared);
        auto* nested = new Entry();
        nested->setUuid(QUuid::createUuid());
        nested->setTitle("Nested");
        nested->setGroup(subgroup);
    }
    Entry* outside = nullptr;
    Entry* referencing = nullptr;
    if (outOfScopeReference) {
        outside = new Entry();
        outside->setUuid(QUuid::createUuid());
        outside->setPassword("outside-password");
        outside->setGroup(db->rootGroup());
        referencing = new Entry();
        referencing->setUuid(QUuid::createUuid());
        referencing->setTitle("Referencing");
        referencing->setPassword(QString("{REF:P@I:%1}").arg(outside->uuidToHex()));
        referencing->setGroup(shared);
    }

    KeeShareSettings::Reference reference;
    reference.keepGroups = keepGroups;
    reference.type = KeeShareSettings::SynchronizeWith;
    reference.password = "share-password";
    reference.path = "share.kdbx";
    KeeShare::setReferenceTo(shared, reference);
    const auto sharePath = directory.filePath(reference.path);

    KeeShareSettings::Active active;
    active.in = true;
    active.out = true;
    KeeShare::setActive(active);
    ShareObserver observer(db);

    const auto readShare = [&] {
        QFile file(sharePath);
        return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
    };

    // First export writes the container
    QVERIFY(exportDatabase(db, observer));
    const auto exported = readShare();
    QVERIFY(!exported.isEmpty());

    // Nothing changed, the container must not be rewritten (a rewrite has fresh IVs and salts).
    // Wait so that timestamps stamped during export would differ in their seconds.
    QTest::qWait(1100);
    QVERIFY(exportDatabase(db, observer));
    QCOMPARE(readShare(), exported);

    // Statistics are not shared content
    entry->setUpdateTimeinfo(false);
    TimeInfo timeInfo = entry->timeInfo();
    timeInfo.setLastAccessTime(timeInfo.lastAccessTime().addSecs(60));
    timeInfo.setUsageCount(timeInfo.usageCount() + 1);
    entry->setTimeInfo(timeInfo);
    entry->setUpdateTimeinfo(true);
    QVERIFY(exportDatabase(db, observer));
    QCOMPARE(readShare(), exported);

    const auto shareKey = QSharedPointer<CompositeKey>::create();
    shareKey->addKey(QSharedPointer<PasswordKey>::create(reference.password));

    // Another client writes the same content with fresh bytes; after importing it there is nothing to export
    {
        Database other;
        QVERIFY(other.open(sharePath, shareKey));
        QVERIFY(other.saveAs(sharePath));
    }
    const auto rewritten = readShare();
    QVERIFY(rewritten != exported);
    QVERIFY(QMetaObject::invokeMethod(&observer, "handleFileUpdated", Q_ARG(QString, sharePath)));
    QTest::qWait(300);
    QVERIFY(exportDatabase(db, observer));
    QCOMPARE(readShare(), rewritten);

    // Local changes are exported
    entry->setTitle("Changed");
    QVERIFY(exportDatabase(db, observer));
    const auto changed = readShare();
    QVERIFY(changed != exported);
    QVERIFY(exportDatabase(db, observer));
    QCOMPARE(readShare(), changed);

    // A container modified behind our back is rewritten even though local content did not change
    QVERIFY(QFile::remove(sharePath));
    {
        QFile file(sharePath);
        QVERIFY(file.open(QIODevice::WriteOnly));
        file.write(exported);
    }
    QVERIFY(exportDatabase(db, observer));
    QVERIFY(readShare() != exported);

    Database readBack;
    QVERIFY(readBack.open(sharePath, shareKey));
    QVERIFY(readBack.rootGroup()->findEntryByUuid(entry->uuid()));
    QCOMPARE(readBack.rootGroup()->findEntryByUuid(entry->uuid())->title(), QString("Changed"));

    // A deleted container is written again
    QVERIFY(QFile::remove(sharePath));
    QVERIFY(exportDatabase(db, observer));
    QVERIFY(QFile::exists(sharePath));

    if (outOfScopeReference) {
        // Resolving the reference is no edit of the referencing entry
        const auto* resolved = readBack.rootGroup()->findEntryByUuid(referencing->uuid());
        QVERIFY(resolved);
        QCOMPARE(resolved->password(), QString("outside-password"));
        QCOMPARE(resolved->historyItems().size(), referencing->historyItems().size());

        // A change of the referenced entry outside the share is exported and carries its modification time
        QTest::qWait(1100);
        outside->setPassword("changed-outside-password");
        const auto beforeChange = readShare();
        QVERIFY(exportDatabase(db, observer));
        QVERIFY(readShare() != beforeChange);
        Database updated;
        QVERIFY(updated.open(sharePath, shareKey));
        resolved = updated.rootGroup()->findEntryByUuid(referencing->uuid());
        QVERIFY(resolved);
        QCOMPARE(resolved->password(), QString("changed-outside-password"));
        QCOMPARE(resolved->timeInfo().lastModificationTime().toSecsSinceEpoch(),
                 outside->timeInfo().lastModificationTime().toSecsSinceEpoch());
        QVERIFY(resolved->timeInfo().lastModificationTime() > referencing->timeInfo().lastModificationTime());

        // ... and is stable afterwards
        const auto afterChange = readShare();
        QTest::qWait(1100);
        QVERIFY(exportDatabase(db, observer));
        QCOMPARE(readShare(), afterChange);
    }
}

void TestSharing::testObserverSkipsUnchangedImport()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());
    auto db = QSharedPointer<Database>::create();
    db->setFilePath(directory.filePath("outer.kdbx"));

    auto* shared = new Group();
    shared->setUuid(QUuid::createUuid());
    shared->setName("Shared");
    shared->setParent(db->rootGroup());
    auto* entry = new Entry();
    entry->setUuid(QUuid::createUuid());
    entry->setTitle("Deleted locally");
    entry->setGroup(shared);
    const auto deletedUuid = entry->uuid();

    KeeShareSettings::Reference reference;
    reference.type = KeeShareSettings::SynchronizeWith;
    reference.password = "share-password";
    reference.path = "share.kdbx";
    KeeShare::setReferenceTo(shared, reference);
    const auto sharePath = directory.filePath(reference.path);
    const auto shareKey = QSharedPointer<CompositeKey>::create();
    shareKey->addKey(QSharedPointer<PasswordKey>::create(reference.password));

    KeeShareSettings::Active active;
    active.in = true;
    active.out = true;
    KeeShare::setActive(active);
    ShareObserver observer(db);
    QVERIFY(exportDatabase(db, observer));
    QVERIFY(QFile::exists(sharePath));

    QStringList messages;
    connect(&observer, &ShareObserver::sharingMessage, this, [&](const QString& message) { messages << message; });
    const auto importNow = [&] {
        QVERIFY(QMetaObject::invokeMethod(&observer, "handleFileUpdated", Q_ARG(QString, sharePath)));
        QTest::qWait(300);
    };

    // Delete the entry locally before the next save; merging the unchanged container would resurrect it
    delete entry;
    QVERIFY(!shared->findEntryByUuid(deletedUuid));

    // Same bytes
    importNow();
    QVERIFY(!shared->findEntryByUuid(deletedUuid));
    QVERIFY(messages.isEmpty());

    // Same content, new bytes
    {
        Database other;
        QVERIFY(other.open(sharePath, shareKey));
        QVERIFY(other.saveAs(sharePath));
    }
    importNow();
    QVERIFY(!shared->findEntryByUuid(deletedUuid));
    QVERIFY(messages.isEmpty());

    // Changed content is merged
    QUuid addedUuid;
    {
        Database other;
        QVERIFY(other.open(sharePath, shareKey));
        auto* added = new Entry();
        added->setUuid(QUuid::createUuid());
        added->setTitle("Added remotely");
        added->setGroup(other.rootGroup());
        addedUuid = added->uuid();
        QVERIFY(other.saveAs(sharePath));
    }
    importNow();
    QVERIFY(shared->findEntryByUuid(addedUuid));
    QCOMPARE(messages.size(), 1);

    // The local deletion is still exported
    QVERIFY(exportDatabase(db, observer));
    Database readBack;
    QVERIFY(readBack.open(sharePath, shareKey));
    QVERIFY(readBack.rootGroup()->findEntryByUuid(addedUuid));
}

void TestSharing::testObserverImportsSignedContainer()
{
    QTemporaryDir directory;
    QVERIFY(directory.isValid());

    KeeShareSettings::Active active;
    active.in = true;
    active.out = true;
    KeeShare::setActive(active);

    KeeShareSettings::Reference reference;
    reference.type = KeeShareSettings::SynchronizeWith;
    reference.password = "share-password";
    reference.path = "share.kdbx.share";
    const auto sharePath = directory.filePath(reference.path);

    // Export a signed container
    auto source = QSharedPointer<Database>::create();
    source->setFilePath(directory.filePath("source.kdbx"));
    auto* sourceShare = new Group();
    sourceShare->setUuid(QUuid::createUuid());
    sourceShare->setName("Shared");
    sourceShare->setParent(source->rootGroup());
    auto* entry = new Entry();
    entry->setUuid(QUuid::createUuid());
    entry->setTitle("Signed");
    entry->setGroup(sourceShare);
    KeeShare::setReferenceTo(sourceShare, reference);
    ShareObserver sourceObserver(source);
    QVERIFY(exportDatabase(source, sourceObserver));
    QVERIFY(QFile::exists(sharePath));

    // A second database imports it: the zip is read from memory
    auto target = QSharedPointer<Database>::create();
    target->setFilePath(directory.filePath("target.kdbx"));
    auto* targetShare = new Group();
    targetShare->setUuid(QUuid::createUuid());
    targetShare->setName("Imported");
    targetShare->setParent(target->rootGroup());
    {
        reference.type = KeeShareSettings::ImportFrom;
        KeeShare::setReferenceTo(targetShare, reference);
        ShareObserver targetObserver(target);
        QTRY_VERIFY(targetShare->findEntryByUuid(entry->uuid()));
        QCOMPARE(targetShare->findEntryByUuid(entry->uuid())->title(), QString("Signed"));
    }

    // A truncated container is reported, not read beyond its end
    QByteArray container;
    {
        QFile file(sharePath);
        QVERIFY(file.open(QIODevice::ReadOnly));
        container = file.readAll();
    }
    QStringList messages;
    for (const auto size : {container.size() / 2, qsizetype(30), qsizetype(4)}) {
        {
            QFile file(sharePath);
            QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
            file.write(container.left(size));
        }
        ShareObserver observer(target);
        messages.clear();
        connect(&observer, &ShareObserver::sharingMessage, this, [&](const QString& message) { messages << message; });
        QVERIFY(QMetaObject::invokeMethod(&observer, "handleFileUpdated", Q_ARG(QString, sharePath)));
        QTRY_VERIFY(!messages.isEmpty());
        QVERIFY(messages.join(QStringLiteral("\n")).contains("failed"));
    }
}

void TestSharing::testSettingsSerialization()
{
    QFETCH(bool, importing);
    QFETCH(bool, exporting);
    QFETCH(KeeShareSettings::Certificate, ownCertificate);
    QFETCH(KeeShareSettings::Key, ownKey);

    KeeShareSettings::Own originalOwn;
    KeeShareSettings::Active originalActive;
    originalActive.in = importing;
    originalActive.out = exporting;
    originalOwn.certificate = ownCertificate;
    originalOwn.key = ownKey;

    const QString serializedActive = KeeShareSettings::Active::serialize(originalActive);
    KeeShareSettings::Active restoredActive = KeeShareSettings::Active::deserialize(serializedActive);

    const QString serializedOwn = KeeShareSettings::Own::serialize(originalOwn);
    KeeShareSettings::Own restoredOwn = KeeShareSettings::Own::deserialize(serializedOwn);

    QCOMPARE(restoredActive.in, importing);
    QCOMPARE(restoredActive.out, exporting);
    if (ownCertificate.key) {
        QCOMPARE(restoredOwn.certificate, ownCertificate);
    }
    if (ownKey.key) {
        QCOMPARE(restoredOwn.key, ownKey);
    }
}

void TestSharing::testSettingsSerialization_data()
{
    auto sshKey0 = stubkey(0);

    KeeShareSettings::Certificate certificate0;
    certificate0.key = sshKey0;
    certificate0.signer = "signer";

    KeeShareSettings::Key key0;
    key0.key = sshKey0;

    QTest::addColumn<bool>("importing");
    QTest::addColumn<bool>("exporting");
    QTest::addColumn<KeeShareSettings::Certificate>("ownCertificate");
    QTest::addColumn<KeeShareSettings::Key>("ownKey");

    QTest::newRow("1") << false << false << KeeShareSettings::Certificate() << KeeShareSettings::Key();
    QTest::newRow("2") << true << false << KeeShareSettings::Certificate() << KeeShareSettings::Key();
    QTest::newRow("3") << true << true << KeeShareSettings::Certificate() << KeeShareSettings::Key();
    QTest::newRow("4") << false << true << certificate0 << key0;
    QTest::newRow("5") << false << false << certificate0 << key0;
}

const QSharedPointer<Botan::RSA_PrivateKey> TestSharing::stubkey(int index)
{
    static QMap<int, QSharedPointer<Botan::RSA_PrivateKey>> keys;
    if (!keys.contains(index)) {
        keys.insert(index,
                    QSharedPointer<Botan::RSA_PrivateKey>(new Botan::RSA_PrivateKey(*randomGen()->getRng(), 2048)));
    }
    return keys[index];
}
