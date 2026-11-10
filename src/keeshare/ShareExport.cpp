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

#include "ShareExport.h"
#include "core/EntryPlaceholders.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "crypto/Random.h"
#include "format/KeePass2Writer.h"
#include "gui/Icons.h"
#include "gui/MessageBox.h"
#include "keeshare/KeeShare.h"
#include "keeshare/ShareFingerprint.h"
#include "keys/PasswordKey.h"

#include <../minizip/zip.h>
#include <QBuffer>
#include <QTemporaryFile>
#include <botan/pubkey.h>

// Compatibility with minizip-ng
#ifdef MZ_VERSION_BUILD
#undef Z_BEST_COMPRESSION
#define Z_BEST_COMPRESSION MZ_COMPRESS_LEVEL_BEST
#define zipOpenNewFileInZip64 zipOpenNewFileInZip_64
#endif

// The export must be deterministic: extracting unchanged content twice has to produce identical
// timestamps. Otherwise every export looks like a modification to the importing side, which merges
// it, saves and exports again, and the databases sharing the container never settle. Therefore all
// objects of the export database are built with timeinfo updates disabled and are never re-enabled
// (the export database is written once and discarded).
namespace
{
    void resolveReferenceAttributes(Entry* targetEntry, const Database* sourceDb)
    {
        Q_ASSERT(!targetEntry->canUpdateTimeinfo());
        const auto* sourceReference = sourceDb->rootGroup()->findEntryByUuid(targetEntry->uuid());
        if (!sourceReference) {
            return;
        }
        auto timeInfo = targetEntry->timeInfo();
        for (const auto& attribute : EntryAttributes::DefaultAttributes) {
            const auto standardValue = targetEntry->attributes()->value(attribute);
            const auto type = EntryPlaceholders::placeholderType(standardValue);
            if (type != EntryPlaceholders::PlaceholderType::Reference) {
                // No reference to resolve
                continue;
            }
            const auto* referencedTargetEntry = targetEntry->resolveReference(standardValue);
            if (referencedTargetEntry) {
                // References is within scope, no resolving needed
                continue;
            }
            // We could do more sophisticated **** trying to point the reference to the next in-scope reference
            // but those cases with high probability constructed examples and very rare in real usage
            const auto resolvedValue = sourceReference->resolveMultiplePlaceholders(standardValue);
            // Resolving is not an edit: no history item and no "now" timestamp. The resolved value changes only
            // when the referenced entry does, so the exported entry is as recent as the newer of both.
            // That keeps the export stable while still letting importers pick up a changed referenced value.
            const auto* referencedEntry = sourceReference->resolveReference(standardValue);
            if (referencedEntry
                && referencedEntry->timeInfo().lastModificationTime() > timeInfo.lastModificationTime()) {
                timeInfo.setLastModificationTime(referencedEntry->timeInfo().lastModificationTime());
            }
            targetEntry->attributes()->set(attribute, resolvedValue, targetEntry->attributes()->isProtected(attribute));
        }
        targetEntry->setTimeInfo(timeInfo);
    }

    void cloneIcon(Metadata* targetMetadata, const Database* sourceDb, const QUuid& iconUuid)
    {
        if (!iconUuid.isNull() && !targetMetadata->hasCustomIcon(iconUuid)) {
            targetMetadata->addCustomIcon(iconUuid, sourceDb->metadata()->customIcon(iconUuid));
        }
    }

    void cloneEntries(Metadata* targetMetadata, const Group* sourceGroup, Group* targetGroup)
    {
        for (const Entry* sourceEntry : sourceGroup->entries()) {
            auto* targetEntry = sourceEntry->clone(Entry::CloneIncludeHistory);
            targetEntry->setUpdateTimeinfo(false);
            targetEntry->setGroup(targetGroup);
            cloneIcon(targetMetadata, sourceEntry->database(), targetEntry->iconUuid());
        }
    }

    void cloneChildren(Metadata* targetMetadata, const Group* sourceRoot, Group* targetRoot)
    {
        for (const Group* sourceGroup : sourceRoot->children()) {
            auto* targetGroup = sourceGroup->clone(Entry::CloneNoFlags, Group::CloneNoFlags);
            // Stays disabled: adding entries and subgroups below must not stamp the group
            targetGroup->setUpdateTimeinfo(false);
            targetGroup->setParent(targetRoot);
            cloneIcon(targetMetadata, sourceRoot->database(), targetGroup->iconUuid());
            cloneEntries(targetMetadata, sourceGroup, targetGroup);
            cloneChildren(targetMetadata, sourceGroup, targetGroup);
        }
    }

    Database* extractIntoDatabase(const KeeShareSettings::Reference& reference, const Group* sourceRoot)
    {
        const auto* sourceDb = sourceRoot->database();
        auto* targetDb = new Database();
        auto* targetMetadata = targetDb->metadata();
        targetMetadata->setRecycleBinEnabled(false);

        // Copy the source root as the root of the export database, memory manage the old root node
        auto* targetRoot = sourceRoot->clone(Entry::CloneNoFlags, Group::CloneNoFlags);
        targetRoot->setUpdateTimeinfo(false);
        KeeShare::setReferenceTo(targetRoot, KeeShareSettings::Reference());
        cloneIcon(targetMetadata, sourceRoot->database(), targetRoot->iconUuid());
        cloneEntries(targetMetadata, sourceRoot, targetRoot);
        if (reference.keepGroups) {
            cloneChildren(targetMetadata, sourceRoot, targetRoot);
        }

        auto key = QSharedPointer<CompositeKey>::create();
        key->addKey(QSharedPointer<PasswordKey>::create(reference.password));
        targetDb->setKey(key);

        auto obsoleteRoot = targetDb->setRootGroup(targetRoot);
        delete obsoleteRoot;

        targetDb->metadata()->setName(sourceRoot->name());

        // Push all deletions of the source database to the target
        // simple moving out of a share group will not trigger a deletion in the
        // target - a more elaborate mechanism may need the use of another custom
        // attribute to share unshared entries from the target db
        for (const auto& object : sourceDb->deletedObjects()) {
            targetDb->addDeletedObject(object);
        }
        for (auto* targetEntry : targetRoot->entriesRecursive(false)) {
            if (targetEntry->hasReferences()) {
                resolveReferenceAttributes(targetEntry, sourceDb);
            }
        }
        return targetDb;
    }

    bool writeZipFile(void* zf, const QString& fileName, const QByteArray& data)
    {
        zipOpenNewFileInZip64(zf,
                              fileName.toLatin1().data(),
                              nullptr,
                              nullptr,
                              0,
                              nullptr,
                              0,
                              nullptr,
                              Z_DEFLATED,
                              Z_BEST_COMPRESSION,
                              1);
        int pos = 0;
        do {
            auto len = qMin(data.size() - pos, 8192);
            zipWriteInFileInZip(zf, data.data() + pos, len);
            pos += len;
        } while (pos < data.size());

        zipCloseFileInZip(zf);
        return true;
    }

    bool signData(const QByteArray& data, const KeeShareSettings::Key& key, QString& signature)
    {
        if (key.key->algo_name() == "RSA") {
            try {
                Botan::PK_Signer signer(*key.key, *randomGen()->getRng(), "EMSA3(SHA-256)");
                signer.update(reinterpret_cast<const uint8_t*>(data.constData()), data.size());
                auto s = signer.signature(*randomGen()->getRng());

                auto hex = QByteArray(reinterpret_cast<char*>(s.data()), s.size()).toHex();
                signature = QString("rsa|%1").arg(QString::fromLatin1(hex));
                return true;
            } catch (std::exception& e) {
                qWarning("KeeShare: Failed to sign data: %s", e.what());
                return false;
            }
        }
        qWarning("Unsupported Public/Private key format");
        return false;
    }
} // namespace

ShareObserver::Result ShareExport::containerFrom(QByteArray& containerData,
                                                 const KeeShareSettings::Reference& reference,
                                                 const Group* group,
                                                 QByteArray* fingerprint)
{
    containerData.clear();
    QScopedPointer<Database> targetDb(extractIntoDatabase(reference, group));
    // Fingerprint the extracted content so resolved references are covered as they are written
    const auto contentFingerprint = ShareFingerprint::of(targetDb->rootGroup(), reference);
    if (fingerprint && !fingerprint->isEmpty() && *fingerprint == contentFingerprint) {
        // The container already holds this content, writing it again would only trigger other observers
        return {};
    }
    if (reference.path.endsWith(".kdbx.share")) {
        // Write database to memory and sign it
        QByteArray dbData, signatureData;
        QBuffer buffer;

        buffer.setBuffer(&dbData);
        buffer.open(QIODevice::WriteOnly);

        KeePass2Writer writer;
        if (!writer.writeDatabase(&buffer, targetDb.data())) {
            qWarning("Serializing export database failed: %s.", writer.errorString().toLatin1().data());
            return {reference.path, ShareObserver::Result::Error, writer.errorString()};
        }

        buffer.close();

        // Get Own Certificate for signing
        const auto own = KeeShare::own();
        Q_ASSERT(!own.isNull());

        // Sign the database data
        KeeShareSettings::Sign sign;
        sign.certificate = own.certificate;
        signData(dbData, own.key, sign.signature);

        signatureData = KeeShareSettings::Sign::serialize(sign).toLatin1();

        // minizip requires a filename. Stage the signed container locally, never on the share.
        QTemporaryFile container;
        if (!container.open()) {
            return {reference.path, ShareObserver::Result::Error, container.errorString()};
        }
        const auto containerPath = container.fileName();
        container.close();
        auto zf = zipOpen64(QFile::encodeName(containerPath).constData(), 0);
        if (!zf) {
            return {reference.path, ShareObserver::Result::Error, ShareExport::tr("Could not write export container.")};
        }

        writeZipFile(zf, KeeShare::signatureFileName().toLatin1().data(), signatureData);
        writeZipFile(zf, KeeShare::containerFileName().toLatin1().data(), dbData);

        zipClose(zf, nullptr);
        if (!container.open()) {
            return {reference.path, ShareObserver::Result::Error, container.errorString()};
        }
        containerData = container.readAll();
        if (container.error() != QFileDevice::NoError) {
            return {reference.path, ShareObserver::Result::Error, container.errorString()};
        }
    } else {
        QBuffer buffer(&containerData);
        buffer.open(QIODevice::WriteOnly);
        KeePass2Writer writer;
        if (!writer.writeDatabase(&buffer, targetDb.data())) {
            return {reference.path, ShareObserver::Result::Error, writer.errorString()};
        }
    }

    if (fingerprint) {
        *fingerprint = contentFingerprint;
    }
    return {reference.path};
}
