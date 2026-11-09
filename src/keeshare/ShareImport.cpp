/*
 *  Copyright (C) 2019 KeePassXC Team <team@keepassxc.org>
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
#include "ShareImport.h"
#include "core/Merger.h"
#include "format/KeePass2Reader.h"
#include "keeshare/KeeShare.h"
#include "keeshare/ShareFingerprint.h"
#include "keys/PasswordKey.h"

#include <../minizip/unzip.h>
#include <QBuffer>
#include <QSet>

#include <cstring>

namespace
{
    QByteArray readZipFile(void* uf)
    {
        QByteArray data;
        char buffer[8192];
        unzOpenCurrentFile(uf);
        while (true) {
            int bytes = unzReadCurrentFile(uf, buffer, sizeof(buffer));
            if (bytes <= 0) {
                break;
            }
            data.append(buffer, bytes);
        }
        unzCloseCurrentFile(uf);
        return data;
    }

    // Read-only minizip stream over a container already in memory, so the file is read only once
    struct MemoryStream
    {
        const QByteArray* data;
        ZPOS64_T position;
    };

    voidpf ZCALLBACK memoryOpen(voidpf opaque, const void*, int mode)
    {
        if ((mode & ZLIB_FILEFUNC_MODE_READWRITEFILTER) != ZLIB_FILEFUNC_MODE_READ) {
            return nullptr;
        }
        auto* stream = static_cast<MemoryStream*>(opaque);
        stream->position = 0;
        return stream;
    }

    uLong ZCALLBACK memoryRead(voidpf, voidpf handle, void* buffer, uLong size)
    {
        auto* stream = static_cast<MemoryStream*>(handle);
        const auto total = static_cast<ZPOS64_T>(stream->data->size());
        if (stream->position >= total) {
            return 0;
        }
        const auto count = static_cast<uLong>(qMin<ZPOS64_T>(size, total - stream->position));
        std::memcpy(buffer, stream->data->constData() + stream->position, count);
        stream->position += count;
        return count;
    }

    uLong ZCALLBACK memoryWrite(voidpf, voidpf, const void*, uLong)
    {
        return 0;
    }

    ZPOS64_T ZCALLBACK memoryTell(voidpf, voidpf handle)
    {
        return static_cast<MemoryStream*>(handle)->position;
    }

    long ZCALLBACK memorySeek(voidpf, voidpf handle, ZPOS64_T offset, int origin)
    {
        auto* stream = static_cast<MemoryStream*>(handle);
        const auto total = static_cast<ZPOS64_T>(stream->data->size());
        ZPOS64_T base;
        switch (origin) {
        case ZLIB_FILEFUNC_SEEK_SET:
            base = 0;
            break;
        case ZLIB_FILEFUNC_SEEK_CUR:
            base = stream->position;
            break;
        case ZLIB_FILEFUNC_SEEK_END:
            base = total;
            break;
        default:
            return -1;
        }
        if (offset > total || base > total - offset) {
            return -1;
        }
        stream->position = base + offset;
        return 0;
    }

    int ZCALLBACK memoryClose(voidpf, voidpf)
    {
        return 0;
    }

    int ZCALLBACK memoryError(voidpf, voidpf)
    {
        return 0;
    }

    // Deletions are not part of the content fingerprint (the exporting side pushes the deletions of its whole
    // database, which differ between clients), so a container may only differ by a deletion to apply
    bool hasApplicableDeletions(const Database* sourceDb, const Group* targetGroup)
    {
        const auto& deletedObjects = sourceDb->deletedObjects();
        if (deletedObjects.isEmpty()) {
            return false;
        }
        // The deletions span the exporter's whole database and accumulate over its lifetime, so index the
        // target once instead of searching it for every deletion
        QSet<QUuid> uuids;
        for (const auto* group : targetGroup->groupsRecursive(true)) {
            uuids.insert(group->uuid());
            for (const auto* entry : group->entries()) {
                uuids.insert(entry->uuid());
            }
        }
        for (const auto& object : deletedObjects) {
            if (!object.uuid.isNull() && uuids.contains(object.uuid)) {
                return true;
            }
        }
        return false;
    }
} // namespace

ShareObserver::Result ShareImport::containerInto(const QByteArray& containerData,
                                                 const KeeShareSettings::Reference& reference,
                                                 Group* targetGroup,
                                                 QByteArray* fingerprint)
{
    const QByteArray knownFingerprint = fingerprint ? *fingerprint : QByteArray();
    if (fingerprint) {
        fingerprint->clear();
    }
    QByteArray dbData;

    MemoryStream stream{&containerData, 0};
    zlib_filefunc64_def memoryFunctions{};
    memoryFunctions.zopen64_file = memoryOpen;
    memoryFunctions.zread_file = memoryRead;
    memoryFunctions.zwrite_file = memoryWrite;
    memoryFunctions.ztell64_file = memoryTell;
    memoryFunctions.zseek64_file = memorySeek;
    memoryFunctions.zclose_file = memoryClose;
    memoryFunctions.zerror_file = memoryError;
    memoryFunctions.opaque = &stream;

    auto uf = unzOpen2_64(&stream, &memoryFunctions);
    if (uf) {
        // Open zip share, extract database portion, ignore signature file
        char zipFileName[256];
        auto err = unzGoToFirstFile(uf);
        while (err == UNZ_OK) {
            unzGetCurrentFileInfo64(uf, nullptr, zipFileName, sizeof(zipFileName), nullptr, 0, nullptr, 0);
            if (QString(zipFileName).compare(KeeShare::containerFileName()) == 0) {
                dbData = readZipFile(uf);
            }
            err = unzGoToNextFile(uf);
        }
        unzClose(uf);
    } else {
        // Plain KDBX file
        dbData = containerData;
    }

    QBuffer buffer(&dbData);
    buffer.open(QIODevice::ReadOnly);

    KeePass2Reader reader;
    auto key = QSharedPointer<CompositeKey>::create();
    key->addKey(QSharedPointer<PasswordKey>::create(reference.password));
    auto sourceDb = QSharedPointer<Database>::create();
    sourceDb->setEmitModified(false);
    if (!reader.readDatabase(&buffer, key, sourceDb.data())) {
        qCritical("Error while parsing the database: %s", qPrintable(reader.errorString()));
        return {reference.path, ShareObserver::Result::Error, reader.errorString()};
    }
    sourceDb->setEmitModified(true);
    const auto contentFingerprint = ShareFingerprint::of(sourceDb->rootGroup(), reference);
    if (fingerprint) {
        *fingerprint = contentFingerprint;
    }
    if (!knownFingerprint.isEmpty() && knownFingerprint == contentFingerprint
        && !hasApplicableDeletions(sourceDb.data(), targetGroup)) {
        // Same content in new bytes (e.g. re-encrypted by another client): already synchronized. Merging again
        // could at best change nothing and at worst resurrect entries deleted locally since.
        return {};
    }

    qDebug("Synchronize %s %s with %s",
           qPrintable(reference.path),
           qPrintable(targetGroup->name()),
           qPrintable(sourceDb->rootGroup()->name()));

    Merger merger(sourceDb->rootGroup(), targetGroup);
    merger.setForcedMergeMode(Group::Synchronize);
    merger.setSkipDatabaseCustomData(true);
    auto changelist = merger.merge();
    if (!changelist.isEmpty()) {
        return {reference.path, ShareObserver::Result::Success, ShareImport::tr("Successful import")};
    }

    return {};
}
