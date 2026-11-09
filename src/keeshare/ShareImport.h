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
#ifndef KEEPASSXC_SHAREIMPORT_H
#define KEEPASSXC_SHAREIMPORT_H

#include <QCoreApplication>

#include "keeshare/ShareObserver.h"

class ShareImport
{
    Q_DECLARE_TR_FUNCTIONS(ShareImport)
public:
    /**
     * Merge the container at resolvedPath into targetGroup.
     * If fingerprint is given and not empty, it is the content fingerprint (see ShareFingerprint) of what
     * targetGroup last synchronized with this container; if the container holds that same content, the
     * merge is skipped and an invalid result is returned. On return it receives the content fingerprint of
     * the container if the container could be read, or is cleared otherwise.
     */
    static ShareObserver::Result containerInto(const QString& resolvedPath,
                                               const KeeShareSettings::Reference& reference,
                                               Group* targetGroup,
                                               QByteArray* fingerprint = nullptr);

public:
    ShareImport() = delete;
};

#endif // KEEPASSXC_SHAREIMPORT_H
