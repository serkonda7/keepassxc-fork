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

#ifndef KEEPASSXC_SHAREFINGERPRINT_H
#define KEEPASSXC_SHAREFINGERPRINT_H

#include <QByteArray>

class Group;

namespace KeeShareSettings
{
    struct Reference;
} // namespace KeeShareSettings

namespace ShareFingerprint
{
    /**
     * Compute a deterministic fingerprint of the content shared through a group.
     *
     * The fingerprint covers the entries of the root group and, if the reference keeps groups,
     * all subgroups. The properties of the root group itself, entry history, access statistics,
     * sub-second time precision, the order of items and the serialization (random IVs, salts)
     * are ignored, so exported content and the same content read back from the container
     * produce the same fingerprint. Fingerprints depend on the host byte order: compare them only within
     * the running process, never persist them.
     */
    QByteArray of(const Group* root, const KeeShareSettings::Reference& reference);
} // namespace ShareFingerprint

#endif // KEEPASSXC_SHAREFINGERPRINT_H
