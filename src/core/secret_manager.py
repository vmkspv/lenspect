# secret_manager.py
#
# Copyright 2025 Vladimir Kosolapov
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import gi

gi.require_version('Secret', '1')

from gi.repository import Secret

class SecretManager:
    SCHEMA = Secret.Schema.new(
        "io.github.vmkspv.lenspect",
        Secret.SchemaFlags.NONE,
        {
            "application": Secret.SchemaAttributeType.STRING,
            "key-type": Secret.SchemaAttributeType.STRING,
        }
    )

    def __init__(self):
        self.application_id = "io.github.vmkspv.lenspect"

    def store_api_key(self, api_key: str) -> bool:
        if not api_key or not api_key.strip():
            return False

        try:
            Secret.password_store_sync(
                self.SCHEMA,
                {
                    "application": self.application_id,
                    "key-type": "api-key",
                },
                Secret.COLLECTION_DEFAULT,
                "VirusTotal API Key",
                api_key.strip(),
                None
            )
            return True
        except Exception:
            return False

    def load_api_key(self) -> str | None:
        try:
            password = Secret.password_lookup_sync(
                self.SCHEMA,
                {
                    "application": self.application_id,
                    "key-type": "api-key",
                },
                None
            )
            return password if password else None
        except Exception:
            return None

    def delete_api_key(self) -> bool:
        try:
            Secret.password_clear_sync(
                self.SCHEMA,
                {
                    "application": self.application_id,
                    "key-type": "api-key",
                },
                None
            )
            return True
        except Exception:
            return False
