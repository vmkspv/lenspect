# config_manager.py
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

from json import loads, dumps
from gi.repository import Gio, GLib
from .secret_manager import SecretManager

class ConfigManager:
    def __init__(self):
        self.config_dir = GLib.build_filenamev([GLib.get_user_config_dir(), "lenspect"])
        config_gfile = Gio.File.new_for_path(self.config_dir)
        if not config_gfile.query_exists(None):
            config_gfile.make_directory_with_parents(None)
        self.api_key_file = Gio.File.new_for_path(
            GLib.build_filenamev([self.config_dir, "api_key"]))
        self.secret_manager = SecretManager()

    def load_api_key(self):
        api_key = self.secret_manager.load_api_key()
        if api_key:
            return api_key

        try:
            if self.api_key_file.query_exists(None):
                success, contents, _ = self.api_key_file.load_contents(None)
                if success:
                    api_key = contents.decode("utf-8").strip()
                    if api_key and self.secret_manager.store_api_key(api_key):
                        self.api_key_file.delete(None)
                    return api_key
        except GLib.Error:
            pass
        return None

    def save_api_key(self, api_key):
        if api_key is None:
            return

        api_key = api_key.strip()

        if not api_key:
            self.secret_manager.delete_api_key()
            try:
                self.api_key_file.delete(None)
            except GLib.Error:
                pass
            return

        if self.secret_manager.store_api_key(api_key):
            try:
                self.api_key_file.delete(None)
            except GLib.Error:
                pass
        else:
            try:
                self.api_key_file.replace_contents(
                    api_key.encode("utf-8"), None, False,
                    Gio.FileCreateFlags.PRIVATE, None)
            except GLib.Error:
                pass

    def get_history_file(self, history_type: str):
        return Gio.File.new_for_path(
            GLib.build_filenamev([self.config_dir, f"{history_type}_history.json"]))

    def load_history(self, history_type: str):
        gfile = self.get_history_file(history_type)
        try:
            if gfile.query_exists(None):
                success, contents, _ = gfile.load_contents(None)
                if success:
                    return loads(contents.decode("utf-8"))
        except (GLib.Error, ValueError):
            pass
        return []

    def save_history(self, history_type: str, history_data):
        try:
            gfile = self.get_history_file(history_type)
            data = dumps(history_data, indent=2, ensure_ascii=False).encode("utf-8")
            gfile.replace_contents(data, None, False, Gio.FileCreateFlags.NONE, None)
        except GLib.Error:
            pass

    def add_to_history(self, history_type: str, history_data, **item_data):
        timestamp = GLib.DateTime.new_now_local().format("%Y-%m-%d %H:%M:%S")
        new_item = {"timestamp": timestamp, **item_data}

        unique_key = "file_hash" if history_type == "file" else "url"

        unique_value = new_item[unique_key]
        history_data[:] = [item for item in history_data
                          if item[unique_key] != unique_value]

        history_data.insert(0, new_item)
        history_data[:] = history_data[:25]
        self.save_history(history_type, history_data)

    def check_search_provider(self, file_history, url_history):
        for history_type, history_data in [("file", file_history), ("url", url_history)]:
            for item in history_data:
                if item.get("selected", False):
                    item["selected"] = False
                    self.save_history(history_type, history_data)
                    return (history_type, item)
        return None
