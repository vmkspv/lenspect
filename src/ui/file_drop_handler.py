# file_drop_handler.py
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

from gi.repository import Gdk, Gtk, Gio, GLib

class FileDropHandler:
    def __init__(self, window):
        self.window = window
        self.setup_drop_target()

    def setup_drop_target(self):
        drop_target = Gtk.DropTarget.new(Gdk.FileList, Gdk.DragAction.COPY)
        drop_target.set_preload(True)
        drop_target.connect("drop", self.on_file_drop)
        drop_target.connect("notify::value", self.on_drop_changed)
        drop_target.connect("notify::current-drop", self.on_drop_changed)

        self.window.add_controller(drop_target)

    def on_drop_changed(self, target, param):
        value = target.get_value()
        file = self.get_drop_file(value)
        if value and not file:
            target.reject()
        self.window.drag_revealer.set_reveal_child(
            bool(target.props.current_drop) and file is not None)

    def on_file_drop(self, drop_target, value, x, y):
        file = self.get_drop_file(value)
        if not file:
            return False

        if self.window.scan_mode == "folder":
            self.window.on_folder_selected(file)
        else:
            self.window.on_file_selected(file)

        if self.window.scan_button.get_sensitive():
            self.window.start_scan()

        return True

    def get_drop_file(self, value):
        files = value.get_files() if value else []
        if files and self.can_accept_drop() and self.validate_file(files[0]):
            return files[0]
        return None

    def can_accept_drop(self):
        return (self.window.navigation_view.get_visible_page() == self.window.main_nav_page and
                self.window.scan_mode != "url")

    def validate_file(self, file):
        if not file or not file.get_path():
            return False
        try:
            info = file.query_info("access::can-read,standard::type",
                                   Gio.FileQueryInfoFlags.NONE, None)
            is_folder = info.get_file_type() == Gio.FileType.DIRECTORY
            return (info.get_attribute_boolean("access::can-read") and
                    is_folder == (self.window.scan_mode == "folder"))
        except GLib.Error:
            return False
