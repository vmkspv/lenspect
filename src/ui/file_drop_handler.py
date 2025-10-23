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

from os import access, R_OK
from os.path import exists

from gi.repository import Gtk, Gdk

class FileDropHandler:
    def __init__(self, window):
        self.window = window
        self.setup_drop_target()

    def setup_drop_target(self):
        drop_target = Gtk.DropTarget.new(Gdk.FileList, Gdk.DragAction.COPY)
        drop_target.connect("drop", self.on_file_drop)

        drop_target.connect(
            "notify::current-drop",
            lambda target, _: self.window.drag_revealer.set_reveal_child(
                bool(target.props.current_drop) and self.can_accept_drop()
            )
        )

        self.window.add_controller(drop_target)

    def on_file_drop(self, drop_target, value, x, y):
        if not self.can_accept_drop():
            return False

        files = value.get_files()
        if not files:
            return False

        file = files[0]
        if self.validate_file(file):
            self.window.selected_file = file
            self.window.show_api_key_warning()
            self.window.update_ui_state()

            if self.window.scan_button.get_sensitive():
                self.window.start_scan()

            return True

        return False

    def can_accept_drop(self):
        return (self.window.is_file_mode and
                self.window.view_stack.get_visible_child_name() == "main")

    def validate_file(self, file):
        if not file:
            return False

        file_path = file.get_path()
        if not file_path:
            return False

        return exists(file_path) and access(file_path, R_OK)
