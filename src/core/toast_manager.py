# toast_manager.py
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

from gi.repository import Gio

class ToastManager:
    def __init__(self, application):
        self.application = application

    def send_scan_complete(self, is_clean: bool, threat_count: int = 0):
        if not self.application:
            return

        notification = Gio.Notification.new(_('Scan Complete'))

        if is_clean:
            body = _('No threats detected')
            icon = "security-high-symbolic"
            priority = Gio.NotificationPriority.NORMAL
        else:
            body = _('{} threat(s) detected').format(threat_count)
            icon = "security-low-symbolic"
            priority = Gio.NotificationPriority.HIGH

        notification.set_body(body)
        notification.set_icon(Gio.ThemedIcon.new(icon))
        notification.set_priority(priority)
        notification.add_button(_('View Report'), 'app.present')

        self.application.send_notification("scan-complete", notification)

    def send_scan_failed(self):
        if not self.application:
            return

        notification = Gio.Notification.new(_('Scan Failed'))
        notification.set_body(_('An error occurred during scanning'))
        notification.set_icon(Gio.ThemedIcon.new("dialog-error-symbolic"))
        notification.set_priority(Gio.NotificationPriority.NORMAL)

        self.application.send_notification("scan-failed", notification)

    def withdraw_all(self):
        if not self.application:
            return

        self.application.withdraw_notification("scan-complete")
        self.application.withdraw_notification("scan-failed")
