# main.py
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

import sys
import locale
import gi

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

from gi.repository import Adw, Gtk, Gio
from .window import LenspectWindow

translators = {
    'ru': 'Vladimir Kosolapov https://github.com/vmkspv',
    'uk': 'Vladimir Kosolapov https://github.com/vmkspv'
}

class LenspectApplication(Adw.Application):
    def __init__(self, version):
        super().__init__(application_id='io.github.vmkspv.lenspect',
                        flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.create_action("quit", lambda *_: self.quit(), ['<primary>q'])
        self.create_action("close-window", self.on_close_window_action, ['<primary>w'])
        self.create_action("new-window", self.on_new_window_action, ['<primary>n'])
        self.create_action("about", self.on_about_action)
        self.version = version

    def do_activate(self):
        self.new_window()

    def new_window(self):
        win = LenspectWindow(application=self)
        win.present()

    def on_new_window_action(self, *args):
        self.new_window()

    def get_translator_credits(self):
        locale_code = locale.getlocale()[0] or ''
        return translators.get(locale_code) or translators.get(locale_code[:2], '')

    def on_about_action(self, widget, param):
        about = Adw.AboutDialog.new_from_appdata('io/github/vmkspv/lenspect/metainfo.xml', self.version)
        about.set_developers(['Vladimir Kosolapov https://github.com/vmkspv'])
        about.set_translator_credits(self.get_translator_credits())
        about.set_copyright('© 2025 Vladimir Kosolapov')
        about.add_legal_section(
            title=_('VirusTotal API Service'),
            copyright=None,
            license_type=Gtk.License.CUSTOM,
            license=_('By using this application, you are agreeing to VirusTotal\'s '
                      '<a href=\"https://cloud.google.com/terms\">Terms of Service</a> '
                      'and <a href=\"https://cloud.google.com/terms/secops/privacy-notice\">'
                      'Privacy Notice</a>, and to the <b>sharing of your Sample submission '
                      'with the security community</b>.')
        )
        about.present(self.props.active_window)

    def on_close_window_action(self, *args):
        self.props.active_window.close()

    def create_action(self, name, callback, shortcuts=None):
        action = Gio.SimpleAction.new(name, None)
        action.connect("activate", callback)
        self.add_action(action)
        if shortcuts:
            self.set_accels_for_action(f"app.{name}", shortcuts)

def main(version):
    app = LenspectApplication(version)
    return app.run(sys.argv)
