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

import locale
import sys
import gi

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

from gi.repository import Adw, Gtk, Gio
from .window import LenspectWindow

translators = {
    'bg': 'twlvnn kraftwerk https://github.com/twlvnn',
    'es': 'haggen88 https://github.com/haggen88',
    'he': 'Omer I.S. https://github.com/omeritzics',
    'ja': 'camegone https://github.com/camegone',
    'nl': 'Heimen Stoffels https://github.com/Vistaus',
    'pt_BR': ('Cristiano Fraga G. Nunes https://github.com/cfgnunes\n'
              'Fernando Souza'),
    'ru': 'Vladimir Kosolapov https://github.com/vmkspv',
    'tr': 'Sabri Ünal https://github.com/yakushabb',
    'uk': 'Vladimir Kosolapov https://github.com/vmkspv',
    'vi': 'Loc Huynh https://github.com/hthienloc'
}

class LenspectApplication(Adw.Application):
    def __init__(self, version):
        super().__init__(application_id='io.github.vmkspv.lenspect',
                        flags=Gio.ApplicationFlags.HANDLES_OPEN)
        self.create_action("about", self.on_about_action)
        self.create_action("shortcuts", self.on_shortcuts_action, ['<Primary>question'])
        self.create_action("close-window", self.on_close_window_action, ['<Primary>w'])
        self.create_action("new-window", self.on_new_window_action, ['<Primary>n'])
        self.create_action("present", self.on_present_action)
        self.create_action("quit", lambda *_: self.quit(), ['<Primary>q'])
        self.version = version

    def do_activate(self):
        self.new_window()

    def do_open(self, files, *_):
        for file in files:
            win = self.new_window()
            win.load_file_for_scan(file)

    def new_window(self):
        win = LenspectWindow(application=self)
        win.present()
        return win

    def on_new_window_action(self, *args):
        self.new_window()

    def on_present_action(self, *args):
        if self.props.active_window:
            self.props.active_window.present()
        else:
            self.new_window()

    def get_translator_credits(self):
        locale_code = locale.getlocale()[0] or ''
        return translators.get(locale_code) or translators.get(locale_code[:2], '')

    def on_about_action(self, widget, param):
        about = Adw.AboutDialog.new_from_appdata('/io/github/vmkspv/lenspect/metainfo.xml', self.version)
        about.set_developers(['Vladimir Kosolapov https://github.com/vmkspv'])
        about.set_artists(['Vladimir Kosolapov https://github.com/vmkspv'])
        about.set_translator_credits(self.get_translator_credits())
        about.set_copyright('© 2025-2026 Vladimir Kosolapov')
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
        # Translators: Metainfo and translations for the Netsleuth <https://github.com/vmkspv/netsleuth>
        about.add_other_app('io.github.vmkspv.netsleuth', 'Netsleuth', _('Calculate IP subnets'))
        about.present(self.props.active_window)

    def on_shortcuts_action(self, *args):
        builder = Gtk.Builder.new_from_resource('/io/github/vmkspv/lenspect/shortcuts-dialog.ui')
        dialog = builder.get_object('shortcuts_dialog')
        dialog.present(self.props.active_window)

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
