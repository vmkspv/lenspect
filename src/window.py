# window.py
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
from pathlib import Path

from gi.repository import Adw, Gtk, GLib
from .vt_provider import VirusTotalService, FileAnalysis

@Gtk.Template(resource_path='/io/github/vmkspv/lenspect/window.ui')
class LenspectWindow(Adw.ApplicationWindow):
    __gtype_name__ = 'LenspectWindow'

    view_stack = Gtk.Template.Child()
    header_bar = Gtk.Template.Child()
    about_button = Gtk.Template.Child()
    cancel_button = Gtk.Template.Child()
    back_button = Gtk.Template.Child()
    api_key_entry = Gtk.Template.Child()
    api_help_button = Gtk.Template.Child()
    file_selection_row = Gtk.Template.Child()
    scan_button = Gtk.Template.Child()
    scan_spinner = Gtk.Template.Child()
    progress_row = Gtk.Template.Child()
    file_info_row = Gtk.Template.Child()
    detection_row = Gtk.Template.Child()
    detection_icon = Gtk.Template.Child()
    results_details_group = Gtk.Template.Child()
    new_scan_button = Gtk.Template.Child()
    toast_overlay = Gtk.Template.Child()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.vt_service = VirusTotalService()
        self.setup_file_chooser()
        self.selected_file = None
        self.current_task = None
        self.config_file = self.get_config_path()
        self.load_settings()
        self.connect_signals()
        self.update_ui_state()

    def setup_file_chooser(self):
        self.file_chooser = Gtk.FileChooserNative.new(
            title=_('Select File to Scan'),
            parent=self,
            action=Gtk.FileChooserAction.OPEN
        )

    def connect_signals(self):
        self.api_key_entry.connect("notify::text", self.on_api_key_changed)
        self.api_key_entry.connect("activate", self.on_api_key_activate)
        self.file_chooser.connect("response", self.on_file_chooser_response)
        self.vt_service.connect("analysis-progress", self.on_analysis_progress)
        self.vt_service.connect("analysis-completed", self.on_analysis_completed)
        self.vt_service.connect("analysis-failed", self.on_analysis_failed)

    def get_config_path(self):
        config_dir = Path(GLib.get_user_config_dir()) / "lenspect"
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir / "api_key"

    def load_settings(self):
        try:
            if self.config_file.exists():
                api_key = self.config_file.read_text().strip()
                if api_key:
                    self.api_key_entry.set_text(api_key)
                    self.vt_service.api_key = api_key
        except OSError:
            pass

    def save_settings(self, api_key=None):
        if api_key is None:
            return
        try:
            self.config_file.write_text(api_key)
        except OSError:
            pass

    def update_ui_state(self):
        has_api_key = bool(self.vt_service.api_key)
        has_file = self.selected_file is not None
        is_scanning = self.current_task is not None

        self.scan_button.set_sensitive(has_api_key and has_file and not is_scanning)

        if has_file:
            filename = self.selected_file.get_basename()
            if len(filename) > 35:
                filename = filename[:32] + "..."
            self.file_selection_row.set_title(filename)
            self.file_selection_row.set_subtitle(_('Ready to scan'))
        else:
            self.file_selection_row.set_title(_('No File Selected'))
            self.file_selection_row.set_subtitle(_('Click to choose a file to scan'))

    def show_error_dialog(self, title: str, message: str):
        dialog = Adw.AlertDialog.new(title, message)
        dialog.add_response("ok", _('OK'))
        dialog.present(self)

    def on_api_key_changed(self, entry: Adw.PasswordEntryRow, param):
        api_key = entry.get_text().strip()
        self.vt_service.api_key = api_key
        self.save_settings(api_key=api_key)
        self.update_ui_state()

    def on_api_key_activate(self, entry: Adw.PasswordEntryRow):
        if self.selected_file and self.vt_service.has_api_key:
            self.start_scan()

    def show_toast(self, message: str):
        toast = Adw.Toast.new(message)
        toast.set_timeout(2)
        self.toast_overlay.add_toast(toast)

    @Gtk.Template.Callback()
    def on_file_selection_activated(self, *args):
        self.file_chooser.show()

    @Gtk.Template.Callback()
    def on_api_help_clicked(self, button: Gtk.Button):
        self.show_api_help_dialog()

    @Gtk.Template.Callback()
    def on_cancel_scan_clicked(self, button: Gtk.Button):
        self.cancel_scan()

    @Gtk.Template.Callback()
    def on_back_button_clicked(self, *args):
        self.navigate_to_main()
        self.reset_for_new_scan()

    @Gtk.Template.Callback()
    def on_new_scan_button_clicked(self, *args):
        self.navigate_to_main()
        self.reset_for_new_scan()

    @Gtk.Template.Callback()
    def on_scan_button_clicked(self, button: Gtk.Button):
        self.start_scan()

    def on_file_chooser_response(self, dialog: Gtk.FileChooserNative, response: int):
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                self.selected_file = file
                filename = file.get_basename()

                self.update_ui_state()

    def navigate_to_main(self):
        self.view_stack.set_visible_child_name("main")
        self.about_button.set_visible(True)
        self.cancel_button.set_visible(False)
        self.back_button.set_visible(False)

    def navigate_to_scanning(self):
        self.view_stack.set_visible_child_name("scanning")
        self.about_button.set_visible(False)
        self.cancel_button.set_visible(True)
        self.back_button.set_visible(False)

    def navigate_to_results(self):
        self.view_stack.set_visible_child_name("results")
        self.about_button.set_visible(False)
        self.cancel_button.set_visible(False)
        self.back_button.set_visible(True)

    def reset_for_new_scan(self):
        self.selected_file = None
        self.current_task = None
        self.update_ui_state()

    def show_api_help_dialog(self):
        dialog = Adw.AlertDialog.new(
            _('Get VirusTotal API Key'),
            _('To use Lenspect, you need a public VirusTotal API key:\n\n'
            '1. Go to virustotal.com\n'
            '2. Create a free account\n'
            '3. Open your profile settings\n'
            '4. Copy personal API key\n'
            '5. Paste it in the Lenspect')
        )
        dialog.add_response("cancel", _('Close'))
        dialog.add_response("open", _('Documentation'))
        dialog.set_response_appearance("open", Adw.ResponseAppearance.SUGGESTED)
        dialog.connect("response", self.on_api_help_response)
        dialog.present(self)

    def on_api_help_response(self, dialog: Adw.AlertDialog, response: str):
        if response == "open":
            Gtk.show_uri(self, "https://docs.virustotal.com/docs/please-give-me-an-api-key", 0)

    def start_scan(self):
        file_path = self.selected_file.get_path()
        if not file_path:
            self.show_error_dialog(_('Error'), _('Could not access the selected file'))
            return

        if not exists(file_path):
            self.show_error_dialog(_('Error'), _('Selected file no longer exists'))
            return

        if not access(file_path, R_OK):
            self.show_error_dialog(_('Error'), _('Cannot read the selected file'))
            return

        self.navigate_to_scanning()
        self.current_task = self.vt_service.scan_file_async(file_path)
        self.update_ui_state()

    def on_analysis_progress(self, service: VirusTotalService, message: str):
        self.progress_row.set_title(message)
        self.progress_row.set_subtitle(_('This may take a few minutes'))

    def on_analysis_completed(self, service: VirusTotalService, analysis: FileAnalysis):
        self.current_task = None
        self.navigate_to_results()
        self.display_analysis_results(analysis)

    def on_analysis_failed(self, service: VirusTotalService, error_message: str):
        self.current_task = None
        self.navigate_to_main()
        self.update_ui_state()
        self.show_error_dialog(
            _('Scan Failed'),
            _('Analysis failed: {error_message}').format(error_message=error_message))

    def display_analysis_results(self, analysis: FileAnalysis):
        filename = analysis.file_name or (
            self.selected_file.get_basename()
            if self.selected_file else _('Unknown'))
        file_size_str = (
            f"{analysis.file_size:,} {_('bytes')}"
            if analysis.file_size > 0 else _('Unknown size'))

        self.file_info_row.set_title(filename)
        self.file_info_row.set_subtitle(
            "{file_size} • {analysis_date}".format(
                file_size=file_size_str, analysis_date=analysis.last_analysis_date))

        detection_text = f"{analysis.threat_count}/{analysis.total_engines}"
        if analysis.is_clean:
            self.detection_row.set_title(_('No Threats Detected'))
            self.detection_row.set_subtitle(
                _('Clean • {engines} engines').format(engines=detection_text))
            self.detection_icon.set_from_icon_name("security-high-symbolic")
            self.detection_icon.remove_css_class("error")
            self.detection_icon.add_css_class("success")
        else:
            self.detection_row.set_title(_('Threats Detected'))
            self.detection_row.set_subtitle(
                _('Malicious: {malicious} • Suspicious: {suspicious}').format(
                    malicious=analysis.malicious_count,
                    suspicious=analysis.suspicious_count))
            self.detection_icon.set_from_icon_name("security-low-symbolic")
            self.detection_icon.remove_css_class("success")
            self.detection_icon.add_css_class("error")

        self.clear_results_details()

        self.add_results_section(_('File Information'), [
            (_('Filename'), filename),
            (_('Size'), file_size_str),
            (_('Last Analyzed'), analysis.last_analysis_date),
        ])

        self.add_results_section(_('Detection Statistics'), [
            (_('Malicious'), str(analysis.malicious_count)),
            (_('Suspicious'), str(analysis.suspicious_count)),
            (_('Clean'), str(analysis.harmless_count)),
            (_('Undetected'), str(analysis.undetected_count)),
            (_('Total Engines'), str(analysis.total_engines)),
        ])

        if analysis.threat_count > 0:
            detections = analysis.get_detections()
            detection_items = [
                (engine, detection)
                for engine, detection in detections.items()]
            self.add_results_section(_('Threat Detections'), detection_items)

    def clear_results_details(self):
        child = self.results_details_group.get_first_child()
        while child:
            next_child = child.get_next_sibling()
            self.results_details_group.remove(child)
            child = next_child

    def add_results_section(self, section_title: str, items: list):
        section_group = Adw.PreferencesGroup()
        section_group.set_title(section_title)
        section_group.add_css_class("boxed-list")

        for title, value in items:
            row = self.create_copyable_row(title, value)
            section_group.add(row)

        self.results_details_group.append(section_group)

    def create_copyable_row(self, title: str, value: str):
        row = Adw.ActionRow(title=title, subtitle=value, subtitle_selectable=True)
        row.add_css_class("property-row")

        copy_button = Gtk.Button(
            icon_name="edit-copy-symbolic",
            valign=Gtk.Align.CENTER,
            tooltip_text=_('Copy')
        )
        copy_button.add_css_class("flat")
        copy_button.connect("clicked", self.on_copy_clicked, value)

        row.add_suffix(copy_button)
        return row

    def on_copy_clicked(self, button: Gtk.Button, text: str):
        clipboard = self.get_clipboard()
        clipboard.set(text)
        self.show_toast(_('Copied to clipboard'))

    def cancel_scan(self):
        if self.current_task:
            cancellable = self.current_task.get_cancellable()
            if cancellable:
                cancellable.cancel()
            self.current_task = None
            self.update_ui_state()
            self.navigate_to_main()
        else:
            self.navigate_to_main()
