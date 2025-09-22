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
from html import escape

from gi.repository import Adw, Gtk, GLib
from .vt_provider import VirusTotalService, FileAnalysis, URLAnalysis

@Gtk.Template(resource_path='/io/github/vmkspv/lenspect/window.ui')
class LenspectWindow(Adw.ApplicationWindow):
    __gtype_name__ = 'LenspectWindow'

    view_stack = Gtk.Template.Child()
    mode_stack = Gtk.Template.Child()
    toast_overlay = Gtk.Template.Child()

    header_bar = Gtk.Template.Child()
    window_title = Gtk.Template.Child()
    about_button = Gtk.Template.Child()
    cancel_button = Gtk.Template.Child()
    back_button = Gtk.Template.Child()
    vt_button = Gtk.Template.Child()

    main_page = Gtk.Template.Child()
    api_key_entry = Gtk.Template.Child()
    api_help_button = Gtk.Template.Child()
    quota_label = Gtk.Template.Child()
    file_group = Gtk.Template.Child()
    file_selection_row = Gtk.Template.Child()
    file_history_button = Gtk.Template.Child()
    url_group = Gtk.Template.Child()
    url_entry = Gtk.Template.Child()
    url_history_button = Gtk.Template.Child()
    scan_button = Gtk.Template.Child()

    scanning_page = Gtk.Template.Child()
    scan_spinner = Gtk.Template.Child()
    progress_row = Gtk.Template.Child()

    info_row = Gtk.Template.Child()
    detection_row = Gtk.Template.Child()
    detection_icon = Gtk.Template.Child()
    results_group = Gtk.Template.Child()
    copy_all_button = Gtk.Template.Child()
    export_button = Gtk.Template.Child()
    new_scan_button = Gtk.Template.Child()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.vt_service = VirusTotalService()
        self.api_key_file = self.get_api_key_path()
        self.setup_file_chooser()
        self.is_file_mode = True
        self.selected_file = None
        self.current_url = None
        self.current_task = None
        self.current_analysis = None

        self.file_history = []
        self.url_history = []
        self.file_history_dialog = None
        self.url_history_dialog = None

        self.mode_switcher = Adw.ViewSwitcher()
        self.mode_switcher.set_stack(self.mode_stack)
        self.mode_switcher.set_policy(Adw.ViewSwitcherPolicy.WIDE)

        self.mode_stack.set_enable_transitions(True)
        self.mode_stack.set_transition_duration(200)

        self.view_stack.set_enable_transitions(True)
        self.view_stack.set_transition_duration(350)

        self.load_api_key()
        self.load_history()
        self.connect_signals()
        self.update_ui_state()
        self.update_quota_data()
        self.navigate_to_main()

    def setup_file_chooser(self):
        self.file_chooser = Gtk.FileChooserNative.new(
            title=_('Select file to scan'),
            parent=self,
            action=Gtk.FileChooserAction.OPEN
        )

    def connect_signals(self):
        self.mode_stack.connect("notify::visible-child-name", self.on_mode_changed)
        self.api_key_entry.connect("notify::text", self.on_api_key_changed)
        self.api_key_entry.connect("activate", self.on_api_key_activate)
        self.file_chooser.connect("response", self.on_file_chooser_response)
        self.url_entry.get_delegate().connect("activate", self.on_url_activate)
        self.vt_service.connect("analysis-progress", self.on_analysis_progress)
        self.vt_service.connect("file-analysis-completed", self.on_file_analysis_completed)
        self.vt_service.connect("url-analysis-completed", self.on_url_analysis_completed)
        self.vt_service.connect("analysis-failed", self.on_analysis_failed)

    def get_api_key_path(self):
        config_dir = Path(GLib.get_user_config_dir()) / "lenspect"
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir / "api_key"

    def load_api_key(self):
        try:
            if self.api_key_file.exists():
                api_key = self.api_key_file.read_text().strip()
                if api_key:
                    self.api_key_entry.set_text(api_key)
                    self.vt_service.api_key = api_key
        except OSError:
            pass

    def save_api_key(self, api_key=None):
        if api_key is None:
            return
        try:
            self.api_key_file.write_text(api_key)
        except OSError:
            pass

    def get_history_path(self, history_type: str):
        config_dir = Path(GLib.get_user_config_dir()) / "lenspect"
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir / f"{history_type}_history.json"

    def load_history(self):
        from json import load

        for history_type in ["file", "url"]:
            history_path = self.get_history_path(history_type)
            try:
                if history_path.exists():
                    with open(history_path, "r") as f:
                        setattr(self, f"{history_type}_history", load(f))
                else:
                    setattr(self, f"{history_type}_history", [])
            except (OSError, ValueError):
                setattr(self, f"{history_type}_history", [])

    def save_history(self, history_type):
        from json import dump

        try:
            history_path = self.get_history_path(history_type)
            history_data = getattr(self, f"{history_type}_history")
            with open(history_path, "w") as f:
                dump(history_data, f, indent=2, ensure_ascii=False)
        except OSError:
            pass

    def update_quota_data(self):
        if not self.vt_service.has_api_key:
            self.quota_label.set_visible(False)
            return

        def fetch_quota():
            try:
                quotas = self.vt_service.get_api_quotas()
                usage = self.vt_service.get_api_usage()

                if quotas and usage:
                    GLib.idle_add(self.show_quota, quotas, usage)
                else:
                    GLib.idle_add(lambda: self.quota_label.set_visible(False))
            except Exception:
                GLib.idle_add(lambda: self.quota_label.set_visible(False))

        from threading import Thread
        Thread(target=fetch_quota, daemon=True).start()

    def parse_api_usage(self, usage_data):
        from datetime import date

        today = date.today().strftime("%Y-%m-%d")
        daily_data = usage_data.get("daily", {})
        today_data = daily_data.get(today, {})
        daily_used = sum(today_data.values())

        total_data = usage_data.get("total", {})
        monthly_used = sum(total_data.values())

        return daily_used, monthly_used

    def show_quota(self, quotas, usage):
        daily_quota = quotas.get("api_requests_daily", {}).get("user", {})
        monthly_quota = quotas.get("api_requests_monthly", {}).get("user", {})

        daily_limit = daily_quota.get("allowed", 0)
        monthly_limit = monthly_quota.get("allowed", 0)

        daily_used, monthly_used = self.parse_api_usage(usage)

        daily_limit_str = str(daily_limit)
        monthly_limit_str = "∞" if monthly_limit >= 1000000000 else str(monthly_limit)

        tooltip = (
            f"{_('Daily')}: {daily_used}/{daily_limit_str}\n"
            f"{_('Monthly')}: {monthly_used}/{monthly_limit_str}"
        )
        self.quota_label.set_tooltip_text(tooltip)
        self.quota_label.set_visible(True)

    def update_ui_state(self):
        has_api_key = bool(self.vt_service.api_key)
        is_scanning = self.current_task is not None

        current_page = self.mode_stack.get_visible_child_name()
        self.is_file_mode = (current_page == "file")

        if self.is_file_mode:
            self.main_page.set_title(_('Scan Files for Malware'))
            self.main_page.set_description(_('Use VirusTotal to check files for security threats'))
        else:
            self.main_page.set_title(_('Scan URLs for Threats'))
            self.main_page.set_description(_('Use VirusTotal to check URLs for malicious content'))

        has_valid_input = False
        if self.is_file_mode:
            has_valid_input = self.selected_file is not None
            if self.selected_file:
                filename = self.selected_file.get_basename()
                original_filename = filename
                if len(filename) > 35:
                    filename = filename[:32] + "..."
                self.file_selection_row.set_title(filename)
                self.file_selection_row.set_subtitle(_('Ready to scan'))

                if len(original_filename) > 35:
                    self.file_selection_row.set_tooltip_text(original_filename)
                else:
                    self.file_selection_row.set_tooltip_text("")
            else:
                self.file_selection_row.set_title(_('No File Selected'))
                self.file_selection_row.set_subtitle(_('Click to choose a file to scan'))
                self.file_selection_row.set_tooltip_text("")
        else:
            has_valid_input = bool(self.current_url and self.vt_service.validate_url(self.current_url))

        self.scan_button.set_sensitive(has_api_key and has_valid_input and not is_scanning)

    def show_error_dialog(self, title: str, message: str):
        dialog = Adw.AlertDialog.new(title, message)
        dialog.add_response("ok", _('OK'))
        dialog.present(self)

    def on_api_key_changed(self, entry: Adw.PasswordEntryRow, param):
        api_key = entry.get_text().strip()
        self.vt_service.api_key = api_key
        self.save_api_key(api_key=api_key)
        self.update_ui_state()
        self.update_quota_data()

    def on_api_key_activate(self, entry: Adw.PasswordEntryRow):
        if self.vt_service.has_api_key and self.can_start_scan():
            self.start_scan()

    def on_url_activate(self, entry):
        if self.scan_button.get_sensitive():
            self.on_scan_button_clicked(self.scan_button)

    def show_toast(self, message: str):
        toast = Adw.Toast.new(message)
        toast.set_timeout(2)
        self.toast_overlay.add_toast(toast)

    @Gtk.Template.Callback()
    def on_file_selection_activated(self, *args):
        self.file_chooser.show()

    @Gtk.Template.Callback()
    def on_api_help_clicked(self, button):
        self.show_api_help_dialog()

    @Gtk.Template.Callback()
    def on_cancel_scan_clicked(self, button):
        self.cancel_scan()

    @Gtk.Template.Callback()
    def on_back_button_clicked(self, *args):
        self.navigate_to_main()
        self.reset_for_new_scan()

    @Gtk.Template.Callback()
    def on_vt_button_clicked(self, *args):
        if self.current_analysis:
            vt_url = self.get_virustotal_url(self.current_analysis)
            if vt_url:
                Gtk.show_uri(self, vt_url, 0)

    @Gtk.Template.Callback()
    def on_new_scan_button_clicked(self, *args):
        self.navigate_to_main()
        self.reset_for_new_scan()

    @Gtk.Template.Callback()
    def on_scan_button_clicked(self, button):
        self.start_scan()

    def on_mode_changed(self, stack, *args):
        self.update_ui_state()

    @Gtk.Template.Callback()
    def on_url_changed(self, entry: Adw.EntryRow, *args):
        self.current_url = entry.get_text().strip() or None
        self.update_ui_state()

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
        self.vt_button.set_visible(False)
        self.header_bar.set_title_widget(self.mode_switcher)

    def navigate_to_scanning(self):
        self.view_stack.set_visible_child_name("scanning")
        self.about_button.set_visible(False)
        self.cancel_button.set_visible(True)
        self.back_button.set_visible(False)
        self.vt_button.set_visible(False)
        self.header_bar.set_title_widget(self.window_title)

        if self.is_file_mode:
            self.scanning_page.set_title(_('Scanning File'))
            self.scanning_page.set_description(_('Please wait for the file analysis...'))
        else:
            self.scanning_page.set_title(_('Scanning URL'))
            self.scanning_page.set_description(_('Please wait for the URL analysis...'))

    def navigate_to_results(self):
        self.view_stack.set_visible_child_name("results")
        self.about_button.set_visible(False)
        self.cancel_button.set_visible(False)
        self.back_button.set_visible(True)
        self.vt_button.set_visible(True)
        self.header_bar.set_title_widget(self.window_title)

    def reset_for_new_scan(self):
        self.selected_file = None
        self.current_url = None
        self.url_entry.set_text("")
        self.current_task = None
        self.current_analysis = None
        self.update_ui_state()

    def can_start_scan(self):
        if self.is_file_mode:
            return self.selected_file is not None
        else:
            return bool(self.current_url and self.vt_service.validate_url(self.current_url))

    def show_api_help_dialog(self):
        message = _('To use Lenspect, you need a public VirusTotal API key:\n\n'
            '1. Go to {link}\n'
            '2. Create a free account\n'
            '3. Open your profile settings\n'
            '4. Copy personal API key\n'
            '5. Paste it in the Lenspect').format(
            link='<a href="https://www.virustotal.com">virustotal.com</a>')

        dialog = Adw.AlertDialog.new(_('Get VirusTotal API Key'), message)
        dialog.set_body_use_markup(True)
        dialog.add_response("cancel", _('Close'))
        dialog.add_response("open", _('Documentation'))
        dialog.set_response_appearance("open", Adw.ResponseAppearance.SUGGESTED)
        dialog.connect("response", self.on_api_help_response)
        dialog.present(self)

    def on_api_help_response(self, dialog: Adw.AlertDialog, response: str):
        if response == "open":
            Gtk.show_uri(self, "https://docs.virustotal.com/docs/please-give-me-an-api-key", 0)

    def start_scan(self):
        if self.is_file_mode:
            self.start_file_scan()
        else:
            self.start_url_scan()

    def start_file_scan(self):
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

    def start_url_scan(self):
        if not self.vt_service.validate_url(self.current_url):
            self.show_error_dialog(_('Error'), _('Please enter a valid URL'))
            return

        self.navigate_to_scanning()
        self.current_task = self.vt_service.scan_url_async(self.current_url)
        self.update_ui_state()

    def on_analysis_progress(self, service: VirusTotalService, message: str):
        self.progress_row.set_title(message)
        self.progress_row.set_subtitle(_('This may take a few minutes'))

    def on_file_analysis_completed(self, service: VirusTotalService, analysis: FileAnalysis):
        self.current_task = None
        self.current_analysis = analysis

        if self.selected_file:
            file_hash = analysis.file_id
            filename = analysis.file_name or self.selected_file.get_basename()
            self.add_file_to_history(filename, file_hash)

        self.navigate_to_results()
        self.display_file_analysis_results(analysis)
        self.update_quota_data()

    def on_url_analysis_completed(self, service: VirusTotalService, analysis: URLAnalysis):
        self.current_task = None
        self.current_analysis = analysis

        if self.current_url:
            self.add_url_to_history(self.current_url)

        self.navigate_to_results()
        self.display_url_analysis_results(analysis)
        self.update_quota_data()

    def on_analysis_failed(self, service: VirusTotalService, error_message: str):
        self.current_task = None
        self.navigate_to_main()
        self.update_ui_state()
        self.show_error_dialog(_('Scan Failed'), error_message)
        self.update_quota_data()

    def display_file_analysis_results(self, analysis: FileAnalysis):
        filename = analysis.file_name or (
            self.selected_file.get_basename()
            if self.selected_file else _('Unknown'))
        file_size_str = (
            f"{analysis.file_size:,} {_('bytes')}"
            if analysis.file_size > 0 else _('Unknown size'))

        self.info_row.set_title(escape(filename, quote=True))
        self.info_row.set_subtitle(
            "{file_size} • {analysis_date}".format(
                file_size=file_size_str, analysis_date=analysis.last_analysis_date))

        detection_text = f"{analysis.threat_count}/{analysis.total_vendors}"
        if analysis.is_clean:
            self.detection_row.set_title(_('No Threats Detected'))
            self.detection_row.set_subtitle(
                _('Clean • {vendors} vendors').format(vendors=detection_text))
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
            (_('Total Vendors'), str(analysis.total_vendors)),
        ])

        if analysis.threat_count > 0:
            detections = analysis.get_detections()
            detection_items = sorted([
                (vendor, detection)
                for vendor, detection in detections.items()])
            self.add_results_section(_('Threat Detections'), detection_items)

    def display_url_analysis_results(self, analysis: URLAnalysis):
        url_title = analysis.title or _('Untitled')
        url_display = analysis.url
        if len(url_display) > 42:
            url_display = url_display[:39] + "..."

        self.info_row.set_title(escape(url_title, quote=True))
        self.info_row.set_subtitle(
            "{url} • {analysis_date}".format(
                url=url_display, analysis_date=analysis.last_analysis_date))

        detection_text = f"{analysis.threat_count}/{analysis.total_vendors}"
        if analysis.is_clean:
            self.detection_row.set_title(_('No Threats Detected'))
            self.detection_row.set_subtitle(
                _('Clean • {vendors} vendors').format(vendors=detection_text))
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

        self.add_results_section(_('URL Information'), [
            (_('URL'), analysis.url),
            (_('Title'), url_title),
            (_('Last Analyzed'), analysis.last_analysis_date),
            (_('Community Score'), str(analysis.community_score)),
        ])

        categories = analysis.get_categories()
        if categories:
            category_items = sorted([(vendor, category) for vendor, category in categories.items()])
            self.add_results_section(_('Categories'), category_items)

        self.add_results_section(_('Detection Statistics'), [
            (_('Malicious'), str(analysis.malicious_count)),
            (_('Suspicious'), str(analysis.suspicious_count)),
            (_('Clean'), str(analysis.harmless_count)),
            (_('Undetected'), str(analysis.undetected_count)),
            (_('Total Vendors'), str(analysis.total_vendors)),
        ])

        if analysis.threat_count > 0:
            detections = analysis.get_detections()
            detection_items = sorted([
                (vendor, detection)
                for vendor, detection in detections.items()])
            self.add_results_section(_('Threat Detections'), detection_items)

    def clear_results_details(self):
        child = self.results_group.get_first_child()
        while child:
            next_child = child.get_next_sibling()
            self.results_group.remove(child)
            child = next_child

    def add_results_section(self, section_title: str, items: list):
        section_group = Adw.PreferencesGroup()
        section_group.set_title(section_title)
        section_group.add_css_class("boxed-list")

        for title, value in items:
            row = self.create_copyable_row(title, value)
            section_group.add(row)

        self.results_group.append(section_group)

    def create_copyable_row(self, title: str, value: str):
        safe_title = escape(title, quote=True)
        safe_value = escape(value, quote=True)
        row = Adw.ActionRow(title=safe_title, subtitle=safe_value, subtitle_selectable=True)
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

    def on_copy_clicked(self, button, text: str):
        self.get_clipboard().set(text)
        self.show_toast(_('Copied to clipboard'))

    def generate_report_text(self):
        if not self.current_analysis:
            return ""

        analysis = self.current_analysis
        sections = []

        header = f"{_('Generated by Lenspect - VirusTotal Scanner for Linux')}"
        sections.append([header])

        if isinstance(analysis, FileAnalysis):
            filename = analysis.file_name or (
                self.selected_file.get_basename()
                if self.selected_file else _('Unknown'))
            file_size_str = (
                f"{analysis.file_size:,} {_('bytes')}"
                if analysis.file_size > 0 else _('Unknown size'))

            info_section = [
                f"=== {_('File Information')} ===",
                f"{_('Filename')}: {filename}",
                f"{_('Size')}: {file_size_str}",
                f"{_('Last Analyzed')}: {analysis.last_analysis_date}"
            ]
            sections.append(info_section)

        elif isinstance(analysis, URLAnalysis):
            url_title = analysis.title or _('Untitled')
            info_section = [
                f"=== {_('URL Information')} ===",
                f"{_('URL')}: {analysis.url}",
                f"{_('Title')}: {url_title}",
                f"{_('Last Analyzed')}: {analysis.last_analysis_date}",
                f"{_('Community Score')}: {analysis.community_score}"
            ]
            sections.append(info_section)

        stats_section = [
            f"=== {_('Detection Statistics')} ===",
            f"{_('Malicious')}: {analysis.malicious_count}",
            f"{_('Suspicious')}: {analysis.suspicious_count}",
            f"{_('Clean')}: {analysis.harmless_count}",
            f"{_('Undetected')}: {analysis.undetected_count}",
            f"{_('Total Vendors')}: {analysis.total_vendors}"
        ]
        sections.append(stats_section)

        if analysis.threat_count > 0:
            detections = analysis.get_detections()
            if detections:
                threats_section = [f"=== {_('Threat Detections')} ==="]
                for vendor, detection in sorted(detections.items()):
                    threats_section.append(f"{vendor}: {detection}")
                sections.append(threats_section)

        return "\n\n".join("\n".join(section) for section in sections)

    @Gtk.Template.Callback()
    def on_copy_all_clicked(self, button):
        report_text = self.generate_report_text()
        if report_text:
            self.get_clipboard().set(report_text)
            self.show_toast(_('Copied to clipboard'))

    @Gtk.Template.Callback()
    def on_export_clicked(self, button):
        if not self.current_analysis:
            return

        dialog = Gtk.FileChooserNative.new(
            title=_('Export report'),
            parent=self,
            action=Gtk.FileChooserAction.SAVE
        )

        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        dialog.set_current_name(f"lenspect_{timestamp}.txt")
        dialog.connect("response", self.on_export_response)
        dialog.show()

    def on_export_response(self, dialog: Gtk.FileChooserNative, response: int):
        if response == Gtk.ResponseType.ACCEPT:
            file = dialog.get_file()
            if file:
                report_text = self.generate_report_text()
                if report_text:
                    file_path = file.get_path()
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(report_text)
                    file_name = file.get_basename()
                    self.show_toast(_('Saved to {file}').format(file=file_name))

        dialog.destroy()

    def add_to_history(self, history_type, **item_data):
        timestamp = GLib.DateTime.new_now_local().format("%Y-%m-%d %H:%M:%S")
        new_item = {"timestamp": timestamp, **item_data}

        history_data = getattr(self, f"{history_type}_history")

        if history_type == "file":
            unique_key = "file_hash"
        else:
            unique_key = "url"

        unique_value = new_item[unique_key]
        history_data[:] = [item for item in history_data
                          if item[unique_key] != unique_value]

        history_data.insert(0, new_item)
        history_data[:] = history_data[:20]
        self.save_history(history_type)

    def add_file_to_history(self, filename: str, file_hash: str):
        self.add_to_history("file", filename=filename, file_hash=file_hash)

    def add_url_to_history(self, url: str):
        self.add_to_history("url", url=self.vt_service.normalize_url(url))

    @Gtk.Template.Callback()
    def on_file_history_clicked(self, button):
        self.show_history_dialog("file")

    @Gtk.Template.Callback()
    def on_url_history_clicked(self, button):
        self.show_history_dialog("url")

    def show_history_dialog(self, history_type):
        dialog_attr = f"{history_type}_history_dialog"
        if not getattr(self, dialog_attr, None):
            create_method = getattr(self, f"create_{history_type}_history_dialog")
            setattr(self, dialog_attr, create_method())

        update_method = getattr(self, f"update_{history_type}_history_list")
        update_method()

        dialog = getattr(self, dialog_attr)
        dialog.present(self)

    def create_history_dialog(self, history_type):
        dialog = Adw.Dialog()
        title = _('File History') if history_type == "file" else _('URL History')
        dialog.set_title(title)
        dialog.set_size_request(350, 400)

        toolbar_view = Adw.ToolbarView()

        header_bar = Adw.HeaderBar()
        header_bar.add_css_class("flat")

        clear_button = Gtk.Button(
            icon_name="user-trash-symbolic",
            valign=Gtk.Align.CENTER,
            tooltip_text=_('Clear')
        )
        clear_button.add_css_class("flat")
        clear_button.add_css_class("error")
        clear_button.connect("clicked", lambda btn: self.on_clear_history(history_type))
        header_bar.pack_start(clear_button)

        setattr(self, f"{history_type}_clear_button", clear_button)

        toolbar_view.add_top_bar(header_bar)

        history_list = Gtk.ListBox()
        history_list.set_selection_mode(Gtk.SelectionMode.NONE)
        history_list.add_css_class("boxed-list")

        setattr(self, f"{history_type}_history_list", history_list)

        empty_title = _('No History')
        empty_description = (
            _('Your scanned files will appear here') if history_type == "file"
            else _('Your scanned URLs will appear here')
        )

        empty_page = Adw.StatusPage(
            icon_name="document-open-recent-symbolic",
            title=empty_title,
            description=empty_description
        )

        setattr(self, f"empty_{history_type}_history_page", empty_page)

        history_stack = Gtk.Stack()
        history_stack.add_named(history_list, "history")
        history_stack.add_named(empty_page, "empty")

        setattr(self, f"{history_type}_history_stack", history_stack)

        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content_box.set_margin_top(16)
        content_box.set_margin_bottom(24)
        content_box.set_margin_start(16)
        content_box.set_margin_end(16)
        content_box.append(history_stack)

        scrolled_window = Gtk.ScrolledWindow(
            hscrollbar_policy=Gtk.PolicyType.NEVER,
            vscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
            vexpand=True,
            child=content_box
        )

        toolbar_view.set_content(scrolled_window)

        toast_overlay = Adw.ToastOverlay()
        toast_overlay.set_child(toolbar_view)

        setattr(self, f"{history_type}_history_toast_overlay", toast_overlay)

        dialog.set_child(toast_overlay)
        return dialog

    def create_file_history_dialog(self):
        return self.create_history_dialog("file")

    def create_url_history_dialog(self):
        return self.create_history_dialog("url")

    def update_history_list(self, history_type):
        history_list = getattr(self, f"{history_type}_history_list")
        history_stack = getattr(self, f"{history_type}_history_stack")
        history_data = getattr(self, f"{history_type}_history")

        while history_list.get_first_child():
            history_list.remove(history_list.get_first_child())

        if not history_data:
            history_stack.set_visible_child_name("empty")
            self.update_clear_button_state(history_type)
            return

        history_stack.set_visible_child_name("history")

        for item in history_data:
            if history_type == "file":
                display_text = item["filename"]
                full_text = item["filename"]
            else:
                display_text = item["url"]
                full_text = item["url"]

            if len(display_text) > 32:
                display_text = display_text[:29] + "..."

            row = Adw.ActionRow(
                title=display_text,
                subtitle=f"{_('Scanned on')}: {item['timestamp']}",
                activatable=True
            )

            if len(full_text) > 32:
                row.set_tooltip_text(full_text)

            activation_method = getattr(self, f"on_{history_type}_history_item_activated")
            row.connect("activated", activation_method, item)

            use_button = Gtk.Button(
                icon_name="object-select-symbolic",
                valign=Gtk.Align.CENTER,
                tooltip_text=_('Select')
            )
            use_button.add_css_class("flat")
            use_button.connect("clicked", activation_method, item)
            row.add_suffix(use_button)

            history_list.append(row)

        self.update_clear_button_state(history_type)

    def update_file_history_list(self):
        self.update_history_list("file")

    def update_url_history_list(self):
        self.update_history_list("url")

    def update_clear_button_state(self, history_type):
        button_name = f"{history_type}_clear_button"
        history_data = getattr(self, f"{history_type}_history")
        if hasattr(self, button_name):
            button = getattr(self, button_name)
            button.set_sensitive(bool(history_data))

    def on_clear_history(self, history_type):
        history_data = getattr(self, f"{history_type}_history")
        history_data.clear()
        self.save_history(history_type)

        update_method = getattr(self, f"update_{history_type}_history_list")
        update_method()
        self.update_clear_button_state(history_type)

        toast = Adw.Toast.new(_('History cleared'))
        toast.set_timeout(2)
        toast_overlay = getattr(self, f"{history_type}_history_toast_overlay")
        toast_overlay.add_toast(toast)

    def on_history_item_activated(self, history_type, item):
        dialog = getattr(self, f"{history_type}_history_dialog", None)
        if dialog:
            dialog.close()

        self.navigate_to_scanning()

        if history_type == "file":
            self.scanning_page.set_title(_('Loading File Report'))
            report_method = self.vt_service.get_file_report
            report_key = item["file_hash"]
            not_found_message = _('No report found for this file')
        else:
            self.scanning_page.set_title(_('Loading URL Report'))
            report_method = self.vt_service.get_url_report
            report_key = item["url"]
            not_found_message = _('No report found for this URL')

        self.scanning_page.set_description(_('Fetching existing analysis...'))

        def fetch_report():
            try:
                analysis = report_method(report_key)
                if analysis:
                    if history_type == "file":
                        analysis.original_filename = item["filename"]
                    GLib.idle_add(self.show_history_results, analysis, history_type)
                else:
                    GLib.idle_add(self.show_history_error, not_found_message)
            except Exception as e:
                GLib.idle_add(self.show_history_error, str(e))

        from threading import Thread
        Thread(target=fetch_report, daemon=True).start()

    def on_file_history_item_activated(self, widget, item):
        self.on_history_item_activated("file", item)

    def on_url_history_item_activated(self, widget, item):
        self.on_history_item_activated("url", item)

    def show_history_results(self, analysis, analysis_type):
        self.current_analysis = analysis
        self.navigate_to_results()
        if analysis_type == "file":
            self.display_file_analysis_results(analysis)
        else:
            self.display_url_analysis_results(analysis)

    def show_history_error(self, error_message):
        self.navigate_to_main()
        self.show_error_dialog(_('Error'), error_message)

    def get_virustotal_url(self, analysis) -> str:
        if isinstance(analysis, FileAnalysis):
            file_id = analysis.file_id
            if file_id:
                return f"https://www.virustotal.com/gui/file/{file_id}"
        elif isinstance(analysis, URLAnalysis):
            url_id = analysis.url_id
            if url_id:
                return f"https://www.virustotal.com/gui/url/{url_id}"
        return ""

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
