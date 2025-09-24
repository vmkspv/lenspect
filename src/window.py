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

from gi.repository import Adw, Gtk, Gdk, Gio, GLib
from .vt_provider import VirusTotalService, FileAnalysis, URLAnalysis

@Gtk.Template(resource_path='/io/github/vmkspv/lenspect/window.ui')
class LenspectWindow(Adw.ApplicationWindow):
    __gtype_name__ = 'LenspectWindow'

    view_stack = Gtk.Template.Child()
    mode_stack = Gtk.Template.Child()
    toast_overlay = Gtk.Template.Child()

    header_bar = Gtk.Template.Child()
    title_stack = Gtk.Template.Child()
    mode_switcher = Gtk.Template.Child()
    window_title = Gtk.Template.Child()
    about_button = Gtk.Template.Child()
    cancel_button = Gtk.Template.Child()
    back_button = Gtk.Template.Child()
    vt_button = Gtk.Template.Child()

    main_page = Gtk.Template.Child()
    api_key_entry = Gtk.Template.Child()
    quota_label = Gtk.Template.Child()
    file_group = Gtk.Template.Child()
    file_selection_row = Gtk.Template.Child()
    url_group = Gtk.Template.Child()
    url_entry = Gtk.Template.Child()
    scan_button = Gtk.Template.Child()

    scanning_page = Gtk.Template.Child()
    scan_spinner = Gtk.Template.Child()
    progress_row = Gtk.Template.Child()

    info_row = Gtk.Template.Child()
    detection_row = Gtk.Template.Child()
    detection_icon = Gtk.Template.Child()
    results_group = Gtk.Template.Child()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        Gtk.IconTheme.get_for_display(
            self.get_display()).add_resource_path('/io/github/vmkspv/lenspect/icons')

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

        self.load_api_key()
        self.load_history()
        self.setup_file_drop()
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

    def setup_file_drop(self):
        drop_target = Gtk.DropTarget.new(Gdk.FileList, Gdk.DragAction.COPY)
        drop_target.connect("drop", self.on_file_drop)
        self.file_selection_row.add_controller(drop_target)
        self.file_selection_row.add_css_class("file-drop-target")

    def connect_signals(self):
        self.mode_stack.connect("notify::visible-child-name", self.on_mode_changed)
        self.api_key_entry.connect("notify::text", self.on_api_key_changed)
        self.api_key_entry.connect("activate", self.on_api_key_activate)
        self.file_chooser.connect("response", self.on_file_chooser_response)
        self.url_entry.get_delegate().connect("activate", self.on_url_activate)
        self.vt_service.connect("analysis-progress", self.on_analysis_progress)
        self.vt_service.connect("file-analysis-completed", self.on_analysis_completed)
        self.vt_service.connect("url-analysis-completed", self.on_analysis_completed)
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

        def fetch_quota_task(task, source_object, task_data, cancellable):
            try:
                quotas = self.vt_service.get_api_quotas()
                usage = self.vt_service.get_api_usage()

                if quotas and usage:
                    GLib.idle_add(self.show_quota, quotas, usage)
                else:
                    GLib.idle_add(lambda: self.quota_label.set_visible(False))
            except Exception:
                GLib.idle_add(lambda: self.quota_label.set_visible(False))

        task = Gio.Task.new(self, None, None, None)
        task.run_in_thread(fetch_quota_task)

    def show_quota(self, quotas, usage):
        from datetime import date

        daily_quota = quotas.get("api_requests_daily", {}).get("user", {})
        monthly_quota = quotas.get("api_requests_monthly", {}).get("user", {})

        daily_limit = daily_quota.get("allowed", 0)
        monthly_limit = monthly_quota.get("allowed", 0)

        today = date.today().strftime("%Y-%m-%d")
        daily_data = usage.get("daily", {})
        today_data = daily_data.get(today, {})
        daily_used = sum(today_data.values())

        total_data = usage.get("total", {})
        monthly_used = sum(total_data.values())

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
            self.update_file_selection_display()
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
        if self.vt_service.has_api_key:
            if self.is_file_mode:
                can_scan = self.selected_file is not None
            else:
                can_scan = bool(self.current_url and self.vt_service.validate_url(self.current_url))
            if can_scan:
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

    def set_header_buttons(self, about=False, cancel=False, back=False, vt=False):
        self.about_button.set_visible(about)
        self.cancel_button.set_visible(cancel)
        self.back_button.set_visible(back)
        self.vt_button.set_visible(vt)

    def update_file_selection_display(self):
        if self.selected_file:
            filename = self.selected_file.get_basename()
            display_name = filename[:32] + "..." if len(filename) > 35 else filename
            tooltip = filename if len(filename) > 35 else ""

            self.file_selection_row.set_title(display_name)
            self.file_selection_row.set_subtitle(_('Ready to scan'))
            self.file_selection_row.set_tooltip_text(tooltip)
        else:
            self.file_selection_row.set_title(_('No File Selected'))
            self.file_selection_row.set_subtitle(_('Click to choose a file to scan'))
            self.file_selection_row.set_tooltip_text("")

    def navigate_to_main(self):
        self.view_stack.set_visible_child_name("main")
        self.title_stack.set_visible_child(self.mode_switcher)
        self.set_header_buttons(about=True)

    def navigate_to_scanning(self):
        self.view_stack.set_visible_child_name("scanning")
        self.title_stack.set_visible_child(self.window_title)
        self.set_header_buttons(cancel=True)

        if self.is_file_mode:
            title = _('Scanning File')
            description = _('Please wait for the file analysis...')
        else:
            title = _('Scanning URL')
            description = _('Please wait for the URL analysis...')
        self.scanning_page.set_title(title)
        self.scanning_page.set_description(description)

    def navigate_to_results(self):
        self.view_stack.set_visible_child_name("results")
        self.title_stack.set_visible_child(self.window_title)
        self.set_header_buttons(back=True, vt=True)

    def reset_for_new_scan(self):
        self.selected_file = None
        self.current_url = None
        self.url_entry.set_text("")
        self.current_task = None
        self.current_analysis = None
        self.update_ui_state()

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
        if not file_path or not exists(file_path) or not access(file_path, R_OK):
            error_message = (_('Could not access the selected file') if not file_path else
                        _('Selected file no longer exists') if not exists(file_path) else
                        _('Cannot read the selected file'))
            self.show_error_dialog(_('Error'), error_message)
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

    def on_analysis_completed(self, service: VirusTotalService, analysis):
        analysis_type = "file" if isinstance(analysis, FileAnalysis) else "url"
        self.handle_analysis_completion(analysis, analysis_type)

    def handle_analysis_completion(self, analysis, analysis_type):
        self.current_task = None
        self.current_analysis = analysis

        if analysis_type == "file" and self.selected_file:
            file_hash = analysis.file_id
            filename = analysis.file_name or self.selected_file.get_basename()
            self.add_file_to_history(filename, file_hash)
        elif analysis_type == "url" and self.current_url:
            self.add_url_to_history(self.current_url)

        self.navigate_to_results()
        self.display_analysis_results(analysis)
        self.update_quota_data()

    def on_analysis_failed(self, service: VirusTotalService, error_message: str):
        self.current_task = None
        self.navigate_to_main()
        self.update_ui_state()
        self.show_error_dialog(_('Scan Failed'), error_message)
        self.update_quota_data()

    def display_analysis_results(self, analysis):
        self.setup_detection_display(analysis)
        self.clear_results_details()

        if isinstance(analysis, FileAnalysis):
            filename = analysis.file_name or (
                self.selected_file.get_basename()
                if self.selected_file else _('Unknown'))
            file_size_str = (
                f"{analysis.file_size:,} {_('bytes')}"
                if analysis.file_size > 0 else _('Unknown size'))

            self.info_row.set_title(escape(filename, quote=True))
            self.info_row.set_subtitle(
                f"{file_size_str} • {analysis.last_analysis_date}")

            self.add_results_section(_('File Information'), [
                (_('Filename'), filename),
                (_('Size'), file_size_str),
                (_('Last Analyzed'), analysis.last_analysis_date),
            ])
        else:
            url_title = analysis.title or _('Untitled')
            url_display = analysis.url
            if len(url_display) > 45:
                url_display = url_display[:42] + "..."

            self.info_row.set_title(escape(url_title, quote=True))
            self.info_row.set_subtitle(
                f"{url_display} • {analysis.last_analysis_date}")

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

        self.add_detection_statistics_section(analysis)
        self.add_threat_detections_section(analysis)

    def setup_detection_display(self, analysis):
        detection_text = f"{analysis.threat_count}/{analysis.total_vendors}"

        if analysis.is_clean:
            title = _('No Threats Detected')
            subtitle = f"{_('Clean')} • {detection_text} {_('vendors')}"
            icon, css_class = "security-high-symbolic", "success"
            css_remove = "error"
        else:
            title = _('Threats Detected')
            subtitle = (f"{_('Malicious')}: {analysis.malicious_count} • "
                       f"{_('Suspicious')}: {analysis.suspicious_count}")
            icon, css_class = "security-low-symbolic", "error"
            css_remove = "success"

        self.detection_row.set_title(title)
        self.detection_row.set_subtitle(subtitle)
        self.detection_icon.set_from_icon_name(icon)
        self.detection_icon.remove_css_class(css_remove)
        self.detection_icon.add_css_class(css_class)

    def add_detection_statistics_section(self, analysis):
        self.add_results_section(_('Detection Statistics'), [
            (_('Malicious'), str(analysis.malicious_count)),
            (_('Suspicious'), str(analysis.suspicious_count)),
            (_('Clean'), str(analysis.harmless_count)),
            (_('Undetected'), str(analysis.undetected_count)),
            (_('Total Vendors'), str(analysis.total_vendors)),
        ])

    def add_threat_detections_section(self, analysis):
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
            icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER, tooltip_text=_('Copy'))
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
            self.on_copy_clicked(button, report_text)

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
                    self.show_toast(f"{_('Saved to')} {file_name}")

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
            setattr(self, dialog_attr, self.create_history_dialog(history_type))

        self.update_history_list(history_type)

        dialog = getattr(self, dialog_attr)
        dialog.present(self)

    def create_history_dialog(self, history_type):
        dialog = Adw.Dialog()
        dialog.set_title(_('File History') if history_type == "file" else _('URL History'))
        dialog.set_size_request(350, 400)

        clear_button = Gtk.Button(
            icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER, tooltip_text=_('Clear'))
        clear_button.add_css_class("flat")
        clear_button.add_css_class("error")
        clear_button.connect("clicked", lambda btn: self.on_clear_history(history_type))

        header_bar = Adw.HeaderBar()
        header_bar.add_css_class("flat")
        header_bar.pack_start(clear_button)

        setattr(self, f"{history_type}_clear_button", clear_button)

        history_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        history_list.add_css_class("boxed-list")
        setattr(self, f"{history_type}_history_list", history_list)

        empty_title = _('No History')
        empty_description = (
            _('Your scanned files will appear here') if history_type == "file"
            else _('Your scanned URLs will appear here')
        )
        empty_page = Adw.StatusPage(
            icon_name="document-open-recent-symbolic", title=empty_title, description=empty_description)
        setattr(self, f"empty_{history_type}_history_page", empty_page)

        history_stack = Gtk.Stack()
        history_stack.add_named(history_list, "history")
        history_stack.add_named(empty_page, "empty")
        setattr(self, f"{history_type}_history_stack", history_stack)

        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        for margin in ["top", "bottom", "start", "end"]:
            getattr(content_box, f"set_margin_{margin}")(16)
        content_box.append(history_stack)

        scrolled_window = Gtk.ScrolledWindow(
            hscrollbar_policy=Gtk.PolicyType.NEVER, vscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
            vexpand=True, child=content_box)

        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(header_bar)
        toolbar_view.set_content(scrolled_window)

        toast_overlay = Adw.ToastOverlay(child=toolbar_view)
        dialog.set_child(toast_overlay)
        setattr(self, f"{history_type}_history_toast_overlay", toast_overlay)

        return dialog

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
            text = item["filename" if history_type == "file" else "url"]

            row = Adw.ActionRow(
                title=text, subtitle=f"{_('Scanned on')}: {item['timestamp']}",
                title_lines=1, activatable=True)
            row.set_tooltip_text(text) if len(text) > 30 else ""
            row.connect("activated", self.on_history_item_activated, history_type, item)

            use_button = Gtk.Button(
                icon_name="object-select-symbolic", valign=Gtk.Align.CENTER, tooltip_text=_('Select'))
            use_button.add_css_class("flat")
            use_button.connect("clicked", self.on_history_item_activated, history_type, item)
            row.add_suffix(use_button)

            history_list.append(row)

        self.update_clear_button_state(history_type)

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

        self.update_history_list(history_type)
        self.update_clear_button_state(history_type)

        toast = Adw.Toast.new(_('History cleared'))
        toast.set_timeout(2)
        toast_overlay = getattr(self, f"{history_type}_history_toast_overlay")
        toast_overlay.add_toast(toast)

    def on_history_item_activated(self, widget, history_type, item):
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

        def fetch_report_task(task, source_object, task_data, cancellable):
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

        task = Gio.Task.new(self, None, None, None)
        task.run_in_thread(fetch_report_task)

    def show_history_results(self, analysis, analysis_type):
        self.current_analysis = analysis
        self.navigate_to_results()
        self.display_analysis_results(analysis)

    def show_history_error(self, error_message):
        self.navigate_to_main()
        self.show_error_dialog(_('Error'), error_message)

    def on_file_drop(self, drop_target, value, x, y):
        if not (self.is_file_mode and self.view_stack.get_visible_child_name() == "main"):
            return False

        files = value.get_files()
        if files:
            file = files[0]
            file_path = file.get_path()
            if file_path and exists(file_path) and access(file_path, R_OK):
                self.selected_file = file
                self.update_ui_state()
                return True
        return False

    def get_virustotal_url(self, analysis) -> str:
        if isinstance(analysis, FileAnalysis) and analysis.file_id:
            return f"https://www.virustotal.com/gui/file/{analysis.file_id}"
        elif isinstance(analysis, URLAnalysis) and analysis.url_id:
            return f"https://www.virustotal.com/gui/url/{analysis.url_id}"
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
