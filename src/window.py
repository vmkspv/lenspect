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

from gi.repository import Adw, Gtk, Gio, GLib
from .vt_provider import FileAnalysis, URLAnalysis, VirusTotalService

from .core.config_manager import ConfigManager
from .core.report_composer import ReportComposer
from .core.toast_manager import ToastManager

from .ui.dialog_manager import DialogManager
from .ui.file_drop_handler import FileDropHandler
from .ui.history_dialog import HistoryDialog
from .ui.results_display import ResultsDisplay

@Gtk.Template(resource_path='/io/github/vmkspv/lenspect/window.ui')
class LenspectWindow(Adw.ApplicationWindow):
    __gtype_name__ = 'LenspectWindow'

    toast_overlay = Gtk.Template.Child()
    navigation_view = Gtk.Template.Child()

    main_nav_page = Gtk.Template.Child()
    scanning_nav_page = Gtk.Template.Child()
    results_nav_page = Gtk.Template.Child()

    drag_revealer = Gtk.Template.Child()
    error_banner = Gtk.Template.Child()
    main_page = Gtk.Template.Child()
    api_key_entry = Gtk.Template.Child()
    quota_label = Gtk.Template.Child()
    mode_stack = Gtk.Template.Child()
    file_selection_row = Gtk.Template.Child()
    url_entry = Gtk.Template.Child()
    scan_button = Gtk.Template.Child()

    scanning_page = Gtk.Template.Child()
    progress_row = Gtk.Template.Child()

    info_row = Gtk.Template.Child()
    copy_hashes_button = Gtk.Template.Child()
    http_status_badge = Gtk.Template.Child()
    detection_row = Gtk.Template.Child()
    detection_icon = Gtk.Template.Child()
    results_group = Gtk.Template.Child()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        Gtk.IconTheme.get_for_display(
            self.get_display()).add_resource_path('/io/github/vmkspv/lenspect/icons')

        self.vt_service = VirusTotalService(self.get_application().version)
        self.config = ConfigManager()
        self.report = ReportComposer()
        self.toast = ToastManager(self.get_application())
        self.dialog = DialogManager(self)
        self.history_dialog = HistoryDialog(self)
        self.results_display = ResultsDisplay(self)

        self.is_file_mode = True
        self.selected_file = None
        self.current_url = None
        self.current_task = None
        self.current_analysis = None

        self.file_history = []
        self.url_history = []

        self.load_api_key()
        self.load_history()
        self.connect_signals()
        self.setup_file_drop()
        self.update_ui_state()
        self.update_quota_data()
        self.navigate_to_main()

        GLib.idle_add(self.set_initial_focus)
        GLib.idle_add(self.check_search_provider)

    def connect_signals(self):
        self.connect("close-request", self.on_close_request)
        self.navigation_view.connect("popped", self.on_navigation_popped)
        self.api_key_entry.connect("notify::text", self.on_api_key_changed)
        self.api_key_entry.connect("activate", self.on_api_key_activate)
        self.mode_stack.connect("notify::visible-child-name", self.on_mode_changed)
        self.url_entry.get_delegate().connect("activate", self.on_url_activate)
        self.vt_service.connect("analysis-progress", self.on_analysis_progress)
        self.vt_service.connect("file-analysis-completed", self.on_analysis_completed)
        self.vt_service.connect("url-analysis-completed", self.on_analysis_completed)
        self.vt_service.connect("analysis-failed", self.on_analysis_failed)

    def setup_file_drop(self):
        self.file_drop_handler = FileDropHandler(self)

    def set_initial_focus(self):
        if not self.vt_service.has_api_key:
            self.api_key_entry.grab_focus()
        else:
            self.set_focus(None)
            self.api_key_entry.select_region(0, 0)

    def load_api_key(self):
        api_key = self.config.load_api_key()
        if api_key:
            self.api_key_entry.set_text(api_key)
            self.vt_service.api_key = api_key

    def save_api_key(self, api_key):
        self.config.save_api_key(api_key)

    def load_history(self):
        for history_type in ["file", "url"]:
            history_data = self.config.load_history(history_type)
            setattr(self, f"{history_type}_history", history_data)

    def save_history(self, history_type):
        history_data = getattr(self, f"{history_type}_history")
        self.config.save_history(history_type, history_data)

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
        daily_limit = quotas.get("api_requests_daily", {}).get("user", {}).get("allowed", 0)
        monthly_limit = quotas.get("api_requests_monthly", {}).get("user", {}).get("allowed", 0)

        today = GLib.DateTime.new_now_local().format("%Y-%m-%d")
        daily_used = sum(usage.get("daily", {}).get(today, {}).values())
        monthly_used = sum(usage.get("total", {}).values())

        daily_limit_str = str(daily_limit)
        monthly_limit_str = "∞" if monthly_limit >= 1000000000 else str(monthly_limit)

        tooltip = (
            f"{_('Daily')}: {daily_used}/{daily_limit_str}\n"
            f"{_('Monthly')}: {monthly_used}/{monthly_limit_str}"
        )
        self.quota_label.set_tooltip_text(tooltip)
        self.quota_label.set_cursor_from_name("help")
        self.quota_label.set_visible(True)

    def update_ui_state(self):
        has_api_key = bool(self.vt_service.api_key)
        is_scanning = self.current_task is not None

        current_page = self.mode_stack.get_visible_child_name()
        self.is_file_mode = (current_page == "file")

        if self.is_file_mode:
            # Translators: Try to keep this string short to prevent line breaks in the UI.
            self.main_page.set_title(_('Scan Files for Malware'))
            # Translators: Try to keep this string short to prevent line breaks in the UI.
            self.main_page.set_description(_('Use VirusTotal to check files for security threats'))
        else:
            # Translators: Try to keep this string short to prevent line breaks in the UI.
            self.main_page.set_title(_('Scan URLs for Threats'))
            # Translators: Try to keep this string short to prevent line breaks in the UI.
            self.main_page.set_description(_('Use VirusTotal to check URLs for malicious content'))

        if has_api_key:
            self.api_key_entry.remove_css_class("warning")

        has_valid_input = False
        if self.is_file_mode:
            has_valid_input = self.selected_file is not None
            self.update_file_selection_display()
        else:
            has_valid_input = bool(self.current_url and self.vt_service.validate_url(self.current_url))

        self.scan_button.set_sensitive(has_api_key and has_valid_input and not is_scanning)

    def show_error_banner(self, message: str):
        self.error_banner.set_title(message)
        self.error_banner.set_revealed(True)

        GLib.timeout_add_seconds(10, lambda: self.error_banner.set_revealed(False))

    def show_api_key_warning(self):
        if not self.vt_service.api_key:
            self.api_key_entry.add_css_class("warning")

    def on_api_key_changed(self, entry: Adw.PasswordEntryRow, param):
        api_key = entry.get_text().strip()
        self.vt_service.api_key = api_key
        self.save_api_key(api_key)
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

    def on_close_request(self, window):
        self.toast.withdraw_all()
        return False

    def show_toast(self, message: str):
        toast = Adw.Toast.new(message)
        toast.set_timeout(2)
        self.toast_overlay.add_toast(toast)

    @Gtk.Template.Callback()
    def on_file_selection_activated(self, *args):
        self.dialog.show_file_selection(self.on_file_selected)

    @Gtk.Template.Callback()
    def on_api_help_clicked(self, button):
        self.dialog.show_api_help()

    @Gtk.Template.Callback()
    def on_cancel_scan_clicked(self, button):
        self.cancel_scan()

    @Gtk.Template.Callback()
    def on_vt_button_clicked(self, *args):
        if self.current_analysis:
            vt_url = self.get_virustotal_url(self.current_analysis)
            if vt_url:
                Gtk.UriLauncher.new(vt_url).launch(self, None, None, None)

    def on_navigation_popped(self, navigation_view, page):
        visible_page = self.navigation_view.get_visible_page()

        if visible_page == self.main_nav_page:
            self.error_banner.set_revealed(False)
            self.reset_for_new_scan()

    @Gtk.Template.Callback()
    def on_scan_button_clicked(self, button):
        self.start_scan()

    @Gtk.Template.Callback()
    def on_new_scan_button_clicked(self, *args):
        self.navigate_to_main()

    @Gtk.Template.Callback()
    def on_rescan_button_clicked(self, *args):
        if isinstance(self.current_analysis, FileAnalysis):
            item = {
                "file_hash": self.current_analysis.file_id,
                "filename": self.current_analysis.file_name
            }
            self.history_dialog.on_item_activated(None, "file", item)
        else:
            item = {"url": self.current_analysis.url}
            self.history_dialog.on_item_activated(None, "url", item)

    def on_mode_changed(self, stack, *args):
        self.update_ui_state()

    @Gtk.Template.Callback()
    def on_url_changed(self, entry: Adw.EntryRow, *args):
        self.current_url = entry.get_text().strip() or None
        if self.current_url:
            self.show_api_key_warning()
        self.update_ui_state()

    @Gtk.Template.Callback()
    def on_url_paste_clicked(self, button):
        def paste(clipboard, result):
            try:
                if text := clipboard.read_text_finish(result):
                    self.url_entry.set_text(text)
            except Exception:
                pass
        self.get_clipboard().read_text_async(None, paste)

    def on_file_selected(self, file):
        self.selected_file = file
        self.show_api_key_warning()
        self.update_ui_state()

    def load_file_for_scan(self, file: Gio.File):
        self.on_file_selected(file)

        if self.vt_service.has_api_key:
            GLib.idle_add(self.start_file_scan)
        else:
            self.api_key_entry.grab_focus()

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
        while self.navigation_view.get_visible_page() != self.main_nav_page:
            self.navigation_view.pop()

    def navigate_to_scanning(self):
        if self.navigation_view.get_visible_page() != self.main_nav_page:
            self.navigate_to_main()

        if self.is_file_mode:
            title = _('Scanning File')
            description = _('Please wait for the file analysis...')
        else:
            title = _('Scanning URL')
            description = _('Please wait for the URL analysis...')
        self.scanning_page.set_title(title)
        self.scanning_page.set_description(description)

        self.navigation_view.push(self.scanning_nav_page)

    def navigate_to_results(self):
        self.navigation_view.replace([self.main_nav_page, self.results_nav_page])

    def reset_for_new_scan(self):
        self.selected_file = None
        self.current_url = None
        self.url_entry.set_text("")
        self.current_task = None
        self.current_analysis = None
        self.update_ui_state()

    def start_scan(self):
        if self.is_file_mode:
            self.start_file_scan()
        else:
            self.start_url_scan()

    def start_file_scan(self):
        file_path = self.selected_file.get_path()
        if not file_path:
            self.show_error_banner(_('Could not access the selected file'))
            return

        try:
            info = self.selected_file.query_info(
                "access::can-read", Gio.FileQueryInfoFlags.NONE, None)
            if not info.get_attribute_boolean("access::can-read"):
                self.show_error_banner(_('Cannot read the selected file'))
                return
        except GLib.Error:
            self.show_error_banner(_('Selected file no longer exists'))
            return

        self.current_task = self.vt_service.scan_file_async(file_path)
        self.navigate_to_scanning()
        self.update_ui_state()

    def start_url_scan(self):
        if not self.vt_service.validate_url(self.current_url):
            self.show_error_banner(_('Please enter a valid URL'))
            return

        self.current_task = self.vt_service.scan_url_async(self.current_url)
        self.navigate_to_scanning()
        self.update_ui_state()

    def on_analysis_progress(self, service: VirusTotalService, message: str):
        self.progress_row.set_title(message)

    def on_analysis_completed(self, service: VirusTotalService, analysis):
        analysis_type = "file" if isinstance(analysis, FileAnalysis) else "url"
        self.handle_analysis_completion(analysis, analysis_type)

    def handle_analysis_completion(self, analysis, analysis_type):
        self.current_task = None
        self.current_analysis = analysis

        if analysis_type == "file" and self.selected_file:
            file_hash = analysis.file_id
            filename = analysis.file_name or self.selected_file.get_basename()
            self.add_to_history("file", filename=filename, file_hash=file_hash)
        elif analysis_type == "url" and self.current_url:
            self.add_to_history("url", url=self.current_url)

        self.navigate_to_results()
        self.results_display.display_analysis(analysis)
        self.update_quota_data()

        if not self.is_active():
            self.toast.send_scan_complete(analysis.is_clean, analysis.threat_count)

    def on_analysis_failed(self, service: VirusTotalService, error_message: str):
        self.current_task = None
        self.navigate_to_main()
        self.update_ui_state()
        self.show_error_banner(error_message)
        self.update_quota_data()

        if not self.is_active():
            self.toast.send_scan_failed()

    def on_copy_clicked(self, button, text: str):
        self.get_clipboard().set(text)
        self.show_toast(_('Copied to clipboard'))

    def generate_report_text(self):
        if not self.current_analysis:
            return ""

        filename = None

        if isinstance(self.current_analysis, FileAnalysis):
            filename = (
                self.selected_file.get_basename()
                if self.selected_file else None
            )

        return self.report.generate_report(
            self.current_analysis,
            filename=filename
        )

    @Gtk.Template.Callback()
    def on_copy_all_clicked(self, button):
        report_text = self.generate_report_text()
        if report_text:
            self.on_copy_clicked(button, report_text)

    @Gtk.Template.Callback()
    def on_copy_hashes_clicked(self, button):
        hashes = self.results_display.get_file_hashes()
        if hashes:
            self.on_copy_clicked(button, hashes)

    @Gtk.Template.Callback()
    def on_export_clicked(self, button):
        if not self.current_analysis:
            return

        self.dialog.show_export_dialog(self.on_file_exported)

    def on_file_exported(self, file):
        report_text = self.generate_report_text()
        if report_text:
            file_path = file.get_path()
            if self.report.save_to_file(report_text, file_path):
                file_name = file.get_basename()
                self.show_toast(f"{_('Saved to')} {file_name}")
            else:
                self.show_toast(_('Failed to save report'))

    def add_to_history(self, history_type: str, **data):
        if "url" in data:
            data["url"] = self.vt_service.normalize_url(data["url"])
        history = self.file_history if history_type == "file" else self.url_history
        self.config.add_to_history(
            history_type, history, is_clean=self.current_analysis.is_clean, **data)

    def check_search_provider(self):
        result = self.config.check_search_provider(self.file_history, self.url_history)
        if result:
            history_type, item = result
            self.on_history_item_activated(None, history_type, item)
            return False
        return False

    @Gtk.Template.Callback()
    def on_file_history_clicked(self, button):
        self.history_dialog.show_dialog("file")

    @Gtk.Template.Callback()
    def on_url_history_clicked(self, button):
        self.history_dialog.show_dialog("url")

    def on_history_item_activated(self, widget, history_type, item):
        self.history_dialog.on_item_activated(widget, history_type, item)

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
