# history_dialog.py
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

class HistoryDialog:
    def __init__(self, window):
        self.window = window

    def show_dialog(self, history_type):
        dialog = Adw.Dialog()
        dialog.set_title(_('File History') if history_type == "file" else _('URL History'))
        dialog.set_content_width(350)
        dialog.set_content_height(400)

        history_data = getattr(self.window, f"{history_type}_history")

        history_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        history_list.add_css_class("boxed-list-separate")
        history_list.add_css_class("history-list")

        empty_page = Adw.StatusPage(
            icon_name="document-open-recent-symbolic",
            title=_('No History'),
            description=(
                _('Your scanned files will appear here') if history_type == "file"
                else _('Your scanned URLs will appear here')
            ))

        stack = Gtk.Stack()
        stack.add_named(history_list, "history")
        stack.add_named(empty_page, "empty")

        if history_data:
            stack.set_visible_child_name("history")
            for item in history_data:
                history_list.append(self.create_row(history_type, item, dialog))
        else:
            stack.set_visible_child_name("empty")

        content_box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            margin_top=16, margin_bottom=16, margin_start=16, margin_end=16)
        content_box.append(stack)

        scrolled = Gtk.ScrolledWindow(
            hscrollbar_policy=Gtk.PolicyType.NEVER, vscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
            vexpand=True, child=content_box)

        toast_overlay = Adw.ToastOverlay()

        clear_button = Gtk.Button(
            icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER,
            tooltip_text=_('Clear'), sensitive=bool(history_data))
        clear_button.add_css_class("flat")
        clear_button.add_css_class("error")
        clear_button.connect("clicked", lambda btn: self.on_clear(
            history_type, history_list, stack, clear_button, toast_overlay))

        header_bar = Adw.HeaderBar()
        header_bar.pack_start(clear_button)

        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(header_bar)
        toolbar_view.set_content(scrolled)

        toast_overlay.set_child(toolbar_view)
        dialog.set_child(toast_overlay)
        dialog.present(self.window)

    def create_row(self, history_type, item, dialog):
        text = item["filename" if history_type == "file" else "url"]

        row = Adw.ActionRow(
            title=GLib.markup_escape_text(text), subtitle=f"{_('Scanned on')}: {item['timestamp']}",
            title_lines=1, activatable=True)
        if len(text) > 35:
            row.set_tooltip_text(text)
        row.connect("activated", lambda r: self.on_item_activated(r, history_type, item, dialog))

        is_clean = item.get("is_clean", True)
        status_icon = Gtk.Image(
            icon_name="security-high-symbolic" if is_clean else "security-low-symbolic")
        status_icon.add_css_class("success" if is_clean else "error")
        status_icon.set_tooltip_text(_('No Threats Detected') if is_clean else _('Threats Detected'))
        row.add_prefix(status_icon)

        arrow = Gtk.Image(icon_name="go-next-symbolic")
        arrow.add_css_class("dimmed")
        row.add_suffix(arrow)

        return row

    def on_clear(self, history_type, history_list, stack, clear_button, toast_overlay):
        history_data = getattr(self.window, f"{history_type}_history")
        history_data.clear()
        self.window.save_history(history_type)

        while history_list.get_first_child():
            history_list.remove(history_list.get_first_child())
        stack.set_visible_child_name("empty")
        clear_button.set_sensitive(False)

        toast = Adw.Toast.new(_('History cleared'))
        toast.set_timeout(2)
        toast_overlay.add_toast(toast)

    def on_item_activated(self, widget, history_type, item, dialog=None):
        if dialog is not None:
            dialog.close()

        self.window.navigate_to_scanning()

        if history_type == "file":
            self.window.scanning_page.set_title(_('Loading File Report'))
            report_method = self.window.vt_service.get_file_report
            report_key = item["file_hash"]
            not_found_message = _('No report found for this file')
        else:
            self.window.scanning_page.set_title(_('Loading URL Report'))
            report_method = self.window.vt_service.get_url_report
            report_key = item["url"]
            not_found_message = _('No report found for this URL')

        self.window.scanning_page.set_description(_('Fetching existing analysis…'))
        self.window.progress_row.set_title(_('Checking for existing analysis…'))

        def fetch_report_task(task, source_object, task_data, cancellable):
            try:
                analysis = report_method(report_key)
                if analysis:
                    if history_type == "file":
                        analysis.original_filename = item["filename"]
                    GLib.idle_add(self.show_results, analysis)
                else:
                    GLib.idle_add(self.show_error, not_found_message)
            except Exception as e:
                GLib.idle_add(self.show_error, str(e))

        task = Gio.Task.new(self.window, None, None, None)
        task.run_in_thread(fetch_report_task)

    def show_results(self, analysis):
        self.window.current_analysis = analysis
        self.window.navigate_to_results()
        self.window.results_display.display_analysis(analysis)

        if not self.window.is_active():
            self.window.toast.send_scan_complete(analysis.is_clean, analysis.threat_count)

    def show_error(self, error_message: str):
        self.window.navigate_to_main()
        self.window.show_error_banner(error_message)

        if not self.window.is_active():
            self.window.toast.send_scan_failed()
