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
        dialog_attr = f"{history_type}_history_dialog"
        if not getattr(self.window, dialog_attr, None):
            setattr(self.window, dialog_attr, self.create_dialog(history_type))

        self.update_list(history_type)

        dialog = getattr(self.window, dialog_attr)
        dialog.present(self.window)

    def create_dialog(self, history_type):
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

        setattr(self.window, f"{history_type}_clear_button", clear_button)

        history_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        history_list.add_css_class("boxed-list")
        setattr(self.window, f"{history_type}_history_list", history_list)

        empty_title = _('No History')
        empty_description = (
            _('Your scanned files will appear here') if history_type == "file"
            else _('Your scanned URLs will appear here')
        )
        empty_page = Adw.StatusPage(
            icon_name="document-open-recent-symbolic", title=empty_title, description=empty_description)
        setattr(self.window, f"empty_{history_type}_history_page", empty_page)

        history_stack = Gtk.Stack()
        history_stack.add_named(history_list, "history")
        history_stack.add_named(empty_page, "empty")
        setattr(self.window, f"{history_type}_history_stack", history_stack)

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
        setattr(self.window, f"{history_type}_history_toast_overlay", toast_overlay)

        return dialog

    def update_list(self, history_type):
        history_list = getattr(self.window, f"{history_type}_history_list")
        history_stack = getattr(self.window, f"{history_type}_history_stack")
        history_data = getattr(self.window, f"{history_type}_history")

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
            row.connect("activated", self.on_item_activated, history_type, item)

            use_button = Gtk.Button(
                icon_name="object-select-symbolic", valign=Gtk.Align.CENTER, tooltip_text=_('Select'))
            use_button.add_css_class("flat")
            use_button.connect("clicked", self.on_item_activated, history_type, item)
            row.add_suffix(use_button)

            history_list.append(row)

        self.update_clear_button_state(history_type)

    def update_clear_button_state(self, history_type):
        button_name = f"{history_type}_clear_button"
        history_data = getattr(self.window, f"{history_type}_history")
        if hasattr(self.window, button_name):
            button = getattr(self.window, button_name)
            button.set_sensitive(bool(history_data))

    def on_clear_history(self, history_type):
        history_data = getattr(self.window, f"{history_type}_history")
        history_data.clear()
        self.window.save_history(history_type)

        self.update_list(history_type)
        self.update_clear_button_state(history_type)

        toast = Adw.Toast.new(_('History cleared'))
        toast.set_timeout(2)
        toast_overlay = getattr(self.window, f"{history_type}_history_toast_overlay")
        toast_overlay.add_toast(toast)

    def on_item_activated(self, widget, history_type, item):
        if widget is not None:
            dialog = getattr(self.window, f"{history_type}_history_dialog", None)
            if dialog:
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

        self.window.scanning_page.set_description(_('Fetching existing analysis...'))

        def fetch_report_task(task, source_object, task_data, cancellable):
            try:
                analysis = report_method(report_key)
                if analysis:
                    if history_type == "file":
                        analysis.original_filename = item["filename"]
                    GLib.idle_add(self.show_results, analysis, history_type)
                else:
                    GLib.idle_add(self.show_error, not_found_message)
            except Exception as e:
                GLib.idle_add(self.show_error, str(e))

        task = Gio.Task.new(self.window, None, None, None)
        task.run_in_thread(fetch_report_task)

    def show_results(self, analysis, analysis_type):
        self.window.current_analysis = analysis
        self.window.navigate_to_results()
        self.window.results_display.display_analysis(analysis)

        if not self.window.is_active():
            self.window.toast.send_scan_complete(analysis.is_clean, analysis.threat_count)

    def show_error(self, error_message: str):
        self.window.navigate_to_main()
        self.window.show_error_dialog(_('Error'), error_message)

        if not self.window.is_active():
            self.window.toast.send_scan_failed()
