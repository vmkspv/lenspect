# results_display.py
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

from gi.repository import Adw, Gtk, GLib
from ..vt_provider import FileAnalysis

class ResultsDisplay:
    def __init__(self, window):
        self.window = window
        self.pending_sections = []

    def display_analysis(self, analysis):
        self.setup_detection_display(self.window.detection_row, self.window.detection_icon,
                                     *self.get_detection_status(analysis))
        self.setup_info_row_widgets(analysis)
        self.clear_results_details()

        if isinstance(analysis, FileAnalysis):
            self.window.info_row.set_title(GLib.markup_escape_text(analysis.file_name))
            self.window.info_row.set_subtitle(
                f"{analysis.formatted_size} • {analysis.last_analysis_date}")

            community_score_style = "bad-value" if analysis.community_score < 0 else None

            self.add_analysis_section(_('File Information'), [
                (_('Filename'), analysis.file_name),
                (_('Known Filename'), analysis.meaningful_name),
                (_('Size'), analysis.formatted_size),
                (_('Type'), analysis.file_type),
                (_('First Submission'), analysis.first_submission_date),
                (_('Last Analysis'), analysis.last_analysis_date),
                (_('Times Submitted'), str(analysis.times_submitted)),
                (_('Community Score'), str(analysis.community_score), community_score_style),
            ])
        else:
            url_display = analysis.url
            if len(url_display) > 45:
                url_display = url_display[:42] + "…"

            self.window.info_row.set_title(GLib.markup_escape_text(analysis.title))
            self.window.info_row.set_subtitle(
                f"{GLib.markup_escape_text(url_display)} • {analysis.last_analysis_date}")

            community_score_style = "bad-value" if analysis.community_score < 0 else None

            self.add_analysis_section(_('URL Information'), [
                (_('URL'), analysis.url),
                (_('Title'), analysis.title),
                (_('Final URL'), analysis.final_url),
                (_('First Submission'), analysis.first_submission_date),
                (_('Last Analysis'), analysis.last_analysis_date),
                (_('Times Submitted'), str(analysis.times_submitted)),
                (_('Community Score'), str(analysis.community_score), community_score_style),
            ])

            redirect_chain = analysis.get_redirect_chain()
            if redirect_chain:
                if redirect_chain[0].rstrip('/') == analysis.url.rstrip('/'):
                    redirect_chain = redirect_chain[1:]
                if redirect_chain:
                    self.add_analysis_section(_('Redirection Chain'), [
                        (f"{_('Redirect')} {i+1}", url)
                        for i, url in enumerate(redirect_chain)
                    ])

            categories = analysis.get_categories()
            if categories:
                category_items = sorted([(vendor, category) for vendor, category in categories.items()],
                                        key=lambda x: x[0].lower())
                self.add_analysis_section(_('Categories'), category_items)

        self.add_detection_statistics(analysis)
        self.add_threat_detections(analysis)
        self.add_sandbox_verdicts(analysis)
        self.add_crowdsourced_ai(analysis)
        self.arrange_sections()

    def get_file_hashes(self):
        hashes = self.window.current_analysis.get_hashes()
        return "\n".join([f"{name}: {value}" for name, value in hashes if value])

    def display_folder(self, folder, results):
        count = len(self.window.folder_files)
        self.window.folder_info_row.set_title(GLib.markup_escape_text(folder.get_basename()))
        self.window.folder_info_row.set_subtitle(ngettext('{} file', '{} files', count).format(count))

        threat_count, status = self.window.report.format_folder_detection(results)
        title = _('Threats Detected') if threat_count else _('No Threats Detected')
        self.setup_detection_display(self.window.folder_detection_row,
                                     self.window.folder_detection_icon,
                                     title, status, not threat_count)

        self.window.folder_files_list.remove_all()
        for name, analysis, error in results:
            row = Adw.ActionRow(title=GLib.markup_escape_text(name), title_lines=1)
            if len(name) > 35:
                row.set_tooltip_text(name)

            if analysis:
                title, subtitle, is_clean = self.get_detection_status(analysis)
                icon = Gtk.Image(tooltip_text=title)
                self.set_status_icon(icon, is_clean)
                row.set_subtitle(GLib.markup_escape_text(subtitle))
                row.set_activatable(True)
                row.connect("activated", lambda r, a=analysis: self.window.open_folder_item(a))

                arrow = Gtk.Image(icon_name="go-next-symbolic")
                arrow.add_css_class("dimmed")
                row.add_suffix(arrow)
            else:
                icon = Gtk.Image(icon_name="dialog-warning-symbolic")
                icon.add_css_class("warning")
                row.set_subtitle(GLib.markup_escape_text(error))

            row.add_prefix(icon)
            self.window.folder_files_list.append(row)

    def get_detection_status(self, analysis):
        title = _('No Threats Detected') if analysis.is_clean else _('Threats Detected')
        return title, self.window.report.format_detection(analysis), analysis.is_clean

    def setup_detection_display(self, row, icon, title, subtitle, is_clean):
        row.set_title(title)
        row.set_subtitle(GLib.markup_escape_text(subtitle))
        self.set_status_icon(icon, is_clean)

    def set_status_icon(self, icon, is_clean):
        icon.set_from_icon_name("security-high-symbolic" if is_clean else "security-low-symbolic")
        icon.remove_css_class("error" if is_clean else "success")
        icon.add_css_class("success" if is_clean else "error")

    def setup_info_row_widgets(self, analysis):
        self.window.copy_hashes_button.set_visible(isinstance(analysis, FileAnalysis))

        badge = self.window.http_status_badge

        for css_class in ["accent", "error", "success"]:
            badge.remove_css_class(css_class)

        if isinstance(analysis, FileAnalysis) or not analysis.http_response_code:
            badge.set_visible(False)
            return

        status = analysis.http_response_code
        badge.set_label(str(status))
        badge.add_css_class({2: "success", 3: "accent", 4: "error", 5: "error"}
                            .get(status // 100, "accent"))
        badge.set_visible(True)

    def add_detection_statistics(self, analysis):
        malicious_style = "bad-value" if analysis.malicious_count > 0 else None
        suspicious_style = "warning-value" if analysis.suspicious_count > 0 else None

        self.add_analysis_section(_('Detection Statistics'), [
            (_('Malicious'), str(analysis.malicious_count), malicious_style),
            (_('Suspicious'), str(analysis.suspicious_count), suspicious_style),
            (_('Clean'), str(analysis.harmless_count)),
            (_('Undetected'), str(analysis.undetected_count)),
            (_('Total Vendors'), str(analysis.total_vendors)),
        ])

    def add_sandbox_verdicts(self, analysis):
        if not isinstance(analysis, FileAnalysis):
            return
        sandbox_results = analysis.get_sandbox_verdicts()
        if sandbox_results:
            self.add_analysis_section(_('Sandbox Verdicts'), sandbox_results, use_property_style=False)

    def add_crowdsourced_ai(self, analysis):
        if not isinstance(analysis, FileAnalysis):
            return
        ai_results = analysis.get_ai_results()
        if ai_results:
            self.add_ai_section(ai_results)

    def add_threat_detections(self, analysis):
        if analysis.threat_count > 0:
            detections = analysis.get_detections()
            detection_items = sorted([
                (vendor, detection)
                for vendor, detection in detections.items()], key=lambda x: x[0].lower())
            self.add_analysis_section(_('Threat Detections'), detection_items, use_property_style=False)

    def clear_results_details(self):
        self.pending_sections = []
        for column in (self.window.results_column_left, self.window.results_column_right):
            child = column.get_first_child()
            while child:
                next_child = child.get_next_sibling()
                column.remove(child)
                child = next_child

    def add_analysis_section(self, section_title: str, items: list, use_property_style=True):
        section_group = Adw.PreferencesGroup(title=section_title)
        section_group.add_css_class("boxed-list")

        for item in items:
            if not isinstance(item, tuple) or len(item) not in (2, 3):
                continue
            title, value, *extra = item
            if not value:
                continue
            style_class = extra[0] if extra else None
            row = self.create_copyable_row(title, value, use_property_style, style_class)
            section_group.add(row)

        self.pending_sections.append(section_group)

    def add_ai_section(self, items: list):
        section_group = Adw.PreferencesGroup(title=_('Crowdsourced AI'))
        section_group.add_css_class("boxed-list")

        for source, verdict, analysis in items:
            row = Adw.ExpanderRow(
                title=GLib.markup_escape_text(source),
                subtitle=GLib.markup_escape_text(verdict.capitalize()) if verdict else "")

            label = Gtk.Label(
                label=analysis, wrap=True, xalign=0, selectable=True,
                margin_start=12, margin_end=12, margin_top=6, margin_bottom=12)
            row.add_row(label)
            section_group.add(row)

        self.pending_sections.append(section_group)

    def arrange_sections(self):
        split_index = (len(self.pending_sections) + 1) // 2
        for section_group in self.pending_sections[:split_index]:
            self.window.results_column_left.append(section_group)
        for section_group in self.pending_sections[split_index:]:
            self.window.results_column_right.append(section_group)
        self.pending_sections = []

    def create_copyable_row(self, title: str, value: str, use_property_style, style_class=None):
        safe_title = GLib.markup_escape_text(title)
        safe_value = GLib.markup_escape_text(value)
        row = Adw.ActionRow(title=safe_title, subtitle=safe_value, subtitle_selectable=True)

        if use_property_style: row.add_css_class("property")
        if style_class: row.add_css_class(style_class)

        copy_button = Gtk.Button(
            icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER, tooltip_text=_('Copy'))
        copy_button.add_css_class("flat")
        copy_button.connect("clicked", self.window.on_copy_clicked, value)

        row.add_suffix(copy_button)
        return row
