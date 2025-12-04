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

    def display_analysis(self, analysis):
        self.setup_detection_display(analysis)
        self.clear_results_details()

        if isinstance(analysis, FileAnalysis):
            filename = analysis.file_name or self.window.selected_file.get_basename()
            file_size = analysis.formatted_size if analysis.file_size > 0 else _('Unknown size')
            file_type = analysis.file_type or _('Unknown type')

            self.window.info_row.set_title(GLib.markup_escape_text(filename))
            self.window.info_row.set_subtitle(
                f"{file_size} • {analysis.last_analysis_date}")

            self.add_section(_('File Information'), [
                (_('Filename'), filename),
                (_('Size'), file_size),
                (_('Type'), file_type),
                (_('First Submission'), analysis.first_submission_date),
                (_('Last Analysis'), analysis.last_analysis_date),
                (_('Times Submitted'), str(analysis.times_submitted)),
            ])
        else:
            url_title = analysis.title or _('Untitled')
            url_display = analysis.url
            if len(url_display) > 45:
                url_display = url_display[:42] + "..."

            self.window.info_row.set_title(GLib.markup_escape_text(url_title))
            self.window.info_row.set_subtitle(
                f"{url_display} • {analysis.last_analysis_date}")

            self.add_section(_('URL Information'), [
                (_('URL'), analysis.url),
                (_('Title'), url_title),
                (_('Final URL'), analysis.final_url),
                (_('First Submission'), analysis.first_submission_date),
                (_('Last Analysis'), analysis.last_analysis_date),
                (_('Times Submitted'), str(analysis.times_submitted)),
                (_('Community Score'), str(analysis.community_score)),
            ])

            redirect_chain = analysis.get_redirect_chain()
            if redirect_chain:
                self.add_section(_('Redirection Chain'), [
                    (f"{_('Redirect')} {i+1}", url)
                    for i, url in enumerate(redirect_chain)
                ])

            categories = analysis.get_categories()
            if categories:
                category_items = sorted([(vendor, category) for vendor, category in categories.items()],
                                        key=lambda x: x[0].lower())
                self.add_section(_('Categories'), category_items)

        self.add_detection_statistics(analysis)
        self.add_threat_detections(analysis)

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

        self.window.detection_row.set_title(title)
        self.window.detection_row.set_subtitle(subtitle)
        self.window.detection_icon.set_from_icon_name(icon)
        self.window.detection_icon.remove_css_class(css_remove)
        self.window.detection_icon.add_css_class(css_class)

    def add_detection_statistics(self, analysis):
        self.add_section(_('Detection Statistics'), [
            (_('Malicious'), str(analysis.malicious_count)),
            (_('Suspicious'), str(analysis.suspicious_count)),
            (_('Clean'), str(analysis.harmless_count)),
            (_('Undetected'), str(analysis.undetected_count)),
            (_('Total Vendors'), str(analysis.total_vendors)),
        ])

    def add_threat_detections(self, analysis):
        if analysis.threat_count > 0:
            detections = analysis.get_detections()
            detection_items = sorted([
                (vendor, detection)
                for vendor, detection in detections.items()], key=lambda x: x[0].lower())
            self.add_section(_('Threat Detections'), detection_items, use_property_style=False)

    def clear_results_details(self):
        child = self.window.results_group.get_first_child()
        while child:
            next_child = child.get_next_sibling()
            self.window.results_group.remove(child)
            child = next_child

    def add_section(self, section_title: str, items: list, use_property_style=True):
        section_group = Adw.PreferencesGroup()
        section_group.set_title(section_title)
        section_group.add_css_class("boxed-list")

        for title, value in items:
            row = self.create_copyable_row(title, value, use_property_style)
            section_group.add(row)

        self.window.results_group.append(section_group)

    def create_copyable_row(self, title: str, value: str, use_property_style):
        safe_title = GLib.markup_escape_text(title)
        safe_value = GLib.markup_escape_text(value)
        row = Adw.ActionRow(title=safe_title, subtitle=safe_value, subtitle_selectable=True)

        if use_property_style: row.add_css_class("property")

        if ((title == "Community Score" and int(value) < 0) or
            (title == "Malicious" and int(value) > 0)): row.add_css_class("bad-value")
        elif title == "Suspicious" and int(value) > 0: row.add_css_class("warning-value")

        copy_button = Gtk.Button(
            icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER, tooltip_text=_('Copy'))
        copy_button.add_css_class("flat")
        copy_button.connect("clicked", self.window.on_copy_clicked, value)

        row.add_suffix(copy_button)
        return row
