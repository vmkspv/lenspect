# yara_provider.py
#
# Copyright 2026 Vladimir Kosolapov
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

from io import BytesIO
from zipfile import ZipFile, BadZipFile

import yara
import gi

gi.require_version('Soup', '3.0')

from gi.repository import GObject, Gio, GLib, Soup
from .vt_provider import FileAnalysis

class YaraAnalysis(GObject.Object):
    __gtype_name__ = 'YaraAnalysis'

    def __init__(self, data: dict, **kwargs):
        super().__init__(**kwargs)
        self.data = data
        self.matches = data.get("matches", [])
        self.scan_date = GLib.DateTime.new_now_utc().format("%Y-%m-%d %H:%M:%S UTC")

    @GObject.Property(type=str, default="")
    def file_id(self) -> str:
        return self.data.get("sha256", "")

    @GObject.Property(type=str, default="")
    def file_path(self) -> str:
        return self.data.get("path", "")

    @GObject.Property(type=str, default="")
    def file_name(self) -> str:
        return GLib.path_get_basename(self.file_path) if self.file_path else ""

    @GObject.Property(type=int, default=0)
    def file_size(self) -> int:
        return self.data.get("size", 0)

    @GObject.Property(type=str, default="")
    def formatted_size(self) -> str:
        return FileAnalysis({"attributes": {"size": self.file_size}}).formatted_size

    @GObject.Property(type=str, default="")
    def file_type(self) -> str:
        return self.data.get("type") or _('Unknown type')

    @GObject.Property(type=str, default="")
    def rules_name(self) -> str:
        return self.data.get("rules_name", "")

    @GObject.Property(type=int, default=0)
    def rules_count(self) -> int:
        return self.data.get("rules_count", 0)

    @GObject.Property(type=int, default=0)
    def malicious_count(self) -> int:
        return sum(1 for match in self.matches if self.get_score(match) >= 70)

    @GObject.Property(type=int, default=0)
    def suspicious_count(self) -> int:
        return self.threat_count - self.malicious_count

    @GObject.Property(type=int, default=0)
    def threat_count(self) -> int:
        return len(self.matches)

    @GObject.Property(type=bool, default=True)
    def is_clean(self) -> bool:
        return self.threat_count == 0

    @GObject.Property(type=str, default="")
    def threat_label(self) -> str:
        return max(self.matches, key=self.get_score).rule if self.matches else ""

    @GObject.Property(type=str, default="Unknown")
    def last_analysis_date(self) -> str:
        return self.scan_date

    def get_score(self, match) -> int:
        try:
            return int(match.meta.get("score", 100))
        except (TypeError, ValueError):
            return 100

    def get_hashes(self) -> list[tuple[str, str]]:
        return [
            ('MD5', self.data.get('md5', '')),
            ('SHA1', self.data.get('sha1', '')),
            ('SHA256', self.data.get('sha256', '')),
        ]

    def get_detections(self) -> dict[str, str]:
        detections = {}

        for match in self.matches:
            description = match.meta.get("description", "")
            detections[match.rule] = (description.strip() if isinstance(description, str)
                                      and description.strip() else _('Matched rule'))

        return detections

    def get_rule_details(self) -> list[tuple[str, list[tuple]]]:
        results = []

        for match in sorted(self.matches, key=self.get_score, reverse=True):
            meta = {key: str(value).strip() for key, value in match.meta.items()}
            strings = " • ".join(
                f"{string.identifier}: " + ", ".join(
                    f"0x{instance.offset:X}" for instance in string.instances[:3]) +
                ("…" if len(string.instances) > 3 else "")
                for string in match.strings)

            score = meta.get("score", "")
            score_style = None
            if score.lstrip("-").isdigit():
                number = int(score)
                score_style = ("bad-value" if number >= 70 else
                               "warning-value" if number >= 40 else None)

            results.append((match.rule, [
                (_('Status'), _('Malicious') if self.get_score(match) >= 70
                 else _('Suspicious')),
                (_('Score'), score, score_style),
                (_('Author'), meta.get("author", "")),
                (_('Created'), meta.get("date", "")),
                (_('Modified'), meta.get("modified", "")),
                (_('Reference'), meta.get("reference", "")),
                (_('Source'), meta.get("source_url", "")),
                (_('Tags'), ", ".join(match.tags)),
                (_('Matched Strings'), strings),
            ]))

        return results

class YaraService(GObject.Object):
    __gtype_name__ = 'YaraService'
    __gsignals__ = {
        "analysis-progress": (GObject.SignalFlags.RUN_FIRST, None, (str,)),
        "folder-progress": (GObject.SignalFlags.RUN_FIRST, None, (int, int)),
        "file-analysis-completed": (GObject.SignalFlags.RUN_FIRST, None, (YaraAnalysis,)),
        "folder-analysis-completed": (GObject.SignalFlags.RUN_FIRST, None, (object,)),
        "analysis-failed": (GObject.SignalFlags.RUN_FIRST, None, (str,)),
    }

    def __init__(self, version: str, **kwargs):
        super().__init__(**kwargs)
        self.rules = None
        self.rules_key = None
        self.rules_count = 0
        self.base_url = "https://github.com/YARAHQ/yara-forge/releases/latest/download"
        self.rules_dir = GLib.build_filenamev([GLib.get_user_data_dir(), "lenspect", "yara"])
        self.session = Soup.Session()
        self.session.set_user_agent(f"Lenspect/{version}")

    def get_rules_name(self, package: str) -> str:
        return f"YARA Forge {package.capitalize()}"

    def get_package_path(self, package: str) -> str:
        return GLib.build_filenamev([self.rules_dir, f"{package}.yar"])

    def get_rules_info(self, package: str) -> tuple[int, int]:
        gfile = Gio.File.new_for_path(self.get_package_path(package))
        try:
            info = gfile.query_info("time::modified", Gio.FileQueryInfoFlags.NONE, None)
            modified = info.get_attribute_uint64("time::modified")
            if (gfile.get_path(), modified) == self.rules_key:
                return self.rules_count, modified
            success, contents, _etag = gfile.load_contents(None)
        except GLib.Error:
            return 0, 0

        count = sum(1 for line in contents.splitlines()
                    if line.lstrip().startswith((b"rule ", b"private rule ", b"global rule ")))
        return count, modified

    def download_rules(self, package: str, cancellable: Gio.Cancellable | None = None):
        message = Soup.Message.new("GET", f"{self.base_url}/yara-forge-rules-{package}.zip")

        try:
            response_bytes = self.session.send_and_read(message, cancellable)
        except GLib.Error as e:
            raise yara.Error(f"{_('Network error')}: {e.message}")

        if message.get_status() != 200:
            raise yara.Error(f"{_('Failed to download rules')}: HTTP {message.get_status()}")

        try:
            with ZipFile(BytesIO(response_bytes.get_data())) as archive:
                name = next(name for name in archive.namelist() if name.endswith(".yar"))
                contents = archive.read(name)
        except (BadZipFile, StopIteration):
            raise yara.Error(_('Invalid rules package'))

        try:
            GLib.mkdir_with_parents(self.rules_dir, 0o755)
            Gio.File.new_for_path(self.get_package_path(package)).replace_contents(
                contents, None, False, Gio.FileCreateFlags.NONE, cancellable)
        except GLib.Error as e:
            raise yara.Error(f"{_('Failed to save rules')}: {e.message}")
        self.rules_key = None

    def load_rules(self, package: str, cancellable: Gio.Cancellable | None,
                   emit_progress) -> dict:
        path = self.get_package_path(package)
        if not GLib.file_test(path, GLib.FileTest.IS_REGULAR):
            emit_progress(_('Downloading rules…'))
            self.download_rules(package, cancellable)

        count, modified = self.get_rules_info(package)
        if not count:
            raise yara.Error(_('No YARA rules found'))

        rules_key = (path, modified)
        if rules_key != self.rules_key:
            emit_progress(_('Compiling rules…'))
            self.rules = yara.compile(filepath=path)
            self.rules_key = rules_key
            self.rules_count = count

        return {"rules_name": self.get_rules_name(package), "rules_count": count}

    def calculate_file_hashes(self, file_path: str,
                              cancellable: Gio.Cancellable | None = None) -> dict[str, str]:
        checksums = {
            "md5": GLib.Checksum.new(GLib.ChecksumType.MD5),
            "sha1": GLib.Checksum.new(GLib.ChecksumType.SHA1),
            "sha256": GLib.Checksum.new(GLib.ChecksumType.SHA256),
        }
        stream = Gio.File.new_for_path(file_path).read(cancellable)
        try:
            while (chunk := stream.read_bytes(8192, cancellable)).get_size() > 0:
                for checksum in checksums.values():
                    checksum.update(chunk.get_data())
        finally:
            stream.close(cancellable)
        return {name: checksum.get_string() for name, checksum in checksums.items()}

    def run_async(self, thread_func, completed_signal: str, task_data=None):
        def task_func(task, source_object, task_data, cancellable):
            def emit_progress(message):
                if not (cancellable and cancellable.is_cancelled()):
                    GLib.idle_add(lambda: self.emit("analysis-progress", message))

            def check_cancelled():
                return cancellable and cancellable.is_cancelled()

            try:
                analysis = thread_func(cancellable, emit_progress, check_cancelled)
                if analysis is None or check_cancelled():
                    return
                GLib.idle_add(lambda: not check_cancelled() and self.emit(completed_signal, analysis))
                task.return_value(analysis)
            except Exception as e:
                if not check_cancelled():
                    error_message = str(e)
                    GLib.idle_add(lambda: not check_cancelled() and
                                  self.emit("analysis-failed", error_message))

        cancellable = Gio.Cancellable.new()
        task = Gio.Task.new(self, cancellable, None, None)
        task.set_task_data(task_data)
        task.run_in_thread(task_func)

        return task

    def scan_file(self, file_path: str, rules_info: dict, cancellable: Gio.Cancellable | None,
                  emit_progress, check_cancelled) -> YaraAnalysis | None:
        info = Gio.File.new_for_path(file_path).query_info(
            "standard::size,standard::content-type", Gio.FileQueryInfoFlags.NONE, cancellable)
        content_type = info.get_content_type()

        emit_progress(_('Calculating file hash…'))
        if check_cancelled():
            return None

        hashes = self.calculate_file_hashes(file_path, cancellable)

        emit_progress(_('Analyzing…'))
        if check_cancelled():
            return None

        try:
            matches = self.rules.match(file_path, timeout=60)
        except yara.TimeoutError:
            raise yara.Error(_('Analysis timed out'))
        return YaraAnalysis({"path": file_path, "size": info.get_size(),
                             "type": content_type and Gio.content_type_get_description(content_type),
                             "matches": matches, **hashes, **rules_info})

    def scan_file_async(self, file_path: str, package: str, task_data=None):
        def scan_file_in_thread(cancellable, emit_progress, check_cancelled):
            rules_info = self.load_rules(package, cancellable, emit_progress)
            return self.scan_file(file_path, rules_info, cancellable, emit_progress, check_cancelled)

        return self.run_async(scan_file_in_thread, "file-analysis-completed", task_data)

    def scan_folder_async(self, target: Gio.File, files: list[Gio.File], errors: list,
                          package: str, task_data=None):
        def scan_folder_in_thread(cancellable, emit_progress, check_cancelled):
            rules_info = self.load_rules(package, cancellable, emit_progress)
            results = [(target.get_relative_path(error), None, _('Failed to read folder'))
                       for error in errors]
            for index, file in enumerate(files, 1):
                if check_cancelled():
                    return None

                GLib.idle_add(lambda i=index: self.emit("folder-progress", i, len(files)))
                name = target.get_relative_path(file)
                try:
                    analysis = self.scan_file(
                        file.get_path(), rules_info, cancellable, emit_progress, check_cancelled)
                    results.append((name, analysis, None))
                except yara.Error as e:
                    results.append((name, None, str(e)))
                except GLib.Error:
                    results.append((name, None, _('Failed to read file')))
            return results

        return self.run_async(scan_folder_in_thread, "folder-analysis-completed", task_data)
