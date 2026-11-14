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

class YaraService(GObject.Object):
    __gtype_name__ = 'YaraService'
    __gsignals__ = {
        "analysis-progress": (GObject.SignalFlags.RUN_FIRST, None, (str,)),
        "folder-progress": (GObject.SignalFlags.RUN_FIRST, None, (int, int)),
        "file-analysis-completed": (GObject.SignalFlags.RUN_FIRST, None, (YaraAnalysis,)),
        "folder-analysis-completed": (GObject.SignalFlags.RUN_FIRST, None, (object,)),
        "rules-updated": (GObject.SignalFlags.RUN_FIRST, None, (str,)),
        "analysis-failed": (GObject.SignalFlags.RUN_FIRST, None, (str,)),
    }

    def __init__(self, version: str, **kwargs):
        super().__init__(**kwargs)
        self.rules = None
        self.rules_key = None
        self.base_url = "https://github.com/YARAHQ/yara-forge/releases/latest/download"
        self.rules_dir = GLib.build_filenamev([GLib.get_user_data_dir(), "lenspect", "yara"])
        self.session = Soup.Session()
        self.session.set_user_agent(f"Lenspect/{version}")

    def get_rules_name(self, source: str, folder: Gio.File | None = None) -> str:
        if source == "custom":
            return folder.get_basename() if folder else _('Custom Rules')
        return f"YARA Forge {source.capitalize()}"

    def get_package_path(self, package: str) -> str:
        return GLib.build_filenamev([self.rules_dir, f"{package}.yar"])

    def list_rule_files(self, source: str, folder: Gio.File | None = None) -> list[str]:
        if source != "custom":
            path = self.get_package_path(source)
            return [path] if GLib.file_test(path, GLib.FileTest.IS_REGULAR) else []
        if not folder:
            return []

        try:
            infos = folder.enumerate_children("standard::name,standard::type",
                                              Gio.FileQueryInfoFlags.NOFOLLOW_SYMLINKS, None)
        except GLib.Error:
            return []

        files = []
        for info in sorted(infos, key=lambda info: info.get_name().lower()):
            child = folder.get_child(info.get_name())
            if info.get_file_type() == Gio.FileType.DIRECTORY:
                files += self.list_rule_files(source, child)
            elif info.get_name().lower().endswith((".yar", ".yara")):
                files.append(child.get_path())
        return files

    def get_rules_info(self, rule_files: list[str]) -> tuple[int, int]:
        count, modified = 0, 0

        for path in rule_files:
            gfile = Gio.File.new_for_path(path)
            try:
                success, contents, _etag = gfile.load_contents(None)
                info = gfile.query_info("time::modified", Gio.FileQueryInfoFlags.NONE, None)
            except GLib.Error:
                continue
            count += sum(1 for line in contents.decode("utf-8", "replace").splitlines()
                         if line.lstrip().startswith(("rule ", "private rule ", "global rule ")))
            modified = max(modified, info.get_attribute_uint64("time::modified"))

        return count, modified

    def compile_rules(self, rule_files: list[str]) -> yara.Rules:
        filepaths = {}

        for path in rule_files:
            try:
                if len(rule_files) > 1:
                    yara.compile(filepath=path)
                filepaths[path] = path
            except yara.Error:
                continue

        if not filepaths:
            raise yara.Error(_('No YARA rules found'))

        return yara.compile(filepaths=filepaths)

    def download_rules(self, package: str, cancellable: Gio.Cancellable | None = None) -> str:
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

        path = self.get_package_path(package)
        try:
            GLib.mkdir_with_parents(self.rules_dir, 0o755)
            Gio.File.new_for_path(path).replace_contents(
                contents, None, False, Gio.FileCreateFlags.NONE, cancellable)
        except GLib.Error as e:
            raise yara.Error(f"{_('Failed to save rules')}: {e.message}")
        return path

    def load_rules(self, source: str, folder: Gio.File | None,
                   cancellable: Gio.Cancellable | None, emit_progress) -> dict:
        rule_files = self.list_rule_files(source, folder)
        if not rule_files and source != "custom":
            emit_progress(_('Downloading rules…'))
            rule_files = [self.download_rules(source, cancellable)]

        count, modified = self.get_rules_info(rule_files)
        if not count:
            raise yara.Error(_('No YARA rules found'))

        rules_key = (tuple(rule_files), modified)
        if rules_key != self.rules_key:
            emit_progress(_('Compiling rules…'))
            self.rules = self.compile_rules(rule_files)
            self.rules_key = rules_key

        return {"rules_name": self.get_rules_name(source, folder), "rules_count": count}

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
            "standard::size", Gio.FileQueryInfoFlags.NONE, cancellable)

        emit_progress(_('Calculating file hash…'))
        if check_cancelled():
            return None

        hashes = self.calculate_file_hashes(file_path, cancellable)

        emit_progress(_('Scanning file…'))
        if check_cancelled():
            return None

        matches = self.rules.match(file_path, timeout=60)
        return YaraAnalysis({"path": file_path, "size": info.get_size(),
                             "matches": matches, **hashes, **rules_info})

    def scan_file_async(self, file_path: str, source: str,
                        folder: Gio.File | None = None, task_data=None):
        def scan_file_in_thread(cancellable, emit_progress, check_cancelled):
            rules_info = self.load_rules(source, folder, cancellable, emit_progress)
            return self.scan_file(file_path, rules_info, cancellable, emit_progress, check_cancelled)

        return self.run_async(scan_file_in_thread, "file-analysis-completed", task_data)

    def scan_folder_async(self, target: Gio.File, files: list[Gio.File], errors: list,
                          source: str, folder: Gio.File | None = None, task_data=None):
        def scan_folder_in_thread(cancellable, emit_progress, check_cancelled):
            rules_info = self.load_rules(source, folder, cancellable, emit_progress)
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

    def update_rules_async(self, package: str, task_data=None):
        def update_rules_in_thread(cancellable, emit_progress, check_cancelled):
            return self.download_rules(package, cancellable)

        return self.run_async(update_rules_in_thread, "rules-updated", task_data)
