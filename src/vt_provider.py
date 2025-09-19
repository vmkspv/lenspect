# vt_provider.py
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

from hashlib import sha256
from base64 import urlsafe_b64encode
from json import loads, JSONDecodeError
from typing import Dict, Optional

from os import urandom
from os.path import basename, exists, getsize
from time import sleep

from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlparse

from gi.repository import GObject, Gio, GLib

class FileAnalysis(GObject.Object):
    __gtype_name__ = 'FileAnalysis'

    def __init__(self, data: dict, original_filename: Optional[str] = None, **kwargs):
        super().__init__(**kwargs)
        self.data = data
        self.attributes = data.get("attributes", {})
        self.stats = self.attributes.get("last_analysis_stats", {})
        self.original_filename = original_filename

    @GObject.Property(type=str, default="")
    def file_id(self) -> str:
        return self.data.get("id", "")

    @GObject.Property(type=str, default="")
    def file_name(self) -> str:
        return self.original_filename or ""

    @GObject.Property(type=int, default=0)
    def file_size(self) -> int:
        return self.attributes.get("size", 0)

    @GObject.Property(type=int, default=0)
    def malicious_count(self) -> int:
        return self.stats.get("malicious", 0)

    @GObject.Property(type=int, default=0)
    def suspicious_count(self) -> int:
        return self.stats.get("suspicious", 0)

    @GObject.Property(type=int, default=0)
    def harmless_count(self) -> int:
        return self.stats.get("harmless", 0)

    @GObject.Property(type=int, default=0)
    def undetected_count(self) -> int:
        return self.stats.get("undetected", 0)

    @GObject.Property(type=int, default=0)
    def total_engines(self) -> int:
        return sum(self.stats.values())

    @GObject.Property(type=int, default=0)
    def threat_count(self) -> int:
        return self.malicious_count + self.suspicious_count

    @GObject.Property(type=bool, default=True)
    def is_clean(self) -> bool:
        return self.threat_count == 0

    @GObject.Property(type=str, default="Unknown")
    def last_analysis_date(self) -> str:
        analysis_date = self.attributes.get("last_analysis_date")
        if isinstance(analysis_date, int):
            from datetime import datetime
            return datetime.fromtimestamp(analysis_date).strftime("%Y-%m-%d %H:%M:%S")
        return str(analysis_date) if analysis_date else _('Unknown')

    def get_detections(self) -> Dict[str, str]:
        detections = {}
        scan_results = self.attributes.get("last_analysis_results", {})

        for engine, result in scan_results.items():
            category = result.get("category", "")
            if category in ["malicious", "suspicious"]:
                detections[engine] = result.get("result", _('Unknown threat'))

        return detections

    def get_full_data(self) -> dict:
        return self.data

class URLAnalysis(GObject.Object):
    __gtype_name__ = 'URLAnalysis'

    def __init__(self, data: dict, original_url: Optional[str] = None, **kwargs):
        super().__init__(**kwargs)
        self.data = data
        self.attributes = data.get("attributes", {})
        self.stats = self.attributes.get("last_analysis_stats", {})
        self.original_url = original_url

    @GObject.Property(type=str, default="")
    def url_id(self) -> str:
        return self.data.get("id", "")

    @GObject.Property(type=str, default="")
    def url(self) -> str:
        return self.original_url or self.attributes.get("url", "")

    @GObject.Property(type=str, default="")
    def title(self) -> str:
        return self.attributes.get("title", "")

    @GObject.Property(type=int, default=0)
    def malicious_count(self) -> int:
        return self.stats.get("malicious", 0)

    @GObject.Property(type=int, default=0)
    def suspicious_count(self) -> int:
        return self.stats.get("suspicious", 0)

    @GObject.Property(type=int, default=0)
    def harmless_count(self) -> int:
        return self.stats.get("harmless", 0)

    @GObject.Property(type=int, default=0)
    def undetected_count(self) -> int:
        return self.stats.get("undetected", 0)

    @GObject.Property(type=int, default=0)
    def total_engines(self) -> int:
        return sum(self.stats.values())

    @GObject.Property(type=int, default=0)
    def threat_count(self) -> int:
        return self.malicious_count + self.suspicious_count

    @GObject.Property(type=bool, default=True)
    def is_clean(self) -> bool:
        return self.threat_count == 0

    @GObject.Property(type=str, default="Unknown")
    def last_analysis_date(self) -> str:
        analysis_date = self.attributes.get("last_analysis_date")
        if isinstance(analysis_date, int):
            from datetime import datetime
            return datetime.fromtimestamp(analysis_date).strftime("%Y-%m-%d %H:%M:%S")
        return str(analysis_date) if analysis_date else _('Unknown')

    @GObject.Property(type=int, default=0)
    def reputation(self) -> int:
        return self.attributes.get("reputation", 0)

    def get_categories(self) -> Dict[str, str]:
        return self.attributes.get("categories", {})

    def get_detections(self) -> Dict[str, str]:
        detections = {}
        scan_results = self.attributes.get("last_analysis_results", {})

        for engine, result in scan_results.items():
            category = result.get("category", "")
            if category in ["malicious", "suspicious"]:
                detections[engine] = result.get("result", _('Malicious URL'))

        return detections

    def get_full_data(self) -> dict:
        return self.data

class VirusTotalService(GObject.Object):
    __gtype_name__ = 'VirusTotalService'
    __gsignals__ = {
        "analysis-progress": (GObject.SignalFlags.RUN_FIRST, None, (str,)),
        "file-analysis-completed": (GObject.SignalFlags.RUN_FIRST, None, (FileAnalysis,)),
        "url-analysis-completed": (GObject.SignalFlags.RUN_FIRST, None, (URLAnalysis,)),
        "analysis-failed": (GObject.SignalFlags.RUN_FIRST, None, (str,)),
    }

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.api_key_internal: Optional[str] = None
        self.base_url = "https://www.virustotal.com/api/v3"

    @GObject.Property(type=str, default="")
    def api_key(self) -> str:
        return self.api_key_internal or ""

    @api_key.setter
    def api_key(self, value: str):
        self.api_key_internal = value.strip() if value else None

    @GObject.Property(type=bool, default=False)
    def has_api_key(self) -> bool:
        return bool(self.api_key_internal)

    def calculate_file_hash(self, file_path: str) -> str:
        hasher = sha256()

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)

        return hasher.hexdigest()

    def make_request(self, method: str, endpoint: str, data: Optional[bytes] = None,
                     headers: Optional[Dict[str, str]] = None) -> dict:
        if not self.api_key_internal:
            raise VirusTotalError(_('API key is required'))

        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        request_headers = {
            "x-apikey": self.api_key_internal,
            "User-Agent": "Lenspect/1.0.0"
        }
        if headers:
            request_headers.update(headers)

        req = Request(url, data=data, method=method)
        for key, value in request_headers.items():
            req.add_header(key, value)

        try:
            with urlopen(req, timeout=30) as response:
                response_data = response.read().decode("utf-8")
                return loads(response_data)
        except HTTPError as e:
            try:
                error_response = e.read().decode("utf-8")
                error_data = loads(error_response)
                error_msg = error_data.get("error", {}).get("message", f"HTTP {e.code}")
            except (JSONDecodeError, KeyError):
                error_msg = f"HTTP {e.code}: {e.reason}"
            raise VirusTotalError(error_msg, e.code)
        except URLError as e:
            raise VirusTotalError(_(f'Network error: {e.reason}'))
        except JSONDecodeError:
            raise VirusTotalError(_('Invalid response format'))

    def get_file_report(self, file_hash: str,
                        original_filename: Optional[str] = None) -> Optional[FileAnalysis]:
        try:
            response = self.make_request("GET", f"/files/{file_hash}")
            return (FileAnalysis(response["data"], original_filename)
                    if "data" in response else None)
        except VirusTotalError as e:
            if e.code == 404:
                return None
            raise

    def upload_file(self, file_path: str) -> str:
        if not exists(file_path):
            raise VirusTotalError(_(f'File not found: {file_path}'))

        file_size = getsize(file_path)
        if file_size > 32 * 1024 * 1024:
            raise VirusTotalError(_('File size exceeds 32MB limit'))

        upload_url = f"{self.base_url}/files"

        boundary = '----WebKitFormBoundary' + ''.join(['%02x' % b for b in urandom(16)])
        filename = basename(file_path)

        form_parts = [
            f'--{boundary}',
            f'Content-Disposition: form-data; name="file"; filename="{filename}"',
            'Content-Type: application/octet-stream',
            ''
        ]

        with open(file_path, "rb") as f:
            file_content = f.read()

        header_data = "\r\n".join(form_parts).encode("utf-8")
        footer_data = f"\r\n--{boundary}--\r\n".encode("utf-8")
        body = header_data + b"\r\n" + file_content + footer_data

        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "x-apikey": self.api_key_internal
        }

        req = Request(upload_url, data=body, method="POST")
        for key, value in headers.items():
            req.add_header(key, value)

        try:
            with urlopen(req) as response:
                response_data = loads(response.read().decode("utf-8"))
                return response_data["data"]["id"]
        except HTTPError as e:
            try:
                error_response = e.read().decode("utf-8")
                error_data = loads(error_response)
                error_msg = error_data.get("error", {}).get("message", _('Upload failed'))
            except (JSONDecodeError, KeyError):
                error_msg = _(f'Upload failed: HTTP {e.code}')
            raise VirusTotalError(error_msg, e.code)

    def get_analysis(self, analysis_id: str) -> dict:
        return self.make_request("GET", f"/analyses/{analysis_id}")

    def request_rescan(self, file_hash: str) -> str:
        response = self.make_request("POST", f"/files/{file_hash}/analyse")
        return response["data"]["id"]

    def normalize_url(self, url: str) -> str:
        if not url:
            return url

        url = url.strip()

        if url.startswith(("http://", "https://")):
            return url

        if "." in url and not url.startswith("//"):
            return f"http://{url}"

        return url

    def validate_url(self, url: str) -> bool:
        try:
            normalized_url = self.normalize_url(url)
            result = urlparse(normalized_url)
            return all([result.scheme, result.netloc]) and result.scheme in ["http", "https"]
        except Exception:
            return False

    def url_to_id(self, url: str) -> str:
        url_bytes = url.encode("utf-8")
        encoded = urlsafe_b64encode(url_bytes).decode("ascii")
        return encoded.rstrip("=")

    def get_url_report(self, url: str) -> Optional[URLAnalysis]:
        try:
            normalized_url = self.normalize_url(url)
            url_id = self.url_to_id(normalized_url)
            response = self.make_request("GET", f"/urls/{url_id}")
            return (URLAnalysis(response["data"], normalized_url)
                    if "data" in response else None)
        except VirusTotalError as e:
            if e.code == 404:
                return None
            raise

    def submit_url(self, url: str) -> str:
        if not self.validate_url(url):
            raise VirusTotalError(_('Invalid URL format'))

        normalized_url = self.normalize_url(url)
        data = f"url={normalized_url}".encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        response = self.make_request("POST", "/urls", data=data, headers=headers)
        return response["data"]["id"]

    def request_url_rescan(self, url: str) -> str:
        normalized_url = self.normalize_url(url)
        url_id = self.url_to_id(normalized_url)
        response = self.make_request("POST", f"/urls/{url_id}/analyse")
        return response["data"]["id"]

    def scan_file_async(self, file_path: str, task_data=None):
        def task_func(task, source_object, task_data, cancellable):
            def emit_progress(message):
                if not (cancellable and cancellable.is_cancelled()):
                    GLib.idle_add(lambda: self.emit("analysis-progress", message))

            def check_cancelled():
                return cancellable and cancellable.is_cancelled()

            try:
                original_filename = basename(file_path)

                emit_progress(_('Calculating file hash...'))
                if check_cancelled():
                    return

                file_hash = self.calculate_file_hash(file_path)

                emit_progress(_('Checking for existing analysis...'))
                if check_cancelled():
                    return

                existing_analysis = self.get_file_report(file_hash, original_filename)
                if existing_analysis:
                    if not check_cancelled():
                        GLib.idle_add(lambda: self.emit("file-analysis-completed", existing_analysis))
                    task.return_value(existing_analysis)
                    return

                emit_progress(_('Uploading file...'))
                if check_cancelled():
                    return

                analysis_id = self.upload_file(file_path)

                max_attempts = 30
                for attempt in range(max_attempts):
                    if check_cancelled():
                        return

                    emit_progress(_(f'Waiting for analysis... ({attempt + 1}/{max_attempts})'))
                    analysis_result = self.get_analysis(analysis_id)

                    if "data" in analysis_result:
                        status = analysis_result["data"]["attributes"]["status"]

                        if status == "completed":
                            final_analysis = self.get_file_report(file_hash, original_filename)
                            if final_analysis:
                                if not check_cancelled():
                                    GLib.idle_add(lambda: self.emit("file-analysis-completed", final_analysis))
                                task.return_value(final_analysis)
                                return
                            else:
                                raise VirusTotalError(_('Analysis completed but report unavailable'))

                        elif status in ["failed", "error"]:
                            raise VirusTotalError(_(f'Analysis failed: {status}'))

                    for i in range(10):
                        if check_cancelled():
                            return
                        sleep(1)

                raise VirusTotalError(_('Analysis timed out'))

            except Exception as e:
                if not check_cancelled():
                    error_message = str(e)
                    GLib.idle_add(lambda: self.emit("analysis-failed", error_message))
                    task.return_error(GLib.Error(error_message))

        cancellable = Gio.Cancellable.new()
        task = Gio.Task.new(self, cancellable, None, None)
        task.set_task_data(task_data)
        task.run_in_thread(task_func)

        return task

    def scan_url_async(self, url: str, task_data=None):
        def task_func(task, source_object, task_data, cancellable):
            def emit_progress(message):
                if not (cancellable and cancellable.is_cancelled()):
                    GLib.idle_add(lambda: self.emit("analysis-progress", message))

            def check_cancelled():
                return cancellable and cancellable.is_cancelled()

            try:
                emit_progress(_('Validating URL...'))
                if check_cancelled():
                    return

                if not self.validate_url(url):
                    raise VirusTotalError(_('Invalid URL format'))

                emit_progress(_('Checking for existing analysis...'))
                if check_cancelled():
                    return

                existing_analysis = self.get_url_report(url)
                if existing_analysis:
                    if not check_cancelled():
                        GLib.idle_add(lambda: self.emit("url-analysis-completed", existing_analysis))
                    task.return_value(existing_analysis)
                    return

                emit_progress(_('Submitting URL for analysis...'))
                if check_cancelled():
                    return

                analysis_id = self.submit_url(url)

                max_attempts = 30
                for attempt in range(max_attempts):
                    if check_cancelled():
                        return

                    emit_progress(_(f'Waiting for analysis... ({attempt + 1}/{max_attempts})'))
                    analysis_result = self.get_analysis(analysis_id)

                    if "data" in analysis_result:
                        status = analysis_result["data"]["attributes"]["status"]

                        if status == "completed":
                            final_analysis = self.get_url_report(url)
                            if final_analysis:
                                if not check_cancelled():
                                    GLib.idle_add(lambda: self.emit("url-analysis-completed", final_analysis))
                                task.return_value(final_analysis)
                                return
                            else:
                                raise VirusTotalError(_('Analysis completed but report unavailable'))

                        elif status in ["failed", "error"]:
                            raise VirusTotalError(_(f'Analysis failed: {status}'))

                    for i in range(10):
                        if check_cancelled():
                            return
                        sleep(1)

                raise VirusTotalError(_('Analysis timed out'))

            except Exception as e:
                if not check_cancelled():
                    error_message = str(e)
                    GLib.idle_add(lambda: self.emit("analysis-failed", error_message))
                    task.return_error(GLib.Error(error_message))

        cancellable = Gio.Cancellable.new()
        task = Gio.Task.new(self, cancellable, None, None)
        task.set_task_data(task_data)
        task.run_in_thread(task_func)

        return task

class VirusTotalError(Exception):
    def __init__(self, message: str, code: Optional[int] = None):
        super().__init__(message)
        self.code = code
