# folder_scanner.py
#
# Copyright 2026 Lenspect contributors
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

import os
import stat
from dataclasses import dataclass
from pathlib import Path

class FolderScanError(Exception):
    pass

class FolderNotFoundError(FolderScanError):
    pass

class NotAFolderError(FolderScanError):
    pass

class FolderPermissionError(FolderScanError):
    pass

@dataclass(frozen=True)
class FolderScanIssue:
    path: str
    message: str

@dataclass(frozen=True)
class FolderScanResult:
    root: Path
    files: tuple[Path, ...]
    issues: tuple[FolderScanIssue, ...]

def collect_files(folder: str | os.PathLike) -> FolderScanResult:
    root = Path(folder).expanduser()

    try:
        root_stat = root.stat()
    except FileNotFoundError as error:
        raise FolderNotFoundError(str(root)) from error
    except PermissionError as error:
        raise FolderPermissionError(str(root)) from error
    except OSError as error:
        raise FolderScanError(f"{root}: {error.strerror or error}") from error

    if not stat.S_ISDIR(root_stat.st_mode):
        raise NotAFolderError(str(root))

    files = []
    issues = []

    try:
        with os.scandir(root) as entries:
            sorted_entries = sorted(entries, key=lambda entry: entry.name.casefold())
            collect_from_entries(sorted_entries, files, issues)
    except PermissionError as error:
        raise FolderPermissionError(str(root)) from error
    except OSError as error:
        raise FolderScanError(f"{root}: {error.strerror or error}") from error

    return FolderScanResult(root=root, files=tuple(files), issues=tuple(issues))

def collect_from_entries(entries, files: list[Path], issues: list[FolderScanIssue]):
    for entry in entries:
        try:
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                collect_from_directory(Path(entry.path), files, issues)
            elif entry.is_file(follow_symlinks=False):
                files.append(Path(entry.path))
        except OSError as error:
            issues.append(FolderScanIssue(entry.path, error.strerror or str(error)))

def collect_from_directory(directory: Path, files: list[Path], issues: list[FolderScanIssue]):
    try:
        with os.scandir(directory) as entries:
            sorted_entries = sorted(entries, key=lambda entry: entry.name.casefold())
            collect_from_entries(sorted_entries, files, issues)
    except OSError as error:
        issues.append(FolderScanIssue(str(directory), error.strerror or str(error)))
