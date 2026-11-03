import os
from pathlib import Path

import pytest

from src.core.folder_scanner import (
    FolderNotFoundError,
    FolderPermissionError,
    NotAFolderError,
    collect_files,
)

def relative_paths(result, root):
    return [path.relative_to(root).as_posix() for path in result.files]

def test_collects_files_recursively(tmp_path):
    (tmp_path / "root.txt").write_text("root")
    (tmp_path / "alpha").mkdir()
    (tmp_path / "alpha" / "one.txt").write_text("one")
    (tmp_path / "alpha" / "beta").mkdir()
    (tmp_path / "alpha" / "beta" / "two.bin").write_text("two")

    result = collect_files(tmp_path)

    assert relative_paths(result, tmp_path) == [
        "alpha/beta/two.bin",
        "alpha/one.txt",
        "root.txt",
    ]
    assert result.issues == ()

def test_empty_folder_returns_no_files(tmp_path):
    result = collect_files(tmp_path)

    assert result.files == ()
    assert result.issues == ()

def test_nested_empty_directories_are_ignored(tmp_path):
    (tmp_path / "empty").mkdir()
    (tmp_path / "empty" / "deeper").mkdir()
    (tmp_path / "keep.txt").write_text("keep")

    result = collect_files(tmp_path)

    assert relative_paths(result, tmp_path) == ["keep.txt"]

def test_missing_folder_raises(tmp_path):
    missing = tmp_path / "missing"

    with pytest.raises(FolderNotFoundError):
        collect_files(missing)

def test_regular_file_is_not_a_folder(tmp_path):
    file_path = tmp_path / "file.txt"
    file_path.write_text("data")

    with pytest.raises(NotAFolderError):
        collect_files(file_path)

def test_unreadable_root_raises(tmp_path, monkeypatch):
    real_scandir = os.scandir

    def denied_scandir(path):
        if Path(path) == tmp_path:
            raise PermissionError(13, "Permission denied", str(path))
        return real_scandir(path)

    monkeypatch.setattr("src.core.folder_scanner.os.scandir", denied_scandir)

    with pytest.raises(FolderPermissionError):
        collect_files(tmp_path)

def test_unreadable_nested_folder_is_reported(tmp_path, monkeypatch):
    unreadable = tmp_path / "locked"
    unreadable.mkdir()
    (tmp_path / "visible.txt").write_text("visible")
    real_scandir = os.scandir

    def denied_scandir(path):
        if Path(path) == unreadable:
            raise PermissionError(13, "Permission denied", str(path))
        return real_scandir(path)

    monkeypatch.setattr("src.core.folder_scanner.os.scandir", denied_scandir)

    result = collect_files(tmp_path)

    assert relative_paths(result, tmp_path) == ["visible.txt"]
    assert len(result.issues) == 1
    assert result.issues[0].path == str(unreadable)

def test_symbolic_links_are_skipped(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "inside.txt").write_text("inside")

    try:
        (tmp_path / "link").symlink_to(target, target_is_directory=True)
        (tmp_path / "file-link.txt").symlink_to(target / "inside.txt")
    except OSError:
        pytest.skip("symbolic links are not supported on this platform")

    result = collect_files(tmp_path)

    assert relative_paths(result, tmp_path) == ["target/inside.txt"]
