import json
import os
import shutil
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from devfleet import workspace_archives
sys.path.insert(0, str(Path(__file__).parents[1] / "tools"))
from build_release import portable_metadata


ROOT = Path(__file__).parents[1]


def test_compute_venv_isolated_and_hash_bound():
    source = (ROOT / "linux/bootstrap-compute.sh").read_text(encoding="utf-8")
    assert "python3 -m venv --system-site-packages" not in source
    assert "python3 -m venv /opt/devfleet/venv" in source
    assert "--require-hashes" in source
    assert "runtime package origin is outside the DevFleet venv" in source


def test_portable_metadata_rebuilds_release_identity_without_heuristic_replacement(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "VERSION").write_text("1.2.13\n", encoding="utf-8")
    (source / "payload.txt").write_text("payload\n", encoding="utf-8")
    nested = tmp_path / "devfleet-v1.2.13.tar.gz"
    nested.write_bytes(b"tar")
    entries = [
        ("README.md", b"old v1.2.1"),
        ("CLEAN-ROOM-VERIFICATION.md", b"python tools/verify_package.py --archive devfleet-v1.2.9.tar.gz"),
        ("historical-note.txt", b"historical v1.2.9 reference"),
    ]
    rebuilt = dict(portable_metadata(entries, "1.2.13", nested, source))
    assert b"DevFleet Safe Remote Development v1.2.13" in rebuilt["README.md"]
    assert b"python source/tools/verify_package.py --archive devfleet-v1.2.13.tar.gz" in rebuilt["CLEAN-ROOM-VERIFICATION.md"]
    assert rebuilt["historical-note.txt"] == b"historical v1.2.9 reference"


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative regression requires Linux/POSIX")
def test_archive_regular_to_symlink_substitution_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".devfleet").mkdir()
    (workspace / ".devfleet" / "project.json").write_text("{}", encoding="utf-8")
    victim = workspace / "payload.txt"
    victim.write_text("authorized", encoding="utf-8")
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("OUTSIDE-SECRET", encoding="utf-8")
    original_open = workspace_archives.os.open
    swapped = False

    def swap_before_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if not swapped and path == "payload.txt" and dir_fd is not None:
            victim.unlink()
            os.symlink(outside, victim)
            swapped = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(workspace_archives.os, "open", swap_before_open)
    with pytest.raises(ValueError):
        workspace_archives.create_workspace_archive(workspace, "demo", tmp_path / "backup.tar.gz")
    assert outside.read_text(encoding="utf-8") == "OUTSIDE-SECRET"
    assert not (tmp_path / "backup.tar.gz").exists()


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative regression requires Linux/POSIX")
def test_archive_regular_to_different_inode_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".devfleet").mkdir()
    (workspace / ".devfleet" / "project.json").write_text("{}", encoding="utf-8")
    victim = workspace / "payload.txt"
    victim.write_text("authorized", encoding="utf-8")
    replacement = tmp_path / "replacement.txt"
    replacement.write_text("replacement", encoding="utf-8")
    original_open = workspace_archives.os.open
    swapped = False

    def swap_before_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if not swapped and path == "payload.txt" and dir_fd is not None:
            victim.unlink()
            replacement.rename(victim)
            swapped = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(workspace_archives.os, "open", swap_before_open)
    with pytest.raises(ValueError):
        workspace_archives.create_workspace_archive(workspace, "demo", tmp_path / "backup.tar.gz")


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative regression requires Linux/POSIX")
def test_restore_staging_substitution_never_touches_outside_sentinel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / ".devfleet").mkdir()
    (source / ".devfleet" / "project.json").write_text("{}", encoding="utf-8")
    archive = tmp_path / "backup.tar.gz"
    workspace_archives.create_workspace_archive(source, "demo", archive)
    destination = tmp_path / "demo"
    destination.mkdir()
    (destination / "old.txt").write_text("old", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "SENTINEL"
    sentinel.write_text("keep", encoding="utf-8")
    original_atomic_json = workspace_archives.atomic_json
    swapped = False

    def journal_then_swap(path: Path, value: dict):
        nonlocal swapped
        original_atomic_json(path, value)
        if not swapped and value.get("phase") == "PREPARED":
            staging = Path(value["staging_root"])
            staging.rename(tmp_path / "detached-stage")
            os.symlink(outside, staging, target_is_directory=True)
            swapped = True

    monkeypatch.setattr(workspace_archives, "atomic_json", journal_then_swap)
    with pytest.raises((RuntimeError, ValueError)):
        workspace_archives.restore_workspace_archive(archive, destination, "demo")
    assert sentinel.read_text(encoding="utf-8") == "keep"


@pytest.mark.skipif(os.name != "posix", reason="standard unzip mode test requires POSIX")
def test_standard_unzip_restores_contract_modes(tmp_path: Path):
    unzip = shutil.which("unzip")
    if not unzip:
        pytest.skip("standard unzip is unavailable")
    source = tmp_path / "source"
    source.mkdir()
    (source / "VERSION").write_text("1.2.13\n", encoding="utf-8")
    nested = tmp_path / "devfleet-v1.2.13.tar.gz"
    nested.write_bytes(b"tar")
    data = dict(portable_metadata([], "1.2.13", nested, source))
    archive = tmp_path / "portable.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        for name, content in data.items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            mode = 0o755 if name == "source/VERSION" else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            handle.writestr(info, content)
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    subprocess.run([unzip, "-q", str(archive), "-d", str(extracted)], check=True)
    assert stat.S_IMODE((extracted / "source/VERSION").stat().st_mode) == 0o755
    assert stat.S_IMODE((extracted / "README.md").stat().st_mode) == 0o644
