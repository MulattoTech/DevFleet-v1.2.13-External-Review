from __future__ import annotations

import hashlib
import os
import tarfile
from pathlib import Path

import pytest
from types import SimpleNamespace

from devfleet import projects
from devfleet.workspace_archives import (
    create_workspace_archive,
    restore_workspace_archive,
    write_backup_manifest,
)


def _hash_tree(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def _metadata(source: Path) -> None:
    metadata = source / ".devfleet" / "project.json"
    metadata.parent.mkdir(parents=True, exist_ok=True)
    metadata.write_text('{"schema_version":3,"managed_by":"devfleet","project_id":"12345678-1234-1234-1234-123456789012","slug":"demo","runtime_provider":"docker-compose","host_id":"test-node"}', encoding="utf-8")


def test_destructive_backup_preserves_generated_looking_user_files(tmp_path: Path):
    source = tmp_path / "source"
    _metadata(source)
    for relative, data in {
        "build/irreplaceable.bin": b"build-user-data",
        "dist/manual-output.dat": b"dist-user-data",
        "node_modules/user-preserved-test.txt": b"node-user-data",
        ".next/notes.txt": b"next-user-data",
        "arbitrary/nested-generated-looking/file.txt": b"nested-user-data",
    }.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    archive = tmp_path / "backup.tar.gz"
    result = create_workspace_archive(source, "demo", archive, include_generated=True, consistency_level="quiesced")
    assert result["omitted_paths"] == []
    assert result["included_file_count"] == 6
    restored = tmp_path / "restored"
    restore_workspace_archive(archive, restored, "demo")
    assert _hash_tree(source) == _hash_tree(restored)


def test_routine_backup_keeps_documented_generated_directory_omission(tmp_path: Path):
    source = tmp_path / "source"
    _metadata(source)
    (source / "build").mkdir(parents=True)
    (source / "build" / "cache.bin").write_bytes(b"cache")
    archive = tmp_path / "routine.tar.gz"
    result = create_workspace_archive(source, "demo", archive)
    assert "build" in result["omitted_paths"]
    with tarfile.open(archive, "r:gz") as bundle:
        assert "demo/build/cache.bin" not in bundle.getnames()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission fidelity is unavailable on Windows")
def test_restore_preserves_safe_modes_and_strips_special_bits(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    _metadata(source)
    executable = source / "hook.sh"
    private = source / "private.key"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    private.write_text("secret", encoding="utf-8")
    os.chmod(executable, 0o755)
    os.chmod(private, 0o600)
    archive = tmp_path / "modes.tar.gz"
    create_workspace_archive(source, "demo", archive, include_generated=True)

    # Make the archive metadata hostile.  Restore must mask privilege-bearing
    # special bits while retaining ordinary permissions.
    rewritten = tmp_path / "hostile.tar.gz"
    with tarfile.open(archive, "r:gz") as original, tarfile.open(rewritten, "w:gz") as target:
        for member in original.getmembers():
            member.mode |= 0o6000
            if member.name.endswith("hook.sh"):
                member.mode = 0o6755
            source_file = original.extractfile(member) if member.isfile() else None
            target.addfile(member, source_file)
            if source_file is not None:
                source_file.close()

    restored = tmp_path / "restored"
    restore_workspace_archive(rewritten, restored, "demo")
    assert (restored / "hook.sh").stat().st_mode & 0o777 == 0o755
    assert (restored / "private.key").stat().st_mode & 0o777 == 0o600


def test_restore_deleted_project_uses_tombstone_and_exact_identity(tmp_path: Path, monkeypatch):
    workspaces = tmp_path / "workspaces"
    runtime = tmp_path / "runtime"
    settings = SimpleNamespace(workspaces=workspaces, runtime_root=runtime, host_id="test-node")
    monkeypatch.setattr(projects, "SETTINGS", settings)
    source = tmp_path / "source"
    _metadata(source)
    (source / "build").mkdir()
    (source / "build" / "irreplaceable.bin").write_bytes(b"keep")
    backup_dir = runtime / "workspace-backups" / "demo-backup"
    archive = backup_dir / "demo.tar.gz"
    result = create_workspace_archive(source, "demo", archive, include_generated=True, consistency_level="quiesced")
    write_backup_manifest(
        backup_dir,
        slug="demo",
        project_id="12345678-1234-1234-1234-123456789012",
        runtime={"provider": "docker-compose", "runtime_id": ""},
        archive=result,
        consistency_level="quiesced",
    )
    tombstone = {
        "project_id": "12345678-1234-1234-1234-123456789012",
        "slug": "demo",
        "runtime_provider": "docker-compose",
        "backup_id": "demo-backup",
        "backup_sha256": result["archive_sha256"],
    }
    tombstone_path = projects._recovery_tombstone_path("demo", tombstone["project_id"])
    tombstone_path.parent.mkdir(parents=True, exist_ok=True)
    tombstone_path.write_text(__import__("json").dumps(tombstone), encoding="utf-8")
    recovered = projects.restore_deleted_project(
        "demo", "demo-backup", project_id=tombstone["project_id"], confirm_restore=True
    )
    assert recovered["ok"] is True
    assert (workspaces / "demo" / "build" / "irreplaceable.bin").read_bytes() == b"keep"
    with pytest.raises(ValueError, match="absent destination"):
        projects.restore_deleted_project(
            "demo", "demo-backup", project_id=tombstone["project_id"], confirm_restore=True
        )
