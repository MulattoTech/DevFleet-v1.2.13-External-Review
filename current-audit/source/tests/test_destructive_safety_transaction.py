import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from devfleet import projects
from devfleet.workspace_archives import create_workspace_archive


def _settings(tmp_path: Path):
    return SimpleNamespace(
        workspaces=tmp_path / "workspaces",
        runtime_root=tmp_path / "runtime",
        backup_before_rebuild=False,
        backup_before_quarantine=True,
        node_name="test-node",
        development_profile="strict",
        allow_permanent_delete=True,
    )


def _project(tmp_path: Path, slug: str = "active-writer") -> Path:
    project = tmp_path / "workspaces" / slug
    (project / ".devfleet").mkdir(parents=True)
    (project / ".devfleet" / "project.json").write_text(
        json.dumps({"schema_version": 3, "managed_by": "devfleet", "project_id": "12345678-1234-1234-1234-123456789012", "slug": slug, "runtime_provider": "docker-compose", "host_id": "test-node"}),
        encoding="utf-8",
    )
    (project / "README.md").write_text("stable\n", encoding="utf-8")
    return project


def test_safety_backup_binds_fresh_backup_and_source_fingerprint(tmp_path, monkeypatch):
    project = _project(tmp_path)
    settings = _settings(tmp_path)
    settings.workspaces.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(projects, "SETTINGS", settings)
    monkeypatch.setattr(projects, "stop_project", lambda _slug: "stopped")
    monkeypatch.setattr(projects, "running", lambda _project: False)
    archive = tmp_path / "runtime" / "workspace-backups" / "fresh" / "active-writer.tar.gz"
    result = create_workspace_archive(project, "active-writer", archive)
    monkeypatch.setattr(
        projects,
        "backup_project",
        lambda _slug: json.dumps({
            "backup_status": "verified",
            "backup_id": "fresh-transaction",
            "backup_path": str(archive),
            "backup_sha256": result["archive_sha256"],
        }),
    )

    outcome = projects.safety_backup_project("active-writer")
    binding = outcome["binding"]
    assert binding["project_id"] == "12345678-1234-1234-1234-123456789012"
    assert binding["backup_id"] == "fresh-transaction"
    assert binding["backup_sha256"] == result["archive_sha256"]
    assert binding["transaction_id"].startswith("destroy-")


def test_writer_after_quiescence_fails_closed(tmp_path, monkeypatch):
    project = _project(tmp_path)
    settings = _settings(tmp_path)
    settings.workspaces.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(projects, "SETTINGS", settings)

    monkeypatch.setattr(projects, "stop_project", lambda _slug: "stopped")
    monkeypatch.setattr(projects, "running", lambda _project: False)

    def backup_with_active_writer(_slug):
        (project / "README.md").write_text("written during backup\n", encoding="utf-8")
        return json.dumps({"backup_status": "verified", "backup_id": "old", "backup_sha256": "a" * 64})

    monkeypatch.setattr(projects, "backup_project", backup_with_active_writer)
    with pytest.raises(RuntimeError, match="changed during the safety backup"):
        projects.safety_backup_project("active-writer")
