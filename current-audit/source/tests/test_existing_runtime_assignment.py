import json
from pathlib import Path

import pytest

import devfleet.projects as projects
from devfleet.core import SETTINGS


def make_existing(slug: str, *, metadata: dict | None = None) -> tuple[Path, dict]:
    project = SETTINGS.workspaces / slug
    (project / ".devfleet").mkdir(parents=True, exist_ok=True)
    (project / "compose.yaml").write_text("services:\n  app:\n    image: ubuntu:24.04\n", encoding="utf-8")
    (project / "README.md").write_text("workspace-preserved\n", encoding="utf-8")
    record = metadata or {"schema_version": 3, "managed_by": "devfleet", "slug": slug, "display_name": "Legacy project", "project_id": "12345678-1234-1234-1234-123456789abc", "runtime_provider": "docker-compose", "host_id": "test-node"}
    (project / ".devfleet" / "project.json").write_text(json.dumps(record), encoding="utf-8")
    (project / ".devfleet" / "template.json").write_text(json.dumps({
        "start_command": "docker compose up -d --build",
        "stop_command": "docker compose down --remove-orphans",
        "restart_command": "docker compose restart",
        "rebuild_command": "docker compose build && docker compose up -d",
        "logs_command": "docker compose logs",
    }), encoding="utf-8")
    return project, record


def mark_healthy(slug: str) -> str:
    project = SETTINGS.workspaces / slug
    meta = projects.load_meta(project)
    meta.update({'health_status': 'healthy', 'health_scope': 'application-check'})
    projects.atomic_json(projects.metadata_path(project), meta)
    return 'healthy'


def test_legacy_project_is_detected_and_explicitly_assigned_to_container(monkeypatch: pytest.MonkeyPatch):
    slug = "legacy-container-adopt"
    project, _ = make_existing(slug)
    monkeypatch.setattr(projects, "running", lambda _project: False)
    monkeypatch.setattr(projects, "backup_project", lambda _slug: json.dumps({"backup_status": "verified", "backup_id": "test-backup", "backup_sha256": "a" * 64}))
    monkeypatch.setattr(projects, "start_project", lambda _slug: "started")
    monkeypatch.setattr(projects, "runtime_health", lambda _slug: {"ok": True, "healthy": True})
    monkeypatch.setattr(projects, "health_project", mark_healthy)

    result = projects.assign_project_runtime(slug, "container", "standard")

    saved = json.loads((project / ".devfleet" / "project.json").read_text())
    assert result["workspace_preserved"] is True
    assert saved["runtime_isolation"] == "container"
    assert saved["runtime_provider"] == "docker-compose"
    assert saved["resource_profile"] == "standard"
    assert (project / ".devfleet" / "runtime-resources.yaml").is_file()
    assert (project / "README.md").read_text() == "workspace-preserved\n"


def test_existing_project_vm_assignment_imports_workspace_and_persists_metadata(monkeypatch: pytest.MonkeyPatch):
    slug = "legacy-vm-adopt"
    project, _ = make_existing(slug)
    monkeypatch.setattr(projects, "running", lambda _project: False)
    monkeypatch.setattr(projects, "backup_project", lambda _slug: json.dumps({"backup_status": "verified", "backup_id": "test-backup", "backup_sha256": "a" * 64}))
    monkeypatch.setattr(projects, "get_host_capacity", lambda: {"capacity": {"allocatable_cpus": 8, "allocatable_memory_gb": 24, "allocatable_disk_gb": 300}})
    monkeypatch.setattr(projects.VmRuntimeOperations, "ensure", staticmethod(lambda _slug, _meta: {"runtime_id": "devfleet-project-legacy-vm-adopt", "address": "10.0.0.10", "state": "ready"}))
    monkeypatch.setattr(projects.VmRuntimeOperations, "stop", staticmethod(lambda _slug, _meta: {"state": "stopped"}))
    imported = {}

    def fake_import(import_slug, runtime_id, *, source_vm, project_id):
        imported.update(slug=import_slug, runtime_id=runtime_id, source_vm=source_vm, project_id=project_id)
        return {"archive_sha256": "a" * 64, "target_archive_sha256": "a" * 64, "workspace_preserved": True}

    monkeypatch.setattr(projects, "import_project_workspace", fake_import)
    monkeypatch.setattr(projects, "sync_project_vm_ssh_alias", lambda *_args, **_kwargs: {"validated": True})
    monkeypatch.setattr(projects, "start_project", lambda _slug: "started")
    monkeypatch.setattr(projects, "stop_project", lambda _slug: "stopped")
    monkeypatch.setattr(projects, "runtime_health", lambda _slug: {"ok": True, "healthy": True})
    monkeypatch.setattr(projects, "health_project", mark_healthy)

    result = projects.assign_project_runtime(slug, "vm", "small")

    saved = json.loads((project / ".devfleet" / "project.json").read_text())
    assert result["workspace_preserved"] is True
    assert saved["runtime_isolation"] == "vm"
    assert saved["runtime_provider"] == "multipass-host-agent"
    assert saved["runtime_id"] == "devfleet-project-legacy-vm-adopt"
    assert imported["source_vm"] == SETTINGS.node_name
    assert imported["project_id"] == saved["project_id"]
    assert (project / "README.md").read_text() == "workspace-preserved\n"


def test_vm_assignment_rolls_back_metadata_and_override_when_import_fails(monkeypatch: pytest.MonkeyPatch):
    slug = "legacy-vm-rollback"
    project, original = make_existing(slug)
    override = project / ".devfleet" / "runtime-resources.yaml"
    override.write_text("services:\n  app:\n    cpus: 1\n", encoding="utf-8")
    original_bytes = (project / ".devfleet" / "project.json").read_bytes()
    original_override = override.read_text()
    monkeypatch.setattr(projects, "running", lambda _project: False)
    monkeypatch.setattr(projects, "backup_project", lambda _slug: json.dumps({"backup_status": "verified", "backup_id": "test-backup", "backup_sha256": "a" * 64}))
    monkeypatch.setattr(projects, "get_host_capacity", lambda: {"capacity": {"allocatable_cpus": 8, "allocatable_memory_gb": 24, "allocatable_disk_gb": 300}})
    monkeypatch.setattr(projects.VmRuntimeOperations, "ensure", staticmethod(lambda _slug, _meta: {"runtime_id": "devfleet-project-legacy-vm-rollback", "address": "10.0.0.11", "state": "ready"}))
    monkeypatch.setattr(projects, "import_project_workspace", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("import failed")))
    destroyed = []
    monkeypatch.setattr(projects, "destroy_project_vm", lambda *args, **kwargs: destroyed.append(kwargs["runtime_id"]))

    with pytest.raises(RuntimeError, match="import failed"):
        projects.assign_project_runtime(slug, "vm", "small")

    assert (project / ".devfleet" / "project.json").read_bytes() == original_bytes
    assert override.read_text() == original_override
    assert destroyed == ["devfleet-project-legacy-vm-rollback"]


def test_vm_assignment_rejects_insufficient_capacity_before_mutation(monkeypatch: pytest.MonkeyPatch):
    slug = "legacy-capacity-reject"
    project, _ = make_existing(slug)
    original = (project / ".devfleet" / "project.json").read_bytes()
    monkeypatch.setattr(projects, "running", lambda _project: False)
    monkeypatch.setattr(projects, "get_host_capacity", lambda: {"capacity": {"allocatable_cpus": 1, "allocatable_memory_gb": 1, "allocatable_disk_gb": 10}})

    with pytest.raises(ValueError, match="capacity"):
        projects.assign_project_runtime(slug, "vm", "standard")

    assert (project / ".devfleet" / "project.json").read_bytes() == original


def test_malformed_metadata_is_not_silently_deleted(monkeypatch: pytest.MonkeyPatch):
    slug = "legacy-malformed-metadata"
    project = SETTINGS.workspaces / slug
    (project / ".devfleet").mkdir(parents=True, exist_ok=True)
    (project / "compose.yaml").write_text("services:\n  app:\n    image: ubuntu:24.04\n", encoding="utf-8")
    metadata_file = project / ".devfleet" / "project.json"
    metadata_file.write_text("{not-json", encoding="utf-8")

    with pytest.raises(ValueError, match="malformed"):
        projects.assign_project_runtime(slug, "container", "small")

    assert metadata_file.read_text() == "{not-json"
