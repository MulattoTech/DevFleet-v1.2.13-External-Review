import json
import shutil
import uuid
from pathlib import Path

import pytest

import devfleet.projects as projects
from devfleet.core import SETTINGS


def _template(project: Path, _name: str) -> None:
    control = project / ".devfleet"
    control.mkdir(parents=True, exist_ok=True)
    (control / "template.json").write_text(json.dumps({
        "bootstrap_command": "./.devfleet/bootstrap.sh",
        "health_command": "./.devfleet/health-check.sh",
        "test_command": "./.devfleet/smoke-test.sh",
    }), encoding="utf-8")


def _template_metadata(_name: str) -> dict:
    return {"language": "python", "framework": "fastapi", "language_rationale": "test", "template_maturity": "stable"}


def _prepare(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(projects, "_copy_template", _template)
    monkeypatch.setattr(projects, "template_metadata", _template_metadata)


def test_vm_create_returns_coherent_metadata_and_syncs_host_alias(monkeypatch: pytest.MonkeyPatch):
    slug = f"v124-vm-create-{uuid.uuid4().hex[:8]}"
    shutil.rmtree(SETTINGS.workspaces / slug, ignore_errors=True)
    _prepare(monkeypatch)
    calls: list[tuple] = []
    runtime_id = f"devfleet-project-{slug}"
    monkeypatch.setattr(projects.VmRuntimeOperations, "ensure", staticmethod(lambda _slug, _meta: {"runtime_id": runtime_id, "address": "10.0.0.44", "state": "ready"}))
    monkeypatch.setattr(projects, "import_project_workspace", lambda *_args, **_kwargs: {"ok": True, "workspace_preserved": True, "address": "10.0.0.44"})
    monkeypatch.setattr(projects, "sync_project_vm_ssh_alias", lambda slug, runtime_id, *, project_id: calls.append((slug, runtime_id, project_id)) or {"validated": True})

    result = projects.create_project(slug, template="generic", runtime_isolation="vm", use_ollama=False)

    for key in ("project_id", "slug", "runtime_isolation", "runtime_provider", "runtime_id", "runtime_address", "ssh_alias", "workspace_host", "workspace_path", "resource_profile", "resource_limits", "provisioning_status", "lifecycle_status", "health_status", "health_scope"):
        assert key in result
    assert result["runtime_isolation"] == "vm"
    assert result["runtime_provider"] == "multipass-host-agent"
    assert result["runtime_id"] == result["ssh_alias"] == runtime_id
    assert result["runtime_address"] == result["workspace_host"] == "10.0.0.44"
    assert result["provisioning_status"] == result["lifecycle_status"] == "ready"
    assert result["health_status"] == "unknown"
    assert result["health_scope"] == "workspace-ready-not-app-healthy"
    assert calls == [(slug, result["runtime_id"], result["project_id"])]
    shutil.rmtree(SETTINGS.workspaces / slug, ignore_errors=True)


def test_container_create_returns_metadata(monkeypatch: pytest.MonkeyPatch):
    slug = f"v124-container-create-{uuid.uuid4().hex[:8]}"
    shutil.rmtree(SETTINGS.workspaces / slug, ignore_errors=True)
    _prepare(monkeypatch)

    result = projects.create_project(slug, template="generic", runtime_isolation="container", use_ollama=False)

    assert isinstance(result, dict)
    assert result["slug"] == slug
    assert result["runtime_isolation"] == "container"
    assert result["runtime_provider"] == "docker-compose"
    assert result["provisioning_status"] == result["lifecycle_status"] == "ready"
    shutil.rmtree(SETTINGS.workspaces / slug, ignore_errors=True)


def test_worktree_to_vm_is_rejected_before_provider_ensure(monkeypatch: pytest.MonkeyPatch):
    token = uuid.uuid4().hex[:8]
    source_slug, destination_slug = f"v124-worktree-source-{token}", f"v124-worktree-vm-{token}"
    source, destination = SETTINGS.workspaces / source_slug, SETTINGS.workspaces / destination_slug
    shutil.rmtree(source, ignore_errors=True)
    shutil.rmtree(destination, ignore_errors=True)
    (source / ".git").mkdir(parents=True)
    ensured: list[object] = []
    monkeypatch.setattr(projects.VmRuntimeOperations, "ensure", staticmethod(lambda *_args: ensured.append(True)))

    with pytest.raises(ValueError, match="Worktree-to-VM provisioning is blocked"):
        projects.create_project(destination_slug, template="generic", runtime_isolation="vm", worktree_source=source_slug, worktree_branch="feature", use_ollama=False)

    assert ensured == []
    assert not destination.exists()
    shutil.rmtree(source, ignore_errors=True)


def test_host_control_alias_operation_is_fixed_and_structured(monkeypatch: pytest.MonkeyPatch):
    import devfleet.host_control as host_control

    received: dict = {}
    monkeypatch.setattr(host_control, "host_control_request", lambda operation, payload, *, runtime_id: received.update(operation=operation, payload=payload, runtime_id=runtime_id) or {"ok": True})

    assert host_control.sync_project_vm_ssh_alias("v124-alias", "devfleet-project-v124-alias", project_id="12345678-1234-1234-1234-123456789abc") == {"ok": True}
    assert received == {"operation": "sync-ssh-alias", "payload": {"slug": "v124-alias", "project_id": "12345678-1234-1234-1234-123456789abc"}, "runtime_id": "devfleet-project-v124-alias"}


def test_host_agent_readiness_probe_runs_with_required_privilege():
    root = Path(__file__).resolve().parents[1]
    script = (root / "windows" / "DevFleet-HostAgent.ps1").read_text(encoding="utf-8")

    assert "@('exec',$VmName,'--','sudo','/usr/local/sbin/devfleet-project-health')" in script
    assert "@('exec',$SourceVm,'--','sudo','tar','-czf',$sourceArchive" in script
    assert "@('exec',$record.vm_name,'--','sudo','find',$targetPath" in script
    assert "@('exec',$Record.vm_name,'--','sudo','-u','devrunner','bash','--noprofile','--norc','-lc'" in script
    assert "exec $cmd" in script
    assert "workspace boundary validation failed" in script
    assert '$keyProperty="    ssh_authorized_keys:`n      - \'$key\'"' in script
    assert "Configured DevFleet SSH public key is not available" in script


def test_vm_runtime_compatibility_facade_routes_trusted_commands(monkeypatch: pytest.MonkeyPatch):
    import devfleet.runtime as runtime

    received: dict = {}
    monkeypatch.setattr(runtime.VM_RUNTIME, "command", lambda slug, metadata, operation, *, command_key="", tail=150: received.update(slug=slug, metadata=metadata, operation=operation, command_key=command_key, tail=tail) or {"ok": True})

    assert runtime.VmRuntimeOperations.command("demo", {"project_id": "id"}, "project-test", command_key="test", tail=42) == {"ok": True}
    assert received == {"slug": "demo", "metadata": {"project_id": "id"}, "operation": "project-test", "command_key": "test", "tail": 42}
