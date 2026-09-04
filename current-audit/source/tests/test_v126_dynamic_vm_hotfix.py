import json
from dataclasses import replace
from pathlib import Path

import devfleet.host_control as host_control
import devfleet.projects as projects
from devfleet.core import SETTINGS


PROJECT_ID = "12345678-1234-1234-1234-123456789abc"


def _vm_project(tmp_path: Path, slug: str = "dynamic-address") -> Path:
    workspaces = tmp_path / "workspaces"
    workspaces.mkdir()
    project = workspaces / slug
    (project / ".devfleet").mkdir(parents=True)
    (project / ".devfleet" / "project.json").write_text(json.dumps({
        "slug": slug,
        "project_id": PROJECT_ID,
        "runtime_isolation": "vm",
        "runtime_type": "vm",
        "runtime_provider": "multipass-host-agent",
        "runtime_id": f"devfleet-project-{slug}",
        "runtime_address": "172.30.14.36",
        "ssh_alias": f"devfleet-project-{slug}",
        "lifecycle_status": "running",
    }), encoding="utf-8")
    return project


def test_host_agent_dynamic_address_contract_and_bridge_filter():
    script = (Path(__file__).resolve().parents[1] / "windows" / "DevFleet-HostAgent.ps1").read_text(encoding="utf-8")
    assert "$script:AgentVersion = '2.5.0'" in script
    assert "function Get-PrimaryProjectVmIpv4" in script
    assert "function Refresh-ProjectVmConnectionState" in script
    assert "172\\.(17|18|19)\\." in script
    assert "'start' {Invoke-Multipass @('start',$vmName) 120|Out-Null;Wait-ProjectVmReady $vmName|Out-Null;return Refresh-ProjectVmConnectionState" in script
    assert "'restart' {Invoke-Multipass @('restart',$vmName) 180|Out-Null;Wait-ProjectVmReady $vmName|Out-Null;return Refresh-ProjectVmConnectionState" in script


def test_refresh_operation_uses_fixed_host_agent_route(monkeypatch):
    captured = {}

    def fake_request(operation, payload, *, runtime_id=""):
        captured.update(operation=operation, payload=payload, runtime_id=runtime_id)
        return {"ok": True, "address": "172.30.13.23"}

    monkeypatch.setattr(host_control, "host_control_request", fake_request)
    result = host_control.refresh_project_vm_connection_state("dynamic-address", "devfleet-project-dynamic-address", project_id=PROJECT_ID)
    assert result["address"] == "172.30.13.23"
    assert captured == {
        "operation": "refresh-connection-state",
        "payload": {"slug": "dynamic-address", "project_id": PROJECT_ID},
        "runtime_id": "devfleet-project-dynamic-address",
    }


def test_stopped_vm_runtime_health_is_read_only(monkeypatch, tmp_path):
    project = _vm_project(tmp_path, "stopped-health")
    monkeypatch.setattr(projects, "SETTINGS", replace(SETTINGS, workspaces=project.parent))
    calls = []
    monkeypatch.setattr(projects.VmRuntimeOperations, "inspect", staticmethod(lambda *_: calls.append("inspect") or {"ok": True, "info": {"state": "Stopped"}}))
    monkeypatch.setattr(projects.VmRuntimeOperations, "health", staticmethod(lambda *_: (_ for _ in ()).throw(AssertionError("guest health must not run"))))

    result = projects.runtime_health("stopped-health")

    assert result["state"] == "stopped"
    assert result["runtime_health"] == "not-run-stopped"
    assert result["application_health"] == "not-run-stopped"
    assert result["guest_exec_performed"] is False
    assert calls == ["inspect"]


def test_running_vm_health_uses_guest_health_after_inspect(monkeypatch, tmp_path):
    project = _vm_project(tmp_path, "running-health")
    monkeypatch.setattr(projects, "SETTINGS", replace(SETTINGS, workspaces=project.parent))
    calls = []
    monkeypatch.setattr(projects.VmRuntimeOperations, "inspect", staticmethod(lambda *_: calls.append("inspect") or {"ok": True, "info": {"state": "Running"}}))
    monkeypatch.setattr(projects.VmRuntimeOperations, "health", staticmethod(lambda *_: calls.append("health") or {"ok": True, "healthy": True, "state": "healthy"}))

    result = projects.runtime_health("running-health")

    assert result["healthy"] is True
    assert calls == ["inspect", "health"]


def test_open_workspace_blocks_address_only_legacy_refresh(monkeypatch, tmp_path):
    project = _vm_project(tmp_path, "open-workspace")
    monkeypatch.setattr(projects, "SETTINGS", replace(SETTINGS, workspaces=project.parent))
    monkeypatch.setattr(projects.VmRuntimeOperations, "inspect", staticmethod(lambda *_: {"ok": True, "info": {"state": "Running"}}))
    monkeypatch.setattr(projects.VmRuntimeOperations, "refresh", staticmethod(lambda *_: {"ok": True, "address": "172.30.13.23"}))

    result = projects.open_workspace("open-workspace")
    saved = json.loads((project / ".devfleet" / "project.json").read_text(encoding="utf-8"))

    assert result["ok"] is False
    assert result["launcher_uri"] == ""
    assert result["readiness"]["ready"] is False
    assert "ready" in result["error"].lower() or "proof" in result["error"].lower()
    assert saved["runtime_address"] == "172.30.13.23"
    assert saved["workspace_host"] == "172.30.13.23"


def test_open_workspace_does_not_start_stopped_vm(monkeypatch, tmp_path):
    project = _vm_project(tmp_path, "open-stopped")
    monkeypatch.setattr(projects, "SETTINGS", replace(SETTINGS, workspaces=project.parent))
    monkeypatch.setattr(projects.VmRuntimeOperations, "inspect", staticmethod(lambda *_: {"ok": True, "info": {"state": "Stopped"}}))
    monkeypatch.setattr(projects.VmRuntimeOperations, "refresh", staticmethod(lambda *_: (_ for _ in ()).throw(AssertionError("refresh must not run for stopped VM"))))

    result = projects.open_workspace("open-stopped")

    assert result["ok"] is False
    assert result["state"] == "stopped"
    assert "Start it explicitly" in result["error"]
