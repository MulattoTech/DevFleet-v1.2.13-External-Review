from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from devfleet import main, projects


def _project(root: Path, slug: str, state: str, *, isolation: str = "vm") -> Path:
    project = root / slug
    (project / ".devfleet").mkdir(parents=True)
    metadata = {
        "slug": slug,
        "display_name": "Stopped Project",
        "runtime_isolation": isolation,
        "runtime_type": isolation,
        "runtime_provider": "multipass-host-agent" if isolation == "vm" else "docker-compose",
        "lifecycle_status": state,
        "runtime_status": state,
        "runtime_id": f"devfleet-project-{slug}",
        "runtime_address": "172.30.1.20" if state == "running" else "",
        "ssh_alias": f"devfleet-project-{slug}",
        "ssh_host_key_pinned": state == "running",
        "ssh_authenticated": state == "running",
        "ssh_validation_passed": state == "running",
        "workspace_provisioned": True,
        "resource_profile": "large",
        "resource_limits": {"cpus": 4, "memory": "8G", "memory_gb": 8, "disk_gb": 80},
    }
    (project / ".devfleet" / "project.json").write_text(json.dumps(metadata), encoding="utf-8")
    return project


@pytest.mark.parametrize(
    ("state", "can_start", "can_stop", "live", "transitioning"),
    [
        ("stopped", True, False, False, False),
        ("starting", False, True, False, True),
        ("running", False, True, True, False),
        ("stopping", False, False, False, True),
        ("unreachable", True, False, False, False),
    ],
)
def test_vm_capability_state_matrix(tmp_path, monkeypatch, state, can_start, can_stop, live, transitioning):
    monkeypatch.setattr(projects, "SETTINGS", replace(projects.SETTINGS, workspaces=tmp_path))
    _project(tmp_path, state, state)
    caps = projects.project_capabilities(state)
    assert caps["can_start"] is can_start
    assert caps["can_stop"] is can_stop
    assert caps["runtime_transitioning"] is transitioning
    assert caps["can_query_live_metrics"] is live
    assert caps["can_query_application_health"] is live
    assert caps["can_query_logs"] is live


def test_stopped_runtime_endpoint_makes_zero_live_calls(tmp_path, monkeypatch):
    settings = replace(projects.SETTINGS, workspaces=tmp_path)
    monkeypatch.setattr(projects, "SETTINGS", settings)
    monkeypatch.setattr(main, "SETTINGS", settings)
    _project(tmp_path, "demo", "stopped")
    monkeypatch.setattr(main, "inspect_runtime", lambda *_: pytest.fail("inspect must not run"))
    monkeypatch.setattr(main, "runtime_health", lambda *_: pytest.fail("health must not run"))
    result = main.api_project_runtime("demo")
    assert result["runtime"]["live_metrics"] == "unavailable"
    assert result["health"]["status"] == "not-checked"


def test_stopped_logs_endpoints_make_zero_guest_calls(tmp_path, monkeypatch):
    settings = replace(projects.SETTINGS, workspaces=tmp_path)
    monkeypatch.setattr(projects, "SETTINGS", settings)
    monkeypatch.setattr(main, "SETTINGS", settings)
    _project(tmp_path, "demo", "stopped")
    monkeypatch.setattr(main, "project_logs", lambda *_args, **_kwargs: pytest.fail("logs must not run"))
    monkeypatch.setattr(main, "ui", lambda *_args, **_kwargs: None)
    request = type("Request", (), {})()
    response = main.ui_project_logs(request, "demo")
    assert response.status_code == 409
    with pytest.raises(Exception) as exc:
        main.api_project_logs("demo")
    assert getattr(exc.value, "status_code", None) == 409


def test_stopped_project_html_is_terminal_and_keeps_resources(tmp_path, monkeypatch):
    settings = replace(projects.SETTINGS, workspaces=tmp_path)
    monkeypatch.setattr(projects, "SETTINGS", settings)
    monkeypatch.setattr(main, "SETTINGS", settings)
    _project(tmp_path, "demo", "stopped")
    catalog = projects.list_project_catalog()
    assert catalog[0]["resource_limits"] == {"cpus": 4, "memory": "8G", "memory_gb": 8, "disk_gb": 80}
    template = (Path(__file__).parents[1] / "app" / "templates" / "index.html").read_text(encoding="utf-8")
    js = (Path(__file__).parents[1] / "app" / "static" / "app.js").read_text(encoding="utf-8")
    assert "Project is stopped" in template
    assert "Start the project to view live logs" in template
    assert "caps.can_query_logs" in template
    assert "fetchWithTimeout" in js and "AbortController" in js


def test_container_workspace_nonregression_when_application_stopped(tmp_path, monkeypatch):
    monkeypatch.setattr(projects, "SETTINGS", replace(projects.SETTINGS, workspaces=tmp_path))
    _project(tmp_path, "container-demo", "stopped", isolation="container")
    meta = projects.load_meta(tmp_path / "container-demo")
    meta.update({"workspace_host": "devfleet-primary", "ssh_alias": "devfleet-primary", "workspace_accessible": True})
    ready = projects.workspace_readiness("container-demo", meta)
    caps = projects.project_capabilities("container-demo", meta)
    assert ready["ready"] is True
    assert caps["can_open_workspace"] is True
    assert caps["can_query_logs"] is False
