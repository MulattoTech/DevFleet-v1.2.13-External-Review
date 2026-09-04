from pathlib import Path
from types import SimpleNamespace

import pytest

from devfleet.runtime import CONTAINER_PROVIDER, VM_PROVIDER, provider_for
from devfleet import host_control, workspace_archives
from devfleet.version import __version__
from devfleet.workspace_archives import create_workspace_archive, inspect_workspace, validate_archive, write_backup_manifest, restore_workspace_archive


def test_version_and_provider_contract():
    root = Path(__file__).resolve().parents[1]
    expected = (root / "VERSION").read_text(encoding="utf-8").strip()
    assert expected == "1.2.13"
    assert __version__ == expected
    assert provider_for({}) == CONTAINER_PROVIDER
    assert provider_for({"runtime_provider": "multipass"}) == VM_PROVIDER
    assert provider_for({"runtime_isolation": "vm", "runtime_provider": "docker-compose"}) == VM_PROVIDER


def test_workspace_archive_is_reopenable_and_identity_bound(tmp_path: Path):
    workspace = tmp_path / "demo-project"
    (workspace / ".devfleet").mkdir(parents=True)
    (workspace / ".devfleet" / "project.json").write_text('{"project_id":"123"}\n', encoding="utf-8")
    (workspace / "README.md").write_text("hello\n", encoding="utf-8")
    inspection = inspect_workspace(workspace)
    assert inspection["safe_for_archive"] is True
    archive = tmp_path / "backups" / "demo-project.tar.gz"
    result = create_workspace_archive(workspace, "demo-project", archive)
    assert result["verified"] is True
    assert validate_archive(archive, "demo-project")["archive_sha256"] == result["archive_sha256"]
    manifest = write_backup_manifest(tmp_path / "backups" / "demo-project-1", slug="demo-project", project_id="123", runtime={"provider": "docker-compose"}, archive=result)
    assert manifest["verification"]["status"] == "verified"


def test_workspace_archive_rejects_symbolic_links_when_supported(tmp_path: Path):
    workspace = tmp_path / "demo-project"
    (workspace / ".devfleet").mkdir(parents=True)
    (workspace / ".devfleet" / "project.json").write_text("{}\n", encoding="utf-8")
    link = workspace / "link"
    try:
        link.symlink_to(workspace / ".devfleet" / "project.json")
    except (OSError, NotImplementedError):
        return
    assert inspect_workspace(workspace)["safe_for_archive"] is False


def test_workspace_restore_refuses_cross_filesystem_promotion(tmp_path: Path, monkeypatch):
    workspace = tmp_path / "demo-project"
    (workspace / ".devfleet").mkdir(parents=True)
    (workspace / ".devfleet" / "project.json").write_text("{}\n", encoding="utf-8")
    archive = tmp_path / "demo-project.tar.gz"
    create_workspace_archive(workspace, "demo-project", archive)
    if workspace_archives.POSIX_FD_HARDENING:
        original_open = workspace_archives._open_verified_child

        def different_filesystem(parent_fd, name, expected_type):
            fd, result = original_open(parent_fd, name, expected_type)
            if name == "demo-project":
                result = SimpleNamespace(st_dev=int(result.st_dev) + 1, st_ino=result.st_ino, st_mode=result.st_mode)
            return fd, result

        monkeypatch.setattr(workspace_archives, "_open_verified_child", different_filesystem)
    else:
        monkeypatch.setattr("devfleet.workspace_archives._assert_same_filesystem", lambda *_: (_ for _ in ()).throw(ValueError("different filesystems")))
    with pytest.raises(ValueError, match="different filesystems"):
        restore_workspace_archive(archive, tmp_path / "destination", "demo-project")


def test_workspace_archive_excludes_generated_directories(tmp_path: Path):
    workspace = tmp_path / "demo-project"
    (workspace / ".devfleet").mkdir(parents=True)
    (workspace / ".devfleet" / "project.json").write_text("{}\n", encoding="utf-8")
    (workspace / "node_modules" / "package").mkdir(parents=True)
    (workspace / "node_modules" / "package" / "generated.js").write_text("generated\n", encoding="utf-8")
    (workspace / "README.md").write_text("kept\n", encoding="utf-8")
    inspection = inspect_workspace(workspace)
    assert inspection["generated_dirs"] == ["node_modules"]
    archive = tmp_path / "backups" / "demo-project.tar.gz"
    create_workspace_archive(workspace, "demo-project", archive)
    import tarfile
    with tarfile.open(archive, "r:gz") as handle:
        names = handle.getnames()
    assert "demo-project/README.md" in names
    assert not any(name.startswith("demo-project/node_modules/") for name in names)


def test_host_agent_contract_has_verified_archive_and_fixed_project_commands():
    root = Path(__file__).resolve().parents[1]
    script = (root / "windows" / "DevFleet-HostAgent.ps1").read_text(encoding="utf-8")
    assert "$script:AgentVersion = '2.5.0'" in script
    assert "function Export-ProjectWorkspaceToSource" in script
    assert "archive_sha256" in script
    assert "manifestPath" in script
    assert "Invoke-ProjectCommand" in script
    assert "Invoke-Expression" not in script


def test_project_vm_operations_use_fixed_routes_and_bound_log_tail(monkeypatch):
    captured = {}

    def fake_request(operation, payload, *, runtime_id=""):
        captured.update(operation=operation, payload=payload, runtime_id=runtime_id)
        return {"ok": True, "host_name": "MULATTOTECHBOX"}

    monkeypatch.setattr(host_control, "host_control_request", fake_request)
    result = host_control.project_vm_operation(
        "demo-project",
        "project-logs",
        runtime_id="devfleet-project-demo-project",
        project_id="12345678-1234-1234-1234-123456789012",
        tail=9999,
    )
    assert result["ok"] is True
    assert captured["operation"] == "project-logs"
    assert captured["runtime_id"] == "devfleet-project-demo-project"
    assert captured["payload"]["tail"] == 500


def test_permanent_vm_destroy_requires_artifact_identity():
    with pytest.raises(ValueError, match="identified, hashed"):
        host_control.destroy_project_vm(
            "demo-project",
            "demo-project",
            "DESTROY demo-project",
            runtime_id="devfleet-project-demo-project",
            project_id="12345678-1234-1234-1234-123456789012",
        )


def test_dashboard_has_bounded_logs_and_read_only_preflight_routes():
    root = Path(__file__).resolve().parents[1]
    main = (root / "app" / "devfleet" / "main.py").read_text(encoding="utf-8")
    assert any(marker in main for marker in ("@app.get('/api/projects/{slug}/logs'", '@app.get("/api/projects/{slug}/logs"'))
    assert any(marker in main for marker in ("max(1,min(int(tail),500))", "max(1, min(int(tail), 500))"))
    assert any(marker in main for marker in ("@app.get('/api/projects/{slug}/preflight'", '@app.get("/api/projects/{slug}/preflight"'))
    assert any(marker in main for marker in ("'migration_would_be_performed':False", "'migration_would_be_performed': False", '"migration_would_be_performed": False'))
