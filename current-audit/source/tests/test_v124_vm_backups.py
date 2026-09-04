import tarfile
from pathlib import Path

import pytest

from devfleet import projects
from devfleet.core import SETTINGS, atomic_json
from devfleet.workspace_archives import create_workspace_archive


ROOT = Path(__file__).resolve().parents[1]


def _vm_project(slug: str) -> Path:
    project = SETTINGS.workspaces / slug
    (project / ".devfleet").mkdir(parents=True, exist_ok=True)
    atomic_json(project / ".devfleet/project.json", {
        "schema_version": 3,
        "managed_by": "devfleet",
        "project_id": "11111111-1111-1111-1111-111111111111",
        "slug": slug,
        "host_id": "test-node",
        "runtime_isolation": "vm",
        "runtime_provider": "multipass-host-agent",
        "runtime_id": f"devfleet-project-{slug}",
    })
    return project


def test_vm_backup_history_uses_host_provider(monkeypatch):
    slug = "v124-vm-history"
    project = _vm_project(slug)
    expected = [{"backup_id": "v124-vm-history-20260810-000000-deadbeef", "provider": "multipass-host-agent", "restore_eligible": True}]
    monkeypatch.setattr(projects.VM_RUNTIME, "list_backups", lambda selected, metadata: expected)
    try:
        assert projects.list_backups(slug) == expected
    finally:
        import shutil
        shutil.rmtree(project, ignore_errors=True)


def test_vm_restore_requires_deliberate_overwrite_confirmation(monkeypatch):
    slug = "v124-vm-restore"
    project = _vm_project(slug)
    called = []
    monkeypatch.setattr(projects.VM_RUNTIME, "restore_backup", lambda selected, metadata, backup_id, confirm_restore=False: called.append((backup_id, confirm_restore)) or {"backup_sha256": "a" * 64})
    try:
        with pytest.raises(ValueError, match="overwrite confirmation"):
            projects.restore_backup(slug, "v124-vm-restore-20260810-000000-deadbeef", confirm_restore=True, allow_overwrite=False)
        result = projects.restore_backup(slug, "v124-vm-restore-20260810-000000-deadbeef", confirm_restore=True, allow_overwrite=True)
        assert result["provider"] == "multipass-host-agent"
        assert called == [("v124-vm-restore-20260810-000000-deadbeef", True)]
    finally:
        import shutil
        shutil.rmtree(project, ignore_errors=True)


def test_generated_symlink_directory_is_excluded_from_workspace_archive(tmp_path):
    slug = "generated-exclusion"
    workspace = tmp_path / slug
    (workspace / ".devfleet").mkdir(parents=True)
    (workspace / ".devfleet/project.json").write_text('{"project_id":"11111111-1111-1111-1111-111111111111"}', encoding="utf-8")
    (workspace / "src").mkdir()
    (workspace / "src/main.js").write_text("console.log('ok')", encoding="utf-8")
    generated_bin = workspace / "node_modules/.bin"
    generated_bin.mkdir(parents=True)
    target = workspace / "node_modules/tool.js"
    target.write_text("generated", encoding="utf-8")
    try:
        (generated_bin / "tool").symlink_to(target)
    except OSError:
        pytest.skip("Symlink creation is unavailable on this platform")
    archive = tmp_path / "workspace.tar.gz"
    result = create_workspace_archive(workspace, slug, archive)
    assert "node_modules" in result["generated_dirs"]
    with tarfile.open(archive, "r:gz") as handle:
        names = handle.getnames()
    assert f"{slug}/src/main.js" in names
    assert not any("node_modules" in name for name in names)


def test_host_agent_backup_and_export_share_generated_directory_exclusions():
    source = (ROOT / "windows/DevFleet-HostAgent.ps1").read_text(encoding="utf-8")
    assert "function New-VerifiedRemoteWorkspaceArchive" in source
    assert 'excluded = {"node_modules", ".next", "build", "dist", ".venv", "venv", ".pytest_cache", "__pycache__", ".test-runtime"}' in source
    assert source.count("New-VerifiedRemoteWorkspaceArchive $Record.vm_name $remoteArchive") >= 2
    assert all(operation in source for operation in ("'list-backups'", "'inspect-backup'", "'restore-backup'"))
