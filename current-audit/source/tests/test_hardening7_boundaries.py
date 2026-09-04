from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import json
import re

import yaml


ROOT = Path(__file__).parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_linux_bootstrap_has_stdin_only_secret_transport_and_separated_identities():
    bootstrap = read("linux/bootstrap-compute.sh")
    service = read("app/systemd/devfleet.service")
    backup = read("app/systemd/devfleet-backup.service")
    assert '"${2:-}" == "--secrets-stdin"' in bootstrap
    assert "Refusing legacy plaintext node-secrets.json input" in bootstrap
    assert 'SECRETS_SOURCE="${PAYLOAD}/node-secrets.json"' not in bootstrap
    assert "User=devfleet-control" in service
    assert "Group=devfleet-control" in service
    assert "User=devfleet-backup" in backup
    assert "Group=devfleet-backup" in backup
    assert "chown root:devfleet-control /etc/devfleet/secrets.env" in bootstrap
    assert "chmod 0640 /etc/devfleet/secrets.env" in bootstrap
    assert "NOPASSWD:ALL" not in bootstrap
    assert "sudoers.d/devfleet-devrunner" in bootstrap


def test_windows_provisioning_never_writes_node_secret_file_or_passes_secret_argv():
    provision = read("windows/02-Provision-ComputeNode.ps1")
    common = read("windows/DevFleet.Common.psm1")
    assert "node-secrets.json" not in provision
    assert "--secrets-stdin" in provision
    assert "-StandardInputText" in provision
    assert "RedirectStandardInput" in common
    assert "-p$password" not in common
    assert "DFENV001" in common
    assert "AesGcm" in common


def test_live_vm_identity_is_guest_bound_and_stopped_operations_fail_closed():
    agent = read("windows/DevFleet-HostAgent.ps1")
    assert "project-runtime.json" in agent
    for field in ("managed_by", "project_id", "slug", "runtime_id", "host_id", "provisioning_attempt_id"):
        assert f"runtimeMeta.{field}" in agent
    assert "AllowStoppedTransition" in agent
    assert "Operation -eq 'start'" in agent
    assert "groups: [docker, sudo]" not in read("cloud-init/compute.yaml")
    assert "NOPASSWD:ALL" not in agent


def test_cleanup_is_postcondition_and_transaction_bound():
    lifecycle = read("../installer-source/DevFleet.Setup/Services/InstallerLifecycle.cs")
    services = read("../installer-source/DevFleet.Setup/Services/InstallerServices.cs")
    assert "InstallationGeneration" in lifecycle
    assert "PayloadFingerprint" in lifecycle
    assert "Owned registry entry remains after cleanup" in lifecycle
    assert "Owned shortcut remains after cleanup" in lifecycle
    assert "Owned file remains after cleanup" in services
    assert "Owned scheduled task remains after cleanup" in lifecycle
    assert "cleanup-history" in lifecycle


def test_uac_does_not_stage_before_elevation_and_vscode_is_trusted():
    main = read("../installer-source/DevFleet.Setup/MainWindow.xaml.cs")
    app = read("../installer-source/DevFleet.Setup/App.xaml.cs")
    lifecycle = read("../installer-source/DevFleet.Setup/Services/InstallerLifecycle.cs")
    assert "elevation-check" not in main
    assert "TrustedExecutableResolver.VsCodePath()" in app
    assert "UseShellExecute = false" in app
    assert "ArgumentList.Add" in app
    assert "Microsoft VS Code" in lifecycle


def test_safety_policy_restore_journal_compose_reanalysis_and_frontend_terminal_states():
    projects = read("app/devfleet/projects.py")
    restore = read("app/devfleet/workspace_archives.py")
    operations = read("app/devfleet/operations.py")
    frontend = read("app/static/app.js")
    assert "FINGERPRINT_POLICY_VERSION" in projects
    assert "fingerprint_policy" in projects
    assert "_assert_current_compose_safety" in projects
    assert "force=True" in projects
    for phase in ("PREPARED", "OLD_MOVED_TO_ROLLBACK", "NEW_PROMOTED", "POSTCHECK_PASSED", "COMMITTED"):
        assert phase in restore
    assert "BoundedSemaphore" in operations
    assert "queued_deadline_at" in operations
    for state in ("completed", "failed", "cancelled", "interrupted"):
        assert state in frontend


def test_yaml_generation_uses_rejecting_scalar_encoders():
    common = read("windows/DevFleet.Common.psm1")
    provision = read("windows/02-Provision-ComputeNode.ps1")
    vault = read("windows/03-Provision-Vault.ps1")
    assert "ConvertTo-YamlSingleQuotedScalar" in common
    assert "ConvertTo-ShellSingleQuotedScalar" in common
    assert "ConvertTo-YamlSingleQuotedScalar" in provision
    assert "ConvertTo-ShellSingleQuotedScalar" in provision
    assert "ConvertTo-YamlSingleQuotedScalar" in vault


def test_cloud_init_write_file_permissions_are_explicit_schema_strings():
    expected_counts = {"cloud-init/compute.yaml": 3, "cloud-init/vault.yaml": 2}
    for relative, expected_count in expected_counts.items():
        source = read(relative)
        assert source.count("permissions: !!str 0644") == expected_count
        assert not re.search(r"(?m)^\s+permissions:\s+(?!!!str\b)\S+", source)

        document = yaml.safe_load(source)
        permissions = [entry["permissions"] for entry in document["write_files"]]
        assert len(permissions) == expected_count
        assert all(isinstance(mode, str) and re.fullmatch(r"0[0-7]{3}", mode) for mode in permissions)


def test_project_metadata_transaction_preserves_concurrent_fields(tmp_path):
    from devfleet.projects import project_metadata_transaction

    project = tmp_path / "transaction-project"
    (project / ".devfleet").mkdir(parents=True)
    metadata = {
        "schema_version": 3,
        "managed_by": "devfleet",
        "slug": project.name,
        "identity": project.name,
        "project_id": "12345678-1234-1234-1234-123456789012",
        "runtime_provider": "docker-compose",
        "runtime_id": "",
        "host_id": "test-node",
        "health_status": "unknown",
        "lifecycle_status": "ready",
    }
    (project / ".devfleet/project.json").write_text(json.dumps(metadata), encoding="utf-8")

    def write_field(name, value):
        with project_metadata_transaction(project) as current:
            current[name] = value

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda item: write_field(*item), (("field_a", "a"), ("field_b", "b"))))
    result = json.loads((project / ".devfleet/project.json").read_text(encoding="utf-8"))
    assert result["field_a"] == "a"
    assert result["field_b"] == "b"
