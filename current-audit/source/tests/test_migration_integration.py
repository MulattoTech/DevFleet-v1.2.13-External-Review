from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
MIGRATE = ROOT / "windows" / "Migrate-Config.ps1"
PWSH = shutil.which("pwsh")
PWSH_REQUIRED = os.environ.get("DEVFLEET_REQUIRE_PWSH_TESTS") == "1"
if PWSH_REQUIRED and PWSH is None:
    raise RuntimeError(
        "BLOCKED — required PowerShell release-test prerequisite pwsh is unavailable"
    )
requires_pwsh = pytest.mark.skipif(
    PWSH is None,
    reason="SKIP — platform prerequisite: pwsh is unavailable",
)


def _run(config: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(PWSH), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(MIGRATE), "-ConfigPath", str(config), "-OutputPath", str(config), *extra],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def _legacy_config() -> dict:
    return {
        "SchemaVersion": 1,
        "PackageVersion": "1.0.0",
        "Primary": {"InstanceName": "DevFleet-E2E-primary"},
        "Failover": {"InstanceName": "DevFleet-E2E-failover"},
        "Vault": {"InstanceName": "DevFleet-E2E-vault"},
        "Development": {"Profile": "balanced"},
        "Docker": {"PrimaryMode": "rootful", "FailoverMode": "rootful"},
    }


@requires_pwsh
def test_supported_schema_migrates_in_place_and_preserves_identity(tmp_path: Path):
    config = tmp_path / "devfleet.config.json"
    config.write_text(json.dumps(_legacy_config()), encoding="utf-8")
    result = _run(config, "-Confirm:$false")
    assert result.returncode == 0, result.stderr
    migrated = json.loads(config.read_text(encoding="utf-8"))
    assert migrated["SchemaVersion"] == 2
    assert migrated["PackageVersion"] == "1.1.0"
    assert migrated["Primary"]["InstanceName"] == "DevFleet-E2E-primary"
    assert migrated["Failover"]["InstanceName"] == "DevFleet-E2E-failover"
    assert migrated["Vault"]["InstanceName"] == "DevFleet-E2E-vault"
    assert migrated["Development"]["Profile"] == "strict"
    assert migrated["Docker"]["PrimaryMode"] == "rootless"


@requires_pwsh
def test_preview_and_malformed_migration_are_non_destructive(tmp_path: Path):
    config = tmp_path / "devfleet.config.json"
    original = json.dumps(_legacy_config(), indent=2)
    config.write_text(original, encoding="utf-8")
    preview = _run(config, "-PreviewOnly")
    assert preview.returncode == 0, preview.stderr
    assert config.read_text(encoding="utf-8") == original
    assert list(tmp_path.glob("devfleet-v1.1.0-migration-preview-*.json"))

    config.write_text("{not-json", encoding="utf-8")
    failed = _run(config, "-Confirm:$false")
    assert failed.returncode != 0
    assert config.read_text(encoding="utf-8") == "{not-json"


def test_upgrade_script_orders_backup_and_snapshot_before_provisioning():
    upgrade = (ROOT / "Upgrade-DevFleet.ps1").read_text(encoding="utf-8")
    assert upgrade.index("upgrade-backups") < upgrade.index("New-DevFleetSnapshotSafe")
    assert upgrade.index("New-DevFleetSnapshotSafe") < upgrade.index("02-Provision-ComputeNode.ps1")
    assert "Protect-DevFleetStateAcl" in upgrade
