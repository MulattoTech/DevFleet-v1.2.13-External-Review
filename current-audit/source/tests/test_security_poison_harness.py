import json
from pathlib import Path


ROOT = Path(__file__).parents[2]


def test_security_poison_has_a_dedicated_phase_executor_and_schema():
    config = json.loads((ROOT / "automation/release-e2e/config/devfleet-e2e.defaults.json").read_text(encoding="utf-8"))
    executor = config["FullReleaseExecutors"]["SECURITY-POISON"]
    assert config["HarnessVersion"] == "1.5.0"
    assert executor.endswith("Invoke-SecurityPoisonPhase.ps1")
    assert "Invoke-HostAgentPhase" not in executor
    source = (ROOT / executor).read_text(encoding="utf-8")
    for scenario in (
        "DEPENDENCY-TRUST",
        "PROVISIONING-OWNERSHIP",
        "HOST-AGENT-PROTOCOL",
        "PROJECT-MUTATION-AUTHORITY",
        "SSH-READINESS",
        "SECURITY-CONFIGURATION",
        "PACKAGE-WATCHDOG",
    ):
        assert scenario in source
    assert "REAL E2E PASS" in source
    assert "Invoke-ActualWpfAction" not in source


def test_primary_and_linux_do_not_alias_generic_wpf_fresh_install():
    config = json.loads((ROOT / "automation/release-e2e/config/devfleet-e2e.defaults.json").read_text(encoding="utf-8"))
    assert config["FullReleaseExecutors"]["PRIMARY"].endswith("Invoke-PrimaryPhase.ps1")
    assert config["FullReleaseExecutors"]["LINUX"].endswith("Invoke-LinuxPhase.ps1")
    primary = (ROOT / config["FullReleaseExecutors"]["PRIMARY"]).read_text(encoding="utf-8")
    linux = (ROOT / config["FullReleaseExecutors"]["LINUX"]).read_text(encoding="utf-8")
    assert "Invoke-PrimaryRolePhase" in primary
    assert "Invoke-ActualWpfAction $context 'FreshInstall'" not in linux
    assert "Invoke-LinuxBootstrapPhase" in linux
