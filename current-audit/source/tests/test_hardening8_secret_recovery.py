from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_rekey_is_explicit_transactional_and_commits_last():
    script = (ROOT / "windows/Repair-DevFleetHostSecrets.ps1").read_text(encoding="utf-8")
    assert "ValidateSet('REKEY DEVFLEET HOST SECRETS')" in script
    assert "New-DevFleetSnapshotSafe" in script
    assert "Get-ExactGuestIdentity" in script
    assert "Assert-DevFleetTaskBinding" in script
    assert "-StandardInputText" in script
    assert "host-secrets.before.json" in script
    assert "rollback" in script
    assert "plaintextSecretsLogged=$false" in script
    assert script.index("$evidence.hostAgent.verified = $true") < script.index("Write-AtomicUtf8 -Path $secretPath")
    assert script.index("Write-AtomicUtf8 -Path $secretPath") < script.index("$committed = $true")


def test_rekey_helpers_bind_identity_verify_and_preserve_rollback_state():
    compute = (ROOT / "linux/devfleet-rotate-compute-secrets").read_text(encoding="utf-8")
    vault = (ROOT / "linux/devfleet-rotate-vault-secrets").read_text(encoding="utf-8")
    assert "/etc/devfleet/node-identity.json" in compute
    assert "deployment_id" in compute and "node_id" in compute
    assert "X-DevFleet-Token" in compute and "/api/status" in compute
    assert 'MODE == rollback' in compute
    assert "/etc/devfleet-vault-identity.json" in vault
    assert "deployment_id" in vault and "node_id" in vault
    assert "htpasswd -iv" in vault
    assert 'MODE == rollback' in vault
    assert "rest_password" not in " ".join(line for line in vault.splitlines() if line.startswith("printf '{"))


def test_missing_or_corrupt_existing_secrets_never_silently_regenerate():
    common = (ROOT / "windows/DevFleet.Common.psm1").read_text(encoding="utf-8")
    missing_guard = "if (Test-ExistingDeploymentState) { throw 'SECRET RECOVERY REQUIRED: host secrets are missing"
    corrupt_guard = "if (Test-ExistingDeploymentState) { throw 'SECRET RECOVERY REQUIRED: host secrets are corrupt"
    assert missing_guard in common
    assert corrupt_guard in common
    assert "Test-DevFleetSecretRecord" in common


def test_cluster_join_persists_deployment_binding_for_future_rekey():
    complete = (ROOT / "windows/Complete-Cluster.ps1").read_text(encoding="utf-8")
    assert "$hostIdentity.deployment_id=[string]$primaryNode.deployment_id" in complete
    assert "$vaultIdentity.deployment_id=[string]$primaryNode.deployment_id" in complete
    assert "/etc/devfleet-vault-identity.json" in complete
