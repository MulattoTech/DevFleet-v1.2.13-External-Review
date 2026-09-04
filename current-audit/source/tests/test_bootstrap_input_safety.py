from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_compute_bootstrap_validates_numeric_and_secret_boundaries_before_templates():
    source = (ROOT / "linux" / "bootstrap-compute.sh").read_text(encoding="utf-8")
    assert "PORT =~ ^[0-9]+$" in source
    assert "BACKUP_INTERVAL =~ ^[0-9]+$" in source
    assert "value != *$'\\r'*" in source
    assert "value != *$'\\n'*" in source
    assert "python3 - \"$SECRETS_ENV_TMP\"" in source
    assert "target.replace('/etc/devfleet/secrets.env')" in source
    assert "DEVFLEET_ADMIN_PASSWORD=$ADMIN_PASSWORD" not in source


def test_compute_bootstrap_uses_structured_json_generation():
    source = (ROOT / "linux" / "bootstrap-compute.sh").read_text(encoding="utf-8")
    assert "jq -n" in source
    assert "--arg" in source
    assert "--argjson" in source
    assert 's|__PORT__|$PORT|g' in source
    assert 's|__WORKSPACES__|$WORKSPACES|g' in source
    assert 's|__QUARANTINE__|$QUARANTINE|g' in source
