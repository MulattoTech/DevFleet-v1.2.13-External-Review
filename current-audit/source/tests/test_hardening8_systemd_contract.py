import json
from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_control_service_writable_paths_derive_from_canonical_contract():
    contract = json.loads((ROOT / "app/systemd/mutable-paths.json").read_text(encoding="utf-8"))
    service = (ROOT / "app/systemd/devfleet.service").read_text(encoding="utf-8")
    backup_service = (ROOT / "app/systemd/devfleet-backup.service").read_text(encoding="utf-8")
    bootstrap = (ROOT / "linux/bootstrap-compute.sh").read_text(encoding="utf-8")

    assert contract == {
        "schema_version": 1,
        "workspace": "/home/devrunner/workspaces",
        "quarantine": "/home/devrunner/.devfleet-quarantine",
        "transaction_root": "/home/devrunner/workspaces/.devfleet-transactions",
    }
    assert "ProtectSystem=strict" in service
    assert "ProtectHome=read-only" in service
    assert "User=devfleet-control" in service
    assert "Group=devfleet-control" in service
    assert "ReadWritePaths=__WORKSPACES__ __QUARANTINE__ __TRANSACTION_ROOT__ /var/lib/devfleet /var/cache/devfleet" in service
    assert "/home/devrunner" not in service.replace("__WORKSPACES__", "").replace("__QUARANTINE__", "")
    assert "ReadOnlyPaths=__WORKSPACES__ __QUARANTINE__" in backup_service
    assert 'MUTABLE_PATH_CONTRACT="$PAYLOAD/app/systemd/mutable-paths.json"' in bootstrap
    assert 'WORKSPACES=$(jq -er ".workspace" "$MUTABLE_PATH_CONTRACT")' in bootstrap
    assert 'QUARANTINE=$(jq -er ".quarantine" "$MUTABLE_PATH_CONTRACT")' in bootstrap
    assert 'TRANSACTION_ROOT=$(jq -er ".transaction_root" "$MUTABLE_PATH_CONTRACT")' in bootstrap
    assert '[[ $TRANSACTION_ROOT == "$WORKSPACES/.devfleet-transactions" ]]' in bootstrap
    assert 'install -d -o root -g devfleet-control -m 0750 "$WORKSPACES" "$QUARANTINE"' in bootstrap
    assert 'install -d -o devfleet-control -g devfleet-control -m 0700 "$TRANSACTION_ROOT"' in bootstrap
    assert 'chown -R devrunner:devrunner /home/devrunner/.config "$WORKSPACES"' not in bootstrap
    assert '--arg workspaces "$WORKSPACES" --arg quarantine "$QUARANTINE"' in bootstrap
    assert "__WORKSPACES__" in bootstrap and "__QUARANTINE__" in bootstrap
    assert "/etc/devfleet" not in next(line for line in service.splitlines() if line.startswith("ReadWritePaths="))
