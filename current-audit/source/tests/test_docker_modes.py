from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def test_both_docker_stores_are_detected_and_reported():
 text=(ROOT/'linux/devfleet-docker-mode-report').read_text()
 assert 'Rootless store:' in text and 'Rootful store:' in text
 assert 'Stores are separate' in text

def test_switch_requires_rootful_ack_and_never_prunes():
 text=(ROOT/'linux/devfleet-switch-docker-mode').read_text()
 assert '--acknowledge-rootful' in text
 assert 'docker system prune' not in text
 assert 'Stores were not migrated or deleted' in text

def test_clean_installer_requires_rootful_acknowledgement():
 text=(ROOT/'Install-DevFleet.ps1').read_text()
 assert 'ENABLE ROOTFUL CODEXDEVVM' in text

def test_windows_mode_wrapper_snapshots_and_updates_authoritative_config():
 text=(ROOT/'windows/Set-DevFleetDockerMode.ps1').read_text()
 assert 'New-DevFleetSnapshotSafe' in text and 'Save-DevFleetConfig' in text
 assert '-AcknowledgeRootful' in text
 assert "@('delete'" not in text.lower() and 'multipass delete' not in text.lower()

def test_update_and_repair_follow_selected_docker_mode():
 for rel in ('linux/devfleet-safe-update','linux/devfleet-repair','linux/devfleet-user-repair'):
  text=(ROOT/rel).read_text()
  lower=text.lower()
  assert "docker_mode" in lower and 'rootless' in lower and 'rootful' in lower

def test_windows_maintenance_uses_stopped_state_snapshot_helper():
 for rel in ('windows/Update-DevFleet.ps1','windows/Repair-DevFleet.ps1','windows/03-Provision-Vault.ps1'):
  text=(ROOT/rel).read_text()
  assert 'New-DevFleetSnapshotSafe' in text
