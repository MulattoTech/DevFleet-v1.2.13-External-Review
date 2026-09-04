from pathlib import Path
from devfleet.configuration import migrate_cluster_config
def test_config_migration_does_not_touch_data(tmp_path):
 p=tmp_path/'projects/demo';v=tmp_path/'vault/repo';p.mkdir(parents=True);v.mkdir(parents=True);(p/'x').write_text('project');(v/'pack').write_text('vault');migrate_cluster_config({'SchemaVersion':1,'Primary':{'InstanceName':'p'},'Failover':{'InstanceName':'f'},'Vault':{'InstanceName':'v'},'Safety':{'RequireRootlessDocker':True,'AllowDockerTcp':False}});assert (p/'x').read_text()=='project' and (v/'pack').read_text()=='vault'
def test_snapshot_before_provision_and_rerunnable():
 t=(Path(__file__).resolve().parents[1]/'Upgrade-DevFleet.ps1').read_text();assert t.index('New-DevFleetSnapshotSafe')<t.index('02-Provision-ComputeNode.ps1');assert '$isV11=' in t;assert 'Protect-DevFleetStateAcl' in t
def test_no_destructive_instance_commands():
 t=(Path(__file__).resolve().parents[1]/'Upgrade-DevFleet.ps1').read_text().lower();assert 'multipass delete' not in t and "@('delete'" not in t and "@('purge'" not in t
