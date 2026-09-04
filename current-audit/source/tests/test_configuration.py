from devfleet.configuration import migrate_cluster_config,validate_cluster_config
def schema1(rootless=True):return {'SchemaVersion':1,'ClusterName':'custom','Primary':{'InstanceName':'p','Cpus':99},'Failover':{'InstanceName':'f'},'Vault':{'InstanceName':'v'},'Ollama':{'BaseUrl':'http://old/v1','Model':'m'},'Network':{'PortalPort':9999},'Backup':{},'Safety':{'RequireRootlessDocker':rootless,'AllowDockerTcp':False}}
def test_migration_preserves_values_and_names():
 out,changes=migrate_cluster_config(schema1());validate_cluster_config(out);assert out['Primary']['InstanceName']=='p' and out['Primary']['Cpus']==99;assert out['Development']['Profile']=='strict';assert out['Docker']['PrimaryMode']=='rootless';assert out['Primary']['FriendlyName']=='CodexDevVM';assert changes
def test_clean_install_balanced():assert migrate_cluster_config(schema1(),clean_install=True)[0]['Development']['Profile']=='balanced'
def test_custom_safety_preserved_without_store_switch():
 out,_=migrate_cluster_config(schema1(False));assert out['Safety']['RequireRootlessDocker'] is False;assert out['Docker']['PrimaryMode']=='rootless'
def test_docker_tcp_rejected():
 out,_=migrate_cluster_config(schema1());out['Safety']['AllowDockerTcp']=True
 try:validate_cluster_config(out)
 except ValueError:pass
 else:raise AssertionError('must reject Docker TCP')
