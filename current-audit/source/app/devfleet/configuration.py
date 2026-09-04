from __future__ import annotations
from copy import deepcopy
from typing import Any
SCHEMA_VERSION=2
PROFILE_NAMES={'strict','balanced','fast'}
DOCKER_MODES={'rootless','rootful'}

def _setdefault_path(data:dict[str,Any],path:tuple[str,...],value:Any)->None:
    cur=data
    for key in path[:-1]:cur=cur.setdefault(key,{})
    cur.setdefault(path[-1],value)

def migrate_cluster_config(source:dict[str,Any],*,clean_install:bool=False)->tuple[dict[str,Any],list[str]]:
    data=deepcopy(source); version=int(data.get('SchemaVersion',1)); changes=[]
    if version>2: raise ValueError(f'Configuration schema {version} is newer than this package supports.')
    if version==1:
        profile='balanced' if clean_install else 'strict'
        _setdefault_path(data,('Hosts',),{'DesktopFriendlyName':'DevFleet Primary','LaptopFriendlyName':'DevFleet Surrogate'})
        for key,friendly,alias in [('Primary','CodexDevVM','CodexDevVM'),('Failover','DevFleetFailover','DevFleetFailover'),('Vault','DevFleetVault','DevFleetVault')]:
            node=data.setdefault(key,{}); node.setdefault('FriendlyName',friendly); node.setdefault('SshAlias',alias)
        data.setdefault('Development',{'Profile':profile,'EnableSharedBuildCaches':profile!='strict','EnableAnalyzerCache':True,'EnableTrustedOrchestrator':True,'AllowLoopbackPortPublishing':True,'AllowTailnetPortPublishing':profile!='strict','AutoStartCodexPro':True,'AutoStartProjectServices':True,'RequireConfirmationForRoutineRebuild':False,'RequireConfirmationForRoutineRepair':False,'BackupBeforeRebuild':False,'BackupBeforeQuarantine':True})
        data.setdefault('Docker',{'PrimaryMode':'rootless','FailoverMode':'rootless','EnableBuildKit':True,'EnableSharedBuildCache':profile!='strict','EnableRegistryCache':False,'RootfulModeAcknowledged':False})
        data.setdefault('CodexPro',{'Mode':'project-scoped-adapter','AutoBootstrap':True,'ToolCards':True,'DefaultHost':'127.0.0.1','DefaultPort':8787,'SharedTransportStatus':'adapter-only-until-a-verified-multi-workspace-registration-interface-is-exposed'})
        ollama=data.setdefault('Ollama',{}); ollama.setdefault('PreferredBaseUrl',''); ollama.setdefault('Profile','stable-interactive'); ollama.setdefault('ProfilesFile','config/ollama-profiles.json')
        network=data.setdefault('Network',{}); network.setdefault('TailnetCidr','100.64.0.0/10'); network.setdefault('PublicBindingAllowed',False)
        backup=data.setdefault('Backup',{}); backup.setdefault('RequireVerifiedBackupBeforeQuarantine',True); backup.setdefault('OfflineExportEnabled',True)
        safety=data.setdefault('Safety',{}); safety.setdefault('BlockWindowsPaths',True); safety.setdefault('BlockUncPaths',True); safety.setdefault('BlockWorkspaceEscape',True); safety.setdefault('OrdinaryContainersMayMountDockerSocket',False)
        data.setdefault('LanguagePolicy',{'DefaultAutomation':'python','DefaultWindowsAdministration':'powershell','DefaultLinuxAdministration':'bash-or-python','DefaultCrossPlatformCli':'go','DefaultWebFrontend':'typescript','DefaultRapidApi':'python-fastapi'})
        data['SchemaVersion']=2
        changes += ['SchemaVersion: 1 -> 2',f'Development.Profile: {profile}','Existing rootless Docker stores preserved; no implicit image/volume migration','Primary friendly name and SSH alias: CodexDevVM; instance remains devfleet-primary']
    data['PackageVersion']=__import__('devfleet.version',fromlist=['__version__']).__version__
    return data,changes

def validate_cluster_config(data:dict[str,Any])->None:
    if int(data.get('SchemaVersion',0))!=2: raise ValueError('SchemaVersion must be 2 after migration.')
    if str(data.get('Development',{}).get('Profile','')).lower() not in PROFILE_NAMES: raise ValueError('Unknown development profile.')
    for key in ('PrimaryMode','FailoverMode'):
        if str(data.get('Docker',{}).get(key,'')).lower() not in DOCKER_MODES: raise ValueError(f'Docker.{key} must be rootless or rootful.')
    if data.get('Safety',{}).get('AllowDockerTcp'): raise ValueError('Unauthenticated Docker TCP remains unsupported.')
