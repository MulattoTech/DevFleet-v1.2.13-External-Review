from __future__ import annotations
import json,os,shutil,socket,time,threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
import httpx,psutil
from .core import SETTINGS,load_peer,run
from .projects import list_projects,list_project_catalog
from .ollama import ollama_health
from .operations import list_operations
from .containers import list_containers
from .host_control import get_host_capacity,get_provider_status,host_control_status
from .version import __version__
from .node_registry import NodeRegistry
from urllib.parse import urlsplit

_RUNTIME_CACHE: tuple[float,dict[str,Any]]|None=None
_SNAPSHOT_LOCK=threading.RLock()
_SNAPSHOT_EXECUTOR=ThreadPoolExecutor(max_workers=2,thread_name_prefix='devfleet-snapshot')
_SNAPSHOTS:dict[str,dict[str,Any]]={
 'runtime':{'value':None,'updated_at':0.0,'refreshing':False,'last_duration_ms':None,'error':'','retry_after':0.0,'failures':0},
 'cluster':{'value':None,'updated_at':0.0,'refreshing':False,'last_duration_ms':None,'error':'','retry_after':0.0,'failures':0},
}
_SNAPSHOT_TTLS={'runtime':5.0,'cluster':20.0}
_PEER_BACKOFF_BASE=2.0;_PEER_BACKOFF_MAX=60.0;_PEER_FAILURE_WINDOW=300.0
_PEER_STATE={'failures':0,'last_failure':0.0,'retry_after':0.0,'circuit_until':0.0,'value':None,'inflight':False}

def _node_identity()->dict[str,Any]:
 try:
  registry=NodeRegistry().load();nodes=registry.get('nodes',[]) if isinstance(registry,dict) else []
  local=next((item for item in nodes if isinstance(item,dict) and item.get('node_name')==SETTINGS.node_name),None)
  return {'deployment_id':registry.get('deployment_id',''),'node_id':(local or {}).get('node_id',''),'node_role':(local or {}).get('node_role',SETTINGS.node_role),'coordinator_node_id':(local or {}).get('coordinator_node_id')}
 except (OSError,ValueError,TypeError):
  return {'deployment_id':'','node_id':'','node_role':SETTINGS.node_role,'coordinator_node_id':None}

_BACKUP_STATUS_PATH=Path('/var/lib/devfleet/backup-status/latest.json')
_BACKUP_CONFIG_PATH=Path('/var/lib/devfleet/backup-status/config.json')

def _backup_snapshot()->dict[str,Any]:
 try:
  data=json.loads(_BACKUP_STATUS_PATH.read_text(encoding='utf-8'))
  return data if isinstance(data,dict) else {}
 except (OSError,json.JSONDecodeError): return {}

def _cheap_runtime()->dict[str,Any]:
 hour=time.localtime().tm_hour;greeting='Good morning' if hour < 12 else 'Good afternoon' if hour < 18 else 'Good evening'
 return {'node':SETTINGS.node_name,'friendly_name':SETTINGS.friendly_name,'role':SETTINGS.node_role,'version':__version__,'greeting':f'{greeting}, developer','profile':SETTINGS.development_profile,'docker':{},'containers':[],'backup':backup_status(),'ollama':{'status':'not-yet-refreshed'},'system':{},'vault':{'status':'not-yet-refreshed'},'host_agent':{'status':'not-yet-refreshed'},'host_capacity':{'status':'not-yet-refreshed'},'vm_provider':{'status':'not-yet-refreshed'}}

def _refresh_snapshot(name:str)->None:
 with _SNAPSHOT_LOCK:
  state=_SNAPSHOTS[name]
  state['refreshing']=True
 started=time.monotonic()
 try:
  value=runtime_status() if name=='runtime' else cluster_status()
  error=''
 except Exception as exc:
  value=None;error=str(exc)[-500:]
 with _SNAPSHOT_LOCK:
   state=_SNAPSHOTS[name];state['refreshing']=False;state['last_duration_ms']=round((time.monotonic()-started)*1000,2);state['error']=error;now=time.monotonic()
   if value is not None:state['value']=value;state['updated_at']=now;state['retry_after']=0.0;state['failures']=0
   else:
    state['failures']=min(int(state.get('failures',0))+1,8);delay=min(60.0,2.0*(2**(state['failures']-1)));state['retry_after']=now+delay;state['updated_at']=now

def _schedule_snapshot(name:str)->None:
 with _SNAPSHOT_LOCK:
  if _SNAPSHOTS[name]['refreshing']:return
  # Reserve the refresh before submitting: concurrent readers can never queue
  # duplicate work between the check and executor.submit().
  _SNAPSHOTS[name]['refreshing']=True
 try:
  _SNAPSHOT_EXECUTOR.submit(_refresh_snapshot,name)
 except Exception:
  with _SNAPSHOT_LOCK:_SNAPSHOTS[name]['refreshing']=False

def _snapshot(name:str)->dict[str,Any]:
 now=time.monotonic()
 with _SNAPSHOT_LOCK:
  state=dict(_SNAPSHOTS[name]);value=state.get('value') or (_cheap_runtime() if name=='runtime' else {'updated_at':'','nodes':[],'containers':[]})
  age=(now-state['updated_at']) if state['updated_at'] else None
  stale=age is None or age>_SNAPSHOT_TTLS[name]
  refreshing=bool(state['refreshing']);retry_after=float(state.get('retry_after',0.0) or 0.0)
  if stale and now>=retry_after:_schedule_snapshot(name)
 result=dict(value);result['snapshot']={'last_updated':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(time.time()-age)) if age is not None else None,'age_seconds':round(age,3) if age is not None else None,'stale':stale,'refreshing':refreshing,'last_duration_ms':state.get('last_duration_ms'),'error':state.get('error','')}
 return result

def runtime_snapshot()->dict[str,Any]:return _snapshot('runtime')
def cluster_snapshot()->dict[str,Any]:return _snapshot('cluster')
def docker_status()->dict[str,Any]:
 try:r=run(['docker','info','--format','{{json .}}'],check=False,timeout=3)
 except Exception as exc:return {'ok':False,'mode':SETTINGS.docker_mode,'error':f'Docker status probe timed out: {exc}'}
 if r.returncode:return {'ok':False,'mode':SETTINGS.docker_mode,'error':r.stderr[-500:]}
 try:
  d=json.loads(r.stdout);return {'ok':True,'mode':SETTINGS.docker_mode,'rootless':any('rootless' in str(x) for x in d.get('SecurityOptions') or []),'containers':d.get('Containers'),'images':d.get('Images'),'driver':d.get('Driver'),'docker_root_dir':d.get('DockerRootDir')}
 except Exception as exc:return {'ok':False,'mode':SETTINGS.docker_mode,'error':str(exc)}

def system_status()->dict[str,Any]:
 disk=shutil.disk_usage(SETTINGS.workspaces)
 return {'cpu_percent':psutil.cpu_percent(interval=.05),'memory_percent':psutil.virtual_memory().percent,'disk_free_gb':round(disk.free/1024**3,1),'load':list(os.getloadavg()) if hasattr(os,'getloadavg') else []}

def vault_status()->dict[str,Any]:
 """Probe the append-only vault listener without requiring Docker or exposing credentials."""
 config_path=_BACKUP_CONFIG_PATH
 if not config_path.is_file():return {'configured':False,'status':'not-configured'}
 repository=''
 try: repository=str((json.loads(config_path.read_text(encoding='utf-8')) or {}).get('repository') or '')
 except (OSError,json.JSONDecodeError): return {'configured':True,'reachable':False,'status':'invalid-status-record'}
 if repository.startswith('rest:'):repository=repository[5:]
 parsed=urlsplit(repository)
 if parsed.scheme not in {'http','https'} or not parsed.hostname or not parsed.port:
  return {'configured':True,'reachable':False,'status':'invalid-repository-url'}
 started=time.monotonic()
 try:
  with socket.create_connection((parsed.hostname,parsed.port),timeout=1.5):pass
  return {'configured':True,'reachable':True,'status':'reachable','host':parsed.hostname,'port':parsed.port,'probe_ms':round((time.monotonic()-started)*1000)}
 except OSError as exc:
  return {'configured':True,'reachable':False,'status':'unreachable','host':parsed.hostname,'port':parsed.port,'error':str(exc)[-500:]}

def runtime_status()->dict[str,Any]:
 global _RUNTIME_CACHE
 now=time.monotonic()
 if _RUNTIME_CACHE and now-_RUNTIME_CACHE[0] < 2.0:return _RUNTIME_CACHE[1]
 docker=docker_status()
 try:containers=list_containers()
 except Exception as exc:containers=[];docker={**docker,'container_probe_error':str(exc)[-500:]}
 agent=host_control_status()
 capacity={'configured':False,'status':'not-configured'}
 provider={'configured':False,'status':'not-configured'}
 if agent.get('configured'):
  if agent.get('reachable'):
   try:capacity={'configured':True,'status':'ok',**get_host_capacity()}
   except Exception as exc:capacity={'configured':True,'status':'unavailable','error':str(exc)[-500:]}
   try:provider={'configured':True,'status':'ok',**get_provider_status()}
   except Exception as exc:provider={'configured':True,'status':'unavailable','error':str(exc)[-500:]}
  else:
   capacity={'configured':True,'status':'unreachable','error':agent.get('error','Host agent is unreachable.')}
   provider={'configured':True,'status':'unreachable','error':agent.get('error','Host agent is unreachable.')}
 raw_capacity=capacity.get('capacity',capacity) if isinstance(capacity,dict) else {}
 normalized_capacity={**raw_capacity,'configured':capacity.get('configured',False),'status':capacity.get('status',raw_capacity.get('health','unavailable')),'available':bool(capacity.get('ok',False) and raw_capacity),'reason':capacity.get('error','') or ('' if raw_capacity else 'Host capacity has not been checked.')}
 hour=time.localtime().tm_hour;greeting='Good morning' if hour < 12 else 'Good afternoon' if hour < 18 else 'Good evening'
 value={'node':SETTINGS.node_name,'friendly_name':SETTINGS.friendly_name,'role':SETTINGS.node_role,'node_identity':_node_identity(),'version':__version__,'greeting':f'{greeting}, developer','profile':SETTINGS.development_profile,'docker':docker,'containers':containers,'backup':backup_status(),'ollama':ollama_health(),'system':system_status(),'vault':vault_status(),'host_agent':agent,'host_capacity':normalized_capacity,'vm_provider':provider}
 _RUNTIME_CACHE=(now,value)
 return value
def backup_status()->dict[str,Any]:
 snapshot=_backup_snapshot()
 if not snapshot:return {'configured':_BACKUP_CONFIG_PATH.exists(),'status':'not-yet-refreshed'}
 # Restic may wait on repository/network state for many seconds. Do not make
 # every dashboard render wait on that probe; the backup action/diagnostics
 # remain responsible for authoritative backup verification.
 return {'configured':True,**snapshot}
def local_status(*,live:bool=False)->dict[str,Any]:
 runtime=runtime_status() if live else runtime_snapshot()
 return {**runtime,'projects':list_projects() if live else list_project_catalog(),'operations':list_operations(20)}

def peer_node_status()->dict[str,Any]:
 peer=load_peer()
 if not peer.get('Url') or not peer.get('Token'):return {'configured':False,'status':'not-configured'}
 now=time.monotonic()
 with _SNAPSHOT_LOCK:
   if _PEER_STATE.get('last_failure') and now-_PEER_STATE['last_failure']>_PEER_FAILURE_WINDOW:_PEER_STATE.update({'failures':0,'retry_after':0.0,'circuit_until':0.0})
   if now < _PEER_STATE['retry_after']:
    cached=_PEER_STATE.get('value');return cached if isinstance(cached,dict) else {'configured':True,'ok':False,'status':'backoff','retry_after':round(_PEER_STATE['retry_after']-now,2)}
   if now < _PEER_STATE['circuit_until']:
    cached=_PEER_STATE.get('value');return cached if isinstance(cached,dict) else {'configured':True,'ok':False,'status':'circuit-open'}
   if _PEER_STATE.get('inflight'):
    cached=_PEER_STATE.get('value');return cached if isinstance(cached,dict) else {'configured':True,'ok':False,'status':'refreshing'}
   _PEER_STATE['inflight']=True
 try:
  base=peer['Url'].rstrip('/');headers={'X-DevFleet-Token':peer['Token']};started=time.monotonic()
  r=httpx.get(base+'/api/node/status',headers=headers,timeout=2.5)
  if r.status_code==404:
   # v1.1 peers expose /api/status, which includes project and container
   # inventory and is slower than the lightweight node endpoint. Do not
   # classify a healthy peer as offline merely because this fallback needs
   # a few seconds to assemble its inventory.
   legacy=httpx.get(base+'/api/status',headers=headers,timeout=4.5);legacy.raise_for_status();data=legacy.json();data.setdefault('containers',[]);data['compatibility']='legacy';data['probe_ms']=round((time.monotonic()-started)*1000)
  else:
   r.raise_for_status();data=r.json();data['probe_ms']=round((time.monotonic()-started)*1000)
  result={'configured':True,'ok':True,'node':data}
  with _SNAPSHOT_LOCK:_PEER_STATE.update({'failures':0,'last_failure':0.0,'retry_after':0.0,'circuit_until':0.0,'value':result,'inflight':False})
  return result
 except Exception as exc:
  with _SNAPSHOT_LOCK:
   failures=_PEER_STATE['failures']+1;_PEER_STATE['failures']=failures;_PEER_STATE['last_failure']=now
   delay=min(_PEER_BACKOFF_MAX,_PEER_BACKOFF_BASE*(2**min(failures-1,5)));_PEER_STATE['retry_after']=time.monotonic()+delay
   if failures>=3:_PEER_STATE['circuit_until']=time.monotonic()+min(_PEER_BACKOFF_MAX,delay*2)
   _PEER_STATE['inflight']=False
  return {'configured':True,'ok':False,'status':'unreachable','error':str(exc)[-500:],'retry_after':round(delay,2)}

def cluster_status()->dict[str,Any]:
 local=runtime_status();peer=peer_node_status();nodes=[{**local,'id':local['node'],'status':'online','reachable':True,'destination_selectable':True}]
 if peer.get('ok'):
  remote=peer.get('node') or {};nodes.append({**remote,'id':remote.get('node','devfleet-failover'),'status':'online','reachable':True,'destination_selectable':True})
 else:
  nodes.append({'id':'devfleet-failover','node':'devfleet-failover','friendly_name':'DevFleetFailover','role':'failover','status':'offline','reachable':False,'destination_selectable':False,'error':peer.get('error') or peer.get('status','unavailable'),'containers':[],'docker':{'ok':False},'system':{}})
 vault=vault_status();nodes.append({'id':'devfleet-vault','node':'devfleet-vault','friendly_name':'DevFleetVault','role':'vault','status':'online' if vault.get('reachable') else 'offline','reachable':bool(vault.get('reachable')),'vault':vault,'containers':[],'docker':{'ok':False,'mode':'not-applicable'},'system':{}})
 containers=[]
 for node in nodes:
  for item in node.get('containers') or []:
   containers.append({**item,'node_id':node['id'],'node_name':node.get('friendly_name') or node['id'],'control_scope':'peer' if node['id']=='devfleet-failover' else 'local'})
 return {'updated_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'nodes':nodes,'containers':containers}
def peer_status()->dict[str,Any]:
 peer=load_peer()
 if not peer.get('Url') or not peer.get('Token'):return {'configured':False}
 try:
  r=httpx.get(peer['Url'].rstrip('/')+'/api/status',headers={'X-DevFleet-Token':peer['Token']},timeout=4.5);r.raise_for_status();return {'configured':True,'ok':True,'peer':r.json()}
 except Exception as exc:return {'configured':True,'ok':False,'error':str(exc)}
