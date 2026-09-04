from __future__ import annotations
from pathlib import Path
from typing import Any
from .core import SETTINGS,atomic_json,now_iso,run
def lease_path(project:Path)->Path:return project/'.devfleet'/'ownership-lease.json'
def load_lease(project:Path)->dict[str,Any]:
 try:return __import__('json').loads(lease_path(project).read_text())
 except Exception:return {}
def _git(project:Path)->tuple[str,bool]:
 commit=run(['git','rev-parse','HEAD'],cwd=project,check=False,timeout=15).stdout.strip();dirty=bool(run(['git','status','--porcelain'],cwd=project,check=False,timeout=15).stdout.strip());return commit,dirty
def update_lease(project:Path,*,active:bool|None=None,clean_shutdown:bool|None=None,backup_time:str|None=None)->dict[str,Any]:
 data=load_lease(project);meta={}
 try:meta=__import__('json').loads((project/'.devfleet/project.json').read_text())
 except Exception:pass
 commit,dirty=_git(project);now=now_iso();data.update({'project_identity':meta.get('identity',project.name),'active_node':SETTINGS.node_name if active else data.get('active_node'),'heartbeat_time':now,'git_commit':commit,'working_tree_dirty':dirty})
 if active is not None:
  data['active']=active
  if active:data['start_time']=now;data['last_clean_shutdown']=None
 if clean_shutdown is not None:data['last_clean_shutdown']=now if clean_shutdown else None
 if backup_time:data['last_backup']=backup_time
 atomic_json(lease_path(project),data);return data
def heartbeat_lease(project:Path)->dict[str,Any]:return update_lease(project)
