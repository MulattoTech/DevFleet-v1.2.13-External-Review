from __future__ import annotations
import json,time
from pathlib import Path
from typing import Any
from .core import SETTINGS
def codexpro_status(project:Path)->dict[str,Any]:
 runtime=project/'.ai-bridge/local-agent';status=project/'.devfleet/runtime/codexpro-status.json';log=project/'.devfleet/runtime/codexpro-bootstrap.log';handoff=project/'.ai-bridge/current-plan.md'
 data={'healthy':False,'state':'not-bootstrapped','workspace':str(project),'runtime_log':str(log),'model_endpoint':SETTINGS.ollama_base_url,'handoff_age_seconds':None}
 try:data.update(json.loads(status.read_text()))
 except Exception:pass
 if handoff.exists():data['handoff_age_seconds']=max(0,int(time.time()-handoff.stat().st_mtime))
 data['runtime_directory']=str(runtime);return data
def bootstrap_command(project:Path)->list[str]:return [str(project/'.devfleet/codexpro-bootstrap.sh')]
