from __future__ import annotations
from typing import Any
import httpx
from .core import SETTINGS
def ollama_health(*,queue_probe:bool=False)->dict[str,Any]:
 if not SETTINGS.ollama_base_url:return {'configured':False}
 base=SETTINGS.ollama_base_url.rstrip('/')
 try:
  r=httpx.get(base+'/models',timeout=1.5);r.raise_for_status();models=r.json().get('data',[]);names=[str(x.get('id','')) for x in models]
  out={'configured':True,'ok':True,'endpoint':base,'model':SETTINGS.ollama_model,'model_available':SETTINGS.ollama_model in names,'models':names[:20],'profile':SETTINGS.ollama_profile}
  if queue_probe:
   p=httpx.post(base+'/chat/completions',json={'model':SETTINGS.ollama_model,'messages':[{'role':'user','content':'Reply OK'}],'max_tokens':4},timeout=60);out['queue_response']=p.status_code
  return out
 except Exception as exc:return {'configured':True,'ok':False,'endpoint':base,'error':str(exc),'profile':SETTINGS.ollama_profile}
