from __future__ import annotations
from pathlib import Path
from typing import Any
import yaml
from .core import SETTINGS
MOUNTS={'python':[('pip','/home/vscode/.cache/pip'),('uv','/home/vscode/.cache/uv')],'javascript':[('npm','/home/node/.npm'),('pnpm','/home/node/.local/share/pnpm/store')],'typescript':[('npm','/home/node/.npm'),('pnpm','/home/node/.local/share/pnpm/store')],'java':[('maven','/home/vscode/.m2/repository'),('gradle','/home/vscode/.gradle/caches')],'kotlin':[('maven','/home/vscode/.m2/repository'),('gradle','/home/vscode/.gradle/caches')],'csharp':[('nuget','/home/vscode/.nuget/packages')],'go':[('go-mod','/go/pkg/mod'),('go-build','/home/vscode/.cache/go-build')],'rust':[('cargo-registry','/usr/local/cargo/registry'),('cargo-git','/usr/local/cargo/git')],'php':[('composer','/home/vscode/.cache/composer')],'ruby':[('bundler','/usr/local/bundle/cache')]}
def cache_override(project:Path,compose_file:Path,meta:dict[str,Any])->Path|None:
 if not SETTINGS.enable_shared_caches or meta.get('profile',SETTINGS.development_profile)=='strict':return None
 mounts=MOUNTS.get(str(meta.get('language','')).lower(),[])
 if not mounts:return None
 data=yaml.safe_load(compose_file.read_text()) or {};services=data.get('services') or {};override={'services':{}}
 for service in services:
  volumes=[]
  for name,target in mounts:
   source=SETTINGS.cache_root/name;source.mkdir(parents=True,exist_ok=True);volumes.append({'type':'bind','source':str(source),'target':target})
  override['services'][service]={'volumes':volumes}
 out=SETTINGS.runtime_root/'compose-overrides'/f'{project.name}.cache.yaml';out.parent.mkdir(parents=True,exist_ok=True);out.write_text(yaml.safe_dump(override,sort_keys=False));return out
