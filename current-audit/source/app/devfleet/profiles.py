from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class DevelopmentProfile:
    name:str; block_hardening:bool; allow_tailnet:bool; allow_devices:bool; allow_privileged:bool; shared_caches:bool

PROFILES={
 'strict':DevelopmentProfile('strict',True,False,False,False,False),
 'balanced':DevelopmentProfile('balanced',False,True,False,False,True),
 'fast':DevelopmentProfile('fast',False,True,True,True,True),
}
def get_profile(name:str)->DevelopmentProfile:
    key=(name or 'strict').lower()
    if key not in PROFILES: raise ValueError(f'Unknown development profile: {key}')
    return PROFILES[key]
