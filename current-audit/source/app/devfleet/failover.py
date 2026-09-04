from __future__ import annotations
from typing import Any,Callable,Protocol
class Progress(Protocol):
 def update(self,progress:int,message:str)->None:...
def guided_transfer(slug:str,ctx:Progress,*,stop:Callable[[str],Any],backup:Callable[[str],Any],peer_call:Callable[[str,str,dict|None],Any])->str:
 ctx.update(5,'Stopping local project');stop(slug);ctx.update(20,'Creating and verifying append-only backup');backup(slug);ctx.update(45,'Restoring canonical project copy on peer');peer_call('POST',f'/api/projects/{slug}/restore-vault',{'canonical':True});ctx.update(75,'Starting project on peer and transferring ownership lease');peer_call('POST',f'/api/projects/{slug}/start',{'confirm_failover':False});return 'Ownership transferred to peer.'
