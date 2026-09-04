from devfleet.failover import guided_transfer
class C:
 def __init__(self):self.events=[]
 def update(self,p,m):self.events.append((p,m))
def test_guided_transfer_order():
 events=[];c=C();peer=lambda m,p,b:events.append(('peer',p,b)) or {'ok':True};guided_transfer('demo',c,stop=lambda s:events.append(('stop',s)),backup=lambda s:events.append(('backup',s)),peer_call=peer);assert events[0][0]=='stop' and events[1][0]=='backup' and 'restore-vault' in events[2][1] and events[3][1].endswith('/start')
def test_interrupted_transfer_does_not_start():
 events=[];c=C()
 def peer(m,p,b):events.append(p);raise RuntimeError('lost peer')
 try:guided_transfer('demo',c,stop=lambda s:None,backup=lambda s:None,peer_call=peer)
 except RuntimeError:pass
 assert not any(x.endswith('/start') for x in events)
