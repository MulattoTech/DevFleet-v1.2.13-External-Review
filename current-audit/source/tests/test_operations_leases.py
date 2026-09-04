import time
from pathlib import Path
from devfleet import operations
from devfleet.operations import submit_operation,get_operation
from devfleet.leases import update_lease
def test_operation_progress():
 op=submit_operation('x','demo',lambda ctx:(ctx.update(50,'half'),'ok')[1])
 for _ in range(50):
  data=get_operation(op)
  if data['state'] in {'completed','failed'}:break
  time.sleep(.02)
 assert data['state']=='completed' and data['progress']==100
def test_lease_fields(tmp_path,monkeypatch):
 p=tmp_path/'demo';(p/'.devfleet').mkdir(parents=True);(p/'.devfleet/project.json').write_text('{"identity":"demo"}');monkeypatch.setattr('devfleet.leases._git',lambda p:('abc',True));d=update_lease(p,active=True);assert d['project_identity']=='demo' and d['active'] and d['git_commit']=='abc' and d['working_tree_dirty']


def test_background_heartbeat_keeps_long_operation_owned(monkeypatch):
 monkeypatch.setattr(operations, '_LEASE_SECONDS', 0.12)
 monkeypatch.setattr(operations, '_HEARTBEAT_INTERVAL_SECONDS', 0.03)
 def slow(_ctx):
  time.sleep(0.24)
  return 'done'
 op=submit_operation('heartbeat-test','heartbeat-demo',slow)
 time.sleep(0.17)
 mid=get_operation(op)
 assert mid['state']=='running'
 assert mid.get('heartbeat_at')
 assert not operations._lease_expired(mid.get('lease_expires_at'))
 for _ in range(50):
  data=get_operation(op)
  if data['state']=='completed': break
  time.sleep(.02)
 assert data['state']=='completed'
