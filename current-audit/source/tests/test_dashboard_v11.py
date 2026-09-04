from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def test_long_operations_auto_refresh_and_show_log_timestamps():
 text=(ROOT/'app/templates/index.html').read_text(encoding='utf-8')
 assert 'http-equiv="refresh"' not in text
 assert 'operation-banner' in text
 assert 'operation.updated_at' in text and 'operation.log' in text

def test_sensitive_actions_have_explicit_acknowledgements():
 text=(ROOT/'app/templates/index.html').read_text(encoding='utf-8')
 for name in ('confirm_slug','confirm_phrase','DANGER ZONE','Move to another node'):
  assert name in text

def test_dashboard_exposes_requested_quick_commands_and_cache_status():
 text=(ROOT/'app/templates/index.html').read_text(encoding='utf-8')
 assert 'workspace_target(p)' in text and 'data-provider' in text
 assert 'Advanced details' in text and 'Last backup' in text

def test_v1_dashboard_repair_and_peer_control_are_preserved():
 main=(ROOT/'app/devfleet/main.py').read_text()
 html=(ROOT/'app/templates/index.html').read_text(encoding='utf-8')
 assert any(marker in main for marker in ("@app.post('/repair')", '@app.post("/repair")')) and any(marker in main for marker in ("@app.post('/peer/projects/{slug}/{action}')", '@app.post("/peer/projects/{slug}/{action}")'))
 assert 'Run non-destructive repair' in html and 'Move to another node' in html

def test_cluster_monitor_has_all_refresh_choices_and_manual_refresh():
 text=(ROOT/'app/templates/index.html').read_text(encoding='utf-8')
 js=(ROOT/'app/static/app.js').read_text()
 for value in ('value="0"','value="5"','value="10"','value="15"','value="30"'):
  assert value in text
 assert 'id="refresh-cluster"' in text and "setInterval(refreshCluster" in js
 assert "fetch('/cluster/status'" in js

def test_portainer_style_container_controls_are_present_and_confirm_removal():
 main=(ROOT/'app/devfleet/main.py').read_text()
 html=(ROOT/'app/templates/index.html').read_text(encoding='utf-8')
 js=(ROOT/'app/static/app.js').read_text()
 containers=(ROOT/'app/devfleet/containers.py').read_text()
 assert any(marker in main for marker in ("@app.get('/api/containers'", '@app.get("/api/containers"')) and any(marker in main for marker in ("@app.post('/containers/{container_ref}/{action}')", '@app.post("/containers/{container_ref}/{action}")'))
 assert 'container-inspect' in js and 'container-action' in js and 'container-table' in html
 assert 'confirm_remove' in main and '"docker", "stats"' in containers

def test_cluster_status_covers_failover_and_vault():
 status=(ROOT/'app/devfleet/status.py').read_text()
 assert 'def cluster_status' in status and "devfleet-failover" in status and "devfleet-vault" in status
