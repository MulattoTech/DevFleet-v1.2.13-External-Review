import ast
import threading
import time
from pathlib import Path

from devfleet import status


ROOT = Path(__file__).resolve().parents[1]


def _function(path: Path, name: str):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    return next(node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name)


def test_project_action_submission_is_route_level_not_nested_task():
    node = _function(ROOT / 'app/devfleet/main.py', 'project_action')
    nested = next(child for child in node.body if isinstance(child, ast.FunctionDef) and child.name == 'task')
    assert any(isinstance(child, ast.Return) and isinstance(child.value, ast.Call) and getattr(getattr(child.value, 'func', None), 'id', '') == 'redirect' for child in node.body)
    assert not any('submit_operation' in ast.unparse(child) for child in nested.body)


def test_version_and_ui_contract_are_v123():
    assert (ROOT / 'VERSION').read_text(encoding='utf-8').strip() == '1.2.13'
    template = (ROOT / 'app/templates/index.html').read_text(encoding='utf-8')
    script = (ROOT / 'app/static/app.js').read_text(encoding='utf-8')
    assert 'data-existing-environment-wizard' in template
    assert all(label in template for label in ('1. Environment', '2. Resources', '3. Review', '4. Confirm'))
    assert 'initProjectActions' in script and 'X-DevFleet-UI' in script
    assert "operation.state || operation.status" in script
    assert "reconciliation-required" not in script or "interrupted" in script


def test_peer_probe_is_single_flight(monkeypatch):
    status._PEER_STATE.update({'failures': 0, 'last_failure': 0.0, 'retry_after': 0.0, 'circuit_until': 0.0, 'value': None, 'inflight': False})
    monkeypatch.setattr(status, 'load_peer', lambda: {'Url': 'http://peer', 'Token': 'token'})
    calls = []
    started = threading.Event()
    release = threading.Event()

    class Response:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {'node': 'peer'}

    def probe(*args, **kwargs):
        if args[0] == 'http://peer/api/node/status':
            calls.append(args[0]); started.set(); release.wait(2)
        return Response()

    monkeypatch.setattr(status.httpx, 'get', probe)
    results = []
    workers = [threading.Thread(target=lambda: results.append(status.peer_node_status())) for _ in range(5)]
    workers[0].start(); assert started.wait(1)
    for worker in workers[1:]: worker.start()
    time.sleep(.05); release.set()
    for worker in workers: worker.join(2)
    assert calls == ['http://peer/api/node/status']
    assert any(result.get('status') == 'refreshing' for result in results)
    assert any(result.get('ok') is True for result in results)


def test_snapshot_failure_sets_retry_deadline(monkeypatch):
    state = status._SNAPSHOTS['runtime']
    state.update({'value': None, 'updated_at': 0.0, 'refreshing': False, 'retry_after': 0.0, 'failures': 0})
    monkeypatch.setattr(status, 'runtime_status', lambda: (_ for _ in ()).throw(RuntimeError('offline')))
    status._refresh_snapshot('runtime')
    assert state['error'] == 'offline'
    assert state['retry_after'] > time.monotonic()
    assert state['failures'] == 1


def test_laptop_surrogate_resource_policy_has_single_safe_default_and_floor():
    import json

    config = json.loads((ROOT / 'config' / 'devfleet.config.json').read_text(encoding='utf-8'))
    profile = config['RoleProfiles']['LaptopSurrogate']
    assert profile['Recommended'] == {'FailoverMemory': '5G', 'VaultMemory': '2G'}
    assert profile['MinimumTested'] == {'FailoverMemory': '4G', 'VaultMemory': '2G'}
    preflight = (ROOT / 'windows' / '00-Preflight.ps1').read_text(encoding='utf-8')
    assert '$config.RoleProfiles.LaptopSurrogate' in preflight
    assert '$minimumFailMem' in preflight and '$minimumVaultMem' in preflight


def test_vault_backup_script_rejects_plaintext_deferred_transport():
    script = (ROOT / 'linux' / 'devfleet-configure-backup').read_text(encoding='utf-8')
    assert "pairing_mode" in script
    assert "plaintext deferred-local transport is disabled" in script
    assert "RFC1918 private IPv4" not in script


def test_session_store_publishes_restrictive_file_and_parent_permissions():
    auth = (ROOT / 'app' / 'devfleet' / 'auth.py').read_text(encoding='utf-8')
    assert 'os.fchmod(fd, 0o600)' in auth
    assert 'parent.chmod(0o700)' in auth
    assert 'os.replace(temp_name, path)' in auth
