"""Focused v1.2.7 project UX, readiness, and host-helper contracts."""

import re
from dataclasses import replace
from pathlib import Path

from devfleet import main
from devfleet.projects import workspace_readiness


def _no_redirect(client, method, url, **kwargs):
    try:
        return getattr(client, method)(url, follow_redirects=False, **kwargs)
    except TypeError:
        return getattr(client, method)(url, allow_redirects=False, **kwargs)


def _signed_in():
    from fastapi.testclient import TestClient

    client = TestClient(main.app)
    login = client.get('/login')
    login_csrf = re.search(r'name="csrf_token" value="([^"]+)"', login.text).group(1)
    assert _no_redirect(client, 'post', '/login', data={
        'username': 'test', 'password': 'test-password', 'next': '/', 'csrf_token': login_csrf,
    }).status_code == 303
    index = client.get('/')
    return client, re.search(r'name="csrf_token" value="([^"]+)"', index.text).group(1)


def test_vm_readiness_requires_running_and_all_connection_proofs():
    meta = {
        'slug': 'demo', 'runtime_isolation': 'vm', 'runtime_provider': 'multipass-host-agent',
        'lifecycle_status': 'stopped', 'runtime_address': '172.30.9.35', 'ssh_alias': 'devfleet-project-demo',
        'ssh_host_key_pinned': True, 'ssh_authenticated': True, 'ssh_validation_passed': True,
        'workspace_provisioned': True,
    }
    stopped = workspace_readiness('demo', meta)
    assert stopped['ready'] is False and 'stopped' in stopped['reason']
    meta['lifecycle_status'] = 'running'
    running = workspace_readiness('demo', meta)
    assert running['ready'] is True and running['status'] == 'ready'
    meta['ssh_authenticated'] = False
    assert workspace_readiness('demo', meta)['ready'] is False


def test_project_action_requires_exact_origin_port_and_uses_lifecycle_idempotency(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'SETTINGS', replace(main.SETTINGS, workspaces=tmp_path))
    (tmp_path / 'demo').mkdir()
    client, csrf = _signed_in()
    calls = []
    monkeypatch.setattr(main, 'submit_operation', lambda *args, **kwargs: calls.append(kwargs) or 'start-test-op')
    response = _no_redirect(client, 'post', '/projects/demo/start', headers={
        'Host': 'testserver:8787', 'Origin': 'http://testserver:80', 'Sec-Fetch-Site': 'same-origin',
    }, data={'csrf_token': csrf})
    assert response.status_code == 403
    response = _no_redirect(client, 'post', '/projects/demo/start', headers={
        'Host': 'testserver:8787', 'Origin': 'http://testserver:8787', 'Accept': 'application/json',
    }, data={'csrf_token': csrf})
    assert response.status_code == 202
    assert calls[-1]['idempotency_key'] == 'project-action:demo:start'


def test_migrated_vm_host_identity_is_local_without_disabling_failover_guard(tmp_path, monkeypatch):
    project = tmp_path / 'demo'
    (project / '.devfleet').mkdir(parents=True)
    (project / '.devfleet' / 'project.json').write_text('{}', encoding='utf-8')
    monkeypatch.setattr(main, 'SETTINGS', replace(
        main.SETTINGS, workspaces=tmp_path, node_name='devfleet-primary',
        expected_host_name='MULATTOTECHBOX',
    ))
    monkeypatch.setattr(main, 'safe_child', lambda _root, _slug: project)
    monkeypatch.setattr(main, 'project_identity', lambda _slug: 'demo')
    monkeypatch.setattr(main, 'load_meta', lambda _project: {
        'host_id': 'MULATTOTECHBOX', 'runtime_provider': 'multipass-host-agent',
    })
    monkeypatch.setattr(main, 'peer_status', lambda: (_ for _ in ()).throw(
        AssertionError('local migrated VM must not require peer reachability'),
    ))
    main.require_safe_start('demo', False)


def test_spa_action_delegation_and_resource_contracts():
    root = Path(__file__).resolve().parents[1]
    js = (root / 'app/static/app.js').read_text(encoding='utf-8')
    html = (root / 'app/templates/index.html').read_text(encoding='utf-8')
    assert 'window.__devfleetProjectActionsBound' in js
    assert 'event.preventDefault();' in js and "'Idempotency-Key'" in js
    assert 'initializeView();' in js and 'nodeFilter?.addEventListener' in js
    assert 'resource_allocation(p)' in html and 'Not applicable — VM isolation' in html
    assert 'Workspace readiness has not been verified' in html


def test_vscode_helper_is_scoped_atomic_and_malformed_safe():
    root = Path(__file__).resolve().parents[1]
    helper = (root / 'windows/DevFleet-VSCode.ps1').read_text(encoding='utf-8')
    agent = (root / 'windows/DevFleet-HostAgent.ps1').read_text(encoding='utf-8')
    installer = (root / 'windows/Install-DevFleet-HostAgent.ps1').read_text(encoding='utf-8')
    assert 'remote.SSH.remotePlatform' in helper
    assert 'Copy($Path, $backup, $false)' in helper
    assert 'Move-Item -LiteralPath $tmp -Destination $Path -Force' in helper
    assert 'ConvertFrom-DevFleetJsonc' in helper and 'malformed user settings' in helper.lower() and 'replacement is written' in helper.lower()
    assert 'Sync-DevFleetVsCodeRemotePlatform' in agent and 'VsCodeSettingsPaths' in installer
    assert '[switch]$SkipFirewall' in installer and 'if (-not $SkipFirewall)' in installer
