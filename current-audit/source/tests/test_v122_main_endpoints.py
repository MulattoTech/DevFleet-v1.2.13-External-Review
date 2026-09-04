"""Focused v1.2.2 backend UI endpoint contracts."""

import re
from dataclasses import replace

import pytest

try:
    from fastapi.testclient import TestClient
    from devfleet import main
except Exception as exc:  # pragma: no cover - dependency-version specific
    pytest.skip(f'FastAPI application tests unavailable in this environment: {exc}', allow_module_level=True)


def _no_redirect(client, method, url, **kwargs):
    try:
        return getattr(client, method)(url, follow_redirects=False, **kwargs)
    except TypeError:
        return getattr(client, method)(url, allow_redirects=False, **kwargs)


def _signed_in():
    client = TestClient(main.app)
    login = client.get('/login')
    login_csrf = re.search(r'name="csrf_token" value="([^"]+)"', login.text).group(1)
    response = _no_redirect(client, 'post', '/login', data={
        'username': 'test', 'password': 'test-password', 'next': '/',
        'csrf_token': login_csrf,
    })
    assert response.status_code == 303
    index = client.get('/')
    session_csrf = re.search(r'name="csrf_token" value="([^"]+)"', index.text).group(1)
    return client, session_csrf


def test_ui_logs_are_session_authenticated_bounded_and_provider_aware(tmp_path, monkeypatch):
    client, _csrf = _signed_in()
    project = tmp_path / 'demo'
    project.mkdir()
    monkeypatch.setattr(main, 'SETTINGS', replace(main.SETTINGS, workspaces=tmp_path))
    monkeypatch.setattr(main, 'load_meta', lambda _project: {'runtime_provider': 'multipass-host-agent', 'runtime_isolation': 'vm', 'lifecycle_status': 'running', 'runtime_address': '172.30.1.20'})
    monkeypatch.setattr(main, 'project_logs', lambda slug, tail: f'{slug}:{tail}')

    assert client.get('/ui/projects/demo/logs?tail=9999').json() == {
        'ok': True, 'slug': 'demo', 'tail': 500,
        'provider': 'multipass-host-agent', 'logs': 'demo:500',
    }
    assert _no_redirect(TestClient(main.app), 'get', '/ui/projects/demo/logs').status_code == 303
    assert client.get('/api/projects/demo/logs?tail=9999').status_code == 401


def test_operation_ui_and_api_unknown_ids_are_intentional_404s():
    client, _csrf = _signed_in()
    assert client.get('/ui/operations/not-real').status_code == 404
    assert client.get('/operations/not-real').status_code == 404
    assert client.get('/api/operations/not-real').status_code == 401
    assert client.get('/api/operations/not-real', headers={'X-DevFleet-Token': 'test-token'}).status_code == 404


def test_project_action_returns_json_202_or_legacy_redirect_and_requires_csrf(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'SETTINGS', replace(main.SETTINGS, workspaces=tmp_path))
    (tmp_path / 'demo').mkdir()
    client, csrf = _signed_in()
    monkeypatch.setattr(main, 'submit_operation', lambda *args, **kwargs: 'start-test-op')

    missing_csrf = _no_redirect(client, 'post', '/projects/demo/start', headers={'Accept': 'application/json'}, data={})
    assert missing_csrf.status_code == 403

    json_response = _no_redirect(client, 'post', '/projects/demo/start', headers={'Accept': 'application/json', 'Sec-Fetch-Site': 'same-origin'}, data={'csrf_token': csrf})
    assert json_response.status_code == 202
    assert json_response.json() == {'ok': True, 'operation_id': 'start-test-op'}

    ui_response = _no_redirect(client, 'post', '/projects/demo/start', headers={'X-DevFleet-UI': '1', 'Sec-Fetch-Site': 'same-origin'}, data={'csrf_token': csrf})
    assert ui_response.status_code == 202
    redirect_response = _no_redirect(client, 'post', '/projects/demo/start', headers={'Sec-Fetch-Site': 'same-origin'}, data={'csrf_token': csrf})
    assert redirect_response.status_code == 303
    assert redirect_response.headers['location'] == '/?operation=start-test-op'


def test_project_action_safety_checks_are_synchronous_and_action_set_is_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'SETTINGS', replace(main.SETTINGS, workspaces=tmp_path))
    (tmp_path / 'demo').mkdir()
    client, csrf = _signed_in()
    headers = {'Sec-Fetch-Site': 'same-origin'}
    assert _no_redirect(client, 'post', '/projects/demo/quarantine', headers=headers, data={'csrf_token': csrf}).status_code == 400
    assert _no_redirect(client, 'post', '/projects/demo/destroy', headers=headers, data={'csrf_token': csrf}).status_code == 400
    assert _no_redirect(client, 'post', '/projects/demo/not-an-action', headers=headers, data={'csrf_token': csrf}).status_code == 404
    assert 'logs' in main.PROJECT_ACTIONS
    assert {'start', 'stop', 'restart', 'inspect', 'runtime-health', 'rebuild', 'backup', 'bootstrap', 'health', 'test', 'codexpro', 'quarantine', 'destroy', 'restore-vault', 'analyze-force'} <= main.PROJECT_ACTIONS
