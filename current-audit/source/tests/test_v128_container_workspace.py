import json
from dataclasses import replace
from pathlib import Path

import devfleet.projects as projects
from devfleet.core import SETTINGS


def _project(tmp_path: Path, slug: str, metadata: dict) -> Path:
    project = tmp_path / slug
    (project / '.devfleet').mkdir(parents=True)
    (project / '.devfleet' / 'project.json').write_text(json.dumps(metadata), encoding='utf-8')
    return project


def test_container_workspace_opens_when_application_containers_are_stopped(monkeypatch, tmp_path):
    _project(tmp_path, 'container-stopped', {
        'slug': 'container-stopped',
        'runtime_isolation': 'container',
        'runtime_type': 'container',
        'runtime_provider': 'docker-compose',
        'lifecycle_status': 'stopped',
        'runtime_status': 'stopped',
        'workspace_host': 'devfleet-primary',
        'ssh_alias': 'devfleet-primary',
        'workspace_path': '/home/devrunner/workspaces/container-stopped',
        'workspace_provisioned': True,
        'workspace_accessible': True,
    })
    monkeypatch.setattr(projects, 'SETTINGS', replace(SETTINGS, workspaces=tmp_path, node_name='devfleet-primary'))
    monkeypatch.setattr(projects, 'running', lambda *_: False)

    result = projects.open_workspace('container-stopped')

    assert result['ok'] is True
    assert result['readiness']['ready'] is True
    assert result['readiness']['application_running'] is False
    assert result['ssh_alias'] == 'devfleet-primary'
    assert 'ssh-remote+devfleet-primary' in result['launcher_uri']


def test_container_workspace_blocks_when_primary_workspace_is_unavailable(monkeypatch, tmp_path):
    _project(tmp_path, 'container-unavailable', {
        'slug': 'container-unavailable',
        'runtime_isolation': 'container',
        'runtime_type': 'container',
        'lifecycle_status': 'stopped',
        'workspace_accessible': False,
    })
    monkeypatch.setattr(projects, 'SETTINGS', replace(SETTINGS, workspaces=tmp_path, node_name='devfleet-primary'))

    result = projects.open_workspace('container-unavailable')

    assert result['ok'] is False
    assert 'not accessible' in result['error']


def test_starting_dedicated_vm_cannot_open(monkeypatch, tmp_path):
    _project(tmp_path, 'vm-starting', {
        'slug': 'vm-starting',
        'runtime_isolation': 'vm',
        'runtime_type': 'vm',
        'runtime_provider': 'multipass-host-agent',
        'lifecycle_status': 'starting',
        'runtime_id': 'devfleet-project-vm-starting',
        'ssh_alias': 'devfleet-project-vm-starting',
    })
    monkeypatch.setattr(projects, 'SETTINGS', replace(SETTINGS, workspaces=tmp_path))
    monkeypatch.setattr(projects.VmRuntimeOperations, 'inspect', staticmethod(lambda *_: {'info': {'state': 'Starting'}}))
    monkeypatch.setattr(projects.VmRuntimeOperations, 'refresh', staticmethod(lambda *_: (_ for _ in ()).throw(AssertionError('refresh must wait for running state'))))

    result = projects.open_workspace('vm-starting')

    assert result['ok'] is False
    assert result['state'] == 'starting'
    assert 'starting' in result['error'].lower()


def test_running_ssh_ready_dedicated_vm_opens(monkeypatch, tmp_path):
    _project(tmp_path, 'vm-ready', {
        'slug': 'vm-ready',
        'runtime_isolation': 'vm',
        'runtime_type': 'vm',
        'runtime_provider': 'multipass-host-agent',
        'lifecycle_status': 'running',
        'runtime_id': 'devfleet-project-vm-ready',
        'runtime_address': '172.30.9.35',
        'ssh_alias': 'devfleet-project-vm-ready',
        'ssh_host_key_pinned': True,
        'ssh_authenticated': True,
        'ssh_validation_passed': True,
        'workspace_provisioned': True,
    })
    monkeypatch.setattr(projects, 'SETTINGS', replace(SETTINGS, workspaces=tmp_path))
    monkeypatch.setattr(projects.VmRuntimeOperations, 'inspect', staticmethod(lambda *_: {'info': {'state': 'Running'}}))
    monkeypatch.setattr(projects, 'running', lambda *_: True)

    result = projects.open_workspace('vm-ready')

    assert result['ok'] is True
    assert result['readiness']['ready'] is True
    assert result['ssh_alias'] == 'devfleet-project-vm-ready'
