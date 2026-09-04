import json
from pathlib import Path

import pytest

from devfleet.resource_profiles import custom_resource_metadata, write_resource_override
from devfleet.workspace_archives import create_workspace_archive, inspect_workspace


ROOT = Path(__file__).resolve().parents[1]


def test_custom_limits_are_bounded_and_host_pid_is_rejected():
    limits = custom_resource_metadata({'cpus': 3, 'memory_gb': 6, 'disk_gb': 60, 'pids': 2048})
    assert limits['cpus'] == 3.0 and limits['memory_gb'] == 6.0 and limits['pids'] == 2048
    with pytest.raises(ValueError, match='Host PID namespace'):
        custom_resource_metadata({'cpus': 2, 'memory_gb': 4, 'disk_gb': 40, 'pids': 512, 'pid_mode': 'host'})


def test_compose_override_uses_custom_limits(tmp_path: Path):
    project = tmp_path / 'demo'
    (project / '.devfleet').mkdir(parents=True)
    compose = project / 'compose.yaml'
    compose.write_text('services:\n  app:\n    image: alpine\n', encoding='utf-8')
    override = write_resource_override(project, compose, {'cpus': 2, 'memory_gb': 4, 'disk_gb': 40, 'pids': 512})
    assert override is not None
    assert 'cpus: 2.0' in override.read_text(encoding='utf-8')
    assert 'mem_limit: 4g' in override.read_text(encoding='utf-8')


def test_archive_reports_exclusions_and_estimate(tmp_path: Path):
    workspace = tmp_path / 'demo'
    (workspace / '.devfleet').mkdir(parents=True)
    (workspace / '.devfleet' / 'project.json').write_text('{"project_id":"p"}\n', encoding='utf-8')
    (workspace / 'src').mkdir()
    (workspace / 'src' / 'main.py').write_text('print(1)\n', encoding='utf-8')
    (workspace / 'node_modules').mkdir()
    (workspace / 'node_modules' / 'generated.bin').write_bytes(b'x' * 10)
    inspected = inspect_workspace(workspace)
    assert inspected['generated_dirs'] == ['node_modules']
    assert inspected['generated_bytes'] == 10
    assert inspected['estimated_archive_bytes'] >= inspected['bytes']
    result = create_workspace_archive(workspace, 'demo', tmp_path / 'demo.tar.gz')
    assert result['verified'] is True
    assert result['generated_details'][0]['path'] == 'node_modules'


def test_host_agent_command_contract_is_explicit():
    text = (ROOT / 'windows' / 'DevFleet-HostAgent.ps1').read_text(encoding='utf-8')
    assert "docker compose build && docker compose up -d" in text
    assert "^\\./\\.devfleet/(bootstrap|health-check|smoke-test|codexpro-bootstrap)\\.sh$" in text
    assert "docker\\s+(run|exec)" in text
    assert 'docker compose version' in text


def test_every_template_contains_lifecycle_commands():
    required = {'start_command', 'stop_command', 'restart_command', 'rebuild_command', 'logs_command', 'codexpro_command'}
    files = list((ROOT / 'templates').glob('*/.devfleet/template.json'))
    assert len(files) == 20
    for path in files:
        data = json.loads(path.read_text(encoding='utf-8'))
        assert required <= data.keys(), path
