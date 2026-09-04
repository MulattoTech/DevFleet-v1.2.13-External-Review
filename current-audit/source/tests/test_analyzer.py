from pathlib import Path
import tempfile
import pytest

from devfleet.analyzer import analyze_project, has_blockers


def analyze(compose: str):
    with tempfile.TemporaryDirectory() as tmp:
        p=Path(tmp)
        (p/'compose.yaml').write_text(compose)
        return analyze_project(p)


def test_safe_relative_mount():
    findings=analyze('''services:\n  dev:\n    image: ubuntu:24.04\n    volumes: [\".:/workspaces/x\"]\n    security_opt: [\"no-new-privileges:true\"]\n    healthcheck: {test: [\"CMD\", \"true\"]}\n''')
    assert not has_blockers(findings), findings


def test_absolute_mount_blocked():
    findings=analyze('''services:\n  dev:\n    image: ubuntu:24.04\n    volumes: [\"/home/devrunner:/host\"]\n''')
    assert any(x['code']=='docker.mount' and x['severity']=='critical' for x in findings)


def test_parent_mount_blocked():
    findings=analyze('''services:\n  dev:\n    image: ubuntu:24.04\n    volumes: [\"../other-project:/other\"]\n''')
    assert any(x['code']=='docker.mount' and x['severity']=='critical' for x in findings)


def test_socket_and_privileged_blocked():
    findings=analyze('''services:\n  dev:\n    image: ubuntu:24.04\n    privileged: true\n    volumes: [\"/run/user/1001/docker.sock:/var/run/docker.sock\"]\n''')
    assert has_blockers(findings)
    assert {'docker.mount','docker.privileged'} <= {x['code'] for x in findings}

def test_public_port_and_device_blocked():
    findings=analyze('''services:\n  dev:\n    image: ubuntu:24.04\n    ports: [\"3000:3000\"]\n    devices: [\"/dev/kvm:/dev/kvm\"]\n''')
    assert {'docker.port-public','docker.devices'} <= {x['code'] for x in findings}


def test_loopback_port_allowed():
    findings=analyze('''services:\n  dev:\n    image: ubuntu:24.04\n    ports: [\"127.0.0.1:3000:3000\"]\n    security_opt: [\"no-new-privileges:true\"]\n    healthcheck: {test: [\"CMD\", \"true\"]}\n''')
    assert not has_blockers(findings), findings

def test_symlink_bind_source_outside_project_is_blocked(tmp_path: Path):
    outside=tmp_path/'outside'
    outside.mkdir()
    project=tmp_path/'project'
    project.mkdir()
    try:
        (project/'escape').symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip('Windows test host does not grant symbolic-link creation privilege')
    (project/'compose.yaml').write_text('''services:\n  app:\n    image: alpine:3.20\n    security_opt: [no-new-privileges:true]\n    volumes:\n      - ./escape:/data\n    ports:\n      - 127.0.0.1:8080:80\n''')
    findings=analyze_project(project)
    assert has_blockers(findings)
    assert any(x['code']=='docker.mount-resolution' for x in findings)


def test_rebuild_context_symlink_outside_project_is_blocked(tmp_path: Path):
    outside=tmp_path/'outside-build'
    outside.mkdir()
    project=tmp_path/'project'
    project.mkdir()
    try:
        (project/'escape-build').symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip('Windows test host does not grant symbolic-link creation privilege')
    (project/'compose.yaml').write_text('''services:\n  app:\n    build: ./escape-build\n    security_opt: [no-new-privileges:true]\n    ports:\n      - 127.0.0.1:8080:80\n''')
    findings=analyze_project(project)
    assert has_blockers(findings)
    assert any(x['code']=='docker.build-context' for x in findings)
