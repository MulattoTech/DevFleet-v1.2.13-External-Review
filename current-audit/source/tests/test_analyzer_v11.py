from pathlib import Path
import pytest
from devfleet.analyzer import analyze_project,has_blockers
def project(tmp_path,text):
 p=tmp_path/'demo';p.mkdir();(p/'compose.yaml').write_text(text);return p
def test_windows_mount_blocked(tmp_path):assert has_blockers(analyze_project(project(tmp_path,'services:\n  x:\n    image: x:1\n    volumes: ["C:\\\\Users:/host"]\n'),'balanced',True))
def test_parent_mount_blocked(tmp_path):assert has_blockers(analyze_project(project(tmp_path,'services:\n  x:\n    image: x:1\n    volumes: ["../:/host"]\n'),'fast',True))
def test_docker_socket_blocked_in_fast(tmp_path):assert has_blockers(analyze_project(project(tmp_path,'services:\n  x:\n    image: x:1\n    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]\n'),'fast',True))
def test_loopback_port_allowed_balanced(tmp_path):assert not has_blockers(analyze_project(project(tmp_path,'services:\n  x:\n    image: x:1\n    ports: ["127.0.0.1:3000:3000"]\n    healthcheck: {test: ["CMD","true"]}\n    security_opt: ["no-new-privileges:true"]\n'),'balanced',True))
def test_tailnet_allowed_balanced(tmp_path):assert not has_blockers(analyze_project(project(tmp_path,'services:\n  x:\n    image: x:1\n    ports: ["100.64.1.2:3000:3000"]\n    healthcheck: {test: ["CMD","true"]}\n    security_opt: ["no-new-privileges:true"]\n'),'balanced',True))
def test_public_port_blocked(tmp_path):assert has_blockers(analyze_project(project(tmp_path,'services:\n  x:\n    image: x:1\n    ports: ["3000:3000"]\n'),'fast',True))
def test_symlink_escape_blocked(tmp_path):
 p=project(tmp_path,'services:\n  x:\n    image: x:1\n')
 try:(p/'escape').symlink_to(tmp_path)
 except OSError:pytest.skip('Windows test host does not grant symbolic-link creation privilege')
 assert has_blockers(analyze_project(p,'balanced',True))
def test_cache_invalidates(tmp_path):
 p=project(tmp_path,'services:\n  x:\n    image: x:1\n    ports: ["127.0.0.1:3000:3000"]\n');a=analyze_project(p,'balanced');(p/'compose.yaml').write_text('services:\n  x:\n    image: x:1\n    ports: ["3000:3000"]\n');b=analyze_project(p,'balanced');assert a!=b and has_blockers(b)

def test_balanced_hardening_items_are_warnings(tmp_path):
 p=project(tmp_path,'services:\n  x:\n    build: .\n    ports: ["127.0.0.1:3000:3000"]\n');(p/'Dockerfile').write_text('FROM alpine:3.20\nRUN true\n')
 findings=analyze_project(p,'balanced',True)
 by_code={x['code']:x['severity'] for x in findings}
 assert by_code['docker.healthcheck']=='warning'
 assert by_code['docker.no-new-privileges']=='warning'
 assert by_code['docker.non-root-user']=='warning'
 assert not has_blockers(findings)

def test_strict_hardening_items_block(tmp_path):
 p=project(tmp_path,'services:\n  x:\n    build: .\n');(p/'Dockerfile').write_text('FROM alpine:3.20\n')
 assert has_blockers(analyze_project(p,'strict',True))

def test_fast_device_requires_project_acknowledgement(tmp_path):
 p=project(tmp_path,'services:\n  x:\n    image: alpine:3.20\n    devices: ["/dev/kvm:/dev/kvm"]\n    ports: ["127.0.0.1:3000:3000"]\n    healthcheck: {test: ["CMD","true"]}\n    security_opt: ["no-new-privileges:true"]\n')
 (p/'.devfleet').mkdir();(p/'.devfleet/project.json').write_text('{"profile":"fast","allow_devices":false}')
 assert has_blockers(analyze_project(p,'fast',True))
 (p/'.devfleet/project.json').write_text('{"profile":"fast","allow_devices":true}')
 assert not has_blockers(analyze_project(p,'fast',True))

def test_cache_invalidates_when_referenced_environment_file_changes(tmp_path):
 p=project(tmp_path,'services:\n  x:\n    image: alpine:3.20\n    env_file: config/runtime-settings\n    ports: ["127.0.0.1:3000:3000"]\n    healthcheck: {test: ["CMD","true"]}\n    security_opt: ["no-new-privileges:true"]\n')
 (p/'config').mkdir();env=p/'config/runtime-settings';env.write_text('MODE=one\n')
 analyze_project(p,'balanced');cache=p/'.devfleet/runtime/analyzer-cache.json';first=cache.read_text()
 env.write_text('MODE=two-with-different-size\n')
 analyze_project(p,'balanced');assert cache.read_text()!=first
