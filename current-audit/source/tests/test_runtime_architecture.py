from pathlib import Path

from devfleet.resource_profiles import RESOURCE_PROFILES, recommend_resource_profile, recommend_runtime_isolation, write_resource_override
from devfleet.runtime import CONTAINER_PROVIDER, VM_PROVIDER, provider_for


def test_resource_profiles_are_central_and_include_vm_disk():
    assert set(RESOURCE_PROFILES) == {'small', 'standard', 'large', 'xlarge'}
    assert RESOURCE_PROFILES['standard'].disk_gb == 40
    assert RESOURCE_PROFILES['xlarge'].cpus == 6
    assert recommend_resource_profile(scale='large', intent='production').name == 'large'
    assert recommend_runtime_isolation(scale='large', intent='production') == 'vm'


def test_container_resource_override_is_generated(tmp_path: Path):
    project = tmp_path / 'project'
    project.mkdir()
    compose = project / 'compose.yaml'
    compose.write_text('services:\n  dev:\n    image: ubuntu:24.04\n')
    override = write_resource_override(project, compose, 'standard')
    assert override and override.is_file()
    text = override.read_text()
    assert 'cpus: 2.0' in text
    assert 'mem_limit: 4g' in text
    assert 'pids_limit: 768' in text


def test_runtime_provider_migrates_old_projects_to_container():
    assert provider_for({}) == CONTAINER_PROVIDER
    assert provider_for({'runtime_isolation': 'vm'}) == VM_PROVIDER
    assert provider_for({'runtime_type': 'container'}) == CONTAINER_PROVIDER


def test_host_agent_exposes_only_structured_runtime_operations():
    root = Path(__file__).resolve().parents[1]
    script = (root / 'windows' / 'DevFleet-HostAgent.ps1').read_text()
    assert "'ensure'" in script
    assert "'destroy'" in script
    assert "'capacity'" in script
    assert 'Invoke-Expression' not in script
    assert 'Start-Process' not in script
    assert 'X-DevFleet-Host-Signature' in script
    assert 'X-DevFleet-Host-Token' not in script
    assert 'devfleet-project-$Slug' in script
