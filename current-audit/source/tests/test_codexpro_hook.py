import shutil
import subprocess
import uuid
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def project_root():
    if os.name == 'nt':
        pytest.skip('CodexPro shell-hook tests require a POSIX execution environment')
    base = Path(os.environ.get("DEVFLEET_TEST_WORKSPACES", "/workspaces"))
    base.mkdir(parents=True, exist_ok=True)
    project = base / f"devfleet-hook-test-{uuid.uuid4().hex[:12]}"
    project.mkdir(parents=True)
    try:
        yield project
    finally:
        shutil.rmtree(project, ignore_errors=True)


def materialize(project: Path):
    hook = project / ".devfleet/codexpro-bootstrap.sh"
    hook.parent.mkdir()
    hook.write_text((ROOT / "templates/generic/.devfleet/codexpro-bootstrap.sh").read_text())
    hook.chmod(0o755)
    return hook


def hook_env(project: Path):
    env = dict(os.environ)
    env.update(PATH="/usr/bin:/bin", DEVFLEET_WORKSPACES_ROOT=str(project.parent), DEVFLEET_CODEXPRO_HEALTH_URL="http://127.0.0.1:18787/healthz")
    return env
    return hook


def test_unavailable_state_is_actionable(project_root):
    hook = materialize(project_root)
    result = subprocess.run(
        [str(hook)],
        cwd=project_root,
        text=True,
        capture_output=True,
        env=hook_env(project_root),
    )
    assert result.returncode == 0
    assert "unavailable" in (project_root / ".devfleet/runtime/codexpro-status.json").read_text()


def test_hook_idempotent_unavailable(project_root):
    hook = materialize(project_root)
    subprocess.run([str(hook)], cwd=project_root, env=hook_env(project_root), check=True)
    subprocess.run([str(hook)], cwd=project_root, env=hook_env(project_root), check=True)
    assert (project_root / ".devfleet/runtime/codexpro-bootstrap.log").exists()
