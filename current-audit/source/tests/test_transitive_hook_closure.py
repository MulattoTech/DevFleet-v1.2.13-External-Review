from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from hook_modes import executable_template_hook_closure, hook_mode_manifest


def test_executable_hook_closure_includes_transitive_health_dependencies() -> None:
    closures = executable_template_hook_closure(ROOT)
    assert len(set().union(*(item.executable for item in closures.values()))) == 78
    assert all(item.transitive for item in closures.values() if item.direct and item.transitive)
    assert "templates/node/.devfleet/smoke-test.sh" in set().union(*(item.executable for item in closures.values()))


def test_hook_manifest_classifies_every_template_script() -> None:
    manifest = hook_mode_manifest(ROOT)
    scripts = list((ROOT / "templates").glob("*/.devfleet/*.sh"))
    assert len(manifest["classification"]) == len(scripts)
    assert set(manifest["classification"].values()) <= {
        "executable-by-contract",
        "non-executable-source/helper",
    }
    assert manifest["count"] == 78


def test_hook_closure_rejects_unsafe_local_reference(tmp_path: Path) -> None:
    template = tmp_path / "templates" / "fixture" / ".devfleet"
    template.mkdir(parents=True)
    (template / "template.json").write_text(
        json.dumps({"health_command": "./.devfleet/health-check.sh"}), encoding="utf-8"
    )
    (template / "health-check.sh").write_text("#!/usr/bin/env bash\n./.devfleet/../outside.sh\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unsafe local hook reference"):
        executable_template_hook_closure(tmp_path)
