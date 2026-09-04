from __future__ import annotations

import json
from pathlib import Path

import pytest


def test_security_config_malformed_does_not_fall_back_to_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from devfleet import core

    path = tmp_path / "config.json"
    path.write_text("{malformed", encoding="utf-8")
    monkeypatch.setattr(core, "CONFIG_PATH", path)
    with pytest.raises(ValueError, match="refusing fail-open defaults"):
        core.load_settings()


def test_security_config_valid_policy_is_loaded_without_mutation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from devfleet import core

    path = tmp_path / "config.json"
    path.write_text(json.dumps({"node_name": "test", "require_tailscale": True, "public_binding_allowed": False}), encoding="utf-8")
    monkeypatch.setattr(core, "CONFIG_PATH", path)
    settings = core.load_settings()
    assert settings.node_name == "test"
    assert settings.require_tailscale is True
    assert settings.public_binding_allowed is False
