from types import SimpleNamespace

import pytest

from devfleet import core, main


def test_tailscale_network_policy_allows_loopback_and_tailnet_only(monkeypatch):
    settings = SimpleNamespace(require_tailscale=True, public_binding_allowed=False, tailnet_cidr="100.64.0.0/10")
    monkeypatch.setattr(core, "SETTINGS", settings)
    assert core.client_allowed_by_network("127.0.0.1") is True
    assert core.client_allowed_by_network("100.100.20.4") is True
    assert core.client_allowed_by_network("192.168.1.25") is False
    assert core.client_allowed_by_network("10.0.0.2") is False
    assert core.client_allowed_by_network("not-an-ip") is False


def test_public_binding_policy_is_explicit_opt_in(monkeypatch):
    settings = SimpleNamespace(require_tailscale=True, public_binding_allowed=True, tailnet_cidr="100.64.0.0/10")
    monkeypatch.setattr(core, "SETTINGS", settings)
    assert core.client_allowed_by_network("192.168.1.25") is True


def test_login_csrf_generation_requires_request():
    with pytest.raises(ValueError, match="request-bound session"):
        main.ui_csrf_token()


def test_login_csrf_cookie_is_http_only_and_server_rendered():
    source = (main.__file__ and __import__("pathlib").Path(main.__file__).read_text(encoding="utf-8"))
    assert "httponly=True" in source
    assert "httponly=False" not in source
