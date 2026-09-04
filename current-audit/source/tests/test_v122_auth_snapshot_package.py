import os
import stat
import tarfile
from pathlib import Path

import pytest

from devfleet import auth, status

ROOT = Path(__file__).resolve().parents[1]


def test_v122_ttls_and_nonempty_secret_guards():
    assert auth.SESSION_TTL == 12 * 60 * 60
    assert auth.REMEMBERED_TTL == 7 * 24 * 60 * 60
    assert not auth.valid_credentials("", "anything")
    assert not auth.valid_credentials("test", "")
    assert auth.session_cookie_options()["samesite"] == "strict"


def test_session_csrf_and_credential_generation_invalidation(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "_session_path", lambda: tmp_path / "sessions.json")
    token, ttl, csrf = auth.issue_session("test")
    assert ttl == auth.SESSION_TTL
    assert auth.validate_session(token) == "test"
    record = auth._load_sessions()[token]
    assert auth.validate_session_csrf(_request_with_cookie(token), csrf)
    original_password = auth.SETTINGS.admin_password
    try:
        object.__setattr__(auth.SETTINGS, "admin_password", "rotated-password")
        assert auth.validate_session(token) is None
        assert record["credential_generation"] != auth._credential_generation()
    finally:
        object.__setattr__(auth.SETTINGS, "admin_password", original_password)


class _Request:
    def __init__(self, token):
        self.cookies = {auth.SESSION_COOKIE: token}


def _request_with_cookie(token):
    return _Request(token)


def test_login_backoff_is_bounded_and_source_scoped(monkeypatch):
    auth._LOGIN_FAILURES.clear()
    for _ in range(20):
        auth._record_login_failure("bad-user", "source-a", now=100.0)
    delay = auth.login_backoff_seconds("bad-user", "source-a", now=100.0)
    assert 0 < delay <= auth._BACKOFF_MAX
    assert auth.login_backoff_seconds("bad-user", "source-b", now=100.0) == 0


def test_snapshot_schedule_reserves_before_submit(monkeypatch):
    status._SNAPSHOTS["runtime"].update({"refreshing": False, "value": None, "updated_at": 0.0})
    submitted = []
    class Executor:
        def submit(self, fn, name):
            submitted.append((fn, name))
    monkeypatch.setattr(status, "_SNAPSHOT_EXECUTOR", Executor())
    status._schedule_snapshot("runtime")
    status._schedule_snapshot("runtime")
    assert len(submitted) == 1
    status._SNAPSHOTS["runtime"]["refreshing"] = False


def test_peer_failure_enters_backoff_without_retries(monkeypatch):
    status._PEER_STATE.update({"failures": 0, "retry_after": 0.0, "circuit_until": 0.0, "value": None})
    monkeypatch.setattr(status, "load_peer", lambda: {"Url": "http://peer", "Token": "token"})
    calls = []
    def fail(*args, **kwargs):
        calls.append(args[0])
        raise OSError("offline")
    monkeypatch.setattr(status.httpx, "get", fail)
    first = status.peer_node_status()
    second = status.peer_node_status()
    assert first["ok"] is False and second["status"] in {"unreachable", "backoff"}
    assert calls == ["http://peer/api/node/status"]


def test_verifier_is_pinned_to_v122_and_checks_hooks():
    verifier = (ROOT / "tools/verify_package.py").read_text(encoding="utf-8")
    assert 're.fullmatch(r"\\d+\\.\\d+\\.\\d+", PACKAGE_VERSION)' in verifier
    assert "linux_executable_hooks" in verifier
    assert "Basic" not in (ROOT / "app/devfleet/auth.py").read_text(encoding="utf-8")


def test_all_trusted_hooks_are_executable_on_posix():
    if os.name == "nt":
        pytest.skip("Windows does not expose POSIX execute bits")
    hooks = list((ROOT / "templates").glob("*/.devfleet/codexpro-bootstrap.sh"))
    assert hooks
    assert all(p.stat().st_mode & stat.S_IXUSR for p in hooks)
