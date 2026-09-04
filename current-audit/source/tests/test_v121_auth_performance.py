"""Regression coverage for the v1.2.1 session and dashboard contracts.

These tests intentionally exercise the ASGI app in-process.  They never start a
service and the performance test uses a mocked five-second peer instead of a
real network endpoint.
"""

import re
import time

import pytest


try:
    from fastapi.testclient import TestClient
    from devfleet import main
    from devfleet import status as status_module
except Exception as exc:  # pragma: no cover - depends on the host test image
    pytest.skip(
        f"FastAPI application tests unavailable in this environment: {exc}",
        allow_module_level=True,
    )


def _no_redirect(client, method, url, **kwargs):
    """Support both Starlette/TestClient keyword spellings across versions."""
    try:
        return getattr(client, method)(url, follow_redirects=False, **kwargs)
    except TypeError:
        return getattr(client, method)(url, allow_redirects=False, **kwargs)


def _client():
    try:
        return TestClient(main.app)
    except Exception as exc:  # pragma: no cover - dependency-version specific
        pytest.skip(f"TestClient unavailable in this environment: {exc}")


def _csrf(html):
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "expected a rendered CSRF form token"
    return match.group(1)


def _signed_in_client():
    client = _client()
    login_page = client.get("/login")
    assert login_page.status_code == 200
    token = _csrf(login_page.text)
    response = _no_redirect(
        client,
        "post",
        "/login",
        data={
            "username": "test",
            "password": "test-password",
            "next": "/",
            "csrf_token": token,
        },
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert "devfleet_session" in client.cookies
    return client


def test_session_login_logout_and_csrf_contract():
    client = _client()

    login_page = client.get("/login")
    assert login_page.status_code == 200
    login_csrf = _csrf(login_page.text)
    assert "devfleet_login_csrf" in client.cookies

    rejected = _no_redirect(
        client,
        "post",
        "/login",
        data={
            "username": "test",
            "password": "test-password",
            "next": "/",
            "csrf_token": "wrong-token",
        },
    )
    assert rejected.status_code == 401
    assert "devfleet_session" not in client.cookies

    signed_in = _no_redirect(
        client,
        "post",
        "/login",
        data={
            "username": "test",
            "password": "test-password",
            "next": "/",
            "csrf_token": login_csrf,
        },
    )
    assert signed_in.status_code == 303
    assert signed_in.headers["location"] == "/"
    assert client.cookies.get("devfleet_session")

    index = client.get("/")
    assert index.status_code == 200
    session_csrf = _csrf(index.text)

    missing_csrf = _no_redirect(client, "post", "/logout", data={})
    assert missing_csrf.status_code == 403
    assert client.get("/").status_code == 200

    logged_out = _no_redirect(
        client, "post", "/logout", headers={"Sec-Fetch-Site": "same-origin"}, data={"csrf_token": session_csrf}
    )
    assert logged_out.status_code == 303
    assert logged_out.headers["location"].startswith("/login")
    assert _no_redirect(client, "get", "/").status_code == 303


def test_api_token_contract():
    client = _client()

    assert client.get("/api/status").status_code == 401
    assert client.get("/api/status", headers={"X-DevFleet-Token": "wrong"}).status_code == 401

    response = client.get("/api/status", headers={"X-DevFleet-Token": "test-token"})
    assert response.status_code == 200
    assert response.json()["node"] == "test-node"


def test_index_uses_catalog_and_snapshots_without_waiting_for_a_slow_peer(monkeypatch):
    client = _signed_in_client()
    catalog_calls = []
    snapshot_calls = []
    slow_peer_calls = []

    def catalog():
        catalog_calls.append(True)
        return [{"slug": "catalog-only", "display_name": "Catalog project"}]

    def live_projects_must_not_run():
        raise AssertionError("normal index rendering used live project inspection")

    def slow_peer():
        slow_peer_calls.append(True)
        time.sleep(5.0)
        return {"configured": True, "ok": True}

    def snapshot():
        snapshot_calls.append(True)
        return {
            "updated_at": "2026-08-10T00:00:00Z",
            "nodes": [],
            "containers": [],
            "snapshot": {"stale": False, "refreshing": False},
        }

    monkeypatch.setattr(status_module, "list_project_catalog", catalog)
    monkeypatch.setattr(status_module, "list_projects", live_projects_must_not_run)
    monkeypatch.setattr(status_module, "runtime_snapshot", lambda: status_module._cheap_runtime())
    monkeypatch.setattr(status_module, "peer_node_status", slow_peer)
    monkeypatch.setattr(main, "cluster_snapshot", snapshot)
    monkeypatch.setattr(main, "peer_call", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("peer_call used")))
    monkeypatch.setattr(main, "get_host_capacity", lambda: (_ for _ in ()).throw(AssertionError("host probe used")))
    monkeypatch.setattr(main, "get_provider_status", lambda: (_ for _ in ()).throw(AssertionError("provider probe used")))
    monkeypatch.setattr(main, "analyze_project", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("analyzer used")))

    started = time.perf_counter()
    response = client.get("/")
    elapsed = time.perf_counter() - started

    assert response.status_code == 200
    assert "catalog-only" in response.text
    assert catalog_calls == [True]
    assert snapshot_calls == [True]
    assert slow_peer_calls == []
    assert elapsed < 2.0, f"index rendering took {elapsed:.2f}s"
