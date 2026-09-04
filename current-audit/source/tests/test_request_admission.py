import asyncio
import dataclasses
import json

import httpx
from fastapi.testclient import TestClient

from devfleet import core, main
from devfleet.request_guards import API_BODY_LIMIT


async def _asgi_post(
    path,
    chunks,
    *,
    token=None,
    content_length=None,
    peer="100.64.0.5",
    slow=False,
):
    headers = [(b"content-type", b"application/json")]
    if token is not None:
        headers.append((b"x-devfleet-token", token.encode("ascii")))
    if content_length is not None:
        headers.append((b"content-length", str(content_length).encode("ascii")))
    messages = [
        {"type": "http.request", "body": chunk, "more_body": index < len(chunks) - 1}
        for index, chunk in enumerate(chunks)
    ]
    sent = []
    consumed = 0

    async def receive():
        nonlocal consumed
        if slow:
            await asyncio.sleep(0)
        if messages:
            message = messages.pop(0)
            consumed += len(message.get("body", b""))
            return message
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": (peer, 31337),
        "server": ("testserver", 80),
        "state": {},
    }
    await main.app(scope, receive, send)
    status = next(
        message["status"]
        for message in sent
        if message.get("type") == "http.response.start"
    )
    return status, consumed


def test_normal_login_and_static_requests_remain_available():
    client = TestClient(main.app)
    assert client.get("/static/app.js").status_code == 200
    assert client.head("/static/app.js").status_code == 200
    response = client.post("/login", data={"username": "bad", "password": "bad", "csrf_token": "bad"})
    assert response.status_code in {401, 403}


def test_declared_and_range_limits_reject_before_expensive_processing():
    client = TestClient(main.app)
    oversized = client.post(
        "/login",
        content=b"x" * (64 * 1024 + 1),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert oversized.status_code == 413
    assert client.get("/static/app.js", headers={"Range": "bytes=" + ",".join(["1-2"] * 9)}).status_code == 416
    assert client.get("/static/app.js", headers={"Range": "items=0-1"}).status_code == 416


def test_chunked_oversized_login_is_rejected_before_form_parsing():
    async def body():
        yield b"x" * 40_000
        yield b"y" * 40_000

    async def run():
        transport = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post(
                "/login",
                content=body(),
                headers={"content-type": "application/x-www-form-urlencoded"},
            )

    response = asyncio.run(run())
    assert response.status_code == 413


def test_missing_and_wrong_api_tokens_reject_declared_body_without_consumption():
    body = b"x" * (API_BODY_LIMIT + 1)
    for token in (None, "wrong-token"):
        status, consumed = asyncio.run(
            _asgi_post(
                "/api/projects/create",
                [body],
                token=token,
                content_length=len(body),
            )
        )
        assert status == 401
        assert consumed == 0


def test_missing_and_wrong_api_tokens_reject_chunked_body_without_consumption():
    chunks = [b"x" * 64_000 for _ in range(8)]
    for token in (None, "wrong-token"):
        status, consumed = asyncio.run(
            _asgi_post("/api/projects/create", chunks, token=token)
        )
        assert status == 401
        assert consumed == 0


def test_valid_api_token_allows_small_missing_length_body(monkeypatch):
    monkeypatch.setattr(main, "submit_operation", lambda *args, **kwargs: "op-test")
    body = json.dumps({"slug": "admission-test"}).encode("utf-8")
    status, consumed = asyncio.run(
        _asgi_post("/api/projects/create", [body], token="test-token")
    )
    assert status == 202
    assert consumed == len(body)


def test_valid_api_token_rejects_declared_and_chunked_over_limit_bodies():
    declared = API_BODY_LIMIT + 1
    status, consumed = asyncio.run(
        _asgi_post(
            "/api/projects/create",
            [b"x" * declared],
            token="test-token",
            content_length=declared,
        )
    )
    assert status == 413
    assert consumed == 0

    chunks = [b"x" * 65_536 for _ in range(8)]
    status, consumed = asyncio.run(
        _asgi_post("/api/projects/create", chunks, token="test-token")
    )
    assert status == 413
    assert API_BODY_LIMIT < consumed <= API_BODY_LIMIT + len(chunks[0])
    assert consumed < sum(map(len, chunks))


def test_valid_api_token_rejects_malformed_content_length_without_consumption():
    for content_length in ("not-a-number", "-1"):
        status, consumed = asyncio.run(
            _asgi_post(
                "/api/projects/create",
                [b"{}"],
                token="test-token",
                content_length=content_length,
            )
        )
        assert status == 400
        assert consumed == 0


def test_slow_many_chunk_api_body_stops_at_the_limit():
    chunks = [b"x" * 1024 for _ in range(300)]
    status, consumed = asyncio.run(
        _asgi_post(
            "/api/projects/create",
            chunks,
            token="test-token",
            slow=True,
        )
    )
    assert status == 413
    assert API_BODY_LIMIT < consumed <= API_BODY_LIMIT + len(chunks[0])
    assert consumed < sum(map(len, chunks))


def test_disallowed_network_peer_still_rejects_before_body_or_token_processing(monkeypatch):
    restricted = dataclasses.replace(
        core.SETTINGS,
        public_binding_allowed=False,
        require_tailscale=True,
    )
    monkeypatch.setattr(core, "SETTINGS", restricted)
    body = b"x" * (API_BODY_LIMIT + 1)
    status, consumed = asyncio.run(
        _asgi_post(
            "/api/projects/create",
            [body],
            peer="203.0.113.5",
        )
    )
    assert status == 403
    assert consumed == 0
