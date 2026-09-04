"""Bounded admission guards for expensive HTTP parser paths."""
from __future__ import annotations

import logging
import re
import time
from collections.abc import Awaitable, Callable
from typing import Any

from .auth import api_token_valid


LOGGER = logging.getLogger("devfleet.http_admission")
LOGIN_BODY_LIMIT = 64 * 1024
API_BODY_LIMIT = 256 * 1024
DEFAULT_BODY_LIMIT = 256 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_HEADER_COUNT = 64
MAX_RANGE_HEADER_BYTES = 4096
MAX_RANGE_COUNT = 8
_RANGE_RE = re.compile(r"^(?:\d+-\d*|-\d+)$")


def _header_map(scope: dict[str, Any]) -> dict[str, str]:
    return {
        bytes(name).decode("latin-1").lower(): bytes(value).decode("latin-1")
        for name, value in scope.get("headers", [])
    }


def _peer(scope: dict[str, Any]) -> str:
    client = scope.get("client")
    return str(client[0])[:200] if client else "unknown"


def _reject_reason(scope: dict[str, Any], reason: str, *, declared: int | None, observed: int, started: float) -> None:
    headers = _header_map(scope)
    LOGGER.warning(
        "bounded HTTP request rejected peer=%s path=%s content_type=%s declared_bytes=%s observed_bytes=%s reason=%s elapsed_ms=%.2f",
        _peer(scope), str(scope.get("path", ""))[:256], headers.get("content-type", "")[:120],
        declared if declared is not None else "missing", observed, reason,
        (time.perf_counter() - started) * 1000,
    )


class RequestAdmissionRejected(Exception):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


def _declared_length(headers: dict[str, str]) -> int | None:
    raw = headers.get("content-length")
    if raw is None:
        return None
    try:
        value = int(raw.strip())
    except ValueError as exc:
        raise RequestAdmissionRejected(400, "invalid Content-Length") from exc
    if value < 0:
        raise RequestAdmissionRejected(400, "invalid Content-Length")
    return value


def validate_range_header(value: str | None) -> tuple[bool, str]:
    if not value:
        return True, ""
    if len(value.encode("latin-1", errors="replace")) > MAX_RANGE_HEADER_BYTES:
        return False, "range header too long"
    if not value.lower().startswith("bytes="):
        return False, "unsupported range unit"
    ranges = [part.strip() for part in value[6:].split(",")]
    if not ranges or len(ranges) > MAX_RANGE_COUNT or any(not _RANGE_RE.fullmatch(part) for part in ranges):
        return False, "malformed or excessive range set"
    return True, ""


async def _send_rejection(send: Callable[..., Awaitable[None]], status: int, reason: str) -> None:
    body = (reason + "\n").encode("utf-8")
    await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"text/plain; charset=utf-8"), (b"content-length", str(len(body)).encode("ascii"))]})
    await send({"type": "http.response.body", "body": body})


async def _send_api_token_rejection(send: Callable[..., Awaitable[None]]) -> None:
    body = b'{"detail":"Invalid API token"}'
    await send({"type": "http.response.start", "status": 401, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode("ascii"))]})
    await send({"type": "http.response.body", "body": body})


class RequestAdmissionMiddleware:
    """Reject bounded parser abuse before FastAPI dependency/form parsing."""

    def __init__(self, app: Callable[..., Awaitable[None]]) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Callable[..., Awaitable[dict[str, Any]]], send: Callable[..., Awaitable[None]]) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers = _header_map(scope)
        started = time.perf_counter()
        header_bytes = sum(len(name) + len(value) for name, value in scope.get("headers", []))
        if len(scope.get("headers", [])) > MAX_HEADER_COUNT or header_bytes > MAX_HEADER_BYTES:
            _reject_reason(scope, "header budget exceeded", declared=None, observed=0, started=started)
            await _send_rejection(send, 431, "request headers exceed the bounded limit")
            return

        path = str(scope.get("path", ""))
        if path.startswith("/static"):
            valid, reason = validate_range_header(headers.get("range"))
            if not valid:
                _reject_reason(scope, reason, declared=None, observed=0, started=started)
                await _send_rejection(send, 416, "range request is not accepted")
                return

        method = str(scope.get("method", "")).upper()
        body_bearing = method in {"POST", "PUT", "PATCH"}
        is_api = path.startswith("/api/")
        if is_api and not api_token_valid(headers.get("x-devfleet-token")):
            _reject_reason(scope, "invalid API token", declared=None, observed=0, started=started)
            await _send_api_token_rejection(send)
            return

        is_login = path == "/login" and method == "POST"
        if is_login:
            limit = LOGIN_BODY_LIMIT
        elif body_bearing and is_api:
            limit = API_BODY_LIMIT
        elif body_bearing:
            limit = DEFAULT_BODY_LIMIT
        else:
            limit = None
        try:
            declared = _declared_length(headers)
        except RequestAdmissionRejected as exc:
            _reject_reason(scope, exc.reason, declared=None, observed=0, started=started)
            await _send_rejection(send, exc.status, exc.reason)
            return
        if is_login:
            content_type = headers.get("content-type", "").lower()
            if not (content_type.startswith("application/x-www-form-urlencoded") or content_type.startswith("multipart/form-data;")):
                _reject_reason(scope, "unsupported login content type", declared=declared, observed=0, started=started)
                await _send_rejection(send, 415, "login requires a bounded form content type")
                return
        if limit is not None and declared is not None and declared > limit:
            reason = "declared login body exceeds limit" if is_login else "declared request body exceeds limit"
            message = "login form body exceeds the bounded limit" if is_login else "request body exceeds the bounded limit"
            _reject_reason(scope, reason, declared=declared, observed=0, started=started)
            await _send_rejection(send, 413, message)
            return

        if limit is not None:
            # Read only the bounded body before invoking FastAPI.  The
            # buffer can never exceed `limit`; an over-limit chunk is rejected
            # without being retained, so parser work cannot start first and
            # turn the admission failure into a generic 400 response.
            buffered: list[dict[str, Any]] = []
            observed = 0
            while True:
                message = await receive()
                if message.get("type") != "http.request":
                    buffered.append(message)
                    break
                body = message.get("body", b"") or b""
                observed += len(body)
                if observed > limit:
                    reason = "observed login body exceeds limit" if is_login else "observed request body exceeds limit"
                    message = "login form body exceeds the bounded limit" if is_login else "request body exceeds the bounded limit"
                    _reject_reason(scope, reason, declared=declared, observed=observed, started=started)
                    await _send_rejection(send, 413, message)
                    return
                buffered.append(message)
                if not message.get("more_body", False):
                    break
            replay = iter(buffered)

            async def bounded_receive() -> dict[str, Any]:
                try:
                    return next(replay)
                except StopIteration:
                    return {"type": "http.disconnect"}

            await self.app(scope, bounded_receive, send)
            return

        await self.app(scope, receive, send)
