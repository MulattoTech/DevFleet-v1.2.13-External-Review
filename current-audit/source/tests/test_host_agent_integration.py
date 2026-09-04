from __future__ import annotations

import hmac
import json
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from devfleet import host_control
from devfleet.host_control import build_request_auth, build_response_auth


KEY = "integration-only-host-agent-key"
HOST = "DISPOSABLE-HOST"


class _HostAgentHandler(BaseHTTPRequestHandler):
    server_version = "DevFleetTestHostAgent/1.0"

    def log_message(self, *_args):
        return

    def _body(self) -> bytes:
        size = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(size) if size else b""

    def _send_json(self, status: int, payload: dict[str, object], *, signed: bool = True) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if signed:
            signature = build_response_auth(
                self.command,
                self.path,
                status,
                body,
                KEY,
                HOST,
                timestamp=self.headers["X-DevFleet-Host-Timestamp"],
                nonce=self.headers["X-DevFleet-Host-Nonce"],
            )
            self.send_header("X-DevFleet-Host-Response-Signature", signature)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_request(self, body: bytes) -> bool:
        provided = self.headers.get("X-DevFleet-Host-Signature", "")
        expected = build_request_auth(
            self.command,
            self.path,
            body,
            KEY,
            HOST,
            timestamp=int(self.headers.get("X-DevFleet-Host-Timestamp", "0")),
            nonce=self.headers.get("X-DevFleet-Host-Nonce", ""),
        )["X-DevFleet-Host-Signature"]
        return bool(self.headers.get("X-DevFleet-Host-Expected") == HOST and hmac.compare_digest(provided, expected))

    def _dispatch(self) -> None:
        body = self._body()
        if not self._check_request(body):
            self._send_json(401, {"ok": False, "error": "request authentication failed"}, signed=False)
            return
        if self.path == "/healthz":
            self._send_json(200, {"ok": True, "host_name": HOST, "agent_version": "1.2.13"})
        elif self.path == "/v1/host/capacity":
            self._send_json(200, {"ok": True, "host_name": HOST, "capacity": {"allocatable_cpus": 8}})
        elif self.path.endswith("/project-health"):
            self._send_json(500, {"ok": False, "error": "disposable worker failure"})
        else:
            self._send_json(404, {"ok": False, "error": "not found"})

    def do_GET(self):  # noqa: N802
        self._dispatch()

    def do_POST(self):  # noqa: N802
        self._dispatch()


@pytest.fixture
def disposable_host_agent(monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HostAgentHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    original = host_control.SETTINGS
    monkeypatch.setattr(
        host_control,
        "SETTINGS",
        replace(
            original,
            host_control_enabled=True,
            host_control_url=f"http://127.0.0.1:{server.server_port}",
            host_control_token=KEY,
            expected_host_name=HOST,
        ),
    )
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_python_client_exercises_real_local_host_agent_contract(disposable_host_agent):
    assert host_control.host_control_status()["status"] == "healthy"
    assert host_control.get_host_capacity()["capacity"]["allocatable_cpus"] == 8
    with pytest.raises(RuntimeError, match="500"):
        host_control.host_control_request("project-health", {"slug": "demo"}, runtime_id="runtime-demo")
