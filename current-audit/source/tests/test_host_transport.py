from __future__ import annotations

import pytest

from devfleet.host_control import build_request_auth, build_response_auth, validate_backup_reference, verify_response_auth


def test_host_transport_mac_binds_method_path_body_host_and_nonce():
    first = build_request_auth("POST", "/v1/project-vms/x/start", b'{"x":1}', "key-a", "HOST-A", timestamp=1_700_000_000, nonce="nonce-a")
    same = build_request_auth("POST", "/v1/project-vms/x/start", b'{"x":1}', "key-a", "HOST-A", timestamp=1_700_000_000, nonce="nonce-a")
    assert first == same
    assert first["X-DevFleet-Host-Signature"] != build_request_auth("POST", "/v1/project-vms/x/start", b'{"x":2}', "key-a", "HOST-A", timestamp=1_700_000_000, nonce="nonce-a")["X-DevFleet-Host-Signature"]
    assert first["X-DevFleet-Host-Signature"] != build_request_auth("POST", "/v1/project-vms/x/start", b'{"x":1}', "key-b", "HOST-A", timestamp=1_700_000_000, nonce="nonce-a")["X-DevFleet-Host-Signature"]
    assert first["X-DevFleet-Host-Signature"] != build_request_auth("POST", "/v1/project-vms/x/start", b'{"x":1}', "key-a", "HOST-B", timestamp=1_700_000_000, nonce="nonce-a")["X-DevFleet-Host-Signature"]


def test_host_transport_response_mac_is_bound_to_request_and_body():
    body = b'{"ok":true,"runtime_id":"runtime-a"}'
    signature = build_response_auth(
        "POST", "/v1/project-vms/runtime-a/inspect", 200, body, "key-a", "HOST-A",
        timestamp="1700000000", nonce="nonce-a",
    )
    verify_response_auth(
        "POST", "/v1/project-vms/runtime-a/inspect", 200, body, "key-a", "HOST-A",
        timestamp="1700000000", nonce="nonce-a", provided=signature,
    )
    with pytest.raises(RuntimeError, match="response authentication"):
        verify_response_auth(
            "POST", "/v1/project-vms/runtime-a/inspect", 200,
            b'{"ok":false,"runtime_id":"attacker"}', "key-a", "HOST-A",
            timestamp="1700000000", nonce="nonce-a", provided=signature,
        )
    with pytest.raises(RuntimeError, match="response authentication"):
        verify_response_auth(
            "POST", "/v1/project-vms/runtime-a/inspect", 200, body, "key-a", "HOST-A",
            timestamp="1700000000", nonce="nonce-b", provided=signature,
        )


def test_hostagent_backup_reference_is_opaque_and_identity_bound():
    reference = {
        "provider": "multipass-host-agent",
        "backup_id": "demo-20260818-abc123",
        "project_id": "11111111-1111-1111-1111-111111111111",
        "slug": "demo",
        "runtime_id": "devfleet-project-demo",
        "host_id": "MULATTOTECHBOX",
        "archive_sha256": "a" * 64,
        "archive_bytes": 42,
        "manifest_sha256": "b" * 64,
        "created_at": "2026-08-18T00:00:00Z",
        "consistency_level": "quiesced",
    }
    checked = validate_backup_reference(reference, project_id=reference["project_id"], slug="demo", runtime_id=reference["runtime_id"], host_id=reference["host_id"])
    assert "archive_path" not in checked
    old_provider = {**reference, "backup_path": r"C:\ProgramData\DevFleetHostAgent\backups\demo.tar.gz"}
    with pytest.raises(RuntimeError, match="provider-local backup path"):
        validate_backup_reference(old_provider, project_id=reference["project_id"], slug="demo", runtime_id=reference["runtime_id"], host_id=reference["host_id"])
    with pytest.raises(RuntimeError, match="does not match"):
        validate_backup_reference(reference, project_id=reference["project_id"], slug="foreign", runtime_id=reference["runtime_id"], host_id=reference["host_id"])
