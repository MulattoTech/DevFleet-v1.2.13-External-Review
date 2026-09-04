"""Narrow authenticated client for the Windows DevFleet host agent."""
from __future__ import annotations

import json
import re
import hashlib
import hmac
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .core import SETTINGS, validate_project_id, validate_slug
from .resource_profiles import validate_resource_limits


_ACTION_TIMEOUTS = {
    "inspect": 10,
    "health": 15,
    "capacity": 10,
    "provider": 10,
    "start": 120,
    "stop": 120,
    "restart": 180,
    "create": 1200,
    "destroy": 600,
    "backup": 600,
    "list-backups": 30,
    "inspect-backup": 60,
    "restore-backup": 1200,
    "quarantine": 600,
    "restore": 600,
    "import": 900,
    "export": 1200,
    "export-to-source": 1200,
    "restore-previous-source": 300,
    "sync-ssh-alias": 30,
    "refresh-connection-state": 30,
    "project-start": 900,
    "project-stop": 900,
    "project-restart": 1200,
    "project-health": 120,
    "project-test": 1800,
    "project-bootstrap": 3600,
    "project-rebuild": 3600,
    "project-logs": 120,
}


def validate_backup_reference(
    reference: Any,
    *,
    provider: str = "multipass-host-agent",
    project_id: str = "",
    slug: str = "",
    runtime_id: str = "",
    host_id: str = "",
) -> dict[str, Any]:
    """Validate a provider-owned backup identity without accepting a path.

    A provider-local archive path is deliberately not part of the returned
    authority.  Only the provider can resolve and verify the opaque ID.
    """
    if not isinstance(reference, dict):
        raise RuntimeError("Host agent returned no provider-owned backup reference.")
    forbidden = {"backup_path", "archive_path", "manifest_path", "path"}
    if forbidden.intersection(reference):
        raise RuntimeError("Host agent exposed a provider-local backup path as authority.")
    expected = {
        "provider": provider,
        "project_id": project_id,
        "slug": slug,
        "runtime_id": runtime_id,
        "host_id": host_id,
    }
    for key, value in expected.items():
        if value and str(reference.get(key) or "") != str(value):
            raise RuntimeError(f"Provider backup reference {key} does not match the requested identity.")
    for key in ("backup_id", "archive_sha256", "manifest_sha256"):
        if not str(reference.get(key) or ""):
            raise RuntimeError(f"Provider backup reference is missing {key}.")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", str(reference["archive_sha256"])):
        raise RuntimeError("Provider backup reference archive hash is malformed.")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", str(reference["manifest_sha256"])):
        raise RuntimeError("Provider backup reference manifest hash is malformed.")
    if int(reference.get("archive_bytes") or 0) < 0:
        raise RuntimeError("Provider backup reference archive size is malformed.")
    return {key: reference[key] for key in ("provider", "backup_id", "project_id", "slug", "runtime_id", "host_id", "archive_sha256", "archive_bytes", "manifest_sha256", "created_at", "consistency_level") if key in reference}


def build_request_auth(method: str, path: str, body: bytes, key: str, expected_host: str, *, timestamp: int | None = None, nonce: str | None = None) -> dict[str, str]:
    """Build the non-bearer request-authentication headers.

    The key never appears in a request.  The server binds the MAC to the
    expected host, preventing a captured request from being redirected to a
    different configured Host Agent.
    """
    timestamp_text = str(int(time.time()) if timestamp is None else int(timestamp))
    nonce_text = nonce or secrets.token_urlsafe(24)
    material = b"\n".join((method.upper().encode(), path.encode(), timestamp_text.encode(), nonce_text.encode(), body, expected_host.encode()))
    signature = hmac.new(str(key).encode(), material, hashlib.sha256).hexdigest()
    return {"X-DevFleet-Host-Timestamp": timestamp_text, "X-DevFleet-Host-Nonce": nonce_text, "X-DevFleet-Host-Expected": expected_host, "X-DevFleet-Host-Signature": signature}


def _response_auth_material(
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    status: int,
    body: bytes,
    expected_host: str,
) -> bytes:
    return b"\n".join(
        (
            method.upper().encode(),
            path.encode(),
            str(timestamp).encode(),
            str(nonce).encode(),
            str(int(status)).encode(),
            body,
            expected_host.encode(),
        )
    )


def build_response_auth(
    method: str,
    path: str,
    status: int,
    body: bytes,
    key: str,
    expected_host: str,
    *,
    timestamp: str,
    nonce: str,
) -> str:
    """Return the response MAC bound to the exact authenticated request."""
    material = _response_auth_material(method, path, timestamp, nonce, status, body, expected_host)
    return hmac.new(str(key).encode(), material, hashlib.sha256).hexdigest()


def verify_response_auth(
    method: str,
    path: str,
    status: int,
    body: bytes,
    key: str,
    expected_host: str,
    *,
    timestamp: str,
    nonce: str,
    provided: str,
) -> None:
    expected = build_response_auth(
        method, path, status, body, key, expected_host, timestamp=timestamp, nonce=nonce
    )
    if not provided or not hmac.compare_digest(expected, str(provided).lower()):
        raise RuntimeError("Host agent response authentication failed.")


def _configured() -> None:
    if not SETTINGS.host_control_enabled or not SETTINGS.host_control_url or not SETTINGS.host_control_token:
        raise RuntimeError("Host VM control is not configured on this DevFleet node.")


def _url(path: str) -> str:
    _configured()
    base = SETTINGS.host_control_url.rstrip("/")
    return base + "/" + path.lstrip("/")


def _request(method: str, path: str, payload: dict[str, Any] | None = None, *, timeout: int = 30) -> dict[str, Any]:
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    raw_body = body or b""
    expected_host = str(getattr(SETTINGS, "expected_host_name", "") or "")
    request_auth = build_request_auth(method, path, raw_body, SETTINGS.host_control_token, expected_host)
    headers.update(request_auth)
    request = urllib.request.Request(_url(path), data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=max(1, int(timeout))) as response:
            response_body = response.read()
            verify_response_auth(
                method,
                path,
                int(getattr(response, "status", response.getcode())),
                response_body,
                SETTINGS.host_control_token,
                expected_host,
                timestamp=request_auth["X-DevFleet-Host-Timestamp"],
                nonce=request_auth["X-DevFleet-Host-Nonce"],
                provided=response.headers.get("X-DevFleet-Host-Response-Signature", ""),
            )
            result = json.loads(response_body.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        response_body = exc.read()
        try:
            verify_response_auth(
                method,
                path,
                int(exc.code),
                response_body,
                SETTINGS.host_control_token,
                expected_host,
                timestamp=request_auth["X-DevFleet-Host-Timestamp"],
                nonce=request_auth["X-DevFleet-Host-Nonce"],
                provided=exc.headers.get("X-DevFleet-Host-Response-Signature", ""),
            )
        except RuntimeError:
            raise
        detail = response_body.decode("utf-8", errors="replace")[-2000:]
        raise RuntimeError(f"Host agent rejected request ({exc.code}): {detail}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        raise RuntimeError(f"Host agent request failed: {exc}") from exc
    if not isinstance(result, dict) or not result.get("ok", False):
        raise RuntimeError(str(result.get("error") if isinstance(result, dict) else "Host agent returned an invalid response."))
    remote_host = str(result.get("host_name") or result.get("host_id") or "")
    if path != "/healthz" and SETTINGS.expected_host_name and remote_host.lower() != SETTINGS.expected_host_name.lower():
        raise RuntimeError(f"Host identity mismatch: expected {SETTINGS.expected_host_name}, received {remote_host}.")
    return result


def host_control_request(operation: str, payload: dict[str, Any], *, runtime_id: str = "") -> dict[str, Any]:
    """Compatibility entry point that maps intent to a fixed endpoint."""
    operation = str(operation or "").lower()
    if operation == "capacity":
        return _request("GET", "/v1/host/capacity", timeout=_ACTION_TIMEOUTS["capacity"])
    if operation == "provider":
        return _request("GET", "/v1/provider", timeout=_ACTION_TIMEOUTS["provider"])
    if operation == "ensure":
        return _request("POST", "/v1/project-vms", payload, timeout=_ACTION_TIMEOUTS["create"])
    runtime_id = runtime_id or str(payload.get("runtime_id") or "")
    if not runtime_id:
        raise ValueError("A runtime id is required for this host-agent operation.")
    encoded = urllib.parse.quote(runtime_id, safe="")
    if operation == "inspect":
        return _request("GET", f"/v1/project-vms/{encoded}", timeout=_ACTION_TIMEOUTS["inspect"])
    if operation == "destroy":
        # Keep the destructive request on the fixed action route so the
        # Windows host agent receives the JSON confirmation body reliably.
        return _request("POST", f"/v1/project-vms/{encoded}/destroy", payload, timeout=_ACTION_TIMEOUTS["destroy"])
    if operation in {"start", "stop", "restart", "health", "backup", "list-backups", "inspect-backup", "restore-backup", "quarantine", "restore", "export", "export-to-source", "restore-previous-source", "sync-ssh-alias", "refresh-connection-state", "project-start", "project-stop", "project-restart", "project-health", "project-test", "project-bootstrap", "project-rebuild", "project-logs"}:
        return _request("POST", f"/v1/project-vms/{encoded}/{operation}", payload, timeout=_ACTION_TIMEOUTS[operation])
    if operation == "import":
        return _request("POST", f"/v1/project-vms/{encoded}/import", payload, timeout=_ACTION_TIMEOUTS[operation])
    raise ValueError(f"Unsupported host-agent operation: {operation}")


def host_control_status() -> dict[str, Any]:
    if not SETTINGS.host_control_enabled or not SETTINGS.host_control_url or not SETTINGS.host_control_token:
        return {"configured": False, "reachable": False, "status": "not-configured"}
    try:
        result = _request("GET", "/healthz", timeout=5)
        return {"configured": True, "reachable": True, "status": "healthy", **result}
    except Exception as exc:
        return {"configured": True, "reachable": False, "status": "unreachable", "error": str(exc)[-500:]}


def get_host_capacity() -> dict[str, Any]:
    return host_control_request("capacity", {})


def get_provider_status() -> dict[str, Any]:
    return host_control_request("provider", {})


def ensure_project_vm(slug: str, resource_limits: dict[str, Any], *, project_id: str = "", git_url: str = "") -> dict[str, Any]:
    slug = validate_slug(slug)
    project_id = validate_project_id(project_id)
    limits = validate_resource_limits(resource_limits, runtime_type="vm")
    payload = {
        "project_id": project_id,
        "slug": slug,
        "resource_limits": limits,
        "git_url": git_url,
        "gpu": False,
        "gpu_passthrough": False,
    }
    return host_control_request("ensure", payload)


def runtime_project_vm(slug: str, operation: str, *, runtime_id: str = "", project_id: str = "") -> dict[str, Any]:
    payload = {"slug": validate_slug(slug), "project_id": project_id}
    return host_control_request(operation, payload, runtime_id=runtime_id)


def list_project_vm_backups(slug: str, *, runtime_id: str = "", project_id: str = "") -> list[dict[str, Any]]:
    result = host_control_request("list-backups", {"slug": validate_slug(slug), "project_id": validate_project_id(project_id)}, runtime_id=runtime_id)
    backups = result.get("backups")
    if not isinstance(backups, list):
        raise RuntimeError("Host agent returned an invalid backup list.")
    checked: list[dict[str, Any]] = []
    for item in backups:
        if not isinstance(item, dict):
            continue
        reference = item.get("backup_reference") or item
        checked_reference = validate_backup_reference(reference, project_id=project_id, slug=slug, runtime_id=runtime_id)
        checked.append({key: value for key, value in item.items() if key not in {"backup_path", "archive_path", "manifest_path"} and key != "backup_reference"} | {"backup_reference": checked_reference})
    return checked


def inspect_project_vm_backup(slug: str, backup_id: str, *, runtime_id: str = "", project_id: str = "") -> dict[str, Any]:
    payload = {"slug": validate_slug(slug), "project_id": validate_project_id(project_id), "backup_id": str(backup_id or "")}
    result = host_control_request("inspect-backup", payload, runtime_id=runtime_id)
    reference = validate_backup_reference((result.get("backup") or {}).get("backup_reference") or result.get("backup"), project_id=project_id, slug=slug, runtime_id=runtime_id)
    return {key: value for key, value in result.items() if key not in {"backup_path", "archive_path", "manifest_path"}} | {"backup_reference": reference}


def restore_project_vm_backup(slug: str, backup_id: str, *, confirm_restore: bool = False, runtime_id: str = "", project_id: str = "") -> dict[str, Any]:
    if not confirm_restore:
        raise ValueError("Backup restore requires explicit confirmation.")
    payload = {"slug": validate_slug(slug), "project_id": validate_project_id(project_id), "backup_id": str(backup_id or ""), "confirm_restore": True}
    return host_control_request("restore-backup", payload, runtime_id=runtime_id)


def import_project_workspace(slug: str, runtime_id: str, *, source_vm: str, project_id: str = "") -> dict[str, Any]:
    """Copy an existing workspace from the current DevFleet VM into an owned project VM."""
    slug = validate_slug(slug)
    source_vm = validate_slug(source_vm)
    project_id = validate_project_id(project_id)
    if not source_vm.startswith("devfleet-"):
        raise ValueError("Workspace imports are limited to a DevFleet source VM.")
    if not runtime_id:
        raise ValueError("A target project VM runtime id is required for workspace import.")
    payload = {"slug": slug, "project_id": project_id, "source_vm": source_vm}
    return host_control_request("import", payload, runtime_id=runtime_id)


def sync_project_vm_ssh_alias(slug: str, runtime_id: str, *, project_id: str = "") -> dict[str, Any]:
    """Create or refresh the host-owned alias for one dedicated project VM.

    The host agent derives both alias and address from its ownership registry;
    callers cannot submit SSH configuration text or an arbitrary host.
    """
    slug = validate_slug(slug)
    project_id = validate_project_id(project_id)
    if not runtime_id:
        raise ValueError("A project VM runtime id is required for SSH alias synchronization.")
    return host_control_request("sync-ssh-alias", {"slug": slug, "project_id": project_id}, runtime_id=runtime_id)


def refresh_project_vm_connection_state(slug: str, runtime_id: str, *, project_id: str = "") -> dict[str, Any]:
    """Reconcile the current owned VM address, registry, and pinned SSH alias."""
    slug = validate_slug(slug)
    project_id = validate_project_id(project_id)
    if not runtime_id:
        raise ValueError("A project VM runtime id is required for connection-state refresh.")
    return host_control_request("refresh-connection-state", {"slug": slug, "project_id": project_id}, runtime_id=runtime_id)


def export_project_workspace(slug: str, runtime_id: str, *, project_id: str = "") -> dict[str, Any]:
    slug = validate_slug(slug)
    project_id = validate_project_id(project_id)
    if not runtime_id:
        raise ValueError("A project VM runtime id is required for workspace export.")
    return host_control_request("export", {"slug": slug, "project_id": project_id}, runtime_id=runtime_id)


def export_project_workspace_to_source(slug: str, runtime_id: str, *, source_vm: str, project_id: str = "", replace_source: bool = False) -> dict[str, Any]:
    slug = validate_slug(slug)
    source_vm = validate_slug(source_vm)
    project_id = validate_project_id(project_id)
    if not source_vm.startswith("devfleet-") or not runtime_id:
        raise ValueError("VM export requires a DevFleet source VM and target runtime id.")
    return host_control_request("export-to-source", {"slug": slug, "project_id": project_id, "source_vm": source_vm, "replace_source": bool(replace_source)}, runtime_id=runtime_id)


def restore_previous_source_workspace(slug: str, runtime_id: str, *, source_vm: str, project_id: str, previous_workspace_path: str) -> dict[str, Any]:
    """Atomically reinstate the source workspace retained by a VM export."""
    slug = validate_slug(slug)
    source_vm = validate_slug(source_vm)
    project_id = validate_project_id(project_id)
    if not source_vm.startswith("devfleet-") or not runtime_id or not previous_workspace_path:
        raise ValueError("Restoring a previous source workspace requires a DevFleet source VM, runtime id, and retained path.")
    payload = {"slug": slug, "project_id": project_id, "source_vm": source_vm, "previous_workspace_path": previous_workspace_path}
    return host_control_request("restore-previous-source", payload, runtime_id=runtime_id)


def project_vm_operation(slug: str, operation: str, *, runtime_id: str = "", project_id: str = "", command_key: str = "", tail: int = 150) -> dict[str, Any]:
    slug = validate_slug(slug)
    project_id = validate_project_id(project_id)
    if operation not in {"project-start", "project-stop", "project-restart", "project-health", "project-test", "project-bootstrap", "project-rebuild", "project-logs"}:
        raise ValueError("Unsupported structured project VM operation.")
    payload: dict[str, Any] = {"slug": slug, "project_id": project_id}
    if command_key:
        payload["command_key"] = command_key
    if operation == "project-logs":
        payload["tail"] = max(1, min(int(tail), 500))
    return host_control_request(operation, payload, runtime_id=runtime_id)


def stop_project_vm(slug: str, *, runtime_id: str = "", project_id: str = "") -> dict[str, Any]:
    return runtime_project_vm(slug, "stop", runtime_id=runtime_id, project_id=project_id)


def destroy_project_vm(slug: str, confirm_slug: str, confirm_phrase: str, *, backup_verified: bool = False, backup_id: str = "", backup_sha256: str = "", cleanup_only: bool = False, cleanup_stage: str = "", local_archive_sha256: str = "", import_archive_sha256: str = "", runtime_id: str = "", project_id: str = "") -> dict[str, Any]:
    slug = validate_slug(slug)
    if confirm_slug != slug or confirm_phrase != f"DESTROY {slug}":
        raise ValueError("Permanent destruction requires the exact project slug and confirmation phrase.")
    if not cleanup_only and (not backup_id or not backup_sha256):
        raise ValueError("Permanent VM destruction requires an identified, hashed workspace backup artifact.")
    if cleanup_only:
        if not backup_verified or not backup_id:
            raise ValueError("Failed-migration cleanup requires a verified provider-aware backup identity.")
        if cleanup_stage not in {"pre-import", "post-import"}:
            raise ValueError("Failed-migration cleanup requires an explicit pre-import or post-import stage.")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", str(backup_sha256 or "")) or not re.fullmatch(r"[0-9a-fA-F]{64}", str(local_archive_sha256 or "")):
            raise ValueError("Failed-migration cleanup requires verified provider and local archive SHA-256 values.")
        if cleanup_stage == "post-import" and import_archive_sha256 and not re.fullmatch(r"[0-9a-fA-F]{64}", str(import_archive_sha256)):
            raise ValueError("Failed-migration cleanup import archive SHA-256 is malformed.")
    payload = {"slug": slug, "project_id": project_id, "confirm_slug": confirm_slug, "confirm_phrase": confirm_phrase, "backup_verified": bool(backup_verified), "backup_id": backup_id, "backup_sha256": backup_sha256, "cleanup_only": bool(cleanup_only), "cleanup_stage": cleanup_stage, "local_archive_sha256": local_archive_sha256, "import_archive_sha256": import_archive_sha256}
    return host_control_request("destroy", payload, runtime_id=runtime_id)
