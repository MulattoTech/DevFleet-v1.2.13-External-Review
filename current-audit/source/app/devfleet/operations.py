"""Durable, bounded operation state with per-project serialization."""
from __future__ import annotations

import json
import secrets
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from .core import SETTINGS, atomic_json, now_iso


OP_ID_RE = r"^[a-z0-9][a-z0-9._-]{1,127}$"
_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="devfleet-op")
_ADMISSION = threading.BoundedSemaphore(2)
_LOCK = threading.RLock()
_ACTIVE_LOCKS: dict[str, threading.Lock] = {}
_WORKER_INSTANCE_ID = secrets.token_hex(12)
_LEASE_SECONDS = 45
_QUEUED_SECONDS = 15
_HEARTBEAT_INTERVAL_SECONDS = max(1, _LEASE_SECONDS // 3)


def _lease_until() -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=_LEASE_SECONDS)).isoformat()


def _lease_expired(value: Any) -> bool:
    if not value:
        return True
    try:
        timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return True
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp <= datetime.now(timezone.utc)


def _queued_expired(data: dict[str, Any]) -> bool:
    return _lease_expired(data.get("queued_deadline_at") or data.get("lease_expires_at"))


def reconcile_operations() -> list[str]:
    """Mark work that lost its process lease as recoverable, never as complete."""
    recovered: list[str] = []
    if not SETTINGS.operations.exists():
        return recovered
    for record_path in SETTINGS.operations.glob("*.json"):
        try:
            data = json.loads(record_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or data.get("state") not in {"queued", "running"}:
                continue
            # Worker identity is diagnostic only.  Lease expiry, not a process
            # restart or instance-id mismatch, is the authority for orphaning
            # work.  A live foreign worker must retain ownership during a
            # rolling restart.
            expired = _queued_expired(data) if data.get("state") == "queued" else _lease_expired(data.get("lease_expires_at"))
            if not expired:
                continue
            op_id = str(data.get("operation_id") or data.get("id") or record_path.stem)
            update_operation(
                op_id,
                state="interrupted",
                current_step="reconciliation-required",
                message="The previous worker stopped before this operation reached a terminal state.",
                recovery_required=True,
                worker_instance_id=None,
                lease_expires_at=None,
                reconciled_at=now_iso(),
                log="Worker lease expired or belonged to a previous process instance.",
            )
            recovered.append(op_id)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return recovered


def _path(op_id: str) -> Path:
    import re

    if not re.fullmatch(OP_ID_RE, str(op_id or "")):
        raise ValueError("Invalid operation id.")
    return SETTINGS.operations / f"{op_id}.json"


def _load(op_id: str) -> dict[str, Any]:
    path = _path(op_id)
    last_error: Exception | None = None
    for _ in range(5):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            break
        except (PermissionError, json.JSONDecodeError) as exc:
            last_error = exc
            time.sleep(0.01)
        except OSError as exc:
            raise FileNotFoundError(op_id) from exc
    else:
        raise FileNotFoundError(op_id) from last_error
    if not isinstance(data, dict):
        raise ValueError("Operation record is not an object.")
    return data


def update_operation(op_id: str, **changes: Any) -> dict[str, Any]:
    with _LOCK:
        data = _load(op_id)
        log = changes.pop("log", None)
        if log:
            data.setdefault("log", []).append({"time": now_iso(), "message": str(log)[-4000:]})
            data["log"] = data["log"][-200:]
        data.update(changes)
        data["updated_at"] = now_iso()
        atomic_json(_path(op_id), data)
        return data


def _renew_operation_lease(op_id: str) -> bool:
    """Renew only a still-running operation owned by this worker."""
    with _LOCK:
        try:
            data = _load(op_id)
        except (FileNotFoundError, ValueError):
            return False
        if data.get("state") != "running" or data.get("worker_instance_id") != _WORKER_INSTANCE_ID:
            return False
        data["lease_expires_at"] = _lease_until()
        data["heartbeat_at"] = now_iso()
        data["updated_at"] = now_iso()
        atomic_json(_path(op_id), data)
        return True


def _operation_heartbeat(op_id: str, stop: threading.Event) -> None:
    while not stop.wait(_HEARTBEAT_INTERVAL_SECONDS):
        if not _renew_operation_lease(op_id):
            return


@dataclass
class OperationContext:
    operation_id: str

    def update(self, progress: int, message: str, step: str | None = None) -> None:
        changes: dict[str, Any] = {"progress": max(0, min(100, int(progress))), "message": str(message)}
        if step:
            changes["current_step"] = step
        changes.update({"last_progress_at": now_iso(), "lease_expires_at": _lease_until()})
        update_operation(self.operation_id, **changes)

    def log(self, message: str) -> None:
        update_operation(self.operation_id, log=message)

    def set_runtime(self, runtime_id: str) -> None:
        update_operation(self.operation_id, runtime_id=runtime_id)


def _find_idempotent(key: str) -> str | None:
    if not key or not SETTINGS.operations.exists():
        return None
    for record_path in SETTINGS.operations.glob("*.json"):
        try:
            data = json.loads(record_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("idempotency_key") == key and data.get("state") in {"queued", "running"}:
            if (data.get("state") == "queued" and _queued_expired(data)) or (data.get("state") == "running" and _lease_expired(data.get("lease_expires_at"))):
                continue
            return str(data.get("id"))
    return None


def submit_operation(
    kind: str,
    project: str,
    func: Callable[[OperationContext], Any],
    *,
    project_id: str = "",
    runtime_id: str = "",
    idempotency_key: str = "",
    host_id: str | None = None,
) -> str:
    SETTINGS.operations.mkdir(parents=True, exist_ok=True)
    reconcile_operations()
    with _LOCK:
        existing = _find_idempotent(idempotency_key)
        if existing:
            return existing
        op_id = f"{kind.lower().replace('_', '-')}-{secrets.token_hex(6)}"
        record = {
            "id": op_id,
            "operation_id": op_id,
            "kind": kind,
            "operation_type": kind,
            "project": project,
            "project_id": project_id,
            "host_id": host_id or SETTINGS.host_id,
            "runtime_id": runtime_id,
            "idempotency_key": idempotency_key,
            "state": "queued",
            "current_step": "queued",
            "progress": 0,
            "message": "Queued",
            "created_at": now_iso(),
            "started_at": None,
            "updated_at": now_iso(),
            "completed_at": None,
            "log": [],
            "recovery_metadata": {"resume_policy": "reconcile-before-retry"},
            "worker_instance_id": _WORKER_INSTANCE_ID,
            "operation_generation": 1,
            "lease_expires_at": None,
            "queued_deadline_at": (datetime.now(timezone.utc) + timedelta(seconds=_QUEUED_SECONDS)).isoformat(),
            "last_progress_at": now_iso(),
            "recovery_required": False,
        }
        atomic_json(_path(op_id), record)

    if not _ADMISSION.acquire(blocking=False):
        update_operation(
            op_id,
            state="failed",
            current_step="capacity",
            message="DevFleet is busy processing the maximum number of lifecycle operations; retry shortly.",
            error="operation_capacity",
            completed_at=now_iso(),
            lease_expires_at=None,
        )
        return op_id

    lock_key = f"project:{project.lower()}" if project else f"operation:{kind.lower()}"

    def runner() -> None:
        def admit_if_still_queued() -> bool:
            with _LOCK:
                data = _load(op_id)
                if data.get("state") != "queued":
                    return False
                if _queued_expired(data):
                    update_operation(op_id, state="interrupted", current_step="reconciliation-required", message="Queued operation expired before execution capacity became available.", recovery_required=True, completed_at=now_iso(), queued_deadline_at=None)
                    return False
                return True

        if not admit_if_still_queued():
            _ADMISSION.release()
            return
        with _LOCK:
            project_lock = _ACTIVE_LOCKS.setdefault(lock_key, threading.Lock())
        acquired = project_lock.acquire(blocking=False)
        if not acquired:
            update_operation(op_id, state="failed", current_step="locked", message="Another lifecycle operation is already active for this project.", error="operation_locked")
            _ADMISSION.release()
            return
        if not admit_if_still_queued():
            project_lock.release()
            _ADMISSION.release()
            return
        heartbeat_stop = threading.Event()
        heartbeat_thread: threading.Thread | None = None
        try:
            update_operation(op_id, state="running", current_step="starting", progress=1, message="Started", started_at=now_iso(), worker_instance_id=_WORKER_INSTANCE_ID, lease_expires_at=_lease_until(), queued_deadline_at=None, last_progress_at=now_iso())
            heartbeat_thread = threading.Thread(target=_operation_heartbeat, args=(op_id, heartbeat_stop), name=f"devfleet-heartbeat-{op_id}", daemon=True)
            heartbeat_thread.start()
            result = func(OperationContext(op_id))
            update_operation(op_id, state="completed", current_step="completed", progress=100, message="Completed", result=str(result)[-12000:], completed_at=now_iso(), lease_expires_at=None, last_progress_at=now_iso())
        except Exception as exc:  # the durable record is the recovery boundary
            message=str(exc)
            update_operation(op_id, state="failed", current_step="failed", message=message, friendly_error=message, recovery_actions=["Review the operation details.", "Re-check runtime and backup status before retrying."], error=traceback.format_exc()[-12000:], completed_at=now_iso(), lease_expires_at=None, last_progress_at=now_iso())
        finally:
            heartbeat_stop.set()
            if heartbeat_thread is not None and heartbeat_thread is not threading.current_thread():
                heartbeat_thread.join(timeout=max(1, _HEARTBEAT_INTERVAL_SECONDS))
            project_lock.release()
            _ADMISSION.release()

    try:
        _EXECUTOR.submit(runner)
    except Exception:
        _ADMISSION.release()
        raise
    return op_id


def get_operation(op_id: str) -> dict[str, Any]:
    reconcile_operations()
    return _load(op_id)


def list_operations(limit: int = 50) -> list[dict[str, Any]]:
    SETTINGS.operations.mkdir(parents=True, exist_ok=True)
    reconcile_operations()
    out: list[dict[str, Any]] = []
    for path in sorted(SETTINGS.operations.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)[: max(1, min(int(limit), 200))]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                out.append(data)
        except (OSError, json.JSONDecodeError):
            continue
    return out


# Reconcile durable records when this process becomes the new operation owner.
reconcile_operations()
