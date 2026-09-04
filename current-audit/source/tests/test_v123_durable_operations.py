from __future__ import annotations

from datetime import datetime, timedelta, timezone

from devfleet import operations


def test_orphaned_running_operation_becomes_reconciliation_required():
    operation_id = "orphaned-recovery-test"
    path = operations._path(operation_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    operations.atomic_json(
        path,
        {
            "id": operation_id,
            "operation_id": operation_id,
            "state": "running",
            "idempotency_key": "orphan-key",
            "worker_instance_id": "previous-process",
            "lease_expires_at": (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat(),
        },
    )
    try:
        assert operation_id in operations.reconcile_operations()
        record = operations.get_operation(operation_id)
        assert record["state"] == "interrupted"
        assert record["recovery_required"] is True
        assert operations._find_idempotent("orphan-key") is None
    finally:
        path.unlink(missing_ok=True)


def test_live_foreign_worker_lease_is_not_interrupted():
    operation_id = "foreign-live-lease"
    operations.atomic_json(
        operations._path(operation_id),
        {
            "id": operation_id,
            "state": "running",
            "worker_instance_id": "different-worker",
            "lease_expires_at": (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat(),
        },
    )
    assert operations.reconcile_operations() == []
    assert operations.get_operation(operation_id)["state"] == "running"
    operations._path(operation_id).unlink(missing_ok=True)


def test_operation_context_refreshes_worker_lease():
    operation_id = "lease-refresh-test"
    path = operations._path(operation_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    operations.atomic_json(path, {"id": operation_id, "state": "running"})
    try:
        context = operations.OperationContext(operation_id)
        context.update(25, "still working", "test")
        record = operations.get_operation(operation_id)
        assert record["last_progress_at"]
        assert record["lease_expires_at"]
        assert record["progress"] == 25
    finally:
        path.unlink(missing_ok=True)
