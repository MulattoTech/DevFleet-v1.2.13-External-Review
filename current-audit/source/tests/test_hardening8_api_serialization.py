import threading
import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from devfleet import main, operations


def _project(tmp_path, slug="demo"):
    project = tmp_path / slug
    project.mkdir()
    return project


def _route_state(monkeypatch, tmp_path):
    _project(tmp_path)
    monkeypatch.setattr(main, "SETTINGS", replace(main.SETTINGS, workspaces=tmp_path))
    metadata = {
        "managed_by": "devfleet",
        "project_id": "12345678-1234-1234-1234-123456789abc",
        "slug": "demo",
        "runtime_id": "df_demo",
        "host_id": "test-node",
        "runtime_provider": "docker-compose",
    }
    monkeypatch.setattr(main, "load_meta", lambda _project: metadata)
    monkeypatch.setattr(main, "project_capabilities", lambda *_args: {"can_run_runtime_action": True, "status_reason": ""})
    return metadata


def test_api_mutator_is_accepted_by_durable_serializer_and_never_runs_inline(monkeypatch, tmp_path):
    metadata = _route_state(monkeypatch, tmp_path)
    submissions = []
    monkeypatch.setattr(main, "stop_project", lambda *_: pytest.fail("API mutator ran inline"))
    monkeypatch.setattr(main, "submit_operation", lambda *args, **kwargs: submissions.append((args, kwargs)) or "stop-op-1")

    response = TestClient(main.app).post(
        "/api/projects/demo/stop",
        headers={"X-DevFleet-Token": "test-token", "X-Idempotency-Key": "client-request-1"},
        json={},
    )

    assert response.status_code == 202
    assert response.json() == {
        "ok": True,
        "accepted": True,
        "operation_id": "stop-op-1",
        "operation_url": "/api/operations/stop-op-1",
    }
    args, kwargs = submissions[0]
    assert args[:2] == ("stop", "demo")
    assert kwargs["project_id"] == metadata["project_id"]
    assert kwargs["runtime_id"] == metadata["runtime_id"]
    assert kwargs["idempotency_key"].endswith(":client-request-1")


def test_read_only_api_actions_remain_synchronous(monkeypatch, tmp_path):
    _route_state(monkeypatch, tmp_path)
    monkeypatch.setattr(main, "inspect_runtime", lambda slug: {"slug": slug, "read_only": True})
    monkeypatch.setattr(main, "submit_operation", lambda *_args, **_kwargs: pytest.fail("read-only action was queued"))

    response = TestClient(main.app).post(
        "/api/projects/demo/inspect",
        headers={"X-DevFleet-Token": "test-token"},
        json={},
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True, "output": {"slug": "demo", "read_only": True}}


def test_api_project_creation_uses_the_same_durable_admission(monkeypatch):
    submissions = []
    monkeypatch.setattr(main, "create_project", lambda **_kwargs: pytest.fail("API create ran inline"))
    monkeypatch.setattr(main, "submit_operation", lambda *args, **kwargs: submissions.append((args, kwargs)) or "create-op-1")

    response = TestClient(main.app).post(
        "/api/projects/create",
        headers={"X-DevFleet-Token": "test-token"},
        json={"slug": "new-app", "idempotency_key": "create-request-1"},
    )

    assert response.status_code == 202
    assert response.json()["operation_id"] == "create-op-1"
    assert submissions[0][0][:2] == ("create", "new-app")
    assert submissions[0][1]["idempotency_key"] == "project-create:new-app:create-request-1"


def test_action_classification_is_explicit_and_closed():
    assert main.PROJECT_READ_ONLY_ACTIONS == {"inspect", "runtime-health", "logs"}
    assert {
        "start", "stop", "restart", "rebuild", "backup", "bootstrap", "health", "test",
        "codexpro", "quarantine", "destroy", "restore-vault", "restore-backup",
        "analyze-force", "reconcile-failed-migration",
    } == main.PROJECT_MUTATING_ACTIONS
    assert main.PROJECT_ACTIONS == main.PROJECT_READ_ONLY_ACTIONS | main.PROJECT_MUTATING_ACTIONS


def _wait_terminal(operation_id, timeout=3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        record = operations.get_operation(operation_id)
        if record["state"] in {"completed", "failed", "cancelled", "interrupted"}:
            return record
        time.sleep(0.01)
    raise AssertionError(f"operation {operation_id} did not become terminal")


@pytest.mark.parametrize(
    ("first_kind", "second_kind"),
    [("api-start", "api-stop"), ("api-destroy", "ui-start"), ("api-backup", "ui-start"), ("api-rebuild", "api-stop")],
)
def test_same_project_mutators_have_maximum_concurrency_one(monkeypatch, tmp_path, first_kind, second_kind):
    monkeypatch.setattr(operations, "SETTINGS", replace(operations.SETTINGS, runtime_root=tmp_path))
    started = threading.Event()
    release = threading.Event()
    active = 0
    maximum = 0
    guard = threading.Lock()

    def first(_ctx):
        nonlocal active, maximum
        with guard:
            active += 1
            maximum = max(maximum, active)
        started.set()
        release.wait(2)
        with guard:
            active -= 1
        return "first"

    def second(_ctx):
        nonlocal active, maximum
        with guard:
            active += 1
            maximum = max(maximum, active)
            active -= 1
        return "second"

    first_id = operations.submit_operation(first_kind, "demo", first)
    assert started.wait(1)
    second_id = operations.submit_operation(second_kind, "demo", second)
    release.set()
    assert _wait_terminal(first_id)["state"] == "completed"
    assert _wait_terminal(second_id)["state"] in {"completed", "failed"}
    assert maximum == 1


def test_cancelled_queued_operation_never_executes(monkeypatch, tmp_path):
    monkeypatch.setattr(operations, "SETTINGS", replace(operations.SETTINGS, runtime_root=tmp_path))
    queued = []

    class DeferredExecutor:
        def submit(self, callback):
            queued.append(callback)

    monkeypatch.setattr(operations, "_EXECUTOR", DeferredExecutor())
    ran = []
    operation_id = operations.submit_operation("api-start", "demo", lambda _ctx: ran.append(True))
    operations.update_operation(operation_id, state="cancelled", completed_at=operations.now_iso())

    queued[0]()

    assert ran == []
    assert operations.get_operation(operation_id)["state"] == "cancelled"


def test_operation_admission_backpressure_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(operations, "SETTINGS", replace(operations.SETTINGS, runtime_root=tmp_path))
    monkeypatch.setattr(operations, "_ADMISSION", threading.BoundedSemaphore(1))
    queued = []

    class DeferredExecutor:
        def submit(self, callback):
            queued.append(callback)

    monkeypatch.setattr(operations, "_EXECUTOR", DeferredExecutor())
    first = operations.submit_operation("api-start", "first", lambda _ctx: "held")
    second = operations.submit_operation("api-start", "second", lambda _ctx: pytest.fail("backpressured work ran"))

    assert operations.get_operation(first)["state"] == "queued"
    blocked = operations.get_operation(second)
    assert blocked["state"] == "failed"
    assert blocked["error"] == "operation_capacity"
    operations.update_operation(first, state="cancelled", completed_at=operations.now_iso())
    queued[0]()
