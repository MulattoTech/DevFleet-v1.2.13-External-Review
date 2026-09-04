from pathlib import Path
from types import SimpleNamespace
import threading
import time

from devfleet import core, host_control, operations
from devfleet.resource_profiles import (
    HostResourcePolicy,
    adaptive_host_thresholds,
    capacity_allows,
    evaluate_host_memory_admission,
    get_resource_profile,
    validate_resource_limits,
)
from devfleet.runtime import ProjectRuntimeProvider, VM_PROVIDER, runtime_metadata


def test_vm_profiles_are_bounded_and_gpu_free():
    policy = HostResourcePolicy()
    for name in ("small", "standard", "large", "xlarge"):
        profile = get_resource_profile(name)
        limits = validate_resource_limits(profile.limits("vm"), runtime_type="vm", policy=policy)
        assert limits["cpus"] <= policy.max_project_cpus
        assert limits["memory_gb"] <= policy.max_project_memory_gb
        assert limits["disk_gb"] <= policy.max_project_disk_gb
        assert runtime_metadata(VM_PROVIDER, status="ready")["gpu_enabled"] is False


def test_capacity_gate_fails_closed_when_any_required_dimension_is_short():
    allowed, _ = capacity_allows({"allocatable_cpus": 2, "allocatable_memory_gb": 4, "allocatable_disk_gb": 40}, {"cpus": 2, "memory_gb": 4, "disk_gb": 40})
    blocked, reason = capacity_allows({"allocatable_cpus": 1, "allocatable_memory_gb": 4, "allocatable_disk_gb": 40}, {"cpus": 2, "memory_gb": 4, "disk_gb": 40})
    assert allowed is True
    assert blocked is False
    assert "CPU" in reason


def test_adaptive_memory_policy_uses_physical_and_commit_headroom():
    assert adaptive_host_thresholds(16, 64).physical_floor_gb == 8
    assert adaptive_host_thresholds(128, 128).physical_floor_gb == 12.8
    result = evaluate_host_memory_admission(
        usable_physical_gb=64,
        available_physical_gb=24,
        commit_limit_gb=64,
        committed_gb=36,
        projected_allocation_gb=4,
    )
    assert result["start_safe"] is True
    assert result["physical_floor_gb"] == 8
    assert result["commit_headroom_floor_gb"] == 16
    blocked = evaluate_host_memory_admission(
        usable_physical_gb=64,
        available_physical_gb=24,
        commit_limit_gb=64,
        committed_gb=50,
        projected_allocation_gb=4,
    )
    assert blocked["start_safe"] is False
    assert blocked["projected_commit_headroom_gb"] < blocked["commit_headroom_floor_gb"]


def test_adaptive_memory_policy_matrix_covers_representative_host_sizes_and_pressure():
    expected_floors = {16: 8.0, 32: 8.0, 64: 8.0, 128: 12.8}
    for installed, floor in expected_floors.items():
        assert adaptive_host_thresholds(installed, installed * 1.25).physical_floor_gb == floor

    cases = [
        ("high available low commit", dict(usable_physical_gb=64, available_physical_gb=40, commit_limit_gb=80, committed_gb=20, projected_allocation_gb=8), True),
        ("low available high commit", dict(usable_physical_gb=64, available_physical_gb=9, commit_limit_gb=80, committed_gb=65, projected_allocation_gb=8), False),
        ("adequate physical inadequate commit", dict(usable_physical_gb=64, available_physical_gb=30, commit_limit_gb=80, committed_gb=67, projected_allocation_gb=1), False),
        ("VM heavy host", dict(usable_physical_gb=32, available_physical_gb=12, commit_limit_gb=40, committed_gb=25, projected_allocation_gb=2), False),
        ("desktop heavy host", dict(usable_physical_gb=128, available_physical_gb=20, commit_limit_gb=160, committed_gb=40, projected_allocation_gb=4), True),
        ("resource exhaustion event", dict(usable_physical_gb=64, available_physical_gb=40, commit_limit_gb=80, committed_gb=20, projected_allocation_gb=4, resource_exhaustion=True), False),
    ]
    for _name, values, expected in cases:
        assert evaluate_host_memory_admission(**values)["start_safe"] is expected


def test_vm_request_is_gpu_free_and_uses_project_identity(monkeypatch):
    captured = {}

    def fake_request(operation, payload):
        captured["operation"] = operation
        captured["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(host_control, "host_control_request", fake_request)
    result = host_control.ensure_project_vm("example-project", {"cpus": 1, "memory_gb": 2, "disk_gb": 20, "pids": 512}, project_id="12345678-1234-1234-1234-123456789012")
    assert result["ok"] is True
    assert captured["operation"] == "ensure"
    assert captured["payload"]["gpu"] is False
    assert captured["payload"]["gpu_passthrough"] is False
    assert captured["payload"]["slug"] == "example-project"


def test_operation_idempotency_returns_existing_queued_operation(tmp_path, monkeypatch):
    fake_settings = SimpleNamespace(operations=tmp_path / "operations", host_id="MULATTOTECHBOX")
    monkeypatch.setattr(operations, "SETTINGS", fake_settings)
    gate = threading.Event()
    def work(ctx):
        gate.wait(2)
        return "ok"
    first = operations.submit_operation("create", "example-project", work, idempotency_key="create:example-project:v1")
    second = operations.submit_operation("create", "example-project", lambda ctx: "should-not-run", idempotency_key="create:example-project:v1")
    assert first == second
    gate.set()
    deadline = time.time() + 2
    while time.time() < deadline and operations.get_operation(first)["state"] not in {"completed", "failed"}:
        time.sleep(0.01)
    assert operations.get_operation(first)["state"] == "completed"


def test_atomic_text_retries_transient_windows_replace_denial(tmp_path, monkeypatch):
    target = tmp_path / "atomic.txt"
    original_replace = core.os.replace
    attempts = 0

    class TransientWindowsSharingError(PermissionError):
        winerror = 5

    def transient_replace(source, destination):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise TransientWindowsSharingError("transient sharing denial")
        original_replace(source, destination)

    monkeypatch.setattr(core.os, "replace", transient_replace)
    core.atomic_text(target, "complete\n")
    assert attempts == 3
    assert target.read_text(encoding="utf-8") == "complete\n"


def test_host_agent_has_narrow_authenticated_gpu_free_boundary():
    root = Path(__file__).resolve().parents[1]
    script = (root / "windows" / "DevFleet-HostAgent.ps1").read_text(encoding="utf-8")
    assert "X-DevFleet-Host-Signature" in script
    assert "SeenRequestNonces" in script
    assert "X-DevFleet-Host-Token" not in script
    assert "Global\\DevFleetHostAgent-Provisioning" in script
    assert "gpu_enabled=$false" in script
    assert "gpu_passthrough=$false" in script.lower()
    assert "Invoke-Expression" not in script
    assert "Start-Process" not in script
    assert "Restart-Computer" not in script


def test_installer_host_agent_client_uses_request_mac_not_bearer_token():
    root = Path(__file__).resolve().parents[2]
    source = (root / "installer-source" / "DevFleet.Setup" / "Services" / "InstallerLifecycle.cs").read_text(encoding="utf-8")
    assert "X-DevFleet-Host-Token" not in source
    assert "X-DevFleet-Host-Signature" in source
    assert "X-DevFleet-Host-Nonce" in source
    assert "X-DevFleet-Host-Timestamp" in source
    assert "AddRequestAuthentication" in source
