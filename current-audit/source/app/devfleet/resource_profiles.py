"""Central resource profiles and host-safe allocation policy."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any

import yaml

from .core import atomic_text


_RESOURCE_POLICY_DEFAULTS = {
    "schemaVersion": 1,
    "policyVersion": "1.0.0",
    "physicalFloorMinGiB": 8.0,
    "physicalFloorPercent": 0.10,
    "commitHeadroomFloorMinGiB": 16.0,
    "commitHeadroomPercent": 0.20,
    "commitUsageLimitPercent": 80.0,
}
_RESOURCE_POLICY_PATH = Path(__file__).resolve().parents[2] / "config" / "resource-policy.json"
try:
    _RESOURCE_POLICY = {**_RESOURCE_POLICY_DEFAULTS, **json.loads(_RESOURCE_POLICY_PATH.read_text(encoding="utf-8"))}
except (OSError, ValueError, TypeError):
    _RESOURCE_POLICY = dict(_RESOURCE_POLICY_DEFAULTS)
RESOURCE_POLICY_VERSION = str(_RESOURCE_POLICY["policyVersion"])


@dataclass(frozen=True)
class ResourceProfile:
    name: str
    label: str
    cpus: float
    memory: str
    disk_gb: int
    pids: int
    rationale: str

    @property
    def vcpus(self) -> float:
        return self.cpus

    @property
    def memory_gb(self) -> float:
        return float(str(self.memory).lower().replace("gb", "").replace("g", "").strip())

    def limits(self, runtime_type: str = "container") -> dict[str, Any]:
        result = {
            "cpus": self.cpus,
            "memory": self.memory,
            "memory_gb": self.memory_gb,
            "disk_gb": self.disk_gb,
            "pids": self.pids,
        }
        if runtime_type == "vm":
            result["vcpus"] = self.vcpus
        return result


@dataclass(frozen=True)
class HostResourcePolicy:
    # Legacy fields remain for config compatibility; adaptive admission below
    # is the authoritative host-memory rule and does not use fixed reserves.
    minimum_free_memory_gb: float = 0.0
    reserved_memory_gb: float = 0.0
    reserved_logical_processors: float = 2.0
    minimum_free_disk_gb: float = 50.0
    maximum_vm_count: int = 4
    maximum_parallel_provisioning: int = 1
    max_project_cpus: float = 6.0
    max_project_memory_gb: float = 12.0
    max_project_disk_gb: float = 120.0


@dataclass(frozen=True)
class AdaptiveHostThresholds:
    physical_floor_gb: float
    commit_headroom_floor_gb: float
    commit_usage_limit_percent: float = 80.0


def adaptive_host_thresholds(usable_physical_gb: float, commit_limit_gb: float) -> AdaptiveHostThresholds:
    """Return the versioned host-admission floors used by E2E and capacity UI."""
    usable = float(usable_physical_gb)
    commit_limit = float(commit_limit_gb)
    if usable < 0 or commit_limit < 0:
        raise ValueError("Host memory values must be non-negative.")
    return AdaptiveHostThresholds(
        physical_floor_gb=max(float(_RESOURCE_POLICY["physicalFloorMinGiB"]), usable * float(_RESOURCE_POLICY["physicalFloorPercent"])),
        commit_headroom_floor_gb=max(float(_RESOURCE_POLICY["commitHeadroomFloorMinGiB"]), commit_limit * float(_RESOURCE_POLICY["commitHeadroomPercent"])),
        commit_usage_limit_percent=float(_RESOURCE_POLICY["commitUsageLimitPercent"]),
    )


def evaluate_host_memory_admission(
    *,
    usable_physical_gb: float,
    available_physical_gb: float,
    commit_limit_gb: float,
    committed_gb: float,
    projected_allocation_gb: float,
    resource_exhaustion: bool = False,
) -> dict[str, Any]:
    thresholds = adaptive_host_thresholds(usable_physical_gb, commit_limit_gb)
    projected_available = float(available_physical_gb) - float(projected_allocation_gb)
    projected_headroom = float(commit_limit_gb) - float(committed_gb) - float(projected_allocation_gb)
    commit_percent = (float(committed_gb) / float(commit_limit_gb) * 100.0) if commit_limit_gb else 100.0
    return {
        "policy_version": RESOURCE_POLICY_VERSION,
        "physical_floor_gb": round(thresholds.physical_floor_gb, 2),
        "commit_headroom_floor_gb": round(thresholds.commit_headroom_floor_gb, 2),
        "projected_available_physical_gb": round(projected_available, 2),
        "projected_commit_headroom_gb": round(projected_headroom, 2),
        "current_commit_usage_percent": round(commit_percent, 2),
        "resource_exhaustion": bool(resource_exhaustion),
        "start_safe": bool(
            projected_available >= thresholds.physical_floor_gb
            and projected_headroom >= thresholds.commit_headroom_floor_gb
            and commit_percent < thresholds.commit_usage_limit_percent
            and not resource_exhaustion
        ),
    }


def resolved_resource_metadata(
    profile_name: str,
    runtime_type: str = "container",
    *,
    actual_runtime_resources: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Keep requested profile, resolved limits, and observed runtime separate."""
    if profile_name == "custom":
        requested = dict(actual_runtime_resources or {})
    else:
        requested = resource_metadata(profile_name, runtime_type)
    resolved = dict(requested)
    actual = dict(actual_runtime_resources or {})
    drift = {
        key: {"expected": resolved.get(key), "actual": actual.get(key)}
        for key in ("cpus", "memory_gb", "disk_gb")
        if key in actual and str(actual.get(key)) != str(resolved.get(key))
    }
    return {
        "policy_version": RESOURCE_POLICY_VERSION,
        "requested_profile": profile_name,
        "requested_limits": requested,
        "resolved_resources": resolved,
        "actual_runtime_resources": actual,
        "resource_drift": drift,
        "resource_drift_status": "RESOURCE DRIFT" if drift else "MATCH",
    }


RESOURCE_PROFILES = {
    "small": ResourceProfile("small", "Light", 1.0, "2g", 20, 512, "Lightweight prototype or automation workload."),
    "standard": ResourceProfile("standard", "Standard", 2.0, "4g", 40, 768, "Normal web, API, CLI, or service development."),
    "large": ResourceProfile("large", "Performance", 4.0, "8g", 80, 1536, "Multi-service, production-like, or data-heavy development."),
    "xlarge": ResourceProfile("xlarge", "Intensive", 6.0, "12g", 120, 2048, "Heavy build or infrastructure workload; still GPU-free."),
}

RUNTIME_ISOLATIONS = {
    "container": "Project-isolated containers on the shared DevFleet host",
    "vm": "Dedicated Multipass VM (host-assisted provisioning; no GPU path)",
}

LAPTOP_PROFILE_DEFAULT = {"failover_memory_gb": 5.0, "vault_memory_gb": 2.0}
LAPTOP_PROFILE_MINIMUM_TESTED = {"failover_memory_gb": 4.0, "vault_memory_gb": 2.0}


def laptop_surrogate_profile(*, failover_memory_gb: float = 5.0, vault_memory_gb: float = 2.0) -> dict[str, float]:
    """Return the conservative tested Laptop/Surrogate memory profile."""
    failover = float(failover_memory_gb)
    vault = float(vault_memory_gb)
    if failover < LAPTOP_PROFILE_MINIMUM_TESTED["failover_memory_gb"] or vault < LAPTOP_PROFILE_MINIMUM_TESTED["vault_memory_gb"]:
        raise ValueError("Laptop/Surrogate memory is below the lowest tested stable profile.")
    return {"failover_memory_gb": failover, "vault_memory_gb": vault}


def policy_from_config(values: dict[str, Any] | None = None) -> HostResourcePolicy:
    values = values or {}
    aliases = {
        "minimum_free_memory": "minimum_free_memory_gb",
        "reserved_memory": "reserved_memory_gb",
        "reserved_logical_processors": "reserved_logical_processors",
        "minimum_free_disk": "minimum_free_disk_gb",
        "max_vm_count": "maximum_vm_count",
        "maximum_vm_count": "maximum_vm_count",
        "max_parallel_provisioning": "maximum_parallel_provisioning",
    }
    normalized = {aliases.get(k, k): v for k, v in values.items()}
    defaults = asdict(HostResourcePolicy())
    for key, default in defaults.items():
        if key in normalized:
            try:
                defaults[key] = type(default)(normalized[key])
            except (TypeError, ValueError):
                raise ValueError(f"Invalid host resource policy value: {key}")
    return HostResourcePolicy(**defaults)


def get_resource_profile(name: str) -> ResourceProfile:
    key = str(name or "").strip().lower()
    if key not in RESOURCE_PROFILES:
        raise ValueError(f"Unknown resource profile: {key}")
    return RESOURCE_PROFILES[key]


def custom_resource_metadata(values: dict[str, Any], *, runtime_type: str = "container") -> dict[str, Any]:
    """Validate dashboard-supplied limits without allowing privileged PID mode."""
    if str(values.get("pid_mode", "private") or "private").lower() != "private":
        raise ValueError("Host PID namespace is not supported by the safe DevFleet runtime policy.")
    return validate_resource_limits(values, runtime_type=runtime_type)


def validate_resource_limits(values: dict[str, Any], *, runtime_type: str = "container", policy: HostResourcePolicy | None = None) -> dict[str, Any]:
    policy = policy or HostResourcePolicy()
    try:
        cpus = float(values.get("cpus", values.get("vcpus")))
        memory_gb = float(values.get("memory_gb", str(values.get("memory", "")).lower().replace("gb", "").replace("g", "")))
        disk_gb = int(values.get("disk_gb"))
        pids = int(values.get("pids", 0))
    except (TypeError, ValueError):
        raise ValueError("Resource limits must contain numeric CPU, memory, disk, and PID values.")
    if cpus < 1 or cpus > policy.max_project_cpus:
        raise ValueError("CPU allocation is outside the host-agent policy.")
    if memory_gb < 2 or memory_gb > policy.max_project_memory_gb:
        raise ValueError("Memory allocation is outside the host-agent policy.")
    if disk_gb < 20 or disk_gb > policy.max_project_disk_gb:
        raise ValueError("Disk allocation is outside the host-agent policy.")
    if pids < 0 or pids > 4096:
        raise ValueError("PID limit is outside the host-agent policy.")
    return {
        "cpus": cpus,
        "vcpus": cpus,
        "memory_gb": memory_gb,
        "memory": f"{int(memory_gb) if memory_gb.is_integer() else memory_gb:g}g",
        "disk_gb": disk_gb,
        "pids": pids,
        "runtime_type": runtime_type,
    }


def capacity_allows(capacity: dict[str, Any], limits: dict[str, Any]) -> tuple[bool, str]:
    checks = (
        ("allocatable_cpus", float(limits.get("cpus", limits.get("vcpus", 0))), "CPU"),
        ("allocatable_memory_gb", float(limits.get("memory_gb", 0)), "memory"),
        ("allocatable_disk_gb", float(limits.get("disk_gb", 0)), "disk"),
    )
    for key, requested, label in checks:
        available = float(capacity.get(key, 0) or 0)
        if requested > available:
            return False, f"Host capacity is below the safe threshold for {label}: requested {requested:g}, available {available:g}."
    return True, "Host capacity is sufficient."


def recommend_resource_profile(*, scale: str = "", intent: str = "", project_kind: str = "", language: str = "", framework: str = "") -> ResourceProfile:
    scale = str(scale or "").lower()
    intent = str(intent or "").lower()
    kind = str(project_kind or "").lower()
    language = str(language or "").lower()
    framework = str(framework or "").lower()
    if scale == "large" or kind in {"infrastructure-service", "full-stack-web"} or "data" in kind or "spark" in framework:
        return RESOURCE_PROFILES["large"]
    if intent == "production" and (kind in {"web-frontend", "rapid-api", "full-stack-web"} or framework in {"next.js", "spring", "spring-boot", "fastapi"}):
        return RESOURCE_PROFILES["large"]
    if scale == "medium" or intent == "production" or language in {"java", "csharp", "c++", "cpp", "rust"}:
        return RESOURCE_PROFILES["standard"]
    return RESOURCE_PROFILES["small"]


def recommend_runtime_isolation(*, scale: str = "", intent: str = "", project_kind: str = "") -> str:
    if str(scale or "").lower() == "large" and str(intent or "").lower() == "production":
        return "vm"
    if str(project_kind or "").lower() == "infrastructure-service":
        return "vm"
    return "container"


def resource_metadata(name: str, runtime_type: str = "container") -> dict[str, Any]:
    profile = get_resource_profile(name)
    return {**asdict(profile), **profile.limits(runtime_type)}


def resource_override_path(project: Path) -> Path:
    return project / ".devfleet" / "runtime-resources.yaml"


def ownership_override_path(project: Path) -> Path:
    return project / ".devfleet" / "runtime-ownership.yaml"


def write_ownership_override(project: Path, compose_file: Path, labels: dict[str, str]) -> Path | None:
    try:
        document = yaml.safe_load(compose_file.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return None
    services = document.get("services") if isinstance(document, dict) else None
    if not isinstance(services, dict) or not services:
        return None
    override = {"services": {str(service): {"labels": dict(labels)} for service in services}}
    destination = ownership_override_path(project)
    atomic_text(destination, yaml.safe_dump(override, sort_keys=False))
    return destination


def write_resource_override(project: Path, compose_file: Path, profile_name: str | dict[str, Any]) -> Path | None:
    if isinstance(profile_name, dict):
        limits = custom_resource_metadata(profile_name, runtime_type="container")
    else:
        limits = get_resource_profile(profile_name).limits("container")
    try:
        document = yaml.safe_load(compose_file.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return None
    services = document.get("services") if isinstance(document, dict) else None
    if not isinstance(services, dict) or not services:
        return None
    override = {"services": {str(service): {"cpus": limits["cpus"], "mem_limit": limits["memory"], "pids_limit": limits["pids"]} for service in services}}
    destination = resource_override_path(project)
    atomic_text(destination, yaml.safe_dump(override, sort_keys=False))
    return destination
