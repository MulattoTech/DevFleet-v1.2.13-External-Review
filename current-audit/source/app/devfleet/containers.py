from __future__ import annotations

import json
import re
from typing import Any

from .core import SETTINGS, run, safe_child, validate_project_id, validate_slug


_CONTAINER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_ACTIONS = {
    "start": "start",
    "stop": "stop",
    "restart": "restart",
    "pause": "pause",
    "unpause": "unpause",
    "remove": "rm",
}
_IMMUTABLE_CONTAINER_ID = re.compile(r"^[0-9a-fA-F]{64}$")
OWNERSHIP_LABELS = {
    "managed_by": "io.devfleet.managed-by",
    "project_id": "io.devfleet.project-id",
    "slug": "io.devfleet.project-slug",
    "runtime_id": "io.devfleet.runtime-id",
    "deployment_id": "io.devfleet.deployment-id",
    "host_id": "io.devfleet.host-id",
}


def container_ownership_labels(metadata: dict[str, Any]) -> dict[str, str]:
    values = {
        "managed_by": str(metadata.get("managed_by") or "").strip().lower(),
        "project_id": str(metadata.get("project_id") or "").strip(),
        "slug": str(metadata.get("slug") or "").strip(),
        "runtime_id": str(metadata.get("runtime_id") or "").strip(),
        "deployment_id": str(metadata.get("deployment_id") or "").strip(),
        "host_id": str(metadata.get("host_id") or "").strip(),
    }
    if values["managed_by"] != "devfleet":
        raise ValueError("Container ownership binding is missing the DevFleet manager identity.")
    validate_project_id(values["project_id"])
    validate_slug(values["slug"])
    if any(not values[key] for key in ("runtime_id", "deployment_id", "host_id")):
        raise ValueError("Container ownership binding is incomplete.")
    return {label: values[field] for field, label in OWNERSHIP_LABELS.items()}


def _authoritative_container_binding(inspected: dict[str, Any]) -> tuple[str, dict[str, str]]:
    immutable_id = str(inspected.get("Id") or "").strip()
    if not _IMMUTABLE_CONTAINER_ID.fullmatch(immutable_id):
        raise ValueError("Container ownership verification failed: Docker returned no canonical immutable ID.")
    config = inspected.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if not isinstance(labels, dict):
        raise ValueError("Container ownership verification failed: container labels are missing.")
    slug = str(labels.get(OWNERSHIP_LABELS["slug"]) or "")
    try:
        slug = validate_slug(slug)
        project = safe_child(SETTINGS.workspaces, slug)
    except ValueError as exc:
        raise ValueError("Container ownership verification failed: project slug binding is invalid.") from exc
    metadata_path = project / ".devfleet" / "project.json"
    if project.is_symlink() or not metadata_path.is_file() or metadata_path.is_symlink():
        raise ValueError("Container ownership verification failed: authoritative project state is unavailable.")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        raise ValueError("Container ownership verification failed: authoritative project state is unreadable.") from exc
    if not isinstance(metadata, dict) or str(metadata.get("runtime_provider") or "") != "docker-compose":
        raise ValueError("Container ownership verification failed: project is not currently Compose-managed.")
    expected = container_ownership_labels(metadata)
    if expected[OWNERSHIP_LABELS["deployment_id"]] != SETTINGS.deployment_id or expected[OWNERSHIP_LABELS["host_id"]] != SETTINGS.host_id:
        raise ValueError("Container ownership verification failed: project deployment or host binding is not current.")
    mismatches = [key for key, value in expected.items() if str(labels.get(key) or "") != value]
    compose_project = str(labels.get("com.docker.compose.project") or "")
    compose_service = str(labels.get("com.docker.compose.service") or "")
    if compose_project != expected[OWNERSHIP_LABELS["runtime_id"]] or not compose_service:
        mismatches.append("com.docker.compose.project/service")
    if mismatches:
        raise ValueError("Container ownership verification failed: complete DevFleet/Compose binding does not match current project state (" + ", ".join(sorted(set(mismatches))) + ").")
    return immutable_id, expected


def validate_container_ref(value: str) -> str:
    value = str(value or "").strip()
    if not _CONTAINER_ID.fullmatch(value):
        raise ValueError("Invalid container reference.")
    return value


def _json_lines(args: list[str], timeout: int = 8) -> list[dict[str, Any]]:
    result = run(args, check=False, timeout=timeout)
    rows: list[dict[str, Any]] = []
    for line in (result.stdout or "").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _docker_inspect(ref: str) -> dict[str, Any]:
    result = run(["docker", "inspect", ref], check=False, timeout=10)
    if result.returncode:
        raise ValueError((result.stderr or "Container not found.").strip()[-1000:])
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("Docker returned invalid inspect data.") from exc
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        raise ValueError("Container not found.")
    return data[0]


def _authorized_read(ref: str) -> tuple[str, dict[str, str], dict[str, Any]]:
    """Resolve, bind, and revalidate a read before data can leave the service."""
    inspected = _docker_inspect(ref)
    immutable_id, expected = _authoritative_container_binding(inspected)
    try:
        current = _docker_inspect(immutable_id)
    except ValueError as exc:
        raise ValueError("Container ownership verification failed: immutable container disappeared before the read.") from exc
    current_id, current_expected = _authoritative_container_binding(current)
    if current_id != immutable_id or current_expected != expected:
        raise ValueError("Container ownership verification failed: immutable identity changed before the read.")
    return immutable_id, expected, current


def list_containers() -> list[dict[str, Any]]:
    """Return a safe, Portainer-style summary without exposing the Docker socket."""
    containers = _json_lines([
        "docker", "ps", "-a", "--no-trunc", "--format",
        "{{json .}}",
    ])
    stats = _json_lines([
        "docker", "stats", "--no-stream", "--format", "{{json .}}",
    ])
    stats_by_id = {str(item.get("ID") or ""): item for item in stats}
    result: list[dict[str, Any]] = []
    for item in containers:
        ref = str(item.get("ID") or "")
        if not ref:
            continue
        try:
            immutable_id, expected, inspected = _authorized_read(ref)
        except ValueError:
            # A Docker-engine container without a current authoritative DevFleet
            # binding is deliberately absent, including from metrics.
            continue
        stat = stats_by_id.get(immutable_id) or {}
        name = str(inspected.get("Name") or item.get("Names") or immutable_id[:12]).lstrip("/")
        result.append({
            "id": immutable_id,
            "short_id": immutable_id[:12],
            "name": name,
            "image": item.get("Image") or "",
            "state": item.get("State") or "unknown",
            "status": item.get("Status") or "",
            "created": item.get("CreatedAt") or "",
            "ports": item.get("Ports") or "",
            "labels": expected,
            "cpu_percent": stat.get("CPUPerc") or "—",
            "memory_usage": stat.get("MemUsage") or "—",
            "memory_percent": stat.get("MemPerc") or "—",
            "network_io": stat.get("NetIO") or "—",
            "block_io": stat.get("BlockIO") or "—",
            "pids": stat.get("PIDs") or "—",
        })
    return result


def inspect_container(ref: str) -> dict[str, Any]:
    ref = validate_container_ref(ref)
    _, _, inspected = _authorized_read(ref)
    return inspected


def container_logs(ref: str, tail: int = 200) -> str:
    ref = validate_container_ref(ref)
    tail = max(1, min(int(tail), 1000))
    immutable_id, _, _ = _authorized_read(ref)
    result = run([
        "docker", "logs", "--timestamps", "--tail", str(tail), immutable_id,
    ], check=False, timeout=15)
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    return output[-30000:] or "No container log output."


def container_action(ref: str, action: str) -> str:
    ref = validate_container_ref(ref)
    command = _ACTIONS.get(str(action or "").lower())
    if not command:
        raise ValueError("Unsupported container action.")
    inspected = _docker_inspect(ref)
    immutable_id, expected = _authoritative_container_binding(inspected)
    try:
        current = _docker_inspect(immutable_id)
    except ValueError as exc:
        raise ValueError("Container ownership verification failed: immutable container disappeared before mutation; no same-name replacement was touched.") from exc
    current_id, current_expected = _authoritative_container_binding(current)
    if current_id != immutable_id or current_expected != expected:
        raise ValueError("Container ownership verification failed: immutable identity changed before mutation.")
    result = run(["docker", command, immutable_id], check=False, timeout=60)
    if result.returncode:
        raise ValueError((result.stderr or result.stdout or "Docker action failed.").strip()[-2000:])
    return (result.stdout or result.stderr or f"Container {action} completed.").strip()[-4000:]
