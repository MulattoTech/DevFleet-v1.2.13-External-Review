from __future__ import annotations
import base64, copy, errno, json, re, shutil, time, uuid, hashlib, tarfile, os, contextlib
from urllib.parse import quote
from pathlib import Path
from typing import Any
from .core import (
    SETTINGS,
    atomic_bytes,
    atomic_json,
    atomic_text,
    now_iso,
    run,
    safe_child,
    validate_slug,
)
from .analyzer import analyze_project, has_blockers
from .language_policy import TEMPLATES, recommend_template, template_metadata
from .caches import cache_override
from .leases import load_lease, update_lease, heartbeat_lease
from .codexpro import codexpro_status
from .resource_profiles import (
    get_resource_profile,
    resource_metadata,
    resource_override_path,
    ownership_override_path,
    recommend_resource_profile,
    recommend_runtime_isolation,
    write_resource_override,
    write_ownership_override,
    validate_resource_limits,
    custom_resource_metadata,
    capacity_allows,
    resolved_resource_metadata,
)
from .containers import container_ownership_labels
from .host_control import (
    destroy_project_vm,
    get_host_capacity,
    import_project_workspace,
    sync_project_vm_ssh_alias,
)
from .runtime import VM_RUNTIME, VmRuntimeOperations, provider_for, runtime_metadata
from .workspace_archives import (
    create_workspace_archive,
    inspect_workspace,
    restore_workspace_archive,
    validate_archive,
    write_backup_manifest,
)


class _MetadataSnapshot(dict[str, Any]):
    """Metadata mapping carrying the version observed before mutation."""

    def __init__(self, value: dict[str, Any]):
        super().__init__(value)
        self._observed = copy.deepcopy(value)

TEMPLATE_ROOT = Path("/opt/devfleet/project-templates")
GITHUB_URL_RE = re.compile(
    r"^(?:https://github\.com/[^/\s]+/[^/\s]+(?:\.git)?|git@github\.com:[^/\s]+/[^/\s]+(?:\.git)?|ssh://git@github\.com/[^/\s]+/[^/\s]+(?:\.git)?)$"
)
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
PROJECT_COMMAND_KEYS = (
    "bootstrap_command",
    "health_command",
    "test_command",
    "format_command",
    "lint_command",
    "start_command",
    "stop_command",
    "restart_command",
    "rebuild_command",
    "logs_command",
    "codexpro_command",
)
VM_LIFECYCLE_COMMAND_KEYS = (
    "start_command",
    "stop_command",
    "restart_command",
    "rebuild_command",
    "logs_command",
)
FINGERPRINT_POLICY_VERSION = 1
FINGERPRINT_ALGORITHM = "sha256-relative-path-and-bytes-v1"
IGNORED_FINGERPRINT_DIRS = {
    "node_modules", ".next", "build", "dist", ".venv", "venv",
    ".pytest_cache", "__pycache__", ".test-runtime",
}


@contextlib.contextmanager
def _destructive_lock(slug: str):
    """Serialize destructive lifecycle work across API workers/processes."""
    root = (SETTINGS.runtime_root / "lifecycle-locks").resolve()
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{validate_slug(slug)}.lock"
    handle = path.open("a+b")
    lock_kind = "none"
    try:
        if handle.seek(0, os.SEEK_END) == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            lock_kind = "fcntl"
        except ImportError:
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            lock_kind = "msvcrt"
        yield
    finally:
        if lock_kind == "fcntl":
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        elif lock_kind == "msvcrt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        handle.close()


def _source_state_fingerprint(project: Path, *, include_generated: bool = False) -> str:
    """Hash source paths and bytes, excluding only DevFleet's mutable metadata."""
    digest = hashlib.sha256()
    for current, dirs, names in os.walk(project, topdown=True, followlinks=False):
        if not include_generated:
            dirs[:] = [d for d in dirs if d not in IGNORED_FINGERPRINT_DIRS]
        dirs[:] = sorted(dirs)
        for name in sorted(names):
            path = Path(current) / name
            rel = path.relative_to(project).as_posix()
            if rel == ".devfleet/project.json":
                continue
            if path.is_symlink() or not path.is_file():
                raise ValueError(
                    f"Workspace changed to an unsupported entry during destructive preparation: {rel}"
                )
            digest.update(rel.encode())
            digest.update(b"\0")
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            digest.update(b"\0")
    return digest.hexdigest()


def _safety_backup_fields(
    result: dict[str, Any], meta: dict[str, Any]
) -> tuple[str, str, str]:
    runtime = result.get("runtime") if isinstance(result.get("runtime"), dict) else {}
    backup_id = str(
        result.get("backup_id")
        or runtime.get("backup_id")
        or meta.get("backup_id")
        or ""
    )
    backup_sha = str(
        result.get("backup_sha256")
        or runtime.get("backup_sha256")
        or meta.get("backup_sha256")
        or ""
    )
    status = str(
        result.get("backup_status")
        or runtime.get("backup_status")
        or meta.get("backup_status")
        or ""
    ).lower()
    return backup_id, backup_sha, status


def _assert_safety_binding_current(project: Path, binding: dict[str, Any]) -> None:
    """Fail closed if workspace bytes or exact project identity drifted."""
    policy = binding.get("fingerprint_policy")
    if not isinstance(policy, dict) or int(policy.get("schema_version", 0)) != FINGERPRINT_POLICY_VERSION:
        raise RuntimeError("Destructive deletion blocked: the safety fingerprint policy is missing or unsupported.")
    if policy.get("algorithm") != FINGERPRINT_ALGORITHM:
        raise RuntimeError("Destructive deletion blocked: the safety fingerprint algorithm is not recognized.")
    include_generated = bool(policy.get("include_generated"))
    expected_ignored = [] if include_generated else sorted(IGNORED_FINGERPRINT_DIRS)
    if sorted(policy.get("ignored_directories") or []) != expected_ignored:
        raise RuntimeError("Destructive deletion blocked: the recorded safety fingerprint policy is inconsistent.")
    current = _source_state_fingerprint(project, include_generated=include_generated)
    if current != str(binding.get("source_state_fingerprint") or ""):
        raise RuntimeError(
            "Destructive deletion blocked: workspace changed after the safety backup; no deletion was performed."
        )
    current_meta = load_meta(project)
    for key in ("project_id", "runtime_id"):
        expected = str(binding.get(key) or "")
        if expected and str(current_meta.get(key) or "") != expected:
            raise RuntimeError(
                f"Destructive deletion blocked: {key} changed after the safety backup; no deletion was performed."
            )


_SAFE_COMPOSE_COMMANDS = {
    "docker compose up -d --build",
    "docker compose down --remove-orphans",
    "docker compose restart",
    "docker compose build && docker compose up -d",
    "docker compose logs",
}


def metadata_path(project: Path) -> Path:
    return project / ".devfleet/project.json"


def _raw_meta(project: Path) -> dict[str, Any]:
    try:
        value = json.loads(metadata_path(project).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def load_project_for_catalog(project: Path) -> dict[str, Any]:
    """Load display metadata with recovery defaults; never grants mutation authority."""
    try:
        data = json.loads(metadata_path(project).read_text())
        data = data if isinstance(data, dict) else {}
        if not data:
            data = {}
    except Exception:
        data = {}
    runtime_isolation = str(data.get("runtime_isolation") or "container")
    runtime_type = str(data.get("runtime_type") or runtime_isolation)
    resource_profile = str(
        data.get("resource_profile") or data.get("project_scale") or "standard"
    ).lower()
    if resource_profile not in ("small", "standard", "large", "xlarge", "custom"):
        resource_profile = "standard"
    resource_limits = data.get("resource_limits")
    if not isinstance(resource_limits, dict):
        resource_limits = resource_metadata(
            resource_profile,
            runtime_type if runtime_type in ("container", "vm") else "container",
        )
    observed_resources = data.get("actual_runtime_resources") if isinstance(data.get("actual_runtime_resources"), dict) else (resource_limits if resource_profile == "custom" else None)
    resource_state = resolved_resource_metadata(
        resource_profile,
        runtime_type if runtime_type in ("container", "vm") else "container",
        actual_runtime_resources=observed_resources,
    )
    defaults = {
        "schema_version": 3,
        "project_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"devfleet:{project.name}")),
        "slug": project.name,
        "identity": project.name,
        "display_name": project.name,
        "template": "existing",
        "profile": SETTINGS.development_profile,
        "runtime_isolation": runtime_isolation,
        "runtime_type": runtime_type,
        "runtime_provider": (
            "docker-compose" if runtime_isolation != "vm" else "multipass-host-agent"
        ),
        "runtime_status": "container-ready" if runtime_isolation != "vm" else "unknown",
        "lifecycle_status": "ready",
        "provisioning_status": "ready" if runtime_isolation != "vm" else "unknown",
        "health_status": "unknown",
        "health_scope": "not-checked",
        "workspace_location": str(project),
        "host_id": SETTINGS.node_name,
        "runtime_id": "",
        "gpu_enabled": False,
        "backup_status": "not-verified",
        "quarantine_state": "active",
        "last_error": "",
        "last_operation_id": "",
        "resource_profile": resource_profile,
        "resource_limits": resource_limits,
        "requested_resource_profile": resource_state["requested_profile"],
        "resolved_resources": resource_state["resolved_resources"],
        "actual_runtime_resources": resource_state["actual_runtime_resources"],
        "resource_policy_version": resource_state["policy_version"],
        "resource_drift": resource_state["resource_drift"],
        "resource_drift_status": resource_state["resource_drift_status"],
    }
    for key, value in defaults.items():
        data.setdefault(key, value)
    return _MetadataSnapshot(data)


def load_meta(project: Path) -> dict[str, Any]:
    """Compatibility alias for read-only/catalog callers.

    Dangerous operations must call load_authoritative_project_identity_for_mutation
    instead.  Keeping this alias makes the boundary explicit at call sites while
    preserving the existing catalog API.
    """
    return load_project_for_catalog(project)


def load_authoritative_project_identity_for_mutation(
    project: Path,
    *,
    require_runtime: bool = False,
    allow_legacy_migration: bool = False,
) -> dict[str, Any]:
    """Return only a persisted DevFleet ownership record suitable for mutation.

    A directory under the workspace root is not evidence of DevFleet ownership.
    Missing, malformed, incomplete, or mismatched metadata fails closed and never
    receives the catalog loader's synthesized defaults.
    """
    project = project.resolve()
    if not project.is_dir() or project.is_symlink():
        raise ValueError("Mutation requires a real project workspace directory.")
    path = metadata_path(project)
    if not path.is_file() or path.is_symlink():
        raise ValueError(
            "Mutation denied: persisted DevFleet ownership metadata is missing."
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(
            "Mutation denied: project ownership metadata is malformed."
        ) from exc
    if not isinstance(value, dict):
        raise ValueError(
            "Mutation denied: project ownership metadata must be a JSON object."
        )
    try:
        schema = int(value.get("schema_version"))
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Mutation denied: project ownership schema/version is missing."
        ) from exc
    legacy = (
        schema == 2
        and allow_legacy_migration
        and str(value.get("managed_by") or "").strip().lower() == "devfleet"
        and str(value.get("identity") or "").strip()
        == str(value.get("slug") or "").strip()
    )
    if schema < 3 and not legacy:
        raise ValueError(
            "Mutation denied: project ownership schema/version is unsupported."
        )
    if not legacy and str(value.get("managed_by") or "").strip().lower() != "devfleet":
        raise ValueError(
            "Mutation denied: project is not explicitly marked as DevFleet-owned."
        )
    slug = str(value.get("slug") or "").strip()
    if not slug or slug != project.name or validate_slug(slug) != slug:
        raise ValueError(
            "Mutation denied: persisted project slug does not bind to the workspace path."
        )
    project_id = str(value.get("project_id") or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F-]{16,128}", project_id):
        raise ValueError(
            "Mutation denied: persisted project ID is missing or malformed."
        )
    provider = str(value.get("runtime_provider") or "").strip().lower()
    if provider not in {
        "docker-compose",
        "multipass-host-agent",
        "multipass",
        "virtualbox",
    }:
        raise ValueError(
            "Mutation denied: persisted runtime provider is missing or unsupported."
        )
    runtime_id = str(value.get("runtime_id") or "").strip()
    if require_runtime and not runtime_id:
        raise ValueError("Mutation denied: persisted runtime identity is missing.")
    if runtime_id and (
        len(runtime_id) > 128
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", runtime_id)
    ):
        raise ValueError("Mutation denied: persisted runtime identity is malformed.")
    if not str(value.get("host_id") or "").strip():
        raise ValueError(
            "Mutation denied: persisted deployment/node ownership is missing."
        )
    return _MetadataSnapshot(value)


def _commit_project_metadata(project: Path, candidate: dict[str, Any]) -> None:
    """Commit only changes made since the caller's read under the project lock."""
    project = project.resolve()
    slug = validate_slug(project.name)
    observed = getattr(candidate, "_observed", None)
    with _destructive_lock(f"metadata-{slug}"):
        latest = load_authoritative_project_identity_for_mutation(project)
        if isinstance(observed, dict):
            sentinel = object()
            for key in set(observed) | set(candidate):
                before = observed.get(key, sentinel)
                after = candidate.get(key, sentinel)
                if before == after:
                    continue
                if key in candidate:
                    latest[key] = copy.deepcopy(candidate[key])
                else:
                    latest.pop(key, None)
        else:
            latest.update(copy.deepcopy(candidate))
        latest["updated_at"] = now_iso()
        atomic_json(metadata_path(project), latest)


@contextlib.contextmanager
def project_metadata_transaction(project: Path):
    """Serialize read-modify-write metadata updates across API processes."""
    project = project.resolve()
    slug = validate_slug(project.name)
    with _destructive_lock(f"metadata-{slug}"):
        meta = load_authoritative_project_identity_for_mutation(project)
        yield meta
        meta["updated_at"] = now_iso()
        atomic_json(metadata_path(project), meta)


def workspace_readiness(
    slug: str, metadata: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Return the single readiness contract used by UI and workspace launch."""
    meta = metadata or load_meta(safe_child(SETTINGS.workspaces, slug))
    provider = provider_for(meta)
    state = str(
        meta.get("lifecycle_status") or meta.get("runtime_status") or "unknown"
    ).lower()
    path = str(meta.get("workspace_path") or f"/home/devrunner/workspaces/{slug}")
    if not provider.is_vm:
        # Container application lifecycle and code-workspace lifecycle are separate.
        # The workspace is reached through the managed primary compute SSH target;
        # stopped Compose services must not make the code workspace appear absent.
        alias = str(
            meta.get("workspace_ssh_alias")
            or meta.get("ssh_alias")
            or SETTINGS.node_name
            or "devfleet-primary"
        )
        host = str(
            meta.get("workspace_host")
            or meta.get("host_id")
            or SETTINGS.node_name
            or "devfleet-primary"
        )
        provisioned = bool(meta.get("workspace_provisioned", bool(path)))
        accessible = bool(meta.get("workspace_accessible", True))
        ready = bool(path and alias and host and provisioned and accessible)
        reason = (
            ""
            if ready
            else (
                "Container workspace is not accessible from the primary compute host."
                if not accessible
                else "Container workspace has not been provisioned."
            )
        )
        return {
            "ready": ready,
            "status": "ready" if ready else "not-ready",
            "state": state,
            "reason": reason,
            "runtime_address": host,
            "ssh_alias": alias,
            "workspace_path": path,
            "host_key_pinned": bool(
                meta.get("ssh_host_key_pinned", meta.get("host_key_pinned", False))
            ),
            "authenticated_connection": bool(
                meta.get(
                    "ssh_authenticated", meta.get("authenticated_connection", False)
                )
            ),
            "validated": ready,
            "workspace_provisioned": provisioned,
            "application_running": state == "running",
        }
    if state == "stopped":
        reason = "Not ready — VM is stopped."
    elif state in {"starting", "provisioning", "restarting", "stopping"}:
        reason = f"Waiting — VM is {state}."
    else:
        reason = "Not ready — SSH readiness is being reconciled."
    address = str(meta.get("runtime_address") or "")
    alias = str(meta.get("ssh_alias") or "")
    pinned = bool(meta.get("ssh_host_key_pinned", meta.get("host_key_pinned", False)))
    authenticated = bool(
        meta.get("ssh_authenticated", meta.get("authenticated_connection", False))
    )
    validated = bool(meta.get("ssh_validation_passed", meta.get("validated", False)))
    provisioned = bool(meta.get("workspace_provisioned", False))
    ready = state == "running" and bool(
        address and alias and pinned and authenticated and validated and provisioned
    )
    if ready:
        reason = ""
    elif (
        state == "running"
        and address
        and alias
        and pinned
        and authenticated
        and validated
        and not provisioned
    ):
        reason = "Not ready — workspace path has not been verified."
    return {
        "ready": ready,
        "status": "ready" if ready else "not-ready",
        "state": state,
        "reason": reason,
        "runtime_address": address,
        "ssh_alias": alias,
        "workspace_path": path,
        "host_key_pinned": pinned,
        "authenticated_connection": authenticated,
        "validated": validated,
        "workspace_provisioned": provisioned,
    }


def project_capabilities(
    slug: str, metadata: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Return the server-authoritative, metadata-only project availability model.

    This function must never inspect, start, or contact a runtime.  Ordinary page
    rendering uses it to decide whether a live request is allowed at all.
    """
    meta = metadata or load_meta(safe_child(SETTINGS.workspaces, slug))
    readiness = workspace_readiness(slug, meta)
    provider = provider_for(meta)
    raw_state = (
        str(meta.get("lifecycle_status") or meta.get("runtime_status") or "unknown")
        .strip()
        .lower()
    )
    aliases = {
        "ready": "running",
        "healthy": "running",
        "container-ready": "running",
        "offline": "unreachable",
        "failed": "error",
    }
    state = aliases.get(raw_state, raw_state)
    transitioning = state in {"starting", "stopping", "restarting", "provisioning"}
    running_state = state == "running"
    stopped_state = state == "stopped"
    reachable = running_state and (
        not provider.is_vm or bool(meta.get("runtime_address"))
    )
    live = bool(running_state and reachable and not transitioning)
    return {
        "lifecycle_state": state,
        "runtime_provider": provider.name,
        "runtime_reachable": reachable,
        "runtime_transitioning": transitioning,
        "ssh_ready": (
            bool(readiness.get("ready"))
            if provider.is_vm
            else bool(readiness.get("ready"))
        ),
        "application_health_available": live,
        "logs_available": live,
        "live_metrics_available": live,
        "workspace_open_available": bool(readiness.get("ready")),
        "can_start": stopped_state or state in {"error", "unreachable", "unknown"},
        "can_stop": running_state or state == "starting",
        "can_restart": live,
        "can_query_live_metrics": live,
        "can_query_application_health": live,
        "can_query_logs": live,
        "can_open_workspace": bool(readiness.get("ready")),
        "can_run_runtime_tests": live,
        "can_run_runtime_action": live,
        "status_reason": (
            "Environment stopped."
            if stopped_state
            else (
                f"Environment {state}."
                if transitioning
                else "Runtime is unreachable." if state == "unreachable" else ""
            )
        ),
    }


def _record_vm_readiness(
    meta: dict[str, Any],
    result: dict[str, Any] | None = None,
    *,
    workspace_provisioned: bool | None = None,
) -> None:
    result = result if isinstance(result, dict) else {}
    for target, source in (
        ("runtime_id", "runtime_id"),
        ("runtime_address", "address"),
        ("ssh_alias", "ssh_alias"),
    ):
        value = result.get(source)
        if value is not None and str(value):
            meta[target] = str(value)
    if "host_key_pinned" in result:
        meta["ssh_host_key_pinned"] = bool(result.get("host_key_pinned"))
    if "authenticated_connection" in result:
        meta["ssh_authenticated"] = bool(result.get("authenticated_connection"))
    if "validated" in result:
        meta["ssh_validation_passed"] = bool(result.get("validated"))
    if workspace_provisioned is not None:
        meta["workspace_provisioned"] = bool(workspace_provisioned)
    if meta.get("runtime_address"):
        meta["workspace_host"] = str(meta["runtime_address"])
    meta["workspace_readiness_checked_at"] = now_iso()
    meta["workspace_readiness"] = workspace_readiness(str(meta.get("slug") or ""), meta)


def _json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _safe_vm_command(command: str) -> bool:
    cmd = str(command or "")
    hook_allowed = bool(
        re.fullmatch(
            r"\./\.devfleet/(bootstrap|health-check|smoke-test|codexpro-bootstrap)\.sh",
            cmd,
        )
    )
    compose_allowed = cmd in _SAFE_COMPOSE_COMMANDS
    forbidden = bool(
        re.search(r"[\r\n`$<>]", cmd)
        or re.search(
            r"(?i)(^|\s)(sudo|su|shutdown|reboot|poweroff|systemctl|service|multipass)(\s|$)",
            cmd,
        )
        or re.search(r"(?i)(rm\s+-rf|docker\s+(run|exec)|curl\s+|wget\s+)", cmd)
    )
    return 0 < len(cmd) <= 512 and (hook_allowed or compose_allowed) and not forbidden


def project_command_readiness(
    project: Path, metadata: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Resolve only fixed trusted command keys for legacy project metadata.

    Explicit project values win.  A missing key may fall back first to the copied
    project template and then to the canonical package template identified by the
    project's template id.  Every resolved value must still pass the Host Agent's
    fixed command allowlist.
    """
    raw = metadata if isinstance(metadata, dict) else _raw_meta(project)
    local_template = _json_object(project / ".devfleet/template.json")
    template_id = str(raw.get("template") or local_template.get("id") or "").strip()
    canonical_template: dict[str, Any] = {}
    if template_id and re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,62}", template_id):
        candidate = TEMPLATE_ROOT / template_id / ".devfleet/template.json"
        if candidate.is_file() and not candidate.is_symlink():
            canonical_template = _json_object(candidate)
    nested = raw.get("commands") if isinstance(raw.get("commands"), dict) else {}
    resolved: dict[str, str] = {}
    sources: dict[str, str] = {}
    invalid: dict[str, str] = {}
    for key in PROJECT_COMMAND_KEYS:
        present = False
        value: Any = ""
        source = ""
        if key in raw:
            present = True
            value = raw.get(key)
            source = "project.json"
        elif key in nested:
            present = True
            value = nested.get(key)
            source = "project.json.commands"
        elif key in local_template:
            present = True
            value = local_template.get(key)
            source = "project-template"
        elif key in canonical_template:
            present = True
            value = canonical_template.get(key)
            source = f"canonical-template:{template_id}"
        if not present or value is None or not str(value).strip():
            continue
        command = str(value).strip()
        if not _safe_vm_command(command):
            invalid[key] = source or "unknown"
            continue
        resolved[key] = command
        sources[key] = source
    missing = [key for key in VM_LIFECYCLE_COMMAND_KEYS if key not in resolved]
    invalid_required = {
        key: invalid[key] for key in VM_LIFECYCLE_COMMAND_KEYS if key in invalid
    }
    return {
        "ready": not missing and not invalid_required,
        "resolved_commands": resolved,
        "sources": sources,
        "required_commands": list(VM_LIFECYCLE_COMMAND_KEYS),
        "missing_required": missing,
        "invalid_required": invalid_required,
        "invalid_commands": invalid,
        "template_id": template_id,
    }


def detect_runtime(slug: str) -> dict[str, Any]:
    project = safe_child(SETTINGS.workspaces, slug)
    if not project.is_dir():
        raise FileNotFoundError(slug)
    raw = _raw_meta(project)
    meta = load_meta(project)
    explicit = any(
        key in raw
        for key in (
            "runtime_isolation",
            "runtime_type",
            "runtime_provider",
            "resource_profile",
            "resource_limits",
        )
    )
    provider = provider_for(meta)
    return {
        "runtime_isolation": provider.runtime_type,
        "runtime_type": provider.runtime_type,
        "runtime_provider": provider.name,
        "resource_profile": str(meta.get("resource_profile") or "standard"),
        "resource_limits": meta.get("resource_limits")
        or resource_metadata(
            str(meta.get("resource_profile") or "standard"), provider.runtime_type
        ),
        "source": "metadata" if explicit else "inferred-from-existing-workspace",
        "workspace": str(project),
        "runtime_id": str(meta.get("runtime_id") or ""),
        "host_id": str(meta.get("host_id") or SETTINGS.node_name),
        "lifecycle_status": str(meta.get("lifecycle_status") or "unknown"),
        "provisioning_status": str(meta.get("provisioning_status") or "unknown"),
        "health_status": str(meta.get("health_status") or "unknown"),
    }


def project_identity(slug: str) -> str:
    project = safe_child(SETTINGS.workspaces, slug)
    if not project.is_dir():
        raise FileNotFoundError(slug)
    meta = load_meta(project)
    return validate_slug(str(meta.get("identity") or meta.get("slug") or slug))


def compose_file(project: Path) -> Path | None:
    for rel in (
        "compose.yaml",
        "compose.yml",
        ".devcontainer/compose.yaml",
        ".devcontainer/docker-compose.yml",
        "docker-compose.yml",
    ):
        p = project / rel
        if (
            p.exists()
            and not p.is_symlink()
            and p.resolve().is_relative_to(project.resolve())
        ):
            return p
    return None


def compose_name(slug: str) -> str:
    return "df_" + slug.replace(".", "_").replace("-", "_")


def compose_args(project: Path, cf: Path) -> list[str]:
    args = ["docker", "compose", "-f", str(cf)]
    override = cache_override(project, cf, load_meta(project))
    if override:
        args += ["-f", str(override)]
    ownership_override = ownership_override_path(project)
    if ownership_override.is_file():
        args += ["-f", str(ownership_override)]
    resource_override = resource_override_path(project)
    if resource_override.is_file():
        args += ["-f", str(resource_override)]
    return args + ["-p", compose_name(project.name)]


def _write_current_compose_ownership(project: Path, compose: Path, metadata: dict[str, Any]) -> Path:
    expected_runtime = compose_name(project.name)
    if str(metadata.get("runtime_id") or "") != expected_runtime:
        raise ValueError("Compose runtime identity does not match the authoritative project identity.")
    labels = container_ownership_labels(metadata)
    result = write_ownership_override(project, compose, labels)
    if result is None:
        raise ValueError("Compose services could not be read; no ownership binding was written.")
    return result


def _assert_current_compose_safety(project: Path, meta: dict[str, Any]) -> None:
    """Re-analyze current compose bytes immediately before container creation."""
    findings = analyze_project(
        project,
        str(meta.get("profile") or SETTINGS.development_profile),
        force=True,
    )
    if has_blockers(findings):
        raise ValueError(
            "Security analyzer found blocking boundary violations in the current compose configuration."
        )


def _resource_selection(
    resource_profile: str,
    resource_limits: dict[str, Any] | None,
    runtime_type: str,
    scale: str,
    intent: str,
    project_kind: str,
    language: str,
    framework: str,
) -> tuple[str, dict[str, Any]]:
    if resource_limits:
        return "custom", custom_resource_metadata(
            resource_limits, runtime_type=runtime_type
        )
    recommended = recommend_resource_profile(
        scale=scale,
        intent=intent,
        project_kind=project_kind,
        language=language,
        framework=framework,
    )
    selected = str(resource_profile or recommended.name).lower()
    if selected not in {"small", "standard", "large", "xlarge"}:
        raise ValueError("Unknown resource profile.")
    return selected, validate_resource_limits(
        resource_metadata(selected, runtime_type), runtime_type=runtime_type
    )


def running(project: Path) -> bool:
    cf = compose_file(project)
    if cf:
        return bool(
            run(
                [*compose_args(project, cf), "ps", "--status", "running", "--quiet"],
                cwd=project,
                check=False,
                timeout=30,
            ).stdout.strip()
        )
    return bool(
        run(
            [
                "docker",
                "ps",
                "--filter",
                f"label=devcontainer.local_folder={project}",
                "--format",
                "{{.ID}}",
            ],
            check=False,
            timeout=30,
        ).stdout.strip()
    )


def git_summary(project: Path) -> dict[str, Any]:
    return {
        "commit": run(
            ["git", "rev-parse", "HEAD"], cwd=project, check=False, timeout=20
        ).stdout.strip(),
        "dirty": bool(
            run(
                ["git", "status", "--porcelain"], cwd=project, check=False, timeout=20
            ).stdout.strip()
        ),
    }


def list_projects() -> list[dict[str, Any]]:
    SETTINGS.workspaces.mkdir(parents=True, exist_ok=True)
    out = []
    for p in sorted(SETTINGS.workspaces.iterdir()):
        if not p.is_dir():
            continue
        if p.is_symlink():
            out.append(
                {
                    "slug": p.name,
                    "identity": p.name,
                    "display_name": p.name,
                    "template": "unsafe-symlink",
                    "path": str(p),
                    "running": False,
                    "findings": [
                        {
                            "severity": "critical",
                            "code": "project.symlink-directory",
                            "message": "Workspace directories may not be symlinks.",
                            "file": p.name,
                        }
                    ],
                    "blockers": True,
                }
            )
            continue
        meta = load_meta(p)
        profile = str(meta.get("profile") or SETTINGS.development_profile)
        findings = analyze_project(p, profile)
        readiness = workspace_readiness(p.name, meta)
        is_running = (
            (readiness["state"] == "running")
            if provider_for(meta).is_vm
            else running(p)
        )
        lease = heartbeat_lease(p) if is_running else load_lease(p)
        capabilities = project_capabilities(
            p.name,
            {
                **meta,
                "lifecycle_status": (
                    "running" if is_running else meta.get("lifecycle_status")
                ),
            },
        )
        try:
            profile_info = get_resource_profile(
                str(meta.get("resource_profile") or "standard")
            )
        except ValueError:
            profile_info = None
        cache_path = p / ".devfleet/runtime/analyzer-cache.json"
        cache_status = {
            "enabled": SETTINGS.enable_analyzer_cache,
            "present": cache_path.is_file(),
        }
        if cache_path.is_file():
            try:
                cached = json.loads(cache_path.read_text())
                cache_status.update(
                    {
                        "profile": cached.get("profile"),
                        "fingerprint": cached.get("fingerprint"),
                        "updated_at": time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ",
                            time.gmtime(cache_path.stat().st_mtime),
                        ),
                    }
                )
            except Exception:
                cache_status["error"] = "unreadable cache"
        out.append(
            {
                **meta,
                "slug": p.name,
                "identity": str(meta.get("identity") or p.name),
                "path": str(p),
                "running": is_running,
                "lifecycle_state": capabilities["lifecycle_state"],
                "capabilities": capabilities,
                "workspace_readiness": readiness,
                "resource_profile_label": (
                    profile_info.label if profile_info else "Custom"
                ),
                "findings": findings,
                "blockers": has_blockers(findings),
                "analyzer_cache": cache_status,
                "lease": lease,
                "codexpro": codexpro_status(p),
                "git": git_summary(p),
                "docker_mode": SETTINGS.docker_mode,
            }
        )
    return out


def list_project_catalog() -> list[dict[str, Any]]:
    """Return only local metadata needed to render ordinary navigation.

    This deliberately does not run analyzer, Docker, Git, lease, or Codex probes.
    Authoritative details are refreshed by the runtime/status snapshot paths.
    """
    SETTINGS.workspaces.mkdir(parents=True, exist_ok=True)
    out = []
    for p in sorted(SETTINGS.workspaces.iterdir(), key=lambda item: item.name):
        if not p.is_dir():
            continue
        if p.is_symlink():
            out.append(
                {
                    "slug": p.name,
                    "identity": p.name,
                    "display_name": p.name,
                    "template": "unsafe-symlink",
                    "path": str(p),
                    "running": False,
                    "findings": [
                        {
                            "severity": "critical",
                            "code": "project.symlink-directory",
                            "message": "Workspace directories may not be symlinks.",
                            "file": p.name,
                        }
                    ],
                    "blockers": True,
                    "catalog_only": True,
                }
            )
            continue
        meta = load_meta(p)
        readiness = workspace_readiness(p.name, meta)
        capabilities = project_capabilities(p.name, meta)
        try:
            profile_info = get_resource_profile(
                str(meta.get("resource_profile") or "standard")
            )
        except ValueError:
            profile_info = None
        out.append(
            {
                **meta,
                "slug": p.name,
                "identity": str(meta.get("identity") or p.name),
                "display_name": str(meta.get("display_name") or p.name),
                "path": str(p),
                "running": capabilities["lifecycle_state"] == "running",
                "lifecycle_state": capabilities["lifecycle_state"],
                "capabilities": capabilities,
                "workspace_readiness": readiness,
                "resource_profile_label": (
                    profile_info.label if profile_info else "Custom"
                ),
                "findings": (
                    meta.get("findings")
                    if isinstance(meta.get("findings"), list)
                    else []
                ),
                "blockers": bool(meta.get("blockers", False)),
                "lease": (
                    meta.get("lease") if isinstance(meta.get("lease"), dict) else {}
                ),
                "git": (
                    meta.get("git")
                    if isinstance(meta.get("git"), dict)
                    else {
                        "commit": meta.get("last_known_commit", ""),
                        "dirty": meta.get("last_known_dirty"),
                    }
                ),
                "codexpro": (
                    meta.get("codexpro")
                    if isinstance(meta.get("codexpro"), dict)
                    else {}
                ),
                "docker_mode": SETTINGS.docker_mode,
                "catalog_only": True,
            }
        )
    return out


def _copy_template(project: Path, template: str) -> None:
    src = TEMPLATE_ROOT / template
    if not src.is_dir():
        raise ValueError(f"Template is not installed: {template}")
    for item in src.iterdir():
        dest = project / item.name
        if dest.exists():
            continue
        shutil.copytree(item, dest) if item.is_dir() else shutil.copy2(item, dest)


TRUSTED_TEMPLATE_HOOKS = {
    "bootstrap.sh",
    "codexpro-bootstrap.sh",
    "health-check.sh",
    "smoke-test.sh",
}


def _replace(project: Path, tokens: dict[str, str]) -> None:
    for p in project.rglob("*"):
        if (
            ".git" in p.parts
            or p.is_symlink()
            or not p.is_file()
            or p.stat().st_size >= 1_000_000
        ):
            continue
        try:
            # Keep executable bits (especially .devfleet/*.sh hooks) when replacing
            # template tokens. Path.write_text creates a new file mode from the
            # process umask, which made freshly created projects' test/bootstrap
            # scripts non-executable on Linux.
            mode = p.stat().st_mode
            text = p.read_text()
            for k, v in tokens.items():
                text = text.replace(k, v)
            p.write_text(text)
            if p.parent.name == ".devfleet" and p.name in TRUSTED_TEMPLATE_HOOKS:
                p.chmod(mode | 0o111)
            else:
                p.chmod(mode)
        except (UnicodeDecodeError, OSError):
            pass


def create_project(
    slug: str,
    display_name: str = "",
    template: str = "generic",
    git_url: str = "",
    language: str = "",
    framework: str = "",
    scale: str = "small",
    intent: str = "prototype",
    testing_level: str = "standard",
    profile: str = "",
    resource_profile: str = "",
    resource_limits: dict[str, Any] | None = None,
    runtime_isolation: str = "",
    use_ollama: bool = True,
    worktree_source: str = "",
    worktree_branch: str = "",
    project_kind: str = "",
    operation_context: Any | None = None,
) -> dict[str, Any]:
    slug = validate_slug(slug)
    project = safe_child(SETTINGS.workspaces, slug)
    if project.exists():
        raise ValueError("Project already exists.")
    selected = (profile or SETTINGS.development_profile).lower()
    if selected not in {"strict", "balanced", "fast"}:
        raise ValueError("Profile must be strict, balanced, or fast.")
    selected_isolation = (
        runtime_isolation
        or recommend_runtime_isolation(
            scale=scale, intent=intent, project_kind=project_kind
        )
    ).lower()
    if selected_isolation not in {"container", "vm"}:
        raise ValueError("Runtime isolation must be container or vm.")
    selected_resource, selected_limits = _resource_selection(
        resource_profile,
        resource_limits,
        selected_isolation,
        scale,
        intent,
        project_kind,
        language,
        framework,
    )
    if template in {"auto", "recommended", ""}:
        template = recommend_template(language, framework, scale, intent, project_kind)
    if template not in TEMPLATES:
        raise ValueError("Unknown template.")
    if git_url and not GITHUB_URL_RE.fullmatch(git_url.strip()):
        raise ValueError("Git URL must be a GitHub HTTPS or SSH repository URL.")
    if worktree_source:
        source = safe_child(SETTINGS.workspaces, worktree_source)
        if not source.is_dir() or not (source / ".git").exists():
            raise ValueError(
                "Worktree source must be an existing DevFleet Git project."
            )
        if not BRANCH_RE.fullmatch(worktree_branch):
            raise ValueError("A safe worktree branch is required.")
        # `git worktree add` creates a linked destination even when the source has a
        # normal `.git` directory.  A linked worktree cannot safely be imported into
        # a dedicated VM, so reject the combination before any scaffold or provider
        # operation is created.
        if selected_isolation == "vm":
            raise ValueError(
                "Worktree-to-VM provisioning is blocked because Git worktrees are linked repositories; use a standalone clone/import instead. No VM was created."
            )
    try:
        project.parent.mkdir(parents=True, exist_ok=True)
        project_id = str(uuid.uuid4())
        if operation_context:
            operation_context.update(12, "Project identity reserved", "validate")
        if worktree_source:
            run(
                ["git", "worktree", "add", str(project), worktree_branch],
                cwd=source,
                timeout=600,
            )
        elif git_url:
            run(["git", "clone", "--", git_url, str(project)], timeout=600)
        else:
            project.mkdir()
        _copy_template(project, template)
        tm = template_metadata(template)
        details = json.loads((project / ".devfleet/template.json").read_text())
        chosen_language = language.strip().lower() or tm["language"]
        chosen_framework = framework.strip().lower() or tm["framework"]
        display_name = (display_name or slug).strip()
        if operation_context:
            operation_context.update(28, "Project scaffold created", "scaffold")
        if len(display_name) > 100 or any(ord(c) < 32 for c in display_name):
            raise ValueError("Invalid display name.")
        _replace(
            project,
            {
                "__PROJECT_SLUG__": slug,
                "__PROJECT_NAME__": display_name,
                "__PROJECT_LANGUAGE__": chosen_language,
                "__PROJECT_FRAMEWORK__": chosen_framework,
                "__PROJECT_PROFILE__": selected,
                "__OLLAMA_BASE_URL__": SETTINGS.ollama_base_url,
                "__OLLAMA_MODEL__": SETTINGS.ollama_model,
            },
        )
        hook = project / ".devfleet/codexpro-bootstrap.sh"
        if hook.exists():
            hook.chmod(hook.stat().st_mode | 0o111)
        meta = {
            "schema_version": 5,
            "managed_by": "devfleet",
            "project_id": project_id,
            "slug": slug,
            "identity": slug,
            "display_name": display_name,
            "template": template,
            "git_url": git_url,
            "created_at": now_iso(),
            "updated_at": now_iso(),
            "node_created": SETTINGS.node_name,
            "host_id": SETTINGS.node_name,
            "deployment_id": SETTINGS.deployment_id,
            "profile": selected,
            "docker_mode": SETTINGS.docker_mode,
            "language": chosen_language,
            "framework": chosen_framework,
            "language_rationale": tm["language_rationale"],
            "template_maturity": tm["template_maturity"],
            "project_scale": scale,
            "intent": intent,
            "testing_level": testing_level,
            "resource_profile": selected_resource,
            "resource_limits": selected_limits,
            "runtime_isolation": selected_isolation,
            "runtime_type": selected_isolation,
            "runtime_provider": (
                "multipass-host-agent"
                if selected_isolation == "vm"
                else "docker-compose"
            ),
            "runtime_status": (
                "host-provisioning-required"
                if selected_isolation == "vm"
                else "container-ready"
            ),
            "lifecycle_status": "provisioning",
            "provisioning_status": "pending",
            "health_status": "unknown",
            "runtime_id": compose_name(slug) if selected_isolation == "container" else "",
            "runtime_address": "",
            "gpu_enabled": False,
            "backup_status": "not-verified",
            "quarantine_state": "active",
            "last_error": "",
            "last_operation_id": "",
            "workspace_location": str(project),
            "workspace_host": SETTINGS.node_name,
            "workspace_user": "devrunner",
            "workspace_path": f"/home/devrunner/workspaces/{slug}",
            "use_ollama": bool(use_ollama),
            "ollama_endpoint": SETTINGS.ollama_base_url if use_ollama else "",
            "ollama_model": SETTINGS.ollama_model if use_ollama else "",
            "allow_tailnet_ports": selected != "strict",
            "allow_devices": False,
            "allow_privileged": False,
            "worktree": bool(worktree_source),
            "worktree_source": worktree_source,
            "worktree_branch": worktree_branch,
            "bootstrap_command": details.get(
                "bootstrap_command", "./.devfleet/bootstrap.sh"
            ),
            "format_command": details.get("format_command", ""),
            "lint_command": details.get("lint_command", ""),
            "test_command": details.get("test_command", "./.devfleet/smoke-test.sh"),
            "health_command": details.get(
                "health_command", "./.devfleet/health-check.sh"
            ),
            "start_command": details.get("start_command", ""),
            "stop_command": details.get("stop_command", ""),
            "restart_command": details.get("restart_command", ""),
            "rebuild_command": details.get("rebuild_command", ""),
            "logs_command": details.get("logs_command", ""),
            "codexpro_command": details.get("codexpro_command", ""),
        }
        meta["ssh_alias"] = (
            "devfleet-primary"
            if selected_isolation == "container"
            else f"devfleet-project-{slug}"
        )
        atomic_json(metadata_path(project), meta)
        if operation_context:
            operation_context.update(45, "Runtime metadata persisted", "persist")
        compose = compose_file(project)
        if compose and selected_isolation == "container":
            _write_current_compose_ownership(project, compose, meta)
        if (
            compose
            and selected_isolation == "container"
            and write_resource_override(project, compose, selected_limits) is None
        ):
            raise ValueError(
                "Compose services could not be read; no resource override was written."
            )
        if not (project / ".git").exists():
            run(["git", "init"], cwd=project)
        run(["git", "add", "."], cwd=project, check=False)
        if selected_isolation == "vm":
            if operation_context:
                operation_context.update(
                    55, "Validating host capacity and creating dedicated VM", "creating"
                )
            # The local scaffold is authoritative. Provision the VM without a clone,
            # then import and verify the final scaffold so generated/template changes
            # cannot diverge from the VM workspace.
            vm_result = VmRuntimeOperations.ensure(slug, {**meta, "git_url": ""})
            runtime_id = vm_result.get("runtime_id") or vm_result.get("vm_name", "")
            imported = import_project_workspace(
                slug,
                str(runtime_id),
                source_vm=SETTINGS.node_name,
                project_id=project_id,
            )
            if (
                imported.get("ok") is False
                or imported.get("workspace_preserved") is not True
            ):
                raise RuntimeError(
                    "Host agent did not verify the new VM workspace import."
                )
            vm_result = {**vm_result, **imported}
            meta.update(
                runtime_metadata(
                    provider_for(meta),
                    status="ready",
                    runtime_id=runtime_id,
                    runtime_address=vm_result.get("address", ""),
                    provisioning_status="ready",
                    health_status="unknown",
                    health_scope="workspace-ready-not-app-healthy",
                    lifecycle_status="ready",
                )
            )
            meta["workspace_host"] = str(vm_result.get("address") or runtime_id)
            meta["updated_at"] = now_iso()
            atomic_json(metadata_path(project), meta)
            meta["ssh_alias"] = str(runtime_id)
            sync_project_vm_ssh_alias(slug, str(runtime_id), project_id=project_id)
            atomic_json(metadata_path(project), meta)
            if operation_context:
                operation_context.set_runtime(str(runtime_id))
            if operation_context:
                operation_context.update(
                    92,
                    "Dedicated VM workspace ready; application health remains unverified",
                    "verify",
                )
        else:
            meta["provisioning_status"] = "ready"
            meta["lifecycle_status"] = "ready"
            meta["health_status"] = "unknown"
            meta["health_scope"] = "not-checked"
            meta["updated_at"] = now_iso()
            atomic_json(metadata_path(project), meta)
            if operation_context:
                operation_context.update(
                    92, "Container runtime metadata finalized", "verify"
                )
            update_lease(project, active=False, clean_shutdown=True)
        return meta
    except Exception as exc:
        if (
            project.exists()
            and project.resolve().parent == SETTINGS.workspaces.resolve()
        ):
            # Preserve a failed VM workspace and metadata for reconciliation. A
            # failed host operation must never be mistaken for a clean rollback.
            meta_path = metadata_path(project)
            if selected_isolation == "vm" and meta_path.is_file():
                try:
                    failed = json.loads(meta_path.read_text(encoding="utf-8"))
                    failed.update(
                        {
                            "lifecycle_status": "failed",
                            "provisioning_status": "failed",
                            "health_status": "unknown",
                            "last_error": str(exc),
                            "updated_at": now_iso(),
                        }
                    )
                    atomic_json(meta_path, failed)
                except Exception:
                    pass
            elif worktree_source:
                run(
                    ["git", "worktree", "remove", "--force", str(project)],
                    cwd=safe_child(SETTINGS.workspaces, worktree_source),
                    check=False,
                    timeout=120,
                )
            elif project.is_dir() and selected_isolation != "vm":
                shutil.rmtree(project)
        raise


def _migration_snapshot_path(slug: str) -> Path:
    root = SETTINGS.runtime_root / "runtime-migrations"
    root.mkdir(parents=True, exist_ok=True)
    return (
        root
        / f'{validate_slug(slug)}-{time.strftime("%Y%m%d-%H%M%S")}-{uuid.uuid4().hex[:8]}.json'
    )


def _local_migration_backup(project: Path, slug: str, snapshot: Path) -> dict[str, str]:
    archive = snapshot.with_suffix(".workspace.tar.gz")
    result = create_workspace_archive(project, slug, archive)
    return {
        "path": str(archive),
        "sha256": str(result["archive_sha256"]),
        "size_bytes": str(result["archive_bytes"]),
        "files": str(result["files"]),
    }


def _restore_local_migration_backup(
    project: Path, slug: str, backup: dict[str, str]
) -> dict[str, Any]:
    archive = Path(str(backup.get("path") or ""))
    if not archive.is_file():
        raise FileNotFoundError("Migration backup archive is unavailable.")
    return restore_workspace_archive(archive, project, slug)


def assign_project_runtime(
    slug: str,
    runtime_isolation: str = "container",
    resource_profile: str = "",
    resource_limits: dict[str, Any] | None = None,
    operation_context: Any | None = None,
) -> dict[str, Any]:
    """Assign an existing workspace to a supported runtime without moving its source directory.

    The source workspace remains on the current DevFleet VM. Container assignment
    updates the existing Compose project in place. VM assignment provisions a
    project VM through the authenticated host agent, imports the source workspace
    from the current VM, and only then persists the VM runtime metadata.
    """
    slug = validate_slug(slug)
    project = safe_child(SETTINGS.workspaces, slug)
    if not project.is_dir() or project.is_symlink():
        raise ValueError("Existing project must be a safe workspace directory.")
    selected = str(runtime_isolation or "container").strip().lower()
    if selected not in {"container", "vm"}:
        raise ValueError("Environment type must be container or vm.")
    metadata_file = metadata_path(project)
    metadata_present = metadata_file.exists()
    previous_metadata_bytes = metadata_file.read_bytes() if metadata_present else b""
    if metadata_present:
        try:
            previous_raw = json.loads(metadata_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(
                "Project metadata is malformed; repair it before changing the environment."
            ) from exc
        if not isinstance(previous_raw, dict):
            raise ValueError(
                "Project metadata must be a JSON object; repair it before changing the environment."
            )
    else:
        previous_raw = {}
    previous = load_authoritative_project_identity_for_mutation(
        project, allow_legacy_migration=True
    )
    previous_provider = provider_for(previous)
    previous_running = False
    command_readiness = project_command_readiness(project, previous_raw)
    if selected == "vm" and not command_readiness["ready"]:
        details = []
        if command_readiness["missing_required"]:
            details.append(
                "missing " + ", ".join(command_readiness["missing_required"])
            )
        if command_readiness["invalid_required"]:
            details.append(
                "unsafe or unsupported "
                + ", ".join(command_readiness["invalid_required"])
            )
        raise ValueError(
            "Dedicated VM lifecycle commands are not ready: " + "; ".join(details)
        )
    if previous_provider.is_vm:
        previous_running = str(previous.get("lifecycle_status") or "") == "running"
    else:
        previous_running = running(project)
    previous_lifecycle = "running" if previous_running else "stopped"
    previous_profile = str(previous.get("resource_profile") or "standard").lower()
    if resource_limits:
        selected_profile, limits = _resource_selection(
            "",
            resource_limits,
            selected,
            str(previous.get("project_scale") or ""),
            str(previous.get("intent") or ""),
            str(previous.get("project_kind") or ""),
            str(previous.get("language") or ""),
            str(previous.get("framework") or ""),
        )
    elif (
        not resource_profile
        and previous_profile == "custom"
        and isinstance(previous.get("resource_limits"), dict)
    ):
        selected_profile = "custom"
        limits = custom_resource_metadata(
            previous["resource_limits"], runtime_type=selected
        )
    else:
        selected_profile, limits = _resource_selection(
            resource_profile or previous_profile,
            None,
            selected,
            str(previous.get("project_scale") or ""),
            str(previous.get("intent") or ""),
            str(previous.get("project_kind") or ""),
            str(previous.get("language") or ""),
            str(previous.get("framework") or ""),
        )
    if selected == "vm":
        if (
            previous_provider.is_vm
            and str(previous.get("resource_profile") or selected_profile)
            != selected_profile
        ):
            raise ValueError(
                "Dedicated VM resources are fixed after creation; keep the current profile or create a new VM environment."
            )
        capacity_result = get_host_capacity()
        capacity = (
            capacity_result.get("capacity", capacity_result)
            if isinstance(capacity_result, dict)
            else {}
        )
        allowed, reason = capacity_allows(capacity, limits)
        if not allowed:
            raise ValueError(reason)
    if (
        selected == "container"
        and previous_provider.is_vm
        and not str(previous.get("runtime_id") or "")
    ):
        raise ValueError(
            "Dedicated VM metadata has no runtime identity; export is blocked until the VM is reconciled."
        )
    compose = compose_file(project)
    if selected == "container" and compose is None:
        raise ValueError(
            "This workspace has no supported Compose configuration for a container environment."
        )
    snapshot = _migration_snapshot_path(slug)
    override_file = resource_override_path(project)
    override_present = override_file.is_file()
    override_text = (
        override_file.read_text(encoding="utf-8") if override_present else ""
    )
    lease_file = project / ".devfleet/ownership-lease.json"
    lease_present = lease_file.is_file()
    lease_text = lease_file.read_text(encoding="utf-8") if lease_present else ""
    migration = {
        "schema_version": 4,
        "slug": slug,
        "project_id": str(previous.get("project_id") or ""),
        "source_runtime": detect_runtime(slug),
        "target_runtime": {
            "runtime_isolation": selected,
            "resource_profile": selected_profile,
            "resource_limits": limits,
        },
        "workspace": str(project),
        "created_at": now_iso(),
        "state": "prepared",
        "previous_metadata": previous_raw,
        "previous_metadata_b64": (
            base64.b64encode(previous_metadata_bytes).decode("ascii")
            if metadata_present
            else ""
        ),
        "previous_resource_override": {
            "present": override_present,
            "text": override_text,
        },
        "previous_lease": {"present": lease_present, "text": lease_text},
        "previous_lifecycle": previous_lifecycle,
        "backup_status": "pending",
        "runtime_id": "",
        "fallback_runtime": previous.get("runtime_id", ""),
        "command_resolution": command_readiness,
    }
    atomic_json(snapshot, migration)
    old_runtime_id = str(previous.get("runtime_id") or "")
    new_runtime_id = ""
    stopped_for_transition = False
    local_backup: dict[str, str] = {}
    source_promoted = False
    previous_workspace_path = ""
    source_vm_started_for_export = False
    source_vm_stopped_for_transition = False
    destination_started = False
    rollback_errors: list[str] = []
    backup_result: dict[str, Any] = {}
    imported: dict[str, Any] = {}
    try:
        if operation_context:
            operation_context.update(12, "Creating a rollback snapshot", "snapshot")
        backup_result = json.loads(backup_project(slug))
        if str(backup_result.get("backup_status") or "").lower() != "verified":
            raise RuntimeError("Migration backup was not verified.")
        local_backup = _local_migration_backup(project, slug, snapshot)
        migration["backup_status"] = "verified-local-archive"
        migration["backup_result"] = backup_result
        migration["backup_artifact"] = local_backup
        migration["backup_completed_at"] = now_iso()
        atomic_json(snapshot, migration)
        if selected == "vm":
            if previous_provider.is_vm:
                candidate = {
                    **previous,
                    "resource_profile": selected_profile,
                    "resource_limits": limits,
                }
                result = {
                    "runtime_id": old_runtime_id,
                    "address": str(previous.get("runtime_address") or ""),
                    "state": "ready",
                }
            else:
                if previous_running:
                    if operation_context:
                        operation_context.update(
                            28,
                            "Stopping the old container runtime before import",
                            "source-runtime",
                        )
                    stop_project(slug)
                    stopped_for_transition = True
                # Adoption imports the existing local workspace into the new VM.  Do not
                # clone the repository first: an existing project may have uncommitted
                # work, and a pre-cloned workspace would make the import correctly refuse
                # the target as non-empty.
                candidate = {
                    **previous,
                    **command_readiness["resolved_commands"],
                    "git_url": "",
                    "runtime_isolation": "vm",
                    "runtime_type": "vm",
                    "runtime_provider": "multipass-host-agent",
                    "resource_profile": selected_profile,
                    "resource_limits": limits,
                    "runtime_status": "provisioning",
                    "lifecycle_status": "provisioning",
                    "provisioning_status": "pending",
                    "health_status": "unknown",
                    "runtime_id": "",
                    "runtime_address": "",
                    "host_id": SETTINGS.expected_host_name or SETTINGS.node_name,
                    "gpu_enabled": False,
                    "last_error": "",
                    "updated_at": now_iso(),
                }
                # Stage self-contained, trusted command metadata before import so the
                # destination can run fixed Host Agent operations. Rollback restores the
                # exact legacy bytes captured above.
                atomic_json(metadata_path(project), candidate)
                if operation_context:
                    operation_context.update(
                        42,
                        "Checking host capacity and creating the dedicated VM",
                        "provision",
                    )
                result = VmRuntimeOperations.ensure(slug, candidate)
                new_runtime_id = str(
                    result.get("runtime_id") or result.get("vm_name") or ""
                )
                if not new_runtime_id:
                    raise RuntimeError("Host agent created no runtime identity.")
                if operation_context:
                    operation_context.set_runtime(new_runtime_id)
                if operation_context:
                    operation_context.update(
                        72,
                        "Importing the existing workspace into the dedicated VM",
                        "workspace-import",
                    )
                imported = import_project_workspace(
                    slug,
                    new_runtime_id,
                    source_vm=SETTINGS.node_name,
                    project_id=str(candidate.get("project_id") or ""),
                )
                if (
                    imported.get("ok") is False
                    or imported.get("workspace_preserved") is not True
                ):
                    raise RuntimeError(
                        "Host agent did not verify the imported workspace."
                    )
                if (
                    imported.get("source_archive_sha256")
                    and imported.get("target_archive_sha256")
                    and imported["source_archive_sha256"]
                    != imported["target_archive_sha256"]
                ):
                    raise RuntimeError(
                        "Imported workspace archive hashes do not match."
                    )
                migration["import_verified"] = True
                migration["import_result"] = imported
                atomic_json(snapshot, migration)
                result = {**result, **imported}
                candidate.update(
                    runtime_metadata(
                        provider_for(candidate),
                        status="ready" if previous_running else "stopped",
                        runtime_id=str(
                            result.get("runtime_id") or old_runtime_id or new_runtime_id
                        ),
                        runtime_address=str(
                            result.get("address")
                            or previous.get("runtime_address")
                            or ""
                        ),
                        provisioning_status="ready",
                        health_status="unknown",
                        lifecycle_status="ready" if previous_running else "stopped",
                    )
                )
                candidate["health_scope"] = (
                    "workspace-ready-not-app-healthy"
                    if previous_running
                    else "not-checked-stopped"
                )
                candidate["resource_profile"] = selected_profile
                candidate["resource_limits"] = limits
                candidate["ssh_alias"] = (
                    str(candidate.get("runtime_id") or "devfleet-primary")
                    if selected == "vm"
                    else "devfleet-primary"
                )
                candidate["previous_runtime"] = {
                    "runtime_provider": previous_provider.name,
                    "runtime_type": previous_provider.runtime_type,
                    "runtime_id": old_runtime_id,
                    "was_running": previous_running,
                }
                candidate["runtime_migration_snapshot"] = str(snapshot)
                candidate["updated_at"] = now_iso()
                candidate["last_error"] = ""
                if selected == "vm":
                    sync_project_vm_ssh_alias(
                        slug,
                        str(candidate.get("runtime_id") or ""),
                        project_id=str(candidate.get("project_id") or ""),
                    )
                atomic_json(metadata_path(project), candidate)
        else:
            if previous_provider.is_vm:
                if operation_context:
                    operation_context.update(
                        42,
                        "Exporting the verified VM workspace back to the source VM",
                        "vm-export",
                    )
                if not previous_running:
                    VmRuntimeOperations.start(slug, previous)
                    source_vm_started_for_export = True
                exported = VM_RUNTIME.export_to_source(
                    slug, previous, source_vm=SETTINGS.node_name, replace_source=True
                )
                migration["vm_export"] = exported
                source_promoted = bool(
                    exported.get("state") == "verified"
                    and exported.get("workspace_path")
                )
                previous_workspace_path = str(
                    exported.get("previous_workspace_path") or ""
                )
                migration["source_promoted"] = source_promoted
                migration["previous_workspace_path"] = previous_workspace_path
                atomic_json(snapshot, migration)
                if operation_context:
                    operation_context.update(
                        58,
                        "Stopping the old dedicated VM after verified export",
                        "source-runtime",
                    )
                stop_project(slug)
                source_vm_stopped_for_transition = True
                # The host agent has promoted the VM copy to the canonical source path.
                project = safe_child(SETTINGS.workspaces, slug)
                previous = load_meta(project)
                compose = compose_file(project)
                if compose is None:
                    raise ValueError(
                        "The exported VM workspace has no supported Compose configuration."
                    )
            if operation_context:
                operation_context.update(
                    68,
                    "Applying the selected container resources to the existing Compose project",
                    "container-runtime",
                )
            override = write_resource_override(project, compose, limits)
            if override is None:
                raise ValueError(
                    "Compose services could not be read; no container resource override was written."
                )
            fallback = {
                "runtime_provider": previous_provider.name,
                "runtime_type": previous_provider.runtime_type,
                "runtime_id": old_runtime_id,
                "runtime_address": str(previous.get("runtime_address") or ""),
                "was_running": previous_running,
                "lifecycle_status": previous_lifecycle,
                "workspace_path": (
                    str(exported.get("workspace_path") or "")
                    if previous_provider.is_vm
                    else str(project)
                ),
                "previous_workspace_path": previous_workspace_path,
            }
            candidate = {
                **previous,
                "runtime_isolation": "container",
                "runtime_type": "container",
                "runtime_provider": "docker-compose",
                "runtime_status": "container-ready" if previous_running else "stopped",
                "lifecycle_status": "ready" if previous_running else "stopped",
                "provisioning_status": "ready",
                "health_status": "unknown",
                "health_scope": (
                    "not-checked" if previous_running else "not-checked-stopped"
                ),
                "resource_profile": selected_profile,
                "resource_limits": limits,
                "runtime_id": "",
                "runtime_address": "",
                "host_id": SETTINGS.node_name,
                "gpu_enabled": False,
                "runtime_migration_snapshot": str(snapshot),
                "previous_environment": fallback,
                "last_error": "",
                "updated_at": now_iso(),
            }
            if (
                previous_running
                and str(previous.get("resource_profile") or previous_profile)
                != selected_profile
            ):
                candidate["runtime_status"] = "restart-required"
            atomic_json(metadata_path(project), candidate)
        if previous_running:
            if operation_context:
                operation_context.update(
                    78,
                    "Starting and checking the destination runtime",
                    "destination-start",
                )
            start_project(slug)
            destination_started = True
            runtime_check = runtime_health(slug)
            if not bool(runtime_check.get("ok", runtime_check.get("healthy", False))):
                raise RuntimeError(
                    f"Destination runtime health check failed: {runtime_check}"
                )
            app_output = health_project(slug)
            candidate = load_meta(project)
            if str(candidate.get("health_status") or "") != "healthy":
                raise RuntimeError("Destination application health was not verified.")
            destination_health = "healthy"
        else:
            if selected == "vm":
                # The destination application was never started. Preserve a stopped
                # source lifecycle by stopping only the VM, not by requiring an
                # application stop command that had no services to stop.
                VmRuntimeOperations.stop(slug, candidate)
            candidate = load_meta(project)
            candidate.update(
                {
                    "lifecycle_status": "stopped",
                    "runtime_status": "stopped",
                    "health_status": "unknown",
                    "health_scope": "not-checked-stopped",
                    "updated_at": now_iso(),
                }
            )
            atomic_json(metadata_path(project), candidate)
            update_lease(project, active=False, clean_shutdown=True)
            runtime_check = {
                "ok": True,
                "healthy": False,
                "state": "stopped",
                "preserved_previous_lifecycle": True,
            }
            app_output = "Destination intentionally left stopped to preserve the prior lifecycle state."
            destination_health = "not-run-stopped"
        migration["state"] = "verified"
        migration["destination_runtime"] = runtime_check
        migration["destination_application_health"] = destination_health
        migration["destination_started"] = destination_started
        migration["runtime_id"] = str(
            new_runtime_id or old_runtime_id or candidate.get("runtime_id") or ""
        )
        atomic_json(snapshot, migration)
        migration["state"] = "completed"
        migration["completed_at"] = now_iso()
        atomic_json(snapshot, migration)
        if operation_context:
            operation_context.update(94, "Environment assignment verified", "verify")
        return {
            "ok": True,
            "project": candidate,
            "migration_snapshot": str(snapshot),
            "backup_status": "verified",
            "workspace_preserved": True,
            "runtime": (
                result
                if selected == "vm"
                else {
                    "provider": "docker-compose",
                    "resource_override": str(resource_override_path(project)),
                }
            ),
            "runtime_health": runtime_check,
            "application_health": destination_health,
            "application_health_output": (
                app_output[-2000:]
                if isinstance(app_output, str)
                else str(app_output)[-2000:]
            ),
        }
    except Exception as exc:
        migration["state"] = "rollback-required"
        migration["error"] = str(exc)
        migration["failed_at"] = now_iso()
        migration["runtime_id"] = str(new_runtime_id)
        atomic_json(snapshot, migration)
        # A VM retained after a failed migration is a first-class fallback.  It is
        # never silently deleted when the previous environment was a VM.
        if new_runtime_id and not previous_provider.is_vm:
            try:
                cleanup_hash = str(local_backup.get("sha256") or "")
                destroy_project_vm(
                    slug,
                    slug,
                    f"DESTROY {slug}",
                    backup_verified=True,
                    backup_id=str(backup_result.get("backup_id") or f"cleanup-{slug}"),
                    backup_sha256=str(backup_result.get("backup_sha256") or ""),
                    cleanup_only=True,
                    cleanup_stage=(
                        "post-import"
                        if imported.get("workspace_preserved") is True
                        else "pre-import"
                    ),
                    local_archive_sha256=cleanup_hash,
                    import_archive_sha256=str(
                        imported.get("archive_sha256")
                        or imported.get("source_archive_sha256")
                        or ""
                    ),
                    runtime_id=new_runtime_id,
                    project_id=str(previous.get("project_id") or ""),
                )
                migration["cleanup"] = (
                    "partially-created VM removed after import failure"
                )
            except Exception as cleanup_exc:
                migration["cleanup_required"] = True
                migration["cleanup_error"] = str(cleanup_exc)
                migration["cleanup_note"] = (
                    "Dedicated VM preserved for explicit host-agent reconciliation after migration failure."
                )
                rollback_errors.append(f"cleanup: {cleanup_exc}")
        if source_promoted:
            try:
                if previous_workspace_path:
                    restored = VM_RUNTIME.restore_previous_source(
                        slug,
                        previous,
                        source_vm=SETTINGS.node_name,
                        previous_workspace_path=previous_workspace_path,
                    )
                    if str(restored.get("state") or "") != "restored":
                        raise RuntimeError(
                            "Host agent did not confirm atomic previous-workspace restoration."
                        )
                    migration["workspace_restored"] = True
                    migration["previous_workspace_consumed"] = True
                    migration["previous_workspace_restore"] = restored
                else:
                    _restore_local_migration_backup(project, slug, local_backup)
                    migration["workspace_restored"] = True
                    migration["workspace_restore_fallback"] = (
                        "local-archive-no-previous-path"
                    )
            except Exception as restore_workspace_exc:
                rollback_errors.append(f"workspace: {restore_workspace_exc}")
        try:
            if metadata_present:
                atomic_bytes(metadata_path(project), previous_metadata_bytes)
            elif metadata_path(project).exists():
                metadata_path(project).unlink()
        except Exception as metadata_restore_exc:
            rollback_errors.append(f"metadata: {metadata_restore_exc}")
        try:
            if override_present:
                atomic_text(override_file, override_text)
            elif override_file.exists():
                override_file.unlink()
        except Exception as override_restore_exc:
            rollback_errors.append(f"override: {override_restore_exc}")
        try:
            if lease_present:
                atomic_text(lease_file, lease_text)
            elif lease_file.exists():
                lease_file.unlink()
        except Exception as lease_restore_exc:
            rollback_errors.append(f"lease: {lease_restore_exc}")
        if (
            stopped_for_transition
            or source_vm_stopped_for_transition
            or source_vm_started_for_export
        ):
            try:
                if previous_running:
                    start_project(slug)
                elif previous_provider.is_vm and source_vm_started_for_export:
                    stop_project(slug)
            except Exception as restore_exc:
                rollback_errors.append(f"runtime: {restore_exc}")
        if rollback_errors:
            migration["state"] = "rollback-incomplete"
            migration["rollback_errors"] = rollback_errors
            migration["failure_state"] = {
                "previous_lifecycle": previous_lifecycle,
                "destination_started": destination_started,
                "source_promoted": source_promoted,
                "requires_reconciliation": True,
            }
        else:
            migration["state"] = "rolled-back"
            migration["rollback_completed_at"] = now_iso()
        atomic_json(snapshot, migration)
        raise


def _verified_sha256(path: Path, expected: str) -> str:
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError(f"Recovery artifact is unavailable: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if (
        not re.fullmatch(r"[0-9a-f]{64}", str(expected or ""))
        or actual != str(expected).lower()
    ):
        raise ValueError(f"Recovery artifact SHA-256 mismatch: {path}")
    return actual


def reconcile_failed_migration(
    slug: str, migration_snapshot: str, confirm_phrase: str = ""
) -> dict[str, Any]:
    """Reconcile one known rollback-incomplete container-to-VM transaction."""
    slug = validate_slug(slug)
    if confirm_phrase != f"RECONCILE {slug}":
        raise ValueError(
            "Failed-migration reconciliation requires the exact project confirmation phrase."
        )
    root = (SETTINGS.runtime_root / "runtime-migrations").resolve()
    snapshot = Path(str(migration_snapshot or "")).resolve()
    if (
        not snapshot.is_relative_to(root)
        or snapshot.parent != root
        or not re.fullmatch(
            rf"{re.escape(slug)}-[0-9]{{8}}-[0-9]{{6}}-[0-9a-f]{{8}}\.json",
            snapshot.name,
        )
    ):
        raise ValueError(
            "Migration snapshot path is outside the managed runtime-migrations directory."
        )
    data = _json_object(snapshot)
    if data.get("state") != "rollback-incomplete" or not data.get("cleanup_required"):
        raise ValueError(
            "Only a cleanup-required rollback-incomplete migration may be reconciled."
        )
    if str(data.get("slug") or "") != slug:
        raise ValueError(
            "Migration snapshot slug does not match the requested project."
        )
    project = safe_child(SETTINGS.workspaces, slug)
    meta = load_authoritative_project_identity_for_mutation(project)
    if provider_for(meta).is_vm:
        raise ValueError(
            "Source project metadata was not restored to the container environment."
        )
    if running(project):
        raise ValueError(
            "Source container must remain stopped during failed-migration reconciliation."
        )
    runtime_id = str(data.get("runtime_id") or "")
    expected_runtime = f"devfleet-project-{slug}"
    if runtime_id != expected_runtime:
        raise ValueError(
            "Migration snapshot runtime identity is not the deterministic project VM name."
        )
    backup = (
        data.get("backup_result") if isinstance(data.get("backup_result"), dict) else {}
    )
    local = (
        data.get("backup_artifact")
        if isinstance(data.get("backup_artifact"), dict)
        else {}
    )
    if str(backup.get("backup_status") or "").lower() != "verified":
        raise ValueError(
            "Migration snapshot does not contain a verified provider-aware backup."
        )
    provider_sha = _verified_sha256(
        Path(str(backup.get("backup_path") or "")),
        str(backup.get("backup_sha256") or ""),
    )
    local_sha = _verified_sha256(
        Path(str(local.get("path") or "")), str(local.get("sha256") or "")
    )
    result = destroy_project_vm(
        slug,
        slug,
        f"DESTROY {slug}",
        backup_verified=True,
        backup_id=str(backup.get("backup_id") or ""),
        backup_sha256=provider_sha,
        cleanup_only=True,
        cleanup_stage="post-import",
        local_archive_sha256=local_sha,
        import_archive_sha256=str(
            (data.get("import_result") or {}).get("archive_sha256") or ""
        ),
        runtime_id=runtime_id,
        project_id=str(data.get("project_id") or meta.get("project_id") or ""),
    )
    reconciliation = {
        "schema_version": 1,
        "slug": slug,
        "project_id": str(data.get("project_id") or meta.get("project_id") or ""),
        "runtime_id": runtime_id,
        "original_snapshot": str(snapshot),
        "original_snapshot_state": str(data.get("state")),
        "state": "reconciled",
        "reconciled_at": now_iso(),
        "backup_id": str(backup.get("backup_id") or ""),
        "provider_backup_sha256": provider_sha,
        "local_archive_sha256": local_sha,
        "host_cleanup": result,
        "source_environment": detect_runtime(slug),
    }
    record = snapshot.with_suffix(".reconciliation.json")
    atomic_json(record, reconciliation)
    return {
        "ok": True,
        "state": "reconciled",
        "reconciliation_record": str(record),
        "original_snapshot_preserved": True,
        "runtime_id": runtime_id,
        "cleanup": result,
        "source_environment": reconciliation["source_environment"],
    }


def _hook(project: Path, cf: Path | None) -> str:
    hook = project / ".devfleet/codexpro-bootstrap.sh"
    if not SETTINGS.auto_start_codexpro or not hook.exists():
        return "CodexPro auto-bootstrap disabled or hook absent."
    command = (
        "test -f ./.devfleet/codexpro-bootstrap.sh && ./.devfleet/codexpro-bootstrap.sh"
    )
    if cf:
        services = run(
            [*compose_args(project, cf), "config", "--services"],
            cwd=project,
            check=False,
        ).stdout.split()
        if services:
            return (
                run(
                    [
                        *compose_args(project, cf),
                        "exec",
                        "-T",
                        services[0],
                        "sh",
                        "-lc",
                        command,
                    ],
                    cwd=project,
                    check=False,
                    timeout=900,
                ).stdout
                or ""
            )[-4000:]
    ids = run(
        [
            "docker",
            "ps",
            "-q",
            "--filter",
            f"label=devcontainer.local_folder={project}",
        ],
        check=False,
    ).stdout.split()
    return (
        (
            run(
                ["docker", "exec", ids[0], "sh", "-lc", command],
                check=False,
                timeout=900,
            ).stdout
            or ""
        )[-4000:]
        if ids
        else "No running container."
    )


def start_project(slug: str, override_failover: bool = False) -> str:
    project = safe_child(SETTINGS.workspaces, slug)
    meta = load_meta(project)
    _assert_current_compose_safety(project, meta)
    if provider_for(meta).is_vm:
        meta.update(
            {
                "lifecycle_status": "starting",
                "runtime_status": "starting",
                "health_scope": "transition",
                "last_error": "",
                "workspace_provisioned": False,
                "updated_at": now_iso(),
            }
        )
        atomic_json(metadata_path(project), meta)
        try:
            result = VmRuntimeOperations.start(slug, meta)
            meta.update(
                runtime_metadata(
                    provider_for(meta),
                    status="starting",
                    runtime_id=result.get("runtime_id")
                    or result.get("vm_name", meta.get("runtime_id", "")),
                    runtime_address=result.get(
                        "address", meta.get("runtime_address", "")
                    ),
                    provisioning_status="ready",
                    health_status="unknown",
                    health_scope="runtime-ready-not-app-healthy",
                    lifecycle_status="starting",
                )
            )
            _record_vm_readiness(meta, result, workspace_provisioned=False)
            project_result = VM_RUNTIME.command(
                slug, meta, "project-start", command_key="start"
            )
            meta.update(
                {
                    "lifecycle_status": "running",
                    "runtime_status": "running",
                    "health_status": "unknown",
                    "health_scope": "runtime-ready-not-app-healthy",
                    "updated_at": now_iso(),
                }
            )
            _record_vm_readiness(meta, result, workspace_provisioned=True)
            atomic_json(metadata_path(project), meta)
            update_lease(project, active=True)
            return str(
                project_result.get("output")
                or result.get(
                    "message", "Dedicated project VM and project services started."
                )
            )
        except Exception as exc:
            meta.update(
                {
                    "lifecycle_status": "failed",
                    "runtime_status": "failed",
                    "health_status": "unknown",
                    "health_scope": "not-ready",
                    "last_error": str(exc)[-1000:],
                    "updated_at": now_iso(),
                }
            )
            atomic_json(metadata_path(project), meta)
            raise
    cf = compose_file(project)
    if cf:
        _assert_current_compose_safety(project, meta)
        _write_current_compose_ownership(project, cf, meta)
        r = run(
            [*compose_args(project, cf), "up", "-d", "--build"],
            cwd=project,
            timeout=1800,
        )
    elif (project / ".devcontainer/devcontainer.json").exists():
        r = run(
            ["devcontainer", "up", "--workspace-folder", str(project)],
            cwd=project,
            timeout=1800,
        )
    else:
        raise ValueError("No supported container configuration.")
    meta["lifecycle_status"] = "running"
    meta["runtime_status"] = "running"
    meta["updated_at"] = now_iso()
    atomic_json(metadata_path(project), meta)
    update_lease(project, active=True)
    return ((r.stdout + r.stderr) + "\n" + _hook(project, cf))[-12000:]


def stop_project(slug: str) -> str:
    project = safe_child(SETTINGS.workspaces, slug)
    meta = load_meta(project)
    if provider_for(meta).is_vm:
        meta.update(
            {
                "lifecycle_status": "stopping",
                "runtime_status": "stopping",
                "health_scope": "transition",
                "updated_at": now_iso(),
            }
        )
        atomic_json(metadata_path(project), meta)
        try:
            project_result = VM_RUNTIME.command(
                slug, meta, "project-stop", command_key="stop"
            )
            result = VmRuntimeOperations.stop(slug, meta)
            if meta.get("runtime_address"):
                meta["last_known_runtime_address"] = meta.get("runtime_address")
            meta.update(
                {
                    "runtime_address": "",
                    "workspace_host": "",
                    "lifecycle_status": "stopped",
                    "runtime_status": "stopped",
                    "health_status": "unknown",
                    "health_scope": "not-checked-stopped",
                    "workspace_provisioned": False,
                    "ssh_host_key_pinned": False,
                    "ssh_authenticated": False,
                    "ssh_validation_passed": False,
                    "updated_at": now_iso(),
                }
            )
            _record_vm_readiness(
                meta,
                {
                    "address": "",
                    "ssh_alias": meta.get("ssh_alias", ""),
                    "host_key_pinned": False,
                    "authenticated_connection": False,
                    "validated": False,
                },
                workspace_provisioned=False,
            )
            atomic_json(metadata_path(project), meta)
            update_lease(project, active=False, clean_shutdown=True)
            return str(
                project_result.get("output")
                or result.get("message", "Dedicated project VM stopped.")
            )
        except Exception as exc:
            meta.update(
                {
                    "lifecycle_status": "failed",
                    "runtime_status": "failed",
                    "last_error": str(exc)[-1000:],
                    "updated_at": now_iso(),
                }
            )
            atomic_json(metadata_path(project), meta)
            raise
    cf = compose_file(project)
    if cf:
        r = run(
            [*compose_args(project, cf), "down", "--remove-orphans"],
            cwd=project,
            timeout=600,
        )
        out = (r.stdout + r.stderr)[-4000:]
    else:
        ids = run(
            [
                "docker",
                "ps",
                "-aq",
                "--filter",
                f"label=devcontainer.local_folder={project}",
            ],
            check=False,
        ).stdout.split()
        if ids:
            run(["docker", "stop", *ids], timeout=300)
        out = "Stopped."
    meta["lifecycle_status"] = "stopped"
    meta["runtime_status"] = "stopped"
    meta["updated_at"] = now_iso()
    atomic_json(metadata_path(project), meta)
    update_lease(project, active=False, clean_shutdown=True)
    return out


def restart_project(slug: str) -> str:
    project = safe_child(SETTINGS.workspaces, slug)
    meta = load_meta(project)
    if provider_for(meta).is_vm:
        meta.update(
            {
                "lifecycle_status": "restarting",
                "runtime_status": "restarting",
                "health_scope": "transition",
                "workspace_provisioned": False,
                "updated_at": now_iso(),
            }
        )
        atomic_json(metadata_path(project), meta)
        try:
            result = VmRuntimeOperations.restart(slug, meta)
            meta.update(
                runtime_metadata(
                    provider_for(meta),
                    status="restarting",
                    runtime_id=result.get("runtime_id", meta.get("runtime_id", "")),
                    runtime_address=result.get(
                        "address", meta.get("runtime_address", "")
                    ),
                    health_status="unknown",
                    health_scope="runtime-ready-not-app-healthy",
                    lifecycle_status="restarting",
                )
            )
            _record_vm_readiness(meta, result, workspace_provisioned=False)
            project_result = VM_RUNTIME.command(
                slug, meta, "project-start", command_key="start"
            )
            meta.update(
                {
                    "lifecycle_status": "running",
                    "runtime_status": "running",
                    "updated_at": now_iso(),
                }
            )
            _record_vm_readiness(meta, result, workspace_provisioned=True)
            atomic_json(metadata_path(project), meta)
            return str(
                project_result.get("output")
                or result.get(
                    "message",
                    "Dedicated project VM restarted and project services started.",
                )
            )
        except Exception as exc:
            meta.update(
                {
                    "lifecycle_status": "failed",
                    "runtime_status": "failed",
                    "last_error": str(exc)[-1000:],
                    "updated_at": now_iso(),
                }
            )
            atomic_json(metadata_path(project), meta)
            raise
    stop_project(slug)
    return start_project(slug)


def inspect_runtime(slug: str) -> dict[str, Any]:
    project = safe_child(SETTINGS.workspaces, slug)
    meta = load_meta(project)
    if provider_for(meta).is_vm:
        return VmRuntimeOperations.inspect(slug, meta)
    return {
        "ok": True,
        "provider": provider_for(meta).name,
        "runtime_type": "container",
        "running": running(project),
        "project_id": meta.get("project_id"),
        "resource_limits": meta.get("resource_limits"),
    }


def runtime_health(slug: str) -> dict[str, Any]:
    project = safe_child(SETTINGS.workspaces, slug)
    meta = load_meta(project)
    if provider_for(meta).is_vm:
        inspection = VmRuntimeOperations.inspect(slug, meta)
        info = inspection.get("info") if isinstance(inspection, dict) else {}
        state = str((info or {}).get("state") or "").lower()
        if state != "running":
            return {
                "ok": True,
                "provider": provider_for(meta).name,
                "runtime_type": "vm",
                "runtime_id": meta.get("runtime_id"),
                "state": "stopped",
                "healthy": False,
                "runtime_health": "not-run-stopped",
                "application_healthy": False,
                "application_health": "not-run-stopped",
                "health_scope": "runtime-only",
                "guest_exec_performed": False,
                "project_id": meta.get("project_id"),
                "info": info or {},
                "note": "The VM is stopped; health inspection did not execute a guest command.",
            }
        result = VmRuntimeOperations.health(slug, meta)
        return {
            **result,
            "application_healthy": False,
            "health_scope": "runtime-only",
            "note": "Use the project health check for application health.",
        }
    is_running = running(project)
    return {
        "ok": True,
        "provider": provider_for(meta).name,
        "runtime_type": "container",
        "healthy": is_running,
        "application_healthy": is_running,
        "health_scope": "container-runtime",
        "project_id": meta.get("project_id"),
    }


def open_workspace(slug: str) -> dict[str, Any]:
    project = safe_child(SETTINGS.workspaces, slug)
    meta = load_meta(project)
    provider = provider_for(meta)
    alias = str(meta.get("ssh_alias") or meta.get("runtime_id") or "devfleet-primary")
    remote_path = str(
        meta.get("workspace_path") or f"/home/devrunner/workspaces/{slug}"
    )
    if provider.is_vm:
        inspection = VmRuntimeOperations.inspect(slug, meta)
        info = inspection.get("info") if isinstance(inspection, dict) else {}
        runtime_state = str((info or {}).get("state") or "").lower()
        if runtime_state != "running":
            readiness = workspace_readiness(
                slug, {**meta, "lifecycle_status": runtime_state or "unknown"}
            )
            if runtime_state == "stopped":
                error = "Project VM is stopped. Start it explicitly before opening the workspace."
            else:
                error = (
                    readiness["reason"]
                    or f'Project VM is {runtime_state or "not ready"}. Wait until it is running before opening the workspace.'
                )
            return {
                "ok": False,
                "provider": provider.name,
                "state": runtime_state or readiness["state"],
                "runtime_health": f'not-run-{runtime_state or "unknown"}',
                "ssh_alias": alias,
                "workspace_path": remote_path,
                "launcher_uri": "",
                "readiness": readiness,
                "error": error,
            }
        meta.update({"lifecycle_status": "running", "runtime_status": "running"})
        readiness = workspace_readiness(slug, meta)
        if not readiness["ready"]:
            refreshed = VmRuntimeOperations.refresh(slug, meta)
            _record_vm_readiness(meta, refreshed, workspace_provisioned=True)
            # A legacy agent that returns only an address supplies no trust
            # proof. Preserve the address as diagnostic state, but leave the
            # workspace blocked until a current agent or a real trusted SSH
            # validation supplies all three proofs.
            meta.update({"last_connection_refresh": now_iso(), "updated_at": now_iso()})
            atomic_json(metadata_path(project), meta)
            readiness = workspace_readiness(slug, meta)
            alias = str(meta.get("ssh_alias") or alias)
        if not readiness["ready"]:
            return {
                "ok": False,
                "provider": provider.name,
                "state": readiness["state"],
                "ssh_alias": alias,
                "workspace_path": remote_path,
                "launcher_uri": "",
                "readiness": readiness,
                "error": readiness["reason"] or "Workspace is not ready to open.",
            }
    else:
        readiness = workspace_readiness(slug, meta)
        alias = str(readiness.get("ssh_alias") or alias)
        remote_path = str(readiness.get("workspace_path") or remote_path)
        if not readiness["ready"]:
            return {
                "ok": False,
                "provider": provider.name,
                "state": readiness["state"],
                "ssh_alias": alias,
                "workspace_path": remote_path,
                "launcher_uri": "",
                "readiness": readiness,
                "error": readiness["reason"] or "Workspace is not ready to open.",
            }
    return {
        "ok": True,
        "provider": provider.name,
        "state": (
            "running"
            if provider.is_vm
            else ("running" if running(project) else "stopped")
        ),
        "runtime_address": str(meta.get("runtime_address") or ""),
        "ssh_alias": str(meta.get("ssh_alias") or alias),
        "workspace_path": remote_path,
        "readiness": readiness,
        "launcher_uri": f'vscode://vscode-remote/ssh-remote+{quote(str(meta.get("ssh_alias") or alias),safe="")}/{quote(remote_path.lstrip("/"),safe="/")}',
    }


def backup_project(
    slug: str,
    *,
    consistency_level: str = "live-best-effort",
    destructive: bool = False,
) -> str:
    project = safe_child(SETTINGS.workspaces, slug)
    if not project.is_dir():
        raise FileNotFoundError(slug)
    meta = load_authoritative_project_identity_for_mutation(project)
    if provider_for(meta).is_vm:
        if not str(meta.get("runtime_id") or ""):
            if str(meta.get("lifecycle_status") or "") != "failed":
                raise RuntimeError(
                    "A VM project without a runtime id is not in a verified failed-provisioning state."
                )
            root = SETTINGS.runtime_root / "workspace-backups"
            backup_id = f'{validate_slug(slug)}-{time.strftime("%Y%m%d-%H%M%S")}-{uuid.uuid4().hex[:8]}'
            directory = root / backup_id
            archive = directory / f"{validate_slug(slug)}.tar.gz"
            result = create_workspace_archive(project, slug, archive, include_generated=destructive, consistency_level=consistency_level)
            manifest = write_backup_manifest(
                directory,
                slug=slug,
                project_id=str(meta.get("project_id") or ""),
                runtime={"provider": "local-workspace-archive", "runtime_id": ""},
                archive=result,
                consistency_level=consistency_level,
            )
            meta.update(
                {
                    "backup_status": "verified",
                    "backup_id": backup_id,
                    "backup_path": str(archive),
                    "backup_sha256": result["archive_sha256"],
                    "backup_manifest": str(directory / "manifest.json"),
                    "updated_at": now_iso(),
                }
            )
            atomic_json(metadata_path(project), meta)
            return json.dumps(
                {
                    "ok": True,
                    "provider": "local-workspace-archive",
                    "backup_status": "verified",
                    "backup_id": backup_id,
                    "backup_path": str(archive),
                    "backup_sha256": result["archive_sha256"],
                    "manifest": manifest,
                }
            )
        result = VmRuntimeOperations.backup(slug, meta, consistency_level=consistency_level, destructive=destructive)
        if str(result.get("backup_status", "")).lower() != "verified":
            raise RuntimeError(
                "Host provider did not return a verified workspace backup artifact."
            )
        meta.update(
            {
                "backup_status": "verified",
                "backup_id": result.get("backup_id", ""),
                "backup_sha256": result.get("backup_sha256", ""),
                "backup_manifest_sha256": result.get("manifest_sha256", ""),
                "backup_reference": result.get("backup_reference"),
                "updated_at": now_iso(),
            }
        )
        atomic_json(metadata_path(project), meta)
        update_lease(project, backup_time=now_iso())
        return json.dumps(
            {
                "ok": True,
                "provider": "multipass-host-agent",
                "backup_status": meta["backup_status"],
                "runtime": result,
            },
            default=str,
        )
    root = SETTINGS.runtime_root / "workspace-backups"
    backup_id = (
        f'{validate_slug(slug)}-{time.strftime("%Y%m%d-%H%M%S")}-{uuid.uuid4().hex[:8]}'
    )
    directory = root / backup_id
    archive = directory / f"{validate_slug(slug)}.tar.gz"
    result = create_workspace_archive(project, slug, archive, include_generated=destructive, consistency_level=consistency_level)
    manifest = write_backup_manifest(
        directory,
        slug=slug,
        project_id=str(meta.get("project_id") or ""),
        runtime={"provider": "docker-compose", "runtime_id": ""},
        archive=result,
        consistency_level=consistency_level,
    )
    vault = run(["/usr/local/bin/devfleet-backup"], timeout=1800, check=False)
    meta.update(
        {
            "backup_status": "verified",
            "backup_id": backup_id,
            "backup_path": str(archive),
            "backup_sha256": result["archive_sha256"],
            "backup_manifest": str(directory / "manifest.json"),
            "updated_at": now_iso(),
        }
    )
    atomic_json(metadata_path(project), meta)
    update_lease(project, backup_time=now_iso())
    return json.dumps(
        {
            "ok": True,
            "provider": "docker-compose",
            "backup_status": "verified",
            "backup_id": backup_id,
            "backup_path": str(archive),
            "backup_sha256": result["archive_sha256"],
            "vault_exit_code": vault.returncode,
            "vault_output": (vault.stdout + vault.stderr)[-2000:],
            "manifest": manifest,
        },
        default=str,
    )


def safety_backup_project(slug: str, _lock_held: bool = False) -> dict[str, Any]:
    """Stop managed writers, create a fresh stable backup, and bind its identity."""
    project = safe_child(SETTINGS.workspaces, slug)
    if not project.is_dir() or project.is_symlink():
        raise ValueError("Project workspace is not a safe directory.")
    with contextlib.nullcontext() if _lock_held else _destructive_lock(slug):
        meta = load_authoritative_project_identity_for_mutation(project)
        transaction_id = f"destroy-{uuid.uuid4().hex}"
        meta.update(
            {
                "lifecycle_status": "destructive-quiesce-pending",
                "destructive_transaction_id": transaction_id,
                "updated_at": now_iso(),
            }
        )
        atomic_json(metadata_path(project), meta)
        stop_project(slug)
        refreshed = load_authoritative_project_identity_for_mutation(project)
        if provider_for(refreshed).is_vm:
            if str(refreshed.get("lifecycle_status") or "").lower() == "running":
                raise RuntimeError(
                    "Destructive deletion blocked: owned VM is still running after quiesce."
                )
        elif running(project):
            raise RuntimeError(
                "Destructive deletion blocked: DevFleet-owned containers remain running after compose down."
            )
        meta = load_authoritative_project_identity_for_mutation(project)
        meta.update(
            {
                "lifecycle_status": "destructive-quiesced",
                "destructive_transaction_id": transaction_id,
                "updated_at": now_iso(),
            }
        )
        atomic_json(metadata_path(project), meta)
        before = _source_state_fingerprint(project, include_generated=True)
        # Consistency is transaction-local and explicit.  The signature check
        # keeps older focused test doubles compatible without reintroducing
        # mutable module state.
        import inspect
        backup_signature = inspect.signature(backup_project)
        if "consistency_level" in backup_signature.parameters:
            result = json.loads(backup_project(slug, consistency_level="quiesced", destructive=True))
        else:
            result = json.loads(backup_project(slug))
        result.setdefault("consistency_level", "quiesced")
        meta = load_authoritative_project_identity_for_mutation(project)
        after = _source_state_fingerprint(project, include_generated=True)
        if before != after:
            raise RuntimeError(
                "Destructive deletion blocked: workspace changed during the safety backup; no deletion was performed."
            )
        backup_id, backup_sha, status = _safety_backup_fields(result, meta)
        if (
            status != "verified"
            or not backup_id
            or not re.fullmatch(r"[0-9a-f]{64}", backup_sha.lower())
        ):
            raise RuntimeError(
                "Destructive deletion blocked: fresh safety backup was not cryptographically verified."
            )
        provider = provider_for(meta)
        if provider.is_vm:
            reference = result.get("backup_reference") or (result.get("runtime") or {}).get("backup_reference") or meta.get("backup_reference")
            from .host_control import validate_backup_reference
            checked_reference = validate_backup_reference(reference, project_id=str(meta.get("project_id") or ""), slug=slug, runtime_id=str(meta.get("runtime_id") or ""))
            if checked_reference["archive_sha256"].lower() != backup_sha.lower():
                raise RuntimeError("Destructive deletion blocked: provider backup reference hash changed after verification.")
            meta["backup_reference"] = checked_reference
        else:
            archive = Path(str(result.get("backup_path") or meta.get("backup_path") or ""))
            if not archive.is_file():
                raise RuntimeError("Destructive deletion blocked: fresh safety backup archive is unavailable.")
            verified = validate_archive(archive, slug)
            if verified.get("archive_sha256", "").lower() != backup_sha.lower():
                raise RuntimeError("Destructive deletion blocked: fresh safety backup hash changed after verification.")
        binding = {
            "transaction_id": transaction_id,
            "project_id": str(meta.get("project_id") or ""),
            "runtime_id": str(meta.get("runtime_id") or ""),
            "backup_id": backup_id,
            "backup_sha256": backup_sha.lower(),
            "source_state_fingerprint": after,
            "fingerprint_policy": {
                "schema_version": FINGERPRINT_POLICY_VERSION,
                "algorithm": FINGERPRINT_ALGORITHM,
                "include_generated": True,
                "ignored_directories": [],
                "result": "verified",
            },
            "created_at": now_iso(),
        }
        meta.update(
            {
                "lifecycle_status": "destructive-backup-verified",
                "destructive_backup_binding": binding,
                "updated_at": now_iso(),
            }
        )
        atomic_json(metadata_path(project), meta)
        return {"result": result, "binding": binding, "meta": meta}


def list_backups(slug: str) -> list[dict[str, Any]]:
    slug = validate_slug(slug)
    project = safe_child(SETTINGS.workspaces, slug)
    meta = load_meta(project)
    project_id = str(meta.get("project_id") or "")
    if provider_for(meta).is_vm and str(meta.get("runtime_id") or ""):
        return VM_RUNTIME.list_backups(slug, meta)
    root = SETTINGS.runtime_root / "workspace-backups"
    items = []
    if root.is_dir():
        for directory in sorted(
            (p for p in root.iterdir() if p.is_dir()), reverse=True
        ):
            manifest_file = directory / "manifest.json"
            try:
                manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if manifest.get("slug") != slug or (
                project_id and str(manifest.get("project_id") or "") != project_id
            ):
                continue
            workspace = (
                manifest.get("workspace")
                if isinstance(manifest.get("workspace"), dict)
                else {}
            )
            archive = Path(str(workspace.get("archive_path") or ""))
            digest = str(workspace.get("archive_sha256") or "")
            eligible = archive.is_file()
            if eligible:
                try:
                    eligible = (
                        validate_archive(archive, slug).get("archive_sha256") == digest
                    )
                except (OSError, ValueError, tarfile.TarError):
                    eligible = False
            items.append(
                {
                    "backup_id": directory.name,
                    "created_at": manifest.get("created_at", ""),
                    "project_id": manifest.get("project_id", ""),
                    "provider": str(
                        (manifest.get("runtime") or {}).get("provider")
                        or "docker-compose"
                    ),
                    "runtime_id": str(
                        (manifest.get("runtime") or {}).get("runtime_id") or ""
                    ),
                    "archive_path": str(archive),
                    "archive_bytes": archive.stat().st_size if archive.is_file() else 0,
                    "archive_sha256": digest,
                    "sha_verified": eligible,
                    "restore_eligible": eligible,
                    "reason": (
                        ""
                        if eligible
                        else "Archive is missing or failed SHA/path verification."
                    ),
                    "status": "eligible" if eligible else "invalid",
                    "manifest_path": str(manifest_file),
                }
            )
    return items


def restore_backup(
    slug: str,
    backup_id: str,
    confirm_restore: bool = False,
    allow_overwrite: bool = False,
) -> dict[str, Any]:
    slug = validate_slug(slug)
    if "/" in backup_id or "\\" in backup_id or backup_id in {".", ".."}:
        raise ValueError("Invalid backup identifier.")
    project = safe_child(SETTINGS.workspaces, slug)
    meta = load_authoritative_project_identity_for_mutation(project)
    project_id = str(meta.get("project_id") or "")
    if provider_for(meta).is_vm and str(meta.get("runtime_id") or ""):
        if not confirm_restore:
            raise ValueError("Backup restore requires explicit confirmation.")
        if not allow_overwrite:
            raise ValueError(
                "VM backup restore replaces the current workspace and requires explicit overwrite confirmation."
            )
        result = VM_RUNTIME.restore_backup(slug, meta, backup_id, confirm_restore=True)
        restored = {
            **meta,
            "backup_status": "verified",
            "backup_id": backup_id,
            "backup_sha256": str(result.get("backup_sha256") or ""),
            "updated_at": now_iso(),
            "last_restore_at": now_iso(),
        }
        atomic_json(metadata_path(project), restored)
        return {
            "ok": True,
            "provider": "multipass-host-agent",
            "backup_id": backup_id,
            "backup_sha256": restored["backup_sha256"],
            "project": restored,
            "restore": result,
        }
    directory = (SETTINGS.runtime_root / "workspace-backups" / backup_id).resolve()
    root = (SETTINGS.runtime_root / "workspace-backups").resolve()
    if directory.parent != root or not directory.is_dir():
        raise FileNotFoundError(backup_id)
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    workspace = (
        manifest.get("workspace") if isinstance(manifest.get("workspace"), dict) else {}
    )
    archive = Path(str(workspace.get("archive_path") or ""))
    if (
        manifest.get("slug") != slug
        or str(manifest.get("project_id") or "") != project_id
    ):
        raise ValueError("Backup identity does not match this project.")
    if not confirm_restore:
        raise ValueError("Backup restore requires explicit confirmation.")
    verified = validate_archive(archive, slug)
    if verified.get("archive_sha256") != str(workspace.get("archive_sha256") or ""):
        raise ValueError("Backup archive hash does not match its manifest.")
    if project.exists() and any(project.iterdir()):
        if not allow_overwrite:
            raise ValueError(
                "Restore refuses to overwrite a non-empty workspace without explicit overwrite confirmation."
            )
        backup_project(slug)
    result = restore_workspace_archive(archive, project, slug)
    restored = load_meta(project)
    restored.update(
        {
            "backup_status": "verified",
            "backup_id": backup_id,
            "backup_path": str(archive),
            "backup_sha256": verified["archive_sha256"],
            "backup_manifest": str(directory / "manifest.json"),
            "updated_at": now_iso(),
            "last_restore_at": now_iso(),
        }
    )
    atomic_json(metadata_path(project), restored)
    return {
        "ok": True,
        "backup_id": backup_id,
        "backup_sha256": verified["archive_sha256"],
        "project": restored,
        "restore": result,
    }


def _recovery_tombstone_path(slug: str, project_id: str) -> Path:
    safe_id = re.sub(r"[^0-9a-fA-F-]", "", str(project_id)) or "unknown"
    return SETTINGS.runtime_root / "recovery-tombstones" / f"{validate_slug(slug)}-{safe_id}.json"


def _write_recovery_tombstone(meta: dict[str, Any], binding: dict[str, Any]) -> Path:
    tombstone = {
        "schema_version": 1,
        "managed_by": "devfleet",
        "project_id": str(meta.get("project_id") or ""),
        "slug": validate_slug(str(meta.get("slug") or "")),
        "runtime_provider": str(meta.get("runtime_provider") or "docker-compose"),
        "host_id": str(meta.get("host_id") or SETTINGS.host_id),
        "backup_id": str(binding.get("backup_id") or ""),
        "backup_sha256": str(binding.get("backup_sha256") or ""),
        "backup_reference": meta.get("backup_reference"),
        "created_at": now_iso(),
    }
    path = _recovery_tombstone_path(tombstone["slug"], tombstone["project_id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(path, tombstone)
    return path


def restore_deleted_project(
    slug: str,
    backup_id: str,
    *,
    project_id: str,
    confirm_restore: bool = False,
) -> dict[str, Any]:
    """Recover a permanently deleted local project from a bound tombstone.

    This path is intentionally separate from live-workspace restore: there is
    no current workspace identity to trust, so the durable tombstone and
    archive metadata must establish every identity before promotion.
    """
    slug = validate_slug(slug)
    project_id = str(project_id or "")
    if not confirm_restore:
        raise ValueError("Deleted-project restore requires explicit confirmation.")
    tombstone_path = _recovery_tombstone_path(slug, project_id)
    if not tombstone_path.is_file():
        raise FileNotFoundError("No durable recovery tombstone exists for this project identity.")
    try:
        tombstone = json.loads(tombstone_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Recovery tombstone is invalid.") from exc
    if tombstone.get("slug") != slug or str(tombstone.get("project_id") or "") != project_id:
        raise ValueError("Recovery tombstone identity does not match the requested project.")
    if str(tombstone.get("backup_id") or "") != backup_id:
        raise ValueError("Requested backup is not the tombstone-bound backup.")
    if str(tombstone.get("runtime_provider") or "") != "docker-compose":
        raise ValueError("Deleted VM workspace recovery requires the provider restore lifecycle and cannot use a local archive path.")
    directory = (SETTINGS.runtime_root / "workspace-backups" / backup_id).resolve()
    root = (SETTINGS.runtime_root / "workspace-backups").resolve()
    if directory.parent != root or not directory.is_dir():
        raise FileNotFoundError(backup_id)
    manifest_path = directory / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Recovery backup manifest is invalid.") from exc
    if manifest.get("slug") != slug or str(manifest.get("project_id") or "") != project_id:
        raise ValueError("Recovery backup identity does not match the tombstone.")
    workspace = manifest.get("workspace") if isinstance(manifest.get("workspace"), dict) else {}
    archive = Path(str(workspace.get("archive_path") or ""))
    verified = validate_archive(archive, slug)
    expected_sha = str(tombstone.get("backup_sha256") or workspace.get("archive_sha256") or "")
    if verified.get("archive_sha256") != expected_sha or str(workspace.get("archive_sha256") or "") != expected_sha:
        raise ValueError("Recovery archive hash does not match the tombstone and manifest.")
    project = safe_child(SETTINGS.workspaces, slug)
    if project.exists():
        raise ValueError("Deleted-project restore requires an absent destination; no overwrite was performed.")
    restored = restore_workspace_archive(archive, project, slug)
    recovered_meta = load_authoritative_project_identity_for_mutation(project)
    if str(recovered_meta.get("project_id") or "") != project_id or str(recovered_meta.get("slug") or "") != slug or str(recovered_meta.get("managed_by") or "") != "devfleet":
        raise ValueError("Recovered workspace metadata does not prove exact DevFleet ownership.")
    return {"ok": True, "project": recovered_meta, "backup_id": backup_id, "backup_sha256": expected_sha, "restore": restored, "tombstone": str(tombstone_path)}


def rebuild_project(slug: str) -> str:
    project = safe_child(SETTINGS.workspaces, slug)
    meta = load_meta(project)
    cf = compose_file(project)
    if SETTINGS.backup_before_rebuild:
        backup_project(slug)
    if provider_for(meta).is_vm:
        result = VmRuntimeOperations.command(
            slug, meta, "project-rebuild", command_key="rebuild"
        )
        return str(result.get("output") or result.get("message") or result)[-12000:]
    if cf:
        _write_current_compose_ownership(project, cf, meta)
        _assert_current_compose_safety(project, meta)
        run([*compose_args(project, cf), "build", "--pull"], cwd=project, timeout=1800)
    return start_project(slug)


def _command(slug: str, key: str, default: str, timeout: int = 1800) -> str:
    project = safe_child(SETTINGS.workspaces, slug)
    meta = load_meta(project)
    cf = compose_file(project)
    command = str(meta.get(key) or default).strip()
    if (
        len(command) > 512
        or command.startswith(("/", "~"))
        or ".." in command
        or not (
            command == "true"
            or re.fullmatch(
                r"\./\.devfleet/(bootstrap|health-check|smoke-test|codexpro-bootstrap)\.sh",
                command,
            )
        )
    ):
        raise ValueError("Project command is unsafe or unsupported.")
    if provider_for(meta).is_vm:
        key_map = {
            "bootstrap_command": "project-bootstrap",
            "health_command": "project-health",
            "test_command": "project-test",
            "start_command": "project-start",
            "stop_command": "project-stop",
            "restart_command": "project-restart",
            "rebuild_command": "project-rebuild",
            "logs_command": "project-logs",
            "codexpro_command": "project-bootstrap",
        }
        operation = key_map.get(key)
        if not operation:
            raise ValueError(
                "This VM project command is not an approved provider operation."
            )
        result = VmRuntimeOperations.command(slug, meta, operation, command_key=key)
        return str(result.get("output") or result.get("message") or result)[-12000:]
    if cf:
        _assert_current_compose_safety(project, meta)
        services = run(
            [*compose_args(project, cf), "config", "--services"], cwd=project
        ).stdout.split()
        r = run(
            [
                *compose_args(project, cf),
                "run",
                "--rm",
                services[0],
                "sh",
                "-lc",
                command,
            ],
            cwd=project,
            timeout=timeout,
        )
    else:
        raise ValueError(
            "Host-shell fallback is disabled for project commands without a Compose runtime."
        )
    return (r.stdout + r.stderr)[-12000:]


def bootstrap_project(slug: str) -> str:
    return _command(slug, "bootstrap_command", "./.devfleet/bootstrap.sh", 3600)


def health_project(slug: str) -> str:
    project = safe_child(SETTINGS.workspaces, slug)
    try:
        out = _command(slug, "health_command", "./.devfleet/health-check.sh", 300)
    except Exception as exc:
        with project_metadata_transaction(project) as meta:
            meta.update(
                {
                    "health_status": "unhealthy",
                    "health_scope": "application-check-failed",
                    "health_contract": "exit-code-0-healthy",
                    "last_health_check": now_iso(),
                    "last_error": str(exc)[-1000:],
                }
            )
        raise
    with project_metadata_transaction(project) as meta:
        meta.update(
            {
                "health_status": "healthy",
                "health_scope": "application-check",
                "health_contract": "exit-code-0-healthy",
                "last_health_check": now_iso(),
            }
        )
    return out


def test_project(slug: str) -> str:
    out = _command(slug, "test_command", "./.devfleet/smoke-test.sh")
    project = safe_child(SETTINGS.workspaces, slug)
    meta = load_meta(project)
    meta["last_successful_test"] = now_iso()
    _commit_project_metadata(project, meta)
    return out


def quarantine_project(slug: str) -> str:
    project = safe_child(SETTINGS.workspaces, slug)
    meta = load_authoritative_project_identity_for_mutation(project)
    if provider_for(meta).is_vm:
        stop_project(slug)
        backup = backup_project(slug)
        result = VmRuntimeOperations.quarantine(slug, meta)
        meta.update(
            {
                "lifecycle_status": "quarantined",
                "runtime_status": "quarantined",
                "health_status": "unknown",
                "quarantine_state": "quarantined",
                "backup_status": "verified",
                "updated_at": now_iso(),
            }
        )
        _commit_project_metadata(project, meta)
        return json.dumps(
            {
                "ok": True,
                "provider": "multipass-host-agent",
                "backup": backup,
                "runtime": result,
            },
            default=str,
        )
    stop_project(slug)
    if SETTINGS.backup_before_quarantine:
        backup_project(slug)
    SETTINGS.quarantine.mkdir(parents=True, exist_ok=True)
    dest = SETTINGS.quarantine / f"{time.strftime('%Y%m%d-%H%M%S')}-{slug}"
    try:
        project.rename(dest)
    except OSError as exc:
        # Workspaces and the quarantine volume can be separate filesystems. A
        # plain rename is atomic only on one filesystem; fall back to shutil.move
        # after the verified backup so the safe cleanup action still completes.
        if exc.errno != errno.EXDEV:
            raise
        shutil.move(str(project), str(dest))
    return str(dest)


def list_quarantine() -> list[dict[str, str]]:
    SETTINGS.quarantine.mkdir(parents=True, exist_ok=True)
    return [
        {"name": p.name, "path": str(p)}
        for p in sorted(SETTINGS.quarantine.iterdir(), reverse=True)
        if p.is_dir()
    ]


def restore_quarantine(name: str) -> str:
    if "/" in name or "\\" in name or name in {".", ".."}:
        raise ValueError("Invalid quarantine name.")
    src = (SETTINGS.quarantine / name).resolve()
    base = SETTINGS.quarantine.resolve()
    if src.parent != base or not src.is_dir():
        raise FileNotFoundError(name)
    identity = load_authoritative_project_identity_for_mutation(src)
    slug = str(identity["slug"])
    dest = safe_child(SETTINGS.workspaces, slug)
    if dest.exists():
        raise ValueError(
            "Quarantine restore is blocked: the exact owned workspace path already exists."
        )
    try:
        src.rename(dest)
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
        shutil.move(str(src), str(dest))
    if not dest.is_dir() or dest.is_symlink():
        raise ValueError(
            "Quarantine restore did not produce a safe workspace directory."
        )
    return str(dest)


def restore_from_vault(slug: str, canonical: bool = False) -> str:
    slug = validate_slug(slug)
    project = safe_child(SETTINGS.workspaces, slug)
    load_authoritative_project_identity_for_mutation(project)
    cmd = ["/usr/local/bin/devfleet-restore-project", slug]
    cmd += ["--canonical"] if canonical else []
    return run(cmd, timeout=3600).stdout.strip()


def project_logs(slug: str, tail: int = 150) -> str:
    project = safe_child(SETTINGS.workspaces, slug)
    meta = load_meta(project)
    if provider_for(meta).is_vm:
        result = VM_RUNTIME.logs(slug, meta, tail=tail)
        return str(
            result.get("output")
            or result.get("logs")
            or result.get("message")
            or result
        )[-30000:]
    cf = compose_file(project)
    if cf:
        return (
            run(
                [
                    *compose_args(project, cf),
                    "logs",
                    "--no-color",
                    "--tail",
                    str(max(1, min(tail, 500))),
                ],
                cwd=project,
                check=False,
                timeout=60,
            ).stdout
            or ""
        )[-30000:]
    return "No Compose runtime log available."


def bootstrap_codexpro(slug: str) -> str:
    project = safe_child(SETTINGS.workspaces, slug)
    meta = load_meta(project)
    if provider_for(meta).is_vm:
        result = VmRuntimeOperations.command(
            slug, meta, "project-bootstrap", command_key="codexpro"
        )
        return str(result.get("output") or result.get("message") or result)[-12000:]
    return _hook(project, compose_file(project))


def destroy_project(slug: str, confirm_slug: str = "", confirm_phrase: str = "") -> str:
    with _destructive_lock(slug):
        project = safe_child(SETTINGS.workspaces, slug)
        meta = load_authoritative_project_identity_for_mutation(project)
        if not SETTINGS.allow_permanent_delete:
            raise ValueError("Permanent project deletion is disabled by policy.")
        if confirm_slug != slug or confirm_phrase != f"DESTROY {slug}":
            raise ValueError(
                "Permanent deletion requires the exact project slug and confirmation phrase."
            )
        safety = safety_backup_project(slug, _lock_held=True)
        meta = safety["meta"]
        binding = safety["binding"]
        backup_result = safety["result"]
        backup_id = str(binding["backup_id"])
        backup_sha256 = str(binding["backup_sha256"])
        _assert_safety_binding_current(project, binding)
        if provider_for(meta).is_vm:
            if str(meta.get("runtime_id") or ""):
                meta["lifecycle_status"] = "destroying"
                meta["provisioning_status"] = "destroying"
                meta["updated_at"] = now_iso()
                _commit_project_metadata(project, meta)
                result = VmRuntimeOperations.destroy(
                    slug,
                    meta,
                    confirm_slug=confirm_slug,
                    confirm_phrase=confirm_phrase,
                    backup_verified=True,
                    backup_id=backup_id,
                    backup_sha256=backup_sha256,
                )
            else:
                result = {
                    "message": "No project VM was allocated; fresh safety workspace archive verified."
                }
        else:
            result = {
                "message": "Project containers quiesced and fresh safety backup verified."
            }
        _assert_safety_binding_current(project, binding)
        tombstone_path = _write_recovery_tombstone(meta, binding)
        shutil.rmtree(project)
        if project.exists():
            raise RuntimeError(
                "Permanent deletion post-condition failed: workspace still exists."
            )
        return (
            str(result.get("message", "Project destroyed."))
            + f" Workspace permanently removed after exact fresh backup binding; recovery tombstone {tombstone_path.name} retained."
        )
