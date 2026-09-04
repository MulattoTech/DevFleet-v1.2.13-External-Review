from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

import yaml

from .core import SETTINGS, atomic_json
from .profiles import get_profile


# The analyzer intentionally supports a reviewed subset instead of invoking a
# resolver on attacker-controlled files. Changing either identifier changes the
# analyzer's security boundary and therefore its cache identity.
ANALYZER_POLICY_VERSION = "2.0.0"
COMPOSE_SUPPORTED_SCHEMA = "compose-spec-safe-subset-2026-08"
DEVCONTAINER_SUPPORTED_SCHEMA = "devcontainer-json-safe-subset-2026-08"
MAX_REFERENCE_DEPTH = 8
MAX_REFERENCE_FILES = 256
MAX_REFERENCE_BYTES = 32 * 1024 * 1024

WINDOWS_PATH = re.compile(r"^[a-z]:[\\/]", re.I)
UNC_PATH = re.compile(r"^(?:\\\\|//)")
DOCKER_SOCKET = re.compile(r"(?:docker\.sock|/run/user/\d+/docker\.sock)", re.I)
RELEVANT_NAMES = {"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml", "devcontainer.json", ".env", "project.json"}
COMPOSE_FILES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml", ".devcontainer/compose.yaml", ".devcontainer/docker-compose.yml")

# Current Docker Compose service keys. Unknown keys are blocking so a future
# execution-affecting field cannot silently disappear from review.
COMPOSE_SERVICE_KEYS = {
    "annotations", "attach", "build", "blkio_config", "cpu_count", "cpu_percent", "cpu_shares", "cpu_period",
    "cpu_quota", "cpu_rt_runtime", "cpu_rt_period", "cpus", "cpuset", "cap_add", "cap_drop", "cgroup",
    "cgroup_parent", "command", "configs", "container_name", "credential_spec", "depends_on", "deploy", "develop",
    "device_cgroup_rules", "devices", "dns", "dns_opt", "dns_search", "domainname", "entrypoint", "env_file",
    "environment", "expose", "external_links", "extra_hosts", "gpus", "group_add", "healthcheck", "hostname",
    "image", "init", "ipc", "isolation", "labels", "label_file", "links", "logging", "mac_address", "mem_limit",
    "mem_reservation", "mem_swappiness", "memswap_limit", "models", "network_mode", "networks", "oom_kill_disable",
    "oom_score_adj", "pid", "pids_limit", "platform", "ports", "post_start", "pre_start", "pre_stop", "privileged",
    "profiles", "provider", "pull_policy", "read_only", "restart", "runtime", "scale", "secrets", "security_opt",
    "shm_size", "stdin_open", "stop_grace_period", "stop_signal", "storage_opt", "sysctls", "tmpfs", "tty",
    "ulimits", "use_api_socket", "user", "userns_mode", "uts", "volumes", "volumes_from", "working_dir", "extends",
}
COMPOSE_TOP_LEVEL_KEYS = {"name", "version", "services", "networks", "volumes", "secrets", "configs", "models", "include"}
COMPOSE_UNSUPPORTED_KEYS = {
    "include", "extends", "use_api_socket", "volumes_from", "provider", "post_start", "pre_start", "pre_stop",
    "credential_spec", "runtime", "gpus", "device_cgroup_rules", "cgroup_parent", "sysctls", "tmpfs", "isolation",
}
COMPOSE_HOST_NAMESPACE_KEYS = {"network_mode", "pid", "ipc", "uts", "userns_mode"}

DEVCONTAINER_KEYS = {
    "name", "image", "dockerFile", "dockerfile", "context", "build", "dockerComposeFile", "service", "workspaceFolder",
    "workspaceMount", "shutdownAction", "overrideCommand", "remoteUser", "containerUser", "containerEnv", "remoteEnv",
    "mounts", "runArgs", "privileged", "capAdd", "securityOpt", "features", "overrideFeatureInstallOrder",
    "initializeCommand", "onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand",
    "postAttachCommand", "forwardPorts", "portsAttributes", "otherPortsAttributes", "appPort", "init", "customizations",
    "hostRequirements", "waitFor", "userEnvProbe", "secrets",
}


def finding(severity: str, code: str, message: str, file: str = "") -> dict[str, str]:
    return {"severity": severity, "code": code, "message": message, "file": file}


def _unsafe_source(source: str) -> str | None:
    source = source.strip()
    norm = source.replace("\\", "/")
    if not source:
        return "empty path"
    if "$" in source:
        return "environment-variable interpolation"
    if WINDOWS_PATH.search(source) or UNC_PATH.search(source):
        return "Windows/UNC host path"
    if DOCKER_SOCKET.search(source):
        return "Docker socket"
    if source.startswith(("/", "~")):
        return "absolute host path"
    if ".." in PurePosixPath(norm).parts:
        return "parent-directory traversal"
    return None


def _severity(profile: str, kind: str) -> str:
    p = get_profile(profile)
    if kind in {"hardening", "health"}:
        return "critical" if p.block_hardening else "warning"
    if kind in {"device", "privileged"}:
        return "warning" if p.name == "fast" else "critical"
    return "critical"


def _inside_project(project: Path, candidate: Path) -> bool:
    try:
        candidate.resolve(strict=False).relative_to(project.resolve())
        return True
    except ValueError:
        return False


def _contains_symlink(project: Path, candidate: Path) -> bool:
    try:
        relative = candidate.relative_to(project)
    except ValueError:
        return True
    current = project
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _reference(project: Path, base: Path, raw: Any, rel: str, kind: str, findings: list[dict[str, str]], references: set[Path], *, required: bool = False) -> Path | None:
    path_code = "docker.mount-resolution" if kind == "bind mount source" else "docker.build-context" if kind == "build.context" else "compose.path-escape"
    value = str(raw or "").strip()
    reason = _unsafe_source(value)
    if reason:
        findings.append(finding("critical", "compose.path-reference", f"{kind} is unsafe ({reason}): {value!r}.", rel))
        return None
    candidate = (base / value).resolve(strict=False)
    if not _inside_project(project, candidate):
        findings.append(finding("critical", path_code, f"{kind} resolves outside the project boundary: {value!r}.", rel))
        return None
    lexical = base / value
    if _contains_symlink(project, lexical):
        findings.append(finding("critical", path_code, f"{kind} may not traverse a symlink: {value!r}.", rel))
        return None
    if required and not candidate.is_file():
        findings.append(finding("critical", "compose.missing-reference", f"Referenced {kind} does not exist: {value!r}.", rel))
        return None
    references.add(candidate)
    return candidate


def _short_bind_source(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    if WINDOWS_PATH.search(value) or UNC_PATH.search(value) or DOCKER_SOCKET.search(value):
        return value
    if ":" not in value:
        return value if value.startswith((".", "..", "/", "~")) else None
    return value.split(":", 1)[0]


def _volume_source(value: Any) -> tuple[str, bool]:
    if isinstance(value, dict):
        kind = str(value.get("type", "volume")).lower()
        source = str(value.get("source") or value.get("src") or "")
        return source, kind == "bind"
    source = _short_bind_source(str(value))
    return source or "", source is not None


def _parse_yaml(path: Path) -> dict[str, Any] | None:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _iter_env_files(value: Any) -> Iterable[Any]:
    if isinstance(value, (str, dict)):
        return (value,)
    return value or ()


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(key)
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _preflight_compose(project: Path, path: Path, findings: list[dict[str, str]], references: set[Path], seen: set[Path], state: dict[str, int], depth: int) -> dict[str, Any] | None:
    rel = str(path.relative_to(project)) if _inside_project(project, path) else str(path)
    if depth > MAX_REFERENCE_DEPTH:
        findings.append(finding("critical", "compose.reference-depth", "Compose reference depth exceeds the bounded policy.", rel))
        return None
    path = path.resolve(strict=False)
    if path in seen:
        return _parse_yaml(path)
    if len(seen) >= MAX_REFERENCE_FILES:
        findings.append(finding("critical", "compose.reference-count", "Compose reference count exceeds the bounded policy.", rel))
        return None
    seen.add(path)
    if not path.is_file():
        findings.append(finding("critical", "compose.missing-reference", "Compose configuration is missing.", rel))
        return None
    state["bytes"] += path.stat().st_size
    if state["bytes"] > MAX_REFERENCE_BYTES:
        findings.append(finding("critical", "compose.reference-bytes", "Compose referenced input bytes exceed the bounded policy.", rel))
        return None
    data = _parse_yaml(path)
    if data is None:
        findings.append(finding("error", "yaml.invalid", "Compose configuration is not a YAML object.", rel))
        return None
    if any("${" in text for text in _strings(data)):
        findings.append(finding("critical", "compose.interpolation", "Compose environment interpolation is blocked in the security-reviewed subset.", rel))
    for key in data:
        if not str(key).startswith("x-") and key not in COMPOSE_TOP_LEVEL_KEYS:
            findings.append(finding("critical", "compose.unknown-field", f"Unreviewed top-level Compose field is blocked: {key!r}.", rel))
    includes = data.get("include")
    if includes:
        findings.append(finding("critical", "compose.include", "Compose include is blocked until a bounded resolver is certified.", rel))
        entries = includes if isinstance(includes, list) else [includes]
        for entry in entries:
            include_path = entry.get("path") if isinstance(entry, dict) else entry
            included = _reference(project, path.parent, include_path, rel, "Compose include", findings, references)
            if included and included.is_file():
                _preflight_compose(project, included, findings, references, seen, state, depth + 1)
    services = data.get("services") or {}
    if not isinstance(services, dict):
        findings.append(finding("error", "compose.services", "Compose services must be a mapping.", rel))
        return data
    for name, service in services.items():
        if not isinstance(service, dict):
            findings.append(finding("error", "compose.service", f"Compose service {name!r} must be a mapping.", rel))
            continue
        for key in service:
            if key not in COMPOSE_SERVICE_KEYS and not str(key).startswith("x-"):
                findings.append(finding("critical", "compose.unknown-field", f"Unreviewed service field is blocked: {name}.{key}.", rel))
        extends = service.get("extends")
        if extends:
            findings.append(finding("critical", "compose.extends", "Compose extends is blocked until effective-model resolution is certified.", rel))
            if isinstance(extends, dict) and extends.get("file"):
                inherited = _reference(project, path.parent, extends.get("file"), rel, "Compose extends file", findings, references)
                if inherited and inherited.is_file():
                    _preflight_compose(project, inherited, findings, references, seen, state, depth + 1)
        for env_file in _iter_env_files(service.get("env_file")):
            env_path = env_file.get("path") if isinstance(env_file, dict) else env_file
            _reference(project, path.parent, env_path, rel, "env_file", findings, references)
        build = service.get("build")
        if isinstance(build, str):
            _reference(project, path.parent, build, rel, "build.context", findings, references)
        elif isinstance(build, dict):
            context = build.get("context")
            if context:
                context_path = _reference(project, path.parent, context, rel, "build.context", findings, references)
                if context_path and build.get("dockerfile"):
                    _reference(project, context_path.parent, build.get("dockerfile"), rel, "build.dockerfile", findings, references, required=True)
        for volume in service.get("volumes") or ():
            source, is_bind = _volume_source(volume)
            if is_bind:
                _reference(project, path.parent, source, rel, "bind mount source", findings, references)
        for key in ("secrets", "configs"):
            value = service.get(key)
            if value:
                findings.append(finding("critical", "compose.secret-config", f"Service {name}.{key} is blocked until host-file authorization is certified.", rel))
    for key in ("secrets", "configs"):
        declarations = data.get(key)
        if isinstance(declarations, dict):
            for name, declaration in declarations.items():
                if isinstance(declaration, dict) and declaration.get("file"):
                    _reference(project, path.parent, declaration["file"], rel, f"{key}.{name} file", findings, references, required=True)
                if declaration:
                    findings.append(finding("critical", "compose.secret-config", f"Top-level {key}.{name} is blocked until host-file authorization is certified.", rel))
    return data


def _scan_compose_service(project: Path, path: Path, name: str, svc: dict[str, Any], profile: str, out: list[dict[str, str]]) -> None:
    rel = str(path.relative_to(project))
    metadata: dict[str, Any] = {}
    try:
        metadata = json.loads((project / ".devfleet/project.json").read_text(encoding="utf-8"))
    except Exception:
        pass
    for key in COMPOSE_UNSUPPORTED_KEYS:
        if key in svc and svc.get(key) not in (None, False, [], {}):
            out.append(finding("critical", f"compose.{key.replace('_', '-')}", f"{name}.{key} is blocked by the supported Compose security policy.", rel))
    if svc.get("container_name"):
        out.append(finding("critical" if profile == "strict" else "warning", "docker.container-name", f"{name}: explicit container_name can collide across projects.", rel))
    if svc.get("privileged") is True:
        severity = _severity(profile, "privileged")
        if profile == "fast" and not metadata.get("allow_privileged"):
            severity = "critical"
        out.append(finding(severity, "docker.privileged", f"{name}: privileged mode requires Fast Trusted plus project-level acknowledgement.", rel))
    for key in COMPOSE_HOST_NAMESPACE_KEYS:
        value = str(svc.get(key, "")).lower()
        if value == "host" or value.startswith(("container:", "service:")):
            out.append(finding("critical", "docker.host-namespace", f"{name}: {key}={value} is forbidden.", rel))
    caps = [str(x).upper() for x in (svc.get("cap_add") or [])]
    if caps:
        severity = _severity(profile, "device")
        if profile == "fast" and not metadata.get("allow_privileged"):
            severity = "critical"
        out.append(finding(severity, "docker.capabilities", f"{name}: capabilities require explicit reviewed acknowledgement: {caps}.", rel))
    if svc.get("devices"):
        severity = _severity(profile, "device")
        if profile == "fast" and not metadata.get("allow_devices"):
            severity = "critical"
        out.append(finding(severity, "docker.devices", f"{name}: device access requires Fast Trusted plus project-level acknowledgement.", rel))
    for volume in svc.get("volumes") or ():
        source, is_bind = _volume_source(volume)
        if is_bind:
            reason = _unsafe_source(source)
            if reason:
                out.append(finding("critical", "docker.mount", f"{name}: rejected {reason}: {source!r}.", rel))
    build = svc.get("build")
    if build:
        context = build if isinstance(build, str) else str(build.get("context", "."))
        reason = _unsafe_source(context)
        if reason and context not in {".", "./"}:
            out.append(finding("critical", "docker.build-context", f"{name}: rejected {reason}: {context}.", rel))
        if isinstance(build, dict) and build.get("privileged"):
            out.append(finding("critical", "docker.build-privileged", f"{name}: privileged image builds are blocked.", rel))
        if isinstance(build, dict) and build.get("secrets"):
            out.append(finding("critical", "docker.build-secrets", f"{name}: build secrets are blocked.", rel))
        context_path = (path.parent / context).resolve(strict=False)
        dockerfile_name = "Dockerfile" if isinstance(build, str) else str(build.get("dockerfile", "Dockerfile"))
        dockerfile = (context_path / dockerfile_name).resolve(strict=False)
        if _inside_project(project, dockerfile) and dockerfile.is_file():
            users = []
            for line in dockerfile.read_text(encoding="utf-8", errors="ignore").splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2 and parts[0].upper() == "USER":
                    users.append(parts[1].strip())
            if not users or users[-1].lower() in {"root", "0", "0:0"}:
                out.append(finding(_severity(profile, "hardening"), "docker.non-root-user", f"{name}: Dockerfile does not finish with a non-root USER.", str(dockerfile.relative_to(project))))
    for env_file in _iter_env_files(svc.get("env_file")):
        value = str(env_file.get("path", "")) if isinstance(env_file, dict) else str(env_file)
        reason = _unsafe_source(value)
        if reason:
            out.append(finding("critical", "docker.env-file", f"{name}: unsafe env_file ({reason}): {value}.", rel))
    for port in svc.get("ports") or ():
        state, text = _port_state(port)
        if state == "public":
            out.append(finding("critical", "docker.port-public", f"{name}: public/unbound port publication is forbidden: {text}.", rel))
        elif state == "tailnet" and not (get_profile(profile).allow_tailnet and SETTINGS.allow_tailnet_ports):
            out.append(finding("critical", "docker.port-tailnet", f"{name}: tailnet port requires policy approval: {text}.", rel))
    if "healthcheck" not in svc:
        out.append(finding(_severity(profile, "health"), "docker.healthcheck", f"{name}: no container healthcheck is defined.", rel))
    image = str(svc.get("image", ""))
    if image.endswith(":latest") or (image and ":" not in image):
        out.append(finding(_severity(profile, "hardening"), "docker.unpinned-image", f"{name}: development image is not pinned.", rel))
    security = [str(x).lower() for x in (svc.get("security_opt") or [])]
    if any("unconfined" in x for x in security):
        out.append(finding("critical", "docker.unconfined", f"{name}: unconfined security profile is forbidden.", rel))
    if not any("no-new-privileges" in x for x in security):
        out.append(finding(_severity(profile, "hardening"), "docker.no-new-privileges", f"{name}: no-new-privileges is not set.", rel))


def _strip_jsonc(text: str) -> str:
    result: list[str] = []
    i = 0
    in_string = False
    escaped = False
    while i < len(text):
        char = text[i]
        if in_string:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            i += 1
            continue
        if char == '"':
            in_string = True
            result.append(char)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = len(text) if end < 0 else end + 2
        else:
            result.append(char)
            i += 1
    return re.sub(r",\s*([}\]])", r"\1", "".join(result))


def _parse_jsonc(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(_strip_jsonc(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _scan_devcontainer(project: Path, profile: str, out: list[dict[str, str]], references: set[Path]) -> None:
    path = project / ".devcontainer/devcontainer.json"
    if not path.exists():
        return
    rel = str(path.relative_to(project))
    if path.is_symlink():
        out.append(finding("critical", "project.symlink-config", "devcontainer.json may not be a symbolic link.", rel))
        return
    data = _parse_jsonc(path)
    if data is None:
        out.append(finding("error", "devcontainer.json.invalid", "devcontainer.json is not valid bounded JSONC.", rel))
        return
    for key in data:
        if key not in DEVCONTAINER_KEYS and not key.startswith("x-"):
            out.append(finding("critical", "devcontainer.unknown-field", f"Unreviewed Dev Container field is blocked: {key!r}.", rel))
    compose_files = data.get("dockerComposeFile")
    compose_files = compose_files if isinstance(compose_files, list) else ([compose_files] if compose_files else [])
    for compose_file in compose_files:
        lexical = path.parent / str(compose_file)
        candidate = lexical.resolve(strict=False)
        if not _inside_project(project, candidate) or _contains_symlink(project, lexical):
            out.append(finding("critical", "devcontainer.compose-path", "dockerComposeFile escapes the project or crosses a symlink.", rel))
        elif candidate.is_file():
            references.add(candidate)
    if data.get("initializeCommand") is not None:
        out.append(finding("critical", "devcontainer.host-command", "initializeCommand executes on the host and is blocked.", rel))
    if data.get("privileged") is True:
        out.append(finding(_severity(profile, "privileged"), "devcontainer.privileged", "Privileged Dev Container mode is blocked without an explicit reviewed exception.", rel))
    if data.get("capAdd"):
        out.append(finding("critical", "devcontainer.capabilities", "Dev Container capabilities are blocked in the supported subset.", rel))
    if data.get("securityOpt"):
        out.append(finding("critical", "devcontainer.security-options", "Dev Container security options are blocked in the supported subset.", rel))
    run_args = data.get("runArgs")
    if run_args:
        if not isinstance(run_args, list) or any(not isinstance(item, str) for item in run_args):
            out.append(finding("critical", "devcontainer.run-args", "runArgs must be a list of strings and is blocked by default.", rel))
        else:
            dangerous = {"--privileged", "--network", "--pid", "--ipc", "--uts", "--userns", "--volume", "-v", "--mount", "--device", "--cap-add", "--security-opt", "--env-file"}
            for arg in run_args:
                if arg.split("=", 1)[0] in dangerous:
                    out.append(finding("critical", "devcontainer.run-args-dangerous", f"Dangerous Dev Container runtime argument is blocked: {arg!r}.", rel))
            out.append(finding("critical", "devcontainer.run-args", "runArgs are rejected by default until each runtime option has a reviewed allowlist entry.", rel))
    if data.get("workspaceMount"):
        out.append(finding("critical", "devcontainer.workspace-mount", "workspaceMount is blocked until its host-path contract is authorized.", rel))
    if data.get("mounts"):
        out.append(finding("critical", "devcontainer.mount", "Dev Container mounts are blocked until their complete host-path and socket semantics are authorized.", rel))
    features = data.get("features")
    if features:
        out.append(finding("critical", "devcontainer.features-unsupported", "Dev Container Features are blocked until immutable resolution and derived runtime metadata are validated.", rel))
        if isinstance(features, dict):
            for feature in features:
                if str(feature).startswith((".", "/", "~")):
                    lexical = path.parent / str(feature)
                    if not _inside_project(project, lexical) or _contains_symlink(project, lexical):
                        out.append(finding("critical", "devcontainer.feature-path", "Local Feature path escapes the project or crosses a symlink.", rel))


def _port_state(port: Any) -> tuple[str, str]:
    if isinstance(port, dict):
        host = str(port.get("host_ip", ""))
        text = json.dumps(port, sort_keys=True)
    else:
        text = str(port)
        parts = text.rsplit(":", 2)
        host = parts[0] if len(parts) >= 3 else ""
    if host in {"127.0.0.1", "::1", "[::1]"}:
        return "loopback", text
    if host.startswith("100."):
        try:
            n = int(host.split(".")[1])
            return ("tailnet" if 64 <= n <= 127 else "public"), text
        except Exception:
            pass
    return "public", text


def _scan(project: Path, profile: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    references: set[Path] = set()
    found = False
    for relative in COMPOSE_FILES:
        path = project / relative
        if not path.exists():
            continue
        found = True
        if path.is_symlink():
            out.append(finding("critical", "project.symlink-config", "Container configuration may not be a symbolic link.", relative))
            continue
        document = _preflight_compose(project, path, out, references, set(), {"bytes": 0}, 0)
        if document:
            services = document.get("services") or {}
            if isinstance(services, dict):
                for name, service in services.items():
                    if isinstance(service, dict):
                        _scan_compose_service(project, path, str(name), service, profile, out)
    dc = project / ".devcontainer/devcontainer.json"
    if dc.exists():
        found = True
        _scan_devcontainer(project, profile, out, references)
    if not found:
        out.append(finding("warning", "project.no-container-config", "No supported Compose or Dev Container configuration found."))
    for pth in project.rglob("*"):
        if pth.is_symlink():
            try:
                pth.resolve().relative_to(project.resolve())
            except ValueError:
                out.append(finding("critical", "project.symlink-escape", "Symbolic link resolves outside the project.", str(pth.relative_to(project))))
    return sorted(out, key=lambda x: {"critical": 0, "error": 1, "warning": 2, "info": 3}.get(x["severity"], 9))


def _fingerprint(project: Path, profile: str) -> str:
    h = hashlib.sha256()
    for value in (ANALYZER_POLICY_VERSION, COMPOSE_SUPPORTED_SCHEMA, DEVCONTAINER_SUPPORTED_SCHEMA, profile):
        h.update(value.encode("utf-8"))
        h.update(b"\0")
    try:
        files = sorted(project.rglob("*"), key=lambda item: str(item.relative_to(project)))
    except OSError:
        files = []
    for path in files:
        try:
            relative = path.relative_to(project)
            if relative.as_posix() == ".devfleet/runtime/analyzer-cache.json" or not path.is_file():
                continue
            h.update(str(relative).encode("utf-8"))
            h.update(b"\0")
            if path.is_symlink():
                h.update(b"symlink:")
                h.update(str(path.resolve(strict=False)).encode("utf-8"))
            else:
                h.update(b"file:")
                h.update(hashlib.sha256(path.read_bytes()).digest())
            h.update(b"\0")
        except (OSError, ValueError):
            h.update(f"unreadable:{path}".encode("utf-8"))
    return h.hexdigest()


def analyze_project(project: Path, profile: str | None = None, force: bool = False) -> list[dict[str, str]]:
    profile = (profile or SETTINGS.development_profile).lower()
    fp = _fingerprint(project, profile)
    cache = project / ".devfleet/runtime/analyzer-cache.json"
    if SETTINGS.enable_analyzer_cache and not force:
        try:
            data = json.loads(cache.read_text(encoding="utf-8"))
            if data.get("fingerprint") == fp and data.get("policyVersion") == ANALYZER_POLICY_VERSION:
                return data.get("findings", [])
        except Exception:
            pass
    findings = _scan(project, profile)
    if SETTINGS.enable_analyzer_cache:
        atomic_json(cache, {"fingerprint": fp, "policyVersion": ANALYZER_POLICY_VERSION, "findings": findings})
    return findings


def has_blockers(findings: list[dict[str, str]]) -> bool:
    return any(x["severity"] in {"critical", "error"} for x in findings)
