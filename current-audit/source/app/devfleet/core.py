"""Shared DevFleet settings, validation, and crash-safe filesystem helpers.

This module deliberately contains no host-management logic.  Host changes are
made only through the narrow authenticated host-agent client.
"""
from __future__ import annotations

import json
import ipaddress
import os
import re
import secrets
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import pwd
except ImportError:  # pragma: no cover - Windows has no pwd module.
    pwd = None


CONFIG_PATH = Path(os.environ.get("DEVFLEET_CONFIG_PATH", "/etc/devfleet/config.json"))
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,62}$")
PROJECT_ID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")


@dataclass(frozen=True)
class Settings:
    node_name: str
    deployment_id: str
    node_role: str
    friendly_name: str
    portal_port: int
    workspaces: Path
    quarantine: Path
    peer_file: Path
    runtime_root: Path
    cache_root: Path
    ollama_base_url: str
    ollama_model: str
    ollama_profile: str
    development_profile: str
    docker_mode: str
    docker_host: str
    docker_owner_uid: int | None
    enable_shared_caches: bool
    enable_analyzer_cache: bool
    auto_start_codexpro: bool
    allow_tailnet_ports: bool
    backup_before_rebuild: bool
    backup_before_quarantine: bool
    allow_permanent_delete: bool
    host_control_enabled: bool
    host_control_url: str
    host_control_token: str
    expected_host_name: str
    host_agent_timeout_seconds: int
    host_resource_policy: dict[str, Any]
    admin_user: str
    admin_password: str
    api_token: str
    require_tailscale: bool
    tailnet_cidr: str
    public_binding_allowed: bool

    @property
    def operations(self) -> Path:
        return self.runtime_root / "operations"

    @property
    def host_id(self) -> str:
        return self.node_name


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _default_config() -> dict[str, Any]:
    root = Path(os.environ.get("DEVFLEET_TEST_ROOT", "/tmp/devfleet"))
    return {
        "node_name": os.environ.get("DEVFLEET_NODE_NAME", "devfleet-primary"),
        "deployment_id": os.environ.get("DEVFLEET_DEPLOYMENT_ID", ""),
        "node_role": "primary",
        "friendly_name": "DevFleet",
        "portal_port": 8787,
        "workspaces": str(root / "workspaces"),
        "quarantine": str(root / "quarantine"),
        "peer_file": str(root / "peer.json"),
        "runtime_root": str(root / "runtime"),
        "cache_root": str(root / "cache"),
        "docker_mode": "rootless",
        "docker_host": os.environ.get("DOCKER_HOST", ""),
        "host_resource_policy": {},
        "require_tailscale": True,
        "tailnet_cidr": "100.64.0.0/10",
        "public_binding_allowed": False,
    }


def load_settings() -> Settings:
    if CONFIG_PATH.exists():
        try:
            if os.name != "nt" and str(CONFIG_PATH).startswith("/etc/devfleet/"):
                stat = CONFIG_PATH.stat()
                if stat.st_uid != 0 or stat.st_mode & 0o022:
                    raise ValueError("security configuration ownership or permissions are unsafe")
            cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            raise ValueError("security configuration is missing, malformed, or unreadable; refusing fail-open defaults") from exc
        if not isinstance(cfg, dict):
            raise ValueError("security configuration must be a JSON object")
    else:
        cfg = _default_config()
    policy = dict(cfg.get("host_resource_policy") or {})
    return Settings(
        node_name=str(cfg.get("node_name", cfg.get("host_id", "devfleet-primary"))),
        deployment_id=str(cfg.get("deployment_id", "")),
        node_role=str(cfg.get("node_role", "primary")),
        friendly_name=str(cfg.get("friendly_name", cfg.get("node_name", "DevFleet"))),
        portal_port=int(cfg.get("portal_port", 8787)),
        workspaces=Path(cfg.get("workspaces", "/var/lib/devfleet/workspaces")),
        quarantine=Path(cfg.get("quarantine", "/var/lib/devfleet/quarantine")),
        peer_file=Path(cfg.get("peer_file", "/etc/devfleet/peer.json")),
        runtime_root=Path(cfg.get("runtime_root", "/var/lib/devfleet/runtime")),
        cache_root=Path(cfg.get("cache_root", "/var/cache/devfleet")),
        ollama_base_url=str(cfg.get("ollama_base_url", "")),
        ollama_model=str(cfg.get("ollama_model", "")),
        ollama_profile=str(cfg.get("ollama_profile", "stable-interactive")),
        development_profile=str(cfg.get("development_profile", "strict")),
        docker_mode=str(cfg.get("docker_mode", "rootless")),
        docker_host=str(os.environ.get("DOCKER_HOST", cfg.get("docker_host", ""))),
        docker_owner_uid=(int(os.environ["DEVFLEET_DOCKER_OWNER_UID"]) if os.environ.get("DEVFLEET_DOCKER_OWNER_UID") else (int(cfg["docker_owner_uid"]) if cfg.get("docker_owner_uid") is not None else None)),
        enable_shared_caches=bool(cfg.get("enable_shared_caches", False)),
        enable_analyzer_cache=bool(cfg.get("enable_analyzer_cache", True)),
        auto_start_codexpro=bool(cfg.get("auto_start_codexpro", True)),
        allow_tailnet_ports=bool(cfg.get("allow_tailnet_ports", False)),
        backup_before_rebuild=bool(cfg.get("backup_before_rebuild", False)),
        backup_before_quarantine=bool(cfg.get("backup_before_quarantine", True)),
        allow_permanent_delete=bool(cfg.get("allow_permanent_delete", False)),
        host_control_enabled=_env_bool("DEVFLEET_HOST_CONTROL_ENABLED", bool(cfg.get("host_control_enabled", False))),
        host_control_url=str(os.environ.get("DEVFLEET_HOST_CONTROL_URL", cfg.get("host_control_url", ""))),
        host_control_token=str(os.environ.get("DEVFLEET_HOST_CONTROL_TOKEN", cfg.get("host_control_token", ""))),
        expected_host_name=str(cfg.get("expected_host_name", cfg.get("host_name", os.environ.get("COMPUTERNAME", "devfleet-host")))),
        host_agent_timeout_seconds=int(cfg.get("host_agent_timeout_seconds", 30)),
        host_resource_policy=policy,
        admin_user=os.environ.get("DEVFLEET_ADMIN_USER", ""),
        admin_password=os.environ.get("DEVFLEET_ADMIN_PASSWORD", ""),
        api_token=os.environ.get("DEVFLEET_API_TOKEN", ""),
        require_tailscale=bool(cfg.get("require_tailscale", cfg.get("RequireTailscale", True))),
        tailnet_cidr=str(cfg.get("tailnet_cidr", cfg.get("TailnetCidr", "100.64.0.0/10"))),
        public_binding_allowed=bool(cfg.get("public_binding_allowed", cfg.get("PublicBindingAllowed", False))),
    )


SETTINGS = load_settings()


_ROOTLESS_DOCKER_HOST = re.compile(r"^unix:///run/user/(?P<uid>[1-9][0-9]*)/docker\.sock$")


def _expected_docker_owner_uid() -> int:
    if SETTINGS.docker_owner_uid is not None:
        return SETTINGS.docker_owner_uid
    if pwd is not None:
        try:
            return int(pwd.getpwnam("devrunner").pw_uid)
        except KeyError:
            pass
    raise RuntimeError("Rootless Docker owner identity is not configured; refusing to guess from the controller UID.")


def _validate_rootless_docker_host(raw: str) -> str:
    match = _ROOTLESS_DOCKER_HOST.fullmatch(str(raw or "").strip())
    if not match:
        raise RuntimeError("Rootless Docker requires an explicit unix:///run/user/<devrunner-uid>/docker.sock endpoint.")
    configured_uid = int(match.group("uid"))
    expected_uid = _expected_docker_owner_uid()
    if configured_uid != expected_uid:
        raise RuntimeError("Configured Docker socket UID is not the authoritative devrunner owner UID.")
    socket_path = Path(raw[len("unix://"):])
    try:
        socket_stat = os.lstat(socket_path)
    except OSError as exc:
        raise RuntimeError("Configured rootless Docker socket is missing or unreadable.") from exc
    if stat.S_ISLNK(socket_stat.st_mode) or not stat.S_ISSOCK(socket_stat.st_mode):
        raise RuntimeError("Configured rootless Docker endpoint is not a Unix socket.")
    if int(socket_stat.st_uid) != expected_uid:
        raise RuntimeError("Configured rootless Docker socket has an unexpected owner.")
    return raw


def client_allowed_by_network(host: str | None) -> bool:
    """Enforce the configured portal boundary using the TCP peer address.

    Loopback is always allowed for local bootstrap/proxy operations.  When the
    portal requires Tailscale, only the configured tailnet CIDR is accepted;
    arbitrary RFC1918 peers are deliberately not treated as trusted.
    """
    if SETTINGS.public_binding_allowed or not SETTINGS.require_tailscale:
        return True
    try:
        address = ipaddress.ip_address(str(host or "").split("%", 1)[0])
        if address.is_loopback:
            return True
        return address in ipaddress.ip_network(SETTINGS.tailnet_cidr, strict=False)
    except ValueError:
        return False


def validate_slug(value: str) -> str:
    value = str(value or "").strip().lower()
    if not SLUG_RE.fullmatch(value):
        raise ValueError("Project slug must be 2-63 lowercase letters, numbers, dots, underscores, or dashes.")
    return value


def validate_project_id(value: str) -> str:
    value = str(value or "").strip()
    if not PROJECT_ID_RE.fullmatch(value):
        raise ValueError("Project id must be a UUID-shaped value.")
    return value


def safe_child(base: Path, name: str) -> Path:
    slug = validate_slug(name)
    base_real = base.resolve()
    lexical = base_real / slug
    if lexical.is_symlink():
        raise ValueError("Project path may not be a symbolic link.")
    candidate = lexical.resolve(strict=False)
    if candidate.parent != base_real or candidate.name != slug:
        raise ValueError("Unsafe project path.")
    return candidate


def run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 900,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a known executable with bounded time and captured output."""
    if not cmd or any(not isinstance(part, str) or not part for part in cmd):
        raise ValueError("Command arguments must be non-empty strings.")
    env = os.environ.copy()
    executable = Path(cmd[0]).name.lower()
    if SETTINGS.docker_mode == "rootless" and executable in {"docker", "docker.exe"}:
        env["DOCKER_HOST"] = _validate_rootless_docker_host(env.get("DOCKER_HOST") or SETTINGS.docker_host)
    elif SETTINGS.docker_mode != "rootless":
        env.pop("DOCKER_HOST", None)
    try:
        result = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env,
            text=True,
            capture_output=True,
            timeout=max(1, int(timeout)),
            check=False,
        )
    except FileNotFoundError as exc:
        if check:
            raise RuntimeError(f"Command not found: {cmd[0]}") from exc
        return subprocess.CompletedProcess(cmd, 127, "", str(exc))
    except subprocess.TimeoutExpired as exc:
        detail = ((exc.stdout or "") + "\n" + (exc.stderr or ""))[-2000:]
        if check:
            raise RuntimeError(f"Command timed out after {timeout}s: {cmd[0]}\n{detail}") from exc
        return subprocess.CompletedProcess(cmd, 124, exc.stdout or "", exc.stderr or "timeout")
    if check and result.returncode:
        detail = (result.stderr or result.stdout or "")[-4000:]
        raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(cmd)}\n{detail}")
    return result


def _atomic_replace(temp_name: str, path: Path) -> None:
    deadline = time.monotonic() + 0.5
    while True:
        try:
            os.replace(temp_name, path)
            return
        except PermissionError as exc:
            if getattr(exc, "winerror", None) not in {5, 32, 33} or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        _atomic_replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _atomic_replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def atomic_json(path: Path, data: Any) -> None:
    atomic_text(path, json.dumps(data, indent=2, sort_keys=True, default=str) + "\n")


def load_peer() -> dict[str, Any]:
    try:
        data = json.loads(SETTINGS.peer_file.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
