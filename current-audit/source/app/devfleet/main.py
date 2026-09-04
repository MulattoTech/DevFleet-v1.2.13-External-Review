from __future__ import annotations
from urllib.parse import quote, urlsplit
import hashlib, html, hmac, json, logging, os, re
from pathlib import Path
from typing import Any
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import httpx
from .auth import (
    LOGIN_CSRF_COOKIE,
    SESSION_COOKIE,
    check_api,
    check_session,
    issue_session,
    login_csrf_token,
    login_retry_after,
    revoke_session,
    safe_next,
    session_cookie_options,
    session_csrf_token,
    session_user,
    validate_login_csrf,
    valid_credentials,
)
from .core import (
    SETTINGS,
    load_peer,
    safe_child,
    validate_slug,
    atomic_json,
    run,
    client_allowed_by_network,
)
from .projects import (
    create_project,
    project_identity,
    start_project,
    stop_project,
    restart_project,
    inspect_runtime,
    runtime_health,
    open_workspace,
    rebuild_project,
    quarantine_project,
    destroy_project,
    list_backups,
    restore_backup,
    list_quarantine,
    restore_quarantine,
    restore_from_vault,
    backup_project,
    test_project,
    load_meta,
    metadata_path,
    project_logs,
    bootstrap_codexpro,
    bootstrap_project,
    health_project,
    assign_project_runtime,
    detect_runtime,
    project_command_readiness,
    project_capabilities,
    reconcile_failed_migration,
)
from .status import (
    cluster_snapshot,
    local_status,
    peer_status,
    peer_node_status,
    runtime_status,
    cluster_status,
)
from .containers import (
    container_action,
    container_logs,
    inspect_container,
    list_containers,
    validate_container_ref,
)
from .operations import submit_operation, get_operation, list_operations
from .analyzer import analyze_project
from .language_policy import TEMPLATES, recommend_template
from .resource_profiles import (
    RESOURCE_PROFILES,
    RUNTIME_ISOLATIONS,
    capacity_allows,
    custom_resource_metadata,
    recommend_resource_profile,
    recommend_runtime_isolation,
)
from .host_control import host_control_status, get_host_capacity, get_provider_status
from .failover import guided_transfer
from .workspace_archives import inspect_workspace
from .request_guards import RequestAdmissionMiddleware
from .version import __version__

app = FastAPI(title="DevFleet", version=__version__, docs_url=None, redoc_url=None)
LOGGER = logging.getLogger("devfleet")
templates = Jinja2Templates(
    directory=str(
        Path(os.environ.get("DEVFLEET_TEMPLATE_DIR", "/opt/devfleet/templates"))
    )
)
app.mount(
    "/static",
    StaticFiles(
        directory=str(
            Path(os.environ.get("DEVFLEET_STATIC_DIR", "/opt/devfleet/static"))
        ),
        check_dir=True,
    ),
    name="static",
)
app.add_middleware(RequestAdmissionMiddleware)


def ui_csrf_token(request: Request | None = None) -> str:
    if request is None:
        raise ValueError("A request-bound session is required for UI CSRF generation.")
    return session_csrf_token(request)


def valid_ui_csrf(value: str, request: Request | None = None) -> bool:
    expected = ui_csrf_token(request)
    return bool(value and expected) and hmac.compare_digest(value, expected)


@app.middleware("http")
async def headers(request: Request, call_next):
    started = __import__("time").perf_counter()
    response = await call_next(request)
    duration = (__import__("time").perf_counter() - started) * 1000
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = (
        "public, max-age=31536000, immutable"
        if request.url.path.startswith("/static/")
        else "no-store"
    )
    response.headers["Server-Timing"] = f"app;dur={duration:.2f}"
    response.headers["X-DevFleet-Render-Ms"] = f"{duration:.2f}"
    return response


@app.middleware("http")
async def network_guard(request: Request, call_next):
    if not client_allowed_by_network(request.client.host if request.client else None):
        return JSONResponse(
            {
                "detail": "Portal access is restricted to loopback and the configured Tailscale network."
            },
            status_code=403,
        )
    return await call_next(request)


def _human_ui_route(path: str) -> bool:
    return path == "/" or path.startswith(
        (
            "/projects",
            "/cluster",
            "/containers",
            "/peer",
            "/operations",
            "/ui",
            "/quarantine",
            "/repair",
        )
    )


@app.middleware("http")
async def session_guard(request: Request, call_next):
    if _human_ui_route(request.url.path) and not session_user(request):
        target = request.url.path + (
            (f"?{request.url.query}") if request.url.query else ""
        )
        return RedirectResponse(
            "/login?next=" + quote(safe_next(target), safe="/?:=&%"), status_code=303
        )
    return await call_next(request)


def ui(request: Request, csrf_token: str = ""):
    check_session(request)
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        if not valid_ui_csrf(csrf_token, request):
            raise HTTPException(403, "A valid session CSRF token is required.")
        expected = f"{request.url.scheme}://{request.url.netloc}"
        origin = request.headers.get("origin", "").strip()
        referer = request.headers.get("referer", "").strip()
        candidate = origin if origin.lower() not in {"", "null"} else referer
        if candidate:
            try:
                p = urlsplit(candidate)
                request_parts = urlsplit(expected)
                same_scheme = p.scheme.lower() == request_parts.scheme.lower()
                same_host = (p.hostname or "").lower() == (
                    request_parts.hostname or ""
                ).lower()

                def effective_port(parts):
                    if parts.port is not None:
                        return parts.port
                    return {"http": 80, "https": 443}.get(parts.scheme.lower())

                same_port = effective_port(p) == effective_port(request_parts)
            except ValueError:
                same_scheme = same_host = same_port = False
            if not (same_scheme and same_host and same_port):
                LOGGER.warning(
                    "Rejected form origin: origin=%r referer=%r fetch_site=%r fetch_mode=%r fetch_dest=%r scheme=%r host=%r path=%r user_agent=%r",
                    origin,
                    referer,
                    request.headers.get("sec-fetch-site", ""),
                    request.headers.get("sec-fetch-mode", ""),
                    request.headers.get("sec-fetch-dest", ""),
                    request.url.scheme,
                    request.headers.get("host", ""),
                    request.url.path,
                    request.headers.get("user-agent", ""),
                )
                raise HTTPException(403, "Cross-origin form submission rejected.")
        elif request.headers.get("sec-fetch-site", "").lower() != "same-origin":
            LOGGER.warning(
                "Rejected unverifiable form: origin=%r referer=%r fetch_site=%r fetch_mode=%r fetch_dest=%r scheme=%r host=%r path=%r user_agent=%r",
                origin,
                referer,
                request.headers.get("sec-fetch-site", ""),
                request.headers.get("sec-fetch-mode", ""),
                request.headers.get("sec-fetch-dest", ""),
                request.url.scheme,
                request.headers.get("host", ""),
                request.url.path,
                request.headers.get("user-agent", ""),
            )
            raise HTTPException(403, "Cross-origin form submission rejected.")


def peer_call(
    method: str, path: str, payload: dict | None = None, timeout: float = 1800
):
    peer = load_peer()
    if not peer.get("Url") or not peer.get("Token"):
        raise ValueError("Peer is not configured.")
    with httpx.Client(timeout=timeout) as client:
        r = client.request(
            method,
            peer["Url"].rstrip("/") + path,
            headers={"X-DevFleet-Token": peer["Token"]},
            json=payload or {},
        )
        if r.status_code >= 400:
            raise ValueError(f"Peer error {r.status_code}: {r.text[-1000:]}")
        return r.json()


def require_safe_start(slug: str, confirmed: bool) -> None:
    identity = project_identity(slug)
    project = safe_child(SETTINGS.workspaces, slug)
    try:
        lease = __import__("json").loads(
            (project / ".devfleet/ownership-lease.json").read_text()
        )
    except Exception:
        lease = {}
    if (
        lease.get("active")
        and lease.get("active_node")
        and lease.get("active_node") != SETTINGS.node_name
        and not confirmed
    ):
        raise ValueError(
            f"Ownership lease belongs to {lease.get('active_node')}. Use guided transfer or acknowledge failover risk."
        )
    meta = load_meta(project)
    # A project already owned by this node is not a failover operation.  The
    # peer may be offline while the local VM/container still needs an ordinary
    # start or rebuild.  Foreign ownership leases remain blocked above.
    local_host_ids = {
        str(SETTINGS.node_name or "").strip().lower(),
        str(SETTINGS.expected_host_name or "").strip().lower(),
    }
    recorded_host = str(meta.get("host_id") or "").strip().lower()
    if recorded_host in local_host_ids and str(meta.get("runtime_provider") or "") in {
        "",
        "docker-compose",
        "multipass-host-agent",
    }:
        return
    state = peer_status()
    if not state.get("configured"):
        return
    if not state.get("ok") and not confirmed:
        raise ValueError(
            "Peer is unreachable. Confirm failover risk only after verifying the project is not active there."
        )
    if state.get("ok"):
        matches = [
            x
            for x in state["peer"].get("projects", [])
            if (x.get("identity") or x.get("slug")) == identity
        ]
        if (
            any(
                x.get("running") or (x.get("lease") or {}).get("active")
                for x in matches
            )
            and not confirmed
        ):
            raise ValueError(
                "Peer reports this project running or holding the active ownership lease. Use guided ownership transfer or explicitly acknowledge failover risk."
            )


PROJECT_READ_ONLY_ACTIONS = frozenset({
    "inspect",
    "runtime-health",
    "logs",
})
PROJECT_MUTATING_ACTIONS = frozenset({
    "start",
    "stop",
    "restart",
    "rebuild",
    "backup",
    "bootstrap",
    "health",
    "test",
    "codexpro",
    "quarantine",
    "destroy",
    "restore-vault",
    "restore-backup",
    "analyze-force",
    "reconcile-failed-migration",
})
PROJECT_ACTIONS = PROJECT_READ_ONLY_ACTIONS | PROJECT_MUTATING_ACTIONS


def _project_action_task(slug: str, action: str, payload: dict[str, Any]):
    def task(ctx):
        def progress(value: int, message: str, step: str | None = None) -> None:
            if ctx is not None:
                ctx.update(value, message, step)

        if action == "start":
            progress(10, "Checking ownership and analyzer")
            require_safe_start(slug, bool(payload.get("confirm_failover")))
            progress(35, "Building and starting project services")
            result = start_project(slug, bool(payload.get("confirm_failover")))
        elif action == "stop":
            progress(20, "Stopping project services")
            result = stop_project(slug)
        elif action == "restart":
            progress(20, "Restarting project runtime")
            result = restart_project(slug)
        elif action == "inspect":
            progress(25, "Inspecting project runtime")
            result = inspect_runtime(slug)
        elif action == "runtime-health":
            progress(25, "Checking project runtime health")
            result = runtime_health(slug)
        elif action == "rebuild":
            progress(10, "Checking ownership and analyzer")
            require_safe_start(slug, bool(payload.get("confirm_failover")))
            progress(30, "Rebuilding project images and services")
            result = rebuild_project(slug)
        elif action == "backup":
            progress(15, "Creating append-only encrypted backup")
            result = backup_project(slug)
        elif action == "bootstrap":
            progress(15, "Installing project dependencies")
            result = bootstrap_project(slug)
        elif action == "health":
            progress(25, "Running project health check")
            result = health_project(slug)
        elif action == "test":
            progress(15, "Running project test command")
            result = test_project(slug)
        elif action == "codexpro":
            progress(15, "Checking and bootstrapping CodexPro")
            result = bootstrap_codexpro(slug)
        elif action == "logs":
            progress(20, "Reading bounded project logs")
            result = project_logs(slug)
        elif action == "quarantine":
            progress(10, "Stopping project and verifying backup before quarantine")
            result = quarantine_project(slug)
        elif action == "destroy":
            progress(10, "Creating and verifying backup before permanent destruction")
            result = destroy_project(slug, str(payload.get("confirm_slug") or ""), str(payload.get("confirm_phrase") or ""))
        elif action == "restore-vault":
            progress(10, "Restoring project from encrypted vault")
            result = restore_from_vault(slug, bool(payload.get("canonical")))
        elif action == "restore-backup":
            progress(10, "Verifying backup identity and archive hash")
            result = restore_backup(slug, str(payload.get("backup_id") or ""), confirm_restore=True, allow_overwrite=bool(payload.get("allow_overwrite")))
        elif action == "analyze-force":
            progress(20, "Running complete uncached analyzer scan")
            result = analyze_project(safe_child(SETTINGS.workspaces, slug), force=True)
        elif action == "reconcile-failed-migration":
            progress(10, "Reconciling failed migration ownership")
            result = reconcile_failed_migration(slug, str(payload.get("migration_snapshot") or ""), str(payload.get("confirm_phrase") or ""))
        else:
            raise ValueError("Unknown action.")
        if ctx is not None:
            ctx.log(str(result)[-4000:])
            ctx.update(90, "Operation command completed")
        return result

    return task


def _action_idempotency_key(slug: str, action: str, payload: dict[str, Any], supplied: str = "") -> str:
    supplied = str(supplied or payload.get("idempotency_key") or "").strip()
    if supplied and not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", supplied):
        raise HTTPException(400, "Idempotency key must be 1-128 safe identifier characters.")
    if supplied:
        return f"project-action:{slug}:{action}:{supplied}"
    if action in {"start", "stop", "restart"}:
        return f"project-action:{slug}:{action}"
    if action == "restore-backup" and payload.get("backup_id"):
        return f"project-action:{slug}:{action}:{payload['backup_id']}"
    return ""


def redirect(op_id: str):
    return RedirectResponse("/?operation=" + op_id, 303)


def _form_resource_limits(
    profile: str, cpus: str, ram_gb: str, disk_gb: str, pid_limit: str, pid_mode: str
) -> dict | None:
    # Presets deliberately ignore custom fields: browsers retain hidden inputs and
    # an old custom value must never silently override a selected preset.
    profile = str(profile or "").strip().lower()
    if profile and profile != "custom":
        if profile not in RESOURCE_PROFILES:
            raise HTTPException(400, "Unknown resource profile.")
        return None
    if profile == "custom":
        try:
            return custom_resource_metadata(
                {
                    "cpus": cpus,
                    "memory_gb": ram_gb,
                    "disk_gb": disk_gb,
                    "pids": pid_limit,
                    "pid_mode": pid_mode,
                }
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
    values = {
        "cpus": cpus,
        "memory_gb": ram_gb,
        "disk_gb": disk_gb,
        "pids": pid_limit,
        "pid_mode": pid_mode,
    }
    if (
        not any(str(value or "").strip() for value in (cpus, ram_gb, disk_gb))
        and str(pid_limit or "4096") == "4096"
        and str(pid_mode or "private") == "private"
    ):
        return None
    selected = (
        RESOURCE_PROFILES.get(str(profile or "").lower())
        or RESOURCE_PROFILES["standard"]
    )
    return {
        "cpus": cpus or selected.cpus,
        "memory_gb": ram_gb or selected.memory_gb,
        "disk_gb": disk_gb or selected.disk_gb,
        "pids": pid_limit or selected.pids,
        "pid_mode": pid_mode or "private",
    }


def ui_wants_json(request: Request) -> bool:
    return (
        "application/json" in request.headers.get("accept", "").lower()
        or "x-devfleet-ui" in request.headers
    )


def _preflight(
    slug: str,
    runtime_isolation: str = "",
    resource_profile: str = "",
    custom_cpus: str = "",
    custom_ram_gb: str = "",
    custom_disk_gb: str = "",
    pid_mode: str = "private",
    pid_limit: str = "4096",
) -> dict:
    project = safe_child(SETTINGS.workspaces, slug)
    meta = load_meta(project)
    inspection = inspect_workspace(project)
    selected = str(
        runtime_isolation or meta.get("runtime_isolation") or "container"
    ).lower()
    blockers = []
    warnings = []
    if selected not in {"container", "vm"}:
        blockers.append("Choose a supported environment type.")
    selected_profile = str(
        resource_profile or meta.get("resource_profile") or "standard"
    ).lower()
    try:
        limits = _form_resource_limits(
            selected_profile,
            custom_cpus,
            custom_ram_gb,
            custom_disk_gb,
            pid_limit,
            pid_mode,
        )
        if limits is None:
            profile = RESOURCE_PROFILES.get(
                selected_profile
            ) or recommend_resource_profile(
                scale=str(meta.get("project_scale") or ""),
                intent=str(meta.get("intent") or ""),
                project_kind=str(meta.get("project_kind") or ""),
                language=str(meta.get("language") or ""),
                framework=str(meta.get("framework") or ""),
            )
            selected_profile = profile.name
            limits = profile.limits(selected)
    except HTTPException as exc:
        limits = {}
        blockers.append(str(exc.detail))
    try:
        capacity_result = get_host_capacity()
        capacity = (
            capacity_result.get("capacity", capacity_result)
            if isinstance(capacity_result, dict)
            else {}
        )
    except Exception as exc:
        capacity = {"status": "unavailable", "error": str(exc)[-500:]}
        blockers.append("Host capacity could not be inspected.")
    capacity_ready = False
    if limits and isinstance(capacity, dict):
        capacity_ready, reason = capacity_allows(capacity, limits)
        if not capacity_ready:
            blockers.append(reason)
    archive_ready = bool(inspection.get("safe_for_archive"))
    if not archive_ready:
        blockers.append("Workspace contains symlinks and cannot be safely archived.")
    compose_ready = (
        selected == "vm"
        or (project / "compose.yaml").is_file()
        or (project / "docker-compose.yml").is_file()
        or (project / "docker-compose.yaml").is_file()
    )
    if not compose_ready:
        blockers.append("Container assignment requires a supported Compose file.")
    worktree_ready = not (selected == "vm" and bool(meta.get("worktree")))
    if not worktree_ready:
        blockers.append("Linked Git worktrees cannot be assigned to a dedicated VM.")
    command_readiness = project_command_readiness(project)
    lifecycle_commands_ready = selected != "vm" or bool(command_readiness.get("ready"))
    if not lifecycle_commands_ready:
        missing = ", ".join(command_readiness.get("missing_required") or [])
        invalid = ", ".join((command_readiness.get("invalid_required") or {}).keys())
        detail = "; ".join(
            part
            for part in (
                f"missing {missing}" if missing else "",
                f"unsafe or unsupported {invalid}" if invalid else "",
            )
            if part
        )
        blockers.append(
            "Dedicated VM lifecycle commands are not ready"
            + (f": {detail}" if detail else ".")
        )
    inspection_ok = True
    migration_ready = (
        inspection_ok
        and archive_ready
        and compose_ready
        and worktree_ready
        and lifecycle_commands_ready
        and capacity_ready
        and not blockers
    )
    return {
        "ok": migration_ready,
        "read_only": True,
        "project_id": meta.get("project_id"),
        "slug": slug,
        "workspace": inspection,
        "current_runtime": detect_runtime(slug),
        "selected_environment": selected,
        "selected_resource_profile": selected_profile,
        "selected_limits": limits,
        "capacity": capacity,
        "inspection_ok": inspection_ok,
        "migration_ready": migration_ready,
        "capacity_ready": capacity_ready,
        "archive_ready": archive_ready,
        "compose_ready": compose_ready,
        "worktree_ready": worktree_ready,
        "lifecycle_commands_ready": lifecycle_commands_ready,
        "lifecycle_commands": command_readiness,
        "blockers": blockers,
        "warnings": warnings,
        "target_vm_name": (
            f"devfleet-project-{slug}"
            if len(f"devfleet-project-{slug}") <= 60
            else "deterministic-name-hashed-by-host-agent"
        ),
        "migration_would_be_performed": False,
    }


def operation_or_404(op_id: str) -> dict:
    try:
        return get_operation(op_id)
    except (FileNotFoundError, ValueError):
        raise HTTPException(404, "Operation not found.")


@app.get("/healthz")
def healthz():
    return {"ok": True, "service": "devfleet", "agent_version": __version__}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/"):
    token = login_csrf_token()
    response = templates.TemplateResponse(
        request,
        "login.html",
        {
            "csrf_token": token,
            "next": safe_next(next),
            "version": __version__,
            "error": "",
        },
    )
    response.set_cookie(
        LOGIN_CSRF_COOKIE,
        token,
        max_age=600,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )
    return response


@app.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    next: str = Form("/"),
    keep_signed_in: bool = Form(False),
    csrf_token: str = Form(""),
):
    target = safe_next(next)
    source = request.client.host if request.client else None

    def rejected(
        status_code: int = 401,
        error: str = "The username, password, or sign-in form token was not accepted.",
    ):
        token = request.cookies.get(LOGIN_CSRF_COOKIE) or login_csrf_token()
        response = templates.TemplateResponse(
            request,
            "login.html",
            {
                "csrf_token": token,
                "next": target,
                "version": __version__,
                "error": error,
            },
            status_code=status_code,
        )
        response.set_cookie(
            LOGIN_CSRF_COOKIE,
            token,
            max_age=600,
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            path="/",
        )
        return response

    if not validate_login_csrf(request.cookies.get(LOGIN_CSRF_COOKIE), csrf_token):
        return rejected()
    if not valid_credentials(username, password, source=source):
        retry_after = login_retry_after(username, source)
        if retry_after:
            response = rejected(429, "Too many sign-in attempts. Try again shortly.")
            response.headers["Retry-After"] = str(retry_after)
            return response
        return rejected()
    token, ttl, _csrf = issue_session(username, keep_signed_in)
    response = RedirectResponse(target, 303)
    response.set_cookie(
        SESSION_COOKIE, token, max_age=ttl, **session_cookie_options(request)
    )
    response.delete_cookie(LOGIN_CSRF_COOKIE, path="/")
    return response


@app.post("/logout")
def logout(request: Request, csrf_token: str = Form("")):
    ui(request, csrf_token)
    revoke_session(request.cookies.get(SESSION_COOKIE))
    response = RedirectResponse("/login?logged_out=1", 303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.get("/api/status", dependencies=[Depends(check_api)])
def api_status(refresh: bool = False):
    return local_status(live=refresh)


@app.get("/api/node/status", dependencies=[Depends(check_api)])
def api_node_status():
    return runtime_status()


@app.get("/api/host/status", dependencies=[Depends(check_api)])
def api_host_status():
    return host_control_status()


@app.get("/api/host/capacity", dependencies=[Depends(check_api)])
def api_host_capacity():
    try:
        return get_host_capacity()
    except Exception as exc:
        return {"ok": False, "status": "unavailable", "error": str(exc)[-500:]}


@app.get("/api/provider/status", dependencies=[Depends(check_api)])
def api_provider_status():
    try:
        return get_provider_status()
    except Exception as exc:
        return {"ok": False, "status": "unavailable", "error": str(exc)[-500:]}


@app.get("/api/cluster/status", dependencies=[Depends(check_api)])
def api_cluster_status():
    return cluster_status()


@app.get("/api/containers", dependencies=[Depends(check_api)])
def api_containers():
    return {"containers": list_containers()}


@app.get("/api/containers/{container_ref}/inspect", dependencies=[Depends(check_api)])
def api_container_inspect(container_ref: str):
    try:
        return inspect_container(container_ref)
    except ValueError as exc:
        raise HTTPException(403, "Container is not an authorized DevFleet-owned resource.") from exc


@app.get("/api/containers/{container_ref}/logs", dependencies=[Depends(check_api)])
def api_container_logs(container_ref: str, tail: int = 200):
    try:
        return {"logs": container_logs(container_ref, tail)}
    except ValueError as exc:
        raise HTTPException(403, "Container is not an authorized DevFleet-owned resource.") from exc


@app.post("/api/containers/{container_ref}/{action}", dependencies=[Depends(check_api)])
def api_container_action(container_ref: str, action: str, payload: dict | None = None):
    payload = payload or {}
    if action == "remove" and not payload.get("confirm_remove"):
        raise HTTPException(400, "Removing a container requires explicit confirmation.")
    try:
        return {"ok": True, "output": container_action(container_ref, action)}
    except ValueError as exc:
        raise HTTPException(403, "Container is not an authorized DevFleet-owned resource.") from exc


@app.get("/cluster/status")
def cluster_status_ui(request: Request, refresh: bool = False):
    ui(request)
    return JSONResponse(cluster_status() if refresh else cluster_snapshot())


@app.get("/containers/{container_ref}/inspect")
def container_inspect_ui(request: Request, container_ref: str):
    ui(request)
    try:
        return JSONResponse(inspect_container(container_ref))
    except ValueError as exc:
        raise HTTPException(403, "Container is not an authorized DevFleet-owned resource.") from exc


@app.get("/containers/{container_ref}/logs")
def container_logs_ui(request: Request, container_ref: str, tail: int = 200):
    ui(request)
    try:
        return JSONResponse({"logs": container_logs(container_ref, tail)})
    except ValueError as exc:
        raise HTTPException(403, "Container is not an authorized DevFleet-owned resource.") from exc


@app.get("/peer/containers/{container_ref}/inspect")
def peer_container_inspect_ui(request: Request, container_ref: str):
    ui(request)
    return JSONResponse(
        peer_call(
            "GET", f"/api/containers/{validate_container_ref(container_ref)}/inspect"
        )
    )


@app.get("/peer/containers/{container_ref}/logs")
def peer_container_logs_ui(request: Request, container_ref: str, tail: int = 200):
    ui(request)
    return JSONResponse(
        peer_call(
            "GET",
            f"/api/containers/{validate_container_ref(container_ref)}/logs?tail={max(1,min(int(tail),1000))}",
        )
    )


@app.post("/containers/{container_ref}/{action}")
def container_action_ui(
    request: Request,
    container_ref: str,
    action: str,
    confirm_remove: bool = Form(False),
    csrf_token: str = Form(""),
):
    ui(request, csrf_token)
    if action == "remove" and not confirm_remove:
        raise HTTPException(400, "Removing a container requires explicit confirmation.")
    try:
        return JSONResponse({"ok": True, "output": container_action(container_ref, action)})
    except ValueError as exc:
        raise HTTPException(403, "Container is not an authorized DevFleet-owned resource.") from exc


@app.post("/peer/containers/{container_ref}/{action}")
def peer_container_action_ui(
    request: Request,
    container_ref: str,
    action: str,
    confirm_remove: bool = Form(False),
    csrf_token: str = Form(""),
):
    ui(request, csrf_token)
    if action == "remove" and not confirm_remove:
        raise HTTPException(400, "Removing a container requires explicit confirmation.")
    return JSONResponse(
        {
            "ok": True,
            "output": peer_call(
                "POST",
                f"/api/containers/{validate_container_ref(container_ref)}/{action}",
                {"confirm_remove": bool(confirm_remove)},
            ),
        }
    )


@app.get("/api/operations", dependencies=[Depends(check_api)])
def api_operations():
    return {"operations": list_operations()}


@app.get("/api/operations/{op_id}", dependencies=[Depends(check_api)])
def api_operation(op_id: str):
    return operation_or_404(op_id)


@app.get("/operations/{op_id}")
def operation_ui(request: Request, op_id: str):
    ui(request)
    return operation_or_404(op_id)


@app.get("/ui/operations/{op_id}")
def ui_operation(request: Request, op_id: str):
    ui(request)
    return JSONResponse(operation_or_404(op_id))


@app.get("/", response_class=HTMLResponse)
def index(
    request: Request, operation: str = "", view: str = "overview", project: str = ""
):
    ui(request)
    op = None
    if operation:
        try:
            op = get_operation(operation)
        except Exception:
            pass
    status = local_status()
    cluster = cluster_snapshot()
    peer_node = next(
        (
            node
            for node in cluster.get("nodes", [])
            if node.get("id") == "devfleet-failover"
        ),
        {},
    )
    peer = {
        "configured": bool(peer_node),
        "ok": bool(peer_node.get("reachable")),
        "peer": peer_node,
        "status": peer_node.get("status", "unavailable"),
        "error": peer_node.get("error", ""),
    }
    allowed_views = {
        "overview",
        "projects",
        "project",
        "infrastructure",
        "activity",
        "settings",
    }
    selected_view = view if view in allowed_views else "overview"
    selected_project = next(
        (item for item in status.get("projects", []) if item.get("slug") == project),
        None,
    )
    if selected_view == "project" and selected_project is None:
        raise HTTPException(404, "Project not found.")
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "status": status,
            "version": __version__,
            "peer": peer,
            "cluster": cluster,
            "quarantine": list_quarantine() if SETTINGS.quarantine.exists() else [],
            "templates_catalog": TEMPLATES,
            "operation": op,
            "csrf_token": ui_csrf_token(request),
            "view": selected_view,
            "selected_project": selected_project,
            "resource_profiles": RESOURCE_PROFILES,
            "runtime_isolations": RUNTIME_ISOLATIONS,
        },
    )


@app.get("/api/templates/recommend", dependencies=[Depends(check_api)])
def api_recommend(
    language: str = "",
    framework: str = "",
    scale: str = "",
    intent: str = "",
    project_kind: str = "",
):
    return {
        "template": recommend_template(language, framework, scale, intent, project_kind)
    }


@app.get("/api/runtime/recommend", dependencies=[Depends(check_api)])
def api_runtime_recommend(
    language: str = "",
    framework: str = "",
    scale: str = "",
    intent: str = "",
    project_kind: str = "",
):
    resource = recommend_resource_profile(
        scale=scale,
        intent=intent,
        project_kind=project_kind,
        language=language,
        framework=framework,
    )
    return {
        "resource_profile": resource.name,
        "resource_limits": resource.__dict__,
        "runtime_isolation": recommend_runtime_isolation(
            scale=scale, intent=intent, project_kind=project_kind
        ),
        "runtime_options": RUNTIME_ISOLATIONS,
    }


@app.post("/projects/create")
def project_create(
    request: Request,
    slug: str = Form(...),
    display_name: str = Form(""),
    template: str = Form("auto"),
    git_url: str = Form(""),
    target: str = Form("local"),
    language: str = Form(""),
    framework: str = Form(""),
    scale: str = Form("small"),
    intent: str = Form("prototype"),
    testing_level: str = Form("standard"),
    profile: str = Form("balanced"),
    resource_profile: str = Form(""),
    runtime_isolation: str = Form(""),
    use_ollama: bool = Form(False),
    worktree_source: str = Form(""),
    worktree_branch: str = Form(""),
    project_kind: str = Form(""),
    custom_cpus: str = Form(""),
    custom_ram_gb: str = Form(""),
    custom_disk_gb: str = Form(""),
    pid_mode: str = Form("private"),
    pid_limit: str = Form("4096"),
    csrf_token: str = Form(""),
):
    ui(request, csrf_token)
    payload = {
        "slug": slug,
        "display_name": display_name,
        "template": template,
        "git_url": git_url,
        "language": language,
        "framework": framework,
        "scale": scale,
        "intent": intent,
        "testing_level": testing_level,
        "profile": profile,
        "resource_profile": resource_profile,
        "resource_limits": _form_resource_limits(
            resource_profile,
            custom_cpus,
            custom_ram_gb,
            custom_disk_gb,
            pid_limit,
            pid_mode,
        ),
        "runtime_isolation": runtime_isolation,
        "use_ollama": use_ollama,
        "worktree_source": worktree_source,
        "worktree_branch": worktree_branch,
        "project_kind": project_kind,
    }
    if profile == "fast":
        raise HTTPException(
            400,
            "Use the explicit Fast profile acknowledgement after creating the project in Balanced mode.",
        )

    def task(ctx):
        ctx.update(10, "Validating project request", "validate")
        result = (
            peer_call("POST", "/api/projects/create", payload)
            if target == "peer"
            else create_project(operation_context=ctx, **payload)
        )
        ctx.update(90, "Project runtime provisioned", "verify")
        return result

    return redirect(
        submit_operation("peer-create" if target == "peer" else "create", slug, task)
    )


@app.get("/projects/{slug}", response_class=HTMLResponse)
def project_page(request: Request, slug: str):
    ui(request)
    return index(
        request,
        operation=request.query_params.get("operation", ""),
        view="project",
        project=slug,
    )


@app.get("/projects/{slug}/workspace")
def project_workspace(request: Request, slug: str):
    ui(request)
    result = open_workspace(slug)
    if not result.get("ok"):
        raise HTTPException(
            409, str(result.get("error") or "Workspace is not ready to open.")
        )
    return RedirectResponse(str(result["launcher_uri"]), status_code=307)


@app.post("/projects/{slug}/environment")
def project_environment(
    request: Request,
    slug: str,
    runtime_isolation: str = Form("container"),
    resource_profile: str = Form(""),
    custom_cpus: str = Form(""),
    custom_ram_gb: str = Form(""),
    custom_disk_gb: str = Form(""),
    pid_mode: str = Form("private"),
    pid_limit: str = Form("4096"),
    wizard_confirmed: bool = Form(False),
    csrf_token: str = Form(""),
):
    ui(request, csrf_token)
    if not wizard_confirmed:
        raise HTTPException(
            400,
            "Complete the Environment, Resources, Review, and Confirm stages before applying this assignment.",
        )
    preflight = _preflight(
        slug,
        runtime_isolation,
        resource_profile,
        custom_cpus,
        custom_ram_gb,
        custom_disk_gb,
        pid_mode,
        pid_limit,
    )
    if not preflight["migration_ready"]:
        raise HTTPException(
            409,
            "Environment preflight is not ready: " + "; ".join(preflight["blockers"]),
        )
    limits = _form_resource_limits(
        resource_profile,
        custom_cpus,
        custom_ram_gb,
        custom_disk_gb,
        pid_limit,
        pid_mode,
    )

    def task(ctx):
        ctx.update(
            8, "Validating the existing workspace and selected environment", "validate"
        )
        result = assign_project_runtime(
            slug, runtime_isolation, resource_profile, limits, operation_context=ctx
        )
        ctx.log(json.dumps(result, default=str)[-4000:])
        return result

    operation_id = submit_operation(
        "runtime-adoption",
        slug,
        task,
        idempotency_key=f'runtime-adoption:{slug}:{runtime_isolation}:{resource_profile or "current"}',
    )
    if ui_wants_json(request):
        return JSONResponse(
            {
                "ok": True,
                "operation_id": operation_id,
                "message": "Environment assignment queued.",
            },
            status_code=202,
        )
    return redirect(operation_id)


@app.post("/projects/{slug}/{action}")
def project_action(
    request: Request,
    slug: str,
    action: str,
    confirm_failover: bool = Form(False),
    confirm_quarantine: bool = Form(False),
    confirm_slug: str = Form(""),
    confirm_phrase: str = Form(""),
    backup_id: str = Form(""),
    confirm_restore: bool = Form(False),
    allow_overwrite: bool = Form(False),
    csrf_token: str = Form(""),
):
    ui(request, csrf_token)
    if action not in PROJECT_ACTIONS:
        raise HTTPException(404, "Unknown project action.")
    project = safe_child(SETTINGS.workspaces, slug)
    if not project.is_dir() or project.is_symlink():
        raise HTTPException(404, "Project not found.")
    capabilities = project_capabilities(slug, load_meta(project))
    if (
        action
        in {
            "restart",
            "runtime-health",
            "bootstrap",
            "health",
            "test",
            "codexpro",
            "logs",
        }
        and not capabilities["can_run_runtime_action"]
    ):
        raise HTTPException(
            409,
            f"Runtime action unavailable: {capabilities['status_reason'] or 'environment is not ready.'}",
        )
    if action == "quarantine" and not confirm_quarantine:
        raise HTTPException(400, "Quarantine requires explicit acknowledgement.")
    if action == "destroy" and (
        confirm_slug != slug or confirm_phrase != f"DESTROY {slug}"
    ):
        raise HTTPException(400, "Permanent destruction requires exact confirmation.")
    if action == "restore-backup" and (not confirm_restore or not backup_id):
        raise HTTPException(400, "Backup restore requires an identified backup and explicit confirmation.")

    payload = {
        "confirm_failover": confirm_failover,
        "confirm_quarantine": confirm_quarantine,
        "confirm_slug": confirm_slug,
        "confirm_phrase": confirm_phrase,
        "backup_id": backup_id,
        "confirm_restore": confirm_restore,
        "allow_overwrite": allow_overwrite,
    }
    shared_task = _project_action_task(slug, action, payload)
    def task(ctx):
        return shared_task(ctx)

    idempotency_key = _action_idempotency_key(slug, action, payload)
    operation_id = submit_operation(action, slug, task, idempotency_key=idempotency_key)
    if ui_wants_json(request):
        return JSONResponse({"ok": True, "operation_id": operation_id}, status_code=202)
    return redirect(operation_id)


@app.post("/projects/{slug}/profile")
def project_profile(
    request: Request,
    slug: str,
    profile: str = Form(...),
    confirm_fast: bool = Form(False),
    allow_devices: bool = Form(False),
    allow_privileged: bool = Form(False),
    csrf_token: str = Form(""),
):
    ui(request, csrf_token)
    profile = profile.lower()
    if profile not in {"strict", "balanced", "fast"}:
        raise HTTPException(400, "Unknown profile.")
    if profile == "fast" and not confirm_fast:
        raise HTTPException(400, "Fast Trusted mode requires explicit acknowledgement.")
    if (allow_devices or allow_privileged) and (profile != "fast" or not confirm_fast):
        raise HTTPException(
            400, "Device or privileged access requires Fast Trusted acknowledgement."
        )
    project = safe_child(SETTINGS.workspaces, slug)
    meta = load_meta(project)
    previous = str(meta.get("profile") or SETTINGS.development_profile)
    meta.setdefault("profile_history", []).append(
        {
            "from": previous,
            "to": profile,
            "time": __import__("time").strftime(
                "%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()
            ),
        }
    )
    meta["profile_history"] = meta["profile_history"][-50:]
    meta["profile"] = profile
    meta["allow_tailnet_ports"] = profile != "strict"
    meta["allow_devices"] = bool(allow_devices) if profile == "fast" else False
    meta["allow_privileged"] = bool(allow_privileged) if profile == "fast" else False
    atomic_json(metadata_path(project), meta)
    analyze_project(project, profile, force=True)
    return RedirectResponse("/", 303)


@app.post("/peer/projects/{slug}/{action}")
def peer_project_action(
    request: Request,
    slug: str,
    action: str,
    confirm_failover: bool = Form(False),
    confirm_quarantine: bool = Form(False),
    csrf_token: str = Form(""),
):
    ui(request, csrf_token)
    payload = {
        "confirm_failover": bool(confirm_failover),
        "confirm_quarantine": bool(confirm_quarantine),
    }

    def task(ctx):
        ctx.update(15, "Sending authenticated action to peer")
        result = peer_call("POST", f"/api/projects/{slug}/{action}", payload)
        ctx.log(str(result)[-4000:])
        ctx.update(90, "Peer action completed")
        return result

    return redirect(submit_operation("peer-" + action, slug, task))


@app.post("/repair")
def repair(request: Request, csrf_token: str = Form("")):
    ui(request, csrf_token)

    def task(ctx):
        ctx.update(20, "Running non-destructive node repair")
        result = run(["/usr/local/bin/devfleet-user-repair"], timeout=600).stdout[
            -8000:
        ]
        ctx.log(result)
        ctx.update(90, "Repair health checks completed")
        return result

    return redirect(submit_operation("repair", "node", task))


@app.post("/projects/{slug}/transfer-to-peer")
def transfer(request: Request, slug: str, csrf_token: str = Form("")):
    ui(request, csrf_token)
    if (
        load_meta(safe_child(SETTINGS.workspaces, slug)).get("runtime_isolation")
        == "vm"
    ):
        raise HTTPException(
            409,
            "Dedicated-VM peer transfer is blocked until a verified node-to-node VM transfer protocol is available. The current VM remains the canonical owner.",
        )
    state = peer_node_status()
    if not state.get("ok"):
        raise HTTPException(
            409,
            "DevFleetFailover is offline or unavailable; ownership transfer is disabled.",
        )
    return redirect(
        submit_operation(
            "ownership-transfer",
            slug,
            lambda ctx: guided_transfer(
                slug, ctx, stop=stop_project, backup=backup_project, peer_call=peer_call
            ),
            idempotency_key=f"ownership-transfer:{slug}",
        )
    )


@app.post("/quarantine/restore")
def restore(request: Request, name: str = Form(...), csrf_token: str = Form("")):
    ui(request, csrf_token)

    def task(ctx):
        ctx.update(20, "Restoring reversible quarantine entry")
        result = restore_quarantine(name)
        ctx.update(90, "Quarantine entry restored")
        return result

    return redirect(submit_operation("restore-quarantine", name, task))


@app.get("/projects/{slug}/logs", response_class=HTMLResponse)
def logs(request: Request, slug: str):
    ui(request)
    safe_child(SETTINGS.workspaces, slug)
    return RedirectResponse(f"/projects/{slug}?tab=logs", 303)


@app.get("/ui/projects/{slug}/logs")
def ui_project_logs(request: Request, slug: str, tail: int = 150):
    ui(request)
    project = safe_child(SETTINGS.workspaces, slug)
    if not project.is_dir():
        raise HTTPException(404, "Project not found.")
    meta = load_meta(project)
    capabilities = project_capabilities(slug, meta)
    if not capabilities["can_query_logs"]:
        return JSONResponse(
            {
                "ok": False,
                "slug": slug,
                "state": capabilities["lifecycle_state"],
                "terminal": True,
                "logs": "Start the project to view live logs.",
                "capabilities": capabilities,
            },
            status_code=409,
        )
    bounded = max(1, min(int(tail), 500))
    try:
        logs_value = project_logs(slug, tail=bounded)
    except FileNotFoundError:
        raise HTTPException(404, "Project not found.")
    except (OSError, ValueError, RuntimeError) as exc:
        raise HTTPException(503, f"Project logs unavailable: {str(exc)[-500:]}")
    return JSONResponse(
        {
            "ok": True,
            "slug": slug,
            "tail": bounded,
            "provider": meta.get("runtime_provider")
            or meta.get("runtime_isolation")
            or "unknown",
            "logs": str(logs_value)[-30000:],
        }
    )


@app.get("/api/projects/{slug}/runtime", dependencies=[Depends(check_api)])
def api_project_runtime(slug: str):
    project = safe_child(SETTINGS.workspaces, slug)
    meta = load_meta(project)
    capabilities = project_capabilities(slug, meta)
    if not capabilities["can_query_live_metrics"]:
        return {
            "ok": True,
            "project": meta,
            "capabilities": capabilities,
            "runtime": {
                "status": "unavailable",
                "reason": capabilities["status_reason"],
                "live_metrics": "unavailable",
            },
            "health": {
                "status": "not-checked",
                "reason": (
                    "environment stopped"
                    if capabilities["lifecycle_state"] == "stopped"
                    else capabilities["status_reason"]
                ),
            },
        }
    return {
        "ok": True,
        "project": meta,
        "capabilities": capabilities,
        "runtime": inspect_runtime(slug),
        "health": runtime_health(slug),
    }


@app.get("/api/projects/{slug}/capabilities", dependencies=[Depends(check_api)])
def api_project_capabilities(slug: str):
    project = safe_child(SETTINGS.workspaces, slug)
    return {"ok": True, "capabilities": project_capabilities(slug, load_meta(project))}


@app.get("/api/projects/{slug}/workspace", dependencies=[Depends(check_api)])
def api_project_workspace(slug: str):
    return open_workspace(slug)


@app.get("/api/projects/{slug}/logs", dependencies=[Depends(check_api)])
def api_project_logs(slug: str, tail: int = 150):
    project = safe_child(SETTINGS.workspaces, slug)
    capabilities = project_capabilities(slug, load_meta(project))
    if not capabilities["can_query_logs"]:
        raise HTTPException(
            409,
            f"Logs unavailable: {capabilities['status_reason'] or 'environment is not ready.'}",
        )
    bounded = max(1, min(int(tail), 500))
    return {
        "ok": True,
        "slug": slug,
        "tail": bounded,
        "logs": project_logs(slug, tail=bounded),
    }


@app.get("/ui/projects/{slug}/backups")
def ui_project_backups(request: Request, slug: str):
    ui(request)
    safe_child(SETTINGS.workspaces, slug)
    return JSONResponse({"ok": True, "backups": list_backups(slug)})


@app.get("/api/projects/{slug}/backups", dependencies=[Depends(check_api)])
def api_project_backups(slug: str):
    return {"ok": True, "backups": list_backups(slug)}


@app.get("/api/projects/{slug}/environment", dependencies=[Depends(check_api)])
def api_project_environment(slug: str):
    detected = detect_runtime(slug)
    capacity = {}
    try:
        capacity = get_host_capacity()
    except Exception as exc:
        capacity = {"ok": False, "status": "unavailable", "error": str(exc)[-500:]}
    nodes = []
    for node in cluster_status().get("nodes", []):
        nodes.append(
            {
                "id": node.get("id"),
                "name": node.get("friendly_name") or node.get("id"),
                "status": node.get("status"),
                "reachable": bool(node.get("reachable")),
                "selectable": bool(
                    node.get("destination_selectable", node.get("reachable"))
                ),
                "reason": node.get("error", ""),
            }
        )
    return {
        "ok": True,
        "project": detected,
        "detected_runtime": detected,
        "runtime_options": RUNTIME_ISOLATIONS,
        "resource_profiles": {
            name: profile.__dict__ for name, profile in RESOURCE_PROFILES.items()
        },
        "capacity": capacity,
        "nodes": nodes,
        "workspace_preserved_by_default": True,
    }


@app.get("/api/projects/{slug}/preflight", dependencies=[Depends(check_api)])
def api_project_preflight(
    slug: str,
    runtime_isolation: str = "",
    resource_profile: str = "",
    custom_cpus: str = "",
    custom_ram_gb: str = "",
    custom_disk_gb: str = "",
    pid_mode: str = "private",
    pid_limit: str = "4096",
):
    return _preflight(
        slug,
        runtime_isolation,
        resource_profile,
        custom_cpus,
        custom_ram_gb,
        custom_disk_gb,
        pid_mode,
        pid_limit,
    )


@app.get("/ui/projects/{slug}/preflight")
def ui_project_preflight(
    request: Request,
    slug: str,
    runtime_isolation: str = "",
    resource_profile: str = "",
    custom_cpus: str = "",
    custom_ram_gb: str = "",
    custom_disk_gb: str = "",
    pid_mode: str = "private",
    pid_limit: str = "4096",
):
    ui(request)
    try:
        return JSONResponse(
            _preflight(
                slug,
                runtime_isolation,
                resource_profile,
                custom_cpus,
                custom_ram_gb,
                custom_disk_gb,
                pid_mode,
                pid_limit,
            )
        )
    except FileNotFoundError:
        raise HTTPException(404, "Project not found.")


@app.post("/api/projects/{slug}/environment", dependencies=[Depends(check_api)])
def api_project_environment_assign(slug: str, payload: dict | None = None):
    payload = payload or {}
    if not payload.get("wizard_confirmed"):
        raise HTTPException(400, "Final wizard confirmation is required.")
    runtime_isolation = str(payload.get("runtime_isolation") or "container")
    resource_profile = str(payload.get("resource_profile") or "")
    resource_limits = (
        payload.get("resource_limits")
        if isinstance(payload.get("resource_limits"), dict)
        else None
    )
    selected = resource_limits or {}
    preflight = _preflight(
        slug,
        runtime_isolation,
        resource_profile,
        str(selected.get("cpus", "")),
        str(selected.get("memory_gb", "")),
        str(selected.get("disk_gb", "")),
        str(selected.get("pid_mode", "private")),
        str(selected.get("pids", "4096")),
    )
    if not preflight["migration_ready"]:
        raise HTTPException(
            409,
            "Environment preflight is not ready: " + "; ".join(preflight["blockers"]),
        )
    op = submit_operation(
        "runtime-adoption",
        slug,
        lambda ctx: assign_project_runtime(
            slug,
            runtime_isolation,
            resource_profile,
            resource_limits,
            operation_context=ctx,
        ),
        idempotency_key=f'runtime-adoption:{slug}:{runtime_isolation}:{resource_profile or "current"}',
    )
    return JSONResponse(
        {"ok": True, "operation_id": op, "message": "Environment assignment queued."},
        status_code=202,
    )


@app.post("/api/projects/create", dependencies=[Depends(check_api)])
def api_create(payload: dict):
    defaults = {
        "slug": "", "display_name": "", "template": "generic", "git_url": "",
        "language": "", "framework": "", "scale": "small", "intent": "prototype",
        "testing_level": "standard", "profile": "", "resource_profile": "",
        "resource_limits": None, "runtime_isolation": "", "use_ollama": True,
        "worktree_source": "", "worktree_branch": "", "project_kind": "",
    }
    values = {key: payload.get(key, default) for key, default in defaults.items()}
    slug = validate_slug(str(values["slug"]))
    supplied = str(payload.get("idempotency_key") or "").strip()
    if supplied and not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", supplied):
        raise HTTPException(400, "Idempotency key must be 1-128 safe identifier characters.")

    def task(ctx):
        return create_project(**values, operation_context=ctx)

    operation_id = submit_operation("create", slug, task, idempotency_key=f"project-create:{slug}:{supplied or 'default'}")
    return JSONResponse({"ok": True, "accepted": True, "operation_id": operation_id, "operation_url": f"/api/operations/{operation_id}"}, status_code=202)


@app.post("/api/projects/{slug}/{action}", dependencies=[Depends(check_api)])
def api_action(request: Request, slug: str, action: str, payload: dict | None = None):
    payload = payload or {}
    if action not in PROJECT_ACTIONS:
        raise HTTPException(404, "Unknown action")
    project = safe_child(SETTINGS.workspaces, slug)
    if not project.is_dir() or project.is_symlink():
        raise HTTPException(404, "Project not found.")
    metadata = load_meta(project)
    capabilities = project_capabilities(slug, metadata)
    if (
        action
        in {
            "restart",
            "runtime-health",
            "bootstrap",
            "health",
            "test",
            "codexpro",
            "logs",
        }
        and not capabilities["can_run_runtime_action"]
    ):
        raise HTTPException(
            409,
            f"Runtime action unavailable: {capabilities['status_reason'] or 'environment is not ready.'}",
        )
    if action == "quarantine" and not payload.get("confirm_quarantine"):
        raise HTTPException(400, "Quarantine requires explicit acknowledgement.")
    if action == "destroy" and (
        payload.get("confirm_slug") != slug
        or payload.get("confirm_phrase") != f"DESTROY {slug}"
    ):
        raise HTTPException(400, "Permanent destruction requires exact confirmation.")
    if action == "restore-backup" and (not payload.get("confirm_restore") or not payload.get("backup_id")):
        raise HTTPException(400, "Backup restore requires an identified backup and explicit confirmation.")
    task = _project_action_task(slug, action, payload)
    if action in PROJECT_READ_ONLY_ACTIONS:
        return {"ok": True, "output": task(None)}
    idempotency_key = _action_idempotency_key(slug, action, payload, request.headers.get("X-Idempotency-Key", ""))
    operation_id = submit_operation(
        action,
        slug,
        task,
        project_id=str(metadata.get("project_id") or ""),
        runtime_id=str(metadata.get("runtime_id") or ""),
        idempotency_key=idempotency_key,
        host_id=str(metadata.get("host_id") or SETTINGS.host_id),
    )
    return JSONResponse({"ok": True, "accepted": True, "operation_id": operation_id, "operation_url": f"/api/operations/{operation_id}"}, status_code=202)
