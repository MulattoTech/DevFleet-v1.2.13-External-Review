from __future__ import annotations
import hashlib, hmac, json, secrets, time, threading, math, os, tempfile
from contextlib import contextmanager
from pathlib import Path
from fastapi import Header, HTTPException, Request, status
from .core import SETTINGS, atomic_json

SESSION_COOKIE = "devfleet_session"
LOGIN_CSRF_COOKIE = "devfleet_login_csrf"
SESSION_TTL = 12 * 60 * 60
REMEMBERED_TTL = 7 * 24 * 60 * 60
SESSION_SAMESITE = "strict"
SESSION_SECURE_COOKIE = True
_SESSION_LOCK = threading.RLock()
_LOGIN_LOCK = threading.RLock()
_LOGIN_FAILURES = {}
_SOURCE_FAILURES = {}
_CREDENTIAL_FAILURES = {}
_GLOBAL_FAILURES = []
_BACKOFF_BASE = 0.25
_BACKOFF_MAX = 8.0
_SOURCE_WINDOW = 15 * 60
_GLOBAL_WINDOW = 60.0
_GLOBAL_LIMIT = 40


def _session_path() -> Path:
    return SETTINGS.runtime_root / "sessions.json"


@contextmanager
def _session_file_lock():
    """Serialize the complete sessions read/modify/write transaction across workers."""
    path = _session_path().with_name("sessions.json.lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "a+b")
    try:
        if os.name != "nt":
            os.chmod(path, 0o600)
    except OSError:
        pass
    try:
        if os.name != "nt":
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        else:
            import msvcrt

            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        yield
    finally:
        try:
            if os.name != "nt":
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            else:
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            handle.close()
    try:
        if os.name != "nt":
            path.chmod(0o600)
    except OSError:
        pass


def _load_sessions() -> dict[str, dict]:
    try:
        value = json.loads(_session_path().read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_sessions(value: dict[str, dict]) -> None:
    path = _session_path()
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            parent.chmod(0o700)
        except OSError:
            pass
    payload = json.dumps(value, indent=2, sort_keys=True, default=str) + "\n"
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(parent)
    )
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            fd = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        replace_error = None
        for attempt in range(6):
            try:
                os.replace(temp_name, path)
                replace_error = None
                break
            except PermissionError as exc:
                replace_error = exc
                if os.name != "nt" or attempt == 5:
                    raise
                time.sleep(0.02 * (attempt + 1))
        if replace_error is not None:
            raise replace_error
    finally:
        if fd != -1:
            os.close(fd)
        try:
            Path(temp_name).unlink(missing_ok=True)
        except OSError:
            pass
    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError:
            pass


def _credential_generation() -> str:
    return hashlib.sha256(
        (str(SETTINGS.admin_user) + "\0" + str(SETTINGS.admin_password)).encode()
    ).hexdigest()


def _prune_sessions(
    sessions: dict[str, dict], now: int | None = None
) -> dict[str, dict]:
    now = int(time.time() if now is None else now)
    return {
        k: v
        for k, v in sessions.items()
        if isinstance(v, dict) and int(v.get("expires_at", 0)) > now
    }


def login_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def session_cookie_options(request: Request | None = None) -> dict:
    """Cookie settings for callers that emit the session cookie.

    v1.2.1's route signatures remain unchanged; this centralizes the strict,
    secure-compatible policy for future/compatible emitters.
    """
    return {
        "httponly": True,
        "samesite": SESSION_SAMESITE,
        "secure": bool(request and request.url.scheme == "https"),
        "path": "/",
    }


def safe_next(value: str | None) -> str:
    value = str(value or "/").strip()
    if (
        not value.startswith("/")
        or value.startswith("//")
        or "\\" in value
        or "://" in value
    ):
        return "/"
    return value


def _backoff_key(user: str, source: str | None = None) -> str:
    return f'{source or "unknown"}:{user}'


def _source_key(source: str | None) -> str:
    return str(source or "unknown").strip().lower()[:200]


def _credential_key(user: str) -> str:
    return hashlib.sha256(str(user or "").strip().lower().encode()).hexdigest()


def _backoff_seconds(entries: dict[str, dict], key: str, now: float) -> float:
    entry = entries.get(key)
    return max(0.0, float(entry["until"]) - now) if entry else 0.0


def login_backoff_seconds(
    user: str, source: str | None = None, now: float | None = None
) -> float:
    now = time.monotonic() if now is None else now
    key = _backoff_key(user, source)
    with _LOGIN_LOCK:
        entry = _LOGIN_FAILURES.get(key)
        return max(0.0, float(entry["until"]) - now) if entry else 0.0


def _record_login_failure(
    user: str, source: str | None = None, now: float | None = None
) -> None:
    now = time.monotonic() if now is None else now
    key = _backoff_key(user, source)
    with _LOGIN_LOCK:
        cutoff = now - _SOURCE_WINDOW
        _LOGIN_FAILURES.update(
            {k: v for k, v in _LOGIN_FAILURES.items() if v["last"] >= cutoff}
        )
        entry = _LOGIN_FAILURES.get(key, {"count": 0, "last": now, "until": now})
        count = min(int(entry["count"]) + 1, 8)
        entry = {
            "count": count,
            "last": now,
            "until": now + min(_BACKOFF_MAX, _BACKOFF_BASE * (2 ** (count - 1))),
        }
        _LOGIN_FAILURES[key] = entry
        for entries, entry_key in (
            (_SOURCE_FAILURES, _source_key(source)),
            (_CREDENTIAL_FAILURES, _credential_key(user)),
        ):
            old = entries.get(entry_key, {"count": 0, "last": now, "until": now})
            n = min(int(old["count"]) + 1, 8)
            entries[entry_key] = {
                "count": n,
                "last": now,
                "until": now + min(_BACKOFF_MAX, _BACKOFF_BASE * (2 ** (n - 1))),
            }
        _GLOBAL_FAILURES[:] = [t for t in _GLOBAL_FAILURES if t >= now - _GLOBAL_WINDOW]
        if len(_GLOBAL_FAILURES) < _GLOBAL_LIMIT:
            _GLOBAL_FAILURES.append(now)


def login_retry_after(
    user: str, source: str | None = None, now: float | None = None
) -> int:
    now = time.monotonic() if now is None else now
    with _LOGIN_LOCK:
        source_delay = _backoff_seconds(_SOURCE_FAILURES, _source_key(source), now)
        credential_delay = _backoff_seconds(
            _CREDENTIAL_FAILURES, _credential_key(user), now
        )
        global_delay = 0.0
        if len(_GLOBAL_FAILURES) >= _GLOBAL_LIMIT:
            global_delay = max(0.0, (_GLOBAL_FAILURES[0] + _GLOBAL_WINDOW) - now)
    return max(0, math.ceil(max(source_delay, credential_delay, global_delay)))


def valid_credentials(user: str, password: str, source: str | None = None) -> bool:
    user = str(user or "")
    password = str(password or "")
    # Keep both comparisons on every credential attempt.  Input-shape
    # rejection is applied only after the comparisons so an invalid username
    # cannot skip the password comparison.
    user_ok = hmac.compare_digest(user, SETTINGS.admin_user)
    password_ok = hmac.compare_digest(password, SETTINGS.admin_password)
    valid = bool(user.strip() and password and (user_ok & password_ok))
    if not user.strip() or not password:
        _record_login_failure(user, source)
        return False
    if not valid:
        if login_retry_after(user, source):
            return False
        _record_login_failure(user, source)
    else:
        # A correct credential must not be permanently locked out by earlier
        # failures for the same account; throttle invalid attempts while allowing
        # the owner to recover without waiting for the backoff window.
        with _LOGIN_LOCK:
            _LOGIN_FAILURES.pop(_backoff_key(user, source), None)
            _CREDENTIAL_FAILURES.pop(_credential_key(user), None)
            _SOURCE_FAILURES.pop(_source_key(source), None)
    return valid


def issue_session(user: str, remember: bool = False) -> tuple[str, int, str]:
    now = int(time.time())
    ttl = REMEMBERED_TTL if remember else SESSION_TTL
    session_id = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    with _SESSION_LOCK, _session_file_lock():
        sessions = _prune_sessions(_load_sessions())
        sessions[session_id] = {
            "user": user,
            "issued_at": now,
            "expires_at": now + ttl,
            "csrf": csrf,
            "credential_generation": _credential_generation(),
        }
        _save_sessions(sessions)
    return session_id, ttl, csrf


def _session_file_generation() -> tuple[int, int]:
    try:
        stat = _session_path().stat()
        return (int(stat.st_mtime_ns), int(stat.st_size))
    except OSError:
        return (0, 0)


def _request_session_record(request: Request) -> dict | None:
    token = request.cookies.get(SESSION_COOKIE)
    signature = (token, _credential_generation(), _session_file_generation())
    state = getattr(request, "state", None)
    cached = (
        getattr(state, "devfleet_session_cache", None) if state is not None else None
    )
    if isinstance(cached, dict) and cached.get("signature") == signature:
        return cached.get("record")
    with _SESSION_LOCK, _session_file_lock():
        record = _prune_sessions(_load_sessions()).get(token or "")
    if (
        not isinstance(record, dict)
        or record.get("user") != SETTINGS.admin_user
        or record.get("credential_generation") != signature[1]
        or int(record.get("expires_at", 0)) <= int(time.time())
    ):
        record = None
    if state is not None:
        state.devfleet_session_cache = {"signature": signature, "record": record}
    return record


def validate_session(token: str | None) -> str | None:
    if not token:
        return None
    with _SESSION_LOCK, _session_file_lock():
        record = _prune_sessions(_load_sessions()).get(token)
    if (
        not isinstance(record, dict)
        or record.get("user") != SETTINGS.admin_user
        or record.get("credential_generation") != _credential_generation()
    ):
        return None
    if int(record.get("expires_at", 0)) <= int(time.time()):
        revoke_session(token)
        return None
    return str(record["user"])


def session_user(request: Request) -> str | None:
    record = _request_session_record(request)
    return str(record["user"]) if isinstance(record, dict) else None


def check_session(request: Request) -> None:
    if not session_user(request):
        raise HTTPException(status_code=401, detail="Login required.")


def session_csrf_token(request: Request) -> str:
    record = _request_session_record(request)
    return str(record.get("csrf", "")) if isinstance(record, dict) else ""


def validate_login_csrf(cookie: str | None, form_value: str) -> bool:
    return bool(cookie and form_value) and hmac.compare_digest(cookie, form_value)


def validate_session_csrf(request: Request, form_value: str) -> bool:
    return bool(form_value) and hmac.compare_digest(
        session_csrf_token(request), form_value
    )


def revoke_session(token: str | None) -> None:
    if not token:
        return
    with _SESSION_LOCK, _session_file_lock():
        sessions = _load_sessions()
        sessions.pop(token, None)
        _save_sessions(sessions)


def api_token_valid(token: str | None) -> bool:
    """Validate the API token without short-circuiting the digest comparison."""
    expected = str(SETTINGS.api_token or "")
    supplied = str(token or "")
    configured = bool(expected.strip())
    provided = bool(supplied.strip())
    matches = hmac.compare_digest(supplied, expected)
    return configured and provided and matches


def check_api(x_devfleet_token: str = Header(default="")) -> None:
    if not api_token_valid(x_devfleet_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API token"
        )
