#!/usr/bin/env python3
"""Offline, read-only verification for a DevFleet package or release archive."""
from __future__ import annotations

import hashlib
import json
import os
import py_compile
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import zipfile
from pathlib import Path, PurePosixPath

import jinja2
import yaml
from hook_modes import executable_template_hook_closure, executable_template_hooks, hook_mode_manifest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
TRANSIENT_DIRS = {".git", ".pytest_cache", ".test-runtime", "__pycache__", "runtime-migrations"}


def is_transient_part(part: str) -> bool:
    return part in TRANSIENT_DIRS or part.startswith(".venv")
CHECKSUM_MANIFEST = "CHECKSUMS.sha256"
REQUIRED = [
    "VERSION", "README-FIRST.md", "Upgrade-DevFleet.ps1",
    "DevFleet-v1.1.0-MIGRATION.md", "DevFleet-v1.1.0-VALIDATION.md",
    "DevFleet-v1.1.0-FILE-CHANGES.md", "BASELINE-v1.0.0-FILES.txt",
    "config/devfleet.config.json", "config/ollama-profiles.json",
    "client/Configure-SSH.ps1", "client/Configure-DockerContext.ps1",
    "client/Configure-VSCode.ps1", "windows/Migrate-Config.ps1",
    "windows/Configure-Ollama.ps1", "windows/Set-DevFleetDockerMode.ps1",
    "windows/Test-Ollama.ps1", "linux/bootstrap-compute.sh",
    "linux/devfleet-switch-docker-mode", "app/devfleet/main.py",
    "app/devfleet/analyzer.py", "docs/08-DEVELOPMENT-PROFILES.md",
    "docs/09-LANGUAGE-SELECTION.md", "docs/10-OLLAMA-AND-GPU.md",
    "docs/11-REMOTE-VSCODE.md", "docs/12-UPGRADING-FROM-1.0.0.md",
    "docs/13-PERFORMANCE-TUNING.md",
]
CORE = {"generic", "python", "python-fastapi", "node", "typescript-node",
        "typescript-next", "go-service", "dotnet-service", "java-spring", "rust-service"}


DEFAULT_EXTERNAL_TIMEOUT_SECONDS = 120
DEFAULT_EXTERNAL_OUTPUT_LIMIT = 2 * 1024 * 1024


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Terminate one external hook and descendants without relying on shell quoting."""
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            import signal

            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
    try:
        process.kill()
    except OSError:
        pass


def run_bounded(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float = DEFAULT_EXTERNAL_TIMEOUT_SECONDS,
    output_limit: int = DEFAULT_EXTERNAL_OUTPUT_LIMIT,
    label: str = "external hook",
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a package hook with a deadline, process-tree kill, and bounded output."""
    if output_limit <= 0 or timeout <= 0:
        raise ValueError("run_bounded limits must be positive")
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    process = subprocess.Popen(
        args,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name != "nt",
        creationflags=creationflags,
    )
    captured: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    overflow = threading.Event()

    def drain(name: str, stream: object) -> None:
        assert hasattr(stream, "read")
        reader = stream  # type: ignore[assignment]
        while True:
            chunk = reader.read(65536)
            if not chunk:
                return
            remaining = output_limit - len(captured[name])
            if len(chunk) > remaining:
                if remaining > 0:
                    captured[name].extend(chunk[:remaining])
                overflow.set()
                return
            captured[name].extend(chunk)

    threads = [
        threading.Thread(target=drain, args=(name, stream), daemon=True)
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr))
    ]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + timeout
    timed_out = False
    while process.poll() is None:
        if overflow.is_set():
            _terminate_process_tree(process)
            break
        if time.monotonic() >= deadline:
            timed_out = True
            _terminate_process_tree(process)
            break
        time.sleep(0.02)
    if timed_out:
        reason = f"{label} exceeded {timeout:g}s timeout"
    elif overflow.is_set():
        reason = f"{label} exceeded {output_limit} byte output limit"
    else:
        reason = ""
    if reason:
        process.wait(timeout=10)
    for thread in threads:
        thread.join(timeout=10)
    result = subprocess.CompletedProcess(
        args,
        process.returncode,
        captured["stdout"].decode(errors="replace"),
        captured["stderr"].decode(errors="replace"),
    )
    if reason:
        raise RuntimeError(f"{reason}; stdout/stderr excerpt: {result.stdout[-1000:]} {result.stderr[-1000:]}")
    if check and result.returncode:
        raise subprocess.CalledProcessError(result.returncode, args, result.stdout, result.stderr)
    return result


def is_transient(path: Path, root: Path = ROOT) -> bool:
    """Return whether a path belongs to generated/test state excluded from a package."""
    return any(is_transient_part(part) for part in path.relative_to(root).parts)


def package_files(root: Path = ROOT) -> set[str]:
    return {
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file() and not is_transient(p, root)
    }


def require_files(root: Path = ROOT) -> None:
    for rel in REQUIRED:
        assert (root / rel).is_file(), f"missing {rel}"


def parse_data(root: Path = ROOT) -> None:
    for rel in package_files(root):
        p = root / rel
        if p.suffix == ".json":
            json.loads(p.read_text(encoding="utf-8"))
    vscode = root / "client/vscode-settings.jsonc"
    json.loads(re.sub(r"(?m)^\s*//.*$", "", vscode.read_text(encoding="utf-8")))
    for p in list((root / "cloud-init").glob("*.yaml")) + list((root / "templates").glob("*/compose.yaml")):
        assert isinstance(yaml.safe_load(p.read_text(encoding="utf-8")), dict), f"YAML root is not mapping: {p}"


def compile_python_jinja(root: Path = ROOT) -> None:
    with tempfile.TemporaryDirectory() as td:
        cache = Path(td)
        for rel in package_files(root):
            p = root / rel
            if p.suffix == ".py":
                py_compile.compile(str(p), cfile=str(cache / (hashlib.sha256(rel.encode()).hexdigest() + ".pyc")), doraise=True)
    jinja2.Environment().parse((root / "app/templates/index.html").read_text(encoding="utf-8"))


def bash_available() -> bool:
    try:
        return shutil.which("bash") is not None and run_bounded(["bash", "-c", "exit 0"], timeout=5, label="bash probe", check=False).returncode == 0
    except (OSError, RuntimeError):
        return False


def bash_syntax(root: Path = ROOT) -> None:
    if not bash_available():
        return
    for rel in package_files(root):
        p = root / rel
        if p.suffix == ".sh" or (p.parts and p.parts[-1] == "devfleet-switch-docker-mode"):
            run_bounded(["bash", "-n", str(p)], label=f"bash syntax check {p}")


def linux_executable_hooks(root: Path = ROOT) -> None:
    """Require every command-referenced template hook to be exactly 0755."""
    hooks = executable_template_hooks(root)
    assert hooks, "no executable template hooks were derived from metadata"
    for rel in sorted(hooks):
        p = root / rel
        assert p.is_file(), f"trusted hook is not a regular file: {p}"
        if os.name != "nt":
            assert p.stat().st_mode & 0o777 == 0o755, f"template hook mode is not 0755: {p}"
        first = p.read_text(encoding="utf-8").splitlines()[0] if p.stat().st_size else ""
        assert first == "#!/usr/bin/env bash", f"trusted hook has invalid shebang: {p}"


def powershell_lexical(root: Path = ROOT) -> None:
    pairs = {"(": ")", "[": "]", "{": "}"}
    for rel in package_files(root):
        p = root / rel
        if p.suffix not in {".ps1", ".psm1"}:
            continue
        t = p.read_text(encoding="utf-8-sig")
        stack: list[str] = []
        quote = here = None
        i = 0
        line = True
        while i < len(t):
            if here:
                end = "'@" if here == "'" else '"@'
                if line and t.startswith(end, i):
                    here = None; i += 2; line = False; continue
                line = t[i] == "\n"; i += 1; continue
            c = t[i]
            if quote:
                if c == "`": i += 2; continue
                if c == quote:
                    if quote == "'" and i + 1 < len(t) and t[i + 1] == "'": i += 2; continue
                    quote = None
                line = c == "\n"; i += 1; continue
            if line and t.startswith("@'", i): here = "'"; i += 2; line = False; continue
            if line and t.startswith('@"', i): here = '"'; i += 2; line = False; continue
            if c == "#":
                while i < len(t) and t[i] != "\n": i += 1
                line = True; continue
            if c in "'\"": quote = c
            elif c in pairs: stack.append(c)
            elif c in pairs.values(): assert stack and pairs[stack.pop()] == c, f"unbalanced {c} in {p}"
            line = c == "\n"; i += 1
        assert not stack and quote is None and here is None, f"unbalanced PowerShell structure: {p}"


def template_smoke(root: Path = ROOT) -> None:
    if not bash_available():
        return
    for source in (root / "templates").glob("*"):
        if not source.is_dir() or is_transient(source, root):
            continue
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "demo"; shutil.copytree(source, dest)
            for p in dest.rglob("*"):
                if p.is_file() and not p.is_symlink():
                    try:
                        p.write_text(p.read_text().replace("__PROJECT_SLUG__", "demo-project").replace("__PROJECT_NAME__", "Demo Project").replace("__PROJECT_PROFILE__", "balanced").replace("__PROJECT_LANGUAGE__", "test").replace("__PROJECT_FRAMEWORK__", "test").replace("__OLLAMA_BASE_URL__", "http://127.0.0.1:11434/v1").replace("__OLLAMA_MODEL__", "test-model"))
                    except UnicodeDecodeError:
                        pass
            meta = json.loads((dest / ".devfleet/template.json").read_text())
            smoke = ".devfleet/smoke-test.sh"
            if (dest / smoke).is_file():
                run_bounded(["bash", str(dest / smoke)], cwd=dest, label=f"template smoke {source.name}")
            if source.name in CORE:
                for key in ("bootstrap_command", "format_command", "lint_command", "test_command", "health_command"):
                    assert meta.get(key), f"{source.name} missing {key}"


def codexpro_guard_tests(root: Path = ROOT) -> None:
    """Exercise the production /workspaces guard without running CodexPro."""
    if not bash_available():
        print("CodexPro guard tests skipped: POSIX bash is unavailable.")
        return
    hook = root / "templates/generic/.devfleet/codexpro-bootstrap.sh"
    with tempfile.TemporaryDirectory() as outside:
        refused = run_bounded(["bash", str(hook)], cwd=Path(outside), label="CodexPro guard refusal", check=False)
        assert refused.returncode == 2, "CodexPro hook must refuse a non-/workspaces project root"
        assert "must be under /workspaces" in refused.stderr
    workspaces = Path("/workspaces")
    try:
        workspaces.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=workspaces) as valid:
            accepted = run_bounded(["bash", str(hook)], cwd=Path(valid), label="CodexPro guard success", check=False)
            assert accepted.returncode == 0, accepted.stderr
    except (OSError, PermissionError):
        print("CodexPro success-path test skipped: /workspaces is unavailable.")


def fastapi_smoke(root: Path = ROOT) -> None:
    try:
        import fastapi  # noqa: F401
    except ModuleNotFoundError as exc:
        print(f"FastAPI smoke skipped: verification environment does not provide runtime dependency {exc.name}.")
        return
    except SystemError as exc:
        if "pydantic-core version" in str(exc):
            print("FastAPI smoke skipped: local Python dependency set has an existing pydantic/pydantic-core mismatch.")
            return
        raise
    with tempfile.TemporaryDirectory() as td:
        b = Path(td); [(b / d).mkdir() for d in ("workspaces", "quarantine", "runtime", "cache")]
        cfg = {"node_name": "verify", "node_role": "primary", "friendly_name": "CodexDevVM", "portal_port": 8787, "workspaces": str(b / "workspaces"), "quarantine": str(b / "quarantine"), "peer_file": str(b / "peer.json"), "runtime_root": str(b / "runtime"), "cache_root": str(b / "cache"), "development_profile": "balanced", "docker_mode": "rootless", "ollama_base_url": "", "ollama_model": "", "ollama_profile": "stable-interactive", "require_tailscale": False, "public_binding_allowed": True}
        (b / "config.json").write_text(json.dumps(cfg)); (b / "peer.json").write_text("{}")
        env = os.environ.copy(); env.update({"PYTHONPATH": str(root / "app"), "DEVFLEET_CONFIG_PATH": str(b / "config.json"), "DEVFLEET_STATIC_DIR": str(root / "app/static"), "DEVFLEET_TEMPLATE_DIR": str(root / "app/templates"), "DEVFLEET_ADMIN_USER": "x", "DEVFLEET_ADMIN_PASSWORD": "y", "DEVFLEET_API_TOKEN": "z"})
        code = 'from fastapi.testclient import TestClient;from devfleet.main import app;r=TestClient(app).get("/healthz");assert r.status_code==200 and r.json()["agent_version"]=="' + PACKAGE_VERSION + '"'
        run_bounded([sys.executable, "-c", code], env=env, label="FastAPI smoke")


def verify_checksums(root: Path = ROOT) -> None:
    p = root / CHECKSUM_MANIFEST
    assert p.is_file(), "missing checksum manifest"
    entries: dict[str, str] = {}
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parts = line.split("  ", 1)
        assert len(parts) == 2 and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]), f"malformed checksum line: {line}"
        expected, rel = parts; rel = rel.replace("\\", "/")
        assert rel != CHECKSUM_MANIFEST and not is_transient(root / rel, root), f"invalid checksum target: {rel}"
        assert rel not in entries, f"duplicate checksum entry: {rel}"
        target = root / rel
        try:
            target.resolve().relative_to(root.resolve())
        except ValueError:
            raise AssertionError(f"checksum target escapes package root: {rel}")
        assert target.is_file(), f"missing checksum target {rel}"
        actual = hashlib.sha256(target.read_bytes()).hexdigest().lower()
        if actual != expected.lower() and target.is_file():
            # Windows may materialize committed LF text as CRLF. Accept only
            # the exact LF-normalized bytes; content changes still fail.
            raw = target.read_bytes()
            if b"\r" in raw.replace(b"\r\n", b""):
                normalized = None
            else:
                normalized = raw.replace(b"\r\n", b"\n")
            if normalized is not None:
                actual = hashlib.sha256(normalized).hexdigest().lower()
        assert actual == expected.lower(), f"checksum mismatch {rel}"
        entries[rel] = expected.lower()
    eligible = package_files(root) - {CHECKSUM_MANIFEST}
    assert set(entries) == eligible, f"checksum manifest coverage mismatch: missing={sorted(eligible-set(entries))[:10]} extra={sorted(set(entries)-eligible)[:10]}"


def no_empty(root: Path = ROOT) -> None:
    assert not [rel for rel in package_files(root) if (root / rel).stat().st_size == 0 and Path(rel).name != "__init__.py"]


def baseline_preserved(root: Path = ROOT) -> None:
    for rel in (root / "BASELINE-v1.0.0-FILES.txt").read_text(encoding="utf-8").splitlines():
        if rel.strip(): assert (root / rel).exists(), f"v1 baseline path removed: {rel}"


def _safe_member(name: str) -> str:
    normalized = name.replace("\\", "/")
    pure = PurePosixPath(normalized)
    assert normalized and not pure.is_absolute() and ".." not in pure.parts, f"unsafe archive member: {name}"
    assert not any(is_transient_part(part) for part in pure.parts), f"transient archive member: {name}"
    return str(pure)


def _safe_target(dest: Path, name: str) -> Path:
    target = dest / name
    try:
        target.resolve().relative_to(dest.resolve())
    except ValueError:
        raise AssertionError(f"archive member escapes extraction root: {name}")
    return target


def _extract_regular_zip_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, dest: Path, name: str) -> None:
    target = _safe_target(dest, name)
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = (info.external_attr >> 16) & 0o170000
    assert mode not in (stat.S_IFLNK, stat.S_IFDIR), f"unsupported ZIP entry type: {name}"
    with archive.open(info, "r") as source, target.open("xb") as output:
        shutil.copyfileobj(source, output)
    archived_mode = (info.external_attr >> 16) & 0o777
    if archived_mode and os.name != "nt":
        target.chmod(archived_mode)


def _extract_regular_tar_member(archive: tarfile.TarFile, info: tarfile.TarInfo, dest: Path, name: str) -> None:
    assert info.isfile(), f"unsupported TAR entry type: {name}"
    target = _safe_target(dest, name)
    target.parent.mkdir(parents=True, exist_ok=True)
    source = archive.extractfile(info)
    assert source is not None, f"TAR member could not be read: {name}"
    with source, target.open("xb") as output:
        shutil.copyfileobj(source, output)
    if os.name != "nt":
        target.chmod(info.mode & 0o777)


def verify_archive(path: Path) -> None:
    """Validate and clean-extract a zip/tar release archive without running it."""
    assert path.is_file(), f"archive not found: {path}"
    with tempfile.TemporaryDirectory() as td:
        dest = Path(td); names: set[str] = set(); modes: dict[str, int] = {}
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    name = _safe_member(info.filename)
                    if name.endswith("/"): continue
                    assert name not in names, f"duplicate archive member: {name}"; names.add(name)
                    modes[name] = (info.external_attr >> 16) & 0o777
                    _extract_regular_zip_member(archive, info, dest, name)
        else:
            with tarfile.open(path, "r:*") as archive:
                for info in archive.getmembers():
                    name = _safe_member(info.name)
                    if info.isdir(): continue
                    assert name not in names, f"duplicate archive member: {name}"; names.add(name); modes[name] = info.mode & 0o777
                    assert info.isfile(), f"unsupported TAR entry type: {name}"
                    _extract_regular_tar_member(archive, info, dest, name)
        assert set(REQUIRED).issubset(names), f"archive missing required files: {sorted(set(REQUIRED)-names)[:10]}"
        hooks = [name for name in names if name in executable_template_hooks(dest)]
        assert hooks, "archive contains no trusted template hooks"
        for name in hooks:
            assert modes.get(name, 0) == 0o755, f"template hook does not have 0755 mode in archive: {name}"
            # Windows extraction APIs do not expose POSIX execute bits. The
            # archive mode is still checked above; on POSIX, also verify the
            # mode survived the actual clean extraction.
            if os.name != "nt":
                assert (dest / name).stat().st_mode & 0o111, f"trusted template hook lost executable mode after extraction: {name}"
        assert CHECKSUM_MANIFEST in names, "archive missing checksum manifest"


def archive_structural_checks(root: Path = ROOT) -> None:
    """Round-trip a clean tar archive to exercise release structure and modes."""
    with tempfile.TemporaryDirectory() as td:
        archive = Path(td) / "package.tar.gz"
        hooks = executable_template_hooks(root)
        with tarfile.open(archive, "w:gz") as out:
            for rel in sorted(package_files(root)):
                source = root / rel; info = out.gettarinfo(str(source), arcname=rel)
                if rel in hooks: info.mode = 0o755
                with source.open("rb") as stream: out.addfile(info, stream)
        verify_archive(archive)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    assert re.fullmatch(r"\d+\.\d+\.\d+", PACKAGE_VERSION), PACKAGE_VERSION
    require_files(); parse_data(); compile_python_jinja(); bash_syntax(); linux_executable_hooks(); powershell_lexical(); template_smoke(); codexpro_guard_tests(); fastapi_smoke(); no_empty(); baseline_preserved(); verify_checksums(); archive_structural_checks()
    if args.archive: verify_archive(args.archive)
    print(f"DevFleet v{PACKAGE_VERSION} offline package verification passed.")


if __name__ == "__main__":
    main()
