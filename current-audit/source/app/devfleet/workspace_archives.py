"""Verified workspace archives used by migration, backup, and deletion gates.

The archive format is deliberately boring: a gzip tar with one top-level
project directory.  We validate the source before writing and validate the
archive again after writing so a backup is never reported as verified merely
because a command returned zero.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tarfile
import tempfile
import shutil
import uuid
import contextlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .core import atomic_json, now_iso, validate_slug


GENERATED_DIR_NAMES = {
    "node_modules", ".next", "build", "dist", ".venv", "venv",
    ".pytest_cache", "__pycache__", ".test-runtime",
}


# Linux is the deployed control-plane target.  Its openat/no-follow primitives
# let the archive code bind authorization to an already-open object instead of
# asking tarfile to reopen a mutable pathname.  Windows retains the historical
# compatibility implementation below; it is not promoted as Linux identity
# evidence.
POSIX_FD_HARDENING = os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "supports_dir_fd")


def _object_identity(result: os.stat_result) -> dict[str, int]:
    return {
        "st_dev": int(result.st_dev),
        "st_ino": int(result.st_ino),
        "st_type": int(stat.S_IFMT(result.st_mode)),
    }


def _identity_matches(result: os.stat_result, expected: dict[str, int] | None) -> bool:
    return expected is not None and _object_identity(result) == expected


def _fd_directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _fd_regular_flags() -> int:
    return os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _open_verified_child(parent_fd: int, name: str, kind: int) -> tuple[int, os.stat_result]:
    observed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if stat.S_IFMT(observed.st_mode) != kind:
        raise ValueError(f"Workspace entry changed type before it could be opened: {name}")
    if kind == stat.S_IFREG and observed.st_nlink != 1:
        raise ValueError(f"Workspace entry has an unexpected hard-link count: {name}")
    flags = _fd_directory_flags() if kind == stat.S_IFDIR else _fd_regular_flags()
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise ValueError(f"Workspace entry could not be opened without following aliases: {name}") from exc
    try:
        actual = os.fstat(fd)
        if not _identity_matches(actual, _object_identity(observed)):
            raise ValueError(f"Workspace entry identity changed before it could be authorized: {name}")
        return fd, actual
    except Exception:
        os.close(fd)
        raise


def _open_verified_root(root: Path) -> tuple[int, os.stat_result, Path]:
    lexical = Path(os.path.abspath(os.fspath(root)))
    observed = os.lstat(lexical)
    if stat.S_IFMT(observed.st_mode) != stat.S_IFDIR:
        raise ValueError("Workspace must be a real directory.")
    try:
        fd = os.open(lexical, _fd_directory_flags())
    except OSError as exc:
        raise ValueError("Workspace root could not be opened without following aliases.") from exc
    try:
        actual = os.fstat(fd)
        if not _identity_matches(actual, _object_identity(observed)):
            raise ValueError("Workspace root identity changed before it could be authorized.")
        return fd, actual, lexical
    except Exception:
        os.close(fd)
        raise


@dataclass
class _AuthorizedEntry:
    name: str
    kind: int
    result: os.stat_result
    fd: int | None


def _scan_generated_fd(fd: int) -> tuple[int, int]:
    count = 0
    total = 0
    for name in sorted(os.listdir(fd)):
        result = os.stat(name, dir_fd=fd, follow_symlinks=False)
        kind = stat.S_IFMT(result.st_mode)
        if kind == stat.S_IFLNK:
            continue
        if kind == stat.S_IFDIR:
            child_fd, _ = _open_verified_child(fd, name, stat.S_IFDIR)
            try:
                child_count, child_total = _scan_generated_fd(child_fd)
                count += child_count
                total += child_total
            finally:
                os.close(child_fd)
        elif kind == stat.S_IFREG:
            child_fd, child_result = _open_verified_child(fd, name, stat.S_IFREG)
            os.close(child_fd)
            count += 1
            total += int(child_result.st_size)
        else:
            raise ValueError(f"Unsupported generated workspace entry: {name}")
    return count, total


def _capture_workspace_posix(root: Path, *, include_generated: bool) -> tuple[dict[str, Any], list[_AuthorizedEntry]]:
    root_fd, root_result, lexical_root = _open_verified_root(root)
    entries: list[_AuthorizedEntry] = [_AuthorizedEntry("", stat.S_IFDIR, root_result, root_fd)]
    symlinks: list[str] = []
    symlink_targets: dict[str, str] = {}
    generated: list[str] = []
    generated_details: list[dict[str, Any]] = []
    files = 0
    bytes_total = 0

    def walk(parent_fd: int, prefix: str) -> None:
        nonlocal files, bytes_total
        for name in sorted(os.listdir(parent_fd)):
            rel = f"{prefix}/{name}" if prefix else name
            result = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            kind = stat.S_IFMT(result.st_mode)
            if kind == stat.S_IFLNK:
                symlinks.append(rel)
                symlink_targets[rel] = os.readlink(name, dir_fd=parent_fd)
                continue
            if kind == stat.S_IFDIR:
                child_fd, child_result = _open_verified_child(parent_fd, name, stat.S_IFDIR)
                if name in GENERATED_DIR_NAMES and not include_generated:
                    try:
                        excluded_files, excluded_bytes = _scan_generated_fd(child_fd)
                    finally:
                        os.close(child_fd)
                    generated.append(rel)
                    generated_details.append({"path": rel, "files": excluded_files, "bytes": excluded_bytes})
                    continue
                entries.append(_AuthorizedEntry(rel, kind, child_result, child_fd))
                walk(child_fd, rel)
                continue
            if kind != stat.S_IFREG:
                raise ValueError(f"Unsupported workspace entry: {rel}")
            child_fd, child_result = _open_verified_child(parent_fd, name, stat.S_IFREG)
            entries.append(_AuthorizedEntry(rel, kind, child_result, child_fd))
            files += 1
            bytes_total += int(child_result.st_size)

    try:
        walk(root_fd, "")
        included_paths = len(entries) - 1
        inspection = {
            "workspace": str(lexical_root),
            "files": files,
            "bytes": bytes_total,
            "symlinks": sorted(symlinks),
            "symlink_targets": dict(sorted(symlink_targets.items())),
            "generated_dirs": sorted(generated),
            "generated_details": sorted(generated_details, key=lambda item: item["path"]),
            "generated_bytes": sum(item["bytes"] for item in generated_details),
            "estimated_archive_bytes": bytes_total + (files * 512),
            "safe_for_archive": not symlinks,
            "included_path_count": included_paths,
            "included_file_count": files,
            "included_byte_count": bytes_total,
            "omitted_paths": sorted(generated),
            "omission_policy_source": "routine-generated-directory-policy" if generated else "none",
        }
        return inspection, entries
    except Exception:
        for entry in reversed(entries):
            if entry.fd is not None:
                with contextlib.suppress(OSError):
                    os.close(entry.fd)
        raise


def _close_authorized_entries(entries: list[_AuthorizedEntry]) -> None:
    for entry in reversed(entries):
        if entry.fd is not None:
            with contextlib.suppress(OSError):
                os.close(entry.fd)


def _tarinfo_from_authorized(entry: _AuthorizedEntry, name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.mode = stat.S_IMODE(entry.result.st_mode)
    info.mtime = int(entry.result.st_mtime)
    info.uid = int(entry.result.st_uid)
    info.gid = int(entry.result.st_gid)
    info.uname = ""
    info.gname = ""
    if entry.kind == stat.S_IFDIR:
        info.type = tarfile.DIRTYPE
    else:
        info.type = tarfile.REGTYPE
        info.size = int(entry.result.st_size)
    return info


def _write_authorized_tar(path: Path, slug: str, entries: list[_AuthorizedEntry]) -> None:
    with tarfile.open(path, "w:gz", dereference=False) as archive:
        for entry in entries:
            name = slug if not entry.name else f"{slug}/{entry.name}"
            info = _tarinfo_from_authorized(entry, name)
            if entry.kind == stat.S_IFREG:
                if entry.fd is None:
                    raise ValueError(f"Authorized file has no stable descriptor: {name}")
                current = os.fstat(entry.fd)
                if not _identity_matches(current, _object_identity(entry.result)):
                    raise ValueError(f"Authorized file identity changed before archive read: {name}")
                with os.fdopen(os.dup(entry.fd), "rb") as stream:
                    archive.addfile(info, stream)
            else:
                archive.addfile(info)


def _relative_path(root: Path, candidate: Path) -> str:
    try:
        relative = candidate.resolve(strict=False).relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError("Workspace entry escapes the workspace root.") from exc
    text = relative.as_posix()
    if not text or text == "." or text.startswith("../") or "/../" in f"/{text}":
        raise ValueError("Workspace entry has an unsafe relative path.")
    return text


def inspect_workspace(root: Path, *, include_generated: bool = False) -> dict[str, Any]:
    if POSIX_FD_HARDENING:
        inspection, entries = _capture_workspace_posix(root, include_generated=include_generated)
        _close_authorized_entries(entries)
        return inspection
    root = root.resolve()
    if not root.is_dir() or root.is_symlink():
        raise ValueError("Workspace must be a real directory.")
    symlinks: list[str] = []
    symlink_targets: dict[str, str] = {}
    generated: list[str] = []
    generated_details: list[dict[str, Any]] = []
    generated_bytes = 0
    files = 0
    bytes_total = 0
    included_paths = 0
    for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        kept_dirs: list[str] = []
        for name in dirs:
            path = current_path / name
            rel = _relative_path(root, path)
            if path.is_symlink():
                symlinks.append(rel)
                symlink_targets[rel] = os.readlink(path)
                continue
            if name in GENERATED_DIR_NAMES and not include_generated:
                generated.append(rel)
                excluded_files = 0
                excluded_bytes = 0
                for excluded_current, _, excluded_names in os.walk(path, topdown=True, followlinks=False):
                    for excluded_name in excluded_names:
                        excluded_path = Path(excluded_current) / excluded_name
                        if excluded_path.is_symlink():
                            continue
                        if excluded_path.is_file():
                            excluded_files += 1
                            excluded_bytes += excluded_path.stat().st_size
                generated_bytes += excluded_bytes
                generated_details.append({"path": rel, "files": excluded_files, "bytes": excluded_bytes})
                continue
            kept_dirs.append(name)
            included_paths += 1
        dirs[:] = kept_dirs
        for name in names:
            path = current_path / name
            rel = _relative_path(root, path)
            if path.is_symlink():
                symlinks.append(rel)
                symlink_targets[rel] = os.readlink(path)
                continue
            if not path.is_file():
                raise ValueError(f"Unsupported workspace entry: {rel}")
            files += 1
            bytes_total += path.stat().st_size
    return {
        "workspace": str(root),
        "files": files,
        "bytes": bytes_total,
        "symlinks": sorted(symlinks),
        "symlink_targets": dict(sorted(symlink_targets.items())),
        "generated_dirs": sorted(generated),
        "generated_details": sorted(generated_details, key=lambda item: item["path"]),
        "generated_bytes": generated_bytes,
        "estimated_archive_bytes": bytes_total + (files * 512),
        "safe_for_archive": not symlinks,
        "included_path_count": included_paths + files,
        "included_file_count": files,
        "included_byte_count": bytes_total,
        "omitted_paths": sorted(generated),
        "omission_policy_source": "routine-generated-directory-policy" if generated else "none",
    }


def _validate_members(archive: tarfile.TarFile, slug: str) -> list[str]:
    names: list[str] = []
    prefix = f"{slug}/"
    for member in archive.getmembers():
        name = member.name.replace("\\", "/")
        parts = name.split("/")
        if name.startswith("/") or name.startswith("../") or "/../" in f"/{name}" or "\x00" in name or any(part in {"", ".", ".."} for part in parts):
            raise ValueError(f"Archive contains an unsafe path: {member.name}")
        if not name.startswith(prefix) and name != slug:
            raise ValueError("Archive must contain exactly one project-root directory.")
        if member.issym() or member.islnk() or member.isdev() or not (member.isdir() or member.isfile()):
            raise ValueError(f"Archive contains an unsupported entry type: {member.name}")
        names.append(name)
    if not any(name == slug for name in names):
        raise ValueError("Archive is missing its project-root directory.")
    return names


def validate_archive(path: Path, slug: str) -> dict[str, Any]:
    slug = validate_slug(slug)
    digest = hashlib.sha256()
    size = path.stat().st_size
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    with tarfile.open(path, "r:gz") as archive:
        members = _validate_members(archive, slug)
        if not any(name.startswith(f"{slug}/.devfleet/") for name in members):
            raise ValueError("Archive is missing .devfleet metadata.")
    return {"archive_sha256": digest.hexdigest(), "archive_bytes": size, "entries": len(members), "verified": True}


def _assert_same_filesystem(staging: Path, destination_parent: Path) -> None:
    """Require atomic rename topology before moving an existing workspace."""
    try:
        staging_device = os.stat(staging).st_dev
        destination_device = os.stat(destination_parent).st_dev
    except OSError as exc:
        raise ValueError("Workspace restore cannot verify same-filesystem atomic promotion.") from exc
    if staging_device != destination_device:
        raise ValueError("Workspace restore refused: staging and destination are on different filesystems.")


def _restore_journal_path(destination: Path) -> Path:
    return destination.parent / f".{destination.name}.restore-transaction.json"


RESTORE_JOURNAL_SCHEMA_VERSION = 1
RESTORE_JOURNAL_PHASES = frozenset({
    "PREPARED",
    "OLD_MOVED_TO_ROLLBACK",
    "NEW_PROMOTED",
    "POSTCHECK_PASSED",
    "COMMITTED",
})


@dataclass(frozen=True)
class _RestoreJournal:
    schema_version: int
    slug: str
    destination: Path
    staging_root: Path
    rollback: Path
    phase: str


def _is_reparse_point(path: Path) -> bool:
    """Return true for symlinks and Windows junction/reparse objects."""
    if path.is_symlink():
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _canonical_journal_path(value: Any, field: str) -> tuple[Path, Path]:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Restore journal {field} must be a non-empty absolute path.")
    raw = Path(value)
    if not raw.is_absolute() or value.strip() in {".", ".."}:
        raise ValueError(f"Restore journal {field} must be an absolute path.")
    lexical = Path(os.path.abspath(os.fspath(raw)))
    canonical = raw.resolve(strict=False)
    if os.path.normcase(os.fspath(lexical)) != os.path.normcase(os.fspath(canonical)):
        raise ValueError(f"Restore journal {field} uses a symlink, reparse point, or alias path.")
    return lexical, canonical


def _require_direct_safe_transaction_child(path: Path, parent: Path, field: str) -> None:
    if path == parent or path.parent != parent:
        raise ValueError(f"Restore journal {field} is not a direct transaction sibling.")
    if path.exists() or path.is_symlink():
        if _is_reparse_point(path):
            raise ValueError(f"Restore journal {field} is a symlink or reparse point.")


def _parse_restore_journal(journal: Any, requested_destination: Path) -> _RestoreJournal:
    if not isinstance(journal, dict):
        raise ValueError("Restore journal must be a JSON object.")
    schema_version = journal.get("schema_version")
    if type(schema_version) is not int or schema_version != RESTORE_JOURNAL_SCHEMA_VERSION:
        raise ValueError("Restore journal schema version is unsupported.")

    expected_slug = validate_slug(requested_destination.name)
    slug = journal.get("slug")
    if not isinstance(slug, str) or slug != expected_slug:
        raise ValueError("Restore journal slug does not match the requested workspace.")

    destination_lexical, destination = _canonical_journal_path(journal.get("destination"), "destination")
    staging_lexical, staging_root = _canonical_journal_path(journal.get("staging_root"), "staging_root")
    rollback_lexical, rollback = _canonical_journal_path(journal.get("rollback"), "rollback")
    if destination != requested_destination or destination_lexical != requested_destination:
        raise ValueError("Restore journal destination does not match the requested workspace.")

    parent = requested_destination.parent
    for path, field in ((staging_root, "staging_root"), (rollback, "rollback")):
        if path in {requested_destination, parent}:
            raise ValueError(f"Restore journal {field} aliases the destination or transaction parent.")
        _require_direct_safe_transaction_child(path, parent, field)

    stage_pattern = re.compile(rf"^\.{re.escape(expected_slug)}-restore-[A-Za-z0-9_-]{{6,64}}$")
    rollback_pattern = re.compile(rf"^\.{re.escape(expected_slug)}\.rollback-[0-9a-f]{{32}}$")
    if not stage_pattern.fullmatch(staging_lexical.name):
        raise ValueError("Restore journal staging_root has an invalid transaction identity.")
    if not rollback_pattern.fullmatch(rollback_lexical.name):
        raise ValueError("Restore journal rollback has an invalid transaction identity.")
    if staging_root == rollback:
        raise ValueError("Restore journal staging and rollback identities overlap.")

    phase = journal.get("phase")
    if not isinstance(phase, str) or phase not in RESTORE_JOURNAL_PHASES:
        raise ValueError("Restore journal phase is unsupported.")
    return _RestoreJournal(schema_version, slug, destination, staging_root, rollback, phase)


def _write_restore_manual_recovery(destination: Path, journal_path: Path, reason: str) -> None:
    evidence_path = destination.parent / f".{destination.name}.restore-manual-recovery.json"
    atomic_json(evidence_path, {
        "schema_version": 1,
        "status": "MANUAL_RECOVERY_REQUIRED",
        "destination": str(destination),
        "journal": str(journal_path),
        "reason": reason,
        "detected_at": now_iso(),
    })


POSIX_RESTORE_JOURNAL_SCHEMA_VERSION = 2
TRANSACTION_ROOT_NAME = ".devfleet-transactions"


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _open_directory_path(path: Path) -> tuple[int, os.stat_result]:
    lexical = _absolute_path(path)
    observed = os.lstat(lexical)
    if stat.S_IFMT(observed.st_mode) != stat.S_IFDIR:
        raise ValueError(f"Restore path is not a real directory: {lexical}")
    fd = os.open(lexical, _fd_directory_flags())
    try:
        actual = os.fstat(fd)
        if not _identity_matches(actual, _object_identity(observed)):
            raise ValueError(f"Restore directory identity changed before authorization: {lexical}")
        return fd, actual
    except Exception:
        os.close(fd)
        raise


def _identity_at(parent_fd: int, name: str) -> dict[str, int] | None:
    try:
        return _object_identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
    except FileNotFoundError:
        return None


def _mkdir_verified_at(parent_fd: int, name: str, mode: int = 0o700) -> tuple[int, os.stat_result]:
    try:
        os.mkdir(name, mode, dir_fd=parent_fd)
    except FileExistsError:
        pass
    return _open_verified_child(parent_fd, name, stat.S_IFDIR)


def _remove_tree_at(parent_fd: int, name: str, expected: dict[str, int], field: str) -> None:
    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not _identity_matches(current, expected):
        raise RuntimeError(f"Restore transaction {field} changed before cleanup; manual recovery required.")
    kind = stat.S_IFMT(current.st_mode)
    if kind == stat.S_IFLNK:
        raise RuntimeError(f"Restore transaction {field} is an alias; manual recovery required.")
    if kind == stat.S_IFREG:
        os.unlink(name, dir_fd=parent_fd)
        return
    if kind != stat.S_IFDIR:
        raise RuntimeError(f"Restore transaction {field} has an unsupported type; manual recovery required.")
    fd, _ = _open_verified_child(parent_fd, name, stat.S_IFDIR)
    try:
        for child in sorted(os.listdir(fd)):
            child_identity = _identity_at(fd, child)
            if child_identity is None:
                raise RuntimeError(f"Restore transaction {field} changed during cleanup; manual recovery required.")
            _remove_tree_at(fd, child, child_identity, f"{field}/{child}")
    finally:
        os.close(fd)
    # The transaction parent is service-owned in the deployed Linux layout;
    # verify the named object one final time before removing the directory.
    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not _identity_matches(current, expected):
        raise RuntimeError(f"Restore transaction {field} changed before directory removal; manual recovery required.")
    os.rmdir(name, dir_fd=parent_fd)


def _extract_archive_at_fd(archive: tarfile.TarFile, slug: str, staging_fd: int) -> None:
    # The archive contract is <slug>/<descendants>.  Keep that root object
    # beneath the protected transaction directory so promotion can rename the
    # exact descriptor-bound staging/<slug> object.  Descendants are then
    # created relative to the already-open verified slug descriptor.
    slug_fd, _ = _mkdir_verified_at(staging_fd, slug)
    try:
        for member in archive.getmembers():
            safe_name = member.name.replace("\\", "/")
            parts = safe_name.split("/")
            if parts[0] != slug:
                raise ValueError(f"Archive member is outside the requested project: {member.name}")
            relative = parts[1:]
            if not relative:
                if member.isdir():
                    os.fchmod(slug_fd, member.mode & 0o777)
                continue
            current_fd = slug_fd
            opened: list[int] = []
            try:
                for component in relative[:-1]:
                    try:
                        child_fd, _ = _open_verified_child(current_fd, component, stat.S_IFDIR)
                    except FileNotFoundError:
                        os.mkdir(component, 0o700, dir_fd=current_fd)
                        child_fd, _ = _open_verified_child(current_fd, component, stat.S_IFDIR)
                    opened.append(child_fd)
                    current_fd = child_fd
                leaf = relative[-1]
                if member.isdir():
                    try:
                        leaf_fd, _ = _open_verified_child(current_fd, leaf, stat.S_IFDIR)
                    except FileNotFoundError:
                        os.mkdir(leaf, member.mode & 0o777, dir_fd=current_fd)
                        leaf_fd, _ = _open_verified_child(current_fd, leaf, stat.S_IFDIR)
                    os.fchmod(leaf_fd, member.mode & 0o777)
                    os.close(leaf_fd)
                else:
                    fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), member.mode & 0o777, dir_fd=current_fd)
                    try:
                        source = archive.extractfile(member)
                        if source is None:
                            raise ValueError(f"Archive member could not be read: {member.name}")
                        with source, os.fdopen(fd, "wb", closefd=False) as target:
                            shutil.copyfileobj(source, target)
                        os.fchmod(fd, member.mode & 0o777)
                    finally:
                        os.close(fd)
            finally:
                for fd in reversed(opened):
                    os.close(fd)
    finally:
        os.close(slug_fd)


def _posix_restore_journal(destination: Path, staging: Path, rollback: Path, transaction_root: Path, *, phase: str, destination_identity: dict[str, int] | None, staging_identity: dict[str, int], rollback_identity: dict[str, int] | None, restored_identity: dict[str, int] | None) -> dict[str, Any]:
    return {
        "schema_version": POSIX_RESTORE_JOURNAL_SCHEMA_VERSION,
        "slug": validate_slug(destination.name),
        "destination": str(destination),
        "transaction_root": str(transaction_root),
        "staging_root": str(staging),
        "rollback": str(rollback),
        "destination_identity": destination_identity,
        "staging_identity": staging_identity,
        "rollback_identity": rollback_identity,
        "restored_identity": restored_identity,
        "phase": phase,
        "updated_at": now_iso(),
    }


def _parse_posix_restore_journal(value: Any, destination: Path) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != POSIX_RESTORE_JOURNAL_SCHEMA_VERSION:
        raise ValueError("Restore journal schema version is unsupported.")
    if value.get("slug") != validate_slug(destination.name):
        raise ValueError("Restore journal slug does not match the requested workspace.")
    expected_destination = _absolute_path(destination)
    for field in ("destination", "transaction_root", "staging_root", "rollback"):
        raw = value.get(field)
        if not isinstance(raw, str) or _absolute_path(Path(raw)) != Path(raw):
            raise ValueError(f"Restore journal {field} is not a lexical absolute path.")
    if Path(value["destination"]) != expected_destination:
        raise ValueError("Restore journal destination does not match the requested workspace.")
    transaction_root = Path(value["transaction_root"])
    if transaction_root != expected_destination.parent / TRANSACTION_ROOT_NAME:
        raise ValueError("Restore journal transaction root is not the protected local root.")
    staging = Path(value["staging_root"])
    rollback = Path(value["rollback"])
    if staging.parent != transaction_root or rollback.parent != expected_destination.parent:
        raise ValueError("Restore journal transaction paths are not descriptor-bound siblings.")
    slug = validate_slug(destination.name)
    if not re.fullmatch(rf".{re.escape(slug)}-restore-[A-Za-z0-9_-]{{6,64}}", staging.name):
        raise ValueError("Restore journal staging identity is invalid.")
    if not re.fullmatch(rf".{re.escape(slug)}\.rollback-[0-9a-f]{{32}}", rollback.name):
        raise ValueError("Restore journal rollback identity is invalid.")
    for field in ("destination_identity", "staging_identity", "rollback_identity", "restored_identity"):
        identity = value.get(field)
        if identity is not None and (not isinstance(identity, dict) or set(identity) != {"st_dev", "st_ino", "st_type"} or not all(type(identity[key]) is int for key in identity)):
            raise ValueError(f"Restore journal {field} identity is malformed.")
    if value.get("phase") not in RESTORE_JOURNAL_PHASES:
        raise ValueError("Restore journal phase is unsupported.")
    if not isinstance(value.get("staging_identity"), dict):
        raise ValueError("Restore journal is missing the staging identity.")
    return value


def _posix_manual_recovery(destination: Path, journal_path: Path, reason: str) -> None:
    _write_restore_manual_recovery(destination, journal_path, reason)


def _reconcile_restore_transaction_posix(destination: Path) -> dict[str, Any] | None:
    destination = _absolute_path(destination)
    journal_path = _restore_journal_path(destination)
    if not journal_path.is_file():
        return None
    parent_fd = transaction_fd = None
    try:
        if _is_reparse_point(journal_path):
            raise ValueError("Restore transaction record is an alias.")
        record = _parse_posix_restore_journal(json.loads(journal_path.read_text(encoding="utf-8")), destination)
        parent_fd, _ = _open_directory_path(destination.parent)
        transaction_fd, _ = _open_verified_child(parent_fd, TRANSACTION_ROOT_NAME, stat.S_IFDIR)
        staging = Path(record["staging_root"])
        rollback = Path(record["rollback"])
        phase = record["phase"]
        staging_id = record["staging_identity"]
        rollback_id = record.get("rollback_identity")
        destination_id = record.get("destination_identity")
        restored_id = record.get("restored_identity")
        if _identity_at(transaction_fd, staging.name) != staging_id:
            raise RuntimeError("Restore staging identity is ambiguous; manual recovery required.")
        if phase in {"PREPARED", "OLD_MOVED_TO_ROLLBACK"}:
            if phase == "PREPARED":
                current_destination = _identity_at(parent_fd, destination.name)
                current_rollback = _identity_at(parent_fd, rollback.name)
                if current_destination != destination_id or current_rollback is not None:
                    raise RuntimeError("Restore PREPARED identities changed; manual recovery required.")
            else:
                if _identity_at(parent_fd, destination.name) is not None or _identity_at(parent_fd, rollback.name) != rollback_id:
                    raise RuntimeError("Restore rollback identities changed; manual recovery required.")
                os.rename(rollback.name, destination.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                if _identity_at(parent_fd, destination.name) != destination_id:
                    raise RuntimeError("Restore rollback promotion identity check failed; manual recovery required.")
        elif phase in {"NEW_PROMOTED", "POSTCHECK_PASSED", "COMMITTED"}:
            if _identity_at(parent_fd, destination.name) != restored_id:
                raise RuntimeError("Restore destination identity is ambiguous; manual recovery required.")
            if phase != "COMMITTED":
                try:
                    inspection = inspect_workspace(destination)
                    if not inspection["safe_for_archive"]:
                        raise ValueError("Restored workspace is not archive-safe.")
                except Exception:
                    if rollback_id is None or _identity_at(parent_fd, rollback.name) != rollback_id:
                        raise RuntimeError("Restore rollback identity is unavailable; manual recovery required.")
                    _remove_tree_at(parent_fd, destination.name, restored_id, "destination")
                    os.rename(rollback.name, destination.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                    if _identity_at(parent_fd, destination.name) != destination_id:
                        raise RuntimeError("Restore rollback verification failed; manual recovery required.")
        if _identity_at(transaction_fd, staging.name) != staging_id:
            raise RuntimeError("Restore staging changed before cleanup; manual recovery required.")
        _remove_tree_at(transaction_fd, staging.name, staging_id, "staging")
        if rollback_id is not None and _identity_at(parent_fd, rollback.name) is not None:
            if _identity_at(parent_fd, rollback.name) != rollback_id:
                raise RuntimeError("Restore rollback changed before cleanup; manual recovery required.")
            if _identity_at(parent_fd, destination.name) is None:
                raise RuntimeError("Restore cleanup lost the canonical destination; manual recovery required.")
            _remove_tree_at(parent_fd, rollback.name, rollback_id, "rollback")
        journal_path.unlink(missing_ok=True)
        return {"recovered": True, "phase": phase, "destination": str(destination)}
    except Exception as exc:
        reason = f"{type(exc).__name__}: {exc}"
        with contextlib.suppress(OSError):
            _posix_manual_recovery(destination, journal_path, reason)
        if isinstance(exc, RuntimeError) and "manual recovery required" in str(exc):
            raise
        raise RuntimeError("Unfinished workspace restore could not be reconciled safely; manual recovery required and cleanup was refused.") from exc
    finally:
        if transaction_fd is not None:
            os.close(transaction_fd)
        if parent_fd is not None:
            os.close(parent_fd)


def reconcile_restore_transaction(destination: Path) -> dict[str, Any] | None:
    if POSIX_FD_HARDENING:
        return _reconcile_restore_transaction_posix(destination)
    return _reconcile_restore_transaction_compat(destination)


def _reconcile_restore_transaction_compat(destination: Path) -> dict[str, Any] | None:
    """Compatibility recovery path for Windows unit-test support."""
    destination = destination.resolve(strict=False)
    journal_path = _restore_journal_path(destination)
    if not journal_path.is_file():
        return None
    try:
        if _is_reparse_point(journal_path):
            raise ValueError("Restore transaction record is a symlink or reparse point.")
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        transaction = _parse_restore_journal(journal, destination)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        reason = f"{type(exc).__name__}: {exc}"
        try:
            _write_restore_manual_recovery(destination, journal_path, reason)
        except OSError:
            pass
        raise RuntimeError("Unfinished workspace restore is unauthorized or unreadable; manual recovery required and cleanup was refused.") from exc
    phase = transaction.phase
    staged = transaction.staging_root
    rollback = transaction.rollback
    if phase in {"PREPARED", "OLD_MOVED_TO_ROLLBACK"}:
        if not destination.exists() and rollback.exists():
            os.replace(rollback, destination)
        if not destination.exists() and phase == "OLD_MOVED_TO_ROLLBACK":
            raise RuntimeError("Unfinished workspace restore lost both canonical and rollback identities; manual recovery required.")
    elif phase in {"NEW_PROMOTED", "POSTCHECK_PASSED"}:
        if not destination.is_dir() or destination.is_symlink():
            if rollback.exists():
                os.replace(rollback, destination)
            else:
                raise RuntimeError("Unfinished workspace restore has no safe canonical or rollback copy.")
        else:
            try:
                inspect_workspace(destination)
            except Exception:
                if rollback.exists():
                    shutil.rmtree(destination)
                    os.replace(rollback, destination)
                else:
                    raise
    if staged.exists():
        shutil.rmtree(staged, ignore_errors=True)
    if rollback.exists() and destination.exists():
        shutil.rmtree(rollback, ignore_errors=True)
    journal_path.unlink(missing_ok=True)
    return {"recovered": True, "phase": phase, "destination": str(destination)}


def _restore_workspace_archive_posix(archive_path: Path, destination: Path, slug: str) -> dict[str, Any]:
    slug = validate_slug(slug)
    verification = validate_archive(archive_path, slug)
    destination = _absolute_path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    reconcile_restore_transaction(destination)
    parent_fd, _ = _open_directory_path(destination.parent)
    transaction_fd = None
    staging_fd = None
    promoted_id = None
    old_destination_id = _identity_at(parent_fd, destination.name)
    rollback_name = f".{destination.name}.rollback-{uuid.uuid4().hex}"
    staging_name = f".{slug}-restore-{uuid.uuid4().hex}"
    rollback_id = None
    staging_id = None
    journal_path = _restore_journal_path(destination)
    transaction_root = destination.parent / TRANSACTION_ROOT_NAME
    staging = transaction_root / staging_name
    rollback = destination.parent / rollback_name
    try:
        transaction_fd, _ = _mkdir_verified_at(parent_fd, TRANSACTION_ROOT_NAME)
        os.mkdir(staging_name, 0o700, dir_fd=transaction_fd)
        staging_fd, staging_result = _open_verified_child(transaction_fd, staging_name, stat.S_IFDIR)
        staging_id = _object_identity(staging_result)
        if _identity_at(parent_fd, rollback_name) is not None:
            raise RuntimeError("Restore rollback name unexpectedly exists; manual recovery required.")
        journal = _posix_restore_journal(destination, staging, rollback, transaction_root, phase="PREPARED", destination_identity=old_destination_id, staging_identity=staging_id, rollback_identity=None, restored_identity=None)
        atomic_json(journal_path, journal)
        with tarfile.open(archive_path, "r:gz") as archive:
            _validate_members(archive, slug)
            _extract_archive_at_fd(archive, slug, staging_fd)
        restored_fd, restored_result = _open_verified_child(staging_fd, slug, stat.S_IFDIR)
        restored_id = _object_identity(restored_result)
        os.close(restored_fd)
        journal["restored_identity"] = restored_id
        atomic_json(journal_path, journal)
        if restored_result.st_dev != os.fstat(parent_fd).st_dev:
            raise ValueError("Workspace restore refused: staging and destination are on different filesystems.")
        if old_destination_id is not None:
            if _identity_at(parent_fd, destination.name) != old_destination_id or _identity_at(parent_fd, rollback_name) is not None:
                raise RuntimeError("Restore destination changed before rollback transition; manual recovery required.")
            os.rename(destination.name, rollback_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            rollback_id = _identity_at(parent_fd, rollback_name)
            if rollback_id != old_destination_id:
                raise RuntimeError("Restore rollback identity check failed; manual recovery required.")
            journal["rollback_identity"] = rollback_id
            journal["phase"] = "OLD_MOVED_TO_ROLLBACK"
            journal["updated_at"] = now_iso()
            atomic_json(journal_path, journal)
        if _identity_at(transaction_fd, staging_name) != staging_id or _identity_at(parent_fd, destination.name) is not None:
            raise RuntimeError("Restore staging or destination identity changed before promotion; manual recovery required.")
        os.rename(slug, destination.name, src_dir_fd=staging_fd, dst_dir_fd=parent_fd)
        promoted_id = _identity_at(parent_fd, destination.name)
        if promoted_id != restored_id:
            raise RuntimeError("Restore destination identity check failed; manual recovery required.")
        journal["phase"] = "NEW_PROMOTED"
        journal["updated_at"] = now_iso()
        atomic_json(journal_path, journal)
        inspection = inspect_workspace(destination)
        if not inspection["safe_for_archive"]:
            raise ValueError("Restored workspace failed the archive safety inspection.")
        journal["phase"] = "POSTCHECK_PASSED"
        journal["updated_at"] = now_iso()
        atomic_json(journal_path, journal)
        if rollback_id is not None:
            _remove_tree_at(parent_fd, rollback_name, rollback_id, "rollback")
        _remove_tree_at(transaction_fd, staging_name, staging_id, "staging")
        journal["phase"] = "COMMITTED"
        journal["updated_at"] = now_iso()
        atomic_json(journal_path, journal)
        journal_path.unlink(missing_ok=True)
        return {**verification, "workspace": str(destination), "restored": True, "inspection": inspection}
    except Exception as exc:
        # Roll back only identities proven to be the objects this transaction
        # created/moved.  A substituted destination or rollback is left in
        # place with a manual-recovery record rather than recursively deleting it.
        try:
            current_destination = _identity_at(parent_fd, destination.name)
            if promoted_id is not None:
                if current_destination != promoted_id:
                    raise RuntimeError("Restore promoted destination identity is ambiguous; manual recovery required.")
                _remove_tree_at(parent_fd, destination.name, promoted_id, "destination")
                current_destination = None
            if old_destination_id is not None and current_destination is None:
                current_rollback = _identity_at(parent_fd, rollback_name)
                if rollback_id is not None and current_rollback != rollback_id:
                    raise RuntimeError("Restore rollback identity is ambiguous; manual recovery required.")
                if current_rollback == old_destination_id or current_rollback == rollback_id:
                    os.rename(rollback_name, destination.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            if staging_id is not None and transaction_fd is not None and _identity_at(transaction_fd, staging_name) == staging_id:
                _remove_tree_at(transaction_fd, staging_name, staging_id, "staging")
        except Exception as rollback_exc:
            reason = f"{type(rollback_exc).__name__}: {rollback_exc}"
            with contextlib.suppress(OSError):
                _posix_manual_recovery(destination, journal_path, reason)
            raise RuntimeError("Workspace restore failed with ambiguous transaction identity; manual recovery required.") from rollback_exc
        raise
    finally:
        if staging_fd is not None:
            os.close(staging_fd)
        if transaction_fd is not None:
            os.close(transaction_fd)
        os.close(parent_fd)


def restore_workspace_archive(archive_path: Path, destination: Path, slug: str) -> dict[str, Any]:
    if POSIX_FD_HARDENING:
        return _restore_workspace_archive_posix(archive_path, destination, slug)
    return _restore_workspace_archive_compat(archive_path, destination, slug)


def _restore_workspace_archive_compat(archive_path: Path, destination: Path, slug: str) -> dict[str, Any]:
    """Restore one verified archive with rollback-safe sibling promotion.

    The existing workspace is never deleted before the staged tree has been
    validated.  Promotion is a same-filesystem rename, and the rollback sibling
    is retained until the promoted tree passes its post-promotion inspection.
    """
    slug = validate_slug(slug)
    verification = validate_archive(archive_path, slug)
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    rollback = destination.parent / f'.{destination.name}.rollback-{uuid.uuid4().hex}'
    _reconcile_restore_transaction_compat(destination)
    journal_path = _restore_journal_path(destination)
    staging_root = Path(tempfile.mkdtemp(prefix=f'.{slug}-restore-', dir=str(destination.parent)))
    journal = {"schema_version": 1, "slug": slug, "destination": str(destination), "staging_root": str(staging_root), "rollback": str(rollback), "phase": "PREPARED", "updated_at": now_iso()}
    atomic_json(journal_path, journal)
    promoted = False
    try:
        with tarfile.open(archive_path, 'r:gz') as archive:
            _validate_members(archive, slug)
            # Members were validated above; extract explicitly so behavior does
            # not depend on Python's version-specific tar extraction filter.
            members = archive.getmembers()
            for member in members:
                safe_name = member.name.replace('\\', '/')
                target = staging_root.joinpath(*safe_name.split('/'))
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    os.chmod(target, member.mode & 0o777)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError(f'Archive member could not be read: {member.name}')
                with source, target.open('xb') as destination_file:
                    shutil.copyfileobj(source, destination_file)
                # Tar metadata is untrusted.  Preserve only ordinary POSIX
                # permission bits; never restore setuid/setgid/sticky bits.
                os.chmod(target, member.mode & 0o777)
        restored = staging_root / slug
        if not restored.is_dir() or restored.is_symlink():
            raise ValueError('Verified archive did not produce a safe workspace directory.')
        _assert_same_filesystem(staging_root, destination.parent)
        if destination.exists():
            if destination.is_symlink() or not destination.is_dir():
                raise ValueError('Workspace destination is not a safe directory.')
            os.replace(destination, rollback)
            journal["phase"] = "OLD_MOVED_TO_ROLLBACK"; journal["updated_at"] = now_iso(); atomic_json(journal_path, journal)
        try:
            os.replace(restored, destination)
            promoted = True
            journal["phase"] = "NEW_PROMOTED"; journal["updated_at"] = now_iso(); atomic_json(journal_path, journal)
            inspection = inspect_workspace(destination)
            if not inspection['safe_for_archive']:
                raise ValueError('Restored workspace failed the archive safety inspection.')
            journal["phase"] = "POSTCHECK_PASSED"; journal["updated_at"] = now_iso(); atomic_json(journal_path, journal)
        except Exception:
            if destination.exists() and promoted:
                shutil.rmtree(destination)
            if rollback.exists() and not destination.exists():
                os.replace(rollback, destination)
            raise
        if rollback.exists():
            shutil.rmtree(rollback)
        journal["phase"] = "COMMITTED"; journal["updated_at"] = now_iso(); atomic_json(journal_path, journal)
        journal_path.unlink(missing_ok=True)
        return {**verification, 'workspace': str(destination), 'restored': True, 'inspection': inspection}
    finally:
        if staging_root.exists():
            shutil.rmtree(staging_root, ignore_errors=True)


def create_workspace_archive(
    root: Path,
    slug: str,
    destination: Path,
    *,
    include_generated: bool = False,
    consistency_level: str = "live-best-effort",
) -> dict[str, Any]:
    slug = validate_slug(slug)
    if POSIX_FD_HARDENING:
        inspection, entries = _capture_workspace_posix(root, include_generated=include_generated)
        if not inspection["safe_for_archive"]:
            _close_authorized_entries(entries)
            raise ValueError("Workspace contains symbolic links and cannot be archived safely.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=f".{slug}-", suffix=".tar.gz.tmp", dir=str(destination.parent))
        os.close(fd)
        temp_path = Path(temp_name)
        try:
            # Every regular member is streamed from the descriptor captured and
            # identity-checked above.  tarfile never reopens a workspace path.
            _write_authorized_tar(temp_path, slug, entries)
            verification = validate_archive(temp_path, slug)
            os.replace(temp_path, destination)
            return {
                **inspection,
                **verification,
                "archive_path": str(destination),
                "created_at": now_iso(),
                "consistency_level": consistency_level,
            }
        finally:
            _close_authorized_entries(entries)
            temp_path.unlink(missing_ok=True)
    inspection = inspect_workspace(root, include_generated=include_generated)
    if not inspection["safe_for_archive"]:
        raise ValueError("Workspace contains symbolic links and cannot be archived safely.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{slug}-", suffix=".tar.gz.tmp", dir=str(destination.parent))
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        with tarfile.open(temp_path, "w:gz", dereference=False) as archive:
            archive.add(
                root,
                arcname=slug,
                recursive=True,
                filter=lambda info: _archive_filter(info, slug, include_generated=include_generated),
            )
        verification = validate_archive(temp_path, slug)
        os.replace(temp_path, destination)
        return {
            **inspection,
            **verification,
            "archive_path": str(destination),
            "created_at": now_iso(),
            "consistency_level": consistency_level,
        }
    finally:
        temp_path.unlink(missing_ok=True)


def _archive_filter(
    info: tarfile.TarInfo,
    slug: str,
    *,
    include_generated: bool = False,
) -> tarfile.TarInfo | None:
    relative_parts = Path(info.name).parts[1:]
    if not include_generated and any(part in GENERATED_DIR_NAMES for part in relative_parts):
        return None
    # The source walk rejects symlinks and unsupported filesystem entries; this
    # second check protects against a race between inspection and tar.add().
    if info.issym() or info.islnk() or info.isdev() or not (info.isdir() or info.isfile()):
        raise ValueError(f"Workspace contains an unsupported archive entry: {info.name}")
    return info


def write_backup_manifest(directory: Path, *, slug: str, project_id: str, runtime: dict[str, Any], archive: dict[str, Any], consistency_level: str = "live-best-effort") -> dict[str, Any]:
    if consistency_level not in {"live-best-effort", "quiesced", "application-consistent"}:
        raise ValueError("Unknown backup consistency level.")
    directory.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": 1,
        "backup_id": directory.name,
        "created_at": archive.get("created_at") or now_iso(),
        "project_id": project_id,
        "slug": validate_slug(slug),
        "runtime": runtime,
        "workspace": {key: archive.get(key) for key in ("archive_path", "archive_sha256", "archive_bytes", "files", "bytes", "entries", "generated_dirs", "generated_details", "generated_bytes", "estimated_archive_bytes", "symlinks", "symlink_targets", "included_path_count", "included_file_count", "included_byte_count", "omitted_paths", "omission_policy_source")},
        "verification": {"status": "verified", "integrity_verified": True, "consistency_level": consistency_level, "consistency_level_source": "transaction-parameter", "verified_at": now_iso()},
    }
    atomic_json(directory / "manifest.json", manifest)
    return manifest
