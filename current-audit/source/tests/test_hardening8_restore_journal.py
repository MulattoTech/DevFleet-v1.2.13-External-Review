import json
import os
import stat
from pathlib import Path

import pytest

from devfleet import workspace_archives
from devfleet.workspace_archives import reconcile_restore_transaction


ROLLBACK_TOKEN = "0123456789abcdef0123456789abcdef"


def _paths(tmp_path: Path, slug: str = "demo") -> tuple[Path, Path, Path, Path]:
    destination = tmp_path / slug
    transaction_root = tmp_path / workspace_archives.TRANSACTION_ROOT_NAME
    staging = transaction_root / f".{slug}-restore-ABC12345" if workspace_archives.POSIX_FD_HARDENING else tmp_path / f".{slug}-restore-ABC12345"
    rollback = tmp_path / f".{slug}.rollback-{ROLLBACK_TOKEN}"
    journal = tmp_path / f".{slug}.restore-transaction.json"
    return destination, staging, rollback, journal


def _record(destination: Path, staging: Path, rollback: Path, phase: str = "PREPARED") -> dict:
    if workspace_archives.POSIX_FD_HARDENING:
        def identity(path: Path):
            result = path.lstat()
            return {
                "st_dev": int(result.st_dev),
                "st_ino": int(result.st_ino),
                "st_type": int(stat.S_IFMT(result.st_mode)),
            }

        destination_identity = identity(destination) if destination.exists() else None
        rollback_identity = identity(rollback) if rollback.exists() else None
        restored_identity = destination_identity if phase in {"NEW_PROMOTED", "POSTCHECK_PASSED", "COMMITTED"} else None
        return {
            "schema_version": workspace_archives.POSIX_RESTORE_JOURNAL_SCHEMA_VERSION,
            "slug": destination.name,
            "destination": str(destination.absolute()),
            "transaction_root": str(destination.parent / workspace_archives.TRANSACTION_ROOT_NAME),
            "staging_root": str(staging.absolute()),
            "rollback": str(rollback.absolute()),
            "destination_identity": destination_identity if phase != "OLD_MOVED_TO_ROLLBACK" else rollback_identity,
            "staging_identity": identity(staging) if staging.exists() else None,
            "rollback_identity": rollback_identity,
            "restored_identity": restored_identity,
            "phase": phase,
        }
    return {
        "schema_version": 1,
        "slug": destination.name,
        "destination": str(destination),
        "staging_root": str(staging),
        "rollback": str(rollback),
        "phase": phase,
    }


def _write_record(journal: Path, record: dict) -> None:
    journal.write_text(json.dumps(record), encoding="utf-8")


def _assert_refused_without_mutation(tmp_path: Path, record: dict) -> None:
    destination, staging, rollback, journal = _paths(tmp_path)
    if workspace_archives.POSIX_FD_HARDENING:
        staging.parent.mkdir(exist_ok=True)
    destination.mkdir(exist_ok=True)
    staging.mkdir(exist_ok=True)
    rollback.mkdir(exist_ok=True)
    for path in (destination, staging, rollback):
        (path / "SENTINEL").write_text(path.name, encoding="utf-8")
    _write_record(journal, record)

    with pytest.raises(RuntimeError, match="manual recovery required"):
        reconcile_restore_transaction(destination)

    assert journal.exists()
    assert (tmp_path / ".demo.restore-manual-recovery.json").is_file()
    for path in (destination, staging, rollback):
        assert (path / "SENTINEL").read_text(encoding="utf-8") == path.name


@pytest.mark.parametrize(
    ("field", "unsafe"),
    [
        ("staging_root", ""),
        ("staging_root", None),
        ("staging_root", "."),
        ("staging_root", ".."),
        ("staging_root", "../outside"),
        ("rollback", ""),
        ("rollback", None),
        ("rollback", "."),
        ("rollback", ".."),
        ("rollback", "../outside"),
    ],
)
def test_restore_journal_rejects_empty_and_relative_paths_without_mutation(tmp_path, field, unsafe):
    destination, staging, rollback, _ = _paths(tmp_path)
    record = _record(destination, staging, rollback)
    record[field] = unsafe
    _assert_refused_without_mutation(tmp_path, record)


@pytest.mark.parametrize("field", ["staging_root", "rollback"])
def test_restore_journal_rejects_absolute_outside_paths_and_preserves_sentinel(tmp_path, field):
    destination, staging, rollback, _ = _paths(tmp_path)
    outside = tmp_path.parent / f"outside-{field}-{tmp_path.name}"
    outside.mkdir()
    try:
        sentinel = outside / "UNRELATED-SENTINEL"
        sentinel.write_text("keep", encoding="utf-8")
        record = _record(destination, staging, rollback)
        record[field] = str(outside)
        _assert_refused_without_mutation(tmp_path, record)
        assert sentinel.read_text(encoding="utf-8") == "keep"
    finally:
        for child in outside.iterdir():
            child.unlink()
        outside.rmdir()


@pytest.mark.parametrize(
    "mutation",
    [
        {"schema_version": 2},
        {"schema_version": "1"},
        {"slug": "wrong-slug"},
        {"destination": None},
        {"destination": "."},
        {"phase": "UNKNOWN"},
    ],
)
def test_restore_journal_rejects_wrong_schema_slug_destination_and_phase(tmp_path, mutation):
    destination, staging, rollback, _ = _paths(tmp_path)
    record = _record(destination, staging, rollback)
    record.update(mutation)
    if mutation.get("destination") is None and "destination" not in mutation:
        record["destination"] = str(tmp_path / "wrong")
    _assert_refused_without_mutation(tmp_path, record)


def test_restore_journal_rejects_wrong_absolute_destination(tmp_path):
    destination, staging, rollback, _ = _paths(tmp_path)
    record = _record(destination, staging, rollback)
    record["destination"] = str(tmp_path / "other")
    _assert_refused_without_mutation(tmp_path, record)


def test_restore_journal_rejects_swapped_stage_and_rollback(tmp_path):
    destination, staging, rollback, _ = _paths(tmp_path)
    record = _record(destination, staging, rollback)
    record["staging_root"], record["rollback"] = record["rollback"], record["staging_root"]
    _assert_refused_without_mutation(tmp_path, record)


@pytest.mark.parametrize("field", ["staging_root", "rollback"])
def test_restore_journal_rejects_symlinked_transaction_paths(tmp_path, field):
    destination, staging, rollback, _ = _paths(tmp_path)
    target = tmp_path / "foreign-target"
    target.mkdir()
    path = staging if field == "staging_root" else rollback
    if workspace_archives.POSIX_FD_HARDENING:
        path.parent.mkdir(exist_ok=True)
    try:
        os.symlink(target, path, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlink creation unavailable: {exc}")
    other = rollback if field == "staging_root" else staging
    if workspace_archives.POSIX_FD_HARDENING:
        other.parent.mkdir(exist_ok=True)
    other.mkdir()
    destination.mkdir()
    for candidate in (destination, target, other):
        (candidate / "SENTINEL").write_text(candidate.name, encoding="utf-8")
    record = _record(destination, staging, rollback)
    journal = tmp_path / ".demo.restore-transaction.json"
    _write_record(journal, record)

    with pytest.raises(RuntimeError, match="manual recovery required"):
        reconcile_restore_transaction(destination)

    assert (target / "SENTINEL").read_text(encoding="utf-8") == target.name
    assert (other / "SENTINEL").read_text(encoding="utf-8") == other.name
    assert journal.exists()


@pytest.mark.parametrize(
    "phase",
    ["PREPARED", "OLD_MOVED_TO_ROLLBACK", "NEW_PROMOTED", "POSTCHECK_PASSED", "COMMITTED"],
)
def test_restore_journal_reconciles_every_legitimate_phase_and_is_idempotent(tmp_path, phase):
    destination, staging, rollback, journal = _paths(tmp_path)
    if workspace_archives.POSIX_FD_HARDENING:
        staging.parent.mkdir(exist_ok=True)
    staging.mkdir()
    (staging / "temporary").write_text("discard", encoding="utf-8")
    if phase == "OLD_MOVED_TO_ROLLBACK":
        destination.mkdir()
        (destination / "known-good").write_text("old", encoding="utf-8")
        destination.rename(rollback)
    elif phase in {"NEW_PROMOTED", "POSTCHECK_PASSED", "COMMITTED"}:
        destination.mkdir()
        (destination / "canonical").write_text("current", encoding="utf-8")
        rollback.mkdir()
        (rollback / "known-good").write_text("old", encoding="utf-8")
    else:
        destination.mkdir()
        (destination / "canonical").write_text("current", encoding="utf-8")
    _write_record(journal, _record(destination, staging, rollback, phase))

    result = reconcile_restore_transaction(destination)

    assert result == {"recovered": True, "phase": phase, "destination": str(destination)}
    assert destination.is_dir()
    assert not staging.exists()
    assert not rollback.exists()
    assert not journal.exists()
    assert reconcile_restore_transaction(destination) is None
