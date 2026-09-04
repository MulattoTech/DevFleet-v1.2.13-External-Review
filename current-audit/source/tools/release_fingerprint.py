"""Build a deterministic fingerprint for the shipping packaging closure."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

try:
    from hook_modes import executable_template_hooks
except ModuleNotFoundError:  # imported as tools.release_fingerprint in tests
    from .hook_modes import executable_template_hooks


TRANSIENT_PARTS = {
    ".git",
    ".pytest_cache",
    ".test-runtime",
    "__pycache__",
    "bin",
    "obj",
    "outputs",
    "audit",
    "Payload",
}


def is_transient_part(part: str) -> bool:
    return part in TRANSIENT_PARTS or part.startswith(".venv")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _included(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    return path.is_file() and not any(is_transient_part(part) for part in relative.parts)


def _entries(root: Path, label: str, *, executable_by_contract: set[str] | frozenset[str] = frozenset()) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        if not _included(path, root):
            continue
        relative = path.relative_to(root).as_posix()
        result.append(
            {
                "root": label,
                "path": relative,
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
                # This is the mode written into the canonical TAR/portable
                # payload, never the incidental mode of the checkout host.
                "mode": "0755" if relative in executable_by_contract else "0644",
            }
        )
    return result


def _tooling_fingerprint(source_root: Path) -> dict[str, object]:
    """Fingerprint non-shipping release/audit tooling separately.

    The shipping release identity intentionally excludes repository-level tooling and
    automation so a review-bundle or harness change cannot silently invalidate a
    byte-identical application candidate.  Tooling still receives its own identity.
    """
    workspace = source_root.parent
    roots = [(workspace / "tools", "tools"), (workspace / "automation", "automation")]
    entries = [entry for root, label in roots if root.exists() for entry in _entries(root, label)]
    canonical = {"schemaVersion": 1, "toolingInputs": entries}
    serialized = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {**canonical, "toolingFingerprintId": hashlib.sha256(serialized.encode("utf-8")).hexdigest()}


def build_fingerprint(
    source_root: Path,
    installer_root: Path,
    artifacts: dict[str, Path] | None = None,
    *,
    source_executable_paths: set[str] | None = None,
) -> dict[str, object]:
    source_root = source_root.resolve()
    installer_root = installer_root.resolve()
    version = (source_root / "VERSION").read_text(encoding="utf-8").strip()
    installer_version = (installer_root / "INSTALLER_VERSION").read_text(encoding="utf-8").strip()
    executable_paths = executable_template_hooks(source_root) if source_executable_paths is None else set(source_executable_paths)
    unknown_executables = sorted(executable_paths - {path.relative_to(source_root).as_posix() for path in source_root.rglob("*") if _included(path, source_root)})
    if unknown_executables:
        raise ValueError(f"shipping mode contract names a missing file: {unknown_executables[0]}")
    entries = _entries(source_root, "source", executable_by_contract=executable_paths) + _entries(installer_root, "installer-source")
    artifact_entries: list[dict[str, object]] = []
    for name, path in sorted((artifacts or {}).items()):
        if not path.exists():
            continue
        artifact_entries.append({"name": name, "bytes": path.stat().st_size, "sha256": sha256(path)})
    canonical = {
        "schemaVersion": 2,
        "devfleetVersion": version,
        "installerVersion": installer_version,
        "shippingModeContract": {
            "schemaVersion": 1,
            "defaultMode": "0644",
            "executableMode": "0755",
            "executableByContract": sorted(executable_paths),
        },
        "shippingInputs": entries,
        "artifacts": artifact_entries,
    }
    serialized = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        **canonical,
        "releaseFingerprintId": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        "toolingFingerprint": _tooling_fingerprint(source_root),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--installer-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--artifact", action="append", default=[], metavar="NAME=PATH")
    args = parser.parse_args()
    artifacts = {}
    for value in args.artifact:
        name, separator, raw_path = value.partition("=")
        if not separator or not name or not raw_path:
            parser.error(f"artifact must be NAME=PATH: {value}")
        artifacts[name] = Path(raw_path)
    output = build_fingerprint(args.source_root, args.installer_root, artifacts)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temporary, args.output)
    print(output["releaseFingerprintId"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
