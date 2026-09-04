"""Compute live and candidate shipping-input rows from the release fingerprint contract.

This is release tooling: it imports the candidate-bound ``release_fingerprint``
implementation instead of maintaining a second inclusion/mode/hash policy.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


RELEASE_ARTIFACT_NAMES = frozenset({"exe", "tar", "portable", "installerSource"})


def _fingerprint(source: Path, installer: Path, artifacts: dict[str, Path] | None = None) -> dict[str, object]:
    tools = source / "tools"
    previous_modules = {name: sys.modules.get(name) for name in ("release_fingerprint", "hook_modes")}
    for name in previous_modules:
        sys.modules.pop(name, None)
    sys.path.insert(0, str(tools))
    try:
        from release_fingerprint import build_fingerprint  # type: ignore

        return build_fingerprint(source, installer, artifacts)
    finally:
        sys.path.pop(0)
        for name in previous_modules:
            sys.modules.pop(name, None)
        for name, module in previous_modules.items():
            if module is not None:
                sys.modules[name] = module


def _git_commit_exists(workspace: Path, commit: str) -> None:
    if not commit or len(commit) != 40 or any(ch not in "0123456789abcdefABCDEF" for ch in commit):
        raise ValueError("candidate commit must be an explicit 40-character Git object ID")
    try:
        subprocess.run(["git", "-C", str(workspace), "cat-file", "-e", f"{commit}^{{commit}}"], check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"candidate commit does not resolve to a commit: {commit}") from exc


def _materialize_candidate(workspace: Path, commit: str, artifacts: dict[str, Path] | None = None) -> tuple[dict[str, object], Path]:
    """Materialize candidate shipping trees without changing the checkout."""
    _git_commit_exists(workspace, commit)
    try:
        archive = subprocess.check_output(["git", "-C", str(workspace), "-c", "core.autocrlf=false", "archive", "--format=tar", commit, "source", "installer-source"], stderr=subprocess.STDOUT)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"candidate shipping tree could not be materialized: {commit}") from exc
    staging = Path(tempfile.mkdtemp(prefix="devfleet-candidate-"))
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as stream:
            stream.extractall(staging, filter="data")
        source, installer = staging / "source", staging / "installer-source"
        if not source.is_dir() or not installer.is_dir():
            raise ValueError("candidate commit has ambiguous or incomplete shipping roots")
        return _fingerprint(source, installer, artifacts), staging
    except Exception:
        import shutil
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _shipping_identity(fingerprint: dict[str, object]) -> str:
    payload = {"schemaVersion": 1, "devfleetVersion": fingerprint["devfleetVersion"], "installerVersion": fingerprint["installerVersion"], "shippingModeContract": fingerprint["shippingModeContract"], "shippingInputs": fingerprint["shippingInputs"]}
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _materialization_comparison(
    live_source: Path,
    live_installer: Path,
    candidate_source: Path,
    candidate_installer: Path,
    live: dict[str, object],
    candidate: dict[str, object],
) -> dict[str, object]:
    """Classify checkout differences without weakening Git-object authority.

    Only insertion of CR before an LF in a live Windows checkout is accepted
    as a non-substantive materialization difference.  Missing files, mode
    contract changes, versions, bare CR changes, or any other byte change are
    substantive.
    """

    def rows(value: dict[str, object]) -> dict[str, dict[str, object]]:
        return {
            f"{row['root']}/{row['path']}": row
            for row in value["shippingInputs"]  # type: ignore[index]
        }

    live_rows, candidate_rows = rows(live), rows(candidate)
    changed = sorted(
        path
        for path in set(live_rows) | set(candidate_rows)
        if live_rows.get(path) != candidate_rows.get(path)
    )
    crlf_only_paths: list[str] = []
    crlf_only = bool(changed)
    for relative in changed:
        live_row, candidate_row = live_rows.get(relative), candidate_rows.get(relative)
        if live_row is None or candidate_row is None or live_row.get("mode") != candidate_row.get("mode"):
            crlf_only = False
            continue
        root_name, path = relative.split("/", 1)
        live_root = live_source if root_name == "source" else live_installer
        candidate_root = candidate_source if root_name == "source" else candidate_installer
        live_bytes = (live_root / path).read_bytes()
        candidate_bytes = (candidate_root / path).read_bytes()
        if live_bytes != candidate_bytes and live_bytes.replace(b"\r\n", b"\n") == candidate_bytes:
            crlf_only_paths.append(relative)
        else:
            crlf_only = False
    if (
        live["shippingModeContract"] != candidate["shippingModeContract"]
        or live["devfleetVersion"] != candidate["devfleetVersion"]
        or live["installerVersion"] != candidate["installerVersion"]
    ):
        crlf_only = False
    if crlf_only and len(crlf_only_paths) != len(changed):
        crlf_only = False
    return {
        "lineEndingComparison": "CRLF_ONLY" if crlf_only else ("BYTE_EXACT" if not changed else "SUBSTANTIVE"),
        "materializedChangedPaths": changed,
        "crlfOnlyPaths": crlf_only_paths if crlf_only else [],
        "crlfOnlyMaterialization": crlf_only,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--candidate-commit")
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--installer-root", type=Path)
    parser.add_argument("--artifact", action="append", default=[], metavar="NAME=PATH")
    args = parser.parse_args()
    artifacts: dict[str, Path] = {}
    for value in args.artifact:
        name, separator, raw_path = value.partition("=")
        if not separator or not name or not raw_path:
            parser.error(f"artifact must be NAME=PATH: {value}")
        if name in artifacts:
            parser.error(f"duplicate artifact name: {name}")
        artifacts[name] = Path(raw_path).resolve()
    if artifacts:
        missing = sorted(RELEASE_ARTIFACT_NAMES - set(artifacts))
        unexpected = sorted(set(artifacts) - RELEASE_ARTIFACT_NAMES)
        if missing or unexpected:
            parser.error(f"artifact tuple must be exactly {sorted(RELEASE_ARTIFACT_NAMES)}; missing={missing}; unexpected={unexpected}")
        absent = sorted(name for name, path in artifacts.items() if not path.is_file())
        if absent:
            parser.error(f"artifact paths must be existing files: {absent}")
    if args.source_root and args.installer_root:
        fingerprint = _fingerprint(args.source_root.resolve(), args.installer_root.resolve(), artifacts)
        print(json.dumps({"shippingInputIdentity": _shipping_identity(fingerprint), "releaseFingerprintId": fingerprint["releaseFingerprintId"], "artifacts": fingerprint["artifacts"], "toolingFingerprint": fingerprint["toolingFingerprint"]}, ensure_ascii=False, separators=(",", ":")))
        return 0
    if not args.workspace or not args.candidate_commit:
        parser.error("--workspace and --candidate-commit are required unless --source-root and --installer-root are supplied")
    workspace = args.workspace.resolve()
    live = _fingerprint(workspace / "source", workspace / "installer-source", artifacts)
    candidate, staging = _materialize_candidate(workspace, args.candidate_commit, artifacts)
    try:
        comparison = _materialization_comparison(
            workspace / "source",
            workspace / "installer-source",
            staging / "source",
            staging / "installer-source",
            live,
            candidate,
        )
        candidate_fingerprint = {
            key: value for key, value in candidate.items() if key != "toolingFingerprint"
        }
        payload = {
            "liveShippingInputs": live["shippingInputs"],
            "candidateShippingInputs": candidate["shippingInputs"],
            "liveShippingModeContract": live["shippingModeContract"],
            "candidateShippingModeContract": candidate["shippingModeContract"],
            "liveVersion": live["devfleetVersion"],
            "candidateVersion": candidate["devfleetVersion"],
            "liveInstallerVersion": live["installerVersion"],
            "candidateInstallerVersion": candidate["installerVersion"],
            "liveShippingInputIdentity": _shipping_identity(live),
            "candidateShippingInputIdentity": _shipping_identity(candidate),
            "liveReleaseFingerprintId": live["releaseFingerprintId"],
            "candidateReleaseFingerprintId": candidate["releaseFingerprintId"],
            "artifacts": candidate["artifacts"],
            "candidateFingerprint": candidate_fingerprint,
            "liveToolingFingerprint": live["toolingFingerprint"],
            **comparison,
        }
    finally:
        import shutil
        shutil.rmtree(staging, ignore_errors=True)
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
