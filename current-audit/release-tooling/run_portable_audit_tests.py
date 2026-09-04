"""Run the bounded, self-contained test corpus from a clean audit extraction."""
from __future__ import annotations

import argparse
import fnmatch
import importlib.util
import shutil
import json
import subprocess
import sys
from pathlib import Path

from audit_bundle_paths import resolve_bundle_layout


def _classify(path: str, manifest: dict) -> str:
    for category, patterns in manifest.get("categories", {}).items():
        if any(fnmatch.fnmatch(path, pattern) for pattern in patterns):
            return category
    return "UNCLASSIFIED"


def run(root: Path) -> dict:
    root = root.resolve()
    layout = resolve_bundle_layout(root)
    if layout.bundle_root != root:
        raise RuntimeError(f"runner root is not the extracted bundle root: {root}")
    manifest_path = layout.release_tooling_root / "audit-test-manifest.json"
    if not manifest_path.is_file():
        raise RuntimeError(f"audit test manifest is missing: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    if manifest.get("entrypoint") != "release-tooling/run_portable_audit_tests.py":
        raise RuntimeError("audit test manifest entrypoint is not canonical")
    # The portable tests intentionally retain their repository-relative
    # authority imports (ROOT / tools/...).  A clean audit extraction maps
    # release tooling under release-tooling/, so stage only these two
    # non-shipping authority helpers into the temporary extraction root.
    compatibility_root = root / "tools"
    compatibility_root.mkdir(parents=True, exist_ok=True)
    for helper in ("compute_shipping_input_identity.py", "validate_release_bundle.py", "Build-AIAuditBundle.ps1"):
        source_helper = layout.release_tooling_root / helper
        if not source_helper.is_file():
            raise RuntimeError(f"portable authority helper is missing from extraction: {helper}")
        shutil.copy2(source_helper, compatibility_root / helper)
    classifications: dict[str, dict] = {}
    for path in sorted((root / "source/tests").glob("test_*.py")):
        relative = path.relative_to(root).as_posix()
        category = _classify(relative, manifest)
        classifications[relative] = {"category": category, "status": "NOT_RUN", "reason": "not selected by bounded portable corpus"}
    for path in manifest.get("portableTests", []):
        if path not in classifications:
            raise RuntimeError(f"manifest portable test is missing from extraction: {path}")
        classifications[path] = {"category": "portable", "status": "PENDING", "reason": "selected portable test"}
    unclassified = [path for path, record in classifications.items() if record["category"] == "UNCLASSIFIED"]
    if unclassified:
        raise RuntimeError(f"unclassified tests: {unclassified}")
    for path, record in classifications.items():
        if record["status"] == "NOT_RUN":
            record["status"] = "SKIPPED"
            record["reason"] = f"classified {record['category']}; required artifact/platform is not part of portable mode"
    pytest_available = importlib.util.find_spec("pytest") is not None
    if not pytest_available:
        raise RuntimeError("portable test runner requires pytest in the invoking interpreter; no original .venv-test path is used")
    selected = list(manifest["portableTests"])
    completed = subprocess.run([sys.executable, "-m", "pytest", "-q", *selected], cwd=root, capture_output=True, text=True, timeout=300)
    if completed.returncode:
        raise RuntimeError(f"portable pytest collection/test failure (exit {completed.returncode}): {(completed.stdout + completed.stderr)[-4000:]}")
    for path in selected:
        classifications[path]["status"] = "PASS"
        classifications[path]["reason"] = "portable test completed with the invoking interpreter"
    return {
        "schemaVersion": 1,
        "status": "PASS",
        "root": str(root),
        "python": sys.executable,
        "workingDirectory": str(root),
        "portableTests": selected,
        "tests": classifications,
        "unexpectedCollectionFailures": [],
        "explicitSkips": [record for record in classifications.values() if record["status"] == "SKIPPED"],
        "nestedReleaseArchiveAssumption": False,
        "canonicalReleaseToolingResolved": True,
        "originalRepositoryFallback": False,
        "pytestOutput": completed.stdout,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = run(args.root)
    except Exception as exc:  # noqa: BLE001 - structured CLI failure is required
        result = {"schemaVersion": 1, "status": "FAIL", "error": str(exc), "unexpectedCollectionFailures": [str(exc)]}
        print(json.dumps(result, indent=2))
        return 2
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
