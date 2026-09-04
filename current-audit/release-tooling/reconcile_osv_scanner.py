"""Reconcile the custom dependency gate with first-party OSV-Scanner output."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _scanner_packages(payload: dict[str, Any]) -> set[tuple[str, str]]:
    packages: set[tuple[str, str]] = set()
    for result in payload.get("results", []) or []:
        for item in result.get("packages", []) or []:
            package = item.get("package") or {}
            name, version = package.get("name"), package.get("version")
            if name and version:
                packages.add((str(name).lower().replace("_", "-"), str(version)))
    return packages


def _scanner_advisories(payload: dict[str, Any]) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for result in payload.get("results", []) or []:
        for item in result.get("packages", []) or []:
            package = item.get("package") or {}
            for vulnerability in item.get("vulnerabilities", []) or []:
                if isinstance(vulnerability, dict):
                    found.append({
                        "id": str(vulnerability.get("id") or vulnerability.get("aliases", ["unknown"])[0]),
                        "package": str(package.get("name") or ""),
                        "version": str(package.get("version") or ""),
                        "severity": str(vulnerability.get("severity") or "UNKNOWN"),
                    })
    return sorted(found, key=lambda item: (item["package"], item["version"], item["id"]))


def _scanner_version(scanner: Path) -> str:
    completed = subprocess.run([str(scanner), "--version"], capture_output=True, text=True, timeout=30, check=True)
    for line in completed.stdout.splitlines():
        if line.lower().startswith("osv-scanner version:"):
            return line.split(":", 1)[1].strip()
    raise RuntimeError("OSV-Scanner version output was not recognizable")


def reconcile(scanner: Path, lock: Path, custom_report: Path, output: Path) -> dict[str, Any]:
    custom = json.loads(custom_report.read_text(encoding="utf-8"))
    raw_path = output.with_name(output.name + ".scanner-raw.json")
    version = _scanner_version(scanner)
    command = [str(scanner), "scan", "source", "--lockfile", str(lock), "--format", "json", "--all-packages", "--output-file", str(raw_path), "--verbosity", "error"]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=180)
        try:
            scanner_payload = json.loads(raw_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"OSV-Scanner returned no valid JSON (exit {completed.returncode}): {completed.stderr[-1000:]}") from exc
    finally:
        raw_path.unlink(missing_ok=True)
    custom_packages = {
        (str(item["package"]).lower().replace("_", "-"), str(item["version"]))
        for item in custom.get("packages", [])
    }
    scanner_packages = _scanner_packages(scanner_payload)
    advisories = _scanner_advisories(scanner_payload)
    errors: list[str] = []
    if completed.returncode != 0:
        errors.append(f"OSV-Scanner exit code {completed.returncode}: {completed.stderr[-1000:]}")
    if custom.get("status") != "PASS":
        errors.append(f"custom dependency gate status is {custom.get('status')!r}")
    if custom_packages != scanner_packages:
        errors.append(f"package inventory mismatch: custom_only={sorted(custom_packages - scanner_packages)} scanner_only={sorted(scanner_packages - custom_packages)}")
    if advisories:
        errors.append("independent OSV-Scanner found advisories")
    report = {
        "schema_version": 1,
        "status": "PASS" if not errors else "BLOCKED",
        "scanner": "OSV-Scanner",
        "scanner_version": version,
        "invocation": command,
        "input_lock": str(lock),
        "input_lock_sha256": _sha(lock),
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "package_count": len(scanner_packages),
        "custom_package_count": len(custom_packages),
        "advisories": advisories,
        "custom_blocking_advisories": custom.get("blocking_advisories", []),
        "allowlisted_advisories": [item for item in custom.get("packages", []) if item.get("advisories")],
        "errors": errors,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scanner", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--custom-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = reconcile(args.scanner, args.lock, args.custom_report, args.output)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, RuntimeError) as exc:
        print(json.dumps({"status": "BLOCKED", "error": str(exc)}))
        return 2
    print(json.dumps({"status": report["status"], "packages": report["package_count"], "advisories": len(report["advisories"]), "errors": len(report["errors"])}))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
