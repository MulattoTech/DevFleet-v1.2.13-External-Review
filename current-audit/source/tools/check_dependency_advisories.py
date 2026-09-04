"""Reproducible OSV freshness gate for the exact DevFleet dependency lock."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from packaging.markers import Marker
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

try:
    from cvss import CVSS2, CVSS3, CVSS4
    from cvss.exceptions import CVSSError
except ImportError as exc:  # pragma: no cover - exercised by release preflight
    raise RuntimeError(
        "release dependency gate requires the pinned 'cvss' release-tool dependency"
    ) from exc


OSV_QUERY_URL = "https://api.osv.dev/v1/query"
TIMEOUT_SECONDS = 8
HIGH_SCORE = 7.0
CRITICAL_SCORE = 9.0
KNOWN_SEVERITIES = {"NONE", "LOW", "MEDIUM", "MODERATE", "HIGH", "CRITICAL"}
BLOCKING_SEVERITIES = {"HIGH", "CRITICAL", "UNKNOWN"}


def _logical_requirement_lines(lock: Path) -> list[str]:
    """Return requirement expressions from a pip-compile style lock.

    Hashes and pip-compile annotations are deliberately ignored.  A continued
    marker expression is retained, while a continued requirement is finalized
    before the next top-level package line.
    """
    expressions: list[str] = []
    pending: str | None = None
    for physical in lock.read_text(encoding="utf-8").splitlines():
        line = physical.strip()
        if not line or line.startswith("#") or line.startswith("--hash="):
            continue
        # pip-compile may emit other option continuations; none are part of the
        # PEP 508 requirement we need to query.
        if line.startswith("--"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].rstrip()
        if not line:
            continue
        if pending is not None:
            if line.startswith(";") or line.startswith(","):
                pending = f"{pending} {line}"
                if pending.endswith("\\"):
                    pending = pending[:-1].rstrip()
                continue
            expressions.append(pending)
            pending = None
        if line.endswith("\\"):
            pending = line[:-1].rstrip()
        else:
            expressions.append(line)
    if pending is not None:
        expressions.append(pending)
    return expressions


def _requirement_expression(line: str) -> tuple[str, str, str | None]:
    try:
        requirement = Requirement(line)
    except InvalidRequirement as exc:
        raise ValueError(f"unsupported lock requirement: {line!r}") from exc
    specifiers = list(requirement.specifier)
    if len(specifiers) != 1 or specifiers[0].operator != "==" or specifiers[0].version.endswith(".*"):
        raise ValueError(f"lock requirement is not an exact == pin: {line!r}")
    version = specifiers[0].version.strip()
    if not version or any(ch.isspace() for ch in version) or ";" in version:
        raise ValueError(f"lock requirement has an invalid pinned version: {line!r}")
    marker = str(requirement.marker) if requirement.marker else None
    # Constructing Marker validates the complete expression, and makes the
    # target-environment policy explicit even though all exact lock pins are
    # queried conservatively below.
    if marker:
        Marker(marker)
    return canonicalize_name(requirement.name), version, marker


def lock_requirements(lock: Path) -> list[tuple[str, str, str | None]]:
    parsed = [_requirement_expression(line) for line in _logical_requirement_lines(lock)]
    if not parsed:
        raise ValueError(f"lock contains no exact pinned requirements: {lock}")
    # A compiled lock is the certified dependency set.  Query every exact pin,
    # including platform-marked pins, rather than silently dropping a supported
    # target.  Duplicate name/version rows are queried once.
    unique: list[tuple[str, str, str | None]] = []
    seen: set[tuple[str, str]] = set()
    for package, version, marker in parsed:
        key = (package, version)
        if key not in seen:
            seen.add(key)
            unique.append((package, version, marker))
    return unique


def lock_packages(lock: Path) -> list[tuple[str, str]]:
    return [(package, version) for package, version, _marker in lock_requirements(lock)]


def _score(vulnerability: dict) -> float | None:
    scores: list[float] = []
    for item in vulnerability.get("severity", []) or []:
        raw = str(item.get("score", ""))
        if not raw:
            continue
        try:
            kind = str(item.get("type") or "").upper()
            if raw.startswith("CVSS:2.0/") or kind == "CVSS_V2":
                scores.append(float(CVSS2(raw).scores()[0]))
            elif raw.startswith(("CVSS:3.0/", "CVSS:3.1/")) or kind == "CVSS_V3":
                scores.append(float(CVSS3(raw).scores()[0]))
            elif raw.startswith("CVSS:4.0/") or kind == "CVSS_V4":
                scores.append(float(CVSS4(raw).scores()[0]))
            else:
                # OSV has historically emitted numeric scores for some records;
                # accept only a complete numeric value in the valid CVSS range.
                numeric = float(raw)
                if 0.0 <= numeric <= 10.0:
                    scores.append(numeric)
        except (TypeError, ValueError, IndexError, CVSSError):
            continue
    return max(scores) if scores else None


def _declared_severities(vulnerability: dict) -> list[str]:
    values: list[str] = []
    specific = vulnerability.get("database_specific") or {}
    for value in (specific.get("severity"),):
        if value is not None:
            values.append(str(value).upper())
    for affected in vulnerability.get("affected", []) or []:
        if not isinstance(affected, dict):
            continue
        ecosystem_specific = affected.get("ecosystem_specific") or {}
        if ecosystem_specific.get("severity") is not None:
            values.append(str(ecosystem_specific["severity"]).upper())
    return values


def _severity(vulnerability: dict) -> str:
    declared_values = _declared_severities(vulnerability)
    invalid_declared = [value for value in declared_values if value not in KNOWN_SEVERITIES]
    declared = max(
        (value for value in declared_values if value in KNOWN_SEVERITIES),
        key=lambda value: {"NONE": 0, "LOW": 1, "MEDIUM": 2, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4}[value],
        default="",
    )
    score = _score(vulnerability)
    if score is not None:
        score_label = "CRITICAL" if score >= CRITICAL_SCORE else "HIGH" if score >= HIGH_SCORE else "MEDIUM" if score >= 4.0 else "LOW" if score > 0 else "NONE"
        rank = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4}
        if rank[score_label] > rank.get(declared, -1):
            declared = score_label
    invalid_vectors = any(
        str(item.get("score") or "").upper().startswith("CVSS:") and _score({"severity": [item]}) is None
        for item in vulnerability.get("severity", []) or []
        if isinstance(item, dict)
    )
    if (invalid_declared or invalid_vectors) and declared not in {"HIGH", "CRITICAL"}:
        return "UNKNOWN"
    if score is not None and score >= CRITICAL_SCORE:
        return "CRITICAL"
    if score is not None and score >= HIGH_SCORE:
        return "HIGH"
    return declared or "UNKNOWN"


def query(package: str, version: str) -> dict:
    body = json.dumps({"package": {"name": package, "ecosystem": "PyPI"}, "version": version}).encode()
    request = urllib.request.Request(OSV_QUERY_URL, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return json.load(response)


def run(lock: Path, allowlist: Path) -> dict:
    checked_at = datetime.now(timezone.utc).isoformat()
    lock_bytes = lock.read_bytes()
    allowlist_bytes = allowlist.read_bytes() if allowlist.is_file() else b'{"exceptions": []}'
    allowed = json.loads(allowlist.read_text(encoding="utf-8")) if allowlist.is_file() else {"exceptions": []}
    exceptions = {
        (str(item.get("advisory_id")), str(item.get("package")).lower().replace("_", "-"), str(item.get("affected_version"))): item
        for item in allowed.get("exceptions", [])
        if isinstance(item, dict)
    }
    results: list[dict] = []
    blocking: list[dict] = []
    errors: list[str] = []
    for package, version, marker in lock_requirements(lock):
        try:
            response = query(package, version)
            vulnerabilities = response.get("vulns", []) or []
            advisories = []
            for vulnerability in vulnerabilities:
                advisory_id = str(vulnerability.get("id") or "unknown")
                severity = _severity(vulnerability)
                item = {"id": advisory_id, "severity": severity, "summary": str(vulnerability.get("summary") or "")[:500]}
                advisories.append(item)
                if severity in BLOCKING_SEVERITIES and (advisory_id, package, version) not in exceptions:
                    blocking.append({"package": package, "version": version, **item})
            results.append({"package": package, "version": version, "marker": marker, "query": {"package": {"name": package, "ecosystem": "PyPI"}, "version": version}, "advisories": advisories, "status": "PASS" if not advisories else "ADVISORIES_REVIEWED"})
        except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            errors.append(f"{package}=={version}: {type(exc).__name__}: {exc}")
            results.append({"package": package, "version": version, "status": "ERROR", "error": str(exc)[:500]})
    status = "BLOCKED" if blocking or errors else "PASS"
    return {
        "schema_version": 2,
        "checker": "DevFleet dependency advisory gate",
        "checker_version": "2.0.0",
        "status": status,
        "source": OSV_QUERY_URL,
        "checked_at": checked_at,
        "lock": str(lock),
        "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "allowlist": str(allowlist),
        "allowlist_sha256": hashlib.sha256(allowlist_bytes).hexdigest(),
        "target_environment_policy": "query every exact pin in the compiled lock, including platform-marked pins; deduplicate only identical canonical package/version pairs",
        "packages": results,
        "blocking_advisories": blocking,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--allowlist", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.lock, args.allowlist)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "packages": len(report["packages"]), "blocking": len(report["blocking_advisories"]), "errors": len(report["errors"])}))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
