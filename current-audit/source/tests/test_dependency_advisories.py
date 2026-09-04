from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools import check_dependency_advisories as gate


def _lock(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "requirements.txt"
    path.write_text(text, encoding="utf-8")
    return path


def test_exact_pin_and_canonical_name(tmp_path: Path):
    assert gate.lock_packages(_lock(tmp_path, "Fast_API[security]==1.2.3\n")) == [("fast-api", "1.2.3")]


def test_pip_compile_continuation_and_trailing_whitespace(tmp_path: Path):
    lock = _lock(
        tmp_path,
        """demo==1.2.3 \\
    --hash=sha256:abc \\
    # via test
next==2.0.0""" + "   \n" + """
""",
    )
    assert gate.lock_packages(lock) == [("demo", "1.2.3"), ("next", "2.0.0")]


def test_marker_continuation_and_extras(tmp_path: Path):
    lock = _lock(
        tmp_path,
        """demo[extra]==1.2.3 \\
    ; python_version < "3.13"
platform==2.0; sys_platform == "win32"
""",
    )
    assert gate.lock_requirements(lock) == [
        ("demo", "1.2.3", 'python_version < "3.13"'),
        ("platform", "2.0", 'sys_platform == "win32"'),
    ]


def test_inline_annotation_is_not_part_of_version(tmp_path: Path):
    assert gate.lock_packages(_lock(tmp_path, "demo==1.2.3 # generated annotation\n")) == [("demo", "1.2.3")]


def test_non_exact_pin_fails_closed(tmp_path: Path):
    with pytest.raises(ValueError, match="exact"):
        gate.lock_packages(_lock(tmp_path, "demo>=1.2\n"))


def test_cvss_v2_v3_and_v4_scores():
    assert gate._score({"severity": [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}]}) == pytest.approx(7.5)
    assert gate._score({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}) == pytest.approx(9.8)
    assert gate._score({"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]}) == pytest.approx(9.3)


def test_high_critical_and_unknown_severity_block():
    high = {"id": "HIGH", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}
    critical = {"id": "CRIT", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    malformed = {"id": "BAD", "severity": [{"type": "CVSS_V3", "score": "CVSS:9.9/not-a-vector"}]}
    assert gate._severity(high) == "HIGH"
    assert gate._severity(critical) == "CRITICAL"
    assert gate._severity(malformed) == "UNKNOWN"


def test_declared_affected_severity_is_considered():
    vulnerability = {"affected": [{"ecosystem_specific": {"severity": "HIGH"}}]}
    assert gate._severity(vulnerability) == "HIGH"


def test_run_sends_exact_query_and_allowlist(monkeypatch, tmp_path: Path):
    lock = _lock(
        tmp_path,
        """Demo_Package[extra]==1.2.3 ; sys_platform == "win32" \\
    --hash=sha256:abc
""",
    )
    allowlist = tmp_path / "allow.json"
    allowlist.write_text(json.dumps({"exceptions": [{"advisory_id": "OSV-1", "package": "demo-package", "affected_version": "1.2.3"}]}), encoding="utf-8")
    requests: list[tuple[str, str]] = []

    def fake_query(package: str, version: str) -> dict:
        requests.append((package, version))
        return {"vulns": [{"id": "OSV-1", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]}

    monkeypatch.setattr(gate, "query", fake_query)
    report = gate.run(lock, allowlist)
    assert requests == [("demo-package", "1.2.3")]
    assert report["packages"][0]["query"]["version"] == "1.2.3"
    assert report["status"] == "PASS"


def test_zero_advisories_pass_and_network_failure_blocks(monkeypatch, tmp_path: Path):
    lock = _lock(tmp_path, "demo==1.2.3\n")
    allowlist = tmp_path / "allow.json"
    allowlist.write_text('{"exceptions": []}', encoding="utf-8")
    monkeypatch.setattr(gate, "query", lambda *_: {"vulns": []})
    assert gate.run(lock, allowlist)["status"] == "PASS"
    monkeypatch.setattr(gate, "query", lambda *_: (_ for _ in ()).throw(OSError("offline")))
    report = gate.run(lock, allowlist)
    assert report["status"] == "BLOCKED"
    assert report["errors"]


def test_relevant_unknown_advisory_blocks(monkeypatch, tmp_path: Path):
    lock = _lock(tmp_path, "demo==1.2.3\n")
    allowlist = tmp_path / "allow.json"
    allowlist.write_text('{"exceptions": []}', encoding="utf-8")
    monkeypatch.setattr(gate, "query", lambda *_: {"vulns": [{"id": "OSV-BAD", "severity": [{"type": "CVSS_V3", "score": "not-supported"}]}]})
    report = gate.run(lock, allowlist)
    assert report["status"] == "BLOCKED"
    assert report["blocking_advisories"][0]["severity"] == "UNKNOWN"
