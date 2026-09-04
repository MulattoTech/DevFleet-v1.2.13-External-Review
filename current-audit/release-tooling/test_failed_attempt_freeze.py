"""Executable regression checks for the failed replacement-attempt contract."""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
import zipfile
from pathlib import Path

import pytest

import importlib.util

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("candidate_validator", ROOT / "source/tools/validate_audit_coherence.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)
AI_SPEC = importlib.util.spec_from_file_location("ai_bundle_validator", ROOT / "source/tools/validate_ai_audit_bundle.py")
AI_MODULE = importlib.util.module_from_spec(AI_SPEC)
assert AI_SPEC.loader is not None
AI_SPEC.loader.exec_module(AI_MODULE)
RELEASE_SPEC = importlib.util.spec_from_file_location("release_bundle_validator", ROOT / "tools/validate_release_bundle.py")
RELEASE_MODULE = importlib.util.module_from_spec(RELEASE_SPEC)
assert RELEASE_SPEC.loader is not None
RELEASE_SPEC.loader.exec_module(RELEASE_MODULE)


def _state() -> dict:
    snapshot = json.loads((ROOT / AI_MODULE.FAILED_ATTEMPT_SNAPSHOT).read_text(encoding="utf-8-sig"))
    attempted = json.loads((ROOT / "audit/attemptedReplacementCandidate.json").read_text(encoding="utf-8-sig"))
    artifact_rows = snapshot["candidate"]["newArtifactTuple"]["artifacts"]
    candidate = {str(row["name"]): copy.deepcopy(row) for row in artifact_rows}
    historical_artifacts = {
        name: {"bytes": expected[0], "sha256": expected[1]}
        for name, expected in MODULE.HISTORICAL_ARTIFACTS.items()
    }
    post_paths = []
    for relative in ("source/tools/validate_audit_coherence.py", "source/tools/validate_ai_audit_bundle.py"):
        post_paths.append({"path": relative, "sha256": hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()})
    return {
        "status": "BLOCKED — USER ACTION REQUIRED",
        "blocker_code": MODULE.FAILED_ATTEMPT_BLOCKER,
        "candidate_git_commit": MODULE.FAILED_ATTEMPT_COMMIT,
        "shipping_input_identity": MODULE.FAILED_ATTEMPT_BUILD_SHIPPING_IDENTITY,
        "candidate_shipping_input_identity": MODULE.FAILED_ATTEMPT_BUILD_SHIPPING_IDENTITY,
        "candidate_is_current": False,
        "source_changed_since_candidate": True,
        "rebuild_required": True,
        "artifact_tuple_matches_candidate": False,
        "full_release_passed": False,
        "internal_promotion_allowed": False,
        "public_promotion_allowed": False,
        "candidate": candidate,
        "historical_candidate": {
            "candidateCommit": MODULE.HISTORICAL_CANDIDATE,
            "shippingInputIdentity": MODULE.HISTORICAL_SHIPPING_IDENTITY,
            "releaseFingerprintId": MODULE.HISTORICAL_RELEASE_FINGERPRINT,
            "artifacts": historical_artifacts,
        },
        "failed_replacement_attempt": {
            "snapshotPath": AI_MODULE.FAILED_ATTEMPT_SNAPSHOT,
            "snapshotSha256": MODULE.FAILED_ATTEMPT_SNAPSHOT_SHA256,
            "attemptedCommit": MODULE.FAILED_ATTEMPT_COMMIT,
            "commitShippingInputIdentity": MODULE.FAILED_ATTEMPT_GIT_SHIPPING_IDENTITY,
            "buildTimeShippingInputIdentity": MODULE.FAILED_ATTEMPT_BUILD_SHIPPING_IDENTITY,
            "artifactTupleValid": True,
            "artifactTupleMatchesCandidate": False,
            "blockerCode": MODULE.FAILED_ATTEMPT_BLOCKER,
            "postFailureEvidenceTooling": {"classification": "POST_FAILURE_EVIDENCE_TOOLING", "paths": post_paths},
            "terminalEvidence": attempted["terminalEvidence"],
        },
    }


def test_failed_attempt_snapshot_is_recomputed_and_blocked():
    state = _state()
    result = MODULE._validate_failed_attempt_freeze(ROOT, state, {}, {})
    assert result["snapshotSha256"] == "ac37997945b6fa5ae9326b083ee730494b2c0c2e60d4809e7b49fc9707c0caac"
    assert result["shippingRows"] == 730
    assert result["changedRows"] == 28
    assert result["crlfOnlyRows"] == 25
    assert result["generatedShippingOutputRows"] == 3


@pytest.mark.parametrize("field,value", [
    ("candidate_is_current", True),
    ("source_changed_since_candidate", False),
    ("rebuild_required", False),
    ("artifact_tuple_matches_candidate", True),
    ("blocker_code", ""),
])
def test_failed_attempt_flags_and_blocker_fail_closed(field: str, value: object):
    state = _state()
    state[field] = value
    with pytest.raises(ValueError):
        MODULE._validate_failed_attempt_freeze(ROOT, state, {}, {})


def test_historical_tuple_remains_separate_from_attempt():
    state = _state()
    historical = state["historical_candidate"]
    assert historical["candidateCommit"] == "2739e0366d070285e44b4fc764ef9247d40b2f94"
    assert state["failed_replacement_attempt"]["attemptedCommit"] == "21752fc0e50978183322204c523b40947d073aa0"
    assert historical["releaseFingerprintId"] == "80c8b88c2f2ec828f5ab0f9713d63fa3f4cc4cbad7c382aa2f154f3196c3de84"


def test_snapshot_tamper_is_rejected(tmp_path: Path):
    source = ROOT / "audit/luna-high-failed-attempt-freeze-20260831T002237512571Z.json"
    tampered = tmp_path / source.name
    tampered.write_bytes(source.read_bytes() + b"\n")
    state = _state()
    original = MODULE._sha256
    MODULE._sha256 = lambda path: original(tampered) if path == ROOT / "audit/luna-high-failed-attempt-freeze-20260831T002237512571Z.json" else original(path)
    try:
        with pytest.raises(ValueError, match="hash-mismatched"):
            MODULE._validate_failed_attempt_freeze(ROOT, state, {}, {})
    finally:
        MODULE._sha256 = original


def _blocker_record_fixture(tmp_path: Path) -> tuple[set[str], dict]:
    records = list(AI_MODULE.FAILED_ATTEMPT_CURRENT_RECORDS)
    for relative in records:
        target = tmp_path / Path(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        if relative == "evidence/CURRENT-PROOF.json":
            target.write_text(json.dumps({"status": "NOT_OBSERVED", "outcome": "NOT_OBSERVED", "blockerCode": MODULE.FAILED_ATTEMPT_BLOCKER}), encoding="utf-8")
        else:
            shutil.copy2(ROOT / relative, target)
    inventory = []
    for relative in records:
        target = tmp_path / Path(*relative.split("/"))
        inventory.append({"path": relative, "bytes": target.stat().st_size, "sha256": hashlib.sha256(target.read_bytes()).hexdigest(), "mode": "0644"})
    (tmp_path / "EVIDENCE-MODES.json").write_text(json.dumps([{"path": relative, "posixMode": 420, "mode": "0644", "executable": False} for relative in records]), encoding="utf-8")
    (tmp_path / "EVIDENCE-SHA256SUMS.txt").write_text("\n".join(f"{row['sha256']}  {row['path']}" for row in inventory), encoding="utf-8")
    return set(records) | {AI_MODULE.FAILED_ATTEMPT_SNAPSHOT, "EVIDENCE-MODES.json", "EVIDENCE-SHA256SUMS.txt"}, {"evidenceInventory": inventory}


def test_failed_attempt_blocker_records_are_present_and_cross_bound(tmp_path: Path):
    names, manifest = _blocker_record_fixture(tmp_path)
    AI_MODULE._validate_failed_attempt_records(tmp_path, names, manifest)


@pytest.mark.parametrize("missing", AI_MODULE.FAILED_ATTEMPT_CURRENT_RECORDS)
def test_failed_attempt_blocker_record_missing_fails_closed(tmp_path: Path, missing: str):
    names, manifest = _blocker_record_fixture(tmp_path)
    (tmp_path / Path(*missing.split("/"))).unlink()
    names.remove(missing)
    with pytest.raises(ValueError, match="missing"):
        AI_MODULE._validate_failed_attempt_records(tmp_path, names, manifest)


def test_failed_attempt_blocker_record_tamper_fails_closed(tmp_path: Path):
    names, manifest = _blocker_record_fixture(tmp_path)
    target = tmp_path / Path(*"audit/candidateBindingFailure.json".split("/"))
    target.write_text(target.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="evidenceInventory hash/mode mismatch"):
        AI_MODULE._validate_failed_attempt_records(tmp_path, names, manifest)


def test_release_bundle_failed_attempt_records_are_cross_bound(tmp_path: Path):
    names, manifest = _blocker_record_fixture(tmp_path)
    state = _state()
    (tmp_path / "finalization-state.json").write_text(json.dumps(state), encoding="utf-8")
    (tmp_path / "CURRENT-CANDIDATE.json").write_text("{}", encoding="utf-8")
    (tmp_path / "AUDIT-MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
    result = RELEASE_MODULE._validate_diagnostic(tmp_path, names | {"finalization-state.json", "CURRENT-CANDIDATE.json", "AUDIT-MANIFEST.json"})
    assert result["status"] == "PASS_WITH_BLOCKER"


@pytest.mark.parametrize("missing", ["audit/attemptedReplacementCandidate.json", "audit/candidateBindingFailure.json"])
def test_release_bundle_missing_failed_attempt_record_fails_closed(tmp_path: Path, missing: str):
    names, manifest = _blocker_record_fixture(tmp_path)
    state = _state()
    (tmp_path / "finalization-state.json").write_text(json.dumps(state), encoding="utf-8")
    (tmp_path / "CURRENT-CANDIDATE.json").write_text("{}", encoding="utf-8")
    (tmp_path / "AUDIT-MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
    names |= {"finalization-state.json", "CURRENT-CANDIDATE.json", "AUDIT-MANIFEST.json"}
    names.remove(missing)
    with pytest.raises(ValueError, match="missing"):
        RELEASE_MODULE._validate_diagnostic(tmp_path, names)


def test_ai_diagnostic_full_path_loads_manifest_before_blocker_records(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    snapshot = "audit/luna-high-failed-attempt-freeze-20260831T002237512571Z.json"
    records = list(AI_MODULE.FAILED_ATTEMPT_CURRENT_RECORDS)
    inventory = []
    injected: dict[str, bytes] = {snapshot: (ROOT / snapshot).read_bytes()}
    for relative in records:
        data = (ROOT / relative).read_bytes()
        injected[relative] = data
        inventory.append({"path": relative, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "mode": "0644"})
    injected["EVIDENCE-MODES.json"] = json.dumps([{"path": row["path"], "posixMode": 420, "mode": "0644", "executable": False} for row in inventory]).encode()
    injected["EVIDENCE-SHA256SUMS.txt"] = "\n".join(f"{row['sha256']}  {row['path']}" for row in inventory).encode()
    observed: dict[str, object] = {}
    original_extract = AI_MODULE._extract
    def fake_extract(archive: Path, extracted: Path) -> set[str]:
        names = set(original_extract(archive, extracted))
        for relative, data in injected.items():
            target = extracted / Path(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            names.add(relative)
        manifest_path = extracted / "AUDIT-MANIFEST.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        manifest["evidenceInventory"] = inventory
        manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
        candidate_path = extracted / "CURRENT-CANDIDATE.json"
        candidate = json.loads(candidate_path.read_text(encoding="utf-8-sig"))
        candidate["artifactTupleMatchesCandidate"] = False
        candidate_path.write_text(json.dumps(candidate) + "\n", encoding="utf-8")
        return names
    monkeypatch.setattr(AI_MODULE, "_extract", fake_extract)
    def fake_records(extracted: Path, names: set[str], loaded_manifest: dict) -> None:
        observed["manifest"] = loaded_manifest
    monkeypatch.setattr(AI_MODULE, "_validate_failed_attempt_records", fake_records)
    monkeypatch.setattr(AI_MODULE, "_run_candidate_validator", lambda command, cwd, mode: {"status": "PASS_WITH_BLOCKER", "blockerCode": "REPLACEMENT_CANDIDATE_BINDING_MISMATCH", "releaseEligible": False})
    result = AI_MODULE.validate(ROOT / "outputs/DevFleet-v1.2.13-AI-Audit-LATEST.zip", mode="diagnostic")
    assert result["status"] == "PASS_WITH_BLOCKER"
    assert isinstance(observed.get("manifest"), dict)


@pytest.mark.parametrize("manifest_bytes", [b"", b"not-json"])
def test_ai_diagnostic_malformed_or_missing_manifest_fails_closed(tmp_path: Path, manifest_bytes: bytes):
    entries: dict[str, bytes] = {}
    with zipfile.ZipFile(ROOT / "outputs/DevFleet-v1.2.13-AI-Audit-LATEST.zip") as archive:
        entries = {name: archive.read(name) for name in archive.namelist() if not name.endswith("/")}
    if manifest_bytes:
        entries["AUDIT-MANIFEST.json"] = manifest_bytes
    else:
        entries.pop("AUDIT-MANIFEST.json", None)
    archive_path = tmp_path / "malformed.zip"
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    with pytest.raises(Exception):
        AI_MODULE.validate(archive_path, mode="diagnostic")
