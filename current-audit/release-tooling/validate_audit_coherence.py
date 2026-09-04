"""Validate current release-tooling authorities without rewriting identity."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Iterable

CURRENT_AUTHORITIES = (
    "AUDIT-MANIFEST.json", "CURRENT-CANDIDATE.json", "finalization-state.json",
    "outputs/final-artifact-hashes.json", "evidence/CURRENT-STATUS.json",
    "evidence/CURRENT-GATES.json", "evidence/CURRENT-PROOF.json",
    "evidence/FULLRELEASE-SUMMARY.json", "audit/CURRENT-HANDOFF.json",
    "evidence/CURRENT-HANDOFF.json",
)
REQUIRED_SOURCE_PROOF = "release-tooling/proof-entrypoints/run-exact-candidate-proof.ps1"
FAILED_ATTEMPT_SNAPSHOT = "audit/luna-high-failed-attempt-freeze-20260831T002237512571Z.json"
FAILED_ATTEMPT_SNAPSHOT_SHA256 = "ac37997945b6fa5ae9326b083ee730494b2c0c2e60d4809e7b49fc9707c0caac"
FAILED_ATTEMPT_BLOCKER = "REPLACEMENT_CANDIDATE_BINDING_MISMATCH"


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def walk(value: Any, location: str) -> Iterable[tuple[str, dict[str, Any]]]:
    if isinstance(value, dict):
        yield location, value
        for key, child in value.items():
            yield from walk(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, f"{location}[{index}]")


def bool_value(value: Any, location: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{location} must be a JSON boolean")
    return value


def git_head(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def validate_failed_attempt_authority(root: Path, state: dict[str, Any]) -> dict[str, Any] | None:
    snapshot_path = root / Path(*FAILED_ATTEMPT_SNAPSHOT.split("/"))
    if not snapshot_path.is_file():
        return None
    if sha256(snapshot_path) != FAILED_ATTEMPT_SNAPSHOT_SHA256:
        raise ValueError("failed replacement-attempt snapshot is missing or hash-mismatched")
    snapshot = load(snapshot_path)
    if snapshot.get("immutableSnapshot") is not True or snapshot.get("freezeType") != "LUNA_HIGH_FAILED_ATTEMPT_EVIDENCE_FREEZE":
        raise ValueError("failed replacement-attempt snapshot is not immutable evidence")
    shipping = snapshot.get("shippingIdentity") if isinstance(snapshot.get("shippingIdentity"), dict) else {}
    archive = shipping.get("gitArchive") if isinstance(shipping.get("gitArchive"), dict) else {}
    live = shipping.get("buildTimeLive") if isinstance(shipping.get("buildTimeLive"), dict) else {}
    if archive.get("rowCount") != 730 or live.get("rowCount") != 730 or archive.get("identity") != "6e0bac4b4eebc83cdcd9eddda2008607ba15c8835e5c72a931792f5b83c653f4" or live.get("identity") != "3a65fd54d70fe05565ac3a32f73100ca2c81a77a4008feb361f99f229f025f8a":
        raise ValueError("failed replacement-attempt snapshot shipping identity is invalid")
    diff = shipping.get("normalizedRowDiff") if isinstance(shipping.get("normalizedRowDiff"), dict) else {}
    rows = diff.get("rows")
    if diff.get("rowCount") != 28 or diff.get("crlfOnlyRows") != 25 or diff.get("exactChangedRows") != 3 or not isinstance(rows, list) or len(rows) != 28:
        raise ValueError("failed replacement-attempt snapshot row partition is invalid")
    generated = {"source/CHECKSUMS.sha256", "installer-source/DevFleet.Setup/PayloadManifest.cs", "installer-source/INSTALLER-BUILD-MANIFEST.json"}
    if {f"{r.get('root')}/{r.get('path')}" for r in rows if isinstance(r, dict) and r.get("comparison") == "CONTENT_OR_GENERATED_CHANGE"} != generated or sum(1 for r in rows if isinstance(r, dict) and r.get("comparison") == "CRLF_ONLY_NORMALIZED_EQUAL") != 25:
        raise ValueError("failed replacement-attempt snapshot generated/CRLF partition is invalid")
    attempt = state.get("failed_replacement_attempt")
    if not isinstance(attempt, dict) or attempt.get("snapshotPath") != FAILED_ATTEMPT_SNAPSHOT or attempt.get("snapshotSha256") != FAILED_ATTEMPT_SNAPSHOT_SHA256 or attempt.get("blockerCode") != FAILED_ATTEMPT_BLOCKER or attempt.get("artifactTupleValid") is not True or attempt.get("artifactTupleMatchesCandidate") is not False:
        raise ValueError("current authority does not bind the failed replacement attempt")
    if (state.get("candidate_is_current"), state.get("source_changed_since_candidate"), state.get("rebuild_required"), state.get("artifact_tuple_matches_candidate"), state.get("full_release_passed"), state.get("internal_promotion_allowed"), state.get("public_promotion_allowed")) != (False, True, True, False, False, False, False):
        raise ValueError("failed replacement-attempt authority flags are not truthful")
    if state.get("status") != "BLOCKED — USER ACTION REQUIRED" or state.get("blocker_code") != FAILED_ATTEMPT_BLOCKER:
        raise ValueError("failed replacement-attempt status is not user-action blocked")
    return {"status": "PASS_WITH_BLOCKER", "blockerCode": FAILED_ATTEMPT_BLOCKER, "releaseEligible": False}


def validate(root: Path) -> dict[str, Any]:
    root = root.resolve()
    state_path = root / "finalization-state.json"
    manifest_path = root / "outputs" / "final-artifact-hashes.json"
    if not state_path.is_file() or not manifest_path.is_file():
        raise ValueError("Current finalization state and artifact manifest are required")
    state, manifest = load(state_path), load(manifest_path)
    if not isinstance(state, dict) or not isinstance(manifest, dict):
        raise ValueError("Current state and artifact manifest must be JSON objects")
    failed_result = validate_failed_attempt_authority(root, state)
    live_head = git_head(root)
    expected_head = live_head or str(state.get("repository_head") or manifest.get("repositoryHead") or "")
    candidate = str(state.get("candidate_git_commit") or state.get("candidateGitCommit") or manifest.get("candidateGitCommit") or "")
    release = str(state.get("releaseFingerprintId") or manifest.get("releaseFingerprintId") or "")
    tooling = str(state.get("toolingFingerprintId") or manifest.get("toolingFingerprintId") or "")
    candidate_shipping = str(state.get("shipping_input_identity") or state.get("shippingInputIdentity") or manifest.get("shippingInputIdentity") or "")
    # A bundle may expose both the immutable candidate shipping identity in
    # current state/artifact metadata and the freshly hashed live identity in
    # AUDIT-MANIFEST.  Accept exactly this two-value split; every other value
    # remains a fail-closed contradiction.
    audit_manifest_path = root / "AUDIT-MANIFEST.json"
    audit_manifest = load(audit_manifest_path) if audit_manifest_path.is_file() else {}
    live_shipping = str(audit_manifest.get("shippingInputIdentity") or candidate_shipping)
    working_shipping = str(state.get("working_tree_shipping_input_identity") or "")
    working_tooling = str(state.get("working_tree_tooling_fingerprint_id") or "")
    if len(expected_head) != 40 or len(candidate) != 40:
        raise ValueError("Current repository HEAD or signed candidate commit is missing/malformed")
    if any(len(value) != 64 for value in (release, tooling, candidate_shipping, live_shipping)):
        raise ValueError("Current release/tooling/shipping identity tuple is incomplete")
    if bool(working_shipping) != bool(working_tooling) or any(len(value) != 64 for value in (working_shipping, working_tooling) if value):
        raise ValueError("Working-tree shipping/tooling identity tuple is incomplete")

    def check_working_tree(value: dict[str, Any], location: str) -> None:
        if not working_shipping:
            return
        observed_shipping = str(value.get("shippingInputIdentity") or value.get("shipping_input_identity") or "")
        observed_tooling = str(value.get("toolingFingerprintId") or value.get("tooling_fingerprint_id") or "")
        canonicalized = str(value.get("canonicalizedShippingInputIdentity") or "")
        if observed_shipping and observed_shipping != working_shipping:
            raise ValueError(f"{location}.shippingInputIdentity disagrees with the working-tree tuple")
        if observed_tooling and observed_tooling != working_tooling:
            raise ValueError(f"{location}.toolingFingerprintId disagrees with the working-tree tuple")
        if canonicalized and canonicalized != live_shipping:
            raise ValueError(f"{location}.canonicalizedShippingInputIdentity disagrees with the bundled live identity")

    def check_identity(value: dict[str, Any], location: str, candidate_context: bool = False) -> None:
        for key in ("repositoryHead", "repository_head", "gitCommit", "git_commit"):
            if key in value:
                expected = candidate if candidate_context and key in ("gitCommit", "git_commit") else expected_head
                if str(value[key]) != expected:
                    raise ValueError(f"{location}.{key} disagrees with its bound Git identity")
        for key in ("candidateGitCommit", "candidate_git_commit", "candidateCommit", "candidate_commit"):
            if key in value and str(value[key]) != candidate:
                raise ValueError(f"{location}.{key} disagrees with signed candidate commit")
        for key in ("releaseFingerprintId", "toolingFingerprintId"):
            expected = release if key == "releaseFingerprintId" else tooling
            if key in value and str(value[key]) != expected:
                raise ValueError(f"{location}.{key} disagrees with current identity tuple")
        for key in ("shippingInputIdentity", "shipping_input_identity"):
            if key in value and str(value[key]) not in {candidate_shipping, live_shipping}:
                raise ValueError(f"{location}.{key} disagrees with current shipping identity")

    check_identity(state, "finalization-state.json")
    check_identity(manifest, "outputs/final-artifact-hashes.json")
    if str(state.get("repository_head") or "") != expected_head:
        raise ValueError("finalization-state.json.repository_head is required")
    if str(manifest.get("repositoryHead") or "") != expected_head:
        raise ValueError("final-artifact-hashes.json.repositoryHead is required")
    if str(manifest.get("candidateGitCommit") or "") != candidate:
        raise ValueError("final-artifact-hashes.json.candidateGitCommit is required")

    checked: list[Path] = [state_path, manifest_path]
    for relative in CURRENT_AUTHORITIES:
        path = root / relative
        if not path.is_file() or path.resolve() in {p.resolve() for p in checked}:
            continue
        value = load(path)
        # A preserved interrupted proof/old FullRelease record is useful
        # diagnostic evidence, but it is not a current authority.  The
        # builder marks these records diagnosticOnly so they cannot poison the
        # current identity tuple or masquerade as a release result.
        if isinstance(value, dict) and (value.get("historical") is True or value.get("diagnosticOnly") is True or value.get("historicalEvidenceOnly") is True):
            continue
        if not isinstance(value, dict):
            raise ValueError(f"{relative} must be a JSON object")
        check_identity(value, relative, candidate_context=(relative == "CURRENT-CANDIDATE.json"))
        for location, record in walk(value, relative):
            if ".workingTree" in location or ".working_tree" in location:
                check_working_tree(record, location)
                continue
            if not (record.get("historical") is True or record.get("diagnosticOnly") is True or record.get("historicalEvidenceOnly") is True):
                check_identity(record, location, candidate_context=(".candidate" in location or location.endswith("CURRENT-CANDIDATE.json")))
        checked.append(path)

    for relative in ("outputs/release-fingerprint.json", "outputs/tooling-fingerprint-current.json"):
        path = root / relative
        if path.is_file():
            check_identity(load(path), relative)
            checked.append(path)
    artifacts = {str(row.get("name", "")).lower().replace("_", "").replace("-", ""): row for row in manifest.get("artifacts", []) if isinstance(row, dict)}
    if not {"exe", "tar", "portable", "installersource"}.issubset(artifacts):
        raise ValueError("Current artifact manifest is missing a required artifact row")
    for name, row in artifacts.items():
        path, digest = root / str(row.get("path") or ""), str(row.get("sha256") or "").lower()
        # Universal audit bundles intentionally exclude compiled binaries; in
        # that mode the artifact manifest is an evidence-only tuple and the
        # live workspace validator remains responsible for byte verification.
        bundle_manifest_path = root / "AUDIT-MANIFEST.json"
        embedded = True
        if bundle_manifest_path.is_file():
            try:
                embedded = bool(load(bundle_manifest_path).get("compiledArtifactsEmbedded", True))
            except (OSError, ValueError, json.JSONDecodeError):
                embedded = True
        if not path.is_file() and not embedded and len(digest) == 64 and int(row.get("bytes") or 0) > 0:
            continue
        if not path.is_file() or len(digest) != 64 or sha256(path) != digest:
            raise ValueError(f"Current artifact bytes/hash mismatch: {name}")

    passed = bool_value(state.get("full_release_passed", False), "finalization-state.json.full_release_passed")
    if not passed:
        # The current blocked state must still describe the one latest proof;
        # it is intentionally not required to contain final-release evidence.
        current_proof_path = root / "evidence/CURRENT-PROOF.json"
        if current_proof_path.is_file():
            current_proof = load(current_proof_path)
            if not isinstance(current_proof, dict):
                raise ValueError("evidence/CURRENT-PROOF.json must be a JSON object")
            if str(current_proof.get("outcome") or "") != "NOT_OBSERVED":
                raise ValueError("Blocked current proof must remain NOT_OBSERVED until a natural terminal result exists")
            if str(current_proof.get("status") or "") not in {"BLOCKED", "NOT_OBSERVED"}:
                raise ValueError("Blocked current proof status is not fail-closed")
    if passed:
        missing = [relative for relative in CURRENT_AUTHORITIES if not (root / relative).is_file()]
        if missing or not (root / REQUIRED_SOURCE_PROOF).is_file():
            raise ValueError(f"Final authority/source evidence missing: {missing or [REQUIRED_SOURCE_PROOF]}")
        proof = load(root / "evidence/CURRENT-PROOF.json")
        if str(proof.get("outcome") or "") not in {"PASS", "REAL E2E PASS", "COMPLETED"}:
            raise ValueError("Final current proof is not PASS")
        for relative in ("evidence/l1-terminal-state.json", "evidence/l2-terminal-state.json"):
            if not (root / relative).is_file():
                raise ValueError(f"Final terminal evidence missing: {relative}")
    result = {"status": "PASS", "filesChecked": len({p.resolve() for p in checked}), "currentRepositoryHead": expected_head, "candidateCommit": candidate, "shippingInputIdentity": live_shipping, "candidateShippingInputIdentity": candidate_shipping, "currentReleaseFingerprintId": release, "currentToolingFingerprintId": tooling}
    if failed_result:
        result.update(failed_result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args.root), sort_keys=True))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"AUDIT COHERENCE FAIL: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
