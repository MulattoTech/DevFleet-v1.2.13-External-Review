"""Strict post-cleanup release-bundle gate (release tooling only).

The candidate-bound source validator intentionally remains byte-identified.
This validator adds current proof, terminal-state, and post-cleanup authority
requirements without changing shipping inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
import stat
from pathlib import Path, PurePosixPath

HISTORICAL_CANDIDATE = "2739e0366d070285e44b4fc764ef9247d40b2f94"
HISTORICAL_PROVENANCE = "f334a6eff999287b170fdbd9b6a31c3ef24a6119"
HISTORICAL_SHIPPING_IDENTITY = "daa30ef9f521a47fedb4bacce91e3440c20e1a8f05543b4d5e823e5c3541e64e"
HISTORICAL_RAW_GIT_SHIPPING_IDENTITY = "cdabf0791016282b1dc116c2e0d407718e7d7249d93935f90cc681afd737e92e"
HISTORICAL_RELEASE_FINGERPRINT = "80c8b88c2f2ec828f5ab0f9713d63fa3f4cc4cbad7c382aa2f154f3196c3de84"
FAILED_ATTEMPT_SNAPSHOT = "audit/luna-high-failed-attempt-freeze-20260831T002237512571Z.json"
FAILED_ATTEMPT_BLOCKER = "REPLACEMENT_CANDIDATE_BINDING_MISMATCH"
FAILED_ATTEMPT_CURRENT_RECORDS = {
    "evidence/CURRENT-PROOF.json",
    "audit/attemptedReplacementCandidate.json",
    "audit/candidateBindingFailure.json",
}
FAILED_ATTEMPT_INVENTORY_FILES = {"EVIDENCE-MODES.json", "EVIDENCE-SHA256SUMS.txt"}
AUTHORIZED_SHIPPING_PATHS = {
    "installer-source/DevFleet.Setup/Services/InstallerLifecycle.cs",
    "installer-source/DevFleet.Setup/Services/InstallerServices.cs",
    "installer-source/DevFleet.Setup.Tests/Program.cs",
    "source/tools/validate_audit_coherence.py",
    "source/tools/validate_ai_audit_bundle.py",
    "source/tests/test_audit_coherence.py",
    "source/windows/DevFleet.Common.psm1",
}

REQUIRED = {
    "AUDIT-MANIFEST.json", "CURRENT-CANDIDATE.json", "finalization-state.json",
    "outputs/final-artifact-hashes.json", "evidence/CURRENT-STATUS.json",
    "outputs/dependency-advisory-gate.json", "outputs/independent-osv-reconciliation.json",
    "evidence/CURRENT-GATES.json", "evidence/CURRENT-PROOF.json",
    "evidence/FULLRELEASE-SUMMARY.json", "audit/CURRENT-HANDOFF.json",
    "evidence/l1-terminal-state.json", "evidence/l2-terminal-state.json",
    "evidence/current-fullrelease/run-state.json",
    "evidence/current-fullrelease/fullrelease-phase-records.json",
    "evidence/current-fullrelease/final-cleanup.json",
    "evidence/current-fullrelease/post-cleanup-finalization.json",
    "release-tooling/proof-entrypoints/run-exact-candidate-proof.ps1",
    "release-tooling/proof-entrypoints/Invoke-RealProductPhase.psm1",
    "release-tooling/proof-entrypoints/Invoke-WpfUiAutomation.ps1",
}

DIAGNOSTIC_REQUIRED = {
    "AUDIT-MANIFEST.json", "CURRENT-CANDIDATE.json", "finalization-state.json",
    "outputs/final-artifact-hashes.json", "evidence/CURRENT-STATUS.json",
    "outputs/dependency-advisory-gate.json", "outputs/independent-osv-reconciliation.json",
    "evidence/CURRENT-GATES.json", "evidence/CURRENT-PROOF.json",
    "evidence/FULLRELEASE-SUMMARY.json", "audit/CURRENT-HANDOFF.json",
    "release-tooling/proof-entrypoints/run-exact-candidate-proof.ps1",
}


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_extract(bundle: zipfile.ZipFile, destination: Path) -> set[str]:
    names: set[str] = set()
    for info in bundle.infolist():
        normalized = PurePosixPath(info.filename.replace("\\", "/"))
        if normalized.is_absolute() or ".." in normalized.parts:
            raise ValueError(f"unsafe archive member: {info.filename}")
        name = normalized.as_posix()
        if name in names:
            raise ValueError(f"duplicate archive member: {name}")
        file_type = (info.external_attr >> 16) & stat.S_IFMT(0o170000)
        if file_type in (stat.S_IFLNK, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO):
            raise ValueError(f"unsupported special archive member: {name}")
        names.add(name)
        target = (destination / Path(*normalized.parts)).resolve()
        if destination.resolve() not in target.parents and target != destination.resolve():
            raise ValueError(f"archive member escapes extraction root: {info.filename}")
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(info, "r") as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
    return names


def _proof_identity(value: object, *keys: str) -> str:
    if isinstance(value, dict):
        for key in keys:
            if value.get(key):
                return str(value[key])
        for child in value.values():
            found = _proof_identity(child, *keys)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _proof_identity(child, *keys)
            if found:
                return found
    return ""


def _canonical_shipping_rows(rows: list[object]) -> list[dict[str, object]]:
    """Normalize and order rows exactly like the candidate-bound validator."""
    normalized: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("candidate shipping row is not an object")
        mode = str(row.get("mode") or "")
        if mode not in {"0644", "0755"}:
            raise ValueError("candidate shipping row has a missing or invalid mode")
        root = str(row.get("root") or "").replace("\\", "/").strip("/")
        path = str(row.get("path") or "").replace("\\", "/").lstrip("/")
        if root not in {"source", "installer-source"} or not path or ".." in PurePosixPath(path).parts:
            raise ValueError("candidate shipping row has an invalid path")
        normalized.append({"root": root, "path": path, "bytes": int(row.get("bytes", -1)), "sha256": str(row.get("sha256") or "").lower(), "mode": mode})
    return sorted(normalized, key=lambda row: (0 if row["root"] == "source" else 1, tuple(part.casefold() for part in str(row["path"]).split("/"))))


def _candidate_shipping_identity(rows: list[object], version: object, installer: object, mode: object) -> str:
    payload = {"schemaVersion": 1, "devfleetVersion": version, "installerVersion": installer, "shippingModeContract": mode, "shippingInputs": _canonical_shipping_rows(rows)}
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _validate_candidate_bound(root: Path, mode: str) -> dict[str, object]:
    script = root / "source/tools/validate_audit_coherence.py"
    if not script.is_file():
        raise ValueError("candidate-bound validator is missing from the bundle")
    try:
        completed = subprocess.run([sys.executable, str(script), "--root", str(root), "--mode", mode], capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("candidate-bound validator could not be executed") from exc
    if completed.returncode != 0:
        raise ValueError(f"candidate-bound validator failed: {(completed.stderr or completed.stdout)[-2000:]}")
    try:
        result = json.loads(completed.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        raise ValueError("candidate-bound validator did not return JSON") from exc
    expected = "PASS_WITH_BLOCKER" if mode == "diagnostic" else "PASS"
    if result.get("status") != expected:
        raise ValueError(f"candidate-bound validator returned {result.get('status')!r}, expected {expected!r}")
    if mode == "diagnostic" and result.get("releaseEligible") is not False:
        raise ValueError("candidate-bound diagnostic result is release eligible")
    return result


def _validate_diagnostic(root: Path, names: set[str]) -> dict[str, object]:
    candidate_record = read_json(root / "CURRENT-CANDIDATE.json")
    manifest = read_json(root / "AUDIT-MANIFEST.json")
    if FAILED_ATTEMPT_SNAPSHOT in names:
        missing = sorted((FAILED_ATTEMPT_CURRENT_RECORDS | FAILED_ATTEMPT_INVENTORY_FILES) - names)
        if missing:
            raise ValueError(f"failed-attempt diagnostic blocker records are missing: {missing}")
        state = read_json(root / "finalization-state.json")
        if (state.get("status"), state.get("blocker_code"), state.get("candidate_is_current"), state.get("source_changed_since_candidate"), state.get("rebuild_required"), state.get("artifact_tuple_matches_candidate"), state.get("full_release_passed"), state.get("internal_promotion_allowed"), state.get("public_promotion_allowed")) != ("BLOCKED — USER ACTION REQUIRED", FAILED_ATTEMPT_BLOCKER, False, True, True, False, False, False, False):
            raise ValueError("failed replacement-attempt authority flags are not truthful")
        attempt = state.get("failed_replacement_attempt")
        if not isinstance(attempt, dict) or attempt.get("snapshotPath") != FAILED_ATTEMPT_SNAPSHOT or attempt.get("blockerCode") != FAILED_ATTEMPT_BLOCKER:
            raise ValueError("failed replacement-attempt authority binding is missing")
        terminal = attempt.get("terminalEvidence")
        if not isinstance(terminal, dict) or not isinstance(terminal.get("l1"), dict) or not isinstance(terminal.get("l2"), dict):
            raise ValueError("failed replacement-attempt terminal L1/L2 evidence is missing")
        proof = read_json(root / "evidence/CURRENT-PROOF.json")
        attempted = read_json(root / "audit/attemptedReplacementCandidate.json")
        failure = read_json(root / "audit/candidateBindingFailure.json")
        expected = {
            "attemptedCommit": "21752fc0e50978183322204c523b40947d073aa0",
            "commitShippingInputIdentity": "6e0bac4b4eebc83cdcd9eddda2008607ba15c8835e5c72a931792f5b83c653f4",
            "buildTimeShippingInputIdentity": "3a65fd54d70fe05565ac3a32f73100ca2c81a77a4008feb361f99f229f025f8a",
        }
        if proof.get("status") != "NOT_OBSERVED" or proof.get("outcome") != "NOT_OBSERVED" or proof.get("blockerCode") != FAILED_ATTEMPT_BLOCKER:
            raise ValueError("failed-attempt CURRENT-PROOF contradicts the blocker authority")
        if attempted.get("snapshotPath") != FAILED_ATTEMPT_SNAPSHOT or attempted.get("blockerCode") != FAILED_ATTEMPT_BLOCKER or any(attempted.get(key) != value for key, value in expected.items()):
            raise ValueError("attemptedReplacementCandidate contradicts the failed-attempt authority")
        if attempted.get("artifactTupleValid") is not True or attempted.get("artifactTupleMatchesCandidate") is not False or attempted.get("buildInvocationCount") != 1 or attempted.get("signingInvocationCount") != 1:
            raise ValueError("attemptedReplacementCandidate one-shot/artifact state is invalid")
        if failure.get("blockerCode") != FAILED_ATTEMPT_BLOCKER or any(failure.get(key) != value for key, value in expected.items()) or failure.get("artifactTupleValid") is not True or failure.get("artifactTupleMatchesCandidate") is not False or failure.get("currentProofOutcome") != "NOT_OBSERVED":
            raise ValueError("candidateBindingFailure contradicts the failed-attempt authority")
        manifest = read_json(root / "AUDIT-MANIFEST.json")
        inventory = manifest.get("evidenceInventory")
        if not isinstance(inventory, list) or {str(row.get("path")) for row in inventory if isinstance(row, dict)} != FAILED_ATTEMPT_CURRENT_RECORDS:
            raise ValueError("failed-attempt evidenceInventory is missing or incomplete")
        for row in inventory:
            relative = str(row.get("path"))
            path = root / Path(*relative.split("/"))
            if relative in FAILED_ATTEMPT_CURRENT_RECORDS and (not path.is_file() or int(row.get("bytes", -1)) != path.stat().st_size or str(row.get("sha256") or "").lower() != sha(path) or row.get("mode") != "0644"):
                raise ValueError(f"failed-attempt evidenceInventory hash/mode mismatch: {relative}")
        modes = read_json(root / "EVIDENCE-MODES.json")
        mode_by_path = {str(row.get("path")): row for row in modes if isinstance(row, dict)} if isinstance(modes, list) else {}
        if set(mode_by_path) != FAILED_ATTEMPT_CURRENT_RECORDS or any(row.get("posixMode") != 420 or row.get("mode") != "0644" for row in mode_by_path.values()):
            raise ValueError("failed-attempt evidence mode inventory is missing or contradictory")
        hash_rows = {}
        for line in (root / "EVIDENCE-SHA256SUMS.txt").read_text(encoding="utf-8-sig").splitlines():
            if line.strip():
                digest, relative = line.split("  ", 1)
                hash_rows[relative] = digest.lower()
        if set(hash_rows) != FAILED_ATTEMPT_CURRENT_RECORDS or any(hash_rows[path] != next(row["sha256"] for row in inventory if row.get("path") == path) for path in FAILED_ATTEMPT_CURRENT_RECORDS):
            raise ValueError("failed-attempt evidence hash inventory is missing or contradictory")
        return {"status": "PASS_WITH_BLOCKER", "bundleMode": "diagnostic", "diagnostic": True, "blockerCode": FAILED_ATTEMPT_BLOCKER, "releaseEligible": False, "candidateIsCurrent": False, "sourceChangedSinceCandidate": True, "rebuildRequired": True, "proofOutcome": "NOT_OBSERVED", "filesChecked": len(names)}
    candidate_commit = str(candidate_record.get("candidateCommit") or candidate_record.get("candidateGitCommit") or "").lower()
    if candidate_commit != HISTORICAL_CANDIDATE:
        state = read_json(root / "finalization-state.json")
        flags = (state.get("candidate_is_current"), state.get("source_changed_since_candidate"), state.get("rebuild_required"), state.get("full_release_passed"), state.get("internal_promotion_allowed"), state.get("public_promotion_allowed"))
        current_pending = (True, False, False, False, False, False)
        invalidated_pending = (False, True, True, False, False, False)
        if flags not in {current_pending, invalidated_pending}:
            raise ValueError("generic diagnostic candidate authority flags are not truthful")
        current = read_json(root / "evidence/CURRENT-PROOF.json")
        if str(current.get("outcome")) != "NOT_OBSERVED" or str(current.get("status")) not in {"BLOCKED", "NOT_OBSERVED"}:
            raise ValueError("generic diagnostic bundle must preserve a blocked NOT_OBSERVED current proof")
        summary = read_json(root / "evidence/FULLRELEASE-SUMMARY.json")
        if not summary.get("diagnosticOnly") and not summary.get("historicalEvidenceOnly"):
            raise ValueError("generic diagnostic summary must be marked diagnosticOnly or historicalEvidenceOnly")
        invalidated = flags == invalidated_pending
        if invalidated:
            authorization = state.get("authorized_correction")
            paths = authorization.get("shipping_paths") if isinstance(authorization, dict) else None
            working = candidate_record.get("workingTreeTuple")
            if not isinstance(paths, list) or not paths or not isinstance(working, dict):
                raise ValueError("invalidated diagnostic is missing its exact correction or working-tree tuple")
            for key in ("shippingInputIdentity", "canonicalizedShippingInputIdentity", "toolingFingerprintId"):
                value = str(working.get(key) or "")
                if len(value) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in value):
                    raise ValueError(f"invalidated diagnostic working-tree tuple is malformed: {key}")
        return {"status": "PASS_WITH_BLOCKER", "bundleMode": "diagnostic", "diagnostic": True, "blockerCode": "CANDIDATE_INVALIDATED_REBUILD_REQUIRED" if invalidated else "DIAGNOSTIC_PROOF_PENDING", "releaseEligible": False, "candidateIsCurrent": not invalidated, "sourceChangedSinceCandidate": invalidated, "rebuildRequired": invalidated, "proofOutcome": "NOT_OBSERVED", "filesChecked": len(names)}
    provenance_values = [value for value in (candidate_record.get("historicalProvenance"), manifest.get("historicalProvenance") if isinstance(manifest, dict) else None) if isinstance(value, dict)]
    provenance = provenance_values[0] if provenance_values else None
    if not isinstance(provenance, dict):
        raise ValueError("diagnostic bundle requires structured historicalProvenance")
    if any(value != provenance for value in provenance_values[1:]):
        raise ValueError("diagnostic historical provenance declarations disagree")
    if str(provenance.get("candidateCommit") or "").lower() != HISTORICAL_CANDIDATE:
        raise ValueError("diagnostic candidate is not the preserved 2739 object")
    if str(provenance.get("provenanceCommit") or provenance.get("sourceCommit") or "").lower() != HISTORICAL_PROVENANCE:
        raise ValueError("diagnostic provenance is not the preserved f334 object")
    if str(provenance.get("materialization") or "") != "git-archive" or provenance.get("coreAutocrlf") is not False:
        raise ValueError("diagnostic provenance is not deterministic core.autocrlf=false materialization")
    if str(provenance.get("lineEndingComparison") or "").upper() not in {"CRLF_ONLY", "CRLF-ONLY"}:
        raise ValueError("diagnostic provenance is not a proven CRLF-only comparison")
    if str(provenance.get("historicalShippingInputIdentity") or "").lower() != HISTORICAL_SHIPPING_IDENTITY:
        raise ValueError("diagnostic historical shipping identity is not the preserved value")
    if str(provenance.get("historicalReleaseFingerprintId") or "").lower() != HISTORICAL_RELEASE_FINGERPRINT:
        raise ValueError("diagnostic historical release fingerprint is not the preserved value")
    if str(candidate_record.get("devfleetVersion") or "") != "1.2.13" or str(candidate_record.get("installerVersion") or "") != "1.4.1":
        raise ValueError("diagnostic historical candidate version tuple is not the exact 1.2.13/1.4.1 tuple")
    mode = candidate_record.get("candidateShippingModeContract")
    if not isinstance(mode, dict) or set(mode) != {"schemaVersion", "defaultMode", "executableMode", "executableByContract"} or mode.get("schemaVersion") != 1 or mode.get("defaultMode") != "0644" or mode.get("executableMode") != "0755" or not isinstance(mode.get("executableByContract"), list) or mode["executableByContract"] != sorted(str(path) for path in mode["executableByContract"]):
        raise ValueError("diagnostic historical candidate mode contract is incomplete or non-canonical")
    labels = provenance.get("identityLabels") if isinstance(provenance.get("identityLabels"), dict) else {}
    if not str(labels.get("preservedCanonicalShippingInputIdentity") or "").lower().startswith("454edc") or not str(labels.get("rawGitShippingInputIdentity") or "").lower().startswith("cdab") or not str(labels.get("rawGitReleaseFingerprintId") or "").lower().startswith("eba40"):
        raise ValueError("diagnostic historical identity labels are incomplete")
    recorded_paths = {str(path).replace("\\", "/") for path in provenance.get("authorizedCurrentShippingPaths", []) if str(path)}
    if recorded_paths != AUTHORIZED_SHIPPING_PATHS:
        raise ValueError("diagnostic historical provenance does not bind exactly the seven authorized shipping paths")
    rows = candidate_record.get("candidateShippingInputs")
    if not isinstance(rows, list) or not rows:
        raise ValueError("diagnostic candidate shipping rows are mandatory offline evidence")
    recomputed_identity = _candidate_shipping_identity(rows, candidate_record.get("devfleetVersion"), candidate_record.get("installerVersion"), candidate_record.get("candidateShippingModeContract") or {})
    if str(provenance.get("recomputedCandidateShippingInputIdentity") or "").lower() != recomputed_identity or recomputed_identity != HISTORICAL_RAW_GIT_SHIPPING_IDENTITY:
        raise ValueError("diagnostic candidate shipping identity was not recomputed from embedded rows")
    release_file = root / "outputs/release-fingerprint.json"
    release = read_json(release_file) if release_file.is_file() else {}
    release_rows = release.get("shippingInputs")
    if not isinstance(release_rows, list) or not release_rows:
        raise ValueError("diagnostic release rows are missing")
    release_payload = {key: release.get(key) for key in ("schemaVersion", "devfleetVersion", "installerVersion", "shippingModeContract")}
    # release_fingerprint.py canonicalizes each root independently (source
    # first, installer-source second); preserve that authoritative order.
    release_payload["shippingInputs"] = release_rows
    release_payload["artifacts"] = release.get("artifacts", [])
    recomputed_release = hashlib.sha256(json.dumps(release_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    if recomputed_release != HISTORICAL_RELEASE_FINGERPRINT or str(release.get("releaseFingerprintId") or "").lower() != recomputed_release:
        raise ValueError("diagnostic release rows do not recompute to the preserved fingerprint")
    declared_recomputed_release = str(provenance.get("recomputedHistoricalReleaseFingerprintId") or "").lower()
    if not declared_recomputed_release or declared_recomputed_release != recomputed_release:
        raise ValueError("diagnostic historical release fingerprint closure is not recomputed")
    state = read_json(root / "finalization-state.json")
    release_artifacts = {str(row.get("name") or "").lower().replace("-", "").replace("_", ""): row for row in release.get("artifacts", []) if isinstance(row, dict)}
    state_candidate = state.get("candidate") if isinstance(state, dict) else None
    if not isinstance(state_candidate, dict):
        raise ValueError("diagnostic candidate artifact tuple is missing")
    candidate_artifacts = {str(value.get("name") or key).lower().replace("-", "").replace("_", ""): value for key, value in state_candidate.items() if isinstance(value, dict)}
    for key in ("exe", "tar", "portable", "installersource"):
        expected = next((row for name, row in release_artifacts.items() if key in name), None)
        observed = next((row for name, row in candidate_artifacts.items() if key in name), None)
        if expected is None or observed is None or str(expected.get("sha256") or "").lower() != str(observed.get("sha256") or "").lower() or int(expected.get("bytes", -1)) != int(observed.get("bytes", -2)):
            raise ValueError(f"diagnostic artifact closure mismatch: {key}")
    state_flags = (state.get("candidate_is_current"), state.get("source_changed_since_candidate"), state.get("rebuild_required"), state.get("full_release_passed"), state.get("internal_promotion_allowed"), state.get("public_promotion_allowed"))
    if state_flags != (False, True, True, False, False, False):
        raise ValueError("diagnostic authority flags are not truthful")
    if provenance.get("releaseEligible") is not False or provenance.get("promotionAllowed") is not False:
        raise ValueError("diagnostic historical provenance cannot be promoted")
    current = read_json(root / "evidence/CURRENT-PROOF.json")
    if str(current.get("outcome")) != "NOT_OBSERVED" or str(current.get("status")) not in {"BLOCKED", "NOT_OBSERVED"}:
        raise ValueError("diagnostic bundle must preserve a blocked NOT_OBSERVED current proof")
    handoff = read_json(root / "audit/CURRENT-HANDOFF.json")
    classification = str(current.get("blockerClassification") or handoff.get("blockerClassification") or "")
    if "RELEASE HARNESS" not in classification or ("EVIDENCE TOOLING" not in classification and "/ TOOLING" not in classification):
        raise ValueError("diagnostic bundle blocker classification is not release harness/evidence tooling")
    historical_start = str(current.get("proofStartHistoricalPath") or "")
    if not historical_start or not (root / historical_start).is_file():
        raise ValueError("diagnostic bundle is missing the exact historical proof-start archive path")
    start = read_json(root / historical_start)
    provenance = start.get("provenance") if isinstance(start.get("provenance"), dict) else {}
    historical_root = (root / historical_start).parent
    historical_sources = {
        "proofScriptSha256": historical_root / "run-exact-candidate-proof.ps1",
        "invokeRealProductPhaseSha256": historical_root / "Invoke-RealProductPhase.psm1",
        "invokeWpfUiAutomationSha256": historical_root / "Invoke-WpfUiAutomation.ps1",
    }
    for key, path in historical_sources.items():
        expected = str(provenance.get(key) or "").lower()
        if not expected or not path.is_file() or sha(path) != expected:
            raise ValueError(f"historical proof-start source cannot be verified: {key}")
    summary = read_json(root / "evidence/FULLRELEASE-SUMMARY.json")
    if not summary.get("diagnosticOnly") and not summary.get("historicalEvidenceOnly"):
        raise ValueError("blocked FullRelease summary must be marked diagnosticOnly or historicalEvidenceOnly")
    if bool(state.get("full_release_passed")) or bool(state.get("internal_promotion_allowed")) or bool(state.get("public_promotion_allowed")):
        raise ValueError("diagnostic bundle cannot claim promotion or FullRelease PASS")
    return {"status": "PASS_WITH_BLOCKER", "bundleMode": "diagnostic", "diagnostic": True, "releaseEligible": False, "candidateIsCurrent": False, "sourceChangedSinceCandidate": True, "rebuildRequired": True, "proofOutcome": "NOT_OBSERVED", "filesChecked": len(names)}


def validate(archive: Path, mode: str = "final") -> dict[str, object]:
    if mode == "final":
        # Backward-compatible Python API spelling; the command-line contract
        # intentionally exposes only diagnostic and release.
        mode = "release"
    if mode not in {"diagnostic", "release"}:
        raise ValueError("bundle mode must be diagnostic or release")
    if not archive.is_file():
        raise ValueError(f"bundle is missing: {archive}")
    temp = Path(tempfile.mkdtemp(prefix="DevFleet release bundle "))
    try:
        with zipfile.ZipFile(archive) as bundle:
            names = {PurePosixPath(info.filename.replace("\\", "/")).as_posix() for info in bundle.infolist()}
            required = DIAGNOSTIC_REQUIRED if mode == "diagnostic" else REQUIRED
            missing = sorted(required - names)
            if missing:
                raise ValueError(f"current release evidence missing: {missing}")
            names = _safe_extract(bundle, temp)
        root = temp
        candidate_result = _validate_candidate_bound(root, mode)
        sys.path.insert(0, str(root / "release-tooling"))
        from validate_audit_coherence import validate as validate_coherence  # type: ignore
        validate_coherence(root)
        authority_state = read_json(root / "finalization-state.json")
        expected_head = str(authority_state.get("repository_head") or authority_state.get("repositoryHead") or "")
        candidate = str(authority_state.get("candidate_git_commit") or authority_state.get("candidateGitCommit") or "")
        shipping = str(authority_state.get("shipping_input_identity") or authority_state.get("shippingInputIdentity") or "")
        release = str(authority_state.get("releaseFingerprintId") or "")
        tooling = str(authority_state.get("toolingFingerprintId") or "")
        if mode == "diagnostic":
            result = _validate_diagnostic(root, names)
            result["candidateBoundVerification"] = candidate_result
            return result
        current = read_json(root / "evidence/CURRENT-PROOF.json")
        if str(current.get("status")) != "PASS" or str(current.get("outcome")) not in {"PASS", "REAL E2E PASS", "COMPLETED"}:
            raise ValueError("CURRENT-PROOF is not a passing proof")
        progress = root / "evidence/current-proof"
        if not any((progress / name).is_file() for name in ("product-lifecycle-progress.jsonl", "product-lifecycle-progress-current.json")):
            raise ValueError("incremental lifecycle progress journal is missing")
        l1, l2 = read_json(root / "evidence/l1-terminal-state.json"), read_json(root / "evidence/l2-terminal-state.json")
        if not l1.get("name") or not (l1.get("id") or l1.get("vmId")) or not l1.get("state") or not (l1.get("timestamp") or l1.get("timestampUtc")) or not l1.get("ownershipScope"):
            raise ValueError("l1 terminal state is incomplete")
        if not l2.get("expectedName") or "present" not in l2 or not l2.get("timestamp") or not l2.get("verificationMethod"):
            raise ValueError("l2 terminal state is incomplete")
        post_cleanup = read_json(root / "evidence/current-fullrelease/post-cleanup-finalization.json")
        if str(post_cleanup.get("status")) != "PASS" or not post_cleanup.get("cleanupConsumed") or not post_cleanup.get("reconcileAfterCleanup"):
            raise ValueError("post-cleanup finalization did not consume CLEANUP evidence")
        live_checks = post_cleanup.get("liveChecks")
        if not isinstance(live_checks, dict) or any(live_checks.get(key) is not True for key in ("l1ExactOff", "l2ExactAbsent")):
            raise ValueError("post-cleanup finalization is missing passing liveChecks")
        cleanup_path = root / "evidence/current-fullrelease/final-cleanup.json"
        cleanup_expected = str(post_cleanup.get("cleanupEvidenceHash") or "").lower()
        if len(cleanup_expected) != 64 or sha(cleanup_path) != cleanup_expected:
            raise ValueError("post-cleanup finalization hash does not match final cleanup evidence")
        for key, relative in (("terminalL1Hash", "evidence/l1-terminal-state.json"), ("terminalL2Hash", "evidence/l2-terminal-state.json")):
            expected_hash = str(post_cleanup.get(key) or "").lower()
            if len(expected_hash) != 64 or sha(root / relative) != expected_hash:
                raise ValueError(f"post-cleanup finalization hash does not match {relative}")
        if str(post_cleanup.get("runId") or "") != str(read_json(root / "evidence/current-fullrelease/run-state.json").get("runId") or ""):
            raise ValueError("post-cleanup finalization RunId is not the current FullRelease RunId")
        records = read_json(root / "evidence/current-fullrelease/fullrelease-phase-records.json")
        if not isinstance(records, list) or not all(any(str(row.get("id")) == phase and str(row.get("status")) == "PASS" for row in records if isinstance(row, dict)) for phase in ("RECONCILE", "CLEANUP")):
            raise ValueError("current FullRelease evidence lacks passing RECONCILE and CLEANUP records")
        run_state = read_json(root / "evidence/current-fullrelease/run-state.json")
        full_summary = read_json(root / "evidence/FULLRELEASE-SUMMARY.json")
        run_id = str(run_state.get("runId") or "")
        if not run_id or str(full_summary.get("latestRunId") or "") != run_id or str(current.get("fullReleaseRunId") or run_id) != run_id:
            raise ValueError("current FullRelease identity is missing or mixed")
        full_tuple = run_state.get("candidateHashes") if isinstance(run_state.get("candidateHashes"), dict) else full_summary.get("candidateTuple")
        if not isinstance(full_tuple, dict):
            raise ValueError("current FullRelease candidate tuple is missing")
        for aliases, expected in ((("repositoryHead", "repository_head"), expected_head), ( ("candidateCommit", "candidateGitCommit", "candidate_git_commit"), candidate), (("shippingInputIdentity", "shipping_input_identity"), shipping), (("releaseFingerprintId", "releaseFingerprint"), release), (("toolingFingerprintId", "toolingFingerprint"), tooling)):
            observed = next((str(full_tuple.get(key)) for key in aliases if full_tuple.get(key)), "")
            if observed != expected:
                raise ValueError("current FullRelease candidate tuple disagrees with current authority")
        for row in records:
            if isinstance(row, dict) and row.get("runId") and str(row["runId"]) != run_id:
                raise ValueError("current FullRelease phase record has a mixed RunId")
        proof_root = root / "evidence/proof-runs"
        runs = [path for path in proof_root.iterdir() if path.is_dir()] if proof_root.is_dir() else []
        passing = []
        transactions = []
        lineages = []
        source_hash = sha(root / "release-tooling/proof-entrypoints/run-exact-candidate-proof.ps1")
        source_bindings = {
            "invokeRealProductPhaseSha256": root / "release-tooling/proof-entrypoints/Invoke-RealProductPhase.psm1",
            "invokeWpfUiAutomationSha256": root / "release-tooling/proof-entrypoints/Invoke-WpfUiAutomation.ps1",
        }
        for run in runs:
            start, final = run / "proof-start.json", run / "proof-final.json"
            if not start.is_file() or not final.is_file():
                continue
            start_value, final_value = read_json(start), read_json(final)
            run_id = str(start_value.get("runId") or "")
            if run_id != run.name or str(final_value.get("runId") or run_id) != run_id or str(final_value.get("status") or final_value.get("outcome") or "") not in {"PASS", "REAL E2E PASS", "COMPLETED"}:
                raise ValueError(f"proof run identity/outcome invalid: {run.name}")
            if str(start_value.get("proofScriptSha256") or "").lower() != source_hash:
                raise ValueError(f"proof source hash mismatch: {run.name}")
            provenance = start_value.get("provenance") if isinstance(start_value.get("provenance"), dict) else start_value
            for aliases, expected in (( ("repositoryHead", "repository_head"), expected_head), (("candidateCommit", "candidateGitCommit", "candidate_git_commit"), candidate), (("shippingInputIdentity", "shipping_input_identity"), shipping), (("releaseFingerprintId", "releaseFingerprint"), release), (("toolingFingerprintId", "toolingFingerprint"), tooling)):
                observed = next((str(provenance.get(key)) for key in aliases if provenance.get(key)), "")
                if observed != expected:
                    raise ValueError(f"proof tuple mismatch: {run.name}")
            for key, source_path in source_bindings.items():
                bound = str(provenance.get(key) or "").lower()
                if bound and bound != sha(source_path):
                    raise ValueError(f"proof entrypoint source hash mismatch for {key}: {run.name}")
            # Fair proofs must not reuse a transaction or checkpoint lineage.
            transaction = _proof_identity(start_value, "transactionId", "transaction_id")
            lineage = _proof_identity(start_value, "checkpointLineageId", "checkpoint_lineage_id")
            if transaction:
                transactions.append(transaction)
            if lineage:
                lineages.append(lineage)
            passing.append(run_id)
        if len(passing) != 2 or len(set(passing)) != 2:
            raise ValueError("release bundle does not contain two independent passing proof runs")
        if len(transactions) != 2 or len(transactions) != len(set(transactions)):
            raise ValueError("proof runs reuse a transaction identity")
        if len(lineages) != 2 or len(lineages) != len(set(lineages)):
            raise ValueError("proof runs reuse checkpoint lineage")
        return {"status": "PASS", "proofs": "2/2", "filesChecked": len(names), "proofSourceSha256": source_hash, "candidateBoundVerification": candidate_result}
    finally:
        shutil.rmtree(temp, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--mode", choices=("diagnostic", "release"), default="release")
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args.archive.resolve(), args.mode), sort_keys=True))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"RELEASE BUNDLE FAIL: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
