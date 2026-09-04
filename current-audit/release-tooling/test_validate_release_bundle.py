"""Behavioral negative tests for the release-tooling bundle gate."""
from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import zipfile
from pathlib import Path

from validate_release_bundle import validate

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "outputs" / "DevFleet-v1.2.13-AI-Audit-LATEST.zip"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(entries: dict[str, bytes], name: str) -> dict:
    return json.loads(entries[name].decode("utf-8-sig"))


def put(entries: dict[str, bytes], name: str, value: object) -> None:
    entries[name] = (json.dumps(value, indent=2) + "\n").encode()


def canonical_shipping_rows(rows: list[dict]) -> list[dict]:
    return sorted(rows, key=lambda row: (0 if row["root"] == "source" else 1, tuple(part.casefold() for part in row["path"].split("/"))))


def shipping_identity(rows: list[dict], mode: dict, version: str, installer: str) -> str:
    payload = {"schemaVersion": 1, "devfleetVersion": version, "installerVersion": installer, "shippingModeContract": mode, "shippingInputs": canonical_shipping_rows(rows)}
    return digest(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())


def release_identity(release: dict) -> str:
    payload = {key: release.get(key) for key in ("schemaVersion", "devfleetVersion", "installerVersion", "shippingModeContract")}
    payload["shippingInputs"] = release.get("shippingInputs")
    payload["artifacts"] = release.get("artifacts", [])
    return digest(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())


def final_entries() -> dict[str, bytes]:
    with zipfile.ZipFile(ARCHIVE) as archive:
        entries = {name: archive.read(name) for name in archive.namelist() if not name.endswith("/")}
    state = read_json(entries, "finalization-state.json")
    candidate = str(state["candidate_git_commit"])
    head = str(state["repository_head"])
    manifest = read_json(entries, "AUDIT-MANIFEST.json")
    shipping_rows = []
    for row in manifest["sourceInventory"]:
        path = str(row["path"]).replace("\\", "/")
        if path.startswith("source/"):
            root_name, relative = "source", path[len("source/"):]
        elif path.startswith("installer-source/"):
            root_name, relative = "installer-source", path[len("installer-source/"):]
        else:
            continue
        shipping_rows.append({"root": root_name, "path": relative, "bytes": int(row["bytes"]), "sha256": str(row["sha256"]).lower(), "mode": str(row["mode"])})
    mode = manifest["shippingModeContract"]
    shipping_rows = canonical_shipping_rows(shipping_rows)
    shipping = shipping_identity(shipping_rows, mode, str(manifest["devfleetVersion"]), str(manifest["installerVersion"]))
    release_record = read_json(entries, "outputs/release-fingerprint.json")
    release_record.update({"devfleetVersion": manifest["devfleetVersion"], "installerVersion": manifest["installerVersion"], "shippingModeContract": mode, "shippingInputs": shipping_rows})
    release = release_identity(release_record)
    release_record["releaseFingerprintId"] = release
    put(entries, "outputs/release-fingerprint.json", release_record)
    tooling_record = read_json(entries, "outputs/tooling-fingerprint-current.json")
    tooling_record.update({"releaseFingerprintId": release})
    put(entries, "outputs/tooling-fingerprint-current.json", tooling_record)
    tooling = str(state["toolingFingerprintId"])
    run_id = "FullRelease-synthetic-current"
    state["repository_head"] = head
    state["candidate_git_commit"] = head
    state["candidate_shipping_input_identity"] = shipping
    state["shipping_input_identity"] = shipping
    state["releaseFingerprintId"] = release
    state.update({"source_changed_since_candidate": False, "rebuild_required": False, "source_identity_matches_candidate": True, "artifact_tuple_matches_candidate": True, "candidate_build_current": True, "candidate_is_current": True, "validation_evidence_current": True, "full_release_passed": True, "internal_promotion_allowed": True, "public_promotion_allowed": False, "full_release_run_id": run_id, "full_release_current": True})
    state.update({"status": "PASS", "release_status": "PASS", "blocker": None})
    candidate_record = read_json(entries, "CURRENT-CANDIDATE.json")
    candidate_record.pop("historicalProvenance", None)
    candidate_record.update({"repositoryHead": head, "gitCommit": head, "candidateCommit": head, "candidateShippingInputs": shipping_rows, "candidateShippingModeContract": mode, "shippingModeContract": mode, "shippingInputIdentity": shipping, "candidateShippingInputIdentity": shipping, "releaseFingerprintId": release, "candidateIsCurrent": True, "sourceChangedSinceCandidate": False, "rebuildRequired": False})
    manifest.pop("historicalProvenance", None)
    manifest.update({"repositoryHead": head, "gitCommit": head, "candidateGitCommit": head, "shippingInputIdentity": shipping, "candidateShippingInputIdentity": shipping, "releaseFingerprintId": release, "candidate": candidate_record, "candidateIsCurrent": True, "sourceChangedSinceCandidate": False, "rebuildRequired": False})
    put(entries, "CURRENT-CANDIDATE.json", candidate_record)
    put(entries, "AUDIT-MANIFEST.json", manifest)
    artifact_manifest = read_json(entries, "outputs/final-artifact-hashes.json")
    artifact_manifest.update({"repositoryHead": head, "gitCommit": head, "candidateGitCommit": head, "shippingInputIdentity": shipping, "releaseFingerprintId": release, "sourceChangedSinceCandidate": False, "rebuildRequired": False, "sourceIdentityMatchesCandidate": True, "candidateBuildCurrent": True, "candidateIsCurrent": True, "validationEvidenceCurrent": True, "fullReleasePassed": True, "internalPromotionAllowed": True, "publicPromotionAllowed": False})
    put(entries, "outputs/final-artifact-hashes.json", artifact_manifest)
    tuple_value = {"repositoryHead": head, "candidateCommit": candidate, "shippingInputIdentity": shipping, "releaseFingerprintId": release, "toolingFingerprintId": tooling}
    tuple_value["candidateCommit"] = head

    # The archive contains several current-authority documents whose nested
    # ``candidate`` records predate this synthetic current-candidate fixture.
    # Rebind those records together, so the release-tooling validator sees one
    # coherent tuple while preserving any separately marked historical data.
    def rebind_current_authority(value: object) -> None:
        if isinstance(value, dict):
            for key in ("repositoryHead", "repository_head", "gitCommit", "git_commit", "candidateGitCommit", "candidate_git_commit", "candidateCommit", "candidate_commit"):
                if key in value:
                    value[key] = head
            for key in ("shippingInputIdentity", "shipping_input_identity", "candidateShippingInputIdentity", "candidate_shipping_input_identity"):
                if key in value:
                    value[key] = shipping
            for key in ("releaseFingerprintId",):
                if key in value:
                    value[key] = release
            for key in ("toolingFingerprintId",):
                if key in value:
                    value[key] = tooling
            for key in ("candidateIsCurrent", "candidate_is_current", "sourceIdentityMatchesCandidate", "source_identity_matches_candidate", "candidateBuildCurrent", "candidate_build_current", "validationEvidenceCurrent", "validation_evidence_current", "fullReleasePassed", "full_release_passed", "internalPromotionAllowed", "internal_promotion_allowed"):
                if key in value:
                    value[key] = True
            for key in ("sourceChangedSinceCandidate", "source_changed_since_candidate", "rebuildRequired", "rebuild_required", "publicPromotionAllowed", "public_promotion_allowed"):
                if key in value:
                    value[key] = False
            for child in value.values():
                rebind_current_authority(child)
        elif isinstance(value, list):
            for child in value:
                rebind_current_authority(child)

    for authority_name in ("evidence/CURRENT-STATUS.json", "evidence/CURRENT-GATES.json", "evidence/CURRENT-PROOF.json", "evidence/FULLRELEASE-SUMMARY.json", "evidence/CURRENT-HANDOFF.json"):
        authority = read_json(entries, authority_name)
        rebind_current_authority(authority)
        put(entries, authority_name, authority)

    # A release-good fixture must never smuggle the historical candidate
    # provenance that is tested separately in diagnostic mode.
    assert "historicalProvenance" not in candidate_record
    assert "historicalProvenance" not in manifest
    # Current authority evidence must bind the same synthetic current tuple;
    # preserved historical records, if any, remain untouched in their own
    # historical namespaces.
    handoff = read_json(entries, "audit/CURRENT-HANDOFF.json")
    handoff.update({"repositoryHead": head, "candidateCommit": head, "shippingInputIdentity": shipping, "candidateShippingInputIdentity": shipping, "releaseFingerprintId": release, "toolingFingerprintId": tooling, "candidateIsCurrent": True, "sourceChangedSinceCandidate": False, "rebuildRequired": False})
    put(entries, "audit/CURRENT-HANDOFF.json", handoff)
    put(entries, "finalization-state.json", state)
    current = read_json(entries, "evidence/CURRENT-PROOF.json")
    current.update({"status": "PASS", "outcome": "PASS", "fullReleaseRunId": run_id, **tuple_value})
    put(entries, "evidence/CURRENT-PROOF.json", current)
    summary = read_json(entries, "evidence/FULLRELEASE-SUMMARY.json")
    summary.update({"diagnosticOnly": False, "historicalEvidenceOnly": False, "latestRunId": run_id, "candidateTuple": tuple_value})
    put(entries, "evidence/FULLRELEASE-SUMMARY.json", summary)
    put(entries, "evidence/l1-terminal-state.json", {"name": "DevFleet-E2E-Win11-01", "id": "84b7d8b8-ee6c-4085-aa29-4b0adc316de2", "state": "Off", "timestamp": "2026-08-30T00:00:00Z", "ownershipScope": "exact disposable"})
    put(entries, "evidence/l2-terminal-state.json", {"expectedName": "DevFleet-E2E-Linux-01", "present": False, "timestamp": "2026-08-30T00:00:01Z", "verificationMethod": "Get-VM -Name exact"})
    cleanup = {"status": "PASS", "l1": {"state": "Off"}, "guest": {"runRootAbsent": True, "foreignResourcesMutated": False}}
    put(entries, "evidence/current-fullrelease/final-cleanup.json", cleanup)
    cleanup_hash = digest(entries["evidence/current-fullrelease/final-cleanup.json"])
    l1_hash = digest(entries["evidence/l1-terminal-state.json"])
    l2_hash = digest(entries["evidence/l2-terminal-state.json"])
    put(entries, "evidence/current-fullrelease/post-cleanup-finalization.json", {"status": "PASS", "runId": run_id, "cleanupConsumed": True, "reconcileAfterCleanup": True, "cleanupEvidenceHash": cleanup_hash, "terminalL1Hash": l1_hash, "terminalL2Hash": l2_hash, "liveChecks": {"l1ExactOff": True, "l2ExactAbsent": True}})
    put(entries, "evidence/current-fullrelease/run-state.json", {"runId": run_id, "candidateHashes": tuple_value})
    put(entries, "evidence/current-fullrelease/fullrelease-phase-records.json", [{"id": "RECONCILE", "status": "PASS", "runId": run_id}, {"id": "CLEANUP", "status": "PASS", "runId": run_id}])
    entries["evidence/current-proof/product-lifecycle-progress.jsonl"] = b'{"heartbeat":true}\n'
    source_map = {"proofScriptSha256": digest(entries["release-tooling/proof-entrypoints/run-exact-candidate-proof.ps1"]), "invokeRealProductPhaseSha256": digest(entries["release-tooling/proof-entrypoints/Invoke-RealProductPhase.psm1"]), "invokeWpfUiAutomationSha256": digest(entries["release-tooling/proof-entrypoints/Invoke-WpfUiAutomation.ps1"])}
    for index in (1, 2):
        proof_id = f"e2e-proof{index}-synthetic"
        start = {"runId": proof_id, "proofScriptSha256": source_map["proofScriptSha256"], "provenance": {**tuple_value, **source_map, "transactionId": f"transaction-{index}", "checkpointLineageId": f"lineage-{index}"}}
        put(entries, f"evidence/proof-runs/{proof_id}/proof-start.json", start)
        put(entries, f"evidence/proof-runs/{proof_id}/proof-final.json", {"runId": proof_id, "status": "PASS", "outcome": "PASS"})
    return entries


def write_archive(entries: dict[str, bytes], path: Path) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)


def must_fail(entries: dict[str, bytes], mutate, label: str) -> None:
    changed = copy.deepcopy(entries)
    mutate(changed)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "synthetic.zip"
        write_archive(changed, path)
        try:
            validate(path, "final")
        except ValueError:
            return
    raise AssertionError(f"negative bundle was accepted: {label}")


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        diagnostic = Path(directory) / "diagnostic.zip"
        with zipfile.ZipFile(ARCHIVE) as source, zipfile.ZipFile(diagnostic, "w", zipfile.ZIP_DEFLATED) as target:
            for info in source.infolist():
                target.writestr(info, source.read(info.filename))
        # Exercise both missing and wrong historical source handling through
        # the real diagnostic archive validator.
        with zipfile.ZipFile(ARCHIVE) as source:
            entries = {name: source.read(name) for name in source.namelist() if not name.endswith("/")}
        historical_good = Path(directory) / "historical-diagnostic.zip"
        # The checked-in archive predates the authorized Common.psm1 trust
        # policy correction.  Keep it immutable, but bind this isolated
        # historical fixture to the current exact seven-path authority set.
        seven_paths = [
            "installer-source/DevFleet.Setup/Services/InstallerLifecycle.cs",
            "installer-source/DevFleet.Setup/Services/InstallerServices.cs",
            "installer-source/DevFleet.Setup.Tests/Program.cs",
            "source/tools/validate_audit_coherence.py",
            "source/tools/validate_ai_audit_bundle.py",
            "source/tests/test_audit_coherence.py",
            "source/windows/DevFleet.Common.psm1",
        ]
        for authority_name in ("finalization-state.json", "CURRENT-CANDIDATE.json", "AUDIT-MANIFEST.json"):
            authority = read_json(entries, authority_name)
            if authority_name == "finalization-state.json":
                authority["authorized_correction"]["shipping_paths"] = seven_paths
            else:
                authority["authorizedCurrentShippingPaths"] = seven_paths
                if isinstance(authority.get("historicalProvenance"), dict):
                    authority["historicalProvenance"]["authorizedCurrentShippingPaths"] = seven_paths
            put(entries, authority_name, authority)
        write_archive(entries, historical_good)
        diagnostic_result = validate(historical_good, "diagnostic")
        assert diagnostic_result.get("status") == "PASS_WITH_BLOCKER"
        assert diagnostic_result.get("releaseEligible") is False
        try:
            validate(historical_good, "release")
        except ValueError:
            pass
        else:
            raise AssertionError("historical provenance was accepted in release mode")
        current = read_json(entries, "evidence/CURRENT-PROOF.json")
        historical = current["proofStartHistoricalPath"]
        entries.pop(historical)
        missing = Path(directory) / "missing.zip"
        write_archive(entries, missing)
        try:
            validate(missing, "diagnostic")
        except ValueError:
            pass
        else:
            raise AssertionError("missing historical source was accepted")
        with zipfile.ZipFile(ARCHIVE) as source:
            entries = {name: source.read(name) for name in source.namelist() if not name.endswith("/")}
        entries[historical.replace("proof-start.json", "run-exact-candidate-proof.ps1")] = b"wrong historical bytes"
        wrong = Path(directory) / "wrong.zip"
        write_archive(entries, wrong)
        try:
            validate(wrong, "diagnostic")
        except ValueError:
            pass
        else:
            raise AssertionError("wrong historical source was accepted")
    entries = final_entries()
    with tempfile.TemporaryDirectory() as directory:
        good = Path(directory) / "good.zip"
        write_archive(entries, good)
        validate(good, "final")
    must_fail(entries, lambda e: [e.update({f"evidence/proof-runs/e2e-proof2-synthetic/proof-start.json": json.dumps({**read_json(e, "evidence/proof-runs/e2e-proof2-synthetic/proof-start.json"), "provenance": {**read_json(e, "evidence/proof-runs/e2e-proof2-synthetic/proof-start.json")["provenance"], "transactionId": "transaction-1", "checkpointLineageId": "lineage-1"}}).encode()})], "reused transaction/lineage")
    must_fail(entries, lambda e: [e.update({"evidence/proof-runs/e2e-proof2-synthetic/proof-final.json": json.dumps({"runId": "wrong-run", "status": "PASS"}).encode()})], "mixed RunId")
    must_fail(entries, lambda e: [e.update({"evidence/current-fullrelease/post-cleanup-finalization.json": json.dumps({"status": "PASS", "runId": "FullRelease-synthetic-current", "cleanupConsumed": True, "reconcileAfterCleanup": True}).encode()})], "absent liveChecks")
    must_fail(entries, lambda e: [e.update({"evidence/current-fullrelease/post-cleanup-finalization.json": json.dumps({**read_json(e, "evidence/current-fullrelease/post-cleanup-finalization.json"), "liveChecks": {"l1ExactOff": False, "l2ExactAbsent": True}}).encode()})], "false liveChecks")
    must_fail(entries, lambda e: [e.update({"evidence/current-fullrelease/final-cleanup.json": b"{\"status\":\"tampered\"}"})], "cleanup hash mismatch")
    must_fail(entries, lambda e: [e.update({"evidence/l1-terminal-state.json": b"{\"state\":\"Running\"}"})], "terminal hash mismatch")
    print(json.dumps({"status": "PASS", "cases": 8}))


if __name__ == "__main__":
    main()
