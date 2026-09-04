# External AI findings triage — v1.2.13

> **Historical record:** This document captures the Hardening-11 review state. It is not the current `v1.2.13-audit-remediation` signed-candidate authority. Use `NEXT-CODEX-HANDOFF.*`, `finalization-state.json`, and current output manifests for live release identity.

## Historical Hardening-11 disposition

At the time captured, the source was release-closeout commit `62a99072d30b857c693812785bdab58c2ad50629` on branch `v1.2.13-hardening-11`. The H10 candidate and all prior candidate identities were historical. H11 release fingerprint was schema 2 / `3bfc656045619109638a984332ce244b78e4a44fefd0fe61332edced8c9860a2`; tooling fingerprint was `b27a793a9690d9a6e93295217cbff327218d224fa400fc11f7b0dac1d5a438e5`.

The six newly confirmed findings are source-remediated with focused evidence: RED-001 Compose effective-model boundary, RED-002 Dev Container runtime privilege boundary, RED-003 authoritative read ownership, RED-004 explicit rootless Docker socket identity, RED-005 canonical extracted-bundle path mapping, and RED-006 non-short-circuit credential comparison. The durable corpus and related focused suites pass; these are **SOURCE REMEDIATED / FOCUSED TEST PASS**, not real E2E PASS until the exact H11 FullRelease reaches those phases.

DBB-001 through DBB-005 are retained as source-remediated Daybreak Blue items. Current H11 exact-candidate evidence still requires the complete normal FullRelease and Linux-native regression execution. No Laptop/Surrogate Test Kit is eligible before FullRelease.

The final exact-candidate FullRelease run `e2e-20260823T124827Z-142bfd3f` used the current H11 artifact tuple and fresh adaptive HOST-SAFETY. Pre-start HOST-SAFETY and candidate verification passed, then post-start HOST-SAFETY blocked at RESTORE-CLEAN due to fresh memory pressure. The VM was left OFF by normal failure cleanup; maintenance is 0/5 and Linux/Tailscale/surrogate stages were not reached. Earlier intermediate runs that reached nested Linux remain historical and are not substituted for this final run.

The supplied workspace did not contain the six external report documents. The JSON records each supplied lead as a hypothesis and the independently observed current-source status. Source, reproducible tests, and exact-current-candidate evidence remain authoritative.

Confirmed high-risk items are being remediated in focused change groups: release identity/order, C# signer enforcement, bounded redirect validation, Release manifest isolation, Host Agent authentication/recovery, ownership/firewall scope, and the non-shipping review-bundle tooling. Linux bootstrap supply-chain hardening remains a P1 work item requiring disposable Linux validation before it can be promoted as fixed.

The GitHub digest claim is treated as a false premise: current official GitHub release-asset API documentation exposes a `digest` field when available. Missing digest remains fail-closed for strategies that require it.

The triage is not an independent delegated security scan; the explicit one-agent constraint prevented that workflow. It is a parent-agent source-backed triage.

## Second audit reconciliation

The second source review reopened the previous restore/reboot classifications instead of grandfathering them. Workspace restore is now transactionally staged with rollback-focused tests. Reboot/resume and Clean Reinstall are only **partially fixed** until fresh-process and disposable fault-boundary evidence exists. Trusted executable resolution, Release test-root isolation, durable operation orphan reconciliation, wizard polling, streaming hashes, and the AI bundle inventory are covered by current focused/live verification. Linux supply-chain hardening, Vault transport, TOCTOU race resistance, ledger ACL/junction adversarial coverage, and physical/disposable topology validation remain evidence-gated.

The current bundle verification is objective: the final actual AI ZIP contains 699 manifest files, 78 executable-by-contract hooks, 0 missing files, 0 hash mismatches, 0 POSIX mode mismatches, and secret scan PASS. This is tooling evidence only and does not promote the obsolete candidate or any expensive release gate.

## Newest adversarial lead reconciliation

The newest 14 leads were independently checked against the local source and deduplicated into a 52-finding matrix: 30 original findings, 15 second-audit findings, and 7 genuinely new roots. DF-001, DF-005, DF-008, DF-009, DF-010, DF-011, and DF-012 overlap existing roots and are retained as explicit aliases rather than inflated findings.

Current source changes include the shared destructive quiescence/fresh-backup invariant, fresh Factory Reset authorization, canonical privileged executable resolution, Windows Home/VirtualBox dependency modeling, hash-bound Linux Python/npm acquisition, serializer-safe Linux metadata, explicit archive extraction, request-local session caching, deterministic backup discovery, and contract-driven hook modes. Focused and static gates pass; dynamic poison, Linux, WPF responsiveness, Windows Home, final ZIP round-trip, and disposable destructive E2E evidence remain open.

The current source hook contract reports 78 executable-by-contract hooks, and the final actual ZIP round-trip now verifies all 78. The prior 80-hook claim is not carried forward.

The previous blocked RC remains historical only: fingerprint `410c2bf4467a9dbbf841ee9095881640ec969e26e94290a347ece1a8a11bbbd3`, EXE SHA-256 `90c82a4e1f6b57d89abf023eba3896bd401d01c7df62d47f7eec03240d4e00b6`. No FullRelease was run against it.

## Hardening-10 Daybreak Blue remediation

The five Daybreak Blue findings are now tracked explicitly in `daybreakBlueFindings` in this file's JSON companion. DBB-001 was reproduced and fixed by restoring the required `staging/<slug>` layout with descriptor-relative extraction; the normal POSIX restore and the repeated substitution/kill/reconciliation matrix pass. DBB-002 and DBB-003 use the upgraded FastAPI 0.141.1 / Starlette 1.6.0 / python-multipart 0.0.32 stack, complete exact hashes, an OSV freshness gate, bounded pre-parser login admission, and bounded `/static` Range admission. DBB-004 now writes Unix-origin ZIP metadata and passes a standard Ubuntu unzip round trip. DBB-005 uses schema-2 transaction fixtures and explicit canonical source-root mapping.

Native Ubuntu evidence is 339 passed and one environment-only skip when the two PowerShell-only migration tests are excluded, plus 10 complete restore/race repetitions of 40 passed tests. Combined Windows/Linux statement coverage for `workspace_archives.py` is 86.02%. These are source and focused-platform results; the exact Hardening-10 candidate and its clean FullRelease remain pending and are not promoted by this triage.

## Historical hardening-3 exact-candidate evidence

The current candidate is release fingerprint `c698835743203f299a176a51cb52288291a17a756bb33e001d0c255a5e8c9235` with tooling fingerprint `9733d6d2ead3df5483ef06dab865e7c0ee8f994df543eb66c2967a5fc3231e19`. Its EXE self-test passes. FullRelease run `e2e-v1213-hardening3-final-14` passed HOST-SAFETY, CANDIDATE-VERIFY, exact CLEAN checkpoint restore, and a real interactive guest session (`DEVFLEET-E2E-01`), then failed closed at DEPENDENCY-MATRIX because no real product executor is configured. It did not promote any downstream phase. The disposable VM finished OFF at the required fixed 16 GiB / Dynamic Memory OFF topology; production VMs and MulattoTechSurface were untouched.

Final artifact evidence: EXE 71,934,740 bytes / `835f16f6ea38dfd5eedaab39d6375094b9e7f31e823200b03182a974f7779480`; TAR 263,360 bytes / `31ce08249a86c178fc759f5da94245f9b0da18de269fa81aa94c01eec76cc649`; Portable 1,852,511 bytes / `31d2303ed57b7eb388a68d531c80938ba63fcdf8e363625b9da5aca9e9122eda`; Installer Source 546,522 bytes / `777b4182a4b39d65ecfeffcf01201322521bc456fa240fce11aa9a55e1841be0`.

The remaining audit matrix is evidence-gated rather than silently passed: dynamic destructive-writer, fresh Factory Reset backup, poison executable, Linux supply-chain/serialization, WPF responsiveness, Windows Home/VirtualBox, reboot/resume, Clean Reinstall, and physical surrogate evidence remain pending or preview-unverified.

## Hardening-7 reconciliation

Hardening-6 is preserved as the immutable historical reference, but its candidate is invalidated by the first Hardening-7 shipping-source edit. The JSON `hardening7Findings` matrix records the new leads H7-001 through H7-020 with allowed classifications, affected paths, remediation, focused tests, commit placeholder, dynamic evidence boundary, and remaining risk. The current state is therefore source-changed/rebuild-required, not candidate-current.

Confirmed and addressed in the current source include the Linux control-plane/backup identity split, removal of the devrunner sudo escape, explicit runtime ownership, live guest VM identity assertions, cleanup postconditions and transaction binding, UAC staging order, stdin-only node-secret transport, password-free encrypted bundles, exact fingerprint policy binding, restore transaction journaling, immediate Compose reanalysis, metadata transaction support, bounded operation admission, terminal frontend polling, explicit backup durability fields, persisted Host Agent nonce replay state, fail-closed host-secret recovery, safe cloud-init scalar encoding, structured archive validation, abandoned-mutex reconciliation, and trusted VS Code resolution.

Focused source tests and parse checks pass for the addressed contracts. Real Linux bootstrap, disposable Windows UAC/cleanup/poison tests, archive/envelope runtime round trips, and the exact rebuilt-candidate FullRelease remain evidence gates. No Hardening-6 evidence is reused to promote Hardening-7.

## Hardening-4 current-state reconciliation

The current candidate is DevFleet 1.2.13 / installer 1.4.1 with release fingerprint `17514081ab4f50fe5ba4a6878bc41f0ce09f16fb640c9189a03d62073052486d` and tooling fingerprint `32bfd276db3623e6909eb25853d80a4d2e91e34d337259e4bf3783b72797891a`. Candidate state is current, source-changed-since-candidate is false, rebuild-required is false, production-unchanged is true, and MulattoTechSurface-touched is false. The older fingerprint and artifact hashes in this file are explicitly historical evidence only.

Current artifact evidence: EXE `2ebd34c8cb93042998b3224f8f62767727d7bf1fd66005e028a14bb49bf1ce76` (71,955,622 bytes); TAR `8f3f467c16c67594a442c486f72954f5a0dedf4e8a79500621700509fdb15a35` (279,424 bytes); Portable `8ec28b70921027191b60150b00522b0a8ab383982c1ee65cc206f1d9c652bb07` (1,970,173 bytes); Installer Source `0a08f0f9cafd3165605670434c8bf0ffcff98cd7618da9845dd42fe2a25c9457` (569,530 bytes).

Deduplicated current classifications account for the requested latest roots: installed-binary authenticity, malformed ownership, exact Factory Reset selection, quiesced destructive backups, long-slug backup IDs, bounded Host Agent concurrency, request authentication, health privacy, portal policy, bootstrap/input serializers, command-slug revalidation, cross-process sessions, login CSRF, lease reconciliation, streaming archive hashing, workspace same-filesystem promotion, supply-chain pinning, and developer-machine default removal are fixed in source with focused tests where available; poison, Linux, WPF, disposable destructive, and physical topology evidence remain dynamic-gated. The optional 7-Zip password-in-argv path remains an explicitly documented local residual risk with secret-bearing logs redacted and core functionality independent of it. No current gate is promoted from historical evidence.
