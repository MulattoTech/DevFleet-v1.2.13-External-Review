# DevFleet v1.2.13 — Current Codex Resume Checkpoint

Updated: 2026-08-31T22:55:01.1895009Z

## Verdict

**BLOCKED — CANDIDATE INVALIDATED / PLATFORM AUTHORIZATION**

This is a truthful stop checkpoint, not release approval. `PASS — INTERNAL RELEASE ELIGIBLE` is not proven.

## Candidate truth

- Repository HEAD: `d677ce6b7a850d897b06fabe61ae9b61148d9e36`
- Invalidated candidate: `f95ac87a4e1bf51f19973e5e2d4044b64f5ab004`
- Historical candidate shipping identity: `7d0e4d5e6362918188641cd85cc80f1df18522e3e7f3151f4ab60a9a0dc5615c`
- Historical release fingerprint: `a0b2ed36772f57adeaf881b5c054ccbe955af6eca16d81c4a368c57db73a1e7e`
- Candidate current / source changed / rebuild required: **FALSE / TRUE / TRUE**

A fresh, fail-closed standard-token self-test proved the signed candidate is defective: the `asInvoker` process applied production-only Administrators/SYSTEM staging ACLs, removed its own traversal rights, then failed creating `InstallerCache/1.2.13/self-test`. The previous adjacent PASS report was stale. Independent review confirmed candidate invalidation.

## Prepared correction

The corrected shipping batch preserves production staging as exactly Administrators plus SYSTEM. Only a GUID-shaped, in-process-registered self-test root directly beneath `%TEMP%` adds FullControl for the exact current-user SID. No broad Users, Authenticated Users, or Everyone ACE is introduced.

- Prepared working-tree shipping identity: `e4eb71ff955e72387a2a30cf00772d96b93c6c61c442c979a95180a76394aa9c`
- Working-tree tooling fingerprint: `c4eddc9e69dc53f5f7b34222857a167cf0094514db0bc22f3636236be71cb2ab`
- Prepared TAR: `1fdb468e5339cfb4a8f05db9077858bdaf6d054f1cd07e91c85c6f08763cec51`
- Prepared portable ZIP: `e4a7702c17f8eac4db6d8639f9917f1e0d825eb78e3f251b34f4ba19b88e0a2a`
- Two-pass PREPARE idempotence: **PASS**
- Independent implementation review: **NO BLOCKER**

Verification completed:

- Python source suite: **459 passed, 15 platform skips**
- Release-tooling regression suite: **22 / 22 PASS**
- Installer executable suite: **PASS**
- Published non-administrator `asInvoker --self-test`: **PASS**, exit 0, all required checks, zero residual scratch
- Release harness: **83 / 83 PASS**
- Lifecycle observer suite: **102 PASS**
- Shipping-identity unit tests: **3 PASS**
- `git diff --check`: **PASS**
- Diagnostic source validator: **PASS_WITH_BLOCKER**, non-release-eligible
- Diagnostic release-tooling validator: **PASS_WITH_BLOCKER**, non-release-eligible
- Diagnostic secret scan and bundle sidecar verification: **PASS**

## True platform blockers

1. Canonical Git metadata is read-only to this managed sandbox. `git add` fails with `Unable to create .git/index.lock: Permission denied`. Therefore the prepared source cannot be committed, assigned a canonical Git-object identity, rebuilt, signed, or bound as a truthful new candidate.
2. The current token is not authorized for Hyper-V. `Get-VM`, `root/virtualization/v2`, and `hcsdiag` return Access denied for exact L1, and the alternate Windows control bridge is unavailable. Exact proofs and FullRelease cannot run.

Current runtime truth:

- L1 `DevFleet-E2E-Win11-01` / `84b7d8b8-ee6c-4085-aa29-4b0adc316de2`: **UNVERIFIED — ACCESS DENIED**
- L2 `DevFleet-E2E-Linux-01`: **ABSENT** in the current Multipass inventory
- Protected Multipass instances were observed stopped and were not mutated.
- One positively identified host-local scratch directory from the invalidated-candidate self-test remains under `%TEMP%`; the managed sandbox rejected recursive deletion. It has no release authority or product-state impact.
- Exact proofs: **0 / 2 PASS**
- Maintenance: **0 / 5 PASS**
- FullRelease: **NOT RUN FOR A CURRENT CANDIDATE**

## Resume sequence

Resume under a token with writable canonical `.git` metadata. Commit the coherent tooling batch and prepared shipping batch without including unrelated user-owned files. Then recompute canonical Git-object identity, verify frozen inputs, build once, sign once with the existing authorized certificate, and atomically bind the new candidate. Under an already Hyper-V-authorized token, restore exact CLEAN and continue through proofs 1/2, maintenance/sentinels, FullRelease, RECONCILE, CLEANUP, final bundle validation, and adversarial review.

## Safety

Protected production, host reboot, AMD/Radeon, BIOS/UEFI, MulattoTechSurface, GitHub, signing-key export, trust stores, and F-005 were untouched.
