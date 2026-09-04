# DevFleet v1.2.13 progress report

Generated: 2026-09-04T00:13:57Z

## Current status

Certification is incomplete because the user requested a stop while current Proof #1 was still making meaningful progress. No release PASS is claimed.

- Repository HEAD / candidate commit: `d8cc7a0ae393b130bc31d82d821f271bb26c8ae5`
- Branch: `v1.2.13-audit-remediation`
- Candidate current: `true`
- Source changed since candidate: `false`
- Rebuild required: `false`
- Validation evidence current: `false`
- FullRelease passed: `false`
- Internal promotion allowed: `false`
- Proofs: `0 / 2 PASS`
- Current stopped run: `e2e-exact-candidate-proof-1-20260903T233505Z`

## Final candidate tuple

- Shipping-input identity: `787dc058797ac72cd031f7efd5ca3ad4feb1714b3ed0712509e931cbe14d2085`
- Release fingerprint: `8e6ea895a4d0fd6c2461bbed2f1ca76e4615a941152dab422830a063b265e835`
- Tooling fingerprint: `c2016c2a317ee9a061cb75caa0e6e2259318d585d5aea2f489c8640d438d56aa`
- Signed EXE: 72,214,976 bytes; SHA-256 `fe64c01e8f22a971e35b2fb9e51492e5aac90901840b705b3a7bb550327a2cfb`
- TAR SHA-256: `06bb8491ef7b056fa5e9f752a20cf7e340b0c717802d3fc1a5ff0f838e0ec562`
- Portable SHA-256: `112161ba57392b96c87ac29cebd5d43d889470ae458913339083161fc958e6f0`
- Installer Source SHA-256: `30e7230abe649142d36fa31853099a35f61dee179a9ef0bf002de62a6bc19738`
- Authenticode: valid; `CN=DevFleet Private Personal Code Signing`
- Certificate thumbprint: `DE42CD7369A01E9357BDA13597C0173E5E703E9D`
- RSA: 3072; existing signing identity used; private key not exported

## Completed corrections

1. Redirected-process output is now bounded after direct child exit. `ProcessResult` explicitly reports `OutputComplete`; exit-code-authoritative installer paths retain direct exit `0`/`3010`, while trust/output parsers reject incomplete output.
2. The same confirmed post-exit drain pattern was corrected in the scoped C# and PowerShell runners without a broad process abstraction refactor.
3. WPF proof finalization now treats a missing/exited process and missing process ID truthfully instead of invoking CIM with a null object.
4. Reboot checkpoint JSON writes now use durable write-through, disk flush, atomic replacement, and exact readback verification.
5. Reboot servicing samples now compare stable semantic fields instead of session-specific remoting metadata.
6. Trusted executable-root selection preserves complete paths instead of scalarizing strings.
7. The connected installer lifecycle now has the repository-authoritative 1,800-second bound while ordinary probes retain 900 seconds.
8. Long compute and vault bootstrap executions use the existing 1,800-second nested bootstrap budget instead of being killed at 900 seconds.

Key commits for the final correction chain:

- `7ec2bef` Bound redirected process output drains
- `b066fa9` Preserve complete trusted executable roots
- `4fbf283` Compare reboot servicing state semantically
- `1f27188` Durably flush atomic installer state
- `57b812d` Guard missing WPF proof process IDs
- `1f3f788` Align connected install timeout with lifecycle budget
- `cd81dd6` Align nested bootstrap execution budgets
- `d8cc7a0` Refresh release payload for bootstrap budgets

## Validation completed

- Current release build: PASS, zero compiler warnings/errors.
- Dependency advisory gate: PASS, 26 packages, 0 blocking advisories/errors.
- Independent OSV reconciliation: PASS, 26 packages, 0 advisories/errors.
- Installer .NET regression executable: PASS, including inherited-pipe direct exits, exact `3010`, 200k stdout/stderr, normal nonzero exit, direct timeout, durable state, and installer lifecycle cases.
- PowerShell output-drain/bootstrap-budget regression: PASS, 4/4.
- PowerShell AST validation for the changed compute, vault, and regression scripts: PASS.
- Authenticode verification against the existing signing certificate: PASS.

## Latest Proof #1 observations

Run `e2e-exact-candidate-proof-1-20260903T233505Z` was stopped at the user's requested wrap-up boundary, not by a product failure.

- Real signed WPF interactive launch: observed.
- Fresh transaction: `c01334ae6445464bacc481e99eac87e4`.
- Generation 0: durable `NEXT_REBOOT` observed.
- Exact L1 product-authorized reboot and generation-1 resume: observed.
- Checkpoint remained valid and was consumed by the resumed flow.
- Prerequisites and Host Agent stage markers: durable.
- Host Agent listener: present.
- Compute bootstrap passed both former 900-second boundaries and was still making meaningful progress at stop.
- Last meaningful progress: `2026-09-04T00:09:55.385104Z`.
- Observed product-process CPU at stop: `1493.766` seconds.
- Terminal product outcome: not observed.
- Proof PASS claimed: no.

## Cleanup and safety

- Run-owned cleanup: PASS.
- L1 `DevFleet-E2E-Win11-01`: OFF.
- L2 `DevFleet-E2E-Linux-01`: absent.
- Ordinary DefaultPassword: absent.
- LSA DefaultPassword: absent.
- AutoLogon cleanup and registry persistence barrier: PASS.
- Production resources mutated: no.
- MULATTOTECHBOX rebooted: no.
- AMD/Radeon or BIOS/UEFI touched: no.
- MulattoTechSurface touched: no.
- GitHub pushed: no.
- Signing private key exported: no.
- F-005 attempted: no.

## Remaining release work

Start a fresh current-candidate Proof #1 from canonical CLEAN with a new RunId. If it passes, run independent Proof #2, maintenance/sentinels, one current FullRelease, maintenance 5/5, RECONCILE, durable CLEANUP, and then generate a release-mode AI audit ZIP. The present diagnostic ZIP must not be treated as release eligibility evidence.
