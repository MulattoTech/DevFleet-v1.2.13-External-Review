# DevFleet v1.2.13 timeout-hierarchy remediation — after-action report

## Result

**BLOCKED — diagnostic handoff, not an internal release approval.**

The permanent timeout-ownership repair was implemented, statically tested, committed, and used to create one replacement signed candidate. Exact Proof #1 reached generation 1, crossed the former 1800-second parent boundary without the old parent-preempts-child failure, and was intentionally stopped while still inside the finite child-owned provisioning path at the user's request. It did not produce a natural PASS or a child-owned terminal result. Proof #2, maintenance 5/5, FullRelease, RECONCILE, and release certification were therefore not run.

## Current tuple

- Repository HEAD: `d65560c1ec7bf97f4002a9e9a438fbc1b25f22bd`
- Signed candidate commit: `f2617e2277b4fb717058feec2ca93e30761f774b`
- Shipping-input identity: `194f64f99a4268c8b5b47abad9d73379e8eca10187e377a7f79b1693adecb39a`
- Release fingerprint: `6cd57a5c5a21b1f6ef142d695674eefaf4ab4d442b2a513c829b53989f3e3c9f`
- Current tooling fingerprint: `125080ef78e6e2afbd952cee305d67e10e76747eb1ce3349dcaaa65666f3dab4`
- Signed EXE SHA-256: `8f892501544c367da75a43c025dd711feffabc3740068f1d13d3dd8f4c5ff78e`
- Signing certificate: `CN=DevFleet Private Personal Code Signing`
- Proof #1 lineage: `e2e-exact-candidate-proof-1-20260904T184913Z`
- Proof #1 state: `NOT_OBSERVED` after generation-1 child-owned provisioning was stopped
- L1: `DevFleet-E2E-Win11-01` — OFF
- L2: `DevFleet-E2E-Linux-01` — ABSENT

## Implemented repair

The repair is a composable finite deadline hierarchy. Operation maxima are subordinate to remaining owning-stage deadlines; compute and vault stage budgets are derived from their bounded sequential paths; role-aware Desktop/Laptop transaction budgets dominate those stages; the lifecycle observer has separate rolling no-progress and immutable absolute budgets; FullRelease dominates the observer; exact-proof outer validation dominates the calculated inner bound and fails configuration instead of silently clamping.

`Wait-MultipassReady` and external probes now receive the minimum of their operation maximum and remaining active-stage deadline. The connected installer keeps tree-kill fail-closed behavior only when its true owning transaction deadline expires. The global process-wide timeout environment variable is not used as the architectural fix.

The implementation also fixed bounded Hyper-V session opening and session lifetime across reboot, preserved concrete proof child errors, and made current blocker authority bind to the newest proof lineage.

## Validation completed

- Harness contracts: `107/107 PASS`
- Source Python tests: `479 passed, 8 skipped`
- Installer build and .NET tests: PASS
- Lifecycle observer tests: `110/110 PASS`
- ProcessRunner, checkpoint, interactive-login, final-convergence, release-integrity, security-poison, and related focused gates: PASS where executed
- Authenticode verification: PASS with the existing personal/test certificate
- Replacement candidate build/sign: completed once after shipping inputs stabilized
- Fresh direct HOST-SAFETY: PASS
- Exact synthetic reboot boundary: PASS in the latest proof lineage

## Main issue for the next LLM

The remaining obstacle is not the original 1800-second parent preemption. In the latest proof, generation 1 entered the real product lifecycle and remained active in the child-owned provisioning path for an extended period. The observer continued recording progress evidence and no parent watchdog terminated the healthy child at the former boundary. The run was stopped before the child reached either successful completion or its own legitimate finite terminal condition.

The next LLM should inspect the latest run's generation-1 progress evidence and determine whether the child is making meaningful progress toward a bounded terminal state, whether the progress classifier is appropriately treating CPU/activity changes as meaningful, and whether the legal critical path's derived allowance is correctly represented. If another proof is attempted, use a fresh RunId from the exact clean checkpoint and keep the current candidate/tooling tuple unchanged unless shipping source changes.

Earlier transient blockers that were addressed in this session included an invalid `New-PSSession -SessionOption` parameter combination, loss of nested Hyper-V sessions when the opener pipeline was disposed, and insufficient proof error capture. Do not confuse those historical tooling failures with a proven compute defect.

## Release gates not claimed

Proof #2, maintenance/sentinels, FullRelease, maintenance 5/5, RECONCILE, durable cleanup certification, and final internal-release eligibility remain incomplete. Public promotion remains false. F-005 was not attempted; no formatter-only audit cleanup or structural refactoring was performed. Protected production VMs, MULATTOTECHBOX reboot, AMD/Radeon, BIOS/UEFI, MulattoTechSurface, GitHub, private signing-key export, and security controls were not touched.
