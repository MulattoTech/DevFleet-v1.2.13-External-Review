# AI-agnostic DevFleet troubleshooting prompt

You are an independent software/release-forensics reviewer. Do not assume the included diagnosis is correct. Try to falsify it from source and machine-readable evidence.

## Goal

Determine exactly why DevFleet v1.2.13 has still not reached a current exact Proof #1 PASS after the timeout-hierarchy repair, and provide a concrete minimal permanent fix and certification plan.

Start with:

1. `03-CURRENT-STATE.json`
2. `02-INDEPENDENT-ANALYSIS.md`
3. `current-audit/evidence/CURRENT-PROOF.json`
4. `current-audit/evidence/CURRENT-RELEASE-AUTHORITY.json`
5. `current-audit/evidence/current-proof/product-lifecycle-progress.jsonl`
6. `current-audit/source/windows/02-Provision-ComputeNode.ps1`
7. `current-audit/source/windows/DevFleet.Common.psm1`
8. `current-audit/source/linux/bootstrap-compute.sh`
9. `current-audit/automation/release-e2e/modules/executors/Invoke-RealProductPhase.psm1`
10. `current-audit/automation/release-e2e/config/devfleet-e2e.defaults.json`

## Established history you should verify

The previous whole-install 1,800-second parent timeout preempted an inner 1,800-second compute operation. The new implementation introduced finite deadline ownership and the latest proof crossed that former boundary without parent preemption.

The latest proof was then manually stopped before a natural terminal. Do not misattribute an earlier `NO_PROGRESS_TIMEOUT` from the same long Codex transcript to the latest proof lineage.

## Core questions

1. Does the newest proof show real forward product progress, or only CPU/process activity?
2. Is `Test-ProductMeaningfulProgress` logically flawed because `productChildInstances` contains changing CPU fields, making its JSON change before the aggregate CPU threshold is checked?
3. Could a busy-loop/hung `multipass.exe` therefore keep resetting the no-progress deadline?
4. Conversely, is ~95% CPU/wall utilization strong enough to treat this specific run as legitimate progress?
5. What exact internal Linux operation is most likely consuming the runtime? Can the current evidence prove it?
6. Is `guestBootstrap=6300` source-backed and sufficient?
7. Are compute=9600, Desktop transaction=30420, Laptop transaction=41520, observer absolute=31020, and exact proof outer=131580 correctly derived, or unnecessarily inflated?
8. Do any parent/child inequalities remain inverted?
9. Should the product emit durable guest-bootstrap substage progress (for example a non-secret progress JSON/marker file), and should the host observer read it while the primary `multipass exec` is active?
10. Which Linux commands need their own finite operation deadlines rather than only the outer `multipass exec` deadline?
11. Can a harness-only correction preserve the current signed candidate, or is a shipping-source change necessary?
12. The latest proof-start tooling fingerprint differs from current tooling authority. Confirm whether a fresh Proof #1 is mandatory even if the interrupted run otherwise looked healthy.
13. Propose a Plus-plan-friendly certification sequence that avoids assuming one >5-hour Codex session.

## Required output

Return these sections:

1. VERDICT
2. CURRENT PROOF INTERPRETATION
3. ROOT CAUSE / REMAINING UNCERTAINTY
4. PROGRESS-CLASSIFIER AUDIT
5. GUEST-BOOTSTRAP AUDIT
6. DEADLINE-POLICY AUDIT
7. MINIMUM PERMANENT PATCH
8. CANDIDATE REBUILD / RE-SIGN POLICY
9. FAST REGRESSION TEST PLAN
10. RUNTIME PROOF PLAN
11. DOWNSTREAM FULLRELEASE LOOKAHEAD
12. FIVE-HOUR SESSION ORCHESTRATION
13. SOLVED-STATE CHECKLIST

For every proposed code change, cite the exact file/function and explain why it is required.

Do not recommend unbounded waits. Do not weaken Host Safety, VM ownership, signing, authentication, cleanup, or F-005 restrictions.
