# Independent analysis — current DevFleet v1.2.13 blocker

## Bottom line

The original parent-preempts-child timeout defect appears to be fixed. The latest exact proof crossed the old 1,800-second parent boundary with the real `Bootstrap-Install -> Install-DevFleet -> multipass exec` chain still alive.

However, DevFleet is **not one certification prompt away with high confidence**. The current proof was manually stopped before a natural product terminal, and its proof-start tuple is now historical relative to current tooling authority (`125080ef78e6e2afbd952cee305d67e10e76747eb1ce3349dcaaa65666f3dab4` at proof start vs `5fdff42ff7b2ea11e6dad10bf09fbce981a9333b22f0ac4c22d0dab935b6a216` current). A fresh Proof #1 is required regardless.

Release gates currently remain 0/2 proofs, no current FullRelease, no maintenance 5/5, and no release eligibility.

## What the latest proof actually showed

Run: `e2e-exact-candidate-proof-1-20260904T184913Z`

Last journal event:
- event: `MEANINGFUL_PROGRESS`
- observed UTC: `2026-09-04T19:52:06.9156183Z`
- last meaningful progress UTC: `2026-09-04T19:52:06.9827699Z`
- no-progress deadline UTC: `2026-09-04T20:22:06.9827699Z`
- absolute lifecycle deadline UTC: `2026-09-05T03:34:26.7790999Z`

The active guest bootstrap `multipass.exe` began at approximately `2026-09-04T18:59:30.0885547Z`.
At the final captured observation it had accumulated approximately **3024.8 CPU-seconds** over **3156.8 wall-seconds** (CPU/wall ratio about **0.958**), which is strong evidence of active computation rather than an idle process.

The configured guest bootstrap maximum is **6300 seconds**. The proof stopped after only about **3157 seconds** of that operation, leaving roughly **3143 seconds** of its own configured allowance unused.

That means this run does not establish a compute failure.

## The unresolved observability problem

The harness function `Test-ProductMeaningfulProgress` compares the serialized `productChildInstances` objects before it evaluates the aggregate CPU-delta threshold. Those child-instance objects include changing fields such as `cpuSeconds` and `responding`.

Therefore changing per-process CPU counters can make the whole child-instance JSON differ and immediately count as `MEANINGFUL_PROGRESS`. This can reset the no-progress deadline even when there has been no durable product-stage transition.

Separately, `bootstrap-compute.sh` is a long monolithic script containing apt, Docker, Tailscale, rootless-runtime, Node/npm, Python/pip, service and firewall work. The host observer cannot currently identify which internal Linux substage is active from the supplied proof bundle. `multipass exec` stdout/stderr are not available as incremental semantic stage evidence in the current proof package.

So two facts can simultaneously be true:

1. the child is genuinely working; and
2. the harness currently lacks enough semantic visibility to distinguish genuine progress from a CPU-burning hang.

## Deadline-policy practicality

The new policy is finite and structurally ordered, but its worst-case upper bounds are very large:

- guest bootstrap: 6300s (1.75h)
- compute stage: 9600s (2.67h)
- Desktop transaction: 30420s (8.45h)
- Laptop transaction: 41520s (11.53h)
- observer absolute: 31020s (8.62h)
- exact-proof outer watchdog: 131580s (36.55h)

These values satisfy hierarchy inequalities, but they are not operationally compatible with assuming a single ChatGPT Plus five-hour Codex session will necessarily complete two exact proofs plus maintenance and FullRelease.

External reviewers should determine whether the policy is correctly conservative or whether stage budgets were formed by summing mutually exclusive maxima and can be safely tightened without reintroducing parent preemption.

## Most important questions for reviewers

1. Is the current 6,300-second `guestBootstrap` maximum justified by the exact operations in `bootstrap-compute.sh`?
2. Does `Test-ProductMeaningfulProgress` incorrectly treat changing `productChildInstances.cpuSeconds` as semantic progress before applying `CpuDeltaThreshold`?
3. Should CPU delta be only a secondary/liveness signal with a finite maximum CPU-only-progress window?
4. Should `bootstrap-compute.sh` emit durable, non-secret substage markers that the Windows host can observe independently while `multipass exec` is running?
5. Should every long Linux operation have a bounded child timeout and explicit progress marker so the true blocker is identifiable?
6. Can the current candidate be kept if only harness progress classification changes? If shipping Linux bootstrap instrumentation is required, identify exactly why rebuild/re-sign is required.
7. Is the derived deadline policy materially over-conservative, and if so what source-backed finite values/invariants should replace it?
8. After the above, what is the minimum safe sequence to obtain current Proof #1, Proof #2, maintenance/sentinels, FullRelease, RECONCILE and release eligibility?

## Current recommendation

Do not blindly increase timeouts again.

Do not classify compute as failed from this proof.

Do not rerun a multi-hour certification unchanged until the progress semantics/observability are independently reviewed.

The likely permanent improvement is to make guest bootstrap progress **semantic and observable** (durable substage markers / bounded sub-operations) and make the harness distinguish semantic stage progress from raw CPU activity. Whether that requires a shipping rebuild depends on the chosen implementation.
