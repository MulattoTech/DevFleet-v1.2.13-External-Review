# Solved-state contract

Do not call the remaining blocker solved until:

- the harness distinguishes durable/semantic guest-bootstrap progress from raw CPU/PID churn;
- long Linux bootstrap work has sufficient non-secret bounded observability to identify its current substage;
- every child operation remains finite and subordinate to its owning stage;
- no no-progress watchdog can be reset indefinitely by meaningless process activity;
- no legitimate long-running operation is falsely killed merely because its stage is active;
- a fresh Proof #1 is run against the exact current candidate/tooling tuple and reaches a natural PASS;
- an independent current Proof #2 reaches PASS;
- maintenance/sentinels pass;
- one coherent FullRelease passes;
- maintenance 5/5 passes;
- RECONCILE and durable CLEANUP pass;
- final L1 is OFF and final L2 is ABSENT;
- the final release-mode audit bundle validates as release eligible.
