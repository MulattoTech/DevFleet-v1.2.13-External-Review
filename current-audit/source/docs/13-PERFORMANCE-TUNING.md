# Performance tuning and practical token efficiency

DevFleet does not claim to alter ChatGPT/model quotas. It improves throughput with selective file loading, initial workspace opening without a full tree, search/read targeting, diff-oriented review, concise `.ai-bridge` handoffs, cached analyzer fingerprints, changed-file manifests, reusable dependency/BuildKit caches, one canonical checkout plus Git worktrees, and exclusions for dependencies/generated/model/cache/binary/runtime data.

Control ownership:
- ChatGPT controls the selected model, app/connector availability, memory/settings, and product usage limits.
- CodexPro controls verified roots, auth, tool/write/bash/transcript modes, output limits, blocked globs, and exposed tools.
- DevFleet controls VMs, Docker mode, lifecycle, leases, backups, analyzer, operations, peer transfer, and dashboard.
- The project controls committed instructions, `.devfleet/project.json`, Compose/Dev Container files, tests, language metadata, and `.ai-bridge` handoffs.
- Ollama controls the local endpoint, model availability, context/concurrency/queue settings, and observable GPU/CPU placement.
- Hidden headers, connector-retention flags, model-routing overrides, context-cache bypasses, and rate-limit bypasses are not fabricated.

Use the included session bootstrap/reconnect/broken-session/handoff prompts. Call `server_config` first, self-test only for fresh/broken/reconfigured sessions, open without a full tree, and verify tool reachability before long work.


The DevFleet package verifier and file-change manifest prevent repeated broad inspection of unchanged package content. Per-project analyzer fingerprints cover Compose, Dev Container, Dockerfile, environment-file, metadata, symlink, and bind-target inputs and are invalidated when those inputs change. Docker BuildKit's daemon-local cache is reused within each selected Docker store; dependency-manager caches are mounted only through trusted generated overrides and never include source repositories.
