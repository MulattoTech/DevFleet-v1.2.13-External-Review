# CodexPro integration

DevFleet separates **VM/container lifecycle authority** from **repository-scoped coding access**.

- The authenticated DevFleet VM controller may use the selected rootless or rootful Docker socket.
- Ordinary project containers, including CodexPro tooling inside them, are not automatically given `docker.sock`.
- New projects, sibling-container operations, failover, backup, quarantine, and restore go through DevFleet.
- Each project keeps its own allowed root, metadata, logs, runtime state, prompts, and `.ai-bridge` continuity files.

Each generated project includes:

```text
.devfleet/codexpro-bootstrap.sh
.devfleet/codexpro.env.example
.devfleet/codexpro-profile.json
.devfleet/prompts/session-bootstrap.md
.devfleet/prompts/reconnect.md
.devfleet/prompts/broken-session-recovery.md
.ai-bridge/handoff-template.md
```

## Verified live capabilities

The live CodexPro interface used while building v1.1.0 exposed:

- configuration/status inspection;
- opening one configured workspace;
- project and global skill discovery;
- bounded context, file reads, writes, and exact edits;
- controlled verification commands;
- Git status/diff review;
- handoff files and read-only session browsing.

It did **not** expose a documented multi-root registration API, a connector-authorization command, hidden ChatGPT headers, model-routing controls, quota bypasses, or a public context-cache control. DevFleet does not invent those capabilities. Its closest supported architecture is a shared VM lifecycle/status controller plus a project-local CodexPro adapter and profile.

## Idempotent bootstrap adapter

When a project starts, DevFleet executes `.devfleet/codexpro-bootstrap.sh` inside that project's running container. The adapter:

1. requires the canonical root `/workspaces/<project-slug>`;
2. creates `.devfleet/runtime` and `.ai-bridge/local-agent/logs`;
3. checks the loopback health endpoint first;
4. detects the `codexpro` executable;
5. starts it with the verified `codexpro start` interface when available;
6. writes an actionable status file and log;
7. exits successfully when already healthy or when installation/authorization is the only missing manual step.

No private credential or connector URL is embedded. The only verified environment variable placed in the example file is `CODEXPRO_TOOL_CARDS=1`. The exact private/local installation source and ChatGPT connector authorization remain manual because they are not exposed by the connected tool interface.

## Project profile

The observed workspace-scoped values are preserved as documentation, not treated as a universal installer schema:

```text
defaultRoot=/workspaces/<project-slug>
allowedRoots=[/workspaces/<project-slug>]
authEnabled=true
bashMode=full
bashTranscript=full
writeMode=workspace
toolMode=full
inheritEnv=false
contextDir=.ai-bridge
maxReadBytes=180000
maxWriteBytes=1000000
maxOutputBytes=120000
maxSearchResults=200
```

Keep `.git`, dependencies, `.env*`, private keys, `.ssh`, build outputs, models, caches, coverage, and `.ai-bridge/local-agent` excluded from broad context loading. One project must not broaden its allowed root to a sibling repository. VM-level Docker actions belong to DevFleet rather than arbitrary repository code.

## Efficient session startup

The generated session prompt directs the connected assistant to call configuration/status first, self-test only when fresh/broken/reconfigured, open without a full tree, load skills and authoritative instructions, inspect Git/context selectively, prefer diffs and changed-file manifests, and update a compact handoff before context becomes crowded. This improves practical throughput without claiming that model rate limits can be changed.
