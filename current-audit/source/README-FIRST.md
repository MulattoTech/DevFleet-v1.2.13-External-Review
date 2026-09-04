# DevFleet Safe Remote Development v1.2.13

DevFleet turns an installed Windows host into isolated primary compute and a separately configured Windows host into the optional client, failover compute, and append-only vault host. It preserves the v1.0.0 three-VM recovery architecture while adding configurable development profiles, rootless/rootful Docker modes, reusable caches, language-aware templates, first-class CodexPro status/bootstrap, nonblocking dashboard operations, ownership leases, Ollama profiles, and a friendly `CodexDevVM` SSH alias. The internal Multipass instance remains `devfleet-primary`.

## Clean install

1. Review `docs/00-HARD-STOPS-AND-ASSUMPTIONS.md` and `config/devfleet.config.json`.
2. On the configured Surrogate host run `START-HERE-LAPTOP.cmd` as Administrator.
3. Transfer the encrypted pairing bundle and run `START-HERE-DESKTOP.cmd` on the configured Primary host.
4. Return the encrypted desktop pairing bundle and run `windows\Complete-Cluster.ps1` on the laptop.
5. `Complete-Cluster.ps1` configures SSH and core VS Code support automatically; optionally run the client scripts again for additional language extension groups or a Docker-over-SSH context.
6. Configure/test Windows Ollama with `windows\Configure-Ollama.ps1` and `windows\Test-Ollama.ps1`.
7. Run the health shortcut and a disposable create/start/test/backup/quarantine/restore exercise.

A clean installation defaults to Balanced, rootful Docker inside CodexDevVM, and rootless Docker on failover. The desktop installer requires the exact `ENABLE ROOTFUL CODEXDEVVM` acknowledgement before enabling rootful mode. Windows host folders remain unavailable to all VMs and containers.

## Upgrade v1.0.0

```powershell
pwsh -File .\Upgrade-DevFleet.ps1 -FromVersion 1.0.0 -PreviewOnly
pwsh -File .\Upgrade-DevFleet.ps1 -FromVersion 1.0.0
```

The upgrade backs up installed state and creates stopped-state Multipass snapshots before service changes. A baseline v1.0 deployment remains Strict/rootless until you explicitly change profile or Docker store.

## CodexPro

The project hook is an idempotent adapter using only capabilities verified in the connected CodexPro interface. It validates the active root, creates `.ai-bridge/local-agent` runtime folders, checks loopback health, invokes the verified `codexpro start` command when installed, and writes actionable logs. Private installation sources and connector authorization are never embedded. A documented multi-workspace registration command was not exposed, so DevFleet does not invent one.

## Safety invariants

All profiles retain the Windows-host filesystem boundary, project-root/path/symlink validation, no unauthenticated Docker TCP, no ordinary application access to `docker.sock`, append-only compute backup credentials, separate vault-admin retention authority, backup-before-quarantine, reversible quarantine, one writable owner per project identity, explicit split-brain acknowledgement, offline encrypted vault export, and GitHub as off-device committed history.

## Audit reports

- `DevFleet-v1.1.0-VALIDATION.md` and `DevFleet-v1.1.0-FILE-CHANGES.md` are historical records only.
- Current v1.2.13 release identity, hashes, and audit state are generated from `VERSION`, `INSTALLER_VERSION`, and the universal AI Audit bundle.
