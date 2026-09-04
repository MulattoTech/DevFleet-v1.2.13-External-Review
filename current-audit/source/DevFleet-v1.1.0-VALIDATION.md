# DevFleet v1.2.1 validation report

## Offline validation completed

The recovered package tree passed the following checks before final archive creation; the release version is 1.2.1.

- **66 focused pytest tests** covering configuration migration, preservation, profiles, Docker-store detection/switching, analyzer policy/cache invalidation, project templates/language metadata, Git worktrees, ownership leases and interrupted transfer, operation progress, dashboard confirmation boundaries, CodexPro bootstrap states, Ollama checks, SSH/Docker-context generation, Windows-host mount prevention, traversal/symlink escapes, backup-before-quarantine, v1 project restoration, and package structure.
- Python bytecode compilation for DevFleet application, tools, and tests.
- Bash syntax checks for Linux helpers and every template hook.
- JSON and JSONC parsing.
- YAML parsing for cloud-init and generated Compose definitions.
- Jinja template parsing.
- FastAPI `/healthz` smoke test.
- All 20 project templates materialized and ran their package-level smoke hook; all 10 core templates were checked for required formatter, linter, test, bootstrap, and health metadata.
- Native sample tests executed successfully where the sandbox toolchain was available: Python, Python/FastAPI, Node.js, and Go.
- Preservation comparison against the verified v1.0.0 ZIP confirmed that no baseline file path was removed.
- Embedded SHA-256 verification and independent post-extraction archive verification are performed after the final manifests are frozen.

## PowerShell validation boundary

The package includes `tools/Verify-Package.ps1`, which uses the real PowerShell AST parser on Windows before installation. PowerShell was not installed in the offline Linux sandbox, and outbound DNS prevented downloading it, so the final sandbox pass uses the companion structural PowerShell validator. The real AST check remains a hard preflight on the target Windows machines.

## Checks requiring Dylan's actual environment

These cannot be truthfully completed offline and remain installation/preflight tests:

- Hyper-V or VirtualBox selection and firmware virtualization.
- Multipass launch, stopped-state snapshots, VM refresh, and host-mount disablement.
- Rootless/rootful Docker stores, BuildKit, Compose validation against a live daemon, and Docker-over-SSH context.
- Tailscale login, MagicDNS, ACL reachability, tailnet-only port/firewall behavior, and peer transfer.
- Append-only rest-server/restic credentials, backup/restore, vault retention authority, and encrypted offline export.
- GitHub device authorization and private-repository access.
- VS Code Remote SSH/Dev Containers against `CodexDevVM`.
- CodexPro installation/connector authorization and project bootstrap against Dylan's live service.
- Windows Ollama, RX 7900 XTX observation, expected model availability, concurrency profiles, and OpenAI-compatible `/v1` behavior.

The install and upgrade scripts stop rather than silently bypassing these checks when a required real-machine prerequisite is missing.
