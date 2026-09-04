# Changelog

## 1.2.5

- Added safe legacy lifecycle-command resolution and preflight reporting for dedicated-VM migrations.
- Corrected stopped-source VM lifecycle preservation and identity-safe pre/post-import rollback cleanup.
- Added managed Ed25519 SSH host-key pinning with authenticated alias verification and fixed cloud-init permission typing.

## 1.2.4

- Completed safe dedicated-VM creation, project SSH alias management, and early worktree rejection.
- Added confirmed, capacity-aware environment migration with lifecycle preservation, transactional rollback, and retained previous-environment metadata.
- Added provider-aware VM backup history, inspection, staged restore with safety backup, and generated-directory archive exclusions.
- Reduced the canonical `devfleet-primary` control-plane memory allocation from 32G to 12G without changing project VM profiles or host reserve policy.

## 1.2.3

- Fixed asynchronous project-action submission, session throttling, and status-probe concurrency.
- Added transactional environment assignment verification, explicit rollback-incomplete state, workspace restore, backup history/restore, and the existing-project environment wizard.
- Added runtime-aware VS Code Remote-SSH workspace links and regenerated release identity.

## 1.2.1
- Removed synchronous infrastructure, peer, Docker, Git, analyzer, and Host Agent probes from ordinary navigation with cached stale-while-revalidate snapshots.
- Replaced browser Basic Auth challenges with a DevFleet login page, opaque session cookies, session CSRF, logout, and safe redirects while preserving token-authenticated APIs.
- Added persistent client navigation, in-page log controls, and cache-aware infrastructure refresh behavior.

## 1.2.0
- Added provider-routed project commands, verified VM workspace archives, backup-bound destruction gates, and safe VM workspace export.
- Added runtime-versus-application health semantics and normalized host capacity for the dashboard.

## 1.1.0
- Preserved every v1.0.0 path, the three-VM recovery architecture, and internal instance names.
- Added schema-2 migration with configuration backup and stopped-state Multipass snapshots.
- Added Strict, Balanced, and Fast Trusted profiles.
- Added rootless/rootful Docker selection, reports, explicit acknowledgement, stopped-state snapshots, and non-destructive switching.
- Added BuildKit and dependency-manager caches through trusted controller overrides.
- Added language policy and 20 templates, including 10 core templates.
- Replaced the CodexPro no-op with a verified project-scoped adapter and status view.
- Added auto-refreshing operation IDs/progress/logs, analyzer caching, ownership leases, guided transfer, peer controls, and preserved non-destructive repair.
- Added Windows Ollama profiles/testing and remote SSH/Docker-context/VS Code client setup.

## 1.0.0
Original safe remote-development baseline, preserved separately.
## 1.2.6

- Reconcile owned Multipass project VM IPv4 addresses after create/start/restart without reprovisioning.
- Preserve deterministic HostKeyAlias/known-host pinning while refreshing managed SSH host addresses.
- Make stopped Dedicated VM runtime/status health inspection side-effect-free.
- Add explicit running-only Open Workspace refresh semantics and portable verification documentation.
## v1.2.7 — Project UX and readiness hotfix

- Fixed project action controls after SPA navigation with one delegated submit handler and lifecycle idempotency keys.
- Added exact-port same-origin validation, transition-aware lifecycle metadata, and operation progress continuity.
- Added canonical dedicated-VM workspace readiness with managed SSH/host-key/authentication proofs.
- Gated Open workspace until readiness is verified and exposed live allocation cards, including VM PID semantics.
- Added Host Agent-owned stable/Insiders VS Code `remote.SSH.remotePlatform` reconciliation with JSONC-safe backups.
