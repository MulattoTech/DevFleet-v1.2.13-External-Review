# Development profiles

**Strict** preserves v1.0-equivalent behavior for unknown repositories, third-party Compose files, security-sensitive work, and unreviewed automation. Rootless Docker is expected; tailnet ports/shared caches are disabled; missing hardening can block.

**Balanced** is the recommended normal profile. It retains Windows-host, workspace, ownership, and vault boundaries while enabling trusted orchestration, shared caches, loopback/authenticated-tailnet ports, routine operations without repeated confirmation, and analyzer caching. Missing non-root USER, no-new-privileges, healthchecks, or fully pinned development images are warnings unless combined with a boundary escape.

**Fast Trusted Development** is explicit, visible, logged, and reversible. It can use rootful Docker inside the disposable VM and declared devices/capabilities. Application containers still do not receive docker.sock automatically. Windows folders, unauthenticated Docker TCP, vault-admin credentials, public exposure, and path/deletion boundaries remain protected.

Docker mode is a node property. Run `devfleet-docker-mode-report`, stop projects, then use `sudo devfleet-switch-docker-mode rootful --acknowledge-rootful` or `rootless`. Stores are separate and never silently migrated.

## Changing Docker mode safely

Use the Windows administrator wrapper so the authoritative schema-2 configuration and the selected VM stay aligned:

```powershell
pwsh -File .\windows\Set-DevFleetDockerMode.ps1 -NodeRole Primary -Mode rootful -AcknowledgeRootful
pwsh -File .\windows\Set-DevFleetDockerMode.ps1 -NodeRole Primary -Mode rootless
```

The wrapper verifies host-mount isolation, takes a stopped-state Multipass snapshot, records both Docker stores, requires all projects to be stopped, switches services, updates configuration, and runs a health check. It never copies, prunes, or deletes images, containers, or volumes from either store.
