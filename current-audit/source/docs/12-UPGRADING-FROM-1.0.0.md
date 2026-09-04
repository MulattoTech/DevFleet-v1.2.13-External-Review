# DevFleet v1.0.0 to v1.1.0 migration

Run the preview and then the upgrade from an elevated PowerShell 7 terminal:

```powershell
pwsh -File .\Upgrade-DevFleet.ps1 -FromVersion 1.0.0 -PreviewOnly
pwsh -File .\Upgrade-DevFleet.ps1 -FromVersion 1.0.0
```

The entry point backs up `C:\ProgramData\DevFleet` configuration, secrets, exports, and package metadata; validates Multipass host-mount isolation; stops each local DevFleet VM; creates a named snapshot; restores the prior running state; previews schema 2; and refreshes only existing instances. It does not delete or recreate VMs, projects, Git repositories, Docker stores/volumes, backup credentials, restic snapshots, vault data, Tailscale identities, SSH keys, dashboard credentials, pairing data, quarantine, or custom values.

A schema-1 baseline becomes Strict/rootless first. Rootless and rootful Docker have separate stores; optional switching requires a report, stopped projects, and explicit rootful acknowledgement. Re-running the v1.1 upgrade is safe and creates another recovery set rather than resetting the selected v1.1 profile.
