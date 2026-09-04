# Recovery

## Quarantined project

Use the dashboard **Restore** button. The original project path is recreated without overwriting an existing folder.

## Corrupted or missing project

Use **Restore copy from vault**. DevFleet searches snapshots newest-first and restores the newest snapshot that actually contains that project into a new `PROJECT-recovered-TIMESTAMP` directory. Existing files are not overwritten.

## Primary VM destroyed

1. Re-run the desktop START-HERE installer; it creates a new primary without automatically deleting anything.
2. Supply the laptop bootstrap bundle.
3. authenticate Tailscale/GitHub;
4. restore projects from the vault or clone from GitHub;
5. re-run the desktop pairing export and laptop completion step if credentials changed.

## Failover VM destroyed

Re-run the laptop installer **without deleting `devfleet-vault`**. Reconfigure/restore projects from the existing vault.

## Vault VM damaged

Committed work remains in GitHub. Live primary/failover copies remain usable. Restore the vault from your newest offline encrypted export only after preserving the damaged VM and validating the export checksum.

## Manual retention and integrity check

Compute nodes never run `forget` or `prune`. From the laptop only:

```powershell
pwsh -File .\windows\Invoke-Vault-Maintenance.ps1
```

The script snapshots the vault VM, stops append-only service access, applies retention locally, prunes, checks the repository, and restarts the service.

## Diagnostics

```powershell
pwsh -File .\windows\Export-Diagnostics.ps1 -AllLocalInstances
```

The resulting ZIP contains host/VM status and service logs but intentionally excludes DevFleet secrets.

## v1.1.0 guided ownership transfer

When both nodes are reachable, Transfer stops the active copy, creates/verifies an append-only backup, restores a canonical copy on the peer, transfers the ownership lease by starting only the target, and reports progress. A peer-unreachable failover requires explicit split-brain acknowledgement. Read-only status/log/backup inspection remains available.
