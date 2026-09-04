# Daily use

## Start from either computer

Double-click **DevFleet – Open Dashboard**. The shortcut starts that computer's local compute VM, finds its Tailscale IP, and opens the dashboard. Use **DevFleet – Show Credentials** for the random local dashboard password.

Double-click **DevFleet – Open VS Code** to connect through standard OpenSSH over Tailscale. Select a project and run:

```text
Dev Containers: Reopen in Container
```

## Create a project

The dashboard accepts:

- a lowercase project slug;
- display name;
- generic, Python, or Node template;
- optional GitHub HTTPS/SSH repository URL;
- local or peer target node.

Each generated project has `.devcontainer`, `.devfleet`, and a hardened Compose definition. The analyzer blocks startup for privileged containers, host networking, dangerous capabilities, Docker sockets, absolute host paths, Windows/UNC paths, or `../` sibling-workspace mounts.

## Delete safely

The dashboard action is named **Quarantine**, not permanent delete. It:

1. stops the container;
2. requires a successful immediate backup;
3. moves the directory to a timestamped quarantine path;
4. leaves it available for one-click restore.

Permanent purge is separate and confirmation-protected:

```powershell
pwsh -File .\windows\Invoke-Quarantine-Maintenance.ps1 `
  -InstanceName devfleet-primary -OlderThanDays 30
```

Run the equivalent against `devfleet-failover` only after checking its backups.

## Failover

When the desktop is unavailable:

1. open the laptop dashboard;
2. restore a new copy from the vault or clone from GitHub;
3. verify the primary is truly down/not writing;
4. check **failover override**;
5. start the recovered project.

When the desktop returns, stop one writer first. Commit/push or back up the failover changes, then restore/merge on the primary. Never intentionally run the same project on both nodes.

## Updates

Ubuntu unattended security updates are enabled. Use **DevFleet – Update Safely** for reviewed host/guest updates. Multipass is excluded by default because hypervisor upgrades deserve a current backup and explicit `-IncludeMultipass` choice.

## Offline vault copy

On the laptop, periodically use **DevFleet – Export Offline Vault Copy** and choose an external drive. The export stops the REST service briefly, copies the already encrypted repository, writes a SHA-256 file, and restarts the service. Disconnect the drive afterward.

## v1.1.0 daily workflow

Open the dashboard shortcut on either computer, create a language-aware project, then use `ssh CodexDevVM` or VS Code Remote SSH. Routine start/stop/health/test/rebuild operations are nonblocking and expose operation IDs, progress, timestamps, results, and logs.
