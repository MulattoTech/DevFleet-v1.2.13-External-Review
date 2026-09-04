# Exact installation order

Extract the package into a local folder on both computers. Keep the same package version on each computer.

## Phase A — laptop first

Double-click:

```text
START-HERE-LAPTOP.cmd
```

Or run manually from an elevated PowerShell 7 window:

```powershell
pwsh -File .\Install-DevFleet.ps1 -Role Laptop
```

The laptop phase:

1. checks virtualization, disk, RAM, CPU, Windows edition, and emulator conflicts;
2. installs/updates PowerShell, Git, VS Code, Tailscale, 7-Zip, GitHub CLI, OpenSSH Client, Multipass, and Hyper-V or VirtualBox;
3. disables Multipass host mounts;
4. connects the Windows host to Tailscale;
5. creates `devfleet-failover` and `devfleet-vault`;
6. installs rootless Docker and the failover dashboard;
7. installs the append-only vault service;
8. connects both VMs to Tailscale;
9. initializes encrypted 15-minute backups;
10. creates shortcuts;
11. writes an encrypted `devfleet-laptop-bootstrap-*.dfe` bundle under `C:\ProgramData\DevFleet\exports`.

If Windows requests a reboot, reboot and double-click the same file again. Existing completed resources are reused; the installer refuses automatic VM destruction.

Copy the generated encrypted bundle to the desktop. Keep its passphrase.

## Phase B — desktop

Double-click:

```text
START-HERE-DESKTOP.cmd
```

Enter the laptop bootstrap bundle path when prompted. Manual equivalent:

```powershell
pwsh -File .\Install-DevFleet.ps1 -Role Desktop `
  -BundlePath "X:\Path\devfleet-laptop-bootstrap-YYYYMMDD-HHMMSS.dfe"
```

The desktop phase creates the primary VM, imports vault access, pairs primary-to-failover control, and outputs `devfleet-desktop-pairing-*.dfe` under `C:\ProgramData\DevFleet\exports`.

Copy that pairing bundle back to the laptop.

## Phase C — finish two-way pairing on laptop

Open PowerShell 7 as Administrator in the extracted package folder:

```powershell
pwsh -File .\windows\Complete-Cluster.ps1 `
  -DesktopPairingBundlePath "X:\Path\devfleet-desktop-pairing-YYYYMMDD-HHMMSS.dfe"
```

## Phase D — GitHub authentication

Run the command only on the physical computer that locally owns each VM:

```powershell
# Desktop
pwsh -File .\windows\Configure-GitHub.ps1 -InstanceName devfleet-primary

# Laptop
pwsh -File .\windows\Configure-GitHub.ps1 -InstanceName devfleet-failover
```

Approve the browser/device flow.

## Phase E — validate before real work

```powershell
pwsh -File .\windows\Test-DevFleet.ps1 -AllLocalInstances
pwsh -File .\tools\Verify-Package.ps1
```

Then:

1. use **DevFleet – Show Credentials**;
2. open **DevFleet – Open Dashboard**;
3. create a `generic` project named `devfleet-smoke-test`;
4. start it and confirm the analyzer has no blockers;
5. wait at least 15 minutes and confirm a backup timestamp appears;
6. quarantine and restore the test project;
7. stop/delete the test project only after confirming recovery works.

## v1.1.0 client completion

After pairing, `Complete-Cluster.ps1` configures the SSH aliases and core VS Code extensions. Re-run `client\Configure-VSCode.ps1` for optional language groups, optionally run `client\Configure-DockerContext.ps1`, then configure/test Ollama on MulattoTechBox. The clean desktop install requires an explicit rootful-Docker acknowledgement; a v1.0 upgrade stays rootless. For upgrades, use `Upgrade-DevFleet.ps1` rather than the clean installer.
