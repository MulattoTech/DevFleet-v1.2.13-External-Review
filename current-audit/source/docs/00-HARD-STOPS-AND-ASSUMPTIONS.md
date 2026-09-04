# Hard stops and assumptions

No unanswered design question blocked creation of this package. The installer performs preflight checks and stops before VM provisioning when a required condition is missing.

## Actual hard stops while installing

1. **Hardware virtualization must be enabled in UEFI/BIOS.**
2. **Windows Package Manager (`winget`) must work.** The included bootstrap can install PowerShell 7, but cannot repair a missing or damaged App Installer installation.
3. **Free storage:** approximately 120 GB on the desktop and 100 GB on the laptop with the default sparse VM sizes. The preflight script adjusts CPU/RAM conservatively but does not silently shrink disks.
4. **Tailscale approval:** sign in the laptop Windows host, desktop Windows host, primary VM, failover VM, and vault VM. Existing authenticated hosts are detected and skipped.
5. **Reboot:** enabling Hyper-V requires a reboot. Run the same START-HERE file again afterward.
6. **Private GitHub repositories:** browser/device authorization cannot be scripted away.
7. **Encrypted bundle passphrase:** choose at least 12 characters and keep it until both pairing transfers are complete.

## One decision to review before running

You use MuMu Player. Hyper-V can affect some Android-emulator configurations. The preflight warns when emulator/virtualization processes are running. Close MuMu before provisioning and confirm your current MuMu build works with Hyper-V before allowing a Windows edition that supports Hyper-V to enable it. On Windows Home, the package uses VirtualBox instead.

## Defaults used

- Desktop primary: up to 12 vCPU, 32 GB RAM, 220 GB sparse disk; automatically reduced for smaller hardware.
- Laptop failover: up to 4 vCPU, 8 GB RAM, 70 GB sparse disk.
- Laptop vault: up to 2 vCPU, 3 GB RAM, 160 GB sparse disk.
- Ubuntu 24.04 LTS guests.
- Ollama remains on MulattoTechBox using `oaksight-gpt-oss-20b:latest`. DevFleet prefers the configured tailnet hostname and retains `http://192.168.1.243:11434/v1` as the supported LAN fallback.
- Git identity: `Dylan Mellor <dylanmellor@gmail.com>`.
- Backups every 15 minutes.
- Quarantine review window: 30 days.
- Vault retention maintenance default: 90 days.

Edit `config/devfleet.config.json` **before the first run** to change these defaults.

## CodexPro hard limit

The package creates a project-scoped `.devfleet/codexpro-bootstrap.sh` hook, but does not contain your private CodexPro installer, credentials, or ChatGPT connector authorization. The hook executes **inside the selected project container**, which is not given the Docker socket. Exact CodexPro authentication remains an interactive/product-specific step.

## v1.1.0 additions

Clean installation defaults to Balanced/rootful on CodexDevVM and rootless on failover. Upgrade defaults remain Strict/rootless. Installation stops for missing virtualization, winget, disk capacity, reboot requirements, Tailscale/GitHub authorization, failed mount isolation, failed snapshots, or missing encrypted-bundle passphrases. CodexPro private authorization remains the only intentionally manual adapter input.
