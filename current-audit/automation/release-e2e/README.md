# DevFleet E2E Automation Harness

Version: 1.5.0
Profile: local/free, disposable-only, non-shipping release tooling

The entry point is `Invoke-DevFleetReleaseE2E.ps1`. It discovers the candidate and its
associated release artifacts, hashes them, runs the unsigned self-test before expensive
work, records a durable atomic run state, and refuses ambiguous VM ownership.

## Prerequisites

PowerShell 7, Hyper-V PowerShell, a positively identified `DevFleet-E2E-*` VM, an
appropriate clean checkpoint, and enough free host RAM for the configured fixed-memory
guest. The default preference is 20 GiB available before starting a fixed 16 GiB L1.
Production VMs are read-only observations and are never cleanup targets.

The mandatory Windows/release Python lane must set
`DEVFLEET_REQUIRE_PWSH_TESTS=1`. On general cross-platform lanes, migration tests
report `SKIP — platform prerequisite` when `pwsh` is absent; the mandatory lane
instead blocks during collection and cannot silently convert required coverage into
a skip.

Initialize the local DPAPI-bound disposable credential store once:

```powershell
.\Initialize-DevFleetE2ESecrets.ps1
```

The store is under the user's local application data, never in this workspace. A one-time
migration from an existing disposable credential file is supported with
`-CredentialFile`; the file is not copied into evidence.

## Modes

```powershell
.\Invoke-DevFleetReleaseE2E.ps1 -Mode PlanOnly -Candidate <path-to-installer>
.\Invoke-DevFleetReleaseE2E.ps1 -Mode Preflight -Candidate <path-to-installer>
.\Invoke-DevFleetReleaseE2E.ps1 -Mode Quick -Candidate <path-to-installer>
.\Invoke-DevFleetReleaseE2E.ps1 -Mode Closeout -Candidate <path-to-installer>
.\Invoke-DevFleetReleaseE2E.ps1 -Mode Resume -RunStatePath <run-state.json>
.\Invoke-DevFleetReleaseE2E.ps1 -Mode FullRelease
```

`PlanOnly` is non-mutating. `Preflight`, `Quick`, and `Closeout` are read-only/smoke
operations. `Resume` verifies candidate and recorded disposable identity before it
continues. `FullRelease` is guarded by `-ConfirmDisposableLab -ExecuteExpensive` and
executes the ordered durable phase plan from exact disposable checkpoints. It performs
host/candidate verification, clean restore, guest-session establishment, then invokes
only explicitly configured real product executors for the dependency, install,
maintenance, destructive, recovery, ownership, Vault, Tailscale, AI-bundle, and
reconciliation phases. Each executor stages and hashes the exact candidate, drives the
real product/UI or guest lifecycle for its phase, and returns structured independent
evidence. Missing or incomplete action evidence fails closed; a candidate self-test or
script exit code is never
promoted to PASS merely because a scenario group was recorded.

Tailscale supports the existing free modes: Deferred (no authentication) and
InteractiveRelease (the product's official browser flow, followed by bounded polling).
One-time auth URLs, passwords, tokens, and cookies are never placed in durable evidence.

## Evidence and cleanup

Each run is written under `audit/automation-harness/runs/<RunId>/` with artifact hashes,
host safety, run state, gate records, and a cleanup manifest. Cleanup requires exact VM
identity plus the `DevFleet-E2E-*` boundary. Unknown or production-named resources fail
closed. A passed release may power down the disposable L1; a failure can retain the
checkpoint and evidence for diagnosis.

The current development candidate uses this harness for static tests, PlanOnly, Closeout smoke,
and exact-candidate FullRelease evidence. Run:

```powershell
.\Invoke-DevFleetReleaseE2E.ps1 -Mode FullRelease
```

from a clean checkpoint to certify the full dependency, WPF, Primary, maintenance,
stopped-project, and Tailscale scenario groups.

The `LINUX` phase is a real nested path, not a WSL syntax probe. The exact
candidate TAR is hashed on the host, staged into the disposable Windows L1,
transferred into a positively owned Ubuntu 24.04 Multipass L2, and hashed again
before the candidate's `linux/bootstrap-compute.sh` is invoked. The phase verifies
systemd, the DevFleet service, the explicitly selected `devrunner` rootless Docker
socket, control-account access to that socket, container execution, local `/healthz`,
configuration ownership/modes, and OOM absence. The L2 is deleted with
`multipass delete --purge` only after its run marker is positively verified; an
unbound resource is retained and the phase fails closed.

Nested Linux resource sizing is kept in `config/devfleet-e2e.defaults.json`.
Hyper-V nested virtualization is a disposable-lab prerequisite. Multipass and the
Linux bootstrap remain product prerequisites and are exercised through the
candidate's normal installation/bootstrap path.
