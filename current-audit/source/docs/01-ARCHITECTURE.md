# Architecture

```text
Laptop Windows — trusted recovery side
├─ Tailscale client + VS Code
├─ devfleet-failover Ubuntu VM
│  ├─ rootless Docker by default
│  ├─ project containers
│  └─ DevFleet dashboard/API
├─ devfleet-vault Ubuntu VM
│  ├─ no Docker
│  ├─ append-only rest-server
│  └─ client-side encrypted restic repository
└─ optional encrypted offline vault exports

Desktop Windows — heavy disposable compute
├─ Tailscale client + VS Code
├─ Ollama / RX 7900 XTX service remains on Windows
└─ devfleet-primary Ubuntu VM (friendly name: CodexDevVM)
   ├─ selectable Docker mode (rootful on a clean Balanced install)
   ├─ project containers
   └─ DevFleet dashboard/API

GitHub
└─ off-device committed history
```

## Isolation layers

1. Windows files are outside the VMs.
2. Multipass host-directory mounting is disabled globally with `local.privileged-mounts=false`.
3. Docker runs inside each disposable compute VM. Strict mode requires rootless Docker; Balanced/Fast may select rootful Docker on CodexDevVM without exposing Docker TCP or mounting Windows files.
4. A project may bind only relative paths within its own project directory. Absolute, parent-directory, Windows, UNC, and Docker-socket mounts are blocked before startup.
5. CodexPro hooks run inside project containers, not on the VM control plane.
6. Compute nodes receive append-only vault credentials. Vault pruning requires a separate laptop-admin action.

## Dashboard redundancy

The two dashboards are stateless peers. Either one can display/control its local node and proxy safe project actions to the other over a random API token on Tailscale.

The dashboards are deliberately **not** a shared multi-writer database and do not automatically promote a project. Projects are recovered to the other node from restic or GitHub. Peer-unreachable and peer-running states require explicit override before start.

## What the dashboard cannot do

- start a Windows VM that is currently stopped—the desktop shortcut performs that job;
- delete or purge a Multipass VM;
- access the vault filesystem directly;
- prune/forget vault snapshots;
- permanently delete quarantined projects;
- mount or browse Windows drives.

Keeping these powers out of the web service is part of the security design, not an unfinished feature.

## v1.1.0 control plane

`devfleet-primary` is displayed as `CodexDevVM`; it is not renamed. Both compute VMs run the same authenticated FastAPI dashboard. The VM-level controller can use the selected Docker socket, while application containers cannot. The laptop remains the primary UI and hosts failover plus the Docker-free append-only vault.
