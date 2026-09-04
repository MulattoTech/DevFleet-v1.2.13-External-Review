# Security model

## Project-container restrictions

Startup is blocked for:

- privileged containers;
- host networking;
- `ALL` or `SYS_ADMIN` capabilities;
- Docker socket mounts;
- absolute Linux host paths;
- Windows drive-letter or UNC paths;
- `../` parent/sibling workspace bind mounts;
- published ports that do not bind to VM loopback (`127.0.0.1` or `::1`);
- device passthrough, `volumes_from`, host namespaces, or unconfined security profiles;
- invalid Compose/devcontainer configuration.

Only project-relative bind paths and named Docker volumes are accepted by the analyzer. Generated templates also drop all capabilities and set `no-new-privileges:true`.

## Rootless control plane

Docker runs as `devrunner` inside each compute VM. Rootful Docker services are disabled. The dashboard can control the rootless daemon and VM project folders, but cannot see Windows files because none are mounted.

The dashboard's repair button runs an unprivileged user-service repair. Root/VM/package repair remains a separate Windows administrator shortcut that takes a Multipass snapshot first.

## Network and web security

- Windows hosts and all VMs connect to Tailscale.
- UFW denies inbound traffic except SSH/dashboard/vault ports on `tailscale0`.
- VS Code uses ordinary OpenSSH keys over the encrypted Tailscale network; Tailscale SSH interception is not required.
- The dashboard uses random HTTP Basic credentials and same-origin POST checks.
- Peer APIs use separate random tokens.
- Security headers disable framing and restrict content/form origins.
- Docker TCP is never exposed.

The dashboard is HTTP rather than public TLS because traffic is restricted to the encrypted tailnet. Do not expose its port through router forwarding, Funnel, Serve, public reverse proxies, or a LAN-wide firewall rule.

## Backup security

Restic encrypts before upload. The vault server is append-only and uses private per-user repository paths. Compute-node credentials can read/add snapshots but cannot prune or delete prior snapshots through the REST interface. Vault-admin retention credentials never leave the vault VM.

## Remaining risks

- Windows administrator activity or administrator-level ransomware can delete Multipass VM files.
- Laptop disk failure can destroy the online vault unless an offline export exists.
- Compromised Tailscale, GitHub, or Windows accounts can expose access.
- Malicious code can exfiltrate data present inside its own project/container.
- Explicit failover override can create divergent writers.
- A software defect in Multipass, Docker, the Linux kernel, or this package could weaken isolation.

This is defense in depth and recovery-oriented isolation, not a mathematical guarantee.

## v1.1.0 profile invariant

Balanced is a practical development profile inside an already disposable VM, not a removal of host-file or vault boundaries. Fast Trusted can relax VM-internal container hardening only after explicit acknowledgement. No profile enables Windows mounts, Docker 2375, public dashboard exposure, ordinary docker.sock mounts, vault-admin credentials, sibling-workspace access, or deletion outside approved roots.
