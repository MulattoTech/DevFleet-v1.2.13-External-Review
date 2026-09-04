# DevFleet host-agent portability

The dashboard talks to a narrow authenticated host-agent contract rather than directly to Multipass. A second Windows host such as MulattoTechSurface only needs the same contract and a host-specific configuration file.

Required configuration values are `HostId`, `HostName`, `ListenPrefix`, `TokenPath`, `MultipassPath`, `MultipassVersion`, `UbuntuImage`, `BootTimeoutSeconds`, `SshPublicKeyPath`, and `ResourcePolicy`. The resource policy must include host reserves, `MaximumVmCount`, `MaximumParallelProvisioning`, and project CPU, memory, and disk ceilings.

Portability rules:

- Keep the host identity unique and verify it on every authenticated response.
- Discover Multipass and actual host capacity on the target; do not copy MulattoTechBox capacity values blindly.
- Keep `gpu_enabled`, `gpu`, and `gpu_passthrough` false unless a separately reviewed provider is introduced.
- Use the same deterministic project VM naming and ownership registry on every host.
- Do not migrate or recreate an existing project automatically. Reconcile first, then require an explicit transfer operation.
- Keep host-agent install, firewall scope, and scheduled-task settings in the host-specific installer; the dashboard and provider contract remain shared.

The current package intentionally does not install or configure the Surface host. This document and the provider boundary are the preparation for a later one-package patch and a separately gated host-specific install.
