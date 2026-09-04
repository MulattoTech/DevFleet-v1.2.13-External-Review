# Tailscale setup

The wizard exposes installed/service/authentication state, captures only an official `https://login.tailscale.com/` authentication URL, and opens it only after the user clicks the button. Passwords and reusable auth keys are never requested, logged, or persisted. Guest URLs identify the node being paired. `--defer-network-pairing` carries `DeferNetworkPairing` through both PowerShell entrypoints and leaves a deliberate Maintenance completion path.
