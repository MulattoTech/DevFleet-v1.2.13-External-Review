# Ollama and RX 7900 XTX

Keep Ollama on MulattoTechBox Windows unless real testing proves a better supported path. Do not assume Hyper-V/Multipass GPU passthrough. DevFleet prefers the desktop's authenticated Tailscale address and retains `http://192.168.1.243:11434/v1` as fallback. The one authoritative endpoint lives in installed schema-2 configuration and is propagated during project generation.

Profiles: Stable Interactive (low latency, 1–2 requests), Large Context (one primary analysis task), Parallel Agents (more concurrency with smaller contexts). `Configure-Ollama.ps1` uses documented `OLLAMA_HOST`, `OLLAMA_CONTEXT_LENGTH`, `OLLAMA_NUM_PARALLEL`, `OLLAMA_MAX_LOADED_MODELS`, `OLLAMA_MAX_QUEUE`, and `OLLAMA_KEEP_ALIVE`. `Test-Ollama.ps1` checks `/v1/models`, expected model availability, optional chat completion, and `ollama ps` GPU/CPU observation when local.


`Configure-Ollama.ps1` binds Ollama to the Windows host's Tailscale IPv4 address rather than a wildcard, creates a Windows Firewall rule limited to the tailnet CIDR, and records the MagicDNS name as the preferred client endpoint when Tailscale reports one. It does not add ROCm, HIP, Vulkan, or AMD-specific variables. After changing an installed endpoint, safely refresh each compute node so its generated service configuration receives the authoritative value.
