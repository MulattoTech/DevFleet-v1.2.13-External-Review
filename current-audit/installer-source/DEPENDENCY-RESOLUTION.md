# Dependency resolution

`dependencies.json` is the single catalog consumed by WPF and PowerShell. Detection
uses PATH, App Paths, registry, and known vendor locations, then probes version and
compatibility. Only Compatible and Compatible-Newer states are preserved automatically;
Outdated is updated, Broken is repaired/reinstalled, and Unsupported-Major is blocked.

Every downloaded executable is restricted to an official vendor source and checked for
expected file type and Authenticode signer before execution. Post-install discovery and
version verification are mandatory.
