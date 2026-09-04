# Clean-room installation

Supported release profile: Windows 11 Pro x64, fully patched, Internet-connected,
administrator/UAC available, and hardware virtualization available. A clean test host
must have no DevFleet, PowerShell 7, Git, Multipass, or DevFleet VMs. MULATTOTECHBOX is
only a build/reference host and is never a clean-room target.

Run the current `DevFleet-Setup-v<DevFleet VERSION>-win-x64.exe`; record preflight, dependency resolution,
UAC, reboot/resume, role, Multipass, guest bootstrap, SSH, dashboard, and maintenance
evidence. Do not treat mocked providers or source inspection as E2E evidence.
