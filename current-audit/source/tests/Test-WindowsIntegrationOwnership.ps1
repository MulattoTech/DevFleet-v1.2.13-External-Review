$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'windows\DevFleet-WindowsIntegrationOwnership.psm1') -Force

function Assert-ThrowsOwnershipConflict([scriptblock]$Action) {
    try { & $Action; throw 'Expected an ownership conflict.' }
    catch { if ($_.Exception.Message -notmatch 'OWNERSHIP CONFLICT') { throw } }
}

$generation = [guid]::NewGuid().ToString('D')
$task = @{Name='DevFleet Host Agent';Executable="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe";Arguments='-NoProfile -File "C:\ProgramData\DevFleetHostAgent\DevFleet-HostAgent.ps1"';Principal='SYSTEM';LogonType='ServiceAccount';RunLevel='Highest';Description="M-TechLabs DevFleet; generation=$generation";Generation=$generation;Marker='M-TechLabs DevFleet Host Agent'}
Assert-DevFleetTaskBinding -Expected $task -Actual (@{} + $task) | Out-Null
$foreignTask = @{} + $task; $foreignTask.Executable = "$env:SystemRoot\System32\cmd.exe"
Assert-ThrowsOwnershipConflict { Assert-DevFleetTaskBinding -Expected $task -Actual $foreignTask }

$firewall = @{Name='DevFleetHostAgent-8790-Tailscale';DisplayName='DevFleet Host Agent 8790 - Tailscale';Group='M-TechLabs DevFleet Host Agent';Description="M-TechLabs DevFleet; generation=$generation";Direction='Inbound';Action='Allow';Protocol='TCP';LocalPort='8790';InterfaceAlias='Tailscale';RemoteAddress='100.64.0.0/10';Profile='Any';Generation=$generation;Marker='M-TechLabs DevFleet Host Agent'}
Assert-DevFleetFirewallBinding -Expected $firewall -Actual (@{} + $firewall) | Out-Null
$foreignFirewall = @{} + $firewall; $foreignFirewall.RemoteAddress = 'Any'
Assert-ThrowsOwnershipConflict { Assert-DevFleetFirewallBinding -Expected $firewall -Actual $foreignFirewall }

$service = @{Name='DevFleetHostAgent';ImagePath='C:\Program Files\M-TechLabs\DevFleet\agent.exe';Account='LocalSystem';StartMode='Auto';Generation=$generation;Marker='M-TechLabs DevFleet Host Agent'}
$liveService = @{} + $service; $liveService.ImagePath = '"C:\Program Files\M-TechLabs\DevFleet\agent.exe" --service'
Assert-DevFleetServiceBinding -Expected $service -Actual $liveService | Out-Null
$foreignService = @{} + $service; $foreignService.ImagePath = 'C:\Foreign\agent.exe'
Assert-ThrowsOwnershipConflict { Assert-DevFleetServiceBinding -Expected $service -Actual $foreignService }

$temporary = Join-Path ([IO.Path]::GetTempPath()) ("devfleet-integration-ownership-$([guid]::NewGuid().ToString('N')).json")
try {
    $ledger = @{SchemaVersion=1;InstallationGeneration=$generation;ScheduledTasks=@($task);FirewallRules=@($firewall);Services=@($service)}
    Write-DevFleetIntegrationOwnership -Path $temporary -Ledger $ledger
    $loaded = Read-DevFleetIntegrationOwnership -Path $temporary
    if ($loaded.InstallationGeneration -ne $generation) { throw 'Ledger generation did not round-trip.' }
    $ledger.FirewallRules[0].Generation = [guid]::NewGuid().ToString('D')
    Write-DevFleetIntegrationOwnership -Path $temporary -Ledger $ledger
    try { Read-DevFleetIntegrationOwnership -Path $temporary | Out-Null; throw 'Cross-generation ledger was accepted.' }
    catch { if ($_.Exception.Message -notmatch 'cross-generation') { throw } }
} finally { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }

'PASS Windows integration ownership binding tests'
