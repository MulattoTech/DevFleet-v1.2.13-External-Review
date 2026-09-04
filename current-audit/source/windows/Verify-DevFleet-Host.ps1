[CmdletBinding()]
param(
    [string]$HostAgentUrl = 'http://127.0.0.1:8790',
    [string]$TokenPath = 'C:\ProgramData\DevFleetHostAgent\token.txt'
)

$ErrorActionPreference = 'Stop'
$commonModule = Join-Path $PSScriptRoot 'DevFleet.Common.psm1'
$protocolModule = Join-Path $PSScriptRoot 'DevFleet-HostAgentProtocol.psm1'
Import-Module $commonModule -Force
Import-Module $protocolModule -Force
# Read-only verification utility. It never changes drivers, Windows features,
# networking, services, VM state, or scheduled tasks.

$driver = Get-CimInstance Win32_PnPSignedDriver -Filter "DeviceName LIKE '%AMD Radeon%'" | Select-Object -First 1 DeviceName,DriverVersion,DriverDate,Status
$multipass = try { Get-MultipassExe } catch { $null }
$vmInventory = $null
if ($multipass) {
    $vmInventory = (& $multipass list --format json 2>&1 | Out-String).Trim()
}
$agent = [ordered]@{configured=$false;status='not-configured'}
try {
    if (Test-Path -LiteralPath $TokenPath) {
        try {
            $token = (Get-Content -LiteralPath $TokenPath -Raw).Trim()
            if ($token) {
                try {
                    $health = Invoke-HostAgentAuthenticatedJson -Uri "$($HostAgentUrl.TrimEnd('/'))/healthz" -Method GET -Key $token -ExpectedHost $env:COMPUTERNAME
                    $agent = [ordered]@{configured=$true;status='healthy';health=$health}
                } catch { $agent = [ordered]@{configured=$true;status='unreachable';error=$_.Exception.Message} }
            }
        } catch { $agent = [ordered]@{configured=$true;status='token-unreadable';error='Run this read-only verification utility elevated to inspect the SYSTEM-protected token.'} }
    }
} catch { $agent = [ordered]@{configured=$true;status='token-unreadable';error='Run this read-only verification utility elevated to inspect the SYSTEM-protected token.'} }
[ordered]@{
    hostname=$env:COMPUTERNAME
    amd_driver=$driver
    multipass_present=[bool]$multipass
    vm_inventory_json=$vmInventory
    host_agent=$agent
    protected_baseline=[ordered]@{amd_adrenalin='26.3.1';display_driver='32.0.23033.1002';gpu_passthrough=$false;reboot_requested=$false}
} | ConvertTo-Json -Depth 10
