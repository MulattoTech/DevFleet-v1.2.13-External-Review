[CmdletBinding()]
param(
    [string]$OwnershipPath = 'C:\ProgramData\DevFleetHostAgent\integration-ownership.json',
    [Parameter(Mandatory)][string]$ExpectedGeneration
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet-WindowsIntegrationOwnership.psm1') -Force
$canonicalOwnershipPath = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'DevFleetHostAgent\integration-ownership.json'))
if (-not [IO.Path]::GetFullPath($OwnershipPath).Equals($canonicalOwnershipPath,[StringComparison]::OrdinalIgnoreCase)) { throw 'Windows integration ownership ledger path is not canonical; all resources preserved.' }
$ledger = Read-DevFleetIntegrationOwnership -Path $OwnershipPath
if ([string]$ledger.InstallationGeneration -ne $ExpectedGeneration) { throw 'Windows integration ownership generation changed; foreign resources preserved.' }

foreach ($binding in @($ledger.ScheduledTasks)) {
    $task = Get-ScheduledTask -TaskName ([string]$binding.Name) -ErrorAction SilentlyContinue
    if (-not $task) { continue }
    if (@($task.Actions).Count -ne 1) { throw 'WINDOWS INTEGRATION OWNERSHIP CONFLICT: scheduled task action count changed. Foreign resource preserved.' }
    $actual = @{
        Name=[string]$task.TaskName; Executable=[string]$task.Actions[0].Execute; Arguments=[string]$task.Actions[0].Arguments
        Principal=[string]$task.Principal.UserId; LogonType=[string]$task.Principal.LogonType; RunLevel=[string]$task.Principal.RunLevel
        Description=[string]$task.Description; Generation=[string]$binding.Generation
    }
    Assert-DevFleetTaskBinding -Expected $binding -Actual $actual | Out-Null
    Stop-ScheduledTask -TaskName ([string]$binding.Name) -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName ([string]$binding.Name) -Confirm:$false
}

foreach ($binding in @($ledger.FirewallRules)) {
    $rules = @(Get-NetFirewallRule -Name ([string]$binding.Name) -ErrorAction SilentlyContinue)
    if ($rules.Count -eq 0) { continue }
    if ($rules.Count -ne 1) { throw 'WINDOWS INTEGRATION OWNERSHIP CONFLICT: firewall identity is ambiguous. Foreign resources preserved.' }
    $rule = $rules[0]; $port = $rule | Get-NetFirewallPortFilter; $address = $rule | Get-NetFirewallAddressFilter; $interface = $rule | Get-NetFirewallInterfaceFilter
    $actual = @{
        Name=[string]$rule.Name; DisplayName=[string]$rule.DisplayName; Group=[string]$rule.Group; Description=[string]$rule.Description
        Direction=[string]$rule.Direction; Action=[string]$rule.Action; Protocol=[string]$port.Protocol; LocalPort=[string]$port.LocalPort; Profile=[string]$rule.Profile
        InterfaceAlias=[string]$interface.InterfaceAlias; RemoteAddress=[string]$address.RemoteAddress; Generation=[string]$binding.Generation
    }
    Assert-DevFleetFirewallBinding -Expected $binding -Actual $actual | Out-Null
    $rule | Remove-NetFirewallRule -Confirm:$false
}

foreach ($binding in @($ledger.Services)) {
    $escapedServiceName = ([string]$binding.Name).Replace('"','""')
    $serviceFilter = "Name=`"$escapedServiceName`""
    $service = Get-CimInstance Win32_Service -Filter $serviceFilter -ErrorAction SilentlyContinue
    if (-not $service) { continue }
    $actual = @{Name=[string]$service.Name;ImagePath=[string]$service.PathName;Account=[string]$service.StartName;StartMode=[string]$service.StartMode;Generation=[string]$binding.Generation}
    Assert-DevFleetServiceBinding -Expected $binding -Actual $actual | Out-Null
    Stop-Service -Name ([string]$binding.Name) -ErrorAction SilentlyContinue
    & (Join-Path $env:SystemRoot 'System32\sc.exe') delete ([string]$binding.Name) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Owned service deletion failed: $($binding.Name)" }
}

foreach ($binding in @($ledger.ScheduledTasks)) { if (Get-ScheduledTask -TaskName ([string]$binding.Name) -ErrorAction SilentlyContinue) { throw "Owned scheduled task remains after cleanup: $($binding.Name)" } }
foreach ($binding in @($ledger.FirewallRules)) { if (Get-NetFirewallRule -Name ([string]$binding.Name) -ErrorAction SilentlyContinue) { throw "Owned firewall rule remains after cleanup: $($binding.Name)" } }
foreach ($binding in @($ledger.Services)) { if (Get-Service -Name ([string]$binding.Name) -ErrorAction SilentlyContinue) { throw "Owned service remains after cleanup: $($binding.Name)" } }
