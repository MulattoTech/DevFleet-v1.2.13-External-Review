[CmdletBinding()]
param(
    [string]$InstallRoot = 'C:\ProgramData\DevFleetHostAgent',
    [int]$Port = 8790,
    [switch]$SkipFirewall,
    [switch]$AdoptLegacyDevFleetIntegrations
)

$ErrorActionPreference = 'Stop'
$commonModule = Join-Path $PSScriptRoot 'DevFleet.Common.psm1'
$protocolModule = Join-Path $PSScriptRoot 'DevFleet-HostAgentProtocol.psm1'
$ownershipModule = Join-Path $PSScriptRoot 'DevFleet-WindowsIntegrationOwnership.psm1'
Import-Module $commonModule -Force
Import-Module $protocolModule -Force
Import-Module $ownershipModule -Force
function Write-AtomicText {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Text,[Text.Encoding]$Encoding = [Text.UTF8Encoding]::new($false))
    $tmp = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText($tmp,$Text,$Encoding)
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}
$expectedHost = $env:DEVFLEET_HOST_AGENT_EXPECTED_HOST
if ($expectedHost -and $env:COMPUTERNAME -ne $expectedHost) { throw "Host-agent fixture restriction failed. Expected: $expectedHost. Current host: $env:COMPUTERNAME" }
$multipass = Get-MultipassExe
if (-not $multipass) { throw 'Multipass was installed but could not be rediscovered from PATH, App Paths, registry, or known vendor locations.' }
$packageRoot = Split-Path -Parent $PSScriptRoot
$agentSource = Join-Path $packageRoot 'windows\DevFleet-HostAgent.ps1'
$protocolSource = Join-Path $packageRoot 'windows\DevFleet-HostAgentProtocol.psm1'
if (-not (Test-Path -LiteralPath $agentSource)) { throw "Host agent source not found: $agentSource" }
if (-not (Test-Path -LiteralPath $protocolSource)) { throw "Host agent protocol helper not found: $protocolSource" }
$vscodeHelperSource = Join-Path $packageRoot 'windows\DevFleet-VSCode.ps1'
if (-not (Test-Path -LiteralPath $vscodeHelperSource)) { throw "VS Code helper source not found: $vscodeHelperSource" }
$ownershipModuleSource = Join-Path $packageRoot 'windows\DevFleet-WindowsIntegrationOwnership.psm1'
$removalHelperSource = Join-Path $packageRoot 'windows\Remove-DevFleet-OwnedIntegrations.ps1'
if (-not (Test-Path -LiteralPath $ownershipModuleSource)) { throw "Windows integration ownership helper not found: $ownershipModuleSource" }
if (-not (Test-Path -LiteralPath $removalHelperSource)) { throw "Windows integration removal helper not found: $removalHelperSource" }

# The agent is intentionally a SYSTEM scheduled task.  Multipass 1.16.x
# authenticates each Windows client by its per-profile certificate, so make
# the already-authenticated installing user's client available to SYSTEM.
# Copy only the two client PEM files into the SYSTEM profile and lock the
# destination to SYSTEM and local Administrators.  No Multipass daemon
# restart or host-network change is required.
$userMultipassCertRoot = Join-Path $env:LOCALAPPDATA 'multipass-client-certificate'
$systemMultipassCertRoot = Join-Path $env:SystemRoot 'System32\config\systemprofile\AppData\Local\multipass-client-certificate'
if (-not (Test-Path -LiteralPath $userMultipassCertRoot)) {
    if (-not (Test-Path -LiteralPath $systemMultipassCertRoot)) { throw "Authenticated Multipass client certificate directory was not found: $userMultipassCertRoot" }
} else {
    New-Item -ItemType Directory -Path $systemMultipassCertRoot -Force | Out-Null
    Get-ChildItem -LiteralPath $userMultipassCertRoot -File -Filter '*.pem' -ErrorAction Stop | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $systemMultipassCertRoot $_.Name) -Force
    }
}
$certAcl = New-Object System.Security.AccessControl.DirectorySecurity
$certAcl.SetAccessRuleProtection($true, $false)
$certAcl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow')))
$certAcl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow')))
Set-Acl -LiteralPath $systemMultipassCertRoot -AclObject $certAcl
Get-ChildItem -LiteralPath $systemMultipassCertRoot -File -Filter '*.pem' | ForEach-Object { Set-Acl -LiteralPath $_.FullName -AclObject $certAcl }

New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
$initialAcl = Get-Acl -LiteralPath $InstallRoot
$initialAcl.SetAccessRuleProtection($true, $false)
foreach ($existingRule in @($initialAcl.Access)) { $initialAcl.RemoveAccessRuleAll($existingRule) }
$initialAcl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow')))
$initialAcl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow')))
Set-Acl -LiteralPath $InstallRoot -AclObject $initialAcl
$tokenPath = Join-Path $InstallRoot 'token.txt'
if (-not (Test-Path -LiteralPath $tokenPath)) {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    Write-AtomicText $tokenPath ([Convert]::ToBase64String($bytes)) ([Text.ASCIIEncoding]::new())
}
$token = (Get-Content -LiteralPath $tokenPath -Raw).Trim()
if ($token.Length -lt 40) { throw 'Host-agent token is unexpectedly short.' }

$agentPath = Join-Path $InstallRoot 'DevFleet-HostAgent.ps1'
$vscodeHelperPath = Join-Path $InstallRoot 'DevFleet-VSCode.ps1'
$configPath = Join-Path $InstallRoot 'config.json'
$ownershipPath = Join-Path $InstallRoot 'integration-ownership.json'
$taskName = 'DevFleet Host Agent'
$powerShellPath = ConvertTo-DevFleetCanonicalPath (Get-DevFleetPowerShell)
$taskArguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$agentPath`" -ConfigPath `"$configPath`""
$existingOwnership = Read-DevFleetIntegrationOwnership -Path $ownershipPath -AllowMissing
function Remove-PriorOwnedFirewallRules {
    param($Ownership)
    if (-not $Ownership) { return }
    foreach ($ownedRule in @($Ownership.FirewallRules)) {
        $liveRules = @(Get-NetFirewallRule -Name ([string]$ownedRule.Name) -ErrorAction SilentlyContinue)
        if ($liveRules.Count -eq 0) { continue }
        if ($liveRules.Count -ne 1) { throw "WINDOWS INTEGRATION OWNERSHIP CONFLICT: prior firewall identity '$($ownedRule.Name)' is ambiguous. All rules preserved." }
        $live = $liveRules[0]
        $portFilter = $live | Get-NetFirewallPortFilter
        $addressFilter = $live | Get-NetFirewallAddressFilter
        $interfaceFilter = $live | Get-NetFirewallInterfaceFilter
        $actual = @{Name=[string]$live.Name;DisplayName=[string]$live.DisplayName;Group=[string]$live.Group;Description=[string]$live.Description;Direction=[string]$live.Direction;Action=[string]$live.Action;Protocol=[string]$portFilter.Protocol;LocalPort=[string]$portFilter.LocalPort;InterfaceAlias=[string]$interfaceFilter.InterfaceAlias;RemoteAddress=[string]$addressFilter.RemoteAddress;Profile=[string]$live.Profile;Generation=[string]$ownedRule.Generation}
        Assert-DevFleetFirewallBinding -Expected $ownedRule -Actual $actual | Out-Null
        $live | Remove-NetFirewallRule -Confirm:$false
    }
}
$existingTask = Get-ScheduledTask -TaskName 'DevFleet Host Agent' -ErrorAction SilentlyContinue
if ($existingTask) {
    if (@($existingTask.Actions).Count -ne 1) { throw 'WINDOWS INTEGRATION OWNERSHIP CONFLICT: scheduled task has an ambiguous action set. Foreign task preserved.' }
    $ownedTask = if ($existingOwnership) { @($existingOwnership.ScheduledTasks | Where-Object { [string]$_.Name -eq $taskName }) } else { @() }
    if ($ownedTask.Count -eq 1) {
        $actualTask = @{Name=[string]$existingTask.TaskName;Executable=[string]$existingTask.Actions[0].Execute;Arguments=[string]$existingTask.Actions[0].Arguments;Principal=[string]$existingTask.Principal.UserId;LogonType=[string]$existingTask.Principal.LogonType;RunLevel=[string]$existingTask.Principal.RunLevel;Description=[string]$existingTask.Description;Generation=[string]$ownedTask[0].Generation}
        Assert-DevFleetTaskBinding -Expected $ownedTask[0] -Actual $actualTask | Out-Null
    } elseif ($AdoptLegacyDevFleetIntegrations) {
        $legacyExpected = @{Name=$taskName;Executable=$powerShellPath;Arguments=$taskArguments;Principal='SYSTEM';LogonType='ServiceAccount';RunLevel='Highest';Description=[string]$existingTask.Description;Generation='legacy-explicit-adoption'}
        $legacyActual = @{Name=[string]$existingTask.TaskName;Executable=[string]$existingTask.Actions[0].Execute;Arguments=[string]$existingTask.Actions[0].Arguments;Principal=[string]$existingTask.Principal.UserId;LogonType=[string]$existingTask.Principal.LogonType;RunLevel=[string]$existingTask.Principal.RunLevel;Description=[string]$existingTask.Description;Generation='legacy-explicit-adoption'}
        Assert-DevFleetTaskBinding -Expected $legacyExpected -Actual $legacyActual | Out-Null
    } else {
        throw 'WINDOWS INTEGRATION OWNERSHIP CONFLICT: same-name scheduled task has no owned binding. Foreign task preserved. Use -AdoptLegacyDevFleetIntegrations only after explicit legacy review.'
    }
    Stop-ScheduledTask -TaskName 'DevFleet Host Agent' -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}
Copy-Item -LiteralPath $agentSource -Destination $agentPath -Force
Copy-Item -LiteralPath $protocolSource -Destination (Join-Path $InstallRoot 'DevFleet-HostAgentProtocol.psm1') -Force
Copy-Item -LiteralPath $vscodeHelperSource -Destination $vscodeHelperPath -Force
Copy-Item -LiteralPath $ownershipModuleSource -Destination (Join-Path $InstallRoot 'DevFleet-WindowsIntegrationOwnership.psm1') -Force
Copy-Item -LiteralPath $removalHelperSource -Destination (Join-Path $InstallRoot 'Remove-DevFleet-OwnedIntegrations.ps1') -Force
$multipassVersion = (& $multipass version 2>$null | Select-Object -First 1).ToString().Trim()
$config = [ordered]@{
    SchemaVersion = 1
    HostId = $env:COMPUTERNAME.ToLowerInvariant()
    HostName = $env:COMPUTERNAME
    ListenPrefix = "http://+:$Port/"
    TokenPath = $tokenPath
    MultipassPath = $multipass
    MultipassVersion = $multipassVersion
    MultipassClientCertificateRoot = $systemMultipassCertRoot
    UbuntuImage = '24.04'
    BootTimeoutSeconds = 900
    ResourcePolicy = [ordered]@{
        PolicyVersion = '1.0.0'
        PhysicalFloorMinGb = 8
        PhysicalFloorPercent = 0.10
        CommitHeadroomFloorMinGb = 16
        CommitHeadroomPercent = 0.20
        CommitUsageLimitPercent = 80
        ReservedLogicalProcessors = 2
        ReservedHostDiskGb = 50
        MaximumVmCount = 4
        MaximumParallelProvisioning = 1
        MaxProjectCpus = 6
        MaxProjectMemoryGb = 12
        MaxProjectDiskGb = 120
    }
    SshPublicKeyPath = Join-Path $env:USERPROFILE '.ssh\devfleet_ed25519.pub'
    # Project aliases are deliberately scoped to this installing user's SSH
    # config. The SYSTEM host agent receives only this fixed path and key path,
    # never browser-provided SSH configuration text.
    SshConfigPath = Join-Path $env:USERPROFILE '.ssh\config'
    SshKnownHostsPath = Join-Path $env:USERPROFILE '.ssh\devfleet_known_hosts'
    SshPrivateKeyPath = Join-Path $env:USERPROFILE '.ssh\devfleet_ed25519'
    VsCodeSettingsPaths = @(
        (Join-Path $env:APPDATA 'Code\User\settings.json'),
        (Join-Path $env:APPDATA 'Code\User\settings.jsonc'),
        (Join-Path $env:APPDATA 'Code - Insiders\User\settings.json'),
        (Join-Path $env:APPDATA 'Code - Insiders\User\settings.jsonc')
    )
}
Write-AtomicText $configPath ($config | ConvertTo-Json -Depth 8)

$acl = Get-Acl -LiteralPath $InstallRoot
$acl.SetAccessRuleProtection($true, $false)
$acl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow')))
$acl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow')))
Set-Acl -LiteralPath $InstallRoot -AclObject $acl
Set-Acl -LiteralPath $tokenPath -AclObject $acl
Set-Acl -LiteralPath $configPath -AclObject $acl

$generation = [guid]::NewGuid().ToString('D')
$version = (Get-Content -LiteralPath (Join-Path $packageRoot 'VERSION') -Raw).Trim()
$taskDescription = "M-TechLabs DevFleet Host Agent v$version; generation=$generation"
$action = New-ScheduledTaskAction -Execute $powerShellPath -Argument $taskArguments
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $taskDescription -Force | Out-Null
$taskBinding = [ordered]@{Name=$taskName;Executable=$powerShellPath;Arguments=$taskArguments;Principal='SYSTEM';LogonType='ServiceAccount';RunLevel='Highest';Description=$taskDescription;Generation=$generation;Marker='M-TechLabs DevFleet Host Agent';Version=$version}
$firewallBindings = @()
Remove-PriorOwnedFirewallRules -Ownership $existingOwnership
if (-not $SkipFirewall) {
    $multipassAdapter = Get-NetAdapter -Name 'vEthernet (Default Switch)' -ErrorAction SilentlyContinue
    $tailscaleAdapter = Get-NetAdapter -Name 'Tailscale' -ErrorAction SilentlyContinue
    if ($multipassAdapter) {
        $multipassAddress = Get-NetIPAddress -InterfaceIndex $multipassAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -First 1
        if (-not $multipassAddress) { throw 'Multipass adapter has no usable IPv4 subnet; refusing a broad host-agent firewall rule.' }
        $multipassSubnet = "$($multipassAddress.IPAddress)/$($multipassAddress.PrefixLength)"
        $firewallBindings += [ordered]@{Name="DevFleetHostAgent-$Port-Multipass";DisplayName="DevFleet Host Agent $Port - Multipass";Group='M-TechLabs DevFleet Host Agent';Description="M-TechLabs DevFleet Host Agent v$version; generation=$generation; scope=Multipass";Direction='Inbound';Action='Allow';Protocol='TCP';LocalPort=[string]$Port;InterfaceAlias=[string]$multipassAdapter.Name;RemoteAddress=$multipassSubnet;Profile='Any';Generation=$generation;Marker='M-TechLabs DevFleet Host Agent';Version=$version}
    }
    if ($tailscaleAdapter) {
        $firewallBindings += [ordered]@{Name="DevFleetHostAgent-$Port-Tailscale";DisplayName="DevFleet Host Agent $Port - Tailscale";Group='M-TechLabs DevFleet Host Agent';Description="M-TechLabs DevFleet Host Agent v$version; generation=$generation; scope=Tailscale";Direction='Inbound';Action='Allow';Protocol='TCP';LocalPort=[string]$Port;InterfaceAlias=[string]$tailscaleAdapter.Name;RemoteAddress='100.64.0.0/10';Profile='Any';Generation=$generation;Marker='M-TechLabs DevFleet Host Agent';Version=$version}
    }
    if (-not $multipassAdapter -and -not $tailscaleAdapter) { throw 'No supported narrow host-agent interface was found; refusing a broad firewall rule.' }

    foreach ($desired in $firewallBindings) {
        $sameDisplay = @(Get-NetFirewallRule -DisplayName ([string]$desired.DisplayName) -ErrorAction SilentlyContinue)
        foreach ($live in $sameDisplay) {
            $owned = if ($existingOwnership) { @($existingOwnership.FirewallRules | Where-Object { [string]$_.Name -eq [string]$live.Name }) } else { @() }
            $portFilter = $live | Get-NetFirewallPortFilter; $addressFilter = $live | Get-NetFirewallAddressFilter; $interfaceFilter = $live | Get-NetFirewallInterfaceFilter
            $actual = @{Name=[string]$live.Name;DisplayName=[string]$live.DisplayName;Group=[string]$live.Group;Description=[string]$live.Description;Direction=[string]$live.Direction;Action=[string]$live.Action;Protocol=[string]$portFilter.Protocol;LocalPort=[string]$portFilter.LocalPort;InterfaceAlias=[string]$interfaceFilter.InterfaceAlias;RemoteAddress=[string]$addressFilter.RemoteAddress;Profile=[string]$live.Profile;Generation=if($owned.Count -eq 1){[string]$owned[0].Generation}else{'legacy-explicit-adoption'}}
            if ($owned.Count -eq 1) { Assert-DevFleetFirewallBinding -Expected $owned[0] -Actual $actual | Out-Null }
            elseif ($AdoptLegacyDevFleetIntegrations) {
                $legacyExpected = @{}
                foreach ($key in $desired.Keys) { $legacyExpected[$key] = $desired[$key] }
                $legacyExpected.Name=[string]$live.Name;$legacyExpected.Group=[string]$live.Group;$legacyExpected.Description=[string]$live.Description;$legacyExpected.Generation='legacy-explicit-adoption'
                Assert-DevFleetFirewallBinding -Expected $legacyExpected -Actual $actual | Out-Null
            } else { throw "WINDOWS INTEGRATION OWNERSHIP CONFLICT: same-name firewall rule '$($desired.DisplayName)' has no owned binding. Foreign rule preserved." }
            $live | Remove-NetFirewallRule -Confirm:$false
        }
        New-NetFirewallRule -Name ([string]$desired.Name) -DisplayName ([string]$desired.DisplayName) -Group ([string]$desired.Group) -Description ([string]$desired.Description) -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -RemoteAddress ([string]$desired.RemoteAddress) -InterfaceAlias ([string]$desired.InterfaceAlias) -Profile Any | Out-Null
    }
}
$integrationLedger = [ordered]@{SchemaVersion=1;InstallationGeneration=$generation;DevFleetVersion=$version;Marker='M-TechLabs DevFleet Host Agent';ScheduledTasks=@($taskBinding);FirewallRules=@($firewallBindings);Services=@();UpdatedUtc=(Get-Date).ToUniversalTime().ToString('o')}
Write-DevFleetIntegrationOwnership -Path $ownershipPath -Ledger $integrationLedger
Start-ScheduledTask -TaskName $taskName
$healthExpectedHost = if($expectedHost){$expectedHost}else{$env:COMPUTERNAME}
for ($i = 0; $i -lt 30; $i++) {
    try { $health = Invoke-HostAgentAuthenticatedJson -Uri "http://127.0.0.1:$Port/healthz" -Method GET -Key $token -ExpectedHost $healthExpectedHost; if ($health.ok) { $health | ConvertTo-Json -Compress; exit 0 } } catch {}
    Start-Sleep -Seconds 1
}
throw 'DevFleet host agent did not pass its local health check.'
