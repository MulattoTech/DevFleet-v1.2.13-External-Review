[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Laptop','Desktop')]
    [string]$Role,
    [string]$BootstrapBundlePath,
    [string]$PackageRoot,
    [ValidateSet('Connected')]
    [string]$InstallationMode = 'Connected',
    [switch]$NonInteractive,
    [switch]$SkipWindowsUpdates,
    [switch]$ForceReprovision,
  [switch]$DeferNetworkPairing,
  [switch]$AcknowledgeRootfulDocker,
  [string]$TransactionDeadlineUtc,
  [string]$DeadlinePolicyVersion = '1.0.0'
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$packageRoot = if ($PackageRoot) { (Resolve-Path -LiteralPath $PackageRoot).Path } else { $here }
if (-not (Test-Path -LiteralPath (Join-Path $packageRoot 'windows\00-Preflight.ps1'))) { throw "Package root is not a valid DevFleet package: $packageRoot" }
Import-Module (Join-Path $here 'windows\DevFleet.Common.psm1') -Force
if($DeadlinePolicyVersion -ne '1.0.0'){throw "Unsupported deadline policy version: $DeadlinePolicyVersion"}
$transactionDeadline = if($TransactionDeadlineUtc){try{[datetime]::Parse($TransactionDeadlineUtc).ToUniversalTime()}catch{throw 'Transaction deadline is not a valid UTC timestamp.'}}else{[datetime]::UtcNow.AddSeconds((Get-DevFleetTransactionBudgetSeconds $Role))}
Set-DevFleetDeadlineContext -TransactionDeadlineUtc $transactionDeadline -StageName 'preflight' -StageBudgetSeconds (Get-DevFleetStageBudgetSeconds 'preflight') | Out-Null
Assert-PowerShell7
Assert-Administrator
Initialize-DevFleetState -PackageRoot $here
# Establish the host-secret record before any durable deployment identity is
# created. A prerequisite 3010 boundary must resume with credentials intact.
Get-OrCreateSecrets | Out-Null

Write-Host "`n=== DevFleet installation: $Role ===" -ForegroundColor Cyan
& (Join-Path $here 'windows\00-Preflight.ps1') -Role $Role -InstallationMode $InstallationMode
if(-not (Test-StageMarker "prereqs-$Role")){ Set-DevFleetDeadlineContext -TransactionDeadlineUtc $transactionDeadline -StageName 'prerequisites' -StageBudgetSeconds (Get-DevFleetStageBudgetSeconds 'prerequisites') | Out-Null; & (Join-Path $here 'windows\01-Install-Prerequisites.ps1') -Role $Role -OfflinePackageRoot $packageRoot -InstallationMode $InstallationMode -SkipWindowsUpdates:$SkipWindowsUpdates }

if (Test-PendingReboot) {
    Write-Warning 'Windows requires a reboot before VM provisioning. Re-run this same command after reboot; completed stages will be detected.'
    exit 3010
}

# Do not create durable deployment identity before the prerequisite stage has
# crossed its reboot boundary.
$nodeIdentity = Get-OrCreateNodeIdentity -Role $Role

if (-not $DeferNetworkPairing -and -not (Test-StageMarker 'windows-tailscale')) { Set-DevFleetDeadlineContext -TransactionDeadlineUtc $transactionDeadline -StageName 'windowsTailscale' -StageBudgetSeconds (Get-DevFleetStageBudgetSeconds 'windowsTailscale') | Out-Null; & (Join-Path $here 'windows\04a-Connect-WindowsTailscale.ps1'); Write-StageMarker 'windows-tailscale' } elseif ($DeferNetworkPairing) { Write-Warning 'Windows Tailscale pairing was deliberately deferred; complete it from Maintenance.' }
if(-not (Test-StageMarker 'host-agent')){ Set-DevFleetDeadlineContext -TransactionDeadlineUtc $transactionDeadline -StageName 'hostAgent' -StageBudgetSeconds (Get-DevFleetStageBudgetSeconds 'hostAgent') | Out-Null; & (Join-Path $here 'windows\Install-DevFleet-HostAgent.ps1'); Write-StageMarker 'host-agent' }

if ($Role -eq 'Desktop') {
    $installedConfig = Get-DevFleetConfig
if ($AcknowledgeRootfulDocker -and [string]$installedConfig.Docker.PrimaryMode -eq 'rootful') { $installedConfig.Docker.RootfulModeAcknowledged = $true; Save-DevFleetConfig -Config $installedConfig }
if ([string]$installedConfig.Docker.PrimaryMode -eq 'rootful' -and -not [bool]$installedConfig.Docker.RootfulModeAcknowledged) {
        if ($NonInteractive) { throw 'NonInteractive installation cannot acknowledge rootful Docker; configure rootless mode or provide an explicit reviewed configuration.' }
        $phrase = Read-Host 'CodexDevVM is an isolated VM, but rootful Docker has broader VM-level authority. Type ENABLE ROOTFUL CODEXDEVVM to continue'
        if ($phrase -ne 'ENABLE ROOTFUL CODEXDEVVM') { throw 'Rootful Docker acknowledgement did not match. Set Docker.PrimaryMode to rootless or rerun and acknowledge it.' }
        $installedConfig.Docker.RootfulModeAcknowledged = $true
        Save-DevFleetConfig -Config $installedConfig
    }
}

if ($Role -eq 'Laptop') {
    if(-not (Test-StageMarker 'compute-devfleet-failover')){ Set-DevFleetDeadlineContext -TransactionDeadlineUtc $transactionDeadline -StageName 'compute' -StageBudgetSeconds (Get-DevFleetStageBudgetSeconds 'compute') | Out-Null; & (Join-Path $here 'windows\02-Provision-ComputeNode.ps1') -NodeRole Failover -ForceReprovision:$ForceReprovision }
    if(-not (Test-StageMarker 'vault')){ Set-DevFleetDeadlineContext -TransactionDeadlineUtc $transactionDeadline -StageName 'vault' -StageBudgetSeconds (Get-DevFleetStageBudgetSeconds 'vault') | Out-Null; & (Join-Path $here 'windows\03-Provision-Vault.ps1') -ForceReprovision:$ForceReprovision }
    if (-not $DeferNetworkPairing) { Set-DevFleetDeadlineContext -TransactionDeadlineUtc $transactionDeadline -StageName 'tailscale' -StageBudgetSeconds (Get-DevFleetStageBudgetSeconds 'tailscale') | Out-Null; & (Join-Path $here 'windows\04-Connect-Tailscale.ps1') -InstanceName (Get-DevFleetConfig).Failover.InstanceName; & (Join-Path $here 'windows\04-Connect-Tailscale.ps1') -InstanceName (Get-DevFleetConfig).Vault.InstanceName }
    Set-DevFleetDeadlineContext -TransactionDeadlineUtc $transactionDeadline -StageName 'vaultClient' -StageBudgetSeconds (Get-DevFleetStageBudgetSeconds 'vaultClient') | Out-Null; & (Join-Path $here 'windows\05-Configure-LocalVaultClient.ps1') -InstanceName (Get-DevFleetConfig).Failover.InstanceName
    Set-DevFleetDeadlineContext -TransactionDeadlineUtc $transactionDeadline -StageName 'shortcuts' -StageBudgetSeconds (Get-DevFleetStageBudgetSeconds 'shortcuts') | Out-Null; & (Join-Path $here 'windows\08-Install-Shortcuts.ps1') -LocalInstanceName (Get-DevFleetConfig).Failover.InstanceName
    $sevenzip = @((Get-CanonicalDependencyManifest -PackageRoot $packageRoot).dependencies) | Where-Object id -eq 'sevenzip' | Select-Object -First 1
    if ($sevenzip -and (Get-DependencyStatus -Dependency $sevenzip).Status -eq 'Compatible') {
        Set-DevFleetDeadlineContext -TransactionDeadlineUtc $transactionDeadline -StageName 'export' -StageBudgetSeconds (Get-DevFleetStageBudgetSeconds 'export') | Out-Null; & (Join-Path $here 'windows\09-Export-Laptop-Bootstrap.ps1')
    } else {
        Write-Warning '7-Zip is not available; encrypted laptop bootstrap export is unavailable, but core Laptop installation remains complete.'
    }
    Write-Host "`nLaptop stage complete. Copy the encrypted bootstrap bundle shown above to the desktop." -ForegroundColor Green
} else {
    if(-not (Test-StageMarker 'compute-devfleet-primary')){ Set-DevFleetDeadlineContext -TransactionDeadlineUtc $transactionDeadline -StageName 'compute' -StageBudgetSeconds (Get-DevFleetStageBudgetSeconds 'compute') | Out-Null; & (Join-Path $here 'windows\02-Provision-ComputeNode.ps1') -NodeRole Primary -ForceReprovision:$ForceReprovision }
    if (-not $DeferNetworkPairing) { Set-DevFleetDeadlineContext -TransactionDeadlineUtc $transactionDeadline -StageName 'tailscale' -StageBudgetSeconds (Get-DevFleetStageBudgetSeconds 'tailscale') | Out-Null; & (Join-Path $here 'windows\04-Connect-Tailscale.ps1') -InstanceName (Get-DevFleetConfig).Primary.InstanceName }
    if ($BootstrapBundlePath) {
        & (Join-Path $here 'windows\06-Import-Laptop-Bootstrap.ps1') -BundlePath $BootstrapBundlePath
    } else {
        Write-Warning 'No laptop bootstrap bundle was supplied. The primary works locally, but backups and peer control are not configured yet.'
    }
    Set-DevFleetDeadlineContext -TransactionDeadlineUtc $transactionDeadline -StageName 'shortcuts' -StageBudgetSeconds (Get-DevFleetStageBudgetSeconds 'shortcuts') | Out-Null; & (Join-Path $here 'windows\08-Install-Shortcuts.ps1') -LocalInstanceName (Get-DevFleetConfig).Primary.InstanceName
    $sevenzip = @((Get-CanonicalDependencyManifest -PackageRoot $packageRoot).dependencies) | Where-Object id -eq 'sevenzip' | Select-Object -First 1
    if ($sevenzip -and (Get-DependencyStatus -Dependency $sevenzip).Status -eq 'Compatible') {
        Set-DevFleetDeadlineContext -TransactionDeadlineUtc $transactionDeadline -StageName 'export' -StageBudgetSeconds (Get-DevFleetStageBudgetSeconds 'export') | Out-Null; & (Join-Path $here 'windows\10-Export-Desktop-Pairing.ps1') -NonInteractive:$NonInteractive
    } else {
        Write-Warning '7-Zip is not available; encrypted desktop pairing export is unavailable, but core Desktop installation remains complete.'
    }
    Write-Host "`nDesktop stage complete. Copy the desktop pairing bundle back to the laptop and run Complete-Cluster.ps1." -ForegroundColor Green
}

# A servicing signal can appear asynchronously while Host Agent or nested
# compute provisioning is running. Surface it before final verification so the
# lifecycle persists a new bounded reboot generation instead of committing
# install-state over an outstanding Windows reboot obligation.
if (Test-PendingReboot) {
    Write-Warning 'Windows reported a new reboot requirement after provisioning. Re-run this same transaction after reboot; completed stages will be detected.'
    exit 3010
}

Set-DevFleetDeadlineContext -TransactionDeadlineUtc $transactionDeadline -StageName 'verification' -StageBudgetSeconds (Get-DevFleetStageBudgetSeconds 'verification') | Out-Null
& (Join-Path $here 'windows\Test-DevFleet.ps1') -AllLocalInstances
