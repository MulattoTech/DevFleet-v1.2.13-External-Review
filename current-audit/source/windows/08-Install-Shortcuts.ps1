[CmdletBinding()]
param([Parameter(Mandatory)][string]$LocalInstanceName)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
$pkg=Get-PackageRootFromState;$pwsh=Get-DevFleetPowerShell
$launcher=Join-Path $pkg 'windows\Start-DevFleet.ps1'
New-DesktopShortcut -Name 'DevFleet - Open Dashboard' -Target $pwsh -Arguments "-NoProfile -ExecutionPolicy Bypass -File `"$launcher`" -InstanceName `"$LocalInstanceName`" -Mode Dashboard" -WorkingDirectory $pkg
New-DesktopShortcut -Name 'DevFleet - Open VS Code' -Target $pwsh -Arguments "-NoProfile -ExecutionPolicy Bypass -File `"$launcher`" -InstanceName `"$LocalInstanceName`" -Mode VSCode" -WorkingDirectory $pkg -IconLocation 'shell32.dll,220'
New-DesktopShortcut -Name 'DevFleet - Health Check' -Target $pwsh -Arguments "-NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $pkg 'windows\Test-DevFleet.ps1')`" -AllLocalInstances" -WorkingDirectory $pkg -IconLocation 'shell32.dll,167'
New-DesktopShortcut -Name 'DevFleet - Repair Safely' -Target $pwsh -Arguments "-NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $pkg 'windows\Repair-DevFleet.ps1')`" -InstanceName `"$LocalInstanceName`"" -WorkingDirectory $pkg -IconLocation 'shell32.dll,316'
New-DesktopShortcut -Name 'DevFleet - Update Safely' -Target $pwsh -Arguments "-NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $pkg 'windows\Update-DevFleet.ps1')`" -InstanceName `"$LocalInstanceName`"" -WorkingDirectory $pkg -IconLocation 'shell32.dll,238'

New-DesktopShortcut -Name 'DevFleet - Show Credentials' -Target $pwsh -Arguments "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $pkg 'windows\Show-DevFleet-Credentials.ps1')`"" -WorkingDirectory $pkg -IconLocation 'shell32.dll,48'
New-DesktopShortcut -Name 'DevFleet - Stop Compute Safely' -Target $pwsh -Arguments "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $pkg 'windows\Stop-DevFleet.ps1')`" -InstanceName `"$LocalInstanceName`"" -WorkingDirectory $pkg -IconLocation 'shell32.dll,28'

$config=Get-DevFleetConfig
if(Test-MultipassInstance $config.Vault.InstanceName){
  New-DesktopShortcut -Name 'DevFleet - Export Offline Vault Copy' -Target $pwsh -Arguments "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $pkg 'windows\Export-Vault-OfflineCopy.ps1')`"" -WorkingDirectory $pkg -IconLocation 'shell32.dll,167'
  New-DesktopShortcut -Name 'DevFleet - Update Vault Safely' -Target $pwsh -Arguments "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $pkg 'windows\Update-Vault.ps1')`"" -WorkingDirectory $pkg -IconLocation 'shell32.dll,238'
}
Write-Host 'Desktop shortcuts created.' -ForegroundColor Green
