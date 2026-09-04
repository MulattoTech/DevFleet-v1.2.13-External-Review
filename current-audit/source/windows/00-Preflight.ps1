[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('Laptop','Desktop')][string]$Role,[ValidateSet('Offline','Connected')][string]$InstallationMode='Offline')
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
Assert-PowerShell7; Assert-Administrator
$config=Get-DevFleetConfig

Write-Host "`nPreflight for $Role on $env:COMPUTERNAME ($InstallationMode)" -ForegroundColor Cyan
$os=Get-CimInstance Win32_OperatingSystem
$cpu=Get-CimInstance Win32_Processor | Select-Object -First 1
$sys=Get-CimInstance Win32_ComputerSystem
$drive=Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':'))
$virtFirmware=$cpu.VirtualizationFirmwareEnabled
$slat=$cpu.SecondLevelAddressTranslationExtensions
$nestedHyperVOperational=$false
if (-not $slat) {
  try { Get-VMHost -ErrorAction Stop | Out-Null; $nestedHyperVOperational=$true } catch { }
}

[pscustomobject]@{
  Windows=$os.Caption
  Version=$os.Version
  CPU=$cpu.Name
  LogicalProcessors=$sys.NumberOfLogicalProcessors
  RAMGB=[math]::Round($sys.TotalPhysicalMemory/1GB,1)
  SystemDriveFreeGB=[math]::Round($drive.Free/1GB,1)
  VirtualizationFirmwareEnabled=$virtFirmware
  SLAT=$slat
  OperationalHyperVHost=$nestedHyperVOperational
} | Format-List

if (-not $virtFirmware) { throw 'Hardware virtualization is disabled in UEFI/BIOS.' }
if (-not $slat -and -not $nestedHyperVOperational) { throw 'Second Level Address Translation is required.' }
# Conservatively adapt defaults to this machine instead of overcommitting RAM/CPU.
$ramGB=[math]::Floor($sys.TotalPhysicalMemory/1GB);$logical=[int]$sys.NumberOfLogicalProcessors;$changed=$false
if($Role -eq 'Desktop'){
  $mem=[math]::Max(8,[math]::Min(32,[math]::Floor($ramGB*0.60)));$cpus=[math]::Max(2,[math]::Min(12,$logical-2))
  if($config.Primary.Memory -ne "${mem}G"){$config.Primary.Memory="${mem}G";$changed=$true}
  if([int]$config.Primary.Cpus -ne $cpus){$config.Primary.Cpus=$cpus;$changed=$true}
}else{
  $profile=$config.RoleProfiles.LaptopSurrogate
  if(-not $profile -or -not $profile.Recommended -or -not $profile.MinimumTested){throw 'Laptop/Surrogate resource policy is missing from the canonical configuration.'}
  $failMem=[int]([string]$profile.Recommended.FailoverMemory -replace '[^0-9.]','')
  $vaultMem=[int]([string]$profile.Recommended.VaultMemory -replace '[^0-9.]','')
  $minimumFailMem=[int]([string]$profile.MinimumTested.FailoverMemory -replace '[^0-9.]','')
  $minimumVaultMem=[int]([string]$profile.MinimumTested.VaultMemory -replace '[^0-9.]','')
  if($failMem -lt $minimumFailMem -or $vaultMem -lt $minimumVaultMem){throw 'Canonical Laptop/Surrogate resource policy is below the tested minimum.'}
  $failCpu=[math]::Max(2,[math]::Min(4,$logical-2));$vaultCpu=[math]::Max(1,[math]::Min(2,[math]::Floor($logical/4)))
  if($config.Failover.Memory -ne "${failMem}G"){$config.Failover.Memory="${failMem}G";$changed=$true}
  if($config.Vault.Memory -ne "${vaultMem}G"){$config.Vault.Memory="${vaultMem}G";$changed=$true}
  if([int]$config.Failover.Cpus -ne $failCpu){$config.Failover.Cpus=$failCpu;$changed=$true}
  if([int]$config.Vault.Cpus -ne $vaultCpu){$config.Vault.Cpus=$vaultCpu;$changed=$true}
}
if($changed){Save-DevFleetConfig $config;Write-Host 'VM CPU/RAM defaults were adjusted conservatively for this computer.' -ForegroundColor Yellow}
$requiredFree = if ($Role -eq 'Desktop') { 120 } else { 100 }
if (($drive.Free/1GB) -lt $requiredFree) { throw "At least $requiredFree GB free is required with current defaults. Reduce VM disk sizes in the config or free space." }

$edition=(Get-ComputerInfo -Property WindowsProductName).WindowsProductName
$hyperVCapable=$edition -match 'Pro|Enterprise|Education'
if (-not $hyperVCapable) { Write-Warning 'Hyper-V is not included in this Windows edition. Multipass will require VirtualBox.' }

$conflicts=Get-Process -Name 'MuMuPlayer','NemuHeadless','VBoxHeadless','vmware' -ErrorAction SilentlyContinue
if ($conflicts) { Write-Warning 'A virtualization/emulator process is running. Close it before installing or changing a hypervisor.' }
Write-Host 'Preflight passed.' -ForegroundColor Green
