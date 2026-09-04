[CmdletBinding()]
param([Parameter(Mandatory)][string]$InstanceName,[switch]$IncludeMultipass)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
$manifest=Get-CanonicalDependencyManifest -PackageRoot (Split-Path -Parent $PSScriptRoot)
$mp=Get-MultipassExe
$snap="pre-update-$((Get-Date).ToString('yyyyMMdd-HHmmss'))"
New-DevFleetSnapshotSafe -InstanceName $InstanceName -SnapshotName $snap|Out-Null
Invoke-External $mp @('start',$InstanceName) -IgnoreExitCode
$config=Get-DevFleetConfig
if($InstanceName -eq $config.Primary.InstanceName){
 & (Join-Path $PSScriptRoot '02-Provision-ComputeNode.ps1') -NodeRole Primary
}elseif($InstanceName -eq $config.Failover.InstanceName){
 & (Join-Path $PSScriptRoot '02-Provision-ComputeNode.ps1') -NodeRole Failover
}else{throw "InstanceName must be the configured primary or failover compute node: $InstanceName"}
Invoke-External $mp @('exec',$InstanceName,'--','sudo','/usr/local/sbin/devfleet-safe-update')
foreach($dependency in @($manifest.dependencies)|Where-Object { $_.wingetPackageId -and ($_.required -or $_.classification -in @('ROLE_REQUIRED','RECOMMENDED')) }){Install-WingetPackage -Id $dependency.wingetPackageId -Upgrade}
if($IncludeMultipass){
 Write-Warning 'Multipass upgrade requested. Ensure vault and project backups are current.'
 $multipass=@($manifest.dependencies)|Where-Object id -eq 'multipass'|Select-Object -First 1
 Install-WingetPackage -Id $multipass.wingetPackageId -Upgrade
}else{Write-Host 'Multipass was intentionally not auto-upgraded. Re-run with -IncludeMultipass after verifying backups.' -ForegroundColor Yellow}
Write-Host "Update complete. Snapshot: $snap" -ForegroundColor Green
