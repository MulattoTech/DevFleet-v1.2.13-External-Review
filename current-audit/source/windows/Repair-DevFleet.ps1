[CmdletBinding()]
param([Parameter(Mandatory)][string]$InstanceName)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
$mp=Get-MultipassExe
Invoke-External $mp @('set','local.privileged-mounts=false')
Assert-MultipassIsolation -InstanceNames @($InstanceName)
# Snapshot before repair. No deletions or pruning.
$snap="pre-repair-$((Get-Date).ToString('yyyyMMdd-HHmmss'))"
New-DevFleetSnapshotSafe -InstanceName $InstanceName -SnapshotName $snap|Out-Null
Invoke-External $mp @('start',$InstanceName) -IgnoreExitCode
Invoke-External $mp @('exec',$InstanceName,'--','sudo','/usr/local/sbin/devfleet-repair')
Write-Host "Safe repair complete. Snapshot: $snap" -ForegroundColor Green
