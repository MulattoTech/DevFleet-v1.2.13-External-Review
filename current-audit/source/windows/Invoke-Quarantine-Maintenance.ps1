[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
param([int]$OlderThanDays=30,[string]$InstanceName)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
$config=Get-DevFleetConfig;$mp=Get-MultipassExe
if(-not $InstanceName){$InstanceName=$config.Failover.InstanceName}
Write-Warning 'This is the only included permanent project-file deletion path. Verify GitHub and vault backups first.'
$phrase=Read-Host "Type PURGE QUARANTINE $InstanceName to continue"
if($phrase -ne "PURGE QUARANTINE $InstanceName"){throw 'Confirmation phrase did not match.'}
if($PSCmdlet.ShouldProcess($InstanceName,"Permanently delete quarantine entries older than $OlderThanDays days")){
 Invoke-External $mp @('exec',$InstanceName,'--','sudo','-u','devrunner','/usr/local/bin/devfleet-purge-quarantine',[string]$OlderThanDays)
}
