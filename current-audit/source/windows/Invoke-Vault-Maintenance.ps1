[CmdletBinding(SupportsShouldProcess)]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
$config=Get-DevFleetConfig;$mp=Get-MultipassExe;$name=$config.Vault.InstanceName
if($PSCmdlet.ShouldProcess($name,'Stop append-only server temporarily, apply retention locally, prune and check repository')){
 Invoke-External $mp @('snapshot',$name,'--name',"pre-maintenance-$((Get-Date).ToString('yyyyMMdd-HHmmss'))") -IgnoreExitCode
 Invoke-External $mp @('exec',$name,'--','sudo','/usr/local/sbin/devfleet-vault-maintenance',[string]$config.Backup.KeepWithin)
}
