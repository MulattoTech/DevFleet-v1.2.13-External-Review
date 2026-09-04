[CmdletBinding()]
param([switch]$AllLocalInstances,[string]$InstanceName)
$ErrorActionPreference='Continue'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
$config=Get-DevFleetConfig;$mp=Get-MultipassExe
try{Assert-MultipassIsolation -InstanceNames @($config.Primary.InstanceName,$config.Failover.InstanceName,$config.Vault.InstanceName);Write-Host 'Multipass host-mount isolation: OK' -ForegroundColor Green}catch{Write-Error $_}
$names=if($InstanceName){@($InstanceName)}elseif($AllLocalInstances){@($config.Primary.InstanceName,$config.Failover.InstanceName,$config.Vault.InstanceName)|Where-Object{Test-MultipassInstance $_}}else{@()}
foreach($name in $names){
 Write-Host "`n=== $name ===" -ForegroundColor Cyan
 Invoke-External $mp @('start',$name) -IgnoreExitCode
 $cmd=if($name -eq $config.Vault.InstanceName){'sudo /usr/local/sbin/devfleet-vault-health'}else{'sudo -u devrunner /usr/local/bin/devfleet-health'}
 & $mp exec $name -- bash -lc $cmd
}
