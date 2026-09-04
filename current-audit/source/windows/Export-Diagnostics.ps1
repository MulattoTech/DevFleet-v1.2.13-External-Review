[CmdletBinding()]
param([switch]$AllLocalInstances)
$ErrorActionPreference='Continue'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
$config=Get-DevFleetConfig;$mp=Get-MultipassExe;$out=Join-Path (Get-DevFleetStateRoot) "exports\diagnostics-$((Get-Date).ToString('yyyyMMdd-HHmmss'))";New-Item -ItemType Directory $out -Force|Out-Null
Get-ComputerInfo|Out-File (Join-Path $out 'computer-info.txt')
& $mp version|Out-File (Join-Path $out 'multipass-version.txt')
& $mp list --format json|Out-File (Join-Path $out 'multipass-list.json')
$names=@($config.Primary.InstanceName,$config.Failover.InstanceName,$config.Vault.InstanceName)|Where-Object{Test-MultipassInstance $_}
foreach($name in $names){& $mp exec $name -- bash -lc 'sudo journalctl -u devfleet -n 300 --no-pager 2>/dev/null || sudo journalctl -u rest-server -n 300 --no-pager 2>/dev/null || true'|Out-File (Join-Path $out "$name.log")}
Compress-Archive -Path "$out\*" -DestinationPath "$out.zip"
Write-Host "Diagnostics: $out.zip" -ForegroundColor Green
