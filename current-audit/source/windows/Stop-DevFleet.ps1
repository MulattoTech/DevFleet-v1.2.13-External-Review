[CmdletBinding()]
param([Parameter(Mandatory)][string]$InstanceName,[switch]$Force)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
$mp=Get-MultipassExe
if(-not (Test-MultipassInstance $InstanceName)){throw "Instance not found: $InstanceName"}
$running=Invoke-External $mp @('exec',$InstanceName,'--','sudo','-u','devrunner','bash','-lc','export DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock; docker ps --format "{{.Names}}" 2>/dev/null') -Capture -IgnoreExitCode
if($running -and -not $Force){
  throw "Running project containers were found. Stop them in the dashboard first, or rerun with -Force after verifying work is saved.`n$running"
}
Invoke-External $mp @('stop',$InstanceName)
Write-Host "$InstanceName stopped safely." -ForegroundColor Green
