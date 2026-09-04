[CmdletBinding()]
param([Parameter(Mandatory)][string]$InstanceName)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
$config=Get-DevFleetConfig;$mp=Get-MultipassExe
Invoke-External $mp @('exec',$InstanceName,'--','sudo','-u','devrunner','git','config','--global','user.name',[string]$config.Git.UserName)
Invoke-External $mp @('exec',$InstanceName,'--','sudo','-u','devrunner','git','config','--global','user.email',[string]$config.Git.Email)
Write-Host 'Complete the GitHub browser/device authentication below.' -ForegroundColor Yellow
& $mp exec $InstanceName -- sudo -iu devrunner gh auth login --web --git-protocol ssh
