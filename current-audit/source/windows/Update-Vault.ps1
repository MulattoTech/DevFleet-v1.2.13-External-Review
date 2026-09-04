[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
Assert-PowerShell7
Assert-Administrator
$config=Get-DevFleetConfig
$name=$config.Vault.InstanceName
if(-not (Test-MultipassInstance $name)){throw 'The local DevFleet vault VM was not found.'}
Write-Host 'Refreshing the vault through the idempotent provisioner. A pre-refresh VM snapshot is taken first.' -ForegroundColor Cyan
& (Join-Path $PSScriptRoot '03-Provision-Vault.ps1')
Invoke-External (Get-MultipassExe) @('exec',$name,'--','sudo','apt-get','update')
Invoke-External (Get-MultipassExe) @('exec',$name,'--','sudo','env','DEBIAN_FRONTEND=noninteractive','apt-get','-y','upgrade')
Invoke-External (Get-MultipassExe) @('exec',$name,'--','sudo','systemctl','restart','tailscaled','rest-server')
Invoke-External (Get-MultipassExe) @('exec',$name,'--','sudo','/usr/local/sbin/devfleet-vault-health')
Write-Host 'Vault update and health check completed.' -ForegroundColor Green
