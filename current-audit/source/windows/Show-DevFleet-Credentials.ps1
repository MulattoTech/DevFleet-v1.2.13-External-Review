[CmdletBinding()]
param([switch]$CopyPassword)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
$secrets=Get-OrCreateSecrets
Write-Host "`nDevFleet dashboard credentials for this Windows host" -ForegroundColor Cyan
Write-Host "Username: $($secrets.PortalAdminUser)"
Write-Host "Password: $($secrets.PortalAdminPassword)"
if($CopyPassword){Set-Clipboard -Value $secrets.PortalAdminPassword;Write-Host 'Password copied to clipboard.' -ForegroundColor Yellow}
Write-Host "Stored with restricted ACLs under C:\ProgramData\DevFleet\secrets." -ForegroundColor DarkGray
Read-Host 'Press Enter to close'
