[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
Assert-Administrator
$service=Get-Service -Name Tailscale -ErrorAction SilentlyContinue
if($service -and $service.Status -ne 'Running'){Start-Service $service}
$ts=Get-TailscaleExe
$status=Invoke-External $ts @('status','--json') -Capture -IgnoreExitCode
if($status -match '"BackendState"\s*:\s*"Running"'){
  Write-Host "Windows host $env:COMPUTERNAME is already connected to Tailscale." -ForegroundColor Green
  return
}
Write-Host "`nTailscale authentication is required for Windows host $env:COMPUTERNAME." -ForegroundColor Cyan
Write-Host 'Approve the browser/device sign-in shown by Tailscale. DNS changes are disabled for this DevFleet connection.' -ForegroundColor Yellow
Invoke-External $ts @('up','--accept-dns=false','--hostname',("{0}-devfleet-host" -f $env:COMPUTERNAME.ToLower()))
