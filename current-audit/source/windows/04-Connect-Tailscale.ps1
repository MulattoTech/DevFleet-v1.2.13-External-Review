[CmdletBinding()]
param([Parameter(Mandatory)][string]$InstanceName)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
$mp=Get-MultipassExe
Invoke-External $mp @('start',$InstanceName) -IgnoreExitCode
$status=Invoke-External $mp @('exec',$InstanceName,'--','bash','-lc','tailscale status --json 2>/dev/null || true') -Capture -IgnoreExitCode
if($status -match '"BackendState"\s*:\s*"Running"'){Write-Host "$InstanceName is already connected to Tailscale." -ForegroundColor Green;return}
Write-Host "`nTailscale authentication is required for $InstanceName." -ForegroundColor Cyan
Write-Host 'A login URL will appear below. Open it and approve the VM. This is an unavoidable interactive security step.' -ForegroundColor Yellow
& $mp exec $InstanceName -- sudo tailscale up --accept-dns=false --hostname $InstanceName
if($LASTEXITCODE -ne 0){throw "Tailscale setup failed for $InstanceName"}
$ip=Get-InstanceIPv4 $InstanceName -PreferTailscale
Write-Host "$InstanceName Tailscale IP: $ip" -ForegroundColor Green
