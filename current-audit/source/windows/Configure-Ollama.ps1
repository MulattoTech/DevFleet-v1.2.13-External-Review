[CmdletBinding()]
param(
    [ValidateSet('stable-interactive','large-context','parallel-agents')][string]$Profile='stable-interactive',
    [string]$LanFallback='http://192.168.1.243:11434/v1'
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
Assert-PowerShell7
Assert-Administrator
$root=Get-PackageRootFromState
$profiles=Get-Content (Join-Path $root 'config\ollama-profiles.json') -Raw|ConvertFrom-Json -AsHashtable
$selected=$profiles[$Profile]
if(-not $selected){throw 'Profile not found.'}
$tailscaleIp=$null
$magicDns=$null
try {
    $ts=Get-TailscaleExe
    $tailscaleIp=(Invoke-External $ts @('ip','-4') -Capture).Trim().Split("`n")[0]
    $status=Invoke-External $ts @('status','--json') -Capture|ConvertFrom-Json
    $magicDns=([string]$status.Self.DNSName).TrimEnd('.')
} catch { Write-Warning "Tailscale identity could not be resolved: $_" }
$hostValue=if($tailscaleIp){$tailscaleIp}else{'127.0.0.1'}
if($hostValue -in @('0.0.0.0','::')){throw 'Wildcard Ollama binding is refused.'}
[Environment]::SetEnvironmentVariable('OLLAMA_HOST',"$hostValue`:11434",'User')
foreach($kv in $selected.Environment.GetEnumerator()){
    [Environment]::SetEnvironmentVariable([string]$kv.Key,[string]$kv.Value,'User')
}
$ruleName='DevFleet Ollama Tailnet Only'
Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue|Remove-NetFirewallRule
if($tailscaleIp){
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $tailscaleIp -LocalPort 11434 -RemoteAddress '100.64.0.0/10' -Profile Any|Out-Null
}
$state=Get-DevFleetStateRoot
$cfg=Get-DevFleetConfig
$cfg.Ollama.Profile=$Profile
$cfg.Ollama.PreferredBaseUrl=if($magicDns){"http://$magicDns`:11434/v1"}elseif($tailscaleIp){"http://$tailscaleIp`:11434/v1"}else{$LanFallback}
Save-DevFleetConfig $cfg
[ordered]@{
    Profile=$Profile
    BindHost=$hostValue
    MagicDns=$magicDns
    PreferredBaseUrl=$cfg.Ollama.PreferredBaseUrl
    LanFallback=$LanFallback
    Environment=$selected.Environment
    FirewallScope=if($tailscaleIp){'Tailscale local IP; remote 100.64.0.0/10'}else{'No inbound DevFleet rule created'}
    Configured=(Get-Date).ToString('o')
}|ConvertTo-Json -Depth 10|Set-Content (Join-Path $state 'ollama-effective.json') -Encoding utf8
Write-Host 'Restart Ollama completely, then run Test-Ollama.ps1. Re-run compute-node provisioning to propagate a changed endpoint into an already installed VM.' -ForegroundColor Green
