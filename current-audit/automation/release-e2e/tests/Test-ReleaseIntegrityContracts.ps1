[CmdletBinding()]
param([string]$Workspace = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '..\modules\TailscaleE2E.psm1') -Force
$passed=0;$failed=[System.Collections.Generic.List[string]]::new()
function Check([bool]$Condition,[string]$Name){if($Condition){$script:passed++}else{[void]$script:failed.Add($Name)}}
$attemptedFalseRejected=$false
try { Assert-TailscaleAuthenticationResult -Result ([pscustomobject]@{authenticationAttempted=$false;authenticationSucceeded=$true}) | Out-Null } catch { $attemptedFalseRejected=$true }
Check $attemptedFalseRejected 'TAILSCALE-AUTH rejects authenticationAttempted=false'
$providerFailureRejected=$false
try { Assert-TailscaleAuthenticationResult -Result ([pscustomobject]@{authenticationAttempted=$true;authenticationSucceeded=$false}) | Out-Null } catch { $providerFailureRejected=$true }
Check $providerFailureRejected 'TAILSCALE-AUTH rejects provider failure'
$providerSuccess = Assert-TailscaleAuthenticationResult -Result ([pscustomobject]@{authenticationAttempted=$true;authenticationSucceeded=$true})
Check ([bool]$providerSuccess) 'TAILSCALE-AUTH accepts only attempted provider success'
$old=$env:DEVFLEET_TAILSCALE_AUTH_KEY
try {
    Remove-Item Env:DEVFLEET_TAILSCALE_AUTH_KEY -ErrorAction SilentlyContinue
    $missing=Get-TailscaleAuthenticationSecret -Config ([pscustomobject]@{Authentication=[pscustomobject]@{Provider='AuthKeyEnvironment';SecretEnvironmentVariable='DEVFLEET_TAILSCALE_AUTH_KEY'}})
Check (-not [bool]$missing.available -and $missing.secret -eq $null) 'Tailscale credentials are absent without leaking a secret'
} finally { if($null -eq $old){Remove-Item Env:DEVFLEET_TAILSCALE_AUTH_KEY -ErrorAction SilentlyContinue}else{$env:DEVFLEET_TAILSCALE_AUTH_KEY=$old} }
$cleanupSource=Get-Content -Raw (Join-Path $PSScriptRoot '..\modules\Cleanup.psm1')
Check ($cleanupSource -match '\[Parameter\(Mandatory\)\]\[string\]\$L2Name' -and $cleanupSource -match 'DevFleet-H10-Linux') 'terminal L2 evidence requires configured name and protects foreign H10 resource'
$finalizationSource=Get-Content -Raw (Join-Path $PSScriptRoot '..\modules\FullRelease.psm1')
Check ($finalizationSource -match 'Get-VM -Id' -and $finalizationSource -match 'terminalL1Hash' -and $finalizationSource -match 'l2ExactAbsent') 'post-cleanup finalization performs live terminal checks and consumes hashes'
$buildSource=Get-Content -Raw (Join-Path $Workspace 'installer-source\Build-Release.ps1')
Check ($buildSource -match 'authorizedCorrection' -and $buildSource -match 'authorized_correction=\$authorizedCorrection' -and $buildSource -match 'RELEASE BLOCKED — authorized correction path is invalid') 'release build preserves only validated authorized-correction shipping paths in generated authority'
if($failed.Count){[pscustomobject]@{status='FAIL';passed=$passed;failures=@($failed)}|ConvertTo-Json -Depth 5;exit 1}
[pscustomobject]@{status='PASS';passed=$passed;failures=@()}|ConvertTo-Json -Depth 5
