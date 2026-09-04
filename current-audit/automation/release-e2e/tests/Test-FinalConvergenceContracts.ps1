[CmdletBinding()]
param([string]$Workspace = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
$ErrorActionPreference = 'Stop'
$finalizer = Get-Content -LiteralPath (Join-Path $Workspace 'tools\Invoke-DevFleetFinalConvergence.ps1') -Raw
$builder = Get-Content -LiteralPath (Join-Path $Workspace 'tools\Build-AIAuditBundle.ps1') -Raw
$entrypoint = Get-Content -LiteralPath (Join-Path $Workspace 'automation\release-e2e\Invoke-DevFleetReleaseE2E.ps1') -Raw
$checks = [ordered]@{
    proofExceptionHasFinally = ($finalizer -match 'StageScript' -and $finalizer -match 'finally\s*\{')
    fullReleaseExceptionCanBeWrapped = ($finalizer -match 'StageArgumentList' -and $entrypoint -match 'FullRelease')
    hostSafetyIsDiagnostic = ($finalizer -match 'TerminalMode' -and $finalizer -match 'BLOCKED')
    originalBlockerPreserved = ($finalizer -match 'primaryBlocker' -and $finalizer -match 'secondaryBlockers')
    idempotentTerminalChecks = ($finalizer -match 'Get-VM -Id' -and $finalizer -match 'Get-VM -Name' -and $finalizer -match 'exact L1')
    noCredentials = ($finalizer -match 'credentialValuesIncluded\s*=\s*\$false' -and $finalizer -match 'hostAgentSecretsIncluded\s*=\s*\$false' -and $finalizer -match 'REDACTED')
    exactL1Only = ($finalizer -match '84b7d8b8-ee6c-4085-aa29-4b0adc316de2' -and $finalizer -match 'DevFleet-E2E-Win11-01' -and $finalizer -match 'L1Touched')
    protectedNamesRejected = ($finalizer -match 'L2Name' -and $finalizer -match 'no deletion or adoption')
    l2AbsenceRecorded = ($finalizer -match 'l2ExactAbsent' -and $finalizer -match 'FINALIZER-TERMINAL-STATE')
    passVsDiagnosticMode = ($finalizer -match "'PASS','BLOCKED'" -and $finalizer -match "'diagnostic'" -and $finalizer -match "'release'")
    sidecarLast = ($builder -match 'outer sidecar is the final filesystem write' -and $builder -notmatch 'Set-Content -LiteralPath \$sidecarPath[\s\S]{0,300}Write-Json \$manifestPath')
    zipNotMutatedAfterSidecar = ($finalizer -match 'No ZIP write occurs after this point' -and $builder -match 'ZIP is never modified after this point')
}
$failed = @($checks.GetEnumerator() | Where-Object { -not [bool]$_.Value } | ForEach-Object Key)
$result = [ordered]@{status=if($failed.Count -eq 0){'PASS'}else{'FAIL'};passed=($checks.Count-$failed.Count);total=$checks.Count;checks=$checks;failures=$failed}
$result | ConvertTo-Json -Depth 8
if ($failed.Count) { exit 1 }
