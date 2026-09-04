[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunId,
    [Parameter(Mandatory)][string]$WorkspaceRoot,
    [switch]$AllowRamPressure,
    [switch]$DiagnosticOnly
)

$ErrorActionPreference = 'Stop'
$WorkspaceRoot = (Resolve-Path -LiteralPath $WorkspaceRoot).Path
$scriptRoot = Join-Path $WorkspaceRoot 'automation\release-e2e'
$vmId = [guid]'84b7d8b8-ee6c-4085-aa29-4b0adc316de2'
$candidatePath = Join-Path $WorkspaceRoot 'outputs\DevFleet-Setup-v1.2.13-win-x64.exe'
$runDir = Join-Path $WorkspaceRoot (Join-Path 'audit\automation-harness\runs' $RunId)
$vm = $null
$result = $null
$proofExitCode = 0
New-Item -ItemType Directory -Force -Path $runDir | Out-Null

function Set-CurrentProofPointer([string]$Outcome) {
    $statePath=Join-Path $WorkspaceRoot 'finalization-state.json'
    if(-not(Test-Path -LiteralPath $statePath -PathType Leaf)){return}
    $state=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json -AsHashtable
    $state.current_proof_run_id=$RunId;$state.current_proof_outcome=$Outcome;$state.current_proof_updated_utc=(Get-Date).ToUniversalTime().ToString('o')
    if($DiagnosticOnly){$state.current_diagnostic_run_id=$RunId;$state.diagnostic_run_ids=@(@($state.diagnostic_run_ids)+$RunId|Where-Object{$_}|Select-Object -Unique)}
    else{$state.proof_run_ids=@(@($state.proof_run_ids)+$RunId|Where-Object{$_}|Select-Object -Unique)}
    $tmp="$statePath.$([guid]::NewGuid().ToString('N')).tmp"
    try{[IO.File]::WriteAllText($tmp,(($state|ConvertTo-Json -Depth 24)+[Environment]::NewLine),[Text.UTF8Encoding]::new($false));Move-Item -LiteralPath $tmp -Destination $statePath -Force}
    finally{Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue}
}

Import-Module (Join-Path $scriptRoot 'modules\Candidate.psm1') -Force
Import-Module (Join-Path $scriptRoot 'modules\Evidence.psm1') -Force
Import-Module (Join-Path $scriptRoot 'modules\GuestSession.psm1') -Force
Import-Module (Join-Path $scriptRoot 'modules\executors\Invoke-RealProductPhase.psm1') -Force
Import-Module (Join-Path $scriptRoot 'modules\HostSafety.psm1') -Force
Import-Module (Join-Path $scriptRoot 'modules\Secrets.psm1') -Global -Force
Import-Module (Join-Path $scriptRoot 'modules\FullRelease.psm1') -Global -Force
Import-Module (Join-Path $scriptRoot 'modules\Evidence.psm1') -Global -Force
Import-Module (Join-Path $scriptRoot 'modules\HarnessBudget.psm1') -Global -Force

$configPath=Join-Path $scriptRoot 'config\devfleet-e2e.defaults.json'
$config=Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json -ErrorAction Stop
$budgetPolicy=Get-HarnessBudgetPolicy -Config $config
Assert-HarnessBudgetPolicy -Policy $budgetPolicy | Out-Null

try {
    $vm = Get-VM -Id $vmId -ErrorAction Stop
    if ($vm.Name -notlike 'DevFleet-E2E-*' -or $vm.Id.ToString() -ne $vmId.ToString()) { throw 'Exact disposable VM identity assertion failed.' }
    $fingerprint = Get-CandidateFingerprint -WorkspaceRoot $WorkspaceRoot -CandidatePath $candidatePath
    $provenance = [ordered]@{
        repositoryHead = (& git -C $WorkspaceRoot rev-parse HEAD).Trim()
        candidateCommit = [string]$fingerprint.gitCommit
        shippingInputIdentity = [string]$fingerprint.shippingInputIdentity
        releaseFingerprint = [string]$fingerprint.releaseFingerprintId
        toolingFingerprint = [string]$fingerprint.toolingFingerprintId
        invokeRealProductPhaseSha256 = (Get-FileHash (Join-Path $scriptRoot 'modules\executors\Invoke-RealProductPhase.psm1') -Algorithm SHA256).Hash.ToLowerInvariant()
        invokeWpfUiAutomationSha256 = (Get-FileHash (Join-Path $scriptRoot 'modules\executors\Invoke-WpfUiAutomation.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()
        proofScriptSha256 = (Get-FileHash $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
        certificationEligible = (-not [bool]$DiagnosticOnly)
        diagnosticOnly = [bool]$DiagnosticOnly
        invocation = [ordered]@{runId=$RunId;switches=@('-RunId', $RunId, '-WorkspaceRoot', $WorkspaceRoot) + $(if($AllowRamPressure){@('-AllowRamPressure')}else{@()}) + $(if($DiagnosticOnly){@('-DiagnosticOnly')}else{@()});fastMode=$false;ramPressureOverrideAuthorized=[bool]$AllowRamPressure;diagnosticOnly=[bool]$DiagnosticOnly}
        exactArtifacts = [ordered]@{exe=$fingerprint.candidate;tar=$fingerprint.tar;portable=$fingerprint.portable;installerSource=$fingerprint.installerSource}
        deadlinePolicy = $budgetPolicy
    }
    $safety = Apply-RamPressureOverride -Snapshot (Get-HostSafetySnapshot -Vm $vm -ExpectedVmStartCostGiB 14.38) -AllowRamPressure:$AllowRamPressure
    Write-EvidenceJson -Path (Join-Path $runDir 'proof-start.json') -Value ([ordered]@{
        status = if ($safety.effectiveE2EStartAuthorized) { if($safety.ramPressureOverrideAuthorized){'PASS — USER-AUTHORIZED RAM PRESSURE'}else{'PASS'} } else { 'BLOCKED' }
        generatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        runId = $RunId
        vmName = $vm.Name
        vmId = $vm.Id.ToString()
        hostSafety = $safety
         candidate = $fingerprint
         provenance = $provenance
         credentialLoaded = Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'DevFleet\E2E\secrets.json') -PathType Leaf
        passwordLogged = $false
    })
    if (-not $safety.effectiveE2EStartAuthorized) { throw 'BLOCKED — HOST-SAFETY' }
    $snapshot = Get-ExactCheckpoint -Vm $vm -Name 'DevFleet-E2E-CLEAN'
    $restored = Restore-ExactCheckpoint -Vm $vm -Name 'DevFleet-E2E-CLEAN' -StartAfterRestore
    $context = [ordered]@{
        runId = $RunId
        phaseId = 'REBOOT-RESUME'
        label = 'EXACT CURRENT-CANDIDATE REBOOT/RESUME PROOF'
        checkpoint = 'DevFleet-E2E-CLEAN'
        destructive = $true
        candidate = $fingerprint
        vmName = $vm.Name
        vmId = $vm.Id.ToString()
        runDir = $runDir
        config = $config
        deadlinePolicy = $budgetPolicy
        # A clean disposable first-install may legitimately need several minutes
        # to settle its durable reboot handoff before install-state/health appear.
        # Keep the observation bounded and fail closed; do not shorten it to the
        # generic 180-second diagnostic window.
        diagnosticObservationSeconds = 1800
    }
    # Keep a small outer bound beyond the observer's immutable lifecycle
    # deadline. A broken observer must become an explicit harness outcome,
    # never an inferred product defect and never an unbounded proof process.
    $contextJson = $context | ConvertTo-Json -Depth 32 -Compress
    # The policy is authoritative and already validated before restoring the
    # disposable checkpoint. Never silently truncate an outer watchdog.
    $innerLifecycleBoundSeconds=[int]$budgetPolicy.exactProofInnerBoundSeconds
    $outerWatchdogSeconds=[int]$budgetPolicy.exactProofOuterWatchdogSeconds
    if($outerWatchdogSeconds -le $innerLifecycleBoundSeconds){throw 'Invalid exact-proof deadline hierarchy: outer watchdog does not exceed calculated inner bound.'}
    $phaseModule = Join-Path $scriptRoot 'modules\executors\Invoke-RealProductPhase.psm1'
    $phaseJob = Start-Job -ScriptBlock {
        param($modulePath,$serializedContext)
        Import-Module $modulePath -Force
        Invoke-RealProductPhase -ContextJson $serializedContext
    } -ArgumentList $phaseModule,$contextJson
    try {
        $finished = Wait-Job -Job $phaseJob -Timeout $outerWatchdogSeconds
        if(-not $finished){
            Stop-Job -Job $phaseJob -ErrorAction SilentlyContinue
            Wait-Job -Job $phaseJob -Timeout 15 -ErrorAction SilentlyContinue | Out-Null
            $watchdog = [ordered]@{status='HARNESS_WATCHDOG_EXPIRED';classification='RELEASE HARNESS';runId=$RunId;outerWatchdogSeconds=$outerWatchdogSeconds;innerLifecycleBoundSeconds=$innerLifecycleBoundSeconds;outerExceedsInnerBound=($outerWatchdogSeconds -gt $innerLifecycleBoundSeconds);boundModel=$budgetPolicy;preserveEvidence=$true;timestampUtc=(Get-Date).ToUniversalTime().ToString('o')}
            Write-EvidenceJson -Path (Join-Path $runDir 'proof-watchdog.json') -Value $watchdog
            throw 'HARNESS_WATCHDOG_EXPIRED: proof outer watchdog exceeded the observer bound.'
        }
        $jobErrors=@($phaseJob.ChildJobs | ForEach-Object {
            $reason=$_.JobStateInfo.Reason
            if($reason){
                $message=if($reason.Exception -and $reason.Exception.Message){[string]$reason.Exception.Message}else{[string]$reason.ToString()}
                if($message){$message}
            }
        } | Where-Object { $_ })
        if($jobErrors.Count){throw "Proof lifecycle job failed: $($jobErrors -join ' | ')"}
        $jobOutput=@(Receive-Job -Job $phaseJob -ErrorAction Stop)
        if($jobOutput.Count -eq 0){throw "Proof lifecycle job returned no terminal evidence (state=$($phaseJob.State); childState=$($phaseJob.ChildJobs[0].State))."}
        $result=$jobOutput[-1]
    } finally {
        if($phaseJob){Remove-Job -Job $phaseJob -Force -ErrorAction SilentlyContinue}
    }
    if ([string]$result.status -ne 'REAL E2E PASS') { throw 'Exact candidate reboot/resume proof did not return REAL E2E PASS.' }
    Write-EvidenceJson -Path (Join-Path $runDir 'proof-final.json') -Value ([ordered]@{
        status = 'PASS'
        runId = $RunId
        candidate = $fingerprint
        cleanCheckpoint = $snapshot
        restored = $restored
        phase = $result
        diagnosticOnly = [bool]$DiagnosticOnly
        certificationEligible = (-not [bool]$DiagnosticOnly)
        passwordLogged = $false
    })
    Set-CurrentProofPointer $(if($DiagnosticOnly){'DIAGNOSTIC_PASS'}else{'PASS'})
    [ordered]@{status='PASS';runId=$RunId;evidencePath=(Join-Path $runDir 'proof-final.json');candidateSha256=$fingerprint.candidate.sha256}|ConvertTo-Json -Depth 8 -Compress
} catch {
    $errorText = $_.Exception.Message
    try { Write-EvidenceJson -Path (Join-Path $runDir 'proof-error.json') -Value ([ordered]@{status='BLOCKED';runId=$RunId;error=$errorText;passwordLogged=$false}) } catch { }
    try { Set-CurrentProofPointer $(if($DiagnosticOnly){'DIAGNOSTIC_NOT_OBSERVED'}else{'NOT_OBSERVED'}) } catch { try { Write-EvidenceJson -Path (Join-Path $runDir 'authority-pointer-error.json') -Value ([ordered]@{status='TOOLING_ERROR';runId=$RunId;error=$_.Exception.Message;passwordLogged=$false}) } catch {} }
    [ordered]@{status='BLOCKED';runId=$RunId;error=$errorText;evidencePath=(Join-Path $runDir 'proof-error.json')}|ConvertTo-Json -Depth 8 -Compress
    $proofExitCode = 1
} finally {
    try {
        $current = Get-VM -Id $vmId -ErrorAction SilentlyContinue
        $state = 'ACCESS_UNAVAILABLE'
        if ($current) {
            if ($current.State -ne 'Off') { Stop-VM -VM $current -Force -Confirm:$false -ErrorAction SilentlyContinue }
            $deadline = (Get-Date).AddMinutes(2)
            do { Start-Sleep -Seconds 2; $state = [string](Get-VM -Id $vmId -ErrorAction SilentlyContinue).State } while ($state -ne 'Off' -and (Get-Date) -lt $deadline)
        }
        if ($runDir) { Write-EvidenceJson -Path (Join-Path $runDir 'cleanup-state.json') -Value ([ordered]@{l1State=$state;l2Present=[bool](multipass list 2>$null | Select-String '^DevFleet-E2E-Linux-01\s');runOwnedOnly=$true}) }
    } catch { }
    try { & (Join-Path $WorkspaceRoot 'tools\Update-CurrentReleaseAuthority.ps1') -Workspace $WorkspaceRoot -CurrentProofRunId $RunId | Out-Null } catch { try { Write-EvidenceJson -Path (Join-Path $runDir 'authority-refresh-error.json') -Value ([ordered]@{status='TOOLING_ERROR';runId=$RunId;error=$_.Exception.Message;passwordLogged=$false}) } catch {} }
}
if($proofExitCode -ne 0){exit $proofExitCode}
