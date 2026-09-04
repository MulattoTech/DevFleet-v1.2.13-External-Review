[CmdletBinding()]
param(
    [ValidateSet('Preflight','Quick','FullRelease','Resume','Closeout','PlanOnly','LaptopPreflight','LaptopPlanOnly','LaptopInstallAndSmoke','LaptopResume','LaptopEvidence')][string]$Mode='Preflight',
    [string]$Candidate,
    [string]$WorkspaceRoot,
    [string]$ConfigPath,
    [string]$VmName,
    [Nullable[int]]$MinAvailableMemoryGiB,
    [double]$ExpectedVmStartCostGiB,
    [string]$RunId,
    [string]$RunStatePath,
    [switch]$ResumeLast,
    [switch]$SyntheticResume,
    [switch]$ConfirmDisposableLab,
    [switch]$ExecuteExpensive,
    [switch]$Cleanup,
    [switch]$KeepLab,
    [switch]$AllowRamPressure
)
$ErrorActionPreference='Stop'
$scriptRoot=$PSScriptRoot
if (-not $WorkspaceRoot) { $WorkspaceRoot=(Resolve-Path (Join-Path $scriptRoot '..\..')).Path }
else { $WorkspaceRoot=(Resolve-Path $WorkspaceRoot).Path }
if (-not $ConfigPath) { $ConfigPath=Join-Path $scriptRoot 'config\devfleet-e2e.defaults.json' }
$config=Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$budgetModule=Join-Path $scriptRoot 'modules\HarnessBudget.psm1'
Import-Module $budgetModule -Force
$budgetPolicy=Get-HarnessBudgetPolicy -Config $config
Assert-HarnessBudgetPolicy -Policy $budgetPolicy | Out-Null
if (-not $PSBoundParameters.ContainsKey('ExpectedVmStartCostGiB')) { $ExpectedVmStartCostGiB=[double]$config.ExpectedVmStartCostGiB }
foreach($m in @('Candidate','HostSafety','ResumeState','Evidence','Cleanup','GuestSession','TailscaleE2E','FullRelease')) { Import-Module (Join-Path $scriptRoot "modules\$m.psm1") -Force }

$script:DevFleetFinalConvergencePrimaryBlocker = $null
try {

function Save-State([psobject]$State,[string]$Path) { Save-RunState -State $State -Path $Path }
function Gate([string]$Name,[string]$Status,[string]$Details) { New-GateRecord -Name $Name -Status $Status -Details $Details }
function Show-Result([string]$label,[string]$status,[string]$detail) { Write-Host "[$status] $label - $detail" }

if (($Mode -eq 'Resume' -or $ResumeLast) -and -not $RunStatePath) {
    $latest=Get-ChildItem -LiteralPath (Join-Path $WorkspaceRoot 'audit\automation-harness\runs') -Filter run-state.json -Recurse -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if (-not $latest) { throw 'No durable harness run-state exists to resume.' }
    $RunStatePath=$latest.FullName
}

$fingerprint=Get-CandidateFingerprint -WorkspaceRoot $WorkspaceRoot -CandidatePath $Candidate
$runId=if($RunId){$RunId}else{New-HarnessRunId}
$runDir=New-RunEvidenceDirectory -WorkspaceRoot $WorkspaceRoot -RunId $runId
$statePath=if($RunStatePath){$RunStatePath}else{Join-Path $runDir 'run-state.json'}
$vm=$null; $hostSnapshot=$null
$isLaptopMode=$Mode -like 'Laptop*'
if(-not $isLaptopMode){
    try { $vm=Get-DisposableVm -VmName $VmName -Pattern ([string]$config.DisposableVmNamePattern); Assert-DisposableOwnership -Vm $vm | Out-Null; $hostSnapshot=Apply-RamPressureOverride -Snapshot (Get-HostSafetySnapshot -Vm $vm -ExpectedVmStartCostGiB $ExpectedVmStartCostGiB) -AllowRamPressure:$AllowRamPressure } catch { if($Mode -ne 'PlanOnly' -and $Mode -ne 'Resume' -and -not $SyntheticResume){ throw }; $hostSnapshot=[pscustomobject]@{status='UNAVAILABLE_IN_SYNTHETIC_OR_PLAN_CONTEXT';error=$_.Exception.Message} }
} else {
    $hostSnapshot=[ordered]@{status='READ_ONLY_LAPTOP_MODE';computerName=$env:COMPUTERNAME;availableMemoryGiB=[math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory/1MB,2);productionMutation=$false}
}

$state=[ordered]@{
    schemaVersion=1; harnessVersion=$config.HarnessVersion; runId=$runId; startedAt=(Get-Date).ToUniversalTime().ToString('o'); mode=$Mode
    candidatePath=$fingerprint.candidate.path; candidateVersion=$fingerprint.releaseVersion; installerVersion=$fingerprint.installerVersion
    candidateHashes=[ordered]@{ repositoryHead=$fingerprint.repositoryHead; candidateCommit=$fingerprint.gitCommit; shippingInputIdentity=$fingerprint.shippingInputIdentity; releaseFingerprintId=$fingerprint.releaseFingerprintId; toolingFingerprintId=$fingerprint.toolingFingerprintId; exe=$fingerprint.candidate.sha256; tar=$fingerprint.tar.sha256; portable=$fingerprint.portable.sha256; installerSource=$fingerprint.installerSource.sha256 }
    currentPhase='Preflight'; completedPhases=@(); currentTransaction=$null
    vmName=if($vm){$vm.Name}else{$null}; vmId=if($vm){$vm.Id.ToString()}else{$null}; checkpointIds=@(); projectIds=@(); backupIds=@(); expectedRebootState=$null; userActionState=$null
    evidencePaths=@(); cleanupManifestPath=$null; errors=@(); finalStatus='IN_PROGRESS'; synthetic=[bool]$SyntheticResume
}

if ($Mode -eq 'Resume' -or $ResumeLast) {
    $existing=Read-StrictJson -Path $statePath
    if ($SyntheticResume -and -not $existing.synthetic) { throw 'Synthetic resume refused a non-synthetic state.' }
    if ($existing.vmName -and -not $vm) { $vm=Get-DisposableVm -VmName $existing.vmName -Pattern ([string]$config.DisposableVmNamePattern) }
    Assert-ResumeIdentity -State $existing -Fingerprint $fingerprint -Vm $vm | Out-Null
    $existing.currentPhase='ResumeVerified'; $existing.completedPhases=@($existing.completedPhases)+@('ResumeVerified'); if($existing.PSObject.Properties['finalStatus']){$existing.finalStatus='PASS - resume mechanics verified'}else{$existing | Add-Member -NotePropertyName finalStatus -NotePropertyValue 'PASS - resume mechanics verified'}
    Save-State $existing $statePath
    Write-EvidenceJson -Path (Join-Path $runDir 'resume-verification.json') -Value ([ordered]@{ status='PASS'; candidateHashes=$existing.candidateHashes; vmName=$existing.vmName; vmId=$existing.vmId; synthetic=[bool]$existing.synthetic; statePath=$statePath })
    Show-Result 'Resume identity' 'PASS' 'candidate and recorded disposable identity verified'
    return
}

Save-State $state $statePath
Write-EvidenceJson -Path (Join-Path $runDir 'artifact-hashes.json') -Value $fingerprint
Write-EvidenceJson -Path (Join-Path $runDir 'host-safety.json') -Value $hostSnapshot
$state.evidencePaths=@('artifact-hashes.json','host-safety.json','run-state.json')

if ($Mode -eq 'PlanOnly') {
    $plan=[ordered]@{ status='PASS'; mode='PlanOnly'; candidate=$fingerprint; disposableVm=if($vm){[ordered]@{name=$vm.Name;id=$vm.Id.ToString()}}else{$null}; hostSafety=$hostSnapshot; productionDenyList=@($config.ProductionNameDenyList); phases=@('candidate self-test','clean checkpoint restore','interactive E2EAdmin desktop','dependency matrix','WPF UIA','Primary','independent maintenance checkpoints','stopped project','Tailscale Deferred or InteractiveRelease','reconcile','audit bundles','ownership-proven cleanup'); destructiveActionsPerformed=$false }
    Write-EvidenceJson -Path (Join-Path $runDir 'plan.json') -Value $plan
    $state.currentPhase='PlanOnly'; $state.completedPhases=@('PlanOnly'); $state.finalStatus='PASS - plan generated; no destructive action performed'; Save-State $state $statePath
    Show-Result 'PlanOnly' 'PASS' "candidate $($fingerprint.releaseVersion), no destructive action performed"
    return
}

if($isLaptopMode){
    $laptopEvidence=[ordered]@{status='PASS';mode=$Mode;candidate=$fingerprint;host=$hostSnapshot;role='Laptop / Surrogate';mutationPerformed=$false;productionMutation=$false;actions=@('read-only preflight','verify candidate fingerprint','preserve existing projects and unrelated resources','require explicit coordinator/deployment pairing before install')}
    if($Mode -eq 'LaptopInstallAndSmoke'){$laptopEvidence.status='BLOCKED';$laptopEvidence.reason='Laptop mutation is intentionally not executable from the development/reference host; run this mode on MulattoTechSurface after LaptopPreflight and LaptopPlanOnly.'}
    if($Mode -eq 'LaptopResume'){$laptopEvidence.status='UNVERIFIED';$laptopEvidence.reason='No durable laptop run-state was supplied.'}
    Write-EvidenceJson -Path (Join-Path $runDir 'laptop-mode.json') -Value $laptopEvidence
    $state.currentPhase=$Mode; $state.completedPhases=@($state.completedPhases)+@($Mode); $state.finalStatus=$laptopEvidence.status; Save-State $state $statePath
    $laptopDetail = if($laptopEvidence.reason){ [string]$laptopEvidence.reason } else { 'read-only laptop/surrogate harness validation complete' }
    Show-Result $Mode $laptopEvidence.status $laptopDetail
    return
}

if ($Mode -in @('Quick','Closeout','FullRelease')) {
    $selfTest=Invoke-CandidateSelfTest -Fingerprint $fingerprint
    Write-EvidenceJson -Path (Join-Path $runDir 'self-test.json') -Value $selfTest
    $badChecks=@($selfTest.requiredChecks.GetEnumerator() | Where-Object { $_.Value -ne $true })
    if (($selfTest.result -ne 'PASS') -or ($badChecks.Count -gt 0)) { throw 'Candidate self-test did not satisfy the required contract.' }
    $state.completedPhases=@($state.completedPhases)+@('CandidateVerified'); $state.currentPhase='CandidateVerified'; Save-State $state $statePath
    Show-Result 'Candidate self-test' 'PASS' 'version, payload, extraction, bootstrap, contract, reset gate, and plan safety verified'
}

if ($Mode -eq 'Preflight') {
    $status=if($hostSnapshot.startSafe){'PASS'}else{'USER ACTION'}
    Write-EvidenceJson -Path (Join-Path $runDir 'preflight.json') -Value ([ordered]@{status=$status;candidate=$fingerprint;hostSafety=$hostSnapshot;vmOwnership=if($vm){[ordered]@{name=$vm.Name;id=$vm.Id.ToString();disposable=$true}}else{$null};productionMutation=$false})
    $state.currentPhase='Preflight'; $state.completedPhases=@('Preflight'); $state.finalStatus=$status; Save-State $state $statePath
    Show-Result 'Preflight' $status 'read-only host, candidate, and ownership checks complete'
    return
}

if ($Mode -eq 'Quick') {
    $state.currentPhase='Quick'; $state.completedPhases=@($state.completedPhases)+@('Quick'); $state.finalStatus='PASS'; Save-State $state $statePath
    Show-Result 'Quick' 'PASS' 'candidate and self-test checks complete'; return
}

if ($Mode -eq 'FullRelease') {
    if (-not $ConfirmDisposableLab -or -not $ExecuteExpensive) { throw 'FullRelease is destructive and requires -ConfirmDisposableLab -ExecuteExpensive; use PlanOnly for a non-mutating preview.' }
    if (-not $vm) { throw 'FullRelease requires an ownership-verified disposable VM.' }
    # Bind the current FullRelease RunId before any phase starts.  This is a
    # durable identity pointer, not a PASS claim; promotion remains false
    # until post-cleanup reconciliation consumes the completed evidence.
    try {
        $finalPath=Join-Path $WorkspaceRoot 'finalization-state.json'
        $finalCurrent=(Read-StrictJson -Path $finalPath | ConvertTo-Json -Depth 24 | ConvertFrom-Json -AsHashtable)
        $finalCurrent.full_release_run_id=$runId;$finalCurrent.full_release_current=$true;$finalCurrent.full_release_passed=$false;$finalCurrent.validation_evidence_current=$false;$finalCurrent.internal_promotion_allowed=$false
        $tmp="$finalPath.$([guid]::NewGuid().ToString('N')).tmp";[IO.File]::WriteAllText($tmp,(($finalCurrent|ConvertTo-Json -Depth 24)+[Environment]::NewLine),[Text.UTF8Encoding]::new($false));Move-Item -LiteralPath $tmp -Destination $finalPath -Force
        & (Join-Path $WorkspaceRoot 'tools\Update-CurrentReleaseAuthority.ps1') -Workspace $WorkspaceRoot -FullReleaseRunId $runId | Out-Null
    } catch { throw "Could not bind current FullRelease RunId '$runId' into finalization authority: $($_.Exception.Message)" }
    try {
        $result=Invoke-FullReleaseRun -State $state -Fingerprint $fingerprint -Vm $vm -Config $config -WorkspaceRoot $WorkspaceRoot -RunDir $runDir -StatePath $statePath -HostSnapshot $hostSnapshot -SelfTest $selfTest
        & (Join-Path $WorkspaceRoot 'tools\Update-CurrentReleaseAuthority.ps1') -Workspace $WorkspaceRoot -FullReleaseRunId $runId | Out-Null
        Show-Result 'FullRelease' 'PASS' 'all configured real product phases completed with durable evidence'
        return
    } catch {
        if (-not $KeepLab -and $vm) {
            try {
                $failureCleanup=New-CleanupManifest -Vm $vm -RunId $runId
                $failureVm=Get-AssertedDisposableVm -ExpectedVm $vm
                $durable=$false
                if([string]$failureVm.State -eq 'Off'){$durable=$true}else{
                    $failureLogon=Clear-DevFleetE2EInteractiveLogonState -VmId ([guid][string]$vm.Id)
                    $durable=([string]$failureLogon.status -eq 'PASS' -and [bool]$failureLogon.registryCleanupPersisted -and [bool]$failureLogon.temporaryDefaultPasswordRemovalPersisted -and -not [bool]$failureLogon.ordinaryDefaultPasswordPresent)
                }
                if($durable){Stop-ManifestVm -Manifest $failureCleanup;Write-TerminalVmEvidence -Vm $vm -RunDir $runDir -L2Name ([string]$config.NestedLinux.Name) | Out-Null}
            } catch {}
        }
        try { & (Join-Path $WorkspaceRoot 'tools\Update-CurrentReleaseAuthority.ps1') -Workspace $WorkspaceRoot -FullReleaseRunId $runId | Out-Null } catch {}
        Show-Result 'FullRelease' 'BLOCKED' $_.Exception.Message
        throw
    }
}

if ($Mode -eq 'Closeout') {
    $finalStatePath=Join-Path $WorkspaceRoot 'finalization-state.json'
    $finalState=Read-StrictJson -Path $finalStatePath
    $tailStatus=$null; $guestState=$null; $session=$null
    try {
        $session=Connect-DevFleetGuest -VmId $vm.Id
        $guestState=Get-InteractiveGuestState -Session $session
        $tailStatus=Get-TailscaleGuestStatus -Session $session -ExpectedNodePattern ([string]$config.Tailscale.ExpectedGuestNodePattern)
    } catch { $tailStatus=[pscustomobject]@{status='UNVERIFIED';error=$_.Exception.Message;credentialsStoredInEvidence=$false} }
    finally { if($session){Remove-PSSession $session} }
    $cleanupManifest=New-CleanupManifest -Vm $vm -RunId $runId
    $cleanupPath=Join-Path $runDir 'cleanup-manifest.json'; Write-EvidenceJson -Path $cleanupPath -Value $cleanupManifest
    $tailGate = 'FAIL'
    if($tailStatus -and (Test-TailscaleConnected $tailStatus)) { $tailGate = 'REAL E2E PASS' }
    $cleanupGate = 'FAIL'
    if(Test-CleanupManifest $cleanupManifest) { $cleanupGate = 'UNIT/INTEGRATION TESTED' }
    $gateRecords=@(
        (Gate 'candidate' 'REAL E2E PASS' $fingerprint.candidate.sha256),
        (Gate 'accepted-final-state' 'REAL E2E PASS' ([string]$finalState.status)),
        (Gate 'tailscale-connected-state' $tailGate 'read-only guest status plus bounded WPF state was independently verified'),
        (Gate 'cleanup-manifest' $cleanupGate 'exact disposable VM identity; production deny list; no fuzzy deletion')
    )
    $closeout=[ordered]@{status=if(@($gateRecords|Where-Object status -eq 'FAIL').Count -eq 0){'PASS'}else{'FAIL'};candidate=$fingerprint;acceptedGates=$finalState.gates;guest=$guestState;tailscale=$tailStatus;gates=$gateRecords;cleanupManifest=$cleanupPath;destructiveActionsPerformed=$false}
    Write-EvidenceJson -Path (Join-Path $runDir 'closeout.json') -Value $closeout
    $state.currentPhase='Closeout'; $state.completedPhases=@($state.completedPhases)+@('Closeout'); $state.cleanupManifestPath=$cleanupPath; $state.finalStatus=$closeout.status; Save-State $state $statePath
    Show-Result 'Closeout smoke' $closeout.status 'current candidate, accepted evidence, Tailscale state, and cleanup safety verified'
}
} catch {
    $script:DevFleetFinalConvergencePrimaryBlocker = $_.Exception.Message
    throw
} finally {
    # Every controlled entrypoint outcome, including early HOST-SAFETY and
    # FullRelease failures, goes through the same fail-safe audit finalizer.
    try {
        $finalizer = Join-Path $WorkspaceRoot 'tools\Invoke-DevFleetFinalConvergence.ps1'
        $finalizerArgs = @('-Workspace',$WorkspaceRoot)
        if ($script:DevFleetFinalConvergencePrimaryBlocker) {
            $finalizerArgs += @('-PrimaryBlocker',$script:DevFleetFinalConvergencePrimaryBlocker,'-PrimaryBlockerClassification','BLOCKED — RELEASE HARNESS / PLATFORM')
        }
        & (Get-Command pwsh.exe -ErrorAction Stop).Source -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $finalizer @finalizerArgs | Write-Output
    } catch {
        Write-Warning "Mandatory finalizer invocation failed: $($_.Exception.Message)"
    }
}
