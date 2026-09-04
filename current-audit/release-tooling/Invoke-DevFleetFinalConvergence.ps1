[CmdletBinding()]
param(
    [string]$Workspace = (Split-Path -Parent $PSScriptRoot),
    [string]$StageScript,
    [string[]]$StageArgumentList = @(),
    [ValidateSet('AUTO','PASS','BLOCKED')][string]$TerminalMode = 'AUTO',
    [string]$PrimaryBlocker,
    [string]$PrimaryBlockerClassification,
    [guid]$L1Id = '84b7d8b8-ee6c-4085-aa29-4b0adc316de2',
    [string]$L1Name = 'DevFleet-E2E-Win11-01',
    [string]$L2Name = 'DevFleet-E2E-Linux-01',
    [switch]$L1Touched,
    [switch]$InteractiveLogonArmed,
    [switch]$SkipLiveCleanup
)

$ErrorActionPreference = 'Stop'
$Workspace = (Resolve-Path -LiteralPath $Workspace).Path
$audit = Join-Path $Workspace 'audit'
$evidence = Join-Path $Workspace 'evidence'
$outputs = Join-Path $Workspace 'outputs'
$zipPath = Join-Path $outputs 'DevFleet-v1.2.13-AI-Audit-LATEST.zip'
$sidecarPath = "$zipPath.sha256.txt"
$primaryRecordPath = Join-Path $audit 'FINALIZER-PRIMARY-BLOCKER.json'
$stageError = $null
$secondaryErrors = [System.Collections.Generic.List[string]]::new()
$finalizerStatus = 'BLOCKED'
$stageResult = $null

function Add-SecondaryError([string]$Message) {
    if ($Message -and -not $secondaryErrors.Contains($Message)) { [void]$secondaryErrors.Add($Message) }
}

function Write-AtomicJson([string]$Path, $Value) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText($temporary, (($Value | ConvertTo-Json -Depth 40) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
}

function Get-FileSha256([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }

function Get-SafeError([object]$ErrorRecord) {
    $message = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception.Message } else { [string]$ErrorRecord }
    if (-not $message) { $message = 'Unknown controlled terminal error.' }
    return ($message -replace '(?i)(password|secret|token|hmac|dpapi|private.?key)\s*[:=]\s*[^;\r\n ]+', '$1=[REDACTED]')
}

function Write-PrimaryRecord([string]$Status, [string]$Classification, [string]$Blocker, [string[]]$Secondary) {
    Write-AtomicJson $primaryRecordPath ([ordered]@{
        schemaVersion=1; generatedAtUtc=(Get-Date).ToUniversalTime().ToString('o'); status=$Status
        primaryBlocker=if($Blocker){$Blocker}else{$null}; primaryBlockerClassification=if($Classification){$Classification}else{$null}
        secondaryBlockers=@($Secondary); credentialsStoredInEvidence=$false; credentialValuesIncluded=$false; hostAgentSecretsIncluded=$false
    })
}

function Invoke-ExactTerminalCleanup {
    if ($SkipLiveCleanup) { return [ordered]@{status='SKIPPED_FOR_TEST';l1State='NOT_CHECKED';l2State='NOT_CHECKED'} }
    $result = [ordered]@{status='PASS';l1State='UNVERIFIED';l2State='UNVERIFIED';l1Name=$L1Name;l1Id=$L1Id.ToString();l2Name=$L2Name}
    try {
        $vm = Get-VM -Id $L1Id -ErrorAction Stop
        if ($vm.Name -cne $L1Name) { throw "Exact L1 identity mismatch: expected $L1Name, got $($vm.Name)." }
        if ($L1Touched -and [string]$vm.State -ne 'Off') {
            Import-Module (Join-Path $Workspace 'automation\release-e2e\modules\InteractiveLogon.psm1') -Force
            $interactiveCleanup=Clear-DevFleetE2EInteractiveLogonState -VmId $L1Id
            if([string]$interactiveCleanup.status -ne 'PASS' -or -not [bool]$interactiveCleanup.registryCleanupPersisted -or [bool]$interactiveCleanup.ordinaryDefaultPasswordPresent){throw 'Exact touched L1 durable interactive cleanup did not pass before force-stop.'}
            $result.interactiveCleanup=$interactiveCleanup
            Stop-VM -VM $vm -Force -Confirm:$false -ErrorAction Stop
        }
        $vm = Get-VM -Id $L1Id -ErrorAction Stop
        if ($vm.Name -cne $L1Name) { throw 'Exact L1 identity changed during finalization.' }
        $result.l1State = [string]$vm.State; $result.l1ExactOff = ([string]$vm.State -eq 'Off')
        $l1Timestamp=(Get-Date).ToUniversalTime().ToString('o')
        $result.l1Observation=[ordered]@{schemaVersion=1;name=$vm.Name;id=$vm.Id.ToString();state=[string]$vm.State;timestamp=$l1Timestamp;timestampUtc=$l1Timestamp;ownershipScope='exact disposable DevFleet-E2E VM identity';ownershipMethod='Get-VM -Id plus exact case-sensitive name'}
        if (-not $result.l1ExactOff) { throw 'Exact disposable L1 is not safely Off at finalization.' }
    } catch {
        $result.status='BLOCKED'; $result.l1Error=Get-SafeError $_; Add-SecondaryError "L1 terminal cleanup: $($result.l1Error)"
    }
    try {
        $l2 = @(Get-VM -Name $L2Name -ErrorAction SilentlyContinue)
        if ($l2.Count -gt 1) { throw "Ambiguous exact L2 name '$L2Name'; no deletion or adoption attempted." }
        $result.l2State=if($l2.Count -eq 0){'ABSENT'}else{[string]$l2[0].State}; $result.l2ExactAbsent=($l2.Count -eq 0)
        $l2Timestamp=(Get-Date).ToUniversalTime().ToString('o')
        $result.l2Observation=if($l2.Count -eq 0){[ordered]@{schemaVersion=1;expectedName=$L2Name;present=$false;timestamp=$l2Timestamp;timestampUtc=$l2Timestamp;verificationMethod='Get-VM -Name exact returned no VM';ownershipScope='exact expected disposable L2 name only'}}else{[ordered]@{schemaVersion=1;expectedName=$L2Name;present=$true;id=$l2[0].Id.ToString();state=[string]$l2[0].State;timestamp=$l2Timestamp;timestampUtc=$l2Timestamp;verificationMethod='Get-VM -Name exact; presence only, no ownership/adoption claim';ownershipScope='not claimed'}}
        if (-not $result.l2ExactAbsent) { Add-SecondaryError "Exact L2 remains present; no foreign resource was removed." }
    } catch { $result.status='BLOCKED'; $result.l2Error=Get-SafeError $_; Add-SecondaryError "L2 terminal check: $($result.l2Error)" }
    return $result
}

function Invoke-CanonicalAuditBundle {
    $builder=Join-Path $Workspace 'tools\Build-AIAuditBundle.ps1'
    if (-not(Test-Path -LiteralPath $builder -PathType Leaf)){throw "Canonical audit builder is missing: $builder"}
    $builderOutput=@(& (Get-Command pwsh.exe -ErrorAction Stop).Source -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $builder -Workspace $Workspace 2>&1)
    if($LASTEXITCODE -ne 0){throw "Canonical audit builder failed: $($builderOutput -join [Environment]::NewLine)"}
    if(-not(Test-Path -LiteralPath $zipPath -PathType Leaf)){throw 'Canonical audit builder returned without an audit ZIP.'}
    $zipHash=Get-FileSha256 $zipPath; $zipBytes=[int64](Get-Item -LiteralPath $zipPath).Length
    $validator=Join-Path $Workspace 'source\tools\validate_ai_audit_bundle.py'; $mode=if($finalizerStatus -eq 'PASS'){'release'}else{'diagnostic'}
    $validation=@(& python $validator --archive $zipPath --mode $mode 2>&1)
    if($LASTEXITCODE -ne 0){throw "Audit ZIP $mode validation failed: $($validation -join [Environment]::NewLine)"}
    $result=try{($validation -join "`n")|ConvertFrom-Json}catch{throw "Audit ZIP validator did not return JSON: $($_.Exception.Message)"}
    if($mode -eq 'diagnostic' -and [bool]$result.releaseEligible){throw 'Diagnostic audit ZIP was incorrectly marked release eligible.'}
    # No ZIP write occurs after this point. The sidecar is deliberately last.
    @("PATH: $([IO.Path]::GetFullPath($zipPath))","BYTES: $zipBytes","SHA-256: $zipHash")|Set-Content -LiteralPath $sidecarPath -Encoding UTF8
    [ordered]@{path=$zipPath;bytes=$zipBytes;sha256=$zipHash;sidecar=$sidecarPath;mode=$mode;validation=$result}
}

try {
    if($StageScript){if(-not(Test-Path -LiteralPath $StageScript -PathType Leaf)){throw "Stage script is missing: $StageScript"};$stageResult=@(& $StageScript @StageArgumentList);if($LASTEXITCODE -ne 0){throw "Stage exited with code $LASTEXITCODE."}}
    $finalizerStatus=if($TerminalMode -eq 'PASS'){'PASS'}elseif($TerminalMode -eq 'BLOCKED'){'BLOCKED'}elseif($PrimaryBlocker){'BLOCKED'}else{'PASS'}
} catch {
    $stageError=$_;if(-not $PrimaryBlocker){$PrimaryBlocker=Get-SafeError $_};$finalizerStatus='BLOCKED'
} finally {
    try {
        New-Item -ItemType Directory -Force -Path $audit,$evidence,$outputs|Out-Null
        # Durable interactive cleanup is performed before the touched L1 force-stop
        # inside Invoke-ExactTerminalCleanup. Do not reconnect after power-off.
    } catch { Add-SecondaryError "Interactive cleanup: $(Get-SafeError $_)" }
    try { $safePrimary=if($PrimaryBlocker){Get-SafeError $PrimaryBlocker}else{$null};Write-PrimaryRecord $finalizerStatus $PrimaryBlockerClassification $safePrimary @($secondaryErrors) } catch { Add-SecondaryError "Primary blocker record: $(Get-SafeError $_)" }
    try {
        $statePath=Join-Path $Workspace 'finalization-state.json'
        if(Test-Path -LiteralPath $statePath -PathType Leaf){
            $stateBeforeRefresh=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json
            if(-not [bool]$stateBeforeRefresh.full_release_passed){
                $candidateBinder=Join-Path $Workspace 'tools\Finalize-CandidateEvidence.ps1'
                $bindOutput=@(& (Get-Command pwsh.exe -ErrorAction Stop).Source -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $candidateBinder -Workspace $Workspace 2>&1)
                if($LASTEXITCODE -ne 0){throw "Current tooling fingerprint refresh failed: $($bindOutput -join [Environment]::NewLine)"}
            }
        }
        # A tooling-only commit advances the live tooling tuple without
        # invalidating shipping bytes. Before rebuilding the diagnostic
        # authority, bind the live non-shipping tuple when no release is
        # currently promoted; a promoted release remains immutable.
        $statePath=Join-Path $Workspace 'finalization-state.json'
        if(Test-Path -LiteralPath $statePath -PathType Leaf){
            $stateForAuthority=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json -AsHashtable
            if(-not [bool]$stateForAuthority.full_release_passed){
                $stateForAuthority.working_tree_tooling_fingerprint_id=[string]$stateForAuthority.toolingFingerprintId
                $stateForAuthority.working_tree_shipping_input_identity=[string]$stateForAuthority.shipping_input_identity
                Write-AtomicJson $statePath $stateForAuthority
            }
        }
        $authorityUpdater=Join-Path $Workspace 'tools\Update-CurrentReleaseAuthority.ps1';$updateArgs=@('-Workspace',$Workspace)
        if($PrimaryBlocker){$classification=if($PrimaryBlockerClassification){$PrimaryBlockerClassification}else{'BLOCKED — FINALIZER'};& $authorityUpdater -Workspace $Workspace -TerminalBlocker (Get-SafeError $PrimaryBlocker) -TerminalBlockerClassification $classification 2>&1|Out-Null}
        else {& $authorityUpdater -Workspace $Workspace 2>&1|Out-Null}
        if($LASTEXITCODE -ne 0){throw 'Current authority refresh failed.'}
    } catch { Add-SecondaryError "Authority refresh: $(Get-SafeError $_)" }
    try {
        $terminal=Invoke-ExactTerminalCleanup
        Write-AtomicJson (Join-Path $evidence 'FINALIZER-TERMINAL-STATE.json') $terminal
        # These two root evidence files are canonical, not historical copies.
        # Refresh them from the same exact host observations used by the
        # mandatory finalizer on every controlled terminal outcome.
        if($terminal.l1Observation){Write-AtomicJson (Join-Path $evidence 'l1-terminal-state.json') $terminal.l1Observation}
        if($terminal.l2Observation){Write-AtomicJson (Join-Path $evidence 'l2-terminal-state.json') $terminal.l2Observation}
        $interactivePath=Join-Path $evidence 'CURRENT-INTERACTIVE-LOGIN.json'
        if(Test-Path -LiteralPath $interactivePath -PathType Leaf){$interactive=Get-Content -LiteralPath $interactivePath -Raw|ConvertFrom-Json -AsHashtable;if($terminal.l1Observation){$interactive.finalL1=$terminal.l1Observation.state};if($terminal.l2Observation){$interactive.finalL2=if([bool]$terminal.l2Observation.present){$terminal.l2Observation.state}else{'ABSENT'}};Write-AtomicJson $interactivePath $interactive}
    }catch{Add-SecondaryError "Terminal cleanup: $(Get-SafeError $_)"}
    try {$diff=@(& git -C $Workspace diff --check 2>&1);if($LASTEXITCODE -ne 0){Add-SecondaryError "git diff --check: $($diff -join [Environment]::NewLine)"}}catch{Add-SecondaryError "git diff --check: $(Get-SafeError $_)"}
    try {$bundle=Invoke-CanonicalAuditBundle}catch{Add-SecondaryError "AUDIT_BUNDLE_FINALIZATION_FAILURE: $(Get-SafeError $_)";$bundle=$null}
    try {
        $statePath=Join-Path $Workspace 'finalization-state.json'
        if(Test-Path -LiteralPath $statePath -PathType Leaf){$state=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json -AsHashtable;$state.finalizer_primary_blocker=if($PrimaryBlocker){Get-SafeError $PrimaryBlocker}else{$null};$state.finalizer_secondary_blockers=@($secondaryErrors);$state.audit_bundle_finalization_status=if($bundle){'PASS'}else{'BLOCKED'};$state.audit_bundle_path=if($bundle){$bundle.path}else{$null};$state.audit_bundle_sha256=if($bundle){$bundle.sha256}else{$null};$state.finalizer_completed_utc=(Get-Date).ToUniversalTime().ToString('o');Write-AtomicJson $statePath $state}
    }catch{Add-SecondaryError "Finalization state update: $(Get-SafeError $_)"}
}

[ordered]@{status=$finalizerStatus;primaryBlocker=if($PrimaryBlocker){Get-SafeError $PrimaryBlocker}else{$null};secondaryBlockers=@($secondaryErrors);stageOutput=$stageResult;auditBundle=$bundle}|ConvertTo-Json -Depth 20
if($stageError){throw $stageError}
