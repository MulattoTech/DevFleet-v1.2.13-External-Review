[CmdletBinding()]
param(
    [string]$Workspace = (Split-Path -Parent $PSScriptRoot),
    [string]$CurrentProofRunId,
    [string]$FullReleaseRunId,
    [string]$TerminalBlocker,
    [string]$TerminalBlockerClassification
)

$ErrorActionPreference = 'Stop'
$Workspace = (Resolve-Path -LiteralPath $Workspace).Path
$outputs = Join-Path $Workspace 'outputs'
$audit = Join-Path $Workspace 'audit'
$evidence = Join-Path $Workspace 'evidence'
$runRoot = Join-Path $audit 'automation-harness\runs'

function Read-Json([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}
function Write-AtomicJson([string]$Path,$Value) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText($temporary,(($Value | ConvertTo-Json -Depth 40) + [Environment]::NewLine),[Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
}
function Write-AtomicText([string]$Path,[string]$Value) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText($temporary,$Value,[Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
}
function Get-StringHash([string]$Value) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)) | ForEach-Object { $_.ToString('x2') }) -join '') }
    finally { $sha.Dispose() }
}
function Get-FirstProperty($Value,[string[]]$Names) {
    if ($null -eq $Value) { return $null }
    foreach ($name in $Names) {
        if ($Value -is [Collections.IDictionary] -and $Value.Contains($name)) { return $Value[$name] }
        if ($Value.PSObject.Properties.Name -contains $name) { return $Value.$name }
    }
    return $null
}
function Get-NewestJson([string]$Root,[string]$Name) {
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return $null }
    $file = Get-ChildItem -LiteralPath $Root -Filter $Name -File -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if (-not $file) { return $null }
    try { return [ordered]@{value=(Read-Json $file.FullName);relativePath=$file.FullName.Substring($Workspace.Length).TrimStart('\','/').Replace('\','/');lastWriteUtc=$file.LastWriteTimeUtc.ToString('o')} }
    catch { return [ordered]@{value=$null;relativePath=$file.FullName.Substring($Workspace.Length).TrimStart('\','/').Replace('\','/');lastWriteUtc=$file.LastWriteTimeUtc.ToString('o');readError='JSON_UNREADABLE'} }
}

New-Item -ItemType Directory -Force -Path $audit,$evidence | Out-Null
$statePath = Join-Path $Workspace 'finalization-state.json'
$manifestPath = Join-Path $outputs 'final-artifact-hashes.json'
$releasePath = Join-Path $outputs 'release-fingerprint.json'
$toolingPath = Join-Path $outputs 'tooling-fingerprint-current.json'
$state = Read-Json $statePath
$manifest = Read-Json $manifestPath
$release = Read-Json $releasePath
$tooling = Read-Json $toolingPath
if (-not $state -or -not $manifest -or -not $release -or -not $tooling) { throw 'Current release authority inputs are incomplete.' }

$head = (& git -C $Workspace rev-parse HEAD).Trim()
$branch = (& git -C $Workspace branch --show-current).Trim()
$candidateCommit = [string](Get-FirstProperty $state @('candidate_git_commit','candidateGitCommit','candidateCommit'))
$shippingIdentity = [string](Get-FirstProperty $state @('shipping_input_identity','shippingInputIdentity'))
$releaseId = [string]$state.releaseFingerprintId
$toolingId = [string]$state.toolingFingerprintId
if ($head -notmatch '^[0-9a-f]{40}$' -or $candidateCommit -notmatch '^[0-9a-f]{40}$' -or $shippingIdentity -notmatch '^[0-9a-f]{64}$' -or $releaseId -notmatch '^[0-9a-f]{64}$' -or $toolingId -notmatch '^[0-9a-f]{64}$') { throw 'Current release authority identity tuple is malformed.' }
if ([string]$manifest.candidateGitCommit -cne $candidateCommit -or [string]$manifest.shippingInputIdentity -cne $shippingIdentity -or [string]$manifest.releaseFingerprintId -cne $releaseId -or [string]$manifest.toolingFingerprintId -cne $toolingId) { throw 'Artifact manifest disagrees with finalization authority.' }
if ([string]$release.releaseFingerprintId -cne $releaseId -or [string]$release.toolingFingerprint.toolingFingerprintId -cne $toolingId -or [string]$tooling.releaseFingerprintId -cne $releaseId -or [string]$tooling.toolingFingerprintId -cne $toolingId) { throw 'Release/tooling fingerprint records disagree with finalization authority.' }
$candidateRows = @($release.shippingInputs)
if (-not $candidateRows.Count) { throw 'Candidate-bound release fingerprint contains no shipping rows.' }

# The durable candidate authority must invalidate itself when the live shipping
# tree no longer matches the candidate-bound identity. This catches a new
# shipping commit or an uncommitted shipping edit before any newer proof prose
# can be mistaken for evidence for the old binary.
$identityTool = Join-Path $Workspace 'tools\compute_shipping_input_identity.py'
$identityPython = Join-Path $Workspace 'source\.venv-test\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $identityPython -PathType Leaf)) { $identityPython = (Get-Command python.exe -ErrorAction Stop).Source }
$identityJson = & $identityPython $identityTool --workspace $Workspace --candidate-commit $candidateCommit | Select-Object -Last 1
if ($LASTEXITCODE) { throw 'Current shipping input identity could not be recomputed for authority refresh.' }
$identity = $identityJson | ConvertFrom-Json
$liveShippingIdentity = [string]$identity.liveShippingInputIdentity
if ($liveShippingIdentity -notmatch '^[0-9a-f]{64}$') { throw 'Live shipping input identity is malformed during authority refresh.' }
$substantiveShippingDrift = $liveShippingIdentity -cne $shippingIdentity -and -not [bool]$identity.crlfOnlyMaterialization
if ($substantiveShippingDrift) {
    $state.candidate_is_current = $false
    $state.source_identity_matches_candidate = $false
    $state.source_changed_since_candidate = $true
    $state.rebuild_required = $true
    $state.validation_evidence_current = $false
    $state.full_release_passed = $false
    $state.internal_promotion_allowed = $false
    $state.release_status = 'BLOCKED'
    $state.status = 'BLOCKED — CANDIDATE INVALIDATED / REBUILD REQUIRED'
    $state.current_phase = 'candidate-invalidated-rebuild-required'
    $invalidationReason = "Live shipping input identity $liveShippingIdentity differs from candidate-bound identity $shippingIdentity."
    if ($state.PSObject.Properties.Name -contains 'candidate_invalidation_reason') { $state.candidate_invalidation_reason = $invalidationReason }
    else { $state | Add-Member -NotePropertyName candidate_invalidation_reason -NotePropertyValue $invalidationReason }
    Write-AtomicJson $statePath $state
    $state = Read-Json $statePath
}

$candidateFlags = [ordered]@{
    candidateIsCurrent = [bool]$state.candidate_is_current
    sourceIdentityMatchesCandidate = [bool]$state.source_identity_matches_candidate
    sourceChangedSinceCandidate = [bool]$state.source_changed_since_candidate
    rebuildRequired = [bool]$state.rebuild_required
    candidateBuildCurrent = [bool]$state.candidate_build_current
    artifactTupleMatchesCandidate = [bool]$state.artifact_tuple_matches_candidate
    validationEvidenceCurrent = [bool]$state.validation_evidence_current
    fullReleasePassed = [bool]$state.full_release_passed
    internalPromotionAllowed = [bool]$state.internal_promotion_allowed
    publicPromotionAllowed = [bool]$state.public_promotion_allowed
    publicPublisherTrust = [bool]$state.public_publisher_trust
}
$candidateSafe = $candidateFlags.candidateIsCurrent -and $candidateFlags.sourceIdentityMatchesCandidate -and -not $candidateFlags.sourceChangedSinceCandidate -and -not $candidateFlags.rebuildRequired -and $candidateFlags.candidateBuildCurrent -and $candidateFlags.artifactTupleMatchesCandidate
$workingTree = [ordered]@{
    shippingInputIdentity = [string](Get-FirstProperty $state @('working_tree_shipping_input_identity','workingTreeShippingInputIdentity'))
    releaseFingerprintWithHistoricalArtifacts = [string](Get-FirstProperty $state @('working_tree_release_fingerprint_with_historical_artifacts','workingTreeReleaseFingerprintWithHistoricalArtifacts'))
    toolingFingerprintId = [string](Get-FirstProperty $state @('working_tree_tooling_fingerprint_id','workingTreeToolingFingerprintId'))
    preparedTarSha256 = [string](Get-FirstProperty $state @('prepared_tar_sha256','preparedTarSha256'))
    preparedPortableSha256 = [string](Get-FirstProperty $state @('prepared_portable_sha256','preparedPortableSha256'))
}

$artifactByName = [ordered]@{}
foreach ($row in @($manifest.artifacts)) { $artifactByName[[string]$row.name] = $row }
foreach ($required in @('exe','tar','portable','installerSource')) { if (-not $artifactByName.Contains($required)) { throw "Artifact manifest is missing $required." } }
$candidate = [ordered]@{
    schemaVersion=2; generatedAtUtc=(Get-Date).ToUniversalTime().ToString('o'); releaseVersion=[string]$manifest.releaseVersion; installerVersion=[string]$manifest.installerVersion
    repositoryHead=$head; branch=$branch; gitCommit=$candidateCommit; candidateGitCommit=$candidateCommit
    shippingInputIdentity=$shippingIdentity; candidateShippingInputIdentity=$shippingIdentity; releaseFingerprintId=$releaseId; toolingFingerprintId=$toolingId
    candidateShippingInputs=$candidateRows; candidateShippingModeContract=$release.shippingModeContract; shippingModeContract=$release.shippingModeContract
    lineEndingComparison=if($candidateFlags.sourceChangedSinceCandidate){'SUBSTANTIVE'}else{[string]($tooling.lineEndingComparison ?? $manifest.lineEndingComparison ?? 'UNVERIFIED')}; crlfOnlyPaths=if($candidateFlags.sourceChangedSinceCandidate){@()}else{@($tooling.crlfOnlyPaths)}
    candidateIsCurrent=$candidateFlags.candidateIsCurrent; sourceIdentityMatchesCandidate=$candidateFlags.sourceIdentityMatchesCandidate; sourceChangedSinceCandidate=$candidateFlags.sourceChangedSinceCandidate; rebuildRequired=$candidateFlags.rebuildRequired
    candidateBuildCurrent=$candidateFlags.candidateBuildCurrent; artifactTupleMatchesCandidate=$candidateFlags.artifactTupleMatchesCandidate; validationEvidenceCurrent=$candidateFlags.validationEvidenceCurrent; fullReleasePassed=$candidateFlags.fullReleasePassed
    internalPromotionAllowed=$candidateFlags.internalPromotionAllowed; publicPromotionAllowed=$false; publicPublisherTrust=$false
    exeSha256=[string]$artifactByName.exe.sha256; exeBytes=[int64]$artifactByName.exe.bytes; tarSha256=[string]$artifactByName.tar.sha256; tarBytes=[int64]$artifactByName.tar.bytes
    portableSha256=[string]$artifactByName.portable.sha256; portableBytes=[int64]$artifactByName.portable.bytes; installerSourceSha256=[string]$artifactByName.installerSource.sha256; installerSourceBytes=[int64]$artifactByName.installerSource.bytes
    artifacts=@($manifest.artifacts); signingState=[string]$manifest.signingState; privateSigningProfile=[string]$manifest.privateSigningProfile; signerSubject=[string]$manifest.signerSubject; signerThumbprint=[string]$manifest.privateSigningCertificateThumbprint
    privateKeyExportable=$false; privateKeyExported=$false; publicCertificate=$manifest.publicCertificate
    superseded=(-not $candidateFlags.candidateIsCurrent); invalidationReason=[string](Get-FirstProperty $state @('candidate_invalidation_reason','candidateInvalidationReason'))
    f005Attempted=$false; formatterOnlyAuditCleanup=$false; f005StructuralRefactor=$false
}

$interactiveCurrent = Read-Json (Join-Path $evidence 'CURRENT-INTERACTIVE-LOGIN.json')
$interactiveSmokeRunId = if($interactiveCurrent -and [string]$interactiveCurrent.RunId){[string]$interactiveCurrent.RunId}else{$null}
if (-not $CurrentProofRunId) { $CurrentProofRunId = [string]$state.current_proof_run_id }
$proofRun = if ($CurrentProofRunId) { Join-Path $runRoot $CurrentProofRunId } else { $null }
$proofStartRecord = if ($proofRun) { Get-NewestJson $proofRun 'proof-start.json' } else { $null }
$proofFinalRecord = if ($proofRun) { Get-NewestJson $proofRun 'proof-final.json' } else { $null }
$proofErrorRecord = if ($proofRun) { Get-NewestJson $proofRun 'proof-error.json' } else { $null }
$terminalRecord = if ($proofRun) { Get-NewestJson $proofRun 'product-lifecycle-terminal.json' } else { $null }
$providerRecord = if ($proofRun) { Get-NewestJson $proofRun 'product-lifecycle-provider-failure.json' } else { $null }
$progressRecord = if ($proofRun) { Get-NewestJson $proofRun 'product-lifecycle-progress-current.json' } else { $null }
$cleanupRecord = if ($proofRun) { Get-NewestJson $proofRun 'cleanup-state.json' } else { $null }
$proofStart = if ($proofStartRecord) { $proofStartRecord.value } else { $null }
$proofFinal = if ($proofFinalRecord) { $proofFinalRecord.value } else { $null }
$proofError = if ($proofErrorRecord) { $proofErrorRecord.value } else { $null }
$terminal = if ($terminalRecord) { $terminalRecord.value } else { $null }
$providerFailure = if ($providerRecord) { $providerRecord.value } else { $null }
$progress = if ($progressRecord) { $progressRecord.value } else { $null }
$proofStartCurrent = $false
$candidateBindingUtc = [datetime]::MinValue
$candidateBindingRaw = Get-FirstProperty $state @('candidate_binding_utc','candidateBindingUtc','finalizer_completed_utc')
try { if($candidateBindingRaw){$candidateBindingUtc=[datetime]::Parse([string]$candidateBindingRaw).ToUniversalTime()} } catch { $candidateBindingUtc=[datetime]::MinValue }
if ($proofStart -and $proofStart.provenance) {
    $proofStartedUtc = [datetime]::MinValue
    $proofStartedRaw = Get-FirstProperty $proofStart @('generatedAtUtc','timestampUtc','startedAtUtc')
    try { if($proofStartedRaw){$proofStartedUtc=[datetime]::Parse([string]$proofStartedRaw).ToUniversalTime()} elseif($proofStartRecord.lastWriteUtc){$proofStartedUtc=[datetime]::Parse([string]$proofStartRecord.lastWriteUtc).ToUniversalTime()} } catch { $proofStartedUtc=[datetime]::MinValue }
    $proofStartCurrent = [string]$proofStart.provenance.repositoryHead -ceq $head -and [string]$proofStart.provenance.candidateCommit -ceq $candidateCommit -and [string]$proofStart.provenance.shippingInputIdentity -ceq $shippingIdentity -and [string]$proofStart.provenance.releaseFingerprint -ceq $releaseId -and [string]$proofStart.provenance.toolingFingerprint -ceq $toolingId -and $proofStartedUtc -ge $candidateBindingUtc
}
# A failed/current smoke supersedes a stale historical proof pointer until a
# newly started proof writes its own current tuple. Preserve all old run files;
# only the current authority pointer is cleared.
if($interactiveCurrent -and [string]$interactiveCurrent.status -ne 'PASS' -and $interactiveSmokeRunId -and (-not $proofStartCurrent)){
    $CurrentProofRunId=$null
    $proofRun=$null;$proofStartRecord=$null;$proofFinalRecord=$null;$proofErrorRecord=$null;$terminalRecord=$null;$providerRecord=$null;$progressRecord=$null;$cleanupRecord=$null
    $proofStart=$null;$proofFinal=$null;$proofError=$null;$terminal=$null;$providerFailure=$null;$progress=$null
}
$certificationEligible = $proofStart -and -not ([bool](Get-FirstProperty $proofStart.provenance @('diagnosticOnly'))) -and (Get-FirstProperty $proofStart.provenance @('certificationEligible')) -ne $false
$proofNaturalPass = $proofStartCurrent -and $certificationEligible -and $proofFinal -and [string]$proofFinal.status -eq 'PASS'
$proofOutcome = if ($proofNaturalPass) { 'PASS' } else { 'NOT_OBSERVED' }
$proofStatus = if ($proofNaturalPass) { 'PASS' } else { 'BLOCKED' }
$terminalPhase = [string](Get-FirstProperty $terminal @('phase'))
$terminalProvider = [string](Get-FirstProperty $terminal @('provider'))
$terminalStable = [string](Get-FirstProperty $terminal @('lastStableStep'))
$terminalError = [string](Get-FirstProperty $terminal @('error','failure','terminalReason'))
if (-not $terminalError -and $proofError) { $terminalError = [string]$proofError.error }

$passingProofs = @()
foreach ($proofId in @($state.proof_run_ids | Where-Object { $_ } | Select-Object -Unique)) {
    $candidateRun = Join-Path $runRoot ([string]$proofId)
    $startRecord = Get-NewestJson $candidateRun 'proof-start.json'; $finalRecord = Get-NewestJson $candidateRun 'proof-final.json'
    if (-not $startRecord -or -not $finalRecord -or -not $startRecord.value.provenance) { continue }
    $p = $startRecord.value.provenance
    $eligible = -not ([bool](Get-FirstProperty $p @('diagnosticOnly'))) -and (Get-FirstProperty $p @('certificationEligible')) -ne $false
    $currentTuple = $eligible -and [string]$p.repositoryHead -ceq $head -and [string]$p.candidateCommit -ceq $candidateCommit -and [string]$p.shippingInputIdentity -ceq $shippingIdentity -and [string]$p.releaseFingerprint -ceq $releaseId -and [string]$p.toolingFingerprint -ceq $toolingId
    $proofStartedUtc=[datetime]::MinValue;$proofStartedRaw=Get-FirstProperty $startRecord.value @('generatedAtUtc','timestampUtc','startedAtUtc');try{if($proofStartedRaw){$proofStartedUtc=[datetime]::Parse([string]$proofStartedRaw).ToUniversalTime()}elseif($startRecord.lastWriteUtc){$proofStartedUtc=[datetime]::Parse([string]$startRecord.lastWriteUtc).ToUniversalTime()}}catch{$proofStartedUtc=[datetime]::MinValue}
    if ($currentTuple -and $proofStartedUtc -ge $candidateBindingUtc -and [string]$finalRecord.value.status -eq 'PASS') { $passingProofs += [ordered]@{runId=[string]$proofId;proofStartPath=$startRecord.relativePath;proofFinalPath=$finalRecord.relativePath;status='PASS'} }
}
$currentCertificationStage = if($CurrentProofRunId -and $proofStartCurrent){'EXACT-CANDIDATE-PROOF'}elseif($interactiveSmokeRunId){'INTERACTIVE-LOGIN-SMOKE'}else{'EXACT-PROOF-NOT-RUN'}

if (-not $FullReleaseRunId) { $FullReleaseRunId = [string]$state.full_release_run_id }
$fullRun = if ($FullReleaseRunId) { Join-Path $runRoot $FullReleaseRunId } else { $null }
$runStateRecord = if ($fullRun) { Get-NewestJson $fullRun 'run-state.json' } else { $null }
$runState = if ($runStateRecord) { $runStateRecord.value } else { $null }
$fullStatus = if ($runState) { [string]$runState.finalStatus } else { 'NOT_RUN_FOR_CURRENT_CANDIDATE' }
$fullCurrent = [bool]$state.full_release_current -and [bool]$FullReleaseRunId
$fullPassed = [bool]$state.full_release_passed -and $fullCurrent -and $fullStatus -match '^PASS'
$fullSummary = [ordered]@{
    schemaVersion=2; generatedAtUtc=(Get-Date).ToUniversalTime().ToString('o'); repositoryHead=$head; candidateGitCommit=$candidateCommit; shippingInputIdentity=$shippingIdentity; candidateShippingInputIdentity=$shippingIdentity; releaseFingerprintId=$releaseId; toolingFingerprintId=$toolingId
    latestRunId=if($FullReleaseRunId){$FullReleaseRunId}else{$null}; status=$fullStatus; fullReleasePassed=$fullPassed; historicalEvidenceOnly=(-not $fullCurrent); diagnosticOnly=(-not $fullPassed); lastCompletedPhase=if($runState){@($runState.completedPhases|Select-Object -Last 1)}else{@()}; currentPhase=if($runState){[string]$runState.currentPhase}else{''}
    candidateTuple=[ordered]@{repositoryHead=$head;candidateCommit=$candidateCommit;shippingInputIdentity=$shippingIdentity;releaseFingerprintId=$releaseId;toolingFingerprintId=$toolingId;exe=[string]$artifactByName.exe.sha256;tar=[string]$artifactByName.tar.sha256;portable=[string]$artifactByName.portable.sha256;installerSource=[string]$artifactByName.installerSource.sha256}
}

$releaseEligible = $candidateSafe -and $passingProofs.Count -ge 2 -and $fullPassed -and $candidateFlags.validationEvidenceCurrent -and $candidateFlags.internalPromotionAllowed
if ($releaseEligible) {
    $status='PASS';$blockerClassification='PASS';$blocker=$null;$nextAction='Preserve the final release state and perform independent bundle verification.'
} elseif (-not $candidateSafe) {
    $status='BLOCKED';$blockerClassification='BLOCKED — CANDIDATE INVALIDATED / PLATFORM AUTHORIZATION'
    $stateBlockers=@($state.blockers | ForEach-Object {[string]$_} | Where-Object {$_})
    $invalidation=[string](Get-FirstProperty $state @('candidate_invalidation_reason','candidateInvalidationReason'))
    $blocker=if($invalidation -and @($stateBlockers | Where-Object {$_.Contains($invalidation)}).Count -gt 0){$stateBlockers -join ' | '}else{(@($invalidation)+$stateBlockers | Where-Object {$_} | Select-Object -Unique) -join ' | '}
    if(-not $blocker){$blocker='The candidate/source/artifact authority tuple is not current.'}
    $nextAction='Under a workspace token with writable canonical Git metadata, commit the prepared batch, rebuild/sign once, bind the new candidate, then resume exact proofs under authorized Hyper-V access.'
} elseif ($proofNaturalPass) {
    $status='BLOCKED';$blockerClassification='BLOCKED — CERTIFICATION INCOMPLETE';$blocker="Current proof $CurrentProofRunId passed, but exact proofs/FullRelease acceptance is incomplete.";$nextAction='Continue the current candidate/tooling certification campaign.'
} elseif ($CurrentProofRunId) {
    $status='BLOCKED';$blockerClassification=if($terminalError -match '(?i)access denied|not authorized|insufficient privileges'){'BLOCKED — EXTERNAL HYPER-V AUTHORIZATION'}elseif($terminalProvider -match 'Checkpoint|Observer|Transition'){'BLOCKED — RELEASE HARNESS / RUNTIME OBSERVABILITY'}else{'BLOCKED — EXACT PROOF NOT OBSERVED'}
    $blocker=("RunId={0}; phase={1}; provider={2}; lastStableStep={3}; outcome={4}; error={5}" -f $CurrentProofRunId,$terminalPhase,$terminalProvider,$terminalStable,$proofOutcome,$terminalError).Trim()
    if ($proofStart -and -not $proofStartCurrent) { $blocker += '; proof-start tuple is historical relative to current tooling authority' }
    $nextAction=if($blockerClassification -match 'EXTERNAL HYPER-V'){'Resume under a token that is already authorized for Hyper-V; do not change Hyper-V security membership from the release harness.'}else{'Run the current instrumented exact-candidate lifecycle and diagnose the recorded terminal evidence.'}
} else {
    $status='BLOCKED';$blockerClassification='BLOCKED — EXACT PROOF NOT RUN';$blocker='No exact proof is bound to the current candidate/tooling tuple.';$nextAction='Run exact proof 1 from the exact clean disposable checkpoint.'
}

if ($TerminalBlocker) {
    $status = 'BLOCKED'
    $blockerClassification = if ($TerminalBlockerClassification) { $TerminalBlockerClassification } else { 'BLOCKED — FINALIZER' }
    $blocker = $TerminalBlocker
    $nextAction = 'Resolve the primary blocker, then resume the current candidate certification boundary.'
}

$proof = [ordered]@{
    schemaVersion=2; authorityGeneratedAtUtc=(Get-Date).ToUniversalTime().ToString('o'); repositoryHead=$head; candidateCommit=$candidateCommit; candidateGitCommit=$candidateCommit; shippingInputIdentity=$shippingIdentity; candidateShippingInputIdentity=$shippingIdentity; releaseFingerprintId=$releaseId; toolingFingerprintId=$toolingId
    candidateIsCurrent=$candidateFlags.candidateIsCurrent; sourceChangedSinceCandidate=$candidateFlags.sourceChangedSinceCandidate; rebuildRequired=$candidateFlags.rebuildRequired
    currentCertificationStage=$currentCertificationStage; currentSmokeRunId=$interactiveSmokeRunId; currentProofRunId=if($CurrentProofRunId){$CurrentProofRunId}else{$null}; candidateBindingUtc=if($candidateBindingUtc -gt [datetime]::MinValue){$candidateBindingUtc.ToString('o')}else{$null}; passingProofs=@($passingProofs)
    runId=if($CurrentProofRunId){$CurrentProofRunId}else{$null}; status=$proofStatus; outcome=$proofOutcome; diagnosticOnly=(-not $certificationEligible); diagnosticOutcome=if($proofFinal){[string]$proofFinal.status}else{'NOT_OBSERVED'}; certificationEligible=$certificationEligible; proofStartCurrent=$proofStartCurrent
    proofStart=if($proofStartCurrent){$proofStart}else{$null}; proofStartPath=if($proofStartCurrent -and $proofStartRecord){$proofStartRecord.relativePath}else{$null}; proofStartHistoricalPath=if(-not $proofStartCurrent -and $proofStartRecord){"release-tooling/historical/$CurrentProofRunId/proof-start.json"}else{$null}; historicalProofStart=if(-not $proofStartCurrent -and $proofStart){[ordered]@{historical=$true;runId=$CurrentProofRunId;repositoryHead=[string]$proofStart.provenance.repositoryHead;candidateCommit=[string]$proofStart.provenance.candidateCommit;toolingFingerprintId=[string]$proofStart.provenance.toolingFingerprint;sourcePath=$proofStartRecord.relativePath}}else{$null}
    proofFinal=$proofFinal; proofFinalPath=if($proofFinalRecord){$proofFinalRecord.relativePath}else{$null}; proofError=$proofError; proofErrorPath=if($proofErrorRecord){$proofErrorRecord.relativePath}else{$null}
    terminal=$terminal; terminalPath=if($terminalRecord){$terminalRecord.relativePath}else{$null}; providerFailure=$providerFailure; providerFailurePath=if($providerRecord){$providerRecord.relativePath}else{$null}; progress=$progress; progressPath=if($progressRecord){$progressRecord.relativePath}else{$null}; cleanup=if($cleanupRecord){$cleanupRecord.value}else{$null}
    phase=$terminalPhase; provider=$terminalProvider; lastStableStep=$terminalStable; terminalError=$terminalError; blockerClassification=$blockerClassification; blocker=$blocker
    currentTuplePassingProofCount=$passingProofs.Count; currentTuplePassingProofs=$passingProofs; fullReleaseRunId=if($FullReleaseRunId){$FullReleaseRunId}else{$null}
}

$authorityCore = [ordered]@{
    schemaVersion=3; generatedAtUtc=(Get-Date).ToUniversalTime().ToString('o'); status=$status; blockerClassification=$blockerClassification; blocker=$blocker; nextAction=$nextAction
    repositoryHead=$head; branch=$branch; candidateCommit=$candidateCommit; shippingInputIdentity=$shippingIdentity; candidateShippingInputIdentity=$shippingIdentity; releaseFingerprintId=$releaseId; toolingFingerprintId=$toolingId
    candidate=$candidate; workingTree=$workingTree; proof=$proof; proofs=[ordered]@{passing=$passingProofs.Count;required=2;status=if($passingProofs.Count -ge 2){'2 / 2 PASS'}else{"$($passingProofs.Count) / 2 PASS"};runs=$passingProofs}; fullRelease=$fullSummary
    candidateIsCurrent=$candidateFlags.candidateIsCurrent; sourceChangedSinceCandidate=$candidateFlags.sourceChangedSinceCandidate; rebuildRequired=$candidateFlags.rebuildRequired; validationEvidenceCurrent=$candidateFlags.validationEvidenceCurrent; fullReleasePassed=$fullPassed; internalPromotionAllowed=[bool]$state.internal_promotion_allowed; publicPromotionAllowed=$false; publicPublisherTrust=$false; currentCertificationStage=$currentCertificationStage; currentSmokeRunId=$interactiveSmokeRunId; currentProofRunId=if($CurrentProofRunId){$CurrentProofRunId}else{$null}; passingProofs=@($passingProofs)
    f005=[ordered]@{attempted=$false;formatterOnlyAuditCleanupPerformed=$false;structuralRefactoringPerformed=$false}
}
$authorityId = Get-StringHash ($authorityCore | ConvertTo-Json -Compress -Depth 40)
$authority = [ordered]@{authorityId=$authorityId} + $authorityCore
$candidate.authorityId=$authorityId;$candidate.status=$status;$candidate.blockerClassification=$blockerClassification
$proof.authorityId=$authorityId;$fullSummary.authorityId=$authorityId

$currentStatus = [ordered]@{schemaVersion=3;authorityId=$authorityId;generatedAtUtc=$authority.generatedAtUtc;status=$status;blockerClassification=$blockerClassification;blocker=$blocker;nextAction=$nextAction;repositoryHead=$head;candidateCommit=$candidateCommit;shippingInputIdentity=$shippingIdentity;candidateShippingInputIdentity=$shippingIdentity;releaseFingerprintId=$releaseId;toolingFingerprintId=$toolingId;workingTree=$workingTree;candidateIsCurrent=$candidateFlags.candidateIsCurrent;sourceChangedSinceCandidate=$candidateFlags.sourceChangedSinceCandidate;rebuildRequired=$candidateFlags.rebuildRequired;validationEvidenceCurrent=$candidateFlags.validationEvidenceCurrent;fullReleasePassed=$fullPassed;internalPromotionAllowed=[bool]$state.internal_promotion_allowed;publicPromotionAllowed=$false;publicPublisherTrust=$false;currentProofRunId=if($CurrentProofRunId){$CurrentProofRunId}else{$null};currentProofOutcome=$proofOutcome;proofsPassed=$passingProofs.Count;proofsRequired=2;fullReleaseRunId=if($FullReleaseRunId){$FullReleaseRunId}else{$null};f005Attempted=$false;productionUnchanged=$true;mulattoTechSurfaceTouched=$false;disposableLabOnly=$true}
$currentGates = [ordered]@{schemaVersion=3;authorityId=$authorityId;generatedAtUtc=$authority.generatedAtUtc;status=$status;repositoryHead=$head;candidateCommit=$candidateCommit;shippingInputIdentity=$shippingIdentity;releaseFingerprintId=$releaseId;toolingFingerprintId=$toolingId;candidate=$candidate;proofs=$authority.proofs;fullRelease=$fullSummary;gates=$state.gates;blockers=if($blocker){@($blocker)}else{@()};currentPhase=[string]$state.current_phase;lastCompletedPhase=[string]$state.last_completed_phase}
$l1 = Read-Json (Join-Path $evidence 'l1-terminal-state.json');$l2 = Read-Json (Join-Path $evidence 'l2-terminal-state.json')
$handoff = [ordered]@{schemaVersion=3;authorityId=$authorityId;historical=$false;generatedAtUtc=$authority.generatedAtUtc;status=$status;blockerClassification=$blockerClassification;blocker=$blocker;nextAction=$nextAction;repositoryHead=$head;candidateCommit=$candidateCommit;shippingInputIdentity=$shippingIdentity;candidateShippingInputIdentity=$shippingIdentity;releaseFingerprintId=$releaseId;toolingFingerprintId=$toolingId;currentProofRunId=if($CurrentProofRunId){$CurrentProofRunId}else{$null};currentProofOutcome=$proofOutcome;phase=$terminalPhase;provider=$terminalProvider;lastStableStep=$terminalStable;terminalError=$terminalError;proofsPassed=$passingProofs.Count;proofsRequired=2;fullReleaseRunId=if($FullReleaseRunId){$FullReleaseRunId}else{$null};fullReleaseStatus=$fullStatus;l1State=if($l1){[string]$l1.state}else{'UNVERIFIED'};l2State=if($l2){if([bool]$l2.present){'PRESENT'}else{'ABSENT'}}else{'UNVERIFIED'};f005Attempted=$false;formatterOnlyAuditCleanup=$false;f005StructuralRefactor=$false;publicPromotionAllowed=$false;publicPublisherTrust=$false}
$next = [ordered]@{schemaVersion=3;authorityId=$authorityId;historical=$false;generatedFrom='evidence/CURRENT-RELEASE-AUTHORITY.json';status=$status;blockerClassification=$blockerClassification;blocker=$blocker;nextAction=$nextAction;repository=[ordered]@{branch=$branch;head=$head;candidateCommit=$candidateCommit};candidate=$candidate;workingTree=$workingTree;runtime=[ordered]@{currentProofRunId=if($CurrentProofRunId){$CurrentProofRunId}else{$null};currentProofOutcome=$proofOutcome;proofs=$authority.proofs;fullRelease=$fullSummary;internalPromotionAllowed=[bool]$state.internal_promotion_allowed;publicPromotionAllowed=$false;publicPublisherTrust=$false};safety=[ordered]@{protectedProductionMutated=$false;hostRebooted=$false;amdRadeonTouched=$false;biosUefiTouched=$false;mulattoTechSurfaceTouched=$false;githubPushed=$false;privateSigningKeyExported=$false};f005=$authority.f005}

Write-AtomicJson (Join-Path $evidence 'CURRENT-RELEASE-AUTHORITY.json') $authority
Write-AtomicJson (Join-Path $Workspace 'CURRENT-CANDIDATE.json') $candidate
Write-AtomicJson (Join-Path $evidence 'CURRENT-STATUS.json') $currentStatus
Write-AtomicJson (Join-Path $evidence 'CURRENT-GATES.json') $currentGates
Write-AtomicJson (Join-Path $evidence 'CURRENT-PROOF.json') $proof
Write-AtomicJson (Join-Path $evidence 'FULLRELEASE-SUMMARY.json') $fullSummary
Write-AtomicJson (Join-Path $evidence 'CURRENT-HANDOFF.json') $handoff
Write-AtomicJson (Join-Path $audit 'CURRENT-HANDOFF.json') $handoff
Write-AtomicJson (Join-Path $audit 'NEXT-CODEX-HANDOFF.json') $next
$nextMd = (@('# DevFleet v1.2.13 current release handoff','',"Authority: $authorityId","Status: $status","Repository/tooling HEAD: $head","Candidate commit: $candidateCommit","Shipping input: $shippingIdentity","Release fingerprint: $releaseId","Tooling fingerprint: $toolingId","Exact proofs: $($passingProofs.Count) / 2 PASS","FullRelease: $fullStatus",'',"Blocker: $(if($blocker){$blocker}else{'None'})","Next action: $nextAction",'','F-005 attempted: NO','Formatter-only F-005 cleanup: NO','F-005 structural refactoring: NO') -join [Environment]::NewLine) + [Environment]::NewLine
Write-AtomicText (Join-Path $audit 'NEXT-CODEX-HANDOFF.md') $nextMd

$mutableState = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -AsHashtable
$mutableState.repository_head=$head;$mutableState.git_commit=$head;$mutableState.current_authority_id=$authorityId;$mutableState.current_proof_run_id=if($CurrentProofRunId){$CurrentProofRunId}else{$null};$mutableState.current_proof_outcome=$proofOutcome;$mutableState.current_proof_updated_utc=$authority.generatedAtUtc;$mutableState.proofs_passed=[int]$passingProofs.Count;$mutableState.proofs_required=2
$mutableState.blockers=if($blocker){@($blocker)}else{@()};$mutableState.status=$status;$mutableState.release_status=$status;$mutableState.public_promotion_allowed=$false;$mutableState.public_publisher_trust=$false
Write-AtomicJson $statePath $mutableState

[pscustomobject]@{schemaVersion=3;authorityId=$authorityId;status=$status;repositoryHead=$head;candidateCommit=$candidateCommit;releaseFingerprintId=$releaseId;toolingFingerprintId=$toolingId;currentProofRunId=$CurrentProofRunId;currentProofOutcome=$proofOutcome;passingProofs=$passingProofs.Count;fullReleaseRunId=$FullReleaseRunId;fullReleaseStatus=$fullStatus;blocker=$blocker} | ConvertTo-Json -Depth 12
