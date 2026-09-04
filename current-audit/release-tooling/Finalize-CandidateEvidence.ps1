[CmdletBinding()]
param([string]$Workspace = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$Workspace = (Resolve-Path -LiteralPath $Workspace).Path
$source = Join-Path $Workspace 'source'
$installer = Join-Path $Workspace 'installer-source'
$outputs = Join-Path $Workspace 'outputs'
Import-Module (Join-Path $Workspace 'automation\release-e2e\modules\Candidate.psm1') -Force
$version = (Get-Content -LiteralPath (Join-Path $source 'VERSION') -Raw).Trim()
$installerVersion = (Get-Content -LiteralPath (Join-Path $installer 'INSTALLER_VERSION') -Raw).Trim()

function Write-AtomicJson([string]$Path,$Value) {
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText($temporary,(($Value | ConvertTo-Json -Depth 20) + [Environment]::NewLine),[Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
}

function Write-AtomicText([string]$Path,[string]$Value) {
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText($temporary,$Value,[Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
}

$artifactPaths = [ordered]@{
    exe = Join-Path $outputs "DevFleet-Setup-v$version-win-x64.exe"
    tar = Join-Path $outputs "devfleet-v$version.tar.gz"
    portable = Join-Path $outputs "DevFleet-v$version-Portable-Codebase-Verified-r1.zip"
    installerSource = Join-Path $outputs "DevFleet-v$version-Installer-Source.zip"
}
foreach ($path in $artifactPaths.Values) { if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Candidate artifact is missing: $path" } }
$artifactRows = @(
    foreach ($name in $artifactPaths.Keys) {
        $path = $artifactPaths[$name]
        [ordered]@{name=$name;path=('outputs/' + [IO.Path]::GetFileName($path));bytes=[int64](Get-Item -LiteralPath $path).Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
    }
)

$status = @(& git -C $Workspace status --short)
$unexpected = @($status | Where-Object {
    $_ -notmatch '^\s*[ MADRCU?]{1,2}\s+finalization-state\.(json|txt)\s*$' -and
    $_ -notmatch '^\s*[ MADRCU?]{1,2}\s+audit(?:\\|/)' -and
    $_ -notmatch '^\s*[ MADRCU?]{1,2}\s+audit-extract(?:\\|/)' -and
    $_ -notmatch '^\s*[ MADRCU?]{1,2}\s+evidence(?:\\|/)' -and
    $_ -notmatch '^\s*[ MADRCU?]{1,2}\s+(?:tools|automation/release-e2e)(?:\\|/)' -and
    $_ -notmatch '^\s*[ MADRCU?]{1,2}\s+source/tools/validate_audit_coherence\.py\s*$' -and
    $_ -notmatch '^\s*[ MADRCU?]{1,2}\s+CURRENT-CANDIDATE\.json\s*$' -and
    $_ -notmatch '^\?\?\s+codex-session-[0-9a-f-]+\.md\s*$'
})
if ($unexpected.Count) { throw "Candidate source/tooling tree is not clean after the generated payload closure commit: $($unexpected -join '; ')" }
$head = (& git -C $Workspace rev-parse HEAD).Trim()
$branch = (& git -C $Workspace branch --show-current).Trim()
if ($head -notmatch '^[0-9a-f]{40}$' -or -not $branch) { throw 'Final candidate Git identity is invalid.' }
$existingState = Get-Content -LiteralPath (Join-Path $Workspace 'finalization-state.json') -Raw | ConvertFrom-Json
$candidateCommit = [string]($existingState.candidate_git_commit ?? $existingState.candidateGitCommit)
if ($candidateCommit -notmatch '^[0-9a-fA-F]{40}$') { throw 'Existing candidate commit is missing or malformed; refusing to bind it to the live HEAD.' }

$identityArguments = @('--workspace',$Workspace,'--candidate-commit',$candidateCommit)
foreach ($name in $artifactPaths.Keys) { $identityArguments += @('--artifact',"$name=$($artifactPaths[$name])") }
$identityRaw = @(& python (Join-Path $Workspace 'tools\compute_shipping_input_identity.py') @identityArguments)
if ($LASTEXITCODE -ne 0 -or $identityRaw.Count -eq 0) { throw 'Candidate Git-object fingerprint regeneration failed.' }
try { $identity = ($identityRaw -join "`n") | ConvertFrom-Json } catch { throw "Candidate fingerprint output was not valid JSON: $($_.Exception.Message)" }
$candidateIdentity = [string]$identity.candidateShippingInputIdentity
$existingCandidateIdentity = [string]($existingState.shipping_input_identity ?? $existingState.shippingInputIdentity)
if ($candidateIdentity -notmatch '^[0-9a-f]{64}$') { throw 'Candidate Git-object shipping identity is malformed.' }
$generatedAuthorityRefresh = [string]::IsNullOrWhiteSpace($existingCandidateIdentity)
if ($generatedAuthorityRefresh) {
    if (-not [bool]$existingState.candidate_is_current -or -not [bool]$existingState.candidate_build_current -or [bool]$existingState.source_changed_since_candidate -or [bool]$existingState.rebuild_required) {
        throw 'Generated candidate authority omitted its shipping identity outside the exact fresh-build state.'
    }
} elseif ($existingCandidateIdentity -notmatch '^[0-9a-f]{64}$' -or $candidateIdentity -cne $existingCandidateIdentity) {
    throw 'Candidate Git-object shipping identity differs from the preserved signed-candidate authority.'
}
if ([string]$identity.liveShippingInputIdentity -cne $candidateIdentity -and -not [bool]$identity.crlfOnlyMaterialization) { throw 'Live shipping inputs differ substantively from the preserved candidate; rebuild/sign review is required.' }
if ([string]$identity.lineEndingComparison -notin @('BYTE_EXACT','CRLF_ONLY')) { throw 'Live/candidate materialization comparison is not release-safe.' }
$fingerprint = $identity.candidateFingerprint
if (-not $fingerprint -or [int]$fingerprint.schemaVersion -ne 2) { throw 'Candidate Git-object materialization did not produce release fingerprint schema v2.' }
$existingReleaseId = [string]$existingState.releaseFingerprintId
if ([string]$fingerprint.releaseFingerprintId -notmatch '^[0-9a-f]{64}$' -or [string]$fingerprint.releaseFingerprintId -cne $existingReleaseId) { throw 'Candidate Git-object release fingerprint differs from the preserved signed-candidate authority.' }
$fingerprint | Add-Member -NotePropertyName toolingFingerprint -NotePropertyValue $identity.liveToolingFingerprint -Force
$candidateArtifactMap = @{}; foreach ($row in @($fingerprint.artifacts)) { $candidateArtifactMap[[string]$row.name] = $row }
foreach ($row in $artifactRows) {
    $candidateArtifact = $candidateArtifactMap[[string]$row.name]
    if (-not $candidateArtifact -or [int64]$candidateArtifact.bytes -ne [int64]$row.bytes -or [string]$candidateArtifact.sha256 -cne [string]$row.sha256) { throw "Candidate release fingerprint artifact tuple differs at $($row.name)." }
}
if ($candidateArtifactMap.Count -ne $artifactRows.Count) { throw 'Candidate release fingerprint artifact tuple is not exactly the four release artifacts.' }
Write-AtomicJson (Join-Path $outputs 'release-fingerprint.json') $fingerprint

$toolingCurrent = [ordered]@{schemaVersion=2;releaseFingerprintSchemaVersion=2;releaseFingerprintId=$fingerprint.releaseFingerprintId;toolingFingerprintId=$identity.liveToolingFingerprint.toolingFingerprintId;toolingInputs=$identity.liveToolingFingerprint.toolingInputs;artifacts=$artifactRows;candidateGitCommit=$candidateCommit;shippingInputIdentity=$candidateIdentity;lineEndingComparison=[string]$identity.lineEndingComparison;crlfOnlyPaths=@($identity.crlfOnlyPaths);generatedAt=(Get-Date).ToUniversalTime().ToString('o')}
Write-AtomicJson (Join-Path $outputs 'tooling-fingerprint-current.json') $toolingCurrent
$providerPath = Join-Path $outputs 'signing-provider.json'
if (-not (Test-Path -LiteralPath $providerPath -PathType Leaf)) { throw 'Signed candidate provider evidence is missing.' }
$provider = Get-Content -LiteralPath $providerPath -Raw | ConvertFrom-Json -ErrorAction Stop
$signing = 'PRIVATE SELF-SIGNED AUTHENTICODE — VALID ON EXPLICITLY TRUSTED PERSONAL/TEST SYSTEMS'
$exeRow = @($artifactRows | Where-Object name -eq 'exe')
$publicCertificatePath = Join-Path $outputs 'DevFleet-Private-Personal-Code-Signing.cer'
if (-not (Test-Path -LiteralPath $publicCertificatePath -PathType Leaf)) { throw 'Private signing public verifier certificate is missing.' }
$authenticode = Test-PrivateAuthenticodeSignature -Path $artifactPaths.exe -PublicCertificatePath $publicCertificatePath -ExpectedThumbprint ([string]$provider.signerThumbprint)
$signature = Get-AuthenticodeSignature -LiteralPath $artifactPaths.exe
$providerProfile = if ([string]$provider.privateSigningProfile) { [string]$provider.privateSigningProfile } elseif ([string]$provider.signingProfile -eq 'PrivateSelfSigned') { 'PRIVATE_SELF_SIGNED' } else { '' }
$providerPrivateKeyExportable = if ($null -eq $provider.privateKeyExportable) { $false } else { [bool]$provider.privateKeyExportable }
$providerPrivateKeyExported = if ($null -eq $provider.privateKeyExported) { $false } else { [bool]$provider.privateKeyExported }
$providerPublicPublisherTrust = if ($null -eq $provider.publicPublisherTrust) { $false } else { [bool]$provider.publicPublisherTrust }
$providerPublicPromotionAllowed = if ($null -eq $provider.publicPromotionAllowed) { $false } else { [bool]$provider.publicPromotionAllowed }
$providerCodeSigningEku = if ([string]$provider.codeSigningEku) { [string]$provider.codeSigningEku } else { '1.3.6.1.5.5.7.3.3' }
$providerRsaBits = if ([int]$provider.rsaBits -gt 0) { [int]$provider.rsaBits } else { [int]$signature.SignerCertificate.PublicKey.Key.KeySize }
$providerTamperStatus = if ([string]$provider.tamperedCopyVerification) { [string]$provider.tamperedCopyVerification } else { [string]$provider.tamperedCopyStatus }
if ($exeRow.Count -ne 1 -or $providerProfile -ne 'PRIVATE_SELF_SIGNED') { throw 'Signed candidate provider profile is invalid.' }
if ($providerPrivateKeyExportable -or $providerPrivateKeyExported -or $providerPublicPublisherTrust -or $providerPublicPromotionAllowed) { throw 'Signed candidate provider violates the private-signing safety contract.' }
if ([string]$provider.finalSignedExe.sha256 -ne [string]$exeRow[0].sha256 -or [int64]$provider.finalSignedExe.bytes -ne [int64]$exeRow[0].bytes) { throw 'Signed candidate provider identity differs from the exact EXE.' }
if ([string]$authenticode.status -ne 'PASS' -or [string]$authenticode.effectiveSignatureStatus -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -cne [string]$provider.signerThumbprint) { throw 'Exact signed candidate Authenticode verification failed.' }
if ('1.3.6.1.5.5.7.3.3' -notin @($signature.SignerCertificate.EnhancedKeyUsageList | ForEach-Object { [string]$_.ObjectId })) { throw 'Exact signed candidate lacks the Code Signing EKU.' }
$canonicalProvider = [ordered]@{
    schemaVersion = 1
    provider = [string]$provider.provider
    signingProfile = 'PrivateSelfSigned'
    privateSigningProfile = 'PRIVATE_SELF_SIGNED'
    timestampState = [string]$provider.timestampState
    signatureStatus = [string]$authenticode.effectiveSignatureStatus
    platformSignatureStatus = [string]$authenticode.platformSignatureStatus
    platformSignatureStatusMessage = [string]$authenticode.platformSignatureStatusMessage
    signerSubject = [string]$provider.signerSubject
    signerThumbprint = [string]$provider.signerThumbprint
    codeSigningEkuVerified = $true
    codeSigningEku = $providerCodeSigningEku
    rsaBits = $providerRsaBits
    signtoolVerification = [string]$provider.signtoolVerification
    tamperedCopyVerification = [string]$authenticode.tamperedCopyStatus
    explicitTrustValidation = [string]$authenticode.explicitTrustValidation
    trustMode = [string]$authenticode.trustMode
    trustStoreMutated = [bool]$authenticode.trustStoreMutated
    preSignExe = $provider.preSignExe
    finalSignedExe = $provider.finalSignedExe
    publicCertificate = $provider.publicCertificate
    privateKeyExportable = $providerPrivateKeyExportable
    privateKeyExported = $providerPrivateKeyExported
    publicPublisherTrust = $providerPublicPublisherTrust
    publicPromotionAllowed = $providerPublicPromotionAllowed
}
Write-AtomicJson $providerPath $canonicalProvider
$provider = [pscustomobject]$canonicalProvider
$manifest = [ordered]@{schemaVersion=2;releaseFingerprintSchemaVersion=2;releaseVersion=$version;installerVersion=$installerVersion;repositoryHead=$head;gitCommit=$head;branch=$branch;candidateGitCommit=$candidateCommit;shippingInputIdentity=$candidateIdentity;releaseFingerprintId=$fingerprint.releaseFingerprintId;toolingFingerprintId=$identity.liveToolingFingerprint.toolingFingerprintId;artifacts=$artifactRows;preSignExe=$provider.preSignExe;sourceChangedSinceCandidate=$false;rebuildRequired=$false;sourceIdentityMatchesCandidate=$true;artifactTupleMatchesCandidate=$true;candidateBuildCurrent=$true;candidateIsCurrent=$true;validationEvidenceCurrent=$false;fullReleasePassed=$false;physicalSurrogateCertificationCurrent=$false;internalPromotionAllowed=$false;publicPromotionAllowed=$false;releaseStatus='BLOCKED';signingState=$signing;signing=$signing;privateSigningProfile='PRIVATE_SELF_SIGNED';privateSigningCertificateThumbprint=[string]$provider.signerThumbprint;signerSubject=[string]$provider.signerSubject;codeSigningEku=[string]$provider.codeSigningEku;rsaBits=[int]$provider.rsaBits;privateKeyExportable=$false;privateKeyExported=$false;publicCertificate=$provider.publicCertificate;publicPublisherTrust=$false;timestampState=[string]$provider.timestampState;gitClean=($status.Count -eq 0);lineEndingComparison=[string]$identity.lineEndingComparison;crlfOnlyPaths=@($identity.crlfOnlyPaths)}
Write-AtomicJson (Join-Path $outputs 'final-artifact-hashes.json') $manifest

$statePath = Join-Path $Workspace 'finalization-state.json'
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -AsHashtable
$previousFullReleasePassed=[bool]$state.full_release_passed
$previousFullReleaseRunId=[string]$state.full_release_run_id
$state.release_version=$version;$state.installer_version=$installerVersion;$state.branch=$branch;$state.repository_head=$head;$state.git_commit=$head;$state.candidate_git_commit=$candidateCommit
$state.release_fingerprint_schema_version=2;$state.releaseFingerprintId=$fingerprint.releaseFingerprintId;$state.toolingFingerprintId=$identity.liveToolingFingerprint.toolingFingerprintId
$state.shipping_input_identity=$candidateIdentity
$state.source_changed_since_candidate=$false;$state.rebuild_required=$false;$state.source_identity_matches_candidate=$true;$state.artifact_tuple_matches_candidate=$true;$state.candidate_build_current=$true;$state.candidate_is_current=$true
$state.validation_evidence_current=$false;$state.full_release_passed=$false;$state.internal_promotion_allowed=$false;$state.public_promotion_allowed=$false;$state.public_publisher_trust=$false;$state.release_status='BLOCKED';$state.signing_state=$signing
$state.private_signing_profile='PRIVATE_SELF_SIGNED';$state.private_signing_certificate_thumbprint=[string]$provider.signerThumbprint;$state.signing_subject=[string]$provider.signerSubject;$state.signing_code_signing_eku=[string]$provider.codeSigningEku;$state.signing_rsa_bits=[int]$provider.rsaBits;$state.private_key_exportable=$false;$state.private_key_exported=$false;$state.timestamp_state=[string]$provider.timestampState;$state.pre_sign_exe=$provider.preSignExe;$state.public_signing_certificate=$provider.publicCertificate
$state.current_phase='PRE-EXACT-PROOF';$state.last_completed_phase='CANDIDATE-EVIDENCE-BINDING';$state.status='BLOCKED — fresh exact-candidate proofs and FullRelease required'
$state.candidate_binding_utc=(Get-Date).ToUniversalTime().ToString('o')
if ($previousFullReleaseRunId -and -not $previousFullReleasePassed) {
    $state.historical_full_release_run_ids=@(@($state.historical_full_release_run_ids)+$previousFullReleaseRunId | Select-Object -Unique)
    $state.full_release_run_id=$null
}
if ($state.ai_audit_bundle) { $state.ai_audit_bundle.current=$false;$state.ai_audit_bundle.historical=$true;$state.ai_audit_bundle.historicalReason='Superseded by current release-tooling HEAD.' }
$state.blockers=@('Fresh exact-candidate proof 1 and proof 2 are required.','Fresh coherent FullRelease and maintenance 5/5 are required.')
$state.candidate=[ordered]@{exe=$artifactRows[0];tar=$artifactRows[1];portable=$artifactRows[2];installer_source=$artifactRows[3]}
Write-AtomicJson $statePath $state
$stateText=(@("DevFleet $version / Installer $installerVersion",'Status: candidate current; awaiting exact-candidate proofs and coherent FullRelease',"Repository/tooling HEAD: $head","Candidate commit: $candidateCommit","Shipping input identity: $candidateIdentity","Release fingerprint schema: 2","Release fingerprint: $($fingerprint.releaseFingerprintId)","Tooling fingerprint: $($identity.liveToolingFingerprint.toolingFingerprintId)","Line-ending comparison: $([string]$identity.lineEndingComparison)",'Signing: PRIVATE SELF-SIGNED AUTHENTICODE — VALID ON EXPLICITLY TRUSTED PERSONAL/TEST SYSTEMS','Source changed since candidate: FALSE','Rebuild required: FALSE','Candidate is current: TRUE','Acceptance gates remain unpromoted until current exact-candidate evidence exists.') -join [Environment]::NewLine) + [Environment]::NewLine
Write-AtomicText (Join-Path $Workspace 'finalization-state.txt') $stateText
$authorityOutput = @(& (Join-Path $Workspace 'tools\Update-CurrentReleaseAuthority.ps1') -Workspace $Workspace)
if ($LASTEXITCODE -ne 0 -or $authorityOutput.Count -eq 0) { throw 'Current release authority refresh failed after candidate evidence binding.' }
[pscustomobject]@{schemaVersion=2;gitCommit=$head;candidateGitCommit=$candidateCommit;shippingInputIdentity=$candidateIdentity;releaseFingerprintId=$fingerprint.releaseFingerprintId;toolingFingerprintId=$identity.liveToolingFingerprint.toolingFingerprintId;lineEndingComparison=[string]$identity.lineEndingComparison;artifacts=$artifactRows} | ConvertTo-Json -Depth 8
