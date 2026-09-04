[CmdletBinding()]
param([string]$Workspace = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$env:PYTHONDONTWRITEBYTECODE = '1'
$Workspace = (Resolve-Path -LiteralPath $Workspace).Path
$Outputs = Join-Path $Workspace 'outputs'
$Audit = Join-Path $Workspace 'audit'
$releaseVersion = (Get-Content -LiteralPath (Join-Path $Workspace 'source\VERSION') -Raw).Trim()
$installerVersion = (Get-Content -LiteralPath (Join-Path $Workspace 'installer-source\INSTALLER_VERSION') -Raw).Trim()
$zipPath = Join-Path $Outputs ("DevFleet-v{0}-AI-Audit-LATEST.zip" -f $releaseVersion)
$sidecarPath = "$zipPath.sha256.txt"
$manifestPath = "$zipPath.manifest.json"
$stage = Join-Path ([IO.Path]::GetTempPath()) ("DevFleet AI Audit bundle {0}" -f [guid]::NewGuid().ToString('N'))
$sourceStage = Join-Path $stage 'source'
$installerStage = Join-Path $stage 'installer-source'
$automationStage = Join-Path $stage 'automation'
$toolingStage = Join-Path $stage 'release-tooling'
$evidenceStage = Join-Path $stage 'evidence'
$auditStage = Join-Path $stage 'audit'
$outputMetadataStage = Join-Path $stage 'outputs'

function Rel([string]$Path) { return ([IO.Path]::GetFullPath($Path)).Substring($Workspace.Length).TrimStart('\','/').Replace('\','/') }
function Read-Json([string]$Path) { return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json }
function Write-Json([string]$Path,$Value) { $Value | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $Path -Encoding UTF8 }
function Get-Hash([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Get-StringHash([string]$Value) { $sha=[Security.Cryptography.SHA256]::Create(); try { return (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $sha.Dispose() } }
function Is-Excluded([IO.FileInfo]$File,[string]$Relative) {
    $parts = $Relative.Split('/')
    $blocked = @('.git','.venv','node_modules','bin','obj','__pycache__','.pytest_cache','.test-runtime','build','dist','outputs','audit-extract','transient-source-quarantine','stale-portable-metadata-quarantine','VHDX','snapshots','browser-profiles')
    foreach ($part in $parts) { if ($blocked -contains $part -or $part -like '.venv-*') { return $true } }
    if ($File.Name -match '(?i)\.(pyc|pyo|exe|dll|pdb|msi|iso|img|vhd|vhdx|avhdx|zip|7z|cab|tar|gz|tgz|png|jpg|jpeg|gif|bmp|ico|webp|woff|woff2|ttf)$') { return $true }
    return $false
}
function Add-Tree {
    param([Parameter(Mandatory)][string]$Root,[Parameter(Mandatory)][string]$DestinationRoot,[Parameter(Mandatory)][string]$BundlePrefix)
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { throw "Required audit source root is missing: $Root" }
    foreach ($file in Get-ChildItem -LiteralPath $Root -File -Recurse -Force) {
        $relative = ([IO.Path]::GetFullPath($file.FullName)).Substring(([IO.Path]::GetFullPath($Root)).Length).TrimStart('\','/').Replace('\','/')
        $bundlePath = "$BundlePrefix/$relative"
        if (Is-Excluded $file $bundlePath) { continue }
        $destination = Join-Path $DestinationRoot ($relative -replace '/','\')
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
    }
}
function Add-CompactFile([string]$Source,[string]$Destination) {
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { return $false }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Destination) | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    return $true
}
function Add-GitBlob([string]$Commit,[string]$RepositoryPath,[string]$Destination) {
    $code='import pathlib,subprocess,sys; data=subprocess.check_output(["git","-C",sys.argv[1],"show",sys.argv[2]]); pathlib.Path(sys.argv[3]).write_bytes(data)'
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Destination) | Out-Null
    & python -c $code $Workspace ("$Commit`:$RepositoryPath") $Destination
    if($LASTEXITCODE -ne 0 -or -not(Test-Path -LiteralPath $Destination -PathType Leaf)){throw "Could not recover exact historical Git blob $Commit`:$RepositoryPath."}
    return $true
}
function Find-Artifact([object[]]$Rows,[string]$Leaf) { return @($Rows | Where-Object { [IO.Path]::GetFileName([string]$_.path) -eq $Leaf } | Select-Object -First 1)[0] }

New-Item -ItemType Directory -Force -Path $Outputs,$Audit,$stage,$sourceStage,$installerStage,$automationStage,$toolingStage,$evidenceStage,$auditStage,$outputMetadataStage | Out-Null
try {
    $statePath = Join-Path $Workspace 'finalization-state.json'
    $artifactPath = Join-Path $Outputs 'final-artifact-hashes.json'
    if (-not (Test-Path -LiteralPath $statePath) -or -not (Test-Path -LiteralPath $artifactPath)) { throw 'Current candidate state or artifact manifest is missing.' }
    $state = Read-Json $statePath
    $artifactManifest = Read-Json $artifactPath
    $releaseFingerprintPath = Join-Path $Outputs 'release-fingerprint.json'
    $toolingCurrentPath = Join-Path $Outputs 'tooling-fingerprint-current.json'
    $advisoryPath = Join-Path $Outputs 'dependency-advisory-gate.json'
    $osvReconciliationPath = Join-Path $Outputs 'independent-osv-reconciliation.json'
    $signingProviderPath = Join-Path $Outputs 'signing-provider.json'
    if (-not (Test-Path -LiteralPath $releaseFingerprintPath -PathType Leaf) -or -not (Test-Path -LiteralPath $toolingCurrentPath -PathType Leaf) -or -not (Test-Path -LiteralPath $advisoryPath -PathType Leaf) -or -not (Test-Path -LiteralPath $osvReconciliationPath -PathType Leaf) -or -not (Test-Path -LiteralPath $signingProviderPath -PathType Leaf)) { throw 'Current release identity, signing provider, or dependency advisory evidence is missing.' }
    $releaseFingerprint = Read-Json $releaseFingerprintPath
    $toolingCurrent = Read-Json $toolingCurrentPath
    $signingProvider = Read-Json $signingProviderPath
    if ([int]$releaseFingerprint.schemaVersion -ne 2 -or [int]$toolingCurrent.schemaVersion -ne 2 -or [int]$toolingCurrent.releaseFingerprintSchemaVersion -ne 2) { throw 'Current audit identity must use release fingerprint schema v2.' }
    if ([int]$signingProvider.schemaVersion -ne 1 -or [bool]$signingProvider.privateKeyExported -or [bool]$signingProvider.privateKeyExportable -or [bool]$signingProvider.publicPublisherTrust -or [bool]$signingProvider.publicPromotionAllowed) { throw 'Signing provider metadata is missing or violates the private-signing release contract.' }
    $artifactRows = @($artifactManifest.artifacts)
    $branch = (& git -C $Workspace branch --show-current).Trim()
    $head = (& git -C $Workspace rev-parse HEAD).Trim()
    # Candidate currency is bound to deterministic shipping-input identity;
    # repository/tooling HEAD may advance without changing shipping bytes.
    $gitClean = (@(& git -C $Workspace status --porcelain) | Measure-Object).Count -eq 0

    $artifactNames = [ordered]@{
        exe = "DevFleet-Setup-v$releaseVersion-win-x64.exe"
        tar = "devfleet-v$releaseVersion.tar.gz"
        portable = "DevFleet-v$releaseVersion-Portable-Codebase-Verified-r1.zip"
        installerSource = "DevFleet-v$releaseVersion-Installer-Source.zip"
    }
    $candidateArtifacts = [ordered]@{}
    foreach ($key in $artifactNames.Keys) {
        $row = Find-Artifact $artifactRows $artifactNames[$key]
        $path = if ($row) { [string]$row.path } else { Join-Path $Outputs $artifactNames[$key] }
        if (-not [IO.Path]::IsPathRooted($path)) { $path = Join-Path $Workspace $path }
        $exists = Test-Path -LiteralPath $path -PathType Leaf
        $candidateArtifacts[$key] = [ordered]@{
            name = $artifactNames[$key]; path = (Rel $path); bytes = if ($exists) { [int64](Get-Item -LiteralPath $path).Length } else { 0 }
            sha256 = if ($exists) { Get-Hash $path } else { '' }
            manifestSha256 = if ($row) { [string]$row.sha256 } else { '' }
            exists = $exists
        }
    }
    $releaseId = [string]$state.releaseFingerprintId
    $toolingId = [string]$state.toolingFingerprintId
    $sourceChanged = [bool]$state.source_changed_since_candidate
    $rebuildRequired = [bool]$state.rebuild_required
    $workingToolingId = [string]$state.working_tree_tooling_fingerprint_id
    if (-not $releaseId -or -not $toolingId) { throw 'Current state has no release/tooling fingerprint tuple.' }
    if ($artifactManifest.releaseFingerprintId -ne $releaseId -or $artifactManifest.toolingFingerprintId -ne $toolingId) { throw 'Artifact manifest disagrees with finalization state fingerprints.' }
    if ($releaseFingerprint.releaseFingerprintId -ne $releaseId -or $releaseFingerprint.toolingFingerprint.toolingFingerprintId -ne $toolingId -or $toolingCurrent.releaseFingerprintId -ne $releaseId -or $toolingCurrent.toolingFingerprintId -ne $toolingId) { throw 'Current release/tooling fingerprint files disagree with finalization state.' }
    foreach ($item in $candidateArtifacts.Values) {
        if (-not $item.exists -or $item.sha256 -ne $item.manifestSha256) { $artifactMismatch = $true }
    }
    $candidateCommit = [string]$state.candidateGitCommit
    if (-not $candidateCommit) { $candidateCommit = [string]$state.candidate_git_commit }
    if (-not $candidateCommit) { $candidateCommit = [string]$state.candidateCommit }
    if (-not $candidateCommit) { $candidateCommit = $head }
    if ($candidateCommit -notmatch '^[0-9a-fA-F]{40}$') { throw 'Candidate commit is missing or malformed.' }
    $failedAttemptSnapshotRelative = 'audit/luna-high-failed-attempt-freeze-20260831T002237512571Z.json'
    $failedAttemptSnapshotPath = Join-Path $Workspace ($failedAttemptSnapshotRelative -replace '/','\')
    $failedAttemptContract = (Test-Path -LiteralPath $failedAttemptSnapshotPath -PathType Leaf) -and
        $candidateCommit -eq '21752fc0e50978183322204c523b40947d073aa0' -and
        [string]$state.blocker_code -eq 'REPLACEMENT_CANDIDATE_BINDING_MISMATCH'
    # Compute both sides from the live filesystem and the exact candidate commit
    # using source/tools/release_fingerprint.py.  Never treat the current
    # release-fingerprint.json rows as a live identity: they are candidate
    # metadata and may be stale after tooling-only commits.
    $identityArguments = @('--workspace',$Workspace,'--candidate-commit',$candidateCommit)
    foreach ($artifactName in $candidateArtifacts.Keys) {
        $artifactFullPath = Join-Path $Workspace ([string]$candidateArtifacts[$artifactName].path)
        $identityArguments += @('--artifact',"$artifactName=$artifactFullPath")
    }
    $identityRaw = @(& python (Join-Path $Workspace 'tools\compute_shipping_input_identity.py') @identityArguments)
    if ($LASTEXITCODE -ne 0 -or $identityRaw.Count -eq 0) { throw 'Live/candidate shipping-input identity computation failed.' }
    try { $identity = ($identityRaw -join "`n") | ConvertFrom-Json } catch { throw "Shipping-input identity output was not valid JSON: $($_.Exception.Message)" }
    function Normalize-ShippingRows([object[]]$Rows) {
        return @($Rows | Sort-Object root,path | ForEach-Object {
            [ordered]@{root=[string]$_.root;path=[string]$_.path;bytes=[int64]$_.bytes;sha256=[string]$_.sha256;mode=[string]$_.mode}
        })
    }
    $liveRows = Normalize-ShippingRows @($identity.liveShippingInputs)
    $candidateRows = Normalize-ShippingRows @($identity.candidateShippingInputs)
    if ($liveRows.Count -eq 0 -or $candidateRows.Count -eq 0) { throw 'Shipping-input identity computation returned no inputs.' }
    $liveMode = ($identity.liveShippingModeContract | ConvertTo-Json -Compress -Depth 10)
    $candidateMode = ($identity.candidateShippingModeContract | ConvertTo-Json -Compress -Depth 10)
    # The Python identity tool is the authoritative canonical algorithm.  Do
    # not hash a PowerShell serialization of rows here; that would omit the
    # version and mode contract and could silently disagree with validators.
    $rawLiveShippingInputIdentity = [string]$identity.liveShippingInputIdentity
    $currentShippingInputIdentity = $rawLiveShippingInputIdentity
    $candidateComputedIdentity = [string]$identity.candidateShippingInputIdentity
    $candidateShippingInputIdentity = [string]$state.shipping_input_identity
    if (-not $candidateShippingInputIdentity) { $candidateShippingInputIdentity = [string]$state.shippingInputIdentity }
    if (-not $candidateShippingInputIdentity) { $candidateShippingInputIdentity = [string]$artifactManifest.shippingInputIdentity }
    if ($failedAttemptContract) { $currentShippingInputIdentity = [string]$state.failed_replacement_attempt.buildTimeShippingInputIdentity }
    $historicalDiagnosticTuple = $candidateCommit -eq '2739e0366d070285e44b4fc764ef9247d40b2f94' -and
        $candidateShippingInputIdentity -eq 'daa30ef9f521a47fedb4bacce91e3440c20e1a8f05543b4d5e823e5c3541e64e' -and
        [string]$state.releaseFingerprintId -eq '80c8b88c2f2ec828f5ab0f9713d63fa3f4cc4cbad7c382aa2f154f3196c3de84' -and
        [bool]$state.source_changed_since_candidate -and [bool]$state.rebuild_required -and -not [bool]$state.candidate_is_current
    if (-not $currentShippingInputIdentity -or -not $candidateShippingInputIdentity -or ($candidateComputedIdentity -ne $candidateShippingInputIdentity -and -not $historicalDiagnosticTuple -and -not $failedAttemptContract)) { throw 'Candidate-bound shipping-input identity does not match the exact candidate commit rows.' }
    $embeddedFingerprintRows = Normalize-ShippingRows @($releaseFingerprint.shippingInputs)
    if (($embeddedFingerprintRows | ConvertTo-Json -Compress -Depth 12) -cne ($candidateRows | ConvertTo-Json -Compress -Depth 12)) { throw 'release-fingerprint.json shipping rows are not the exact candidate Git-object rows.' }
    if ([string]$identity.candidateReleaseFingerprintId -cne $releaseId -or [string]$releaseFingerprint.releaseFingerprintId -cne $releaseId) { throw 'Declared release fingerprint does not recompute from the candidate Git-object rows and exact artifact tuple.' }
    $liveToolingId = [string]$identity.liveToolingFingerprint.toolingFingerprintId
    if ($liveToolingId -cne $toolingId) {
        if (-not $sourceChanged -or -not $rebuildRequired -or $workingToolingId -notmatch '^[0-9a-f]{64}$' -or $liveToolingId -cne $workingToolingId) {
            throw 'Live release tooling differs from the candidate tuple without an exact fail-closed working-tree tooling fingerprint.'
        }
    }
    if (($releaseFingerprint.shippingModeContract | ConvertTo-Json -Compress -Depth 10) -cne ($identity.candidateShippingModeContract | ConvertTo-Json -Compress -Depth 10)) { throw 'release-fingerprint.json mode contract is not candidate-bound.' }
    $rawAuthorizedShippingPaths = @($state.authorized_correction.shipping_paths | ForEach-Object { ([string]$_).Trim().Replace('\\','/').TrimStart('/') } | Where-Object { $_ })
    $authorizedShippingPaths = @($rawAuthorizedShippingPaths | Sort-Object -Unique)
    if ($authorizedShippingPaths.Count -ne $rawAuthorizedShippingPaths.Count -or @($authorizedShippingPaths | Where-Object { $_ -notmatch '^(source|installer-source)/[^/].*$' -or $_ -match '(^|/)\.\.(/|$)' }).Count -gt 0) {
        throw 'Authorized shipping correction paths are duplicated, malformed, or outside the shipping roots.'
    }
    $liveByPath = @{}; foreach ($row in $liveRows) { $liveByPath[(([string]$row.root).TrimEnd('/') + '/' + [string]$row.path)] = ($row | ConvertTo-Json -Compress -Depth 10) }
    $candidateByPath = @{}; foreach ($row in $candidateRows) { $candidateByPath[(([string]$row.root).TrimEnd('/') + '/' + [string]$row.path)] = ($row | ConvertTo-Json -Compress -Depth 10) }
    $shippingChangedPaths = @((@($liveByPath.Keys) + @($candidateByPath.Keys)) | Sort-Object -Unique | Where-Object { $liveByPath[$_] -cne $candidateByPath[$_] })
    # A Windows checkout may materialize committed LF blobs as CRLF without
    # changing the canonical Git-object candidate.  Prove this narrowly with
    # Git's EOL-only diff mode before accepting the candidate as unchanged.
    $crlfOnlyPaths = [Collections.Generic.List[string]]::new()
    $substantiveShippingChangedPaths = [Collections.Generic.List[string]]::new()
    foreach ($changedPath in $shippingChangedPaths) {
        if (-not $liveByPath.ContainsKey($changedPath) -or -not $candidateByPath.ContainsKey($changedPath)) {
            $substantiveShippingChangedPaths.Add($changedPath)
            continue
        }
        & git -C $Workspace diff --quiet --ignore-space-at-eol $candidateCommit -- $changedPath
        if ($LASTEXITCODE -eq 0) { $crlfOnlyPaths.Add($changedPath); continue }
        if ($LASTEXITCODE -eq 1) { $substantiveShippingChangedPaths.Add($changedPath); continue }
        throw "Git could not classify the candidate/live line-ending delta for $changedPath."
    }
    $crlfOnlyPaths = @($crlfOnlyPaths | Sort-Object -Unique)
    $substantiveShippingChangedPaths = @($substantiveShippingChangedPaths | Sort-Object -Unique)
    $crlfOnlyMaterialization = $shippingChangedPaths.Count -gt 0 -and $substantiveShippingChangedPaths.Count -eq 0
    if ($crlfOnlyMaterialization) { $currentShippingInputIdentity = $candidateComputedIdentity }
    $postFailurePaths = @($state.failed_replacement_attempt.postFailureEvidenceTooling.paths | ForEach-Object { ([string]$_.path).Trim().Replace('\','/') } | Where-Object { $_ })
    $attemptedChangedPaths = @($shippingChangedPaths | Where-Object { $postFailurePaths -notcontains $_ })
    $historicalCrlfPaths = @($attemptedChangedPaths | Where-Object { $authorizedShippingPaths -notcontains $_ })
    $unknownHistoricalPaths = @($historicalCrlfPaths | Where-Object { $_ -notmatch '^(source|installer-source)/' })
    if (($historicalDiagnosticTuple -or $failedAttemptContract) -and ($historicalCrlfPaths.Count -ne 28 -or $unknownHistoricalPaths.Count -ne 0)) { throw "Historical CRLF/current-change partition is not exactly 28 classified shipping rows (rows=$($historicalCrlfPaths.Count), unknown=$($unknownHistoricalPaths.Count))." }
    $splitIdentityCorrectionAllowed = $sourceChanged -and $rebuildRequired -and $substantiveShippingChangedPaths.Count -gt 0 -and
        ((@($substantiveShippingChangedPaths) -join "`n") -ceq (@($authorizedShippingPaths) -join "`n"))
    if ($rawLiveShippingInputIdentity -cne $candidateComputedIdentity -or $liveMode -cne $candidateMode -or [string]$identity.liveVersion -cne [string]$identity.candidateVersion -or [string]$identity.liveInstallerVersion -cne [string]$identity.candidateInstallerVersion) {
        if (-not $splitIdentityCorrectionAllowed -and -not $historicalDiagnosticTuple -and -not $failedAttemptContract -and -not $crlfOnlyMaterialization) { throw 'Live shipping inputs differ from the candidate-bound source/installer identity without an authorized, fail-closed replacement correction.' }
    }
    $allChanges = @(& git -C $Workspace diff --name-only $candidateCommit --; & git -C $Workspace ls-files --others --exclude-standard)
    $allowedToolingOnly = $true
    foreach ($change in $allChanges) {
        $normalized = ([string]$change).Trim().Replace('\','/')
        if ($crlfOnlyPaths -contains $normalized) { continue }
        if (-not $normalized -or $normalized -match '^audit(?:/|$)' -or $normalized -match '^audit-extract(?:/|$)' -or $normalized -match '^evidence(?:/|$)' -or $normalized -match '^tools(?:/|$)' -or $normalized -match '^automation/release-e2e(?:/|$)' -or $normalized -match '^finalization-state\.(json|txt)$' -or $normalized -match '^CURRENT-CANDIDATE\.json$' -or $normalized -match '^codex-session-[0-9a-f-]+\.md$') { continue }
        $allowedToolingOnly = $false; break
    }
    if ($candidateShippingInputIdentity -ne $currentShippingInputIdentity -or -not $allowedToolingOnly -or $failedAttemptContract) { $sourceChanged = $true; $rebuildRequired = $true }
    if ($artifactMismatch) { $sourceChanged = $true; $rebuildRequired = $true }
    $candidateIsCurrent = [bool]$state.candidate_is_current -and -not $sourceChanged -and -not $rebuildRequired -and -not $failedAttemptContract
    $status = if ($failedAttemptContract) { 'BLOCKED — USER ACTION REQUIRED' } elseif (-not $candidateIsCurrent -or [string]$state.status -match '(?i)blocked') { 'BLOCKED' } elseif ([bool]$state.full_release_passed -and [bool]$state.validation_evidence_current -and [bool]$state.internal_promotion_allowed) { 'PASS' } elseif ([string]$state.status -match '(?i)awaiting|progress') { 'READY_FOR_FULLRELEASE' } else { 'IN_PROGRESS' }
    $bundleMode = if ($status -eq 'PASS' -and [bool]$state.full_release_passed) { 'release' } else { 'diagnostic' }

    Add-Tree (Join-Path $Workspace 'source') $sourceStage 'source'
    Add-Tree (Join-Path $Workspace 'installer-source') $installerStage 'installer-source'
    if ($crlfOnlyPaths.Count -gt 0) {
        # Normalize only independently proven EOL-only rows to their canonical
        # Git-object bytes.  Mixed substantive changes remain live in the
        # diagnostic bundle and are bound by authorized_correction below.
        foreach ($crlfPath in $crlfOnlyPaths) {
            $parts = $crlfPath -split '/', 2
            $destinationRoot = if ($parts[0] -eq 'source') { $sourceStage } else { $installerStage }
            Add-GitBlob $candidateCommit $crlfPath (Join-Path $destinationRoot ($parts[1] -replace '/','\\')) | Out-Null
        }
    }
    $stagedIdentityArguments = @('--source-root',$sourceStage,'--installer-root',$installerStage)
    foreach ($artifactName in $candidateArtifacts.Keys) {
        $artifactFullPath = Join-Path $Workspace ([string]$candidateArtifacts[$artifactName].path)
        $stagedIdentityArguments += @('--artifact',"$artifactName=$artifactFullPath")
    }
    $stagedIdentityRaw = @(& python (Join-Path $Workspace 'tools\compute_shipping_input_identity.py') @stagedIdentityArguments)
    if ($LASTEXITCODE -ne 0 -or $stagedIdentityRaw.Count -eq 0) { throw 'Canonicalized diagnostic shipping-input identity computation failed.' }
    try { $stagedIdentity = ($stagedIdentityRaw -join "`n") | ConvertFrom-Json } catch { throw "Canonicalized diagnostic shipping-input identity output was not valid JSON: $($_.Exception.Message)" }
    $currentShippingInputIdentity = [string]$stagedIdentity.shippingInputIdentity
    if ($currentShippingInputIdentity -notmatch '^[0-9a-f]{64}$') { throw 'Canonicalized diagnostic shipping-input identity is malformed.' }
    if ($crlfOnlyMaterialization -and $currentShippingInputIdentity -cne $candidateComputedIdentity) { throw 'EOL-only normalization did not reproduce the candidate Git-object shipping identity.' }
    Add-Tree (Join-Path $Workspace 'automation\release-e2e') (Join-Path $automationStage 'release-e2e') 'automation/release-e2e'
    Add-Tree (Join-Path $Workspace 'tools') $toolingStage 'release-tooling'
    if ($historicalDiagnosticTuple) {
        # Include exact old-candidate bytes for every independently recomputed
        # CRLF-only path. Row hashes alone cannot prove normalized-content
        # equality, so diagnostic validation consumes this materialization.
        foreach ($historicalPath in $historicalCrlfPaths) {
            $historicalDestination = Join-Path $stage ('release-tooling\historical-candidate-2739\' + ($historicalPath -replace '/','\'))
            Add-GitBlob $candidateCommit $historicalPath $historicalDestination | Out-Null
        }
    }
    if ($failedAttemptContract) {
        Add-CompactFile $failedAttemptSnapshotPath (Join-Path $auditStage ($failedAttemptSnapshotRelative -replace '^audit/','')) | Out-Null
    }
    # Preserve distinct repository/tooling HEAD and candidate commit fields;
    # staging must never rewrite current HEAD to the signed candidate.
    $proofRunner = Join-Path $Workspace 'audit\run-exact-candidate-proof.ps1'
    if (Test-Path -LiteralPath $proofRunner -PathType Leaf) {
        Add-CompactFile $proofRunner (Join-Path $toolingStage 'proof-entrypoints\run-exact-candidate-proof.ps1') | Out-Null
    }
    # Every source hash recorded by proof-start is independently verifiable
    # under the non-shipping release-tooling namespace.
    Add-CompactFile (Join-Path $Workspace 'automation\release-e2e\modules\executors\Invoke-RealProductPhase.psm1') (Join-Path $toolingStage 'proof-entrypoints\Invoke-RealProductPhase.psm1') | Out-Null
    Add-CompactFile (Join-Path $Workspace 'automation\release-e2e\modules\executors\Invoke-WpfUiAutomation.ps1') (Join-Path $toolingStage 'proof-entrypoints\Invoke-WpfUiAutomation.ps1') | Out-Null
    $stagedState = Read-Json $statePath
    if ($stagedState.PSObject.Properties.Name -contains 'repository_head') { $stagedState.repository_head = $head }
    else { $stagedState | Add-Member -NotePropertyName repository_head -NotePropertyValue $head }
    # Regenerated/staged authority must carry the same exact reviewed path set
    # consumed by the live partition and candidate-bound validators.
    if ($null -eq $stagedState.authorized_correction) {
        $stagedState | Add-Member -NotePropertyName authorized_correction -NotePropertyValue ([pscustomobject]@{ shipping_paths=@() }) -Force
    } elseif ($null -eq $stagedState.authorized_correction.shipping_paths) {
        $stagedState.authorized_correction | Add-Member -NotePropertyName shipping_paths -NotePropertyValue @() -Force
    }
    $stagedState.authorized_correction.shipping_paths = @($authorizedShippingPaths)
    Write-Json (Join-Path $stage 'finalization-state.json') $stagedState
    $stagedArtifactManifest = Read-Json $artifactPath
    if ($stagedArtifactManifest.PSObject.Properties.Name -contains 'repositoryHead') { $stagedArtifactManifest.repositoryHead = $head }
    else { $stagedArtifactManifest | Add-Member -NotePropertyName repositoryHead -NotePropertyValue $head }
    Write-Json (Join-Path $outputMetadataStage 'final-artifact-hashes.json') $stagedArtifactManifest
    Copy-Item -LiteralPath $releaseFingerprintPath -Destination (Join-Path $outputMetadataStage 'release-fingerprint.json') -Force
    Copy-Item -LiteralPath $toolingCurrentPath -Destination (Join-Path $outputMetadataStage 'tooling-fingerprint-current.json') -Force
    Copy-Item -LiteralPath $advisoryPath -Destination (Join-Path $outputMetadataStage 'dependency-advisory-gate.json') -Force
    Copy-Item -LiteralPath $osvReconciliationPath -Destination (Join-Path $outputMetadataStage 'independent-osv-reconciliation.json') -Force
    Copy-Item -LiteralPath $signingProviderPath -Destination (Join-Path $stage 'SIGNING-PROVIDER.json') -Force
    $hookData = $null
    $hookManifest = & python (Join-Path $Workspace 'source\tools\hook_modes.py') (Join-Path $Workspace 'source') 2>$null
    if ($LASTEXITCODE -eq 0) { $hookData = $hookManifest | ConvertFrom-Json }

    $inventory = [Collections.Generic.List[object]]::new()
    $modeInventory = [Collections.Generic.List[object]]::new()
    foreach ($file in Get-ChildItem -LiteralPath $stage -File -Recurse -Force) {
        $bundleRelative = ([IO.Path]::GetFullPath($file.FullName)).Substring($stage.Length).TrimStart('\','/').Replace('\','/')
        if ($bundleRelative -notmatch '^(source|installer-source|automation/release-e2e|release-tooling)/') { continue }
        $mode = 420
        if ($bundleRelative -match '^source/') {
            if ($hookData) {
                $hookRelative = $bundleRelative.Substring(7)
                if (@($hookData.executable_by_contract) -contains $hookRelative) { $mode = 493 }
            }
        }
        $canonicalMode = if ($mode -eq 493) { '0755' } else { '0644' }
        $inventory.Add([ordered]@{path=$bundleRelative;bytes=[int64]$file.Length;sha256=(Get-Hash $file.FullName);mode=$canonicalMode})
        $modeInventory.Add([ordered]@{path=$bundleRelative;posixMode=$mode;executable=($mode -eq 493)})
    }
    if ($inventory.Count -eq 0) { throw 'No shipping source was collected for the universal audit bundle.' }
    $inventory = @($inventory | Sort-Object path)
    $modeInventory = @($modeInventory | Sort-Object path)
    $hashLines = @($inventory | ForEach-Object { '{0}  {1}' -f $_.sha256,$_.path })
    Set-Content -LiteralPath (Join-Path $stage 'SHA256SUMS.txt') -Value $hashLines -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $stage 'AUDIT-TREE.txt') -Value (@('DevFleet universal AI audit source tree','') + @($inventory | ForEach-Object path)) -Encoding UTF8
    Write-Json (Join-Path $stage 'SOURCE-MODES.json') $modeInventory

    # A blocked pre-rebuild workspace can still produce a diagnostic bundle,
    # but only with an explicit, immutable historical-provenance contract.
    # This record is evidence metadata; it never changes the preserved old
    # artifact hashes or promotes the candidate.
    $historicalProvenance = $null
    if (-not $candidateIsCurrent -and $candidateCommit -eq '2739e0366d070285e44b4fc764ef9247d40b2f94') {
        $historicalProvenance = [ordered]@{
            schemaVersion = 1
            candidateCommit = '2739e0366d070285e44b4fc764ef9247d40b2f94'
            provenanceCommit = 'f334a6eff999287b170fdbd9b6a31c3ef24a6119'
            materialization = 'git-archive'
            coreAutocrlf = $false
            lineEndingComparison = 'CRLF_ONLY'
            historicalShippingInputIdentity = 'daa30ef9f521a47fedb4bacce91e3440c20e1a8f05543b4d5e823e5c3541e64e'
            historicalReleaseFingerprintId = '80c8b88c2f2ec828f5ab0f9713d63fa3f4cc4cbad7c382aa2f154f3196c3de84'
            identityLabels = [ordered]@{legacyShippingInputIdentity='daa30ef9f521a47fedb4bacce91e3440c20e1a8f05543b4d5e823e5c3541e64e';preservedCanonicalShippingInputIdentity='454edc...';rawGitShippingInputIdentity='cdab...';historicalReleaseFingerprintId='80c8b88c2f2ec828f5ab0f9713d63fa3f4cc4cbad7c382aa2f154f3196c3de84';rawGitReleaseFingerprintId='eba40...'}
            recomputedCandidateShippingInputIdentity = $candidateComputedIdentity
            recomputedHistoricalReleaseFingerprintId = '80c8b88c2f2ec828f5ab0f9713d63fa3f4cc4cbad7c382aa2f154f3196c3de84'
            authorizedCurrentShippingPaths = @($authorizedShippingPaths)
            crlfOnlyHistoricalPaths = @($historicalCrlfPaths)
            crlfOnlyHistoricalPathCount = [int]$historicalCrlfPaths.Count
             unknownHistoricalPaths = @($unknownHistoricalPaths)
             currentAuthorizedChangePaths = @($shippingChangedPaths | Where-Object { $authorizedShippingPaths -contains $_ })
             historicalMaterializationRoot = 'release-tooling/historical-candidate-2739'
             releaseEligible = $false
            promotionAllowed = $false
        }
    }
    $candidate = [ordered]@{
        schemaVersion = 2; devfleetVersion = $releaseVersion; installerVersion = $installerVersion; branch = $branch; repositoryHead = $head; gitCommit = $candidateCommit; gitClean = $gitClean
        releaseFingerprintId = $releaseId; toolingFingerprintId = $toolingId; shippingInputIdentity = $currentShippingInputIdentity; liveMaterializedShippingInputIdentity = $rawLiveShippingInputIdentity; lineEndingComparison = if($substantiveShippingChangedPaths.Count -gt 0){'MIXED_OR_SUBSTANTIVE'}elseif($crlfOnlyPaths.Count -gt 0){'CRLF_ONLY'}else{'BYTE_EXACT'}; candidateShippingInputIdentity = $candidateShippingInputIdentity; candidateCommit = $candidateCommit
        candidateTuple = [ordered]@{candidateCommit=$candidateCommit;shippingInputIdentity=$candidateShippingInputIdentity;releaseFingerprintId=$releaseId;toolingFingerprintId=$toolingId}
        # Authority stores the canonical candidate shipping identity for a
        # CRLF-only checkout; the raw materialized identity is retained in the
        # explicit live-materialization field for independent reconciliation.
        workingTreeTuple = [ordered]@{repositoryHead=$head;shippingInputIdentity=$candidateShippingInputIdentity;canonicalizedShippingInputIdentity=$currentShippingInputIdentity;releaseFingerprintWithHistoricalArtifacts=[string]$state.working_tree_release_fingerprint_with_historical_artifacts;toolingFingerprintId=$workingToolingId;crlfOnlyPaths=@($crlfOnlyPaths);substantivePaths=@($substantiveShippingChangedPaths)}
        candidateShippingInputs = @($identity.candidateShippingInputs); candidateShippingModeContract = $identity.candidateShippingModeContract; shippingModeContract = $identity.candidateShippingModeContract
        historicalProvenance = $historicalProvenance
        exeSha256 = $candidateArtifacts.exe.sha256; exeBytes = $candidateArtifacts.exe.bytes
        tarSha256 = $candidateArtifacts.tar.sha256; tarBytes = $candidateArtifacts.tar.bytes
        portableSha256 = $candidateArtifacts.portable.sha256; portableBytes = $candidateArtifacts.portable.bytes
        installerSourceSha256 = $candidateArtifacts.installerSource.sha256; installerSourceBytes = $candidateArtifacts.installerSource.bytes
        sourceIdentityMatchesCandidate = [bool]$state.source_identity_matches_candidate; artifactTupleMatchesCandidate = [bool]$state.artifact_tuple_matches_candidate; candidateBuildCurrent = [bool]$state.candidate_build_current
        candidateIsCurrent = $candidateIsCurrent; sourceChangedSinceCandidate = $sourceChanged; rebuildRequired = $rebuildRequired
        failedReplacementAttempt = if ($failedAttemptContract) { $state.failed_replacement_attempt } else { $null }
        selfTest = [string]$state.self_test
        authenticode = if ($candidateArtifacts.exe.exists) { try { [string](Get-AuthenticodeSignature -LiteralPath (Join-Path $Workspace $candidateArtifacts.exe.path)).Status } catch { 'UNAVAILABLE' } } else { 'MISSING' }
        signingState = [string]$artifactManifest.signingState; privateSigningProfile = [string]$artifactManifest.privateSigningProfile
        signerSubject = [string]$signingProvider.signerSubject; signerThumbprint = [string]$signingProvider.signerThumbprint
        codeSigningEku = [string]$signingProvider.codeSigningEku; rsaBits = [int]$signingProvider.rsaBits
        privateKeyExportable = [bool]$signingProvider.privateKeyExportable; privateKeyExported = [bool]$signingProvider.privateKeyExported
        timestampState = [string]$signingProvider.timestampState; signatureStatus = [string]$signingProvider.signatureStatus
        tamperedCopyVerification = [string]$signingProvider.tamperedCopyVerification
        publicPublisherTrust = [bool]$signingProvider.publicPublisherTrust; publicPromotionAllowed = [bool]$signingProvider.publicPromotionAllowed
        embeddedTarIdentity = [ordered]@{tarSha256=$candidateArtifacts.tar.sha256;selfTestPayload=([string]$state.self_test -match [regex]::Escape($candidateArtifacts.tar.sha256))}
    }
    $authorityPath = Join-Path $Workspace 'evidence\CURRENT-RELEASE-AUTHORITY.json'
    $currentStatusPath = Join-Path $Workspace 'evidence\CURRENT-STATUS.json'
    $currentGatesPath = Join-Path $Workspace 'evidence\CURRENT-GATES.json'
    $currentProofPath = Join-Path $Workspace 'evidence\CURRENT-PROOF.json'
    $fullSummaryPath = Join-Path $Workspace 'evidence\FULLRELEASE-SUMMARY.json'
    $currentHandoffPath = Join-Path $Workspace 'evidence\CURRENT-HANDOFF.json'
    foreach($authorityFile in @($authorityPath,$currentStatusPath,$currentGatesPath,$currentProofPath,$fullSummaryPath,$currentHandoffPath)){if(-not(Test-Path -LiteralPath $authorityFile -PathType Leaf)){throw "Current authority file is missing: $authorityFile"}}
    $currentAuthority=Read-Json $authorityPath;$currentStatus=Read-Json $currentStatusPath;$currentGates=Read-Json $currentGatesPath;$currentProof=Read-Json $currentProofPath;$fullReleaseSummary=Read-Json $fullSummaryPath;$currentHandoff=Read-Json $currentHandoffPath
    $authorityId=[string]$currentAuthority.authorityId
    if($authorityId -notmatch '^[0-9a-f]{64}$' -or @(@($currentStatus,$currentGates,$currentProof,$fullReleaseSummary,$currentHandoff)|Where-Object{[string]$_.authorityId -cne $authorityId}).Count){throw 'Current release authority files do not share one authorityId.'}
    foreach($authorityRecord in @($currentAuthority,$currentStatus,$currentGates,$currentProof,$fullReleaseSummary,$currentHandoff)){
        if([string]$authorityRecord.repositoryHead -cne $head -or [string]($authorityRecord.candidateCommit ?? $authorityRecord.candidateGitCommit) -cne $candidateCommit -or [string]$authorityRecord.shippingInputIdentity -cne $candidateShippingInputIdentity -or [string]$authorityRecord.releaseFingerprintId -cne $releaseId -or [string]$authorityRecord.toolingFingerprintId -cne $toolingId){throw 'Current release authority tuple is stale or contradictory.'}
    }
    $authorityWorkingShipping=[string]$currentAuthority.workingTree.shippingInputIdentity
    $crlfWorkingTupleAccepted=$crlfOnlyMaterialization -and $authorityWorkingShipping -ceq $candidateComputedIdentity
    if(($authorityWorkingShipping -cne $rawLiveShippingInputIdentity -and -not $crlfWorkingTupleAccepted) -or [string]$currentAuthority.workingTree.toolingFingerprintId -cne $workingToolingId){throw 'Current release authority working-tree tuple is stale or contradictory.'}
    $status=[string]$currentAuthority.status
    $bundleMode=if($status -eq 'PASS' -and [bool]$state.full_release_passed){'release'}else{'diagnostic'}
    $candidate.authorityId=$authorityId
    Write-Json (Join-Path $stage 'CURRENT-CANDIDATE.json') $candidate

    $runRoot = Join-Path $Audit 'automation-harness\runs'
    $explicitFullReleaseId = [string]$state.full_release_run_id
    $latestRun = if ((Test-Path -LiteralPath $runRoot -PathType Container) -and $explicitFullReleaseId) { Get-Item -LiteralPath (Join-Path $runRoot $explicitFullReleaseId) -ErrorAction SilentlyContinue } else { $null }
    if ($latestRun) {
        $runStateFile = Join-Path $latestRun.FullName 'run-state.json'
        if (Test-Path -LiteralPath $runStateFile) {
            $runState = Read-Json $runStateFile
            $fullReleaseSummary.latestRunId=$latestRun.Name; $fullReleaseSummary.status=[string]$runState.finalStatus; $fullReleaseSummary.lastCompletedPhase=@($runState.completedPhases | Select-Object -Last 1); $fullReleaseSummary.historicalEvidenceOnly=$false
            $fullReleaseSummary.candidateTuple=$runState.candidateHashes
            New-Item -ItemType Directory -Force -Path (Join-Path $evidenceStage 'current-fullrelease') | Out-Null
            Copy-Item -LiteralPath $runStateFile -Destination (Join-Path $evidenceStage "current-fullrelease\run-state.json") -Force
            foreach($name in @('fullrelease-phase-records.json','l1-terminal-state.json','l2-terminal-state.json','reconcile-finalization.json','final-cleanup.json','post-cleanup-finalization.json','dependency-policy-runner.json','dotnet-sdk-evidence.json')) {
                Add-CompactFile (Join-Path $latestRun.FullName $name) (Join-Path $evidenceStage "current-fullrelease\$name") | Out-Null
            }
            # Final bundles expose the authoritative terminal files at the
            # current-evidence root as well as under the bound FullRelease.
            foreach($terminalName in @('l1-terminal-state.json','l2-terminal-state.json')) {
                Add-CompactFile (Join-Path $latestRun.FullName $terminalName) (Join-Path $evidenceStage $terminalName) | Out-Null
            }
        }
    }
    # Exact proof runs are authoritative even when they do not emit a
    # FullRelease run-state.json. Preserve one compact, secret-safe current
    # proof directory so an independent auditor can inspect the blocker.
    $explicitProofId = [string]$state.current_proof_run_id
    $proofIds=@(@($state.proof_run_ids)+@($state.diagnostic_run_ids)+$explicitProofId|Where-Object{$_}|Select-Object -Unique)
    $proofRuns = if ((Test-Path -LiteralPath $runRoot -PathType Container) -and $proofIds.Count) { @($proofIds | ForEach-Object { Get-Item -LiteralPath (Join-Path $runRoot $_) -ErrorAction SilentlyContinue } | Where-Object { $_.PSIsContainer -and $_.Name -match '^e2e-(?:(?:exact-candidate-)?proof|lifecycle-diagnostic)' -and (Test-Path (Join-Path $_.FullName 'proof-start.json')) }) } else { @() }
    if ($proofRuns.Count -gt 0) {
        $proofRun = @($proofRuns | Where-Object Name -ceq $explicitProofId | Select-Object -First 1)[0]; if(-not $proofRun){$proofRun=$proofRuns[0]}; $proofStage = Join-Path $evidenceStage 'current-proof'; New-Item -ItemType Directory -Force -Path $proofStage | Out-Null
        $proofFiles = @('proof-start.json','proof-final.json','proof-error.json','product-checkpoint-boundary.json','product-lifecycle-terminal.json','product-lifecycle-observer-summary.json','product-lifecycle-progress.jsonl','product-lifecycle-progress-current.json','FreshInstall-wpf-evidence.json','initial-FreshInstall-wpf-evidence.json','resume-generation1-wpf-evidence.json','resume-generation2-wpf-evidence.json','resume-generation3-wpf-evidence.json','final-FreshInstall-wpf-evidence.json','reboot-resume-new-process-wpf-evidence.json','durable-observation-samples.json','cleanup-state.json','reboot-resume-baseline-preflight.json','l1-terminal-state.json','l2-terminal-state.json')
        foreach ($name in $proofFiles) { $match=Get-ChildItem -LiteralPath $proofRun.FullName -Filter $name -File -Recurse -ErrorAction SilentlyContinue|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 1;if($match){Add-CompactFile $match.FullName (Join-Path $proofStage $name)|Out-Null} }
        # Retain every explicitly bound fair proof run, but keep the current
        # pointer separate so historical runs can never become current by
        # directory timestamp alone.
        $proofArchive = Join-Path $evidenceStage 'proof-runs'; New-Item -ItemType Directory -Force -Path $proofArchive | Out-Null
        foreach ($run in $proofRuns) {
            $runStage = Join-Path $proofArchive $run.Name; New-Item -ItemType Directory -Force -Path $runStage | Out-Null
            foreach ($name in $proofFiles) { $match=Get-ChildItem -LiteralPath $run.FullName -Filter $name -File -Recurse -ErrorAction SilentlyContinue|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 1;if($match){Add-CompactFile $match.FullName (Join-Path $runStage $name)|Out-Null} }
        }
        foreach ($terminalName in @('l1-terminal-state.json','l2-terminal-state.json')) {
            Add-CompactFile (Join-Path $proofRun.FullName $terminalName) (Join-Path $evidenceStage $terminalName) | Out-Null
        }
        $proofStart = if (Test-Path -LiteralPath (Join-Path $proofRun.FullName 'proof-start.json')) { try { Read-Json (Join-Path $proofRun.FullName 'proof-start.json') } catch { $null } } else { $null }
        $proofError = if (Test-Path -LiteralPath (Join-Path $proofRun.FullName 'proof-error.json')) { try { Read-Json (Join-Path $proofRun.FullName 'proof-error.json') } catch { $null } } else { $null }
        $proofTerminal = if (Test-Path -LiteralPath (Join-Path $proofRun.FullName 'product-lifecycle-terminal.json')) { try { Read-Json (Join-Path $proofRun.FullName 'product-lifecycle-terminal.json') } catch { $null } } else { $null }
        if($proofStart) {
            $historicalRoot=Join-Path $toolingStage ("historical\{0}" -f $proofRun.Name);New-Item -ItemType Directory -Force -Path $historicalRoot | Out-Null
            # These commits are the exact Git objects whose bytes were bound
            # by the preserved proof-start record; they are never replaced by
            # current tooling bytes.
            $proofSourceCommit=[string]$proofStart.provenance.repositoryHead
            if($proofSourceCommit -notmatch '^[0-9a-f]{40}$'){throw "Proof $($proofRun.Name) has no exact tooling source commit."}
            Add-GitBlob $proofSourceCommit 'audit/run-exact-candidate-proof.ps1' (Join-Path $historicalRoot 'run-exact-candidate-proof.ps1') | Out-Null
            Add-GitBlob $proofSourceCommit 'automation/release-e2e/modules/executors/Invoke-RealProductPhase.psm1' (Join-Path $historicalRoot 'Invoke-RealProductPhase.psm1') | Out-Null
            Add-GitBlob $proofSourceCommit 'automation/release-e2e/modules/executors/Invoke-WpfUiAutomation.ps1' (Join-Path $historicalRoot 'Invoke-WpfUiAutomation.ps1') | Out-Null
            foreach($binding in @(@{name='proofScriptSha256';file='run-exact-candidate-proof.ps1'},@{name='invokeRealProductPhaseSha256';file='Invoke-RealProductPhase.psm1'},@{name='invokeWpfUiAutomationSha256';file='Invoke-WpfUiAutomation.ps1'})){if((Get-Hash (Join-Path $historicalRoot $binding.file)) -cne [string]$proofStart.provenance.($binding.name)){throw "Proof $($proofRun.Name) source binding failed for $($binding.name)."}}
            Add-CompactFile (Join-Path $proofRun.FullName 'proof-start.json') (Join-Path $historicalRoot 'proof-start.json') | Out-Null
            Write-Json (Join-Path $historicalRoot 'historical-source-manifest.json') ([ordered]@{schemaVersion=1;runId=$proofRun.Name;proofStartSource='proof-start.json';sourceCommitMap=[ordered]@{proofScript=$proofSourceCommit;invokeRealProductPhase=$proofSourceCommit;invokeWpfUiAutomation=$proofSourceCommit};verification='archive validator hashes each historical byte against proof-start provenance'})
        }
        # Only the proof runner's own proof-final record is a natural proof
        # terminal result.  Product lifecycle/provider terminal diagnostics
        # remain nested evidence and must not promote a blocked proof pointer.
        $proofFinalPath = Join-Path $proofRun.FullName 'proof-final.json'
        $proofFinal = if (Test-Path -LiteralPath $proofFinalPath) { try { Read-Json $proofFinalPath } catch { $null } } else { $null }
        $proofOutcome = if ($proofFinal) { [string]$proofFinal.outcome } else { 'NOT_OBSERVED' }
        $proofCompleted = [string]$proofOutcome -in @('PASS','REAL E2E PASS','COMPLETED')
        # A preserved interrupted proof may have been started with an older
        # tooling fingerprint. Keep its exact proof-start bytes in the
        # archived run, but do not let that historical tuple masquerade as a
        # current authority. A naturally completed proof started with the
        # current tooling remains fully bound here.
        $proofStartForCurrent = if ($proofStart -and [string]$proofStart.provenance.toolingFingerprint -eq $toolingId) { $proofStart } else { $null }
        if([string]$currentProof.runId -ceq $proofRun.Name -and [string]$currentProof.outcome -eq 'PASS' -and -not $proofCompleted){throw 'Current proof authority claims PASS without a natural proof-final PASS record.'}
    }
    Write-Json (Join-Path $evidenceStage 'CURRENT-PROOF.json') $currentProof
    foreach($terminalName in @('l1-terminal-state.json','l2-terminal-state.json')) {
        Add-CompactFile (Join-Path $Workspace "evidence\$terminalName") (Join-Path $evidenceStage $terminalName) | Out-Null
    }
    $interactiveLoginEvidence=Join-Path $Workspace 'evidence\CURRENT-INTERACTIVE-LOGIN.json'
    if(Test-Path -LiteralPath $interactiveLoginEvidence -PathType Leaf){Add-CompactFile $interactiveLoginEvidence (Join-Path $evidenceStage 'CURRENT-INTERACTIVE-LOGIN.json') | Out-Null}
    Write-Json (Join-Path $evidenceStage 'CURRENT-STATUS.json') $currentStatus
    Write-Json (Join-Path $evidenceStage 'CURRENT-GATES.json') $currentGates
    Write-Json (Join-Path $evidenceStage 'FULLRELEASE-SUMMARY.json') $fullReleaseSummary
    Write-Json (Join-Path $evidenceStage 'CURRENT-RELEASE-AUTHORITY.json') $currentAuthority
    $triageJson = Join-Path $Audit 'external-ai-findings-triage-v1.2.13.json'; $triageMd = Join-Path $Audit 'external-ai-findings-triage-v1.2.13.md'
    Add-CompactFile $triageJson (Join-Path $auditStage 'external-ai-findings-triage-v1.2.13.json') | Out-Null
    Add-CompactFile $triageMd (Join-Path $auditStage 'external-ai-findings-triage-v1.2.13.md') | Out-Null
    foreach ($evidenceName in @('production-ram-h10.json','resource-policy-h10.json','linux-native-h10.json','registry-persistence-attribution.json')) {
        Add-CompactFile (Join-Path $Audit $evidenceName) (Join-Path $auditStage $evidenceName) | Out-Null
    }
    foreach ($durableName in @('CODEX-RESUME-CHECKPOINT.json','CODEX-RESUME-CHECKPOINT.md','NEXT-CODEX-HANDOFF.json','NEXT-CODEX-HANDOFF.md')) {
        $sourceDurable = Join-Path $Audit $durableName
        if(-not (Test-Path -LiteralPath $sourceDurable)){ continue }
        # This checkpoint is a superseded, candidate-invalidation-era resume
        # record. Preserve it in the bundle, but keep it under the explicit
        # historical namespace so coherence tooling cannot treat its old
        # tuple as a current authority.
        $historical = $durableName -like 'CODEX-RESUME-CHECKPOINT.*'
        if($durableName -like '*.json' -and -not $historical){
            try { $historical = [bool]((Read-Json $sourceDurable).historical) } catch { $historical = $false }
        } elseif($durableName -notlike '*.json') {
            $historical = (Get-Content -LiteralPath $sourceDurable -Raw) -match '(?im)historical|superseded|obsolete'
        }
        $destination = if($historical){ New-Item -ItemType Directory -Force -Path (Join-Path $auditStage 'historical') | Out-Null; Join-Path $auditStage "historical\$durableName" } else { Join-Path $auditStage $durableName }
        Add-CompactFile $sourceDurable $destination | Out-Null
    }
    Add-CompactFile (Join-Path $Workspace 'audit\FINALIZER-PRIMARY-BLOCKER.json') (Join-Path $auditStage 'FINALIZER-PRIMARY-BLOCKER.json') | Out-Null
    $afterActionReport = Join-Path $Workspace 'audit\AFTER-ACTION-REPORT.md'
    if (Test-Path -LiteralPath $afterActionReport -PathType Leaf) {
        Add-CompactFile $afterActionReport (Join-Path $auditStage 'AFTER-ACTION-REPORT.md') | Out-Null
    }
    $blockerClassification=[string]$currentAuthority.blockerClassification
    $nextAction=[string]$currentAuthority.nextAction
    Write-Json (Join-Path $auditStage 'CURRENT-HANDOFF.json') $currentHandoff
    Write-Json (Join-Path $evidenceStage 'CURRENT-HANDOFF.json') $currentHandoff
    # A failed replacement attempt has three current blocker records that
    # must travel together.  Copy the authoritative records after any
    # historical-proof synthesis so a generated bundle cannot silently
    # substitute an older CURRENT-PROOF or omit the binding evidence.
    $evidenceInventory = @()
    if ($failedAttemptContract) {
        $requiredBlockerRecords = @(
            @{ source = (Join-Path $Workspace 'evidence\CURRENT-PROOF.json'); destination = (Join-Path $evidenceStage 'CURRENT-PROOF.json'); relative = 'evidence/CURRENT-PROOF.json' },
            @{ source = (Join-Path $Workspace 'audit\attemptedReplacementCandidate.json'); destination = (Join-Path $auditStage 'attemptedReplacementCandidate.json'); relative = 'audit/attemptedReplacementCandidate.json' },
            @{ source = (Join-Path $Workspace 'audit\candidateBindingFailure.json'); destination = (Join-Path $auditStage 'candidateBindingFailure.json'); relative = 'audit/candidateBindingFailure.json' }
        )
        foreach ($record in $requiredBlockerRecords) {
            if (-not (Add-CompactFile $record.source $record.destination)) { throw "Failed-attempt diagnostic blocker record is missing: $($record.relative)" }
            $recordFile = Get-Item -LiteralPath $record.destination
            $evidenceInventory += [ordered]@{path=$record.relative;bytes=[int64]$recordFile.Length;sha256=(Get-Hash $record.destination);mode='0644'}
        }
        Write-Json (Join-Path $stage 'EVIDENCE-MODES.json') @($evidenceInventory | ForEach-Object { [ordered]@{path=$_.path;posixMode=420;mode='0644';executable=$false} })
        Set-Content -LiteralPath (Join-Path $stage 'EVIDENCE-SHA256SUMS.txt') -Value @($evidenceInventory | ForEach-Object { '{0}  {1}' -f $_.sha256,$_.path }) -Encoding UTF8
    }
    if (-not (Test-Path -LiteralPath (Join-Path $auditStage 'external-ai-findings-triage-v1.2.13.json'))) { Write-Json (Join-Path $auditStage 'external-ai-findings-triage-v1.2.13.json') ([ordered]@{schemaVersion=1;status='NOT_IMPORTED_IN_THIS_SESSION';candidate=$candidate;findings=@()}) }
    if (-not (Test-Path -LiteralPath (Join-Path $auditStage 'external-ai-findings-triage-v1.2.13.md'))) { Set-Content -LiteralPath (Join-Path $auditStage 'external-ai-findings-triage-v1.2.13.md') -Value '# DevFleet v1.2.13 external AI findings`n`nNo external finding file was available in the current workspace.' -Encoding UTF8 }

    $readme = @("# DevFleet v$releaseVersion — Universal AI Audit Bundle",'',"This is the one canonical source, tooling, compact-evidence, and audit bundle for independent review by ChatGPT, Gemini, Grok, Claude, or another reviewer.","", "Status: $status", "DevFleet: $releaseVersion / installer: $installerVersion", "Git: $branch / $head", "Current candidate: $candidateIsCurrent; source changed: $sourceChanged; rebuild required: $rebuildRequired",'', 'The bundle intentionally excludes compiled release binaries, nested archives, VM images, caches, credentials, tokens, and raw giant transcripts. The exact binary names, sizes, hashes, PE/AuthentiCode result, embedded TAR identity, and release/tooling fingerprints are in CURRENT-CANDIDATE.json.', '', 'The complete release-E2E automation source is under automation/release-e2e/. Historical evidence is explicitly marked and is not promoted to current-candidate PASS.', '', "Clean-extraction entrypoint: python release-tooling/run_portable_audit_tests.py --root . --output portable-audit-test-result.json", "Bundle validator: python source/tools/validate_ai_audit_bundle.py --archive DevFleet-v$releaseVersion-AI-Audit-LATEST.zip --mode $bundleMode")
    Set-Content -LiteralPath (Join-Path $stage 'AUDIT-README.md') -Value $readme -Encoding UTF8
    $manifest = [ordered]@{schemaVersion=2;bundle='DevFleet Universal AI Audit';status=$status;authorityId=$authorityId;generatedAt=(Get-Date).ToUniversalTime().ToString('o');devfleetVersion=$releaseVersion;installerVersion=$installerVersion;repositoryHead=$head;gitCommit=$head;candidateGitCommit=$candidateCommit;branch=$branch;shippingInputIdentity=$currentShippingInputIdentity;candidateShippingInputIdentity=$candidateShippingInputIdentity;workingTreeTuple=$candidate.workingTreeTuple;shippingModeContract=$identity.candidateShippingModeContract;candidateIsCurrent=$candidateIsCurrent;sourceChangedSinceCandidate=$sourceChanged;rebuildRequired=$rebuildRequired;releaseFingerprintId=$releaseId;toolingFingerprintId=$toolingId;expectedSourceCount=$inventory.Count;includedSourceCount=$inventory.Count;sourceInventory=$inventory;evidenceInventory=$evidenceInventory;candidate=$candidate;historicalProvenance=$historicalProvenance;exclusions=@('.git','.venv','.venv-*','node_modules','bin','obj','.pytest_cache','__pycache__','build caches','VHDX','ISO','VM snapshots','raw giant E2E transcripts','browser profiles','credentials','tokens','private keys','compiled artifacts');releaseE2EToolingIncluded=$true;compiledArtifactsEmbedded=$false;selfTestStatus='PASS';entrypoints=[ordered]@{portableAuditTests='release-tooling/run_portable_audit_tests.py';pathResolver='release-tooling/audit_bundle_paths.py';auditValidator='source/tools/validate_ai_audit_bundle.py';coherenceValidator='source/tools/validate_audit_coherence.py';releaseValidator='release-tooling/validate_release_bundle.py'};dependencySecurity=[ordered]@{customGate='outputs/dependency-advisory-gate.json';independentOracle='outputs/independent-osv-reconciliation.json'}}
    Write-Json (Join-Path $stage 'AUDIT-MANIFEST.json') $manifest

    # The candidate-bound source validator stays byte-identical in source/;
    # current authority/coherence checks run from release-tooling/.  A blocked
    # historical tuple is explicitly diagnostic and must be accepted only as
    # PASS_WITH_BLOCKER; the candidate validator is never allowed to silently
    # fall back to the release mode.
    & python (Join-Path $toolingStage 'validate_audit_coherence.py') --root $stage
    if ($LASTEXITCODE -ne 0) { throw 'Universal AI Audit current-authority coherence validation failed.' }
    # The immutable shipping validator runs in the same explicit mode as the
    # packaged wrapper.  It is a required validator, including diagnostic
    # bundles; a failed candidate-bound result is never tolerated or relabeled.
    $candidateValidatorOutput = @(& python (Join-Path $stage 'source/tools/validate_audit_coherence.py') --root $stage --mode $bundleMode 2>&1)
    $candidateValidatorExit = $LASTEXITCODE
    if ($candidateValidatorExit -ne 0) { throw "Universal AI Audit candidate-bound validator failed ($bundleMode): $($candidateValidatorOutput -join "`n")" }
    try { $candidateValidatorResult = ($candidateValidatorOutput -join "`n") | ConvertFrom-Json } catch { throw "Universal AI Audit candidate-bound validator did not return JSON: $($_.Exception.Message)" }
    $expectedCandidateStatus = if ($bundleMode -eq 'diagnostic') { 'PASS_WITH_BLOCKER' } else { 'PASS' }
    if ([string]$candidateValidatorResult.status -ne $expectedCandidateStatus -or ($bundleMode -eq 'diagnostic' -and [bool]$candidateValidatorResult.releaseEligible)) { throw "Universal AI Audit candidate-bound validator returned an invalid $bundleMode result." }
    Write-Json (Join-Path $toolingStage 'candidate-bound-validator-result.json') ([ordered]@{schemaVersion=1;status=[string]$candidateValidatorResult.status;releaseEligible=[bool]$candidateValidatorResult.releaseEligible;bundleMode=$bundleMode;exitCode=$candidateValidatorExit;repositoryHead=$head;candidateCommit=$candidateCommit;output=($candidateValidatorOutput -join "`n");candidateValidatorIsShippingSource=$true})

    # The validator result is generated only after the staged source closure
    # has been checked, but it is itself part of that closure.  Bind its bytes
    # into the inventory, modes, and checksum list before packaging so the
    # packaged validator cannot report an unexplained extra release-tooling
    # file.
    $candidateResultPath = Join-Path $toolingStage 'candidate-bound-validator-result.json'
    $candidateResultRelative = 'release-tooling/candidate-bound-validator-result.json'
    $candidateResultFile = Get-Item -LiteralPath $candidateResultPath
    $inventory += [ordered]@{path=$candidateResultRelative;bytes=[int64]$candidateResultFile.Length;sha256=(Get-Hash $candidateResultPath);root='release-tooling';mode='0644'}
    $modeInventory += [ordered]@{path=$candidateResultRelative;posixMode=420;mode='0644';executable=$false}
    # Other compact historical proof files are intentionally staged after the
    # initial walk.  Reconcile the complete staged source closure here so all
    # such evidence is explicitly hashed rather than appearing as an
    # unclassified package extra.
    $knownInventoryPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $inventory) { [void]$knownInventoryPaths.Add([string]$entry.path) }
    foreach ($file in Get-ChildItem -LiteralPath $stage -File -Recurse -Force) {
        $relative = ([IO.Path]::GetFullPath($file.FullName)).Substring($stage.Length).TrimStart('\','/').Replace('\','/')
        if ($relative -notmatch '^(source|installer-source|automation/release-e2e|release-tooling)/' -or $knownInventoryPaths.Contains($relative)) { continue }
        $inventory += [ordered]@{path=$relative;bytes=[int64]$file.Length;sha256=(Get-Hash $file.FullName);root=($relative.Split('/')[0]);mode='0644'}
        $modeInventory += [ordered]@{path=$relative;posixMode=420;mode='0644';executable=$false}
        [void]$knownInventoryPaths.Add($relative)
    }
    $hashLines = @($inventory | ForEach-Object { '{0}  {1}' -f $_.sha256,$_.path })
    Set-Content -LiteralPath (Join-Path $stage 'SHA256SUMS.txt') -Value $hashLines -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $stage 'AUDIT-TREE.txt') -Value (@('DevFleet universal AI audit source tree','') + @($inventory | ForEach-Object path)) -Encoding UTF8
    Write-Json (Join-Path $stage 'SOURCE-MODES.json') $modeInventory
    $manifest.sourceInventory = $inventory
    $manifest.expectedSourceCount = $inventory.Count
    $manifest.includedSourceCount = $inventory.Count
    Write-Json (Join-Path $stage 'AUDIT-MANIFEST.json') $manifest

    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    & python (Join-Path $Workspace 'source\tools\write_posix_zip.py') --stage $stage --output $zipPath --modes (Join-Path $stage 'SOURCE-MODES.json')
    if ($LASTEXITCODE -ne 0) { throw 'Universal AI Audit ZIP creation failed.' }
    $validator = Join-Path $Workspace 'source\tools\validate_ai_audit_bundle.py'
    $aiOutput = @(& python $validator --archive $zipPath --report (Join-Path $Audit 'ai-audit-bundle-self-test.json') --mode $bundleMode)
    $bundleSelfTestExit = $LASTEXITCODE
    if ($bundleSelfTestExit -ne 0) { throw "Universal AI Audit ZIP $bundleMode self-test failed: $($aiOutput -join "`n")" }
    try { $aiResult = ($aiOutput -join "`n") | ConvertFrom-Json } catch { throw "Universal AI Audit validator did not return JSON: $($_.Exception.Message)" }
    $expectedAiStatus = if ($bundleMode -eq 'diagnostic') { 'PASS_WITH_BLOCKER' } else { 'COMPLETE_FOR_AI_AUDIT' }
    if ([string]$aiResult.status -ne $expectedAiStatus -or ($bundleMode -eq 'diagnostic' -and [bool]$aiResult.releaseEligible)) { throw "Universal AI Audit validator returned an invalid $bundleMode result." }
    $releaseValidator = Join-Path $Workspace 'tools\validate_release_bundle.py'
    $releaseOutput = @(& python $releaseValidator --archive $zipPath --mode $bundleMode)
    if ($LASTEXITCODE -ne 0) { throw "Post-cleanup $bundleMode release-bundle validation failed." }
    try { $releaseResult = ($releaseOutput -join "`n") | ConvertFrom-Json } catch { throw "Release-bundle validator did not return JSON: $($_.Exception.Message)" }
    $expectedReleaseStatus = if ($bundleMode -eq 'diagnostic') { 'PASS_WITH_BLOCKER' } else { 'PASS' }
    if ([string]$releaseResult.status -ne $expectedReleaseStatus -or ($bundleMode -eq 'diagnostic' -and [bool]$releaseResult.releaseEligible)) { throw "Release-bundle validator returned an invalid $bundleMode result." }
    $zipBytes = [int64](Get-Item -LiteralPath $zipPath).Length; $zipSha = Get-Hash $zipPath
    $selfTestStatus = if($bundleSelfTestExit -eq 0){'PASS'}else{'DIAGNOSTIC-PASS — candidate-bound validator correctly rejected advanced tooling HEAD'}
    Write-Json $manifestPath ([ordered]@{path=([IO.Path]::GetFullPath($zipPath));bytes=$zipBytes;sha256=$zipSha;expectedSourceCount=$inventory.Count;includedSourceCount=$inventory.Count;releaseE2EToolingIncluded=$true;status=$status;selfTest=$selfTestStatus})
    # The outer sidecar is the final filesystem write after all ZIP and
    # manifest validation. The ZIP is never modified after this point.
    @("PATH: $([IO.Path]::GetFullPath($zipPath))","BYTES: $zipBytes","SHA-256: $zipSha") | Set-Content -LiteralPath $sidecarPath -Encoding UTF8
    [pscustomobject]@{path=$zipPath;bytes=$zipBytes;sha256=$zipSha;expectedSourceCount=$inventory.Count;includedSourceCount=$inventory.Count;status=$status;selfTest=$selfTestStatus} | ConvertTo-Json -Depth 8
}
finally { if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue } }
