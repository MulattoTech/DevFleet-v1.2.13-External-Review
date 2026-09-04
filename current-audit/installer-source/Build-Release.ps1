[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$SourceRoot,
  [Parameter(Mandatory)][string]$PreviousPortableZip,
  [Parameter(Mandatory)][string]$OutputDirectory,
  [string]$DotNet = 'dotnet',
  [switch]$UnsignedDeveloperBuild,
  [switch]$VerifyFrozenInputs,
  [switch]$PrepareReleaseInputs,
  [string]$SignToolPath,
  [string]$SigningDlibPath,
  [string]$SigningMetadataPath,
  [string]$CertificateThumbprint,
  [string]$OsvScannerPath = '',
  [ValidateSet('PublicTrusted','PrivateSelfSigned')][string]$SigningProfile = 'PublicTrusted',
  [string]$TimestampUrl = 'http://timestamp.acs.microsoft.com'
)
$ErrorActionPreference='Stop'
if($UnsignedDeveloperBuild -and $PSBoundParameters.ContainsKey('SigningProfile')){throw 'UnsignedDeveloperBuild cannot be combined with an explicit signing profile.'}
$installerRoot=$PSScriptRoot
$releasePowerShell = @((Join-Path $PSHOME 'powershell.exe'),(Join-Path $PSHOME 'pwsh.exe')) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $releasePowerShell) { throw "Trusted build PowerShell executable was not found under $PSHOME" }
if($PrepareReleaseInputs){
  & $releasePowerShell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $installerRoot 'Prepare-ReleaseInputs.ps1') -Mode Prepare -SourceRoot $SourceRoot -PreviousPortableZip $PreviousPortableZip -OutputDirectory $OutputDirectory -SigningProfile $SigningProfile -ProveIdempotent
  if($LASTEXITCODE){throw 'Release-input preparation failed.'}
  exit 0
}
if(-not $VerifyFrozenInputs){throw 'Build-Release requires -VerifyFrozenInputs; tracked release inputs must be prepared and committed before build/sign.'}
$privateIdentityPreflight=$null
if(-not $UnsignedDeveloperBuild -and $SigningProfile -eq 'PrivateSelfSigned'){
  if($CertificateThumbprint -cne 'DE42CD7369A01E9357BDA13597C0173E5E703E9D'){throw 'RELEASE BLOCKED — the authorized existing DevFleet signing thumbprint must be supplied exactly.'}
  Import-Module (Join-Path $installerRoot 'PrivateSelfSignedSigning.psm1') -Force
  $privateIdentityPreflight=Initialize-DevFleetPrivateSigningIdentity -TrustSigningHost -RequiredThumbprint $CertificateThumbprint -RequireExisting
}
$source=(Resolve-Path -LiteralPath $SourceRoot).Path
$previous=(Resolve-Path -LiteralPath $PreviousPortableZip).Path
New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
$outputs=(Resolve-Path -LiteralPath $OutputDirectory).Path
$workspaceRoot=Split-Path -Parent $source
$priorStatePath=Join-Path $workspaceRoot 'finalization-state.json'
$authorizedCorrection=[ordered]@{shipping_paths=@()}
if(Test-Path -LiteralPath $priorStatePath -PathType Leaf){
  try{$priorState=Get-Content -LiteralPath $priorStatePath -Raw|ConvertFrom-Json -ErrorAction Stop}catch{throw 'RELEASE BLOCKED — prior finalization authority is unreadable.'}
  $authorizedPaths=@($priorState.authorized_correction.shipping_paths|ForEach-Object{([string]$_).Trim().Replace('\','/').TrimStart('/')}|Where-Object{$_}|Sort-Object -Unique)
  foreach($authorizedPath in $authorizedPaths){
    if($authorizedPath -notmatch '^(source|installer-source)/' -or $authorizedPath -match '(^|/)\.\.(/|$)' -or [IO.Path]::IsPathRooted($authorizedPath)){throw "RELEASE BLOCKED — authorized correction path is invalid: $authorizedPath"}
  }
  $authorizedCorrection.shipping_paths=@($authorizedPaths)
}
$releasePythonCandidate=Join-Path $workspaceRoot 'source\.venv-test\Scripts\python.exe'
$releasePython=if(Test-Path -LiteralPath $releasePythonCandidate -PathType Leaf){$releasePythonCandidate}else{(Get-Command python.exe -ErrorAction Stop).Source}
$releaseToolingRequirements=Join-Path $workspaceRoot 'tools\release-tooling-requirements.txt'
if(-not (Test-Path -LiteralPath $releaseToolingRequirements -PathType Leaf)){throw 'RELEASE BLOCKED — pinned release-tooling requirements are missing.'}
& $releasePython -c "import packaging, cvss; assert packaging.__version__ == '26.3'; assert cvss.__version__ == '3.6'"
if($LASTEXITCODE){throw 'RELEASE BLOCKED — the pinned packaging/cvss release-tool dependencies are unavailable.'}
$shippingIdentityTool=Join-Path $workspaceRoot 'tools\compute_shipping_input_identity.py'
$candidateGitCommit=(& git -C $workspaceRoot rev-parse HEAD 2>$null).Trim()
$verificationMarker = & $releasePowerShell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $installerRoot 'Prepare-ReleaseInputs.ps1') -Mode Verify -SourceRoot $source -PreviousPortableZip $previous -OutputDirectory $outputs -SigningProfile $SigningProfile -CandidateCommit $candidateGitCommit | Select-Object -Last 1
if($LASTEXITCODE){throw 'RELEASE BLOCKED — prepared shipping inputs do not reproduce exactly from the candidate commit.'}
$verification = $verificationMarker | ConvertFrom-Json
if($verification.status -ne 'PASS'){throw 'RELEASE BLOCKED — frozen release-input verification did not PASS.'}
$buildSource=[string]$verification.sourceRoot
$buildInstaller=[string]$verification.installerRoot
$candidateIdentityJson = & $releasePython $shippingIdentityTool --workspace $workspaceRoot --candidate-commit $candidateGitCommit | Select-Object -Last 1
if($LASTEXITCODE){throw 'RELEASE BLOCKED — candidate shipping identity could not be computed.'}
$candidateIdentity = $candidateIdentityJson | ConvertFrom-Json
function Normalize-CrlfOnly([byte[]]$Bytes) {
  $out = New-Object System.Collections.Generic.List[byte]
  for($i=0; $i -lt $Bytes.Length; $i++) {
    if($Bytes[$i] -eq 13) {
      if($i + 1 -ge $Bytes.Length -or $Bytes[$i + 1] -ne 10) { throw 'RELEASE BLOCKED — live shipping input contains a lone CR; only CRLF materialization is permitted.' }
      [void]$out.Add(10); $i++; continue
    }
    [void]$out.Add($Bytes[$i])
  }
  return $out.ToArray()
}
function Test-ByteArrayEqual([byte[]]$Left,[byte[]]$Right) {
  if($Left.Length -ne $Right.Length){return $false}
  for($i=0;$i -lt $Left.Length;$i++){if($Left[$i] -ne $Right[$i]){return $false}}
  return $true
}
$candidateKeys=@($candidateIdentity.candidateShippingInputs | ForEach-Object { "$($_.root)/$($_.path)" })
$liveKeys=@($candidateIdentity.liveShippingInputs | ForEach-Object { "$($_.root)/$($_.path)" })
if($candidateKeys.Count -ne $liveKeys.Count -or @((Compare-Object -ReferenceObject $candidateKeys -DifferenceObject $liveKeys -IncludeEqual:$false)).Count -ne 0){throw 'RELEASE BLOCKED — live and candidate shipping input row sets differ.'}
foreach($row in @($candidateIdentity.candidateShippingInputs)) {
  $rootPath = if([string]$row.root -ceq 'source'){$source}else{Join-Path $workspaceRoot 'installer-source'}
  $candidateRoot = if([string]$row.root -ceq 'source'){$buildSource}else{$buildInstaller}
  $livePath = Join-Path $rootPath ([string]$row.path).Replace('/','\')
  $candidatePath = Join-Path $candidateRoot ([string]$row.path).Replace('/','\')
  if(-not (Test-Path -LiteralPath $livePath -PathType Leaf) -or -not (Test-Path -LiteralPath $candidatePath -PathType Leaf)){throw "RELEASE BLOCKED — shipping input is missing from live or candidate tree: $($row.root)/$($row.path)"}
  $liveBytes=[IO.File]::ReadAllBytes($livePath); $candidateBytes=[IO.File]::ReadAllBytes($candidatePath)
  if(-not (Test-ByteArrayEqual $liveBytes $candidateBytes)) {
    $normalizedLive=Normalize-CrlfOnly $liveBytes
    if(-not (Test-ByteArrayEqual $normalizedLive $candidateBytes)){throw "RELEASE BLOCKED — live checkout shipping input differs substantively from the candidate commit: $($row.root)/$($row.path)"}
  }
}
$stageIdentityJson = & $releasePython $shippingIdentityTool --source-root $buildSource --installer-root $buildInstaller | Select-Object -Last 1
if($LASTEXITCODE){throw 'RELEASE BLOCKED — staged shipping identity could not be computed.'}
$stageIdentity = $stageIdentityJson | ConvertFrom-Json
if([string]$stageIdentity.shippingInputIdentity -cne [string]$candidateIdentity.candidateShippingInputIdentity){throw 'RELEASE BLOCKED — staged shipping identity does not match the candidate commit.'}
$verifiedOutputs=[string]$verification.outputDirectory
$verifiedTar=Join-Path $verifiedOutputs "devfleet-v$((Get-Content -LiteralPath (Join-Path $buildSource 'VERSION') -Raw).Trim()).tar.gz"
$verifiedPortable=Join-Path $verifiedOutputs "DevFleet-v$((Get-Content -LiteralPath (Join-Path $buildSource 'VERSION') -Raw).Trim())-Portable-Codebase-Verified-r1.zip"
if(-not (Test-Path -LiteralPath $verifiedTar) -or -not (Test-Path -LiteralPath $verifiedPortable)){throw 'RELEASE BLOCKED — frozen verification did not produce authoritative TAR and portable artifacts.'}
Copy-Item -LiteralPath $verifiedTar -Destination (Join-Path $outputs (Split-Path -Leaf $verifiedTar)) -Force
Copy-Item -LiteralPath $verifiedPortable -Destination (Join-Path $outputs (Split-Path -Leaf $verifiedPortable)) -Force
function Assert-StageShippingIdentity([string]$Phase) {
  $currentJson = & $releasePython $shippingIdentityTool --source-root $buildSource --installer-root $buildInstaller | Select-Object -Last 1
  if($LASTEXITCODE){throw "RELEASE BLOCKED — shipping identity recomputation failed at $Phase."}
  $current = $currentJson | ConvertFrom-Json
  if([string]$current.shippingInputIdentity -cne [string]$candidateIdentity.candidateShippingInputIdentity){throw "RELEASE BLOCKED — shipping identity changed at $Phase."}
}
$devfleetVersion=(Get-Content -LiteralPath (Join-Path $buildSource 'VERSION') -Raw).Trim()
$installerVersion=(Get-Content -LiteralPath (Join-Path $buildInstaller 'INSTALLER_VERSION') -Raw).Trim()
if($devfleetVersion -notmatch '^\d+\.\d+\.\d+$'){throw "Release source VERSION is not semantic: $devfleetVersion"}
if($installerVersion -notmatch '^\d+\.\d+\.\d+$'){throw "Installer VERSION is not semantic: $installerVersion"}
$assemblyVersion="$installerVersion.0"
$advisoryReport = Join-Path $outputs 'dependency-advisory-gate.json'
& $releasePython (Join-Path $buildSource 'tools\check_dependency_advisories.py') --lock (Join-Path $buildSource 'app\requirements-hashed.txt') --allowlist (Join-Path $buildSource 'linux\dependency-advisory-allowlist.json') --output $advisoryReport
if($LASTEXITCODE){throw 'Dependency security-freshness gate blocked the release build.'}
$osvScanner=if($OsvScannerPath){$OsvScannerPath}elseif($env:DEVFLEET_OSV_SCANNER_PATH){$env:DEVFLEET_OSV_SCANNER_PATH}else{(Get-Command osv-scanner.exe -ErrorAction SilentlyContinue).Source}
if(-not $osvScanner -or -not (Test-Path -LiteralPath $osvScanner -PathType Leaf)){throw 'RELEASE BLOCKED — first-party OSV-Scanner is unavailable; dependency reconciliation is fail-closed.'}
$osvReconciliation = Join-Path $outputs 'independent-osv-reconciliation.json'
& $releasePython (Join-Path $workspaceRoot 'tools\reconcile_osv_scanner.py') --scanner $osvScanner --lock (Join-Path $buildSource 'app\requirements-hashed.txt') --custom-report $advisoryReport --output $osvReconciliation
if($LASTEXITCODE){throw 'Independent OSV-Scanner reconciliation blocked the release build.'}
$tar=Join-Path $outputs "devfleet-v$devfleetVersion.tar.gz"
$hash=(Get-FileHash -LiteralPath $tar -Algorithm SHA256).Hash.ToLowerInvariant()
if((Get-Content -LiteralPath (Join-Path $buildInstaller 'DevFleet.Setup\PayloadManifest.cs') -Raw) -notmatch [regex]::Escape($hash)){throw 'PayloadManifest.cs is not synchronized with the frozen TAR SHA-256.'}
if((Get-Content -LiteralPath (Join-Path $buildInstaller 'DevFleet.Setup\DevFleet.Setup.csproj') -Raw) -notmatch [regex]::Escape("devfleet-v$devfleetVersion.tar.gz")){throw 'Installer project payload metadata is not synchronized with the frozen version.'}
if((Get-Content -LiteralPath (Join-Path $buildInstaller 'DevFleet.Setup\app.manifest') -Raw) -notmatch ('assemblyIdentity\s+version="'+[regex]::Escape($assemblyVersion)+'"')){throw 'Windows application manifest identity is not synchronized with the frozen installer version.'}
$sourceZip = Join-Path $outputs "DevFleet-v$devfleetVersion-Installer-Source.zip"
& $releasePowerShell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $buildSource 'tools\Build-InstallerSourceZip.ps1') -SourceRoot $buildSource -InstallerRoot $buildInstaller -OutputPath $sourceZip
if($LASTEXITCODE){throw 'Installer source archive build failed.'}
& $releasePython (Join-Path $buildSource 'tools\release_fingerprint.py') --source-root $buildSource --installer-root $buildInstaller --output (Join-Path $outputs 'release-fingerprint.json') --artifact "tar=$tar" --artifact "portable=$(Join-Path $outputs "DevFleet-v$devfleetVersion-Portable-Codebase-Verified-r1.zip")" --artifact "installerSource=$sourceZip"
if($LASTEXITCODE){throw 'Release fingerprint generation failed.'}
& $DotNet restore (Join-Path $buildInstaller 'DevFleet.Setup\DevFleet.Setup.csproj')
if($LASTEXITCODE){throw 'dotnet restore failed.'}
& $DotNet build (Join-Path $buildInstaller 'DevFleet.Setup\DevFleet.Setup.csproj') -c Release --no-restore
if($LASTEXITCODE){throw 'dotnet build failed.'}
& $DotNet run --project (Join-Path $buildInstaller 'DevFleet.Setup.Tests\DevFleet.Setup.Tests.csproj') -c Release
if($LASTEXITCODE){throw 'installer tests failed.'}
$publish=Join-Path $outputs 'publish';New-Item -ItemType Directory -Path $publish -Force|Out-Null
& $DotNet publish (Join-Path $buildInstaller 'DevFleet.Setup\DevFleet.Setup.csproj') -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o $publish
if($LASTEXITCODE){throw 'installer publish failed.'}
$unsignedExe=Join-Path $outputs "DevFleet-Setup-v$devfleetVersion-win-x64.exe"
Copy-Item -LiteralPath (Join-Path $publish 'DevFleet.Setup.exe') -Destination $unsignedExe -Force
$selfTest=Join-Path $outputs 'unsigned-self-test.txt'
$env:DEVFLEET_SELF_TEST_OUTPUT=$selfTest
$selfTestProcess=Start-Process -FilePath $unsignedExe -ArgumentList '--self-test' -Wait -PassThru
Remove-Item Env:DEVFLEET_SELF_TEST_OUTPUT -ErrorAction SilentlyContinue
if($selfTestProcess.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $selfTest) -or (Get-Content -LiteralPath $selfTest -Raw) -notmatch '(?m)^PASS(?:\r?$)'){throw 'Unsigned installer self-test failed.'}
Assert-StageShippingIdentity 'pre-sign'
$portable = Join-Path $outputs "DevFleet-v$devfleetVersion-Portable-Codebase-Verified-r1.zip"
$fingerprintArgs = @(
  ("--artifact=exe=$unsignedExe"),
  ("--artifact=tar=$tar"),
  ("--artifact=portable=$portable"),
  ("--artifact=installerSource=$sourceZip")
)
& $releasePython (Join-Path $buildSource 'tools\release_fingerprint.py') --source-root $buildSource --installer-root $buildInstaller --output (Join-Path $outputs 'release-fingerprint.json') @fingerprintArgs
if($LASTEXITCODE){throw 'Final release fingerprint generation failed.'}
$artifactRows = @(
  [ordered]@{name='exe';path="outputs/DevFleet-Setup-v$devfleetVersion-win-x64.exe";bytes=(Get-Item $unsignedExe).Length;sha256=(Get-FileHash $unsignedExe -Algorithm SHA256).Hash.ToLowerInvariant()},
  [ordered]@{name='tar';path="outputs/devfleet-v$devfleetVersion.tar.gz";bytes=(Get-Item $tar).Length;sha256=(Get-FileHash $tar -Algorithm SHA256).Hash.ToLowerInvariant()},
  [ordered]@{name='portable';path="outputs/DevFleet-v$devfleetVersion-Portable-Codebase-Verified-r1.zip";bytes=(Get-Item $portable).Length;sha256=(Get-FileHash $portable -Algorithm SHA256).Hash.ToLowerInvariant()},
  [ordered]@{name='installerSource';path="outputs/DevFleet-v$devfleetVersion-Installer-Source.zip";bytes=(Get-Item $sourceZip).Length;sha256=(Get-FileHash $sourceZip -Algorithm SHA256).Hash.ToLowerInvariant()}
)
$fingerprintObject=Get-Content (Join-Path $outputs 'release-fingerprint.json') -Raw | ConvertFrom-Json
if([int]$fingerprintObject.schemaVersion -ne 2){throw 'Current candidate release fingerprint must use schema v2.'}
$candidateGitBranch=(& git -C $workspaceRoot branch --show-current 2>$null).Trim()
if($candidateGitCommit -notmatch '^[0-9a-fA-F]{40}$' -or -not $candidateGitBranch){throw 'Release candidate identity could not be bound to a local Git commit and branch.'}
$signingState='PRE-SIGN UNSIGNED — Authenticode signing and verification occur later in this invocation'
$currentTooling = [ordered]@{schemaVersion=2;releaseFingerprintSchemaVersion=2;releaseFingerprintId=$fingerprintObject.releaseFingerprintId;toolingFingerprintId=$fingerprintObject.toolingFingerprint.toolingFingerprintId;toolingInputs=$fingerprintObject.toolingFingerprint.toolingInputs;artifacts=$artifactRows;generatedAt=(Get-Date).ToUniversalTime().ToString('o')}
$currentToolingPath = Join-Path $outputs 'tooling-fingerprint-current.json'
$currentToolingTemporary = "$currentToolingPath.$([guid]::NewGuid().ToString('N')).tmp"
try {
  [IO.File]::WriteAllText($currentToolingTemporary, (($currentTooling | ConvertTo-Json -Depth 12) + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))
  Move-Item -LiteralPath $currentToolingTemporary -Destination $currentToolingPath -Force
} finally {
  Remove-Item -LiteralPath $currentToolingTemporary -Force -ErrorAction SilentlyContinue
}
$finalManifest = [ordered]@{schemaVersion=2;releaseFingerprintSchemaVersion=2;releaseVersion=$devfleetVersion;installerVersion=$installerVersion;gitCommit=$candidateGitCommit;branch=$candidateGitBranch;candidateGitCommit=$candidateGitCommit;releaseFingerprintId=$fingerprintObject.releaseFingerprintId;toolingFingerprintId=$fingerprintObject.toolingFingerprint.toolingFingerprintId;artifacts=$artifactRows;sourceChangedSinceCandidate=$false;rebuildRequired=$false;sourceIdentityMatchesCandidate=$true;artifactTupleMatchesCandidate=$true;candidateBuildCurrent=$true;candidateIsCurrent=$true;validationEvidenceCurrent=$false;fullReleasePassed=$false;physicalSurrogateCertificationCurrent=$false;internalPromotionAllowed=$false;publicPromotionAllowed=$false;releaseStatus='BLOCKED';signingState=$signingState;signing=$signingState}
$finalManifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $outputs 'final-artifact-hashes.json') -Encoding utf8
$state=[ordered]@{
  release_version=$devfleetVersion;installer_version=$installerVersion;workspace=$workspaceRoot;branch=$candidateGitBranch;git_commit=$candidateGitCommit;candidate_git_commit=$candidateGitCommit;current_phase='candidate-built-awaiting-clean-fullrelease';last_completed_phase='candidate-build-and-self-test';status='BLOCKED';authorized_correction=$authorizedCorrection;source_changed_since_candidate=$false;rebuild_required=$false;source_identity_matches_candidate=$true;artifact_tuple_matches_candidate=$true;candidate_build_current=$true;candidate_is_current=$true;validation_evidence_current=$false;full_release_passed=$false;physical_surrogate_certification_current=$false;internal_promotion_allowed=$false;public_promotion_allowed=$false;release_status='BLOCKED';signing_state=$signingState;release_fingerprint_schema_version=2;releaseFingerprintId=$fingerprintObject.releaseFingerprintId;toolingFingerprintId=$fingerprintObject.toolingFingerprint.toolingFingerprintId;production_safety=[ordered]@{production_unchanged=$true;mulattotechsurface_touched=$false;scope='disposable DevFleet-E2E resources only'};candidate=[ordered]@{exe=$artifactRows[0];tar=$artifactRows[1];portable=$artifactRows[2];installer_source=$artifactRows[3]};self_test=(Get-Content (Join-Path $outputs 'unsigned-self-test.txt') -Raw);gates=[ordered]@{dependency_matrix='UNVERIFIED — exact candidate FullRelease required';wpf='UNVERIFIED — exact candidate FullRelease required';linux='UNVERIFIED — exact candidate Linux validation required';primary='UNVERIFIED — exact candidate FullRelease required';repair='UNVERIFIED — exact candidate FullRelease required';clean_reinstall='UNVERIFIED — exact candidate FullRelease required';uninstall='UNVERIFIED — exact candidate FullRelease required';factory_reset='UNVERIFIED — exact candidate FullRelease required';reboot_resume='UNVERIFIED — exact candidate FullRelease required';maintenance='UNVERIFIED — 0/5 promoted for current candidate';stopped_project='UNVERIFIED — exact candidate FullRelease required';tailscale_install_deferred='UNVERIFIED — exact candidate FullRelease required';tailscale_full_auth='UNVERIFIED — exact candidate FullRelease required';automation_harness='IMPLEMENTED — non-shipping tooling; complete FullRelease not yet certified'};blockers=@('Final clean-room FullRelease against this exact candidate is required.','Physical MulattoTechSurface Laptop/Surrogate validation is required before v1.2.13 can be final.')
}
$state | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $workspaceRoot 'finalization-state.json') -Encoding utf8
@("DevFleet $devfleetVersion / Installer $installerVersion","Status: candidate current; awaiting exact-candidate clean FullRelease","Git commit: $candidateGitCommit","Release fingerprint: $($fingerprintObject.releaseFingerprintId)","Tooling fingerprint: $($fingerprintObject.toolingFingerprint.toolingFingerprintId)",'Source changed since candidate: FALSE','Rebuild required: FALSE','Candidate is current: TRUE','All expensive acceptance gates remain unpromoted until exact-candidate evidence exists.') | Set-Content -LiteralPath (Join-Path $workspaceRoot 'finalization-state.txt') -Encoding utf8
$preSignExe=[ordered]@{path="outputs/DevFleet-Setup-v$devfleetVersion-win-x64.exe";bytes=(Get-Item $unsignedExe).Length;sha256=(Get-FileHash $unsignedExe -Algorithm SHA256).Hash.ToLowerInvariant();authenticodeStatus=[string](Get-AuthenticodeSignature -LiteralPath $unsignedExe).Status}
if(-not $UnsignedDeveloperBuild){
  if($preSignExe.authenticodeStatus -ne 'NotSigned'){throw 'RELEASE BLOCKED — final build output was already signed before the selected signing profile ran.'}
  $tool=if($SignToolPath){$SignToolPath}elseif($env:DEVFLEET_SIGNTOOL_PATH){$env:DEVFLEET_SIGNTOOL_PATH}else{(Get-Command signtool.exe -ErrorAction SilentlyContinue).Source}
  $dlib=if($SigningDlibPath){$SigningDlibPath}else{$env:DEVFLEET_SIGNING_DLIB_PATH}
  $metadata=if($SigningMetadataPath){$SigningMetadataPath}else{$env:DEVFLEET_SIGNING_METADATA_PATH}
  $privateIdentity=$null;$timestampState='NOT TIMESTAMPED';$signtoolVerification='UNAVAILABLE — SignTool not installed'
  if($SigningProfile -eq 'PrivateSelfSigned'){
    $privateIdentity=$privateIdentityPreflight
    $thumbprint=[string]$privateIdentity.thumbprint
    if($CertificateThumbprint -and $CertificateThumbprint -cne $thumbprint){throw 'Configured certificate thumbprint does not match the persisted DevFleet private signing identity.'}
    if($tool){
      if(-not(Test-Path -LiteralPath $tool)){throw 'RELEASE BLOCKED — SIGNTOOL PATH IS INVALID.'}
      & $tool sign /v /sha1 $thumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $unsignedExe
      $timestampExit=$LASTEXITCODE
      if($timestampExit){
        $afterTimestampAttempt=Get-AuthenticodeSignature -LiteralPath $unsignedExe
        if($afterTimestampAttempt.Status -eq 'NotSigned'){
          & $tool sign /v /sha1 $thumbprint /fd SHA256 $unsignedExe
          if($LASTEXITCODE){throw "Private Authenticode signing without a timestamp failed with exit code $LASTEXITCODE."}
        }elseif($afterTimestampAttempt.Status -ne 'Valid' -or $afterTimestampAttempt.SignerCertificate.Thumbprint -cne $thumbprint){
          throw "Private Authenticode timestamp attempt failed with exit code $timestampExit and left an unusable signature; the artifact was not double-signed."
        }
        $timestampState='NOT TIMESTAMPED — RFC3161 timestamp unavailable; private SignTool signing completed without a timestamp'
      }else{$timestampState='RFC3161 TIMESTAMPED'}
    }else{
      $certificate=Get-Item -LiteralPath "Cert:\CurrentUser\My\$thumbprint"
      $setResult=Set-AuthenticodeSignature -LiteralPath $unsignedExe -Certificate $certificate -HashAlgorithm SHA256
      if($setResult.Status -ne 'Valid'){throw "Private Authenticode fallback signing failed: $($setResult.Status)"}
      $timestampState='NOT TIMESTAMPED — SignTool unavailable; Set-AuthenticodeSignature fallback used'
    }
  }else{
    $thumbprint=if($CertificateThumbprint){$CertificateThumbprint}else{$env:DEVFLEET_SIGNING_CERTIFICATE_THUMBPRINT}
    if($tool -and $dlib -and $metadata){
      if(-not (Test-Path -LiteralPath $tool) -or -not (Test-Path -LiteralPath $dlib) -or -not (Test-Path -LiteralPath $metadata)){throw 'RELEASE BLOCKED — AUTHENTICODE SIGNING INPUT PATH IS INVALID.'}
      & $tool sign /v /debug /fd SHA256 /tr $TimestampUrl /td SHA256 /dlib $dlib /dmdf $metadata $unsignedExe
    }elseif($tool -and $thumbprint){
      if(-not (Test-Path -LiteralPath $tool)){throw 'RELEASE BLOCKED — SIGNTOOL PATH IS INVALID.'}
      & $tool sign /v /sha1 $thumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $unsignedExe
    }else{throw 'RELEASE BLOCKED — AUTHENTICODE PUBLISHER IDENTITY REQUIRED'}
    if($LASTEXITCODE){throw "Authenticode signing failed with exit code $LASTEXITCODE."}
    $timestampState='RFC3161 TIMESTAMPED'
  }
  $verifyText=Join-Path $outputs 'authenticode-verification.txt'
  if($tool){
    & $tool verify /pa /v $unsignedExe 2>&1 | Set-Content -LiteralPath $verifyText
    if($LASTEXITCODE){throw 'SignTool /pa verification failed.'}
    $signtoolVerification='PASS'
  }else{
    'UNAVAILABLE — SignTool is not installed; Get-AuthenticodeSignature verification is authoritative for this private build.' | Set-Content -LiteralPath $verifyText
  }
  $signature=Get-AuthenticodeSignature -LiteralPath $unsignedExe
  if($signature.Status -ne 'Valid'){throw "Get-AuthenticodeSignature did not return Valid: $($signature.Status)"}
  if($SigningProfile -eq 'PrivateSelfSigned'){
    if($signature.SignerCertificate.Thumbprint -cne [string]$privateIdentity.thumbprint){throw 'Private Authenticode signer thumbprint does not match the expected DevFleet identity.'}
    if('1.3.6.1.5.5.7.3.3' -notin @($signature.SignerCertificate.EnhancedKeyUsageList|ForEach-Object{[string]$_.ObjectId})){throw 'Private Authenticode signer lacks the Code Signing EKU.'}
  }
  $tamperedCopy=Join-Path $outputs ".authenticode-tamper-$([guid]::NewGuid().ToString('N')).exe"
  try{
    Copy-Item -LiteralPath $unsignedExe -Destination $tamperedCopy
    $stream=[IO.File]::Open($tamperedCopy,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try{$stream.Position=4096;$originalByte=$stream.ReadByte();$stream.Position=4096;$stream.WriteByte(($originalByte -bxor 1))}finally{$stream.Dispose()}
    $tamperedStatus=[string](Get-AuthenticodeSignature -LiteralPath $tamperedCopy).Status
    if($tamperedStatus -eq 'Valid'){throw 'Tampered Authenticode probe unexpectedly remained valid.'}
  }finally{Remove-Item -LiteralPath $tamperedCopy -Force -ErrorAction SilentlyContinue}
  $signedTest=Join-Path $outputs 'signed-self-test.txt';$env:DEVFLEET_SELF_TEST_OUTPUT=$signedTest
  $signedProcess=Start-Process -FilePath $unsignedExe -ArgumentList '--self-test' -Wait -PassThru
  Remove-Item Env:DEVFLEET_SELF_TEST_OUTPUT -ErrorAction SilentlyContinue
  if($signedProcess.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $signedTest) -or (Get-Content -LiteralPath $signedTest -Raw) -notmatch '(?m)^PASS(?:\r?$)'){throw 'Signed installer self-test failed.'}
  Assert-StageShippingIdentity 'post-sign'

  $artifactRows[0]=[ordered]@{name='exe';path="outputs/DevFleet-Setup-v$devfleetVersion-win-x64.exe";bytes=(Get-Item $unsignedExe).Length;sha256=(Get-FileHash $unsignedExe -Algorithm SHA256).Hash.ToLowerInvariant()}
  & $releasePython (Join-Path $buildSource 'tools\release_fingerprint.py') --source-root $buildSource --installer-root $buildInstaller --output (Join-Path $outputs 'release-fingerprint.json') --artifact "exe=$unsignedExe" --artifact "tar=$tar" --artifact "portable=$portable" --artifact "installerSource=$sourceZip"
  if($LASTEXITCODE){throw 'Signed final release fingerprint generation failed.'}
  $fingerprintObject=Get-Content (Join-Path $outputs 'release-fingerprint.json') -Raw|ConvertFrom-Json
  $signingState=if($SigningProfile -eq 'PrivateSelfSigned'){'PRIVATE SELF-SIGNED AUTHENTICODE — VALID ON EXPLICITLY TRUSTED PERSONAL/TEST SYSTEMS'}else{'AUTHENTICODE SIGNED — VALID PUBLIC SIGNING PATH'}
  $currentTooling.releaseFingerprintId=$fingerprintObject.releaseFingerprintId;$currentTooling.toolingFingerprintId=$fingerprintObject.toolingFingerprint.toolingFingerprintId;$currentTooling.artifacts=$artifactRows
  [IO.File]::WriteAllText($currentToolingPath,(($currentTooling|ConvertTo-Json -Depth 12)+[Environment]::NewLine),(New-Object Text.UTF8Encoding($false)))
  $finalManifest.releaseFingerprintId=$fingerprintObject.releaseFingerprintId;$finalManifest.toolingFingerprintId=$fingerprintObject.toolingFingerprint.toolingFingerprintId;$finalManifest.artifacts=$artifactRows;$finalManifest.signingState=$signingState;$finalManifest.signing=$signingState;$finalManifest.preSignExe=$preSignExe;$finalManifest.publicPromotionAllowed=$false
  if($SigningProfile -eq 'PrivateSelfSigned'){$finalManifest.privateSigningProfile='PRIVATE_SELF_SIGNED';$finalManifest.privateSigningCertificateThumbprint=[string]$privateIdentity.thumbprint;$finalManifest.publicPublisherTrust=$false;$finalManifest.timestampState=$timestampState}
  $finalManifest|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $outputs 'final-artifact-hashes.json') -Encoding utf8
  $state.releaseFingerprintId=$fingerprintObject.releaseFingerprintId;$state.toolingFingerprintId=$fingerprintObject.toolingFingerprint.toolingFingerprintId;$state.signing_state=$signingState;$state.candidate.exe=$artifactRows[0];$state.pre_sign_exe=$preSignExe
  if($SigningProfile -eq 'PrivateSelfSigned'){$state.private_signing_profile='PRIVATE_SELF_SIGNED';$state.private_signing_certificate_thumbprint=[string]$privateIdentity.thumbprint;$state.public_publisher_trust=$false;$state.timestamp_state=$timestampState}
  $state|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $workspaceRoot 'finalization-state.json') -Encoding utf8
  $publicCertificateRecord=$null
  if($SigningProfile -eq 'PrivateSelfSigned'){
    $publicCertificateOutput=Join-Path $outputs 'DevFleet-Private-Personal-Code-Signing.cer'
    Copy-Item -LiteralPath ([string]$privateIdentity.publicCertificatePath) -Destination $publicCertificateOutput -Force
    $publicCertificateRecord=[ordered]@{path='outputs/DevFleet-Private-Personal-Code-Signing.cer';bytes=(Get-Item $publicCertificateOutput).Length;sha256=(Get-FileHash $publicCertificateOutput -Algorithm SHA256).Hash.ToLowerInvariant()}
  }
  [ordered]@{provider=if($SigningProfile -eq 'PrivateSelfSigned' -and $tool){'Windows certificate store / SignTool'}elseif($SigningProfile -eq 'PrivateSelfSigned'){'Windows certificate store / Set-AuthenticodeSignature fallback'}elseif($dlib){'Azure Artifact Signing'}else{'Windows certificate store'};signingProfile=$SigningProfile;timestampState=$timestampState;signatureStatus=$signature.Status;signerSubject=$signature.SignerCertificate.Subject;signerThumbprint=$signature.SignerCertificate.Thumbprint;codeSigningEkuVerified=$true;signtoolVerification=$signtoolVerification;tamperedCopyStatus=$tamperedStatus;preSignExe=$preSignExe;finalSignedExe=$artifactRows[0];publicCertificate=$publicCertificateRecord;publicPublisherTrust=($SigningProfile -ne 'PrivateSelfSigned');publicPromotionAllowed=$false} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $outputs 'signing-provider.json')
  @("DevFleet $devfleetVersion / Installer $installerVersion","Status: signed candidate current; awaiting exact-candidate clean FullRelease","Git commit: $candidateGitCommit","Release fingerprint: $($fingerprintObject.releaseFingerprintId)","Tooling fingerprint: $($fingerprintObject.toolingFingerprint.toolingFingerprintId)","Signing state: $signingState",'Source changed since candidate: FALSE','Rebuild required: FALSE','Candidate is current: TRUE','Public promotion allowed: FALSE')|Set-Content -LiteralPath (Join-Path $workspaceRoot 'finalization-state.txt') -Encoding utf8
}else{Write-Warning 'Unsigned developer build explicitly requested; this artifact is not release eligible.'}
Write-Host "Release complete: $outputs"
