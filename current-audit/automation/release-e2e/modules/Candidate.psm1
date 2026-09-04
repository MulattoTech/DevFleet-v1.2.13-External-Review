Set-StrictMode -Version Latest

function Get-FileHashRecord {
    param([Parameter(Mandatory)][string]$Path)
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved -ErrorAction Stop
    [pscustomobject]@{
        path = $resolved
        bytes = [int64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Test-PrivateAuthenticodeSignature {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$PublicCertificatePath,
        [Parameter(Mandatory)][string]$ExpectedThumbprint
    )
    $resolved=(Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $certificatePath=(Resolve-Path -LiteralPath $PublicCertificatePath -ErrorAction Stop).Path
    $trustedCertificate=$null;$chain=$null;$tampered=Join-Path ([IO.Path]::GetTempPath()) ("devfleet-authenticode-tampered-{0}.exe" -f [guid]::NewGuid().ToString('N'))
    try{
        $trustedCertificate=[Security.Cryptography.X509Certificates.X509Certificate2]::new($certificatePath)
        if($trustedCertificate.Thumbprint -cne $ExpectedThumbprint){throw 'Public verifier certificate thumbprint differs from the private signing manifest.'}
        $signature=Get-AuthenticodeSignature -LiteralPath $resolved
        if(-not $signature.SignerCertificate){throw 'Private candidate has no Authenticode signer certificate.'}
        if($signature.SignerCertificate.Thumbprint -cne $ExpectedThumbprint){throw 'Private candidate signer thumbprint differs from the final manifest.'}
        if([Convert]::ToBase64String($signature.SignerCertificate.RawData) -cne [Convert]::ToBase64String($trustedCertificate.RawData)){throw 'Private candidate signer differs from the exact supplied public certificate.'}
        if([string]$signature.Status -notin @('Valid','UnknownError')){throw "Private candidate Authenticode returned an unexpected status: $($signature.Status)."}
        if([string]$signature.Status -eq 'UnknownError' -and [string]$signature.StatusMessage -notmatch '(?i)trust|root|certificate chain'){throw "Private candidate Authenticode UnknownError was not solely an untrusted-root condition: $($signature.StatusMessage)"}
        if('1.3.6.1.5.5.7.3.3' -notin @($signature.SignerCertificate.EnhancedKeyUsageList|ForEach-Object{[string]$_.ObjectId})){throw 'Private candidate signer lacks Code Signing EKU.'}
        $chain=[Security.Cryptography.X509Certificates.X509Chain]::new()
        $chain.ChainPolicy.RevocationMode=[Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags=[Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
        $null=$chain.ChainPolicy.ExtraStore.Add($trustedCertificate)
        if(-not $chain.Build($signature.SignerCertificate)){throw "Private candidate exact-certificate chain validation failed: $(@($chain.ChainStatus|ForEach-Object Status)-join ', ')"}
        $unexpected=@($chain.ChainStatus|Where-Object{[string]$_.Status -notin @('NoError','UntrustedRoot')})
        if($unexpected.Count){throw "Private candidate chain has unexpected status: $(@($unexpected|ForEach-Object Status)-join ', ')"}
        Copy-Item -LiteralPath $resolved -Destination $tampered
        $stream=[IO.File]::Open($tampered,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        try{$stream.Position=4096;$byte=$stream.ReadByte();if($byte -lt 0){throw 'Candidate is too small for the tamper negative control.'};$stream.Position=4096;$stream.WriteByte(($byte -bxor 1))}finally{$stream.Dispose()}
        $tamperedStatus=[string](Get-AuthenticodeSignature -LiteralPath $tampered).Status
        if($tamperedStatus -ne 'HashMismatch'){throw "Private candidate tampered-copy verification returned $tamperedStatus instead of HashMismatch."}
        [pscustomobject]@{status='PASS';effectiveSignatureStatus='Valid';platformSignatureStatus=[string]$signature.Status;platformSignatureStatusMessage=[string]$signature.StatusMessage;signerThumbprint=$signature.SignerCertificate.Thumbprint;exactCertificateMatch=$true;codeSigningEkuVerified=$true;explicitTrustValidation='PASS';trustMode='IN_MEMORY_EXACT_CERTIFICATE';chainStatuses=@($chain.ChainStatus|ForEach-Object{[string]$_.Status});tamperedCopyStatus=$tamperedStatus;trustStoreMutated=$false;publicPublisherTrust=$false}
    }finally{
        Remove-Item -LiteralPath $tampered -Force -ErrorAction SilentlyContinue
        if($chain){$chain.Dispose()}
        if($trustedCertificate){$trustedCertificate.Dispose()}
    }
}

function Get-CandidateFingerprint {
    param(
        [Parameter(Mandatory)][string]$WorkspaceRoot,
        [string]$CandidatePath
    )
    $workspace = (Resolve-Path -LiteralPath $WorkspaceRoot -ErrorAction Stop).Path
    $outputs = Join-Path $workspace 'outputs'
    if ($CandidatePath) {
        $exe = (Resolve-Path -LiteralPath $CandidatePath -ErrorAction Stop).Path
    } else {
        $choices = @(Get-ChildItem -LiteralPath $outputs -Filter 'DevFleet-Setup-*.exe' -File | Sort-Object LastWriteTimeUtc -Descending)
        if ($choices.Count -ne 1) { throw "Candidate discovery is ambiguous: found $($choices.Count) installer EXEs." }
        $exe = $choices[0].FullName
    }
    $leaf = Split-Path -Leaf $exe
    $match = [regex]::Match($leaf, '(?i)v(?<version>\d+\.\d+\.\d+)')
    if ($match.Success) { $version = $match.Groups['version'].Value }
    else {
        $version = (Get-Item -LiteralPath $exe).VersionInfo.ProductVersion -replace '[^0-9.].*$',''
        if (-not $version) { throw 'Unable to determine candidate version.' }
    }
    $tar = Join-Path $outputs "devfleet-v$version.tar.gz"
    $portable = @(Get-ChildItem -LiteralPath $outputs -Filter "DevFleet-v$version-Portable*.zip" -File)
    $sourceZip = Join-Path $outputs "DevFleet-v$version-Installer-Source.zip"
    foreach ($required in @($tar,$sourceZip)) { if (-not (Test-Path -LiteralPath $required)) { throw "Associated release artifact missing: $required" } }
    if ($portable.Count -ne 1) { throw "Portable artifact discovery is ambiguous: found $($portable.Count)." }
    $installerVersionPath = Join-Path $workspace 'installer-source\INSTALLER_VERSION'
    $installerVersion = if (Test-Path -LiteralPath $installerVersionPath) { (Get-Content -LiteralPath $installerVersionPath -Raw).Trim() } else { 'UNKNOWN' }
    $releaseFingerprintId = $null
    $toolingFingerprintId = $null
    $candidateGitCommit = $null
    $candidateStatePath = Join-Path $workspace 'finalization-state.json'
    $candidateManifestPath = Join-Path $outputs 'final-artifact-hashes.json'
    if(-not (Test-Path -LiteralPath $candidateStatePath) -or -not (Test-Path -LiteralPath $candidateManifestPath)){throw 'Current candidate evidence state is missing.'}
    $candidateState=Get-Content -LiteralPath $candidateStatePath -Raw|ConvertFrom-Json
    $candidateManifest=Get-Content -LiteralPath $candidateManifestPath -Raw|ConvertFrom-Json
    if(-not [bool]$candidateState.candidate_is_current -or [bool]$candidateState.source_changed_since_candidate -or [bool]$candidateState.rebuild_required){throw 'Candidate evidence says the candidate is stale or requires rebuild.'}
    $candidateGitCommit=[string]$candidateManifest.candidateGitCommit
    if(-not $candidateGitCommit){$candidateGitCommit=[string]$candidateState.candidate_git_commit}
    $head=(& git -C $workspace rev-parse HEAD 2>$null).Trim()
    if($candidateGitCommit -notmatch '^[0-9a-fA-F]{40}$'){throw 'Candidate evidence has an invalid shipping candidate commit.'}
    $candidateIdentity=[string]($candidateState.shipping_input_identity ?? $candidateState.shippingInputIdentity ?? $candidateManifest.shippingInputIdentity)
    if($candidateIdentity -notmatch '^[0-9a-fA-F]{64}$'){throw 'Candidate evidence is missing deterministic shipping-input identity.'}
    if([string]$candidateManifest.candidateGitCommit -and [string]$candidateManifest.candidateGitCommit -ne $candidateGitCommit){throw 'Candidate manifest commit fields disagree.'}
    $candidateRecord=@($candidateManifest.artifacts|Where-Object name -eq 'exe')
    if($candidateRecord.Count -ne 1){throw 'Candidate manifest must contain exactly one EXE artifact identity.'}
    $observedCandidate=Get-FileHashRecord -Path $exe
    if([string]$candidateRecord[0].sha256 -ne $observedCandidate.sha256 -or [int64]$candidateRecord[0].bytes -ne $observedCandidate.bytes){throw 'Candidate EXE does not match its final post-sign manifest identity.'}
    $privateSigningProfile=if($candidateManifest.PSObject.Properties['privateSigningProfile']){[string]$candidateManifest.privateSigningProfile}else{''}
    $privateSigningThumbprint=if($candidateManifest.PSObject.Properties['privateSigningCertificateThumbprint']){[string]$candidateManifest.privateSigningCertificateThumbprint}else{''}
    $manifestPublicPublisherTrust=if($candidateManifest.PSObject.Properties['publicPublisherTrust']){[bool]$candidateManifest.publicPublisherTrust}else{$false}
    $manifestPublicPromotionAllowed=if($candidateManifest.PSObject.Properties['publicPromotionAllowed']){[bool]$candidateManifest.publicPromotionAllowed}else{$false}
    $publicCertificate=$null
    if($privateSigningProfile -eq 'PRIVATE_SELF_SIGNED'){
        if($manifestPublicPublisherTrust -or $manifestPublicPromotionAllowed){throw 'Private self-signed candidate evidence incorrectly enables public trust or promotion.'}
        if($privateSigningThumbprint -notmatch '^[0-9A-Fa-f]{40}$'){throw 'Private signing manifest thumbprint is invalid.'}
        $publicCertificatePath=Join-Path $outputs 'DevFleet-Private-Personal-Code-Signing.cer'
        if(-not(Test-Path -LiteralPath $publicCertificatePath -PathType Leaf)){throw 'Private candidate public verifier certificate is missing.'}
        $publicCertificate=Get-FileHashRecord -Path $publicCertificatePath
        $authenticode=Test-PrivateAuthenticodeSignature -Path $exe -PublicCertificatePath $publicCertificatePath -ExpectedThumbprint $privateSigningThumbprint
    }
    $releaseFingerprintPath = Join-Path $outputs 'release-fingerprint.json'
    if (Test-Path -LiteralPath $releaseFingerprintPath) {
        $releaseMetadata = Get-Content -LiteralPath $releaseFingerprintPath -Raw | ConvertFrom-Json -ErrorAction Stop
        $releaseFingerprintId = [string]$releaseMetadata.releaseFingerprintId
        $toolingFingerprintId = [string]$releaseMetadata.toolingFingerprint.toolingFingerprintId
    }
    [pscustomobject]@{
        releaseVersion = $version
        installerVersion = $installerVersion
        gitCommit = $candidateGitCommit
        repositoryHead = $head
        shippingInputIdentity = $candidateIdentity
        releaseFingerprintId = $releaseFingerprintId
        toolingFingerprintId = $toolingFingerprintId
        candidate = $observedCandidate
        tar = Get-FileHashRecord -Path $tar
        portable = Get-FileHashRecord -Path $portable[0].FullName
        installerSource = Get-FileHashRecord -Path $sourceZip
        signingState = if($candidateManifest.PSObject.Properties['signingState']){[string]$candidateManifest.signingState}else{''}
        privateSigningProfile = $privateSigningProfile
        privateSigningCertificateThumbprint = $privateSigningThumbprint
        publicPublisherTrust = $manifestPublicPublisherTrust
        publicPromotionAllowed = $manifestPublicPromotionAllowed
        publicCertificate = $publicCertificate
        authenticode = $authenticode
    }
}

function Invoke-CandidateSelfTest {
    param([Parameter(Mandatory)][psobject]$Fingerprint)
    $selfTestName=if([string]$Fingerprint.privateSigningProfile -eq 'PRIVATE_SELF_SIGNED'){'signed-self-test.txt'}else{'unsigned-self-test.txt'}
    $reportPath = Join-Path (Split-Path -Parent $Fingerprint.candidate.path) $selfTestName
    Remove-Item -LiteralPath $reportPath -Force -ErrorAction SilentlyContinue
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Fingerprint.candidate.path
    $psi.Arguments = '--self-test'
    $psi.WorkingDirectory = Split-Path -Parent $Fingerprint.candidate.path
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.Environment['DEVFLEET_SELF_TEST_OUTPUT'] = $reportPath
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $psi
    if (-not $process.Start()) { throw 'Unable to start candidate self-test.' }
    if (-not $process.WaitForExit(120000)) { try { $process.Kill() } catch {}; throw 'Candidate self-test timed out.' }
    $report = if (Test-Path -LiteralPath $reportPath) { Get-Content -LiteralPath $reportPath -Raw } else { '' }
    [pscustomobject]@{
        exitCode = $process.ExitCode
        reportPath = $reportPath
        result = if ($process.ExitCode -eq 0 -and $report -match '(?m)^PASS\s*$') { 'PASS' } else { 'FAIL' }
        reportSha256 = if (Test-Path -LiteralPath $reportPath) { (Get-FileHash -LiteralPath $reportPath -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
        requiredChecks = [ordered]@{
            devfleet = $report -match [regex]::Escape("devfleet_version=$($Fingerprint.releaseVersion)")
            installer = $report -match [regex]::Escape("installer_version=$($Fingerprint.installerVersion)")
            embeddedTarCount = $report -match '(?m)^embedded_tar_count=1\s*$'
            payloadSha = $report -match [regex]::Escape("payload=$($Fingerprint.tar.sha256)")
            extraction = $report -match '(?m)^payload_extraction=PASS\s*$'
            bootstrap = $report -match '(?m)^bootstrap_entrypoint=PASS\s*$'
            parameterContract = $report -match '(?m)^bootstrap_parameter_contract=PASS\s*$'
            factoryResetBackupGate = $report -match '(?m)^factory_reset_backup_gate=PASS\s*$'
            planSafety = $report -match '(?m)^plan_safety=PASS\s*$'
        }
    }
}

function Test-CandidateFingerprint {
    param([Parameter(Mandatory)][psobject]$Expected,[Parameter(Mandatory)][psobject]$Actual)
    foreach ($name in @('candidate','tar','portable','installerSource')) {
        if ($Expected.$name.sha256 -ne $Actual.$name.sha256 -or $Expected.$name.bytes -ne $Actual.$name.bytes) { return $false }
    }
    foreach($name in @('releaseFingerprintId','toolingFingerprintId','gitCommit')){if([string]$Expected.$name -ne [string]$Actual.$name){return $false}}
    return $true
}

Export-ModuleMember -Function Get-FileHashRecord,Test-PrivateAuthenticodeSignature,Get-CandidateFingerprint,Invoke-CandidateSelfTest,Test-CandidateFingerprint
