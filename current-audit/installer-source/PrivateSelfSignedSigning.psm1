Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:PrivateSigningSubject = 'CN=DevFleet Private Personal Code Signing'
$script:CodeSigningEku = '1.3.6.1.5.5.7.3.3'

function Get-PrivateKeyExportable {
    param([Parameter(Mandatory)]$Certificate)
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if ($null -eq $rsa) { throw 'DevFleet private signing certificate does not expose an RSA private key.' }
    try {
        if ($rsa -is [System.Security.Cryptography.RSACng]) {
            $policy = $rsa.Key.ExportPolicy
            return [bool](
                ($policy -band [System.Security.Cryptography.CngExportPolicies]::AllowExport) -or
                ($policy -band [System.Security.Cryptography.CngExportPolicies]::AllowPlaintextExport)
            )
        }
        if ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
            return [bool]$rsa.CspKeyContainerInfo.Exportable
        }
        throw "Unsupported RSA private-key provider: $($rsa.GetType().FullName)"
    } finally {
        $rsa.Dispose()
    }
}

function Test-UsablePrivateSigningCertificate {
    param([Parameter(Mandatory)]$Certificate)
    $eku = @($Certificate.EnhancedKeyUsageList | ForEach-Object { [string]$_.ObjectId })
    if ($Certificate.Subject -cne $script:PrivateSigningSubject) { return $false }
    if (-not $Certificate.HasPrivateKey) { return $false }
    if ($Certificate.NotBefore -gt (Get-Date)) { return $false }
    if ($Certificate.NotAfter -le (Get-Date).AddDays(30)) { return $false }
    if ($script:CodeSigningEku -notin $eku) { return $false }
    return -not (Get-PrivateKeyExportable -Certificate $Certificate)
}

function Assert-PrivateSigningCertificate {
    param([Parameter(Mandatory)]$Certificate)
    if (-not (Test-UsablePrivateSigningCertificate -Certificate $Certificate)) {
        throw 'DevFleet private signing certificate failed exact subject, validity, EKU, private-key, or non-exportable-key policy.'
    }
    if ([int]$Certificate.PublicKey.Key.KeySize -lt 3072) {
        throw 'DevFleet private signing certificate RSA key is smaller than 3072 bits.'
    }
}

function Import-PublicCertificateForPrivateTrust {
    param(
        [Parameter(Mandatory)][string]$PublicCertificatePath,
        [Parameter(Mandatory)][string]$Thumbprint
    )
    foreach ($storeName in @('TrustedPublisher')) {
        $storePath = "Cert:\CurrentUser\$storeName"
        $present = Get-ChildItem -LiteralPath $storePath | Where-Object { $_.Thumbprint -ceq $Thumbprint }
        if (-not $present) {
            & (Join-Path $env:SystemRoot 'System32\certutil.exe') -user -f -addstore $storeName $PublicCertificatePath | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "certutil failed to install the DevFleet public certificate in CurrentUser/$storeName." }
        }
        $verified = Get-ChildItem -LiteralPath $storePath | Where-Object { $_.Thumbprint -ceq $Thumbprint }
        if (-not $verified) { throw "DevFleet public signing certificate was not installed in CurrentUser/$storeName." }
    }
    $trustedRoot = @(Get-ChildItem -LiteralPath 'Cert:\CurrentUser\Root' | Where-Object { $_.Thumbprint -ceq $Thumbprint })
    if ($trustedRoot.Count -ne 1) {
        throw "USER ACTION REQUIRED — Windows requires interactive consent before trusting DevFleet private signing certificate $Thumbprint in CurrentUser/Root."
    }
}

function Initialize-DevFleetPrivateSigningIdentity {
    [CmdletBinding()]
    param(
        [string]$StateRoot = (Join-Path $env:LOCALAPPDATA 'DevFleet\Signing\PrivateSelfSigned'),
        [switch]$TrustSigningHost,
        [string]$RequiredThumbprint,
        [switch]$RequireExisting
    )

    New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
    $metadataPath = Join-Path $StateRoot 'identity.json'
    $publicCertificatePath = Join-Path $StateRoot 'DevFleet-Private-Personal-Code-Signing.cer'
    $persisted = $null
    if (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
        try { $persisted = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json }
        catch { throw "DevFleet private signing identity metadata is malformed: $($_.Exception.Message)" }
        if ([string]$persisted.subject -cne $script:PrivateSigningSubject) {
            throw 'DevFleet private signing identity metadata has an unexpected subject.'
        }
        if ([string]$persisted.thumbprint -notmatch '^[0-9A-Fa-f]{40}$') {
            throw 'DevFleet private signing identity metadata has an invalid thumbprint.'
        }
    }

    $store = 'Cert:\CurrentUser\My'
    $exactSubject = @(Get-ChildItem -LiteralPath $store | Where-Object { $_.Subject -ceq $script:PrivateSigningSubject })
    $certificate = $null
    $rolloverFrom = $null
    $created = $false
    if ($persisted) {
        $rolloverFrom = ([string]$persisted.thumbprint).ToUpperInvariant()
        $candidate = @($exactSubject | Where-Object { $_.Thumbprint -ceq $rolloverFrom })
        if ($candidate.Count -gt 1) { throw 'Multiple certificates matched the persisted DevFleet private signing thumbprint.' }
        if ($candidate.Count -eq 1 -and (Test-UsablePrivateSigningCertificate -Certificate $candidate[0])) {
            $certificate = $candidate[0]
            $rolloverFrom = $null
        }
    } else {
        $usable = @($exactSubject | Where-Object { Test-UsablePrivateSigningCertificate -Certificate $_ })
        if ($usable.Count -gt 1) {
            throw 'Multiple usable DevFleet private signing identities exist without persisted exact-thumbprint authority.'
        }
        if ($usable.Count -eq 1) { $certificate = $usable[0] }
    }

    if ($RequireExisting) {
        if (-not $RequiredThumbprint -or $RequiredThumbprint -notmatch '^[0-9A-Fa-f]{40}$') {
            throw 'DevFleet private signing requires an explicit existing certificate thumbprint.'
        }
        $required = @(Get-ChildItem -LiteralPath $store | Where-Object { $_.Thumbprint -ceq $RequiredThumbprint.ToUpperInvariant() })
        if ($required.Count -ne 1 -or -not (Test-UsablePrivateSigningCertificate -Certificate $required[0])) {
            throw "RELEASE BLOCKED — required existing DevFleet signing certificate $RequiredThumbprint is unavailable or fails policy; replacement creation is forbidden."
        }
        $certificate = $required[0]
        if ($persisted -and ([string]$persisted.thumbprint).ToUpperInvariant() -cne $certificate.Thumbprint.ToUpperInvariant()) {
            throw 'Persisted DevFleet private signing identity does not match the required existing certificate thumbprint.'
        }
    }
    if (-not $certificate) {
        $certificate = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $script:PrivateSigningSubject `
            -FriendlyName 'DevFleet PRIVATE/PERSONAL Code Signing' `
            -CertStoreLocation $store `
            -KeyAlgorithm RSA `
            -KeyLength 3072 `
            -HashAlgorithm SHA256 `
            -KeyExportPolicy NonExportable `
            -NotAfter (Get-Date).AddYears(3)
        $created = $true
    }

    Assert-PrivateSigningCertificate -Certificate $certificate
    Export-Certificate -Cert $certificate -FilePath $publicCertificatePath -Force | Out-Null
    if ($TrustSigningHost) {
        Import-PublicCertificateForPrivateTrust -PublicCertificatePath $publicCertificatePath -Thumbprint $certificate.Thumbprint
    }

    $metadata = [ordered]@{
        schemaVersion = 1
        profile = 'PRIVATE_SELF_SIGNED'
        subject = $certificate.Subject
        thumbprint = $certificate.Thumbprint
        codeSigningEku = $script:CodeSigningEku
        notBefore = $certificate.NotBefore.ToUniversalTime().ToString('o')
        notAfter = $certificate.NotAfter.ToUniversalTime().ToString('o')
        keyAlgorithm = $certificate.PublicKey.Oid.FriendlyName
        keySize = [int]$certificate.PublicKey.Key.KeySize
        privateKeyExportable = $false
        privateKeyExported = $false
        publicCertificatePath = $publicCertificatePath
        trustStores = if ($TrustSigningHost) { @('CurrentUser/Root', 'CurrentUser/TrustedPublisher') } else { @() }
        createdThisRun = $created
        rolloverFromThumbprint = $rolloverFrom
        updatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
    $temporary = "$metadataPath.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText($temporary, (($metadata | ConvertTo-Json -Depth 6) + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temporary -Destination $metadataPath -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
    return [pscustomobject]$metadata
}

Export-ModuleMember -Function Initialize-DevFleetPrivateSigningIdentity
