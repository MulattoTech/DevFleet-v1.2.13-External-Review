[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$UnsignedExecutable,
    [switch]$RequireTrusted
)
$ErrorActionPreference = 'Stop'

$source = (Resolve-Path -LiteralPath $UnsignedExecutable).Path
$sourceSignature = Get-AuthenticodeSignature -LiteralPath $source
if ($sourceSignature.Status -ne 'NotSigned') { throw 'Private signing probe requires an unsigned source executable.' }

Import-Module (Join-Path $PSScriptRoot 'PrivateSelfSignedSigning.psm1') -Force
$identity = Initialize-DevFleetPrivateSigningIdentity -TrustSigningHost:$RequireTrusted
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$($identity.thumbprint)"
$scratchRoot = Join-Path $env:LOCALAPPDATA 'Temp\DevFleet-PrivateSigningProbe'
New-Item -ItemType Directory -Path $scratchRoot -Force | Out-Null
$probe = Join-Path $scratchRoot "probe-$([guid]::NewGuid().ToString('N')).exe"
$tampered = Join-Path $scratchRoot "tampered-$([guid]::NewGuid().ToString('N')).exe"
try {
    Copy-Item -LiteralPath $source -Destination $probe
    $setResult = Set-AuthenticodeSignature -LiteralPath $probe -Certificate $certificate -HashAlgorithm SHA256
    $signature = Get-AuthenticodeSignature -LiteralPath $probe
    $chainValid = $setResult.Status -eq 'Valid' -and $signature.Status -eq 'Valid'
    if ($RequireTrusted -and -not $chainValid) { throw "Private signing probe did not validate: set=$($setResult.Status); verify=$($signature.Status); message=$($signature.StatusMessage)" }
    if ($signature.SignerCertificate.Thumbprint -cne [string]$identity.thumbprint) { throw 'Private signing probe used an unexpected certificate.' }
    if ('1.3.6.1.5.5.7.3.3' -notin @($signature.SignerCertificate.EnhancedKeyUsageList | ForEach-Object { [string]$_.ObjectId })) { throw 'Private signing probe certificate lacks Code Signing EKU.' }

    Copy-Item -LiteralPath $probe -Destination $tampered
    $stream = [IO.File]::Open($tampered, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $stream.Position = 4096
        $originalByte = $stream.ReadByte()
        $stream.Position = 4096
        $stream.WriteByte(($originalByte -bxor 1))
    } finally {
        $stream.Dispose()
    }
    $tamperedSignature = Get-AuthenticodeSignature -LiteralPath $tampered
    if ($tamperedSignature.Status -eq 'Valid') { throw 'Tampered private signing probe unexpectedly validated.' }
    [ordered]@{
        status = if ($chainValid) { 'PASS' } else { 'BLOCKED — TRUST' }
        sourceStatus = [string]$sourceSignature.Status
        signedStatus = [string]$signature.Status
        subject = $signature.SignerCertificate.Subject
        thumbprint = $signature.SignerCertificate.Thumbprint
        codeSigningEkuVerified = $true
        timestampState = if ($signature.TimeStamperCertificate) { 'PRESENT' } else { 'NOT TIMESTAMPED' }
        tamperedCopyStatus = [string]$tamperedSignature.Status
        privateKeyExported = $false
    } | ConvertTo-Json -Depth 4
} finally {
    foreach ($path in @($probe, $tampered)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force }
    }
}
