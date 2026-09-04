[CmdletBinding()]
param(
  [ValidateSet('Prepare','Verify')][string]$Mode = 'Prepare',
  [Parameter(Mandatory)][string]$SourceRoot,
  [Parameter(Mandatory)][string]$PreviousPortableZip,
  [Parameter(Mandatory)][string]$OutputDirectory,
  [ValidateSet('PublicTrusted','PrivateSelfSigned')][string]$SigningProfile = 'PrivateSelfSigned',
  [string]$CandidateCommit,
  [switch]$ProveIdempotent
)
$ErrorActionPreference = 'Stop'

function Write-Utf8NoBom([string]$Path, [string]$Text) {
  $normalized = [regex]::Replace($Text, "`r`n|`r", "`n")
  [IO.File]::WriteAllText($Path, $normalized, (New-Object Text.UTF8Encoding($false)))
}

function Get-Bytes([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
  return [IO.File]::ReadAllBytes($Path)
}

function Get-Snapshot([string]$Source, [string]$Installer) {
  $version = (Get-Content -LiteralPath (Join-Path $Source 'VERSION') -Raw).Trim()
  $payload = Join-Path $Installer "DevFleet.Setup\Payload\devfleet-v$version.tar.gz"
  $relative = @(
    'source/CHECKSUMS.sha256',
    'installer-source/dependencies.json',
    'installer-source/OFFLINE-PAYLOAD-SHA256.txt',
    'installer-source/DevFleet.Setup/PayloadManifest.cs',
    'installer-source/DevFleet.Setup/DevFleet.Setup.csproj',
    'installer-source/DevFleet.Setup/app.manifest',
    'installer-source/INSTALLER-BUILD-MANIFEST.json',
    "installer-source/DevFleet.Setup/Payload/devfleet-v$version.tar.gz"
  )
  $snapshot = [ordered]@{}
  foreach ($item in $relative) {
    $path = Join-Path (Split-Path -Parent $Source) ($item.Replace('/', '\'))
    if ($item.StartsWith('source/')) { $path = Join-Path $Source $item.Substring(7).Replace('/', '\') }
    elseif ($item.StartsWith('installer-source/')) { $path = Join-Path $Installer $item.Substring(17).Replace('/', '\') }
    $bytes = Get-Bytes $path
    $snapshot[$item] = if ($null -eq $bytes) { $null } else { [Convert]::ToBase64String($bytes) }
  }
  return $snapshot
}

function Invoke-Prepare([string]$Source, [string]$Installer, [string]$Previous, [string]$Outputs) {
  $devfleetVersion = (Get-Content -LiteralPath (Join-Path $Source 'VERSION') -Raw).Trim()
  $installerVersion = (Get-Content -LiteralPath (Join-Path $Installer 'INSTALLER_VERSION') -Raw).Trim()
  if ($devfleetVersion -notmatch '^\d+\.\d+\.\d+$') { throw "Release source VERSION is not semantic: $devfleetVersion" }
  if ($installerVersion -notmatch '^\d+\.\d+\.\d+$') { throw "Installer VERSION is not semantic: $installerVersion" }
  New-Item -ItemType Directory -Path $Outputs -Force | Out-Null

  $sourceDependencies = Join-Path $Source 'dependencies.json'
  $installerDependencies = Join-Path $Installer 'DevFleet.Setup\dependencies.json'
  Copy-Item -LiteralPath $sourceDependencies -Destination $installerDependencies -Force
  if ((Get-FileHash -LiteralPath $sourceDependencies -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $installerDependencies -Algorithm SHA256).Hash) {
    throw 'Installer dependency manifest is not byte-identical to the canonical source manifest.'
  }

  & python (Join-Path $Source 'tools\build_release.py') --source $Source --old-portable $Previous --output-dir $Outputs
  if ($LASTEXITCODE) { throw 'DevFleet TAR/portable release build failed while preparing release inputs.' }
  $tar = Join-Path $Outputs "devfleet-v$devfleetVersion.tar.gz"
  $hash = (Get-FileHash -LiteralPath $tar -Algorithm SHA256).Hash.ToLowerInvariant()
  $payload = Join-Path $Installer 'DevFleet.Setup\Payload'
  Get-ChildItem -LiteralPath $payload -Filter '*.tar.gz' -File -ErrorAction SilentlyContinue | Remove-Item -Force
  Copy-Item -LiteralPath $tar -Destination (Join-Path $payload (Split-Path -Leaf $tar)) -Force

  $manifestText = @"
namespace DevFleet.Setup;

internal static class PayloadManifest
{
    public const string DevFleetVersion = "$devfleetVersion";
    public const string InstallerVersion = "$installerVersion";
    public const string PayloadName = "devfleet-v$devfleetVersion.tar.gz";
    public const string PayloadSha256 = "$hash";
}
"@
  Write-Utf8NoBom (Join-Path $Installer 'DevFleet.Setup\PayloadManifest.cs') $manifestText

  $project = Join-Path $Installer 'DevFleet.Setup\DevFleet.Setup.csproj'
  $projectText = Get-Content -LiteralPath $project -Raw
  $projectText = [regex]::Replace($projectText, '<Version>[^<]+</Version>', "<Version>$installerVersion</Version>")
  $projectText = [regex]::Replace($projectText, '<FileVersion>[^<]+</FileVersion>', "<FileVersion>$installerVersion.0</FileVersion>")
  $projectText = [regex]::Replace($projectText, '<InformationalVersion>[^<]+</InformationalVersion>', "<InformationalVersion>DevFleet Setup $installerVersion for DevFleet $devfleetVersion</InformationalVersion>")
  $projectText = [regex]::Replace($projectText, '<EmbeddedResource Include="Payload\\devfleet-v[^"]+\.tar\.gz" />', "<EmbeddedResource Include=`"Payload\devfleet-v$devfleetVersion.tar.gz`" />")
  $projectText = [regex]::Replace($projectText, '<EmbeddedResource Include="dependencies\.json"[^>]*/>', '<EmbeddedResource Include="dependencies.json" LogicalName="DevFleet.Setup.dependencies.json" />')
  Write-Utf8NoBom $project ($projectText.TrimEnd("`r", "`n") + [Environment]::NewLine)

  $applicationManifest = Join-Path $Installer 'DevFleet.Setup\app.manifest'
  $applicationManifestText = Get-Content -LiteralPath $applicationManifest -Raw
  $assemblyVersion = "$installerVersion.0"
  $applicationManifestText = [regex]::Replace($applicationManifestText, '(<assemblyIdentity\s+version=")[^"]+("\s+name="MTechLabs\.DevFleet\.Setup"\s*/>)', ("`${1}" + $assemblyVersion + '$2'))
  Write-Utf8NoBom $applicationManifest $applicationManifestText

  $offline = "$( $hash )  Payload/devfleet-v$devfleetVersion.tar.gz`n"
  Write-Utf8NoBom (Join-Path $Installer 'OFFLINE-PAYLOAD-SHA256.txt') $offline

  $signing = if ($SigningProfile -eq 'PrivateSelfSigned') {
    'PRIVATE SELF-SIGNED AUTHENTICODE — exact candidate signing and verification required before release eligibility'
  } else {
    'PUBLIC TRUSTED AUTHENTICODE — exact candidate signing and verification required before release eligibility'
  }
  $buildManifest = [ordered]@{
    installerProduct = 'DevFleet Setup'
    installerVersion = $installerVersion
    devfleetVersion = $devfleetVersion
    targetRuntime = 'win-x64'
    framework = 'net8.0-windows'
    selfContained = $true
    singleFile = $true
    payload = [ordered]@{ name = "devfleet-v$devfleetVersion.tar.gz"; sha256 = $hash }
    signing = $signing
    runtimeNetworkDownloads = $false
    productionMutationPerformed = $false
    releaseInputsPrepared = $true
  }
  Write-Utf8NoBom (Join-Path $Installer 'INSTALLER-BUILD-MANIFEST.json') (($buildManifest | ConvertTo-Json -Depth 8) + [Environment]::NewLine)
  return [pscustomobject]@{ Version = $devfleetVersion; Tar = $tar; Portable = (Join-Path $Outputs "DevFleet-v$devfleetVersion-Portable-Codebase-Verified-r1.zip"); TarSha256 = $hash }
}

function Assert-SameSnapshot($Before, $After, [string]$Label) {
  foreach ($key in $Before.Keys) {
    if ($Before[$key] -ne $After[$key]) { throw "Release input preparation is not idempotent ($Label): $key changed." }
  }
}

function Normalize-TextTree([string]$Root) {
  foreach ($file in Get-ChildItem -LiteralPath $Root -Recurse -File) {
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    if ($bytes -contains 0) { continue }
    try { $text = [Text.Encoding]::UTF8.GetString($bytes) } catch { continue }
    if ($text.IndexOf([char]0) -ge 0) { continue }
    $normalized = [regex]::Replace($text, "`r`n|`r", "`n")
    if ($normalized -cne $text) { Write-Utf8NoBom $file.FullName $normalized }
  }
}

function Copy-ReleaseTree([string]$Source, [string]$Destination) {
  $excluded = @('.git', '.test-runtime', '.pytest_cache', '__pycache__', 'runtime-migrations', 'bin', 'obj')
  foreach ($file in Get-ChildItem -LiteralPath $Source -Recurse -File) {
    $relative = $file.FullName.Substring($Source.Length).TrimStart('\')
    $parts = $relative -split '\\'
    if ($parts | Where-Object { $excluded -contains $_ -or $_ -like '.venv*' }) { continue }
    $target = Join-Path $Destination $relative
    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
    Copy-Item -LiteralPath $file.FullName -Destination $target -Force
  }
}

function Copy-PreparedShippingInputs([string]$PreparedSource, [string]$PreparedInstaller, [string]$Source, [string]$Installer) {
  $version = (Get-Content -LiteralPath (Join-Path $PreparedSource 'VERSION') -Raw).Trim()
  $copyPairs = @(
    @{ From = (Join-Path $PreparedSource 'CHECKSUMS.sha256'); To = (Join-Path $Source 'CHECKSUMS.sha256') },
    @{ From = (Join-Path $PreparedInstaller 'DevFleet.Setup\dependencies.json'); To = (Join-Path $Installer 'DevFleet.Setup\dependencies.json') },
    @{ From = (Join-Path $PreparedInstaller 'OFFLINE-PAYLOAD-SHA256.txt'); To = (Join-Path $Installer 'OFFLINE-PAYLOAD-SHA256.txt') },
    @{ From = (Join-Path $PreparedInstaller 'DevFleet.Setup\PayloadManifest.cs'); To = (Join-Path $Installer 'DevFleet.Setup\PayloadManifest.cs') },
    @{ From = (Join-Path $PreparedInstaller 'DevFleet.Setup\DevFleet.Setup.csproj'); To = (Join-Path $Installer 'DevFleet.Setup\DevFleet.Setup.csproj') },
    @{ From = (Join-Path $PreparedInstaller 'DevFleet.Setup\app.manifest'); To = (Join-Path $Installer 'DevFleet.Setup\app.manifest') },
    @{ From = (Join-Path $PreparedInstaller 'INSTALLER-BUILD-MANIFEST.json'); To = (Join-Path $Installer 'INSTALLER-BUILD-MANIFEST.json') },
    @{ From = (Join-Path $PreparedInstaller "DevFleet.Setup\Payload\devfleet-v$version.tar.gz"); To = (Join-Path $Installer "DevFleet.Setup\Payload\devfleet-v$version.tar.gz") }
  )
  foreach ($pair in $copyPairs) { Copy-Item -LiteralPath $pair.From -Destination $pair.To -Force }
}

function Invoke-NormalizedPrepare([string]$Source, [string]$Installer, [string]$Previous, [string]$Outputs) {
  $root = Join-Path ([IO.Path]::GetTempPath()) "devfleet-release-prepare-$([guid]::NewGuid().ToString('N'))"
  $preparedSource = Join-Path $root 'source'
  $preparedInstaller = Join-Path $root 'installer-source'
  $preparedOutputs = Join-Path $root 'outputs'
  try {
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    Copy-ReleaseTree $Source $preparedSource
    Copy-ReleaseTree $Installer $preparedInstaller
    Normalize-TextTree $preparedSource
    Normalize-TextTree $preparedInstaller
    New-Item -ItemType Directory -Path $preparedOutputs -Force | Out-Null
    $result = Invoke-Prepare $preparedSource $preparedInstaller $Previous $preparedOutputs
    Copy-PreparedShippingInputs $preparedSource $preparedInstaller $Source $Installer
    Copy-Item -Path (Join-Path $preparedOutputs '*') -Destination $Outputs -Force -Recurse
    return [pscustomobject]@{ Version = $result.Version; Tar = (Join-Path $Outputs (Split-Path -Leaf $result.Tar)); Portable = (Join-Path $Outputs (Split-Path -Leaf $result.Portable)); TarSha256 = $result.TarSha256 }
  } finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
  }
}

if ($Mode -eq 'Prepare') {
  $source = (Resolve-Path -LiteralPath $SourceRoot).Path
  $installer = $PSScriptRoot
  $previous = (Resolve-Path -LiteralPath $PreviousPortableZip).Path
  $output = (Resolve-Path -LiteralPath (New-Item -ItemType Directory -Path $OutputDirectory -Force)).Path
  $first = Invoke-NormalizedPrepare $source $installer $previous $output
  if ($ProveIdempotent) {
    $afterFirst = Get-Snapshot $source $installer
    [void](Invoke-NormalizedPrepare $source $installer $previous $output)
    $afterSecond = Get-Snapshot $source $installer
    Assert-SameSnapshot $afterFirst $afterSecond 'second prepare pass'
    Write-Output 'RELEASE_INPUT_PREPARE_IDEMPOTENCE=PASS'
  }
  [ordered]@{ mode = 'Prepare'; version = $first.Version; tar = $first.Tar; portable = $first.Portable; tarSha256 = $first.TarSha256 } | ConvertTo-Json -Compress
  exit 0
}

if ($ProveIdempotent) { throw '-ProveIdempotent is valid only with -Mode Prepare.' }
$sourcePath = (Resolve-Path -LiteralPath $SourceRoot).Path
$workspace = Split-Path -Parent $sourcePath
if ($CandidateCommit -notmatch '^[0-9a-fA-F]{40}$') { throw 'Verify mode requires an explicit 40-character candidate commit.' }
$previous = (Resolve-Path -LiteralPath $PreviousPortableZip).Path
$verificationRoot = Join-Path ((Resolve-Path -LiteralPath (New-Item -ItemType Directory -Path $OutputDirectory -Force)).Path) '.release-input-stage'
if (Test-Path -LiteralPath $verificationRoot) { Remove-Item -LiteralPath $verificationRoot -Recurse -Force }
New-Item -ItemType Directory -Path $verificationRoot -Force | Out-Null
$archive = Join-Path $verificationRoot 'candidate.tar'
& git -C $workspace -c core.autocrlf=false archive --format=tar --output=$archive $CandidateCommit source installer-source tools automation
if ($LASTEXITCODE) { throw "Could not materialize candidate commit $CandidateCommit for release-input verification." }
$candidateTree = Join-Path $verificationRoot 'candidate'
$buildTree = Join-Path $verificationRoot 'build'
New-Item -ItemType Directory -Path $candidateTree,$buildTree -Force | Out-Null
& tar -xf $archive -C $candidateTree
if ($LASTEXITCODE) { throw 'Candidate shipping tree extraction failed during release-input verification.' }
Copy-Item -LiteralPath (Join-Path $candidateTree 'source') -Destination $buildTree -Recurse
Copy-Item -LiteralPath (Join-Path $candidateTree 'installer-source') -Destination $buildTree -Recurse
Copy-Item -LiteralPath (Join-Path $candidateTree 'tools') -Destination $buildTree -Recurse -ErrorAction SilentlyContinue
Copy-Item -LiteralPath (Join-Path $candidateTree 'automation') -Destination $buildTree -Recurse -ErrorAction SilentlyContinue
$buildSource = Join-Path $buildTree 'source'
$buildInstaller = Join-Path $buildTree 'installer-source'
$buildOutputs = Join-Path $verificationRoot 'artifacts'
$expected = Get-Snapshot $candidateTree\source $candidateTree\installer-source
[void](Invoke-Prepare $buildSource $buildInstaller $previous $buildOutputs)
$actual = Get-Snapshot $buildSource $buildInstaller
Assert-SameSnapshot $expected $actual 'candidate commit'
[ordered]@{ mode = 'Verify'; candidateCommit = $CandidateCommit; sourceRoot = $buildSource; installerRoot = $buildInstaller; outputDirectory = $buildOutputs; status = 'PASS' } | ConvertTo-Json -Compress
