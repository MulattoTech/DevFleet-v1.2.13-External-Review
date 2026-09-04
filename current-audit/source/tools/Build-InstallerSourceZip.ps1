[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourceRoot,
    [Parameter(Mandatory)][string]$InstallerRoot,
    [Parameter(Mandatory)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$sourceRootResolved = (Resolve-Path -LiteralPath $SourceRoot).Path
$sourceCandidate = Join-Path $sourceRootResolved 'source'
$source = if (Test-Path -LiteralPath (Join-Path $sourceCandidate 'VERSION')) { (Resolve-Path -LiteralPath $sourceCandidate).Path } else { $sourceRootResolved }
$installer = (Resolve-Path -LiteralPath $InstallerRoot).Path
$output = [IO.Path]::GetFullPath($OutputPath)
New-Item -ItemType Directory -Force -Path ([IO.Path]::GetDirectoryName($output)) | Out-Null
if ([IO.File]::Exists($output)) { [IO.File]::Delete($output) }

$excluded = @(
    '\.git([\\/]|$)',
    '(^|[\\/])(bin|obj|node_modules|__pycache__|\.pytest_cache|\.test-runtime|\.venv[^\\/]*|test-images|outputs|audit|dotnet-sdk)([\\/]|$)',
    '(^|[\\/])DevFleet\.Setup([\\/])Payload([\\/]).*\.(tar\.gz|exe)$',
    '\.(vhd|vhdx|avhdx|iso|exe)$'
)
$seen = @{}
$zip = [IO.Compression.ZipFile]::Open($output, [IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($root in @($source, $installer)) {
        foreach ($file in Get-ChildItem -LiteralPath $root -Recurse -File | Sort-Object FullName) {
            $relative = ([Uri]::new(($root.TrimEnd('\') + '\')).MakeRelativeUri([Uri]::new($file.FullName)).ToString()).Replace('/','/')
            if ($excluded | Where-Object { $relative -match $_ }) { continue }
            $entryName = $relative
            if ($seen.ContainsKey($entryName)) {
                if ($root -eq $installer -and $entryName -eq 'dependencies.json') { continue }
                $existingHash = $seen[$entryName]
                $currentHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
                if ($existingHash -ne $currentHash) { throw "Source archive collision with different contents: $entryName" }
                continue
            }
            $entry = $zip.CreateEntry($entryName, [IO.Compression.CompressionLevel]::Optimal)
            $input = [IO.File]::OpenRead($file.FullName); $outputStream = $entry.Open()
            try { $input.CopyTo($outputStream) } finally { $outputStream.Dispose(); $input.Dispose() }
            $seen[$entryName] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        }
    }
} finally { $zip.Dispose() }
$result = Get-Item -LiteralPath $output
Write-Host "Installer source archive generated: $output ($($result.Length) bytes)"
