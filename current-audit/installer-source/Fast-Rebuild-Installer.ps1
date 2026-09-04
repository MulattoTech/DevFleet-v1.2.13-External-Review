[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputDirectory,[string]$DotNet='dotnet',[switch]$UnsignedDeveloperBuild)
$ErrorActionPreference='Stop';$root=$PSScriptRoot;$version=(Get-Content -LiteralPath (Join-Path $root '..\source\VERSION') -Raw -ErrorAction Stop).Trim();if(-not $version){throw 'Source VERSION is empty.'}
if(-not $UnsignedDeveloperBuild){throw 'Fast rebuild is developer-only and requires -UnsignedDeveloperBuild; it never produces a release artifact.'}
$publish=Join-Path $OutputDirectory 'publish-fast';New-Item -ItemType Directory -Path $publish -Force|Out-Null
& $DotNet publish (Join-Path $root 'DevFleet.Setup\DevFleet.Setup.csproj') -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o $publish
if($LASTEXITCODE){throw 'Fast installer rebuild failed.'}
Copy-Item -LiteralPath (Join-Path $publish 'DevFleet.Setup.exe') -Destination (Join-Path $OutputDirectory "DevFleet-Setup-v$version-win-x64.exe") -Force
Write-Warning "Fast installer rebuild complete as an explicitly unsigned developer artifact."
