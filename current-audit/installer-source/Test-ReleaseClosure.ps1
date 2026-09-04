[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$SourceRoot,
  [Parameter(Mandatory)][string]$PreviousPortableZip,
  [Parameter(Mandatory)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path -LiteralPath $SourceRoot).Path | Split-Path -Parent
$commit = (git -C $workspace rev-parse HEAD).Trim()
if ($commit -notmatch '^[0-9a-fA-F]{40}$') { throw 'Release closure regression requires an explicit candidate commit.' }
$tool = Join-Path $workspace 'tools\compute_shipping_input_identity.py'
$candidateJson = & python $tool --workspace $workspace --candidate-commit $commit | Select-Object -Last 1
if ($LASTEXITCODE) { throw 'Could not compute candidate shipping identity.' }
$candidate = $candidateJson | ConvertFrom-Json
$verifyJson = & pwsh -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Prepare-ReleaseInputs.ps1') -Mode Verify -SourceRoot $SourceRoot -PreviousPortableZip $PreviousPortableZip -OutputDirectory $OutputDirectory -SigningProfile PrivateSelfSigned -CandidateCommit $commit | Select-Object -Last 1
if ($LASTEXITCODE) { throw 'Frozen release-input verification failed.' }
$verify = $verifyJson | ConvertFrom-Json
$beforeJson = & python $tool --source-root $verify.sourceRoot --installer-root $verify.installerRoot | Select-Object -Last 1
$before = $beforeJson | ConvertFrom-Json
$closureOutput = Join-Path $verify.outputDirectory 'closure-build'
New-Item -ItemType Directory -Path $closureOutput -Force | Out-Null
& python (Join-Path $verify.sourceRoot 'tools\build_release.py') --source $verify.sourceRoot --old-portable $PreviousPortableZip --output-dir $closureOutput
if ($LASTEXITCODE) { throw 'Prepared-commit build simulation failed.' }
$afterJson = & python $tool --source-root $verify.sourceRoot --installer-root $verify.installerRoot | Select-Object -Last 1
$after = $afterJson | ConvertFrom-Json
if ([string]$before.shippingInputIdentity -cne [string]$after.shippingInputIdentity -or [string]$before.shippingInputIdentity -cne [string]$candidate.candidateShippingInputIdentity) {
  throw 'FINAL BUILD AGAINST A PREPARED COMMIT failed: shipping identity before != after or candidate.'
}
[ordered]@{ status = 'PASS'; candidateCommit = $commit; shippingIdentityBefore = $before.shippingInputIdentity; shippingIdentityAfter = $after.shippingInputIdentity; candidateShippingIdentity = $candidate.candidateShippingInputIdentity } | ConvertTo-Json -Compress
