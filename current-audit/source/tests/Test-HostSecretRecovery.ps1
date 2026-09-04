$ErrorActionPreference = 'Stop'
$originalProgramData = $env:ProgramData
$testProgramData = Join-Path ([IO.Path]::GetTempPath()) "devfleet-secret-tests-$([guid]::NewGuid().ToString('N'))"
$env:ProgramData = $testProgramData
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'windows\DevFleet.Common.psm1') -Force

function Reset-State([switch]$Existing) {
    $root = Get-DevFleetStateRoot
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
    New-Item -ItemType Directory -Path (Join-Path $root 'secrets') -Force | Out-Null
    if ($Existing) { [IO.File]::WriteAllText((Join-Path $root 'node-identity.json'),' {"schema_version":1,"node_id":"fixture"} ') }
    return $root
}
function Assert-RecoveryRequired([scriptblock]$Action) {
    try { & $Action; throw 'Expected SECRET RECOVERY REQUIRED.' }
    catch { if ($_.Exception.Message -notmatch '^SECRET RECOVERY REQUIRED') { throw } }
}

try {
    $root = Reset-State
    $fresh = Get-OrCreateSecrets
    if (-not (Test-DevFleetSecretRecord $fresh) -or [int]$fresh.SchemaVersion -ne 2 -or [string]$fresh.SecretGeneration -notmatch '^[0-9a-fA-F-]{36}$') { throw 'Fresh secret generation is invalid.' }

    $root = Reset-State -Existing
    Assert-RecoveryRequired { Get-OrCreateSecrets | Out-Null }

    $root = Reset-State -Existing
    [IO.File]::WriteAllText((Join-Path $root 'secrets\host-secrets.json'),'{not-json')
    Assert-RecoveryRequired { Get-OrCreateSecrets | Out-Null }

    $root = Reset-State -Existing
    [IO.File]::WriteAllText((Join-Path $root 'secrets\host-secrets.json'),'{"PortalAdminUser":"dylan"}')
    Assert-RecoveryRequired { Get-OrCreateSecrets | Out-Null }

    $first = New-DevFleetSecretRecord
    $second = New-DevFleetSecretRecord
    if ($first.SecretGeneration -eq $second.SecretGeneration -or $first.NodeApiToken -eq $second.NodeApiToken) { throw 'Re-key generations or token material were reused.' }
    'PASS host secret fail-closed and generation tests'
} finally {
    $env:ProgramData = $originalProgramData
    if (Test-Path -LiteralPath $testProgramData) { Remove-Item -LiteralPath $testProgramData -Recurse -Force }
}
