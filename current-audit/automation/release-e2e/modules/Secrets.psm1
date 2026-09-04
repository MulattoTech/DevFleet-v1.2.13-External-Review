Set-StrictMode -Version Latest

function Get-DevFleetE2ESecretPath {
    Join-Path $env:LOCALAPPDATA 'DevFleet\E2E\secrets.json'
}

function Save-DevFleetE2ECredential {
    param([Parameter(Mandatory)][pscredential]$Credential)
    $path = Get-DevFleetE2ESecretPath
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
    $data = [ordered]@{ schemaVersion=1; username=$Credential.UserName; passwordDpapi=$Credential.Password | ConvertFrom-SecureString; createdAt=(Get-Date).ToUniversalTime().ToString('o') }
    $data | ConvertTo-Json | Set-Content -LiteralPath $path -Encoding utf8
    [IO.File]::SetAttributes($path,[IO.FileAttributes]::Hidden)
    $path
}

function Get-DevFleetE2ECredential {
    $path = Get-DevFleetE2ESecretPath
    if (-not (Test-Path -LiteralPath $path)) { throw "Secure E2E credential store not initialized: $path" }
    $data = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    [pscredential]::new([string]$data.username,(ConvertTo-SecureString -String ([string]$data.passwordDpapi)))
}

Export-ModuleMember -Function Get-DevFleetE2ESecretPath,Save-DevFleetE2ECredential,Get-DevFleetE2ECredential
