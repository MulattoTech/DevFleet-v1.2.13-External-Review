Set-StrictMode -Version Latest

function Write-AtomicJson {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][object]$Value)
    $full = [IO.Path]::GetFullPath($Path)
    $dir = Split-Path -Parent $full
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $tmp = "$full.$([guid]::NewGuid().ToString('N')).tmp"
    $json = $Value | ConvertTo-Json -Depth 32
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    $stream = [IO.File]::Open($tmp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    Move-Item -LiteralPath $tmp -Destination $full -Force
}

function Read-StrictJson {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "State file not found: $Path" }
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding utf8
    if ([string]::IsNullOrWhiteSpace($raw)) { throw "State file is empty: $Path" }
    try { $raw | ConvertFrom-Json -ErrorAction Stop } catch { throw "Invalid JSON state: $Path" }
}

function New-HarnessRunId { "e2e-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))-$([guid]::NewGuid().ToString('N').Substring(0,8))" }

function Save-RunState { param([Parameter(Mandatory)][psobject]$State,[Parameter(Mandatory)][string]$Path); Write-AtomicJson -Path $Path -Value $State }

function Assert-ResumeIdentity {
    param([Parameter(Mandatory)][psobject]$State,[Parameter(Mandatory)][psobject]$Fingerprint,[psobject]$Vm)
    if ($State.candidateHashes -and $State.candidateHashes.exe -ne $Fingerprint.candidate.sha256) { throw 'Resume refused: candidate hash changed.' }
    if ($State.candidateHashes -and $State.candidateHashes.tar -ne $Fingerprint.tar.sha256) { throw 'Resume refused: TAR hash changed.' }
    if ($State.vmId -and $Vm -and $State.vmId -ne $Vm.Id.ToString()) { throw 'Resume refused: disposable VM identity changed.' }
    $true
}

Export-ModuleMember -Function Write-AtomicJson,Read-StrictJson,New-HarnessRunId,Save-RunState,Assert-ResumeIdentity
