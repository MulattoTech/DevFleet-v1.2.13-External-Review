function ConvertFrom-DevFleetJsonc {
    param([Parameter(Mandatory)][string]$Text)
    $out = New-Object Text.StringBuilder
    $inString = $false; $escape = $false; $lineComment = $false; $blockComment = $false
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $c = $Text[$i]; $next = if ($i + 1 -lt $Text.Length) { $Text[$i + 1] } else { [char]0 }
        if ($lineComment) { if ($c -eq "`r" -or $c -eq "`n") { $lineComment = $false; [void]$out.Append($c) }; continue }
        if ($blockComment) { if ($c -eq '*' -and $next -eq '/') { $blockComment = $false; $i++ }; continue }
        if ($inString) {
            [void]$out.Append($c)
            if ($escape) { $escape = $false } elseif ($c -eq '\') { $escape = $true } elseif ($c -eq '"') { $inString = $false }
            continue
        }
        if ($c -eq '"') { $inString = $true; [void]$out.Append($c); continue }
        if ($c -eq '/' -and $next -eq '/') { $lineComment = $true; $i++; continue }
        if ($c -eq '/' -and $next -eq '*') { $blockComment = $true; $i++; continue }
        [void]$out.Append($c)
    }
    return [regex]::Replace($out.ToString(), ',\s*([}\]])', '$1')
}

function Read-DevFleetVsCodeSettings {
    param([Parameter(Mandatory)][string]$Path)
    $raw = [IO.File]::ReadAllText($Path)
    try { return [pscustomobject]@{Raw=$raw;Data=(ConvertFrom-DevFleetJsonc $raw | ConvertFrom-Json -AsHashtable)} }
    catch {
        # Preserve the evidence before reporting malformed user settings. No
        # replacement is written when parsing fails.
        $backup = "$Path.devfleet-backup-$([guid]::NewGuid().ToString('N')).jsonc"
        [IO.File]::Copy($Path, $backup, $false)
        throw "VS Code settings are not valid JSONC; preserved backup $backup"
    }
}

function Write-DevFleetVsCodeSettings {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)]$Data)
    $json = $Data | ConvertTo-Json -Depth 50
    $backup = "$Path.devfleet-backup-$([guid]::NewGuid().ToString('N')).jsonc"
    [IO.File]::Copy($Path, $backup, $false)
    $tmp = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try { [IO.File]::WriteAllText($tmp, $json, (New-Object Text.UTF8Encoding($false))); Move-Item -LiteralPath $tmp -Destination $Path -Force }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    return $backup
}

function Set-DevFleetVsCodeRemotePlatform {
    param([Parameter(Mandatory)][string[]]$Paths,[Parameter(Mandatory)][string]$Alias)
    $updated = @(); $skipped = @()
    foreach ($path in $Paths) {
        if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { $skipped += $path; continue }
        $settings = Read-DevFleetVsCodeSettings $path
        $data = $settings.Data
        if ($null -eq $data) { $data = @{} }
        if (-not ($data -is [hashtable])) { throw "VS Code settings root must be an object: $path" }
        $mapping = if ($data.ContainsKey('remote.SSH.remotePlatform') -and $data['remote.SSH.remotePlatform'] -is [hashtable]) { $data['remote.SSH.remotePlatform'] } else { @{} }
        if ([string]$mapping[$Alias] -eq 'linux') { $skipped += $path; continue }
        $mapping[$Alias] = 'linux'; $data['remote.SSH.remotePlatform'] = $mapping
        $backup = Write-DevFleetVsCodeSettings $path $data
        $updated += [ordered]@{path=$path;backup=$backup;alias=$Alias;platform='linux'}
    }
    return [ordered]@{ok=$true;status='updated';updated_paths=@($updated);skipped_paths=@($skipped);alias=$Alias;platform='linux'}
}

function Remove-DevFleetVsCodeRemotePlatform {
    param([Parameter(Mandatory)][string[]]$Paths,[Parameter(Mandatory)][string]$Alias)
    $removed = @(); $skipped = @()
    foreach ($path in $Paths) {
        if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { $skipped += $path; continue }
        $settings = Read-DevFleetVsCodeSettings $path; $data = $settings.Data
        if ($null -eq $data -or -not ($data -is [hashtable])) { throw "VS Code settings root must be an object: $path" }
        $mapping = $data['remote.SSH.remotePlatform']
        if ($mapping -isnot [hashtable] -or -not $mapping.ContainsKey($Alias)) { $skipped += $path; continue }
        $mapping.Remove($Alias)
        if ($mapping.Count -eq 0) { $data.Remove('remote.SSH.remotePlatform') }
        $backup = Write-DevFleetVsCodeSettings $path $data
        $removed += [ordered]@{path=$path;backup=$backup;alias=$Alias}
    }
    return [ordered]@{ok=$true;status='updated';removed_paths=@($removed);skipped_paths=@($skipped);alias=$Alias}
}

function Get-DevFleetVsCodeSettingsPaths {
    $values = @($script:Config.VsCodeSettingsPaths)
    return @($values | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
}

function Sync-DevFleetVsCodeRemotePlatform {
    param([Parameter(Mandatory)][string]$Alias)
    $paths = @(Get-DevFleetVsCodeSettingsPaths)
    $knownExecutables = @(
        (Join-Path ${env:ProgramFiles} 'Microsoft VS Code\Code.exe'),
        (Join-Path ${env:LOCALAPPDATA} 'Programs\Microsoft VS Code\Code.exe'),
        (Join-Path ${env:ProgramFiles} 'Microsoft VS Code Insiders\Code - Insiders.exe'),
        (Join-Path ${env:LOCALAPPDATA} 'Programs\Microsoft VS Code Insiders\Code - Insiders.exe')
    )
    if (-not ($knownExecutables | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })) { return [ordered]@{ok=$true;status='skipped';reason='VS Code is not installed.';updated_paths=@();alias=$Alias;platform='linux'} }
    return Set-DevFleetVsCodeRemotePlatform $paths $Alias
}
