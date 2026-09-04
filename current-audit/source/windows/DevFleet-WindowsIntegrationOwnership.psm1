Set-StrictMode -Version Latest

function ConvertTo-DevFleetCanonicalPath {
    param([Parameter(Mandatory)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Windows integration executable path is empty.' }
    return [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Path)).TrimEnd('\')
}

function Assert-DevFleetExactFields {
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][hashtable]$Expected,
        [Parameter(Mandatory)][hashtable]$Actual,
        [Parameter(Mandatory)][string[]]$Fields
    )
    foreach ($field in $Fields) {
        $expectedValue = [string]$Expected[$field]
        $actualValue = [string]$Actual[$field]
        $comparison = if ($field -in @('Arguments','Description')) { [StringComparison]::Ordinal } else { [StringComparison]::OrdinalIgnoreCase }
        if (-not [string]::Equals($expectedValue,$actualValue,$comparison)) {
            throw "WINDOWS INTEGRATION OWNERSHIP CONFLICT: $Kind field '$field' does not match the installation ownership ledger. Foreign resource preserved."
        }
    }
    return $true
}

function Assert-DevFleetTaskBinding {
    param([Parameter(Mandatory)][hashtable]$Expected,[Parameter(Mandatory)][hashtable]$Actual)
    $Expected.Executable = ConvertTo-DevFleetCanonicalPath ([string]$Expected.Executable)
    $Actual.Executable = ConvertTo-DevFleetCanonicalPath ([string]$Actual.Executable)
    Assert-DevFleetExactFields 'scheduled task' $Expected $Actual @('Name','Executable','Arguments','Principal','LogonType','RunLevel','Description','Generation')
}

function Assert-DevFleetFirewallBinding {
    param([Parameter(Mandatory)][hashtable]$Expected,[Parameter(Mandatory)][hashtable]$Actual)
    Assert-DevFleetExactFields 'firewall rule' $Expected $Actual @('Name','DisplayName','Group','Description','Direction','Action','Protocol','LocalPort','InterfaceAlias','RemoteAddress','Profile','Generation')
}

function Assert-DevFleetServiceBinding {
    param([Parameter(Mandatory)][hashtable]$Expected,[Parameter(Mandatory)][hashtable]$Actual)
    $Expected.ImagePath = ConvertTo-DevFleetCanonicalPath ([string]$Expected.ImagePath)
    $liveImage = [string]$Actual.ImagePath
    if ($liveImage.StartsWith('"')) {
        $closingQuote = $liveImage.IndexOf('"',1)
        if ($closingQuote -lt 2) { throw 'WINDOWS INTEGRATION OWNERSHIP CONFLICT: service image path is malformed. Foreign service preserved.' }
        $liveImage = $liveImage.Substring(1,$closingQuote - 1)
    } else {
        $liveImage = ($liveImage -split '\s+',2)[0]
    }
    $Actual.ImagePath = ConvertTo-DevFleetCanonicalPath $liveImage
    Assert-DevFleetExactFields 'service' $Expected $Actual @('Name','ImagePath','Account','StartMode','Generation')
}

function Read-DevFleetIntegrationOwnership {
    param([Parameter(Mandatory)][string]$Path,[switch]$AllowMissing)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        if ($AllowMissing) { return $null }
        throw "Windows integration ownership ledger is missing: $Path"
    }
    if ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Windows integration ownership ledger is a reparse point; all resources preserved.'
    }
    $ledger = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
    if (-not $ledger -or [int]$ledger.SchemaVersion -ne 1 -or [string]::IsNullOrWhiteSpace([string]$ledger.InstallationGeneration)) {
        throw 'Windows integration ownership ledger is malformed or unsupported.'
    }
    $generation = [guid]::Empty
    if (-not [guid]::TryParse([string]$ledger.InstallationGeneration,[ref]$generation) -or $generation -eq [guid]::Empty) {
        throw 'Windows integration ownership ledger generation is invalid.'
    }
    $identities = @{}
    foreach ($kindAndBindings in @(@('ScheduledTask',@($ledger.ScheduledTasks)),@('FirewallRule',@($ledger.FirewallRules)),@('Service',@($ledger.Services)))) {
        $kind = [string]$kindAndBindings[0]
        foreach ($binding in @($kindAndBindings[1])) {
        if ([string]$binding.Generation -ne [string]$ledger.InstallationGeneration) {
            throw 'Windows integration ownership ledger contains a cross-generation binding.'
        }
            $name = [string]$binding.Name
            if ([string]::IsNullOrWhiteSpace($name) -or $name.Contains('*') -or $name.Contains('?')) { throw 'Windows integration ownership ledger contains an ambiguous identity.' }
            $identity = "$kind`0$name".ToLowerInvariant()
            if ($identities.ContainsKey($identity)) { throw 'Windows integration ownership ledger contains a duplicate identity.' }
            $identities[$identity] = $true
            $required = switch ($kind) {
                'ScheduledTask' { @('Marker','Executable','Arguments','Principal','LogonType','RunLevel','Description') }
                'FirewallRule' { @('Marker','DisplayName','Group','Description','Direction','Action','Protocol','LocalPort','InterfaceAlias','RemoteAddress','Profile') }
                'Service' { @('Marker','ImagePath','Account','StartMode') }
            }
            foreach ($field in $required) {
                if ([string]::IsNullOrWhiteSpace([string]$binding[$field])) { throw "Windows integration ownership ledger contains an incomplete $kind binding." }
            }
        }
    }
    return $ledger
}

function Write-DevFleetIntegrationOwnership {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][hashtable]$Ledger)
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText($temporary,($Ledger | ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

Export-ModuleMember -Function ConvertTo-DevFleetCanonicalPath,Assert-DevFleetTaskBinding,Assert-DevFleetFirewallBinding,Assert-DevFleetServiceBinding,Read-DevFleetIntegrationOwnership,Write-DevFleetIntegrationOwnership
