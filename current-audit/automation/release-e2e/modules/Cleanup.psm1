Set-StrictMode -Version Latest

function New-CleanupManifest {
    param([Parameter(Mandatory)][psobject]$Vm,[Parameter(Mandatory)][string]$RunId)
    if ($Vm.Name -notlike 'DevFleet-E2E-*') { throw 'Cleanup manifest refused a non-disposable VM.' }
    [pscustomobject]@{
        schemaVersion=1; runId=$RunId; createdAt=(Get-Date).ToUniversalTime().ToString('o');
        resources=@([pscustomobject]@{ kind='Hyper-V VM'; name=$Vm.Name; id=$Vm.Id.ToString(); ownership='exact recorded disposable identity'; destructiveAllowed=$true });
        deniedNames=@('devfleet-primary','devfleet-project-m-techlabs-job-finder','MulattoTechSurface','MULATTOTECHBOX');
        productionTouched=$false
    }
}

function Test-CleanupManifest {
    param([Parameter(Mandatory)][psobject]$Manifest)
    foreach($r in @($Manifest.resources)) {
        if ($r.name -notlike 'DevFleet-E2E-*' -or -not $r.id -or $r.destructiveAllowed -ne $true) { return $false }
    }
    if ($Manifest.productionTouched -ne $false) { return $false }
    $true
}

function Get-OwnedManifestVm {
    param([Parameter(Mandatory)][psobject]$Resource)
    if ($Resource.name -notlike 'DevFleet-E2E-*' -or -not $Resource.id -or $Resource.destructiveAllowed -ne $true) {
        throw 'Cleanup resource failed exact disposable identity validation.'
    }
    try { $expectedId = [guid][string]$Resource.id }
    catch { throw "Cleanup resource has an invalid VM ID for $($Resource.name)." }
    $vm = Get-VM -Id $expectedId -ErrorAction Stop
    if ($vm.Id -ne $expectedId -or $vm.Name -cne [string]$Resource.name) {
        throw "Cleanup identity mismatch for $($Resource.name)."
    }
    return $vm
}

function Stop-ManifestVm {
    param([Parameter(Mandatory)][psobject]$Manifest)
    if (-not (Test-CleanupManifest $Manifest)) { throw 'Cleanup manifest failed validation.' }
    foreach($r in @($Manifest.resources)) {
        $vm = Get-OwnedManifestVm -Resource $r
        if ($vm.State -ne 'Off') { Stop-VM -VM $vm -Force -Confirm:$false }
    }
}

function Write-TerminalVmEvidence {
    param([Parameter(Mandatory)][psobject]$Vm,[Parameter(Mandatory)][string]$RunDir,[Parameter(Mandatory)][string]$L2Name)
    if($Vm.Name -notlike 'DevFleet-E2E-*' -or -not $Vm.Id){throw 'Terminal evidence requires an exact disposable L1 identity.'}
    if([string]::IsNullOrWhiteSpace($L2Name) -or $L2Name -notlike 'DevFleet-E2E-*' -or $L2Name -eq 'DevFleet-H10-Linux') { throw 'Terminal L2 evidence requires the configured exact disposable L2 name and explicitly protects DevFleet-H10-Linux.' }
    $actual=Get-VM -Id ([guid][string]$Vm.Id) -ErrorAction Stop
    if($actual.Name -cne [string]$Vm.Name -or $actual.Id.ToString() -cne $Vm.Id.ToString()){throw 'Terminal L1 identity changed while collecting evidence.'}
    $timestamp=(Get-Date).ToUniversalTime().ToString('o')
    $l1=[ordered]@{schemaVersion=1;name=$actual.Name;id=$actual.Id.ToString();state=[string]$actual.State;timestamp=$timestamp;timestampUtc=$timestamp;ownershipScope='exact disposable DevFleet-E2E VM identity';ownershipMethod='Get-VM -Id plus exact case-sensitive name';runId=(Split-Path -Leaf $RunDir)}
    $l2s=@(Get-VM -Name $L2Name -ErrorAction SilentlyContinue)
    if($l2s.Count -gt 1){throw "Terminal L2 evidence found ambiguous duplicate exact name '$L2Name'; refusing cleanup claim."}
    $l2=$null
    if($l2s.Count -eq 1){$item=$l2s[0];$l2=[ordered]@{schemaVersion=1;expectedName=$L2Name;present=$true;id=$item.Id.ToString();state=[string]$item.State;timestamp=$timestamp;timestampUtc=$timestamp;verificationMethod='Get-VM -Name exact; presence only, no ownership/adoption claim';ownershipScope='not claimed'} }
    else {$l2=[ordered]@{schemaVersion=1;expectedName=$L2Name;present=$false;timestamp=$timestamp;timestampUtc=$timestamp;verificationMethod='Get-VM -Name exact returned no VM';ownershipScope='exact expected disposable L2 name only'}}
    Write-EvidenceJson -Path (Join-Path $RunDir 'l1-terminal-state.json') -Value $l1
    Write-EvidenceJson -Path (Join-Path $RunDir 'l2-terminal-state.json') -Value $l2
    [pscustomobject]@{l1=$l1;l2=$l2}
}

Export-ModuleMember -Function New-CleanupManifest,Test-CleanupManifest,Get-OwnedManifestVm,Stop-ManifestVm,Write-TerminalVmEvidence
