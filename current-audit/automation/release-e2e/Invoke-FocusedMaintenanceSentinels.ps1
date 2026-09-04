[CmdletBinding()]
param(
    [string]$WorkspaceRoot,
    [string]$Candidate,
    [string]$ConfigPath,
    [string]$RunId,
    [switch]$AllowRamPressure
)
$ErrorActionPreference='Stop'
$scriptRoot=$PSScriptRoot
if(-not $WorkspaceRoot){$WorkspaceRoot=(Resolve-Path (Join-Path $scriptRoot '..\..')).Path}else{$WorkspaceRoot=(Resolve-Path $WorkspaceRoot).Path}
if(-not $ConfigPath){$ConfigPath=Join-Path $scriptRoot 'config\devfleet-e2e.defaults.json'}
$config=Get-Content -LiteralPath $ConfigPath -Raw|ConvertFrom-Json
foreach($m in @('Candidate','HostSafety','ResumeState','Evidence','Cleanup','GuestSession','FullRelease')){Import-Module (Join-Path $scriptRoot "modules\$m.psm1") -Force}
$fingerprint=Get-CandidateFingerprint -WorkspaceRoot $WorkspaceRoot -CandidatePath $Candidate
$runId=if($RunId){$RunId}else{"focused-maintenance-$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))-$([guid]::NewGuid().ToString('N').Substring(0,8))"}
$runDir=New-RunEvidenceDirectory -WorkspaceRoot $WorkspaceRoot -RunId $runId
$vm=$null;$evidence=[ordered]@{status='BLOCKED';runId=$runId;phase='MAINTENANCE-READY/WINDOWS-SENTINELS';candidate=$fingerprint;runDir=$runDir;cleanup=$null}
try{
    $vm=Get-DisposableVm -Pattern ([string]$config.DisposableVmNamePattern);Assert-DisposableOwnership -Vm $vm|Out-Null
    $hostSafety=Apply-RamPressureOverride -Snapshot (Get-HostSafetySnapshot -Vm $vm -ExpectedVmStartCostGiB ([double]$config.ExpectedVmStartCostGiB)) -AllowRamPressure:$AllowRamPressure
    Write-EvidenceJson -Path (Join-Path $runDir 'focused-host-safety.json') -Value $hostSafety
    if(-not[bool]$hostSafety.effectiveE2EStartAuthorized){throw 'USER ACTION REQUIRED — fresh HOST-SAFETY startSafe=false.'}
    $fixture=Ensure-MaintenanceReadyFixture -Vm $vm -Fingerprint $fingerprint -Config $config -WorkspaceRoot $WorkspaceRoot -RunId $runId -RunDir $runDir
    Write-EvidenceJson -Path (Join-Path $runDir 'maintenance-ready-provenance-evidence.json') -Value $fixture
    $restored=Restore-MaintenanceReadyCheckpoint -Vm $vm -Fingerprint $fingerprint -WorkspaceRoot $WorkspaceRoot
    $context=[ordered]@{runId=$runId;phaseId='WINDOWS-SENTINELS';label='WINDOWS FOREIGN SENTINELS';checkpoint='DevFleet-E2E-MAINTENANCE-READY';destructive=$true;candidate=$fingerprint;vmName=$vm.Name;vmId=$vm.Id.ToString();runDir=$runDir;config=$config}
    $executor=Get-ExecutorPath -Config $config -PhaseId 'WINDOWS-SENTINELS' -WorkspaceRoot $WorkspaceRoot
    if(-not $executor){throw 'WINDOWS-SENTINELS executor is not configured.'}
    $sentinelEvidence=Invoke-ConfiguredExecutor -Path $executor -Context ([pscustomobject]$context)
    if([string]$sentinelEvidence.status -notin @('PASS','REAL E2E PASS') -or [string]$sentinelEvidence.sentinels.status -ne 'PASS' -or -not[bool]$sentinelEvidence.sentinels.unchanged){throw 'WINDOWS-SENTINELS did not prove foreign resources survived.'}
    Write-EvidenceJson -Path (Join-Path $runDir 'windows-sentinels-focused-evidence.json') -Value ([ordered]@{status='PASS';runId=$runId;hostSafety=$hostSafety;fixture=$fixture;independentRestore=$restored;windowsSentinels=$sentinelEvidence;foreignResourcesMutated=$false})
    $evidence.status='PASS';$evidence.hostSafety=$hostSafety;$evidence.fixture=$fixture;$evidence.independentRestore=$restored;$evidence.windowsSentinels=$sentinelEvidence;$evidence.foreignResourcesMutated=$false
}catch{
    $evidence.error=$_.Exception.Message
    Write-EvidenceJson -Path (Join-Path $runDir 'focused-maintenance-error.json') -Value $evidence
    throw
}finally{
    if($vm){
        try{$manifest=New-CleanupManifest -Vm $vm -RunId $runId;Write-EvidenceJson -Path (Join-Path $runDir 'cleanup-manifest.json') -Value $manifest;Stop-ManifestVm -Manifest $manifest;$final=Get-AssertedDisposableVm -ExpectedVm $vm;$evidence.cleanup=[ordered]@{manifest=(Join-Path $runDir 'cleanup-manifest.json');l1Name=$final.Name;l1Id=$final.Id.ToString();l1State=[string]$final.State;runOwnedOnly=$true};Write-EvidenceJson -Path (Join-Path $runDir 'focused-maintenance-final.json') -Value $evidence}catch{$evidence.cleanupError=$_.Exception.Message;Write-EvidenceJson -Path (Join-Path $runDir 'focused-maintenance-final.json') -Value $evidence}}
}
$evidence|ConvertTo-Json -Depth 32
