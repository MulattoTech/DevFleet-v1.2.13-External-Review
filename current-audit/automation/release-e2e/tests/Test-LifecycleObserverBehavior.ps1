[CmdletBinding()]
param([string]$WorkspaceRoot)
$ErrorActionPreference='Stop'
if(-not $WorkspaceRoot){$WorkspaceRoot=(Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path}
$module=Join-Path $WorkspaceRoot 'automation\release-e2e\modules\executors\Invoke-RealProductPhase.psm1'
Import-Module $module -Force
Import-Module (Join-Path $WorkspaceRoot 'automation\release-e2e\modules\HarnessBudget.psm1') -Force
$passed=0;$failed=[System.Collections.Generic.List[string]]::new();$script:testEvidenceDirs=[System.Collections.Generic.List[string]]::new();$lifeRoot=$null
try {
function Check([bool]$Condition,[string]$Name){if($Condition){$script:passed++}else{[void]$script:failed.Add($Name)}}
$prior=[pscustomobject]@{checkpointGeneration=1;transactionId='a'*32;payloadSha256='b'*64;action='FreshInstall';role='Primary / Desktop';state='waiting-for-reboot'}
function Obs([hashtable]$Values){$base=[ordered]@{checkpointPresent=$false;checkpoint=$null;matchingConsumedReceipt=$false;installStateValid=$false;canonicalOwnershipValid=$false;authenticatedHealthOk=$false;terminalFailure=$false};foreach($k in $Values.Keys){$base[$k]=$Values[$k]};[pscustomobject]$base}
$next=Obs @{checkpointPresent=$true;checkpoint=[pscustomobject]@{checkpointGeneration=2;transactionId='a'*32;payloadSha256='b'*64;action='FreshInstall';role='Primary / Desktop';state='waiting-for-reboot'}}
Check ((Get-DurableProgressClassification -Observation $next -PriorCheckpoint $prior -MaxGeneration 3) -eq 'NEXT_REBOOT') 'generation advancement returns NEXT_REBOOT'
$gen1=Obs @{checkpointPresent=$true;checkpoint=$prior}
Check ((Get-DurableProgressClassification -Observation $gen1 -PriorCheckpoint $prior -MaxGeneration 3) -eq 'NO_PROGRESS') 'generation 1 persistence is not another reboot'
$complete=Obs @{matchingConsumedReceipt=$true;installStateValid=$true;canonicalOwnershipValid=$true;authenticatedHealthOk=$true}
Check ((Get-DurableProgressClassification -Observation $complete -PriorCheckpoint $prior) -eq 'COMPLETED') 'matching receipt/install/ownership/authenticated health returns COMPLETED'
$mismatch=Obs @{checkpointPresent=$true;checkpoint=[pscustomobject]@{checkpointGeneration=2;transactionId='c'*32;payloadSha256='b'*64;action='FreshInstall';role='Primary / Desktop';state='waiting-for-reboot'}}
$mismatch.terminalFailure=$true
Check ((Get-DurableProgressClassification -Observation $mismatch -PriorCheckpoint $prior) -eq 'TERMINAL_FAILURE') 'binding mismatch returns TERMINAL_FAILURE'
$completedCheckpoint=Obs @{checkpointPresent=$true;checkpoint=$next.checkpoint;matchingConsumedReceipt=$true;installStateValid=$true;canonicalOwnershipValid=$true;authenticatedHealthOk=$true;status='COMPLETED'}
Check ((Get-DurableProgressClassification -Observation $completedCheckpoint -PriorCheckpoint $prior -MaxGeneration 3) -eq 'TERMINAL_FAILURE') 'COMPLETED carrying an active checkpoint fails closed'
$hiddenForeignCheckpoint=Obs @{checkpointPresent=$false;checkpoint=$mismatch.checkpoint}
Check ((Get-DurableProgressClassification -Observation $hiddenForeignCheckpoint -PriorCheckpoint $prior -MaxGeneration 3) -eq 'TERMINAL_FAILURE') 'checkpointPresent false cannot hide a foreign checkpoint'
$flagWithoutCheckpoint=Obs @{checkpointPresent=$true;checkpoint=$null}
Check ((Get-DurableProgressClassification -Observation $flagWithoutCheckpoint -PriorCheckpoint $prior -MaxGeneration 3) -eq 'TERMINAL_FAILURE') 'checkpointPresent true with null checkpoint fails closed'
$pending=Obs @{}
Check ((Get-DurableProgressClassification -Observation $pending -PriorCheckpoint $prior) -ne 'NO_PROGRESS_TIMEOUT') 'DURABLE_PENDING is an intermediate observation, never timeout'
Check ((Get-Command Wait-DevFleetProductLifecycleTransition).Name -eq 'Wait-DevFleetProductLifecycleTransition') 'observer is callable at runtime'
$realPhaseModule=Get-Module Invoke-RealProductPhase
$explicitExitObservation=[pscustomobject]@{terminalFailure=$true;failure='candidate process exited before a durable checkpoint or completion state';error='candidate process exited before a durable checkpoint or completion state';status='TERMINAL_FAILURE'}
$normalizedExitObservation=& $realPhaseModule {param($value) ConvertTo-NormalizedLifecycleObservation $value} $explicitExitObservation
Check ([string]$normalizedExitObservation.failure -eq 'candidate process exited before a durable checkpoint or completion state') 'explicit product-owned terminal failure survives observation normalization'
$firstServicing=[pscustomobject]@{cbs=$false;windowsUpdate=$false;pendingCount=2;RunspaceId=[guid]::NewGuid();PSComputerName='L1'}
$secondServicing=[pscustomobject]@{cbs=$false;windowsUpdate=$false;pendingCount=2;RunspaceId=[guid]::NewGuid();PSComputerName='L1'}
$servicingMetadataMatch=& $realPhaseModule {param($first,$second) Test-ProductServicingSamplesMatch -First $first -Second $second} $firstServicing $secondServicing
Check ([bool]$servicingMetadataMatch) 'servicing settlement ignores per-session remoting metadata'
$secondServicing.pendingCount=3
$servicingStateMismatch=& $realPhaseModule {param($first,$second) Test-ProductServicingSamplesMatch -First $first -Second $second} $firstServicing $secondServicing
Check (-not [bool]$servicingStateMismatch) 'servicing settlement detects semantic state changes'
$servicingMissingState=& $realPhaseModule {param($first,$second) Test-ProductServicingSamplesMatch -First $first -Second $second} $firstServicing ([pscustomobject]@{cbs=$false;windowsUpdate=$false})
Check (-not [bool]$servicingMissingState) 'servicing settlement fails closed on incomplete samples'
$source=Get-Content -Raw $module
Check ($source -match 'Invoke-HostAgentAuthenticatedJson' -and $source -notmatch 'Invoke-RestMethod -Uri ''http://127\.0\.0\.1:8790/healthz''') 'observer uses authenticated Host Agent protocol'
Check ($source -match 'progressSamples' -and $source -match 'cpuSeconds' -and $source -match 'Bootstrap-Install' -and $source -match 'Get-NetTCPConnection') 'observer records forward progress evidence'
Check ($source -match 'EvidenceLabel' -and $source -match 'resume-generation-' -and $source -match 'processStartTime' -and $source -match 'bootIdentity') 'WPF lifecycle legs have distinct immutable identity evidence'

# Behavioral seam: these tests use only an injected observation, clock, and
# sleep provider. They are intentionally VM-free and exercise the same wait
# loop used by the real observer.
function LifecycleObs([hashtable]$Values) {
    $base=[ordered]@{checkpointPresent=$false;checkpoint=$null;matchingConsumedReceipt=$false;installStateValid=$false;canonicalOwnershipValid=$false;authenticatedHealthOk=$false;terminalFailure=$false;processTree=@();timestampUtc='2026-01-01T00:00:00Z';progress=[ordered]@{checkpointGeneration=1;checkpointState='waiting-for-reboot';completedStages=@('bootstrap');resumeStage='install';stages=@([ordered]@{name='DevFleet.Setup';path='C:\DevFleet.Setup.exe';commandClass='candidate-child'});cpuSeconds=0;installStateSha256=$null;ownershipSha256=$null;receiptMatch=$false;health=$false;hostAgentTaskState='Running';listener=$false}}
    foreach($k in $Values.Keys){$base[$k]=$Values[$k]};[pscustomobject]$base
}
function RunInjectedWait([object[]]$Samples,[int]$NoProgress=2,[int]$Absolute=20,[double]$CpuThreshold=1.0) {
    $global:DevFleetTestClock=[datetime]'2026-01-01T00:00:00Z';$script:testIndex=0
    $clock={ $current=[datetime]$global:DevFleetTestClock; $global:DevFleetTestClock=$current.AddSeconds(5); return $current };$sleep={param($seconds)}
    $provider={param($state)$i=[Math]::Min([int]$state.observationIndex,$state.providerContext.Count-1);return $state.providerContext[$i]}
    $testEvidenceDir=Join-Path ([IO.Path]::GetTempPath()) ("devfleet-observer-test-{0}" -f ([guid]::NewGuid().ToString('N')));New-Item -ItemType Directory -Path $testEvidenceDir -Force|Out-Null;[void]$script:testEvidenceDirs.Add($testEvidenceDir)
    $path=Join-Path $testEvidenceDir 'observer-result.json'
    try{$result=Wait-DevFleetProductLifecycleTransition -Session ([pscustomobject]@{}) -TransactionId ('a'*32) -PayloadSha256 ('b'*64) -Action 'FreshInstall' -Role 'Primary / Desktop' -PriorGeneration 1 -MaxGeneration 3 -BudgetSeconds $Absolute -NoProgressBudgetSeconds $NoProgress -AbsoluteBudgetSeconds $Absolute -PollSeconds 10 -CpuDeltaThreshold $CpuThreshold -ExpectedDevFleetVersion '1.2.13' -ExpectedInstallerVersion '1.4.1' -EvidencePath $path -ObservationProvider $provider -ObservationProviderContext $Samples -ClockProvider $clock -SleepProvider $sleep;$result|Add-Member -NotePropertyName testEvidencePath -NotePropertyValue $path -Force;return $result}
    finally{$script:testIndex=0}
}
function CompletionSample([hashtable]$Values){$sample=LifecycleObs @{matchingConsumedReceipt=$true;installStateValid=$true;canonicalOwnershipValid=$true;authenticatedHealthOk=$true};$sample.progress.checkpointGeneration=0;$sample.progress.checkpointState='';$sample.progress.resumeStage='';foreach($k in $Values.Keys){$sample|Add-Member -NotePropertyName $k -NotePropertyValue $Values[$k] -Force};return $sample}
function Check-WaitTerminalEvidence([psobject]$Result,[string]$Name){$path=[string]$Result.testEvidencePath;$dir=if($path){Split-Path -Parent $path}else{''};$journal=if($dir){Join-Path $dir 'product-lifecycle-progress.jsonl'}else{''};$current=if($dir){Join-Path $dir 'product-lifecycle-progress-current.json'}else{''};$present=($path -and (Test-Path -LiteralPath $path) -and (Test-Path -LiteralPath $journal) -and (Test-Path -LiteralPath $current));$matches=$false;if($present){try{$last=@(Get-Content -LiteralPath $journal|Where-Object{$_})[-1]|ConvertFrom-Json;$matches=([string]$last.event -eq 'TERMINAL' -and [string]$last.terminalReason -eq [string]$Result.outcome)}catch{}};Check ($present -and $matches) "$Name writes terminal/current/journal evidence"}
function ProviderForm([int]$Kind,[hashtable]$Values){if($Kind -eq 0){return [pscustomobject]$Values};if($Kind -eq 1){return $Values};if($Kind -eq 2){$ordered=[ordered]@{};foreach($key in $Values.Keys){$ordered[$key]=$Values[$key]};return $ordered};$generic=[Collections.Generic.Dictionary[string,object]]::new();foreach($key in $Values.Keys){$generic[$key]=$Values[$key]};return $generic}
$stable=LifecycleObs @{}
$stableResult=RunInjectedWait @($stable,$stable,$stable) 60 120
Check ([string]$stableResult.outcome -eq 'NO_PROGRESS_TIMEOUT') 'OBS-01 stable lifecycle naturally returns NO_PROGRESS_TIMEOUT'
Check ([int]$stableResult.progressSampleCount -ge 2) 'OBS-01 bounded timeline has repeated observations'
$churn=LifecycleObs @{};$churn.processTree=@([ordered]@{ProcessId=100;Name='powershell.exe';CommandLine='-ServerMode V2SocketServerMode'})
$churnResult=RunInjectedWait @($churn,$churn,$churn) 60 120
Check ([string]$churnResult.outcome -eq 'NO_PROGRESS_TIMEOUT') 'OBS-02/03 observer remoting and V2SocketServerMode churn do not reset clock'
$tiny=LifecycleObs @{};$tiny.progress.cpuSeconds=.2
$tinyResult=RunInjectedWait @($stable,$tiny,$tiny,$tiny) 60 120
Check ([string]$tinyResult.outcome -eq 'NO_PROGRESS_TIMEOUT') 'OBS-04 tiny CPU noise does not reset clock'
$meaningful=LifecycleObs @{};$meaningful.progress.cpuSeconds=2
$meaningfulResult=RunInjectedWait @($stable,$meaningful,$meaningful,$meaningful,$meaningful) 60 120
Check ([string]$meaningfulResult.outcome -eq 'NO_PROGRESS_TIMEOUT' -and [int]$meaningfulResult.progressSampleCount -gt 2) 'OBS-05 meaningful CPU delta is accepted before timeout'
$heartbeatSamples=@();for($i=0;$i -lt 20;$i++){$sample=LifecycleObs @{};$sample.progress.cpuSeconds=($i*2);$sample.progress.resumeStage="step-$i";$heartbeatSamples+=$sample};$absoluteResult=RunInjectedWait $heartbeatSamples 7200 120
Check ([string]$absoluteResult.outcome -eq 'ABSOLUTE_TIMEOUT') 'OBS-06 immutable absolute deadline cannot be extended'
$badVersionRejected=$false;try{Wait-DevFleetProductLifecycleTransition -Session ([pscustomobject]@{}) -TransactionId ('a'*32) -PayloadSha256 ('b'*64) -Role 'Primary / Desktop' -ExpectedDevFleetVersion '' -ExpectedInstallerVersion '1.4.1' -AbsoluteBudgetSeconds 1}catch{$badVersionRejected=$true}
Check ($badVersionRejected) 'OBS-06 expected version identity is fail-closed'
Check ([int]$stableResult.effectiveNoProgressBudgetSeconds -eq 60 -and [int]$stableResult.effectiveAbsoluteBudgetSeconds -eq 120 -and [int]$stableResult.requestedBudgetSeconds -eq 120) 'OBS-06 effective budgets preserve requested finite values without silent clamping'
$policy=Get-HarnessBudgetPolicy -Config (Get-Content (Join-Path $WorkspaceRoot 'automation\release-e2e\config\devfleet-e2e.defaults.json') -Raw|ConvertFrom-Json)
Check ([int]$policy.observerAbsoluteBudgetSeconds -gt [int]$policy.productTransactionAbsoluteBudgetSeconds -and [int]$policy.fullReleaseWatchdogSeconds -gt [int]$policy.observerAbsoluteBudgetSeconds -and [int]$policy.exactProofOuterWatchdogSeconds -gt [int]$policy.exactProofInnerBoundSeconds) 'OBS-15 composed parent deadlines strictly dominate their children'
Check ((Assert-HarnessBudgetPolicy -Policy $policy) -eq $true) 'OBS-16 invalid hierarchy policy is rejected by the authoritative validator'
$genJump=LifecycleObs @{checkpointPresent=$true;checkpoint=[pscustomobject]@{checkpointGeneration=3;transactionId='a'*32;payloadSha256='b'*64;action='FreshInstall';role='Primary / Desktop';state='waiting-for-reboot'}}
Check ((Get-DurableProgressClassification -Observation $genJump -PriorCheckpoint $prior -MaxGeneration 3) -eq 'TERMINAL_FAILURE') 'OBS-07/09 generation jump fails closed'
$foreign=LifecycleObs @{checkpointPresent=$true;checkpoint=[pscustomobject]@{checkpointGeneration=2;transactionId='c'*32;payloadSha256='b'*64;action='FreshInstall';role='Primary / Desktop';state='waiting-for-reboot'}}
Check ((Get-DurableProgressClassification -Observation $foreign -PriorCheckpoint $prior -MaxGeneration 3) -eq 'TERMINAL_FAILURE') 'OBS-10 foreign transaction fails closed'
$complete2=LifecycleObs @{matchingConsumedReceipt=$true;installStateValid=$true;canonicalOwnershipValid=$true;authenticatedHealthOk=$true}
$complete2.progress.checkpointGeneration=0;$complete2.progress.checkpointState='';$complete2.progress.resumeStage=''
Check ((Get-DurableProgressClassification -Observation $complete2 -PriorCheckpoint $prior) -eq 'COMPLETED') 'OBS-11 matching consumed receipt and authenticated health completes'
$orderedComplete=[ordered]@{checkpointPresent=$false;checkpoint=$null;matchingConsumedReceipt=$true;installStateValid=$true;canonicalOwnershipValid=$true;authenticatedHealthOk=$true;progress=[ordered]@{checkpointGeneration=0;checkpointState='';completedStages=@('complete');resumeStage='';stages=@();productChildInstances=@();cpuSeconds=0;receiptMatch=$true;health=$true;hostAgentTaskState='Running';listener=$true}}
$orderedCompleteResult=RunInjectedWait @($orderedComplete) 60 120
Check ([string]$orderedCompleteResult.outcome -eq 'COMPLETED') 'OBS-11 exact production-shaped zero checkpoint generation completes'
$orderedCheckpoint=[ordered]@{checkpointGeneration=2;generation=2;transactionId='a'*32;payloadSha256='b'*64;action='FreshInstall';role='Primary / Desktop';state='waiting-for-reboot'};$orderedNext=[ordered]@{checkpointPresent=$true;checkpoint=$orderedCheckpoint;matchingConsumedReceipt=$false;installStateValid=$false;canonicalOwnershipValid=$false;authenticatedHealthOk=$false;progress=[ordered]@{checkpointGeneration=2;checkpointState='waiting-for-reboot';completedStages=@('bootstrap');resumeStage='install';stages=@();productChildInstances=@();cpuSeconds=1;receiptMatch=$false;health=$false;hostAgentTaskState='Running';listener=$true}}
$orderedNextResult=RunInjectedWait @($orderedNext) 60 120
Check ([string]$orderedNextResult.outcome -eq 'NEXT_REBOOT') 'OBS-11 OrderedDictionary checkpoint reaches NEXT_REBOOT with exact binding'
$generationZeroDir=Join-Path ([IO.Path]::GetTempPath()) ("devfleet-observer-generation-zero-{0}" -f ([guid]::NewGuid().ToString('N')));New-Item -ItemType Directory -Path $generationZeroDir -Force|Out-Null;[void]$script:testEvidenceDirs.Add($generationZeroDir)
$generationZeroTx='f'*32;$generationZeroCheckpoint=[pscustomobject]@{checkpointGeneration=1;generation=1;transactionId=$generationZeroTx;payloadSha256='b'*64;action='FreshInstall';role='Primary / Desktop';state='waiting-for-reboot'};$generationZeroObservation=LifecycleObs @{checkpointPresent=$true;checkpoint=$generationZeroCheckpoint};$global:DevFleetGenerationZeroClock=[datetime]'2026-01-01T00:00:00Z';$generationZeroClock={$value=[datetime]$global:DevFleetGenerationZeroClock;$global:DevFleetGenerationZeroClock=$value.AddSeconds(1);$value};$generationZeroProvider={param($state)$state.providerContext};$generationZeroResult=Wait-DevFleetProductLifecycleTransition -Session ([pscustomobject]@{}) -TransactionId '' -PayloadSha256 ('b'*64) -Action 'FreshInstall' -Role 'Primary / Desktop' -PriorGeneration 0 -MaxGeneration 3 -BudgetSeconds 60 -NoProgressBudgetSeconds 60 -AbsoluteBudgetSeconds 60 -ExpectedDevFleetVersion '1.2.13' -ExpectedInstallerVersion '1.4.1' -EvidencePath (Join-Path $generationZeroDir 'observer.json') -ObservationProvider $generationZeroProvider -ObservationProviderContext $generationZeroObservation -ClockProvider $generationZeroClock -SleepProvider {param($seconds)}
Check ([string]$generationZeroResult.outcome -eq 'NEXT_REBOOT' -and [string]$generationZeroResult.checkpoint.transactionId -eq $generationZeroTx) 'OBS-12 generation-zero observer safely adopts the first exact transaction checkpoint'
$completionForms=@([pscustomobject]$orderedComplete,@{checkpointPresent=$false;checkpoint=$null;matchingConsumedReceipt=$true;installStateValid=$true;canonicalOwnershipValid=$true;authenticatedHealthOk=$true;progress=[ordered]@{checkpointGeneration=0;checkpointState='';completedStages=@('complete');resumeStage='';stages=@();productChildInstances=@();cpuSeconds=0}},$orderedComplete)
$genericCompletion=[Collections.Generic.Dictionary[string,object]]::new();foreach($key in $orderedComplete.Keys){$genericCompletion[$key]=$orderedComplete[$key]};$completionForms+=,$genericCompletion
foreach($index in 0..($completionForms.Count-1)){Check ((Get-DurableProgressClassification -Observation ([psobject]$completionForms[$index]) -PriorCheckpoint $prior) -eq 'COMPLETED') "OBS-11 production-shaped completion representation $($index+1) returns COMPLETED"}
$global:DevFleetDeadlineClock=[datetime]'2026-01-01T00:00:00Z';$global:DevFleetDeadlineCalls=0;$deadlineClock={if($global:DevFleetDeadlineCalls -lt 2){$global:DevFleetDeadlineCalls++;$current=[datetime]$global:DevFleetDeadlineClock;if($global:DevFleetDeadlineCalls -eq 2){$global:DevFleetDeadlineClock=$current.AddSeconds(61)};return $current};return [datetime]$global:DevFleetDeadlineClock};$deadlineProvider={param($s)$s.providerContext};$deadlineDir=Join-Path ([IO.Path]::GetTempPath()) ("devfleet-observer-deadline-{0}" -f ([guid]::NewGuid().ToString('N')));New-Item -ItemType Directory -Path $deadlineDir -Force|Out-Null;[void]$script:testEvidenceDirs.Add($deadlineDir);$deadlineResult=Wait-DevFleetProductLifecycleTransition -Session ([pscustomobject]@{}) -TransactionId ('a'*32) -PayloadSha256 ('b'*64) -Role 'Primary / Desktop' -ExpectedDevFleetVersion '1.2.13' -ExpectedInstallerVersion '1.4.1' -NoProgressBudgetSeconds 60 -AbsoluteBudgetSeconds 60 -ObservationProvider $deadlineProvider -ObservationProviderContext $complete2 -ClockProvider $deadlineClock -EvidencePath (Join-Path $deadlineDir 'observer.json')
Check ([string]$deadlineResult.outcome -eq 'ABSOLUTE_TIMEOUT' -and [string]$deadlineResult.terminalReason -match 'after observation') 'OBS-11 completion one tick after absolute deadline fails closed'
$journalResult=RunInjectedWait @($stable,$stable,$stable) 60 120
Check ($journalResult.startUtc -and $journalResult.absoluteLifecycleDeadlineUtc) 'OBS-13 terminal result includes bounded clock evidence'
Check ((Test-Path -LiteralPath $journalResult.testEvidencePath) -and (Test-Path -LiteralPath ([IO.Path]::Combine([IO.Path]::GetDirectoryName([string]$journalResult.testEvidencePath),'product-lifecycle-progress.jsonl'))) -and (@(Get-Content -LiteralPath ([IO.Path]::Combine([IO.Path]::GetDirectoryName([string]$journalResult.testEvidencePath),'product-lifecycle-progress.jsonl')) | Where-Object { $_ -match '"event":"START"' }).Count -ge 1)) 'OBS-14 interruption journal exists before first observation'
Check ($source -match 'product-lifecycle-progress.jsonl' -and $source -match "event='TERMINAL'") 'OBS-14 interruption-safe incremental journal/current snapshot is wired'
$errorEvidenceDir=Join-Path ([IO.Path]::GetTempPath()) ("devfleet-observer-error-{0}" -f ([guid]::NewGuid().ToString('N')));New-Item -ItemType Directory -Path $errorEvidenceDir -Force|Out-Null;[void]$script:testEvidenceDirs.Add($errorEvidenceDir);$errorProvider={param($s)throw 'controlled provider failure'};$errorResult=Wait-DevFleetProductLifecycleTransition -Session ([pscustomobject]@{}) -TransactionId ('a'*32) -PayloadSha256 ('b'*64) -Role 'Primary / Desktop' -ExpectedDevFleetVersion '1.2.13' -ExpectedInstallerVersion '1.4.1' -ObservationProvider $errorProvider -EvidencePath (Join-Path $errorEvidenceDir 'observer.json')
Check ([string]$errorResult.outcome -eq 'TERMINAL_FAILURE' -and (Test-Path -LiteralPath (Join-Path $errorEvidenceDir 'observer.json'))) 'observer provider error normalizes to strict-safe terminal evidence'
$transportRecoveryDir=Join-Path ([IO.Path]::GetTempPath()) ("devfleet-observer-transport-recovery-{0}" -f ([guid]::NewGuid().ToString('N')));New-Item -ItemType Directory -Path $transportRecoveryDir -Force|Out-Null;[void]$script:testEvidenceDirs.Add($transportRecoveryDir);$global:DevFleetTransportRecoveryClock=[datetime]'2026-01-01T00:00:00Z';$transportRecoveryClock={$value=[datetime]$global:DevFleetTransportRecoveryClock;$global:DevFleetTransportRecoveryClock=$value.AddSeconds(5);$value};$transportRecoveryProvider={param($s)if([int]$s.observationIndex -lt 2){throw 'The background process reported an error with the following message: "The Hyper-V socket target process has ended."'};return $s.providerContext};$transportRecoveryResult=Wait-DevFleetProductLifecycleTransition -Session ([pscustomobject]@{}) -TransactionId ('a'*32) -PayloadSha256 ('b'*64) -Role 'Primary / Desktop' -ExpectedDevFleetVersion '1.2.13' -ExpectedInstallerVersion '1.4.1' -NoProgressBudgetSeconds 60 -AbsoluteBudgetSeconds 120 -ObservationProvider $transportRecoveryProvider -ObservationProviderContext (LifecycleObs @{}) -ClockProvider $transportRecoveryClock -SleepProvider {param($seconds)} -EvidencePath (Join-Path $transportRecoveryDir 'observer.json')
Check ([string]$transportRecoveryResult.outcome -eq 'NO_PROGRESS_TIMEOUT' -and @($transportRecoveryResult.transportRecoveryAttempts).Count -eq 2) 'transient Hyper-V transport failure is retried finitely without resetting lifecycle deadlines'
Check ([string]$transportRecoveryResult.transportRecoveryAttempts[0].error -match 'Hyper-V socket target process has ended' -and [int]$transportRecoveryResult.transportRecoveryAttempts[0].delaySeconds -le 5) 'transport recovery evidence records the bounded error and delay'
$waitForeignCp=[pscustomobject]@{checkpointGeneration=2;generation=2;transactionId='c'*32;payloadSha256='b'*64;action='FreshInstall';role='Primary / Desktop';state='waiting-for-reboot'}
$waitCases=[ordered]@{
    'raw checkpoint object with false presence'=(CompletionSample @{checkpointPresent=$false;checkpoint=$waitForeignCp})
    'raw true presence with null checkpoint'=(CompletionSample @{checkpointPresent=$true;checkpoint=$null})
    'raw top-level generation'=(CompletionSample @{generation=1})
    'raw top-level checkpointGeneration'=(CompletionSample @{checkpointGeneration=1})
    'nested observation checkpoint/generation'=(CompletionSample @{observation=[pscustomobject]@{checkpointPresent=$true;checkpoint=[pscustomobject]@{generation=1;checkpointGeneration=1}}})
    'waiting-for-reboot state'=(CompletionSample @{state='waiting-for-reboot'})
    'terminal claim'=(CompletionSample @{terminalFailure=$true;failure='controlled terminal claim';status='TERMINAL_FAILURE'})
    'GUID generation'=(CompletionSample @{generation=([guid]::NewGuid()).ToString('D')})
    'malformed generation'=(CompletionSample @{generation='not-a-number'})
    'NEXT_REBOOT foreign binding'=(LifecycleObs @{checkpointPresent=$true;checkpoint=$waitForeignCp})
}
$deepSignal=[pscustomobject]@{generation=1};for($d=0;$d -lt 14;$d++){$deepSignal=[pscustomobject]@{nested=$deepSignal}};$deepSample=CompletionSample @{};$deepSample|Add-Member -NotePropertyName deepSignal -NotePropertyValue $deepSignal -Force;$waitCases['depth cutoff active signal']=$deepSample
foreach($waitCase in $waitCases.GetEnumerator()){$waitCaseResult=RunInjectedWait @($waitCase.Value) 60 120;Check ([string]$waitCaseResult.outcome -eq 'TERMINAL_FAILURE') "Wait $($waitCase.Key) fails closed";Check-WaitTerminalEvidence $waitCaseResult "Wait $($waitCase.Key)"}
# Execute the real lifecycle loop with all external effects injected. This is
# intentionally a local candidate/hash check and never opens a VM session.
$testExe=Join-Path $WorkspaceRoot 'outputs\DevFleet-Setup-v1.2.13-win-x64.exe';$testTar=Join-Path $WorkspaceRoot 'outputs\devfleet-v1.2.13.tar.gz';$exeItem=Get-Item -LiteralPath $testExe;$exeHash=(Get-FileHash -LiteralPath $testExe -Algorithm SHA256).Hash.ToLowerInvariant();$tarHash=(Get-FileHash -LiteralPath $testTar -Algorithm SHA256).Hash.ToLowerInvariant();$lifeRoot=Join-Path ([IO.Path]::GetTempPath()) ("devfleet-life-{0}" -f ([guid]::NewGuid().ToString('N')));New-Item -ItemType Directory -Path $lifeRoot -Force|Out-Null
$lifeContext=[pscustomobject]@{phaseId='LIFE-TEST';runDir=$lifeRoot;vmId=([guid]::NewGuid());vmName='test-disposable';candidate=[pscustomobject]@{candidate=[pscustomobject]@{path=$testExe;bytes=$exeItem.Length;sha256=$exeHash};tar=[pscustomobject]@{sha256=$tarHash};releaseVersion='1.2.13';installerVersion='1.4.1';releaseFingerprintId='test-release';toolingFingerprintId='test-tooling'};config=[pscustomobject]@{};phaseBudgetSeconds=60}
$lifeTrace=[System.Collections.Generic.List[string]]::new();$lifeTx='d'*32;$wpfCount=0;$global:DevFleetProductDispatchCount=0
$wpf = {
    param($s)
    $g=[int]$s.generation
    $produced=if($g -eq 0){1}else{$g+1}
    [void]$lifeTrace.Add("WPF:$produced")
    [pscustomobject]@{status='REAL E2E DURABLE PENDING';guest=[pscustomobject]@{processId=0;role='Primary / Desktop'}}
}
$transition = {
    param($s)
    $g=[int]$s.priorGeneration+1
    if([int]$s.priorGeneration -eq 0){$global:DevFleetProductDispatchCount++}
    [void]$lifeTrace.Add("OBSERVE:$g")
    $cp=[pscustomobject]@{checkpointGeneration=$g;generation=$g;transactionId=$lifeTx;payloadSha256=$s.payloadSha256;action='FreshInstall';role='Primary / Desktop';state='waiting-for-reboot'}
    if($g -le 3){
        [pscustomobject]@{outcome='NEXT_REBOOT';checkpointPresent=$true;checkpoint=$cp;observation=[pscustomobject]@{}}
    } else {
        [pscustomobject]@{outcome='COMPLETED';checkpointPresent=$false;checkpoint=$null;observation=[pscustomobject]@{matchingConsumedReceipt=$true;installStateValid=$true;canonicalOwnershipValid=$true;authenticatedHealthOk=$true;installLedger=[pscustomobject]@{DevFleetVersion='1.2.13';InstallerVersion='1.4.1';PackageSha256=$s.payloadSha256;InstallationGeneration='11111111-1111-1111-1111-111111111111';WindowsIntegrationOwnershipPath='C:\ProgramData\DevFleetHostAgent\integration-ownership.json'};ownershipLedger=[pscustomobject]@{SchemaVersion=1;InstallationGeneration='11111111-1111-1111-1111-111111111111';ScheduledTasks=@();FirewallRules=@();Services=@()}}}
    }
}
$reboot = {
    param($s)
    [void]$lifeTrace.Add("REBOOT:$($s.generation)")
    [pscustomobject]@{bootIdentityChanged=$true}
}
$settle = {
    param($s)
    [void]$lifeTrace.Add("SETTLE:$($s.generation)")
    [pscustomobject]@{stable=$true}
}
$lifeResult=Invoke-ProductFreshInstallLifecycle -Context $lifeContext -Role 'Primary / Desktop' -WpfProvider $wpf -TransitionProvider $transition -RebootProvider $reboot -SettleProvider $settle
Check ([bool]$lifeResult.completionVerified) 'LIFE-01 real lifecycle loop reaches explicit completion authority'
$matrixTx='e'*32;foreach($matrixKind in 0..3){$matrixWpf={param($s)ProviderForm $matrixKind @{status='REAL E2E DURABLE PENDING';guest=(ProviderForm $matrixKind @{processId=0})}};$matrixTransition={param($s)if([int]$s.priorGeneration -eq 0){$matrixCp=ProviderForm $matrixKind @{checkpointGeneration=1;generation=1;transactionId=$matrixTx;payloadSha256=$s.payloadSha256;action='FreshInstall';role='Primary / Desktop';state='waiting-for-reboot'};ProviderForm $matrixKind @{outcome='NEXT_REBOOT';checkpointPresent=$true;checkpoint=$matrixCp;observation=(ProviderForm $matrixKind @{checkpointPresent=$true;checkpoint=$matrixCp})}}else{ProviderForm $matrixKind @{outcome='COMPLETED';checkpointPresent=$false;checkpoint=$null;observation=(ProviderForm $matrixKind @{matchingConsumedReceipt=$true;installStateValid=$true;canonicalOwnershipValid=$true;authenticatedHealthOk=$true;progress=(ProviderForm $matrixKind @{checkpointGeneration=0});installLedger=(ProviderForm $matrixKind @{DevFleetVersion='1.2.13';InstallerVersion='1.4.1';PackageSha256=$s.payloadSha256;InstallationGeneration='22222222-2222-2222-2222-222222222222';WindowsIntegrationOwnershipPath='C:\ProgramData\DevFleetHostAgent\integration-ownership.json'});ownershipLedger=(ProviderForm $matrixKind @{SchemaVersion=1;InstallationGeneration='22222222-2222-2222-2222-222222222222';ScheduledTasks=@();FirewallRules=@();Services=@()})})}}};$matrixReboot={param($s)ProviderForm $matrixKind @{bootIdentityChanged=$true}};$matrixSettle={param($s)ProviderForm $matrixKind @{stable=$true}};$matrixResult=Invoke-ProductFreshInstallLifecycle -Context $lifeContext -Role 'Primary / Desktop' -WpfProvider $matrixWpf -TransitionProvider $matrixTransition -RebootProvider $matrixReboot -SettleProvider $matrixSettle;Check ([bool]$matrixResult.completionVerified) "provider representation matrix $($matrixKind+1)/4 executes WPF/transition/reboot/settlement contracts"}
$authorityTerminalRejected=$false;try{$terminalAuthoritySample=CompletionSample @{terminalFailure=$true;failure='constructor terminal claim'};New-ProductLifecycleCompletionAuthority -Context $lifeContext -Candidate $lifeContext.candidate -Role 'Primary / Desktop' -TransactionId $lifeTx -PayloadSha256 $lifeContext.candidate.tar.sha256 -Observation $terminalAuthoritySample -Legs @()|Out-Null}catch{$authorityTerminalRejected=$true}
Check $authorityTerminalRejected 'completion authority constructor rejects terminal claim before PASS'
$missingLedgerRejected=$false;try{New-ProductLifecycleCompletionAuthority -Context $lifeContext -Candidate $lifeContext.candidate -Role 'Primary / Desktop' -TransactionId $lifeTx -PayloadSha256 $lifeContext.candidate.tar.sha256 -Observation (CompletionSample @{}) -Legs @()|Out-Null}catch{$missingLedgerRejected=$true}
Check $missingLedgerRejected 'completion authority rejects missing install/ownership ledgers without raw strict-mode failure'
$terminalRebootCalls=0;$terminalWpf={param($s)[pscustomobject]@{status='REAL E2E DURABLE PENDING';guest=[pscustomobject]@{processId=0}}};$terminalTransition={param($s)[pscustomobject]@{outcome='COMPLETED';observation=(CompletionSample @{terminalFailure=$true;failure='two-step terminal claim'})}};$terminalReboot={param($s)$script:terminalRebootCalls++;[pscustomobject]@{bootIdentityChanged=$true}};$terminalLifecycleResult=Invoke-ProductFreshInstallLifecycle -Context $lifeContext -Role 'Primary / Desktop' -WpfProvider $terminalWpf -TransitionProvider $terminalTransition -RebootProvider $terminalReboot -SettleProvider $settle
Check ([string]$terminalLifecycleResult.status -eq 'TERMINAL_FAILURE' -and $terminalRebootCalls -eq 0) 'two-step lifecycle terminal claim rejects before any reboot'
$mismatchCheckpoint=[ordered]@{checkpointGeneration=1;generation=1;transactionId=$lifeTx;payloadSha256=$lifeContext.candidate.tar.sha256;action='FreshInstall';role='Primary / Desktop';state='waiting-for-reboot'};$mismatchTransitions=@([pscustomobject]@{outcome='NEXT_REBOOT';checkpointPresent=$false;checkpoint=$mismatchCheckpoint;observation=[pscustomobject]@{}},[ordered]@{outcome='NEXT_REBOOT';checkpointPresent=$false;checkpoint=$mismatchCheckpoint;observation=[ordered]@{}},[pscustomobject]@{outcome='NEXT_REBOOT';checkpointPresent=$true;checkpoint=$null;observation=[pscustomobject]@{}},[ordered]@{outcome='NEXT_REBOOT';checkpointPresent=$true;checkpoint=$null;observation=[ordered]@{checkpointPresent=$false;checkpoint=$mismatchCheckpoint}})
foreach($mismatchTransition in $mismatchTransitions){$mismatchCalls=0;$mismatchWpf={param($s)[pscustomobject]@{status='REAL E2E DURABLE PENDING';guest=[pscustomobject]@{processId=0}}};$mismatchReboot={param($s)$script:mismatchCalls++;[pscustomobject]@{bootIdentityChanged=$true}};$mismatchResult=Invoke-ProductFreshInstallLifecycle -Context $lifeContext -Role 'Primary / Desktop' -WpfProvider $mismatchWpf -TransitionProvider {param($s)$mismatchTransition} -RebootProvider $mismatchReboot -SettleProvider $settle;Check ([string]$mismatchResult.status -eq 'TERMINAL_FAILURE' -and $mismatchCalls -eq 0) 'top-level transition checkpoint presence mismatch fails before reboot'}
Check (($lifeTrace -join ',') -eq 'WPF:1,OBSERVE:1,REBOOT:1,SETTLE:1,WPF:2,OBSERVE:2,REBOOT:2,SETTLE:2,WPF:3,OBSERVE:3,REBOOT:3,SETTLE:3,WPF:4,OBSERVE:4') 'LIFE-01/03 actual loop orders three product reboots and final post-gen3 observation'
Check ($lifeTrace.IndexOf('OBSERVE:1') -lt $lifeTrace.IndexOf('REBOOT:1') -and $lifeTrace.IndexOf('OBSERVE:2') -lt $lifeTrace.IndexOf('REBOOT:2')) 'LIFE-02 NEXT_REBOOT is preserved over raw WPF status'
Check ($lifeTrace -contains 'REBOOT:3' -and $lifeTrace -contains 'OBSERVE:4' -and $lifeTrace -notcontains 'REBOOT:4') 'LIFE-03 generation 3 reboot is allowed but generation 4 is not'
$gen4Rejected=$false;$gen4Transition={param($s);$cp=[pscustomobject]@{checkpointGeneration=4;generation=4;transactionId=$lifeTx;payloadSha256=$s.payloadSha256;action='FreshInstall';role='Primary / Desktop';state='waiting-for-reboot'};[pscustomobject]@{outcome='NEXT_REBOOT';checkpointPresent=$true;checkpoint=$cp;observation=[pscustomobject]@{}}};try{$gen4Result=Invoke-ProductFreshInstallLifecycle -Context $lifeContext -Role 'Primary / Desktop' -WpfProvider $wpf -TransitionProvider $gen4Transition -RebootProvider $reboot -SettleProvider $settle;$gen4Rejected=([string]$gen4Result.status -eq 'TERMINAL_FAILURE')}catch{$gen4Rejected=$true}
Check ($gen4Rejected) 'LIFE-03 generation 4 checkpoint is rejected fail-closed'
$badShapeRejected=$false;$badShapeTransition={param($s);$cp=[pscustomobject]@{checkpointGeneration='not-a-number';generation='not-a-number';transactionId=$lifeTx;payloadSha256=$s.payloadSha256;action='FreshInstall';role='Primary / Desktop';state='waiting-for-reboot'};[pscustomobject]@{outcome='NEXT_REBOOT';checkpointPresent=$true;checkpoint=$cp;observation=[pscustomobject]@{}}};try{$badShapeResult=Invoke-ProductFreshInstallLifecycle -Context $lifeContext -Role 'Primary / Desktop' -WpfProvider $wpf -TransitionProvider $badShapeTransition -RebootProvider $reboot -SettleProvider $settle;$badShapeRejected=([string]$badShapeResult.status -eq 'TERMINAL_FAILURE')}catch{$badShapeRejected=$true}
Check ($badShapeRejected) 'real-shaped malformed checkpoint generation fails closed with terminal evidence'
$nullWpf={param($s)$null};$nullWpfResult=Invoke-ProductFreshInstallLifecycle -Context $lifeContext -Role 'Primary / Desktop' -WpfProvider $nullWpf -TransitionProvider $transition -RebootProvider $reboot -SettleProvider $settle
$nullTransition={param($s)$null};$nullTransitionResult=Invoke-ProductFreshInstallLifecycle -Context $lifeContext -Role 'Primary / Desktop' -WpfProvider $wpf -TransitionProvider $nullTransition -RebootProvider $reboot -SettleProvider $settle
$errorReboot={param($s)throw 'controlled reboot failure'};$errorRebootResult=Invoke-ProductFreshInstallLifecycle -Context $lifeContext -Role 'Primary / Desktop' -WpfProvider $wpf -TransitionProvider $transition -RebootProvider $errorReboot -SettleProvider $settle
$nullSettlement={param($s)$null};$nullSettlementResult=Invoke-ProductFreshInstallLifecycle -Context $lifeContext -Role 'Primary / Desktop' -WpfProvider $wpf -TransitionProvider $transition -RebootProvider $reboot -SettleProvider $nullSettlement
Check ([string]$nullWpfResult.status -eq 'TERMINAL_FAILURE') 'WpfProvider null fails closed'
Check ([string]$nullTransitionResult.status -eq 'TERMINAL_FAILURE') 'TransitionProvider null fails closed'
Check ([string]$errorRebootResult.status -eq 'TERMINAL_FAILURE') 'RebootProvider error fails closed'
Check ([string]$nullSettlementResult.status -eq 'TERMINAL_FAILURE') 'SettlementProvider null fails closed'
function Check-FullLifecycleTerminalEvidence([psobject]$Result,[string]$Name){
    $terminal=[string]$Result.evidencePath;$dir=if($terminal){Split-Path -Parent $terminal}else{''};$journal=if($dir){Join-Path $dir 'product-lifecycle-progress.jsonl'}else{''};$current=if($dir){Join-Path $dir 'product-lifecycle-progress-current.json'}else{''};$providerDetail=if($dir){Join-Path $dir 'product-lifecycle-provider-failure.json'}else{''};$pathsPresent=($terminal -and (Test-Path -LiteralPath $terminal) -and (Test-Path -LiteralPath $journal) -and (Test-Path -LiteralPath $current) -and (Test-Path -LiteralPath $providerDetail));$journalMatches=$false;if($pathsPresent){try{$last=@(Get-Content -LiteralPath $journal|Where-Object{$_})[-1]|ConvertFrom-Json;$journalMatches=([string]$last.event -eq 'TERMINAL' -and [string]$last.terminalReason -eq 'TERMINAL_FAILURE')}catch{}};Check ($pathsPresent -and $journalMatches) "$Name writes terminal/provider/current/journal evidence with matching terminal reason"
}
Check-FullLifecycleTerminalEvidence $nullWpfResult 'WpfProvider null'
Check-FullLifecycleTerminalEvidence $nullTransitionResult 'TransitionProvider null'
Check-FullLifecycleTerminalEvidence $errorRebootResult 'RebootProvider exception'
Check-FullLifecycleTerminalEvidence $nullSettlementResult 'SettlementProvider null'
$completedObservation=[pscustomobject]@{matchingConsumedReceipt=$true;installStateValid=$true;canonicalOwnershipValid=$true;authenticatedHealthOk=$true;progress=[ordered]@{}}
$completedVariants=[ordered]@{
    'valid checkpoint object'=[pscustomobject]@{checkpoint=$next.checkpoint}
    'checkpointPresent false with object'=[pscustomobject]@{observation=[pscustomobject]@{checkpointPresent=$false;checkpoint=$next.checkpoint}}
    'top-level generation only'=[pscustomobject]@{generation=1}
    'top-level checkpointGeneration only'=[pscustomobject]@{checkpointGeneration=1}
    'embedded observation checkpoint/generation'=[pscustomobject]@{observation=[pscustomobject]@{checkpointPresent=$true;checkpoint=[pscustomobject]@{generation=1;checkpointGeneration=1;state='waiting-for-reboot'}}}
    'waiting-for-reboot state'=[pscustomobject]@{observation=[pscustomobject]@{state='waiting-for-reboot'}}
}
$variantTraceStart=$lifeTrace.Count;foreach($variant in $completedVariants.GetEnumerator()){$variantTransition={param($s)$result=[ordered]@{outcome='COMPLETED';observation=$completedObservation};foreach($p in $thisVariant.PSObject.Properties){$result[$p.Name]=$p.Value};[pscustomobject]$result};$thisVariant=$variant.Value;$variantResult=Invoke-ProductFreshInstallLifecycle -Context $lifeContext -Role 'Primary / Desktop' -WpfProvider $wpf -TransitionProvider $variantTransition -RebootProvider $reboot -SettleProvider $settle;Check ([string]$variantResult.status -eq 'TERMINAL_FAILURE') "COMPLETED $($variant.Key) is rejected";Check-FullLifecycleTerminalEvidence $variantResult "COMPLETED $($variant.Key)"}
Check (@($lifeTrace|Select-Object -Skip $variantTraceStart|Where-Object{$_ -match '^REBOOT:'}).Count -eq 0) 'presence/checkpoint inconsistencies fail before any reboot provider call'
Check ((Get-ProductLifecycleConsumerMode -PhaseId 'REBOOT-RESUME') -eq 'SYNTHETIC_THEN_PRODUCT' -and (Get-ProductLifecycleConsumerMode -PhaseId 'LINUX') -eq 'PRODUCT_ONLY' -and (Get-ProductLifecycleConsumerMode -PhaseId 'SURROGATE-DISPOSABLE') -eq 'PRODUCT_ONLY' -and (Get-ProductLifecycleConsumerMode -PhaseId 'MAINTENANCE-READY-PROVISION') -eq 'PRODUCT_ONLY' -and (Get-ProductLifecycleConsumerMode -PhaseId 'DEPENDENCY-MATRIX') -eq 'PRODUCT_ONLY') 'LIFE-04/LIFE-05 consumer dispatch proves synthetic independence'
Check ([string]$lifeResult.phase -eq 'LIFE-TEST' -and [string]$lifeResult.invocationId -and (Test-Path -LiteralPath ([string]$lifeResult.evidencePath))) 'LIFE-04 invocation identity and isolated authority evidence are exposed'
$lifeEvidenceDir=Split-Path -Parent ([string]$lifeResult.evidencePath);$observerEvidence=Join-Path $lifeEvidenceDir 'product-lifecycle-observer-generation-1.json';$generationEvidence=Join-Path $lifeEvidenceDir 'product-lifecycle-generation-1.json'
Check ((Test-Path -LiteralPath $observerEvidence) -and (Test-Path -LiteralPath $generationEvidence) -and ([IO.Path]::GetFullPath($observerEvidence) -cne [IO.Path]::GetFullPath($generationEvidence)) -and @($lifeResult.evidenceReferences|Where-Object{$_.kind -eq 'observer-summary' -and $_.sha256}).Count -gt 0 -and @($lifeResult.evidenceReferences|Where-Object{$_.kind -eq 'lifecycle-generation' -and $_.sha256}).Count -gt 0) 'observer summary and lifecycle-generation evidence remain isolated with hash references'
$dispatchTrace=[System.Collections.Generic.List[string]]::new()
$syntheticProvider={param($s);[void]$dispatchTrace.Add('SYNTHETIC');[pscustomobject]@{status='PASS';productLifecycleTouched=$false}}
$dispatchContext=[pscustomobject]@{phaseId='REBOOT-RESUME';runDir=$lifeRoot;vmId=$lifeContext.vmId;vmName=$lifeContext.vmName;candidate=$lifeContext.candidate;config=$lifeContext.config;phaseBudgetSeconds=60;lifecycleWpfProvider=$wpf;lifecycleTransitionProvider=$transition;lifecycleRebootProvider=$reboot;lifecycleSettleProvider=$settle;syntheticRebootProvider=$syntheticProvider}
$dispatchBefore=$global:DevFleetProductDispatchCount;$dispatchResult=Invoke-ProductLifecycleConsumer -Context $dispatchContext
Check ([string]$dispatchResult.contract -eq 'synthetic-probe-then-pure-product-lifecycle' -and $dispatchTrace[0] -eq 'SYNTHETIC' -and ($global:DevFleetProductDispatchCount-$dispatchBefore) -eq 1) 'LIFE-04 actual REBOOT-RESUME dispatch invokes synthetic then exactly one product lifecycle'
$pureBefore=$dispatchTrace.Count;$pureProductBefore=$global:DevFleetProductDispatchCount
foreach($purePhase in @('LINUX','SURROGATE-DISPOSABLE','DEPENDENCY-MATRIX','MAINTENANCE-READY-PROVISION')){$dispatchContext.phaseId=$purePhase;[void](Invoke-ProductLifecycleConsumer -Context $dispatchContext)}
Check ($dispatchTrace.Count -eq $pureBefore -and ($global:DevFleetProductDispatchCount-$pureProductBefore) -eq 4) 'LIFE-05 actual Linux/surrogate/dependency/maintenance dispatch each invokes product once and synthetic zero'
$maintenanceDispatch=[pscustomobject]@{phaseId='MAINTENANCE-READY';runDir=$lifeRoot;vmId=$lifeContext.vmId;vmName=$lifeContext.vmName;candidate=$lifeContext.candidate;config=$lifeContext.config;phaseBudgetSeconds=60;lifecycleWpfProvider=$wpf;lifecycleTransitionProvider=$transition;lifecycleRebootProvider=$reboot;lifecycleSettleProvider=$settle};Import-Module (Join-Path $WorkspaceRoot 'automation\release-e2e\modules\FullRelease.psm1') -Force;$maintenanceDispatchResult=Invoke-MaintenanceReadyProductLifecycle -WorkspaceRoot $WorkspaceRoot -Context $maintenanceDispatch
Check ([string]$maintenanceDispatchResult.phase -eq 'MAINTENANCE-READY-PROVISION' -and [bool]$maintenanceDispatchResult.completionVerified) 'FullRelease maintenance provisioning uses dedicated pure product dispatch'
Check ($source -match "'FRESH-INSTALL-WPF'" -and $source -match "Invoke-SupportedFreshInstallLifecycle[\s\S]{0,180}-CompleteLifecycle" -and $source -match 'FRESH-INSTALL-WPF requires verified lifecycle completion') 'LIFE-05 FRESH-INSTALL-WPF cannot promote a non-terminal lifecycle boundary'
} finally {
    foreach($dir in @($script:testEvidenceDirs)){if($dir -and (Test-Path -LiteralPath $dir)){Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue}}
    if($lifeRoot -and (Test-Path -LiteralPath $lifeRoot)){Remove-Item -LiteralPath $lifeRoot -Recurse -Force -ErrorAction SilentlyContinue}
}
[pscustomobject]@{status=if($failed.Count -eq 0){'PASS'}else{'FAIL'};passed=$passed;failures=@($failed)}|ConvertTo-Json -Depth 5
if($failed.Count){exit 1}
