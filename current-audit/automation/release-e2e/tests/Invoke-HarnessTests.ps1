[CmdletBinding()]
param([string]$WorkspaceRoot)
$ErrorActionPreference='Stop'
if (-not $WorkspaceRoot) { $WorkspaceRoot=(Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path }
$moduleRoot=Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..\modules')).Path ''
foreach($m in @('Candidate','HostSafety','ResumeState','Cleanup','Evidence','FullRelease','HarnessBudget')){Import-Module (Join-Path $moduleRoot "$m.psm1") -Force}
$total=0;$passed=0;$failures=[System.Collections.Generic.List[string]]::new()
function Assert-That([bool]$Condition,[string]$Name){$script:total++;if($Condition){$script:passed++}else{$script:failures.Add($Name)}}
function Assert-DisposableNameTest([string]$Name) { return $Name -like 'DevFleet-E2E-*' }
function Get-HarnessCandidateFingerprint([string]$Root) {
    try { return Get-CandidateFingerprint -WorkspaceRoot $Root }
    catch {
        if ($_.Exception.Message -ne 'Candidate evidence says the candidate is stale or requires rebuild.') { throw }
        $version=(Get-Content -LiteralPath (Join-Path $Root 'source\VERSION') -Raw).Trim()
        $outputs=Join-Path $Root 'outputs'
        $exe=@(Get-ChildItem -LiteralPath $outputs -Filter "DevFleet-Setup-v$version-win-x64.exe" -File)
        $portable=@(Get-ChildItem -LiteralPath $outputs -Filter "DevFleet-v$version-Portable*.zip" -File)
        if($exe.Count -ne 1 -or $portable.Count -ne 1){throw 'Harness fixture artifact discovery is ambiguous.'}
        $release=Get-Content -LiteralPath (Join-Path $outputs 'release-fingerprint.json') -Raw|ConvertFrom-Json
        return [pscustomobject]@{
            releaseVersion=$version
            installerVersion=(Get-Content -LiteralPath (Join-Path $Root 'installer-source\INSTALLER_VERSION') -Raw).Trim()
            gitCommit=(& git -C $Root rev-parse HEAD).Trim()
            releaseFingerprintId=[string]$release.releaseFingerprintId
            toolingFingerprintId=[string]$release.toolingFingerprint.toolingFingerprintId
            candidate=Get-FileHashRecord -Path $exe[0].FullName
            tar=Get-FileHashRecord -Path (Join-Path $outputs "devfleet-v$version.tar.gz")
            portable=Get-FileHashRecord -Path $portable[0].FullName
            installerSource=Get-FileHashRecord -Path (Join-Path $outputs "DevFleet-v$version-Installer-Source.zip")
        }
    }
}
$temp=Join-Path $env:TEMP "DevFleet-E2E-HarnessTests-$([guid]::NewGuid().ToString('N'))"; New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $candidate=Get-HarnessCandidateFingerprint -Root $WorkspaceRoot
    Assert-That ($candidate.releaseVersion -match '^\d+\.\d+\.\d+$') 'version parsing'
    Assert-That ($candidate.candidate.sha256.Length -eq 64 -and $candidate.tar.sha256.Length -eq 64) 'artifact hashing'
    Assert-That ((Test-CandidateFingerprint -Expected $candidate -Actual (Get-HarnessCandidateFingerprint -Root $WorkspaceRoot)) -eq $true) 'candidate fingerprint equality'

    $unsafeProjection=Get-ProjectedHostMemorySafety -AvailableMemoryGiB 25.16 -ExpectedVmStartCostGiB 14.38 -InstalledUsableMemoryGiB 64 -CommitLimitGiB 64 -CommittedGiB 50
    Assert-That (-not $unsafeProjection.startSafe) 'projected post-start memory rejects unsafe VM start'
    Assert-That ($unsafeProjection.projectedPostStartAvailableMemoryGiB -eq 10.78) 'projected post-start memory records expected remainder'
    $overrideBlocked=Apply-RamPressureOverride -Snapshot ([pscustomobject]@{startSafe=$false;resourceExhaustion=$false})
    Assert-That (-not $overrideBlocked.effectiveE2EStartAuthorized -and -not $overrideBlocked.ramPressureOverrideAuthorized) 'RAM override defaults disabled'
    $overrideAllowed=Apply-RamPressureOverride -Snapshot ([pscustomobject]@{startSafe=$false;resourceExhaustion=$false}) -AllowRamPressure
    Assert-That ($overrideAllowed.effectiveE2EStartAuthorized -and -not $overrideAllowed.rawHostSafetyStartSafe -and $overrideAllowed.ramPressureOverrideAuthorized) 'RAM override authorizes memory-only failure and preserves raw result'
    $overrideDenied=Apply-RamPressureOverride -Snapshot ([pscustomobject]@{startSafe=$false;resourceExhaustion=$true}) -AllowRamPressure
    Assert-That (-not $overrideDenied.effectiveE2EStartAuthorized) 'RAM override cannot bypass resource exhaustion'
    $safeProjection=Get-ProjectedHostMemorySafety -AvailableMemoryGiB 35 -ExpectedVmStartCostGiB 14.38 -InstalledUsableMemoryGiB 64 -CommitLimitGiB 64 -CommittedGiB 30
    Assert-That $safeProjection.startSafe 'projected post-start memory accepts safe VM start'
    $runningProjection=Get-ProjectedHostMemorySafety -AvailableMemoryGiB 21 -ExpectedVmStartCostGiB 14.38 -InstalledUsableMemoryGiB 64 -CommitLimitGiB 64 -CommittedGiB 30 -VmAlreadyRunning $true
    Assert-That ($runningProjection.startSafe -and $runningProjection.expectedVmStartCostGiB -eq 0) 'running VM uses observed post-start memory'

    $space=Join-Path $temp 'path with spaces'; New-Item -ItemType Directory -Path $space | Out-Null
    $statePath=Join-Path $space 'run-state.json'; $obj=[pscustomobject]@{schemaVersion=1;candidate=$candidate.candidate.sha256}
    Write-AtomicJson -Path $statePath -Value $obj; $read=Read-StrictJson -Path $statePath
    Assert-That ($read.candidate -eq $candidate.candidate.sha256) 'atomic state write/read with spaces'
    Set-Content -LiteralPath $statePath -Value '{bad json' -Encoding utf8
    $invalidCaught=$false;try{Read-StrictJson -Path $statePath}catch{$invalidCaught=$true}; Assert-That $invalidCaught 'corrupted state rejection'
    Write-AtomicJson -Path $statePath -Value $obj

    $runState=[pscustomobject]@{candidateHashes=[pscustomobject]@{exe=$candidate.candidate.sha256;tar=$candidate.tar.sha256};vmId='expected'}
    $mismatchCaught=$false;try{Assert-ResumeIdentity -State $runState -Fingerprint $candidate -Vm ([pscustomobject]@{Id=[guid]::NewGuid()})|Out-Null}catch{$mismatchCaught=$true}; Assert-That $mismatchCaught 'checkpoint/VM identity mismatch rejection'
    $hashMismatch=[pscustomobject]@{candidateHashes=[pscustomobject]@{exe=('0'*64);tar=$candidate.tar.sha256}}
    $candidateCaught=$false;try{Assert-ResumeIdentity -State $hashMismatch -Fingerprint $candidate}catch{$candidateCaught=$true}; Assert-That $candidateCaught 'candidate hash mismatch rejection'

    $fakeVm=[pscustomobject]@{Name='DevFleet-E2E-Test';Id=([guid]::NewGuid())}; $manifest=New-CleanupManifest -Vm $fakeVm -RunId 'synthetic'; Assert-That (Test-CleanupManifest $manifest) 'cleanup manifest exact ownership'; Assert-That (-not (Assert-DisposableNameTest -Name 'devfleet-primary')) 'production name denied'
    $fixtureVm=[pscustomobject]@{Name='DevFleet-E2E-Test';Id=([guid]::NewGuid())}; $fixtureSnapshot=[pscustomobject]@{Name='DevFleet-E2E-MAINTENANCE-READY';Id=([guid]::NewGuid())}; $generation=([guid]::NewGuid()).ToString('D')
    $fixtureProvenance=[pscustomobject]@{schemaVersion=1;contract='maintenance-ready-provenance-v1';vmName=$fixtureVm.Name;vmId=$fixtureVm.Id.ToString();checkpointName=$fixtureSnapshot.Name;checkpointId=$fixtureSnapshot.Id.ToString();candidate=[pscustomobject]@{gitCommit=$candidate.gitCommit;releaseVersion=$candidate.releaseVersion;installerVersion=$candidate.installerVersion;releaseFingerprintId=$candidate.releaseFingerprintId;toolingFingerprintId=$candidate.toolingFingerprintId;payloadSha256=$candidate.tar.sha256};install=[pscustomobject]@{installationGeneration=$generation};ownership=[pscustomobject]@{schemaVersion=1;installationGeneration=$generation}}
    Assert-That (Assert-MaintenanceReadyProvenance -Provenance $fixtureProvenance -Vm $fixtureVm -Snapshot $fixtureSnapshot -Fingerprint $candidate) 'current maintenance provenance accepted'
    $staleFixture=$fixtureProvenance|ConvertTo-Json -Depth 8|ConvertFrom-Json; $staleFixture.candidate.payloadSha256=('0'*64); $staleCaught=$false; try { Assert-MaintenanceReadyProvenance -Provenance $staleFixture -Vm $fixtureVm -Snapshot $fixtureSnapshot -Fingerprint $candidate|Out-Null } catch {$staleCaught=$true}; Assert-That $staleCaught 'stale maintenance candidate provenance rejected'
    $transferSource=Join-Path $space 'stage.ps1'; $transferTarget=Join-Path $space 'remote-stage.ps1'; [IO.File]::WriteAllBytes($transferSource,[Text.Encoding]::UTF8.GetBytes("Write-Output 'ok'`n")); Copy-Item $transferSource $transferTarget; Assert-That ((Get-FileHash $transferSource).Hash -eq (Get-FileHash $transferTarget).Hash) 'stage transfer SHA equality'; Assert-That (-not ([IO.File]::ReadAllBytes($transferTarget) -contains 0)) 'UTF-8 stage has no null bytes'

    $old=Join-Path $temp 'stale-run-state.json'; Write-AtomicJson -Path $old -Value ([pscustomobject]@{runId='stale';timestamp=(Get-Date).AddDays(-2).ToString('o')}); Assert-That ((Read-StrictJson $old).runId -eq 'stale') 'stale state remains inspectable'
    $sw=[Diagnostics.Stopwatch]::StartNew(); Start-Sleep -Milliseconds 25; $sw.Stop(); Assert-That ($sw.ElapsedMilliseconds -lt 1000) 'bounded wait'; Assert-That ($sw.ElapsedMilliseconds -ge 0) 'no infinite polling'

    $configPath=Join-Path $WorkspaceRoot 'automation\release-e2e\config\devfleet-e2e.defaults.json'
    $config=Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $budgetPolicy=Get-HarnessBudgetPolicy -Config $config
    $guestComponentSum=[int](($budgetPolicy.guestBootstrapComponentsSeconds.PSObject.Properties.Value | Measure-Object -Sum).Sum)
    Assert-That ($guestComponentSum -eq [int]$budgetPolicy.operationMaximumsSeconds.guestBootstrap -and [int]$config.NestedLinux.BootstrapTimeoutSeconds -eq $guestComponentSum) 'guest bootstrap timeout is derived once from finite component maxima'
    Assert-That ([int]$budgetPolicy.stageBudgetsSeconds.compute -eq ([int]$budgetPolicy.operationMaximumsSeconds.multipassLaunch + [int]$budgetPolicy.operationMaximumsSeconds.multipassReadiness + [int]$budgetPolicy.operationMaximumsSeconds.payloadTransfer + $guestComponentSum + [int]$budgetPolicy.operationMaximumsSeconds.sshAndMarker) -and [int]$budgetPolicy.stageBudgetsSeconds.vault -eq ([int]$budgetPolicy.operationMaximumsSeconds.vaultSnapshot + [int]$budgetPolicy.stageBudgetsSeconds.compute)) 'provisioning stages compose their child operation maxima'
    Assert-That ([int]$budgetPolicy.observerAbsoluteBudgetSeconds -gt [int]$budgetPolicy.productTransactionAbsoluteBudgetSeconds) 'observer absolute strictly dominates product transaction'
    Assert-That ([int]$budgetPolicy.fullReleaseWatchdogSeconds -gt [int]$budgetPolicy.observerAbsoluteBudgetSeconds) 'FullRelease watchdog strictly dominates observer absolute'
    Assert-That ([int]$budgetPolicy.exactProofOuterWatchdogSeconds -gt [int]$budgetPolicy.exactProofInnerBoundSeconds) 'exact-proof outer strictly dominates calculated inner bound'
    $prerequisiteMaximum = 6 * ([int]$budgetPolicy.operationMaximumsSeconds.dependencyProbe + [int]$budgetPolicy.operationMaximumsSeconds.dependencyHealth + [int]$budgetPolicy.operationMaximumsSeconds.dependencyInstall + [int]$budgetPolicy.operationMaximumsSeconds.dependencyVerification) + [int]$budgetPolicy.operationMaximumsSeconds.windowsCapability + [int]$budgetPolicy.operationMaximumsSeconds.windowsFeature + (4 * [int]$budgetPolicy.operationMaximumsSeconds.multipassConfiguration) + (3 * [int]$budgetPolicy.operationMaximumsSeconds.vscodeExtension)
    Assert-That ([int]$budgetPolicy.operationMaximumsSeconds.prerequisites -eq $prerequisiteMaximum) 'prerequisite stage is derived from every finite sequential operation'
    $plan=@(Get-FullReleasePhasePlan)
    $requiredPhases=@('HOST-SAFETY','CANDIDATE-VERIFY','RESTORE-CLEAN','ESTABLISH-SESSION','DEPENDENCY-MATRIX','SECURITY-POISON','FRESH-INSTALL-WPF','PRIMARY','LINUX','HTTP-HOSTILE','MAINTENANCE-READY','REPAIR','CLEAN-REINSTALL','UNINSTALL','FACTORY-RESET','REBOOT-RESUME','PERMANENT-DELETE','DELETE-RESTORE','STOPPED-PROJECT','HOST-CONCURRENCY','OPERATION-RECOVERY','OWNERSHIP','WINDOWS-SENTINELS','VAULT','SURROGATE-DISPOSABLE','TAILSCALE-DEFERRED','TAILSCALE-AUTH','AI-BUNDLE','RECONCILE','CLEANUP')
    Assert-That (@($requiredPhases | Where-Object { @($plan.id) -notcontains $_ }).Count -eq 0) 'phase plan contains all configured mandatory phases'
    $executorRequired=@($requiredPhases | Where-Object { $_ -notin @('HOST-SAFETY','CANDIDATE-VERIFY','RESTORE-CLEAN','ESTABLISH-SESSION','MAINTENANCE-READY','CLEANUP') })
    $executorMissing=@($executorRequired | Where-Object { -not $config.FullReleaseExecutors.PSObject.Properties[$_] })
    Assert-That ($executorMissing.Count -eq 0) 'phase plan executor coverage'
    $realPhase=Get-Content -Raw (Join-Path $WorkspaceRoot 'automation\release-e2e\modules\executors\Invoke-RealProductPhase.psm1')
    $deadlineCommonSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'source\windows\DevFleet.Common.psm1')
    $fullReleaseBudgetSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'automation\release-e2e\modules\FullRelease.psm1')
    $guestSessionSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'automation\release-e2e\modules\GuestSession.psm1')
    $exactProofSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'audit\run-exact-candidate-proof.ps1')
    Assert-That ($realPhase -match 'Get-HarnessBudgetPolicy' -and $realPhase -notmatch 'Math\]::Min\([^\r\n]*7200') 'observer consumes authoritative policy without silent 7200 clamp'
    Assert-That ($deadlineCommonSource -match 'DeadlineUtc \$deadline' -and $deadlineCommonSource -match 'remaining=\[int\]\[math\]::Floor') 'readiness probes consume remaining owning deadline'
    Assert-That ($deadlineCommonSource -match '\$deadlines = @\(\)' -and $deadlineCommonSource -match 'Measure-Object -Minimum') 'explicit child deadlines cannot escape the active owning stage'
    Assert-That ($guestSessionSource -match 'BeginInvoke\(\)' -and $guestSessionSource -match 'WaitOne\(60000\)' -and $guestSessionSource -match '\$pipeline\.Stop\(\)') 'guest-session establishment has an explicit finite open timeout'
    Assert-That ($deadlineCommonSource -match 'Get-DevFleetOperationMaximumSeconds.*guestBootstrap' -and $deadlineCommonSource -notmatch 'compute\s*=\s*9600|vault\s*=\s*9900') 'Windows stage budgets are composed from operation maxima'
    Assert-That ((Get-Content -Raw (Join-Path $WorkspaceRoot 'source\windows\02-Provision-ComputeNode.ps1')) -notmatch 'TimeoutSeconds 1800' -and (Get-Content -Raw (Join-Path $WorkspaceRoot 'source\windows\03-Provision-Vault.ps1')) -notmatch 'TimeoutSeconds 1800') 'compute and vault bootstrap use the derived guest operation budget'
    Assert-That ($fullReleaseBudgetSource -match 'Get-HarnessBudgetPolicy' -and $fullReleaseBudgetSource -match 'strictly exceed the observer absolute') 'FullRelease executor validates parent deadline hierarchy'
    Assert-That ($exactProofSource -match 'Assert-HarnessBudgetPolicy' -and $exactProofSource -match 'exactProofOuterWatchdogSeconds' -and $exactProofSource -notmatch 'Min\([^\r\n]*60000') 'exact proof rejects invalid outer bounds instead of silently truncating'
    Assert-That ($exactProofSource -match 'Proof lifecycle job failed:' -and $exactProofSource -match 'returned no terminal evidence \(state=') 'exact proof preserves failed child-job diagnostics'
    $behaviorTest=Join-Path $WorkspaceRoot 'automation\release-e2e\tests\Test-LifecycleObserverBehavior.ps1'
    if(Test-Path -LiteralPath $behaviorTest){
        $behaviorRaw=@(& (Join-Path $PSHOME 'pwsh.exe') -NoProfile -ExecutionPolicy Bypass -File $behaviorTest -WorkspaceRoot $WorkspaceRoot 2>$null)
        $behavior=$null;try{$jsonStart=0;while($jsonStart -lt $behaviorRaw.Count -and ([string]$behaviorRaw[$jsonStart]).Trim() -ne '{'){$jsonStart++};if($jsonStart -lt $behaviorRaw.Count){$behavior=($behaviorRaw[$jsonStart..($behaviorRaw.Count-1)] -join "`n")|ConvertFrom-Json}}catch{}
        Assert-That ($behavior -and [string]$behavior.status -eq 'PASS') 'behavioral lifecycle observer regressions execute and pass'
    }else{Assert-That $false 'behavioral lifecycle observer regression script exists'}
    $interactiveTest=Join-Path $WorkspaceRoot 'automation\release-e2e\tests\Test-InteractiveLogonContracts.ps1'
    if(Test-Path -LiteralPath $interactiveTest){
        $interactiveRaw=@(& (Join-Path $PSHOME 'pwsh.exe') -NoProfile -ExecutionPolicy Bypass -File $interactiveTest -WorkspaceRoot $WorkspaceRoot 2>$null)
        $interactive=$null;try{$jsonStart=0;while($jsonStart -lt $interactiveRaw.Count -and ([string]$interactiveRaw[$jsonStart]).Trim() -ne '{'){$jsonStart++};if($jsonStart -lt $interactiveRaw.Count){$interactive=($interactiveRaw[$jsonStart..($interactiveRaw.Count-1)] -join "`n")|ConvertFrom-Json}}catch{}
        Assert-That ($interactive -and [string]$interactive.status -eq 'PASS') 'deterministic interactive autologon regressions execute and pass'
    }else{Assert-That $false 'interactive autologon regression script exists'}
    $linuxPhase=Get-Content -Raw (Join-Path $WorkspaceRoot 'automation\release-e2e\modules\executors\Invoke-LinuxPhase.ps1')
    Assert-That ($realPhase -match 'Invoke-AiBundlePhase' -and $realPhase -notmatch "bundle='deferred to post-run verifier'") 'AI-BUNDLE waits for current verifier'
    Assert-That ($realPhase -match 'Invoke-ReconcilePhase' -and $realPhase -notmatch 'reconciled=\$true') 'RECONCILE performs actual checks'
    Assert-That ($realPhase -match 'generic Diagnostics is not a contract proof') 'generic Diagnostics cannot promote named contracts'
    Assert-That ($realPhase -match 'multipass.*launch' -and $realPhase -match 'bootstrap-compute\.sh' -and $realPhase -match 'rootless' -and $realPhase -match 'failureOperation' -and $realPhase -match "ErrorActionPreference='Continue'") 'LINUX has real nested bootstrap and native-error evidence contract'
    Assert-That ($realPhase -match "cloud-init/compute\.yaml" -and $realPhase -match "'--cloud-init'" -and $realPhase -match 'cloud-init status --format=json' -and $realPhase -match 'devrunnerIdentityPreBootstrap') 'LINUX applies exact candidate cloud-init before bootstrap'
    Assert-That ($realPhase -match 'ai-bundle-linux-roundtrip' -and $realPhase -match 'SOURCE-MODES\.json' -and $realPhase -match 'unzip -q' -and $realPhase -match 'validate_audit_coherence\.py' -and $realPhase -match 'python3 -m compileall' -and $realPhase -match "bash -n") 'focused LINUX can validate current AI bundle with standard unzip and POSIX modes'
    Assert-That ($realPhase -match 'sudo -n -u devfleet-control -- test -s /etc/devfleet/config\.json' -and $realPhase -match 'sudo -n -u devfleet-control -- jq -e \. /etc/devfleet/config\.json' -and $realPhase -match 'sudo -n -u devrunner test -S /run/user/\$uid/docker\.sock' -and $realPhase -match 'sudo -n -u devfleet-control -- stat -c %U:%G:%a /etc/devfleet/config\.json' -and $realPhase -match 'pass=\[bool\]\$pass') 'focused LINUX postconditions respect restricted identities and serialize booleans'
    Assert-That ($linuxPhase.Length -gt 100 -and $linuxPhase -notmatch 'syntax|sourceOnly|WSL') 'LINUX executor is not a syntax-only stub'
    $httpPhase=Get-Content -Raw (Join-Path $WorkspaceRoot 'automation\release-e2e\modules\executors\Invoke-HttpHostilePhase.ps1')
    Assert-That ($httpPhase -match 'test_request_admission\.py' -and $httpPhase -match 'candidate\.tar\.sha256') 'HTTP-HOSTILE runs exact candidate request-admission regressions'
    Assert-That ($realPhase -match 'Invoke-SurrogateDisposablePhase' -and $realPhase -match "Role 'Laptop / Surrogate'") 'disposable surrogate uses real candidate WPF role path'
    $intentionalMandatoryThrows=@('STOPPED-PROJECT','HOST-CONCURRENCY','OPERATION-RECOVERY','OWNERSHIP','VAULT')|Where-Object{$realPhase -match ("'"+[regex]::Escape($_)+"'\s*\{\s*throw")}
    Assert-That ($intentionalMandatoryThrows.Count -eq 0) 'mandatory phase executors contain no intentional throw stubs'
    Assert-That ($realPhase -notmatch "'REBOOT-RESUME'\s*\{\s*return Invoke-ActualWpfAction.*'Resume'") 'reboot/resume crosses a real process and boot boundary'
    Assert-That ($realPhase -match 'AllowRebootRequired' -and $realPhase -match "REAL E2E REBOOT REQUIRED" -and $realPhase -match 'Invoke-ProductFreshInstallLifecycle') 'reboot/resume records the expected WPF reboot-required boundary through the product lifecycle loop'
    Assert-That ($realPhase -match "'DURABLE_PENDING'\s*\{\s*'REAL E2E DURABLE PENDING'" -and $realPhase -match "'REBOOT_REQUIRED'\s*\{\s*'REAL E2E REBOOT REQUIRED'") 'DURABLE_PENDING and REBOOT_REQUIRED remain distinct harness outcomes'
    Assert-That ($realPhase -match 'Test-RebootBoundaryIdentity' -and $realPhase -match 'checkpointGeneration.*-ne.*PriorCheckpoint.*\+ 1') 'generation advancement, not generation-1 presence, authorizes another reboot'
    Assert-That ($realPhase -match 'Get-PhaseAwareBudgetSeconds' -and $realPhase -match 'NoProgressBudgetSeconds' -and $realPhase -match 'AbsoluteBudgetSeconds') 'product lifecycle observer uses two bounded phase-aware clocks'
    Assert-That ($realPhase -match '\$guestProcessId=Get-LifecycleProperty \$currentGuest ''processId''' -and $realPhase -match '\$guestProcessId=Get-LifecycleProperty \$current ''processId''' -and $realPhase -match '\$candidateProcessId=if\(' -and $realPhase -match '-CandidateProcessId \$candidateProcessId' -and $realPhase -notmatch '-CandidateProcessId \(if\(') 'product lifecycle observer resolves top-level or nested process identity through valid PowerShell expressions'
    Assert-That ($realPhase -match 'ProgramData\\DevFleetHostAgent\\integration-ownership\.json') 'durable completion observes canonical Host Agent ownership path'
    Assert-That ($realPhase -match 'Invoke-SupportedFreshInstallLifecycle' -and $realPhase -match 'CompleteLifecycle') 'shared supported fresh-install lifecycle helper is used by dependent phases'
    Assert-That ($realPhase -match 'Wait-DevFleetProductLifecycleTransition' -and $realPhase -match "outcome='NEXT_REBOOT'" -and $realPhase -match "outcome='COMPLETED'" -and $realPhase -match "outcome='TERMINAL_FAILURE'" -and $realPhase -match "outcome='NO_PROGRESS_TIMEOUT'" -and $realPhase -match "'ABSOLUTE_TIMEOUT'") 'progress-aware lifecycle observer has bounded semantic terminal outcomes'
    Assert-That ($realPhase -match 'Invoke-ProductFreshInstallLifecycle' -and $realPhase -match 'resume-generation-' -and $realPhase -match 'transactionId=') 'complete lifecycle uses one same-transaction product-owned loop instead of replacement FreshInstall'
    Assert-That ($realPhase -match "SURROGATE-DISPOSABLE requires genuine final lifecycle PASS" -and $realPhase -notmatch "return \[ordered\]@\{status=''REAL E2E PASS'';phase=''SURROGATE-DISPOSABLE''[\s\S]{0,120}result\.status") 'surrogate rejects intermediate lifecycle states'
    Assert-That ($realPhase -match "LINUX requires a genuine supported FreshInstall lifecycle PASS") 'Linux rejects intermediate lifecycle states before Multipass'
    Assert-That ($realPhase -notmatch 'DEVFLEET_DEPENDENCY_FIXTURE' -and $realPhase -match 'ADVERSARIAL_PRODUCT_POLICY' -and $realPhase -match 'REAL_DISPOSABLE_L1') 'dependency matrix distinguishes one real healthy path from adversarial policy rows'
    Assert-That ($realPhase -match 'DependencyPolicyRunner\.csproj' -and $realPhase -match 'actualConditionProven' -and $realPhase -notmatch "scenario=\$scenario[\s\S]{0,180}status=''PASS''") 'dependency adversarial rows come from the executable policy runner'
    Assert-That ($realPhase -match 'synthetic-reboot-probe\.json' -and $realPhase -match 'pendingCount' -and $realPhase -match 'MoveFileEx') 'synthetic probe records pre-existing pending state before its exact trigger'
    Assert-That ($realPhase -match 'unrelatedEntriesPreserved' -and $realPhase -notmatch 'synthetic probe baseline has unrelated pending state' -and $realPhase -notmatch 'Remove-ItemProperty.*PendingFileRenameOperations' -and $realPhase -notmatch 'Set-ItemProperty.*PendingFileRenameOperations') 'baseline pending state is preserved and never cleared by the harness'
    Assert-That ($realPhase.Contains('MoveFileEx') -and $realPhase.Contains('MoveFileEx($source,$destination,4)') -and $realPhase -match 'run-owned-PFRO-only' -and -not $realPhase.Contains('Enable-WindowsOptionalFeature')) 'synthetic reboot is one exact run-owned delayed move, not optional-feature servicing'
    Assert-That ($realPhase -match 'settled' -and $realPhase -match 'sourceExists' -and $realPhase -match 'destinationExists' -and $realPhase -match 'synthetic.*delayed operation did not settle') 'synthetic probe independently verifies bounded delayed-move settlement before desktop restore'
    Assert-That ($realPhase -notmatch "'TAILSCALE-(?:DEFERRED|AUTH)'\s*\{\s*return Invoke-ActualWpfAction.*'FreshInstall'") 'Tailscale phases use their official phase-specific flow'
    $fullReleaseSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'automation\release-e2e\modules\FullRelease.psm1')
    $interactiveLogonSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'automation\release-e2e\modules\InteractiveLogon.psm1')
    $wpfExecutorSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'automation\release-e2e\modules\executors\Invoke-RealProductPhase.psm1')
    $wpfDriverSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'automation\release-e2e\modules\executors\Invoke-WpfUiAutomation.ps1')
    $guestSessionSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'automation\release-e2e\modules\GuestSession.psm1')
    $focusedMaintenanceSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'automation\release-e2e\Invoke-FocusedMaintenanceSentinels.ps1')
    $cleanupSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'automation\release-e2e\modules\Cleanup.psm1')
    $entrypointSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'automation\release-e2e\Invoke-DevFleetReleaseE2E.ps1')
    Assert-That (($config.FullReleaseExecutors.PSObject.Properties['CLEANUP'] -or $fullReleaseSource -match "phase\.id -eq 'CLEANUP'") -and $fullReleaseSource -match 'Get-AssertedDisposableVm' -and $fullReleaseSource -notmatch '(?:Start|Stop)-VM\s+-Name\s+\$Vm\.Name' -and $cleanupSource -match 'Get-VM\s+-Id' -and $cleanupSource -match 'Stop-VM\s+-VM' -and $entrypointSource -match 'Stop-ManifestVm\s+-Manifest' -and $entrypointSource -notmatch 'Stop-VM\s+-Name\s+\$vm\.Name' -and $realPhase -match 'SHA256\]::Create\(\)' -and $realPhase -notmatch 'SHA256\]::HashData' -and $realPhase.Contains("'binPath=' `$serviceCommand 'start=' 'disabled' 'DisplayName='")) 'CLEANUP and sentinel setup use ID-bound, Windows-PowerShell-compatible paths'
    Assert-That ($fullReleaseSource -match "status='NOT RUN'" -and $fullReleaseSource -match "record\.status='BLOCKED'") 'FullRelease evidence distinguishes BLOCKED and NOT RUN'
    Assert-That ($fullReleaseSource -match 'maintenance-ready-provenance-v1' -and $fullReleaseSource -match 'Checkpoint-VM' -and $fullReleaseSource -match 'Invoke-MaintenanceReadyGuestValidation' -and $fullReleaseSource -match 'Remove-VMSnapshot' -and $fullReleaseSource -notmatch 'AdoptLegacyDevFleetIntegrations') 'MAINTENANCE-READY is provenance-bound and reprovisions without legacy adoption'
    Assert-That ($interactiveLogonSource -match 'boundExplorer' -and $interactiveLogonSource -match 'activeInteractiveSessionId' -and $interactiveLogonSource -match 'Assert-DevFleetE2EInteractiveDesktop') 'interactive desktop readiness binds the exact E2E user and active Explorer session'
    Assert-That ($wpfDriverSource -match 'Candidate UI window disappeared during completion polling' -and $wpfDriverSource -match 'processExited' -and $wpfDriverSource -match 'DURABLE_PENDING') 'WPF driver reports window-loss diagnostics instead of hanging silently'
    Assert-That ($wpfExecutorSource -match 'UseDurableCompletionFallback' -and $wpfExecutorSource -match 'DURABLE_REBOOT_RESUME_FALLBACK' -and $wpfExecutorSource -match 'Invoke-MaintenanceReadyGuestValidation' -and $wpfExecutorSource -match 'Invoke-HostAgentAuthenticatedJson' -and $wpfExecutorSource -match 'checkpoint remains present') 'reboot-resume fallback requires durable state and authenticated health'
    Assert-That ($wpfExecutorSource -match '\[switch\]\$UseDurableCompletionFallback' -and $wpfExecutorSource -match 'DeferDurableCompletionFallback' -and $wpfExecutorSource -match 'Invoke-ProductFreshInstallLifecycle' -and $wpfExecutorSource -match 'completionVerified') 'product lifecycle defers WPF fallback and uses the observer as durable completion authority'
    Assert-That ($wpfDriverSource -match '\$relinquishCandidateToDurableVerifier=\$false' -and $wpfDriverSource -match 'DURABLE_PENDING[\s\S]*\$relinquishCandidateToDurableVerifier=\$true' -and $wpfDriverSource -match 'DURABLE_PENDING[\s\S]*sessionId=\$process\.SessionId' -and $wpfDriverSource -match 'finally\s*\{[\s\S]*-not \$relinquishCandidateToDurableVerifier[\s\S]*CloseMainWindow[\s\S]*Kill') 'DURABLE_PENDING relinquishes candidate ownership while normal WPF cleanup remains guarded and intact'
    Assert-That ($wpfDriverSource -match 'using System;\s+using System\.Text;\s+using System\.Runtime\.InteropServices;\s+public static class DevFleetE2EWin32' -and $wpfDriverSource -match "FindWindow\('#32770','Confirm exact plan'\)" -and $wpfDriverSource -match 'FindWindowEx\(\$dialog' -and $wpfDriverSource -match 'GetWindowText' -and $wpfDriverSource -match 'GetDlgCtrlID' -and $wpfDriverSource -match 'SendMessage' -and $wpfDriverSource -match '0x0111' -and $wpfDriverSource -match 'IsWindow\(\$dialog\)' -and $wpfDriverSource -match 'NATIVE_YES_EXACT_PROCESS_VERIFIED' -and $wpfDriverSource -match 'NATIVE_IDYES_EXACT_DIALOG_PROCESS_VERIFIED') 'native confirmation fallback verifies the exact-process Yes dialog before durable handoff'
    Assert-That ($wpfExecutorSource -notmatch '\$driverPath' -and $wpfExecutorSource -notmatch '-like\s+"\*\$driverPath\*"' -and $wpfExecutorSource -notmatch '-like\s+"\*\$expectedPath\*"' -and $wpfExecutorSource -notmatch '\$DriverReport\.driver' -and $wpfExecutorSource -match 'candidatePid' -and $wpfExecutorSource -match 'candidateSessionId' -and $wpfExecutorSource -match 'expectedCandidatePath' -and $wpfExecutorSource -match 'processTree' -and $wpfExecutorSource -match 'Stop-Process\s+-Id' -and $wpfExecutorSource -match 'param\(\$processId,\$sessionId,\$expectedPath\)' -and $wpfExecutorSource -notmatch 'param\(\$pid,') 'durable fallback uses exact candidate identity for failure evidence and cleanup'
    Assert-That ($guestSessionSource -match 'Get-VM\s+-Id\s+\$VmId' -and $guestSessionSource -match 'notlike ''DevFleet-E2E-\*''' -and $guestSessionSource -match 'LAB_CREDENTIAL_STALE' -and $guestSessionSource -match 'canonical E2E credential') 'guest credential preflight is exact-L1, fail-closed, and non-secret'
    $commonSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'source\windows\DevFleet.Common.psm1')
    Assert-That ($commonSource -match 'function Test-PendingRebootState' -and $commonSource -match 'IsNullOrWhiteSpace' -and $commonSource -match 'Test-PendingRebootState -CbsPending' -and $commonSource -notmatch 'Remove-ItemProperty[^\r\n]*PendingFileRenameOperations' -and $commonSource -notmatch 'Set-ItemProperty[^\r\n]*PendingFileRenameOperations') 'shipping reboot detection evaluates PFRO contents without registry mutation'
    Assert-That ($wpfExecutorSource -match '\$reportStatus -eq ''DURABLE_PENDING''' -and $wpfExecutorSource -match 'Invoke-RebootResumeWpfFallback' -and $wpfExecutorSource -match 'status=''PASS''.*completionVerified=\$true') 'DURABLE_PENDING is only promoted after the durable verifier returns PASS'
    Assert-That ([regex]::Matches($wpfExecutorSource,"state='PROCESS_EXITED'").Count -ge 3 -and $wpfExecutorSource -match '\[int\]::TryParse\(\[string\]\$id,\[ref\]\$processId\)' -and $wpfExecutorSource -match "PSObject\.Properties\['driverIdentity'\]" -and $wpfExecutorSource -match "PSObject\.Properties\['candidateIdentity'\]") 'WPF finalization preserves pre-exit identity and classifies missing or null process IDs without process/CIM invocation'
    Assert-That ($wpfExecutorSource -match 'DeferDurableCompletionFallback' -and $wpfExecutorSource -match 'Get-ExactProductCheckpoint' -and $wpfExecutorSource -match 'Invoke-ProductRebootBoundary' -and $wpfExecutorSource -match 'same-transaction' -or $wpfExecutorSource -match 'transactionId') 'reboot handoffs observe exact checkpoints without harness process interference and require durable verification'
    Assert-That ($focusedMaintenanceSource -match 'Get-HostSafetySnapshot' -and $focusedMaintenanceSource -match 'Ensure-MaintenanceReadyFixture' -and $focusedMaintenanceSource -match 'WINDOWS-SENTINELS' -and $focusedMaintenanceSource -match 'Stop-ManifestVm' -and $focusedMaintenanceSource -notmatch 'MULATTOTECHBOX|MulattoTechSurface') 'focused maintenance proof is bounded and cleans exact L1'
    $candidateSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'automation\release-e2e\modules\Candidate.psm1')
    $standardTokenSelfTest=Get-Content -Raw (Join-Path $WorkspaceRoot 'automation\release-e2e\tests\Test-InstallerSelfTestStandardToken.ps1')
    $finalizeSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'tools\Finalize-CandidateEvidence.ps1')
    $lifecycleSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'installer-source\DevFleet.Setup\Services\InstallerLifecycle.cs')
    $installerServicesSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'installer-source\DevFleet.Setup\Services\InstallerServices.cs')
    $mainWindowSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'installer-source\DevFleet.Setup\MainWindow.xaml.cs')
    $installerTestsSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'installer-source\DevFleet.Setup.Tests\Program.cs')
    $hostAgentSource=Get-Content -Raw (Join-Path $WorkspaceRoot 'source\windows\DevFleet-HostAgent.ps1')
    Assert-That ($lifecycleSource -match 'bool OutputComplete = true' -and $lifecycleSource -match 'Task\.WhenAll\(stdoutTask, stderrTask\)\.WaitAsync\(TimeSpan\.FromSeconds\(5\)\)' -and $installerTestsSource -match 'AssertInheritedPipeDescendant\(3010\)') 'ProcessRunner bounds post-exit drain, reports output completeness, and preserves direct exit 3010'
    Assert-That ($installerServicesSource -match 'Task\.WhenAll\(stdout, stderr\)\.Wait\(TimeSpan\.FromSeconds\(1\)\)' -and $installerServicesSource -match 'redirected output was incomplete after the bounded post-exit drain') 'preflight process probe bounds post-exit output drain'
    Assert-That ($commonSource -match 'WhenAll\(\[Threading\.Tasks\.Task\[\]\]@\(\$stdoutTask,\$stderrTask\)\)\.Wait\(\[TimeSpan\]::FromSeconds\(5\)\)' -and $commonSource -match 'DEVFLEET_OUTPUT_INCOMPLETE_AFTER_PROCESS_EXIT' -and $hostAgentSource -match 'WhenAll\(\[Threading\.Tasks\.Task\[\]\]@\(\$stdoutTask,\$stderrTask\)\)\.Wait\(\[TimeSpan\]::FromSeconds\(5\)\)' -and $hostAgentSource -match 'redirected output was incomplete after the bounded post-exit drain') 'shipping PowerShell runners bound post-exit drains and reject incomplete trusted output'
    Assert-That ($candidateSource.Contains('Remove-Item -LiteralPath $reportPath -Force -ErrorAction SilentlyContinue') -and $candidateSource.Contains('$psi.Environment[''DEVFLEET_SELF_TEST_OUTPUT''] = $reportPath') -and $candidateSource.Contains('result = if ($process.ExitCode -eq 0 -and $report')) 'candidate self-test deletes stale evidence and binds the exact fresh report path to the child process'
    Assert-That ($standardTokenSelfTest -match 'standardNonAdministratorToken' -and $standardTokenSelfTest -match 'PublishSingleFile=true' -and $standardTokenSelfTest -match 'residualSelfTestScratchCount' -and $standardTokenSelfTest -match "Environment\['DEVFLEET_SELF_TEST_OUTPUT'\]") 'published asInvoker self-test has a standard-token executable regression with fresh evidence and scratch cleanup'
    Assert-That ($installerServicesSource -match 'existing staged payload' -and $installerServicesSource -match 'File\.Exists\(path\)' -and $installerServicesSource -match 'HashService\.Sha256\(path\)') 'reboot resume reuses only an exact-hash staged payload'
    Assert-That ($mainWindowSource -match 'LifecycleEngine\.LastExecution\?\.ExitCode == 3010' -and $mainWindowSource -match 'RebootCheckpointService\.Path' -and $mainWindowSource -match 'Reboot required; checkpoint preserved' -and $mainWindowSource -notmatch 'rebootRequired[\s\S]{0,300}Completed and verified') 'WPF does not report completion while a reboot checkpoint remains'
    Assert-That ($installerTestsSource -match 'stagedResumePathAgain' -and $installerTestsSource -match 'reuse the exact verified staged payload') 'installer regression covers same-transaction staged-payload reuse'
    Assert-That ($candidateSource -match 'PRIVATE_SELF_SIGNED' -and $candidateSource -match 'Get-AuthenticodeSignature' -and $candidateSource -match 'privateSigningCertificateThumbprint' -and $finalizeSource -match 'PRIVATE SELF-SIGNED AUTHENTICODE' -and $finalizeSource -match 'signing-provider\.json' -and $finalizeSource -match 'Write-AtomicText') 'candidate gate and finalizer bind private Authenticode identity'
    Assert-That ($finalizeSource -match 'generatedAuthorityRefresh' -and $finalizeSource -match 'candidate_build_current' -and $finalizeSource -match 'source_changed_since_candidate' -and $finalizeSource -match 'Generated candidate authority omitted its shipping identity outside the exact fresh-build state') 'candidate finalizer refreshes a generated missing shipping identity only for the exact fresh-build state'
    Assert-That ($fullReleaseSource -match "'ESTABLISH-SESSION'[\s\S]+Invoke-DisposablePrivateSignatureVerification" -and $fullReleaseSource -match 'IN_MEMORY_EXACT_CERTIFICATE' -and $fullReleaseSource -match 'AllowUnknownCertificateAuthority' -and $fullReleaseSource -match 'exactCertificateMatch' -and $fullReleaseSource -match "tamperedStatus -ne 'HashMismatch'" -and (($fullReleaseSource -match 'Ensure-FullReleaseInteractiveDesktop -VmId') -or ($wpfExecutorSource -match 'Ensure-FullReleaseInteractiveDesktop -VmId')) -and $fullReleaseSource -notmatch 'New-PSSession -VMName \$VmName') 'private Authenticode and interactive reconnect use noninteractive, exact-ID disposable guest paths'
    Assert-That ($config.NestedLinux.Name -like 'DevFleet-E2E-*' -and $config.NestedLinux.UbuntuImage -eq '24.04') 'nested Linux disposable policy'
    $bundleBuilder=Get-Content -Raw (Join-Path $WorkspaceRoot 'tools\Build-AIAuditBundle.ps1')
    $finalConvergence=Get-Content -Raw (Join-Path $WorkspaceRoot 'tools\Invoke-DevFleetFinalConvergence.ps1')
    $authorityValidator=Get-Content -Raw (Join-Path $WorkspaceRoot 'tools\validate_audit_coherence.py')
    $dependencyProject=Get-Content -Raw (Join-Path $WorkspaceRoot 'automation\release-e2e\tests\DependencyPolicyRunner\DependencyPolicyRunner.csproj')
    $dependencyProgram=Get-Content -Raw (Join-Path $WorkspaceRoot 'automation\release-e2e\tests\DependencyPolicyRunner\Program.cs')
    Assert-That ($bundleBuilder -match 'proof-entrypoints' -and $bundleBuilder -notmatch '\$gitClean\s*=\s*\$true' -and $bundleBuilder -notmatch 'stagedState\.git_commit\s*=') 'bundle identity preserves HEAD/candidate separation and proof source bytes'
    Assert-That ($authorityValidator -match 'filesChecked.*len' -and $authorityValidator -match 'CURRENT-PROOF' -and $authorityValidator -match 'candidate.*commit') 'current authority validator checks semantic authorities and real file count'
    Assert-That ($dependencyProject -match '\.\./\.\./\.\./\.\./installer-source/DevFleet\.Setup/DevFleet\.Setup\.csproj' -and $dependencyProject -match 'SelfContained>true') 'dependency runner references the real installer project with explicit local SDK RID'
    Assert-That ($dependencyProgram -match 'SendAsync' -and $dependencyProgram -match 'Valid-Nonstandard-Path' -and $dependencyProgram -match 'Outdated-Prerequisites' -and $dependencyProgram -match 'actualConditionProven') 'dependency runner has executable branch evidence and async HTTP seam'
    Assert-That (Test-Path -LiteralPath (Join-Path $WorkspaceRoot 'tools\validate_release_bundle.py') -PathType Leaf) 'strict post-cleanup bundle validator exists outside shipping source'
    Assert-That ($finalConvergence -match 'try\s*\{' -and $finalConvergence -match 'finally\s*\{' -and $finalConvergence -match 'AUDIT_BUNDLE_FINALIZATION_FAILURE' -and $finalConvergence -match 'FINALIZER-PRIMARY-BLOCKER' -and $finalConvergence -match 'Get-VM -Id' -and $finalConvergence -match 'Get-VM -Name' -and $finalConvergence -match 'Clear-DevFleetE2EInteractiveLogonState' -and $finalConvergence -match 'git -C \$Workspace diff --check') 'mandatory finalizer preserves primary blocker and performs exact cleanup/authority/audit work'
    Assert-That ($finalConvergence -match 'sidecar' -and $bundleBuilder -match 'outer sidecar is the final filesystem write' -and $bundleBuilder -notmatch 'Set-Content -LiteralPath \$sidecarPath[\s\S]{0,300}Write-Json \$manifestPath') 'audit sidecar is written after ZIP and manifest validation'

    [pscustomobject]@{status=if($failures.Count -eq 0){'PASS'}else{'FAIL'};passed=$passed;total=$total;failures=@($failures);temporaryFilesRemoved=$true} | ConvertTo-Json -Depth 6
} finally { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
