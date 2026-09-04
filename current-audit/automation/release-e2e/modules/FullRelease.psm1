Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'InteractiveLogon.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'HarnessBudget.psm1') -Force

$script:FullReleasePhases = @(
    [pscustomobject]@{ id='HOST-SAFETY'; label='HOST SAFETY'; checkpoint=$null; destructive=$false },
    [pscustomobject]@{ id='CANDIDATE-VERIFY'; label='CANDIDATE/FINGERPRINT VERIFY'; checkpoint=$null; destructive=$false },
    [pscustomobject]@{ id='RESTORE-CLEAN'; label='RESTORE CLEAN DISPOSABLE BASELINE'; checkpoint='DevFleet-E2E-CLEAN'; destructive=$true },
    [pscustomobject]@{ id='ESTABLISH-SESSION'; label='ESTABLISH INTERACTIVE E2E SESSION'; checkpoint='DevFleet-E2E-CLEAN'; destructive=$false },
    [pscustomobject]@{ id='DEPENDENCY-MATRIX'; label='DEPENDENCY MATRIX 7/7'; checkpoint='DevFleet-E2E-CLEAN'; destructive=$true },
    [pscustomobject]@{ id='SECURITY-POISON'; label='SECURITY-POISON SCENARIOS'; checkpoint='DevFleet-E2E-CLEAN'; destructive=$true },
    [pscustomobject]@{ id='FRESH-INSTALL-WPF'; label='FRESH INSTALL THROUGH REAL WPF'; checkpoint='DevFleet-E2E-CLEAN'; destructive=$true },
    [pscustomobject]@{ id='PRIMARY'; label='PRIMARY ROLE'; checkpoint='DevFleet-E2E-CLEAN'; destructive=$true },
    [pscustomobject]@{ id='LINUX'; label='LINUX GUEST BOOTSTRAP'; checkpoint='DevFleet-E2E-CLEAN'; destructive=$true },
    [pscustomobject]@{ id='HTTP-HOSTILE'; label='EXACT-CANDIDATE HOSTILE HTTP REGRESSION'; checkpoint=$null; destructive=$false },
    [pscustomobject]@{ id='MAINTENANCE-READY'; label='CHECKPOINT MAINTENANCE-READY'; checkpoint='DevFleet-E2E-MAINTENANCE-READY'; destructive=$true },
    [pscustomobject]@{ id='WINDOWS-SENTINELS'; label='WINDOWS FOREIGN SENTINELS'; checkpoint='DevFleet-E2E-MAINTENANCE-READY'; destructive=$true },
    [pscustomobject]@{ id='REPAIR'; label='REPAIR'; checkpoint='DevFleet-E2E-MAINTENANCE-READY'; destructive=$true },
    [pscustomobject]@{ id='CLEAN-REINSTALL'; label='CLEAN REINSTALL'; checkpoint='DevFleet-E2E-MAINTENANCE-READY'; destructive=$true },
    [pscustomobject]@{ id='UNINSTALL'; label='UNINSTALL'; checkpoint='DevFleet-E2E-MAINTENANCE-READY'; destructive=$true },
    [pscustomobject]@{ id='FACTORY-RESET'; label='FACTORY RESET'; checkpoint='DevFleet-E2E-MAINTENANCE-READY'; destructive=$true },
    [pscustomobject]@{ id='REBOOT-RESUME'; label='REBOOT/RESUME'; checkpoint='DevFleet-E2E-MAINTENANCE-READY'; destructive=$true },
    [pscustomobject]@{ id='PERMANENT-DELETE'; label='PERMANENT DELETE'; checkpoint='DevFleet-E2E-MAINTENANCE-READY'; destructive=$true },
    [pscustomobject]@{ id='DELETE-RESTORE'; label='DELETE THEN RESTORE'; checkpoint='DevFleet-E2E-MAINTENANCE-READY'; destructive=$true },
    [pscustomobject]@{ id='STOPPED-PROJECT'; label='STOPPED PROJECT'; checkpoint='DevFleet-E2E-MAINTENANCE-READY'; destructive=$true },
    [pscustomobject]@{ id='HOST-CONCURRENCY'; label='HOST AGENT CONCURRENCY'; checkpoint='DevFleet-E2E-MAINTENANCE-READY'; destructive=$false },
    [pscustomobject]@{ id='OPERATION-RECOVERY'; label='OPERATION RESTART RECOVERY'; checkpoint='DevFleet-E2E-MAINTENANCE-READY'; destructive=$false },
    [pscustomobject]@{ id='OWNERSHIP'; label='OWNERSHIP ISOLATION'; checkpoint='DevFleet-E2E-MAINTENANCE-READY'; destructive=$true },
    [pscustomobject]@{ id='VAULT'; label='VAULT TRANSPORT/FIREWALL'; checkpoint='DevFleet-E2E-MAINTENANCE-READY'; destructive=$true },
    [pscustomobject]@{ id='SURROGATE-DISPOSABLE'; label='DISPOSABLE LAPTOP/SURROGATE VALIDATION'; checkpoint='DevFleet-E2E-CLEAN'; destructive=$true },
    [pscustomobject]@{ id='TAILSCALE-DEFERRED'; label='TAILSCALE DEFERRED'; checkpoint='DevFleet-E2E-MAINTENANCE-READY'; destructive=$false },
    [pscustomobject]@{ id='TAILSCALE-AUTH'; label='TAILSCALE FULL AUTH LAST'; checkpoint='DevFleet-E2E-MAINTENANCE-READY'; destructive=$true },
    [pscustomobject]@{ id='AI-BUNDLE'; label='AI CODEBASE BUNDLE ROUND-TRIP'; checkpoint=$null; destructive=$false },
    [pscustomobject]@{ id='RECONCILE'; label='FINAL RECONCILIATION'; checkpoint=$null; destructive=$false },
    [pscustomobject]@{ id='CLEANUP'; label='CLEANUP'; checkpoint=$null; destructive=$true }
)

function Get-FullReleasePhasePlan { return @($script:FullReleasePhases) }

function Assert-FullReleaseDisposableOwnership {
    param([Parameter(Mandatory)][psobject]$Vm)
    if ($Vm.Name -notlike 'DevFleet-E2E-*') { throw "Ownership check failed for $($Vm.Name)." }
    $true
}

function Get-AssertedDisposableVm {
    param([Parameter(Mandatory)][psobject]$ExpectedVm)
    Assert-FullReleaseDisposableOwnership -Vm $ExpectedVm | Out-Null
    try { $expectedId = [guid][string]$ExpectedVm.Id }
    catch { throw "Disposable VM has an invalid recorded ID: $($ExpectedVm.Id)." }
    $actual = Get-VM -Id $expectedId -ErrorAction Stop
    if ($actual.Id -ne $expectedId -or $actual.Name -cne [string]$ExpectedVm.Name) {
        throw "Disposable VM identity/name mismatch for $($ExpectedVm.Name)/$expectedId."
    }
    return $actual
}

function Get-ExactCheckpoint {
    param([Parameter(Mandatory)][psobject]$Vm,[Parameter(Mandatory)][string]$Name)
    $currentVm = Get-AssertedDisposableVm -ExpectedVm $Vm
    $snapshots = @(Get-VMSnapshot -VM $currentVm -ErrorAction Stop | Where-Object { $_.Name -ceq $Name })
    if ($snapshots.Count -ne 1) { throw "Expected exactly one checkpoint named '$Name' for owned VM '$($Vm.Name)'; found $($snapshots.Count)." }
    return $snapshots[0]
}

function Assert-MaintenanceReadyProvenance {
    param(
        [Parameter(Mandatory)][psobject]$Provenance,
        [Parameter(Mandatory)][psobject]$Vm,
        [Parameter(Mandatory)][psobject]$Snapshot,
        [Parameter(Mandatory)][psobject]$Fingerprint
    )
    if ([int]$Provenance.schemaVersion -ne 1 -or [string]$Provenance.contract -ne 'maintenance-ready-provenance-v1') {
        throw 'MAINTENANCE-READY provenance is missing or unsupported.'
    }
    if ([string]$Provenance.vmName -cne [string]$Vm.Name -or [string]$Provenance.vmId -cne [string]$Vm.Id) {
        throw 'MAINTENANCE-READY provenance is bound to a different disposable VM.'
    }
    if ([string]$Provenance.checkpointName -cne [string]$Snapshot.Name -or [string]$Provenance.checkpointId -cne [string]$Snapshot.Id) {
        throw 'MAINTENANCE-READY provenance is bound to a different checkpoint.'
    }
    $expected = [ordered]@{
        gitCommit=[string]$Fingerprint.gitCommit
        releaseVersion=[string]$Fingerprint.releaseVersion
        installerVersion=[string]$Fingerprint.installerVersion
        releaseFingerprintId=[string]$Fingerprint.releaseFingerprintId
        toolingFingerprintId=[string]$Fingerprint.toolingFingerprintId
        payloadSha256=[string]$Fingerprint.tar.sha256
    }
    foreach ($field in $expected.Keys) {
        if ([string]$Provenance.candidate.$field -cne $expected[$field]) { throw "MAINTENANCE-READY provenance candidate mismatch: $field." }
    }
    if ([int]$Provenance.ownership.schemaVersion -ne 1 -or [string]::IsNullOrWhiteSpace([string]$Provenance.ownership.installationGeneration)) {
        throw 'MAINTENANCE-READY provenance has no current ownership-ledger identity.'
    }
    if ([string]$Provenance.install.installationGeneration -cne [string]$Provenance.ownership.installationGeneration) {
        throw 'MAINTENANCE-READY provenance installation and ownership generations differ.'
    }
    return $true
}

function Invoke-MaintenanceReadyProductLifecycle {
    <# Dedicated maintenance provisioning entrypoint. It intentionally does
       not route through REBOOT-RESUME and has no synthetic PFRO switch. #>
    param([Parameter(Mandatory)][psobject]$Context,[Parameter(Mandatory)][string]$WorkspaceRoot)
    $modulePath=Join-Path $WorkspaceRoot 'automation\release-e2e\modules\executors\Invoke-RealProductPhase.psm1'
    if(-not (Test-Path -LiteralPath $modulePath -PathType Leaf)){throw 'Dedicated maintenance product lifecycle executor is missing.'}
    Import-Module $modulePath -Force
    $Context.phaseId='MAINTENANCE-READY-PROVISION'
    return Invoke-ProductLifecycleConsumer -Context $Context
}

function Invoke-MaintenanceReadyGuestValidation {
    param([Parameter(Mandatory)][guid]$VmId,[Parameter(Mandatory)][psobject]$Fingerprint)
    Import-Module (Join-Path $PSScriptRoot 'Secrets.psm1') -Force
    $credential = Get-DevFleetE2ECredential
    $session = $null
    try {
        $session = New-PSSession -VMId $VmId -Credential $credential -ErrorAction Stop
        return Invoke-Command -Session $session -ScriptBlock {
            param($expectedVersion,$expectedInstaller,$expectedPayload)
            $installPath='C:\ProgramData\M-TechLabs\DevFleet\Installer\install-state.json'
            $ownershipPath='C:\ProgramData\DevFleetHostAgent\integration-ownership.json'
            $ownershipModule='C:\ProgramData\DevFleetHostAgent\DevFleet-WindowsIntegrationOwnership.psm1'
            foreach($path in @($installPath,$ownershipPath,$ownershipModule)) {
                if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw "MAINTENANCE-READY guest prerequisite is missing: $path"}
                if((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw "MAINTENANCE-READY guest prerequisite is a reparse point: $path"}
            }
            $install=Get-Content -LiteralPath $installPath -Raw|ConvertFrom-Json
            if([string]$install.DevFleetVersion -cne $expectedVersion -or [string]$install.InstallerVersion -cne $expectedInstaller -or [string]$install.PackageSha256 -cne $expectedPayload){throw 'MAINTENANCE-READY installed candidate identity is stale or mismatched.'}
            if([string]$install.WindowsIntegrationOwnershipPath -cne $ownershipPath -or [string]::IsNullOrWhiteSpace([string]$install.InstallationGeneration)){throw 'MAINTENANCE-READY install ledger lacks the canonical ownership binding.'}
            Import-Module $ownershipModule -Force
            $ownership=Read-DevFleetIntegrationOwnership -Path $ownershipPath
            if([int]$ownership.SchemaVersion -ne 1 -or [string]$ownership.InstallationGeneration -ne [string]$install.InstallationGeneration){throw 'MAINTENANCE-READY ownership generation/schema is not current.'}
            $bindings=@($ownership.ScheduledTasks)+@($ownership.FirewallRules)+@($ownership.Services)
            if($bindings.Count -lt 1){throw 'MAINTENANCE-READY ownership ledger has no installed integrations.'}
            foreach($binding in @($ownership.ScheduledTasks)) {
                $task=Get-ScheduledTask -TaskName ([string]$binding.Name) -ErrorAction Stop
                if(@($task.Actions).Count -ne 1){throw 'MAINTENANCE-READY scheduled-task ownership is ambiguous.'}
                $actual=@{Name=[string]$task.TaskName;Executable=[string]$task.Actions[0].Execute;Arguments=[string]$task.Actions[0].Arguments;Principal=[string]$task.Principal.UserId;LogonType=[string]$task.Principal.LogonType;RunLevel=[string]$task.Principal.RunLevel;Description=[string]$task.Description;Generation=[string]$binding.Generation}
                Assert-DevFleetTaskBinding -Expected $binding -Actual $actual|Out-Null
            }
            foreach($binding in @($ownership.FirewallRules)) {
                $rules=@(Get-NetFirewallRule -Name ([string]$binding.Name) -ErrorAction Stop)
                if($rules.Count -ne 1){throw 'MAINTENANCE-READY firewall ownership is ambiguous.'}
                $rule=$rules[0];$port=$rule|Get-NetFirewallPortFilter;$address=$rule|Get-NetFirewallAddressFilter;$interface=$rule|Get-NetFirewallInterfaceFilter
                $actual=@{Name=[string]$rule.Name;DisplayName=[string]$rule.DisplayName;Group=[string]$rule.Group;Description=[string]$rule.Description;Direction=[string]$rule.Direction;Action=[string]$rule.Action;Protocol=[string]$port.Protocol;LocalPort=[string]$port.LocalPort;InterfaceAlias=[string]$interface.InterfaceAlias;RemoteAddress=[string]$address.RemoteAddress;Profile=[string]$rule.Profile;Generation=[string]$binding.Generation}
                Assert-DevFleetFirewallBinding -Expected $binding -Actual $actual|Out-Null
            }
            foreach($binding in @($ownership.Services)) {
                $service=Get-CimInstance Win32_Service -Filter "Name='$([string]$binding.Name)'" -ErrorAction Stop
                if(-not $service){throw "MAINTENANCE-READY owned service is missing: $([string]$binding.Name)"}
                $actual=@{Name=[string]$service.Name;ImagePath=[string]$service.PathName;Account=[string]$service.StartName;StartMode=[string]$service.StartMode;Generation=[string]$binding.Generation}
                Assert-DevFleetServiceBinding -Expected $binding -Actual $actual|Out-Null
            }
            # Re-prove authenticated Host Agent health at the maintenance
            # boundary.  The token is read and used only inside the guest and
            # is never returned in evidence.
            $protocol='C:\ProgramData\DevFleetHostAgent\DevFleet-HostAgentProtocol.psm1';$tokenPath='C:\ProgramData\DevFleetHostAgent\token.txt'
            if(-not(Test-Path -LiteralPath $protocol -PathType Leaf)-or-not(Test-Path -LiteralPath $tokenPath -PathType Leaf)){throw 'MAINTENANCE-READY authenticated Host Agent health prerequisites are missing.'}
            Import-Module $protocol -Force;$token=(Get-Content -LiteralPath $tokenPath -Raw).Trim();if(-not $token){throw 'MAINTENANCE-READY Host Agent token is empty.'}
            $health=Invoke-HostAgentAuthenticatedJson -Uri 'http://127.0.0.1:8790/healthz' -Method GET -Key $token -ExpectedHost $env:COMPUTERNAME
            if(-not [bool]$health.ok){throw 'MAINTENANCE-READY authenticated Host Agent health returned ok=false.'}
            [ordered]@{
                status='PASS';computer=$env:COMPUTERNAME;installLedgerPath=$installPath;ownershipLedgerPath=$ownershipPath
                installLedgerSha256=(Get-FileHash -LiteralPath $installPath -Algorithm SHA256).Hash.ToLowerInvariant()
                ownershipLedgerSha256=(Get-FileHash -LiteralPath $ownershipPath -Algorithm SHA256).Hash.ToLowerInvariant()
                devFleetVersion=[string]$install.DevFleetVersion;installerVersion=[string]$install.InstallerVersion;packageSha256=[string]$install.PackageSha256
                installationGeneration=[string]$install.InstallationGeneration;ownershipSchemaVersion=[int]$ownership.SchemaVersion;bindingCount=$bindings.Count
                hostAgentHealth=[ordered]@{authenticated=$true;ok=$true;hostName=[string]$health.host_name;hostId=[string]$health.host_id}
            }
        } -ArgumentList ([string]$Fingerprint.releaseVersion),([string]$Fingerprint.installerVersion),([string]$Fingerprint.tar.sha256)
    } finally { if($session){Remove-PSSession $session -ErrorAction SilentlyContinue} }
}

function Ensure-MaintenanceReadyFixture {
    param(
        [Parameter(Mandatory)][psobject]$Vm,[Parameter(Mandatory)][psobject]$Fingerprint,
        [Parameter(Mandatory)][psobject]$Config,[Parameter(Mandatory)][string]$WorkspaceRoot,
        [Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$RunDir
    )
    $provenancePath=Join-Path $WorkspaceRoot 'audit\automation-harness\maintenance-ready-provenance.json'
    $currentVm=Get-AssertedDisposableVm -ExpectedVm $Vm
    $snapshots=@(Get-VMSnapshot -VM $currentVm -ErrorAction Stop|Where-Object{$_.Name -ceq 'DevFleet-E2E-MAINTENANCE-READY'})
    if($snapshots.Count -gt 1){throw 'MAINTENANCE-READY checkpoint identity is ambiguous; refusing adoption or cleanup.'}
    $snapshot=if($snapshots.Count -eq 1){$snapshots[0]}else{$null}
    $provenance=$null;$staleReason='missing provenance sidecar'
    if(Test-Path -LiteralPath $provenancePath -PathType Leaf){
        try{$provenance=Get-Content -LiteralPath $provenancePath -Raw|ConvertFrom-Json -ErrorAction Stop;if($snapshot){Assert-MaintenanceReadyProvenance -Provenance $provenance -Vm $currentVm -Snapshot $snapshot -Fingerprint $Fingerprint|Out-Null;$staleReason='guest validation required'}}catch{$staleReason=$_.Exception.Message;$provenance=$null}
    }
    if($provenance -and $snapshot){
        $restored=Restore-ExactCheckpoint -Vm $Vm -Name 'DevFleet-E2E-MAINTENANCE-READY' -StartAfterRestore
        $guest=Invoke-MaintenanceReadyGuestValidation -VmId ([guid][string]$Vm.Id) -Fingerprint $Fingerprint
        if([string]$guest.status -ne 'PASS' -or [string]$guest.installationGeneration -ne [string]$provenance.install.installationGeneration){throw 'MAINTENANCE-READY guest provenance did not match the current sidecar.'}
        return [ordered]@{status='PASS';reprovisioned=$false;checkpoint=$restored;guest=$guest;provenancePath=$provenancePath}
    }
    $oldSnapshot=$snapshot
    Restore-ExactCheckpoint -Vm $Vm -Name 'DevFleet-E2E-CLEAN' -StartAfterRestore|Out-Null
    # Reprovision through the pure product lifecycle. MAINTENANCE-READY must
    # not rerun the unrelated synthetic PFRO probe; the fixture layer only
    # validates the resulting durable installation ledger.
    $maintenanceContext=[ordered]@{runId=$RunId;phaseId='MAINTENANCE-READY-PROVISION';label='MAINTENANCE-READY PROVISION';checkpoint='DevFleet-E2E-CLEAN';destructive=$true;candidate=$Fingerprint;vmName=$Vm.Name;vmId=$Vm.Id.ToString();runDir=$RunDir;config=$Config}
    $resumeEvidence=Invoke-MaintenanceReadyProductLifecycle -WorkspaceRoot $WorkspaceRoot -Context ([pscustomobject]$maintenanceContext)
    if([string]$resumeEvidence.status -notin @('PASS','REAL E2E PASS')){throw 'MAINTENANCE-READY supported reboot/resume install did not pass.'}
    $freshEvidence=if($resumeEvidence.product -and @($resumeEvidence.product.legs).Count -gt 0){$resumeEvidence.product.legs[0]}else{$resumeEvidence}
    $rebootFeature=if($resumeEvidence.synthetic){$resumeEvidence.synthetic}else{'PURE_PRODUCT_LIFECYCLE'}
    $guest=Invoke-MaintenanceReadyGuestValidation -VmId ([guid][string]$Vm.Id) -Fingerprint $Fingerprint
    if([string]$guest.status -ne 'PASS'){throw 'MAINTENANCE-READY guest validation did not pass.'}
    $currentVm=Get-AssertedDisposableVm -ExpectedVm $Vm
    if($currentVm.State -ne 'Off'){Stop-VM -VM $currentVm -Force -Confirm:$false -ErrorAction Stop}
    $deadline=(Get-Date).AddMinutes(2);do{Start-Sleep -Seconds 2;$currentVm=Get-AssertedDisposableVm -ExpectedVm $Vm}while($currentVm.State -ne 'Off' -and (Get-Date)-lt $deadline)
    if($currentVm.State -ne 'Off'){throw 'MAINTENANCE-READY reprovision could not reach a safe Off state.'}
    if($oldSnapshot){Remove-VMSnapshot -VMSnapshot $oldSnapshot -Confirm:$false -ErrorAction Stop}
    Checkpoint-VM -VM $currentVm -SnapshotName 'DevFleet-E2E-MAINTENANCE-READY' -ErrorAction Stop|Out-Null
    $newSnapshot=@(Get-VMSnapshot -VM (Get-AssertedDisposableVm -ExpectedVm $Vm)|Where-Object{$_.Name -ceq 'DevFleet-E2E-MAINTENANCE-READY'})
    if($newSnapshot.Count -ne 1){throw 'MAINTENANCE-READY reprovision did not create exactly one current checkpoint.'}
    $snapshot=$newSnapshot[0]
    $provenance=[ordered]@{schemaVersion=1;contract='maintenance-ready-provenance-v1';createdUtc=(Get-Date).ToUniversalTime().ToString('o');sourceRunId=$RunId;vmName=$Vm.Name;vmId=$Vm.Id.ToString();checkpointName=$snapshot.Name;checkpointId=$snapshot.Id.ToString();candidate=[ordered]@{gitCommit=$Fingerprint.gitCommit;releaseVersion=$Fingerprint.releaseVersion;installerVersion=$Fingerprint.installerVersion;releaseFingerprintId=$Fingerprint.releaseFingerprintId;toolingFingerprintId=$Fingerprint.toolingFingerprintId;payloadSha256=$Fingerprint.tar.sha256};install=[ordered]@{installationGeneration=$guest.installationGeneration;devFleetVersion=$guest.devFleetVersion;installerVersion=$guest.installerVersion;packageSha256=$guest.packageSha256;ledgerSha256=$guest.installLedgerSha256};ownership=[ordered]@{schemaVersion=$guest.ownershipSchemaVersion;installationGeneration=$guest.installationGeneration;ledgerSha256=$guest.ownershipLedgerSha256;bindingCount=$guest.bindingCount}}
    [IO.File]::WriteAllText($provenancePath,(($provenance|ConvertTo-Json -Depth 16)+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))
    $restored=Restore-ExactCheckpoint -Vm $Vm -Name 'DevFleet-E2E-MAINTENANCE-READY' -StartAfterRestore
    Assert-MaintenanceReadyProvenance -Provenance $provenance -Vm (Get-AssertedDisposableVm -ExpectedVm $Vm) -Snapshot (Get-ExactCheckpoint -Vm $Vm -Name 'DevFleet-E2E-MAINTENANCE-READY') -Fingerprint $Fingerprint|Out-Null
    $postRestoreGuest=Invoke-MaintenanceReadyGuestValidation -VmId ([guid][string]$Vm.Id) -Fingerprint $Fingerprint
    if([string]$postRestoreGuest.installationGeneration -ne [string]$guest.installationGeneration){throw 'MAINTENANCE-READY restored checkpoint changed installation ownership identity.'}
    return [ordered]@{status='PASS';reprovisioned=$true;staleReason=$staleReason;rebootFeature=$rebootFeature;checkpoint=$restored;guest=$postRestoreGuest;provenancePath=$provenancePath;freshInstall=$freshEvidence;resumeInstall=$resumeEvidence}
}

function Restore-MaintenanceReadyCheckpoint {
    param([Parameter(Mandatory)][psobject]$Vm,[Parameter(Mandatory)][psobject]$Fingerprint,[Parameter(Mandatory)][string]$WorkspaceRoot)
    $provenancePath=Join-Path $WorkspaceRoot 'audit\automation-harness\maintenance-ready-provenance.json'
    if(-not(Test-Path -LiteralPath $provenancePath -PathType Leaf)){throw 'MAINTENANCE-READY provenance sidecar is missing; fixture must be reprovisioned.'}
    $currentVm=Get-AssertedDisposableVm -ExpectedVm $Vm
    $snapshot=Get-ExactCheckpoint -Vm $Vm -Name 'DevFleet-E2E-MAINTENANCE-READY'
    $provenance=Get-Content -LiteralPath $provenancePath -Raw|ConvertFrom-Json -ErrorAction Stop
    Assert-MaintenanceReadyProvenance -Provenance $provenance -Vm $currentVm -Snapshot $snapshot -Fingerprint $Fingerprint|Out-Null
    $restored=Restore-ExactCheckpoint -Vm $Vm -Name 'DevFleet-E2E-MAINTENANCE-READY' -StartAfterRestore
    $guest=Invoke-MaintenanceReadyGuestValidation -VmId ([guid][string]$Vm.Id) -Fingerprint $Fingerprint
    if([string]$guest.installationGeneration -cne [string]$provenance.install.installationGeneration){throw 'MAINTENANCE-READY restored guest ownership identity differs from the sidecar.'}
    return [ordered]@{checkpoint=$restored;provenancePath=$provenancePath;guest=$guest}
}

function Ensure-FullReleaseInteractiveDesktop {
    param([Parameter(Mandatory)][guid]$VmId)
    try {
        $existing=Assert-DevFleetE2EInteractiveDesktopAfterDisarm -VmId $VmId
        return [pscustomobject]@{status='PASS';contract='devfleet-disposable-l1-interactive-logon-v1';mode='already-active';desktop=$existing.desktop;survivesDisarm=$existing}
    } catch {
        # A checkpoint restore may have booted without an interactive shell.
        # Only that bounded negative probe authorizes the one-shot arm below.
    }
    $arm=$null;$disarm=$null
    try {
        $arm=Arm-DevFleetE2EInteractiveLogon -VmId $VmId
        Restart-DevFleetE2EL1 -ArmState $arm | Out-Null
        $desktop=Wait-DevFleetE2EInteractiveDesktop -VmId $VmId -TimeoutSeconds 300
        $disarm=Disarm-DevFleetE2EInteractiveLogon -ArmState $arm
        $survival=Assert-DevFleetE2EInteractiveDesktopAfterDisarm -VmId $VmId
        [pscustomobject]@{status='PASS';contract='devfleet-disposable-l1-interactive-logon-v1';arm=$arm;desktop=$desktop;disarm=$disarm;survivesDisarm=$survival}
    } finally {
        if($arm -and -not $disarm){try{Disarm-DevFleetE2EInteractiveLogon -ArmState $arm|Out-Null}catch{}}
    }
}
function Restore-ExactCheckpoint {
    param([Parameter(Mandatory)][psobject]$Vm,[Parameter(Mandatory)][string]$Name,[switch]$StartAfterRestore)
    Assert-FullReleaseDisposableOwnership -Vm $Vm | Out-Null
    $currentVm=Get-AssertedDisposableVm -ExpectedVm $Vm
    if ($currentVm.State -ne 'Off') {
        Stop-VM -VM $currentVm -Force -Confirm:$false -ErrorAction Stop
        $deadline=(Get-Date).AddMinutes(2)
        do { Start-Sleep -Seconds 2; $current=(Get-AssertedDisposableVm -ExpectedVm $Vm).State.ToString() } while ($current -ne 'Off' -and (Get-Date) -lt $deadline)
        if ($current -ne 'Off') { throw "Disposable VM '$($Vm.Name)' did not reach Off before checkpoint restore." }
    }
    $snapshot = Get-ExactCheckpoint -Vm $Vm -Name $Name
    Restore-VMSnapshot -VMSnapshot $snapshot -Confirm:$false -ErrorAction Stop
    $afterVm = Get-AssertedDisposableVm -ExpectedVm $Vm
    $after = Get-VMSnapshot -VM $afterVm -ErrorAction Stop | Where-Object { $_.Id -eq $snapshot.Id }
    if (-not $after) { throw "Checkpoint restore did not preserve exact snapshot identity $($snapshot.Id)." }
    # Hyper-V can materialize a restored checkpoint as Saved before it settles.
    # Memory topology cannot be changed in that state; transition only the owned
    # disposable VM to Off and verify the transition before any correction.
    $settleDeadline = (Get-Date).AddMinutes(2)
    $stableOffPolls = 0
    do {
        $settled = Get-AssertedDisposableVm -ExpectedVm $Vm
        if ($settled.State -eq 'Saved') {
            Stop-VM -VM $settled -Force -Confirm:$false -ErrorAction Stop
            $stableOffPolls = 0
        } elseif ($settled.State -eq 'Off') {
            # A restored checkpoint can report Off briefly before becoming Saved;
            # require a stable observation window before changing its topology.
            $stableOffPolls++
            if ($stableOffPolls -ge 6) { break }
        } else {
            $stableOffPolls = 0
        }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $settleDeadline)
    $settled = Get-AssertedDisposableVm -ExpectedVm $Vm
    if ($settled.State -ne 'Off') { throw "Disposable VM '$($Vm.Name)' did not settle Off after exact checkpoint restore; observed state $($settled.State)." }
    $topology=Get-AssertedDisposableVm -ExpectedVm $Vm
    if ([int64]$topology.MemoryStartup -ne 16GB -or [bool]$topology.DynamicMemoryEnabled) {
        # The owned L1 is contractually fixed at 16 GiB with Dynamic Memory
        # disabled. Snapshots may carry older VM configuration; correct only
        # this exact disposable target and verify before starting it.
        $topologyError=$null
        for($attempt=1;$attempt -le 6;$attempt++) {
            try {
                $topology=Get-AssertedDisposableVm -ExpectedVm $Vm
                if ([bool]$topology.DynamicMemoryEnabled) { Set-VMMemory -VM $topology -DynamicMemoryEnabled $false -Confirm:$false -ErrorAction Stop }
                $topology=Get-AssertedDisposableVm -ExpectedVm $Vm
                if ([int64]$topology.MemoryStartup -ne 16GB) { Set-VMMemory -VM $topology -StartupBytes 16GB -Confirm:$false -ErrorAction Stop }
                $topology=Get-AssertedDisposableVm -ExpectedVm $Vm
                $topologyError=$null;break
            } catch { $topologyError=$_.Exception; if($attempt -lt 6){Start-Sleep -Seconds $attempt} }
        }
        if($topologyError){throw $topologyError}
    }
    if ([int64]$topology.MemoryStartup -ne 16GB -or [bool]$topology.DynamicMemoryEnabled) { throw "Disposable VM topology is not the required fixed 16 GiB / Dynamic Memory OFF contract." }
    if ($StartAfterRestore) {
        $topology=Get-AssertedDisposableVm -ExpectedVm $Vm
        Start-VM -VM $topology -ErrorAction Stop | Out-Null
        $deadline=(Get-Date).AddMinutes(2)
        do { Start-Sleep -Seconds 2; $current=(Get-AssertedDisposableVm -ExpectedVm $Vm).State.ToString() } while ($current -ne 'Running' -and (Get-Date) -lt $deadline)
        if ($current -ne 'Running') { throw "Disposable VM '$($Vm.Name)' did not reach Running after exact checkpoint restore." }
        $heartbeatDeadline = (Get-Date).AddMinutes(3)
        $heartbeat = $null
        do {
            $heartbeatVm = Get-AssertedDisposableVm -ExpectedVm $Vm
            $heartbeat = Get-VMIntegrationService -VM $heartbeatVm -Name 'Heartbeat' -ErrorAction Stop
            if ($heartbeat.PrimaryStatusDescription -eq 'OK') { break }
            Start-Sleep -Seconds 5
        } while ((Get-Date) -lt $heartbeatDeadline)
        if ($heartbeat.PrimaryStatusDescription -ne 'OK') { throw "Disposable VM '$($Vm.Name)' did not report Hyper-V Heartbeat OK before guest-session use." }
        Start-Sleep -Seconds 5
        # Product lifecycle callers establish and authenticate the interactive
        # desktop inside their bounded worker before invoking WPF. Keep restore
        # itself free of a duplicate guest reboot/session transition so a
        # remoting teardown cannot terminate the proof coordinator.
    }
    [pscustomobject]@{ name=$snapshot.Name; id=$snapshot.Id.ToString(); restored=$true; started=[bool]$StartAfterRestore; vmName=$Vm.Name; memoryStartupBytes=[int64]$topology.MemoryStartup; dynamicMemory=[bool]$topology.DynamicMemoryEnabled }
}

function Get-ExecutorPath {
    param([Parameter(Mandatory)][psobject]$Config,[Parameter(Mandatory)][string]$PhaseId,[Parameter(Mandatory)][string]$WorkspaceRoot)
    if (-not $Config.PSObject.Properties['FullReleaseExecutors']) { return $null }
    $entry = $Config.FullReleaseExecutors.PSObject.Properties[$PhaseId]
    if (-not $entry -or [string]::IsNullOrWhiteSpace([string]$entry.Value)) { return $null }
    $candidate = [IO.Path]::GetFullPath((Join-Path $WorkspaceRoot ([string]$entry.Value)))
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw "Configured FullRelease executor is missing for ${PhaseId}: $candidate" }
    return $candidate
}

function Invoke-ConfiguredExecutor {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][psobject]$Context)
    $extension = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($extension -notin @('.ps1','.psm1')) { throw "FullRelease executor must be a PowerShell script: $Path" }
    $shell = Get-Command pwsh.exe -ErrorAction SilentlyContinue
    if (-not $shell) { $shell = Get-Command powershell.exe -ErrorAction SilentlyContinue }
    if (-not $shell) { throw 'No supported PowerShell executable is available for FullRelease executor dispatch.' }
    $contextJson = $Context | ConvertTo-Json -Depth 32 -Compress
    $policy=Get-HarnessBudgetPolicy -Config $Context.config
    $watchdogSeconds=[int]$policy.fullReleaseWatchdogSeconds
    if($watchdogSeconds -le [int]$policy.observerAbsoluteBudgetSeconds){throw 'FullRelease executor watchdog must strictly exceed the observer absolute deadline.'}
    $psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName=$shell.Source;$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
    foreach($arg in @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$Path)){$psi.ArgumentList.Add([string]$arg)}
    $psi.Environment['DEVFLEET_FULLRELEASE_CONTEXT_JSON']=$contextJson
    $child=[Diagnostics.Process]::new();$child.StartInfo=$psi
    if(-not $child.Start()){throw "Could not start FullRelease executor for $($Context.phaseId)."}
    $stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync()
    $completed=$child.WaitForExit($watchdogSeconds*1000)
    $drained=$false
    try{$drained=[Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]]@($stdout,$stderr)).Wait([TimeSpan]::FromSeconds(5))}catch{$drained=$false}
    $stdoutText=if($stdout.Status -eq [Threading.Tasks.TaskStatus]::RanToCompletion){$stdout.GetAwaiter().GetResult()}else{''}
    $stderrText=if($stderr.Status -eq [Threading.Tasks.TaskStatus]::RanToCompletion){$stderr.GetAwaiter().GetResult()}else{''}
    if(-not $completed){try{$child.Kill($true)}catch{};try{[void]([Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]]@($stdout,$stderr)).Wait([TimeSpan]::FromSeconds(5)))}catch{};$stdoutText=if($stdout.Status -eq [Threading.Tasks.TaskStatus]::RanToCompletion){$stdout.GetAwaiter().GetResult()}else{$stdoutText};$stderrText=if($stderr.Status -eq [Threading.Tasks.TaskStatus]::RanToCompletion){$stderr.GetAwaiter().GetResult()}else{$stderrText};$rawOutput="HARNESS_WATCHDOG_EXPIRED`n$stdoutText`n$stderrText"; $rawPath=Join-Path ([string]$Context.runDir) "$($Context.phaseId)-executor-output.txt"; $rawOutput|Set-Content -LiteralPath $rawPath -Encoding UTF8; $child.Dispose(); throw "HARNESS_WATCHDOG_EXPIRED for $($Context.phaseId) after ${watchdogSeconds}s; evidence=$rawPath"}
    $exitCode=$child.ExitCode;$output=@($stdoutText -split "`r?`n")+@($stderrText -split "`r?`n");$child.Dispose()
    $rawOutput = ($output -join "`n")
    $rawPath = Join-Path ([string]$Context.runDir) "$($Context.phaseId)-executor-output.txt"
    $rawOutput | Set-Content -LiteralPath $rawPath -Encoding UTF8
    if ($exitCode -ne 0) { throw "FullRelease executor failed for $($Context.phaseId) with exit code ${exitCode}: $rawOutput" }
    $lines = @($output | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -eq 0) { throw "FullRelease executor returned no evidence for $($Context.phaseId)." }
    for ($index = $lines.Count - 1; $index -ge 0; $index--) {
        $candidateJson = $lines[$index].Trim()
        if (-not ($candidateJson.StartsWith('{') -or $candidateJson.StartsWith('['))) { continue }
        try { return ($candidateJson | ConvertFrom-Json -ErrorAction Stop) } catch { continue }
    }
    throw "FullRelease executor returned invalid JSON for $($Context.phaseId); raw evidence=$rawPath."
}

function Invoke-DisposablePrivateSignatureVerification {
    param(
        [Parameter(Mandatory)][psobject]$Fingerprint,
        [Parameter(Mandatory)][psobject]$Vm,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$RunDir
    )
    if([string]$Fingerprint.privateSigningProfile -ne 'PRIVATE_SELF_SIGNED'){return $null}
    Assert-FullReleaseDisposableOwnership -Vm $Vm|Out-Null
    $thumbprint=[string]$Fingerprint.privateSigningCertificateThumbprint
    $publicCertificate=[string]$Fingerprint.publicCertificate.path
    if(-not(Test-Path -LiteralPath $publicCertificate -PathType Leaf)){throw 'Private signing public certificate is unavailable for disposable verification.'}
    $session=$null
    try{
        $session=Connect-DevFleetGuest -VmId ([guid][string]$Vm.Id)
        $remoteRoot="C:\Users\Public\DevFleet-E2E\$RunId\private-signature-verification"
        $remoteExe=Join-Path $remoteRoot (Split-Path -Leaf ([string]$Fingerprint.candidate.path))
        $remoteCertificate=Join-Path $remoteRoot 'DevFleet-Private-Personal-Code-Signing.cer'
        Invoke-Command -Session $session -ScriptBlock{param($root)New-Item -ItemType Directory -Path $root -Force|Out-Null}-ArgumentList $remoteRoot
        $exeStage=Get-StageIntegrity -LocalPath ([string]$Fingerprint.candidate.path) -Session $session -RemotePath $remoteExe
        $certificateStage=Get-StageIntegrity -LocalPath $publicCertificate -Session $session -RemotePath $remoteCertificate
        if(-not $exeStage.equal -or -not $certificateStage.equal){throw 'Private signature verifier staging identity mismatch.'}
        $verification=Invoke-Command -Session $session -ScriptBlock{
            param($exe,$cer,$expectedThumbprint,$root)
            $ErrorActionPreference='Stop'
            if($env:COMPUTERNAME -match 'SURFACE'){throw 'Disposable signature verification refused a Surface host.'}
            $tampered=Join-Path $root 'tampered-copy.exe';$trustedCertificate=$null;$chain=$null
            try{
                $trustedCertificate=[Security.Cryptography.X509Certificates.X509Certificate2]::new($cer)
                if($trustedCertificate.Thumbprint -cne $expectedThumbprint){throw 'Disposable verifier public certificate thumbprint mismatch.'}
                $signature=Get-AuthenticodeSignature -LiteralPath $exe
                if(-not $signature.SignerCertificate){throw 'Disposable verifier found no Authenticode signer certificate.'}
                if($signature.SignerCertificate.Thumbprint -cne $expectedThumbprint){throw 'Disposable verifier signer thumbprint mismatch.'}
                if([Convert]::ToBase64String($signature.SignerCertificate.RawData) -cne [Convert]::ToBase64String($trustedCertificate.RawData)){throw 'Disposable verifier signer differs from the exact supplied public certificate.'}
                if([string]$signature.Status -notin @('Valid','UnknownError')){throw "Disposable verifier returned an unexpected Authenticode status: $($signature.Status)."}
                if([string]$signature.Status -eq 'UnknownError' -and [string]$signature.StatusMessage -notmatch '(?i)trust|root|certificate chain'){throw "Disposable verifier UnknownError was not solely an untrusted-root condition: $($signature.StatusMessage)"}
                if('1.3.6.1.5.5.7.3.3' -notin @($signature.SignerCertificate.EnhancedKeyUsageList|ForEach-Object{[string]$_.ObjectId})){throw 'Disposable verifier signer lacks Code Signing EKU.'}
                $chain=[Security.Cryptography.X509Certificates.X509Chain]::new()
                $chain.ChainPolicy.RevocationMode=[Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                $chain.ChainPolicy.VerificationFlags=[Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
                $null=$chain.ChainPolicy.ExtraStore.Add($trustedCertificate)
                if(-not $chain.Build($signature.SignerCertificate)){throw "Disposable exact-certificate chain validation failed: $(@($chain.ChainStatus|ForEach-Object Status) -join ', ')"}
                $unexpectedChainStatus=@($chain.ChainStatus|Where-Object{[string]$_.Status -notin @('NoError','UntrustedRoot')})
                if($unexpectedChainStatus.Count){throw "Disposable verifier chain has unexpected status: $(@($unexpectedChainStatus|ForEach-Object Status) -join ', ')"}
                Copy-Item -LiteralPath $exe -Destination $tampered
                $stream=[IO.File]::Open($tampered,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
                try{$stream.Position=4096;$byte=$stream.ReadByte();$stream.Position=4096;$stream.WriteByte(($byte -bxor 1))}finally{$stream.Dispose()}
                $tamperedStatus=[string](Get-AuthenticodeSignature -LiteralPath $tampered).Status
                if($tamperedStatus -ne 'HashMismatch'){throw "Disposable tampered-copy verification returned $tamperedStatus instead of HashMismatch."}
                [pscustomobject]@{status='PASS';computer=$env:COMPUTERNAME;signerThumbprint=$signature.SignerCertificate.Thumbprint;signatureStatus=[string]$signature.Status;signatureStatusMessage=[string]$signature.StatusMessage;codeSigningEkuVerified=$true;exactCertificateMatch=$true;explicitTrustValidation='PASS';trustMode='IN_MEMORY_EXACT_CERTIFICATE';chainStatuses=@($chain.ChainStatus|ForEach-Object{[string]$_.Status});tamperedCopyStatus=$tamperedStatus;trustStores=@();trustInstalledForRun=@();privateKeyPresent=$false;physicalSurfaceTouched=$false}
            }finally{
                Remove-Item -LiteralPath $tampered -Force -ErrorAction SilentlyContinue
                if($chain){$chain.Dispose()}
                if($trustedCertificate){$trustedCertificate.Dispose()}
                Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
            }
        }-ArgumentList $remoteExe,$remoteCertificate,$thumbprint,$remoteRoot
        $evidencePath=Join-Path $RunDir 'private-signature-disposable-verifier.json'
        [IO.File]::WriteAllText($evidencePath,(($verification|ConvertTo-Json -Depth 8)+[Environment]::NewLine),(New-Object Text.UTF8Encoding($false)))
        return [ordered]@{status='PASS';expectedThumbprint=$thumbprint;exeStage=$exeStage;certificateStage=$certificateStage;guest=$verification;evidencePath=$evidencePath;trustCleanup='no persistent guest trust mutation performed'}
    }finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
}

function Invoke-FullReleaseCleanup {
    param(
        [Parameter(Mandatory)][psobject]$Vm,
        [Parameter(Mandatory)][psobject]$Config,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$RunDir
    )
    $manifest=New-CleanupManifest -Vm $Vm -RunId $RunId
    if(-not(Test-CleanupManifest $manifest)){throw 'Final cleanup manifest failed exact disposable ownership validation.'}
    $session=$null;$guestCleanup=$null;$logonCleanup=$null
    try{
        $cleanupVm=Get-AssertedDisposableVm -ExpectedVm $Vm
        if($cleanupVm.State -ne 'Running'){Start-VM -VM $cleanupVm -ErrorAction Stop|Out-Null}
        $session=Connect-DevFleetGuest -VmId ([guid][string]$Vm.Id)
        $logonCleanup=Clear-DevFleetE2EInteractiveLogonState -VmId ([guid][string]$Vm.Id)
        if([string]$logonCleanup.status -ne 'PASS' -or -not [bool]$logonCleanup.registryCleanupPersisted -or -not [bool]$logonCleanup.temporaryDefaultPasswordRemovalPersisted -or [bool]$logonCleanup.ordinaryDefaultPasswordPresent){throw 'Final cleanup durable interactive-login preconditions were not satisfied.'}
        $guestCleanup=Invoke-Command -Session $session -ScriptBlock{
            param($runId,$nestedName)
            $ErrorActionPreference='Stop'
            $runRoot="C:\Users\Public\DevFleet-E2E\$runId"
            if(Test-Path -LiteralPath $runRoot){Remove-Item -LiteralPath $runRoot -Recurse -Force}
            if(Test-Path -LiteralPath $runRoot){throw 'Run-scoped candidate staging directory remains after cleanup.'}
            $tasks=@(Get-ScheduledTask -TaskName 'DevFleet-E2E-UIA-*' -ErrorAction SilentlyContinue)
            if($tasks.Count -gt 0){throw "E2E UI scheduled tasks remain after executor cleanup: $($tasks.TaskName -join ', ')"}
            $multipassCandidates=@((Join-Path $env:ProgramFiles 'Multipass\bin\multipass.exe'),(Join-Path ${env:ProgramFiles(x86)} 'Multipass\bin\multipass.exe'))|Where-Object{$_ -and(Test-Path -LiteralPath $_ -PathType Leaf)}
            $multipass=$multipassCandidates|Select-Object -First 1
            $nestedAbsent=$true
            if($multipass){
                $inventory=(& $multipass list --format json 2>&1)-join "`n"
                if($LASTEXITCODE -ne 0){throw 'Final cleanup could not enumerate Multipass ownership state.'}
                if($inventory -match ('"name"\s*:\s*"'+[regex]::Escape($nestedName)+'"')){
                    & $multipass exec $nestedName -- test -f "/etc/devfleet-e2e-run-$runId" 2>&1|Out-Null
                    if($LASTEXITCODE -ne 0){throw "Nested VM $nestedName exists without this RunId marker; cleanup refused it."}
                    & $multipass delete --purge $nestedName 2>&1|Out-Null
                    if($LASTEXITCODE -ne 0){throw "Run-owned nested VM $nestedName could not be deleted."}
                    $after=(& $multipass list --format json 2>&1)-join "`n";$nestedAbsent=$after -notmatch ('"name"\s*:\s*"'+[regex]::Escape($nestedName)+'"')
                    if(-not $nestedAbsent){throw "Run-owned nested VM $nestedName remains after deletion."}
                }
            }
            [pscustomobject]@{status='PASS';computer=$env:COMPUTERNAME;runRootAbsent=$true;uiaTasksAbsent=$true;nestedName=$nestedName;nestedAbsent=$nestedAbsent;foreignResourcesMutated=$false}
        }-ArgumentList $RunId,([string]$Config.NestedLinux.Name)
    }finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
    Stop-ManifestVm -Manifest $manifest
    $stopDeadline=(Get-Date).AddMinutes(2)
    do{$finalVm=Get-AssertedDisposableVm -ExpectedVm $Vm;if($finalVm.State -eq 'Off'){break};Start-Sleep -Seconds 2}while((Get-Date)-lt $stopDeadline)
    if($finalVm.Id.ToString() -ne $Vm.Id.ToString() -or $finalVm.State -ne 'Off'){throw 'Final cleanup did not leave the exact disposable L1 powered off.'}
    $terminal = Write-TerminalVmEvidence -Vm $Vm -RunDir $RunDir -L2Name ([string]$Config.NestedLinux.Name)
    $evidence=[ordered]@{status='PASS';manifest=$manifest;interactiveLogonCleanup=$logonCleanup;guest=$guestCleanup;l1=[ordered]@{name=$finalVm.Name;id=$finalVm.Id.ToString();state=[string]$finalVm.State;deleted=$false};productionTouched=$false;physicalSurfaceTouched=$false}
    $evidence.terminal=$terminal
    $evidencePath=Join-Path $RunDir 'final-cleanup.json'
    [IO.File]::WriteAllText($evidencePath,(($evidence|ConvertTo-Json -Depth 12)+[Environment]::NewLine),(New-Object Text.UTF8Encoding($false)))
    $evidence.evidencePath=$evidencePath
    return $evidence
}

function Write-PostCleanupFinalization {
    param([Parameter(Mandatory)][psobject]$State,[Parameter(Mandatory)][psobject]$Vm,[Parameter(Mandatory)][psobject]$Config,[Parameter(Mandatory)][string]$RunDir,[Parameter(Mandatory)][object[]]$Records)
    $cleanup = @($Records | Where-Object { [string]$_.id -eq 'CLEANUP' }) | Select-Object -Last 1
    if(-not $cleanup -or [string]$cleanup.status -ne 'PASS' -or -not $cleanup.evidence){throw 'Post-cleanup finalization requires a passing current CLEANUP record.'}
    $cleanupPath=Join-Path $RunDir 'final-cleanup.json'
    if(-not(Test-Path -LiteralPath $cleanupPath -PathType Leaf)){throw 'Post-cleanup finalization is missing final-cleanup.json.'}
    $cleanupValue=Get-Content -LiteralPath $cleanupPath -Raw|ConvertFrom-Json
    if([string]$cleanupValue.status -ne 'PASS' -or [string]$cleanupValue.l1.state -ne 'Off' -or -not [bool]$cleanupValue.guest.runRootAbsent -or [bool]$cleanupValue.guest.foreignResourcesMutated){throw 'Post-cleanup finalization rejected incomplete or unsafe cleanup evidence.'}
    foreach($name in @('l1-terminal-state.json','l2-terminal-state.json')){if(-not(Test-Path -LiteralPath (Join-Path $RunDir $name) -PathType Leaf)){throw "Post-cleanup finalization is missing $name."}}
    $l1=Get-Content -LiteralPath (Join-Path $RunDir 'l1-terminal-state.json') -Raw|ConvertFrom-Json
    $l2=Get-Content -LiteralPath (Join-Path $RunDir 'l2-terminal-state.json') -Raw|ConvertFrom-Json
    if([string]$l1.name -cne [string]$Vm.Name -or [string]$l1.id -cne [string]$Vm.Id -or [string]$l1.state -ne 'Off'){throw 'Post-cleanup L1 terminal evidence is not the exact powered-off disposable VM.'}
    $expectedL2=[string]$Config.NestedLinux.Name
    if([string]::IsNullOrWhiteSpace($expectedL2) -or $expectedL2 -eq 'DevFleet-H10-Linux' -or [string]$l2.expectedName -cne $expectedL2 -or [bool]$l2.present -or [string]$l2.verificationMethod -notmatch 'Get-VM'){throw 'Post-cleanup L2 terminal evidence is not an exact safe absence proof.'}
    # Re-read live Hyper-V state after cleanup; terminal JSON alone is not a
    # boolean claim and is only accepted when it matches this second check.
    $live=Get-VM -Id ([guid][string]$Vm.Id) -ErrorAction Stop
    if($live.Name -cne [string]$Vm.Name -or [string]$live.State -ne 'Off'){throw 'Post-cleanup live L1 verification failed.'}
    if(@(Get-VM -Name $expectedL2 -ErrorAction SilentlyContinue).Count -ne 0){throw 'Post-cleanup live L2 verification found the configured disposable resource.'}
    $hash = { param($path) (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
    $cleanupHash=&$hash $cleanupPath;$l1Path=Join-Path $RunDir 'l1-terminal-state.json';$l2Path=Join-Path $RunDir 'l2-terminal-state.json'
    $value=[ordered]@{schemaVersion=2;status='PASS';contract='authoritative-post-cleanup-finalization';runId=[string]$State.runId;cleanupConsumed=$true;cleanupRecordStatus=[string]$cleanup.status;cleanupEvidenceHash=$cleanupHash;terminalL1='l1-terminal-state.json';terminalL1Hash=(&$hash $l1Path);terminalL1Timestamp=[string]$l1.timestampUtc;terminalL2='l2-terminal-state.json';terminalL2Hash=(&$hash $l2Path);terminalL2Timestamp=[string]$l2.timestampUtc;expectedL2Name=$expectedL2;liveChecks=[ordered]@{l1ExactOff=$true;l2ExactAbsent=$true;foreignResourcesMutated=$false};reconcileAfterCleanup=$true;timestampUtc=(Get-Date).ToUniversalTime().ToString('o')}
    Write-EvidenceJson -Path (Join-Path $RunDir 'post-cleanup-finalization.json') -Value $value
    return $value
}

function Invoke-FullReleaseRun {
    param(
        [Parameter(Mandatory)][psobject]$State,
        [Parameter(Mandatory)][psobject]$Fingerprint,
        [Parameter(Mandatory)][psobject]$Vm,
        [Parameter(Mandatory)][psobject]$Config,
        [Parameter(Mandatory)][string]$WorkspaceRoot,
        [Parameter(Mandatory)][string]$RunDir,
        [Parameter(Mandatory)][string]$StatePath,
        [Parameter(Mandatory)][psobject]$HostSnapshot,
        [Parameter(Mandatory)][psobject]$SelfTest
    )
    $effectiveStartAuthorized = if($HostSnapshot.PSObject.Properties['effectiveE2EStartAuthorized']){[bool]$HostSnapshot.effectiveE2EStartAuthorized}else{[bool]$HostSnapshot.startSafe}
    if (-not $effectiveStartAuthorized) { throw 'USER ACTION REQUIRED — FREE HOST RAM' }
    $records = [System.Collections.Generic.List[object]]::new()
    $context = [ordered]@{ runId=$State.runId; phaseId=''; label=''; checkpoint=$null; destructive=$false; candidate=$Fingerprint; vmName=$Vm.Name; vmId=$Vm.Id.ToString(); statePath=$StatePath; runDir=$RunDir; workspaceRoot=$WorkspaceRoot; config=$Config }
    foreach ($phase in $script:FullReleasePhases) {
        $context.phaseId=$phase.id
        $context.label=$phase.label;$context.checkpoint=$phase.checkpoint;$context.destructive=[bool]$phase.destructive
        $State.currentPhase=$phase.id
        Save-RunState -State $State -Path $StatePath
        $record = [ordered]@{ id=$phase.id; label=$phase.label; checkpoint=$phase.checkpoint; destructive=[bool]$phase.destructive; status='NOT RUN'; evidence=$null; startedAt=(Get-Date).ToUniversalTime().ToString('o') }
        try {
            if ($phase.id -eq 'HOST-SAFETY') {
                if (-not $effectiveStartAuthorized) { throw 'Host safety threshold was not met.' }
                $record.status='PASS';$record.evidence=$HostSnapshot
            } elseif ($phase.id -eq 'CANDIDATE-VERIFY') {
                $checks=$SelfTest.requiredChecks
                $bad=if ($checks -is [System.Collections.IDictionary]) { @($checks.GetEnumerator() | Where-Object { -not [bool]$_.Value }) } else { @($checks.PSObject.Properties | Where-Object { -not [bool]$_.Value }) }
                if ($SelfTest.result -ne 'PASS' -or @($bad).Count -gt 0) { throw 'Candidate self-test is not a complete PASS.' }
                $record.status='PASS';$record.evidence=[ordered]@{selfTest=$SelfTest;hostAuthenticode=[ordered]@{profile=$Fingerprint.privateSigningProfile;thumbprint=$Fingerprint.privateSigningCertificateThumbprint;publicPublisherTrust=$Fingerprint.publicPublisherTrust;publicPromotionAllowed=$Fingerprint.publicPromotionAllowed}}
            } elseif ($phase.id -eq 'MAINTENANCE-READY') {
                $maintenance=Ensure-MaintenanceReadyFixture -Vm $Vm -Fingerprint $Fingerprint -Config $Config -WorkspaceRoot $WorkspaceRoot -RunId ([string]$State.runId) -RunDir $RunDir
                $record.status='PASS';$record.evidence=$maintenance
            } elseif ($phase.id -eq 'RESTORE-CLEAN') {
                $checkpoint=Restore-ExactCheckpoint -Vm $Vm -Name $phase.checkpoint -StartAfterRestore
                $State.checkpointIds=@($State.checkpointIds)+@($checkpoint.id)
                $postStart=$null
                if ($phase.id -eq 'RESTORE-CLEAN') {
                    $postStart=Confirm-PostStartHostMemorySafety -InitialSnapshot $HostSnapshot -SampleSeconds 60 -IntervalSeconds 5
                    if ($postStart.status -ne 'PASS' -and -not [bool]$HostSnapshot.ramPressureOverrideAuthorized) { throw 'USER ACTION REQUIRED — HOST MEMORY PRESSURE AFTER E2E VM START' }
                    if ([bool]$HostSnapshot.ramPressureOverrideAuthorized) { $postStart.rawStatus=$postStart.status; $postStart.status='PASS — USER-AUTHORIZED RAM PRESSURE'; $postStart.overrideAuthorized=$true }
                }
                $record.status='PASS';$record.evidence=$checkpoint
                if ($postStart) { $record.evidence=[ordered]@{ checkpoint=$checkpoint; postStartMemory=$postStart } }
            } elseif ($phase.id -eq 'ESTABLISH-SESSION') {
                $checkpoint=Restore-ExactCheckpoint -Vm $Vm -Name $phase.checkpoint -StartAfterRestore
                $State.checkpointIds=@($State.checkpointIds)+@($checkpoint.id)
                $privateVerifier=Invoke-DisposablePrivateSignatureVerification -Fingerprint $Fingerprint -Vm $Vm -RunId ([string]$State.runId) -RunDir $RunDir
                $desktop=Ensure-FullReleaseInteractiveDesktop -VmId ([guid][string]$Vm.Id)
                $record.status='PASS';$record.evidence=[ordered]@{checkpoint=$checkpoint;interactiveDesktop=$desktop;privateAuthenticodeVerifier=$privateVerifier}
            } elseif ($phase.id -eq 'CLEANUP') {
                $record.status='PASS';$record.evidence=Invoke-FullReleaseCleanup -Vm $Vm -Config $Config -RunId ([string]$State.runId) -RunDir $RunDir
            } else {
                $checkpointEvidence=$null
                if ($phase.checkpoint) {
                    if ([string]$phase.checkpoint -ceq 'DevFleet-E2E-MAINTENANCE-READY') {
                        $checkpointEvidence=Restore-MaintenanceReadyCheckpoint -Vm $Vm -Fingerprint $Fingerprint -WorkspaceRoot $WorkspaceRoot
                        $State.checkpointIds=@($State.checkpointIds)+@($checkpointEvidence.checkpoint.id)
                    } else {
                        $checkpointEvidence=Restore-ExactCheckpoint -Vm $Vm -Name $phase.checkpoint -StartAfterRestore
                        $State.checkpointIds=@($State.checkpointIds)+@($checkpointEvidence.id)
                    }
                }
                $executor=Get-ExecutorPath -Config $Config -PhaseId $phase.id -WorkspaceRoot $WorkspaceRoot
                if (-not $executor) { throw "No real product executor is configured for FullRelease phase $($phase.id); refusing to convert a plan into a PASS." }
                $evidence=Invoke-ConfiguredExecutor -Path $executor -Context ([pscustomobject]$context)
                if ([string]$evidence.status -notin @('PASS','REAL E2E PASS')) { throw "Executor did not return PASS for $($phase.id)." }
                $record.status='PASS';$record.evidence=[ordered]@{ checkpoint=$checkpointEvidence; executor=$evidence }
            }
        } catch {
            $record.status='BLOCKED';$record.error=$_.Exception.Message
            $record.finishedAt=(Get-Date).ToUniversalTime().ToString('o')
            $records.Add([pscustomobject]$record)
            $remainingPhaseIds=@($script:FullReleasePhases.id);$currentIndex=[Array]::IndexOf($remainingPhaseIds,[string]$phase.id)
            foreach($remaining in @($script:FullReleasePhases | Select-Object -Skip ($currentIndex+1))){$records.Add([pscustomobject][ordered]@{id=$remaining.id;label=$remaining.label;checkpoint=$remaining.checkpoint;destructive=[bool]$remaining.destructive;status='NOT RUN';evidence=$null;startedAt=$null;finishedAt=$null})}
            $State.errors=@($State.errors)+@($_.Exception.Message);$State.finalStatus='BLOCKED — FullRelease evidence incomplete';Save-RunState -State $State -Path $StatePath
            Write-EvidenceJson -Path (Join-Path $RunDir 'fullrelease-phase-records.json') -Value $records
            throw
        }
        $record.finishedAt=(Get-Date).ToUniversalTime().ToString('o');$records.Add([pscustomobject]$record)
        $State.completedPhases=@($State.completedPhases)+@($phase.id);Save-RunState -State $State -Path $StatePath
        Write-EvidenceJson -Path (Join-Path $RunDir 'fullrelease-phase-records.json') -Value $records
    }
    $postCleanup=Write-PostCleanupFinalization -State $State -Vm $Vm -Config $Config -RunDir $RunDir -Records @($records)
    $State.currentPhase='COMMITTED';$State.finalStatus='PASS';Save-RunState -State $State -Path $StatePath
    return [pscustomobject]@{ status='PASS'; runId=$State.runId; candidate=$Fingerprint; phases=$records; postCleanupFinalization=$postCleanup }
}

Export-ModuleMember -Function Get-FullReleasePhasePlan,Get-AssertedDisposableVm,Get-ExactCheckpoint,Restore-ExactCheckpoint,Ensure-FullReleaseInteractiveDesktop,Assert-MaintenanceReadyProvenance,Invoke-MaintenanceReadyGuestValidation,Invoke-MaintenanceReadyProductLifecycle,Ensure-MaintenanceReadyFixture,Restore-MaintenanceReadyCheckpoint,Invoke-FullReleaseRun,Invoke-DisposablePrivateSignatureVerification,Invoke-FullReleaseCleanup
