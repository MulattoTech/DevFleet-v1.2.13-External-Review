$ErrorActionPreference = 'Stop'

# One finite, composable deadline policy shared by the lifecycle observer,
# FullRelease, and the exact-proof driver.  Values are operation maxima; the
# enclosing budgets are sums of the operations they own, not replacements for
# them.  A child may consume less than its maximum, but never more than the
# remaining deadline of its owner.
$script:DeadlinePolicyVersion = '1.0.0'

function Get-HarnessBudgetPolicy {
    [CmdletBinding()]
    param([psobject]$Config)

    $configured = if ($Config -and $Config.PSObject.Properties['DeadlinePolicy']) { $Config.DeadlinePolicy } else { $null }
    # The guest bootstrap is one bounded operation at the Windows boundary,
    # but its maximum is itself derived from the finite stages in the current
    # script: package prerequisites, signed repositories, runtime setup, and
    # service/firewall finalization.  This prevents a bootstrap timeout from
    # being a second un-derived magic number.
    $guestBootstrapComponents = [ordered]@{
        packagePrerequisites = 900
        dockerRepositoryAndInstall = 1200
        tailscaleRepositoryAndInstall = 1200
        rootlessRuntime = 600
        nodeToolchain = 600
        pythonRuntime = 1200
        serviceAndFirewallFinalization = 600
    }
    if ($configured -and $configured.PSObject.Properties['GuestBootstrapComponentsSeconds']) {
        foreach ($property in $configured.GuestBootstrapComponentsSeconds.PSObject.Properties) {
            $key = [string]$property.Name
            if ($guestBootstrapComponents.Contains($key)) { $guestBootstrapComponents[$key] = [int]$property.Value }
        }
    }
    foreach ($entry in $guestBootstrapComponents.GetEnumerator()) {
        if ([int]$entry.Value -le 0) { throw "Guest bootstrap component '$($entry.Key)' must be positive." }
    }
    $derivedGuestBootstrap = [int](($guestBootstrapComponents.Values | Measure-Object -Sum).Sum)
    $operationDependencyProbe = 60
    $operationDependencyHealth = 180
    $operationDependencyInstall = 1800
    $operationDependencyVerification = 60
    $operationWindowsCapability = 900
    $operationWindowsFeature = 900
    $operationMultipassConfiguration = 600
    $operationVsCodeExtensions = 300
    $operation = [ordered]@{
        bootstrap = 240
        preflight = 120
        dependencyProbe = $operationDependencyProbe
        dependencyHealth = $operationDependencyHealth
        dependencyInstall = $operationDependencyInstall
        dependencyVerification = $operationDependencyVerification
        windowsCapability = $operationWindowsCapability
        windowsFeature = $operationWindowsFeature
        multipassConfiguration = $operationMultipassConfiguration
        vscodeExtension = $operationVsCodeExtensions
        prerequisites = (6 * ($operationDependencyProbe + $operationDependencyHealth + $operationDependencyInstall + $operationDependencyVerification)) + $operationWindowsCapability + $operationWindowsFeature + (4 * $operationMultipassConfiguration) + (3 * $operationVsCodeExtensions)
        windowsTailscale = 180
        hostAgent = 300
        multipassLaunch = 900
        multipassReadiness = 1200
        payloadTransfer = 900
        guestBootstrap = $derivedGuestBootstrap
        sshAndMarker = 300
        vaultSnapshot = 300
        tailscale = 900
        vaultClient = 300
        shortcuts = 180
        export = 300
        verification = 300
    }
    if ($configured -and $configured.PSObject.Properties['OperationMaximumsSeconds']) {
        foreach ($property in $configured.OperationMaximumsSeconds.PSObject.Properties) {
            $key = [string]$property.Name
            if ($operation.Contains($key) -and $key -ne 'guestBootstrap') { $operation[$key] = [int]$property.Value }
            elseif ($key -eq 'guestBootstrap' -and [int]$property.Value -ne $derivedGuestBootstrap) { throw "guestBootstrap must equal the sum of GuestBootstrapComponentsSeconds ($derivedGuestBootstrap); refusing an un-derived timeout override." }
        }
    }
    $derivedPrerequisites = (6 * ([int]$operation.dependencyProbe + [int]$operation.dependencyHealth + [int]$operation.dependencyInstall + [int]$operation.dependencyVerification)) + [int]$operation.windowsCapability + [int]$operation.windowsFeature + (4 * [int]$operation.multipassConfiguration) + (3 * [int]$operation.vscodeExtension)
    if ($configured -and $configured.OperationMaximumsSeconds -and $configured.OperationMaximumsSeconds.PSObject.Properties['prerequisites'] -and [int]$configured.OperationMaximumsSeconds.prerequisites -ne $derivedPrerequisites) { throw "prerequisites must equal the sum of its finite operation maxima ($derivedPrerequisites); refusing an un-derived timeout override." }
    $operation.prerequisites = $derivedPrerequisites
    foreach ($entry in $operation.GetEnumerator()) {
        if ([int]$entry.Value -le 0) { throw "Deadline policy operation maximum '$($entry.Key)' must be positive." }
    }

    $stage = [ordered]@{
        compute = [int]$operation.multipassLaunch + [int]$operation.multipassReadiness + [int]$operation.payloadTransfer + [int]$operation.guestBootstrap + [int]$operation.sshAndMarker
        vault = [int]$operation.vaultSnapshot + [int]$operation.multipassLaunch + [int]$operation.multipassReadiness + [int]$operation.payloadTransfer + [int]$operation.guestBootstrap + [int]$operation.sshAndMarker
    }
    $desktop = [int]$operation.bootstrap + [int]$operation.preflight + [int]$operation.prerequisites + [int]$operation.windowsTailscale + [int]$operation.hostAgent + $stage.compute + [int]$operation.tailscale + [int]$operation.shortcuts + [int]$operation.export + [int]$operation.verification
    $laptop = [int]$operation.bootstrap + [int]$operation.preflight + [int]$operation.prerequisites + [int]$operation.windowsTailscale + [int]$operation.hostAgent + $stage.compute + $stage.vault + ([int]$operation.tailscale * 2) + [int]$operation.vaultClient + [int]$operation.shortcuts + [int]$operation.export + [int]$operation.verification
    $transactionMargin = 600
    $observerMargin = 600
    $fullReleaseMargin = 600
    $exactProofMargin = 600
    $maxRebootBoundaries = 3
    $observerNoProgress = 1800
    if ($configured) {
        foreach ($name in @('TransactionTerminalizationMarginSeconds','ObserverTerminalizationMarginSeconds','FullReleaseTerminalizationMarginSeconds','ExactProofTerminalizationMarginSeconds','MaxRebootBoundaries','ObserverNoProgressBudgetSeconds')) {
            if ($configured.PSObject.Properties[$name]) {
                $value = [int]$configured.$name
                if ($value -le 0 -and $name -ne 'MaxRebootBoundaries') { throw "Deadline policy '$name' must be positive." }
                if ($name -eq 'TransactionTerminalizationMarginSeconds') { $transactionMargin = $value }
                elseif ($name -eq 'ObserverTerminalizationMarginSeconds') { $observerMargin = $value }
                elseif ($name -eq 'FullReleaseTerminalizationMarginSeconds') { $fullReleaseMargin = $value }
                elseif ($name -eq 'ExactProofTerminalizationMarginSeconds') { $exactProofMargin = $value }
                elseif ($name -eq 'MaxRebootBoundaries') { $maxRebootBoundaries = $value }
                elseif ($name -eq 'ObserverNoProgressBudgetSeconds') { $observerNoProgress = $value }
            }
        }
    }
    if ($maxRebootBoundaries -lt 1) { throw 'Deadline policy must permit at least one bounded reboot boundary.' }
    $transaction = [ordered]@{ Desktop = $desktop + $transactionMargin; Laptop = $laptop + $transactionMargin }
    $productTransaction = [int]$transaction.Desktop
    $observerAbsolute = $productTransaction + $observerMargin
    $wpfAction = 600
    $rebootBoundary = 420
    $servicingSettlement = 180
    $interactiveDesktop = 300
    $checkpointPolling = 900
    $lifecycleInner = $wpfAction + (($maxRebootBoundaries + 1) * $observerAbsolute) + ($maxRebootBoundaries * ($wpfAction + $rebootBoundary + $servicingSettlement + $interactiveDesktop)) + $checkpointPolling + $transactionMargin
    $fullReleaseInner = $lifecycleInner
    $fullReleaseWatchdog = $fullReleaseInner + $fullReleaseMargin
    $exactProofInner = 300 + $fullReleaseInner
    $exactProofOuter = $exactProofInner + $exactProofMargin
    $maximumOuter = 90000
    if ($configured -and $configured.PSObject.Properties['MaximumExactProofOuterWatchdogSeconds']) { $maximumOuter = [int]$configured.MaximumExactProofOuterWatchdogSeconds }
    $policy = [pscustomobject][ordered]@{
        version = $script:DeadlinePolicyVersion
        operationMaximumsSeconds = [pscustomobject]$operation
        guestBootstrapComponentsSeconds = [pscustomobject]$guestBootstrapComponents
        stageBudgetsSeconds = [pscustomobject]$stage
        transactionBudgetsSeconds = [pscustomobject]$transaction
        transactionTerminalizationMarginSeconds = $transactionMargin
        observerTerminalizationMarginSeconds = $observerMargin
        fullReleaseTerminalizationMarginSeconds = $fullReleaseMargin
        exactProofTerminalizationMarginSeconds = $exactProofMargin
        observerNoProgressBudgetSeconds = $observerNoProgress
        observerAbsoluteBudgetSeconds = $observerAbsolute
        productTransactionAbsoluteBudgetSeconds = $productTransaction
        productLifecycleInnerBoundSeconds = $lifecycleInner
        fullReleaseInnerBoundSeconds = $fullReleaseInner
        fullReleaseWatchdogSeconds = $fullReleaseWatchdog
        exactProofInnerBoundSeconds = $exactProofInner
        exactProofOuterWatchdogSeconds = $exactProofOuter
        maximumExactProofOuterWatchdogSeconds = $maximumOuter
        maxRebootBoundaries = $maxRebootBoundaries
        inequalities = [ordered]@{
            stageDominatesOperations = $true
            observerDominatesTransaction = ($observerAbsolute -gt $productTransaction)
            fullReleaseDominatesObserver = ($fullReleaseWatchdog -gt $observerAbsolute)
            exactProofDominatesInner = ($exactProofOuter -gt $exactProofInner)
        }
    }
    Assert-HarnessBudgetPolicy -Policy $policy | Out-Null
    return $policy
}

function Assert-HarnessBudgetPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Policy)
    foreach ($name in @('productTransactionAbsoluteBudgetSeconds','observerAbsoluteBudgetSeconds','fullReleaseWatchdogSeconds','exactProofInnerBoundSeconds','exactProofOuterWatchdogSeconds')) {
        if (-not $Policy.PSObject.Properties[$name] -or [int]$Policy.$name -le 0) { throw "Deadline policy is missing a finite positive '$name'." }
    }
    if ([int]$Policy.observerAbsoluteBudgetSeconds -le [int]$Policy.productTransactionAbsoluteBudgetSeconds) { throw 'Invalid deadline hierarchy: observer absolute must strictly exceed product transaction.' }
    if ([int]$Policy.fullReleaseWatchdogSeconds -le [int]$Policy.observerAbsoluteBudgetSeconds) { throw 'Invalid deadline hierarchy: FullRelease watchdog must strictly exceed observer absolute.' }
    if ([int]$Policy.exactProofOuterWatchdogSeconds -le [int]$Policy.exactProofInnerBoundSeconds) { throw 'Invalid deadline hierarchy: exact-proof outer watchdog must strictly exceed its calculated inner bound.' }
    if ([int]$Policy.exactProofOuterWatchdogSeconds -gt [int]$Policy.maximumExactProofOuterWatchdogSeconds) { throw "Deadline policy requires exact-proof outer watchdog $($Policy.exactProofOuterWatchdogSeconds)s, exceeding configured maximum $($Policy.maximumExactProofOuterWatchdogSeconds)s; refusing to truncate." }
    return $true
}

function Get-DeadlineRemainingSeconds {
    param([Parameter(Mandatory)][datetime]$DeadlineUtc, [datetime]$NowUtc = ([datetime]::UtcNow))
    [int][math]::Floor(($DeadlineUtc.ToUniversalTime() - $NowUtc.ToUniversalTime()).TotalSeconds)
}

function Get-EffectiveDeadlineTimeoutSeconds {
    param([Parameter(Mandatory)][int]$OperationMaximumSeconds, [Parameter(Mandatory)][datetime]$DeadlineUtc, [datetime]$NowUtc = ([datetime]::UtcNow))
    if ($OperationMaximumSeconds -le 0) { throw 'Operation maximum must be positive.' }
    $remaining = Get-DeadlineRemainingSeconds -DeadlineUtc $DeadlineUtc -NowUtc $NowUtc
    if ($remaining -le 0) { throw 'Owning deadline has expired; refusing to start another child operation.' }
    [math]::Min($OperationMaximumSeconds, $remaining)
}

Export-ModuleMember -Function Get-HarnessBudgetPolicy,Assert-HarnessBudgetPolicy,Get-DeadlineRemainingSeconds,Get-EffectiveDeadlineTimeoutSeconds
