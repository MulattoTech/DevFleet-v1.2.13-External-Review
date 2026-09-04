Set-StrictMode -Version Latest

function Get-DisposableVm {
    param([string]$VmName,[string]$Pattern = 'DevFleet-E2E-*')
    if ($VmName) { $vms = @(Get-VM -Name $VmName -ErrorAction Stop) } else { $vms = @(Get-VM | Where-Object { $_.Name -like $Pattern }) }
    if ($vms.Count -eq 0) { throw 'No ownership-scoped disposable DevFleet-E2E VM was found.' }
    if ($vms.Count -gt 1 -and -not $VmName) { throw "Disposable VM discovery is ambiguous: $($vms.Name -join ', ')." }
    $vm = $vms[0]
    if ($vm.Name -notlike 'DevFleet-E2E-*') { throw "Refusing non-disposable VM target: $($vm.Name)" }
    $vm
}

function Get-ProjectedHostMemorySafety {
    param(
        [Parameter(Mandatory)][double]$AvailableMemoryGiB,
        [Parameter(Mandatory)][double]$ExpectedVmStartCostGiB,
        [double]$MinimumPostStartMemoryGiB = -1,
        [double]$InstalledUsableMemoryGiB = 64,
        [double]$CommitLimitGiB = 64,
        [double]$CommittedGiB = 0,
        [bool]$ResourceExhaustion = $false,
        [bool]$VmAlreadyRunning = $false
    )
    if ($AvailableMemoryGiB -lt 0 -or $ExpectedVmStartCostGiB -lt 0 -or $InstalledUsableMemoryGiB -lt 0 -or $CommitLimitGiB -lt 0 -or $CommittedGiB -lt 0) {
        throw 'Host memory safety values must be non-negative.'
    }
    $physicalFloorGiB = [math]::Max(8.0, $InstalledUsableMemoryGiB * 0.10)
    $commitFloorGiB = [math]::Max(16.0, $CommitLimitGiB * 0.20)
    $effectiveStartCostGiB = if ($VmAlreadyRunning) { 0.0 } else { $ExpectedVmStartCostGiB }
    $projectedPostStartGiB = [math]::Round($AvailableMemoryGiB - $effectiveStartCostGiB, 2)
    $projectedCommitHeadroomGiB = [math]::Round($CommitLimitGiB - $CommittedGiB - $effectiveStartCostGiB, 2)
    $commitUsagePercent = if ($CommitLimitGiB -gt 0) { [math]::Round(($CommittedGiB / $CommitLimitGiB) * 100, 2) } else { 100 }
    [pscustomobject]@{
        policyVersion = '1.0.0'
        expectedVmStartCostGiB = [math]::Round($effectiveStartCostGiB, 2)
        projectedPostStartAvailableMemoryGiB = $projectedPostStartGiB
        physicalFloorGiB = [math]::Round($physicalFloorGiB, 2)
        commitHeadroomFloorGiB = [math]::Round($commitFloorGiB, 2)
        projectedCommitHeadroomGiB = $projectedCommitHeadroomGiB
        currentCommitUsagePercent = $commitUsagePercent
        resourceExhaustion = $ResourceExhaustion
        pagingPressureTelemetryOnly = $true
        startSafe = ($projectedPostStartGiB -ge $physicalFloorGiB -and $projectedCommitHeadroomGiB -ge $commitFloorGiB -and $commitUsagePercent -lt 80 -and -not $ResourceExhaustion)
    }
}

function Get-HostSafetySnapshot {
    param(
        [Parameter(Mandatory)][psobject]$Vm,
        [double]$MinimumAvailableMemoryGiB = -1,
        [double]$ExpectedVmStartCostGiB = -1
    )
    $os = Get-CimInstance Win32_OperatingSystem
    $memory = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
    $processor = Get-VMProcessor -VMName $Vm.Name
    $adapter = Get-VMNetworkAdapter -VMName $Vm.Name
    $availableMemoryGiB = [math]::Round([double]$memory.AvailableBytes / 1GB, 2)
    $totalMemoryGiB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $commitLimitGiB = [math]::Round([double]$memory.CommitLimit / 1GB, 2)
    $committedGiB = [math]::Round([double]$memory.CommittedBytes / 1GB, 2)
    if ($ExpectedVmStartCostGiB -lt 0) {
        $ExpectedVmStartCostGiB = [math]::Round([double]$Vm.MemoryStartup / 1GB, 2)
    }
    $resourceExhaustion = @(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Resource-Exhaustion-Detector'; StartTime=(Get-Date).AddMinutes(-10)} -ErrorAction SilentlyContinue).Count -gt 0
    $memorySafety = Get-ProjectedHostMemorySafety -AvailableMemoryGiB $availableMemoryGiB -ExpectedVmStartCostGiB $ExpectedVmStartCostGiB -InstalledUsableMemoryGiB $totalMemoryGiB -CommitLimitGiB $commitLimitGiB -CommittedGiB $committedGiB -ResourceExhaustion $resourceExhaustion -VmAlreadyRunning ($Vm.State.ToString() -eq 'Running')
    $production = @(Get-VM | Where-Object { $_.Name -in @('devfleet-primary','devfleet-project-m-techlabs-job-finder','MulattoTechSurface','MULATTOTECHBOX') } | ForEach-Object {
        [pscustomobject]@{ name=$_.Name; id=$_.Id.ToString(); state=$_.State.ToString(); memoryStartupBytes=[int64]$_.MemoryStartup }
    })
    [pscustomobject]@{
        host = $env:COMPUTERNAME
         availableMemoryGiB = $availableMemoryGiB
         availableBytes = [int64]$memory.AvailableBytes
         totalMemoryGiB = $totalMemoryGiB
         commitLimitGiB = $commitLimitGiB
         committedGiB = $committedGiB
         currentCommitUsagePercent = $memorySafety.currentCommitUsagePercent
         physicalFloorGiB = $memorySafety.physicalFloorGiB
         commitHeadroomFloorGiB = $memorySafety.commitHeadroomFloorGiB
         minimumPreferredGiB = $memorySafety.physicalFloorGiB
        expectedVmStartCostGiB = $memorySafety.expectedVmStartCostGiB
        projectedPostStartAvailableMemoryGiB = $memorySafety.projectedPostStartAvailableMemoryGiB
        minimumPostStartMemoryGiB = $memorySafety.physicalFloorGiB
        vm = [pscustomobject]@{
            name=$Vm.Name; id=$Vm.Id.ToString(); state=$Vm.State.ToString(); memoryStartupBytes=[int64]$Vm.MemoryStartup
            dynamicMemory=[bool]$Vm.DynamicMemoryEnabled; nestedVirtualization=[bool]$processor.ExposeVirtualizationExtensions
            macAddressSpoofing=$adapter.MacAddressSpoofing.ToString()
        }
        productionReadOnly=$production
         resourceExhaustion = $resourceExhaustion
         paging = [pscustomobject]@{ pagesPerSec=[double]$memory.PagesPerSec; pageReadsPerSec=[double]$memory.PageReadsPerSec; blockingGate=$false }
         startSafe = $memorySafety.startSafe
    }
}

function Assert-DisposableOwnership {
    param([Parameter(Mandatory)][psobject]$Vm,[string]$ExpectedId)
    if ($Vm.Name -notlike 'DevFleet-E2E-*') { throw "Ownership check failed for $($Vm.Name)." }
    if ($ExpectedId -and $Vm.Id.ToString() -ne $ExpectedId) { throw "VM identity mismatch: expected $ExpectedId, got $($Vm.Id)." }
    $true
}

function Confirm-PostStartHostMemorySafety {
    param(
        [Parameter(Mandatory)][psobject]$InitialSnapshot,
        [int]$SampleSeconds = 60,
        [int]$IntervalSeconds = 5
    )
    $samples = [System.Collections.Generic.List[object]]::new()
    $count = [math]::Max(1, [math]::Ceiling($SampleSeconds / [math]::Max(1, $IntervalSeconds)))
    for ($i = 0; $i -lt $count; $i++) {
        $memory = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
        $available = [math]::Round([double]$memory.AvailableBytes / 1GB, 2)
        $commitLimit = [math]::Round([double]$memory.CommitLimit / 1GB, 2)
        $committed = [math]::Round([double]$memory.CommittedBytes / 1GB, 2)
        $samples.Add([pscustomobject]@{ availableMemoryGiB=$available; commitLimitGiB=$commitLimit; committedGiB=$committed; commitUsagePercent=if($commitLimit -gt 0){[math]::Round($committed/$commitLimit*100,2)}else{100}; sampledAt=(Get-Date).ToUniversalTime().ToString('o') })
        if ($i -lt ($count - 1)) { Start-Sleep -Seconds ([math]::Max(1, $IntervalSeconds)) }
    }
    $floor = [double]$InitialSnapshot.physicalFloorGiB
    $commitFloor = [double]$InitialSnapshot.commitHeadroomFloorGiB
    $safe = @($samples | Where-Object { $_.availableMemoryGiB -lt $floor -or $_.commitUsagePercent -ge 80 -or ($_.commitLimitGiB - $_.committedGiB) -lt $commitFloor }).Count -eq 0
    [pscustomobject]@{ status=if($safe){'PASS'}else{'BLOCKED'}; sampleSeconds=$SampleSeconds; samples=$samples; physicalFloorGiB=$floor; commitHeadroomFloorGiB=$commitFloor; postStartSafe=$safe; resourceExhaustion=$false }
}

function Apply-RamPressureOverride {
    param([Parameter(Mandatory)][psobject]$Snapshot,[switch]$AllowRamPressure)
    $raw = [bool]$Snapshot.startSafe
    $resourceExhaustion = [bool]$Snapshot.resourceExhaustion
    $ramOnlyFailure = (-not $raw) -and (-not $resourceExhaustion)
    $authorized = [bool]$AllowRamPressure -and $ramOnlyFailure
    $Snapshot | Add-Member -NotePropertyName rawHostSafetyStartSafe -NotePropertyValue $raw -Force
    $Snapshot | Add-Member -NotePropertyName ramPressureOverrideAuthorized -NotePropertyValue $authorized -Force
    $Snapshot | Add-Member -NotePropertyName ramPressureOverrideScope -NotePropertyValue 'THIS OVERNIGHT DISPOSABLE E2E RUN ONLY' -Force
    $Snapshot | Add-Member -NotePropertyName nonRamSafetyPassed -NotePropertyValue (-not $resourceExhaustion) -Force
    $Snapshot | Add-Member -NotePropertyName effectiveE2EStartAuthorized -NotePropertyValue ($raw -or $authorized) -Force
    $Snapshot | Add-Member -NotePropertyName effectiveStartSafe -NotePropertyValue ($raw -or $authorized) -Force
    $Snapshot
}

Export-ModuleMember -Function Get-DisposableVm,Get-ProjectedHostMemorySafety,Get-HostSafetySnapshot,Confirm-PostStartHostMemorySafety,Apply-RamPressureOverride,Assert-DisposableOwnership
