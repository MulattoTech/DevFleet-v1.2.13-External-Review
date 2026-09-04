[CmdletBinding()]
param([string]$ConfigPath = 'C:\ProgramData\DevFleetHostAgent\config.json',[switch]$ValidateOnly,[switch]$LibraryOnly)

$ErrorActionPreference = 'Stop'

# Fixed structured operations exposed by this agent: 'ensure', 'start', 'stop',
# 'restart', 'inspect', 'health', 'backup', 'quarantine', 'restore', 'destroy',
# plus host 'capacity'. There is no arbitrary command execution endpoint.
$script:Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$script:Root = Split-Path -Parent $ConfigPath
$script:Token = (Get-Content -LiteralPath $script:Config.TokenPath -Raw).Trim()
function Resolve-TrustedHostExecutable {
    param([Parameter(Mandatory)][string[]]$Candidates)
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:WINDIR) | Where-Object { $_ } | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') + '\' }
    foreach ($candidate in $Candidates) {
        try {
            $full = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($candidate))
            if ((Test-Path -LiteralPath $full -PathType Leaf) -and -not ((Get-Item -LiteralPath $full -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -and @($roots | Where-Object { $full.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0) { return $full }
        } catch { continue }
    }
    throw 'No trusted machine executable matched the host-agent configuration.'
}
# Multipass resolves its Windows client certificate below LOCALAPPDATA.  The
# installer places the authenticated client in the SYSTEM profile because this
# agent runs as SYSTEM; keep the lookup explicit and host-portable.
if ($script:Config.MultipassClientCertificateRoot) {
    $env:LOCALAPPDATA = Split-Path -Parent ([string]$script:Config.MultipassClientCertificateRoot)
}
$script:Multipass = Resolve-TrustedHostExecutable @($script:Config.MultipassPath, (Join-Path $env:ProgramFiles 'Multipass\bin\multipass.exe'), (Join-Path ${env:ProgramFiles(x86)} 'Multipass\bin\multipass.exe'))
$script:RegistryPath = Join-Path $script:Root 'projects.json'
$script:LogPath = Join-Path $script:Root 'agent.jsonl'
$script:BackupRoot = Join-Path $script:Root 'backups'
$script:BackupVerificationCache = @{}
$script:ReconciliationRequired = $false
$script:AgentVersion = '2.5.0'
$script:VsCodeHelperPath = Join-Path $script:Root 'DevFleet-VSCode.ps1'
if (Test-Path -LiteralPath $script:VsCodeHelperPath -PathType Leaf) { . $script:VsCodeHelperPath }

if ($ValidateOnly) {
    if ([string]$script:Config.HostName -ne [string]$env:COMPUTERNAME) { throw "Host config identity mismatch: $($script:Config.HostName) vs $env:COMPUTERNAME" }
    if ((Get-Content -LiteralPath $script:Config.TokenPath -Raw).Trim().Length -lt 40) { throw 'Host-agent token is unexpectedly short.' }
    $policy = $script:Config.ResourcePolicy
    foreach ($name in 'PolicyVersion','PhysicalFloorMinGb','PhysicalFloorPercent','CommitHeadroomFloorMinGb','CommitHeadroomPercent','CommitUsageLimitPercent','ReservedLogicalProcessors','ReservedHostDiskGb','MaximumVmCount','MaximumParallelProvisioning','MaxProjectCpus','MaxProjectMemoryGb','MaxProjectDiskGb') {
        if ($null -eq $policy.$name) { throw "Resource policy is missing $name." }
    }
    [ordered]@{ok=$true;mode='validate-only';host_name=$script:Config.HostName;host_id=$script:Config.HostId;agent_version=$script:AgentVersion;provider='multipass';gpu_enabled=$false} | ConvertTo-Json -Compress
    exit 0
}

function Write-AgentLog {
    param([string]$Action,[string]$ProjectId = '',[string]$RuntimeId = '',[string]$State = 'info',[string]$Message = '')
    $entry = [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString('o')
        operation_id = [guid]::NewGuid().ToString()
        project_id = $ProjectId
        runtime_id = $RuntimeId
        host_id = [string]$script:Config.HostId
        provider = 'multipass'
        action = $Action
        result = $State
        message = $Message
    }
    ($entry | ConvertTo-Json -Compress) | Add-Content -LiteralPath $script:LogPath -Encoding UTF8
}

function Read-Registry {
    if (-not (Test-Path -LiteralPath $script:RegistryPath)) { return @{schema_version = 2; host_id = [string]$script:Config.HostId; projects = @{}} }
    try {
        $data = Get-Content -LiteralPath $script:RegistryPath -Raw | ConvertFrom-Json -AsHashtable
        if (-not $data.projects) { $data.projects = @{} }
        return $data
    } catch { throw 'Host agent registry is not valid JSON.' }
}

function Write-Registry {
    param([hashtable]$Data)
    $tmp = "$script:RegistryPath.$([guid]::NewGuid().ToString('N')).tmp"
    $json = $Data | ConvertTo-Json -Depth 20
    [IO.File]::WriteAllText($tmp, $json, (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $script:RegistryPath -Force
}

function Invoke-Multipass {
    param([Parameter(Mandatory)][string[]]$ArgumentList,[int]$TimeoutSeconds = 120)
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = [string]$script:Multipass
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    foreach ($arg in $ArgumentList) { [void]$psi.ArgumentList.Add([string]$arg) }
    $process = [Diagnostics.Process]::new();$process.StartInfo = $psi
    try {
        if (-not $process.Start()) { throw 'Unable to start the configured Multipass executable.' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync();$stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit([Math]::Max(1,$TimeoutSeconds) * 1000)) {
            try { $process.Kill($true) } catch {}
            try {[void]([Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]]@($stdoutTask,$stderrTask)).Wait([TimeSpan]::FromSeconds(5)))} catch {}
            $commandLabel=($ArgumentList|Select-Object -First 5)-join ' '
            throw "Multipass command timed out after $TimeoutSeconds seconds: $commandLabel"
        }
        $exitCode=$process.ExitCode
        $outputComplete=$false
        try {$outputComplete=[Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]]@($stdoutTask,$stderrTask)).Wait([TimeSpan]::FromSeconds(5))} catch {$outputComplete=$false}
        $stdout=if($stdoutTask.Status -eq [Threading.Tasks.TaskStatus]::RanToCompletion){$stdoutTask.GetAwaiter().GetResult()}else{''}
        $stderr=if($stderrTask.Status -eq [Threading.Tasks.TaskStatus]::RanToCompletion){$stderrTask.GetAwaiter().GetResult()}else{''}
        if (-not $outputComplete) { $commandLabel=($ArgumentList|Select-Object -First 5)-join ' ';throw "Multipass exited with code $exitCode, but redirected output was incomplete after the bounded post-exit drain: $commandLabel" }
        if ($exitCode -ne 0) { $detail = ($stderr + $stdout).Trim(); throw "Multipass failed ($exitCode): $detail" }
        return [pscustomobject]@{ExitCode=$exitCode;Text=(($stdout + "`n" + $stderr).Trim());OutputComplete=$true}
    } finally { $process.Dispose() }
}

function Assert-Slug { param([Parameter(Mandatory)][string]$Slug); if ($Slug -notmatch '^[a-z0-9][a-z0-9._-]{1,62}$') { throw 'Invalid project slug.' }; return $Slug.ToLowerInvariant() }
function Assert-ProjectId { param([Parameter(Mandatory)][string]$ProjectId); if ($ProjectId -notmatch '^[0-9a-fA-F-]{36}$') { throw 'Invalid project identifier.' }; return $ProjectId }
function Assert-BackupId { param([Parameter(Mandatory)][string]$BackupId);if($BackupId -notmatch '^[a-z0-9][a-z0-9._-]{1,159}$'){throw 'Invalid backup identifier.'};return $BackupId.ToLowerInvariant() }
function Get-Policy { return $script:Config.ResourcePolicy }

function New-VerifiedRemoteWorkspaceArchive {
    param(
        [Parameter(Mandatory)][string]$VmName,
        [Parameter(Mandatory)][string]$Archive,
        [Parameter(Mandatory)][string]$Slug,
        [bool]$IncludeGenerated = $false
    )
    $Slug=Assert-Slug $Slug
    if($Archive -notmatch '^/tmp/devfleet-(backup|export|import)-[a-z0-9._-]+\.tar\.gz$'){throw 'Remote workspace archive path is invalid.'}
    $workspace="/home/devrunner/workspaces/$Slug"
    $archiveScript=@'
import hashlib
import json
import sys
import tarfile
from pathlib import Path, PurePosixPath

archive, workspace, slug, include_generated = sys.argv[1:]
include_generated = include_generated.lower() == "true"
root = Path(workspace)
if not root.is_dir():
    raise SystemExit("workspace is missing")
excluded = {"node_modules", ".next", "build", "dist", ".venv", "venv", ".pytest_cache", "__pycache__", ".test-runtime"}
members = []

def archive_filter(info):
    name = info.name.replace("\\", "/")
    pure = PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts or not (name == slug or name.startswith(slug + "/")):
        raise SystemExit("unsafe workspace archive path")
    if not include_generated and any(part in excluded for part in pure.parts[1:]):
        return None
    if info.issym() or info.islnk() or info.isfifo() or info.isdev():
        raise SystemExit("workspace archive contains a link or special file")
    members.append(name)
    return info

with tarfile.open(archive, "w:gz") as bundle:
    bundle.add(root, arcname=slug, recursive=True, filter=archive_filter)
if not members:
    raise SystemExit("workspace archive is empty")
digest = hashlib.sha256()
with Path(archive).open("rb") as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)
digest = digest.hexdigest()
print(json.dumps({"archive_sha256": digest, "member_count": len(members)}))
'@
    $result=Invoke-Multipass @('exec',$VmName,'--','sudo','python3','-c',$archiveScript,$Archive,$workspace,$Slug,([string]$IncludeGenerated)) 1200
    try{$inspection=$result.Text|ConvertFrom-Json -AsHashtable}catch{throw 'Project VM did not return valid workspace archive verification JSON.'}
    if([string]$inspection.archive_sha256 -notmatch '^[0-9a-f]{64}$' -or [int]$inspection.member_count -lt 1){throw 'Project VM returned incomplete workspace archive verification.'}
    return $inspection
}

function Get-HostCapacity {
    $computer = Get-CimInstance Win32_ComputerSystem;$os = Get-CimInstance Win32_OperatingSystem
    $processor = Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfLogicalProcessors -Sum
    $drive = $env:SystemDrive.TrimEnd(':') + ':';$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$drive'"
    $registry = Read-Registry;$committedCpu = 0.0;$committedMemory = 0.0;$committedDisk = 0.0;$vmCount = 0
    foreach ($item in $registry.projects.Values) {
        if ($item.state -notin @('destroyed')) { $committedCpu += [double]$item.cpus;$committedMemory += [double]$item.memory_gb;$committedDisk += [double]$item.disk_gb;$vmCount++ }
    }
    $policy = Get-Policy
    $totalGb = [math]::Round($computer.TotalPhysicalMemory / 1GB, 2)
    $memory = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
    $availableGb = [math]::Round([double]$memory.AvailableBytes / 1GB, 2)
    $commitGb = 0.0; $commitLimitGb = 0.0
    try {
        $commitGb = [math]::Round((Get-Counter '\Memory\Committed Bytes' -MaxSamples 1 -ErrorAction Stop).CounterSamples.CookedValue / 1GB, 2)
        $commitLimitGb = [math]::Round((Get-Counter '\Memory\Commit Limit' -MaxSamples 1 -ErrorAction Stop).CounterSamples.CookedValue / 1GB, 2)
    } catch {}
    $diskFreeGb = [math]::Round($disk.FreeSpace / 1GB, 2)
    $reservedCpu = [double]$policy.ReservedLogicalProcessors
    $reservedDisk = [double]$policy.ReservedHostDiskGb
    $physicalFloor = [math]::Max([double]$policy.PhysicalFloorMinGb, $totalGb * [double]$policy.PhysicalFloorPercent)
    $commitFloor = [math]::Max([double]$policy.CommitHeadroomFloorMinGb, $commitLimitGb * [double]$policy.CommitHeadroomPercent)
    $commitPercent = if ($commitLimitGb -gt 0) { [math]::Round($commitGb / $commitLimitGb * 100, 2) } else { 100 }
    $resourceExhaustion = @()
    try { $resourceExhaustion = @(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-Resource-Exhaustion-Detector';StartTime=(Get-Date).AddMinutes(-10)} -ErrorAction SilentlyContinue) } catch {}
    $commitHeadroom = [math]::Max(0, $commitLimitGb - $commitGb)
    $physicalHealthy = $availableGb -ge $physicalFloor
    $commitHealthy = $commitHeadroom -ge $commitFloor -and $commitPercent -lt [double]$policy.CommitUsageLimitPercent
    $adaptiveHealthy = $physicalHealthy -and $commitHealthy -and @($resourceExhaustion).Count -eq 0
    $cpuPercent = 0.0
    try { $cpuPercent = [math]::Round((Get-Counter '\Processor(_Total)\% Processor Time' -MaxSamples 1 -ErrorAction Stop).CounterSamples.CookedValue, 1) } catch {}
    return [ordered]@{
        host_id = [string]$script:Config.HostId;host_name = [string]$script:Config.HostName;agent_version = $script:AgentVersion;provider = 'multipass';provider_version = [string]$script:Config.MultipassVersion
        resource_policy_version = [string]$policy.PolicyVersion;logical_cpus = [int]$processor.Sum;total_memory_gb = $totalGb;available_memory_gb = $availableGb;free_memory_gb = $availableGb;cpu_percent = $cpuPercent;disk_free_gb = $diskFreeGb
        physical_floor_gb = [math]::Round($physicalFloor, 2);commit_headroom_floor_gb = [math]::Round($commitFloor, 2);commit_gb = $commitGb;commit_limit_gb = $commitLimitGb;commit_headroom_gb = $commitHeadroom;commit_usage_percent = $commitPercent;resource_exhaustion = @($resourceExhaustion).Count -gt 0
        reserved_host_cpus = $reservedCpu;reserved_host_disk_gb = $reservedDisk
        committed_project_cpus = [math]::Round($committedCpu, 2);committed_project_memory_gb = [math]::Round($committedMemory, 2);committed_project_disk_gb = [math]::Round($committedDisk, 2);managed_vm_count = $vmCount
        allocatable_cpus = [math]::Max(0,[math]::Round([int]$processor.Sum - $reservedCpu - $committedCpu, 2))
        allocatable_memory_gb = [math]::Max(0,[math]::Round([math]::Min($availableGb - $physicalFloor, $commitHeadroom - $commitFloor), 2))
        allocatable_disk_gb = [math]::Max(0,[math]::Round($diskFreeGb - $reservedDisk - $committedDisk, 2))
        health = if (-not $adaptiveHealthy -or $diskFreeGb -lt $reservedDisk -or $cpuPercent -ge 95) { 'degraded' } else { 'healthy' }
    }
}

function Assert-HostCapacity {
    $capacity = Get-HostCapacity;$policy = Get-Policy
    if ($capacity.health -ne 'healthy') { throw 'Host capacity is temporarily below the configured safe threshold. No VM was created.' }
    if ([int]$capacity.managed_vm_count -ge [int]$policy.MaximumVmCount) { throw 'The maximum managed VM count has been reached.' }
    return $capacity
}

function Assert-ResourceRequest {
    param([double]$Cpus,[double]$MemoryGb,[double]$DiskGb)
    $policy = Get-Policy
    if ($Cpus -lt 1 -or $Cpus -gt [double]$policy.MaxProjectCpus) { throw 'Requested project CPU allocation exceeds host-agent policy.' }
    if ($MemoryGb -lt 2 -or $MemoryGb -gt [double]$policy.MaxProjectMemoryGb) { throw 'Requested project memory allocation exceeds host-agent policy.' }
    if ($DiskGb -lt 20 -or $DiskGb -gt [double]$policy.MaxProjectDiskGb) { throw 'Requested project disk allocation exceeds host-agent policy.' }
    $capacity = Assert-HostCapacity
    if ($Cpus -gt $capacity.allocatable_cpus -or $MemoryGb -gt $capacity.allocatable_memory_gb -or $DiskGb -gt $capacity.allocatable_disk_gb) { throw ('Insufficient host capacity. Available: {0} CPU, {1} GB RAM, {2} GB disk.' -f $capacity.allocatable_cpus,$capacity.allocatable_memory_gb,$capacity.allocatable_disk_gb) }
}

function Get-ProjectVmName {
    param([Parameter(Mandatory)][string]$Slug)
    $Slug = Assert-Slug $Slug;$base = "devfleet-project-$Slug"
    if ($base.Length -le 60) { return $base }
    $sha = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($Slug));$hash = (($sha | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0,12)
    return "devfleet-project-$($Slug.Substring(0,35))-$hash"
}

function Get-MultipassVms { $result = Invoke-Multipass @('list','--format','json') 30;try { return @((($result.Text | ConvertFrom-Json).list)) } catch { throw 'Multipass did not return valid VM inventory JSON.' } }
function Get-ProjectRecord { param([Parameter(Mandatory)][string]$Slug);$registry=Read-Registry;$key=(Assert-Slug $Slug).ToLowerInvariant();if(-not $registry.projects.ContainsKey($key)){throw 'Project VM is not registered with the DevFleet host agent.'};return $registry.projects[$key] }
function Get-ProjectSlugByRuntime { param([Parameter(Mandatory)][string]$RuntimeId);$registry=Read-Registry;foreach($entry in $registry.projects.GetEnumerator()){if([string]$entry.Value.runtime_id -eq $RuntimeId){return [string]$entry.Key}};throw 'Runtime identity is not registered with the DevFleet host agent.' }
function Assert-OwnedProjectVm { param([Parameter(Mandatory)][string]$Slug,[string]$RuntimeId='', [switch]$AllowStoppedTransition)
    $record=Get-ProjectRecord $Slug;$expected=Get-ProjectVmName $Slug
    if($record.vm_name -ne $expected -or $record.managed_by -ne 'devfleet' -or $record.host_id -ne $script:Config.HostId){throw 'Project VM ownership registry mismatch.'}
    if($RuntimeId -and $record.runtime_id -ne $RuntimeId){throw 'Runtime identity does not match the ownership registry.'}
    $inventory=@(Get-MultipassVms|Where-Object{$_.name -eq $record.vm_name});if($inventory.Count -ne 1){throw 'Registered project VM is missing or duplicated.'}
    $info=Get-ProjectVmInfo $record.vm_name
    if([string]$info.state -ne 'RUNNING'){
        if($AllowStoppedTransition){return $record}
        throw 'Live project VM ownership cannot be verified while the guest is stopped; refusing the operation.'
    }
    $runtimeText=(Invoke-Multipass @('exec',$record.vm_name,'--','sudo','cat','/etc/devfleet/project-runtime.json') 30).Text
    try{$runtime=$runtimeText|ConvertFrom-Json -AsHashtable}catch{throw 'Live project VM ownership document is missing or malformed.'}
    foreach($key in @('managed_by','project_id','slug','runtime_id','host_id','provisioning_attempt_id')){
        if([string]$runtime[$key] -ne [string]$record[$key]){throw "Live project VM ownership mismatch for $key; refusing the operation."}
    }
    return $record
}

function New-CloudInit {
    param([Parameter(Mandatory)][string]$Slug,[Parameter(Mandatory)][string]$ProjectId,[string]$GitUrl='', [Parameter(Mandatory)][string]$ProvisioningAttemptId)
    $Slug=Assert-Slug $Slug;$ProjectId=Assert-ProjectId $ProjectId
    if($GitUrl -and $GitUrl -notmatch '^(https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?|git@github\.com:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?)$'){throw 'Only GitHub repository URLs are accepted for VM bootstrap.'}
    $publicKeyPath=[string]$script:Config.SshPublicKeyPath
    if([string]::IsNullOrWhiteSpace($publicKeyPath) -or -not(Test-Path -LiteralPath $publicKeyPath -PathType Leaf)){throw 'Configured DevFleet SSH public key is not available for project VM provisioning.'}
    $key=(Get-Content -LiteralPath $publicKeyPath -Raw).Trim()
    if([string]::IsNullOrWhiteSpace($key) -or $key -match "['\r\n]"){throw 'Configured DevFleet SSH public key is invalid.'}
    $keyProperty="    ssh_authorized_keys:`n      - '$key'"
    $workspace="/home/devrunner/workspaces/$Slug";$cloneLine="mkdir -p '$workspace'";if($GitUrl){$cloneLine="git clone --depth 1 '$GitUrl' '$workspace'"}
    $cloud=@"
#cloud-config
package_update: true
packages:
  - openssh-server
  - git
  - curl
  - ca-certificates
  - docker.io
  - docker-compose-v2
users:
  - default
  - name: devrunner
    groups: [users]
    shell: /bin/bash
$keyProperty
write_files:
  - path: /etc/devfleet/project-runtime.json
    permissions: !!str 0644
    content: |
      {"managed_by":"devfleet","project_id":"$ProjectId","slug":"$Slug","runtime_id":"$(Get-ProjectVmName $Slug)","host_id":"$($script:Config.HostId)","provisioning_attempt_id":"$ProvisioningAttemptId","bootstrap_version":"1","gpu_enabled":false}
  - path: /usr/local/sbin/devfleet-project-health
    permissions: !!str 0755
    content: |
      #!/usr/bin/env bash
      set -eu
      test -f /etc/devfleet/project-runtime.json
      test -d /home/devrunner/workspaces/$Slug
      docker --version >/dev/null
      docker compose version >/dev/null
runcmd:
  - [ bash, -lc, "$cloneLine" ]
  - [ bash, -lc, "mkdir -p /home/devrunner/workspaces/$Slug && chown -R devrunner:devrunner /home/devrunner/workspaces/$Slug" ]
  - [ systemctl, enable, --now, ssh ]
  - [ systemctl, enable, --now, docker ]
"@
    return $cloud
}

function Get-ProjectVmInfo { param([Parameter(Mandatory)][string]$VmName);$result=Invoke-Multipass @('info',$VmName,'--format','json') 30;try{$data=$result.Text|ConvertFrom-Json;if($data.info.$VmName){return $data.info.$VmName};return $data}catch{throw 'Multipass did not return valid project VM information.'} }
function Get-PrimaryProjectVmIpv4 {
    param([Parameter(Mandatory)]$Info)
    if([string]$Info.state -ne 'RUNNING'){throw 'Project VM is not running; its address is unavailable.'}
    $candidates=@($Info.ipv4|Where-Object{$_ -match '^\d{1,3}(?:\.\d{1,3}){3}$' -and $_ -notmatch '^(127\.|169\.254\.|172\.(17|18|19)\.)'})
    if($candidates.Count -eq 0){throw 'Running project VM did not report a guest-reachable primary IPv4 address.'}
    return [string]$candidates[0]
}
function Wait-ProjectVmReady { param([Parameter(Mandatory)][string]$VmName)
    $deadline=(Get-Date).AddSeconds([int]$script:Config.BootTimeoutSeconds)
    $attempt=0
    while((Get-Date)-lt $deadline){
        $attempt++;$remaining=[math]::Max(0,($deadline-(Get-Date)).TotalSeconds);$info=$null
        try {
            $info=Invoke-Multipass @('info',$VmName,'--format','json') 30
            if($info.Text -match 'RUNNING'){
                try{$health=Invoke-Multipass @('exec',$VmName,'--','sudo','/usr/local/sbin/devfleet-project-health') 30;if($health.ExitCode -eq 0){return $true};Write-AgentLog 'readiness' '' $VmName 'waiting' "Project VM health probe returned exit $($health.ExitCode); $([math]::Round($remaining,1)) seconds remain."}catch{Write-AgentLog 'readiness' '' $VmName 'waiting' "Project VM health probe failed on attempt $attempt; $([math]::Round($remaining,1)) seconds remain."}
            } else {Write-AgentLog 'readiness' '' $VmName 'waiting' "Project VM is not RUNNING on attempt $attempt; $([math]::Round($remaining,1)) seconds remain."}
        } catch {Write-AgentLog 'readiness' '' $VmName 'waiting' "Project VM readiness inventory failed on attempt $attempt; $([math]::Round($remaining,1)) seconds remain."}
        $remaining=[math]::Max(0,($deadline-(Get-Date)).TotalSeconds);if($remaining -le 0){break};Start-Sleep -Seconds ([int][math]::Min(5,[math]::Max(1,$remaining)))
    }
    throw "Project VM did not become ready within $($script:Config.BootTimeoutSeconds) seconds."
}

function Import-ProjectWorkspace {
    param([Parameter(Mandatory)][string]$Slug,[Parameter(Mandatory)][string]$RuntimeId,[Parameter(Mandatory)][string]$SourceVm,[Parameter(Mandatory)][string]$ProjectId)
    $Slug=Assert-Slug $Slug;$ProjectId=Assert-ProjectId $ProjectId;$record=Assert-OwnedProjectVm $Slug $RuntimeId
    if([string]$record.project_id -ne $ProjectId){throw 'Project identifier does not match the target VM ownership registry.'}
    if($SourceVm -notmatch '^devfleet-[a-z0-9][a-z0-9._-]{1,62}$'){throw 'Workspace imports are limited to a DevFleet source VM.'}
    if($SourceVm -eq $record.vm_name){throw 'The source VM and target project VM must be different.'}
    $lock=New-ProvisioningLock
    $sourceArchive='';$localArchive='';$importRoot="/home/devrunner/workspaces/.devfleet-import-$([guid]::NewGuid().ToString('N'))"
    try {
        $sourceInventory=@(Get-MultipassVms|Where-Object{$_.name -eq $SourceVm});if($sourceInventory.Count -ne 1){throw 'The DevFleet source VM is missing or duplicated.'}
        if([string]$sourceInventory[0].state -ne 'RUNNING'){throw 'The DevFleet source VM must already be running; the import will not start or stop it.'}
        $targetInfo=Get-ProjectVmInfo $record.vm_name;if([string]$targetInfo.state -ne 'RUNNING'){throw 'The target project VM is not running.'}
        $sourcePath="/home/devrunner/workspaces/$Slug";$archiveName="devfleet-import-$Slug-$([guid]::NewGuid().ToString('N')).tar.gz";$sourceArchive="/tmp/$archiveName";$imports=Join-Path $script:Root 'imports';New-Item -ItemType Directory -Force -Path $imports|Out-Null;$localArchive=Join-Path $imports $archiveName
        Invoke-Multipass @('exec',$SourceVm,'--','sudo','test','-d',$sourcePath) 30|Out-Null
        Invoke-Multipass @('exec',$SourceVm,'--','sudo','tar','-czf',$sourceArchive,'-C','/home/devrunner/workspaces',$Slug) 600|Out-Null
        $archiveValidator=@'
import hashlib
import json
import sys
import tarfile
from pathlib import PurePosixPath

archive, slug = sys.argv[1:]
names = []
with tarfile.open(archive, "r:gz") as bundle:
    for member in bundle.getmembers():
        name = member.name.replace("\\", "/")
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or "\x00" in name or not (name == slug or name.startswith(slug + "/")):
            raise SystemExit("unsafe archive path")
        if member.issym() or member.islnk() or member.isdev() or not (member.isdir() or member.isfile()):
            raise SystemExit("unsupported archive member type")
        if member.mode & 0o7000:
            raise SystemExit("unsafe archive mode")
        names.append(name)
    if slug not in names or slug + "/.devfleet/project.json" not in names:
        raise SystemExit("archive root or project metadata is missing")
digest = hashlib.sha256()
with open(archive, "rb") as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)
print(json.dumps({"archive_sha256": digest.hexdigest(), "member_count": len(names)}))
'@
        $sourceValidationText=(Invoke-Multipass @('exec',$SourceVm,'--','sudo','python3','-c',$archiveValidator,$sourceArchive,$Slug) 180).Text
        try{$sourceValidation=$sourceValidationText|ConvertFrom-Json -AsHashtable}catch{throw 'Source VM archive validator did not return structured JSON.'}
        if([string]$sourceValidation.archive_sha256 -notmatch '^[0-9a-f]{64}$' -or [int]$sourceValidation.member_count -lt 2){throw 'Source VM archive failed structured validation.'}
        Invoke-Multipass @('transfer',"${SourceVm}:$sourceArchive",$localArchive) 600|Out-Null
        if(-not(Test-Path -LiteralPath $localArchive)){throw 'The host did not receive the workspace archive.'}
        $digest=(Get-FileHash -LiteralPath $localArchive -Algorithm SHA256).Hash.ToLowerInvariant()
        if($digest -ne [string]$sourceValidation.archive_sha256){throw 'Host archive hash does not match the immutable source validation hash.'}
        Invoke-Multipass @('transfer',$localArchive,"$($record.vm_name):$sourceArchive") 600|Out-Null
        $targetDigest=((Invoke-Multipass @('exec',$record.vm_name,'--','sha256sum',$sourceArchive) 60).Text -split '\s+')[0].ToLowerInvariant()
        if($targetDigest -ne $digest){throw 'Workspace archive integrity verification failed on the target VM.'}
        $targetValidationText=(Invoke-Multipass @('exec',$record.vm_name,'--','sudo','python3','-c',$archiveValidator,$sourceArchive,$Slug) 180).Text
        try{$targetValidation=$targetValidationText|ConvertFrom-Json -AsHashtable}catch{throw 'Target VM archive validator did not return structured JSON.'}
        if([string]$targetValidation.archive_sha256 -ne $digest){throw 'Target VM archive validation hash differs from the transferred archive.'}
        Invoke-Multipass @('exec',$record.vm_name,'--','sudo','mkdir','-p',$importRoot) 30|Out-Null
        Invoke-Multipass @('exec',$record.vm_name,'--','sudo','tar','-xzf',$sourceArchive,'-C',$importRoot,'--no-same-owner','--no-same-permissions') 600|Out-Null
        Invoke-Multipass @('exec',$record.vm_name,'--','sudo','test','-d',"$importRoot/$Slug") 30|Out-Null
        $targetPath="/home/devrunner/workspaces/$Slug";$existing=(Invoke-Multipass @('exec',$record.vm_name,'--','sudo','find',$targetPath,'-mindepth','1','-maxdepth','1','-print') 30).Text.Trim();if($existing){throw 'Target workspace is not empty; import refused to avoid overwriting data.'}
        Invoke-Multipass @('exec',$record.vm_name,'--','sudo','rmdir',$targetPath) 30|Out-Null
        Invoke-Multipass @('exec',$record.vm_name,'--','sudo','mv',"$importRoot/$Slug",$targetPath) 30|Out-Null
        Invoke-Multipass @('exec',$record.vm_name,'--','sudo','rmdir',$importRoot) 30|Out-Null
        Invoke-Multipass @('exec',$record.vm_name,'--','sudo','chown','-R','devrunner:devrunner',$targetPath) 120|Out-Null
        Invoke-Multipass @('exec',$record.vm_name,'--','sudo','test','-f',"$targetPath/.devfleet/project.json") 30|Out-Null
        $record.import_state='verified';$record.import_archive_sha256=$digest;$record.import_source_vm=$SourceVm;$record.imported_at=(Get-Date).ToUniversalTime().ToString('o');$record.updated_at=$record.imported_at;Update-ProjectRecord $Slug $record|Out-Null
        Write-AgentLog 'import' $record.project_id $record.runtime_id 'ready' "Existing workspace imported from $SourceVm with verified archive $digest."
        return [ordered]@{ok=$true;host_name=$script:Config.HostName;runtime_id=$record.runtime_id;vm_name=$record.vm_name;source_vm=$SourceVm;archive_sha256=$digest;target_archive_sha256=$targetDigest;workspace_preserved=$true;state='ready';message='Existing workspace imported into the dedicated VM.'}
    } finally {
        Remove-Item -LiteralPath $localArchive -Force -ErrorAction SilentlyContinue
        if($sourceArchive){try { Invoke-Multipass @('exec',$SourceVm,'--','sudo','rm','-f',$sourceArchive) 30|Out-Null } catch {}}
        if($sourceArchive){try { Invoke-Multipass @('exec',$record.vm_name,'--','sudo','rm','-f',$sourceArchive) 30|Out-Null } catch {}}
        try { Invoke-Multipass @('exec',$record.vm_name,'--','sudo','rm','-rf',$importRoot) 30|Out-Null } catch {}
        try {$lock.ReleaseMutex()}catch{};$lock.Dispose()
    }
}

function New-RegistryLock {
    $mutex=[Threading.Mutex]::new($false,'Global\DevFleetHostAgent-Registry')
    try { $acquired=$mutex.WaitOne(30000) }
    catch [Threading.AbandonedMutexException] { Write-AgentLog 'registry-lock' '' '' 'recovery-required' 'An abandoned registry mutex was recovered; exact live ownership reconciliation is required.'; $script:ReconciliationRequired=$true; $acquired=$true }
    if(-not $acquired){$mutex.Dispose();throw 'Host agent registry is busy; retry the operation.'}
    if($script:ReconciliationRequired){
        $registry=Read-Registry
        foreach($entry in $registry.projects.GetEnumerator()){
            if([string]$entry.Value.state -eq 'destroyed'){continue}
            $null=Assert-OwnedProjectVm ([string]$entry.Key) ([string]$entry.Value.runtime_id)
        }
        $script:ReconciliationRequired=$false
        Write-AgentLog 'registry-reconciliation' '' '' 'reconciled' 'Abandoned registry lock state was re-read and every active project VM passed exact live ownership verification.'
    }
    return $mutex
}
function Invoke-RegistryTransaction {
    param([Parameter(Mandatory)][scriptblock]$Mutation)
    $lock=New-RegistryLock
    try { $registry=Read-Registry; $result=& $Mutation $registry; Write-Registry $registry; return $result }
    finally { try{$lock.ReleaseMutex()}catch{};$lock.Dispose() }
}
function Update-ProjectRecord { param([Parameter(Mandatory)][string]$Slug,[Parameter(Mandatory)]$Record);$key=(Assert-Slug $Slug).ToLowerInvariant();Invoke-RegistryTransaction { param($registry);$registry.projects[$key]=$Record;return $Record } }
function Remove-ProvisionalProjectRecord {
    param([Parameter(Mandatory)][string]$Slug,[Parameter(Mandatory)][string]$ProjectId,[Parameter(Mandatory)][string]$ProvisioningAttemptId)
    $key=(Assert-Slug $Slug).ToLowerInvariant()
    Invoke-RegistryTransaction { param($registry);if($registry.projects.ContainsKey($key)){ $record=$registry.projects[$key]; if([string]$record.project_id -eq $ProjectId -and [string]$record.provisioning_attempt_id -eq $ProvisioningAttemptId){$registry.projects.Remove($key);return $true} };return $false }
}
function New-ProvisioningLock {
    $mutex=[Threading.Mutex]::new($false,'Global\DevFleetHostAgent-Provisioning')
    try { $acquired=$mutex.WaitOne(1000) }
    catch [Threading.AbandonedMutexException] {
        Write-AgentLog 'provisioning-lock' '' '' 'recovery-required' 'An abandoned provisioning mutex was recovered; state reconciliation is required before continuing.'
        $script:ReconciliationRequired=$true
        $acquired=$true
    }
    if(-not $acquired){ $mutex.Dispose();throw 'Another project VM provisioning operation is already active.' }
    if($script:ReconciliationRequired){
        $registry=Read-Registry
        foreach($entry in $registry.projects.GetEnumerator()){
            if([string]$entry.Value.state -eq 'destroyed'){continue}
            $null=Assert-OwnedProjectVm ([string]$entry.Key) ([string]$entry.Value.runtime_id)
        }
        $script:ReconciliationRequired=$false
        Write-AgentLog 'provisioning-reconciliation' '' '' 'reconciled' 'Abandoned provisioning lock state was re-read and every active project VM passed exact live ownership verification.'
    }
    return $mutex
}
function Remove-PartiallyCreatedProjectVm {
    param([Parameter(Mandatory)][string]$Slug,[Parameter(Mandatory)]$Record,[Parameter(Mandatory)]$Attempt)
    try {
        if(-not [bool]$Attempt.launch_succeeded){Write-AgentLog 'create-cleanup' ([string]$Record.project_id) ([string]$Record.runtime_id) 'skipped' 'Provisioning launch did not succeed; cleanup is forbidden because a same-named runtime may be foreign.';return}
        $vmName=Get-ProjectVmName $Slug
        $inventory=@(Get-MultipassVms|Where-Object{$_.name -eq $vmName})
        if($inventory.Count -ne 1){return}
        $runtimeText=(Invoke-Multipass @('exec',$vmName,'--','sudo','cat','/etc/devfleet/project-runtime.json') 30).Text
        try{$runtimeMeta=$runtimeText|ConvertFrom-Json -AsHashtable}catch{Write-AgentLog 'create-cleanup' ([string]$Record.project_id) ([string]$Record.runtime_id) 'skipped' 'Runtime identity proof was unavailable; cleanup was forbidden.';return}
        if([string]$runtimeMeta.managed_by -ne 'devfleet' -or [string]$runtimeMeta.project_id -ne [string]$Record.project_id -or [string]$runtimeMeta.slug -ne $Slug -or [string]$runtimeMeta.runtime_id -ne [string]$Record.runtime_id -or [string]$runtimeMeta.host_id -ne [string]$script:Config.HostId -or [string]$runtimeMeta.provisioning_attempt_id -ne [string]$Attempt.provisioning_attempt_id){Write-AgentLog 'create-cleanup' ([string]$Record.project_id) ([string]$Record.runtime_id) 'skipped' 'Exact provisioning attempt/runtime ownership proof failed; cleanup was forbidden.';return}
        $info=Get-ProjectVmInfo $vmName
        if([string]$info.state -eq 'RUNNING'){Invoke-Multipass @('stop',$vmName) 120|Out-Null}
        Invoke-Multipass @('delete',$vmName,'--purge') 600|Out-Null
        if(@(Get-MultipassVms|Where-Object{$_.name -eq $vmName}).Count -ne 0){throw 'Multipass still reports the partially-created project VM after cleanup.'}
        Write-AgentLog 'create-cleanup' $Record.project_id $Record.runtime_id 'cleaned' 'Removed a project VM left behind by a failed first-time provisioning attempt.'
    } catch {
        Write-AgentLog 'create-cleanup' ([string]$Record.project_id) ([string]$Record.runtime_id) 'cleanup-failed' $_.Exception.Message
    }
}

function Ensure-ProjectVm {
    param([Parameter(Mandatory)][string]$Slug,[Parameter(Mandatory)][string]$ProjectId,[Parameter(Mandatory)][double]$Cpus,[Parameter(Mandatory)][double]$MemoryGb,[Parameter(Mandatory)][double]$DiskGb,[string]$GitUrl='')
    $Slug=Assert-Slug $Slug;$ProjectId=Assert-ProjectId $ProjectId;$vmName=Get-ProjectVmName $Slug;$registry=Read-Registry;$key=$Slug.ToLowerInvariant();$inventory=@(Get-MultipassVms|Where-Object{$_.name -eq $vmName});$existing=$null;if($registry.projects.ContainsKey($key)){$existing=$registry.projects[$key]}
    if($existing -and $existing.project_id -ne $ProjectId){throw 'Project identifier does not match the host ownership registry.'}
    if(-not $existing -and $inventory.Count -gt 0){throw 'A VM with the deterministic project name exists but is not DevFleet-owned.'}
    if($inventory.Count -gt 1){throw 'Duplicate deterministic project VMs detected.'}
    if($inventory.Count -eq 1){$record=Assert-OwnedProjectVm $Slug -AllowStoppedTransition;if($record.cpus -ne $Cpus -or $record.memory_gb -ne $MemoryGb -or $record.disk_gb -ne $DiskGb){throw 'Existing project VM resources do not match persisted allocation; resize is not automatic.'};$info=Get-ProjectVmInfo $vmName;if([string]$info.state -ne 'RUNNING'){Invoke-Multipass @('start',$vmName) 120|Out-Null;Wait-ProjectVmReady $vmName|Out-Null};return Refresh-ProjectVmConnectionState $Slug $record}
    $lock=New-ProvisioningLock
    try {
        # Discovery before the mutex is only advisory.  Re-read after locking
        # so a same-name runtime created by another process is never adopted.
        $registry=Read-Registry;$inventory=@(Get-MultipassVms|Where-Object{$_.name -eq $vmName});$existing=$null;if($registry.projects.ContainsKey($key)){$existing=$registry.projects[$key]}
        if($existing -and [string]$existing.project_id -ne $ProjectId){throw 'Project identifier does not match the host ownership registry.'}
        if(-not $existing -and $inventory.Count -gt 0){throw 'A VM with the deterministic project name exists but is not DevFleet-owned.'}
        if($inventory.Count -gt 1){throw 'Duplicate deterministic project VMs detected.'}
        Assert-ResourceRequest $Cpus $MemoryGb $DiskGb
        $runtimeId=$vmName;$attemptId=[guid]::NewGuid().ToString();$attempt=[ordered]@{provisioning_attempt_id=$attemptId;project_id=$ProjectId;runtime_id=$runtimeId;host_id=[string]$script:Config.HostId;launch_succeeded=$false};$launchSucceeded=$false;$record=[ordered]@{managed_by='devfleet';host_id=$script:Config.HostId;project_id=$ProjectId;slug=$Slug;runtime_id=$runtimeId;vm_name=$vmName;provisioning_attempt_id=$attemptId;cpus=$Cpus;memory_gb=$MemoryGb;disk_gb=$DiskGb;state='creating';address='';gpu_enabled=$false;gpu_passthrough=$false;created_at=(Get-Date).ToUniversalTime().ToString('o');updated_at=(Get-Date).ToUniversalTime().ToString('o');git_url=$GitUrl}
        Update-ProjectRecord $Slug $record|Out-Null;Write-AgentLog 'create' $ProjectId $runtimeId 'creating' 'Creating owned GPU-free project VM.';$cloudPath=Join-Path $script:Root "$vmName.cloud-init.yaml"
        try { New-CloudInit $Slug $ProjectId $GitUrl $attemptId | Set-Content -LiteralPath $cloudPath -Encoding UTF8;Invoke-Multipass @('launch',$script:Config.UbuntuImage,'--name',$vmName,'--cpus',[string]$Cpus,'--memory',"${MemoryGb}G",'--disk',"${DiskGb}G",'--cloud-init',$cloudPath) 1200|Out-Null;$launchSucceeded=$true;$attempt.launch_succeeded=$true;$record.state='booting';$record.updated_at=(Get-Date).ToUniversalTime().ToString('o');Update-ProjectRecord $Slug $record|Out-Null;Wait-ProjectVmReady $vmName|Out-Null;$refreshed=Refresh-ProjectVmConnectionState $Slug $record;Write-AgentLog 'create' $ProjectId $runtimeId 'ready' 'Project VM bootstrap health passed and connection state reconciled.';return $refreshed }
        catch { $errorMessage=$_.Exception.Message;Remove-PartiallyCreatedProjectVm $Slug $record $attempt;if(-not $launchSucceeded){Remove-ProvisionalProjectRecord $Slug $ProjectId $attemptId|Out-Null}else{$record.state='failed';$record.error=$errorMessage;$record.updated_at=(Get-Date).ToUniversalTime().ToString('o');Update-ProjectRecord $Slug $record|Out-Null};Write-AgentLog 'create' $ProjectId $runtimeId 'failed' $errorMessage;throw }
        finally { if(Test-Path -LiteralPath $cloudPath){Remove-Item -LiteralPath $cloudPath -Force -ErrorAction SilentlyContinue} }
    } finally { try{$lock.ReleaseMutex()}catch{};$lock.Dispose() }
}

function Backup-ProjectVm { param([Parameter(Mandatory)]$Record,[bool]$IncludeGenerated=$false)
    New-Item -ItemType Directory -Force -Path $script:BackupRoot | Out-Null
    $slug=Assert-Slug ([string]$Record.slug);$backupId="$slug-$((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'))-$([guid]::NewGuid().ToString('N').Substring(0,8))";$archivePath=Join-Path $script:BackupRoot "$backupId.tar.gz";$manifestPath=Join-Path $script:BackupRoot "$backupId.json";$remoteArchive="/tmp/devfleet-backup-$([guid]::NewGuid().ToString('N')).tar.gz";$workspace="/home/devrunner/workspaces/$slug"
    try {
        $archiveInspection=New-VerifiedRemoteWorkspaceArchive $Record.vm_name $remoteArchive $slug $IncludeGenerated
        $sourceArchiveHash=[string]$archiveInspection.archive_sha256
        Invoke-Multipass @('transfer',"$($Record.vm_name):$remoteArchive",$archivePath) 1200|Out-Null
        if(-not(Test-Path -LiteralPath $archivePath)){throw 'Host did not receive the workspace backup archive.'}
        $archiveHash=(Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if($archiveHash -ne $sourceArchiveHash){throw 'Workspace backup archive SHA-256 differs between the project VM and host.'}
        $manifest=[ordered]@{schema_version=1;backup_id=$backupId;created_at=(Get-Date).ToUniversalTime().ToString('o');host_id=$script:Config.HostId;provider='multipass';project_id=$Record.project_id;slug=$slug;runtime_id=$Record.runtime_id;vm_name=$Record.vm_name;archive_path=$archivePath;archive_sha256=$archiveHash;source_archive_sha256=$sourceArchiveHash;host_archive_sha256=$archiveHash;archive_bytes=(Get-Item -LiteralPath $archivePath).Length;verification='verified';consistency_level=if($IncludeGenerated){'quiesced'}else{'live-best-effort'};gpu_enabled=$false};$json=$manifest|ConvertTo-Json -Depth 20;[IO.File]::WriteAllText($manifestPath,$json,(New-Object Text.UTF8Encoding($false)));$manifestHash=(Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant();$reference=[ordered]@{provider='multipass-host-agent';backup_id=$backupId;project_id=$Record.project_id;slug=$slug;runtime_id=$Record.runtime_id;host_id=$script:Config.HostId;archive_sha256=$archiveHash;archive_bytes=$manifest.archive_bytes;manifest_sha256=$manifestHash;created_at=$manifest.created_at;consistency_level=$manifest.consistency_level};Write-AgentLog 'backup' $Record.project_id $Record.runtime_id 'verified' "Workspace archive $backupId verified with equal source and host SHA-256.";return [ordered]@{ok=$true;backup_status='verified';backup_id=$backupId;backup_sha256=$archiveHash;manifest_sha256=$manifestHash;archive_bytes=$manifest.archive_bytes;backup_reference=$reference;runtime_id=$Record.runtime_id;host_name=$script:Config.HostName;host_id=$script:Config.HostId;project_id=$Record.project_id}
    } finally {if($remoteArchive){try{Invoke-Multipass @('exec',$Record.vm_name,'--','sudo','rm','-f',$remoteArchive) 30|Out-Null}catch{}}}
}

function Get-VerifiedProjectBackup {
    param([Parameter(Mandatory)]$Record,[Parameter(Mandatory)][string]$BackupId)
    $BackupId=Assert-BackupId $BackupId
    $manifestPath=Join-Path $script:BackupRoot "$BackupId.json"
    if(-not(Test-Path -LiteralPath $manifestPath -PathType Leaf)){throw 'The requested backup manifest is not present on the host.'}
    try{$manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json -AsHashtable}catch{throw 'The requested backup manifest is not valid JSON.'}
    if([string]$manifest.backup_id -ne $BackupId -or [string]$manifest.project_id -ne [string]$Record.project_id -or [string]$manifest.slug -ne [string]$Record.slug -or [string]$manifest.runtime_id -ne [string]$Record.runtime_id){throw 'Backup manifest identity does not match this project VM.'}
    $backupRootFull=[IO.Path]::GetFullPath($script:BackupRoot).TrimEnd('\')+'\'
    $archivePath=[IO.Path]::GetFullPath([string]$manifest.archive_path)
    if(-not $archivePath.StartsWith($backupRootFull,[StringComparison]::OrdinalIgnoreCase) -or -not(Test-Path -LiteralPath $archivePath -PathType Leaf)){throw 'Backup archive is missing or outside the host backup root.'}
    $expected=[string]$manifest.archive_sha256
    if($expected -notmatch '^[0-9a-f]{64}$' -or [string]$manifest.source_archive_sha256 -ne $expected -or [string]$manifest.host_archive_sha256 -ne $expected){throw 'Backup manifest does not prove equal source and host SHA-256 values.'}
    $actual=(Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if($actual -ne $expected){throw 'Workspace backup archive hash no longer matches its verified manifest.'}
    $manifestHash=(Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant();return [ordered]@{backup_id=$BackupId;backup_sha256=$actual;archive_bytes=(Get-Item -LiteralPath $archivePath).Length;backup_reference=[ordered]@{provider='multipass-host-agent';backup_id=$BackupId;project_id=$Record.project_id;slug=$Record.slug;runtime_id=$Record.runtime_id;host_id=$script:Config.HostId;archive_sha256=$actual;archive_bytes=(Get-Item -LiteralPath $archivePath).Length;manifest_sha256=$manifestHash;created_at=[string]$manifest.created_at;consistency_level=[string]$manifest.consistency_level};manifest=$manifest}
}

function Get-ProjectVmBackups {
    param([Parameter(Mandatory)]$Record)
    New-Item -ItemType Directory -Force -Path $script:BackupRoot|Out-Null
    $items=@()
    foreach($manifestPath in @(Get-ChildItem -LiteralPath $script:BackupRoot -Filter '*.json' -File|Sort-Object LastWriteTimeUtc -Descending)){
        try{$raw=Get-Content -LiteralPath $manifestPath.FullName -Raw|ConvertFrom-Json -AsHashtable}catch{continue}
        if([string]$raw.project_id -ne [string]$Record.project_id -or [string]$raw.slug -ne [string]$Record.slug -or [string]$raw.runtime_id -ne [string]$Record.runtime_id){continue}
        $backupId=[string]$raw.backup_id
        try{
            $archivePath=[string]$raw.archive_path;$archiveInfo=Get-Item -LiteralPath $archivePath -Force;$manifestHash=(Get-FileHash -LiteralPath $manifestPath.FullName -Algorithm SHA256).Hash.ToLowerInvariant();$cacheKey="$backupId|$manifestHash|$($archiveInfo.Length)|$($archiveInfo.LastWriteTimeUtc.Ticks)|$([string]$raw.archive_sha256)"
            if($script:BackupVerificationCache.ContainsKey($cacheKey)){$verified=$script:BackupVerificationCache[$cacheKey]}else{$verified=Get-VerifiedProjectBackup $Record $backupId;$script:BackupVerificationCache[$cacheKey]=$verified}
            $items += [ordered]@{backup_id=$backupId;created_at=[string]$raw.created_at;provider='multipass-host-agent';runtime_id=[string]$Record.runtime_id;archive_bytes=$verified.archive_bytes;archive_sha256=$verified.backup_sha256;sha_verified=$true;restore_eligible=$true;reason='';status='eligible';backup_reference=$verified.backup_reference}
        }catch{$items += [ordered]@{backup_id=$backupId;created_at=[string]$raw.created_at;provider='multipass-host-agent';runtime_id=[string]$Record.runtime_id;archive_bytes=[int64]($raw.archive_bytes -as [int64]);archive_sha256=[string]$raw.archive_sha256;sha_verified=$false;restore_eligible=$false;reason=$_.Exception.Message;status='invalid'}}
    }
    return @($items)
}

function Restore-ProjectVmBackup {
    param([Parameter(Mandatory)]$Record,[Parameter(Mandatory)][string]$BackupId,[Parameter(Mandatory)][bool]$ConfirmRestore)
    if(-not $ConfirmRestore){throw 'Backup restore requires explicit confirmation.'}
    $verified=Get-VerifiedProjectBackup $Record $BackupId
    $vmName=[string]$Record.vm_name;$slug=Assert-Slug ([string]$Record.slug);$workspace="/home/devrunner/workspaces/$slug"
    $info=Get-ProjectVmInfo $vmName
    if([string]$info.state -ne 'RUNNING'){Invoke-Multipass @('start',$vmName) 120|Out-Null;Wait-ProjectVmReady $vmName|Out-Null}
    $safety=Backup-ProjectVm $Record
    $nonce=[guid]::NewGuid().ToString('N');$remoteArchive="/tmp/devfleet-restore-$nonce.tar.gz";$stage="/home/devrunner/workspaces/.devfleet-restore-$slug-$nonce";$oldPath="${workspace}-before-restore-$nonce";$promoted=$false
    try{
        Invoke-Multipass @('transfer',[string]$verified.archive_path,"${vmName}:$remoteArchive") 1200|Out-Null
        $remoteHash=((Invoke-Multipass @('exec',$vmName,'--','sha256sum',$remoteArchive) 60).Text -split '\s+')[0].ToLowerInvariant()
        if($remoteHash -ne [string]$verified.backup_sha256){throw 'Restore archive SHA-256 differs between the host and project VM.'}
        Invoke-Multipass @('exec',$vmName,'--','sudo','mkdir','-p',$stage) 30|Out-Null
        Invoke-Multipass @('exec',$vmName,'--','sudo','tar','-xzf',$remoteArchive,'-C',$stage,'--no-same-owner','--no-same-permissions') 600|Out-Null
        $restoredMetadata="$stage/$slug/.devfleet/project.json"
        Invoke-Multipass @('exec',$vmName,'--','sudo','test','-f',$restoredMetadata) 30|Out-Null
        $restoredProjectId=(Invoke-Multipass @('exec',$vmName,'--','sudo','python3','-c','import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8")).get("project_id",""))',$restoredMetadata) 30).Text.Trim()
        if($restoredProjectId -ne [string]$Record.project_id){throw 'Restored workspace project identity does not match the owned project VM.'}
        Invoke-Multipass @('exec',$vmName,'--','sudo','mv',$workspace,$oldPath) 60|Out-Null
        Invoke-Multipass @('exec',$vmName,'--','sudo','mv',"$stage/$slug",$workspace) 60|Out-Null;$promoted=$true
        Invoke-Multipass @('exec',$vmName,'--','sudo','chown','-R','devrunner:devrunner',$workspace) 120|Out-Null
        $finalProjectId=(Invoke-Multipass @('exec',$vmName,'--','sudo','python3','-c','import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8")).get("project_id",""))',"$workspace/.devfleet/project.json") 30).Text.Trim()
        if($finalProjectId -ne [string]$Record.project_id){throw 'Promoted restore failed final project identity verification.'}
        Invoke-Multipass @('exec',$vmName,'--','sudo','rm','-rf',$oldPath) 120|Out-Null
        Write-AgentLog 'restore-backup' $Record.project_id $Record.runtime_id 'verified' "Restored $BackupId after verified safety backup $($safety.backup_id)."
        return [ordered]@{ok=$true;host_name=$script:Config.HostName;provider='multipass-host-agent';runtime_id=$Record.runtime_id;project_id=$Record.project_id;backup_id=$BackupId;backup_sha256=$verified.backup_sha256;safety_backup_id=$safety.backup_id;safety_backup_sha256=$safety.backup_sha256;state='restored';message='Project VM workspace restored after staging, identity verification, and safety backup.'}
    }catch{
        if($promoted){try{Invoke-Multipass @('exec',$vmName,'--','sudo','rm','-rf',$workspace) 120|Out-Null;Invoke-Multipass @('exec',$vmName,'--','sudo','mv',$oldPath,$workspace) 120|Out-Null}catch{Write-AgentLog 'restore-backup' $Record.project_id $Record.runtime_id 'rollback-incomplete' $_.Exception.Message}}
        throw
    }finally{
        try{Invoke-Multipass @('exec',$vmName,'--','rm','-f',$remoteArchive) 30|Out-Null}catch{}
        try{Invoke-Multipass @('exec',$vmName,'--','sudo','rm','-rf',$stage) 60|Out-Null}catch{}
    }
}

function Get-ProjectCommandManifest { param([Parameter(Mandatory)]$Record)
    $slug=Assert-Slug ([string]$Record.slug);$workspace="/home/devrunner/workspaces/$slug";$metadataPath="$workspace/.devfleet/project.json"
    $text=(Invoke-Multipass @('exec',$Record.vm_name,'--','sudo','cat',$metadataPath) 30).Text
    try {$metadata=$text|ConvertFrom-Json -AsHashtable} catch {throw 'Project command manifest is not valid JSON.'}
    if(-not $metadata -or ($metadata.runtime_type -and [string]$metadata.runtime_type -notin @('vm','container'))){throw 'Project command manifest declares an unsupported runtime type.'}
    return $metadata
}

function Get-TrustedProjectCommand { param([Parameter(Mandatory)]$Record,[Parameter(Mandatory)][string]$CommandKey,[int]$Tail=150)
    $key=$CommandKey.ToLowerInvariant();$allowed=@('bootstrap_command','health_command','test_command','format_command','lint_command','start_command','stop_command','restart_command','rebuild_command','logs_command','codexpro_command')
    if($key -notin $allowed){throw 'Unsupported project command key.'}
    $metadata=Get-ProjectCommandManifest $Record;$value=$metadata[$key];if($null -eq $value -and $metadata.commands){$value=$metadata.commands[$key]}
    if($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)){throw "Project command '$key' is not configured in .devfleet/project.json."}
    $cmd=[string]$value
    $hookAllowed=$cmd -match '^\./\.devfleet/(bootstrap|health-check|smoke-test|codexpro-bootstrap)\.sh$'
    $composeAllowed=@('docker compose up -d --build','docker compose down --remove-orphans','docker compose restart','docker compose build && docker compose up -d','docker compose logs') -contains $cmd
    if($cmd.Length -gt 512 -or -not ($hookAllowed -or $composeAllowed) -or $cmd -match '[\r\n`$<>]' -or $cmd -match '(?i)(^|\s)(sudo|su|shutdown|reboot|poweroff|systemctl|service|multipass)(\s|$)' -or $cmd -match '(?i)(rm\s+-rf|docker\s+(run|exec)|curl\s+|wget\s+)'){throw "Project command '$key' is unsafe or unsupported."}
    if($key -eq 'logs_command'){$cmd="$cmd --tail $([math]::Max(1,[math]::Min($Tail,500)))"}
    return $cmd
}

function Invoke-ProjectCommand { param([Parameter(Mandatory)]$Record,[Parameter(Mandatory)][string]$CommandKey,[int]$Tail=150)
    $slug=Assert-Slug ([string]$Record.slug);$slug=Assert-Slug $slug;$workspace="/home/devrunner/workspaces/$slug";$cmd=Get-TrustedProjectCommand $Record $CommandKey $Tail
    if($workspace -notmatch '^/home/devrunner/workspaces/[a-z0-9][a-z0-9._-]{1,62}$'){throw 'Project workspace boundary validation failed.'}
    # The command is selected only from the fixed allowlist above. Keep the
    # workspace separately validated immediately before the unavoidable shell
    # boundary and use exec so no extra shell remains after the trusted command.
    $result=Invoke-Multipass @('exec',$Record.vm_name,'--','sudo','-u','devrunner','bash','--noprofile','--norc','-lc',"cd -- '$workspace' && exec $cmd") 3600
    return [ordered]@{ok=$true;host_name=$script:Config.HostName;runtime_id=$Record.runtime_id;project_id=$Record.project_id;command_key=$CommandKey.ToLowerInvariant();output=$result.Text;state='completed'}
}

# Treat remote existence checks as data. Invoke-Multipass throws on a negative
# test, so relying on $LASTEXITCODE would make a valid first import fail.
function Export-ProjectWorkspaceToSource { param([Parameter(Mandatory)][string]$Slug,[Parameter(Mandatory)]$Record,[Parameter(Mandatory)][string]$SourceVm,[Parameter(Mandatory)][string]$ProjectId,[bool]$ReplaceSource=$false)
    $Slug=Assert-Slug $Slug
    $ProjectId=Assert-ProjectId $ProjectId
    if([string]$Record.project_id -ne $ProjectId){throw 'Project identifier does not match the target VM ownership registry.'}
    if($SourceVm -notmatch '^devfleet-[a-z0-9][a-z0-9._-]{1,62}$' -or $SourceVm -eq $Record.vm_name){throw 'The export source VM is invalid.'}
    $sourceInventory=@(Get-MultipassVms|Where-Object{$_.name -eq $SourceVm})
    if($sourceInventory.Count -ne 1 -or [string]$sourceInventory[0].state -ne 'RUNNING'){throw 'The DevFleet source VM must be running for a VM workspace export.'}
    $remoteArchive="/tmp/devfleet-export-$([guid]::NewGuid().ToString('N')).tar.gz"
    $localArchive=Join-Path $script:Root "imports\$([guid]::NewGuid().ToString('N')).tar.gz"
    $sourceArchive="/tmp/devfleet-export-source-$([guid]::NewGuid().ToString('N')).tar.gz"
    $stage="/home/devrunner/workspaces/.devfleet-export-$Slug-$([guid]::NewGuid().ToString('N'))"
    $workspace="/home/devrunner/workspaces/$Slug"
    $oldPath="/home/devrunner/workspaces/$Slug-before-vm-export-$([guid]::NewGuid().ToString('N'))"
    try {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $localArchive)|Out-Null
        $archiveInspection=New-VerifiedRemoteWorkspaceArchive $Record.vm_name $remoteArchive $Slug
        $sourceArchiveHash=[string]$archiveInspection.archive_sha256
        Invoke-Multipass @('transfer',"$($Record.vm_name):$remoteArchive",$localArchive) 1200|Out-Null
        $hash=(Get-FileHash -LiteralPath $localArchive -Algorithm SHA256).Hash.ToLowerInvariant()
        if($hash -ne $sourceArchiveHash){throw 'Workspace export archive SHA-256 differs between the project VM and host.'}
        Invoke-Multipass @('transfer',$localArchive,"${SourceVm}:$sourceArchive") 1200|Out-Null
        Invoke-Multipass @('exec',$SourceVm,'--','sudo','mkdir','-p',$stage) 30|Out-Null
        Invoke-Multipass @('exec',$SourceVm,'--','sudo','tar','-xzf',$sourceArchive,'-C',$stage,'--no-same-owner','--no-same-permissions') 600|Out-Null
        $sourceVmArchiveHash=((Invoke-Multipass @('exec',$SourceVm,'--','sha256sum',$sourceArchive) 60).Text -split '\s+')[0].ToLowerInvariant()
        if($sourceVmArchiveHash -ne $hash){throw 'Workspace export archive SHA-256 differs between the host and source VM.'}
        Invoke-Multipass @('exec',$SourceVm,'--','sudo','test','-f',"$stage/$Slug/.devfleet/project.json") 30|Out-Null
        if($ReplaceSource){
            $sourceState=(Invoke-Multipass @('exec',$SourceVm,'--','sudo','bash','-lc',"if [ -d '$workspace' ]; then printf exists; else printf absent; fi") 30).Text.Trim()
            $hasExisting=$sourceState -eq 'exists'
            if($hasExisting){Invoke-Multipass @('exec',$SourceVm,'--','sudo','mv',$workspace,$oldPath) 60|Out-Null}
            Invoke-Multipass @('exec',$SourceVm,'--','sudo','mv',"$stage/$Slug",$workspace) 60|Out-Null
            Invoke-Multipass @('exec',$SourceVm,'--','sudo','chown','-R','devrunner:devrunner',$workspace) 120|Out-Null
            Write-AgentLog 'export-to-source' $Record.project_id $Record.runtime_id 'verified' "VM workspace exported to $SourceVm with equal source, host, and source-VM SHA-256."
            return [ordered]@{ok=$true;host_name=$script:Config.HostName;runtime_id=$Record.runtime_id;project_id=$Record.project_id;source_vm=$SourceVm;archive_sha256=$hash;source_archive_sha256=$sourceArchiveHash;host_archive_sha256=$hash;source_vm_archive_sha256=$sourceVmArchiveHash;workspace_path=$workspace;previous_workspace_path=if($hasExisting){$oldPath}else{''};state='verified';message='Dedicated VM workspace exported and promoted to the source VM after archive equality verification.'}
        }
        return [ordered]@{ok=$true;host_name=$script:Config.HostName;runtime_id=$Record.runtime_id;project_id=$Record.project_id;source_vm=$SourceVm;archive_sha256=$hash;source_archive_sha256=$sourceArchiveHash;host_archive_sha256=$hash;source_vm_archive_sha256=$sourceVmArchiveHash;staging_path="$stage/$Slug";state='staged';message='Dedicated VM workspace exported to a verified staging directory after archive equality verification.'}
    } finally {
        Remove-Item -LiteralPath $localArchive -Force -ErrorAction SilentlyContinue
        try{Invoke-Multipass @('exec',$Record.vm_name,'--','sudo','rm','-f',$remoteArchive) 30|Out-Null}catch{}
        try{Invoke-Multipass @('exec',$SourceVm,'--','sudo','rm','-f',$sourceArchive) 30|Out-Null}catch{}
        if(-not $ReplaceSource){try{Invoke-Multipass @('exec',$SourceVm,'--','sudo','rm','-rf',$stage) 30|Out-Null}catch{}}
    }
}

function Remove-ImportFailedProjectVm {
    param([Parameter(Mandatory)][string]$Slug,[Parameter(Mandatory)]$Record,[Parameter(Mandatory)]$Payload)
    $Slug=Assert-Slug $Slug
    if([string]$Record.state -notin @('creating','booting','ready','stopped')){throw 'Cleanup-only VM removal is limited to a newly provisioned project VM.'}
    if(-not [bool]$Payload.backup_verified -or [string]::IsNullOrWhiteSpace([string]$Payload.backup_id)){throw 'Cleanup-only removal requires a verified provider-aware recovery backup.'}
    foreach($name in 'backup_sha256','local_archive_sha256'){if([string]$Payload.$name -notmatch '^[0-9a-fA-F]{64}$'){throw "Cleanup-only removal requires a valid $name value."}}
    $stage=[string]$Payload.cleanup_stage;if($stage -notin @('pre-import','post-import')){throw 'Cleanup-only removal requires an explicit pre-import or post-import stage.'}
    $vmName=[string]$Record.vm_name
    if($vmName -ne (Get-ProjectVmName $Slug) -or [string]$Record.runtime_id -ne $vmName -or [string]$Record.managed_by -ne 'devfleet' -or [string]$Record.host_id -ne [string]$script:Config.HostId){throw 'Cleanup-only removal failed the ownership registry identity check.'}
    $inventory=@(Get-MultipassVms|Where-Object{$_.name -eq $vmName});if($inventory.Count -ne 1){throw 'Cleanup-only removal requires exactly one deterministic project VM.'}
    $runtimeText=(Invoke-Multipass @('exec',$vmName,'--','sudo','cat','/etc/devfleet/project-runtime.json') 30).Text
    try{$runtimeMeta=$runtimeText|ConvertFrom-Json -AsHashtable}catch{throw 'The project VM runtime identity document is invalid.'}
    if([string]$runtimeMeta.managed_by -ne 'devfleet' -or [string]$runtimeMeta.slug -ne $Slug -or [string]$runtimeMeta.project_id -ne [string]$Record.project_id){throw 'The project VM runtime identity does not match the ownership registry.'}
    $workspace="/home/devrunner/workspaces/$Slug";$projectMetaPath="$workspace/.devfleet/project.json"
    if($stage -eq 'pre-import'){
        Invoke-Multipass @('exec',$vmName,'--','sudo','bash','-lc',"test ! -e '$projectMetaPath'") 30|Out-Null
    } else {
        $projectText=(Invoke-Multipass @('exec',$vmName,'--','sudo','cat',$projectMetaPath) 30).Text
        try{$projectMeta=$projectText|ConvertFrom-Json -AsHashtable}catch{throw 'The imported project metadata is invalid.'}
        if([string]$projectMeta.slug -ne $Slug -or ([string]$projectMeta.identity -and [string]$projectMeta.identity -ne $Slug)){throw 'The imported workspace identity does not match the cleanup request.'}
        if([string]$projectMeta.project_id -and [string]$projectMeta.project_id -ne [string]$Record.project_id){throw 'The imported workspace project identifier does not match the ownership registry.'}
        $payloadImport=[string]$Payload.import_archive_sha256;$recordImport=[string]$Record.import_archive_sha256
        if($payloadImport -and $payloadImport -notmatch '^[0-9a-fA-F]{64}$'){throw 'Cleanup-only removal received an invalid import archive SHA-256.'}
        if($recordImport -and (!$payloadImport -or $recordImport -ne $payloadImport)){throw 'The cleanup import archive does not match the persisted import evidence.'}
    }
    $lock=New-ProvisioningLock
    try {
        $info=Get-ProjectVmInfo $vmName;if([string]$info.state -eq 'RUNNING'){Invoke-Multipass @('stop',$vmName) 120|Out-Null}
        Invoke-Multipass @('delete',$vmName,'--purge') 600|Out-Null
        if(@(Get-MultipassVms|Where-Object{$_.name -eq $vmName}).Count -ne 0){throw 'Multipass still reports the cleanup VM after deletion.'}
        Remove-ProjectVmSshAlias $Record.runtime_id $Record.project_id
        $Record.state='destroyed';$Record.cleanup_stage=$stage;$Record.destroyed_at=(Get-Date).ToUniversalTime().ToString('o');$Record.updated_at=$Record.destroyed_at;Update-ProjectRecord $Slug $Record|Out-Null
        Write-AgentLog 'import-cleanup' $Record.project_id $Record.runtime_id 'destroyed' "Removed the verified $stage failed-migration VM and released its allocation."
        return [ordered]@{ok=$true;host_name=$script:Config.HostName;runtime_id=$Record.runtime_id;vm_name=$vmName;project_id=$Record.project_id;state='destroyed';cleanup_only=$true;cleanup_stage=$stage;allocation_released=$true;runtime_identity_verified=$true;workspace_identity_verified=($stage -eq 'post-import');message='Failed-migration project VM reconciled after deterministic identity and recovery-evidence checks.'}
    } finally {try{$lock.ReleaseMutex()}catch{};$lock.Dispose()}
}

# The project-VM section is intentionally independent from the ordinary
# DevFleet aliases created by Configure-SSH.ps1.  It is the only section this
# service changes, preserving all user configuration and the primary aliases.
function Get-ProjectVmSshMarkers { param([Parameter(Mandatory)][string]$RuntimeId)
    $safe=[regex]::Escape($RuntimeId)
    return @{Begin="# BEGIN DEVFLEET PROJECT VM $RuntimeId";End="# END DEVFLEET PROJECT VM $RuntimeId";Pattern="(?ms)^# BEGIN DEVFLEET PROJECT VM $safe\r?\n.*?^# END DEVFLEET PROJECT VM $safe\r?\n?"}
}

function Get-ProjectVmKnownHostMarkers { param([Parameter(Mandatory)][string]$RuntimeId)
    $safe=[regex]::Escape($RuntimeId)
    return @{Begin="# BEGIN DEVFLEET PROJECT VM HOST KEY $RuntimeId";End="# END DEVFLEET PROJECT VM HOST KEY $RuntimeId";Pattern="(?ms)^# BEGIN DEVFLEET PROJECT VM HOST KEY $safe\r?\n.*?^# END DEVFLEET PROJECT VM HOST KEY $safe\r?\n?"}
}

function Set-DevFleetManagedTextBlock {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Pattern,[string]$Block='')
    $directory=Split-Path -Parent $Path;if($directory){New-Item -ItemType Directory -Force -Path $directory|Out-Null}
    $existing=if(Test-Path -LiteralPath $Path){[IO.File]::ReadAllText($Path)}else{''}
    $updated=[regex]::Replace($existing,$Pattern,'').TrimEnd()
    if($Block){if($updated){$updated+="`r`n`r`n"};$updated+=$Block.Trim()+"`r`n"}elseif($updated){$updated+="`r`n"}
    if($updated -ne $existing){$temp="$Path.$([guid]::NewGuid().ToString('N')).tmp";[IO.File]::WriteAllText($temp,$updated,(New-Object Text.UTF8Encoding($false)));Move-Item -LiteralPath $temp -Destination $Path -Force}
    return $updated
}

function Sync-ProjectVmSshAlias {
    param([Parameter(Mandatory)][string]$Slug,[Parameter(Mandatory)]$Record,[object]$VmInfo=$null,[string]$Address='')
    $slug=Assert-Slug $Slug;$runtimeId=[string]$Record.runtime_id
    if($runtimeId -ne (Get-ProjectVmName $slug)){throw 'Project VM SSH alias does not match the deterministic owned runtime identity.'}
    $configPath=[string]$script:Config.SshConfigPath;$keyPath=[string]$script:Config.SshPrivateKeyPath;$knownHostsPath=[string]$script:Config.SshKnownHostsPath
    if([string]::IsNullOrWhiteSpace($configPath) -or [string]::IsNullOrWhiteSpace($keyPath) -or [string]::IsNullOrWhiteSpace($knownHostsPath)){throw 'Host-agent SSH alias and known-host paths are not configured.'}
    if(-not(Test-Path -LiteralPath $keyPath)){throw 'Configured DevFleet SSH private key is not available for project aliases.'}
    $info=if($VmInfo){$VmInfo}else{Get-ProjectVmInfo ([string]$Record.vm_name)}
    $address=if($Address){$Address}else{Get-PrimaryProjectVmIpv4 $info}
    if([string]::IsNullOrWhiteSpace($address)){throw 'Project VM has no address available for its SSH alias.'}
    $hostKey=(Invoke-Multipass @('exec',$record.vm_name,'--','sudo','cat','/etc/ssh/ssh_host_ed25519_key.pub') 30).Text.Trim();$hostKeyParts=$hostKey -split '\s+'
    if($hostKeyParts.Count -lt 2 -or $hostKeyParts[0] -ne 'ssh-ed25519' -or $hostKeyParts[1] -notmatch '^[A-Za-z0-9+/]+={0,3}$'){throw 'Project VM did not provide a valid Ed25519 SSH host key.'}
    $knownMarkers=Get-ProjectVmKnownHostMarkers $runtimeId;$knownBlock="$($knownMarkers.Begin)`r`n$runtimeId ssh-ed25519 $($hostKeyParts[1])`r`n$($knownMarkers.End)"
    Set-DevFleetManagedTextBlock $knownHostsPath $knownMarkers.Pattern $knownBlock|Out-Null
    $markers=Get-ProjectVmSshMarkers $runtimeId
    $identity=$keyPath.Replace('\','/');$knownHosts=$knownHostsPath.Replace('\','/')
    $block=@"
$($markers.Begin)
Host $runtimeId
    HostName $address
    User devrunner
    IdentityFile $identity
    IdentitiesOnly yes
    ForwardAgent no
    HostKeyAlias $runtimeId
    UserKnownHostsFile $knownHosts
    StrictHostKeyChecking yes
$($markers.End)
"@
    Set-DevFleetManagedTextBlock $configPath $markers.Pattern $block|Out-Null
    $ssh=Resolve-TrustedHostExecutable @((Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'),(Join-Path $env:ProgramFiles 'OpenSSH\ssh.exe'))
    $resolved=& $ssh -F $configPath -G $runtimeId 2>$null
    if($LASTEXITCODE -ne 0){throw 'OpenSSH could not resolve the managed project VM alias.'}
    $text=$resolved -join "`n"
    if($text -notmatch "(?m)^hostname\s+$([regex]::Escape($address))$" -or $text -notmatch '(?m)^user\s+devrunner$' -or $text -notmatch '(?m)^identitiesonly\s+yes$' -or $text -notmatch '(?m)^forwardagent\s+no$' -or $text -notmatch '(?m)^stricthostkeychecking\s+(yes|true)$' -or $text -notmatch "(?m)^hostkeyalias\s+$([regex]::Escape($runtimeId))$"){throw 'Managed project VM SSH alias did not pass pinned configuration validation.'}
    # The service runs as SYSTEM while the managed alias must remain usable by
    # the installing developer. OpenSSH correctly rejects that developer-owned
    # private key when SYSTEM evaluates its ACL, so validate with a short-lived
    # SYSTEM-only copy of the same key and never expose its contents.
    $validationKey=Join-Path $script:Root "ssh-validation-$([guid]::NewGuid().ToString('N'))"
    try {
        Copy-Item -LiteralPath $keyPath -Destination $validationKey -Force
        $keyAcl=New-Object System.Security.AccessControl.FileSecurity;$keyAcl.SetAccessRuleProtection($true,$false)
        $keyAcl.SetAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('SYSTEM','FullControl','Allow')))
        $keyAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('Administrators','FullControl','Allow')))
        Set-Acl -LiteralPath $validationKey -AclObject $keyAcl
        $sshOutput=& $ssh -F $configPath -i $validationKey -o BatchMode=yes -o ConnectTimeout=15 $runtimeId 'id -un' 2>&1
        if($LASTEXITCODE -ne 0 -or (($sshOutput -join "`n").Trim() -ne 'devrunner')){throw 'Managed project VM SSH alias did not pass an authenticated pinned host-key connection test.'}
    } finally {Remove-Item -LiteralPath $validationKey -Force -ErrorAction SilentlyContinue}
    $vsCode=if(Get-Command Sync-DevFleetVsCodeRemotePlatform -ErrorAction SilentlyContinue){Sync-DevFleetVsCodeRemotePlatform $runtimeId}else{[ordered]@{ok=$true;status='skipped';reason='VS Code helper is not installed.';alias=$runtimeId;platform='linux'}}
    $Record.address=$address;$Record.ssh_alias=$runtimeId;$Record.updated_at=(Get-Date).ToUniversalTime().ToString('o');Update-ProjectRecord $slug $Record|Out-Null
    Write-AgentLog 'sync-ssh-alias' $Record.project_id $runtimeId 'ready' 'Dedicated project VM SSH alias and managed Ed25519 host key passed configuration and authenticated connection checks.'
    return [ordered]@{ok=$true;host_name=$script:Config.HostName;project_id=$Record.project_id;runtime_id=$runtimeId;ssh_alias=$runtimeId;address=$address;host_key_algorithm='ssh-ed25519';host_key_pinned=$true;authenticated_connection=$true;validated=$true;vscode_remote_platform=$vsCode}
}

function Refresh-ProjectVmConnectionState {
    param([Parameter(Mandatory)][string]$Slug,[Parameter(Mandatory)]$Record)
    $slug=Assert-Slug $Slug
    $owned=Assert-OwnedProjectVm $slug ([string]$Record.runtime_id)
    if([string]$owned.project_id -ne [string]$Record.project_id){throw 'Project identifier does not match the ownership registry.'}
    $info=Get-ProjectVmInfo ([string]$owned.vm_name)
    $address=Get-PrimaryProjectVmIpv4 $info
    $sync=Sync-ProjectVmSshAlias $slug $owned -VmInfo $info -Address $address
    $latest=Get-ProjectRecord $slug
    $latest.state='ready';$latest.address=$address;$latest.updated_at=(Get-Date).ToUniversalTime().ToString('o');Update-ProjectRecord $slug $latest|Out-Null
    Write-AgentLog 'refresh-connection-state' $latest.project_id $latest.runtime_id 'ready' "Reconciled owned project VM address $address and managed SSH alias."
    return [ordered]@{ok=$true;host_name=$script:Config.HostName;project_id=$latest.project_id;runtime_id=$latest.runtime_id;vm_name=$latest.vm_name;address=$address;state='ready';registry_address=$address;ssh_alias=$sync.ssh_alias;host_key_pinned=[bool]$sync.host_key_pinned;authenticated_connection=[bool]$sync.authenticated_connection;validated=[bool]$sync.validated;workspace_provisioned=$true;vscode_remote_platform=$sync.vscode_remote_platform;info=$info}
}

function Remove-ProjectVmSshAlias {
    param([Parameter(Mandatory)][string]$RuntimeId,[Parameter(Mandatory)][string]$ProjectId)
    $configPath=[string]$script:Config.SshConfigPath;$knownHostsPath=[string]$script:Config.SshKnownHostsPath;$removed=$false
    if($configPath -and (Test-Path -LiteralPath $configPath)){$markers=Get-ProjectVmSshMarkers $RuntimeId;$before=[IO.File]::ReadAllText($configPath);Set-DevFleetManagedTextBlock $configPath $markers.Pattern|Out-Null;$removed=$removed -or ([IO.File]::ReadAllText($configPath) -ne $before)}
    if($knownHostsPath -and (Test-Path -LiteralPath $knownHostsPath)){$knownMarkers=Get-ProjectVmKnownHostMarkers $RuntimeId;$before=[IO.File]::ReadAllText($knownHostsPath);Set-DevFleetManagedTextBlock $knownHostsPath $knownMarkers.Pattern|Out-Null;$removed=$removed -or ([IO.File]::ReadAllText($knownHostsPath) -ne $before)}
    $vsCode=if(Get-Command Remove-DevFleetVsCodeRemotePlatform -ErrorAction SilentlyContinue){Remove-DevFleetVsCodeRemotePlatform @(Get-DevFleetVsCodeSettingsPaths) $RuntimeId}else{[ordered]@{ok=$true;status='skipped';reason='VS Code helper is not installed.';alias=$RuntimeId}}
    if($removed){Write-AgentLog 'remove-ssh-alias' $ProjectId $RuntimeId 'removed' 'Removed only the destroyed project VM SSH alias and its managed host-key pin.'}
}

function Restore-PreviousSourceWorkspace { param([Parameter(Mandatory)][string]$Slug,[Parameter(Mandatory)]$Record,[Parameter(Mandatory)][string]$SourceVm,[Parameter(Mandatory)][string]$ProjectId,[Parameter(Mandatory)][string]$PreviousWorkspacePath)
    $Slug=Assert-Slug $Slug;$ProjectId=Assert-ProjectId $ProjectId
    if([string]$Record.project_id -ne $ProjectId){throw 'Project identifier does not match the target VM ownership registry.'}
    if($SourceVm -notmatch '^devfleet-[a-z0-9][a-z0-9._-]{1,62}$' -or $SourceVm -eq $Record.vm_name){throw 'The export source VM is invalid.'}
    $expected="^/home/devrunner/workspaces/$([regex]::Escape($Slug))-before-vm-export-[0-9a-f]{32}$"
    if($PreviousWorkspacePath -notmatch $expected){throw 'The retained previous workspace path is invalid.'}
    $sourceInventory=@(Get-MultipassVms|Where-Object{$_.name -eq $SourceVm})
    if($sourceInventory.Count -ne 1 -or [string]$sourceInventory[0].state -ne 'RUNNING'){throw 'The DevFleet source VM must be running to restore its retained workspace.'}
    $workspace="/home/devrunner/workspaces/$Slug";$rollbackPath="/home/devrunner/workspaces/$Slug-failed-migration-$([guid]::NewGuid().ToString('N'))";$metadataPath="$PreviousWorkspacePath/.devfleet/project.json"
    $oldMetaText=(Invoke-Multipass @('exec',$SourceVm,'--','sudo','cat',$metadataPath) 30).Text
    try{$oldMeta=$oldMetaText|ConvertFrom-Json -AsHashtable}catch{throw 'The retained previous workspace metadata is invalid.'}
    if([string]$oldMeta.project_id -ne $ProjectId){throw 'The retained previous workspace belongs to a different project.'}
    $lock=New-ProvisioningLock
    try {
        Invoke-Multipass @('exec',$SourceVm,'--','sudo','test','-d',$workspace) 30|Out-Null
        Invoke-Multipass @('exec',$SourceVm,'--','sudo','test','-d',$PreviousWorkspacePath) 30|Out-Null
        Invoke-Multipass @('exec',$SourceVm,'--','sudo','mv',$workspace,$rollbackPath) 60|Out-Null
        try {Invoke-Multipass @('exec',$SourceVm,'--','sudo','mv',$PreviousWorkspacePath,$workspace) 60|Out-Null}
        catch {try{Invoke-Multipass @('exec',$SourceVm,'--','sudo','mv',$rollbackPath,$workspace) 60|Out-Null}catch{};throw}
        Invoke-Multipass @('exec',$SourceVm,'--','sudo','chown','-R','devrunner:devrunner',$workspace) 120|Out-Null
        Write-AgentLog 'restore-previous-source' $Record.project_id $Record.runtime_id 'restored' 'Atomically reinstated the retained source workspace after migration rollback.'
        return [ordered]@{ok=$true;host_name=$script:Config.HostName;runtime_id=$Record.runtime_id;project_id=$Record.project_id;source_vm=$SourceVm;workspace_path=$workspace;consumed_previous_workspace_path=$PreviousWorkspacePath;replaced_workspace_path=$rollbackPath;state='restored';message='Retained source workspace restored atomically.'}
    } finally {try{$lock.ReleaseMutex()}catch{};$lock.Dispose()}
}

function Invoke-ProjectVmOperation { param([Parameter(Mandatory)][string]$Operation,[Parameter(Mandatory)]$Payload,[string]$RuntimeId='')
    $Operation=$Operation.ToLowerInvariant();if($Operation -eq 'capacity'){return [ordered]@{ok=$true;host_name=$script:Config.HostName;capacity=Get-HostCapacity}};if($Operation -eq 'provider'){return [ordered]@{ok=$true;host_name=$script:Config.HostName;provider='multipass';provider_version=$script:Config.MultipassVersion;gpu_enabled=$false}}
    $slug=Assert-Slug ([string]$Payload.slug);$payloadProjectId=Assert-ProjectId ([string]$Payload.project_id);$record=Assert-OwnedProjectVm $slug $RuntimeId -AllowStoppedTransition:($Operation -eq 'start');if($payloadProjectId -ne [string]$record.project_id){throw 'Project identifier does not match the ownership registry.'};$vmName=[string]$record.vm_name;if($Operation -eq 'destroy' -and [bool]$Payload.cleanup_only){if([string]$Payload.confirm_slug -ne $slug -or [string]$Payload.confirm_phrase -cne "DESTROY $slug"){throw 'Cleanup-only removal requires the exact project confirmation phrase.'};return Remove-ImportFailedProjectVm $slug $record $Payload}
    switch($Operation){
        'sync-ssh-alias' {return Sync-ProjectVmSshAlias $slug $record}
        'refresh-connection-state' {return Refresh-ProjectVmConnectionState $slug $record}
        'start' {Invoke-Multipass @('start',$vmName) 120|Out-Null;Wait-ProjectVmReady $vmName|Out-Null;return Refresh-ProjectVmConnectionState $slug $record}
        'stop' {Invoke-Multipass @('stop',$vmName) 120|Out-Null;if([string]$record.address){$record.last_known_address=[string]$record.address};$record.address='';$record.state='stopped';$record.updated_at=(Get-Date).ToUniversalTime().ToString('o');Update-ProjectRecord $slug $record|Out-Null;Write-AgentLog 'stop' $record.project_id $record.runtime_id 'stopped' 'Project VM stopped; current address cleared and retained only as last_known_address.';return [ordered]@{ok=$true;host_name=$script:Config.HostName;runtime_id=$record.runtime_id;vm_name=$vmName;state='stopped';runtime_address='';last_known_address=$record.last_known_address;message='Dedicated project VM stopped.'}}
        'restart' {Invoke-Multipass @('restart',$vmName) 180|Out-Null;Wait-ProjectVmReady $vmName|Out-Null;return Refresh-ProjectVmConnectionState $slug $record}
        'inspect' {$info=Get-ProjectVmInfo $vmName;return [ordered]@{ok=$true;host_name=$script:Config.HostName;runtime_id=$record.runtime_id;record=$record;info=$info;gpu_enabled=$false}}
        'health' {$info=Get-ProjectVmInfo $vmName;if([string]$info.state -ne 'RUNNING'){return [ordered]@{ok=$true;host_name=$script:Config.HostName;runtime_id=$record.runtime_id;state='stopped';vm_name=$vmName;project_id=$record.project_id;gpu_enabled=$false;healthy=$false;runtime_health='not-run-stopped';health_scope='runtime-only';application_healthy=$false;application_health='not-run-stopped';guest_exec_performed=$false;info=$info}};$health=Invoke-Multipass @('exec',$vmName,'--','sudo','/usr/local/sbin/devfleet-project-health') 30;return [ordered]@{ok=$true;host_name=$script:Config.HostName;runtime_id=$record.runtime_id;state='healthy';vm_name=$vmName;project_id=$record.project_id;gpu_enabled=$false;healthy=$true;runtime_health='healthy';health_scope='runtime-only';application_healthy=$false;application_health='not-run';guest_exec_performed=$true;info=$info}}
        'backup' {return Backup-ProjectVm $record ([bool]$Payload.destructive)}
        'list-backups' {return [ordered]@{ok=$true;host_name=$script:Config.HostName;runtime_id=$record.runtime_id;project_id=$record.project_id;backups=@(Get-ProjectVmBackups $record)}}
        'inspect-backup' {$verified=Get-VerifiedProjectBackup $record ([string]$Payload.backup_id);return [ordered]@{ok=$true;host_name=$script:Config.HostName;host_id=$script:Config.HostId;runtime_id=$record.runtime_id;project_id=$record.project_id;backup=[ordered]@{backup_reference=$verified.backup_reference;sha_verified=$true;restore_eligible=$true}}}
        'restore-backup' {return Restore-ProjectVmBackup $record ([string]$Payload.backup_id) ([bool]$Payload.confirm_restore)}
        'export' {return Backup-ProjectVm $record}
        'export-to-source' {return Export-ProjectWorkspaceToSource $slug $record ([string]$Payload.source_vm) ([string]$Payload.project_id) ([bool]$Payload.replace_source)}
        'restore-previous-source' {return Restore-PreviousSourceWorkspace $slug $record ([string]$Payload.source_vm) ([string]$Payload.project_id) ([string]$Payload.previous_workspace_path)}
        'project-start' {return Invoke-ProjectCommand $record 'start_command'}
        'project-stop' {return Invoke-ProjectCommand $record 'stop_command'}
        'project-restart' {$manifest=Get-ProjectCommandManifest $record;if($manifest.restart_command -or ($manifest.commands -and $manifest.commands.restart_command)){return Invoke-ProjectCommand $record 'restart_command'};Invoke-ProjectCommand $record 'stop_command'|Out-Null;return Invoke-ProjectCommand $record 'start_command'}
        'project-health' {return Invoke-ProjectCommand $record 'health_command'}
        'project-test' {return Invoke-ProjectCommand $record 'test_command'}
        'project-bootstrap' {if([string]$Payload.command_key -eq 'codexpro'){return Invoke-ProjectCommand $record 'codexpro_command'};return Invoke-ProjectCommand $record 'bootstrap_command'}
        'project-rebuild' {return Invoke-ProjectCommand $record 'rebuild_command'}
        'project-logs' {return Invoke-ProjectCommand $record 'logs_command' ([int]$Payload.tail)}
        'quarantine' {if((Get-ProjectVmInfo $vmName).state -eq 'RUNNING'){Invoke-Multipass @('stop',$vmName) 120|Out-Null};$record.state='quarantined';Update-ProjectRecord $slug $record|Out-Null;return [ordered]@{ok=$true;host_name=$script:Config.HostName;runtime_id=$record.runtime_id;state='quarantined';message='Project VM quarantined and preserved.'}}
        'restore' {Invoke-Multipass @('start',$vmName) 120|Out-Null;Wait-ProjectVmReady $vmName|Out-Null;$record.state='ready';Update-ProjectRecord $slug $record|Out-Null;return [ordered]@{ok=$true;host_name=$script:Config.HostName;runtime_id=$record.runtime_id;state='ready';message='Project VM restored.'}}
        'import' {return Import-ProjectWorkspace $slug $RuntimeId ([string]$Payload.source_vm) ([string]$Payload.project_id)}
        'destroy' {$payloadProjectId=Assert-ProjectId ([string]$Payload.project_id);if($payloadProjectId -ne [string]$record.project_id){throw 'Project identifier does not match the ownership registry.'};if([string]$Payload.confirm_slug -ne $slug -or [string]$Payload.confirm_phrase -cne "DESTROY $slug"){throw 'Permanent destruction requires the exact project slug and confirmation phrase.'};if(-not [bool]$Payload.backup_verified -or -not [string]$Payload.backup_id -or -not [string]$Payload.backup_sha256){throw 'A specific verified workspace backup is required before permanent VM destruction.'};$manifestPath=Join-Path $script:BackupRoot "$(Assert-BackupId ([string]$Payload.backup_id)).json";if(-not(Test-Path -LiteralPath $manifestPath)){throw 'The requested backup manifest is not present on the host.'};$manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json -AsHashtable;if([string]$manifest.project_id -ne [string]$record.project_id -or [string]$manifest.slug -ne $slug -or [string]$manifest.runtime_id -ne [string]$record.runtime_id -or [string]$manifest.archive_sha256 -ne [string]$Payload.backup_sha256 -or [string]$manifest.source_archive_sha256 -ne [string]$manifest.host_archive_sha256 -or [string]$manifest.host_archive_sha256 -ne [string]$Payload.backup_sha256){throw 'Backup manifest identity or source/host hash equality does not match the project VM.'};$archiveHash=(Get-FileHash -LiteralPath ([string]$manifest.archive_path) -Algorithm SHA256).Hash.ToLowerInvariant();if($archiveHash -ne [string]$Payload.backup_sha256){throw 'Workspace backup archive hash no longer matches its verified manifest.'};$lock=New-ProvisioningLock;try{$info=Get-ProjectVmInfo $vmName;if([string]$info.state -eq 'RUNNING'){Invoke-Multipass @('stop',$vmName) 120|Out-Null};Invoke-Multipass @('delete',$vmName,'--purge') 600|Out-Null;if(@(Get-MultipassVms|Where-Object{$_.name -eq $vmName}).Count -ne 0){throw 'Multipass still reports the project VM after deletion.'};Remove-ProjectVmSshAlias $record.runtime_id $record.project_id;$record.state='destroyed';$record.destroyed_at=(Get-Date).ToUniversalTime().ToString('o');Update-ProjectRecord $slug $record|Out-Null;Write-AgentLog 'destroy' $record.project_id $record.runtime_id 'destroyed' 'Permanent project VM destruction completed after archive verification.';return [ordered]@{ok=$true;host_name=$script:Config.HostName;runtime_id=$record.runtime_id;vm_name=$vmName;state='destroyed';backup_id=$Payload.backup_id;message='Dedicated project VM destroyed after verified workspace backup.'}}finally{try{$lock.ReleaseMutex()}catch{};$lock.Dispose()}}
        default {throw 'Unsupported host VM operation.'}
    }
}

function Send-JsonResponse { param([Parameter(Mandatory)]$Context,[Parameter(Mandatory)]$Body,[int]$StatusCode=200);$json=$Body|ConvertTo-Json -Depth 20 -Compress;$bytes=[Text.Encoding]::UTF8.GetBytes($json);$Context.Response.StatusCode=$StatusCode;$Context.Response.ContentType='application/json';$Context.Response.ContentEncoding=[Text.Encoding]::UTF8;$Context.Response.ContentLength64=$bytes.Length;$Context.Response.OutputStream.Write($bytes,0,$bytes.Length);$Context.Response.Close() }
function Send-AuthenticatedJsonResponse {
    param([Parameter(Mandatory)]$Context,[Parameter(Mandatory)]$Body,[int]$StatusCode=200,[Parameter(Mandatory)]$Auth)
    $json=$Body|ConvertTo-Json -Depth 20 -Compress
    $bytes=[Text.Encoding]::UTF8.GetBytes($json)
    $material=([string]$Auth.Method.ToUpperInvariant()+"`n"+[string]$Auth.Path+"`n"+[string]$Auth.Timestamp+"`n"+[string]$Auth.Nonce+"`n"+[string]$StatusCode+"`n"+$json+"`n"+[string]$Auth.Expected)
    $hmac=[Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes([string]$script:Token))
    try{$signature=([BitConverter]::ToString($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($material)))-replace '-','').ToLowerInvariant()}finally{$hmac.Dispose()}
    $Context.Response.Headers['X-DevFleet-Host-Response-Signature']=$signature
    $Context.Response.StatusCode=$StatusCode;$Context.Response.ContentType='application/json';$Context.Response.ContentEncoding=[Text.Encoding]::UTF8;$Context.Response.ContentLength64=$bytes.Length;$Context.Response.OutputStream.Write($bytes,0,$bytes.Length);$Context.Response.Close()
}
function Read-JsonBody { param([Parameter(Mandatory)][string]$Text);if(-not $Text){return @{}};try{return $Text|ConvertFrom-Json -AsHashtable}catch{throw 'Request body is not valid JSON.'} }
$script:NonceStatePath=Join-Path $script:Root 'seen-request-nonces.json'
$script:SeenRequestNonces=@{}
function Read-NonceState {
    $script:SeenRequestNonces=@{}
    if(-not (Test-Path -LiteralPath $script:NonceStatePath -PathType Leaf)){return}
    try {
        $data=Get-Content -LiteralPath $script:NonceStatePath -Raw | ConvertFrom-Json -AsHashtable
        foreach($entry in $data.GetEnumerator()){[int64]$stamp=0;if([int64]::TryParse([string]$entry.Value,[ref]$stamp)){$script:SeenRequestNonces[[string]$entry.Key]=$stamp}}
    } catch { Write-AgentLog 'nonce-state' '' '' 'warning' 'Persisted nonce state was unreadable; starting with an empty bounded replay set.' }
}
function Save-NonceState {
    param([int64]$Now)
    foreach($key in @($script:SeenRequestNonces.Keys)){if(($Now-[int64]$script:SeenRequestNonces[$key])-gt 120){$script:SeenRequestNonces.Remove($key)}}
    $tmp="$script:NonceStatePath.$([guid]::NewGuid().ToString('N')).tmp"
    try { $script:SeenRequestNonces | ConvertTo-Json -Compress | Set-Content -LiteralPath $tmp -Encoding UTF8; Move-Item -LiteralPath $tmp -Destination $script:NonceStatePath -Force }
    finally { if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue} }
}
Read-NonceState
function Test-RequestToken {
    param([Parameter(Mandatory)]$Context)
    $reader=[IO.StreamReader]::new($Context.Request.InputStream,[Text.Encoding]::UTF8);try{$body=$reader.ReadToEnd()}finally{$reader.Dispose()}
    $timestamp=[string]$Context.Request.Headers['X-DevFleet-Host-Timestamp'];$nonce=[string]$Context.Request.Headers['X-DevFleet-Host-Nonce'];$expected=[string]$Context.Request.Headers['X-DevFleet-Host-Expected'];$provided=[string]$Context.Request.Headers['X-DevFleet-Host-Signature'];$epoch=0L
    if(-not [long]::TryParse($timestamp,[ref]$epoch)){return $null};$now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if([math]::Abs($now-$epoch)-gt 60 -or [string]::IsNullOrWhiteSpace($nonce) -or [string]::IsNullOrWhiteSpace($provided)){return $null}
    if($expected -ne [string]$script:Config.HostName -and $expected -ne [string]$script:Config.HostId){return $null}
    foreach($key in @($script:SeenRequestNonces.Keys)){if(($now-[int64]$script:SeenRequestNonces[$key])-gt 120){$script:SeenRequestNonces.Remove($key)}}
    $material=([string]$Context.Request.HttpMethod.ToUpperInvariant()+"`n"+[string]$Context.Request.Url.AbsolutePath+"`n"+$timestamp+"`n"+$nonce+"`n"+$body+"`n"+$expected)
    $hmac=[Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes([string]$script:Token));try{$actual=([BitConverter]::ToString($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($material)))-replace '-','').ToLowerInvariant()}finally{$hmac.Dispose()}
    $left=[Text.Encoding]::UTF8.GetBytes($actual);$right=[Text.Encoding]::UTF8.GetBytes($provided.ToLowerInvariant())
    if($left.Length -ne $right.Length -or -not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals($left,$right)){return $null}
    if($script:SeenRequestNonces.ContainsKey($nonce)){return $null}
    $script:SeenRequestNonces[$nonce]=$now;Save-NonceState $now
    return [pscustomobject]@{Body=$body}
}

if($LibraryOnly){return}
$workerScript = {
    param([string]$ScriptPath,[string]$ConfigPath,[psobject]$Request)
    . $ScriptPath -ConfigPath $ConfigPath -LibraryOnly
    try {
        $path=$Request.path.TrimEnd('/');$method=$Request.method.ToUpperInvariant();$payload=if($Request.body){$Request.body|ConvertFrom-Json -AsHashtable}else{@{}}
        $parts=$path.Trim('/').Split('/');$runtimeId=if($parts.Count -ge 3){[uri]::UnescapeDataString($parts[2])}else{''}
        if($method -eq 'GET' -and $path -eq '/v1/host'){ $result=[ordered]@{ok=$true;host_id=$script:Config.HostId;host_name=$script:Config.HostName;agent_version=$script:AgentVersion;provider='multipass';capacity=Get-HostCapacity} }
        elseif($method -eq 'GET' -and $path -eq '/v1/host/capacity'){ $result=[ordered]@{ok=$true;host_name=$script:Config.HostName;capacity=Get-HostCapacity} }
        elseif($method -eq 'GET' -and $path -eq '/v1/provider'){ $result=[ordered]@{ok=$true;host_name=$script:Config.HostName;provider='multipass';provider_version=$script:Config.MultipassVersion;gpu_enabled=$false} }
        elseif($parts.Count -lt 2 -or $parts[0] -ne 'v1' -or $parts[1] -ne 'project-vms'){ throw 'Not found.' }
        elseif($method -eq 'POST' -and $parts.Count -eq 2){$limits=$payload.resource_limits;if(-not $limits){throw 'resource_limits is required.'};$result=Ensure-ProjectVm ([string]$payload.slug) ([string]$payload.project_id) ([double]$limits.cpus) ([double]$limits.memory_gb) ([double]$limits.disk_gb) ([string]$payload.git_url)}
        elseif($method -eq 'GET' -and $parts.Count -eq 3){$slug=Get-ProjectSlugByRuntime $runtimeId;$record=Assert-OwnedProjectVm $slug $runtimeId;$result=[ordered]@{ok=$true;host_name=$script:Config.HostName;runtime_id=$record.runtime_id;record=$record;info=Get-ProjectVmInfo $record.vm_name;gpu_enabled=$false}}
        elseif($parts.Count -ne 4){throw 'Not found.'}
        else {$operation=$parts[3];if($method -eq 'DELETE'){$result=Invoke-ProjectVmOperation 'destroy' $payload $runtimeId}elseif($method -eq 'POST'){$result=Invoke-ProjectVmOperation $operation $payload $runtimeId}else{throw 'Method not allowed.'}}
        [pscustomobject]@{status=200;body=$result}
    } catch { [pscustomobject]@{status=400;body=[ordered]@{ok=$false;error=$_.Exception.Message}} }
}
$listener=[Net.HttpListener]::new();$listener.Prefixes.Add([string]$script:Config.ListenPrefix);$listener.Start();Write-AgentLog 'agent' '' '' 'started' "Listening on $($script:Config.ListenPrefix)"
$pool=[System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1,4);$pool.Open()
$jobs=[Collections.Generic.List[object]]::new();$accept=$listener.BeginGetContext($null,$null)
try {
    while($listener.IsListening) {
        if($accept.IsCompleted) {
            $context=$null;$auth=$null;$responseAuth=$null
            try {
                $context=$listener.EndGetContext($accept);$accept=$listener.BeginGetContext($null,$null);$path=$context.Request.Url.AbsolutePath.TrimEnd('/');$method=$context.Request.HttpMethod.ToUpperInvariant()
                $auth=Test-RequestToken $context
                if(-not $auth){Send-JsonResponse $context @{ok=$false;error='Unauthorized.'} 401;continue}
                $responseAuth=[pscustomobject]@{Timestamp=[string]$context.Request.Headers['X-DevFleet-Host-Timestamp'];Nonce=[string]$context.Request.Headers['X-DevFleet-Host-Nonce'];Expected=[string]$context.Request.Headers['X-DevFleet-Host-Expected'];Method=$method;Path=$path}
                if($method -eq 'GET' -and $path -eq '/healthz'){Send-AuthenticatedJsonResponse $context ([ordered]@{ok=$true;service='devfleet-host-agent';agent_version=$script:AgentVersion;host_name=$script:Config.HostName;host_id=$script:Config.HostId}) 200 $responseAuth;continue}
                if($jobs.Count -ge 4){Send-AuthenticatedJsonResponse $context ([ordered]@{ok=$false;error='Host Agent is busy; retry this request.'}) 503 $responseAuth;continue}
                $ps=[PowerShell]::Create();$ps.RunspacePool=$pool;[void]$ps.AddScript($workerScript).AddArgument($PSCommandPath).AddArgument($ConfigPath).AddArgument([pscustomobject]@{path=$path;method=$method;body=[string]$auth.Body});$async=$ps.BeginInvoke();$jobs.Add([pscustomobject]@{PowerShell=$ps;Async=$async;Context=$context;Auth=$responseAuth})
            } catch { try{if($auth -and $responseAuth){Send-AuthenticatedJsonResponse $context ([ordered]@{ok=$false;error=$_.Exception.Message}) 400 $responseAuth}else{Send-JsonResponse $context @{ok=$false;error=$_.Exception.Message} 400}}catch{} }
        }
        for($i=$jobs.Count-1;$i -ge 0;$i--) {
            $job=$jobs[$i]
            if(-not $job.Async.IsCompleted){continue}
            try{$output=$job.PowerShell.EndInvoke($job.Async);$response=if($output.Count -gt 0){$output[$output.Count-1]}else{[pscustomobject]@{status=500;body=@{ok=$false;error='Worker returned no response.'}}};Send-AuthenticatedJsonResponse $job.Context $response.body ([int]$response.status) $job.Auth}
            catch{try{Send-AuthenticatedJsonResponse $job.Context ([ordered]@{ok=$false;error='Host Agent worker failed.'}) 500 $job.Auth}catch{}}
            finally{$job.PowerShell.Dispose();$jobs.RemoveAt($i)}
        }
        $pollMilliseconds=if($jobs.Count -gt 0){20}else{200}
        Start-Sleep -Milliseconds $pollMilliseconds
    }
} finally {
    try{$listener.Stop();$listener.Close()}catch{}
    foreach($job in @($jobs)){try{$job.PowerShell.Stop()}catch{};try{$job.PowerShell.Dispose()}catch{}}
    try{$pool.Close();$pool.Dispose()}catch{}
    Write-AgentLog 'agent' '' '' 'stopped' 'Host agent listener stopped.'
}
