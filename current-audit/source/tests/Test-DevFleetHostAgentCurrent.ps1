$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ("devfleet-current-hostagent-"+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot -Force|Out-Null
try {
    $tokenPath=Join-Path $testRoot 'token.txt';[IO.File]::WriteAllText($tokenPath,('x'*48))
    $configPath=Join-Path $testRoot 'config.json';$sshConfig=Join-Path $testRoot 'ssh-config';$knownHosts=Join-Path $testRoot 'known-hosts'
    @{HostId='mulattotechbox';HostName='MULATTOTECHBOX';TokenPath=$tokenPath;MultipassPath='multipass.exe';SshConfigPath=$sshConfig;SshKnownHostsPath=$knownHosts;SshPrivateKeyPath=(Join-Path $testRoot 'key')}|ConvertTo-Json|Set-Content -LiteralPath $configPath
    . (Join-Path $root 'windows\DevFleet-HostAgent.ps1') -ConfigPath $configPath -LibraryOnly

    $shell=(Get-Command powershell.exe -ErrorAction Stop).Source
    $script:Multipass=$shell
    $pidPath=Join-Path $testRoot 'hostagent-inherited-pipe.pid';$descendantPid=0
    try{
        $escapedPidPath=$pidPath.Replace("'","''")
        $parentCommand="`$childInfo=[Diagnostics.ProcessStartInfo]::new();`$childInfo.FileName=(Get-Command powershell.exe).Source;`$childInfo.UseShellExecute=`$false;`$childInfo.CreateNoWindow=`$true;`$childInfo.ArgumentList.Add('-NoProfile');`$childInfo.ArgumentList.Add('-NonInteractive');`$childInfo.ArgumentList.Add('-Command');`$childInfo.ArgumentList.Add('Start-Sleep -Seconds 30');`$child=[Diagnostics.Process]::Start(`$childInfo);[IO.File]::WriteAllText('$escapedPidPath',[string]`$child.Id);exit 0"
        $timer=[Diagnostics.Stopwatch]::StartNew();$blocked=$false
        try{Invoke-Multipass @('-NoProfile','-NonInteractive','-Command',$parentCommand) 20|Out-Null}catch{if($_.Exception.Message -match 'redirected output was incomplete after the bounded post-exit drain'){$blocked=$true}else{throw}}
        $timer.Stop()
        if(-not $blocked -or $timer.Elapsed -ge [TimeSpan]::FromSeconds(15)){throw 'Host Agent Multipass runner did not fail closed within the bounded post-exit drain allowance.'}
        if(-not(Test-Path -LiteralPath $pidPath) -or -not [int]::TryParse([IO.File]::ReadAllText($pidPath),[ref]$descendantPid)){throw 'Host Agent inherited-handle fixture did not publish its descendant PID.'}
        $descendant=Get-Process -Id $descendantPid -ErrorAction Stop
        if($descendant.HasExited){throw 'Host Agent runner killed a descendant merely to manufacture redirected-output EOF.'}
    }finally{
        if($descendantPid -gt 0){Stop-Process -Id $descendantPid -Force -ErrorAction SilentlyContinue}
        Remove-Item -LiteralPath $pidPath -Force -ErrorAction SilentlyContinue
        $script:Multipass='multipass.exe'
    }

    $runtime='devfleet-project-demo-project'
    [IO.File]::WriteAllText($knownHosts,"unrelated.example ssh-ed25519 AAAAunrelated`r`n")
    $markers=Get-ProjectVmKnownHostMarkers $runtime
    $first="$($markers.Begin)`r`n$runtime ssh-ed25519 AAAAfirst`r`n$($markers.End)"
    Set-DevFleetManagedTextBlock $knownHosts $markers.Pattern $first|Out-Null
    $initial=[IO.File]::ReadAllText($knownHosts)
    if($initial -notmatch 'AAAAfirst' -or $initial -notmatch 'AAAAunrelated'){throw 'Initial managed host-key pin did not preserve unrelated content.'}
    Set-DevFleetManagedTextBlock $knownHosts $markers.Pattern $first|Out-Null
    if([IO.File]::ReadAllText($knownHosts) -cne $initial){throw 'Re-syncing the same host key was not idempotent.'}
    $second="$($markers.Begin)`r`n$runtime ssh-ed25519 AAAAsecond`r`n$($markers.End)"
    Set-DevFleetManagedTextBlock $knownHosts $markers.Pattern $second|Out-Null
    $changed=[IO.File]::ReadAllText($knownHosts)
    if($changed -match 'AAAAfirst' -or $changed -notmatch 'AAAAsecond' -or $changed -notmatch 'AAAAunrelated'){throw 'Host-key rotation changed unrelated known-host content.'}

    $aliasMarkers=Get-ProjectVmSshMarkers $runtime
    [IO.File]::WriteAllText($sshConfig,"Host unrelated`r`n    HostName 192.0.2.10`r`n`r`n$($aliasMarkers.Begin)`r`nHost $runtime`r`n$($aliasMarkers.End)`r`n")
    Remove-ProjectVmSshAlias $runtime '12345678-1234-1234-1234-123456789abc'
    if((Get-Content -LiteralPath $sshConfig -Raw) -notmatch 'Host unrelated' -or (Get-Content -LiteralPath $sshConfig -Raw) -match [regex]::Escape($runtime)){throw 'Alias removal did not preserve unrelated SSH config.'}
    if((Get-Content -LiteralPath $knownHosts -Raw) -notmatch 'AAAAunrelated' -or (Get-Content -LiteralPath $knownHosts -Raw) -match 'AAAAsecond'){throw 'Host-key removal did not preserve unrelated entries.'}

    $bad=@{state='ready';managed_by='someone-else';host_id='mulattotechbox';runtime_id=$runtime;vm_name=$runtime;project_id='12345678-1234-1234-1234-123456789abc'}
    try {Remove-ImportFailedProjectVm 'demo-project' $bad @{backup_verified=$true;backup_id='backup';backup_sha256=('a'*64);local_archive_sha256=('b'*64);cleanup_stage='pre-import'}|Out-Null;throw 'Unowned VM cleanup unexpectedly succeeded.'} catch {if($_.Exception.Message -notmatch 'ownership registry'){throw}}

    $script:Alive=@{}
    function Get-MultipassVms {return @($script:Alive.GetEnumerator()|Where-Object{$_.Value}|ForEach-Object{[pscustomobject]@{name=$_.Key;state='RUNNING'}})}
    function Get-ProjectVmInfo {param([string]$VmName);return [pscustomobject]@{state='RUNNING'}}
    function New-ProvisioningLock {$lock=[pscustomobject]@{};$lock|Add-Member ScriptMethod ReleaseMutex {};$lock|Add-Member ScriptMethod Dispose {};return $lock}
    function Invoke-Multipass {
        param([string[]]$ArgumentList,[int]$TimeoutSeconds=120)
        $vm=[string]$ArgumentList[1]
        if($ArgumentList[0] -eq 'delete'){$script:Alive[$vm]=$false;return [pscustomobject]@{ExitCode=0;Text=''}}
        if($ArgumentList[0] -eq 'exec' -and ($ArgumentList -contains '/etc/devfleet/project-runtime.json')){$slug=$vm.Substring('devfleet-project-'.Length);return [pscustomobject]@{ExitCode=0;Text=(@{managed_by='devfleet';slug=$slug;project_id='12345678-1234-1234-1234-123456789abc'}|ConvertTo-Json -Compress)}}
        if($ArgumentList[0] -eq 'exec' -and ($ArgumentList|Where-Object{$_ -like '*/.devfleet/project.json'})){$slug=$vm.Substring('devfleet-project-'.Length);return [pscustomobject]@{ExitCode=0;Text=(@{slug=$slug;identity=$slug;project_id='12345678-1234-1234-1234-123456789abc'}|ConvertTo-Json -Compress)}}
        return [pscustomobject]@{ExitCode=0;Text=''}
    }
    foreach($case in @(@{slug='pre-import';stage='pre-import'},@{slug='post-import';stage='post-import'})){
        $vm="devfleet-project-$($case.slug)";$script:Alive[$vm]=$true
        $record=@{slug=$case.slug;state='ready';managed_by='devfleet';host_id='mulattotechbox';runtime_id=$vm;vm_name=$vm;project_id='12345678-1234-1234-1234-123456789abc';cpus=4;memory_gb=8;disk_gb=80}
        $registry=Read-Registry;$registry.projects[$case.slug]=$record;Write-Registry $registry
        $payload=@{backup_verified=$true;backup_id='backup';backup_sha256=('a'*64);local_archive_sha256=('b'*64);import_archive_sha256='';cleanup_stage=$case.stage}
        $result=Remove-ImportFailedProjectVm $case.slug $record $payload
        if(-not $result.allocation_released -or $result.state -ne 'destroyed' -or $script:Alive[$vm]){throw "$($case.stage) cleanup did not release its allocation."}
        if((Read-Registry).projects[$case.slug].state -ne 'destroyed'){throw "$($case.stage) cleanup did not persist the destroyed state."}
    }
    [ordered]@{ok=$true;tests=8;bounded_output_drain=$true;initial_pin=$true;idempotent_resync=$true;rotated_pin=$true;unrelated_preserved=$true;selective_remove=$true;unowned_refused=$true;pre_and_post_import_cleanup=$true}|ConvertTo-Json -Compress
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
