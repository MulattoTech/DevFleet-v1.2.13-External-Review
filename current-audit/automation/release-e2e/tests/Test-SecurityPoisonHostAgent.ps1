[CmdletBinding()]
param([string]$WorkspaceRoot)
$ErrorActionPreference='Stop'
if(-not $WorkspaceRoot){$WorkspaceRoot=(Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path}
$agent=Join-Path $WorkspaceRoot 'source\windows\DevFleet-HostAgent.ps1'
$testRoot=Join-Path ([IO.Path]::GetTempPath()) "devfleet-security-poison-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $testRoot -Force|Out-Null
try {
    $tokenPath=Join-Path $testRoot 'token.txt';[IO.File]::WriteAllText($tokenPath,('x'*48))
    $configPath=Join-Path $testRoot 'config.json'
    $config=[ordered]@{
        HostId='SECURITY-POISON-HOST';HostName='SECURITY-POISON-HOST';TokenPath=$tokenPath
        MultipassPath=(Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe')
        SshConfigPath=(Join-Path $testRoot 'ssh-config');SshKnownHostsPath=(Join-Path $testRoot 'known-hosts')
        SshPrivateKeyPath=(Join-Path $testRoot 'key');BootTimeoutSeconds=1;UbuntuImage='test-image'
        ResourcePolicy=@{MaxProjectCpus=8;MaxProjectMemoryGb=32;MaxProjectDiskGb=500}
    }
    $config|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $configPath -Encoding utf8
    . $agent -ConfigPath $configPath -LibraryOnly
    $registry=Read-Registry;Write-Registry $registry

    # Multiple independent pwsh processes exercise the real inter-process mutex,
    # latest-read transaction, and atomic replacement. Every worker owns a distinct
    # project record; a missing record proves a lost update.
    $workerPath=Join-Path $testRoot 'registry-worker.ps1'
    $worker=@'
param()
$ErrorActionPreference='Stop'
$Agent=$env:DEVFLEET_SECURITY_AGENT;$Config=$env:DEVFLEET_SECURITY_CONFIG;$Slug=$env:DEVFLEET_SECURITY_SLUG;$Index=[int]$env:DEVFLEET_SECURITY_INDEX
. $Agent -ConfigPath $Config -LibraryOnly
$record=@{managed_by='devfleet';host_id='SECURITY-POISON-HOST';project_id=([guid]::NewGuid().ToString());slug=$Slug;runtime_id="runtime-$Slug";vm_name="vm-$Slug";state='ready';worker=$Index;updated_at=(Get-Date).ToUniversalTime().ToString('o')}
Update-ProjectRecord $Slug $record|Out-Null
'PASS'
'@
    [IO.File]::WriteAllText($workerPath,$worker)
    $processes=[Collections.Generic.List[Diagnostics.Process]]::new()
    for($i=0;$i -lt 24;$i++){
        $slug="parallel-$i"
        $psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName=(Get-Command pwsh.exe).Source;$psi.UseShellExecute=$false
        $psi.Arguments="-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$workerPath`""
        $psi.Environment['DEVFLEET_SECURITY_AGENT']=$agent;$psi.Environment['DEVFLEET_SECURITY_CONFIG']=$configPath;$psi.Environment['DEVFLEET_SECURITY_SLUG']=$slug;$psi.Environment['DEVFLEET_SECURITY_INDEX']=[string]$i
        $p=[Diagnostics.Process]::new();$p.StartInfo=$psi;if(-not $p.Start()){throw "Could not start registry worker $i"};$processes.Add($p)
    }
    foreach($p in $processes){if(-not $p.WaitForExit(60000)){try{$p.Kill($true)}catch{};throw 'Registry worker timed out.'};if($p.ExitCode -ne 0){throw "Registry worker failed with $($p.ExitCode)."}}
    $after=Read-Registry
    $missing=@(0..23|Where-Object{-not $after.projects.ContainsKey("parallel-$_")})
    if($missing.Count -gt 0){throw "Registry lost $($missing.Count) concurrent project updates: $($missing -join ',')."}
    $json=Get-Content -LiteralPath $script:RegistryPath -Raw|ConvertFrom-Json
    if(@($json.projects.PSObject.Properties).Count -lt 24){throw 'Concurrent registry result was not valid complete JSON.'}

    # Repeat the TOCTOU collision at launch. The foreign VM is created only by the
    # fake launch boundary; launch_succeeded remains false, so cleanup must never
    # issue delete/purge and the foreign inventory remains observable.
    $raceResults=[Collections.Generic.List[object]]::new()
    function Assert-ResourceRequest { }
    function New-CloudInit { param([string]$Slug,[string]$ProjectId,[string]$GitUrl,[string]$ProvisioningAttemptId);return 'fixture-cloud-init' }
    function Get-MultipassVms { if($script:ForeignCreated){return @([pscustomobject]@{name=$script:ForeignName;state='RUNNING'})};return @() }
    function Invoke-Multipass {
        param([string[]]$ArgumentList,[int]$TimeoutSeconds=120)
        if([string]$ArgumentList[0] -eq 'launch'){$script:ForeignCreated=$true;throw 'fixture same-name foreign launch collision'}
        if([string]$ArgumentList[0] -eq 'delete'){$script:DeleteCalls++;throw 'DELETE MUST NOT BE CALLED AGAINST FOREIGN VM'}
        return [pscustomobject]@{ExitCode=0;Text=''}
    }
    for($i=0;$i -lt 20;$i++){
        $script:ForeignName="devfleet-project-race-$i";$script:ForeignCreated=$false;$script:DeleteCalls=0
        $projectId=[guid]::NewGuid().ToString();$threw=$false
        try{Ensure-ProjectVm "race-$i" $projectId 1 2 20}catch{$threw=$true}
        if(-not $threw -or -not $script:ForeignCreated -or $script:DeleteCalls -ne 0){throw "Same-name race iteration $i did not fail closed."}
        $raceResults.Add([ordered]@{iteration=$i;operation='Ensure-ProjectVm';launch='collision';foreignVmSurvived=$true;deletePurges=0;registryClaimRemoved=(-not (Read-Registry).projects.ContainsKey("race-$i"))})
    }
    if(@($raceResults|Where-Object{-not $_.registryClaimRemoved}).Count -gt 0){throw 'Failed launch left a provisional registry claim.'}
    [ordered]@{status='PASS';schemaVersion=1;registryConcurrency=[ordered]@{iterations=24;lostUpdates=0;validJson=$true};sameNameVmToctou=[ordered]@{iterations=20;foreignVmSurvived=$true;purgesAgainstForeign=0;provisionalClaims=0};evidenceScope='owned temporary fixture resources only'}|ConvertTo-Json -Depth 12 -Compress
}finally{Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue}
