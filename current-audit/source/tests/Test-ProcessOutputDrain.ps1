$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'windows\DevFleet.Common.psm1') -Force

$shell=(Get-Command powershell.exe -ErrorAction Stop).Source
$normal=Invoke-External -FilePath $shell -ArgumentList @('-NoProfile','-NonInteractive','-Command',"[Console]::Out.Write('complete-output')") -Capture
if($normal -cne 'complete-output'){throw 'Invoke-External did not preserve ordinary complete output.'}

$pidPath=Join-Path ([IO.Path]::GetTempPath()) ("devfleet-common-inherited-pipe-"+[guid]::NewGuid().ToString('N')+'.pid')
$descendantPid=0
try{
    $escapedPidPath=$pidPath.Replace("'","''")
    $parentCommand="`$childInfo=[Diagnostics.ProcessStartInfo]::new();`$childInfo.FileName=(Get-Command powershell.exe).Source;`$childInfo.UseShellExecute=`$false;`$childInfo.CreateNoWindow=`$true;`$childInfo.ArgumentList.Add('-NoProfile');`$childInfo.ArgumentList.Add('-NonInteractive');`$childInfo.ArgumentList.Add('-Command');`$childInfo.ArgumentList.Add('Start-Sleep -Seconds 30');`$child=[Diagnostics.Process]::Start(`$childInfo);[IO.File]::WriteAllText('$escapedPidPath',[string]`$child.Id);exit 0"
    $timer=[Diagnostics.Stopwatch]::StartNew();$blocked=$false
    try{Invoke-External -FilePath $shell -ArgumentList @('-NoProfile','-NonInteractive','-Command',$parentCommand) -Capture|Out-Null}catch{if($_.Exception.Message -match 'redirected output was incomplete after the bounded post-exit drain'){$blocked=$true}else{throw}}
    $timer.Stop()
    if(-not $blocked -or $timer.Elapsed -ge [TimeSpan]::FromSeconds(15)){throw 'Invoke-External did not fail closed within the bounded post-exit drain allowance.'}
    if(-not(Test-Path -LiteralPath $pidPath) -or -not [int]::TryParse([IO.File]::ReadAllText($pidPath),[ref]$descendantPid)){throw 'Invoke-External inherited-handle fixture did not publish its descendant PID.'}
    $descendant=Get-Process -Id $descendantPid -ErrorAction Stop
    if($descendant.HasExited){throw 'Invoke-External killed a descendant merely to manufacture redirected-output EOF.'}
}finally{
    if($descendantPid -gt 0){Stop-Process -Id $descendantPid -Force -ErrorAction SilentlyContinue}
    Remove-Item -LiteralPath $pidPath -Force -ErrorAction SilentlyContinue
}

$computeSource=Get-Content -LiteralPath (Join-Path $root 'windows\02-Provision-ComputeNode.ps1') -Raw
if($computeSource -notmatch "(?m)^\s*Invoke-External\s+\`$mp\s+@\('exec'.*?\)\s+-TimeoutSeconds\s+\(Get-DevFleetOperationMaximumSeconds 'guestBootstrap'\)\s+-StandardInputText"){
    throw 'Compute bootstrap execution must use the authoritative guest bootstrap operation budget.'
}
$vaultSource=Get-Content -LiteralPath (Join-Path $root 'windows\03-Provision-Vault.ps1') -Raw
if($vaultSource -notmatch "(?m)^\s*Invoke-External\s+\`$mp\s+@\('exec'.*?\)\s+-TimeoutSeconds\s+\(Get-DevFleetOperationMaximumSeconds 'guestBootstrap'\)\s*$"){
    throw 'Vault bootstrap execution must use the authoritative guest bootstrap operation budget.'
}

[ordered]@{ok=$true;tests=4;ordinaryCompleteOutput=$true;inheritedPipeFailsClosedBoundedly=$true;computeBootstrapBudgetBound=$true;vaultBootstrapBudgetBound=$true}|ConvertTo-Json -Compress
