[CmdletBinding()]
param([Parameter(Mandatory)][string]$InstanceName,[ValidateSet('Dashboard','VSCode')][string]$Mode='Dashboard')
$ErrorActionPreference='Stop'
$InstanceName = $InstanceName.Trim() -replace '^(?i:devfleet-)+',''
$InstanceName = "devfleet-$InstanceName"
try {
 Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
 $config=Get-DevFleetConfig;$mp=Get-MultipassExe
 Assert-MultipassIsolation -InstanceNames @($InstanceName)
 Invoke-External $mp @('start',$InstanceName) -IgnoreExitCode
 Wait-MultipassReady $InstanceName 300
 $ip=Get-InstanceIPv4 $InstanceName -PreferTailscale
 if(-not $ip){throw 'Could not determine the DevFleet VM IP address.'}
 if($Mode -eq 'Dashboard'){
  $port=[int]$config.Network.PortalPort
  if(-not (Test-NetConnection -ComputerName $ip -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue)){
   throw "The DevFleet VM is running, but its dashboard is not reachable at http://${ip}:$port/. The DevFleet service may still be starting; wait one minute and try again."
  }
  Start-Process "http://${ip}:$port/"
 }else{
  $sshDir=Join-Path $env:USERPROFILE '.ssh';New-Item -ItemType Directory $sshDir -Force|Out-Null
  $cfg=Join-Path $sshDir 'config';$alias=$InstanceName
  $block=@"
Host $alias
    HostName $ip
    User devrunner
    IdentityFile $(Get-OrCreateDevFleetSshKey)
    IdentitiesOnly yes
    StrictHostKeyChecking accept-new
"@
  $existing=if(Test-Path $cfg){Get-Content $cfg -Raw}else{''}
  if($existing -notmatch "(?m)^Host\s+$([regex]::Escape($alias))$"){Add-Content $cfg "`n$block"}
  $code=Get-VsCodeCli -AllowPerUser
  if(-not $code){throw 'VS Code CLI not found.'}
  & $code --remote "ssh-remote+$alias" "/home/devrunner/workspaces"
 }
} catch {
 $message = "DevFleet could not open. $($_.Exception.Message)`n`nNo VM was recreated or reprovisioned."
 Write-Error $message
 try { (New-Object -ComObject WScript.Shell).Popup($message,0,'DevFleet launch problem',0x10) | Out-Null } catch { }
 exit 1
}
