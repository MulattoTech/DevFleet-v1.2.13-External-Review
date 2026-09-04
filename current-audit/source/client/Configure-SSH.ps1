[CmdletBinding()]param([switch]$SkipConnectivityTest)
$ErrorActionPreference='Stop';$root=Split-Path -Parent $PSScriptRoot;Import-Module (Join-Path $root 'windows\DevFleet.Common.psm1') -Force;$config=Get-DevFleetConfig;$key=Get-OrCreateDevFleetSshKey;$sshDir=Join-Path $env:USERPROFILE '.ssh';New-Item -ItemType Directory $sshDir -Force|Out-Null;$configFile=Join-Path $sshDir 'config';$begin='# BEGIN DEVFLEET MANAGED';$end='# END DEVFLEET MANAGED';$existing=if(Test-Path $configFile){Get-Content $configFile -Raw}else{''}
function Resolve-Host([string]$Instance){$mp=Get-MultipassExe;$raw=Invoke-External $mp @('exec',$Instance,'--','tailscale','ip','-4') -Capture;return ($raw -split "`n"|Select-Object -First 1).Trim()}
$blocks=@();foreach($n in @($config.Primary,$config.Failover)){try{$hostName=Resolve-Host $n.InstanceName}catch{$hostName=$n.InstanceName};$blocks+=@"
Host $($n.SshAlias)
    HostName $hostName
    User devrunner
    IdentityFile $($key.Replace('\','/'))
    IdentitiesOnly yes
    ServerAliveInterval 30
    ServerAliveCountMax 4
    TCPKeepAlive yes
    Compression yes
    ForwardAgent no
"@}
$managed=$begin+"`n"+($blocks -join "`n")+$end;if($existing -match '(?s)# BEGIN DEVFLEET MANAGED.*?# END DEVFLEET MANAGED'){$existing=[regex]::Replace($existing,'(?s)# BEGIN DEVFLEET MANAGED.*?# END DEVFLEET MANAGED',$managed)}else{$existing=$existing.TrimEnd()+"`n`n"+$managed+"`n"};Set-Content $configFile $existing -Encoding utf8;if(-not $SkipConnectivityTest){& ssh.exe -o BatchMode=yes -o ConnectTimeout=10 $config.Primary.SshAlias 'echo DevFleet SSH OK'};Write-Host "SSH aliases configured: $($config.Primary.SshAlias), $($config.Failover.SshAlias)" -ForegroundColor Green
