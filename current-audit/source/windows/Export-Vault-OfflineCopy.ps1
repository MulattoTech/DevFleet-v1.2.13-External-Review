[CmdletBinding()]
param([string]$DestinationDirectory)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
Assert-Administrator
$config=Get-DevFleetConfig;$mp=Get-MultipassExe;$name=$config.Vault.InstanceName
if(-not (Test-MultipassInstance $name)){throw 'The local DevFleet vault VM was not found.'}
if(-not $DestinationDirectory){
  $default=Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'DevFleet-Offline-Vault-Copies'
  $entered=Read-Host "Destination folder [$default] (an external drive is preferable)"
  $DestinationDirectory=if($entered){$entered}else{$default}
}
New-Item -ItemType Directory -Path $DestinationDirectory -Force|Out-Null
$stamp=(Get-Date).ToString('yyyyMMdd-HHmmss')
$remote="/tmp/devfleet-vault-$stamp.tar.gz"
$local=Join-Path $DestinationDirectory "devfleet-vault-$stamp.tar.gz"
Write-Host 'Temporarily stopping the REST service to make a consistent encrypted repository copy...' -ForegroundColor Cyan
$command="set -Eeuo pipefail; systemctl stop rest-server; trap 'systemctl start rest-server' EXIT; tar -C /srv -czf '$remote' restic; chown ubuntu:ubuntu '$remote'; chmod 0640 '$remote'; systemctl start rest-server; trap - EXIT"
Invoke-External $mp @('exec',$name,'--','sudo','bash','-lc',$command)
try{Invoke-External $mp @('transfer',"${name}:$remote",$local)}
finally{Invoke-External $mp @('exec',$name,'--','sudo','rm','-f',$remote) -IgnoreExitCode}
$hash=Get-FileHash -Algorithm SHA256 -Path $local
"$($hash.Hash.ToLower())  $([IO.Path]::GetFileName($local))"|Set-Content "$local.sha256" -Encoding ascii
Write-Host "Offline encrypted vault copy: $local" -ForegroundColor Green
Write-Host "SHA-256: $($hash.Hash)" -ForegroundColor Green
