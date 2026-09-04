[CmdletBinding()]
param([switch]$ForceReprovision)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
Assert-PowerShell7;Assert-Administrator
$deadlineContext=Get-DevFleetDeadlineContext
if(-not $deadlineContext){$fallbackDeadline=[DateTime]::UtcNow.AddSeconds((Get-DevFleetStageBudgetSeconds 'vault'));Set-DevFleetDeadlineContext -TransactionDeadlineUtc $fallbackDeadline -StageName 'vault' -StageBudgetSeconds (Get-DevFleetStageBudgetSeconds 'vault') | Out-Null}
$config=Get-DevFleetConfig;$v=$config.Vault;$name=$v.InstanceName;$mp=Get-MultipassExe;$package=Get-PackageRootFromState;$secrets=Get-OrCreateSecrets;$vaultIdentity=Get-OrCreateVaultIdentity
Assert-MultipassIsolation -InstanceNames @($name)
if(Test-MultipassInstance $name){
 if($ForceReprovision){throw 'Refusing automatic destruction of an existing backup vault.'}
 New-DevFleetSnapshotSafe -InstanceName $name -SnapshotName "pre-refresh-$((Get-Date).ToString('yyyyMMdd-HHmmss'))"|Out-Null
 Invoke-External $mp @('start',$name) -IgnoreExitCode
 Write-Host "$name already exists; refreshing safe configuration." -ForegroundColor Yellow
}else{
 $cloud=Join-Path (Get-DevFleetStateRoot) "tmp\cloud-$name.yaml"
 (Get-Content (Join-Path $package 'cloud-init\vault.yaml') -Raw).Replace('__NODE_NAME__',(ConvertTo-YamlSingleQuotedScalar $name))|Set-Content $cloud -Encoding utf8
 Invoke-External $mp @('launch',[string]$v.UbuntuImage,'--name',$name,'--cpus',[string]$v.Cpus,'--memory',[string]$v.Memory,'--disk',[string]$v.Disk,'--cloud-init',$cloud)
 Wait-MultipassReady $name 1200
}
$tmp=Join-Path (Get-DevFleetStateRoot) 'tmp\vault-payload';Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue;New-Item -ItemType Directory $tmp -Force|Out-Null
Copy-Item (Join-Path $package 'linux') $tmp -Recurse
[ordered]@{VaultPort=$config.Network.VaultPort;RestUser=$secrets.VaultRestUser;RestPassword=$secrets.VaultRestPassword;ResticPassword=$secrets.ResticPassword;ClusterName=$config.ClusterName;DeploymentId=$vaultIdentity.deployment_id;NodeId=$vaultIdentity.node_id;NodeName=$vaultIdentity.node_name}|ConvertTo-Json|Set-Content (Join-Path $tmp 'vault-secrets.json') -Encoding utf8
$zip=Join-Path (Get-DevFleetStateRoot) 'tmp\vault-payload.zip';Remove-Item $zip -Force -ErrorAction SilentlyContinue;Compress-Archive -Path (Join-Path $tmp '*') -DestinationPath $zip
try {
 Invoke-External $mp @('transfer',$zip,"${name}:/tmp/devfleet-vault-payload.zip")
 $remote='set -Eeuo pipefail; trap ''sudo rm -rf /tmp/devfleet-vault-payload /tmp/devfleet-vault-payload.zip'' EXIT; sudo rm -rf /tmp/devfleet-vault-payload; mkdir /tmp/devfleet-vault-payload; unzip -q /tmp/devfleet-vault-payload.zip -d /tmp/devfleet-vault-payload; sudo bash /tmp/devfleet-vault-payload/linux/bootstrap-vault.sh /tmp/devfleet-vault-payload'
 Invoke-External $mp @('exec',$name,'--','bash','-lc',$remote) -TimeoutSeconds (Get-DevFleetOperationMaximumSeconds 'guestBootstrap')
} finally {
 Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
 Remove-Item $zip -Force -ErrorAction SilentlyContinue
}
Write-StageMarker 'vault';Write-Host "$name provisioned. Do not delete or purge this instance." -ForegroundColor Green
