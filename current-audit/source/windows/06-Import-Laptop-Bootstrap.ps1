[CmdletBinding()]
param([Parameter(Mandatory)][ValidateScript({Test-Path $_})][string]$BundlePath)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
$config=Get-DevFleetConfig;$mp=Get-MultipassExe;$dest=Join-Path (Get-DevFleetStateRoot) 'tmp\import-laptop';$peerFile=$null;Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue
Expand-EncryptedBundle -BundlePath $BundlePath -Destination $dest
try {
$vault=Get-Content (Join-Path $dest 'vault-client.json') -Raw|ConvertFrom-Json
$tmp=Join-Path (Get-DevFleetStateRoot) 'secrets\vault-client.json';$vault|ConvertTo-Json|Set-Content $tmp -Encoding utf8
Protect-DevFleetStateAcl
$name=$config.Primary.InstanceName
Invoke-External $mp @('transfer',$tmp,"${name}:/tmp/vault-client.json")
Invoke-External $mp @('exec',$name,'--','sudo','/usr/local/sbin/devfleet-configure-backup','/tmp/vault-client.json')
$peer=Get-Content (Join-Path $dest 'failover-pairing.json') -Raw|ConvertFrom-Json
$surrogate=Get-Content (Join-Path $dest 'surrogate-node.json') -Raw|ConvertFrom-Json
$primaryIdentity=Get-OrCreateNodeIdentity -Role Desktop
if($surrogate.node_role -ne 'surrogate' -or -not $surrogate.node_id -or -not $primaryIdentity.deployment_id){throw 'Surrogate or Primary registration metadata is incomplete.'}
$surrogate.deployment_id=$primaryIdentity.deployment_id;$surrogate.coordinator_node_id=$primaryIdentity.node_id;$surrogate.protocol_version=$primaryIdentity.protocol_version
$peerFile=Join-Path (Get-DevFleetStateRoot) 'tmp\peer.json';$peer|ConvertTo-Json|Set-Content $peerFile -Encoding utf8
Invoke-External $mp @('transfer',$peerFile,"${name}:/tmp/peer.json")
Invoke-External $mp @('exec',$name,'--','sudo','/usr/local/sbin/devfleet-set-peer','/tmp/peer.json')
$nodeFile=Join-Path (Get-DevFleetStateRoot) 'tmp\surrogate-node.json';$surrogate|ConvertTo-Json|Set-Content $nodeFile -Encoding utf8
Invoke-External $mp @('transfer',$nodeFile,"${name}:/tmp/surrogate-node.json")
Invoke-External $mp @('exec',$name,'--','sudo','/usr/local/sbin/devfleet-register-node','/tmp/surrogate-node.json')
Add-LocalSshKeyToInstance -InstanceName $name -PublicKeyPath (Join-Path $dest 'laptop-client.pub')
Write-Host 'Vault and failover peer imported into the primary node.' -ForegroundColor Green
} finally {
 Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue
 if($peerFile){Remove-Item $peerFile -Force -ErrorAction SilentlyContinue}
}
