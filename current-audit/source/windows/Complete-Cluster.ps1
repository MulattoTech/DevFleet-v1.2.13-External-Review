[CmdletBinding()]
param([Parameter(Mandatory)][ValidateScript({Test-Path $_})][string]$DesktopPairingBundlePath)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
$config=Get-DevFleetConfig;$mp=Get-MultipassExe;$dest=Join-Path (Get-DevFleetStateRoot) 'tmp\import-desktop';$tmp=$null;Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue
Expand-EncryptedBundle -BundlePath $DesktopPairingBundlePath -Destination $dest
try {
$peer=Get-Content (Join-Path $dest 'primary-pairing.json') -Raw|ConvertFrom-Json
$primaryNode=Get-Content (Join-Path $dest 'primary-node.json') -Raw|ConvertFrom-Json
if($primaryNode.node_role -ne 'primary' -or -not $primaryNode.deployment_id -or -not $primaryNode.node_id){throw 'Primary invitation metadata is incomplete.'}
$tmp=Join-Path (Get-DevFleetStateRoot) 'tmp\primary-peer.json';$peer|ConvertTo-Json|Set-Content $tmp -Encoding utf8
$name=$config.Failover.InstanceName
Invoke-External $mp @('transfer',$tmp,"${name}:/tmp/peer.json")
Invoke-External $mp @('exec',$name,'--','sudo','/usr/local/sbin/devfleet-set-peer','/tmp/peer.json')
$nodeFile=Join-Path (Get-DevFleetStateRoot) 'tmp\primary-node.json';$primaryNode|ConvertTo-Json|Set-Content $nodeFile -Encoding utf8
Invoke-External $mp @('transfer',$nodeFile,"${name}:/tmp/primary-node.json")
Invoke-External $mp @('exec',$name,'--','sudo','/usr/local/sbin/devfleet-join-deployment','/tmp/primary-node.json')
$hostIdentityPath=Join-Path (Get-DevFleetStateRoot) 'node-identity.json'
$hostIdentity=Get-Content -LiteralPath $hostIdentityPath -Raw|ConvertFrom-Json
if($hostIdentity.node_role -ne 'surrogate' -or -not $hostIdentity.node_id){throw 'Local surrogate identity is incomplete.'}
$hostIdentity.deployment_id=[string]$primaryNode.deployment_id;$hostIdentity.coordinator_node_id=[string]$primaryNode.node_id;$hostIdentity.registration_state='joined'
$vaultIdentity=Get-OrCreateVaultIdentity
$vaultIdentity.deployment_id=[string]$primaryNode.deployment_id
$vaultIdentityPath=Join-Path (Get-DevFleetStateRoot) 'vault-node-identity.json'
$vaultIdentity|ConvertTo-Json|Set-Content -LiteralPath $vaultIdentityPath -Encoding utf8
$vaultName=[string]$config.Vault.InstanceName
if(Test-MultipassInstance $vaultName){
 $vaultPublic=(Invoke-External $mp @('exec',$vaultName,'--','sudo','cat','/etc/devfleet-vault-public.json') -Capture)|ConvertFrom-Json
 $localSecrets=Get-OrCreateSecrets
 if([string]$vaultPublic.cluster -ne [string]$config.ClusterName -or [string]$vaultPublic.user -ne [string]$localSecrets.VaultRestUser){throw 'Vault legacy adoption identity does not match the exact local cluster/credential binding.'}
 $vaultIdentityTransfer=Join-Path (Get-DevFleetStateRoot) 'tmp\vault-node-identity.json';$vaultIdentity|ConvertTo-Json|Set-Content -LiteralPath $vaultIdentityTransfer -Encoding utf8
 Invoke-External $mp @('transfer',$vaultIdentityTransfer,"${vaultName}:/tmp/devfleet-vault-identity.json")
 Invoke-External $mp @('exec',$vaultName,'--','sudo','install','-o','root','-g','root','-m','0600','/tmp/devfleet-vault-identity.json','/etc/devfleet-vault-identity.json')
 Invoke-External $mp @('exec',$vaultName,'--','sudo','rm','-f','--','/tmp/devfleet-vault-identity.json')
}
$hostIdentity|ConvertTo-Json|Set-Content -LiteralPath $hostIdentityPath -Encoding utf8
Protect-DevFleetStateAcl
Add-LocalSshKeyToInstance -InstanceName $name -PublicKeyPath (Join-Path $dest 'desktop-client.pub')
Write-Host 'Failover node paired with primary. Cluster setup is complete.' -ForegroundColor Green
} finally {
 Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue
 if($tmp){Remove-Item $tmp -Force -ErrorAction SilentlyContinue}
}

try { & (Join-Path (Get-PackageRootFromState) 'client\Configure-SSH.ps1') -SkipConnectivityTest } catch { Write-Warning $_ }

try { & (Join-Path (Get-PackageRootFromState) 'client\Configure-VSCode.ps1') -ExtensionSets core } catch { Write-Warning $_ }
if (Get-Command docker.exe -ErrorAction SilentlyContinue) { try { & (Join-Path (Get-PackageRootFromState) 'client\Configure-DockerContext.ps1') } catch { Write-Warning $_ } }
