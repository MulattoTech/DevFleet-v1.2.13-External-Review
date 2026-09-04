[CmdletBinding()]
param([Parameter(Mandatory)][string]$InstanceName)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
$config=Get-DevFleetConfig;$secrets=Get-OrCreateSecrets;$mp=Get-MultipassExe
$vaultIp=Get-InstanceIPv4 $config.Vault.InstanceName -PreferTailscale
$pairingMode=if($vaultIp -match '^100\.'){'tailscale'}else{throw 'Authenticated Vault transport requires a Tailscale address; plaintext LAN fallback is disabled.'}
$obj=[ordered]@{Repository="rest:http://${vaultIp}:$($config.Network.VaultPort)/$($secrets.VaultRestUser)/$($config.ClusterName)";RestUser=$secrets.VaultRestUser;RestPassword=$secrets.VaultRestPassword;ResticPassword=$secrets.ResticPassword;VaultIp=$vaultIp;VaultPort=$config.Network.VaultPort;PairingMode=$pairingMode}
$tmp=Join-Path (Get-DevFleetStateRoot) 'secrets\vault-client.json';$obj|ConvertTo-Json|Set-Content $tmp -Encoding utf8
Protect-DevFleetStateAcl
Invoke-External $mp @('transfer',$tmp,"${InstanceName}:/tmp/vault-client.json")
Invoke-External $mp @('exec',$InstanceName,'--','sudo','/usr/local/sbin/devfleet-configure-backup','/tmp/vault-client.json')
Write-Host "Append-only backups configured for $InstanceName." -ForegroundColor Green
