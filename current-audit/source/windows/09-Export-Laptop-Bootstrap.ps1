[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
$config=Get-DevFleetConfig;$secrets=Get-OrCreateSecrets;$mp=Get-MultipassExe;$identity=Get-OrCreateNodeIdentity -Role Laptop
$vaultIp=Get-InstanceIPv4 $config.Vault.InstanceName -PreferTailscale
$failIp=Get-InstanceIPv4 $config.Failover.InstanceName -PreferTailscale
if($vaultIp -notmatch '^100\.' -or $failIp -notmatch '^100\.' ){throw 'Vault/failover export requires authenticated Tailscale addresses.'}
$dir=Join-Path (Get-DevFleetStateRoot) 'tmp\export-laptop';Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue;New-Item -ItemType Directory $dir -Force|Out-Null
[ordered]@{Repository="rest:http://${vaultIp}:$($config.Network.VaultPort)/$($secrets.VaultRestUser)/$($config.ClusterName)";RestUser=$secrets.VaultRestUser;RestPassword=$secrets.VaultRestPassword;ResticPassword=$secrets.ResticPassword;VaultIp=$vaultIp;VaultPort=$config.Network.VaultPort}|ConvertTo-Json|Set-Content (Join-Path $dir 'vault-client.json') -Encoding utf8
[ordered]@{Name=$config.Failover.InstanceName;Url="http://${failIp}:$($config.Network.PortalPort)";Token=$secrets.NodeApiToken}|ConvertTo-Json|Set-Content (Join-Path $dir 'failover-pairing.json') -Encoding utf8
[ordered]@{deployment_id=$identity.deployment_id;node_id=$identity.node_id;node_name=$identity.node_name;node_role=$identity.node_role;coordinator_node_id=$identity.coordinator_node_id;protocol_version=$identity.protocol_version}|ConvertTo-Json|Set-Content (Join-Path $dir 'surrogate-node.json') -Encoding utf8
Copy-Item "$(Get-OrCreateDevFleetSshKey).pub" (Join-Path $dir 'laptop-client.pub')
$out=Join-Path (Get-DevFleetStateRoot) "exports\devfleet-laptop-bootstrap-$((Get-Date).ToString('yyyyMMdd-HHmmss')).dfe"
try{New-EncryptedBundle -SourceDirectory $dir -OutputPath $out}finally{Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue}
Write-Host "Laptop bootstrap bundle: $out" -ForegroundColor Green
