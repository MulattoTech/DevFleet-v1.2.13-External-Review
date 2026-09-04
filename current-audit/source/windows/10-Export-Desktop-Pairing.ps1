[CmdletBinding()]
param([switch]$NonInteractive)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
if($NonInteractive){Write-Warning 'Desktop pairing export was deferred because this installation chain is noninteractive. Run the supported Maintenance pairing workflow to create the encrypted bundle.';return}
$config=Get-DevFleetConfig;$secrets=Get-OrCreateSecrets;$identity=Get-OrCreateNodeIdentity -Role Desktop
if(-not $identity.deployment_id -or $identity.node_role -ne 'primary'){throw 'Primary deployment identity is missing or not a Primary.'}
$ip=Get-InstanceIPv4 $config.Primary.InstanceName -PreferTailscale
if(-not $ip){throw 'Primary Tailscale address is unavailable.'}
$dir=Join-Path (Get-DevFleetStateRoot) 'tmp\export-desktop';Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue;New-Item -ItemType Directory $dir -Force|Out-Null
[ordered]@{Name=$config.Primary.InstanceName;Url="http://${ip}:$($config.Network.PortalPort)";Token=$secrets.NodeApiToken}|ConvertTo-Json|Set-Content (Join-Path $dir 'primary-pairing.json') -Encoding utf8
[ordered]@{deployment_id=$identity.deployment_id;node_id=$identity.node_id;node_name=$identity.node_name;node_role=$identity.node_role;protocol_version=$identity.protocol_version}|ConvertTo-Json|Set-Content (Join-Path $dir 'primary-node.json') -Encoding utf8
Copy-Item "$(Get-OrCreateDevFleetSshKey).pub" (Join-Path $dir 'desktop-client.pub')
$out=Join-Path (Get-DevFleetStateRoot) "exports\devfleet-desktop-pairing-$((Get-Date).ToString('yyyyMMdd-HHmmss')).dfe"
try{New-EncryptedBundle -SourceDirectory $dir -OutputPath $out}finally{Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue}
Write-Host "Desktop pairing bundle: $out" -ForegroundColor Green
