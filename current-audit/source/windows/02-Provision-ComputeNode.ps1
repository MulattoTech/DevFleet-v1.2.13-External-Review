[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('Primary','Failover')][string]$NodeRole,[switch]$ForceReprovision)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
Assert-PowerShell7; Assert-Administrator
$deadlineContext=Get-DevFleetDeadlineContext
if(-not $deadlineContext){$fallbackDeadline=[DateTime]::UtcNow.AddSeconds((Get-DevFleetStageBudgetSeconds 'compute'));Set-DevFleetDeadlineContext -TransactionDeadlineUtc $fallbackDeadline -StageName 'compute' -StageBudgetSeconds (Get-DevFleetStageBudgetSeconds 'compute') | Out-Null}
$config=Get-DevFleetConfig
$node=if($NodeRole -eq 'Primary'){$config.Primary}else{$config.Failover}
$name=$node.InstanceName
$mp=Get-MultipassExe
$package=Get-PackageRootFromState
Assert-MultipassIsolation -InstanceNames @($name)
$secrets=Get-OrCreateSecrets
$nodeIdentity=Get-OrCreateNodeIdentity -Role $(if($NodeRole -eq 'Primary'){'Desktop'}else{'Laptop'})

if(Test-MultipassInstance $name){
 if($ForceReprovision){ throw "Refusing automatic destruction of existing $name. Remove it manually only after verifying backups." }
 Write-Host "$name already exists; updating the DevFleet payload in place." -ForegroundColor Yellow
 Invoke-External $mp @('start',$name) -IgnoreExitCode
}else{
 $cloud=Join-Path (Get-DevFleetStateRoot) "tmp\cloud-$name.yaml"
 $template=Get-Content (Join-Path $package 'cloud-init\compute.yaml') -Raw
 $template=$template.Replace('__NODE_NAME__',(ConvertTo-YamlSingleQuotedScalar $name)).Replace('__NODE_ROLE__',(ConvertTo-YamlSingleQuotedScalar $NodeRole.ToLower())).Replace('__GIT_NAME_SHELL__',(ConvertTo-ShellSingleQuotedScalar $config.Git.UserName)).Replace('__GIT_EMAIL_SHELL__',(ConvertTo-ShellSingleQuotedScalar $config.Git.Email))
 Set-Content $cloud $template -Encoding utf8
 Invoke-External $mp @('launch',[string]$node.UbuntuImage,'--name',$name,'--cpus',[string]$node.Cpus,'--memory',[string]$node.Memory,'--disk',[string]$node.Disk,'--cloud-init',$cloud)
 Wait-MultipassReady $name 1200
}

$tmp=Join-Path (Get-DevFleetStateRoot) "tmp\payload-$name"
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $tmp -Force | Out-Null
foreach($d in @('linux','app','templates')){ Copy-Item (Join-Path $package $d) $tmp -Recurse }
Copy-Item (Join-Path $package 'VERSION') (Join-Path $tmp 'VERSION')
$nodeSecrets=[ordered]@{
 NodeName=$name; NodeRole=$(if($NodeRole -eq 'Failover'){'surrogate'}else{'primary'}); FriendlyName=[string]$node.FriendlyName; PortalPort=$config.Network.PortalPort; DeploymentId=[string]$nodeIdentity.deployment_id; NodeId=[string]$nodeIdentity.node_id; CoordinatorNodeId=[string]$nodeIdentity.coordinator_node_id; ProtocolVersion=[int]$nodeIdentity.protocol_version
 AdminUser=$secrets.PortalAdminUser; AdminPassword=$secrets.PortalAdminPassword; ApiToken=$secrets.NodeApiToken
 GitName=$config.Git.UserName; GitEmail=$config.Git.Email; OllamaBaseUrl=($(if($config.Ollama.PreferredBaseUrl){$config.Ollama.PreferredBaseUrl}else{$config.Ollama.BaseUrl})); OllamaModel=$config.Ollama.Model; OllamaProfile=$config.Ollama.Profile
 DevelopmentProfile=$config.Development.Profile; DockerMode=($(if($NodeRole -eq 'Primary'){$config.Docker.PrimaryMode}else{$config.Docker.FailoverMode}))
 EnableSharedCaches=[bool]$config.Development.EnableSharedBuildCaches; EnableAnalyzerCache=[bool]$config.Development.EnableAnalyzerCache; AutoStartCodexPro=[bool]$config.Development.AutoStartCodexPro; AllowTailnetPorts=[bool]$config.Development.AllowTailnetPortPublishing; BackupBeforeRebuild=[bool]$config.Development.BackupBeforeRebuild; BackupBeforeQuarantine=[bool]$config.Development.BackupBeforeQuarantine
 BackupIntervalMinutes=[int]$config.Backup.IntervalMinutes
 PackageVersion=(Get-Content -LiteralPath (Join-Path $package 'VERSION') -Raw).Trim()
}
$zip=Join-Path (Get-DevFleetStateRoot) "tmp\payload-$name.zip"
Remove-Item $zip -Force -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $tmp '*') -DestinationPath $zip
try {
 Invoke-External $mp @('transfer',$zip,"${name}:/tmp/devfleet-payload.zip")
 $remote='set -Eeuo pipefail; trap ''sudo rm -rf /tmp/devfleet-payload /tmp/devfleet-payload.zip'' EXIT; sudo rm -rf /tmp/devfleet-payload; mkdir /tmp/devfleet-payload; unzip -q /tmp/devfleet-payload.zip -d /tmp/devfleet-payload; sudo bash /tmp/devfleet-payload/linux/bootstrap-compute.sh /tmp/devfleet-payload --secrets-stdin'
 Invoke-External $mp @('exec',$name,'--','bash','-lc',$remote) -TimeoutSeconds (Get-DevFleetOperationMaximumSeconds 'guestBootstrap') -StandardInputText ($nodeSecrets | ConvertTo-Json -Compress)
} finally {
 Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
 Remove-Item $zip -Force -ErrorAction SilentlyContinue
 $nodeSecrets=$null
}
Add-LocalSshKeyToInstance -InstanceName $name
Write-StageMarker "compute-$name"
Write-Host "$name provisioned. Portal credentials are stored under C:\ProgramData\DevFleet\secrets." -ForegroundColor Green
