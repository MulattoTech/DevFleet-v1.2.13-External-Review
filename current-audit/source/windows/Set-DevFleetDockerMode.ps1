[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('Primary','Failover')][string]$NodeRole,
    [Parameter(Mandatory)][ValidateSet('rootless','rootful')][string]$Mode,
    [switch]$AcknowledgeRootful
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
Assert-PowerShell7
Assert-Administrator
$config=Get-DevFleetConfig
$node=if($NodeRole -eq 'Primary'){$config.Primary}else{$config.Failover}
$instance=[string]$node.InstanceName
if($Mode -eq 'rootful' -and -not $AcknowledgeRootful){
    throw 'Rootful Docker requires -AcknowledgeRootful. It has broader authority inside the disposable VM, but still receives no Windows mounts or Docker TCP exposure.'
}
if(-not(Test-MultipassInstance $instance)){throw "Multipass instance is not installed locally: $instance"}
Assert-MultipassIsolation -InstanceNames @($instance)
$stamp=(Get-Date).ToString('yyyyMMdd-HHmmss')
$logDir=Join-Path (Get-DevFleetStateRoot) 'logs'
New-Item -ItemType Directory $logDir -Force|Out-Null
if($PSCmdlet.ShouldProcess($instance,"Switch Docker mode to $Mode without migrating or deleting either store")){
    New-DevFleetSnapshotSafe -InstanceName $instance -SnapshotName "pre-docker-mode-$Mode-$stamp"|Out-Null
    $mp=Get-MultipassExe
    Invoke-External $mp @('start',$instance) -IgnoreExitCode
    $report=Invoke-External $mp @('exec',$instance,'--','sudo','/usr/local/bin/devfleet-docker-mode-report') -Capture
    Set-Content (Join-Path $logDir "docker-mode-before-$instance-$stamp.txt") $report -Encoding utf8
    $args=@('exec',$instance,'--','sudo','/usr/local/bin/devfleet-switch-docker-mode',$Mode)
    if($Mode -eq 'rootful'){$args+='--acknowledge-rootful'}
    Invoke-External $mp $args
    if($NodeRole -eq 'Primary'){$config.Docker.PrimaryMode=$Mode}else{$config.Docker.FailoverMode=$Mode}
    if($Mode -eq 'rootful'){$config.Docker.RootfulModeAcknowledged=$true}
    Save-DevFleetConfig -Config $config
    & (Join-Path $PSScriptRoot 'Test-DevFleet.ps1') -InstanceName $instance
    Write-Host "Docker mode for $instance is now $Mode. The other Docker store was not migrated or deleted." -ForegroundColor Green
}
