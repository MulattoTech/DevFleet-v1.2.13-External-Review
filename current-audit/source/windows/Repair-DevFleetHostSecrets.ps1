[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('REKEY DEVFLEET HOST SECRETS')][string]$ConfirmReKey
)

$ErrorActionPreference = 'Stop'
$common = Join-Path $PSScriptRoot 'DevFleet.Common.psm1'
$protocol = Join-Path $PSScriptRoot 'DevFleet-HostAgentProtocol.psm1'
$ownership = Join-Path $PSScriptRoot 'DevFleet-WindowsIntegrationOwnership.psm1'
Import-Module $common -Force
Import-Module $protocol -Force
Import-Module $ownership -Force
Assert-PowerShell7
Assert-Administrator
if (-not (Test-ExistingDeploymentState)) { throw 'SECRET RECOVERY REQUIRED applies only to an existing deployment; use normal fresh installation for a new host.' }

function Write-AtomicUtf8 {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Text)
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText($temporary,$Text,[Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
}

function Get-ExactGuestIdentity {
    param([Parameter(Mandatory)][string]$Multipass,[Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][string]$Path)
    $raw = Invoke-External $Multipass @('exec',$Name,'--','sudo','cat',$Path) -Capture
    try { return $raw | ConvertFrom-Json }
    catch { throw "SECRET RECOVERY REQUIRED: $Name returned invalid immutable identity evidence." }
}

$stateRoot = Get-DevFleetStateRoot
$config = Get-DevFleetConfig
$hostIdentityPath = Join-Path $stateRoot 'node-identity.json'
$hostIdentity = Get-Content -LiteralPath $hostIdentityPath -Raw | ConvertFrom-Json
if ([string]$hostIdentity.node_id -notmatch '^[0-9a-fA-F-]{36}$' -or [string]$hostIdentity.deployment_id -notmatch '^[0-9a-fA-F-]{36}$') {
    throw 'SECRET RECOVERY REQUIRED: deployment/node inventory is incomplete; no credentials were changed.'
}
$generation = [guid]::NewGuid().ToString('D')
$newSecrets = New-DevFleetSecretRecord -Generation $generation
$newHostToken = New-RandomSecret 40
$multipass = Get-MultipassExe
$instances = @(Get-MultipassInstances)
$computeName = if ([string]$hostIdentity.node_role -eq 'primary') { [string]$config.Primary.InstanceName } elseif ([string]$hostIdentity.node_role -eq 'surrogate') { [string]$config.Failover.InstanceName } else { throw 'SECRET RECOVERY REQUIRED: unsupported host node role.' }
if (@($instances | Where-Object name -eq $computeName).Count -ne 1) { throw "SECRET RECOVERY REQUIRED: exact compute instance inventory is ambiguous or missing: $computeName" }
Assert-MultipassIsolation -InstanceNames @($computeName)
Invoke-External $multipass @('start',$computeName) -IgnoreExitCode
$computeIdentity = Get-ExactGuestIdentity -Multipass $multipass -Name $computeName -Path '/etc/devfleet/node-identity.json'
if ([string]$computeIdentity.node_id -ne [string]$hostIdentity.node_id -or [string]$computeIdentity.deployment_id -ne [string]$hostIdentity.deployment_id -or [string]$computeIdentity.node_name -ne $computeName) {
    throw 'SECRET RECOVERY REQUIRED: compute identity does not match the exact deployment inventory; no credentials were changed.'
}

$vaultName = $null
$vaultIdentity = $null
if ([string]$hostIdentity.node_role -eq 'surrogate') {
    $vaultName = [string]$config.Vault.InstanceName
    if (@($instances | Where-Object name -eq $vaultName).Count -ne 1) { throw "SECRET RECOVERY REQUIRED: exact vault instance inventory is ambiguous or missing: $vaultName" }
    $vaultIdentityPath = Join-Path $stateRoot 'vault-node-identity.json'
    if (-not (Test-Path -LiteralPath $vaultIdentityPath -PathType Leaf)) { throw 'SECRET RECOVERY REQUIRED: vault identity metadata is missing; use the explicit legacy vault-adoption procedure before re-keying.' }
    $vaultIdentity = Get-Content -LiteralPath $vaultIdentityPath -Raw | ConvertFrom-Json
    Assert-MultipassIsolation -InstanceNames @($vaultName)
    Invoke-External $multipass @('start',$vaultName) -IgnoreExitCode
    $liveVaultIdentity = Get-ExactGuestIdentity -Multipass $multipass -Name $vaultName -Path '/etc/devfleet-vault-identity.json'
    if ([string]$vaultIdentity.deployment_id -ne [string]$hostIdentity.deployment_id -or [string]$liveVaultIdentity.deployment_id -ne [string]$hostIdentity.deployment_id -or [string]$liveVaultIdentity.node_id -ne [string]$vaultIdentity.node_id -or [string]$liveVaultIdentity.node_name -ne $vaultName) {
        throw 'SECRET RECOVERY REQUIRED: vault identity does not match the exact deployment inventory; no credentials were changed.'
    }
} elseif (Test-Path -LiteralPath (Join-Path $stateRoot 'secrets\vault-client.json') -PathType Leaf) {
    throw 'SECRET RECOVERY REQUIRED: this primary is bound to an external vault. Run a coordinated all-node recovery from the surrogate/vault host; no credentials were changed.'
}

$hostAgentRoot = Join-Path $env:ProgramData 'DevFleetHostAgent'
$hostTokenPath = Join-Path $hostAgentRoot 'token.txt'
$hostOwnershipPath = Join-Path $hostAgentRoot 'integration-ownership.json'
$hostOwnership = Read-DevFleetIntegrationOwnership -Path $hostOwnershipPath
$taskBinding = @($hostOwnership.ScheduledTasks | Where-Object { [string]$_.Name -eq 'DevFleet Host Agent' })
$task = Get-ScheduledTask -TaskName 'DevFleet Host Agent' -ErrorAction SilentlyContinue
if ($taskBinding.Count -ne 1 -or -not $task -or @($task.Actions).Count -ne 1) { throw 'SECRET RECOVERY REQUIRED: Host Agent task ownership is incomplete; no credentials were changed.' }
$taskActual = @{Name=[string]$task.TaskName;Executable=[string]$task.Actions[0].Execute;Arguments=[string]$task.Actions[0].Arguments;Principal=[string]$task.Principal.UserId;LogonType=[string]$task.Principal.LogonType;RunLevel=[string]$task.Principal.RunLevel;Description=[string]$task.Description;Generation=[string]$taskBinding[0].Generation}
Assert-DevFleetTaskBinding -Expected $taskBinding[0] -Actual $taskActual | Out-Null

$recoveryRoot = Join-Path $stateRoot "secret-recovery\$generation"
New-Item -ItemType Directory -Path $recoveryRoot -Force | Out-Null
Protect-DevFleetStateAcl
$secretPath = Join-Path $stateRoot 'secrets\host-secrets.json'
if (Test-Path -LiteralPath $secretPath -PathType Leaf) { Copy-Item -LiteralPath $secretPath -Destination (Join-Path $recoveryRoot 'host-secrets.before.json') -Force }
if (Test-Path -LiteralPath $hostTokenPath -PathType Leaf) { Copy-Item -LiteralPath $hostTokenPath -Destination (Join-Path $recoveryRoot 'host-agent-token.before.txt') -Force }
$pendingSecretsPath = Join-Path $recoveryRoot 'host-secrets.pending.json'
Write-AtomicUtf8 -Path $pendingSecretsPath -Text (($newSecrets | ConvertTo-Json -Depth 5) + [Environment]::NewLine)

$computeHelper = Join-Path (Get-PackageRootFromState) 'linux\devfleet-rotate-compute-secrets'
$vaultHelper = Join-Path (Get-PackageRootFromState) 'linux\devfleet-rotate-vault-secrets'
if (-not (Test-Path -LiteralPath $computeHelper -PathType Leaf) -or ($vaultName -and -not (Test-Path -LiteralPath $vaultHelper -PathType Leaf))) { throw 'Secret recovery helpers are missing from the exact package.' }
$remoteComputeHelper = "/tmp/devfleet-rotate-compute-$generation"
$remoteVaultHelper = "/tmp/devfleet-rotate-vault-$generation"
$computeApplied = $false
$vaultApplied = $false
$hostTokenApplied = $false
$committed = $false
$evidence = [ordered]@{schemaVersion=1;secretGeneration=$generation;deploymentId=[string]$hostIdentity.deployment_id;hostNodeId=[string]$hostIdentity.node_id;compute=[ordered]@{name=$computeName;nodeId=[string]$computeIdentity.node_id;verified=$false};vault=if($vaultName){[ordered]@{name=$vaultName;nodeId=[string]$vaultIdentity.node_id;verified=$false}}else{$null};hostAgent=[ordered]@{task='DevFleet Host Agent';ownershipGeneration=[string]$hostOwnership.InstallationGeneration;verified=$false};plaintextSecretsLogged=$false;status='IN_PROGRESS';startedAt=(Get-Date).ToUniversalTime().ToString('o')}
try {
    New-DevFleetSnapshotSafe -InstanceName $computeName -SnapshotName "pre-secret-rekey-$($generation.Substring(0,8))" | Out-Null
    Wait-MultipassReady -Name $computeName -TimeoutSeconds 600
    Invoke-External $multipass @('transfer',$computeHelper,"${computeName}:$remoteComputeHelper")
    if ($vaultName) {
        New-DevFleetSnapshotSafe -InstanceName $vaultName -SnapshotName "pre-secret-rekey-$($generation.Substring(0,8))" | Out-Null
        Wait-MultipassReady -Name $vaultName -TimeoutSeconds 600
        Invoke-External $multipass @('transfer',$vaultHelper,"${vaultName}:$remoteVaultHelper")
        $vaultPayload = [ordered]@{schema_version=1;secret_generation=$generation;deployment_id=[string]$hostIdentity.deployment_id;node_id=[string]$vaultIdentity.node_id;cluster=[string]$config.ClusterName;rest_user=[string]$newSecrets.VaultRestUser;rest_password=[string]$newSecrets.VaultRestPassword;restic_password=[string]$newSecrets.ResticPassword}
        Invoke-External $multipass @('exec',$vaultName,'--','sudo','bash',$remoteVaultHelper,'apply',$generation) -StandardInputText ($vaultPayload | ConvertTo-Json -Compress)
        $vaultApplied = $true; $evidence.vault.verified = $true
    }
    $computePayload = [ordered]@{schema_version=1;secret_generation=$generation;deployment_id=[string]$hostIdentity.deployment_id;node_id=[string]$hostIdentity.node_id;admin_user=[string]$newSecrets.PortalAdminUser;admin_password=[string]$newSecrets.PortalAdminPassword;api_token=[string]$newSecrets.NodeApiToken;host_control_token=$newHostToken}
    Invoke-External $multipass @('exec',$computeName,'--','sudo','bash',$remoteComputeHelper,'apply',$generation) -StandardInputText ($computePayload | ConvertTo-Json -Compress)
    $computeApplied = $true; $evidence.compute.verified = $true

    if ($vaultName) {
        $vaultIp = Get-InstanceIPv4 -Name $vaultName -PreferTailscale
        if (-not $vaultIp) { throw 'Rotated vault endpoint has no verified reachable address.' }
        $vaultClient = [ordered]@{Repository="rest:http://${vaultIp}:$($config.Network.VaultPort)/$($newSecrets.VaultRestUser)/$($config.ClusterName)";RestUser=[string]$newSecrets.VaultRestUser;RestPassword=[string]$newSecrets.VaultRestPassword;ResticPassword=[string]$newSecrets.ResticPassword;VaultIp=$vaultIp;VaultPort=[int]$config.Network.VaultPort;SecretGeneration=$generation}
        $pendingVaultClient = Join-Path $recoveryRoot 'vault-client.pending.json'
        Write-AtomicUtf8 -Path $pendingVaultClient -Text (($vaultClient | ConvertTo-Json -Depth 5) + [Environment]::NewLine)
        Invoke-External $multipass @('transfer',$pendingVaultClient,"${computeName}:/tmp/devfleet-vault-client-$generation.json")
        $remoteVaultClient = "/tmp/devfleet-vault-client-$generation.json"
        $configureBackup = 'set -Eeuo pipefail; trap ''rm -f -- "$1"'' EXIT; /usr/local/sbin/devfleet-configure-backup "$1"'
        Invoke-External $multipass @('exec',$computeName,'--','sudo','bash','-c',$configureBackup,'--',$remoteVaultClient)
    }

    Write-AtomicUtf8 -Path $hostTokenPath -Text ($newHostToken + [Environment]::NewLine)
    $hostTokenApplied = $true
    Stop-ScheduledTask -TaskName 'DevFleet Host Agent' -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName 'DevFleet Host Agent'
    $hostHealth = $null
    $hostAgentConfig = Get-Content -LiteralPath (Join-Path $hostAgentRoot 'config.json') -Raw | ConvertFrom-Json
    if ([string]$hostAgentConfig.ListenPrefix -notmatch ':(\d{2,5})/$') { throw 'Host Agent listen prefix is invalid during secret verification.' }
    $hostAgentPort = [int]$Matches[1]
    for ($attempt = 0; $attempt -lt 20 -and -not $hostHealth; $attempt++) {
        try { $hostHealth = Invoke-HostAgentAuthenticatedJson -Uri "http://127.0.0.1:$hostAgentPort/healthz" -Method GET -Key $newHostToken -ExpectedHost $env:COMPUTERNAME }
        catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $hostHealth.ok) { throw 'Rotated Host Agent credential did not verify.' }
    $evidence.hostAgent.verified = $true

    if ($vaultName) {
        $pendingVaultClient = Join-Path $recoveryRoot 'vault-client.pending.json'
        $vaultClientPath = Join-Path $stateRoot 'secrets\vault-client.json'
        Write-AtomicUtf8 -Path $vaultClientPath -Text (Get-Content -LiteralPath $pendingVaultClient -Raw)
    }
    Write-AtomicUtf8 -Path $secretPath -Text (($newSecrets | ConvertTo-Json -Depth 5) + [Environment]::NewLine)
    Protect-DevFleetStateAcl
    $committed = $true
    $evidence.status='COMMITTED';$evidence.completedAt=(Get-Date).ToUniversalTime().ToString('o')
} catch {
    $evidence.status='ROLLED_BACK';$evidence.error=$_.Exception.Message;$evidence.failedAt=(Get-Date).ToUniversalTime().ToString('o')
    if ($hostTokenApplied -and (Test-Path -LiteralPath (Join-Path $recoveryRoot 'host-agent-token.before.txt'))) {
        Copy-Item -LiteralPath (Join-Path $recoveryRoot 'host-agent-token.before.txt') -Destination $hostTokenPath -Force
        Stop-ScheduledTask -TaskName 'DevFleet Host Agent' -ErrorAction SilentlyContinue; Start-ScheduledTask -TaskName 'DevFleet Host Agent' -ErrorAction SilentlyContinue
    } elseif ($hostTokenApplied) {
        Remove-Item -LiteralPath $hostTokenPath -Force -ErrorAction SilentlyContinue
        Stop-ScheduledTask -TaskName 'DevFleet Host Agent' -ErrorAction SilentlyContinue
    }
    if ($computeApplied) { try { Invoke-External $multipass @('exec',$computeName,'--','sudo','bash',$remoteComputeHelper,'rollback',$generation) } catch { $evidence.compute.rollbackError=$_.Exception.Message } }
    if ($vaultApplied) { try { Invoke-External $multipass @('exec',$vaultName,'--','sudo','bash',$remoteVaultHelper,'rollback',$generation) } catch { $evidence.vault.rollbackError=$_.Exception.Message } }
    throw
} finally {
    foreach ($target in @(@($computeName,$remoteComputeHelper),@($vaultName,$remoteVaultHelper))) {
        if ($target[0]) { try { Invoke-External $multipass @('exec',[string]$target[0],'--','sudo','rm','-f','--',[string]$target[1]) -IgnoreExitCode } catch {} }
    }
    Remove-Item -LiteralPath $pendingSecretsPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $recoveryRoot 'vault-client.pending.json') -Force -ErrorAction SilentlyContinue
    Write-AtomicUtf8 -Path (Join-Path $recoveryRoot 'recovery-evidence.json') -Text (($evidence | ConvertTo-Json -Depth 8) + [Environment]::NewLine)
}
if (-not $committed) { throw 'Secret recovery did not commit.' }
[ordered]@{ok=$true;status='COMMITTED';secretGeneration=$generation;deploymentId=[string]$hostIdentity.deployment_id;compute=$computeName;vault=$vaultName;plaintextSecretsLogged=$false;recoveryEvidence=(Join-Path $recoveryRoot 'recovery-evidence.json')} | ConvertTo-Json -Compress
