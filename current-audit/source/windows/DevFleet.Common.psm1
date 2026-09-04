Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-DevFleetPackageRoot {
    Split-Path -Parent $PSScriptRoot
}

function Get-DevFleetStateRoot {
    Join-Path $env:ProgramData 'DevFleet'
}

function Get-ActiveDevFleetTransaction {
    $path = Join-Path (Get-DevFleetStateRoot) 'active-transaction.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        $value = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ([string]$value.transactionId -notmatch '^[0-9a-fA-F]{32}$' -or [string]$value.payloadSha256 -notmatch '^[0-9a-fA-F]{64}$' -or [string]$value.action -notin @('FreshInstall','Repair','CleanReinstall','LocalUpdate') -or [string]$value.role -notin @('Laptop','Desktop')) { return $null }
        return $value
    } catch { return $null }
}

function Set-DevFleetDeadlineContext {
    param(
        [Parameter(Mandatory)][datetime]$TransactionDeadlineUtc,
        [Parameter(Mandatory)][string]$StageName,
        [Parameter(Mandatory)][int]$StageBudgetSeconds
    )
    if ($StageBudgetSeconds -le 0) { throw "Stage '$StageName' must have a finite positive budget." }
    $transactionDeadline = $TransactionDeadlineUtc.ToUniversalTime()
    if ($transactionDeadline -le [datetime]::UtcNow) { throw 'The owning DevFleet transaction deadline has expired.' }
    $stageDeadline = [datetime]::UtcNow.AddSeconds($StageBudgetSeconds)
    if ($stageDeadline -gt $transactionDeadline) { $stageDeadline = $transactionDeadline }
    $global:DevFleetDeadlineContext = [pscustomobject]@{
        TransactionDeadlineUtc = $transactionDeadline
        StageName = $StageName
        StageDeadlineUtc = $stageDeadline
        StageBudgetSeconds = $StageBudgetSeconds
    }
    return $global:DevFleetDeadlineContext
}

function Get-DevFleetDeadlineContext {
    $variable=Get-Variable -Scope Global -Name DevFleetDeadlineContext -ErrorAction SilentlyContinue
    if($variable){return $variable.Value}
    return $null
}

function Get-DevFleetStageBudgetSeconds {
    param([Parameter(Mandatory)][string]$StageName)
    if ($StageName -eq 'compute') {
        return (Get-DevFleetOperationMaximumSeconds 'multipassLaunch') + (Get-DevFleetOperationMaximumSeconds 'multipassReadiness') + (Get-DevFleetOperationMaximumSeconds 'payloadTransfer') + (Get-DevFleetOperationMaximumSeconds 'guestBootstrap') + (Get-DevFleetOperationMaximumSeconds 'sshAndMarker')
    }
    if ($StageName -eq 'vault') {
        return (Get-DevFleetOperationMaximumSeconds 'vaultSnapshot') + (Get-DevFleetOperationMaximumSeconds 'multipassLaunch') + (Get-DevFleetOperationMaximumSeconds 'multipassReadiness') + (Get-DevFleetOperationMaximumSeconds 'payloadTransfer') + (Get-DevFleetOperationMaximumSeconds 'guestBootstrap') + (Get-DevFleetOperationMaximumSeconds 'sshAndMarker')
    }
    $budgets = @{
        bootstrap = (Get-DevFleetOperationMaximumSeconds 'bootstrap')
        preflight = (Get-DevFleetOperationMaximumSeconds 'preflight')
        prerequisites = (6 * ((Get-DevFleetOperationMaximumSeconds 'dependencyProbe') + (Get-DevFleetOperationMaximumSeconds 'dependencyHealth') + (Get-DevFleetOperationMaximumSeconds 'dependencyInstall') + (Get-DevFleetOperationMaximumSeconds 'dependencyVerification'))) + (Get-DevFleetOperationMaximumSeconds 'windowsCapability') + (Get-DevFleetOperationMaximumSeconds 'windowsFeature') + (4 * (Get-DevFleetOperationMaximumSeconds 'multipassConfiguration')) + (3 * (Get-DevFleetOperationMaximumSeconds 'vscodeExtension'))
        windowsTailscale = 180
        hostAgent = 300
        tailscale = 900
        vaultClient = 300
        shortcuts = 180
        export = 300
        verification = 300
    }
    if (-not $budgets.ContainsKey($StageName)) { throw "No finite deadline policy exists for stage '$StageName'." }
    return [int]$budgets[$StageName]
}

function Get-DevFleetOperationMaximumSeconds {
    param([Parameter(Mandatory)][ValidateSet('bootstrap','preflight','prerequisites','dependencyProbe','dependencyHealth','dependencyInstall','dependencyVerification','windowsCapability','windowsFeature','multipassConfiguration','vscodeExtension','windowsTailscale','hostAgent','multipassLaunch','multipassReadiness','payloadTransfer','guestBootstrap','sshAndMarker','vaultSnapshot','tailscale','vaultClient','shortcuts','export','verification')][string]$OperationName)
    $operation = [ordered]@{
        bootstrap = 240; preflight = 120; prerequisites = 0; dependencyProbe = 60; dependencyHealth = 180; dependencyInstall = 1800; dependencyVerification = 60; windowsCapability = 900; windowsFeature = 900; multipassConfiguration = 600; vscodeExtension = 300; windowsTailscale = 180; hostAgent = 300
        multipassLaunch = 900; multipassReadiness = 1200; payloadTransfer = 900
        guestBootstrap = (900 + 1200 + 1200 + 600 + 600 + 1200 + 600)
        sshAndMarker = 300; vaultSnapshot = 300; tailscale = 900; vaultClient = 300
        shortcuts = 180; export = 300; verification = 300
    }
    $operation.prerequisites = 6 * ($operation.dependencyProbe + $operation.dependencyHealth + $operation.dependencyInstall + $operation.dependencyVerification) + $operation.windowsCapability + $operation.windowsFeature + (4 * $operation.multipassConfiguration) + (3 * $operation.vscodeExtension)
    return [int]$operation[$OperationName]
}

function Get-DevFleetTransactionBudgetSeconds {
    param([Parameter(Mandatory)][ValidateSet('Laptop','Desktop')][string]$Role)
    $stageNames = if ($Role -eq 'Laptop') {
        @('bootstrap','preflight','prerequisites','windowsTailscale','hostAgent','compute','vault','tailscale','tailscale','vaultClient','shortcuts','export','verification')
    } else {
        @('bootstrap','preflight','prerequisites','windowsTailscale','hostAgent','compute','tailscale','shortcuts','export','verification')
    }
    $total = 0
    foreach ($stage in $stageNames) { $total += Get-DevFleetStageBudgetSeconds $stage }
    return $total + 600
}

function Assert-PowerShell7 {
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw 'PowerShell 7 or newer is required. Re-run Bootstrap-Install.ps1 so the verified local PowerShell payload can be installed.'
    }
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator {
    if (-not (Test-Administrator)) { throw 'Run PowerShell 7 as Administrator.' }
}

function Initialize-DevFleetState {
    param([Parameter(Mandatory)][string]$PackageRoot)
    $root = Get-DevFleetStateRoot
    foreach ($dir in @($root, "$root\exports", "$root\logs", "$root\secrets", "$root\tmp")) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $configPath = Join-Path $root 'devfleet.config.json'
    if (-not (Test-Path $configPath)) {
        Copy-Item (Join-Path $PackageRoot 'config\devfleet.config.json') $configPath
    }
    Set-Content -Path (Join-Path $root 'package-root.txt') -Value $PackageRoot -Encoding utf8
    Protect-DevFleetStateAcl
}

function Get-OrCreateNodeIdentity {
    param([Parameter(Mandatory)][ValidateSet('Laptop','Desktop')][string]$Role)
    $path = Join-Path (Get-DevFleetStateRoot) 'node-identity.json'
    if (Test-Path -LiteralPath $path) { return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json }
    $isPrimary = $Role -eq 'Desktop'
    $identity = [ordered]@{
        schema_version = 1
        deployment_id = if ($isPrimary) { [guid]::NewGuid().ToString() } else { '' }
        node_id = [guid]::NewGuid().ToString()
        node_name = $env:COMPUTERNAME
        node_role = if ($isPrimary) { 'primary' } else { 'surrogate' }
        coordinator_node_id = $null
        protocol_version = 1
        registration_state = if ($isPrimary) { 'coordinator' } else { 'awaiting-primary-join' }
        created_at = (Get-Date).ToUniversalTime().ToString('o')
    }
    $identity | ConvertTo-Json | Set-Content -LiteralPath $path -Encoding utf8
    Protect-DevFleetStateAcl
    return $identity | ConvertTo-Json | ConvertFrom-Json
}

function Get-OrCreateVaultIdentity {
    $path = Join-Path (Get-DevFleetStateRoot) 'vault-node-identity.json'
    if (Test-Path -LiteralPath $path) {
        $identity = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ([string]$identity.node_role -ne 'vault' -or [string]$identity.node_id -notmatch '^[0-9a-fA-F-]{36}$' -or ([string]$identity.deployment_id -and [string]$identity.deployment_id -notmatch '^[0-9a-fA-F-]{36}$')) { throw 'Vault identity is invalid; explicit recovery is required.' }
        return $identity
    }
    $hostIdentity = Get-OrCreateNodeIdentity -Role Laptop
    $identity = [ordered]@{schema_version=1;deployment_id=[string]$hostIdentity.deployment_id;node_id=[guid]::NewGuid().ToString('D');node_name=(Get-DevFleetConfig).Vault.InstanceName;node_role='vault';created_at=(Get-Date).ToUniversalTime().ToString('o')}
    $identity | ConvertTo-Json | Set-Content -LiteralPath $path -Encoding utf8
    Protect-DevFleetStateAcl
    return $identity | ConvertTo-Json | ConvertFrom-Json
}

function Protect-DevFleetStateAcl {
    $root = Get-DevFleetStateRoot
    if (-not (Test-Path $root)) { return }
    $acl = Get-Acl $root
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($existing in @($acl.Access)) { $acl.RemoveAccessRuleAll($existing) }
    foreach ($rule in @(
        [Security.AccessControl.FileSystemAccessRule]::new('BUILTIN\Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow'),
        [Security.AccessControl.FileSystemAccessRule]::new('NT AUTHORITY\SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow'),
        [Security.AccessControl.FileSystemAccessRule]::new("$env:USERDOMAIN\$env:USERNAME",'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    )) { $acl.AddAccessRule($rule) | Out-Null }
    Set-Acl -Path $root -AclObject $acl
}

function Get-DevFleetConfig {
    $path = Join-Path (Get-DevFleetStateRoot) 'devfleet.config.json'
    if (-not (Test-Path $path)) { throw "Missing config: $path" }
    Get-Content $path -Raw | ConvertFrom-Json
}

function Save-DevFleetConfig {
    param([Parameter(Mandatory)]$Config)
    $path = Join-Path (Get-DevFleetStateRoot) 'devfleet.config.json'
    $Config | ConvertTo-Json -Depth 20 | Set-Content $path -Encoding utf8
}

function Get-PackageRootFromState {
    $p = Join-Path (Get-DevFleetStateRoot) 'package-root.txt'
    if (Test-Path $p) { return (Get-Content $p -Raw).Trim() }
    Get-DevFleetPackageRoot
}

function New-RandomSecret {
    param([int]$Bytes = 32)
    $data = New-Object byte[] $Bytes
    [Security.Cryptography.RandomNumberGenerator]::Fill($data)
    [Convert]::ToBase64String($data).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function ConvertTo-YamlSingleQuotedScalar {
    param([AllowNull()][string]$Value)
    $text = if ($null -eq $Value) { '' } else { $Value }
    if ($text.IndexOfAny([char[]]"`0`r`n") -ge 0) { throw 'YAML scalar contains a forbidden control or newline character.' }
    return "'" + $text.Replace("'", "''") + "'"
}

function ConvertTo-ShellSingleQuotedScalar {
    param([AllowNull()][string]$Value)
    $text = if ($null -eq $Value) { '' } else { $Value }
    if ($text.IndexOfAny([char[]]"`0`r`n") -ge 0) { throw 'Shell scalar contains a forbidden control or newline character.' }
    return "'" + $text.Replace("'", "'\''") + "'"
}

function Test-ExistingDeploymentState {
    $root = Get-DevFleetStateRoot
    foreach ($name in @('node-identity.json','deployment.json','host-agent-registry.json','projects.json')) {
        $candidate = Join-Path $root $name
        if ((Test-Path -LiteralPath $candidate -PathType Leaf) -and (Get-Item -LiteralPath $candidate).Length -gt 2) { return $true }
    }
    return $false
}

function Test-DevFleetSecretRecord {
    param([Parameter(Mandatory)]$Secrets)
    foreach ($field in @('PortalAdminUser','PortalAdminPassword','NodeApiToken','ResticPassword','VaultRestUser','VaultRestPassword')) {
        if (-not $Secrets.PSObject.Properties[$field] -or [string]::IsNullOrWhiteSpace([string]$Secrets.$field)) { return $false }
    }
    if ([string]$Secrets.PortalAdminPassword -match '[\r\n]' -or [string]$Secrets.NodeApiToken -match '[\r\n]' -or [string]$Secrets.ResticPassword -match '[\r\n]' -or [string]$Secrets.VaultRestPassword -match '[\r\n]') { return $false }
    if ([string]$Secrets.NodeApiToken -notmatch '^[A-Za-z0-9_-]{40,}$' -or [string]$Secrets.ResticPassword -notmatch '^[A-Za-z0-9_-]{40,}$') { return $false }
    if ($Secrets.PSObject.Properties['SecretGeneration'] -and $Secrets.SecretGeneration) {
        $generation = [guid]::Empty
        if (-not [guid]::TryParse([string]$Secrets.SecretGeneration,[ref]$generation) -or $generation -eq [guid]::Empty) { return $false }
    }
    return $true
}

function New-DevFleetSecretRecord {
    param([string]$Generation = ([guid]::NewGuid().ToString('D')))
    $parsed = [guid]::Empty
    if (-not [guid]::TryParse($Generation,[ref]$parsed) -or $parsed -eq [guid]::Empty) { throw 'Secret generation must be a non-empty UUID.' }
    [ordered]@{
        SchemaVersion = 2
        SecretGeneration = $Generation
        PortalAdminUser = 'dylan'
        PortalAdminPassword = New-RandomSecret 24
        NodeApiToken = New-RandomSecret 32
        ResticPassword = New-RandomSecret 40
        VaultRestUser = "devfleet-client-$($Generation.Substring(0,8))"
        VaultRestPassword = New-RandomSecret 32
        Created = (Get-Date).ToUniversalTime().ToString('o')
    }
}

function Get-OrCreateSecrets {
    $path = Join-Path (Get-DevFleetStateRoot) 'secrets\host-secrets.json'
    if (-not (Test-Path $path)) {
        if (Test-ExistingDeploymentState) { throw 'SECRET RECOVERY REQUIRED: host secrets are missing while existing DevFleet deployment state is present. Use the explicit re-key/repair workflow.' }
        $obj = New-DevFleetSecretRecord
        $obj | ConvertTo-Json | Set-Content $path -Encoding utf8
        Protect-DevFleetStateAcl
    }
    try {
        $secrets = Get-Content $path -Raw | ConvertFrom-Json
        if (-not (Test-DevFleetSecretRecord -Secrets $secrets)) { throw 'Host secret record is incomplete or invalid.' }
        return $secrets
    }
    catch {
        if (Test-ExistingDeploymentState) { throw 'SECRET RECOVERY REQUIRED: host secrets are corrupt while existing DevFleet deployment state is present. Use the explicit re-key/repair workflow.' }
        throw 'Host secrets are corrupt; remove the incomplete fresh-install state and restart setup.'
    }
}

function Invoke-External {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter()][string[]]$ArgumentList = @(),
        [Parameter()][int[]]$RedactArgumentIndexes = @(),
        [Parameter()][int]$TimeoutSeconds = 900,
        [Parameter()][int]$MaxDiagnosticChars = 12000,
        [Parameter()][string]$EvidenceLogPath = '',
        [Parameter()][string]$StandardInputText = '',
        [Parameter()][datetime]$DeadlineUtc = [datetime]::MinValue,
        [Parameter()][int[]]$AllowedExitCodes = @(0),
        [switch]$IgnoreExitCode,
        [switch]$Capture
    )
    $deadlineContext=Get-DevFleetDeadlineContext
    # An explicit child deadline is subordinate to the active owning stage.
    # Taking the minimum here prevents a nested helper (for example readiness
    # or a bounded retry loop) from accidentally escaping its stage merely by
    # supplying its own finite deadline.
    $deadlines = @()
    if ($DeadlineUtc -gt [datetime]::MinValue) { $deadlines += $DeadlineUtc.ToUniversalTime() }
    if ($deadlineContext) { $deadlines += ([datetime]$deadlineContext.StageDeadlineUtc).ToUniversalTime() }
    $deadline = if ($deadlines.Count -gt 0) { ($deadlines | Measure-Object -Minimum).Minimum } else { [datetime]::MinValue }
    if ($deadline -gt [datetime]::MinValue) {
        $remaining = [int][math]::Floor(($deadline - [datetime]::UtcNow).TotalSeconds)
        if ($remaining -le 0) { throw "Owning deadline expired before starting external command: $FilePath" }
        $TimeoutSeconds = [math]::Min($TimeoutSeconds, $remaining)
    }
    if ($TimeoutSeconds -le 0) { throw 'External command timeout must remain positive after deadline propagation.' }
    $safeArguments = for($i=0;$i -lt $ArgumentList.Count;$i++){ if($RedactArgumentIndexes -contains $i){ '<redacted-secret>' } else { [string]$ArgumentList[$i] } }
    Write-Verbose ("Executing: {0} {1}" -f $FilePath, ($safeArguments -join ' '))
    $psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName=$FilePath;$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true;$psi.RedirectStandardInput=($null -ne $StandardInputText -and $StandardInputText.Length -gt 0)
    foreach($argument in $ArgumentList){[void]$psi.ArgumentList.Add([string]$argument)}
    $process=[Diagnostics.Process]::new();$process.StartInfo=$psi;$stdoutTail=[Text.StringBuilder]::new();$stderrTail=[Text.StringBuilder]::new();$logWriter=$null
    try {
        if($EvidenceLogPath){$parent=Split-Path -Parent $EvidenceLogPath;if($parent){New-Item -ItemType Directory -Force -Path $parent|Out-Null};$logWriter=[IO.StreamWriter]::new($EvidenceLogPath,$false,[Text.Encoding]::UTF8)}
        if(-not $process.Start()){throw "Unable to start external command: $FilePath"}
        if($psi.RedirectStandardInput){$process.StandardInput.Write($StandardInputText);$process.StandardInput.Close()}
        $stdoutTask=$process.StandardOutput.ReadToEndAsync();$stderrTask=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit([Math]::Max(1,$TimeoutSeconds)*1000)){
            try{$process.Kill($true)}catch{}
            try{[void]([Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]]@($stdoutTask,$stderrTask)).Wait([TimeSpan]::FromSeconds(5)))}catch{}
            throw "External command timed out after $TimeoutSeconds seconds: $FilePath $($safeArguments -join ' ')"
        }
        $exitCode=$process.ExitCode
        $outputComplete=$false
        try{$outputComplete=[Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]]@($stdoutTask,$stderrTask)).Wait([TimeSpan]::FromSeconds(5))}catch{$outputComplete=$false}
        $stdout=if($stdoutTask.Status -eq [Threading.Tasks.TaskStatus]::RanToCompletion){$stdoutTask.GetAwaiter().GetResult()}else{''}
        $stderr=if($stderrTask.Status -eq [Threading.Tasks.TaskStatus]::RanToCompletion){$stderrTask.GetAwaiter().GetResult()}else{''}
        $combined=($stdout+"`n"+$stderr).Trim()
        if($logWriter){$logWriter.Write($combined);if(-not $outputComplete){$logWriter.Write("`n[DEVFLEET_OUTPUT_INCOMPLETE_AFTER_PROCESS_EXIT]")};$logWriter.Flush()}
        $diagnostic=if($combined.Length -gt $MaxDiagnosticChars){$combined.Substring($combined.Length-$MaxDiagnosticChars)}else{$combined}
        if(-not $outputComplete){
            $message="External command exited with code $exitCode, but redirected output was incomplete after the bounded post-exit drain: $FilePath $($safeArguments -join ' ')"
            if($Capture){throw $message}
            if($exitCode -notin $AllowedExitCodes -and -not $IgnoreExitCode){throw "$message`n$diagnostic"}
            Write-Warning $message
            return
        }
        if($exitCode -notin $AllowedExitCodes -and -not $IgnoreExitCode){throw "$FilePath failed with exit code $exitCode`n$diagnostic"}
        if($Capture){return $combined}
    } finally {if($logWriter){$logWriter.Dispose()};$process.Dispose()}
}

function Test-CommandExists { param([string]$Name) [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

function Get-DevFleetPowerShell {
    foreach($candidate in @(
        (Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'),
        (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe')
    )) { if($candidate -and (Test-TrustedExecutableCandidate $candidate)){return $candidate} }
    throw 'No trusted machine PowerShell executable was found.'
}

function Get-CanonicalDependencyManifest {
    param([Parameter(Mandatory)][string]$PackageRoot)
    $path = Join-Path $PackageRoot 'dependencies.json'
    if (-not (Test-Path -LiteralPath $path)) { throw "Canonical dependency manifest is missing: $path" }
    $manifest = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($manifest.schemaVersion -ne 1 -or $manifest.manifestVersion -ne (Get-Content (Join-Path $PackageRoot 'VERSION') -Raw).Trim()) { throw 'Canonical dependency manifest schema/version mismatch.' }
    if (-not $manifest.dependencies -or @($manifest.dependencies).Count -lt 1) { throw 'Canonical dependency manifest contains no dependency records.' }
    return $manifest
}

function Expand-DependencyLocation {
    param([Parameter(Mandatory)][string]$Path)
    return [Environment]::ExpandEnvironmentVariables($Path)
}

function Resolve-DependencyExecutable {
    param([Parameter(Mandatory)]$Dependency)
    foreach ($candidate in (Get-TrustedDependencyCandidates $Dependency)) { return $candidate }
    return $null
}

function Test-PrimitiveMutationRights {
    param([Parameter(Mandatory)][Security.AccessControl.FileSystemRights]$Rights)
    # Keep this mask primitive-only.  Modify and FullControl are composites;
    # their primitive mutation bits still intersect the mask naturally.
    $mutationMask = [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    return (($Rights -band $mutationMask) -ne 0)
}

function Test-BroadUntrustedPrincipal {
    param([Parameter(Mandatory)][string]$Identity)
    return $Identity.Equals('Everyone',[StringComparison]::OrdinalIgnoreCase) -or
        $Identity.EndsWith('\Users',[StringComparison]::OrdinalIgnoreCase) -or
        $Identity.Equals('NT AUTHORITY\Authenticated Users',[StringComparison]::OrdinalIgnoreCase)
}

function Get-TrustedSystemRootForExecutable {
    param([Parameter(Mandatory)][string]$FullPath)
    try {
        $candidate = [IO.Path]::GetFullPath($FullPath).TrimEnd('\')
        $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:WINDIR) |
            Where-Object { $_ } |
            ForEach-Object { [IO.Path]::GetFullPath([string]$_).TrimEnd('\') } |
            Select-Object -Unique |
            Where-Object { $candidate.StartsWith($_ + '\',[StringComparison]::OrdinalIgnoreCase) }
        if (@($roots).Count -ne 1) { return $null }
        return [string]@($roots)[0]
    } catch { return $null }
}

function Get-TrustedWingetPackageCandidates {
    $result = [Collections.Generic.List[object]]::new()
    try {
        $windowsApps = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'WindowsApps')).TrimEnd('\')
        $windowsAppsInfo = Get-Item -LiteralPath $windowsApps -Force -ErrorAction Stop
        if (($windowsAppsInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return @() }
        foreach ($package in @(Get-AppxPackage -AllUsers -Name 'Microsoft.DesktopAppInstaller' -ErrorAction Stop)) {
            $installLocation = [string]$package.InstallLocation
            if ([string]::IsNullOrWhiteSpace($installLocation)) { continue }
            $root = [IO.Path]::GetFullPath($installLocation).TrimEnd('\')
            $rootInfo = Get-Item -LiteralPath $root -Force -ErrorAction Stop
            $basename = [IO.Path]::GetFileName($root)
            if (-not $package.Name.Equals('Microsoft.DesktopAppInstaller',[StringComparison]::OrdinalIgnoreCase) -or
                -not ([string]$package.PublisherId).Equals('8wekyb3d8bbwe',[StringComparison]::OrdinalIgnoreCase) -or
                -not ([IO.Path]::GetDirectoryName($root)).Equals($windowsApps,[StringComparison]::OrdinalIgnoreCase) -or
                -not $basename.StartsWith('Microsoft.DesktopAppInstaller_',[StringComparison]::OrdinalIgnoreCase) -or
                -not $basename.EndsWith('_x64__8wekyb3d8bbwe',[StringComparison]::OrdinalIgnoreCase) -or
                ($rootInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            $version = $basename.Substring('Microsoft.DesktopAppInstaller_'.Length, $basename.Length - 'Microsoft.DesktopAppInstaller_'.Length - '_x64__8wekyb3d8bbwe'.Length)
            if ([string]::IsNullOrWhiteSpace($version) -or @($version.Split('.') | Where-Object { $_ -notmatch '^\d+$' }).Count -gt 0) { continue }
            $candidate = Join-Path $root 'winget.exe'
            if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
            $candidateInfo = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
            if (($candidateInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            $result.Add([pscustomobject]@{ Path = [IO.Path]::GetFullPath($candidate); Root = $root })
        }
        return @($result | Sort-Object Path -Unique)
    } catch { return @() }
}

function Test-TrustedExecutableCandidate {
    param([Parameter(Mandatory)][string]$Path,[Parameter()][object]$Dependency)
    try {
        if ([string]$Path -match '(?i)(^|[\\/])\.\.?([\\/]|$)') { return $false }
        $full = [IO.Path]::GetFullPath($Path)
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { return $false }
        if ([IO.Path]::GetExtension($full).ToLowerInvariant() -in @('.cmd','.bat') -and $Dependency) { return $false }
        $trustedRoot = $null
        if ([IO.Path]::GetFileName($full).Equals('winget.exe',[StringComparison]::OrdinalIgnoreCase)) {
            $wingetCandidates = @(Get-TrustedWingetPackageCandidates | Where-Object { $_.Path.Equals($full,[StringComparison]::OrdinalIgnoreCase) })
            if ($wingetCandidates.Count -ne 1) { return $false }
            $trustedRoot = [string]$wingetCandidates[0].Root
        } else { $trustedRoot = Get-TrustedSystemRootForExecutable $full }
        if ([string]::IsNullOrWhiteSpace($trustedRoot)) { return $false }
        $rootInfo = Get-Item -LiteralPath $trustedRoot -Force -ErrorAction Stop
        if (($rootInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
        $fileInfo = Get-Item -LiteralPath $full -Force -ErrorAction Stop
        if (($fileInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
        foreach($entry in @((Get-Acl -LiteralPath $full -ErrorAction Stop).Access)) {
            if($entry.AccessControlType -eq 'Allow' -and (Test-BroadUntrustedPrincipal ([string]$entry.IdentityReference.Value)) -and (Test-PrimitiveMutationRights ([Security.AccessControl.FileSystemRights]$entry.FileSystemRights))){return $false}
        }
        $cursor = [IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($full))
        $reachedRoot = $false
        while($cursor){
            if(($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){return $false}
            foreach($entry in @((Get-Acl -LiteralPath $cursor.FullName -ErrorAction Stop).Access)) {
                if($entry.AccessControlType -eq 'Allow' -and (Test-BroadUntrustedPrincipal ([string]$entry.IdentityReference.Value)) -and (Test-PrimitiveMutationRights ([Security.AccessControl.FileSystemRights]$entry.FileSystemRights))){return $false}
            }
            if($cursor.FullName.TrimEnd('\').Equals($trustedRoot.TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase)){ $reachedRoot = $true; break }
            $cursor=$cursor.Parent
        }
        if (-not $reachedRoot) { return $false }
        $policy=if($null -ne $Dependency){$Dependency.installerAuthenticityPolicy}else{$null}
        $exact=@(if($null -ne $policy){$policy.allowedSignerSubjectsExact})
        $signature=Get-AuthenticodeSignature -LiteralPath $full
        $installedTrust = if($null -ne $policy -and $null -ne $policy.PSObject.Properties['installedExecutableTrust']){[string]$policy.installedExecutableTrust}else{''}
        $allowUnsignedInstalled = $installedTrust -eq 'signed-installer-locked-path' -and $signature.Status -eq 'NotSigned'
        if($signature.Status -ne 'Valid' -and -not $allowUnsignedInstalled){return $false}
        if($signature.Status -eq 'Valid' -and @($exact).Count -gt 0 -and -not (Test-ExactSignerIdentity ([string]$signature.SignerCertificate.Subject) $exact)){return $false}
        if(@($exact).Count -eq 0 -and $null -ne $policy -and @($policy.allowedSignerPatterns).Count -gt 0){return $false}
        return $true
    } catch { return $false }
}

function Normalize-SignerIdentity {
    param([Parameter(Mandatory)][string]$Subject)
    try { return (([Security.Cryptography.X509Certificates.X500DistinguishedName]::new($Subject)).Format($false) -replace '\s','').ToUpperInvariant() }
    catch { return ($Subject -replace '\s','').ToUpperInvariant() }
}
function Test-ExactSignerIdentity {
    param([Parameter(Mandatory)][string]$Subject,[Parameter(Mandatory)][string[]]$Expected)
    $actual=Normalize-SignerIdentity $Subject
    return @($Expected | Where-Object { (Normalize-SignerIdentity ([string]$_)) -ceq $actual }).Count -gt 0
}

function Get-TrustedDependencyCandidates {
    param([Parameter(Mandatory)]$Dependency)
    $paths = [Collections.Generic.List[string]]::new()
    foreach ($probe in @($Dependency.executableProbes)) {
        $pathEntries = ([Environment]::GetEnvironmentVariable('PATH') -split [IO.Path]::PathSeparator) | Where-Object { $_ }
        foreach ($entry in $pathEntries) {
            $candidate = Join-Path $entry.Trim('"') $probe
            if ((Test-Path -LiteralPath $candidate) -and (Test-TrustedExecutableCandidate $candidate -Dependency $Dependency)) { $paths.Add([IO.Path]::GetFullPath($candidate)) }
        }
        foreach ($hive in @('HKLM:')) {
            foreach ($subkey in @("SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$probe", "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\$probe")) {
                $key = Get-Item -LiteralPath (Join-Path $hive $subkey) -ErrorAction SilentlyContinue
                $value = if ($key) { $key.GetValue('') } else { $null }
                $candidate = if ($value) { ([string]$value).Trim('"') } else { $null }
                if ($candidate -and (Test-TrustedExecutableCandidate $candidate -Dependency $Dependency)) { $paths.Add([IO.Path]::GetFullPath($candidate)) }
            }
        }
    }
    foreach ($location in @($Dependency.knownVendorInstallLocations)) {
        $expanded = Expand-DependencyLocation $location
        if ((Test-Path -LiteralPath $expanded) -and (Test-TrustedExecutableCandidate $expanded -Dependency $Dependency)) { $paths.Add([IO.Path]::GetFullPath($expanded)) }
    }
    return $paths | Select-Object -Unique
}

function Get-DependencyStatus {
    param([Parameter(Mandatory)]$Dependency)
    $args = @($Dependency.versionProbe.arguments)
    $first = $null
    foreach ($path in (Get-TrustedDependencyCandidates $Dependency)) {
        try { $output = & $path @args 2>&1 | Out-String; $exit = $LASTEXITCODE } catch { continue }
        $match = if ($Dependency.versionProbe.regex) { [regex]::Match($output, [string]$Dependency.versionProbe.regex) } else { $null }
        if ($exit -ne 0 -or -not $match -or -not $match.Success) {
            if ($null -eq $first) { $first = [pscustomobject]@{ Status='Broken'; Path=$path; Version=$null; Detail='Trusted executable was found but version probe failed.' } }
            continue
        }
        $version = [Version]$match.Groups[1].Value
        $minimum = [Version]$Dependency.minimumSupportedVersion
        $status = if ($version -lt $minimum) { 'Outdated' } elseif ($null -ne $Dependency.maximumMajor -and $version.Major -gt [int]$Dependency.maximumMajor) { 'Unsupported-Major' } else { 'Compatible' }
        $result = [pscustomobject]@{ Status=$status; Path=$path; Version=$version; Detail="Resolved trusted executable $path; version $version" }
        if ($status -eq 'Compatible') { return $result }
        if ($null -eq $first) { $first = $result }
    }
    if ($null -ne $first) { return $first }
    return [pscustomobject]@{ Status='Missing'; Path=''; Version=$null; Detail='No trusted machine executable, HKLM App Path, or vendor location matched.' }
}


function Get-TailscaleExe {
    foreach ($candidate in @(
        (Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Tailscale\tailscale.exe')
    )) { if ($candidate -and (Test-TrustedExecutableCandidate $candidate)) { return $candidate } }
    throw 'Tailscale is not installed in a trusted machine location.'
}

function Get-VsCodeCli {
    param([switch]$AllowPerUser)
    foreach ($candidate in @(
        (Join-Path $env:ProgramFiles 'Microsoft VS Code\bin\code.cmd'),
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft VS Code\bin\code.cmd')
    )) { if ($candidate -and (Test-TrustedExecutableCandidate $candidate)) { return $candidate } }
    if ($AllowPerUser) {
        $user = Join-Path $env:LOCALAPPDATA 'Programs\Microsoft VS Code\bin\code.cmd'
        if ($user -and (Test-Path -LiteralPath $user -PathType Leaf) -and -not ((Get-Item -LiteralPath $user -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $user }
    }
    return $null
}

function Get-MultipassExe {
    # Multipass is intentionally allowed to be unsigned after installation only
    # when the canonical dependency policy binds it to a signed installer and a
    # locked machine path.  Resolve through that same policy as Ensure-Dependency
    # so runtime helpers cannot reject a legitimate install (or invent a weaker
    # trust rule of their own).
    $packageRoot = Get-DevFleetPackageRoot
    $manifest = Get-CanonicalDependencyManifest -PackageRoot $packageRoot
    $dependency = @($manifest.dependencies | Where-Object id -eq 'multipass' | Select-Object -First 1)
    if (-not $dependency) { throw 'Canonical Multipass dependency policy is missing.' }
    $status = Get-DependencyStatus -Dependency $dependency
    if ($status.Status -eq 'Compatible' -and $status.Path) { return $status.Path }
    throw "Multipass is not installed in a trusted machine location or compatible state: $($status.Status)."
}


function Assert-MultipassIsolation {
    param([string[]]$InstanceNames = @())
    $mp = Get-MultipassExe
    $setting = Invoke-External $mp @('get','local.privileged-mounts') -Capture
    if ($setting.Trim().ToLowerInvariant() -ne 'false') {
        throw 'Multipass host mounts are not disabled. Run: multipass set local.privileged-mounts=false'
    }
    foreach ($name in $InstanceNames) {
        if (-not $name -or -not (Test-MultipassInstance $name)) { continue }
        $raw = Invoke-External $mp @('info',$name,'--format','json') -Capture
        $data = $raw | ConvertFrom-Json
        $prop = $data.info.PSObject.Properties[$name]
        if (-not $prop) { throw "Multipass info did not contain instance $name." }
        $info = $prop.Value
        if ($info.PSObject.Properties.Name -contains 'mounts' -and $null -ne $info.mounts) {
            $mountCount = 0
            if ($info.mounts -is [System.Array]) {
                $mountCount = @($info.mounts).Count
            } elseif ($info.mounts -is [string]) {
                if (-not [string]::IsNullOrWhiteSpace([string]$info.mounts)) { $mountCount = 1 }
            } else {
                $mountCount = @($info.mounts.PSObject.Properties).Count
            }
            if ($mountCount -gt 0) { throw "$name has one or more host mounts. Remove them before using DevFleet." }
        }
    }
}

function Get-MultipassInstances {
    $mp = Get-MultipassExe
    $raw = Invoke-External $mp @('list','--format','json') -Capture
    if (-not $raw) { return @() }
    $data = $raw | ConvertFrom-Json
    @($data.list)
}

function Test-MultipassInstance { param([string]$Name) [bool](Get-MultipassInstances | Where-Object name -eq $Name) }

function Wait-MultipassReady {
    param([string]$Name,[int]$TimeoutSeconds=600,[datetime]$DeadlineUtc=[datetime]::MinValue)
    $mp = Get-MultipassExe
    if($TimeoutSeconds -le 0){throw 'Multipass readiness timeout must be positive.'}
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $context = Get-DevFleetDeadlineContext
    if($DeadlineUtc -gt [datetime]::MinValue -and $DeadlineUtc.ToUniversalTime() -lt $deadline){$deadline=$DeadlineUtc.ToUniversalTime()}
    elseif($context -and [datetime]$context.StageDeadlineUtc -lt $deadline){$deadline=[datetime]$context.StageDeadlineUtc.ToUniversalTime()}
    $attempt=0
    while([DateTime]::UtcNow -lt $deadline) {
        $attempt++
        $out = $null
        try {
            # Probe without --wait so the outer deadline remains authoritative. Newer
            # cloud-init versions expose JSON; older versions use the normalized text
            # fallback below. Exit code 2 is not itself a readiness result.
            $remaining=[int][math]::Floor(($deadline-[DateTime]::UtcNow).TotalSeconds)
            if($remaining -le 0){break}
            $out = Invoke-External $mp @('exec',$Name,'--','bash','-lc','cloud-init status --format=json 2>&1 || cloud-init status 2>&1') -Capture -IgnoreExitCode -TimeoutSeconds ([math]::Min(900,$remaining)) -DeadlineUtc $deadline
        } catch {
            $remaining=[math]::Max(0,($deadline-[DateTime]::UtcNow).TotalSeconds)
            Write-Verbose "Multipass readiness probe $attempt failed for $Name; retrying with $([math]::Round($remaining,1)) seconds remaining."
            if($remaining -le 0){break}
            Start-Sleep -Milliseconds ([int][math]::Min(5000,[math]::Max(100,$remaining*1000)))
            continue
        }
        $normalized=[regex]::Replace([string]$out,'\x1B(?:\[[0-?]*[ -/]*[@-~]|\][^\a]*(?:\a|\x1B\\))','')
        $normalized=$normalized -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]',''
        $state=$null
        try {
            $structured=$normalized.Trim() | ConvertFrom-Json
            if($structured -and $structured.PSObject.Properties.Name -contains 'status'){$state=[string]$structured.status}
            if($structured -and $structured.PSObject.Properties.Name -contains 'extended_status' -and [string]$structured.extended_status -match '(?i)error|degraded|fail'){$state='error'}
        } catch { }
        if(-not $state){
            if($normalized -match '(?im)^\s*status:\s*done\s*$'){$state='done'}
            elseif($normalized -match '(?im)^\s*status:\s*(error|degraded|failed)\s*$'){$state='error'}
            elseif($normalized -match '(?im)^\s*status:\s*(running|pending|not\s+started)\s*$'){$state='running'}
        }
        if($state -eq 'done'){return}
        if($state -eq 'error'){throw "cloud-init failed in $Name`n$normalized"}
        $remaining=[math]::Max(0,($deadline-[DateTime]::UtcNow).TotalSeconds)
        $summary=($normalized -replace '\s+',' ')
        if($summary.Length -gt 240){$summary=$summary.Substring([math]::Max(0,$summary.Length-240))}
        Write-Verbose "Multipass readiness probe $attempt for $Name returned: $summary; $([math]::Round($remaining,1)) seconds remaining."
        if($remaining -le 0){break}
        Start-Sleep -Milliseconds ([int][math]::Min(5000,[math]::Max(100,$remaining*1000)))
    }
    throw "Instance $Name did not become ready within $TimeoutSeconds seconds."
}

function Get-InstanceIPv4 {
    param([string]$Name,[switch]$PreferTailscale)
    $mp = Get-MultipassExe
    if ($PreferTailscale) {
        $ts = Invoke-External $mp @('exec',$Name,'--','bash','-lc','tailscale ip -4 2>/dev/null | head -n1') -Capture -IgnoreExitCode
        $tsIp = @($ts -split "`r?`n") | Where-Object { $_ -match '^100\.' } | Select-Object -First 1
        if ($tsIp) { return $tsIp.Trim() }
    }
    $raw = Invoke-External $mp @('info',$Name,'--format','json') -Capture
    $obj = $raw | ConvertFrom-Json
    $prop = $obj.info.PSObject.Properties[$Name]
    if (-not $prop) { throw "Multipass info did not contain instance $Name." }
    $ips = @($prop.Value.ipv4) | Where-Object { $_ }
    $preferred = $ips | Where-Object { $_ -notmatch '^(127\.|169\.254\.)' -and $_ -notmatch '^172\.' } | Select-Object -First 1
    if ($preferred) { return $preferred }
    $ips | Where-Object { $_ -notmatch '^(127\.|169\.254\.)' } | Select-Object -First 1
}

function Test-PendingRebootState {
    param(
        [bool]$CbsPending,
        [bool]$WindowsUpdatePending,
        [AllowNull()][object[]]$PendingFileRenameOperations
    )
    if ($CbsPending -or $WindowsUpdatePending) { return $true }
    $meaningful = @($PendingFileRenameOperations | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_)
    })
    $meaningful.Count -gt 0
}

function Test-PendingReboot {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )
    $cbsPending = Test-Path $paths[0]
    $windowsUpdatePending = Test-Path $paths[1]
    $session = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    $raw = if ($null -ne $session) { $session.PendingFileRenameOperations } else { $null }
    Test-PendingRebootState -CbsPending:$cbsPending -WindowsUpdatePending:$windowsUpdatePending -PendingFileRenameOperations $raw
}

function Install-WingetPackage {
    param([Parameter(Mandatory)][string]$Id,[switch]$Upgrade)
    $health = Get-WingetHealth
    if ($health.Status -ne 'Healthy') { throw "WinGet is not healthy ($($health.Status)); use repair or official vendor fallback." }
    $common = @('--id',$Id,'--exact','--source','winget','--accept-package-agreements','--accept-source-agreements','--silent','--disable-interactivity')
    if ($Upgrade) {
        Invoke-External -FilePath $health.Path -ArgumentList (@('upgrade') + $common) -TimeoutSeconds 600 -AllowedExitCodes @(0,-1978335189) | Out-Null
    } else {
        Invoke-External -FilePath $health.Path -ArgumentList (@('install') + $common) -TimeoutSeconds 600 -AllowedExitCodes @(0,-1978335189) | Out-Null
    }
}

function Get-WingetHealth {
    $candidates = @(Get-TrustedWingetPackageCandidates)
    if($candidates.Count -eq 0){ return [pscustomobject]@{ Status='Missing'; Path=''; Version=''; Detail='No exact physical Microsoft.DesktopAppInstaller x64 package with winget.exe was found.' } }
    if($candidates.Count -ne 1){ return [pscustomobject]@{ Status='Broken'; Path=''; Version=''; Detail='WinGet package identity was ambiguous; exactly one physical package is required.' } }
    $wingetPath = [string]$candidates[0].Path
    if(-not (Test-TrustedExecutableCandidate $wingetPath)){ return [pscustomobject]@{ Status='Missing'; Path=''; Version=''; Detail='The physical WinGet package failed trusted-root or ACL validation.' } }
    try { $versionText = Invoke-External -FilePath $wingetPath -ArgumentList @('--version') -TimeoutSeconds 60 -Capture }
    catch { return [pscustomobject]@{ Status='Broken'; Path=$wingetPath; Version=''; Detail="winget --version could not start: $($_.Exception.Message)" } }
    $version = ([regex]::Match($versionText, '(?<!\d)(\d+\.\d+(?:\.\d+){0,2})')).Groups[1].Value
    try { Invoke-External -FilePath $wingetPath -ArgumentList @('source','list','--disable-interactivity') -TimeoutSeconds 60 | Out-Null }
    catch { return [pscustomobject]@{ Status='Broken'; Path=$wingetPath; Version=$version; Detail="winget source list could not start: $($_.Exception.Message)" } }
    try { Invoke-External -FilePath $wingetPath -ArgumentList @('search','--id','Microsoft.PowerShell','--exact','--source','winget','--disable-interactivity') -TimeoutSeconds 60 | Out-Null }
    catch { return [pscustomobject]@{ Status='Broken'; Path=$wingetPath; Version=$version; Detail="winget package search could not start: $($_.Exception.Message)" } }
    return [pscustomobject]@{ Status='Healthy'; Path=$wingetPath; Version=$version; Detail='version, source list, and package search succeeded.' }
}

function Repair-Winget {
    $repair = 'Install-PackageProvider -Name NuGet -Force | Out-Null; Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery | Out-Null; Repair-WinGetPackageManager -Force -Latest'
    $powershell=Get-DevFleetPowerShell
    Invoke-External -FilePath $powershell -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command',$repair) -TimeoutSeconds 600 | Out-Null
    $health = Get-WingetHealth
    if ($health.Status -ne 'Healthy') { throw "WinGet remained unhealthy after repair: $($health.Status)" }
    return $health
}

function Get-AuthenticityStrategy {
    param([Parameter(Mandatory)]$Policy)
    if ($Policy.PSObject.Properties.Name -contains 'strategy' -and $Policy.strategy) { return [string]$Policy.strategy }
    return 'Authenticode'
}

function Test-FileSha256 {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Expected)
    if ($Expected -notmatch '^[0-9a-fA-F]{64}$') { throw "Expected vendor release digest is not a SHA-256 value for $([IO.Path]::GetFileName($Path))." }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if (-not $actual.Equals($Expected, [StringComparison]::OrdinalIgnoreCase)) { throw "Vendor release SHA-256 mismatch for $([IO.Path]::GetFileName($Path)): expected $Expected, got $actual." }
    return $actual.ToLowerInvariant()
}

function Test-OfficialSigner {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)]$Policy)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $strategy = Get-AuthenticityStrategy $Policy
    if ($strategy -eq 'VendorReleaseSha256') { throw "VendorReleaseSha256 requires release metadata digest validation, not Authenticode, for $([IO.Path]::GetFileName($Path))." }
    if ($signature.Status -ne 'Valid' -and $strategy -eq 'Authenticode') { throw "Authenticode verification failed for $([IO.Path]::GetFileName($Path)): $($signature.Status)" }
    if ($signature.Status -ne 'Valid' -and $strategy -eq 'AuthenticodeOrVendorReleaseSha256') { throw "AuthenticodeOrVendorReleaseSha256 requires a valid fallback digest for $([IO.Path]::GetFileName($Path))." }
    $exact=@($Policy.allowedSignerSubjectsExact)
    if(@($exact).Count -gt 0 -and -not (Test-ExactSignerIdentity ([string]$signature.SignerCertificate.Subject) $exact)){throw "Unexpected signer for $([IO.Path]::GetFileName($Path)): $($signature.SignerCertificate.Subject)"}
    if(@($exact).Count -eq 0 -and @($Policy.allowedSignerPatterns).Count -gt 0){throw "Legacy substring signer policy is rejected for $([IO.Path]::GetFileName($Path)); release policy must provide allowedSignerSubjectsExact."}
}

function Save-AllowlistedHttpsDownload {
    param([Parameter(Mandatory)][Uri]$Uri,[Parameter(Mandatory)][string[]]$AllowedHosts,[Parameter(Mandatory)][string]$Path)
    $current=$Uri
    for($hop=0;$hop -le 5;$hop++){
        if($current.Scheme -ne 'https' -or $current.UserInfo -or $current.Host -notin $AllowedHosts){throw "Download redirect left the allowlisted HTTPS boundary: $current"}
        Add-Type -AssemblyName System.Net.Http -ErrorAction Stop
        $handler=[System.Net.Http.HttpClientHandler]::new();$handler.AllowAutoRedirect=$false;$client=[System.Net.Http.HttpClient]::new($handler);$client.Timeout=[TimeSpan]::FromSeconds(60);$response=$null;$input=$null;$output=$null
        try{
            $response=$client.GetAsync($current).GetAwaiter().GetResult()
            if([int]$response.StatusCode -ge 300 -and [int]$response.StatusCode -le 399){
                $location=$response.Headers.Location;$response.Dispose();$response=$null
                if(-not $location){throw 'Allowlisted download redirect omitted Location.'}
                $current=[Uri]::new($current,$location);continue
            }
            if(-not $response.IsSuccessStatusCode){throw "Allowlisted download failed with HTTP $([int]$response.StatusCode)."}
            $input=$response.Content.ReadAsStreamAsync().GetAwaiter().GetResult();$output=[IO.File]::Open($Path,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None);$input.CopyTo($output);$output.Flush();return
        } finally {
            if($output){$output.Dispose()};if($input){$input.Dispose()};if($response){$response.Dispose()};$client.Dispose();$handler.Dispose()
        }
    }
    throw 'Allowlisted download exceeded the redirect limit.'
}

function Install-OfficialDependency {
    param([Parameter(Mandatory)]$Dependency)
    if ($Dependency.directOfficialVendorResolver.type -eq 'windows-capability') {
        $capability = Get-WindowsCapability -Online | Where-Object Name -Like 'OpenSSH.Client*' | Select-Object -First 1
        if (-not $capability) { throw 'Official OpenSSH Windows capability was not found.' }
        if ($capability.State -ne 'Installed') { Add-WindowsCapability -Online -Name $capability.Name | Out-Null }
        return
    }
    $resolver = $Dependency.directOfficialVendorResolver
    $assetName = $null
    $assetUri = $null
    $expectedDigest = $null
    if ($resolver.type -eq 'github-release') {
        $metadata = Invoke-RestMethod -UseBasicParsing -TimeoutSec 60 -Uri $resolver.metadataUri -Headers @{ 'User-Agent'='DevFleet-Setup/1.4.1' }
        if ($resolver.PSObject.Properties.Name -contains 'expectedOwner' -and $resolver.expectedOwner) {
            if ([string]$metadata.author.login -ne [string]$resolver.expectedOwner) { throw "Official release owner mismatch for $($Dependency.displayName)." }
        }
        if ($resolver.PSObject.Properties.Name -contains 'expectedRepository' -and $resolver.expectedRepository) {
            if ([string]$metadata.html_url -notmatch ("/" + [regex]::Escape([string]$resolver.expectedOwner) + "/" + [regex]::Escape([string]$resolver.expectedRepository) + "/releases/")) { throw "Official release repository mismatch for $($Dependency.displayName)." }
        }
        $pageAssetName = $null
        if ($resolver.PSObject.Properties.Name -contains 'officialPageUri' -and $resolver.officialPageUri) {
            $page = (Invoke-WebRequest -UseBasicParsing -TimeoutSec 60 -Uri $resolver.officialPageUri -Headers @{ 'User-Agent'='DevFleet-Setup/1.4.1' }).Content
            $pageLinks = [regex]::Matches($page, '(?i)href\s*=\s*["''](?<href>[^"'']+)["'']') | ForEach-Object { $_.Groups['href'].Value }
            $tag = [string]$metadata.tag_name
            $pageAsset = $null
            foreach ($href in $pageLinks) {
                if ($href -match ("/releases/download/(?<tag>[^/]+)/(?<file>[^?#]+)$") -and $Matches.tag -eq $tag -and $Matches.file -match $resolver.officialPageAssetRegex) { $pageAsset = $href; break }
            }
            if (-not $pageAsset) { throw "Official 7-Zip page did not identify an asset matching the API release tag for $($Dependency.displayName)." }
            $pageAssetName = [IO.Path]::GetFileName(([Uri]$pageAsset).AbsolutePath)
        }
        $asset = @($metadata.assets) | Where-Object { $_.name -match $resolver.assetRegex -and (-not $pageAssetName -or $_.name -eq $pageAssetName) }
        if (@($asset).Count -ne 1) { throw "Expected exactly one official x64 release asset for $($Dependency.displayName), found $(@($asset).Count)." }
        $asset = @($asset)[0]
        $assetName=[string]$asset.name; $assetUri=[Uri]$asset.browser_download_url
        $expectedOwner = if ($resolver.PSObject.Properties.Name -contains 'expectedOwner') { [string]$resolver.expectedOwner } else { '' }
        $expectedRepository = if ($resolver.PSObject.Properties.Name -contains 'expectedRepository') { [string]$resolver.expectedRepository } else { '' }
        if ($expectedOwner -and $expectedRepository -and $assetUri.AbsolutePath -notmatch ("/" + [regex]::Escape($expectedOwner) + "/" + [regex]::Escape($expectedRepository) + "/releases/download/" + [regex]::Escape([string]$metadata.tag_name) + "/")) { throw "Official release asset path/tag mismatch for $($Dependency.displayName)." }
        if ($asset.PSObject.Properties.Name -contains 'digest') { $expectedDigest = ([string]$asset.digest -replace '^sha256:','') }
    } elseif ($resolver.type -eq 'official-download-page') {
        if ($resolver.PSObject.Properties.Name -contains 'directUri' -and $resolver.directUri) {
            $probe = Invoke-WebRequest -UseBasicParsing -TimeoutSec 60 -Method Head -MaximumRedirection 5 -Uri $resolver.directUri -Headers @{ 'User-Agent'='DevFleet-Setup/1.4.1' }
            $candidate = [Uri]$probe.BaseResponse.RequestMessage.RequestUri
            if ($candidate.Host -in @($resolver.allowedHosts) -and ([IO.Path]::GetFileName($candidate.AbsolutePath) -match $resolver.assetRegex)) { $assetUri=$candidate; $assetName=[IO.Path]::GetFileName($candidate.AbsolutePath) }
        } else {
            $page = (Invoke-WebRequest -UseBasicParsing -TimeoutSec 60 -Uri $resolver.metadataUri -Headers @{ 'User-Agent'='DevFleet-Setup/1.4.1' }).Content
            $links = [regex]::Matches($page, '(?i)href\s*=\s*["''](?<href>[^"'']+)["'']') | ForEach-Object { $_.Groups['href'].Value }
            foreach ($href in $links) {
                try { $candidate=[Uri]::new([Uri]$resolver.metadataUri,$href) } catch { continue }
                if ($candidate.Host -in @($resolver.allowedHosts) -and ([IO.Path]::GetFileName($candidate.AbsolutePath) -match $resolver.assetRegex)) { $assetUri=$candidate; $assetName=[IO.Path]::GetFileName($candidate.AbsolutePath); break }
            }
        }
    } else { throw "No implemented authenticated direct resolver for $($Dependency.displayName); official source: $($resolver.metadataUri)" }
    if (-not $assetUri -or $assetUri.Host -notin @($resolver.allowedHosts)) { throw "No authenticated official asset matched for $($Dependency.displayName)." }
    $cache = Join-Path (Get-DevFleetStateRoot) 'InstallerCache\Dependencies'; New-Item -ItemType Directory -Path $cache -Force | Out-Null
    $path = Join-Path $cache $assetName
    $downloaded = $false
    for($attempt=1;$attempt -le 3;$attempt++) { try { Save-AllowlistedHttpsDownload -Uri $assetUri -AllowedHosts @($resolver.allowedHosts) -Path $path; $downloaded=$true; break } catch { if($attempt -eq 3){throw}; Start-Sleep -Seconds $attempt } }
    if (-not $downloaded -or -not (Test-Path -LiteralPath $path)) { throw "Official download did not complete for $($Dependency.displayName)." }
    if ($Dependency.installerAuthenticityPolicy.extensions -notcontains ([IO.Path]::GetExtension($path).ToLowerInvariant())) { throw "Unexpected installer file type for $($Dependency.displayName)." }
    $strategy = Get-AuthenticityStrategy $Dependency.installerAuthenticityPolicy
    if ($strategy -eq 'VendorReleaseSha256' -or $strategy -eq 'AuthenticodeOrVendorReleaseSha256') {
        if (-not $expectedDigest) { throw "Official vendor release did not provide a SHA-256 digest for $($Dependency.displayName)." }
        Test-FileSha256 -Path $path -Expected $expectedDigest | Out-Null
        Write-Host "Verified $($Dependency.displayName) using VendorReleaseSha256 (Authenticode status: $((Get-AuthenticodeSignature -LiteralPath $path).Status))." -ForegroundColor Green
        if ($strategy -eq 'AuthenticodeOrVendorReleaseSha256') {
            $signature = Get-AuthenticodeSignature -LiteralPath $path
            if ($signature.Status -eq 'Valid') { Test-OfficialSigner -Path $path -Policy $Dependency.installerAuthenticityPolicy }
        }
    } else {
        Test-OfficialSigner -Path $path -Policy $Dependency.installerAuthenticityPolicy
    }
    $args = @($Dependency.silentInstallArguments)
    if ([IO.Path]::GetExtension($path).ToLowerInvariant() -eq '.msi') { $msiexec=Join-Path $env:WINDIR 'System32\msiexec.exe';if(-not (Test-TrustedExecutableCandidate $msiexec)){throw 'Trusted Windows Installer executable was not found.'};Invoke-External -FilePath $msiexec -ArgumentList (@('/i',$path)+$args) -TimeoutSeconds (Get-DevFleetOperationMaximumSeconds 'dependencyInstall') | Out-Null } else { Invoke-External -FilePath $path -ArgumentList $args -TimeoutSeconds (Get-DevFleetOperationMaximumSeconds 'dependencyInstall') | Out-Null }
}

function Convert-SecureStringToBundlePassword {
    param([Parameter(Mandatory)][Security.SecureString]$SecureString)
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

function New-EncryptedBundle {
    param([Parameter(Mandatory)][string]$SourceDirectory,[Parameter(Mandatory)][string]$OutputPath)
    $secure = Read-Host 'Enter a strong passphrase for this transfer bundle' -AsSecureString
    $password = Convert-SecureStringToBundlePassword $secure
    if ($password.Length -lt 12) { throw 'Bundle passphrase must be at least 12 characters.' }
    $iterations = 600000
    $salt = [byte[]]::new(16); [Security.Cryptography.RandomNumberGenerator]::Fill($salt)
    $nonce = [byte[]]::new(12); [Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
    $zipPath = "$OutputPath.zip.tmp"
    $key = $null; $plain = $null; $cipher = $null; $tag = $null
    try {
        if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }
        if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
        [IO.Compression.ZipFile]::CreateFromDirectory($SourceDirectory, $zipPath, [IO.Compression.CompressionLevel]::Optimal, $false)
        $plain = [IO.File]::ReadAllBytes($zipPath)
        $header = [byte[]]::new(40)
        [Array]::Copy([Text.Encoding]::ASCII.GetBytes('DFENV001'), 0, $header, 0, 8)
        [Array]::Copy([BitConverter]::GetBytes([uint32]$iterations), 0, $header, 8, 4)
        [Array]::Copy($salt, 0, $header, 12, 16); [Array]::Copy($nonce, 0, $header, 28, 12)
        $kdf = [Security.Cryptography.Rfc2898DeriveBytes]::new($password, $salt, $iterations, [Security.Cryptography.HashAlgorithmName]::SHA256)
        try { $key = $kdf.GetBytes(32) } finally { $kdf.Dispose() }
        $cipher = [byte[]]::new($plain.Length); $tag = [byte[]]::new(16)
        $aes = [Security.Cryptography.AesGcm]::new($key, 16)
        try { $aes.Encrypt($nonce, $plain, $cipher, $tag, $header) } finally { $aes.Dispose() }
        $stream = [IO.File]::Open($OutputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($header,0,$header.Length); $stream.Write([BitConverter]::GetBytes([int64]$cipher.Length),0,8); $stream.Write($cipher,0,$cipher.Length); $stream.Write($tag,0,$tag.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    } finally {
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        if ($plain) { [Array]::Clear($plain,0,$plain.Length) }; if ($cipher) { [Array]::Clear($cipher,0,$cipher.Length) }; if ($key) { [Array]::Clear($key,0,$key.Length) }; $password=$null
    }
}

function Expand-EncryptedBundle {
    param([Parameter(Mandatory)][string]$BundlePath,[Parameter(Mandatory)][string]$Destination)
    $secure = Read-Host 'Enter the transfer-bundle passphrase' -AsSecureString
    $password = Convert-SecureStringToBundlePassword $secure
    $raw = $null; $key = $null; $plain = $null; $zipPath = "$BundlePath.zip.tmp"
    try {
        $raw = [IO.File]::ReadAllBytes($BundlePath)
        if ($raw.Length -lt 72) { throw 'Encrypted bundle is truncated.' }
        $header = [byte[]]::new(40); [Array]::Copy($raw,0,$header,0,40)
        if ([Text.Encoding]::ASCII.GetString($header,0,8) -ne 'DFENV001') { throw 'Unsupported encrypted bundle format.' }
        $iterations = [BitConverter]::ToUInt32($header,8); if ($iterations -lt 100000 -or $iterations -gt 2000000) { throw 'Encrypted bundle KDF parameters are invalid.' }
        $salt = [byte[]]::new(16); $nonce = [byte[]]::new(12); [Array]::Copy($header,12,$salt,0,16); [Array]::Copy($header,28,$nonce,0,12)
        $length = [BitConverter]::ToInt64($raw,40); if ($length -lt 1 -or $length -gt 1073741824 -or $raw.Length -ne 48+$length+16) { throw 'Encrypted bundle ciphertext length is invalid.' }
        $cipher = [byte[]]::new([int]$length); $tag = [byte[]]::new(16); [Array]::Copy($raw,48,$cipher,0,$cipher.Length); [Array]::Copy($raw,48+$cipher.Length,$tag,0,16)
        $kdf = [Security.Cryptography.Rfc2898DeriveBytes]::new($password, $salt, [int]$iterations, [Security.Cryptography.HashAlgorithmName]::SHA256)
        try { $key = $kdf.GetBytes(32) } finally { $kdf.Dispose() }
        $plain = [byte[]]::new($cipher.Length); $aes = [Security.Cryptography.AesGcm]::new($key,16)
        try { $aes.Decrypt($nonce,$cipher,$tag,$plain,$header) } finally { $aes.Dispose() }
        [IO.File]::WriteAllBytes($zipPath,$plain); New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        [IO.Compression.ZipFile]::ExtractToDirectory($zipPath,$Destination,$true)
    } finally {
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        if ($raw) { [Array]::Clear($raw,0,$raw.Length) }; if ($plain) { [Array]::Clear($plain,0,$plain.Length) }; if ($key) { [Array]::Clear($key,0,$key.Length) }; $password=$null
    }
}

function New-DesktopShortcut {
    param([string]$Name,[string]$Target,[string]$Arguments,[string]$WorkingDirectory,[string]$IconLocation='shell32.dll,13')
    $desktop = [Environment]::GetFolderPath('Desktop')
    $path = Join-Path $desktop "$Name.lnk"
    $shell = New-Object -ComObject WScript.Shell
    $sc = $shell.CreateShortcut($path)
    $sc.TargetPath = $Target
    $sc.Arguments = $Arguments
    $sc.WorkingDirectory = $WorkingDirectory
    $sc.IconLocation = $IconLocation
    $sc.Save()
}

function Write-StageMarker {
    param([string]$Name)
    $path = Join-Path (Get-DevFleetStateRoot) "stage-$Name.complete"
    $transaction = Get-ActiveDevFleetTransaction
    if (-not $transaction) { throw 'Cannot write an unbound stage marker without an active DevFleet transaction.' }
    [ordered]@{ transactionId = [string]$transaction.transactionId; payloadSha256 = [string]$transaction.payloadSha256; action = [string]$transaction.action; role = [string]$transaction.role; stage = "stage-$Name"; completedUtc = (Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json -Compress | Set-Content -LiteralPath $path -Encoding utf8
}
function Test-StageMarker {
    param([string]$Name)
    $path = Join-Path (Get-DevFleetStateRoot) "stage-$Name.complete"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $false }
    $transaction = Get-ActiveDevFleetTransaction
    if (-not $transaction) { return $false }
    try {
        $marker = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        return [string]$marker.transactionId -eq [string]$transaction.transactionId -and [string]$marker.payloadSha256 -eq [string]$transaction.payloadSha256 -and [string]$marker.action -eq [string]$transaction.action -and [string]$marker.role -eq [string]$transaction.role -and [string]$marker.stage -eq "stage-$Name"
    } catch { return $false }
}


function Get-OrCreateDevFleetSshKey {
    $sshDir = Join-Path $env:USERPROFILE '.ssh'
    New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
    $key = Join-Path $sshDir 'devfleet_ed25519'
    if (-not (Test-Path $key)) {
        $sshKeygen = @(
            (Join-Path $env:WINDIR 'System32\OpenSSH\ssh-keygen.exe'),
            (Join-Path $env:ProgramFiles 'OpenSSH\ssh-keygen.exe')
        ) | Where-Object { $_ -and (Test-TrustedExecutableCandidate $_) } | Select-Object -First 1
        if (-not $sshKeygen) { throw 'OpenSSH Client/ssh-keygen is required.' }
        $null = Invoke-External $sshKeygen @('-t','ed25519','-a','100','-N','','-C',"devfleet-$env:COMPUTERNAME",'-f',$key)
        & icacls.exe $key /inheritance:r /grant:r "${env:USERNAME}:(R,W)" | Out-Null
    }
    return $key
}

function Add-LocalSshKeyToInstance {
    param([Parameter(Mandatory)][string]$InstanceName,[string]$PublicKeyPath)
    if (-not $PublicKeyPath) { $PublicKeyPath = "$(Get-OrCreateDevFleetSshKey).pub" }
    if (-not (Test-Path $PublicKeyPath)) { throw "Public key not found: $PublicKeyPath" }
    $mp = Get-MultipassExe
    Invoke-External $mp @('transfer',$PublicKeyPath,"${InstanceName}:/tmp/devfleet-client.pub")
    $remote = 'install -d -o devrunner -g devrunner -m 0700 /home/devrunner/.ssh; touch /home/devrunner/.ssh/authorized_keys; key=$(cat /tmp/devfleet-client.pub); grep -qxF "$key" /home/devrunner/.ssh/authorized_keys || echo "$key" >> /home/devrunner/.ssh/authorized_keys; chown devrunner:devrunner /home/devrunner/.ssh/authorized_keys; chmod 0600 /home/devrunner/.ssh/authorized_keys; rm -f /tmp/devfleet-client.pub'
    Invoke-External $mp @('exec',$InstanceName,'--','sudo','bash','-lc',$remote)
}

function New-DevFleetSnapshotSafe {
    param([Parameter(Mandatory)][string]$InstanceName,[Parameter(Mandatory)][string]$SnapshotName)
    Assert-MultipassIsolation -InstanceNames @($InstanceName)
    $mp = Get-MultipassExe
    $raw = Invoke-External $mp @('info',$InstanceName,'--format','json') -Capture
    $info = $raw | ConvertFrom-Json
    $property = $info.info.PSObject.Properties[$InstanceName]
    if (-not $property) { throw "Multipass instance not found: $InstanceName" }
    $state = [string]$property.Value.state
    $wasRunning = $state -eq 'Running'
    if ($wasRunning) { Invoke-External $mp @('stop',$InstanceName) }
    try { Invoke-External $mp @('snapshot',$InstanceName,'--name',$SnapshotName) }
    finally { if ($wasRunning) { Invoke-External $mp @('start',$InstanceName) } }
    return $SnapshotName
}

Export-ModuleMember -Function *
