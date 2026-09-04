[CmdletBinding()]
param(
    [string]$WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path,
    [string]$DotNetPath = (Join-Path $WorkspaceRoot '.dotnet\dotnet.exe')
)

$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path -LiteralPath $WorkspaceRoot -ErrorAction Stop).Path
$dotnet = (Resolve-Path -LiteralPath $DotNetPath -ErrorAction Stop).Path
$project = Join-Path $workspace 'installer-source\DevFleet.Setup\DevFleet.Setup.csproj'
$scratch = Join-Path ([IO.Path]::GetTempPath()) ("DevFleet-StandardTokenSelfTest-{0}" -f [guid]::NewGuid().ToString('N'))
$publish = Join-Path $scratch 'publish'
$reportPath = Join-Path $scratch 'self-test-report.txt'
$process = $null

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Standard-token self-test requires a genuinely non-administrator caller.'
    }

    New-Item -ItemType Directory -Path $publish -Force | Out-Null
    & $dotnet publish $project -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o $publish
    if ($LASTEXITCODE -ne 0) { throw "Installer self-test validation publish failed with exit code $LASTEXITCODE." }

    $exe = Join-Path $publish 'DevFleet.Setup.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Published installer self-test executable is missing.' }
    $before = @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory -Filter 'DevFleet-Setup-SelfTest-*' -ErrorAction SilentlyContinue | ForEach-Object FullName)

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $exe
    $start.Arguments = '--self-test'
    $start.WorkingDirectory = $publish
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.Environment['DEVFLEET_SELF_TEST_OUTPUT'] = $reportPath
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) { throw 'Unable to start the published installer self-test.' }
    if (-not $process.WaitForExit(120000)) {
        try { $process.Kill() } catch {}
        throw 'Published installer self-test timed out.'
    }

    $report = if (Test-Path -LiteralPath $reportPath -PathType Leaf) { Get-Content -LiteralPath $reportPath -Raw } else { '' }
    $after = @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory -Filter 'DevFleet-Setup-SelfTest-*' -ErrorAction SilentlyContinue | ForEach-Object FullName)
    $residual = @($after | Where-Object { $_ -notin $before })
    $required = [ordered]@{
        pass = $report -match '(?m)^PASS\s*$'
        payloadExtraction = $report -match '(?m)^payload_extraction=PASS\s*$'
        bootstrapEntrypoint = $report -match '(?m)^bootstrap_entrypoint=PASS\s*$'
        parameterContract = $report -match '(?m)^bootstrap_parameter_contract=PASS\s*$'
        embeddedTarCount = $report -match '(?m)^embedded_tar_count=1\s*$'
        factoryResetBackupGate = $report -match '(?m)^factory_reset_backup_gate=PASS\s*$'
        planSafety = $report -match '(?m)^plan_safety=PASS\s*$'
    }
    $failed = @($required.GetEnumerator() | Where-Object { -not [bool]$_.Value })
    if ($process.ExitCode -ne 0 -or $failed.Count -ne 0 -or $residual.Count -ne 0) {
        throw "Published standard-token self-test failed: exit=$($process.ExitCode); failedChecks=$(@($failed.Name) -join ','); residualScratch=$($residual.Count)."
    }

    [ordered]@{
        status = 'PASS'
        standardNonAdministratorToken = $true
        exitCode = $process.ExitCode
        reportSha256 = (Get-FileHash -LiteralPath $reportPath -Algorithm SHA256).Hash.ToLowerInvariant()
        requiredChecks = $required
        residualSelfTestScratchCount = $residual.Count
    } | ConvertTo-Json -Depth 6
}
finally {
    if ($process) { $process.Dispose() }
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
