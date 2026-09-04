[CmdletBinding()]
param([string]$ContextJson = $env:DEVFLEET_FULLRELEASE_CONTEXT_JSON)
$ErrorActionPreference='Stop'
$context=$ContextJson|ConvertFrom-Json -ErrorAction Stop
$workspace=(Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..')).Path
$candidatePath=[string]$context.candidate.candidate.path
$candidateItem=Get-Item -LiteralPath $candidatePath -ErrorAction Stop
$candidateSha=(Get-FileHash -LiteralPath $candidatePath -Algorithm SHA256).Hash.ToLowerInvariant()
if($candidateSha -ne [string]$context.candidate.candidate.sha256 -or [int64]$candidateItem.Length -ne [int64]$context.candidate.candidate.bytes){throw 'Security-Poison exact candidate changed before adversarial execution.'}
$candidateTuple=[ordered]@{releaseFingerprintId=[string]$context.candidate.releaseFingerprintId;toolingFingerprintId=[string]$context.candidate.toolingFingerprintId;gitCommit=[string]$context.candidate.gitCommit;exeSha256=$candidateSha;exeBytes=[int64]$candidateItem.Length}
$runDir=[string]$context.runDir;New-Item -ItemType Directory -Force -Path $runDir|Out-Null
$python=if(Test-Path -LiteralPath (Join-Path $workspace '.venv-test\Scripts\python.exe')){(Join-Path $workspace '.venv-test\Scripts\python.exe')}else{(Get-Command python.exe -ErrorAction Stop).Source}
$scenarioDefinitions=@(
    [ordered]@{id='DEPENDENCY-TRUST';command='tests/test_installed_dependency_authenticity.py tests/test_v1211_release_contract.py';reason='canonical redirect and exact signer policy plus bootstrap boundary tests'},
    [ordered]@{id='PROVISIONING-OWNERSHIP';command='automation/release-e2e/tests/Test-SecurityPoisonHostAgent.ps1';reason='real inter-process registry stress and same-name collision fixture'},
    [ordered]@{id='HOST-AGENT-PROTOCOL';command='tests/test_host_transport.py tests/test_host_agent_integration.py';reason='real local signed endpoint, tamper binding, and authenticated error responses'},
    [ordered]@{id='PROJECT-MUTATION-AUTHORITY';command='tests/test_project_safety.py tests/test_v126_dynamic_vm_hotfix.py';reason='missing/foreign identity and address-only readiness fail-closed tests'},
    [ordered]@{id='SSH-READINESS';command='tests/test_v126_dynamic_vm_hotfix.py tests/test_v124_vm_creation_ssh.py';reason='proof-bearing connection state is required before workspace readiness'},
    [ordered]@{id='SECURITY-CONFIGURATION';command='tests/test_security_config.py tests/test_configuration.py';reason='malformed and unsafe policy fixtures fail closed'},
    [ordered]@{id='PACKAGE-WATCHDOG';command='tests/test_verify_package_watchdog.py';reason='timeout, descendant termination, and bounded output fixtures'}
)
$records=[Collections.Generic.List[object]]::new()
foreach($scenario in $scenarioDefinitions){
    $started=(Get-Date).ToUniversalTime().ToString('o');$output=@();$exit=0;$command=[string]$scenario.command
    if($scenario.id -eq 'PROVISIONING-OWNERSHIP'){
        $output=& pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $workspace $command) -WorkspaceRoot $workspace 2>&1;$exit=$LASTEXITCODE
    }else{
        $paths=@($command -split '\s+')
        Push-Location (Join-Path $workspace 'source');try{$output=& $python -m pytest -q @paths 2>&1;$exit=$LASTEXITCODE}finally{Pop-Location}
    }
    $text=($output|ForEach-Object{[string]$_}) -join "`n"
    $records.Add([ordered]@{id=$scenario.id;status=if($exit -eq 0){'PASS'}else{'FAIL'};exitCode=$exit;startedAt=$started;completedAt=(Get-Date).ToUniversalTime().ToString('o');testCommand=$command;reason=$scenario.reason;outputExcerpt=if($text.Length -gt 4000){$text.Substring($text.Length-4000)}else{$text}})
    if($exit -ne 0){throw "SECURITY-POISON scenario $($scenario.id) failed. Evidence has been retained under $runDir."}
}
$evidence=[ordered]@{schemaVersion=1;status='REAL E2E PASS';phase='SECURITY-POISON';candidate=$candidateTuple;fixturePolicy=[ordered]@{malware=$false;credentialsAccessed=$false;productionMutation=$false;resources='temporary test roots and loopback endpoint only'};scenarios=@($records);allRequiredScenariosPassed=$true}
$evidencePath=Join-Path $runDir 'SECURITY-POISON-evidence.json';$evidence|ConvertTo-Json -Depth 16|Set-Content -LiteralPath $evidencePath -Encoding utf8
$evidence|ConvertTo-Json -Depth 16 -Compress
