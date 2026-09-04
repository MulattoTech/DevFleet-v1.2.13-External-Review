param([string]$ContextJson = $env:DEVFLEET_FULLRELEASE_CONTEXT_JSON)
Import-Module (Join-Path $PSScriptRoot 'Invoke-RealProductPhase.psm1') -Force
Invoke-RealProductPhase -ContextJson $ContextJson | ConvertTo-Json -Depth 32 -Compress
