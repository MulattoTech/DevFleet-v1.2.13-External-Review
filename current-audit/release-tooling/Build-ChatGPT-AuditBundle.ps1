[CmdletBinding()]
param([string]$Workspace = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
Write-Warning 'Build-ChatGPT-AuditBundle.ps1 is deprecated; it now delegates to the universal AI audit bundle.'
& (Join-Path $PSScriptRoot 'Build-AIAuditBundle.ps1') -Workspace $Workspace
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
