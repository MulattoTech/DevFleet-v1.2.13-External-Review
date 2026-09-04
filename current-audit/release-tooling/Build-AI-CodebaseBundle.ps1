[CmdletBinding()]
param([string]$Workspace = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Build-AIAuditBundle.ps1') -Workspace $Workspace
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
