$ErrorActionPreference='Stop'
$sourcePath=Join-Path (Split-Path -Parent $PSScriptRoot) 'windows\DevFleet.Common.psm1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($sourcePath,[ref]$tokens,[ref]$errors)
if($errors){throw "Common module parse failed: $($errors -join '; ')"}
$definition=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-TrustedSystemRootForExecutable'},$true))
if($definition.Count -ne 1){throw 'Expected one Get-TrustedSystemRootForExecutable definition.'}
Invoke-Expression $definition[0].Extent.Text

function Assert-That([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
$names=@('ProgramFiles','ProgramFiles(x86)','WINDIR')
$saved=@{};foreach($name in $names){$saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
try {
  [Environment]::SetEnvironmentVariable('ProgramFiles','C:\Program Files','Process')
  [Environment]::SetEnvironmentVariable('ProgramFiles(x86)','C:\Program Files (x86)','Process')
  [Environment]::SetEnvironmentVariable('WINDIR','C:\Windows','Process')
  $programFilesRoot=Get-TrustedSystemRootForExecutable 'C:\Program Files\Git\cmd\git.exe'
  Assert-That ($programFilesRoot -ceq 'C:\Program Files') 'A single matching trusted root was collapsed to its first character.'
  $windowsRoot=Get-TrustedSystemRootForExecutable 'C:\Windows\System32\msiexec.exe'
  Assert-That ($windowsRoot -ceq 'C:\Windows') 'The Windows trusted root was not preserved as a full path.'
  Assert-That ($null -eq (Get-TrustedSystemRootForExecutable 'C:\Untrusted\tool.exe')) 'A path outside the exact trusted roots was accepted.'
} finally {
  foreach($name in $names){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}
}

[pscustomobject]@{status='PASS';tests=3;scalarRootPreserved=$true;ancestorWideningRejected=$true}|ConvertTo-Json -Compress
