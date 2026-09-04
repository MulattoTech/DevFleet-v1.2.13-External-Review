# Compatible with Windows PowerShell 5.1. It bootstraps PowerShell 7 for a
# connected clean-room installation from an official Microsoft release.
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('Laptop','Desktop')][string]$Role,
  [string]$BootstrapBundlePath,
  [string]$PackageRoot,
  [ValidateSet('Connected')][string]$InstallationMode='Connected',
  [switch]$NonInteractive,
  [switch]$SkipWindowsUpdates,
  [switch]$DeferNetworkPairing,
  [switch]$AcknowledgeRootfulDocker,
  [string]$TransactionDeadlineUtc,
  [string]$DeadlinePolicyVersion = '1.0.0'
)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$packageRoot=if($PackageRoot){(Resolve-Path -LiteralPath $PackageRoot).Path}else{$root}
$manifestPath=Join-Path $packageRoot 'dependencies.json'
if(-not(Test-Path -LiteralPath $manifestPath)){throw "Canonical dependency manifest is missing: $manifestPath"}
Import-Module (Join-Path $root 'windows\DevFleet.Common.psm1') -Force
if($DeadlinePolicyVersion -ne '1.0.0'){throw "Unsupported deadline policy version: $DeadlinePolicyVersion"}
$transactionDeadline = if($TransactionDeadlineUtc){try{[datetime]::Parse($TransactionDeadlineUtc).ToUniversalTime()}catch{throw 'Transaction deadline is not a valid UTC timestamp.'}}else{[datetime]::UtcNow.AddSeconds((Get-DevFleetTransactionBudgetSeconds $Role))}
Set-DevFleetDeadlineContext -TransactionDeadlineUtc $transactionDeadline -StageName 'bootstrap' -StageBudgetSeconds (Get-DevFleetStageBudgetSeconds 'bootstrap') | Out-Null
$manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
$powershellDependency=@($manifest.dependencies)|Where-Object id -eq 'powershell7'|Select-Object -First 1
if(-not $powershellDependency){throw 'Canonical PowerShell 7 dependency record is missing.'}
function Find-Pwsh {
  foreach($base in @(${env:ProgramFiles},${env:ProgramFiles(x86)})){
    if(-not $base){continue};$known=Join-Path $base 'PowerShell\7\pwsh.exe';if(Test-Path -LiteralPath $known){return $known}
  }
  return $null
}
function Get-OfficialPowerShellPayload {
  $context=Get-DevFleetDeadlineContext
  $remaining=if($context){[int][math]::Floor(([datetime]$context.StageDeadlineUtc-[datetime]::UtcNow).TotalSeconds)}else{60}
  if($remaining -le 0){throw 'Bootstrap stage deadline expired before resolving the PowerShell payload.'}
  $release=Invoke-RestMethod -UseBasicParsing -TimeoutSec ([math]::Min(60,$remaining)) -Uri $powershellDependency.directOfficialVendorResolver.metadataUri -Headers @{'User-Agent'='DevFleet-Setup/1.4.1'}
  if(-not $release.tag_name -or $release.prerelease -or $release.draft){throw 'The official PowerShell stable release metadata was not usable.'}
  $asset=$release.assets|Where-Object name -Match $powershellDependency.directOfficialVendorResolver.assetRegex|Select-Object -First 1
  if(-not $asset -or ([Uri]$asset.browser_download_url).Host -notin @($powershellDependency.directOfficialVendorResolver.allowedHosts)){throw 'The official PowerShell x64 MSI asset was not found on an allowlisted host.'}
  $directory=Join-Path $env:ProgramData 'DevFleet\InstallerCache\Bootstrap';New-Item -ItemType Directory -Path $directory -Force|Out-Null
  & icacls.exe $directory /inheritance:r /grant:r 'BUILTIN\Administrators:(OI)(CI)(F)' 'NT AUTHORITY\SYSTEM:(OI)(CI)(F)' | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Unable to establish the protected PowerShell staging ACL.'}
  $payload=Join-Path $directory $asset.name
  $assetUri=[Uri]$asset.browser_download_url
  $assetName=[IO.Path]::GetFileName($assetUri.AbsolutePath)
  if($assetName -ne [string]$asset.name -or $assetName -notmatch $powershellDependency.directOfficialVendorResolver.assetRegex -or [IO.Path]::GetExtension($assetName) -ne '.msi'){throw 'The resolved PowerShell payload is not the canonical x64 MSI asset.'}
  Save-AllowlistedHttpsDownload -Uri $assetUri -AllowedHosts @($powershellDependency.directOfficialVendorResolver.allowedHosts) -Path $payload
  if(-not (Test-Path -LiteralPath $payload) -or (Get-Item -LiteralPath $payload).Length -lt 1){throw 'Official PowerShell MSI download failed or produced an empty payload.'}
  Test-OfficialSigner -Path $payload -Policy $powershellDependency.installerAuthenticityPolicy
  return $payload
}
$pwsh=Find-Pwsh
function Get-PwshVersion([string]$Path) {
  $context=Get-DevFleetDeadlineContext
  $remaining=if($context){[int][math]::Floor(([datetime]$context.StageDeadlineUtc-[datetime]::UtcNow).TotalSeconds)}else{60}
  if($remaining -le 0){throw 'Bootstrap stage deadline expired before querying PowerShell.'}
  $psi=New-Object Diagnostics.ProcessStartInfo
  $psi.FileName=$Path;$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
  $psi.Arguments='-NoProfile -NonInteractive -Command "' + '$PSVersionTable.PSVersion.ToString()' + '"'
  $process=New-Object Diagnostics.Process
  $process.StartInfo=$psi
  try {
    if(-not $process.Start()){throw "Unable to start PowerShell executable: $Path"}
    $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
    if(-not $process.WaitForExit([math]::Min(60,$remaining)*1000)){try{$process.Kill()}catch{};throw "PowerShell version query exceeded its bootstrap deadline: $Path"}
    [void]([Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]]@($stdout,$stderr)).Wait([TimeSpan]::FromSeconds(5)))
    $text=(($stdout.GetAwaiter().GetResult())+"`n"+($stderr.GetAwaiter().GetResult()))
  } finally { $process.Dispose() }
  $match=[regex]::Match($text,'(?<!\d)(\d+\.\d+(?:\.\d+){0,2})')
  if(-not $match.Success){return $null}
  return [Version]$match.Groups[1].Value
}
$minimumPowerShell=[Version]$powershellDependency.minimumSupportedVersion
$pwshVersion=if($pwsh){Get-PwshVersion $pwsh}else{$null}
if(-not $pwsh -or -not $pwshVersion -or $pwshVersion -lt $minimumPowerShell){
  $payload=Get-OfficialPowerShellPayload
  $msiexec=Join-Path $env:WINDIR 'System32\msiexec.exe'
  if(-not (Test-Path -LiteralPath $msiexec)){throw 'Trusted Windows Installer executable was not found.'}
  $context=Get-DevFleetDeadlineContext
  $remaining=if($context){[int][math]::Floor(([datetime]$context.StageDeadlineUtc-[datetime]::UtcNow).TotalSeconds)}else{60}
  if($remaining -le 0){throw 'Bootstrap stage deadline expired before installing PowerShell.'}
  $p=Start-Process $msiexec -ArgumentList @('/i',$payload,'/qn','/norestart') -PassThru
  if(-not $p.WaitForExit([math]::Min(60,$remaining)*1000)){try{$p.Kill()}catch{};throw 'PowerShell MSI installation exceeded its bootstrap deadline.'}
  if($p.ExitCode -notin @(0,3010)){throw "PowerShell 7 bootstrap failed with exit code $($p.ExitCode)."}
  $pwsh=Find-Pwsh
  if(-not $pwsh){throw 'PowerShell 7 installer completed but pwsh.exe was not found.'}
  $pwshVersion=Get-PwshVersion $pwsh
}
if(-not $pwshVersion -or $pwshVersion -lt $minimumPowerShell){throw "Resolved PowerShell is below the supported minimum ${minimumPowerShell}: $pwshVersion"}
$args=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $root 'Install-DevFleet.ps1'),'-Role',$Role,'-InstallationMode',$InstallationMode,'-PackageRoot',$packageRoot,'-TransactionDeadlineUtc',$transactionDeadline.ToString('o'),'-DeadlinePolicyVersion',$DeadlinePolicyVersion)
if($BootstrapBundlePath){$args+=@('-BootstrapBundlePath',$BootstrapBundlePath)}
if($NonInteractive){$args+='-NonInteractive'}
if($SkipWindowsUpdates){$args+='-SkipWindowsUpdates'}
if($DeferNetworkPairing){$args+='-DeferNetworkPairing'}
if($AcknowledgeRootfulDocker){$args+='-AcknowledgeRootfulDocker'}
& $pwsh @args
exit $LASTEXITCODE
