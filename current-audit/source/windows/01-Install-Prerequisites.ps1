[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('Laptop','Desktop')][string]$Role,
  [Parameter(Mandatory)][string]$OfflinePackageRoot,
  [ValidateSet('Offline','Connected')][string]$InstallationMode='Offline',
  [switch]$SkipWindowsUpdates
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'DevFleet.Common.psm1') -Force
Assert-PowerShell7; Assert-Administrator

function Test-InstalledCommand([string]$Name) { return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }
$manifest=Get-CanonicalDependencyManifest -PackageRoot $OfflinePackageRoot
function Get-OfflinePayload([string]$PackageId) {
  $manifestPath=Join-Path $OfflinePackageRoot 'OFFLINE-DEPENDENCIES.json'
  if(-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)){ throw 'Release-bound offline dependency manifest is missing.' }
  $offline=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
  if($offline.schemaVersion -ne 2 -or [string]$offline.devfleetVersion -ne '1.2.13' -or -not $offline.releaseBinding){ throw 'Offline dependency manifest is not bound to this DevFleet release.' }
  $entries=@($offline.payloads)
  $duplicateDependency=$entries | Group-Object dependencyId | Where-Object Count -ne 1
  $duplicateFile=$entries | Group-Object filename | Where-Object Count -ne 1
  if($duplicateDependency -or $duplicateFile){ throw 'Offline dependency manifest contains duplicate payload identities.' }
  $entry=@($entries) | Where-Object { [string]$_.dependencyId -eq $PackageId }
  if($entry.Count -ne 1){ throw "No exact release-bound offline payload exists for $PackageId. Connected mode is required for this target." }
  if([IO.Path]::IsPathRooted([string]$entry[0].filename) -or ([string]$entry[0].filename).Contains('..')){ throw 'Offline payload filename escapes the release package root.' }
  $payloadPath=Join-Path $OfflinePackageRoot ([string]$entry[0].filename)
  if(-not (Test-Path -LiteralPath $payloadPath -PathType Leaf)){ throw "Exact offline payload is missing: $($entry[0].filename)." }
  $item=Get-Item -LiteralPath $payloadPath -Force
  if([int64]$item.Length -ne [int64]$entry[0].sizeBytes){ throw "Offline payload size mismatch for $($item.Name)." }
  $actual=(Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
  if($actual -ne ([string]$entry[0].sha256).ToLowerInvariant()){ throw "Offline prerequisite hash mismatch for $($item.Name)." }
  $allFiles=@(Get-ChildItem -LiteralPath $OfflinePackageRoot -File -Recurse | Where-Object Name -ne 'OFFLINE-DEPENDENCIES.json')
  $allowed=@($entries | ForEach-Object { [IO.Path]::GetFullPath((Join-Path $OfflinePackageRoot ([string]$_.filename))) })
  if(@($allFiles | Where-Object { $allowed -notcontains $_.FullName }).Count -gt 0){ throw 'Unlisted offline payload files are rejected.' }
  return $payloadPath
}
function Install-OfflinePayload([string]$PackageId,[string[]]$Arguments) {
  $payload=Get-OfflinePayload $PackageId
  $dependency=@($manifest.dependencies)|Where-Object id -eq $PackageId|Select-Object -First 1
  if(-not $dependency){throw "Dependency id is not present in canonical manifest: $PackageId"}
  $strategy=Get-AuthenticityStrategy $dependency.installerAuthenticityPolicy
  if($strategy -ne 'VendorReleaseSha256'){Test-OfficialSigner -Path $payload -Policy $dependency.installerAuthenticityPolicy}
  $ext=[IO.Path]::GetExtension($payload).ToLowerInvariant()
  if($ext -eq '.msi') { $msiexec=Join-Path $env:WINDIR 'System32\msiexec.exe';if(-not (Test-TrustedExecutableCandidate $msiexec)){throw 'Trusted Windows Installer executable was not found.'};Invoke-External -FilePath $msiexec -ArgumentList (@('/i',$payload,'/qn','/norestart')) -TimeoutSeconds (Get-DevFleetOperationMaximumSeconds 'dependencyInstall') -AllowedExitCodes @(0,3010) | Out-Null }
  elseif($ext -eq '.exe') { Invoke-External -FilePath $payload -ArgumentList $Arguments -TimeoutSeconds (Get-DevFleetOperationMaximumSeconds 'dependencyInstall') -AllowedExitCodes @(0,3010) | Out-Null }
  else { throw "Unsupported offline installer type for ${PackageId}: $ext" }
}
function Ensure-Dependency([string]$Id,[switch]$FeatureRequested) {
  $dependency=@($manifest.dependencies)|Where-Object id -eq $Id|Select-Object -First 1
  if(-not $dependency){throw "Dependency id is not present in canonical manifest: $Id"}
  $detected=Get-DependencyStatus -Dependency $dependency
  Write-Host "$($dependency.displayName): detected=$($detected.Version) path=$($detected.Path) status=$($detected.Status)" -ForegroundColor Cyan
   if($detected.Status -eq 'Compatible'){Write-Host "Preserving compatible prerequisite: $($dependency.displayName)";return}
  if(-not $dependency.required -and [string]$dependency.classification -in @('OPTIONAL','RECOMMENDED') -and -not $FeatureRequested){Write-Warning "$($dependency.displayName) is $($dependency.classification.ToLowerInvariant()) for core installation; leaving its feature unavailable rather than forcing acquisition.";return}
  if($detected.Status -eq 'Unsupported-Major'){throw "$($dependency.displayName) major version $($detected.Version) is outside the supported policy."}
  if($InstallationMode -eq 'Offline'){
    if($dependency.required){Install-OfflinePayload $dependency.wingetPackageId @()}
    else{Write-Warning "Optional prerequisite is absent or incompatible and no local payload was selected: $($dependency.displayName)"}
  }else{
    $health=Get-WingetHealth
    if($health.Status -eq 'Healthy' -and $dependency.wingetPackageId){
      try { Install-WingetPackage -Id $dependency.wingetPackageId -Upgrade:($detected.Status -eq 'Outdated') }
      catch {
        if($_.Exception.Message -notmatch '(?i)External command timed out' -or -not $dependency.directOfficialVendorResolver){throw}
        Write-Warning "WinGet stalled for $($dependency.displayName); switching to the authenticated official vendor resolver."
        Install-OfficialDependency -Dependency $dependency
      }
    }
    else{Write-Warning "WinGet $($health.Status); using direct official fallback for $($dependency.displayName).";Install-OfficialDependency -Dependency $dependency}
  }
  $after=Get-DependencyStatus -Dependency $dependency
  if($after.Status -notin @('Compatible')){throw "$($dependency.displayName) did not reach a compatible post-install state: $($after.Status) ($($after.Detail))"}
  Write-Host "Verified post-install: $($dependency.displayName) $($after.Version) at $($after.Path)" -ForegroundColor Green
}

function Install-VsCodeExtension([string]$CodeCli,[string]$Extension) {
  $cmd=Join-Path $env:WINDIR 'System32\cmd.exe'
  if(-not (Test-TrustedExecutableCandidate $cmd)){throw 'Trusted command interpreter was not found for the optional VS Code integration.'}
  $quotedCode='"'+$CodeCli.Replace('"','""')+'"'
  $quotedExtension='"'+$Extension.Replace('"','""')+'"'
  Invoke-External -FilePath $cmd -ArgumentList @('/d','/s','/c',"$quotedCode --install-extension $quotedExtension --force") -TimeoutSeconds (Get-DevFleetOperationMaximumSeconds 'vscodeExtension') | Out-Null
}

function Invoke-MultipassConfigurationProbe([string]$Multipass,[string[]]$Arguments,[string]$FailureMessage) {
  $context=Get-DevFleetDeadlineContext
  $operationDeadline=[DateTime]::UtcNow.AddSeconds((Get-DevFleetOperationMaximumSeconds 'multipassConfiguration'))
  if($context -and ([datetime]$context.StageDeadlineUtc -lt $operationDeadline)){$operationDeadline=[datetime]$context.StageDeadlineUtc}
  for($attempt=0;$attempt -lt 60;$attempt++){
    $remaining=[int][math]::Floor(($operationDeadline-[DateTime]::UtcNow).TotalSeconds)
    if($remaining -le 0){break}
    try {
      return (Invoke-External $Multipass $Arguments -Capture -TimeoutSeconds ([math]::Min(60,$remaining)) -DeadlineUtc $operationDeadline)
    } catch {
      if($attempt -eq 59){break}
      $sleepSeconds=[math]::Min(1,[math]::Max(0,$remaining-1))
      if($sleepSeconds -gt 0){Start-Sleep -Seconds $sleepSeconds}
    }
  }
  throw $FailureMessage
}

Write-Host "`nInstalling/updating Windows prerequisites ($InstallationMode) ..." -ForegroundColor Cyan
Ensure-Dependency 'git'
Ensure-Dependency 'multipass'
Ensure-Dependency 'tailscale'
Ensure-Dependency 'github-cli'
Ensure-Dependency 'sevenzip'
Ensure-Dependency 'vscode'

$ssh=Get-WindowsCapability -Online | Where-Object Name -Like 'OpenSSH.Client*' | Select-Object -First 1
if(-not $ssh){ throw 'Windows OpenSSH Client capability was not found.' }
if($ssh.State -ne 'Installed'){
  if($InstallationMode -eq 'Offline'){ throw 'OpenSSH Client is not installed and Windows capability acquisition is not supported by this Full Offline profile.' }
  Add-WindowsCapability -Online -Name $ssh.Name | Out-Null
}

$edition=(Get-ComputerInfo -Property WindowsProductName).WindowsProductName
if($edition -match 'Pro|Enterprise|Education'){
  $feature=Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
  if($feature.State -ne 'Enabled'){
    Write-Warning 'Enabling Hyper-V. A reboot will be required before VM provisioning.'
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart | Out-Null
  }
}else{
  Ensure-Dependency 'virtualbox' -FeatureRequested
}

if(-not (Test-PendingReboot)){
  $mp=Get-MultipassExe
  if($edition -match 'Pro|Enterprise|Education'){ Invoke-External $mp @('set','local.driver=hyperv') -TimeoutSeconds (Get-DevFleetOperationMaximumSeconds 'multipassConfiguration') }
  else{ Invoke-External $mp @('set','local.driver=virtualbox') -TimeoutSeconds (Get-DevFleetOperationMaximumSeconds 'multipassConfiguration') }
  $selectedDriver=([string](Invoke-MultipassConfigurationProbe $mp @('get','local.driver') 'Multipass did not become ready after the driver setting was applied.')).Trim()
  if($edition -notmatch 'Pro|Enterprise|Education' -and $selectedDriver -ne 'virtualbox'){throw "Multipass did not select the VirtualBox driver: $selectedDriver"}
  Invoke-External $mp @('set','local.privileged-mounts=false') -TimeoutSeconds (Get-DevFleetOperationMaximumSeconds 'multipassConfiguration')
  Invoke-MultipassConfigurationProbe $mp @('get','local.privileged-mounts') 'Multipass did not become ready after privileged mounts were disabled.'
}else{ Write-Warning 'Hypervisor configuration will finish automatically when this installer is re-run after reboot.' }

$code=Get-VsCodeCli
if($code){
  $vsixRoot=Join-Path $OfflinePackageRoot 'vsix'
  foreach($ext in @('ms-vscode-remote.remote-ssh','ms-vscode-remote.remote-containers','ms-vscode.remote-explorer')){
    if($InstallationMode -eq 'Offline'){
      $vsix=Get-ChildItem -LiteralPath $vsixRoot -Filter "*$ext*.vsix" -File -ErrorAction SilentlyContinue | Select-Object -First 1
      if($vsix){ Install-VsCodeExtension $code $vsix.FullName } else { Write-Warning "Optional VS Code extension payload is absent: $ext" }
    }else{ Install-VsCodeExtension $code $ext }
  }
}else{ Write-Warning 'VS Code integration is optional and its CLI is not available.' }

if(-not $SkipWindowsUpdates){ Write-Host 'Windows Update is not forced automatically. Install pending Windows security updates, then reboot if Windows requests it.' -ForegroundColor Yellow }
# A prerequisite stage is not durably complete while servicing still requires a
# reboot.  Leaving the marker absent makes the resumed transaction rerun only
# this idempotent prerequisite stage and then advance normally.
if(-not (Test-PendingReboot)){ Write-StageMarker "prereqs-$Role" } else { Write-Warning 'Prerequisite stage remains pending until Windows servicing settles; no completion marker was written.' }
