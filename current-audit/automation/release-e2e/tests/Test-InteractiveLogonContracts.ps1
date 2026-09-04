[CmdletBinding()]
param([Parameter(Mandatory)][string]$WorkspaceRoot)
$ErrorActionPreference='Stop'
$modulePath=Join-Path $WorkspaceRoot 'automation\release-e2e\modules\InteractiveLogon.psm1'
$source=Get-Content -LiteralPath $modulePath -Raw
Import-Module $modulePath -Force
$total=0;$passed=0;$failures=[System.Collections.Generic.List[string]]::new()
function Assert-That([bool]$Condition,[string]$Name){$script:total++;if($Condition){$script:passed++}else{$script:failures.Add($Name)}}
function Throws([scriptblock]$Action){try{&$Action|Out-Null;return $false}catch{return $true}}

$target=Get-DevFleetE2EInteractiveLogonTarget
Assert-That ($target.name -ceq 'DevFleet-E2E-Win11-01' -and $target.id -eq [guid]'84b7d8b8-ee6c-4085-aa29-4b0adc316de2') 'exact authorized L1 identity is immutable'
Assert-That ($target.user -ceq 'E2EAdmin' -and $target.domain -ceq 'DEVFLEET-E2E-01') 'exact E2EAdmin account contract'
Assert-That (Assert-DevFleetE2EL1Identity -Vm ([pscustomobject]@{Name=$target.name;Id=$target.id})) 'exact L1 GUID and name accepted'
Assert-That (Throws { Assert-DevFleetE2EL1Identity -Vm ([pscustomobject]@{Name='DevFleet-E2E-Win11-02';Id=$target.id}) }) 'wrong L1 name rejected'
Assert-That (Throws { Assert-DevFleetE2EL1Identity -Vm ([pscustomobject]@{Name=$target.name;Id=[guid]::NewGuid()}) }) 'wrong L1 GUID rejected'

$good=[pscustomobject]@{computer='DEVFLEET-E2E-01';activeInteractiveSessionId=1;boundExplorer=@([pscustomobject]@{pid=4242;owner='DEVFLEET-E2E-01\E2EAdmin';sessionId=1})}
$proof=Assert-DevFleetE2EInteractiveDesktop -State $good
Assert-That ($proof.status -eq 'PASS' -and $proof.sessionId -eq 1 -and $proof.explorerPid -eq 4242) 'exact E2EAdmin Explorer session accepted'
Assert-That (Throws { Assert-DevFleetE2EInteractiveDesktop -State ($good|Select-Object * -ExcludeProperty activeInteractiveSessionId|Add-Member -NotePropertyName activeInteractiveSessionId -NotePropertyValue 0 -PassThru) }) 'Session 0 rejected'
Assert-That (Throws { Assert-DevFleetE2EInteractiveDesktop -State ($good|Select-Object * -ExcludeProperty boundExplorer|Add-Member -NotePropertyName boundExplorer -NotePropertyValue @() -PassThru) }) 'missing Explorer rejected'
$wrongUser=$good|ConvertTo-Json -Depth 5|ConvertFrom-Json;$wrongUser.boundExplorer[0].owner='DEVFLEET-E2E-01\OtherUser'
Assert-That (Throws { Assert-DevFleetE2EInteractiveDesktop -State $wrongUser }) 'wrong-user Explorer rejected'
$wrongSession=$good|ConvertTo-Json -Depth 5|ConvertFrom-Json;$wrongSession.boundExplorer[0].sessionId=2
Assert-That (Throws { Assert-DevFleetE2EInteractiveDesktop -State $wrongSession }) 'wrong Explorer SessionId rejected'
Assert-That ((Get-DevFleetE2EInteractiveDesktopFailureCategory -Stage pssession) -eq 'pssession-unavailable') 'PowerShell Direct failure remains distinct'
Assert-That ((Get-DevFleetE2EInteractiveDesktopFailureCategory -Stage guest-state) -eq 'guest-state-collection-failure') 'guest state failure remains distinct'
Assert-That ((Get-DevFleetE2EInteractiveDesktopFailureCategory -State ([pscustomobject]@{activeInteractiveSessionId=0;explorer=@()}) -Stage assertion) -eq 'no-active-e2eadmin-session') 'no active E2EAdmin session remains distinct'
Assert-That ((Get-DevFleetE2EInteractiveDesktopFailureCategory -State ([pscustomobject]@{activeInteractiveSessionId=1;explorer=@()}) -Stage assertion) -eq 'explorer-absent') 'Explorer absent remains distinct'
Assert-That ((Get-DevFleetE2EInteractiveDesktopFailureCategory -State ([pscustomobject]@{activeInteractiveSessionId=1;explorer=@([pscustomobject]@{owner='DEVFLEET-E2E-01\OtherUser'})}) -Stage assertion) -eq 'wrong-explorer-user') 'wrong Explorer user remains distinct'
Assert-That ((Get-DevFleetE2EInteractiveDesktopFailureCategory -State ([pscustomobject]@{activeInteractiveSessionId=1;explorer=@([pscustomobject]@{owner='DEVFLEET-E2E-01\E2EAdmin'})}) -Stage assertion) -eq 'wrong-noninteractive-session') 'wrong or noninteractive session remains distinct'
Assert-That ($source -match '\$expectedActive=.*\$_.user -ieq ''E2EAdmin''' -and $source -match '\$bound=.*\$_.domain -ieq ''DEVFLEET-E2E-01''') 'quser case normalization does not reject the exact interactive principal'
Assert-That ($source -match 'owner="\$\(\$owner\.Domain\)\\\$\(\$owner\.User\)"') 'Explorer owner identity preserves the CIM domain and user fields'

Assert-That ($source -match 'Get-DevFleetE2ECredential' -and $source -match 'secrets.json' -or $source -match 'Secrets\.psm1') 'canonical DPAPI credential authority is used'
Assert-That ($source -match 'LsaOpenPolicy' -and $source -match 'LsaStorePrivateData' -and $source -match 'LsaClose' -and $source -match 'LsaNtStatusToWinError') 'LSA protected DefaultPassword implementation exists'
Assert-That ($source -match 'LsaStorePrivateData\(policy, ref key, IntPtr\.Zero\)' -and $source -match 'ClearAndProbe\(' -and $source -match '0x4' -and $source -match '\$clearAndProbeError -notin @\(0,2,1168\)' -and $source -match 'ZeroFreeGlobalAllocUnicode' -and $source -match 'ZeroFreeBSTR') 'LSA clear independently verifies absence and unmanaged secret zeroing are bounded'
Assert-That ($source -match "InteractiveLogonMode = 'native-winlogon'" -and $source -match "SetValue\('AutoLogonCount',100" -and $source -notmatch 'AutoLogonCount -Value 1\b' -and $source -notmatch 'AutoLogonCount -Value 2\b') 'native Winlogon mode uses the historically successful bounded allowance'
$nativeArmStart=$source.IndexOf('function Set-DevFleetE2EWinlogonAutologon');$nativeArmEnd=$source.IndexOf('function Restore-DevFleetE2EWinlogonBaseline',$nativeArmStart);$nativeArm=$source.Substring($nativeArmStart,$nativeArmEnd-$nativeArmStart)
Assert-That ($nativeArm -match 'param\(\[securestring\]\$securePassword\)' -and $nativeArm -match 'SecureStringToBSTR' -and $nativeArm -match 'PtrToStringBSTR' -and $nativeArm -match 'ZeroFreeBSTR' -and $nativeArm -match 'SetValue\(''DefaultPassword'',\$plain') 'ordinary DefaultPassword write is confined to the bounded guest-only SecureString conversion helper'
Assert-That ($nativeArm -match 'COMPUTERNAME.*DEVFLEET-E2E-01' -and $nativeArm -match 'SetValue\(''DefaultDomainName'',\[string\]\$env:COMPUTERNAME' -and $nativeArm -match 'SetValue\(''AutoLogonCount'',100') 'native helper asserts exact guest and uses exact local computer domain'
Assert-That ($nativeArm -match 'OpenSubKey\(\$path,\$true\)' -and $nativeArm -match 'Flush\(\)' -and $nativeArm -notmatch 'Set-ItemProperty') 'native Winlogon mutation uses one direct guest RegistryKey handle and explicit flush'
Assert-That ($nativeArm -notmatch 'ForceAutoLogon|IgnoreShiftOverride' -and $nativeArm -match 'defaultPasswordPresent=\$true') 'native helper adds no experimental Winlogon behavior and returns non-secret verification only'
Assert-That ($source -match 'Get-AssertedDevFleetE2EL1' -and $source -match 'Get-DevFleetE2ECredential' -and $source -match 'pre-existing ordinary DefaultPassword') 'helper requires exact L1 identity and canonical DPAPI credential authority'
Assert-That ($source -match 'MaximumLength = \(ushort\)\(key.Length \+ 2\)' -and $source -match 'MaximumLength = \(ushort\)\(privateData.Length \+ 2\)') 'LSA strings include terminating WCHAR capacity'
Assert-That ($source -match 'Compare\(' -and $source -match 'secretMatchesCredential' -and $source -match 'secretPresent') 'LSA arm compares protected secret to canonical credential inside the guest without revealing it'
Assert-That ($source -match 'attributes.Length = 0') 'LSA reserved object attributes remain zero initialized'
Assert-That ($source -match 'IgnoreShiftOverridePresent' -and $source -match 'IgnoreShiftOverride=if' -and $nativeArm -notmatch 'IgnoreShiftOverride -Value') 'Winlogon shift bypass is baseline tracked and never forced by native mode'
Assert-That ($source -match 'ForceAutoLogonPresent' -and $source -match 'ForceAutoLogon=if' -and $nativeArm -notmatch 'ForceAutoLogon -Value') 'Winlogon forced autologon is baseline tracked and never forced by native mode'
Assert-That ($source -match 'DeleteValue\(''DefaultPassword'',\$false\)' -and $source -match 'ordinaryDefaultPasswordPresent=\$false') 'ordinary DefaultPassword is removed during cleanup'
Assert-That ($source -match 'function Restore-DevFleetE2EWinlogonBaseline[\s\S]*Invoke-Command[\s\S]*-ArgumentList \$Baseline \| Out-Null') 'Winlogon baseline restore returns one authoritative result object'
Assert-That ($source -match 'Restart-VM -VM' -and $source -match 'Remove-PSSession' -and $source -match 'QuietSettleSeconds' -and $source -match 'armDeadlineSeconds=120' -and $source -match 'rebootCount=1') 'host-controlled one-reboot quiet-settle and hard deadline are explicit'
Assert-That ($source -match 'function Disarm-DevFleetE2EInteractiveLogon' -and $source -match 'function Assert-DevFleetE2EInteractiveDesktopAfterDisarm' -and $source -match 'survivesDisarm') 'disarm and active-session survival proof exist'
Assert-That ($source -match 'function Clear-DevFleetE2EInteractiveLogonState' -and $source -match 'autologonStateCleared=\$true') 'final cleanup removes all autologon state'
Assert-That ($source -match 'lsaClearedBeforeArm' -and $source -match 'lsaDefaultPasswordPresent=\$false' -and $source -match 'ordinaryDefaultPasswordPresent=\$false') 'native arm clears residual LSA state and disarm proves both credential authorities absent'
Assert-That ($source -match 'DevFleetE2EGuestComputer' -and $source -match "expectedComputer='DEVFLEET-E2E-01'") 'guest identity is distinct from the Hyper-V host VM identity'
Assert-That ($source -match 'pollProgress' -and $source -match 'pssession-unavailable' -and $source -match 'guest-state-collection-failure' -and $source -match 'wrong-explorer-user' -and $source -match 'lastSuccessfullyCollectedState' -and $source -match 'guestObservationCount') 'desktop wait preserves concise categorized progression and bounded final failure'
Assert-That ($source -notmatch 'Write-Host[^\r\n]*(?:Secret|Password|credential)' -and $source -notmatch 'ConvertTo-Json[^\r\n]*(?:plain|secureSecret)') 'credential material is not written to logs or evidence'
Assert-That ($source -match 'function Get-DevFleetE2EPreLogonPolicyState' -and $source -match 'LegalNoticeCaption' -and $source -match 'LegalNoticeText' -and $source -match 'utf16leSha256') 'pre-logon banner policy captures structural UTF-16 evidence'
Assert-That ($source -match 'function Remove-DevFleetE2EPreLogonPolicy' -and $source -match 'function Restore-DevFleetE2EPreLogonPolicy' -and $source -match 'RegistryValueKind' -and $source -match 'LOGON_BANNER_POLICY_REASSERTED') 'banner suppression is bounded and restores exact disposable-lab policy'
$policyFixture=[ordered]@{caption=[ordered]@{present=$true;registryValueKind='String';utf16CodeUnitCount=1;stringLength=1;isZeroLength=$false;isOnlyNulCharacters=$false;isOnlyWhitespace=$false;utf16leSha256='fixture';rawValue='not-durable'};text=[ordered]@{present=$true;registryValueKind='String';utf16CodeUnitCount=1;stringLength=1;isZeroLength=$false;isOnlyNulCharacters=$false;isOnlyWhitespace=$false;utf16leSha256='fixture';rawValue='not-durable'};source='unknown';sourceEvidence=[ordered]@{localPolicyRegistryPath=$true;domainPolicyRegistryPath=$false;policyManagerPath=$false}}
$policyStructure=Get-DevFleetE2EPreLogonPolicyStructure -State $policyFixture
Assert-That ($source -match 'rawValue' -and $source -match 'function Get-PolicyStructure' -and $source -match 'preLogonPolicyRestored' -and -not ($policyStructure.caption.Keys -contains 'rawValue') -and -not ($policyStructure.text.Keys -contains 'rawValue')) 'banner contents remain transient and cleanup truth is exposed without durable plaintext'
$armOrder=@($nativeArm.IndexOf('SetValue'),$nativeArm.IndexOf('GetValueNames'),$nativeArm.IndexOf('Invoke-DevFleetE2ERegistryPersistenceBarrier'),$nativeArm.IndexOf('Get-DevFleetE2EWinlogonBaseline'))
Assert-That (($armOrder|Where-Object{$_ -ge 0}).Count -eq 4 -and $armOrder[0] -lt $armOrder[1] -and $armOrder[1] -lt $armOrder[2] -and $armOrder[2] -lt $armOrder[3]) 'Winlogon arm orders writes, readback, persistence barrier, and post-flush readback'
$armFunction=$source.Substring($source.IndexOf('function Arm-DevFleetE2EInteractiveLogon'),$source.IndexOf('function Restart-DevFleetE2EL1')-$source.IndexOf('function Arm-DevFleetE2EInteractiveLogon'))
Assert-That ($armFunction.IndexOf('registryPersistenceBarrier') -ge 0 -and $armFunction.IndexOf('Remove-PSSession') -gt $armFunction.IndexOf('registryPersistenceBarrier')) 'Winlogon persistence completes before arm session removal and host restart path'
$policyRemove=$source.Substring($source.IndexOf('function Remove-DevFleetE2EPreLogonPolicy'),$source.IndexOf('function Restore-DevFleetE2EPreLogonPolicy')-$source.IndexOf('function Remove-DevFleetE2EPreLogonPolicy'))
Assert-That ($policyRemove.IndexOf('DeleteValue') -lt $policyRemove.IndexOf('Invoke-DevFleetE2ERegistryPersistenceBarrier') -and $policyRemove.IndexOf('Invoke-DevFleetE2ERegistryPersistenceBarrier') -lt $policyRemove.IndexOf('Get-DevFleetE2EPreLogonPolicyState') -and $policyRemove -match 'preLogonPolicySuppressionPersisted') 'pre-logon suppression orders mutation, barrier, and verification with truthful persistence'
$policyRestore=$source.Substring($source.IndexOf('function Restore-DevFleetE2EPreLogonPolicy'),$source.IndexOf('function Set-DevFleetE2EWinlogonAutologon')-$source.IndexOf('function Restore-DevFleetE2EPreLogonPolicy'))
Assert-That ($policyRestore.IndexOf('SetValue') -lt $policyRestore.IndexOf('Invoke-DevFleetE2ERegistryPersistenceBarrier') -and $policyRestore.IndexOf('Invoke-DevFleetE2ERegistryPersistenceBarrier') -lt $policyRestore.IndexOf('Get-DevFleetE2EPreLogonPolicyState') -and $policyRestore -match 'preLogonPolicyRestorationPersisted') 'pre-logon restoration orders mutation, barrier, reread, and persistence evidence'
$disarmFunction=$source.Substring($source.IndexOf('function Disarm-DevFleetE2EInteractiveLogon'),$source.IndexOf('function Clear-DevFleetE2EInteractiveLogonState')-$source.IndexOf('function Disarm-DevFleetE2EInteractiveLogon'))
Assert-That ($disarmFunction.IndexOf('Restore-DevFleetE2EWinlogonBaseline') -lt $disarmFunction.IndexOf('Invoke-DevFleetE2EGuestLsa -Session $session -Clear') -and $disarmFunction.IndexOf('Invoke-DevFleetE2EGuestLsa -Session $session -Clear') -lt $disarmFunction.IndexOf('registryCleanupPersisted') -and $disarmFunction -match 'autologonBaselinePersistenceConfirmed' -and $disarmFunction -match 'preLogonPolicyRestorationPersisted') 'disarm removes ordinary registry state before durable LSA clear and PASS evidence'
$clearFunction=$source.Substring($source.IndexOf('function Clear-DevFleetE2EInteractiveLogonState'),$source.IndexOf('function Assert-DevFleetE2EInteractiveDesktopAfterDisarm')-$source.IndexOf('function Clear-DevFleetE2EInteractiveLogonState'))
Assert-That ($clearFunction.IndexOf('DeleteValue') -lt $clearFunction.IndexOf('Invoke-DevFleetE2ERegistryPersistenceBarrier') -and $clearFunction.IndexOf('Invoke-DevFleetE2ERegistryPersistenceBarrier') -lt $clearFunction.IndexOf('Get-DevFleetE2EWinlogonBaseline') -and $clearFunction -match 'temporaryDefaultPasswordRemovalPersisted') 'final clear orders transient removal, persistence barrier, reread, and force-stop evidence'

$realPhase=Get-Content -LiteralPath (Join-Path $WorkspaceRoot 'automation\release-e2e\modules\executors\Invoke-RealProductPhase.psm1') -Raw
$wpfDriver=Get-Content -LiteralPath (Join-Path $WorkspaceRoot 'automation\release-e2e\modules\executors\Invoke-WpfUiAutomation.ps1') -Raw
Assert-That ($realPhase -match 'Arm-DevFleetE2EInteractiveLogon' -and $realPhase -match 'Restart-DevFleetE2EL1' -and $realPhase -match 'Wait-DevFleetE2EInteractiveDesktop' -and $realPhase -match 'Disarm-DevFleetE2EInteractiveLogon') 'legitimate product reboot re-arms one-shot autologon'
Assert-That ($realPhase -match 'New-ScheduledTaskPrincipal -UserId .DEVFLEET-E2E-01\\E2EAdmin' -and $realPhase -match 'driverIdentity' -and $realPhase -match 'candidateIdentity' -and $realPhase -match 'interactiveProof\.sessionId') 'driver and candidate share exact interactive Explorer session'
Assert-That ($wpfDriver -match '\$driverPid=\[int\]\$PID' -and $wpfDriver -match 'driverSessionId' -and $wpfDriver -match 'processId=\$process\.Id' -and $wpfDriver -match 'sessionId=\$process\.SessionId') 'WPF driver records its own PID/session separately from candidate'
$rebootStart=$realPhase.IndexOf('function Invoke-ProductRebootBoundary {');$rebootEnd=$realPhase.IndexOf('function New-ProductLifecycleCompletionAuthority {',$rebootStart);$rebootPath=$realPhase.Substring($rebootStart,$rebootEnd-$rebootStart)
Assert-That ($rebootPath -notmatch 'Restart-Computer -Force' -and $rebootPath -notmatch 'AutoLogonCount.*100') 'product reboot path has no guest self-reboot or synthetic autologon retry'

[pscustomobject]@{status=if($failures.Count -eq 0){'PASS'}else{'FAIL'};passed=$passed;total=$total;failures=@($failures)}|ConvertTo-Json -Depth 6
