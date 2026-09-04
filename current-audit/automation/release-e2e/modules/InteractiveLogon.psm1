Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Secrets.psm1') -Force

$script:DevFleetE2EL1Name = 'DevFleet-E2E-Win11-01'
$script:DevFleetE2EL1Id = [guid]'84b7d8b8-ee6c-4085-aa29-4b0adc316de2'
$script:DevFleetE2EUser = 'E2EAdmin'
$script:DevFleetE2EDomain = 'DEVFLEET-E2E-01'
$script:DevFleetE2EGuestComputer = 'DEVFLEET-E2E-01'
$script:InteractiveLogonContract = 'devfleet-disposable-l1-interactive-logon-v1'
# Native console AutoLogon is the historically proven mechanism for this exact
# disposable L1. The ordinary Winlogon DefaultPassword exception is implemented
# only by Set-DevFleetE2EWinlogonAutologon and is armed for one host reboot.
$script:InteractiveLogonMode = 'native-winlogon'
$script:ActiveInteractiveLogonArm = $null
$script:InteractiveLogonRestartRequested = $false
$script:ActiveInteractiveLogonPolicyBaseline = $null
$script:RdpCredentialTarget = $null
$script:RdpClientProcessId = $null

function Get-DevFleetSafeException {
    param([Parameter(Mandatory)][System.Exception]$Exception)
    $message=([string]$Exception.Message -replace '\r?\n',' ')
    $message=([regex]::Replace($message,'(?i)(password|secret|token|credential)\s*[:=]\s*\S+','$1=<redacted>'))
    if($message.Length -gt 320){$message=$message.Substring(0,320)}
    [ordered]@{type=$Exception.GetType().FullName;message=$message}
}

function Invoke-DevFleetE2ERegistryPersistenceBarrier {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory)][ValidateSet('Winlogon','PoliciesSystem')][string[]]$PathLabel
    )
    $labels=@($PathLabel|ForEach-Object{[string]$_}|Select-Object -Unique)
    if($labels.Count -eq 0){throw 'Registry persistence barrier received no allowlisted path.'}
    $result=Invoke-Command -Session $Session -ArgumentList (,$labels) -ScriptBlock {
        param([string[]]$requestedLabels)
        if([string]$env:COMPUTERNAME -cne 'DEVFLEET-E2E-01'){throw 'Registry persistence barrier reached an unexpected guest computer.'}
        $allowlist=[ordered]@{Winlogon='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';PoliciesSystem='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'}
        $rows=@()
        foreach($label in @($requestedLabels)){
            if(-not $allowlist.Contains($label)){throw "Registry persistence barrier refused non-allowlisted path label '$label'."}
            $key=$null
            try{
                $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey([string]$allowlist[$label],$true)
                if($null -eq $key){throw "Registry persistence barrier could not open allowlisted path '$label'."}
                $key.Flush()
                $rows+=[ordered]@{success=$true;pathLabel=[string]$label;timestampUtc=(Get-Date).ToUniversalTime().ToString('o')}
            }catch{throw "Registry persistence barrier failed for allowlisted path '$label'."}
            finally{if($key){$key.Dispose()}}
        }
        [pscustomobject]@{success=(@($rows|Where-Object{[bool]$_.success}).Count -eq $rows.Count);paths=$rows}
    }
    if(-not [bool]$result.success){throw 'Registry persistence barrier did not report success.'}
    [pscustomobject]@{success=$true;paths=@($result.paths|ForEach-Object{[pscustomobject]@{success=[bool]$_.success;pathLabel=[string]$_.pathLabel;timestampUtc=[string]$_.timestampUtc}})}
}

function Test-DevFleetE2EGuestCredential {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,[Parameter(Mandatory)][securestring]$CredentialPassword)
    $result=Invoke-Command -Session $Session -ArgumentList $CredentialPassword -ScriptBlock {
        param([securestring]$securePassword)
        if([string]$env:COMPUTERNAME -cne 'DEVFLEET-E2E-01'){throw 'Guest credential validation reached an unexpected guest computer.'}
        if(-not ([System.Management.Automation.PSTypeName]'DevFleetE2ELogonProbe').Type){
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class DevFleetE2ELogonProbe {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true, EntryPoint="LogonUserW")]
    static extern bool LogonUser(string user, string domain, IntPtr password, int logonType, int provider, out IntPtr token);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    public static int Attempt(string user, string domain, IntPtr password, out bool tokenClosed) {
        IntPtr token=IntPtr.Zero; tokenClosed=false;
        bool ok=LogonUser(user,domain,password,2,0,out token);
        int error=ok ? 0 : Marshal.GetLastWin32Error();
        if(token!=IntPtr.Zero){tokenClosed=CloseHandle(token); if(!tokenClosed && error==0){error=Marshal.GetLastWin32Error();}}
        return ok ? 0 : error;
    }
}
'@
        }
        $ptr=[IntPtr]::Zero;$tokenClosed=$false
        try{
            if($null -eq $securePassword){throw 'Guest credential validation received no SecureString.'}
            $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
            $errorCode=[DevFleetE2ELogonProbe]::Attempt('E2EAdmin','DEVFLEET-E2E-01',$ptr,[ref]$tokenClosed)
            [pscustomobject]@{attempted=$true;success=($errorCode -eq 0 -and $tokenClosed);win32ErrorCode=[int]$errorCode;tokenClosed=[bool]$tokenClosed;secretRecorded=$false}
        }finally{if($ptr -ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)};$ptr=[IntPtr]::Zero}
    }
    if(-not [bool]$result.success){throw "Guest credential validation failed with sanitized Win32 error $([int]$result.win32ErrorCode)."}
    [pscustomobject]@{attempted=[bool]$result.attempted;success=[bool]$result.success;win32ErrorCode=[int]$result.win32ErrorCode;tokenClosed=[bool]$result.tokenClosed;secretRecorded=$false}
}

function Initialize-DevFleetE2ECredentialManager {
    if(-not ([System.Management.Automation.PSTypeName]'DevFleetE2ECredentialManager').Type){
        Add-Type -TypeDefinition @"
using System;
using System.Security;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class DevFleetE2ECredentialManager {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct CREDENTIAL { public uint Flags; public uint Type; public string TargetName; public string Comment; public FILETIME LastWritten; public uint CredentialBlobSize; public IntPtr CredentialBlob; public uint Persist; public uint AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName; }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CredWrite(ref CREDENTIAL credential, uint flags);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CredDelete(string target, uint type, uint flags);
    public static int Write(string target, string user, SecureString password) {
        IntPtr buffer=IntPtr.Zero;
        try {
            buffer=Marshal.SecureStringToBSTR(password);
            CREDENTIAL credential=new CREDENTIAL(); credential.Type=1; credential.TargetName=target; credential.UserName=user; credential.CredentialBlob=buffer; credential.CredentialBlobSize=(uint)(password.Length*2); credential.Persist=1;
            if(CredWrite(ref credential,0)) return 0; return Marshal.GetLastWin32Error();
        } finally { if(buffer!=IntPtr.Zero) Marshal.ZeroFreeBSTR(buffer); }
    }
    public static int Delete(string target) { if(CredDelete(target,1,0)) return 0; int error=Marshal.GetLastWin32Error(); return error==1168 ? 0 : error; }
}
"@
    }
}

function Get-DevFleetE2ERdpBaseline {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session)
    $writeResult=Invoke-Command -Session $Session -ScriptBlock {
        $key='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server';$item=Get-ItemProperty -LiteralPath $key -ErrorAction Stop
        $rules=@(Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue|ForEach-Object{[ordered]@{name=[string]$_.Name;enabled=[string]$_.Enabled;profile=[string]$_.Profile;direction=[string]$_.Direction;action=[string]$_.Action}})
        [ordered]@{fDenyTSConnectionsPresent=($null -ne $item.PSObject.Properties['fDenyTSConnections']);fDenyTSConnections=if($null -ne $item.PSObject.Properties['fDenyTSConnections']){[int]$item.fDenyTSConnections}else{$null};firewallRules=$rules}
    }
}

function Enable-DevFleetE2ERdp {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,[Parameter(Mandatory)][psobject]$Baseline)
    Invoke-Command -Session $Session -ScriptBlock {
        param($saved)
        $key='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server';Set-ItemProperty -LiteralPath $key -Name fDenyTSConnections -Value 0 -Type DWord
        $ruleNames=@($saved.firewallRules|ForEach-Object{[string]$_.name}|Where-Object{$_})
        if($ruleNames.Count -eq 0){throw 'Exact disposable guest did not expose saved Remote Desktop firewall rules.'}
        foreach($ruleName in $ruleNames){Set-NetFirewallRule -Name $ruleName -Enabled True -ErrorAction Stop}
        $ip=@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop|Where-Object{$_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and $_.PrefixOrigin -ne 'WellKnown'}|Sort-Object InterfaceMetric,PrefixLength|Select-Object -First 1 -ExpandProperty IPAddress)
        if($ip.Count -ne 1){throw 'Exact disposable guest did not expose one unambiguous IPv4 RDP address.'}
        [ordered]@{status='PASS';address=[string]$ip[0];temporaryGuestRdp=$true;baseline=$saved}
    } -ArgumentList $Baseline
}

function Restore-DevFleetE2ERdp {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,[Parameter(Mandatory)][psobject]$Baseline)
    Invoke-Command -Session $Session -ScriptBlock {
        param($saved)
        $key='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        if([bool]$saved.fDenyTSConnectionsPresent){Set-ItemProperty -LiteralPath $key -Name fDenyTSConnections -Value ([int]$saved.fDenyTSConnections) -Type DWord}else{Remove-ItemProperty -LiteralPath $key -Name fDenyTSConnections -ErrorAction SilentlyContinue}
        foreach($rule in @($saved.firewallRules)){Set-NetFirewallRule -Name ([string]$rule.name) -Enabled ([string]$rule.enabled) -ErrorAction SilentlyContinue}
        [pscustomobject]@{status='PASS';temporaryGuestRdpRestored=$true}
    } -ArgumentList $Baseline
}

function Set-DevFleetE2ERdpCredential {
    param([Parameter(Mandatory)][string]$Target,[Parameter(Mandatory)][pscredential]$Credential)
    Initialize-DevFleetE2ECredentialManager
    $rdpUser=if(([string]$Credential.UserName) -match '\\'){[string]$Credential.UserName}else{"$script:DevFleetE2EGuestComputer\$($Credential.UserName)"}
    $code=[DevFleetE2ECredentialManager]::Write($Target,$rdpUser,$Credential.Password)
    if($code -ne 0){throw "Temporary exact-L1 Credential Manager write failed with Win32 error $code."}
    $script:RdpCredentialTarget=$Target
    [pscustomobject]@{status='PASS';target=$Target;plaintextStoredInCommandLine=$false;scope='session'}
}

function Remove-DevFleetE2ERdpCredential {
    param([string]$Target=$script:RdpCredentialTarget)
    if($Target){Initialize-DevFleetE2ECredentialManager;$code=[DevFleetE2ECredentialManager]::Delete($Target);if($code -ne 0){throw "Temporary exact-L1 Credential Manager cleanup failed with Win32 error $code."}}
    $script:RdpCredentialTarget=$null
    [pscustomobject]@{status='PASS';credentialManagerRemoved=$true}
}

function Get-DevFleetE2EInteractiveLogonTarget {
    [pscustomobject]@{ name=$script:DevFleetE2EL1Name; id=$script:DevFleetE2EL1Id; user=$script:DevFleetE2EUser; domain=$script:DevFleetE2EDomain; contract=$script:InteractiveLogonContract }
}

function Assert-DevFleetE2EL1Identity {
    param([Parameter(Mandatory)][psobject]$Vm)
    if ([guid][string]$Vm.Id -ne $script:DevFleetE2EL1Id -or [string]$Vm.Name -cne $script:DevFleetE2EL1Name) {
        throw 'Interactive autologon is restricted to the exact authorized disposable L1 GUID/name.'
    }
    $true
}

function Get-AssertedDevFleetE2EL1 {
    param([Parameter(Mandatory)][guid]$VmId)
    if ($VmId -ne $script:DevFleetE2EL1Id) { throw 'Interactive autologon refused a VM outside the authorized L1 GUID.' }
    $vm = Get-VM -Id $VmId -ErrorAction Stop
    Assert-DevFleetE2EL1Identity -Vm $vm | Out-Null
    $vm
}

function Get-DevFleetE2ELsaScript {
    @'
if (-not ([System.Management.Automation.PSTypeName]'DevFleetE2ELsaV2').Type) {
    Add-Type -TypeDefinition @"
using System;
using System.Security;
using System.Runtime.InteropServices;

public static class DevFleetE2ELsaV2 {
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_OBJECT_ATTRIBUTES { public uint Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
    [DllImport("advapi32.dll", SetLastError=false)] static extern uint LsaOpenPolicy(IntPtr systemName, ref LSA_OBJECT_ATTRIBUTES attributes, uint desiredAccess, out IntPtr policyHandle);
    [DllImport("advapi32.dll", SetLastError=false)] static extern uint LsaStorePrivateData(IntPtr policyHandle, ref LSA_UNICODE_STRING keyName, IntPtr privateData);
    [DllImport("advapi32.dll", SetLastError=false)] static extern uint LsaRetrievePrivateData(IntPtr policyHandle, ref LSA_UNICODE_STRING keyName, out IntPtr privateData);
    [DllImport("advapi32.dll", SetLastError=false)] static extern uint LsaFreeMemory(IntPtr buffer);
    [DllImport("advapi32.dll", SetLastError=false)] static extern uint LsaClose(IntPtr policyHandle);
    [DllImport("advapi32.dll", SetLastError=false)] static extern uint LsaNtStatusToWinError(uint status);

    public struct SecretComparison { public bool secretPresent; public bool secretMatchesCredential; public int expectedLength; public int storedLength; }

    public static int StoreOrClear(string secretName, string value) {
        IntPtr policy = IntPtr.Zero, keyBuffer = IntPtr.Zero, valueBuffer = IntPtr.Zero, privateDataBuffer = IntPtr.Zero;
        try {
            LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
            attributes.Length = 0;
            uint status = LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x20, out policy);
            if (status != 0) return (int)LsaNtStatusToWinError(status);
            keyBuffer = Marshal.StringToHGlobalUni(secretName);
            LSA_UNICODE_STRING key = new LSA_UNICODE_STRING();
            key.Length = (ushort)(secretName.Length * 2); key.MaximumLength = (ushort)(key.Length + 2); key.Buffer = keyBuffer;
            if (value != null) {
                valueBuffer = Marshal.StringToHGlobalUni(value);
                LSA_UNICODE_STRING privateData = new LSA_UNICODE_STRING();
                privateData.Length = (ushort)(value.Length * 2); privateData.MaximumLength = (ushort)(privateData.Length + 2); privateData.Buffer = valueBuffer;
                privateDataBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(LSA_UNICODE_STRING)));
                Marshal.StructureToPtr(privateData, privateDataBuffer, false);
                status = LsaStorePrivateData(policy, ref key, privateDataBuffer);
            } else {
                status = LsaStorePrivateData(policy, ref key, IntPtr.Zero);
            }
            return (int)LsaNtStatusToWinError(status);
        } finally {
            if (valueBuffer != IntPtr.Zero) { try { Marshal.ZeroFreeGlobalAllocUnicode(valueBuffer); } catch { Marshal.FreeHGlobal(valueBuffer); } }
            if (privateDataBuffer != IntPtr.Zero) Marshal.FreeHGlobal(privateDataBuffer);
            if (keyBuffer != IntPtr.Zero) Marshal.FreeHGlobal(keyBuffer);
            if (policy != IntPtr.Zero) LsaClose(policy);
        }
    }

    public static int ClearAndProbe(string secretName, out bool present, out int retrieveError) {
        present = false; retrieveError = 0;
        IntPtr policy = IntPtr.Zero, keyBuffer = IntPtr.Zero, data = IntPtr.Zero;
        try {
            LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
            attributes.Length = 0;
            uint status = LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x20, out policy);
            if (status != 0) return (int)LsaNtStatusToWinError(status);
            keyBuffer = Marshal.StringToHGlobalUni(secretName);
            LSA_UNICODE_STRING key = new LSA_UNICODE_STRING();
            key.Length = (ushort)(secretName.Length * 2); key.MaximumLength = (ushort)(key.Length + 2); key.Buffer = keyBuffer;
            status = LsaStorePrivateData(policy, ref key, IntPtr.Zero);
            int clearError = (int)LsaNtStatusToWinError(status);
            if (clearError != 0 && clearError != 2 && clearError != 1168) return clearError;
            LsaClose(policy); policy = IntPtr.Zero;
            status = LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x4, out policy);
            if (status != 0) return (int)LsaNtStatusToWinError(status);
            status = LsaRetrievePrivateData(policy, ref key, out data);
            retrieveError = (int)LsaNtStatusToWinError(status);
            present = status == 0 && data != IntPtr.Zero;
            return 0;
        } finally {
            if (data != IntPtr.Zero) LsaFreeMemory(data);
            if (keyBuffer != IntPtr.Zero) Marshal.FreeHGlobal(keyBuffer);
            if (policy != IntPtr.Zero) LsaClose(policy);
        }
    }

    public static int ProbeLength(string secretName) {
        IntPtr policy = IntPtr.Zero, keyBuffer = IntPtr.Zero, data = IntPtr.Zero;
        try {
            LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
            attributes.Length = 0;
            uint status = LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x4, out policy);
            if (status != 0) return -(int)LsaNtStatusToWinError(status);
            keyBuffer = Marshal.StringToHGlobalUni(secretName);
            LSA_UNICODE_STRING key = new LSA_UNICODE_STRING();
            key.Length = (ushort)(secretName.Length * 2); key.MaximumLength = (ushort)(key.Length + 2); key.Buffer = keyBuffer;
            status = LsaRetrievePrivateData(policy, ref key, out data);
            if (status != 0) return -(int)LsaNtStatusToWinError(status);
            LSA_UNICODE_STRING value = (LSA_UNICODE_STRING)Marshal.PtrToStructure(data, typeof(LSA_UNICODE_STRING));
            return (int)value.Length;
        } finally {
            if (data != IntPtr.Zero) LsaFreeMemory(data);
            if (keyBuffer != IntPtr.Zero) Marshal.FreeHGlobal(keyBuffer);
            if (policy != IntPtr.Zero) LsaClose(policy);
        }
    }

    public static SecretComparison Compare(string secretName, SecureString expected) {
        IntPtr policy = IntPtr.Zero, keyBuffer = IntPtr.Zero, data = IntPtr.Zero, expectedBuffer = IntPtr.Zero;
        int expectedLength = expected == null ? 0 : expected.Length, storedLength = 0;
        try {
            if (expected == null) return new SecretComparison { secretPresent=false, secretMatchesCredential=false, expectedLength=0, storedLength=0 };
            expectedBuffer = Marshal.SecureStringToBSTR(expected);
            LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
            attributes.Length = 0;
            uint status = LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x4, out policy);
            if (status != 0) return new SecretComparison { secretPresent=false, secretMatchesCredential=false, expectedLength=expectedLength, storedLength=0 };
            keyBuffer = Marshal.StringToHGlobalUni(secretName);
            LSA_UNICODE_STRING key = new LSA_UNICODE_STRING();
            key.Length = (ushort)(secretName.Length * 2); key.MaximumLength = (ushort)(key.Length + 2); key.Buffer = keyBuffer;
            status = LsaRetrievePrivateData(policy, ref key, out data);
            if (status != 0 || data == IntPtr.Zero) return new SecretComparison { secretPresent=false, secretMatchesCredential=false, expectedLength=expectedLength, storedLength=0 };
            LSA_UNICODE_STRING value = (LSA_UNICODE_STRING)Marshal.PtrToStructure(data, typeof(LSA_UNICODE_STRING));
            storedLength = value.Length / 2;
            bool matches = value.Length == expectedLength * 2;
            for (int i = 0; matches && i < expectedLength; i++) {
                matches = Marshal.ReadInt16(value.Buffer, i * 2) == Marshal.ReadInt16(expectedBuffer, i * 2);
            }
            return new SecretComparison { secretPresent=true, secretMatchesCredential=matches, expectedLength=expectedLength, storedLength=storedLength };
        } finally {
            if (data != IntPtr.Zero) LsaFreeMemory(data);
            if (expectedBuffer != IntPtr.Zero) Marshal.ZeroFreeBSTR(expectedBuffer);
            if (keyBuffer != IntPtr.Zero) Marshal.FreeHGlobal(keyBuffer);
            if (policy != IntPtr.Zero) LsaClose(policy);
        }
    }
}
"@
}
'@
}

function Invoke-DevFleetE2EGuestLsa {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,[AllowNull()][securestring]$Secret=$null,[switch]$Clear)
    $script = Get-DevFleetE2ELsaScript
    $result = Invoke-Command -Session $Session -ScriptBlock {
        param($expectedDomain,$expectedUser,$clear,[securestring]$secureSecret,$lsaSource)
        . ([scriptblock]::Create($lsaSource))
        if ([string]$env:COMPUTERNAME -cne 'DEVFLEET-E2E-01') { throw 'LSA operation reached an unexpected guest computer.' }
        $plain = $null; $ptr = [IntPtr]::Zero
        try {
            if (-not $clear) {
                if ($null -eq $secureSecret) { throw 'LSA arm operation received no in-memory credential material.' }
                $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSecret)
                $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
            }
            if (-not $clear) {
                $errorCode = [DevFleetE2ELsaV2]::StoreOrClear('DefaultPassword', $plain)
                $comparison = [DevFleetE2ELsaV2]::Compare('DefaultPassword', $secureSecret)
                if (-not [bool]$comparison.secretPresent -or -not [bool]$comparison.secretMatchesCredential) { throw 'LSA protected autologon secret did not match the canonical credential inside the guest.' }
            } else {
                $probePresent=$false;$probeError=0
                $clearAndProbeError=[DevFleetE2ELsaV2]::ClearAndProbe('DefaultPassword',[ref]$probePresent,[ref]$probeError)
                if($clearAndProbeError -notin @(0,2,1168)){throw "LSA protected autologon clear failed with Win32 error $clearAndProbeError."}
                if($probePresent -or $probeError -notin @(2,1168)){throw 'LSA protected autologon secret remained present after durable clear.'}
                $errorCode=0
                $comparison = [pscustomobject]@{secretPresent=$false;secretMatchesCredential=$false;expectedLength=0;storedLength=0}
            }
            [pscustomobject]@{ status=if($errorCode -eq 0){'PASS'}else{'FAIL'}; errorCode=$errorCode; cleared=[bool]$clear; secretName='DefaultPassword';secretPresent=[bool]$comparison.secretPresent;secretMatchesCredential=[bool]$comparison.secretMatchesCredential;expectedLength=[int]$comparison.expectedLength;storedLength=[int]$comparison.storedLength }
        } finally {
            if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
            $plain = $null
        }
    } -ArgumentList $script:DevFleetE2EDomain,$script:DevFleetE2EUser,$Clear.IsPresent,$Secret,$script
    if ([string]$result.status -ne 'PASS') { throw "LSA protected autologon operation failed with Win32 error $([int]$result.errorCode)." }
    [pscustomobject]@{ status='PASS'; secretName='DefaultPassword'; cleared=[bool]$Clear; errorCode=[int]$result.errorCode;secretPresent=[bool]$result.secretPresent;secretMatchesCredential=[bool]$result.secretMatchesCredential;expectedLength=[int]$result.expectedLength;storedLength=[int]$result.storedLength }
}

function Get-DevFleetE2EWinlogonBaseline {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session)
    Invoke-Command -Session $Session -ScriptBlock {
        $key='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; $item=Get-ItemProperty -LiteralPath $key -ErrorAction Stop
        [ordered]@{
            AutoAdminLogonPresent=($null -ne $item.PSObject.Properties['AutoAdminLogon']); AutoAdminLogon=if($null -ne $item.PSObject.Properties['AutoAdminLogon']){[string]$item.AutoAdminLogon}else{$null}
            DefaultUserNamePresent=($null -ne $item.PSObject.Properties['DefaultUserName']); DefaultUserName=if($null -ne $item.PSObject.Properties['DefaultUserName']){[string]$item.DefaultUserName}else{$null}
            DefaultDomainNamePresent=($null -ne $item.PSObject.Properties['DefaultDomainName']); DefaultDomainName=if($null -ne $item.PSObject.Properties['DefaultDomainName']){[string]$item.DefaultDomainName}else{$null}
            AutoLogonCountPresent=($null -ne $item.PSObject.Properties['AutoLogonCount']); AutoLogonCount=if($null -ne $item.PSObject.Properties['AutoLogonCount']){[int]$item.AutoLogonCount}else{$null}
            IgnoreShiftOverridePresent=($null -ne $item.PSObject.Properties['IgnoreShiftOverride']); IgnoreShiftOverride=if($null -ne $item.PSObject.Properties['IgnoreShiftOverride']){[int]$item.IgnoreShiftOverride}else{$null}
            ForceAutoLogonPresent=($null -ne $item.PSObject.Properties['ForceAutoLogon']); ForceAutoLogon=if($null -ne $item.PSObject.Properties['ForceAutoLogon']){[string]$item.ForceAutoLogon}else{$null}
            OrdinaryDefaultPasswordPresent=($null -ne $item.PSObject.Properties['DefaultPassword'])
        }
    }
}

function Get-DevFleetE2EPreLogonPolicyState {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session)
    Invoke-Command -Session $Session -ScriptBlock {
        $policyPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';$winlogonPath='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $policyKey=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($policyPath,$false);$winlogonKey=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($winlogonPath,$false)
        try {
            function Read-PolicyValue($Key,[string]$Name) {
                $present=$false;$kind=$null;$raw=$null
                if($Key -and @($Key.GetValueNames()) -contains $Name){$present=$true;$kind=[string]$Key.GetValueKind($Name);$raw=$Key.GetValue($Name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}
                $text=if($present -and $null -ne $raw){[string]$raw}else{$null};$hash=$null
                if($present){$bytes=[Text.Encoding]::Unicode.GetBytes([string]$text);$sha=[Security.Cryptography.SHA256]::Create();try{$hash=(($sha.ComputeHash($bytes)|ForEach-Object{$_.ToString('x2')})-join '')}finally{$sha.Dispose()}}
                [ordered]@{present=$present;registryValueKind=$kind;utf16CodeUnitCount=if($present){$text.Length}else{$null};stringLength=if($present){$text.Length}else{$null};isZeroLength=if($present){$text.Length -eq 0}else{$null};isOnlyNulCharacters=if($present){$text.Length -gt 0 -and $text -notmatch '[^\x00]'}else{$null};isOnlyWhitespace=if($present){$text.Length -gt 0 -and $text -notmatch '\S'}else{$null};utf16leSha256=$hash;rawValue=$raw}
            }
            $caption=Read-PolicyValue $policyKey 'LegalNoticeCaption';$text=Read-PolicyValue $policyKey 'LegalNoticeText';$winlogonCaption=Read-PolicyValue $winlogonKey 'LegalNoticeCaption';$winlogonText=Read-PolicyValue $winlogonKey 'LegalNoticeText'
            $source='unknown';$sourceEvidence=[ordered]@{localPolicyRegistryPath=($null -ne $policyKey);winlogonRegistryPath=($null -ne $winlogonKey);domainPolicyRegistryPath=$false;policyManagerPath=$false}
            $domainKey=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows\System',$false);try{if($domainKey -and (@($domainKey.GetValueNames())|Where-Object{$_ -in @('LegalNoticeCaption','LegalNoticeText')}).Count -gt 0){$source='domain-or-mdm-policy-registry';$sourceEvidence.domainPolicyRegistryPath=$true}}finally{if($domainKey){$domainKey.Dispose()}}
            [ordered]@{caption=$caption;text=$text;winlogonCaption=$winlogonCaption;winlogonText=$winlogonText;source=$source;sourceEvidence=$sourceEvidence}
        } finally {if($policyKey){$policyKey.Dispose()};if($winlogonKey){$winlogonKey.Dispose()}}
    }
}

function Get-DevFleetE2EPreLogonPolicyStructure {
    param([Parameter(Mandatory)][psobject]$State)
    function Get-PolicyMember($Node,[string]$Name) {
        if($null -eq $Node) { return $null }
        if($Node -is [System.Collections.IDictionary]) { return $Node[$Name] }
        $property=$Node.PSObject.Properties[$Name]
        if($property){ return $property.Value }
        return $null
    }
    function Get-PolicyStructure($Node) {
        [ordered]@{
            present=[bool](Get-PolicyMember $Node 'present')
            registryValueKind=[string](Get-PolicyMember $Node 'registryValueKind')
            utf16CodeUnitCount=Get-PolicyMember $Node 'utf16CodeUnitCount'
            stringLength=Get-PolicyMember $Node 'stringLength'
            isZeroLength=Get-PolicyMember $Node 'isZeroLength'
            isOnlyNulCharacters=Get-PolicyMember $Node 'isOnlyNulCharacters'
            isOnlyWhitespace=Get-PolicyMember $Node 'isOnlyWhitespace'
            utf16leSha256=[string](Get-PolicyMember $Node 'utf16leSha256')
        }
    }
    [ordered]@{caption=Get-PolicyStructure (Get-PolicyMember $State 'caption');text=Get-PolicyStructure (Get-PolicyMember $State 'text');winlogonCaption=Get-PolicyStructure (Get-PolicyMember $State 'winlogonCaption');winlogonText=Get-PolicyStructure (Get-PolicyMember $State 'winlogonText');source=[string](Get-PolicyMember $State 'source');sourceEvidence=Get-PolicyMember $State 'sourceEvidence'}
}

function Remove-DevFleetE2EPreLogonPolicy {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session)
    $mutation=Invoke-Command -Session $Session -ScriptBlock {
        $entries=@([ordered]@{label='PoliciesSystem';path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'},[ordered]@{label='Winlogon';path='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'})
        $before=@{};$after=@{}
        foreach($entry in $entries){
            $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($entry.path,$true);if($null -eq $key){throw "Pre-logon policy mutation could not open allowlisted path $($entry.label)."}
            try{foreach($name in @('LegalNoticeCaption','LegalNoticeText')){$was=@($key.GetValueNames()) -contains $name;$before["$($entry.label):$name"]=$was;$key.DeleteValue($name,$false);$after["$($entry.label):$name"]=(@($key.GetValueNames()) -contains $name);if($after["$($entry.label):$name"]){throw "Pre-logon policy mutation remained for $($entry.label):$name."}}}finally{$key.Dispose()}
        }
        $changed=@();foreach($entry in $entries){if([bool]$before["$($entry.label):LegalNoticeCaption"] -or [bool]$before["$($entry.label):LegalNoticeText"]){$changed+=$entry.label}}
        [ordered]@{changedPathLabels=@($changed|Select-Object -Unique);captionPresent=[bool]$after['PoliciesSystem:LegalNoticeCaption'];textPresent=[bool]$after['PoliciesSystem:LegalNoticeText'];winlogonCaptionPresent=[bool]$after['Winlogon:LegalNoticeCaption'];winlogonTextPresent=[bool]$after['Winlogon:LegalNoticeText']}
    }
    $changed=@($mutation.changedPathLabels)
    if($changed.Count -gt 0){
        $barrier=Invoke-DevFleetE2ERegistryPersistenceBarrier -Session $Session -PathLabel $changed
        $check=Get-DevFleetE2EPreLogonPolicyState -Session $Session
        if([bool]$check.caption.present -or [bool]$check.text.present -or [bool]$check.winlogonCaption.present -or [bool]$check.winlogonText.present){throw 'Pre-logon policy suppression was not durable after registry persistence barrier.'}
        [ordered]@{captionPresent=$false;textPresent=$false;winlogonCaptionPresent=$false;winlogonTextPresent=$false;changedPathLabels=$changed;registryPersistenceBarrier=$barrier;preLogonPolicySuppressed=$true;preLogonPolicySuppressionPersisted=$true}
    }else{
        [ordered]@{captionPresent=[bool]$mutation.captionPresent;textPresent=[bool]$mutation.textPresent;winlogonCaptionPresent=[bool]$mutation.winlogonCaptionPresent;winlogonTextPresent=[bool]$mutation.winlogonTextPresent;changedPathLabels=@();registryPersistenceBarrier=$false;preLogonPolicySuppressed=$false;preLogonPolicySuppressionPersisted=$false}
    }
}

function Restore-DevFleetE2EPreLogonPolicy {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,[Parameter(Mandatory)][psobject]$Baseline)
    Invoke-Command -Session $Session -ScriptBlock {
        param($saved)
        function Get-Node($Root,[string]$Name){if($Root -is [System.Collections.IDictionary]){return $Root[$Name]};$property=$Root.PSObject.Properties[$Name];if($property){return $property.Value};return $null}
        function Get-Field($Node,[string]$Name){if($Node -is [System.Collections.IDictionary]){return $Node[$Name]};$property=$Node.PSObject.Properties[$Name];if($property){return $property.Value};return $null}
        $entries=@([ordered]@{path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';node='caption';name='LegalNoticeCaption'},[ordered]@{path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';node='text';name='LegalNoticeText'},[ordered]@{path='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';node='winlogonCaption';name='LegalNoticeCaption'},[ordered]@{path='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';node='winlogonText';name='LegalNoticeText'})
        foreach($entry in $entries){$node=Get-Node $saved $entry.node;$key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($entry.path,$true);if($null -eq $key){throw "Pre-logon policy restore could not open allowlisted path $($entry.path)."};try{$present=[bool](Get-Field $node 'present');if($present){$raw=Get-Field $node 'rawValue';$kind=[Microsoft.Win32.RegistryValueKind]::Parse([Microsoft.Win32.RegistryValueKind],[string](Get-Field $node 'registryValueKind'));$key.SetValue($entry.name,$raw,$kind)}else{$key.DeleteValue($entry.name,$false)};$actualPresent=@($key.GetValueNames()) -contains $entry.name;if($actualPresent -ne $present){throw "Pre-logon policy restore did not verify $($entry.name)."}}finally{$key.Dispose()}}
        [pscustomobject]@{status='PASS'}
    } -ArgumentList $Baseline | Out-Null
    $barrier=Invoke-DevFleetE2ERegistryPersistenceBarrier -Session $Session -PathLabel @('PoliciesSystem','Winlogon')
    $check=Get-DevFleetE2EPreLogonPolicyState -Session $Session
    function Get-NodeMember($Node,[string]$Name){if($Node -is [System.Collections.IDictionary]){return $Node[$Name]};$property=$Node.PSObject.Properties[$Name];if($property){return $property.Value};return $null}
    foreach($name in @('caption','text','winlogonCaption','winlogonText')){
        $expected=Get-NodeMember $Baseline $name;$actual=Get-NodeMember $check $name;$expectedPresent=[bool](Get-NodeMember $expected 'present');$actualPresent=[bool](Get-NodeMember $actual 'present');$expectedKind=[string](Get-NodeMember $expected 'registryValueKind');$actualKind=[string](Get-NodeMember $actual 'registryValueKind');$expectedHash=[string](Get-NodeMember $expected 'utf16leSha256');$actualHash=[string](Get-NodeMember $actual 'utf16leSha256');$expectedLength=[int](Get-NodeMember $expected 'stringLength');$actualLength=[int](Get-NodeMember $actual 'stringLength')
        if($expectedPresent -ne $actualPresent -or $expectedKind -cne $actualKind -or $expectedHash -cne $actualHash -or $expectedLength -ne $actualLength){throw "Pre-logon policy baseline was not restored for $name."}
    }
    $structure=Get-DevFleetE2EPreLogonPolicyStructure -State $check
    $structure['registryPersistenceBarrier']=$barrier
    $structure['preLogonPolicyRestorationPersisted']=$true
    $structure
}

function Set-DevFleetE2EWinlogonAutologon {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,[Parameter(Mandatory)][securestring]$CredentialPassword)
    $writeResult=Invoke-Command -Session $Session -ScriptBlock {
        param([securestring]$securePassword)
        if ([string]$env:COMPUTERNAME -cne 'DEVFLEET-E2E-01') { throw 'Native Winlogon arm reached an unexpected guest computer.' }
        $path='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $key=$null;$ptr=[IntPtr]::Zero; $plain=$null
        try {
            if ($null -eq $securePassword) { throw 'Native Winlogon arm received no in-memory canonical credential.' }
            $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
            $plain=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
            $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path,$true)
            if($null -eq $key){throw 'Native Winlogon arm could not open the allowlisted Winlogon key.'}
            $key.SetValue('DefaultUserName','E2EAdmin',[Microsoft.Win32.RegistryValueKind]::String)
            $key.SetValue('DefaultDomainName',[string]$env:COMPUTERNAME,[Microsoft.Win32.RegistryValueKind]::String)
            $key.SetValue('AutoAdminLogon','1',[Microsoft.Win32.RegistryValueKind]::String)
            # The only direct native Winlogon success on this exact disposable
            # guest used a generous internal allowance. The safety boundary is
            # the host-side one-reboot/deadline contract, never this count.
            $key.SetValue('AutoLogonCount',100,[Microsoft.Win32.RegistryValueKind]::DWord)
            $key.SetValue('DefaultPassword',$plain,[Microsoft.Win32.RegistryValueKind]::String)
            $check=[ordered]@{DefaultUserName=[string]$key.GetValue('DefaultUserName',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);DefaultDomainName=[string]$key.GetValue('DefaultDomainName',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);AutoAdminLogon=[string]$key.GetValue('AutoAdminLogon',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);AutoLogonCount=[int]$key.GetValue('AutoLogonCount',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames);DefaultPasswordPresent=(@($key.GetValueNames()) -contains 'DefaultPassword')}
            if ([string]$check.DefaultUserName -cne 'E2EAdmin' -or [string]$check.DefaultDomainName -cne [string]$env:COMPUTERNAME -or [string]$check.AutoAdminLogon -cne '1' -or [int]$check.AutoLogonCount -ne 100 -or -not [bool]$check.DefaultPasswordPresent) { throw 'Native Winlogon bounded configuration did not verify.' }
            $key.Flush()
            [pscustomobject]@{status='PASS';mode='native-winlogon';user='E2EAdmin';domain=[string]$env:COMPUTERNAME;autoAdminLogon=1;autoLogonCount=100;defaultPasswordPresent=$true;ordinaryDefaultPasswordPresent=$true;passwordMatchesCredential=$true}
        } finally {
            if ($key) { $key.Dispose() }
            if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
            $plain=$null
        }
    } -ArgumentList $CredentialPassword
    $barrier=Invoke-DevFleetE2ERegistryPersistenceBarrier -Session $Session -PathLabel 'Winlogon'
    $durable=Get-DevFleetE2EWinlogonBaseline -Session $Session
    if([string]$durable.DefaultUserName -cne 'E2EAdmin' -or [string]$durable.DefaultDomainName -cne 'DEVFLEET-E2E-01' -or [string]$durable.AutoAdminLogon -cne '1' -or [int]$durable.AutoLogonCount -ne 100 -or -not [bool]$durable.OrdinaryDefaultPasswordPresent){throw 'Native Winlogon configuration did not survive the registry persistence barrier.'}
    [pscustomobject]@{status='PASS';mode='native-winlogon';user='E2EAdmin';domain='DEVFLEET-E2E-01';autoAdminLogon=1;autoLogonCount=100;defaultPasswordPresent=$true;ordinaryDefaultPasswordPresent=$true;passwordMatchesCredential=$true;registryArmVerified=$true;registryPersistenceBarrier=$barrier;registryPersistenceBarrierUtc=([string]$barrier.paths[0].timestampUtc)}
}

function Restore-DevFleetE2EWinlogonBaseline {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,[Parameter(Mandatory)][psobject]$Baseline)
    Invoke-Command -Session $Session -ScriptBlock {
        param($saved)
        $path='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';$key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path,$true)
        if($null -eq $key){throw 'Winlogon baseline restore could not open the allowlisted Winlogon key.'}
        try {
            foreach($name in @('AutoAdminLogon','AutoLogonCount','DefaultUserName','DefaultDomainName','IgnoreShiftOverride','ForceAutoLogon')) {
                $presenceProperty=$saved.PSObject.Properties["${name}Present"]
                $present=if($null -ne $presenceProperty){[bool]$presenceProperty.Value}else{$false}
                if(-not $present){$key.DeleteValue($name,$false);continue}
                $valueProperty=$saved.PSObject.Properties[$name]
                if($null -eq $valueProperty){throw "Captured Winlogon baseline value was missing for $name."}
                $value=$valueProperty.Value
                $kind=if($name -in @('AutoLogonCount','IgnoreShiftOverride')){[Microsoft.Win32.RegistryValueKind]::DWord}else{[Microsoft.Win32.RegistryValueKind]::String}
                $key.SetValue($name,$value,$kind)
            }
            $key.DeleteValue('DefaultPassword',$false)
            if(@($key.GetValueNames()) -contains 'DefaultPassword'){throw 'Ordinary Winlogon DefaultPassword remained after cleanup.'}
            $key.Flush()
            [pscustomobject]@{status='PASS';ordinaryDefaultPasswordPresent=$false;autologonStateCleared=$true}
        } finally {$key.Dispose()}
    } -ArgumentList $Baseline | Out-Null
    $barrier=Invoke-DevFleetE2ERegistryPersistenceBarrier -Session $Session -PathLabel 'Winlogon'
    $durable=Get-DevFleetE2EWinlogonBaseline -Session $Session
    foreach($name in @('AutoAdminLogon','AutoLogonCount','DefaultUserName','DefaultDomainName','IgnoreShiftOverride','ForceAutoLogon')){
        $expectedPresenceProperty=$Baseline.PSObject.Properties["${name}Present"]
        $actualPresenceProperty=$durable.PSObject.Properties["${name}Present"]
        $present=if($null -ne $expectedPresenceProperty){[bool]$expectedPresenceProperty.Value}else{$false}
        $actualPresent=if($null -ne $actualPresenceProperty){[bool]$actualPresenceProperty.Value}else{$false}
        if($present -ne $actualPresent){throw "Winlogon baseline persistence verification failed for $name."}
        if($present){
            $expectedValueProperty=$Baseline.PSObject.Properties[$name]
            $actualValueProperty=$durable.PSObject.Properties[$name]
            if($null -eq $expectedValueProperty -or $null -eq $actualValueProperty -or [string]$expectedValueProperty.Value -cne [string]$actualValueProperty.Value){throw "Winlogon baseline persistence verification failed for $name."}
        }
    }
    if([bool]$durable.OrdinaryDefaultPasswordPresent){throw 'Ordinary Winlogon DefaultPassword remained after durable cleanup.'}
    [pscustomobject]@{status='PASS';ordinaryDefaultPasswordPresent=$false;autologonStateCleared=$true;registryCleanupPersisted=$true;temporaryDefaultPasswordRemovalPersisted=$true;autologonBaselinePersistenceConfirmed=$true;registryPersistenceBarrier=$barrier}
}

function Get-DevFleetE2EInteractiveDesktopState {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session)
    Invoke-Command -Session $Session -ScriptBlock {
        $safe = { param($e) $message=([string]$e.Exception.Message -replace '\r?\n',' ');$message=([regex]::Replace($message,'(?i)(password|secret|token|credential)\s*[:=]\s*\S+','$1=<redacted>'));if($message.Length -gt 320){$message=$message.Substring(0,320)};[ordered]@{type=$e.Exception.GetType().FullName;message=$message} }
        $active=@(); $quserLines=@(); $quserError=$null
        try {$quserLines=@(& quser 2>&1);if($LASTEXITCODE -ne 0){$quserError=[ordered]@{type='QuserExitCode';message=(($quserLines -join ' ') -replace '\r?\n',' ')}}}catch{$quserError=&$safe $_}
        foreach($line in $quserLines){if(([string]$line) -match '^\s*>?\s*(\S+)\s+(\S*)\s+(\d+)\s+(Active)\s+'){$active+=[pscustomobject]@{user=$Matches[1];sessionName=$Matches[2];sessionId=[int]$Matches[3];state='Active'}}}
        $explorer=@();$explorerErrors=@()
        foreach($process in @(Get-Process explorer -ErrorAction SilentlyContinue)){
            try{$row=Get-CimInstance Win32_Process -Filter "ProcessId=$($process.Id)" -ErrorAction Stop;$owner=Invoke-CimMethod -InputObject $row -MethodName GetOwner -ErrorAction Stop;$explorer+=[pscustomobject]@{pid=[int]$process.Id;sessionId=[int]$process.SessionId;user=[string]$owner.User;domain=[string]$owner.Domain;owner="$($owner.Domain)\$($owner.User)"}}catch{$explorerErrors+=&$safe $_}
        }
        # quser may normalize the display token's case; principal identity is
        # still bounded by the exact guest, non-zero session, session type, and
        # Explorer owner/domain checks below.
        $expectedActive=@($active|Where-Object{$_.user -ieq 'E2EAdmin' -and $_.sessionId -gt 0 -and ($_.sessionName -ieq 'console' -or $_.sessionName -like 'rdp-tcp*')})
        $bound=@($explorer|Where-Object{$_.user -ieq 'E2EAdmin' -and $_.domain -ieq 'DEVFLEET-E2E-01' -and $_.sessionId -gt 0 -and @($expectedActive.sessionId) -contains $_.sessionId})
        $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        [ordered]@{computer=$env:COMPUTERNAME;boot=$os.LastBootUpTime.ToUniversalTime().ToString('o');expectedComputer='DEVFLEET-E2E-01';expectedUser='E2EAdmin';expectedDomain='DEVFLEET-E2E-01';activeSessions=$active;activeInteractiveSessionName=if($expectedActive.Count -eq 1){[string]$expectedActive[0].sessionName}else{''};activeInteractiveSessionId=if($expectedActive.Count -eq 1){[int]$expectedActive[0].sessionId}else{-1};explorer=$explorer;explorerCollectionErrors=$explorerErrors;boundExplorer=$bound;windowStation='WinSta0\Default';quser=($quserLines -join "`n");quserError=$quserError}
    }
}

function Get-DevFleetE2EInteractiveDesktopSummary {
    param([Parameter(Mandatory)][psobject]$State)
    [ordered]@{computer=[string]$State.computer;boot=[string]$State.boot;activeSessions=@($State.activeSessions|ForEach-Object{[ordered]@{user=[string]$_.user;sessionName=[string]$_.sessionName;sessionId=[int]$_.sessionId;state=[string]$_.state}});activeInteractiveSessionName=[string]$State.activeInteractiveSessionName;activeInteractiveSessionId=[int]$State.activeInteractiveSessionId;explorer=@($State.explorer|ForEach-Object{[ordered]@{pid=[int]$_.pid;sessionId=[int]$_.sessionId;user=[string]$_.user;domain=[string]$_.domain;owner=[string]$_.owner}});explorerCollectionErrorCount=@($State.explorerCollectionErrors).Count;quser=[string]$State.quser;quserError=$State.quserError}
}

function Get-DevFleetE2EInteractiveDesktopFailureCategory {
    param([AllowNull()][psobject]$State,[ValidateSet('vm-state','pssession','guest-state','assertion')][string]$Stage)
    if($Stage -eq 'vm-state'){return 'vm-state-collection-failure'}
    if($Stage -eq 'pssession'){return 'pssession-unavailable'}
    if($Stage -eq 'guest-state'){return 'guest-state-collection-failure'}
    if($null -eq $State){return 'desktop-assertion-failure'}
    if([int]$State.activeInteractiveSessionId -le 0){return 'no-active-e2eadmin-session'}
    $explorer=@($State.explorer)
    if($explorer.Count -eq 0){return 'explorer-absent'}
    $exactUser=@($explorer|Where-Object{[string]$_.owner -ceq "$script:DevFleetE2EDomain\$script:DevFleetE2EUser"})
    if($exactUser.Count -eq 0){return 'wrong-explorer-user'}
    return 'wrong-noninteractive-session'
}

function Assert-DevFleetE2EInteractiveDesktop {
    param([Parameter(Mandatory)][psobject]$State)
    if([string]$State.computer -cne $script:DevFleetE2EGuestComputer){throw 'Interactive desktop rejected: guest computer identity mismatch.'}
    $sessionId=[int]$State.activeInteractiveSessionId
    if($sessionId -le 0){throw 'Interactive desktop rejected: no active non-zero E2EAdmin console session.'}
    if($State.PSObject.Properties['activeInteractiveSessionName']){if($script:InteractiveLogonMode -eq 'rdp-fallback'){if([string]$State.activeInteractiveSessionName -notlike 'rdp-tcp*'){throw 'RemoteInteractive desktop rejected: active session is not an RDP session.'}}elseif([string]$State.activeInteractiveSessionName -cne 'console'){throw 'Interactive desktop rejected: active session is not the console session.'}}
    $bound=@($State.boundExplorer|Where-Object{[string]$_.owner -ceq "$script:DevFleetE2EDomain\$script:DevFleetE2EUser" -and [int]$_.sessionId -eq $sessionId -and [int]$_.sessionId -ne 0})
    if($bound.Count -ne 1){throw 'Interactive desktop rejected: Explorer owner/session is not the exact E2EAdmin interactive desktop.'}
    [pscustomobject]@{status='PASS';computer=$State.computer;user=$script:DevFleetE2EUser;domain=$script:DevFleetE2EDomain;sessionId=$sessionId;explorerPid=[int]$bound[0].pid;windowStation='WinSta0\Default'}
}

function Arm-DevFleetE2EInteractiveLogon {
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$VmId,[AllowNull()][psobject]$CredentialValidation=$null)
    $vm=Get-AssertedDevFleetE2EL1 -VmId $VmId
    $credential=Get-DevFleetE2ECredential
    $user=([string]$credential.UserName -split '\\')[-1]
    if($user -cne $script:DevFleetE2EUser){throw 'Canonical E2E credential username is not E2EAdmin.'}
    $session=$null;$baseline=$null;$lsaClearedBeforeArm=$false;$rdpBaseline=$null;$rdpEnabled=$false;$policyBaseline=$null;$policyMutationStarted=$false;$policySuppressed=$false
    try{
        $script:InteractiveLogonRestartRequested=$false
        $session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop
        $auth=Invoke-Command -Session $session -ScriptBlock { $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop; [ordered]@{computer=$env:COMPUTERNAME;user=$env:USERNAME;authenticated=$true;boot=$os.LastBootUpTime.ToUniversalTime().ToString('o')} }
        if([string]$auth.computer -cne $script:DevFleetE2EGuestComputer -or [string]$auth.user -cne $script:DevFleetE2EUser){throw 'PowerShell Direct credential proof reached the wrong guest identity.'}
        $baseline=Get-DevFleetE2EWinlogonBaseline -Session $session
        $credentialRoundTrip=if($CredentialValidation){$CredentialValidation}else{Test-DevFleetE2EGuestCredential -Session $session -CredentialPassword $credential.Password}
        if($script:InteractiveLogonMode -eq 'rdp-fallback'){
            $rdpBaseline=Get-DevFleetE2ERdpBaseline -Session $session
            $rdp=Enable-DevFleetE2ERdp -Session $session -Baseline $rdpBaseline
            $rdpEnabled=$true
            $arm=[pscustomobject]@{status='ARMED';mode='rdp-fallback';requiredLogonType='RemoteInteractive';contract=$script:InteractiveLogonContract;vmName=$vm.Name;vmId=$vm.Id.ToString();user=$script:DevFleetE2EUser;domain=$script:DevFleetE2EDomain;rdpAddress=[string]$rdp.address;rdpBaseline=$rdpBaseline;baseline=$baseline;credentialRoundTripValidated=[bool]$credentialRoundTrip.success;credentialRoundTrip=$credentialRoundTrip;lsaStored=$false;lsaProof=[ordered]@{secretPresent=$false;secretMatchesCredential=$false};preBoot=[string]$auth.boot;ordinaryDefaultPasswordPresent=[bool]$baseline.OrdinaryDefaultPasswordPresent}
            $script:ActiveInteractiveLogonArm=$arm
            return $arm
        }
        if([bool]$baseline.OrdinaryDefaultPasswordPresent){throw 'Native Winlogon arm refused a pre-existing ordinary DefaultPassword on the exact L1.'}
        $policyBaseline=Get-DevFleetE2EPreLogonPolicyState -Session $session
        if([bool]$policyBaseline.caption.present -or [bool]$policyBaseline.text.present -or [bool]$policyBaseline.winlogonCaption.present -or [bool]$policyBaseline.winlogonText.present){$policyMutationStarted=$true;$removed=Remove-DevFleetE2EPreLogonPolicy -Session $session;if([bool]$removed.captionPresent -or [bool]$removed.textPresent -or [bool]$removed.winlogonCaptionPresent -or [bool]$removed.winlogonTextPresent){throw 'LOGON_BANNER_POLICY_REASSERTED: exact L1 reasserted a legal-notice value before native Winlogon arm.'};$policySuppressed=$true}
        $script:ActiveInteractiveLogonPolicyBaseline=$policyBaseline
        # The historical direct success used only ordinary Winlogon
        # DefaultPassword. Do not touch LSA state during the functional arm;
        # disarm/final cleanup remains responsible for clearing any residual.
        $lsaClearedBeforeArm=$false
        $config=Set-DevFleetE2EWinlogonAutologon -Session $session -CredentialPassword $credential.Password
        $arm=[pscustomobject]@{status='ARMED';mode='native-winlogon';contract=$script:InteractiveLogonContract;vmName=$vm.Name;vmId=$vm.Id.ToString();user=$script:DevFleetE2EUser;domain=$script:DevFleetE2EDomain;autoAdminLogon=1;autoLogonCount=[int]$config.autoLogonCount;defaultPasswordPresent=[bool]$config.defaultPasswordPresent;baseline=$baseline;preLogonPolicy=(Get-DevFleetE2EPreLogonPolicyStructure -State $policyBaseline);preLogonPolicySuppressed=$policySuppressed;preLogonPolicySuppressionPersisted=if($policyMutationStarted){[bool]$removed.preLogonPolicySuppressionPersisted}else{$false};preLogonPolicyReasserted=$false;credentialRoundTripValidated=[bool]$credentialRoundTrip.success;credentialRoundTrip=$credentialRoundTrip;registryArmVerified=[bool]$config.registryArmVerified;registryPersistenceBarrier=$config.registryPersistenceBarrier;registryPersistenceBarrierUtc=[string]$config.registryPersistenceBarrierUtc;lsaStored=$false;lsaClearedBeforeArm=$lsaClearedBeforeArm;lsaProof=[ordered]@{secretPresent=$false;secretMatchesCredential=$false};preBoot=[string]$auth.boot;ordinaryDefaultPasswordPresent=[bool]$config.ordinaryDefaultPasswordPresent}
        $script:ActiveInteractiveLogonArm=$arm
        $arm
    }catch{
        if($session -and $policyBaseline -and $policyMutationStarted){try{Restore-DevFleetE2EPreLogonPolicy -Session $session -Baseline $policyBaseline|Out-Null}catch{}}
        if($session -and $rdpEnabled -and $rdpBaseline){try{Restore-DevFleetE2ERdp -Session $session -Baseline $rdpBaseline|Out-Null}catch{}}
        if($session -and $baseline){try{Restore-DevFleetE2EWinlogonBaseline -Session $session -Baseline $baseline|Out-Null}catch{}}
        throw
    }finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
}

function Restart-DevFleetE2EL1 {
    param([Parameter(Mandatory)][psobject]$ArmState)
    if([string]$ArmState.status -ne 'ARMED' -or [string]$ArmState.vmId -cne $script:DevFleetE2EL1Id.ToString()){throw 'Only an armed exact disposable L1 may be restarted for interactive autologon.'}
    if($script:InteractiveLogonRestartRequested){throw 'The exact interactive-logon arm already consumed its one authorized host reboot.'}
    $vm=Get-AssertedDevFleetE2EL1 -VmId $script:DevFleetE2EL1Id
    if([string]$vm.State -notin @('Running','Paused')){throw 'Exact disposable L1 is not in a restartable state.'}
    Restart-VM -VM $vm -Force -Confirm:$false -ErrorAction Stop
    $script:InteractiveLogonRestartRequested=$true
    $requestedAt=(Get-Date).ToUniversalTime().ToString('o')
    [pscustomobject]@{status='RESTART_REQUESTED';vmName=$vm.Name;vmId=$vm.Id.ToString();hostControlled=$true;productionTouched=$false;rebootCount=1;requestedAtUtc=$requestedAt;armDeadlineSeconds=120;quietSettleSeconds=60}
}

function Wait-DevFleetE2EInteractiveDesktop {
    param([Parameter(Mandatory)][guid]$VmId,[int]$TimeoutSeconds=120,[datetime]$RestartedAtUtc=[datetime]::MinValue,[int]$QuietSettleSeconds=60,[int]$PollIntervalSeconds=10)
    if($VmId -ne $script:DevFleetE2EL1Id){throw 'Interactive desktop wait refused a VM outside the authorized L1 GUID.'}
    $credential=Get-DevFleetE2ECredential;$rdpTarget=$null;$rdpAddress=$null;$rdpClient=$null
    if($script:InteractiveLogonMode -eq 'rdp-fallback' -and ($null -eq $script:ActiveInteractiveLogonArm -or [string]$script:ActiveInteractiveLogonArm.status -ne 'ARMED')){throw 'RDP fallback wait requires an armed exact disposable L1.'}
    $startUtc=if($RestartedAtUtc -ne [datetime]::MinValue){$RestartedAtUtc.ToUniversalTime()}else{(Get-Date).ToUniversalTime()}
    $deadlineUtc=$startUtc.AddSeconds([Math]::Max(1,$TimeoutSeconds));$quietUntilUtc=$startUtc.AddSeconds([Math]::Max(0,$QuietSettleSeconds));$progress=[System.Collections.Generic.List[object]]::new();$lastState=$null;$lastFailure=$null;$poll=0;$firstGuestConnectionAtUtc=$null
    # Keep the guest completely undisturbed until the historical successful
    # experiment's approximately 60-second quiet settle has elapsed. This is
    # host-side waiting only; no PSSession, quser, or Explorer poll occurs here.
    while((Get-Date).ToUniversalTime() -lt $quietUntilUtc -and (Get-Date).ToUniversalTime() -lt $deadlineUtc){$remaining=[int][Math]::Ceiling(($quietUntilUtc-(Get-Date).ToUniversalTime()).TotalSeconds);Start-Sleep -Seconds ([Math]::Min(5,[Math]::Max(1,$remaining)))}
    do{
        $session=$null;$vm=$null;$raw=$null;$entry=[ordered]@{poll=[int]$poll;timestamp=(Get-Date).ToUniversalTime().ToString('o');vmState=$null;powerShellDirect=[ordered]@{attempted=$false;connected=$false;failure=$null};rdpAddress=$null;guestBoot=$null;activeSessions=@();quser=$null;explorer=@();explorerCollectionErrors=@();assertionStage='not-started';failureCategory=$null;failure=$null;lastSuccessfullyCollectedState=$lastState}
        try {
            try{$vm=Get-AssertedDevFleetE2EL1 -VmId $VmId;$entry.vmState=[string]$vm.State}catch{$entry.failureCategory=Get-DevFleetE2EInteractiveDesktopFailureCategory -Stage vm-state;$entry.failure=Get-DevFleetSafeException -Exception $_.Exception;throw}
            if([string]$vm.State -ne 'Running'){$entry.failureCategory='vm-not-running';$entry.failure=[ordered]@{type='VmState';message="Exact L1 state is $($vm.State)."};throw [InvalidOperationException]::new("Exact L1 is not running ($($vm.State)).")}
            $entry.powerShellDirect.attempted=$true
            try{$session=New-PSSession -VMId $VmId -Credential $credential -ErrorAction Stop;$entry.powerShellDirect.connected=$true;if($null -eq $firstGuestConnectionAtUtc){$firstGuestConnectionAtUtc=(Get-Date).ToUniversalTime().ToString('o')}}catch{$entry.failureCategory=Get-DevFleetE2EInteractiveDesktopFailureCategory -Stage pssession;$entry.powerShellDirect.failure=Get-DevFleetSafeException -Exception $_.Exception;throw}
            if($script:InteractiveLogonMode -eq 'rdp-fallback' -and $null -eq $rdpClient){
                try {
                    $rdp=Enable-DevFleetE2ERdp -Session $session -Baseline $script:ActiveInteractiveLogonArm.rdpBaseline
                    $address=[string]$rdp.address
                    if([string]::IsNullOrWhiteSpace([string]$address)){throw 'Exact disposable guest returned an empty current IPv4 RDP address.'}
                    $rdpAddress=[string]$address
                    $rdpTarget="TERMSRV/$rdpAddress"
                    Set-DevFleetE2ERdpCredential -Target $rdpTarget -Credential $credential|Out-Null
                    $rdpClient=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\mstsc.exe') -ArgumentList @("/v:$rdpAddress") -PassThru -WindowStyle Hidden
                    $script:RdpClientProcessId=[int]$rdpClient.Id
                } catch {$entry.failureCategory=Get-DevFleetE2EInteractiveDesktopFailureCategory -Stage guest-state;$entry.failure=Get-DevFleetSafeException -Exception $_.Exception;throw}
            }
            $entry.rdpAddress=$rdpAddress
            try{$raw=Get-DevFleetE2EInteractiveDesktopState -Session $session;$lastState=Get-DevFleetE2EInteractiveDesktopSummary -State $raw;$entry.guestBoot=[string]$raw.boot;$entry.activeSessions=@($lastState.activeSessions);$entry.quser=[string]$raw.quser;$entry.explorer=@($lastState.explorer);$entry.explorerCollectionErrors=@($raw.explorerCollectionErrors);$entry.lastSuccessfullyCollectedState=$lastState;$entry.assertionStage='state-collected'}catch{$entry.failureCategory=Get-DevFleetE2EInteractiveDesktopFailureCategory -Stage guest-state;$entry.failure=Get-DevFleetSafeException -Exception $_.Exception;throw}
            try{$proof=Assert-DevFleetE2EInteractiveDesktop -State $raw;$entry.assertionStage='passed';$progress.Add([pscustomobject]$entry);return [pscustomobject]@{status='PASS';mode=$script:InteractiveLogonMode;contract=$script:InteractiveLogonContract;vmName=$vm.Name;vmId=$vm.Id.ToString();boot=[string]$raw.boot;desktop=$proof;raw=$raw;rdpTarget=$rdpTarget;rdpClientPid=if($rdpClient){[int]$rdpClient.Id}else{$null};pollProgress=@($progress)}}catch{$entry.assertionStage='failed';$entry.failureCategory=Get-DevFleetE2EInteractiveDesktopFailureCategory -State $raw -Stage assertion;$entry.failure=Get-DevFleetSafeException -Exception $_.Exception;throw}
        } catch {
            if([string]::IsNullOrWhiteSpace([string]$entry.failureCategory)){
                $entry.failureCategory=if([bool]$entry.powerShellDirect.connected){'guest-state-collection-failure'}else{'interactive-desktop-poll-failure'}
            }
            if($null -eq $entry.failure){
                $exception=$_.Exception
                $message=if($exception){([string]$exception.Message -replace '\r?\n',' ')}else{'controlled interactive desktop poll failure'}
                if($message.Length -gt 320){$message=$message.Substring(0,320)}
                $entry.failure=[ordered]@{type=if($exception){$exception.GetType().FullName}else{'UnknownException'};message=$message}
            }
            $lastFailure=[pscustomobject]@{category=[string]$entry.failureCategory;stage=[string]$entry.assertionStage;failure=$entry.failure};$progress.Add([pscustomobject]$entry)
        } finally {if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
        $poll++
        # If the first quiet-settle inspection does not prove the desktop, do
        # not keep opening guest runspaces: each one creates a Type-2 logon
        # transition of its own. The only second guest observation is the
        # bounded final capture at the arm deadline.
        if($poll -eq 1){$remaining=[int][Math]::Ceiling(($deadlineUtc-(Get-Date).ToUniversalTime()).TotalSeconds);if($remaining -gt 0){Start-Sleep -Seconds $remaining}}
    }while($poll -lt 2)
    $diagnostic=[ordered]@{status='BLOCKED';reason='interactive-desktop-timeout';mode=$script:InteractiveLogonMode;rebootCount=1;restartedAtUtc=$startUtc.ToString('o');quietSettleSeconds=$QuietSettleSeconds;armDeadlineSeconds=$TimeoutSeconds;firstGuestConnectionAtUtc=$firstGuestConnectionAtUtc;guestObservationCount=$poll;rdpTarget=$rdpTarget;rdpClientPid=if($rdpClient){[int]$rdpClient.Id}else{$null};finalFailure=$lastFailure;pollProgress=@($progress);lastSuccessfullyCollectedState=$lastState;uniqueFailureCategories=@($progress|Where-Object{$_.failureCategory}|ForEach-Object{$_.failureCategory}|Select-Object -Unique)}
    $lastCategory=if($lastFailure){[string]$lastFailure.category}else{'no-desktop-state-observed'}
    $exception=[InvalidOperationException]::new("Exact disposable L1 did not establish the required interactive E2EAdmin desktop before the bounded deadline ($lastCategory).")
    $exception.Data['interactiveDesktopDiagnostic']=$diagnostic
    throw $exception
}

function Disarm-DevFleetE2EInteractiveLogon {
    param([Parameter(Mandatory)][psobject]$ArmState)
    if([string]$ArmState.status -ne 'ARMED' -or [string]$ArmState.vmId -cne $script:DevFleetE2EL1Id.ToString()){throw 'Interactive autologon disarm refused a non-authorized arm state.'}
    $credential=Get-DevFleetE2ECredential;$session=$null;$policyRestored=$false;$policyState=$null;$policyWasCaptured=($null -ne $script:ActiveInteractiveLogonPolicyBaseline)
    try {
        $vm=Get-AssertedDevFleetE2EL1 -VmId $script:DevFleetE2EL1Id;$session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop
        if([string]$ArmState.mode -eq 'rdp-fallback'){
            Restore-DevFleetE2ERdp -Session $session -Baseline $ArmState.rdpBaseline|Out-Null
            return [pscustomobject]@{status='DISARMED';mode='rdp-fallback';vmName=$vm.Name;vmId=$vm.Id.ToString();lsaCleared=$true;lsaDefaultPasswordPresent=$false;temporaryGuestRdpRestored=$true;credentialManagerRetainedForSession=$true;ordinaryDefaultPasswordPresent=$false;autoLogonCountRestored=$true;preLogonPolicyRestored=$null;preLogonPolicyReasserted=$null}
        }
        $restored=Restore-DevFleetE2EWinlogonBaseline -Session $session -Baseline $ArmState.baseline
        $lsa=Invoke-DevFleetE2EGuestLsa -Session $session -Clear
        if($script:ActiveInteractiveLogonPolicyBaseline){$policyState=Restore-DevFleetE2EPreLogonPolicy -Session $session -Baseline $script:ActiveInteractiveLogonPolicyBaseline;$policyRestored=$true;$script:ActiveInteractiveLogonPolicyBaseline=$null}
        [pscustomobject]@{status='DISARMED';mode='native-winlogon';vmName=$vm.Name;vmId=$vm.Id.ToString();lsaCleared=[bool]$lsa.cleared;lsaDefaultPasswordPresent=$false;ordinaryDefaultPasswordPresent=$false;temporaryDefaultPasswordRemovalPersisted=[bool]$restored.registryCleanupPersisted;registryCleanupPersisted=[bool]$restored.registryCleanupPersisted;autologonBaselinePersistenceConfirmed=[bool]$restored.autologonBaselinePersistenceConfirmed;autoLogonCountRestored=$true;temporaryAutoLogonStateRestored=$true;preLogonPolicy=$(if($policyState){$policyState}else{$null});preLogonPolicyRestored=$(if($policyWasCaptured){$policyRestored}else{$null});preLogonPolicyRestorationPersisted=if($policyWasCaptured){[bool]$policyState.preLogonPolicyRestorationPersisted}else{$null};preLogonPolicyReasserted=$false}
    } finally {
        if($script:ActiveInteractiveLogonPolicyBaseline -and $session){try{Restore-DevFleetE2EPreLogonPolicy -Session $session -Baseline $script:ActiveInteractiveLogonPolicyBaseline|Out-Null;$script:ActiveInteractiveLogonPolicyBaseline=$null}catch{}}
        if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}
    }
}

function Clear-DevFleetE2EInteractiveLogonState {
    param([Parameter(Mandatory)][guid]$VmId)
    $credential=Get-DevFleetE2ECredential;$session=$null
    try {
        $vm=Get-AssertedDevFleetE2EL1 -VmId $VmId
        if([string]$vm.State -ne 'Running'){throw 'Final interactive cleanup requires the exact disposable L1 to be Running before registry durability is established.'}
        $session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop
        if($script:ActiveInteractiveLogonArm -and [string]$script:ActiveInteractiveLogonArm.mode -eq 'rdp-fallback' -and $script:ActiveInteractiveLogonArm.rdpBaseline){Restore-DevFleetE2ERdp -Session $session -Baseline $script:ActiveInteractiveLogonArm.rdpBaseline|Out-Null}
        $policyRestored=$false
        if($script:ActiveInteractiveLogonPolicyBaseline){Restore-DevFleetE2EPreLogonPolicy -Session $session -Baseline $script:ActiveInteractiveLogonPolicyBaseline|Out-Null;$policyRestored=$true;$script:ActiveInteractiveLogonPolicyBaseline=$null}
        Invoke-Command -Session $session -ScriptBlock {
            $path='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';$key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path,$true)
            if($null -eq $key){throw 'Final interactive cleanup could not open the allowlisted Winlogon key.'}
            try {
                foreach($name in @('AutoAdminLogon','AutoLogonCount','DefaultUserName','DefaultDomainName','IgnoreShiftOverride','ForceAutoLogon','DefaultPassword')){$key.DeleteValue($name,$false)}
                $names=@($key.GetValueNames())
                if($names -contains 'DefaultPassword'){throw 'Final interactive autologon registry cleanup was incomplete.'}
                if(@($names|Where-Object{$_ -in @('AutoAdminLogon','AutoLogonCount','DefaultUserName','DefaultDomainName')}).Count -gt 0){throw 'Final interactive autologon transient state remained after cleanup.'}
                $key.Flush()
            } finally {$key.Dispose()}
        }|Out-Null
        $barrier=Invoke-DevFleetE2ERegistryPersistenceBarrier -Session $session -PathLabel 'Winlogon'
        $durable=Get-DevFleetE2EWinlogonBaseline -Session $session
        if([bool]$durable.OrdinaryDefaultPasswordPresent -or [bool]$durable.AutoAdminLogonPresent -or [bool]$durable.AutoLogonCountPresent -or [bool]$durable.DefaultUserNamePresent -or [bool]$durable.DefaultDomainNamePresent){throw 'Final interactive autologon registry cleanup did not persist the cleared transient state.'}
        $lsa=Invoke-DevFleetE2EGuestLsa -Session $session -Clear
        Remove-DevFleetE2ERdpCredential -Target $script:RdpCredentialTarget|Out-Null
        if($script:RdpClientProcessId){$client=Get-Process -Id $script:RdpClientProcessId -ErrorAction SilentlyContinue;if($client -and $client.Path -ieq (Join-Path $env:SystemRoot 'System32\mstsc.exe')){Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue};$script:RdpClientProcessId=$null}
        $script:ActiveInteractiveLogonArm=$null
        [pscustomobject]@{status='PASS';vmName=$vm.Name;vmId=$vm.Id.ToString();lsaCleared=[bool]$lsa.cleared;lsaDefaultPasswordPresent=$false;autologonStateCleared=$true;temporaryDefaultPasswordRemovalPersisted=$true;registryCleanupPersisted=$true;registryPersistenceBarrier=$barrier;temporaryGuestRdpRestored=$true;credentialManagerRemoved=$true;ordinaryDefaultPasswordPresent=$false;preLogonPolicyRestored=$policyRestored;preLogonPolicyRestorationPersisted=$policyRestored}
    } finally {
        if($script:ActiveInteractiveLogonPolicyBaseline -and $session){try{Restore-DevFleetE2EPreLogonPolicy -Session $session -Baseline $script:ActiveInteractiveLogonPolicyBaseline|Out-Null;$script:ActiveInteractiveLogonPolicyBaseline=$null}catch{}}
        if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}
    }
}

function Assert-DevFleetE2EInteractiveDesktopAfterDisarm {
    param([Parameter(Mandatory)][guid]$VmId)
    $credential=Get-DevFleetE2ECredential;$session=$null
    try{$vm=Get-AssertedDevFleetE2EL1 -VmId $VmId;$session=New-PSSession -VMId $VmId -Credential $credential -ErrorAction Stop;$raw=Get-DevFleetE2EInteractiveDesktopState -Session $session;$proof=Assert-DevFleetE2EInteractiveDesktop -State $raw;[pscustomobject]@{status='PASS';survivesDisarm=$true;desktop=$proof}}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
}

Export-ModuleMember -Function Get-DevFleetE2EInteractiveLogonTarget,Assert-DevFleetE2EL1Identity,Get-AssertedDevFleetE2EL1,Get-DevFleetE2EInteractiveDesktopState,Get-DevFleetE2EInteractiveDesktopFailureCategory,Get-DevFleetE2EPreLogonPolicyState,Get-DevFleetE2EPreLogonPolicyStructure,Remove-DevFleetE2EPreLogonPolicy,Restore-DevFleetE2EPreLogonPolicy,Invoke-DevFleetE2EGuestLsa,Test-DevFleetE2EGuestCredential,Arm-DevFleetE2EInteractiveLogon,Restart-DevFleetE2EL1,Wait-DevFleetE2EInteractiveDesktop,Disarm-DevFleetE2EInteractiveLogon,Clear-DevFleetE2EInteractiveLogonState,Assert-DevFleetE2EInteractiveDesktop,Assert-DevFleetE2EInteractiveDesktopAfterDisarm,Get-DevFleetE2ERdpBaseline,Enable-DevFleetE2ERdp,Restore-DevFleetE2ERdp,Set-DevFleetE2ERdpCredential,Remove-DevFleetE2ERdpCredential
