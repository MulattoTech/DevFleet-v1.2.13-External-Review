param(
    [Parameter(Mandatory)][string]$ExePath,
    [Parameter(Mandatory)][string]$Action,
    [string]$Role = 'Primary / Desktop',
    [Parameter(Mandatory)][string]$OutputPath,
    [string]$StartedPath,
    [switch]$AllowMutation,
    [switch]$AllowRebootRequired,
    [switch]$UseDurableCompletionFallback
)
$ErrorActionPreference='Stop'
$driverPid=[int]$PID
$driverSessionId=[Diagnostics.Process]::GetCurrentProcess().SessionId
if ($Action -eq 'Diagnostics' -and $Role -eq 'Primary / Desktop') { $AllowMutation = $false }
if ($StartedPath) {
    [ordered]@{status='STARTED';action=$Action;role=$Role;timestamp=(Get-Date).ToUniversalTime().ToString('o');computer=$env:COMPUTERNAME;user=$env:USERNAME;driverPid=$driverPid;driverSessionId=$driverSessionId} | ConvertTo-Json -Compress | Set-Content -LiteralPath $StartedPath -Encoding UTF8
}
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
if (-not ('DevFleetE2EWindowProbe' -as [type])) {
    Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class DevFleetE2EWindowProbe {
    [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
}
'@
}
$candidateHash=(Get-FileHash -LiteralPath $ExePath -Algorithm SHA256).Hash.ToLowerInvariant()
$process=Start-Process -FilePath $ExePath -ArgumentList @('--action',$Action,'--role',$Role,'--defer-network-pairing') -PassThru
$actions=@();$visible=@();$diagnostics=@();$postConfirmationState=$null;$completed=$false;$relinquishCandidateToDurableVerifier=$false
function Get-ProcessIdentityEvidence([int]$Id,[int]$ExpectedSessionId){
    try{
        $row=Get-CimInstance Win32_Process -Filter "ProcessId=$Id" -ErrorAction Stop
        if(-not $row){return $null}
        $owner=Invoke-CimMethod -InputObject $row -MethodName GetOwner -ErrorAction Stop
        $processInfo=Get-Process -Id $Id -ErrorAction Stop
        if([int]$processInfo.SessionId -ne $ExpectedSessionId){return $null}
        [ordered]@{present=$true;pid=$Id;user=[string]$owner.User;domain=[string]$owner.Domain;owner=([string]$owner.Domain+'\'+[string]$owner.User);sessionId=[int]$processInfo.SessionId}
    }catch{$null}
}
try {
    function Get-UiElements {
        param([Parameter(Mandatory)]$Root)
        @($Root.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition))
    }
    function Invoke-UiButton {
        param([Parameter(Mandatory)]$Root,[Parameter(Mandatory)][string]$Pattern)
        $element=Get-UiElements $Root|Where-Object{$_.Current.ControlType -eq [System.Windows.Automation.ControlType]::Button -and $_.Current.IsEnabled -and $_.Current.Name -match $Pattern}|Select-Object -First 1
        if(-not $element){return $false}
        $element.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke();Start-Sleep -Milliseconds 700;return $true
    }
    function Ensure-UiCheckbox {
        param([Parameter(Mandatory)]$Root,[Parameter(Mandatory)][string]$Pattern)
        $element=Get-UiElements $Root|Where-Object{$_.Current.ControlType -eq [System.Windows.Automation.ControlType]::CheckBox -and $_.Current.Name -match $Pattern}|Select-Object -First 1
        if(-not $element){return $false}
        $toggle=$element.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
        if($toggle.Current.ToggleState -ne [System.Windows.Automation.ToggleState]::On){$toggle.Toggle();Start-Sleep -Milliseconds 300}
        return $true
    }
    function Get-UiDiagnosticValues {
        param([Parameter(Mandatory)]$Root)
        $values=@()
        foreach($edit in @(Get-UiElements $Root|Where-Object{$_.Current.ControlType -eq [System.Windows.Automation.ControlType]::Edit})){try{$value=$edit.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).Current.Value;if($value){$values+=[string]$value}}catch{}}
        return $values
    }
    $deadline=(Get-Date).AddSeconds(90);$window=$null
    while((Get-Date)-lt $deadline -and -not $window){ Start-Sleep -Milliseconds 500;$process.Refresh();if($process.MainWindowHandle -ne 0){try{$window=[System.Windows.Automation.AutomationElement]::FromHandle($process.MainWindowHandle)}catch{}} }
    if(-not $window){throw "Exact candidate did not expose a WPF window for action $Action."}
    $all=Get-UiElements $window
    $buttons=@($all|Where-Object{$_.Current.ControlType -eq [System.Windows.Automation.ControlType]::Button})
    $actions=@([ordered]@{name='startup';result='PASS';window=$window.Current.Name})
    $navigationReady=$null;$navigationReadyDeadline=(Get-Date).AddSeconds(90)
    while((Get-Date)-lt $navigationReadyDeadline -and -not $navigationReady){
        $all=Get-UiElements $window
        $buttons=@($all|Where-Object{$_.Current.ControlType -eq [System.Windows.Automation.ControlType]::Button})
        $navigationReady=$buttons|Where-Object{$_.Current.IsEnabled -and $_.Current.Name -match '^(Next|Continue)$'}|Select-Object -First 1
        if(-not $navigationReady){Start-Sleep -Milliseconds 500}
    }
    if(-not $navigationReady){throw "Action $Action did not expose an enabled Next control after preflight."}
    for($i=0;$i -lt 8;$i++){
        [void](Ensure-UiCheckbox $window 'Configure network pairing later')
        [void](Ensure-UiCheckbox $window 'I explicitly acknowledge rootful Docker')
        $button=$buttons|Where-Object{$_.Current.IsEnabled -and $_.Current.Name -match '^(Next|Continue)$'}|Select-Object -First 1
        if(-not $button){break}
        try{$button.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke();$actions+=[ordered]@{name='navigation';result='INVOKED';label=$button.Current.Name};Start-Sleep -Milliseconds 600}catch{break}
        $all=Get-UiElements $window;$buttons=@($all|Where-Object{$_.Current.ControlType -eq [System.Windows.Automation.ControlType]::Button})
    }
    $visible=@($all|ForEach-Object{$_.Current.Name}|Where-Object{$_})
    if($AllowMutation){
        $execute=$buttons|Where-Object{$_.Current.IsEnabled -and $_.Current.Name -match 'Execute verified plan'}|Select-Object -First 1
        if(-not $execute){throw "Action $Action never exposed the reviewed execute control."}
        $execute.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke();$actions+=[ordered]@{name='execute';result='INVOKED'};Start-Sleep -Seconds 2
        $root=[System.Windows.Automation.AutomationElement]::RootElement;$yes=$null;$confirmDeadline=(Get-Date).AddSeconds(10)
        while((Get-Date)-lt $confirmDeadline -and -not $yes){
            $yes=@($root.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition)|Where-Object{$_.Current.ControlType -eq [System.Windows.Automation.ControlType]::Button -and $_.Current.IsEnabled -and $_.Current.Name -eq 'Yes' -and $_.Current.ProcessId -eq $process.Id}|Select-Object -First 1)
            if(-not $yes){Start-Sleep -Milliseconds 500}
        }
        if($yes){$yes.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke();$actions+=[ordered]@{name='confirmation';result='INVOKED'}}else{
            if(-not ('DevFleetE2EWin32' -as [type])){
                Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class DevFleetE2EWin32 {
    [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr hWnd);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindowEx(IntPtr hWndParent, IntPtr hWndChildAfter, string lpszClass, string lpszWindow);
    [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int maxCount);
    [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
    [DllImport("user32.dll")] public static extern void keybd_event(byte virtualKey, byte scanCode, uint flags, UIntPtr extraInfo);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr hWnd, StringBuilder className, int maxCount);
}
'@
            }
            $dialog=[DevFleetE2EWin32]::FindWindow('#32770','Confirm exact plan')
            if($dialog -eq [IntPtr]::Zero){throw 'The exact native confirmation dialog was not found.'}
            $dialogProcessId=0;[void][DevFleetE2EWin32]::GetWindowThreadProcessId($dialog,[ref]$dialogProcessId)
            if($dialogProcessId -ne [uint32]$process.Id){throw 'The native confirmation dialog was not owned by the exact candidate process.'}
            $yesButton=[IntPtr]::Zero;$child=[IntPtr]::Zero
            do {
                $child=[DevFleetE2EWin32]::FindWindowEx($dialog,$child,$null,$null)
                if($child -eq [IntPtr]::Zero){break}
                $classBuffer=[Text.StringBuilder]::new(128);$captionBuffer=[Text.StringBuilder]::new(128)
                [void][DevFleetE2EWin32]::GetClassName($child,$classBuffer,$classBuffer.Capacity)
                [void][DevFleetE2EWin32]::GetWindowText($child,$captionBuffer,$captionBuffer.Capacity)
                if($classBuffer.ToString() -eq 'Button' -and ([DevFleetE2EWin32]::GetDlgCtrlID($child) -eq 6 -or ($captionBuffer.ToString() -replace '&','').Trim() -eq 'Yes')){$yesButton=$child;break}
            } while($true)
            if($yesButton -eq [IntPtr]::Zero){
                # Some WPF-hosted MessageBox instances expose the dialog but
                # not its child controls through FindWindowEx. The exact
                # candidate-owned dialog still accepts the standard IDYES
                # WM_COMMAND; keep the process/title binding and verify close.
                [void][DevFleetE2EWin32]::SendMessage($dialog,0x0111,[IntPtr]6,[IntPtr]::Zero)
                $confirmationVerified=$false;$confirmationVerifyDeadline=(Get-Date).AddSeconds(10)
                while((Get-Date)-lt $confirmationVerifyDeadline -and -not $confirmationVerified){
                    $process.Refresh()
                    if(-not [DevFleetE2EWin32]::IsWindow($dialog)){$confirmationVerified=$true;break}
                    Start-Sleep -Milliseconds 250
                }
                if(-not $confirmationVerified){throw 'The exact native confirmation dialog exposed no Yes control and did not close after the exact IDYES command.'}
                $actions+=[ordered]@{name='confirmation';result='NATIVE_IDYES_EXACT_DIALOG_PROCESS_VERIFIED'}
            } else {
                $buttonProcessId=0;[void][DevFleetE2EWin32]::GetWindowThreadProcessId($yesButton,[ref]$buttonProcessId)
                if($buttonProcessId -ne [uint32]$process.Id){throw 'The native Yes button was not owned by the exact candidate process.'}
                [void][DevFleetE2EWin32]::SendMessage($yesButton,0x00F5,[IntPtr]::Zero,[IntPtr]::Zero)
                $confirmationVerified=$false;$confirmationVerifyDeadline=(Get-Date).AddSeconds(10)
                while((Get-Date)-lt $confirmationVerifyDeadline -and -not $confirmationVerified){
                    $process.Refresh()
                    # A native MessageBox is class #32770. Do not relinquish the
                    # candidate until the exact Yes button click dismisses it.
                    if(-not [DevFleetE2EWin32]::IsWindow($dialog)){$confirmationVerified=$true;break}
                    Start-Sleep -Milliseconds 250
                }
                if(-not $confirmationVerified){throw 'The exact native Yes button was invoked, but the confirmation dialog did not demonstrably close.'}
                $actions+=[ordered]@{name='confirmation';result='NATIVE_YES_EXACT_PROCESS_VERIFIED'}
            }
        }
        if ($UseDurableCompletionFallback) {
            Start-Sleep -Seconds 5
            try {
                $process.Refresh()
                $postAll=Get-UiElements $window
                $postConfirmationState=[ordered]@{hasExited=[bool]$process.HasExited;sessionId=$process.SessionId;mainWindowHandle=[int64]$process.MainWindowHandle;mainWindowTitle=$process.MainWindowTitle;responding=[bool]$process.Responding;cpuSeconds=[double]$process.TotalProcessorTime.TotalSeconds;visibleNames=@($postAll|ForEach-Object{$_.Current.Name}|Where-Object{$_})}
            } catch { $postConfirmationState=[ordered]@{captureError=$_.Exception.Message} }
            $evidence=[ordered]@{status='DURABLE_PENDING';action=$Action;role=$Role;candidateSha256=$candidateHash;processId=$process.Id;sessionId=$process.SessionId;driverPid=$driverPid;driverSessionId=$driverSessionId;driverIdentity=(Get-ProcessIdentityEvidence $driverPid $driverSessionId);candidateIdentity=(Get-ProcessIdentityEvidence $process.Id $process.SessionId);windowTitle=$window.Current.Name;visibleNames=$visible;actions=$actions;diagnostics=$diagnostics;postConfirmationState=$postConfirmationState;mutationInvoked=[bool]$AllowMutation;dispatcherResponsive=$true;completionVerified=$false;durableCompletionPending=$true}
            $evidence|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $OutputPath -Encoding UTF8
            $relinquishCandidateToDurableVerifier=$true
            return
        }
        $completeDeadline=(Get-Date).AddMinutes(5);$completed=$false;$failed=$false;$rebootRequired=$false
        $windowLostSince=$null
        while((Get-Date)-lt $completeDeadline){
            try {
                $process.Refresh()
                $windowHandle = [IntPtr]$process.MainWindowHandle
                $windowOwner = 0
                if ($windowHandle -ne [IntPtr]::Zero) { [void][DevFleetE2EWindowProbe]::GetWindowThreadProcessId($windowHandle, [ref]$windowOwner) }
                $windowValid = $windowHandle -ne [IntPtr]::Zero -and [DevFleetE2EWindowProbe]::IsWindow($windowHandle) -and $windowOwner -eq [uint32]$process.Id
                $windowLost = $process.HasExited -or -not $windowValid
            } catch { $windowLost = $true }
            if ($windowLost) {
                if (-not $windowLostSince) { $windowLostSince = Get-Date }
                elseif (((Get-Date) - $windowLostSince).TotalSeconds -ge 5) {
                    throw "Candidate UI window disappeared during completion polling; processExited=$([bool]$process.HasExited); candidatePid=$($process.Id)."
                }
            } else { $windowLostSince = $null }
            $all=Get-UiElements $window;$visible=@($all|ForEach-Object{$_.Current.Name}|Where-Object{$_});$diagnostics=Get-UiDiagnosticValues $window
            $completed=@($visible|Where-Object{$_ -eq 'Completed and verified'}).Count -gt 0
            $rebootRequired=@($visible|Where-Object{$_ -eq 'Reboot required; checkpoint preserved'}).Count -gt 0
            $failed=@($visible|Where-Object{$_ -match 'Failed|FAILED|error|blocked'}).Count -gt 0
            if($completed -or $rebootRequired -or $failed){break};Start-Sleep -Seconds 3
        }
        if($rebootRequired -and $AllowRebootRequired){
            $evidence=[ordered]@{status='REBOOT_REQUIRED';action=$Action;role=$Role;candidateSha256=$candidateHash;processId=$process.Id;sessionId=$process.SessionId;driverPid=$driverPid;driverSessionId=$driverSessionId;driverIdentity=(Get-ProcessIdentityEvidence $driverPid $driverSessionId);candidateIdentity=(Get-ProcessIdentityEvidence $process.Id $process.SessionId);windowTitle=$window.Current.Name;visibleNames=$visible;actions=$actions;diagnostics=$diagnostics;mutationInvoked=[bool]$AllowMutation;dispatcherResponsive=$true;completionVerified=$false;rebootRequired=$true}
            $evidence|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $OutputPath -Encoding UTF8
            return
        }
        if(-not $completed){throw "Action $Action did not reach Completed and verified."}
        $actions+=[ordered]@{name='completion';result='VERIFIED'}
    }
    $evidence=[ordered]@{status='PASS';action=$Action;role=$Role;candidateSha256=$candidateHash;processId=$process.Id;sessionId=$process.SessionId;driverPid=$driverPid;driverSessionId=$driverSessionId;driverIdentity=(Get-ProcessIdentityEvidence $driverPid $driverSessionId);candidateIdentity=(Get-ProcessIdentityEvidence $process.Id $process.SessionId);windowTitle=$window.Current.Name;visibleNames=$visible;actions=$actions;mutationInvoked=[bool]$AllowMutation;dispatcherResponsive=$true;completionVerified=([bool]$AllowMutation -eq $false -or $completed)}
    $evidence|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $OutputPath -Encoding UTF8
} catch {
    [ordered]@{status='FAIL';action=$Action;role=$Role;candidateSha256=$candidateHash;driverPid=$driverPid;driverSessionId=$driverSessionId;error=$_.Exception.Message;actions=$actions;visibleNames=$visible;diagnostics=$diagnostics;postConfirmationState=$postConfirmationState;dispatcherResponsive=$true}|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $OutputPath -Encoding UTF8
    throw
} finally {
    try {
        if (-not $relinquishCandidateToDurableVerifier -and -not $process.HasExited) {
            $process.CloseMainWindow()|Out-Null
            Start-Sleep -Seconds 1
            if(-not $process.HasExited){$process.Kill()}
        }
    } catch{}
}
