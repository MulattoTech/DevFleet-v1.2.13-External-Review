Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Secrets.psm1') -Force

# A Hyper-V PSSession created by a nested PowerShell pipeline remains backed by
# that pipeline's runspace.  Keep completed opener pipelines alive until the
# proof process exits; callers still own and remove the returned PSSession.
$script:GuestSessionPipelines = @{}

function New-BoundedVmPSSession {
    param([guid]$VmId,[string]$VmName,[Parameter(Mandatory)][pscredential]$Credential)
    $pipeline=[powershell]::Create()
    $session=$null
    try {
        $null=$pipeline.AddCommand('New-PSSession').AddParameter('Credential',$Credential).AddParameter('ErrorAction','Stop')
        if($VmId -ne [guid]::Empty){$null=$pipeline.AddParameter('VMId',$VmId)}else{$null=$pipeline.AddParameter('VMName',$VmName)}
        $async=$pipeline.BeginInvoke()
        if(-not $async.AsyncWaitHandle.WaitOne(60000)){
            try{$pipeline.Stop()}catch{}
            throw 'Guest session establishment exceeded its finite 60-second open deadline.'
        }
        $output=@($pipeline.EndInvoke($async))
        if($pipeline.HadErrors){$errorText=(@($pipeline.Streams.Error|ForEach-Object{[string]$_})-join '; ');throw $errorText}
        # New-PSSession returns the live session directly from the local
        # pipeline.  Do not assume every pipeline item exposes the remoting
        # wrapper's BaseObject adapter; strict mode correctly rejects that
        # assumption for a native PSSession instance.
        $session=@($output|Where-Object{$_})|Select-Object -First 1
        if(-not $session){throw 'Guest session establishment returned no session.'}
        $script:GuestSessionPipelines[[string]$session.InstanceId] = $pipeline
        return $session
    } finally {
        # Disposing the opener here closes the live remoting session before a
        # reboot-resume caller can use it.  Failed openers have no session to
        # preserve and can be disposed immediately.
        if (-not $session) { $pipeline.Dispose() }
    }
}

function Connect-DevFleetGuest {
    [CmdletBinding(DefaultParameterSetName='ById')]
    param(
        [Parameter(Mandatory,ParameterSetName='ById')][guid]$VmId,
        [Parameter(Mandatory,ParameterSetName='ByName')][string]$VmName
    )
    $credential = Get-DevFleetE2ECredential
    if ($PSCmdlet.ParameterSetName -eq 'ById') {
        $target = Get-VM -Id $VmId -ErrorAction Stop
        if ($target.Name -notlike 'DevFleet-E2E-*') { throw 'Guest session refused a non-disposable VM identity.' }
        try { New-BoundedVmPSSession -VmId $VmId -Credential $credential }
        catch {
            if ($_.Exception.Message -match '(?i)credential|logon|authentication|access is denied') {
                throw 'LAB_CREDENTIAL_STALE: canonical E2E credential was rejected by the exact disposable guest before WPF execution.'
            }
            throw
        }
    } else {
        $target = Get-VM -Name $VmName -ErrorAction Stop
        if ($target.Name -notlike 'DevFleet-E2E-*') { throw 'Guest session refused a non-disposable VM identity.' }
        try { New-BoundedVmPSSession -VmName $VmName -Credential $credential }
        catch {
            if ($_.Exception.Message -match '(?i)credential|logon|authentication|access is denied') {
                throw 'LAB_CREDENTIAL_STALE: canonical E2E credential was rejected by the exact disposable guest before WPF execution.'
            }
            throw
        }
    }
}

function Get-InteractiveGuestState {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session)
    Invoke-Command -Session $Session -ScriptBlock { [pscustomobject]@{ computer=$env:COMPUTERNAME; quser=(@(quser 2>&1) -join "`n"); explorer=@(Get-Process explorer -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SessionId) } }
}

function Get-StageIntegrity {
    param([Parameter(Mandatory)][string]$LocalPath,[Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,[Parameter(Mandatory)][string]$RemotePath)
    $localHash=(Get-FileHash -LiteralPath $LocalPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Copy-Item -LiteralPath $LocalPath -Destination $RemotePath -ToSession $Session -Force
    $remoteHash=Invoke-Command -Session $Session -ScriptBlock { param($p) (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() } -ArgumentList $RemotePath
    [pscustomobject]@{ localPath=$LocalPath; remotePath=$RemotePath; localSha256=$localHash; remoteSha256=$remoteHash; equal=($localHash -eq $remoteHash) }
}

Export-ModuleMember -Function Connect-DevFleetGuest,Get-InteractiveGuestState,Get-StageIntegrity
