Set-StrictMode -Version Latest

function Get-TailscaleGuestStatus {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,[string]$ExpectedNodePattern='DevFleet-E2E-*')
    Invoke-Command -Session $Session -ScriptBlock {
        param($pattern)
        $statusText = & tailscale status --json 2>&1
        $statusExit = $LASTEXITCODE
        $ip = (& tailscale ip -4 2>&1) -join ' '
        $ipExit = $LASTEXITCODE
        $version = (& tailscale version 2>&1 | Select-Object -First 1) -join ' '
        $json=$null; try { $json=$statusText | ConvertFrom-Json -ErrorAction Stop } catch {}
        $node = if($json){[string]$json.Self.HostName}else{''}
        [pscustomobject]@{ statusExit=$statusExit; ipExit=$ipExit; backendState=if($json){[string]$json.BackendState}else{''}; needsLogin=if($json){[string]$json.BackendState -eq 'NeedsLogin'}else{$true}; online=if($json){[bool]$json.Self.Online}else{$false}; node=$node; ip=$ip; version=$version; expectedNode=($node -like $pattern); credentialsStored=$false }
    } -ArgumentList $ExpectedNodePattern
}

function Test-TailscaleConnected {
    param([Parameter(Mandatory)][psobject]$Status)
    $statusExit = if($Status.PSObject.Properties['statusExit']){[int]$Status.statusExit}else{-1}
    $ipExit = if($Status.PSObject.Properties['ipExit']){[int]$Status.ipExit}else{-1}
    $backend = if($Status.PSObject.Properties['backendState']){[string]$Status.backendState}else{''}
    $needsLogin = if($Status.PSObject.Properties['needsLogin']){[bool]$Status.needsLogin}else{$true}
    $online = if($Status.PSObject.Properties['online']){[bool]$Status.online}else{$false}
    $expected = if($Status.PSObject.Properties['expectedNode']){[bool]$Status.expectedNode}else{$false}
    $ip = if($Status.PSObject.Properties['ip']){[string]$Status.ip}else{''}
    ($statusExit -eq 0 -and $ipExit -eq 0 -and $backend -eq 'Running' -and -not $needsLogin -and $online -and $expected -and $ip)
}

function Get-TailscaleAuthenticationSecret {
    param([Parameter(Mandatory)][psobject]$Config)
    $auth = if ($Config.PSObject.Properties['Authentication']) { $Config.Authentication } else { $null }
    $provider = if ($auth -and $auth.PSObject.Properties['Provider']) { [string]$auth.Provider } else { '' }
    $variable = if ($auth -and $auth.PSObject.Properties['SecretEnvironmentVariable']) { [string]$auth.SecretEnvironmentVariable } else { '' }
    if ($provider -ne 'AuthKeyEnvironment' -or [string]::IsNullOrWhiteSpace($variable)) {
        return [pscustomobject]@{ available=$false; provider=$provider; reason='explicit AuthKeyEnvironment provider and secret environment variable are required'; secret=$null }
    }
    $secret = [Environment]::GetEnvironmentVariable($variable, 'Process')
    if ([string]::IsNullOrWhiteSpace($secret)) {
        return [pscustomobject]@{ available=$false; provider=$provider; reason='configured process-local Tailscale auth secret is absent'; secret=$null }
    }
    [pscustomobject]@{ available=$true; provider=$provider; reason='process-local secret available'; secret=$secret }
}

function Invoke-TailscaleAuthentication {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,[Parameter(Mandatory)][psobject]$Config)
    $credential = Get-TailscaleAuthenticationSecret -Config $Config
    if (-not [bool]$credential.available) {
        return [ordered]@{ authenticationAttempted=$false; authenticationSucceeded=$false; provider=[string]$credential.provider; userActionRequired=$true; reason=[string]$credential.reason }
    }
    try {
        $result = Invoke-Command -Session $Session -ScriptBlock {
            param($authKey)
            $output = (& tailscale up --auth-key $authKey --accept-dns=false 2>&1 | Out-String)
            [pscustomobject]@{ exitCode=[int]$LASTEXITCODE; output=($output -replace [regex]::Escape($authKey), '<redacted>') }
        } -ArgumentList ([string]$credential.secret) -ErrorAction Stop
        $ok = [int]$result.exitCode -eq 0
        return [ordered]@{ authenticationAttempted=$true; authenticationSucceeded=$ok; provider=[string]$credential.provider; userActionRequired=$false; exitCode=[int]$result.exitCode; output=[string]$result.output }
    } catch {
        return [ordered]@{ authenticationAttempted=$true; authenticationSucceeded=$false; provider=[string]$credential.provider; userActionRequired=$false; error='Tailscale authentication provider invocation failed' }
    }
}

function Assert-TailscaleAuthenticationResult {
    param([Parameter(Mandatory)][psobject]$Result)
    if (-not [bool]$Result.authenticationAttempted) { throw 'TAILSCALE-AUTH cannot pass when authenticationAttempted=false.' }
    if (-not [bool]$Result.authenticationSucceeded) { throw 'TAILSCALE-AUTH authentication provider did not establish authentication.' }
    $true
}

Export-ModuleMember -Function Get-TailscaleGuestStatus,Test-TailscaleConnected,Get-TailscaleAuthenticationSecret,Invoke-TailscaleAuthentication,Assert-TailscaleAuthenticationResult
