Set-StrictMode -Version Latest

function ConvertTo-HostAgentHmac {
    param([Parameter(Mandatory)][byte[]]$Key,[Parameter(Mandatory)][byte[]]$Material)
    $hmac=[Security.Cryptography.HMACSHA256]::new($Key)
    try { return (([BitConverter]::ToString($hmac.ComputeHash($Material)) -replace '-','').ToLowerInvariant()) }
    finally { $hmac.Dispose() }
}

function New-HostAgentRequestAuthentication {
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Body,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$ExpectedHost
    )
    if([string]::IsNullOrWhiteSpace($Key) -or [string]::IsNullOrWhiteSpace($ExpectedHost)){throw 'Host Agent authentication configuration is incomplete.'}
    $timestamp=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString([Globalization.CultureInfo]::InvariantCulture)
    $nonceBytes=New-Object byte[] 18;$rng=[Security.Cryptography.RandomNumberGenerator]::Create();try{$rng.GetBytes($nonceBytes)}finally{$rng.Dispose()}
    $nonce=[Convert]::ToBase64String($nonceBytes).TrimEnd('=').Replace('+','-').Replace('/','_')
    $material=[Text.Encoding]::UTF8.GetBytes(([string]$Method.ToUpperInvariant()+"`n"+$Path+"`n"+$timestamp+"`n"+$nonce+"`n"+[Text.Encoding]::UTF8.GetString($Body)+"`n"+$ExpectedHost))
    return [ordered]@{Timestamp=$timestamp;Nonce=$nonce;Expected=$ExpectedHost;Signature=(ConvertTo-HostAgentHmac ([Text.Encoding]::UTF8.GetBytes($Key)) $material)}
}

function Test-HostAgentResponseAuthentication {
    param(
        [Parameter(Mandatory)][string]$Method,[Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][int]$StatusCode,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Body,[Parameter(Mandatory)][string]$Key,[Parameter(Mandatory)][string]$ExpectedHost,
        [Parameter(Mandatory)][string]$Timestamp,[Parameter(Mandatory)][string]$Nonce,[Parameter(Mandatory)][string]$Provided
    )
    $material=[Text.Encoding]::UTF8.GetBytes(([string]$Method.ToUpperInvariant()+"`n"+$Path+"`n"+$Timestamp+"`n"+$Nonce+"`n"+$StatusCode.ToString([Globalization.CultureInfo]::InvariantCulture)+"`n"+[Text.Encoding]::UTF8.GetString($Body)+"`n"+$ExpectedHost))
    $actual=ConvertTo-HostAgentHmac ([Text.Encoding]::UTF8.GetBytes($Key)) $material
    $left=[Text.Encoding]::ASCII.GetBytes($actual);$right=[Text.Encoding]::ASCII.GetBytes(([string]$Provided).ToLowerInvariant())
    if($left.Length -ne $right.Length -or -not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals($left,$right)){throw 'Host Agent response authentication failed.'}
    return $true
}

function Invoke-HostAgentAuthenticatedJson {
    param([Parameter(Mandatory)][string]$Uri,[Parameter(Mandatory)][string]$Method,[Parameter(Mandatory)][string]$Key,[Parameter(Mandatory)][string]$ExpectedHost,[hashtable]$Body=@{})
    $parsed=[Uri]$Uri;$path=$parsed.AbsolutePath;$bodyBytes=[Text.Encoding]::UTF8.GetBytes(($Body|ConvertTo-Json -Depth 20 -Compress));if($Method.ToUpperInvariant() -eq 'GET'){$bodyBytes=[byte[]]@()}
    $auth=New-HostAgentRequestAuthentication $Method $path $bodyBytes $Key $ExpectedHost
    $request=[Net.HttpWebRequest]::Create($Uri);$request.Method=$Method.ToUpperInvariant();$request.Timeout=3000;$request.ReadWriteTimeout=3000;$request.Headers['X-DevFleet-Host-Timestamp']=$auth.Timestamp;$request.Headers['X-DevFleet-Host-Nonce']=$auth.Nonce;$request.Headers['X-DevFleet-Host-Expected']=$auth.Expected;$request.Headers['X-DevFleet-Host-Signature']=$auth.Signature
    if($bodyBytes.Length -gt 0){$request.ContentType='application/json';$request.ContentLength=$bodyBytes.Length;$stream=$request.GetRequestStream();try{$stream.Write($bodyBytes,0,$bodyBytes.Length)}finally{$stream.Dispose()}}
    $response=$null;$responseBody=[byte[]]@()
    try{$response=$request.GetResponse()}catch [Net.WebException]{if(-not $_.Exception.Response){throw};$response=$_.Exception.Response}
    try{$stream=$response.GetResponseStream();$memory=[IO.MemoryStream]::new();try{$stream.CopyTo($memory);$responseBody=$memory.ToArray()}finally{$memory.Dispose();$stream.Dispose()};$status=[int]$response.StatusCode;$signature=[string]$response.Headers['X-DevFleet-Host-Response-Signature'];Test-HostAgentResponseAuthentication $Method $path $status $responseBody $Key $ExpectedHost $auth.Timestamp $auth.Nonce $signature|Out-Null;if($status -lt 200 -or $status -ge 300){throw "Host Agent rejected authenticated request ($status)."};return ([Text.Encoding]::UTF8.GetString($responseBody)|ConvertFrom-Json)}finally{if($response){$response.Dispose()}}
}

Export-ModuleMember -Function New-HostAgentRequestAuthentication,Test-HostAgentResponseAuthentication,Invoke-HostAgentAuthenticatedJson
