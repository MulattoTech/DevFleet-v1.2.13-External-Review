[CmdletBinding()]
param([string]$CredentialFile)
$ErrorActionPreference='Stop'
$module=Join-Path $PSScriptRoot 'modules\Secrets.psm1'
Import-Module $module -Force
if ($CredentialFile) {
    $kv=@{}
    foreach($line in Get-Content -LiteralPath $CredentialFile){ $parts=$line.Split('=',2); if($parts.Count -eq 2){$kv[$parts[0]]=$parts[1]} }
    if (-not $kv.username -or -not $kv.password) { throw 'Credential file must contain username and password keys.' }
    $secure=ConvertTo-SecureString $kv.password -AsPlainText -Force
    $credential=[pscredential]::new($kv.username,$secure)
} else {
    $username=Read-Host 'Disposable E2E username'
    $secure=Read-Host 'Disposable E2E password' -AsSecureString
    $credential=[pscredential]::new($username,$secure)
}
$path=Save-DevFleetE2ECredential -Credential $credential
[pscustomobject]@{ status='PASS'; storePath=$path; plaintextStoredInWorkspace=$false; passwordPrinted=$false } | ConvertTo-Json
