$ErrorActionPreference = 'Stop'
$common = Join-Path (Split-Path -Parent $PSScriptRoot) 'windows\DevFleet.Common.psm1'
Import-Module $common -Force
$cases = @(
    @{ name='clean absent'; cbs=$false; wu=$false; pfro=$null; expected=$false },
    @{ name='empty value'; cbs=$false; wu=$false; pfro=@(); expected=$false },
    @{ name='empty strings'; cbs=$false; wu=$false; pfro=@('','   '); expected=$false },
    @{ name='real rename'; cbs=$false; wu=$false; pfro=@('C:\source.tmp','C:\destination.tmp'); expected=$true },
    @{ name='real delete'; cbs=$false; wu=$false; pfro=@('C:\source.tmp',''); expected=$true },
    @{ name='CBS with empty value'; cbs=$true; wu=$false; pfro=@(''); expected=$true },
    @{ name='Windows Update with empty value'; cbs=$false; wu=$true; pfro=@(''); expected=$true },
    @{ name='multiple operations'; cbs=$false; wu=$false; pfro=@('C:\one','C:\two','C:\three',''); expected=$true }
)
foreach ($case in $cases) {
    $actual = Test-PendingRebootState -CbsPending:$case.cbs -WindowsUpdatePending:$case.wu -PendingFileRenameOperations $case.pfro
    if ([bool]$actual -ne [bool]$case.expected) { throw "PFRO semantic case failed: $($case.name) expected=$($case.expected) actual=$actual" }
}
$source = Get-Content $common -Raw
if ($source -match '(?m)\b(Remove|Set)-Item(Property)?\b[^\r\n]*PendingFileRenameOperations') { throw 'PFRO regression test detected registry mutation in shipping reboot detection.' }
[ordered]@{ status='PASS'; cases=$cases.Count; cbsAndWindowsUpdatePreserved=$true; registryMutated=$false } | ConvertTo-Json -Compress
