Set-StrictMode -Version Latest
Import-Module ThreadJob -ErrorAction SilentlyContinue
Import-Module (Join-Path $PSScriptRoot '..\GuestSession.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\HostSafety.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\Evidence.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\FullRelease.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\InteractiveLogon.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\TailscaleE2E.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\HarnessBudget.psm1') -Force

$script:CanonicalIntegrationOwnershipPath = 'C:\ProgramData\DevFleetHostAgent\integration-ownership.json'

# Provider payloads cross JSON/ remoting boundaries as PSCustomObject,
# Hashtable, or OrderedDictionary. Keep lifecycle decisions independent of
# that representation and use these helpers at every trust boundary.
function Get-LifecycleProperty {
    param([AllowNull()][object]$Value,[Parameter(Mandatory)][string]$Name,[ref]$Found)
    $Found.Value=$false
    if($null -eq $Value){return $null}
    if($Value -is [System.Collections.IDictionary]){
        foreach($key in $Value.Keys){if([string]$key -ieq $Name){$Found.Value=$true;return $Value[$key]}}
        return $null
    }
    foreach($property in @($Value.PSObject.Properties)){if([string]$property.Name -ieq $Name){$Found.Value=$true;return $property.Value}}
    return $null
}
function Get-LifecyclePropertyNames {
    param([AllowNull()][object]$Value)
    if($null -eq $Value){return @()}
    if($Value -is [System.Collections.IDictionary]){return @($Value.Keys|ForEach-Object{[string]$_})}
    return @($Value.PSObject.Properties|ForEach-Object{[string]$_.Name})
}
function Test-LifecycleProperty {
    param([AllowNull()][object]$Value,[Parameter(Mandatory)][string]$Name)
    $found=$false;[void](Get-LifecycleProperty -Value $Value -Name $Name -Found ([ref]$found));return $found
}

function Test-RebootBoundaryIdentity {
    param(
        [Parameter(Mandatory)][psobject]$PriorCheckpoint,
        [AllowNull()][psobject]$CurrentCheckpoint,
        [int]$MaxGeneration = 3
    )
    if (-not $CurrentCheckpoint) { return $false }
    foreach($required in @('checkpointGeneration','transactionId','action','role','payloadSha256','state')){if(-not (Test-LifecycleProperty -Value $CurrentCheckpoint -Name $required)){return $false}}
    # Exactly one product generation is allowed to authorize one reboot.  A
    # jump (for example 1 -> 3) is an ambiguous/foreign lifecycle and must
    # never be treated as a valid boundary.
    $found=$false;$currentGeneration=Get-LifecycleProperty $CurrentCheckpoint 'checkpointGeneration' ([ref]$found);if(-not $found){return $false};$found=$false;$priorGenerationValue=Get-LifecycleProperty $PriorCheckpoint 'checkpointGeneration' ([ref]$found);if(-not $found){return $false};$generation=0;$priorGeneration=0;if(-not [int]::TryParse([string]$currentGeneration,[ref]$generation)-or-not [int]::TryParse([string]$priorGenerationValue,[ref]$priorGeneration)){return $false}
    # checkpointGeneration -ne PriorCheckpoint.checkpointGeneration + 1 is
    # the fail-closed rule (expressed with parsed numeric values below).
    if ($generation -ne ($priorGeneration + 1)) { return $false }
    if ($generation -gt $MaxGeneration) { return $false }
    foreach ($name in @('transactionId','action','role','payloadSha256')) {
        $currentFound=$false;$currentValue=Get-LifecycleProperty $CurrentCheckpoint $name ([ref]$currentFound);$priorFound=$false;$priorValue=Get-LifecycleProperty $PriorCheckpoint $name ([ref]$priorFound);if(-not $currentFound -or -not $priorFound -or [string]$currentValue -cne [string]$priorValue) { return $false }
    }
    $found=$false;$state=Get-LifecycleProperty $CurrentCheckpoint 'state' ([ref]$found);return ($found -and [string]$state -eq 'waiting-for-reboot')
}

function ConvertTo-CanonicalLifecycleCheckpoint {
    param([AllowNull()][object]$Checkpoint)
    if(-not $Checkpoint){return $null}
    $hasCheckpointGeneration=Test-LifecycleProperty -Value $Checkpoint -Name 'checkpointGeneration'
    $hasGeneration=Test-LifecycleProperty -Value $Checkpoint -Name 'generation'
    if(-not $hasCheckpointGeneration -and -not $hasGeneration){return $null}
    $checkpointGeneration=0;$generation=0
    $found=$false;$checkpointGenerationValue=Get-LifecycleProperty $Checkpoint 'checkpointGeneration' ([ref]$found);if($hasCheckpointGeneration -and -not [int]::TryParse([string]$checkpointGenerationValue,[ref]$checkpointGeneration)){return $null}
    $found=$false;$generationValue=Get-LifecycleProperty $Checkpoint 'generation' ([ref]$found);if($hasGeneration -and -not [int]::TryParse([string]$generationValue,[ref]$generation)){return $null}
    if(-not $hasCheckpointGeneration){$checkpointGeneration=$generation}
    if(-not $hasGeneration){$generation=$checkpointGeneration}
    if($generation -ne $checkpointGeneration){return $null}
    $copy=[ordered]@{}
    if($Checkpoint -is [System.Collections.IDictionary]){foreach($key in $Checkpoint.Keys){$copy[[string]$key]=$Checkpoint[$key]}}else{foreach($property in $Checkpoint.PSObject.Properties){$copy[$property.Name]=$property.Value}}
    $copy.generation=$generation
    $copy.checkpointGeneration=$checkpointGeneration
    return [pscustomobject]$copy
}

function Test-NoActiveProductCheckpoint {
    param([AllowNull()][object]$Value,[int]$Depth=0,[System.Collections.Generic.HashSet[int]]$Seen,[string]$Path='root')
    if($null -eq $Value -or $Value -is [string] -or $Value.GetType().IsPrimitive -or $Value -is [datetime] -or $Value -is [guid]){return $true}
    if($Depth -gt 12){return $false}
    if(-not $Seen){$Seen=[System.Collections.Generic.HashSet[int]]::new()};$identity=[Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($Value);if(-not $Seen.Add($identity)){return $false}
    # IDictionary (including [ordered] test/projection payloads) is enumerable,
    # but its entries are lifecycle fields rather than a signal-free list. Walk
    # entries by key so generation/checkpoint fields cannot be hidden, while
    # avoiding the false cycle reports caused by enumerating dictionary views.
    if($Value -is [System.Collections.IDictionary]){
        foreach($entry in $Value.GetEnumerator()){
            $lower=([string]$entry.Key).ToLowerInvariant();$item=$entry.Value;$childPath=if($Path -eq 'root'){([string]$entry.Key)}else{"$Path.$([string]$entry.Key)"}
            if($lower -eq 'rawactivelifecyclesignals' -and $item -and @($item).Count -gt 0){foreach($signal in @($item)){$kindFound=$false;$kind=Get-LifecycleProperty $signal 'kind' ([ref]$kindFound);$pathFound=$false;$signalPath=Get-LifecycleProperty $signal 'path' ([ref]$pathFound);$valueFound=$false;$signalValue=Get-LifecycleProperty $signal 'value' ([ref]$valueFound);$zero=0;$benign=($kindFound -and [string]$kind -ieq 'checkpointgeneration' -and $pathFound -and [string]$signalPath -eq 'progress.checkpointGeneration' -and [int]::TryParse([string]$signalValue,[ref]$zero) -and $zero -eq 0 -and [string]$signalValue -match '^0$');if(-not $benign){return $false}}}
            if($lower -eq 'checkpoint' -and $null -ne $item){return $false}
            if($lower -eq 'checkpointpresent' -and [bool]$item){return $false}
            if($lower -in @('checkpointgeneration','generation')){$zeroValue=0;$zeroAllowed=($lower -eq 'checkpointgeneration' -and ($Path -eq 'progress' -or $Path -match '\.progress$') -and [int]::TryParse([string]$item,[ref]$zeroValue) -and $zeroValue -eq 0 -and [string]$item -match '^0$');if(-not $zeroAllowed){return $false}}
            if($lower -eq 'state' -and [string]$item -ieq 'waiting-for-reboot'){return $false}
            if($lower -in @('installledger','ownershipledger','installstate','ownership','receipt')){continue}
            $childSeen=[System.Collections.Generic.HashSet[int]]::new($Seen);if(-not (Test-NoActiveProductCheckpoint -Value $item -Depth ($Depth+1) -Seen $childSeen -Path $childPath)){return $false}
        }
        return $true
    }
    if($Value -is [System.Collections.IEnumerable]){foreach($item in $Value){$childSeen=[System.Collections.Generic.HashSet[int]]::new($Seen);if(-not (Test-NoActiveProductCheckpoint -Value $item -Depth ($Depth+1) -Seen $childSeen -Path ($Path+'[]'))){return $false}};return $true}
    foreach($property in @($Value.PSObject.Properties)){
        $name=[string]$property.Name;$item=$property.Value;$lower=$name.ToLowerInvariant()
        if($lower -eq 'rawactivelifecyclesignals' -and $item -and @($item).Count -gt 0){foreach($signal in @($item)){$kindFound=$false;$kind=Get-LifecycleProperty $signal 'kind' ([ref]$kindFound);$pathFound=$false;$signalPath=Get-LifecycleProperty $signal 'path' ([ref]$pathFound);$valueFound=$false;$signalValue=Get-LifecycleProperty $signal 'value' ([ref]$valueFound);$zero=0;$benign=($kindFound -and [string]$kind -ieq 'checkpointgeneration' -and $pathFound -and [string]$signalPath -eq 'progress.checkpointGeneration' -and [int]::TryParse([string]$signalValue,[ref]$zero) -and $zero -eq 0 -and [string]$signalValue -match '^0$');if(-not $benign){return $false}}}
        if($lower -eq 'checkpoint' -and $null -ne $item){return $false}
        if($lower -eq 'checkpointpresent' -and [bool]$item){return $false}
        if($lower -in @('checkpointgeneration','generation')){
            $zeroValue=0;$zeroAllowed=($lower -eq 'checkpointgeneration' -and ($Path -eq 'progress' -or $Path -match '\.progress$') -and [int]::TryParse([string]$item,[ref]$zeroValue) -and $zeroValue -eq 0 -and [string]$item -match '^0$');if(-not $zeroAllowed){return $false}
        }
        if($lower -eq 'state' -and [string]$item -ieq 'waiting-for-reboot'){return $false}
        if($lower -in @('installledger','ownershipledger','installstate','ownership','receipt')){continue}
        $childPath=if($Path -eq 'root'){$name}else{"$Path.$name"};$childSeen=[System.Collections.Generic.HashSet[int]]::new($Seen);if(-not (Test-NoActiveProductCheckpoint -Value $item -Depth ($Depth+1) -Seen $childSeen -Path $childPath)){return $false}
    }
    return $true
}

function Test-BenignLifecycleCheckpointGenerationSignal {
    param([AllowNull()][object]$Signal)
    $kindFound=$false;$kind=Get-LifecycleProperty $Signal 'kind' ([ref]$kindFound)
    $pathFound=$false;$path=Get-LifecycleProperty $Signal 'path' ([ref]$pathFound)
    $valueFound=$false;$value=Get-LifecycleProperty $Signal 'value' ([ref]$valueFound)
    $parsed=0
    return ($kindFound -and [string]$kind -ieq 'checkpointgeneration' -and $pathFound -and [string]$path -match '(^|\.)progress\.checkpointGeneration$' -and $valueFound -and [int]::TryParse([string]$value,[ref]$parsed) -and $parsed -eq 0 -and [string]$value -ceq '0')
}

function Test-LifecycleCompletionInput {
    param([AllowNull()][object]$Value,[ref]$Reason)
    $Reason.Value=''
    if(-not (Test-NoActiveProductCheckpoint -Value $Value)){$Reason.Value='active checkpoint, generation, or waiting-for-reboot signal';return $false}
    $found=$false;$terminal=Get-LifecycleProperty $Value 'terminalFailure' ([ref]$found);if($found -and [bool]$terminal){$Reason.Value='terminalFailure claim';return $false}
    foreach($name in @('failure','error')){$found=$false;$claim=Get-LifecycleProperty $Value $name ([ref]$found);if($found -and -not [string]::IsNullOrWhiteSpace([string]$claim)){$Reason.Value="$name claim";return $false}}
    foreach($name in @('status','outcome')){$found=$false;$claim=Get-LifecycleProperty $Value $name ([ref]$found);if($found -and [string]$claim -match '^(?i:TERMINAL_FAILURE|TERMINAL|ERROR|WAITING_FOR_REBOOT)$'){$Reason.Value="$name=$claim";return $false}}
    $signals=@(Get-RawActiveLifecycleSignals -Value $Value);$unsafe=$signals|Where-Object{$_.kind -in @('terminalFailure','failure','error','terminalReason','terminal-status','depth-cutoff','cycle') -or ($_.kind -eq 'waiting-for-reboot' -and [string]$_.path -notmatch '^checkpoint\.state$') -or ($_.kind -eq 'checkpoint' -and [string]$_.path -notmatch '^checkpoint$') -or ($_.kind -eq 'generation' -and [string]$_.path -notmatch '^checkpoint\.') -or ($_.kind -eq 'checkpointgeneration' -and -not (Test-BenignLifecycleCheckpointGenerationSignal $_) -and [string]$_.path -notmatch '^(progress|checkpoint)\.') }|Select-Object -First 1
    if($unsafe){$Reason.Value="unsafe lifecycle signal at $([string]$unsafe.path)";return $false}
    return $true
}

function Test-LifecycleTransitionObservationBinding {
    param([AllowNull()][object]$Observation,[AllowNull()][object]$Checkpoint,[ref]$Reason)
    $Reason.Value=''
    if($null -eq $Observation){return $true}
    $found=$false;$rawCheckpoint=Get-LifecycleProperty $Observation 'checkpoint' ([ref]$found);$hasRawCheckpoint=$found -and $null -ne $rawCheckpoint;$flagFound=$false;$flagValue=Get-LifecycleProperty $Observation 'checkpointPresent' ([ref]$flagFound);if($flagFound -and ([bool]$flagValue) -ne $hasRawCheckpoint){$Reason.Value='transition observation checkpoint presence flag disagrees with object';return $false}
    if($hasRawCheckpoint){if(-not $flagFound){$Reason.Value='transition observation checkpointPresent flag is missing';return $false};if($null -eq $Checkpoint){$Reason.Value='transition observation supplied a checkpoint for a non-reboot outcome';return $false};$canonical=ConvertTo-CanonicalLifecycleCheckpoint $rawCheckpoint;if(-not $canonical){$Reason.Value='transition observation checkpoint is malformed';return $false};foreach($name in @('generation','checkpointGeneration','transactionId','payloadSha256','action','role','state')){$expectedFound=$false;$expectedValue=Get-LifecycleProperty $Checkpoint $name ([ref]$expectedFound);$actualFound=$false;$actualValue=Get-LifecycleProperty $canonical $name ([ref]$actualFound);if(-not $expectedFound -or -not $actualFound -or [string]$expectedValue -cne [string]$actualValue){$Reason.Value="transition observation checkpoint binding mismatch: $name";return $false}}}
    $signals=@(Get-RawActiveLifecycleSignals -Value $Observation);$unsafe=$signals|Where-Object{($_.kind -eq 'generation' -and [string]$_.path -notmatch '^checkpoint\.') -or ($_.kind -eq 'checkpointgeneration' -and -not (Test-BenignLifecycleCheckpointGenerationSignal $_) -and [string]$_.path -notmatch '^(progress|checkpoint)\.') -or ($_.kind -eq 'checkpoint' -and [string]$_.path -notmatch '^checkpoint$') -or [string]$_.path -match '(^|\.)observation\.' -or ($_.kind -eq 'waiting-for-reboot' -and [string]$_.path -notmatch '^checkpoint\.state$') -or $_.kind -in @('terminalFailure','failure','error','terminalReason','terminal-status','depth-cutoff','cycle')}|Select-Object -First 1;if($unsafe){$Reason.Value="transition observation active signal at $([string]$unsafe.path)";return $false}
    return $true
}

function Get-RawActiveLifecycleSignals {
    param([AllowNull()][object]$Value,[string]$Path='root',[int]$Depth=0,[System.Collections.Generic.HashSet[int]]$Seen)
    $signals=@();if($null -eq $Value -or $Value -is [string] -or $Value.GetType().IsPrimitive -or $Value -is [datetime] -or $Value -is [guid]){return @()}
    if($Depth -gt 12){return @([pscustomobject]@{path=$Path;kind='depth-cutoff';value='unsafe'})}
    if(-not $Seen){$Seen=[System.Collections.Generic.HashSet[int]]::new()};$identity=[Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($Value);if(-not $Seen.Add($identity)){return @([pscustomobject]@{path=$Path;kind='cycle';value='unsafe'})}
    if($Value -is [System.Collections.IDictionary]){
        foreach($entry in $Value.GetEnumerator()){
            $name=[string]$entry.Key;$item=$entry.Value;$lower=$name.ToLowerInvariant();$childPath=if($Path -eq 'root'){$name}else{"$Path.$name"}
            $ignoredLedger=($lower -in @('installledger','ownershipledger','installstate','ownership','receipt'))
            if(-not $ignoredLedger){
                if($lower -in @('generation','checkpointgeneration')){$signals+=[pscustomobject]@{path=$childPath;kind=$lower;value=[string]$item}}
                elseif($lower -eq 'checkpoint' -and $null -ne $item){$signals+=[pscustomobject]@{path=$childPath;kind='checkpoint';value='present'}}
                elseif($lower -eq 'checkpointpresent' -and [bool]$item){$signals+=[pscustomobject]@{path=$childPath;kind='checkpointPresent';value='true'}}
                elseif($lower -eq 'state' -and [string]$item -ieq 'waiting-for-reboot'){$signals+=[pscustomobject]@{path=$childPath;kind='waiting-for-reboot';value='true'}}
                elseif($lower -eq 'terminalfailure' -and [bool]$item){$signals+=[pscustomobject]@{path=$childPath;kind='terminalFailure';value='true'}}
                elseif($lower -in @('failure','error','terminalreason') -and -not [string]::IsNullOrWhiteSpace([string]$item)){$signals+=[pscustomobject]@{path=$childPath;kind=$lower;value=[string]$item}}
                elseif($lower -eq 'status' -and [string]$item -match '^(?i:TERMINAL_FAILURE|TERMINAL|ERROR|WAITING_FOR_REBOOT)$'){$signals+=[pscustomobject]@{path=$childPath;kind='terminal-status';value=[string]$item}}
                $childSeen=[System.Collections.Generic.HashSet[int]]::new($Seen);$signals+=@(Get-RawActiveLifecycleSignals -Value $item -Path $childPath -Depth ($Depth+1) -Seen $childSeen)
            }
        }
        return $signals
    }
    if($Value -is [System.Collections.IEnumerable]){foreach($item in $Value){$childSeen=[System.Collections.Generic.HashSet[int]]::new($Seen);$signals+=@(Get-RawActiveLifecycleSignals -Value $item -Path ($Path+'[]') -Depth ($Depth+1) -Seen $childSeen)};return $signals}
    foreach($property in @($Value.PSObject.Properties)){
        $name=[string]$property.Name;$item=$property.Value;$lower=$name.ToLowerInvariant();$childPath=if($Path -eq 'root'){$name}else{"$Path.$name"}
        $ignoredLedger=($lower -in @('installledger','ownershipledger','installstate','ownership','receipt'))
        if(-not $ignoredLedger){
            if($lower -in @('generation','checkpointgeneration')){$signals+=[pscustomobject]@{path=$childPath;kind=$lower;value=[string]$item}}
            elseif($lower -eq 'checkpoint' -and $null -ne $item){$signals+=[pscustomobject]@{path=$childPath;kind='checkpoint';value='present'}}
            elseif($lower -eq 'checkpointpresent' -and [bool]$item){$signals+=[pscustomobject]@{path=$childPath;kind='checkpointPresent';value='true'}}
            elseif($lower -eq 'state' -and [string]$item -ieq 'waiting-for-reboot'){$signals+=[pscustomobject]@{path=$childPath;kind='waiting-for-reboot';value='true'}}
            elseif($lower -eq 'terminalfailure' -and [bool]$item){$signals+=[pscustomobject]@{path=$childPath;kind='terminalFailure';value='true'}}
            elseif($lower -in @('failure','error','terminalreason') -and -not [string]::IsNullOrWhiteSpace([string]$item)){$signals+=[pscustomobject]@{path=$childPath;kind=$lower;value=[string]$item}}
            elseif($lower -eq 'status' -and [string]$item -match '^(?i:TERMINAL_FAILURE|TERMINAL|ERROR|WAITING_FOR_REBOOT)$'){$signals+=[pscustomobject]@{path=$childPath;kind='terminal-status';value=[string]$item}}
        $childSeen=[System.Collections.Generic.HashSet[int]]::new($Seen);$signals+=@(Get-RawActiveLifecycleSignals -Value $item -Path $childPath -Depth ($Depth+1) -Seen $childSeen)
        }
    }
    return $signals
}

function Get-DurableProgressClassification {
    param(
        [Parameter(Mandatory)][psobject]$Observation,
        [Parameter(Mandatory)][psobject]$PriorCheckpoint,
        [int]$MaxGeneration = 3
    )
    $observationProperties=Get-LifecyclePropertyNames $Observation
    $hasCheckpointProperty=Test-LifecycleProperty -Value $Observation -Name 'checkpoint'
    $found=$false;$observationCheckpoint=Get-LifecycleProperty $Observation 'checkpoint' ([ref]$found)
    $actualCheckpointPresent=($null -ne $observationCheckpoint)
    $hasPresenceFlag=Test-LifecycleProperty -Value $Observation -Name 'checkpointPresent';$found=$false;$checkpointPresentValue=Get-LifecycleProperty $Observation 'checkpointPresent' ([ref]$found)
    $flaggedCheckpointPresent=($hasPresenceFlag -and [bool]$checkpointPresentValue)
    if($hasPresenceFlag -and $flaggedCheckpointPresent -ne $actualCheckpointPresent){return 'TERMINAL_FAILURE'}
    $observationCheckpointPresent=$actualCheckpointPresent
    # Apply the same fail-closed raw-signal precedence as the normalized wait
    # seam. Direct classifier callers must not be able to hide an active or
    # contradictory lifecycle signal in an unknown/nested property.
    $rawSignals=@(Get-RawActiveLifecycleSignals -Value $Observation)
    $unsafeSignal=$rawSignals|Where-Object{($_.kind -eq 'generation' -and [string]$_.path -notmatch '^checkpoint\.') -or ($_.kind -eq 'checkpointgeneration' -and -not (Test-BenignLifecycleCheckpointGenerationSignal $_) -and [string]$_.path -notmatch '^(progress|checkpoint)\.') -or ($_.kind -eq 'checkpoint' -and [string]$_.path -notmatch '^checkpoint$') -or [string]$_.path -match '(^|\.)observation\.' -or ($_.kind -eq 'waiting-for-reboot' -and [string]$_.path -notmatch '^checkpoint\.state$') -or $_.kind -in @('terminalFailure','failure','error','terminalReason','terminal-status','depth-cutoff','cycle')}|Select-Object -First 1
    if($unsafeSignal){return 'TERMINAL_FAILURE'}
    if($observationCheckpointPresent){$canonicalObservationCheckpoint=ConvertTo-CanonicalLifecycleCheckpoint $observationCheckpoint;if(-not $canonicalObservationCheckpoint){return 'TERMINAL_FAILURE'};$observationCheckpoint=$canonicalObservationCheckpoint}
    $found=$false;$terminalFlag=Get-LifecycleProperty $Observation 'terminalFailure' ([ref]$found);$terminalClaim=($found -and [bool]$terminalFlag);$found=$false;$failureValue=Get-LifecycleProperty $Observation 'failure' ([ref]$found);$failureClaim=($found -and -not [string]::IsNullOrWhiteSpace([string]$failureValue));$found=$false;$errorValue=Get-LifecycleProperty $Observation 'error' ([ref]$found);$errorClaim=($found -and -not [string]::IsNullOrWhiteSpace([string]$errorValue));$found=$false;$statusValue=Get-LifecycleProperty $Observation 'status' ([ref]$found);$statusClaim=($found -and [string]$statusValue -match '^(?i:TERMINAL_FAILURE|TERMINAL|ERROR)$');if($terminalClaim -or $failureClaim -or $errorClaim -or $statusClaim){return 'TERMINAL_FAILURE'}
    $statusClaimsCompleted=($found -and [string]$statusValue -eq 'COMPLETED');$allCompletionFields=$true
    foreach($completionField in @('matchingConsumedReceipt','installStateValid','canonicalOwnershipValid','authenticatedHealthOk')){$fieldFound=$false;$fieldValue=Get-LifecycleProperty $Observation $completionField ([ref]$fieldFound);if(-not ($fieldFound -and [bool]$fieldValue)){$allCompletionFields=$false}}
    $claimsCompleted=$statusClaimsCompleted -or $allCompletionFields
    if($actualCheckpointPresent -and $claimsCompleted){return 'TERMINAL_FAILURE'}
    if ($observationCheckpoint -and $observationCheckpointPresent) {
        foreach($required in @('checkpointGeneration','transactionId','payloadSha256','action','role','state')){if(-not (Test-LifecycleProperty -Value $observationCheckpoint -Name $required)){return 'TERMINAL_FAILURE'}}
        $found=$false;$currentCheckpointGeneration=Get-LifecycleProperty $observationCheckpoint 'checkpointGeneration' ([ref]$found);if(-not $found){return 'TERMINAL_FAILURE'};$found=$false;$priorCheckpointGeneration=Get-LifecycleProperty $PriorCheckpoint 'checkpointGeneration' ([ref]$found);if(-not $found){return 'TERMINAL_FAILURE'};$generation=0;$priorGeneration=0;if(-not [int]::TryParse([string]$currentCheckpointGeneration,[ref]$generation)-or-not [int]::TryParse([string]$priorCheckpointGeneration,[ref]$priorGeneration)){return 'TERMINAL_FAILURE'}
        $bindingMatches=$true
        foreach($name in @('transactionId','payloadSha256','action','role')) {
            $currentFound=$false;$currentValue=Get-LifecycleProperty $observationCheckpoint $name ([ref]$currentFound);$priorFound=$false;$priorValue=Get-LifecycleProperty $PriorCheckpoint $name ([ref]$priorFound);if(-not $currentFound -or -not $priorFound -or [string]$currentValue -cne [string]$priorValue){$bindingMatches=$false;break}
        }
        $found=$false;$checkpointState=Get-LifecycleProperty $observationCheckpoint 'state' ([ref]$found);if(-not $bindingMatches -or -not $found -or [string]$checkpointState -ne 'waiting-for-reboot' -or $generation -lt 1 -or $generation -gt $MaxGeneration -or $generation -gt ($priorGeneration + 1) -or $generation -lt $priorGeneration) { return 'TERMINAL_FAILURE' }
    }
    if (Test-RebootBoundaryIdentity -PriorCheckpoint $PriorCheckpoint -CurrentCheckpoint $observationCheckpoint -MaxGeneration $MaxGeneration) {
        return 'NEXT_REBOOT'
    }
    $receiptFound=$false;$receiptValue=Get-LifecycleProperty $Observation 'matchingConsumedReceipt' ([ref]$receiptFound);$receiptOk=($receiptFound -and [bool]$receiptValue);$installFound=$false;$installValue=Get-LifecycleProperty $Observation 'installStateValid' ([ref]$installFound);$installOk=($installFound -and [bool]$installValue);$ownershipFound=$false;$ownershipValue=Get-LifecycleProperty $Observation 'canonicalOwnershipValid' ([ref]$ownershipFound);$ownershipOk=($ownershipFound -and [bool]$ownershipValue);$healthFound=$false;$healthValue=Get-LifecycleProperty $Observation 'authenticatedHealthOk' ([ref]$healthFound);$healthOk=($healthFound -and [bool]$healthValue)
    $progressGeneration=0
    $progressFound=$false;$progressValue=Get-LifecycleProperty $Observation 'progress' ([ref]$progressFound);if($progressFound -and $progressValue -and (Test-LifecycleProperty -Value $progressValue -Name 'checkpointGeneration')){
        $progressFieldFound=$false;$progressGenerationValue=Get-LifecycleProperty $progressValue 'checkpointGeneration' ([ref]$progressFieldFound);if(-not [int]::TryParse([string]$progressGenerationValue,[ref]$progressGeneration)-or$progressGeneration -lt 0){return 'TERMINAL_FAILURE'}
    }
    if (-not $observationCheckpointPresent -and $progressGeneration -eq 0 -and $receiptOk -and $installOk -and $ownershipOk -and $healthOk) {
        return 'COMPLETED'
    }
    if ($terminalClaim) { return 'TERMINAL_FAILURE' }
    return 'NO_PROGRESS'
}

function Get-ProductLifecycleObservation {
    <#
      Reads one guest observation.  ObservationProvider is deliberately a
      seam is exposed by Wait-DevFleetProductLifecycleTransition; direct
      observation calls remain authenticated PSSession-only.
    #>
    param(
        [Parameter(Mandatory)][object]$Session,
        [Parameter(Mandatory)][AllowEmptyString()][string]$TransactionId,
        [Parameter(Mandatory)][string]$PayloadSha256,
        [Parameter(Mandatory)][string]$Role,
        [string]$Action='FreshInstall',
        [int]$PriorGeneration=0,
        [int]$MaxGeneration=3,
        [int]$CandidateProcessId=0,
        [scriptblock]$ObservationProvider,
        [string]$ExpectedDevFleetVersion,
        [string]$ExpectedInstallerVersion,
        [int]$ObservationTimeoutSeconds=0,
        [string]$InvocationStartUtc
    )
    if([string]::IsNullOrWhiteSpace($ExpectedDevFleetVersion)-or$ExpectedDevFleetVersion -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$'){throw 'TERMINAL_FAILURE: expected DevFleet version is missing or malformed.'}
    if([string]::IsNullOrWhiteSpace($ExpectedInstallerVersion)-or$ExpectedInstallerVersion -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$'){throw 'TERMINAL_FAILURE: expected installer version is missing or malformed.'}
    if($ObservationProvider){throw 'TERMINAL_FAILURE: ObservationProvider is only permitted through the bounded lifecycle wait seam.'}
    $remoteScript = {
        param($tx,$payload,$expectedAction,$expectedRole,$prior,$max,$candidatePid,$expectedVersion,$expectedInstaller,$invocationStart)
        $checkpointPath='C:\ProgramData\M-TechLabs\DevFleet\Installer\resume-checkpoint.json'
        $checkpoint=$null
        if(Test-Path -LiteralPath $checkpointPath -PathType Leaf){
            try {
                $value=Get-Content -LiteralPath $checkpointPath -Raw|ConvertFrom-Json
                if($invocationStart){$created=[datetime]::MinValue;if(-not [datetime]::TryParse([string]$value.createdUtc,[ref]$created)){throw 'checkpoint lacks a trustworthy createdUtc provenance'};if($created.ToUniversalTime() -lt ([datetime]$invocationStart).ToUniversalTime()){throw 'checkpoint predates this lifecycle invocation'}}
                $checkpointGeneration=0;if(-not [int]::TryParse([string]$value.checkpointGeneration,[ref]$checkpointGeneration)){throw 'checkpoint generation is not numeric'}
                $checkpoint=[ordered]@{transactionId=[string]$value.transactionId;payloadSha256=[string]$value.payloadSha256;action=[string]$value.action;role=[string]$value.role;state=[string]$value.state;generation=$checkpointGeneration;checkpointGeneration=$checkpointGeneration;completedStages=@($value.completedStages);resumeStage=[string]$value.resumeStage;lastWriteUtc=(Get-Item -LiteralPath $checkpointPath).LastWriteTimeUtc.ToString('o')}
                if([int]$value.checkpointGeneration -lt 1 -or [int]$value.checkpointGeneration -gt $max){return [ordered]@{terminalFailure=$true;failure='invalid checkpoint generation';checkpoint=$checkpoint;checkpointPresent=$true}}
            } catch { return [ordered]@{terminalFailure=$true;failure=$_.Exception.Message;checkpointPresent=$true} }
        }
        $receiptPath="C:\ProgramData\M-TechLabs\DevFleet\Installer\resume-consumed\$tx.json"
        $receipt=$null
        if(Test-Path -LiteralPath $receiptPath -PathType Leaf){try{$receipt=Get-Content -LiteralPath $receiptPath -Raw|ConvertFrom-Json}catch{return [ordered]@{terminalFailure=$true;failure='invalid consumed receipt'}}}
        if(-not $tx -and (Test-Path -LiteralPath (Split-Path -Parent $receiptPath) -PathType Container)){$receiptCandidates=@(Get-ChildItem -LiteralPath (Split-Path -Parent $receiptPath) -Filter '*.json' -File -ErrorAction SilentlyContinue|ForEach-Object{try{$r=Get-Content -LiteralPath $_.FullName -Raw|ConvertFrom-Json;$consumed=[datetime]::MinValue;if(-not [datetime]::TryParse([string]$r.consumedUtc,[ref]$consumed)){return};if($invocationStart -and $consumed.ToUniversalTime() -lt ([datetime]$invocationStart).ToUniversalTime()){return};if([string]$r.payloadSha256 -ceq $payload -and [string]$r.action -ceq $expectedAction -and [string]$r.role -ceq $expectedRole){$r}}catch{}});if($receiptCandidates.Count -gt 1){return [ordered]@{terminalFailure=$true;failure='multiple current consumed receipts match the lifecycle payload/action/role';checkpointPresent=[bool]$checkpoint}}elseif($receiptCandidates.Count -eq 1){$receipt=$receiptCandidates[0];$tx=[string]$receipt.transactionId}}
        # AppPaths.LedgerPath is the installer-owned ledger, not the Host
        # Agent integration ledger. Validate JSON content and its canonical
        # ownership binding before advertising completion.
        $installPath='C:\ProgramData\M-TechLabs\DevFleet\Installer\install-state.json';$ownershipPath='C:\ProgramData\DevFleetHostAgent\integration-ownership.json'
        $installLedger=$null;$installValid=$false;$installError=''
        if(Test-Path -LiteralPath $installPath -PathType Leaf){try{$installLedger=Get-Content -LiteralPath $installPath -Raw|ConvertFrom-Json;$canonicalInstallRoot='C:\Program Files\M-TechLabs\DevFleet';$filesValid=$true;foreach($file in @($installLedger.FilesInstalled|Where-Object{$_})){if(-not [IO.Path]::GetFullPath([string]$file).StartsWith($canonicalInstallRoot+'\',[StringComparison]::OrdinalIgnoreCase)){$filesValid=$false}};if([string]::IsNullOrWhiteSpace($expectedVersion)-or([string]$installLedger.DevFleetVersion -ceq $expectedVersion -and [string]$installLedger.InstallerVersion -ceq $expectedInstaller -and [string]$installLedger.PackageSha256 -ceq $payload -and [guid]::Parse([string]$installLedger.InstallationGeneration) -ne [guid]::Empty -and [string]$installLedger.WindowsIntegrationOwnershipPath -ieq $ownershipPath -and $filesValid)){$installValid=$true}else{$installError='installer ledger identity/schema/path mismatch'}}catch{$installError='installer ledger is unreadable'}}else{$installError='installer ledger is absent'}
        $ownershipLedger=$null;$ownershipValid=$false;$ownershipError=''
        if(Test-Path -LiteralPath $ownershipPath -PathType Leaf){try{$ownershipLedger=Get-Content -LiteralPath $ownershipPath -Raw|ConvertFrom-Json;$bindings=@($ownershipLedger.ScheduledTasks)+@($ownershipLedger.FirewallRules)+@($ownershipLedger.Services);$ownershipValid=([int]$ownershipLedger.SchemaVersion -eq 1 -and [string]$ownershipLedger.InstallationGeneration -and $installLedger -and [string]$ownershipLedger.InstallationGeneration -ceq [string]$installLedger.InstallationGeneration -and (@($bindings|Where-Object{[string]$_.Generation -and [string]$_.Generation -cne [string]$ownershipLedger.InstallationGeneration -or [string]$_.Name -match '[*?]'}).Count -eq 0))}catch{$ownershipError='ownership ledger is unreadable'}}else{$ownershipError='ownership ledger is absent'}
        $fileHash={param($path)if(Test-Path -LiteralPath $path -PathType Leaf){(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}else{$null}}
        $installHash=& $fileHash $installPath;$ownershipHash=& $fileHash $ownershipPath
        $healthOk=$false;$healthError=''
        try {
            $protocol='C:\ProgramData\DevFleetHostAgent\DevFleet-HostAgentProtocol.psm1';$tokenPath='C:\ProgramData\DevFleetHostAgent\token.txt'
            if(-not(Test-Path -LiteralPath $protocol -PathType Leaf)-or-not(Test-Path -LiteralPath $tokenPath -PathType Leaf)){throw 'authenticated Host Agent protocol prerequisites missing'}
            Import-Module $protocol -Force;$token=(Get-Content -LiteralPath $tokenPath -Raw).Trim();if(-not $token){throw 'authenticated Host Agent token is empty'}
            $health=Invoke-HostAgentAuthenticatedJson -Uri 'http://127.0.0.1:8790/healthz' -Method GET -Key $token -ExpectedHost $env:COMPUTERNAME;$healthOk=[bool]$health.ok
            if(-not $healthOk){throw 'authenticated Host Agent health returned ok=false'}
        }catch{$healthError='authenticated health unavailable'}
        $all=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
        $root=if($candidatePid -gt 0){$all|Where-Object{[int]$_.ProcessId -eq $candidatePid}|Select-Object -First 1}else{$null}
        $commandClass={param($row)
            $line=[string]$row.CommandLine
            if($line -match '(?i)Bootstrap-Install'){return 'Bootstrap-Install'}
            if($line -match '(?i)Install-DevFleet'){return 'Install-DevFleet'}
            if([string]$row.Name -match '(?i)^winget'){return 'winget'}
            if([string]$row.Name -match '(?i)^msiexec'){return 'msiexec'}
            if([string]$row.Name -match '(?i)^multipass'){return 'multipass'}
            if([int]$row.ProcessId -eq $candidatePid){return 'DevFleet-Setup'}
            return 'candidate-child'
        }
        $compactProcess={param($row)
            if(-not $row){return $null}
            $runtime=$null;try{$runtime=Get-Process -Id ([int]$row.ProcessId) -ErrorAction Stop}catch{}
            $class=&$commandClass $row
            [ordered]@{
                pid=[int]$row.ProcessId;parentPid=[int]$row.ParentProcessId;name=[string]$row.Name;path=[string]$row.ExecutablePath;sessionId=[int]$row.SessionId
                commandLineRedacted=("{0} {1} <arguments redacted>" -f [string]$row.Name,$class).Trim()
                commandClass=$class
                startTimeUtc=if($runtime){try{$runtime.StartTime.ToUniversalTime().ToString('o')}catch{''}}else{''}
                cpuSeconds=if($runtime){try{[math]::Round([double]$runtime.TotalProcessorTime.TotalSeconds,3)}catch{0.0}}else{0.0}
                responding=if($runtime){try{[bool]$runtime.Responding}catch{$false}}else{$false}
            }
        }
        $interesting=@($all|Where-Object{[string]$_.Name -match '(?i)DevFleet|msiexec|winget|multipass|powershell|pwsh' -or [string]$_.CommandLine -match '(?i)Bootstrap-Install|Install-DevFleet'}|Sort-Object ProcessId|Select-Object -First 80|ForEach-Object{&$compactProcess $_})
        $candidateTreeIds=[System.Collections.Generic.HashSet[int]]::new();if($candidatePid -gt 0){[void]$candidateTreeIds.Add($candidatePid)}
        do{$added=$false;foreach($row in $all){if($candidateTreeIds.Contains([int]$row.ParentProcessId)-and $candidateTreeIds.Add([int]$row.ProcessId)){$added=$true}}}while($added)
        # V2SocketServerMode is a CommandLine marker on powershell.exe, not a
        # process name.  Also exclude remoting/WMI helper command lines from
        # candidate descendants before calculating semantic process activity.
        $observerPattern='(?i)V2SocketServerMode|ServerRemoteHost|WSMan|WinRM|CimCmdlets|Get-CimInstance|Invoke-Command|Enter-PSSession'
        $progressProcesses=@($all|Where-Object{
            $isObserver=[string]$_.CommandLine -match $observerPattern
            $isCandidate=$candidateTreeIds.Contains([int]$_.ProcessId)
            $isBootstrap=([string]$_.CommandLine -match '(?i)Bootstrap-Install|Install-DevFleet') -and [string]$_.CommandLine -notmatch $observerPattern
            ($isCandidate -or $isBootstrap) -and -not $isObserver
        }|Sort-Object Name,ExecutablePath|Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,SessionId)
        $cpu=0.0;foreach($row in $progressProcesses){try{$cpu += [double](Get-Process -Id ([int]$row.ProcessId) -ErrorAction Stop).TotalProcessorTime.TotalSeconds}catch{}}
        $stages=@($progressProcesses|ForEach-Object{[ordered]@{name=[string]$_.Name;path=[string]$_.ExecutablePath;commandClass=(&$commandClass $_)}})
        $instances=@($progressProcesses|ForEach-Object{&$compactProcess $_})
        $bootstrap=@('C:\ProgramData\M-TechLabs\DevFleet\Installer\Bootstrap-Install.ps1','C:\ProgramData\M-TechLabs\DevFleet\Installer\Install-DevFleet.ps1')|ForEach-Object{[ordered]@{path=$_;present=(Test-Path -LiteralPath $_ -PathType Leaf)}}
        $activePath='C:\ProgramData\DevFleet\active-transaction.json';$activeTransaction=$null;$activeHash=$null
        if(Test-Path -LiteralPath $activePath -PathType Leaf){
            try{$raw=Get-Content -LiteralPath $activePath -Raw;$activeValue=$raw|ConvertFrom-Json;$activeTransaction=[ordered]@{path=$activePath;transactionId=[string]$activeValue.transactionId;payloadSha256=[string]$activeValue.payloadSha256;action=[string]$activeValue.action;role=[string]$activeValue.role;preparedUtc=[string]$activeValue.preparedUtc;lastWriteUtc=(Get-Item -LiteralPath $activePath).LastWriteTimeUtc.ToString('o')};$activeHash=(Get-FileHash -LiteralPath $activePath -Algorithm SHA256).Hash.ToLowerInvariant()}catch{$activeTransaction=[ordered]@{path=$activePath;error='active transaction record is unreadable'}}
        }
        $stageMarkers=@()
        foreach($stateRoot in @('C:\ProgramData\DevFleet','C:\ProgramData\M-TechLabs\DevFleet\Installer')){
            if(-not(Test-Path -LiteralPath $stateRoot -PathType Container)){continue}
            foreach($marker in @(Get-ChildItem -LiteralPath $stateRoot -Filter 'stage-*.complete' -File -ErrorAction SilentlyContinue)){
                try{$markerValue=Get-Content -LiteralPath $marker.FullName -Raw|ConvertFrom-Json;$stageMarkers+=[ordered]@{name=$marker.Name;path=$marker.FullName;transactionId=[string]$markerValue.transactionId;payloadSha256=[string]$markerValue.payloadSha256;action=[string]$markerValue.action;role=[string]$markerValue.role;stage=[string]$markerValue.stage;lastWriteUtc=$marker.LastWriteTimeUtc.ToString('o');sha256=(Get-FileHash -LiteralPath $marker.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}}catch{$stageMarkers+=[ordered]@{name=$marker.Name;path=$marker.FullName;error='stage marker is unreadable'}}
            }
        }
        $pfr=@((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations)
        $pfrPairs=@();for($i=0;$i -lt $pfr.Count;$i+=2){$src=[string]$pfr[$i];$dst=if($i+1 -lt $pfr.Count){[string]$pfr[$i+1]}else{''};if($src -or $dst){$pfrPairs+=[ordered]@{source=$src;destination=$dst}}}
        $ownedPfr=@($pfrPairs|Where-Object{[string]$_.source -match '(?i)DevFleet|M-TechLabs' -or [string]$_.destination -match '(?i)DevFleet|M-TechLabs'})
        $servicing=[ordered]@{cbsRebootPending=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending');windowsUpdateRebootRequired=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired');pendingFileRenamePairCount=$pfrPairs.Count;ownedPendingFileRenamePairs=$ownedPfr;foreignPendingFileRenamePairCount=[Math]::Max(0,$pfrPairs.Count-$ownedPfr.Count)}
        $task=$null;try{$task=Get-ScheduledTask -TaskName 'DevFleet Host Agent' -ErrorAction SilentlyContinue}catch{}
        $listener=$false;try{$listener=@(Get-NetTCPConnection -LocalPort 8790 -State Listen -ErrorAction SilentlyContinue).Count -gt 0}catch{}
        $receiptFresh=$false;if($receipt){$consumed=[datetime]::MinValue;$receiptFresh=[datetime]::TryParse([string]$receipt.consumedUtc,[ref]$consumed);if($receiptFresh -and $invocationStart){$receiptFresh=$consumed.ToUniversalTime() -ge ([datetime]$invocationStart).ToUniversalTime()}};$receiptMatch=([bool]$receipt-and$receiptFresh-and(-not $tx -or [string]$receipt.transactionId-eq$tx)-and[string]$receipt.payloadSha256-eq$payload-and[string]$receipt.action-eq$expectedAction-and[string]$receipt.role-eq$expectedRole)
        $processExited=($candidatePid -gt 0 -and -not $root)
        $terminalFailure=$false;$failure='';if($processExited-and-not$checkpoint-and-not$receiptMatch-and-not$installValid){$terminalFailure=$true;$failure='candidate process exited before a durable checkpoint or completion state'}
        $candidateCompact=&$compactProcess $root
        $markerSet=(@($stageMarkers|ForEach-Object{"$($_.name):$($_.sha256)"}|Sort-Object)-join '|')
        $servicingState=($servicing|ConvertTo-Json -Compress -Depth 8)
        $progress=[ordered]@{checkpointState=if($checkpoint){[string]$checkpoint.state}else{''};completedStages=if($checkpoint){@($checkpoint.completedStages)}else{@()};resumeStage=if($checkpoint){[string]$checkpoint.resumeStage}else{''};stages=$stages;productChildInstances=$instances;cpuSeconds=[math]::Round($cpu,3);candidateProcessPresent=[bool]$root;candidateResponsive=if($candidateCompact){[bool]$candidateCompact.responding}else{$false};activeTransactionSha256=$activeHash;stageMarkerSet=$markerSet;servicingState=$servicingState;installStateSha256=$installHash;ownershipSha256=$ownershipHash;receiptMatch=$receiptMatch;health=$healthOk;hostAgentTaskState=if($task){[string]$task.State}else{'ABSENT'};listener=$listener};if($checkpoint){$progress.checkpointGeneration=[int]$checkpoint.checkpointGeneration}
        [ordered]@{checkpointPresent=[bool]$checkpoint;checkpoint=$checkpoint;receipt=$receipt;matchingConsumedReceipt=$receiptMatch;installStateValid=$installValid;installLedger=$installLedger;installStateError=$installError;canonicalOwnershipValid=$ownershipValid;ownershipLedger=$ownershipLedger;ownershipStateError=$ownershipError;authenticatedHealthOk=$healthOk;authenticatedHealthError=$healthError;terminalFailure=$terminalFailure;failure=$failure;candidateProcessExited=$processExited;candidateProcess=$candidateCompact;processTree=$interesting;bootstrap=$bootstrap;activeTransaction=$activeTransaction;stageMarkers=$stageMarkers;servicing=$servicing;hostAgentTaskState=if($task){[string]$task.State}else{'ABSENT'};hostAgentListener=$listener;progress=$progress;progressMarker=($progress|ConvertTo-Json -Compress -Depth 20);timestampUtc=(Get-Date).ToUniversalTime().ToString('o')}
    }
    if($ObservationTimeoutSeconds -gt 0){
        $job=Invoke-Command -Session $Session -ScriptBlock $remoteScript -ArgumentList $TransactionId,$PayloadSha256,$Action,$Role,$PriorGeneration,$MaxGeneration,$CandidateProcessId,$ExpectedDevFleetVersion,$ExpectedInstallerVersion,$InvocationStartUtc -AsJob
        if(-not (Wait-Job -Job $job -Timeout $ObservationTimeoutSeconds)){Stop-Job -Job $job -ErrorAction SilentlyContinue;Remove-Job -Job $job -Force -ErrorAction SilentlyContinue;return [ordered]@{terminalFailure=$true;failure='observer remote call timeout';observerCallTimedOut=$true;timestampUtc=(Get-Date).ToUniversalTime().ToString('o');progress=[ordered]@{}}}
        try{return Receive-Job -Job $job -ErrorAction Stop}finally{Remove-Job -Job $job -Force -ErrorAction SilentlyContinue}
    }
    return Invoke-Command -Session $Session -ScriptBlock $remoteScript -ArgumentList $TransactionId,$PayloadSha256,$Action,$Role,$PriorGeneration,$MaxGeneration,$CandidateProcessId,$ExpectedDevFleetVersion,$ExpectedInstallerVersion,$InvocationStartUtc
}

function Test-ProductMeaningfulProgress {
    param([AllowNull()][psobject]$Previous,[Parameter(Mandatory)][psobject]$Current,[double]$CpuDeltaThreshold=1.0)
    if(-not $Previous){return $true}
    $found=$false;$a=Get-LifecycleProperty $Previous 'progress' ([ref]$found);$found=$false;$b=Get-LifecycleProperty $Current 'progress' ([ref]$found)
    if(-not $a -or -not $b){
        # Older/provider observations may expose only a durable marker. Treat
        # a changed marker as semantic progress, never process/PID churn.
        $found=$false;$apm=Get-LifecycleProperty $Previous 'progressMarker' ([ref]$found);$found=$false;$bpm=Get-LifecycleProperty $Current 'progressMarker' ([ref]$found);return ([string]$apm -cne [string]$bpm)
    }
    foreach($name in @('checkpointGeneration','checkpointState','resumeStage','candidateProcessPresent','candidateResponsive','activeTransactionSha256','stageMarkerSet','servicingState','installStateSha256','ownershipSha256','receiptMatch','health','hostAgentTaskState','listener')){$afound=$false;$av=Get-LifecycleProperty $a $name ([ref]$afound);$bfound=$false;$bv=Get-LifecycleProperty $b $name ([ref]$bfound);if([string]$av-cne[string]$bv){return $true}}
    $afound=$false;$ac=Get-LifecycleProperty $a 'completedStages' ([ref]$afound);if(-not $afound){$ac=@()};$bfound=$false;$bc=Get-LifecycleProperty $b 'completedStages' ([ref]$bfound);if(-not $bfound){$bc=@()};$aCompleted=($ac|ConvertTo-Json -Compress -Depth 8);$bCompleted=($bc|ConvertTo-Json -Compress -Depth 8);if($aCompleted-cne$bCompleted){return $true}
    $afound=$false;$as=Get-LifecycleProperty $a 'stages' ([ref]$afound);if(-not $afound){$as=@()};$bfound=$false;$bs=Get-LifecycleProperty $b 'stages' ([ref]$bfound);if(-not $bfound){$bs=@()};$aStages=($as|ConvertTo-Json -Compress -Depth 12);$bStages=($bs|ConvertTo-Json -Compress -Depth 12);if($aStages-cne$bStages){return $true}
    $afound=$false;$aInstances=Get-LifecycleProperty $a 'productChildInstances' ([ref]$afound);if(-not $afound){$aInstances=@()};$bfound=$false;$bInstances=Get-LifecycleProperty $b 'productChildInstances' ([ref]$bfound);if(-not $bfound){$bInstances=@()};if(($aInstances|ConvertTo-Json -Compress -Depth 12)-cne($bInstances|ConvertTo-Json -Compress -Depth 12)){return $true}
    $afound=$false;$aCpuValue=Get-LifecycleProperty $a 'cpuSeconds' ([ref]$afound);$acpu=if($afound){[double]$aCpuValue}else{0.0};$bfound=$false;$bCpuValue=Get-LifecycleProperty $b 'cpuSeconds' ([ref]$bfound);$bcpu=if($bfound){[double]$bCpuValue}else{0.0};return ($bcpu-$acpu -ge $CpuDeltaThreshold)
}

function ConvertTo-NormalizedLifecycleObservation {
    <# Providers and remote calls are untrusted boundaries.  Always return a
       complete shape so strict mode cannot turn a timeout or stale provider
       payload into an unrecorded exception. #>
    param([AllowNull()][object]$Observation,[string]$Failure='')
    $now=(Get-Date).ToUniversalTime().ToString('o')
    $progress=[ordered]@{checkpointState='';completedStages=@();resumeStage='';stages=@();productChildInstances=@();cpuSeconds=0.0;candidateProcessPresent=$false;candidateResponsive=$false;activeTransactionSha256=$null;stageMarkerSet='';servicingState='';installStateSha256=$null;ownershipSha256=$null;receiptMatch=$false;health=$false;hostAgentTaskState='';listener=$false}
    $normalized=[ordered]@{status='';checkpointPresent=$false;checkpoint=$null;matchingConsumedReceipt=$false;installStateValid=$false;installLedger=$null;installStateError='';canonicalOwnershipValid=$false;ownershipLedger=$null;ownershipStateError='';authenticatedHealthOk=$false;authenticatedHealthError='';terminalFailure=$false;failure='';error='';terminalReason='';observerCallTimedOut=$false;observerCallFailed=$false;candidateProcessExited=$false;candidateProcess=$null;processTree=@();bootstrap=@();activeTransaction=$null;stageMarkers=@();servicing=$null;hostAgentTaskState='ABSENT';hostAgentListener=$false;progress=$progress;progressMarker='';rawActiveLifecycleSignals=@();rawActiveLifecycleSignalCount=0;timestampUtc=$now}
    if($Observation -is [array]){if($Observation.Count -eq 1){$Observation=$Observation[0]}else{$Failure=if($Failure){$Failure}else{'observation provider returned an ambiguous result set'}}}
    # Force array context around the conditional itself. PowerShell otherwise
    # unwraps a one-item result, which breaks strict-mode evidence handling.
    $rawSignals=@(if($Observation){Get-RawActiveLifecycleSignals -Value $Observation}else{@()});$normalized.rawActiveLifecycleSignals=$rawSignals;$normalized.rawActiveLifecycleSignalCount=$rawSignals.Count
    if($Observation){if($Observation -is [System.Collections.IDictionary]){foreach($key in $Observation.Keys){if($normalized.Contains([string]$key)){$normalized[[string]$key]=$Observation[$key]}}}else{foreach($property in $Observation.PSObject.Properties){if($normalized.Contains($property.Name)){$normalized[$property.Name]=$property.Value}}}}elseif(-not $Failure){$Failure='observation provider returned no result'}
    if($Failure){$normalized.terminalFailure=$true;$normalized.status='TERMINAL_FAILURE';$normalized.failure=$Failure;$normalized.error=$Failure;$normalized.terminalReason=$Failure}
    $explicitFailure=[string]$normalized.failure
    $explicitTerminalClaim=([bool]$normalized.terminalFailure -or -not [string]::IsNullOrWhiteSpace($explicitFailure) -or -not [string]::IsNullOrWhiteSpace([string]$normalized.error) -or [string]$normalized.status -match '^(?i:TERMINAL_FAILURE|TERMINAL|ERROR)$')
    $unsafeSignal=$rawSignals|Where-Object{($_.kind -eq 'generation' -and [string]$_.path -notmatch '^checkpoint\.') -or ($_.kind -eq 'checkpointgeneration' -and -not (Test-BenignLifecycleCheckpointGenerationSignal $_) -and [string]$_.path -notmatch '^(progress|checkpoint)\.') -or ($_.kind -eq 'checkpoint' -and [string]$_.path -notmatch '^checkpoint$') -or [string]$_.path -match '(^|\.)observation\.' -or ($_.kind -eq 'waiting-for-reboot' -and [string]$_.path -notmatch '^checkpoint\.state$') -or $_.kind -in @('depth-cutoff','cycle') -or ((-not $explicitTerminalClaim) -and $_.kind -in @('terminalFailure','failure','error','terminalReason','terminal-status'))}|Select-Object -First 1
    if($unsafeSignal){$normalized.terminalFailure=$true;$normalized.status='TERMINAL_FAILURE';if([string]::IsNullOrWhiteSpace($explicitFailure)){$normalized.failure="unsafe lifecycle signal at $([string]$unsafeSignal.path)"};$normalized.error=$normalized.failure;$normalized.terminalReason=$normalized.failure}
    if([string]::IsNullOrWhiteSpace([string]$normalized.timestampUtc)){$normalized.timestampUtc=$now}
    if(-not $normalized.progress){$normalized.progress=$progress}
    foreach($property in $progress.Keys){if(-not (Test-LifecycleProperty -Value $normalized.progress -Name $property)){if($normalized.progress -is [System.Collections.IDictionary]){$normalized.progress[$property]=$progress[$property]}else{$normalized.progress|Add-Member -NotePropertyName $property -NotePropertyValue $progress[$property]}}}
    $actualCheckpointPresent=($null -ne $normalized.checkpoint);$flaggedCheckpointPresent=[bool]$normalized.checkpointPresent
    if($flaggedCheckpointPresent -ne $actualCheckpointPresent){$normalized.terminalFailure=$true;$normalized.failure='checkpoint presence flag disagrees with checkpoint object';$normalized.error=$normalized.failure}
    $normalized.checkpointPresent=$actualCheckpointPresent
    if($actualCheckpointPresent){
        if(-not $normalized.checkpoint){$normalized.terminalFailure=$true;$normalized.failure='checkpointPresent was asserted without a checkpoint payload';$normalized.error=$normalized.failure}
        else {$canonicalCheckpoint=ConvertTo-CanonicalLifecycleCheckpoint $normalized.checkpoint;if(-not $canonicalCheckpoint){$normalized.terminalFailure=$true;$normalized.failure='checkpoint generation is missing, malformed, or inconsistent';$normalized.error=$normalized.failure}else{$normalized.checkpoint=$canonicalCheckpoint}}
    }
    if([bool]$normalized.terminalFailure){if([string]::IsNullOrWhiteSpace([string]$normalized.failure)){$normalized.failure='normalized lifecycle observation reported terminal failure'};$normalized.status='TERMINAL_FAILURE';if([string]::IsNullOrWhiteSpace([string]$normalized.error)){$normalized.error=$normalized.failure};if([string]::IsNullOrWhiteSpace([string]$normalized.terminalReason)){$normalized.terminalReason=$normalized.failure}}
    if([string]::IsNullOrWhiteSpace([string]$normalized.progressMarker)){$normalized.progressMarker=($normalized.progress|ConvertTo-Json -Compress -Depth 16)}
    return [pscustomobject]$normalized
}

function Wait-DevFleetProductLifecycleTransition {
    <#
      One bounded observer for the product-owned durable lifecycle.  It never
      writes a checkpoint and never treats a merely existing process/file as
      progress.  The caller owns the reboot operation after NEXT_REBOOT.
    #>
    param(
        [Parameter(Mandatory)][object]$Session,
        [Parameter(Mandatory)][AllowEmptyString()][string]$TransactionId,
        [Parameter(Mandatory)][string]$PayloadSha256,
        [Parameter(Mandatory)][string]$Role,
        [string]$Action = 'FreshInstall',
        [int]$PriorGeneration = 0,
        [int]$MaxGeneration = 3,
        [int]$BudgetSeconds = 1800,
        [int]$PollSeconds = 5,
        [int]$CandidateProcessId = 0,
        [string]$EvidencePath,
        [scriptblock]$ObservationProvider,
        [scriptblock]$ClockProvider,
        [scriptblock]$SleepProvider,
        [double]$CpuDeltaThreshold=1.0,
        [int]$NoProgressBudgetSeconds=0,
        [int]$AbsoluteBudgetSeconds=0,
        [string]$ExpectedDevFleetVersion,
        [string]$ExpectedInstallerVersion,
        [int]$ObservationTimeoutSeconds=0,
        [string]$InvocationStartUtc,
        [object]$ObservationProviderContext,
        [scriptblock]$SessionProvider
    )
    if($BudgetSeconds -le 0){throw 'Lifecycle budget must be finite and positive.'}
    if([string]::IsNullOrWhiteSpace($ExpectedDevFleetVersion)-or$ExpectedDevFleetVersion -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$'){throw 'TERMINAL_FAILURE: expected DevFleet version is missing or malformed.'}
    if([string]::IsNullOrWhiteSpace($ExpectedInstallerVersion)-or$ExpectedInstallerVersion -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$'){throw 'TERMINAL_FAILURE: expected installer version is missing or malformed.'}
    $noProgressBudget=if($NoProgressBudgetSeconds -gt 0){[int]$NoProgressBudgetSeconds}else{[int]$BudgetSeconds}
    $absoluteBudget=if($AbsoluteBudgetSeconds -gt 0){[int]$AbsoluteBudgetSeconds}else{[int]$BudgetSeconds}
    if($noProgressBudget -le 0 -or $absoluteBudget -le 0){throw 'Lifecycle no-progress and absolute budgets must be finite and positive.'}
    $NoProgressBudgetSeconds=$noProgressBudget;$AbsoluteBudgetSeconds=$absoluteBudget
    if($ObservationTimeoutSeconds -le 0){$ObservationTimeoutSeconds=[Math]::Min([Math]::Max($PollSeconds+2,5),60)}else{$ObservationTimeoutSeconds=[Math]::Min([Math]::Max($ObservationTimeoutSeconds,2),60)}
    $now={if($ClockProvider){&$ClockProvider}else{Get-Date}}
    $sleep={param($seconds)if($SleepProvider){&$SleepProvider $seconds}else{Start-Sleep -Seconds $seconds}}
    $start=&$now;if(-not $InvocationStartUtc){$InvocationStartUtc=$start.ToUniversalTime().ToString('o')};$absoluteDeadline=$start.AddSeconds($AbsoluteBudgetSeconds);$noProgressDeadline=$start.AddSeconds($NoProgressBudgetSeconds)
    $lastProgressAt=$start;$previous=$null
    $lastObserved = $null;$providerIndex=0
    $progressSamples = [System.Collections.Generic.List[object]]::new()
    # A Hyper-V/PowerShell transport can terminate independently of the
    # product transaction.  Recover only this narrowly identified transport
    # class, with a finite retry count and a delay charged to both immutable
    # deadlines.  Semantic product failures and arbitrary provider errors
    # remain fail-closed on the first observation.
    $transportRecoveryAttempts = [System.Collections.Generic.List[object]]::new()
    $transportRecoveryLimit = 3
    $transportRecoveryDelaySeconds = 5
    $isRecoverableTransportError = {
        param([string]$Message)
        return $Message -match '(?i)Hyper-V socket target process has ended|background process reported an error with the following message'
    }
    # WinRM sessions can become broken during a legitimately long product
    # transaction.  A broken observer transport is not a product result and
    # must not terminate the lifecycle while the candidate is still within its
    # immutable absolute deadline.  The caller may provide an authenticated,
    # exact-VM session factory; those short-lived sessions are disposed after
    # each observation so a stale transport cannot poison the whole lifecycle.
    $observeSession = $Session
    $getRemoteObservation = {
        $sessionForObservation = $observeSession
        $created = $false
        try {
            if ($SessionProvider) { $sessionForObservation = & $SessionProvider; $created = $true }
            return Get-ProductLifecycleObservation -Session $sessionForObservation -TransactionId $TransactionId -PayloadSha256 $PayloadSha256 -Action $Action -Role $Role -PriorGeneration $PriorGeneration -MaxGeneration $MaxGeneration -CandidateProcessId $CandidateProcessId -ExpectedDevFleetVersion $ExpectedDevFleetVersion -ExpectedInstallerVersion $ExpectedInstallerVersion -ObservationTimeoutSeconds $ObservationTimeoutSeconds -InvocationStartUtc $InvocationStartUtc
        } finally {
            if ($created -and $sessionForObservation) { Remove-PSSession $sessionForObservation -ErrorAction SilentlyContinue }
        }
    }
    $journalPath=if($EvidencePath){Join-Path (Split-Path -Parent $EvidencePath) 'product-lifecycle-progress.jsonl'}else{$null}
    $currentPath=if($EvidencePath){Join-Path (Split-Path -Parent $EvidencePath) 'product-lifecycle-progress-current.json'}else{$null}
    if($journalPath){
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $journalPath)|Out-Null
        $initialEntry=[ordered]@{event='START';startUtc=$start.ToUniversalTime().ToString('o');lastMeaningfulProgressUtc=$start.ToUniversalTime().ToString('o');noMeaningfulProgressDeadlineUtc=$noProgressDeadline.ToUniversalTime().ToString('o');absoluteLifecycleDeadlineUtc=$absoluteDeadline.ToUniversalTime().ToString('o');requestedBudgetSeconds=[int]$BudgetSeconds;effectiveNoProgressBudgetSeconds=[int]$NoProgressBudgetSeconds;effectiveAbsoluteBudgetSeconds=[int]$AbsoluteBudgetSeconds;candidateProcessId=$CandidateProcessId;transactionId=$TransactionId;payloadSha256=$PayloadSha256;action=$Action;role=$Role;observationTimeoutSeconds=$ObservationTimeoutSeconds}
        Add-Content -LiteralPath $journalPath -Value (($initialEntry|ConvertTo-Json -Compress -Depth 12)) -Encoding UTF8;Write-EvidenceJson -Path $currentPath -Value $initialEntry
    }
    $writeSample={param($sample,$event)
        $entry=[ordered]@{event=$event;observedUtc=[string]$sample.timestampUtc;startUtc=$start.ToUniversalTime().ToString('o');lastMeaningfulProgressUtc=$lastProgressAt.ToUniversalTime().ToString('o');noMeaningfulProgressDeadlineUtc=$noProgressDeadline.ToUniversalTime().ToString('o');absoluteLifecycleDeadlineUtc=$absoluteDeadline.ToUniversalTime().ToString('o');requestedBudgetSeconds=[int]$BudgetSeconds;effectiveNoProgressBudgetSeconds=[int]$NoProgressBudgetSeconds;effectiveAbsoluteBudgetSeconds=[int]$AbsoluteBudgetSeconds;candidateProcessId=$CandidateProcessId;transactionId=$TransactionId;payloadSha256=$PayloadSha256;action=$Action;role=$Role;observation=$sample}
        if($journalPath){New-Item -ItemType Directory -Force -Path (Split-Path -Parent $journalPath)|Out-Null;Add-Content -LiteralPath $journalPath -Value (($entry|ConvertTo-Json -Compress -Depth 24)) -Encoding UTF8
            # Keep interruption evidence bounded while retaining the most
            # recent semantic transitions and heartbeats.
            $journalLines=@(Get-Content -LiteralPath $journalPath -ErrorAction SilentlyContinue);if($journalLines.Count -gt 512){@($journalLines[0])+@($journalLines | Select-Object -Last 511) | Set-Content -LiteralPath $journalPath -Encoding UTF8}
            Write-EvidenceJson -Path $currentPath -Value $entry}
    }
    function Complete-ObserverResult([object]$Result) {
        $Result.progressSamples=@($progressSamples);$Result.progressSampleCount=$progressSamples.Count
        $Result.requestedBudgetSeconds=[int]$BudgetSeconds;$Result.effectiveNoProgressBudgetSeconds=[int]$NoProgressBudgetSeconds;$Result.effectiveAbsoluteBudgetSeconds=[int]$AbsoluteBudgetSeconds;$Result.budgetSeconds=[int]$NoProgressBudgetSeconds
        $Result.transportRecoveryAttempts=@($transportRecoveryAttempts)
        $Result.startUtc=$start.ToUniversalTime().ToString('o');$Result.lastMeaningfulProgressUtc=$lastProgressAt.ToUniversalTime().ToString('o');$Result.noMeaningfulProgressDeadlineUtc=$noProgressDeadline.ToUniversalTime().ToString('o');$Result.absoluteLifecycleDeadlineUtc=$absoluteDeadline.ToUniversalTime().ToString('o')
        if($EvidencePath){
            # The terminal record is journaled after the final observation so
            # an interrupted/failed provider leaves one unambiguous last event
            # in addition to the terminal result and current snapshot.
            $resultReasonFound=$false;$resultReason=Get-LifecycleProperty $Result 'terminalReason' ([ref]$resultReasonFound);$terminalEntry=[ordered]@{event='TERMINAL';terminalReason=[string]$Result.outcome;terminalDetail=[string]$resultReason;startUtc=$Result.startUtc;lastMeaningfulProgressUtc=$lastProgressAt.ToUniversalTime().ToString('o');noMeaningfulProgressDeadlineUtc=$noProgressDeadline.ToUniversalTime().ToString('o');absoluteLifecycleDeadlineUtc=$absoluteDeadline.ToUniversalTime().ToString('o');requestedBudgetSeconds=$Result.requestedBudgetSeconds;effectiveNoProgressBudgetSeconds=$Result.effectiveNoProgressBudgetSeconds;effectiveAbsoluteBudgetSeconds=$Result.effectiveAbsoluteBudgetSeconds;transactionId=$TransactionId;payloadSha256=$PayloadSha256;action=$Action;role=$Role}
            if($journalPath){Add-Content -LiteralPath $journalPath -Value (($terminalEntry|ConvertTo-Json -Compress -Depth 24)) -Encoding UTF8;$journalLines=@(Get-Content -LiteralPath $journalPath -ErrorAction SilentlyContinue);if($journalLines.Count -gt 512){@($journalLines[0])+@($journalLines | Select-Object -Last 511) | Set-Content -LiteralPath $journalPath -Encoding UTF8}}
            Write-EvidenceJson -Path $EvidencePath -Value $Result; if($currentPath){Write-EvidenceJson -Path $currentPath -Value $terminalEntry}
        }
        return $Result
    }
    do {
        if((&$now) -ge $absoluteDeadline){return Complete-ObserverResult ([ordered]@{outcome='ABSOLUTE_TIMEOUT';terminalReason='absolute deadline reached before next observation';observation=$lastObserved})}
        $observation=$null;$transportFailure='';$recovered=$false
        for($transportAttempt=0;$transportAttempt -le $transportRecoveryLimit;$transportAttempt++){
            $transportFailure='';$observation=$null
            try {
                if($ObservationProvider){
                    if(-not (Get-Command Start-ThreadJob -ErrorAction SilentlyContinue)){throw 'no bounded ObservationProvider execution primitive is available'}
                    $providerState=[pscustomobject]@{transactionId=$TransactionId;payloadSha256=$PayloadSha256;action=$Action;role=$Role;priorGeneration=$PriorGeneration;maxGeneration=$MaxGeneration;candidateProcessId=$CandidateProcessId;invocationStartUtc=$InvocationStartUtc;observationIndex=$providerIndex;providerContext=$ObservationProviderContext}
                    $providerIndex++
                    $providerJob=Start-ThreadJob -ScriptBlock {param($provider,$state)&$provider $state} -ArgumentList $ObservationProvider,$providerState
                    if(-not (Wait-Job -Job $providerJob -Timeout $ObservationTimeoutSeconds)){
                        Stop-Job -Job $providerJob -ErrorAction SilentlyContinue;Wait-Job -Job $providerJob -Timeout 2 -ErrorAction SilentlyContinue|Out-Null;Remove-Job -Job $providerJob -Force -ErrorAction SilentlyContinue
                        $observation=ConvertTo-NormalizedLifecycleObservation $null 'observer provider timeout';$observation|Add-Member -NotePropertyName observerCallTimedOut -NotePropertyValue $true -Force
                    }else{
                        try{$observation=Receive-Job -Job $providerJob -ErrorAction Stop}catch{$transportFailure=$_.Exception.Message}finally{Remove-Job -Job $providerJob -Force -ErrorAction SilentlyContinue}
                    }
                }else{$observation=&$getRemoteObservation}
            }catch{$transportFailure=$_.Exception.Message}
            $providerFailedFound=$false;$providerFailed=if($observation){Get-LifecycleProperty $observation 'observerCallFailed' ([ref]$providerFailedFound)}else{$null}
            if(-not $transportFailure -and $observation -and $providerFailedFound -and [bool]$providerFailed){$failureFound=$false;$transportFailure=[string](Get-LifecycleProperty $observation 'failure' ([ref]$failureFound));if([string]::IsNullOrWhiteSpace($transportFailure)){$errorFound=$false;$transportFailure=[string](Get-LifecycleProperty $observation 'error' ([ref]$errorFound))}}
            if(-not $transportFailure){$recovered=$true;break}
            if(-not (&$isRecoverableTransportError $transportFailure) -or $transportAttempt -ge $transportRecoveryLimit){break}
            $recoveryNow=&$now;$remainingAbsolute=($absoluteDeadline-$recoveryNow).TotalSeconds;$remainingNoProgress=($noProgressDeadline-$recoveryNow).TotalSeconds;$remainingRecovery=[math]::Min($remainingAbsolute,$remainingNoProgress)
            if($remainingRecovery -le 0){break}
            $delay=[int][math]::Min($transportRecoveryDelaySeconds,[math]::Floor($remainingRecovery));if($delay -le 0){break}
            [void]$transportRecoveryAttempts.Add([ordered]@{attempt=$transportAttempt+1;error=$transportFailure;delaySeconds=$delay;observedUtc=$recoveryNow.ToUniversalTime().ToString('o')})
            &$sleep $delay
        }
        if($transportFailure -and -not $recovered){$observation=ConvertTo-NormalizedLifecycleObservation $null ('observer call failed: '+$transportFailure);$observation|Add-Member -NotePropertyName observerCallFailed -NotePropertyValue $true -Force}
        $observation=ConvertTo-NormalizedLifecycleObservation $observation
        # A provider may return just as the immutable lifecycle deadline is
        # reached. Do not accept its semantic progress or terminal decision;
        # preserve the observation and fail closed as ABSOLUTE_TIMEOUT.
        if((&$now) -ge $absoluteDeadline){return Complete-ObserverResult ([ordered]@{outcome='ABSOLUTE_TIMEOUT';terminalReason='absolute deadline reached after observation';observation=$observation})}
        $lastObserved=$observation
        [void]$progressSamples.Add($observation)
        if($progressSamples.Count -gt 512){$progressSamples.RemoveAt(0)}
        $checkpoint=$observation.checkpoint
        # The transaction identifier is deliberately unknown before the first
        # product-owned checkpoint (or consumed receipt) exists.  Adopt it
        # only from an observation that is already bound to the exact payload,
        # action, role, invocation time, and bounded generation.  This lets the
        # full progress observer run from generation zero instead of waiting
        # blindly for a checkpoint while the real installer child executes.
        if($PriorGeneration -eq 0 -and [string]::IsNullOrWhiteSpace($TransactionId)){
            $observedTransaction=''
            if($checkpoint){
                $checkpointTxFound=$false;$checkpointTx=Get-LifecycleProperty $checkpoint 'transactionId' ([ref]$checkpointTxFound)
                $checkpointPayloadFound=$false;$checkpointPayload=Get-LifecycleProperty $checkpoint 'payloadSha256' ([ref]$checkpointPayloadFound)
                $checkpointActionFound=$false;$checkpointAction=Get-LifecycleProperty $checkpoint 'action' ([ref]$checkpointActionFound)
                $checkpointRoleFound=$false;$checkpointRole=Get-LifecycleProperty $checkpoint 'role' ([ref]$checkpointRoleFound)
                if($checkpointTxFound -and $checkpointPayloadFound -and $checkpointActionFound -and $checkpointRoleFound -and
                    [string]$checkpointPayload -ceq $PayloadSha256 -and [string]$checkpointAction -ceq $Action -and [string]$checkpointRole -ceq $Role){
                    $observedTransaction=[string]$checkpointTx
                }
            }elseif($observation.matchingConsumedReceipt -and $observation.receipt){
                $receiptTxFound=$false;$receiptTx=Get-LifecycleProperty $observation.receipt 'transactionId' ([ref]$receiptTxFound)
                if($receiptTxFound){$observedTransaction=[string]$receiptTx}
            }
            if($observedTransaction){
                if($observedTransaction -notmatch '^[0-9a-fA-F]{32}$'){
                    $observation.terminalFailure=$true;$observation.failure='observed lifecycle transaction identity is malformed';$observation.error=$observation.failure
                }else{$TransactionId=$observedTransaction}
            }
        }
        $prior = [pscustomobject]@{checkpointGeneration=$PriorGeneration;transactionId=$TransactionId;payloadSha256=$PayloadSha256;action=$Action;role=$Role;state='waiting-for-reboot'}
        $observationTerminalFound=$false;$observationTerminal=Get-LifecycleProperty $observation 'terminalFailure' ([ref]$observationTerminalFound);$classification=if($observationTerminalFound -and [bool]$observationTerminal){'TERMINAL_FAILURE'}else{Get-DurableProgressClassification -Observation $observation -PriorCheckpoint $prior -MaxGeneration $MaxGeneration}
        if(Test-ProductMeaningfulProgress -Previous $previous -Current $observation -CpuDeltaThreshold $CpuDeltaThreshold){$lastProgressAt=&$now;$noProgressDeadline=$lastProgressAt.AddSeconds($NoProgressBudgetSeconds);$event='MEANINGFUL_PROGRESS'}else{$event='HEARTBEAT'}
        &$writeSample $observation $event;$previous=$observation
        if($classification -eq 'COMPLETED'){$completionReason='';if(-not (Test-LifecycleCompletionInput -Value $observation -Reason ([ref]$completionReason))){$classification='TERMINAL_FAILURE';$observation.terminalFailure=$true;$observation.failure="COMPLETED observation rejected: $completionReason";$observation.error=$observation.failure;$observation.terminalReason=$observation.failure;$observation.status='TERMINAL_FAILURE'}}
        if($classification -eq 'TERMINAL_FAILURE'){ return Complete-ObserverResult ([ordered]@{outcome='TERMINAL_FAILURE';observation=$observation;terminalReason=$observation.failure}) }
        if($classification -eq 'NEXT_REBOOT'){ return Complete-ObserverResult ([ordered]@{outcome='NEXT_REBOOT';checkpointPresent=$true;observation=$observation;checkpoint=$checkpoint}) }
        if($classification -eq 'COMPLETED'){ return Complete-ObserverResult ([ordered]@{outcome='COMPLETED';observation=$observation}) }
        &$sleep $PollSeconds
    } while((&$now) -lt $noProgressDeadline -and (&$now) -lt $absoluteDeadline)
    # Machine-readable terminal vocabulary: outcome='NO_PROGRESS_TIMEOUT' or
    # outcome='ABSOLUTE_TIMEOUT' (the proof runner's outer outcome is
    # outcome='HARNESS_WATCHDOG_EXPIRED').
    $terminal=if((&$now) -ge $absoluteDeadline){'ABSOLUTE_TIMEOUT'}else{'NO_PROGRESS_TIMEOUT'} # outcome='ABSOLUTE_TIMEOUT'
    $result=[ordered]@{outcome=$terminal;observation=$lastObserved;requestedBudgetSeconds=[int]$BudgetSeconds;effectiveNoProgressBudgetSeconds=[int]$NoProgressBudgetSeconds;effectiveAbsoluteBudgetSeconds=[int]$AbsoluteBudgetSeconds;budgetSeconds=[int]$NoProgressBudgetSeconds;progressSamples=@($progressSamples);progressSampleCount=$progressSamples.Count;terminalReason=$terminal}
    return Complete-ObserverResult $result
}

function Get-PhaseAwareBudgetSeconds {
    param([psobject]$Context,[int]$DefaultSeconds = 0)
    $configFound=$false;$config=Get-LifecycleProperty $Context 'config' ([ref]$configFound)
    $policy=Get-HarnessBudgetPolicy -Config $(if($configFound){$config}else{$null})
    $roleFound=$false;$role=Get-LifecycleProperty $Context 'role' ([ref]$roleFound)
    if(-not $roleFound){$role='Primary / Desktop'}
    if([string]$role -match '(?i)Laptop'){return [int]$policy.transactionBudgetsSeconds.Laptop}
    return [int]$policy.transactionBudgetsSeconds.Desktop
}

function ConvertTo-ProductServicingSample {
    param([AllowNull()][object]$Sample)
    if($null -eq $Sample){return $null}
    $values=[ordered]@{}
    foreach($name in @('cbs','windowsUpdate','pendingCount')){
        $found=$false;$value=Get-LifecycleProperty -Value $Sample -Name $name -Found ([ref]$found)
        if(-not $found){return $null}
        $values[$name]=$value
    }
    $pendingCount=0
    if(-not [int]::TryParse([string]$values.pendingCount,[ref]$pendingCount) -or $pendingCount -lt 0){return $null}
    return [pscustomobject][ordered]@{cbs=[bool]$values.cbs;windowsUpdate=[bool]$values.windowsUpdate;pendingCount=$pendingCount}
}

function Test-ProductServicingSamplesMatch {
    param([AllowNull()][object]$First,[AllowNull()][object]$Second)
    $left=ConvertTo-ProductServicingSample $First
    $right=ConvertTo-ProductServicingSample $Second
    if($null -eq $left -or $null -eq $right){return $false}
    return ($left.cbs -eq $right.cbs -and $left.windowsUpdate -eq $right.windowsUpdate -and $left.pendingCount -eq $right.pendingCount)
}

function Get-ExactProductCheckpoint {
    param([Parameter(Mandatory)][guid]$VmId,[string]$TransactionId,[Parameter(Mandatory)][string]$PayloadSha256,[Parameter(Mandatory)][string]$Action,[Parameter(Mandatory)][string]$Role,[int]$MinimumGeneration=1,[int]$MaxGeneration=3,[string]$InvocationStartUtc)
    $session=$null
    try {
        $session=Connect-DevFleetGuest -VmId $VmId
        return Invoke-Command -Session $session -ScriptBlock {
            param($tx,$payload,$expectedAction,$expectedRole,$min,$max,$invocationStart)
            $path='C:\ProgramData\M-TechLabs\DevFleet\Installer\resume-checkpoint.json'
            if(-not(Test-Path -LiteralPath $path -PathType Leaf)){return $null}
            $value=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
            if($invocationStart){$created=[datetime]::MinValue;if(-not [datetime]::TryParse([string]$value.createdUtc,[ref]$created)){throw 'Product checkpoint lacks createdUtc provenance.'};if($created.ToUniversalTime() -lt ([datetime]$invocationStart).ToUniversalTime()){throw 'Product checkpoint predates this lifecycle invocation.'}}
            if($tx -and [string]$value.transactionId -cne [string]$tx){throw 'Product checkpoint binding mismatch: transactionId.'}
            foreach($pair in @(@('payloadSha256',$payload),@('action',$expectedAction),@('role',$expectedRole))){if([string]$value.($pair[0]) -cne [string]$pair[1]){throw "Product checkpoint binding mismatch: $($pair[0])."}}
            $generation=[int]$value.checkpointGeneration
            if([string]$value.state -ne 'waiting-for-reboot' -or $generation -lt $min -or $generation -gt $max){throw 'Product checkpoint is not an exact bounded waiting-for-reboot boundary.'}
            [ordered]@{path=$path;transactionId=[string]$value.transactionId;payloadSha256=[string]$value.payloadSha256;action=[string]$value.action;role=[string]$value.role;state=[string]$value.state;generation=$generation;checkpointGeneration=$generation;completedStages=@($value.completedStages);resumeStage=[string]$value.resumeStage;lastWriteUtc=(Get-Item -LiteralPath $path).LastWriteTimeUtc.ToString('o')}
        } -ArgumentList $TransactionId,$PayloadSha256,$Action,$Role,$MinimumGeneration,$MaxGeneration,$InvocationStartUtc
    }finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
}

function Invoke-ProductRebootBoundary {
    param([Parameter(Mandatory)][psobject]$Context,[Parameter(Mandatory)][psobject]$Checkpoint,[Parameter(Mandatory)][int]$PriorGeneration)
    if([int]$Checkpoint.generation -ne ($PriorGeneration+1)){throw 'Product reboot boundary did not advance exactly one generation.'}
    # Product truth authorizes this boundary; the harness may only automate the
    # existing exact disposable L1 and only once for this generation.
    $arm=$null;$disarm=$null
    try {
        $arm=Arm-DevFleetE2EInteractiveLogon -VmId ([guid][string]$Context.vmId)
        $restart=Restart-DevFleetE2EL1 -ArmState $arm
        $desktop=Wait-DevFleetE2EInteractiveDesktop -VmId ([guid][string]$Context.vmId) -TimeoutSeconds 300
        $disarm=Disarm-DevFleetE2EInteractiveLogon -ArmState $arm
        $survival=Assert-DevFleetE2EInteractiveDesktopAfterDisarm -VmId ([guid][string]$Context.vmId)
    } finally {
        if($arm -and -not $disarm){try{Disarm-DevFleetE2EInteractiveLogon -ArmState $arm|Out-Null}catch{}}
    }
    $post=[ordered]@{computer=$desktop.desktop.computer;boot=[string]$desktop.boot;sessionId=[int]$desktop.desktop.sessionId;explorerPid=[int]$desktop.desktop.explorerPid}
    $bootChanged=$false
    try{$bootChanged=([datetime]$post.boot -gt [datetime]$arm.preBoot)}catch{throw 'Product reboot boundary did not return comparable pre/post boot identities.'}
    if(-not $bootChanged){throw 'Product reboot boundary did not prove a changed boot identity.'}
    # Servicing is observed and allowed to settle, but it is never a product
    # generation or authorization to reboot. Require two identical samples.
    $settleSession=$null;$servicingSettlement=$null;$servicingStable=$false;$servicingDeadline=(Get-Date).AddMinutes(3)
    do {
        try {
            $settleSession=Connect-DevFleetGuest -VmId ([guid][string]$Context.vmId)
            $first=ConvertTo-ProductServicingSample (Invoke-Command -Session $settleSession -ScriptBlock {$pfr=@((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations);$m=@($pfr|Where-Object{-not [string]::IsNullOrWhiteSpace([string]$_)});[ordered]@{cbs=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending');windowsUpdate=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired');pendingCount=$m.Count}})
            Remove-PSSession $settleSession -ErrorAction SilentlyContinue;$settleSession=$null
            Start-Sleep -Seconds 3
            $settleSession=Connect-DevFleetGuest -VmId ([guid][string]$Context.vmId)
            $second=ConvertTo-ProductServicingSample (Invoke-Command -Session $settleSession -ScriptBlock {$pfr=@((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations);$m=@($pfr|Where-Object{-not [string]::IsNullOrWhiteSpace([string]$_)});[ordered]@{cbs=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending');windowsUpdate=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired');pendingCount=$m.Count}})
            $servicingStable=Test-ProductServicingSamplesMatch -First $first -Second $second
            $servicingSettlement=[ordered]@{first=$first;second=$second;stable=$servicingStable;observedUtc=(Get-Date).ToUniversalTime().ToString('o')}
        } catch {$servicingSettlement=[ordered]@{stable=$false;error='servicing observation failed'}} finally {if($settleSession){Remove-PSSession $settleSession -ErrorAction SilentlyContinue}}
        if(-not $servicingStable){Start-Sleep -Seconds 3}
    }while(-not $servicingStable -and (Get-Date)-lt $servicingDeadline)
    if(-not $servicingStable){throw 'Product reboot servicing state did not reach a stable settlement observation before the bounded deadline.'}
    return [ordered]@{checkpoint=$Checkpoint;priorGeneration=$PriorGeneration;postGeneration=[int]$Checkpoint.generation;preBoot=[ordered]@{boot=[string]$arm.preBoot};postBoot=$post;bootIdentityChanged=$bootChanged;servicingSettlement=$servicingSettlement;interactiveDesktop=[ordered]@{status='PASS';desktop=$desktop.desktop;disarm=$disarm;survivesDisarm=$survival}}
}
function New-ProductLifecycleCompletionAuthority {
    param([Parameter(Mandatory)][psobject]$Context,[Parameter(Mandatory)][psobject]$Candidate,[Parameter(Mandatory)][string]$Role,[Parameter(Mandatory)][string]$TransactionId,[Parameter(Mandatory)][string]$PayloadSha256,[Parameter(Mandatory)][psobject]$Observation,[object[]]$Legs)
    $reason='';if(-not (Test-LifecycleCompletionInput -Value $Observation -Reason ([ref]$reason))){throw "TERMINAL_FAILURE: completion authority observation rejected: $reason"};if(-not (Test-LifecycleCompletionInput -Value $Legs -Reason ([ref]$reason))){throw "TERMINAL_FAILURE: completion authority lifecycle legs rejected: $reason"}
    $found=$false;$install=Get-LifecycleProperty $Observation 'installStateValid' ([ref]$found);$installOk=($found -and [bool]$install);$found=$false;$ownership=Get-LifecycleProperty $Observation 'canonicalOwnershipValid' ([ref]$found);$ownershipOk=($found -and [bool]$ownership);$found=$false;$health=Get-LifecycleProperty $Observation 'authenticatedHealthOk' ([ref]$found);$healthOk=($found -and [bool]$health);$found=$false;$receipt=Get-LifecycleProperty $Observation 'matchingConsumedReceipt' ([ref]$found);$receiptOk=($found -and [bool]$receipt);if(-not $installOk -or -not $ownershipOk -or -not $healthOk -or -not $receiptOk){throw 'TERMINAL_FAILURE: completion authority lacks exact receipt, installer ledger, ownership, or authenticated health evidence.'}
    $found=$false;$installLedger=Get-LifecycleProperty $Observation 'installLedger' ([ref]$found);if(-not $found -or $null -eq $installLedger){throw 'TERMINAL_FAILURE: completion authority is missing the installer ledger.'};foreach($required in @('DevFleetVersion','InstallerVersion','PackageSha256','InstallationGeneration','WindowsIntegrationOwnershipPath')){if(-not (Test-LifecycleProperty -Value $installLedger -Name $required)){throw "TERMINAL_FAILURE: installer ledger lacks required property $required."}}
    $found=$false;$ownershipLedger=Get-LifecycleProperty $Observation 'ownershipLedger' ([ref]$found);if(-not $found -or $null -eq $ownershipLedger){throw 'TERMINAL_FAILURE: completion authority is missing the ownership ledger.'};foreach($required in @('SchemaVersion','InstallationGeneration','ScheduledTasks','FirewallRules','Services')){if(-not (Test-LifecycleProperty -Value $ownershipLedger -Name $required)){throw "TERMINAL_FAILURE: ownership ledger lacks required property $required."}}
    $guest=[ordered]@{role=$Role;action='FreshInstall';completionVerified=$true;mutationInvoked=$true;transactionId=$TransactionId;payloadSha256=$PayloadSha256;installState=$installLedger;ownership=$ownershipLedger;authenticatedHealth=$healthOk}
    $found=$false;$logicalPhase=Get-LifecycleProperty $Context 'logicalPhaseId' ([ref]$found);$phase=if($found){[string]$logicalPhase}else{[string](Get-LifecycleProperty $Context 'phaseId' ([ref]$found))}
    $evidenceReferences=@();foreach($pattern in @('product-lifecycle-observer-generation-*.json','product-lifecycle-generation-*.json')){foreach($file in @(Get-ChildItem -LiteralPath ([string]$Context.runDir) -Filter $pattern -File -ErrorAction SilentlyContinue)){ $evidenceReferences+=[ordered]@{kind=if($pattern -like '*observer*'){'observer-summary'}else{'lifecycle-generation'};path=$file.FullName;sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()} }}
    $found=$false;$lifecycleInvocationId=Get-LifecycleProperty $Context 'lifecycleInvocationId' ([ref]$found);return [ordered]@{status='REAL E2E PASS';phase=$phase;invocationId=if($found){[string]$lifecycleInvocationId}else{''};contract='product-lifecycle-completion-authority';completionVerified=$true;candidate=$Candidate;role=$Role;transactionId=$TransactionId;payloadSha256=$PayloadSha256;installState=$installLedger;ownership=$ownershipLedger;authenticatedHealth=$true;guest=$guest;legs=@($Legs);evidenceReferences=$evidenceReferences;evidencePath=(Join-Path ([string]$Context.runDir) 'product-lifecycle-completion-authority.json')}
}

function Write-ProductLifecycleTerminalEvidence {
    param(
        [Parameter(Mandatory)][string]$InvocationDir,
        [Parameter(Mandatory)][string]$Phase,
        [Parameter(Mandatory)][string]$InvocationId,
        [Parameter(Mandatory)][string]$Provider,
        [Parameter(Mandatory)][string]$LastStableStep,
        [Parameter(Mandatory)][string]$ErrorMessage,
        [string]$TransactionId,
        [string]$PayloadSha256,
        [string]$Action='FreshInstall',
        [string]$Role='Primary / Desktop',
        [string]$Outcome='TERMINAL_FAILURE',
        [object]$Detail
    )
    $now=(Get-Date).ToUniversalTime().ToString('o')
    $journalPath=Join-Path $InvocationDir 'product-lifecycle-progress.jsonl'
    $currentPath=Join-Path $InvocationDir 'product-lifecycle-progress-current.json'
    $terminalPath=Join-Path $InvocationDir 'product-lifecycle-terminal.json'
    $providerPath=Join-Path $InvocationDir 'product-lifecycle-provider-failure.json'
    $entry=[ordered]@{event='TERMINAL';terminalReason=$Outcome;status=$Outcome;completionVerified=$false;phase=$Phase;invocationId=$InvocationId;provider=$Provider;lastStableStep=$LastStableStep;error=$ErrorMessage;timestampUtc=$now;transactionId=$TransactionId;payloadSha256=$PayloadSha256;action=$Action;role=$Role}
    if($Detail){$entry.detail=$Detail}
    New-Item -ItemType Directory -Path $InvocationDir -Force|Out-Null
    Add-Content -LiteralPath $journalPath -Value ($entry|ConvertTo-Json -Compress -Depth 24) -Encoding UTF8
    Write-EvidenceJson -Path $currentPath -Value $entry
    Write-EvidenceJson -Path $terminalPath -Value $entry
    $providerEntry=[ordered]@{status=$Outcome;contract='product-lifecycle-provider-failure';phase=$Phase;invocationId=$InvocationId;provider=$Provider;lastStableStep=$LastStableStep;error=$ErrorMessage;evidencePath=$terminalPath;terminalEvidencePath=$terminalPath;providerFailurePath=$providerPath;progressJournalPath=$journalPath;progressCurrentPath=$currentPath;timestampUtc=$now}
    if($Detail){$providerEntry.detail=$Detail}
    Write-EvidenceJson -Path $providerPath -Value $providerEntry
    return [pscustomobject]$providerEntry
}

function Invoke-ProductFreshInstallLifecycle {
    <# One product-owned loop. Synthetic reboot state is intentionally absent.
       MaxRebootBoundaries limits product reboots, not the final observation
       after the last WPF resume. Provider seams are test-only and retain all
       production binding/ordering checks around their results. #>
    param(
        [Parameter(Mandatory)][psobject]$Context,
        [string]$Role='Primary / Desktop',
        [psobject]$InitialResult,
        [scriptblock]$WpfProvider,
        [scriptblock]$TransitionProvider,
        [scriptblock]$RebootProvider,
        [scriptblock]$SettleProvider
    )
    if(-not $WpfProvider -and (Test-LifecycleProperty -Value $Context -Name 'lifecycleWpfProvider')){$found=$false;$WpfProvider=Get-LifecycleProperty $Context 'lifecycleWpfProvider' ([ref]$found)};if(-not $TransitionProvider -and (Test-LifecycleProperty -Value $Context -Name 'lifecycleTransitionProvider')){$found=$false;$TransitionProvider=Get-LifecycleProperty $Context 'lifecycleTransitionProvider' ([ref]$found)};if(-not $RebootProvider -and (Test-LifecycleProperty -Value $Context -Name 'lifecycleRebootProvider')){$found=$false;$RebootProvider=Get-LifecycleProperty $Context 'lifecycleRebootProvider' ([ref]$found)};if(-not $SettleProvider -and (Test-LifecycleProperty -Value $Context -Name 'lifecycleSettleProvider')){$found=$false;$SettleProvider=Get-LifecycleProperty $Context 'lifecycleSettleProvider' ([ref]$found)}
    $candidate=Assert-ExactCandidate $Context
    $expectedPayload=[string]$Context.candidate.tar.sha256
    $expectedVersion=[string]$Context.candidate.releaseVersion
    $expectedInstaller=[string]$Context.candidate.installerVersion
    if($expectedPayload -notmatch '^[0-9a-fA-F]{64}$'){throw 'TERMINAL_FAILURE: lifecycle payload identity is missing.'}
    if($expectedVersion -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$' -or $expectedInstaller -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$'){throw 'TERMINAL_FAILURE: lifecycle version identity is missing or malformed.'}
    $invocationStart=(Get-Date).ToUniversalTime().ToString('o')
    $contextPhaseFound=$false;$contextPhaseValue=Get-LifecycleProperty $Context 'phaseId' ([ref]$contextPhaseFound);$rawPhase=if($contextPhaseFound){[string]$contextPhaseValue}else{'PRODUCT-LIFECYCLE'}
    $logicalPhase=$rawPhase
    $safePhase=($rawPhase -replace '[^A-Za-z0-9_.-]','_').Trim('_');if(-not $safePhase){$safePhase='PRODUCT-LIFECYCLE'}
    $invocationId=[guid]::NewGuid().ToString('N')
    $invocationDir=Join-Path ([string]$Context.runDir) ("lifecycle-{0}-{1}" -f $safePhase,$invocationId)
    New-Item -ItemType Directory -Path $invocationDir -Force|Out-Null
    $contextConfigFound=$false;$contextConfig=Get-LifecycleProperty $Context 'config' ([ref]$contextConfigFound);$contextBudgetFound=$false;$contextBudget=Get-LifecycleProperty $Context 'phaseBudgetSeconds' ([ref]$contextBudgetFound)
    $lifeContext=[ordered]@{logicalPhaseId=$logicalPhase;phaseId=("{0}-{1}" -f $safePhase,$invocationId);lifecycleInvocationId=$invocationId;runDir=$invocationDir;vmId=$Context.vmId;vmName=$Context.vmName;candidate=$Context.candidate;config=$contextConfig;phaseBudgetSeconds=$contextBudget;invocationStartUtc=$invocationStart}
    if($Context -is [System.Collections.IDictionary]){foreach($key in $Context.Keys){if(-not $lifeContext.Contains([string]$key)){$lifeContext[[string]$key]=$Context[$key]}}}else{foreach($prop in @($Context.PSObject.Properties)){if(-not $lifeContext.Contains($prop.Name)){$lifeContext[$prop.Name]=$prop.Value}}}
    $lifeContext=[pscustomobject]$lifeContext
    $transactionId=''
    $providerFailure={param($kind,$message,$step,$detail)$failure=Write-ProductLifecycleTerminalEvidence -InvocationDir ([string]$lifeContext.runDir) -Phase $logicalPhase -InvocationId $invocationId -Provider $kind -LastStableStep $step -ErrorMessage $message -TransactionId $transactionId -PayloadSha256 $expectedPayload -Action 'FreshInstall' -Role $Role -Detail $detail;$failure|Add-Member -NotePropertyName completionVerified -NotePropertyValue $false -Force;$failure|Add-Member -NotePropertyName evidencePath -NotePropertyValue (Join-Path ([string]$lifeContext.runDir) 'product-lifecycle-terminal.json') -Force;return $failure}
    $callProvider={param($provider,$state,$kind,$required)$value=$null;try{$value=&$provider $state;if(-not $value){throw "$kind returned null"};if($required -and -not (Test-LifecycleProperty -Value $value -Name $required)){throw "$kind result lacks $required"};[ordered]@{ok=$true;value=$value}}catch{[ordered]@{ok=$false;error=$_.Exception.Message}}}
    if($InitialResult){$current=$InitialResult}elseif($WpfProvider){$wpfCall=&$callProvider $WpfProvider ([pscustomobject]@{context=$lifeContext;role=$Role;action='FreshInstall';generation=0;invocationId=$invocationId}) 'WpfProvider' 'status';if(-not $wpfCall.ok){return &$providerFailure 'WpfProvider' $wpfCall.error 'initial-WPF'};$current=$wpfCall.value}else{try{$current=Invoke-ActualWpfAction -Context $lifeContext -Action 'FreshInstall' -Role $Role -EvidenceLabel 'initial-FreshInstall' -AllowMutation -AllowRebootRequired -DeferDurableCompletionFallback}catch{return &$providerFailure 'WpfProvider' $_.Exception.Message 'initial-WPF'}}
    if($current -is [System.Collections.IDictionary]){$current=[pscustomobject]$current}
    if(-not $current){return &$providerFailure 'WpfProvider' 'WPF result was null' 'initial-WPF'}
    $currentProperties=Get-LifecyclePropertyNames $current;$found=$false;$currentStatus=Get-LifecycleProperty $current 'status' ([ref]$found);if(-not $found){return &$providerFailure 'WpfProvider' 'WPF result lacks status' 'initial-WPF'}
    if([string]$currentStatus -notin @('REAL E2E PASS','REAL E2E REBOOT REQUIRED','REAL E2E DURABLE PENDING')){return &$providerFailure 'WpfProvider' "WPF result returned unsupported status $([string]$currentStatus)" 'initial-WPF'}
    $legs=[System.Collections.Generic.List[object]]::new();$max=3;$priorGeneration=0;$transactionId='';$rebootCount=0;$checkpoint=$null
    while($true) {
        [void]$legs.Add($current)
        $found=$false;$currentGuest=Get-LifecycleProperty $current 'guest' ([ref]$found);$guestFound=$false;$guestCompleted=Get-LifecycleProperty $currentGuest 'completionVerified' ([ref]$guestFound);$currentCompleted=($currentGuest -and $guestFound -and [bool]$guestCompleted)
        $found=$false;$currentStatus=Get-LifecycleProperty $current 'status' ([ref]$found)
        if([string]$currentStatus -eq 'REAL E2E PASS' -and $currentCompleted){
            $completionReason='';if(-not (Test-LifecycleCompletionInput -Value $current -Reason ([ref]$completionReason))){return &$providerFailure 'WpfProvider' "immediate WPF PASS rejected: $completionReason" ("generation-{0}" -f $priorGeneration)}
            try{$verifySession=$null;try{$verifySession=Connect-DevFleetGuest -VmId ([guid][string]$lifeContext.vmId);$verification=Get-ProductLifecycleObservation -Session $verifySession -TransactionId $transactionId -PayloadSha256 $expectedPayload -Action 'FreshInstall' -Role $Role -ExpectedDevFleetVersion $expectedVersion -ExpectedInstallerVersion $expectedInstaller -ObservationTimeoutSeconds 30 -InvocationStartUtc $invocationStart}finally{if($verifySession){Remove-PSSession $verifySession -ErrorAction SilentlyContinue}}
                if(-not $verification.installStateValid -or -not $verification.canonicalOwnershipValid -or -not $verification.authenticatedHealthOk -or -not $verification.matchingConsumedReceipt){throw 'immediate WPF PASS could not be bound to current installer/receipt/ownership/health ledgers.'}
                if(-not $transactionId -and $verification.receipt){$transactionId=[string]$verification.receipt.transactionId};if($transactionId -notmatch '^[0-9a-fA-F]{32}$'){throw 'immediate WPF PASS has no exact consumed transaction receipt.'}
                $authority=New-ProductLifecycleCompletionAuthority -Context $lifeContext -Candidate $Context.candidate -Role $Role -TransactionId $transactionId -PayloadSha256 $expectedPayload -Observation $verification -Legs @($legs);Write-EvidenceJson -Path $authority.evidencePath -Value $authority;return $authority
            }catch{return &$providerFailure 'CompletionVerification' $_.Exception.Message ("generation-{0}" -f $priorGeneration)}
        }
        if([string]$currentStatus -notin @('REAL E2E REBOOT REQUIRED','REAL E2E DURABLE PENDING')){return &$providerFailure 'WpfProvider' "WPF result returned unsupported status $([string]$currentStatus)" ("generation-{0}" -f $priorGeneration)}
        $tx=$transactionId;if($tx -and $tx -notmatch '^[0-9a-fA-F]{32}$'){return &$providerFailure 'TransitionProvider' 'product transaction identity is malformed' ("generation-{0}" -f $priorGeneration)}
        $observer=$null
        if($TransitionProvider){
            $transitionCall=&$callProvider $TransitionProvider ([pscustomobject]@{context=$lifeContext;transactionId=$tx;payloadSha256=$expectedPayload;action='FreshInstall';role=$Role;priorGeneration=$priorGeneration;maxGeneration=$max;generation=$priorGeneration;invocationId=$invocationId}) 'TransitionProvider' 'outcome';if(-not $transitionCall.ok){return &$providerFailure 'TransitionProvider' $transitionCall.error ("WPF-generation-{0}" -f $priorGeneration)};$transition=$transitionCall.value
            if($transition -is [System.Collections.IDictionary]){$transition=[pscustomobject]$transition}
            if(-not (Test-LifecycleProperty -Value $transition -Name 'outcome')){return &$providerFailure 'TransitionProvider' 'transition provider result lacks outcome' ("WPF-generation-{0}" -f $priorGeneration)}
            $found=$false;$outcomeValue=Get-LifecycleProperty $transition 'outcome' ([ref]$found);$outcome=[string]$outcomeValue
            if($outcome -notin @('COMPLETED','NEXT_REBOOT','TERMINAL_FAILURE','NO_PROGRESS_TIMEOUT','ABSOLUTE_TIMEOUT')){return &$providerFailure 'TransitionProvider' 'transition provider returned an unknown outcome' ("WPF-generation-{0}" -f $priorGeneration)}
            if($outcome -eq 'NEXT_REBOOT' -and -not (Test-LifecycleProperty -Value $transition -Name 'checkpoint')){return &$providerFailure 'TransitionProvider' 'NEXT_REBOOT result lacks checkpoint' ("WPF-generation-{0}" -f $priorGeneration)}
            if($outcome -in @('COMPLETED','TERMINAL_FAILURE','NO_PROGRESS_TIMEOUT','ABSOLUTE_TIMEOUT') -and -not (Test-LifecycleProperty -Value $transition -Name 'observation')){$transition|Add-Member -NotePropertyName observation -NotePropertyValue ([pscustomobject]@{}) -Force}
            $found=$false;$transitionCheckpoint=Get-LifecycleProperty $transition 'checkpoint' ([ref]$found);$checkpoint=if($found){ConvertTo-CanonicalLifecycleCheckpoint $transitionCheckpoint}else{$null}
            $topCheckpointFound=$false;$topCheckpointValue=Get-LifecycleProperty $transition 'checkpoint' ([ref]$topCheckpointFound);$topFlagFound=$false;$topFlagValue=Get-LifecycleProperty $transition 'checkpointPresent' ([ref]$topFlagFound);$topActualPresent=($topCheckpointFound -and $null -ne $topCheckpointValue);if($topFlagFound -and ([bool]$topFlagValue) -ne $topActualPresent){return &$providerFailure 'TransitionProvider' 'transition checkpointPresent flag disagrees with top-level checkpoint object' ("WPF-generation-{0}" -f $priorGeneration)};if($topActualPresent -and -not $topFlagFound){return &$providerFailure 'TransitionProvider' 'transition checkpoint object has no checkpointPresent flag' ("WPF-generation-{0}" -f $priorGeneration)};if($outcome -eq 'NEXT_REBOOT' -and (-not $topFlagFound -or -not [bool]$topFlagValue)){return &$providerFailure 'TransitionProvider' 'NEXT_REBOOT transition lacks an affirmative top-level checkpointPresent binding' ("WPF-generation-{0}" -f $priorGeneration)}
            if($outcome -eq 'NEXT_REBOOT' -and -not $checkpoint){return &$providerFailure 'TransitionProvider' 'transition provider returned a malformed checkpoint schema' ("WPF-generation-{0}" -f $priorGeneration)}
            if($checkpoint -and -not $tx){$tx=[string]$checkpoint.transactionId}
            if($tx -and $tx -notmatch '^[0-9a-fA-F]{32}$'){return &$providerFailure 'TransitionProvider' 'product transaction identity is malformed' ("WPF-generation-{0}" -f $priorGeneration)}
            if($checkpoint -and -not (Test-RebootBoundaryIdentity -PriorCheckpoint ([pscustomobject]@{checkpointGeneration=$priorGeneration;transactionId=$tx;payloadSha256=$expectedPayload;action='FreshInstall';role=$Role;state='waiting-for-reboot'}) -CurrentCheckpoint $checkpoint -MaxGeneration $max)){return &$providerFailure 'TransitionProvider' ("transition provider returned an inexact checkpoint boundary: checkpoint=$($checkpoint|ConvertTo-Json -Compress -Depth 8); tx=$tx; expectedPayload=$expectedPayload; prior=$priorGeneration") ("WPF-generation-{0}" -f $priorGeneration)}
            $transitionObservationFound=$false;$transitionObservation=Get-LifecycleProperty $transition 'observation' ([ref]$transitionObservationFound);if($transitionObservationFound){$bindingReason='';if(-not (Test-LifecycleTransitionObservationBinding -Observation $transitionObservation -Checkpoint $checkpoint -Reason ([ref]$bindingReason))){return &$providerFailure 'TransitionProvider' $bindingReason ("WPF-generation-{0}" -f $priorGeneration)}}
            if($checkpoint){$transition.checkpoint=$checkpoint}
            if($outcome -eq 'COMPLETED'){$completionReason='';if(-not (Test-LifecycleCompletionInput -Value $transition -Reason ([ref]$completionReason))){return &$providerFailure 'TransitionProvider' "COMPLETED transition rejected: $completionReason" ("WPF-generation-{0}" -f $priorGeneration)}}
            $observer=$transition
        }else{
            # Observe from generation zero.  The earlier checkpoint-only poll
            # hid the exact child lifetime, CPU/stage movement, servicing
            # state, and normal-completion path for up to 30 minutes.  The
            # bounded observer can safely begin with an unknown transaction;
            # it adopts the transaction only from a fully candidate-bound
            # checkpoint or consumed receipt.
            $checkpoint=[pscustomobject]@{generation=$priorGeneration;checkpointGeneration=$priorGeneration;transactionId=$tx;payloadSha256=$expectedPayload;action='FreshInstall';role=$Role;state='waiting-for-reboot'}
            try{$observerSession=$null;try{$observerSession=Connect-DevFleetGuest -VmId ([guid][string]$lifeContext.vmId);$guestFound=$false;$guestProcessId=Get-LifecycleProperty $currentGuest 'processId' ([ref]$guestFound);if(-not $guestFound){$guestProcessId=Get-LifecycleProperty $current 'processId' ([ref]$guestFound)};$candidateProcessId=if($guestFound){[int]$guestProcessId}else{0};$policy=Get-HarnessBudgetPolicy -Config $lifeContext.config;$transactionBudget=if($Role -match '(?i)Laptop'){[int]$policy.transactionBudgetsSeconds.Laptop}else{[int]$policy.transactionBudgetsSeconds.Desktop};$observer=Wait-DevFleetProductLifecycleTransition -Session $observerSession -SessionProvider { Connect-DevFleetGuest -VmId ([guid][string]$lifeContext.vmId) } -TransactionId $tx -PayloadSha256 $expectedPayload -Action 'FreshInstall' -Role $Role -PriorGeneration $priorGeneration -MaxGeneration $max -BudgetSeconds $transactionBudget -NoProgressBudgetSeconds ([int]$policy.observerNoProgressBudgetSeconds) -AbsoluteBudgetSeconds ([int]$policy.observerAbsoluteBudgetSeconds) -CandidateProcessId $candidateProcessId -ExpectedDevFleetVersion $expectedVersion -ExpectedInstallerVersion $expectedInstaller -ObservationTimeoutSeconds 30 -EvidencePath (Join-Path ([string]$lifeContext.runDir) ("product-lifecycle-observer-generation-{0}.json" -f $priorGeneration)) -InvocationStartUtc $invocationStart}finally{if($observerSession){Remove-PSSession $observerSession -ErrorAction SilentlyContinue}}}catch{return &$providerFailure 'TransitionObserver' $_.Exception.Message ("generation-{0}" -f $priorGeneration)}
            $observerCheckpointFound=$false;$observerCheckpoint=Get-LifecycleProperty $observer 'checkpoint' ([ref]$observerCheckpointFound);if($observerCheckpointFound -and $observerCheckpoint){$checkpoint=$observerCheckpoint}
            if(-not $tx){
                if($checkpoint -and [int]$checkpoint.checkpointGeneration -gt 0){$tx=[string]$checkpoint.transactionId}
                else{$observerObservationFound=$false;$observerObservation=Get-LifecycleProperty $observer 'observation' ([ref]$observerObservationFound);if($observerObservationFound -and $observerObservation -and $observerObservation.matchingConsumedReceipt -and $observerObservation.receipt){$tx=[string]$observerObservation.receipt.transactionId}}
                if($tx -and $tx -notmatch '^[0-9a-fA-F]{32}$'){return &$providerFailure 'TransitionObserver' 'observer returned a malformed product transaction identity' ("generation-{0}" -f $priorGeneration)}
            }
        }
        $observerEvidenceGeneration=if($checkpoint){[int]$checkpoint.generation}else{$priorGeneration};$observerSummaryPath=Join-Path ([string]$lifeContext.runDir) ("product-lifecycle-observer-generation-{0}.json" -f $observerEvidenceGeneration);if($TransitionProvider){Write-EvidenceJson -Path $observerSummaryPath -Value $observer}
        $transactionId=$tx
        $found=$false;$observerOutcome=Get-LifecycleProperty $observer 'outcome' ([ref]$found);if([string]$observerOutcome -eq 'COMPLETED'){try{$found=$false;$observerObservation=Get-LifecycleProperty $observer 'observation' ([ref]$found);$authority=New-ProductLifecycleCompletionAuthority -Context $lifeContext -Candidate $Context.candidate -Role $Role -TransactionId $tx -PayloadSha256 $expectedPayload -Observation $observerObservation -Legs @($legs);Write-EvidenceJson -Path $authority.evidencePath -Value $authority;return $authority}catch{return &$providerFailure 'TransitionProvider' $_.Exception.Message ("generation-{0}" -f $priorGeneration)}}
        if([string]$observerOutcome -notin @('NEXT_REBOOT')){return &$providerFailure 'TransitionProvider' "$([string]$observerOutcome): product lifecycle observer stopped at generation $priorGeneration." ("generation-{0}" -f $priorGeneration)}
        if(-not $checkpoint -or [int]$checkpoint.generation -gt $max){return &$providerFailure 'TransitionProvider' 'generation 4 product reboot requested; MaxRebootBoundaries is 3' ("generation-{0}" -f $priorGeneration)}
        if($RebootProvider){$rebootCall=&$callProvider $RebootProvider ([pscustomobject]@{context=$lifeContext;checkpoint=$checkpoint;priorGeneration=$priorGeneration;generation=[int]$checkpoint.generation;invocationId=$invocationId}) 'RebootProvider' 'bootIdentityChanged';if(-not $rebootCall.ok){return &$providerFailure 'RebootProvider' $rebootCall.error ("NEXT_REBOOT-generation-{0}" -f [int]$checkpoint.generation)};$reboot=$rebootCall.value;$bootChangedFound=$false;$bootChanged=Get-LifecycleProperty $reboot 'bootIdentityChanged' ([ref]$bootChangedFound);if(-not $bootChangedFound -or -not [bool]$bootChanged){return &$providerFailure 'RebootProvider' 'reboot provider did not prove a changed boot identity' ("NEXT_REBOOT-generation-{0}" -f [int]$checkpoint.generation)};if($SettleProvider){$settleCall=&$callProvider $SettleProvider ([pscustomobject]@{context=$lifeContext;checkpoint=$checkpoint;reboot=$reboot;priorGeneration=$priorGeneration;generation=[int]$checkpoint.generation;invocationId=$invocationId}) 'SettlementProvider' 'stable';if(-not $settleCall.ok){return &$providerFailure 'SettlementProvider' $settleCall.error ("reboot-generation-{0}" -f [int]$checkpoint.generation)};$settlement=$settleCall.value;$stableFound=$false;$stable=Get-LifecycleProperty $settlement 'stable' ([ref]$stableFound);if(-not $stableFound -or -not [bool]$stable){return &$providerFailure 'SettlementProvider' 'servicing settlement provider did not establish a stable boundary' ("reboot-generation-{0}" -f [int]$checkpoint.generation)};$reboot=[ordered]@{reboot=$reboot;servicingSettlement=$settlement}}}else{try{$reboot=Invoke-ProductRebootBoundary -Context $lifeContext -Checkpoint $checkpoint -PriorGeneration $priorGeneration}catch{return &$providerFailure 'RebootProvider' $_.Exception.Message ("NEXT_REBOOT-generation-{0}" -f [int]$checkpoint.generation)}}
        $priorGeneration=[int]$checkpoint.generation;$rebootCount++
        if($WpfProvider){$wpfCall=&$callProvider $WpfProvider ([pscustomobject]@{context=$lifeContext;role=$Role;action='FreshInstall';generation=$priorGeneration;priorGeneration=$priorGeneration;invocationId=$invocationId}) 'WpfProvider' 'status';if(-not $wpfCall.ok){return &$providerFailure 'WpfProvider' $wpfCall.error ("reboot-generation-{0}" -f $priorGeneration)};$current=$wpfCall.value}else{try{$current=Invoke-ActualWpfAction -Context $lifeContext -Action 'FreshInstall' -Role $Role -EvidenceLabel ("resume-generation-{0}" -f $priorGeneration) -AllowMutation -AllowRebootRequired -DeferDurableCompletionFallback}catch{return &$providerFailure 'WpfProvider' $_.Exception.Message ("reboot-generation-{0}" -f $priorGeneration)}}
        if($current -is [System.Collections.IDictionary]){$current=[pscustomobject]$current}
        if(-not $current){return &$providerFailure 'WpfProvider' 'WPF result was null' ("reboot-generation-{0}" -f $priorGeneration)}
        $currentProperties=Get-LifecyclePropertyNames $current;$found=$false;$currentStatus=Get-LifecycleProperty $current 'status' ([ref]$found);if(-not $found){return &$providerFailure 'WpfProvider' 'WPF result lacks status' ("reboot-generation-{0}" -f $priorGeneration)}
        if([string]$currentStatus -notin @('REAL E2E PASS','REAL E2E REBOOT REQUIRED','REAL E2E DURABLE PENDING')){return &$providerFailure 'WpfProvider' "WPF result returned unsupported status $([string]$currentStatus)" ("reboot-generation-{0}" -f $priorGeneration)}
        $record=[ordered]@{generation=$priorGeneration;reboot=$reboot;observer=$observer;resume=$current;invocationId=$invocationId;observerEvidencePath=$observerSummaryPath;generationEvidencePath=(Join-Path ([string]$lifeContext.runDir) ("product-lifecycle-generation-{0}.json" -f $priorGeneration))};Write-EvidenceJson -Path (Join-Path ([string]$lifeContext.runDir) ("product-lifecycle-generation-{0}.json" -f $priorGeneration)) -Value $record
    }
}

function Invoke-SupportedFreshInstallLifecycle {
    <# Shared release-tooling contract. Product checkpoints and receipts remain authoritative. #>
    param(
        [Parameter(Mandatory)][psobject]$Context,
        [string]$Role = 'Primary / Desktop',
        [switch]$CompleteLifecycle
    )
    if (-not $CompleteLifecycle) { return Invoke-ActualWpfAction -Context $Context -Action 'FreshInstall' -Role $Role -EvidenceLabel 'initial-FreshInstall' -AllowMutation -AllowRebootRequired -DeferDurableCompletionFallback }
    return Invoke-ProductFreshInstallLifecycle -Context $Context -Role $Role
}

function Read-PhaseContext {
    param([Parameter(Mandatory)][string]$ContextJson)
    $context = $ContextJson | ConvertFrom-Json -ErrorAction Stop
    if (-not $context.candidate.candidate.path -or -not $context.vmName -or -not $context.runDir) { throw 'FullRelease phase context is missing exact candidate, disposable VM, or evidence identity.' }
    return $context
}

function Assert-ExactCandidate {
    param([Parameter(Mandatory)][psobject]$Context)
    $item = Get-Item -LiteralPath ([string]$Context.candidate.candidate.path) -ErrorAction Stop
    $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne [string]$Context.candidate.candidate.sha256 -or [int64]$item.Length -ne [int64]$Context.candidate.candidate.bytes) { throw "Exact candidate changed before phase $($Context.phaseId)." }
    return [ordered]@{ path=$item.FullName; bytes=[int64]$item.Length; sha256=$hash; releaseFingerprintId=[string]$Context.candidate.releaseFingerprintId; toolingFingerprintId=[string]$Context.candidate.toolingFingerprintId }
}

function New-GuestForeignSentinels {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$PhaseId)
    Invoke-Command -Session $Session -ScriptBlock {
        param($runId,$phaseId)
        $sha256=[Security.Cryptography.SHA256]::Create()
        try{$suffix=($sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes("${runId}:${phaseId}"))|ForEach-Object{$_.ToString('x2')}) -join ''}finally{$sha256.Dispose()}
        $suffix=$suffix.Substring(0,12)
        $taskName="DevFleet-E2E-Foreign-$suffix"
        $serviceName="DevFleetE2EForeign$suffix"
        $firewallName="DevFleet-E2E-Foreign-Firewall-$suffix"
        $registryPath="HKLM:\SOFTWARE\DevFleet-E2E\ForeignSentinels\$suffix"
        $filePath="C:\Users\Public\DevFleet-E2E\Sentinels\$suffix.txt"
        $value="foreign-sentinel-${runId}-${phaseId}"
        if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'Foreign scheduled-task sentinel already exists.'}
        if(Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue){throw 'Foreign service sentinel already exists.'}
        if(Get-NetFirewallRule -Name $firewallName -ErrorAction SilentlyContinue){throw 'Foreign firewall sentinel already exists.'}
        $taskAction=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\cmd.exe') -Argument '/d /c exit 0'
        $taskSettings=New-ScheduledTaskSettingsSet -Disable
        Register-ScheduledTask -TaskName $taskName -Action $taskAction -Settings $taskSettings -User 'SYSTEM' -RunLevel Highest -Force|Out-Null
        $serviceCommand='"'+(Join-Path $env:SystemRoot 'System32\cmd.exe')+'" /d /c exit 0'
        & (Join-Path $env:SystemRoot 'System32\sc.exe') create $serviceName 'binPath=' $serviceCommand 'start=' 'disabled' 'DisplayName=' "DevFleet E2E Foreign Sentinel $suffix"|Out-Null
        if($LASTEXITCODE -ne 0){throw 'Foreign service sentinel creation failed.'}
        New-NetFirewallRule -Name $firewallName -DisplayName $firewallName -Group 'DevFleet E2E Foreign Sentinels' -Direction Inbound -Action Block -Protocol TCP -LocalPort 65535 -Profile Any|Out-Null
        New-Item -ItemType Directory -Path (Split-Path -Parent $filePath) -Force|Out-Null
        New-Item -Path $registryPath -Force|Out-Null
        New-ItemProperty -Path $registryPath -Name Value -Value $value -PropertyType String -Force|Out-Null
        [IO.File]::WriteAllText($filePath,$value,[Text.UTF8Encoding]::new($false))
        $sha256=[Security.Cryptography.SHA256]::Create()
        try{$valueSha256=($sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($value))|ForEach-Object{$_.ToString('x2')})-join ''}finally{$sha256.Dispose()}
        return [ordered]@{task=$taskName;service=$serviceName;firewall=$firewallName;registry=$registryPath;file=$filePath;valueSha256=$valueSha256;fileSha256=(Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()}
    } -ArgumentList $RunId,$PhaseId
}

function Test-GuestForeignSentinels {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,[Parameter(Mandatory)][psobject]$Sentinels)
    Invoke-Command -Session $Session -ScriptBlock {
        param($sentinels)
        $task=@(Get-ScheduledTask -TaskName ([string]$sentinels.task) -ErrorAction SilentlyContinue)
        $service=@(Get-CimInstance Win32_Service -Filter "Name='$([string]$sentinels.service)'" -ErrorAction SilentlyContinue)
        $firewall=@(Get-NetFirewallRule -Name ([string]$sentinels.firewall) -ErrorAction SilentlyContinue)
        $value=[string](Get-ItemProperty -Path ([string]$sentinels.registry) -Name Value -ErrorAction Stop).Value
        $sha256=[Security.Cryptography.SHA256]::Create()
        try{$valueSha=($sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($value))|ForEach-Object{$_.ToString('x2')})-join ''}finally{$sha256.Dispose()}
        $fileSha=if(Test-Path -LiteralPath ([string]$sentinels.file) -PathType Leaf){(Get-FileHash -LiteralPath ([string]$sentinels.file) -Algorithm SHA256).Hash.ToLowerInvariant()}else{''}
        $checks=[ordered]@{scheduledTask=($task.Count -eq 1);service=($service.Count -eq 1 -and [string]$service[0].StartMode -eq 'Disabled');firewall=($firewall.Count -eq 1 -and [string]$firewall[0].Action -eq 'Block');registry=($valueSha -eq [string]$sentinels.valueSha256);file=($fileSha -eq [string]$sentinels.fileSha256)}
        if(@($checks.GetEnumerator()|Where-Object{-not [bool]$_.Value}).Count){throw 'One or more unrelated Windows sentinels changed during the lifecycle action.'}
        return [ordered]@{status='PASS';checks=$checks;unchanged=$true}
    } -ArgumentList $Sentinels
}

function Remove-GuestForeignSentinels {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,[Parameter(Mandatory)][psobject]$Sentinels)
    Invoke-Command -Session $Session -ScriptBlock {
        param($sentinels)
        Unregister-ScheduledTask -TaskName ([string]$sentinels.task) -Confirm:$false -ErrorAction SilentlyContinue
        if(Get-CimInstance Win32_Service -Filter "Name='$([string]$sentinels.service)'" -ErrorAction SilentlyContinue){& (Join-Path $env:SystemRoot 'System32\sc.exe') delete ([string]$sentinels.service)|Out-Null}
        Get-NetFirewallRule -Name ([string]$sentinels.firewall) -ErrorAction SilentlyContinue|Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath ([string]$sentinels.registry) -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath ([string]$sentinels.file) -Force -ErrorAction SilentlyContinue
        $remaining=[ordered]@{task=[bool](Get-ScheduledTask -TaskName ([string]$sentinels.task) -ErrorAction SilentlyContinue);service=[bool](Get-CimInstance Win32_Service -Filter "Name='$([string]$sentinels.service)'" -ErrorAction SilentlyContinue);firewall=[bool](Get-NetFirewallRule -Name ([string]$sentinels.firewall) -ErrorAction SilentlyContinue);registry=(Test-Path -LiteralPath ([string]$sentinels.registry));file=(Test-Path -LiteralPath ([string]$sentinels.file))}
        if(@($remaining.GetEnumerator()|Where-Object{[bool]$_.Value}).Count){throw 'Run-owned Windows sentinel cleanup was incomplete.'}
        return [ordered]@{status='PASS';absent=$true}
    } -ArgumentList $Sentinels
}

function Invoke-RebootResumeWpfFallback {
    param(
        [Parameter(Mandatory)][psobject]$Context,
        [Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory)][psobject]$DriverReport
    )
    $expectedPayload = [string]$Context.candidate.tar.sha256
    $expectedCandidatePath = Join-Path "C:\Users\Public\DevFleet-E2E\$($Context.runId)\$($Context.phaseId)" (Split-Path -Leaf ([string]$Context.candidate.candidate.path))
    $candidatePid = 0
    $candidateSessionId = -1
    $driverProcessFound=$false;$driverProcess=Get-LifecycleProperty $DriverReport 'processId' ([ref]$driverProcessFound);if($driverProcessFound){$candidatePid=[int]$driverProcess}
    $driverSessionFound=$false;$driverSession=Get-LifecycleProperty $DriverReport 'sessionId' ([ref]$driverSessionFound);if($driverSessionFound){$candidateSessionId=[int]$driverSession}
    $observationSeconds = 180
    $diagnosticSecondsFound=$false;$diagnosticSeconds=Get-LifecycleProperty $Context 'diagnosticObservationSeconds' ([ref]$diagnosticSecondsFound);if ($diagnosticSecondsFound) {
        $requestedSeconds = 0
        if ([int]::TryParse([string]$diagnosticSeconds, [ref]$requestedSeconds) -and $requestedSeconds -gt 180) {
            $observationSeconds = [Math]::Min($requestedSeconds, 1800)
        }
    }
    $observationPath = Join-Path ([string]$Context.runDir) 'durable-observation-samples.json'
    $observationSamples = [System.Collections.Generic.List[object]]::new()
    $deadline = (Get-Date).AddSeconds($observationSeconds)
    $lastError = 'durable completion not yet observable'
    do {
        try {
            $sample = Invoke-Command -Session $Session -ScriptBlock {
                param($processId,$sessionId,$expectedPath)
                $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
                $ids = [System.Collections.Generic.HashSet[int]]::new()
                if ($processId -gt 0) { [void]$ids.Add($processId) }
                do {
                    $before = $ids.Count
                    foreach ($row in $all) { if ($ids.Contains([int]$row.ParentProcessId)) { [void]$ids.Add([int]$row.ProcessId) } }
                } while ($ids.Count -gt $before)
                $root = $all | Where-Object { [int]$_.ProcessId -eq $processId } | Select-Object -First 1
                $processMeta = $null
                try {
                    $p = Get-Process -Id $processId -ErrorAction Stop
                    $processMeta = [ordered]@{hasExited=$false;responding=[bool]$p.Responding;mainWindowHandle=[int64]$p.MainWindowHandle;cpuSeconds=[double]$p.TotalProcessorTime.TotalSeconds;workingSetBytes=[int64]$p.WorkingSet64;threadCount=[int]$p.Threads.Count;handleCount=[int]$p.HandleCount;startTime=$p.StartTime.ToUniversalTime().ToString('o')}
                } catch { $processMeta = [ordered]@{hasExited=$true} }
                $checkpointPath = 'C:\ProgramData\M-TechLabs\DevFleet\Installer\resume-checkpoint.json'
                $checkpoint = $null
                if (Test-Path -LiteralPath $checkpointPath -PathType Leaf) {
                    try { $v = Get-Content -LiteralPath $checkpointPath -Raw | ConvertFrom-Json; $checkpoint = [ordered]@{state=$v.state;action=$v.action;transactionId=$v.transactionId;payloadSha256=$v.payloadSha256;checkpointGeneration=$v.checkpointGeneration;completedStages=$v.completedStages;resumeStage=$v.resumeStage;createdUtc=$v.createdUtc;lastWriteUtc=(Get-Item -LiteralPath $checkpointPath).LastWriteTimeUtc.ToString('o')} } catch { $checkpoint = [ordered]@{readError=$_.Exception.Message} }
                }
                $consumedRoot = 'C:\ProgramData\M-TechLabs\DevFleet\Installer\resume-consumed'
                $receipts = @()
                if (Test-Path -LiteralPath $consumedRoot) { $receipts = @(Get-ChildItem -LiteralPath $consumedRoot -Filter '*.json' -File -ErrorAction SilentlyContinue | Select-Object Name,Length,LastWriteTimeUtc) }
                $installPath = 'C:\ProgramData\M-TechLabs\DevFleet\Installer\install-state.json'
                $ownershipPath = 'C:\ProgramData\DevFleetHostAgent\integration-ownership.json'
                [ordered]@{timestampUtc=(Get-Date).ToUniversalTime().ToString('o');candidate=$processMeta;candidateRow=if($root){[ordered]@{processId=$root.ProcessId;parentProcessId=$root.ParentProcessId;executablePath=$root.ExecutablePath;commandLine=$root.CommandLine;sessionId=$root.SessionId}}else{$null};processTree=@($all | Where-Object { $ids.Contains([int]$_.ProcessId) } | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,SessionId);checkpoint=$checkpoint;checkpointPresent=(Test-Path -LiteralPath $checkpointPath -PathType Leaf);receiptFiles=$receipts;installStatePresent=(Test-Path -LiteralPath $installPath -PathType Leaf);installStateLastWriteUtc=if(Test-Path -LiteralPath $installPath){(Get-Item -LiteralPath $installPath).LastWriteTimeUtc.ToString('o')}else{$null};ownershipPresent=(Test-Path -LiteralPath $ownershipPath -PathType Leaf);nodeIdentityPresent=(Test-Path -LiteralPath 'C:\ProgramData\DevFleet\node-identity.json' -PathType Leaf);hostAgentPresent=(Test-Path -LiteralPath 'C:\ProgramData\DevFleetHostAgent' -PathType Container);hostAgentTaskPresent=[bool](Get-ScheduledTask -TaskName 'DevFleet Host Agent' -ErrorAction SilentlyContinue);listenerPresent=[bool](Get-NetTCPConnection -LocalPort 8790 -State Listen -ErrorAction SilentlyContinue);pendingCbs=(Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending');pendingWindowsUpdate=(Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')}
            } -ArgumentList $candidatePid,$candidateSessionId,$expectedCandidatePath
            [void]$observationSamples.Add($sample)
            Write-EvidenceJson -Path $observationPath -Value @($observationSamples)
        } catch {
            [void]$observationSamples.Add([ordered]@{timestampUtc=(Get-Date).ToUniversalTime().ToString('o');sampleError=$_.Exception.Message})
            Write-EvidenceJson -Path $observationPath -Value @($observationSamples)
        }
        try {
            $durable = Invoke-MaintenanceReadyGuestValidation -VmId ([guid][string]$Context.vmId) -Fingerprint $Context.candidate
            $health = Invoke-Command -Session $Session -ScriptBlock {
                param($payload)
                $checkpoint = 'C:\ProgramData\M-TechLabs\DevFleet\Installer\resume-checkpoint.json'
                if (Test-Path -LiteralPath $checkpoint -PathType Leaf) { throw 'Reboot checkpoint remains present; completion is not verified.' }
                $consumedRoot = 'C:\ProgramData\M-TechLabs\DevFleet\Installer\resume-consumed'
                $receipt = @(Get-ChildItem -LiteralPath $consumedRoot -Filter '*.json' -File -ErrorAction SilentlyContinue | ForEach-Object {
                    try { $value = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json; if ([string]$value.payloadSha256 -ceq $payload) { $_ } } catch { }
                } | Select-Object -Last 1)
                if (-not $receipt) { throw 'No consumed reboot receipt matched the exact candidate payload.' }
                $protocol = 'C:\ProgramData\DevFleetHostAgent\DevFleet-HostAgentProtocol.psm1'
                $tokenPath = 'C:\ProgramData\DevFleetHostAgent\token.txt'
                if (-not (Test-Path -LiteralPath $protocol -PathType Leaf) -or -not (Test-Path -LiteralPath $tokenPath -PathType Leaf)) { throw 'Host Agent authenticated-health prerequisites are missing.' }
                Import-Module $protocol -Force
                $token = (Get-Content -LiteralPath $tokenPath -Raw).Trim()
                if (-not $token) { throw 'Host Agent token is empty.' }
                $result = Invoke-HostAgentAuthenticatedJson -Uri 'http://127.0.0.1:8790/healthz' -Method GET -Key $token -ExpectedHost $env:COMPUTERNAME
                if (-not [bool]$result.ok) { throw 'Host Agent authenticated health did not return ok=true.' }
                [ordered]@{status='PASS';hostName=[string]$result.host_name;hostId=[string]$result.host_id;receiptPath=$receipt.FullName}
            } -ArgumentList $expectedPayload
            return [ordered]@{status='PASS';mode='DURABLE_REBOOT_RESUME_FALLBACK';driver=$DriverReport;guest=$durable;health=$health;authenticatedHealth=$true;checkpointConsumed=$true}
        } catch { $lastError = $_.Exception.Message }
        Start-Sleep -Seconds 3
    } while ((Get-Date) -lt $deadline)
    $processEvidence = $null
    $cleanupEvidence = $null
    if ($candidatePid -gt 0 -and $candidateSessionId -ge 0) {
        try {
            $processEvidence = Invoke-Command -Session $Session -ScriptBlock {
                param($processId,$sessionId,$expectedPath)
                $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
                $ids = [System.Collections.Generic.HashSet[int]]::new()
                [void]$ids.Add($processId)
                do {
                    $before = $ids.Count
                    foreach ($row in $all) { if ($ids.Contains([int]$row.ParentProcessId)) { [void]$ids.Add([int]$row.ProcessId) } }
                } while ($ids.Count -gt $before)
                $target = @($all | Where-Object { $ids.Contains([int]$_.ProcessId) } | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,SessionId)
                $root = $all | Where-Object { [int]$_.ProcessId -eq $processId } | Select-Object -First 1
                $sessionMatch = $false
                try { $sessionMatch = [int](Get-Process -Id $processId -ErrorAction Stop).SessionId -eq $sessionId } catch { }
                $pathMatch = $null -ne $root -and -not [string]::IsNullOrWhiteSpace($expectedPath) -and [string]$root.ExecutablePath -ieq $expectedPath
                [ordered]@{candidatePid=$processId;expectedSessionId=$sessionId;expectedPath=$expectedPath;candidatePresent=($null -ne $root);sessionMatch=$sessionMatch;pathMatch=$pathMatch;processTree=$target}
            } -ArgumentList $candidatePid,$candidateSessionId,$expectedCandidatePath
        } catch { $processEvidence = [ordered]@{captureError=$_.Exception.Message} }
        try {
            $cleanupEvidence = Invoke-Command -Session $Session -ScriptBlock {
                param($processId,$sessionId,$expectedPath)
                $row = Get-CimInstance Win32_Process -Filter "ProcessId=$processId" -ErrorAction SilentlyContinue
                $sessionMatch = $false
                try { $sessionMatch = [int](Get-Process -Id $processId -ErrorAction Stop).SessionId -eq $sessionId } catch { }
                $pathMatch = $null -ne $row -and -not [string]::IsNullOrWhiteSpace($expectedPath) -and [string]$row.ExecutablePath -ieq $expectedPath
                if ($row -and $sessionMatch -and $pathMatch) { Stop-Process -Id $processId -Force -ErrorAction Stop; [ordered]@{attempted=$true;stopped=$true;pid=$processId;sessionMatch=$sessionMatch;pathMatch=$pathMatch} }
                else { [ordered]@{attempted=$false;stopped=$false;pid=$processId;present=($null -ne $row);sessionMatch=$sessionMatch;pathMatch=$pathMatch} }
            } -ArgumentList $candidatePid,$candidateSessionId,$expectedCandidatePath
        } catch { $cleanupEvidence = [ordered]@{cleanupError=$_.Exception.Message} }
    } else {
        $cleanupEvidence = [ordered]@{attempted=$false;reason='No exact candidate PID and session identity was present in the driver report.'}
    }
    $details = [ordered]@{lastError=$lastError;observationSeconds=$observationSeconds;observationPath=$observationPath;observationSamples=@($observationSamples);processEvidence=$processEvidence;cleanupEvidence=$cleanupEvidence} | ConvertTo-Json -Depth 12 -Compress
    throw "WPF window disappeared and durable reboot-resume completion did not become verifiable within the bounded fallback window: $details"
}

function Invoke-ActualWpfAction {
    param([Parameter(Mandatory)][psobject]$Context,[Parameter(Mandatory)][string]$Action,[string]$Role='Primary / Desktop',[string]$EvidenceLabel,[switch]$AllowMutation,[switch]$AllowRebootRequired,[switch]$UseDurableCompletionFallback,[switch]$DeferDurableCompletionFallback)
    $candidate = Assert-ExactCandidate $Context
    $session = $null
    $sentinels=$null
    $sentinelVerification=$null
    $sentinelCleanup=$null
    try {
        $session = Connect-DevFleetGuest -VmId ([guid][string]$Context.vmId)
        try{$interactiveState=Get-DevFleetE2EInteractiveDesktopState -Session $session;$interactiveProof=Assert-DevFleetE2EInteractiveDesktop -State $interactiveState}
        catch{Remove-PSSession $session -ErrorAction SilentlyContinue;$session=$null;Ensure-FullReleaseInteractiveDesktop -VmId ([guid][string]$Context.vmId)|Out-Null;$session=Connect-DevFleetGuest -VmId ([guid][string]$Context.vmId);$interactiveState=Get-DevFleetE2EInteractiveDesktopState -Session $session;$interactiveProof=Assert-DevFleetE2EInteractiveDesktop -State $interactiveState}
        $remoteRoot = "C:\Users\Public\DevFleet-E2E\$($Context.runId)\$($Context.phaseId)"
        $remoteExe = Join-Path $remoteRoot (Split-Path -Leaf $candidate.path)
        $remoteDriver = Join-Path $remoteRoot 'Invoke-WpfUiAutomation.ps1'
        $safeEvidenceLabel = if ([string]::IsNullOrWhiteSpace($EvidenceLabel)) { "$($Context.phaseId)-$Action-$([guid]::NewGuid().ToString('N'))" } else { $EvidenceLabel }
        $safeEvidenceLabel = ($safeEvidenceLabel -replace '[^A-Za-z0-9._-]','-')
        $localEvidence = Join-Path ([string]$Context.runDir) ("$safeEvidenceLabel-wpf-evidence.json")
        New-Item -ItemType Directory -Force -Path ([string]$Context.runDir) | Out-Null
        Invoke-Command -Session $session -ScriptBlock { param($root) New-Item -ItemType Directory -Force -Path $root | Out-Null } -ArgumentList $remoteRoot
        if($AllowMutation){$sentinels=New-GuestForeignSentinels -Session $session -RunId ([string]$Context.runId) -PhaseId ([string]$Context.phaseId)}
        $stage = Get-StageIntegrity -LocalPath $candidate.path -Session $session -RemotePath $remoteExe
        if (-not $stage.equal) { throw 'Candidate stage hash differed on disposable guest.' }
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Invoke-WpfUiAutomation.ps1') -Destination $remoteDriver -ToSession $session -Force
        $remoteReport = Join-Path $remoteRoot 'wpf-evidence.json'
        $remoteStarted = Join-Path $remoteRoot 'wpf-started.json'
        $remoteDiagnostic = Join-Path $remoteRoot 'wpf-no-report.json'
        try {
            # A phase may intentionally launch the same action more than once
            # (for example, across a real guest reboot). Never accept a report
            # left by an earlier launch as evidence for the current process.
            Invoke-Command -Session $session -ScriptBlock {
                param($reportPath,$startedPath,$diagnosticPath)
                Remove-Item -LiteralPath $reportPath,$startedPath,$diagnosticPath -Force -ErrorAction SilentlyContinue
            } -ArgumentList $remoteReport,$remoteStarted,$remoteDiagnostic
            $report = Invoke-Command -Session $session -ScriptBlock {
                param($driver,$exe,$action,$role,$phaseId,$report,$started,$diagnostic,$allowMutation,$allowRebootRequired,$useDurableCompletionFallback)
                if (-not (Test-Path -LiteralPath $driver -PathType Leaf)) { throw "Remote WPF driver was not staged: $driver" }
                if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Remote candidate was not staged: $exe" }
                $taskName = "DevFleet-E2E-UIA-$([guid]::NewGuid().ToString('N'))"
                try {
                    $argument = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -STA -File `"$driver`" -ExePath `"$exe`" -Action `"$action`" -Role `"$role`" -OutputPath `"$report`" -StartedPath `"$started`""
                    if ($allowMutation) { $argument += ' -AllowMutation' }
                    if ($allowRebootRequired) { $argument += ' -AllowRebootRequired' }
                    if ($useDurableCompletionFallback) { $argument += ' -UseDurableCompletionFallback' }
                    $taskAction = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument $argument
                    if($env:USERNAME -cne 'E2EAdmin'){throw 'WPF driver launch reached a non-E2EAdmin PowerShell Direct identity.'}
                    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'DEVFLEET-E2E-01\E2EAdmin' -LogonType Interactive -RunLevel Highest
                    $taskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
                    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Principal $taskPrincipal -Settings $taskSettings -Force | Out-Null
                    Start-ScheduledTask -TaskName $taskName
                    $deadline = if ([string]$phaseId -eq 'REBOOT-RESUME' -and [string]$action -eq 'FreshInstall') { (Get-Date).AddSeconds(90) } else { (Get-Date).AddMinutes(5) }
                    while (-not (Test-Path -LiteralPath $report -PathType Leaf) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
                    if (-not (Test-Path -LiteralPath $report -PathType Leaf)) {
                        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                        $diag=[ordered]@{status='NO_REPORT';taskName=$taskName;taskState=if($task){[string]$task.State}else{'MISSING'};driver=$driver;exe=$exe;started=(Test-Path -LiteralPath $started -PathType Leaf);processes=@(Get-Process powershell,pwsh,DevFleet.Setup -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,SessionId,MainWindowHandle,Path);timestamp=(Get-Date).ToUniversalTime().ToString('o')}
                        $diag | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $diagnostic -Encoding UTF8
                        return [pscustomobject]$diag
                    }
                    $result=Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
                    function Get-TaskProcessIdentity($id){
                        $processId=0
                        if(-not [int]::TryParse([string]$id,[ref]$processId) -or $processId -le 0){return [ordered]@{present=$false;pid=$null;state='PROCESS_EXITED'}}
                        $row=Get-CimInstance Win32_Process -Filter "ProcessId=$processId" -ErrorAction SilentlyContinue
                        $p=Get-Process -Id $processId -ErrorAction SilentlyContinue
                        if(-not $row -or -not $p){return [ordered]@{present=$false;pid=$processId;state='PROCESS_EXITED'}}
                        try{$owner=Invoke-CimMethod -InputObject $row -MethodName GetOwner -ErrorAction Stop}catch{
                            $current=Get-CimInstance Win32_Process -Filter "ProcessId=$processId" -ErrorAction SilentlyContinue
                            if(-not $current){return [ordered]@{present=$false;pid=$processId;state='PROCESS_EXITED'}}
                            throw
                        }
                        [ordered]@{present=$true;pid=$processId;user=[string]$owner.User;domain=[string]$owner.Domain;owner="${owner.Domain}\$($owner.User)";sessionId=[int]$p.SessionId}
                    }
                    $result | Add-Member -NotePropertyName taskPrincipal -NotePropertyValue 'DEVFLEET-E2E-01\E2EAdmin' -Force
                    if(-not $result.PSObject.Properties['driverIdentity'] -or -not $result.driverIdentity){$result | Add-Member -NotePropertyName driverIdentity -NotePropertyValue (Get-TaskProcessIdentity $result.driverPid) -Force}
                    if(-not $result.PSObject.Properties['candidateIdentity'] -or -not $result.candidateIdentity){$result | Add-Member -NotePropertyName candidateIdentity -NotePropertyValue (Get-TaskProcessIdentity $result.processId) -Force}
                    $result
                } finally {
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                }
            } -ArgumentList $remoteDriver,$remoteExe,$Action,$Role,[string]$Context.phaseId,$remoteReport,$remoteStarted,$remoteDiagnostic,[bool]$AllowMutation,[bool]$AllowRebootRequired,[bool]$UseDurableCompletionFallback
            if(-not $report){
                $report=Invoke-Command -Session $session -ScriptBlock { param($path) if(Test-Path -LiteralPath $path -PathType Leaf){Get-Content -LiteralPath $path -Raw | ConvertFrom-Json} } -ArgumentList $remoteReport -ErrorAction Stop
            }
        } catch {
            if (Test-Path -LiteralPath $remoteReport -PathType Leaf) {
                try { Copy-Item -FromSession $session -LiteralPath $remoteReport -Destination $localEvidence -Force -ErrorAction Stop } catch { }
            }
            foreach($diagnosticPath in @($remoteStarted,$remoteDiagnostic)) {
                if (Test-Path -LiteralPath $diagnosticPath -PathType Leaf) {
                    try { Copy-Item -FromSession $session -LiteralPath $diagnosticPath -Destination (Join-Path ([string]$Context.runDir) (Split-Path -Leaf $diagnosticPath)) -Force -ErrorAction Stop } catch { }
                }
            }
            throw "Remote WPF action $Action failed: $($_.Exception.Message); evidenceLocal=$localEvidence"
        }
        try {
            $bootProcess = Invoke-Command -Session $session -ScriptBlock {
                param($processId)
                $os = Get-CimInstance Win32_OperatingSystem
                $start = $null
                try { $start = (Get-Process -Id $processId -ErrorAction Stop).StartTime.ToUniversalTime().ToString('o') } catch { }
                [ordered]@{bootIdentity=$os.LastBootUpTime.ToUniversalTime().ToString('o');processStartTime=$start;computer=$env:COMPUTERNAME}
            } -ArgumentList ([int]$report.processId)
            $report | Add-Member -NotePropertyName evidenceLabel -NotePropertyValue $safeEvidenceLabel -Force
            $report | Add-Member -NotePropertyName runId -NotePropertyValue ([string]$Context.runId) -Force
            $report | Add-Member -NotePropertyName phaseId -NotePropertyValue ([string]$Context.phaseId) -Force
            $report | Add-Member -NotePropertyName candidatePath -NotePropertyValue ([string]$candidate.path) -Force
            $report | Add-Member -NotePropertyName candidateSha256 -NotePropertyValue ([string]$candidate.sha256) -Force
            $report | Add-Member -NotePropertyName bootIdentity -NotePropertyValue ([string]$bootProcess.bootIdentity) -Force
            $report | Add-Member -NotePropertyName processStartTime -NotePropertyValue ([string]$bootProcess.processStartTime) -Force
            $report | Add-Member -NotePropertyName evidenceProvenance -NotePropertyValue 'Invoke-ActualWpfAction/Invoke-WpfUiAutomation' -Force
            [IO.File]::WriteAllText($localEvidence,(($report | ConvertTo-Json -Depth 20)+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))
        } catch { try { Copy-Item -FromSession $session -LiteralPath $remoteReport -Destination $localEvidence -Force -ErrorAction Stop } catch { } }
        $identity=$null
        if(-not $report){throw "Remote WPF action $Action returned no result; evidenceLocal=$localEvidence"}
        $reportStatusForIdentityFound=$false
        $reportStatusForIdentityValue=Get-LifecycleProperty $report 'status' ([ref]$reportStatusForIdentityFound)
        $reportStatusForIdentity=if($reportStatusForIdentityFound){[string]$reportStatusForIdentityValue}else{''}
        if(-not ($report.PSObject.Properties['driverIdentity'] -and $report.PSObject.Properties['candidateIdentity'])){
            $driverPidFound=$false;$driverPid=Get-LifecycleProperty $report 'driverPid' ([ref]$driverPidFound)
            $candidatePidFound=$false;$candidatePid=Get-LifecycleProperty $report 'processId' ([ref]$candidatePidFound)
            if($driverPidFound -and $candidatePidFound -and [int]$driverPid -gt 0 -and [int]$candidatePid -gt 0){
                $identity=Invoke-Command -Session $session -ScriptBlock {
                    param($driver,$candidate)
                    function Resolve-ProcessIdentity([int]$Id){
                        $row=Get-CimInstance Win32_Process -Filter "ProcessId=$Id" -ErrorAction SilentlyContinue
                        $process=Get-Process -Id $Id -ErrorAction SilentlyContinue
                        if(-not $row -or -not $process){return [ordered]@{present=$false;pid=$Id;state='PROCESS_EXITED'}}
                        try{$owner=Invoke-CimMethod -InputObject $row -MethodName GetOwner -ErrorAction Stop}catch{
                            $current=Get-CimInstance Win32_Process -Filter "ProcessId=$Id" -ErrorAction SilentlyContinue
                            if(-not $current){return [ordered]@{present=$false;pid=$Id;state='PROCESS_EXITED'}}
                            throw
                        }
                        [ordered]@{present=$true;pid=$Id;user=[string]$owner.User;domain=[string]$owner.Domain;owner=([string]$owner.Domain+'\'+[string]$owner.User);sessionId=[int]$process.SessionId}
                    }
                    [ordered]@{driver=(Resolve-ProcessIdentity $driver);candidate=(Resolve-ProcessIdentity $candidate)}
                } -ArgumentList ([int]$driverPid),([int]$candidatePid) -ErrorAction Stop
                $report | Add-Member -NotePropertyName driverIdentity -NotePropertyValue $identity.driver -Force
                $report | Add-Member -NotePropertyName candidateIdentity -NotePropertyValue $identity.candidate -Force
            }
        }
        if($report.PSObject.Properties['driverIdentity'] -and $report.PSObject.Properties['candidateIdentity']){
            if(-not $identity){$identity=[ordered]@{driver=$report.driverIdentity;candidate=$report.candidateIdentity}}
            foreach($role in @('driver','candidate')){
                $item=if($role -eq 'driver'){$identity.driver}else{$identity.candidate}
                if(-not $item -or -not $item.present -or [string]$item.owner -cne 'DEVFLEET-E2E-01\E2EAdmin' -or [int]$item.sessionId -ne [int]$interactiveProof.sessionId -or [int]$item.sessionId -eq 0){throw "WPF $role identity did not share the exact active E2EAdmin interactive session."}
            }
        } elseif($reportStatusForIdentity -in @('PASS','REBOOT_REQUIRED','DURABLE_PENDING')) { throw 'WPF report omitted the required driver/candidate process identity proof.' }
        $report | Add-Member -NotePropertyName interactiveSessionId -NotePropertyValue ([int]$interactiveProof.sessionId) -Force
        if($identity){$report | Add-Member -NotePropertyName driverIdentity -NotePropertyValue $identity.driver -Force;$report | Add-Member -NotePropertyName candidateIdentity -NotePropertyValue $identity.candidate -Force}
        [IO.File]::WriteAllText($localEvidence,(($report | ConvertTo-Json -Depth 20)+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))
        $reportStatusFound=$false;$reportStatusValue=Get-LifecycleProperty $report 'status' ([ref]$reportStatusFound);$reportStatus=[string]$reportStatusValue
        $reportErrorForFallbackFound=$false;$reportErrorForFallback=Get-LifecycleProperty $report 'error' ([ref]$reportErrorForFallbackFound)
        if (-not $DeferDurableCompletionFallback -and [string]$Context.phaseId -eq 'REBOOT-RESUME' -and $Action -eq 'FreshInstall' -and ($reportStatus -eq 'NO_REPORT' -or $reportStatus -eq 'DURABLE_PENDING' -or ($reportStatus -eq 'FAIL' -and [string]$reportErrorForFallback -match 'Candidate UI window disappeared during completion polling'))) {
            $fallback = Invoke-RebootResumeWpfFallback -Context $Context -Session $session -DriverReport $report
            $report = [pscustomobject]@{ status='PASS'; action=$Action; role=$Role; candidateSha256=[string]$candidate.sha256; processId=$report.processId; windowTitle='durable completion fallback'; visibleNames=@('Durable reboot-resume completion verified'); actions=@($report.actions); diagnostics=@($report.diagnostics); mutationInvoked=$true; dispatcherResponsive=$true; completionVerified=$true; fallback=$fallback }
        }
        $acceptedStatuses=@('PASS');if($AllowRebootRequired){$acceptedStatuses+='REBOOT_REQUIRED'};if($DeferDurableCompletionFallback){$acceptedStatuses+='DURABLE_PENDING'}
        if ($reportStatus -notin $acceptedStatuses) {
            $names = [string]::Join(' | ', @($report.visibleNames))
            $actionLog = (@($report.actions) | ConvertTo-Json -Depth 8 -Compress)
            $reportErrorFound=$false;$reportErrorValue=Get-LifecycleProperty $report 'error' ([ref]$reportErrorFound);$reportError = if ($reportErrorFound) { [string]$reportErrorValue } else { 'WPF driver returned no error field.' }
            throw "Real WPF action did not pass for ${Action}: $reportError; visible=$names; actions=$actionLog; evidenceLocal=$localEvidence"
        }
        if($sentinels){$sentinelVerification=Test-GuestForeignSentinels -Session $session -Sentinels $sentinels}
        $overallStatus = switch ($reportStatus) {
            'REBOOT_REQUIRED' { 'REAL E2E REBOOT REQUIRED'; break }
            'DURABLE_PENDING' { 'REAL E2E DURABLE PENDING'; break }
            default { 'REAL E2E PASS' }
        }
    return [ordered]@{ status=$overallStatus; phase=$Context.phaseId; action=$Action; role=$Role; candidate=$candidate; stage=$stage; guest=$report; evidencePath=$localEvidence; remoteEvidencePath=$remoteReport; evidenceLabel=$safeEvidenceLabel; mutationAllowed=[bool]$AllowMutation;foreignSentinels=$sentinelVerification }
    } finally { if($session -and $sentinels){$sentinelCleanup=Remove-GuestForeignSentinels -Session $session -Sentinels $sentinels};if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue } }
}

function Invoke-PrimaryRolePhase {
    param([Parameter(Mandatory)][string]$ContextJson)
    $context = Read-PhaseContext $ContextJson
    $result = Invoke-ActualWpfAction -Context $context -Action 'Diagnostics' -Role 'Primary / Desktop' -AllowMutation:$false
    if ([string]$result.guest.role -ne 'Primary / Desktop') { throw 'Primary phase did not verify the exact Primary / Desktop role.' }
    if ([bool]$result.guest.mutationInvoked) { throw 'Primary phase diagnostics unexpectedly invoked a mutation.' }
    return [ordered]@{ status='REAL E2E PASS'; phase=$context.phaseId; contract='primary-role-diagnostics'; candidate=$result.candidate; role=$result.role; guest=$result.guest; evidencePath=$result.evidencePath }
}

function Invoke-SurrogateDisposablePhase {
    param([Parameter(Mandatory)][psobject]$Context)
    $result = Invoke-SupportedFreshInstallLifecycle -Context $Context -Role 'Laptop / Surrogate' -CompleteLifecycle
    if ([string]$result.guest.role -ne 'Laptop / Surrogate') { throw 'Disposable surrogate phase did not verify the Laptop / Surrogate role.' }
    if (-not [bool]$result.guest.mutationInvoked) { throw 'Disposable surrogate phase did not invoke the real mutation.' }
    if ([string]$result.status -ne 'REAL E2E PASS' -or -not [bool]$result.guest.completionVerified) {
        throw "SURROGATE-DISPOSABLE requires genuine final lifecycle PASS; observed $($result.status)."
    }
    return [ordered]@{status='REAL E2E PASS';phase='SURROGATE-DISPOSABLE';contract='disposable-laptop-surrogate-real-wpf-install';candidate=$result.candidate;role=$result.role;guest=$result.guest;evidencePath=$result.evidencePath;physicalSurfaceTouched=$false;testKitEligibility='EVIDENCE INPUT ONLY — RECONCILE DECIDES'}
}

function Invoke-TailscalePolicyPhase {
    param([Parameter(Mandatory)][psobject]$Context)
    $candidate=Assert-ExactCandidate $Context
    $configuredMode=[string]$Context.config.Tailscale.Mode
    if([string]$Context.phaseId -eq 'TAILSCALE-AUTH') {
        $session=$null
        try {
            $session=Connect-DevFleetGuest -VmId ([guid][string]$Context.vmId)
            $auth=Invoke-TailscaleAuthentication -Session $session -Config $Context.config.Tailscale
            if(-not [bool]$auth.authenticationAttempted -and [bool]$auth.userActionRequired) { throw "USER ACTION REQUIRED — TAILSCALE-AUTH: $([string]$auth.reason)." }
            Assert-TailscaleAuthenticationResult -Result $auth | Out-Null
            $status=Get-TailscaleGuestStatus -Session $session -ExpectedNodePattern ([string]$Context.config.Tailscale.ExpectedGuestNodePattern)
            if(-not (Test-TailscaleConnected -Status $status)) { throw 'TAILSCALE-AUTH provider reported success but the guest is not connected.' }
            return [ordered]@{status='REAL E2E PASS';phase=[string]$Context.phaseId;contract='explicit-authkey-provider';configuredMode=$configuredMode;candidate=$candidate;guest=$status;authenticationAttempted=$true;authenticationSucceeded=$true;credentialsStoredInEvidence=$false;userActionRequired=$false}
        }finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
    }
    if($configuredMode -ne 'Deferred'){throw 'USER ACTION REQUIRED — configured Tailscale policy requires the official interactive authentication boundary.'}
    $session=$null
    try{
        $session=Connect-DevFleetGuest -VmId ([guid][string]$Context.vmId)
        $status=Get-TailscaleGuestStatus -Session $session -ExpectedNodePattern ([string]$Context.config.Tailscale.ExpectedGuestNodePattern)
        if([bool]$status.online -or -not[bool]$status.needsLogin){throw 'Deferred Tailscale policy expected an installed but unauthenticated guest.'}
        if([string]::IsNullOrWhiteSpace([string]$status.version) -or [string]$status.version -match 'not recognized|not found'){throw 'Deferred Tailscale policy could not verify the installed Tailscale client.'}
        return [ordered]@{status='REAL E2E PASS';phase=[string]$Context.phaseId;contract=if([string]$Context.phaseId -eq 'TAILSCALE-DEFERRED'){'installed-client-deferred-no-auth'}else{'authentication-explicitly-not-run-by-supported-deferred-policy'};configuredMode=$configuredMode;candidate=$candidate;guest=$status;authenticationAttempted=$false;credentialsStoredInEvidence=$false;userActionRequired=$false}
    }finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
}

function Invoke-LinuxBootstrapPhase {
    param([Parameter(Mandatory)][string]$ContextJson)
    $context = Read-PhaseContext $ContextJson
    $candidate = Assert-ExactCandidate $context
    $tarPath = [string]$context.candidate.tar.path
    if (-not (Test-Path -LiteralPath $tarPath -PathType Leaf)) { throw "Linux phase TAR is missing: $tarPath" }
    $tarHash = (Get-FileHash -LiteralPath $tarPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($tarHash -ne [string]$context.candidate.tar.sha256) { throw 'Linux phase TAR hash differs from the exact candidate tuple.' }
    $aiBundle = $null
    $aiBundleFound=$false;$aiBundleValue=Get-LifecycleProperty $context 'aiAuditZip' ([ref]$aiBundleFound);if ($aiBundleFound -and $aiBundleValue) {
        $aiPathFound=$false;$aiPathValue=Get-LifecycleProperty $aiBundleValue 'path' ([ref]$aiPathFound);$aiHashFound=$false;$aiHashValue=Get-LifecycleProperty $aiBundleValue 'sha256' ([ref]$aiHashFound);$aiBundlePath = [string]$aiPathValue
        $expectedAiBundleHash = ([string]$aiHashValue).ToLowerInvariant()
        if (-not (Test-Path -LiteralPath $aiBundlePath -PathType Leaf)) { throw "Focused Linux AI audit bundle is missing: $aiBundlePath" }
        if ($expectedAiBundleHash -notmatch '^[0-9a-f]{64}$') { throw 'Focused Linux AI audit bundle is missing an exact SHA-256 identity.' }
        $actualAiBundleHash = (Get-FileHash -LiteralPath $aiBundlePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualAiBundleHash -ne $expectedAiBundleHash) { throw 'Focused Linux AI audit bundle hash differs from the supplied exact identity.' }
        $aiBundle = [ordered]@{path=(Resolve-Path -LiteralPath $aiBundlePath).Path;sha256=$actualAiBundleHash;bytes=(Get-Item -LiteralPath $aiBundlePath).Length}
    }
    if ([string]$context.vmName -notlike 'DevFleet-E2E-*') { throw 'LINUX phase requires an ownership-scoped disposable L1.' }
    if ($env:COMPUTERNAME -notmatch '^MULATTOTechBOX$|^MULATTOTECHBOX$' -or $env:COMPUTERNAME -match 'SURFACE') { throw 'LINUX phase is not running on the approved MULATTOTECHBOX host.' }
    $l1 = Get-VM -Id ([guid][string]$context.vmId) -ErrorAction Stop
    if ($l1.Name -cne [string]$context.vmName) { throw 'LINUX phase disposable L1 identity/name mismatch.' }
    $vmProcessor = Get-VMProcessor -VM $l1 -ErrorAction Stop
    if (-not [bool]$vmProcessor.ExposeVirtualizationExtensions) { throw 'Disposable L1 does not expose nested virtualization.' }
    $nested = $context.config.NestedLinux
    if (-not $nested) { throw 'E2E config is missing the NestedLinux resource policy.' }
    $l2Name = [string]$nested.Name
    $l2Image = [string]$nested.UbuntuImage
    $l2Cpus = [int]$nested.Cpus
    $l2Memory = [string]$nested.Memory
    $l2Disk = [string]$nested.Disk
    $budgetPolicy = Get-HarnessBudgetPolicy -Config $context.config
    $l2BootstrapTimeout = [int]$budgetPolicy.operationMaximumsSeconds.guestBootstrap
    if ($l2Name -notlike 'DevFleet-E2E-*' -or $l2Name -eq ([string]$context.vmName)) { throw 'Nested Linux identity is outside the disposable E2E namespace.' }
    if ($l2Cpus -lt 1 -or $l2BootstrapTimeout -lt 1) { throw 'Nested Linux resource policy contains an invalid positive integer.' }
    # Each FullRelease phase restores its declared checkpoint independently.
    # The clean checkpoint intentionally has no product prerequisites, so the
    # Linux phase must exercise the candidate's real install path in this same
    # phase before asking the installed L1 to provide Multipass.
    $productInstall = Invoke-SupportedFreshInstallLifecycle -Context $context -Role 'Primary / Desktop' -CompleteLifecycle
    if ([string]$productInstall.status -ne 'REAL E2E PASS' -or -not [bool]$productInstall.guest.completionVerified) {
        throw "LINUX requires a genuine supported FreshInstall lifecycle PASS before Multipass; observed $($productInstall.status)."
    }
    $session = $null
    try {
        $session = Connect-DevFleetGuest -VmId ([guid][string]$context.vmId)
        $remoteRoot = "C:\Users\Public\DevFleet-E2E\$($context.runId)\$($context.phaseId)"
        $remoteTar = Join-Path $remoteRoot (Split-Path -Leaf $tarPath)
        Invoke-Command -Session $session -ScriptBlock { param($root) New-Item -ItemType Directory -Force -Path $root | Out-Null } -ArgumentList $remoteRoot
        $stage = Get-StageIntegrity -LocalPath $tarPath -Session $session -RemotePath $remoteTar
        if (-not $stage.equal) { throw 'Exact candidate TAR did not survive host-to-L1 staging.' }
        $remoteAiBundle = $null
        $aiBundleStage = $null
        if ($aiBundle) {
            $remoteAiBundle = Join-Path $remoteRoot (Split-Path -Leaf ([string]$aiBundle.path))
            $aiBundleStage = Get-StageIntegrity -LocalPath ([string]$aiBundle.path) -Session $session -RemotePath $remoteAiBundle
            if (-not $aiBundleStage.equal -or ([string]$aiBundleStage.remoteSha256).ToLowerInvariant() -ne [string]$aiBundle.sha256) { throw 'Exact AI audit ZIP did not survive host-to-L1 staging.' }
        }
        $secretJson = [ordered]@{
            NodeName=$l2Name; NodeRole='surrogate'; FriendlyName='DevFleet E2E Linux'; PortalPort=8787
            DeploymentId=("e2e-$($context.runId)"); NodeId=([guid]::NewGuid().ToString()); CoordinatorNodeId=''
            ProtocolVersion=1; AdminUser='e2e-admin'; AdminPassword=('E2E-' + [guid]::NewGuid().ToString('N')); ApiToken=('e2e-token-' + [guid]::NewGuid().ToString('N'))
            GitName='DevFleet E2E'; GitEmail='e2e@example.invalid'; OllamaBaseUrl=''; OllamaModel='e2e-disabled'; OllamaProfile='stable-interactive'
            DevelopmentProfile='strict'; DockerMode='rootless'; EnableSharedCaches=$false; EnableAnalyzerCache=$true; AutoStartCodexPro=$false
            AllowTailnetPorts=$false; BackupBeforeRebuild=$false; BackupBeforeQuarantine=$true; BackupIntervalMinutes=15; PackageVersion=$context.candidate.releaseVersion
        } | ConvertTo-Json -Compress
        $linuxResult = Invoke-Command -Session $session -ScriptBlock {
            param($remoteTarPath,$expectedTarHash,$runId,$phaseId,$l2,$image,$cpus,$memory,$disk,$secret,$timeoutSeconds,$remoteAiBundlePath,$expectedAiBundleHash)
            $ErrorActionPreference='Stop'
            # Resolve the same trusted machine locations used by the shipping
            # product. PATH/App Execution Alias discovery is not sufficient for
            # a freshly-installed guest and can race the vendor service setup.
            $mpCandidates=@(
                (Join-Path $env:ProgramFiles 'Multipass\bin\multipass.exe'),
                (Join-Path ${env:ProgramFiles(x86)} 'Multipass\bin\multipass.exe')
            ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) }
            $mp=$mpCandidates | Select-Object -First 1
            if (-not $mp) {
                $mpCommand=Get-Command multipass.exe -ErrorAction SilentlyContinue
                if (-not $mpCommand) { $mpCommand=Get-Command multipass -ErrorAction SilentlyContinue }
                if ($mpCommand) { $mp=$mpCommand.Source }
            }
            if (-not $mp) { throw 'The real Desktop candidate path did not provide Multipass inside disposable L1.' }
            $started=$false; $marker="/etc/devfleet-e2e-run-$runId"; $lastOperation='initialization'; $lastMpResult=$null; $cloudInitPath=$null; $nestedDeadline=[DateTime]::UtcNow.AddSeconds($timeoutSeconds)
            $result=[ordered]@{status='FAIL';runId=$runId;phase=$phaseId;l1TarSha256=$null;l2TarSha256=$null;l2Name=$l2;ubuntu=$null;multipassVersion=$null;cloudInitSource='exact-candidate-tar:cloud-init/compute.yaml';cloudInitRenderedSha256=$null;cloudInitStatus=$null;devrunnerIdentityPreBootstrap=$false;bootstrapExitCode=$null;bootstrapLogExcerpt=@();postconditions=@{};aiAuditBundle=if($remoteAiBundlePath){[ordered]@{status='PENDING';expectedSha256=$expectedAiBundleHash}}else{[ordered]@{status='NOT REQUESTED'}};failureOperation=$null;lastMultipassCommand=$null;cleanup=$null}
            function Invoke-Mp([string[]]$Arguments,[switch]$DoNotRecord) {
                $remaining=[int][math]::Floor(($nestedDeadline-[DateTime]::UtcNow).TotalSeconds)
                if($remaining -le 0){throw 'Nested Multipass owning deadline expired before starting the next operation.'}
                $effective=[math]::Min(900,$remaining)
                $psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName=$mp;$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
                foreach($argument in $Arguments){[void]$psi.ArgumentList.Add([string]$argument)}
                $process=[Diagnostics.Process]::new();$process.StartInfo=$psi;$out=@();$code=-1
                try{
                    if(-not $process.Start()){throw 'Unable to start Multipass operation.'}
                    $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
                    if(-not $process.WaitForExit($effective*1000)){try{$process.Kill($true)}catch{};try{[void]([Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]]@($stdout,$stderr)).Wait([TimeSpan]::FromSeconds(5)))}catch{};throw "Multipass operation timed out after $effective seconds."}
                    try{[void]([Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]]@($stdout,$stderr)).Wait([TimeSpan]::FromSeconds(5)))}catch{}
                    $out=@($(if($stdout.Status -eq [Threading.Tasks.TaskStatus]::RanToCompletion){$stdout.GetAwaiter().GetResult()})+$(if($stderr.Status -eq [Threading.Tasks.TaskStatus]::RanToCompletion){$stderr.GetAwaiter().GetResult()}) -split "`r?`n" | ForEach-Object {[string]$_})
                    $code=[int]$process.ExitCode
                } finally {$process.Dispose()}
                $record=[pscustomobject]@{arguments=@($Arguments);output=@($out);exitCode=$code}
                if(-not $DoNotRecord){Set-Variable -Scope 1 -Name lastMpResult -Value $record}
                return $record
            }
            try {
                $l1Hash=(Get-FileHash -LiteralPath $remoteTarPath -Algorithm SHA256).Hash.ToLowerInvariant(); $result.l1TarSha256=$l1Hash
                if ($l1Hash -ne $expectedTarHash) { throw 'L1 TAR hash differs from exact candidate TAR.' }
                $lastOperation='inventory';$inventory=Invoke-Mp @('list','--format','json');if($inventory.exitCode -ne 0){throw "Multipass inventory failed: $($inventory.output -join ' ')"};$existing=$inventory.output -join "`n"
                if ($existing -match ('"name"\s*:\s*"' + [regex]::Escape($l2) + '"')) { throw "Nested VM identity already exists; refusing to adopt or mutate $l2." }
                $version=$null
                for($attempt=1;$attempt -le 30;$attempt++) {
                    $lastOperation='version-probe'
                    $version=Invoke-Mp @('version')
                    if($version.exitCode -eq 0){break}
                    if($attempt -lt 30){Start-Sleep -Seconds 2}
                }
                if($null -eq $version -or $version.exitCode -ne 0){throw "Multipass version probe failed after bounded retry: $($version.output -join ' ')"}
                $result.multipassVersion=($version.output -join ' ')
                # The shipping product creates the restricted devrunner account
                # through the exact candidate cloud-init template before invoking
                # bootstrap-compute.sh.  Exercise that same prerequisite here;
                # running the bootstrap against a raw Ubuntu image is not the
                # production provisioning contract.
                $lastOperation='cloud-init-template'
                $tarCommand=Get-Command tar.exe -ErrorAction SilentlyContinue
                if(-not $tarCommand){$tarCommand=Get-Command tar -ErrorAction SilentlyContinue}
                if(-not $tarCommand){throw 'Windows tar is unavailable for exact candidate cloud-init extraction.'}
                $previousErrorActionPreference=$ErrorActionPreference
                try{
                    $ErrorActionPreference='Continue'
                    $cloudTemplateOutput=@(& $tarCommand.Source -xOf $remoteTarPath 'cloud-init/compute.yaml' 2>&1|ForEach-Object{[string]$_})
                    $cloudTemplateExit=[int]$LASTEXITCODE
                }finally{$ErrorActionPreference=$previousErrorActionPreference}
                if($cloudTemplateExit -ne 0){throw "Exact candidate cloud-init extraction failed: $($cloudTemplateOutput -join ' ')"}
                $cloudTemplate=$cloudTemplateOutput -join "`n"
                if([string]::IsNullOrWhiteSpace($cloudTemplate)){throw 'Exact candidate cloud-init template is empty.'}
                $yamlNode="'"+$l2.Replace("'","''")+"'"
                $renderedCloudInit=$cloudTemplate.Replace('__NODE_NAME__',$yamlNode).Replace('__NODE_ROLE__',"'surrogate'").Replace('__GIT_NAME_SHELL__',"'DevFleet E2E'").Replace('__GIT_EMAIL_SHELL__',"'e2e@example.invalid'")
                if($renderedCloudInit -match '__[A-Z0-9_]+__'){throw 'Exact candidate cloud-init has unresolved placeholders.'}
                $cloudInitPath=Join-Path $env:TEMP "DevFleet-E2E-$runId-cloud-init.yaml"
                [IO.File]::WriteAllText($cloudInitPath,$renderedCloudInit,[Text.UTF8Encoding]::new($false))
                $result.cloudInitRenderedSha256=(Get-FileHash -LiteralPath $cloudInitPath -Algorithm SHA256).Hash.ToLowerInvariant()
                $lastOperation='launch'
                $launch=(Invoke-Mp @('launch',$image,'--name',$l2,'--cpus',[string]$cpus,'--memory',[string]$memory,'--disk',[string]$disk,'--cloud-init',$cloudInitPath)); if($launch.exitCode -ne 0){throw "Multipass launch failed: $($launch.output -join ' ')"}; $started=$true
                $lastOperation='run-marker'
                $mark=(Invoke-Mp @('exec',$l2,'--','bash','-lc',"echo '$runId' | sudo tee '$marker' >/dev/null")); if($mark.exitCode -ne 0){throw 'Unable to bind nested L2 to this E2E run.'}
                $lastOperation='cloud-init-ready'
                $cloudInitDeadline=(Get-Date).AddSeconds([math]::Min($timeoutSeconds,1200))
                $cloudInitDone=$false
                do{
                    $cloudProbe=Invoke-Mp @('exec',$l2,'--','bash','-lc','cloud-init status --format=json 2>&1 || cloud-init status 2>&1')
                    $cloudText=($cloudProbe.output -join "`n")
                    if($cloudProbe.exitCode -eq 0 -and $cloudText -match '(?im)("status"\s*:\s*"done"|^\s*status:\s*done\s*$)'){$cloudInitDone=$true;break}
                    if($cloudText -match '(?im)("status"\s*:\s*"(error|degraded|failed)"|^\s*status:\s*(error|degraded|failed)\s*$)'){throw "Exact candidate cloud-init failed: $cloudText"}
                    if((Get-Date)-lt $cloudInitDeadline){Start-Sleep -Seconds 5}
                }while((Get-Date)-lt $cloudInitDeadline)
                if(-not $cloudInitDone){throw "Exact candidate cloud-init did not finish before the bounded deadline: $cloudText"}
                $result.cloudInitStatus='done'
                $lastOperation='cloud-init-identity-contract'
                $identityProbe=Invoke-Mp @('exec',$l2,'--','bash','-lc','id -u devrunner >/dev/null && getent group devrunner >/dev/null')
                if($identityProbe.exitCode -ne 0){throw "Exact candidate cloud-init did not create the restricted devrunner identity: $($identityProbe.output -join ' ')"}
                $result.devrunnerIdentityPreBootstrap=$true
                $lastOperation='tar-transfer'
                $transfer=(Invoke-Mp @('transfer',$remoteTarPath,"${l2}:/tmp/devfleet-e2e-candidate.tar.gz")); if($transfer.exitCode -ne 0){throw "L1-to-L2 TAR transfer failed: $($transfer.output -join ' ')"}
                $lastOperation='tar-hash'
                $l2HashProbe=(Invoke-Mp @('exec',$l2,'--','sha256sum','/tmp/devfleet-e2e-candidate.tar.gz')); if($l2HashProbe.exitCode -ne 0){throw 'L2 TAR hash probe failed.'}; $l2Hash=((($l2HashProbe.output -join '').Trim() -split '\s+')[0]).ToLowerInvariant(); $result.l2TarSha256=$l2Hash
                if($l2Hash -ne $expectedTarHash){throw 'L2 TAR hash differs from exact candidate TAR.'}
                $lastOperation='payload-reset'
                $removePayload=(Invoke-Mp @('exec',$l2,'--','rm','-rf','/tmp/devfleet-e2e-payload')); if($removePayload.exitCode -ne 0){throw 'Unable to reset the exact candidate extraction directory in L2.'}
                $makePayload=(Invoke-Mp @('exec',$l2,'--','mkdir','-m','0755','/tmp/devfleet-e2e-payload')); if($makePayload.exitCode -ne 0){throw 'Unable to create the exact candidate extraction directory in L2.'}
                $lastOperation='payload-extraction'
                $extractArchive=(Invoke-Mp @('exec',$l2,'--','tar','-xzf','/tmp/devfleet-e2e-candidate.tar.gz','-C','/tmp/devfleet-e2e-payload')); if($extractArchive.exitCode -ne 0){throw 'Exact candidate extraction failed in L2.'}
                $lastOperation='entrypoint-probe'
                $entrypointProbe=(Invoke-Mp @('exec',$l2,'--','test','-f','/tmp/devfleet-e2e-payload/linux/bootstrap-compute.sh')); if($entrypointProbe.exitCode -ne 0){throw 'Exact candidate bootstrap entrypoint check failed in L2.'}
                $secretPath=Join-Path $env:TEMP "DevFleet-E2E-$runId-secrets.json"; [IO.File]::WriteAllText($secretPath,$secret,[Text.UTF8Encoding]::new($false))
                try {
                    $lastOperation='secret-transfer'
                    $secretTransfer=(Invoke-Mp @('transfer',$secretPath,"${l2}:/tmp/devfleet-e2e-secrets.json")); if($secretTransfer.exitCode -ne 0){throw 'Ephemeral synthetic secret transfer failed.'}
                    $bootstrapScriptPath=Join-Path $env:TEMP "DevFleet-E2E-$runId-bootstrap.sh"
                    $bootstrapScript=@'
#!/usr/bin/env bash
set +e
sudo chmod 600 /tmp/devfleet-e2e-secrets.json
timeout __TIMEOUT__ sudo bash /tmp/devfleet-e2e-payload/linux/bootstrap-compute.sh /tmp/devfleet-e2e-payload --secrets-stdin < /tmp/devfleet-e2e-secrets.json
code=$?
sudo rm -f /tmp/devfleet-e2e-secrets.json
exit "$code"
'@ -replace '__TIMEOUT__',[string]$timeoutSeconds
                    [IO.File]::WriteAllText($bootstrapScriptPath,$bootstrapScript,[Text.UTF8Encoding]::new($false))
                    $lastOperation='bootstrap-wrapper-transfer'
                    $bootstrapTransfer=(Invoke-Mp @('transfer',$bootstrapScriptPath,"${l2}:/tmp/devfleet-e2e-bootstrap.sh")); if($bootstrapTransfer.exitCode -ne 0){throw 'Ephemeral Linux bootstrap wrapper transfer failed.'}
                    $lastOperation='bootstrap'
                    $boot=Invoke-Mp @('exec',$l2,'--','bash','/tmp/devfleet-e2e-bootstrap.sh');$bootOutput=@($boot.output);$result.bootstrapExitCode=[int]$boot.exitCode; $result.bootstrapLogExcerpt=@($bootOutput | ForEach-Object {[string]$_} | Select-Object -Last 120 | ForEach-Object { if($_.Length -gt 400){$_.Substring(0,400)}else{$_} })
                    if($result.bootstrapExitCode -ne 0){throw 'Real Linux bootstrap returned a non-zero exit code.'}
                } finally { Remove-Item -LiteralPath $secretPath -Force -ErrorAction SilentlyContinue; if($bootstrapScriptPath){Remove-Item -LiteralPath $bootstrapScriptPath -Force -ErrorAction SilentlyContinue}; [void](Invoke-Mp -Arguments @('exec',$l2,'--','rm','-f','/tmp/devfleet-e2e-bootstrap.sh','/tmp/devfleet-e2e-secrets.json') -DoNotRecord) }
                $checkScriptPath=Join-Path $env:TEMP "DevFleet-E2E-$runId-postconditions.sh"
                $checkScript=@'
#!/usr/bin/env bash
set +e
overall=0
if (. /etc/os-release && test "$VERSION_ID" = "24.04"); then echo 'ubuntu=PASS'; else echo 'ubuntu=FAIL'; overall=1; fi
if test "$(ps -p 1 -o comm=)" = systemd; then echo 'systemd=PASS'; else echo 'systemd=FAIL'; overall=1; fi
if systemctl is-active --quiet devfleet.service; then echo 'service=PASS'; else echo 'service=FAIL'; overall=1; fi
if sudo -n -u devfleet-control -- test -s /etc/devfleet/config.json && sudo -n -u devfleet-control -- jq -e . /etc/devfleet/config.json >/dev/null; then echo 'config=PASS'; else echo 'config=FAIL'; overall=1; fi
uid=$(id -u devrunner)
if sudo -n -u devrunner test -S /run/user/$uid/docker.sock && sudo -n -u devrunner env HOME=/home/devrunner XDG_RUNTIME_DIR=/run/user/$uid DOCKER_HOST=unix:///run/user/$uid/docker.sock docker info --format '{{json .SecurityOptions}}' | grep -q rootless; then echo 'rootless=PASS'; else echo 'rootless=FAIL'; overall=1; fi
if sudo -n -u devfleet-control env DOCKER_HOST=unix:///run/user/$uid/docker.sock docker info >/dev/null; then echo 'controlSocket=PASS'; else echo 'controlSocket=FAIL'; overall=1; fi
if sudo -n -u devrunner env HOME=/home/devrunner XDG_RUNTIME_DIR=/run/user/$uid DOCKER_HOST=unix:///run/user/$uid/docker.sock docker run --rm hello-world >/dev/null; then echo 'container=PASS'; else echo 'container=FAIL'; overall=1; fi
if curl --fail --silent --show-error --connect-timeout 5 http://127.0.0.1:8787/healthz >/dev/null; then echo 'health=PASS'; else echo 'health=FAIL'; overall=1; fi
if test "$(sudo -n -u devfleet-control -- stat -c %U:%G:%a /etc/devfleet/config.json)" = root:devfleet-control:640 && test "$(sudo -n -u devfleet-control -- stat -c %U:%G:%a /etc/devfleet/secrets.env)" = root:devfleet-control:640; then echo 'ownership=PASS'; else echo 'ownership=FAIL'; overall=1; fi
if ! journalctl -k -b --no-pager 2>/dev/null | grep -Eiq 'out of memory|oom-killer|killed process'; then echo 'oom=PASS'; else echo 'oom=FAIL'; overall=1; fi
exit "$overall"
'@
                [IO.File]::WriteAllText($checkScriptPath,$checkScript,[Text.UTF8Encoding]::new($false))
                try {
                    $lastOperation='postcondition-transfer'
                    $checkTransfer=(Invoke-Mp @('transfer',$checkScriptPath,"${l2}:/tmp/devfleet-e2e-postconditions.sh")); if($checkTransfer.exitCode -ne 0){throw 'Linux postcondition script transfer failed.'}
                    $lastOperation='postconditions'
                    $check=Invoke-Mp @('exec',$l2,'--','bash','/tmp/devfleet-e2e-postconditions.sh');$checkOutput=@($check.output);$checkExit=[int]$check.exitCode
                    foreach($name in @('ubuntu','systemd','service','config','rootless','controlSocket','container','health','ownership','oom')) { $line=@($checkOutput | ForEach-Object {[string]$_} | Where-Object {$_ -match ('^'+[regex]::Escape($name)+'=(PASS|FAIL)$')} | Select-Object -Last 1); $pass=($line.Count -eq 1 -and [string]$line[0] -eq ($name+'=PASS')); $result.postconditions[$name]=[ordered]@{pass=[bool]$pass;output=$line}; if(-not $pass){throw "Linux postcondition failed: $name"} }
                    if($checkExit -ne 0){throw 'One or more Linux postconditions failed.'}
                } finally { Remove-Item -LiteralPath $checkScriptPath -Force -ErrorAction SilentlyContinue; [void](Invoke-Mp -Arguments @('exec',$l2,'--','rm','-f','/tmp/devfleet-e2e-postconditions.sh') -DoNotRecord) }
                if($remoteAiBundlePath){
                    $lastOperation='ai-bundle-transfer'
                    $aiTransfer=Invoke-Mp @('transfer',$remoteAiBundlePath,"${l2}:/tmp/devfleet-e2e-ai-audit.zip")
                    if($aiTransfer.exitCode -ne 0){throw "L1-to-L2 AI audit ZIP transfer failed: $($aiTransfer.output -join ' ')"}
                    $aiValidationScriptPath=Join-Path $env:TEMP "DevFleet-E2E-$runId-ai-bundle.sh"
                    $aiValidationScript=@'
#!/usr/bin/env bash
set -euo pipefail
expected_hash="$1"
archive=/tmp/devfleet-e2e-ai-audit.zip
extract_root="/tmp/devfleet e2e ai audit"
actual_hash="$(sha256sum "$archive" | awk '{print $1}')"
test "$actual_hash" = "$expected_hash"
rm -rf "$extract_root"
mkdir -m 0755 "$extract_root"
unzip -q "$archive" -d "$extract_root"
python3 - "$extract_root" <<'PY'
import json
import os
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
records = json.loads((root / "SOURCE-MODES.json").read_text(encoding="utf-8"))
failures = []
executable = 0
for record in records:
    path = root / record["path"]
    expected = int(record["posixMode"])
    if not path.is_file():
        failures.append(f"missing:{record['path']}")
        continue
    actual = stat.S_IMODE(path.stat().st_mode)
    if actual != expected:
        failures.append(f"mode:{record['path']}:{actual:04o}!={expected:04o}")
    executable += int(bool(record["executable"]))
if failures:
    raise SystemExit(";".join(failures[:20]))
print(json.dumps({"status":"PASS","modeRecords":len(records),"executableRecords":executable}, sort_keys=True))
PY
python3 "$extract_root/source/tools/validate_audit_coherence.py" --root "$extract_root"
python3 -m compileall -q "$extract_root/source" "$extract_root/automation"
while IFS= read -r -d '' script; do bash -n "$script"; done < <(find "$extract_root/source" "$extract_root/automation" -type f -name '*.sh' -print0)
printf 'aiBundle=PASS\n'
'@
                    [IO.File]::WriteAllText($aiValidationScriptPath,$aiValidationScript,[Text.UTF8Encoding]::new($false))
                    try{
                        $lastOperation='ai-bundle-validator-transfer'
                        $aiValidatorTransfer=Invoke-Mp @('transfer',$aiValidationScriptPath,"${l2}:/tmp/devfleet-e2e-ai-bundle.sh")
                        if($aiValidatorTransfer.exitCode -ne 0){throw 'AI audit Linux validator transfer failed.'}
                        $lastOperation='ai-bundle-linux-roundtrip'
                        $aiCheck=Invoke-Mp @('exec',$l2,'--','bash','/tmp/devfleet-e2e-ai-bundle.sh',$expectedAiBundleHash)
                        $aiOutput=@($aiCheck.output|ForEach-Object{[string]$_})
                        if($aiCheck.exitCode -ne 0 -or $aiOutput -notcontains 'aiBundle=PASS'){throw "AI audit Linux unzip/mode validation failed: $($aiOutput -join ' ')"}
                        $modeJson=@($aiOutput|Where-Object{$_ -match '^\{"executableRecords"'}|Select-Object -Last 1)
                        $coherenceJson=@($aiOutput|Where-Object{$_ -match '^\{"currentReleaseFingerprintId"'}|Select-Object -Last 1)
                        $result.aiAuditBundle=[ordered]@{status='PASS';sha256=$expectedAiBundleHash;standardUnzip=$true;pathWithSpaces=$true;modeInventory=if($modeJson){$modeJson|ConvertFrom-Json}else{$null};coherence=if($coherenceJson){$coherenceJson|ConvertFrom-Json}else{$null};pythonCompile=$true;bashSyntax=$true;output=@($aiOutput|Select-Object -Last 40)}
                    }finally{
                        Remove-Item -LiteralPath $aiValidationScriptPath -Force -ErrorAction SilentlyContinue
                        [void](Invoke-Mp -Arguments @('exec',$l2,'--','rm','-f','/tmp/devfleet-e2e-ai-bundle.sh','/tmp/devfleet-e2e-ai-audit.zip') -DoNotRecord)
                    }
                }
                $result.status='REAL E2E PASS'
            } catch {
                $errorMessage=[string]$_.Exception.Message
                $errorRecord=([string]($_ | Out-String)).Trim()
                if([string]::IsNullOrWhiteSpace($errorMessage)){$errorMessage=$errorRecord}
                if([string]::IsNullOrWhiteSpace($errorMessage) -and $lastMpResult){$errorMessage=(@($lastMpResult.output)-join ' ').Trim()}
                if([string]::IsNullOrWhiteSpace($errorMessage)){$errorMessage='Unknown nested Linux harness failure.'}
                $result.failureOperation=$lastOperation
                if($lastMpResult){$result.lastMultipassCommand=[ordered]@{arguments=@($lastMpResult.arguments);exitCode=[int]$lastMpResult.exitCode;output=@($lastMpResult.output|Select-Object -Last 40)}}
                $result.error="${lastOperation}: $errorMessage"
            }
            finally {
                if($cloudInitPath){Remove-Item -LiteralPath $cloudInitPath -Force -ErrorAction SilentlyContinue}
                if($started){
                    $boundFile=(Invoke-Mp @('exec',$l2,'--','test','-f',$marker))
                    $boundValue=(Invoke-Mp @('exec',$l2,'--','cat',$marker))
                    $bound=($boundFile.exitCode -eq 0 -and $boundValue.exitCode -eq 0 -and (($boundValue.output -join '').Trim() -eq $runId))
                    if($bound){ $deleted=(Invoke-Mp @('delete','--purge',$l2)); $gone=(Invoke-Mp @('list','--format','json')).output -join "`n"; $result.cleanup=[ordered]@{boundToRun=$true;deleteExitCode=$deleted.exitCode;absent=($gone -notmatch ('"name"\s*:\s*"' + [regex]::Escape($l2) + '"'));deleteOutput=(($deleted.output -join ' ') | Select-Object -Last 20)} }
                    else { $result.cleanup=[ordered]@{boundToRun=$false;absent=$false;error='L2 run marker was not positively verified; resource retained for manual cleanup.'} }
                } else { $result.cleanup=[ordered]@{boundToRun=$false;absent=$true;notCreated=$true} }
            }
            $result
        } -ArgumentList $remoteTar,$tarHash,$context.runId,$context.phaseId,$l2Name,$l2Image,$l2Cpus,$l2Memory,$l2Disk,$secretJson,$l2BootstrapTimeout,$remoteAiBundle,$(if($aiBundle){[string]$aiBundle.sha256}else{$null})
        $evidencePath = Join-Path ([string]$context.runDir) 'linux-l2-evidence.json'
        ($linuxResult | ConvertTo-Json -Depth 32) | Set-Content -LiteralPath $evidencePath -Encoding UTF8
        if ([string]$linuxResult.status -ne 'REAL E2E PASS') { throw "Real nested Linux E2E failed: $([string]$linuxResult.error); evidence=$evidencePath" }
        if (-not [bool]$linuxResult.cleanup.absent) { throw "Nested Linux cleanup was not positively verified; evidence=$evidencePath" }
        return [ordered]@{status='REAL E2E PASS';phase='LINUX';contract='nested-multipass-ubuntu-bootstrap-after-real-wpf-install';candidate=$candidate;productInstall=$productInstall;hostToL1=$stage;aiBundleHostToL1=$aiBundleStage;l1=$linuxResult.l1TarSha256;l2=$linuxResult;linuxEvidencePath=$evidencePath}
    } finally { if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue } }
}

function Invoke-DependencyMatrix {
    param([Parameter(Mandatory)][psobject]$Context)
    $scenarios = @('Healthy-WinGet','Outdated-Prerequisites','WinGet-Missing','WinGet-Broken','WinGet-Source-Broken','Official-Direct-Fallback','Valid-Nonstandard-Path')
    $records = [System.Collections.Generic.List[object]]::new()
    $healthy = Invoke-SupportedFreshInstallLifecycle -Context $Context -Role 'Primary / Desktop' -CompleteLifecycle
    [void]$records.Add([ordered]@{scenario='Healthy-WinGet';evidenceClass='REAL_DISPOSABLE_L1';status=[string]$healthy.status;candidate=$healthy.candidate;guest=$healthy.guest;condition='current trusted WinGet/dependency inventory';actualConditionProven=$true})
    if([string]$healthy.status -ne 'REAL E2E PASS' -or -not [bool]$healthy.guest.completionVerified){throw 'Healthy-WinGet did not complete the supported exact-candidate lifecycle.'}
    $workspace = if($Context.workspaceRoot){[string]$Context.workspaceRoot}else{(Resolve-Path (Join-Path $Context.runDir '..\..\..\..')).Path}
    $dotnet = Join-Path $workspace '.dotnet\dotnet.exe'
    if(-not(Test-Path -LiteralPath $dotnet -PathType Leaf)){throw "Explicit repository-local .NET SDK is missing: $dotnet"}
    $sdkVersion = (& $dotnet --version 2>&1 | Out-String).Trim()
    if($LASTEXITCODE -ne 0 -or $sdkVersion -ne '8.0.424'){throw "Dependency runner requires repository-local .NET SDK 8.0.424; observed '$sdkVersion'."}
    $sdkHash=(Get-FileHash -LiteralPath $dotnet -Algorithm SHA256).Hash.ToLowerInvariant()
    $sdkEvidence=[ordered]@{schemaVersion=1;contract='explicit-repository-local-dotnet-sdk';path=(Resolve-Path -LiteralPath $dotnet).Path;version=$sdkVersion;sha256=$sdkHash;source='repository-local .dotnet SDK';globalPathMutated=$false;capturedUtc=(Get-Date).ToUniversalTime().ToString('o')}
    Write-EvidenceJson -Path (Join-Path ([string]$Context.runDir) 'dotnet-sdk-evidence.json') -Value $sdkEvidence
    $runnerProject=Join-Path $workspace 'automation\release-e2e\tests\DependencyPolicyRunner\DependencyPolicyRunner.csproj'
    if(-not(Test-Path -LiteralPath $runnerProject -PathType Leaf)){throw 'Tooling-only dependency policy runner is missing.'}
    $steps=[ordered]@{}
    function Invoke-SdkStep([string]$Name,[string[]]$Arguments,[string]$Cwd) {
        $lines=@(& $dotnet @Arguments 2>&1 | ForEach-Object {[string]$_});$exit=[int]$LASTEXITCODE
        $steps[$Name]=[ordered]@{command=@($dotnet)+$Arguments;workingDirectory=$Cwd;exitCode=$exit;stdoutStderr=$lines}
        if($exit -ne 0){
            # Persist the failed step before throwing so a bounded tooling
            # blocker retains stdout/stderr and the exact command contract.
            Write-EvidenceJson -Path (Join-Path ([string]$Context.runDir) 'dependency-policy-runner.json') -Value ([ordered]@{schemaVersion=1;contract='restore-build-run-explicit-local-sdk';status='FAIL';failedStep=$Name;sdk=$sdkEvidence;project=$runnerProject;steps=$steps})
            throw "Dependency policy runner $Name failed with exit code $exit."
        }
        return $lines
    }
    $projectDir=Split-Path -Parent $runnerProject
    [void](Invoke-SdkStep 'restore' @('restore',$runnerProject,'--nologo') $workspace)
    [void](Invoke-SdkStep 'build' @('build',$runnerProject,'--configuration','Release','--nologo','-v:minimal') $workspace)
    $json=Invoke-SdkStep 'run' @('run','--project',$runnerProject,'--configuration','Release','--nologo') $workspace
    Write-EvidenceJson -Path (Join-Path ([string]$Context.runDir) 'dependency-policy-runner.json') -Value ([ordered]@{schemaVersion=1;contract='restore-build-run-explicit-local-sdk';sdk=$sdkEvidence;project=$runnerProject;steps=$steps})
    try{$adversarial=@(($json -join "`n")|ConvertFrom-Json)}catch{throw "Dependency policy runner returned invalid JSON: $($_.Exception.Message)"}
    $scenarioIds=@('WinGet-Missing','WinGet-Broken','WinGet-Source-Broken','Official-Direct-Fallback','Valid-Nonstandard-Path','Outdated-Prerequisites')
    if(@($adversarial.scenario|Sort-Object -Unique).Count -ne $scenarioIds.Count -or @($adversarial).Count -ne $scenarioIds.Count -or (@($adversarial.scenario|Sort-Object -Unique) -join '|') -ne (@($scenarioIds|Sort-Object) -join '|')){throw 'Dependency policy runner returned duplicate, missing, or unexpected scenario IDs.'}
    foreach($row in $adversarial){
        if([string]$row.status -ne 'PASS' -or [string]$row.evidenceClass -ne 'ADVERSARIAL_PRODUCT_POLICY' -or -not [bool]$row.actualConditionProven){throw "Dependency policy scenario did not prove its intended branch: $($row.scenario)."}
        [void]$records.Add($row)
    }
    if(@($records).Count -ne $scenarios.Count){throw 'Dependency matrix did not execute every required policy condition.'}
    return [ordered]@{status='PASS';phase=$Context.phaseId;scenarios=$scenarios;evidence=@($records);contract='one-real-healthy-L1-plus-adversarial-resolver-policy';runner=$runnerProject}
}

function Invoke-NestedProductScenario {
    param([Parameter(Mandatory)][psobject]$Context,[Parameter(Mandatory)][string]$Scenario)
    $candidate=Assert-ExactCandidate $Context
    $tarPath=[string]$Context.candidate.tar.path
    $tarHash=(Get-FileHash -LiteralPath $tarPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if($tarHash -ne [string]$Context.candidate.tar.sha256){throw "Exact candidate TAR changed before $($Context.phaseId)."}
    if([string]$Context.vmName -notlike 'DevFleet-E2E-*'){throw "$($Context.phaseId) requires an ownership-scoped disposable L1."}
    $localDriver=Join-Path $PSScriptRoot 'Invoke-ProductLifecycleScenario.py'
    if(-not(Test-Path -LiteralPath $localDriver -PathType Leaf)){throw 'Product lifecycle scenario driver is missing.'}
    $session=$null
    try{
        $session=Connect-DevFleetGuest -VmId ([guid][string]$Context.vmId)
        $remoteRoot="C:\Users\Public\DevFleet-E2E\$($Context.runId)\$($Context.phaseId)"
        $remoteTar=Join-Path $remoteRoot (Split-Path -Leaf $tarPath)
        $remoteDriver=Join-Path $remoteRoot 'Invoke-ProductLifecycleScenario.py'
        Invoke-Command -Session $session -ScriptBlock {param($path) New-Item -ItemType Directory -Path $path -Force|Out-Null} -ArgumentList $remoteRoot
        $stage=Get-StageIntegrity -LocalPath $tarPath -Session $session -RemotePath $remoteTar
        if(-not $stage.equal){throw 'Exact candidate TAR changed while staging to the disposable L1.'}
        Copy-Item -LiteralPath $localDriver -Destination $remoteDriver -ToSession $session -Force
        $driverHash=(Get-FileHash -LiteralPath $localDriver -Algorithm SHA256).Hash.ToLowerInvariant()
        $guestResult=Invoke-Command -Session $session -ScriptBlock {
            param($tar,$expectedTarHash,$driver,$expectedDriverHash,$runId,$phaseId,$scenario)
            $ErrorActionPreference='Stop'
            if($env:COMPUTERNAME -notlike 'DEVFLEET-E2E-*'){throw 'Product scenario is not running inside the disposable L1.'}
            if((Get-FileHash -LiteralPath $tar -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedTarHash){throw 'L1 candidate TAR hash mismatch.'}
            if((Get-FileHash -LiteralPath $driver -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedDriverHash){throw 'L1 scenario driver hash mismatch.'}
            $configPath='C:\ProgramData\DevFleet\devfleet.config.json'
            $identityPath='C:\ProgramData\DevFleet\node-identity.json'
            if(-not(Test-Path -LiteralPath $configPath -PathType Leaf) -or -not(Test-Path -LiteralPath $identityPath -PathType Leaf)){throw 'Installed DevFleet L1 configuration or deployment identity is missing.'}
            $config=Get-Content -LiteralPath $configPath -Raw|ConvertFrom-Json
            $hostIdentity=Get-Content -LiteralPath $identityPath -Raw|ConvertFrom-Json
            $primary=[string]$config.Primary.InstanceName
            if($primary -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$' -or -not [string]$hostIdentity.deployment_id){throw 'Installed Primary/deployment identity is invalid.'}
            $expectedMultipass=Join-Path $env:ProgramFiles 'Multipass\bin\multipass.exe'
            $multipass=@(Get-Command multipass.exe -All -ErrorAction Stop|Where-Object{$_.Source -ceq $expectedMultipass})
            if($multipass.Count -ne 1){throw 'Trusted machine Multipass resolution is ambiguous or missing inside L1.'}
            $mp=$multipass[0].Source
            $inventoryRaw=@(& $mp list --format json 2>&1);if($LASTEXITCODE -ne 0){throw 'Multipass inventory failed inside L1.'}
            $inventory=($inventoryRaw -join "`n")|ConvertFrom-Json
            $instances=@($inventory.list|Where-Object name -ceq $primary)
            if($instances.Count -ne 1){throw "Expected exactly one configured Primary instance inside L1; found $($instances.Count)."}
            & $mp start $primary 2>&1|Out-Null;if($LASTEXITCODE -ne 0){throw 'Configured Primary instance could not be started.'}
            $safeRun=($runId -replace '[^A-Za-z0-9-]','')
            $safePhase=($phaseId -replace '[^A-Za-z0-9-]','')
            $l2Root="/tmp/devfleet-e2e/$safeRun/$safePhase"
            if($l2Root -notmatch '^/tmp/devfleet-e2e/e2e-[A-Za-z0-9-]+/[A-Z0-9-]+$'){throw 'Nested scenario root failed ownership validation.'}
            $l2Tar="$l2Root/candidate.tar.gz";$l2Driver="$l2Root/Invoke-ProductLifecycleScenario.py"
            try{
                & $mp exec $primary -- sudo rm -rf -- $l2Root 2>&1|Out-Null
                & $mp exec $primary -- sudo install -d -m 0755 $l2Root "$l2Root/source" 2>&1|Out-Null;if($LASTEXITCODE -ne 0){throw 'Nested scenario root could not be created.'}
                & $mp transfer $tar "$primary`:$l2Tar" 2>&1|Out-Null;if($LASTEXITCODE -ne 0){throw 'Candidate TAR transfer from L1 to Primary failed.'}
                & $mp transfer $driver "$primary`:$l2Driver" 2>&1|Out-Null;if($LASTEXITCODE -ne 0){throw 'Scenario driver transfer from L1 to Primary failed.'}
                $l2Hash=(@(& $mp exec $primary -- sha256sum $l2Tar 2>&1)|Select-Object -Last 1).ToString().Split(' ')[0].ToLowerInvariant()
                if($LASTEXITCODE -ne 0 -or $l2Hash -ne $expectedTarHash){throw 'L2 candidate TAR hash differs from host/L1 identity.'}
                & $mp exec $primary -- sudo tar -xzf $l2Tar -C "$l2Root/source" 2>&1|Out-Null;if($LASTEXITCODE -ne 0){throw 'Exact candidate extraction failed in Primary.'}
                $sourceRoot="$l2Root/source"
                & $mp exec $primary -- test -f "$sourceRoot/VERSION" 2>&1|Out-Null
                if($LASTEXITCODE -ne 0){throw 'Exact candidate extraction did not produce the canonical source root.'}
                $python=(@(& $mp exec $primary -- bash -lc "for p in /opt/devfleet/venv/bin/python /opt/devfleet/venv/bin/python3; do test -x \"`$p\" && echo \"`$p\" && exit 0; done; exit 1" 2>&1)|Select-Object -Last 1).ToString()
                if($LASTEXITCODE -ne 0 -or -not $python.StartsWith('/opt/devfleet/venv/bin/python')){throw 'Installed DevFleet Python runtime is unavailable in Primary.'}
                $raw=@(& $mp exec $primary -- sudo -u devfleet-control env HOME=/nonexistent $python $l2Driver --source-root $sourceRoot --run-id $runId --scenario $scenario 2>&1)
                $exit=$LASTEXITCODE
                $jsonLine=@($raw|ForEach-Object{[string]$_}|Where-Object{$_.TrimStart().StartsWith('{')}|Select-Object -Last 1)
                if($jsonLine.Count -ne 1){throw "Product scenario returned no structured result: $((@($raw)|Select-Object -Last 8)-join ' | ')"}
                $scenarioResult=$jsonLine[0]|ConvertFrom-Json
                if($exit -ne 0 -or [string]$scenarioResult.status -ne 'PASS'){throw "Product scenario failed: $([string]$scenarioResult.error)"}
                $guestIdentityRaw=@(& $mp exec $primary -- sudo cat /etc/devfleet/node-identity.json 2>&1);if($LASTEXITCODE -ne 0){throw 'Primary node identity could not be read.'}
                $guestIdentity=($guestIdentityRaw -join "`n")|ConvertFrom-Json
                if([string]$guestIdentity.deployment_id -ne [string]$hostIdentity.deployment_id){throw 'Primary deployment identity differs from the owning L1 deployment.'}
                return [ordered]@{status='PASS';scenario=$scenario;l1=[ordered]@{computer=$env:COMPUTERNAME;deploymentId=[string]$hostIdentity.deployment_id};primary=[ordered]@{name=$primary;deploymentId=[string]$guestIdentity.deployment_id;nodeId=[string]$guestIdentity.node_id};tarSha256=[ordered]@{l1=$expectedTarHash;l2=$l2Hash};product=$scenarioResult;secretsInEvidence=$false}
            }finally{
                & $mp exec $primary -- sudo rm -rf -- $l2Root 2>&1|Out-Null
                Remove-Item -LiteralPath (Split-Path -Parent $tar) -Recurse -Force -ErrorAction SilentlyContinue
            }
        } -ArgumentList $remoteTar,$tarHash,$remoteDriver,$driverHash,[string]$Context.runId,[string]$Context.phaseId,$Scenario
        $evidencePath=Join-Path ([string]$Context.runDir) ("$($Context.phaseId.ToLowerInvariant())-product-evidence.json")
        [IO.File]::WriteAllText($evidencePath,(($guestResult|ConvertTo-Json -Depth 32)+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))
        return [ordered]@{status='REAL E2E PASS';phase=[string]$Context.phaseId;contract='exact-candidate-product-lifecycle-in-owned-primary';candidate=$candidate;scenario=$Scenario;guest=$guestResult;evidencePath=$evidencePath}
    }finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
}

function Invoke-DisposableSyntheticRebootProbe {
    <# Independent harness probe. It owns only a run-scoped PFRO trigger and
       never reads, creates, or advances a product lifecycle checkpoint. #>
    param([Parameter(Mandatory)][psobject]$Context)
    if([string]$Context.vmName -notlike 'DevFleet-E2E-*'){throw 'Synthetic reboot probe requires an ownership-scoped disposable L1.'}
    $session=$null
    try {
        $session=Connect-DevFleetGuest -VmId ([guid][string]$Context.vmId)
        $baseline=Invoke-Command -Session $session -ScriptBlock {
            $pfr=@((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations)
            $meaningful=@($pfr|Where-Object{-not [string]::IsNullOrWhiteSpace([string]$_)});$pairs=@();for($i=0;$i -lt $pfr.Count;$i+=2){$pairs+=[ordered]@{source=[string]$pfr[$i];destination=if($i+1 -lt $pfr.Count){[string]$pfr[$i+1]}else{''}}}
            [ordered]@{boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');pendingCount=$meaningful.Count;pendingFileRenameOperationsPresent=($meaningful.Count -gt 0);pairs=$pairs}
        }
        $pre=Invoke-Command -Session $session -ScriptBlock {
            param($runId,$phaseId)
            $safeRun=$runId -replace '[^A-Za-z0-9-]','';$safePhase=$phaseId -replace '[^A-Za-z0-9-]',''
            $root="C:\Users\Public\DevFleet-E2E\$safeRun\$safePhase\synthetic-reboot";$source=Join-Path $root 'source.bin';$destination=Join-Path $root 'destination.bin'
            New-Item -ItemType Directory -Force -Path $root|Out-Null;[IO.File]::WriteAllText($source,'DevFleet synthetic reboot probe')
            if(-not ('DevFleetE2EMoveFile' -as [type])){Add-Type @'
using System.Runtime.InteropServices;
public static class DevFleetE2EMoveFile { [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool MoveFileEx(string a,string b,int f); }
'@}
            if(-not [DevFleetE2EMoveFile]::MoveFileEx($source,$destination,4)){throw 'MoveFileEx synthetic trigger failed.'}
            $os=Get-CimInstance Win32_OperatingSystem;[ordered]@{source=$source;destination=$destination;boot=$os.LastBootUpTime.ToUniversalTime().ToString('o');queued=$true}
        } -ArgumentList ([string]$Context.runId),([string]$Context.phaseId)
        try{Invoke-Command -Session $session -ScriptBlock {Restart-Computer -Force} -ErrorAction Stop|Out-Null}catch{}
    }finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
    Start-Sleep -Seconds 10;$post=$null;$lastError='';$deadline=(Get-Date).AddMinutes(5)
    do {$probe=$null;try{$probe=Connect-DevFleetGuest -VmId ([guid][string]$Context.vmId);$post=Invoke-Command -Session $probe -ScriptBlock {$os=Get-CimInstance Win32_OperatingSystem;[ordered]@{boot=$os.LastBootUpTime.ToUniversalTime().ToString('o')}};if([datetime]$post.boot -le [datetime]$pre.boot){$post=$null}}catch{$lastError=$_.Exception.Message}finally{if($probe){Remove-PSSession $probe -ErrorAction SilentlyContinue}};if(-not $post){Start-Sleep -Seconds 5}}while(-not $post -and (Get-Date)-lt $deadline)
    if(-not $post){throw "Synthetic reboot probe did not observe a changed boot identity: $lastError"}
    $settlementSession=$null;$settled=$null
    try{$settlementSession=Connect-DevFleetGuest -VmId ([guid][string]$Context.vmId);$settled=Invoke-Command -Session $settlementSession -ScriptBlock {param($source,$destination,$baselinePairs)$pfr=@((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations);$meaningful=@($pfr|Where-Object{-not [string]::IsNullOrWhiteSpace([string]$_)});$pairs=@();for($i=0;$i -lt $pfr.Count;$i+=2){$pairs+=[ordered]@{source=[string]$pfr[$i];destination=if($i+1 -lt $pfr.Count){[string]$pfr[$i+1]}else{''}}};$keys=@($pairs|ForEach-Object{"$($_.source)`n$($_.destination)"});$baseKeys=@($baselinePairs|ForEach-Object{"$($_.source)`n$($_.destination)"});[ordered]@{sourceExists=(Test-Path -LiteralPath $source -PathType Leaf);destinationExists=(Test-Path -LiteralPath $destination -PathType Leaf);pendingCount=$meaningful.Count;pendingFileRenameOperationsMeaningfulCount=$meaningful.Count;unrelatedEntriesPreserved=(@($baseKeys|Where-Object{$keys -contains $_}).Count -eq $baseKeys.Count);pairs=$pairs}} -ArgumentList ([string]$pre.source),([string]$pre.destination),@($baseline.pairs)}finally{if($settlementSession){Remove-PSSession $settlementSession -ErrorAction SilentlyContinue}}
    if([bool]$settled.sourceExists -or -not [bool]$settled.destinationExists){throw 'Synthetic reboot run-owned delayed operation did not settle.'}
    # Windows may legitimately consume unrelated pending operations while the
    # owned operation settles. Never delete or rewrite foreign state; retain a
    # before/after comparison for audit and make the ownership-specific verdict
    # the gate.
    $settled.unrelatedStateChangedByHarness=$false
    $settled.unrelatedStatePreserved=[bool]$settled.unrelatedEntriesPreserved
    $settled.ownershipSpecificVerdict='PASS'
    $evidence=[ordered]@{status='PASS';phase='SYNTHETIC-REBOOT-PROBE';contract='run-owned-PFRO-only';baseline=$baseline;preBoot=$pre;postBoot=$post;settlement=$settled;bootIdentityChanged=$true;interactiveDesktop=[ordered]@{status='NOT_APPLICABLE';reason='Synthetic probe does not launch product UI.'};productLifecycleTouched=$false}
    $path=Join-Path ([string]$Context.runDir) 'synthetic-reboot-probe.json';Write-EvidenceJson -Path $path -Value $evidence;$evidence.evidencePath=$path;return $evidence
}

function Invoke-RebootResumePhase {
    param([Parameter(Mandatory)][psobject]$Context,[psobject]$InitialResult,[scriptblock]$WpfProvider,[scriptblock]$TransitionProvider,[scriptblock]$RebootProvider,[scriptblock]$SettleProvider)
    $synthetic=$null
    $skipFound=$false;$skipSynthetic=Get-LifecycleProperty $Context 'skipSyntheticReboot' ([ref]$skipFound);if(-not ($skipFound -and [bool]$skipSynthetic)){
        $syntheticProviderFound=$false;$syntheticProvider=Get-LifecycleProperty $Context 'syntheticRebootProvider' ([ref]$syntheticProviderFound);if($syntheticProviderFound){$synthetic=&$syntheticProvider ([pscustomobject]@{context=$Context;phaseId=(Get-LifecycleProperty $Context 'phaseId' ([ref]$skipFound))})}else{$synthetic=Invoke-DisposableSyntheticRebootProbe -Context $Context}
        $syntheticStatusFound=$false;$syntheticStatus=Get-LifecycleProperty $synthetic 'status' ([ref]$syntheticStatusFound);if(-not $syntheticStatusFound -or [string]$syntheticStatus -ne 'PASS'){throw 'Synthetic reboot probe did not pass.'}
    }
    # The synthetic boundary and product lifecycle are independent proofs. The
    # product loop gets a new WPF process and owns every product generation.
    $product=Invoke-ProductFreshInstallLifecycle -Context $Context -Role 'Primary / Desktop' -WpfProvider $WpfProvider -TransitionProvider $TransitionProvider -RebootProvider $RebootProvider -SettleProvider $SettleProvider
    $productCandidate = if($product.PSObject.Properties['candidate']){$product.candidate}else{$Context.candidate}
    $productGuest = if($product.PSObject.Properties['guest']){$product.guest}else{$null}
    $productEvidence = if($product.PSObject.Properties['evidencePath']){$product.evidencePath}else{$null}
    $completionFound = $false
    $completionValue = Get-LifecycleProperty $product 'completionVerified' ([ref]$completionFound)
    $productCompletionVerified = $completionFound -and [bool]$completionValue
    $statusFound = $false
    $statusValue = Get-LifecycleProperty $product 'status' ([ref]$statusFound)
    $productStatus = if($statusFound){[string]$statusValue}elseif($productCompletionVerified){'REAL E2E PASS'}else{'TERMINAL_FAILURE'}
    if($productStatus -ne 'REAL E2E PASS' -or -not $productCompletionVerified){ return [ordered]@{status='TERMINAL_FAILURE';phase=[string]$Context.phaseId;contract='pure-product-lifecycle';completionVerified=$false;synthetic=$synthetic;product=$product;candidate=$productCandidate;guest=$productGuest;evidencePath=$productEvidence} }
    return [ordered]@{status='REAL E2E PASS';phase=[string]$Context.phaseId;contract=if($synthetic){'synthetic-probe-then-pure-product-lifecycle'}else{'pure-product-lifecycle'};synthetic=$synthetic;product=$product;candidate=$productCandidate;guest=$productGuest;evidencePath=$productEvidence}
}

function Invoke-ProductLifecycleConsumer {
    <# Actual phase dispatch seam used by focused tests and by consumers that
       need only the supported product lifecycle. #>
    param([Parameter(Mandatory)][psobject]$Context)
    $wpfProvider = if ($Context.PSObject.Properties['lifecycleWpfProvider']) { $Context.lifecycleWpfProvider } else { $null }
    $transitionProvider = if ($Context.PSObject.Properties['lifecycleTransitionProvider']) { $Context.lifecycleTransitionProvider } else { $null }
    $rebootProvider = if ($Context.PSObject.Properties['lifecycleRebootProvider']) { $Context.lifecycleRebootProvider } else { $null }
    $settleProvider = if ($Context.PSObject.Properties['lifecycleSettleProvider']) { $Context.lifecycleSettleProvider } else { $null }
    if((Get-ProductLifecycleConsumerMode -PhaseId ([string]$Context.phaseId)) -eq 'SYNTHETIC_THEN_PRODUCT'){
        return Invoke-RebootResumePhase -Context $Context -WpfProvider $wpfProvider -TransitionProvider $transitionProvider -RebootProvider $rebootProvider -SettleProvider $settleProvider
    }
    if((Get-ProductLifecycleConsumerMode -PhaseId ([string]$Context.phaseId)) -eq 'PRODUCT_ONLY'){
        return Invoke-ProductFreshInstallLifecycle -Context $Context -Role 'Primary / Desktop' -WpfProvider $wpfProvider -TransitionProvider $transitionProvider -RebootProvider $rebootProvider -SettleProvider $settleProvider
    }
    throw "No product lifecycle consumer dispatch exists for $($Context.phaseId)."
}

function Get-ProductLifecycleConsumerMode {
    param([Parameter(Mandatory)][string]$PhaseId)
    if($PhaseId -eq 'REBOOT-RESUME'){return 'SYNTHETIC_THEN_PRODUCT'}
    if($PhaseId -in @('LINUX','SURROGATE-DISPOSABLE','MAINTENANCE-READY-PROVISION','DEPENDENCY-MATRIX')){return 'PRODUCT_ONLY'}
    return 'NOT_APPLICABLE'
}

function Invoke-WindowsSentinelPhase {
    param([Parameter(Mandatory)][psobject]$Context)
    $result=Invoke-ActualWpfAction -Context $Context -Action 'Uninstall' -AllowMutation
    if([string]$result.foreignSentinels.status -ne 'PASS' -or -not [bool]$result.foreignSentinels.unchanged){throw 'Windows foreign sentinels did not survive the exact candidate destructive lifecycle.'}
    return [ordered]@{status='REAL E2E PASS';phase='WINDOWS-SENTINELS';contract='foreign-task-service-firewall-registry-file-survive-real-uninstall';candidate=$result.candidate;guest=$result.guest;sentinels=$result.foreignSentinels;evidencePath=$result.evidencePath}
}

function Invoke-AiBundlePhase {
    param([Parameter(Mandatory)][psobject]$Context)
    $candidate = Assert-ExactCandidate $Context
    $workspace = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..')).Path
    $builder = Join-Path $workspace 'tools\Build-AIAuditBundle.ps1'
    $archive = Join-Path $workspace ('outputs\DevFleet-v{0}-AI-Audit-LATEST.zip' -f $Context.candidate.releaseVersion)
    if (-not (Test-Path -LiteralPath $builder -PathType Leaf)) { throw 'Canonical AI audit builder is missing.' }
    $buildOutput = @(& (Get-Command pwsh.exe -ErrorAction Stop).Source -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $builder -Workspace $workspace 2>&1)
    $buildExit = $LASTEXITCODE
    $buildRawPath = Join-Path ([string]$Context.runDir) 'ai-bundle-build-output.txt'
    $buildOutput | ForEach-Object { [string]$_ } | Set-Content -LiteralPath $buildRawPath -Encoding UTF8
    if ($buildExit -ne 0 -or -not (Test-Path -LiteralPath $archive -PathType Leaf)) { throw "Canonical AI audit builder failed; evidence=$buildRawPath" }
    $validator = Join-Path $workspace 'source\tools\validate_ai_audit_bundle.py'
    $report = Join-Path ([string]$Context.runDir) 'ai-audit-bundle-self-test.json'
    & python $validator --archive $archive --report $report | Out-File -LiteralPath (Join-Path ([string]$Context.runDir) 'ai-bundle-validator-output.txt') -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { throw "Canonical AI audit validator failed; report=$report" }
    $manifest = "$archive.manifest.json"
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw 'Canonical AI audit sidecar manifest is missing.' }
    $bundleManifest = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
    if ([string]$bundleManifest.selfTest -ne 'PASS' -or [int]$bundleManifest.expectedSourceCount -ne [int]$bundleManifest.includedSourceCount) { throw 'Canonical AI audit source inventory is incomplete.' }
    $tarList = @(& tar.exe -tzf ([string]$Context.candidate.tar.path) 2>&1)
    if ($LASTEXITCODE -ne 0 -or @($tarList | Where-Object { $_ -match '(^|/)linux/bootstrap-compute\.sh$' }).Count -ne 1) { throw 'Standard TAR extraction cannot locate the exact Linux bootstrap entrypoint.' }
    return [ordered]@{status='REAL E2E PASS';phase='AI-BUNDLE';contract='current-candidate-audit-builder-validator';candidate=$candidate;archive=[ordered]@{path=$archive;bytes=[int64](Get-Item $archive).Length;sha256=(Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant();sourceCount=[int]$bundleManifest.includedSourceCount;validatorReport=$report};buildOutput=$buildRawPath;standardTarListing='PASS' }
}

function Invoke-ReconcilePhase {
    param([Parameter(Mandatory)][psobject]$Context)
    $candidate = Assert-ExactCandidate $Context
    $workspace = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..')).Path
    $head = (& git -C $workspace rev-parse HEAD).Trim()
    $manifest = Get-Content -LiteralPath (Join-Path $workspace 'outputs\final-artifact-hashes.json') -Raw | ConvertFrom-Json
    $state = Get-Content -LiteralPath (Join-Path $workspace 'finalization-state.json') -Raw | ConvertFrom-Json
    $release = Get-Content -LiteralPath (Join-Path $workspace 'outputs\release-fingerprint.json') -Raw | ConvertFrom-Json
    $tooling = Get-Content -LiteralPath (Join-Path $workspace 'outputs\tooling-fingerprint-current.json') -Raw | ConvertFrom-Json
    $currentShippingIdentity = [string]$state.shipping_input_identity
    if (-not $currentShippingIdentity -or [string]$state.candidate_git_commit -ne [string]$Context.candidate.gitCommit) { throw 'RECONCILE is missing independent repository-head/candidate identity.' }
    if ([string]$manifest.shippingInputIdentity -and [string]$manifest.shippingInputIdentity -ne $currentShippingIdentity) { throw 'RECONCILE shipping-input identity mismatch.' }
    foreach($pair in @(@('releaseFingerprintId',$Context.candidate.releaseFingerprintId,$manifest.releaseFingerprintId,$release.releaseFingerprintId,$tooling.releaseFingerprintId),@('toolingFingerprintId',$Context.candidate.toolingFingerprintId,$manifest.toolingFingerprintId,$release.toolingFingerprint.toolingFingerprintId,$tooling.toolingFingerprintId))){ if(@($pair[1..4] | ForEach-Object {[string]$_} | Select-Object -Unique).Count -ne 1){throw "RECONCILE identity mismatch: $($pair[0])"} }
    if (-not [bool]$state.candidate_is_current -or [bool]$state.source_changed_since_candidate -or [bool]$state.rebuild_required) { throw 'RECONCILE found a stale candidate state or rebuild requirement.' }
    $rows = @()
    $recordsPath = Join-Path ([string]$Context.runDir) 'fullrelease-phase-records.json'
    if (Test-Path -LiteralPath $recordsPath) { $rows = @(Get-Content -LiteralPath $recordsPath -Raw | ConvertFrom-Json) }
    $required = @('HOST-SAFETY','CANDIDATE-VERIFY','RESTORE-CLEAN','ESTABLISH-SESSION','DEPENDENCY-MATRIX','SECURITY-POISON','FRESH-INSTALL-WPF','PRIMARY','LINUX','HTTP-HOSTILE','MAINTENANCE-READY','WINDOWS-SENTINELS','REPAIR','CLEAN-REINSTALL','UNINSTALL','FACTORY-RESET','REBOOT-RESUME','PERMANENT-DELETE','DELETE-RESTORE','STOPPED-PROJECT','HOST-CONCURRENCY','OPERATION-RECOVERY','OWNERSHIP','VAULT','SURROGATE-DISPOSABLE','TAILSCALE-DEFERRED','TAILSCALE-AUTH','AI-BUNDLE')
    $missing=@($required | Where-Object { $row=$rows | Where-Object id -eq $_ | Select-Object -Last 1; -not $row -or [string]$row.status -ne 'PASS' })
    if($missing.Count){throw "RECONCILE found mandatory phases missing or not PASS: $($missing -join ', ')"}
    $maintenance=@('REPAIR','CLEAN-REINSTALL','UNINSTALL','FACTORY-RESET','REBOOT-RESUME') | ForEach-Object { $rows | Where-Object id -eq $_ | Select-Object -Last 1 }
    if(@($maintenance).Count -ne 5){throw 'RECONCILE maintenance count is not 5/5.'}
    return [ordered]@{status='REAL E2E PASS';phase='RECONCILE';contract='exact-candidate-final-state-reconciliation';candidate=$candidate;repositoryHead=$head;candidateCommit=[string]$state.candidate_git_commit;shippingInputIdentity=$currentShippingIdentity;identities=[ordered]@{releaseFingerprintId=$release.releaseFingerprintId;toolingFingerprintId=$tooling.toolingFingerprintId};candidateState=[ordered]@{candidateIsCurrent=$state.candidate_is_current;sourceChangedSinceCandidate=$state.source_changed_since_candidate;rebuildRequired=$state.rebuild_required};mandatoryPhaseCount=$required.Count;maintenance='5/5';recordsPath=$recordsPath }
}

function Invoke-RealProductPhase {
    param([Parameter(Mandatory)][string]$ContextJson)
    $context = Read-PhaseContext $ContextJson
    # Generic Diagnostics is not a contract proof for named lifecycle phases; every such phase below dispatches scenario-specific evidence.
    switch ([string]$context.phaseId) {
        'DEPENDENCY-MATRIX' { return Invoke-DependencyMatrix $context }
        'SECURITY-POISON' { return Invoke-ActualWpfAction $context 'Diagnostics' -AllowMutation }
        'FRESH-INSTALL-WPF' {
            $ui=Invoke-SupportedFreshInstallLifecycle -Context $context -Role 'Primary / Desktop' -CompleteLifecycle
            if([string]$ui.status -ne 'REAL E2E PASS' -or -not [bool]$ui.completionVerified){throw "FRESH-INSTALL-WPF requires verified lifecycle completion; observed $([string]$ui.status)."}
            return $ui
        }
        'PRIMARY' { throw 'PRIMARY must be dispatched by Invoke-PrimaryPhase.ps1, not the generic product driver.' }
        'LINUX' { throw 'LINUX must be dispatched by Invoke-LinuxPhase.ps1, not the generic product driver.' }
        'HTTP-HOSTILE' { throw 'HTTP-HOSTILE must be dispatched by Invoke-HttpHostilePhase.ps1, not the generic product driver.' }
        'REPAIR' { return Invoke-ActualWpfAction $context 'Repair' -AllowMutation }
        'CLEAN-REINSTALL' { return Invoke-ActualWpfAction $context 'CleanReinstall' -AllowMutation }
        'UNINSTALL' { return Invoke-ActualWpfAction $context 'Uninstall' -AllowMutation }
        'FACTORY-RESET' { return Invoke-ActualWpfAction $context 'FactoryReset' -AllowMutation }
        'REBOOT-RESUME' { return Invoke-RebootResumePhase $context }
        'MAINTENANCE-READY-PROVISION' { return Invoke-ProductLifecycleConsumer -Context $context }
        'PERMANENT-DELETE' { return Invoke-NestedProductScenario $context 'permanent-delete' }
        'DELETE-RESTORE' { return Invoke-NestedProductScenario $context 'delete-restore' }
        'STOPPED-PROJECT' { return Invoke-NestedProductScenario $context 'stopped-project' }
        'HOST-CONCURRENCY' { return Invoke-NestedProductScenario $context 'host-concurrency' }
        'OPERATION-RECOVERY' { return Invoke-NestedProductScenario $context 'operation-recovery' }
        'OWNERSHIP' { return Invoke-NestedProductScenario $context 'ownership' }
        'WINDOWS-SENTINELS' { return Invoke-WindowsSentinelPhase $context }
        'VAULT' { return Invoke-NestedProductScenario $context 'vault' }
        'SURROGATE-DISPOSABLE' { return Invoke-SurrogateDisposablePhase $context }
        'TAILSCALE-DEFERRED' { return Invoke-TailscalePolicyPhase $context }
        'TAILSCALE-AUTH' { return Invoke-TailscalePolicyPhase $context }
        'AI-BUNDLE' { return Invoke-AiBundlePhase $context }
        'RECONCILE' { return Invoke-ReconcilePhase $context }
        default { throw "No phase-specific product driver exists for $($context.phaseId)." }
    }
}

Export-ModuleMember -Function Invoke-RealProductPhase,Invoke-PrimaryRolePhase,Invoke-LinuxBootstrapPhase,Invoke-SupportedFreshInstallLifecycle,Invoke-ProductFreshInstallLifecycle,Invoke-DisposableSyntheticRebootProbe,Invoke-RebootResumePhase,Invoke-ProductLifecycleConsumer,Get-ProductLifecycleConsumerMode,Get-ProductLifecycleObservation,Wait-DevFleetProductLifecycleTransition,Test-ProductMeaningfulProgress,Test-RebootBoundaryIdentity,Get-DurableProgressClassification,Get-PhaseAwareBudgetSeconds
