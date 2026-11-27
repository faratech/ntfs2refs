#Requires -Version 7.2

function Get-HostedRoundFailures([Collections.IDictionary]$Row, [switch]$BeforeCleanup) {
    if ($Row.outcome -cnotin 'converted', 'ntfs-as-before') { 'conversion or recovery did not complete' }
    if ($Row.manifest_matches -isnot [bool] -or -not $Row.manifest_matches) { 'manifest comparison did not pass' }
    if ($Row.outcome -ceq 'converted' -and [string]::IsNullOrEmpty($Row.refs_version)) { 'ReFS version was not observed' }
    if ($Row.hold_at -and ($Row.reached_hold -isnot [bool] -or -not $Row.reached_hold)) { 'requested hold was not reached' }

    $observation = $Row.event_observation
    $start = [datetimeoffset]::MinValue
    $end = [datetimeoffset]::MinValue
    $partition = [guid]::Empty
    if ($observation -isnot [Collections.IDictionary] -or $observation.schema -ne 1 -or
        $observation.completed -isnot [bool] -or -not $observation.completed -or $Row.events -isnot [Collections.IList] -or
        $observation.target -isnot [Collections.IDictionary] -or -not $observation.target.image -or
        -not [guid]::TryParse([string]$observation.target.partition_guid, [ref]$partition) -or $partition -eq [guid]::Empty -or
        -not ($observation.target.aliases -match '^\\\\\?\\Volume\{[0-9a-f-]{36}\}[\\]?$') -or
        -not [datetimeoffset]::TryParse($observation.started_utc, [ref]$start) -or
        -not [datetimeoffset]::TryParse($observation.ended_utc, [ref]$end) -or $end -lt $start) {
        'storage event observation is incomplete'
    }
    $aliases = if ($observation -is [Collections.IDictionary] -and $observation.target -is [Collections.IDictionary]) { $observation.target.aliases } else { @() }
    $otherAliases = if ($observation -is [Collections.IDictionary] -and $observation.target -is [Collections.IDictionary]) { $observation.target.other_aliases } else { @() }
    foreach ($event in $Row.events) {
        if ($event -isnot [Collections.IDictionary] -or -not $event.provider -or $null -eq $event.id) {
            'storage event observation contains an invalid event record'
            continue
        }
        if ($event.provider -match 'ReFS' -and $event.id -in 131, 134) {
            $observed = Get-HostedEventAttribution @($event.volume) @($aliases) @($otherAliases)
            if ($event.attribution -ceq 'other' -and $observed.attribution -ceq 'other' -and $event.phase) { continue }
            if ($event.attribution -ceq 'target' -and $observed.attribution -ceq 'target' -and $event.phase) {
                "ReFS event $($event.id) on $($event.volume) during $($event.phase)"
            } else { "Unattributed ReFS event $($event.id); qualification is inconclusive" }
        }
    }
    if (-not $BeforeCleanup -and ($Row.cleanup_ok -isnot [bool] -or -not $Row.cleanup_ok)) { 'cleanup did not pass' }
    if ($Row.retention -eq 'failed') { 'failure evidence retention failed' }
}

function Assert-HostedRoundPassed([Collections.IDictionary]$Row, [string]$Label) {
    $problems = @(Get-HostedRoundFailures $Row)
    if ($Row.passed -isnot [bool] -or -not $Row.passed -or $Row.failures -isnot [Collections.IList] -or $Row.failures.Count -or $problems.Count) {
        throw "Invalid hosted qualification verdict for ${Label}: $($problems -join ', ')"
    }
}

# Map a volume GUID path or kernel volume name, never a bare drive letter.
function Get-HostedEventAttribution([string[]]$Fields, [string[]]$Aliases, [string[]]$OtherAliases) {
    $volumes = @($Fields | Where-Object { $_ -match '^(?:\\Device\\HarddiskVolume\d+|\\\\\?\\Volume\{[0-9a-f-]{36}\}[\\]?)$' } |
        ForEach-Object { $_.TrimEnd('\') } | Sort-Object -Unique)
    $target = @($Aliases | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') })
    $matchesTarget = @($volumes | Where-Object { $_ -in $target })
    if ($matchesTarget.Count -and $matchesTarget.Count -eq $volumes.Count) {
        return @{ attribution = 'target'; volume = $matchesTarget[0] }
    }
    # Only a positively observed other volume GUID can rule out the test
    # volume. Kernel volume numbers can change during mount transitions.
    if ($volumes.Count -eq 1 -and $volumes[0] -match '^\\\\\?\\Volume\{' -and
        $volumes[0] -in @($OtherAliases | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') })) {
        return @{ attribution = 'other'; volume = $volumes[0] }
    }
    @{ attribution = 'unresolved'; volume = $null }
}
