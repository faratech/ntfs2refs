# The reported event was within acceptance. A completed host hash batch wholly
# inside each of these guest steps establishes CPU activity in that window.
$Integrity131Phases = 'fill the volume and free it', 'mount again'

function Start-IntegrityCpuLoad([int]$Workers, [string]$Heartbeat) {
    Start-Job -ArgumentList $Workers, $Heartbeat -ScriptBlock {
        param([int]$workers, [string]$heartbeat)
        1..$workers | ForEach-Object -ThrottleLimit $workers -Parallel {
            $path = $using:heartbeat
            $bytes = [byte[]]::new(1MB)
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                if ($_ -ne 1 -or -not $path) {
                    while ($true) { $null = $sha.ComputeHash($bytes) }
                }
                while ($true) {
                    $started = [datetime]::UtcNow
                    $watch = [Diagnostics.Stopwatch]::StartNew()
                    $hashes = 0
                    do {
                        $null = $sha.ComputeHash($bytes)
                        $hashes++
                    } while ($watch.ElapsedMilliseconds -lt 40)
                    $row = @{
                        started_utc = $started.ToString('o'); finished_utc = [datetime]::UtcNow.ToString('o'); hashes = $hashes
                    } | ConvertTo-Json -Compress
                    [IO.File]::AppendAllText($path, $row + [Environment]::NewLine)
                }
            } finally { $sha.Dispose() }
        }
    }
}

function Convert-IntegrityUtc($Value) {
    if ($Value -is [datetime] -and $Value.Kind -eq [DateTimeKind]::Utc) { return [datetimeoffset]$Value }
    if ($Value -is [datetimeoffset] -and $Value.Offset -eq [timespan]::Zero) { return $Value }
    if ($Value -isnot [string] -or $Value -cnotmatch '(?:Z|\+00:00)$') { return }
    $parsed = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$parsed)) {
        return $parsed
    }
}

function Test-IntegrityCpuWindow($Cpu, [datetimeoffset]$Started, [datetimeoffset]$Finished) {
    $begin = Convert-IntegrityUtc $Cpu.started_utc
    $end = Convert-IntegrityUtc $Cpu.finished_utc
    $null -ne $begin -and $null -ne $end -and $begin -ge $Started -and $end -le $Finished -and $end -gt $begin -and
        ($Cpu.hashes -is [int] -or $Cpu.hashes -is [long]) -and $Cpu.hashes -gt 0
}

function Get-IntegrityClockBounds($Clock) {
    $beforeStart = Convert-IntegrityUtc $Clock.before.host_before_utc
    $beforeEnd = Convert-IntegrityUtc $Clock.before.host_after_utc
    $afterStart = Convert-IntegrityUtc $Clock.after.host_before_utc
    $afterEnd = Convert-IntegrityUtc $Clock.after.host_after_utc
    $guestFirst = Convert-IntegrityUtc $Clock.before.guest_utc
    $guestLast = Convert-IntegrityUtc $Clock.after.guest_utc
    if ($null -in @($beforeStart, $beforeEnd, $afterStart, $afterEnd, $guestFirst, $guestLast) -or
        $beforeStart -gt $beforeEnd -or $afterStart -gt $afterEnd -or $beforeEnd -gt $afterStart -or $guestFirst -ge $guestLast) { return }
    # A host-to-guest call brackets one simultaneous timestamp inside its
    # round trip. Use the widest observed offset interval across both calls.
    $earliest = @($beforeStart - $guestFirst; $afterStart - $guestLast) | Sort-Object | Select-Object -First 1
    $latest = @($beforeEnd - $guestFirst; $afterEnd - $guestLast) | Sort-Object | Select-Object -Last 1
    @{ earliest = $earliest; latest = $latest; guest_first = $guestFirst; guest_last = $guestLast }
}

function Get-Integrity131Windows($Acceptance, $CpuBatches, $Clock) {
    $bounds = Get-IntegrityClockBounds $Clock
    foreach ($step in $Acceptance.steps | Where-Object { $_.step -cin $Integrity131Phases }) {
        $begin = Convert-IntegrityUtc $step.started_utc
        $end = Convert-IntegrityUtc $step.finished_utc
        $batch = if ($bounds -and $null -ne $begin -and $null -ne $end) {
            $CpuBatches | Where-Object { Test-IntegrityCpuWindow $_ ($begin + $bounds.latest) ($end + $bounds.earliest) } |
                Select-Object -First 1
        }
        @{
            step = $step.step; ok = $step.ok; started_utc = $step.started_utc; finished_utc = $step.finished_utc
            cpu = $batch
        }
    }
}

function Assert-IntegrityLoadWindows($Row, [string]$Label) {
    $bounds = Get-IntegrityClockBounds $Row.integrity_clock
    if (!$bounds) { throw "Incomplete $Label host and guest clock evidence" }
    $priorFinish = $bounds.guest_first
    foreach ($phase in $Integrity131Phases) {
        $windows = @($Row.integrity_windows | Where-Object step -CEQ $phase)
        if ($windows.Count -ne 1 -or $windows[0].ok -ne $true) {
            throw "Incomplete $Label acceptance evidence for $phase"
        }
        $window = $windows[0]
        $begin = Convert-IntegrityUtc $window.started_utc
        $end = Convert-IntegrityUtc $window.finished_utc
        if ($null -eq $begin -or $null -eq $end -or $end -le $begin -or $begin -lt $priorFinish -or $end -gt $bounds.guest_last -or
            -not (Test-IntegrityCpuWindow $window.cpu ($begin + $bounds.latest) ($end + $bounds.earliest))) {
            throw "Incomplete $Label CPU load evidence for $phase"
        }
        $priorFinish = $end
    }
}

function Assert-Integrity131Case($Row) {
    $fixture = $Row.integrity_fixture
    if ($Row.route -cne 'integrity' -or $Row.windows -ne 26300 -or $Row.windows_edition -ne 48 -or
        $fixture.content -cne 'lived-in' -or $fixture.directory_entries -ne 4000 -or $fixture.check_agrees -ne $true -or
        $fixture.source_bytes -ne 50GB -or $fixture.ntfs_sector_bytes -ne 512 -or $fixture.ntfs_cluster_bytes -ne 4096 -or
        $fixture.ntfs_record_bytes -ne 1024 -or $Row.observed_target_format -cne 'dev-drive' -or
        $Row.observed_target_clusters -ne 4096 -or $fixture.mounted_refs_clusters -ne 4096 -or $fixture.refs_version -cne '3.14') {
        throw 'Incomplete ReFS event 131 fixture evidence'
    }
    Assert-IntegrityLoadWindows $Row 'ReFS event 131'
}
