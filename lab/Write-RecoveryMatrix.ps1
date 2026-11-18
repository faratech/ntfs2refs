<#
.SYNOPSIS
Writes docs\recovery-matrix.md from the verdicts of the lab's interrupted attempts.

.DESCRIPTION
An attempt run with -InterruptAt stops the converter at a named point, ends it,
recovers with the command the run printed, and compares the listing. This
script reads every attempt's verdict.json and tabulates, for each hold point
(crates\n2r-win32\src\lab_hold.rs defines them and their order), which
recoveries were run, on what, and how they ended. The document therefore says
what was run and nothing more: a row with no attempt says so.

Recoveries of the full Windows volume are listed one by one, with whether the
recovered installation was then started. Attempts that end the converter
while it prepares (-StopDuringPreparation of the data-volume harness) have a
table of their own: nothing has been written to the source at that point.

Attempts that did not recover are listed too, each with its outcome. The few
that were made on purpose to show a defect are explained in $Explained below,
by name, with the attempt that shows the same row after the fix.
#>
[CmdletBinding()]
param(
    [string]$Attempts,
    [string]$Output
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$workspace = Split-Path -Parent $PSScriptRoot
if (-not $Attempts) { $Attempts = Join-Path $workspace '.lab\hyperv\attempts' }
if (-not $Output) { $Output = Join-Path $workspace 'docs\recovery-matrix.md' }

$Explained = @{
    'v1-restart' = 'a fault of the harness: the reference VM''s own Windows is on ReFS, which cannot give up space for a partition beside it; the route is run on the Windows Server VM from v3-restart on'
    'v2-restart' = 'the same fault of the harness'
    'v3-restart' = 'working storage on ReFS, which this route does not take: "fresh ordinary unallocated external intent file required"; the route asks for NTFS working storage'
    'v4-restart-ntfs' = 'before f25430b: the route took a source partition of exactly 52 GiB only; the partition was left read-only, which the ways back of 0af9466 undo'
    'v5-restart' = 'before f25430b: a firmware boot entry that names the disk and not the boot manager file was refused'
    'v6-restart' = 'before f25430b: the same assumption in what bcdedit shows of the firmware''s boot order'
    'v7-restart' = 'a fault of the harness: Windows numbers a partition made a moment ago anew at its next start; the harness starts Windows once more after making it'
    'v8-restart' = 'before f25430b: the conversion and the return of the boot selection were complete; assigning the drive letter in the minimal Windows failed the run'
    'w1-restart-after-image' = 'a fault of the harness: the volume was given back whole; the comparison counted the file Windows itself writes into System Volume Information'
    'w1-restart-after-arm' = 'the same fault of the harness'
    'w1-restart-skip-reboot' = 'the same fault of the harness'
    'wb2-restart-after-image' = 'a fault of the harness: the comparison counted the changed times of the directory System Volume Information'
    'wb2-restart-after-arm' = 'the same fault of the harness'
    'wb2-restart-skip-reboot' = 'the same fault of the harness'
    'wb2-winpe-before-apply' = 'build 60fbe4d: the machine was put back and Windows started, but the volume was not given back (the search for its volume stopped at a volume that is on no disk); wb3-winpe-before-apply is the same row after the fix of 0af9466'
    'd5-shared-apply-resume' = 'a fault of the harness: the recovery finished and the volumes beside the source were back with identical bytes, but the harness looked for its earlier listing of one of them in the recovery''s working folder; d6-shared-apply-resume is the same row without it'
    'd5-shared-apply-rollback' = 'the same fault of the harness; d6-shared-apply-rollback is the same row without it'
    'd5-shared-handoff-resume' = 'the same fault of the harness; d6-shared-handoff-resume is the same row without it'
    'd5-shared-handoff-rollback' = 'asked for what recovery refuses by design: after the handoff a rollback is closed, and the run said so ("Run the recovery command without --rollback to finish the conversion")'
    'q-finalize-readonly-resume-01' ='reproduced issue #43 before its fix; t-finalize-readonly-resume-01 is the same row after it'
    'y-torn-handoff-older-build-01' = 'ran the build from before the fix of issue #1 on purpose, to show that the fix is what recovers a torn marker'
    'r1-stop-supply-cancel' = 'a fault of the harness, which put the cancel command together on the host; r2-stop-supply-cancel is the same row with the command the run prints'
    'r1-stop-journal-cancel' = 'the same fault of the harness; r2-stop-journal-cancel is the same row without it'
    'r1-stop-supply-restart' = 'the build before the fix of issue #95: the new run was refused with "letter has absent/ambiguous/unsupported volume mapping" and nothing named the way back; r2-stop-supply-restart is the same row after it'
    'v3s-vss-answering-apply-resume' = 'a fault of the harness: the recovery finished and the volume listed identical, but the harness looked for the shadow-copy provider''s note in the recovery''s output instead of the stopped run''s; v4s-vss-answering-apply-resume is the same row without it'
    'v3s-vss-answering-apply-rollback' = 'the same fault of the harness; v4s-vss-answering-apply-rollback is the same row without it'
    'v3s-vss-answering-handoff-resume' = 'the same fault of the harness; v4s-vss-answering-handoff-resume is the same row without it'
}

# The hold points and what state each one is, from the source that defines them.
$source = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates\n2r-win32\src\lab_hold.rs')
$block = [regex]::Match($source, '(?s)pub const POINTS: &\[&str\] = &\[(.*?)\];').Groups[1].Value
if (-not $block) { throw 'lab_hold.rs has no POINTS list' }
$points = New-Object System.Collections.Generic.List[object]
$comment = @()
foreach ($line in $block -split "`r?`n") {
    if ($line -match '^\s*//\s*(.+)$') { $comment += $Matches[1].Trim() }
    elseif ($line -match '"([a-z-]+)"') { $points.Add([pscustomobject]@{ point = $Matches[1]; state = ($comment -join ' ') }); $comment = @() }
}

$read = 0
$stops = New-Object System.Collections.Generic.List[object]
$restarts = New-Object System.Collections.Generic.List[object]
$rows = foreach ($directory in Get-ChildItem -LiteralPath $Attempts -Directory) {
    $file = Join-Path $directory.FullName 'verdict.json'
    if (-not (Test-Path -LiteralPath $file)) { continue }
    try { $verdict = Get-Content -Raw -LiteralPath $file | ConvertFrom-Json } catch { continue }
    $read++
    $names = @($verdict.PSObject.Properties.Name)
    if ($names -contains 'interrupt' -and $verdict.interrupt -and $verdict.interrupt.point) {
        $mode = if ($names -contains 'recovery' -and $verdict.recovery) { "$($verdict.recovery.mode)" } else { 'none' }
        $kind = "$($verdict.interrupt.kind)"
        if ($names -contains 'torn_marker' -and $verdict.torn_marker) { $kind += ', marker torn' }
        $volume = if ($verdict.fixture) { 'Windows fixture' } else { 'Windows, full volume' }
        if ($names -contains 'source_shape' -and $verdict.source_shape) { $volume += ' (shaped)' }
        [pscustomobject]@{ point = "$($verdict.interrupt.point)"; kind = $kind; mode = $mode; volume = $volume; outcome = "$($verdict.outcome)"
            name = "$($verdict.name)"; started = "$($verdict.started_utc)" }
    } elseif ($names -contains 'stopped_in_phase' -and $verdict.stopped_in_phase) {
        $left = if ($names -contains 'left_by_the_stop') { $verdict.left_by_the_stop } else { $null }
        $held = $left -and (@($left.offline_disks).Count -or @($left.read_only_disks).Count -or -not $left.v_mounted)
        # An attempt that turned the VM off in the phase says so in its verdict.
        $then = "$($verdict.after_stop)"
        if ($names -contains 'interruption' -and "$($verdict.interruption)" -eq 'vm turned off') { $then = "the machine turned off and started again, then $then" }
        $stops.Add([pscustomobject]@{ phase = "$($verdict.stopped_in_phase)"; then = $then; outcome = "$($verdict.outcome)"; name = "$($verdict.name)"
                left = if (-not $left) { 'not recorded' } elseif ($held) { 'offline or read-only' } else { 'online and writable' }
                started = (Get-Item -LiteralPath $file).LastWriteTimeUtc.ToString('o') })
    } elseif ($names -contains 'recovery_sha256' -and $names -contains 'partition_mb' -and $names -contains 'arguments') {
        # An attempt of the restart route (Invoke-RestartRouteAttempt.ps1).
        $arguments = @($verdict.arguments | ForEach-Object { "$_" })
        $at = [Array]::IndexOf($arguments, '--lab-fail-at')
        $restarts.Add([pscustomobject]@{ point = if ($at -ge 0) { $arguments[$at + 1] } else { '' }; outcome = "$($verdict.outcome)"; name = "$($verdict.name)"
                started = (Get-Item -LiteralPath $file).LastWriteTimeUtc.ToString('o') })
    } elseif ($names -contains 'interrupted_at' -and $verdict.interrupted_at) {
        # A volume that shares its disk is a row of its own: recovery returns
        # the volumes beside it too, and the attempt compares them.
        $shared = $names -contains 'siblings' -and $verdict.siblings
        [pscustomobject]@{ point = "$($verdict.interrupted_at)"; kind = 'process-termination'; mode = "$($verdict.recover_mode)"; volume = $(if ($shared) { 'data volume on a shared disk' } else { 'data volume' })
            outcome = "$($verdict.outcome)"; name = "$($verdict.name)"; started = (Get-Item -LiteralPath $file).LastWriteTimeUtc.ToString('o') }
    }
}
# An attempt that was interrupted and left for a later -RecoverFrom is not a recovery.
$rows = @($rows | Where-Object { $_.mode -in 'resume', 'rollback' })
# (Case matters: a data-volume attempt that recovered but failed one of its
# other checks ends as 'resumed-but-...', and is not a recovery that passed.)
$passed = { param($row) $row.outcome -cmatch '^(RESUMED|ROLLED-BACK)-' -or $row.outcome -cin 'resumed', 'rolled-back' }

function Cell($point, $mode) {
    $all = @($rows | Where-Object { $_.point -eq $point -and $_.mode -eq $mode })
    $good = @($all | Where-Object { & $passed $_ })
    if (-not $all) { return 'not run' }
    $parts = @()
    foreach ($group in $good | Group-Object volume, kind | Sort-Object Name) {
        $latest = ($group.Group | Sort-Object started | Select-Object -Last 1).name
        $parts += '{0}, {1}: {2} (latest `{3}`)' -f $group.Group[0].volume, $group.Group[0].kind, $group.Count, $latest
    }
    $bad = @($all | Where-Object { -not (& $passed $_) })
    if ($bad) { $parts += "did not recover: $($bad.Count), listed below" }
    $parts -join '<br>'
}

$text = New-Object System.Collections.Generic.List[string]
$text.Add('# Recovery matrix')
$text.Add('')
$text.Add('Written by `lab\Write-RecoveryMatrix.ps1` from the verdicts of the lab''s interrupted')
$text.Add("attempts ($read verdicts read, $($rows.Count) of them interrupted and recovered). Do not edit it by hand:")
$text.Add('run an attempt and write it again.')
$text.Add('')
$text.Add('Each attempt stops the converter at a named point (`--lab-hold-at`), ends it, runs')
$text.Add('the recovery command the run printed, and compares the volume''s listing: after a')
$text.Add('resume with the listing before the conversion (the converted volume must be')
$text.Add('identical under the allowances a conversion has), after a rollback with `--exact`')
$text.Add('(the NTFS volume must list exactly as before). A cell counts the attempts that')
$text.Add('ended that way, by what was converted and how it was interrupted.')
$text.Add('')
$text.Add('| Hold point | State of the source there | Resume | Rollback |')
$text.Add('|---|---|---|---|')
foreach ($point in $points) { $text.Add(('| `{0}` | {1} | {2} | {3} |' -f $point.point, $point.state, (Cell $point.point 'resume'), (Cell $point.point 'rollback'))) }
$unknown = @($rows | Where-Object { $_.point -notin $points.point } | Select-Object -ExpandProperty point -Unique)
if ($unknown) { $text.Add(''); $text.Add("Attempts name hold points that the source no longer defines: $($unknown -join ', ').") }
$full = @($rows | Where-Object { $_.volume -like 'Windows, full volume*' -and (& $passed $_) } | Sort-Object started)
if ($full) {
    $text.Add('')
    $text.Add('## The full Windows volume')
    $text.Add('')
    $text.Add('The rows above count these too. An outcome ending in `BOOTED-ON-REFS` or `BOOTED-ON-NTFS` means that,')
    $text.Add('after the recovery, the disk was started alone with Secure Boot on and reached the desktop on that')
    $text.Add('file system; `NOT-BOOTED` means the attempt was run without its boot step.')
    $text.Add('')
    $text.Add('| Attempt | Hold point | Interrupted by | Recovery | Ended as |')
    $text.Add('|---|---|---|---|---|')
    foreach ($row in $full) { $text.Add(('| `{0}` | `{1}` | {2} | {3} | {4} |' -f $row.name, $row.point, $row.kind, $row.mode, $row.outcome)) }
}
$text.Add('')
$text.Add('## Stopped during preparation')
$text.Add('')
if ($stops.Count) {
    $text.Add('Until a run prints its recovery command it has written nothing to the source, but it holds the')
    $text.Add('volume offline and read-only. These attempts end the converter''s process in a named phase of')
    $text.Add('preparation and then do one of two things. "cancel" runs what the run printed for this case at its')
    $text.Add('start, `--recover <directory> --recovery-sha256 <preparation checksum> --rollback`; the NTFS volume')
    $text.Add('must then be back and list exactly as before. "restart" starts the same conversion again as if')
    $text.Add('nothing had happened.')
    $text.Add('')
    $text.Add('| Phase | The stop left the volume | Then | Ended as | Attempts |')
    $text.Add('|---|---|---|---|---|')
    $ended = { param($stop) $stop.outcome -in 'preparation-cancelled', 'preparation-cancelled-after-power-off', 'restart-refused-then-cancelled' }
    foreach ($group in $stops | Where-Object { & $ended $_ } | Group-Object phase, then, outcome, left | Sort-Object Name) {
        $first = $group.Group[0]; $latest = ($group.Group | Sort-Object started | Select-Object -Last 1).name
        $text.Add(('| `{0}` | {1} | {2} | {3} | {4} (latest `{5}`) |' -f $first.phase, $first.left, $first.then, $first.outcome, $group.Count, $latest))
    }
    $other = @($stops | Where-Object { -not (& $ended $_) } | Sort-Object started)
    if ($other) {
        $text.Add('')
        $text.Add('Attempts that ended otherwise:')
        $text.Add('')
        $text.Add('| Attempt | Phase | Then | Outcome | Note |')
        $text.Add('|---|---|---|---|---|')
        foreach ($stop in $other) { $text.Add(('| `{0}` | `{1}` | {2} | {3} | {4} |' -f $stop.name, $stop.phase, $stop.then, $stop.outcome, $(if ($Explained.ContainsKey($stop.name)) { $Explained[$stop.name] } else { '' }))) }
    }
} else {
    $text.Add('Not run. Until a run prints its recovery command it has written nothing to the source.')
}
$text.Add('')
$text.Add('## A partition on the Windows disk, converted through a restart')
$text.Add('')
if ($restarts.Count) {
    $text.Add('The run prepares in Windows, restarts into a minimal Windows made from installation media and')
    $text.Add('converts there (`--restart-media`). Until the conversion itself starts nothing is written to the')
    $text.Add('partition, and each of these attempts stops the run at a laboratory point before that')
    $text.Add('(`--lab-fail-at`): the volume has to be back as writable NTFS listing as before, and Windows''')
    $text.Add('boot selection its own. An attempt without a point converts.')
    $text.Add('')
    $text.Add('| Where the run was stopped | What has to follow | Ended as | Attempts |')
    $text.Add('|---|---|---|---|')
    $said = @{
        '' = @('not stopped', 'the partition is ReFS when Windows is back')
        'restart-after-protect' = @('in Windows, after the partition was marked read-only', 'the run gives the volume back by itself')
        'restart-after-image' = @('in Windows, after the minimal Windows was made', 'the run gives the volume back by itself')
        'restart-after-arm' = @('in Windows, after the minimal Windows was selected for the next start', '`--recover` says what state the run is in; `--recover --rollback` gives the volume and the boot selection back')
        'restart-skip-reboot' = @('in Windows, with everything ready and the restart not requested', '`--recover` says what state the run is in; `--recover --rollback` gives the volume and the boot selection back')
        'winpe-before-apply' = @('in the minimal Windows, before the conversion started', 'the machine is put back by itself and Windows starts with the volume as NTFS')
    }
    $good = { param($run) $run.outcome -in 'converted', 'cancelled-volume-as-before' }
    foreach ($group in $restarts | Where-Object { & $good $_ } | Group-Object point, outcome | Sort-Object Name) {
        $first = $group.Group[0]; $latest = ($group.Group | Sort-Object started | Select-Object -Last 1).name
        $words = if ($said.ContainsKey($first.point)) { $said[$first.point] } else { @($first.point, '') }
        $text.Add(('| {0} | {1} | {2} | {3} (latest `{4}`) |' -f $words[0], $words[1], $first.outcome, $group.Count, $latest))
    }
    $other = @($restarts | Where-Object { -not (& $good $_) } | Sort-Object started)
    if ($other) {
        $text.Add('')
        $text.Add('Attempts that ended otherwise:')
        $text.Add('')
        $text.Add('| Attempt | Stopped | Outcome | Note |')
        $text.Add('|---|---|---|---|')
        foreach ($run in $other) { $text.Add(('| `{0}` | {1} | {2} | {3} |' -f $run.name, $(if ($run.point) { "``$($run.point)``" } else { 'not stopped' }), $run.outcome, $(if ($Explained.ContainsKey($run.name)) { $Explained[$run.name] } else { '' }))) }
    }
    $text.Add('')
    $text.Add('Not shown: an interruption while the minimal Windows converts (it returns to the minimal Windows,')
    $text.Add('which asks whether to go on or to put NTFS back), Windows 11, a physical machine, and BitLocker on')
    $text.Add('the Windows volume.')
} else {
    $text.Add('Not run.')
}
$text.Add('')
$text.Add('## Attempts that did not recover')
$text.Add('')
$failed = @($rows | Where-Object { -not (& $passed $_) } | Sort-Object started)
if ($failed) {
    $text.Add('| Attempt | Hold point | Recovery | Outcome | Note |')
    $text.Add('|---|---|---|---|---|')
    foreach ($row in $failed) { $text.Add(('| `{0}` | `{1}` | {2} | {3} | {4} |' -f $row.name, $row.point, $row.mode, $row.outcome, $(if ($Explained.ContainsKey($row.name)) { $Explained[$row.name] } else { '' }))) }
} else { $text.Add('None.') }
$text.Add('')
$text.Add('## What these attempts do not show')
$text.Add('')
$kinds = @($rows | ForEach-Object { ($_.kind -split ',')[0] } | Sort-Object -Unique)
$text.Add("- How the converter was interrupted: $($kinds -join '; '). The lab cannot cut power to the storage")
$text.Add('  itself. A marker write cut short is made by hand (`-TearMarker`) once the process has ended; other')
$text.Add('  torn writes are covered by the model tests (`tests\recovery_model.rs` and its siblings) only.')
if (-not $full) { $text.Add('- No interrupted run of the full Windows volume has been recovered.') }
$text.Add('- A machine that loses power while a run prepares: the stops during preparation end the converter''s')
$text.Add('  process, and the guest''s unflushed writes survive that.')
[IO.File]::WriteAllLines($Output, $text, [Text.UTF8Encoding]::new($false))
"${Output}: $($points.Count) hold points, $($rows.Count) recoveries, $($failed.Count) that did not recover, $($stops.Count) stops during preparation"
