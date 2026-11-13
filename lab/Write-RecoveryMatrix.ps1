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
    'q-finalize-readonly-resume-01' = 'reproduced issue #43 before its fix; t-finalize-readonly-resume-01 is the same row after it'
    'y-torn-handoff-older-build-01' = 'ran the build from before the fix of issue #1 on purpose, to show that the fix is what recovers a torn marker'
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
    } elseif ($names -contains 'interrupted_at' -and $verdict.interrupted_at) {
        [pscustomobject]@{ point = "$($verdict.interrupted_at)"; kind = 'process-termination'; mode = "$($verdict.recover_mode)"; volume = 'data volume'
            outcome = "$($verdict.outcome)"; name = "$($verdict.name)"; started = (Get-Item -LiteralPath $file).LastWriteTimeUtc.ToString('o') }
    }
}
# An attempt that was interrupted and left for a later -RecoverFrom is not a recovery.
$rows = @($rows | Where-Object { $_.mode -in 'resume', 'rollback' })
$passed = { param($row) $row.outcome -match '^(RESUMED|ROLLED-BACK)-' -or $row.outcome -in 'resumed', 'rolled-back' }

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
$full = @($rows | Where-Object { $_.volume -like 'Windows, full volume*' -and (& $passed $_) })
$text.Add("- Interrupted runs of the full Windows volume that recovered: $($full.Count)$(if ($full) { ' (' + (($full | ForEach-Object { '`' + $_.name + '`: ' + $_.outcome }) -join ', ') + ')' }).")
$text.Add('- A stop during preparation is not in this matrix: nothing has been written to the source then, and')
$text.Add('  the run is started again.')
[IO.File]::WriteAllLines($Output, $text, [Text.UTF8Encoding]::new($false))
"${Output}: $($points.Count) hold points, $($rows.Count) recoveries, $($failed.Count) that did not recover"
