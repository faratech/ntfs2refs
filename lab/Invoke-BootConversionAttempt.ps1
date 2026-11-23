<#
.SYNOPSIS
  One disposable Windows boot-volume conversion attempt, start to finish.

.DESCRIPTION
  Restores the baseline checkpoint, gives the VM a fresh scratch disk, boots
  the control OS, runs the converter against the original Windows partition,
  then (unless told otherwise) boots disk0 alone and records what came up.

  Every attempt starts from the checkpoint and may be thrown away. Nothing here
  is pinned to a particular run: no PIDs, hashes or sizes. Results land in
  .lab\hyperv\attempts\<Name>\ with a verdict.json and a progress.log.

.EXAMPLE
  lab\Invoke-BootConversionAttempt.ps1 -Fixture            # thinned fixture, full route, boot
  lab\Invoke-BootConversionAttempt.ps1 -Diagnose           # full Windows: build the shadow, list every per-object failure, stop before publication
  lab\Invoke-BootConversionAttempt.ps1                     # full Windows, convert and boot
  lab\Invoke-BootConversionAttempt.ps1 -NoConvert          # restore and prepare only, leave the control OS up
#>
[CmdletBinding()]
param(
    [string]$Name = (Get-Date -Format 'yyyyMMdd-HHmmss'),
    [string]$Checkpoint = 'N2R-Qualification-NTFS-*',
    [string]$FixtureCheckpoint = 'N2R-Thinned-Fixture',
    [string]$Binary,
    [int]$MemoryGB = 24,
    # How long an attempt waits for the host to have memory for its VM.
    [int]$WaitForMemoryMinutes = 240,
    [int]$Processors = 8,
    [int]$ScratchGB = 120,
    [ValidateSet('ReFS', 'NTFS')][string]$ScratchFileSystem = 'ReFS',
    [string[]]$ConverterArgs = @(),
    # Record where the converter spends its time: stacks.txt in the attempt
    # folder, one line per distinct call stack with its sample count.
    [switch]$SampleStacks,
    [switch]$Fixture,
    # A script (a name under lab\guest, or a path) run in the control OS
    # against the mounted source before it is listed, to give it features a
    # freshly installed Windows volume lacks, such as named streams. It
    # receives -SourceLetter and prints one line saying what it made.
    [string]$ShapeSource,
    [switch]$Diagnose,
    [switch]$NoBoot,
    [switch]$NoConvert,
    # Leave the scratch disk (and the control OS, if still up) for inspection.
    [switch]$KeepScratch,
    # If the converter stops after it has written ReFS to the source (or is
    # stopped there by -InterruptAt with -RecoverMode none), shut the VM down
    # and save that state under this checkpoint name. Its recovery can then
    # be run in minutes with -RecoverFrom instead of a whole new conversion.
    [string]$CheckpointAfterConvert,
    # Save the converted, not yet booted state under this checkpoint name
    # before the boot attempt, with the control OS and scratch disk still
    # attached, so a failed boot can be examined and tried again without
    # converting again. Keeps the scratch disk, which the checkpoint uses.
    [string]$CheckpointBeforeBoot,
    # The name of an earlier attempt that saved its state with
    # -CheckpointAfterConvert. That checkpoint is restored and
    # `ntfs2refs --recover` is run with the command that attempt printed,
    # then compared with the listing that attempt took: all three come from
    # the named attempt's own records, never from whatever ran most recently.
    [string]$RecoverFrom,
    # Recovery qualification. Stop the converter at a named point of apply or
    # handoff (crates/n2r-win32/src/lab_hold.rs lists them), end its process
    # there, then run the recovery command it printed and compare as usual.
    [string]$InterruptAt,
    # How the converter is interrupted there. 'process' ends its process.
    # 'vm' turns the VM off, as if the machine's power had gone: whatever the
    # guest had not flushed is lost, the control OS starts again, and
    # recovery runs in that fresh Windows. (The virtual disks themselves are
    # the host's files; power to the storage cannot be cut in the lab.)
    [ValidateSet('process', 'vm')][string]$InterruptKind = 'process',
    # After disk0 has booted on ReFS, use that Windows: files in a profile, a
    # path through a former short name, sfc, DISM, a feature enabled and
    # disabled, two more starts (guest\Test-ConvertedWindowsUse.ps1). With
    # -NoConvert it is the control: the unconverted Windows, used the same way.
    [switch]$Acceptance,
    [ValidateSet('resume', 'rollback', 'none')][string]$RecoverMode = 'resume',
    # Before recovery runs, leave the journal's handoff marker as a write that
    # stopped part-way leaves it (its first 512-byte sector written, its last
    # one clear). The lab cannot cut power to the storage; this is the image
    # such a cut leaves, made by hand once the converter's process has ended.
    # Recovery has to settle the marker before it can read the journal, and
    # has to say that it did. With -InterruptAt apply-handoff-durable (a run
    # with --verify thorough, whose apply step writes the handoff with the
    # disk offline and writable) the whole marker is there and is torn; with
    # -InterruptAt verify-passed (--verify fast, the default, whose finalizer
    # writes the handoff after the verification with the disk sealed offline
    # and read-only) it is not written yet, and the torn image of the marker
    # that would be written next is made from the apply intent beside it.
    [ValidateSet('handoff')][string]$TearMarker,
    # The converter's --verify: fast (its default) or thorough. Not with
    # -RecoverFrom: a recovery takes the mode its run recorded.
    [ValidateSet('fast', 'thorough')][string]$Verify,
    # The account the converter (and its recovery) runs as in the control OS.
    # 'system' is what every attempt used before this switch existed, and it
    # hid that an administrator was refused: the converter's working objects
    # admit SYSTEM alone. 'administrator' is what an owner's elevated terminal
    # is: the guest's administrator, elevated, with no stored password.
    [ValidateSet('system', 'administrator')][string]$RunAs = 'system',
    [int]$SourceDisk = 0,
    [int]$SourcePartition = 3,
    # Independent check: list the source before conversion and the converted
    # volume after, and require the two listings to match.
    [string]$ManifestBinary,
    [switch]$NoManifest,
    # Leave the control OS's scheduled drive optimisation on. Windows starts
    # its automatic maintenance some eleven minutes after the control OS
    # boots, in every run, because a restored checkpoint is always overdue;
    # the optimisation it runs (defrag.exe -c -h -o) holds up writes to the
    # control OS's ReFS volumes for minutes, and a run then measures that and
    # not the converter (issue 132). It is switched off for a run by default.
    [switch]$WithDriveOptimization,
    [int]$MinHostFreeGB = 40,
    [int]$ConvertTimeoutMinutes = 720,
    [int]$BootTimeoutMinutes = 25,
    # The reference VM, or a clone of it made by lab/New-LabVmClone.ps1.
    [string]$VmId = '8f7fc646-8c9f-41d0-b65a-ecfadccfc36a'
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$workspace = Split-Path -Parent $PSScriptRoot
$Recover = [bool]$RecoverFrom
$verifyInArgs = @($ConverterArgs | Where-Object { $_ -like '--verify*' })
if ($Verify -and $verifyInArgs) { throw "-Verify $Verify and $($verifyInArgs -join ' ') in -ConverterArgs: give the mode once" }
if ($Verify -and $Recover) { throw '-Verify applies to a conversion, not to -RecoverFrom: a recovery takes the mode its run recorded' }
# The mode the converter runs with: -Verify, else one in -ConverterArgs, else its default.
$verifyMode = if ($Verify) { $Verify } else {
    $at = [array]::IndexOf([string[]]$ConverterArgs, '--verify')
    if ($at -ge 0 -and $at + 1 -lt $ConverterArgs.Count) { $ConverterArgs[$at + 1] }
    elseif ($ConverterArgs -contains '--verify=thorough' -or $ConverterArgs -contains '--verify-full-content') { 'thorough' }
    else { 'fast' }
}
if ($TearMarker) {
    # Where each mode's run is held with its handoff marker either whole and
    # nothing after it done (thorough), or about to be written (fast).
    $tearAt = @{ 'apply-handoff-durable' = 'thorough'; 'verify-passed' = 'fast' }
    if (-not $InterruptAt -or -not $tearAt.ContainsKey($InterruptAt) -or $RecoverMode -eq 'none') {
        throw '-TearMarker handoff needs -InterruptAt apply-handoff-durable (with --verify thorough) or verify-passed (with --verify fast, the default), and a -RecoverMode: nothing after the marker may be done when it is torn'
    }
    if ($tearAt[$InterruptAt] -ne $verifyMode) {
        throw "-TearMarker handoff with -InterruptAt $InterruptAt needs --verify $($tearAt[$InterruptAt]); this run would use --verify $verifyMode and never reach that point"
    }
}
$case = Join-Path $workspace ".lab\hyperv\attempts\$Name"
if (Test-Path -LiteralPath $case) { throw "Attempt directory already exists: $case" }
$null = New-Item -ItemType Directory -Path $case
if (-not $Binary) { $Binary = Join-Path $workspace 'target\release\ntfs2refs.exe' }
if (-not $ManifestBinary) { $ManifestBinary = Join-Path $workspace 'target\release\lab-volume-manifest.exe' }
$progressLog = Join-Path $case 'progress.log'
$verdict = [ordered]@{ name = $Name; fixture = [bool]$Fixture; diagnose = [bool]$Diagnose; started_utc = [DateTime]::UtcNow.ToString('o')
    phases = [ordered]@{}; converter = $null; boot = $null; outcome = 'incomplete'
    evidence = [System.Collections.Generic.List[object]]::new(); evidence_complete = $false }
$verdict.run_as = $RunAs
$script:workerSession = $null; $script:workerJob = $null
$phaseWatch = [Diagnostics.Stopwatch]::StartNew()
# identical | differs | not-compared | tool-failed; 'not-run' when no comparison was asked for.
$listing = 'not-run'

function Say([string]$Text) {
    $line = '{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $Text
    Add-Content -LiteralPath $progressLog -Value $line -Encoding UTF8; Write-Host $line
}
function Phase([string]$PhaseName) {
    $script:verdict.phases[$PhaseName] = [Math]::Round($script:phaseWatch.Elapsed.TotalSeconds, 1)
    $script:phaseWatch.Restart(); Say "done: $PhaseName"
}
# Every piece of evidence an attempt retains is recorded with its size and
# SHA-256, or with the reason it is missing. Nothing is dropped silently.
function Add-Evidence([string]$Label, [string]$Path, [string]$MissingReason, [switch]$Required, [Nullable[long]]$GuestBytes, [string]$GuestSha256) {
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        $script:verdict.evidence.Add([ordered]@{ name = $Label; present = $true; required = [bool]$Required
                bytes = (Get-Item -LiteralPath $Path).Length; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() })
    } else {
        $entry = [ordered]@{ name = $Label; present = $false; required = [bool]$Required
            reason = if ($MissingReason) { $MissingReason } else { 'not found' } }
        # A record left in the guest is still identified: its size and digest there.
        if ($null -ne $GuestBytes) { $entry.guest_bytes = $GuestBytes }
        if ($GuestSha256) { $entry.guest_sha256 = $GuestSha256 }
        $script:verdict.evidence.Add($entry)
        if ($Required) { Say "required evidence missing: $Label ($MissingReason)" }
    }
}
function Copy-Evidence($Session, [string]$GuestPath, [string]$Label, [switch]$Required) {
    $target = Join-Path $case $Label; $reason = $null
    try {
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force
        Copy-Item -LiteralPath $GuestPath -Destination $target -FromSession $Session -ErrorAction Stop
    } catch { $reason = $_.Exception.Message }
    Add-Evidence $Label $target $reason -Required:$Required
}
# Copies the small records (json, txt, log) under a guest directory. One it
# leaves behind is named with its size, its digest taken in the guest and
# the reason, so the verdict accounts for every record the run wrote.
function Copy-RunRecords([string]$GuestDirectory, [string]$LabelRoot) {
    try {
        $found = Invoke-Command -Session $script:session -ArgumentList $GuestDirectory -ScriptBlock {
            param($directory)
            $failures = @()
            $files = @(Get-ChildItem -LiteralPath $directory -Recurse -File -ErrorAction SilentlyContinue -ErrorVariable failures |
                    Where-Object { $_.Extension -in '.json', '.txt', '.log' } | Sort-Object FullName | ForEach-Object {
                        $digest = $null
                        if ($_.Length -gt 4MB) { try { $digest = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() } catch { $digest = $null } }
                        [pscustomobject]@{ FullName = $_.FullName; Length = $_.Length; Sha256 = $digest } })
            [pscustomobject]@{ files = $files; errors = @($failures | ForEach-Object { "$_" }) }
        }
        foreach ($failure in @($found.errors)) { Add-Evidence $LabelRoot $null "listing ${GuestDirectory}: $failure" }
        $copied = 0
        foreach ($record in @($found.files)) {
            $label = Join-Path $LabelRoot $record.FullName.Substring($GuestDirectory.Length).TrimStart('\')
            if ($record.Length -gt 4MB) { Add-Evidence $label $null 'not copied: over the 4 MB record limit' -GuestBytes $record.Length -GuestSha256 $record.Sha256 }
            elseif ($copied -ge 400) { Add-Evidence $label $null 'not copied: over the 400-record limit' -GuestBytes $record.Length }
            else { Copy-Evidence $script:session $record.FullName $label; $copied++ }
        }
    } catch { Add-Evidence $LabelRoot $null "collection failed: $($_.Exception.Message)" -Required }
}
# Starts ntfs2refs.exe in the guest as SYSTEM, through the worker beside it.
function Start-Converter([string]$Root, [string]$TaskName, [string[]]$Arguments) {
    Invoke-Command -Session $script:session -ArgumentList $Root, ($Arguments -join "`t") -ScriptBlock {
        param($root, $joined)
        [IO.File]::WriteAllText("$root\run.json", (@{ arguments = @([string[]]$joined.Split("`t")) } | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    }
    Stop-AdministratorWorker
    if ($RunAs -eq 'administrator') {
        # The worker runs in a guest session of its own, as that session's
        # account: the guest's administrator, elevated, which is what an
        # owner's elevated terminal is. (A scheduled task for that account
        # stays queued in this guest and never starts.) The session lives as
        # long as this harness does; the converter ends with it.
        $script:workerSession = New-PSSession -VMId $vmId -Credential (Get-GuestCredential)
        $script:workerJob = Invoke-Command -Session $script:workerSession -ArgumentList $Root -AsJob -ScriptBlock {
            param($root)
            & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$root\worker.ps1" -Root $root
        }
    } else {
        Invoke-Command -Session $script:session -ArgumentList $Root, $TaskName -ScriptBlock {
            param($root, $task)
            $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
                -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File $root\worker.ps1 -Root $root"
            $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
            $null = Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings
            Start-ScheduledTask -TaskName $task
        }
    }
    Say "converter started as ${RunAs}: ntfs2refs.exe $($Arguments -join ' ')"
}
# Ends the guest session an administrator run's worker lived in, if any.
function Stop-AdministratorWorker {
    if ($script:workerJob) { Remove-Job -Job $script:workerJob -Force -ErrorAction SilentlyContinue; $script:workerJob = $null }
    if ($script:workerSession) { Remove-PSSession $script:workerSession -ErrorAction SilentlyContinue; $script:workerSession = $null }
}
# Follows a started converter until it ends. With -HoldPoint, the converter
# is expected to stop at that laboratory hold and report it; its process is
# then ended, which is the interruption under test.
function Wait-Converter([string]$Root, [string]$TaskName, [string]$ScratchLetter, [string]$HoldPoint) {
    $deadline = (Get-Date).AddMinutes($ConvertTimeoutMinutes); $lastLine = ''; $state = $null; $polls = 0; $failedPolls = 0; $vmStopped = $null; $held = $null
    while ($true) {
        Start-Sleep -Seconds 20; $polls++
        # Hyper-V pauses the VM when the host volume fills and turns it off
        # later. Either way the converter is not running; say so and stop.
        $vmState = (Get-LabVm).State.ToString()
        if ($vmState -ne 'Running') {
            $vmStopped = "VM is $vmState; host volume has {0:N1} GB free" -f ((Get-HostFreeBytes) / 1GB)
            Say "converter cannot continue: $vmStopped"; break
        }
        try {
            if ($script:session.State -ne 'Opened') { Remove-PSSession $script:session -ErrorAction SilentlyContinue; $script:session = Wait-Guest 5 $null; if (-not $script:session) { throw 'guest session lost' } }
            $state = Invoke-Command -Session $script:session -ArgumentList $Root, $TaskName, $ScratchLetter -ErrorAction Stop -ScriptBlock {
                param($root, $task, $letter)
                $tail = { param($path) if (Test-Path -LiteralPath $path) { @(Get-Content -LiteralPath $path -Tail 3 -Encoding UTF8) } else { @() } }
                $hold = if (Test-Path -LiteralPath "$root\stdout.log") { Select-String -LiteralPath "$root\stdout.log" -SimpleMatch -Pattern '"kind":"lab-hold-v1"' | Select-Object -Last 1 } else { $null }
                [pscustomobject]@{
                    task = $(try { (Get-ScheduledTask -TaskName $task -ErrorAction Stop).State.ToString() } catch { 'none' })
                    terminal = if (Test-Path "$root\native-terminal.json") { Get-Content "$root\native-terminal.json" -Raw | ConvertFrom-Json } else { $null }
                    worker_error = if (Test-Path "$root\worker-error.txt") { Get-Content "$root\worker-error.txt" -Raw } else { $null }
                    stdout = & $tail "$root\stdout.log"; stderr = & $tail "$root\stderr.log"
                    hold = if ($hold) { $hold.Line } else { $null }
                    scratch_free = (Get-Volume -DriveLetter $letter).SizeRemaining
                    control_free = (Get-Volume -DriveLetter $env:SystemDrive[0]).SizeRemaining
                }
            }
            $failedPolls = 0
        } catch {
            $failedPolls++; Say "poll failed ($failedPolls): $($_.Exception.Message)"
            if ($failedPolls -ge 9) { $vmStopped = 'control OS stopped answering'; break }
            continue
        }
        if ($HoldPoint -and $state.hold -and -not $held -and -not $state.terminal) {
            $held = $state.hold
            if ($InterruptKind -eq 'vm') {
                # What the user would still have: the output on their screen.
                # (Read, not copied: the worker holds the log open for writing.)
                try {
                    $shown = Invoke-Command -Session $script:session -ArgumentList $Root -ErrorAction Stop -ScriptBlock { param($root) Get-Content -LiteralPath "$root\stdout.log" -Raw -Encoding UTF8 }
                    [IO.File]::WriteAllText((Join-Path $case 'stdout-before-vm-off.log'), "$shown", [Text.UTF8Encoding]::new($false))
                } catch { Say "could not save the output before the VM was turned off: $($_.Exception.Message)" }
                Say "converter is holding at its laboratory point: $held; turning the VM off"
                Remove-PSSession $script:session -ErrorAction SilentlyContinue
                Stop-VM -VM (Get-LabVm) -TurnOff -Force
                Start-VM -VM (Get-LabVm)
                $script:session = Wait-Guest 15 $null
                if ($script:session) { Say 'the control OS has started again' } else { $vmStopped = 'the control OS did not start again after the VM was turned off' }
                break
            }
            Say "converter is holding at its laboratory point: $held; ending its process"
            Invoke-Command -Session $script:session -ArgumentList $Root -ErrorAction Stop -ScriptBlock {
                param($root) $id = (Get-Content -LiteralPath "$root\native-process.json" -Raw | ConvertFrom-Json).pid
                Stop-Process -Id $id -Force -ErrorAction Stop }
            continue
        }
        $line = @($state.stdout) | Select-Object -Last 1
        # The converter reports progress as JSON; show the short form.
        if ($line -like '{"kind":"conversion-progress-v1"*') { try { $p = $line | ConvertFrom-Json; $line = '{0}: {1} pass {2}, {3}/{4} {5}' -f $p.label, $p.progress.phase, $p.progress.pass, $p.progress.completed, $p.progress.total, $p.progress.unit } catch { } }
        $phaseKey = ($line -replace '\d+/', '')
        if (($line -and $phaseKey -ne $lastLine) -or $polls % 15 -eq 0) {
            $lastLine = $phaseKey
            Say ("[{0:N0} min] {1} | scratch free {2:N1} GB, control free {3:N1} GB" -f ($phaseWatch.Elapsed.TotalMinutes), $line, ($state.scratch_free / 1GB), ($state.control_free / 1GB))
        }
        # An administrator run has no task: its worker is the job in its own session.
        $running = if ($RunAs -eq 'administrator') { $script:workerJob -and $script:workerJob.State -eq 'Running' } else { $state.task -eq 'Running' }
        if ($state.terminal -or $state.worker_error -or (-not $running -and $polls -gt 3)) { break }
        if ((Get-Date) -gt $deadline) { Say 'converter timed out; leaving it running for inspection'; break }
    }
    [pscustomobject]@{ state = $state; vm_stopped = $vmStopped; held = $held }
}
# Lists the source volume as it is now, compares that with the listing taken
# before the run and records the comparison in the verdict. -Exact is for a
# source that must not have changed (after a diagnose run or a rollback):
# every recorded field equal, nothing accepted as an expected difference.
# Answers identical | differs | not-compared | tool-failed.
# -CaseMarksNotCarried is for a run that said it does not set the directories'
# case-sensitive marks on the new volume: a mark that is gone is then counted,
# not a difference.
function Compare-Listing([string]$Exe, [string]$Letter, [string]$Directory, [switch]$Exact, [switch]$CaseMarksNotCarried) {
    $compared = Invoke-Command -Session $script:session -ArgumentList $Exe, "${Letter}:\", $Directory, ([bool]$Exact), ([bool]$CaseMarksNotCarried) -ScriptBlock {
        param($exe, $root, $directory, $exact, $marksLeft)
        # The listing this attempt took, or the one -RecoverFrom brought with it.
        $before = "$directory\manifest-before.jsonl"
        if (-not (Test-Path -LiteralPath $before)) { $before = $null }
        if (-not $before) { return [pscustomobject]@{ stage = 'no-before-listing'; exit = -1; differences = $null; listed = 'no listing from before the run exists'; summary = ''; before = $null } }
        $listed = & $exe capture --root $root --output "$directory\manifest-after.jsonl" 2>&1
        if ($LASTEXITCODE -ne 0) { return [pscustomobject]@{ stage = 'capture-after'; exit = $LASTEXITCODE; differences = $null; listed = ($listed -join ' '); summary = ''; before = $before } }
        $report = "$directory\manifest-report.json"
        if (Test-Path -LiteralPath $report) { Remove-Item -LiteralPath $report -Force }
        $arguments = @('compare'); if ($exact) { $arguments += '--exact' } elseif ($marksLeft) { $arguments += '--case-marks-not-carried' }
        $arguments += @('--before', $before, '--after', "$directory\manifest-after.jsonl", '--report', $report)
        $summary = & $exe $arguments 2>&1
        $exit = $LASTEXITCODE
        # The count comes from the report the comparison wrote, not from its exit code alone.
        $differences = $null
        if (Test-Path -LiteralPath $report) { try { $differences = [int](Get-Content -Raw -LiteralPath $report | ConvertFrom-Json).difference_count } catch { $differences = $null } }
        [pscustomobject]@{ stage = 'compare'; exit = $exit; differences = $differences; listed = ($listed -join ' '); summary = ($summary -join ' '); before = $before }
    }
    Copy-Evidence $script:session "$Directory\manifest-after.jsonl" 'manifest-after.jsonl' -Required
    Copy-Evidence $script:session "$Directory\manifest-report.json" 'manifest-report.json' -Required:($compared.stage -eq 'compare' -and $compared.exit -in 0, 2)
    $script:verdict.before_listing_used = $compared.before
    # Exit 0 with no differences counted is identical; exit 2 with a report
    # that counts differences is a real difference. Anything else (a crash,
    # an unreadable listing, a usage error) is the listing tool failing,
    # which says nothing about the volume. No listing to compare with (a
    # -RecoverFrom of an attempt that took none) is neither.
    $result = if ($compared.stage -eq 'no-before-listing') { 'not-compared' }
        elseif ($compared.stage -eq 'compare' -and $compared.exit -eq 0 -and $compared.differences -eq 0) { 'identical' }
        elseif ($compared.stage -eq 'compare' -and $compared.exit -eq 2 -and $compared.differences -gt 0) { 'differs' }
        else { 'tool-failed' }
    $script:verdict.manifest = [ordered]@{ result = $result; exact = [bool]$Exact; stage = $compared.stage; exit = $compared.exit
        differences = $compared.differences; listed = $compared.listed; summary = $compared.summary }
    Say "listing after the run: $($compared.listed)"
    Say "before/after comparison$(if ($Exact) { ', exact' }): $result ($($compared.stage) exit $($compared.exit)): $($compared.summary)"
    Phase 'compare'
    $result
}
function Save-Verdict {
    $script:verdict.evidence_complete = -not @($script:verdict.evidence | Where-Object { $_.required -and -not $_.present }).Count
    $script:verdict.finished_utc = [DateTime]::UtcNow.ToString('o')
    $script:verdict | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $case 'verdict.json') -Encoding UTF8
}
function Get-LabVm { Get-VM -Id $vmId }
function Get-HostFreeBytes { [long](Get-Volume -FilePath $case).SizeRemaining }
function Remove-Scratch {
    # A dynamic scratch disk grows to several GB per run; left behind, they fill
    # the host volume and Hyper-V pauses the VM in the middle of a conversion.
    $path = Join-Path $case 'scratch.vhdx'
    if (-not (Test-Path -LiteralPath $path)) { return }
    try {
        $vm = Get-LabVm
        $attached = @(Get-VMHardDiskDrive -VM $vm | Where-Object Path -EQ $path)
        if ($attached.Count) {
            if ($vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Force }
            $attached | Remove-VMHardDiskDrive
        }
        Remove-Item -LiteralPath $path -Force
        Say ("scratch disk removed; host has {0:N0} GB free" -f ((Get-HostFreeBytes) / 1GB))
    } catch { Say "scratch disk not removed: $($_.Exception.Message)" }
}
# Hyper-V's view of a VM's drives lags behind a checkpoint restore, a
# turn-off and a change of its drives for a few seconds (#228): the add of
# the scratch disk one second after a restore was refused ("the specified
# location is in use"), and a minute later the same add took a free place.
# An add refused for its location is tried again, for up to half a minute;
# any other error is not.
function Invoke-DriveChange([scriptblock]$Change) {
    for ($try = 1; ; $try++) {
        try { return (& $Change) }
        catch {
            if ($try -ge 30 -or "$($_.Exception.Message)" -notmatch 'location') { throw }
            Start-Sleep -Seconds 1
        }
    }
}
# The boot step detaches every disk but disk0. Those are the VM's active
# differencing disks for the attempt. Restoring a checkpoint discards the
# active disks that are attached, so the detached ones used to stay behind
# for good, about 4.5 GB per booted attempt. The boot step now records what
# it detached, and the next attempt on the same VM puts those disks back
# before it restores its checkpoint: Hyper-V then discards them with the
# rest of the old attempt's state. The harness itself deletes nothing.
function Get-DetachedDiskRecord { Join-Path $workspace ".lab\hyperv\detached-disks-$vmId.json" }
function Save-DetachedDisks($Disks) {
    $record = [ordered]@{ vm_id = $vmId; attempt = $Name; detached_utc = [DateTime]::UtcNow.ToString('o')
        disks = @($Disks | ForEach-Object { [ordered]@{ path = $_.Path; controller_number = $_.ControllerNumber; controller_location = $_.ControllerLocation } }) }
    $record | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Get-DetachedDiskRecord) -Encoding UTF8
}
function Restore-DetachedDisks {
    $file = Get-DetachedDiskRecord
    if (-not (Test-Path -LiteralPath $file)) { return }
    $record = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
    # A record already acted on lists no disks.
    if (-not @($record.disks).Count) { return }
    $returned = 0
    foreach ($disk in @($record.disks)) {
        # Only a differencing disk that still exists, into the slot it came from.
        if ($disk.path -notlike '*.avhdx' -or -not (Test-Path -LiteralPath $disk.path)) { continue }
        $vm = Get-LabVm
        $taken = Get-VMHardDiskDrive -VM $vm | Where-Object { $_.ControllerNumber -eq $disk.controller_number -and $_.ControllerLocation -eq $disk.controller_location }
        if ($taken -or (Get-VMHardDiskDrive -VM $vm | Where-Object Path -EQ $disk.path)) { continue }
        # A DVD drive takes a place as well: the use test gives the media back
        # at the first free place, which is that of a detached disk (#228).
        # The checkpoint about to be restored has its own DVD drive.
        foreach ($media in @(Get-VMDvdDrive -VM $vm | Where-Object { $_.ControllerNumber -eq $disk.controller_number -and $_.ControllerLocation -eq $disk.controller_location })) {
            Say "a DVD drive is at the place of $(Split-Path -Leaf $disk.path), $($disk.controller_number)/$($disk.controller_location): taken out first"
            try { $media | Remove-VMDvdDrive -ErrorAction Stop } catch { Say "the DVD drive could not be taken out: $($_.Exception.Message)" }
        }
        try {
            Invoke-DriveChange { Add-VMHardDiskDrive -VM (Get-LabVm) -ControllerType SCSI -ControllerNumber $disk.controller_number -ControllerLocation $disk.controller_location -Path $disk.path -ErrorAction Stop }
            $returned++
        } catch { Say "could not return $(Split-Path -Leaf $disk.path) to the VM: $($_.Exception.Message)" }
    }
    if ($returned) { Say "returned $returned disk(s) that attempt '$($record.attempt)' detached for its boot step; the restore discards them with that attempt's state" }
    # The record is spent whether or not every disk could be returned.
    [ordered]@{ vm_id = $vmId; attempt = $record.attempt; disks = @(); returned = $returned; returned_utc = [DateTime]::UtcNow.ToString('o') } |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $file -Encoding UTF8
}
function Get-GuestCredential {
    $saved = Import-Clixml -LiteralPath (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
    [pscredential]::new('LabAdmin', $saved.Password)
}
function Wait-Guest([int]$Minutes, [scriptblock]$EachMinute) {
    $deadline = (Get-Date).AddMinutes($Minutes); $credential = Get-GuestCredential; $tick = 0
    while ((Get-Date) -lt $deadline) {
        try {
            $session = New-PSSession -VMId $vmId -Credential $credential -ErrorAction Stop
            $null = Invoke-Command -Session $session -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            return $session
        } catch { Start-Sleep -Seconds 10 }
        $tick++
        if ($EachMinute -and $tick % 6 -eq 0) { & $EachMinute ([int]($tick / 6)) }
    }
    return $null
}
# Shuts the control OS down, detaches every disk but disk0 and boots it alone,
# Secure Boot on. Answers what the Windows that came up says of itself and
# whether its desktop was reached; $null when no usable Windows came up (the
# verdict's boot record then says how far it got).
function Start-Disk0Alone {
    $controlBoot = Invoke-Command -Session $script:session -ScriptBlock { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') }
    Remove-PSSession $script:session
    try { Stop-VM -VM (Get-LabVm) -Force } catch { Stop-VM -VM (Get-LabVm) -TurnOff -Force }
    if ($CheckpointBeforeBoot) {
        Checkpoint-VM -VM (Get-LabVm) -SnapshotName $CheckpointBeforeBoot
        $script:KeepScratch = [switch]$true; $verdict.converted_checkpoint = $CheckpointBeforeBoot
        Say "saved the converted, not yet booted state as checkpoint '$CheckpointBeforeBoot'"
    }
    $vm = Get-LabVm
    $others = @(Get-VMHardDiskDrive -VM $vm | Where-Object { -not ($_.ControllerNumber -eq 0 -and $_.ControllerLocation -eq 0) })
    # The scratch disk is this attempt's own file and is removed when it ends.
    $returnable = @($others | Where-Object { $_.Path -ne (Join-Path $case 'scratch.vhdx') })
    Save-DetachedDisks $returnable
    $verdict.detached_for_boot = @($returnable | ForEach-Object { $_.Path })
    $others | Remove-VMHardDiskDrive
    # The installation media goes too, and comes back for the use test,
    # whose Setup scan reads it (#113).
    $installationMedia = @(Get-VMDvdDrive -VM $vm | Where-Object Path | ForEach-Object Path) | Select-Object -First 1
    Get-VMDvdDrive -VM $vm | Remove-VMDvdDrive
    $disk0 = Get-VMHardDiskDrive -VM $vm
    if (@($disk0).Count -ne 1) { throw 'Expected exactly disk0 to remain attached' }
    Set-VMFirmware -VM $vm -FirstBootDevice $disk0
    Say 'booting the original disk0 alone, Secure Boot on'
    Start-VM -VM $vm
    $script:shots = 0
    $booted = Wait-Guest $BootTimeoutMinutes {
        param($minute)
        if ($minute -le 5 -or $minute % 5 -eq 0) { $script:shots++; $null = Save-VmScreen (Join-Path $case ('boot-{0:D2}min.png' -f $minute)) }
        $heartbeat = (Get-VMIntegrationService -VM (Get-LabVm) -Name 'Heartbeat').PrimaryStatusDescription
        Say "waiting for Windows on disk0: minute $minute, VM $((Get-LabVm).State), heartbeat $heartbeat"
    }
    $null = Save-VmScreen (Join-Path $case 'boot-final.png')
    if (-not $booted) {
        $verdict.boot = @{ reached_windows = $false; vm_state = (Get-LabVm).State.ToString()
            heartbeat = (Get-VMIntegrationService -VM (Get-LabVm) -Name 'Heartbeat').PrimaryStatusDescription }
        return $null
    }
    $observed = Invoke-Command -Session $booted -ArgumentList $controlBoot -ScriptBlock {
        param($controlBoot)
        $os = Get-CimInstance Win32_OperatingSystem; $partition = Get-Partition -DriveLetter $env:SystemDrive[0]; $volume = Get-Volume -DriveLetter $env:SystemDrive[0]
        $refs = @(& "$env:SystemRoot\System32\fsutil.exe" fsinfo refsinfo "$env:SystemDrive" 2>&1)
        $setup = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\Setup'
        $signatures = foreach ($relative in 'System32\winload.efi', 'System32\drivers\refs.sys') {
            $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $env:SystemRoot $relative)
            [pscustomobject]@{ file = $relative; status = [string]$signature.Status; signer = $signature.SignerCertificate.Subject }
        }
        [pscustomobject]@{
            boot_utc = $os.LastBootUpTime.ToUniversalTime().ToString('o'); newer_than_control_boot = $os.LastBootUpTime.ToUniversalTime() -gt [DateTime]::Parse($controlBoot).ToUniversalTime()
            windows_directory = $os.WindowsDirectory; build = $os.BuildNumber; disk = $partition.DiskNumber; partition = $partition.PartitionNumber
            partition_guid = $partition.Guid; filesystem = [string]$volume.FileSystem; cluster_bytes = $volume.AllocationUnitSize
            health = [string]$volume.HealthStatus; refs_version = (($refs -join "`n") -replace '(?s).*REFS Volume Version\s*:\s*([\d.]+).*', '$1')
            secure_boot = (Confirm-SecureBootUEFI); setup_in_progress = $setup.SystemSetupInProgress; oobe_in_progress = $setup.OOBEInProgress
            signatures = @($signatures); disks = @(Get-Disk | Select-Object Number, Size)
        }
    }
    Remove-PSSession $booted
    $observed = $observed | Select-Object * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
    $desktop = Enter-Desktop
    $null = Save-VmScreen (Join-Path $case 'boot-desktop.png')
    [pscustomobject]@{ observed = $observed; desktop = $desktop }
}
# Runs guest\Test-ConvertedWindowsUse.ps1 in the Windows that booted from disk0,
# records every step, then shuts that Windows down and starts it twice more.
function Invoke-WindowsUseTest([string]$Expected) {
    $result = [ordered]@{ passed = $false; steps = @(); restarts = @() }
    $guestSession = Wait-Guest 10 $null
    if (-not $guestSession) { $result.error = 'the booted Windows did not answer'; return [pscustomobject]$result }
    try {
        # (As text: the guest's execution policy does not run files, and nothing has to be copied.)
        $script = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'guest\Test-ConvertedWindowsUse.ps1')
        $json = Invoke-Command -Session $guestSession -ArgumentList $script -ScriptBlock { param($script) & ([scriptblock]::Create($script)) }
        $use = ($json | Select-Object -Last 1) | ConvertFrom-Json
        [IO.File]::WriteAllText((Join-Path $case 'acceptance.json'), "$($json | Select-Object -Last 1)", [Text.UTF8Encoding]::new($false))
    } finally { Remove-PSSession $guestSession -ErrorAction SilentlyContinue }
    $result.steps = @($use.steps)
    foreach ($step in $use.steps) { Say ("use: {0}: {1} ({2} s): {3}" -f $step.step, $(if ($null -eq $step.ok) { 'skipped' } elseif ($step.ok) { 'ok' } else { 'FAILED' }), $step.seconds, $step.detail) }
    $restartsOk = $true
    foreach ($round in 1, 2) {
        try { Stop-VM -VM (Get-LabVm) -Force } catch { Stop-VM -VM (Get-LabVm) -TurnOff -Force }
        Start-VM -VM (Get-LabVm)
        $guestSession = Wait-Guest $BootTimeoutMinutes $null
        if (-not $guestSession) { $result.restarts += "start ${round}: Windows did not come back"; $restartsOk = $false; break }
        $state = Invoke-Command -Session $guestSession -ScriptBlock { $volume = Get-Volume -DriveLetter $env:SystemDrive[0]; "$($volume.FileSystem) $($volume.HealthStatus)" }
        Remove-PSSession $guestSession
        $result.restarts += "start ${round}: $state"
        if ($state -ne "$Expected Healthy") { $restartsOk = $false }
    }
    Say "use: shut down and started again twice: $($result.restarts -join '; ')"
    $result.passed = [bool]$use.passed -and $restartsOk
    [pscustomobject]$result
}
function Save-VmScreen([string]$Path) {
    # A picture of the console is the fastest way to read a boot failure.
    try {
        Add-Type -AssemblyName System.Drawing
        $ns = 'root\virtualization\v2'
        $system = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "Name='$($vmId.ToUpperInvariant())'"
        $settings = Get-CimAssociatedInstance -InputObject $system -ResultClassName Msvm_VirtualSystemSettingData |
            Where-Object VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized'
        $service = Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemManagementService
        $width = 1024; $height = 768
        $result = Invoke-CimMethod -InputObject $service -MethodName GetVirtualSystemThumbnailImage -Arguments @{
            TargetSystem = $settings; WidthPixels = [uint16]$width; HeightPixels = [uint16]$height }
        if ($result.ReturnValue -ne 0 -or -not $result.ImageData) { return $false }
        $bitmap = [Drawing.Bitmap]::new($width, $height, [Drawing.Imaging.PixelFormat]::Format16bppRgb565)
        $area = [Drawing.Rectangle]::new(0, 0, $width, $height)
        $data = $bitmap.LockBits($area, [Drawing.Imaging.ImageLockMode]::WriteOnly, $bitmap.PixelFormat)
        [Runtime.InteropServices.Marshal]::Copy([byte[]]$result.ImageData, 0, $data.Scan0, [Math]::Min($result.ImageData.Length, $data.Stride * $height))
        $bitmap.UnlockBits($data); $bitmap.Save($Path, [Drawing.Imaging.ImageFormat]::Png); $bitmap.Dispose()
        return $true
    } catch { Say "screen capture failed: $($_.Exception.Message)"; return $false }
}
function Enter-Desktop {
    # Windows answering a remote session has reached the lock screen, not the
    # desktop. Sign in at the console as the lab account, through the VM's
    # keyboard, and wait for that account's shell.
    $credential = Get-GuestCredential
    $result = [ordered]@{ shell = $false; user = $null; seconds = $null }
    try {
        $ns = 'root\virtualization\v2'
        $system = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "Name='$($vmId.ToUpperInvariant())'"
        $keyboard = Get-CimAssociatedInstance -InputObject $system -ResultClassName Msvm_Keyboard
        $started = Get-Date
        $null = Invoke-CimMethod -InputObject $keyboard -MethodName TypeKey -Arguments @{ keyCode = [uint32]0x20 }   # dismiss the lock screen
        Start-Sleep -Seconds 3
        $null = Invoke-CimMethod -InputObject $keyboard -MethodName TypeText -Arguments @{ asciiText = $credential.GetNetworkCredential().Password }
        Start-Sleep -Seconds 1
        $null = Invoke-CimMethod -InputObject $keyboard -MethodName TypeKey -Arguments @{ keyCode = [uint32]0x0D }
        $deadline = (Get-Date).AddMinutes(3)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 10
            $owner = Invoke-Command -VMId $vmId -Credential $credential -ErrorAction Stop -ScriptBlock {
                $explorer = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'")
                if ($explorer) { (Invoke-CimMethod -InputObject $explorer[0] -MethodName GetOwner).User }
            }
            if ($owner) {
                $result.shell = $true; $result.user = [string]$owner
                $result.seconds = [math]::Round(((Get-Date) - $started).TotalSeconds)
                Start-Sleep -Seconds 15   # let the desktop draw before its picture is taken
                break
            }
        }
    } catch { $result.error = $_.Exception.Message }
    $result
}

try {
    # ---- restore the baseline ------------------------------------------------
    $vm = Get-LabVm
    $origin = $null
    if ($Recover) {
        if ($Fixture -or $Diagnose -or $NoConvert) { throw '-RecoverFrom restores the named attempt''s own checkpoint; it does not combine with -Fixture, -Diagnose or -NoConvert' }
        $originRoot = Join-Path $workspace ".lab\hyperv\attempts\$RecoverFrom"
        $originVerdict = Join-Path $originRoot 'verdict.json'
        if (-not (Test-Path -LiteralPath $originVerdict)) { throw "No verdict for attempt '$RecoverFrom' at $originVerdict" }
        $record = Get-Content -LiteralPath $originVerdict -Raw | ConvertFrom-Json
        $saved = if ($record.PSObject.Properties['applied_checkpoint']) { [string]$record.applied_checkpoint } else { '' }
        if (-not $saved) { throw "Attempt '$RecoverFrom' saved no checkpoint (run it with -CheckpointAfterConvert)" }
        $printed = Select-String -LiteralPath (Join-Path $originRoot 'stdout.log') -Pattern '^To recover: ntfs2refs --recover "(.+)" --recovery-sha256 ([0-9a-f]{64})' | Select-Object -Last 1
        if (-not $printed) { throw "Attempt '$RecoverFrom' printed no ""To recover:"" line" }
        # Its before-listing, if it took one, must be the file its verdict recorded.
        $originListing = Join-Path $originRoot 'manifest-before.jsonl'
        $listed = @($record.evidence | Where-Object { $_.name -eq 'manifest-before.jsonl' -and $_.present })
        if ($listed.Count -and (Test-Path -LiteralPath $originListing)) {
            $digest = (Get-FileHash -LiteralPath $originListing -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($digest -ne $listed[0].sha256) { throw "The before-listing of attempt '$RecoverFrom' is not the file its verdict recorded ($digest, recorded $($listed[0].sha256))" }
        } else { $originListing = $null }
        $origin = [pscustomobject]@{ name = $RecoverFrom; checkpoint = $saved; recover_directory = $printed.Matches[0].Groups[1].Value
            recover_sha256 = $printed.Matches[0].Groups[2].Value; before_listing = $originListing
            before_listing_sha256 = if ($originListing) { $listed[0].sha256 } else { $null } }
        $verdict.recover_from = $origin
    }
    $wanted = if ($origin) { $origin.checkpoint } elseif ($Fixture) { $FixtureCheckpoint } else { $Checkpoint }
    # A saved checkpoint is named exactly; the baselines are matched by pattern.
    $snapshots = @(Get-VMSnapshot -VM $vm | Where-Object { if ($origin) { $_.Name -eq $wanted } else { $_.Name -like $wanted } })
    if ($snapshots.Count -ne 1) { throw "Expected exactly one checkpoint matching '$wanted', found $($snapshots.Count)" }
    if ($CheckpointAfterConvert -and (Get-VMSnapshot -VM $vm | Where-Object Name -EQ $CheckpointAfterConvert)) {
        throw "Checkpoint '$CheckpointAfterConvert' already exists; pick another name or remove it"
    }
    if ($CheckpointBeforeBoot -and (Get-VMSnapshot -VM $vm | Where-Object Name -EQ $CheckpointBeforeBoot)) {
        throw "Checkpoint '$CheckpointBeforeBoot' already exists; pick another name or remove it"
    }
    Say "attempt ${Name}: restoring checkpoint '$($snapshots[0].Name)'"
    if ($vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Force }
    Restore-DetachedDisks
    Restore-VMSnapshot -VMSnapshot $snapshots[0] -Confirm:$false
    $vm = Get-LabVm
    if ($vm.State -eq 'Saved') { Remove-VMSavedState -VM $vm; $vm = Get-LabVm }
    if ($vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Force; $vm = Get-LabVm }
    # Measured here, not before the restore. What the previous attempt on this
    # VM left on the host volume (the changes to its disks, several GB) is
    # released by the restore; counted against this attempt, it refused runs
    # that had room, most often the one after an attempt that booted.
    # A full-volume attempt grows its scratch disk to about 30 GB and the VM's
    # own disks by about as much before the scratch disk is removed; one that
    # started with 70 GB free was down to 12 GB at its end.
    if (-not $Fixture -and -not $Recover -and -not $NoConvert -and $MinHostFreeGB -lt 65) { $MinHostFreeGB = 65 }
    # Hyper-V frees the disks a restore discards after it returns, and the
    # host's ReFS reports the space later still: within seconds for a small
    # attempt, five minutes after a full-volume attempt that booted and was
    # used (41.6 GB free three minutes after one, 73.6 GB two minutes later).
    # So the wait goes on for as long as the free space is still growing.
    $hostFreeDisk = Get-HostFreeBytes; $grownAt = 0
    for ($waited = 0; $hostFreeDisk -lt [long]$MinHostFreeGB * 1GB -and $waited -lt 900 -and $waited - $grownAt -lt 180; $waited += 2) {
        Start-Sleep -Seconds 2; $now = Get-HostFreeBytes
        if ($now -gt $hostFreeDisk + 256MB) { $grownAt = $waited }
        $hostFreeDisk = $now
    }
    if ($waited -ge 30) { Say ("waited {0} s for the host to report the space the restore freed: {1:N1} GB free" -f $waited, ($hostFreeDisk / 1GB)) }
    if ($hostFreeDisk -lt [long]$MinHostFreeGB * 1GB) {
        throw ("Host volume has {0:N1} GB free with checkpoint '{2}' restored, and that stopped growing {3} s ago; an attempt needs {1} GB. Free space first (old attempts' scratch.vhdx files, or the other lab VM's last attempt)." -f ($hostFreeDisk / 1GB), $MinHostFreeGB, $snapshots[0].Name, ($waited - $grownAt))
    }
    # The VM fits what the host has free, and the host keeps 8 GB of it.
    # (It was given four fifths: with 23 GB free that left the host under
    # 5 GB, a run's own growth took the rest, and the host stopped the round
    # for lack of memory: 17 November, 2.6 GB free of 64, #165.)
    # A VM is given less than 8 GB only when the caller asked for it (a run
    # on a small machine, -MemoryGB 4), never because the host is short:
    # where the host has too little, the attempt waits for it, for up to
    # -WaitForMemoryMinutes, and only then gives up.
    $least = [Math]::Min(8GB, [long]$MemoryGB * 1GB)
    $waitedForMemory = 0
    while ($true) {
        $hostFree = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1KB
        $memory = [Math]::Min([long]$MemoryGB * 1GB, [long](($hostFree - 8GB) / 1GB) * 1GB)
        if ($memory -ge $least) { break }
        if ($waitedForMemory -ge $WaitForMemoryMinutes * 60) {
            throw "Host has too little free memory for the VM: $([Math]::Round($hostFree/1GB,1)) GB free after waiting $WaitForMemoryMinutes minutes; the VM needs $([Math]::Round($least/1GB)) GB and the host keeps 8"
        }
        if ($waitedForMemory % 600 -eq 0) { Say ("waiting for host memory: {0:N1} GB free, the VM needs {1:N0} GB and the host keeps 8" -f ($hostFree / 1GB), ($least / 1GB)) }
        Start-Sleep -Seconds 30; $waitedForMemory += 30
    }
    if ($waitedForMemory) { Say ("host memory is there after {0} s: the VM gets {1:N0} GB" -f $waitedForMemory, ($memory / 1GB)) }
    Set-VM -VM $vm -StaticMemory -MemoryStartupBytes $memory
    Set-VMProcessor -VM $vm -Count ([Math]::Min($Processors, [Environment]::ProcessorCount))
    # The boot step of an earlier attempt detached everything but disk0, and
    # Hyper-V then withdrew this VM's access to the DVD image it detached. The
    # restored checkpoint names the image again without that access, and the
    # VM does not start ("Access is denied"). Attaching it again grants it.
    # For some five seconds after a drive is emptied the Hyper-V cmdlets still
    # hold its old state and refuse the new image ("object was not found").
    foreach ($dvd in @(Get-VMDvdDrive -VM $vm | Where-Object Path)) {
        $image = $dvd.Path; $number = $dvd.ControllerNumber; $location = $dvd.ControllerLocation
        if ((& icacls $image 2>$null) -match [regex]::Escape($vmId)) { continue }
        Say "giving the VM back its access to $image"
        $dvd | Set-VMDvdDrive -Path $null
        for ($try = 1; ; $try++) {
            try {
                Get-VMDvdDrive -VM (Get-LabVm) | Where-Object { $_.ControllerNumber -eq $number -and $_.ControllerLocation -eq $location } |
                    Set-VMDvdDrive -Path $image -ErrorAction Stop
                break
            } catch { if ($try -ge 60) { throw }; Start-Sleep -Milliseconds 500 }
        }
        $vm = Get-LabVm
    }
    if (-not $Recover) {
        $scratchPath = Join-Path $case 'scratch.vhdx'
        $null = New-VHD -Path $scratchPath -SizeBytes ([long]$ScratchGB * 1GB) -Dynamic
        Invoke-DriveChange { Add-VMHardDiskDrive -VM (Get-LabVm) -ControllerType SCSI -ControllerNumber 0 -Path $scratchPath -ErrorAction Stop }
        $vm = Get-LabVm
    }
    $verdict.vm = @{ memory_bytes = $memory; processors = (Get-VMProcessor -VM $vm).Count; checkpoint = $snapshots[0].Name
        host_free_disk_bytes = (Get-Volume -FilePath $case).SizeRemaining }
    Phase 'restore'

    # ---- control OS up, scratch disk ready --------------------------------------
    Start-VM -VM $vm
    $session = Wait-Guest 15 $null
    if (-not $session) { throw 'Control OS did not accept a PowerShell Direct session within 15 minutes' }
    # The same build took 25 s and 243 s for one step, and once stood still
    # for 15 minutes with every processor busy in the kernel and "An IO took
    # more than 30000 ms" logged for the shadow's file, while this task ran.
    $verdict.drive_optimization = if ($WithDriveOptimization) { 'left on' } else {
        try {
            Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                # -ErrorAction on the call, not the preference variable: a
                # variable set here stays set in the session.
                $null = Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag' -ErrorAction Stop
                Stop-ScheduledTask -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag' -ErrorAction SilentlyContinue
            }
            'switched off for this run'
        } catch { "not switched off: $($_.Exception.Message)" }
    }
    Say "the control OS's scheduled drive optimisation: $($verdict.drive_optimization)"
    $guest = if ($Recover) {
        # The saved state already holds the original run's scratch volume and
        # its records; the source disk is offline and holds the ReFS image.
        Invoke-Command -Session $session -ArgumentList $SourceDisk, $SourcePartition -ScriptBlock {
            param($sourceDisk, $sourcePartition)
            $ErrorActionPreference = 'Stop'
            $scratch = @(Get-Volume | Where-Object { $_.FileSystemLabel -eq 'N2R_SCRATCH' -and $_.DriveLetter })
            if ($scratch.Count -ne 1) { throw "Expected one lettered N2R_SCRATCH volume, found $($scratch.Count)" }
            $system = Get-Partition -DriveLetter $env:SystemDrive[0]; $os = Get-CimInstance Win32_OperatingSystem
            $disk = Get-Disk -Number $sourceDisk
            [pscustomobject]@{
                scratch_letter = [string]$scratch[0].DriveLetter; scratch_filesystem = [string]$scratch[0].FileSystem
                scratch_free_bytes = $scratch[0].SizeRemaining
                control_disk = $system.DiskNumber; control_filesystem = (Get-Volume -DriveLetter $env:SystemDrive[0]).FileSystem
                control_free_bytes = (Get-Volume -DriveLetter $env:SystemDrive[0]).SizeRemaining
                source_letter = ''; source_disk = $sourceDisk; source_partition = $sourcePartition
                source_bytes = (Get-Partition -DiskNumber $sourceDisk -PartitionNumber $sourcePartition).Size; source_used_bytes = 0
                source_guid = (Get-Partition -DiskNumber $sourceDisk -PartitionNumber $sourcePartition).Guid
                source_offline = $disk.IsOffline; source_readonly = $disk.IsReadOnly
                free_memory_bytes = $os.FreePhysicalMemory * 1KB; build = $os.BuildNumber
                disks = @(Get-Disk | Select-Object Number, Size, PartitionStyle, IsOffline, IsBoot)
            }
        }
    } else { Invoke-Command -Session $session -ArgumentList $ScratchFileSystem, ([long]$ScratchGB * 1GB) -ScriptBlock {
        param($fileSystem, $scratchBytes)
        $ErrorActionPreference = 'Stop'
        $raw = @(Get-Disk | Where-Object { $_.PartitionStyle -eq 'RAW' -and $_.Size -eq $scratchBytes })
        if ($raw.Count -ne 1) { throw "Expected one blank scratch disk of $scratchBytes bytes, found $($raw.Count)" }
        if ($raw[0].IsOffline) { Set-Disk -Number $raw[0].Number -IsOffline $false }
        if ($raw[0].IsReadOnly) { Set-Disk -Number $raw[0].Number -IsReadOnly $false }
        Initialize-Disk -Number $raw[0].Number -PartitionStyle GPT
        $letter = @('S', 'T', 'U', 'V', 'W') | Where-Object { -not (Test-Path "${_}:\") } | Select-Object -First 1
        $partition = New-Partition -DiskNumber $raw[0].Number -UseMaximumSize -DriveLetter $letter
        if ($fileSystem -eq 'ReFS') {
            # Windows client editions format ReFS only as a Dev Drive. The converter's
            # working files were always kept on ReFS; NTFS pre-allocates differently
            # and trips its allocation checks, so do not fall back silently.
            $null = Format-Volume -Partition $partition -FileSystem NTFS -Confirm:$false
            $formatted = cmd /c "format.com ${letter}: /FS:ReFS /DevDrv /Q /Y /V:N2R_SCRATCH" 2>&1
            if ($LASTEXITCODE -ne 0 -or (Get-Volume -DriveLetter $letter).FileSystem -ne 'ReFS') { throw "Scratch ReFS format failed: $($formatted | Select-Object -Last 3)" }
        } else { $null = Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel 'N2R_SCRATCH' -Confirm:$false }
        # A Dev Drive is scanned by Defender in deferred mode: files are opened
        # again shortly after they are closed. The converter reopens its own
        # working files exclusively and then fails with a sharing violation.
        try { Add-MpPreference -ExclusionPath "${letter}:\" -ExclusionProcess 'ntfs2refs.exe' -ErrorAction Stop } catch { Write-Warning "Defender exclusion not set: $($_.Exception.Message)" }
        $system = Get-Partition -DriveLetter $env:SystemDrive[0]
        # The source is the largest lettered NTFS partition on a disk other than the running one.
        $source = Get-Partition | Where-Object { $_.DriveLetter -and $_.DiskNumber -ne $system.DiskNumber -and $_.DiskNumber -ne $raw[0].Number } |
            Where-Object { (Get-Volume -Partition $_).FileSystem -eq 'NTFS' } | Sort-Object Size -Descending | Select-Object -First 1
        if (-not $source) { throw 'No lettered NTFS source partition found off the control disk' }
        $os = Get-CimInstance Win32_OperatingSystem
        [pscustomobject]@{
            scratch_letter = $letter; scratch_filesystem = (Get-Volume -DriveLetter $letter).FileSystem
            scratch_free_bytes = (Get-Volume -DriveLetter $letter).SizeRemaining
            control_disk = $system.DiskNumber; control_filesystem = (Get-Volume -DriveLetter $env:SystemDrive[0]).FileSystem
            control_free_bytes = (Get-Volume -DriveLetter $env:SystemDrive[0]).SizeRemaining
            source_letter = [string]$source.DriveLetter; source_disk = $source.DiskNumber; source_partition = $source.PartitionNumber
            source_bytes = $source.Size; source_used_bytes = $source.Size - (Get-Volume -Partition $source).SizeRemaining
            source_guid = $source.Guid; free_memory_bytes = $os.FreePhysicalMemory * 1KB; build = $os.BuildNumber
            disks = @(Get-Disk | Select-Object Number, Size, PartitionStyle, IsOffline, IsBoot)
        }
    } }
    $verdict.guest = $guest | Select-Object * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
    Say ("control OS up: source {0}: disk {1} partition {2}, {3:N1} GB used; scratch {4}: {5}, {6:N0} GB free; RAM free {7:N1} GB" -f `
        $guest.source_letter, $guest.source_disk, $guest.source_partition, ($guest.source_used_bytes / 1GB), $guest.scratch_letter,
        $guest.scratch_filesystem, ($guest.scratch_free_bytes / 1GB), ($guest.free_memory_bytes / 1GB))
    Phase 'prepare'
    if ($NoConvert -and $Acceptance) {
        # Nothing is converted: what the use test finds here is what this
        # Windows does anyway.
        $started = Start-Disk0Alone | Select-Object -Last 1
        if (-not $started -or -not $started.PSObject.Properties['observed']) { $verdict.outcome = 'control-boot-failed'; Phase 'boot'; return }
        $verdict.boot = @{ reached_windows = $true; observed = $started.observed; desktop = $started.desktop }
        Say "disk0 booted unconverted: $($started.observed.filesystem), health $($started.observed.health)"
        Phase 'boot'
        $use = Invoke-WindowsUseTest 'NTFS' | Select-Object -Last 1
        $verdict.acceptance = $use
        $verdict.outcome = if ($use.passed) { 'control-passed' } else { 'control-use-failed' }
        Phase 'use'; return
    }
    if ($NoConvert) { $verdict.outcome = 'prepared-only'; Remove-PSSession $session; return }

    # ---- run the converter ------------------------------------------------------
    if (-not (Test-Path -LiteralPath $Binary)) { throw "Converter binary not found: $Binary (build with cargo build --release)" }
    $guestRoot = "C:\n2r\$Name"; $scratchDirectory = "$($guest.scratch_letter):\runs"
    $arguments = if ($Recover) { @('--recover', $origin.recover_directory, '--recovery-sha256', $origin.recover_sha256) }
        else { @('--drive', $guest.source_letter, '--windows-boot-volume', '--scratch-directory', $scratchDirectory, '--target-format', 'dev-drive') }
    if ($Diagnose) { $arguments += '--diagnose' }
    if ($InterruptAt) {
        if ($Recover -or $Diagnose) { throw '-InterruptAt applies to a conversion, not to -RecoverFrom or -Diagnose' }
        $arguments += @('--lab-hold-at', $InterruptAt, '--acknowledge-lab-hold-never-completes')
    }
    if ($Verify) { $arguments += @('--verify', $Verify) }
    if (-not $Recover) { $verdict.verify = $verifyMode }
    $arguments += $ConverterArgs
    $symbols = [IO.Path]::ChangeExtension($Binary, '.pdb')
    if ($SampleStacks) {
        if (-not (Test-Path -LiteralPath $symbols)) { throw "-SampleStacks needs the symbols beside the binary: $symbols" }
        $arguments += @('--sample-stacks', "$guestRoot\stacks.txt")
    }
    Invoke-Command -Session $session -ArgumentList $guestRoot, $scratchDirectory -ScriptBlock {
        param($root, $scratch) $null = New-Item -ItemType Directory -Path $root -Force; $null = New-Item -ItemType Directory -Path $scratch -Force }
    Copy-Item -LiteralPath $Binary -Destination "$guestRoot\ntfs2refs.exe" -ToSession $session
    if ($SampleStacks) { Copy-Item -LiteralPath $symbols -Destination "$guestRoot\ntfs2refs.pdb" -ToSession $session }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'guest\Invoke-ConverterRun.ps1') -Destination "$guestRoot\worker.ps1" -ToSession $session
    if ($ShapeSource) {
        if ($Recover) { throw '-ShapeSource applies to a new attempt, not to -RecoverFrom' }
        $shapePath = if (Test-Path -LiteralPath $ShapeSource) { (Resolve-Path -LiteralPath $ShapeSource).Path } else { Join-Path $PSScriptRoot "guest\$ShapeSource" }
        if (-not (Test-Path -LiteralPath $shapePath)) { throw "Shape script not found: $ShapeSource" }
        Copy-Item -LiteralPath $shapePath -Destination "$guestRoot\shape.ps1" -ToSession $session
        $shaped = Invoke-Command -Session $session -ArgumentList "$guestRoot\shape.ps1", $guest.source_letter -ScriptBlock {
            param($script, $letter)
            $text = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script -SourceLetter $letter 2>&1
            [pscustomobject]@{ exit = $LASTEXITCODE; text = (@($text) -join ' ') }
        }
        if ($shaped.exit -ne 0) { throw "Shaping the source with $(Split-Path -Leaf $shapePath) failed (exit $($shaped.exit)): $($shaped.text)" }
        # The source that is listed, converted and compared is the shaped one.
        $verdict.source_shape = [ordered]@{ script = (Split-Path -Leaf $shapePath)
            sha256 = (Get-FileHash -LiteralPath $shapePath -Algorithm SHA256).Hash.ToLowerInvariant(); result = $shaped.text }
        Say "source shaped by $(Split-Path -Leaf $shapePath): $($shaped.text)"; Phase 'shape'
    }
    $manifestExe = "$guestRoot\lab-volume-manifest.exe"
    if (-not $NoManifest) {
        if (-not (Test-Path -LiteralPath $ManifestBinary)) { throw "Listing tool not found: $ManifestBinary (cargo build --release --bin lab-volume-manifest)" }
        Copy-Item -LiteralPath $ManifestBinary -Destination $manifestExe -ToSession $session
        if (-not $Recover) {
            $listed = Invoke-Command -Session $session -ArgumentList $manifestExe, "$($guest.source_letter):\", "$guestRoot\manifest-before.jsonl" -ScriptBlock {
                param($exe, $root, $output) $text = & $exe capture --root $root --output $output 2>&1; [pscustomobject]@{ exit = $LASTEXITCODE; text = ($text -join ' ') } }
            if ($listed.exit -ne 0) { throw "Listing the source before conversion failed: $($listed.text)" }
            # Kept on the host from now on, whatever becomes of the run and the guest.
            Copy-Evidence $session "$guestRoot\manifest-before.jsonl" 'manifest-before.jsonl' -Required
            Say "source listed before conversion: $($listed.text)"; Phase 'list-before'
        } elseif ($origin.before_listing) {
            # The listing the originating attempt took, by the digest its verdict recorded.
            Copy-Item -LiteralPath $origin.before_listing -Destination "$guestRoot\manifest-before.jsonl" -ToSession $session
            Copy-Item -LiteralPath $origin.before_listing -Destination (Join-Path $case 'manifest-before.jsonl')
            Add-Evidence 'manifest-before.jsonl' (Join-Path $case 'manifest-before.jsonl') $null -Required
            Say "comparing with the listing attempt '$($origin.name)' took before its conversion ($($origin.before_listing_sha256))"
        } else { Say "attempt '$($origin.name)' took no before-listing; the result will not be compared" }
    }
    if (-not $Recover) {
        # What would stop this installation booting once its file system has changed.
        try {
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'guest\Test-SourceBootReadiness.ps1') -Destination "$guestRoot\readiness.ps1" -ToSession $session
            # Loading a copy of the source's SYSTEM hive needs backup and restore
            # privileges, so the check runs as SYSTEM, like the converter.
            $readiness = Invoke-Command -Session $session -ArgumentList "$guestRoot\readiness.ps1", $guest.source_letter, "$guestRoot\readiness.json", "N2R-Readiness-$Name" -ScriptBlock {
                param($script, $letter, $output, $task)
                $command = "& '$script' -SourceLetter $letter | Set-Content -LiteralPath '$output' -Encoding UTF8"
                $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
                    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"$command`""
                $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
                $null = Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Force
                Start-ScheduledTask -TaskName $task
                $deadline = (Get-Date).AddSeconds(120)
                do { Start-Sleep -Milliseconds 500 } until ((Get-ScheduledTask -TaskName $task).State -ne 'Running' -or (Get-Date) -gt $deadline)
                Unregister-ScheduledTask -TaskName $task -Confirm:$false
                if (Test-Path -LiteralPath $output) { Get-Content -LiteralPath $output -Raw } else { throw 'the readiness check wrote no report' }
            } | Out-String | ConvertFrom-Json
            $verdict.boot_readiness = $readiness
            $readiness | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $case 'boot-readiness.json') -Encoding UTF8
            Say ("boot readiness: {0}; hiberfil {1}; early drivers {2}; file-system drivers {3}" -f `
                $(if ($readiness.ready) { 'no findings' } else { @($readiness.findings) -join '; ' }),
                $(if ($readiness.hiberfil) { "$($readiness.hiberfil.bytes) bytes, signature $($readiness.hiberfil.signature)" } else { 'absent' }),
                $readiness.early_drivers, (@($readiness.file_system_drivers) -join ' '))
        } catch { Say "boot readiness check failed: $($_.Exception.Message)" }
    }
    $taskName = "N2R-Attempt-$Name"
    Start-Converter $guestRoot $taskName $arguments
    $run = Wait-Converter $guestRoot $taskName $guest.scratch_letter $InterruptAt
    $state = $run.state; $vmStopped = $run.vm_stopped
    if ($vmStopped) {
        # Nothing can be copied out of a guest that is not running. Say which
        # records that leaves behind instead of ending with an empty list.
        foreach ($leaf in 'stdout.log', 'stderr.log', 'native-process.json', 'native-terminal.json', 'run.json', 'run records') {
            Add-Evidence $leaf $null "not collected: $vmStopped" -Required
        }
        $verdict.converter = [ordered]@{ arguments = $arguments; exit = $null; stopped = $vmStopped }
        $verdict.outcome = 'vm-stopped'; Phase 'convert'; return
    }
    # ---- collect evidence -------------------------------------------------------
    foreach ($leaf in 'stdout.log', 'stderr.log', 'native-process.json', 'native-terminal.json', 'run.json') {
        # A converter that went down with its machine wrote no terminal record.
        Copy-Evidence $session "$guestRoot\$leaf" $leaf -Required:($leaf -ne 'native-terminal.json' -or -not ($InterruptAt -and $InterruptKind -eq 'vm'))
    }
    # Written only when the worker fails, and only when stacks were asked for.
    Copy-Evidence $session "$guestRoot\worker-error.txt" 'worker-error.txt'
    Copy-Evidence $session "$guestRoot\stacks.txt" 'stacks.txt' -Required:$SampleStacks
    Copy-RunRecords $scratchDirectory 'run'
    $exit = if ($state -and $state.terminal) { [int]$state.terminal.native_exit } else { $null }
    $verdict.converter = [ordered]@{ arguments = $arguments; exit = $exit
        wall_seconds = if ($state -and $state.terminal) { $state.terminal.wall_seconds } else { $null }
        peak_working_set_bytes = if ($state -and $state.terminal) { $state.terminal.peak_working_set_bytes } else { $null }
        stderr_tail = if ($state) { @($state.stderr) } else { @() }; worker_error = if ($state) { $state.worker_error } else { $null } }
    # What the control OS's own disks did meanwhile. A full run once stood
    # still for 16 minutes while each of its disk I/Os took more than 30 s,
    # three minutes after Windows' automatic maintenance had started there,
    # and only the control OS's logs said so (issue 132).
    try {
        $disks = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
            $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
            $slow = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Storage-Storport/Operational'; Id = 557; StartTime = $boot } -ErrorAction SilentlyContinue)
            $task = Get-ScheduledTask -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag' -ErrorAction SilentlyContinue | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            [pscustomobject]@{
                slow = $slow.Count
                first = if ($slow.Count) { $slow[-1].TimeCreated.ToString('HH:mm:ss') } else { $null }
                last = if ($slow.Count) { $slow[0].TimeCreated.ToString('HH:mm:ss') } else { $null }
                maintenance = if ($task -and $task.LastRunTime -ge $boot) { $task.LastRunTime.ToString('HH:mm:ss') } else { $null }
            }
        }
        $verdict.control_os = [ordered]@{ disk_io_over_30_seconds = $disks.slow; first = $disks.first; last = $disks.last; maintenance_started = $disks.maintenance }
        if ($disks.slow) { Say "the control OS reported $($disks.slow) disk I/O(s) that took more than 30 s, from $($disks.first) to $($disks.last)$(if ($disks.maintenance) { "; its automatic maintenance had started at $($disks.maintenance)" }): the time this run took is not the converter's alone" }
        elseif ($disks.maintenance) { Say "the control OS started its automatic maintenance at $($disks.maintenance); no disk I/O took more than 30 s" }
    } catch { Say "the control OS's disk latency was not read: $($_.Exception.Message)" }
    Phase 'convert'
    if ($InterruptAt) {
        # The interruption under test: the converter stopped at the named
        # point and its process was ended there. Recovery starts from what
        # that left on the disks, with nothing but the command it printed.
        $verdict.interrupt = [ordered]@{ point = $InterruptAt; kind = $(if ($InterruptKind -eq 'vm') { 'vm-turned-off' } else { 'process-termination' }); held = $run.held; converter_exit = $exit
            evidence_kinds = [ordered]@{ process_termination = ([bool]$run.held -and $InterruptKind -eq 'process'); vm_interruption = ([bool]$run.held -and $InterruptKind -eq 'vm')
                storage_power_loss = 'not covered: the lab cannot cut power to the storage' } }
        if (-not $run.held) {
            $verdict.outcome = 'interrupt-not-reached'; Say "the converter ended (exit $exit) without reaching the hold at $InterruptAt"
            Remove-PSSession $session; return
        }
        if ($RecoverMode -eq 'none') {
            $verdict.outcome = 'interrupted-not-recovered'; Remove-PSSession $session
            if ($CheckpointAfterConvert) {
                try { Stop-VM -VM (Get-LabVm) -Force } catch { Stop-VM -VM (Get-LabVm) -TurnOff -Force }
                Checkpoint-VM -VM (Get-LabVm) -SnapshotName $CheckpointAfterConvert
                # The checkpoint's disk chain starts at this attempt's scratch.vhdx.
                $KeepScratch = [switch]$true; $verdict.applied_checkpoint = $CheckpointAfterConvert
                Say "saved the interrupted state as checkpoint '$CheckpointAfterConvert'; recover it with -RecoverFrom '$Name'"
            }
            return
        }
        $printed = Select-String -LiteralPath (Join-Path $case 'stdout.log') -Pattern '^To recover: ntfs2refs --recover "(.+)" --recovery-sha256 ([0-9a-f]{64})' | Select-Object -Last 1
        $beforeOff = Join-Path $case 'stdout-before-vm-off.log'
        if (-not $printed -and (Test-Path -LiteralPath $beforeOff)) {
            # The log file lost its end with the machine; the line had been printed.
            $printed = Select-String -LiteralPath $beforeOff -Pattern '^To recover: ntfs2refs --recover "(.+)" --recovery-sha256 ([0-9a-f]{64})' | Select-Object -Last 1
            if ($printed) { $verdict.interrupt.recovery_command_from = 'the output saved before the VM was turned off; the log file in the guest had lost it'; Say 'the guest log lost the "To recover:" line with the machine; using the output saved before the VM was turned off' }
        }
        if ($printed -and $InterruptKind -eq 'vm') {
            # Someone who lost the screen as well can still recover: the
            # checksum is the SHA-256 of the envelope in that directory.
            $onDisk = Invoke-Command -Session $session -ArgumentList $printed.Matches[0].Groups[1].Value -ScriptBlock {
                param($directory) $file = Join-Path $directory 'recovery-envelope.json'
                if (Test-Path -LiteralPath $file) { (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null } }
            $verdict.interrupt.envelope_after_restart = [ordered]@{ sha256 = $onDisk; equals_printed_checksum = ($onDisk -eq $printed.Matches[0].Groups[2].Value) }
            Say "recovery envelope after the restart: $(if ($onDisk -eq $printed.Matches[0].Groups[2].Value) { 'its SHA-256 is the printed checksum' } elseif ($onDisk) { "its SHA-256 is $onDisk, not the printed checksum" } else { 'not found' })"
        }
        if (-not $printed) { $verdict.outcome = 'interrupted-without-recovery-command'; Say 'the interrupted run printed no "To recover:" line'; Remove-PSSession $session; return }
        $recoverArguments = @('--recover', $printed.Matches[0].Groups[1].Value, '--recovery-sha256', $printed.Matches[0].Groups[2].Value)
        if ($RecoverMode -eq 'rollback') { $recoverArguments += '--rollback' }
        if ($TearMarker) {
            $torn = Invoke-Command -Session $session -ArgumentList "$($printed.Matches[0].Groups[1].Value)\selected.journal", $TearMarker, $InterruptAt -ScriptBlock {
                param($journal, $marker, $point)
                # The handoff is the journal's first granule (offset 0); the
                # apply intent beside it is the second (offset 4096).
                $magic = @{ handoff = 'N2RSHN01' }[$marker]; $offset = @{ handoff = 0 }[$marker]
                $sha = [Security.Cryptography.SHA256]::Create()
                $digest = { param($bytes) [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
                $stream = [IO.File]::Open($journal, 'Open', 'ReadWrite', 'None')
                try {
                    $granule = New-Object byte[] 4096
                    $null = $stream.Seek($offset, 'Begin')
                    if ($stream.Read($granule, 0, 4096) -ne 4096) { throw "short read of the $marker marker in $journal" }
                    if ($point -eq 'verify-passed') {
                        # --verify fast: the finalizer writes the handoff after
                        # this point, so its granule is still clear. The marker
                        # it would write carries the apply intent's digests (the
                        # journal's immutable digest and the new selected digest,
                        # bytes 8 to 71) under the handoff's magic, and ends in
                        # the SHA-256 of the 4,064 bytes before it
                        # (src/selected_journal.rs, marker()).
                        if (@($granule | Where-Object { $_ -ne 0 }).Count) { throw "$journal holds something at offset ${offset}: a run held at verify-passed has not written its $marker marker" }
                        $intent = New-Object byte[] 4096
                        $null = $stream.Seek(4096, 'Begin')
                        if ($stream.Read($intent, 0, 4096) -ne 4096) { throw "short read of the apply intent in $journal" }
                        if ([Text.Encoding]::ASCII.GetString($intent, 0, 8) -ne 'N2RSAP01' -or
                            [BitConverter]::ToString($intent, 4064, 32) -ne [BitConverter]::ToString($sha.ComputeHash($intent, 0, 4064))) {
                            throw "$journal does not hold a whole apply intent at offset 4096"
                        }
                        [Array]::Copy([Text.Encoding]::ASCII.GetBytes($magic), 0, $granule, 0, 8)
                        [Array]::Copy($intent, 8, $granule, 8, 64)
                        [Array]::Copy($sha.ComputeHash($granule, 0, 4064), 0, $granule, 4064, 32)
                    } else {
                        $lastSector = @($granule[3584..4095] | Where-Object { $_ -ne 0 })
                        if ([Text.Encoding]::ASCII.GetString($granule, 0, 8) -ne $magic -or -not $lastSector.Count) {
                            throw "$journal does not hold a whole $marker marker at offset $offset"
                        }
                    }
                    $whole = & $digest $granule
                    [Array]::Clear($granule, 3584, 512)
                    $null = $stream.Seek($offset, 'Begin'); $stream.Write($granule, 0, 4096); $stream.Flush($true)
                    $left = & $digest $granule
                } finally { $stream.Dispose() }
                [pscustomobject]@{ journal = $journal; marker = $marker; offset = $offset; whole_sha256 = $whole; torn_sha256 = $left }
            }
            $verdict.torn_marker = [ordered]@{ marker = $torn.marker; journal = $torn.journal; journal_offset = $torn.offset
                image = 'first 512-byte sector written, last sector clear'; whole_sha256 = $torn.whole_sha256; torn_sha256 = $torn.torn_sha256
                whole_marker = $(if ($InterruptAt -eq 'verify-passed') { 'not yet written by the run (--verify fast): made from the apply intent beside it' } else { 'written by the run' })
                evidence_kind = 'marker image made by hand after the process ended; not a power loss'; settled_by_recovery = $false }
            Say "left the $($torn.marker) marker of $($torn.journal) partly written (last sector cleared)"
        }
        $recoverRoot = "$guestRoot-recover"; $recoverTask = "N2R-Recover-$Name"
        Invoke-Command -Session $session -ArgumentList $guestRoot, $recoverRoot -ScriptBlock {
            param($from, $to) $null = New-Item -ItemType Directory -Path $to -Force
            Copy-Item -LiteralPath "$from\ntfs2refs.exe", "$from\worker.ps1" -Destination $to }
        Start-Converter $recoverRoot $recoverTask $recoverArguments
        $recovery = Wait-Converter $recoverRoot $recoverTask $guest.scratch_letter $null
        foreach ($leaf in 'stdout.log', 'stderr.log', 'native-process.json', 'native-terminal.json', 'run.json') {
            Copy-Evidence $session "$recoverRoot\$leaf" (Join-Path 'recover' $leaf) -Required
        }
        Copy-Evidence $session "$recoverRoot\worker-error.txt" (Join-Path 'recover' 'worker-error.txt')
        # Recovery writes its own records beside the journal, not under the run.
        if (-not $recovery.vm_stopped) {
            $recoveryDirectories = @(Invoke-Command -Session $session -ArgumentList "$($guest.scratch_letter):\" -ScriptBlock {
                    param($root) @(Get-ChildItem -LiteralPath $root -Directory -Filter 'ntfs2refs-recovery-*' | ForEach-Object FullName) })
            if (-not $recoveryDirectories.Count) { Add-Evidence 'recover-records' $null 'recovery left no ntfs2refs-recovery-* directory on the journal volume' }
            foreach ($directory in $recoveryDirectories) { Copy-RunRecords $directory (Join-Path 'recover-records' (Split-Path -Leaf $directory)) }
        }
        $recoverState = $recovery.state
        $recoverExit = if ($recoverState -and $recoverState.terminal) { [int]$recoverState.terminal.native_exit } else { $null }
        $verdict.recovery = [ordered]@{ mode = $RecoverMode; arguments = $recoverArguments; exit = $recoverExit; stopped = $recovery.vm_stopped
            wall_seconds = if ($recoverState -and $recoverState.terminal) { $recoverState.terminal.wall_seconds } else { $null }
            stderr_tail = if ($recoverState) { @($recoverState.stderr) } else { @() } }
        Phase 'recover'
        if ($recovery.vm_stopped -or $null -eq $recoverExit -or $recoverExit -ne 0) {
            $verdict.outcome = 'recover-failed'
            Say "recovery ($RecoverMode) exit: $recoverExit. stderr: $(if ($recoverState) { @($recoverState.stderr) -join ' | ' })"
            Remove-PSSession $session; return
        }
        Say "recovery ($RecoverMode) exit 0"
        if ($TearMarker) {
            # A recovery that got through without noticing the marker read
            # something other than what was left for it.
            $reported = Select-String -LiteralPath (Join-Path $case 'recover\stderr.log') -SimpleMatch -Quiet -Pattern "held a partly written $TearMarker marker"
            $verdict.torn_marker.settled_by_recovery = [bool]$reported
            if (-not $reported) {
                $verdict.outcome = 'torn-marker-not-reported'; Say "recovery succeeded without reporting the partly written $TearMarker marker"
                Remove-PSSession $session; return
            }
            Say "recovery reported and settled the partly written $TearMarker marker"
        }
        if ($RecoverMode -eq 'rollback') {
            # What Windows says of the source now: the same partition, NTFS
            # again, online and writable. Then its listing, which has to
            # equal the one taken before the conversion in every field.
            $after = Invoke-Command -Session $session -ArgumentList $guest.source_disk, $guest.source_partition -ScriptBlock {
                param($disk, $number)
                $partition = Get-Partition -DiskNumber $disk -PartitionNumber $number; $volume = Get-Volume -Partition $partition
                [pscustomobject]@{ filesystem = [string]$volume.FileSystem; health = [string]$volume.HealthStatus; bytes = $partition.Size; guid = $partition.Guid
                    letter = [string]$partition.DriveLetter; offline = [bool]$partition.IsOffline; read_only = [bool]$partition.IsReadOnly }
            }
            $verdict.source_after_rollback = $after | Select-Object * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
            $restored = $after.filesystem -eq 'NTFS' -and $after.bytes -eq $guest.source_bytes -and $after.guid -eq $guest.source_guid -and
                -not $after.offline -and -not $after.read_only -and $after.health -eq 'Healthy'
            Say "source after rollback: $($after.filesystem), $($after.bytes) bytes, offline $($after.offline), read-only $($after.read_only), health $($after.health)"
            if (-not $restored) { $verdict.outcome = 'rolled-back-but-unhealthy'; Remove-PSSession $session; return }
            if ($NoManifest) { $verdict.outcome = 'ROLLED-BACK-NOT-COMPARED'; Remove-PSSession $session; return }
            if (-not $after.letter) { $verdict.outcome = 'rolled-back-but-no-drive-letter'; Remove-PSSession $session; return }
            $listing = Compare-Listing $manifestExe $after.letter $guestRoot -Exact
            $verdict.outcome = switch ($listing) {
                'identical' { 'ROLLED-BACK-NOT-BOOTED' } 'differs' { 'rolled-back-but-listing-differs' } default { 'rolled-back-listing-tool-failed' } }
            if ($NoBoot -or $listing -ne 'identical') { Remove-PSSession $session; return }
            # The installation that was rolled back has to start as it did before.
            $started = Start-Disk0Alone | Select-Object -Last 1
            if (-not $started -or -not $started.PSObject.Properties['observed']) { $verdict.outcome = 'rolled-back-but-boot-failed'; Say "after the rollback disk0 did not reach a usable Windows within $BootTimeoutMinutes minutes; see boot-*.png"; Phase 'boot'; return }
            $observed = $started.observed; $desktop = $started.desktop
            $ok = $observed.filesystem -eq 'NTFS' -and $observed.partition -eq $guest.source_partition -and $observed.partition_guid -eq $guest.source_guid -and
                @($observed.disks).Count -eq 1 -and $observed.secure_boot -eq $true -and $observed.newer_than_control_boot -and $observed.health -eq 'Healthy'
            $verdict.boot = @{ reached_windows = $true; observed = $observed; desktop = $desktop }
            $verdict.outcome = if (-not $ok) { 'rolled-back-booted-but-checks-failed' } elseif (-not $desktop.shell) { 'rolled-back-booted-without-desktop' } else { 'ROLLED-BACK-BOOTED-ON-NTFS' }
            Say "disk0 booted after the rollback: $($observed.filesystem), partition $($observed.partition), health $($observed.health); desktop $(if ($desktop.shell) { "reached as $($desktop.user) in $($desktop.seconds) s" } else { "not reached: $($desktop.error)" }) => $($verdict.outcome)"
            Phase 'boot'; return
        }
        # A resumed conversion is held to everything a completed one is.
        $exit = 0
    }
    # A diagnose run exits 0 when it found nothing and 3 when it reported
    # failures; either way the diagnosis itself completed.
    $diagnosed = $Diagnose -and ($exit -eq 0 -or $exit -eq 3)
    if (-not $diagnosed -and ($null -eq $exit -or $exit -ne 0)) {
        $verdict.outcome = if ($null -eq $exit) { 'converter-did-not-finish' } else { 'converter-failed' }
        Say "converter exit: $exit. stderr: $((@($state.stderr) -join ' | '))"; Remove-PSSession $session
        if ($CheckpointAfterConvert) {
            $log = Join-Path $case 'stdout.log'
            if ((Test-Path -LiteralPath $log) -and (Select-String -LiteralPath $log -Pattern 'Source changes verified' -Quiet)) {
                try { Stop-VM -VM (Get-LabVm) -Force } catch { Stop-VM -VM (Get-LabVm) -TurnOff -Force }
                Checkpoint-VM -VM (Get-LabVm) -SnapshotName $CheckpointAfterConvert
                # The checkpoint's disk chain starts at this attempt's scratch.vhdx.
                $KeepScratch = [switch]$true; $verdict.applied_checkpoint = $CheckpointAfterConvert
                Say "saved the applied-but-not-finalized state as checkpoint '$CheckpointAfterConvert'; retry finalization with -RecoverFrom '$Name'"
            } else { Say 'no checkpoint saved: the converter stopped before it changed the source' }
        }
        return
    }
    Say "converter exit $exit"
    if ($Diagnose) {
        # The converter's own account of the diagnosis, then what Windows says
        # of the source afterwards: the same partition, NTFS, online, writable.
        $diagnosis = $null; $log = Join-Path $case 'stdout.log'
        if (Test-Path -LiteralPath $log) {
            $found = Select-String -LiteralPath $log -SimpleMatch -Pattern '"kind":"diagnose-result-v1"' | Select-Object -Last 1
            if ($found) { try { $diagnosis = $found.Line | ConvertFrom-Json } catch { $diagnosis = $null } }
        }
        $verdict.diagnosis = $diagnosis
        $after = Invoke-Command -Session $session -ArgumentList $guest.source_disk, $guest.source_partition -ScriptBlock {
            param($disk, $number)
            $partition = Get-Partition -DiskNumber $disk -PartitionNumber $number; $volume = Get-Volume -Partition $partition
            [pscustomobject]@{ filesystem = [string]$volume.FileSystem; health = [string]$volume.HealthStatus; bytes = $partition.Size; guid = $partition.Guid
                letter = [string]$partition.DriveLetter; offline = [bool]$partition.IsOffline; read_only = [bool]$partition.IsReadOnly }
        }
        $verdict.source_after_diagnose = $after | Select-Object * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
        $sourceIntact = $after.filesystem -eq 'NTFS' -and $after.bytes -eq $guest.source_bytes -and $after.guid -eq $guest.source_guid -and
            -not $after.offline -and -not $after.read_only
        Say "source after diagnose: $($after.filesystem), $($after.bytes) bytes, offline $($after.offline), read-only $($after.read_only), health $($after.health)"
        # Independent of the converter: the source lists exactly as it did
        # before the run. Nothing is accepted as an expected difference.
        if ($sourceIntact -and -not $NoManifest) {
            $listing = if ($after.letter) { Compare-Listing $manifestExe $after.letter $guestRoot -Exact } else { 'not-compared' }
        }
        $verdict.outcome = if (-not $sourceIntact) { 'diagnose-changed-source' }
            elseif ($listing -eq 'differs') { 'diagnose-source-listing-differs' }
            elseif ($listing -in 'not-compared', 'tool-failed') { 'diagnose-source-not-compared' }
            elseif (-not $diagnosis) { 'diagnose-result-missing' }
            elseif ($exit -eq 0 -and $diagnosis.failures -eq 0 -and $diagnosis.examined_all_objects) { 'diagnose-clean' }
            elseif ($exit -eq 3 -and ($diagnosis.failures -gt 0 -or -not $diagnosis.examined_all_objects)) { 'diagnose-found-failures' }
            else { 'diagnose-result-inconsistent' }
        Remove-PSSession $session; return
    }
    if (-not $Diagnose) {
        # Independent of the converter: does Windows itself mount the result as ReFS?
        $mounted = Invoke-Command -Session $session -ArgumentList $guest.source_disk, $guest.source_partition -ScriptBlock {
            param($disk, $number)
            $partition = Get-Partition -DiskNumber $disk -PartitionNumber $number; $volume = Get-Volume -Partition $partition
            $letter = [string]$partition.DriveLetter
            $refs = if ($letter) { @(& "$env:SystemRoot\System32\fsutil.exe" fsinfo refsinfo "${letter}:" 2>&1) -join "`n" } else { '' }
            # Repair-Volume -Scan is not offered for a Dev Drive. What the ReFS
            # driver itself logged while mounting and reading the volume is.
            # "No events were found" is an answer; any other failure means the log was not read.
            $scanError = $null; $refsEvents = @()
            try {
                $refsEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2, 3; StartTime = (Get-Date).AddHours(-2) } -ErrorAction Stop |
                        Where-Object ProviderName -Match 'ReFS' | Select-Object -First 20 | ForEach-Object { '{0:HH:mm:ss} {1} {2}: {3}' -f $_.TimeCreated, $_.Id, $_.LevelDisplayName, (($_.Message -split "`n")[0]) })
            } catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $scanError = $_.Exception.Message } }
            $scan = if ($scanError) { "event log query failed: $scanError" }
                elseif ($refsEvents.Count) { "$($refsEvents.Count) ReFS warning/error events: $($refsEvents -join ' || ')" } else { 'no ReFS warnings or errors logged' }
            $sample = if ($letter) { @(Get-ChildItem -LiteralPath "${letter}:\" -Force -ErrorAction SilentlyContinue | Select-Object -First 40 -ExpandProperty Name) } else { @() }
            [pscustomobject]@{ letter = $letter; filesystem = [string]$volume.FileSystem; health = [string]$volume.HealthStatus
                cluster_bytes = $volume.AllocationUnitSize; used_bytes = $volume.Size - $volume.SizeRemaining
                refs_version = ($refs -replace '(?s).*REFS Volume Version\s*:\s*([\d.]+).*', '$1'); scan = $scan; scan_failed = [bool]$scanError; root_entries = $sample }
        }
        $verdict.mounted = $mounted | Select-Object * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
        # A log that could not be read is not a log with nothing in it.
        if ($mounted.scan_failed) { Add-Evidence 'refs-event-scan' $null $mounted.scan -Required }
        Say "source partition now mounts as $($mounted.filesystem) $($mounted.refs_version), health $($mounted.health), $([math]::Round($mounted.used_bytes / 1GB, 2)) GB used; $($mounted.scan)"
        if ($mounted.filesystem -ne 'ReFS') { $verdict.outcome = 'converter-ok-but-not-refs'; Remove-PSSession $session; return }
        if (-not $NoManifest) {
            if (-not $mounted.letter) { $verdict.outcome = 'converted-but-no-drive-letter'; Remove-PSSession $session; return }
            # The run says before it begins whether it sets the directories' case-sensitive marks on the new volume
            # (it does not on a volume that holds a Windows); a run that was cut off said it in the attempt it began in.
            $spoken = @((Join-Path $case 'stdout.log'), $(if ($RecoverFrom) { Join-Path $workspace ".lab\hyperv\attempts\$RecoverFrom\stdout.log" })) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
            $marksLeft = [bool]($spoken | Where-Object { Select-String -LiteralPath $_ -SimpleMatch -Pattern 'The converter does not set the mark on the new volume' -Quiet } | Select-Object -First 1)
            $listing = Compare-Listing $manifestExe $mounted.letter $guestRoot -CaseMarksNotCarried:$marksLeft
            # A listing that differs is a failed conversion, but whether the result
            # boots is separate evidence worth having from the same run.
            if ($listing -ne 'identical' -and ($NoBoot -or $Diagnose)) {
                $verdict.outcome = switch ($listing) {
                    'not-compared' { 'converted-not-compared' } 'differs' { 'converted-but-listing-differs' } default { 'converted-listing-tool-failed' } }
                Remove-PSSession $session; return
            }
        }
    }
    # A conversion finished by a recovery, in this attempt or from an earlier one, is named as one.
    $resumed = [bool]$InterruptAt -or $Recover
    if ($NoBoot) { $verdict.outcome = if ($resumed) { 'RESUMED-NOT-BOOTED' } else { 'converted-not-booted' }; Remove-PSSession $session; return }

    # ---- boot disk0 alone ------------------------------------------------------
    $started = Start-Disk0Alone | Select-Object -Last 1
    if (-not $started -or -not $started.PSObject.Properties['observed']) { $verdict.outcome = 'boot-failed'; Say "disk0 did not reach a usable Windows within $BootTimeoutMinutes minutes; see boot-*.png"; Phase 'boot'; return }
    $observed = $started.observed; $desktop = $started.desktop
    $ok = $observed.filesystem -eq 'ReFS' -and $observed.refs_version -eq '3.14' -and $observed.cluster_bytes -eq 4096 -and
        $observed.partition -eq $guest.source_partition -and $observed.partition_guid -eq $guest.source_guid -and @($observed.disks).Count -eq 1 -and
        $observed.secure_boot -eq $true -and $observed.newer_than_control_boot -and $observed.health -eq 'Healthy' -and
        -not (@($observed.signatures) | Where-Object status -NE 'Valid')
    $verdict.boot = @{ reached_windows = $true; observed = $observed; desktop = $desktop }
    # Only an identical listing (or one the operator switched off) can end as BOOTED-ON-REFS.
    $verdict.outcome = if (-not $ok) { 'booted-but-checks-failed' } elseif (-not $desktop.shell) { 'booted-without-desktop' }
        elseif ($listing -eq 'differs') { 'booted-but-listing-differs' } elseif ($listing -eq 'not-compared') { 'booted-not-compared' }
        elseif ($listing -eq 'tool-failed') { 'booted-listing-tool-failed' } elseif ($resumed) { 'RESUMED-BOOTED-ON-REFS' } else { 'BOOTED-ON-REFS' }
    Say "disk0 booted: $($observed.filesystem) $($observed.refs_version), cluster $($observed.cluster_bytes), partition $($observed.partition), health $($observed.health); desktop $(if ($desktop.shell) { "reached as $($desktop.user) in $($desktop.seconds) s" } else { "not reached: $($desktop.error)" }) => $($verdict.outcome)"
    Phase 'boot'
    if ($Acceptance -and $verdict.outcome -in 'BOOTED-ON-REFS', 'RESUMED-BOOTED-ON-REFS') {
        # Reaching the desktop is not the same as going on being used and serviced.
        if ($installationMedia) {
            try { Add-VMDvdDrive -VM (Get-LabVm) -Path $installationMedia; Say "installation media attached again for the use test: $installationMedia" }
            catch { Say "the installation media could not be attached again: $($_.Exception.Message)" }
        }
        $use = Invoke-WindowsUseTest 'ReFS' | Select-Object -Last 1
        $verdict.acceptance = $use
        if (-not $use.passed) { $verdict.result = $verdict.outcome; $verdict.outcome = "$($verdict.outcome)-BUT-USE-FAILED" }
        Phase 'use'
    }
} catch {
    $verdict.outcome = 'harness-error'; $verdict.error = ($_ | Out-String); Say "HARNESS ERROR: $($_.Exception.Message)"; throw
} finally {
    # A result is only as good as the records that support it: a success whose
    # required evidence was not retained is reported as incomplete, and its
    # scratch disk is kept so the records can still be recovered.
    $missing = @($verdict.evidence | Where-Object { $_.required -and -not $_.present })
    if ($missing.Count -and $verdict.outcome -in 'converted-not-booted', 'BOOTED-ON-REFS', 'diagnose-clean', 'diagnose-found-failures',
        'RESUMED-NOT-BOOTED', 'RESUMED-BOOTED-ON-REFS', 'ROLLED-BACK-NOT-BOOTED', 'ROLLED-BACK-BOOTED-ON-NTFS', 'ROLLED-BACK-NOT-COMPARED') {
        $verdict.result = $verdict.outcome; $verdict.outcome = 'incomplete-evidence'; $KeepScratch = [switch]$true
        Say "required evidence missing: $(($missing | ForEach-Object { $_.name }) -join ', '); scratch disk kept"
    }
    Stop-AdministratorWorker
    if (-not $KeepScratch -and -not $NoConvert) { Remove-Scratch }
    Save-Verdict; Say "outcome: $($verdict.outcome). Records: $case"
}
