<#
.SYNOPSIS
  Converts the Windows a lab VM runs from, with one command in that Windows.

.DESCRIPTION
  Boots the VM's own Windows (the disk at controller 0, location 0) with its
  working disk attached, runs `ntfs2refs --drive C --scratch-directory ...`
  in it, waits through the restarts the run makes (its Windows Recovery
  Environment, then Windows again), and records what came back: the file
  system of C:, the run's own report, and the boot menu.

  The working disk is an NTFS disk left by a control-OS attempt
  (Invoke-BootConversionAttempt.ps1 -NoConvert -KeepScratch -ScratchFileSystem
  NTFS); its VHDX is named with -ScratchVhdx and is attached by that attempt's
  configuration. Nothing under .lab is deleted here. What earlier attempts
  left on the working volume (their runs-* folders and the folders of their
  recoveries and cancellations) is the attempts' own scratch and is emptied
  before a run.

  -Restore starts from the VM's baseline checkpoint, so that an attempt can
  follow one that converted C:. -HoldAt cuts the power under the conversion
  and has the run recover by itself. -Acceptance uses the converted Windows.
  -Reattach gives the VM back the disks the attempt detached.

  Outcomes: PASSED (C: is the file system the run was to leave, healthy, and
  the converter ended with 0), CONVERTER-EXIT-<n>, C-IS-<file system>[-<health>],
  REFUSED-IN-WINDOWS, no-return, and after a power cut CUT-RECOVERED-TO-REFS,
  CUT-BACK-TO-NTFS, CUT-NOT-AT-THE-HOLD, CUT-BEFORE-THE-RUN-BEGAN,
  CUT-RECOVERY-UNCLEAR-C-IS-<file system> and RUN-ENDED-BEFORE-THE-CUT; with
  -Acceptance a use test that failed adds -BUT-USE-FAILED.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$VmId,
    [Parameter(Mandatory)][string]$Binary,
    [int]$MemoryGB = 8,
    # How long Windows has to come back with the run's report: from the
    # restart, or from the power cut of -HoldAt.
    [int]$AwayMinutes = 120,
    [switch]$Diagnose,
    # Stop at a command prompt in the recovery environment (type into it with
    # Send-VmKeys.ps1) instead of running the session there.
    [switch]$Hold,
    # Laboratory: write this SAN policy (3: offline internal) into the recovery
    # image before it boots, as the media route's image does.
    [string]$SanPolicy,
    # Laboratory: boot this image instead of the VM's WinRE: 'media' for the
    # installation media's boot.wim (index 2), kept in the DVD drive.
    [string]$Image,
    # Laboratory: stop the converter in the environment at this hold point
    # (crates/n2r-win32/src/lab_hold.rs), turn the VM off when it is parked
    # there, as if the power went, and start it again: the run must recover
    # by itself. The environment has no remote session, so the hold is seen
    # from outside: the VM's screen has not changed for two minutes and at
    # least HoldAfterMinutes have passed since the restart; CutAfterMinutes
    # after the restart the power is cut whatever the screen shows. Whether
    # the converter had reported the hold is read from its own output once
    # Windows is back. 'none' arms no hold: the power is cut CutAfterMinutes
    # after the restart, wherever the run is then.
    [string]$HoldAt,
    [int]$CutAfterMinutes = 40,
    [int]$HoldAfterMinutes = 5,
    # The working disk to attach when the VM has none (after a checkpoint was
    # restored).
    [string]$ScratchVhdx,
    [string[]]$ConverterArgs = @(),
    # Restore the VM's baseline checkpoint first. The disks an earlier attempt
    # detached are put back before that, so that Hyper-V discards them with
    # that attempt's state instead of leaving them behind.
    [switch]$Restore,
    [string]$Checkpoint = 'N2R-Qualification-NTFS-*',
    # When C: came back as ReFS: use that Windows (guest\Test-ConvertedWindowsUse.ps1),
    # then shut it down and start it twice more. The verdict has every step.
    [switch]$Acceptance,
    # When the attempt ends, however it ends: shut the VM down and give it
    # back the disks and the installation media this attempt detached, each
    # in the place it had.
    [switch]$Reattach
)
$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
if (-not $ScratchVhdx) { $ScratchVhdx = Join-Path $workspace '.lab\hyperv\attempts\envprobe-c-up\scratch.vhdx' }
if ($Hold -and ($HoldAt -or $Acceptance -or $Reattach)) { throw '-Hold leaves the VM at a command prompt in the recovery environment: not with -HoldAt, -Acceptance or -Reattach' }
$timedCut = $HoldAt -eq 'none'
# One attempt per VM at a time: an earlier attempt still waiting to cut the
# power would cut this one (runc-cut-midranges-2).
$others = @(Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -like '*Invoke-RunningWindowsAttempt*' -and $_.CommandLine -like "*$VmId*" })
if ($others) { throw "another running-Windows attempt drives this VM (process $($others.ProcessId -join ', ')); stop it first" }
$records = Join-Path $workspace ".lab\hyperv\attempts\$Name"
if (Test-Path -LiteralPath $records) { throw "attempt $Name already has records; use a new name" }
$null = New-Item -ItemType Directory -Path $records
function Say([string]$Text) { $line = '{0:HH:mm:ss} {1}' -f (Get-Date), $Text; Add-Content -LiteralPath (Join-Path $records 'progress.log') -Value $line -Encoding utf8; Write-Host $line }
$saved = Import-Clixml -LiteralPath (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$credential = [pscredential]::new('LabAdmin', $saved.Password)
function Get-LabVm { Get-VM -Id $VmId }
function Wait-Guest([int]$Minutes) {
    $deadline = (Get-Date).AddMinutes($Minutes)
    while ((Get-Date) -lt $deadline) {
        try {
            $session = New-PSSession -VMId $VmId -Credential $credential -ErrorAction Stop
            $null = Invoke-Command -Session $session -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            return $session
        } catch { Start-Sleep -Seconds 15 }
    }
    return $null
}
$verdict = [ordered]@{ name = $Name; vm_id = $VmId; started = (Get-Date).ToString('o'); outcome = 'harness-error' }
function Save-Verdict { [IO.File]::WriteAllText((Join-Path $records 'verdict.json'), ($verdict | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false)) }

# The VM's screen as Hyper-V shows it (800 by 600, two bytes a pixel), which
# is all that can be seen of the recovery environment from outside; nothing
# when it cannot be had.
$screenWidth = 800; $screenHeight = 600
function Get-VmScreen {
    try {
        $ns = 'root\virtualization\v2'
        $system = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "Name='$($VmId.ToUpper())'"
        $service = Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemManagementService
        $settings = Get-CimAssociatedInstance -InputObject $system -ResultClassName Msvm_VirtualSystemSettingData | Where-Object VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized'
        $result = Invoke-CimMethod -InputObject $service -MethodName GetVirtualSystemThumbnailImage -Arguments @{ TargetSystem = $settings; WidthPixels = [uint16]$screenWidth; HeightPixels = [uint16]$screenHeight }
        if ($result.ReturnValue -ne 0 -or -not $result.ImageData) { return $null }
        return , ([byte[]]$result.ImageData)
    } catch { return $null }
}
function Save-VmScreen([byte[]]$Screen, [string]$Path) {
    if (-not $Screen) { return }
    try {
        Add-Type -AssemblyName System.Drawing
        $bitmap = New-Object System.Drawing.Bitmap $screenWidth, $screenHeight, ([System.Drawing.Imaging.PixelFormat]::Format16bppRgb565)
        $data = $bitmap.LockBits((New-Object System.Drawing.Rectangle 0, 0, $screenWidth, $screenHeight), 'WriteOnly', $bitmap.PixelFormat)
        [Runtime.InteropServices.Marshal]::Copy($Screen, 0, $data.Scan0, [Math]::Min($Screen.Length, $data.Stride * $screenHeight)); $bitmap.UnlockBits($data)
        $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png); $bitmap.Dispose()
    } catch { Say "the screen could not be saved to $(Split-Path -Leaf $Path): $($_.Exception.Message)" }
}
if (-not ('N2RScreen' -as [type])) {
    Add-Type -TypeDefinition 'public static class N2RScreen { public static int Differing(byte[] a, byte[] b) { if (a == null || b == null || a.Length != b.Length) return int.MaxValue; int n = 0; for (int i = 0; i + 1 < a.Length; i += 2) { if (a[i] != b[i] || a[i + 1] != b[i + 1]) n++; } return n; } }'
}
# Two pictures of a screen on which nothing is written any more differ by
# the cursor, which blinks: a few of the 480,000 pixels. A line of progress
# changes hundreds.
$screenTolerance = 64

# What the attempt detached, with the place each disk had, kept where the
# boot harness keeps its own record of the same kind
# (Invoke-BootConversionAttempt.ps1): the next attempt on this VM that
# restores a checkpoint, by either harness, puts the differencing disks back
# first, and Hyper-V then discards them with the old attempt's state.
function Get-DetachedDiskRecord { Join-Path $workspace ".lab\hyperv\detached-disks-$VmId.json" }
function Read-DetachedDiskRecord {
    $file = Get-DetachedDiskRecord
    if (-not (Test-Path -LiteralPath $file)) { return $null }
    try { Get-Content -LiteralPath $file -Raw | ConvertFrom-Json } catch { $null }
}
function Save-DetachedDisks($Disks, $Dvds, [string]$FirstBootPath) {
    # Disks an earlier attempt detached and nothing has returned stay on the record.
    $attached = @(Get-VMHardDiskDrive -VM (Get-LabVm) | ForEach-Object Path)
    $earlier = Read-DetachedDiskRecord
    $pending = @(if ($earlier) { @($earlier.disks) | Where-Object { $_ -and $_.path -and $_.path -notin $attached -and $_.path -notin @($Disks | ForEach-Object Path) } })
    $record = [ordered]@{ vm_id = $VmId; attempt = $Name; detached_utc = [DateTime]::UtcNow.ToString('o')
        disks = @(@($pending | ForEach-Object { [ordered]@{ path = $_.path; controller_number = $_.controller_number; controller_location = $_.controller_location } }) +
            @($Disks | ForEach-Object { [ordered]@{ path = $_.Path; controller_number = $_.ControllerNumber; controller_location = $_.ControllerLocation } }))
        dvds = @($Dvds | ForEach-Object { [ordered]@{ path = $_.Path; controller_number = $_.ControllerNumber; controller_location = $_.ControllerLocation } })
        first_boot_path = $FirstBootPath }
    $record | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Get-DetachedDiskRecord) -Encoding UTF8
}
# Hyper-V's view of a VM's drives lags behind a checkpoint restore, a
# turn-off and a change of its drives for a few seconds (#228): an add made
# then was refused ("the specified location is in use" one second after a
# restore; a minute later the same add took a free location). An add or a
# move refused for its location is tried again, for up to half a minute;
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
# Waits, up to half a minute, for Hyper-V to show a disk it was just given.
function Wait-AttachedDrive([string]$Path) {
    for ($try = 0; $try -lt 15; $try++) {
        $drive = Get-VMHardDiskDrive -VM (Get-LabVm) | Where-Object Path -EQ $Path | Select-Object -First 1
        if ($drive) { return $drive }
        Start-Sleep -Seconds 2
    }
    return $null
}
# The drives of the VM as one line each: place and file.
function Get-DriveView {
    @(@(Get-VMHardDiskDrive -VM (Get-LabVm)) + @(Get-VMDvdDrive -VM (Get-LabVm)) |
        ForEach-Object { '{0}/{1}/{2}|{3}' -f $_.ControllerType, $_.ControllerNumber, $_.ControllerLocation, $_.Path } | Sort-Object)
}
# A restore makes a new differencing disk for every disk of the checkpoint,
# so the drives read just after Restore-VMSnapshot can still be the ones from
# before it: the second running-Windows case of a round, restored a second
# after the previous case had given its disks back, found the working disk
# attached in that view, did not attach it, and started Windows without it
# (#228). This waits, up to a minute, until the view differs from the one
# before the restore and reads the same twice in a row; whether it did is
# returned.
function Wait-RestoredDriveView([string[]]$Before) {
    $deadline = (Get-Date).AddMinutes(1); $last = $null
    while ($true) {
        $view = Get-DriveView
        if ($last -and ($view -join "`n") -eq ($last -join "`n") -and ($view -join "`n") -ne ($Before -join "`n")) { return $true }
        if ((Get-Date) -ge $deadline) { return $false }
        $last = $view; Start-Sleep -Seconds 2
    }
}
# Before a checkpoint is restored: the differencing disks only, as the boot
# harness returns them. With -Everything (for -Reattach): every disk that is
# still there, the installation media, and the device the VM started from.
# A place is taken by a DVD drive as well as by a disk: the use test gives
# the media back, and where it went to the first free place, that was the
# place of a detached disk, which could then not return ("no available
# locations were found on the disk controller", #228). Such a DVD drive is
# taken out first; with -Everything its media goes back to its own place
# below, and before a restore the checkpoint has its own. A disk that could
# not be returned at the end of an attempt (-Everything) stays on the
# record, for the next attempt that restores a checkpoint to return first.
function Restore-DetachedDisks([switch]$Everything) {
    $record = Read-DetachedDiskRecord
    if (-not $record) { return 0 }
    $returned = 0; $left = @()
    foreach ($disk in @($record.disks)) {
        if (-not $disk -or -not $disk.path -or -not (Test-Path -LiteralPath $disk.path)) { continue }
        if (-not $Everything -and $disk.path -notlike '*.avhdx') { continue }
        $drives = @(Get-VMHardDiskDrive -VM (Get-LabVm))
        if ($drives | Where-Object Path -EQ $disk.path) { continue }
        if ($drives | Where-Object { $_.ControllerNumber -eq $disk.controller_number -and $_.ControllerLocation -eq $disk.controller_location }) {
            Say "could not return $(Split-Path -Leaf $disk.path) to the VM: another disk is at its place, $($disk.controller_number)/$($disk.controller_location)"
            if ($Everything) { $left += $disk }
            continue
        }
        foreach ($media in @(Get-VMDvdDrive -VM (Get-LabVm) | Where-Object { $_.ControllerNumber -eq $disk.controller_number -and $_.ControllerLocation -eq $disk.controller_location })) {
            Say "a DVD drive ($(if ($media.Path) { Split-Path -Leaf $media.Path } else { 'empty' })) is at the place of $(Split-Path -Leaf $disk.path), $($disk.controller_number)/$($disk.controller_location): taken out first"
            try { $media | Remove-VMDvdDrive -ErrorAction Stop } catch { Say "the DVD drive could not be taken out: $($_.Exception.Message)" }
        }
        try {
            Invoke-DriveChange { Add-VMHardDiskDrive -VM (Get-LabVm) -ControllerType SCSI -ControllerNumber $disk.controller_number -ControllerLocation $disk.controller_location -Path $disk.path -ErrorAction Stop }
            $returned++
        } catch {
            Say "could not return $(Split-Path -Leaf $disk.path) to the VM: $($_.Exception.Message)"
            if ($Everything) { $left += $disk }
        }
    }
    if ($Everything) {
        foreach ($dvd in @($record.dvds)) {
            if (-not $dvd -or -not $dvd.path -or -not (Test-Path -LiteralPath $dvd.path)) { continue }
            if (Get-VMDvdDrive -VM (Get-LabVm) | Where-Object Path -EQ $dvd.path) { continue }
            # Its own place, or the first free one where a disk has that now.
            $taken = @(Get-VMHardDiskDrive -VM (Get-LabVm)) + @(Get-VMDvdDrive -VM (Get-LabVm)) | Where-Object { $_.ControllerNumber -eq $dvd.controller_number -and $_.ControllerLocation -eq $dvd.controller_location }
            try {
                if ($taken) { Invoke-DriveChange { Add-VMDvdDrive -VM (Get-LabVm) -Path $dvd.path -ErrorAction Stop } }
                else { Invoke-DriveChange { Add-VMDvdDrive -VM (Get-LabVm) -ControllerNumber $dvd.controller_number -ControllerLocation $dvd.controller_location -Path $dvd.path -ErrorAction Stop } }
                $returned++
            } catch { Say "could not return the installation media $(Split-Path -Leaf $dvd.path) to the VM: $($_.Exception.Message)" }
        }
        if ($record.first_boot_path) {
            $first = @(@(Get-VMHardDiskDrive -VM (Get-LabVm)) + @(Get-VMDvdDrive -VM (Get-LabVm)) | Where-Object Path -EQ $record.first_boot_path) | Select-Object -First 1
            if ($first) { try { Set-VMFirmware -VM (Get-LabVm) -FirstBootDevice $first -ErrorAction Stop } catch { Say "could not make $(Split-Path -Leaf $record.first_boot_path) the first boot device again: $($_.Exception.Message)" } }
        }
    }
    # The record is spent but for the disks that could not be returned.
    [ordered]@{ vm_id = $VmId; attempt = $record.attempt; returned = $returned; returned_utc = [DateTime]::UtcNow.ToString('o')
        disks = @($left | ForEach-Object { [ordered]@{ path = $_.path; controller_number = $_.controller_number; controller_location = $_.controller_location } }) } |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Get-DetachedDiskRecord) -Encoding UTF8
    return $returned
}

# Runs guest\Test-ConvertedWindowsUse.ps1 in the converted Windows, records
# every step, then shuts that Windows down and starts it twice more (as
# Invoke-BootConversionAttempt.ps1 does after its boot).
function Invoke-WindowsUseTest([string]$Expected) {
    $result = [ordered]@{ passed = $false; steps = @(); restarts = @() }
    $guest = Wait-Guest 10
    if (-not $guest) { $result.error = 'the converted Windows did not answer'; return [pscustomobject]$result }
    $use = $null
    try {
        # (As text: the guest's execution policy does not run files, and nothing has to be copied.)
        $script = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'guest\Test-ConvertedWindowsUse.ps1')
        $json = Invoke-Command -Session $guest -ArgumentList $script -ScriptBlock { param($script) & ([scriptblock]::Create($script)) }
        $use = ($json | Select-Object -Last 1) | ConvertFrom-Json
        [IO.File]::WriteAllText((Join-Path $records 'acceptance.json'), "$($json | Select-Object -Last 1)", [Text.UTF8Encoding]::new($false))
    } catch { $result.error = "the use test did not run to its end: $($_.Exception.Message)" }
    finally { Remove-PSSession $guest -ErrorAction SilentlyContinue }
    if (-not $use) { return [pscustomobject]$result }
    $result.steps = @($use.steps)
    foreach ($step in $use.steps) { Say ("use: {0}: {1} ({2} s): {3}" -f $step.step, $(if ($null -eq $step.ok) { 'skipped' } elseif ($step.ok) { 'ok' } else { 'FAILED' }), $step.seconds, $step.detail) }
    $restartsOk = $true
    foreach ($round in 1, 2) {
        try {
            try { Stop-VM -VM (Get-LabVm) -Force } catch { Stop-VM -VM (Get-LabVm) -TurnOff -Force }
            Start-VM -VM (Get-LabVm)
            $guest = Wait-Guest 15
            if (-not $guest) { $result.restarts += "start ${round}: Windows did not come back"; $restartsOk = $false; break }
            $state = Invoke-Command -Session $guest -ScriptBlock { $volume = Get-Volume -DriveLetter $env:SystemDrive[0]; "$($volume.FileSystem) $($volume.HealthStatus)" }
            Remove-PSSession $guest
            $result.restarts += "start ${round}: $state"
            if ($state -ne "$Expected Healthy") { $restartsOk = $false }
        } catch { $result.restarts += "start ${round}: $($_.Exception.Message)"; $restartsOk = $false; break }
    }
    Say "use: shut down and started again twice: $($result.restarts -join '; ')"
    $result.passed = [bool]$use.passed -and $restartsOk
    [pscustomobject]$result
}

$failure = $null
try {
    # The VM boots its own Windows: disk0 first, the control OS's disks and the
    # installation media detached (not deleted), the working disk kept.
    $vm = Get-LabVm
    if ($vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Force; $vm = Get-LabVm }
    if ($Restore) {
        $snapshots = @(Get-VMSnapshot -VM $vm | Where-Object { $_.Name -like $Checkpoint })
        if ($snapshots.Count -ne 1) { throw "Expected exactly one checkpoint matching '$Checkpoint', found $($snapshots.Count)" }
        $returned = Restore-DetachedDisks
        if ($returned) { Say "returned $returned disk(s) an earlier attempt detached; the restore discards them with that attempt's state" }
        Say "restoring checkpoint '$($snapshots[0].Name)'"
        $viewBefore = Get-DriveView
        Restore-VMSnapshot -VMSnapshot $snapshots[0] -Confirm:$false
        $vm = Get-LabVm
        if ($vm.State -eq 'Saved') { Remove-VMSavedState -VM $vm; $vm = Get-LabVm }
        if ($vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Force; $vm = Get-LabVm }
        $verdict.restored_checkpoint = $snapshots[0].Name
        $verdict.restored_drive_view_settled = Wait-RestoredDriveView $viewBefore
        if (-not $verdict.restored_drive_view_settled) { Say 'a minute after the restore Hyper-V still showed the drives as before it, or they kept changing: going on with what it shows now' }
        $vm = Get-LabVm
    }
    Set-VMMemory -VM $vm -DynamicMemoryEnabled $false -StartupBytes ($MemoryGB * 1GB)
    $drives = @(Get-VMHardDiskDrive -VM $vm)
    $disk0 = $drives | Where-Object { $_.ControllerNumber -eq 0 -and $_.ControllerLocation -eq 0 }
    $scratch = $drives | Where-Object { $_.Path -like '*\scratch.vhdx' } | Select-Object -First 1
    if (-not $scratch -and (Test-Path -LiteralPath $ScratchVhdx)) {
        Invoke-DriveChange { Add-VMHardDiskDrive -VM (Get-LabVm) -ControllerType SCSI -Path $ScratchVhdx -ErrorAction Stop }
        $scratch = Wait-AttachedDrive $ScratchVhdx
        $drives = @(Get-VMHardDiskDrive -VM $vm)
    }
    if (-not $disk0) { throw 'the VM has no disk at SCSI 0/0, its own Windows (disk0)' }
    if (-not $scratch) { throw "the VM has no working disk (scratch.vhdx) attached, and $ScratchVhdx $(if (Test-Path -LiteralPath $ScratchVhdx) { 'did not show as attached after it was added' } else { 'does not exist' })" }
    # The boot partition's disk: a 1 GB VHDX beside the working disk, made once
    # and kept (FAT32 inside, made in the guest below).
    $bootVhdx = Join-Path (Split-Path -Parent $scratch.Path) 'boot.vhdx'
    if (-not (Test-Path -LiteralPath $bootVhdx)) { $null = New-VHD -Path $bootVhdx -SizeBytes 1GB -Dynamic }
    if (-not ($drives | Where-Object Path -eq $bootVhdx)) {
        Invoke-DriveChange { Add-VMHardDiskDrive -VM (Get-LabVm) -ControllerType SCSI -Path $bootVhdx -ErrorAction Stop }
        if (-not (Wait-AttachedDrive $bootVhdx)) { throw "the boot partition's disk $bootVhdx did not show as attached after it was added" }
        $drives = @(Get-VMHardDiskDrive -VM $vm)
    }
    # The guest finds the working disk by its size where Windows does not
    # show its volume under a letter (#228).
    $scratchBytes = (Get-VHD -Path $scratch.Path).Size
    $others = @($drives | Where-Object { $_.Path -ne $disk0.Path -and $_.Path -ne $scratch.Path -and $_.Path -ne $bootVhdx })
    $detached = @($others | ForEach-Object { $_.Path })
    Set-Content -LiteralPath (Join-Path $records 'detached-disks.json') -Value ($detached | ConvertTo-Json) -Encoding utf8
    $dvdDrives = @(Get-VMDvdDrive -VM $vm | Where-Object Path)
    $dvd = @($dvdDrives | ForEach-Object Path) | Select-Object -First 1
    $firstBoot = @((Get-VMFirmware -VM $vm).BootOrder) | Select-Object -First 1
    $firstBootPath = if ($firstBoot -and "$($firstBoot.BootType)" -eq 'Drive' -and $firstBoot.Device -and $firstBoot.Device.Path) { "$($firstBoot.Device.Path)" } else { '' }
    Save-DetachedDisks $others $(if ($Image -ne 'media') { $dvdDrives } else { @() }) $firstBootPath
    $others | Remove-VMHardDiskDrive
    if ($Image -ne 'media') { Get-VMDvdDrive -VM $vm | Remove-VMDvdDrive }
    elseif (-not $dvd) { Add-VMDvdDrive -VM $vm -Path 'C:\Users\mfara\Downloads\Windows11_Client_x64_en-us_26300_9457.iso' }
    Set-VMFirmware -VM $vm -FirstBootDevice $disk0
    # What the VM starts with, as Hyper-V shows it.
    $verdict.drives_at_start = Get-DriveView
    Say "starting the VM's own Windows (disk0), working disk $($scratch.Path)"
    Start-VM -VM $vm
    $session = Wait-Guest 15
    if (-not $session) { throw 'the VM''s own Windows did not answer' }
    $restartedAt = $null
    try {
        $before = Invoke-Command -Session $session -ArgumentList $scratchBytes -ScriptBlock {
            param($scratchBytes)
            $c = Get-Volume -DriveLetter C
            # The working volume: labelled N2R_SCRATCH, under a letter. Where
            # Windows does not show it so (#228: the second case of a round on
            # one VM found none), its disk is looked for by its size, apart
            # from the Windows disk, and what it is is said; a disk that is
            # offline or read-only is brought online and writable, and a
            # volume without a letter is given one, each once, while Windows
            # has two minutes to show the volume.
            $windowsDisk = (Get-Partition -DriveLetter C).DiskNumber
            $first = ''; $state = ''; $changed = @(); $done = @{}
            $began = Get-Date; $deadline = $began.AddMinutes(2)
            while ($true) {
                $scratch = Get-Volume | Where-Object { $_.FileSystemLabel -eq 'N2R_SCRATCH' -and "$($_.DriveLetter)" -match '^[A-Za-z]$' } | Select-Object -First 1
                if ($scratch) { break }
                $disks = @(Get-Disk | Where-Object { $_.Size -eq $scratchBytes -and $_.Number -ne $windowsDisk })
                if ($disks.Count -ne 1) {
                    $state = "$($disks.Count) disks of the working disk's size ($scratchBytes bytes) besides the Windows disk: $(if ($disks.Count) { 'which is the working disk is not known' } else { 'the working disk is not attached' })"
                } else {
                    $disk = $disks[0]
                    $parts = @(Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue | ForEach-Object {
                            $volume = $_ | Get-Volume -ErrorAction SilentlyContinue
                            "partition $($_.PartitionNumber) ($($_.Type)): letter '$($_.DriveLetter)', hidden $($_.IsHidden), no default letter $($_.NoDefaultDriveLetter), volume '$($volume.FileSystemLabel)' $($volume.FileSystem) $($volume.HealthStatus)" })
                    $state = "disk $($disk.Number): offline $($disk.IsOffline)$(if ($disk.IsOffline) { " ($($disk.OfflineReason))" }), read-only $($disk.IsReadOnly), $($disk.PartitionStyle); $(if ($parts) { $parts -join '; ' } else { 'no partitions shown' })"
                    $part = @(Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue | Where-Object { ($_ | Get-Volume -ErrorAction SilentlyContinue).FileSystemLabel -eq 'N2R_SCRATCH' }) | Select-Object -First 1
                    $repair = if ($disk.IsOffline -and -not $done.online) { 'online' }
                        elseif ($disk.IsReadOnly -and -not $done.writable) { 'writable' }
                        elseif ($part -and "$($part.DriveLetter)" -notmatch '^[A-Za-z]$' -and -not $done.letter) { 'letter' }
                    if ($repair) {
                        if (-not $first) { $first = $state }
                        $done[$repair] = $true
                        try {
                            switch ($repair) {
                                'online' { Set-Disk -Number $disk.Number -IsOffline $false -ErrorAction Stop; $changed += "disk $($disk.Number) was offline ($($disk.OfflineReason)): brought online" }
                                'writable' { Set-Disk -Number $disk.Number -IsReadOnly $false -ErrorAction Stop; $changed += "disk $($disk.Number) was read-only: made writable" }
                                'letter' { $part | Add-PartitionAccessPath -AssignDriveLetter -ErrorAction Stop; $changed += "partition $($part.PartitionNumber) of disk $($disk.Number) had no letter: given one" }
                            }
                        } catch { $changed += "disk $($disk.Number): making it $repair failed: $($_.Exception.Message)" }
                        continue
                    }
                }
                if (-not $first) { $first = $state }
                if ((Get-Date) -ge $deadline) { break }
                Start-Sleep -Seconds 5
            }
            $serial = ((cmd /c 'vol C:') | Select-String 'Serial Number').ToString().Split(' ')[-1]
            [pscustomobject]@{ filesystem = [string]$c.FileSystem; serial = $serial; scratch = if ($scratch) { "$($scratch.DriveLetter):" } else { '' }; scratch_fs = [string]$scratch.FileSystem
                build = (Get-CimInstance Win32_OperatingSystem).BuildNumber; free_gb = [Math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 1)
                working_disk = [ordered]@{ seconds = [int]((Get-Date) - $began).TotalSeconds; first_seen = $first; last_seen = $state; changed = $changed } }
        }
        $verdict.before = $before
        Say "running Windows: C: is $($before.filesystem), serial $($before.serial), build $($before.build); working disk $($before.scratch); RAM free $($before.free_gb) GB"
        if ($before.working_disk.first_seen) { Say "the working volume was not under a letter when Windows came up ($($before.working_disk.first_seen)); after $($before.working_disk.seconds) s: $(if (@($before.working_disk.changed).Count) { @($before.working_disk.changed) -join '; ' } else { 'nothing changed by the harness' })" }
        if ($before.filesystem -ne 'NTFS') { throw "C: is $($before.filesystem), not NTFS" }
        if ($before.scratch -notmatch '^[A-Z]:$') { throw "the running Windows has no volume labelled N2R_SCRATCH under a letter after $($before.working_disk.seconds) s: $($before.working_disk.last_seen)" }
        # What earlier attempts left on the working volume: their run folders
        # and the folders their recoveries and cancellations wrote beside
        # them. A virtual disk under one that Windows still has attached is
        # detached first.
        $swept = Invoke-Command -Session $session -ArgumentList $before.scratch -ScriptBlock {
            param($scratch)
            $removed = @(); $kept = @()
            $old = @(Get-ChildItem -LiteralPath "$scratch\" -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like 'runs-*' -or $_.Name -like 'ntfs2refs-preparation-cancel-*' -or $_.Name -like 'ntfs2refs-recovery-*' })
            foreach ($directory in $old) {
                foreach ($disk in @(Get-ChildItem -LiteralPath $directory.FullName -Recurse -Force -Filter '*.vhdx' -ErrorAction SilentlyContinue)) {
                    $script = Join-Path $env:TEMP 'n2r-detach.txt'
                    Set-Content -LiteralPath $script -Value ("select vdisk file=`"$($disk.FullName)`"`r`ndetach vdisk") -Encoding ASCII
                    $null = & diskpart.exe /s $script 2>&1
                }
                try { Remove-Item -LiteralPath $directory.FullName -Recurse -Force -ErrorAction Stop; $removed += $directory.Name }
                catch { $kept += "$($directory.Name): $($_.Exception.Message)" }
            }
            [pscustomobject]@{ removed = $removed; kept = $kept; free_gb = [Math]::Round((Get-Volume -DriveLetter $scratch[0]).SizeRemaining / 1GB, 1) }
        }
        $verdict.working_volume = [ordered]@{ removed = @($swept.removed); not_removed = @($swept.kept); free_gb = $swept.free_gb }
        Say "working volume $($before.scratch): $(@($swept.removed).Count) folder(s) of earlier attempts removed$(if (@($swept.kept).Count) { ", $(@($swept.kept).Count) could not be removed ($(@($swept.kept) -join '; '))" }); $($swept.free_gb) GB free"
        $runs = "$($before.scratch)\runs-$Name"
        # The boot partition: FAT32, letter B, on the 1 GB disk.
        $bootLetter = Invoke-Command -Session $session -ScriptBlock {
            $disk = Get-Disk | Where-Object { $_.Size -eq 1GB } | Select-Object -First 1
            if (-not $disk) { throw 'no 1 GB boot disk in the guest' }
            if ($disk.PartitionStyle -eq 'RAW') { $null = Initialize-Disk -Number $disk.Number -PartitionStyle GPT }
            $part = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Type -eq 'Basic' -or $_.GptType -eq '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' } | Select-Object -First 1
            if (-not $part) { $part = New-Partition -DiskNumber $disk.Number -UseMaximumSize; $null = Format-Volume -Partition $part -FileSystem FAT32 -NewFileSystemLabel N2R_BOOT -Confirm:$false }
            if (-not $part.DriveLetter -or $part.DriveLetter -eq [char]0) { $part | Set-Partition -NewDriveLetter B; $part = Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber }
            [string]$part.DriveLetter
        }
        Say "boot partition: $($bootLetter): (FAT32, 1 GB disk)"
        Invoke-Command -Session $session -ScriptBlock { $null = New-Item -ItemType Directory -Force -Path 'C:\n2r' }
        Copy-Item -ToSession $session -LiteralPath $Binary -Destination 'C:\n2r\ntfs2refs.exe'
        $arguments = @('--drive', 'C', '--scratch-directory', $runs, '--boot-partition', $bootLetter, '--yes', '--volume-serial', $before.serial) + $ConverterArgs
        if ($Diagnose) { $arguments += '--diagnose' }
        $verdict.converter_arguments = $arguments
        Say "running: ntfs2refs $($arguments -join ' ')"
        # ('none' is no hold point: the converter would refuse the name.)
        $said = Invoke-Command -Session $session -ArgumentList (, $arguments), $SanPolicy, [bool]$Hold, $Image, $(if ($timedCut) { '' } else { $HoldAt }) -ScriptBlock {
            param($arguments, $san, $hold, $image, $holdAt)
            if ($san) { $env:N2R_LAB_SAN_POLICY = $san }
            if ($holdAt) { $env:N2R_LAB_HOLD_AT = $holdAt }
            if ($hold -eq $true) { $env:N2R_LAB_HOLD_IN_IMAGE = '1' } else { Remove-Item Env:N2R_LAB_HOLD_IN_IMAGE -ErrorAction SilentlyContinue }
            if ($image -eq 'media') {
                $dvd = Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -and $_.DriveLetter } | Select-Object -First 1
                Copy-Item "$($dvd.DriveLetter):\sources\boot.wim" "$env:TEMP\n2r-boot.wim" -Force
                Set-ItemProperty "$env:TEMP\n2r-boot.wim" -Name IsReadOnly -Value $false
                $env:N2R_LAB_IMAGE = "$env:TEMP\n2r-boot.wim|2"
            }
            $ErrorActionPreference = 'Continue'
            (& C:\n2r\ntfs2refs.exe @arguments 2>&1 | Out-String)
        }
        $restartedAt = Get-Date
        [IO.File]::WriteAllText((Join-Path $records 'windows-side.txt'), $said, [Text.UTF8Encoding]::new($false))
        # A refusal in Windows changes nothing and restarts nothing: say it and stop.
        if ($said -notmatch 'Restarting in') {
            $refusal = ($said -split "`n" | Where-Object { $_ -match '^error:' } | Select-Object -First 1)
            $verdict.outcome = 'REFUSED-IN-WINDOWS'; $verdict.refusal = "$refusal".Trim()
            Say "refused in Windows, nothing restarted: $($verdict.refusal)"
            return
        }
        if ($Hold) {
            $null = Invoke-Command -Session $session -ArgumentList "$runs\n2r-running\hold.flag" -ScriptBlock { param($f) Set-Content -LiteralPath $f -Value hold }
            $verdict.outcome = 'held-in-the-environment'
            Say 'hold: the recovery environment stops at a command prompt'; return
        }
        Say 'the run staged the recovery environment and restarted the machine'
    } finally { Remove-PSSession $session -ErrorAction SilentlyContinue }

    # Away: the recovery environment (the conversion), then Windows again.
    Start-Sleep -Seconds 45
    $cutMade = $false
    if ($HoldAt) {
        $ceiling = $restartedAt.AddMinutes($CutAfterMinutes)
        if ($timedCut) { Say "no hold: the VM is turned off $CutAfterMinutes minutes after the restart, wherever the run is then" }
        else { Say "hold at ${HoldAt}: the VM is turned off when its screen has stood still for two minutes, $HoldAfterMinutes minutes after the restart at the earliest and $CutAfterMinutes at the latest" }
        $reference = $null; $stillSince = $null; $why = ''; $windowsBack = $false; $screen = $null
        while (-not $why -and -not $windowsBack) {
            $now = Get-Date
            $since = ($now - $restartedAt).TotalSeconds
            if ($now -ge $ceiling) { $why = if ($timedCut) { 'timed' } else { 'ceiling' }; break }
            # The environment has no integration services: a heartbeat means the
            # run ended early and Windows is back; there is nothing to cut. (Not
            # asked in the first two minutes, while the Windows that restarts
            # may still answer.)
            if ($since -ge 120 -and (Get-VMIntegrationService -VM (Get-LabVm) -Name 'Heartbeat').PrimaryStatusDescription -eq 'OK') { $windowsBack = $true; break }
            if (-not $timedCut) {
                # A held converter parks for ever and writes nothing more: the
                # screen stays as it is. A screen that cannot be read counts
                # as one that changed.
                $screen = Get-VmScreen
                if (-not $screen) { $reference = $null; $stillSince = $null }
                elseif (-not $reference -or [N2RScreen]::Differing($reference, $screen) -gt $screenTolerance) { $reference = $screen; $stillSince = $now }
                elseif (($now - $stillSince).TotalSeconds -ge 120 -and $since -ge $HoldAfterMinutes * 60) { $why = 'parked'; break }
            }
            Start-Sleep -Seconds ([int][Math]::Max(1, [Math]::Min(15, ($ceiling - (Get-Date)).TotalSeconds)))
        }
        $minutes = [Math]::Round(((Get-Date) - $restartedAt).TotalMinutes, 1)
        Say $(if ($windowsBack) { 'Windows is back before the cut: the run ended early' } elseif ($why -eq 'parked') { "the screen has stood still for two minutes ($minutes minutes after the restart): the converter is taken to be parked at the hold" } elseif ($why -eq 'timed') { "$minutes minutes after the restart" } else { "the latest time came first ($minutes minutes after the restart)" })
        if (-not $windowsBack) {
            # What the screen showed when the power went.
            $last = Get-VmScreen
            if (-not $last) { $last = $screen }
            Save-VmScreen $last (Join-Path $records 'screen-at-cut.png')
            Stop-VM -VM (Get-LabVm) -TurnOff -Force
            Say 'turned off (power cut); starting again, the run has to recover by itself'
            Start-VM -VM (Get-LabVm)
            $cutMade = $true
            $verdict.cut = [ordered]@{ hold_at = $HoldAt; decided_by = $why; minutes_after_restart = $minutes; latest_minutes = $CutAfterMinutes }
        }
    }
    # Windows has AwayMinutes to come back: from the restart, or from the
    # power cut, after which the run starts its recovery.
    $deadline = $(if ($cutMade) { Get-Date } else { $restartedAt }).AddMinutes($AwayMinutes)
    $back = $null
    $found = $null
    do {
        Start-Sleep -Seconds 20
        try {
            $back = New-PSSession -VMId $VmId -Credential $credential -ErrorAction Stop
            # (The working volume may have another letter than before the restart.)
            $found = Invoke-Command -Session $back -ArgumentList $before.scratch, $Name -ScriptBlock {
                param($scratch, $name)
                $volume = Get-Volume | Where-Object { $_.FileSystemLabel -eq 'N2R_SCRATCH' -and $_.DriveLetter } | Select-Object -First 1
                $root = if ($volume) { "$($volume.DriveLetter):" } else { $scratch }
                $staging = "$root\runs-$name\n2r-running"
                $p = "$staging\session-result.txt"
                if (Test-Path -LiteralPath $p) { [pscustomobject]@{ staging = $staging; report = [string](Get-Content -LiteralPath $p -Raw) } }
            }
            if (-not $found -or -not $found.report) { Remove-PSSession $back; $back = $null }
        } catch { $back = $null }
        if ($back) { break }
    } while ((Get-Date) -lt $deadline)
    if (-not $back) {
        $verdict.outcome = 'no-return'; Say "Windows did not come back with the run's report within $AwayMinutes minutes"
        Save-VmScreen (Get-VmScreen) (Join-Path $records 'screen-no-return.png')
    } else {
        $report = $found.report
        try {
            [IO.File]::WriteAllText((Join-Path $records 'session-result.txt'), $report, [Text.UTF8Encoding]::new($false))
            # What the converter and its recovery said in the environment, kept on the working disk.
            foreach ($leaf in 'converter-output.txt', 'converter-errors.txt', 'recover-forward-output.txt', 'recover-rollback-output.txt', 'recover-command.json', 'recover-command.done.json') {
                try { Copy-Item -FromSession $back -LiteralPath "$($found.staging)\$leaf" -Destination $records -ErrorAction Stop } catch { }
            }
            $after = Invoke-Command -Session $back -ArgumentList (Split-Path -Parent $found.staging) -ScriptBlock {
                param($run)
                $c = Get-Volume -DriveLetter C
                $bcd = (& bcdedit.exe /enum '{bootmgr}' 2>&1 | Out-String)
                $refs = (& "$env:SystemRoot\System32\fsutil.exe" fsinfo refsinfo C: 2>&1 | Out-String)
                # Whether this Windows has the run's virtual disks attached
                # (#182): a run folder cannot be removed while one is, and a
                # finished run or recovery detaches its working volume. What
                # Windows answers for each, or why it would not.
                $images = @(Get-ChildItem -LiteralPath $run -Recurse -Force -Filter '*.vhdx' -ErrorAction SilentlyContinue | ForEach-Object {
                    $image = $_.FullName
                    # Windows' own list of disks names an attached image's file
                    # in Location and opens nothing; Get-DiskImage opens the
                    # image and is refused (Access is denied) as the converter
                    # was before #182.
                    try { [pscustomobject]@{ path = $image; attached = [bool](@(Get-Disk -ErrorAction Stop | Where-Object { $_.Location -and $_.Location -ieq $image }).Count) } }
                    catch { [pscustomobject]@{ path = $image; error = "$($_.Exception.Message)" } }
                })
                [pscustomobject]@{ filesystem = [string]$c.FileSystem; health = [string]$c.HealthStatus; cluster_bytes = $c.AllocationUnitSize; bootmgr = $bcd; refsinfo = $refs
                    boot_utc = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o'); run_images = $images }
            }
            $verdict.after = $after
            Say "back in Windows: C: is $($after.filesystem), health $($after.health)"
            foreach ($runImage in @($after.run_images)) {
                Say "the run's $(Split-Path -Leaf $runImage.path) ($($runImage.path)): $(if ($runImage.error) { "Windows did not say whether it is attached: $($runImage.error)" } elseif ($runImage.attached) { 'ATTACHED' } else { 'not attached' })"
            }
            $expected = if ($Diagnose) { 'NTFS' } else { 'ReFS' }
            $converterEnded = if ($report -match 'The converter ended with exit code: (\d+)') { [int]$Matches[1] } else { -1 }
            $verdict.converter_exit = $converterEnded
            $healthy = $after.health -eq 'Healthy'
            if ($cutMade) {
                # What the start after the cut said it did, and what C: is,
                # have to agree. A start that found nothing to recover from
                # was cut before the converter had begun: it converted anew,
                # and nothing was recovered.
                $recovered = $report -match 'An earlier start of this run was cut off'
                $saidTo = if ($report -match 'The recovery finished: the volume is converted') { 'ReFS' }
                    elseif ($report -match 'The recovery finished: the run had not started writing' -or $report -match 'The recovery put the NTFS volume back') { 'NTFS' } else { '' }
                $verdict.cut.recovered_after_it = [bool]$recovered; $verdict.cut.recovery_said = $saidTo
                # Whether the converter had reported the hold before the power went.
                $transcript = Join-Path $records 'converter-output.txt'
                $verdict.cut.hold_reported = if ($timedCut) { $null } elseif (Test-Path -LiteralPath $transcript) {
                    [bool](Select-String -LiteralPath $transcript -SimpleMatch -Pattern "`"kind`":`"lab-hold-v1`",`"point`":`"$HoldAt`"" -Quiet) } else { $false }
                if (-not $timedCut) { Say "the converter's own output $(if ($verdict.cut.hold_reported) { "has its hold at '$HoldAt'" } elseif (Test-Path -LiteralPath $transcript) { "does NOT have its hold at '$HoldAt': the power was cut somewhere else" } else { 'was not found on the working disk' })" }
                $verdict.outcome = if (-not $recovered) { 'CUT-BEFORE-THE-RUN-BEGAN' }
                    elseif (-not $timedCut -and -not $verdict.cut.hold_reported) { 'CUT-NOT-AT-THE-HOLD' }
                    elseif ($saidTo -eq 'ReFS' -and $after.filesystem -eq 'ReFS' -and $healthy) { 'CUT-RECOVERED-TO-REFS' }
                    elseif ($saidTo -eq 'NTFS' -and $after.filesystem -eq 'NTFS' -and $healthy) { 'CUT-BACK-TO-NTFS' }
                    else { "CUT-RECOVERY-UNCLEAR-C-IS-$($after.filesystem)" }
            } elseif ($HoldAt) {
                # The power was to be cut and was not: whatever the run left, this is not the case asked for.
                $verdict.outcome = 'RUN-ENDED-BEFORE-THE-CUT'
            } else {
                $verdict.outcome = if ($after.filesystem -eq $expected -and $converterEnded -eq 0 -and $healthy) { 'PASSED' } elseif ($converterEnded -ne 0) { "CONVERTER-EXIT-$converterEnded" }
                    elseif ($after.filesystem -ne $expected) { "C-IS-$($after.filesystem)" } else { "C-IS-$($after.filesystem)-$($after.health)" }
            }
        } finally { Remove-PSSession $back -ErrorAction SilentlyContinue }
        if ($Acceptance -and $after.filesystem -eq 'ReFS' -and $verdict.outcome -in 'PASSED', 'CUT-RECOVERED-TO-REFS') {
            # Coming back is not the same as going on being used and serviced.
            # (The installation media comes back for the use test, whose Setup scan reads it.)
            # At the place it had: the first free place was that of a disk the
            # attempt had detached, which then could not return (#228).
            if ($dvd -and -not (Get-VMDvdDrive -VM (Get-LabVm) | Where-Object Path -EQ $dvd)) {
                $place = $dvdDrives | Where-Object Path -EQ $dvd | Select-Object -First 1
                $taken = $place -and (@(Get-VMHardDiskDrive -VM (Get-LabVm)) + @(Get-VMDvdDrive -VM (Get-LabVm)) | Where-Object { $_.ControllerNumber -eq $place.ControllerNumber -and $_.ControllerLocation -eq $place.ControllerLocation })
                try {
                    if ($place -and -not $taken) { Invoke-DriveChange { Add-VMDvdDrive -VM (Get-LabVm) -ControllerNumber $place.ControllerNumber -ControllerLocation $place.ControllerLocation -Path $dvd -ErrorAction Stop } }
                    else { Invoke-DriveChange { Add-VMDvdDrive -VM (Get-LabVm) -Path $dvd -ErrorAction Stop } }
                    Say "installation media attached again for the use test: $dvd"
                } catch { Say "the installation media could not be attached again: $($_.Exception.Message)" }
            }
            $use = Invoke-WindowsUseTest 'ReFS' | Select-Object -Last 1
            $verdict.acceptance = $use
            if (-not $use.passed) { $verdict.result = $verdict.outcome; $verdict.outcome = "$($verdict.outcome)-BUT-USE-FAILED" }
        } elseif ($Acceptance) { Say "no use test: C: is $($after.filesystem) and the outcome is $($verdict.outcome)" }
    }
} catch {
    $failure = $_
    # Nothing here sets an outcome and then stops on purpose: an error after
    # one was set (in the use test, say) must not leave it standing as the
    # attempt's result.
    if ($verdict.outcome -ne 'harness-error') { $verdict.result = $verdict.outcome; $verdict.outcome = 'harness-error' }
    $verdict.error = "$($_.Exception.Message)"
    Say "error: $($_.Exception.Message)"
} finally {
    if ($Reattach) {
        try {
            $vm = Get-LabVm
            if ($vm.State -ne 'Off') { try { Stop-VM -VM $vm -Force } catch { Stop-VM -VM (Get-LabVm) -TurnOff -Force } }
            $returned = Restore-DetachedDisks -Everything
            $verdict.reattached = $returned
            Say "the VM is off and has $returned of its detached disk(s) and media back, each in its place"
        } catch { $verdict.reattach_error = "$($_.Exception.Message)"; Say "the detached disks could not be given back: $($_.Exception.Message)" }
    } else { Say 'the detached disks (control OS and others) are listed in detached-disks.json; -Reattach, or the next attempt that restores a checkpoint, gives them back' }
    $verdict.finished = (Get-Date).ToString('o')
    Save-Verdict
    Say "outcome: $($verdict.outcome)"
}
if ($failure) { throw $failure }
