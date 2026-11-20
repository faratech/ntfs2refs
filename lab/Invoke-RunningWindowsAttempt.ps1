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
# Before a checkpoint is restored: the differencing disks only, as the boot
# harness returns them. With -Everything (for -Reattach): every disk that is
# still there, the installation media, and the device the VM started from.
function Restore-DetachedDisks([switch]$Everything) {
    $record = Read-DetachedDiskRecord
    if (-not $record) { return 0 }
    $returned = 0
    foreach ($disk in @($record.disks)) {
        if (-not $disk -or -not $disk.path -or -not (Test-Path -LiteralPath $disk.path)) { continue }
        if (-not $Everything -and $disk.path -notlike '*.avhdx') { continue }
        $drives = @(Get-VMHardDiskDrive -VM (Get-LabVm))
        if (($drives | Where-Object { $_.ControllerNumber -eq $disk.controller_number -and $_.ControllerLocation -eq $disk.controller_location }) -or ($drives | Where-Object Path -EQ $disk.path)) { continue }
        try {
            Add-VMHardDiskDrive -VM (Get-LabVm) -ControllerType SCSI -ControllerNumber $disk.controller_number -ControllerLocation $disk.controller_location -Path $disk.path -ErrorAction Stop
            $returned++
        } catch { Say "could not return $(Split-Path -Leaf $disk.path) to the VM: $($_.Exception.Message)" }
    }
    if ($Everything) {
        foreach ($dvd in @($record.dvds)) {
            if (-not $dvd -or -not $dvd.path -or -not (Test-Path -LiteralPath $dvd.path)) { continue }
            if (Get-VMDvdDrive -VM (Get-LabVm) | Where-Object Path -EQ $dvd.path) { continue }
            try {
                Add-VMDvdDrive -VM (Get-LabVm) -ControllerNumber $dvd.controller_number -ControllerLocation $dvd.controller_location -Path $dvd.path -ErrorAction Stop
                $returned++
            } catch { Say "could not return the installation media $(Split-Path -Leaf $dvd.path) to the VM: $($_.Exception.Message)" }
        }
        if ($record.first_boot_path) {
            $first = @(@(Get-VMHardDiskDrive -VM (Get-LabVm)) + @(Get-VMDvdDrive -VM (Get-LabVm)) | Where-Object Path -EQ $record.first_boot_path) | Select-Object -First 1
            if ($first) { try { Set-VMFirmware -VM (Get-LabVm) -FirstBootDevice $first -ErrorAction Stop } catch { Say "could not make $(Split-Path -Leaf $record.first_boot_path) the first boot device again: $($_.Exception.Message)" } }
        }
    }
    # The record is spent whether or not every disk could be returned.
    [ordered]@{ vm_id = $VmId; attempt = $record.attempt; disks = @(); returned = $returned; returned_utc = [DateTime]::UtcNow.ToString('o') } |
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
        try { Stop-VM -VM (Get-LabVm) -Force } catch { Stop-VM -VM (Get-LabVm) -TurnOff -Force }
        Start-VM -VM (Get-LabVm)
        $guest = Wait-Guest 15
        if (-not $guest) { $result.restarts += "start ${round}: Windows did not come back"; $restartsOk = $false; break }
        $state = Invoke-Command -Session $guest -ScriptBlock { $volume = Get-Volume -DriveLetter $env:SystemDrive[0]; "$($volume.FileSystem) $($volume.HealthStatus)" }
        Remove-PSSession $guest
        $result.restarts += "start ${round}: $state"
        if ($state -ne "$Expected Healthy") { $restartsOk = $false }
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
        Restore-VMSnapshot -VMSnapshot $snapshots[0] -Confirm:$false
        $vm = Get-LabVm
        if ($vm.State -eq 'Saved') { Remove-VMSavedState -VM $vm; $vm = Get-LabVm }
        if ($vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Force; $vm = Get-LabVm }
        $verdict.restored_checkpoint = $snapshots[0].Name
    }
    Set-VMMemory -VM $vm -DynamicMemoryEnabled $false -StartupBytes ($MemoryGB * 1GB)
    $drives = @(Get-VMHardDiskDrive -VM $vm)
    $disk0 = $drives | Where-Object { $_.ControllerNumber -eq 0 -and $_.ControllerLocation -eq 0 }
    $scratch = $drives | Where-Object { $_.Path -like '*\scratch.vhdx' } | Select-Object -First 1
    if (-not $scratch -and (Test-Path -LiteralPath $ScratchVhdx)) {
        Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -Path $ScratchVhdx
        $drives = @(Get-VMHardDiskDrive -VM $vm)
        $scratch = $drives | Where-Object { $_.Path -eq $ScratchVhdx }
    }
    if (-not $disk0 -or -not $scratch) { throw 'the VM needs its disk0 and a scratch.vhdx attached' }
    # The boot partition's disk: a 1 GB VHDX beside the working disk, made once
    # and kept (FAT32 inside, made in the guest below).
    $bootVhdx = Join-Path (Split-Path -Parent $scratch.Path) 'boot.vhdx'
    if (-not (Test-Path -LiteralPath $bootVhdx)) { $null = New-VHD -Path $bootVhdx -SizeBytes 1GB -Dynamic }
    if (-not ($drives | Where-Object Path -eq $bootVhdx)) { Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -Path $bootVhdx; $drives = @(Get-VMHardDiskDrive -VM $vm) }
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
    Say "starting the VM's own Windows (disk0), working disk $($scratch.Path)"
    Start-VM -VM $vm
    $session = Wait-Guest 15
    if (-not $session) { throw 'the VM''s own Windows did not answer' }
    $restartedAt = $null
    try {
        $before = Invoke-Command -Session $session -ScriptBlock {
            $c = Get-Volume -DriveLetter C
            $scratch = Get-Volume | Where-Object FileSystemLabel -eq 'N2R_SCRATCH' | Select-Object -First 1
            $serial = ((cmd /c 'vol C:') | Select-String 'Serial Number').ToString().Split(' ')[-1]
            [pscustomobject]@{ filesystem = [string]$c.FileSystem; serial = $serial; scratch = "$($scratch.DriveLetter):"; scratch_fs = [string]$scratch.FileSystem
                build = (Get-CimInstance Win32_OperatingSystem).BuildNumber; free_gb = [Math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 1) }
        }
        $verdict.before = $before
        Say "running Windows: C: is $($before.filesystem), serial $($before.serial), build $($before.build); working disk $($before.scratch); RAM free $($before.free_gb) GB"
        if ($before.filesystem -ne 'NTFS') { throw "C: is $($before.filesystem), not NTFS" }
        if ($before.scratch -notmatch '^[A-Z]:$') { throw 'the running Windows has no volume labelled N2R_SCRATCH under a letter: the working disk is not there' }
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
    $deadline = (Get-Date).AddMinutes($AwayMinutes)
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
            $after = Invoke-Command -Session $back -ScriptBlock {
                $c = Get-Volume -DriveLetter C
                $bcd = (& bcdedit.exe /enum '{bootmgr}' 2>&1 | Out-String)
                $refs = (& "$env:SystemRoot\System32\fsutil.exe" fsinfo refsinfo C: 2>&1 | Out-String)
                [pscustomobject]@{ filesystem = [string]$c.FileSystem; health = [string]$c.HealthStatus; cluster_bytes = $c.AllocationUnitSize; bootmgr = $bcd; refsinfo = $refs
                    boot_utc = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') }
            }
            $verdict.after = $after
            Say "back in Windows: C: is $($after.filesystem), health $($after.health)"
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
            if ($dvd -and -not (Get-VMDvdDrive -VM (Get-LabVm) | Where-Object Path -EQ $dvd)) {
                try { Add-VMDvdDrive -VM (Get-LabVm) -Path $dvd; Say "installation media attached again for the use test: $dvd" }
                catch { Say "the installation media could not be attached again: $($_.Exception.Message)" }
            }
            $use = Invoke-WindowsUseTest 'ReFS' | Select-Object -Last 1
            $verdict.acceptance = $use
            if (-not $use.passed) { $verdict.result = $verdict.outcome; $verdict.outcome = "$($verdict.outcome)-BUT-USE-FAILED" }
        } elseif ($Acceptance) { Say "no use test: C: is $($after.filesystem) and the outcome is $($verdict.outcome)" }
    }
} catch {
    $failure = $_
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
