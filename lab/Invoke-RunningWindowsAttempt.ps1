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
  (Invoke-BootConversionAttempt.ps1 -NoConvert -KeepScratch); its VHDX is
  named with -ScratchVhdx and is attached by that attempt's configuration.
  Nothing under .lab is deleted here.
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
    # (crates/n2r-win32/src/lab_hold.rs), turn the VM off CutAfterMinutes after
    # the restart, as if the power went, and start it again: the run must
    # recover by itself.
    [string]$HoldAt,
    [int]$CutAfterMinutes = 40,
    # The working disk to attach when the VM has none (after a checkpoint was
    # restored).
    [string]$ScratchVhdx,
    [string[]]$ConverterArgs = @()
)
$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
if (-not $ScratchVhdx) { $ScratchVhdx = Join-Path $workspace '.lab\hyperv\attempts\envprobe-c-up\scratch.vhdx' }
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

# The VM boots its own Windows: disk0 first, the control OS's disks and the
# installation media detached (not deleted), the working disk kept.
$vm = Get-LabVm
if ($vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Force }
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
$others | Remove-VMHardDiskDrive
$dvd = @(Get-VMDvdDrive -VM $vm | Where-Object Path | ForEach-Object Path) | Select-Object -First 1
if ($Image -ne 'media') { Get-VMDvdDrive -VM $vm | Remove-VMDvdDrive }
elseif (-not $dvd) { Add-VMDvdDrive -VM $vm -Path 'C:\Users\mfara\Downloads\Windows11_Client_x64_en-us_26300_9457.iso' }
Set-VMFirmware -VM $vm -FirstBootDevice $disk0
Say "starting the VM's own Windows (disk0), working disk $($scratch.Path)"
Start-VM -VM $vm
$session = Wait-Guest 15
if (-not $session) { throw 'the VM'' own Windows did not answer' }
$verdict = [ordered]@{ name = $Name; started = (Get-Date).ToString('o'); outcome = 'unknown' }
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
    Say "running: ntfs2refs $($arguments -join ' ')"
    $said = Invoke-Command -Session $session -ArgumentList (, $arguments), $SanPolicy, [bool]$Hold, $Image, $HoldAt -ScriptBlock {
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
    [IO.File]::WriteAllText((Join-Path $records 'windows-side.txt'), $said, [Text.UTF8Encoding]::new($false))
    if ($Hold) { $null = Invoke-Command -Session $session -ArgumentList "$runs\n2r-running\hold.flag" -ScriptBlock { param($f) Set-Content -LiteralPath $f -Value hold }; Say 'hold: the recovery environment stops at a command prompt'; return }
    Say 'the run staged the recovery environment and restarted the machine'
} finally { Remove-PSSession $session -ErrorAction SilentlyContinue }

# Away: the recovery environment (the conversion), then Windows again.
$deadline = (Get-Date).AddMinutes($AwayMinutes)
Start-Sleep -Seconds 45
if ($HoldAt) {
    Say "hold at ${HoldAt}: the VM is turned off $CutAfterMinutes minutes after the restart"
    Start-Sleep -Seconds ($CutAfterMinutes * 60)
    $shot = Join-Path $records 'at-cut.png'
    Stop-VM -VM (Get-LabVm) -TurnOff -Force
    Say "turned off (power cut); starting again, the run has to recover by itself"
    Start-VM -VM (Get-LabVm)
    $verdict.cut = @{ hold_at = $HoldAt; minutes = $CutAfterMinutes }
}
$back = $null
$report = $null
do {
    Start-Sleep -Seconds 20
    try {
        $back = New-PSSession -VMId $VmId -Credential $credential -ErrorAction Stop
        $report = Invoke-Command -Session $back -ArgumentList $before.scratch, $Name -ScriptBlock {
            param($scratch, $name)
            $p = "$scratch\runs-$name\n2r-running\session-result.txt"
            if (Test-Path -LiteralPath $p) { Get-Content -LiteralPath $p -Raw }
        }
        if (-not $report) { Remove-PSSession $back; $back = $null }
    } catch { $back = $null }
    if ($back) { break }
} while ((Get-Date) -lt $deadline)
if (-not $back) { $verdict.outcome = 'no-return'; Say "Windows did not come back with the run's report within $AwayMinutes minutes" }
else {
    try {
        [IO.File]::WriteAllText((Join-Path $records 'session-result.txt'), $report, [Text.UTF8Encoding]::new($false))
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
        $verdict.outcome = if ($after.filesystem -eq $expected -and $converterEnded -eq 0) { 'PASSED' } elseif ($converterEnded -ne 0) { "CONVERTER-EXIT-$converterEnded" } else { "C-IS-$($after.filesystem)" }
    } finally { Remove-PSSession $back -ErrorAction SilentlyContinue }
}
$verdict.finished = (Get-Date).ToString('o')
[IO.File]::WriteAllText((Join-Path $records 'verdict.json'), ($verdict | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
Say "outcome: $($verdict.outcome)"
Say "the detached disks (control OS and others) are listed in detached-disks.json; reattach them to use the control OS again"
