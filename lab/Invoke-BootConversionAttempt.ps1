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
    [int]$Processors = 8,
    [int]$ScratchGB = 120,
    [ValidateSet('ReFS', 'NTFS')][string]$ScratchFileSystem = 'ReFS',
    [string[]]$ConverterArgs = @(),
    # Record where the converter spends its time: stacks.txt in the attempt
    # folder, one line per distinct call stack with its sample count.
    [switch]$SampleStacks,
    [switch]$Fixture,
    [switch]$Diagnose,
    [switch]$NoBoot,
    [switch]$NoConvert,
    # Leave the scratch disk (and the control OS, if still up) for inspection.
    [switch]$KeepScratch,
    # If the converter stops after it has written ReFS to the source, shut the
    # VM down and save that state under this checkpoint name. Finalization can
    # then be retried in minutes with -Recover instead of a whole new run.
    [string]$CheckpointAfterConvert,
    # Save the converted, not yet booted state under this checkpoint name
    # before the boot attempt, with the control OS and scratch disk still
    # attached, so a failed boot can be examined and tried again without
    # converting again. Keeps the scratch disk, which the checkpoint uses.
    [string]$CheckpointBeforeBoot,
    # Restore -Checkpoint (one saved by -CheckpointAfterConvert) and run
    # `ntfs2refs --recover` with the command the original run printed.
    [switch]$Recover,
    # Recovery qualification. Stop the converter at a named point of apply or
    # handoff (crates/n2r-win32/src/lab_hold.rs lists them), end its process
    # there, then run the recovery command it printed and compare as usual.
    [string]$InterruptAt,
    [ValidateSet('resume', 'rollback', 'none')][string]$RecoverMode = 'resume',
    [int]$SourceDisk = 0,
    [int]$SourcePartition = 3,
    # Independent check: list the source before conversion and the converted
    # volume after, and require the two listings to match.
    [string]$ManifestBinary,
    [switch]$NoManifest,
    [int]$MinHostFreeGB = 40,
    [int]$ConvertTimeoutMinutes = 720,
    [int]$BootTimeoutMinutes = 25,
    # The reference VM, or a clone of it made by lab/New-LabVmClone.ps1.
    [string]$VmId = '8f7fc646-8c9f-41d0-b65a-ecfadccfc36a'
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$workspace = Split-Path -Parent $PSScriptRoot
$case = Join-Path $workspace ".lab\hyperv\attempts\$Name"
if (Test-Path -LiteralPath $case) { throw "Attempt directory already exists: $case" }
$null = New-Item -ItemType Directory -Path $case
if (-not $Binary) { $Binary = Join-Path $workspace 'target\release\ntfs2refs.exe' }
if (-not $ManifestBinary) { $ManifestBinary = Join-Path $workspace 'target\release\lab-volume-manifest.exe' }
$progressLog = Join-Path $case 'progress.log'
$verdict = [ordered]@{ name = $Name; fixture = [bool]$Fixture; diagnose = [bool]$Diagnose; started_utc = [DateTime]::UtcNow.ToString('o')
    phases = [ordered]@{}; converter = $null; boot = $null; outcome = 'incomplete'
    evidence = [System.Collections.Generic.List[object]]::new(); evidence_complete = $false }
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
function Add-Evidence([string]$Label, [string]$Path, [string]$MissingReason, [switch]$Required) {
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        $script:verdict.evidence.Add([ordered]@{ name = $Label; present = $true; required = [bool]$Required
                bytes = (Get-Item -LiteralPath $Path).Length; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() })
    } else {
        $script:verdict.evidence.Add([ordered]@{ name = $Label; present = $false; required = [bool]$Required
                reason = if ($MissingReason) { $MissingReason } else { 'not found' } })
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
# Starts ntfs2refs.exe in the guest as SYSTEM, through the worker beside it.
function Start-Converter([string]$Root, [string]$TaskName, [string[]]$Arguments) {
    Invoke-Command -Session $script:session -ArgumentList $Root, $TaskName, ($Arguments -join "`t") -ScriptBlock {
        param($root, $task, $joined)
        $arguments = [string[]]$joined.Split("`t")
        [IO.File]::WriteAllText("$root\run.json", (@{ arguments = @($arguments) } | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
        $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File $root\worker.ps1 -Root $root"
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
        $null = Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings
        Start-ScheduledTask -TaskName $task
    }
    Say "converter started: ntfs2refs.exe $($Arguments -join ' ')"
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
                    task = (Get-ScheduledTask -TaskName $task).State.ToString()
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
        if ($state.terminal -or $state.worker_error -or ($state.task -ne 'Running' -and $polls -gt 3)) { break }
        if ((Get-Date) -gt $deadline) { Say 'converter timed out; leaving it running for inspection'; break }
    }
    [pscustomobject]@{ state = $state; vm_stopped = $vmStopped; held = $held }
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
    $wanted = if ($Fixture) { $FixtureCheckpoint } else { $Checkpoint }
    $snapshots = @(Get-VMSnapshot -VM $vm | Where-Object Name -Like $wanted)
    if ($snapshots.Count -ne 1) { throw "Expected exactly one checkpoint matching '$wanted', found $($snapshots.Count)" }
    if ($CheckpointAfterConvert -and (Get-VMSnapshot -VM $vm | Where-Object Name -EQ $CheckpointAfterConvert)) {
        throw "Checkpoint '$CheckpointAfterConvert' already exists; pick another name or remove it"
    }
    if ($CheckpointBeforeBoot -and (Get-VMSnapshot -VM $vm | Where-Object Name -EQ $CheckpointBeforeBoot)) {
        throw "Checkpoint '$CheckpointBeforeBoot' already exists; pick another name or remove it"
    }
    $hostFreeDisk = Get-HostFreeBytes
    # A full-volume attempt grows its scratch disk to about 30 GB and the VM's
    # own disks by about as much before the scratch disk is removed; one that
    # started with 70 GB free was down to 12 GB at its end.
    if (-not $Fixture -and -not $Recover -and -not $NoConvert -and $MinHostFreeGB -lt 65) { $MinHostFreeGB = 65 }
    if ($hostFreeDisk -lt [long]$MinHostFreeGB * 1GB) {
        throw ("Host volume has {0:N1} GB free; an attempt needs {1} GB. Free space first (old attempts' scratch.vhdx files)." -f ($hostFreeDisk / 1GB), $MinHostFreeGB)
    }
    Say "attempt ${Name}: restoring checkpoint '$($snapshots[0].Name)'"
    if ($vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Force }
    Restore-VMSnapshot -VMSnapshot $snapshots[0] -Confirm:$false
    $vm = Get-LabVm
    if ($vm.State -eq 'Saved') { Remove-VMSavedState -VM $vm; $vm = Get-LabVm }
    if ($vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Force; $vm = Get-LabVm }
    $hostFree = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1KB
    $memory = [Math]::Min([long]$MemoryGB * 1GB, [long]($hostFree * 0.8 / 1GB) * 1GB)
    if ($memory -lt 8GB) { throw "Host has too little free memory for the VM: $([Math]::Round($hostFree/1GB,1)) GB free" }
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
        Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -ControllerNumber 0 -Path $scratchPath
    }
    $verdict.vm = @{ memory_bytes = $memory; processors = (Get-VMProcessor -VM $vm).Count; checkpoint = $snapshots[0].Name
        host_free_disk_bytes = (Get-Volume -FilePath $case).SizeRemaining }
    Phase 'restore'

    # ---- control OS up, scratch disk ready --------------------------------------
    Start-VM -VM $vm
    $session = Wait-Guest 15 $null
    if (-not $session) { throw 'Control OS did not accept a PowerShell Direct session within 15 minutes' }
    $guest = if ($Recover) {
        # The saved state already holds the original run's scratch volume and
        # its records; the source disk is offline and holds the ReFS image.
        Invoke-Command -Session $session -ArgumentList $SourceDisk, $SourcePartition -ScriptBlock {
            param($sourceDisk, $sourcePartition)
            $ErrorActionPreference = 'Stop'
            $scratch = @(Get-Volume | Where-Object { $_.FileSystemLabel -eq 'N2R_SCRATCH' -and $_.DriveLetter })
            if ($scratch.Count -ne 1) { throw "Expected one lettered N2R_SCRATCH volume, found $($scratch.Count)" }
            $printed = Get-ChildItem 'C:\n2r' -Directory | Sort-Object LastWriteTime -Descending | ForEach-Object {
                $log = Join-Path $_.FullName 'stdout.log'
                if (Test-Path -LiteralPath $log) { Select-String -LiteralPath $log -Pattern '^To recover: ntfs2refs --recover "(.+)" --recovery-sha256 ([0-9a-f]{64})' | Select-Object -Last 1 }
            } | Select-Object -First 1
            if (-not $printed) { throw 'No "To recover:" line found in any earlier run log under C:\n2r' }
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
                recover_directory = $printed.Matches[0].Groups[1].Value; recover_sha256 = $printed.Matches[0].Groups[2].Value
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
    if ($NoConvert) { $verdict.outcome = 'prepared-only'; Remove-PSSession $session; return }

    # ---- run the converter ------------------------------------------------------
    if (-not (Test-Path -LiteralPath $Binary)) { throw "Converter binary not found: $Binary (build with cargo build --release)" }
    $guestRoot = "C:\n2r\$Name"; $scratchDirectory = "$($guest.scratch_letter):\runs"
    $arguments = if ($Recover) { @('--recover', $guest.recover_directory, '--recovery-sha256', $guest.recover_sha256) }
        else { @('--drive', $guest.source_letter, '--windows-boot-volume', '--scratch-directory', $scratchDirectory, '--target-format', 'dev-drive') }
    if ($Diagnose) { $arguments += '--diagnose' }
    if ($InterruptAt) {
        if ($Recover -or $Diagnose) { throw '-InterruptAt applies to a conversion, not to -Recover or -Diagnose' }
        $arguments += @('--lab-hold-at', $InterruptAt, '--acknowledge-lab-hold-never-completes')
    }
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
    $manifestExe = "$guestRoot\lab-volume-manifest.exe"
    if (-not $NoManifest -and -not $Diagnose) {
        if (-not (Test-Path -LiteralPath $ManifestBinary)) { throw "Listing tool not found: $ManifestBinary (cargo build --release --bin lab-volume-manifest)" }
        Copy-Item -LiteralPath $ManifestBinary -Destination $manifestExe -ToSession $session
        if (-not $Recover) {
            $listed = Invoke-Command -Session $session -ArgumentList $manifestExe, "$($guest.source_letter):\", "$guestRoot\manifest-before.jsonl" -ScriptBlock {
                param($exe, $root, $output) $text = & $exe capture --root $root --output $output 2>&1; [pscustomobject]@{ exit = $LASTEXITCODE; text = ($text -join ' ') } }
            if ($listed.exit -ne 0) { throw "Listing the source before conversion failed: $($listed.text)" }
            # Kept on the host from now on, whatever becomes of the run and the guest.
            Copy-Evidence $session "$guestRoot\manifest-before.jsonl" 'manifest-before.jsonl' -Required
            Say "source listed before conversion: $($listed.text)"; Phase 'list-before'
        }
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
        $verdict.converter = [ordered]@{ arguments = $arguments; exit = $null; stopped = $vmStopped }
        $verdict.outcome = 'vm-stopped'; Phase 'convert'; return
    }
    # ---- collect evidence -------------------------------------------------------
    foreach ($leaf in 'stdout.log', 'stderr.log', 'native-process.json', 'native-terminal.json', 'run.json') {
        Copy-Evidence $session "$guestRoot\$leaf" $leaf -Required
    }
    # Written only when the worker fails, and only when stacks were asked for.
    Copy-Evidence $session "$guestRoot\worker-error.txt" 'worker-error.txt'
    Copy-Evidence $session "$guestRoot\stacks.txt" 'stacks.txt' -Required:$SampleStacks
    try {
        $listing_ = Invoke-Command -Session $session -ArgumentList $scratchDirectory -ScriptBlock {
            param($scratch)
            $failures = @()
            $found = @(Get-ChildItem -LiteralPath $scratch -Recurse -File -ErrorAction SilentlyContinue -ErrorVariable failures |
                    Where-Object { $_.Extension -in '.json', '.txt', '.log' } | Select-Object FullName, Length)
            [pscustomobject]@{ files = $found; errors = @($failures | ForEach-Object { "$_" }) }
        }
        foreach ($failure in @($listing_.errors)) { Add-Evidence 'run records' $null "listing the run directory: $failure" }
        $collected = 0
        foreach ($record in @($listing_.files)) {
            $relative = $record.FullName.Substring($scratchDirectory.Length).TrimStart('\'); $label = Join-Path 'run' $relative
            # Small records are copied; the rest are named with the reason, not dropped.
            if ($record.Length -gt 4MB) { Add-Evidence $label $null "not collected: $($record.Length) bytes is over the 4 MB record limit" }
            elseif ($collected -ge 400) { Add-Evidence $label $null 'not collected: over the 400-record limit' }
            else { Copy-Evidence $session $record.FullName $label; $collected++ }
        }
    } catch { Add-Evidence 'run records' $null "collection failed: $($_.Exception.Message)" -Required }
    $exit = if ($state -and $state.terminal) { [int]$state.terminal.native_exit } else { $null }
    $verdict.converter = [ordered]@{ arguments = $arguments; exit = $exit
        wall_seconds = if ($state -and $state.terminal) { $state.terminal.wall_seconds } else { $null }
        peak_working_set_bytes = if ($state -and $state.terminal) { $state.terminal.peak_working_set_bytes } else { $null }
        stderr_tail = if ($state) { @($state.stderr) } else { @() }; worker_error = if ($state) { $state.worker_error } else { $null } }
    Phase 'convert'
    if ($InterruptAt) {
        # The interruption under test: the converter stopped at the named
        # point and its process was ended there. Recovery starts from what
        # that left on the disks, with nothing but the command it printed.
        $verdict.interrupt = [ordered]@{ point = $InterruptAt; kind = 'process-termination'; held = $run.held; converter_exit = $exit
            evidence_kinds = [ordered]@{ process_termination = [bool]$run.held; vm_interruption = $false
                storage_power_loss = 'not covered: the lab cannot cut power to the storage' } }
        if (-not $run.held) {
            $verdict.outcome = 'interrupt-not-reached'; Say "the converter ended (exit $exit) without reaching the hold at $InterruptAt"
            Remove-PSSession $session; return
        }
        if ($RecoverMode -eq 'none') { $verdict.outcome = 'interrupted-not-recovered'; Remove-PSSession $session; return }
        $printed = Select-String -LiteralPath (Join-Path $case 'stdout.log') -Pattern '^To recover: ntfs2refs --recover "(.+)" --recovery-sha256 ([0-9a-f]{64})' | Select-Object -Last 1
        if (-not $printed) { $verdict.outcome = 'interrupted-without-recovery-command'; Say 'the interrupted run printed no "To recover:" line'; Remove-PSSession $session; return }
        $recoverArguments = @('--recover', $printed.Matches[0].Groups[1].Value, '--recovery-sha256', $printed.Matches[0].Groups[2].Value)
        if ($RecoverMode -eq 'rollback') { $recoverArguments += '--rollback' }
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
        if ($RecoverMode -eq 'rollback') {
            # What Windows says of the source now: the same partition, NTFS
            # again, online and writable. Its contents are compared once the
            # listing tool can compare two NTFS listings exactly.
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
            $verdict.outcome = if ($restored) { 'ROLLED-BACK-NOT-COMPARED' } else { 'rolled-back-but-unhealthy' }
            Remove-PSSession $session; return
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
                Say "saved the applied-but-not-finalized state as checkpoint '$CheckpointAfterConvert'; retry finalization with -Recover -Checkpoint '$CheckpointAfterConvert'"
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
        $verdict.outcome = if (-not $sourceIntact) { 'diagnose-changed-source' }
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
            $compared = Invoke-Command -Session $session -ArgumentList $manifestExe, "$($mounted.letter):\", $guestRoot -ScriptBlock {
                param($exe, $root, $directory)
                # A -Recover attempt has no listing of its own; use the one the original run took.
                $before = @("$directory\manifest-before.jsonl") + @(Get-ChildItem 'C:\n2r' -Directory | Sort-Object LastWriteTime -Descending |
                        ForEach-Object { Join-Path $_.FullName 'manifest-before.jsonl' }) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
                if (-not $before) { return [pscustomobject]@{ stage = 'no-before-listing'; exit = -1; differences = $null; listed = 'no listing from before the conversion exists'; summary = ''; before = $null } }
                $listed = & $exe capture --root $root --output "$directory\manifest-after.jsonl" 2>&1
                if ($LASTEXITCODE -ne 0) { return [pscustomobject]@{ stage = 'capture-after'; exit = $LASTEXITCODE; differences = $null; listed = ($listed -join ' '); summary = ''; before = $before } }
                $report = "$directory\manifest-report.json"
                if (Test-Path -LiteralPath $report) { Remove-Item -LiteralPath $report -Force }
                $summary = & $exe compare --before $before --after "$directory\manifest-after.jsonl" --report $report 2>&1
                $exit = $LASTEXITCODE
                # The count comes from the report the comparison wrote, not from its exit code alone.
                $differences = $null
                if (Test-Path -LiteralPath $report) { try { $differences = [int](Get-Content -Raw -LiteralPath $report | ConvertFrom-Json).difference_count } catch { $differences = $null } }
                [pscustomobject]@{ stage = 'compare'; exit = $exit; differences = $differences; listed = ($listed -join ' '); summary = ($summary -join ' '); before = $before }
            }
            # A -Recover attempt took no listing of its own; an ordinary one copied its listing when it was taken.
            if ($Recover -and $compared.before) { Copy-Evidence $session $compared.before 'manifest-before.jsonl' -Required }
            Copy-Evidence $session "$guestRoot\manifest-after.jsonl" 'manifest-after.jsonl' -Required
            Copy-Evidence $session "$guestRoot\manifest-report.json" 'manifest-report.json' -Required:($compared.stage -eq 'compare' -and $compared.exit -in 0, 2)
            $verdict.before_listing_used = $compared.before
            # Exit 0 with no differences counted is identical; exit 2 with a report
            # that counts differences is a real difference. Anything else (a crash,
            # an unreadable listing, a usage error) is the listing tool failing,
            # which says nothing about the volume. No listing to compare with (a
            # -Recover of a checkpoint whose own run took none) is neither.
            $listing = if ($compared.stage -eq 'no-before-listing') { 'not-compared' }
                elseif ($compared.stage -eq 'compare' -and $compared.exit -eq 0 -and $compared.differences -eq 0) { 'identical' }
                elseif ($compared.stage -eq 'compare' -and $compared.exit -eq 2 -and $compared.differences -gt 0) { 'differs' }
                else { 'tool-failed' }
            $verdict.manifest = [ordered]@{ result = $listing; stage = $compared.stage; exit = $compared.exit; differences = $compared.differences
                listed = $compared.listed; summary = $compared.summary }
            Say "listing after conversion: $($compared.listed)"
            Say "before/after comparison: $listing ($($compared.stage) exit $($compared.exit)): $($compared.summary)"
            Phase 'compare'
            # A listing that differs is a failed conversion, but whether the result
            # boots is separate evidence worth having from the same run.
            if ($listing -ne 'identical' -and ($NoBoot -or $Diagnose)) {
                $verdict.outcome = switch ($listing) {
                    'not-compared' { 'converted-not-compared' } 'differs' { 'converted-but-listing-differs' } default { 'converted-listing-tool-failed' } }
                Remove-PSSession $session; return
            }
        }
    }
    if ($NoBoot) { $verdict.outcome = if ($InterruptAt) { 'RESUMED-NOT-BOOTED' } else { 'converted-not-booted' }; Remove-PSSession $session; return }

    # ---- boot disk0 alone ------------------------------------------------------
    $controlBoot = Invoke-Command -Session $session -ScriptBlock { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') }
    Remove-PSSession $session
    try { Stop-VM -VM (Get-LabVm) -Force } catch { Stop-VM -VM (Get-LabVm) -TurnOff -Force }
    if ($CheckpointBeforeBoot) {
        Checkpoint-VM -VM (Get-LabVm) -SnapshotName $CheckpointBeforeBoot
        $KeepScratch = [switch]$true; $verdict.converted_checkpoint = $CheckpointBeforeBoot
        Say "saved the converted, not yet booted state as checkpoint '$CheckpointBeforeBoot'"
    }
    $vm = Get-LabVm
    Get-VMHardDiskDrive -VM $vm | Where-Object { -not ($_.ControllerNumber -eq 0 -and $_.ControllerLocation -eq 0) } | Remove-VMHardDiskDrive
    Get-VMDvdDrive -VM $vm | Remove-VMDvdDrive
    $disk0 = Get-VMHardDiskDrive -VM $vm
    if (@($disk0).Count -ne 1) { throw 'Expected exactly disk0 to remain attached' }
    Set-VMFirmware -VM $vm -FirstBootDevice $disk0
    Say 'booting the original disk0 alone, Secure Boot on'
    Start-VM -VM $vm
    $shots = 0
    $session = Wait-Guest $BootTimeoutMinutes {
        param($minute)
        if ($minute -le 5 -or $minute % 5 -eq 0) { $script:shots++; $null = Save-VmScreen (Join-Path $case ('boot-{0:D2}min.png' -f $minute)) }
        $heartbeat = (Get-VMIntegrationService -VM (Get-LabVm) -Name 'Heartbeat').PrimaryStatusDescription
        Say "waiting for Windows on disk0: minute $minute, VM $((Get-LabVm).State), heartbeat $heartbeat"
    }
    $null = Save-VmScreen (Join-Path $case 'boot-final.png')
    if (-not $session) {
        $verdict.boot = @{ reached_windows = $false; vm_state = (Get-LabVm).State.ToString()
            heartbeat = (Get-VMIntegrationService -VM (Get-LabVm) -Name 'Heartbeat').PrimaryStatusDescription }
        $verdict.outcome = 'boot-failed'; Say "disk0 did not reach a usable Windows within $BootTimeoutMinutes minutes; see boot-*.png"; Phase 'boot'; return
    }
    $observed = Invoke-Command -Session $session -ArgumentList $controlBoot -ScriptBlock {
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
    Remove-PSSession $session
    $observed = $observed | Select-Object * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
    $ok = $observed.filesystem -eq 'ReFS' -and $observed.refs_version -eq '3.14' -and $observed.cluster_bytes -eq 4096 -and
        $observed.partition -eq $guest.source_partition -and $observed.partition_guid -eq $guest.source_guid -and @($observed.disks).Count -eq 1 -and
        $observed.secure_boot -eq $true -and $observed.newer_than_control_boot -and $observed.health -eq 'Healthy' -and
        -not (@($observed.signatures) | Where-Object status -NE 'Valid')
    $desktop = Enter-Desktop
    $null = Save-VmScreen (Join-Path $case 'boot-desktop.png')
    $verdict.boot = @{ reached_windows = $true; observed = $observed; desktop = $desktop }
    # Only an identical listing (or one the operator switched off) can end as BOOTED-ON-REFS.
    $verdict.outcome = if (-not $ok) { 'booted-but-checks-failed' } elseif (-not $desktop.shell) { 'booted-without-desktop' }
        elseif ($listing -eq 'differs') { 'booted-but-listing-differs' } elseif ($listing -eq 'not-compared') { 'booted-not-compared' }
        elseif ($listing -eq 'tool-failed') { 'booted-listing-tool-failed' } elseif ($InterruptAt) { 'RESUMED-BOOTED-ON-REFS' } else { 'BOOTED-ON-REFS' }
    Say "disk0 booted: $($observed.filesystem) $($observed.refs_version), cluster $($observed.cluster_bytes), partition $($observed.partition), health $($observed.health); desktop $(if ($desktop.shell) { "reached as $($desktop.user) in $($desktop.seconds) s" } else { "not reached: $($desktop.error)" }) => $($verdict.outcome)"
    Phase 'boot'
} catch {
    $verdict.outcome = 'harness-error'; $verdict.error = ($_ | Out-String); Say "HARNESS ERROR: $($_.Exception.Message)"; throw
} finally {
    # A result is only as good as the records that support it: a success whose
    # required evidence was not retained is reported as incomplete, and its
    # scratch disk is kept so the records can still be recovered.
    $missing = @($verdict.evidence | Where-Object { $_.required -and -not $_.present })
    if ($missing.Count -and $verdict.outcome -in 'converted-not-booted', 'BOOTED-ON-REFS', 'diagnose-clean', 'diagnose-found-failures',
        'RESUMED-NOT-BOOTED', 'RESUMED-BOOTED-ON-REFS', 'ROLLED-BACK-NOT-COMPARED') {
        $verdict.result = $verdict.outcome; $verdict.outcome = 'incomplete-evidence'; $KeepScratch = [switch]$true
        Say "required evidence missing: $(($missing | ForEach-Object { $_.name }) -join ', '); scratch disk kept"
    }
    if (-not $KeepScratch -and -not $NoConvert) { Remove-Scratch }
    Save-Verdict; Say "outcome: $($verdict.outcome). Records: $case"
}
