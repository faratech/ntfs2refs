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
  lab\Invoke-BootConversionAttempt.ps1 -Diagnose           # full Windows, report every failure, write nothing
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
    # Restore -Checkpoint (one saved by -CheckpointAfterConvert) and run
    # `ntfs2refs --recover` with the command the original run printed.
    [switch]$Recover,
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
    phases = [ordered]@{}; converter = $null; boot = $null; outcome = 'incomplete' }
$phaseWatch = [Diagnostics.Stopwatch]::StartNew()
$listingDiffers = $false

function Say([string]$Text) {
    $line = '{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $Text
    Add-Content -LiteralPath $progressLog -Value $line -Encoding UTF8; Write-Host $line
}
function Phase([string]$PhaseName) {
    $script:verdict.phases[$PhaseName] = [Math]::Round($script:phaseWatch.Elapsed.TotalSeconds, 1)
    $script:phaseWatch.Restart(); Say "done: $PhaseName"
}
function Save-Verdict {
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

try {
    # ---- restore the baseline ------------------------------------------------
    $vm = Get-LabVm
    $wanted = if ($Fixture) { $FixtureCheckpoint } else { $Checkpoint }
    $snapshots = @(Get-VMSnapshot -VM $vm | Where-Object Name -Like $wanted)
    if ($snapshots.Count -ne 1) { throw "Expected exactly one checkpoint matching '$wanted', found $($snapshots.Count)" }
    if ($CheckpointAfterConvert -and (Get-VMSnapshot -VM $vm | Where-Object Name -EQ $CheckpointAfterConvert)) {
        throw "Checkpoint '$CheckpointAfterConvert' already exists; pick another name or remove it"
    }
    $hostFreeDisk = Get-HostFreeBytes
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
    Invoke-Command -Session $session -ArgumentList $guestRoot, $taskName, ($arguments -join "`t") -ScriptBlock {
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
    Say "converter started: ntfs2refs.exe $($arguments -join ' ')"
    $deadline = (Get-Date).AddMinutes($ConvertTimeoutMinutes); $lastLine = ''; $state = $null; $polls = 0; $failedPolls = 0; $vmStopped = $null
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
            if ($session.State -ne 'Opened') { Remove-PSSession $session -ErrorAction SilentlyContinue; $session = Wait-Guest 5 $null; if (-not $session) { throw 'guest session lost' } }
            $state = Invoke-Command -Session $session -ArgumentList $guestRoot, $taskName, $guest.scratch_letter -ErrorAction Stop -ScriptBlock {
                param($root, $task, $letter)
                $tail = { param($path) if (Test-Path -LiteralPath $path) { @(Get-Content -LiteralPath $path -Tail 3 -Encoding UTF8) } else { @() } }
                [pscustomobject]@{
                    task = (Get-ScheduledTask -TaskName $task).State.ToString()
                    terminal = if (Test-Path "$root\native-terminal.json") { Get-Content "$root\native-terminal.json" -Raw | ConvertFrom-Json } else { $null }
                    worker_error = if (Test-Path "$root\worker-error.txt") { Get-Content "$root\worker-error.txt" -Raw } else { $null }
                    stdout = & $tail "$root\stdout.log"; stderr = & $tail "$root\stderr.log"
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
    if ($vmStopped) {
        $verdict.converter = [ordered]@{ arguments = $arguments; exit = $null; stopped = $vmStopped }
        $verdict.outcome = 'vm-stopped'; Phase 'convert'; return
    }
    # ---- collect evidence -------------------------------------------------------
    foreach ($leaf in 'stdout.log', 'stderr.log', 'native-process.json', 'native-terminal.json', 'worker-error.txt', 'run.json', 'stacks.txt') {
        try { Copy-Item -LiteralPath "$guestRoot\$leaf" -Destination (Join-Path $case $leaf) -FromSession $session -ErrorAction Stop } catch { }
    }
    try {
        $records = Invoke-Command -Session $session -ArgumentList $scratchDirectory -ScriptBlock {
            param($scratch) @(Get-ChildItem -LiteralPath $scratch -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -in '.json', '.txt', '.log' -and $_.Length -le 4MB } | Select-Object -First 400 -ExpandProperty FullName) }
        foreach ($record in $records) {
            $relative = $record.Substring($scratchDirectory.Length).TrimStart('\'); $target = Join-Path (Join-Path $case 'run') $relative
            $null = New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force
            try { Copy-Item -LiteralPath $record -Destination $target -FromSession $session -ErrorAction Stop } catch { }
        }
    } catch { Say "run record collection failed: $($_.Exception.Message)" }
    $exit = if ($state -and $state.terminal) { [int]$state.terminal.native_exit } else { $null }
    $verdict.converter = [ordered]@{ arguments = $arguments; exit = $exit
        wall_seconds = if ($state -and $state.terminal) { $state.terminal.wall_seconds } else { $null }
        peak_working_set_bytes = if ($state -and $state.terminal) { $state.terminal.peak_working_set_bytes } else { $null }
        stderr_tail = if ($state) { @($state.stderr) } else { @() }; worker_error = if ($state) { $state.worker_error } else { $null } }
    Phase 'convert'
    if ($null -eq $exit -or $exit -ne 0) {
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
    Say 'converter exit 0'
    if (-not $Diagnose) {
        # Independent of the converter: does Windows itself mount the result as ReFS?
        $mounted = Invoke-Command -Session $session -ArgumentList $guest.source_disk, $guest.source_partition -ScriptBlock {
            param($disk, $number)
            $partition = Get-Partition -DiskNumber $disk -PartitionNumber $number; $volume = Get-Volume -Partition $partition
            $letter = [string]$partition.DriveLetter
            $refs = if ($letter) { @(& "$env:SystemRoot\System32\fsutil.exe" fsinfo refsinfo "${letter}:" 2>&1) -join "`n" } else { '' }
            # Repair-Volume -Scan is not offered for a Dev Drive. What the ReFS
            # driver itself logged while mounting and reading the volume is.
            $refsEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2, 3; StartTime = (Get-Date).AddHours(-2) } -ErrorAction SilentlyContinue |
                    Where-Object ProviderName -Match 'ReFS' | Select-Object -First 20 | ForEach-Object { '{0:HH:mm:ss} {1} {2}: {3}' -f $_.TimeCreated, $_.Id, $_.LevelDisplayName, (($_.Message -split "`n")[0]) })
            $scan = if ($refsEvents.Count) { "$($refsEvents.Count) ReFS warning/error events: $($refsEvents -join ' || ')" } else { 'no ReFS warnings or errors logged' }
            $sample = if ($letter) { @(Get-ChildItem -LiteralPath "${letter}:\" -Force -ErrorAction SilentlyContinue | Select-Object -First 40 -ExpandProperty Name) } else { @() }
            [pscustomobject]@{ letter = $letter; filesystem = [string]$volume.FileSystem; health = [string]$volume.HealthStatus
                cluster_bytes = $volume.AllocationUnitSize; used_bytes = $volume.Size - $volume.SizeRemaining
                refs_version = ($refs -replace '(?s).*REFS Volume Version\s*:\s*([\d.]+).*', '$1'); scan = $scan; root_entries = $sample }
        }
        $verdict.mounted = $mounted | Select-Object * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
        Say "source partition now mounts as $($mounted.filesystem) $($mounted.refs_version), health $($mounted.health), $([math]::Round($mounted.used_bytes / 1GB, 2)) GB used; $($mounted.scan)"
        if ($mounted.filesystem -ne 'ReFS') { $verdict.outcome = 'converter-ok-but-not-refs'; Remove-PSSession $session; return }
        if (-not $NoManifest) {
            if (-not $mounted.letter) { $verdict.outcome = 'converted-but-no-drive-letter'; Remove-PSSession $session; return }
            $compared = Invoke-Command -Session $session -ArgumentList $manifestExe, "$($mounted.letter):\", $guestRoot -ScriptBlock {
                param($exe, $root, $directory)
                # A -Recover attempt has no listing of its own; use the one the original run took.
                $before = @("$directory\manifest-before.jsonl") + @(Get-ChildItem 'C:\n2r' -Directory | Sort-Object LastWriteTime -Descending |
                        ForEach-Object { Join-Path $_.FullName 'manifest-before.jsonl' }) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
                if (-not $before) { return [pscustomobject]@{ exit = -1; listed = 'no listing from before the conversion exists'; summary = ''; before = $null } }
                $listed = & $exe capture --root $root --output "$directory\manifest-after.jsonl" 2>&1
                if ($LASTEXITCODE -ne 0) { return [pscustomobject]@{ exit = $LASTEXITCODE; listed = ($listed -join ' '); summary = ''; before = $before } }
                $summary = & $exe compare --before $before --after "$directory\manifest-after.jsonl" --report "$directory\manifest-report.json" 2>&1
                [pscustomobject]@{ exit = $LASTEXITCODE; listed = ($listed -join ' '); summary = ($summary -join ' '); before = $before }
            }
            foreach ($pair in @(@($compared.before, 'manifest-before.jsonl'), @("$guestRoot\manifest-after.jsonl", 'manifest-after.jsonl'), @("$guestRoot\manifest-report.json", 'manifest-report.json'))) {
                if ($pair[0]) { try { Copy-Item -LiteralPath $pair[0] -Destination (Join-Path $case $pair[1]) -FromSession $session -ErrorAction Stop } catch { } }
            }
            $verdict.manifest = [ordered]@{ exit = $compared.exit; listed = $compared.listed; summary = $compared.summary }
            Say "listing after conversion: $($compared.listed)"
            Say "before/after comparison (exit $($compared.exit)): $($compared.summary)"
            Phase 'compare'
            # A listing that differs is a failed conversion, but whether the result
            # boots is separate evidence worth having from the same run.
            $listingDiffers = $compared.exit -ne 0
            if ($listingDiffers -and ($NoBoot -or $Diagnose)) { $verdict.outcome = 'converted-but-listing-differs'; Remove-PSSession $session; return }
        }
    }
    if ($Diagnose -or $NoBoot) { $verdict.outcome = if ($Diagnose) { 'diagnose-clean' } else { 'converted-not-booted' }; Remove-PSSession $session; return }

    # ---- boot disk0 alone ------------------------------------------------------
    $controlBoot = Invoke-Command -Session $session -ScriptBlock { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') }
    Remove-PSSession $session
    try { Stop-VM -VM (Get-LabVm) -Force } catch { Stop-VM -VM (Get-LabVm) -TurnOff -Force }
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
    $verdict.boot = @{ reached_windows = $true; observed = $observed }
    $verdict.outcome = if (-not $ok) { 'booted-but-checks-failed' } elseif ($listingDiffers) { 'booted-but-listing-differs' } else { 'BOOTED-ON-REFS' }
    Say "disk0 booted: $($observed.filesystem) $($observed.refs_version), cluster $($observed.cluster_bytes), partition $($observed.partition), health $($observed.health) => $($verdict.outcome)"
    Phase 'boot'
} catch {
    $verdict.outcome = 'harness-error'; $verdict.error = ($_ | Out-String); Say "HARNESS ERROR: $($_.Exception.Message)"; throw
} finally {
    if (-not $KeepScratch -and -not $NoConvert) { Remove-Scratch }
    Save-Verdict; Say "outcome: $($verdict.outcome). Records: $case"
}
