<#
.SYNOPSIS
Converts a data partition on the disk of the running Windows of a lab VM
through the restart route, and compares the volume's listing before and after.

.DESCRIPTION
A partition that shares its disk with the running Windows cannot be converted
while Windows runs: a conversion takes the disk offline. The restart route
prepares everything in Windows, restarts the machine into a minimal Windows
(WinPE) built from installation media, converts there and returns to Windows.

This script makes such a partition in the control OS of a lab VM (it shrinks
C: and makes P: beside it), fills it, lists it, starts the converter with
`--drive P --restart-media <the DVD>`, waits for the machine to go away and
come back, lists the volume again and compares.

The control OS must already be up from its checkpoint, with the scratch volume
S: and Windows installation media in its DVD drive:
`Invoke-BootConversionAttempt.ps1 -Name <n> -NoConvert -KeepScratch [-VmId ...]`.
The attempt changes the control OS's disk; the next boot attempt restores the
checkpoint.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,39}$')][string]$Name,
    [Parameter(Mandatory)][guid]$VmId,
    [string]$Binary,
    # The executable that runs in WinPE. It is copied beside the converter
    # as ntfs2refs-recovery.exe, the name the converter looks for.
    [string]$RecoveryBinary,
    [string]$ManifestBinary,
    [string]$CredentialPath,
    # Size of the partition made beside C:. ReFS covers whole 64 MiB units,
    # and this route does not shrink a partition to one.
    [ValidateScript({ $_ % 64 -eq 0 -and $_ -ge 2048 })][int]$PartitionMB = 6144,
    [int]$Files = 400,
    # Working storage on a disk of its own, made by the host for the attempt
    # and attached to the VM: this many GB, GPT, formatted with the file
    # system named, at J:. 0 uses the VM's scratch volume S:.
    # A laboratory failure point of the route (--lab-fail-at): the run is
    # made to stop there, and what has to follow is checked. With
    # restart-after-protect and restart-after-image the run gives the volume
    # back by itself; with restart-after-arm and restart-skip-reboot it is
    # left prepared, is asked what state it is in (--recover) and is then
    # cancelled (--recover --rollback); with winpe-before-apply the machine
    # restarts, cannot start the conversion there and has to come back to
    # Windows by itself. Each ends "cancelled-volume-as-before" when the
    # volume is writable NTFS listing exactly as before and Windows' boot
    # selection is its own again.
    [ValidateSet('', 'restart-after-protect', 'restart-after-image', 'restart-after-arm', 'restart-skip-reboot', 'winpe-before-apply')][string]$LabFailAt = '',
    [switch]$ExpectScratchRefusal,
    # On a disposable Windows fixture, protect C: and prove the
    # data-partition restart route refuses before changing its source or BCD.
    [switch]$ExpectWindowsBitLockerRefusal,
    [int]$WorkingDiskGB = 0,
    [ValidateSet('NTFS', 'ReFS')][string]$WorkingFileSystem = 'NTFS',
    # How long the machine may be away (restart, WinPE, conversion, return).
    [int]$AwayMinutes = 45,
    [string[]]$ConverterArgs = @()
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$workspace = Split-Path -Parent $PSScriptRoot
if (-not $Binary) { $Binary = Join-Path $workspace 'target\release\ntfs2refs.exe' }
if (-not $RecoveryBinary) { $RecoveryBinary = Join-Path (Split-Path $Binary) 'ntfs2refs-recovery.exe' }
if (-not $ManifestBinary) { $ManifestBinary = Join-Path (Split-Path $Binary) 'lab-volume-manifest.exe' }
foreach ($file in $Binary, $RecoveryBinary, $ManifestBinary) { if (-not (Test-Path -LiteralPath $file)) { throw "Not found: $file" } }

$records = Join-Path $workspace ".lab\hyperv\attempts\$Name"
if (Test-Path -LiteralPath $records) { throw "Attempt '$Name' already has records at $records; choose another -Name" }
$null = New-Item -ItemType Directory -Path $records
$progress = Join-Path $records 'progress.log'
function Say([string]$Text) { $line = '{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $Text; Add-Content -LiteralPath $progress -Value $line -Encoding UTF8; Write-Host $line }
$verdict = [ordered]@{
    name = $Name; outcome = 'harness-error'; vm_id = $VmId; partition_mb = $PartitionMB; files = $Files; lab_fail_at = $LabFailAt
    converter_sha256 = (Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash.ToLowerInvariant()
    recovery_sha256 = (Get-FileHash -LiteralPath $RecoveryBinary -Algorithm SHA256).Hash.ToLowerInvariant()
    listing_tool_sha256 = (Get-FileHash -LiteralPath $ManifestBinary -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Save-Verdict { [IO.File]::WriteAllText((Join-Path $records 'verdict.json'), ($verdict | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false)) }

$vm = Get-VM -Id $VmId
if ($vm.State -ne 'Running') { throw "VM $($vm.Name) is $($vm.State). Start its control OS first: Invoke-BootConversionAttempt.ps1 -Name <n> -NoConvert -KeepScratch -VmId $VmId" }
if (-not $CredentialPath) { $CredentialPath = Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml' }
$saved = Import-Clixml -LiteralPath $CredentialPath
$credential = [pscredential]::new('LabAdmin', $saved.Password)
$guestRoot = "C:\n2r\restart\$Name"
$session = $null
function Connect([int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ($true) {
        try { return New-PSSession -VMId $VmId -Credential $credential -ErrorAction Stop }
        catch { if ((Get-Date) -gt $deadline) { throw }; Start-Sleep -Seconds 5 }
    }
}
function Screenshot([string]$Leaf) {
    # What the console shows while no session can be had (WinPE).
    try {
        $service = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_VirtualSystemManagementService
        $system = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_ComputerSystem -Filter "Name='$($VmId.ToString().ToUpper())'"
        $setting = Get-CimAssociatedInstance -InputObject $system -ResultClassName Msvm_VirtualSystemSettingData | Where-Object VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized'
        $image = Invoke-CimMethod -InputObject $service -MethodName GetVirtualSystemThumbnailImage -Arguments @{ TargetSystem = $setting; WidthPixels = [uint16]1024; HeightPixels = [uint16]768 }
        if ($image.ReturnValue -eq 0) { [IO.File]::WriteAllBytes((Join-Path $records "$Leaf.rgb565"), [byte[]]$image.ImageData) }
    } catch { }
}

$hostDisk = $null
$work = if ($WorkingDiskGB -gt 0) { 'J:\restart' } else { 'S:\restart' }
if ($ExpectScratchRefusal -and $LabFailAt) { throw 'Test either the working storage refusal or a restart fault' }
if ($ExpectWindowsBitLockerRefusal -and ($ExpectScratchRefusal -or $LabFailAt)) { throw 'Choose only one expected restart refusal or interruption' }
try {
    $session = Connect 60
    if ($WorkingDiskGB -gt 0) {
        $hostDisk = Join-Path $records 'working.vhdx'
        $null = New-VHD -Path $hostDisk -SizeBytes ([long]$WorkingDiskGB * 1GB) -Dynamic
        Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -Path $hostDisk
        $made = Invoke-Command -Session $session -ArgumentList ([long]$WorkingDiskGB * 1GB), $WorkingFileSystem -ScriptBlock {
            param($bytes, $fileSystem)
            $deadline = (Get-Date).AddSeconds(60)
            do { Start-Sleep -Milliseconds 500; $new = @(Get-Disk | Where-Object { $_.PartitionStyle -eq 'RAW' -and $_.Size -eq $bytes }) } until ($new.Count -eq 1 -or (Get-Date) -gt $deadline)
            if ($new.Count -ne 1) { throw "expected one new blank disk of $bytes bytes in the guest, found $($new.Count)" }
            $number = $new[0].Number
            if ($new[0].IsOffline) { Set-Disk -Number $number -IsOffline $false }
            if ($new[0].IsReadOnly) { Set-Disk -Number $number -IsReadOnly $false }
            Initialize-Disk -Number $number -PartitionStyle GPT
            $partition = New-Partition -DiskNumber $number -UseMaximumSize -DriveLetter J
            $null = Format-Volume -Partition $partition -FileSystem $fileSystem -NewFileSystemLabel 'N2RWORK' -Confirm:$false
            "disk $number, $fileSystem"
        }
        Say "working storage: J: on a disk of its own ($made)"
    }
    Say "attempt ${Name}: a $PartitionMB MiB partition beside C: on $($vm.Name), converted through a restart"
    $made = Invoke-Command -Session $session -ArgumentList $guestRoot, $PartitionMB, $Files, $work -ScriptBlock {
        param($root, $partitionMB, $files, $work)
        $ErrorActionPreference = 'Stop'
        if (-not (Test-Path -LiteralPath (Split-Path -Qualifier $work))) { throw "The control OS has no volume $(Split-Path -Qualifier $work) for working storage." }
        $media = Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -and $_.DriveLetter -and (Test-Path -LiteralPath "$($_.DriveLetter):\sources\boot.wim") } | Select-Object -First 1
        if (-not $media) { throw 'No DVD drive with Windows installation media (sources\boot.wim) in the control OS.' }
        $null = New-Item -ItemType Directory -Path $root, $work -Force
        $c = Get-Partition -DriveLetter C
        if (Get-Partition -DriveLetter P -ErrorAction SilentlyContinue) { throw 'The control OS already has a volume P:.' }
        # C: gives up what Windows says it can: files that cannot be moved
        # (the page file, the end of the file table) bound it. The partition
        # is the size asked for, or the largest multiple of 64 MiB that
        # fits.
        $supported = Get-PartitionSupportedSize -DriveLetter C
        $room = $c.Size - $supported.SizeMin - 128MB
        $bytes = [Math]::Min([long]$partitionMB * 1MB, [long]([Math]::Floor($room / 64MB)) * 64MB)
        if ($bytes -lt 1024MB) { throw "C: can give up $([Math]::Round($room / 1MB)) MiB (it is $([Math]::Round($c.Size / 1GB, 1)) GiB and cannot be smaller than $([Math]::Round($supported.SizeMin / 1GB, 1)) GiB): too little for a partition beside it" }
        try { Resize-Partition -DriveLetter C -Size ($c.Size - $bytes - 64MB) } catch { throw "shrinking C: by $([Math]::Round(($bytes + 64MB) / 1MB)) MiB: $($_.Exception.Message)" }
        try { $partition = New-Partition -DiskNumber $c.DiskNumber -Size $bytes -DriveLetter P } catch { throw "making the partition beside C:: $($_.Exception.Message)" }
        $null = Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel 'RESTART' -Confirm:$false
        # No 8.3 short names: a data volume that has them is refused.
        $null = & fsutil.exe 8dot3name set P: 1
        $random = New-Object Random 11
        foreach ($i in 1..$files) {
            $directory = 'P:\data\{0:d2}\{1:d2}' -f ($i % 7), ($i % 13)
            $null = New-Item -ItemType Directory -Path $directory -Force
            $content = New-Object byte[] ($random.Next(1, 400000)); $random.NextBytes($content)
            [IO.File]::WriteAllBytes("$directory\file-$i.bin", $content)
        }
        Set-Content -LiteralPath 'P:\data\note.txt' -Value 'a partition beside the running Windows' -Encoding UTF8
        Set-Content -LiteralPath 'P:\data\note.txt' -Stream 'second' -Value 'a second stream'
        $null = & fsutil.exe hardlink create 'P:\data\note-link.txt' 'P:\data\note.txt'
        $null = New-Item -ItemType Directory -Path 'P:\empty' -Force
        Write-VolumeCache -DriveLetter P
        $disk = Get-Disk -Number $c.DiskNumber
        [pscustomobject]@{
            media = "$($media.DriveLetter):\"; disk = $c.DiskNumber; style = "$($disk.PartitionStyle)"; partition = $partition.PartitionNumber
            offset = $partition.Offset; size = $partition.Size; c_size_after = (Get-Partition -DriveLetter C).Size
            working_filesystem = (Get-Volume -DriveLetter (Split-Path -Qualifier $work).TrimEnd(':')).FileSystem
            windows_build = [Environment]::OSVersion.Version.ToString(); free_memory_bytes = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1KB
        }
    }
    $verdict.made = $made
    if ($ExpectScratchRefusal -and $made.working_filesystem -ne 'ReFS') { throw 'The restart refusal case needs ReFS working storage' }
    # Windows numbers a disk's partitions anew when it starts, by where they
    # lie: a partition made a moment ago in a gap before another one has a
    # number it will not keep (5 here, 4 after a start), and a run binds its
    # volume by number as well as by GUID. The machine is started once more,
    # as it would have been between someone making a partition and
    # converting it. (The first run of this route to reach WinPE stopped
    # there for the number: "source is not the exact nonrequired basic data
    # partition".)
    Invoke-Command -Session $session -ScriptBlock { Restart-Computer -Force }
    Remove-PSSession $session -ErrorAction SilentlyContinue; $session = $null
    Start-Sleep -Seconds 30
    $session = Connect 600
    $numbered = Invoke-Command -Session $session -ScriptBlock { $p = Get-Partition -DriveLetter P; "partition $($p.PartitionNumber) of disk $($p.DiskNumber)" }
    Say "after a start of Windows, P: is $numbered (it was partition $($made.partition))"
    Say "P: is partition $($made.partition) of disk $($made.disk) ($($made.style)), the disk of the running Windows; media at $($made.media)"

    if ($ExpectWindowsBitLockerRefusal) {
        $verdict.windows_bitlocker_before = Invoke-Command -Session $session -ArgumentList $AwayMinutes -ScriptBlock {
            param($minutes)
            $initial = Get-BitLockerVolume -MountPoint 'C:'
            if ($initial.VolumeStatus -ne 'FullyDecrypted') { throw 'BitLocker refusal test requires the disposable decrypted Windows baseline' }
            # The cloned lab TPM is not a valid OS protector on this fixture.
            # Its branch is discarded after the test and is never restarted encrypted.
            $policy = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
            $null = New-Item -Path $policy -Force
            foreach ($setting in 'UseAdvancedStartup', 'EnableBDEWithNoTPM', 'OSPassphrase') {
                $null = New-ItemProperty -LiteralPath $policy -Name $setting -PropertyType DWord -Value 1 -Force
            }
            $password = ConvertTo-SecureString ([guid]::NewGuid().ToString('N')) -AsPlainText -Force
            $null = Enable-BitLocker -MountPoint 'C:' -PasswordProtector -Password $password -UsedSpaceOnly -SkipHardwareTest -ErrorAction Stop
            $deadline = (Get-Date).AddMinutes($minutes)
            do {
                $state = Get-BitLockerVolume -MountPoint 'C:'
                if ($state.ProtectionStatus -eq 'On' -and $state.VolumeStatus -ne 'FullyDecrypted') { break }
                if ($state.VolumeStatus -eq 'FullyEncrypted') {
                    $null = Resume-BitLocker -MountPoint 'C:' -ErrorAction Stop
                    $state = Get-BitLockerVolume -MountPoint 'C:'
                    break
                }
                Start-Sleep -Seconds 5
            } until ((Get-Date) -ge $deadline)
            if ($state.ProtectionStatus -ne 'On' -or $state.VolumeStatus -eq 'FullyDecrypted') { throw 'The disposable Windows volume did not start BitLocker protection' }
            [pscustomobject]@{ volume = [string]$state.VolumeStatus; protection = [string]$state.ProtectionStatus }
        }
        Say "Windows BitLocker is $($verdict.windows_bitlocker_before.protection) on C:"
    }

    Copy-Item -ToSession $session -LiteralPath $Binary -Destination "$guestRoot\ntfs2refs.exe" -Force
    Copy-Item -ToSession $session -LiteralPath $RecoveryBinary -Destination "$guestRoot\ntfs2refs-recovery.exe" -Force
    Copy-Item -ToSession $session -LiteralPath $ManifestBinary -Destination "$guestRoot\lab-volume-manifest.exe" -Force

    $before = Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock {
        param($root)
        $text = & "$root\lab-volume-manifest.exe" capture --root 'P:\' --output "$root\manifest-before.jsonl" 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { throw "Restart source manifest capture failed (exit $LASTEXITCODE): $text" }
        $list = @(& "$root\ntfs2refs.exe" --list 2>&1 | ForEach-Object { "$_" })
        if ($LASTEXITCODE -ne 0) { throw "Restart source listing failed (exit $LASTEXITCODE): $list" }
        $row = [string]($list | Where-Object { $_ -match '\sP:\\\s' } | Select-Object -First 1)
        [pscustomobject]@{ exit = $LASTEXITCODE; listing = $text.Trim(); row = $row.Trim(); list = $list
            serial = if ($row -match 'serial ([0-9A-F]{4}-[0-9A-F]{4})') { $Matches[1] } else { $null } }
    }
    [IO.File]::WriteAllLines((Join-Path $records 'list.txt'), [string[]]$before.list)
    $verdict.list_row = $before.row
    Say "--list: $($before.row)"
    Say "listed before: $($before.listing)"
    if (-not $before.serial) { $verdict.outcome = 'list-did-not-show-serial'; throw "--list shows no serial number for P:: $($before.row)" }

    $arguments = @('--drive', 'P', '--restart-media', $made.media, '--scratch-directory', $work, '--yes', '--volume-serial', $before.serial) + $ConverterArgs
    if ($LabFailAt) { $arguments += @('--lab-fail-at', $LabFailAt, '--acknowledge-lab-fail-stops-the-run') }
    $staysInWindows = $ExpectScratchRefusal -or $ExpectWindowsBitLockerRefusal -or $LabFailAt -in 'restart-after-protect', 'restart-after-image', 'restart-after-arm', 'restart-skip-reboot'
    $verdict.arguments = $arguments
    Say "converter: ntfs2refs.exe $($arguments -join ' ')"
    # Started as SYSTEM by a task, with its output in files on C:, which is
    # there again after the restart: the session does not outlive it.
    Invoke-Command -Session $session -ArgumentList $guestRoot, (,$arguments) -ScriptBlock {
        param($root, $arguments)
        $line = "`"$root\ntfs2refs.exe`" " + (($arguments | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }) -join ' ')
        Set-Content -LiteralPath "$root\run.cmd" -Encoding ASCII -Value "@echo off`r`n$line > `"$root\stdout.log`" 2> `"$root\stderr.log`"`r`necho %ERRORLEVEL% > `"$root\exit.txt`""
        $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument "/c `"$root\run.cmd`""
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 6) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        $null = Register-ScheduledTask -TaskName 'n2r-restart-route' -Action $action -Principal $principal -Settings $settings -Force
        Start-ScheduledTask -TaskName 'n2r-restart-route'
    }
    $started = Get-Date
    # The run prepares in Windows, then restarts the machine. Until then the
    # session answers; a converter that ends without a restart has refused
    # or failed.
    $restarted = $false; $last = ''; $endedInWindows = $false
    while (-not $restarted -and -not $endedInWindows) {
        Start-Sleep -Seconds 10
        try {
            $state = Invoke-Command -Session $session -ArgumentList $guestRoot -ErrorAction Stop -ScriptBlock {
                param($root)
                $exit = if (Test-Path -LiteralPath "$root\exit.txt") { (Get-Content -LiteralPath "$root\exit.txt" -Raw).Trim() } else { $null }
                $tail = if (Test-Path -LiteralPath "$root\stdout.log") { [string](Get-Content -LiteralPath "$root\stdout.log" -Tail 1) } else { '' }
                [pscustomobject]@{ exit = $exit; tail = $tail }
            }
            if ($state.tail -and $state.tail -ne $last) { $last = $state.tail; Say ("[{0:N0} s] {1}" -f ((Get-Date) - $started).TotalSeconds, $last.Substring(0, [Math]::Min(180, $last.Length))) }
            if ($null -ne $state.exit -and $staysInWindows) {
                # The laboratory point ends the run in Windows.
                $verdict.exit = $state.exit; $endedInWindows = $true
                Say "the converter ended in Windows with exit $($state.exit)"
            } elseif ($null -ne $state.exit -and $state.exit -ne '0') {
                $verdict.outcome = 'refused-or-failed-in-windows'; $verdict.exit = $state.exit
                throw "the converter ended in Windows with exit $($state.exit) and did not restart"
            }
        } catch [System.Management.Automation.Remoting.PSRemotingTransportException] { $restarted = $true }
        catch { if ($_.Exception.Message -match 'session|pipeline|connection|broken|closed') { $restarted = $true } else { throw } }
        if (((Get-Date) - $started).TotalMinutes -gt $AwayMinutes) { $verdict.outcome = 'no-restart'; throw "no restart after $AwayMinutes minutes" }
    }
    $verdict.prepared_seconds = [Math]::Round(((Get-Date) - $started).TotalSeconds)
    if ($endedInWindows) {
        $said = Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock {
            param($root)
            $partition = Get-Partition -DriveLetter P -ErrorAction SilentlyContinue
            [pscustomobject]@{
                error = [string](Get-Content -LiteralPath "$root\stderr.log" -Tail 3 -ErrorAction SilentlyContinue | Out-String).Trim()
                output = [string](Get-Content -LiteralPath "$root\stdout.log" -Tail 30 -ErrorAction SilentlyContinue | Out-String)
                read_only = if ($partition) { [bool]$partition.IsReadOnly } else { $null }
                boot = [string](& bcdedit.exe /enum '{bootmgr}' 2>&1 | Where-Object { $_ -match '^(default|timeout)' } | Out-String).Trim() -replace '\s+', ' '
            }
        }
        Say "the run said: $($said.error -replace '\s+', ' ')"
        Say "P: read-only: $($said.read_only); boot manager: $($said.boot)"
        $verdict.after_the_point = $said
        if ($ExpectScratchRefusal) {
            $verdict.scratch_refusal = $verdict.exit -ne '0' -and $said.error.Contains('restart preparation needs an NTFS --scratch-directory')
            if (-not $verdict.scratch_refusal) { throw "Expected an NTFS working-storage refusal. $($said.error)" }
        } elseif ($ExpectWindowsBitLockerRefusal) {
            $verdict.windows_bitlocker_refusal = $verdict.exit -ne '0' -and $said.error.Contains('the running Windows volume is encrypted with BitLocker')
            if (-not $verdict.windows_bitlocker_refusal) { throw "Expected a BitLocker refusal for the running Windows volume. $($said.error)" }
        } else {
            $marker = '"kind":"lab-fail-v1","point":"' + $LabFailAt + '"'
            $verdict.reached_lab_fail_at = $said.output.Contains($marker)
        }
        if ($LabFailAt -and -not $verdict.reached_lab_fail_at) {
            $verdict.outcome = 'failure-point-not-reached'
            throw "The converter stopped before $LabFailAt. $($said.error)"
        }
        if ($LabFailAt -in 'restart-after-arm', 'restart-skip-reboot') {
            # Left prepared: asked what it is, then cancelled.
            $recovered = Invoke-Command -Session $session -ArgumentList $guestRoot, $work -ScriptBlock {
                param($root, $work)
                $run = @(Get-ChildItem -LiteralPath $work -Directory -Filter 'partition-offline-conversion-*')[0].FullName
                $status = @(& "$root\ntfs2refs.exe" --recover $run 2>&1 | ForEach-Object { "$_" }); $statusExit = $LASTEXITCODE
                $cancel = @(& "$root\ntfs2refs.exe" --recover $run --rollback --yes 2>&1 | ForEach-Object { "$_" }); $cancelExit = $LASTEXITCODE
                $again = @(& "$root\ntfs2refs.exe" --recover $run 2>&1 | ForEach-Object { "$_" }); $againExit = $LASTEXITCODE
                [pscustomobject]@{ run = $run; status = $status; status_exit = $statusExit; cancel = $cancel; cancel_exit = $cancelExit; again = $again; again_exit = $againExit }
            }
            [IO.File]::WriteAllLines((Join-Path $records 'recover-status.txt'), [string[]]$recovered.status)
            [IO.File]::WriteAllLines((Join-Path $records 'recover-rollback.txt'), [string[]]$recovered.cancel)
            [IO.File]::WriteAllLines((Join-Path $records 'recover-status-after.txt'), [string[]]$recovered.again)
            if ($recovered.status_exit -ne 0 -or $recovered.cancel_exit -ne 0 -or $recovered.again_exit -ne 0) {
                throw 'Restart cancellation or its status check failed. See the recovery logs.'
            }
            $plain = { param($lines) @($lines | Where-Object { $_ -match '^[A-Z].* ' -and $_ -notmatch '^[a-z0-9-]+$' }) -join ' | ' }
            Say "--recover (exit $($recovered.status_exit)): $(& $plain $recovered.status)"
            Say "--recover --rollback (exit $($recovered.cancel_exit)): $(& $plain $recovered.cancel)"
            Say "--recover afterwards (exit $($recovered.again_exit)): $(& $plain $recovered.again)"
            $verdict.recover = [ordered]@{ status_exit = $recovered.status_exit; cancel_exit = $recovered.cancel_exit; again_exit = $recovered.again_exit }
        }
    } else {
    Say "the machine went away after $($verdict.prepared_seconds) s in Windows"
    Remove-PSSession $session -ErrorAction SilentlyContinue; $session = $null

    # Away: WinPE, the conversion, the return. No session can be had in
    # WinPE; the console is pictured once a minute.
    $away = Get-Date; $shot = 0
    while ($true) {
        Start-Sleep -Seconds 20
        if (((Get-Date) - $away).TotalSeconds -ge 60 * ($shot + 1)) { $shot++; Screenshot ('console-{0:d2}' -f $shot) }
        try {
            $session = New-PSSession -VMId $VmId -Credential $credential -ErrorAction Stop
            $null = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock { $env:COMPUTERNAME }
            break
        } catch { $session = $null }
        if (((Get-Date) - $away).TotalMinutes -gt $AwayMinutes) { $verdict.outcome = 'did-not-return'; Screenshot 'console-last'; throw "Windows did not come back within $AwayMinutes minutes" }
    }
    $verdict.away_seconds = [Math]::Round(((Get-Date) - $away).TotalSeconds)
    Say "Windows is back after $($verdict.away_seconds) s away"
    }

    $after = Invoke-Command -Session $session -ArgumentList $guestRoot, $work -ScriptBlock {
        param($root, $work)
        $volume = Get-Volume -DriveLetter P -ErrorAction SilentlyContinue
        $listed = ''; $summary = ''; $compare = $null
        if ($volume) {
            $listed = & "$root\lab-volume-manifest.exe" capture --root 'P:\' --output "$root\manifest-after.jsonl" 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) { throw "Restart result manifest capture failed (exit $LASTEXITCODE): $listed" }
            # Not --exact: Windows writes its own file into System Volume
            # Information as soon as a volume is writable again (a volume
            # given back listed one file more for it). What else the
            # comparison let through is held to nothing below.
            $summary = & "$root\lab-volume-manifest.exe" compare --before "$root\manifest-before.jsonl" --after "$root\manifest-after.jsonl" --report "$root\manifest-report.json" 2>&1 | Out-String
            $compare = $LASTEXITCODE
            if ($compare -notin 0, 2) { throw "Restart manifest comparison failed (exit ${compare}): $summary" }
            $report = Get-Content -LiteralPath "$root\manifest-report.json" -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $report.allowed -or $null -eq $report.differences -or $null -eq $report.difference_count -or
                ($report.difference_count -eq 0) -ne ($compare -eq 0)) { throw 'Restart manifest report disagrees with the comparison result' }
            if ($compare -eq 2) {
                # The directory System Volume Information itself has new
                # times once Windows has written into it: that alone is no
                # difference of the volume's.
                $differences = @($report.differences)
                $other = @($differences | Where-Object { $_.path -ne '\System Volume Information' -or $_.kind -notin 'creation time changed', 'last write time changed', 'change time changed' })
                if ($differences.Count -eq $report.difference_count -and -not $other) { $compare = 0; $summary = "only the times of System Volume Information differ. $summary" }
            }
            if ($compare -eq 0) {
                $let = @($report.allowed.PSObject.Properties.Name | Where-Object { $_ -ne 'System Volume Information content' })
                if ($let) { $compare = 2; $summary = "let through besides Windows' own files: $($let -join ', '). $summary" }
            }
        }
        $partition = Get-Partition -DriveLetter P -ErrorAction SilentlyContinue
        # A volume given back has to take a write and give it up again.
        # (After the listing: a write changes the root directory's times.)
        $writable = $null
        try { [IO.File]::WriteAllText('P:\written-after.txt', 'x'); Remove-Item -LiteralPath 'P:\written-after.txt' -Force; $writable = $true } catch { $writable = $false }
        [pscustomobject]@{
            filesystem = if ($volume) { "$($volume.FileSystem)" } else { $null }; health = if ($volume) { "$($volume.HealthStatus)" } else { $null }
            read_only = if ($partition) { [bool]$partition.IsReadOnly } else { $null }
            writable = $writable
            cancelled = @(Get-ChildItem -LiteralPath $work -Recurse -Filter 'cancelled.json' -ErrorAction SilentlyContinue | ForEach-Object { (Get-Content -LiteralPath $_.FullName -Raw) -replace '\s+', ' ' })
            listed = $listed.Trim(); summary = $summary.Trim(); compare_exit = $compare
            boot_default = [string](& bcdedit.exe /enum '{bootmgr}' 2>&1 | Where-Object { $_ -match '^(default|displayorder|timeout)' } | Out-String).Trim()
            runs = @(Get-ChildItem -LiteralPath $work -Directory -ErrorAction SilentlyContinue | ForEach-Object Name)
        }
    }
    $verdict.after = $after
    Say "P: is $($after.filesystem), $($after.health), read-only: $($after.read_only), takes a write: $($after.writable)"
    Say "boot manager: $($after.boot_default -replace '\s+', ' ')"
    foreach ($record in $after.cancelled) { Say "cancelled.json: $($record.Substring(0, [Math]::Min(600, $record.Length)))" }
    Say "compare: $($after.summary)"
    foreach ($leaf in 'stdout.log', 'stderr.log', 'exit.txt', 'manifest-report.json') {
        try { Copy-Item -FromSession $session -LiteralPath "$guestRoot\$leaf" -Destination $records -Force -ErrorAction Stop } catch { }
    }
    # The run's small records, and what WinPE wrote beside them.
    try {
        $archived = Invoke-Command -Session $session -ArgumentList $guestRoot, $work -ScriptBlock {
            param($root, $work)
            $files = Get-ChildItem -LiteralPath $work -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 4MB -and $_.Extension -in '.json', '.log', '.txt' }
            if ($files) { Compress-Archive -LiteralPath $files.FullName -DestinationPath "$root\records.zip" -Force }
            Test-Path -LiteralPath "$root\records.zip" -PathType Leaf
        }
        if ($archived) { Copy-Item -FromSession $session -LiteralPath "$guestRoot\records.zip" -Destination $records -Force -ErrorAction Stop }
    } catch { Say "the run's records could not be collected: $($_.Exception.Message)" }
    if ($ExpectWindowsBitLockerRefusal) {
        $verdict.windows_bitlocker_after = Invoke-Command -Session $session -ScriptBlock {
            $state = Get-BitLockerVolume -MountPoint 'C:'
            [pscustomobject]@{ volume = [string]$state.VolumeStatus; protection = [string]$state.ProtectionStatus }
        }
    }
    $verdict.outcome = if ($ExpectScratchRefusal) {
            if ($verdict.scratch_refusal -and $after.filesystem -eq 'NTFS' -and $after.compare_exit -eq 0 -and $after.writable -and $after.boot_default -match 'default\s+\{current\}' -and -not $after.runs) { 'refused-source-unchanged' }
            else { 'scratch-refusal-incomplete' }
        }
        elseif ($ExpectWindowsBitLockerRefusal) {
            if ($verdict.windows_bitlocker_refusal -and $after.filesystem -eq 'NTFS' -and $after.compare_exit -eq 0 -and
                $after.writable -and $after.read_only -eq $false -and $after.boot_default -match 'default\s+\{current\}' -and
                -not $after.runs -and $verdict.windows_bitlocker_after.protection -eq 'On') {
                'refused-windows-bitlocker-source-unchanged'
            } else { 'windows-bitlocker-refusal-incomplete' }
        }
        elseif ($LabFailAt) {
            if ($after.filesystem -eq 'NTFS' -and $after.compare_exit -eq 0 -and $after.read_only -eq $false -and $after.writable -and $after.boot_default -match 'default\s+\{current\}') { 'cancelled-volume-as-before' }
            else { 'cancel-incomplete' }
        }
        elseif ($after.filesystem -ne 'ReFS') { "returned-with-$($after.filesystem)" }
        elseif ($after.compare_exit -ne 0) { 'converted-but-listing-differs' }
        else { 'converted' }
    $verdict.manifest = @{ result = if ($after.compare_exit -eq 0) { 'identical' } else { 'differs' }; exact = $false }
}
catch {
    $verdict.error = "$($_.Exception.Message)"
    Say "ERROR: $($verdict.error)"
    if ($session) {
        foreach ($leaf in 'stdout.log', 'stderr.log', 'exit.txt') { try { Copy-Item -FromSession $session -LiteralPath "$guestRoot\$leaf" -Destination $records -Force -ErrorAction Stop } catch { } }
        try {
            Invoke-Command -Session $session -ArgumentList $guestRoot, $work -ErrorAction Stop -ScriptBlock {
                param($root, $work)
                $files = Get-ChildItem -LiteralPath $work -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 4MB -and $_.Extension -in '.json', '.log', '.txt' }
                if ($files) { Compress-Archive -LiteralPath $files.FullName -DestinationPath "$root\records.zip" -Force }
                $partition = Get-Partition -DriveLetter P -ErrorAction SilentlyContinue
                "P: after the failure: " + $(if ($partition) { "read-only $($partition.IsReadOnly), offline $($partition.IsOffline), GPT attributes 0x$('{0:x}' -f $partition.GptAttributes)" } else { 'no partition at P:' })
            } | ForEach-Object { Say "$_" }
            Copy-Item -FromSession $session -LiteralPath "$guestRoot\records.zip" -Destination $records -Force -ErrorAction Stop
        } catch { }
    }
}
finally {
    if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
    # The working disk stays attached: the caller turns the VM off and
    # restores its checkpoint, and removes the file then.
    Save-Verdict
    Say "outcome: $($verdict.outcome). Records: $records"
}
