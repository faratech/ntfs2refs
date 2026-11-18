<#
.SYNOPSIS
Converts one NTFS data volume of a chosen geometry in a lab VM's control OS
and compares the volume's listing before and after.

.DESCRIPTION
The boot harness (Invoke-BootConversionAttempt.ps1) converts the lab's Windows
partition, which has one geometry. This script makes a data volume of the
geometry asked for, fills it with a fixed set of ordinary and awkward
objects, lists it, converts it with `ntfs2refs --drive`, lists it again and
compares the two listings with lab-volume-manifest. It takes seconds, so one
VM can run a whole matrix of geometries.

The control OS must already be up: run
`Invoke-BootConversionAttempt.ps1 -Name <n> -NoConvert -KeepScratch [-VmId ...]`
first. The volume is a VHDX on that attempt's scratch disk (S:), or, for
-SectorBytes 4096, a VHDX the host makes in this attempt's folder and attaches
to the VM for the length of the attempt. It is removed when the attempt ends
unless -KeepVolume is given.

Outcomes: converted (ReFS, listing identical), converted-but-listing-differs,
converted-but-target-differs (with -ExpectTarget: Windows reports another
kind of ReFS volume than the one expected),
refused-source-unchanged (the converter stopped and the NTFS volume lists
exactly as before), refused-as-expected (the same, and -ExpectRefusal matched),
refused-after-shrinking-the-partition (it lists as before, and is shorter),
and named failures. With -InterruptAt: resumed (recovered to ReFS, listing
identical) or rolled-back (recovered to NTFS, listing exactly as before).
With -StopDuringPreparation: preparation-cancelled (the command the run
printed for this case gave the NTFS volume back, listing exactly as before)
or, with -AfterStop restart, restart-refused-then-cancelled (a new run was
refused with that way back named, and it then worked).
Records land in .lab\hyperv\attempts\<Name>\.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Name,
    [string]$VmId = '8f7fc646-8c9f-41d0-b65a-ecfadccfc36a',
    # The guest account's saved credential. The reference VMs share one; a VM
    # made by New-ServerLabVm.ps1 has its own and prints where it is.
    [string]$CredentialPath,
    # NTFS allocation unit of the source, in bytes: 512 through 2097152.
    [int]$ClusterBytes = 4096,
    # Logical sector size of the source disk. 4096 is a 4Kn disk.
    [ValidateSet(512, 4096)][int]$SectorBytes = 512,
    # format /L: 4096-byte file records on a 512-byte-sector disk.
    [switch]$LargeRecords,
    # Size of the source partition. ReFS covers whole 64 MiB units.
    [int]$PartitionMB = 51200,
    # 'default' gives the converter no --target-format, as someone does who
    # does not know the option: what it then asks Windows for, and what
    # Windows says the volume is, are in the verdict (target.requested,
    # target.windows_reports). -ExpectTarget holds the run to one of them.
    [ValidateSet('dev-drive', 'standard', 'default')][string]$TargetFormat = 'dev-drive',
    # A pattern for what Windows has to report the converted volume as, for
    # example '^standard' or '^Dev Drive'; a volume it reports as anything
    # else makes the outcome converted-but-target-differs.
    [string]$ExpectTarget,
    # ReFS allocation unit of the target, passed as --target-cluster-bytes; 0 leaves the converter's default.
    [int]$TargetClusterBytes = 0,
    [ValidateSet('system', 'administrator')][string]$RunAs = 'system',
    # What to put on the volume: the fixed mixed set, nothing but one file, a
    # file of many streams and one of many islands, or the mixed set with what
    # a volume that has been in use has (see -Features).
    [ValidateSet('mixed', 'minimal', 'many', 'lived-in')][string]$Content = 'mixed',
    # NTFS features to add after the content, made by guest\Add-VolumeFeatures.ps1:
    # objectids, security, ea, links, longpath, deep, bigdir, bigfile, full,
    # copy, usn, casemark, manyfiles (all of which convert; -Content lived-in
    # adds them except bigfile, full, casemark and manyfiles), and shortnames, temporary, offline,
    # efs, wof, quota, casesensitive, snapshot, bitlocker, dirstream (which
    # are refused).
    [string[]]$Features = @(),
    [int]$DirectoryEntries = 20000,
    [int]$BigFileGB = 6,
    # Files of the 'manyfiles' feature: a volume for measuring how a run
    # grows with their number. The verdict's "resources" has what the run
    # took: the converter's peak memory and the working storage at its
    # largest, sampled every two seconds.
    [int]$FileCount = 500000,
    # Further converter arguments, for example '--diagnose'.
    [string[]]$ConverterArgs = @(),
    # A pattern the converter's error must match for a refusal to count as expected.
    [string]$ExpectRefusal,
    # A laboratory hold point (for example apply-mid-ranges or handoff-sealed):
    # the converter is ended when it reports that it is held there, and the
    # run is then recovered with the command it printed.
    [string]$InterruptAt,
    [ValidateSet('resume', 'rollback')][string]$RecoverMode = 'resume',
    # A phase of preparation, as the converter's progress records name it (for
    # example payload_supply or recovery_journal): the converter's process is
    # ended as soon as it reports that phase, before it has printed a
    # recovery command or written to the volume. What that leaves is recorded.
    [string]$StopDuringPreparation,
    # What is done about a preparation that was stopped. 'cancel' runs the
    # command the run printed for this case at its start. 'restart' first
    # starts the same conversion again as if nothing had happened, which is
    # what someone does who did not see the run stop: it has to be refused
    # with words that name the way back, and the cancellation is run then.
    [ValidateSet('cancel', 'restart')][string]$AfterStop = 'cancel',
    # Run the converter with --diagnose: nothing is written, and the volume
    # must list exactly as before whatever it reports.
    [switch]$Diagnose,
    # Sample the converter's stacks while it runs (needs ntfs2refs.pdb beside
    # the binary); the profile lands in stacks.txt.
    [switch]$SampleStacks,
    # Islands of the sparse file that -Content many makes.
    [int]$Islands = 70000,
    [string]$Binary,
    [string]$ManifestBinary,
    [int]$TimeoutMinutes = 60,
    # After a conversion whose listing is identical, use the volume: write,
    # change, rename and delete files, fill it and free it, snapshot it, mount
    # it again (guest\Test-ConvertedVolumeUse.ps1). A step that fails makes
    # the outcome converted-but-use-failed.
    [switch]$Acceptance,
    # The control for -Acceptance: nothing is converted. Windows formats the
    # volume as ReFS itself, the content is put on it, and the same use test
    # runs. What fails here too is how ReFS or this Windows behaves; what
    # fails only on a converted volume is the conversion's. Use it with
    # -Content minimal and features that ReFS can hold (copy, security, ea,
    # links, longpath, deep, bigdir).
    [switch]$NativeRefsControl,
    # Run the converter as a script would: `--yes --volume-serial <the volume's
    # serial number>`, with nothing typed at its prompt. A recovery gets --yes.
    [switch]$Unattended,
    # With -Unattended: give a serial number that is not the volume's. The run
    # has to refuse before it opens anything.
    [switch]$WrongSerial,
    # Run `ntfs2refs --check` on the volume first and record what it says
    # (check.txt, and `check` in the verdict). The attempt then goes on as
    # usual and the two are compared: a check that found nothing before a
    # conversion that was refused, or the other way round, adds
    # "-but-check-disagreed" to the outcome, and a check that named a
    # refusal other than the one the conversion gave adds
    # "-but-check-named-another-refusal".
    # Leave the control OS's scheduled drive optimisation on (see the note
    # where it is switched off, and issue 132).
    [switch]$WithDriveOptimization,
    [switch]$Check,
    # Only the check: nothing is converted, and the volume has to list
    # exactly as before and be as long, online and writable as before.
    # Outcomes: check-clean, check-found-refusals (check-refused-as-expected
    # when -ExpectRefusal matches one of them), check-inconclusive,
    # check-changed-the-source.
    [switch]$CheckOnly,
    # With -Check or -CheckOnly: a file is created on the volume a moment
    # before the check and nothing waits for Windows to write it out, as
    # when someone saves a file and starts the converter. The check has to
    # read it: on a volume with short names its refusal counts the file.
    [switch]$FreshFile,
    # With -Check or -CheckOnly: while the check reads, a program holds a
    # file open that it has deleted. NTFS keeps such a file in a directory
    # of its own until the handle closes, and a volume in use can have some
    # at any moment. The check must not refuse the volume for it and has to
    # say in a note that it saw one; the handle is closed before the run.
    [switch]$DeletedWhileOpen,
    # With -CheckOnly: files are written to and deleted from the volume all
    # the while it is read. The check may find the volume at rest or not; it
    # must never report a refusal that is not there.
    [switch]$WriteLoad,
    # Put the source on a disk it shares with four other partitions: an EFI
    # system partition (FAT32, no letter), W: (an ordinary NTFS volume), and
    # behind the source X: (NTFS, write-protected in the partition table)
    # and a partition of another operating system, with no file system
    # Windows knows. Before the run and after it W: is listed and compared
    # exactly, and the other three, which nothing writes to, are hashed
    # through the disk; W: and X: have to be back under their letters.
    # Anything else adds "-but-siblings-changed" to the outcome.
    [switch]$Siblings,
    # The source disk is MBR instead of GPT: the volume is a primary
    # partition of type 07. With -MbrBeside a second primary partition (W:,
    # NTFS, one file) lies beside it, which makes the disk one the volume
    # shares.
    [switch]$SourceMbr,
    [switch]$MbrBeside,
    # The working directory is on an MBR disk of its own (M:\runs, a virtual
    # disk made for the attempt) instead of on S:.
    [switch]$WorkingMbr,
    # With -Siblings, something about W: for which a run has to refuse the
    # disk: 'busy' keeps a file on it open, 'snapshot' gives it a shadow
    # copy, 'dump' names it as the place Windows writes its crash dump to.
    # Each is undone when the attempt ends.
    [ValidateSet('', 'busy', 'snapshot', 'dump')][string]$SiblingState = '',
    # Run the converter (and the check before it) with --short-names drop:
    # a volume with 8.3 short names (-Features shortnames) then converts.
    # The comparison is the one made for such a run: a short name that is
    # gone is counted, nothing else is let through, and the converted
    # volume must list no short name at all.
    [switch]$DropShortNames,
    # A shadow-copy (VSS) provider that the converter does not know.
    # 'answering' is one of Windows Server's own, the iSCSI target storage
    # provider (the Windows feature iSCSITarget-VSS-VDS, so the VM has to run
    # Windows Server): it answers when asked and holds no shadow copy, so the
    # volume converts, and the check and the run each have to say so in a
    # note that names it. The feature is installed if it is missing and
    # stays: Windows wants a restart to finish removing it, so it is removed
    # by hand when the cases are done. 'silent' registers a provider whose
    # class does not exist, for as long as the attempt lasts: it cannot
    # answer, and the volume has to be refused with words that name it
    # (-ExpectRefusal).
    [ValidateSet('', 'answering', 'silent')][string]$VssProvider = '',
    # Run the converter with --compare-listing: it lists the volume itself
    # before and after and compares. The harness's own listings are made as
    # always, and the two comparisons have to agree: a run whose own
    # comparison says other than the harness's ends
    # "...-but-own-listing-disagreed".
    [switch]$CompareListing,
    [switch]$KeepVolume
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$workspace = Split-Path -Parent $PSScriptRoot
if (-not $Binary) { $Binary = Join-Path $workspace 'target\release\ntfs2refs.exe' }
if (-not $ManifestBinary) { $ManifestBinary = Join-Path $workspace 'target\release\lab-volume-manifest.exe' }
foreach ($file in $Binary, $ManifestBinary) { if (-not (Test-Path -LiteralPath $file)) { throw "Not found: $file (cargo build --locked --release --bin ntfs2refs --bin lab-volume-manifest)" } }
if ($ClusterBytes -lt 512 -or $ClusterBytes -gt 2097152 -or ($ClusterBytes -band ($ClusterBytes - 1))) { throw "-ClusterBytes $ClusterBytes is not a power of two from 512 to 2097152" }
if ($ClusterBytes -lt $SectorBytes) { throw "-ClusterBytes $ClusterBytes is smaller than the $SectorBytes-byte sector" }
if ($StopDuringPreparation -and ($InterruptAt -or $Diagnose)) { throw '-StopDuringPreparation is a run of its own: not with -InterruptAt or -Diagnose' }

$records = Join-Path $workspace ".lab\hyperv\attempts\$Name"
if (Test-Path -LiteralPath $records) { throw "Attempt '$Name' already has records at $records; choose another -Name" }
$null = New-Item -ItemType Directory -Path $records
$progress = Join-Path $records 'progress.log'
function Say([string]$Text) { $line = '{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $Text; Add-Content -LiteralPath $progress -Value $line -Encoding UTF8; Write-Host $line }
$verdict = [ordered]@{
    name = $Name; outcome = 'harness-error'; vm_id = $VmId; run_as = $RunAs
    source = [ordered]@{ cluster_bytes = $ClusterBytes; sector_bytes = $SectorBytes; large_records = [bool]$LargeRecords; partition_mb = $PartitionMB; content = $Content }
    target = [ordered]@{ format = $TargetFormat; cluster_bytes_requested = $TargetClusterBytes }
    converter_sha256 = (Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash.ToLowerInvariant()
    listing_tool_sha256 = (Get-FileHash -LiteralPath $ManifestBinary -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Save-Verdict { [IO.File]::WriteAllText((Join-Path $records 'verdict.json'), ($verdict | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false)) }

# Runs guest\Test-ConvertedVolumeUse.ps1 on V:, records every step and answers its result.
function Invoke-UseTest([string]$Root) {
    Copy-Item -ToSession $session -LiteralPath (Join-Path $PSScriptRoot 'guest\Test-ConvertedVolumeUse.ps1') -Destination "$Root\use.ps1" -Force
    $useJson = Invoke-Command -Session $session -ArgumentList $Root -ScriptBlock {
        param($root)
        $block = [scriptblock]::Create((Get-Content -LiteralPath "$root\use.ps1" -Raw))
        & $block -Root 'V:\' -WorkDirectory "$root\use" -ProgressFile "$root\use-progress.log"
    }
    $use = ($useJson | Select-Object -Last 1) | ConvertFrom-Json
    Set-Content -LiteralPath (Join-Path $records 'acceptance.json') -Value ($useJson | Select-Object -Last 1) -Encoding UTF8
    $verdict.acceptance = $use
    foreach ($step in $use.steps) { Say ("use: {0}: {1} ({2} s): {3}" -f $step.step, $(if ($null -eq $step.ok) { 'skipped' } elseif ($step.ok) { 'ok' } else { 'FAILED' }), $step.seconds, $step.detail) }
    $use
}

$vm = Get-VM -Id $VmId
if ($vm.State -ne 'Running') { throw "VM $($vm.Name) is $($vm.State). Start its control OS first: Invoke-BootConversionAttempt.ps1 -Name <n> -NoConvert -KeepScratch -VmId $VmId" }
if (-not $CredentialPath) { $CredentialPath = Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml' }
$saved = Import-Clixml -LiteralPath $CredentialPath
$credential = [pscredential]::new('LabAdmin', $saved.Password)
$session = New-PSSession -VMId $VmId -Credential $credential
# The control OS's scheduled drive optimisation holds up writes to its ReFS
# volumes for minutes when Windows' automatic maintenance starts it (issue
# 132); an attempt then measures that. It is switched off unless asked for.
$verdict.drive_optimization = if ($WithDriveOptimization) { 'left on' } else {
    try {
        Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
            # -ErrorAction on the call, not the preference variable: a
            # variable set here stays set in the session, and a note the
            # converter writes to stderr would then end the command that
            # runs it.
            $null = Disable-ScheduledTask -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag' -ErrorAction Stop
            Stop-ScheduledTask -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag' -ErrorAction SilentlyContinue
        }
        'switched off for this attempt'
    } catch { "not switched off: $($_.Exception.Message)" }
}
Say "the control OS's scheduled drive optimisation: $($verdict.drive_optimization)"
$hostDisk = $null; $worker = $null
$guestRoot = "C:\n2r\datalab\$Name"
# format.com spells an allocation unit as bytes up to 8192 and as K or M above.
$unit = if ($ClusterBytes -ge 1048576) { '{0}M' -f ($ClusterBytes / 1048576) } elseif ($ClusterBytes -ge 16384) { '{0}K' -f ($ClusterBytes / 1024) } else { "$ClusterBytes" }
try {
    Say "attempt ${Name}: NTFS $ClusterBytes-byte clusters on $SectorBytes-byte sectors$(if ($LargeRecords) { ', 4096-byte file records' }), $PartitionMB MiB, content '$Content', as $RunAs"
    $ready = Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock {
        param($root)
        if (-not (Test-Path -LiteralPath 'S:\')) { throw 'The control OS has no scratch volume S:. Prepare it with Invoke-BootConversionAttempt.ps1 -NoConvert -KeepScratch.' }
        $null = New-Item -ItemType Directory -Path $root, 'S:\datalab\runs' -Force
        # A volume an earlier attempt left at V: is detached, never reused.
        $old = Get-Partition -DriveLetter V -ErrorAction SilentlyContinue
        if ($old) {
            $location = (Get-Disk -Number $old.DiskNumber).Location
            if ($location -like '*.vhd*') {
                Set-Content -LiteralPath "$root\detach-old.txt" -Value ("select vdisk file=`"$location`"`r`ndetach vdisk") -Encoding ASCII
                $null = & diskpart.exe /s "$root\detach-old.txt" 2>&1
            } else { Remove-PartitionAccessPath -DiskNumber $old.DiskNumber -PartitionNumber $old.PartitionNumber -AccessPath 'V:\' }
        }
        (Get-Disk).Number
    }
    Copy-Item -ToSession $session -LiteralPath $Binary -Destination "$guestRoot\ntfs2refs.exe" -Force
    if ($SampleStacks) {
        $symbols = [IO.Path]::ChangeExtension($Binary, '.pdb')
        if (-not (Test-Path -LiteralPath $symbols)) { throw "-SampleStacks needs the symbols beside the binary: $symbols" }
        Copy-Item -ToSession $session -LiteralPath $symbols -Destination "$guestRoot\ntfs2refs.pdb" -Force
    }
    Copy-Item -ToSession $session -LiteralPath $ManifestBinary -Destination "$guestRoot\lab-volume-manifest.exe" -Force
    Copy-Item -ToSession $session -LiteralPath (Join-Path $PSScriptRoot 'guest\Invoke-ConverterRun.ps1') -Destination "$guestRoot\worker.ps1" -Force
    Copy-Item -ToSession $session -LiteralPath (Join-Path $PSScriptRoot 'guest\Add-VolumeFeatures.ps1') -Destination "$guestRoot\features.ps1" -Force

    # The source disk: a VHDX in the guest, or for 4Kn one the host attaches.
    if ($Siblings -and ($SectorBytes -eq 4096 -or $NativeRefsControl)) { throw '-Siblings is for a converted volume on a 512-byte-sector disk' }
    if ($SourceMbr -and $Siblings) { throw '-Siblings makes a GPT disk; a partition beside an MBR source is -MbrBeside' }
    if ($MbrBeside -and -not $SourceMbr) { throw '-MbrBeside is something about the disk -SourceMbr makes' }
    if ($SiblingState -and -not $Siblings) { throw '-SiblingState is something about the volume W: that -Siblings makes' }
    $sizeMB = $PartitionMB + 2048 + $(if ($Siblings) { 3840 } else { 0 })
    $style = if ($SourceMbr) { 'mbr' } else { 'gpt' }
    $working = if ($WorkingMbr) { 'M:\runs' } else { 'S:\datalab\runs' }
    if ($SectorBytes -eq 4096) {
        $hostDisk = Join-Path $records 'source-4kn.vhdx'
        $null = New-VHD -Path $hostDisk -SizeBytes ($sizeMB * 1MB) -Dynamic -LogicalSectorSizeBytes 4096 -PhysicalSectorSizeBytes 4096
        Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -Path $hostDisk
        Say "attached a 4Kn disk to the VM: $hostDisk"
    }
    # A VHDX reports 4096-byte physical sectors, and NTFS will not format a
    # cluster smaller than the physical sector; a VHD reports 512.
    $container = if ($ClusterBytes -lt 4096) { 'vhd' } else { 'vhdx' }
    if ($NativeRefsControl -and $TargetFormat -eq 'default') { throw '-NativeRefsControl formats the volume itself: name -TargetFormat dev-drive or standard' }
    if ($NativeRefsControl -and $Content -ne 'minimal') { throw '-NativeRefsControl takes -Content minimal: the mixed content uses what only NTFS has' }
    if ($WorkingMbr) {
        # Working storage on an MBR disk: a virtual disk of its own, so that
        # the disk a run keeps its shadow and its records on has a signature
        # and no GUIDs.
        $work = Invoke-Command -Session $session -ArgumentList $guestRoot, $Name, ($PartitionMB * 2 + 16384) -ScriptBlock {
            param($root, $name, $sizeMB)
            $file = "S:\datalab\$name-work.vhdx"
            $script = "create vdisk file=`"$file`" maximum=$sizeMB type=expandable`r`nattach vdisk`r`nconvert mbr`r`ncreate partition primary`r`nformat fs=ntfs quick label=N2RWORK`r`nassign letter=M"
            Set-Content -LiteralPath "$root\make-work.txt" -Value $script -Encoding ASCII
            $diskpart = & diskpart.exe /s "$root\make-work.txt" 2>&1 | Out-String
            if (-not (Get-Partition -DriveLetter M -ErrorAction SilentlyContinue)) { throw "diskpart made no volume M:`n$diskpart" }
            $null = New-Item -ItemType Directory -Path 'M:\runs' -Force
            $disk = Get-Disk -Number (Get-Partition -DriveLetter M).DiskNumber
            [pscustomobject]@{ style = "$($disk.PartitionStyle)"; signature = ('{0:x8}' -f $disk.Signature); number = $disk.Number }
        }
        if ($work.style -ne 'MBR') { throw "the working disk is $($work.style), not MBR" }
        Say "working storage: M:\runs on MBR disk $($work.number), signature $($work.signature)"
        $verdict.working_disk = $work
    }
    $made = Invoke-Command -Session $session -ArgumentList $guestRoot, $Name, $sizeMB, $PartitionMB, $SectorBytes, $unit, ([bool]$LargeRecords), @($ready), $container, ([bool]$NativeRefsControl), $TargetFormat, ([bool]$Siblings), $style, ([bool]$MbrBeside) -ScriptBlock {
        param($root, $name, $sizeMB, $partitionMB, $sectorBytes, $unit, $largeRecords, $known, $container, $native, $targetFormat, $siblings, $style, $mbrBeside)
        if ($sectorBytes -eq 4096) {
            $deadline = (Get-Date).AddSeconds(60)
            do { Start-Sleep -Milliseconds 500; $new = @(Get-Disk | Where-Object { $_.Number -notin $known -and $_.LogicalSectorSize -eq 4096 }) } until ($new.Count -eq 1 -or (Get-Date) -gt $deadline)
            if ($new.Count -ne 1) { throw "expected one new 4Kn disk in the guest, found $($new.Count)" }
            $number = $new[0].Number
            if ($new[0].IsOffline) { Set-Disk -Number $number -IsOffline $false }
            if ($new[0].IsReadOnly) { Set-Disk -Number $number -IsReadOnly $false }
            $script = "select disk $number`r`nclean`r`nconvert $style`r`ncreate partition primary size=$partitionMB`r`nassign letter=V"
        } else {
            $file = "S:\datalab\$name.$container"
            $script = "create vdisk file=`"$file`" maximum=$sizeMB type=expandable`r`nattach vdisk`r`nconvert $style`r`ncreate partition primary size=$partitionMB`r`nassign letter=V"
            # A second primary partition beside an MBR source.
            if ($mbrBeside) { $script += "`r`ncreate partition primary size=1024`r`nformat fs=ntfs quick label=BESIDE`r`nassign letter=W" }
            if ($siblings) {
                # An EFI system partition (FAT32, no letter), W:, the source,
                # X:, and a partition of another operating system (no file
                # system Windows knows): what a disk that was once a
                # computer's own, or is shared with another system, holds.
                $script = "create vdisk file=`"$file`" maximum=$sizeMB type=expandable`r`nattach vdisk`r`nconvert gpt`r`ncreate partition efi size=100`r`nformat fs=fat32 quick label=SIBLING-E`r`ncreate partition primary size=2048`r`nformat fs=ntfs quick label=SIBLING-A`r`nassign letter=W`r`ncreate partition primary size=$partitionMB`r`nassign letter=V`r`ncreate partition primary size=1024`r`nformat fs=ntfs quick label=SIBLING-B`r`nassign letter=X`r`ncreate partition primary size=512 id=0fc63daf-8483-4772-8e79-3d69d8477de4"
            }
        }
        Set-Content -LiteralPath "$root\make.txt" -Value $script -Encoding ASCII
        $diskpart = & diskpart.exe /s "$root\make.txt" 2>&1 | Out-String
        if (-not (Get-Partition -DriveLetter V -ErrorAction SilentlyContinue)) { throw "diskpart made no volume V:`n$diskpart" }
        if ($mbrBeside) { Set-Content -LiteralPath 'W:\kept.txt' -Value 'beside an MBR source' -Encoding ASCII }
        $arguments = @('V:', '/FS:NTFS', "/A:$unit", '/Q', '/Y', '/V:DATALAB'); if ($largeRecords) { $arguments += '/L' }
        if ($native) { $arguments = @('V:', '/FS:ReFS', '/Q', '/Y', '/V:DATALAB'); if ($targetFormat -eq 'dev-drive') { $arguments += '/DevDrv' } }
        $format = & "$env:SystemRoot\System32\format.com" $arguments 2>&1 | Out-String
        if ($siblings) {
            $content = New-Object byte[] 300000; (New-Object Random 7).NextBytes($content)
            foreach ($letter in 'W', 'X') {
                $null = New-Item -ItemType Directory -Path "${letter}:\kept\inner" -Force
                [IO.File]::WriteAllBytes("${letter}:\kept\a.bin", $content); [IO.File]::WriteAllBytes("${letter}:\kept\inner\b.bin", $content[0..99999])
                Set-Content -LiteralPath "${letter}:\kept\note.txt" -Value "sibling $letter" -Encoding ASCII
            }
            # (Written out first: what is still in the cache when the
            # partition becomes write-protected never reaches it.)
            Write-VolumeCache -DriveLetter W; Write-VolumeCache -DriveLetter X
            Set-Content -LiteralPath "$root\protect.txt" -Value "select volume X`r`ngpt attributes=0x1000000000000000" -Encoding ASCII
            $protect = & diskpart.exe /s "$root\protect.txt" 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) { throw "diskpart could not write-protect X:`n$protect" }
        }
        $volume = Get-Volume -DriveLetter V
        $wanted = if ($native) { 'ReFS' } else { 'NTFS' }
        if ($volume.FileSystem -ne $wanted) { throw "format.com $($arguments -join ' ') left V: as '$($volume.FileSystem)':`n$format" }
        $ntfs = (& fsutil.exe fsinfo $(if ($native) { 'refsinfo' } else { 'ntfsinfo' }) V: 2>&1 | Out-String)
        $partition = Get-Partition -DriveLetter V
        [pscustomobject]@{ diskpart = $diskpart; format = $format; ntfsinfo = $ntfs; disk = $partition.DiskNumber; partition = $partition.PartitionNumber
            bytes = $partition.Size; offset = $partition.Offset; logical_sector = (Get-Disk -Number $partition.DiskNumber).LogicalSectorSize }
    }
    Set-Content -LiteralPath (Join-Path $records 'volume.log') -Value ($made.diskpart, $made.format, $made.ntfsinfo) -Encoding UTF8
    $field = { param($label) if ($made.ntfsinfo -match "(?m)^\s*$label\s*:\s*([0-9,]+)") { [int64]($Matches[1] -replace ',') } else { $null } }
    $verdict.source.observed = [ordered]@{ bytes_per_sector = & $field 'Bytes Per Sector'; bytes_per_cluster = & $field 'Bytes Per Cluster'
        bytes_per_file_record = & $field 'Bytes Per FileRecord Segment'; partition_bytes = $made.bytes; partition_offset = $made.offset; disk_logical_sector = $made.logical_sector }
    Say "source V: disk $($made.disk) partition $($made.partition), $($made.bytes) bytes; NTFS reports $($verdict.source.observed.bytes_per_sector)-byte sectors, $($verdict.source.observed.bytes_per_cluster)-byte clusters, $($verdict.source.observed.bytes_per_file_record)-byte file records"
    if (-not $NativeRefsControl -and $verdict.source.observed.bytes_per_cluster -ne $ClusterBytes) { throw "the volume has $($verdict.source.observed.bytes_per_cluster)-byte clusters, not the $ClusterBytes asked for" }

    $filled = Invoke-Command -Session $session -ArgumentList $Content, $ClusterBytes, $Islands -ScriptBlock {
        param($content, $cluster, $islands)
        $random = [Random]::new(20261112)
        $bytes = { param([int]$n) $b = New-Object byte[] $n; $random.NextBytes($b); , $b }
        if ($content -eq 'minimal') { [IO.File]::WriteAllBytes('V:\one.bin', (& $bytes 100000)); return 'one file' }
        if ($content -eq 'many') {
            # Counts past the numbers that used to be fixed: named streams on
            # one file (64), and separately allocated runs of one stream
            # (65,536), which a sparse file with that many islands has.
            [IO.File]::WriteAllBytes('V:\many-streams.bin', (& $bytes 5000))
            foreach ($n in 0..199) { Set-Content -LiteralPath 'V:\many-streams.bin' -Stream ('stream{0:d3}' -f $n) -Value ("stream $n " * (1 + $n % 7)) -Encoding ASCII }
            $null = New-Item -ItemType File -Path 'V:\many-islands.bin' -Force
            $null = & fsutil.exe sparse setflag 'V:\many-islands.bin'
            # One island in every second allocation granule of a sparse stream.
            $granule = if ($cluster -le 4096) { 16 * $cluster } else { [Math]::Max(65536, $cluster) }
            $one = & $bytes 512
            $file = [IO.File]::Open('V:\many-islands.bin', 'Open', 'Write'); $file.SetLength([long]$islands * 2 * $granule)
            for ($i = 0; $i -lt $islands; $i++) { $file.Position = [long]$i * 2 * $granule; $file.Write($one, 0, $one.Length) }
            $file.Dispose()
            return "a file with 200 named streams; a sparse file with $islands islands"
        }
        $made = New-Object System.Collections.Generic.List[string]
        # Files around every boundary that matters: resident, one cluster of
        # each side's size more or less a byte, several clusters, megabytes.
        $null = New-Item -ItemType Directory -Path 'V:\sizes' -Force
        # (The comma binds tighter than arithmetic: each sum is in brackets.)
        $sizes = @(0, 1, 600, 1500, 4095, 4096, 4097, 65535, 65536, 65537, 200001, 1048577, 5242883, ($cluster - 1), $cluster, ($cluster + 1), (3 * $cluster + 17)) | Sort-Object -Unique
        foreach ($size in $sizes) { [IO.File]::WriteAllBytes("V:\sizes\f$size.bin", (& $bytes $size)) }
        $made.Add("$($sizes.Count) files of boundary sizes")
        # A tree with nested and empty directories and names outside ASCII.
        foreach ($d in 0..3) {
            $dir = "V:\tree\d$d\inner\deeper"; $null = New-Item -ItemType Directory -Path $dir -Force
            foreach ($f in 0..4) { [IO.File]::WriteAllBytes("$dir\file$f.bin", (& $bytes (1 + $random.Next(1, 300000)))) }
            Set-Content -LiteralPath "V:\tree\d$d\note.txt" -Value ("note $d " * 40) -Encoding ASCII
        }
        $null = New-Item -ItemType Directory -Path 'V:\tree\empty directory' -Force
        $unicode = "V:\tree\" + [string][char]0x00DC + 'n' + [char]0x00EF + 'c' + [char]0x00F6 + 'd' + [char]0x00E9 + ' ' + [char]0x65E5 + [char]0x672C + [char]0x8A9E + ' ' + [char]0x0444 + [char]0x0430 + [char]0x0439 + [char]0x043B + '.txt'
        Set-Content -LiteralPath $unicode -Value 'names outside ASCII' -Encoding UTF8
        [IO.File]::WriteAllBytes(('V:\tree\' + ('long-name-' * 20) + '.bin'), (& $bytes 5000))
        $made.Add('a nested tree, an empty directory, a non-ASCII name, a 200-character name')
        # Named streams, small and large, on a file and beside an empty one.
        Set-Content -LiteralPath 'V:\tree\d0\note.txt' -Stream 'tag' -Value 'a named stream' -Encoding ASCII
        [IO.File]::WriteAllBytes('V:\streams.bin', (& $bytes 70000))
        # (.NET in Windows PowerShell 5.1 refuses a stream path; the provider takes it.)
        Set-Content -LiteralPath 'V:\streams.bin' -Stream 'large' -Value (& $bytes 300000) -Encoding Byte
        $null = New-Item -ItemType File -Path 'V:\empty.dat' -Force
        Set-Content -LiteralPath 'V:\empty.dat' -Stream 'only' -Value 'data only in a named stream' -Encoding ASCII
        $made.Add('named streams')
        # Hard links, in one directory and across two.
        [IO.File]::WriteAllBytes('V:\linked.bin', (& $bytes 150000))
        $null = & fsutil.exe hardlink create 'V:\linked-second-name.bin' 'V:\linked.bin'
        $null = & fsutil.exe hardlink create 'V:\tree\d1\linked-elsewhere.bin' 'V:\linked.bin'
        $made.Add('a file with three names')
        # A sparse file: two islands of data in 64 MiB.
        $null = New-Item -ItemType File -Path 'V:\sparse.bin' -Force
        $null = & fsutil.exe sparse setflag 'V:\sparse.bin'
        $sparse = [IO.File]::Open('V:\sparse.bin', 'Open', 'Write'); $sparse.SetLength(64MB)
        $island = & $bytes 1048576; $sparse.Write($island, 0, $island.Length); $sparse.Position = 32MB + 123; $sparse.Write($island, 0, 700000); $sparse.Dispose()
        $made.Add('a sparse file')
        # NTFS compresses only on clusters of 4 KiB and smaller.
        if ($cluster -le 4096) {
            $text = [Text.Encoding]::ASCII.GetBytes(('compressible text line ' * 30000))
            [IO.File]::WriteAllBytes('V:\compressed.txt', $text)
            $null = & compact.exe /c 'V:\compressed.txt'
            $null = New-Item -ItemType Directory -Path 'V:\compressed directory' -Force
            $null = & compact.exe /c 'V:\compressed directory'
            [IO.File]::WriteAllBytes('V:\compressed directory\inherits.txt', $text[0..199999])
            [IO.File]::WriteAllBytes('V:\compressed directory\random.bin', (& $bytes 250000))
            $made.Add('compressed files')
        }
        # Two files grown in turns, so that each is in many separate runs.
        $a = [IO.File]::Open('V:\fragmented-a.bin', 'Create'); $b = [IO.File]::Open('V:\fragmented-b.bin', 'Create')
        foreach ($turn in 0..59) { $chunk = & $bytes (3 * [Math]::Max($cluster, 4096) + 1); $a.Write($chunk, 0, $chunk.Length); $a.Flush($true); $b.Write($chunk, 0, $chunk.Length); $b.Flush($true) }
        $a.Dispose(); $b.Dispose()
        $made.Add('two interleaved, fragmented files')
        # Attributes and times that are not the defaults.
        foreach ($case in @(@('readonly.txt', 'ReadOnly'), @('hidden.txt', 'Hidden'), @('system.txt', 'System'), @('plain.txt', 'Normal'), @('hidden-system-readonly.txt', 'Hidden,System,ReadOnly'))) {
            Set-Content -LiteralPath "V:\tree\$($case[0])" -Value $case[1] -Encoding ASCII
            (Get-Item -LiteralPath "V:\tree\$($case[0])" -Force).Attributes = $case[1]
        }
        $old = Get-Item -LiteralPath 'V:\tree\d2\note.txt'
        $old.CreationTimeUtc = [DateTime]::new(2001, 2, 3, 4, 5, 6, [DateTimeKind]::Utc); $old.LastWriteTimeUtc = [DateTime]::new(2010, 11, 12, 13, 14, 15, [DateTimeKind]::Utc)
        (Get-Item -LiteralPath 'V:\tree\d3').CreationTimeUtc = [DateTime]::new(1999, 12, 31, 23, 59, 59, [DateTimeKind]::Utc)
        $made.Add('attributes and old times')
        $made -join '; '
    }
    Say "content: $filled"

    $wanted = @($Features | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
    if ($Content -eq 'lived-in') { $wanted = @(@('copy', 'objectids', 'security', 'ea', 'links', 'longpath', 'deep', 'bigdir', 'usn') + $wanted | Select-Object -Unique) }
    if ($wanted) {
        try {
            # (As a script block: the guest's execution policy does not run files.)
            $featureJson = Invoke-Command -Session $session -ArgumentList $guestRoot, $wanted, $DirectoryEntries, $BigFileGB, $FileCount -ScriptBlock {
                param($root, $features, $entries, $bigGB, $files)
                $block = [scriptblock]::Create((Get-Content -LiteralPath "$root\features.ps1" -Raw))
                & $block -Root 'V:\' -Features $features -DirectoryEntries $entries -BigFileGB $bigGB -FileCount $files
            }
        } catch { $verdict.outcome = 'feature-not-made'; throw "a feature could not be put on the volume: $($_.Exception.Message)" }
        $verdict.source.features = ($featureJson | Select-Object -Last 1) | ConvertFrom-Json
        Set-Content -LiteralPath (Join-Path $records 'features.json') -Value ($featureJson | Select-Object -Last 1) -Encoding UTF8
        Say "features: $($wanted -join ', ')"
    }
    if ($NativeRefsControl) {
        # Nothing to convert: the volume is ReFS as Windows made it.
        $use = Invoke-UseTest $guestRoot
        $verdict.outcome = if ($use.passed) { 'control-passed' } else { 'control-use-failed' }
        return
    }

    # A volume the bitlocker feature encrypted locks whenever it is mounted
    # again (the converter's freeze and return are such a remount, and so is
    # the one below); a volume in use is unlocked, so the lab unlocks it.
    $unlock = 'if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) { $b = Get-BitLockerVolume -MountPoint "V:" -ErrorAction SilentlyContinue; if ($b -and "$($b.LockStatus)" -eq "Locked") { $null = Unlock-BitLocker -MountPoint "V:" -Password (ConvertTo-SecureString "Lab-volume-password-2026" -AsPlainText -Force) } }'
    $listed = Invoke-Command -Session $session -ArgumentList $guestRoot, $unlock, ([bool]($wanted -contains 'links')) -ScriptBlock {
        param($root, $unlock, $junctions)
        $unlock = [scriptblock]::Create($unlock)
        # Windows writes its own files into "System Volume Information" when a
        # volume arrives: the search indexer's IndexerVolumeGuid and, on a
        # volume with junctions, the mount manager's database. A volume in use
        # has them already; one made a moment ago gets them when it next
        # mounts, which would be after it was converted, and the directory's
        # changed times would show as a difference. So the volume is mounted
        # afresh first (again every 20 s: a guest that has just started has
        # no indexer yet), and listed when those files are there and two
        # listings in a row find as many entries in that directory. A Windows
        # without the search service (Windows Server, unless the feature was
        # added) never writes the indexer's file, and is not waited for. What
        # every Windows writes is the storage service's WPSettings.dat, a
        # few seconds after the volume arrives: an attempt on Windows Server
        # that did not wait for it had it written under a check.
        $indexer = [bool](Get-Service -Name WSearch -ErrorAction SilentlyContinue | Where-Object { "$($_.StartType)" -ne 'Disabled' })
        $deadline = (Get-Date).AddSeconds(150); $settled = $false; $previous = -1
        $mountAfresh = { $number = (Get-Partition -DriveLetter V).DiskNumber; Set-Disk -Number $number -IsOffline $true; Set-Disk -Number $number -IsOffline $false }
        & $mountAfresh; $remount = (Get-Date).AddSeconds(20)
        do {
            Start-Sleep -Seconds 2
            & $unlock
            $text = & "$root\lab-volume-manifest.exe" capture --root 'V:\' --output "$root\manifest-before.jsonl" 2>&1
            if ($LASTEXITCODE -ne 0) { break }
            $own = @(Select-String -LiteralPath "$root\manifest-before.jsonl" -Pattern 'System Volume Information' -SimpleMatch)
            $has = { param($leaf) [bool]($own | Where-Object { $_.Line -like "*$leaf*" }) }
            $settled = (& $has 'WPSettings.dat') -and (-not $indexer -or (& $has 'IndexerVolumeGuid')) -and (-not $junctions -or (& $has 'MountPointManagerRemoteDatabase')) -and $own.Count -eq $previous
            $previous = $own.Count
            if (-not $settled -and (Get-Date) -ge $remount) { & $mountAfresh; $remount = (Get-Date).AddSeconds(20); $previous = -1 }
        } until ($settled -or (Get-Date) -gt $deadline)
        [pscustomobject]@{ exit = $LASTEXITCODE; text = ($text -join ' '); settled = $settled; indexer = $indexer }
    }
    if ($listed.exit -ne 0) { throw "listing before the run failed (exit $($listed.exit)): $($listed.text)" }
    Copy-Item -FromSession $session -LiteralPath "$guestRoot\manifest-before.jsonl" -Destination $records
    # The volumes beside the source, as they are before the run and after.
    # (Their listings are kept in the attempt's first folder: a recovery works in one of its own.)
    $siblingRoot = $guestRoot
    $observeSiblings = {
        param($root, $tag)
        if (-not ('SiblingRaw' -as [type])) {
            Add-Type -TypeDefinition @'
using System; using System.IO; using System.Runtime.InteropServices; using System.Security.Cryptography; using Microsoft.Win32.SafeHandles;
public static class SiblingRaw {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    public static string Sha256(string device, long offset, long bytes) {
        using (var handle = CreateFileW(device, 0x80000000, 7, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
            if (handle.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            using (var stream = new FileStream(handle, FileAccess.Read, 1 << 20))
            using (var sha = SHA256.Create()) {
                stream.Seek(offset, SeekOrigin.Begin);
                var buffer = new byte[1 << 20]; long left = bytes;
                while (left > 0) {
                    int read = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, left));
                    if (read <= 0) throw new IOException("short read of " + device + " with " + left + " bytes left");
                    sha.TransformBlock(buffer, 0, read, null, 0); left -= read;
                }
                sha.TransformFinalBlock(buffer, 0, 0);
                return BitConverter.ToString(sha.Hash).Replace("-", "").ToLowerInvariant();
            }
        }
    }
    public static void Fill(string device, long offset, int bytes, int seed) {
        using (var handle = CreateFileW(device, 0xC0000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
            if (handle.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            using (var stream = new FileStream(handle, FileAccess.ReadWrite, 1 << 20)) {
                var buffer = new byte[bytes]; new Random(seed).NextBytes(buffer);
                stream.Seek(offset, SeekOrigin.Begin); stream.Write(buffer, 0, bytes); stream.Flush();
            }
        }
    }
}
'@
        }
        # (Back under their letters a moment after the disk comes online.)
        $deadline = (Get-Date).AddSeconds(30)
        do { $w = Get-Volume -DriveLetter W -ErrorAction SilentlyContinue; $x = Get-Volume -DriveLetter X -ErrorAction SilentlyContinue; if (-not ($w -and $x)) { Start-Sleep -Milliseconds 500 } } until (($w -and $x) -or (Get-Date) -gt $deadline)
        # W: is an ordinary volume, and Windows writes its own files to it
        # when it arrives, as it does to the source: before the run it is
        # listed when they are there and two listings in a row agree.
        $indexer = [bool](Get-Service -Name WSearch -ErrorAction SilentlyContinue | Where-Object { "$($_.StartType)" -ne 'Disabled' })
        $listed = 'no W:'; $listedOk = $false; $settled = $tag -ne 'before'; $previous = -1; $deadline = (Get-Date).AddSeconds(90)
        if ($w) {
            do {
                $listed = & "$root\lab-volume-manifest.exe" capture --root 'W:\' --output "$root\sibling-a-$tag.jsonl" 2>&1 | Out-String
                $listedOk = $LASTEXITCODE -eq 0
                if (-not $listedOk -or $settled) { break }
                $own = @(Select-String -LiteralPath "$root\sibling-a-$tag.jsonl" -Pattern 'System Volume Information' -SimpleMatch)
                $has = { param($leaf) [bool]($own | Where-Object { $_.Line -like "*$leaf*" }) }
                $settled = (& $has 'WPSettings.dat') -and (-not $indexer -or (& $has 'IndexerVolumeGuid')) -and $own.Count -eq $previous
                $previous = $own.Count
                if (-not $settled) { Start-Sleep -Seconds 2 }
            } until ($settled -or (Get-Date) -gt $deadline)
        }
        # X: is write-protected in the partition table, the EFI system
        # partition has no letter, and the partition of another system has
        # no file system Windows knows: nothing writes to them, so their
        # bytes, read through the disk, stay as they are. (The last gets
        # content of its own first: a run of zeros would not show a part
        # that was zeroed.)
        $protected = $null
        if ($x) { try { [IO.File]::WriteAllText('X:\kept\written.txt', 'x'); $protected = $false; Remove-Item -LiteralPath 'X:\kept\written.txt' -Force } catch { $protected = $true } }
        $raw = [ordered]@{}; $rawErrors = @()
        $number = if ($w) { (Get-Partition -DriveLetter W).DiskNumber } elseif ($x) { (Get-Partition -DriveLetter X).DiskNumber } else { $null }
        if ($null -ne $number) {
            $device = "\\.\PhysicalDrive$number"
            $parts = @(Get-Partition -DiskNumber $number)
            $named = [ordered]@{
                efi = @($parts | Where-Object { "$($_.GptType)" -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' })
                x = @($parts | Where-Object { "$($_.DriveLetter)" -eq 'X' })
                other = @($parts | Where-Object { "$($_.GptType)" -eq '{0fc63daf-8483-4772-8e79-3d69d8477de4}' })
            }
            foreach ($name in $named.Keys) {
                $part = $named[$name]
                if ($part.Count -ne 1) { $rawErrors += "${name}: $($part.Count) such partition(s) on disk $number"; continue }
                try {
                    if ($name -eq 'other' -and $tag -eq 'before') { [SiblingRaw]::Fill($device, $part[0].Offset, 4MB, 11); [SiblingRaw]::Fill($device, $part[0].Offset + $part[0].Size - 1MB, 1MB, 12) }
                    $raw[$name] = [SiblingRaw]::Sha256($device, $part[0].Offset, $part[0].Size)
                } catch { $rawErrors += "${name}: $($_.Exception.Message)" }
            }
        } else { $rawErrors += 'neither W: nor X: is there to find the disk by' }
        [pscustomobject]@{ a = [bool]$w; a_filesystem = "$($w.FileSystem)"; a_health = "$($w.HealthStatus)"; a_listed = [bool]$listedOk; a_settled = [bool]$settled; a_listing = "$listed".Trim()
            b = [bool]$x; b_filesystem = "$($x.FileSystem)"; b_write_protected = $protected
            raw_sha256 = [pscustomobject]$raw; raw_errors = @($rawErrors)
            b_note = $(if (Test-Path -LiteralPath 'X:\kept\note.txt') { (Get-Content -LiteralPath 'X:\kept\note.txt' -Raw).Trim() } else { $null })
            a_note = $(if (Test-Path -LiteralPath 'W:\kept\note.txt') { (Get-Content -LiteralPath 'W:\kept\note.txt' -Raw).Trim() } else { $null }) }
    }
    # Whatever the run did, the volumes beside the source are what they
    # were, and are back under their letters.
    $holdSiblings = {
        param($saidOfThem)
        $siblingsAfter = Invoke-Command -Session $session -ArgumentList $siblingRoot, 'after' -ScriptBlock $observeSiblings
        $sameListing = $false; $listingSummary = ''
        if ($siblingsAfter.a_listed) {
            $compared = Invoke-Command -Session $session -ArgumentList $siblingRoot -ScriptBlock {
                param($root)
                $summary = & "$root\lab-volume-manifest.exe" compare --exact --before "$root\sibling-a-before.jsonl" --after "$root\sibling-a-after.jsonl" --report "$root\sibling-a-report.json" 2>&1
                [pscustomobject]@{ exit = $LASTEXITCODE; summary = ($summary -join ' ') }
            }
            $sameListing = $compared.exit -eq 0; $listingSummary = $compared.summary
        }
        if ($SiblingState -eq 'snapshot') {
            # A shadow copy of W: keeps its storage in files on W: that
            # nothing else can read: they are listed as unreadable, before
            # and after alike, and everything else has to be identical. The
            # shadow copy itself has to be there still.
            $kinds = try { ($listingSummary | ConvertFrom-Json).kinds } catch { $null }
            $names = @(if ($kinds) { $kinds.PSObject.Properties.Name })
            $onlyStorage = $kinds -and $names.Count -eq 2 -and ($names -contains 'unreadable before') -and ($names -contains 'unreadable afterwards') -and $kinds.'unreadable before' -eq $kinds.'unreadable afterwards'
            $shadows = Invoke-Command -Session $session -ScriptBlock { $w = (Get-Volume -DriveLetter W -ErrorAction SilentlyContinue).Path; @(Get-CimInstance Win32_ShadowCopy | Where-Object { $w -and $_.VolumeName -eq $w }).Count }
            $verdict.siblings.shadow_copies_after = $shadows
            if ($onlyStorage -and $shadows -ge 1) { $sameListing = $true; $listingSummary = "identical apart from the shadow copy's storage, which cannot be read; the shadow copy is still there: $listingSummary" }
        }
        foreach ($leaf in 'sibling-a-before.jsonl', 'sibling-a-after.jsonl', 'sibling-a-report.json') { try { Copy-Item -FromSession $session -LiteralPath "$siblingRoot\$leaf" -Destination $records } catch { } }
        # (A partition that could not be read, on a disk that is still offline, has no hash.)
        $shaOf = { param($state, $name) $entry = $state.raw_sha256.PSObject.Properties[$name]; if ($entry) { $entry.Value } }
        $differing = @('efi', 'x', 'other' | Where-Object { $now = & $shaOf $siblingsAfter $_; -not $now -or $now -ne (& $shaOf $verdict.siblings.before $_) })
        $verdict.siblings.after = $siblingsAfter
        $verdict.siblings.a_listing_identical = $sameListing
        $verdict.siblings.a_listing_summary = $listingSummary
        $verdict.siblings.raw_bytes_identical = $differing.Count -eq 0
        $verdict.siblings.raw_bytes_differ = $differing
        $verdict.siblings.said = $saidOfThem
        $siblingsKept = $sameListing -and $differing.Count -eq 0 -and $siblingsAfter.a_filesystem -eq 'NTFS' -and $siblingsAfter.b_filesystem -eq 'NTFS' -and $siblingsAfter.a_note -eq 'sibling W' -and $siblingsAfter.b_note -eq 'sibling X' -and $siblingsAfter.b_write_protected
        $verdict.siblings.kept = [bool]$siblingsKept
        Say "siblings after the run: W: $(if ($siblingsAfter.a) { "$($siblingsAfter.a_filesystem), listing $(if ($sameListing) { 'identical' } else { "DIFFERS: $listingSummary" })" } else { 'NOT BACK' }); X: $(if ($siblingsAfter.b) { "$($siblingsAfter.b_filesystem)" } else { 'NOT BACK' }); bytes of the EFI system partition, X: and the other system's partition: $(if ($differing.Count -eq 0) { 'identical' } else { "DIFFER in $($differing -join ', ') $($siblingsAfter.raw_errors -join '; ')" })"
        if ($saidOfThem) { Say "the converter said: $saidOfThem" }
        if (-not $siblingsKept) { $verdict.outcome = "$($verdict.outcome)-but-siblings-changed" }
    }
    if ($Siblings) {
        if ($SiblingState) {
            $made = Invoke-Command -Session $session -ArgumentList $siblingRoot, $SiblingState -ScriptBlock {
                param($root, $state)
                switch ($state) {
                    'busy' {
                        # A program that keeps a file on W: open, as an editor or a player does.
                        $holder = Start-Process -FilePath powershell.exe -WindowStyle Hidden -PassThru -ArgumentList '-NoProfile', '-Command', "`$f = [IO.File]::Open('W:\kept\a.bin', 'Open', 'Read', 'ReadWrite'); Start-Sleep -Seconds 3600"
                        Set-Content -LiteralPath "$root\sibling-holder.txt" -Value $holder.Id -Encoding ASCII
                        Start-Sleep -Seconds 4
                        if ($holder.HasExited) { throw 'the process that was to hold W:\kept\a.bin open has ended' }
                        "process $($holder.Id) holds W:\kept\a.bin open"
                    }
                    'snapshot' {
                        $result = ([wmiclass]'Win32_ShadowCopy').Create('W:\', 'ClientAccessible')
                        if ($result.ReturnValue -ne 0) { throw "Win32_ShadowCopy.Create for W: returned $($result.ReturnValue)" }
                        "a shadow copy of W: ($($result.ShadowID))"
                    }
                    'dump' {
                        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
                        $was = (Get-Item -LiteralPath $key).GetValue('DumpFile', '', 'DoNotExpandEnvironmentNames')
                        Set-Content -LiteralPath "$root\sibling-dumpfile.txt" -Value "$was" -Encoding ASCII
                        Set-ItemProperty -LiteralPath $key -Name DumpFile -Value 'W:\MEMORY.DMP' -Type ExpandString
                        "the crash dump file is W:\MEMORY.DMP (it was '$was')"
                    }
                }
            }
            $verdict.sibling_state = [ordered]@{ kind = $SiblingState; made = "$made" }
            Say "sibling state '$SiblingState': $made"
        }
        $siblingsBefore = Invoke-Command -Session $session -ArgumentList $siblingRoot, 'before' -ScriptBlock $observeSiblings
        if (-not ($siblingsBefore.a_listed -and $siblingsBefore.a_settled -and $siblingsBefore.b_write_protected -and $siblingsBefore.a_note -eq 'sibling W' -and $siblingsBefore.b_note -eq 'sibling X' -and $siblingsBefore.raw_sha256.efi -and $siblingsBefore.raw_sha256.x -and $siblingsBefore.raw_sha256.other)) {
            $verdict.outcome = 'siblings-not-made'; throw "the volumes beside the source could not be recorded: $($siblingsBefore | ConvertTo-Json -Compress -Depth 4)"
        }
        $verdict.siblings = [ordered]@{ before = $siblingsBefore }
        Say "siblings before the run: W: $($siblingsBefore.a_filesystem), listed; X: $($siblingsBefore.b_filesystem), write-protected; SHA-256 of the EFI system partition $($siblingsBefore.raw_sha256.efi.Substring(0, 12)), of X: $($siblingsBefore.raw_sha256.x.Substring(0, 12)), of the other system's partition $($siblingsBefore.raw_sha256.other.Substring(0, 12))"
    }
    $verdict.source.windows_files_settled = $listed.settled; $verdict.source.search_indexer = $listed.indexer
    Say "listing before the run: $($listed.text)$(if (-not $listed.settled) { ' (Windows had not written its own files to the volume within 150 s)' })$(if (-not $listed.indexer) { ' (this Windows has no search indexer)' })"

    # Starts the guest worker (the one the boot harness uses) in a guest
    # folder with these converter arguments: as SYSTEM from a scheduled task,
    # or as the elevated administrator in a session of its own.
    function Start-Worker([string]$Root, [string[]]$Arguments, [string]$Task) {
        Invoke-Command -Session $session -ArgumentList $Root, ($Arguments -join "`t"), (-not $Unattended) -ScriptBlock {
            param($root, $joined, $answer) [IO.File]::WriteAllText("$root\run.json", (@{ arguments = @([string[]]$joined.Split("`t")); answer = [bool]$answer } | ConvertTo-Json), [Text.UTF8Encoding]::new($false)) }
        if ($RunAs -eq 'administrator') {
            if ($script:worker) { Remove-PSSession $script:worker -ErrorAction SilentlyContinue }
            $script:worker = New-PSSession -VMId $VmId -Credential $credential
            $null = Invoke-Command -Session $script:worker -ArgumentList $Root -AsJob -ScriptBlock {
                param($root) $null = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$root\worker.ps1" -Root $root 2>&1 }
        } else {
            Invoke-Command -Session $session -ArgumentList $Root, $Task -ScriptBlock {
                param($root, $task)
                Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
                $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File $root\worker.ps1 -Root $root"
                $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
                $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
                $null = Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings
                Start-ScheduledTask -TaskName $task
            }
        }
    }
    # Waits for the worker to end. With a hold point, the converter is ended
    # once it reports that it is held there; with a phase of preparation, as
    # soon as its progress names that phase. Answers whether the worker ended,
    # whether the hold was reached and whether it was stopped in the phase.
    # What the converter took, at its largest over the attempt: sampled each
    # time the wait below looks whether it has ended.
    $usage = @{ peak_working_set = 0L; private_bytes = 0L; working_bytes = 0L; samples = 0 }
    function Wait-Worker([string]$Root, [string]$HoldAt, [string]$StopInPhase) {
        $deadline = (Get-Date).AddMinutes($TimeoutMinutes); $held = $false; $stopped = $false
        do {
            if (-not $StopInPhase -or $stopped) { Start-Sleep -Seconds 2 }
            $state = Invoke-Command -Session $session -ArgumentList $Root, ([bool]$HoldAt -and -not $held), $(if ($stopped) { '' } else { $StopInPhase }) -ScriptBlock {
                param($root, $watchHold, $phase)
                $ended = (Test-Path "$root\native-terminal.json") -or (Test-Path "$root\worker-error.txt")
                $atHold = $false; $inPhase = $false
                if ($phase -and -not $ended) {
                    # Looked for ten times a second, so that the stop lands in the phase and not after it.
                    $until = (Get-Date).AddSeconds(2)
                    do {
                        if ((Test-Path "$root\stdout.log") -and (Select-String -LiteralPath "$root\stdout.log" -SimpleMatch -Pattern "`"phase`":`"$phase`"" -Quiet)) {
                            Get-Process -Name ntfs2refs -ErrorAction SilentlyContinue | Stop-Process -Force
                            $inPhase = $true; break
                        }
                        Start-Sleep -Milliseconds 100
                        $ended = (Test-Path "$root\native-terminal.json") -or (Test-Path "$root\worker-error.txt")
                    } until ($ended -or (Get-Date) -ge $until)
                }
                if ($watchHold -and -not $ended -and (Test-Path "$root\stdout.log")) {
                    $atHold = [bool](Select-String -LiteralPath "$root\stdout.log" -SimpleMatch -Pattern '"kind":"lab-hold-v1"' -Quiet)
                    # The lab ends a process; it cannot cut power to the storage.
                    if ($atHold) { Get-Process -Name ntfs2refs -ErrorAction SilentlyContinue | Stop-Process -Force }
                }
                # A sample that cannot be taken is left out: the process may end, and
                # the working files come and go, between the look and the reading.
                $sample = { param($take) try { [long](& $take) } catch { 0L } }
                $running = @(Get-Process -Name ntfs2refs -ErrorAction SilentlyContinue)
                [pscustomobject]@{ ended = $ended; at_hold = $atHold; in_phase = $inPhase
                    peak_working_set = & $sample { ($running | Measure-Object PeakWorkingSet64 -Maximum).Maximum }
                    private_bytes = & $sample { ($running | Measure-Object PrivateMemorySize64 -Maximum).Maximum }
                    working_bytes = & $sample { (Get-ChildItem -LiteralPath $(if (Test-Path -LiteralPath 'M:\runs') { 'M:\runs' } else { 'S:\datalab\runs' }) -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum } }
            }
            foreach ($measure in 'peak_working_set', 'private_bytes', 'working_bytes') { if ($state.$measure -gt $usage[$measure]) { $usage[$measure] = $state.$measure } }
            $usage.samples++
            if ($state.at_hold) { $held = $true; Say "the converter reported its hold at '$HoldAt' and was ended" }
            if ($state.in_phase) { $stopped = $true; Say "the converter reported the phase '$StopInPhase' and was ended" }
        } until ($state.ended -or (Get-Date) -gt $deadline)
        [pscustomobject]@{ ended = [bool]$state.ended; held = $held; stopped = $stopped }
    }
    if ($VssProvider) {
        $provider = Invoke-Command -Session $session -ArgumentList $guestRoot, $VssProvider -ScriptBlock {
            param($root, $kind)
            if ($kind -eq 'silent') {
                $name = 'N2R Lab Silent Provider'
                $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\VSS\Providers\{4e325253-494c-454e-5450-524f56494452}'
                # Noted first: whatever happens next, the attempt's end removes it.
                Set-Content -LiteralPath "$root\vss-provider.txt" -Value "key $key" -Encoding ASCII
                $null = New-Item -Path $key -Force; Set-Item -Path $key -Value $name
                Set-ItemProperty -Path $key -Name Type -Value 2 -Type DWord
                Set-ItemProperty -Path $key -Name Version -Value '1.0' -Type String
                Set-ItemProperty -Path $key -Name VersionId -Value '{4e325253-494c-454e-5450-524f56494453}' -Type String
                $null = New-Item -Path "$key\CLSID" -Force; Set-Item -Path "$key\CLSID" -Value '{4e325253-494c-454e-5450-524f56494454}'
            } else {
                $name = 'Microsoft iSCSI Target VSS Hardware Provider'
                if (-not (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) { throw "-VssProvider answering installs a Windows Server feature, and this is $((Get-CimInstance Win32_OperatingSystem).Caption)" }
                if ((Get-WindowsFeature -Name iSCSITarget-VSS-VDS).InstallState -ne 'Installed') {
                    $installed = Install-WindowsFeature -Name iSCSITarget-VSS-VDS
                    if (-not $installed.Success -or "$($installed.RestartNeeded)" -ne 'No') { throw "the feature iSCSITarget-VSS-VDS wants a restart before it can be used ($($installed.ExitCode)): restart the VM and run the case again" }
                }
            }
            # The shadow-copy service reads its providers when it starts.
            Stop-Service -Name VSS -Force -ErrorAction SilentlyContinue
            $listed = @(& vssadmin.exe list providers 2>&1 | Where-Object { "$_" -like "*'$name'*" }).Count
            [pscustomobject]@{ name = $name; listed = [bool]$listed }
        }
        $verdict.vss_provider = [ordered]@{ kind = $VssProvider; name = $provider.name }
        if (-not $provider.listed) { $verdict.outcome = 'provider-not-made'; throw "Windows does not list the shadow-copy provider '$($provider.name)'" }
        Say "shadow-copy provider for this attempt, one the converter does not know: '$($provider.name)' ($VssProvider)"
    }
    $arguments = @('--drive', 'V', '--scratch-directory', $working)
    if ($TargetFormat -ne 'default') { $arguments += @('--target-format', $TargetFormat) }
    if ($TargetClusterBytes) { $arguments += @('--target-cluster-bytes', "$TargetClusterBytes") }
    if ($InterruptAt) { $arguments += @('--lab-hold-at', $InterruptAt, '--acknowledge-lab-hold-never-completes') }
    if ($SampleStacks) { $arguments += @('--sample-stacks', "$guestRoot\stacks.txt") }
    if ($Diagnose) { $arguments += '--diagnose' }
    if ($CompareListing) { $arguments += '--compare-listing' }
    if ($DropShortNames) { $arguments += @('--short-names', 'drop') }
    # What --list says of the volume, as an elevated user sees it: whether a
    # conversion would take it, its serial number, and BitLocker.
    $listed = Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock {
        param($root)
        $text = @(& "$root\ntfs2refs.exe" --list 2>&1 | ForEach-Object { "$_" })
        [IO.File]::WriteAllLines("$root\list.txt", [string[]]$text, [Text.UTF8Encoding]::new($false))
        $row = [string]($text | Where-Object { $_ -match '\sV:\\' } | Select-Object -First 1)
        [pscustomobject]@{ exit = $LASTEXITCODE; row = $row.Trim(); serial = if ($row -match 'serial ([0-9A-F]{4}-[0-9A-F]{4})') { $Matches[1] } else { $null } }
    }
    try { Copy-Item -FromSession $session -LiteralPath "$guestRoot\list.txt" -Destination $records } catch { }
    $verdict.list = [ordered]@{ exit = $listed.exit; row = $listed.row; serial = $listed.serial }
    Say "--list: $($listed.row)"
    if ($FreshFile) {
        if (-not ($Check -or $CheckOnly)) { throw '-FreshFile is a file made just before a check: with -Check or -CheckOnly' }
        $fresh = Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock {
            param($root)
            [IO.File]::WriteAllText('V:\a file made a moment before the check.txt', 'fresh')
            $text = & "$root\lab-volume-manifest.exe" capture --root 'V:\' --output "$root\manifest-before.jsonl" 2>&1
            [pscustomobject]@{ exit = $LASTEXITCODE; text = ($text -join ' ') }
        }
        if ($fresh.exit -ne 0) { throw "listing the volume with its fresh file failed (exit $($fresh.exit)): $($fresh.text)" }
        Copy-Item -FromSession $session -LiteralPath "$guestRoot\manifest-before.jsonl" -Destination $records -Force
        $verdict.source.fresh_file = 'V:\a file made a moment before the check.txt'
        Say "a file was created on the volume a moment before the check; listing with it: $($fresh.text)"
    }
    if ($DeletedWhileOpen) {
        if (-not ($Check -or $CheckOnly)) { throw '-DeletedWhileOpen is a file held open during a check: with -Check or -CheckOnly' }
        $holding = Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock {
            param($root)
            # A process of its own holds the handle: it outlives this call and
            # ends when it is told to, or by itself after three minutes.
            $holder = @"
`$path = 'V:\deleted while a program has it open.bin'
[IO.File]::WriteAllBytes(`$path, (New-Object byte[] 8192))
`$handle = [IO.File]::Open(`$path, 'Open', 'Read', 'ReadWrite, Delete')
[IO.File]::Delete(`$path)
Set-Content -LiteralPath '$root\deleted-held.txt' -Value `$PID
`$until = (Get-Date).AddMinutes(3)
while (-not (Test-Path -LiteralPath '$root\deleted-release.txt') -and (Get-Date) -lt `$until) { Start-Sleep -Milliseconds 200 }
`$handle.Dispose()
"@
            Set-Content -LiteralPath "$root\deleted-holder.ps1" -Value $holder -Encoding UTF8
            $null = Start-Process -FilePath powershell.exe -WindowStyle Hidden -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "$root\deleted-holder.ps1"
            foreach ($try in 1..100) { if (Test-Path -LiteralPath "$root\deleted-held.txt") { break }; Start-Sleep -Milliseconds 100 }
            $held = Test-Path -LiteralPath "$root\deleted-held.txt"
            $text = & "$root\lab-volume-manifest.exe" capture --root 'V:\' --output "$root\manifest-before.jsonl" 2>&1
            [pscustomobject]@{ held = $held; exit = $LASTEXITCODE; text = ($text -join ' '); named = (Test-Path -LiteralPath 'V:\deleted while a program has it open.bin') }
        }
        if (-not $holding.held -or $holding.named) { $verdict.outcome = 'deleted-file-not-held'; throw "no program holds a deleted file open on the volume (held: $($holding.held), still under its name: $($holding.named))" }
        if ($holding.exit -ne 0) { throw "listing the volume failed (exit $($holding.exit)): $($holding.text)" }
        Copy-Item -FromSession $session -LiteralPath "$guestRoot\manifest-before.jsonl" -Destination $records -Force
        Say "a program holds a file open that it has deleted; listing without it: $($holding.text)"
    }
    if ($Check -or $CheckOnly) {
        $checkArguments = @('--drive', 'V', '--scratch-directory', $working, '--check')
        if ($TargetFormat -ne 'default') { $checkArguments += @('--target-format', $TargetFormat) }
        if ($TargetClusterBytes) { $checkArguments += @('--target-cluster-bytes', "$TargetClusterBytes") }
        if ($DropShortNames) { $checkArguments += @('--short-names', 'drop') }
        $checked = Invoke-Command -Session $session -ArgumentList $guestRoot, $checkArguments, ([bool]$WriteLoad) -ScriptBlock {
            param($root, $arguments, $load)
            $writer = $null
            if ($load) {
                $writer = Start-Job -ScriptBlock {
                    $i = 0
                    while ($true) {
                        $i++
                        [IO.File]::WriteAllBytes("V:\load-$($i % 300).bin", (New-Object byte[] (4096 * (1 + $i % 60))))
                        if ($i % 5 -eq 0) { Remove-Item "V:\load-$(($i * 7) % 300).bin" -Force -ErrorAction SilentlyContinue }
                    }
                }
                Start-Sleep -Seconds 3
            }
            $clock = [Diagnostics.Stopwatch]::StartNew()
            $text = @(& "$root\ntfs2refs.exe" @arguments 2>&1 | ForEach-Object { "$_" })
            $exit = $LASTEXITCODE
            $seconds = [Math]::Round($clock.Elapsed.TotalSeconds, 1)
            if ($writer) { Stop-Job $writer; Remove-Job $writer -Force; Remove-Item 'V:\load-*.bin' -Force -ErrorAction SilentlyContinue }
            [IO.File]::WriteAllLines("$root\check.txt", [string[]]$text, [Text.UTF8Encoding]::new($false))
            $left = @(Get-ChildItem $(if (Test-Path -LiteralPath 'M:\runs') { 'M:\runs' } else { 'S:\datalab\runs' }) -Directory -Filter 'check-*' -ErrorAction SilentlyContinue).Count
            $partition = Get-Partition -DriveLetter V; $disk = Get-Disk -Number $partition.DiskNumber
            [pscustomobject]@{ exit = $exit; seconds = $seconds; text = $text; left = $left
                bytes = $partition.Size; offline = [bool]$disk.IsOffline; read_only = [bool]$disk.IsReadOnly; filesystem = (Get-Volume -DriveLetter V).FileSystem }
        }
        try { Copy-Item -FromSession $session -LiteralPath "$guestRoot\check.txt" -Destination $records } catch { }
        $checkRefusals = @($checked.text | Where-Object { $_ -match '^\s+\d+\.\s' -or $_ -match '^A conversion would refuse this volume: ' } | ForEach-Object { ($_ -replace '^\s+\d+\.\s+', '') -replace '^A conversion would refuse this volume: ', '' })
        $verdict.check = [ordered]@{ exit = $checked.exit; seconds = $checked.seconds; refusals = $checkRefusals
            takes = @($checked.text | Where-Object { $_ -match '^  \S' -and $_ -notmatch '^\s+\d+\.\s' })
            working_directories_left = $checked.left; write_load = [bool]$WriteLoad
            source_as_before = ($checked.bytes -eq $verdict.source.observed.partition_bytes -and -not $checked.offline -and -not $checked.read_only -and $checked.filesystem -eq 'NTFS') }
        Say "check: exit $($checked.exit) after $($checked.seconds) s; $($checkRefusals.Count) refusal(s)$(if ($checked.left) { "; $($checked.left) working director(ies) left behind" })"
        foreach ($refusal in $checkRefusals) { Say ("check refusal: " + $refusal.Substring(0, [Math]::Min(400, $refusal.Length))) }
        foreach ($line in $verdict.check.takes) { Say "check: $($line.Trim())" }
        if ($checked.exit -notin 0, 3, 5) { $verdict.outcome = 'check-failed'; throw "the check ended with exit $($checked.exit): $(($checked.text | Select-Object -Last 3) -join ' / ')" }
        if ($FreshFile) {
            # The check's count of short names against Windows' own: the
            # listing made a moment before it, which has the fresh file.
            $counted = @($checkRefusals | ForEach-Object { if ($_ -match '^(\d+) file\(s\) and directories on this volume have an 8\.3 short name') { [int]$Matches[1] } })
            $listedShort = @(Get-Content -LiteralPath (Join-Path $records 'manifest-before.jsonl') -Encoding UTF8 | Where-Object { $_ -match '"short_name":"' }).Count
            if ($counted.Count -ne 1) { $verdict.outcome = 'fresh-file-not-countable'; throw '-FreshFile needs a volume whose refusal counts its short names (-Features shortnames)' }
            $verdict.check.short_names_counted = $counted[0]; $verdict.check.short_names_listed = $listedShort
            Say "check counted $($counted[0]) short name(s); Windows lists $listedShort"
            if ($counted[0] -ne $listedShort) { $verdict.outcome = 'check-missed-what-was-just-written'; throw "the check counted $($counted[0]) short names where Windows lists $($listedShort): it did not read what was written a moment before" }
        }
        if ($DeletedWhileOpen) {
            # The handle is closed now: a run could not lock the volume otherwise.
            $closed = Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock {
                param($root)
                $id = [int]"$(Get-Content -LiteralPath "$root\deleted-held.txt" -Raw)".Trim()
                Set-Content -LiteralPath "$root\deleted-release.txt" -Value 'release'
                foreach ($try in 1..100) { if (-not (Get-Process -Id $id -ErrorAction SilentlyContinue)) { break }; Start-Sleep -Milliseconds 100 }
                -not (Get-Process -Id $id -ErrorAction SilentlyContinue)
            }
            $said = [bool]($checked.text | Where-Object { $_ -match '^Note: 1 file\(s\) or directories were deleted while a program still had them open' } | Select-Object -First 1)
            $verdict.check.deleted_while_open = [ordered]@{ said = $said; refusals = $checkRefusals.Count; handle_closed = [bool]$closed }
            Say "the file deleted while open: the check said so: $said; it refused for $($checkRefusals.Count) reason(s); the handle is closed: $closed"
            if (-not $said -or $checkRefusals.Count) { $verdict.outcome = 'check-refused-a-file-deleted-while-open'; throw "the check $(if ($checkRefusals.Count) { "refused the volume: $($checkRefusals -join ' | ')" } else { 'did not say that a file was deleted while open' })" }
            if (-not $closed) { $verdict.outcome = 'deleted-file-still-held'; throw 'the program holding the deleted file did not end' }
        }
        if ($checked.left) { $verdict.outcome = 'check-left-working-files'; throw 'the check left a working directory behind' }
        if ($CheckOnly) {
            $after = Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock {
                param($root)
                $listed = & "$root\lab-volume-manifest.exe" capture --root 'V:\' --output "$root\manifest-after.jsonl" 2>&1
                if ($LASTEXITCODE -ne 0) { return [pscustomobject]@{ identical = $false; summary = "listing failed ($LASTEXITCODE): $($listed -join ' ')" } }
                $summary = & "$root\lab-volume-manifest.exe" compare --exact --before "$root\manifest-before.jsonl" --after "$root\manifest-after.jsonl" --report "$root\manifest-report.json" 2>&1
                [pscustomobject]@{ identical = ($LASTEXITCODE -eq 0); summary = ($summary -join ' ') }
            }
            foreach ($leaf in 'manifest-after.jsonl', 'manifest-report.json') { try { Copy-Item -FromSession $session -LiteralPath "$guestRoot\$leaf" -Destination $records } catch { } }
            $verdict.manifest = [ordered]@{ result = $(if ($after.identical) { 'identical' } else { 'differs' }); exact = $true; summary = $after.summary }
            Say "before/after comparison, exact: $($verdict.manifest.result): $($after.summary)"
            $verdict.outcome = if (-not $verdict.check.source_as_before -or (-not $WriteLoad -and -not $after.identical)) { 'check-changed-the-source' }
                elseif ($checked.exit -eq 0) { 'check-clean' }
                elseif ($checked.exit -eq 5) { 'check-inconclusive' }
                elseif ($ExpectRefusal -and ($checkRefusals -join "`n") -match $ExpectRefusal) { 'check-refused-as-expected' }
                else { 'check-found-refusals' }
            if ($VssProvider -eq 'answering') {
                # The provider is passed over, and the check says so by its name.
                $named = '^Note: A shadow-copy \(VSS\) provider .*' + [regex]::Escape("`"$($verdict.vss_provider.name)`"") + '.*full backup'
                $verdict.vss_provider.note_in_check = [bool]($checked.text | Where-Object { $_ -match $named } | Select-Object -First 1)
                Say "provider note: in the check's output $($verdict.vss_provider.note_in_check)"
                if ($verdict.outcome -eq 'check-clean' -and -not $verdict.vss_provider.note_in_check) { $verdict.outcome = 'check-clean-without-the-provider-note' }
            }
            if ($Siblings) { & $holdSiblings ([string]($checked.text | Where-Object { $_ -match '^This volume shares disk ' } | Select-Object -Last 1)) }
            return
        }
        if (-not $verdict.check.source_as_before) { $verdict.outcome = 'check-changed-the-source'; throw 'the check left the volume other than it found it' }
    }
    if ('bitlocker' -in $wanted -and $listed.row -notmatch 'encrypted with BitLocker') {
        $verdict.outcome = 'list-did-not-show-bitlocker'; throw "--list does not say that V: is encrypted with BitLocker: $($listed.row)"
    }
    if ($Unattended) {
        if (-not $listed.serial) { $verdict.outcome = 'list-did-not-show-serial'; throw "--list shows no serial number for V:: $($listed.row)" }
        $arguments += @('--yes', '--volume-serial', $(if ($WrongSerial) { '0000-0000' } else { $listed.serial }))
    }
    $arguments += $ConverterArgs
    $verdict.converter_arguments = $arguments
    $task = "N2R-DataLab-$Name"
    Start-Worker $guestRoot $arguments $task
    Say "converter started: ntfs2refs $($arguments -join ' ')"
    $waited = Wait-Worker $guestRoot $InterruptAt $StopDuringPreparation
    $verdict.resources = [ordered]@{ peak_working_set_bytes = $usage.peak_working_set; peak_private_bytes = $usage.private_bytes
        peak_working_storage_bytes = $usage.working_bytes; samples = $usage.samples; sampled_every_seconds = 2 }
    # What the run's own memory ledger reached, which is what refuses a volume for memory.
    $ledger = Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock { param($root) if (Test-Path "$root\stderr.log") { [string](Get-Content -LiteralPath "$root\stderr.log" -Encoding UTF8 | Where-Object { $_ -match '^memory: the run''s reservations peaked at' } | Select-Object -Last 1) } }
    if ("$ledger" -match 'peaked at (\d+) MiB of the (\d+) MiB') { $verdict.resources.reserved_peak_mib = [int]$Matches[1]; $verdict.resources.reserved_limit_mib = [int]$Matches[2]; Say "its reservations peaked at $($Matches[1]) MiB of the $($Matches[2]) MiB it may hold" }
    # What the volume itself took of that: without the caches and the batches' spare memory.
    if ("$ledger" -match 'could not do without peaked at (\d+) MiB') { $verdict.resources.needed_peak_mib = [int]$Matches[1]; Say "of which it could not do without $($Matches[1]) MiB" }
    Say "the converter took at most $([Math]::Round($usage.peak_working_set / 1MB)) MiB of memory and $([Math]::Round($usage.working_bytes / 1MB)) MiB of working storage ($($usage.samples) samples)"
    $ended = $waited.ended
    if ($StopDuringPreparation) {
        # The converter was ended while it prepared: it had not printed a
        # recovery command and had not written to the volume. What is the
        # volume now, and does what the run offers for this case work?
        foreach ($leaf in 'stdout.log', 'stderr.log') {
            try { Copy-Item -FromSession $session -LiteralPath "$guestRoot\$leaf" -Destination (Join-Path $records "interrupted-$leaf") } catch { }
        }
        if (-not $waited.stopped) { $verdict.outcome = 'preparation-phase-not-reached'; throw "the converter ended without reporting the phase '$StopDuringPreparation'" }
        $shown = Join-Path $records 'interrupted-stdout.log'
        if (Select-String -LiteralPath $shown -Pattern '^To recover: ' -Quiet) {
            $verdict.outcome = 'stopped-after-preparation'; throw "the converter had printed its recovery command before it was ended in '$StopDuringPreparation': not a stop during preparation"
        }
        $left = Invoke-Command -Session $session -ScriptBlock {
            [pscustomobject]@{ mounted = [bool](Get-Partition -DriveLetter V -ErrorAction SilentlyContinue)
                offline = @(Get-Disk | Where-Object IsOffline | ForEach-Object Number); read_only = @(Get-Disk | Where-Object IsReadOnly | ForEach-Object Number) } }
        $verdict.stopped_in_phase = $StopDuringPreparation; $verdict.after_stop = $AfterStop
        $verdict.left_by_the_stop = [ordered]@{ v_mounted = [bool]$left.mounted; offline_disks = @($left.offline); read_only_disks = @($left.read_only) }
        Say "the stop left V: $(if ($left.mounted) { 'mounted' } else { 'not mounted' }); offline disks: $(@($left.offline) -join ', '); read-only disks: $(@($left.read_only) -join ', ')"
        # The command the run printed for this case, exactly as it printed it.
        $printed = Select-String -LiteralPath $shown -Pattern 'To get it back as NTFS: ntfs2refs --recover "(.+)" --recovery-sha256 ([0-9a-f]{64}) --rollback' | Select-Object -First 1
        if (-not $printed) { $verdict.outcome = 'stopped-without-cancel-command'; throw 'the stopped run had not printed the command that cancels its preparation' }
        $cancel = @('--recover', $printed.Matches[0].Groups[1].Value, '--recovery-sha256', $printed.Matches[0].Groups[2].Value, '--rollback')
        if ($Unattended) { $cancel += '--yes' }
        $verdict.cancel_arguments = $cancel
        $stoppedRoot = $guestRoot
        $stage = {
            param($leaf)
            $root = "$stoppedRoot\$leaf"
            Invoke-Command -Session $session -ArgumentList $root, $stoppedRoot -ScriptBlock {
                param($root, $from)
                $null = New-Item -ItemType Directory -Path $root -Force
                foreach ($file in 'ntfs2refs.exe', 'lab-volume-manifest.exe', 'worker.ps1', 'manifest-before.jsonl') { Copy-Item -LiteralPath (Join-Path $from $file) -Destination $root }
            }
            $root
        }
        if ($AfterStop -eq 'restart') {
            # Someone who did not see the run stop starts it again.
            $restartRoot = & $stage 'restart'
            Start-Worker $restartRoot $arguments $task
            Say "started again: ntfs2refs $($arguments -join ' ')"
            $null = Wait-Worker $restartRoot '' ''
            $again = Invoke-Command -Session $session -ArgumentList $restartRoot -ScriptBlock {
                param($root)
                $terminal = if (Test-Path "$root\native-terminal.json") { Get-Content "$root\native-terminal.json" -Raw | ConvertFrom-Json } else { $null }
                $said = if (Test-Path "$root\stderr.log") { [string](Get-Content -LiteralPath "$root\stderr.log" -Encoding UTF8 | Where-Object { $_ -match '^error:' } | Select-Object -Last 1) } else { '' }
                [pscustomobject]@{ exit = if ($terminal) { [int]$terminal.native_exit } else { $null }; error = $said }
            }
            foreach ($leaf in 'stdout.log', 'stderr.log') {
                try { Copy-Item -FromSession $session -LiteralPath "$restartRoot\$leaf" -Destination (Join-Path $records "restart-$leaf") } catch { }
            }
            # The refusal has to lead to the command above: it names the offline disk and --recover.
            $verdict.restart = [ordered]@{ exit = $again.exit; error = $again.error
                names_the_way_back = ($again.exit -ne 0 -and $again.error -match 'offline' -and $again.error -match '--recover') }
            Say "the new run ended with exit $($again.exit): $($again.error)"
        }
        $guestRoot = & $stage 'recover'
        Start-Worker $guestRoot $cancel $task
        Say "cancelling the preparation: ntfs2refs $($cancel -join ' ')"
        $ended = (Wait-Worker $guestRoot '' '').ended
    }
    if ($InterruptAt) {
        # The interrupted run's own output, then the recovery it printed.
        foreach ($leaf in 'stdout.log', 'stderr.log') {
            try { Copy-Item -FromSession $session -LiteralPath "$guestRoot\$leaf" -Destination (Join-Path $records "interrupted-$leaf") } catch { }
        }
        if (-not $waited.held) { $verdict.outcome = 'hold-not-reached'; throw "the converter ended without reporting its hold at '$InterruptAt'" }
        $printed = Select-String -LiteralPath (Join-Path $records 'interrupted-stdout.log') -Pattern '^To recover: ntfs2refs --recover "(.+)" --recovery-sha256 ([0-9a-f]{64})' | Select-Object -Last 1
        if (-not $printed) { $verdict.outcome = 'interrupted-without-recovery-command'; throw 'the interrupted run printed no "To recover:" line' }
        $recover = @('--recover', $printed.Matches[0].Groups[1].Value, '--recovery-sha256', $printed.Matches[0].Groups[2].Value)
        if ($RecoverMode -eq 'rollback') { $recover += '--rollback' }
        if ($Unattended) { $recover += '--yes' }
        $verdict.interrupted_at = $InterruptAt; $verdict.recover_mode = $RecoverMode; $verdict.recovery_arguments = $recover
        # A folder of its own, so the interrupted run's records stay as they are.
        $guestRoot = "$guestRoot\recover"
        Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock {
            param($root)
            $null = New-Item -ItemType Directory -Path $root -Force
            foreach ($leaf in 'ntfs2refs.exe', 'lab-volume-manifest.exe', 'worker.ps1', 'manifest-before.jsonl') { Copy-Item -LiteralPath (Join-Path (Split-Path $root) $leaf) -Destination $root }
        }
        Start-Worker $guestRoot $recover $task
        Say "recovery started: ntfs2refs $($recover -join ' ')"
        $ended = (Wait-Worker $guestRoot '' '').ended
    }
    $run = Invoke-Command -Session $session -ArgumentList $guestRoot, $task, $unlock -ScriptBlock {
        param($root, $task, $unlock)
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
        try { & ([scriptblock]::Create($unlock)) } catch { }
        $terminal = if (Test-Path "$root\native-terminal.json") { Get-Content "$root\native-terminal.json" -Raw | ConvertFrom-Json } else { $null }
        $volume = Get-Volume -DriveLetter V -ErrorAction SilentlyContinue
        $partition = Get-Partition -DriveLetter V -ErrorAction SilentlyContinue
        $disk = if ($partition) { Get-Disk -Number $partition.DiskNumber } else { $null }
        $refs = if ($volume -and $volume.FileSystem -eq 'ReFS') { & fsutil.exe fsinfo refsinfo V: 2>&1 | Out-String } else { '' }
        [pscustomobject]@{ exit = if ($terminal) { [int]$terminal.native_exit } else { $null }; seconds = if ($terminal) { [Math]::Round([double]$terminal.wall_seconds, 1) } else { $null }
            worker_error = if (Test-Path "$root\worker-error.txt") { Get-Content "$root\worker-error.txt" -Raw } else { $null }
            filesystem = if ($volume) { $volume.FileSystem } else { $null }; label = if ($volume) { $volume.FileSystemLabel } else { $null }
            health = if ($volume) { "$($volume.HealthStatus)" } else { $null }; mounted = [bool]$partition
            offline = if ($disk) { $disk.IsOffline } else { $null }; read_only = if ($disk) { $disk.IsReadOnly } else { $null }; refsinfo = $refs
            partition_bytes = if ($partition) { $partition.Size } else { $null } }
    }
    foreach ($leaf in 'stdout.log', 'stderr.log') {
        try { Copy-Item -FromSession $session -LiteralPath "$guestRoot\$leaf" -Destination $records } catch { Say "could not collect ${leaf}: $($_.Exception.Message)" }
    }
    if ($SampleStacks) {
        try { Copy-Item -FromSession $session -LiteralPath "$guestRoot\stacks.txt" -Destination $records } catch { Say "could not collect stacks.txt: $($_.Exception.Message)" }
    }
    if (-not $ended) { $verdict.outcome = 'converter-timed-out'; throw "the converter did not end within $TimeoutMinutes minutes" }
    if ($run.worker_error) { throw "guest worker failed: $($run.worker_error)" }
    $errorLine = ''
    $stderr = Join-Path $records 'stderr.log'
    if (Test-Path -LiteralPath $stderr) { $errorLine = [string](Get-Content -LiteralPath $stderr -Encoding UTF8 | Where-Object { $_ -match '^error:' } | Select-Object -Last 1) }
    $refsField = { param($label) if ($run.refsinfo -match "(?m)^\s*$label\s*:\s*(\S+)") { $Matches[1] } else { $null } }
    $verdict.converter = [ordered]@{ exit = $run.exit; seconds = $run.seconds; error = $errorLine }
    # What the run said it would ask Windows for, and what Windows then calls the volume.
    $stdout = Join-Path $records 'stdout.log'
    $said = { param($pattern) if (Test-Path -LiteralPath $stdout) { $line = [string](Get-Content -LiteralPath $stdout -Encoding UTF8 | Where-Object { $_ -match $pattern } | Select-Object -Last 1); if ($line -match $pattern) { $Matches[1].Trim() } } }
    $verdict.target.requested = & $said '^Requested target: (.+?)\s*\(ReFS,'
    $verdict.target.windows_reports = & $said '^Windows reports the converted source: (.+?);'
    $verdict.volume_after = [ordered]@{ filesystem = $run.filesystem; label = $run.label; health = $run.health; mounted = $run.mounted; disk_offline = $run.offline; disk_read_only = $run.read_only
        partition_bytes = $run.partition_bytes
        refs_version = & $refsField 'REFS Volume Version'; refs_bytes_per_cluster = & $refsField 'Bytes Per Cluster'; refs_bytes_per_sector = & $refsField 'Bytes Per Sector' }
    Say "converter exit $($run.exit) after $($run.seconds) s; V: is $($run.filesystem) '$($run.label)' $($run.health)$(if ($run.filesystem -eq 'ReFS') { ", ReFS $($verdict.volume_after.refs_version), $($verdict.volume_after.refs_bytes_per_cluster)-byte clusters" })"
    if ($errorLine) { Say $errorLine }

    # A converted volume is compared with the listing's allowances; a source
    # that the converter refused must list exactly as it did.
    # (Exit 6: converted, and the run's own listings differ.)
    $converted = $run.exit -in $(if ($CompareListing) { 0, 6 } else { 0 }) -and $run.filesystem -eq 'ReFS'
    $returned = $run.filesystem -eq 'NTFS' -and $run.mounted -and -not $run.offline -and -not $run.read_only
    $listing = 'not-compared'
    if ($converted -or $returned) {
        $compared = Invoke-Command -Session $session -ArgumentList $guestRoot, (-not $converted), ([bool]$DropShortNames) -ScriptBlock {
            param($root, $exact, $dropped)
            $listed = & "$root\lab-volume-manifest.exe" capture --root 'V:\' --output "$root\manifest-after.jsonl" 2>&1
            if ($LASTEXITCODE -ne 0) { return [pscustomobject]@{ stage = 'capture-after'; exit = $LASTEXITCODE; differences = $null; listed = ($listed -join ' '); summary = '' } }
            $arguments = @('compare'); if ($exact) { $arguments += '--exact' } elseif ($dropped) { $arguments += '--short-names-dropped' }
            $arguments += @('--before', "$root\manifest-before.jsonl", '--after', "$root\manifest-after.jsonl", '--report', "$root\manifest-report.json")
            $summary = & "$root\lab-volume-manifest.exe" $arguments 2>&1
            $exit = $LASTEXITCODE; $differences = $null; $kinds = @{}
            if (Test-Path -LiteralPath "$root\manifest-report.json") {
                try {
                    $report = Get-Content -Raw -LiteralPath "$root\manifest-report.json" | ConvertFrom-Json
                    $differences = [int]$report.difference_count
                    foreach ($kind in $report.difference_kinds.PSObject.Properties) { $kinds[$kind.Name] = [int]$kind.Value }
                } catch { $differences = $null }
            }
            $shortBefore = @(Select-String -LiteralPath "$root\manifest-before.jsonl" -Pattern '"short_name":"' -SimpleMatch).Count
            $shortAfter = @(Select-String -LiteralPath "$root\manifest-after.jsonl" -Pattern '"short_name":"' -SimpleMatch).Count
            [pscustomobject]@{ stage = 'compare'; exit = $exit; differences = $differences; kinds = $kinds; listed = ($listed -join ' '); summary = ($summary -join ' ')
                short_before = $shortBefore; short_after = $shortAfter; short_dropped = $(if ($report -and $report.PSObject.Properties['short_names_dropped']) { [int]$report.short_names_dropped } else { 0 }) }
        }
        foreach ($leaf in 'manifest-after.jsonl', 'manifest-report.json') { try { Copy-Item -FromSession $session -LiteralPath "$guestRoot\$leaf" -Destination $records } catch { } }
        # Exit 0 with nothing counted is identical; exit 2 with a count is a
        # real difference; anything else is the listing tool failing.
        $listing = if ($compared.stage -eq 'compare' -and $compared.exit -eq 0 -and $compared.differences -eq 0) { 'identical' }
            elseif ($compared.stage -eq 'compare' -and $compared.exit -eq 2 -and $compared.differences -gt 0) { 'differs' } else { 'tool-failed' }
        # A volume with shadow copies or BitLocker holds files of Windows' own
        # that nothing may open. They count as differences because they could
        # not be read; when that is all there is, and as many before as after,
        # a refused volume is as unchanged as a listing can show. Only for a
        # refusal: on a converted volume every file has to be readable.
        if ($listing -eq 'differs' -and -not $converted -and @($compared.kinds.Keys).Count -eq 2 -and
            $compared.kinds['unreadable before'] -gt 0 -and $compared.kinds['unreadable before'] -eq $compared.kinds['unreadable afterwards']) {
            $listing = 'unreadable-both-times'
        }
        if ($DropShortNames -and $converted) {
            # A run that drops short names leaves none, and the comparison counted every one that was listed.
            $verdict.short_names = [ordered]@{ listed_before = $compared.short_before; listed_after = $compared.short_after; counted_as_dropped = $compared.short_dropped }
            Say "short names: $($compared.short_before) listed before, $($compared.short_after) after; $($compared.short_dropped) counted as dropped"
            if ($listing -eq 'identical' -and ($compared.short_after -ne 0 -or $compared.short_dropped -ne $compared.short_before)) { $listing = 'differs' }
        }
        $verdict.manifest = [ordered]@{ result = $listing; exact = (-not $converted); stage = $compared.stage; exit = $compared.exit; differences = $compared.differences; listed = $compared.listed; summary = $compared.summary }
        Say "listing after the run: $($compared.listed)"
        Say "before/after comparison$(if (-not $converted) { ', exact' }): $listing ($($compared.stage) exit $($compared.exit)): $($compared.summary)"
    }
    $verdict.outcome = if ($StopDuringPreparation -and $AfterStop -eq 'cancel') {
        # Nothing had been written: the NTFS volume must be back and list exactly as before.
        if ($run.exit -eq 0 -and $returned -and $listing -eq 'identical') { 'preparation-cancelled' }
        elseif ($run.exit -eq 0 -and $returned) { "preparation-cancelled-but-listing-$listing" }
        else { 'preparation-cancel-failed' }
    } elseif ($StopDuringPreparation) {
        # The new run must have been refused with the way back named, and that way must then have worked.
        if ($verdict.restart.exit -eq 0) { 'restart-was-not-refused' }
        elseif (-not $verdict.restart.names_the_way_back) { 'restart-refused-without-the-way-back' }
        elseif ($run.exit -eq 0 -and $returned -and $listing -eq 'identical') { 'restart-refused-then-cancelled' }
        elseif ($run.exit -eq 0 -and $returned) { "restart-refused-then-cancelled-but-listing-$listing" }
        else { 'restart-refused-then-cancel-failed' }
    } elseif ($InterruptAt -and $RecoverMode -eq 'rollback') {
        # A rollback returns the NTFS volume, which must list exactly as before.
        if ($run.exit -eq 0 -and $returned -and $listing -eq 'identical') { 'rolled-back' }
        elseif ($run.exit -eq 0 -and $returned) { "rolled-back-but-listing-$listing" }
        else { 'rollback-failed' }
    } elseif ($InterruptAt) {
        if ($converted -and $listing -eq 'identical') { 'resumed' }
        elseif ($converted) { "resumed-but-listing-$listing" }
        else { 'resume-failed' }
    } elseif ($Diagnose -and $run.exit -in 0, 3) {
        # 0: every object examined, none failed. 3: failures were reported.
        if (-not $returned -or $listing -ne 'identical') { 'diagnose-changed-the-source' }
        elseif ($run.exit -eq 0) { 'diagnose-clean' } else { 'diagnose-found-failures' }
    } elseif ($converted) {
        switch ($listing) { 'identical' { 'converted' } 'differs' { 'converted-but-listing-differs' } default { 'converted-listing-tool-failed' } }
    } elseif ($run.exit -eq 0) { 'exit-0-but-not-refs' }
    elseif ($returned -and $listing -in 'identical', 'unreadable-both-times') { if ($ExpectRefusal -and $errorLine -match $ExpectRefusal) { 'refused-as-expected' } else { 'refused-source-unchanged' } }
    elseif ($returned) { "refused-source-listing-$listing" }
    elseif ($run.filesystem -eq 'ReFS') { 'failed-after-conversion' }
    else { 'failed-source-not-returned' }
    # A run that refuses or only diagnoses has to leave the partition as long
    # as it was. (A conversion of a partition that is not a multiple of
    # 64 MiB shortens it, and a run recovered to NTFS after that keeps the
    # shorter length; both say so.)
    if ($StopDuringPreparation) {
        # The cancellation has to say what the run that was cut off left in
        # the working directory, and how large it is.
        $left = [string](Get-Content -LiteralPath $stdout -Encoding UTF8 -ErrorAction SilentlyContinue | Where-Object { $_ -match '^The run that was cut off left its working files' } | Select-Object -Last 1)
        $verdict.cancellation_said_of_what_is_left = $left
        if ($left) { Say "the cancellation said: $left" }
        elseif ($verdict.outcome -in 'preparation-cancelled', 'restart-refused-then-cancelled') { $verdict.outcome = "$($verdict.outcome)-without-naming-what-is-left" }
    }
    $lengthBefore = $verdict.source.observed.partition_bytes; $lengthAfter = $verdict.volume_after.partition_bytes
    if ($lengthBefore -and $lengthAfter -and $lengthAfter -ne $lengthBefore) {
        $verdict.source.partition_bytes_changed_by = $lengthAfter - $lengthBefore
        Say "the partition's length changed by $($lengthAfter - $lengthBefore) bytes ($lengthBefore -> $lengthAfter)"
        if ($verdict.outcome -in 'refused-source-unchanged', 'refused-as-expected') { $verdict.outcome = 'refused-after-shrinking-the-partition' }
        elseif ($verdict.outcome -in 'diagnose-clean', 'diagnose-found-failures') { $verdict.outcome = 'diagnose-changed-the-source' }
    }
    if ($Siblings) { & $holdSiblings (& $said '^(This volume shares disk .*)$') }
    if ($Check) {
        # The check and the conversion have to agree: on whether the volume
        # is refused, and, when it is, on why.
        $refusedNow = $verdict.outcome -match '^refused'
        $wholeError = if (Test-Path -LiteralPath $stderr) { (Get-Content -LiteralPath $stderr -Encoding UTF8) -join "`n" } else { '' }
        $same = @($verdict.check.refusals | Where-Object { $_ -and $wholeError.Contains($_.Substring(0, [Math]::Min(60, $_.Length))) }).Count -gt 0
        $verdict.check.agrees = switch ($verdict.check.exit) { 0 { -not $refusedNow } 3 { $refusedNow } default { $null } }
        $verdict.check.named_the_same_refusal = if ($verdict.check.exit -eq 3 -and $refusedNow) { $same } else { $null }
        Say "check and run: $(if ($null -eq $verdict.check.agrees) { 'the check was inconclusive' } elseif ($verdict.check.agrees) { 'agree' } else { 'DISAGREE' })$(if ($null -ne $verdict.check.named_the_same_refusal) { "; the same refusal: $($verdict.check.named_the_same_refusal)" })"
        if ($verdict.check.agrees -eq $false) { $verdict.outcome = "$($verdict.outcome)-but-check-disagreed" }
        elseif ($verdict.check.named_the_same_refusal -eq $false) { $verdict.outcome = "$($verdict.outcome)-but-check-named-another-refusal" }
    }
    if ($CompareListing) {
        $own = & $said '^(The volume (?:lists as it did before the conversion|does NOT list as it did before the conversion).*)$'
        $ownSame = "$own" -match '^The volume lists as it did'
        $verdict.own_listing = [ordered]@{ exit = $run.exit; identical = $ownSame; said = "$own" }
        Say "the run's own comparison: $(if ($own) { $own.Substring(0, [Math]::Min(260, $own.Length)) } else { 'not printed' })"

        if ($converted -and ($ownSame -ne ($listing -eq 'identical') -or ($run.exit -eq 0) -ne $ownSame)) { $verdict.outcome = "$($verdict.outcome)-but-own-listing-disagreed" }
    }
    if ($verdict.target.requested) { Say "target: the run asked for '$($verdict.target.requested)'; Windows reports '$($verdict.target.windows_reports)'" }
    if ($ExpectTarget -and $verdict.outcome -eq 'converted' -and "$($verdict.target.windows_reports)" -notmatch $ExpectTarget) { $verdict.outcome = 'converted-but-target-differs' }
    if ($VssProvider -eq 'answering') {
        # The provider is passed over, and the check and the run each say so by its name.
        $named = '^Note: A shadow-copy \(VSS\) provider .*' + [regex]::Escape("`"$($verdict.vss_provider.name)`"") + '.*full backup'
        # A run that was stopped said it before it was stopped; its recovery asks nothing of the kind.
        $spoken = @($stdout, (Join-Path $records 'interrupted-stdout.log')) | Where-Object { Test-Path -LiteralPath $_ }
        $verdict.vss_provider.note_in_run = [bool]($spoken | ForEach-Object { Get-Content -LiteralPath $_ -Encoding UTF8 } | Where-Object { $_ -match $named } | Select-Object -First 1)
        if ($Check) { $verdict.vss_provider.note_in_check = [bool]($checked.text | Where-Object { $_ -match $named } | Select-Object -First 1) }
        Say "provider note: in the run's output $($verdict.vss_provider.note_in_run)$(if ($Check) { ", in the check's $($verdict.vss_provider.note_in_check)" })"
        if ($verdict.outcome -in 'converted', 'resumed', 'rolled-back', 'diagnose-clean' -and (-not $verdict.vss_provider.note_in_run -or ($Check -and -not $verdict.vss_provider.note_in_check))) {
            $verdict.outcome = "$($verdict.outcome)-without-the-provider-note"
        }
    }
    if ($Acceptance -and $verdict.outcome -in 'converted', 'resumed') {
        # The listing shows what was carried over; this shows that the result
        # is a volume one can go on working with.
        $use = Invoke-UseTest $guestRoot
        if (-not $use.passed) { $verdict.outcome = "$($verdict.outcome)-but-use-failed" }
    }
} catch {
    $verdict.error = "$($_.Exception.Message)"
    Say "error: $($_.Exception.Message)"
} finally {
    if ($worker) { Remove-PSSession $worker -ErrorAction SilentlyContinue }
    try {
        if ($SiblingState) {
            # What -SiblingState set up outside the disk (a shadow copy goes
            # with it), noted in the attempt's first folder.
            Invoke-Command -Session $session -ArgumentList "C:\n2r\datalab\$Name" -ErrorAction Stop -ScriptBlock {
                param($root)
                if (Test-Path -LiteralPath "$root\sibling-holder.txt") {
                    Stop-Process -Id ([int](Get-Content -LiteralPath "$root\sibling-holder.txt" -Raw)) -Force -ErrorAction SilentlyContinue
                    Remove-Item -LiteralPath "$root\sibling-holder.txt" -Force
                }
                if (Test-Path -LiteralPath "$root\sibling-dumpfile.txt") {
                    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'; $was = "$(Get-Content -LiteralPath "$root\sibling-dumpfile.txt" -Raw)".Trim()
                    if ($was) { Set-ItemProperty -LiteralPath $key -Name DumpFile -Value $was -Type ExpandString } else { Remove-ItemProperty -LiteralPath $key -Name DumpFile -ErrorAction SilentlyContinue }
                    Remove-Item -LiteralPath "$root\sibling-dumpfile.txt" -Force
                }
            }
        }
        if ($DeletedWhileOpen) {
            # Whatever happened, nothing holds the volume when it is taken away.
            Invoke-Command -Session $session -ArgumentList $guestRoot -ErrorAction Stop -ScriptBlock {
                param($root)
                if (-not (Test-Path -LiteralPath "$root\deleted-held.txt")) { return }
                Set-Content -LiteralPath "$root\deleted-release.txt" -Value 'release'
                $id = [int]"$(Get-Content -LiteralPath "$root\deleted-held.txt" -Raw)".Trim()
                foreach ($try in 1..50) { if (-not (Get-Process -Id $id -ErrorAction SilentlyContinue)) { break }; Start-Sleep -Milliseconds 100 }
                Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
            }
        }
        if ($VssProvider) {
            # The provider this attempt brought, as it noted it.
            $removed = Invoke-Command -Session $session -ArgumentList $guestRoot -ErrorAction Stop -ScriptBlock {
                param($root)
                $note = "$root\vss-provider.txt"
                if (-not (Test-Path -LiteralPath $note)) { return 'nothing of this attempt to remove' }
                $kind, $what = "$(Get-Content -LiteralPath $note -Raw)".Trim() -split ' ', 2
                Remove-Item -Path $what -Recurse -Force -ErrorAction SilentlyContinue
                $said = "registration removed: $(-not (Test-Path -Path $what))"
                Stop-Service -Name VSS -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath $note -Force
                "$said; providers now: $(@(& vssadmin.exe list providers 2>&1 | Where-Object { "$_" -match 'Provider name' }).Count)"
            }
            Say "shadow-copy provider: $removed"
        }
        if (-not $KeepVolume) {
            Invoke-Command -Session $session -ArgumentList $guestRoot, $Name -ErrorAction Stop -ScriptBlock {
                param($root, $name)
                foreach ($file in "S:\datalab\$name.vhdx", "S:\datalab\$name.vhd") {
                    if (Test-Path -LiteralPath $file) {
                        Set-Content -LiteralPath "$root\detach.txt" -Value ("select vdisk file=`"$file`"`r`ndetach vdisk") -Encoding ASCII
                        $null = & diskpart.exe /s "$root\detach.txt" 2>&1
                        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
                    }
                }
                # The run's working files: a shadow as large as the volume.
                Get-ChildItem -LiteralPath $(if (Test-Path -LiteralPath 'M:\runs') { 'M:\runs' } else { 'S:\datalab\runs' }) -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                    Get-ChildItem -LiteralPath $_.FullName -Recurse -Filter '*.vhdx' -ErrorAction SilentlyContinue | ForEach-Object {
                        Set-Content -LiteralPath "$root\detach.txt" -Value ("select vdisk file=`"$($_.FullName)`"`r`ndetach vdisk") -Encoding ASCII
                        $null = & diskpart.exe /s "$root\detach.txt" 2>&1
                    }
                    Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                }
                # The MBR working disk of -WorkingMbr, after what it held.
                $work = "S:\datalab\$name-work.vhdx"
                if (Test-Path -LiteralPath $work) {
                    Set-Content -LiteralPath "$root\detach.txt" -Value ("select vdisk file=`"$work`"`r`ndetach vdisk") -Encoding ASCII
                    $null = & diskpart.exe /s "$root\detach.txt" 2>&1
                    Remove-Item -LiteralPath $work -Force -ErrorAction SilentlyContinue
                }
            }
            if ($hostDisk) {
                Get-VMHardDiskDrive -VM $vm | Where-Object Path -EQ $hostDisk | Remove-VMHardDiskDrive
                Remove-Item -LiteralPath $hostDisk -Force
            }
        } elseif ($hostDisk) { Say "kept: the 4Kn disk stays attached to the VM ($hostDisk)" }
    } catch { Say "cleanup failed: $($_.Exception.Message)" }
    Remove-PSSession $session -ErrorAction SilentlyContinue
    Save-Verdict
    Say "outcome: $($verdict.outcome). Records: $records"
}
$verdict.outcome
