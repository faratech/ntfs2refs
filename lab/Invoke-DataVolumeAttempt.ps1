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
refused-source-unchanged (the converter stopped and the NTFS volume lists
exactly as before), refused-as-expected (the same, and -ExpectRefusal matched),
and named failures. With -InterruptAt: resumed (recovered to ReFS, listing
identical) or rolled-back (recovered to NTFS, listing exactly as before).
Records land in .lab\hyperv\attempts\<Name>\.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Name,
    [string]$VmId = '8f7fc646-8c9f-41d0-b65a-ecfadccfc36a',
    # NTFS allocation unit of the source, in bytes: 512 through 2097152.
    [int]$ClusterBytes = 4096,
    # Logical sector size of the source disk. 4096 is a 4Kn disk.
    [ValidateSet(512, 4096)][int]$SectorBytes = 512,
    # format /L: 4096-byte file records on a 512-byte-sector disk.
    [switch]$LargeRecords,
    # Size of the source partition. ReFS covers whole 64 MiB units.
    [int]$PartitionMB = 51200,
    [ValidateSet('dev-drive', 'standard')][string]$TargetFormat = 'dev-drive',
    # ReFS allocation unit of the target, passed as --target-cluster-bytes; 0 leaves the converter's default.
    [int]$TargetClusterBytes = 0,
    [ValidateSet('system', 'administrator')][string]$RunAs = 'system',
    # What to put on the volume: the fixed mixed set, or nothing but one file.
    [ValidateSet('mixed', 'minimal', 'many')][string]$Content = 'mixed',
    # Further converter arguments, for example '--diagnose'.
    [string[]]$ConverterArgs = @(),
    # A pattern the converter's error must match for a refusal to count as expected.
    [string]$ExpectRefusal,
    # A laboratory hold point (for example apply-mid-ranges or handoff-sealed):
    # the converter is ended when it reports that it is held there, and the
    # run is then recovered with the command it printed.
    [string]$InterruptAt,
    [ValidateSet('resume', 'rollback')][string]$RecoverMode = 'resume',
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
    [switch]$KeepVolume
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$workspace = Split-Path -Parent $PSScriptRoot
if (-not $Binary) { $Binary = Join-Path $workspace 'target\release\ntfs2refs.exe' }
if (-not $ManifestBinary) { $ManifestBinary = Join-Path $workspace 'target\release\lab-volume-manifest.exe' }
foreach ($file in $Binary, $ManifestBinary) { if (-not (Test-Path -LiteralPath $file)) { throw "Not found: $file (cargo build --locked --release --bin ntfs2refs --bin lab-volume-manifest)" } }
if ($ClusterBytes -lt 512 -or $ClusterBytes -gt 2097152 -or ($ClusterBytes -band ($ClusterBytes - 1))) { throw "-ClusterBytes $ClusterBytes is not a power of two from 512 to 2097152" }
if ($ClusterBytes -lt $SectorBytes) { throw "-ClusterBytes $ClusterBytes is smaller than the $SectorBytes-byte sector" }

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

$vm = Get-VM -Id $VmId
if ($vm.State -ne 'Running') { throw "VM $($vm.Name) is $($vm.State). Start its control OS first: Invoke-BootConversionAttempt.ps1 -Name <n> -NoConvert -KeepScratch -VmId $VmId" }
$saved = Import-Clixml -LiteralPath (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$credential = [pscredential]::new('LabAdmin', $saved.Password)
$session = New-PSSession -VMId $VmId -Credential $credential
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

    # The source disk: a VHDX in the guest, or for 4Kn one the host attaches.
    $sizeMB = $PartitionMB + 2048
    if ($SectorBytes -eq 4096) {
        $hostDisk = Join-Path $records 'source-4kn.vhdx'
        $null = New-VHD -Path $hostDisk -SizeBytes ($sizeMB * 1MB) -Dynamic -LogicalSectorSizeBytes 4096 -PhysicalSectorSizeBytes 4096
        Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -Path $hostDisk
        Say "attached a 4Kn disk to the VM: $hostDisk"
    }
    # A VHDX reports 4096-byte physical sectors, and NTFS will not format a
    # cluster smaller than the physical sector; a VHD reports 512.
    $container = if ($ClusterBytes -lt 4096) { 'vhd' } else { 'vhdx' }
    $made = Invoke-Command -Session $session -ArgumentList $guestRoot, $Name, $sizeMB, $PartitionMB, $SectorBytes, $unit, ([bool]$LargeRecords), @($ready), $container -ScriptBlock {
        param($root, $name, $sizeMB, $partitionMB, $sectorBytes, $unit, $largeRecords, $known, $container)
        if ($sectorBytes -eq 4096) {
            $deadline = (Get-Date).AddSeconds(60)
            do { Start-Sleep -Milliseconds 500; $new = @(Get-Disk | Where-Object { $_.Number -notin $known -and $_.LogicalSectorSize -eq 4096 }) } until ($new.Count -eq 1 -or (Get-Date) -gt $deadline)
            if ($new.Count -ne 1) { throw "expected one new 4Kn disk in the guest, found $($new.Count)" }
            $number = $new[0].Number
            if ($new[0].IsOffline) { Set-Disk -Number $number -IsOffline $false }
            if ($new[0].IsReadOnly) { Set-Disk -Number $number -IsReadOnly $false }
            $script = "select disk $number`r`nclean`r`nconvert gpt`r`ncreate partition primary size=$partitionMB`r`nassign letter=V"
        } else {
            $file = "S:\datalab\$name.$container"
            $script = "create vdisk file=`"$file`" maximum=$sizeMB type=expandable`r`nattach vdisk`r`nconvert gpt`r`ncreate partition primary size=$partitionMB`r`nassign letter=V"
        }
        Set-Content -LiteralPath "$root\make.txt" -Value $script -Encoding ASCII
        $diskpart = & diskpart.exe /s "$root\make.txt" 2>&1 | Out-String
        if (-not (Get-Partition -DriveLetter V -ErrorAction SilentlyContinue)) { throw "diskpart made no volume V:`n$diskpart" }
        $arguments = @('V:', '/FS:NTFS', "/A:$unit", '/Q', '/Y', '/V:DATALAB'); if ($largeRecords) { $arguments += '/L' }
        $format = & "$env:SystemRoot\System32\format.com" $arguments 2>&1 | Out-String
        $volume = Get-Volume -DriveLetter V
        if ($volume.FileSystem -ne 'NTFS') { throw "format.com $($arguments -join ' ') left V: as '$($volume.FileSystem)':`n$format" }
        $ntfs = (& fsutil.exe fsinfo ntfsinfo V: 2>&1 | Out-String)
        $partition = Get-Partition -DriveLetter V
        [pscustomobject]@{ diskpart = $diskpart; format = $format; ntfsinfo = $ntfs; disk = $partition.DiskNumber; partition = $partition.PartitionNumber
            bytes = $partition.Size; offset = $partition.Offset; logical_sector = (Get-Disk -Number $partition.DiskNumber).LogicalSectorSize }
    }
    Set-Content -LiteralPath (Join-Path $records 'volume.log') -Value ($made.diskpart, $made.format, $made.ntfsinfo) -Encoding UTF8
    $field = { param($label) if ($made.ntfsinfo -match "(?m)^\s*$label\s*:\s*([0-9,]+)") { [int64]($Matches[1] -replace ',') } else { $null } }
    $verdict.source.observed = [ordered]@{ bytes_per_sector = & $field 'Bytes Per Sector'; bytes_per_cluster = & $field 'Bytes Per Cluster'
        bytes_per_file_record = & $field 'Bytes Per FileRecord Segment'; partition_bytes = $made.bytes; partition_offset = $made.offset; disk_logical_sector = $made.logical_sector }
    Say "source V: disk $($made.disk) partition $($made.partition), $($made.bytes) bytes; NTFS reports $($verdict.source.observed.bytes_per_sector)-byte sectors, $($verdict.source.observed.bytes_per_cluster)-byte clusters, $($verdict.source.observed.bytes_per_file_record)-byte file records"
    if ($verdict.source.observed.bytes_per_cluster -ne $ClusterBytes) { throw "the volume has $($verdict.source.observed.bytes_per_cluster)-byte clusters, not the $ClusterBytes asked for" }

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

    $listed = Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock {
        param($root)
        # Windows writes its own files into "System Volume Information" when a
        # volume arrives (the search indexer's IndexerVolumeGuid among them).
        # A volume in use has them already; one made a moment ago gets them
        # when it next mounts, which would be after it was converted. So the
        # volume is remounted (again every 20 s: a guest that has just
        # started has no indexer yet) and listed when the file is there.
        $deadline = (Get-Date).AddSeconds(150); $remount = Get-Date; $settled = $false
        do {
            Start-Sleep -Seconds 2
            $text = & "$root\lab-volume-manifest.exe" capture --root 'V:\' --output "$root\manifest-before.jsonl" 2>&1
            if ($LASTEXITCODE -ne 0) { break }
            $settled = [bool](Select-String -LiteralPath "$root\manifest-before.jsonl" -Pattern 'IndexerVolumeGuid' -SimpleMatch -Quiet)
            if (-not $settled -and (Get-Date) -ge $remount) {
                $number = (Get-Partition -DriveLetter V).DiskNumber
                Set-Disk -Number $number -IsOffline $true; Set-Disk -Number $number -IsOffline $false; $remount = (Get-Date).AddSeconds(20)
            }
        } until ($settled -or (Get-Date) -gt $deadline)
        [pscustomobject]@{ exit = $LASTEXITCODE; text = ($text -join ' '); settled = $settled }
    }
    if ($listed.exit -ne 0) { throw "listing before the run failed (exit $($listed.exit)): $($listed.text)" }
    Copy-Item -FromSession $session -LiteralPath "$guestRoot\manifest-before.jsonl" -Destination $records
    $verdict.source.windows_files_settled = $listed.settled
    Say "listing before the run: $($listed.text)$(if (-not $listed.settled) { ' (Windows had not written its own files to the volume within 150 s)' })"

    # Starts the guest worker (the one the boot harness uses) in a guest
    # folder with these converter arguments: as SYSTEM from a scheduled task,
    # or as the elevated administrator in a session of its own.
    function Start-Worker([string]$Root, [string[]]$Arguments, [string]$Task) {
        Invoke-Command -Session $session -ArgumentList $Root, ($Arguments -join "`t") -ScriptBlock {
            param($root, $joined) [IO.File]::WriteAllText("$root\run.json", (@{ arguments = @([string[]]$joined.Split("`t")) } | ConvertTo-Json), [Text.UTF8Encoding]::new($false)) }
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
    # once it reports that it is held there. Answers whether the worker ended
    # and whether the hold was reached.
    function Wait-Worker([string]$Root, [string]$HoldAt) {
        $deadline = (Get-Date).AddMinutes($TimeoutMinutes); $held = $false
        do {
            Start-Sleep -Seconds 2
            $state = Invoke-Command -Session $session -ArgumentList $Root, ([bool]$HoldAt -and -not $held) -ScriptBlock {
                param($root, $watchHold)
                $ended = (Test-Path "$root\native-terminal.json") -or (Test-Path "$root\worker-error.txt")
                $atHold = $false
                if ($watchHold -and -not $ended -and (Test-Path "$root\stdout.log")) {
                    $atHold = [bool](Select-String -LiteralPath "$root\stdout.log" -SimpleMatch -Pattern '"kind":"lab-hold-v1"' -Quiet)
                    # The lab ends a process; it cannot cut power to the storage.
                    if ($atHold) { Get-Process -Name ntfs2refs -ErrorAction SilentlyContinue | Stop-Process -Force }
                }
                [pscustomobject]@{ ended = $ended; at_hold = $atHold }
            }
            if ($state.at_hold) { $held = $true; Say "the converter reported its hold at '$HoldAt' and was ended" }
        } until ($state.ended -or (Get-Date) -gt $deadline)
        [pscustomobject]@{ ended = [bool]$state.ended; held = $held }
    }
    $arguments = @('--drive', 'V', '--scratch-directory', 'S:\datalab\runs', '--target-format', $TargetFormat)
    if ($TargetClusterBytes) { $arguments += @('--target-cluster-bytes', "$TargetClusterBytes") }
    if ($InterruptAt) { $arguments += @('--lab-hold-at', $InterruptAt, '--acknowledge-lab-hold-never-completes') }
    if ($SampleStacks) { $arguments += @('--sample-stacks', "$guestRoot\stacks.txt") }
    if ($Diagnose) { $arguments += '--diagnose' }
    $arguments += $ConverterArgs
    $verdict.converter_arguments = $arguments
    $task = "N2R-DataLab-$Name"
    Start-Worker $guestRoot $arguments $task
    Say "converter started: ntfs2refs $($arguments -join ' ')"
    $waited = Wait-Worker $guestRoot $InterruptAt
    $ended = $waited.ended
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
        $ended = (Wait-Worker $guestRoot '').ended
    }
    $run = Invoke-Command -Session $session -ArgumentList $guestRoot, $task -ScriptBlock {
        param($root, $task)
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
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
    $verdict.volume_after = [ordered]@{ filesystem = $run.filesystem; label = $run.label; health = $run.health; mounted = $run.mounted; disk_offline = $run.offline; disk_read_only = $run.read_only
        partition_bytes = $run.partition_bytes
        refs_version = & $refsField 'REFS Volume Version'; refs_bytes_per_cluster = & $refsField 'Bytes Per Cluster'; refs_bytes_per_sector = & $refsField 'Bytes Per Sector' }
    Say "converter exit $($run.exit) after $($run.seconds) s; V: is $($run.filesystem) '$($run.label)' $($run.health)$(if ($run.filesystem -eq 'ReFS') { ", ReFS $($verdict.volume_after.refs_version), $($verdict.volume_after.refs_bytes_per_cluster)-byte clusters" })"
    if ($errorLine) { Say $errorLine }

    # A converted volume is compared with the listing's allowances; a source
    # that the converter refused must list exactly as it did.
    $converted = $run.exit -eq 0 -and $run.filesystem -eq 'ReFS'
    $returned = $run.filesystem -eq 'NTFS' -and $run.mounted -and -not $run.offline -and -not $run.read_only
    $listing = 'not-compared'
    if ($converted -or $returned) {
        $compared = Invoke-Command -Session $session -ArgumentList $guestRoot, (-not $converted) -ScriptBlock {
            param($root, $exact)
            $listed = & "$root\lab-volume-manifest.exe" capture --root 'V:\' --output "$root\manifest-after.jsonl" 2>&1
            if ($LASTEXITCODE -ne 0) { return [pscustomobject]@{ stage = 'capture-after'; exit = $LASTEXITCODE; differences = $null; listed = ($listed -join ' '); summary = '' } }
            $arguments = @('compare'); if ($exact) { $arguments += '--exact' }
            $arguments += @('--before', "$root\manifest-before.jsonl", '--after', "$root\manifest-after.jsonl", '--report', "$root\manifest-report.json")
            $summary = & "$root\lab-volume-manifest.exe" $arguments 2>&1
            $exit = $LASTEXITCODE; $differences = $null
            if (Test-Path -LiteralPath "$root\manifest-report.json") { try { $differences = [int](Get-Content -Raw -LiteralPath "$root\manifest-report.json" | ConvertFrom-Json).difference_count } catch { $differences = $null } }
            [pscustomobject]@{ stage = 'compare'; exit = $exit; differences = $differences; listed = ($listed -join ' '); summary = ($summary -join ' ') }
        }
        foreach ($leaf in 'manifest-after.jsonl', 'manifest-report.json') { try { Copy-Item -FromSession $session -LiteralPath "$guestRoot\$leaf" -Destination $records } catch { } }
        # Exit 0 with nothing counted is identical; exit 2 with a count is a
        # real difference; anything else is the listing tool failing.
        $listing = if ($compared.stage -eq 'compare' -and $compared.exit -eq 0 -and $compared.differences -eq 0) { 'identical' }
            elseif ($compared.stage -eq 'compare' -and $compared.exit -eq 2 -and $compared.differences -gt 0) { 'differs' } else { 'tool-failed' }
        $verdict.manifest = [ordered]@{ result = $listing; exact = (-not $converted); stage = $compared.stage; exit = $compared.exit; differences = $compared.differences; listed = $compared.listed; summary = $compared.summary }
        Say "listing after the run: $($compared.listed)"
        Say "before/after comparison$(if (-not $converted) { ', exact' }): $listing ($($compared.stage) exit $($compared.exit)): $($compared.summary)"
    }
    $verdict.outcome = if ($InterruptAt -and $RecoverMode -eq 'rollback') {
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
    elseif ($returned -and $listing -eq 'identical') { if ($ExpectRefusal -and $errorLine -match $ExpectRefusal) { 'refused-as-expected' } else { 'refused-source-unchanged' } }
    elseif ($returned) { "refused-source-listing-$listing" }
    elseif ($run.filesystem -eq 'ReFS') { 'failed-after-conversion' }
    else { 'failed-source-not-returned' }
} catch {
    $verdict.error = "$($_.Exception.Message)"
    Say "error: $($_.Exception.Message)"
} finally {
    if ($worker) { Remove-PSSession $worker -ErrorAction SilentlyContinue }
    try {
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
                Get-ChildItem -LiteralPath 'S:\datalab\runs' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                    Get-ChildItem -LiteralPath $_.FullName -Recurse -Filter '*.vhdx' -ErrorAction SilentlyContinue | ForEach-Object {
                        Set-Content -LiteralPath "$root\detach.txt" -Value ("select vdisk file=`"$($_.FullName)`"`r`ndetach vdisk") -Encoding ASCII
                        $null = & diskpart.exe /s "$root\detach.txt" 2>&1
                    }
                    Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
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
