#Requires -Version 7.2
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Converts NTFS volumes on virtual disks of this machine, one round after
another, for as long as it is given: the soak the hosted runners run every
night (.github/workflows/soak.yml).

.DESCRIPTION
Each round makes a virtual disk (VHDX) on this machine, formats it NTFS with
a cluster size it draws, fills it with content made from the round's seed,
lists it with lab-volume-manifest, and converts it in one of these ways:

  convert   straight through
  many      straight through, with tens of thousands of small files
  resume    held at a laboratory hold point, the process ended there, then
            the recovery command the run printed
  rollback  held at a hold point before the handoff, ended there, then the
            recovery command with --rollback
  cancel    ended at a moment drawn at random, without a hold, then whatever
            the run had printed: the recovery command, or the command that
            gives the volume back as NTFS, or nothing if it printed neither

It lists the volume again and compares the two listings: with a conversion's
allowances when the volume is ReFS, exactly when it is NTFS again. A round
that fails stops the soak and keeps its records; the disk is deleted either
way.

Every draw comes from the round's seed, which the round prints first, so a
failed round is made again with:

  Invoke-Soak.ps1 -Binaries <dir> -Profile <its profile> -Seed <its seed> -Rounds 1

It needs an elevated PowerShell 7 and a drive letter nothing else uses.
#>
[CmdletBinding()]
param(
    # A directory with ntfs2refs.exe and lab-volume-manifest.exe.
    [Parameter(Mandatory)][string]$Binaries,
    [ValidateSet('convert', 'many', 'resume', 'rollback', 'cancel')][string[]]$Profile = @('convert', 'many', 'resume', 'rollback', 'cancel'),
    # How long to go on starting rounds; a round that has started finishes.
    [int]$Minutes = 60,
    # At most this many rounds (0: as many as fit in -Minutes).
    [int]$Rounds = 0,
    # The first round's seed (0: one drawn now). Round n uses Seed + n - 1.
    [int]$Seed = 0,
    # Where the virtual disks are made.
    [string]$Disks,
    # The working storage the converter is given: not on the virtual disk.
    [string]$Scratch,
    # Where each round's records go.
    [string]$Records = (Join-Path ([IO.Path]::GetTempPath()) 'n2r-soak-records')
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest

$converter = Join-Path $Binaries 'ntfs2refs.exe'
$manifest = Join-Path $Binaries 'lab-volume-manifest.exe'
foreach ($file in $converter, $manifest) { if (-not (Test-Path -LiteralPath $file)) { throw "Not found: $file" } }
$fixed = @(Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' -and $_.FileSystem -eq 'NTFS' } | Sort-Object SizeRemaining -Descending)
if (-not $Disks) { $Disks = Join-Path "$($fixed[0].DriveLetter):\" 'n2r-soak\disks' }
if (-not $Scratch) {
    # Another volume than the disks' where there is one.
    $other = @($fixed | Where-Object { "$($_.DriveLetter):" -ne (Split-Path -Qualifier $Disks) }) + $fixed | Select-Object -First 1
    $Scratch = Join-Path "$($other.DriveLetter):\" 'n2r-soak\runs'
}
$null = New-Item -ItemType Directory -Force -Path $Disks, $Scratch, $Records
$used = @(Get-Volume | Where-Object DriveLetter | ForEach-Object { [string]$_.DriveLetter }) + @(Get-PSDrive -PSProvider FileSystem | ForEach-Object Name)
$letter = @('V', 'W', 'T', 'U', 'R', 'Q') | Where-Object { $_ -notin $used } | Select-Object -First 1
if (-not $letter) { throw 'no free drive letter among V, W, T, U, R, Q' }
if ($Seed -eq 0) { $Seed = Get-Random -Minimum 1 -Maximum 1000000000 }

$holdPoints = @('apply-activated', 'apply-mid-ranges', 'apply-ranges-written', 'apply-before-boot-granule', 'apply-boot-granule-written',
    'apply-before-handoff', 'apply-handoff-durable', 'handoff-sealed', 'finalize-authenticated', 'finalize-source-readonly',
    'finalize-before-online', 'finalize-online')
# The points a rollback is designed for: before the handoff marker is durable.
$rollbackPoints = $holdPoints[0..5]
$recoverLine = '^To recover: ntfs2refs --recover "(.+)" --recovery-sha256 ([0-9a-f]{64})'
$cancelLine = 'To get it back as NTFS: ntfs2refs --recover "(.+)" --recovery-sha256 ([0-9a-f]{64}) --rollback'

function Say([string]$text) { "$(Get-Date -Format HH:mm:ss) $text" }

function Read-Shared([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return '' }
    $stream = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
    try { [IO.StreamReader]::new($stream).ReadToEnd() } finally { $stream.Dispose() }
}

# Runs the converter with its output in files of $dir. It answers the one
# confirmation prompt. With $holdAt it ends the process once the run reports
# that hold; with $endAfterSeconds it ends it then, wherever it is.
function Invoke-Converter([string[]]$arguments, [string]$dir, [string]$holdAt = '', [double]$endAfterSeconds = 0, [int]$timeoutMinutes = 90) {
    $null = New-Item -ItemType Directory -Force -Path $dir
    $info = [Diagnostics.ProcessStartInfo]::new($converter)
    foreach ($argument in $arguments) { $info.ArgumentList.Add($argument) }
    $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    $out = [IO.FileStream]::new((Join-Path $dir 'stdout.log'), 'Create', 'Write', 'Read', 1)
    $err = [IO.FileStream]::new((Join-Path $dir 'stderr.log'), 'Create', 'Write', 'Read', 1)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $process = [Diagnostics.Process]::Start($info)
    $ended = $false; $held = $false
    try {
        $outTask = $process.StandardOutput.BaseStream.CopyToAsync($out)
        $errTask = $process.StandardError.BaseStream.CopyToAsync($err)
        try { $process.StandardInput.WriteLine('y'); $process.StandardInput.Close() } catch [IO.IOException] { }
        while (-not $process.WaitForExit(250)) {
            if ($holdAt -and (Read-Shared (Join-Path $dir 'stdout.log')).Contains('"kind":"lab-hold-v1"')) { $held = $true; $process.Kill($true); $ended = $true; break }
            if ($endAfterSeconds -gt 0 -and $watch.Elapsed.TotalSeconds -ge $endAfterSeconds) { $process.Kill($true); $ended = $true; break }
            if ($watch.Elapsed.TotalMinutes -ge $timeoutMinutes) { $process.Kill($true); throw "ntfs2refs $($arguments -join ' ') did not end within $timeoutMinutes minutes" }
        }
        $process.WaitForExit()
        $null = $outTask.GetAwaiter().GetResult(); $null = $errTask.GetAwaiter().GetResult()
    } finally { $out.Dispose(); $err.Dispose() }
    [pscustomobject]@{ exit = $process.ExitCode; ended = $ended; held = $held; seconds = [Math]::Round($watch.Elapsed.TotalSeconds, 1)
        stdout = Read-Shared (Join-Path $dir 'stdout.log'); stderr = Read-Shared (Join-Path $dir 'stderr.log')
        said = "$(Read-Shared (Join-Path $dir 'stdout.log'))`n$(Read-Shared (Join-Path $dir 'stderr.log'))" }
}

function New-SoakDisk([string]$path, [int]$gib, [int]$cluster) {
    $script = Join-Path (Split-Path $path) 'create.txt'
    Set-Content -LiteralPath $script -Value "create vdisk file=`"$path`" maximum=$($gib * 1024) type=expandable" -Encoding ascii
    $said = & diskpart.exe /s $script 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $path)) { throw "diskpart could not make $path`: $said" }
    $disk = Mount-DiskImage -ImagePath $path -NoDriveLetter -PassThru | Get-Disk
    Initialize-Disk -Number $disk.Number -PartitionStyle GPT
    $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -DriveLetter $letter
    $null = Format-Volume -Partition $partition -FileSystem NTFS -AllocationUnitSize $cluster -NewFileSystemLabel 'soak' -Confirm:$false -Force
    # No 8.3 names: a volume with them is refused unless --short-names drop.
    $null = & fsutil.exe 8dot3name set "${letter}:" 1
    $disk.Number
}

function Remove-SoakDisk([string]$path) {
    if (Test-Path -LiteralPath $path) {
        try { Dismount-DiskImage -ImagePath $path -ErrorAction Stop | Out-Null } catch { }
        for ($i = 0; $i -lt 20; $i++) { try { Remove-Item -LiteralPath $path -Force -ErrorAction Stop; break } catch { Start-Sleep -Milliseconds 500 } }
    }
}

# The volume's content, all of it drawn from $seed.
function New-SoakContent([string]$root, [int]$seed, [int]$cluster, [bool]$many, [long]$budget) {
    $random = [Random]::new($seed)
    $bytes = { param([int]$n) $b = [byte[]]::new($n); $random.NextBytes($b); , $b }
    $made = [Collections.Generic.List[string]]::new()
    $written = 0L
    $null = New-Item -ItemType Directory -Path "$root\sizes"
    $sizes = @(0, 1, 511, 512, 513, 600, 1500, 4095, 4096, 4097, 65535, 65536, 65537, 200001, 1048577, ($cluster - 1), $cluster, ($cluster + 1), (3 * $cluster + 17)) | Where-Object { $_ -ge 0 } | Sort-Object -Unique
    foreach ($size in $sizes) { [IO.File]::WriteAllBytes("$root\sizes\f$size.bin", (& $bytes $size)); $written += $size }
    $made.Add("$($sizes.Count) files of boundary sizes")
    if ($many) {
        $count = $random.Next(20000, 100001)
        $per = $random.Next(200, 2001)
        for ($i = 0; $i -lt $count; $i++) {
            $dir = "$root\many\d{0:d4}" -f [int][Math]::Floor($i / $per)
            if ($i % $per -eq 0) { $null = New-Item -ItemType Directory -Path $dir }
            $n = $random.Next(0, 2500)
            [IO.File]::WriteAllBytes("$dir\f$i.dat", (& $bytes $n)); $written += $n
        }
        $made.Add("$count small files in directories of $per")
    } else {
        $directories = [Collections.Generic.List[string]]::new(); $directories.Add("$root\tree")
        $null = New-Item -ItemType Directory -Path "$root\tree"
        foreach ($d in 1..$random.Next(10, 80)) {
            $parent = $directories[$random.Next(0, $directories.Count)]
            $child = "$parent\d$d"; $null = New-Item -ItemType Directory -Path $child; $directories.Add($child)
        }
        $files = 0
        while ($written -lt $budget -and $files -lt 5000) {
            $roll = $random.NextDouble()
            $n = if ($roll -lt 0.6) { $random.Next(0, 4096) } elseif ($roll -lt 0.9) { $random.Next(4096, 262144) } elseif ($roll -lt 0.99) { $random.Next(262144, 4194304) } else { $random.Next(4194304, 33554432) }
            $dir = $directories[$random.Next(0, $directories.Count)]
            [IO.File]::WriteAllBytes("$dir\file$files.bin", (& $bytes $n)); $written += $n; $files++
        }
        $made.Add("$files files in $($directories.Count) directories, $([Math]::Round($written / 1MB)) MiB")
    }
    # Names: outside ASCII, long, with spaces and dots; none differ only by case.
    $null = New-Item -ItemType Directory -Path "$root\names"
    foreach ($name in @(([string][char]0x00DC + 'n' + [char]0x00EF + 'c' + [char]0x00F6 + 'd' + [char]0x00E9), ([string][char]0x65E5 + [char]0x672C + [char]0x8A9E), ([string][char]0x0444 + [char]0x0430 + [char]0x0439 + [char]0x043B),
            ([string][char]0x05E7 + [char]0x05D5 + [char]0x05D1 + [char]0x05E5), ([string][char]0xD83D + [char]0xDE00 + ' emoji'), 'with spaces and . dots .x', ('long-' * 40), '#percent%and&amp')) {
        [IO.File]::WriteAllBytes("$root\names\$name.txt", (& $bytes $random.Next(0, 3000)))
    }
    $made.Add('names outside ASCII, long and odd')
    # Named streams on files (a directory's named stream is refused).
    [IO.File]::WriteAllBytes("$root\streams.bin", (& $bytes 70000))
    foreach ($s in 0..$random.Next(1, 30)) { Set-Content -LiteralPath "$root\streams.bin" -Stream "s$s" -Value (& $bytes $random.Next(1, 100000)) -AsByteStream }
    $null = New-Item -ItemType File -Path "$root\only-a-stream.dat"
    Set-Content -LiteralPath "$root\only-a-stream.dat" -Stream 'only' -Value 'data only in a named stream' -Encoding ascii
    $made.Add('named streams')
    # Hard links, in one directory and across two.
    [IO.File]::WriteAllBytes("$root\linked.bin", (& $bytes 150000))
    $null = New-Item -ItemType HardLink -Path "$root\linked-second.bin" -Target "$root\linked.bin"
    $null = New-Item -ItemType HardLink -Path "$root\sizes\linked-elsewhere.bin" -Target "$root\linked.bin"
    $made.Add('hard links')
    # Sparse files with islands.
    $null = New-Item -ItemType File -Path "$root\sparse.bin"
    $null = & fsutil.exe sparse setflag "$root\sparse.bin"
    $stream = [IO.File]::Open("$root\sparse.bin", 'Open', 'Write'); $stream.SetLength(256MB)
    foreach ($island in 1..$random.Next(1, 200)) { $stream.Position = [long]$random.Next(0, 255) * 1MB + $random.Next(0, 1000); $chunk = & $bytes $random.Next(1, 300000); $stream.Write($chunk, 0, $chunk.Length) }
    $stream.Dispose()
    $made.Add('a sparse file')
    # NTFS compresses only on clusters of 4 KiB and smaller; the flag is not carried over.
    if ($cluster -le 4096) {
        [IO.File]::WriteAllBytes("$root\compressed.txt", [Text.Encoding]::ASCII.GetBytes(('compressible text ' * $random.Next(1000, 60000))))
        $null = & compact.exe /c "$root\compressed.txt"
        $made.Add('a compressed file')
    }
    # Two files grown in turns, so that each lies in many runs.
    $a = [IO.File]::Open("$root\fragmented-a.bin", 'Create'); $b = [IO.File]::Open("$root\fragmented-b.bin", 'Create')
    foreach ($turn in 0..$random.Next(10, 80)) { $chunk = & $bytes (2 * [Math]::Max($cluster, 4096) + 1); $a.Write($chunk, 0, $chunk.Length); $a.Flush($true); $b.Write($chunk, 0, $chunk.Length); $b.Flush($true) }
    $a.Dispose(); $b.Dispose()
    $made.Add('fragmented files')
    # Links: symbolic (absolute and relative) and a junction.
    $null = New-Item -ItemType Directory -Path "$root\links"
    $null = New-Item -ItemType SymbolicLink -Path "$root\links\absolute" -Target "$root\sizes\f4096.bin"
    Push-Location "$root\links"; try { $null = New-Item -ItemType SymbolicLink -Path 'relative' -Target '..\linked.bin' } finally { Pop-Location }
    $null = New-Item -ItemType Junction -Path "$root\links\junction" -Target "$root\sizes"
    $made.Add('symbolic links and a junction')
    # Attributes (not TEMPORARY or OFFLINE, which are refused), times, security, object IDs.
    # "V:" alone is the current directory of V:, not its root.
    # (System Volume Information is not the content's, and not readable.)
    $all = @(Get-ChildItem -LiteralPath "$($root.TrimEnd('\'))\" -Directory -Force | Where-Object { $_.Name -ne 'System Volume Information' -and -not $_.LinkType } |
        Get-ChildItem -Recurse -File -Force | Where-Object { -not $_.LinkType } | Select-Object -First 4000)
    if ($all.Count -lt 50) { throw "the content listing found $($all.Count) files under $root" }
    $epoch = [DateTime]::SpecifyKind([DateTime]::new(1990, 1, 1), [DateTimeKind]::Utc)
    foreach ($file in $all | Get-Random -Count ([Math]::Min(300, $all.Count)) -SetSeed ($seed + 1)) {
        $when = $epoch.AddSeconds($random.NextDouble() * 1.2e9).AddTicks($random.Next(0, 10000000))
        [IO.File]::SetCreationTimeUtc($file.FullName, $when); [IO.File]::SetLastWriteTimeUtc($file.FullName, $when.AddDays($random.Next(0, 3000)))
    }
    $null = New-Item -ItemType Directory -Path "$root\secured"
    [IO.File]::WriteAllBytes("$root\secured\private.bin", (& $bytes 5000))
    $null = & icacls.exe "$root\secured" /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX'
    $null = & icacls.exe "$root\sizes\f1.bin" /grant '*S-1-1-0:(R)'
    foreach ($file in $all | Get-Random -Count ([Math]::Min(20, $all.Count)) -SetSeed ($seed + 2)) { $null = & fsutil.exe objectid create $file.FullName 2>&1 }
    # Attributes last: a read-only file refuses new times.
    $flags = @([IO.FileAttributes]::ReadOnly, [IO.FileAttributes]::Hidden, [IO.FileAttributes]::System, [IO.FileAttributes]::Archive, [IO.FileAttributes]::NotContentIndexed)
    foreach ($file in $all | Get-Random -Count ([Math]::Min(200, $all.Count)) -SetSeed ($seed + 3)) {
        [IO.File]::SetAttributes($file.FullName, [IO.File]::GetAttributes($file.FullName) -bor $flags[$random.Next(0, $flags.Count)])
    }
    $made.Add('attributes, times, security descriptors, object IDs')
    $null = New-Item -ItemType Directory -Path "$root\empty directory"
    $null = New-Item -ItemType File -Path "$root\empty.dat"
    $made -join '; '
}

function Capture([string]$path) {
    $said = & $manifest capture --root "${letter}:\" --output $path 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "lab-volume-manifest capture failed ($LASTEXITCODE): $said" }
}

function Wait-Volume([string]$fileSystem) {
    for ($i = 0; $i -lt 120; $i++) {
        $volume = Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue
        if ($volume -and $volume.FileSystem -eq $fileSystem) { return $volume }
        Start-Sleep -Milliseconds 500
    }
    $volume = Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue
    throw "${letter}: is $(if ($volume) { "$($volume.FileSystem) $($volume.HealthStatus)" } else { 'not mounted' }), not $fileSystem"
}

$started = Get-Date
$results = [Collections.Generic.List[object]]::new()
$failed = $null
"soak of $converter ($((& $converter --version 2>$null) -join ' ')) for $Minutes minutes$(if ($Rounds) { " or $Rounds rounds" }); profiles $($Profile -join ', '); first seed $Seed"
"disks in $Disks, working storage in $Scratch, records in $Records, volume ${letter}:"
for ($round = 1; ; $round++) {
    if ($Rounds -and $round -gt $Rounds) { break }
    if (((Get-Date) - $started).TotalMinutes -ge $Minutes) { break }
    $roundSeed = $Seed + $round - 1
    $draw = [Random]::new($roundSeed)
    $kind = $Profile[($round - 1) % $Profile.Count]
    # (A VHDX made by diskpart has 4 KiB physical sectors: no 512-byte clusters.)
    $ntfsCluster = @(4096, 4096, 4096, 8192, 16384, 32768, 65536)[$draw.Next(0, 7)]
    $refsCluster = @(4096, 65536)[$draw.Next(0, 2)]
    $gib = if ($kind -eq 'many') { 8 } else { $draw.Next(2, 7) }
    $hold = switch ($kind) { 'resume' { $holdPoints[$draw.Next(0, $holdPoints.Count)] } 'rollback' { $rollbackPoints[$draw.Next(0, $rollbackPoints.Count)] } default { '' } }
    $endAfter = if ($kind -eq 'cancel') { [Math]::Round(0.5 + $draw.NextDouble() * 40, 1) } else { 0 }
    $name = 'r{0:d3}-{1}-{2}' -f $round, $kind, $roundSeed
    $dir = Join-Path $Records $name
    $null = New-Item -ItemType Directory -Force -Path $dir
    $vhd = Join-Path $Disks "$name.vhdx"
    $work = Join-Path $Scratch $name
    $result = [ordered]@{ round = $round; profile = $kind; seed = $roundSeed; ntfs_cluster = $ntfsCluster; refs_cluster = $refsCluster; disk_gib = $gib
        hold_at = $hold; end_after_seconds = $endAfter; content = ''; convert_seconds = $null; recovery = ''; outcome = ''; detail = '' }
    Say "round ${round}: $kind, seed $roundSeed, NTFS clusters of $ntfsCluster, ReFS clusters of $refsCluster, a $gib GiB disk$(if ($hold) { ", held at $hold" })$(if ($endAfter) { ", ended after $endAfter s" })"
    try {
        $null = New-SoakDisk $vhd $gib $ntfsCluster
        $result.content = New-SoakContent "${letter}:" $roundSeed $ntfsCluster ($kind -eq 'many') ([Math]::Min(1.5GB, [long]$gib * 1GB / 4))
        Say "  content: $($result.content)"
        Capture (Join-Path $dir 'before.jsonl')
        $null = New-Item -ItemType Directory -Force -Path $work
        $arguments = @('--drive', $letter, '--scratch-directory', $work, '--target-cluster-bytes', "$refsCluster")
        if ($hold) { $arguments += @('--lab-hold-at', $hold, '--acknowledge-lab-hold-never-completes') }
        $run = Invoke-Converter $arguments (Join-Path $dir 'convert') $hold $endAfter
        $result.convert_seconds = $run.seconds
        if ($hold -and -not $run.held) { throw "the run ended with exit $($run.exit) without reporting its hold at $hold" }
        Say "  ntfs2refs $($arguments -join ' '): $(if ($run.held) { "held at $hold after $($run.seconds) s" } elseif ($run.ended) { "ended after $($run.seconds) s" } else { "exit $($run.exit) after $($run.seconds) s" })"
        $expect = 'ReFS'
        if ($run.ended) {
            $recover = [regex]::Match($run.said, $recoverLine, 'Multiline')
            $cancel = [regex]::Match($run.said, $cancelLine)
            $recovery = $null
            if ($kind -eq 'rollback' -and $recover.Success) { $recovery = @('--recover', $recover.Groups[1].Value, '--recovery-sha256', $recover.Groups[2].Value, '--rollback'); $expect = 'NTFS' }
            elseif ($recover.Success) { $recovery = @('--recover', $recover.Groups[1].Value, '--recovery-sha256', $recover.Groups[2].Value) }
            elseif ($cancel.Success) { $recovery = @('--recover', $cancel.Groups[1].Value, '--recovery-sha256', $cancel.Groups[2].Value, '--rollback'); $expect = 'NTFS' }
            elseif ($hold) { throw "the run was held at $hold but had printed no `"To recover:`" line" }
            else { $expect = 'NTFS' }
            if ($recovery) {
                $result.recovery = $recovery -join ' '
                $again = Invoke-Converter $recovery (Join-Path $dir 'recover')
                Say "  ntfs2refs $($result.recovery): exit $($again.exit) after $($again.seconds) s"
                if ($again.exit -ne 0) { throw "the recovery ended with exit $($again.exit): $(($again.stderr -split "`n" | Where-Object { $_ -match '^error' } | Select-Object -Last 1))" }
            } else {
                $result.recovery = 'none printed: the volume has to be as it was'
                Say "  the run had printed no recovery command; ${letter}: has to be NTFS as it was"
            }
        } elseif ($run.exit -ne 0) {
            throw "the conversion ended with exit $($run.exit): $(($run.stderr -split "`n" | Where-Object { $_ -match '^error' } | Select-Object -Last 1))"
        }
        $volume = Wait-Volume $expect
        Capture (Join-Path $dir 'after.jsonl')
        $compare = @('compare', '--before', (Join-Path $dir 'before.jsonl'), '--after', (Join-Path $dir 'after.jsonl'), '--report', (Join-Path $dir 'report.json'))
        if ($expect -eq 'NTFS') { $compare += '--exact' }
        $summary = & $manifest @compare 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            $first = try { (Get-Content -Raw -LiteralPath (Join-Path $dir 'report.json') | ConvertFrom-Json).differences | Select-Object -First 12 | ForEach-Object { "$($_.path): $($_.kind): $($_.what)" } } catch { @("(no report: $_)") }
            foreach ($line in $first) { Say "    differs: $line" }
            throw "the listings differ ($(if ($expect -eq 'NTFS') { 'exact' } else { 'with the allowances of a conversion' })): $($summary.Trim()); first: $($first -join ' | ')"
        }
        $result.outcome = if ($expect -eq 'ReFS') { 'converted' } else { 'ntfs-as-before' }
        Say "  ${letter}: is $($volume.FileSystem) $($volume.HealthStatus); listings $(if ($expect -eq 'NTFS') { 'identical' } else { 'match' })"
        foreach ($leaf in 'before.jsonl', 'after.jsonl') { Remove-Item -LiteralPath (Join-Path $dir $leaf) -Force -ErrorAction SilentlyContinue }
    } catch {
        $result.outcome = 'FAILED'; $result.detail = "$_"
        Say "  FAILED: $_"
        try { & $converter --list 2>&1 | Out-File -LiteralPath (Join-Path $dir 'list-after-failure.txt') -Encoding utf8 } catch { }
        $failed = $result
    } finally {
        Remove-SoakDisk $vhd
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
        $results.Add([pscustomobject]$result)
        ([pscustomobject]$result | ConvertTo-Json -Compress) | Add-Content -LiteralPath (Join-Path $Records 'rounds.jsonl') -Encoding utf8
    }
    if ($failed) { break }
}

$lines = @('| Round | Profile | Seed | NTFS / ReFS clusters | Hold or end | Seconds | Outcome |', '|---|---|---|---|---|---|---|')
foreach ($r in $results) { $lines += "| $($r.round) | $($r.profile) | $($r.seed) | $($r.ntfs_cluster) / $($r.refs_cluster) | $(if ($r.hold_at) { $r.hold_at } elseif ($r.end_after_seconds) { "$($r.end_after_seconds) s" } else { '' }) | $($r.convert_seconds) | $($r.outcome)$(if ($r.detail) { ': ' + ($r.detail -replace '\|', '/') }) |" }
$headline = "soak: $($results.Count) rounds in $([Math]::Round(((Get-Date) - $started).TotalMinutes)) minutes, $(@($results | Where-Object outcome -ne 'FAILED').Count) passed$(if ($failed) { "; round $($failed.round) failed (reproduce: -Profile $($failed.profile) -Seed $($failed.seed) -Rounds 1)" })"
$headline
$lines
if ($env:GITHUB_STEP_SUMMARY) { (@("### $headline", '') + $lines) | Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Encoding utf8 }
if ($failed -or $results.Count -eq 0) { exit 1 }
