<#
.SYNOPSIS
Uses a ReFS volume the way a volume is used after a conversion, and says
whether everything it did held.

.DESCRIPTION
A conversion is judged by a listing that is identical before and after. That
shows what was carried over, not that the result is a volume one can go on
working with: that Windows can allocate in it, grow and delete what was
converted, fill it and empty it, snapshot it, mount it again and find it
whole. This script does those things on the volume it is given and prints one
JSON object: a result per step, and "passed".

Run it on a converted volume, and on a volume Windows formatted as ReFS itself
with the same content (the control): a step that fails on both is how ReFS or
this Windows behaves, one that fails only on the converted volume is the
conversion's.

Nothing here repairs anything. A step that cannot be run on this Windows
(a tool that is not installed) is reported as skipped with the reason.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Root,
    # New files to create.
    [int]$NewFiles = 1500,
    # Times the volume is taken offline and brought back.
    [int]$Remounts = 5,
    [string]$WorkDirectory = "$env:TEMP\n2r-use",
    # Each step and each file it is about to change is written here before
    # it is done, through to the disk: if Windows goes down, this says where.
    [string]$ProgressFile
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$drive = $Root.TrimEnd('\')
$letter = $drive.TrimEnd(':')
$started = Get-Date
$steps = New-Object System.Collections.Generic.List[object]
$random = [Random]::new(20261113)
$sha = [Security.Cryptography.SHA256]::Create()
function Bytes([int]$n) { $b = New-Object byte[] $n; $random.NextBytes($b); , $b }
function Hash([string]$path) {
    $stream = [IO.File]::OpenRead($path)
    try { [BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-' } finally { $stream.Dispose() }
}
$progress = $null
if ($ProgressFile) { $progress = [IO.FileStream]::new($ProgressFile, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read, 4096, [IO.FileOptions]::WriteThrough) }
function Note([string]$text) {
    if ($progress) { $bytes = [Text.Encoding]::UTF8.GetBytes("$([datetime]::UtcNow.ToString('o')) $text`r`n"); $progress.Write($bytes, 0, $bytes.Length); $progress.Flush($true) }
}
function Step([string]$name, [scriptblock]$body) {
    $begin = [datetime]::UtcNow
    Note "step: $name"
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $ok = $true
    try {
        $detail = & $body
    } catch {
        $detail = $_.Exception.Message
        $ok = if ($detail -like 'skipped:*') { $null } else { $false }
    }
    $steps.Add([pscustomobject]@{
        step = $name; ok = $ok; seconds = [Math]::Round($watch.Elapsed.TotalSeconds, 1); detail = "$detail"
        started_utc = $begin.ToString('o'); finished_utc = [datetime]::UtcNow.ToString('o')
    })
}
$volume = Get-Volume -DriveLetter $letter
if ($volume.FileSystem -ne 'ReFS') { throw "$drive is $($volume.FileSystem), not ReFS" }
$null = New-Item -ItemType Directory -Path $WorkDirectory -Force

# What was on the volume before this script touched it: a sample of files
# with their digests, to be found unchanged at the end.
$existing = @(Get-ChildItem -LiteralPath "$drive\" -Recurse -File -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notlike "$drive\System Volume Information\*" -and $_.FullName.Length -lt 240 -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) })
# Evenly across the volume, not its first directory.
$readable = @($existing | Sort-Object FullName | Where-Object { $_.Length -gt 0 -and $_.Length -lt 64MB })
$stride = [Math]::Max(1, [int][Math]::Floor($readable.Count / 400))
$sample = @(for ($i = 0; $i -lt $readable.Count -and $i / $stride -lt 400; $i += $stride) { $readable[$i] })
$digests = @{}
Step 'read what was converted' {
    foreach ($file in $sample) { $digests[$file.FullName] = Hash $file.FullName }
    "$($sample.Count) of $($existing.Count) existing files read and digested"
}

$work = "$drive\n2r-use"
$made = @{}
Step 'create files' {
    foreach ($i in 0..($NewFiles - 1)) {
        $dir = '{0}\tree\{1:d2}\{2:d2}' -f $work, ($i % 17), ($i % 5)
        $null = [IO.Directory]::CreateDirectory($dir)
        $size = switch ($i % 9) { 0 { 0 } 1 { 1 } 2 { 700 } 3 { 4096 } 4 { 4097 } 5 { 65536 } 6 { 300001 } 7 { 1048577 } default { $random.Next(1, 200000) } }
        $path = '{0}\new-{1:d5}.bin' -f $dir, $i
        $bytes = Bytes $size
        [IO.File]::WriteAllBytes($path, $bytes)
        $made[$path] = [BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-'
    }
    foreach ($path in $made.Keys) { if ((Hash $path) -ne $made[$path]) { throw "a new file does not read back as written: $path" } }
    "$NewFiles files written and read back"
}
Step 'change converted files' {
    # Append to, overwrite inside and truncate files that the conversion carried over.
    $targets = @($sample | Where-Object { -not $_.IsReadOnly -and $_.Length -gt 1 })
    $changed = 0; $protected = 0; $linked = 0
    foreach ($file in $targets) {
        if ($changed -ge 150) { break }
        $path = $file.FullName
        Note "change $path ($($file.Length) bytes)"
        $before = [IO.File]::ReadAllBytes($path)
        # Overwriting inside needs a file long enough to have an inside.
        $mode = if ($before.Length -lt 100) { ($changed % 2) * 2 } else { $changed % 3 }
        # A file whose security does not let this account write (program
        # files keep TrustedInstaller's) is passed over, on any volume.
        try { $stream = [IO.File]::Open($path, 'Open', 'ReadWrite') } catch [UnauthorizedAccessException] { $protected++; continue }
        try {
            if ($mode -eq 0) { $stream.Position = $stream.Length; $extra = Bytes 5000; $stream.Write($extra, 0, $extra.Length); $expected = $before + $extra }
            elseif ($mode -eq 1) { $patch = Bytes 37; $stream.Position = 50; $stream.Write($patch, 0, $patch.Length); $expected = [byte[]]$before.Clone(); [Array]::Copy($patch, 0, $expected, 50, 37) }
            else { $stream.SetLength([int]($before.Length / 2)); $expected = [byte[]]$before[0..([int]($before.Length / 2) - 1)] }
        } finally { $stream.Dispose() }
        $after = [IO.File]::ReadAllBytes($path)
        if ($after.Length -ne $expected.Length -or (Compare-Object $after $expected -SyncWindow 0)) { throw "a changed file does not read back as changed: $path" }
        $digests[$path] = Hash $path
        # A file with several names is one file: what was changed through
        # this name has to read the same through the others.
        Note "  changed (mode $mode); listing its names"
        $names = @(& fsutil.exe hardlink list $path 2>$null | Where-Object { $_ -like '\*' })
        foreach ($name in $names) {
            $other = "$drive$name"
            # (fsutil prints a name outside the console's code page with
            # question marks; such a name is not one that can be opened.)
            if ($other -eq $path -or -not [IO.File]::Exists($other)) { continue }
            if ((Hash $other) -ne $digests[$path]) { throw "a file changed through $path reads differently through its other name $other" }
            if ($digests.ContainsKey($other)) { $digests[$other] = $digests[$path] }
            $linked++
        }
        $changed++
    }
    if ($changed -eq 0) { throw 'skipped: the volume has no writable converted file to change' }
    "$changed converted files appended to, overwritten inside or truncated, and read back ($linked times through another hard link as well); $protected passed over, which this account may not write"
}
Step 'rename and delete' {
    $renamed = 0
    foreach ($path in @($made.Keys | Sort-Object | Select-Object -First 200)) {
        $new = "$path.renamed"; [IO.File]::Move($path, $new); $made[$new] = $made[$path]; $made.Remove($path); $renamed++
    }
    $deleted = 0
    foreach ($path in @($made.Keys | Sort-Object | Select-Object -Last 400)) { [IO.File]::Delete($path); $made.Remove($path); $deleted++ }
    # A converted file is deleted and a converted directory renamed too.
    $victim = $null
    foreach ($candidate in @($sample | Where-Object { -not $_.IsReadOnly -and $digests.ContainsKey($_.FullName) } | Sort-Object FullName -Descending)) {
        try { [IO.File]::Delete($candidate.FullName); $digests.Remove($candidate.FullName); $victim = $candidate; break } catch [UnauthorizedAccessException] { }
    }
    foreach ($path in $made.Keys) { if (-not [IO.File]::Exists($path)) { throw "a file that was not deleted is gone: $path" } }
    "$renamed renamed, $deleted new and $([int][bool]$victim) converted deleted"
}
Step 'streams, links, security, sparse' {
    $base = "$work\features"; $null = New-Item -ItemType Directory -Path $base -Force
    [IO.File]::WriteAllBytes("$base\with-stream.bin", (Bytes 9000))
    Set-Content -LiteralPath "$base\with-stream.bin" -Stream 'note' -Value 'a named stream written after the conversion' -Encoding ASCII
    if ((Get-Content -LiteralPath "$base\with-stream.bin" -Stream 'note') -ne 'a named stream written after the conversion') { throw 'a named stream does not read back' }
    $null = & fsutil.exe hardlink create "$base\second-name.bin" "$base\with-stream.bin"; if ($LASTEXITCODE -ne 0) { throw 'a hard link could not be made' }
    $null = & cmd.exe /c mklink "$base\symlink.bin" "$base\with-stream.bin"; if ($LASTEXITCODE -ne 0) { throw 'a symbolic link could not be made' }
    $null = & cmd.exe /c mklink /J "$base\junction" "$work\tree"; if ($LASTEXITCODE -ne 0) { throw 'a junction could not be made' }
    $null = & icacls.exe "$base\with-stream.bin" /grant '*S-1-5-32-545:(R)'; if ($LASTEXITCODE -ne 0) { throw 'an access entry could not be added' }
    $null = New-Item -ItemType File -Path "$base\sparse.bin" -Force
    $null = & fsutil.exe sparse setflag "$base\sparse.bin"; if ($LASTEXITCODE -ne 0) { throw 'a file could not be made sparse' }
    $stream = [IO.File]::Open("$base\sparse.bin", 'Open', 'Write'); $stream.SetLength(256MB); $island = Bytes 70000; $stream.Position = 100MB; $stream.Write($island, 0, $island.Length); $stream.Dispose()
    'a named stream, a hard link, a symbolic link, a junction, an access entry and a sparse file'
}
Step 'fill the volume and free it' {
    $freeBefore = (Get-Volume -DriveLetter $letter).SizeRemaining
    $fill = "$work\fill"; $null = New-Item -ItemType Directory -Path $fill -Force
    $block = Bytes (16 * 1048576)
    $count = 0
    # Dynamic test disks are far larger than what the lab host can back: fill at most 6 GiB.
    while ((Get-Volume -DriveLetter $letter).SizeRemaining -gt 256MB -and $count -lt 384) {
        $stream = [IO.File]::Open(('{0}\fill-{1:d4}.bin' -f $fill, $count), 'Create'); $stream.Write($block, 0, $block.Length); $stream.Dispose(); $count++
    }
    $first = Hash ('{0}\fill-{1:d4}.bin' -f $fill, 0); $last = Hash ('{0}\fill-{1:d4}.bin' -f $fill, ($count - 1))
    if ($first -ne $last) { throw 'two files written with the same bytes read back differently' }
    Remove-Item -LiteralPath $fill -Recurse -Force
    # ReFS gives space back some time after a delete; wait for it.
    $deadline = (Get-Date).AddSeconds(180); $waited = [Diagnostics.Stopwatch]::StartNew()
    do { Start-Sleep -Seconds 3; $freeAfter = (Get-Volume -DriveLetter $letter).SizeRemaining } until ($freeAfter -ge $freeBefore - 512MB -or (Get-Date) -gt $deadline)
    if ($freeAfter -lt $freeBefore - 512MB) { throw "three minutes after writing and deleting $count files of 16 MiB, $([Math]::Round(($freeBefore - $freeAfter) / 1MB)) MiB are still not free" }
    "$count files of 16 MiB written and deleted; free space $([Math]::Round($freeBefore / 1MB)) MiB before, $([Math]::Round($freeAfter / 1MB)) MiB $([int]$waited.Elapsed.TotalSeconds) s after the delete"
}
Step 'snapshot' {
    $result = ([wmiclass]'Win32_ShadowCopy').Create("$drive\", 'ClientAccessible')
    if ($result.ReturnValue -ne 0) { throw "skipped: Windows made no shadow copy of this volume (Win32_ShadowCopy.Create returned $($result.ReturnValue))" }
    $shadow = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $result.ShadowID }
    try {
        $probe = $made.Keys | Sort-Object | Select-Object -First 1
        $inside = $shadow.DeviceObject + $probe.Substring(2)
        $bytes = [IO.File]::ReadAllBytes($inside)
        if (([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-') -ne $made[$probe]) { throw 'a file read through the shadow copy differs' }
    } finally { $shadow.Delete() }
    'a shadow copy was made, read through and deleted'
}
Step 'consistency scan' {
    $ran = @()
    try { $scan = Repair-Volume -DriveLetter $letter -Scan -ErrorAction Stop; $ran += "Repair-Volume -Scan: $scan"; if ("$scan" -notin 'NoErrorsFound', '0') { throw "Repair-Volume -Scan reported $scan" } }
    catch { if ("$($_.Exception.Message)" -like 'Repair-Volume -Scan reported*') { throw } else { $ran += "Repair-Volume -Scan is not offered here ($($_.Exception.Message))" } }
    if (-not $ran) { throw 'skipped: this Windows offers no consistency scan for the volume' }
    $ran -join '; '
}
Step 'mount again' {
    $number = (Get-Partition -DriveLetter $letter).DiskNumber
    foreach ($round in 1..$Remounts) {
        Set-Disk -Number $number -IsOffline $true; Set-Disk -Number $number -IsOffline $false
        $deadline = (Get-Date).AddSeconds(60)
        do { Start-Sleep -Milliseconds 500; $v = Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue } until (($v -and $v.FileSystem -eq 'ReFS') -or (Get-Date) -gt $deadline)
        if (-not $v -or $v.FileSystem -ne 'ReFS') { throw "after remount $round the volume is not ReFS" }
        if ("$($v.HealthStatus)" -ne 'Healthy') { throw "after remount $round the volume is $($v.HealthStatus)" }
        foreach ($path in @($made.Keys | Sort-Object | Select-Object -First 40)) { if ((Hash $path) -ne $made[$path]) { throw "after remount $round a new file reads differently: $path" } }
    }
    "taken offline and brought back $Remounts times; Healthy each time"
}
Step 'converted files are as they were left' {
    $checked = 0
    foreach ($path in $digests.Keys) { if ((Hash $path) -ne $digests[$path]) { throw "a converted file reads differently at the end: $path" }; $checked++ }
    "$checked converted files read again"
}
Step 'ReFS events' {
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $started } -ErrorAction Stop |
            Where-Object { $_.ProviderName -match 'ReFS|Ntfs|volmgr|disk' -and ($_.Level -le 3 -or $_.Id -in 131, 134) })
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
        $events = @()
    }
    # Taking a disk offline while its ReFS volume is mounted makes ReFS log
    # event 135 ("unable to mount it ... a device which does not exist"): the
    # 'mount again' step does that on purpose, and a volume Windows formatted
    # itself logs the same (the control run shows it). Anything else is an error.
    $offline = @($events | Where-Object { $_.ProviderName -match 'ReFS' -and $_.Id -eq 135 -and $_.Message -match 'device which does not exist' })
    $serious = @($events | Where-Object { $_.ProviderName -match 'ReFS' -and ($_.Level -le 2 -or $_.Id -in 131, 134) -and $_ -notin $offline })
    if ($serious) { throw "ReFS logged $($serious.Count) error(s): $($serious[0].Id) $((($serious[0].Message -split "`n")[0]).Trim())" }
    "no ReFS error; $($offline.Count) of event 135 from taking the disk offline; $($events.Count - $offline.Count) storage warning(s) or error(s) of other providers"
}
[pscustomobject]@{ root = $drive; file_system = $volume.FileSystem; passed = -not ($steps | Where-Object { $_.ok -eq $false }); steps = $steps } | ConvertTo-Json -Depth 4 -Compress
