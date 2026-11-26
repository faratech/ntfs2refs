<#
.SYNOPSIS
Puts named NTFS features on a data volume in the lab's control OS.

.DESCRIPTION
Invoke-DataVolumeAttempt.ps1 runs this in the guest after it has filled the
volume. Each feature is something a volume that has been used has and a
freshly generated one does not, or something the converter must refuse.
Prints one JSON object: what was made, per feature, and what could not be.
A feature that cannot be made is an error, never a silent skip: the attempt
would otherwise claim to have covered it.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string[]]$Features,
    # Entries of the large directory.
    [int]$DirectoryEntries = 20000,
    # Size of the dense file, in GiB.
    [int]$BigFileGB = 6,
    # Files of the 'manyfiles' feature.
    [int]$FileCount = 500000,
    # A directory of the control OS to copy onto the volume with its security.
    [string]$CopyFrom = 'C:\Program Files'
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$drive = $Root.TrimEnd('\')
$letter = $drive.TrimEnd(':')
$made = [ordered]@{}
$random = [Random]::new(20261113)
function Bytes([int]$n) { $b = New-Object byte[] $n; $random.NextBytes($b); , $b }
function Run([string]$exe, [string[]]$arguments) {
    $text = & $exe $arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "$exe $($arguments -join ' ') exited ${LASTEXITCODE}: $($text.Trim())" }
    $text
}
function ObjectId([string]$path) {
    $text = & fsutil.exe objectid query $path 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0 -and $text -match 'Object ID\s*:\s*([0-9a-fA-F]+)') { $Matches[1] } else { $null }
}

foreach ($feature in $Features) {
    $dir = "$drive\feature-$feature"
    switch ($feature) {
        'objectids' {
            # What link tracking leaves on a file: an object ID. One is made
            # outright; a shortcut shows whether Windows makes one by itself.
            $null = New-Item -ItemType Directory -Path $dir -Force
            [IO.File]::WriteAllBytes("$dir\has-object-id.bin", (Bytes 30000))
            $null = Run 'fsutil.exe' @('objectid', 'create', "$dir\has-object-id.bin")
            [IO.File]::WriteAllBytes("$dir\shortcut-target.txt", (Bytes 2000))
            $before = ObjectId "$dir\shortcut-target.txt"
            $shell = New-Object -ComObject WScript.Shell
            $link = $shell.CreateShortcut("$dir\shortcut.lnk"); $link.TargetPath = "$dir\shortcut-target.txt"; $link.Save()
            # (fsutil cannot open a directory to give it one; a shortcut may.)
            $null = New-Item -ItemType Directory -Path "$dir\shortcut target directory" -Force
            $link = $shell.CreateShortcut("$dir\shortcut to a directory.lnk"); $link.TargetPath = "$dir\shortcut target directory"; $link.Save()
            $made[$feature] = [ordered]@{ explicit = (ObjectId "$dir\has-object-id.bin"); shortcut_target_before = $before
                shortcut_target_after = (ObjectId "$dir\shortcut-target.txt"); shortcut_directory_after = (ObjectId "$dir\shortcut target directory") }
        }
        'manyobjectids' {
            # Enough object IDs for the volume's object-ID index to outgrow
            # its root: what a volume has after years of shortcuts.
            Add-Type -TypeDefinition @'
using System; using System.ComponentModel; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles;
public static class N2RLabObjectId {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(SafeFileHandle handle, uint code, IntPtr input, uint inputSize, byte[] output, uint outputSize, out uint returned, IntPtr overlapped);
    public static void Create(string path) {
        // GENERIC_WRITE, share all, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS; FSCTL_CREATE_OR_GET_OBJECT_ID.
        using (SafeFileHandle handle = CreateFileW(path, 0x40000000, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero)) {
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "opening " + path);
            byte[] output = new byte[64]; uint returned;
            if (!DeviceIoControl(handle, 0x000900C0, IntPtr.Zero, 0, output, 64, out returned, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "giving " + path + " an object ID");
        }
    }
}
'@
            $null = New-Item -ItemType Directory -Path $dir -Force
            $small = Bytes 24
            foreach ($i in 0..($DirectoryEntries - 1)) {
                $path = '{0}\with-id-{1:d6}.dat' -f $dir, $i
                [IO.File]::WriteAllBytes($path, $small); [N2RLabObjectId]::Create($path)
            }
            foreach ($i in 0..49) { $sub = '{0}\directory-{1:d2}' -f $dir, $i; $null = New-Item -ItemType Directory -Path $sub -Force; [N2RLabObjectId]::Create($sub) }
            $made[$feature] = "$DirectoryEntries files and 50 directories with object IDs; one is $(ObjectId ('{0}\with-id-{1:d6}.dat' -f $dir, 0))"
        }
        'security' {
            # Explicit entries, a deny, a protected directory, another owner, an audit entry.
            $null = New-Item -ItemType Directory -Path "$dir\protected\child" -Force
            foreach ($leaf in 'explicit.txt', 'owned.txt', 'audited.txt', 'protected\inside.txt', 'protected\child\deeper.txt') { [IO.File]::WriteAllBytes("$dir\$leaf", (Bytes 1200)) }
            $null = Run 'icacls.exe' @("$dir\explicit.txt", '/grant', '*S-1-5-32-545:(R)', '/deny', '*S-1-5-32-546:(W)')
            $null = Run 'icacls.exe' @("$dir\protected", '/inheritance:d')
            $null = Run 'icacls.exe' @("$dir\protected", '/grant', '*S-1-5-11:(OI)(CI)(M)')
            $null = Run 'icacls.exe' @("$dir\owned.txt", '/setowner', '*S-1-5-18')
            $acl = Get-Acl -LiteralPath "$dir\audited.txt" -Audit
            $acl.AddAuditRule((New-Object Security.AccessControl.FileSystemAuditRule('Everyone', 'Write', 'Failure')))
            Set-Acl -LiteralPath "$dir\audited.txt" -AclObject $acl
            $made[$feature] = [ordered]@{ explicit = (Get-Acl -LiteralPath "$dir\explicit.txt").Sddl; owned = (Get-Acl -LiteralPath "$dir\owned.txt").Owner
                audited = (Get-Acl -LiteralPath "$dir\audited.txt" -Audit).Sddl }
        }
        'ea' {
            # Extended attributes, which nothing in PowerShell sets.
            Add-Type -TypeDefinition @'
using System; using System.IO; using System.Runtime.InteropServices; using System.Text; using Microsoft.Win32.SafeHandles;
public static class N2RLabEa {
    [StructLayout(LayoutKind.Sequential)] struct IoStatusBlock { public IntPtr Status; public IntPtr Information; }
    [DllImport("ntdll.dll")] static extern int NtSetEaFile(SafeFileHandle handle, out IoStatusBlock io, byte[] buffer, int length);
    public static void Set(string path, string name, byte[] value) {
        byte[] n = Encoding.ASCII.GetBytes(name);
        byte[] b = new byte[(8 + n.Length + 1 + value.Length + 3) & ~3];
        b[5] = (byte)n.Length; b[6] = (byte)(value.Length & 0xff); b[7] = (byte)(value.Length >> 8);
        Buffer.BlockCopy(n, 0, b, 8, n.Length); Buffer.BlockCopy(value, 0, b, 8 + n.Length + 1, value.Length);
        using (var file = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read)) {
            IoStatusBlock io; int status = NtSetEaFile(file.SafeFileHandle, out io, b, b.Length);
            if (status != 0) throw new IOException("NtSetEaFile " + name + " on " + path + ": 0x" + status.ToString("x8"));
        }
    }
}
'@
            $null = New-Item -ItemType Directory -Path $dir -Force
            [IO.File]::WriteAllBytes("$dir\one-ea.bin", (Bytes 5000)); [N2RLabEa]::Set("$dir\one-ea.bin", 'LAB.SMALL', [Text.Encoding]::ASCII.GetBytes('a small value'))
            [IO.File]::WriteAllBytes("$dir\several-eas.bin", (Bytes 90000))
            foreach ($n in 1..5) { [N2RLabEa]::Set("$dir\several-eas.bin", "LAB.NUMBER$n", (Bytes (200 * $n))) }
            [IO.File]::WriteAllBytes("$dir\large-ea.bin", (Bytes 10)); [N2RLabEa]::Set("$dir\large-ea.bin", 'LAB.LARGE', (Bytes 30000))
            $made[$feature] = 'one, five and one large (30,000-byte) extended attribute'
        }
        'links' {
            # Reparse points the converter carries over: junction and symbolic links.
            $null = New-Item -ItemType Directory -Path "$dir\real directory" -Force
            [IO.File]::WriteAllBytes("$dir\real directory\real.txt", (Bytes 800))
            foreach ($arguments in @(@('/J', "$dir\junction", "$dir\real directory"), @('/D', "$dir\directory symlink", "$dir\real directory"),
                    @("$dir\file symlink.txt", "$dir\real directory\real.txt"), @("$dir\relative symlink.txt", 'real directory\real.txt'), @('/D', "$dir\dangling", "$drive\does-not-exist"))) {
                $text = & cmd.exe /c mklink @arguments 2>&1 | Out-String
                if ($LASTEXITCODE -ne 0) { throw "mklink $($arguments -join ' '): $($text.Trim())" }
            }
            $made[$feature] = 'a junction, a directory and a file symbolic link, a relative one and a dangling one'
        }
        'longpath' {
            # A path past the 260 characters of the old Win32 limit.
            $path = "\\?\$dir"
            foreach ($i in 1..8) { $path += '\' + ("segment-$i-of-a-long-path-").PadRight(40, 'x') }
            $null = [IO.Directory]::CreateDirectory($path)
            [IO.File]::WriteAllBytes("$path\at-the-end-of-a-long-path.bin", (Bytes 4000))
            $made[$feature] = "a file at a path of $($path.Length + 30) characters"
        }
        'deep' {
            $path = "\\?\$dir"
            foreach ($i in 1..40) { $path += "\level$i" }
            $null = [IO.Directory]::CreateDirectory($path)
            [IO.File]::WriteAllBytes("$path\bottom.txt", (Bytes 300))
            $made[$feature] = 'a file under 40 nested directories'
        }
        'bigdir' {
            # Enough entries for an index of several levels.
            $null = New-Item -ItemType Directory -Path $dir -Force
            $small = Bytes 40
            foreach ($i in 0..($DirectoryEntries - 1)) { [IO.File]::WriteAllBytes(('{0}\entry-{1:d7}-{2}.dat' -f $dir, $i, ($i * 2654435761 % 1000003)), $small) }
            $made[$feature] = "a directory of $DirectoryEntries entries"
        }
        'manyfiles' {
            # A volume of very many files, for measuring how a run grows
            # with their number: directories of 1,000 files under
            # directories of 100; nine files in ten small enough to live in
            # their file record, the tenth of 4 to 36 KiB.
            if (-not ('ManyFiles' -as [type])) {
                Add-Type -TypeDefinition @'
using System; using System.IO;
public static class ManyFiles {
    public static long Make(string root, int count) {
        var small = new byte[700]; var large = new byte[36 * 1024];
        new Random(7).NextBytes(small); new Random(8).NextBytes(large);
        long bytes = 0;
        for (int i = 0; i < count; i++) {
            string directory = Path.Combine(root, (i / 100000).ToString("d2"), (i / 1000).ToString("d5"));
            if (i % 1000 == 0) Directory.CreateDirectory(directory);
            uint mixed = unchecked((uint)i * 2654435761u);
            bool big = i % 10 == 9;
            int length = big ? 4096 + (int)(mixed % (32 * 1024)) : (int)(mixed % 700);
            var source = big ? large : small;
            source[0] = (byte)i; source[1] = (byte)(i >> 8); source[2] = (byte)(i >> 16);
            using (var file = new FileStream(Path.Combine(directory, "file-" + i.ToString("d7") + ".dat"), FileMode.CreateNew, FileAccess.Write, FileShare.None, 1))
                file.Write(source, 0, length);
            bytes += length;
        }
        return bytes;
    }
}
'@
            }
            $null = New-Item -ItemType Directory -Path $dir -Force
            $clock = [Diagnostics.Stopwatch]::StartNew()
            $bytes = [ManyFiles]::Make($dir, $FileCount)
            $made[$feature] = "$FileCount files in $([int][Math]::Ceiling($FileCount / 1000)) directories, $([Math]::Round($bytes / 1MB)) MiB, made in $([int]$clock.Elapsed.TotalSeconds) s"
        }
        'bigfile' {
            # A dense file past 4 GiB, written in 64 MiB pieces.
            $null = New-Item -ItemType Directory -Path $dir -Force
            $piece = Bytes (64 * 1048576)
            $file = [IO.File]::Open("$dir\dense.bin", 'Create')
            foreach ($i in 1..($BigFileGB * 16)) { $piece[0] = [byte]($i -band 255); $piece[1] = [byte]($i -shr 8); $file.Write($piece, 0, $piece.Length) }
            $file.Dispose()
            $made[$feature] = "a dense file of $BigFileGB GiB"
        }
        'full' {
            # Fill the volume, free every second file, then write files that
            # have to take the holes: a nearly full, fragmented volume.
            $null = New-Item -ItemType Directory -Path "$dir\filler", "$dir\late" -Force
            $block = Bytes 1048576
            $index = 0
            while ((Get-Volume -DriveLetter $letter).SizeRemaining -gt 48MB) { [IO.File]::WriteAllBytes(('{0}\filler\f{1:d6}.bin' -f $dir, $index), $block); $index++ }
            for ($i = 0; $i -lt $index; $i += 2) { Remove-Item -LiteralPath ('{0}\filler\f{1:d6}.bin' -f $dir, $i) -Force }
            $late = 0
            while ((Get-Volume -DriveLetter $letter).SizeRemaining -gt 96MB) { [IO.File]::WriteAllBytes(('{0}\late\g{1:d4}.bin' -f $dir, $late), (Bytes (5 * 1048576 + 4097))); $late++ }
            $volume = Get-Volume -DriveLetter $letter
            $made[$feature] = [ordered]@{ fillers_kept = [int]($index / 2); late_files = $late; free_bytes = $volume.SizeRemaining; size_bytes = $volume.Size }
        }
        'copy' {
            # Real files with the security Windows gave them.
            $text = & robocopy.exe $CopyFrom "$dir" /E /COPYALL /SL /XJ /R:0 /W:0 /NFL /NDL /NP /NJH 2>&1 | Out-String
            if ($LASTEXITCODE -ge 16) { throw "robocopy $CopyFrom exited ${LASTEXITCODE}: $($text.Trim())" }
            $counted = Get-ChildItem -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum
            $made[$feature] = [ordered]@{ from = $CopyFrom; robocopy_exit = $LASTEXITCODE; objects = $counted.Count; bytes = [long]$counted.Sum }
        }
        'usn' {
            $null = Run 'fsutil.exe' @('usn', 'createjournal', 'm=33554432', 'a=4194304', $drive)
            $null = New-Item -ItemType Directory -Path $dir -Force
            foreach ($i in 1..50) { [IO.File]::WriteAllBytes("$dir\journalled-$i.bin", (Bytes 700)) }
            $made[$feature] = 'a change journal with records in it'
        }
        'shortnames' {
            # 8.3 names, which Windows made on every volume until Windows 8.
            $null = Run 'fsutil.exe' @('8dot3name', 'set', $drive, '0')
            $null = New-Item -ItemType Directory -Path "$dir\a directory with a long name" -Force
            foreach ($i in 1..6) { [IO.File]::WriteAllBytes("$dir\a directory with a long name\a file with a long name $i.txt", (Bytes 900)) }
            $listed = & cmd.exe /c dir /x "$dir" 2>&1 | Out-String
            if ($listed -notmatch 'ADIREC~1') { throw "no 8.3 name was made: $listed" }
            $made[$feature] = 'a directory and six files with 8.3 names'
        }
        'shortnames-wide' {
            # 8.3 names on more than plain files, for a run that leaves them
            # behind (--short-names drop): on every directory of a deep
            # chain, on a file with a second hard link, on one with a named
            # stream, on names outside ASCII; and a name that is its own
            # short name, which has none to leave.
            $null = Run 'fsutil.exe' @('8dot3name', 'set', $drive, '0')
            $deep = "$dir\first directory with a long name\second directory with a long name\third directory with a long name"
            $null = New-Item -ItemType Directory -Path $deep -Force
            foreach ($i in 1..4) { [IO.File]::WriteAllBytes("$deep\a file with a long name $i.txt", (Bytes (700 * $i))) }
            [IO.File]::WriteAllBytes("$dir\a linked file with a long name.bin", (Bytes 5000))
            $null = New-Item -ItemType Directory -Path "$dir\another directory for the link" -Force
            $null = Run 'fsutil.exe' @('hardlink', 'create', "$dir\another directory for the link\the second name of the linked file.bin", "$dir\a linked file with a long name.bin")
            [IO.File]::WriteAllBytes("$dir\a file with a named stream and a long name.dat", (Bytes 3000))
            Set-Content -LiteralPath "$dir\a file with a named stream and a long name.dat" -Stream 'a stream' -Value 'in the stream' -Encoding ASCII
            [IO.File]::WriteAllBytes("$dir\$([char]0x00fc)ber einen langen Namen $([char]0x4e2d)$([char]0x6587).txt", (Bytes 1200))
            [IO.File]::WriteAllBytes("$dir\SHORT.TXT", (Bytes 800))
            $listed = (& cmd.exe /c dir /x /s "$dir" 2>&1 | Out-String)
            foreach ($short in 'FIRSTD~1', 'THIRDD~1', 'ALINKE~1.BIN', 'AFILEW~1.DAT') { if ($listed -notmatch [regex]::Escape($short)) { throw "no 8.3 name $short was made: $listed" } }
            $made[$feature] = 'three nested directories, four files, a hard-linked file, a file with a named stream and a name outside ASCII, all with 8.3 names, and one name that is its own'
        }
        'shortnames-stripped' {
            # The remedy the refusal of 'shortnames' gives: Windows' own tool
            # removes the 8.3 names and their creation is turned off.
            $null = Run 'fsutil.exe' @('8dot3name', 'set', $drive, '0')
            $null = New-Item -ItemType Directory -Path "$dir\a directory with a long name" -Force
            foreach ($i in 1..6) { [IO.File]::WriteAllBytes("$dir\a directory with a long name\a file with a long name $i.txt", (Bytes 900)) }
            if ((& cmd.exe /c dir /x "$dir" 2>&1 | Out-String) -notmatch 'ADIREC~1') { throw 'no 8.3 name was made to strip' }
            $stripped = Run 'fsutil.exe' @('8dot3name', 'strip', '/s', '/f', "$drive\")
            $null = Run 'fsutil.exe' @('8dot3name', 'set', $drive, '1')
            if ((& cmd.exe /c dir /x "$dir" 2>&1 | Out-String) -match 'ADIREC~1') { throw "fsutil 8dot3name strip left a short name: $stripped" }
            $made[$feature] = 'a directory and six files whose 8.3 names were stripped, with creation turned off'
        }
        'temporary' {
            $null = New-Item -ItemType Directory -Path $dir -Force
            [IO.File]::WriteAllBytes("$dir\temporary.tmp", (Bytes 3000)); [IO.File]::SetAttributes("$dir\temporary.tmp", 'Temporary')
            if (-not ([IO.File]::GetAttributes("$dir\temporary.tmp") -band [IO.FileAttributes]::Temporary)) { throw 'the TEMPORARY attribute did not stay' }
            $made[$feature] = 'a file with the TEMPORARY attribute'
        }
        'offline' {
            $null = New-Item -ItemType Directory -Path $dir -Force
            [IO.File]::WriteAllBytes("$dir\offline.dat", (Bytes 3000)); [IO.File]::SetAttributes("$dir\offline.dat", 'Offline')
            if (-not ([IO.File]::GetAttributes("$dir\offline.dat") -band [IO.FileAttributes]::Offline)) { throw 'the OFFLINE attribute did not stay' }
            $made[$feature] = 'a file with the OFFLINE attribute'
        }
        'efs' {
            $null = New-Item -ItemType Directory -Path $dir -Force
            [IO.File]::WriteAllBytes("$dir\encrypted.txt", (Bytes 5000))
            $null = Run 'cipher.exe' @('/e', "$dir\encrypted.txt")
            if (-not ([IO.File]::GetAttributes("$dir\encrypted.txt") -band [IO.FileAttributes]::Encrypted)) { throw 'cipher /e left the file unencrypted' }
            $made[$feature] = 'a file encrypted with EFS'
        }
        'wof' {
            # compact /exe stores the data in a WOF reparse point.
            $null = New-Item -ItemType Directory -Path $dir -Force
            [IO.File]::WriteAllBytes("$dir\wof-compressed.bin", [Text.Encoding]::ASCII.GetBytes(('compressible text for WOF ' * 20000)))
            # (The WOF filter hides the reparse point from fsutil and from every
            # other reader on the mounted volume; compact's own answer is the check.)
            $compacted = (Run 'compact.exe' @('/c', '/exe:xpress4k', "$dir\wof-compressed.bin")) -replace '\s+', ' '
            if ($compacted -notmatch '1 files within 1 directories were compressed') { throw "compact /exe did not compress the file: $compacted" }
            $made[$feature] = "a file compressed by compact /exe:xpress4k ($([regex]::Match($compacted, '[\d,]+ total bytes of data are stored in [\d,]+ bytes').Value))"
        }
        'quota' {
            $null = Run 'fsutil.exe' @('quota', 'enforce', $drive)
            $null = Run 'fsutil.exe' @('quota', 'modify', $drive, '100000000', '200000000', "$env:COMPUTERNAME\$env:USERNAME")
            $made[$feature] = 'quotas enforced, with an entry for one user'
        }
        'casemark' {
            # The mark alone, as WSL and Git leave it: no two names that differ
            # only by case. A directory made inside a marked one inherits it.
            $null = New-Item -ItemType Directory -Path $dir -Force
            $null = Run 'fsutil.exe' @('file', 'setCaseSensitiveInfo', $dir, 'enable')
            $null = New-Item -ItemType Directory -Path "$dir\Inner" -Force
            [IO.File]::WriteAllBytes("$dir\Readme.txt", (Bytes 100)); [IO.File]::WriteAllBytes("$dir\Inner\Makefile", (Bytes 300)); [IO.File]::WriteAllBytes("$dir\Inner\data.bin", (Bytes 20000))
            $marked = @($dir, "$dir\Inner" | Where-Object { "$(& fsutil.exe file queryCaseSensitiveInfo $_)" -match 'is enabled' }).Count
            if ($marked -lt 1) { throw "no directory is marked case-sensitive after fsutil file setCaseSensitiveInfo" }
            # An ordinary directory inside a marked one: it takes the mark
            # when it is made, and the mark is taken off again. A conversion
            # that carries the mark over has to clear it there too. Recorded
            # as it turned out, not required: the mark is the case's subject.
            $null = New-Item -ItemType Directory -Path "$dir\Plain" -Force
            $plainSaid = "$(& fsutil.exe file setCaseSensitiveInfo "$dir\Plain" disable 2>&1)".Trim()
            $plain = "$(& fsutil.exe file queryCaseSensitiveInfo "$dir\Plain" 2>&1)" -match 'is disabled'
            [IO.File]::WriteAllBytes("$dir\Plain\note.txt", (Bytes 50))
            $made[$feature] = "$marked directories marked case-sensitive, none holding two names that differ only by case; an ordinary directory inside a marked one: $(if ($plain) { 'made' } else { "not made ($plainSaid)" })"
        }
        'casemark-root' {
            # The volume's root directory itself marked, and a directory in
            # it. A conversion sets no mark on such a volume on any Windows
            # and says why: the new root is never empty when its mark could
            # be set. If Windows does not mark this root (it may refuse a
            # directory that holds something), the feature is not made.
            # Windows marks only an empty directory (0x91 otherwise), and the
            # content is written before the features: the root's own entries
            # are moved off the volume while it is marked, then put back. What
            # Windows keeps there itself (System Volume Information, the
            # recycle bin) stays, and if it is there the mark is still refused.
            $aside = Join-Path $env:TEMP "casemark-root-$([guid]::NewGuid().ToString('N'))"
            $null = New-Item -ItemType Directory -Path $aside -Force
            $moved = @(Get-ChildItem -LiteralPath "$drive\" -Force | Where-Object { $_.Name -notin 'System Volume Information', '$RECYCLE.BIN' })
            foreach ($entry in $moved) { Move-Item -LiteralPath $entry.FullName -Destination $aside -Force }
            try {
                $left = @(Get-ChildItem -LiteralPath "$drive\" -Force | ForEach-Object Name) -join ', '
                $said = "$(& fsutil.exe file setCaseSensitiveInfo "$drive\" enable 2>&1)".Trim()
            } finally {
                foreach ($entry in @(Get-ChildItem -LiteralPath $aside -Force)) { Move-Item -LiteralPath $entry.FullName -Destination "$drive\" -Force }
                Remove-Item -LiteralPath $aside -Force -Recurse -ErrorAction SilentlyContinue
            }
            if ("$(& fsutil.exe file queryCaseSensitiveInfo "$drive\" 2>&1)" -notmatch 'is enabled') { throw "the root directory is not marked case-sensitive after fsutil file setCaseSensitiveInfo (its own entries moved aside; the root then held: $left): $said" }
            $null = New-Item -ItemType Directory -Path $dir -Force
            [IO.File]::WriteAllBytes("$dir\Readme.txt", (Bytes 100))
            $inner = "$(& fsutil.exe file queryCaseSensitiveInfo $dir 2>&1)" -match 'is enabled'
            $made[$feature] = "the root directory marked case-sensitive; a directory made in it is $(if ($inner) { 'marked too' } else { 'not marked' })"
        }
        'casemark-control' {
            # The control for 'casemark', for a volume Windows formatted as
            # ReFS itself (-NativeRefsControl): what Windows does with the
            # mark there. Recorded, whatever it is; on the lab's build ReFS
            # takes the mark and then keeps two such names apart.
            $null = New-Item -ItemType Directory -Path $dir -Force
            $said = "$(& fsutil.exe file setCaseSensitiveInfo $dir enable 2>&1)".Trim(); $code = $LASTEXITCODE
            $state = "$(& fsutil.exe file queryCaseSensitiveInfo $dir 2>&1)".Trim()
            [IO.File]::WriteAllBytes("$dir\Readme.txt", (Bytes 100))
            $apart = $false
            if ($state -match 'is enabled') {
                [IO.File]::WriteAllText("$dir\name.txt", 'lower'); [IO.File]::WriteAllText("$dir\NAME.txt", 'UPPER')
                $apart = [IO.File]::ReadAllText("$dir\name.txt") -eq 'lower' -and [IO.File]::ReadAllText("$dir\NAME.txt") -eq 'UPPER'
                # The use test that follows keeps its notes by name without
                # regard to case, and would take the two for one file.
                [IO.File]::Delete("$dir\name.txt"); [IO.File]::Delete("$dir\NAME.txt")
            }
            $made[$feature] = "fsutil file setCaseSensitiveInfo exited $code and said: $said. The directory then: $state. Two names that differ only by case kept apart: $apart"
        }
        'casesensitive' {
            $null = New-Item -ItemType Directory -Path $dir -Force
            $null = Run 'fsutil.exe' @('file', 'setCaseSensitiveInfo', $dir, 'enable')
            [IO.File]::WriteAllBytes("$dir\name.txt", (Bytes 100)); [IO.File]::WriteAllBytes("$dir\NAME.txt", (Bytes 200))
            $made[$feature] = "a case-sensitive directory holding $(@(Get-ChildItem -LiteralPath $dir).Count) names that differ only by case"
        }
        'snapshot' {
            $null = New-Item -ItemType Directory -Path $dir -Force
            [IO.File]::WriteAllBytes("$dir\before-snapshot.bin", (Bytes 50000))
            $result = ([wmiclass]'Win32_ShadowCopy').Create("$drive\", 'ClientAccessible')
            if ($result.ReturnValue -ne 0) { throw "Win32_ShadowCopy.Create returned $($result.ReturnValue)" }
            $made[$feature] = "a shadow copy of the volume ($($result.ShadowID))"
        }
        'bitlocker' {
            $password = ConvertTo-SecureString 'Lab-volume-password-2026' -AsPlainText -Force
            $null = Enable-BitLocker -MountPoint $drive -PasswordProtector -Password $password -UsedSpaceOnly -SkipHardwareTest -WarningAction SilentlyContinue
            $state = Get-BitLockerVolume -MountPoint $drive
            $made[$feature] = "BitLocker: $($state.VolumeStatus), protection $($state.ProtectionStatus), $($state.EncryptionPercentage)% encrypted"
        }
        'dirstream' {
            $null = New-Item -ItemType Directory -Path "$dir\directory with a stream" -Force
            $null = & cmd.exe /c "echo a named stream on a directory> `"$dir\directory with a stream:note`""
            if ($LASTEXITCODE -ne 0) { throw 'could not write a named stream on a directory' }
            # And one past a cluster that does not end on one: its data is
            # placed through a carrier and its tail supplied apart.
            $null = New-Item -ItemType Directory -Path "$dir\directory with a large stream" -Force
            [IO.File]::WriteAllText("$dir\large-stream.txt", ('directory stream ' * 65600))
            $null = & cmd.exe /c "type `"$dir\large-stream.txt`" > `"$dir\directory with a large stream:large`""
            if ($LASTEXITCODE -ne 0) { throw 'could not write a large named stream on a directory' }
            Remove-Item -LiteralPath "$dir\large-stream.txt" -Force
            $made[$feature] = 'a directory with a named stream, and one with a named stream of about 1 MiB'
        }
        'wsl' {
            # What the Windows Subsystem for Linux leaves on a Windows
            # volume: owner and mode in extended attributes on every file,
            # and its own reparse tags for symbolic links, sockets, FIFOs and
            # device files. Made here as WSL makes them, without WSL. Each
            # is tried by itself: on a file system that does not take one
            # (a native ReFS control) the others are still made, and the
            # result says which were.
            Add-Type -TypeDefinition @'
using System; using System.IO; using System.Runtime.InteropServices; using System.Text; using Microsoft.Win32.SafeHandles;
public static class N2RLabWsl {
    [StructLayout(LayoutKind.Sequential)] struct IoStatusBlock { public IntPtr Status; public IntPtr Information; }
    [DllImport("ntdll.dll")] static extern int NtSetEaFile(SafeFileHandle handle, out IoStatusBlock io, byte[] buffer, int length);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(SafeFileHandle handle, uint code, byte[] input, uint inputSize, IntPtr output, uint outputSize, out uint returned, IntPtr overlapped);
    static byte[] Ea(string name, byte[] value) {
        byte[] n = Encoding.ASCII.GetBytes(name);
        byte[] b = new byte[(8 + n.Length + 1 + value.Length + 3) & ~3];
        b[5] = (byte)n.Length; b[6] = (byte)(value.Length & 0xff); b[7] = (byte)(value.Length >> 8);
        Buffer.BlockCopy(n, 0, b, 8, n.Length); Buffer.BlockCopy(value, 0, b, 8 + n.Length + 1, value.Length);
        return b;
    }
    // Owner, group and mode as WSL keeps them; a device number for a device file.
    public static void Metadata(string path, uint uid, uint gid, uint mode, ulong? device) {
        // GENERIC_WRITE, share all, OPEN_EXISTING, BACKUP_SEMANTICS | OPEN_REPARSE_POINT.
        using (var handle = CreateFileW(path, 0x40000000, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero)) {
            if (handle.IsInvalid) throw new IOException("open " + path + ": " + Marshal.GetLastWin32Error());
            var all = new System.Collections.Generic.List<Tuple<string, byte[]>> {
                Tuple.Create("$LXUID", BitConverter.GetBytes(uid)), Tuple.Create("$LXGID", BitConverter.GetBytes(gid)), Tuple.Create("$LXMOD", BitConverter.GetBytes(mode)) };
            if (device.HasValue) all.Add(Tuple.Create("$LXDEV", BitConverter.GetBytes(device.Value)));
            foreach (var one in all) {
                byte[] b = Ea(one.Item1, one.Item2); IoStatusBlock io;
                int status = NtSetEaFile(handle, out io, b, b.Length);
                if (status != 0) throw new IOException("NtSetEaFile " + one.Item1 + " on " + path + ": 0x" + status.ToString("x8"));
            }
        }
    }
    // A reparse point with one of WSL's tags and the data WSL puts there.
    public static void Point(string path, uint tag, byte[] data) {
        byte[] b = new byte[8 + data.Length];
        BitConverter.GetBytes(tag).CopyTo(b, 0); BitConverter.GetBytes((ushort)data.Length).CopyTo(b, 4);
        data.CopyTo(b, 8);
        using (var handle = CreateFileW(path, 0x40000000, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero)) {
            if (handle.IsInvalid) throw new IOException("open " + path + ": " + Marshal.GetLastWin32Error());
            uint returned;
            // FSCTL_SET_REPARSE_POINT
            if (!DeviceIoControl(handle, 0x000900A4, b, (uint)b.Length, IntPtr.Zero, 0, out returned, IntPtr.Zero))
                throw new IOException("FSCTL_SET_REPARSE_POINT 0x" + tag.ToString("x8") + " on " + path + ": " + Marshal.GetLastWin32Error());
        }
    }
}
'@
            $null = New-Item -ItemType Directory -Path "$dir\home\user" -Force
            $done = [Collections.Generic.List[string]]::new(); $failed = [Collections.Generic.List[string]]::new()
            $try = { param($what, $block) try { & $block; $done.Add($what) } catch { $failed.Add("$what ($($_.Exception.GetBaseException().Message))") } }
            # An ordinary file and a directory with Linux owner and mode.
            [IO.File]::WriteAllBytes("$dir\home\user\script.sh", [Text.Encoding]::UTF8.GetBytes("#!/bin/sh`necho made under WSL`n"))
            & $try 'file with owner and mode' { [N2RLabWsl]::Metadata("$dir\home\user\script.sh", 1000, 1000, 0x81ED, $null) }
            & $try 'directory with owner and mode' { [N2RLabWsl]::Metadata("$dir\home\user", 1000, 1000, 0x41ED, $null) }
            # A Linux symbolic link: version 2 and the target in UTF-8.
            $kinds = @(
                @{ name = 'link-to-script'; what = 'symbolic link'; tag = [Convert]::ToUInt32('A000001D', 16); mode = 0xA1FF; data = [byte[]](2, 0, 0, 0) + [Text.Encoding]::UTF8.GetBytes('script.sh'); device = $null },
                @{ name = 'socket'; what = 'socket'; tag = [Convert]::ToUInt32('80000023', 16); mode = 0xC1ED; data = [byte[]]@(); device = $null },
                @{ name = 'fifo'; what = 'FIFO'; tag = [Convert]::ToUInt32('80000024', 16); mode = 0x11A4; data = [byte[]]@(); device = $null },
                @{ name = 'null'; what = 'character device'; tag = [Convert]::ToUInt32('80000025', 16); mode = 0x21B6; data = [byte[]]@(); device = [uint64]0x0000000300000001 },
                @{ name = 'loop0'; what = 'block device'; tag = [Convert]::ToUInt32('80000026', 16); mode = 0x61B0; data = [byte[]]@(); device = [uint64]0x0000000000000007 }
            )
            foreach ($kind in $kinds) {
                $path = "$dir\home\user\$($kind.name)"
                [IO.File]::WriteAllBytes($path, [byte[]]@())
                & $try "$($kind.what): owner and mode" { [N2RLabWsl]::Metadata($path, 1000, 1000, [uint32]$kind.mode, $kind.device) }
                & $try "$($kind.what): reparse tag 0x$('{0:x8}' -f [uint32]$kind.tag)" { [N2RLabWsl]::Point($path, [uint32]$kind.tag, [byte[]]$kind.data) }
            }
            $made[$feature] = "made: $($done -join '; ')$(if ($failed.Count) { ". NOT taken by this file system: $($failed -join '; ')" })"
        }
        'names' {
            # Names from other alphabets and the names Windows' own tools
            # stumble over. NTFS takes any UTF-16 code unit but a few; so
            # must a conversion, unchanged and in the same order.
            $long = '\\?\' + $dir
            $null = New-Item -ItemType Directory -Path $dir -Force
            $names = [ordered]@{
                'Chinese'                = "$([char]0x6587)$([char]0x4EF6)$([char]0x5939)-$([char]0x6D4B)$([char]0x8BD5).txt"
                'Japanese'               = "$([char]0x30C6)$([char]0x30B9)$([char]0x30C8)$([char]0x30D5)$([char]0x30A1)$([char]0x30A4)$([char]0x30EB).txt"
                'Korean'                 = "$([char]0xD30C)$([char]0xC77C)-$([char]0xC2DC)$([char]0xD5D8).txt"
                'Arabic (right to left)' = "$([char]0x0645)$([char]0x0644)$([char]0x0641)-$([char]0x0627)$([char]0x062E)$([char]0x062A)$([char]0x0628)$([char]0x0627)$([char]0x0631).txt"
                'Hebrew (right to left)' = "$([char]0x05E7)$([char]0x05D5)$([char]0x05D1)$([char]0x05E5)-$([char]0x05D1)$([char]0x05D3)$([char]0x05D9)$([char]0x05E7)$([char]0x05D4).txt"
                'a right-to-left override in the name' = "report-$([char]0x202E)txt.exe"
                'an emoji (a surrogate pair)' = "party-$([char]::ConvertFromUtf32(0x1F389)).txt"
                'a rare Han character (a surrogate pair)' = "$([char]::ConvertFromUtf32(0x20BB7))-rare.txt"
                'combining marks (decomposed)' = "cafe$([char]0x0301)-decomposed.txt"
                'the same word precomposed' = "caf$([char]0x00E9)-precomposed.txt"
                'Turkish dotless and dotted i' = "$([char]0x0131)$([char]0x0130)-turkish.txt"
                'German sharp s and its capital' = "stra$([char]0x00DF)e-$([char]0x1E9E).txt"
                'a zero-width joiner' = "zero$([char]0x200D)width.txt"
                'spaces and a leading dot' = '.  leading dot and  double spaces.txt'
                'characters cmd treats specially' = 'percent%TEMP% caret^ amp& paren(1) bang! semi;comma,equals=.txt'
            }
            $done = [Collections.Generic.List[string]]::new(); $failed = [Collections.Generic.List[string]]::new()
            foreach ($what in $names.Keys) {
                try { [IO.File]::WriteAllBytes("$long\$($names[$what])", [Text.Encoding]::UTF8.GetBytes($what)); $done.Add($what) }
                catch { $failed.Add("$what ($($_.Exception.GetBaseException().Message))") }
            }
            # Names Win32 refuses and NTFS holds: made through the \\?\ form,
            # which passes them to the file system as they are.
            $raw = [ordered]@{
                'a trailing dot' = 'trailing-dot.'
                'a trailing space' = 'trailing-space '
                'only dots' = '...'
                'a device name' = 'con'
                'a device name with an extension' = 'aux.txt'
                'a device name as a directory' = 'nul'
            }
            foreach ($what in $raw.Keys) {
                try {
                    if ($what -like '*directory*') { $null = [IO.Directory]::CreateDirectory("$long\$($raw[$what])"); [IO.File]::WriteAllBytes("$long\$($raw[$what])\inside.txt", [byte[]](1, 2, 3)) }
                    else { [IO.File]::WriteAllBytes("$long\$($raw[$what])", [Text.Encoding]::UTF8.GetBytes($what)) }
                    $done.Add($what)
                } catch { $failed.Add("$what ($($_.Exception.GetBaseException().Message))") }
            }
            # A directory whose own name and whose children's are not ASCII,
            # and a name of the greatest length, 255 code units, in Cyrillic.
            try {
                $deep = "$long\$([char]0x043F)$([char]0x0430)$([char]0x043F)$([char]0x043A)$([char]0x0430)\$([char]0x03B1)$([char]0x03B2)$([char]0x03B3)"
                $null = [IO.Directory]::CreateDirectory($deep)
                [IO.File]::WriteAllBytes("$deep\$(([string][char]0x0436) * 251).txt", (Bytes 1000))
                $done.Add('a 255-unit Cyrillic name in Cyrillic and Greek directories')
            } catch { $failed.Add("a 255-unit Cyrillic name ($($_.Exception.GetBaseException().Message))") }
            $made[$feature] = "$($done.Count) names made: $($done -join '; ')$(if ($failed.Count) { ". NOT made: $($failed -join '; ')" })"
        }
        'lonesurrogates' {
            # Names that are not valid UTF-16: half of a surrogate pair by
            # itself. NTFS holds them; the lab's listing tool does not list
            # them, so they are a case of their own.
            $long = '\\?\' + $dir
            $null = New-Item -ItemType Directory -Path $dir -Force
            [IO.File]::WriteAllBytes("$long\lone-$([char]0xD83C)-high.txt", [byte[]](1, 2, 3))
            [IO.File]::WriteAllBytes("$long\lone-$([char]0xDF89)-low.txt", [byte[]](4, 5, 6))
            $made[$feature] = 'two names with a lone surrogate, high and low'
        }
        default { throw "unknown feature '$feature'" }
    }
}
$made | ConvertTo-Json -Depth 5 -Compress
