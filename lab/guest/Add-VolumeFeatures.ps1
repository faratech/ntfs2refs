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
            $made[$feature] = "$marked directories marked case-sensitive, none holding two names that differ only by case"
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
            $made[$feature] = 'a directory with a named stream'
        }
        default { throw "unknown feature '$feature'" }
    }
}
$made | ConvertTo-Json -Depth 5 -Compress
