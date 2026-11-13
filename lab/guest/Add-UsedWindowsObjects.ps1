<#
.SYNOPSIS
  Shapes a lab Windows source: adds what a Windows volume that has been used
  has and a freshly installed one does not.

.DESCRIPTION
  Run in the control OS against the mounted NTFS Windows source, before it is
  listed and converted (the harness's -ShapeSource). Everything is created
  under one new directory at the root of the source:

  - a tree 25 directories deep with a file at the bottom (the installed
    Windows has no directory deeper than 16; a profile or a source tree does);
  - 300 files and 20 directories with object IDs, which is what link tracking
    leaves on the targets of shortcuts, and enough of them for the volume's
    object-ID index to outgrow its root;
  - a shortcut to a file and one to a directory, made the way the shell does.

  Prints one JSON line saying what was made.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$SourceLetter)
$ErrorActionPreference = 'Stop'
$root = "${SourceLetter}:\n2r-shape-used-windows"
if (Test-Path -LiteralPath $root) { throw "$root already exists" }
$null = New-Item -ItemType Directory -Path $root
$random = [Random]::new(20261113)
function Bytes([int]$n) { $b = New-Object byte[] $n; $random.NextBytes($b); , $b }

$deep = "\\?\$root\deep"
foreach ($i in 1..25) { $deep += "\level $i of a deep tree" }
$null = [IO.Directory]::CreateDirectory($deep)
[IO.File]::WriteAllBytes("$deep\at the bottom.bin", (Bytes 70000))
[IO.File]::WriteAllBytes("$deep\small at the bottom.txt", (Bytes 300))

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
$ids = "$root\object ids"
$null = New-Item -ItemType Directory -Path $ids
foreach ($i in 0..299) { $path = '{0}\tracked file {1:d3}.dat' -f $ids, $i; [IO.File]::WriteAllBytes($path, (Bytes (40 + $i))); [N2RLabObjectId]::Create($path) }
foreach ($i in 0..19) { $path = '{0}\tracked directory {1:d2}' -f $ids, $i; $null = New-Item -ItemType Directory -Path $path; [N2RLabObjectId]::Create($path) }

$null = New-Item -ItemType Directory -Path "$root\shortcuts\a directory a shortcut points at"
[IO.File]::WriteAllBytes("$root\shortcuts\a file a shortcut points at.txt", (Bytes 1500))
$shell = New-Object -ComObject WScript.Shell
foreach ($pair in @(@('to a file.lnk', 'a file a shortcut points at.txt'), @('to a directory.lnk', 'a directory a shortcut points at'))) {
    $link = $shell.CreateShortcut("$root\shortcuts\$($pair[0])"); $link.TargetPath = "$root\shortcuts\$($pair[1])"; $link.Save()
}
$query = & fsutil.exe objectid query "$root\shortcuts\a file a shortcut points at.txt" 2>&1 | Out-String

[pscustomobject]@{ root = $root; deepest_directory_components = 27; object_ids = 320
    shortcut_target_has_object_id = [bool]($LASTEXITCODE -eq 0 -and $query -match 'Object ID') } | ConvertTo-Json -Compress
