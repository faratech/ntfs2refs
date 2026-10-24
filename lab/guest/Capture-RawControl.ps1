<# Read a locked disposable target volume into the separate journal volume.
https://learn.microsoft.com/windows/win32/api/winioctl/ni-winioctl-fsctl_lock_volume
https://learn.microsoft.com/windows/win32/api/winioctl/ni-winioctl-fsctl_allow_extended_dasd_io
There is no raw write operation in this capture implementation. #>
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][string]$TargetManifestPath, [Parameter(Mandatory)][string]$JournalManifestPath, [Parameter(Mandatory)][string]$OutputPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'GuestLab.psm1') -Force
$targetManifest = Get-Content -LiteralPath $TargetManifestPath -Raw | ConvertFrom-Json
$journalManifest = Get-Content -LiteralPath $JournalManifestPath -Raw | ConvertFrom-Json
if ($targetManifest.role -ne 'target' -or $journalManifest.role -ne 'journal') { throw 'Capture requires target and journal identities.' }
$target = Get-LabGuestDisk $targetManifest
$journal = Get-LabGuestDisk $journalManifest
if ($target.Number -eq $journal.Number) { throw 'Target and journal must be different disks.' }
$targetParts = @(Get-Partition -DiskNumber $target.Number | Where-Object DriveLetter)
$journalParts = @(Get-Partition -DiskNumber $journal.Number | Where-Object DriveLetter)
if ($targetParts.Count -ne 1 -or $journalParts.Count -ne 1 -or $targetParts[0].Size -ne 1GB) { throw 'Capture accepts one exactly 1 GiB target partition and one journal partition.' }
$targetVolume = Get-Volume -DriveLetter $targetParts[0].DriveLetter
$journalVolume = Get-Volume -DriveLetter $journalParts[0].DriveLetter
if ($targetVolume.FileSystem -notin @('NTFS','ReFS') -or $targetVolume.FileSystemLabel -ne 'ntfs2refs-target' -or $journalVolume.FileSystem -ne 'NTFS' -or $journalVolume.FileSystemLabel -ne 'ntfs2refs-journal') { throw 'Unexpected control or journal filesystem/label.' }
if ($journalVolume.SizeRemaining -lt 2GB) { throw 'Journal volume must have at least 2 GiB free.' }
$journalRoot = [string]$journalParts[0].DriveLetter + ':\'
$output = [IO.Path]::GetFullPath($OutputPath)
if (-not $output.StartsWith($journalRoot, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetExtension($output) -ne '.raw') { throw 'Capture destination must be a .raw file on the journal volume.' }
$cursor = Split-Path $output -Parent
while ($cursor.Length -ge $journalRoot.Length) {
    if (Test-Path -LiteralPath $cursor) { if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Capture destination traverses a reparse point.' } }
    $parent = Split-Path $cursor -Parent; if (-not $parent -or $parent -eq $cursor) { break }; $cursor = $parent
}
if ((Test-Path -LiteralPath $output) -or (Test-Path -LiteralPath ($output + '.partial')) -or (Test-Path -LiteralPath ($output + '.json'))) { throw 'Capture output already exists.' }
if (-not $PSCmdlet.ShouldProcess($output, 'Lock target volume, read exactly 1 GiB to journal, hash and mark complete')) { return }
if (-not ('Ntfs2Refs.NativeControlCapture' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Ntfs2Refs {
 public static class NativeControlCapture {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool DeviceIoControl(SafeFileHandle handle, uint code, IntPtr input, uint inputSize, IntPtr output, uint outputSize, out uint returned, IntPtr overlapped);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool ReadFile(SafeFileHandle handle, IntPtr buffer, uint count, out uint read, IntPtr overlapped);
  const int BufferBytes = 1048576;
  const long CaptureBytes = 1073741824L;
  static void Control(SafeFileHandle h, uint code) { uint done; if (!DeviceIoControl(h, code, IntPtr.Zero, 0, IntPtr.Zero, 0, out done, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error()); }
  static int ValidateGeometry(uint logical, uint physical) {
   if (logical < 512 || physical < logical || physical > 65536 ||
       (logical & (logical - 1)) != 0 || (physical & (physical - 1)) != 0 ||
       BufferBytes % physical != 0) throw new ArgumentOutOfRangeException("geometry", "Expected bounded power-of-two logical/physical sector sizes.");
   return checked((int)physical);
  }
  static IntPtr AlignBuffer(IntPtr allocation, int alignment) {
   return new IntPtr(checked(allocation.ToInt64() + alignment - 1) & ~((long)alignment - 1));
  }
  static void CopyAligned(SafeFileHandle input, string partial, uint logical, uint physical, long length) {
   int alignment = ValidateGeometry(logical, physical);
   if (input == null || input.IsInvalid || input.IsClosed) throw new ArgumentException("Expected an open read handle.");
   if (length <= 0 || length > CaptureBytes || length % alignment != 0) throw new ArgumentOutOfRangeException("length");
   // Align the unmanaged allocation explicitly; a pinned managed byte[] does
   // not guarantee the device's physical-sector alignment. The managed array
   // is used only for ordinary buffered journal-file output.
   IntPtr allocation = Marshal.AllocHGlobal(checked(BufferBytes + alignment - 1));
   try {
    IntPtr aligned = AlignBuffer(allocation, alignment);
    byte[] staging = new byte[BufferBytes];
    using (var output = new FileStream(partial, FileMode.CreateNew, FileAccess.Write, FileShare.None, BufferBytes)) {
     long remaining = length;
     while (remaining != 0) {
      uint requested = checked((uint)Math.Min(BufferBytes, remaining)); uint read;
      if (!ReadFile(input, aligned, requested, out read, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
      if (read == 0) throw new EndOfStreamException("Target shorter than partition.");
      if (read != requested) throw new IOException("Short raw read; incomplete capture retained.");
      Marshal.Copy(aligned, staging, 0, checked((int)read));
      output.Write(staging, 0, checked((int)read));
      remaining -= read;
     }
     output.Flush(true);
    }
   } finally { Marshal.FreeHGlobal(allocation); }
  }
  public static void Capture(string device, string partial, uint logical, uint physical) {
   if (device.Length != 6 || !device.StartsWith(@"\\.\") || device[4] < 'A' || device[4] > 'Z' || device[5] != ':') throw new ArgumentException("Expected a volume-letter device.");
   ValidateGeometry(logical, physical);
   // GENERIC_READ only; explicit noncached I/O follows the volume-handle
   // contract, including aligned buffers, lengths, and the initial offset 0.
   using (var h = CreateFile(device, 0x80000000, 3, IntPtr.Zero, 3, 0x20000000, IntPtr.Zero)) {
    if (h.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
    Control(h, 0x00090018); // Lock flushes filesystem caches and rejects open files.
    try {
     Control(h, 0x00090020); // Dismount only after lock succeeded.
     Control(h, 0x00090083); // Read through the final partition sectors.
     CopyAligned(h, partial, logical, physical, CaptureBytes);
    } finally { if (!h.IsClosed) { uint ignored; DeviceIoControl(h, 0x0009001c, IntPtr.Zero, 0, IntPtr.Zero, 0, out ignored, IntPtr.Zero); } }
   }
  }
 }
}
'@
}
$target = Get-LabGuestDisk $targetManifest
$journal = Get-LabGuestDisk $journalManifest
if ((Get-Partition -DriveLetter $targetParts[0].DriveLetter).DiskNumber -ne $target.Number -or (Get-Partition -DriveLetter $journalParts[0].DriveLetter).DiskNumber -ne $journal.Number) { throw 'A capture drive letter changed ownership.' }
New-Item -ItemType Directory -Path (Split-Path $output -Parent) -Force | Out-Null
$device = '\\.\' + [string]$targetParts[0].DriveLetter + ':'
[Ntfs2Refs.NativeControlCapture]::Capture($device, ($output + '.partial'), [uint32]$target.LogicalSectorSize, [uint32]$target.PhysicalSectorSize)
$partial = Get-Item -LiteralPath ($output + '.partial')
if ($partial.Length -ne 1GB) { throw 'Capture length mismatch; partial image retained.' }
$hash = (Get-FileHash -LiteralPath $partial.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
Move-Item -LiteralPath $partial.FullName -Destination $output
$record = [pscustomobject]@{ schemaVersion = 1; status = 'complete'; imagePath = $output; length = 1GB; sha256 = $hash; fileSystem = $targetVolume.FileSystem; allocationUnitSize = $targetVolume.AllocationUnitSize; target = $targetManifest; partitionOffset = $targetParts[0].Offset; logicalSectorSize = $target.LogicalSectorSize; physicalSectorSize = $target.PhysicalSectorSize; ioBufferAlignment = $target.PhysicalSectorSize; captureMethod = 'Locked/dismounted volume; GENERIC_READ noncached handle; aligned unmanaged ReadFile buffer; exactly partition length'; capturedUtc = [DateTime]::UtcNow.ToString('o') }
$record | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath ($output + '.json') -Encoding UTF8
$record
