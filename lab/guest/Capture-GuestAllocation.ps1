<# Read-only allocation observations for explicitly named disposable fixtures.
   VCN/LCN values remain API addresses: no raw-offset translation is inferred. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [Parameter(Mandatory)][ValidateCount(1,32)][string[]]$FixtureRelativePath,
    [Parameter(Mandatory)][string]$OutputPath,
    [ValidateRange(1,256)][int]$MaximumHashMiB = 64
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-AllocationRelativePath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Length -gt 160 -or $Path -match '[/:*?"<>|\x00-\x1f]' -or $Path.StartsWith('\')) { throw 'Expected a bounded ordinary path relative to fixtures, without streams or wildcards.' }
    foreach ($component in $Path.Split('\')) {
        if (-not $component -or $component -in @('.','..') -or $component.EndsWith('.') -or $component.EndsWith(' ') -or $component -match '^(?i:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)') { throw 'Ambiguous or reserved fixture path component.' }
    }
}

if (-not ('Ntfs2Refs.NativeAllocationEvidence' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
namespace Ntfs2Refs {
 public sealed class AllocationExtent {
  public long startingVcn, nextVcn, lcn;
  public string lcnInterpretation;
 }
 public sealed class AllocationPage {
  public long startingVcn, nextVcn;
  public AllocationExtent[] extents;
 }
 public sealed class AllocationObservation {
  public string status, sha256, fileId64, volumeSerialHex, attributes;
  public long length;
  public bool complete, stableDuringObservation;
  public int nativeError, controlCalls;
  public AllocationExtent[] extents = new AllocationExtent[0];
 }
 public static class NativeAllocationEvidence {
  const uint RetrievalPointers = 0x00090073;
  const uint Read = 0x80000000, ReadAttributes = 0x80, ShareRead = 1, OpenExisting = 3;
  const uint OpenReparsePoint = 0x00200000, BackupSemantics = 0x02000000;
  const uint Directory = 0x10, ReparsePoint = 0x400;
  const int MaxExtents = 4096, MaxCalls = 16;
  [StructLayout(LayoutKind.Sequential)] struct FileInformation {
   public uint attributes; public System.Runtime.InteropServices.ComTypes.FILETIME creation, access, write;
   public uint volumeSerial, sizeHigh, sizeLow, links, indexHigh, indexLow;
  }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation info);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, uint capacity, uint flags);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool DeviceIoControl(SafeFileHandle file, uint code, byte[] input, uint inputLength, byte[] output, uint outputLength, out uint returned, IntPtr overlapped);

  public static string ValidateLocalPath(string path) {
   if (String.IsNullOrEmpty(path) || path.Length > 240 || path.Length < 4 || !Char.IsLetter(path[0]) || path[1] != ':' || path[2] != '\\' || path.IndexOf('/', 2) >= 0 || path.IndexOf(':', 2) >= 0 || path.IndexOfAny(new char[] {'*','?','"','<','>','|'}) >= 0) throw new ArgumentException("Expected a bounded absolute local ordinary path.");
   foreach (string component in path.Substring(3).Split('\\')) {
    if (component.Length == 0 || component == "." || component == ".." || component.EndsWith(".") || component.EndsWith(" ") || System.Text.RegularExpressions.Regex.IsMatch(component, @"^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)", System.Text.RegularExpressions.RegexOptions.IgnoreCase)) throw new ArgumentException("Ambiguous or reserved path component.");
    foreach (char c in component) if (c < 32) throw new ArgumentException("Control character in path.");
   }
   string canonical = Path.GetFullPath(path);
   if (!String.Equals(canonical, path, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Noncanonical path.");
   return canonical;
  }

  static FileInformation Information(SafeFileHandle handle) {
   FileInformation info;
   if (!GetFileInformationByHandle(handle, out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
   return info;
  }
  static SafeFileHandle Open(string path, bool directory) {
   SafeFileHandle handle = CreateFile(path, directory ? ReadAttributes : Read, ShareRead, IntPtr.Zero, OpenExisting, OpenReparsePoint | (directory ? BackupSemantics : 0), IntPtr.Zero);
   if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
   try {
    FileInformation info = Information(handle);
    if ((info.attributes & ReparsePoint) != 0 || ((info.attributes & Directory) != 0) != directory) throw new IOException("Reparse points and unexpected object types are refused.");
    StringBuilder final = new StringBuilder(512);
    uint length = GetFinalPathNameByHandle(handle, final, (uint)final.Capacity, 0);
    if (length == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
    if (length >= final.Capacity || !String.Equals(final.ToString(), @"\\?\" + path, StringComparison.OrdinalIgnoreCase)) throw new IOException("Resolved handle path differs from the ordinary requested path.");
    return handle;
   } catch { handle.Dispose(); throw; }
  }

  // Public pure parser is also used by bounded malformed/native-page tests.
  public static AllocationPage ParsePage(byte[] bytes, int returned, long requestedVcn, int remainingExtents) {
   if (bytes == null || returned < 16 || returned > bytes.Length || requestedVcn < 0 || remainingExtents < 1 || remainingExtents > MaxExtents) throw new InvalidDataException("Invalid retrieval page bounds.");
   uint count = BitConverter.ToUInt32(bytes, 0);
   if (count == 0 || count > remainingExtents || count > (returned - 16) / 16 || returned != 16 + 16 * (long)count) throw new InvalidDataException("Invalid retrieval extent count or response length.");
   long starting = BitConverter.ToInt64(bytes, 8);
   // Every request is an observed extent boundary, beginning at zero. A
   // driver-rounded boundary cannot silently duplicate/omit part of a mapping.
   if (starting != requestedVcn) throw new InvalidDataException("Unexpected retrieval starting VCN; mapping is unqualified.");
   List<AllocationExtent> extents = new List<AllocationExtent>();
   long current = starting;
   for (int i = 0; i < count; i++) {
    long next = BitConverter.ToInt64(bytes, 16 + i * 16);
    long lcn = BitConverter.ToInt64(bytes, 24 + i * 16);
    if (next <= current || lcn < -1 || (lcn >= 0 && lcn > Int64.MaxValue - (next - current))) throw new InvalidDataException("Invalid retrieval extent progression or LCN range.");
    extents.Add(new AllocationExtent { startingVcn=current, nextVcn=next, lcn=lcn, lcnInterpretation=lcn == -1 ? "unallocated-or-partially-compressed-native-sentinel" : "native-volume-logical-cluster" });
    current = next;
   }
   return new AllocationPage { startingVcn=starting, nextVcn=current, extents=extents.ToArray() };
  }
  static AllocationObservation Query(SafeFileHandle handle) {
   AllocationObservation result = new AllocationObservation();
   List<AllocationExtent> extents = new List<AllocationExtent>();
   long next = 0;
   for (int call = 0; call < MaxCalls; call++) {
    byte[] output = new byte[16 + 16 * 256];
    uint returned;
    bool ok = DeviceIoControl(handle, RetrievalPointers, BitConverter.GetBytes(next), 8, output, (uint)output.Length, out returned, IntPtr.Zero);
    int error = ok ? 0 : Marshal.GetLastWin32Error();
    result.controlCalls++;
    if (!ok && error == 38 && next == 0 && returned == 0) {
     result.status = "no-nonresident-mapping-returned"; result.nativeError = error; result.complete = true; return result;
    }
    if (!ok && error != 234) {
     result.status = "native-error"; result.nativeError = error; result.extents = extents.ToArray(); return result;
    }
    AllocationPage page = ParsePage(output, checked((int)returned), next, MaxExtents - extents.Count);
    extents.AddRange(page.extents); next = page.nextVcn;
    if (ok) { result.status = "mapping-returned"; result.complete = true; result.extents = extents.ToArray(); return result; }
    if (extents.Count == MaxExtents) break;
   }
   result.status = "bounded-query-limit"; result.extents = extents.ToArray(); return result;
  }
  static bool SameMapping(AllocationObservation a, AllocationObservation b) {
   if (a.status != b.status || a.nativeError != b.nativeError || a.complete != b.complete || a.extents.Length != b.extents.Length) return false;
   for (int i = 0; i < a.extents.Length; i++) if (a.extents[i].startingVcn != b.extents[i].startingVcn || a.extents[i].nextVcn != b.extents[i].nextVcn || a.extents[i].lcn != b.extents[i].lcn) return false;
   return true;
  }
  public static AllocationObservation Collect(string path, long maximumHashBytes) {
   path = ValidateLocalPath(path);
   if (maximumHashBytes < 0 || maximumHashBytes > 268435456) throw new ArgumentOutOfRangeException("maximumHashBytes");
   List<SafeFileHandle> parents = new List<SafeFileHandle>();
   try {
    // Pin each parent without write/delete sharing and reject reparses on
    // opened handles, preventing path replacement during this observation.
    string parent = path.Substring(0, 3);
    parents.Add(Open(parent, true));
    string[] parts = path.Substring(3).Split('\\');
    for (int i = 0; i < parts.Length - 1; i++) { parent = Path.Combine(parent, parts[i]); parents.Add(Open(parent, true)); }
    using (SafeFileHandle handle = Open(path, false)) {
     FileInformation before = Information(handle);
     ulong size = ((ulong)before.sizeHigh << 32) | before.sizeLow;
     if (size > (ulong)maximumHashBytes) throw new IOException("Logical hash budget exceeded.");
     AllocationObservation result = Query(handle);
     result.length = (long)size;
     result.fileId64 = "0x" + before.indexHigh.ToString("x8") + before.indexLow.ToString("x8");
     result.volumeSerialHex = "0x" + before.volumeSerial.ToString("x8");
     result.attributes = ((FileAttributes)before.attributes).ToString();
     // Reuse the read-only handle for the full logical hash. The FileStream
     // owns it only after both mapping observations and identity checks finish.
     using (FileStream stream = new FileStream(handle, FileAccess.Read, 65536, false)) {
      using (SHA256 sha = SHA256.Create()) result.sha256 = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
      if (stream.Position != (long)size || stream.Length != (long)size) throw new IOException("Logical file length changed while hashing.");
      AllocationObservation after = Query(handle);
      FileInformation final = Information(handle);
      result.controlCalls += after.controlCalls;
      result.stableDuringObservation = SameMapping(result, after) && before.volumeSerial == final.volumeSerial && before.indexHigh == final.indexHigh && before.indexLow == final.indexLow && before.sizeHigh == final.sizeHigh && before.sizeLow == final.sizeLow && before.attributes == final.attributes && before.write.dwHighDateTime == final.write.dwHighDateTime && before.write.dwLowDateTime == final.write.dwLowDateTime;
      if (!result.stableDuringObservation) { result.status = "changed-during-observation"; result.complete = false; }
     }
     return result;
    }
   } finally { for (int i = parents.Count - 1; i >= 0; i--) parents[i].Dispose(); }
  }
  public static void WriteReport(string path, byte[] bytes) {
   path = ValidateLocalPath(path);
   if (bytes == null || bytes.Length > 8388608) throw new ArgumentException("Report exceeds the bounded output.");
   List<SafeFileHandle> parents = new List<SafeFileHandle>();
   try {
    string parent = path.Substring(0, 3);
    parents.Add(Open(parent, true));
    string[] parts = path.Substring(3).Split('\\');
    for (int i = 0; i < parts.Length - 1; i++) { parent = Path.Combine(parent, parts[i]); parents.Add(Open(parent, true)); }
    using (FileStream report = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { report.Write(bytes, 0, bytes.Length); report.Flush(true); }
   } finally { for (int i = parents.Count - 1; i >= 0; i--) parents[i].Dispose(); }
  }
 }
}
'@
}

Import-Module (Join-Path $PSScriptRoot 'GuestLab.psm1') -Force
if ((Get-Item -LiteralPath $ManifestPath).Length -gt 64KB) { throw 'Manifest exceeds the bounded input.' }
$manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.role -cne 'target') { throw 'Allocation observations require the enrolled target role.' }
$disk = Get-LabGuestDisk $manifest
$partitions = @(Get-Partition -DiskNumber $disk.Number | Where-Object { $_.DriveLetter })
if ($partitions.Count -ne 1) { throw 'Expected exactly one mounted target data partition.' }
$partition = $partitions[0]
$volume = Get-Volume -DriveLetter $partition.DriveLetter
if ($volume.FileSystem -cnotin @('NTFS','ReFS') -or $volume.FileSystemLabel -cne 'ntfs2refs-target') { throw 'Unexpected fixture filesystem or volume label.' }
$fixtureRoot = "$($partition.DriveLetter):\fixtures"
$outputFull = [Ntfs2Refs.NativeAllocationEvidence]::ValidateLocalPath($OutputPath)
if ($outputFull.Substring(0,2) -ieq ($fixtureRoot.Substring(0,2))) { throw 'Evidence output must be on a different volume.' }
$outputVolume = Get-Volume -DriveLetter $outputFull[0]
if ([string]::IsNullOrWhiteSpace([string]$volume.UniqueId) -or [string]::IsNullOrWhiteSpace([string]$outputVolume.UniqueId) -or [string]$volume.UniqueId -ieq [string]$outputVolume.UniqueId) { throw 'Evidence destination must identify a different volume, including drive-letter aliases.' }
if (Test-Path -LiteralPath $outputFull) { throw 'Evidence output already exists.' }
$parent = Get-Item -LiteralPath (Split-Path $outputFull -Parent)
if (-not $parent.PSIsContainer -or $parent.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Evidence parent must be an existing ordinary directory.' }
$seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($relative in $FixtureRelativePath) {
    Assert-AllocationRelativePath $relative
    if (-not $seen.Add($relative)) { throw 'Duplicate fixture path.' }
}
$remaining = [long]$MaximumHashMiB * 1MB
$records = New-Object 'System.Collections.Generic.List[object]'
$failures = New-Object 'System.Collections.Generic.List[string]'
$extentCount = 0
foreach ($relative in $FixtureRelativePath) {
    try {
        $observation = [Ntfs2Refs.NativeAllocationEvidence]::Collect((Join-Path $fixtureRoot $relative), $remaining)
        $remaining -= $observation.length
        $extentCount += $observation.extents.Count
        if ($extentCount -gt 8192) { throw 'Cumulative extent report limit exceeded.' }
        $records.Add([pscustomobject]@{ path=('fixtures\' + $relative); stream=':$DATA'; observation=$observation })
        if (-not $observation.complete -or -not $observation.stableDuringObservation) { $failures.Add("Unqualified observation for ${relative}: $($observation.status); native error $($observation.nativeError)") }
    } catch { $failures.Add("Cannot observe ${relative}: $($_.Exception.Message)"); break }
}
$diskAfter = Get-LabGuestDisk $manifest
$partitionAfter = @(Get-Partition -DiskNumber $diskAfter.Number | Where-Object { $_.DriveLetter })
if ($partitionAfter.Count -ne 1 -or $partitionAfter[0].PartitionNumber -ne $partition.PartitionNumber -or $partitionAfter[0].Offset -ne $partition.Offset -or $partitionAfter[0].Size -ne $partition.Size -or $partitionAfter[0].DriveLetter -ne $partition.DriveLetter) { throw 'Target partition identity changed during evidence collection.' }
$volumeAfter = Get-Volume -DriveLetter $partition.DriveLetter
foreach ($field in @('UniqueId','FileSystem','FileSystemLabel','AllocationUnitSize','Size')) {
    if ([string]$volumeAfter.$field -cne [string]$volume.$field) { throw "Target volume $field changed during evidence collection." }
}
$version = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$driverName = if ($volume.FileSystem -ceq 'ReFS') { 'refs.sys' } else { 'ntfs.sys' }
$driver = Get-Item -LiteralPath (Join-Path $env:SystemRoot ('System32\drivers\' + $driverName))
$report = [ordered]@{
    schemaVersion=1; createdUtc=[DateTime]::UtcNow.ToString('o'); kind='native-file-allocation-observations'
    evidenceScriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    diskIdentity=$manifest; diskNumberObserved=$disk.Number; logicalSectorSize=$disk.LogicalSectorSize; physicalSectorSize=$disk.PhysicalSectorSize
    partition=[pscustomobject]@{ number=$partition.PartitionNumber; offset=$partition.Offset; size=$partition.Size; driveLetter=[string]$partition.DriveLetter }
    volume=[pscustomobject]@{ fileSystem=[string]$volume.FileSystem; label=[string]$volume.FileSystemLabel; uniqueId=[string]$volume.UniqueId; allocationUnitSize=$volume.AllocationUnitSize; size=$volume.Size }
    windowsBuild=([string]$version.CurrentBuild+'.'+[string]$version.UBR)
    filesystemDriver=[pscustomobject]@{ name=$driverName; version=$driver.VersionInfo.FileVersion; sha256=(Get-FileHash -LiteralPath $driver.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    requestedFiles=$FixtureRelativePath; files=$records.ToArray(); failures=$failures.ToArray()
    complete=($failures.Count -eq 0 -and $records.Count -eq $FixtureRelativePath.Count)
    hashBudgetBytes=([long]$MaximumHashMiB * 1MB); hashedLogicalBytes=([long]$MaximumHashMiB * 1MB - $remaining)
    sourceWriteRequestsIssued=$false; retrievalPointerBaseQueried=$false; physicalMappingVerified=$false; conversionQualified=$false; bootQualified=$false
    limitations=@('Only explicitly selected unnamed file streams are observed; this is not a filesystem inventory.','VCN and LCN are native API addresses. No equivalence to raw partition, guest disk or VHDX offsets is established.','LCN -1 is retained as a native sentinel; allocation/compression semantics are not independently decoded.','Two equal mapping observations and a logical hash are not an offline snapshot or crash-consistency proof.','No nonresident mapping does not distinguish an empty file from resident content.','The 64-bit file identifier is an observation only; complete ReFS file identity may require FILE_ID_INFO.','The collector requests no source writes; the mounted filesystem may update access metadata during reads.')
}
$json = $report | ConvertTo-Json -Depth 10
$bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json)
if ($bytes.Length -gt 8MB) { throw 'Allocation report exceeds the bounded output.' }
[Ntfs2Refs.NativeAllocationEvidence]::WriteReport($outputFull,$bytes)
[pscustomobject]@{ OutputPath=$outputFull; Complete=$report.complete; Files=$records.Count; Failures=$failures.Count; PhysicalMappingVerified=$false; ConversionQualified=$false }
