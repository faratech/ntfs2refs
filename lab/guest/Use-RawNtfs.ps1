<#
.SYNOPSIS
Reads, and for one case patches, an NTFS partition's own metadata through
its disk, in the lab's control OS.

.DESCRIPTION
Invoke-DataVolumeAttempt.ps1 runs this in the guest for the features that
are not made through Windows: 'lfs2' (read-log: the two $LogFile restart
pages as a clean dismount left them) and 'ntfs30' (set-version: $Volume's
NTFS version written as 3.0 in the MFT and in $MFTMirr) and 'ntfs30-headers'
(set-headers-30: every in-use FILE record of $MFT, found through $MFT's own
runs, rewritten from the NTFS 3.1 header form to the 3.0 form, and the
$MFTMirr records that mirror them, then $Volume set to 3.0; read-headers
reads the forms back once Windows has the volume mounted again). The disk
must be offline for set-version and set-headers-30, so that no file system
has the volume mounted while its bytes are written; read-version,
read-headers and read-log only read.

The two FILE record header forms: NTFS 3.1 (Windows XP and later) holds
the record's own number at 0x2c and the update sequence array at 0x30; NTFS
3.0 (Windows 2000) has no number and the array at 0x2a (ntfs-3g layout.h,
MFT_RECORD and MFT_RECORD_OLD). Microsoft documents the header with the
array directly after the 16-bit field at 0x28, that is at 0x2a, "valid
only for major version 3 and minor version 0 or 1"
(learn.microsoft.com/windows/win32/devnotes/file-record-segment-header).
A record is rewritten through its fixups: the array is moved to 0x2a with
the record's own update sequence number, and with -Layout packed (the
default, as Windows 2000 lays a record out) the attributes move down to
the first 8-byte boundary after it, the first-attribute offset and bytes
in use with them; with -Layout in-place they stay where they were. The
bytes from 0x2a to the first attribute are the array and zeros, nothing
else changes, and each record is read back and held to that.

What is read is read as the converter reads it: the boot sector gives the
sector, cluster and file-record sizes and the MFT and mirror positions
(src/ntfs_inspect.rs inspect_boot_sector), $Volume is MFT record 3 and its
version the bytes 8 and 9 of the resident $VOLUME_INFORMATION (type 0x70)
value (read_volume_version), and a restart page states its version at 0x1c
(major) and 0x1a (minor), its system page size at 0x10, its restart area
at 0x18 and the area's flags at +0x0e, bit 1 the clean dismount
(src/ntfs_log.rs). Update-sequence fixups use a 512-byte stride whatever
the sector size. A record is written back with the update sequence number
it had.

Prints one JSON object.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][int]$DiskNumber,
    # The partition's byte offset on the disk.
    [Parameter(Mandatory)][long]$PartitionOffset,
    [Parameter(Mandatory)][ValidateSet('read-version', 'set-version', 'read-log', 'set-headers-30', 'read-headers')][string]$Action,
    [int]$Major = -1,
    [int]$Minor = -1,
    # read-headers: the records set-headers-30 rewrote, each checked again.
    [long[]]$Records = @(),
    # set-headers-30: 'packed' lays a record out as Windows 2000 does (its
    # attributes moved down to the first 8-byte boundary after the 3.0
    # array, 0x30 for 1 KiB records); 'in-place' leaves them where the 3.1
    # form put them (0x38).
    [ValidateSet('packed', 'in-place')][string]$Layout = 'packed',
    # set-headers-30: the first record number rewritten. 0 rewrites the
    # system files too; 16 only ordinary files and directories (records 0
    # to 15, $MFT to the reserved ones, keep the 3.1 form, and $MFTMirr with
    # them).
    [ValidateRange(0, 16)][int]$FromRecord = 0
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
if (-not ('N2RLabRawNtfs' -as [type])) {
    Add-Type -TypeDefinition @'
using System; using System.IO; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles;
public static class N2RLabRawNtfs {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFilePointerEx(SafeFileHandle handle, long distance, out long position, uint method);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadFile(SafeFileHandle handle, byte[] buffer, int count, out int done, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteFile(SafeFileHandle handle, byte[] buffer, int count, out int done, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FlushFileBuffers(SafeFileHandle handle);
    // A multiple of every sector size a lab disk has (512 and 4096).
    const long Align = 4096;
    const int Stride = 512;

    static Exception Failed(string what, string device, long at) {
        int code = Marshal.GetLastWin32Error();
        return new IOException(what + " " + device + " at byte " + at + ": " + new System.ComponentModel.Win32Exception(code).Message + " (Windows error " + code + ")");
    }
    static SafeFileHandle Open(string device, bool write) {
        SafeFileHandle handle = CreateFileW(device, write ? 0xC0000000u : 0x80000000u, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (handle.IsInvalid) throw Failed(write ? "opening for writing" : "opening for reading", device, 0);
        return handle;
    }
    static byte[] ReadAligned(SafeFileHandle handle, string device, long start, int length) {
        long position;
        if (!SetFilePointerEx(handle, start, out position, 0)) throw Failed("seeking", device, start);
        byte[] buffer = new byte[length];
        int done;
        if (!ReadFile(handle, buffer, length, out done, IntPtr.Zero)) throw Failed("reading", device, start);
        if (done != length) throw new IOException("short read of " + device + " at byte " + start + ": " + done + " of " + length + " bytes");
        return buffer;
    }
    // Bytes at any offset, read in whole aligned blocks.
    public static byte[] Read(string device, long offset, int count) {
        long start = offset - offset % Align;
        long end = (offset + count + Align - 1) / Align * Align;
        using (SafeFileHandle handle = Open(device, false)) {
            byte[] block = ReadAligned(handle, device, start, checked((int)(end - start)));
            byte[] result = new byte[count];
            Array.Copy(block, offset - start, result, 0, count);
            return result;
        }
    }
    // Bytes written at any offset: the aligned blocks around them are read,
    // changed and written whole.
    public static void Write(string device, long offset, byte[] bytes) {
        long start = offset - offset % Align;
        long end = (offset + bytes.Length + Align - 1) / Align * Align;
        int length = checked((int)(end - start));
        using (SafeFileHandle handle = Open(device, true)) {
            byte[] block = ReadAligned(handle, device, start, length);
            Array.Copy(bytes, 0, block, offset - start, bytes.Length);
            long position;
            if (!SetFilePointerEx(handle, start, out position, 0)) throw Failed("seeking", device, start);
            int done;
            if (!WriteFile(handle, block, length, out done, IntPtr.Zero)) throw Failed("writing", device, start);
            if (done != length) throw new IOException("short write of " + device + " at byte " + start + ": " + done + " of " + length + " bytes");
            if (!FlushFileBuffers(handle)) throw Failed("flushing", device, start);
        }
    }
    public static int U16(byte[] b, int at) { return b[at] | b[at + 1] << 8; }
    public static long U32(byte[] b, int at) { return (long)((uint)(b[at] | b[at + 1] << 8 | b[at + 2] << 16 | b[at + 3] << 24)); }
    // Applies a protected structure's update sequence (its whole length is
    // the structure) and answers its update sequence number.
    public static int Unfix(byte[] b, string what) {
        int usa = U16(b, 4), count = U16(b, 6);
        if (b.Length % Stride != 0 || count != b.Length / Stride + 1 || usa < 0x1e || usa % 2 != 0 || usa + count * 2 > Stride - 2)
            throw new InvalidDataException(what + ": update sequence array at " + usa + " with " + count + " entries does not fit a " + b.Length + "-byte structure");
        int usn = U16(b, usa);
        for (int i = 1; i < count; i++) {
            int tail = i * Stride - 2;
            if (U16(b, tail) != usn) throw new InvalidDataException(what + ": torn at stride " + i + " (sequence " + U16(b, tail) + ", expected " + usn + ")");
            b[tail] = b[usa + 2 * i]; b[tail + 1] = b[usa + 2 * i + 1];
        }
        return usn;
    }
    // The reverse, with the sequence number the array holds.
    public static void Fix(byte[] b) {
        int usa = U16(b, 4), count = U16(b, 6);
        byte low = b[usa], high = b[usa + 1];
        for (int i = 1; i < count; i++) {
            int tail = i * Stride - 2;
            b[usa + 2 * i] = b[tail]; b[usa + 2 * i + 1] = b[tail + 1];
            b[tail] = low; b[tail + 1] = high;
        }
    }
    // The offset of the first unnamed attribute of a type in a FILE record, or -1.
    public static int Find(byte[] record, long type) {
        int at = U16(record, 0x14);
        while (at + 16 <= record.Length) {
            long found = U32(record, at);
            if (found == 0xFFFFFFFFL) break;
            int length = (int)U32(record, at + 4);
            if (length < 16 || at + length > record.Length) throw new InvalidDataException("attribute at " + at + " has length " + length);
            if (found == type && record[at + 9] == 0) return at;
            at += length;
        }
        return -1;
    }
    // The runs of a non-resident attribute: (first VCN, LCN or -1 for a hole, clusters) each.
    public static long[] Runs(byte[] record, int attribute) {
        int length = (int)U32(record, attribute + 4);
        int at = attribute + U16(record, attribute + 0x20);
        long vcn = BitConverter.ToInt64(record, attribute + 0x10), lcn = 0;
        System.Collections.Generic.List<long> runs = new System.Collections.Generic.List<long>();
        while (at < attribute + length && record[at] != 0) {
            int header = record[at++], sizeBytes = header & 0xF, offsetBytes = header >> 4;
            if (sizeBytes == 0 || sizeBytes > 8 || offsetBytes > 8) throw new InvalidDataException("mapping pair header " + header + " at " + (at - 1));
            long clusters = 0;
            for (int i = 0; i < sizeBytes; i++) clusters |= (long)record[at + i] << (8 * i);
            at += sizeBytes;
            long start = -1;
            if (offsetBytes > 0) {
                long delta = 0;
                for (int i = 0; i < offsetBytes; i++) delta |= (long)record[at + i] << (8 * i);
                int unused = 64 - 8 * offsetBytes;
                delta = (delta << unused) >> unused;
                at += offsetBytes;
                lcn += delta; start = lcn;
            }
            runs.Add(vcn); runs.Add(start); runs.Add(clusters);
            vcn += clusters;
        }
        return runs.ToArray();
    }
    // Bytes of a stream from its runs.
    public static byte[] ReadStream(string device, long partition, long cluster, long[] runs, long offset, int count) {
        byte[] result = new byte[count];
        int done = 0;
        while (done < count) {
            long vcn = (offset + done) / cluster, within = (offset + done) % cluster;
            bool mapped = false;
            for (int r = 0; r < runs.Length; r += 3) {
                if (vcn < runs[r] || vcn >= runs[r] + runs[r + 2]) continue;
                if (runs[r + 1] < 0) throw new InvalidDataException("the stream has a hole at cluster " + vcn);
                long left = (runs[r] + runs[r + 2] - vcn) * cluster - within;
                int take = (int)Math.Min(left, count - done);
                byte[] part = Read(device, partition + (runs[r + 1] + vcn - runs[r]) * cluster + within, take);
                Array.Copy(part, 0, result, done, take);
                done += take; mapped = true;
                break;
            }
            if (!mapped) throw new InvalidDataException("the stream has no run for cluster " + vcn);
        }
        return result;
    }
    // Bytes of a stream written through its runs, a run's piece at a time.
    public static void WriteStream(string device, long partition, long cluster, long[] runs, long offset, byte[] bytes) {
        int done = 0;
        while (done < bytes.Length) {
            long vcn = (offset + done) / cluster, within = (offset + done) % cluster;
            bool mapped = false;
            for (int r = 0; r < runs.Length; r += 3) {
                if (vcn < runs[r] || vcn >= runs[r] + runs[r + 2]) continue;
                if (runs[r + 1] < 0) throw new InvalidDataException("the stream has a hole at cluster " + vcn);
                long left = (runs[r] + runs[r + 2] - vcn) * cluster - within;
                int take = (int)Math.Min(left, bytes.Length - done);
                byte[] part = new byte[take];
                Array.Copy(bytes, done, part, 0, take);
                Write(device, partition + (runs[r + 1] + vcn - runs[r]) * cluster + within, part);
                done += take; mapped = true;
                break;
            }
            if (!mapped) throw new InvalidDataException("the stream has no run for cluster " + vcn);
        }
    }
    // The NTFS 3.1 FILE record header (Windows XP and later) holds the
    // record's own number at 0x2c and its update sequence array at 0x30; the
    // NTFS 3.0 one (Windows 2000) has no number and the array at 0x2a
    // (ntfs-3g layout.h, MFT_RECORD and MFT_RECORD_OLD). Answers the record
    // as it is on the disk in the 3.0 form, or null if it already has it:
    // the array moved to 0x2a with the record's own update sequence number
    // and count, and the fixups applied again. Packed, as Windows 2000 lays
    // a record out, the attributes move down to the first 8-byte boundary
    // after the array (0x30 for 1 KiB records, where the 3.1 form has 0x38),
    // with the first-attribute offset and bytes-in-use moved by as much and
    // the bytes freed at the end zeroed; in place, they stay where they are.
    // Either way the bytes from 0x2a to the first attribute are the array
    // and zeros, and nothing else changes.
    public static byte[] ToHeader30(byte[] raw, string what, bool packed) {
        byte[] b = (byte[])raw.Clone();
        int usn = Unfix(b, what);
        int usa = U16(b, 4), count = U16(b, 6), first = U16(b, 0x14);
        long used = U32(b, 0x18), allocated = U32(b, 0x1c);
        if (usa == 0x2a) return null;
        if (usa != 0x30) throw new InvalidDataException(what + ": update sequence array at " + usa + ", neither the 3.1 form (48) nor the 3.0 form (42)");
        int end = 0x2a + 2 * count;
        if (first < 0x38 || first < 0x30 + 2 * count || first % 8 != 0 || first >= b.Length)
            throw new InvalidDataException(what + ": first attribute at " + first + ", inside the 3.1 header (an attribute cannot start before 0x38) or misaligned");
        if (allocated != b.Length || used < first + 8 || used > b.Length || used % 8 != 0)
            throw new InvalidDataException(what + ": " + used + " bytes in use of " + allocated + " allocated, first attribute at " + first);
        // As the converter checks it: the array ends before the first stride's last word and before the first attribute.
        if (end > Stride - 2 || end > first) throw new InvalidDataException(what + ": the 3.0 array would end at " + end);
        int target = packed ? (end + 7) / 8 * 8 : first;
        int shift = first - target;
        if (shift > 0) {
            Array.Copy(b, first, b, target, (int)used - first);
            for (int i = (int)used - shift; i < used; i++) b[i] = 0;
            b[0x14] = (byte)target; b[0x15] = (byte)(target >> 8);
            long now = used - shift;
            b[0x18] = (byte)now; b[0x19] = (byte)(now >> 8); b[0x1a] = (byte)(now >> 16); b[0x1b] = (byte)(now >> 24);
        }
        for (int i = 0x2a; i < target; i++) b[i] = 0;
        b[4] = 0x2a; b[5] = 0;
        b[0x2a] = (byte)usn; b[0x2b] = (byte)(usn >> 8);
        Fix(b);
        return b;
    }
    public static bool Same(byte[] a, byte[] b) {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
        return true;
    }
    // A record read back after ToHeader30 was written: with its fixups
    // applied it has the 3.0 form, the sequence number and count it had,
    // its header fields (but for the array offset, first-attribute offset
    // and bytes in use) as they were, its attributes byte for byte where the
    // first-attribute offset now says (moved down by as much as bytes in
    // use), zeros between the array and them and in what the move freed,
    // and its slack after that as it was.
    public static void CheckHeader30(byte[] before, byte[] after, string what) {
        byte[] old = (byte[])before.Clone(), now = (byte[])after.Clone();
        int usnBefore = Unfix(old, what + " before"), usnAfter = Unfix(now, what + " read back");
        int count = U16(old, 6), first = U16(old, 0x14), target = U16(now, 0x14);
        long used = U32(old, 0x18), usedNow = U32(now, 0x18);
        int shift = first - target;
        Func<string, Exception> bad = why => new InvalidDataException(what + " reads back " + why);
        if (U16(now, 4) != 0x2a) throw bad("with its update sequence array at " + U16(now, 4) + ", not 0x2a");
        if (U16(now, 6) != count) throw bad("with " + U16(now, 6) + " update sequence entries, not " + count);
        if (usnAfter != usnBefore) throw bad("with update sequence number " + usnAfter + ", not " + usnBefore);
        if (shift < 0 || target % 8 != 0 || target < 0x2a + 2 * count || usedNow != used - shift) throw bad("with its first attribute at " + target + " and " + usedNow + " bytes in use (they were " + first + " and " + used + ")");
        for (int i = 0; i < 0x2a; i++) {
            if (i == 4 || i == 5 || i == 0x14 || i == 0x15 || (i >= 0x18 && i < 0x1c)) continue;
            if (old[i] != now[i]) throw bad("changed at header byte " + i);
        }
        for (int i = 0x2a + 2 * count; i < target; i++) if (now[i] != 0) throw bad("with byte " + i + ", between the array and the first attribute, not zero");
        for (int i = first; i < used; i++) if (old[i] != now[i - shift]) throw bad("with its attributes changed (byte " + i + " now at " + (i - shift) + ")");
        for (int i = (int)used - shift; i < used; i++) if (now[i] != 0) throw bad("with byte " + i + ", freed by the move, not zero");
        for (int i = (int)used; i < old.Length; i++) if (old[i] != now[i]) throw bad("changed at byte " + i + ", after the bytes in use");
    }
    public static bool InUse(byte[] raw) { return (U16(raw, 0x16) & 1) != 0; }
}
'@
}
$device = "\\.\PhysicalDrive$DiskNumber"
function Get-Hex([byte[]]$Bytes, [int]$At, [int]$Count) { [BitConverter]::ToString($Bytes, $At, $Count).Replace('-', '').ToLowerInvariant() }
function Get-Sha256([byte[]]$Bytes) { $sha = [Security.Cryptography.SHA256]::Create(); try { [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() } }

# The boot sector, read as inspect_boot_sector reads it.
$boot = [N2RLabRawNtfs]::Read($device, $PartitionOffset, 512)
if ([Text.Encoding]::ASCII.GetString($boot, 3, 8) -ne 'NTFS    ' -or $boot[510] -ne 0x55 -or $boot[511] -ne 0xAA) {
    throw "the partition at byte $PartitionOffset of disk $DiskNumber has no NTFS boot sector (its name reads '$([Text.Encoding]::ASCII.GetString($boot, 3, 8))')"
}
$sector = [int][BitConverter]::ToUInt16($boot, 11)
$encoded = [int]$boot[13]
$perCluster = if ($encoded -gt 128) { [long]1 -shl (256 - $encoded) } else { [long]$encoded }
$cluster = [long]$sector * $perCluster
$mftLcn = [BitConverter]::ToInt64($boot, 48); $mirrorLcn = [BitConverter]::ToInt64($boot, 56)
$code = [int]$boot[64]
$recordBytes = if ($code -ge 128) { [int](1 -shl (256 - $code)) } else { [int]($code * $cluster) }
if ($cluster -le 0 -or $recordBytes -lt 512 -or $mftLcn -le 0 -or $mirrorLcn -le 0) { throw "the boot sector states $cluster-byte clusters, $recordBytes-byte file records, the MFT at cluster $mftLcn and its mirror at $mirrorLcn" }
$geometry = [ordered]@{ bytes_per_sector = $sector; cluster_bytes = $cluster; file_record_bytes = $recordBytes; mft_lcn = $mftLcn; mftmirr_lcn = $mirrorLcn }

# A FILE record of the MFT or of its mirror, as it is on the disk and with its fixups applied.
function Read-FileRecord([long]$Number, [string]$Copy) {
    $lcn = if ($Copy -eq 'mirror') { $mirrorLcn } else { $mftLcn }
    $at = $PartitionOffset + $lcn * $cluster + $Number * $recordBytes
    $raw = [N2RLabRawNtfs]::Read($device, $at, $recordBytes)
    $what = "MFT record $Number ($Copy copy, byte $at of disk $DiskNumber)"
    if ([Text.Encoding]::ASCII.GetString($raw, 0, 4) -ne 'FILE') { throw "$what is not a FILE record (it begins '$([Text.Encoding]::ASCII.GetString($raw, 0, 4))')" }
    $fixed = [byte[]]$raw.Clone()
    $usn = [N2RLabRawNtfs]::Unfix($fixed, $what)
    [pscustomobject]@{ at = $at; what = $what; raw = $raw; fixed = $fixed; usn = $usn }
}
# The version $Volume states, where read_volume_version reads it.
function Get-VolumeVersion($Record) {
    $attribute = [N2RLabRawNtfs]::Find($Record.fixed, 0x70)
    if ($attribute -lt 0) { throw "$($Record.what) has no volume information attribute (0x70)" }
    if ($Record.fixed[$attribute + 8] -ne 0) { throw "$($Record.what): its volume information is not resident" }
    $length = [int][N2RLabRawNtfs]::U32($Record.fixed, $attribute + 0x10)
    $value = $attribute + [N2RLabRawNtfs]::U16($Record.fixed, $attribute + 0x14)
    if ($length -lt 12 -or $value + $length -gt $Record.fixed.Length) { throw "$($Record.what): volume information of $length bytes at $value" }
    [pscustomobject]@{ value_at = $value; value_bytes = $length; version = '{0}.{1}' -f $Record.fixed[$value + 8], $Record.fixed[$value + 9]; value_hex = (Get-Hex $Record.fixed $value $length) }
}

function Assert-Offline([string]$What) {
    if (-not (Get-Disk -Number $DiskNumber).IsOffline) { throw "disk $DiskNumber is online: its volume could be mounted while $What. Take it offline first" }
}
# $Volume's version written as Major.Minor in MFT record 3 and in its
# $MFTMirr copy, each read back and held to it.
function Set-VolumeVersion($Result, [int]$Major, [int]$Minor) {
    $copies = [ordered]@{ mft = (Read-FileRecord 3 'mft'); mirror = (Read-FileRecord 3 'mirror') }
    $Result.mirror_matched_before = (Get-Sha256 $copies.mft.raw) -eq (Get-Sha256 $copies.mirror.raw)
    $wanted = '{0}.{1}' -f $Major, $Minor
    foreach ($copy in 'mft', 'mirror') {
        $record = $copies[$copy]
        $before = Get-VolumeVersion $record
        $patched = [byte[]]$record.fixed.Clone()
        $patched[$before.value_at + 8] = [byte]$Major; $patched[$before.value_at + 9] = [byte]$Minor
        [N2RLabRawNtfs]::Fix($patched)
        [N2RLabRawNtfs]::Write($device, $record.at, $patched)
        $again = Read-FileRecord 3 $copy
        $after = Get-VolumeVersion $again
        # Nothing but the two version bytes differs once the fixups are applied, and the sequence number is the one it had.
        $changed = @(for ($i = 0; $i -lt $recordBytes; $i++) { if ($record.fixed[$i] -ne $again.fixed[$i]) { $i } })
        # (The comma binds tighter than arithmetic: each sum is in brackets.)
        $allowed = @(($before.value_at + 8), ($before.value_at + 9))
        $stray = @($changed | Where-Object { $_ -notin $allowed })
        if ($after.version -ne $wanted -or $again.usn -ne $record.usn -or $stray.Count) {
            throw "$($record.what) reads $($after.version) with sequence number $($again.usn) after it was written as $wanted with $($record.usn)$(if ($stray.Count) { "; bytes other than the version changed at $($stray -join ', ')" })"
        }
        $Result[$copy] = [ordered]@{ at = $record.at; usn = $record.usn; version_before = $before.version; version_after = $after.version
            value_at = $before.value_at; value_hex_before = $before.value_hex; value_hex_after = $after.value_hex
            record_sha256_before = (Get-Sha256 $record.raw); record_sha256_after = (Get-Sha256 $again.raw); bytes_changed = @($changed) }
    }
}
# Where $MFT's records are: the runs of its unnamed $DATA in record 0, which
# have to map the whole stream (a $MFT whose mapping goes on in another
# record, through an attribute list, is refused by name, not guessed at).
function Get-MftLayout {
    $record = Read-FileRecord 0 'mft'
    $attribute = [N2RLabRawNtfs]::Find($record.fixed, 0x80)
    if ($attribute -lt 0) { throw "$($record.what) (`$MFT) has no unnamed data attribute" }
    if ($record.fixed[$attribute + 8] -ne 1) { throw "$($record.what) (`$MFT): its data is resident" }
    $lowest = [BitConverter]::ToInt64($record.fixed, $attribute + 0x10)
    $highest = [BitConverter]::ToInt64($record.fixed, $attribute + 0x18)
    $allocated = [BitConverter]::ToInt64($record.fixed, $attribute + 0x28)
    $dataBytes = [BitConverter]::ToInt64($record.fixed, $attribute + 0x30)
    # Records past the initialized length read as zeros to NTFS, whatever the disk holds there.
    $initialized = [BitConverter]::ToInt64($record.fixed, $attribute + 0x38)
    $clusters = [long]($allocated / $cluster)
    if ($lowest -ne 0 -or $highest + 1 -ne $clusters) {
        throw "`$MFT's data maps clusters $lowest to $highest of $clusters in record 0: the rest of its mapping is in another record (an attribute list), which this tool does not follow"
    }
    $runs = [N2RLabRawNtfs]::Runs($record.fixed, $attribute)
    $mapped = 0L
    for ($r = 0; $r -lt $runs.Count; $r += 3) {
        if ($runs[$r + 1] -lt 0) { throw "`$MFT's data has a hole at cluster $($runs[$r])" }
        $mapped += $runs[$r + 2]
    }
    if ($mapped -ne $clusters) { throw "`$MFT's runs map $mapped clusters of $clusters" }
    if ($runs[1] -ne $mftLcn) { throw "`$MFT's first run starts at cluster $($runs[1]), the boot sector says $mftLcn" }
    [pscustomobject]@{ runs = $runs; data_bytes = $dataBytes; initialized_bytes = $initialized
        records = [long]([Math]::Min($dataBytes, $initialized) / $recordBytes); run_count = $runs.Count / 3 }
}
# $MFT's records in chunks of about a MiB, through its runs (a chunk may
# span runs: ReadStream and WriteStream follow them).
function Get-MftChunks($Mft) {
    $per = [long][Math]::Max(1, [Math]::Floor(1MB / $recordBytes))
    for ($first = 0L; $first -lt $Mft.records; $first += $per) {
        [pscustomobject]@{ first = $first; count = [int][Math]::Min($per, $Mft.records - $first) }
    }
}

$result = [ordered]@{ action = $Action; disk = $DiskNumber; partition_offset = $PartitionOffset; geometry = $geometry }
switch ($Action) {
    'read-version' {
        foreach ($copy in 'mft', 'mirror') {
            $record = Read-FileRecord 3 $copy
            $result[$copy] = [ordered]@{ usn = $record.usn; version = (Get-VolumeVersion $record).version }
        }
    }
    'set-version' {
        if ($Major -lt 0 -or $Major -gt 255 -or $Minor -lt 0 -or $Minor -gt 255) { throw 'set-version takes -Major and -Minor' }
        Assert-Offline '$Volume is written'
        Set-VolumeVersion $result $Major $Minor
    }
    'set-headers-30' {
        Assert-Offline 'its FILE records are written'
        $mft = Get-MftLayout
        $slots = [int]([Math]::Max($cluster, 4 * [long]$recordBytes) / $recordBytes)
        $primaryBefore = @{}
        $rewritten = [Collections.Generic.List[object]]::new()
        $counts = [ordered]@{ records = $mft.records; in_use = 0; already_3_0_form = 0; not_in_use = 0; not_file = 0; left_below_from_record = 0 }
        $rewrittenSet = [Collections.Generic.HashSet[long]]::new()
        foreach ($chunk in (Get-MftChunks $mft)) {
            $bytes = [N2RLabRawNtfs]::ReadStream($device, $PartitionOffset, $cluster, $mft.runs, $chunk.first * [long]$recordBytes, $chunk.count * $recordBytes)
            $written = [Collections.Generic.List[object]]::new()
            for ($i = 0; $i -lt $chunk.count; $i++) {
                $number = $chunk.first + $i
                $raw = New-Object byte[] $recordBytes
                [Array]::Copy($bytes, $i * $recordBytes, $raw, 0, $recordBytes)
                if ($number -lt $slots) { $primaryBefore[[int]$number] = $raw }
                if ([Text.Encoding]::ASCII.GetString($raw, 0, 4) -ne 'FILE') { $counts.not_file++; continue }
                if (-not [N2RLabRawNtfs]::InUse($raw)) { $counts.not_in_use++; continue }
                $counts.in_use++
                if ($number -lt $FromRecord) { $counts.left_below_from_record++; continue }
                $new = [N2RLabRawNtfs]::ToHeader30($raw, "MFT record $number", ($Layout -eq 'packed'))
                if ($null -eq $new) { $counts.already_3_0_form++; continue }
                [Array]::Copy($new, 0, $bytes, $i * $recordBytes, $recordBytes)
                $written.Add([pscustomobject]@{ number = $number; index = $i; before = $raw; after = $new })
            }
            if (-not $written.Count) { continue }
            [N2RLabRawNtfs]::WriteStream($device, $PartitionOffset, $cluster, $mft.runs, $chunk.first * [long]$recordBytes, $bytes)
            # Read back: each record exactly as written, and in the 3.0 form with nothing but its header changed.
            $again = [N2RLabRawNtfs]::ReadStream($device, $PartitionOffset, $cluster, $mft.runs, $chunk.first * [long]$recordBytes, $chunk.count * $recordBytes)
            foreach ($entry in $written) {
                $back = New-Object byte[] $recordBytes
                [Array]::Copy($again, $entry.index * $recordBytes, $back, 0, $recordBytes)
                if (-not [N2RLabRawNtfs]::Same($back, $entry.after)) { throw "MFT record $($entry.number) does not read back as it was written" }
                [N2RLabRawNtfs]::CheckHeader30($entry.before, $back, "MFT record $($entry.number)")
                $rewritten.Add([ordered]@{ number = $entry.number; sha256_before = (Get-Sha256 $entry.before); sha256_after = (Get-Sha256 $back) })
                $null = $rewrittenSet.Add([long]$entry.number)
            }
        }
        # $MFTMirr: each slot whose MFT record was rewritten and that held the
        # same bytes as it, rewritten the same way so the two stay equal (the
        # converter requires the first four equal and every other slot equal
        # or an inactive format template, which is left as it is).
        $mirror = [Collections.Generic.List[object]]::new()
        $mirrorLeft = [Collections.Generic.List[object]]::new()
        for ($slot = 0; $slot -lt $slots; $slot++) {
            $at = $PartitionOffset + $mirrorLcn * $cluster + $slot * [long]$recordBytes
            $raw = [N2RLabRawNtfs]::Read($device, $at, $recordBytes)
            $equal = $primaryBefore.ContainsKey([int]$slot) -and [N2RLabRawNtfs]::Same($raw, $primaryBefore[[int]$slot])
            if ($slot -ge 4 -and -not $equal) { $mirrorLeft.Add($slot); continue }
            if ($slot -lt 4 -and -not $equal) { throw "`$MFTMirr slot $slot does not hold the same bytes as MFT record $slot before the rewrite" }
            if (-not $rewrittenSet.Contains([long]$slot)) { continue }
            $new = [N2RLabRawNtfs]::ToHeader30($raw, "`$MFTMirr slot $slot", ($Layout -eq 'packed'))
            if ($null -eq $new) { continue }
            [N2RLabRawNtfs]::Write($device, $at, $new)
            $back = [N2RLabRawNtfs]::Read($device, $at, $recordBytes)
            if (-not [N2RLabRawNtfs]::Same($back, $new)) { throw "`$MFTMirr slot $slot does not read back as it was written" }
            [N2RLabRawNtfs]::CheckHeader30($raw, $back, "`$MFTMirr slot $slot")
            $primaryNow = [N2RLabRawNtfs]::ReadStream($device, $PartitionOffset, $cluster, $mft.runs, $slot * [long]$recordBytes, $recordBytes)
            if (-not [N2RLabRawNtfs]::Same($back, $primaryNow)) { throw "`$MFTMirr slot $slot and MFT record $slot differ after the rewrite" }
            $mirror.Add([ordered]@{ slot = $slot; sha256_before = (Get-Sha256 $raw); sha256_after = (Get-Sha256 $back) })
        }
        Set-VolumeVersion $result 3 0
        $result.layout = $Layout
        $result.from_record = $FromRecord
        $result.mft_runs = @($mft.runs)
        $result.mft_data_bytes = $mft.data_bytes; $result.mft_initialized_bytes = $mft.initialized_bytes
        $result.headers = $counts
        $result.rewritten_count = $rewritten.Count
        $result.rewritten_records = @($rewritten | ForEach-Object { $_.number })
        $result.rewritten = @($rewritten)
        $result.mirror_slots = $slots
        $result.mirror_rewritten = @($mirror)
        $result.mirror_left_as_templates = @($mirrorLeft)
        if (-not $rewritten.Count) { throw "no MFT record was in the NTFS 3.1 header form ($($counts.in_use) in use, $($counts.already_3_0_form) already in the 3.0 form)" }
    }
    'read-headers' {
        $mft = Get-MftLayout
        $forms = @{}
        $current = [Collections.Generic.List[long]]::new()
        $state = @{}
        # Raw headers of the records NTFS needs to mount the volume and of the
        # first few rewritten ones, as the disk holds them now.
        $sampled = @(@(0, 1, 2, 3, 5) + @($Records | Select-Object -First 6) | ForEach-Object { [long]$_ } | Select-Object -Unique)
        $sample = [Collections.Generic.List[object]]::new()
        foreach ($chunk in (Get-MftChunks $mft)) {
            $bytes = [N2RLabRawNtfs]::ReadStream($device, $PartitionOffset, $cluster, $mft.runs, $chunk.first * [long]$recordBytes, $chunk.count * $recordBytes)
            for ($i = 0; $i -lt $chunk.count; $i++) {
                $number = $chunk.first + $i
                $at = $i * $recordBytes
                $file = [Text.Encoding]::ASCII.GetString($bytes, $at, 4) -eq 'FILE'
                $inUse = $file -and ([N2RLabRawNtfs]::U16($bytes, $at + 0x16) -band 1)
                $usa = if ($file) { [N2RLabRawNtfs]::U16($bytes, $at + 4) } else { -1 }
                $state[[long]$number] = [pscustomobject]@{ in_use = [bool]$inUse; usa = $usa }
                if ([long]$number -in $sampled) {
                    $raw = New-Object byte[] $recordBytes
                    [Array]::Copy($bytes, $at, $raw, 0, $recordBytes)
                    $sample.Add([ordered]@{ number = $number; sha256 = (Get-Sha256 $raw); header_hex = (Get-Hex $raw 0 0x40); usa = $usa
                        first_attribute = [N2RLabRawNtfs]::U16($raw, 0x14); bytes_in_use = [N2RLabRawNtfs]::U32($raw, 0x18); in_use = [bool]$inUse })
                }
                if (-not $inUse) { continue }
                $key = '0x{0:x}' -f $usa
                $forms[$key] = 1 + $(if ($forms.ContainsKey($key)) { $forms[$key] } else { 0 })
                if ($usa -eq 0x30) { $current.Add($number) }
            }
        }
        $result.records = $mft.records
        $result.in_use_by_array_offset = $forms
        $result.in_use_in_3_1_form = @($current)
        $result.sample = @($sample)
        if ($Records.Count) {
            $result.checked = $Records.Count
            $result.rewritten_now_3_1_form = @($Records | Where-Object { $state.ContainsKey([long]$_) -and $state[[long]$_].in_use -and $state[[long]$_].usa -eq 0x30 })
            $result.rewritten_now_other_form = @($Records | Where-Object { $state.ContainsKey([long]$_) -and $state[[long]$_].in_use -and $state[[long]$_].usa -notin 0x2a, 0x30 })
            $result.rewritten_no_longer_in_use = @($Records | Where-Object { -not $state.ContainsKey([long]$_) -or -not $state[[long]$_].in_use })
        }
        $result.mirror = @(for ($slot = 0; $slot -lt 4; $slot++) {
                $raw = [N2RLabRawNtfs]::Read($device, $PartitionOffset + $mirrorLcn * $cluster + $slot * [long]$recordBytes, $recordBytes)
                [ordered]@{ slot = $slot; usa = [N2RLabRawNtfs]::U16($raw, 4) }
            })
        $volume = Read-FileRecord 3 'mft'
        $result.version = (Get-VolumeVersion $volume).version
    }
    'read-log' {
        $record = Read-FileRecord 2 'mft'
        $attribute = [N2RLabRawNtfs]::Find($record.fixed, 0x80)
        if ($attribute -lt 0) { throw "$($record.what) (`$LogFile) has no unnamed data attribute" }
        if ($record.fixed[$attribute + 8] -ne 1) { throw "$($record.what) (`$LogFile): its data is resident" }
        $runs = [N2RLabRawNtfs]::Runs($record.fixed, $attribute)
        $logBytes = [BitConverter]::ToInt64($record.fixed, $attribute + 0x30)
        $read = { param($offset, $count) [N2RLabRawNtfs]::ReadStream($device, $PartitionOffset, $cluster, $runs, $offset, $count) }
        $first = & $read 0 4096
        $magic = [Text.Encoding]::ASCII.GetString($first, 0, 4)
        if ($magic -ne 'RSTR') { throw "the first `$LogFile restart page begins '$magic', not 'RSTR'" }
        $page = [long][N2RLabRawNtfs]::U32($first, 0x10)
        if ($page -lt 4096 -or $page -gt 65536 -or ($page -band ($page - 1))) { throw "the first `$LogFile restart page states a $page-byte system page" }
        $both = & $read 0 ([int](2 * $page))
        $pages = foreach ($index in 0, 1) {
            $bytes = New-Object byte[] $page
            [Array]::Copy($both, $index * $page, $bytes, 0, $page)
            $rawSha = Get-Sha256 $bytes
            $pageMagic = [Text.Encoding]::ASCII.GetString($bytes, 0, 4)
            if ($pageMagic -ne 'RSTR') { throw "`$LogFile restart page $index begins '$pageMagic', not 'RSTR'" }
            $null = [N2RLabRawNtfs]::Unfix($bytes, "`$LogFile restart page $index")
            $area = [N2RLabRawNtfs]::U16($bytes, 0x18)
            if ($area + 0x10 -gt $page) { throw "`$LogFile restart page $index states its restart area at $area" }
            $flags = [N2RLabRawNtfs]::U16($bytes, $area + 0x0e)
            [ordered]@{ index = $index; raw_sha256 = $rawSha
                lfs_version = '{0}.{1}' -f [N2RLabRawNtfs]::U16($bytes, 0x1c), [N2RLabRawNtfs]::U16($bytes, 0x1a)
                header_hex = (Get-Hex $bytes 0 0x20)
                system_page_bytes = [N2RLabRawNtfs]::U32($bytes, 0x10); log_page_bytes = [N2RLabRawNtfs]::U32($bytes, 0x14)
                restart_area_at = $area; current_lsn = [BitConverter]::ToUInt64($bytes, $area)
                log_clients = [N2RLabRawNtfs]::U16($bytes, $area + 8); clients_in_use = [N2RLabRawNtfs]::U16($bytes, $area + 0x0c)
                flags = $flags; clean_dismount = [bool]($flags -band 2) }
        }
        $result.logfile = [ordered]@{ bytes = $logBytes; runs = @($runs) }
        $result.pages = @($pages)
        $result.lfs_version = if ($pages[0].lfs_version -eq $pages[1].lfs_version) { $pages[0].lfs_version } else { "$($pages[0].lfs_version) and $($pages[1].lfs_version)" }
        $result.clean_dismount = [bool]($pages[0].clean_dismount -and $pages[1].clean_dismount)
    }
}
[pscustomobject]$result | ConvertTo-Json -Depth 6 -Compress
