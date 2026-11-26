<#
.SYNOPSIS
Reads, and for one case patches, an NTFS partition's own metadata through
its disk, in the lab's control OS.

.DESCRIPTION
Invoke-DataVolumeAttempt.ps1 runs this in the guest for the features that
are not made through Windows: 'lfs2' (read-log: the two $LogFile restart
pages as a clean dismount left them) and 'ntfs30' (set-version: $Volume's
NTFS version written as 3.0 in the MFT and in $MFTMirr). The disk must be
offline for set-version, so that no file system has the volume mounted
while its bytes are written; read-version and read-log only read.

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
    [Parameter(Mandatory)][ValidateSet('read-version', 'set-version', 'read-log')][string]$Action,
    [int]$Major = -1,
    [int]$Minor = -1
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
        if (-not (Get-Disk -Number $DiskNumber).IsOffline) { throw "disk $DiskNumber is online: its volume could be mounted while `$Volume is written. Take it offline first" }
        $copies = [ordered]@{ mft = (Read-FileRecord 3 'mft'); mirror = (Read-FileRecord 3 'mirror') }
        $result.mirror_matched_before = (Get-Sha256 $copies.mft.raw) -eq (Get-Sha256 $copies.mirror.raw)
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
            $result[$copy] = [ordered]@{ at = $record.at; usn = $record.usn; version_before = $before.version; version_after = $after.version
                value_at = $before.value_at; value_hex_before = $before.value_hex; value_hex_after = $after.value_hex
                record_sha256_before = (Get-Sha256 $record.raw); record_sha256_after = (Get-Sha256 $again.raw); bytes_changed = @($changed) }
        }
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
