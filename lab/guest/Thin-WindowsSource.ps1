<# Guest worker: thin an offline Windows volume to a small sample of itself.

   Runs in the control OS as SYSTEM (Windows PowerShell 5.1) against the mounted
   source volume. It keeps what the converter's boot checks need, every reparse
   point, and a deterministic 1-in-N sample of everything else; it deletes the
   rest through the NTFS driver using backup/restore privileges. Anything that
   refuses deletion is simply kept. The result is a real Windows-shaped NTFS
   volume with the same feature classes and far fewer objects. Not bootable. #>
param([Parameter(Mandatory)][string]$Drive, [int]$KeepOneIn = 10, [Parameter(Mandatory)][string]$ResultPath)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
# C# 5 only: Windows PowerShell compiles this with the in-box compiler.
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public class N2RThin {
    [StructLayout(LayoutKind.Sequential)] struct LUID { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] struct TOKEN_PRIVILEGES { public uint Count; public LUID Luid; public uint Attributes; }
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool LookupPrivilegeValue(string system, string name, out LUID luid);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES state, uint length, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFileInformationByHandle(SafeFileHandle handle, int infoClass, ref uint info, uint size);

    public long FilesSeen, FilesDeleted, FilesKept, FilesRefused, DirectoriesSeen, DirectoriesDeleted, DirectoriesUnreadable, ReparsePointsKept, BytesDeleted;
    public Dictionary<int, long> RefusalCodes = new Dictionary<int, long>();
    public List<string> RefusedExamples = new List<string>();
    string root; ulong keepOneIn; HashSet<string> keepExact; string[] keepUnder;

    public static void EnablePrivilege(string name) {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token)) throw new Win32Exception();
        TOKEN_PRIVILEGES state = new TOKEN_PRIVILEGES(); state.Count = 1; state.Attributes = 2;
        if (!LookupPrivilegeValue(null, name, out state.Luid)) throw new Win32Exception();
        if (!AdjustTokenPrivileges(token, false, ref state, 0, IntPtr.Zero, IntPtr.Zero) || Marshal.GetLastWin32Error() != 0)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "privilege not held: " + name);
    }
    // 0 on success, otherwise the Win32 error. Never follows a reparse point.
    static int Delete(string path) {
        // DELETE, all sharing, OPEN_EXISTING, BACKUP_SEMANTICS | OPEN_REPARSE_POINT
        using (SafeFileHandle handle = CreateFileW(@"\\?\" + path, 0x00010000, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero)) {
            if (handle.IsInvalid) return Marshal.GetLastWin32Error();
            uint flags = 0x13; // DELETE | POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE
            if (!SetFileInformationByHandle(handle, 21 /* FileDispositionInfoEx */, ref flags, 4)) return Marshal.GetLastWin32Error();
            return 0;
        }
    }
    // FNV-1a over the lower-cased relative path: stable across runs.
    bool Sampled(string relative) {
        ulong h = 14695981039346656037UL;
        unchecked { foreach (char c in relative) { h = (h ^ c) * 1099511628211UL; } }
        return h % keepOneIn == 0;
    }
    public N2RThin(string root, int keepOneIn, string[] keepExact, string[] keepUnder) {
        this.root = root; this.keepOneIn = (ulong)keepOneIn; this.keepExact = new HashSet<string>(keepExact); this.keepUnder = keepUnder;
    }
    public void Run() { Visit(root.TrimEnd('\\')); }
    // Returns true when the directory still has entries afterwards.
    bool Visit(string directory) {
        string[] entries;
        try { entries = Directory.GetFileSystemEntries(@"\\?\" + directory + @"\"); }
        catch (Exception) { DirectoriesUnreadable++; return true; }
        bool remaining = false;
        foreach (string full in entries) {
            string entry = full.Substring(4);
            string relative = entry.Substring(root.Length).ToLowerInvariant();
            FileAttributes attributes;
            try { attributes = File.GetAttributes(full); } catch (Exception) { remaining = true; continue; }
            if ((attributes & FileAttributes.ReparsePoint) != 0) { ReparsePointsKept++; remaining = true; continue; }
            if ((attributes & FileAttributes.Directory) != 0) {
                DirectoriesSeen++;
                bool protectedTree = false;
                foreach (string prefix in keepUnder) { if ((relative + @"\").StartsWith(prefix)) { protectedTree = true; break; } }
                if (protectedTree) { remaining = true; continue; }
                bool childRemaining = Visit(entry);
                if (!childRemaining && !Sampled(relative) && Delete(entry) == 0) { DirectoriesDeleted++; } else { remaining = true; }
                continue;
            }
            FilesSeen++;
            if (keepExact.Contains(relative) || Sampled(relative)) { FilesKept++; remaining = true; continue; }
            long length = 0; try { length = new FileInfo(full).Length; } catch (Exception) { }
            int code = Delete(entry);
            if (code == 0) { FilesDeleted++; BytesDeleted += length; }
            else {
                FilesRefused++; remaining = true;
                long count; RefusalCodes.TryGetValue(code, out count); RefusalCodes[code] = count + 1;
                if (RefusedExamples.Count < 40) RefusedExamples.Add(code + " " + relative);
            }
        }
        return remaining;
    }
}
'@
foreach ($privilege in 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeTakeOwnershipPrivilege') { [N2RThin]::EnablePrivilege($privilege) }
$keepExact = [string[]]@('windows\system32\winload.efi', 'windows\system32\winload.exe', 'windows\system32\ntoskrnl.exe',
    'windows\system32\drivers\refs.sys', 'windows\system32\hal.dll', 'windows\system32\ci.dll')
$keepUnder = [string[]]@('windows\system32\config\', 'windows\boot\', 'system volume information\', 'efi\', 'boot\')
$thin = [N2RThin]::new("${Drive}:\", $KeepOneIn, $keepExact, $keepUnder)
$watch = [Diagnostics.Stopwatch]::StartNew(); $failure = $null
try { $thin.Run() } catch { $failure = ($_ | Out-String) }
$volume = Get-Volume -DriveLetter $Drive
$codes = @{}; foreach ($pair in $thin.RefusalCodes.GetEnumerator()) { $codes[[string]$pair.Key] = $pair.Value }
$stats = [ordered]@{
    files_seen = $thin.FilesSeen; files_deleted = $thin.FilesDeleted; files_kept = $thin.FilesKept; files_refused = $thin.FilesRefused
    directories_seen = $thin.DirectoriesSeen; directories_deleted = $thin.DirectoriesDeleted; directories_unreadable = $thin.DirectoriesUnreadable
    reparse_points_kept = $thin.ReparsePointsKept; bytes_deleted = $thin.BytesDeleted; refusal_codes = $codes
    refused_examples = @($thin.RefusedExamples); seconds = [Math]::Round($watch.Elapsed.TotalSeconds, 1); error = $failure
    volume_used_bytes_after = $volume.Size - $volume.SizeRemaining
}
[IO.File]::WriteAllText($ResultPath, ($stats | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
