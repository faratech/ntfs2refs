[CmdletBinding()]
param([Parameter(Mandatory)][string]$ManifestPath,[Parameter(Mandatory)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
function Invoke-EvidenceFsutil([string[]]$Arguments) {
    # Read native stdout/stderr directly: PS5 promotes redirected stderr to a
    # terminating NativeCommandError under Stop, hiding the native exit code.
    $process = New-Object Diagnostics.Process
    try {
        $process.StartInfo.FileName = Join-Path $env:SystemRoot 'System32\fsutil.exe'
        $process.StartInfo.Arguments = (($Arguments | ForEach-Object { '"' + ($_ -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"' }) -join ' ')
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        if (-not $process.Start()) { throw 'Native evidence command did not start.' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) { $process.Kill(); $process.WaitForExit(); throw 'Native evidence command timed out.' }
        [pscustomobject]@{ exitCode=$process.ExitCode; output=$stdout.GetAwaiter().GetResult(); stderr=$stderr.GetAwaiter().GetResult() }
    } finally { $process.Dispose() }
}
Import-Module (Join-Path $PSScriptRoot 'GuestLab.psm1') -Force
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$disk = Get-LabGuestDisk $manifest
$partitions = @(Get-Partition -DiskNumber $disk.Number | Where-Object { $_.DriveLetter })
if ($partitions.Count -ne 1) { throw 'Expected exactly one mounted data partition.' }
$root = "$($partitions[0].DriveLetter):\"
$outputFull = [IO.Path]::GetFullPath($OutputPath)
if ($outputFull.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) { throw 'Evidence must be written to a different volume.' }
if (Test-Path -LiteralPath $outputFull) { throw 'Evidence output already exists.' }
$queue = New-Object 'System.Collections.Generic.Queue[string]'
$queue.Enqueue($root)
$records = New-Object 'System.Collections.Generic.List[object]'
$failures = New-Object 'System.Collections.Generic.List[string]'
if (-not ('Ntfs2Refs.NativeEvidenceStreams' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Ntfs2Refs {
 public static class NativeEvidenceStreams {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
  public static FileStream OpenRead(string path) {
   if (String.IsNullOrEmpty(path) || path.Length < 4 || !Char.IsLetter(path[0]) || path[1] != ':' || path[2] != '\\') throw new ArgumentException("Expected an absolute local file path.");
   // CreateFile supports filename:stream syntax without .NET Framework's
   // legacy path validation. This handle has read access only.
   var handle = CreateFile(path, 0x80000000, 1, IntPtr.Zero, 3, 0x08000000, IntPtr.Zero);
   if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
   try { return new FileStream(handle, FileAccess.Read, 65536, false); }
   catch { handle.Dispose(); throw; }
  }
 }
}
'@
}
while ($queue.Count) {
    $directory = $queue.Dequeue()
    try { $items = @(Get-ChildItem -LiteralPath $directory -Force) } catch { $failures.Add("Cannot enumerate ${directory}: $($_.Exception.Message)"); continue }
    foreach ($item in $items) {
        $reparse = [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
        $sddl = $null; $sacl = $null; $streams = @(); $fileId = $null
        try { $sddl = (Get-Acl -LiteralPath $item.FullName).Sddl } catch { $failures.Add("Cannot read ACL: $($item.FullName)") }
        try { $sacl = (Get-Acl -LiteralPath $item.FullName -Audit).Sddl } catch { $failures.Add("Cannot read SACL: $($item.FullName)") }
        $query = Invoke-EvidenceFsutil @('file','queryfileid',$item.FullName)
        if ($query.exitCode -eq 0) { $fileId = [regex]::Match($query.output,'0x[0-9a-fA-F]+').Value } else { $failures.Add("Cannot query file ID: $($item.FullName); exit $($query.exitCode); $($query.stderr) $($query.output)") }
        if (-not $item.PSIsContainer -and -not $reparse) {
            try {
                foreach ($entry in @(Get-Item -LiteralPath $item.FullName -Stream *)) {
                    $path = if ($entry.Stream -eq ':$DATA') { $item.FullName } else { $item.FullName + ':' + $entry.Stream }
                    $file = [Ntfs2Refs.NativeEvidenceStreams]::OpenRead($path)
                    $sha = [Security.Cryptography.SHA256]::Create()
                    try { $digest = [BitConverter]::ToString($sha.ComputeHash($file)).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose(); $file.Dispose() }
                    $streams += [pscustomobject]@{ name=$entry.Stream;length=$entry.Length;sha256=$digest }
                }
            } catch { $failures.Add("Cannot inventory streams for $($item.FullName): $($_.Exception.Message)") }
        }
        if ($item.PSIsContainer -and -not $reparse) { $queue.Enqueue($item.FullName) }
        $records.Add([pscustomobject]@{ path=$item.FullName.Substring($root.Length);directory=[bool]$item.PSIsContainer;attributes=[string]$item.Attributes;creationTimeUtc=$item.CreationTimeUtc.ToString('o');lastWriteTimeUtc=$item.LastWriteTimeUtc.ToString('o');fileId=$fileId;sddl=$sddl;auditSddl=$sacl;reparse=$reparse;streams=$streams })
    }
}
$version = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$driver = Get-Item (Join-Path $env:SystemRoot 'System32\drivers\refs.sys')
# fsutil's volume parser rejects the doubled trailing slash produced by CRT
# quoting. A drive designator is an accepted, unambiguous volume argument.
$volumeArgument = $root.TrimEnd('\')
$nativeInfo = Invoke-EvidenceFsutil @('fsinfo','volumeinfo',$volumeArgument)
if ($nativeInfo.exitCode -ne 0) { $failures.Add("Native volume information failed: exit $($nativeInfo.exitCode); $($nativeInfo.stderr) $($nativeInfo.output)") }
$volume = Get-Volume -DriveLetter $partitions[0].DriveLetter
$refsInfo = if ($volume.FileSystem -eq 'ReFS') { Invoke-EvidenceFsutil @('fsinfo','refsinfo',$volumeArgument) } else { [pscustomobject]@{exitCode=$null;output='Not applicable: this control is NTFS.';stderr=''} }
if ($volume.FileSystem -eq 'ReFS' -and $refsInfo.exitCode -ne 0) { $failures.Add("Native ReFS information failed: exit $($refsInfo.exitCode); $($refsInfo.stderr) $($refsInfo.output)") }
$report = [pscustomobject]@{schemaVersion=1;diskIdentity=$manifest;fileSystem=[string]$volume.FileSystem;allocationUnitSize=$volume.AllocationUnitSize;windowsBuild=([string]$version.CurrentBuild+'.'+[string]$version.UBR);refsDriverVersion=$driver.VersionInfo.FileVersion;volumeInfo=@($nativeInfo.output,$nativeInfo.stderr);refsInfo=@($refsInfo.output,$refsInfo.stderr);nativeCommandResults=[pscustomobject]@{volumeInfo=$nativeInfo;refsInfo=$refsInfo};files=$records.ToArray();failures=$failures.ToArray();nativeEnumerationSucceeded=($failures.Count -eq 0);limitations=@('Reparse payloads and EA raw bytes require the offline inspector; this native manifest does not certify them.','Mounted read-only evidence collection does not establish crash consistency. Shut down after collection for the checkpoint.')}
$report | Add-Member -NotePropertyName evidenceScriptSha256 -NotePropertyValue ((Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant())
$report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $outputFull -Encoding UTF8
$report | Select-Object windowsBuild,refsDriverVersion,nativeEnumerationSucceeded,@{n='FileCount';e={$_.files.Count}},@{n='FailureCount';e={$_.failures.Count}}
