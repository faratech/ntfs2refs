# Start one exact-7feb public recovery in the enrolled owning VM. This bounded
# lab dispatcher does not restore/boot/stop/checkpoint, change disk attributes,
# or replace the native journal/device checks. It omits the older independent
# full-baseline pre/post scan; no 811-stream or power-loss claim follows.
#Requires -Version 5.1
[CmdletBinding()]
param(
 [Parameter(Mandatory)][ValidateSet('Resume','Rollback')][string]$Operation,
 [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds,
 [Parameter(Mandatory)][ValidateRange(1,50000000000)][long]$ForecastAdditionalBytes,
 [switch]$AcknowledgeEnrolledDisposableDevices
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$vmId=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$original=[guid]'58bd9ceb-60bc-4b34-81e1-7af197523a80';$sourceParent=[guid]'a0627dbd-aa3b-4896-bbeb-495f5e372057'
$sourceCommit='7feb4c06d21e9de73bb88961197f5b745463e490';$exeSha='c7b5809f4456f55e71f19b47d4e4cb9b7ee6cad86c4ff0fac36c1db5a5b909d1'
$buildSha='d4afec214f672fe4eb3b12c5e82a5315ccbee25f92f9222ef426605948f54814';$receiptSha='d4321534441dfcd7a8bf2a91358950b7caaf4af9620b48fb818f0fd13068aa8a'
$bundleSha='334098c8baa0a04c95275130d2714b1551740dfeee66a011db179000ad2f7baa';$ticketSha='f8f24a9764f4e5eb1950942c3d0184b809245762cfd49ad4cc8b1c37c3c08f7b';$requestSha='8ed66ae01482fe29a636277f276bf2231b65e243318cbce075836b9e13fb5bdb'
$candidate=Join-Path $workspace '.lab\development\release-candidates\r7feb4c0';$binary=Join-Path $candidate 'bin\ntfs2refs.exe'
$producerRoot=Join-Path $base 'paged-envelope-interrupt-fe086985340548db9eb098a884f4d1be';$receipt=Join-Path $producerRoot 'checkpoint-observer-completed.json'
$bundle=Join-Path $producerRoot 'closed\producer\conversion\allocation-recovery-bundle.json';$ticket=Join-Path $producerRoot 'closed\producer\conversion\selected-ticket.json'
$guestRecovery='C:\ntfs2refs\paged-envelope-interrupt-fe086985340548db9eb098a884f4d1be\conversion';$guestBundle=Join-Path $guestRecovery 'allocation-recovery-bundle.json';$guestShadow='C:\ntfs2refs\paged-envelope-interrupt-fe086985340548db9eb098a884f4d1be\managed-shadow\shadow.vhdx'
$mode=$Operation.ToLowerInvariant();$run=[guid]::NewGuid().ToString('N');$root=Join-Path $base ('paged-envelope-recovery-'+$mode+'-'+$run)
$stage='C:\ntfs2refs\paged-envelope-recovery-'+$mode+'-'+$run;$task='N2R-PagedEnvelope-Recovery-'+$mode+'-'+$run
$ids=@($ExpectedCheckpointIds|ForEach-Object {$_.ToString('D')});$held=[Collections.Generic.List[IO.FileStream]]::new();$session=$null;$created=$false;$dispatched=$false
function Need([bool]$ok,[string]$message){if(-not$ok){throw $message}}
function Ordinary([string]$path,[bool]$directory){$m=Get-Item -LiteralPath $path -Force;Need ($m.PSIsContainer-eq$directory) 'Ordinary path type differs.';$p=$m;while($null-ne$p){Need (-not($p.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse ancestry refused.';if($p-is[IO.DirectoryInfo]){$p=$p.Parent}else{$p=$p.Directory}};return $m}
function Pin([string]$path,[string]$sha,[long]$maximum,[bool]$parse){
 Need ([IO.Path]::GetFullPath($path)-ceq$path-and$sha-cmatch'\A[0-9a-f]{64}\z') 'Absolute pinned input required.';$m=Ordinary $path $false;Need ($m.Length-gt0-and$m.Length-le$maximum) 'Bounded input required.'
 $f=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$held.Add($f);$h=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($h.ComputeHash($f))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};Need ($actual-ceq$sha-and$f.Length-eq$m.Length) 'Held source input differs.';$f.Position=0;$value=$null
 if($parse){$r=[IO.StreamReader]::new($f,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true);try{$value=$r.ReadToEnd()|ConvertFrom-Json}finally{$r.Dispose()};$f.Position=0};return @{path=$path;bytes=$m.Length;sha256=$actual;value=$value}
}
function Save([string]$name,$value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 24));Need ($bytes.Length-gt0-and$bytes.Length-le1MB) 'Bounded host receipt required.';$f=[IO.File]::Open((Join-Path $root $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
function SharedBytes([string]$relative){
 Need ($relative-cin@('target\shared-experiments','target\shared-experiments-staging')) 'Exact shared build storage root required.';$path=Join-Path $workspace $relative;if(-not(Test-Path -LiteralPath $path)){return [long]0};$null=Ordinary $path $true;$q=[Collections.Generic.Queue[string]]::new();$q.Enqueue($path);$n=[long]0
 while($q.Count){foreach($m in Get-ChildItem -LiteralPath $q.Dequeue() -Force){Need (-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse shared target refused.';if($m.PSIsContainer){$q.Enqueue($m.FullName)}else{Need ($n-le[long]::MaxValue-$m.Length) 'Shared storage sum overflow.';$n+=$m.Length}}};return $n
}
function Capacity {
 $actual=Get-LabCapacity -Configuration $configuration;$cache=SharedBytes 'target\shared-experiments';$staging=SharedBytes 'target\shared-experiments-staging'
 Need ($actual.MaximumActualBytes-eq329374052988-and$actual.MinimumFreeBytes-eq17179869184-and$actual.ActualBytes-le[long]::MaxValue-$cache-and([long]$actual.ActualBytes+$cache)-le[long]::MaxValue-$staging) 'Original capacity epoch/reserve or arithmetic differs.'
 $combined=[pscustomobject]@{ActualBytes=([long]$actual.ActualBytes+$cache+$staging);FreeBytes=$actual.FreeBytes;MaximumActualBytes=$actual.MaximumActualBytes;MinimumFreeBytes=$actual.MinimumFreeBytes};Assert-LabCapacity -Capacity $combined -AdditionalBytes $ForecastAdditionalBytes
 return @{lab_bytes=$actual.ActualBytes;shared_target_bytes=$cache;shared_source_staging_bytes=$staging;forecast_bytes=$ForecastAdditionalBytes;host_available_bytes=$actual.FreeBytes;minimum_host_free_bytes=$actual.MinimumFreeBytes;maximum_actual_bytes=$actual.MaximumActualBytes;forecast_is_reservation=$false}
}
function SourceChain([string]$path){
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$current=[IO.Path]::GetFullPath($path)
 while($true){
  Need ($current.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)-and$seen.Add($current)) 'Source VHD ancestry escaped the owned lab or cycled.'
  $null=Ordinary $current $false;$vhd=Get-VHD -Path $current -ErrorAction Stop
  Need ([guid]$vhd.DiskIdentifier-eq[guid]'5e010a4c-f0f9-451d-9174-d8ba87de3b21'-and$vhd.Size-eq64GB-and$vhd.LogicalSectorSize-eq512-and$vhd.PhysicalSectorSize-eq4096-and$vhd.VhdFormat.ToString()-ceq'VHDX') 'Original source VHD identity/geometry differs.'
  if([string]::IsNullOrEmpty($vhd.ParentPath)){Need ($vhd.VhdType.ToString()-in@('Dynamic','Fixed')) 'Original source root type differs.';break}
  Need ($vhd.VhdType.ToString()-ceq'Differencing') 'Non-root source VHD must be differencing.';$next=[string]$vhd.ParentPath;if(-not[IO.Path]::IsPathRooted($next)){$next=Join-Path (Split-Path $current -Parent) $next};$current=[IO.Path]::GetFullPath($next)
 }
}
function HostGuard {
 $vm=Get-VM -Id $vmId -ErrorAction Stop;$nodes=@(Get-VMSnapshot -VM $vm -ErrorAction Stop);$actual=@($nodes|ForEach-Object {$_.Id.ToString('D')});$old=@($nodes|Where-Object {$_.Id-eq$original})
 Need ($vm.Name-ceq'ntfs2refs-streaming-v2-20261027'-and$vm.State.ToString()-ceq'Running'-and$vm.ParentSnapshotId-eq$original-and$vm.MemoryStartup-eq4GB-and$vm.MemoryAssigned-eq4GB-and-not$vm.DynamicMemoryEnabled-and(Get-VMProcessor -VM $vm).Count-eq4-and@(Get-VMNetworkAdapter -VM $vm).Count-eq0) 'Exact running original-parent VM/4GiB/4CPU/noNIC required.'
 Need ($ids.Count-gt0-and$ids.Count-eq$actual.Count-and@($ids|Sort-Object -Unique).Count-eq$ids.Count-and@($ids|Where-Object {$_-notin$actual}).Count-eq0-and$old.Count-eq1-and$old[0].ParentSnapshotId-eq$sourceParent) 'Exact original checkpoint ancestry/inventory required.'
 $all=@(Get-VMHardDiskDrive -VM $vm);$locations=@($all|ForEach-Object {$_.ControllerLocation});Need ($all.Count-eq6-and@($all|Where-Object {$_.ControllerType.ToString()-cne'SCSI'-or$_.ControllerNumber-ne0}).Count-eq0-and@(0,1,2,4,5,6|Where-Object {$_-notin$locations}).Count-eq0) 'Exact original six SCSI attachments required.'
 $source=@($all|Where-Object ControllerLocation -EQ 1);Need ($source.Count-eq1-and$source[0].Path.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)) 'Exact owned source attachment required.';SourceChain $source[0].Path;return $vm
}

$guestGuard=@'
function Need([bool]$ok,[string]$message){if(-not$ok){throw $message}}
function Inventory {
 $all=@(Get-Disk -ErrorAction Stop|Sort-Object Number);Need ($all.Count-eq6) 'Exactly six enrolled guest disks required; original managed shadow must be absent.'
 $expected=@('1f804918-e98f-4a71-9022-fc00c3cb7c26','1b191872-c372-41ee-a416-e18863996f54','09fcc613-b8c2-4a1a-8833-226f9399be7f','c0f2cd39-ad3d-484e-9990-0e6eba74485f','e1f3b9d3-979f-4123-9fee-399640c25092','ad077674-6305-4767-a2aa-6ded3b707e36')
 $rows=@();$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
 for($i=0;$i-lt6;$i++){$d=$all[$i];$id=[guid]::Empty;Need ($d.Number-eq$i-and[guid]::TryParse([string]$d.Guid,[ref]$id)-and$id-eq[guid]$expected[$i]-and$seen.Add($id.ToString('D'))) 'Guest disk inventory GUID/number differs.';$rows+=[pscustomobject][ordered]@{number=[int]$d.Number;guid=$id.ToString('D');bytes=[long]$d.Size;offline=[bool]$d.IsOffline;readonly=[bool]$d.IsReadOnly;boot=[bool]$d.IsBoot;system=[bool]$d.IsSystem}}
 return $rows
}
function Routes {
 Need ($env:COMPUTERNAME-ceq'N2R-WIN11'-and$env:SystemDrive-ceq'C:') 'Exact owning guest required.'
 $s=Get-Disk -Number 1;$sp=Get-Partition -DiskNumber 1 -PartitionNumber 2
 Need ($s.PartitionStyle.ToString()-ceq'GPT'-and[guid]$s.Guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'-and$s.Size-eq64GB-and$s.LogicalSectorSize-eq512-and$s.PhysicalSectorSize-eq4096-and$s.IsOffline-and-not$s.IsReadOnly-and-not$s.IsBoot-and-not$s.IsSystem-and[guid]$sp.Guid-eq[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-and$sp.Offset-eq16MB-and$sp.Size-eq52GB) 'Original interrupted source identity/exclusion differs.'
 $o=Get-Disk -Number 0;$op=Get-Partition -DiskNumber 0 -PartitionNumber 3;$cp=Get-Partition -DriveLetter C;$cv=$cp|Get-Volume
 Need ($o.PartitionStyle.ToString()-ceq'GPT'-and[guid]$o.Guid-eq[guid]'1f804918-e98f-4a71-9022-fc00c3cb7c26'-and$o.Size-eq64GB-and$o.LogicalSectorSize-eq512-and$o.PhysicalSectorSize-eq4096-and-not$o.IsOffline-and-not$o.IsReadOnly-and[guid]$op.Guid-eq[guid]'c6c3318f-a7c8-47b9-be6d-6dde5e00862f'-and$op.Offset-eq331350016-and$op.Size-eq66238545920-and'\\?\Volume{c6c3318f-a7c8-47b9-be6d-6dde5e00862f}\'-in@($op.AccessPaths)-and$cp.DiskNumber-eq0-and$cp.PartitionNumber-eq3-and$cv.FileSystem-ceq'NTFS'-and$cv.SizeRemaining-ge1GB) 'Actual independent OS/journal volume differs.'
 $g=Get-Disk -Number 4;$gp=Get-Partition -DriveLetter G;$gv=$gp|Get-Volume;$old=Get-Disk -Number 5
 Need ([guid]$g.Guid-eq[guid]'e1f3b9d3-979f-4123-9fee-399640c25092'-and-not$g.IsOffline-and-not$g.IsReadOnly-and$gp.DiskNumber-eq4-and$gv.FileSystem-ceq'ReFS'-and$gv.AllocationUnitSize-eq4096-and[guid]$old.Guid-eq[guid]'ad077674-6305-4767-a2aa-6ded3b707e36'-and$old.IsOffline-and$old.IsReadOnly) 'Other protected test disks differ.'
 Need (-not(Test-Path -LiteralPath (Join-Path $c.recovery 'compact-recovery-bundle.json'))-and(Get-FileHash -LiteralPath $c.bundle -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$c.bundle_sha256-and(Get-FileHash -LiteralPath (Join-Path $c.recovery 'selected-ticket.json') -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$c.ticket_sha256-and(Get-FileHash -LiteralPath (Join-Path $c.recovery 'request.json') -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$c.request_sha256) 'Self-contained allocation bundle selection or original bundle/ticket/request pins differ.'
 return @{source_disk=1;source_offline=[bool]$s.IsOffline;source_readonly=[bool]$s.IsReadOnly;source_guid=[string]$s.Guid;journal_disk=0;journal_guid=[string]$o.Guid;journal_volume_guid=[string]$op.Guid;journal_free_bytes=[long]$cv.SizeRemaining;inventory=@(Inventory);utc=[DateTime]::UtcNow.ToString('o')}
}
function Idle([string]$ownTask){
 $others=@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.TaskName-cne$ownTask-and$_.State.ToString()-notin@('Ready','Disabled')});$procs=@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'})
 Need ($others.Count-eq0-and$procs.Count-eq0) 'Another project task/process is active.'
}
'@

$worker=@'
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CONFIG__'))|ConvertFrom-Json
__GUARD__
function Save([string]$name,$value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 24));Need ($b.Length-le1MB) 'Bounded guest receipt required.';$f=[IO.File]::Open((Join-Path $c.stage $name),'CreateNew','Write','Read');try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Log([string]$path){$m=Get-Item -LiteralPath $path;return @{sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();bytes=[long]$m.Length}}
function BackingSnapshot([IO.FileStream]$stream){
 if(-not('N2RFastBackingV1'-as[type])){Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public sealed class N2RFastBackingResultV1 { public ulong Length, LastWriteFileTime, FileId64; public uint Attributes, VolumeSerialNumber, NumberOfLinks; }
public static class N2RFastBackingV1 {
 [StructLayout(LayoutKind.Explicit, Size=52)] private struct Info { [FieldOffset(0)] public uint Attributes; [FieldOffset(20)] public uint WriteLow; [FieldOffset(24)] public uint WriteHigh; [FieldOffset(28)] public uint VolumeSerial; [FieldOffset(32)] public uint SizeHigh; [FieldOffset(36)] public uint SizeLow; [FieldOffset(40)] public uint Links; [FieldOffset(44)] public uint IndexHigh; [FieldOffset(48)] public uint IndexLow; }
 [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
 public static N2RFastBackingResultV1 Observe(SafeFileHandle handle) { Info i; if(!GetFileInformationByHandle(handle,out i)) throw new Win32Exception(Marshal.GetLastWin32Error()); return new N2RFastBackingResultV1 { Length=((ulong)i.SizeHigh<<32)|i.SizeLow, LastWriteFileTime=((ulong)i.WriteHigh<<32)|i.WriteLow, FileId64=((ulong)i.IndexHigh<<32)|i.IndexLow, Attributes=i.Attributes, VolumeSerialNumber=i.VolumeSerial, NumberOfLinks=i.Links }; }
}
"@}
 Need ($stream.CanRead-and-not$stream.CanWrite-and-not$stream.SafeFileHandle.IsClosed-and-not$stream.SafeFileHandle.IsInvalid) 'Held exclusive backing stream required.'
 $s=[N2RFastBackingV1]::Observe($stream.SafeFileHandle);Need ($s.Length-gt0-and$s.Length-eq$stream.Length-and$s.LastWriteFileTime-gt0-and$s.FileId64-ne0-and$s.NumberOfLinks-gt0-and($s.Attributes-band1040)-eq0) 'Original held backing metadata differs.'
 return [pscustomobject][ordered]@{length=[uint64]$s.Length;last_write_filetime_100ns=[uint64]$s.LastWriteFileTime;file_id64=[uint64]$s.FileId64;volume_serial_number=[uint32]$s.VolumeSerialNumber;attributes=[uint32]$s.Attributes;number_of_links=[uint32]$s.NumberOfLinks}
}
$shadowOwner=$null;$p=$null;$stdoutStream=$null;$stderrStream=$null;$stdoutPipe=$null;$stderrPipe=$null;$nativeExit=$null
try{
 Idle $c.task;$before=Routes
 Need ((Get-FileHash -LiteralPath (Join-Path $c.stage 'ntfs2refs.exe') -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$c.binary_sha256) 'Staged published executable differs.'
 $shadow=Get-Item -LiteralPath $c.shadow -Force;Need (-not$shadow.PSIsContainer-and$shadow.Length-gt0) 'Original managed-shadow backing file is absent.';$a=$shadow;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Original backing ancestry is reparse.';if($a-is[IO.DirectoryInfo]){$a=$a.Parent}else{$a=$a.Directory}}
 $shadowOwner=[IO.File]::Open($c.shadow,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None);$shadowPin=BackingSnapshot $shadowOwner;$after=Routes
 Need ((ConvertTo-Json -InputObject $before.inventory -Depth 6 -Compress)-ceq(ConvertTo-Json -InputObject $after.inventory -Depth 6 -Compress)) 'Full disk inventory changed while holding the original absent-shadow backing.'
 Save 'preflight.json' @{schema_version=1;kind='exact-alpha-fast-recovery-preflight';before=$before;after=$after;shadow_backing_path=$c.shadow;shadow_backing=$shadowPin;shadow_ordinary_provider_excluded_while_handle_held=$true;shadow_payload_read=$false;provider_identity_not_queried=$true;native_device_and_journal_gates_unchanged=$true;independent_full_baseline_scan=$false;grants_authority=$false;utc=[DateTime]::UtcNow.ToString('o')}
 $exe=Join-Path $c.stage 'ntfs2refs.exe';$argv=@('--recover',$c.recovery,'--recovery-sha256',$c.bundle_sha256);if($c.operation-ceq'rollback'){$argv+=@('--rollback')}
 $argsLine=($argv|ForEach-Object {Need ($_-cnotmatch'["\r\n\x00]') 'Unsafe native argument.';'"'+$_+'"'})-join' '
 $stdinPath=Join-Path $c.stage 'native.stdin.txt';$f=[IO.File]::Open($stdinPath,'CreateNew','Write','Read');try{$b=[Text.Encoding]::ASCII.GetBytes("yes`r`n");$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}
 Save 'native-dispatch-intent.json' @{binary=$exe;binary_sha256=$c.binary_sha256;argv=$argv;stdin_file=$stdinPath;affirmative_stdin_yes_crlf=$true;expected_exit=0;public_recovery=$true;fresh_source_certificate_recreated=$false;utc=[DateTime]::UtcNow.ToString('o')}
 $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$exe;$start.Arguments=$argsLine;$start.WorkingDirectory=$c.stage;$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true;$start.RedirectStandardInput=$true
 $p=[Diagnostics.Process]::new();$p.StartInfo=$start;$stdout=Join-Path $c.stage 'native.stdout.log';$stderr=Join-Path $c.stage 'native.stderr.log';$stdoutStream=[IO.File]::Open($stdout,'CreateNew','Write','Read');$stderrStream=[IO.File]::Open($stderr,'CreateNew','Write','Read');$clock=[Diagnostics.Stopwatch]::StartNew()
 Need ($p.Start()) 'CreateProcess did not return an owned child.';$null=$p.Handle;$birth=([DateTimeOffset]$p.StartTime).ToUnixTimeMilliseconds();$nativePid=$p.Id
 $stdoutPipe=$p.StandardOutput.BaseStream;$stderrPipe=$p.StandardError.BaseStream;$stdoutDrain=$stdoutPipe.CopyToAsync($stdoutStream,65536);$stderrDrain=$stderrPipe.CopyToAsync($stderrStream,65536)
 Save 'native-process.json' @{pid=$nativePid;creation_ms=$birth;parent_pid=$PID;binary=$exe;binary_sha256=$c.binary_sha256;argv=$argv;stdin_file=$stdinPath;affirmative_stdin_yes_crlf=$true;expected_exit=0;process_handle_retained_before_wait=$true;raw_log_drains_started_before_wait=$true;utc=[DateTime]::UtcNow.ToString('o')}
 $p.StandardInput.Write("yes`r`n");$p.StandardInput.Flush();$p.StandardInput.Close();$p.WaitForExit();$clock.Stop();$p.Refresh();$nativeExit=$p.ExitCode
 $null=$stdoutDrain.GetAwaiter().GetResult();$null=$stderrDrain.GetAwaiter().GetResult();$stdoutStream.Flush($true);$stderrStream.Flush($true);$stdoutStream.Dispose();$stdoutStream=$null;$stderrStream.Dispose();$stderrStream=$null
 Save 'native-terminal.json' @{pid=$nativePid;creation_ms=$birth;native_exit=$nativeExit;native_exit_observed=$true;expected_exit=0;wall_seconds=$clock.Elapsed.TotalSeconds;process_handle_retained_through_terminal=$true;stdout=(Log $stdout);stderr=(Log $stderr);utc=[DateTime]::UtcNow.ToString('o')}
 Need ($nativeExit-eq0) 'The one actual public recovery process failed; no retry is attempted.'
 $postShadow=BackingSnapshot $shadowOwner;Need ((ConvertTo-Json -InputObject $shadowPin -Compress)-ceq(ConvertTo-Json -InputObject $postShadow -Compress)) 'Original absent-shadow backing changed while held.'
 Save 'wrapper-result.json' @{schema_version=1;kind='exact-alpha-fast-recovery-process-observation';success=$true;operation=$c.operation;native_exit=$nativeExit;native_device_and_journal_gates_unchanged=$true;independent_full_baseline_scan=$false;independent_811_stream_hashes_checked=$false;power_loss_qualified=$false;automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')}
}catch{try{Save 'wrapper-failed.json' @{success=$false;native_exit=$nativeExit;native_exit_observed=($null-ne$nativeExit);error=$_.Exception.ToString();automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')}}catch{};throw}
finally{foreach($s in @($stdoutPipe,$stderrPipe,$stdoutStream,$stderrStream,$shadowOwner)){if($null-ne$s){try{$s.Dispose()}catch{}}};if($null-ne$p){$p.Dispose()}}
'@

try{
 Need $AcknowledgeEnrolledDisposableDevices 'Explicit enrolled disposable devices acknowledgment required.'
 Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force;$configuration=Get-LabConfiguration -WorkspaceRoot $workspace
 $manifest=(Pin (Join-Path $candidate 'manifest.json') $buildSha 1MB $true).value;$exe=Pin $binary $exeSha 64MB $false;$record=(Pin $receipt $receiptSha 1MB $true).value;$originalBundle=(Pin $bundle $bundleSha 1MB $true).value;$originalTicket=(Pin $ticket $ticketSha 1MB $true).value
 Need ($manifest.kind-ceq'clean-committed-source-release-candidate'-and$manifest.source_commit-ceq$sourceCommit-and-not$manifest.qualification_inherited-and-not$manifest.unit_tests_run-and@($manifest.binaries|Where-Object {$_.name-ceq'ntfs2refs'-and$_.sha256-ceq$exeSha}).Count-eq1) 'Exact clean public alpha build provenance required.'
 Need ($record.kind-ceq'paged-envelope-first-write-observer-completed-checkpoint-v2'-and[guid]$record.checkpoint_id-eq$original-and[guid]$record.checkpoint_parent_id-eq$sourceParent-and$record.source_commit-ceq$sourceCommit-and$record.native_exit-eq86-and$record.first_write_flushed-and$record.no_handoff-and$record.recovery_sha256-ceq$bundleSha-and$originalBundle.ticket.sha256-ceq$ticketSha-and$originalBundle.request.sha256-ceq$requestSha-and$originalTicket.range_count-eq5157-and$originalTicket.selected_bytes-eq11396272128) 'Original independent checkpoint, bundle and ticket pins differ.'
 $vm=HostGuard;$capacity=Capacity
 New-Item -ItemType Directory -Path $root -ErrorAction Stop|Out-Null;$created=$true
 $config=@{schema_version=1;run_id=$run;stage=$stage;task=$task;operation=$mode;binary_sha256=$exeSha;recovery=$guestRecovery;bundle=$guestBundle;bundle_sha256=$bundleSha;ticket_sha256=$ticketSha;request_sha256=$requestSha;shadow=$guestShadow}
 $json=$config|ConvertTo-Json -Depth 8 -Compress;$config64=[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($json));$text=$worker.Replace('__CONFIG__',$config64).Replace('__GUARD__',$guestGuard)
 $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors);Need ($errors.Count-eq0) 'Generated guest worker syntax differs.'
 $wrapper=Join-Path $root 'wrapper.ps1';$f=[IO.File]::Open($wrapper,'CreateNew','Write','Read');try{$b=[Text.UTF8Encoding]::new($false).GetBytes($text);$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()};$wrapperSha=(Get-FileHash -LiteralPath $wrapper -Algorithm SHA256).Hash.ToLowerInvariant()
 $dispatcherSha=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
 Save 'intent.json' @{schema_version=1;kind='exact-alpha-fast-recovery-intent';run_id=$run;operation=$mode;vm_id=$vmId.ToString('D');parent_id=$original.ToString('D');source_commit=$sourceCommit;binary_sha256=$exeSha;bundle_sha256=$bundleSha;ticket_sha256=$ticketSha;request_sha256=$requestSha;original_receipt_sha256=$receiptSha;dispatcher_sha256=$dispatcherSha;capacity=$capacity;native_checks_unchanged=$true;independent_baseline_scan=$false;automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')}
 $credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml');$session=New-PSSession -VMId $vmId -Credential $credential -ErrorAction Stop
 $prepare=[scriptblock]::Create(('param($stage,$task,$c)'+[Environment]::NewLine+'Set-StrictMode -Version Latest; $ErrorActionPreference="Stop"'+[Environment]::NewLine+$guestGuard+[Environment]::NewLine+@'
Idle $task;$routes=Routes
if(Test-Path -LiteralPath $stage){throw 'Fresh unique guest stage required.'}
$a=Get-Item -LiteralPath (Split-Path $stage -Parent) -Force;while($null-ne$a){if(-not($a-is[IO.DirectoryInfo])-or($a.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary stage ancestry required.'};$a=$a.Parent}
New-Item -ItemType Directory -Path $stage -ErrorAction Stop|Out-Null
return $routes
'@))
 $guestConfig=([string]$json)|ConvertFrom-Json;$prepareArgs=[object[]]@($stage,$task,$guestConfig)
 $ready=Invoke-Command -Session $session -ArgumentList $prepareArgs -ScriptBlock $prepare
 Save 'ready.json' @{schema_version=1;kind='exact-alpha-fast-host-preflight';guest=$ready;utc=[DateTime]::UtcNow.ToString('o')}
 Copy-Item -LiteralPath $binary -ToSession $session -Destination (Join-Path $stage 'ntfs2refs.exe') -ErrorAction Stop
 Copy-Item -LiteralPath $wrapper -ToSession $session -Destination (Join-Path $stage 'wrapper.ps1') -ErrorAction Stop
 $null=HostGuard
 Save 'dispatch.json' @{schema_version=1;kind='exact-alpha-fast-recovery-dispatch-v1';run_id=$run;operation=$mode;parent_id=$original.ToString('D');checkpoint_ids=$ids;source_commit=$sourceCommit;task_name=$task;guest_stage=$stage;wrapper_sha256=$wrapperSha;dispatcher_sha256=$dispatcherSha;configuration=@{recovery_sha256=$bundleSha;interrupted_checkpoint_receipt_sha256=$receiptSha;binary_sha256=$exeSha;original_shadow_backing_guard_required=$true;independent_full_baseline_scan=$false;native_device_and_journal_gates_unchanged=$true};expected_exit=0;completion_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')}
 $registerArgs=[object[]]@($stage,$task,$wrapperSha,$exeSha)
 Invoke-Command -Session $session -ArgumentList $registerArgs -ScriptBlock {param($stage,$task,$wrapperSha,$exeSha)
  $ErrorActionPreference='Stop';$w=Join-Path $stage 'wrapper.ps1';$exe=Join-Path $stage 'ntfs2refs.exe';if((Get-FileHash -LiteralPath $w -Algorithm SHA256).Hash.ToLowerInvariant()-cne$wrapperSha-or(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()-cne$exeSha-or@(Get-ScheduledTask|Where-Object TaskName -CEQ $task).Count){throw 'Fresh pinned SYSTEM task and executable required.'}
  Register-ScheduledTask -TaskName $task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$w+'"')) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
 }
 $null=HostGuard;$null=Capacity
 Save 'start-intent.json' @{run_id=$run;task=$task;start_will_be_issued_once=$true;automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')}
 $startArgs=[object[]]@($stage,$task,$wrapperSha)
 Invoke-Command -Session $session -ArgumentList $startArgs -ScriptBlock {param($stage,$task,$wrapperSha)
  $ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskName $task;$info=$t|Get-ScheduledTaskInfo;$w=Join-Path $stage 'wrapper.ps1';if($t.State.ToString()-cne'Ready'-or$info.LastRunTime.Year-ge2000-or@($t.Actions).Count-ne1-or$t.Principal.UserId-notin@('SYSTEM','S-1-5-18')-or$t.Principal.RunLevel.ToString()-cne'Highest'-or$t.Actions[0].Execute-cne"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"-or$t.Actions[0].Arguments-cne('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$w+'"')-or(Get-FileHash -LiteralPath $w -Algorithm SHA256).Hash.ToLowerInvariant()-cne$wrapperSha-or@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.TaskName-cne$task-and$_.State.ToString()-notin@('Ready','Disabled')}).Count){throw 'Exact sole untouched SYSTEM task required.'};Start-ScheduledTask -TaskName $task
 }
 $dispatched=$true;Save 'start.json' @{run_id=$run;task=$task;start_issued_once=$true;completion_inferred=$false;automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')}
 Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw
}catch{if($created-and-not(Test-Path -LiteralPath (Join-Path $root 'dispatch-failed.json'))){try{Save 'dispatch-failed.json' @{success=$false;error=$_.Exception.ToString();start_returned=$dispatched;automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')}}catch{}};throw}
finally{if($null-ne$session){Remove-PSSession $session -ErrorAction SilentlyContinue};foreach($f in $held){$f.Dispose()}}
