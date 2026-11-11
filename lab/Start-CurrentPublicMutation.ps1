# Mounted filesystem mutation and separate post-boot read-only verification.
# Root alone owns VM lifecycle. No conversion, raw device/journal replay or
# original-file writes exist here. Each invocation starts one fresh SYSTEM task.
[CmdletBinding()]param(
 [ValidateSet('Mutate','VerifyAfterBoot')][string]$Operation='Mutate',
 [Parameter(Mandatory)][string]$ToolsetManifest,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ToolsetManifestSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit,
 [Parameter(Mandatory)][guid]$ExpectedParent,
 [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds,
 [Parameter(Mandatory)][ValidateRange(1,50000000000)][long]$ForecastAdditionalBytes,
 [string]$MutationDispatchPath='',
 [ValidatePattern('\A(?:[0-9a-f]{64})?\z')][string]$MutationDispatchSha256='',
 [ValidatePattern('\A(?:[0-9a-f]{64})?\z')][string]$PreBootResultSha256=''
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop';$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$vmId=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$converted=[guid]'afb9afa4-859e-471d-8600-2ba4abb9d2dd'
$publicCase=Join-Path $base 'public-min-scratch-0cf3676b6409471dbe237e61053bb876';$publicStage='C:\ntfs2refs\public-min-scratch-0cf3676b6409471dbe237e61053bb876'
$records='C:\ProgramData\ntfs2refs\runs\dd3b74cc743eab2b4b8c5a4f85f66f9b\conversion';$run=[guid]::NewGuid().ToString('N')
$root=Join-Path $base ('current-public-mutation-'+$Operation.ToLowerInvariant()+'-'+$run);$stage='C:\ntfs2refs\current-public-mutation-'+$Operation.ToLowerInvariant()+'-'+$run;$task='N2R-CurrentPublicMutation-'+$run
$held=[Collections.Generic.List[IO.FileStream]]::new();$session=$null;$made=$false
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function Hold([string]$Path,[string]$Sha,[long]$Maximum,[bool]$Json){
 $m=Get-Item -LiteralPath $Path -Force;Need (-not$m.PSIsContainer-and$m.Length-gt0-and$m.Length-le$Maximum) 'Bounded ordinary input required.';$a=$m;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse input refused.';if($a-is[IO.DirectoryInfo]){$a=$a.Parent}else{$a=$a.Directory}}
 $f=[IO.File]::Open($Path,'Open','Read','Read');$held.Add($f);$h=[Security.Cryptography.SHA256]::Create();try{$s=([BitConverter]::ToString($h.ComputeHash($f))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};Need ($s-ceq$Sha-and$f.Length-eq$m.Length) 'Held input pin differs.';$f.Position=0;if($Json){$r=[IO.StreamReader]::new($f,[Text.UTF8Encoding]::new($false),$true,4096,$true);try{return ($r.ReadToEnd()|ConvertFrom-Json)}finally{$r.Dispose()}};return $m
}
function Save([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 32));Need ($b.Length-le4MB) 'Bounded host metadata required.';$f=[IO.File]::Open((Join-Path $root $Name),'CreateNew','Write','Read');try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function HostGuard{$v=Get-VM -Id $vmId;$ids=@(Get-VMSnapshot -VM $v|ForEach-Object {$_.Id.ToString('D')});$expected=@($ExpectedCheckpointIds|ForEach-Object {$_.ToString('D')});Need ($ExpectedParent-eq$converted-and$v.ParentSnapshotId-eq$converted-and$v.State.ToString()-ceq'Running'-and$v.MemoryStartup-eq4GB-and$v.MemoryAssigned-eq4GB-and-not$v.DynamicMemoryEnabled-and(Get-VMProcessor -VM $v).Count-eq4-and@(Get-VMNetworkAdapter -VM $v).Count-eq0-and$ids.Count-eq$expected.Count-and@($expected|Where-Object {$_-notin$ids}).Count-eq0) 'Exact running converted checkpoint/4GiB/4CPU/noNIC required.'}
$workload=@'
[CmdletBinding()]param([Parameter(Mandatory)][string]$ConfigurationPath,[Parameter(Mandatory)][string]$ConfigurationSha256)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if((Get-FileHash -LiteralPath $ConfigurationPath).Hash.ToLowerInvariant()-cne$ConfigurationSha256){throw 'Pinned workload configuration differs.'}
$c=Get-Content -LiteralPath $ConfigurationPath -Raw -Encoding UTF8|ConvertFrom-Json
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function Hex([byte[]]$Bytes){return ([BitConverter]::ToString($Bytes)).Replace('-','').ToLowerInvariant()}
function Save([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 10));Need ($b.Length-le1MB) 'Bounded workload report required.';$f=[IO.File]::Open((Join-Path $c.stage $Name),'CreateNew','Write','Read');try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function NewData([string]$Path,[int]$MiB,[int]$Seed){
 Need ([IO.Path]::GetFullPath($Path).StartsWith($c.mutation_root+'\',[StringComparison]::OrdinalIgnoreCase)-and-not(Test-Path -LiteralPath $Path)) 'Only fresh mutation-child files may be written.'
 $f=[IO.File]::Open($Path,'CreateNew','Write','None');$h=[Security.Cryptography.SHA256]::Create();$prefix=[Security.Cryptography.SHA256]::Create();$rng=[Random]::new($Seed);$buffer=[byte[]]::new(1MB)
 try{for($n=0;$n-lt$MiB;$n++){$rng.NextBytes($buffer);$f.Write($buffer,0,$buffer.Length);$null=$h.TransformBlock($buffer,0,$buffer.Length,$null,0);if($n-lt10){$null=$prefix.TransformBlock($buffer,0,$buffer.Length,$null,0)}};$f.Flush($true);$null=$h.TransformFinalBlock([byte[]]::new(0),0,0);$null=$prefix.TransformFinalBlock([byte[]]::new(0),0,0);$expected=Hex $h.Hash;$first10=Hex $prefix.Hash}finally{$f.Dispose();$h.Dispose();$prefix.Dispose()}
 Need ((Get-Item -LiteralPath $Path).Length-eq([long]$MiB*1MB)-and(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant()-ceq$expected) 'New-file source-buffer hash differs from actual readback.'
 return @{path=$Path;bytes=([long]$MiB*1MB);sha256=$expected;first10_sha256=$first10}
}
try{
 $d=Get-Disk -Number 1;$p=Get-Partition -DriveLetter F;$v=$p|Get-Volume
 Need ($env:COMPUTERNAME-ceq'N2R-WIN11'-and[guid]$d.Guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'-and-not$d.IsOffline-and-not$d.IsReadOnly-and-not$d.IsBoot-and-not$d.IsSystem-and$p.DiskNumber-eq1-and$p.Size-eq52GB-and[guid]$p.Guid-eq[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-and$v.FileSystem-ceq'ReFS'-and$v.AllocationUnitSize-eq4096-and$v.FileSystemLabel-ceq'n2r-stream-source'-and$v.SizeRemaining-ge256MB) 'Exact mounted converted source/free space required.'
 Need ($c.mutation_root-cmatch'\AF:\\n2r-current-mutation-[0-9a-f]{32}\z'-and-not(Test-Path -LiteralPath $c.mutation_root)) 'Fresh exact mutation directory required.'
 $null=New-Item -ItemType Directory -Path $c.mutation_root
 $cycle=Join-Path $c.mutation_root 'cycle.bin';$original=NewData $cycle 50 20261102
 $f=[IO.File]::Open($cycle,'Open','ReadWrite','None');try{$f.SetLength(80MB);$f.Position=80MB-1;$f.WriteByte(165);$f.Flush($true);$f.Position=50MB;$gap=[byte[]]::new(65536);Need ($f.Read($gap,0,$gap.Length)-eq$gap.Length-and@($gap|Where-Object {$_-ne0}).Count-eq0) 'Grown valid-data gap is not zero.';$f.SetLength(10MB);$f.Flush($true)}finally{$f.Dispose()}
 $reused=Join-Path $c.mutation_root 'reusable.bin';[IO.File]::Move($cycle,$reused);Need ((Get-Item -LiteralPath $reused).Length-eq10MB-and(Get-FileHash -LiteralPath $reused).Hash.ToLowerInvariant()-ceq$original.first10_sha256) 'Truncated/renamed data differs.'
 Need ([IO.Path]::GetFullPath($reused).StartsWith($c.mutation_root+'\',[StringComparison]::OrdinalIgnoreCase)) 'Delete target escaped mutation directory.';[IO.File]::Delete($reused)
 $persistent=NewData $reused 16 20261103;$second=NewData (Join-Path $c.mutation_root 'second.bin') 16 20261104
 $transient=Join-Path $c.mutation_root 'transient.bin';$null=NewData $transient 1 20261105;[IO.File]::Delete($transient)
 $growth=Join-Path $c.mutation_root 'growth';$null=New-Item -ItemType Directory -Path $growth;$files=[Collections.Generic.List[object]]::new()
 foreach($entry in @($persistent,$second)){$files.Add(@{path=$entry.path;bytes=$entry.bytes;sha256=$entry.sha256})}
 $rng=[Random]::new(20261106);$data=[byte[]]::new(4096)
 for($n=0;$n-lt256;$n++){$rng.NextBytes($data);$path=Join-Path $growth ('entry-{0:D3}.bin'-f$n);$f=[IO.File]::Open($path,'CreateNew','Write','None');try{$f.Write($data,0,$data.Length);$f.Flush($true)}finally{$f.Dispose()};$h=[Security.Cryptography.SHA256]::Create();try{$digest=Hex ($h.ComputeHash($data))}finally{$h.Dispose()};$files.Add(@{path=$path;bytes=4096;sha256=$digest})}
 Write-VolumeCache -DriveLetter F -ErrorAction Stop
 foreach($entry in $files){Need ((Get-Item -LiteralPath $entry.path).Length-eq$entry.bytes-and(Get-FileHash -LiteralPath $entry.path).Hash.ToLowerInvariant()-ceq$entry.sha256) 'Persisted new-file readback differs.'}
 Need (-not(Test-Path -LiteralPath $cycle)-and-not(Test-Path -LiteralPath $transient)-and@(Get-ChildItem -LiteralPath $growth -File).Count-eq256) 'Delete/directory growth state differs.'
 Save 'mutation-report.json' @{schema_version=1;kind='current-public-mounted-mutation';run_id=$c.run_id;directory=$c.mutation_root;operations=@('create-50MiB','grow-80MiB','zero-gap-read','truncate-10MiB','rename','delete','recreate-same-path-16MiB','second-file-16MiB','directory-growth-256');files=$files.ToArray();growth_directory=$growth;growth_entries=256;deleted_paths=@($cycle,$transient);new_files_verified=258;only_new_test_paths_written=$true;delete_reallocate_exercised=$true;physical_cluster_reuse_proven=$false;original_payload_scanned=$false;source_disk_or_journal_raw_access=$false;utc=[DateTime]::UtcNow.ToString('o')}
 exit 0
}catch{Save 'mutation-workload-failed.json' @{success=$false;error=$_.Exception.ToString();automatic_retry_or_cleanup=$false};exit 1}
'@
$body=@'
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop';$c=$null;$leases=[Collections.Generic.List[IO.FileStream]]::new();$lastExit=$null
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function Pin([string]$Path){return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function ReadPin($Row,[bool]$Json=$true){
 $m=Get-Item -LiteralPath $Row.path -Force;Need (-not$m.PSIsContainer-and$m.Length-eq$Row.bytes-and$m.Length-le64MB) 'Bounded actual pinned metadata required.';$a=$m;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse metadata ancestry refused.';if($a-is[IO.DirectoryInfo]){$a=$a.Parent}else{$a=$a.Directory}}
 $f=[IO.File]::Open($Row.path,'Open','Read','Read');$leases.Add($f);$h=[Security.Cryptography.SHA256]::Create();try{$s=([BitConverter]::ToString($h.ComputeHash($f))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};Need ($s-ceq$Row.sha256-and$f.Length-eq$Row.bytes) 'Held metadata pin differs.';$f.Position=0;if($Json){$r=[IO.StreamReader]::new($f,[Text.UTF8Encoding]::new($false),$true,4096,$true);try{return ($r.ReadToEnd()|ConvertFrom-Json)}finally{$r.Dispose()}}
}
function Save([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 24));Need ($b.Length-le4MB) 'Bounded observation required.';$f=[IO.File]::Open((Join-Path $c.stage $Name),'CreateNew','Write','Read');try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function SourceGuard{
 $all=@(Get-Disk);$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);foreach($disk in $all){$g=[guid]::Empty;Need ([guid]::TryParse([string]$disk.Guid,[ref]$g)-and$g-ne[guid]::Empty-and$seen.Add($g.ToString('D'))) 'Unknown or duplicate live disk GUID.'}
 $d=Get-Disk -Number 1;$p=Get-Partition -DriveLetter F;$v=$p|Get-Volume
 Need ([guid]$d.Guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'-and$d.Size-eq64GB-and-not$d.IsBoot-and-not$d.IsSystem-and-not$d.IsOffline-and-not$d.IsReadOnly-and$p.DiskNumber-eq1-and$p.PartitionNumber-eq2-and[guid]$p.Guid-eq[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-and$p.Offset-eq16MB-and$p.Size-eq52GB-and$v.FileSystem-ceq'ReFS'-and$v.AllocationUnitSize-eq4096-and$v.FileSystemLabel-ceq'n2r-stream-source') 'Exact mounted converted F:ReFS4K source required.'
 return @{disk_guid=[string]$d.Guid;partition_guid=[string]$p.Guid;filesystem=$v.FileSystem;cluster_bytes=$v.AllocationUnitSize;label=$v.FileSystemLabel}
}
function Idle{Need (@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.TaskName-cne$c.task-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-eq0-and@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-eq0) 'Other project workers/tasks must be terminal.'}
function Native([string]$Role,[string]$Binary,[string]$BinaryPin,[string[]]$Argv){
 Need ((Pin $Binary)-ceq$BinaryPin) 'Actual workload/digest executable changed.';$argsText=($Argv|ForEach-Object {Need ($_-cnotmatch'["\r\n\x00]') 'Unsafe argument.';'"'+[regex]::Replace($_,'(\\+)$','$1$1')+'"'})-join' '
 $outPath=Join-Path $c.stage ($Role+'.stdout.log');$errPath=Join-Path $c.stage ($Role+'.stderr.log');$o=[IO.File]::Open($outPath,'CreateNew','Write','Read');$e=[IO.File]::Open($errPath,'CreateNew','Write','Read');$p=[Diagnostics.Process]::new()
 $info=[Diagnostics.ProcessStartInfo]::new();$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.FileName=$Binary;$info.Arguments=$argsText;$info.WorkingDirectory=$c.stage;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;$p.StartInfo=$info
 try{Save ($Role+'-dispatch.json') @{binary=$Binary;binary_sha256=$BinaryPin;argv=$Argv;expected_exit=0};$clock=[Diagnostics.Stopwatch]::StartNew();Need ($p.Start()) 'Owned process failed to start.';$null=$p.Handle;$birth=([DateTimeOffset]$p.StartTime).ToUnixTimeMilliseconds();$pidValue=$p.Id;$outDrain=$p.StandardOutput.BaseStream.CopyToAsync($o,65536);$errDrain=$p.StandardError.BaseStream.CopyToAsync($e,65536)
  Save ($Role+'-process.json') @{pid=$pidValue;creation_ms=$birth;binary=$Binary;binary_sha256=$BinaryPin;argv=$Argv;process_handle_retained_before_wait=$true};$p.WaitForExit();$clock.Stop();$exit=$p.ExitCode;$script:lastExit=$exit;$null=$outDrain.GetAwaiter().GetResult();$null=$errDrain.GetAwaiter().GetResult();$o.Flush($true);$e.Flush($true);Need ($o.Length-le1MB-and$e.Length-le1MB) 'Process logs exceeded bound.';$o.Dispose();$o=$null;$e.Dispose();$e=$null
  Save ($Role+'-terminal.json') @{pid=$pidValue;creation_ms=$birth;native_exit=$exit;native_exit_observed=$true;process_handle_retained_through_terminal=$true;wall_seconds=$clock.Elapsed.TotalSeconds;stdout_sha256=(Pin $outPath);stderr_sha256=(Pin $errPath)};Need ($exit-eq0) 'Actual owned workload/digest process did not exit0.';return [IO.File]::ReadAllText($outPath)
 }finally{if($null-ne$o){$o.Dispose()};if($null-ne$e){$e.Dispose()};$p.Dispose()}
}
function NewFiles($Report){
 Need ($Report.kind-ceq'current-public-mounted-mutation'-and$Report.only_new_test_paths_written-and$Report.directory-ceq$c.mutation_root-and$Report.new_files_verified-eq258-and@($Report.files).Count-eq258) 'Exact current mutation report required.'
 foreach($f in $Report.files){Need ([IO.Path]::GetFullPath([string]$f.path).StartsWith($c.mutation_root+'\',[StringComparison]::OrdinalIgnoreCase)-and(Get-Item -LiteralPath $f.path).Length-eq$f.bytes-and(Pin $f.path)-ceq$f.sha256) 'New persisted mutation file differs.'}
 foreach($path in $Report.deleted_paths){Need ([IO.Path]::GetFullPath([string]$path).StartsWith($c.mutation_root+'\',[StringComparison]::OrdinalIgnoreCase)-and-not(Test-Path -LiteralPath $path)) 'Deleted mutation path reappeared.'};Need (@(Get-ChildItem -LiteralPath $Report.growth_directory -File).Count-eq256) 'Directory-growth entry count differs.'
}
try{
 $cfgPath=Join-Path '__STAGE__' 'configuration.json';$cfgInfo=Get-Item -LiteralPath $cfgPath;$c=ReadPin @{path=$cfgPath;bytes=$cfgInfo.Length;sha256='__CONFIG_SHA__'}
 Need ($env:COMPUTERNAME-ceq'N2R-WIN11'-and[Security.Principal.WindowsIdentity]::GetCurrent().User.Value-ceq'S-1-5-18'-and$c.stage-ceq'__STAGE__') 'Exact owning SYSTEM guest required.'
 Idle;Save 'source-before.json' (SourceGuard);$original=ReadPin $c.result_pin;$closed=ReadPin $c.handoff_pin;$null=ReadPin $c.finalization_pin $false
 Need ($original.success-and$original.rollback_closed-and$original.source_admitted-and$closed.replay_closed) 'Actual pinned public result and closed HND required; no replay is performed.'
 $boot=([DateTimeOffset](Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToUnixTimeMilliseconds()
 if($c.operation-ceq'Mutate'){
  Need (-not(Test-Path -LiteralPath $c.mutation_root)) 'Mutation root already exists.'
  $workPath=Join-Path $c.stage 'mutation-workload.ps1';$null=ReadPin @{path=$workPath;bytes=$c.workload_bytes;sha256=$c.workload_sha256} $false
  $ps="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe";$psPin=Pin $ps
  $null=Native 'workload' $ps $psPin @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$workPath,'-ConfigurationPath',$cfgPath,'-ConfigurationSha256','__CONFIG_SHA__')
  $reportPath=Join-Path $c.stage 'mutation-report.json';$info=Get-Item -LiteralPath $reportPath;$reportPin=Pin $reportPath;$report=ReadPin @{path=$reportPath;bytes=$info.Length;sha256=$reportPin}
  Need ($report.kind-ceq'current-public-mounted-mutation'-and$report.run_id-ceq$c.run_id-and$report.directory-ceq$c.mutation_root-and$report.only_new_test_paths_written-and$report.new_files_verified-eq258-and@($report.files).Count-eq258-and$report.growth_entries-eq256) 'Actual workload report incomplete.'
  Idle;Save 'source-after.json' (SourceGuard)
  Save 'result.json' @{schema_version=1;kind='current-public-mutation-before-boot';success=$true;run_id=$c.run_id;operation='Mutate';native_workload_exit=0;native_workload_kind='owned-WindowsPowerShell-ordinary-filesystem-workload';native_process_sha256=(Pin (Join-Path $c.stage 'workload-process.json'));native_terminal_sha256=(Pin (Join-Path $c.stage 'workload-terminal.json'));mutation_report=$reportPath;mutation_report_sha256=$reportPin;mutation_root=$c.mutation_root;new_files_verified=258;directory_entries=256;delete_reallocate_exercised=$true;physical_cluster_reuse_proven=$false;original_streams_rehashed=0;original_payload_writes=$false;boot_unix_ms=$boot;configuration_sha256='__CONFIG_SHA__';reboot_performed=$false;raw_source_or_journal_opened=$false;utc=[DateTime]::UtcNow.ToString('o')}
 }else{
  Need ($c.operation-ceq'VerifyAfterBoot') 'Explicit mutation or post-boot verification operation required.'
  $priorTask=Get-ScheduledTask -TaskName $c.prior.task;$priorInfo=$priorTask|Get-ScheduledTaskInfo;Need ($priorTask.State.ToString()-ceq'Ready'-and$priorInfo.LastTaskResult-eq0) 'Original pre-boot mutation task must remain terminal0.'
  $priorPath=Join-Path $c.prior.stage 'result.json';$priorInfoFile=Get-Item -LiteralPath $priorPath;$prior=ReadPin @{path=$priorPath;bytes=$priorInfoFile.Length;sha256=$c.prior.result_sha256}
  Need ($prior.kind-ceq'current-public-mutation-before-boot'-and$prior.success-and$prior.native_workload_exit-eq0-and$prior.configuration_sha256-ceq$c.prior.configuration_sha256-and$prior.mutation_root-ceq$c.mutation_root-and$boot-gt$prior.boot_unix_ms) 'Pinned successful mutation and a genuine later cold boot required.'
  $termPath=Join-Path $c.prior.stage 'workload-terminal.json';$term=ReadPin @{path=$termPath;bytes=(Get-Item -LiteralPath $termPath).Length;sha256=$prior.native_terminal_sha256};$procPath=Join-Path $c.prior.stage 'workload-process.json';$proc=ReadPin @{path=$procPath;bytes=(Get-Item -LiteralPath $procPath).Length;sha256=$prior.native_process_sha256}
  Need ($term.native_exit_observed-and$term.native_exit-eq0-and$term.process_handle_retained_through_terminal-and$term.pid-eq$proc.pid-and$term.creation_ms-eq$proc.creation_ms-and$proc.process_handle_retained_before_wait) 'Actual pre-boot owned workload0 evidence required.'
  Need (@(Get-CimInstance Win32_Process -Filter ('ProcessId='+$proc.pid)|Where-Object {([DateTimeOffset]$_.CreationDate).ToUnixTimeMilliseconds()-eq$proc.creation_ms}).Count-eq0) 'Original mutation worker still live.'
  $reportInfo=Get-Item -LiteralPath $prior.mutation_report;$report=ReadPin @{path=$prior.mutation_report;bytes=$reportInfo.Length;sha256=$prior.mutation_report_sha256};NewFiles $report
  $expected=ReadPin $c.baseline_pin;Need (@($expected.objects).Count-eq1084) 'Complete original1084-object baseline required.'
  $files=@($expected.objects|Where-Object {-not$_.directory});Need ($files.Count-eq811) 'Exactly811 original unnamed stream baselines required.';foreach($file in $files){$named=$file.PSObject.Properties['named_streams'];Need ($null-eq$named-or@($named.Value).Count-eq0) 'This independently pinned fixture has no named streams.'}
  $paths=[Collections.Generic.List[string]]::new();foreach($o in $expected.objects){foreach($part in $o.path){Need ($part-is[string]-and$part.Length-gt0-and$part-notin@('.','..')-and$part-cnotmatch'[\\/"\x00-\x1f]') 'Unsafe independent baseline path.'};$path='F:\'+($o.path-join'\');$m=Get-Item -LiteralPath $path -Force;Need (-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$m.PSIsContainer-eq$o.directory) 'Original namespace object missing/type changed.';if(-not$o.directory){Need ($m.Length-eq$o.length-and$o.sha256-cmatch'\A[0-9a-f]{32}\z') 'Original stream length or independentXXH3-128 hash missing.';$paths.Add($path)}}
  $tool=Join-Path $c.stage 'lab-content-digest.exe';$next=0;$matched=0;$batches=0
  while($next-lt$paths.Count){$batch=[Collections.Generic.List[string]]::new();$characters=$tool.Length+20;while($next-lt$paths.Count-and$batch.Count-lt64){$cost=$paths[$next].Length+3;if($characters+$cost-gt20000){break};$batch.Add($paths[$next]);$characters+=$cost;$next++};Need ($batch.Count-gt0) 'Digest path exceeds bounded command line.';$cli=@('--backup-read')+$batch.ToArray();$text=Native ('digest-'+$batches) $tool $c.digest_sha256 $cli;$values=@($text|ConvertFrom-Json|ForEach-Object {$_});Need ($values.Count-eq$batch.Count) 'Complete ordered digest batch required.';for($n=0;$n-lt$values.Count;$n++){Need ($values[$n]-is[string]-and$values[$n]-ceq$files[$matched].sha256) 'Independent original logical stream hash differs.';$matched++};$batches++}
  Need ($matched-eq811) 'One complete811-stream independent verification required.';Idle;Save 'source-after.json' (SourceGuard)
  Save 'result.json' @{schema_version=1;kind='current-public-mutation-after-cold-boot';success=$true;original_objects_verified=1084;independent_original_streams_verified=$matched;original_digest_algorithm='xxh3-128';mutation_files_verified=258;directory_entries_verified=256;mutation_report_sha256=$prior.mutation_report_sha256;pre_boot_result_sha256=$c.prior.result_sha256;prior_boot_unix_ms=$prior.boot_unix_ms;current_boot_unix_ms=$boot;digest_batches=$batches;original_payload_writes=$false;new_mutation_writes=$false;raw_source_or_journal_opened=$false;recovery_replayed=$false;stable_release=$false;utc=[DateTime]::UtcNow.ToString('o')}
 }
}catch{if($null-ne$c){Save 'failed.json' @{success=$false;error=$_.Exception.ToString();last_actual_native_exit=$lastExit;automatic_retry_or_cleanup=$false;worker_death_inferred=$false}};exit 1}
finally{foreach($f in $leases){$f.Dispose()}}
'@
try{
 Need ($SourceCommit-ceq'4d8ca993cf660ea7430b9cc8b229553946add82b'-and$ToolsetManifestSha256-ceq'77edb210f6236d3e22ec18a2f6cccd043ea0f784ec9a2041afec7be0aba3b396'-and$ExpectedCheckpointIds.Count-gt0-and$ExpectedCheckpointIds.Count-le50-and@($ExpectedCheckpointIds|Sort-Object -Unique).Count-eq$ExpectedCheckpointIds.Count) 'Exact clean4d8 runtime and checkpoint set required.'
 $manifest=Hold $ToolsetManifest $ToolsetManifestSha256 1MB $true;Need ($manifest.schema_version-eq2-and$manifest.source_commit-ceq$SourceCommit) 'Actual sealed runtime provenance differs.'
 $digestRows=@($manifest.tools|Where-Object name -CEQ 'lab-content-digest.exe');Need ($digestRows.Count-eq1) 'One independent content digest tool required.';$digest=$digestRows[0];$digestFile=Hold $digest.path $digest.sha256 64MB $false;Need ($digestFile.Length-eq$digest.bytes) 'Digest tool size differs.'
 $archivePath=Join-Path $publicCase 'closed\archive-manifest.json';$archive=Hold $archivePath '03097395779ac04fb2cbf4a79f5e52162f279f574d1f9fad4eb9cf919bf75311' 1MB $true
 Need ($archive.native_exit-eq0-and$archive.scheduled_task_result-eq0-and$archive.source_commit-ceq$SourceCommit-and$archive.run_id-ceq'0cf3676b6409471dbe237e61053bb876'-and-not$archive.data_plane_copied) 'Actual successful closed current public conversion required.'
 function Row([string]$Path){$r=@($archive.files|Where-Object source -CEQ $Path);Need ($r.Count-eq1-and$r[0].bytes-gt0-and$r[0].bytes-le64MB-and$r[0].sha256-cmatch'\A[0-9a-f]{64}\z') 'One bounded actual closed input pin required.';return @{path=$Path;bytes=$r[0].bytes;sha256=$r[0].sha256}}
 if($Operation-ceq'Mutate'){
  Need (-not$MutationDispatchPath-and-not$MutationDispatchSha256-and-not$PreBootResultSha256) 'Mutation cannot inherit a prior run.'
  $c=@{operation=$Operation;stage=$stage;task=$task;run_id=$run;source_commit=$SourceCommit;mutation_root=('F:\n2r-current-mutation-'+$run);result_pin=(Row ($records+'\result.json'));handoff_pin=(Row ($records+'\handoff.json'));finalization_pin=(Row ($records+'\finalization.json'));baseline_pin=(Row ($publicStage+'\lab-full-content-baseline.json'));digest_sha256=$digest.sha256;prior=$null}
 }else{
  Need ($MutationDispatchPath.StartsWith($base+'\current-public-mutation-mutate-',[StringComparison]::OrdinalIgnoreCase)-and$MutationDispatchSha256-cmatch'\A[0-9a-f]{64}\z'-and$PreBootResultSha256-cmatch'\A[0-9a-f]{64}\z') 'Post-boot verification requires the actual pinned mutation dispatch and closed pre-boot result.'
  $prior=Hold $MutationDispatchPath $MutationDispatchSha256 1MB $true
  Need ($prior.schema_version-eq1-and$prior.kind-ceq'current-public-mutation-dispatch'-and$prior.operation-ceq'Mutate'-and$prior.source_commit-ceq$SourceCommit-and[guid]$prior.parent_id-eq$converted-and$prior.configuration.stage-ceq$prior.guest_stage-and$prior.guest_stage-cmatch'\AC:\\ntfs2refs\\current-public-mutation-mutate-[0-9a-f]{32}\z') 'Actual successful-mutation routing provenance required.'
  $c=$prior.configuration;$oldStage=$c.stage;$oldTask=$c.task;$c.operation=$Operation;$c.stage=$stage;$c.task=$task;$c.prior=@{stage=$oldStage;task=$oldTask;configuration_sha256=$prior.configuration_sha256;result_sha256=$PreBootResultSha256}
 }
 Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force;$configuration=Get-LabConfiguration -WorkspaceRoot $workspace;$capacity=Get-LabCapacity -Configuration $configuration;Need ($capacity.MaximumActualBytes-eq329374052988-and$capacity.MinimumFreeBytes-eq17179869184) 'Fixed capacity epoch required.';Assert-LabCapacity -Capacity $capacity -AdditionalBytes $ForecastAdditionalBytes;HostGuard
 $null=New-Item -ItemType Directory -Path $root;$made=$true
 $workBytes=[Text.UTF8Encoding]::new($false).GetBytes($workload);$hash=[Security.Cryptography.SHA256]::Create();try{$workSha=([BitConverter]::ToString($hash.ComputeHash($workBytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
 if($Operation-ceq'Mutate'){$c.workload_bytes=$workBytes.Length;$c.workload_sha256=$workSha}
 Save 'configuration.json' $c;$configPath=Join-Path $root 'configuration.json';$configSha=(Get-FileHash -LiteralPath $configPath).Hash.ToLowerInvariant()
 $guest=$body.Replace('__STAGE__',$stage).Replace('__CONFIG_SHA__',$configSha)
 foreach($text in @($guest,$workload)){$t=$null;$e=$null;$null=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$t,[ref]$e);Need ($e.Count-eq0) 'Generated wrapper/workload syntax differs.'}
 $wrapperPath=Join-Path $root 'guest-wrapper.ps1';[IO.File]::WriteAllText($wrapperPath,$guest,[Text.UTF8Encoding]::new($false));$wrapperSha=(Get-FileHash -LiteralPath $wrapperPath).Hash.ToLowerInvariant()
 $workPath=Join-Path $root 'mutation-workload.ps1';if($Operation-ceq'Mutate'){[IO.File]::WriteAllBytes($workPath,$workBytes)}
 $session=New-PSSession -VMId $vmId -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml'))
 Invoke-Command -Session $session -ArgumentList $stage,$task -ScriptBlock {param($Stage,$Task)
  $ErrorActionPreference='Stop';if($env:COMPUTERNAME-cne'N2R-WIN11'-or(Test-Path -LiteralPath $Stage)-or@(Get-ScheduledTask|Where-Object {$_.TaskName-ceq$Task-or($_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled'))}).Count-or@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count){throw 'Fresh idle owning guest required.'};$a=Get-Item -LiteralPath 'C:\ntfs2refs';while($null-ne$a){if($a.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse stage ancestry refused.'};$a=$a.Parent};$null=New-Item -ItemType Directory -Path $Stage
 }
 Copy-Item -LiteralPath $digest.path -ToSession $session -Destination (Join-Path $stage 'lab-content-digest.exe');Copy-Item -LiteralPath $configPath -ToSession $session -Destination (Join-Path $stage 'configuration.json');Copy-Item -LiteralPath $wrapperPath -ToSession $session -Destination (Join-Path $stage 'wrapper.ps1');if($Operation-ceq'Mutate'){Copy-Item -LiteralPath $workPath -ToSession $session -Destination (Join-Path $stage 'mutation-workload.ps1')}
 $bootstrap='$ErrorActionPreference="Stop";$f=[IO.File]::Open("'+(Join-Path $stage 'wrapper.ps1')+'","Open","Read","Read");try{$h=[Security.Cryptography.SHA256]::Create();try{$s=([BitConverter]::ToString($h.ComputeHash($f))).Replace("-","").ToLowerInvariant()}finally{$h.Dispose()};if($s-cne"'+$wrapperSha+'"){throw "Pinned wrapper differs"};$f.Position=0;$r=[IO.StreamReader]::new($f,[Text.UTF8Encoding]::new($false),$true,4096,$true);try{$text=$r.ReadToEnd()}finally{$r.Dispose()};& ([scriptblock]::Create($text))}finally{$f.Dispose()}'
 $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap));HostGuard
 Save 'dispatch.json' @{schema_version=1;kind='current-public-mutation-dispatch';operation=$Operation;run_id=$run;source_commit=$SourceCommit;parent_id=$ExpectedParent;checkpoint_ids=$ExpectedCheckpointIds;task_name=$task;guest_stage=$stage;wrapper_sha256=$wrapperSha;configuration_sha256=$configSha;configuration=$c;expected_native_exit=0;root_owns_reboot=$true;raw_source_or_journal_access=$false;completion_inferred=$false}
 Invoke-Command -Session $session -ArgumentList $task,$arguments,$stage,$wrapperSha -ScriptBlock {param($Task,$Arguments,$Stage,$WrapperSha)
  $ErrorActionPreference='Stop';if((Get-FileHash -LiteralPath (Join-Path $Stage 'wrapper.ps1')).Hash.ToLowerInvariant()-cne$WrapperSha-or@(Get-ScheduledTask|Where-Object TaskName -CEQ $Task).Count){throw 'Fresh pinned SYSTEM task required.'};Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $Arguments) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)) -ErrorAction Stop|Out-Null
 }
 HostGuard;Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration $configuration) -AdditionalBytes $ForecastAdditionalBytes
 Invoke-Command -Session $session -ArgumentList $task,$arguments -ScriptBlock {param($Task,$Arguments)
  $ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskName $Task;$i=$t|Get-ScheduledTaskInfo;if($t.State.ToString()-cne'Ready'-or$i.LastRunTime.Year-ge2000-or@($t.Actions).Count-ne1-or$t.Actions[0].Execute-cne"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"-or$t.Actions[0].Arguments-cne$Arguments-or$t.Principal.UserId-notin@('SYSTEM','S-1-5-18')-or$t.Principal.RunLevel.ToString()-cne'Highest'-or@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-or@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count){throw 'Only exact untouched never-run SYSTEM task may start once.'};Start-ScheduledTask -TaskName $Task -ErrorAction Stop
 }
 Save 'start.json' @{start_issued_once=$true;operation=$Operation;task_name=$task;guest_stage=$stage;root_owns_reboot=$true;completion_inferred=$false};Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw
}catch{if($made){Save 'dispatch-failed.json' @{success=$false;error=$_.Exception.ToString();automatic_retry_or_cleanup=$false;worker_death_inferred=$false}};throw}
finally{if($null-ne$session){Remove-PSSession $session -ErrorAction SilentlyContinue};foreach($f in $held){$f.Dispose()}}
