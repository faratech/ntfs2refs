# Launch the public CLI against the newly created H: hard-link fixture only.
# Root restores/boots the reviewed parent. No power, checkpoint, source-layout,
# manual binding, permission or cleanup action is performed by this controller.
[CmdletBinding()]
param(
 [Parameter(Mandatory)][guid]$ExpectedParent,
 [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds,
 [Parameter(Mandatory)][string]$FixtureManifestPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$FixtureManifestSha256,
 [Parameter(Mandatory)][string]$PublicExePath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$PublicExeSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$MainSourceSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$vmId=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$run=[guid]::NewGuid().ToString('N');$root=Join-Path $base ('hardlink-convert-'+$run)
$stage='C:\ntfs2refs\hardlink-convert-'+$run;$task='N2R-HardLinkConvert-'+$run
$session=$null;$created=$false
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function Ordinary([string]$Path,[long]$Maximum){
 $full=[IO.Path]::GetFullPath($Path);$m=Get-Item -LiteralPath $full -Force
 Need ($full-cmatch '\A[A-Za-z]:\\'-and-not$m.PSIsContainer-and$m.Length-gt0-and$m.Length-le$Maximum) 'Bounded ordinary local file required.'
 $a=$m;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse host ancestry refused.';if($a-is[IO.DirectoryInfo]){$a=$a.Parent}else{$a=$a.Directory}}
 return $m
}
function Save([string]$Name,$Value){
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14));Need ($bytes.Length-le1MB) 'Host receipt exceeds one MiB.'
 $file=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
}
$ids=@($ExpectedCheckpointIds|ForEach-Object {$_.ToString('D')})
Need ($ids.Count-gt0-and@($ids|Sort-Object -Unique).Count-eq$ids.Count-and$ExpectedParent.ToString('D')-in$ids) 'Explicit unique current checkpoint set including parent required.'
function HostGuard{
 $vm=Get-VM -Id $vmId -ErrorAction Stop;$actual=@(Get-VMSnapshot -VM $vm|ForEach-Object {$_.Id.ToString('D')})
 Need ($vm.Name-ceq'ntfs2refs-streaming-v2-20261027'-and$vm.State.ToString()-ceq'Running'-and$vm.ParentSnapshotId-eq$ExpectedParent-and$vm.MemoryStartup-eq4GB-and$vm.MemoryAssigned-eq4GB-and-not$vm.DynamicMemoryEnabled-and(Get-VMProcessor -VM $vm).Count-eq4-and@(Get-VMNetworkAdapter -VM $vm).Count-eq0-and$actual.Count-eq$ids.Count-and@($ids|Where-Object {$_-notin$actual}).Count-eq0) 'Reviewed running parent/checkpoints/4 GiB/4 CPU/no NIC required.'
}
try{
 $fixtureFile=Ordinary $FixtureManifestPath 1MB;$exeFile=Ordinary $PublicExePath 64MB
 Need ((Get-FileHash -LiteralPath $fixtureFile.FullName).Hash.ToLowerInvariant()-ceq$FixtureManifestSha256-and(Get-FileHash -LiteralPath $exeFile.FullName).Hash.ToLowerInvariant()-ceq$PublicExeSha256) 'Fixture or public executable pin differs.'
 $fixture=[IO.File]::ReadAllText($fixtureFile.FullName)|ConvertFrom-Json
 Need ($fixture.success-eq$true-and$fixture.kind-ceq'independent-hardlink-ntfs-fixture'-and$fixture.disk_number-eq6-and$fixture.partition_bytes-eq52GB-and$fixture.partition_offset-eq32MB-and$fixture.filesystem-ceq'NTFS'-and$fixture.cluster_bytes-eq4096-and$fixture.label-ceq'n2r-links-source'-and$fixture.user_file_identities-eq3-and$fixture.user_file_names-eq9-and@($fixture.groups).Count-eq3) 'Pinned fresh H: hard-link fixture required.'
 Need ([guid]$fixture.disk_guid-ne[guid]::Empty-and[guid]$fixture.partition_guid-ne[guid]::Empty-and$fixture.disk_unique_id_after-ceq$fixture.disk_unique_id_before) 'Fixture disk identities are missing or unstable.'
 Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
 $configuration=Get-LabConfiguration -WorkspaceRoot $workspace;$capacity=Get-LabCapacity -Configuration $configuration
 Need ($capacity.MaximumActualBytes-eq329374052988-and$capacity.MinimumFreeBytes-eq17179869184) 'Fixed storage epoch differs.'
 Assert-LabCapacity -Capacity $capacity -AdditionalBytes 8GB;HostGuard
 New-Item -ItemType Directory -Path $root -ErrorAction Stop|Out-Null;$created=$true
 $c=@{run_id=$run;stage=$stage;task=$task;fixture_sha256=$FixtureManifestSha256;binary_sha256=$PublicExeSha256;binary_bytes=$exeFile.Length;source_commit=$SourceCommit;main_source_sha256=$MainSourceSha256;partition_number=$fixture.partition_number}
 Save 'intent.json' @{schema_version=1;kind='public-hardlink-conversion-intent';configuration=$c;vm_id=$vmId.ToString('D');parent_id=$ExpectedParent.ToString('D');checkpoint_ids=$ids;fixture_path=$fixtureFile.FullName;binary_path=$exeFile.FullName;capacity=$capacity;forecast_bytes=8GB;manual_binding=$false;source_layout_prearranged=$false;utc=[DateTime]::UtcNow.ToString('o')}
 $body=@'
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$c=[Text.UTF8Encoding]::new($false).GetString([Convert]::FromBase64String('__CONFIG__'))|ConvertFrom-Json
$phase='preflight';$nativeExit=$null;$process=$null
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function Save([string]$Name,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));Need ($bytes.Length-le1MB) 'Wrapper receipt exceeds one MiB.';$file=[IO.File]::Open((Join-Path $c.stage $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
function Json([string]$Path,[long]$Maximum=64MB){$m=Get-Item -LiteralPath $Path -Force;Need ($Path.StartsWith('C:\',[StringComparison]::OrdinalIgnoreCase)-and-not$m.PSIsContainer-and-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$m.Length-gt0-and$m.Length-le$Maximum) 'Bounded ordinary closed C JSON required.';$a=$m.Directory;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse C JSON ancestry.';$a=$a.Parent};return ([IO.File]::ReadAllText($Path)|ConvertFrom-Json)}
function Idle{Need (@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-eq0-and@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.TaskName-cne$c.task-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-eq0) 'Another project worker or task is active.'}
function Log([string]$Path){$m=Get-Item -LiteralPath $Path -Force;Need (-not$m.PSIsContainer-and-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$m.Length-le8MB) 'Bounded native log required.';$reader=[IO.StreamReader]::new($Path);try{$chars=[char[]]::new(32768);$n=$reader.ReadBlock($chars,0,$chars.Length);return @{path=$Path;bytes=$m.Length;sha256=(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant();text=[string]::new($chars,0,$n);truncated=($reader.Peek()-ne-1)}}finally{$reader.Dispose()}}
function SameArray($Left,$Right){$a=@($Left);$b=@($Right);if($a.Count-ne$b.Count){return $false};for($i=0;$i-lt$a.Count;$i++){if($a[$i]-cne$b[$i]){return $false}};return $true}
function Fsutil([string[]]$Arguments){$old=[Console]::OutputEncoding;try{[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$lines=@(& "$env:SystemRoot\System32\fsutil.exe" @Arguments 2>&1|ForEach-Object {[string]$_});$exit=$LASTEXITCODE;Need ($exit-eq0-and($lines-join"`n").Length-le65536) 'Bounded fsutil call failed.';return ,$lines}finally{[Console]::OutputEncoding=$old}}
function VerifyFixture($Fixture,[string]$Filesystem){
 $d=Get-Disk -Number 6 -ErrorAction Stop;$p=Get-Partition -DriveLetter H -ErrorAction Stop;$v=Get-Volume -DriveLetter H -ErrorAction Stop
 Need ($d.UniqueId-ceq$Fixture.disk_unique_id_after-and[guid]$d.Guid-eq[guid]$Fixture.disk_guid-and$d.Size-eq56GB-and-not$d.IsBoot-and-not$d.IsSystem-and-not$d.IsOffline-and-not$d.IsReadOnly-and$p.DiskNumber-eq6-and$p.PartitionNumber-eq$c.partition_number-and[guid]$p.Guid-eq[guid]$Fixture.partition_guid-and$p.Offset-eq32MB-and$p.Size-eq52GB-and$v.FileSystem-ceq$Filesystem-and$v.AllocationUnitSize-eq4096-and$v.FileSystemLabel-ceq'n2r-links-source'-and(Get-Partition -DriveLetter C).DiskNumber-ne6) 'Actual H: source identity, filesystem or label differs.'
 $groups=[Collections.Generic.List[object]]::new();$seenIds=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$seenPaths=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach($group in $Fixture.groups){
  Need (@($group.names).Count-eq3-and$group.sha256-cmatch'\A[0-9a-f]{64}\z') 'Exactly three pinned names per identity required.'
  $expected=@($group.names|ForEach-Object {Need ($_.path.StartsWith('H:\',[StringComparison]::Ordinal)-and$_.path-cnotmatch'\.\.|["\r\n\x00]') 'Fixture path must stay on H:.';$_.path.Substring(2)}|Sort-Object)
  $names=[Collections.Generic.List[object]]::new();$identity=$null
  foreach($name in $group.names){
   Need ($seenPaths.Add($name.path)) 'Duplicate fixture name.'
   $entry=Get-Item -LiteralPath $name.path -Force
   Need (-not$entry.PSIsContainer-and-not($entry.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$entry.Length-eq$group.logical_length-and(Get-FileHash -LiteralPath $name.path -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$group.sha256) 'Fixture alias contents differ.'
   $idText=Fsutil @('file','queryfileid',$name.path);$matches=[regex]::Matches(($idText-join"`n"),'0x[0-9a-fA-F]+');Need ($matches.Count-eq1) 'Expected one native file ID.';$fileId=$matches[0].Value.ToLowerInvariant()
   if($null-eq$identity){$identity=$fileId}else{Need ($identity-ceq$fileId) 'Names do not resolve to one hard-linked file.'}
   if($Filesystem-ceq'NTFS'){Need ($fileId-ceq$group.file_id) 'Frozen fixture file ID changed before conversion.'}
   $linkText=Fsutil @('hardlink','list',$name.path);$links=@($linkText|ForEach-Object {$line=$_.Trim();if($line.Length){if($line.StartsWith('H:\',[StringComparison]::OrdinalIgnoreCase)){$line=$line.Substring(2)};Need ($line.StartsWith('\')) 'Unexpected hard-link list output.';$line}}|Sort-Object)
   Need ($links.Count-eq3-and@(Compare-Object -ReferenceObject $expected -DifferenceObject $links -CaseSensitive).Count-eq0) 'Exact three-name hard-link set was not preserved.'
   $names.Add(@{path=$name.path;file_id=$fileId;length=$entry.Length;sha256=$group.sha256;hardlink_list=$links;queryfileid_output=$idText;hardlink_list_output=$linkText})
  }
  Need ($seenIds.Add($identity)) 'Distinct source identities became the same file.'
  $groups.Add(@{name=$group.name;file_id=$identity;names=$names.ToArray()})
 }
 Need ($seenIds.Count-eq3-and$seenPaths.Count-eq9) 'Fixture identity/name count differs.'
 return @{filesystem=$v.FileSystem;cluster_bytes=$v.AllocationUnitSize;label=$v.FileSystemLabel;disk_guid=[string]$d.Guid;partition_guid=[string]$p.Guid;user_file_identities=$seenIds.Count;user_file_names=$seenPaths.Count;groups=$groups.ToArray()}
}
try{
 Idle
 $fixturePath=Join-Path $c.stage 'fixture.json';Need ((Get-FileHash -LiteralPath $fixturePath).Hash.ToLowerInvariant()-ceq$c.fixture_sha256) 'Staged fixture pin differs.';$fixture=Json $fixturePath 1MB
 $binary=Join-Path $c.stage 'ntfs2refs.exe';$m=Get-Item -LiteralPath $binary -Force;Need (-not$m.PSIsContainer-and-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$m.Length-eq$c.binary_bytes-and(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()-ceq$c.binary_sha256) 'Staged public executable differs.'
 Save 'wrapper-worker.json' @{pid=$PID;creation_ms=([DateTimeOffset](Get-Process -Id $PID).StartTime).ToUnixTimeMilliseconds();utc=[DateTime]::UtcNow.ToString('o')}
 Save 'fixture-before.json' (VerifyFixture $fixture 'NTFS')
 Idle;$phase='public-conversion'
 $stdin=Join-Path $c.stage 'stdin-yes.txt';[IO.File]::WriteAllBytes($stdin,[Text.Encoding]::ASCII.GetBytes("yes`r`n"));$stdout=Join-Path $c.stage 'stdout.log';$stderr=Join-Path $c.stage 'stderr.log';$argv=@('--drive','H','--partition',[string]$c.partition_number)
 Save 'native-dispatch-intent.json' @{binary=$binary;binary_sha256=$c.binary_sha256;argv=$argv;expected_exit=0;utc=[DateTime]::UtcNow.ToString('o')}
 $process=Start-Process -FilePath $binary -ArgumentList ($argv-join' ') -WorkingDirectory $c.stage -RedirectStandardInput $stdin -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden;$null=$process.Handle
 Save 'native-process.json' @{pid=$process.Id;creation_ms=([DateTimeOffset]$process.StartTime).ToUnixTimeMilliseconds();binary=$binary;binary_sha256=$c.binary_sha256;argv=$argv;expected_exit=0;process_handle_retained_before_wait=$true;utc=[DateTime]::UtcNow.ToString('o')}
 $process.WaitForExit();$process.Refresh();$nativeExit=$process.ExitCode;$out=Log $stdout;$err=Log $stderr
 Save 'native-terminal.json' @{native_exit=$nativeExit;native_exit_observed=($null-ne$nativeExit);expected_exit=0;stdout=$out;stderr=$err;utc=[DateTime]::UtcNow.ToString('o')}
 Need ($null-ne$nativeExit-and$nativeExit-eq0) ('Actual public CLI exit was '+$nativeExit)
 $phase='closed-native-conversion-evidence';Idle
 Need (-not$out.truncated) 'Completion log exceeds the bounded parser.'
 $completed=[regex]::Matches($out.text,'(?m)^Conversion completed[.] Recovery records: (C:\\ProgramData\\ntfs2refs\\runs\\[0-9a-f]{32}\\conversion)[ \t]*\r?$')
 Need ($completed.Count-eq1) 'Exactly one native completion path required.';$records=$completed[0].Groups[1].Value
 $result=Json (Join-Path $records 'result.json');$final=Json (Join-Path $records 'finalization.json');$expected=Json (Join-Path $records 'expectation.json');$handoff=Json (Join-Path $records 'handoff.json') 65536;$ticket=Json (Join-Path $records 'selected-ticket.json') 65536;$plan=Json (Join-Path $records 'selected-plan.json') 16MB;$request=Json (Join-Path $records 'request.json') 131072
 $pins=@{};foreach($name in @('result','finalization','expectation','handoff','selected-ticket','selected-plan','request')){$pins[$name]=(Get-FileHash -LiteralPath (Join-Path $records ($name+'.json'))).Hash.ToLowerInvariant()}
 # These are the default allocation-bounded result fields emitted by
 # general_conversion/allocation.rs, not the whole-image compact schema.
 Need ($result.schema_version-eq1-and$result.kind-ceq'experimental-allocation-bounded-conversion'-and$result.success-eq$true-and$result.source_admitted-eq$true-and$result.rollback_closed-eq$true-and$result.free_space_contents_compared-eq$false-and$result.general_conversion_qualified-eq$false-and$result.expected_tree_sha256-ceq$pins.expectation-and$result.ticket_sha256-ceq$pins.'selected-ticket'-and$result.plan_sha256-ceq$pins.'selected-plan') 'Native allocation conversion result or pinned expectation differs.'
 Need ($final.success-eq$true-and$null-eq$final.error-and$final.rollback_closed-eq$true-and$final.mount_paths_preserved-eq$true-and$null-eq$final.mount_paths_error-and$final.mount_paths_after.all_paths_resolve_to_bound_volume-eq$true-and(SameArray $final.mount_paths_after.paths @('H:\'))) 'Native finalization or H: mount preservation failed.'
 Need ($handoff.replay_closed-eq$true-and$handoff.whole_image_verified-eq$false-and$ticket.whole_image_verified-eq$false-and$handoff.selected_bytes-eq$ticket.selected_bytes-and$handoff.range_count-eq$ticket.range_count-and$ticket.range_count-eq@($plan.ranges).Count-and$result.selected_ranges-eq$ticket.range_count-and$result.selected_bytes-eq$ticket.selected_bytes-and$result.journal_bytes-eq$ticket.journal_length-and@($handoff.selected_sha256).Count-eq32-and@($ticket.new_selected_sha256).Count-eq32-and(SameArray $handoff.selected_sha256 $ticket.new_selected_sha256)) 'HND does not match the selected ticket/plan.'
 Need ($request.pair.source.disk_number-eq6-and[guid]$request.pair.source.identity.disk_guid-eq[guid]$fixture.disk_guid-and[guid]$request.pair.source.identity.partition_guid-eq[guid]$fixture.partition_guid-and$request.pair.source.identity.partition_bytes-eq52GB-and$request.pair.source.identity.partition_offset-eq32MB) 'Core used a different source partition.'
 $label=$final.label_restoration;Need ($label.success-eq$true-and$label.readback_matches-eq$true-and$label.flushed-eq$true-and$null-eq$label.error-and$label.after.filesystem-ceq'ReFS') 'Native label restoration was not confirmed.'
 $native=@($final.native.native.objects);$byPath=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
 foreach($object in $native){$key=[string]::Join('\',[string[]]@($object.components));Need (-not$byPath.ContainsKey($key)) 'Duplicate canonical native path.';$byPath.Add($key,$object)}
 $hashes=0;foreach($object in $expected.objects){$key=[string]::Join('\',[string[]]@($object.path));Need ($byPath.ContainsKey($key)) 'Native canonical object missing.';if(-not$object.directory){Need ($byPath[$key].logical_sha256-ceq$object.sha256) 'Native canonical file content differs.';$hashes++}}
 Need ($native.Count-eq@($expected.objects).Count) 'Native canonical object count differs.'
 $phase='hardlink-roundtrip';$roundtrip=VerifyFixture $fixture 'ReFS';Save 'fixture-after.json' $roundtrip
 Save 'wrapper-result.json' @{schema_version=1;kind='public-hardlink-conversion-observation';success=$true;run_id=$c.run_id;source_commit=$c.source_commit;main_source_sha256=$c.main_source_sha256;binary_sha256=$c.binary_sha256;fixture_sha256=$c.fixture_sha256;native_exit=$nativeExit;conversion_records=$records;native_objects=$native.Count;complete_logical_hashes=$hashes;user_file_identities=3;user_file_names=9;hardlink_sets_verified=$true;label_and_mount_verified=$true;handoff_replay_closed=$true;records_pins=$pins;general_conversion_qualified=$false;mutation_or_recovery_tested=$false;utc=[DateTime]::UtcNow.ToString('o')}
}catch{Save 'wrapper-failed.json' @{success=$false;run_id=$c.run_id;phase=$phase;native_exit=$nativeExit;native_exit_observed=($null-ne$nativeExit);error=$_.Exception.ToString();automatic_retry_recovery_restore_cleanup=$false;utc=[DateTime]::UtcNow.ToString('o')};throw}
finally{if($null-ne$process){$process.Dispose()}}
'@
 $body=$body.Replace('__CONFIG__',[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes(($c|ConvertTo-Json -Depth 6 -Compress))))
 $wrapper=Join-Path $root 'guest-wrapper.ps1';[IO.File]::WriteAllText($wrapper,$body,[Text.UTF8Encoding]::new($false));$wrapperPin=(Get-FileHash -LiteralPath $wrapper).Hash.ToLowerInvariant()
 $session=New-PSSession -VMId $vmId -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')) -ErrorAction Stop
 Invoke-Command -Session $session -ArgumentList $stage,$task -ScriptBlock {param($Stage,$Task);$ErrorActionPreference='Stop';if((Test-Path -LiteralPath $Stage)-or@(Get-ScheduledTask|Where-Object TaskName -CEQ $Task).Count-or@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-or@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count){throw 'Fresh idle guest stage required.'};$a=Get-Item -LiteralPath 'C:\ntfs2refs' -Force;while($null-ne$a){if($a.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse guest stage ancestry.'};$a=$a.Parent};New-Item -ItemType Directory -Path $Stage|Out-Null}
 Copy-Item -LiteralPath $exeFile.FullName -ToSession $session -Destination (Join-Path $stage 'ntfs2refs.exe');Copy-Item -LiteralPath $fixtureFile.FullName -ToSession $session -Destination (Join-Path $stage 'fixture.json');Copy-Item -LiteralPath $wrapper -ToSession $session -Destination (Join-Path $stage 'wrapper.ps1')
 HostGuard
 Save 'dispatch.json' @{schema_version=1;kind='public-hardlink-conversion-dispatch';run_id=$run;vm_id=$vmId.ToString('D');parent_id=$ExpectedParent.ToString('D');checkpoint_ids=$ids;guest_stage=$stage;task_name=$task;wrapper_sha256=$wrapperPin;binary_sha256=$PublicExeSha256;source_commit=$SourceCommit;main_source_sha256=$MainSourceSha256;fixture_sha256=$FixtureManifestSha256;argv=@('--drive','H','--partition',[string]$fixture.partition_number);utc=[DateTime]::UtcNow.ToString('o')}
 Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin -ScriptBlock {param($Stage,$Task,$Pin);$ErrorActionPreference='Stop';$path=Join-Path $Stage 'wrapper.ps1';if((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$Pin){throw 'Staged wrapper differs.'};Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'"')) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)) -ErrorAction Stop|Out-Null}
 HostGuard;Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration $configuration) -AdditionalBytes 8GB
 Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin -ScriptBlock {param($Stage,$Task,$Pin);$ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskName $Task;$info=Get-ScheduledTaskInfo -TaskName $Task;$path=Join-Path $Stage 'wrapper.ps1';if($t.State.ToString()-cne'Ready'-or$info.LastRunTime.Year-ge2000-or(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$Pin-or@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count){throw 'Only untouched recorded idle task may start.'};Start-ScheduledTask -TaskName $Task -ErrorAction Stop}
 Save 'start.json' @{start_issued_once=$true;completion_inferred=$false;expected_native_exit=0;utc=[DateTime]::UtcNow.ToString('o')}
 [IO.File]::ReadAllText((Join-Path $root 'dispatch.json'))
}catch{if($created-and-not(Test-Path -LiteralPath (Join-Path $root 'dispatch-failed.json'))){Save 'dispatch-failed.json' @{success=$false;run_id=$run;error=$_.Exception.ToString();automatic_retry=$false;worker_termination_inferred=$false}};throw}
finally{if($null-ne$session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
