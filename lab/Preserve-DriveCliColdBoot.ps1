# Future preservation of the successful saved49 cold-boot user readback only.
# No boot/restore/force/replay, disk setters, managed-shadow attachment or data reads.
[CmdletBinding()]param(
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$PreservationReceiptSha256,
 [Parameter(Mandatory)][string]$ColdBootReceipt,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ColdBootReceiptSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$root=Join-Path $base 'drive-cli-affirmative-20261028-b'
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$run='d33d2e04518346f8bac2ca4bbfb757b3';$engine='58877faed3f4dc12e7e9605ebf717826'
$mainPin='866fc5bbf0f95ef5a091eb211e846573197f7b9bd27c9a1848f45e8ba6951627'
$wrapperPin='cade2bdb89469ae14bcf57a7aed4f4248df2b57ca5d49c038656b61cce6840aa'
$held=[Collections.Generic.List[IO.FileStream]]::new();$session=$null;$created=$false;$phase='host-evidence';$loadedBytes=[long]0
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function True($Value){($Value-is[bool])-and$Value}
function Ordinary([string]$Path,[bool]$Directory){
 $m=Get-Item -LiteralPath $Path -Force
 Need ([bool]$m.PSIsContainer-eq$Directory-and-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Ordinary host path required.'
 $parent=if($m.PSIsContainer){$m.Parent}else{$m.Directory}
 while($null-ne$parent){Need (-not($parent.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse host ancestry refused.';$parent=$parent.Parent};$m
}
function Digest([byte[]]$Bytes){$s=[Security.Cryptography.SHA256]::Create();try{[BitConverter]::ToString($s.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}finally{$s.Dispose()}}
function Load([string]$Path,[string]$Pin=''){
 $m=Ordinary $Path $false;Need ($m.Length-gt0-and$m.Length-le4MB) 'Bounded normal host JSON required.'
 $script:loadedBytes+=$m.Length;Need ($script:loadedBytes-le16MB) 'Host JSON aggregate exceeds16MiB.'
 $f=[IO.File]::Open($m.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$held.Add($f)
 $b=[byte[]]::new([int]$m.Length);$at=0
 while($at-lt$b.Length){$n=$f.Read($b,$at,$b.Length-$at);Need ($n-gt0) 'Short host metadata read.';$at+=$n}
 Need ($f.Length-eq$b.Length) 'Host metadata length changed.';$hash=Digest $b
 if($Pin){Need ($hash-ceq$Pin) 'Host metadata SHA256 differs.'}
 $text=[Text.UTF8Encoding]::new($false,$true).GetString($b).TrimStart([char]0xfeff)
 [pscustomobject]@{path=$m.FullName;sha256=$hash;value=($text|ConvertFrom-Json)}
}
function Utc($Value){if($Value-is[DateTime]){$Value.ToUniversalTime()}else{[DateTimeOffset]::Parse([string]$Value,[Globalization.CultureInfo]::InvariantCulture).UtcDateTime}}
function Svi($Components){@($Components).Count-gt0-and[string]::Equals([string]$Components[0],'System Volume Information',[StringComparison]::OrdinalIgnoreCase)}
function Save([string]$Name,$Value){
 Need ($Name-cmatch'\A[a-z-]+\.json\z') 'Fixed preservation receipt name required.'
 $b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));Need ($b.Length-le2MB) 'Preservation receipt exceeds2MiB.'
 $f=[IO.File]::Open((Join-Path $output $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}
}
try{
 $coldPath=[IO.Path]::GetFullPath($ColdBootReceipt)
 Need ([IO.Path]::GetFileName($coldPath)-ceq'receipt.json') 'Readback receipt leaf must be receipt.json.'
 $coldDirectory=[IO.Path]::GetDirectoryName($coldPath)
 Need ([string]::Equals([IO.Path]::GetDirectoryName($coldDirectory),$root,[StringComparison]::OrdinalIgnoreCase)-and
  [IO.Path]::GetFileName($coldDirectory)-cmatch'\Acoldboot-readback-[0-9a-f]{32}\z') 'Exact owned coldboot-readback directory required.'
 $output=Join-Path $coldDirectory 'coldboot-preservation';Need (-not(Test-Path -LiteralPath $output)) 'Preservation already has state; inspect without retry.'
 $savedRecord=Load (Join-Path $root 'preserved-checkpoint.json') $PreservationReceiptSha256;$saved=$savedRecord.value
 $coldRecord=Load $coldPath $ColdBootReceiptSha256;$cold=$coldRecord.value
 $d=(Load (Join-Path $root 'dispatch.json')).value;$prior=(Load (Join-Path $root 'intent.json')).value
 Need ((True $saved.success)-and$saved.checkpoint_count-eq49-and(True $saved.all_prior48_preserved)-and$saved.state-ceq'Off'-and$saved.memory_assigned-eq0-and
  [guid]$saved.vm_id-eq$id-and$saved.run_id-ceq$run-and$saved.engine_run_id-ceq$engine-and(True $saved.native_process_exit_observed)-and
  $null-ne$saved.native_process_exit-and$saved.native_process_exit-eq0-and$saved.unchanged_user_files-eq7-and$saved.unchanged_user_bytes-eq8594391095) 'Successful actual saved49/native0 receipt required.'
 $parent=[guid]$saved.checkpoint_id;Need ($parent-ne[guid]::Empty) 'Nonempty actual49 identity required.'
 Need ([guid]$d.vm_id-eq$id-and$d.run_id-ceq$run-and$d.task_name-ceq('N2R-DriveCliAffirmative-'+$run)-and$d.expected_exit-eq0-and
  $d.binary_sha256-ceq$mainPin-and$d.wrapper_sha256-ceq$wrapperPin-and$d.guest_stage-ceq('C:\ntfs2refs\drive-cli-affirmative-'+$run)-and
  ($d.argv-join'|')-ceq'--drive|F|--partition|2'-and[guid]$saved.parent_id-eq[guid]$d.parent_id-and[guid]$saved.parent_id-eq[guid]$prior.parent_id) 'Original d33 dispatch/lineage differs.'
 $old48=@($prior.checkpoint_ids|ForEach-Object {([guid]$_).ToString('D')})
 Need ($old48.Count-eq48-and@($old48|Sort-Object -Unique).Count-eq48-and$parent.ToString('D')-notin$old48) 'Complete distinct prior48 checkpoint identities required.'
 $all49=@($old48)+@($parent.ToString('D'))
 Need ((True $cold.success)-and(True $cold.all49_preserved)-and[guid]$cold.vm_id-eq$id-and[guid]$cold.checkpoint_id-eq$parent-and
  $cold.run_id-ceq$run-and$cold.engine_run_id-ceq$engine-and$cold.preserved49_sha256-ceq$PreservationReceiptSha256-and
  $cold.completed_user_files-eq7-and$cold.completed_user_bytes-eq8594391095-and$cold.source_write_handles_requested-eq$false-and
  $cold.raw_journal_packed_opened-eq$false-and$cold.power_disk_checkpoint_actions-eq$false) 'Successful bounded saved49 cold-boot readback receipt required.'
 Need ($cold.observation_id-cmatch'\A[0-9a-f]{32}\z'-and[IO.Path]::GetFileName($coldDirectory)-ceq('coldboot-readback-'+$cold.observation_id)-and
  $cold.guest_result_path-ceq('C:\ntfs2refs\drive-cli-coldboot-'+$cold.observation_id+'\result.json')-and$cold.guest_result_sha256-cmatch'\A[0-9a-f]{64}\z') 'Pinned fresh cold-boot result route differs.'
 $guestRecord=Load (Join-Path $coldDirectory 'guest-result.json') $cold.guest_result_sha256;$report=$guestRecord.value
 Need ((True $report.success)-and$null-eq$report.error-and$report.observation_id-ceq$cold.observation_id-and$report.run_id-ceq$run-and
  $report.engine_run_id-ceq$engine-and$report.original_main_sha256-ceq$mainPin-and(True $report.original_task_terminal0)-and
  $report.completed_user_files-eq7-and$report.completed_user_bytes-eq8594391095-and@($report.files).Count-eq7-and
  $report.source_write_handles_requested-eq$false-and$report.raw_journal_packed_opened-eq$false-and$report.svi_coldboot_rehashed-eq$false) 'Pinned guest complete7-hash result required.'
 $boot=Utc $report.guest_boot_utc;$savedUtc=Utc $saved.utc;Need ($boot-gt$savedUtc) 'Guest boot must postdate actual saved49.'
 foreach($binding in @($report.binding_before,$report.binding_after)){
  Need ([guid]$binding.disk_guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'-and[guid]$binding.partition_guid-eq[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-and
   $binding.mount-ceq'F:\'-and$binding.filesystem-ceq'ReFS'-and$binding.cluster_bytes-eq4096-and$binding.label-ceq'n2r-stream-source'-and
   [string]$binding.volume-cmatch'\A\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\\z') 'Pinned cold-boot F/original partition/ReFS label differs.'
 }
 Need ([string]::Equals([string]$report.binding_before.volume,[string]$report.binding_after.volume,[StringComparison]::OrdinalIgnoreCase)) 'Pinned before/after source volume differs.'
 $earlier=(Load (Join-Path $root 'expected-old-source.json') 'e8fcd75e70facbce879abc6f89c3d280e0512e6fd5c97b6278cd107aa4e442ca').value
 Need ($earlier.expectation_sha256-ceq'149c4aae5f788d5e78b2cee0f057049caf3d5241c6556edeba9e33eedbef6bbe'-and@($earlier.files).Count-eq10-and$earlier.logical_bytes-eq8594411663) 'Earlier10-file baseline differs.'
 $users=@($earlier.files|Where-Object {-not(Svi $_.components)});$svi=@($earlier.files|Where-Object {Svi $_.components})
 Need ($users.Count-eq7-and$svi.Count-eq3) 'Exactly7 user files plus3 separately classified SVI entries required.'
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$total=[long]0
 foreach($file in $report.files){
  $parts=@($file.components);Need ($parts.Count-ge1-and$parts.Count-le16-and-not(Svi $parts)) 'SVI/invalid paths cannot enter user readback.'
  foreach($part in $parts){Need ([string]$part-ne''-and[string]$part-notin@('.','..')-and([string]$part).IndexOfAny([char[]]@('\','/',':',[char]0))-lt0) 'Ambiguous readback component.'}
  $key=$parts-join'\';$matches=@($users|Where-Object {($_.components-join'\')-ceq$key})
  Need ($seen.Add($key)-and$matches.Count-eq1-and(True $file.complete)-and(True $file.matches_earlier_user_snapshot)-and
   $file.reparse_ancestry_observed-eq$false-and$file.sha256-ceq$matches[0].sha256-and$file.bytes-eq$matches[0].bytes-and$file.bytes-ge0) 'An earlier user hash/length is missing, duplicate or different.'
  Need ([long]$file.bytes-le([long]::MaxValue-$total)) 'User byte total overflow.';$total+=[long]$file.bytes
 }
 Need ($seen.Count-eq7-and$total-eq8594391095) 'Complete7-user-file byte total differs.'
 $closed=(Load (Join-Path $root 'closed-conversion-metadata-pins.json')).value
 Need ((True $closed.success)-and$closed.run_id-ceq$run-and$closed.engine_run_id-ceq$engine-and$closed.unchanged_user_files-eq7-and$closed.unchanged_user_bytes-eq$total-and
  $cold.svi_comparison_scope-ceq'Historical earlier-vs-frozen-source conversion classification; SVI was not read or rehashed by this cold-boot observation.') 'Explicit historical SVI exclusion scope required.'
 $classifications=@($cold.filesystem_managed_svi_comparison);$closedClassifications=@($closed.filesystem_managed_svi_comparison)
 foreach($entry in $classifications){
  Need ($entry.path-cmatch'\ASystem Volume Information\\'-and$entry.classification-in@('absent_from_this_frozen_source_expected_tree','same_as_earlier_snapshot','different_by_this_run_frozen_source_capture','new_in_this_run_frozen_source')) 'Unsupported/missing historical SVI classification.'
  $match=@($closedClassifications|Where-Object {$_.path-ceq$entry.path});Need ($match.Count-eq1-and($match[0]|ConvertTo-Json -Depth 8 -Compress)-ceq($entry|ConvertTo-Json -Depth 8 -Compress)) 'Cold receipt changed the historical SVI classification.'
 }
 Need ($classifications.Count-eq$closedClassifications.Count) 'Historical SVI classification set incomplete.'
 foreach($entry in $svi){Need (@($classifications|Where-Object {$_.path-ceq($entry.components-join'\')}).Count-eq1) 'Earlier SVI entry lacks explicit classification.'}
 Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
 $config=Get-LabConfiguration -WorkspaceRoot $workspace
 function Capacity{
  $value=Get-LabCapacity -Configuration $config;Need ($value.MaximumActualBytes-eq329374052988-and$value.MinimumFreeBytes-eq17179869184) 'Fixed50GB capacity epoch differs; never reset it.'
  Assert-LabCapacity -Capacity $value -AdditionalBytes 512MB;$value
 }
 function HostState([string[]]$States){
  $v=Get-VM -Id $id -ErrorAction Stop;$snap=@(Get-VMSnapshot -VM $v -ErrorAction Stop);$ids=@($snap.Id|ForEach-Object {$_.ToString('D')})
  Need ($v.Name-ceq'ntfs2refs-streaming-v2-20261027'-and$v.State.ToString()-in$States-and$v.ParentSnapshotId-eq$parent-and
   $v.MemoryStartup-eq4GB-and-not$v.DynamicMemoryEnabled-and@(Get-VMNetworkAdapter -VM $v).Count-eq0-and$snap.Count-eq49-and
   @($all49|Where-Object {$_-notin$ids}).Count-eq0) 'Actual VM/parent49/resource/all49 snapshot state differs.';$v
 }
 $capacity=Capacity;$null=HostState @('Running');$name='streaming-v2-drive-cli-coldboot-user-readback-passed'
 Need (@(Get-VMSnapshot -VM (Get-VM -Id $id)|Where-Object Name -CEQ $name).Count-eq0) 'Future50 checkpoint name already exists.'
 $null=New-Item -ItemType Directory -Path $output -ErrorAction Stop;$created=$true;$null=Ordinary $output $true
 Save 'preservation-intent.json' @{vm_id=$id.ToString('D');run_id=$run;engine_run_id=$engine;parent_id=$parent.ToString('D');prior_checkpoint_ids=$all49;
  preserved49_receipt_sha256=$PreservationReceiptSha256;coldboot_receipt_path=$coldPath;coldboot_receipt_sha256=$ColdBootReceiptSha256;guest_result_sha256=$guestRecord.sha256;
  native_user_hashes=7;native_user_bytes=$total;svi_coldboot_rehashed=$false;capacity=$capacity;allowance_bytes=512MB;force=$false;boot_restore_replay_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')}
 $phase='guest-terminal-binding-guard'
 $session=New-PSSession -VMId $id -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')) -ErrorAction Stop
 $guard={param($DispatchJson,[long]$ExpectedBootTicks,[string]$ExpectedVolume)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$d=$DispatchJson|ConvertFrom-Json
  $task=Get-ScheduledTask -TaskName $d.task_name -ErrorAction Stop;$info=Get-ScheduledTaskInfo -TaskName $d.task_name -ErrorAction Stop
  if($task.State.ToString()-cne'Ready'-or$info.LastTaskResult-ne0-or$info.LastRunTime.Year-lt2026){throw 'Original d33 task must remain Ready0.'}
  if(@($task.Actions).Count-ne1-or$task.Actions[0].Execute-cne"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"-or$task.Actions[0].Arguments-cnotmatch'\A-NoProfile -NonInteractive -EncodedCommand ([A-Za-z0-9+/=]+)\z'){throw 'Original d33 registered action differs.'}
  $body=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Matches[1]));$sha=[Security.Cryptography.SHA256]::Create()
  try{$pin=[BitConverter]::ToString($sha.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes($body))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  if($pin-cne$d.wrapper_sha256){throw 'Original wrapper action hash differs.'}
  $processes=@(Get-CimInstance Win32_Process -ErrorAction Stop)
  foreach($identity in @(@{pid=3660;creation=[long]1793228776720;name='ntfs2refs.exe'},@{pid=4948;creation=[long]1793228774702;name='powershell.exe'})){
   foreach($p in @($processes|Where-Object ProcessId -eq $identity.pid)){if($p.Name-ceq$identity.name-and([DateTimeOffset]$p.CreationDate).ToUnixTimeMilliseconds()-eq$identity.creation){throw 'Original affirmative worker creation still exists.'}}
  }
  if(@($processes|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-or
   @(Get-ScheduledTask -ErrorAction Stop|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count){throw 'Project workers/tasks are active or unknown.'}
  $boot=(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime()
  if($boot.Ticks-ne$ExpectedBootTicks){throw 'Guest boot changed after the pinned cold-boot readback.'}
  $disk=Get-Disk -Number 1 -ErrorAction Stop;$p=Get-Partition -DriveLetter F -ErrorAction Stop;$v=$p|Get-Volume -ErrorAction Stop
  if([guid]$disk.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or$disk.Size-ne64GB-or$disk.IsOffline-or$disk.IsReadOnly-or$disk.IsBoot-or$disk.IsSystem-or
   $p.DiskNumber-ne1-or$p.PartitionNumber-ne2-or[guid]$p.Guid-ne[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-or$p.Offset-ne16MB-or$p.Size-ne52GB-or
   $v.FileSystem-cne'ReFS'-or$v.AllocationUnitSize-ne4096-or$v.FileSystemLabel-cne'n2r-stream-source'-or-not[string]::Equals([string]$v.UniqueId,$ExpectedVolume,[StringComparison]::OrdinalIgnoreCase)){throw 'Actual original F/source1 ReFS4K52GiB mount/label differs.'}
  $g=Get-Disk -Number 4 -ErrorAction Stop;$gp=Get-Partition -DriveLetter G -ErrorAction Stop;$gv=$gp|Get-Volume -ErrorAction Stop;$oldShadow=Get-Disk -Number 5 -ErrorAction Stop
  if([guid]$g.Guid-ne[guid]'e1f3b9d3-979f-4123-9fee-399640c25092'-or$g.IsOffline-or$g.IsReadOnly-or$gp.DiskNumber-ne4-or$gv.FileSystem-cne'ReFS'-or$gv.AllocationUnitSize-ne4096-or
   [guid]$oldShadow.Guid-ne[guid]'ad077674-6305-4767-a2aa-6ded3b707e36'-or-not$oldShadow.IsOffline-or-not$oldShadow.IsReadOnly){throw 'Preserved G4/shadow5 changed.'}
  # Managed shadow6 is intentionally not required after the cold boot.
  @{original_task_ready0=$true;original_worker_creations_absent=$true;all_project_workers_absent=$true;guest_boot_utc=$boot.ToString('o');source_disk=1;
   source_partition=2;source_disk_guid=[string]$disk.Guid;source_partition_guid=[string]$p.Guid;source_offset_bytes=[long]$p.Offset;source_partition_bytes=[long]$p.Size;
   filesystem=[string]$v.FileSystem;cluster_bytes=[long]$v.AllocationUnitSize;label=[string]$v.FileSystemLabel;mount='F:\';volume=[string]$v.UniqueId;
   preserved_G4_shadow5_unchanged=$true;managed_shadow_required=$false;source_journal_packed_data_opened=$false;utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress
 }
 $dispatchJson=$d|ConvertTo-Json -Depth 10 -Compress
 $terminal=Invoke-Command -Session $session -ScriptBlock $guard -ArgumentList $dispatchJson,([long]$boot.Ticks),([string]$report.binding_after.volume)|ConvertFrom-Json
 Save 'pre-shutdown-terminal.json' $terminal
 $null=HostState @('Running');$null=Capacity
 Remove-PSSession $session -ErrorAction Stop;$session=$null
 $phase='clean-stop-once';$vm=HostState @('Running')
 Save 'shutdown-intent.json' @{vm_id=$id.ToString('D');parent_id=$parent.ToString('D');force=$false;source_data_opened=$false;utc=[DateTime]::UtcNow.ToString('o')}
 Stop-VM -VM $vm -Confirm:$false -ErrorAction Stop
 $deadline=[DateTime]::UtcNow.AddSeconds(30)
 do{$off=HostState @('Running','Stopping','Off');if($off.State.ToString()-ceq'Off'-and$off.MemoryAssigned-eq0){break};if([DateTime]::UtcNow-ge$deadline){throw 'Clean OFF/RAM0 did not settle; no stop retry/force permitted.'};Start-Sleep -Milliseconds 500}while($true)
 $parentBefore=$off.ParentSnapshotId.ToString('D');Need ([guid]$parentBefore-eq$parent) 'OFF parent must remain actual49.';$null=Capacity
 $phase='checkpoint-once'
 Save 'checkpoint-create-intent.json' @{vm_id=$id.ToString('D');name=$name;parent_id=$parentBefore;prior_checkpoint_ids=$all49;creation_issued_at_most_once=$true;utc=[DateTime]::UtcNow.ToString('o')}
 $made=Checkpoint-VM -VM $off -SnapshotName $name -Passthru -ErrorAction Stop;$direct=if($null-ne$made-and[guid]$made.Id-ne[guid]::Empty){$made.Id.ToString('D')}else{$null}
 $deadline=[DateTime]::UtcNow.AddSeconds(30)
 do{
  $fresh=Get-VM -Id $id -ErrorAction Stop;$snap=@(Get-VMSnapshot -VM $fresh -ErrorAction Stop);$match=@($snap|Where-Object Name -CEQ $name);$ids=@($snap.Id|ForEach-Object {$_.ToString('D')})
  Need ($match.Count-le1) 'Duplicate checkpoint name; preserve uncertainty.'
  if($match.Count-eq1-and$snap.Count-eq50-and@($all49|Where-Object {$_-notin$ids}).Count-eq0-and$fresh.State.ToString()-ceq'Off'-and$fresh.MemoryAssigned-eq0){
   $cp=$match[0].Id.ToString('D');Need ($cp-notin$all49-and($null-eq$direct-or$cp-ceq$direct)-and[guid]$match[0].ParentSnapshotId-eq$parent-and$fresh.ParentSnapshotId-eq[guid]$cp) 'Actual50 identity/parent differs.';break
  }
  if([DateTime]::UtcNow-ge$deadline){throw 'Actual50 metadata did not settle; never repeat checkpoint creation.'};Start-Sleep -Milliseconds 500
 }while($true)
 Save 'preserved-checkpoint.json' @{success=$true;vm_id=$id.ToString('D');checkpoint_id=$cp;parent_id=$parentBefore;checkpoint_count=50;all_prior49_preserved=$true;
  state='Off';memory_assigned=0;coldboot_receipt_sha256=$ColdBootReceiptSha256;preserved49_receipt_sha256=$PreservationReceiptSha256;guest_result_sha256=$guestRecord.sha256;
  run_id=$run;engine_run_id=$engine;native_user_hashes=7;native_user_bytes=8594391095;completed_user_files=7;completed_user_bytes=8594391095;svi_coldboot_rehashed=$false;
  svi_classification_scope=$cold.svi_comparison_scope;filesystem_managed_svi_comparison=$classifications;source_journal_packed_data_opened=$false;raw_recovery_authorized=$false;
  scope='Pinned fresh7-user-hash cold-boot readback and actual original ReFS binding preserved; no post-mount raw equality, complete metadata fidelity or storage power-loss claim.';utc=[DateTime]::UtcNow.ToString('o')}
 Get-Content -LiteralPath (Join-Path $output 'preserved-checkpoint.json') -Raw
}catch{
 if($created-and-not(Test-Path -LiteralPath (Join-Path $output 'preservation-failed.json'))){Save 'preservation-failed.json' @{success=$false;phase=$phase;error=$_.Exception.ToString();automatic_retry=$false;boot_restore_force_replay_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')}}
 throw
}finally{
 if($null-ne$session){Remove-PSSession $session -ErrorAction SilentlyContinue}
 for($i=$held.Count-1;$i-ge0;$i--){$held[$i].Dispose()}
}
