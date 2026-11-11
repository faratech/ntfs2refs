# Public preactivation cancellation only; no replay, restore or forced disk state.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
$workspace='D:\code\ntfs2refs';$alpha=Join-Path $workspace '.lab\hyperv\shadow-alpha-20261026'
$caseRoot=Join-Path $alpha 'fault-cases\fd23326c56424b7b94cc4a92658ccb19'
$caseId='fd23326c56424b7b94cc4a92658ccb19'
function Assert-CancelDispatch($Value){
 $inputRoot='C:\ntfs2refs\alpha\fault-inputs\fd23326c56424b7b94cc4a92658ccb19'
 $output='C:\ntfs2refs\alpha\fault-runs\fd23326c56424b7b94cc4a92658ccb19'
 if($Value.schema_version-ne1-or$Value.case-cne'Cancel'-or$Value.run_id-cne'fd23326c56424b7b94cc4a92658ccb19'-or
  [guid]$Value.vm_id-ne[guid]'0d9bfa66-c66c-4ead-86b7-e72cb5f7e040'-or[guid]$Value.checkpoint_id-ne[guid]'7e5582a7-6b15-4531-b77f-9f19cb9e5d47'-or
  $Value.task_name-cne'N2R-AlphaFault-Cancel-fd23326c56424b7b94cc4a92658ccb19'-or$Value.guest_output-cne$output-or
  $Value.guest_input_root-cne$inputRoot-or$Value.guest_input-cne($inputRoot+'\request.json')-or$Value.binary-cne($inputRoot+'\lab-convert-admitted-tree.exe')-or
  $Value.binary_sha256-cne'129ec4cfe6d70812291a343594be1e843f92cc59e3e7bca51c7b8bbb536ed822'-or
  $Value.expected_exit_code-ne87-or$Value.entrypoint-cne'lab-controlled-interruption'-or$Value.request_sha256-cnotmatch'\A[0-9a-f]{64}\z'-or
  $Value.engine_commit-cne'96720eff89c7e808983c8d5c9800d475fe62515c'-or-not$Value.dispatch_recorded_before_start-or$Value.recovery_authorized-or$Value.shadow_detach_authorized){throw 'Exact recorded alpha cancellation dispatch differs.'}
 $expected='--request "'+$Value.guest_input+'" --request-sha256 '+$Value.request_sha256+' --output "'+$output+'" --interrupt-after-source-freeze'
 if($Value.arguments-cne$expected){throw 'Recorded freeze producer arguments differ.'}
}
function Assert-CancelFixture($Value){
 $expected=@{'F:\source0.bin'=65536L;'F:\archive\doc1.bin'=131072L;'F:\archive\nested\doc2.bin'=65536L;
  'F:\notes\doc3.bin'=262144L;'F:\extra.bin'=8388608L;'F:\notes\post-label.bin'=20480L;'F:\natural-large.bin'=134217728L}
 if($Value.kind-cne'native-shadow-alpha-fixture'-or$Value.source_extent_moves-ne0-or@($Value.files).Count-ne7){throw 'Exact seven-file alpha fixture required.'}
 $seen=@{};foreach($row in $Value.files){
  if(-not$expected.ContainsKey([string]$row.path)-or$seen.ContainsKey([string]$row.path)-or
   @($expected.Keys)-cnotcontains[string]$row.path-or
   [long]$row.bytes-ne$expected[$row.path]-or$row.sha256-cnotmatch'\A[0-9a-f]{64}\z'){throw 'Fixture path, length or hash pin differs.'};$seen[$row.path]=$true
 }
 $source=@($Value.partitions|Where-Object {$_.disk_number-eq1})
 if($source.Count-ne1-or$source[0].partition_number-ne2-or$source[0].drive_letter-cne'F'-or$source[0].filesystem-cne'NTFS'-or
  $source[0].offset-ne16MB-or$source[0].bytes-ne52GB-or[guid]$source[0].guid-eq[guid]::Empty){throw 'Fixture source partition enrollment differs.'}
}
function Read-BoundedJson([string]$Path){
 $item=Get-Item -LiteralPath $Path -Force
 if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-gt16MB){throw 'Bounded ordinary controller JSON required.'}
 $parent=$item.Directory;while($parent){if($parent.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Controller evidence has reparse ancestry.'};$parent=$parent.Parent}
 return (Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json)
}
$dispatch=Read-BoundedJson (Join-Path $caseRoot 'dispatch.json');Assert-CancelDispatch $dispatch
$fixture=Read-BoundedJson (Join-Path $alpha 'guest-fixture.json');Assert-CancelFixture $fixture
$manifest=Read-BoundedJson (Join-Path $alpha 'manifest.json')
$vmId=[guid]'0d9bfa66-c66c-4ead-86b7-e72cb5f7e040';$vm=Get-VM -Id $vmId
function Assert-CancelOwner {
 $owned=Get-VM -Id $vmId
 if($owned.Name-cne'ntfs2refs-shadow-alpha-20261026'-or-not$owned.Path.StartsWith($alpha+'\',[StringComparison]::OrdinalIgnoreCase)-or
  $owned.State.ToString()-cne'Running'-or[guid]$owned.ParentSnapshotId-ne[guid]'7e5582a7-6b15-4531-b77f-9f19cb9e5d47'-or
  [guid]$manifest.vm_id-ne$vmId-or$manifest.root-cne$alpha-or@($manifest.disks).Count-ne4-or
  @(Get-VMNetworkAdapter -VM $owned).Count-ne0-or$owned.AutomaticCheckpointsEnabled){throw 'Owned alpha cancellation VM/branch differs.'}
 $drives=@(Get-VMHardDiskDrive -VM $owned);if($drives.Count-ne4){throw 'Alpha backing count differs.'}
 foreach($spec in $manifest.disks){
  $drive=@($drives|Where-Object {$_.ControllerType.ToString()-ceq$spec.controller-and$_.ControllerNumber-eq$spec.controller_number-and$_.ControllerLocation-eq$spec.controller_location})
  if($drive.Count-ne1){throw 'Alpha backing route differs.'};$path=[string]$drive[0].Path;$seen=@{}
  while($true){
   if(-not$path.StartsWith($alpha+'\',[StringComparison]::OrdinalIgnoreCase)-or$seen.ContainsKey($path)-or$seen.Count-ge16){throw 'Alpha backing chain escapes ownership or cycles.'}
   $seen[$path]=$true;$item=Get-Item -LiteralPath $path -Force;if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary alpha backing required.'}
   $backing=Get-VHD -Path $path;if($backing.Size-ne$spec.virtual_bytes){throw 'Alpha backing geometry differs.'}
   if([string]::IsNullOrEmpty([string]$backing.ParentPath)){break};$path=[string]$backing.ParentPath
  }
  if(-not[string]::Equals($path,[string]$spec.path,[StringComparison]::OrdinalIgnoreCase)-or[guid]$backing.DiskIdentifier-ne[guid]$spec.vhd_id){throw 'Alpha backing root identity differs.'}
 }
}
Assert-CancelOwner
if($vm.Name-cne'ntfs2refs-shadow-alpha-20261026'-or$vm.State.ToString()-cne'Running'-or
 [guid]$vm.ParentSnapshotId-ne[guid]'7e5582a7-6b15-4531-b77f-9f19cb9e5d47'-or[guid]$dispatch.vm_id-ne$vmId-or$dispatch.case-cne'Cancel'-or$dispatch.expected_exit_code-ne87){throw 'Exact alpha cancel branch required.'}
if(Test-Path -LiteralPath (Join-Path $caseRoot 'cancel-controller-intent.json')){throw 'Cancellation controller was already dispatched; inspect existing tasks.'}
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$session=New-PSSession -VMId $vmId -Credential $credential
function Save([string]$Name,$Value){
 $path=Join-Path $caseRoot $Name;$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 24))
 if($bytes.Length-gt16MB){throw 'Controller record exceeds bound.'}
 $file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
}
function Export-CancelEvidence([string]$GuestRoot,[string]$Prefix){
 $destination=Join-Path $caseRoot ($Prefix+'-evidence');if(Test-Path -LiteralPath $destination){throw 'Fresh evidence export required.'}
 $rows=@(Invoke-Command -Session $session -ArgumentList $GuestRoot -ScriptBlock {
  param($Root);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  $pending=[Collections.Generic.Stack[string]]::new();$pending.Push($Root);$rows=@();$total=0L;$directories=0
  while($pending.Count){$path=$pending.Pop();$item=Get-Item -LiteralPath $path -Force
   if(-not$item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or++$directories-gt64){throw 'Bounded ordinary evidence tree required.'}
   foreach($file in Get-ChildItem -LiteralPath $path -Force){
    if($file.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Evidence reparse point refused.'}
    if($file.PSIsContainer){if($file.FullName.Substring($Root.Length).Split('\').Count-gt8){throw 'Evidence depth exceeded.'};$pending.Push($file.FullName);continue}
    if($file.Extension-cne'.json'){continue};$total+=$file.Length
    if($file.Length-gt16MB-or$total-gt64MB-or$rows.Count-ge256){throw 'Evidence JSON budget exceeded.'}
    $rows+=[pscustomobject]@{path=$file.FullName;relative=$file.FullName.Substring($Root.Length).TrimStart('\');bytes=[long]$file.Length;sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
   }
  };$rows
 })
 $null=[IO.Directory]::CreateDirectory($destination)
 foreach($row in $rows){
  if([IO.Path]::IsPathRooted($row.relative)-or$row.relative.Contains('..')){throw 'Evidence relative path differs.'}
  $local=Join-Path $destination $row.relative;$null=[IO.Directory]::CreateDirectory((Split-Path $local -Parent))
  Copy-Item -LiteralPath $row.path -Destination $local -FromSession $session
  $null=Read-BoundedJson $local
  if((Get-Item -LiteralPath $local).Length-ne$row.bytes-or(Get-FileHash -LiteralPath $local -Algorithm SHA256).Hash.ToLowerInvariant()-cne$row.sha256){throw 'Guest/export evidence hash differs.'}
 }
 Save ($Prefix+'-export-pins.json') @{guest_root=$GuestRoot;files=$rows;journal_copied=$false;captured_utc=[DateTime]::UtcNow.ToString('o')}
 return $destination
}
try{
 $pins=Invoke-Command -Session $session -ArgumentList ($dispatch|ConvertTo-Json -Compress),($fixture|ConvertTo-Json -Depth 12 -Compress) -ScriptBlock {
  param($Text,$FixtureText);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$d=$Text|ConvertFrom-Json;$fixture=$FixtureText|ConvertFrom-Json
  if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'){throw 'Alpha guest identity differs.'}
  $scheduled=Get-ScheduledTask -TaskName $d.task_name;$info=Get-ScheduledTaskInfo -TaskName $d.task_name
  $actions=@($scheduled.Actions)
  if($actions.Count-ne1-or$actions[0].Execute-cne$d.binary-or$actions[0].Arguments-cne$d.arguments-or
   $scheduled.Principal.UserId-notin@('SYSTEM','S-1-5-18')-or$scheduled.Principal.RunLevel.ToString()-cne'Highest'-or
   $info.LastRunTime.Year-lt2000-or$scheduled.State.ToString()-in@('Running','Queued')-or$info.LastTaskResult-ne87-or
   @(Get-CimInstance Win32_Process -Filter "Name='lab-convert-admitted-tree.exe'").Count){throw 'Controlled freeze producer is not terminal87.'}
  if((Get-FileHash -LiteralPath $d.binary -Algorithm SHA256).Hash.ToLowerInvariant()-cne$d.binary_sha256-or
   (Get-FileHash -LiteralPath $d.guest_input -Algorithm SHA256).Hash.ToLowerInvariant()-cne$d.request_sha256){throw 'Frozen producer executable/input changed.'}
  $source=Get-Disk -Number 1;if(-not$source.IsOffline-or-not$source.IsReadOnly-or$source.IsBoot-or$source.IsSystem){throw 'Frozen NTFS source state differs.'}
  foreach($name in @('request.json','ticket.json','apply.json','finalization.json','result.json','prepare.json','journal-location.json','handoff.json')){
   if(Test-Path -LiteralPath (Join-Path $d.guest_output $name)){throw 'Unexpected post-freeze/activation artifact blocks this cancellation case.'}
  }
  $rows=@();$documents=@{}
  foreach($name in @('conversion-intent.json','qualification\source-frozen.json','qualification\source-mount-paths.json')){
   $path=Join-Path $d.guest_output $name;$item=Get-Item -LiteralPath $path -Force
   if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-gt128KB){throw 'Ordinary bounded pinned cancel input required.'}
   $rows+=[pscustomobject]@{name=$name;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
   $documents[$name]=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
  }
  $frozen=$documents['qualification\source-frozen.json'];$intent=$documents['conversion-intent.json'];$mounts=$documents['qualification\source-mount-paths.json']
  $binding=$frozen.binding;$identity=$binding.identity;$part=@($fixture.partitions|Where-Object {$_.disk_number-eq1})
  $actualPartition=Get-Partition -DiskNumber 1 -PartitionNumber 2
  if($frozen.schema_version-ne1-or$frozen.kind-cne'observed-frozen-source-identity'-or$frozen.state.disk_attributes-ne3-or
   $frozen.source_payload_writes-ne0-or$frozen.source_sha256-cnotmatch'\A[0-9a-f]{64}\z'-or$intent.experiment_id-cne$d.run_id-or$binding.disk_number-ne1-or
   $identity.partition_number-ne2-or$identity.disk_bytes-ne64GB-or$identity.partition_bytes-ne52GB-or$identity.partition_offset-ne16MB-or
   $identity.logical_sector_bytes-ne512-or$identity.physical_sector_bytes-ne4096-or$part.Count-ne1-or
   [guid]$identity.partition_guid-ne[guid]$part[0].guid-or[guid]$source.Guid-ne[guid]$identity.disk_guid-or
   $source.Size-ne64GB-or$source.LogicalSectorSize-ne512-or$source.PhysicalSectorSize-ne4096-or
   [guid]$actualPartition.Guid-ne[guid]$identity.partition_guid-or$actualPartition.Offset-ne16MB-or$actualPartition.Size-ne52GB-or
   ($binding|ConvertTo-Json -Depth 12 -Compress)-cne($intent.pair.source|ConvertTo-Json -Depth 12 -Compress)-or
   ($binding|ConvertTo-Json -Depth 12 -Compress)-cne($mounts.binding|ConvertTo-Json -Depth 12 -Compress)-or-not$mounts.all_paths_resolve_to_bound_volume){throw 'Frozen source, intent, fixture or actual partition binding differs.'}
  $binary='C:\ntfs2refs\alpha\native-shadow-alpha-20261026\ntfs2refs.exe'
  if((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()-cne'714ddd2bc78d1165061524a390e538c15d8022b2b56ca5170040edfe1286b841'){throw 'Frozen public binary differs.'}
  [pscustomobject]@{vm_id=$d.vm_id;run_id=$d.run_id;checkpoint_id=$d.checkpoint_id;binary=$binary;binary_sha256='714ddd2bc78d1165061524a390e538c15d8022b2b56ca5170040edfe1286b841';rows=$rows;run_directory=$d.guest_output;producer_exit_code=87;source_binding=$binding;source_sha256=$frozen.source_sha256}
 }
 Add-Member -InputObject $pins -NotePropertyName fixture_sha256 -NotePropertyValue (Get-FileHash -LiteralPath (Join-Path $alpha 'guest-fixture.json') -Algorithm SHA256).Hash.ToLowerInvariant()
 Add-Member -InputObject $pins -NotePropertyName manifest_sha256 -NotePropertyValue (Get-FileHash -LiteralPath (Join-Path $alpha 'manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant()
 Add-Member -InputObject $pins -NotePropertyName dispatch_sha256 -NotePropertyValue (Get-FileHash -LiteralPath (Join-Path $caseRoot 'dispatch.json') -Algorithm SHA256).Hash.ToLowerInvariant()
 Save 'cancel-controller-intent.json' $pins
 $producerExport=Export-CancelEvidence $pins.run_directory 'producer-freeze'
 foreach($row in $pins.rows){if((Get-FileHash -LiteralPath (Join-Path $producerExport $row.name) -Algorithm SHA256).Hash.ToLowerInvariant()-cne$row.sha256){throw 'Exported producer pin differs.'}}
 foreach($operation in @('operation-state','cancel')){
  Assert-CancelOwner
  $stepId=[guid]::NewGuid().ToString('N');$taskName='N2R-AlphaCancel-'+$stepId
  $output='C:\ntfs2refs\alpha\cancel-results\'+$stepId
  $arguments=$operation+' --run-directory "'+$pins.run_directory+'" --intent-sha256 '+$pins.rows[0].sha256+
   ' --frozen-source-sha256 '+$pins.rows[1].sha256+' --mount-paths-sha256 '+$pins.rows[2].sha256+' --output "'+$output+'"'
  $step=[pscustomobject]@{operation=$operation;task_name=$taskName;binary=$pins.binary;binary_sha256=$pins.binary_sha256;arguments=$arguments;output=$output;started_utc=[DateTime]::UtcNow.ToString('o')}
  Save ($operation+'-intent.json') $step
  Invoke-Command -Session $session -ArgumentList ($step|ConvertTo-Json -Compress) -ScriptBlock {
   param($Text);$ErrorActionPreference='Stop';$s=$Text|ConvertFrom-Json
   if(@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State.ToString()-in@('Running','Queued')}).Count){throw 'Another lab task is active.'}
   if(Test-Path -LiteralPath $s.output){throw 'Fresh cancellation output required.'}
   if((Get-FileHash -LiteralPath $s.binary -Algorithm SHA256).Hash.ToLowerInvariant()-cne$s.binary_sha256-or(Get-ScheduledTask -TaskName $s.task_name -ErrorAction SilentlyContinue)){throw 'Frozen executable/fresh task differs.'}
   $action=New-ScheduledTaskAction -Execute $s.binary -Argument $s.arguments
   $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
   $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
   Register-ScheduledTask -TaskName $s.task_name -Action $action -Principal $principal -Settings $settings|Out-Null
   Start-ScheduledTask -TaskName $s.task_name
  }|Out-Null
  $deadline=[DateTime]::UtcNow.AddMinutes(30)
  do{
   Assert-CancelOwner
   $observed=Invoke-Command -Session $session -ArgumentList ($step|ConvertTo-Json -Compress) -ScriptBlock {param($StepText)
    Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$recorded=$StepText|ConvertFrom-Json
    $scheduled=Get-ScheduledTask -TaskName $recorded.task_name;$info=Get-ScheduledTaskInfo -TaskName $recorded.task_name;$actions=@($scheduled.Actions)
    if($actions.Count-ne1-or$actions[0].Execute-cne$recorded.binary-or$actions[0].Arguments-cne$recorded.arguments-or
     $scheduled.Principal.UserId-notin@('SYSTEM','S-1-5-18')-or$scheduled.Principal.RunLevel.ToString()-cne'Highest'){throw 'Recorded direct cancellation task differs.'}
    $processes=@(Get-CimInstance Win32_Process -Filter "Name='ntfs2refs.exe'"|Where-Object {
     [string]::IsNullOrEmpty([string]$_.ExecutablePath)-or[string]::Equals([string]$_.ExecutablePath,$recorded.binary,[StringComparison]::OrdinalIgnoreCase)}|ForEach-Object {
     [pscustomobject]@{pid=$_.ProcessId;path=$_.ExecutablePath;command_line=$_.CommandLine}})
    [pscustomobject]@{state=$scheduled.State.ToString();result=$info.LastTaskResult;has_run=$info.LastRunTime.Year-ge2000;
     matching_processes=$processes;terminal=($info.LastRunTime.Year-ge2000-and$scheduled.State.ToString()-notin@('Running','Queued')-and$processes.Count-eq0)}}
   if($observed.terminal){break}
   if([DateTime]::UtcNow-ge$deadline){throw 'Cancellation observation timed out; do not infer worker termination or retry.'}
   Start-Sleep -Seconds 15
  }while($true)
  Save ($operation+'-terminal.json') $observed
  if($observed.result-ne0){throw ($operation+' failed; preserve state without automatic recovery.')}
  $name=if($operation-ceq'cancel'){'result.json'}else{'state.json'}
  $collected=Export-CancelEvidence $output $operation
  $localResult=Join-Path $caseRoot ($operation+'-result.json');if(Test-Path -LiteralPath $localResult){throw 'Fresh controller result copy required.'}
  Copy-Item -LiteralPath (Join-Path $collected $name) -Destination $localResult
  $result=Read-BoundedJson $localResult
  if($operation-ceq'operation-state'){
   if($result.state-cne'frozen_before_activation'-or$result.can_request-notcontains'cancel'){throw 'Public state classifier did not permit qualified cancellation.'}
  }else{
   $restored=Read-BoundedJson (Join-Path $collected 'source-restored.json');$unchanged=Read-BoundedJson (Join-Path $collected 'source-unchanged.json')
   if(-not$result.success-or$result.kind-cne'public-preactivation-cancel'-or$result.source_filesystem-cne'NTFS'-or-not$result.original_mount_paths_preserved-or
    $result.source_sha256-cne$pins.source_sha256-or$result.source_hash_scope-cne'complete partition before original NTFS writable mount'-or
    -not$result.source_original_online-or-not$result.exclusive_source_lease-or$result.journal_mutations-ne0-or$result.source_payload_writes-ne0-or$result.raw_reconstruction_authorized-or
    $restored.source_sha256-cne$pins.source_sha256-or$unchanged.source_sha256-cne$pins.source_sha256-or
    $restored.before.disk_attributes-ne3-or$restored.after.disk_attributes-ne0-or$restored.native_bytes_read-ne52GB-or
    -not$restored.exclusive_source_lease-or-not$restored.source_handle_closed-or$restored.raw_source_writes-ne0-or
    ($restored.binding|ConvertTo-Json -Depth 12 -Compress)-cne($pins.source_binding|ConvertTo-Json -Depth 12 -Compress)-or
    ($unchanged.binding|ConvertTo-Json -Depth 12 -Compress)-cne($pins.source_binding|ConvertTo-Json -Depth 12 -Compress)){throw 'Public cancellation proof/frozen-source relation differs.'}
  }
 }
 Assert-CancelOwner;Assert-CancelFixture $fixture
 $verified=Invoke-Command -Session $session -ArgumentList ($fixture.files|ConvertTo-Json -Compress),($pins.source_binding|ConvertTo-Json -Depth 12 -Compress) -ScriptBlock {
  param($Rows,$SourceText);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$expected=$SourceText|ConvertFrom-Json
  $disk=Get-Disk -Number 1;$part=Get-Partition -DiskNumber 1 -PartitionNumber 2;$route=@(Get-Partition -DriveLetter F);$volume=$part|Get-Volume;$files=@($Rows|ConvertFrom-Json)
  if($disk.IsOffline-or$disk.IsReadOnly-or$disk.IsBoot-or$disk.IsSystem-or[guid]$disk.Guid-ne[guid]$expected.identity.disk_guid-or
   [guid]$part.Guid-ne[guid]$expected.identity.partition_guid-or$part.Offset-ne16MB-or$part.Size-ne52GB-or
   $route.Count-ne1-or$route[0].DiskNumber-ne1-or$route[0].PartitionNumber-ne2-or[string]$part.DriveLetter-cne'F'-or
   $volume.FileSystem-cne'NTFS'-or$volume.FileSystemLabel-cne'n2r-alpha-source'-or$files.Count-ne7){throw 'Original NTFS partition availability/label not restored.'}
  foreach($row in $files){$item=Get-Item -LiteralPath $row.path -Force
   if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-ne$row.bytes-or
    (Get-FileHash -LiteralPath $row.path -Algorithm SHA256).Hash.ToLowerInvariant()-cne$row.sha256){throw 'Recovered user payload identity/length/hash differs.'}}
  [pscustomobject]@{source_ntfs=$true;source_online=$true;original_label=$true;seven_user_payload_hashes_matched=$true;
   full_image_equality_scope='public cancel proof before writable mount';postmount_full_security_and_timestamp_audit=$false}
 }
 Save 'cancel-availability-verified.json' $verified
 [pscustomobject]@{case='Cancel';success=$true;directory=$caseRoot;native_availability=$verified}|ConvertTo-Json -Depth 5 -Compress
}finally{Remove-PSSession $session -ErrorAction SilentlyContinue}
