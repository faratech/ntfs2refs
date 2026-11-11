# Source-only until the alpha coordinator invokes it. One terminal exit86 case,
# one owned SCSI0/4 shadow detach, one direct frozen public rollback task.
# Never restores, reboots, stops workers, deletes backing files or retries.
[CmdletBinding()]
param([Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$CaseId,
      [ValidateRange(1,240)][int]$MaximumWaitMinutes=120,
      [ValidateRange(1,30)][int]$PollSeconds=15)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace='D:\code\ntfs2refs';$alphaRoot=Join-Path $workspace '.lab\hyperv\shadow-alpha-20261026'
$packageRoot=Join-Path $workspace '.lab\alpha\native-shadow-alpha-20261026'
$caseRoot=Join-Path $alphaRoot ('fault-cases\'+$CaseId)
$vmId=[guid]'0d9bfa66-c66c-4ead-86b7-e72cb5f7e040';$vmName='ntfs2refs-shadow-alpha-20261026'
$baselineId=[guid]'7e5582a7-6b15-4531-b77f-9f19cb9e5d47'
$stage='C:\ntfs2refs\alpha\native-shadow-alpha-20261026'
$engine='96720eff89c7e808983c8d5c9800d475fe62515c'
$publicPin='714ddd2bc78d1165061524a390e538c15d8022b2b56ca5170040edfe1286b841'
$producerPin='129ec4cfe6d70812291a343594be1e843f92cc59e3e7bca51c7b8bbb536ed822'
$session=$null;$lease=$null;$controllerId=[guid]::NewGuid().ToString('N')
$phase='host-preflight';$intentSaved=$false;$detachAttempted=$false;$startAttempted=$false
function Assert-Ordinary([string]$Path,[bool]$Directory){
 $item=Get-Item -LiteralPath $Path -Force
 if([bool]$item.PSIsContainer-ne$Directory-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw ('Ordinary path required: '+$Path)}
 $parent=Split-Path $item.FullName -Parent
 while($parent){$entry=Get-Item -LiteralPath $parent -Force;if(-not$entry.PSIsContainer-or($entry.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Nonordinary ancestry refused.'};$next=Split-Path $parent -Parent;if($next-ceq$parent){break};$parent=$next}
}
function Read-HostJson([string]$Path){Assert-Ordinary $Path $false;if((Get-Item -LiteralPath $Path).Length-gt2MB){throw 'Bounded host JSON required.'};Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json}
function Save-Record([string]$Name,$Value){
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 32));if($bytes.Length-gt16MB){throw 'Bounded controller record required.'}
 $file=[IO.File]::Open((Join-Path $caseRoot $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
}
function Assert-AlphaVm([bool]$ShadowPresent){
 $vm=Get-VM -Id $vmId -ErrorAction Stop
 if($vm.Name-cne$vmName-or$vm.State.ToString()-cne'Running'-or[guid]$vm.ParentSnapshotId-ne$baselineId-or
  -not$vm.Path.StartsWith($alphaRoot+'\',[StringComparison]::OrdinalIgnoreCase)-or@(Get-VMNetworkAdapter -VM $vm).Count-ne0-or
  $vm.AutomaticCheckpointsEnabled-or$vm.DynamicMemoryEnabled-or$vm.MemoryStartup-ne8GB-or(Get-VMProcessor -VM $vm).Count-ne4){throw 'Exact running alpha VM, branch or isolation differs.'}
 $snapshots=@(Get-VMSnapshot -VM $vm)
 if(@($snapshots|Where-Object {$_.Id-eq$baselineId-and$_.Name-ceq'alpha-ntfs-baseline'}).Count-ne1-or
  @($snapshots|Where-Object {$_.Id-eq[guid]$dispatch.preserved_normal_checkpoint-and[guid]$_.ParentSnapshotId-eq$baselineId}).Count-ne1){throw 'Baseline/preserved normal checkpoint differs.'}
 $drives=@(Get-VMHardDiskDrive -VM $vm);if($drives.Count-ne$(if($ShadowPresent){4}else{3})){throw 'Alpha backing count differs.'}
 $shadow=$null;$chains=@()
 foreach($spec in $manifest.disks){
  $isShadow=$spec.controller-ceq'SCSI'-and$spec.controller_number-eq0-and$spec.controller_location-eq4
  $drive=@($drives|Where-Object {$_.ControllerType.ToString()-ceq$spec.controller-and$_.ControllerNumber-eq$spec.controller_number-and$_.ControllerLocation-eq$spec.controller_location})
  if($isShadow-and-not$ShadowPresent){if($drive.Count){throw 'Shadow attachment remains.'};continue}
  if($drive.Count-ne1){throw 'Owned backing route differs.'};$path=[string]$drive[0].Path;$seen=@{};$chain=@()
  while($true){
   if(-not[string]::Equals($path,[IO.Path]::GetFullPath($path),[StringComparison]::OrdinalIgnoreCase)){throw 'Noncanonical backing path refused.'}
   if(-not$path.StartsWith($alphaRoot+'\',[StringComparison]::OrdinalIgnoreCase)-or$seen.ContainsKey($path)-or$seen.Count-ge128){throw 'Backing escapes ownership, cycles or exceeds bound.'}
   $seen[$path]=$true;Assert-Ordinary $path $false;$vhd=Get-VHD -Path $path -ErrorAction Stop
   if($vhd.Size-ne$spec.virtual_bytes){throw 'Backing geometry differs.'};$item=Get-Item -LiteralPath $path -Force
   $chain+=[pscustomobject]@{path=$path;bytes=$item.Length;vhd_id=[string]$vhd.DiskIdentifier;parent=[string]$vhd.ParentPath}
   if([string]::IsNullOrEmpty([string]$vhd.ParentPath)){break};$path=[string]$vhd.ParentPath
  }
  if(-not[string]::Equals($path,[string]$spec.path,[StringComparison]::OrdinalIgnoreCase)-or[guid]$vhd.DiskIdentifier-ne[guid]$spec.vhd_id){throw 'Owned backing root/container differs.'}
  $chains+=[pscustomobject]@{controller=$spec.controller;number=$spec.controller_number;location=$spec.controller_location;chain=$chain}
  if($isShadow){$shadow=$drive[0]}
 }
 if($ShadowPresent-and$null-eq$shadow){throw 'Exact owned SCSI0 slot4 shadow required.'}
 [pscustomobject]@{vm=$vm;shadow=$shadow;chains=$chains}
}
$manifest=Read-HostJson (Join-Path $alphaRoot 'manifest.json');$baseline=Read-HostJson (Join-Path $alphaRoot 'baseline.json')
$dispatch=Read-HostJson (Join-Path $caseRoot 'dispatch.json');$intent=Read-HostJson (Join-Path $caseRoot 'intent.json')
$inputPath=Join-Path $caseRoot 'input.json';$input=Read-HostJson $inputPath
$bound=Read-HostJson (Join-Path $caseRoot 'binding-discovery.json')
$fixturePath=Join-Path $alphaRoot 'guest-fixture.json';$fixture=Read-HostJson $fixturePath
$package=Read-HostJson (Join-Path $packageRoot 'alpha.json')
if([guid]$manifest.vm_id-ne$vmId-or$manifest.name-cne$vmName-or$manifest.root-cne$alphaRoot-or@($manifest.disks).Count-ne4-or
 [guid]$baseline.vm_id-ne$vmId-or[guid]$baseline.checkpoint_id-ne$baselineId-or$dispatch.case-cne'RollbackWithoutShadow'-or
 $dispatch.run_id-cne$CaseId-or[guid]$dispatch.vm_id-ne$vmId-or[guid]$dispatch.checkpoint_id-ne$baselineId-or$dispatch.expected_exit_code-ne86-or
 $dispatch.binary_sha256-cne$producerPin-or$dispatch.engine_commit-cne$engine-or$dispatch.entrypoint-cne'lab-controlled-interruption'-or
 $dispatch.task_name-cne('N2R-AlphaFault-RollbackWithoutShadow-'+$CaseId)-or
 $dispatch.guest_input_root-cne('C:\ntfs2refs\alpha\fault-inputs\'+$CaseId)-or
 $dispatch.binary-cne('C:\ntfs2refs\alpha\fault-inputs\'+$CaseId+'\lab-convert-admitted-tree.exe')-or
 $dispatch.guest_output-cne('C:\ntfs2refs\alpha\fault-runs\'+$CaseId)-or$dispatch.guest_input-cne('C:\ntfs2refs\alpha\fault-inputs\'+$CaseId+'\request.json')-or
 $dispatch.arguments-cne('--request "'+$dispatch.guest_input+'" --request-sha256 '+$dispatch.request_sha256+' --output "'+$dispatch.guest_output+'" --interrupt-after-writes 1')-or
 $intent.kind-cne'native-shadow-alpha-fault-intent'-or$intent.case-cne$dispatch.case-or$intent.run_id-cne$CaseId-or[guid]$intent.vm_id-ne$vmId-or
 [guid]$intent.restore_only_checkpoint-ne$baselineId-or$bound.request_sha256-cne$dispatch.request_sha256-or
 (Get-FileHash -LiteralPath $inputPath -Algorithm SHA256).Hash.ToLowerInvariant()-cne$dispatch.request_sha256-or$input.experiment_id-cne$CaseId-or
 $input.verify_existing_shadow-or$input.max_journal_bytes-lt1-or$input.max_journal_bytes-gt768MB-or
 $package.engine_commit-cne$engine-or$package.tag-cne'alpha-native-shadow-20261026'-or$fixture.kind-cne'native-shadow-alpha-fixture'-or@($fixture.files).Count-ne7){throw 'Frozen case, ownership, package or fixture differs.'}
if(@($manifest.disks|ForEach-Object {([string]$_.controller)+':'+$_.controller_number+':'+$_.controller_location}|Sort-Object -Unique).Count-ne4-or
 @($manifest.disks.path|Sort-Object -Unique).Count-ne4){throw 'Manifest backing routes/paths are not unique.'}
$shadowSpec=@($manifest.disks|Where-Object {$_.controller-ceq'SCSI'-and$_.controller_number-eq0-and$_.controller_location-eq4})
if($shadowSpec.Count-ne1-or$shadowSpec[0].path-cne(Join-Path $alphaRoot 'disks\shadow.vhdx')-or$shadowSpec[0].virtual_bytes-ne64GB){throw 'New alpha slot4 enrollment differs.'}
$publicRow=@($package.executables|Where-Object {$_.name-ceq'ntfs2refs.exe'});$hostBinary=Join-Path $packageRoot 'bin\ntfs2refs.exe'
Assert-Ordinary $hostBinary $false
if($publicRow.Count-ne1-or$publicRow[0].sha256-cne$publicPin-or(Get-Item -LiteralPath $hostBinary).Length-ne$publicRow[0].bytes-or
 (Get-FileHash -LiteralPath $hostBinary -Algorithm SHA256).Hash.ToLowerInvariant()-cne$publicPin){throw 'Frozen public executable differs.'}
if(Test-Path -LiteralPath (Join-Path $caseRoot 'rollback-controller-intent.json')){throw 'Controller already dispatched; inspect recorded state without retry.'}
$lock=Join-Path $alphaRoot 'fault-dispatch.lock';if(Test-Path -LiteralPath $lock){Assert-Ordinary $lock $false}
$lease=[IO.File]::Open($lock,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)

# The identical guard runs before/after detach and immediately before task
# dispatch. Raw source/shadow payloads are never opened by this controller.
$guestGuard={
 param($DispatchJson,$InputJson,$ExpectedPinsJson,[bool]$ShadowPresent,$PublicPin,[long]$PublicBytes,$StepJson)
 Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
 function Ordinary([string]$Path,[bool]$Directory){
  $f=Get-Item -LiteralPath $Path -Force
  if($f-isnot[IO.FileSystemInfo]-or[bool]($f.Attributes-band[IO.FileAttributes]::Directory)-ne$Directory-or
   ($f.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary guest path required.'}
  # Windows PowerShell5.1 needs a trailing slash to stat a volume-GUID root;
  # both Split-Path and DirectoryInfo.Parent can remove it.
  $p=if($f-is[IO.DirectoryInfo]){$f.Parent}else{$f.Directory}
  while($p){
   $volumeRoot=$p.FullName-match'\A\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\z'
   if($volumeRoot){$p=Get-Item -LiteralPath ($p.FullName+'\') -Force}
   if($p-isnot[IO.DirectoryInfo]-or-not$p.Exists-or-not($p.Attributes-band[IO.FileAttributes]::Directory)-or
    ($p.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Guest ancestry differs.'}
   if($volumeRoot){break};$p=$p.Parent
  };$f
 }
 function Json([string]$Path,[long]$Limit){$f=Ordinary $Path $false;if($f.Length-gt$Limit){throw 'Bounded guest JSON required.'};Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json}
 function Binding($Actual,$Expected){
  if($Actual.disk_number-ne$Expected.disk_number-or[guid]$Actual.volume_guid-ne[guid]$Expected.volume_guid){throw 'Derived disk/volume route differs.'}
  foreach($k in @('disk_guid','partition_guid')){if([guid]$Actual.identity.$k-ne[guid]$Expected.identity.$k){throw 'Derived GPT differs.'}}
  foreach($k in @('partition_number','disk_bytes','partition_offset','partition_bytes','logical_sector_bytes','physical_sector_bytes')){if($Actual.identity.$k-ne$Expected.identity.$k){throw 'Derived geometry differs.'}}
 }
 $d=$DispatchJson|ConvertFrom-Json;$original=$InputJson|ConvertFrom-Json
 $v=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
 if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'-or-not[Environment]::Is64BitProcess-or$v.CurrentBuild-cne'26300'-or$v.UBR-ne9457-or
  [guid](Get-CimInstance Win32_ComputerSystemProduct).UUID-ne[guid]'87d4c43a-4299-460e-b973-b241f239d33f'-or
  (Get-FileHash -LiteralPath 'C:\Windows\System32\drivers\refs.sys' -Algorithm SHA256).Hash.ToLowerInvariant()-cne'3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4'){throw 'Exact alpha guest/build/driver differs.'}
 $task=Get-ScheduledTask -TaskName $d.task_name -ErrorAction Stop;$info=Get-ScheduledTaskInfo -TaskName $d.task_name;$actions=@($task.Actions)
 if($task.State.ToString()-notin@('Ready','Disabled')-or$info.LastTaskResult-ne86-or$info.LastRunTime.Year-lt2000-or$actions.Count-ne1-or
  $actions[0].Execute-cne$d.binary-or$actions[0].Arguments-cne$d.arguments-or$task.Principal.UserId-notin@('SYSTEM','S-1-5-18')-or
  $task.Principal.RunLevel.ToString()-cne'Highest'){throw 'Exact producer is not known terminal exit86.'}
 $live=@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')})
 $workers=@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-bind)?|lab-.+)\.exe\z'-or([string]$_.CommandLine).IndexOf('C:\ntfs2refs\',[StringComparison]::OrdinalIgnoreCase)-ge0})
 if($live.Count-or$workers.Count){throw 'Live/unknown N2R worker blocks rollback; never stop or retry.'}
 $binary='C:\ntfs2refs\alpha\native-shadow-alpha-20261026\ntfs2refs.exe';$bf=Ordinary $binary $false
 Ordinary $d.binary $false|Out-Null;Ordinary $d.guest_input $false|Out-Null
 if($bf.Length-ne$PublicBytes-or(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()-cne$PublicPin-or
  (Get-FileHash -LiteralPath $d.binary -Algorithm SHA256).Hash.ToLowerInvariant()-cne$d.binary_sha256-or
  (Get-FileHash -LiteralPath $d.guest_input -Algorithm SHA256).Hash.ToLowerInvariant()-cne$d.request_sha256){throw 'Frozen binary/producer input differs.'}
 $pins=@();$values=@{}
 foreach($spec in @(@('request.json',128KB),@('ticket.json',64KB),@('prepare.json',16MB),@('journal-location.json',16KB),@('interruption-intent.json',16KB))){
  $path=Join-Path $d.guest_output $spec[0];$f=Ordinary $path $false;$values[$spec[0]]=Json $path $spec[1]
  $pins+=[pscustomobject]@{name=$spec[0];bytes=$f.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
 }
 foreach($name in @('apply.json','finalization.json','result.json','failed.json')){if(Test-Path -LiteralPath (Join-Path $d.guest_output $name)){throw 'Unexpected producer terminal/post-apply artifact.'}}
 if($ExpectedPinsJson){$expectedRows=$ExpectedPinsJson|ConvertFrom-Json;$expectedRows=@($expectedRows)
  if($expectedRows.Count-ne$pins.Count){throw 'Producer pin coverage changed.'}
  foreach($pin in $pins){if(@($expectedRows|Where-Object {$_.name-ceq$pin.name-and$_.bytes-eq$pin.bytes-and$_.sha256-ceq$pin.sha256}).Count-ne1){throw 'Producer pin changed across controller boundaries.'}}
 }
 $r=$values['request.json'];$t=$values['ticket.json'];$p=$values['prepare.json'];$loc=$values['journal-location.json'];$cut=$values['interruption-intent.json']
 Binding $r.pair.source $original.pair.source;Binding $r.pair.shadow $original.pair.shadow;Binding $r.journal.disk $original.journal.disk
 $journal='\\?\Volume{'+$r.journal.disk.volume_guid+'}\ntfs2refs-shadow\'+$d.run_id+'\reconstruction.journal'
 $ticketPin=@($pins|Where-Object {$_.name-ceq'ticket.json'})[0].sha256
 $sourceLabel=@('n2r-alpha-source'.ToCharArray()|ForEach-Object {[int]$_})
 if($r.schema_version-ne1-or$r.experiment_id-cne$d.run_id-or$r.comparison.schema_version-ne2-or$r.comparison.sector_size-ne4096-or
  $r.comparison.expected_length-ne52GB-or$r.comparison.source_sha256-cnotmatch'\A[0-9a-f]{64}\z'-or
  $r.pair.source.disk_number-ne1-or$r.pair.shadow.disk_number-ne3-or$r.journal.disk.disk_number-ne2-or
  $r.max_journal_bytes-ne$original.max_journal_bytes-or$r.max_journal_bytes-gt768MB-or
  $r.journal.externally_enrolled_disk_unique_id-cne$original.journal.externally_enrolled_disk_unique_id-or$r.journal.allow_additional_partitions-ne$original.journal.allow_additional_partitions-or
  [string]::Join(',',@($r.expected_source_label.utf16))-cne[string]::Join(',',$sourceLabel)-or
  @($r.expected_mount_paths|Where-Object {[string]::Equals([string]$_,'F:\',[StringComparison]::OrdinalIgnoreCase)}).Count-ne1-or
  @($r.expected_mount_paths).Count-ne1-or
  $t.schema_version-ne1-or$t.binding.experiment_id-cne$d.run_id-or$t.immutable_sha256-cnotmatch'\A[0-9a-f]{64}\z'-or
  $t.immutable_length+8192-ne$t.journal_length-or$t.journal_length-lt8192-or$t.journal_length-gt$r.max_journal_bytes-or
  ($p.journal.ticket|ConvertTo-Json -Depth 8 -Compress)-cne($t|ConvertTo-Json -Depth 8 -Compress)-or
  ($p.request|ConvertTo-Json -Depth 20 -Compress)-cne($r|ConvertTo-Json -Depth 20 -Compress)-or-not$p.journal.preparation_durable-or$p.journal.conversion_qualified-or
  -not[string]::Equals([string]$loc.path,$journal,[StringComparison]::OrdinalIgnoreCase)-or
  $cut.kind-cne'controlled-conversion-interruption-intent'-or$cut.expected_process_exit_code-ne86-or$cut.interrupt_after_writes-ne1-or
  $cut.ticket_sha256-cne$ticketPin-or$cut.handoff_authorized-or-not[string]::Equals([string]$cut.journal_path,$journal,[StringComparison]::OrdinalIgnoreCase)){throw 'Pinned derived request, journal, ticket or interruption differs.'}
 $disks=@(Get-Disk);$expectedNumbers=if($ShadowPresent){'0,1,2,3'}else{'0,1,2'}
 if((@($disks.Number|Sort-Object)-join',')-cne$expectedNumbers){throw 'Actual alpha disk inventory differs.'}
 foreach($spec in @(@($r.pair.source,$true,$false),@($r.journal.disk,$false,$false))){
  $b=$spec[0];$disk=Get-Disk -Number $b.disk_number;$part=Get-Partition -DiskNumber $b.disk_number -PartitionNumber $b.identity.partition_number
  if([guid]$disk.Guid-ne[guid]$b.identity.disk_guid-or[guid]$part.Guid-ne[guid]$b.identity.partition_guid-or$disk.Size-ne$b.identity.disk_bytes-or
   $part.Offset-ne$b.identity.partition_offset-or$part.Size-ne$b.identity.partition_bytes-or$disk.LogicalSectorSize-ne$b.identity.logical_sector_bytes-or
   $disk.PhysicalSectorSize-ne$b.identity.physical_sector_bytes-or$disk.IsOffline-ne$spec[1]-or$disk.IsReadOnly-ne$spec[2]-or
   $disk.IsBoot-or$disk.IsSystem-or$part.IsBoot-or$part.IsSystem-or$disk.PartitionStyle.ToString()-cne'GPT'){throw 'Actual source/journal identity or exclusion differs.'}
 }
 if((Get-Partition -DriveLetter C).DiskNumber-ne0-or(Get-Partition -DriveLetter J).DiskNumber-ne2-or(Get-Volume -DriveLetter J).FileSystem-cne'NTFS'-or
  (Get-Volume -DriveLetter J).FileSystemLabel-cne'n2r-alpha-journal'){throw 'OS/journal mount route differs.'}
 $shadow=@($disks|Where-Object {$_.Number-eq3-or[guid]$_.Guid-eq[guid]$r.pair.shadow.identity.disk_guid})
 if($ShadowPresent){
  if($shadow.Count-ne1){throw 'Exact shadow required.'};$sd=$shadow[0];$sp=Get-Partition -DiskNumber 3 -PartitionNumber $r.pair.shadow.identity.partition_number
  if([guid]$sd.Guid-ne[guid]$r.pair.shadow.identity.disk_guid-or[guid]$sp.Guid-ne[guid]$r.pair.shadow.identity.partition_guid-or
   $sd.Size-ne$r.pair.shadow.identity.disk_bytes-or$sp.Offset-ne$r.pair.shadow.identity.partition_offset-or$sp.Size-ne$r.pair.shadow.identity.partition_bytes-or
   $sd.LogicalSectorSize-ne512-or$sd.PhysicalSectorSize-ne4096-or-not$sd.IsOffline-or-not$sd.IsReadOnly-or$sd.IsBoot-or$sd.IsSystem-or$sp.IsBoot-or$sp.IsSystem-or
   $sd.PartitionStyle.ToString()-cne'GPT'){throw 'Exact offline/read-only shadow differs.'}
 }elseif($shadow.Count-or@(Get-Partition|Where-Object {[guid]$_.Guid-eq[guid]$r.pair.shadow.identity.partition_guid}).Count){throw 'Shadow GPT disk/partition is still present.'}
 $jf=Ordinary $journal $false;if($jf.Length-ne$t.journal_length){throw 'Actual journal length differs.'}
 $stream=[IO.File]::Open($journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
 try{
  $marker=[byte[]]::new(4096);$read=0;while($read-lt4096){$n=$stream.Read($marker,$read,4096-$read);if($n-eq0){throw 'Truncated journal marker.'};$read+=$n}
  if(@($marker|Where-Object {$_-ne0}).Count){throw 'Handoff/rollback marker is nonzero; never clear or repair it.'}
  $stream.Position=8192;$sha=[Security.Cryptography.SHA256]::Create()
  try{$immutable=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  if($stream.Length-ne$t.journal_length-or$immutable-cne$t.immutable_sha256){throw 'Immutable journal body differs from ticket.'}
 }finally{$stream.Dispose()}
 if($StepJson){
  $s=$StepJson|ConvertFrom-Json;$requestPin=@($pins|Where-Object {$_.name-ceq'request.json'})[0].sha256
  $expected='rollback --without-shadow --request "'+$d.guest_output+'\request.json" --request-sha256 '+$requestPin+
   ' --ticket "'+$d.guest_output+'\ticket.json" --ticket-sha256 '+$ticketPin+' --journal "'+$journal+'" --output "'+$s.output+'"'
  if($s.controller_id-cnotmatch'\A[0-9a-f]{32}\z'-or$s.task_name-cne('N2R-AlphaRollback-'+$s.controller_id)-or$s.binary-cne$binary-or$s.arguments-cne$expected-or
   $s.output-cne('C:\ntfs2refs\alpha\rollback-results\'+$s.controller_id)-or(Test-Path -LiteralPath $s.output)-or(Get-ScheduledTask -TaskName $s.task_name -ErrorAction SilentlyContinue)){throw 'Fresh exact public rollback task/output required.'}
  foreach($parent in @((Split-Path $s.output -Parent),'C:\ntfs2refs\alpha\rollback-inputs')){if(-not(Test-Path -LiteralPath $parent)){$null=[IO.Directory]::CreateDirectory($parent)};Ordinary $parent $true|Out-Null}
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes($StepJson)
  $f=[IO.File]::Open(('C:\ntfs2refs\alpha\rollback-inputs\'+$s.controller_id+'.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
  try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
  $action=New-ScheduledTaskAction -Execute $binary -Argument $s.arguments
  $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
  $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
  $null=Register-ScheduledTask -TaskName $s.task_name -Action $action -Principal $principal -Settings $settings
  Start-ScheduledTask -TaskName $s.task_name -ErrorAction Stop
 }
 [pscustomobject]@{producer_terminal_exit=86;running_n2r_workers=0;shadow_present=$ShadowPresent;source_offline_writable=$true;
  journal_path=$journal;journal_length=$t.journal_length;immutable_sha256=$immutable;handoff_sector_zero=$true;pins=$pins;request=$r;ticket=$t;observed_utc=[DateTime]::UtcNow.ToString('o')}
}

$guestVerify={
 param($Output,$RequestJson,$TicketJson,$RequestPin,$TicketPin,$Journal,$FixtureJson)
 Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$r=$RequestJson|ConvertFrom-Json;$t=$TicketJson|ConvertFrom-Json
 function Ordinary([string]$Path){
  $f=Get-Item -LiteralPath $Path -Force;if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary terminal file required.'}
  $p=$f.Directory;while($p){if($p.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Terminal/file ancestry differs.'};$p=$p.Parent};$f
 }
 $names=@('request.json','ticket.json','intent.json','journal-identity.json','preflight-events.json','execution.json','execution-events.json','completion.json','result.json')
 $files=@();$values=@{};$total=0L
 foreach($name in $names){$path=Join-Path $Output $name;$f=Ordinary $path;$total+=$f.Length
  if($f.Length-gt16MB-or$total-gt64MB){throw 'Terminal JSON bound exceeded.'};$values[$name]=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
  $files+=[pscustomobject]@{name=$name;bytes=$f.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
 }
 if(Test-Path -LiteralPath (Join-Path $Output 'failed.json')){throw 'Public recovery failure artifact exists.'}
 if(@($files|Where-Object {$_.name-ceq'request.json'-and$_.sha256-ceq$RequestPin}).Count-ne1-or@($files|Where-Object {$_.name-ceq'ticket.json'-and$_.sha256-ceq$TicketPin}).Count-ne1){throw 'Public input copies differ.'}
 $e=$values['execution.json'];$c=$values['completion.json'];$result=$values['result.json'];$i=$values['intent.json']
 if($result.kind-cne'general-recovery'-or-not$result.success-or$result.operation-cne'rollback_without_shadow'-or$result.shadow_access_required-or-not$result.ntfs_rollback_completed-or
  $i.operation-cne'rollback_without_shadow'-or$i.shadow_access_required-or$i.request_sha256-cne$RequestPin-or$i.ticket_sha256-cne$TicketPin-or
  $e.expected_target_sha256-cne$r.comparison.source_sha256-or$e.result.target_sha256-cne$r.comparison.source_sha256-or$e.shadow_available-or
  -not$c.success-or-not$c.replay_closed-or$c.shadow_available-or$c.mounted_filesystem-cne'NTFS'-or$c.error-or
  $c.marker.operation-cne'ntfs-rollback-complete'-or$c.marker.target_sha256-cne$r.comparison.source_sha256-or-not$c.marker.handoff_recorded-or
  $c.marker.target_bytes_written-ne0-or$c.marker.patches_written-ne0){throw 'Complete excluded preimage/rollback marker proof differs.'}
 $live=@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')})
 $workers=@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-bind)?|lab-.+)\.exe\z'})
 if($live.Count-or$workers.Count){throw 'A worker is still live; terminal availability is unproven.'}
 $disks=@(Get-Disk)
 if((@($disks.Number|Sort-Object)-join',')-cne'0,1,2'-or@($disks|Where-Object {[guid]$_.Guid-eq[guid]$r.pair.shadow.identity.disk_guid}).Count-or
  @(Get-Partition|Where-Object {[guid]$_.Guid-eq[guid]$r.pair.shadow.identity.partition_guid}).Count){throw 'Actual shadow disk/partition is not absent.'}
 $d=Get-Disk -Number 1;$p=Get-Partition -DiskNumber 1 -PartitionNumber $r.pair.source.identity.partition_number;$v=$p|Get-Volume
 if([guid]$d.Guid-ne[guid]$r.pair.source.identity.disk_guid-or[guid]$p.Guid-ne[guid]$r.pair.source.identity.partition_guid-or$d.IsOffline-or$d.IsReadOnly-or$d.IsBoot-or$d.IsSystem-or
  $d.Size-ne$r.pair.source.identity.disk_bytes-or$p.Offset-ne$r.pair.source.identity.partition_offset-or$p.Size-ne$r.pair.source.identity.partition_bytes-or
  $p.DriveLetter-cne'F'-or$v.FileSystem-cne'NTFS'-or[string]::Join(',',@($v.FileSystemLabel.ToCharArray()|ForEach-Object {[int]$_}))-cne[string]::Join(',',@($r.expected_source_label.utf16))){throw 'Original NTFS mount/label/identity differs.'}
 $jd=Get-Disk -Number 2;$jp=Get-Partition -DiskNumber 2 -PartitionNumber $r.journal.disk.identity.partition_number
 if([guid]$jd.Guid-ne[guid]$r.journal.disk.identity.disk_guid-or[guid]$jp.Guid-ne[guid]$r.journal.disk.identity.partition_guid-or$jd.IsOffline-or$jd.IsReadOnly-or
  (Get-Partition -DriveLetter J).DiskNumber-ne2){throw 'External journal route changed after recovery.'}
 $marker=[byte[]]::new(4096);$null=Ordinary $Journal;$jf=[IO.File]::Open($Journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{if($jf.Length-ne$t.journal_length){throw 'Completed journal length differs.'};$read=0;while($read-lt4096){$n=$jf.Read($marker,$read,4096-$read);if($n-eq0){throw 'Completed marker truncated.'};$read+=$n}}finally{$jf.Dispose()}
 $expected=[byte[]]::new(4096);[Text.Encoding]::ASCII.GetBytes('N2RABT01').CopyTo($expected,0);$expected[8]=4
 for($n=0;$n-lt32;$n++){$expected[16+$n]=[Convert]::ToByte($t.immutable_sha256.Substring(2*$n,2),16);$expected[48+$n]=[Convert]::ToByte($r.comparison.source_sha256.Substring(2*$n,2),16)}
 $sha=[Security.Cryptography.SHA256]::Create();try{$sha.ComputeHash($expected,0,4064).CopyTo($expected,4064);$markerSha=[BitConverter]::ToString($sha.ComputeHash($marker)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
 if([Convert]::ToBase64String($marker)-cne[Convert]::ToBase64String($expected)){throw 'Full rollback marker differs, including padding/checksum.'}
 # Assign first: PS5.1 otherwise wraps a returned JSON array as one item.
 $fixtureRows=$FixtureJson|ConvertFrom-Json;$fixtureRows=@($fixtureRows)
 $allowed=@{'F:\source0.bin'=64KB;'F:\archive\doc1.bin'=128KB;'F:\archive\nested\doc2.bin'=64KB;'F:\notes\doc3.bin'=256KB;
  'F:\extra.bin'=8MB;'F:\notes\post-label.bin'=20KB;'F:\natural-large.bin'=128MB}
 if($fixtureRows.Count-ne7-or@($fixtureRows.path|Sort-Object -Unique).Count-ne7){throw 'Seven distinct fixture files required.'}
 $hashes=@()
 foreach($row in $fixtureRows){
  if($row.path-cnotin@($allowed.Keys)-or$row.bytes-ne$allowed[[string]$row.path]-or$row.sha256-cnotmatch'\A[0-9a-f]{64}\z'){throw 'Pinned fixture path/length differs.'}
  $f=Ordinary $row.path;if($f.Length-ne$row.bytes){throw 'Recovered fixture EOF differs.'}
  $hash=(Get-FileHash -LiteralPath $row.path -Algorithm SHA256).Hash.ToLowerInvariant();if($hash-cne$row.sha256){throw 'Recovered fixture bytes differ.'}
  $hashes+=[pscustomobject]@{path=$row.path;bytes=$f.Length;sha256=$hash}
 }
 [pscustomobject]@{kind='native-shadow-alpha-shadowless-rollback-verified';success=$true;source_ntfs=$true;source_online=$true;original_label=$true;
  seven_user_payload_hashes_matched=$true;shadow_absent=$true;files=$hashes;artifacts=$files;marker_sha256=$markerSha;full_preimage_sha256=$r.comparison.source_sha256;
  full_image_equality_scope='public recovery exact image proof before writable NTFS mount';full_postmount_image_equality_claimed=$false;
  full_security_timestamp_audit=$false;reboot_verified=$false}
}

try{
 $owned=Assert-AlphaVm $true
 $capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace);Assert-LabCapacity -Capacity $capacity -AdditionalBytes 512MB
 $credentialPath=Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml';Assert-Ordinary $credentialPath $false
 $credential=Import-Clixml -LiteralPath $credentialPath;$session=New-PSSession -VMId $vmId -Credential $credential -ErrorAction Stop
 $dispatchJson=$dispatch|ConvertTo-Json -Depth 12 -Compress;$inputJson=$input|ConvertTo-Json -Depth 16 -Compress
 $phase='verify-terminal-producer-and-journal'
 $before=Invoke-Command -Session $session -ScriptBlock $guestGuard -ArgumentList $dispatchJson,$inputJson,'',$true,$publicPin,$publicRow[0].bytes,''
 $pinsJson=$before.pins|ConvertTo-Json -Depth 8 -Compress
 Save-Record 'rollback-controller-intent.json' ([ordered]@{schema_version=1;kind='native-shadow-alpha-shadowless-rollback-intent';case_id=$CaseId;controller_id=$controllerId;
  vm_id=$vmId.ToString('D');baseline_checkpoint=$baselineId.ToString('D');dispatch=$dispatch;producer=$before;chains_before=$owned.chains;capacity=$capacity;
  fixture_sha256=(Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash.ToLowerInvariant();engine_commit=$engine;public_binary_sha256=$publicPin;
  allowed_detach='this VM SCSI0 slot4 only';backing_deletion_authorized=$false;restores_authorized=$false;worker_stop_authorized=$false;automatic_retry_authorized=$false;started_utc=[DateTime]::UtcNow.ToString('o')})
 $intentSaved=$true
 foreach($pin in $before.pins){
  $destination=Join-Path $caseRoot ('rollback-producer-'+$pin.name)
  if(Test-Path -LiteralPath $destination){throw 'Fresh producer export required; never overwrite evidence.'}
  Copy-Item -LiteralPath (Join-Path $dispatch.guest_output $pin.name) -Destination $destination -FromSession $session -ErrorAction Stop;Assert-Ordinary $destination $false
  if((Get-Item -LiteralPath $destination).Length-ne$pin.bytes-or(Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()-cne$pin.sha256){throw 'Exported producer pin differs.'}
 }
 $null=Invoke-Command -Session $session -ScriptBlock $guestGuard -ArgumentList $dispatchJson,$inputJson,$pinsJson,$true,$publicPin,$publicRow[0].bytes,''
 $owned=Assert-AlphaVm $true;$shadowLeaf=[string]$owned.shadow.Path
 Save-Record 'rollback-detach-intent.json' @{vm_id=$vmId.ToString('D');controller='SCSI';number=0;location=4;path=$shadowLeaf;chains=$owned.chains;backing_preserved=$true}
 $phase='detach-owned-shadow-once';$detachAttempted=$true
 Remove-VMHardDiskDrive -VMHardDiskDrive $owned.shadow -Confirm:$false -ErrorAction Stop
 Assert-Ordinary $shadowLeaf $false;$remaining=Assert-AlphaVm $false
 Save-Record 'rollback-detach-returned.json' @{vm_id=$vmId.ToString('D');shadow_leaf=$shadowLeaf;backing_present=$true;remaining_chains=$remaining.chains;observed_utc=[DateTime]::UtcNow.ToString('o')}
 $phase='prove-actual-shadow-absence'
 $absent=Invoke-Command -Session $session -ScriptBlock $guestGuard -ArgumentList $dispatchJson,$inputJson,$pinsJson,$false,$publicPin,$publicRow[0].bytes,''
 Save-Record 'rollback-shadow-absence.json' $absent
 $output='C:\ntfs2refs\alpha\rollback-results\'+$controllerId
 $requestPin=@($before.pins|Where-Object {$_.name-ceq'request.json'})[0].sha256;$ticketPin=@($before.pins|Where-Object {$_.name-ceq'ticket.json'})[0].sha256
 $arguments='rollback --without-shadow --request "'+$dispatch.guest_output+'\request.json" --request-sha256 '+$requestPin+
  ' --ticket "'+$dispatch.guest_output+'\ticket.json" --ticket-sha256 '+$ticketPin+' --journal "'+$before.journal_path+'" --output "'+$output+'"'
 $step=[pscustomobject]@{controller_id=$controllerId;task_name=('N2R-AlphaRollback-'+$controllerId);binary=($stage+'\ntfs2refs.exe');arguments=$arguments;output=$output;request_sha256=$requestPin;ticket_sha256=$ticketPin}
 Save-Record 'rollback-task-intent.json' $step
 $phase='dispatch-public-rollback-once';$startAttempted=$true
 $started=Invoke-Command -Session $session -ScriptBlock $guestGuard -ArgumentList $dispatchJson,$inputJson,$pinsJson,$false,$publicPin,$publicRow[0].bytes,($step|ConvertTo-Json -Depth 8 -Compress)
 Save-Record 'rollback-start-returned.json' $started
 $deadline=[DateTime]::UtcNow.AddMinutes($MaximumWaitMinutes)
 do{
  $null=Assert-AlphaVm $false
  $observed=Invoke-Command -Session $session -ArgumentList ($step|ConvertTo-Json -Compress) -ScriptBlock {
   param($Text);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$s=$Text|ConvertFrom-Json
   $task=Get-ScheduledTask -TaskName $s.task_name;$info=Get-ScheduledTaskInfo -TaskName $s.task_name;$actions=@($task.Actions)
   if($actions.Count-ne1-or$actions[0].Execute-cne$s.binary-or$actions[0].Arguments-cne$s.arguments-or$task.Principal.UserId-notin@('SYSTEM','S-1-5-18')-or$task.Principal.RunLevel.ToString()-cne'Highest'){throw 'Recorded rollback SYSTEM task differs.'}
   $workers=@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-bind)?|lab-.+)\.exe\z'})
   $other=@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.TaskName-cne$s.task_name-and$_.State.ToString()-notin@('Ready','Disabled')})
   if($other.Count){throw 'Another N2R task is active.'}
   [pscustomobject]@{state=$task.State.ToString();exit_code=$info.LastTaskResult;has_run=$info.LastRunTime.Year-ge2000;
    terminal=($task.State.ToString()-in@('Ready','Disabled')-and$info.LastRunTime.Year-ge2000-and$workers.Count-eq0);
    workers=@($workers|Select-Object ProcessId,ExecutablePath,CommandLine,ReadTransferCount,WriteTransferCount)}
  }
  if($observed.terminal){Save-Record 'rollback-terminal.json' $observed;break}
  if([DateTime]::UtcNow-ge$deadline){Save-Record 'rollback-observation-timeout.json' $observed;throw 'Observation timed out; termination is unproven and redispatch is forbidden.'}
  Write-Host ('Shadowless rollback: '+$observed.state+'; workers='+@($observed.workers).Count+'; result='+$observed.exit_code)
  Start-Sleep -Seconds $PollSeconds
 }while($true)
 if($observed.exit_code-ne0){throw 'Public rollback failed; preserve branch/evidence without fallback.'}
 $phase='verify-public-proof-and-native-availability'
 $verified=Invoke-Command -Session $session -ScriptBlock $guestVerify -ArgumentList $output,($before.request|ConvertTo-Json -Depth 20 -Compress),($before.ticket|ConvertTo-Json -Depth 8 -Compress),$requestPin,$ticketPin,$before.journal_path,($fixture.files|ConvertTo-Json -Compress)
 Save-Record 'rollback-availability-verified.json' $verified
 $export=Join-Path $caseRoot ('rollback-evidence-'+$controllerId);if(Test-Path -LiteralPath $export){throw 'Fresh evidence export required.'};$null=[IO.Directory]::CreateDirectory($export)
 foreach($pin in $verified.artifacts){$destination=Join-Path $export $pin.name
  Copy-Item -LiteralPath (Join-Path $output $pin.name) -Destination $destination -FromSession $session;Assert-Ordinary $destination $false
  if((Get-Item -LiteralPath $destination).Length-ne$pin.bytes-or(Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()-cne$pin.sha256){throw 'Exported rollback evidence differs.'}
 }
 $null=Assert-AlphaVm $false;Assert-Ordinary $shadowLeaf $false
 Save-Record 'rollback-controller-result.json' @{kind='native-shadow-alpha-shadowless-rollback-completed';success=$true;case_id=$CaseId;controller_id=$controllerId;
  vm_id=$vmId.ToString('D');baseline_checkpoint=$baselineId.ToString('D');shadow_backing_preserved=$true;shadow_attachment_absent=$true;verified=$verified;
  guest_output=$output;evidence_root=$export;reboot_performed=$false;checkpoint_preservation_required=$true;finished_utc=[DateTime]::UtcNow.ToString('o')}
 [pscustomobject]@{success=$true;case_id=$CaseId;controller_id=$controllerId;directory=$caseRoot;guest_output=$output;shadow_absent=$true;backing_preserved=$true;reboot_verified=$false}
}catch{
 if($intentSaved){Save-Record ('rollback-controller-failed-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json') @{phase=$phase;error=$_.Exception.ToString();
  detach_attempted=$detachAttempted;task_start_attempted=$startAttempted;worker_termination_inferred=$false;automatic_retry_authorized=$false;recorded_utc=[DateTime]::UtcNow.ToString('o')}}
 throw
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue};if($lease){$lease.Dispose()}}
