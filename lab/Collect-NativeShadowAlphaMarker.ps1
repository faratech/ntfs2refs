# Read-only journal evidence on an ALREADY restored/running preserved alpha
# branch. Never restores/starts a VM, changes disk attributes, runs recovery,
# writes a journal, or treats its marker proof as current target-image evidence.
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('Normal','Resume','RollbackWithoutShadow')][string]$Case,
      [ValidatePattern('\A(?:[0-9a-f]{32})?\z')][string]$CaseId='')
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
$workspace='D:\code\ntfs2refs';$alpha=Join-Path $workspace '.lab\hyperv\shadow-alpha-20261026'
$vmId=[guid]'0d9bfa66-c66c-4ead-86b7-e72cb5f7e040';$baseId=[guid]'7e5582a7-6b15-4531-b77f-9f19cb9e5d47'
$engine='96720eff89c7e808983c8d5c9800d475fe62515c'
$publicPin='714ddd2bc78d1165061524a390e538c15d8022b2b56ca5170040edfe1286b841'
$inputPins=[Collections.Generic.List[object]]::new();$leases=[Collections.Generic.List[IO.FileStream]]::new()
$session=$null;$outputRoot=$null;$phase='host-completion-bindings'
function Need([bool]$Value,[string]$Message){if(-not$Value){throw $Message}}
function True($Value){return (($Value-is[bool])-and$Value)}
function Ordinary([string]$Path,[bool]$Directory){
 $item=Get-Item -LiteralPath $Path -Force
 Need ([bool]$item.PSIsContainer-eq$Directory-and-not($item.Attributes-band[IO.FileAttributes]::ReparsePoint)) ('Ordinary path required: '+$Path)
 $parent=if($item.PSIsContainer){$item.Parent}else{$item.Directory}
 while($parent){Need (-not($parent.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse ancestry refused.';$parent=$parent.Parent}
}
function Hash-Bytes([byte[]]$Bytes){$sha=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant())}finally{$sha.Dispose()}}
function Read-Record([string]$Path,[string]$Pin=''){
 Ordinary $Path $false;$item=Get-Item -LiteralPath $Path;Need ($item.Length-le16MB) 'Bounded host JSON required.'
 $bytes=[IO.File]::ReadAllBytes($Path);$hash=Hash-Bytes $bytes
 if($Pin){Need ($Pin-cmatch'\A[0-9a-f]{64}\z'-and$hash-ceq$Pin) 'Pinned host completion input differs.'}
 $inputPins.Add([pscustomobject]@{path=$Path;bytes=$bytes.Length;sha256=$hash})
 return ([Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json)
}
function Save-Bytes([string]$Path,[byte[]]$Bytes){
 Need ($Bytes.Length-le2MB) 'Bounded marker evidence required.'
 $file=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$file.Write($Bytes,0,$Bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
}
function Save-Record([string]$Name,$Value){Save-Bytes (Join-Path $outputRoot $Name) ([Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 24)))}
function New-CanonicalMarker([string]$Magic,[byte]$Code,[string]$ImmutableHash,[string]$TargetHash){
 Need (($Magic-ceq'N2RHND01'-and$Code-eq3)-or($Magic-ceq'N2RABT01'-and$Code-eq4)) 'Unsupported marker kind/code.'
 Need ($ImmutableHash-cmatch'\A[0-9a-f]{64}\z'-and$TargetHash-cmatch'\A[0-9a-f]{64}\z') 'Canonical marker hash pins required.'
 # src/lab_reconstruct.rs::marker: no length fields occur in this sector.
 # Length is bound separately by the ticket and the immutable prepared header.
 $marker=[byte[]]::new(4096);[Text.Encoding]::ASCII.GetBytes($Magic).CopyTo($marker,0);$marker[8]=$Code
 for($i=0;$i-lt32;$i++){$marker[16+$i]=[Convert]::ToByte($ImmutableHash.Substring(2*$i,2),16);$marker[48+$i]=[Convert]::ToByte($TargetHash.Substring(2*$i,2),16)}
 $sha=[Security.Cryptography.SHA256]::Create();try{$sha.ComputeHash($marker,0,4064).CopyTo($marker,4064)}finally{$sha.Dispose()};return ,$marker
}
if($Case-ceq'Normal'){
 if(-not$CaseId){$CaseId='4ad0147fdde044fbb9d5073e5bfdbe8d'}
 Need ($CaseId-ceq'4ad0147fdde044fbb9d5073e5bfdbe8d') 'Only the recorded normal alpha case is enrolled.'
 $controller=Read-Record (Join-Path $alpha 'normal-completion-intent.json')
 Need ($controller.controller_id-ceq'ef9e1456af154eb0b85645a2a094848c'-and[guid]$controller.vm_id-eq$vmId-and$controller.dispatch.run_id-ceq$CaseId) 'Normal completion controller differs.'
 $postRoot=Join-Path $alpha ('postcheck\'+$controller.controller_id)
 $producer=Join-Path $alpha ('normal-evidence\'+$controller.controller_id+'\conversion')
 Need ($controller.postcheck_root-ceq$postRoot-and$controller.evidence_root-ceq(Split-Path $producer -Parent)) 'Normal completion paths differ.'
 $preserved=Read-Record (Join-Path $postRoot 'preserved-checkpoint.json')
 $completed=Read-Record (Join-Path $postRoot 'result.json')
 Need ($completed.kind-ceq'native-shadow-alpha-normal-completed'-and(True $completed.success)-and(True $completed.native_verified)-and(True $completed.mutation_verified)-and(True $completed.reboot_verified)-and[guid]$completed.vm_id-eq$vmId-and[guid]$completed.checkpoint_id-eq[guid]$preserved.checkpoint_id) 'Completed normal branch proof required.'
 $publicResult=Read-Record (Join-Path $producer 'result.json') '9c4a23b2465d4184240beaeca282c9c3aa3e5fa6b5dbd7ff4a4f08a7d939db59'
 Need ($publicResult.kind-ceq'certificate-backed-ntfs-refs-conversion'-and(True $publicResult.success)-and(True $publicResult.rollback_closed)) 'Normal public conversion did not finish.'
 $requestPin=$preserved.request_sha256;$ticketPin=$publicResult.ticket_sha256
 $completion=Read-Record (Join-Path $producer 'finalization.json')
}else{
 Need ([bool]$CaseId) 'An explicit preserved recovery CaseId is required.'
 Need (($Case-ceq'Resume'-and$CaseId-ceq'c2939b18b2fb4ee8836f859dcf1d13b8')-or($Case-ceq'RollbackWithoutShadow'-and$CaseId-ceq'd769b379604c46fd937d5f4fba3a236a')) 'Recovery case is not enrolled in this alpha matrix.'
 $caseRoot=Join-Path $alpha ('fault-cases\'+$CaseId)
 $dispatch=Read-Record (Join-Path $caseRoot 'dispatch.json')
 Need ($dispatch.case-ceq$Case-and$dispatch.run_id-ceq$CaseId-and[guid]$dispatch.vm_id-eq$vmId-and[guid]$dispatch.checkpoint_id-eq$baseId-and$dispatch.engine_commit-ceq$engine-and$dispatch.expected_exit_code-eq86) 'Recovery dispatch differs.'
 if($Case-ceq'Resume'){
  $controller=Read-Record (Join-Path $caseRoot 'resume-controller-intent.json')
  Need ($controller.controller_id-cmatch'\A[0-9a-f]{32}\z'-and$controller.case_id-ceq$CaseId-and[guid]$controller.vm_id-eq$vmId-and$controller.engine_commit-ceq$engine) 'Resume controller differs.'
  $postRoot=Join-Path $caseRoot ('resume-postcheck-'+$controller.controller_id)
  $producer=Join-Path $caseRoot ('resume-evidence-'+$controller.controller_id+'\producer')
  Need ($controller.postcheck_root-ceq$postRoot-and$controller.evidence_root-ceq(Split-Path $producer -Parent)) 'Resume evidence paths differ.'
  $preserved=Read-Record (Join-Path $caseRoot 'resume-preserved-checkpoint.json')
  $completed=Read-Record (Join-Path $postRoot 'result.json') $preserved.result_sha256
  Need ($completed.kind-ceq'native-shadow-alpha-resume-completed'-and(True $completed.success)-and(True $completed.native_verified)-and(True $completed.mutation_verified)-and(True $completed.reboot_verified)-and$completed.case_id-ceq$CaseId-and$preserved.case_id-ceq$CaseId-and$completed.controller_id-ceq$controller.controller_id) 'Completed resume proof required.'
  $requestPin=$completed.request_sha256;$ticketPin=$completed.ticket_sha256
  $completion=Read-Record (Join-Path $postRoot 'post-reboot\finalize\completion.json')
 }else{
  $controller=Read-Record (Join-Path $caseRoot 'rollback-controller-intent.json')
  $completed=Read-Record (Join-Path $caseRoot 'rollback-controller-result.json')
  $preserved=Read-Record (Join-Path $caseRoot 'recovery-preserved-checkpoint.json')
  Need ($controller.kind-ceq'native-shadow-alpha-shadowless-rollback-intent'-and$controller.case_id-ceq$CaseId-and[guid]$controller.vm_id-eq$vmId-and$controller.engine_commit-ceq$engine-and$controller.controller_id-cmatch'\A[0-9a-f]{32}\z'-and
   $completed.kind-ceq'native-shadow-alpha-shadowless-rollback-completed'-and(True $completed.success)-and$completed.case_id-ceq$CaseId-and$completed.controller_id-ceq$controller.controller_id-and(True $completed.shadow_attachment_absent)-and(True $completed.shadow_backing_preserved)-and
   $preserved.case-ceq'RollbackWithoutShadow'-and(True $preserved.payload_reboot_verified)) 'Completed/preserved shadowless rollback proof required.'
  $availability=Read-Record (Join-Path $caseRoot 'rollback-availability-verified.json')
  $export=Join-Path $caseRoot ('rollback-evidence-'+$controller.controller_id)
  Need ($completed.evidence_root-ceq$export-and(True $availability.success)-and(True $availability.shadow_absent)) 'Rollback export/payload evidence differs.'
  $publicIntent=Read-Record (Join-Path $export 'intent.json')
  $requestPin=$publicIntent.request_sha256;$ticketPin=$publicIntent.ticket_sha256
  $producer=$caseRoot
  $completion=Read-Record (Join-Path $export 'completion.json')
 }
}
$prefix=if($Case-ceq'RollbackWithoutShadow'){'rollback-producer-'}else{''}
$request=Read-Record (Join-Path $producer ($prefix+'request.json')) $requestPin
$ticket=Read-Record (Join-Path $producer ($prefix+'ticket.json')) $ticketPin
$prepared=Read-Record (Join-Path $producer ($prefix+'prepare.json'))
$location=Read-Record (Join-Path $producer ($prefix+'journal-location.json'))
Need ($request.schema_version-eq1-and$request.experiment_id-ceq$CaseId-and$ticket.schema_version-eq1-and$ticket.binding.experiment_id-ceq$CaseId-and
 $ticket.immutable_sha256-cmatch'\A[0-9a-f]{64}\z'-and[long]$ticket.immutable_length-ge256-and[long]$ticket.journal_length-le768MB-and
 [long]$ticket.immutable_length+8192-eq[long]$ticket.journal_length-and$request.comparison.source_sha256-cmatch'\A[0-9a-f]{64}\z'-and
 $prepared.journal.ticket.immutable_sha256-ceq$ticket.immutable_sha256-and$prepared.journal.ticket.journal_length-eq$ticket.journal_length-and
 ($prepared.request|ConvertTo-Json -Depth 20 -Compress)-ceq($request|ConvertTo-Json -Depth 20 -Compress)) 'Prepared request/ticket/length relation differs.'
$postimage=$prepared.journal.expected_postimage_sha256
Need ($postimage-cmatch'\A[0-9a-f]{64}\z'-and(True $completion.success)) 'Completed expected target proof required.'
if($Case-ceq'RollbackWithoutShadow'){
 Need ((True $completion.replay_closed)-and$completion.mounted_filesystem-ceq'NTFS'-and$completion.marker.operation-ceq'ntfs-rollback-complete'-and$completion.marker.target_sha256-ceq$request.comparison.source_sha256-and(True $completion.marker.handoff_recorded)) 'Rollback completion marker evidence differs.'
 $magic='N2RABT01';$code=[byte]4;$targetHash=$request.comparison.source_sha256
}else{
 Need ((True $completion.rollback_closed)-and$completion.handoff.operation-ceq'handoff-recorded'-and$completion.handoff.target_sha256-ceq$postimage-and(True $completion.handoff.handoff_recorded)-and$null-ne$completion.native) 'ReFS completion marker evidence differs.'
 $magic='N2RHND01';$code=[byte]3;$targetHash=$postimage
}
$source=$request.pair.source;$journal=$request.journal.disk
Need ($source.disk_number-eq1-and$source.identity.partition_number-eq2-and$source.identity.disk_bytes-eq64GB-and$source.identity.partition_offset-eq16MB-and$source.identity.partition_bytes-eq52GB-and
 [guid]$source.identity.disk_guid-eq[guid]'82df7109-d6a1-4535-852a-9f1abb52966f'-and[guid]$source.identity.partition_guid-eq[guid]'f8bdd003-1df4-45d1-9798-338e57d76414'-and
 $journal.disk_number-eq2-and$journal.identity.partition_number-eq2-and$journal.identity.disk_bytes-eq8GB-and$journal.identity.partition_offset-eq16MB-and$journal.identity.partition_bytes-eq(8GB-32MB)-and
 [guid]$journal.identity.disk_guid-eq[guid]'094f1074-abae-4b68-9eee-b2f5cc9810e9'-and[guid]$journal.identity.partition_guid-eq[guid]'aac9a2e7-e2b3-4f27-b069-d9d70d0495df'-and[guid]$journal.volume_guid-eq[guid]'aac9a2e7-e2b3-4f27-b069-d9d70d0495df'-and
 $source.identity.logical_sector_bytes-eq512-and$source.identity.physical_sector_bytes-eq4096-and$journal.identity.logical_sector_bytes-eq512-and$journal.identity.physical_sector_bytes-eq4096) 'Exact enrolled source/journal geometry differs.'
$journalPath='\\?\Volume{'+$journal.volume_guid+'}\ntfs2refs-shadow\'+$CaseId+'\reconstruction.journal'
Need ($location.path-ceq$journalPath-and[guid]$preserved.vm_id-eq$vmId-and[guid]$preserved.checkpoint_id-ne[guid]::Empty-and
 [guid]$preserved.parent_checkpoint-eq$baseId-and$preserved.state-ceq'Off') 'Preserved branch/journal path differs.'
$manifest=Read-Record (Join-Path $alpha 'manifest.json')
Need ([guid]$manifest.vm_id-eq$vmId-and$manifest.root-ceq$alpha-and@($manifest.disks).Count-eq4) 'Alpha backing manifest differs.'
function Assert-Branch {
 $vm=Get-VM -Id $vmId
 Need ($vm.Name-ceq'ntfs2refs-shadow-alpha-20261026'-and$vm.State.ToString()-ceq'Running'-and$vm.Path.StartsWith($alpha+'\',[StringComparison]::OrdinalIgnoreCase)-and
  [guid]$vm.ParentSnapshotId-eq[guid]$preserved.checkpoint_id-and@(Get-VMNetworkAdapter -VM $vm).Count-eq0-and-not$vm.AutomaticCheckpointsEnabled) 'Run this read-only collector only on the already restored/running preserved branch.'
 $snapshots=@(Get-VMSnapshot -VM $vm|Where-Object {$_.Id-eq[guid]$preserved.checkpoint_id-and[guid]$_.ParentSnapshotId-eq$baseId})
 Need ($snapshots.Count-eq1-and$snapshots[0].Name-ceq$preserved.name) 'Actual preserved checkpoint differs.'
 $drives=@(Get-VMHardDiskDrive -VM $vm);Need ($drives.Count-eq$(if($Case-ceq'RollbackWithoutShadow'){3}else{4})) 'Preserved backing count differs.'
 foreach($drive in $drives){
  $spec=@($manifest.disks|Where-Object {$_.controller-ceq$drive.ControllerType.ToString()-and$_.controller_number-eq$drive.ControllerNumber-and$_.controller_location-eq$drive.ControllerLocation})
  Need ($spec.Count-eq1) 'Unexpected backing route.';$path=[string]$drive.Path;$seen=@{}
  while($true){Need ($path.StartsWith($alpha+'\',[StringComparison]::OrdinalIgnoreCase)-and-not$seen.ContainsKey($path)-and$seen.Count-lt128) 'Backing chain escapes alpha ownership.'
   $seen[$path]=$true;Ordinary $path $false;$vhd=Get-VHD -Path $path;Need ($vhd.Size-eq$spec[0].virtual_bytes) 'Backing geometry differs.'
   if([string]::IsNullOrEmpty([string]$vhd.ParentPath)){break};$path=[string]$vhd.ParentPath}
  Need ([string]::Equals($path,$spec[0].path,[StringComparison]::OrdinalIgnoreCase)-and[guid]$vhd.DiskIdentifier-eq[guid]$spec[0].vhd_id) 'Backing root identity differs.'
 }
}
$canonical=New-CanonicalMarker $magic $code $ticket.immutable_sha256 $targetHash
Assert-Branch
try{
 foreach($name in @('active-alpha-controller.lock','fault-dispatch.lock')){
  $path=Join-Path $alpha $name;Ordinary $path $false;Need ((Get-Item -LiteralPath $path).Length-eq0) 'Host controller lease shape differs.'
  $leases.Add([IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None))
 }
 Assert-Branch;$capture=[guid]::NewGuid().ToString('N');$outputRoot=Join-Path $alpha ('marker-pins\'+$Case+'-'+$CaseId+'-'+$capture)
 Need (-not(Test-Path -LiteralPath $outputRoot)) 'Fresh marker evidence directory required.';$null=[IO.Directory]::CreateDirectory($outputRoot);Ordinary $outputRoot $true
 Save-Record 'intent.json' @{kind='native-shadow-alpha-readonly-marker-intent';case=$Case;case_id=$CaseId;vm_id=$vmId.ToString('D');checkpoint_id=$preserved.checkpoint_id;
  engine_commit=$engine;public_binary_sha256=$publicPin;input_pins=$inputPins.ToArray();journal_path=$journalPath;journal_length=$ticket.journal_length;immutable_length=$ticket.immutable_length;
  immutable_sha256=$ticket.immutable_sha256;expected_marker_sha256=(Hash-Bytes $canonical);target_hash=$targetHash;current_target_image_claimed=$false;writes_authorized=$false;created_utc=[DateTime]::UtcNow.ToString('o')}
 $phase='readonly-guest-journal-observation'
 $credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
 $session=New-PSSession -VMId $vmId -Credential $credential -ErrorAction Stop
 $observed=Invoke-Command -Session $session -ArgumentList ($request|ConvertTo-Json -Depth 20 -Compress),$journalPath,($ticket|ConvertTo-Json -Depth 8 -Compress),([Convert]::ToBase64String($canonical)),$prepared.journal.patch_count,$prepared.journal.changed_bytes,$publicPin -ScriptBlock {
  param($RequestText,$JournalPath,$TicketText,$CanonicalBase64,$PatchCount,$ChangedBytes,$PublicPin)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$r=$RequestText|ConvertFrom-Json;$t=$TicketText|ConvertFrom-Json
  function Hash([byte[]]$b){$sha=[Security.Cryptography.SHA256]::Create();try{return [BitConverter]::ToString($sha.ComputeHash($b)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}
  function Guard {
   if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'-or[guid](Get-CimInstance Win32_ComputerSystemProduct).UUID-ne[guid]'87d4c43a-4299-460e-b973-b241f239d33f'){throw 'Alpha guest identity differs.'}
   $version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
   if($version.CurrentBuild-cne'26300'-or$version.UBR-ne9457-or(Get-FileHash -LiteralPath 'C:\ntfs2refs\alpha\native-shadow-alpha-20261026\ntfs2refs.exe' -Algorithm SHA256).Hash.ToLowerInvariant()-cne$PublicPin){throw 'Frozen alpha engine/build differs.'}
   if(@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-or
    @(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-bind)?|lab-.+)\.exe\z'}).Count){throw 'Active/unknown public or lab process: read-only collection refused without retry.'}
   foreach($binding in @($r.pair.source,$r.journal.disk)){
    $disk=Get-Disk -Number $binding.disk_number;$part=Get-Partition -DiskNumber $binding.disk_number -PartitionNumber $binding.identity.partition_number
    if($disk.IsBoot-or$disk.IsSystem-or[guid]$disk.Guid-ne[guid]$binding.identity.disk_guid-or[guid]$part.Guid-ne[guid]$binding.identity.partition_guid-or
     $disk.Size-ne$binding.identity.disk_bytes-or$part.Offset-ne$binding.identity.partition_offset-or$part.Size-ne$binding.identity.partition_bytes-or
     $disk.LogicalSectorSize-ne512-or$disk.PhysicalSectorSize-ne4096){throw 'Source/journal GPT identity or geometry differs.'}
   }
   $routes=@(Get-Partition -DriveLetter J);$journalDisk=Get-Disk -Number 2;$volume=Get-Volume -DriveLetter J
   if($routes.Count-ne1-or$routes[0].DiskNumber-ne2-or$routes[0].PartitionNumber-ne$r.journal.disk.identity.partition_number-or
    $journalDisk.IsOffline-or$journalDisk.IsReadOnly-or
    [guid]$routes[0].Guid-ne[guid]$r.journal.disk.identity.partition_guid-or$volume.FileSystem-cne'NTFS'-or$volume.FileSystemLabel-cne'n2r-alpha-journal'-or
    [string]$volume.Path-cne('\\?\Volume{'+$r.journal.disk.volume_guid+'}\')){throw 'J: is not the enrolled journal partition.'}
  }
  Guard
  $item=Get-Item -LiteralPath $JournalPath -Force
  if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-ne$t.journal_length){throw 'Exact bounded ordinary journal required.'}
  $parent=$item.Directory;while($parent){if($parent.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Journal reparse ancestry refused.'};$parent=$parent.Parent}
  $file=[IO.File]::Open($JournalPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try{
   if($file.Length-ne$t.journal_length){throw 'Opened journal length differs.'}
   $prefix=[byte[]]::new(8192);$at=0;while($at-lt$prefix.Length){$n=$file.Read($prefix,$at,$prefix.Length-$at);if($n-le0){throw 'Incomplete journal prefix.'};$at+=$n}
   $expected=[Convert]::FromBase64String($CanonicalBase64)
   for($i=0;$i-lt4096;$i++){if($prefix[$i]-ne$expected[$i]){throw 'Partial, foreign or noncanonical completed marker; no repair is permitted.'}}
   $sha=[Security.Cryptography.SHA256]::Create();$buffer=[byte[]]::new(1MB);$remaining=[long]$t.immutable_length;$checked=0L;$header=[byte[]]::new(128)
   try{
    while($remaining-gt0){$wanted=[int][Math]::Min($remaining,$buffer.Length);$n=$file.Read($buffer,0,$wanted);if($n-le0-or$n-gt$wanted){throw 'Incomplete immutable journal read.'}
     if($checked-lt128){[Array]::Copy($buffer,0,$header,[int]$checked,[int][Math]::Min($n,128-$checked))}
     $null=$sha.TransformBlock($buffer,0,$n,$buffer,0);$checked+=$n;$remaining-=$n}
    $null=$sha.TransformFinalBlock([byte[]]::new(0),0,0);$bodyHash=[BitConverter]::ToString($sha.Hash).Replace('-','').ToLowerInvariant()
   }finally{$sha.Dispose()}
   if($bodyHash-cne$t.immutable_sha256-or$file.ReadByte()-ne-1-or$file.Length-ne$t.journal_length){throw 'Immutable body hash or exact journal length changed.'}
   # The prepared header starts at8192; the first8192 are mutable lifecycle data.
   if([Text.Encoding]::ASCII.GetString($header,0,8)-cne'N2RPREP1'-or[BitConverter]::ToUInt32($header,8)-ne1-or
    [BitConverter]::ToUInt64($header,32)-ne[System.UInt64]$t.journal_length-or[BitConverter]::ToUInt32($header,16)-ne$PatchCount-or
    [BitConverter]::ToUInt64($header,24)-ne[System.UInt64]$ChangedBytes-or[BitConverter]::ToUInt32($header,20)-ne0){throw 'Prepared header magic/version/count/length differs.'}
   for($i=72;$i-lt96;$i++){if($header[$i]-ne0){throw 'Prepared header reserved bytes differ.'}}
   $sha=[Security.Cryptography.SHA256]::Create();try{$headerDigest=$sha.ComputeHash($header,0,96)}finally{$sha.Dispose()}
   for($i=0;$i-lt32;$i++){if($header[96+$i]-ne$headerDigest[$i]){throw 'Prepared header checksum differs.'}}
   $null=$file.Seek(0,[IO.SeekOrigin]::Begin);$again=[byte[]]::new(8192);$at=0
   while($at-lt8192){$n=$file.Read($again,$at,8192-$at);if($n-le0){throw 'Prefix reread truncated.'};$at+=$n}
   if([Convert]::ToBase64String($again)-cne[Convert]::ToBase64String($prefix)-or$file.Length-ne$t.journal_length){throw 'Mutable prefix/length changed during observation.'}
   Guard
   $marker=[byte[]]::new(4096);[Array]::Copy($prefix,0,$marker,0,4096)
   [pscustomobject]@{prefix_base64=[Convert]::ToBase64String($prefix);prefix_sha256=(Hash $prefix);marker_sha256=(Hash $marker);
    immutable_sha256=$bodyHash;immutable_bytes_read=$checked;journal_length=$file.Length;prepared_header_base64=[Convert]::ToBase64String($header);
    prepared_header_journal_length=[BitConverter]::ToUInt64($header,32);marker_exact=$true;prefix_unchanged=$true;readonly_file_access=$true;
    native_file_id_verified=$false;external_unique_id_verified=$false;current_target_image_verified=$false;replay_authority_granted=$false;observed_utc=[DateTime]::UtcNow.ToString('o')}
  }finally{$file.Dispose()}
 }
 Assert-Branch;$prefixBytes=[Convert]::FromBase64String($observed.prefix_base64)
 Need ($prefixBytes.Length-eq8192-and(Hash-Bytes $prefixBytes)-ceq$observed.prefix_sha256-and$observed.marker_sha256-ceq(Hash-Bytes $canonical)-and
  $observed.immutable_sha256-ceq$ticket.immutable_sha256-and$observed.immutable_bytes_read-eq$ticket.immutable_length-and$observed.journal_length-eq$ticket.journal_length) 'Returned marker/body evidence differs.'
 for($i=0;$i-lt4096;$i++){Need ($prefixBytes[$i]-eq$canonical[$i]) 'Returned canonical marker bytes differ.'}
 Save-Bytes (Join-Path $outputRoot 'journal-prefix.bin') $prefixBytes
 Save-Record 'result.json' @{schema_version=1;kind='native-shadow-alpha-journal-marker-observation';success=$true;case=$Case;case_id=$CaseId;vm_id=$vmId.ToString('D');preserved_checkpoint=$preserved.checkpoint_id;
  input_pins=$inputPins.ToArray();request_sha256=$requestPin;ticket_sha256=$ticketPin;journal_path=$journalPath;marker_magic=$magic;marker_version=$code;marker_target_sha256=$targetHash;
  prefix_file='journal-prefix.bin';prefix_bytes=8192;prefix_sha256=$observed.prefix_sha256;marker_sha256=$observed.marker_sha256;observation=$observed;
  scope='exact journal marker and immutable journal body only';source_or_target_raw_image_claimed=$false;journal_flush_performed=$false;recovery_or_write_authority_granted=$false;new_native_conversion_qualified=$false}
 Write-Host ('Read-only marker/body evidence saved: '+$outputRoot)
}catch{
 if($outputRoot){Save-Record 'failed-preserved.json' @{phase=$phase;error=$_.Exception.ToString();retry_attempted=$false;journal_writes=0;disk_attribute_changes=0;new_native_qualification=$false}}
 throw
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue};foreach($lease in $leases){$lease.Dispose()}}
