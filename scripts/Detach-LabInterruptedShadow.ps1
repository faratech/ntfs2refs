<# Detach only the enrolled guest shadow after a collected controlled exit86.
   Keeps the target offline/writable and preserves the journal/backing file.
   No checkpoint, restart, mount, payload write, privilege change or retry. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$InterruptedDirectory)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$origin=Assert-LabPath $InterruptedDirectory $cfg.Root
$original=Get-Content -LiteralPath (Join-Path $origin 'dispatch.json') -Raw|ConvertFrom-Json
$terminal=Get-Content -LiteralPath (Join-Path $origin 'collected.json') -Raw|ConvertFrom-Json
if($original.kind-cne'certificate-backed-conversion-dispatch'-or$original.runId-cnotmatch'\A[0-9a-f]{32}\z'-or$original.taskName-cne('N2R-AdmittedConvert-'+$original.runId)-or$original.guestOutput-cne('C:\ntfs2refs\conversions\'+$original.runId)-or$terminal.kind-cne'certificate-backed-conversion-observation'-or$terminal.runId-cne$original.runId-or$terminal.exitCode-ne86-or$terminal.success-or-not$terminal.sourceOffline-or$terminal.sourceReadOnly-or-not$terminal.shadowOffline-or-not$terminal.shadowReadOnly-or$vm.State-ne'Running'-or[guid]$vm.Id-ne[guid]$original.vmId-or[guid]$vm.ParentSnapshotId-ne[guid]$original.checkpointId){throw 'Collected controlled interruption on the exact current owned VM branch required.'}
function Pinned-Artifact([string]$Name,[long]$Limit){
 $pins=@($terminal.files|Where-Object {$_.name-ceq$Name});if($pins.Count-ne1){throw ('Collected pin absent/duplicate: '+$Name)}
 $path=Join-Path $origin $Name;$file=Get-Item -LiteralPath $path -Force
 if($file.PSIsContainer-or($file.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$file.Length-gt$Limit-or$file.Length-ne$pins[0].length-or(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$pins[0].sha256){throw ('Collected artifact differs: '+$Name)}
 [pscustomobject]@{path=$path;sha256=$pins[0].sha256;limit=$Limit}
}
$pins=@{};foreach($spec in @(@('request.json',128KB),@('ticket.json',64KB),@('journal-location.json',16KB),@('interruption-intent.json',16KB))){$pins[$spec[0]]=Pinned-Artifact $spec[0] $spec[1]}
$request=Get-Content -LiteralPath $pins['request.json'].path -Raw|ConvertFrom-Json
$ticket=Get-Content -LiteralPath $pins['ticket.json'].path -Raw|ConvertFrom-Json
$location=Get-Content -LiteralPath $pins['journal-location.json'].path -Raw|ConvertFrom-Json
$intent=Get-Content -LiteralPath $pins['interruption-intent.json'].path -Raw|ConvertFrom-Json
$journal='\\?\Volume{7435ee94-c435-403f-a515-dec1ccd5094e}\ntfs2refs-shadow\'+$original.runId+'\reconstruction.journal'
if($request.experiment_id-cne$original.runId-or$ticket.schema_version-ne1-or$ticket.binding.experiment_id-cne$original.runId-or$ticket.immutable_sha256-cnotmatch'\A[0-9a-f]{64}\z'-or$ticket.journal_length-lt8192-or$ticket.journal_length-gt768MB-or$ticket.immutable_length+8192-ne$ticket.journal_length-or-not[string]::Equals([string]$location.path,$journal,[StringComparison]::OrdinalIgnoreCase)-or$intent.kind-cne'controlled-conversion-interruption-intent'-or$intent.expected_process_exit_code-ne86-or$intent.interrupt_after_writes-lt1-or$intent.interrupt_after_writes-gt4096-or$intent.ticket_sha256-cne$pins['ticket.json'].sha256-or$intent.handoff_authorized-or-not[string]::Equals([string]$intent.journal_path,$journal,[StringComparison]::OrdinalIgnoreCase)){throw 'Pinned recovery request, ticket, journal location or controlled interruption differs.'}
foreach($spec in @(@($request.pair.source,1,'a01574d5-2a5c-4136-958a-dcf0d0e0f7aa','79eaccdf-38d3-4561-97cc-9276af5d223a',64GB,52GB),@($request.pair.shadow,3,'49dbc2d2-4120-4fbf-911d-0f8d58153598','e071a0c1-5f96-4327-85e8-da9b831e27d3',64GB,52GB),@($request.journal.disk,2,'04d5194b-f5db-43da-9b02-ed7a54325d56','7435ee94-c435-403f-a515-dec1ccd5094e',8GB,(8GB-32MB)))){
 $b=$spec[0];if($b.disk_number-ne$spec[1]-or[guid]$b.identity.disk_guid-ne[guid]$spec[2]-or[guid]$b.identity.partition_guid-ne[guid]$spec[3]-or$b.identity.disk_bytes-ne$spec[4]-or$b.identity.partition_bytes-ne$spec[5]-or$b.identity.partition_number-ne2-or$b.identity.partition_offset-ne16MB-or$b.identity.logical_sector_bytes-ne512-or$b.identity.physical_sector_bytes-ne4096){throw 'Pinned source/shadow/journal enrollment differs.'}
}
$helpers=@(@('NativeShadowDisk.cs','d8c54bfdf83fedbc821076dcde6f5e900ec208cc13bdddd1a9ea358e0dd9d2f1'),@('NativeMountBoundary.cs','b5e98bfca7809324a7300ea26effe4d427070b77f11c5c33e67f0153676fd15e'))
foreach($helper in $helpers){$path=Join-Path $workspace ('lab/guest/'+$helper[0]);$file=Get-Item -LiteralPath $path -Force;if($file.PSIsContainer-or($file.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$file.Length-gt128KB-or(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$helper[1]){throw 'Reviewed native detach helper differs.'}}
$step=[guid]::NewGuid().ToString('N');$guestRoot='C:\ntfs2refs\interrupted-shadow-detach\'+$step
$backing='J:\ntfs2refs-shadow\bc71d839927545bd863197ba200422dd\shadow.vhdx';$virtualId='cc064ce6-8a5d-4d58-9828-657f92214f34'
$output=Assert-LabPath (Join-Path $cfg.Root ('interrupted-shadow-detach/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
New-Item -ItemType Directory -Path $output|Out-Null
function Save([string]$Name,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 28));if($bytes.Length-gt2MB){throw 'Detach evidence exceeds bound.'};$file=[IO.File]::Open((Join-Path $output $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
$record=[ordered]@{schemaVersion=1;kind='interrupted-shadow-detach-intent';stepId=$step;originRunId=$original.runId;originDirectory=$origin;vmId=[string]$vm.Id;checkpointId=[string]$vm.ParentSnapshotId;originalTaskName=$original.taskName;guestRoot=$guestRoot;backingPath=$backing;creationIdentityQuery=14;virtualDiskId=$virtualId;journal=$journal;artifactPins=$pins;helpers=$helpers;sourceAttributeSettersAuthorized=$false;rawPayloadWritesAuthorized=$false;retryAuthorized=$false;startedUtc=[DateTime]::UtcNow.ToString('o')}
Save 'intent.json' $record
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null;$reply=$null
try{
 $session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop
 $preflight=Invoke-Command -Session $session -ArgumentList @($guestRoot,$original.taskName,$original.guestOutput,$journal,[long]$ticket.journal_length,$pins,$backing) -ScriptBlock {
  param($Root,$TaskName,$Artifacts,$Journal,$JournalLength,$Pins,$Backing)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  function Ordinary([string]$Path,[bool]$Directory){$item=Get-Item -LiteralPath $Path -Force;if($item.PSIsContainer-ne$Directory-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary evidence/backing ancestry required.'};$item}
  if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'-or-not[Environment]::Is64BitProcess){throw 'Owned x64 Windows guest required.'}
  $task=Get-ScheduledTask -TaskName $TaskName;$info=Get-ScheduledTaskInfo -TaskName $TaskName
  if($task.State-in@('Running','Queued')-or$info.LastRunTime.Year-lt2000-or$info.LastTaskResult-ne86-or@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count-or(Get-Process -Name 'converter','ntfs2refs','ntfs2refs-recover','public-cli','qualifier' -ErrorAction SilentlyContinue)){throw 'Original conversion is not a known stopped exit86 or another worker remains live.'}
  $disks=@(Get-Disk);if((@($disks.Number|Sort-Object)-join',')-cne'0,1,2,3'){throw 'Exactly enrolled four-disk inventory required.'}
  foreach($spec in @(@(1,'a01574d5-2a5c-4136-958a-dcf0d0e0f7aa','79eaccdf-38d3-4561-97cc-9276af5d223a',64GB,52GB,$true,$false),@(3,'49dbc2d2-4120-4fbf-911d-0f8d58153598','e071a0c1-5f96-4327-85e8-da9b831e27d3',64GB,52GB,$true,$true),@(2,'04d5194b-f5db-43da-9b02-ed7a54325d56','7435ee94-c435-403f-a515-dec1ccd5094e',8GB,(8GB-32MB),$false,$false))){$d=Get-Disk -Number $spec[0];$p=Get-Partition -DiskNumber $spec[0] -PartitionNumber 2;if([guid]$d.Guid-ne[guid]$spec[1]-or[guid]$p.Guid-ne[guid]$spec[2]-or$d.Size-ne$spec[3]-or$p.Size-ne$spec[4]-or$p.Offset-ne16MB-or$d.IsOffline-ne$spec[5]-or$d.IsReadOnly-ne$spec[6]-or$d.IsBoot-or$d.IsSystem-or$p.IsBoot-or$p.IsSystem-or$d.PartitionStyle-cne'GPT'-or$d.LogicalSectorSize-ne512-or$d.PhysicalSectorSize-ne4096){throw 'Actual enrolled identity, geometry or exclusion differs.'}}
  if((Get-Partition -DriveLetter C).DiskNumber-ne0-or(Get-Partition -DriveLetter J).DiskNumber-ne2-or(Get-Volume -DriveLetter J).FileSystem-cne'NTFS'){throw 'OS or external-journal route differs.'}
  foreach($name in $Pins.Keys){$p=Join-Path $Artifacts $name;$f=Ordinary $p $false;if($f.Length-gt$Pins[$name].limit-or(Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()-cne$Pins[$name].sha256){throw 'Actual guest interruption/recovery pin differs.'}}
  $jf=Ordinary $Journal $false;if($jf.Length-ne$JournalLength){throw 'Actual journal length differs.'}
  $stream=[IO.File]::Open($Journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try{$marker=[byte[]]::new(4096);if($stream.Read($marker,0,4096)-ne4096-or@($marker|Where-Object {$_-ne0}).Count){throw 'Journal handoff sector must be completely zero; progress sector is not reset.'}}finally{$stream.Dispose()}
  $f=Ordinary $Backing $false;if($f.Length-lt1-or$f.Length-gt6GB){throw 'Enrolled backing bound differs.'}
  $ancestor=Split-Path $Backing -Parent;while($ancestor){Ordinary $ancestor $true|Out-Null;$next=Split-Path $ancestor -Parent;if($next-ceq$ancestor){break};$ancestor=$next}
  if(Test-Path -LiteralPath $Root){throw 'Fresh guest detach evidence required.'}
  $parent=Split-Path $Root -Parent;if(-not(Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Path $parent|Out-Null}
  $ancestor=$parent;while($ancestor){Ordinary $ancestor $true|Out-Null;$next=Split-Path $ancestor -Parent;if($next-ceq$ancestor){break};$ancestor=$next}
  New-Item -ItemType Directory -Path $Root|Out-Null
  [pscustomobject]@{originalExitCode=$info.LastTaskResult;sourceOfflineWritable=$true;shadowOfflineReadOnly=$true;journalHandoffZero=$true;journalLength=$JournalLength;backingLength=$f.Length;backingLastWriteTimeUtc=$f.LastWriteTimeUtc;diskNumbers=@($disks.Number|Sort-Object);checkedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'preflight.json' $preflight
 foreach($helper in $helpers){Copy-Item -LiteralPath (Join-Path $workspace ('lab/guest/'+$helper[0])) -Destination ($guestRoot+'\'+$helper[0]) -ToSession $session}
 # Host intent and collected pins above are durable before the only native mutation.
 $reply=Invoke-Command -Session $session -ArgumentList @($guestRoot,$original.taskName,$original.guestOutput,$journal,[long]$ticket.journal_length,$pins,$helpers,$backing,$virtualId,$preflight.backingLength) -ScriptBlock {
  param($Root,$TaskName,$Artifacts,$Journal,$JournalLength,$Pins,$Helpers,$Backing,$VirtualId,$BackingLength)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$native=$null;$journalLease=$null
  $record=[ordered]@{schemaVersion=1;kind='interrupted-shadow-native-detach';status='started';stage='preflight';backingPath=$Backing;virtualDiskId=$VirtualId;creationIdentityQuery=14;sourceOfflineWritable=$false;shadowAbsent=$false;cleanupComplete=$false;operationCompletionKnown=$true;attributeSettersInvoked=$false;rawPayloadWritesIssued=$false;native=$null;error=$null;createdUtc=[DateTime]::UtcNow.ToString('o')}
  function SaveStage([string]$Name){$record.stage=$Name;if($native){$record.native=$native;$record.operationCompletionKnown=-not$native.OperationActive};$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 28));if($bytes.Length-gt2MB){throw 'Native detach evidence exceeds bound.'};$s=[IO.File]::Open(($Root+'\'+$Name+'.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$s.Write($bytes,0,$bytes.Length);$s.Flush($true)}finally{$s.Dispose()}}
  try{
   if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'){throw 'Owned Windows guest required.'}
   $task=Get-ScheduledTask -TaskName $TaskName;$info=Get-ScheduledTaskInfo -TaskName $TaskName
   if($task.State-in@('Running','Queued')-or$info.LastTaskResult-ne86-or$info.LastRunTime.Year-lt2000-or@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count-or(Get-Process -Name 'converter','ntfs2refs','ntfs2refs-recover','public-cli','qualifier' -ErrorAction SilentlyContinue)){throw 'Worker state changed before detach.'}
   foreach($name in $Pins.Keys){$p=Join-Path $Artifacts $name;$f=Get-Item -LiteralPath $p -Force;if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-gt$Pins[$name].limit-or(Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()-cne$Pins[$name].sha256){throw 'Guest recovery pin changed before detach.'}}
   foreach($helper in $Helpers){$p=Join-Path $Root $helper[0];$f=Get-Item -LiteralPath $p -Force;if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-gt128KB-or(Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()-cne$helper[1]){throw 'Copied native helper pin differs.'}}
   $backingBefore=Get-Item -LiteralPath $Backing -Force;if($backingBefore.PSIsContainer-or($backingBefore.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$backingBefore.Length-ne$BackingLength){throw 'Backing changed before detach.'}
   if((@(Get-Disk|Sort-Object Number|ForEach-Object {$_.Number})-join',')-cne'0,1,2,3'){throw 'Disk inventory changed before native binding.'}
   $jd=Get-Disk -Number 2;$jp=Get-Partition -DiskNumber 2 -PartitionNumber 2
   if([guid]$jd.Guid-ne[guid]'04d5194b-f5db-43da-9b02-ed7a54325d56'-or[guid]$jp.Guid-ne[guid]'7435ee94-c435-403f-a515-dec1ccd5094e'-or$jd.Size-ne8GB-or$jp.Offset-ne16MB-or$jp.Size-ne(8GB-32MB)-or$jd.IsOffline-or$jd.IsReadOnly-or(Get-Partition -DriveLetter J).DiskNumber-ne2){throw 'Actual external journal route changed before detach.'}
   $journalLease=[IO.File]::Open($Journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
   if($journalLease.Length-ne$JournalLength){throw 'Journal changed before detach.'};$marker=[byte[]]::new(4096);if($journalLease.Read($marker,0,4096)-ne4096-or@($marker|Where-Object {$_-ne0}).Count){throw 'Handoff is closed; detach refused.'}
   if(('Ntfs2Refs.NativeShadowDisk'-as[type])-or('Ntfs2Refs.NativeMountBoundary'-as[type])){throw 'Fresh session for pinned native helpers required.'}
   Add-Type -Path @((Join-Path $Root 'NativeShadowDisk.cs'),(Join-Path $Root 'NativeMountBoundary.cs'))
   $native=New-Object Ntfs2Refs.NativeMountBoundary($Backing,([guid]$VirtualId),([guid]'a01574d5-2a5c-4136-958a-dcf0d0e0f7aa'),([guid]'79eaccdf-38d3-4561-97cc-9276af5d223a'),([guid]'49dbc2d2-4120-4fbf-911d-0f8d58153598'),([guid]'e071a0c1-5f96-4327-85e8-da9b831e27d3'))
   SaveStage '01-bind-intent';$native.OpenAndBind();SaveStage '02-bound-offline'
   SaveStage '03-detach-intent';$native.DetachShadow();SaveStage '04-detach-returned'
   $remaining=@(Get-Disk);$native.ConfirmShadowAbsent([int[]]@($remaining.Number|Sort-Object));$record.shadowAbsent=$native.ShadowAbsent
   $source=Get-Disk -Number 1;$part=Get-Partition -DiskNumber 1 -PartitionNumber 2;$jd=Get-Disk -Number 2
   if([guid]$source.Guid-ne[guid]'a01574d5-2a5c-4136-958a-dcf0d0e0f7aa'-or[guid]$part.Guid-ne[guid]'79eaccdf-38d3-4561-97cc-9276af5d223a'-or-not$source.IsOffline-or$source.IsReadOnly-or[guid]$jd.Guid-ne[guid]'04d5194b-f5db-43da-9b02-ed7a54325d56'-or$jd.IsOffline-or$jd.IsReadOnly){throw 'Source exclusion or journal state changed after detach.'}
   $journalLease.Position=0;if($journalLease.Read($marker,0,4096)-ne4096-or@($marker|Where-Object {$_-ne0}).Count){throw 'Handoff changed across detach.'}
   $after=Get-Item -LiteralPath $Backing -Force;if($after.Length-ne$BackingLength-or($after.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Backing was not preserved.'}
   $record.sourceOfflineWritable=$true;$record.remainingDiskNumbers=@($remaining.Number|Sort-Object);$record.backingLength=$after.Length;$record.backingLastWriteTimeUtc=$after.LastWriteTimeUtc
   SaveStage '05-absence-proven'
  }catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString()}
  finally{
   if($native-and-not$native.OperationActive){try{$native.Close()}catch{$record.status='failed-preserved';$record.cleanupError=$_.Exception.ToString()}}
   if($native){$record.cleanupComplete=$native.CleanupComplete;$record.operationCompletionKnown=-not$native.OperationActive;$record.attributeSettersInvoked=@($native.Calls|Where-Object {$_.code-eq[Ntfs2Refs.NativeMountBoundary]::SetAttributesCode}).Count-gt0}
   if($journalLease){$journalLease.Dispose()}
   if(-not$record.error-and$native-and$native.DetachSucceeded-and$native.ShadowAbsent-and$native.CleanupComplete-and-not$native.OperationActive-and-not$native.ProtectAttempted-and-not$native.OnlineAttempted-and$record.sourceOfflineWritable){$record.status='shadow-detached-source-preserved'}
   $record.finishedUtc=[DateTime]::UtcNow.ToString('o');SaveStage '06-result'
  }
  [pscustomobject]$record
 }
 Save 'result.json' $reply
 if($reply.kind-cne'interrupted-shadow-native-detach'-or$reply.status-cne'shadow-detached-source-preserved'-or-not$reply.operationCompletionKnown-or-not$reply.cleanupComplete-or-not$reply.shadowAbsent-or-not$reply.sourceOfflineWritable-or$reply.attributeSettersInvoked-or$reply.rawPayloadWritesIssued){throw 'Native detach did not prove the required terminal state; no retry.'}
 [pscustomobject]@{directory=$output;status=$reply.status;sourceOfflineWritable=$reply.sourceOfflineWritable;shadowAbsent=$reply.shadowAbsent;backingPreserved=$true;guestEvidence=$guestRoot}
}catch{Save 'failed.json' ([ordered]@{kind='interrupted-shadow-detach-failure';error=$_.Exception.ToString();nativeResultAvailable=[bool]$reply;retryAttempted=$false;capturedUtc=[DateTime]::UtcNow.ToString('o')});throw}
finally{if($session-and($null-eq$reply-or$reply.operationCompletionKnown)){Remove-PSSession $session -ErrorAction SilentlyContinue}}
