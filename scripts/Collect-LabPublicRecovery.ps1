<# Read one public recovery task and export pinned terminal evidence. No retry,
   state transition or fallback operation is dispatched by this collector. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$DispatchDirectory)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot;Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$directory=Assert-LabPath $DispatchDirectory $cfg.Root
$dispatch=Get-Content (Join-Path $directory 'dispatch.json') -Raw|ConvertFrom-Json
$expectedJournal='\\?\Volume{7435ee94-c435-403f-a515-dec1ccd5094e}\ntfs2refs-shadow\'+$dispatch.originRunId+'\reconstruction.journal'
if($dispatch.kind-cne'public-cli-recovery-dispatch'-or$dispatch.stepId-cnotmatch'\A[0-9a-f]{32}\z'-or$dispatch.originRunId-cnotmatch'\A[0-9a-f]{32}\z'-or$dispatch.operation-notin@('Resume','Rollback','RollbackWithoutShadow','Finalize','FinalizeAfterMarker')-or$dispatch.taskName-cne('N2R-PublicRecovery-'+$dispatch.stepId)-or$dispatch.guestRoot-cne('C:\ntfs2refs\public-recovery-inputs\'+$dispatch.stepId)-or$dispatch.guestOutput-cne('C:\ntfs2refs\public-recovery\'+$dispatch.stepId)-or-not[string]::Equals([string]$dispatch.journal,$expectedJournal,[StringComparison]::OrdinalIgnoreCase)-or[guid]$dispatch.vmId-ne[guid]$vm.Id-or[guid]$dispatch.checkpointId-ne[guid]$vm.ParentSnapshotId-or$vm.State-ne'Running'){throw 'Public recovery task or owning branch differs.'}
$withoutShadow=$dispatch.operation-ceq'RollbackWithoutShadow'
$sourceSha=$null;$immutableSha=$null;$expectedLabel=$null
if($withoutShadow){
 if(-not$dispatch.withoutShadow-or$dispatch.sourceSha256-cnotmatch'\A[0-9a-f]{64}\z'-or$dispatch.immutableJournalSha256-cnotmatch'\A[0-9a-f]{64}\z'-or$dispatch.expectedSourceLabelUtf16.Count-gt32){throw 'Pinned shadowless rollback evidence required.'}
 $sourceSha=$dispatch.sourceSha256;$immutableSha=$dispatch.immutableJournalSha256;$expectedLabel=@($dispatch.expectedSourceLabelUtf16)
}
if(Test-Path (Join-Path $directory 'collected.json')){throw 'Terminal recovery already collected.'}
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop
 $observed=Invoke-Command -Session $session -ArgumentList @($dispatch.taskName,$dispatch.guestOutput,$dispatch.journal,$withoutShadow,$sourceSha,$immutableSha) -ScriptBlock {
  param($TaskName,$Output,$Journal,$WithoutShadow,$SourceSha,$ImmutableSha);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  function Test-ExpectedRollbackMarker([byte[]]$Marker,[string]$SourceHash,[string]$ImmutableHash){
   if($Marker.Length-ne4096-or$SourceHash-cnotmatch'\A[0-9a-f]{64}\z'-or$ImmutableHash-cnotmatch'\A[0-9a-f]{64}\z'){return $false}
   $expected=[byte[]]::new(4096);[Text.Encoding]::ASCII.GetBytes('N2RABT01').CopyTo($expected,0);$expected[8]=4
   for($i=0;$i-lt32;$i++){$expected[16+$i]=[Convert]::ToByte($ImmutableHash.Substring(2*$i,2),16);$expected[48+$i]=[Convert]::ToByte($SourceHash.Substring(2*$i,2),16)}
   $sha=[Security.Cryptography.SHA256]::Create();try{$sha.ComputeHash($expected,0,4064).CopyTo($expected,4064)}finally{$sha.Dispose()}
   [Convert]::ToBase64String($Marker)-ceq[Convert]::ToBase64String($expected)
  }
  $task=Get-ScheduledTask -TaskName $TaskName;$info=Get-ScheduledTaskInfo -TaskName $TaskName
  $names=@('request.json','ticket.json','expectation.json','intent.json','journal-identity.json','preflight-events.json','execution.json','execution-events.json','completion-events.json','completion.json','result.json','failed.json')
  $present=@($names|Where-Object {Test-Path -LiteralPath (Join-Path $Output $_)})
  if($task.State-in@('Running','Queued')-or$info.LastRunTime.Year-lt2000){return [pscustomobject]@{terminal=$false;state=[string]$task.State;artifacts=$present}}
  $files=@(foreach($name in $present){$path=Join-Path $Output $name;$file=Get-Item -LiteralPath $path -Force;if($file.PSIsContainer-or($file.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$file.Length-gt64MB){throw 'Recovery artifact is not bounded ordinary output.'};[pscustomobject]@{name=$name;length=$file.Length;sha256=(Get-FileHash $path).Hash.ToLowerInvariant()}})
  $source=Get-Disk -Number 1;$journalDisk=Get-Disk -Number 2
  $disks=@(Get-Disk);$shadows=@($disks|Where-Object {$_.Number-eq3-or[guid]$_.Guid-eq[guid]'49dbc2d2-4120-4fbf-911d-0f8d58153598'})
  if($WithoutShadow){if($shadows.Count){throw 'Shadowless recovery observer requires the actual shadow to remain absent.'};$shadow=$null}
  else{$shadow=Get-Disk -Number 3;if([guid]$shadow.Guid-ne[guid]'49dbc2d2-4120-4fbf-911d-0f8d58153598'){throw 'Observed shadow identity differs.'}}
  $part=Get-Partition -DiskNumber 1 -PartitionNumber 2;$journalPart=Get-Partition -DiskNumber 2 -PartitionNumber 2
  if([guid]$source.Guid-ne[guid]'a01574d5-2a5c-4136-958a-dcf0d0e0f7aa'-or[guid]$part.Guid-ne[guid]'79eaccdf-38d3-4561-97cc-9276af5d223a'-or$source.Size-ne64GB-or$part.Offset-ne16MB-or$part.Size-ne52GB-or[guid]$journalDisk.Guid-ne[guid]'04d5194b-f5db-43da-9b02-ed7a54325d56'-or[guid]$journalPart.Guid-ne[guid]'7435ee94-c435-403f-a515-dec1ccd5094e'-or$journalDisk.IsOffline-or$journalDisk.IsReadOnly){throw 'Observed source/journal identities or geometry differ.'}
  $marker=[byte[]]::new(4096);$file=[IO.File]::Open($Journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
  try{if($file.Read($marker,0,4096)-ne4096){throw 'Journal marker sector truncated.'}}finally{$file.Dispose()}
  $sha=[Security.Cryptography.SHA256]::Create();try{$markerSha=[BitConverter]::ToString($sha.ComputeHash($marker)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  $volume=if(-not$source.IsOffline){$part|Get-Volume}else{$null}
  [pscustomobject]@{terminal=$true;state=[string]$task.State;exitCode=$info.LastTaskResult;files=$files;
   sourceOffline=[bool]$source.IsOffline;sourceReadOnly=[bool]$source.IsReadOnly;shadowPresent=[bool]$shadow;shadowOffline=if($shadow){[bool]$shadow.IsOffline}else{$null};shadowReadOnly=if($shadow){[bool]$shadow.IsReadOnly}else{$null};
   sourceFileSystem=if($volume){[string]$volume.FileSystem}else{$null};sourceDriveLetter=[string]$part.DriveLetter;sourceLabel=if($volume){[string]$volume.FileSystemLabel}else{$null};sourceLabelUtf16=if($volume){@(([string]$volume.FileSystemLabel).ToCharArray()|ForEach-Object {[int]$_})}else{$null};
   rollbackMarkerExact=if($WithoutShadow){Test-ExpectedRollbackMarker $marker $SourceSha $ImmutableSha}else{$null};
   handoffClear=@($marker|Where-Object {$_-ne0}).Count-eq0;handoffMagic=[Text.Encoding]::ASCII.GetString($marker,0,8);handoffSectorSha256=$markerSha}
 }
 if(-not$observed.terminal){[pscustomobject]@{status='public-recovery-still-running';taskName=$dispatch.taskName;state=$observed.state;artifacts=$observed.artifacts};return}
 foreach($file in $observed.files){$destination=Join-Path $directory $file.name
  if(-not(Test-Path $destination)){Copy-Item -LiteralPath (Join-Path $dispatch.guestOutput $file.name) -Destination $destination -FromSession $session}
  if((Get-Item $destination).Length-ne$file.length-or(Get-FileHash $destination).Hash.ToLowerInvariant()-cne$file.sha256){throw 'Recovery artifact changed or existing export differs.'}
 }
 $result=$null;$failure=$null;$completion=$null;$execution=$null;$parseError=$null
 try{if(Test-Path (Join-Path $directory 'result.json')){$result=Get-Content (Join-Path $directory 'result.json') -Raw|ConvertFrom-Json};if(Test-Path (Join-Path $directory 'failed.json')){$failure=Get-Content (Join-Path $directory 'failed.json') -Raw|ConvertFrom-Json};if($withoutShadow){$completion=Get-Content (Join-Path $directory 'completion.json') -Raw|ConvertFrom-Json;$execution=Get-Content (Join-Path $directory 'execution.json') -Raw|ConvertFrom-Json}}catch{$parseError=$_.Exception.ToString()}
 $pinsMatched=$true
 foreach($entry in @(@('request.json',$dispatch.requestSha256),@('ticket.json',$dispatch.ticketSha256))){$pin=@($observed.files|Where-Object {$_.name-ceq$entry[0]});if($pin.Count-ne1-or$pin[0].sha256-cne$entry[1]){$pinsMatched=$false}}
 if($dispatch.operation-in@('Finalize','FinalizeAfterMarker')){$pin=@($observed.files|Where-Object {$_.name-ceq'expectation.json'});if($pin.Count-ne1-or$pin[0].sha256-cne$dispatch.expectationSha256){$pinsMatched=$false}}
 $expectedOperation=switch($dispatch.operation){'Resume'{'resume'};'Rollback'{'rollback'};'RollbackWithoutShadow'{'rollback_without_shadow'};'Finalize'{'finalize'};'FinalizeAfterMarker'{'finalize_after_marker'}}
 $stateMatched=switch($dispatch.operation){
  'Resume'{$observed.sourceOffline-and-not$observed.sourceReadOnly-and$observed.handoffClear}
  'Rollback'{-not$observed.sourceOffline-and-not$observed.sourceReadOnly-and$observed.sourceFileSystem-ceq'NTFS'-and$observed.handoffMagic-ceq'N2RABT01'}
  'RollbackWithoutShadow'{-not$observed.sourceOffline-and-not$observed.sourceReadOnly-and$observed.sourceFileSystem-ceq'NTFS'-and$observed.sourceDriveLetter-ceq'F'-and$observed.handoffMagic-ceq'N2RABT01'-and$observed.rollbackMarkerExact-and([string]::Join(',',@($observed.sourceLabelUtf16))-ceq[string]::Join(',',$expectedLabel))}
  default{-not$observed.sourceOffline-and-not$observed.sourceReadOnly-and$observed.sourceFileSystem-ceq'ReFS'-and$observed.handoffMagic-ceq'N2RHND01'}
 }
 $success=$false
 $shadowSafe=if($withoutShadow){-not$observed.shadowPresent}else{$observed.shadowPresent-and$observed.shadowOffline-and$observed.shadowReadOnly}
 $rollbackProof=$false
 try{
  if($withoutShadow){
   $request=Get-Content (Join-Path $directory 'request.json') -Raw|ConvertFrom-Json;$ticket=Get-Content (Join-Path $directory 'ticket.json') -Raw|ConvertFrom-Json
   $rollbackProof=$request.comparison.source_sha256-ceq$sourceSha-and$ticket.immutable_sha256-ceq$immutableSha-and([string]::Join(',',@($request.expected_source_label.utf16))-ceq[string]::Join(',',$expectedLabel))-and$execution.expected_target_sha256-ceq$sourceSha-and$execution.result.target_sha256-ceq$sourceSha-and-not$execution.shadow_available-and$completion.success-and$completion.replay_closed-and-not$completion.shadow_available-and$completion.mounted_filesystem-ceq'NTFS'-and$completion.marker.operation-ceq'ntfs-rollback-complete'-and$completion.marker.target_sha256-ceq$sourceSha-and$completion.marker.handoff_recorded-and$completion.marker.target_bytes_written-eq0-and$completion.marker.patches_written-eq0-and$result.shadow_access_required-ceq$false-and$result.ntfs_rollback_completed
  }
  $success=$observed.exitCode-eq0-and$result-and-not$failure-and-not$parseError-and$result.kind-ceq'general-recovery'-and$result.success-and$result.operation-ceq$expectedOperation-and$pinsMatched-and$stateMatched-and$shadowSafe-and(-not$withoutShadow-or$rollbackProof)
 }catch{$parseError=$_.Exception.ToString()}
 $record=[ordered]@{schemaVersion=1;kind='public-cli-recovery-observation';stepId=$dispatch.stepId;originRunId=$dispatch.originRunId;operation=$dispatch.operation;taskName=$dispatch.taskName;exitCode=$observed.exitCode;success=[bool]$success;
  sourceOffline=$observed.sourceOffline;sourceReadOnly=$observed.sourceReadOnly;shadowPresent=$observed.shadowPresent;shadowOffline=$observed.shadowOffline;shadowReadOnly=$observed.shadowReadOnly;sourceFileSystem=$observed.sourceFileSystem;sourceDriveLetter=$observed.sourceDriveLetter;sourceLabel=$observed.sourceLabel;sourceLabelUtf16=$observed.sourceLabelUtf16;rollbackMarkerExact=$observed.rollbackMarkerExact;shadowlessRollbackProof=[bool]$rollbackProof;
  handoffClear=$observed.handoffClear;handoffMagic=$observed.handoffMagic;handoffSectorSha256=$observed.handoffSectorSha256;inputPinsMatched=$pinsMatched;failure=$failure;resultParseError=$parseError;files=$observed.files;capturedUtc=[DateTime]::UtcNow.ToString('o')}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 14));$file=[IO.File]::Open((Join-Path $directory 'collected.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 [pscustomobject]$record
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
