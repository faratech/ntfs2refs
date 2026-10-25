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
if($dispatch.kind-cne'public-cli-recovery-dispatch'-or$dispatch.stepId-cnotmatch'\A[0-9a-f]{32}\z'-or$dispatch.originRunId-cnotmatch'\A[0-9a-f]{32}\z'-or$dispatch.operation-notin@('Resume','Rollback','Finalize','FinalizeAfterMarker')-or$dispatch.taskName-cne('N2R-PublicRecovery-'+$dispatch.stepId)-or$dispatch.guestRoot-cne('C:\ntfs2refs\public-recovery-inputs\'+$dispatch.stepId)-or$dispatch.guestOutput-cne('C:\ntfs2refs\public-recovery\'+$dispatch.stepId)-or-not[string]::Equals([string]$dispatch.journal,$expectedJournal,[StringComparison]::OrdinalIgnoreCase)-or[guid]$dispatch.vmId-ne[guid]$vm.Id-or[guid]$dispatch.checkpointId-ne[guid]$vm.ParentSnapshotId-or$vm.State-ne'Running'){throw 'Public recovery task or owning branch differs.'}
if(Test-Path (Join-Path $directory 'collected.json')){throw 'Terminal recovery already collected.'}
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop
 $observed=Invoke-Command -Session $session -ArgumentList @($dispatch.taskName,$dispatch.guestOutput,$dispatch.journal) -ScriptBlock {
  param($TaskName,$Output,$Journal);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  $task=Get-ScheduledTask -TaskName $TaskName;$info=Get-ScheduledTaskInfo -TaskName $TaskName
  $names=@('request.json','ticket.json','expectation.json','intent.json','journal-identity.json','preflight-events.json','execution.json','execution-events.json','completion-events.json','completion.json','result.json','failed.json')
  $present=@($names|Where-Object {Test-Path -LiteralPath (Join-Path $Output $_)})
  if($task.State-in@('Running','Queued')-or$info.LastRunTime.Year-lt2000){return [pscustomobject]@{terminal=$false;state=[string]$task.State;artifacts=$present}}
  $files=@(foreach($name in $present){$path=Join-Path $Output $name;$file=Get-Item -LiteralPath $path -Force;if($file.PSIsContainer-or($file.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$file.Length-gt64MB){throw 'Recovery artifact is not bounded ordinary output.'};[pscustomobject]@{name=$name;length=$file.Length;sha256=(Get-FileHash $path).Hash.ToLowerInvariant()}})
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3;$journalDisk=Get-Disk -Number 2
  if([guid]$source.Guid-ne[guid]'a01574d5-2a5c-4136-958a-dcf0d0e0f7aa'-or[guid]$shadow.Guid-ne[guid]'49dbc2d2-4120-4fbf-911d-0f8d58153598'-or[guid]$journalDisk.Guid-ne[guid]'04d5194b-f5db-43da-9b02-ed7a54325d56'){throw 'Observed device identities differ.'}
  $marker=[byte[]]::new(4096);$file=[IO.File]::Open($Journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
  try{if($file.Read($marker,0,4096)-ne4096){throw 'Journal marker sector truncated.'}}finally{$file.Dispose()}
  $sha=[Security.Cryptography.SHA256]::Create();try{$markerSha=[BitConverter]::ToString($sha.ComputeHash($marker)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  [pscustomobject]@{terminal=$true;state=[string]$task.State;exitCode=$info.LastTaskResult;files=$files;
   sourceOffline=[bool]$source.IsOffline;sourceReadOnly=[bool]$source.IsReadOnly;shadowOffline=[bool]$shadow.IsOffline;shadowReadOnly=[bool]$shadow.IsReadOnly;
   sourceFileSystem=if(-not$source.IsOffline){(Get-Partition -DiskNumber 1 -PartitionNumber 2|Get-Volume).FileSystem}else{$null};
   handoffClear=@($marker|Where-Object {$_-ne0}).Count-eq0;handoffMagic=[Text.Encoding]::ASCII.GetString($marker,0,8);handoffSectorSha256=$markerSha}
 }
 if(-not$observed.terminal){[pscustomobject]@{status='public-recovery-still-running';taskName=$dispatch.taskName;state=$observed.state;artifacts=$observed.artifacts};return}
 foreach($file in $observed.files){$destination=Join-Path $directory $file.name
  if(-not(Test-Path $destination)){Copy-Item -LiteralPath (Join-Path $dispatch.guestOutput $file.name) -Destination $destination -FromSession $session}
  if((Get-Item $destination).Length-ne$file.length-or(Get-FileHash $destination).Hash.ToLowerInvariant()-cne$file.sha256){throw 'Recovery artifact changed or existing export differs.'}
 }
 $result=$null;$failure=$null;$parseError=$null
 try{if(Test-Path (Join-Path $directory 'result.json')){$result=Get-Content (Join-Path $directory 'result.json') -Raw|ConvertFrom-Json};if(Test-Path (Join-Path $directory 'failed.json')){$failure=Get-Content (Join-Path $directory 'failed.json') -Raw|ConvertFrom-Json}}catch{$parseError=$_.Exception.ToString()}
 $pinsMatched=$true
 foreach($entry in @(@('request.json',$dispatch.requestSha256),@('ticket.json',$dispatch.ticketSha256))){$pin=@($observed.files|Where-Object {$_.name-ceq$entry[0]});if($pin.Count-ne1-or$pin[0].sha256-cne$entry[1]){$pinsMatched=$false}}
 if($dispatch.operation-in@('Finalize','FinalizeAfterMarker')){$pin=@($observed.files|Where-Object {$_.name-ceq'expectation.json'});if($pin.Count-ne1-or$pin[0].sha256-cne$dispatch.expectationSha256){$pinsMatched=$false}}
 $expectedOperation=switch($dispatch.operation){'Resume'{'resume'};'Rollback'{'rollback'};'Finalize'{'finalize'};'FinalizeAfterMarker'{'finalize_after_marker'}}
 $stateMatched=switch($dispatch.operation){
  'Resume'{$observed.sourceOffline-and-not$observed.sourceReadOnly-and$observed.handoffClear}
  'Rollback'{-not$observed.sourceOffline-and-not$observed.sourceReadOnly-and$observed.sourceFileSystem-ceq'NTFS'-and$observed.handoffMagic-ceq'N2RABT01'}
  default{-not$observed.sourceOffline-and-not$observed.sourceReadOnly-and$observed.sourceFileSystem-ceq'ReFS'-and$observed.handoffMagic-ceq'N2RHND01'}
 }
 $success=$false
 try{$success=$observed.exitCode-eq0-and$result-and-not$failure-and-not$parseError-and$result.kind-ceq'general-recovery'-and$result.success-and$result.operation-ceq$expectedOperation-and$pinsMatched-and$stateMatched-and$observed.shadowOffline-and$observed.shadowReadOnly}catch{$parseError=$_.Exception.ToString()}
 $record=[ordered]@{schemaVersion=1;kind='public-cli-recovery-observation';stepId=$dispatch.stepId;originRunId=$dispatch.originRunId;operation=$dispatch.operation;taskName=$dispatch.taskName;exitCode=$observed.exitCode;success=[bool]$success;
  sourceOffline=$observed.sourceOffline;sourceReadOnly=$observed.sourceReadOnly;shadowOffline=$observed.shadowOffline;shadowReadOnly=$observed.shadowReadOnly;sourceFileSystem=$observed.sourceFileSystem;
  handoffClear=$observed.handoffClear;handoffMagic=$observed.handoffMagic;handoffSectorSha256=$observed.handoffSectorSha256;inputPinsMatched=$pinsMatched;failure=$failure;resultParseError=$parseError;files=$observed.files;capturedUtc=[DateTime]::UtcNow.ToString('o')}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 14));$file=[IO.File]::Open((Join-Path $directory 'collected.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 [pscustomobject]$record
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
