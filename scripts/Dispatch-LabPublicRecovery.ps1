<# Dispatch one public CLI recovery operation after a collected controlled
   interruption. No disk-state transitions, restores, restarts or UAC. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$InterruptedDirectory,
 [Parameter(Mandatory)][ValidateSet('Resume','Rollback','RollbackWithoutShadow','Finalize','FinalizeAfterMarker')][string]$Operation,
 [Parameter(Mandatory)][string]$BinaryPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BinarySha256,
 [string]$PreviousRecoveryDirectory)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot;Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$origin=Assert-LabPath $InterruptedDirectory $cfg.Root
$original=Get-Content -LiteralPath (Join-Path $origin 'dispatch.json') -Raw|ConvertFrom-Json
$terminal=Get-Content -LiteralPath (Join-Path $origin 'collected.json') -Raw|ConvertFrom-Json
if($original.kind-cne'certificate-backed-conversion-dispatch'-or$original.runId-cnotmatch'\A[0-9a-f]{32}\z'-or$original.taskName-cne('N2R-AdmittedConvert-'+$original.runId)-or$original.guestOutput-cne('C:\ntfs2refs\conversions\'+$original.runId)-or$terminal.kind-cne'certificate-backed-conversion-observation'-or$terminal.runId-cne$original.runId-or$terminal.exitCode-ne86-or$terminal.success-or-not$terminal.sourceOffline-or$terminal.sourceReadOnly-or-not$terminal.shadowOffline-or-not$terminal.shadowReadOnly-or$vm.State-ne'Running'-or[guid]$vm.Id-ne[guid]$original.vmId-or[guid]$vm.ParentSnapshotId-ne[guid]$original.checkpointId){throw 'Collected controlled interruption and exact owned VM branch required.'}
function Pinned-Artifact([string]$Name,[long]$Limit){
 $pins=@($terminal.files|Where-Object {$_.name-ceq$Name});if($pins.Count-ne1){throw ('Original pin absent/duplicate: '+$Name)}
 $path=Join-Path $origin $Name;$file=Get-Item -LiteralPath $path -Force
 if($file.PSIsContainer-or($file.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$file.Length-gt$Limit-or$file.Length-ne$pins[0].length-or(Get-FileHash $path).Hash.ToLowerInvariant()-cne$pins[0].sha256){throw ('Original artifact differs: '+$Name)}
 [pscustomobject]@{path=$path;sha256=$pins[0].sha256}
}
$requestPin=Pinned-Artifact 'request.json' 131072;$ticketPin=Pinned-Artifact 'ticket.json' 65536
$expectedPin=Pinned-Artifact 'expectation.json' 16MB;$locationPin=Pinned-Artifact 'journal-location.json' 16384
$interruptionPin=Pinned-Artifact 'interruption-intent.json' 16384
$request=Get-Content $requestPin.path -Raw|ConvertFrom-Json;$ticket=Get-Content $ticketPin.path -Raw|ConvertFrom-Json
$location=Get-Content $locationPin.path -Raw|ConvertFrom-Json
$withoutShadow=$Operation-ceq'RollbackWithoutShadow'
$expectedLabel=$null
if($withoutShadow){
 if($request.comparison.source_sha256-cnotmatch'\A[0-9a-f]{64}\z'-or$ticket.immutable_sha256-cnotmatch'\A[0-9a-f]{64}\z'-or$request.PSObject.Properties.Name-notcontains'expected_source_label'-or-not$request.expected_source_label-or$request.expected_source_label.utf16.Count-gt32-or@($request.expected_source_label.utf16|Where-Object {$_-lt0-or$_-gt65535-or$_-eq0}).Count){throw 'Shadowless rollback qualification requires pinned original source bytes, immutable journal and captured UTF-16 source label.'}
 $expectedLabel=@($request.expected_source_label.utf16)
}
$journal='\\?\Volume{'+$request.journal.disk.volume_guid.Trim('{}')+'}\ntfs2refs-shadow\'+$request.experiment_id+'\reconstruction.journal'
if($request.experiment_id-cne$original.runId-or$request.expected_tree_sha256-cne$expectedPin.sha256-or-not[string]::Equals([string]$location.path,$journal,[StringComparison]::OrdinalIgnoreCase)-or$request.pair.source.disk_number-ne1-or$request.pair.shadow.disk_number-ne3-or$request.journal.disk.disk_number-ne2-or[guid]$request.pair.source.identity.disk_guid-ne[guid]'a01574d5-2a5c-4136-958a-dcf0d0e0f7aa'-or[guid]$request.pair.shadow.identity.disk_guid-ne[guid]'49dbc2d2-4120-4fbf-911d-0f8d58153598'-or[guid]$request.journal.disk.identity.disk_guid-ne[guid]'04d5194b-f5db-43da-9b02-ed7a54325d56'){throw 'Recovery plan, expectation or actual journal location differs.'}
$prior=$null
if($Operation-in@('Finalize','FinalizeAfterMarker')){
 if(-not$PreviousRecoveryDirectory){throw 'Finalize requires a successful collected public Resume.'}
 $priorDirectory=Assert-LabPath $PreviousRecoveryDirectory $cfg.Root
 $priorStart=Get-Content (Join-Path $priorDirectory 'dispatch.json') -Raw|ConvertFrom-Json
 $prior=Get-Content (Join-Path $priorDirectory 'collected.json') -Raw|ConvertFrom-Json
 if($priorStart.kind-cne'public-cli-recovery-dispatch'-or$priorStart.stepId-cnotmatch'\A[0-9a-f]{32}\z'-or$priorStart.taskName-cne('N2R-PublicRecovery-'+$priorStart.stepId)-or$priorStart.operation-cne'Resume'-or$priorStart.originRunId-cne$original.runId-or$priorStart.requestSha256-cne$requestPin.sha256-or$priorStart.ticketSha256-cne$ticketPin.sha256-or[guid]$priorStart.vmId-ne[guid]$vm.Id-or[guid]$priorStart.checkpointId-ne[guid]$vm.ParentSnapshotId-or$prior.kind-cne'public-cli-recovery-observation'-or$prior.stepId-cne$priorStart.stepId-or-not$prior.success-or$prior.exitCode-ne0-or$prior.operation-cne'Resume'-or-not$prior.sourceOffline-or$prior.sourceReadOnly-or-not$prior.shadowOffline-or-not$prior.shadowReadOnly){throw 'A successful excluded Resume on this original run is required.'}
}elseif($PreviousRecoveryDirectory){throw 'Previous recovery evidence is only accepted for finalization.'}
$binary=Get-Item -LiteralPath $BinaryPath -Force
if($binary.PSIsContainer-or($binary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$binary.Length-gt16MB-or(Get-FileHash $binary.FullName).Hash.ToLowerInvariant()-cne$BinarySha256){throw 'Pinned ordinary public CLI executable required.'}
$step=[guid]::NewGuid().ToString('N');$root='C:\ntfs2refs\public-recovery-inputs\'+$step;$result='C:\ntfs2refs\public-recovery\'+$step
$taskName='N2R-PublicRecovery-'+$step
$output=Assert-LabPath (Join-Path $cfg.Root ('public-recovery/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
New-Item -ItemType Directory -Path $output|Out-Null
function Save([string]$Name,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14));$file=[IO.File]::Open((Join-Path $output $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
$record=[ordered]@{schemaVersion=1;kind='public-cli-recovery-dispatch';stepId=$step;operation=$Operation;originRunId=$original.runId;originDirectory=$origin;previousRecoveryDirectory=$PreviousRecoveryDirectory;vmId=[string]$vm.Id;checkpointId=[string]$vm.ParentSnapshotId;taskName=$taskName;guestRoot=$root;guestOutput=$result;binarySha256=$BinarySha256;requestSha256=$requestPin.sha256;ticketSha256=$ticketPin.sha256;expectationSha256=$expectedPin.sha256;interruptionIntentSha256=$interruptionPin.sha256;journal=$journal;startedUtc=[DateTime]::UtcNow.ToString('o')}
if($withoutShadow){$record.withoutShadow=$true;$record.sourceSha256=$request.comparison.source_sha256;$record.immutableJournalSha256=$ticket.immutable_sha256;$record.expectedSourceLabelUtf16=$expectedLabel}
Save 'dispatch.json' $record
Copy-Item -LiteralPath $interruptionPin.path -Destination (Join-Path $output 'interruption-intent.json')
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop
 $priorTask=if($prior){$priorStart.taskName}else{$null}
 $preflight=Invoke-Command -Session $session -ArgumentList @($original.taskName,$original.guestOutput,$original.runId,$Operation,$priorTask,$journal,$requestPin.sha256,$ticketPin.sha256,$expectedPin.sha256,$interruptionPin.sha256,[long]$ticket.journal_length,$root,$result) -ScriptBlock {
  param($OriginalTaskName,$Artifacts,$OriginId,$Operation,$PriorTask,$Journal,$RequestSha,$TicketSha,$ExpectedSha,$InterruptionSha,$JournalLength,$Root,$Output)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'){throw 'Owned Windows guest required.'}
  $originalTask=Get-ScheduledTask -TaskName $OriginalTaskName;$info=Get-ScheduledTaskInfo -TaskName $OriginalTaskName
  if($originalTask.State-in@('Running','Queued')-or$info.LastRunTime.Year-lt2000-or$info.LastTaskResult-ne86){throw 'Original converter is live, unknown or not a completed controlled exit86.'}
  if(@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count-or(Get-Process -Name 'converter','ntfs2refs','ntfs2refs-recover','public-cli','qualifier' -ErrorAction SilentlyContinue)){throw 'Another converter or recovery may still be live.'}
  if($PriorTask){$prior=Get-ScheduledTask -TaskName $PriorTask;$pi=Get-ScheduledTaskInfo -TaskName $PriorTask;if($prior.State-in@('Running','Queued')-or$pi.LastTaskResult-ne0-or$pi.LastRunTime.Year-lt2000){throw 'Prior Resume did not finish successfully.'}}
  $withoutShadow=$Operation-ceq'RollbackWithoutShadow'
  $disks=@(Get-Disk)
  if($withoutShadow-and@($disks|Where-Object {$_.Number-eq3-or[guid]$_.Guid-eq[guid]'49dbc2d2-4120-4fbf-911d-0f8d58153598'}).Count){throw 'Shadowless rollback qualification requires the actual shadow disk to be absent; no detach is performed.'}
  $specs=@(@(1,'a01574d5-2a5c-4136-958a-dcf0d0e0f7aa','79eaccdf-38d3-4561-97cc-9276af5d223a',64GB,52GB,$true,$false),@(2,'04d5194b-f5db-43da-9b02-ed7a54325d56','7435ee94-c435-403f-a515-dec1ccd5094e',8GB,(8GB-32MB),$false,$false))
  if(-not$withoutShadow){$specs+=,@(3,'49dbc2d2-4120-4fbf-911d-0f8d58153598','e071a0c1-5f96-4327-85e8-da9b831e27d3',64GB,52GB,$true,$true)}
  foreach($spec in $specs){
   $disk=Get-Disk -Number $spec[0];$part=Get-Partition -DiskNumber $spec[0] -PartitionNumber 2
   if([guid]$disk.Guid-ne[guid]$spec[1]-or[guid]$part.Guid-ne[guid]$spec[2]-or$disk.Size-ne$spec[3]-or$part.Size-ne$spec[4]-or$part.Offset-ne16MB-or$disk.IsOffline-ne$spec[5]-or$disk.IsReadOnly-ne$spec[6]-or$disk.IsBoot-or$disk.IsSystem-or$part.IsBoot-or$part.IsSystem-or$disk.PartitionStyle-cne'GPT'){throw 'Enrolled disk identity, geometry or persistent exclusion differs.'}
  }
  foreach($entry in @(@('request.json',$RequestSha,131072),@('ticket.json',$TicketSha,65536),@('expectation.json',$ExpectedSha,16MB))){$path=Join-Path $Artifacts $entry[0];$file=Get-Item -LiteralPath $path -Force;if($file.PSIsContainer-or($file.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$file.Length-gt$entry[2]-or(Get-FileHash $path).Hash.ToLowerInvariant()-cne$entry[1]){throw 'Live guest recovery artifact differs from collected pin.'}}
  $intentPath=Join-Path $Artifacts 'interruption-intent.json';$intentFile=Get-Item -LiteralPath $intentPath -Force
  if($intentFile.PSIsContainer-or($intentFile.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$intentFile.Length-gt16384-or(Get-FileHash $intentPath).Hash.ToLowerInvariant()-cne$InterruptionSha){throw 'Ordinary bounded controlled-interruption intent with exact collected pin required.'}
  $intent=Get-Content $intentPath -Raw|ConvertFrom-Json
  if($intent.kind-cne'controlled-conversion-interruption-intent'-or$intent.expected_process_exit_code-ne86-or$intent.interrupt_after_writes-lt1-or$intent.interrupt_after_writes-gt4096-or$intent.ticket_sha256-cne$TicketSha-or$intent.handoff_authorized-or-not[string]::Equals([string]$intent.journal_path,$Journal,[StringComparison]::OrdinalIgnoreCase)){throw 'Controlled interruption intent differs.'}
  $journalFile=Get-Item -LiteralPath $Journal -Force
  if($journalFile.PSIsContainer-or($journalFile.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$journalFile.Length-ne$JournalLength){throw 'Actual journal file type/length differs.'}
  $file=[IO.File]::Open($Journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
  try{$marker=[byte[]]::new(4096);if($file.Read($marker,0,4096)-ne4096){throw 'Journal handoff sector is truncated.'};$zero=@($marker|Where-Object {$_-ne0}).Count-eq0;$magic=[Text.Encoding]::ASCII.GetString($marker,0,8)
   if($Operation-ceq'FinalizeAfterMarker'){if($zero-or$magic-cne'N2RHND01'){throw 'Completed ReFS handoff marker required; no marker will be rewritten.'}}
   elseif(-not$zero){throw 'Handoff is not clear; resume/rollback/new finalization is closed.'}
   $sha=[Security.Cryptography.SHA256]::Create();try{$markerSha=[BitConverter]::ToString($sha.ComputeHash($marker)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  }finally{$file.Dispose()}
  if((Test-Path -LiteralPath $Root)-or(Test-Path -LiteralPath $Output)){throw 'Fresh guest recovery input/output required.'}
  New-Item -ItemType Directory -Path $Root|Out-Null;$outputParent=Split-Path $Output -Parent;if(-not(Test-Path $outputParent)){New-Item -ItemType Directory -Path $outputParent|Out-Null}
  foreach($directory in @($Root,$outputParent)){$ancestor=$directory;while($ancestor){$item=Get-Item -LiteralPath $ancestor -Force;if(-not$item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary guest artifact ancestry required.'};$next=Split-Path $ancestor -Parent;if($next-ceq$ancestor){break};$ancestor=$next}}
  [pscustomobject]@{originalTaskExitCode=$info.LastTaskResult;controlledInterruptionCount=$intent.interrupt_after_writes;interruptionIntentSha256=(Get-FileHash $intentPath).Hash.ToLowerInvariant();journal=$Journal;journalLength=$JournalLength;handoffClear=$zero;handoffMagic=$magic;handoffSectorSha256=$markerSha;sourceOffline=$true;sourceReadOnly=$false;shadowPresent=-not$withoutShadow;shadowOffline=if($withoutShadow){$null}else{$true};shadowReadOnly=if($withoutShadow){$null}else{$true};checkedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'preflight.json' $preflight
 Copy-Item -LiteralPath $binary.FullName -Destination ($root+'\public-cli.exe') -ToSession $session
 foreach($item in @(@($requestPin.path,'request.json'),@($ticketPin.path,'ticket.json'),@($expectedPin.path,'expectation.json'))){Copy-Item -LiteralPath $item[0] -Destination ($root+'\'+$item[1]) -ToSession $session}
 Copy-Item -LiteralPath $binary.FullName -Destination (Join-Path $output 'public-cli.exe')
 $command=if($Operation-ceq'FinalizeAfterMarker'){'finalize'}elseif($withoutShadow){'rollback'}else{$Operation.ToLowerInvariant()}
 $arguments=$command+' --request "'+$root+'\request.json" --request-sha256 '+$requestPin.sha256+' --ticket "'+$root+'\ticket.json" --ticket-sha256 '+$ticketPin.sha256+' --journal "'+$journal+'" --output "'+$result+'"'
 if($Operation-in@('Finalize','FinalizeAfterMarker')){$arguments+=' --expectation "'+$root+'\expectation.json" --expectation-sha256 '+$expectedPin.sha256}
 if($Operation-ceq'FinalizeAfterMarker'){$arguments+=' --after-marker'}
 if($withoutShadow){$arguments+=' --without-shadow'}
 $dispatched=Invoke-Command -Session $session -ArgumentList @($root,$result,$taskName,$BinarySha256,$requestPin.sha256,$ticketPin.sha256,$expectedPin.sha256,$arguments,$withoutShadow) -ScriptBlock {
  param($Root,$Output,$TaskName,$BinarySha,$RequestSha,$TicketSha,$ExpectedSha,$Arguments,$WithoutShadow);$ErrorActionPreference='Stop'
  foreach($entry in @(@('public-cli.exe',$BinarySha),@('request.json',$RequestSha),@('ticket.json',$TicketSha),@('expectation.json',$ExpectedSha))){if((Get-FileHash ($Root+'\'+$entry[0])).Hash.ToLowerInvariant()-cne$entry[1]){throw 'Copied recovery executable/input pin differs.'}}
  if(@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count){throw 'Another lab operation started before dispatch.'}
  $source=Get-Disk -Number 1
  if(-not$source.IsOffline-or$source.IsReadOnly){throw 'Persistent source exclusion changed before dispatch.'}
  if($WithoutShadow){if(@(Get-Disk|Where-Object {$_.Number-eq3-or[guid]$_.Guid-eq[guid]'49dbc2d2-4120-4fbf-911d-0f8d58153598'}).Count){throw 'Shadow appeared before shadowless rollback dispatch.'}}
  else{$shadow=Get-Disk -Number 3;if(-not$shadow.IsOffline-or-not$shadow.IsReadOnly){throw 'Persistent shadow exclusion changed before dispatch.'}}
  if(Test-Path $Output){throw 'Guest recovery output already exists.'}
  $action=New-ScheduledTaskAction -Execute ($Root+'\public-cli.exe') -Argument $Arguments
  $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
  $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
  Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings|Out-Null;Start-ScheduledTask -TaskName $TaskName
  [pscustomobject]@{taskName=$TaskName;state=[string](Get-ScheduledTask -TaskName $TaskName).State;guestOutput=$Output;dispatchedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'task.json' $dispatched
 [pscustomobject]@{directory=$output;taskName=$taskName;guestOutput=$result;operation=$Operation;state=$dispatched.state}
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
