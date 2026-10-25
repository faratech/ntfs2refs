<# Read-only observation of the restored original NTFS mount. Never replays
   the journal or changes disk attributes after online service begins. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$CompletionDispatchDirectory)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$directory=Assert-LabPath $CompletionDispatchDirectory $cfg.Root
$start=Get-Content -LiteralPath (Join-Path $directory 'started.json') -Raw|ConvertFrom-Json
$withoutShadow=($start.PSObject.Properties.Name -contains 'withoutShadow') -and [bool]$start.withoutShadow
$dispatch=Get-Content -LiteralPath (Join-Path $directory 'dispatch.json') -Raw|ConvertFrom-Json
if($start.kind-cne'general-ntfs-rollback-completion-dispatch'-or$start.stepId-cnotmatch'\A[0-9a-f]{32}\z'-or$start.runId-cnotmatch'\A[0-9a-f]{32}\z'-or$start.experimentId-cnotmatch'\A[0-9a-f]{32}\z'-or$dispatch.taskName-cne('N2R-GeneralRollbackOnline-'+$start.stepId)-or$dispatch.guestOutput-cne('C:\ntfs2refs\general-replay\'+$start.runId+'\artifacts\rollback-online-'+$start.stepId+'.json')-or$vm.State-ne'Running'-or[guid]$vm.ParentSnapshotId-ne[guid]$start.parentCheckpointId){throw 'NTFS completion task, VM branch or output differs.'}
if(Test-Path -LiteralPath (Join-Path $directory 'collected.json')){throw 'NTFS completion already collected; preserve earlier observation.'}
$parent=Assert-LabPath $start.parentDirectory $cfg.Root
$replayStart=Get-Content -LiteralPath (Join-Path $parent 'started.json') -Raw|ConvertFrom-Json
$replayDir=Assert-LabPath $replayStart.replayDirectory (Join-Path $workspace '.lab/development')
$requestPath=Join-Path $replayDir 'general-request.json'
if((Get-FileHash -LiteralPath $requestPath).Hash.ToLowerInvariant()-cne$replayStart.requestSha256){throw 'Old NTFS source request pin differs.'}
$request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
if($replayStart.kind-cne'general-tree-replay-dispatch'-or$replayStart.runId-cne$start.runId-or$request.experiment_id-cne$start.experimentId){throw 'Old NTFS completion parent request differs.'}
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $deadline=[DateTime]::UtcNow.AddSeconds(180)
 do{try{$session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop;break}catch{Start-Sleep -Seconds 2}}while([DateTime]::UtcNow-lt$deadline)
 if(-not$session){throw 'Guest session unavailable.'}
 $observed=Invoke-Command -Session $session -ArgumentList @($dispatch.taskName,$dispatch.guestOutput,$start.experimentId) -ScriptBlock {
  param($TaskName,$Output,$ExperimentId)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  $task=Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop;$info=Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
  if($task.State-in@('Running','Queued')-or$info.LastRunTime.Year-lt2000){return [pscustomobject]@{terminal=$false;taskState=[string]$task.State;lastTaskResult=$info.LastTaskResult}}
  $reportSha=$null;if(Test-Path -LiteralPath $Output -PathType Leaf){$reportSha=(Get-FileHash -LiteralPath $Output).Hash.ToLowerInvariant()}
  $journal='J:\ntfs2refs-shadow\'+$ExperimentId+'\reconstruction.journal'
  $marker=$null;$handoffSectorZero=$false
  if(Test-Path -LiteralPath $journal -PathType Leaf){$stream=[IO.File]::Open($journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite);try{$bytes=[byte[]]::new(4096);if($stream.Read($bytes,0,$bytes.Length)-eq$bytes.Length){$marker=[Text.Encoding]::ASCII.GetString($bytes,0,8);$handoffSectorZero=@($bytes|Where-Object {$_ -ne0}).Count-eq0}}finally{$stream.Dispose()}}
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3 -ErrorAction SilentlyContinue
  $filesystem=$null;if(-not$source.IsOffline){try{$volume=Get-Partition -DiskNumber 1 -PartitionNumber 2|Get-Volume;$filesystem=[string]$volume.FileSystem}catch{$filesystem=$null}}
  [pscustomobject]@{terminal=$true;taskState=[string]$task.State;lastTaskResult=$info.LastTaskResult;reportSha256=$reportSha;journalMarker=$marker;handoffSectorZero=$handoffSectorZero;sourceOffline=[bool]$source.IsOffline;sourceReadOnly=[bool]$source.IsReadOnly;sourceFileSystem=$filesystem;shadowPresent=[bool]$shadow;shadowOffline=[bool]($shadow-and$shadow.IsOffline);shadowReadOnly=[bool]($shadow-and$shadow.IsReadOnly)}
 }
 if(-not$observed.terminal){[pscustomobject]@{status='guest-ntfs-rollback-completion-still-running';taskName=$dispatch.taskName;taskState=$observed.taskState};return}
 $report=$null
 if($observed.reportSha256){Copy-Item -LiteralPath $dispatch.guestOutput -Destination (Join-Path $directory 'guest-rollback-online.json') -FromSession $session;$actual=(Get-FileHash -LiteralPath (Join-Path $directory 'guest-rollback-online.json')).Hash.ToLowerInvariant();if($actual-cne$observed.reportSha256){throw 'Guest NTFS completion report changed during export.'};$report=Get-Content -LiteralPath (Join-Path $directory 'guest-rollback-online.json') -Raw|ConvertFrom-Json}
 $afterMarker=($start.PSObject.Properties.Name -contains 'afterMarker') -and [bool]$start.afterMarker
 $markerProof=if($report){if($afterMarker){$report.completed_marker_proof -and$report.completed_marker_proof.kind-ceq'ntfs_rollback' -and$report.completed_marker_proof.target_sha256-ceq$request.comparison.source_sha256}else{$report.marker -and$report.marker.operation-ceq'ntfs-rollback-complete' -and$report.marker.target_sha256-ceq$request.comparison.source_sha256}}else{$false}
 $shadowSafe=(-not$observed.shadowPresent-and$withoutShadow)-or($observed.shadowPresent-and$observed.shadowOffline-and$observed.shadowReadOnly)
 $success=$observed.lastTaskResult-eq0 -and$report -and$report.success -and$report.replay_closed -and([bool]$report.shadow_available -eq (-not$withoutShadow)) -and$markerProof -and$report.mounted_filesystem-ceq'NTFS' -and$observed.journalMarker-ceq'N2RABT01' -and-not$observed.sourceOffline -and-not$observed.sourceReadOnly -and$observed.sourceFileSystem-ceq'NTFS' -and$shadowSafe
 $replayClosed=(-not$observed.handoffSectorZero)-or(-not$observed.sourceOffline)-or($report-and$report.replay_closed)
 $result=[ordered]@{schemaVersion=1;kind='general-ntfs-rollback-completion-observation';stepId=$start.stepId;runId=$start.runId;afterMarker=$afterMarker;withoutShadow=$withoutShadow;taskName=$dispatch.taskName;terminal=$true;taskState=$observed.taskState;lastTaskResult=$observed.lastTaskResult;reportSha256=$observed.reportSha256;journalMarker=$observed.journalMarker;handoffSectorZero=$observed.handoffSectorZero;replayClosed=[bool]$replayClosed;sourceOffline=$observed.sourceOffline;sourceReadOnly=$observed.sourceReadOnly;sourceFileSystem=$observed.sourceFileSystem;shadowPresent=$observed.shadowPresent;shadowOffline=$observed.shadowOffline;shadowReadOnly=$observed.shadowReadOnly;oldNtfsRestoredOnline=[bool]$success;productionConversionQualified=$false;capturedUtc=[DateTime]::UtcNow.ToString('o')}
 $path=Join-Path $directory 'collected.json';$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 12));$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 [pscustomobject]$result
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
