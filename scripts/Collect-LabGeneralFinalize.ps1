<# Read-only collection of an irreversible general ReFS handoff task. A
   missing/failed observer never reopens the old NTFS rollback path. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$FinalizeDispatchDirectory)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$directory=Assert-LabPath $FinalizeDispatchDirectory $cfg.Root
$start=Get-Content -LiteralPath (Join-Path $directory 'started.json') -Raw|ConvertFrom-Json
$dispatch=Get-Content -LiteralPath (Join-Path $directory 'dispatch.json') -Raw|ConvertFrom-Json
if($start.kind-cne'general-tree-finalize-dispatch'-or$start.stepId-cnotmatch'\A[0-9a-f]{32}\z'-or$start.runId-cnotmatch'\A[0-9a-f]{32}\z'-or$start.experimentId-cnotmatch'\A[0-9a-f]{32}\z'-or$dispatch.taskName-cne('N2R-GeneralFinalize-'+$start.stepId)-or$dispatch.guestOutput-cne('C:\ntfs2refs\general-replay\'+$start.runId+'\artifacts\finalize-'+$start.stepId+'.json')-or$vm.State-ne'Running'-or[guid]$vm.ParentSnapshotId-ne[guid]$start.parentCheckpointId){throw 'General finalization task, VM branch or output differs.'}
if(Test-Path -LiteralPath (Join-Path $directory 'collected.json')){throw 'General finalization already collected; preserve earlier observation.'}
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
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
  $filesystem=$null
  if(-not$source.IsOffline){try{$volume=Get-Partition -DiskNumber 1 -PartitionNumber 2|Get-Volume;$filesystem=[string]$volume.FileSystem}catch{$filesystem=$null}}
  [pscustomobject]@{terminal=$true;taskState=[string]$task.State;lastTaskResult=$info.LastTaskResult;reportSha256=$reportSha;journalMarker=$marker;handoffSectorZero=$handoffSectorZero;sourceOffline=[bool]$source.IsOffline;sourceReadOnly=[bool]$source.IsReadOnly;sourceFileSystem=$filesystem;shadowOffline=[bool]$shadow.IsOffline;shadowReadOnly=[bool]$shadow.IsReadOnly}
 }
 if(-not$observed.terminal){[pscustomobject]@{status='guest-general-finalizer-still-running';taskName=$dispatch.taskName;taskState=$observed.taskState};return}
 $report=$null
 if($observed.reportSha256){Copy-Item -LiteralPath $dispatch.guestOutput -Destination (Join-Path $directory 'guest-finalize.json') -FromSession $session;$actual=(Get-FileHash -LiteralPath (Join-Path $directory 'guest-finalize.json')).Hash.ToLowerInvariant();if($actual-cne$observed.reportSha256){throw 'Guest finalizer report changed during export.'};$report=Get-Content -LiteralPath (Join-Path $directory 'guest-finalize.json') -Raw|ConvertFrom-Json}
 $success=$observed.lastTaskResult-eq0 -and$report -and$report.kind-ceq'disposable-general-conversion' -and$report.mode-ceq'finalize' -and$report.success -and$report.rollback_closed -and$report.result.success -and$report.result.rollback_closed -and$report.result.native -and$observed.journalMarker-ceq'N2RHND01' -and-not$observed.sourceOffline -and-not$observed.sourceReadOnly -and$observed.sourceFileSystem-ceq'ReFS' -and$observed.shadowOffline -and$observed.shadowReadOnly
 $rollbackClosed=(-not$observed.handoffSectorZero)-or(-not$observed.sourceOffline)-or($report-and$report.rollback_closed)
 $result=[ordered]@{schemaVersion=1;kind='general-tree-finalize-observation';stepId=$start.stepId;runId=$start.runId;taskName=$dispatch.taskName;terminal=$true;taskState=$observed.taskState;lastTaskResult=$observed.lastTaskResult;reportSha256=$observed.reportSha256;journalMarker=$observed.journalMarker;handoffSectorZero=$observed.handoffSectorZero;rollbackClosed=[bool]$rollbackClosed;sourceOffline=$observed.sourceOffline;sourceReadOnly=$observed.sourceReadOnly;sourceFileSystem=$observed.sourceFileSystem;shadowOffline=$observed.shadowOffline;shadowReadOnly=$observed.shadowReadOnly;nativeFinishSucceeded=[bool]$success;productionConversionQualified=$false;capturedUtc=[DateTime]::UtcNow.ToString('o')}
 $path=Join-Path $directory 'collected.json';$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 12));$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 [pscustomobject]$result
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
