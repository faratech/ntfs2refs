<# Read only the result of a previously dispatched guest recovery task. Never
   starts, retries, rolls back or brings a disk online. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$DispatchDirectory)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$directory=Assert-LabPath $DispatchDirectory $cfg.Root
$start=Get-Content -LiteralPath (Join-Path $directory 'started.json') -Raw|ConvertFrom-Json
$dispatch=Get-Content -LiteralPath (Join-Path $directory 'dispatch.json') -Raw|ConvertFrom-Json
if($start.kind-cne'ordinary-tree-recovery-dispatch'-or$start.stepId-cnotmatch'\A[0-9a-f]{32}\z'-or$dispatch.taskName-cne('N2R-Recover-'+$start.stepId)-or$start.experimentId-cnotmatch'\A[0-9a-f]{32}\z'-or$vm.State-ne'Running'){throw 'Recovery dispatch or owning guest differs.'}
$conversionDirectory=Assert-LabPath $start.conversionDirectory $cfg.Root
$conversion=Get-Content -LiteralPath (Join-Path $conversionDirectory 'started.json') -Raw|ConvertFrom-Json
if($conversion.kind-cne'ordinary-tree-conversion'-or$conversion.runId-cnotmatch'\A[0-9a-f]{32}\z'-or$conversion.experimentId-cne$start.experimentId-or$dispatch.guestOutput-cne('C:\ntfs2refs\tree-conversion\'+$conversion.runId+'\recover-'+$start.stepId+'.json')){throw 'Recovery output path or conversion identity differs.'}
$shadowDirectory=Assert-LabPath $conversion.shadowDirectory $cfg.Root
$shadowHost=Get-Content -LiteralPath (Join-Path $shadowDirectory 'host-result.json') -Raw|ConvertFrom-Json
if([guid]$vm.ParentSnapshotId-ne[guid]$shadowHost.shadowCheckpointId){throw 'VM checkpoint differs from the recovery branch.'}
if(Test-Path -LiteralPath (Join-Path $directory 'collected.json')){throw 'Recovery result already collected; preserve earlier observation.'}
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $deadline=[DateTime]::UtcNow.AddSeconds(180)
 do{try{$session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop;break}catch{Start-Sleep -Seconds 2}}while([DateTime]::UtcNow-lt$deadline)
 if(-not$session){throw 'Guest session unavailable.'}
 $observed=Invoke-Command -Session $session -ArgumentList @($dispatch.taskName,$dispatch.guestOutput,$start.experimentId) -ScriptBlock {
  param($TaskName,$Output,$ExperimentId)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  $task=Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
  $info=Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
  if($task.State-in@('Running','Queued')-or$info.LastRunTime.Year-lt2000){return [pscustomobject]@{terminal=$false;taskState=[string]$task.State;lastTaskResult=$info.LastTaskResult;guestReportPresent=$false;guestReportSha256=$null;reportSucceeded=$false;resumeSucceeded=$false;finishSucceeded=$false;rollbackClosed=$false;marker=$null;sourceOffline=$null;sourceReadOnly=$null}}
  $journal='J:\ntfs2refs-shadow\'+$ExperimentId+'\reconstruction.journal'
  $stream=[IO.File]::Open($journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
  try{$marker=[byte[]]::new(8);if($stream.Read($marker,0,8)-ne8){throw 'Journal marker is truncated.'};$markerText=[Text.Encoding]::ASCII.GetString($marker)}finally{$stream.Dispose()}
  $source=Get-Disk -Number 1
  $report=if(Test-Path -LiteralPath $Output -PathType Leaf){Get-Content -LiteralPath $Output -Raw|ConvertFrom-Json}else{$null}
  $reportSha=if($report){(Get-FileHash -LiteralPath $Output).Hash.ToLowerInvariant()}else{$null}
  [pscustomobject]@{terminal=$true;taskState=[string]$task.State;lastTaskResult=$info.LastTaskResult;guestReportPresent=[bool]$report;guestReportSha256=$reportSha;reportSucceeded=$(if($report){[bool]$report.success}else{$false});resumeSucceeded=$(if($report){[bool]$report.resume.success}else{$false});finishSucceeded=$(if($report-and$report.finish){[bool]$report.finish.success}else{$false});rollbackClosed=$(if($report){[bool]$report.rollback_closed}else{$false});marker=$markerText;sourceOffline=[bool]$source.IsOffline;sourceReadOnly=[bool]$source.IsReadOnly}
 }
 if(-not$observed.terminal){[pscustomobject]@{status='guest-recovery-still-running';taskName=$dispatch.taskName;taskState=$observed.taskState};return}
 $localReportSha=$null
 if($observed.guestReportPresent){Copy-Item -LiteralPath $dispatch.guestOutput -Destination (Join-Path $directory 'guest-recovery.json') -FromSession $session;$localReportSha=(Get-FileHash -LiteralPath (Join-Path $directory 'guest-recovery.json')).Hash.ToLowerInvariant();if($localReportSha-cne$observed.guestReportSha256){throw 'Guest recovery report changed during export.'}}
 $success=$observed.lastTaskResult-eq0 -and $observed.guestReportPresent -and $observed.reportSucceeded -and $observed.resumeSucceeded -and $observed.finishSucceeded -and $observed.rollbackClosed -and $observed.marker-ceq'N2RHND01' -and -not$observed.sourceOffline -and -not$observed.sourceReadOnly
 $result=[ordered]@{kind='ordinary-tree-recovery-observation';taskName=$dispatch.taskName;terminal=$true;taskState=$observed.taskState;lastTaskResult=$observed.lastTaskResult;guestReportPresent=[bool]$observed.guestReportPresent;guestReportSha256=$localReportSha;journalMarker=$observed.marker;sourceOffline=$observed.sourceOffline;sourceReadOnly=$observed.sourceReadOnly;nativeFinishSucceeded=[bool]$success;generalConversionQualified=$false;capturedUtc=[DateTime]::UtcNow.ToString('o')}
 $path=Join-Path $directory 'collected.json';$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 8));$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 [pscustomobject]$result
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
