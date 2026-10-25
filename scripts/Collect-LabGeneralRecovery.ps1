<# Observe one general resume/rollback task without retrying it or changing
   disk state. The journal handoff sector must remain zero. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$RecoveryDispatchDirectory)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$directory=Assert-LabPath $RecoveryDispatchDirectory $cfg.Root
$start=Get-Content -LiteralPath (Join-Path $directory 'started.json') -Raw|ConvertFrom-Json
$dispatch=Get-Content -LiteralPath (Join-Path $directory 'dispatch.json') -Raw|ConvertFrom-Json
if($start.kind-cne'general-tree-recovery-dispatch'-or$start.stepId-cnotmatch'\A[0-9a-f]{32}\z'-or$start.runId-cnotmatch'\A[0-9a-f]{32}\z'-or$start.experimentId-cnotmatch'\A[0-9a-f]{32}\z'-or$start.mode-notin@('Resume','Rollback')-or$dispatch.taskName-cne('N2R-GeneralRecover-'+$start.stepId)-or$dispatch.guestOutput-cne('C:\ntfs2refs\general-replay\'+$start.runId+'\artifacts\recovery-'+$start.stepId+'.json')-or$vm.State-ne'Running'-or[guid]$vm.ParentSnapshotId-ne[guid]$start.parentCheckpointId){throw 'Recovery task, VM branch or output identity differs.'}
if(Test-Path -LiteralPath (Join-Path $directory 'collected.json')){throw 'Recovery result already collected; preserve earlier observation.'}
$parent=Assert-LabPath $start.parentDirectory $cfg.Root
$pins=Get-Content -LiteralPath (Join-Path $parent 'started.json') -Raw|ConvertFrom-Json
$requestPath=Join-Path (Assert-LabPath $pins.replayDirectory (Join-Path $workspace '.lab/development')) 'general-request.json'
if((Get-FileHash -LiteralPath $requestPath).Hash.ToLowerInvariant()-cne$pins.requestSha256){throw 'Recovery parent request pin differs.'}
$request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
if($pins.kind-cne'general-tree-replay-dispatch'-or$pins.runId-cne$start.runId-or$request.experiment_id-cne$start.experimentId){throw 'Recovery parent request differs.'}
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
  $marker=$null;if(Test-Path -LiteralPath $journal -PathType Leaf){$stream=[IO.File]::Open($journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite);try{$bytes=[byte[]]::new(4096);if($stream.Read($bytes,0,$bytes.Length)-eq$bytes.Length){$markerZero=@($bytes|Where-Object {$_ -ne0}).Count-eq0}else{$markerZero=$false}}finally{$stream.Dispose()}}else{$markerZero=$false}
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
  [pscustomobject]@{terminal=$true;taskState=[string]$task.State;lastTaskResult=$info.LastTaskResult;reportSha256=$reportSha;handoffSectorZero=$markerZero;sourceOffline=[bool]$source.IsOffline;sourceReadOnly=[bool]$source.IsReadOnly;shadowOffline=[bool]$shadow.IsOffline;shadowReadOnly=[bool]$shadow.IsReadOnly}
 }
 if(-not$observed.terminal){[pscustomobject]@{status='guest-general-recovery-still-running';taskName=$dispatch.taskName;taskState=$observed.taskState};return}
 $report=$null
 if($observed.reportSha256){Copy-Item -LiteralPath $dispatch.guestOutput -Destination (Join-Path $directory 'guest-recovery.json') -FromSession $session;$actual=(Get-FileHash -LiteralPath (Join-Path $directory 'guest-recovery.json')).Hash.ToLowerInvariant();if($actual-cne$observed.reportSha256){throw 'Recovery report changed during export.'};$report=Get-Content -LiteralPath (Join-Path $directory 'guest-recovery.json') -Raw|ConvertFrom-Json}
 $expected=$(if($start.mode-ceq'Resume'){$request.comparison.shadow_sha256}else{$request.comparison.source_sha256})
 $matched=$observed.lastTaskResult-eq0 -and$report -and$report.kind-ceq'general-journal-recovery' -and$report.success -and$report.mode-ceq$start.mode.ToLowerInvariant() -and$report.execution.result.target_sha256-cne$null -and$report.execution.result.target_sha256-ceq$expected -and$report.target_offline_observed -and$report.shadow_excluded_observed -and$observed.handoffSectorZero -and$observed.sourceOffline -and-not$observed.sourceReadOnly -and$observed.shadowOffline -and$observed.shadowReadOnly
 $result=[ordered]@{schemaVersion=1;kind='general-tree-recovery-observation';stepId=$start.stepId;mode=$start.mode;taskName=$dispatch.taskName;terminal=$true;taskState=$observed.taskState;lastTaskResult=$observed.lastTaskResult;reportSha256=$observed.reportSha256;handoffSectorZero=$observed.handoffSectorZero;sourceOffline=$observed.sourceOffline;sourceReadOnly=$observed.sourceReadOnly;shadowOffline=$observed.shadowOffline;shadowReadOnly=$observed.shadowReadOnly;exactImageRecovered=[bool]$matched;readyForHandoff=([bool]$matched-and$start.mode-ceq'Resume');readyForOldNtfsOnline=([bool]$matched-and$start.mode-ceq'Rollback');productionConversionQualified=$false;capturedUtc=[DateTime]::UtcNow.ToString('o')}
 $path=Join-Path $directory 'collected.json';$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 12));$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 [pscustomobject]$result
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
