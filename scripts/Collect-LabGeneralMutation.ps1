<# Read-only collection of the post-handoff ReFS mutation workload. No
   reboot or converter replay is performed here. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$MutationDispatchDirectory)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$directory=Assert-LabPath $MutationDispatchDirectory $cfg.Root
$start=Get-Content -LiteralPath (Join-Path $directory 'started.json') -Raw|ConvertFrom-Json
$dispatch=Get-Content -LiteralPath (Join-Path $directory 'dispatch.json') -Raw|ConvertFrom-Json
if($start.kind-cne'general-refs-mutation-dispatch'-or$start.stepId-cnotmatch'\A[0-9a-f]{32}\z'-or$start.runId-cnotmatch'\A[0-9a-f]{32}\z'-or$start.experimentId-cnotmatch'\A[0-9a-f]{32}\z'-or$dispatch.taskName-cne('N2R-GeneralMutate-'+$start.stepId)-or$dispatch.guestOutput-cne('C:\ntfs2refs\general-replay\'+$start.runId+'\artifacts\mutation-'+$start.stepId+'.json')-or$vm.State-ne'Running'-or[guid]$vm.ParentSnapshotId-ne[guid]$start.parentCheckpointId){throw 'Mutation task, VM branch or output differs.'}
if(Test-Path -LiteralPath (Join-Path $directory 'collected.json')){throw 'Mutation result already collected; preserve earlier observation.'}
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
  $sha=$null;if(Test-Path -LiteralPath $Output -PathType Leaf){$sha=(Get-FileHash -LiteralPath $Output).Hash.ToLowerInvariant()}
  $journal='J:\ntfs2refs-shadow\'+$ExperimentId+'\reconstruction.journal'
  $marker=$null;if(Test-Path -LiteralPath $journal -PathType Leaf){$stream=[IO.File]::Open($journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite);try{$bytes=[byte[]]::new(8);if($stream.Read($bytes,0,8)-eq8){$marker=[Text.Encoding]::ASCII.GetString($bytes)}}finally{$stream.Dispose()}}
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
  $filesystem=$null;if(-not$source.IsOffline){try{$volume=Get-Partition -DiskNumber 1 -PartitionNumber 2|Get-Volume;$filesystem=[string]$volume.FileSystem}catch{$filesystem=$null}}
  [pscustomobject]@{terminal=$true;taskState=[string]$task.State;lastTaskResult=$info.LastTaskResult;reportSha256=$sha;journalMarker=$marker;sourceOffline=[bool]$source.IsOffline;sourceReadOnly=[bool]$source.IsReadOnly;sourceFileSystem=$filesystem;shadowOffline=[bool]$shadow.IsOffline;shadowReadOnly=[bool]$shadow.IsReadOnly}
 }
 if(-not$observed.terminal){[pscustomobject]@{status='guest-refs-mutation-still-running';taskName=$dispatch.taskName;taskState=$observed.taskState};return}
 $report=$null
 if($observed.reportSha256){Copy-Item -LiteralPath $dispatch.guestOutput -Destination (Join-Path $directory 'guest-mutation.json') -FromSession $session;$actual=(Get-FileHash -LiteralPath (Join-Path $directory 'guest-mutation.json')).Hash.ToLowerInvariant();if($actual-cne$observed.reportSha256){throw 'Guest mutation report changed during export.'};$report=Get-Content -LiteralPath (Join-Path $directory 'guest-mutation.json') -Raw|ConvertFrom-Json}
 $success=$observed.lastTaskResult-eq0 -and$report -and$report.kind-ceq'general-refs-mutation-workload' -and$report.run_id-ceq$start.stepId -and$report.initial_bytes-eq50MB -and$report.grown_bytes-eq80MB -and$report.truncated_bytes-eq10MB -and$report.directory_entries_created-eq128 -and$report.mutation_directory_removed -and$observed.journalMarker-ceq'N2RHND01' -and-not$observed.sourceOffline -and-not$observed.sourceReadOnly -and$observed.sourceFileSystem-ceq'ReFS' -and$observed.shadowOffline -and$observed.shadowReadOnly
 $result=[ordered]@{schemaVersion=1;kind='general-refs-mutation-observation';stepId=$start.stepId;runId=$start.runId;taskName=$dispatch.taskName;terminal=$true;taskState=$observed.taskState;lastTaskResult=$observed.lastTaskResult;reportSha256=$observed.reportSha256;journalMarker=$observed.journalMarker;sourceOffline=$observed.sourceOffline;sourceReadOnly=$observed.sourceReadOnly;sourceFileSystem=$observed.sourceFileSystem;shadowOffline=$observed.shadowOffline;shadowReadOnly=$observed.shadowReadOnly;mutationSucceeded=[bool]$success;readyForRebootVerification=[bool]$success;productionConversionQualified=$false;capturedUtc=[DateTime]::UtcNow.ToString('o')}
 $path=Join-Path $directory 'collected.json';$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 12));$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 [pscustomobject]$result
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
