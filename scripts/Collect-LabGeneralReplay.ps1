<# Observe one dispatched general replay task. No restart, rollback, checkpoint
   action, disk-attribute change or guest converter launch occurs here. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$DispatchDirectory)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$directory=Assert-LabPath $DispatchDirectory $cfg.Root
$start=Get-Content -LiteralPath (Join-Path $directory 'started.json') -Raw|ConvertFrom-Json
$dispatch=Get-Content -LiteralPath (Join-Path $directory 'dispatch.json') -Raw|ConvertFrom-Json
if($start.kind-cne'general-tree-replay-dispatch'-or$start.runId-cnotmatch'\A[0-9a-f]{32}\z'-or$start.experimentId-cnotmatch'\A[0-9a-f]{32}\z'-or$dispatch.taskName-cne('N2R-General-'+$start.runId)-or$dispatch.guestArtifacts-cne('C:\ntfs2refs\general-replay\'+$start.runId+'\artifacts')-or$vm.State-ne'Running'-or[guid]$vm.ParentSnapshotId-ne[guid]$start.parentCheckpointId){throw 'General replay task, VM branch or guest artifacts differ.'}
if(Test-Path -LiteralPath (Join-Path $directory 'collected.json')){throw 'General replay result already collected; preserve earlier observation.'}
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $deadline=[DateTime]::UtcNow.AddSeconds(180)
 do{try{$session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop;break}catch{Start-Sleep -Seconds 2}}while([DateTime]::UtcNow-lt$deadline)
 if(-not$session){throw 'Guest session unavailable.'}
 $observed=Invoke-Command -Session $session -ArgumentList @($dispatch.taskName,$dispatch.guestArtifacts,$start.experimentId) -ScriptBlock {
  param($TaskName,$Artifacts,$ExperimentId)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  $task=Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
  $info=Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
  if($task.State-in@('Running','Queued')-or$info.LastRunTime.Year-lt2000){return [pscustomobject]@{terminal=$false;taskState=[string]$task.State;lastTaskResult=$info.LastTaskResult}}
  $files=@()
  foreach($name in @('intent.json','request.json','expectation.json','prepare.json','ticket.json','recovery.json','apply.json','finish.json','failure.json')){
   $path=Join-Path $Artifacts $name
   if(Test-Path -LiteralPath $path -PathType Leaf){$files+=@([pscustomobject]@{name=$name;sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant();length=(Get-Item -LiteralPath $path).Length})}
  }
  $journal='J:\ntfs2refs-shadow\'+$ExperimentId+'\reconstruction.journal'
  $marker=$null
  if(Test-Path -LiteralPath $journal -PathType Leaf){$stream=[IO.File]::Open($journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite);try{$bytes=[byte[]]::new(8);if($stream.Read($bytes,0,8)-eq8){$marker=[Text.Encoding]::ASCII.GetString($bytes)}}finally{$stream.Dispose()}}
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
  [pscustomobject]@{terminal=$true;taskState=[string]$task.State;lastTaskResult=$info.LastTaskResult;files=$files;journalMarker=$marker;sourceOffline=[bool]$source.IsOffline;sourceReadOnly=[bool]$source.IsReadOnly;shadowOffline=[bool]$shadow.IsOffline;shadowReadOnly=[bool]$shadow.IsReadOnly}
 }
 if(-not$observed.terminal){[pscustomobject]@{status='guest-general-task-still-running';taskName=$dispatch.taskName;taskState=$observed.taskState};return}
 $exported=@()
 foreach($file in @($observed.files|Where-Object {$_})){
  if($file.name-cnotmatch'\A(?:intent|request|expectation|prepare|ticket|recovery|apply|finish|failure)\.json\z'-or$file.length-gt64MB){throw 'Guest artifact inventory exceeds bounds.'}
  $from=Join-Path $dispatch.guestArtifacts $file.name;$to=Join-Path $directory ('guest-'+$file.name)
  Copy-Item -LiteralPath $from -Destination $to -FromSession $session
  $sha=(Get-FileHash -LiteralPath $to).Hash.ToLowerInvariant()
  if($sha-cne$file.sha256){throw 'Guest artifact changed during export.'}
  $exported+=@([ordered]@{name=$file.name;sha256=$sha;length=$file.length})
 }
 $names=@($exported|ForEach-Object {$_.name})
 if($names -contains 'request.json'){if((Get-FileHash -LiteralPath (Join-Path $directory 'guest-request.json')).Hash.ToLowerInvariant()-cne$start.requestSha256){throw 'Exported request differs from dispatch pin.'}}
 if($names -contains 'expectation.json'){if((Get-FileHash -LiteralPath (Join-Path $directory 'guest-expectation.json')).Hash.ToLowerInvariant()-cne$start.expectationSha256){throw 'Exported expectation differs from dispatch pin.'}}
 $finish=$null;if($names -contains 'finish.json'){$finish=Get-Content -LiteralPath (Join-Path $directory 'guest-finish.json') -Raw|ConvertFrom-Json}
 $required=@('request.json','expectation.json','prepare.json','ticket.json','recovery.json','apply.json','finish.json')
 $missing=@($required|Where-Object {$names -notcontains $_})
 $success=$observed.lastTaskResult-eq0 -and$finish -and$finish.success -and$finish.rollback_closed -and$missing.Count-eq0 -and$observed.journalMarker-ceq'N2RHND01' -and-not$observed.sourceOffline -and-not$observed.sourceReadOnly -and$observed.shadowOffline -and$observed.shadowReadOnly
 $recoveryRequired=$observed.lastTaskResult-eq86 -and$observed.journalMarker-ceq([string]([char]0)*8) -and$observed.sourceOffline -and-not$observed.sourceReadOnly -and$observed.shadowOffline -and$observed.shadowReadOnly -and($names -contains 'ticket.json') -and($names -contains 'recovery.json')
 $result=[ordered]@{schemaVersion=1;kind='general-tree-replay-observation';runId=$start.runId;taskName=$dispatch.taskName;terminal=$true;taskState=$observed.taskState;lastTaskResult=$observed.lastTaskResult;journalMarker=$observed.journalMarker;sourceOffline=$observed.sourceOffline;sourceReadOnly=$observed.sourceReadOnly;shadowOffline=$observed.shadowOffline;shadowReadOnly=$observed.shadowReadOnly;nativeFinishSucceeded=[bool]$success;controlledRecoveryRequired=[bool]$recoveryRequired;artifacts=$exported;productionConversionQualified=$false;capturedUtc=[DateTime]::UtcNow.ToString('o')}
 $path=Join-Path $directory 'collected.json';$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 12));$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 [pscustomobject]$result
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
