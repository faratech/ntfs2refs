<# Observe one dispatched certificate-backed conversion. Never restarts a
   task, changes device state or starts recovery. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$DispatchDirectory)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$directory=Assert-LabPath $DispatchDirectory $cfg.Root
$dispatch=Get-Content -LiteralPath (Join-Path $directory 'dispatch.json') -Raw|ConvertFrom-Json
if($dispatch.kind-cne'certificate-backed-conversion-dispatch'-or$dispatch.runId-cnotmatch'\A[0-9a-f]{32}\z'-or$dispatch.taskName-cne('N2R-AdmittedConvert-'+$dispatch.runId)-or$dispatch.guestRoot-cne('C:\ntfs2refs\conversion-inputs\'+$dispatch.runId)-or$dispatch.guestOutput-cne('C:\ntfs2refs\conversions\'+$dispatch.runId)-or[guid]$dispatch.vmId-ne[guid]$vm.Id-or[guid]$dispatch.checkpointId-ne[guid]$vm.ParentSnapshotId-or$vm.State-ne'Running'){throw 'Conversion task or owning VM differs.'}
if(Test-Path -LiteralPath (Join-Path $directory 'collected.json')){throw 'Terminal conversion already collected.'}
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop
 $observed=Invoke-Command -Session $session -ArgumentList @($dispatch.taskName,$dispatch.guestOutput,$dispatch.guestRoot,$dispatch.runId) -ScriptBlock {
  param($TaskName,$Output,$Root,$RunId);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  $task=Get-ScheduledTask -TaskName $TaskName;$info=Get-ScheduledTaskInfo -TaskName $TaskName
  $names=@('conversion-intent.json','qualification/intent.json','qualification/preflight-events.json','qualification/source-mount-paths.json','qualification/source-label.json','qualification/source-label-frozen.json','qualification/source-frozen.json','qualification/source-basis.json','qualification/native-source.json','qualification/source-assessment.json','qualification/source-events.json','qualification/expectation.json','qualification/native-shadow.json','qualification/target-preservation.json','qualification/target-events.json','qualification/certificate.json','qualification/admitted-assessment.json','qualification/result.json','qualification/failed.json','request.json','expectation.json','journal-location.json','prepare.json','ticket.json','interruption-intent.json','preactivation-interruption-intent.json','apply.json','finalization.json','result.json','failed.json')
  $present=@($names|Where-Object {Test-Path -LiteralPath (Join-Path $Output $_)})
  if($task.State-in@('Running','Queued')-or$info.LastRunTime.Year-lt2000){
   # Observe only the executable enrolled by this dispatch. Counters describe
   # I/O activity, not a percentage or proof that a phase has completed.
   $processes=@(Get-CimInstance Win32_Process -Filter "Name='converter.exe'"|Where-Object {$_.ExecutablePath-ceq($Root+'\converter.exe')})
   $activity=@(foreach($process in $processes){[pscustomobject]@{processId=$process.ProcessId;readBytes=[uint64]$process.ReadTransferCount;writtenBytes=[uint64]$process.WriteTransferCount;cpuSeconds=([double]$process.KernelModeTime+[double]$process.UserModeTime)/10000000}})
   $phase=if($present-contains'finalization.json'){'native-finalization-complete'}elseif($present-contains'apply.json'){'handoff-and-native-verification'}elseif($present-contains'ticket.json'){'raw-application'}elseif($present-contains'prepare.json'){'ticket-persistence'}elseif($present-contains'journal-location.json'){'journal-preparation'}elseif($present-contains'qualification/certificate.json'){'qualified'}elseif($present-contains'qualification/native-source.json'){'shadow-construction-and-verification'}else{'source-qualification'}
   $journalBytes=$null
   $location=Join-Path $Output 'journal-location.json'
   if(Test-Path -LiteralPath $location){
    $locationFile=Get-Item -LiteralPath $location -Force
    if(-not$locationFile.PSIsContainer-and-not($locationFile.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$locationFile.Length-le16KB){
     $journal=Get-Content -LiteralPath $location -Raw|ConvertFrom-Json
     $suffix='\ntfs2refs-shadow\'+$RunId+'\reconstruction.journal'
     if($journal.path-is[string]-and$journal.path.EndsWith($suffix,[StringComparison]::OrdinalIgnoreCase)){
      $journalFile=Get-Item -LiteralPath $journal.path -Force -ErrorAction SilentlyContinue
      if($journalFile-and-not$journalFile.PSIsContainer-and-not($journalFile.Attributes-band[IO.FileAttributes]::ReparsePoint)){$journalBytes=[uint64]$journalFile.Length}
     }
    }
   }
   return [pscustomobject]@{terminal=$false;state=[string]$task.State;artifacts=$present;phase=$phase;activity=$activity;journalBytes=$journalBytes;observedUtc=[DateTime]::UtcNow.ToString('o')}
  }
  $files=@(foreach($name in $present){$path=Join-Path $Output $name;$file=Get-Item -LiteralPath $path -Force;if($file.PSIsContainer-or($file.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$file.Length-gt64MB){throw 'Conversion artifact is not bounded ordinary output.'};[pscustomobject]@{name=$name;length=$file.Length;sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()}})
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
  [pscustomobject]@{terminal=$true;state=[string]$task.State;exitCode=$info.LastTaskResult;files=$files;sourceOffline=[bool]$source.IsOffline;sourceReadOnly=[bool]$source.IsReadOnly;shadowOffline=[bool]$shadow.IsOffline;shadowReadOnly=[bool]$shadow.IsReadOnly;sourceFileSystem=if(-not$source.IsOffline){(Get-Partition -DiskNumber 1 -PartitionNumber 2|Get-Volume).FileSystem}else{$null}}
 }
 if(-not$observed.terminal){[pscustomobject]@{status='conversion-still-running';taskName=$dispatch.taskName;state=$observed.state;phase=$observed.phase;activity=$observed.activity;journalBytes=$observed.journalBytes;observedUtc=$observed.observedUtc;artifacts=$observed.artifacts};return}
 foreach($file in $observed.files){$destination=Join-Path $directory $file.name;$parent=Split-Path $destination -Parent;if(-not(Test-Path $parent)){New-Item -ItemType Directory -Path $parent|Out-Null};if(Test-Path $destination){throw 'Artifact export destination already exists.'};Copy-Item -LiteralPath (Join-Path $dispatch.guestOutput $file.name) -Destination $destination -FromSession $session;if((Get-Item $destination).Length-ne$file.length-or(Get-FileHash $destination).Hash.ToLowerInvariant()-cne$file.sha256){throw 'Conversion artifact changed during export.'}}
 $result=if(Test-Path (Join-Path $directory 'result.json')){Get-Content (Join-Path $directory 'result.json') -Raw|ConvertFrom-Json}else{$null}
 $failure=if(Test-Path (Join-Path $directory 'failed.json')){Get-Content (Join-Path $directory 'failed.json') -Raw|ConvertFrom-Json}else{$null}
 $success=$observed.exitCode-eq0-and$result-and$result.kind-ceq'certificate-backed-ntfs-refs-conversion'-and$result.success-and$result.source_admitted-and$result.rollback_closed-and$observed.sourceFileSystem-ceq'ReFS'-and-not$observed.sourceOffline-and-not$observed.sourceReadOnly
 $record=[ordered]@{schemaVersion=1;kind='certificate-backed-conversion-observation';runId=$dispatch.runId;taskName=$dispatch.taskName;exitCode=$observed.exitCode;success=[bool]$success;sourceFileSystem=$observed.sourceFileSystem;sourceOffline=$observed.sourceOffline;sourceReadOnly=$observed.sourceReadOnly;shadowOffline=$observed.shadowOffline;shadowReadOnly=$observed.shadowReadOnly;failure=$failure;files=$observed.files;capturedUtc=[DateTime]::UtcNow.ToString('o')}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 12));$output=[IO.File]::Open((Join-Path $directory 'collected.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$output.Write($bytes,0,$bytes.Length);$output.Flush($true)}finally{$output.Dispose()}
 [pscustomobject]$record
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
