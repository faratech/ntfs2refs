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
 $observed=Invoke-Command -Session $session -ArgumentList @($dispatch.taskName,$dispatch.guestOutput,$dispatch.guestRoot,$dispatch.runId,52GB) -ScriptBlock {
  param($TaskName,$Output,$Root,$RunId,$PartitionBytes);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  function Read-JournalProgress([string]$Path,[long]$ExpectedPartitionBytes){
   # A concurrently rewritten sidecar is diagnostic only. Missing, partial,
   # changed, oversized or noncanonical input never changes task state.
   $stream=$null
   try{
    if($ExpectedPartitionBytes-lt4096-or$ExpectedPartitionBytes%4096-ne0-or$ExpectedPartitionBytes-gt([long]::MaxValue-shr2)){return $null}
    $file=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if($file.PSIsContainer-or($file.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$file.Length-lt1-or$file.Length-gt4096){return $null}
    $length=$file.Length;$writtenTicks=$file.LastWriteTimeUtc.Ticks
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite-bor[IO.FileShare]::Delete))
    if($stream.Length-ne$length){return $null}
    $buffer=[byte[]]::new(4097);$used=0
    while($used-lt$buffer.Length){$read=$stream.Read($buffer,$used,$buffer.Length-$used);if($read-eq0){break};$used+=$read}
    $after=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if($used-ne$length-or$used-gt4096-or$after.PSIsContainer-or($after.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$after.Length-ne$length-or$after.LastWriteTimeUtc.Ticks-ne$writtenTicks){return $null}
    $text=[Text.UTF8Encoding]::new($false,$true).GetString($buffer,0,$used)
    # Parse only this flat ASCII schema. This also rejects duplicate keys,
    # escaped field names, floats, exponents, leading zeros and quoted counters.
    $document=[regex]::Match($text,'(?s)\A\s*\{(?<body>.*)\}\s*\z')
    if(-not$document.Success){return $null};$parts=$document.Groups['body'].Value.Split(',')
    if($parts.Count-ne7){return $null}
    $keys=@('schema_version','kind','subphase','bytes_scanned','total_scan_bytes','elapsed_ms','execution_authorized');$values=@{}
    foreach($part in $parts){
     $pair=[regex]::Match($part,'\A\s*"(?<key>[a-z_]+)"\s*:\s*(?<value>"[a-z-]+"|0|[1-9][0-9]*|false)\s*\z')
     if(-not$pair.Success){return $null};$key=$pair.Groups['key'].Value
     if($keys-cnotcontains$key-or$values.ContainsKey($key)){return $null};$values[$key]=$pair.Groups['value'].Value
    }
    if($values.schema_version-cne'1'-or$values.kind-cne'"journal-preparation-progress"'-or$values.execution_authorized-cne'false'){return $null}
    $subphase=$values.subphase.Trim('"')
    if(@('comparing','rechecking-source','rechecking-shadow','writing-journal','verifying-journal','complete')-cnotcontains$subphase){return $null}
    $counters=@{}
    foreach($key in @('bytes_scanned','total_scan_bytes','elapsed_ms')){$number=[uint64]0;if(-not[uint64]::TryParse($values[$key],[Globalization.NumberStyles]::None,[Globalization.CultureInfo]::InvariantCulture,[ref]$number)){return $null};$counters[$key]=$number}
    $total=[uint64]($ExpectedPartitionBytes*4)
    if($counters.total_scan_bytes-ne$total-or$counters.bytes_scanned-gt$total){return $null}
    [pscustomobject]@{schema_version=1;kind='journal-preparation-progress';subphase=$subphase;bytes_scanned=$counters.bytes_scanned;total_scan_bytes=$total;elapsed_ms=$counters.elapsed_ms;execution_authorized=$false;diagnosticOnly=$true}
   }catch{return $null}finally{if($stream){try{$stream.Dispose()}catch{}}}
  }
  $task=Get-ScheduledTask -TaskName $TaskName;$info=Get-ScheduledTaskInfo -TaskName $TaskName
  $names=@('conversion-intent.json','qualification/intent.json','qualification/preflight-events.json','qualification/source-mount-paths.json','qualification/source-label.json','qualification/source-label-frozen.json','qualification/source-frozen.json','qualification/source-basis.json','qualification/native-source.json','qualification/source-assessment.json','qualification/source-events.json','qualification/expectation.json','qualification/native-shadow.json','qualification/target-preservation.json','qualification/target-events.json','qualification/certificate.json','qualification/admitted-assessment.json','qualification/result.json','qualification/failed.json','request.json','expectation.json','journal-location.json','prepare.json','ticket.json','interruption-intent.json','preactivation-interruption-intent.json','apply.json','finalization.json','result.json','failed.json')
  $present=@($names|Where-Object {Test-Path -LiteralPath (Join-Path $Output $_)})
  if($task.State-in@('Running','Queued')-or$info.LastRunTime.Year-lt2000){
   # Observe only the executable enrolled by this dispatch. Counters describe
   # I/O activity, not a percentage or proof that a phase has completed.
   $processes=@(Get-CimInstance Win32_Process -Filter "Name='converter.exe'"|Where-Object {$_.ExecutablePath-ceq($Root+'\converter.exe')})
   $activity=@(foreach($process in $processes){[pscustomobject]@{processId=$process.ProcessId;readBytes=[uint64]$process.ReadTransferCount;writtenBytes=[uint64]$process.WriteTransferCount;cpuSeconds=([double]$process.KernelModeTime+[double]$process.UserModeTime)/10000000}})
   $phase=if($present-contains'finalization.json'){'native-finalization-complete'}elseif($present-contains'apply.json'){'handoff-and-native-verification'}elseif($present-contains'ticket.json'){'raw-application'}elseif($present-contains'prepare.json'){'ticket-persistence'}elseif($present-contains'journal-location.json'){'journal-preparation'}elseif($present-contains'qualification/certificate.json'){'qualified'}elseif($present-contains'qualification/native-source.json'){'shadow-construction-and-verification'}else{'source-qualification'}
   $journalProgress=$null
   if($phase-ceq'journal-preparation'){$journalProgress=Read-JournalProgress (Join-Path $Output 'journal-progress.json') $PartitionBytes}
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
   return [pscustomobject]@{terminal=$false;state=[string]$task.State;artifacts=$present;phase=$phase;activity=$activity;journalBytes=$journalBytes;journalProgress=$journalProgress;diagnosticOnly=$true;observedUtc=[DateTime]::UtcNow.ToString('o')}
  }
  $files=@(foreach($name in $present){$path=Join-Path $Output $name;$file=Get-Item -LiteralPath $path -Force;if($file.PSIsContainer-or($file.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$file.Length-gt64MB){throw 'Conversion artifact is not bounded ordinary output.'};[pscustomobject]@{name=$name;length=$file.Length;sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()}})
  $diagnosticFiles=@()
  try{$path=Join-Path $Output 'journal-progress.json';$file=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if(-not$file.PSIsContainer-and-not($file.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$file.Length-ge1-and$file.Length-le4096){$diagnosticFiles+=@([pscustomobject]@{name='journal-progress.json';length=$file.Length;sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant();diagnosticOnly=$true})}}catch{}
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3 -ErrorAction SilentlyContinue
  $beforeTargetStop=$info.LastTaskResult-eq87-and$present-contains'preactivation-interruption-intent.json'
  if(-not$shadow-and-not$beforeTargetStop){throw 'Required shadow disk is absent outside the controlled source-freeze stop.'}
  [pscustomobject]@{terminal=$true;state=[string]$task.State;exitCode=$info.LastTaskResult;files=$files;diagnosticFiles=$diagnosticFiles;sourceOffline=[bool]$source.IsOffline;sourceReadOnly=[bool]$source.IsReadOnly;shadowPresent=[bool]$shadow;shadowOffline=if($shadow){[bool]$shadow.IsOffline}else{$null};shadowReadOnly=if($shadow){[bool]$shadow.IsReadOnly}else{$null};sourceFileSystem=if(-not$source.IsOffline){(Get-Partition -DiskNumber 1 -PartitionNumber 2|Get-Volume).FileSystem}else{$null}}
 }
 if(-not$observed.terminal){[pscustomobject]@{status='conversion-still-running';taskName=$dispatch.taskName;state=$observed.state;phase=$observed.phase;activity=$observed.activity;journalBytes=$observed.journalBytes;journalProgress=$observed.journalProgress;diagnosticOnly=$true;observedUtc=$observed.observedUtc;artifacts=$observed.artifacts};return}
 foreach($file in $observed.files){$destination=Join-Path $directory $file.name;$parent=Split-Path $destination -Parent;if(-not(Test-Path $parent)){New-Item -ItemType Directory -Path $parent|Out-Null};if(Test-Path $destination){throw 'Artifact export destination already exists.'};Copy-Item -LiteralPath (Join-Path $dispatch.guestOutput $file.name) -Destination $destination -FromSession $session;if((Get-Item $destination).Length-ne$file.length-or(Get-FileHash $destination).Hash.ToLowerInvariant()-cne$file.sha256){throw 'Conversion artifact changed during export.'}}
 $diagnosticFiles=@();$diagnosticExportError=$null
 foreach($file in $observed.diagnosticFiles){try{$destination=Join-Path $directory 'journal-progress.json';if(Test-Path -LiteralPath $destination){throw 'Diagnostic export already exists; it is not overwritten.'};Copy-Item -LiteralPath (Join-Path $dispatch.guestOutput 'journal-progress.json') -Destination $destination -FromSession $session;$item=Get-Item -LiteralPath $destination -Force;if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-gt4096-or$item.Length-ne$file.length-or(Get-FileHash -LiteralPath $destination).Hash.ToLowerInvariant()-cne$file.sha256){throw 'Diagnostic sidecar changed during export.'};$diagnosticFiles+=@($file)}catch{$diagnosticExportError=$_.Exception.Message}}
 $result=if(Test-Path (Join-Path $directory 'result.json')){Get-Content (Join-Path $directory 'result.json') -Raw|ConvertFrom-Json}else{$null}
 $failure=if(Test-Path (Join-Path $directory 'failed.json')){Get-Content (Join-Path $directory 'failed.json') -Raw|ConvertFrom-Json}else{$null}
 $success=$observed.exitCode-eq0-and$result-and$result.kind-ceq'certificate-backed-ntfs-refs-conversion'-and$result.success-and$result.source_admitted-and$result.rollback_closed-and$observed.sourceFileSystem-ceq'ReFS'-and-not$observed.sourceOffline-and-not$observed.sourceReadOnly
 $record=[ordered]@{schemaVersion=1;kind='certificate-backed-conversion-observation';runId=$dispatch.runId;taskName=$dispatch.taskName;exitCode=$observed.exitCode;success=[bool]$success;sourceFileSystem=$observed.sourceFileSystem;sourceOffline=$observed.sourceOffline;sourceReadOnly=$observed.sourceReadOnly;shadowPresent=$observed.shadowPresent;shadowOffline=$observed.shadowOffline;shadowReadOnly=$observed.shadowReadOnly;failure=$failure;files=$observed.files;diagnosticFiles=$diagnosticFiles;diagnosticExportError=$diagnosticExportError;capturedUtc=[DateTime]::UtcNow.ToString('o')}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 12));$output=[IO.File]::Open((Join-Path $directory 'collected.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$output.Write($bytes,0,$bytes.Length);$output.Flush($true)}finally{$output.Dispose()}
 [pscustomobject]$record
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
