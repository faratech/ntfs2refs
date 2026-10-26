<# Observe one public status/cancel task, preserving terminal evidence only.
   No retries, disk setters, mounts, restores or raw writes are performed. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$DispatchDirectory)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot;Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$vm=Get-OwnedLabVM $cfg (Read-LabManifest $cfg win11)
$directory=Assert-LabPath $DispatchDirectory $cfg.Root
$d=Get-Content -LiteralPath (Join-Path $directory 'dispatch.json') -Raw|ConvertFrom-Json
if($d.kind-cne'public-cancel-dispatch'-or$d.stepId-cnotmatch'\A[0-9a-f]{32}\z'-or$d.originRunId-cnotmatch'\A[0-9a-f]{32}\z'-or$d.taskName-cne('N2R-PublicCancel-'+$d.stepId)-or$d.guestRoot-cne('C:\ntfs2refs\public-cancel-inputs\'+$d.stepId)-or$d.guestOutput-cne('C:\ntfs2refs\public-cancel\'+$d.stepId)-or$vm.State-ne'Running'-or[guid]$vm.Id-ne[guid]$d.vmId-or[guid]$vm.ParentSnapshotId-ne[guid]$d.checkpointId){throw 'Exact public cancel task and owned branch required.'}
if(Test-Path -LiteralPath (Join-Path $directory 'collected.json')){throw 'Terminal cancel already collected.'}
$fixturePath=Join-Path $directory 'fixture-before.json'
if((Get-FileHash -LiteralPath $fixturePath).Hash.ToLowerInvariant()-cne$d.fixtureBeforeSha256){throw 'Pinned fixture-before differs.'}
$fixture=Get-Content -LiteralPath $fixturePath -Raw|ConvertFrom-Json
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop
 $r=Invoke-Command -Session $session -ArgumentList @($d.taskName,$d.guestOutput,$d.guestRoot,$fixture) -ScriptBlock {
  param($Task,$Output,$Root,$Fixture);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  $t=Get-ScheduledTask -TaskName $Task;$i=Get-ScheduledTaskInfo -TaskName $Task
  $names=@('status-process.json','cancel-process.json','state/state.json','cancel/intent.json','cancel/source-unchanged.json','cancel/availability-intent.json','cancel/source-restored.json','cancel/mount-paths.json','cancel/result.json','cancel/failed.json','fixture-after.json','runner-result.json','runner-failed.json')
  $present=@($names|Where-Object {Test-Path -LiteralPath (Join-Path $Output $_)})
  if($t.State-in@('Running','Queued')-or$i.LastRunTime.Year-lt2000){
   $workers=@(Get-CimInstance Win32_Process -Filter "Name='public-cli.exe'"|Where-Object {$_.ExecutablePath-ceq($Root+'\public-cli.exe')}|ForEach-Object {[pscustomobject]@{processId=$_.ProcessId;readBytes=[uint64]$_.ReadTransferCount;writtenBytes=[uint64]$_.WriteTransferCount}})
   return [pscustomobject]@{terminal=$false;state=[string]$t.State;artifacts=$present;workers=$workers}
  }
  $disk=Get-Disk -Number 1;$part=Get-Partition -DiskNumber 1 -PartitionNumber 2
  if([guid]$disk.Guid-ne[guid]'a01574d5-2a5c-4136-958a-dcf0d0e0f7aa'-or[guid]$part.Guid-ne[guid]'79eaccdf-38d3-4561-97cc-9276af5d223a'-or$disk.Size-ne64GB-or$part.Size-ne52GB-or$part.Offset-ne16MB-or$disk.IsBoot-or$disk.IsSystem-or$part.IsBoot-or$part.IsSystem){throw 'Observed source identity differs.'}
  $pins=@(foreach($name in $present){$path=Join-Path $Output $name;$f=Get-Item -LiteralPath $path -Force;if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-gt16MB){throw 'Cancel output is not bounded ordinary evidence.'};[pscustomobject]@{name=$name;length=$f.Length;sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()}})
  $filesystem=$null;$label=$null;$driveLetter=[string]$part.DriveLetter;$files=@();$fixtureError=$null
  if(-not$disk.IsOffline){$vol=$part|Get-Volume;$filesystem=[string]$vol.FileSystem;$label=[string]$vol.FileSystemLabel}
  if(-not$disk.IsOffline-and-not$disk.IsReadOnly-and$filesystem-ceq'NTFS'-and$driveLetter-ceq'F'){
   try{$files=@(foreach($before in $Fixture.files){$path=Join-Path 'F:\' $before.path;$f=Get-Item -LiteralPath $path -Force;if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-gt1MB){throw 'Restored fixture file is not ordinary bounded content.'};[pscustomobject]@{path=$before.path;length=$f.Length;sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()}})}catch{$fixtureError=$_.Exception.ToString()}
  }
  [pscustomobject]@{terminal=$true;state=[string]$t.State;exitCode=$i.LastTaskResult;files=$pins;sourceOffline=[bool]$disk.IsOffline;sourceReadOnly=[bool]$disk.IsReadOnly;sourceFileSystem=$filesystem;sourceLabel=$label;driveLetter=$driveLetter;fixtureFiles=$files;fixtureError=$fixtureError;observedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 if(-not$r.terminal){[pscustomobject]@{status='public-cancel-still-running-or-not-observed';taskName=$d.taskName;state=$r.state;artifacts=$r.artifacts;workers=$r.workers};return}
 foreach($p in $r.files){$destination=Join-Path $directory $p.name;$parent=Split-Path -Parent $destination;if(-not(Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Path $parent|Out-Null};if(-not(Test-Path -LiteralPath $destination)){Copy-Item -LiteralPath (Join-Path $d.guestOutput $p.name) -Destination $destination -FromSession $session};if((Get-Item -LiteralPath $destination).Length-ne$p.length-or(Get-FileHash -LiteralPath $destination).Hash.ToLowerInvariant()-cne$p.sha256){throw 'Exported cancel evidence differs.'}}
 $success=$false;$errorText=$null;$rawHashMatched=$false;$fixtureMatched=$false;$mountsMatched=$false
 try{
  $state=Get-Content -LiteralPath (Join-Path $directory 'state/state.json') -Raw|ConvertFrom-Json
  $native=Get-Content -LiteralPath (Join-Path $directory 'cancel/result.json') -Raw|ConvertFrom-Json
  $restored=Get-Content -LiteralPath (Join-Path $directory 'cancel/source-restored.json') -Raw|ConvertFrom-Json
  $mounts=Get-Content -LiteralPath (Join-Path $directory 'cancel/mount-paths.json') -Raw|ConvertFrom-Json
  $intent=Get-Content -LiteralPath (Join-Path $directory 'cancel/intent.json') -Raw|ConvertFrom-Json
  $runner=Get-Content -LiteralPath (Join-Path $directory 'runner-result.json') -Raw|ConvertFrom-Json
  $statusProcess=Get-Content -LiteralPath (Join-Path $directory 'status-process.json') -Raw|ConvertFrom-Json
  $cancelProcess=Get-Content -LiteralPath (Join-Path $directory 'cancel-process.json') -Raw|ConvertFrom-Json
  $rawHashMatched=$restored.source_sha256-ceq$d.sourceSha256-and$native.source_sha256-ceq$d.sourceSha256-and$restored.before.disk_attributes-eq3-and$restored.after.disk_attributes-eq0-and$restored.native_bytes_read-eq52GB-and$restored.exclusive_source_lease-and$restored.source_handle_closed-and$restored.raw_source_writes-eq0
  $mountsMatched=@($mounts.requested).Count-eq1-and$mounts.requested[0]-ceq'F:\'-and@($mounts.after.paths).Count-eq1-and$mounts.after.paths[0]-ceq'F:\'-and$mounts.after.all_paths_resolve_to_bound_volume
  $fixtureMatched=@($r.fixtureFiles).Count-eq4-and-not$r.fixtureError
  foreach($before in $fixture.files){$after=@($r.fixtureFiles|Where-Object {$_.path-ceq$before.path});if($after.Count-ne1-or$after[0].length-ne$before.length-or$after[0].sha256-cne$before.sha256){$fixtureMatched=$false}}
  $pinsMatched=$intent.conversion_intent_sha256-ceq$d.intentSha256-and$intent.frozen_source_sha256-ceq$d.frozenSha256-and$intent.mount_paths_sha256-ceq$d.mountsSha256
  $success=$r.exitCode-eq0-and$runner.success-and$runner.kind-ceq'public-cancel-runner-result'-and$runner.statusExitCode-eq0-and$runner.cancelExitCode-eq0-and$state.kind-ceq'read-only-public-operation-state'-and$state.state-ceq'frozen_before_activation'-and-not$state.execution_authorized-and-not$state.disk_attributes_changed-and$state.source_payload_writes-eq0-and$statusProcess.exitCode-eq0-and-not$statusProcess.stdoutTruncated-and-not$statusProcess.stderrTruncated-and$cancelProcess.exitCode-eq0-and-not$cancelProcess.stdoutTruncated-and-not$cancelProcess.stderrTruncated-and$native.kind-ceq'public-preactivation-cancel'-and$native.success-and$native.source_original_online-and$native.original_mount_paths_preserved-and$native.source_hash_scope-ceq'complete partition before original NTFS writable mount'-and$native.source_payload_writes-eq0-and$native.journal_mutations-eq0-and-not$native.raw_reconstruction_authorized-and$rawHashMatched-and$fixtureMatched-and$mountsMatched-and$pinsMatched-and-not$r.sourceOffline-and-not$r.sourceReadOnly-and$r.sourceFileSystem-ceq'NTFS'-and$r.sourceLabel-ceq$fixture.label-and$r.driveLetter-ceq'F'-and-not(Test-Path -LiteralPath (Join-Path $directory 'runner-failed.json'))-and-not(Test-Path -LiteralPath (Join-Path $directory 'cancel/failed.json'))
 }catch{$errorText=$_.Exception.ToString()}
 $record=[ordered]@{schemaVersion=1;kind='public-cancel-observation';stepId=$d.stepId;originRunId=$d.originRunId;taskName=$d.taskName;exitCode=$r.exitCode;success=[bool]$success;sourceOffline=$r.sourceOffline;sourceReadOnly=$r.sourceReadOnly;sourceFileSystem=$r.sourceFileSystem;sourceLabel=$r.sourceLabel;driveLetter=$r.driveLetter;frozenSourceSha256=$d.sourceSha256;rawSourceHashMatchedBeforeWritableMount=[bool]$rawHashMatched;sourceHashScope='complete partition before original NTFS writable mount';postmountWholeImageEqualityClaimed=$false;originalMountPathsMatched=[bool]$mountsMatched;fourLogicalFilesMatched=[bool]$fixtureMatched;fixtureFiles=$r.fixtureFiles;fixtureError=$r.fixtureError;parseOrValidationError=$errorText;files=$r.files;capturedUtc=[DateTime]::UtcNow.ToString('o')}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 16));$file=[IO.File]::Open((Join-Path $directory 'collected.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 [pscustomobject]$record
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
