<# One public status/cancel task after a collected freeze stop or explicitly
   selected shadow-construction refusal; no disk setters/retry. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$InterruptedDirectory,[Parameter(Mandatory)][string]$BinaryPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BinarySha256,
 [Parameter(Mandatory)][string]$FixtureBeforePath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$FixtureBeforeSha256,
 [ValidateSet('ControlledFreeze','QualificationFailure')][string]$Mode='ControlledFreeze')
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot;Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$vm=Get-OwnedLabVM $cfg (Read-LabManifest $cfg win11)
$origin=Assert-LabPath $InterruptedDirectory $cfg.Root
$old=Get-Content (Join-Path $origin 'dispatch.json') -Raw|ConvertFrom-Json
$terminal=Get-Content (Join-Path $origin 'collected.json') -Raw|ConvertFrom-Json
$qualificationFailure=$Mode-ceq'QualificationFailure'
$originalExitCode=if($qualificationFailure){1}else{87}
if($old.kind-cne'certificate-backed-conversion-dispatch'-or$old.runId-cnotmatch'\A[0-9a-f]{32}\z'-or$old.taskName-cne('N2R-AdmittedConvert-'+$old.runId)-or$old.guestOutput-cne('C:\ntfs2refs\conversions\'+$old.runId)-or$terminal.kind-cne'certificate-backed-conversion-observation'-or$terminal.runId-cne$old.runId-or$terminal.exitCode-ne$originalExitCode-or$terminal.success-or-not$terminal.sourceOffline-or-not$terminal.sourceReadOnly-or$vm.State-ne'Running'-or[guid]$vm.Id-ne[guid]$old.vmId-or[guid]$vm.ParentSnapshotId-ne[guid]$old.checkpointId){throw 'Collected preactivation outcome and exact owned branch required.'}
if(-not$qualificationFailure-and($old.entrypoint-cne'lab-source-freeze-interruption'-or$old.expectedExitCode-ne87)){throw 'Controlled source-freeze dispatch required.'}
function Read-Pin([string]$Path,[string]$Pin,[long]$Limit){$f=Get-Item -LiteralPath $Path -Force;if($Pin-cnotmatch'\A[0-9a-f]{64}\z'-or$f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-lt1-or$f.Length-gt$Limit-or(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant()-cne$Pin){throw ('Bounded ordinary pin differs: '+$Path)};Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json}
function Origin-Pin([string]$Name,[long]$Limit){$p=@($terminal.files|Where-Object {$_.name-ceq$Name});if($p.Count-ne1){throw ('Origin pin absent/duplicate: '+$Name)};$path=Join-Path $origin $Name;$v=Read-Pin $path $p[0].sha256 $Limit;if((Get-Item $path).Length-ne$p[0].length){throw 'Artifact length differs.'};[pscustomobject]@{name=$Name;sha256=$p[0].sha256;limit=$Limit;value=$v}}
function Assert-Source($b){if($b.disk_number-ne1-or[guid]$b.volume_guid-ne[guid]'79eaccdf-38d3-4561-97cc-9276af5d223a'-or[guid]$b.identity.disk_guid-ne[guid]'a01574d5-2a5c-4136-958a-dcf0d0e0f7aa'-or[guid]$b.identity.partition_guid-ne[guid]'79eaccdf-38d3-4561-97cc-9276af5d223a'-or$b.identity.partition_number-ne2-or$b.identity.disk_bytes-ne64GB-or$b.identity.partition_offset-ne16MB-or$b.identity.partition_bytes-ne52GB-or$b.identity.logical_sector_bytes-ne512-or$b.identity.physical_sector_bytes-ne4096){throw 'Exact enrolled source binding required.'}}
$intent=Origin-Pin 'conversion-intent.json' 16384;$frozen=Origin-Pin 'qualification/source-frozen.json' 16MB
$mounts=Origin-Pin 'qualification/source-mount-paths.json' 65536
$stop=$null;$failures=@()
if($qualificationFailure){
 $failures=@((Origin-Pin 'failed.json' 16384),(Origin-Pin 'qualification/failed.json' 16384))
 if($failures[0].value.phase-cne'qualification'-or$failures[0].value.automatic_rollback_attempted-or$failures[1].value.kind-cne'live-general-qualification-failure'-or$failures[1].value.phase-cne'native-shadow-construction'-or$failures[1].value.execution_authorized-or$failures[1].value.source_payload_writes-ne0){throw 'Pinned source-unchanged shadow-construction refusal required.'}
}else{$stop=Origin-Pin 'preactivation-interruption-intent.json' 16384;Assert-Source $stop.value.binding}
Assert-Source $intent.value.pair.source;Assert-Source $frozen.value.binding;Assert-Source $mounts.value.binding
$blocked=@('request.json','ticket.json','journal-location.json','prepare.json','interruption-intent.json','apply.json','finalization.json','result.json','qualification/native-shadow.json','qualification/certificate.json')
foreach($name in $blocked){if(@($terminal.files|Where-Object {$_.name-ceq$name}).Count-or(Test-Path -LiteralPath (Join-Path $origin $name))){throw ('Later lifecycle artifact prevents controlled test: '+$name)}}
if($intent.value.experiment_id-cne$old.runId-or$frozen.value.kind-cne'observed-frozen-source-identity'-or$frozen.value.state.disk_attributes-ne3-or$frozen.value.source_payload_writes-ne0-or$frozen.value.source_sha256-cnotmatch'\A[0-9a-f]{64}\z'-or-not$mounts.value.all_paths_resolve_to_bound_volume-or@($mounts.value.paths).Count-ne1-or$mounts.value.paths[0]-cne'F:\'){throw 'Frozen identity or original mount differs.'}
if($stop){$s=$stop.value
 if($s.kind-cne'controlled-preactivation-interruption-intent'-or$s.experiment_id-cne$old.runId-or$s.phase-cne'source-frozen-artifact-durable'-or$s.expected_process_exit_code-ne87-or$s.disk_attributes-ne3-or$s.source_frozen_artifact-cne'qualification/source-frozen.json'-or$s.source_frozen_artifact_sha256-cne$frozen.sha256-or$s.source_sha256-cne$frozen.value.source_sha256-or$s.target_construction_started-or$s.journal_prepared-or$s.reconstruction_activated-or$s.handoff_authorized-or$s.source_payload_writes-ne0){throw 'Durable source-freeze interruption differs.'}
}
$fixturePath=Assert-LabPath $FixtureBeforePath $cfg.Root;$fixture=Read-Pin $fixturePath $FixtureBeforeSha256 65536
if([guid]$fixture.sourceGuid-ne[guid]'a01574d5-2a5c-4136-958a-dcf0d0e0f7aa'-or[guid]$fixture.partitionGuid-ne[guid]'79eaccdf-38d3-4561-97cc-9276af5d223a'-or$fixture.fileSystem-cne'NTFS'-or$fixture.label-cne'n2r-retained-source'-or$fixture.mount-cne'F:\'-or@($fixture.files).Count-ne4-or([DateTime]$fixture.capturedUtc).ToUniversalTime().Ticks-gt([DateTime]$old.startedUtc).ToUniversalTime().Ticks){throw 'Original prefreeze fixture differs.'}
foreach($path in @('source0.bin','archive\doc1.bin','archive\nested\doc2.bin','notes\doc3.bin')){$f=@($fixture.files|Where-Object {$_.path-ceq$path});if($f.Count-ne1-or$f[0].length-lt1-or$f[0].length-gt1MB-or$f[0].sha256-cnotmatch'\A[0-9a-f]{64}\z'){throw 'Fixture path/length/hash differs.'}}
$binary=Get-Item -LiteralPath $BinaryPath -Force
if($binary.PSIsContainer-or($binary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$binary.Length-gt16MB-or(Get-FileHash -LiteralPath $binary.FullName).Hash.ToLowerInvariant()-cne$BinarySha256){throw 'Pinned ordinary public executable required.'}
$step=[guid]::NewGuid().ToString('N');$task='N2R-PublicCancel-'+$step;$root='C:\ntfs2refs\public-cancel-inputs\'+$step;$result='C:\ntfs2refs\public-cancel\'+$step
$output=Assert-LabPath (Join-Path $cfg.Root ('public-cancel/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root;New-Item -ItemType Directory -Path $output|Out-Null
function Save-New([string]$Path,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));$f=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
$runner=@'
param([Parameter(Mandatory)][string]$Config,[Parameter(Mandatory)][string]$ConfigSha256)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
function Save([string]$Name,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));$f=[IO.File]::Open((Join-Path $c.output $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Check-Pin([string]$Path,[string]$Sha,[long]$Limit){$f=Get-Item -LiteralPath $Path -Force;if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-gt$Limit-or(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant()-cne$Sha){throw ('Runtime pin differs: '+$Path)}}
Check-Pin $Config $ConfigSha256 32768;$c=Get-Content -LiteralPath $Config -Raw|ConvertFrom-Json
Check-Pin $PSCommandPath $c.runnerSha256 65536;Check-Pin $c.cli $c.binarySha256 16MB;Check-Pin $c.fixture $c.fixtureSha256 65536
foreach($pin in $c.pins){Check-Pin (Join-Path $c.runDirectory $pin.name) $pin.sha256 $pin.limit}
if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'-or(Test-Path -LiteralPath $c.output)){throw 'Owned guest and fresh output required.'}
New-Item -ItemType Directory -Path $c.output|Out-Null;$phase='preflight'
try{
 $t=Get-ScheduledTask -TaskName $c.originalTask;$i=Get-ScheduledTaskInfo -TaskName $c.originalTask
 if($t.State-in@('Running','Queued')-or$i.LastRunTime.Year-lt2000-or$i.LastTaskResult-ne$c.originalExitCode-or@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.TaskName-cne$c.taskName-and$_.State-in@('Running','Queued')}).Count){throw 'Original/other operation may be live.'}
 $d=Get-Disk -Number 1;$p=Get-Partition -DiskNumber 1 -PartitionNumber 2
 if([guid]$d.Guid-ne[guid]'a01574d5-2a5c-4136-958a-dcf0d0e0f7aa'-or[guid]$p.Guid-ne[guid]'79eaccdf-38d3-4561-97cc-9276af5d223a'-or-not$d.IsOffline-or-not$d.IsReadOnly-or$d.IsBoot-or$d.IsSystem-or$p.IsBoot-or$p.IsSystem-or$d.Size-ne64GB-or$p.Size-ne52GB-or$p.Offset-ne16MB){throw 'Source identity/exclusion differs.'}
 foreach($name in $c.blockedArtifacts){if(Test-Path -LiteralPath (Join-Path $c.runDirectory $name)){throw 'Activation or construction artifact appeared.'}}
 Add-Type -TypeDefinition @"
using System;using System.Diagnostics;using System.IO;using System.Text;using System.Threading;
public sealed class N2RPublicCancelCapture {
 public int exitCode,processId;public string stdout,stderr,stdoutReadError,stderrReadError;public bool stdoutTruncated,stderrTruncated;public long stdoutCharacters,stderrCharacters;
 public static N2RPublicCancelCapture Run(string file,string arguments) {
  var r=new N2RPublicCancelCapture();var p=new Process();p.StartInfo=new ProcessStartInfo(file,arguments){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,RedirectStandardInput=true};
  if(!p.Start())throw new IOException("Public process did not start.");r.processId=p.Id;p.StandardInput.Close();var a=new StringBuilder();var b=new StringBuilder();
  var x=new Thread(()=>{try{Drain(p.StandardOutput,a,out r.stdoutCharacters,out r.stdoutTruncated);}catch(Exception e){r.stdoutReadError=e.ToString();}});var y=new Thread(()=>{try{Drain(p.StandardError,b,out r.stderrCharacters,out r.stderrTruncated);}catch(Exception e){r.stderrReadError=e.ToString();}});x.Start();y.Start();p.WaitForExit();x.Join();y.Join();r.exitCode=p.ExitCode;r.stdout=a.ToString();r.stderr=b.ToString();p.Dispose();return r;
 }
 static void Drain(StreamReader reader,StringBuilder text,out long total,out bool truncated){total=0;var buffer=new char[1024];int n;while((n=reader.Read(buffer,0,buffer.Length))!=0){total+=n;int keep=Math.Min(n,65536-text.Length);if(keep>0)text.Append(buffer,0,keep);}truncated=total>65536;}
}
"@
 $envelope=' --run-directory "'+$c.runDirectory+'" --intent-sha256 '+$c.intentSha256+' --frozen-source-sha256 '+$c.frozenSha256+' --mount-paths-sha256 '+$c.mountsSha256
 $phase='operation-state';$status=[N2RPublicCancelCapture]::Run($c.cli,'operation-state'+$envelope+' --output "'+$c.output+'\state"');Save 'status-process.json' $status
 if($status.exitCode-ne0-or$status.stdoutTruncated-or$status.stderrTruncated-or$status.stdoutReadError-or$status.stderrReadError){throw 'Status failed or output capture was incomplete/bounded.'}
 $state=Get-Content -LiteralPath ($c.output+'\state\state.json') -Raw|ConvertFrom-Json
 if($state.kind-cne'read-only-public-operation-state'-or$state.state-cne'frozen_before_activation'-or-not(@($state.can_request)-ccontains'cancel')-or$state.execution_authorized-or$state.disk_attributes_changed-or$state.source_payload_writes-ne0-or$state.source.disk_attributes-ne3){throw 'Readonly status did not establish cancellation candidate.'}
 foreach($pin in $c.pins){Check-Pin (Join-Path $c.runDirectory $pin.name) $pin.sha256 $pin.limit}
 $phase='cancel';$cancel=[N2RPublicCancelCapture]::Run($c.cli,'cancel'+$envelope+' --output "'+$c.output+'\cancel"');Save 'cancel-process.json' $cancel
 if($cancel.exitCode-ne0-or$cancel.stdoutTruncated-or$cancel.stderrTruncated-or$cancel.stdoutReadError-or$cancel.stderrReadError){throw 'Cancel failed or output capture was incomplete/bounded.'}
 $native=Get-Content -LiteralPath ($c.output+'\cancel\result.json') -Raw|ConvertFrom-Json
 if($native.kind-cne'public-preactivation-cancel'-or-not$native.success-or$native.source_sha256-cne$c.sourceSha256-or$native.source_payload_writes-ne0-or$native.journal_mutations-ne0-or$native.raw_reconstruction_authorized){throw 'Public cancel result differs.'}
 $phase='fixture-after';$before=Get-Content -LiteralPath $c.fixture -Raw|ConvertFrom-Json
 $d=Get-Disk -Number 1;$p=Get-Partition -DiskNumber 1 -PartitionNumber 2;$v=$p|Get-Volume
 if($d.IsOffline-or$d.IsReadOnly-or[guid]$d.Guid-ne[guid]$before.sourceGuid-or[guid]$p.Guid-ne[guid]$before.partitionGuid-or$v.FileSystem-cne'NTFS'-or$v.FileSystemLabel-cne$before.label-or[string]$p.DriveLetter-cne'F'){throw 'Original NTFS availability differs.'}
 $files=@(foreach($item in $before.files){$path=Join-Path 'F:\' $item.path;$f=Get-Item -LiteralPath $path -Force;if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-ne$item.length){throw 'Fixture type/length differs.'};$sha=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant();if($sha-cne$item.sha256){throw 'Fixture logical hash differs.'};[pscustomobject]@{path=$item.path;length=$f.Length;sha256=$sha}})
 Save 'fixture-after.json' ([ordered]@{sourceGuid=[string]$d.Guid;partitionGuid=[string]$p.Guid;fileSystem=$v.FileSystem;label=$v.FileSystemLabel;mount='F:\';files=$files;capturedUtc=[DateTime]::UtcNow.ToString('o')})
 Save 'runner-result.json' ([ordered]@{kind='public-cancel-runner-result';success=$true;statusExitCode=$status.exitCode;cancelExitCode=$cancel.exitCode;filesVerified=$files.Count;sourceSha256=$c.sourceSha256;sourceHashScope='complete partition before original NTFS writable mount';rawReplayAuthorized=$false;completedUtc=[DateTime]::UtcNow.ToString('o')});exit 0
}catch{Save 'runner-failed.json' ([ordered]@{kind='public-cancel-runner-failure';phase=$phase;error=$_.Exception.ToString();automaticRetry=$false;capturedUtc=[DateTime]::UtcNow.ToString('o')});exit 1}
'@
$runnerPath=Join-Path $output 'runner.ps1';[IO.File]::WriteAllText($runnerPath,$runner,[Text.UTF8Encoding]::new($false));$runnerSha=(Get-FileHash -LiteralPath $runnerPath).Hash.ToLowerInvariant()
$proofs=if($stop){@($stop)}else{$failures}
$pins=@($intent,$frozen,$mounts)+$proofs|ForEach-Object {[ordered]@{name=$_.name;sha256=$_.sha256;limit=$_.limit}}
$config=[ordered]@{schemaVersion=1;kind='public-cancel-runner-config';mode=$Mode;originalExitCode=$originalExitCode;stepId=$step;taskName=$task;originalTask=$old.taskName;runDirectory=$old.guestOutput;output=$result;cli=$root+'\public-cli.exe';binarySha256=$BinarySha256;fixture=$root+'\fixture-before.json';fixtureSha256=$FixtureBeforeSha256;runnerSha256=$runnerSha;pins=@($pins);blockedArtifacts=$blocked;intentSha256=$intent.sha256;frozenSha256=$frozen.sha256;mountsSha256=$mounts.sha256;sourceSha256=$frozen.value.source_sha256}
Save-New (Join-Path $output 'config.json') $config;$configSha=(Get-FileHash -LiteralPath (Join-Path $output 'config.json')).Hash.ToLowerInvariant()
Copy-Item -LiteralPath $fixturePath -Destination (Join-Path $output 'fixture-before.json')
Save-New (Join-Path $output 'dispatch.json') ([ordered]@{schemaVersion=1;kind='public-cancel-dispatch';mode=$Mode;originalExitCode=$originalExitCode;stepId=$step;originRunId=$old.runId;originDirectory=$origin;taskName=$task;guestRoot=$root;guestOutput=$result;vmId=[string]$vm.Id;checkpointId=[string]$vm.ParentSnapshotId;binarySha256=$BinarySha256;runnerSha256=$runnerSha;configSha256=$configSha;fixtureBeforeSha256=$FixtureBeforeSha256;sourceSha256=$frozen.value.source_sha256;intentSha256=$intent.sha256;frozenSha256=$frozen.sha256;mountsSha256=$mounts.sha256;interruptionSha256=if($stop){$stop.sha256}else{$null};startedUtc=[DateTime]::UtcNow.ToString('o')})
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop
 $preflight=Invoke-Command -Session $session -ArgumentList @($old.taskName,$old.guestOutput,$pins,$blocked,$root,$result,$originalExitCode) -ScriptBlock {
  param($Task,$Artifacts,$Pins,$Blocked,$Root,$Output,$OriginalExitCode);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  $t=Get-ScheduledTask -TaskName $Task;$i=Get-ScheduledTaskInfo -TaskName $Task
  if($t.State-in@('Running','Queued')-or$i.LastRunTime.Year-lt2000-or$i.LastTaskResult-ne$OriginalExitCode-or@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count){throw 'Original operation is live/unknown or not exit87.'}
  $d=Get-Disk -Number 1;$p=Get-Partition -DiskNumber 1 -PartitionNumber 2
  if($env:COMPUTERNAME-cne'N2R-WIN11'-or$d.Size-ne64GB-or$p.Size-ne52GB-or$p.Offset-ne16MB-or[guid]$d.Guid-ne[guid]'a01574d5-2a5c-4136-958a-dcf0d0e0f7aa'-or[guid]$p.Guid-ne[guid]'79eaccdf-38d3-4561-97cc-9276af5d223a'-or-not$d.IsOffline-or-not$d.IsReadOnly-or$d.IsBoot-or$d.IsSystem-or$p.IsBoot-or$p.IsSystem-or$d.LogicalSectorSize-ne512-or$d.PhysicalSectorSize-ne4096){throw 'Source exclusion/hardware/geometry differs.'}
  foreach($pin in $Pins){$path=Join-Path $Artifacts $pin.name;$f=Get-Item -LiteralPath $path -Force;if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-gt$pin.limit-or(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$pin.sha256){throw 'Actual guest artifact pin differs.'}}
  foreach($name in $Blocked){if(Test-Path -LiteralPath (Join-Path $Artifacts $name)){throw 'Construction/activation artifact appeared.'}}
  if((Test-Path -LiteralPath $Root)-or(Test-Path -LiteralPath $Output)){throw 'Fresh guest paths required.'};New-Item -ItemType Directory -Path $Root|Out-Null
  [pscustomobject]@{originalExitCode=$i.LastTaskResult;sourceOffline=$d.IsOffline;sourceReadOnly=$d.IsReadOnly;checkedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 Save-New (Join-Path $output 'preflight.json') $preflight
 foreach($entry in @(@($binary.FullName,'public-cli.exe'),@($runnerPath,'runner.ps1'),@((Join-Path $output 'config.json'),'config.json'),@($fixturePath,'fixture-before.json'))){Copy-Item -LiteralPath $entry[0] -Destination ($root+'\'+$entry[1]) -ToSession $session}
 $launched=Invoke-Command -Session $session -ArgumentList @($root,$task,$BinarySha256,$runnerSha,$configSha,$FixtureBeforeSha256) -ScriptBlock {
  param($Root,$Task,$ExeSha,$RunnerSha,$ConfigSha,$FixtureSha);$ErrorActionPreference='Stop'
  foreach($pair in @(@('public-cli.exe',$ExeSha),@('runner.ps1',$RunnerSha),@('config.json',$ConfigSha),@('fixture-before.json',$FixtureSha))){if((Get-FileHash -LiteralPath ($Root+'\'+$pair[0])).Hash.ToLowerInvariant()-cne$pair[1]){throw 'Copied cancel input differs.'}}
  if(@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count){throw 'Another operation began before dispatch.'}
  $action=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$Root+'\runner.ps1" -Config "'+$Root+'\config.json" -ConfigSha256 '+$ConfigSha)
  Register-ScheduledTask -TaskName $Task -Action $action -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null;Start-ScheduledTask -TaskName $Task
  [pscustomobject]@{taskName=$Task;state=[string](Get-ScheduledTask -TaskName $Task).State;dispatchedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 Save-New (Join-Path $output 'task.json') $launched
 [pscustomobject]@{directory=$output;taskName=$task;guestOutput=$result;state=$launched.state}
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
