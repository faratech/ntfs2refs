<# Observe the existing-tree source through native NTFS with physical read-only
   protection. Re-exclude and hash the actual device before restoring baseline. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$SourceDirectory,
 [Parameter(Mandatory)][string]$VerifyBinaryPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$VerifyBinarySha256)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot;Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$source=Assert-LabPath $SourceDirectory $cfg.Root
$validated=& (Join-Path $workspace 'lab/Test-ExistingTreeFreezeArchive.ps1') -Directory $source
$review=Get-Content (Join-Path $source 'completion-review.json') -Raw|ConvertFrom-Json
$start=Get-Content (Join-Path $source 'started.json') -Raw|ConvertFrom-Json
$binding=(Get-Content (Join-Path $source 'freeze-request.json') -Raw|ConvertFrom-Json).source
if($vm.State-ne'Off'-or$vm.MemoryStartup-ne4GB-or[guid]$vm.ParentSnapshotId-ne[guid]'eda059b3-6d50-46bb-bdf4-018b99b5b34f'-or$review.sourceSha256-cne$validated.sourceSha256){throw 'Verified source and clean baseline required.'}
Assert-LabCapacity (Get-LabCapacity $cfg) -AdditionalBytes 1GB
$cp=Get-ExactLabCheckpoint -VM $vm -Name $review.sourceCheckpointName
if($cp.Id-ne[guid]$review.sourceCheckpointId-or$cp.State-ne'Off'-or$cp.MemoryStartup-ne8GB){throw 'Source snapshot differs.'}
$verify=Get-Item -LiteralPath $VerifyBinaryPath -Force
if($verify.PSIsContainer-or($verify.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$verify.Length-gt16MB-or(Get-FileHash $verify.FullName).Hash.ToLowerInvariant()-cne$VerifyBinarySha256){throw 'Pinned revalidation binary required.'}
$observation=[guid]::NewGuid().ToString('N');$root='C:\ntfs2refs\existing-tree\'+$start.runId
$output=Assert-LabPath (Join-Path $cfg.Root ('existing-tree-attestation/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
New-Item -ItemType Directory -Path $output|Out-Null
function Save([string]$Name,$Value){$p=Join-Path $output $Name;$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 32));$f=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
$record=[ordered]@{schemaVersion=1;kind='existing-tree-native-observation';runId=$start.runId;observationId=$observation;sourceDirectory=$source;sourceCheckpointId=[string]$cp.Id;sourceSha256=$validated.sourceSha256;status='started';operationCompletionKnown=$true;error=$null;sourceAdmitted=$false;conversionQualified=$false}
$collector=Join-Path $source 'lab-ntfs-attest.exe';$request=Join-Path $source 'native-request.json'
$collectorSha=(Get-FileHash $collector).Hash.ToLowerInvariant();$requestSha=(Get-FileHash $request).Hash.ToLowerInvariant()
$record['collectorSha256']=$collectorSha;$record['requestSha256']=$requestSha;$record['verifyBinarySha256']=$VerifyBinarySha256
Copy-Item -LiteralPath $collector -Destination (Join-Path $output 'lab-ntfs-attest.exe');Copy-Item -LiteralPath $verify.FullName -Destination (Join-Path $output 'lab-ntfs-source-verify.exe');Copy-Item -LiteralPath $request -Destination (Join-Path $output 'request.json')
$pins=@();foreach($path in @('src/bin/lab-ntfs-attest.rs','src/bin/lab-ntfs-freeze.rs','src/ntfs_freeze.rs','src/ntfs_attestation.rs','crates/n2r-win32/src/attestation_native.rs','crates/n2r-win32/src/attestation.rs','crates/n2r-win32/src/stream_native.rs','crates/n2r-win32/src/namespace_native.rs','scripts/Capture-LabExistingTreeAttestation.ps1','Cargo.lock')){$to=Join-Path $output ('sources/'+$path);New-Item -ItemType Directory -Path (Split-Path $to -Parent) -Force|Out-Null;Copy-Item -LiteralPath (Join-Path $workspace $path) -Destination $to;$pins+=@([ordered]@{path=$path;sha256=(Get-FileHash $to).Hash.ToLowerInvariant()})};Save 'sources.json' $pins;Save 'started.json' $record
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null;$job=$null
try{
 Restore-VMSnapshot -VMSnapshot $cp -Confirm:$false;$vm=Get-OwnedLabVM $cfg $manifest
 if($vm.State-ne'Off'-or$vm.ParentSnapshotId-ne$cp.Id){throw 'Source restore incomplete.'};Start-VM -VM $vm|Out-Null
 $deadline=[DateTime]::UtcNow.AddSeconds(240)
 do{try{$session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop;break}catch{Start-Sleep -Seconds 2}}while([DateTime]::UtcNow-lt$deadline)
 if(-not$session){throw 'Guest session unavailable.'}
 Copy-Item -LiteralPath $collector -Destination ($root+'\observer-'+$observation+'.exe') -ToSession $session
 Copy-Item -LiteralPath $request -Destination ($root+'\observer-'+$observation+'.request.json') -ToSession $session
 Copy-Item -LiteralPath $verify.FullName -Destination ($root+'\verify-'+$observation+'.exe') -ToSession $session
 $record.operationCompletionKnown=$false
 $job=Invoke-Command -Session $session -AsJob -ArgumentList @($root,$observation,$binding,$collectorSha,$requestSha,$VerifyBinarySha256,$validated.sourceSha256) -ScriptBlock {
  param($Root,$Observation,$Binding,$CollectorSha,$RequestSha,$VerifySha,$SourceSha)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  function Disk([bool]$Offline){$d=Get-Disk -Number 1;if($d.UniqueId-cne'60022480D091C4251B5FFD619706C2B5'-or[guid]$d.Guid-ne[guid]$Binding.identity.disk_guid-or$d.Size-ne64GB-or$d.IsBoot-or$d.IsSystem-or-not$d.IsReadOnly-or$d.IsOffline-ne$Offline){throw 'Expected read-only source state differs.'};$d}
  $collector=$Root+'\observer-'+$Observation+'.exe';$request=$Root+'\observer-'+$Observation+'.request.json';$verify=$Root+'\verify-'+$Observation+'.exe'
  foreach($pin in @(@($collector,$CollectorSha),@($request,$RequestSha),@($verify,$VerifySha))){if((Get-FileHash $pin[0]).Hash.ToLowerInvariant()-cne$pin[1]){throw 'Copied artifact pin differs.'}}
  function Process([string]$Executable,[string]$Arguments,[string]$Name,[int]$Timeout){
   $psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName=$Executable;$psi.Arguments=$Arguments;$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
   $p=[Diagnostics.Process]::new();$p.StartInfo=$psi;if(-not$p.Start()){throw 'Native process did not start.'};$stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync()
   [IO.File]::WriteAllText($Root+'\'+$Observation+'.'+$Name+'.process.json',([ordered]@{pid=$p.Id;executable=$Executable;arguments=$Arguments;startedUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json))
   if(-not$p.WaitForExit($Timeout*1000)){throw ('Native process still live; preserve PID '+$p.Id)}
   [IO.File]::WriteAllText($Root+'\'+$Observation+'.'+$Name+'.stdout',$stdout.Result);[IO.File]::WriteAllText($Root+'\'+$Observation+'.'+$Name+'.stderr',$stderr.Result)
   [pscustomobject]@{exitCode=$p.ExitCode;stdout=$stdout.Result;stderr=$stderr.Result}
  }
  [void](Disk $true);Set-Disk -Number 1 -IsOffline $false;[void](Disk $false)
  $native=$Root+'\'+$Observation+'.native.json'
  $collected=Process $collector ('collect --request "'+$request+'" --request-sha256 '+$RequestSha+' --output "'+$native+'"') 'collector' 180
  if($collected.exitCode-ne0){throw ('Collector failed; preserve read-only source: '+$collected.stderr)}
  [void](Disk $false)
  $queries=@();$fsutil=Join-Path $env:SystemRoot 'System32\fsutil.exe'
  foreach($args in @('8dot3name query','8dot3name query F:','dirty query F:','quota query F:','resource info F:\')){$q=Process $fsutil $args ('query'+$queries.Count) 60;$queries+=@([ordered]@{arguments=$args;result=$q})}
  $health=Process (Join-Path $env:SystemRoot 'System32\chkdsk.exe') 'F:' 'readonly-chkdsk' 180
  [IO.File]::WriteAllText($Root+'\'+$Observation+'.state.json',([ordered]@{queries=$queries;readonlyChkdsk=$health;sourceReadonly=(Get-Disk -Number 1).IsReadOnly}|ConvertTo-Json -Depth 8))
  [void](Disk $false);Set-Disk -Number 1 -IsOffline $true;[void](Disk $true)
  $proof=$Root+'\'+$Observation+'.revalidation.json';$freezeRequest=$Root+'\freeze-request.json';$freezeSha=(Get-FileHash $freezeRequest).Hash.ToLowerInvariant()
  $checked=Process $verify ('--request "'+$freezeRequest+'" --request-sha256 '+$freezeSha+' --output "'+$proof+'" --reopen --verify-source-sha256 '+$SourceSha) 'revalidation' 900
  if($checked.exitCode-ne0){throw ('Full source revalidation failed: '+$checked.stderr)}
  [void](Disk $true)
  [pscustomobject]@{status='observed-source-unchanged';nativeSha256=(Get-FileHash $native).Hash.ToLowerInvariant();stateSha256=(Get-FileHash ($Root+'\'+$Observation+'.state.json')).Hash.ToLowerInvariant();revalidationSha256=(Get-FileHash $proof).Hash.ToLowerInvariant();chkdskExitCode=$health.exitCode}
 }
 if(-not(Wait-Job -Job $job -Timeout 1800)){throw 'Guest operation still live/unknown; preserve branch.'}
 $reply=@(Receive-Job $job -ErrorAction Stop);if($job.State-ne'Completed'-or$reply.Count-ne1-or$reply[0].status-cne'observed-source-unchanged'){throw 'Observation did not complete.'};$record.operationCompletionKnown=$true;Save 'guest-reply.json' $reply[0]
 foreach($name in @('native.json','state.json','revalidation.json')){Copy-Item -LiteralPath ($root+'\'+$observation+'.'+$name) -Destination (Join-Path $output $name) -FromSession $session}
 foreach($phase in @('collector','readonly-chkdsk','revalidation','query0','query1','query2','query3','query4')){foreach($suffix in @('process.json','stdout','stderr')){
  $path=$root+'\'+$observation+'.'+$phase+'.'+$suffix
  $meta=Invoke-Command -Session $session -ArgumentList $path -ScriptBlock {param($Path);$f=Get-Item -LiteralPath $Path -Force;if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-gt128KB){throw 'Invalid process artifact.'};[pscustomobject]@{length=$f.Length;sha256=(Get-FileHash $Path).Hash.ToLowerInvariant()}}
  $to=Join-Path $output ($phase+'.'+$suffix);Copy-Item -LiteralPath $path -Destination $to -FromSession $session
  if((Get-Item $to).Length-ne$meta.length-or(Get-FileHash $to).Hash.ToLowerInvariant()-cne$meta.sha256){throw 'Process artifact export differs.'}
 }}
 foreach($pair in @(@('native.json',$reply[0].nativeSha256),@('state.json',$reply[0].stateSha256),@('revalidation.json',$reply[0].revalidationSha256))){if((Get-FileHash (Join-Path $output $pair[0])).Hash.ToLowerInvariant()-cne$pair[1]){throw 'Export differs.'}}
 $inspection=Join-Path $source 'freeze.inspection.json'
 & $collector compare --inspection $inspection --inspection-sha256 (Get-FileHash $inspection).Hash.ToLowerInvariant() --native (Join-Path $output 'native.json') --native-sha256 $reply[0].nativeSha256 --output (Join-Path $output 'comparison.json') --admission-output (Join-Path $output 'admission.json')
 if($LASTEXITCODE-ne0){throw 'Native comparison failed.'}
 Invoke-Command -Session $session -ScriptBlock {& shutdown.exe /s /t 0;if($LASTEXITCODE-ne0){throw 'Shutdown request failed.'}}|Out-Null
 $deadline=[DateTime]::UtcNow.AddSeconds(180);do{$vm=Get-OwnedLabVM $cfg $manifest;if($vm.State-eq'Off'){break};Start-Sleep -Seconds 2}while([DateTime]::UtcNow-lt$deadline)
 if($vm.State-ne'Off'){throw 'Guest still running.'};Remove-PSSession $session;$session=$null
 $baseline=Get-ExactLabCheckpoint -VM $vm -Name installed-clean
 if($baseline.Id-ne[guid]'eda059b3-6d50-46bb-bdf4-018b99b5b34f'){throw 'Baseline identity differs.'};Restore-VMSnapshot -VMSnapshot $baseline -Confirm:$false
 for($i=0;$i-lt15;$i++){$vm=Get-OwnedLabVM $cfg $manifest;if($vm.State-eq'Off'-and$vm.MemoryStartup-eq4GB-and$vm.ParentSnapshotId-eq$baseline.Id){break};Start-Sleep -Seconds 1}
 if($vm.State-ne'Off'-or$vm.MemoryStartup-ne4GB-or$vm.ParentSnapshotId-ne$baseline.Id){throw 'Baseline restoration not verified.'}
 $record.status='native-observations-captured-source-unchanged';$record['nativeSha256']=$reply[0].nativeSha256;$record['revalidationSha256']=$reply[0].revalidationSha256
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();$record['errorPosition']=$_.InvocationInfo.PositionMessage;throw}
finally{$record['finishedUtc']=[DateTime]::UtcNow.ToString('o');Save 'host-result.json' $record;if($job-and$job.State-in@('Completed','Failed','Stopped')){Remove-Job $job -Force};if($session-and$record.operationCompletionKnown){Remove-PSSession $session -ErrorAction SilentlyContinue}}
[pscustomobject]$record
