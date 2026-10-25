<# Build an independent native ReFS shadow of the frozen natural tree. Source
   remains persistently offline/read-only; no source moves or reconstruction. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$SourceDirectory,
 [Parameter(Mandatory)][string]$BinaryPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BinarySha256,
 [switch]$OrdinaryFiles,
 [switch]$StreamPayload)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
if($StreamPayload-and-not$OrdinaryFiles){throw 'Streaming payloads require the ordinary-files profile.'}
$workspace=Split-Path -Parent $PSScriptRoot;Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$source=Assert-LabPath $SourceDirectory $cfg.Root
$validated=& (Join-Path $workspace 'lab/Test-ExistingTreeFreezeArchive.ps1') -Directory $source
$review=Get-Content (Join-Path $source 'completion-review.json') -Raw|ConvertFrom-Json
$binding=(Get-Content (Join-Path $source 'freeze-request.json') -Raw|ConvertFrom-Json).source
if($vm.State-ne'Off'-or$vm.MemoryStartup-ne4GB-or[guid]$vm.ParentSnapshotId-ne[guid]'eda059b3-6d50-46bb-bdf4-018b99b5b34f'){throw 'Clean stopped baseline required.'}
# The preceding measured branch used about 4 GB, chiefly OS differencing data.
# Reserve that full footprint before boot; preserve the 64 GiB host reserve.
Assert-LabCapacity (Get-LabCapacity $cfg) -AdditionalBytes 4GB
$cp=Get-ExactLabCheckpoint -VM $vm -Name $review.sourceCheckpointName
if($cp.Id-ne[guid]$review.sourceCheckpointId-or$cp.State-ne'Off'-or$cp.MemoryStartup-ne8GB){throw 'Source snapshot differs.'}
$binary=Get-Item -LiteralPath $BinaryPath -Force
if($binary.PSIsContainer-or($binary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$binary.Length-gt16MB-or(Get-FileHash $binary.FullName).Hash.ToLowerInvariant()-cne$BinarySha256){throw 'Pinned shadow binary required.'}
$run=[guid]::NewGuid().ToString('N');$root='C:\ntfs2refs\tree-shadow\'+$run
$output=Assert-LabPath (Join-Path $cfg.Root ('existing-tree-shadow/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
New-Item -ItemType Directory -Path $output|Out-Null
function Save([string]$Name,$Value){$p=Join-Path $output $Name;$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 32));$f=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
$record=[ordered]@{schemaVersion=1;kind='existing-tree-shadow-build';runId=$run;sourceDirectory=$source;sourceCheckpointId=[string]$cp.Id;sourceSha256=$validated.sourceSha256;binarySha256=$BinarySha256;ordinaryFiles=[bool]$OrdinaryFiles;streamPayload=[bool]$StreamPayload;status='started';operationCompletionKnown=$true;error=$null;sourceAdmitted=$false;conversionQualified=$false}
Copy-Item -LiteralPath $binary.FullName -Destination (Join-Path $output 'lab-tree-shadow.exe')
$helpers=@('lab/guest/GuestLab.psm1','lab/guest/Register-GuestDisk.ps1','lab/guest/Prepare-GuestShadowPlatform.ps1','lab/guest/NativeShadowDisk.cs')
$pins=@();foreach($path in @($helpers)+@('src/bin/lab-tree-shadow.rs','src/shadow_tree.rs','src/tree_placement.rs','crates/n2r-win32/src/shadow_native.rs','crates/n2r-win32/src/region_layout.rs','crates/n2r-win32/src/bitmap_layout.rs','crates/n2r-win32/src/attestation_native.rs','crates/n2r-win32/src/native.rs','src/ntfs_freeze.rs','scripts/Build-LabExistingTreeShadow.ps1','Cargo.toml','crates/n2r-win32/Cargo.toml','.cargo/config.toml','Cargo.lock')){
 $to=Join-Path $output ('sources/'+$path);New-Item -ItemType Directory -Path (Split-Path $to -Parent) -Force|Out-Null;Copy-Item -LiteralPath (Join-Path $workspace $path) -Destination $to;$pins+=@([ordered]@{path=$path;sha256=(Get-FileHash $to).Hash.ToLowerInvariant()})
};Save 'sources.json' $pins;Save 'started.json' $record
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null;$job=$null
try{
 Restore-VMSnapshot -VMSnapshot $cp -Confirm:$false
 for($i=0;$i-lt15;$i++){$vm=Get-OwnedLabVM $cfg $manifest;if($vm.State-eq'Off'-and$vm.ParentSnapshotId-eq$cp.Id){break};Start-Sleep -Seconds 1}
 if($vm.State-ne'Off'-or$vm.ParentSnapshotId-ne$cp.Id){throw 'Source restore incomplete.'};Start-VM -VM $vm|Out-Null
 $deadline=[DateTime]::UtcNow.AddSeconds(240)
 do{try{$session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop;break}catch{Start-Sleep -Seconds 2}}while([DateTime]::UtcNow-lt$deadline)
 if(-not$session){throw 'Guest session unavailable.'}
 $sessionProof=Initialize-LabGuestSession -Session $session;Save 'session.json' $sessionProof
 if($sessionProof.status-cne'ready'){throw 'Guest session policy initialization refused.'}
 Invoke-Command -Session $session -ArgumentList $root -ScriptBlock {param($Root);foreach($p in @('C:\ntfs2refs\tree-shadow',$Root,($Root+'\helpers'))){if(Test-Path -LiteralPath $p){$m=Get-Item -LiteralPath $p -Force;if(-not$m.PSIsContainer-or($m.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary directory required.'}}else{New-Item -ItemType Directory -Path $p|Out-Null}}}|Out-Null
 Copy-Item -LiteralPath $binary.FullName -Destination ($root+'\lab-tree-shadow.exe') -ToSession $session
 foreach($p in $helpers){Copy-Item -LiteralPath (Join-Path $workspace $p) -Destination ($root+'\helpers\'+[IO.Path]::GetFileName($p)) -ToSession $session}
 $record.operationCompletionKnown=$false
 $job=Invoke-Command -Session $session -AsJob -ArgumentList @($root,$run,$binding,$validated.sourceSha256,$BinarySha256,$pins,[bool]$OrdinaryFiles,[bool]$StreamPayload) -ScriptBlock {
  param($Root,$Run,$Source,$SourceSha,$BinarySha,$Pins,$OrdinaryFiles,$StreamPayload)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  function CheckSource{ $d=Get-Disk -Number 1;if($d.UniqueId-cne'60022480D091C4251B5FFD619706C2B5'-or[guid]$d.Guid-ne[guid]$Source.identity.disk_guid-or$d.Size-ne64GB-or$d.IsBoot-or$d.IsSystem-or-not$d.IsReadOnly-or-not$d.IsOffline){throw 'Source exclusion or identity differs.'} }
  CheckSource
  if((Get-FileHash ($Root+'\lab-tree-shadow.exe')).Hash.ToLowerInvariant()-cne$BinarySha){throw 'Copied binary differs.'}
  foreach($p in $Pins|Where-Object path -like 'lab/guest/*'){$local=$Root+'\helpers\'+[IO.Path]::GetFileName($p.path);if((Get-FileHash $local).Hash.ToLowerInvariant()-cne$p.sha256){throw 'Copied helper differs.'}}
  & ($Root+'\helpers\Register-GuestDisk.ps1') -UniqueId '600224806AAC261F021F249596F332FC' -Role journal -OutputPath ($Root+'\journal-enrollment.json') -Confirm:$false|Out-Null
  & ($Root+'\helpers\Prepare-GuestShadowPlatform.ps1') -RunId $Run -JournalManifestPath ($Root+'\journal-enrollment.json') -Confirm:$false|Out-Null
  $platformPath='C:\ntfs2refs\shadow-platform\'+$Run+'\prepare.json';$platform=Get-Content $platformPath -Raw|ConvertFrom-Json
  if($platform.status-cne'shadow-platform-prepared'-or-not$platform.nativeOperationCompletionKnown-or-not$platform.attachmentRetained-or-not$platform.handleCloseSucceeded-or-not$platform.privilegeRestored-or$platform.sourceTargetWriteRequestsIssued){throw 'Shadow platform incomplete; preserve branch.'}
  Copy-Item -LiteralPath $platformPath -Destination ($Root+'\platform.json');CheckSource
  $s=$platform.shadow
  if($s.volumeGuid -cnotmatch '\A\\\\\?\\Volume\{(?<id>[0-9a-fA-F-]{36})\}\\\z'){throw 'Shadow volume GUID syntax differs.'};$volumeGuid=([guid]$Matches.id).ToString('D')
  $request=[ordered]@{schema_version=1;source=$Source;source_sha256=$SourceSha;shadow=[ordered]@{disk_number=$s.diskNumber;volume_guid=$volumeGuid;identity=[ordered]@{disk_guid=$s.diskGuid;partition_guid=$s.partitionGuid;partition_number=$s.partitionNumber;disk_bytes=64GB;partition_offset=$s.offset;partition_bytes=$s.length;logical_sector_bytes=$s.logicalSectorSize;physical_sector_bytes=$s.physicalSectorSize}}}
  $requestPath=$Root+'\request.json';$b=[Text.UTF8Encoding]::new($false).GetBytes(($request|ConvertTo-Json -Depth 8));[IO.File]::WriteAllBytes($requestPath,$b);$requestSha=(Get-FileHash $requestPath).Hash.ToLowerInvariant()
  $psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName=$Root+'\lab-tree-shadow.exe';$psi.Arguments='--request "'+$requestPath+'" --request-sha256 '+$requestSha+' --output "'+$Root+'\shadow.json"';if($OrdinaryFiles){$psi.Arguments+=' --ordinary-files'};if($StreamPayload){$psi.Arguments+=' --stream-payload'};$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
  $p=[Diagnostics.Process]::new();$p.StartInfo=$psi;if(-not$p.Start()){throw 'Shadow process failed to start.'};$stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync()
  [IO.File]::WriteAllText($Root+'\process.json',([ordered]@{pid=$p.Id;executable=$psi.FileName;arguments=$psi.Arguments;startedUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json))
  if(-not$p.WaitForExit(900000)){throw ('Native process still live; preserve PID '+$p.Id)}
  [IO.File]::WriteAllText($Root+'\stdout',$stdout.Result);[IO.File]::WriteAllText($Root+'\stderr',$stderr.Result);CheckSource
  $proof=Get-Content ($Root+'\shadow.json') -Raw|ConvertFrom-Json
  [pscustomobject]@{status=if($p.ExitCode-eq0-and$proof.success){'shadow-verified'}else{'shadow-failed-terminal'};exitCode=$p.ExitCode;requestSha256=$requestSha;shadowSha256=(Get-FileHash ($Root+'\shadow.json')).Hash.ToLowerInvariant();platformSha256=(Get-FileHash ($Root+'\platform.json')).Hash.ToLowerInvariant()}
 }
 # A live/unknown job must be observed in place, never killed or retried.
 if(-not(Wait-Job -Job $job -Timeout 1200)){throw 'Guest operation live/unknown; preserve branch.'}
 $reply=@(Receive-Job $job -ErrorAction Stop);if($job.State-ne'Completed'-or$reply.Count-ne1-or$reply[0].status-notin@('shadow-verified','shadow-failed-terminal')){throw 'Guest completion not established.'}
 $record.operationCompletionKnown=$true;Save 'guest-reply.json' $reply[0]
 foreach($name in @('request.json','platform.json','process.json','stdout','stderr','shadow.intent.json','shadow.json','journal-enrollment.json')){Copy-Item -LiteralPath ($root+'\'+$name) -Destination (Join-Path $output $name) -FromSession $session}
 if((Get-FileHash (Join-Path $output 'shadow.json')).Hash.ToLowerInvariant()-cne$reply[0].shadowSha256){throw 'Shadow evidence export differs.'}
 if($reply[0].status-ne'shadow-verified'){throw 'Native shadow failed; terminal evidence exported, preserve branch.'}
 Invoke-Command -Session $session -ScriptBlock {& shutdown.exe /s /t 0;if($LASTEXITCODE-ne0){throw 'Shutdown failed.'}}|Out-Null
 $deadline=[DateTime]::UtcNow.AddSeconds(180);do{$vm=Get-OwnedLabVM $cfg $manifest;if($vm.State-eq'Off'){break};Start-Sleep -Seconds 2}while([DateTime]::UtcNow-lt$deadline)
 if($vm.State-ne'Off'){throw 'Guest still running.'};Remove-PSSession $session;$session=$null
 $name='existing-tree-shadow-'+$run;Checkpoint-VM -VM $vm -SnapshotName $name
 $saved=Get-ExactLabCheckpoint -VM $vm -Name $name
 if($saved.State-ne'Off'-or$saved.MemoryStartup-ne8GB){throw 'Shadow checkpoint state differs.'}
 $record['shadowCheckpointId']=[string]$saved.Id;$record['shadowCheckpointName']=$name
 $baseline=Get-ExactLabCheckpoint -VM $vm -Name installed-clean
 if($baseline.Id-ne[guid]'eda059b3-6d50-46bb-bdf4-018b99b5b34f'){throw 'Baseline differs.'};Restore-VMSnapshot -VMSnapshot $baseline -Confirm:$false
 for($i=0;$i-lt15;$i++){$vm=Get-OwnedLabVM $cfg $manifest;if($vm.State-eq'Off'-and$vm.MemoryStartup-eq4GB-and$vm.ParentSnapshotId-eq$baseline.Id){break};Start-Sleep -Seconds 1}
 if($vm.State-ne'Off'-or$vm.MemoryStartup-ne4GB-or$vm.ParentSnapshotId-ne$baseline.Id){throw 'Baseline restoration unverified.'}
 $record.status='independent-shadow-built-source-unchanged'
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();$record['errorPosition']=$_.InvocationInfo.PositionMessage;throw}
finally{$record['finishedUtc']=[DateTime]::UtcNow.ToString('o');Save 'host-result.json' $record;if($job-and$job.State-in@('Completed','Failed','Stopped')){Remove-Job $job -Force};if($session-and$record.operationCompletionKnown){Remove-PSSession $session -ErrorAction SilentlyContinue}}
[pscustomobject]$record
