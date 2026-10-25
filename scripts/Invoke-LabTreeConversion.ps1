<# Execute the Rust natural-tree reconstruction inside the owning disposable VM.
   Prepare restores only the pinned frozen-tree checkpoint; later operations
   continue that running branch. No source format or extent shaping occurs. #>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][ValidateSet('Prepare','Activate','Apply','Resume','Rollback','Handoff')][string]$Operation,
 [Parameter(Mandatory)][string]$BinaryPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BinarySha256,
 [string]$Directory
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot;Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$binary=Get-Item -LiteralPath $BinaryPath -Force
if($binary.PSIsContainer-or($binary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$binary.Length-gt16MB-or(Get-FileHash -LiteralPath $binary.FullName).Hash.ToLowerInvariant()-cne$BinarySha256){throw 'Pinned Rust tree-reconstruction executable required.'}
$checkpointId=[guid]'7bcaf7f9-07a5-463b-bc88-3a4f88e0e5e1'
$shadowRun='4cf7abc7c0174772868802161b563b7e'
$platformDirectory=Join-Path $cfg.Root 'existing-tree-shadow/win11-20261024T220846244Z'
$platform=Get-Content -LiteralPath (Join-Path $platformDirectory 'platform.json') -Raw|ConvertFrom-Json
$data=Get-Content -LiteralPath (Join-Path $platformDirectory 'request.json') -Raw|ConvertFrom-Json
function Save-New([string]$Path,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 20));$f=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
if($Operation-eq'Prepare'){
 if($Directory-or$vm.State-ne'Off'-or$vm.MemoryStartup-ne4GB-or$vm.ParentSnapshotId-ne[guid]'eda059b3-6d50-46bb-bdf4-018b99b5b34f'){throw 'New preparation requires the stopped clean baseline.'}
 Assert-LabCapacity (Get-LabCapacity $cfg) -AdditionalBytes 1536MB
 $run=[guid]::NewGuid().ToString('N');$root='C:\ntfs2refs\tree-conversion\'+$run
 $Directory=Assert-LabPath (Join-Path $cfg.Root ('tree-conversion/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
 New-Item -ItemType Directory -Path $Directory|Out-Null
 $j=$platform.journal
 $request=[ordered]@{schema_version=2;experiment_id=$shadowRun;source=$data.source;shadow=$data.shadow;comparison=[ordered]@{schema_version=2;sector_size=4096;expected_length=52GB;source_sha256='798926b2783a747f0d046d1010c9a8d2b109a900388117fcef46449c3abddd89';shadow_sha256='da1e6cd1d676ce806e5937d934ab57ebed57fa6bf4c0f6593fb8d34859490e01';retained_ranges=@();max_change_bytes=256MB;max_ranges=65536};journal=[ordered]@{disk_number=2;externally_enrolled_disk_unique_id='600224806AAC261F021F249596F332FC';volume_guid=([guid](($j.volumeGuid-replace '^\\\\\?\\Volume\{','')-replace '\}\\$','')).ToString();identity=[ordered]@{disk_guid=$j.diskGuid;partition_guid=$j.partitionGuid;partition_number=2;disk_bytes=8GB;partition_offset=16MB;partition_bytes=8GB-32MB;logical_sector_bytes=512;physical_sector_bytes=4096}};max_journal_bytes=768MB}
 Save-New (Join-Path $Directory 'request.json') $request
 Save-New (Join-Path $Directory 'started.json') ([ordered]@{runId=$run;guestRoot=$root;sourceCheckpointId=[string]$checkpointId;binarySha256=$BinarySha256;sourceSha256=$request.comparison.source_sha256;shadowSha256=$request.comparison.shadow_sha256;conversionQualified=$false})
 Copy-Item -LiteralPath $binary.FullName -Destination (Join-Path $Directory 'lab-tree-reconstruct.exe')
 $pins=@();foreach($name in @('src/lab_tree_reconstruct.rs','src/bin/lab-tree-reconstruct.rs','src/lab_reconstruct.rs','src/retained_compare.rs','crates/n2r-win32/src/native.rs','scripts/Invoke-LabTreeConversion.ps1','Cargo.lock')){$to=Join-Path $Directory ('sources/'+$name);New-Item -ItemType Directory -Path (Split-Path $to -Parent) -Force|Out-Null;Copy-Item -LiteralPath (Join-Path $workspace $name) -Destination $to;$pins+=@([pscustomobject]@{path=$name;sha256=(Get-FileHash -LiteralPath $to).Hash.ToLowerInvariant()})};Save-New (Join-Path $Directory 'sources.json') $pins
 $cp=Get-ExactLabCheckpoint -VM $vm -Name ('existing-tree-shadow-frozen-'+$shadowRun)
 if($cp.Id-ne$checkpointId-or$cp.State-ne'Off'-or$cp.MemoryStartup-ne8GB){throw 'Frozen-tree checkpoint differs.'}
 Restore-VMSnapshot -VMSnapshot $cp -Confirm:$false
 for($i=0;$i-lt15;$i++){$vm=Get-OwnedLabVM $cfg $manifest;if($vm.State-eq'Off'-and$vm.ParentSnapshotId-eq$checkpointId){break};Start-Sleep -Seconds 1}
 if($vm.State-ne'Off'-or$vm.ParentSnapshotId-ne$checkpointId){throw 'Restore incomplete.'};Start-VM -VM $vm|Out-Null
}else{
 $Directory=Assert-LabPath $Directory $cfg.Root;$start=Get-Content -LiteralPath (Join-Path $Directory 'started.json') -Raw|ConvertFrom-Json
 $root=$start.guestRoot;$run=$start.runId
 $allowedParents=@($checkpointId)
 $preparedPath=Join-Path $Directory 'prepared-checkpoint.json'
 if(Test-Path -LiteralPath $preparedPath){$prepared=Get-Content -LiteralPath $preparedPath -Raw|ConvertFrom-Json;if($prepared.runId-cne$run){throw 'Prepared checkpoint run differs.'};$allowedParents+=@([guid]$prepared.id)}
 if($vm.State-ne'Running'-or$vm.MemoryStartup-ne8GB-or$vm.ParentSnapshotId-notin$allowedParents-or$start.binarySha256-cne$BinarySha256){throw 'Continue only the exact running conversion branch and executable.'}
 Assert-LabCapacity (Get-LabCapacity $cfg) -AdditionalBytes 64MB
}
$Directory=Assert-LabPath $Directory $cfg.Root
$step=$Operation.ToLowerInvariant()+'-'+[guid]::NewGuid().ToString('N')
$requestSha=(Get-FileHash -LiteralPath (Join-Path $Directory 'request.json')).Hash.ToLowerInvariant()
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null;$job=$null
$record=[ordered]@{operation=$Operation;runId=$run;guestRoot=$root;step=$step;directory=$Directory;status='started';operationCompletionKnown=$true;error=$null}
Save-New (Join-Path $Directory ($step+'.started.json')) $record
try{
 for($i=0;$i-lt90;$i++){try{$session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop;break}catch{Start-Sleep -Seconds 2}}
 if(-not$session){throw 'Guest session unavailable.'}
 $ready=Initialize-LabGuestSession $session;if($ready.status-cne'ready'){throw 'Guest script session refused.'}
 if($Operation-eq'Prepare'){
  Invoke-Command -Session $session -ArgumentList $root -ScriptBlock {param($Root);$ErrorActionPreference='Stop';$parent=Split-Path $Root -Parent;if(-not(Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Path $parent|Out-Null};if(Test-Path -LiteralPath $Root){throw 'Fresh artifact root required.'};New-Item -ItemType Directory -Path $Root|Out-Null}
  Copy-Item -LiteralPath $binary.FullName -Destination ($root+'\lab-tree-reconstruct.exe') -ToSession $session
  Copy-Item -LiteralPath (Join-Path $Directory 'request.json') -Destination ($root+'\request.json') -ToSession $session
  foreach($name in @('NativeShadowDisk.cs','NativeMountBoundary.cs','NativeShadowReadOnlyAttachment.cs')){Copy-Item -LiteralPath (Join-Path $workspace ('lab/guest/'+$name)) -Destination ($root+'\'+$name) -ToSession $session}
  $vdiskId=[string]$platform.finalVhd.virtualDiskId
  $attach=Invoke-Command -Session $session -ArgumentList @($root,$shadowRun,$vdiskId) -ScriptBlock {
   param($Root,$Run,$VdiskId);$ErrorActionPreference='Stop'
   $source=Get-Disk -Number 1;if(-not$source.IsOffline-or-not$source.IsReadOnly-or$source.UniqueId-cne'60022480D091C4251B5FFD619706C2B5'){throw 'Frozen source identity/protection differs.'}
   if(@(Get-Disk).Count-ne3){throw 'Require only enrolled disks before independent attachment.'}
   Add-Type -Path @((Join-Path $Root 'NativeShadowDisk.cs'),(Join-Path $Root 'NativeMountBoundary.cs'),(Join-Path $Root 'NativeShadowReadOnlyAttachment.cs'))
   $n=New-Object Ntfs2Refs.NativeShadowDisk(('J:\ntfs2refs-shadow\'+$Run+'\shadow.vhdx'),([guid]$VdiskId),(New-Object Ntfs2Refs.ReadOnlyShadowDiskApi))
   $priv=New-Object Ntfs2Refs.ShadowManageVolumePrivilege
   try{$opened=$n.OpenOwned();try{$priv.Enable();$attached=$n.Attach()}finally{$priv.Restore()}
    if($attached.physicalPath-cne'\\.\PhysicalDrive3'){throw 'Unexpected shadow route.'}
    $protected=[Ntfs2Refs.NativeShadowProtection]::Observe([guid]'cd923950-593c-41f2-bc9b-7b2625d6cb6a',[guid]'f9fefbb5-3781-45aa-a8d4-69463f46bf51',$true)
    if($protected.status-cne'provider-readonly-and-offline-observed'-or$protected.attributesAfter-ne3-or-not$protected.cleanupComplete){throw 'Shadow protection incomplete.'}
    [pscustomobject]@{opened=$opened;attached=$attached;protection=$protected;privilege=$priv.Audit}
   }finally{if(-not$n.OperationActive){$n.Close()}}
  }
  Save-New (Join-Path $Directory 'attachment.json') $attach
 }
 $record.operationCompletionKnown=$false
 $ticketSha=if($Operation-eq'Prepare'){$null}else{(Get-FileHash -LiteralPath (Join-Path $Directory 'ticket.json')).Hash.ToLowerInvariant()}
 $job=Invoke-Command -Session $session -AsJob -ArgumentList @($root,$step,$Operation,$BinarySha256,$requestSha,$shadowRun,$ticketSha) -ScriptBlock {
  param($Root,$Step,$Operation,$BinarySha,$RequestSha,$Run,$TicketSha);$ErrorActionPreference='Stop'
  $exe=$Root+'\lab-tree-reconstruct.exe';$req=$Root+'\request.json';$ticket=$Root+'\ticket.json'
  if((Get-FileHash -LiteralPath $exe).Hash.ToLowerInvariant()-cne$BinarySha-or(Get-FileHash -LiteralPath $req).Hash.ToLowerInvariant()-cne$RequestSha){throw 'Guest binary or request pin differs.'}
  if(Get-Process -Name lab-tree-reconstruct,lab-native-reconstruct,lab-tree-shadow -ErrorAction SilentlyContinue){throw 'A native conversion operation is already live.'}
  $psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName=$exe;$psi.Arguments=$Operation.ToLowerInvariant()+' --request "'+$req+'" --request-sha256 '+$RequestSha+' --journal "J:\ntfs2refs-shadow\'+$Run+'\reconstruction.journal" --ticket "'+$ticket+'" --output "'+$Root+'\'+$Step+'.json"'
  if($Operation-ne'Prepare'){if((Get-FileHash -LiteralPath $ticket).Hash.ToLowerInvariant()-cne$TicketSha){throw 'Independent host ticket pin differs.'};$psi.Arguments+=' --ticket-sha256 '+$TicketSha}
  $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
  $p=[Diagnostics.Process]::new();$p.StartInfo=$psi;if(-not$p.Start()){throw 'Native process failed to start.'};$stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync()
  [IO.File]::WriteAllText($Root+'\'+$Step+'.process.json',([ordered]@{pid=$p.Id;arguments=$psi.Arguments;startedUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json))
  if(-not$p.WaitForExit(2400000)){throw ('Native operation still live; preserve PID '+$p.Id)}
  [IO.File]::WriteAllText($Root+'\'+$Step+'.stdout',$stdout.Result);[IO.File]::WriteAllText($Root+'\'+$Step+'.stderr',$stderr.Result)
  [pscustomobject]@{exitCode=$p.ExitCode;reportSha256=(Get-FileHash -LiteralPath ($Root+'\'+$Step+'.json')).Hash.ToLowerInvariant()}
 }
 if(-not(Wait-Job $job -Timeout 2700)){throw 'Native operation live or unknown; preserve branch.'}
 $reply=@(Receive-Job $job -ErrorAction Stop);if($job.State-ne'Completed'-or$reply.Count-ne1){throw 'Native completion not established.'}
 $record.operationCompletionKnown=$true
 Save-New (Join-Path $Directory ($step+'.reply.json')) $reply[0]
 foreach($name in @('.json','.intent.json','.process.json','.stdout','.stderr')){Copy-Item -LiteralPath ($root+'\'+$step+$name) -Destination (Join-Path $Directory ($step+$name)) -FromSession $session}
 if((Get-FileHash -LiteralPath (Join-Path $Directory ($step+'.json'))).Hash.ToLowerInvariant()-cne$reply[0].reportSha256){throw 'Exported report differs.'}
 if($Operation-eq'Prepare'-and$reply[0].exitCode-eq0){Copy-Item -LiteralPath ($root+'\ticket.json') -Destination (Join-Path $Directory 'ticket.json') -FromSession $session}
 $record.status=if($reply[0].exitCode-eq0){'native-operation-complete'}else{'native-operation-failed-terminal'}
 $record['exitCode']=$reply[0].exitCode
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();throw}
finally{Save-New (Join-Path $Directory ($step+'.host-result.json')) $record;if($job-and$job.State-in@('Completed','Failed','Stopped')){Remove-Job $job -Force};if($session-and$record.operationCompletionKnown){Remove-PSSession $session -ErrorAction SilentlyContinue}}
[pscustomobject]$record
