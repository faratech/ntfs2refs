<# Continue the known natural-tree experiment from its running preparation.
   All filesystem operations execute inside the owning guest. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Directory,
 [Parameter(Mandatory)][string]$FinalizerPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$FinalizerSha256)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot;Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11
$Directory=Assert-LabPath $Directory $cfg.Root
$start=Get-Content -LiteralPath (Join-Path $Directory 'started.json') -Raw|ConvertFrom-Json
$root=$start.guestRoot;$run=$start.runId
if($root-cne('C:\ntfs2refs\tree-conversion\'+$run)-or$start.sourceCheckpointId-cne'7bcaf7f9-07a5-463b-bc88-3a4f88e0e5e1'){throw 'Unexpected conversion case.'}
$binary=Get-Item -LiteralPath $FinalizerPath
if($binary.PSIsContainer-or($binary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$binary.Length-gt16MB-or(Get-FileHash -LiteralPath $binary.FullName).Hash.ToLowerInvariant()-cne$FinalizerSha256){throw 'Pinned finalizer required.'}
function Save([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14));$f=[IO.File]::Open((Join-Path $Directory $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Stage([string]$Phase){$record.phase=$Phase;$record.updatedUtc=[DateTime]::UtcNow.ToString('o');$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 14));$f=[IO.File]::Open((Join-Path $Directory 'workflow.json'),[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
$record=[ordered]@{kind='natural-tree-conversion-workflow';runId=$run;hostPid=$PID;phase='start';success=$false;error=$null;finalizerSha256=$FinalizerSha256;originalSourceExtentShaping=0;rollbackClosed=$false;conversionQualified=$false}
Save 'workflow.intent.json' $record
$archivedFinalizer=Join-Path $Directory ('lab-tree-finalize-'+$FinalizerSha256+'.exe')
if(Test-Path -LiteralPath $archivedFinalizer){if((Get-FileHash -LiteralPath $archivedFinalizer).Hash.ToLowerInvariant()-cne$FinalizerSha256){throw 'Archived finalizer differs.'}}else{Copy-Item -LiteralPath $binary.FullName -Destination $archivedFinalizer}
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
function Connect {
 $script:vm=Get-OwnedLabVM $cfg $manifest
 if($script:vm.State-ne'Running'-or$script:vm.MemoryStartup-ne8GB){throw 'Running owned 8 GiB guest required.'}
 for($i=0;$i-lt90;$i++){try{$script:session=New-PSSession -VMId $script:vm.Id -Credential $credential -ErrorAction Stop;break}catch{Start-Sleep -Seconds 2}}
 if(-not$script:session){throw 'Guest connection unavailable.'}
 $r=Initialize-LabGuestSession $script:session;if($r.status-cne'ready'){throw 'Guest session refused.'}
}
function Guest-Finalizer([string]$Mode){
 $reqSha=(Get-FileHash -LiteralPath (Join-Path $Directory 'request.json')).Hash.ToLowerInvariant()
 $expectSha=if($Mode-eq'finish'){(Get-FileHash -LiteralPath (Join-Path $Directory 'expectation.json')).Hash.ToLowerInvariant()}else{$null}
 $ticketSha=if($Mode-eq'finish'){(Get-FileHash -LiteralPath (Join-Path $Directory 'ticket.json')).Hash.ToLowerInvariant()}else{$null}
 $job=Invoke-Command -Session $session -AsJob -ArgumentList @($root,$Mode,$reqSha,$FinalizerSha256,$expectSha,$ticketSha) -ScriptBlock {
  param($Root,$Mode,$RequestSha,$ExeSha,$ExpectSha,$TicketSha);$ErrorActionPreference='Stop'
  $exe=$Root+'\lab-tree-finalize.exe';$req=$Root+'\request.json';$output=$Root+'\'+$(if($Mode-eq'capture'){'expectation.json'}else{'finish.json'})
  if((Get-FileHash -LiteralPath $exe).Hash.ToLowerInvariant()-cne$ExeSha-or(Get-FileHash -LiteralPath $req).Hash.ToLowerInvariant()-cne$RequestSha){throw 'Copied finalizer or request differs.'}
  $psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName=$exe;$psi.Arguments=$Mode+' --request "'+$req+'" --request-sha256 '+$RequestSha+' --output "'+$output+'"'
  if($Mode-eq'finish'){$psi.Arguments+=' --expectation "'+$Root+'\expectation.json" --expectation-sha256 '+$ExpectSha+' --ticket "'+$Root+'\ticket.json" --ticket-sha256 '+$TicketSha+' --journal "J:\ntfs2refs-shadow\4cf7abc7c0174772868802161b563b7e\reconstruction.journal"'}
  $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
  $p=[Diagnostics.Process]::new();$p.StartInfo=$psi;if(-not$p.Start()){throw 'Finalizer process did not start.'};$stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync()
  [IO.File]::WriteAllText($Root+'\'+$Mode+'.process.json',([ordered]@{pid=$p.Id;arguments=$psi.Arguments;startedUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json))
  if(-not$p.WaitForExit(1800000)){throw ('Finalizer still live; preserve PID '+$p.Id)}
  [IO.File]::WriteAllText($Root+'\'+$Mode+'.stdout',$stdout.Result);[IO.File]::WriteAllText($Root+'\'+$Mode+'.stderr',$stderr.Result)
  [pscustomobject]@{exitCode=$p.ExitCode;output=$output;outputSha256=$(if(Test-Path -LiteralPath $output){(Get-FileHash -LiteralPath $output).Hash.ToLowerInvariant()}else{$null})}
 }
 if(-not(Wait-Job $job -Timeout 2100)){throw 'Finalizer completion unknown; preserve running branch.'}
 try{$reply=@(Receive-Job $job -ErrorAction Stop);if($job.State-ne'Completed'-or$reply.Count-ne1){throw 'Finalizer result incomplete.'}
  foreach($name in @('.process.json','.stdout','.stderr')){Copy-Item -LiteralPath ($root+'\'+$Mode+$name) -Destination (Join-Path $Directory ($Mode+$name)) -FromSession $session}
  if($reply[0].outputSha256){Copy-Item -LiteralPath $reply[0].output -Destination (Join-Path $Directory (Split-Path $reply[0].output -Leaf)) -FromSession $session}
  Save ($Mode+'.reply.json') $reply[0]
  if($reply[0].exitCode-ne0){throw ('Native '+$Mode+' failed; inspect exported stderr and preserve branch.')}
 }finally{if($job.State-in@('Completed','Failed','Stopped')){Remove-Job $job -Force}}
}
function Shutdown-Owned {
 Invoke-Command -Session $session -ScriptBlock {& shutdown.exe /s /t 0;if($LASTEXITCODE){throw 'Shutdown failed.'}}|Out-Null
 for($i=0;$i-lt45;$i++){$script:vm=Get-OwnedLabVM $cfg $manifest;if($script:vm.State-eq'Off'){break};Start-Sleep -Seconds 1}
 if($script:vm.State-ne'Off'){throw 'Guest shutdown incomplete.'};Remove-PSSession $session;$script:session=$null
}
try{
 Stage 'capture-source-expectation';Connect
 Copy-Item -LiteralPath $binary.FullName -Destination ($root+'\lab-tree-finalize.exe') -ToSession $session
 Guest-Finalizer capture
 Stage 'wait-for-current-preparation'
 $deadline=[DateTime]::UtcNow.AddMinutes(40)
 while(-not(Test-Path -LiteralPath (Join-Path $Directory 'ticket.json'))){
  $failed=@(Get-ChildItem -LiteralPath $Directory -Filter 'prepare-*.host-result.json'|ForEach-Object {Get-Content -LiteralPath $_.FullName -Raw|ConvertFrom-Json}|Where-Object status -ne 'native-operation-complete')
  if($failed.Count){throw 'Existing preparation failed; no retry.'}
  if([DateTime]::UtcNow-gt$deadline){throw 'Preparation observation deadline; preserve original operation.'}
  Start-Sleep -Seconds 2
 }
 # Wait for the independently exported terminal host record, not ticket arrival alone.
 $done=$null
 for($i=0;$i-lt60;$i++){$done=@(Get-ChildItem -LiteralPath $Directory -Filter 'prepare-*.host-result.json'|ForEach-Object {Get-Content -LiteralPath $_.FullName -Raw|ConvertFrom-Json});if($done.Count){break};Start-Sleep -Seconds 1}
 if($done.Count-ne1-or$done[0].status-cne'native-operation-complete'){throw 'Preparation terminal evidence unavailable.'}
 Stage 'preserve-prepared-recovery-checkpoint';Shutdown-Owned
 $name='tree-journal-prepared-'+$run;Checkpoint-VM -VM $vm -SnapshotName $name;$cp=Get-ExactLabCheckpoint -VM $vm -Name $name
 Save 'prepared-checkpoint.json' ([ordered]@{runId=$run;id=[string]$cp.Id;name=$name;ticketSha256=(Get-FileHash -LiteralPath (Join-Path $Directory 'ticket.json')).Hash.ToLowerInvariant()})
 Start-VM -VM $vm|Out-Null;Connect
 Stage 'reattach-protected-shadow'
 $attached=Invoke-Command -Session $session -ArgumentList $root -ScriptBlock {
  param($Root);$ErrorActionPreference='Stop'
  Add-Type -Path @((Join-Path $Root 'NativeShadowDisk.cs'),(Join-Path $Root 'NativeMountBoundary.cs'),(Join-Path $Root 'NativeShadowReadOnlyAttachment.cs'))
  $p=Get-Content -LiteralPath 'C:\ntfs2refs\shadow-platform\4cf7abc7c0174772868802161b563b7e\prepare.json' -Raw|ConvertFrom-Json
  $n=New-Object Ntfs2Refs.NativeShadowDisk($p.backingPath,([guid]$p.finalVhd.virtualDiskId),(New-Object Ntfs2Refs.ReadOnlyShadowDiskApi));$priv=New-Object Ntfs2Refs.ShadowManageVolumePrivilege
  try{$opened=$n.OpenOwned();try{$priv.Enable();$attached=$n.Attach()}finally{$priv.Restore()};$r=[Ntfs2Refs.NativeShadowProtection]::Observe([guid]'cd923950-593c-41f2-bc9b-7b2625d6cb6a',[guid]'f9fefbb5-3781-45aa-a8d4-69463f46bf51',$true);if($attached.physicalPath-cne'\\.\PhysicalDrive3'-or$r.attributesAfter-ne3-or-not$r.cleanupComplete){throw 'Reattached shadow protection differs.'};$r}finally{if(-not$n.OperationActive){$n.Close()}}
 }
 Save 'reattachment.json' $attached
 Stage 'activate-offline-target'
 $reconstructor=Join-Path $Directory 'lab-tree-reconstruct.exe'
 $activation=& (Join-Path $PSScriptRoot 'Invoke-LabTreeConversion.ps1') -Operation Activate -Directory $Directory -BinaryPath $reconstructor -BinarySha256 $start.binarySha256
 if($activation.status-cne'native-operation-complete'){throw 'Activation did not complete.'}
 Stage 'apply-same-partition-conversion'
 $apply=& (Join-Path $PSScriptRoot 'Invoke-LabTreeConversion.ps1') -Operation Apply -Directory $Directory -BinaryPath $reconstructor -BinarySha256 $start.binarySha256
 if($apply.status-cne'native-operation-complete'){throw 'Apply did not complete; preserve recoverable branch.'}
 Stage 'handoff-and-native-tree-verification';Guest-Finalizer finish
 $finish=Get-Content -LiteralPath (Join-Path $Directory 'finish.json') -Raw|ConvertFrom-Json
 if(-not$finish.success-or-not$finish.rollback_closed){throw 'Native tree verification did not pass.'}
 $record.rollbackClosed=$true
 Stage 'save-converted-checkpoint';Shutdown-Owned
 $name='tree-converted-'+$run;Checkpoint-VM -VM $vm -SnapshotName $name;$cp=Get-ExactLabCheckpoint -VM $vm -Name $name
 Save 'converted-checkpoint.json' ([ordered]@{runId=$run;id=[string]$cp.Id;name=$name;nativeReportSha256=(Get-FileHash -LiteralPath (Join-Path $Directory 'finish.json')).Hash.ToLowerInvariant()})
 $baseline=Get-ExactLabCheckpoint -VM $vm -Name installed-clean
 if($baseline.Id-ne[guid]'eda059b3-6d50-46bb-bdf4-018b99b5b34f'){throw 'Baseline differs.'};Restore-VMSnapshot -VMSnapshot $baseline -Confirm:$false
 for($i=0;$i-lt15;$i++){$vm=Get-OwnedLabVM $cfg $manifest;if($vm.State-eq'Off'-and$vm.MemoryStartup-eq4GB-and$vm.ParentSnapshotId-eq$baseline.Id){break};Start-Sleep -Seconds 1}
 if($vm.State-ne'Off'-or$vm.MemoryStartup-ne4GB-or$vm.ParentSnapshotId-ne$baseline.Id){throw 'Baseline restore incomplete.'}
 $record.success=$true;Stage 'converted-tree-native-verification-passed'
}catch{$record.error=$_.Exception.ToString();Stage 'failed-preserved';throw}
finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
[pscustomobject]$record
