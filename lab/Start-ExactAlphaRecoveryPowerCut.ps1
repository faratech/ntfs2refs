# One narrowly enrolled Hyper-V power interruption. The exact published 7feb
# public executable runs unchanged. This controller never dispatches, restores,
# retries, replays, mounts, or changes guest storage attributes. It requires the
# producer's closed/synced resume.json (after selected writes/verification),
# checks the actual live process twice, and issues at most one TurnOff.
# Handoff may race the cut: do not infer its state from this receipt.
#Requires -Version 5.1
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$RecoveryDispatchPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$RecoveryDispatchSha256,
 [ValidatePattern('\A[0-9a-f]{64}\z')][string]$ExpectedFastDispatcherSha256,
 [Parameter(Mandatory)][string]$OutputDirectory,
 [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds,
 [ValidateRange(10,1800)][int]$TimeoutSeconds=900,
 [switch]$AcknowledgeEnrolledDisposableVm
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs'
$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$vmId=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$original=[guid]'58bd9ceb-60bc-4b34-81e1-7af197523a80'
$sourceParent=[guid]'a0627dbd-aa3b-4896-bbeb-495f5e372057'
$sourceCommit='7feb4c06d21e9de73bb88961197f5b745463e490'
$exeSha='c7b5809f4456f55e71f19b47d4e4cb9b7ee6cad86c4ff0fac36c1db5a5b909d1'
$receiptSha='d4321534441dfcd7a8bf2a91358950b7caaf4af9620b48fb818f0fd13068aa8a'
$bundleSha='334098c8baa0a04c95275130d2714b1551740dfeee66a011db179000ad2f7baa'
$ticketSha='f8f24a9764f4e5eb1950942c3d0184b809245762cfd49ad4cc8b1c37c3c08f7b'
$producerRoot=Join-Path $base 'paged-envelope-interrupt-fe086985340548db9eb098a884f4d1be'
$receiptPath=Join-Path $producerRoot 'checkpoint-observer-completed.json'
$bundlePath=Join-Path $producerRoot 'closed\producer\conversion\allocation-recovery-bundle.json'
$ticketPath=Join-Path $producerRoot 'closed\producer\conversion\selected-ticket.json'
$guestBundle='C:\ntfs2refs\paged-envelope-interrupt-fe086985340548db9eb098a884f4d1be\conversion\allocation-recovery-bundle.json'
$guestRecovery='C:\ntfs2refs\paged-envelope-interrupt-fe086985340548db9eb098a884f4d1be\conversion'
$ids=@($ExpectedCheckpointIds|ForEach-Object {$_.ToString('D')})
$held=[Collections.Generic.List[IO.FileStream]]::new()
$session=$null;$created=$false;$cutIssued=$false
function Need([bool]$ok,[string]$message){if(-not $ok){throw $message}}
function PollField($value,[string]$name){
 if($value-is[Collections.IDictionary]){Need ($value.Contains($name)) ('Poll field missing: '+$name);return $value[$name]}
 $p=$value.PSObject.Properties[$name];Need ($null-ne$p) ('Poll field missing: '+$name);return $p.Value
}
function OpenPinned([string]$path,[string]$sha,[long]$maximum){
 $full=[IO.Path]::GetFullPath($path);Need ($full-ceq$path-and$sha-cmatch'\A[0-9a-f]{64}\z') 'Exact absolute pinned path and SHA required.'
 $item=Get-Item -LiteralPath $full -Force;Need (-not$item.PSIsContainer-and$item.Length-gt0-and$item.Length-le$maximum) 'Bounded ordinary file required.'
 $cursor=$item;while($null-ne$cursor){Need (-not($cursor.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse ancestry refused.';if($cursor-is[IO.DirectoryInfo]){$cursor=$cursor.Parent}else{$cursor=$cursor.Directory}}
 $f=[IO.File]::Open($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$held.Add($f)
 $hash=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($hash.ComputeHash($f))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
 Need ($actual-ceq$sha-and$f.Length-eq$item.Length) 'Held input SHA/length differs.';$f.Position=0
 $r=[IO.StreamReader]::new($f,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true);try{$value=$r.ReadToEnd()|ConvertFrom-Json}finally{$r.Dispose()};$f.Position=0
 return $value
}
function HoldBinaryPin([string]$path,[string]$sha){
 Need ($sha-cmatch'\A[0-9a-f]{64}\z') 'Independently reviewed fast dispatcher SHA required.'
 $m=Get-Item -LiteralPath $path -Force;Need (-not$m.PSIsContainer-and$m.Length-gt0-and$m.Length-le1MB) 'Bounded fast dispatcher required.'
 $a=$m;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Fast dispatcher reparse ancestry refused.';if($a-is[IO.DirectoryInfo]){$a=$a.Parent}else{$a=$a.Directory}}
 $f=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$held.Add($f);$h=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($h.ComputeHash($f))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};Need ($actual-ceq$sha-and$f.Length-eq$m.Length) 'Reviewed fast dispatcher changed.'
}
function Save([string]$name,$value){
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 24));Need ($bytes.Length-gt0-and$bytes.Length-le1MB) 'Bounded receipt required.'
 $f=[IO.File]::Open((Join-Path $OutputDirectory $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
}
function HostGuard {
 $vm=Get-VM -Id $vmId -ErrorAction Stop;$nodes=@(Get-VMSnapshot -VM $vm -ErrorAction Stop);$actual=@($nodes|ForEach-Object {$_.Id.ToString('D')})
 Need ($vm.Name-ceq'ntfs2refs-streaming-v2-20261027'-and$vm.State.ToString()-ceq'Running'-and$vm.ParentSnapshotId-eq$original-and$vm.MemoryStartup-eq4GB-and$vm.MemoryAssigned-eq4GB-and-not$vm.DynamicMemoryEnabled-and(Get-VMProcessor -VM $vm).Count-eq4-and@(Get-VMNetworkAdapter -VM $vm).Count-eq0) 'Exact running VM, original parent, memory/CPU and no network required.'
 Need ($ids.Count-gt0-and$ids.Count-eq$actual.Count-and@($ids|Sort-Object -Unique).Count-eq$ids.Count-and@($ids|Where-Object {$_-notin$actual}).Count-eq0) 'Checkpoint inventory changed.'
 $old=@($nodes|Where-Object {$_.Id-eq$original});Need ($old.Count-eq1-and$old[0].ParentSnapshotId-eq$sourceParent) 'Original first-write checkpoint ancestry differs.'
 $all=@(Get-VMHardDiskDrive -VM $vm);$loc=@($all|ForEach-Object {$_.ControllerLocation});Need ($all.Count-eq6-and@($all|Where-Object {$_.ControllerType.ToString()-cne'SCSI'-or$_.ControllerNumber-ne0}).Count-eq0-and@(0,1,2,4,5,6|Where-Object {$_-notin$loc}).Count-eq0) 'Exact original six-disk VM attachment layout required.'
 $source=@($all|Where-Object ControllerLocation -EQ 1);Need ($source.Count-eq1-and$source[0].Path.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)) 'Exact owned source attachment required.'
 $vhd=Get-VHD -Path $source[0].Path -ErrorAction Stop;Need ([guid]$vhd.DiskIdentifier-eq[guid]'5e010a4c-f0f9-451d-9174-d8ba87de3b21'-and$vhd.Size-eq64GB) 'Exact source VHD identity/length differs.'
 return $vm
}
try{
 Need $AcknowledgeEnrolledDisposableVm 'Explicit enrolled disposable VM acknowledgment required.'
 Need ([IO.Path]::GetFullPath($OutputDirectory)-ceq$OutputDirectory-and[IO.Path]::GetDirectoryName($OutputDirectory)-ceq$base-and[IO.Path]::GetFileName($OutputDirectory)-cmatch'\Aalpha-public-power-[0-9a-f]{32}\z'-and-not(Test-Path -LiteralPath $OutputDirectory)) 'Fresh immediate owned-lab output required.'
 Need ([IO.Path]::GetDirectoryName($RecoveryDispatchPath).StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)-and[IO.Path]::GetFileName($RecoveryDispatchPath)-ceq'dispatch.json') 'Pinned recovery dispatch must be an owned-lab dispatch.'
 $dispatch=OpenPinned $RecoveryDispatchPath $RecoveryDispatchSha256 1MB
 $originalReceipt=OpenPinned $receiptPath $receiptSha 1MB
 $bundle=OpenPinned $bundlePath $bundleSha 1MB
 $ticket=OpenPinned $ticketPath $ticketSha 1MB
 Need ($originalReceipt.kind-ceq'paged-envelope-first-write-observer-completed-checkpoint-v2'-and[guid]$originalReceipt.checkpoint_id-eq$original-and[guid]$originalReceipt.checkpoint_parent_id-eq$sourceParent-and$originalReceipt.native_exit-eq86-and$originalReceipt.first_write_flushed-eq$true-and$originalReceipt.no_handoff-eq$true-and$originalReceipt.source_commit-ceq$sourceCommit-and$originalReceipt.recovery_sha256-ceq$bundleSha) 'Original independently recorded source checkpoint differs.'
 Need ($bundle.ticket.sha256-ceq$ticketSha-and$bundle.source.disk_number-eq1-and[guid]$bundle.source.identity.disk_guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'-and$ticket.selected_bytes-eq11396272128-and$ticket.range_count-eq5157-and@($ticket.new_selected_sha256).Count-eq32) 'Original bundle/ticket or source facts differ.'
 $newDigest=([BitConverter]::ToString([byte[]]$ticket.new_selected_sha256)).Replace('-','').ToLowerInvariant();Need ($newDigest-ceq'ff9d33f91421d3410e27840f90c01df9eb76793507db136fe4bc4b31f6bc32b6') 'Original selected postimage digest differs.'
 $run=[string]$dispatch.run_id;$stage='C:\ntfs2refs\paged-envelope-recovery-resume-'+$run;$task='N2R-PagedEnvelope-Recovery-resume-'+$run
 $fast=[bool]($dispatch.kind-ceq'exact-alpha-fast-recovery-dispatch-v1')
 if($fast){Need (-not[string]::IsNullOrEmpty($ExpectedFastDispatcherSha256)-and$dispatch.dispatcher_sha256-ceq$ExpectedFastDispatcherSha256-and$dispatch.configuration.binary_sha256-ceq$exeSha-and$dispatch.configuration.original_shadow_backing_guard_required-eq$true-and$dispatch.configuration.independent_full_baseline_scan-eq$false-and$dispatch.configuration.native_device_and_journal_gates_unchanged-eq$true) 'Exact independently reviewed fast dispatch profile required.';HoldBinaryPin (Join-Path $PSScriptRoot 'Start-ExactAlphaRecoveryFast.ps1') $ExpectedFastDispatcherSha256}
 else{Need ($dispatch.kind-ceq'paged-envelope-observer-completed-public-recovery-dispatch') 'Unknown recovery dispatch schema refused.'}
 Need ($run-cmatch'\A[0-9a-f]{32}\z'-and[IO.Path]::GetFileName([IO.Path]::GetDirectoryName($RecoveryDispatchPath))-ceq('paged-envelope-recovery-resume-'+$run)-and$dispatch.operation-ceq'resume'-and$dispatch.source_commit-ceq$sourceCommit-and[guid]$dispatch.parent_id-eq$original-and$dispatch.guest_stage-ceq$stage-and$dispatch.task_name-ceq$task-and$dispatch.wrapper_sha256-cmatch'\A[0-9a-f]{64}\z'-and$dispatch.configuration.recovery_sha256-ceq$bundleSha-and$dispatch.configuration.interrupted_checkpoint_receipt_sha256-ceq$receiptSha) 'Actual pinned public recovery dispatch differs.'
 $null=HostGuard
 New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop|Out-Null;$created=$true
 $controllerSha=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
 Save 'controller-start.json' @{schema_version=1;kind='exact-alpha-recovery-power-controller-start';vm_id=$vmId.ToString('D');original_checkpoint=$original.ToString('D');run_id=$run;dispatch_path=$RecoveryDispatchPath;dispatch_sha256=$RecoveryDispatchSha256;original_receipt_sha256=$receiptSha;bundle_sha256=$bundleSha;ticket_sha256=$ticketSha;source_commit=$sourceCommit;binary_sha256=$exeSha;controller_sha256=$controllerSha;timeout_seconds=$TimeoutSeconds;automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')}
 $credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
 $session=New-PSSession -VMId $vmId -Credential $credential -ErrorAction Stop
 $wrapperSha=[string]($dispatch.wrapper_sha256)
 $clock=[Diagnostics.Stopwatch]::StartNew();$observed=$null;$verifiedPid=0;$verifiedBirth=0L
 while($clock.Elapsed.TotalSeconds-lt$TimeoutSeconds){
  $checkBinaryPin=[bool]($verifiedPid-eq0)
  $pollArgs=[object[]]@($stage,$task,$run,$exeSha,$guestRecovery,$guestBundle,$bundleSha,$ticketSha,$newDigest,$wrapperSha,$checkBinaryPin,$fast)
  $poll=@(Invoke-Command -Session $session -ArgumentList $pollArgs -ScriptBlock {
   param($stage,$task,$run,$exeSha,$guestRecovery,$guestBundle,$bundleSha,$ticketSha,$newDigest,$wrapperSha,$checkBinaryPin,$fast)
   $ErrorActionPreference='Stop'
   function Need([bool]$ok,[string]$message){if(-not$ok){throw $message}}
   Need ($checkBinaryPin-is[bool]) 'Polling binary-pin argument is not Boolean.'
   $taskObject=Get-ScheduledTask -TaskName $task -ErrorAction Stop
   $running=@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-ceq'Running'})
   Need ($taskObject.State.ToString()-ceq'Running'-and$running.Count-eq1-and$running[0].TaskName-ceq$task-and@($taskObject.Actions).Count-eq1-and$taskObject.Principal.UserId-in@('SYSTEM','S-1-5-18')-and$taskObject.Principal.RunLevel.ToString()-ceq'Highest'-and$taskObject.Actions[0].Execute-ceq"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"-and$taskObject.Actions[0].Arguments-ceq('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $stage 'wrapper.ps1')+'"')) 'Exact sole running SYSTEM recovery task differs.'
   $processFile=Join-Path $stage 'native-process.json';if(-not(Test-Path -LiteralPath $processFile)){return @{ready=$false;reason='native-process-not-yet-recorded';pid=[int]0;creation_ms=[long]0;binary_pin_checked=$false}}
   if($fast){$preflight=([string](Get-Content -LiteralPath (Join-Path $stage 'preflight.json') -Raw))|ConvertFrom-Json;Need ($preflight.kind-ceq'exact-alpha-fast-recovery-preflight'-and$preflight.shadow_ordinary_provider_excluded_while_handle_held-eq$true-and$preflight.shadow_payload_read-eq$false-and$preflight.native_device_and_journal_gates_unchanged-eq$true-and$preflight.independent_full_baseline_scan-eq$false-and$preflight.grants_authority-eq$false) 'Actual fast SYSTEM preflight/held shadow guard is missing.'}
   $p=([string](Get-Content -LiteralPath $processFile -Raw))|ConvertFrom-Json
   Need ($p.pid-gt0-and$p.creation_ms-gt0-and$p.binary-ceq(Join-Path $stage 'ntfs2refs.exe')-and$p.binary_sha256-ceq$exeSha-and$p.process_handle_retained_before_wait-eq$true-and$p.affirmative_stdin_yes_crlf-eq$true) 'Original process receipt or public binary pin differs.'
   Need (@($p.argv).Count-eq4-and$p.argv[0]-ceq'--recover'-and$p.argv[1]-ceq$guestRecovery-and$p.argv[2]-ceq'--recovery-sha256'-and$p.argv[3]-ceq$bundleSha) 'Exact public recovery arguments differ.'
   $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$p.pid)
   Need ($null-ne$process-and$process.Name-ceq'ntfs2refs.exe'-and([DateTimeOffset]::new($process.CreationDate.ToUniversalTime())).ToUnixTimeMilliseconds()-eq$p.creation_ms-and$process.ParentProcessId-eq$p.parent_pid-and$process.ExecutablePath-ceq$p.binary) 'Actual native process identity/birth/parent differs.'
   if($checkBinaryPin){Need ((Get-FileHash -LiteralPath $p.binary -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$exeSha-and(Get-FileHash -LiteralPath (Join-Path $stage 'wrapper.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$wrapperSha) 'Exact public executable or wrapper pin differs.'}
   Need (-not(Test-Path -LiteralPath (Join-Path $stage 'native-terminal.json'))) 'Native terminal was already observed.'
   $disk=Get-Disk -Number 1;$part=Get-Partition -DiskNumber 1 -PartitionNumber 2
   Need ([guid]$disk.Guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'-and$disk.Size-eq64GB-and-not$disk.IsBoot-and-not$disk.IsSystem-and$disk.IsOffline-and-not$disk.IsReadOnly-and[guid]$part.Guid-eq[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-and$part.Offset-eq16MB-and$part.Size-eq52GB) 'Actual source disk/partition/exclusion differs.'
   Need ((Get-FileHash -LiteralPath $guestBundle -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$bundleSha-and(Get-FileHash -LiteralPath (Join-Path $guestRecovery 'selected-ticket.json') -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$ticketSha) 'Original guest bundle/ticket differs.'
   $started=[DateTimeOffset]::FromUnixTimeMilliseconds([long]$p.creation_ms).UtcDateTime.AddSeconds(-2)
   $candidates=@();$root='C:\ProgramData\ntfs2refs\runs'
   foreach($d in @(Get-ChildItem -LiteralPath $root -Directory -Filter 'recovery-*' -ErrorAction SilentlyContinue|Where-Object {$_.CreationTimeUtc-ge$started-and$_.Name-cmatch'\Arecovery-[0-9a-f]{32}\z'})){
    $intentPath=Join-Path $d.FullName 'drive-recovery-intent.json';if(-not(Test-Path -LiteralPath $intentPath)){continue}
    try{$intent=([string](Get-Content -LiteralPath $intentPath -Raw -ErrorAction Stop))|ConvertFrom-Json}catch{continue}
    if($intent.kind-ceq'confirmed-allocation-drive-recovery'-and$intent.operation-ceq'resume_then_finalize'-and$intent.bundle_path-ceq$guestBundle-and$intent.bundle_sha256-ceq$bundleSha-and[int]$intent.source.disk_number-eq1-and[guid]$intent.source.identity.disk_guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'){$candidates+=,$d.FullName}
   }
   Need ($candidates.Count-le1) 'Ambiguous public recovery output owners.'
   if($candidates.Count-eq0){return @{ready=$false;reason='recovery-intent-not-yet-closed';pid=[int]$p.pid;creation_ms=[long]$p.creation_ms;binary_pin_checked=[bool]$checkBinaryPin}}
   $records=Join-Path $candidates[0] 'resume';$resumePath=Join-Path $records 'resume.json';$selectionPath=Join-Path $records 'lifecycle-selection.json'
   if(-not(Test-Path -LiteralPath $resumePath)-or-not(Test-Path -LiteralPath $selectionPath)){return @{ready=$false;reason='synced-resume-not-yet-closed';pid=[int]$p.pid;creation_ms=[long]$p.creation_ms;binary_pin_checked=[bool]$checkBinaryPin}}
   try{$f=[IO.File]::Open($resumePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{$r=[IO.StreamReader]::new($f,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true);try{$text=$r.ReadToEnd()}finally{$r.Dispose()};$f.Position=0;$h=[Security.Cryptography.SHA256]::Create();try{$resumeSha=([BitConverter]::ToString($h.ComputeHash($f))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}finally{$f.Dispose()};$resume=$text|ConvertFrom-Json}catch{return @{ready=$false;reason='resume-file-not-yet-closed';pid=[int]$p.pid;creation_ms=[long]$p.creation_ms;binary_pin_checked=[bool]$checkBinaryPin}}
   $selection=([string](Get-Content -LiteralPath $selectionPath -Raw))|ConvertFrom-Json
   $selected=([BitConverter]::ToString([byte[]]$resume.selected_sha256)).Replace('-','').ToLowerInvariant()
   Need ($resume.selected_bytes-eq11396272128-and$resume.range_count-eq5157-and$selected-ceq$newDigest-and$resume.replay_closed-eq$false-and$resume.whole_image_verified-eq$false-and$resume.conversion_qualified-eq$false-and$selection.observed_lifecycle-ceq'apply_intent'-and$selection.selected_action-ceq'resume'-and$selection.journal_handle_held_exclusively-eq$true) 'Closed resumed postimage or original lifecycle differs.'
   return @{ready=$true;reason='synced-resume-closed';pid=[int]$p.pid;creation_ms=[long]$p.creation_ms;binary_pin_checked=[bool]$checkBinaryPin;parent_pid=[int]$p.parent_pid;binary=[string]$p.binary;records=[string]$records;resume_path=[string]$resumePath;resume_sha256=[string]$resumeSha;selected_sha256=[string]$selected;selected_bytes=[long]$resume.selected_bytes;range_count=[int]$resume.range_count;handoff_file_observed=(Test-Path -LiteralPath (Join-Path $records 'handoff.json'));source_offline=[bool]$disk.IsOffline;source_readonly=[bool]$disk.IsReadOnly;observed_utc=[DateTime]::UtcNow.ToString('o')}
  })
  Need ($poll.Count-eq1-and$null-ne$poll[0]) 'Polling must return exactly one observation.'
  $observed=$poll[0];$ready=PollField $observed 'ready';$reason=PollField $observed 'reason';$pollPid=PollField $observed 'pid';$pollBirth=PollField $observed 'creation_ms';$pinChecked=PollField $observed 'binary_pin_checked'
  Need ($ready-is[bool]-and$pinChecked-is[bool]-and$reason-is[string]-and$pollPid-is[int]-and$pollBirth-is[long]) 'Polling observation has invalid field types.'
  if($pollPid-eq0){Need (-not$ready-and-not$pinChecked-and$pollBirth-eq0-and$verifiedPid-eq0-and$reason-ceq'native-process-not-yet-recorded') 'Invalid pre-process polling state.'}
  else{
   Need ($pollPid-gt0-and$pollBirth-gt0) 'Polling process identity is invalid.'
   if($verifiedPid-eq0){Need $pinChecked 'Initial actual executable/wrapper checks absent.';$verifiedPid=$pollPid;$verifiedBirth=$pollBirth}
   else{Need ($pollPid-eq$verifiedPid-and$pollBirth-eq$verifiedBirth-and-not$pinChecked) 'Public recovery process or binary-check state changed while monitoring.'}
  }
  if($ready){Need ($verifiedPid-gt0-and$reason-ceq'synced-resume-closed') 'Ready observation lacks verified process identity.';break}
  Need ($reason-in@('native-process-not-yet-recorded','recovery-intent-not-yet-closed','synced-resume-not-yet-closed','resume-file-not-yet-closed')) 'Unknown not-ready polling state.'
  Start-Sleep -Milliseconds 250
 }
 Need ($null-ne$observed-and(PollField $observed 'ready')-eq$true) 'Timed out before the real closed/synced resume signal; no power action issued.'
 $nativePid=[int](PollField $observed 'pid')
 $nativeBirth=[long](PollField $observed 'creation_ms')
 $resumePath=[string](PollField $observed 'resume_path')
 $resumeSha=[string](PollField $observed 'resume_sha256')
 Need ($nativePid-eq$verifiedPid-and$nativeBirth-eq$verifiedBirth-and$nativePid-gt0-and$nativeBirth-gt0) 'Selected observation differs from cached native process identity.'
 $tokenName='alpha-power-lineage-'+[guid]::NewGuid().ToString('N')+'.json'
 $tokenArgs=[object[]]@($stage,$tokenName,$run,$nativePid,$nativeBirth)
 $token=Invoke-Command -Session $session -ArgumentList $tokenArgs -ScriptBlock {param($stage,$name,$run,$nativePid,$birth)
  if($nativePid-isnot[int]-or$birth-isnot[long]-or$nativePid-le0-or$birth-le0){throw 'Lineage process identity arguments are not typed positive integers.'}
  $path=Join-Path $stage $name;$content=@{kind='exact-alpha-power-lineage-v1';run_id=$run;native_pid=$nativePid;native_creation_ms=$birth;nonce=[guid]::NewGuid().ToString('N');utc=[DateTime]::UtcNow.ToString('o')}
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($content|ConvertTo-Json -Compress));$f=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
  return @{path=[string]$path;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();bytes=[long]$bytes.Length}
 }
 $tokenPath=[string](PollField $token 'path')
 $tokenSha=[string](PollField $token 'sha256')
 Need ($tokenSha-cmatch'\A[0-9a-f]{64}\z'-and-not[string]::IsNullOrWhiteSpace($tokenPath)) 'Lineage token result differs.'
 $null=HostGuard
 $lastArgs=[object[]]@($stage,$task,$nativePid,$nativeBirth,$resumePath,$resumeSha,$tokenPath,$tokenSha)
 $last=Invoke-Command -Session $session -ArgumentList $lastArgs -ScriptBlock {param($stage,$task,$nativePid,$birth,$resumePath,$resumeSha,$tokenPath,$tokenSha)
  if($nativePid-isnot[int]-or$birth-isnot[long]-or$nativePid-le0-or$birth-le0){throw 'Live-check process identity arguments are not typed positive integers.'}
  $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$nativePid);$scheduled=Get-ScheduledTask -TaskName $task;$disk=Get-Disk -Number 1
  if($null-eq$process-or$process.Name-cne'ntfs2refs.exe'-or([DateTimeOffset]::new($process.CreationDate.ToUniversalTime())).ToUnixTimeMilliseconds()-ne$birth-or$scheduled.State.ToString()-cne'Running'-or(Test-Path (Join-Path $stage 'native-terminal.json'))-or-not$disk.IsOffline-or$disk.IsReadOnly-or[guid]$disk.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or(Get-FileHash $resumePath -Algorithm SHA256).Hash.ToLowerInvariant()-cne$resumeSha-or(Get-FileHash $tokenPath -Algorithm SHA256).Hash.ToLowerInvariant()-cne$tokenSha){throw 'Final live process, source, synced signal or lineage token changed.'}
  return @{pid=$nativePid;creation_ms=$birth;task_state=[string]$scheduled.State;source_offline=[bool]$disk.IsOffline;source_readonly=[bool]$disk.IsReadOnly;handoff_file_observed=(Test-Path (Join-Path (Split-Path $resumePath -Parent) 'handoff.json'));observed_utc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'turnoff-intent.json' @{schema_version=1;kind='exact-alpha-public-recovery-power-cut-intent';vm_id=$vmId.ToString('D');original_checkpoint=$original.ToString('D');source_commit=$sourceCommit;binary_sha256=$exeSha;recovery_dispatch_path=$RecoveryDispatchPath;recovery_dispatch_sha256=$RecoveryDispatchSha256;recovery_dispatch_kind=[string]$dispatch.kind;fast_dispatcher_sha256=$(if($fast){$ExpectedFastDispatcherSha256}else{$null});run_id=$run;stage=$stage;task=$task;original_receipt_sha256=$receiptSha;bundle_sha256=$bundleSha;ticket_sha256=$ticketSha;synced_resume=$observed;last_live_observation=$last;lineage_token=$token;handoff_at_cut='unknown';native_exit_observed=$false;automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')}
 $intentSha=(Get-FileHash -LiteralPath (Join-Path $OutputDirectory 'turnoff-intent.json') -Algorithm SHA256).Hash.ToLowerInvariant()
 $vm=HostGuard
 # This is the last guest operation before the single power command. There is
 # still a scheduling race after the observation, so the receipt explicitly
 # does not claim that the process was live at the instant of TurnOff.
 $immediateArgs=[object[]]@($stage,$task,$nativePid,$nativeBirth)
 $immediate=Invoke-Command -Session $session -ArgumentList $immediateArgs -ScriptBlock {param($stage,$task,$nativePid,$birth)
  if($nativePid-isnot[int]-or$birth-isnot[long]-or$nativePid-le0-or$birth-le0){throw 'Immediate process identity arguments are not typed positive integers.'}
  $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+$nativePid);$scheduled=Get-ScheduledTask -TaskName $task;$disk=Get-Disk -Number 1
  if($null-eq$process-or$process.Name-cne'ntfs2refs.exe'-or([DateTimeOffset]::new($process.CreationDate.ToUniversalTime())).ToUnixTimeMilliseconds()-ne$birth-or$scheduled.State.ToString()-cne'Running'-or(Test-Path (Join-Path $stage 'native-terminal.json'))-or-not$disk.IsOffline-or$disk.IsReadOnly-or[guid]$disk.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'){throw 'Process/task/source changed immediately before TurnOff.'}
  return @{pid=$nativePid;creation_ms=$birth;task_state=[string]$scheduled.State;source_offline=[bool]$disk.IsOffline;source_readonly=[bool]$disk.IsReadOnly;observed_utc=[DateTime]::UtcNow.ToString('o')}
 }
 $cutIssued=$true
 Stop-VM -VM $vm -TurnOff -Force -ErrorAction Stop
 $off=Get-VM -Id $vmId -ErrorAction Stop;Need ($off.State.ToString()-ceq'Off'-and$off.MemoryAssigned-eq0) 'VM did not report Off/RAM0 after the one TurnOff.'
 Save 'poweroff-observed.json' @{schema_version=1;kind='exact-alpha-public-recovery-power-off';vm_id=$vmId.ToString('D');original_checkpoint=$original.ToString('D');run_id=$run;turnoff_intent_sha256=$intentSha;state='Off';memory_assigned_bytes=0;turnoff_issued_once=$true;immediate_pre_turnoff_observation=$immediate;native_live_at_turnoff='unproven';native_exit_observed=$false;handoff_at_cut='unknown';postboot_journal_lifecycle='not-yet-observed';physical_power_loss_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')}
 Get-Content -LiteralPath (Join-Path $OutputDirectory 'poweroff-observed.json') -Raw
}catch{
 if($created-and-not(Test-Path -LiteralPath (Join-Path $OutputDirectory 'controller-failed.json'))){try{Save 'controller-failed.json' @{success=$false;error=$_.Exception.ToString();turnoff_was_issued=$cutIssued;automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')}}catch{}}
 throw
}finally{if($null-ne$session){Remove-PSSession $session -ErrorAction SilentlyContinue};foreach($f in $held){$f.Dispose()}}
