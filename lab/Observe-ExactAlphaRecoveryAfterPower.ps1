# Read-only classifier after the exact-alpha power controller. Root separately
# boots the same branch and dispatches the public recovery; this script does not
# start, stop, restore, checkpoint, mount or replay anything. It classifies the
# actual lifecycle selected by the completed 7feb public recovery process.
#Requires -Version 5.1
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$TurnoffIntentPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$TurnoffIntentSha256,
 [Parameter(Mandatory)][string]$PoweroffReceiptPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$PoweroffReceiptSha256,
 [Parameter(Mandatory)][string]$PostbootDispatchPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$PostbootDispatchSha256,
 [ValidatePattern('\A[0-9a-f]{64}\z')][string]$ExpectedFastDispatcherSha256,
 [Parameter(Mandatory)][string]$OutputDirectory,
 [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$vmId=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$original=[guid]'58bd9ceb-60bc-4b34-81e1-7af197523a80';$sourceParent=[guid]'a0627dbd-aa3b-4896-bbeb-495f5e372057'
$sourceCommit='7feb4c06d21e9de73bb88961197f5b745463e490';$exeSha='c7b5809f4456f55e71f19b47d4e4cb9b7ee6cad86c4ff0fac36c1db5a5b909d1'
$bundleSha='334098c8baa0a04c95275130d2714b1551740dfeee66a011db179000ad2f7baa';$ticketSha='f8f24a9764f4e5eb1950942c3d0184b809245762cfd49ad4cc8b1c37c3c08f7b';$originalReceiptSha='d4321534441dfcd7a8bf2a91358950b7caaf4af9620b48fb818f0fd13068aa8a'
$guestRecovery='C:\ntfs2refs\paged-envelope-interrupt-fe086985340548db9eb098a884f4d1be\conversion';$guestBundle=Join-Path $guestRecovery 'allocation-recovery-bundle.json'
$ids=@($ExpectedCheckpointIds|ForEach-Object {$_.ToString('D')});$held=[Collections.Generic.List[IO.FileStream]]::new();$session=$null;$created=$false
function Need([bool]$ok,[string]$message){if(-not$ok){throw $message}}
function OpenPinned([string]$path,[string]$sha,[long]$maximum){
 $full=[IO.Path]::GetFullPath($path);Need ($full-ceq$path-and$sha-cmatch'\A[0-9a-f]{64}\z') 'Exact absolute pinned path and SHA required.'
 $item=Get-Item -LiteralPath $full -Force;Need (-not$item.PSIsContainer-and$item.Length-gt0-and$item.Length-le$maximum) 'Bounded ordinary file required.'
 $a=$item;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse ancestry refused.';if($a-is[IO.DirectoryInfo]){$a=$a.Parent}else{$a=$a.Directory}}
 $f=[IO.File]::Open($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$held.Add($f);$h=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($h.ComputeHash($f))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};Need ($actual-ceq$sha-and$f.Length-eq$item.Length) 'Held input SHA/length differs.';$f.Position=0
 $r=[IO.StreamReader]::new($f,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true);try{$json=[string]$r.ReadToEnd();$options=@{};if((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')){$options.DateKind='String'};$value=$json|ConvertFrom-Json @options}finally{$r.Dispose()};$f.Position=0;return $value
}
function HoldBinaryPin([string]$path,[string]$sha){
 Need ($sha-cmatch'\A[0-9a-f]{64}\z') 'Independently reviewed fast dispatcher SHA required.';$m=Get-Item -LiteralPath $path -Force;Need (-not$m.PSIsContainer-and$m.Length-gt0-and$m.Length-le1MB) 'Bounded fast dispatcher required.'
 $a=$m;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Fast dispatcher reparse ancestry refused.';if($a-is[IO.DirectoryInfo]){$a=$a.Parent}else{$a=$a.Directory}}
 $f=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$held.Add($f);$h=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($h.ComputeHash($f))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};Need ($actual-ceq$sha-and$f.Length-eq$m.Length) 'Reviewed fast dispatcher changed.'
}
function Save([string]$name,$value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 24));Need ($bytes.Length-gt0-and$bytes.Length-le1MB) 'Bounded receipt required.';$f=[IO.File]::Open((Join-Path $OutputDirectory $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
try{
 Need ([IO.Path]::GetFullPath($OutputDirectory)-ceq$OutputDirectory-and[IO.Path]::GetDirectoryName($OutputDirectory)-ceq$base-and[IO.Path]::GetFileName($OutputDirectory)-cmatch'\Aalpha-public-power-classification-[0-9a-f]{32}\z'-and-not(Test-Path -LiteralPath $OutputDirectory)) 'Fresh immediate owned-lab classification directory required.'
 $cutDir=[IO.Path]::GetDirectoryName($TurnoffIntentPath)
 Need ($cutDir.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)-and[IO.Path]::GetFileName($cutDir)-cmatch'\Aalpha-public-power-[0-9a-f]{32}\z'-and[IO.Path]::GetFileName($TurnoffIntentPath)-ceq'turnoff-intent.json'-and[IO.Path]::GetDirectoryName($PoweroffReceiptPath)-ceq$cutDir-and[IO.Path]::GetFileName($PoweroffReceiptPath)-ceq'poweroff-observed.json') 'Exact same-controller power receipt paths required.'
 $intent=OpenPinned $TurnoffIntentPath $TurnoffIntentSha256 1MB;$off=OpenPinned $PoweroffReceiptPath $PoweroffReceiptSha256 1MB
 Need ($intent.kind-ceq'exact-alpha-public-recovery-power-cut-intent'-and$off.kind-ceq'exact-alpha-public-recovery-power-off'-and[guid]$intent.vm_id-eq$vmId-and[guid]$off.vm_id-eq$vmId-and[guid]$intent.original_checkpoint-eq$original-and[guid]$off.original_checkpoint-eq$original-and$intent.run_id-ceq$off.run_id-and$off.turnoff_intent_sha256-ceq$TurnoffIntentSha256-and$intent.source_commit-ceq$sourceCommit-and$intent.binary_sha256-ceq$exeSha-and$intent.bundle_sha256-ceq$bundleSha-and$intent.ticket_sha256-ceq$ticketSha-and$intent.original_receipt_sha256-ceq$originalReceiptSha-and$off.turnoff_issued_once-eq$true-and$off.state-ceq'Off'-and$off.handoff_at_cut-ceq'unknown'-and$off.native_live_at_turnoff-ceq'unproven') 'Actual power controller receipt facts differ.'
 $cutKind=$intent.PSObject.Properties['recovery_dispatch_kind'];$fastPinHeld=$false
 if($null-ne$cutKind-and$cutKind.Value-ceq'exact-alpha-fast-recovery-dispatch-v1'){Need (-not[string]::IsNullOrEmpty($ExpectedFastDispatcherSha256)-and$intent.fast_dispatcher_sha256-ceq$ExpectedFastDispatcherSha256) 'Exact independently reviewed original fast dispatcher required.';HoldBinaryPin (Join-Path $PSScriptRoot 'Start-ExactAlphaRecoveryFast.ps1') $ExpectedFastDispatcherSha256;$fastPinHeld=$true}
 elseif($null-ne$cutKind){Need ($cutKind.Value-ceq'paged-envelope-observer-completed-public-recovery-dispatch') 'Unknown original recovery dispatcher refused.'}
 $dispatch=OpenPinned $PostbootDispatchPath $PostbootDispatchSha256 1MB
 $run=[string]$dispatch.run_id;$stage='C:\ntfs2refs\paged-envelope-recovery-resume-'+$run;$task='N2R-PagedEnvelope-Recovery-resume-'+$run
 $fast=[bool]($dispatch.kind-ceq'exact-alpha-fast-recovery-dispatch-v1')
 if($fast){Need (-not[string]::IsNullOrEmpty($ExpectedFastDispatcherSha256)-and$dispatch.dispatcher_sha256-ceq$ExpectedFastDispatcherSha256-and$dispatch.configuration.binary_sha256-ceq$exeSha-and$dispatch.configuration.original_shadow_backing_guard_required-eq$true-and$dispatch.configuration.independent_full_baseline_scan-eq$false-and$dispatch.configuration.native_device_and_journal_gates_unchanged-eq$true) 'Exact independently reviewed fast postboot dispatcher required.';if(-not$fastPinHeld){HoldBinaryPin (Join-Path $PSScriptRoot 'Start-ExactAlphaRecoveryFast.ps1') $ExpectedFastDispatcherSha256;$fastPinHeld=$true}}
 else{Need ($dispatch.kind-ceq'paged-envelope-observer-completed-public-recovery-dispatch') 'Unknown postboot dispatcher schema refused.'}
 Need ($PostbootDispatchPath.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)-and[IO.Path]::GetFileName($PostbootDispatchPath)-ceq'dispatch.json'-and$run-cmatch'\A[0-9a-f]{32}\z'-and[IO.Path]::GetFileName([IO.Path]::GetDirectoryName($PostbootDispatchPath))-ceq('paged-envelope-recovery-resume-'+$run)-and$run-cne$intent.run_id-and$dispatch.operation-ceq'resume'-and$dispatch.source_commit-ceq$sourceCommit-and[guid]$dispatch.parent_id-eq$original-and$dispatch.guest_stage-ceq$stage-and$dispatch.task_name-ceq$task-and$dispatch.wrapper_sha256-cmatch'\A[0-9a-f]{64}\z'-and$dispatch.configuration.recovery_sha256-ceq$bundleSha-and$dispatch.configuration.interrupted_checkpoint_receipt_sha256-ceq$originalReceiptSha) 'Fresh postboot public recovery dispatch differs.'
 $offTime=[DateTimeOffset]::Parse([string]$off.utc).ToUniversalTime();$dispatchTime=[DateTimeOffset]::Parse([string]$dispatch.utc).ToUniversalTime();Need ($dispatchTime-gt$offTime) 'Postboot dispatch did not follow the recorded power-off.'
 $vm=Get-VM -Id $vmId -ErrorAction Stop;$nodes=@(Get-VMSnapshot -VM $vm -ErrorAction Stop);$actual=@($nodes|ForEach-Object {$_.Id.ToString('D')})
 Need ($vm.Name-ceq'ntfs2refs-streaming-v2-20261027'-and$vm.State.ToString()-ceq'Running'-and$vm.ParentSnapshotId-eq$original-and$vm.MemoryStartup-eq4GB-and$vm.MemoryAssigned-eq4GB-and-not$vm.DynamicMemoryEnabled-and(Get-VMProcessor -VM $vm).Count-eq4-and@(Get-VMNetworkAdapter -VM $vm).Count-eq0-and$ids.Count-eq$actual.Count-and@($ids|Sort-Object -Unique).Count-eq$ids.Count-and@($ids|Where-Object {$_-notin$actual}).Count-eq0) 'Exact postboot VM/parent/checkpoint/resource state differs.'
 $old=@($nodes|Where-Object {$_.Id-eq$original});Need ($old.Count-eq1-and$old[0].ParentSnapshotId-eq$sourceParent) 'Original checkpoint ancestry differs.'
 $all=@(Get-VMHardDiskDrive -VM $vm);$source=@($all|Where-Object ControllerLocation -EQ 1);Need ($all.Count-eq6-and$source.Count-eq1-and$source[0].Path.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)) 'Exact original VM source attachment required.'
 $vhd=Get-VHD -Path $source[0].Path -ErrorAction Stop;Need ([guid]$vhd.DiskIdentifier-eq[guid]'5e010a4c-f0f9-451d-9174-d8ba87de3b21'-and$vhd.Size-eq64GB) 'Original source virtual disk identity differs.'
 New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop|Out-Null;$created=$true
 $credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml');$session=New-PSSession -VMId $vmId -Credential $credential -ErrorAction Stop
 $tokenFact=$intent.lineage_token
 $cutRun=[string]($intent.run_id)
 $cutPid=[long]($intent.synced_resume.pid)
 $cutBirth=[long]($intent.synced_resume.creation_ms)
 $offMs=[long]($offTime.ToUnixTimeMilliseconds())
 $wrapperSha=[string]($dispatch.wrapper_sha256)
 Need ($cutPid-gt0-and$cutBirth-gt0-and$offMs-gt0-and$wrapperSha-cmatch'\A[0-9a-f]{64}\z') 'Typed postboot observation arguments differ.'
 $observeArgs=[object[]]@($stage,$task,$exeSha,$guestRecovery,$guestBundle,$bundleSha,$ticketSha,$tokenFact,$cutRun,$cutPid,$cutBirth,$offMs,$wrapperSha,$fast)
 $observed=Invoke-Command -Session $session -ArgumentList $observeArgs -ScriptBlock {
  param($stage,$task,$exeSha,$guestRecovery,$guestBundle,$bundleSha,$ticketSha,$token,$cutRun,$cutPid,$cutBirth,$offMs,$wrapperSha,$fast)
  $ErrorActionPreference='Stop'
  function Need([bool]$ok,[string]$message){if(-not$ok){throw $message}}
  Need ($cutPid-is[long]-and$cutBirth-is[long]-and$offMs-is[long]-and$cutPid-gt0-and$cutBirth-gt0-and$offMs-gt0) 'Postboot identity/time arguments are not typed positive integers.'
  function Closed([string]$path,[long]$max){
   $meta=Get-Item -LiteralPath $path -Force;Need (-not$meta.PSIsContainer-and$meta.Length-gt0-and$meta.Length-le$max-and-not($meta.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Bounded closed evidence file required.'
   $f=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{$r=[IO.StreamReader]::new($f,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true);try{$text=$r.ReadToEnd()}finally{$r.Dispose()};$f.Position=0;$h=[Security.Cryptography.SHA256]::Create();try{$sha=([BitConverter]::ToString($h.ComputeHash($f))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};Need ($f.Length-eq$meta.Length) 'Closed evidence length changed.';return @{text=[string]$text;sha256=[string]$sha;bytes=[long]$f.Length}}finally{$f.Dispose()}
  }
  $boot=[DateTimeOffset]::new((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()).ToUnixTimeMilliseconds();Need ($boot-ge($offMs-5000)) 'Guest was not observed booting after the recorded cut.'
  $oldStage='C:\ntfs2refs\paged-envelope-recovery-resume-'+$cutRun
  Need ($token.path-ceq(Join-Path $oldStage ([IO.Path]::GetFileName([string]$token.path)))-and[IO.Path]::GetFileName([string]$token.path)-cmatch'\Aalpha-power-lineage-[0-9a-f]{32}\.json\z') 'Power lineage token route differs.'
  $tokenFile=Closed $token.path 4096;Need ($tokenFile.sha256-ceq$token.sha256-and$tokenFile.bytes-eq$token.bytes) 'Same-branch power lineage token is absent or changed.';$lineage=$tokenFile.text|ConvertFrom-Json
  Need ($lineage.kind-ceq'exact-alpha-power-lineage-v1'-and$lineage.run_id-ceq$cutRun-and$lineage.native_pid-eq$cutPid-and$lineage.native_creation_ms-eq$cutBirth) 'Lineage token owner differs.'
  $pfile=Closed (Join-Path $stage 'native-process.json') 1MB;$tfile=Closed (Join-Path $stage 'native-terminal.json') 1MB;$p=$pfile.text|ConvertFrom-Json;$t=$tfile.text|ConvertFrom-Json
  if($fast){$preflightFile=Closed (Join-Path $stage 'preflight.json') 1MB;$preflight=$preflightFile.text|ConvertFrom-Json;$workerFile=Closed (Join-Path $stage 'wrapper-result.json') 1MB;$worker=$workerFile.text|ConvertFrom-Json;Need ($preflight.kind-ceq'exact-alpha-fast-recovery-preflight'-and$preflight.shadow_ordinary_provider_excluded_while_handle_held-eq$true-and$preflight.shadow_payload_read-eq$false-and$preflight.native_device_and_journal_gates_unchanged-eq$true-and$preflight.independent_full_baseline_scan-eq$false-and$preflight.grants_authority-eq$false-and$worker.kind-ceq'exact-alpha-fast-recovery-process-observation'-and$worker.success-eq$true-and$worker.native_exit-eq0-and$worker.independent_full_baseline_scan-eq$false-and$worker.independent_811_stream_hashes_checked-eq$false) 'Actual completed fast worker/shadow guard evidence differs.'}
  $taskObject=Get-ScheduledTask -TaskName $task -ErrorAction Stop
  Need (@($taskObject.Actions).Count-eq1-and$taskObject.Principal.UserId-in@('SYSTEM','S-1-5-18')-and$taskObject.Principal.RunLevel.ToString()-ceq'Highest'-and$taskObject.Actions[0].Execute-ceq"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"-and$taskObject.Actions[0].Arguments-ceq('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $stage 'wrapper.ps1')+'"')-and(Get-FileHash -LiteralPath (Join-Path $stage 'wrapper.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$wrapperSha) 'Postboot SYSTEM task or wrapper pin differs.'
  Need ($p.pid-gt0-and$p.creation_ms-gt$offMs-and$p.binary-ceq(Join-Path $stage 'ntfs2refs.exe')-and$p.binary_sha256-ceq$exeSha-and$p.process_handle_retained_before_wait-eq$true-and$p.raw_log_drains_started_before_wait-eq$true-and$p.affirmative_stdin_yes_crlf-eq$true-and$t.pid-eq$p.pid-and$t.creation_ms-eq$p.creation_ms-and$t.native_exit_observed-eq$true-and$t.native_exit-eq0-and$t.process_handle_retained_through_terminal-eq$true) 'Completed exact public recovery process receipt differs.'
  Need (@($p.argv).Count-eq4-and$p.argv[0]-ceq'--recover'-and$p.argv[1]-ceq$guestRecovery-and$p.argv[2]-ceq'--recovery-sha256'-and$p.argv[3]-ceq$bundleSha-and(Get-FileHash -LiteralPath $p.binary -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$exeSha) 'Postboot public binary or recovery arguments differ.'
  Need ((Get-FileHash -LiteralPath $guestBundle -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$bundleSha-and(Get-FileHash -LiteralPath (Join-Path $guestRecovery 'selected-ticket.json') -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$ticketSha) 'Original guest recovery bundle/ticket differs.'
  $out=Closed (Join-Path $stage 'native.stdout.log') 4MB;Need ($out.sha256-ceq$t.stdout.sha256-and$out.text-match'ReFS recovery completed[.] Recovery records:') 'Closed actual successful public recovery stdout differs.'
  $paths=@([regex]::Matches($out.text,'Recovery records: (C:\\ProgramData\\ntfs2refs\\runs\\recovery-[0-9a-f]{32})')|ForEach-Object {$_.Groups[1].Value}|Sort-Object -Unique);Need ($paths.Count-eq1) 'Public recovery output has no unique records path.'
  $records=Join-Path $paths[0] 'resume';$selectionFile=Closed (Join-Path $records 'lifecycle-selection.json') 1MB;$resultFile=Closed (Join-Path $records 'result.json') 1MB;$selection=$selectionFile.text|ConvertFrom-Json;$result=$resultFile.text|ConvertFrom-Json
  $valid=($selection.observed_lifecycle-ceq'apply_intent'-and$selection.selected_action-ceq'resume')-or($selection.observed_lifecycle-ceq'handoff'-and$selection.selected_action-ceq'verify_handoff')
  Need ($valid-and$selection.journal_handle_held_exclusively-eq$true-and$selection.serialized_selection_grants_authority-eq$false-and$result.success-eq$true-and$result.observed_lifecycle-ceq$selection.observed_lifecycle-and$result.action-ceq$selection.selected_action-and$result.outcome-ceq'refs_completed') 'Actual native journal classification/result differs.'
  $closedName=if($selection.selected_action-ceq'resume'){'handoff.json'}else{'verified-handoff.json'};$closed=Closed (Join-Path $records $closedName) 1MB
  $disk=Get-Disk -Number 1;$part=Get-Partition -DiskNumber 1 -PartitionNumber 2;$volume=$part|Get-Volume
  Need ([guid]$disk.Guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'-and$disk.Size-eq64GB-and[guid]$part.Guid-eq[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-and$part.Offset-eq16MB-and$part.Size-eq52GB-and-not$disk.IsOffline-and$volume.FileSystem-ceq'ReFS') 'Actual post-recovery source identity or mounted ReFS differs.'
  $taskState=(Get-ScheduledTask -TaskName $task).State.ToString()
  return @{guest_boot_ms=[long]$boot;lineage_path=[string]$token.path;lineage_sha256=[string]$tokenFile.sha256;native_pid=[int]$p.pid;native_creation_ms=[long]$p.creation_ms;native_exit=[int]$t.native_exit;native_process_sha256=[string]$pfile.sha256;native_terminal_sha256=[string]$tfile.sha256;native_stdout_sha256=[string]$out.sha256;task_state=[string]$taskState;records=[string]$records;lifecycle=[string]$selection.observed_lifecycle;action=[string]$selection.selected_action;selection_sha256=[string]$selectionFile.sha256;result_sha256=[string]$resultFile.sha256;closed_result_name=[string]$closedName;closed_result_sha256=[string]$closed.sha256;actual_filesystem=[string]$volume.FileSystem;source_disk_guid=[string]$disk.Guid}
 }
 Save 'classification.json' @{schema_version=1;kind='exact-alpha-public-recovery-post-power-observation';source_commit=$sourceCommit;binary_sha256=$exeSha;vm_id=$vmId.ToString('D');original_checkpoint=$original.ToString('D');cut_intent_sha256=$TurnoffIntentSha256;poweroff_receipt_sha256=$PoweroffReceiptSha256;postboot_dispatch_sha256=$PostbootDispatchSha256;cut_run_id=$intent.run_id;postboot_run_id=$run;observed=$observed;actual_handoff_at_power_cut='not-inferred';power_interruption_scope='Hyper-V TurnOff, not physical hardware power loss';source_admission_recreated=$false;physical_power_loss_qualified=$false;general_release_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')}
 Get-Content -LiteralPath (Join-Path $OutputDirectory 'classification.json') -Raw
}catch{if($created-and-not(Test-Path -LiteralPath (Join-Path $OutputDirectory 'classification-failed.json'))){try{Save 'classification-failed.json' @{success=$false;error=$_.Exception.ToString();automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')}}catch{}};throw}
finally{if($null-ne$session){Remove-PSSession $session -ErrorAction SilentlyContinue};foreach($f in $held){$f.Dispose()}}
