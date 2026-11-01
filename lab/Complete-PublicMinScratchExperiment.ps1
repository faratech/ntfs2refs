# Generate, but never dispatch, the read-only completion of the actual public
# d043 native0/HND run. Root reviews and copies the emitted guest script, then
# starts one SYSTEM task. No VM, converter, recovery, mover or disk-state action
# is issued here. The guest launches only the original independent digest tool.
# All original failed outputs stay in place; every new receipt uses a new child.
[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [guid]$CompletionId=[guid]::NewGuid()
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs'
$run='d04360139db64953a53a2d1448018c58'
$root=Join-Path $workspace ('.lab\hyperv\streaming-v2-20261027\public-min-scratch-'+$run)
$originalStage='C:\ntfs2refs\public-min-scratch-'+$run
$records='C:\ProgramData\ntfs2refs\runs\0dd148940f0c665732d7e146426ff52c\conversion'
$wrapperPin='c48007439d45db04b5435d9e77e6aeea8bd4e4a47817dcb6bad87a05a28b59c3'
$dispatchPin='4d8b8bdb2e8288841916235c3d3fec1f53f1fd4f5b7597a507c670ea07ac1746'
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function ReplaceOnce([string]$Text,[string]$Old,[string]$New){
    Need (($Text.Split(@($Old),[StringSplitOptions]::None)).Count-eq2) 'Frozen adaptation must match exactly once.'
    return $Text.Replace($Old,$New)
}
function HostRead([string]$Path,[string]$Pin,[long]$Maximum){
    $item=Get-Item -LiteralPath $Path -Force
    Need (-not$item.PSIsContainer-and$item.Length-gt0-and$item.Length-le$Maximum) 'Bounded ordinary host input required.'
    $a=$item;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Host input reparse ancestry refused.';if($a-is[IO.DirectoryInfo]){$a=$a.Parent}else{$a=$a.Directory}}
    $f=[IO.File]::Open($Path,'Open','Read','Read');$sha=$null;$reader=$null
    try{
        $sha=[Security.Cryptography.SHA256]::Create();$actual=([BitConverter]::ToString($sha.ComputeHash($f))).Replace('-','').ToLowerInvariant()
        Need ($actual-ceq$Pin) ('Actual closed host input pin differs: '+$item.Name)
        $f.Position=0;$reader=[IO.StreamReader]::new($f,[Text.UTF8Encoding]::new($false),$true,4096,$true)
        return $reader.ReadToEnd()
    }finally{if($null-ne$reader){$reader.Dispose()};if($null-ne$sha){$sha.Dispose()};$f.Dispose()}
}
function HostSave([string]$Name,[string]$Text){
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($Text);Need ($bytes.Length-le1MB) 'Bounded generated metadata required.'
    $f=[IO.File]::Open((Join-Path $OutputDirectory $Name),'CreateNew','Write','Read')
    try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
}
Need ($CompletionId-ne[guid]::Empty) 'Fresh nonempty completion identity required.'
$nonce=$CompletionId.ToString('N');$leaf='readonly-completion-'+$nonce
if([string]::IsNullOrEmpty($OutputDirectory)){$OutputDirectory=Join-Path $root $leaf}
Need ([IO.Path]::GetFullPath($OutputDirectory)-ceq$OutputDirectory-and
    [IO.Path]::GetDirectoryName($OutputDirectory)-ceq$root-and[IO.Path]::GetFileName($OutputDirectory)-ceq$leaf-and
    -not(Test-Path -LiteralPath $OutputDirectory)) 'New exact case-local completion directory required.'
$text=HostRead (Join-Path $root 'guest-wrapper.ps1') $wrapperPin 1MB
$dispatch=(HostRead (Join-Path $root 'dispatch.json') $dispatchPin 1MB)|ConvertFrom-Json
# These are the independently collected original guest pins, not replacement
# receipts. Their exact closed host file is pinned below before compilation.
$pinPath=Join-Path $root 'completion-input-pins.json'
$pinFileSha='e387dba6dd6543cbc4e95469cb42bc1b00fe32a82a8bce6c021027691cb9568e'
$inputs=(HostRead $pinPath $pinFileSha 1MB)|ConvertFrom-Json
$terminalPin='c24f3122e32cdf152f9582683a7c52d8fa1cdc410f8563ffa118837311b18329'
$expectedPins=@{
    (Join-Path $originalStage 'native-terminal.json')=$terminalPin
    (Join-Path $originalStage 'native-process.json')='624dbc62097ca481d571fa09a0e2f73344ffbfd88f878f14686d652c78dd27e9'
    (Join-Path $originalStage 'native-dispatch-intent.json')='9777c9ecf4ed7f39f3d90186ed98f647880038a575d0369199b5986db3f06012'
    (Join-Path $originalStage 'wrapper-failed.json')='66b1c96b48c3ebbe6927d04e8fe0902a0e170c5e42541a81bd635fddae3f14a5'
    (Join-Path $originalStage 'stdout.log')='209c9f309b9c81b632ba475a4ee1ad7cfe35c194a94988a1549840fd72e4837d'
    (Join-Path $originalStage 'stderr.log')='6bea9d3b6532c052c8a2cde9cc40e64108d127657bb4f82a74aab6821bc05dc2'
    (Join-Path $records 'result.json')='a453279c8f19fa816d634bee86278478cd7390e7a3a88da4777b03250e4c31b5'
    (Join-Path $records 'finalization.json')='24cf78cc3075428bf21e776d0736c602c4d3be89a6ebcba5ce9fc6e41073ac8d'
    (Join-Path $records 'handoff.json')='7f125406fa136f2e4bdf421a2f83b6534f4b42f9f138865119e6a33864bfa4fa'
    (Join-Path $records 'selected-ticket.json')='87b705fbd120c2b2cf14b4a61eaf43189223c89f575c1861fd61f12220d356b7'
}
Need ($inputs.Count-eq10) 'All ten independently collected closed inputs required.'
$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$pins=@(foreach($row in $inputs){
    Need ($seen.Add($row.path)-and$expectedPins.ContainsKey($row.path)-and$row.sha256-ceq$expectedPins[$row.path]-and$row.bytes-gt0-and$row.bytes-le64MB) 'Exact original closed input inventory/pin required.'
    @{path=$row.path;bytes=$row.bytes;sha256=$row.sha256}
})
$c=$dispatch.configuration
Need ($dispatch.run_id-ceq$run-and$dispatch.wrapper_sha256-ceq$wrapperPin-and$dispatch.guest_stage-ceq$originalStage-and
    $c.run_id-ceq$run-and$c.stage-ceq$originalStage-and$c.source_commit-ceq'65b117814aa8f187dfefed658b222650c72e08fe'-and
    $c.main_sha256-ceq'10aa02df6612c9f8d44440df57970aa73a23ecf7167b06ff4fd3fdf8b165afd8'-and$c.main_bytes-eq10459136-and
    $c.digest_sha256-ceq'eb56af0116b90e9e4bb0462e8cd5145d3181a4e341974a02d7b54e2586cdfbae'-and$c.digest_bytes-eq323072-and
    $c.initial_disk_count-eq6-and$c.fresh_baseline_enabled-and$c.baseline_enabled) 'Exact original public configuration required.'
$originalTask=$c.task;$c.task='N2R-PublicMinScratchCompletion-'+$nonce
$completion=@{schema_version=1;kind='public-min-scratch-readonly-completion-configuration-v1';completion_id=$nonce;
    stage=($originalStage+'\'+$leaf);task=$c.task;original_stage=$originalStage;original_task=$originalTask;
    original_wrapper_sha256=$wrapperPin;original_wrapper_bytes=138291;host_dispatch_sha256=$dispatchPin;
    native_pid=1308;native_creation_ms=1793575210964;records=$records;inputs=$pins;input_pins_host_sha256=$pinFileSha}
$c|Add-Member -NotePropertyName completion_stage -NotePropertyValue $completion.stage
$c|Add-Member -NotePropertyName completion -NotePropertyValue $completion
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
Need ($errors.Count-eq0) 'Frozen guest syntax differs.'
$tries=@($ast.EndBlock.Statements|Where-Object {$_-is[Management.Automation.Language.TryStatementAst]})
Need ($tries.Count-eq1) 'Exactly one frozen top-level native/observer block required.'
$mainTry=$tries[0];$prefix=$text.Substring(0,$mainTry.Extent.StartOffset)
$assignments=@($ast.EndBlock.Statements|Where-Object {$_-is[Management.Automation.Language.AssignmentStatementAst]-and$_.Left-is[Management.Automation.Language.VariableExpressionAst]-and$_.Left.VariablePath.UserPath-ceq'c'})
Need ($assignments.Count-eq1) 'One original literal guest configuration required.'
$configText=$assignments[0].Extent.Text
$configMatch=[regex]::Matches($configText,"FromBase64String\('([A-Za-z0-9+/=]+)'\)")
Need ($configMatch.Count-eq1) 'One original encoded configuration required.'
$originalConfig=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($configMatch[0].Groups[1].Value))|ConvertFrom-Json
Need ($originalConfig.run_id-ceq$run-and$originalConfig.stage-ceq$originalStage-and$originalConfig.main_sha256-ceq$c.main_sha256-and$originalConfig.task-ceq$originalTask) 'Frozen and dispatched configuration identities differ.'
$encoded=[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes(($c|ConvertTo-Json -Depth 32 -Compress)))
$newConfig='$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('''+$encoded+'''))|ConvertFrom-Json'
$prefix=ReplaceOnce $prefix $configText $newConfig
$prefix=ReplaceOnce $prefix '$sourceNative.schema_version-eq12-and$sourceNative.request.schema_version-eq4' '$sourceNative.schema_version-eq14-and$sourceNative.request.schema_version-eq6'
$prefix=ReplaceOnce $prefix '(Join-Path $c.stage $Name),[IO.FileMode]::CreateNew' '(Join-Path $c.completion_stage $Name),[IO.FileMode]::CreateNew'
$prefix=ReplaceOnce $prefix 'Need ($null-ne$nativeExit-and$nativeExit-eq0-and$process.HasExited)' 'Need ($null-ne$nativeExit-and$nativeExit-eq0-and$script:closedNativeHandoffVerified)'
$oldSemantic=@'
   Need ($known.sha256-cmatch'\A[0-9a-f]{32}\z'-and(SameJsonValue (PublicSemanticStream $current) (PublicSemanticStream $known))) 'Original/current stream semantic metadata differs.'
'@
$newSemantic=@'
   $currentSemantic=PublicSemanticStream $current;$knownSemantic=PublicSemanticStream $known
   if(@($name).Count-eq0-and$null-ne$time){$currentSemantic.stored_times[1]=$known.stored_times[1]}
   Need ($known.sha256-cmatch'\A[0-9a-f]{32}\z'-and(SameJsonValue $currentSemantic $knownSemantic)) 'Original/current stream semantic metadata differs.'
'@
$prefix=ReplaceOnce $prefix $oldSemantic $newSemantic
$statements=@($mainTry.Body.Statements);$start=-1
for($i=0;$i-lt$statements.Count;$i++){
    if($statements[$i]-is[Management.Automation.Language.AssignmentStatementAst]-and$statements[$i].Left-is[Management.Automation.Language.VariableExpressionAst]-and$statements[$i].Left.VariablePath.UserPath-ceq'success'){
        Need ($start-eq-1) 'Unique frozen published-success observer start required.';$start=$i
    }
}
Need ($start-ge0) 'Frozen post-native observer tail missing.'
$observer=$text.Substring($statements[$start].Extent.StartOffset,$statements[$statements.Count-1].Extent.EndOffset-$statements[$start].Extent.StartOffset)
$observer=ReplaceOnce $observer "(Join-Path `$c.stage 'independent-target-hashes.json')" "(Join-Path `$c.completion_stage 'independent-target-hashes.json')"
$guest=$prefix+@'

$script:completionInputHandles=[Collections.Generic.List[IO.FileStream]]::new()
$script:closedNativeHandoffVerified=$false
function HoldCompletionInput([string]$Path,[long]$Bytes,[string]$Pin){
 $item=FreshBaselineOrdinary $Path 64MB
 Need ($item.Length-eq$Bytes-and$Pin-cmatch'\A[0-9a-f]{64}\z') 'Exact closed completion input size/pin required.'
 $f=[IO.File]::Open($Path,'Open','Read','Read');$sha=$null
 try{
  Need ($f.Length-eq$Bytes) 'Held completion input length differs.'
  $sha=[Security.Cryptography.SHA256]::Create();$actual=([BitConverter]::ToString($sha.ComputeHash($f))).Replace('-','').ToLowerInvariant()
  Need ($actual-ceq$Pin) ('Held original input pin differs: '+$item.Name)
  $script:completionInputHandles.Add($f);$f=$null
 }finally{if($null-ne$sha){$sha.Dispose()};if($null-ne$f){$f.Dispose()}}
}
try{
 $phase='closed-native-identity-preflight'
 Need ($env:COMPUTERNAME-ceq'N2R-WIN11'-and$PSScriptRoot-ceq$c.completion.stage-and
  [IO.Path]::GetDirectoryName($c.completion.stage)-ceq$c.stage-and$c.stage-ceq$c.completion.original_stage-and
  @(Get-ChildItem -LiteralPath $c.completion.stage -Force|Where-Object {$_.Name-cne'guest-completion.ps1'}).Count-eq0) 'New exact owning-guest completion directory required.'
 $dir=Get-Item -LiteralPath $c.completion.stage -Force;$a=$dir
 while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Completion metadata reparse ancestry refused.';$a=$a.Parent}
 Idle;Source 'ReFS';Protected
 Need (@(Get-Disk).Count-eq($c.initial_disk_count+1)) 'Exact post-public shadow disk count required.'
 $originalTask=Get-ScheduledTask -TaskName $c.completion.original_task -ErrorAction Stop
 Need ($originalTask.State.ToString()-ceq'Ready'-and@($originalTask.Actions).Count-eq1-and
  $originalTask.Actions[0].Execute-ceq"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"-and
  $originalTask.Actions[0].Arguments-ceq('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $c.stage 'wrapper.ps1')+'"')) 'Original failed observer task must be terminal and unchanged.'
 HoldCompletionInput (Join-Path $c.stage 'wrapper.ps1') $c.completion.original_wrapper_bytes $c.completion.original_wrapper_sha256
 foreach($row in $c.completion.inputs){HoldCompletionInput $row.path $row.bytes $row.sha256}
 foreach($tool in $c.tools){HoldCompletionInput (Join-Path $c.stage $tool.name) $tool.bytes $tool.sha256}
 $actualTerminal=Json (Join-Path $c.stage 'native-terminal.json')
 $actualProcess=Json (Join-Path $c.stage 'native-process.json')
 $actualDispatch=Json (Join-Path $c.stage 'native-dispatch-intent.json')
 $actualFailure=Json (Join-Path $c.stage 'wrapper-failed.json')
 $cli=@('--drive','F','--partition','2','--minimize-scratch');$binary=Join-Path $c.stage 'ntfs2refs.exe'
 Need ($actualTerminal.pid-eq$c.completion.native_pid-and$actualTerminal.creation_ms-eq$c.completion.native_creation_ms-and
  $actualTerminal.native_exit_observed-eq$true-and$actualTerminal.native_exit-eq0-and$actualTerminal.expected_exit-eq0-and
  $actualProcess.pid-eq$actualTerminal.pid-and$actualProcess.creation_ms-eq$actualTerminal.creation_ms-and
  $actualProcess.binary-ceq$binary-and$actualProcess.binary_sha256-ceq$c.main_sha256-and$actualProcess.expected_exit-eq0-and
  $actualProcess.process_handle_retained_before_wait-eq$true-and(SameArray $actualProcess.argv $cli)-and
  $actualDispatch.binary-ceq$binary-and$actualDispatch.binary_sha256-ceq$c.main_sha256-and$actualDispatch.expected_exit-eq0-and
  (SameArray $actualDispatch.argv $cli)-and$actualDispatch.stdin_file-ceq(Join-Path $c.stage 'stdin-yes.txt')) 'Actual independently pinned native terminal/process/binary/CLI identity differs.'
 $live=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+$c.completion.native_pid) -ErrorAction Stop)
 Need ($live.Count-eq0-or($live.Count-eq1-and([DateTimeOffset]$live[0].CreationDate).ToUnixTimeMilliseconds()-ne$c.completion.native_creation_ms)) 'Original native PID and creation identity remain live.'
 Need ($actualFailure.success-eq$false-and$actualFailure.native_exit_observed-eq$true-and$actualFailure.native_exit-eq0-and
  $actualFailure.phase-ceq'closed-public-min-scratch-evidence'-and
  $actualFailure.error.Contains('Actual frozen source/protected residual observation is incomplete.')) 'Pinned original post-HND schema-only observer failure required.'
 $out=Log (Join-Path $c.stage 'stdout.log');$err=Log (Join-Path $c.stage 'stderr.log')
 $outJson=($out|ConvertTo-Json -Depth 4)|ConvertFrom-Json;$errJson=($err|ConvertTo-Json -Depth 4)|ConvertFrom-Json
 Need (-not$out.truncated-and-not$err.truncated-and(SameJsonValue $outJson $actualTerminal.stdout)-and
  (SameJsonValue $errJson $actualTerminal.stderr)-and$actualTerminal.metrics.native_io_counter_query_succeeded-eq$true-and
  $actualTerminal.metrics.scope-ceq'actual-public-command-native-process-v1'-and$actualTerminal.metrics.wall_seconds-gt0) 'Actual terminal logs and successfully measured original native IO required.'
 $nativeExit=$actualTerminal.native_exit
 # Keep the recorded metrics, including null/unavailable optional peaks. This
 # observer cannot measure a dead process or reconstruct its old process object.
 $metrics=@{};foreach($p in $actualTerminal.metrics.PSObject.Properties){$metrics[$p.Name]=$p.Value}
 $coreResult=Json (Join-Path $c.completion.records 'result.json')
 $coreFinal=Json (Join-Path $c.completion.records 'finalization.json')
 $handoff=Json (Join-Path $c.completion.records 'handoff.json');$ticket=Json (Join-Path $c.completion.records 'selected-ticket.json')
 Need ($coreResult.kind-ceq'experimental-allocation-bounded-conversion'-and$coreResult.success-eq$true-and
  $coreResult.source_admitted-eq$true-and$coreResult.rollback_closed-eq$true-and$coreFinal.success-eq$true-and
  $coreFinal.rollback_closed-eq$true-and$null-eq$coreFinal.error-and$handoff.replay_closed-eq$true-and
  $handoff.whole_image_verified-eq$false-and$ticket.whole_image_verified-eq$false-and
  $handoff.selected_bytes-eq$ticket.selected_bytes-and$handoff.range_count-eq$ticket.range_count-and
  $coreResult.selected_bytes-eq$ticket.selected_bytes-and$coreResult.selected_ranges-eq$ticket.range_count-and
  @($ticket.new_selected_sha256).Count-eq32-and(SameArray $handoff.selected_sha256 $ticket.new_selected_sha256)-and
  -not(Test-Path -LiteralPath (Join-Path $c.completion.records 'failed.json'))) 'Actual pinned successful core result/finalization and exact replay-closed HND/ticket required.'
 $script:closedNativeHandoffVerified=$true
 Save 'completion-native-evidence.json' @{schema_version=1;kind='independently-pinned-original-native0-and-HND-v1';
  completion_id=$c.completion.completion_id;original_run_id=$c.run_id;original_task=$c.completion.original_task;
  native_terminal=$actualTerminal;native_process=$actualProcess;original_wrapper_failure=$actualFailure;actual_input_pins=$c.completion.inputs;
  original_wrapper_sha256=$c.completion.original_wrapper_sha256;host_dispatch_sha256=$c.completion.host_dispatch_sha256;
  actual_closed_handoff=$handoff;native_exit_invented=$false;process_object_reconstructed=$false;metrics_reconstructed=$false;
  converter_launched=$false;recovery_launched=$false;raw_journal_opened=$false;device_state_changed=$false;utc=[DateTime]::UtcNow.ToString('o')}
 Idle;Protected;$phase='closed-public-min-scratch-evidence'
'@+[Environment]::NewLine+$observer+[Environment]::NewLine+@'
 Need ($records-ceq$c.completion.records-and$independentHashes.all_expected_hashes_match-eq$true-and
  $independentHashes.complete_stream_hashes-eq811-and$independentHashes.default_stream_hashes-eq811-and$independentHashes.named_stream_hashes-eq0) 'All811 independent original target stream hashes required.'
 Save 'completion-result.json' @{schema_version=1;kind='public-min-scratch-readonly-full-observer-completion-v1';success=$true;
  run_id=$c.run_id;completion_id=$c.completion.completion_id;conversion_records=$records;original_native_pid=$actualTerminal.pid;
  original_native_creation_ms=$actualTerminal.creation_ms;original_native_exit=$actualTerminal.native_exit;
  original_terminal_sha256=($c.completion.inputs|Where-Object path -CEQ (Join-Path $c.stage 'native-terminal.json')).sha256;
  original_failed_outputs_preserved=$true;actual_metrics_reused=$true;optional_unavailable_metrics_preserved=$true;
  full_original_observer_repeated=$true;semantic_metadata_masked=$false;all811_independent_hashes_match=$true;
  wrapper_result_sha256=(Get-FileHash -LiteralPath (Join-Path $c.completion_stage 'wrapper-result.json')).Hash.ToLowerInvariant();
  converter_launched=$false;recovery_launched=$false;mover_launched=$false;raw_journal_opened=$false;device_state_changed=$false;utc=[DateTime]::UtcNow.ToString('o')}
}catch{
 Save 'completion-failed.json' @{schema_version=1;success=$false;phase=$phase;error=$_.Exception.ToString();
  native_exit_observed=($null-ne$nativeExit);native_exit=$nativeExit;original_failed_outputs_preserved=$true;
  converter_launched=$false;recovery_launched=$false;mover_launched=$false;raw_journal_opened=$false;
  automatic_retry_recovery_restore_cleanup=$false;worker_death_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')};exit 1
}finally{
 foreach($entry in $script:closedJsonCache.Values){$entry.stream.Dispose()};$script:closedJsonCache.Clear();$script:labIndexes.Clear()
 foreach($stream in $script:completionInputHandles){$stream.Dispose()}
}
'@
$tokens=$null;$errors=$null;$guestAst=[Management.Automation.Language.Parser]::ParseInput($guest,[ref]$tokens,[ref]$errors)
Need ($errors.Count-eq0) ('Generated guest syntax differs: '+(($errors|ForEach-Object {$_.Message})-join'; '))
$forbidden=@('Start-Process','Start-ScheduledTask','Register-ScheduledTask','New-PSSession','Invoke-Command','Add-Type','Set-Disk','Set-Partition','Set-Volume','Initialize-Disk','Format-Volume','Mount-DiskImage','Dismount-DiskImage','Remove-Item','Move-Item')
$commands=@($guestAst.FindAll({param($n) $n-is[Management.Automation.Language.CommandAst]},$true))
Need (@($commands|Where-Object {$_.GetCommandName()-in$forbidden}).Count-eq0-and-not$guest.Contains('$process.HasExited')-and
    -not$guest.Contains('$sourceNative.schema_version-eq12')) 'Read-only completion contains a prohibited dispatcher/state operation or stale guard.'
$dynamic=@($commands|Where-Object {$_.InvocationOperator-eq[Management.Automation.Language.TokenKind]::Ampersand})
Need ($dynamic.Count-eq2-and@($dynamic|Where-Object {$_.CommandElements[0].Extent.Text-cnotin@('$Key','$tool')}).Count-eq0-and
    @($dynamic|Where-Object {$_.CommandElements[0].Extent.Text-ceq'$tool'}).Count-eq1) 'Only original index callback and pinned independent digest child may be invoked.'
New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop|Out-Null
HostSave 'guest-completion.ps1' $guest
$generatedPin=(Get-FileHash -LiteralPath (Join-Path $OutputDirectory 'guest-completion.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()
$receipt=@{schema_version=1;kind='public-min-scratch-readonly-completion-generated-v1';run_id=$run;completion_id=$nonce;
    host_directory=$OutputDirectory;guest_stage=$completion.stage;guest_script_name='guest-completion.ps1';task_name=$c.task;
    guest_script_sha256=$generatedPin;original_wrapper_sha256=$wrapperPin;original_dispatch_sha256=$dispatchPin;
    original_input_pins_sha256=$pinFileSha;actual_input_pins=$pins;native_pid=1308;native_creation_ms=1793575210964;
    conversion_records=$records;generated_only=$true;guest_task_registered=$false;guest_task_started=$false;
    original_failed_outputs_preserved=$true;native_exit_or_metrics_invented=$false;utc=[DateTime]::UtcNow.ToString('o')}
HostSave 'generation.json' ($receipt|ConvertTo-Json -Depth 16)
$receipt|ConvertTo-Json -Depth 16
