# Generate a current-run-only metadata observer. Root owns guest dispatch.
# No converter, recovery command, privilege operation, source-content scan or
# raw journal open is included in the generated script. Original failure and
# native process receipts are held and observed, never rewritten or recreated.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$CorrectedControllerSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs'
$run='e330512f550a49dda07e5700f5c4bb6a'
$original=Join-Path $workspace ('.lab\hyperv\streaming-v2-20261027\native-marker-fresh-'+$run)
$originalStage='C:\ntfs2refs\native-marker-fresh-'+$run
$controller=Join-Path $PSScriptRoot 'Start-NativeMarkerExperiment.ps1'
$id=[guid]::NewGuid().ToString('N')
$root=Join-Path $original ('completion-'+$id)
$stage='C:\ntfs2refs\native-marker-observation-'+$id
$task='N2R-NativeMarkerObservation-'+$id
$held=[Collections.Generic.List[IO.FileStream]]::new()
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function OpenPinned([string]$Path,[string]$Sha,[long]$Maximum){
 Need ([IO.Path]::GetFullPath($Path)-ceq$Path-and$Sha-cmatch'\A[0-9a-f]{64}\z') 'Canonical pinned source required.'
 $item=Get-Item -LiteralPath $Path -Force;Need (-not$item.PSIsContainer-and$item.Length-gt0-and$item.Length-le$Maximum) 'Bounded ordinary source required.'
 $cursor=$item;while($null-ne$cursor){Need (-not($cursor.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse source ancestry refused.';if($cursor-is[IO.DirectoryInfo]){$cursor=$cursor.Parent}else{$cursor=$cursor.Directory}}
 $stream=[IO.File]::Open($Path,'Open','Read','Read');$held.Add($stream);$hash=[Security.Cryptography.SHA256]::Create()
 try{$actual=([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
 Need ($actual-ceq$Sha-and$stream.Length-eq$item.Length) 'Held source SHA/length differs.';$stream.Position=0
 $reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false),$true,4096,$true);try{return $reader.ReadToEnd()}finally{$reader.Dispose()}
}
function Parse([string]$Text){$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($Text,[ref]$tokens,[ref]$errors);Need ($errors.Count-eq0) 'Pinned PowerShell source must parse.';return $ast}
function Functions($Ast){$result=@{};foreach($node in $Ast.EndBlock.Statements){if($node-is[Management.Automation.Language.FunctionDefinitionAst]){Need (-not$result.ContainsKey($node.Name)) 'Duplicate function refused.';$result[$node.Name]=$node.Extent.Text}};return $result}
function WriteNew([string]$Path,[string]$Text){$bytes=[Text.UTF8Encoding]::new($false).GetBytes($Text);Need ($bytes.Length-le1MB) 'Bounded generated artifact required.';$file=[IO.File]::Open($Path,'CreateNew','Write','Read');try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
try{
 $oldText=OpenPinned (Join-Path $original 'guest-wrapper.ps1') '5858063989f6fc5e971c195d96d35093b6fceb44a9b4e99ed2d7e627e29c4cf3' 1MB
 $configText=OpenPinned (Join-Path $original 'configuration.json') '58b6d08af3e514c051c8cf6ecdb5d593652f1c28a5f77272967fac1267a5a6e6' 1MB
 $controllerText=OpenPinned $controller $CorrectedControllerSha256 1MB
 $old=Parse $oldText;$oldFunctions=Functions $old;$hostAst=Parse $controllerText
 $body=@($hostAst.FindAll({param($n) $n-is[Management.Automation.Language.AssignmentStatementAst]-and$n.Left-is[Management.Automation.Language.VariableExpressionAst]-and$n.Left.VariablePath.UserPath-ceq'body'-and$n.Right-is[Management.Automation.Language.CommandExpressionAst]-and$n.Right.Expression-is[Management.Automation.Language.StringConstantExpressionAst]},$true))
 Need ($body.Count-eq1) 'One literal corrected guest body required; host controller is never executed.'
 $corrected=Parse $body[0].Right.Expression.Value;$correctedFunctions=Functions $corrected
 $definitions=[Collections.Generic.List[string]]::new()
 foreach($name in @('Need','ParseJson','Same','OpenPinned','Json','Save','Pin','Log','Idle','Binding','Inventory','Protected','Marker')){Need ($oldFunctions.ContainsKey($name)) 'Frozen original observer function missing.';$definitions.Add($oldFunctions[$name])}
 foreach($name in @('AdmittedEnvelope','Artifacts')){Need ($correctedFunctions.ContainsKey($name)) 'Corrected metadata observer function missing.';$definitions.Add($correctedFunctions[$name])}
 $tries=@($corrected.EndBlock.Statements|Where-Object {$_-is[Management.Automation.Language.TryStatementAst]});Need ($tries.Count-eq1) 'One corrected guest try body required.'
 $statements=@($tries[0].Body.Statements);$starts=@()
 for($i=0;$i-lt$statements.Count;$i++){$node=$statements[$i];if($node-is[Management.Automation.Language.AssignmentStatementAst]-and$node.Left.Extent.Text-ceq'$phase'-and$node.Right.Extent.Text-ceq"'terminal-observation'"){$starts+=,$i}}
 Need ($starts.Count-eq1) 'Exact terminal-only observer boundary required.'
 $observer=[Collections.Generic.List[string]]::new();$faultBranches=0
 for($i=$starts[0];$i-lt$statements.Count;$i++){
  $node=$statements[$i]
  if($node-is[Management.Automation.Language.IfStatementAst]-and$node.Clauses[0].Item1.Extent.Text-ceq'$nativeExit-eq86'){$faultBranches++;continue}
  $observer.Add($node.Extent.Text)
 }
 Need ($faultBranches-eq1) 'Remove exactly the original fault observer branch from this closed-success completion.'
 # A cold boot can leave the already-closed conversion's guest-managed VHDX
 # detached. Observe that absence only after all original HND/native proofs;
 # this completion never reconstructs a live conversion or shadow attachment.
 $shadowStarts=@();for($i=0;$i-lt$observer.Count;$i++){if($observer[$i]-ceq'$null=Binding $c.shadow $true $true'){$shadowStarts+=,$i}}
 Need ($shadowStarts.Count-eq1) 'One original required-shadow observer block required.';$at=$shadowStarts[0]
 Need ($observer[$at+1].StartsWith('$provider=Get-DiskImage ',[StringComparison]::Ordinal)-and$observer[$at+2].Contains('Original shadow provider must remain attached and offline/read-only after native work.')) 'Exact original three-statement shadow observer block required.'
 for($i=0;$i-lt3;$i++){$observer.RemoveAt($at)}
 $optionalShadow=@'
Need ($c.operation-ceq'Fresh'-and-not$c.rollback-and$nativeExit-eq0-and$result.success-eq$true-and$completion.success-eq$true-and$completion.rollback_closed-eq$true-and$closed.replay_closed-eq$true-and(Same $closed.selected_sha256 $facts.ticket.new_selected_sha256)) 'Optional original shadow applies only after this actual closed HND/ReFS completion.'
$inventory=@(Get-Disk -ErrorAction Stop);Need ($inventory.Count-gt0) 'Complete actual disk inventory required.'
$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$matches=@(foreach($disk in $inventory){$guid=[guid]::Empty;Need ([guid]::TryParse([string]$disk.Guid,[ref]$guid)-and$guid-ne[guid]::Empty-and$seen.Add($guid.ToString('D'))) 'Unknown or duplicate current disk GUID refused.';if($guid-eq[guid]$c.shadow.identity.disk_guid){$disk}})
Need ($matches.Count-le1) 'Duplicate original shadow identity refused.'
$imageItem=Get-Item -LiteralPath $c.managed_path -Force;Need (-not$imageItem.PSIsContainer-and$imageItem.Length-gt0) 'Original managed VHDX must remain an existing ordinary file.'
$cursor=$imageItem;while($null-ne$cursor){Need (-not($cursor.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse original managed VHDX ancestry refused.';if($cursor-is[IO.DirectoryInfo]){$cursor=$cursor.Parent}else{$cursor=$cursor.Directory}}
$provider=Get-DiskImage -ImagePath $c.managed_path -ErrorAction Stop
Need ([string]::Equals([string]$provider.ImagePath,$c.managed_path,[StringComparison]::OrdinalIgnoreCase)) 'Original managed VHDX provider route differs.'
if($matches.Count-eq1){
 Need ($matches[0].Number-eq$c.shadow.disk_number) 'Present original shadow disk number differs; no rebind is allowed.'
 $null=Binding $c.shadow $true $true
 Need ($provider.Attached-and[string]::Equals([string]$provider.DevicePath,'\\.\PhysicalDrive6',[StringComparison]::OrdinalIgnoreCase)) 'Present original shadow requires exact offline/read-only geometry and provider.'
}else{
 Need (-not$provider.Attached-and@($inventory|Where-Object Number -EQ $c.shadow.disk_number).Count-eq0) 'Absent original shadow requires the original provider detached and original disk number absent; no attach or replacement is allowed.'
}
Save 'optional-shadow-observation.json' @{scope='closed-handoff-optional-original-managed-shadow-v1';original_binding=$c.shadow;shadow_present=($matches.Count-eq1);provider_check_applicable=($matches.Count-eq1);original_image_path=[string]$provider.ImagePath;original_image_exists=$true;original_provider_attached=[bool]$provider.Attached;current_disk_inventory=(Inventory);all_current_disk_guids_unique=$true;original_shadow_binding_changed=$false;reattachment_performed=$false;attributes_changed=$false;closed_handoff_already_verified=$true;raw_journal_opened=$false;grants_source_or_replay_authority=$false;utc=[DateTime]::UtcNow.ToString('o')}
'@
 $completionStarts=@();for($i=0;$i-lt$observer.Count;$i++){if($observer[$i].StartsWith("Save 'native-completion-observation.json' ",[StringComparison]::Ordinal)){$completionStarts+=,$i}}
 Need ($completionStarts.Count-eq1) 'One original successful native-completion observation required.';$observer.Insert($completionStarts[0],$optionalShadow)
 $guest=@'
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$held=[Collections.Generic.List[IO.FileStream]]::new();$phase='original-metadata-pins'
$c=[pscustomobject]@{stage='__STAGE__';task='__TASK__'}
__FUNCTIONS__
try{
 Need ((Test-Path -LiteralPath $c.stage -PathType Container)-and@(Get-ChildItem -LiteralPath $c.stage -Force|Where-Object Name -CNE 'completion.ps1').Count-eq0) 'Root must stage this observer in its fresh ordinary completion directory.'
 $cursor=Get-Item -LiteralPath $c.stage -Force;while($null-ne$cursor){Need (-not($cursor.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse completion ancestry refused.';$cursor=$cursor.Parent}
 $origin='C:\ntfs2refs\native-marker-fresh-e330512f550a49dda07e5700f5c4bb6a'
 $originalConfig=OpenPinned (Join-Path $origin 'configuration.json') '58b6d08af3e514c051c8cf6ecdb5d593652f1c28a5f77272967fac1267a5a6e6' 1MB $true
 $null=OpenPinned (Join-Path $origin 'wrapper.ps1') '5858063989f6fc5e971c195d96d35093b6fceb44a9b4e99ed2d7e627e29c4cf3' 1MB $false
 $originalProcess=OpenPinned (Join-Path $origin 'native-process.json') 'bd3b3ce2ed055a1890dc738042543b0025c94bb24a950d9c47ab012bd63eac78' 1MB $true
 $terminal=OpenPinned (Join-Path $origin 'native-terminal.json') 'f536c7db6fa0d9a646f63e9093dde5f2107a6b7de8c615e0b0bec9d186bced50' 4MB $true
 $before=OpenPinned (Join-Path $origin 'preflight.json') 'eda5b4b2297068d6b11a3b60e9e3c5ab21d01dd85a1cd5a94c295deb1d2423e7' 1MB $true
 $failure=OpenPinned (Join-Path $origin 'wrapper-failed.json') '9d3c88a90c246d0aa1d9897db77eaa6705d0f74ae1f0700ef59f0d378ba8d637' 1MB $true
 Need ($originalConfig.run_id-ceq'e330512f550a49dda07e5700f5c4bb6a'-and$originalConfig.stage-ceq$origin-and$originalConfig.output-ceq(Join-Path $origin 'conversion')-and$originalConfig.operation-ceq'Fresh'-and-not$originalConfig.first_write_fault-and-not$originalConfig.rollback-and$originalConfig.expected_exit-eq0-and$originalConfig.source_commit-ceq'010316ded73a076747036198bd9036cf51dc082e') 'Exact original already-closed fresh conversion configuration required.'
 $producer=@($originalConfig.tools|Where-Object name -CEQ 'lab-selected-marker-native.exe');Need ($producer.Count-eq1-and$producer[0].sha256-ceq'8cafc1c4fc53294552e011f4786713ec8cd08419b82972091d8fd45288f2b95c') 'Actual original native producer pin required.'
 Need ($originalProcess.pid-gt0-and$originalProcess.creation_ms-gt0-and$originalProcess.binary_sha256-ceq$producer[0].sha256-and$originalProcess.expected_exit-eq0-and$originalProcess.process_handle_retained_before_wait-eq$true-and$terminal.pid-eq$originalProcess.pid-and$terminal.creation_ms-eq$originalProcess.creation_ms-and$terminal.native_exit-eq0-and$terminal.native_exit_observed-eq$true-and$terminal.process_handle_retained_through_terminal-eq$true-and'fresh'-cin@($originalProcess.argv)-and'--first-write-fault'-cnotin@($originalProcess.argv)) 'Actual original retained-handle PID/birth/exit0 receipts required; no new process evidence is created.'
 Need ($failure.observation_passed-eq$false-and$failure.phase-ceq'terminal-observation'-and$failure.native_exit-eq0-and$failure.native_exit_observed-eq$true-and$failure.error-like'*Actual original admitted request routes/policy differ*') 'Preserved original observer-only failure required.'
 $stdout=Join-Path $origin 'native.stdout.log';$stderr=Join-Path $origin 'native.stderr.log'
 Need ((Pin $stdout)-ceq$terminal.stdout.sha256-and(Get-Item -LiteralPath $stdout).Length-eq$terminal.stdout.bytes-and(Pin $stderr)-ceq$terminal.stderr.sha256-and(Get-Item -LiteralPath $stderr).Length-eq$terminal.stderr.bytes) 'Actual original terminal log bytes/pins differ.'
 $nativeExit=$terminal.native_exit;$nativePid=$originalProcess.pid;$birth=$originalProcess.creation_ms
 $c=$originalConfig;$c.stage='__STAGE__';$c.task='__TASK__'
 Idle;Protected
 $bundlePath=Join-Path $c.output 'allocation-recovery-bundle.json'
 Need ((Pin $bundlePath)-ceq'7296ac5c02ec6dfd3292e78f12d8dee48e3d08870faaf025a8f1976aa50723bd') 'Actual original closed conversion bundle pin required.'
 Save 'completion-origin.json' @{schema_version=1;kind='native-marker-readonly-metadata-completion-origin';original_run_id=$c.run_id;original_stage=$origin;original_output=$c.output;original_wrapper_sha256='5858063989f6fc5e971c195d96d35093b6fceb44a9b4e99ed2d7e627e29c4cf3';original_configuration_sha256='58b6d08af3e514c051c8cf6ecdb5d593652f1c28a5f77272967fac1267a5a6e6';original_process_sha256='bd3b3ce2ed055a1890dc738042543b0025c94bb24a950d9c47ab012bd63eac78';original_terminal_sha256='f536c7db6fa0d9a646f63e9093dde5f2107a6b7de8c615e0b0bec9d186bced50';original_preflight_sha256='eda5b4b2297068d6b11a3b60e9e3c5ab21d01dd85a1cd5a94c295deb1d2423e7';original_failure_sha256='9d3c88a90c246d0aa1d9897db77eaa6705d0f74ae1f0700ef59f0d378ba8d637';original_native_pid=$nativePid;original_native_creation_ms=$birth;original_native_exit=$nativeExit;original_wall_seconds=$terminal.wall_seconds;original_peak_working_set_bytes=$terminal.peak_working_set_bytes;original_peak_paged_memory_bytes=$terminal.peak_paged_memory_bytes;corrected_controller_sha256='__CONTROLLER_SHA__';original_failure_preserved=$true;new_native_process_started=$false;raw_journal_opened=$false;native_marker_qualified=$false;hard_power_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')}
__OBSERVER__
 Save 'completion-result.json' @{schema_version=1;kind='native-marker-readonly-metadata-completion';observation_passed=$true;original_run_id=$c.run_id;original_native_pid=$nativePid;original_native_creation_ms=$birth;original_native_exit=$nativeExit;new_native_process_started=$false;source_payload_bytes_read=0;independent_content_hashes_run=$false;raw_journal_opened=$false;original_failure_preserved=$true;optional_shadow_observation='optional-shadow-observation.json';native_marker_qualified=$false;hard_power_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')}
}catch{
 Save 'completion-failed.json' @{observation_passed=$false;phase=$phase;error=$_.Exception.ToString();original_failure_preserved=$true;new_native_process_started=$false;raw_journal_opened=$false;automatic_retry_recover_restore_cleanup=$false;worker_death_inferred=$false;native_marker_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')}
 exit 1
}finally{foreach($stream in $held){$stream.Dispose()}}
'@
 $guest=$guest.Replace('__STAGE__',$stage).Replace('__TASK__',$task).Replace('__FUNCTIONS__',($definitions-join[Environment]::NewLine)).Replace('__OBSERVER__',($observer-join[Environment]::NewLine)).Replace('__CONTROLLER_SHA__',$CorrectedControllerSha256)
 $generated=Parse $guest
 $forbidden=@($generated.FindAll({param($n) $n-is[Management.Automation.Language.CommandAst]-and$n.GetCommandName()-in@('Start-Process','Native','Invoke-Expression','Register-ScheduledTask','Start-ScheduledTask','Set-Disk','Format-Volume','Initialize-Disk','Mount-DiskImage')},$true))
 Need ($forbidden.Count-eq0-and$guest.IndexOf('ProcessStartInfo',[StringComparison]::Ordinal)-lt0-and$guest.IndexOf('::NewGuid',[StringComparison]::Ordinal)-lt0) 'Generated completion must contain metadata observation only.'
 $null=New-Item -ItemType Directory -Path $root
 $path=Join-Path $root 'completion.ps1';WriteNew $path $guest
 $pin=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
 $spec=[ordered]@{schema_version=1;kind='native-marker-metadata-completion-source';original_run_id=$run;original_guest_stage=$originalStage;original_output=($originalStage+'\conversion');completion_guest_stage=$stage;completion_task_name=$task;completion_script=$path;completion_script_sha256=$pin;completion_script_bytes=(Get-Item -LiteralPath $path).Length;corrected_controller_sha256=$CorrectedControllerSha256;root_dispatch_required=$true;expected_exit=0;new_native_process_started=$false;raw_journal_opened=$false;native_marker_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')}
 WriteNew (Join-Path $root 'completion-source.json') ($spec|ConvertTo-Json -Depth 16)
 $spec|ConvertTo-Json -Depth 16
}finally{foreach($stream in $held){$stream.Dispose()}}
