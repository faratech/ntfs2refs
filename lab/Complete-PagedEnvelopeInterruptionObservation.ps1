# Generation only. Root stages and starts this separate SYSTEM metadata observer.
# No VM call, converter, raw journal, protection change, or retry occurs here.
[CmdletBinding()]param([guid]$CompletionId=[guid]::NewGuid(),[string]$OutputDirectory='')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$originalRun='fe086985340548db9eb098a884f4d1be'
$caseRoot=Join-Path $workspace ('.lab\hyperv\streaming-v2-20261027\paged-envelope-interrupt-'+$originalRun)
$held=[Collections.Generic.List[IO.FileStream]]::new()
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function ReadHost([string]$Path,[string]$Sha){
 $m=Get-Item -LiteralPath $Path -Force;Need (-not$m.PSIsContainer-and$m.Length-gt0-and$m.Length-le1MB) 'Bounded original host metadata required.'
 $a=$m;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse host ancestry refused.';if($a-is[IO.DirectoryInfo]){$a=$a.Parent}else{$a=$a.Directory}}
 $f=[IO.File]::Open($Path,'Open','Read','Read');$held.Add($f);$h=[Security.Cryptography.SHA256]::Create();try{$pin=([BitConverter]::ToString($h.ComputeHash($f))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};Need ($pin-ceq$Sha) 'Exact preserved original source pin required.';$f.Position=0
 $r=[IO.StreamReader]::new($f,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true);try{return $r.ReadToEnd()}finally{$r.Dispose()}
}
try{
 Need ($CompletionId-ne[guid]::Empty) 'Fresh nonzero completion ID required.'
 $wrapperSha='2c37e2d01135c8ffa4a8f1d0dc178ef25fec29e2d2cd3f2e8b817f42e315aac3'
 $dispatchSha='e257ee104c122bc9240945aa866c0b2dfb13ca0de13aed2275706f9cd5304a97'
 $text=(ReadHost (Join-Path $caseRoot 'guest-wrapper.ps1') $wrapperSha).Replace(([string][char]13+[char]10),([string][char]10))
 $dispatch=(ReadHost (Join-Path $caseRoot 'dispatch.json') $dispatchSha)|ConvertFrom-Json
 Need ($dispatch.run_id-ceq$originalRun-and$dispatch.wrapper_sha256-ceq$wrapperSha-and$dispatch.expected_exit-eq86-and$dispatch.configuration.source_commit-ceq'7feb4c06d21e9de73bb88961197f5b745463e490') 'Actual original first-write dispatch differs.'
 if(-not$OutputDirectory){$OutputDirectory=Join-Path $caseRoot ('readonly-completion-'+$CompletionId.ToString('N'))}
 Need ([IO.Path]::GetFullPath($OutputDirectory)-ceq$OutputDirectory-and$OutputDirectory.StartsWith($caseRoot+'\',[StringComparison]::OrdinalIgnoreCase)-and-not(Test-Path -LiteralPath $OutputDirectory)) 'Fresh completion artifact directory required.'
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors);Need ($errors.Count-eq0) 'Preserved original worker syntax differs.'
 $definitions=[Collections.Generic.List[string]]::new()
 foreach($name in @('Need','Json','SameArray','SameJsonValue','Log','Idle','Protected','SourceRoute')){
  $nodes=@($ast.EndBlock.Statements|Where-Object {$_-is[Management.Automation.Language.FunctionDefinitionAst]-and$_.Name-ceq$name});Need ($nodes.Count-eq1) ('One original metadata function required: '+$name);$definitions.Add($nodes[0].Extent.Text)
 }
 $start='    $zeroRanges=@();';$end=';exit 86'+[char]10+'}catch{'
 $at=$text.IndexOf($start,[StringComparison]::Ordinal);$last=$text.IndexOf($end,$at,[StringComparison]::Ordinal);Need ($at-ge0-and$last-gt$at-and$text.IndexOf($start,$at+1,[StringComparison]::Ordinal)-lt0) 'Exact remaining original observer block required.'
 $remaining=$text.Substring($at,$last-$at)
 $bad='$freeRanges=if($null-ne$freeProperty){@($freeProperty.Value)}else{@()}'
 Need ([regex]::Matches($remaining,[regex]::Escape($bad)).Count-eq1) 'Only the actual scalar-array bug may be corrected.'
 $remaining=$remaining.Replace($bad,'$freeRanges=@();if($null-ne$freeProperty){$freeRanges=@($freeProperty.Value)}')
 $remaining=$remaining.Replace("observer='pinned-lab-wrapper'","observer='separate-read-only-completion-after-original-wrapper-failure'")
 $oldRoute='publication_path=(Join-Path $c.stage ''native-publication-observation.json'');publication_sha256=(Get-FileHash -LiteralPath (Join-Path $c.stage ''native-publication-observation.json''))'
 $newRoute='publication_path=(Join-Path $observation.stage ''native-publication-observation.json'');publication_sha256=(Get-FileHash -LiteralPath (Join-Path $observation.stage ''native-publication-observation.json''))'
 Need ([regex]::Matches($remaining,[regex]::Escape($oldRoute)).Count-eq1) 'One publication output route required.';$remaining=$remaining.Replace($oldRoute,$newRoute)
 $controllerSha=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
 $observation=@{stage=('C:\ntfs2refs\paged-envelope-observation-'+$CompletionId.ToString('N'));task_name=('N2R-PagedEnvelope-Observation-'+$CompletionId.ToString('N'));controller_sha256=$controllerSha;original_wrapper_sha256=$wrapperSha;original_dispatch_sha256=$dispatchSha;producer_config=$dispatch.configuration;original_run_id=$originalRun}
 $worker=@'
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$observation=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CONFIG__'))|ConvertFrom-Json
$c=$observation.producer_config;$originalTask=$c.task;$c.task=$observation.task_name
$script:closedJsonCache=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$extraHeld=[Collections.Generic.List[IO.FileStream]]::new()
__FUNCTIONS__
function Save([string]$Name,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 32));Need ($bytes.Length-le4MB) 'Bounded separate completion output required.';$f=[IO.File]::Open((Join-Path $observation.stage $Name),'CreateNew','Write','Read');try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Pin([string]$Path,[string]$Expected=''){
 Need ($Path.StartsWith('C:\',[StringComparison]::OrdinalIgnoreCase)) 'Ordinary closed C metadata only.';$m=Get-Item -LiteralPath $Path -Force;Need (-not$m.PSIsContainer-and$m.Length-ge0-and$m.Length-le64MB) 'Bounded closed metadata required.';$a=$m;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse closed metadata ancestry refused.';if($a-is[IO.DirectoryInfo]){$a=$a.Parent}else{$a=$a.Directory}}
 $f=[IO.File]::Open($Path,'Open','Read','Read');$extraHeld.Add($f);$h=[Security.Cryptography.SHA256]::Create();try{$sha=([BitConverter]::ToString($h.ComputeHash($f))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};Need ($f.Length-eq$m.Length-and(-not$Expected-or$sha-ceq$Expected)) 'Actual closed metadata pin differs.';return @{path=$Path;bytes=$f.Length;sha256=$sha}
}
try{
 Need ($env:COMPUTERNAME-ceq'N2R-WIN11'-and[Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) 'Exact owning SYSTEM observer required.'
 $ancestry=Get-Item -LiteralPath $observation.stage -Force;while($null-ne$ancestry){Need (-not($ancestry.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse observation ancestry.';$ancestry=$ancestry.Parent}
 Idle;Protected;SourceRoute $false
 $oldTask=Get-ScheduledTask -TaskName $originalTask;$oldInfo=$oldTask|Get-ScheduledTaskInfo;Need ($oldTask.State.ToString()-ceq'Ready'-and$oldInfo.LastRunTime.Year-ge2000-and$oldInfo.LastTaskResult-eq1) 'Original failed task must remain actual Ready/1.'
 $failurePath=Join-Path $c.stage 'wrapper-failed.json';$failure=Json $failurePath;$failurePin=Pin $failurePath
 Need ($failure.native_exit_observed-eq$true-and$failure.native_exit-eq86-and$failure.error-match'(?s)PropertyNotFoundException.*Count') 'Actual preserved observer Count failure required.'
 $originalProcess=Json (Join-Path $c.stage 'converter-process.json');$originalTerminal=Json (Join-Path $c.stage 'converter-terminal.json')
 Need ($originalProcess.pid-eq6004-and$originalProcess.creation_ms-eq1793661913763-and$originalProcess.expected_exit-eq86-and$originalProcess.process_handle_retained_before_wait-eq$true-and$originalProcess.raw_log_drains_started_before_wait-eq$true-and$originalProcess.binary_sha256-ceq'8b90c712bbe25806fc5c0186275d1617f2255a921a532f04a0d00640e2934fc6'-and$originalTerminal.pid-eq6004-and$originalTerminal.creation_ms-eq1793661913763-and$originalTerminal.native_exit_observed-eq$true-and$originalTerminal.native_exit-eq86-and$originalTerminal.process_handle_retained_through_terminal-eq$true) 'Actual owned native6004/birth/86 evidence required.'
 $lastExit=$originalTerminal.native_exit
 $live=@(Get-CimInstance Win32_Process -Filter 'ProcessId=6004'|Where-Object {([DateTimeOffset]$_.CreationDate).ToUnixTimeMilliseconds()-eq1793661913763});Need ($live.Count-eq0) 'Original producer still live.'
 $originalWorker=Json (Join-Path $c.stage 'wrapper-worker.json');$liveWorker=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+$originalWorker.pid)|Where-Object {([DateTimeOffset]$_.CreationDate).ToUnixTimeMilliseconds()-eq$originalWorker.creation_ms});Need ($liveWorker.Count-eq0) 'Original observer PID/birth still live.'
 $selfBirth=([DateTimeOffset](Get-Process -Id $PID).StartTime).ToUnixTimeMilliseconds();$selfSha=(Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLowerInvariant()
 $observerIdentity=@{stage=$observation.stage;task_name=$observation.task_name;pid=$PID;creation_ms=$selfBirth;controller_sha256=$observation.controller_sha256;worker_sha256=$selfSha}
 Save 'worker-observation.json' $observerIdentity
 $originalPins=[Collections.Generic.List[object]]::new()
 foreach($leaf in @('converter-process.json','converter-terminal.json','wrapper-worker.json','prepared-tail-verification.json','paged-metadata-verification.json','paged-metadata-inspection-process.json','paged-metadata-inspection-terminal.json','paged-metadata-inspection.stdout.json','converter.stdout.log','converter.stderr.log','request.json','managed-shadow.json')){$originalPins.Add((Pin (Join-Path $c.stage $leaf)))}
 $null=Pin (Join-Path $c.stage 'converter.stdout.log') $originalTerminal.stdout.sha256;$null=Pin (Join-Path $c.stage 'converter.stderr.log') $originalTerminal.stderr.sha256
 $typed=Json (Join-Path $c.stage 'paged-metadata-verification.json');$typedStdout=Json (Join-Path $c.stage 'paged-metadata-inspection.stdout.json');$typedProcess=Json (Join-Path $c.stage 'paged-metadata-inspection-process.json');$typedTerminal=Json (Join-Path $c.stage 'paged-metadata-inspection-terminal.json')
 Need ((SameJsonValue $typed $typedStdout)-and$typed.success-eq$true-and$typed.all_expected_objects_validated-eq$true-and$typed.legacy_pretty_semantic_pin_reconstructed-eq$true-and$typed.actual_expected_counts.objects-eq1534-and$typed.actual_expected_counts.directories-eq723-and$typed.actual_expected_counts.data_streams-eq811-and$typedProcess.pid-eq$typedTerminal.pid-and$typedProcess.creation_ms-eq$typedTerminal.creation_ms-and$typedProcess.process_handle_retained_before_wait-eq$true-and$typedTerminal.native_exit_observed-eq$true-and$typedTerminal.native_exit-eq0-and$typed.kind-ceq'lab-paged-resource-metadata-verification'-and$typed.grants_write_authority-eq$false-and$typed.source_device_opened-eq$false-and$typed.raw_journal_opened-eq$false) 'Actual completed independent typed metadata inspection required.'
 $null=Pin (Join-Path $c.stage 'paged-metadata-inspection.stdout.json') $typedTerminal.stdout_sha256
 $bundlePath=Join-Path $c.output 'allocation-recovery-bundle.json';$bundle=Json $bundlePath 65536;$bundlePin=(Pin $bundlePath).sha256
 $pairs=@(@{role='request';leaf='request.json';name='request_sha256'},@{role='expectation';leaf='expectation.json';name='expectation_sha256'},@{role='expectation_pages';leaf='expectation.pages';name='expected_pages_sha256'},@{role='plan';leaf='selected-plan.json';name='plan_sha256'},@{role='ticket';leaf='selected-ticket.json';name='ticket_sha256'},@{role='recovery_payload_manifest';leaf='recovery-payload-manifest.pages';name='payload_pages_sha256'})
 $pins=@{}
 foreach($pair in $pairs){$path=Join-Path $c.output $pair.leaf;$value=$bundle.($pair.role);Need ($value.path-ceq$path-and$value.sha256-ceq$typed.($pair.name)) 'Typed/bundle actual input association differs.';$originalPins.Add((Pin $path $value.sha256));$pins[$pair.role]=$value.sha256}
 $vp=Join-Path $c.output 'verification.json';Need ($bundle.verification.path-ceq$vp) 'Actual verification path differs.';$pins.verification=(Pin $vp $bundle.verification.sha256).sha256
 $rr=Json (Join-Path $c.output 'request.json');$plan=Json (Join-Path $c.output 'selected-plan.json');$ticket=Json (Join-Path $c.output 'selected-ticket.json');$expectation=Json (Join-Path $c.output 'expectation.json');$location=Json (Join-Path $c.output 'journal-location.json');$maps=$typed.complete_recovery_map_inspection
 $r=Json (Join-Path $c.stage 'request.json');$request=Join-Path $c.stage 'request.json';$requestPin=(Pin $request).sha256;$planning=$r.source_resource_profile.experimental_object_envelope_v3;Need ($null-eq$planning-and'--fresh-exclusive-v3-first-write'-cin@($originalProcess.argv)-and$requestPin-cin@($originalProcess.argv)-and$request-cin@($originalProcess.argv)-and$rr.source_resource_profile.experimental_object_envelope_v3.schema_version-eq2) 'Original fresh planningNone/actual admittedSome2 producer binding differs.'
 $managed=Json (Join-Path $c.stage 'managed-shadow.json');$b=$managed.binding;$source=Get-Disk -Number 1;$shadowDisk=Get-Disk -Number $b.disk_number;Need ($source.IsOffline-and-not$source.IsReadOnly-and[guid]$shadowDisk.Guid-eq[guid]$b.identity.disk_guid-and$shadowDisk.IsOffline-and$shadowDisk.IsReadOnly) 'Actual source1/shadow3 exclusion required.'
 $tailVerification=Json (Join-Path $c.stage 'prepared-tail-verification.json');Need ($tailVerification.tail_extent_only_streams-eq650-and$tailVerification.materialized_tail_bytes-eq1371388) 'Original completed exact tail receipt required.'
 $stdoutPath=Join-Path $c.stage 'converter.stdout.log';$stdout=[IO.File]::ReadAllText($stdoutPath);$checksums=[regex]::Matches($stdout,'(?m)^Recovery checksum: ([0-9a-f]{64})\r?$');$directories=[regex]::Matches($stdout,'(?m)^Recovery directory: (.+?)\r?$');Need ($checksums.Count-eq1-and$directories.Count-eq1-and$checksums[0].Groups[1].Value-ceq$bundlePin-and$directories[0].Groups[1].Value-ceq$c.output) 'Actual native publication lines differ.'
__REMAINING__
 Idle;Protected;SourceRoute $false
 $oldTask=Get-ScheduledTask -TaskName $originalTask;$oldInfo=$oldTask|Get-ScheduledTaskInfo;Need ($oldTask.State.ToString()-ceq'Ready'-and$oldInfo.LastTaskResult-eq1-and(Pin $failurePath).sha256-ceq$failurePin.sha256) 'Original failed observer or failure bytes changed.'
 Save 'verified-completion.json' @{schema_version=1;kind='paged-envelope-read-only-observer-completion-v1';success=$true;original_run_id=$observation.original_run_id;original_stage=$c.stage;original_task_name=$originalTask;original_task_state='Ready';original_task_result=1;original_wrapper_sha256=$observation.original_wrapper_sha256;original_wrapper_failure=$failurePin;producer=@{pid=$originalProcess.pid;creation_ms=$originalProcess.creation_ms;native_exit=$originalTerminal.native_exit;native_exit_observed=$originalTerminal.native_exit_observed};observer=$observerIdentity;publication=(Pin (Join-Path $observation.stage 'native-publication-observation.json'));controlled_interruption=(Pin (Join-Path $observation.stage 'wrapper-controlled-interruption.json'));original_metadata_pins=$originalPins.ToArray();all_remaining_original_checks_passed=$true;original_failure_preserved=$true;original_task_exit86_fabricated=$false;converter_launched=$false;raw_journal_opened=$false;protection_changed=$false;source_admission_recreated=$false;utc=[DateTime]::UtcNow.ToString('o')}
 exit 0
}catch{Save 'completion-failed.json' @{success=$false;original_failure_preserved=$true;error=$_.Exception.ToString();position=$_.InvocationInfo.PositionMessage;stack=$_.ScriptStackTrace;converter_launched=$false;raw_journal_opened=$false;protection_changed=$false};exit 1}
finally{foreach($entry in $script:closedJsonCache.Values){$entry.stream.Dispose()};foreach($f in $extraHeld){$f.Dispose()}}
'@
 $worker=$worker.Replace('__FUNCTIONS__',($definitions-join[Environment]::NewLine)).Replace('__REMAINING__',$remaining).Replace('__CONFIG__',[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes(($observation|ConvertTo-Json -Depth 32 -Compress))))
 $tokens=$null;$errors=$null;$generated=[Management.Automation.Language.Parser]::ParseInput($worker,[ref]$tokens,[ref]$errors);Need ($errors.Count-eq0) 'Generated metadata-only observer parse failed.'
 Need (@($generated.FindAll({param($n)$n-is[Management.Automation.Language.CommandAst]-and$n.GetCommandName()-in@('Native','Start-Process','Start-ScheduledTask','Set-Disk','Mount-DiskImage','Dismount-DiskImage','Stop-VM','Restore-VMSnapshot','Checkpoint-VM')},$true)).Count-eq0) 'Completion cannot launch native work or mutate source/VM state.'
 New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
 $workerPath=Join-Path $OutputDirectory 'guest-completion.ps1';[IO.File]::WriteAllText($workerPath,$worker,[Text.UTF8Encoding]::new($false));$workerPin=(Get-FileHash -LiteralPath $workerPath).Hash.ToLowerInvariant()
 $answer=@{schema_version=1;kind='generated-read-only-paged-envelope-observer';worker_path=$workerPath;worker_sha256=$workerPin;controller_sha256=$controllerSha;guest_stage=$observation.stage;task_name=$observation.task_name;staged_worker_leaf='guest-completion.ps1';original_case=$caseRoot;original_wrapper_sha256=$wrapperSha;original_dispatch_sha256=$dispatchSha;expected_exit=0;vm_action_performed=$false;original_native_exit=86;original_native_pid=6004;original_native_creation_ms=1793661913763;original_task_result_must_remain=1;verified_completion_path=(Join-Path $observation.stage 'verified-completion.json');worker_observation_path=(Join-Path $observation.stage 'worker-observation.json');publication_path=(Join-Path $observation.stage 'native-publication-observation.json');control_path=(Join-Path $observation.stage 'wrapper-controlled-interruption.json')}
 [IO.File]::WriteAllText((Join-Path $OutputDirectory 'generation.json'),($answer|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false));$answer|ConvertTo-Json -Depth 12
}finally{foreach($f in $held){$f.Dispose()}}
