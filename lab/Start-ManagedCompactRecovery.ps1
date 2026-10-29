# Future one-shot typed recovery; root preserves/boots partial51 separately.
# Wrapper opens C metadata only. J/packed/VHDX/raw access belongs to the native engine.
[CmdletBinding()]param(
 [Parameter(Mandatory)][ValidateSet('Resume','Rollback')][string]$Operation,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$PartialReceiptSha256
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$Operation=if($Operation-ieq'Resume'){'Resume'}else{'Rollback'}
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027';$original='94eebb1101354d2ca42c2f8f0608f6a0'
$case=Join-Path $base ('managed-compact-interrupt-20261028-'+$original);$root=Join-Path $case ('recovery-'+$Operation.ToLowerInvariant())
$originalStage='C:\ntfs2refs\managed-compact-interrupt-'+$original;$originalOutput=Join-Path $originalStage 'conversion'
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$provider='c87de389-e6ac-457a-bcbd-ad0cc0b15164'
$manifestPath=Join-Path $base 'managed-recovery-tools-20261028-b\manifest.json';$manifestPin='c60df8172afa853f7be612851057c6bc2920f4fb6ec690f25906a8f00d28c411'
$binaryPin='b1f3cde889d38d4d62c253c1dfff64cb650df50b72971c01e0bda60c8ea5bca9';$binaryBytes=4673536
$run=[guid]::NewGuid().ToString('N');$stage='C:\ntfs2refs\managed-compact-recovery-'+$Operation.ToLowerInvariant()+'-'+$run;$task='N2R-ManagedCompactRecovery-'+$Operation+'-'+$run
$held=[Collections.Generic.List[IO.FileStream]]::new();$loadedBytes=[long]0;$session=$null;$created=$false;$phase='closed-host-evidence'
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function Digest([byte[]]$Bytes){$s=[Security.Cryptography.SHA256]::Create();try{[BitConverter]::ToString($s.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}finally{$s.Dispose()}}
function Ordinary([string]$Path,[bool]$Directory){$m=Get-Item -LiteralPath $Path -Force;Need ([bool]$m.PSIsContainer-eq$Directory-and-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Ordinary host path required.';$p=if($m.PSIsContainer){$m.Parent}else{$m.Directory};while($null-ne$p){Need (-not($p.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse host ancestry.';$p=$p.Parent};$m}
function Json([string]$Path,[string]$Pin=''){
 $m=Ordinary $Path $false;Need ($m.Length-gt0-and$m.Length-le4MB) 'Bounded closed host JSON required.';$script:loadedBytes+=$m.Length;Need ($script:loadedBytes-le20MB) 'Closed JSON aggregate exceeds20MiB.'
 $f=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$held.Add($f);$b=[byte[]]::new([int]$m.Length);$at=0
 while($at-lt$b.Length){$n=$f.Read($b,$at,$b.Length-$at);Need ($n-gt0) 'Short metadata read.';$at+=$n};Need ($f.Length-eq$b.Length) 'Closed metadata changed.';$hash=Digest $b;if($Pin){Need ($hash-ceq$Pin) 'Closed metadata SHA differs.'}
 [pscustomobject]@{sha256=$hash;value=([Text.UTF8Encoding]::new($false,$true).GetString($b).TrimStart([char]0xfeff)|ConvertFrom-Json)}
}
function Save([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 24));Need ($b.Length-le4MB) 'Host receipt exceeds4MiB.';$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
try{
 Need (-not(Test-Path -LiteralPath $root)) 'This role has state; inspect without redispatch.'
 $saved=(Json (Join-Path $case 'partial-checkpoint.json') $PartialReceiptSha256).value
 Need ($saved.success-eq$true-and$saved.run_id-ceq$original-and[guid]$saved.vm_id-eq$id-and$saved.checkpoint_count-eq51-and$saved.all_prior50_preserved-eq$true-and$saved.state-ceq'Off'-and$saved.memory_assigned-eq0-and$saved.controlled_interruption_observed-eq$true-and$saved.conversion_success-eq$false-and$saved.native_exit_observed-eq$true-and$saved.native_exit-eq86-and$saved.interrupt_after_writes-eq1-and$saved.raw_recovery_authorized-eq$false) 'Actual successful partial51/observed86 required.'
 $parent=[guid]$saved.checkpoint_id;Need ($parent-ne[guid]::Empty-and[guid]$saved.parent_id-eq[guid]'9e63e9d2-a0e4-408f-87b5-26d31fbdcc24') 'Partial51 lineage differs.'
 $enrollment=(Json (Join-Path $case 'intent.json')).value;$d=(Json (Join-Path $case 'dispatch.json')).value
 $old=@($enrollment.checkpoint_ids|ForEach-Object {([guid]$_).ToString('D')});Need ($old.Count-eq50-and@($old|Sort-Object -Unique).Count-eq50-and$parent.ToString('D')-notin$old) 'Distinct complete prior50 required.';$all51=@($old)+@($parent.ToString('D'))
 Need ($d.run_id-ceq$original-and[guid]$d.vm_id-eq$id-and$d.task_name-ceq('N2R-ManagedCompact-Interrupt-'+$original)-and$d.guest_stage-ceq$originalStage-and$d.output_dir-ceq$originalOutput-and$d.expected_exit-eq86-and$d.interrupt_after_writes-eq1-and$d.wrapper_sha256-ceq'91c45dc9fd96b2ad08dfa3f36ac31b8cf817b17a018233cf9e531cb9900cd5e4'-and$d.toolset_manifest_sha256-ceq$manifestPin) 'Original94e dispatch differs.'
 $partial=(Json (Join-Path $case 'partial-metadata-pins.json') $saved.metadata_pins_sha256).value
 Need ($partial.kind-ceq'closed-managed-partial-metadata-observation'-and$partial.run_id-ceq$original-and$partial.controlled_interruption_observed-eq$true-and$partial.native_exit_observed-eq$true-and$partial.native_exit-eq86-and$partial.interrupt_after_writes-eq1) 'Closed partial metadata differs.'
 $values=@{};$pins=@{};$sources=@{}
 foreach($doc in $partial.documents){Need ($doc.name-cmatch'\A[a-z-]+\.json\z'-and-not$values.ContainsKey($doc.name)-and$doc.sha256-cmatch'\A[0-9a-f]{64}\z') 'Invalid/duplicate archive leaf.';$p=Join-Path $case ('partial-metadata\'+$doc.name);Need ((Ordinary $p $false).Length-eq$doc.bytes) 'Archive length differs.';$values[$doc.name]=(Json $p $doc.sha256).value;$pins[$doc.name]=$doc.sha256;$sources[$doc.name]=[string]$doc.source}
 foreach($name in @('request.json','ticket.json','expectation.json','compact-backing.json','journal-location.json','interruption-intent.json','qualification-composite-capture.json','managed-result.json','wrapper-controlled-interruption.json','converter-process.json','wrapper-worker.json','converter-terminal.json')){Need ($values.ContainsKey($name)) ('Missing closed metadata: '+$name)}
 $request=$values['request.json'];$ticket=$values['ticket.json'];$expected=$values['expectation.json'];$backing=$values['compact-backing.json'];$capture=$values['qualification-composite-capture.json'];$location=$values['journal-location.json'];$fault=$values['interruption-intent.json'];$managed=$values['managed-result.json'];$closed=$values['wrapper-controlled-interruption.json']
 Need ($request.experiment_id-ceq$original-and$request.schema_version-eq2-and$request.source_resource_profile-ceq'experimental_streaming_tree_v2'-and$request.expected_tree_sha256-ceq$pins['expectation.json']-and$ticket.binding.experiment_id-ceq$original-and$closed.controlled_interruption_observed-eq$true-and$closed.native_exit_observed-eq$true-and$closed.native_exit-eq86-and$closed.conversion_success-eq$false-and$values['converter-terminal.json'].native_exit_observed-eq$true-and$values['converter-terminal.json'].native_exit-eq86) 'Reconstruction inputs/actual controlled86 differ.'
 foreach($spec in @(@{b=$request.pair.source;n=1;g='1b191872-c372-41ee-a416-e18863996f54';p='f06075a8-67a2-46b9-8fac-4af4da809617';o=16MB},@{b=$request.pair.shadow;n=6;g='f65b9b29-c38c-49c9-9ef0-ae8869c2df5d';p='57aa3a34-1910-4adc-ad5c-3a32a7017c03';o=32MB})){Need ($spec.b.disk_number-eq$spec.n-and[guid]$spec.b.identity.disk_guid-eq[guid]$spec.g-and[guid]$spec.b.identity.partition_guid-eq[guid]$spec.p-and$spec.b.identity.partition_offset-eq$spec.o-and$spec.b.identity.partition_bytes-eq52GB-and$spec.b.identity.logical_sector_bytes-eq512-and$spec.b.identity.physical_sector_bytes-eq4096) 'Original source1/managed6 identity differs.'}
 Need ($request.journal.disk.disk_number-eq0-and$request.journal.allow_additional_partitions-eq$true-and$request.max_journal_bytes-eq1073741824-and$backing.kind-ceq'experimental-live-composite-recovery-backing'-and$backing.request_sha256-ceq$pins['request.json']-and$backing.expected_tree_sha256-ceq$pins['expectation.json']-and$backing.artifact.report_sha256-ceq$pins['qualification-composite-capture.json']-and$backing.artifact.packed_sha256-cmatch'\A[0-9a-f]{64}\z'-and$capture.source_sha256-ceq$request.comparison.source_sha256-and$capture.composite_target_sha256-ceq$request.comparison.shadow_sha256-and$capture.expected_tree_sha256-ceq$pins['expectation.json']-and$capture.native.compact_difference_capture.packed_sha256-ceq$backing.artifact.packed_sha256-and$fault.ticket_sha256-ceq$pins['ticket.json']-and$fault.expected_process_exit_code-eq86-and$fault.interrupt_after_writes-eq1-and$fault.journal_path-ceq$location.path) 'Declared capture/backing/journal bindings differ; payload is not opened here.'
 $managedPath=Join-Path $originalStage 'managed-shadow\shadow.vhdx';Need ($managed.success-eq$true-and$managed.path-ceq$managedPath-and[guid]$managed.virtual_disk_id-eq[guid]$provider-and[guid]$managed.binding.identity.disk_guid-eq[guid]$request.pair.shadow.identity.disk_guid-and[guid]$managed.binding.identity.partition_guid-eq[guid]$request.pair.shadow.identity.partition_guid) 'Original managed identity/path differs.'
 foreach($name in @('request.json','ticket.json','expectation.json')){Need ($sources[$name]-ceq(Join-Path $originalOutput $name)) 'Original reconstruction paths required, not binder input.'}
 Need ($sources['qualification-composite-capture.json']-ceq(Join-Path $originalOutput 'qualification\composite-capture.json')-and$backing.report_path-ceq$sources['qualification-composite-capture.json']-and$backing.packed_path-ceq(Join-Path $originalOutput 'qualification\changed-clusters.bin')) 'Original capture/packed routes differ.'
 $inputs=@{request=$sources['request.json'];request_sha256=$pins['request.json'];ticket=$sources['ticket.json'];ticket_sha256=$pins['ticket.json'];capture=$backing.report_path;capture_sha256=$pins['qualification-composite-capture.json'];packed=$backing.packed_path;packed_sha256=$backing.artifact.packed_sha256;expectation=$sources['expectation.json'];expectation_sha256=$pins['expectation.json'];journal=[string]$location.path}
 $metadataInputs=@();foreach($name in @('request.json','ticket.json','expectation.json','compact-backing.json','journal-location.json','qualification-composite-capture.json','managed-result.json','wrapper-controlled-interruption.json')){$metadataInputs+=@{path=$sources[$name];sha256=$pins[$name]}}
 $manifest=(Json $manifestPath $manifestPin).value;$tools=@($manifest.tools|Where-Object name -CEQ 'ntfs2refs-compact.exe');Need ($manifest.kind-ceq'selected-managed-recovery-toolset'-and$manifest.schema_version-eq1-and$tools.Count-eq1) 'Sealed recovery toolset required.';$tool=$tools[0]
 Need ($tool.path-ceq(Join-Path ([IO.Path]::GetDirectoryName($manifestPath)) 'ntfs2refs-compact.exe')-and$tool.sha256-ceq$binaryPin-and$tool.bytes-eq$binaryBytes-and(Ordinary $tool.path $false).Length-eq$binaryBytes-and(Get-FileHash -LiteralPath $tool.path).Hash.ToLowerInvariant()-ceq$binaryPin) 'Actual sealed b1f3 compact executable differs.'
 Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force;$config=Get-LabConfiguration -WorkspaceRoot $workspace;$capacity=Get-LabCapacity -Configuration $config
 Need ($capacity.MaximumActualBytes-eq329374052988-and$capacity.MinimumFreeBytes-eq17179869184) 'Fixed50GB epoch differs.';Assert-LabCapacity -Capacity $capacity -AdditionalBytes 7GB
 function Host-Guard{$v=Get-VM -Id $id;$s=@(Get-VMSnapshot -VM $v);$ids=@($s.Id|ForEach-Object {$_.ToString('D')});Need ($v.Name-ceq'ntfs2refs-streaming-v2-20261027'-and$v.State.ToString()-ceq'Running'-and$v.ParentSnapshotId-eq$parent-and$v.MemoryStartup-eq4GB-and-not$v.DynamicMemoryEnabled-and@(Get-VMNetworkAdapter -VM $v).Count-eq0-and$s.Count-eq51-and@($all51|Where-Object {$_-notin$ids}).Count-eq0) 'Already-running partial51/all51 required; no boot/restore is available.'}
 Host-Guard;$null=New-Item -ItemType Directory -Path $root -ErrorAction Stop;$created=$true
 $c=@{operation=$Operation;run_id=$run;original_run_id=$original;stage=$stage;task=$task;original_stage=$originalStage;original_task=$d.task_name;original_wrapper_sha256=$d.wrapper_sha256;tool_pin=$binaryPin;tool_bytes=$binaryBytes;inputs=$inputs;metadata_inputs=$metadataInputs;request_value=$request;expectation_value=$expected;managed_path=$managedPath;managed_id=$provider;original_native=$values['converter-process.json'];original_wrapper=$values['wrapper-worker.json']}
 Save 'intent.json' @{run_id=$run;original_run_id=$original;operation=$Operation;vm_id=$id.ToString('D');parent_id=$parent.ToString('D');checkpoint_ids=$all51;partial_receipt_sha256=$PartialReceiptSha256;metadata_pins_sha256=$saved.metadata_pins_sha256;manifest_sha256=$manifestPin;tool=$tool;inputs=$inputs;managed_shadow_path=$managedPath;managed_shadow_id=$provider;capacity=$capacity;forecast_bytes=[long]7GB;forecast_is_not_reservation=$true;fresh_apply_authorized=$false;source_certificate_recreated=$false;restore_boot_rebind_cleanup_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')}
 $body=@'
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$c=[Text.UTF8Encoding]::new($false).GetString([Convert]::FromBase64String('__CONFIG__'))|ConvertFrom-Json;$phase='preflight';$script:lastExit=$null
function Save([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));if($b.Length-gt4MB){throw 'Wrapper receipt exceeds4MiB.'};$f=[IO.File]::Open((Join-Path $c.stage $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Json([string]$Path){$m=Get-Item -LiteralPath $Path -Force;if($m.PSIsContainer-or($m.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$m.Length-le0-or$m.Length-gt4MB){throw 'Bounded ordinary C metadata required.'};$p=$m.Directory;while($null-ne$p){if($p.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse C metadata ancestry.'};$p=$p.Parent};Get-Content -LiteralPath $Path -Raw -Encoding UTF8|ConvertFrom-Json}
function Idle{
 $tasks=@(Get-ScheduledTask -ErrorAction Stop);$processes=@(Get-CimInstance Win32_Process -ErrorAction Stop)
 if(@($tasks|Where-Object {$_.TaskName-like'N2R-*'-and$_.TaskName-cne$c.task-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-or@($processes|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count){throw 'Another project worker/task is active or unknown.'}
 foreach($x in @($c.original_native,$c.original_wrapper)){foreach($p in @($processes|Where-Object ProcessId -eq $x.pid)){if(([DateTimeOffset]$p.CreationDate).ToUnixTimeMilliseconds()-eq[long]$x.creation_ms){throw 'An original worker creation still exists.'}}}
}
function Protected{
 $g=Get-Disk -Number 4 -ErrorAction Stop;$gp=Get-Partition -DriveLetter G -ErrorAction Stop;$gv=$gp|Get-Volume -ErrorAction Stop;$old=Get-Disk -Number 5 -ErrorAction Stop
 if([guid]$g.Guid-ne[guid]'e1f3b9d3-979f-4123-9fee-399640c25092'-or$g.IsOffline-or$g.IsReadOnly-or$gp.DiskNumber-ne4-or$gv.FileSystem-cne'ReFS'-or$gv.AllocationUnitSize-ne4096-or[guid]$old.Guid-ne[guid]'ad077674-6305-4767-a2aa-6ded3b707e36'-or-not$old.IsOffline-or-not$old.IsReadOnly){throw 'Preserved G4/shadow5 differs.'}
}
function Source([bool]$Online,[string]$Filesystem=''){
 $d=Get-Disk -Number 1 -ErrorAction Stop;$p=Get-Partition -DiskNumber 1 -PartitionNumber 2 -ErrorAction Stop
 if([guid]$d.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or$d.Size-ne64GB-or$d.IsBoot-or$d.IsSystem-or$d.IsReadOnly-or[bool]$d.IsOffline-eq$Online-or[guid]$p.Guid-ne[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-or$p.Offset-ne16MB-or$p.Size-ne52GB){throw 'Actual original source1 binding/exclusion differs.'}
 if($Online){$v=$p|Get-Volume -ErrorAction Stop;$cluster=if($Filesystem-ceq'ReFS'){4096}else{65536};if($v.FileSystem-cne$Filesystem-or$v.AllocationUnitSize-ne$cluster-or$v.FileSystemLabel-cne'n2r-stream-source'-or'F:\'-notin@($p.AccessPaths)){throw 'Recovered original filesystem/label/F mount differs.'}}
}
function Shadow{
 $d=Get-Disk -Number 6 -ErrorAction Stop;$b=$c.request_value.pair.shadow;$p=Get-Partition -DiskNumber 6 -PartitionNumber $b.identity.partition_number -ErrorAction Stop
 if([guid]$d.Guid-ne[guid]'f65b9b29-c38c-49c9-9ef0-ae8869c2df5d'-or-not$d.IsOffline-or-not$d.IsReadOnly-or$d.IsBoot-or$d.IsSystem-or[guid]$p.Guid-ne[guid]'57aa3a34-1910-4adc-ad5c-3a32a7017c03'-or$p.Offset-ne32MB-or$p.Size-ne52GB){throw 'Typed engine did not leave the exact managed6 shadow frozen.'}
}
function Log([string]$Path){$m=Get-Item -LiteralPath $Path -Force;if($m.PSIsContainer-or($m.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$m.Length-gt8MB){throw 'Native log exceeds bound; preserve without retry.'};$reader=[IO.StreamReader]::new($Path);try{$chars=[char[]]::new(32768);$count=$reader.ReadBlock($chars,0,$chars.Length);@{path=$Path;bytes=$m.Length;sha256=(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant();text=[string]::new($chars,0,$count);truncated=($reader.Peek()-ne-1)}}finally{$reader.Dispose()}}
function Native([string]$Role,[string[]]$Cli){
 $binary=Join-Path $c.stage 'ntfs2refs-compact.exe';if((Get-Item -LiteralPath $binary).Length-ne$c.tool_bytes-or(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()-cne$c.tool_pin){throw 'Sealed compact binary changed.'}
 $arguments=($Cli|ForEach-Object {if($_-cmatch'["\r\n\x00]'){throw 'Unsafe native argument.'};$tail=$_.Length-$_.TrimEnd('\').Length;'"'+$_+('\'*$tail)+'"'})-join' '
 Save ($Role+'-dispatch-intent.json') @{binary=$binary;binary_sha256=$c.tool_pin;argv=$Cli;expected_exit=0;started_at_most_once=$true;utc=[DateTime]::UtcNow.ToString('o')}
 $p=$null;$script:lastExit=$null
 try{
  $p=Start-Process -FilePath $binary -ArgumentList $arguments -WorkingDirectory $c.stage -RedirectStandardOutput (Join-Path $c.stage ($Role+'.stdout.log')) -RedirectStandardError (Join-Path $c.stage ($Role+'.stderr.log')) -PassThru -WindowStyle Hidden;$null=$p.Handle
  Save ($Role+'-process.json') @{pid=$p.Id;creation_ms=([DateTimeOffset]$p.StartTime).ToUnixTimeMilliseconds();parent_pid=$PID;binary=$binary;binary_sha256=$c.tool_pin;argv=$Cli;process_handle_retained_before_wait=$true;expected_exit=0;utc=[DateTime]::UtcNow.ToString('o')}
  $p.WaitForExit();$p.Refresh();$script:lastExit=$p.ExitCode
  Save ($Role+'-terminal.json') @{native_exit=$lastExit;native_exit_observed=($null-ne$lastExit);expected_exit=0;stdout=(Log (Join-Path $c.stage ($Role+'.stdout.log')));stderr=(Log (Join-Path $c.stage ($Role+'.stderr.log')));utc=[DateTime]::UtcNow.ToString('o')}
  if($null-eq$lastExit-or$lastExit-ne0){throw ($Role+' actual native exit was not zero.')}
 }finally{if($null-ne$p){$p.Dispose()}}
}
try{
 Idle;Protected;Source $false
 $disks=@(Get-Disk -ErrorAction Stop)
 if(@($disks|Where-Object {$_.Number-eq6-or($_.Guid-and[guid]$_.Guid-eq[guid]'f65b9b29-c38c-49c9-9ef0-ae8869c2df5d')}).Count){throw 'Managed6 must be absent after root booted partial51; never detach/rebind here.'}
 $old=Get-ScheduledTask -TaskName $c.original_task -ErrorAction Stop;$oi=Get-ScheduledTaskInfo -TaskName $c.original_task -ErrorAction Stop
 if($old.State.ToString()-cne'Ready'-or$oi.LastTaskResult-ne86-or$oi.LastRunTime.Year-lt2026-or(Get-FileHash -LiteralPath (Join-Path $c.original_stage 'wrapper.ps1')).Hash.ToLowerInvariant()-cne$c.original_wrapper_sha256){throw 'Original controlled wrapper86/pin differs.'}
 foreach($m in $c.metadata_inputs){$null=Json $m.path;if((Get-FileHash -LiteralPath $m.path).Hash.ToLowerInvariant()-cne$m.sha256){throw 'Original closed C input differs from the partial51 archive.'}}
 if((Get-Partition -DriveLetter C -ErrorAction Stop).DiskNumber-ne0){throw 'OS-journal route changed.'}
 Save 'wrapper-worker.json' @{pid=$PID;creation_ms=([DateTimeOffset](Get-Process -Id $PID).StartTime).ToUnixTimeMilliseconds();original_run_id=$c.original_run_id;operation=$c.operation;utc=[DateTime]::UtcNow.ToString('o')}
 $x=$c.inputs
 $common=@('--acknowledge-experimental-compact','--request',$x.request,'--request-sha256',$x.request_sha256,'--ticket',$x.ticket,'--ticket-sha256',$x.ticket_sha256,'--journal',$x.journal,'--capture',$x.capture,'--capture-sha256',$x.capture_sha256,'--packed',$x.packed,'--packed-sha256',$x.packed_sha256,'--expectation',$x.expectation,'--expectation-sha256',$x.expectation_sha256)
 $first=Join-Path $c.stage $c.operation.ToLowerInvariant();$phase='typed-reattach-and-'+$c.operation.ToLowerInvariant()
 Native $c.operation.ToLowerInvariant() (@($c.operation.ToLowerInvariant())+$common+@('--managed-shadow',$c.managed_path,'--managed-shadow-id',$c.managed_id,'--output',$first))
 Idle;Protected;$result=Json (Join-Path $first 'result.json');$execution=Json (Join-Path $first 'execution.json');$r=$c.request_value
 $expectedHash=if($c.operation-ceq'Resume'){$r.comparison.shadow_sha256}else{$r.comparison.source_sha256}
 if($result.kind-cne'experimental-compact-recovery'-or$result.success-ne$true-or$result.operation-cne$c.operation.ToLowerInvariant()-or$execution.expected_target_sha256-cne$expectedHash-or$execution.result.target_sha256-cne$expectedHash-or$execution.target_after.disk_attributes-ne1-or$execution.shadow_after.disk_attributes-ne3){throw 'Typed recovery did not prove the exact original excluded image.'}
 if($c.operation-ceq'Resume'){
  if($result.target_remains_offline-ne$true-or$result.rollback_closed-ne$false-or$execution.result.handoff_recorded-ne$false){throw 'Resume unexpectedly crossed handoff.'};Source $false;Shadow
  Save 'resume-verified.json' @{success=$true;expected_target_sha256=$expectedHash;source_disk_attributes=1;shadow_disk_attributes=3;request_sha256=$x.request_sha256;ticket_sha256=$x.ticket_sha256;utc=[DateTime]::UtcNow.ToString('o')}
  $phase='typed-finalize-after-exact-resume';$final=Join-Path $c.stage 'finalize'
  # Already attached: deliberately omit both reattachment flags on finalization.
  Native 'finalize' (@('finalize')+$common+@('--output',$final));Idle;Protected
  $result=Json (Join-Path $final 'result.json');$done=Json (Join-Path $final 'completion.json')
  if($result.success-ne$true-or$result.operation-cne'finalize'-or$result.rollback_closed-ne$true-or$done.success-ne$true-or$null-ne$done.error-or$done.rollback_closed-ne$true-or$done.handoff.handoff_recorded-ne$true-or$done.handoff.target_sha256-cne$expectedHash-or$done.mount_paths_preserved-ne$true-or$done.label_restoration.success-ne$true-or$done.label_restoration.readback_matches-ne$true){throw 'Finalization/HND/native mount/label verification failed; never attempt raw rollback here.'}
  $objects=@($done.native.native.objects);if($objects.Count-ne@($c.expectation_value.objects).Count){throw 'Native object set incomplete.'};$hashes=0
  foreach($object in $c.expectation_value.objects){$match=@($objects|Where-Object {($_.components-join'\')-ceq($object.path-join'\')});if($match.Count-ne1){throw 'Expected native object missing/duplicate.'};if(-not$object.directory){if($match[0].logical_sha256-cne$object.sha256){throw 'Native complete stream hash differs.'};$hashes++}}
  Source $true 'ReFS';Shadow
  Save 'wrapper-result.json' @{success=$true;operation=$c.operation;original_run_id=$c.original_run_id;managed_readonly_reattachment_exercised=$true;resume_native_exit=0;finalize_native_exit=0;rollback_closed=$true;native_objects=$objects.Count;complete_native_hashes=$hashes;original_source_label_mount_verified=$true;source_certificate_recreated=$false;raw_recovery_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')}
 }else{
  $done=Json (Join-Path $first 'completion.json')
  if($result.ntfs_rollback_completed-ne$true-or$done.success-ne$true-or$null-ne$done.error-or$done.replay_closed-ne$true-or$done.mounted_filesystem-cne'NTFS'-or$done.marker.operation-cne'ntfs-rollback-complete'-or$done.marker.target_sha256-cne$expectedHash){throw 'Exact original/ABT/native NTFS rollback completion failed.'};Source $true 'NTFS';Shadow
  Save 'wrapper-result.json' @{success=$true;operation=$c.operation;original_run_id=$c.original_run_id;managed_readonly_reattachment_exercised=$true;rollback_native_exit=0;exact_original_premount_sha256=$expectedHash;ntfs_rollback_completed=$true;replay_closed=$true;original_source_label_mount_verified=$true;source_certificate_recreated=$false;raw_recovery_authorized=$false;postmount_raw_image_equality_claimed=$false;utc=[DateTime]::UtcNow.ToString('o')}
 }
 exit 0
}catch{Save 'wrapper-failed.json' @{success=$false;operation=$c.operation;original_run_id=$c.original_run_id;phase=$phase;native_exit=$lastExit;native_exit_observed=($null-ne$lastExit);error=$_.Exception.ToString();automatic_retry_recover_restore_force_create_format_rebind=$false;worker_termination_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')};exit 1}
'@
 $body=$body.Replace('__CONFIG__',[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes(($c|ConvertTo-Json -Depth 32 -Compress))))
 $wrapper=Join-Path $root 'guest-wrapper.ps1';$bytes=[Text.UTF8Encoding]::new($false).GetBytes($body)
 $f=[IO.File]::Open($wrapper,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()};$wrapperPin=Digest $bytes
 $phase='already-running-partial51-preflight';$session=New-PSSession -VMId $id -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')) -ErrorAction Stop
 $ready=Invoke-Command -Session $session -ArgumentList $stage,$task -ScriptBlock {param($Stage,$Task)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  if((Test-Path -LiteralPath $Stage)-or@(Get-ScheduledTask -ErrorAction Stop|Where-Object {$_.TaskName-ceq$Task-or($_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled'))}).Count-or@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count){throw 'Fresh idle recovery task/stage required.'}
  $disks=@(Get-Disk -ErrorAction Stop);$source=@($disks|Where-Object Number -eq 1)
  if($source.Count-ne1-or[guid]$source[0].Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or-not$source[0].IsOffline-or$source[0].IsReadOnly-or@($disks|Where-Object {$_.Number-eq6-or($_.Guid-and[guid]$_.Guid-eq[guid]'f65b9b29-c38c-49c9-9ef0-ae8869c2df5d')}).Count){throw 'Source1 offline1/reboot-missing managed6 required.'}
  $p=Get-Item -LiteralPath 'C:\ntfs2refs' -Force;while($null-ne$p){if($p.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse stage ancestry.'};$p=$p.Parent};New-Item -ItemType Directory -Path $Stage -ErrorAction Stop|Out-Null
  @{source_disk_attributes=1;managed6_absent=$true;boot_or_restore_performed=$false;utc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'ready.json' $ready
 Copy-Item -LiteralPath $tool.path -ToSession $session -Destination (Join-Path $stage 'ntfs2refs-compact.exe')
 Copy-Item -LiteralPath $wrapper -ToSession $session -Destination (Join-Path $stage 'wrapper.ps1')
 Host-Guard;$phase='persist-and-register-system-wrapper'
 $dispatch=@{run_id=$run;original_run_id=$original;operation=$Operation;vm_id=$id.ToString('D');parent_id=$parent.ToString('D');task_name=$task;guest_stage=$stage;wrapper_sha256=$wrapperPin;binary_sha256=$binaryPin;inputs=$inputs;managed_shadow=$managedPath;managed_shadow_id=$provider;expected_exit=0;expected_native_exit=0;
  resume_output=$(if($Operation-ceq'Resume'){Join-Path $stage 'resume'}else{$null});finalize_output=$(if($Operation-ceq'Resume'){Join-Path $stage 'finalize'}else{$null});rollback_output=$(if($Operation-ceq'Rollback'){Join-Path $stage 'rollback'}else{$null});fresh_apply_authorized=$false;source_certificate_recreated=$false;utc=[DateTime]::UtcNow.ToString('o')}
 Save 'dispatch.json' $dispatch
 Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin,$binaryPin,$binaryBytes -ScriptBlock {param($Stage,$Task,$WrapperPin,$BinaryPin,$Bytes)
  $ErrorActionPreference='Stop';$path=Join-Path $Stage 'wrapper.ps1';$binary=Join-Path $Stage 'ntfs2refs-compact.exe'
  if((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$WrapperPin-or(Get-Item -LiteralPath $binary).Length-ne$Bytes-or(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()-cne$BinaryPin-or@(Get-ScheduledTask -ErrorAction Stop|Where-Object TaskName -CEQ $Task).Count){throw 'Fresh sealed wrapper/tool/task required.'}
  Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -File "'+$path+'"')) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
 }
 Host-Guard;$current=Get-LabCapacity -Configuration $config;Need ($current.MaximumActualBytes-eq329374052988-and$current.MinimumFreeBytes-eq17179869184) 'Capacity epoch changed.';Assert-LabCapacity -Capacity $current -AdditionalBytes 7GB
 $phase='start-recorded-wrapper-once'
 Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin -ScriptBlock {param($Stage,$Task,$Pin)
  $ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskName $Task -ErrorAction Stop;$i=Get-ScheduledTaskInfo -TaskName $Task -ErrorAction Stop;$path=Join-Path $Stage 'wrapper.ps1'
  if($t.State.ToString()-cne'Ready'-or$i.LastRunTime.Year-ge2000-or@($t.Actions).Count-ne1-or$t.Actions[0].Execute-cne"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"-or$t.Actions[0].Arguments-cne('-NoProfile -NonInteractive -File "'+$path+'"')-or$t.Principal.UserId-notin@('SYSTEM','S-1-5-18')-or$t.Principal.RunLevel.ToString()-cne'Highest'-or(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$Pin-or@(Get-ScheduledTask -ErrorAction Stop|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count){throw 'Only the untouched pinned SYSTEM task may start once.'}
  Start-ScheduledTask -TaskName $Task -ErrorAction Stop
 }
 Save 'start.json' @{start_issued_once=$true;expected_exit=0;completion_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')};$dispatch|ConvertTo-Json -Depth 10
}catch{if($created-and-not(Test-Path -LiteralPath (Join-Path $root 'dispatch-failed.json'))){Save 'dispatch-failed.json' @{success=$false;phase=$phase;run_id=$run;operation=$Operation;error=$_.Exception.ToString();automatic_retry=$false;worker_termination_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')}};throw}
finally{if($null-ne$session){Remove-PSSession $session -ErrorAction SilentlyContinue};for($i=$held.Count-1;$i-ge0;$i--){$held[$i].Dispose()}}
