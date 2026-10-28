# Single typed recovery dispatch; no restore, source activation, Apply or marker repair.
[CmdletBinding()]param(
    [Parameter(Mandatory)][ValidateSet('Resume','Rollback','Finalize','FinalizeAfterMarker','FinalizeRollback')][string]$Operation,
    [Parameter(Mandatory)][guid]$ExpectedParent,
    [Parameter(Mandatory)][ValidateRange(45,200)][int]$ExpectedCheckpointCount,
    [Parameter(Mandatory)][string]$ToolsetManifest,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ToolsetManifestSha256,
    [string]$PriorRecoveryRoot
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$originalRun='949dbc98138e4514a1098081eb0226ef';$originalTask='N2R-AdmittedCompact-Interrupt-'+$originalRun
$originalStage='C:\ntfs2refs\compact-admitted-interrupt-'+$originalRun;$interrupted=Join-Path $originalStage 'result'
$caseRoot=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\compact-admitted-interrupt-20261028'
$root=Join-Path $workspace ('.lab\hyperv\streaming-v2-20261027\compact-admitted-recovery-20261028\'+$Operation.ToLowerInvariant())
if(Test-Path -LiteralPath $root){throw 'Recovery role has state; inspect without redispatch.'}
$original=Get-Content -LiteralPath (Join-Path $caseRoot 'intent.json') -Raw -Encoding UTF8|ConvertFrom-Json
$originalDispatch=Get-Content -LiteralPath (Join-Path $caseRoot 'dispatch.json') -Raw -Encoding UTF8|ConvertFrom-Json
if($original.run_id -cne $originalRun -or $originalDispatch.task_name -cne $originalTask -or $originalDispatch.expected_native_exit -ne 86 -or $originalDispatch.expected_wrapper_exit -ne 86){throw 'Exact controlled-interrupt enrollment required.'}
$vm=Get-VM -Id $id;$old=@(Get-VMSnapshot -VM $vm|ForEach-Object {$_.Id.ToString()})
if($vm.ParentSnapshotId -ne $ExpectedParent -or $old.Count -ne $ExpectedCheckpointCount -or @($old|Sort-Object -Unique).Count -ne $ExpectedCheckpointCount -or $ExpectedParent.ToString('D') -notin $old -or @($original.old_checkpoint_ids|Where-Object {$_ -notin $old}).Count -or $vm.MemoryStartup -ne 4GB -or $vm.DynamicMemoryEnabled -or @(Get-VMNetworkAdapter -VM $vm).Count){throw 'Supplied saved parent/count, all prior checkpoints and isolated fixed4GiB VM required.'}
$finalize=$Operation -in @('Finalize','FinalizeAfterMarker','FinalizeRollback')
if(-not $finalize -and $vm.State.ToString() -cne 'Off'){throw 'Resume/Rollback require OFF preserved partial branch.'}
if($finalize -and ($vm.State.ToString() -cne 'Running' -or [string]::IsNullOrWhiteSpace($PriorRecoveryRoot))){throw 'Finalize requires existing running branch and prior recovery evidence.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1')
$capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
if($capacity.MaximumActualBytes -ne 329374052988 -or $capacity.MinimumFreeBytes -ne 17179869184){throw 'Approved storage epoch changed; never reset its baseline.'}
Assert-LabCapacity -Capacity $capacity -AdditionalBytes 7GB
if((Get-FileHash -LiteralPath $ToolsetManifest).Hash.ToLowerInvariant() -cne $ToolsetManifestSha256){throw 'Recovery manifest pin differs.'}
$manifest=Get-Content -LiteralPath $ToolsetManifest -Raw -Encoding UTF8|ConvertFrom-Json
if($manifest.schema_version -ne 1 -or $manifest.kind -cne 'admitted-compact-recovery-toolset' -or @($manifest.tools).Count -ne 1){throw 'Sealed recovery toolset required.'}
$tool=$manifest.tools[0];$binary=[IO.Path]::GetFullPath([string]$tool.path);$item=Get-Item -LiteralPath $binary
if($tool.name -cne 'lab-recover-native-composite.exe' -or $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -ne $tool.bytes -or $item.Length -gt 8MB -or $tool.sha256 -cnotmatch '^[a-f0-9]{64}$' -or (Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant() -cne $tool.sha256){throw 'Ordinary pinned native recovery binary differs.'}
$prior=$null
if($finalize){$prior=Get-Content -LiteralPath (Join-Path $PriorRecoveryRoot 'dispatch.json') -Raw -Encoding UTF8|ConvertFrom-Json;$want=if($Operation -ceq 'FinalizeRollback'){'Rollback'}else{'Resume'};if($prior.operation -cne $want -or $prior.original_run_id -cne $originalRun -or [guid]$prior.vm_id -ne $id -or $prior.expected_exit -ne 0){throw 'Matching prior recovery role required.'}}
$run=[guid]::NewGuid().ToString('N');$stage='C:\ntfs2refs\admitted-compact-recovery-'+$Operation.ToLowerInvariant()+'-'+$run
New-Item -ItemType Directory -Path $root|Out-Null
function Save-New([string]$Name,$Value){$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 28));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
Save-New 'intent.json' @{run_id=$run;original_run_id=$originalRun;operation=$Operation;vm_id=$id.ToString();parent_id=$ExpectedParent.ToString();old_checkpoint_ids=$old;capacity=$capacity;additional_forecast_bytes=[long]7GB;forecast_is_not_reservation=$true;toolset_manifest_sha256=$ToolsetManifestSha256;tool=$tool;prior_recovery_root=$PriorRecoveryRoot;expected_exit=0;fresh_apply_authorized=$false;source_activation_authorized=$false;source_certificate_recreated=$false;utc=[DateTime]::UtcNow.ToString('o')}
Copy-Item -LiteralPath $binary -Destination (Join-Path $root $tool.name)
if((Get-FileHash -LiteralPath (Join-Path $root $tool.name)).Hash.ToLowerInvariant() -cne $tool.sha256){throw 'Archived native recovery binary differs.'}
if(-not $finalize){Start-VM -VM $vm|Out-Null}
$credential=Import-Clixml -LiteralPath (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$s=$null;$deadline=[DateTime]::UtcNow.AddMinutes(5)
while($null -eq $s){try{$s=New-PSSession -VMId $id -Credential $credential -ErrorAction Stop}catch{if([DateTime]::UtcNow -ge $deadline){throw 'Single boot/session unavailable; never reboot or retry.'};Start-Sleep -Seconds 3}}
try{
    $ready=Invoke-Command -Session $s -ArgumentList $stage,$Operation,$originalRun,$originalTask,$originalStage,$interrupted,($prior|ConvertTo-Json -Depth 10 -Compress) -ScriptBlock {
        param($Stage,$Operation,$OriginalRun,$OriginalTask,$OriginalStage,$Interrupted,$PriorJson)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        function Hash([string]$Path,[long]$Limit){$m=Get-Item -LiteralPath $Path;if($m.PSIsContainer -or ($m.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $m.Length -gt $Limit){throw 'Recovery input is not bounded and ordinary.'};return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
        function Json([string]$Path){$null=Hash $Path 16777216;return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8|ConvertFrom-Json)}
        # Original native/wrapper terminal86 precedes ALL journal/backing reads.
        $task=Get-ScheduledTask -TaskName $OriginalTask;$info=Get-ScheduledTaskInfo -TaskName $OriginalTask
        if($task.State.ToString() -ceq 'Running' -or $info.LastTaskResult -ne 86 -or $info.LastRunTime.Year -lt 2000 -or @(Get-CimInstance Win32_Process|Where-Object {$_.Name -in @('lab-convert-native-composite.exe','lab-abort-general-source.exe','ntfs2refs-bind.exe','lab-recover-native-composite.exe','lab-apply-compact-fixture.exe','lab-verify-general-converted.exe','lab-general-refs-mutation.exe')}).Count){throw 'Interruption is not terminal86 or another worker remains; do not read recovery storage.'}
        $closed=Json (Join-Path $OriginalStage 'wrapper-controlled-interruption.json')
        if(-not $closed.controlled_interruption_observed -or $closed.conversion_success -or $closed.native_exit -ne 86 -or $closed.expected_native_exit -ne 86 -or $closed.interrupt_after_writes -ne 1 -or $closed.mode -cne 'Interrupt' -or (Test-Path -LiteralPath (Join-Path $OriginalStage 'wrapper-failed.json'))){throw 'Real controlled native/wrapper interruption required.'}
        $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3;$journalDisk=Get-Disk -Number 2
        if([guid]$source.Guid -ne [guid]'1b191872-c372-41ee-a416-e18863996f54' -or -not $source.IsOffline -or $source.IsReadOnly -or [guid]$shadow.Guid -ne [guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f' -or -not $shadow.IsOffline -or -not $shadow.IsReadOnly -or [guid]$journalDisk.Guid -ne [guid]'09fcc613-b8c2-4a1a-8833-226f9399be7f' -or $journalDisk.IsOffline -or $journalDisk.IsReadOnly){throw 'Exact source1/shadow3/independent journal0 state required.'}
        if((Test-Path -LiteralPath (Join-Path $Interrupted 'result.json')) -or (Test-Path -LiteralPath (Join-Path $Interrupted 'finalization.json'))){throw 'Interrupted process unexpectedly completed; inspect without replay.'}
        $requestPath=Join-Path $Interrupted 'request.json';$ticketPath=Join-Path $Interrupted 'ticket.json';$expectedPath=Join-Path $Interrupted 'expectation.json'
        $request=Json $requestPath;$backing=Json (Join-Path $Interrupted 'compact-backing.json');$location=Json (Join-Path $Interrupted 'journal-location.json');$prepared=Json (Join-Path $Interrupted 'prepare.json');$stop=Json (Join-Path $Interrupted 'interruption-intent.json')
        $requestPin=Hash $requestPath 131072;$ticketPin=Hash $ticketPath 65536;$treePin=Hash $expectedPath 16777216
        $capture=[string]$backing.report_path;$packed=[string]$backing.packed_path;$journal=[string]$location.path
        $capturePin=Hash $capture 16777216;$packedPin=Hash $packed 268435456;$captureValue=Json $capture;$ticket=Json $ticketPath
        if($request.experiment_id -cne $OriginalRun -or $request.pair.source.disk_number -ne 1 -or $request.pair.shadow.disk_number -ne 3 -or $request.journal.disk.disk_number -ne 2 -or [guid]$request.pair.source.identity.disk_guid -ne [guid]$source.Guid -or [guid]$request.pair.shadow.identity.disk_guid -ne [guid]$shadow.Guid -or [guid]$request.journal.disk.identity.disk_guid -ne [guid]$journalDisk.Guid -or $request.source_resource_profile -cne 'experimental_streaming_tree_v2' -or $backing.kind -cne 'experimental-live-composite-recovery-backing' -or $backing.request_sha256 -cne $requestPin -or $request.expected_tree_sha256 -cne $treePin -or $backing.expected_tree_sha256 -cne $treePin -or $backing.artifact.report_sha256 -cne $capturePin -or $backing.artifact.packed_sha256 -cne $packedPin -or $captureValue.kind -cne 'frozen-composite-target-capture' -or $captureValue.composite_target_sha256 -cne $request.comparison.shadow_sha256 -or $captureValue.source_sha256 -cne $request.comparison.source_sha256 -or $captureValue.expected_tree_sha256 -cne $treePin -or $stop.expected_process_exit_code -ne 86 -or $stop.interrupt_after_writes -ne 1 -or $stop.ticket_sha256 -cne $ticketPin -or $stop.journal_path -cne $journal -or $stop.artifact_identity_sha256 -cne $backing.artifact_identity_sha256 -or -not $prepared.journal.preparation_durable -or $prepared.journal.expected_postimage_sha256 -cne $request.comparison.shadow_sha256 -or $ticket.journal_length -ne (Get-Item -LiteralPath $journal).Length){throw 'Actual completed preparation and recovery bindings differ.'}
        $prior=$PriorJson|ConvertFrom-Json
        if($Operation -in @('Finalize','FinalizeAfterMarker','FinalizeRollback')){
            $pt=Get-ScheduledTask -TaskName $prior.task_name;$pi=Get-ScheduledTaskInfo -TaskName $prior.task_name
            if($pt.State.ToString() -ceq 'Running' -or $prior.original_run_id -cne $OriginalRun){throw 'Prior recovery is not terminal.'}
            $execution=Json (Join-Path ([string]$prior.output_dir) 'execution.json')
            if($Operation -ceq 'FinalizeRollback'){$completion=Json (Join-Path ([string]$prior.output_dir) 'completion.json');if($pi.LastTaskResult -notin @(0,1) -or $execution.expected_target_sha256 -cne $request.comparison.source_sha256 -or $execution.result.target_sha256 -cne $request.comparison.source_sha256 -or -not $completion.replay_closed){throw 'Prior exact restored image and closed ABT evidence required.'}}
            else{$result=Json (Join-Path ([string]$prior.output_dir) 'result.json');if($pi.LastTaskResult -ne 0 -or -not $result.success -or $result.operation -cne 'resume' -or -not $result.target_remains_offline -or $execution.expected_target_sha256 -cne $request.comparison.shadow_sha256 -or $execution.result.target_sha256 -cne $request.comparison.shadow_sha256){throw 'Prior successful native Resume required.'}}
            if($prior.request_sha256 -cne $requestPin -or $prior.ticket_sha256 -cne $ticketPin -or $prior.capture_sha256 -cne $capturePin -or $prior.packed_sha256 -cne $packedPin){throw 'Prior recovery pins differ.'}
        }
        # Read actual marker bytes read-only, only after every worker is terminal.
        $marker=[byte[]]::new(4096);$f=[IO.File]::Open($journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try{$at=0;while($at -lt 4096){$n=$f.Read($marker,$at,4096-$at);if($n -eq 0){throw 'Actual marker ended early.'};$at+=$n}}finally{$f.Dispose()}
        $zero=@($marker|Where-Object {$_ -ne 0}).Count -eq 0;$magic=[Text.Encoding]::ASCII.GetString($marker,0,8)
        if(($Operation -in @('Resume','Rollback','Finalize') -and -not $zero) -or ($Operation -ceq 'FinalizeAfterMarker' -and $magic -cne 'N2RHND01') -or ($Operation -ceq 'FinalizeRollback' -and $magic -cne 'N2RABT01')){throw 'Lifecycle marker differs; never repair or force replay.'}
        if(Test-Path -LiteralPath $Stage){throw 'Fresh guest recovery stage required.'};New-Item -ItemType Directory -Path $Stage|Out-Null
        $sha=[Security.Cryptography.SHA256]::Create();try{$markerPin=[BitConverter]::ToString($sha.ComputeHash($marker)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
        @{request=$requestPath;request_sha256=$requestPin;ticket=$ticketPath;ticket_sha256=$ticketPin;capture=$capture;capture_sha256=$capturePin;packed=$packed;packed_sha256=$packedPin;expectation=$expectedPath;expectation_sha256=$treePin;journal=$journal;artifact_identity_sha256=$backing.artifact_identity_sha256;journal_marker_zero=$zero;journal_marker_magic=$magic;journal_marker_sha256=$markerPin;source_disk_attributes=1;shadow_disk_attributes=3;original_task_result=86;source_certificate_recreated=$false;utc=[DateTime]::UtcNow.ToString('o')}
    }
    Save-New 'recovery-inputs.json' $ready
    Copy-Item -LiteralPath (Join-Path $root $tool.name) -ToSession $s -Destination (Join-Path $stage $tool.name)
    $dispatch=Invoke-Command -Session $s -ArgumentList $stage,$run,$Operation,$originalRun,$id.ToString(),$tool.sha256,$tool.bytes,($ready|ConvertTo-Json -Depth 10 -Compress) -ScriptBlock {
        param($Stage,$Run,$Operation,$OriginalRun,$VmId,$Pin,$Bytes,$InputsJson);$ErrorActionPreference='Stop';$c=$InputsJson|ConvertFrom-Json;$binary=Join-Path $Stage 'lab-recover-native-composite.exe';$task='N2R-AdmittedCompactRecovery-'+$Operation+'-'+$Run
        if((Get-Item -LiteralPath $binary).Length -ne $Bytes -or (Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant() -cne $Pin -or (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)){throw 'Fresh pinned recovery task required.'}
        $mode=switch($Operation){'FinalizeAfterMarker'{'finalize-after-marker'}'FinalizeRollback'{'finalize-rollback'}default{$Operation.ToLowerInvariant()}}
        $out=Join-Path $Stage 'result';$cli=@($mode,'--acknowledge-experimental-compact-recovery','--request',$c.request,'--request-sha256',$c.request_sha256,'--ticket',$c.ticket,'--ticket-sha256',$c.ticket_sha256,'--capture',$c.capture,'--capture-sha256',$c.capture_sha256,'--packed',$c.packed,'--packed-sha256',$c.packed_sha256,'--expectation',$c.expectation,'--expectation-sha256',$c.expectation_sha256,'--journal',$c.journal,'--output',$out)
        $arguments=($cli|ForEach-Object {if($_.Contains('"')){throw 'Quoted recovery input refused.'};'"'+$_+'"'}) -join ' '
        Register-ScheduledTask -TaskName $task -Action (New-ScheduledTaskAction -Execute $binary -Argument $arguments) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
        @{task_name=$task;operation=$Operation;run_id=$Run;original_run_id=$OriginalRun;vm_id=$VmId;guest_stage=$Stage;output_dir=$out;binary=$binary;binary_sha256=$Pin;arguments=$cli;expected_exit=0;request_sha256=$c.request_sha256;ticket_sha256=$c.ticket_sha256;capture_sha256=$c.capture_sha256;packed_sha256=$c.packed_sha256;expectation_sha256=$c.expectation_sha256;fresh_apply_authorized=$false;source_activation_authorized=$false}
    }
    Save-New 'dispatch.json' $dispatch
    $now=Get-VM -Id $id;$current=@(Get-VMSnapshot -VM $now|ForEach-Object {$_.Id.ToString()});if($now.ParentSnapshotId -ne $ExpectedParent -or $current.Count -ne $ExpectedCheckpointCount -or @($old|Where-Object {$_ -notin $current}).Count){throw 'Branch/checkpoint set changed before dispatch.'}
    Invoke-Command -Session $s -ArgumentList $dispatch.task_name -ScriptBlock {param($Task);if((Get-ScheduledTaskInfo -TaskName $Task).LastRunTime.Year -ge 2000){throw 'Recovery task already ran; do not repeat.'};Start-ScheduledTask -TaskName $Task}
    Save-New 'start.json' @{start_issued_once=$true;expected_exit=0;utc=[DateTime]::UtcNow.ToString('o')}
    $dispatch|ConvertTo-Json -Compress
}finally{Remove-PSSession $s}
