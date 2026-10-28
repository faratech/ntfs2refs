# Case-specific terminal preservation ONLY. Never boots/restores a VM, replays
# recovery, changes source availability, repairs markers or duplicates payloads.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs'
$root=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\compact-admitted-interrupt-20261028'
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$run='949dbc98138e4514a1098081eb0226ef'
$parent=[guid]'cfe0b326-7308-4a58-810d-9730ff8152b4'
$stage='C:\ntfs2refs\compact-admitted-interrupt-'+$run
$task='N2R-AdmittedCompact-Interrupt-'+$run
$snapshotName='streaming-v2-admitted-compact-interrupted-'+$run
$wrapperPin='eeded76ca38eed02870fbb942cc1b375f0bb01a9ef7313d4767add3109aefc39'
function Need([bool]$Condition,[string]$Message){if(-not$Condition){throw $Message}}
function Save-New([string]$Name,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 24));Need ($bytes.Length -le 4MB) 'Host record exceeded four MiB.';$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Save-Bytes([string]$Path,[byte[]]$Bytes){$f=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($Bytes,0,$Bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Hash([byte[]]$Bytes){$s=[Security.Cryptography.SHA256]::Create();try{[BitConverter]::ToString($s.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}finally{$s.Dispose()}}
function Host-Json([string]$Name){$p=Join-Path $root $Name;$item=Get-Item -LiteralPath $p -Force;Need (-not$item.PSIsContainer -and -not($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $item.Length -le 1MB) 'Bounded ordinary host enrollment JSON required.';Get-Content -LiteralPath $p -Raw -Encoding UTF8|ConvertFrom-Json}
foreach($name in @('preservation-intent.json','partial-checkpoint-create-intent.json','partial-checkpoint.json','preservation-failed.json')){Need (-not(Test-Path -LiteralPath (Join-Path $root $name))) 'Preservation already has state; inspect it instead of repeating actions.'}
$dispatch=Host-Json 'dispatch.json';$enrollment=Host-Json 'intent.json'
Need ($dispatch.run_id -ceq $run -and $dispatch.task_name -ceq $task -and $dispatch.mode -ceq 'Interrupt' -and $dispatch.expected_native_exit -eq 86 -and $dispatch.expected_wrapper_exit -eq 86 -and $dispatch.wrapper_sha256 -ceq $wrapperPin -and $dispatch.guest_stage -ceq $stage -and $dispatch.output_dir -ceq (Join-Path $stage 'result')) 'Exact enrolled interrupt dispatcher differs.'
Need ([guid]$enrollment.vm_id -eq $id -and [guid]$enrollment.parent_id -eq $parent -and $enrollment.run_id -ceq $run -and $enrollment.mode -ceq 'Interrupt' -and $enrollment.expected_checkpoint_count -eq 44) 'Interrupt enrollment differs.'
$old=@($enrollment.old_checkpoint_ids|ForEach-Object {([guid]$_).ToString('D')})
Need ($old.Count -eq 44 -and @($old|Sort-Object -Unique).Count -eq 44 -and $old -contains $parent.ToString('D') -and $old -contains '66a34221-06d3-4042-8739-8e48a9977171' -and $old -contains '2720f72d-5565-4b7a-aff8-378d24b65a4d') 'All44 preserved branches, including normal conversion and mutation, are required.'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$configuration=Get-LabConfiguration -WorkspaceRoot $workspace
Need ($configuration.Settings.maximumActualBytes -eq 329374052988 -and $configuration.Settings.minimumHostFreeBytes -eq 16GB) 'Approved cumulative50-GB budget/reserve changed; this helper never resets it.'
$capacity=Get-LabCapacity -Configuration $configuration
Assert-LabCapacity -Capacity $capacity -AdditionalBytes 512MB
$vm=Get-VM -Id $id;$snapshots=@(Get-VMSnapshot -VM $vm)
Need ($vm.Name -ceq 'ntfs2refs-streaming-v2-20261027' -and $vm.State.ToString() -ceq 'Running' -and $vm.ParentSnapshotId -eq $parent -and $vm.MemoryStartup -eq 4GB -and -not$vm.DynamicMemoryEnabled -and @(Get-VMNetworkAdapter -VM $vm).Count -eq 0 -and $snapshots.Count -eq 44 -and @($old|Where-Object {$_ -notin @($snapshots.Id|ForEach-Object {$_.ToString('D')})}).Count -eq 0) 'Exact running interrupted branch/all44 required; no startup or restore is available.'
$credential=Import-Clixml -LiteralPath (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$session=$null;$intentSaved=$false
try{
    $session=New-PSSession -VMId $id -Credential $credential -ErrorAction Stop
    $guard={
        param($Stage,$Task,$Run,$WrapperPin)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        function Require([bool]$Condition,[string]$Message){if(-not$Condition){throw $Message}}
        $t=Get-ScheduledTask -TaskName $Task -ErrorAction Stop;$ti=Get-ScheduledTaskInfo -TaskName $Task -ErrorAction Stop
        Require ($t.State.ToString() -ceq 'Ready' -and $ti.LastTaskResult -eq 86 -and $ti.LastRunTime.Year -ge 2026) 'Interrupted task has not reached terminal86; no journal read is allowed.'
        Require (@($t.Actions).Count -eq 1 -and $t.Actions[0].Execute -ceq "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -and $t.Actions[0].Arguments -cmatch '\A-NoProfile -NonInteractive -EncodedCommand ([A-Za-z0-9+/=]+)\z') 'Task action differs from the enrolled wrapper.'
        $body=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Matches[1]));$sha=[Security.Cryptography.SHA256]::Create();try{$actual=[BitConverter]::ToString($sha.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes($body))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
        Require ($actual -ceq $WrapperPin) 'Actual scheduled wrapper pin differs.'
        $processes=@(Get-CimInstance Win32_Process -ErrorAction Stop)
        foreach($identity in @(@{pid=700;creation_ms=[long]1793216860509;name='powershell.exe'},@{pid=5364;creation_ms=[long]1793217057038;name='lab-convert-native-composite.exe'})){
            foreach($p in @($processes|Where-Object ProcessId -eq $identity.pid)){$created=([DateTimeOffset]$p.CreationDate).ToUnixTimeMilliseconds();Require (-not($created -eq $identity.creation_ms -and $p.Name -ceq $identity.name)) 'The enrolled worker creation is still present.'}
        }
        $known=@('lab-convert-native-composite.exe','lab-recover-native-composite.exe','lab-abort-general-source.exe','ntfs2refs.exe','ntfs2refs-recover.exe','ntfs2refs-bind.exe','lab-apply-compact-fixture.exe','lab-prepare-compact-journal.exe','lab-allocate-private-tree.exe')
        Require (@($processes|Where-Object {$_.Name -in $known}).Count -eq 0) 'Another project native worker is active.'
        Require (@(Get-ScheduledTask -ErrorAction Stop|Where-Object {$_.TaskName -like 'N2R-*' -and $_.State.ToString() -in @('Running','Queued')}).Count -eq 0) 'Another N2R task is running/queued.'
        $path=Join-Path $Stage 'wrapper-controlled-interruption.json';$m=Get-Item -LiteralPath $path -Force
        Require (-not$m.PSIsContainer -and -not($m.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $m.Length -gt 0 -and $m.Length -le 64KB) 'Closed bounded interruption receipt required.'
        $f=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try{$r=[IO.StreamReader]::new($f,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true);try{$text=$r.ReadToEnd()}finally{$r.Dispose()};$receipt=$text|ConvertFrom-Json;$f.Position=0;$s=[Security.Cryptography.SHA256]::Create();try{$receiptPin=[BitConverter]::ToString($s.ComputeHash($f)).Replace('-','').ToLowerInvariant()}finally{$s.Dispose()}}finally{$f.Dispose()}
        Require ($receipt.mode -ceq 'Interrupt' -and $receipt.controlled_interruption_observed -is [bool] -and $receipt.controlled_interruption_observed -and $receipt.conversion_success -is [bool] -and -not$receipt.conversion_success -and $receipt.phase -ceq 'controlled-interruption-state' -and $receipt.native_exit -eq 86 -and $receipt.expected_native_exit -eq 86 -and $receipt.interrupt_after_writes -eq 1 -and $receipt.source_offline -eq $true -and $receipt.source_readonly -eq $false -and $receipt.shadow_offline -eq $true -and $receipt.shadow_readonly -eq $true) 'Wrapper did not record the exact controlled interruption.'
        $source=Get-Disk -Number 1 -ErrorAction Stop;$shadow=Get-Disk -Number 3 -ErrorAction Stop;$journal=Get-Disk -Number 2 -ErrorAction Stop
        Require ([guid]$source.Guid -eq [guid]'1b191872-c372-41ee-a416-e18863996f54' -and $source.IsOffline -and -not$source.IsReadOnly -and [guid]$shadow.Guid -eq [guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f' -and $shadow.IsOffline -and $shadow.IsReadOnly -and [guid]$journal.Guid -eq [guid]'09fcc613-b8c2-4a1a-8833-226f9399be7f' -and -not$journal.IsOffline -and -not$journal.IsReadOnly) 'Persistent source1/shadow3/journal0 route differs.'
        @{terminal=$true;run_id=$Run;task=$Task;last_task_result=$ti.LastTaskResult;wrapper_sha256=$actual;wrapper_receipt_sha256=$receiptPin;source_offline=$true;source_readonly=$false;shadow_offline=$true;shadow_readonly=$true;worker_creation_checks=@(@{pid=700;creation_ms=[long]1793216860509;absent=$true},@{pid=5364;creation_ms=[long]1793217057038;absent=$true});utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 5 -Compress
    }
    # This first check never opens J:. Busy/refused attempts leave no intent,
    # so the owner may wait for the existing task rather than restarting it.
    $terminalText=Invoke-Command -Session $session -ScriptBlock $guard -ArgumentList $stage,$task,$run,$wrapperPin
    $terminal=$terminalText|ConvertFrom-Json
    Save-New 'preservation-intent.json' @{run_id=$run;vm_id=$id.ToString();parent_id_before_any_checkpoint=$parent.ToString('D');old_checkpoint_ids=$old;terminal=$terminal;capacity=$capacity;additional_bytes=512MB;script_sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLowerInvariant();restore_authorized=$false;source_state_changes_authorized=$false;raw_recovery_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')};$intentSaved=$true
    $collectionText=Invoke-Command -Session $session -ArgumentList $stage,$run,$terminal.wrapper_receipt_sha256 -ScriptBlock {
        param($Stage,$Run,$WrapperReceiptPin)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        function Require([bool]$Condition,[string]$Message){if(-not$Condition){throw $Message}}
        function Digest([byte[]]$Bytes){$s=[Security.Cryptography.SHA256]::Create();try{[BitConverter]::ToString($s.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}finally{$s.Dispose()}}
        function Hex([string]$Text){Require ($Text -cmatch '\A[0-9a-f]{64}\z') 'Canonical digest required.';$b=[byte[]]::new(32);for($i=0;$i -lt 32;$i++){$b[$i]=[Convert]::ToByte($Text.Substring(2*$i,2),16)};,$b}
        function ReadAt([IO.FileStream]$File,[long]$Offset,[int]$Length){Require ($Offset -ge 0 -and $Length -ge 0 -and $Offset -le $File.Length-$Length) 'Bounded read escapes file.';$File.Position=$Offset;$b=[byte[]]::new($Length);$done=0;while($done -lt $Length){$n=$File.Read($b,$done,$Length-$done);Require ($n -gt 0) 'Short journal read.';$done+=$n};,$b}
        function Ordinary([string]$Path){$item=Get-Item -LiteralPath $Path -Force;Require (-not$item.PSIsContainer -and -not($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Ordinary evidence file required.';$cursor=$item.Directory;while($null -ne $cursor){Require (-not($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Reparse evidence ancestry refused.';$cursor=$cursor.Parent};$item}
        function SameBinding($A,$B){foreach($n in @('experiment_id','target_identity_sha256','shadow_identity_sha256','journal_identity_sha256','source_resource_profile')){Require ($A.$n -ceq $B.$n) ('Prepared ticket binding differs: '+$n)}}
        $specs=@(
            @{name='wrapper-controlled-interruption.json';relative='wrapper-controlled-interruption.json';max=64KB},
            @{name='initial-conversion.json';relative='conversion.json';max=128KB},
            @{name='conversion-start.json';relative='conversion-start.json';max=64KB},
            @{name='request.json';relative='result\request.json';max=128KB},
            @{name='ticket.json';relative='result\ticket.json';max=64KB},
            @{name='expectation.json';relative='result\expectation.json';max=4MB},
            @{name='compact-backing.json';relative='result\compact-backing.json';max=1MB},
            @{name='journal-location.json';relative='result\journal-location.json';max=64KB},
            @{name='prepare.json';relative='result\prepare.json';max=4MB},
            @{name='interruption-intent.json';relative='result\interruption-intent.json';max=64KB},
            @{name='composite-capture.json';relative='result\qualification\composite-capture.json';max=4MB},
            @{name='composite-artifact-pins.json';relative='result\qualification\composite-artifact-pins.json';max=1MB},
            @{name='source-frozen.json';relative='result\qualification\source-frozen.json';max=1MB},
            @{name='qualification-result.json';relative='result\qualification\result.json';max=4MB},
            @{name='certificate.json';relative='result\qualification\certificate.json';max=4MB},
            @{name='admitted-assessment.json';relative='result\qualification\admitted-assessment.json';max=4MB}
        )
        $held=[Collections.Generic.List[IO.FileStream]]::new();$documents=[Collections.Generic.List[object]]::new();$values=@{};$pins=@{};$total=[long]0;$j=$null
        try{
            foreach($spec in $specs){$path=Join-Path $Stage $spec.relative;$item=Ordinary $path;Require ($item.Length -gt 0 -and $item.Length -le $spec.max) 'Metadata artifact exceeds its bound.';$total+=$item.Length;Require ($total -le 16MB) 'Metadata aggregate exceeds16MiB.';$f=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$held.Add($f);$b=ReadAt $f 0 ([int]$item.Length);Require ($f.Length -eq $b.Length) 'Closed metadata changed.';$pin=Digest $b;$pins[$spec.name]=$pin;$values[$spec.name]=[Text.UTF8Encoding]::new($false,$true).GetString($b)|ConvertFrom-Json;$documents.Add(@{name=$spec.name;source=$path;bytes=$b.Length;sha256=$pin;bytes_base64=[Convert]::ToBase64String($b)})}
            $request=$values['request.json'];$ticket=$values['ticket.json'];$backing=$values['compact-backing.json'];$prepared=$values['prepare.json'];$fault=$values['interruption-intent.json'];$capture=$values['composite-capture.json'];$artifact=$values['composite-artifact-pins.json'];$wrapper=$values['wrapper-controlled-interruption.json'];$qualification=$values['qualification-result.json']
            Require ($pins['wrapper-controlled-interruption.json'] -ceq $WrapperReceiptPin -and $wrapper.request_sha256 -ceq $pins['initial-conversion.json'] -and $values['conversion-start.json'].request_sha256 -ceq $pins['initial-conversion.json'] -and $values['initial-conversion.json'].experiment_id -ceq $Run) 'Terminal wrapper/initial input pins differ.'
            Require ($request.schema_version -eq 2 -and $request.source_resource_profile -ceq 'experimental_streaming_tree_v2' -and $request.experiment_id -ceq $Run -and $request.max_journal_bytes -eq 256MB -and $ticket.schema_version -eq 2 -and $ticket.binding.experiment_id -ceq $Run) 'Prepared version/run/budget differs.'
            foreach($spec in @(@{value=$request.pair.source;number=1;guid='1b191872-c372-41ee-a416-e18863996f54';partition='f06075a8-67a2-46b9-8fac-4af4da809617'},@{value=$request.pair.shadow;number=3;guid='c0f2cd39-ad3d-484e-9990-0e6eba74485f';partition='cbfd3e55-e35c-4f6e-aaac-dca706c3ec17'})){Require ($spec.value.disk_number -eq $spec.number -and [guid]$spec.value.identity.disk_guid -eq [guid]$spec.guid -and [guid]$spec.value.identity.partition_guid -eq [guid]$spec.partition -and $spec.value.identity.partition_offset -eq 16MB -and $spec.value.identity.partition_bytes -eq 52GB -and $spec.value.identity.logical_sector_bytes -eq 512 -and $spec.value.identity.physical_sector_bytes -eq 4096) 'Prepared data device binding differs.'}
            Require ($backing.kind -ceq 'experimental-live-composite-recovery-backing' -and $backing.request_sha256 -ceq $pins['request.json'] -and $backing.expected_tree_sha256 -ceq $pins['expectation.json'] -and $request.expected_tree_sha256 -ceq $pins['expectation.json'] -and $backing.report_path -ceq (Join-Path $Stage 'result\qualification\composite-capture.json') -and $backing.packed_path -ceq (Join-Path $Stage 'result\qualification\changed-clusters.bin')) 'Pinned recovery metadata routes differ.'
            Require ($backing.artifact.report_sha256 -ceq $pins['composite-capture.json'] -and $artifact.report_sha256 -ceq $pins['composite-capture.json'] -and $artifact.packed_sha256 -ceq $backing.artifact.packed_sha256 -and $capture.kind -ceq 'frozen-composite-target-capture' -and $capture.success -eq $true -and $capture.source_backed_payloads -eq $true -and $capture.native.compact_difference_capture.packed_sha256 -ceq $backing.artifact.packed_sha256 -and $capture.native.compact_difference_capture.layout.changed_bytes -eq $backing.artifact.packed_bytes) 'Capture/backing declared hash/layout pins differ.'
            Require ($capture.source_sha256 -ceq $request.comparison.source_sha256 -and $capture.composite_target_sha256 -ceq $request.comparison.shadow_sha256 -and $capture.expected_tree_sha256 -ceq $pins['expectation.json'] -and $capture.native.compact_difference_capture.selected_bytes_compared -eq 52GB -and $capture.native.compact_difference_capture.layout.partition_bytes -eq 52GB) 'Capture is not the complete admitted source/target address space.'
            Require ($qualification.kind -ceq 'live-composite-tree-qualification' -and $qualification.success -eq $true -and $qualification.source_admitted -eq $true -and $qualification.source_sha256 -ceq $request.comparison.source_sha256 -and $qualification.expected_tree_sha256 -ceq $pins['expectation.json'] -and $qualification.certificate_sha256 -ceq $pins['certificate.json'] -and $values['source-frozen.json'].source_sha256 -ceq $request.comparison.source_sha256) 'Original fresh qualification receipts differ; metadata is never new admission authority.'
            SameBinding $ticket.binding $prepared.observed_binding;SameBinding $ticket.binding $prepared.journal.ticket.binding
            foreach($name in @('schema_version','immutable_sha256','immutable_length','journal_length')){Require ($ticket.$name -ceq $prepared.journal.ticket.$name) 'Prepared ticket fields differ.'}
            Require ($fault.kind -ceq 'controlled-composite-conversion-interruption-intent' -and $fault.interrupt_after_writes -eq 1 -and $fault.expected_process_exit_code -eq 86 -and $fault.ticket_sha256 -ceq $pins['ticket.json'] -and $fault.artifact_identity_sha256 -ceq $backing.artifact_identity_sha256) 'Durable interruption intent does not bind the ticket/backing.'
            foreach($name in @('apply.json','finalization.json','result.json','failed.json')){Require (-not(Test-Path -LiteralPath (Join-Path $Stage ('result\'+$name)))) 'Completed/failed conversion artifact contradicts first-write interruption.'}
            $expectedJournal='\\?\Volume{8bdb2a25-9c1a-4132-a1fc-0b4654153d3b}\ntfs2refs-shadow\'+$Run+'\reconstruction.journal'
            Require ($values['journal-location.json'].path -ceq $expectedJournal -and $fault.journal_path -ceq $expectedJournal -and $request.journal.disk.disk_number -eq 2 -and [guid]$request.journal.disk.identity.disk_guid -eq [guid]'09fcc613-b8c2-4a1a-8833-226f9399be7f' -and [guid]$request.journal.disk.volume_guid -eq [guid]'8bdb2a25-9c1a-4132-a1fc-0b4654153d3b') 'Exact current journal route required.'
            # Repeat the terminal-only project guard BEFORE any J: handle.
            Require ((Get-ScheduledTaskInfo -TaskName ('N2R-AdmittedCompact-Interrupt-'+$Run)).LastTaskResult -eq 86 -and @((Get-ScheduledTask -TaskName ('N2R-AdmittedCompact-Interrupt-'+$Run))|Where-Object {$_.State.ToString() -ne 'Ready'}).Count -eq 0) 'Task is no longer terminal86.'
            Require (@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -in @('lab-convert-native-composite.exe','lab-recover-native-composite.exe','ntfs2refs.exe','ntfs2refs-recover.exe','lab-apply-compact-fixture.exe')}).Count -eq 0) 'Worker exists before journal observation.'
            $item=Ordinary $expectedJournal;Require ($item.Length -eq $ticket.journal_length -and $item.Length -gt 8192+256 -and $item.Length -le 256MB -and $ticket.immutable_length+8192 -eq $item.Length) 'Bounded journal/ticket length differs.'
            $stamp=$item.LastWriteTimeUtc.Ticks;$j=[IO.File]::Open($expectedJournal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
            [byte[]]$prefix=ReadAt $j 0 8192
            for($i=0;$i -lt 4096;$i++){Require ($prefix[$i] -eq 0) 'A handoff byte is nonzero; no pre-handoff preservation claim.'}
            $intent=[byte[]]::new(4096);[Text.Encoding]::ASCII.GetBytes('N2RINT01').CopyTo($intent,0);$intent[8]=1;(Hex $ticket.immutable_sha256).CopyTo($intent,16);(Hex $prepared.journal.expected_postimage_sha256).CopyTo($intent,48)
            $intentDigest=Hex (Digest ([byte[]]$intent[0..4063]));$intentDigest.CopyTo($intent,4064)
            Require ([Convert]::ToBase64String([byte[]]$prefix[4096..8191]) -ceq [Convert]::ToBase64String($intent)) 'Operation-intent sector is not the exact code1 marker bound to ticket/postimage.'
            $header=ReadAt $j 8192 128;$metadataBytes=[BitConverter]::ToUInt32($header,12);$count=[BitConverter]::ToUInt32($header,16);$changed=[BitConverter]::ToUInt64($header,24)
            Require ([Text.Encoding]::ASCII.GetString($header,0,8) -ceq 'N2RPREP1' -and [BitConverter]::ToUInt32($header,8) -eq 2 -and $metadataBytes -le 1MB -and $count -le 65536 -and $changed -eq $prepared.journal.changed_bytes -and [BitConverter]::ToUInt64($header,32) -eq $ticket.journal_length -and (Digest ([byte[]]$header[0..95])) -ceq ([BitConverter]::ToString($header,96,32).Replace('-','').ToLowerInvariant())) 'Prepared header/checksum/bounds differ.'
            Require ([long]8192+128+$metadataBytes+[long]160*$count+[long]2*$changed+128 -eq $ticket.journal_length) 'Prepared journal byte accounting differs.'
            $metadata=ReadAt $j (8192+128) ([int]$metadataBytes);Require ((Digest $metadata) -ceq ([BitConverter]::ToString($header,40,32).Replace('-','').ToLowerInvariant())) 'Immutable manifest digest differs.'
            $manifest=[Text.UTF8Encoding]::new($false,$true).GetString($metadata)|ConvertFrom-Json;SameBinding $manifest.binding $ticket.binding
            Require ($manifest.schema_version -eq 2 -and $manifest.expected_postimage_sha256 -ceq $prepared.journal.expected_postimage_sha256 -and $manifest.expected_postimage_sha256 -ceq $request.comparison.shadow_sha256) 'Immutable postimage differs.'
            foreach($name in @('schema_version','sector_size','expected_length','source_sha256','shadow_sha256','max_change_bytes','max_ranges')){Require ($manifest.request.$name -ceq $request.comparison.$name) 'Immutable comparison scalar differs.'}
            Require (@($manifest.request.retained_ranges).Count -eq @($request.comparison.retained_ranges).Count) 'Immutable retained-range count differs.'
            for($i=0;$i -lt @($manifest.request.retained_ranges).Count;$i++){foreach($name in @('offset','length','source_sha256','shadow_sha256')){Require ($manifest.request.retained_ranges[$i].$name -ceq $request.comparison.retained_ranges[$i].$name) 'Immutable retained-range descriptor differs.'}}
            $footer=ReadAt $j ($j.Length-128) 128
            Require ([Text.Encoding]::ASCII.GetString($footer,0,8) -ceq 'N2REND01' -and [BitConverter]::ToUInt64($footer,8) -eq $count -and [BitConverter]::ToUInt64($footer,16) -eq $j.Length-128 -and (Digest ([byte[]]$footer[0..95])) -ceq ([BitConverter]::ToString($footer,96,32).Replace('-','').ToLowerInvariant()) -and (Digest $header) -ceq ([BitConverter]::ToString($footer,56,32).Replace('-','').ToLowerInvariant())) 'Prepared footer/header digest differs.'
            $full=[Security.Cryptography.SHA256]::Create();$body=[Security.Cryptography.SHA256]::Create();$buffer=[byte[]]::new(1MB);$position=[long]0;$j.Position=0
            try{while($position -lt $j.Length){$wanted=[int][Math]::Min($buffer.Length,$j.Length-$position);$n=$j.Read($buffer,0,$wanted);Require ($n -gt 0) 'Journal digest read ended early.';[void]$full.TransformBlock($buffer,0,$n,$buffer,0);$skip=[int][Math]::Min($n,[Math]::Max([long]0,8192-$position));if($n -gt $skip){[void]$body.TransformBlock($buffer,$skip,$n-$skip,$buffer,$skip)};$position+=$n};[void]$full.TransformFinalBlock([byte[]]::new(0),0,0);[void]$body.TransformFinalBlock([byte[]]::new(0),0,0);$fullPin=[BitConverter]::ToString($full.Hash).Replace('-','').ToLowerInvariant();$bodyPin=[BitConverter]::ToString($body.Hash).Replace('-','').ToLowerInvariant()}finally{$full.Dispose();$body.Dispose()}
            Require ($bodyPin -ceq $ticket.immutable_sha256 -and $position -eq $ticket.journal_length -and $j.Length -eq $ticket.journal_length -and (Get-Item -LiteralPath $expectedJournal).LastWriteTimeUtc.Ticks -eq $stamp) 'Journal immutable ticket digest/length/stamp changed.'
            Require ([Convert]::ToBase64String((ReadAt $j 0 8192)) -ceq [Convert]::ToBase64String($prefix)) 'Mutable sectors changed during observation.'
            $record=@{kind='terminal-admitted-partial-journal-observation';run_id=$Run;documents=$documents.ToArray();journal_path=$expectedJournal;journal_bytes=$j.Length;journal_sha256=$fullPin;immutable_sha256=$bodyPin;immutable_ticket_digest_verified=$true;header_manifest_footer_observed=$true;deep_record_payload_validation_performed=$false;handoff_first4096_all_zero=$true;operation_intent_exact_code1=$true;prefix8192_base64=[Convert]::ToBase64String($prefix);prefix8192_sha256=(Digest $prefix);packed_payload_opened=$false;packed_payload_copied=$false;packed_hash_rechecked=$false;source_image_opened=$false;source_image_normalized_or_hashed=$false;raw_recovery_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')}
            $text=$record|ConvertTo-Json -Depth 8 -Compress;Require ([Text.Encoding]::UTF8.GetByteCount($text) -le 24MB) 'Bounded metadata transport exceeded24MiB.';$text
        }finally{if($null -ne $j){$j.Dispose()};for($i=$held.Count-1;$i -ge 0;$i--){$held[$i].Dispose()}}
    }
    $collection=$collectionText|ConvertFrom-Json
    $archive=Join-Path $root 'partial-metadata';Need (-not(Test-Path -LiteralPath $archive)) 'Metadata archive already exists.';New-Item -ItemType Directory -Path $archive|Out-Null
    $pins=@();foreach($doc in $collection.documents){Need ($doc.name -cmatch '\A[a-z0-9-]+\.json\z') 'Unexpected metadata archive name.';[byte[]]$bytes=[Convert]::FromBase64String($doc.bytes_base64);Need ($bytes.Length -eq $doc.bytes -and (Hash $bytes) -ceq $doc.sha256) 'Transported metadata bytes/hash differ.';Save-Bytes (Join-Path $archive $doc.name) $bytes;$pins+=@{name=$doc.name;source=$doc.source;bytes=$bytes.Length;sha256=$doc.sha256}}
    [byte[]]$prefix=[Convert]::FromBase64String($collection.prefix8192_base64);Need ($prefix.Length -eq 8192 -and (Hash $prefix) -ceq $collection.prefix8192_sha256) 'Transported marker bytes differ.';Save-Bytes (Join-Path $archive 'journal-prefix-8192.bin') $prefix
    $collection.documents=$pins;$collection.PSObject.Properties.Remove('prefix8192_base64');Save-New 'partial-journal-observation.json' $collection
    # Recheck the actual terminal worker/task and persistent disk state after
    # journal handles close, before the one clean shutdown request.
    $recheckText=Invoke-Command -Session $session -ScriptBlock $guard -ArgumentList $stage,$task,$run,$wrapperPin
    $recheck=$recheckText|ConvertFrom-Json;Need ($recheck.wrapper_receipt_sha256 -ceq $terminal.wrapper_receipt_sha256) 'Interruption receipt changed before shutdown.'
    Save-New 'pre-shutdown-terminal.json' $recheck
    Remove-PSSession $session;$session=$null
    $vm=Get-VM -Id $id;Need ($vm.State.ToString() -ceq 'Running' -and $vm.ParentSnapshotId -eq $parent) 'Owned VM changed before shutdown.'
    Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration $configuration) -AdditionalBytes 256MB
    Save-New 'clean-shutdown-intent.json' @{vm_id=$id.ToString();parent_id=$vm.ParentSnapshotId.ToString('D');worker_absence_rechecked=$true;force=$false;utc=[DateTime]::UtcNow.ToString('o')}
    Stop-VM -VM $vm -Confirm:$false -ErrorAction Stop
    $deadline=[DateTime]::UtcNow.AddSeconds(30)
    do{$fresh=Get-VM -Id $id;$native=Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_ComputerSystem -Filter ("Name='"+$id.ToString()+"'") -ErrorAction Stop;if($fresh.State.ToString() -ceq 'Off' -and $fresh.MemoryAssigned -eq 0 -and $native.EnabledState -eq 3){break};if([DateTime]::UtcNow -ge $deadline){throw 'Clean OFF is not freshly confirmed; never issue another stop or force.'};Start-Sleep -Milliseconds 500}while($true)
    # Capture immutable scalar parent before Checkpoint-VM can change the live
    # VM object's ParentSnapshotId. Poll fresh views; never create a retry CP.
    $parentBeforeCheckpoint=$fresh.ParentSnapshotId.ToString('D');Need ([guid]$parentBeforeCheckpoint -eq $parent) 'OFF parent differs.'
    $before=@(Get-VMSnapshot -VM (Get-VM -Id $id));Need ($before.Count -eq 44 -and @($old|Where-Object {$_ -notin @($before.Id|ForEach-Object {$_.ToString('D')})}).Count -eq 0) 'All44 branches required before checkpoint creation.'
    Need (@($before|Where-Object Name -CEQ $snapshotName).Count -eq 0) 'Named partial checkpoint already exists; do not create another.'
    Save-New 'partial-checkpoint-create-intent.json' @{vm_id=$id.ToString();run_id=$run;name=$snapshotName;parent_id_before_creation=$parentBeforeCheckpoint;prior_checkpoint_ids=$old;creation_may_be_issued_once=$true;utc=[DateTime]::UtcNow.ToString('o')}
    $created=Checkpoint-VM -VM (Get-VM -Id $id) -SnapshotName $snapshotName -Passthru -ErrorAction Stop
    $createdId=if($null -ne $created -and [guid]$created.Id -ne [guid]::Empty){([guid]$created.Id).ToString('D')}else{$null}
    $deadline=[DateTime]::UtcNow.AddSeconds(30)
    do{$fresh=Get-VM -Id $id;$all=@(Get-VMSnapshot -VM $fresh);$matches=@($all|Where-Object Name -CEQ $snapshotName);Need ($matches.Count -le 1) 'Duplicate partial checkpoint name; preserve uncertainty.'
        if($matches.Count -eq 1 -and $all.Count -eq 45 -and @($old|Where-Object {$_ -notin @($all.Id|ForEach-Object {$_.ToString('D')})}).Count -eq 0){$actualId=$matches[0].Id.ToString('D');Need (($null -eq $createdId -or $createdId -ceq $actualId) -and $actualId -notin $old -and $fresh.State.ToString() -ceq 'Off' -and $fresh.MemoryAssigned -eq 0) 'Fresh checkpoint identity/OFF state differs.';break}
        if([DateTime]::UtcNow -ge $deadline){throw 'Fresh partial checkpoint view did not settle within30s; creation intent is preserved, no second creation allowed.'};Start-Sleep -Milliseconds 500
    }while($true)
    Save-New 'partial-checkpoint.json' @{success=$true;run_id=$run;vm_id=$id.ToString();checkpoint_id=$actualId;parent_id=$parentBeforeCheckpoint;name=$snapshotName;checkpoint_count=45;all_prior44_preserved=$true;state='Off';memory_assigned=0;journal_sha256=$collection.journal_sha256;immutable_ticket_digest_verified=$true;handoff_first4096_all_zero=$true;operation_intent_exact_code1=$true;deep_record_payload_validation_performed=$false;raw_recovery_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')}
    Get-Content -LiteralPath (Join-Path $root 'partial-checkpoint.json') -Raw
}catch{if($intentSaved -and -not(Test-Path -LiteralPath (Join-Path $root 'preservation-failed.json'))){Save-New 'preservation-failed.json' @{run_id=$run;error=$_.Exception.ToString();automatic_retry=$false;checkpoint_creation_repeated=$false;utc=[DateTime]::UtcNow.ToString('o')}};throw}
finally{if($null -ne $session){Remove-PSSession $session}}
