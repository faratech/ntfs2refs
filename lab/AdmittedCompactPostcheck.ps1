# Completed admitted conversion only. No raw replay, VM restore, or forced shutdown.
[CmdletBinding()]param(
    [Parameter(Mandatory)][ValidateSet('Collect','BootVerify','Mutate','AfterMutation','RebootVerify','Preserve')][string]$Phase,
    [string]$ToolsetManifest='D:\code\ntfs2refs\.lab\hyperv\streaming-v2-20261027\compact-admitted-retry-20261028\postcheck-tools\manifest.json',
    [ValidatePattern('^[a-f0-9]{64}$')][string]$ToolsetManifestSha256='4ea054fba859d2dd9f2544e539f0083b3594ae6d3349462ab3a4d5510b28af27'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$run='ac098b7437e04d2d928bc2e18f3b5218';$parent=[guid]'cfe0b326-7308-4a58-810d-9730ff8152b4'
$task='N2R-AdmittedCompact-Retry-'+$run
$conversionStage='C:\ntfs2refs\compact-admitted-retry-'+$run;$converted=Join-Path $conversionStage 'result'
$runRoot=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\compact-admitted-retry-20261028'
$root=Join-Path $runRoot 'admitted-postcheck';$guestStage='C:\ntfs2refs\admitted-compact-postcheck-'+$run
$forecast=[long]7GB;$maximum=[long]329374052988;$minimum=[long]17179869184
function Save-New([string]$Name,$Value){$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 32));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Read-Receipt([string]$Name){$v=Get-Content -LiteralPath (Join-Path $root $Name) -Raw -Encoding UTF8|ConvertFrom-Json;if(-not $v.success -or $v.run_id -cne $run){throw ('Matching successful receipt required: '+$Name)};return $v}
function Boot-UTC($Value){if($Value -is [DateTime]){if($Value.Kind -eq [DateTimeKind]::Unspecified){throw 'Boot timezone missing.'};return $Value.ToUniversalTime().ToString('o')};if($Value -is [DateTimeOffset]){return $Value.UtcDateTime.ToString('o')};if([string]$Value -cnotmatch '(Z|[+-][0-9]{2}:[0-9]{2})$'){throw 'Explicit boot timezone required.'};return [DateTimeOffset]::Parse([string]$Value,[Globalization.CultureInfo]::InvariantCulture).UtcDateTime.ToString('o')}
function Capacity([long]$Additional){$c=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace);if($c.MaximumActualBytes -ne $maximum -or $c.MinimumFreeBytes -ne $minimum){throw 'Approved one-time storage epoch changed; do not reset its baseline.'};Assert-LabCapacity -Capacity $c -AdditionalBytes $Additional;return $c}
function Snapshot-Ids($Vm){return @(Get-VMSnapshot -VM $Vm|ForEach-Object {$_.Id.ToString()})}
function Assert-Preserved($Ids,$Required){if(@($Required|Where-Object {$_ -notin $Ids}).Count){throw 'A prior checkpoint is missing.'}}
function Clean-Off($Vm,$Session){Invoke-Command -Session $Session -ScriptBlock {if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name -in @('lab-convert-native-composite.exe','lab-recover-native-composite.exe','lab-verify-general-converted.exe','lab-general-refs-mutation.exe','lab-apply-compact-fixture.exe')}).Count){throw 'Worker active; clean shutdown refused.'}};Stop-VM -VM $Vm -Confirm:$false;$v=Get-VM -Id $id;if($v.State.ToString() -cne 'Off' -or $v.MemoryAssigned -ne 0){throw 'Clean OFF not observed; do not repeat or force shutdown.'};return $v}
function Session-Once($Credential){$s=$null;$deadline=[DateTime]::UtcNow.AddMinutes(5);while($null -eq $s){try{$s=New-PSSession -VMId $id -Credential $Credential -ErrorAction Stop}catch{if([DateTime]::UtcNow -ge $deadline){throw 'Single boot/session not ready; do not reboot again.'};Start-Sleep -Seconds 3}};return $s}

# This script block only observes process/task state and bounded completed JSON.
# In-flight conversion reports and every journal/payload/VHD are left unopened.
$inspectGuest={
    param($Run,$Task,$Stage,$Converted)
    Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
    if((Get-FileHash -LiteralPath 'C:\Windows\System32\drivers\refs.sys').Hash.ToLowerInvariant() -cne '3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4'){throw 'Pinned ReFS driver changed; preserve the branch without postcheck.'}
    function Doc([string]$Path,[long]$Limit){$m=Get-Item -LiteralPath $Path;if($m.PSIsContainer -or ($m.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $m.Length -gt $Limit){throw 'Completed report is not bounded and ordinary.'};$f=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{if($f.Length -gt $Limit){throw 'Completed report grew.'};$b=[byte[]]::new([int]$f.Length);$at=0;while($at -lt $b.Length){$n=$f.Read($b,$at,$b.Length-$at);if($n -eq 0){throw 'Completed report ended early.'};$at+=$n};$sha=[Security.Cryptography.SHA256]::Create();try{$pin=[BitConverter]::ToString($sha.ComputeHash($b)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};$text=[Text.UTF8Encoding]::new($false,$true).GetString($b);@{path=$Path;sha256=$pin;bytes=$b.Length;data=[Convert]::ToBase64String($b);value=($text|ConvertFrom-Json)}}finally{$f.Dispose()}}
    $t=Get-ScheduledTask -TaskName $Task;$ti=Get-ScheduledTaskInfo -TaskName $Task
    $workers=@(Get-CimInstance Win32_Process|Where-Object {$_.ProcessId -in @(5108,4892) -or $_.Name -in @('lab-convert-native-composite.exe','lab-abort-general-source.exe','ntfs2refs-bind.exe','lab-recover-native-composite.exe','lab-verify-general-converted.exe','lab-general-refs-mutation.exe','lab-apply-compact-fixture.exe')}|Select-Object ProcessId,Name,CreationDate,WorkingSetSize,PageFileUsage)
    $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
    $status=@{run_id=$Run;task_name=$Task;task_state=$t.State.ToString();last_task_result=[long]$ti.LastTaskResult;last_run_time=$ti.LastRunTime;workers=$workers;guest_boot_utc=$boot;completed=$false;documents=@();utc=[DateTime]::UtcNow.ToString('o')}
    if($workers.Count -or $t.State.ToString() -ceq 'Running' -or $ti.LastTaskResult -ne 0 -or $ti.LastRunTime.Year -lt 2000){return $status}
    if((Test-Path -LiteralPath (Join-Path $Stage 'wrapper-failed.json')) -or (Test-Path -LiteralPath (Join-Path $Converted 'failed.json'))){throw 'Conversion recorded a failure; no postcheck is authorized.'}
    $w=Doc (Join-Path $Stage 'wrapper-result.json') 65536;$r=Doc (Join-Path $Converted 'result.json') 16777216;$f=Doc (Join-Path $Converted 'finalization.json') 16777216
    if(-not $w.value.success -or $w.value.exit -ne 0 -or $w.value.phase -cne 'fresh-admitted-conversion' -or -not $r.value.success -or -not $r.value.source_admitted -or -not $r.value.rollback_closed -or $r.value.kind -cne 'experimental-certificate-backed-composite-conversion' -or -not $r.value.complete_native_address_space_compared -or -not $f.value.success -or -not $f.value.rollback_closed -or -not $f.value.handoff.handoff_recorded){throw 'Terminal successful admitted conversion and closed HND required.'}
    $p=Doc (Join-Path $Converted 'request.json') 131072;$e=Doc (Join-Path $Converted 'expectation.json') 16777216;$a=Doc (Join-Path $Converted 'apply.json') 16777216
    if($p.value.experiment_id -cne $Run -or $p.value.expected_tree_sha256 -cne $e.sha256 -or $r.value.expected_tree_sha256 -cne $e.sha256 -or $p.value.source_resource_profile -cne 'experimental_streaming_tree_v2' -or $a.value.result.target_sha256 -cne $p.value.comparison.shadow_sha256){throw 'Completed request/tree/apply bindings differ.'}
    $status.completed=$true;$status.request_sha256=$p.sha256;$status.expectation_sha256=$e.sha256
    $status.documents=@(@{name='wrapper-result.json';doc=$w},@{name='result.json';doc=$r},@{name='finalization.json';doc=$f},@{name='request.json';doc=$p},@{name='expectation.json';doc=$e},@{name='apply.json';doc=$a})
    return $status
}

$enrollment=Get-Content -LiteralPath (Join-Path $runRoot 'intent.json') -Raw -Encoding UTF8|ConvertFrom-Json
if($enrollment.run_id -cne $run -or [guid]$enrollment.vm_id -ne $id -or [guid]$enrollment.parent_id -ne $parent -or @($enrollment.old_checkpoint_ids).Count -ne 42){throw 'Exact retry enrollment/all42 baseline required.'}
$vm=Get-VM -Id $id;$ids=Snapshot-Ids $vm;Assert-Preserved $ids $enrollment.old_checkpoint_ids
if($vm.MemoryStartup -ne 4GB -or $vm.DynamicMemoryEnabled -or @(Get-VMNetworkAdapter -VM $vm).Count){throw 'Fixed4GiB isolated VM required.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1')
$capacity=Capacity $(if($Phase -ceq 'Collect'){0}else{$forecast})
if(-not (Test-Path -LiteralPath $root)){if($Phase -cne 'Collect'){throw 'Run metadata-only Collect first.'};New-Item -ItemType Directory -Path $root|Out-Null}
$credential=Import-Clixml -LiteralPath (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
if($Phase -ceq 'Collect'){
    $observation=$null;$s=$null
    try{if($vm.State.ToString() -ceq 'Running'){$s=New-PSSession -VMId $id -Credential $credential;$observation=Invoke-Command -Session $s -ScriptBlock $inspectGuest -ArgumentList $run,$task,$conversionStage,$converted}
        if($null -ne $observation -and $observation.completed){
            foreach($row in $observation.documents){$path=Join-Path $root ('conversion-'+$row.name);if(Test-Path -LiteralPath $path){if((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -cne $row.doc.sha256){throw 'Archived completed report pin differs.'}}else{$b=[Convert]::FromBase64String($row.doc.data);$f=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}};if((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -cne $row.doc.sha256){throw 'Completed report archive differs.'}}
            $receipt=@{success=$true;run_id=$run;vm_id=$id.ToString();task_name=$task;request_sha256=$observation.request_sha256;expectation_sha256=$observation.expectation_sha256;guest_boot_utc=$observation.guest_boot_utc;documents=@($observation.documents|ForEach-Object {@{name=$_.name;path=$_.doc.path;sha256=$_.doc.sha256;bytes=$_.doc.bytes}});old_checkpoint_ids=$enrollment.old_checkpoint_ids;source_parent_id=$parent.ToString();utc=[DateTime]::UtcNow.ToString('o')}
            if(Test-Path -LiteralPath (Join-Path $root 'completed-conversion.json')){$old=Read-Receipt 'completed-conversion.json';if($old.request_sha256 -cne $receipt.request_sha256 -or $old.expectation_sha256 -cne $receipt.expectation_sha256){throw 'Completed conversion receipt changed.'}}else{Save-New 'completed-conversion.json' $receipt}
            $observation.documents=$receipt.documents
        }
        Save-New ('Collect-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff')+'-'+[guid]::NewGuid().ToString('N')+'.json') @{run_id=$run;vm_state=$vm.State.ToString();checkpoint_ids=$ids;capacity=$capacity;observation=$observation;metadata_only=$true;vm_actions=$false;utc=[DateTime]::UtcNow.ToString('o')}
        [pscustomobject]@{phase='Collect';conversion_terminal_success=($null -ne $observation -and $observation.completed);vm_state=$vm.State.ToString();vm_actions=$false}|ConvertTo-Json -Compress;return
    }finally{if($null -ne $s){Remove-PSSession $s}}
}

$complete=Read-Receipt 'completed-conversion.json'
if(Test-Path -LiteralPath (Join-Path $root ($Phase+'-intent.json'))){throw 'Phase has state; inspect without redispatch.'}
if((Get-FileHash -LiteralPath $ToolsetManifest).Hash.ToLowerInvariant() -cne $ToolsetManifestSha256){throw 'Toolset manifest pin differs.'}
$manifest=Get-Content -LiteralPath $ToolsetManifest -Raw -Encoding UTF8|ConvertFrom-Json
if($manifest.schema_version -ne 1 -or $manifest.kind -cne 'admitted-compact-postcheck-toolset' -or @($manifest.tools).Count -ne 2){throw 'Pinned admitted toolset required.'}
$names=@('lab-verify-general-converted.exe','lab-general-refs-mutation.exe')
foreach($name in $names){$rows=@($manifest.tools|Where-Object name -ceq $name);if($rows.Count -ne 1){throw 'Toolset coverage differs.'};$tool=$rows[0];$path=[IO.Path]::GetFullPath([string]$tool.path);$allowed=[IO.Path]::GetFullPath((Join-Path $runRoot 'postcheck-tools'))+'\';$item=Get-Item -LiteralPath $path;if(-not $path.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase) -or $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -ne $tool.bytes -or $item.Length -gt 8MB -or (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -cne $tool.sha256){throw 'Pinned ordinary observer differs.'}}
$previous=$null
if($Phase -ceq 'BootVerify'){if($ids.Count -ne 42 -or $vm.ParentSnapshotId -ne $parent -or $vm.State.ToString() -cne 'Running'){throw 'Fresh completed running retry/all42 required.'}}
else{$previous=Read-Receipt $(switch($Phase){'Mutate'{'BootVerify.json'}'AfterMutation'{'Mutate.json'}'RebootVerify'{'AfterMutation.json'}'Preserve'{'RebootVerify.json'}});$saved=Read-Receipt 'converted-preservation.json';if($ids.Count -ne 43 -or $vm.ParentSnapshotId -ne [guid]$saved.checkpoint_id){throw 'Preserved converted checkpoint43 branch required.'};Assert-Preserved $ids (@($complete.old_checkpoint_ids)+@($saved.checkpoint_id))}
if($vm.State.ToString() -cne 'Running'){throw 'Existing running postcheck branch required.'}
$s=New-PSSession -VMId $id -Credential $credential
try{
    $terminal=Invoke-Command -Session $s -ScriptBlock $inspectGuest -ArgumentList $run,$task,$conversionStage,$converted
    if(-not $terminal.completed -or $terminal.request_sha256 -cne $complete.request_sha256 -or $terminal.expectation_sha256 -cne $complete.expectation_sha256){throw 'Exact conversion is not terminal and closed; no stateful postcheck.'}
    Save-New ($Phase+'-intent.json') @{run_id=$run;phase=$Phase;capacity=$capacity;additional_forecast_bytes=$forecast;forecast_is_not_reservation=$true;toolset_manifest_sha256=$ToolsetManifestSha256;prior_checkpoint_ids=$ids;utc=[DateTime]::UtcNow.ToString('o')}
    if($Phase -in @('BootVerify','RebootVerify','Preserve')){
        $vm=Clean-Off $vm $s;Remove-PSSession $s;$s=$null
        if($Phase -in @('BootVerify','Preserve')){
            $label=if($Phase -ceq 'BootVerify'){'admitted-compact-converted-'}else{'admitted-compact-reboot-mutation-passed-'}
            $cp=Checkpoint-VM -VM $vm -SnapshotName ($label+$run) -Passthru
            $deadline=[DateTime]::UtcNow.AddSeconds(30)
            do{$new=Snapshot-Ids (Get-VM -Id $id);if($new.Count -eq ($ids.Count+1) -and $cp.Id.ToString() -in $new){break};if([DateTime]::UtcNow -ge $deadline){throw 'New checkpoint is not visible; inspect without creating another.'};Start-Sleep -Milliseconds 250}while($true)
            Assert-Preserved $new $ids
            if($new.Count -ne ($ids.Count+1) -or $cp.Id.ToString() -in $ids){throw 'New checkpoint receipt/count differs; inspect without another checkpoint.'}
            $saved=@{success=$true;run_id=$run;checkpoint_id=$cp.Id.ToString();parent_id=$vm.ParentSnapshotId.ToString();old_checkpoint_ids=$ids;checkpoint_count=$new.Count;all_prior_preserved=$true;state='Off';memory_assigned=0;utc=[DateTime]::UtcNow.ToString('o')}
            Save-New $(if($Phase -ceq 'BootVerify'){'converted-preservation.json'}else{'Preserve.json'}) $saved
            if($Phase -ceq 'Preserve'){Write-Output 'Postcheck preserved OFF; all44 checkpoints retained.';return}
        }
        Start-VM -VM (Get-VM -Id $id)|Out-Null;$s=Session-Once $credential
    }
    if($Phase -ceq 'BootVerify'){
        Invoke-Command -Session $s -ArgumentList $guestStage -ScriptBlock {param($Stage);if(Test-Path -LiteralPath $Stage){throw 'Fresh guest observer stage required.'};New-Item -ItemType Directory -Path $Stage|Out-Null}
        foreach($tool in $manifest.tools){Copy-Item -LiteralPath ([IO.Path]::GetFullPath([string]$tool.path)) -ToSession $s -Destination (Join-Path $guestStage $tool.name)}
    }
    $mutation=if($Phase -in @('AfterMutation','RebootVerify')){Read-Receipt 'Mutate.json'}else{$null}
    $priorBoot=if($Phase -ceq 'BootVerify'){Boot-UTC $complete.guest_boot_utc}elseif($Phase -ceq 'RebootVerify'){Boot-UTC $previous.guest_boot_utc}else{''}
    $result=Invoke-Command -Session $s -ArgumentList $Phase,$guestStage,$run,$converted,$complete.request_sha256,$complete.expectation_sha256,($manifest.tools|ConvertTo-Json -Compress),$priorBoot,($mutation|ConvertTo-Json -Depth 8 -Compress) -ScriptBlock {
        param($Phase,$Stage,$Run,$Converted,$RequestPin,$TreePin,$ToolsJson,$PriorBoot,$MutationJson);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        foreach($tool in ($ToolsJson|ConvertFrom-Json)){$p=Join-Path $Stage $tool.name;if((Get-Item -LiteralPath $p).Length -ne $tool.bytes -or (Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant() -cne $tool.sha256){throw 'Guest observer pin differs.'}}
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.ProcessId -in @(5108,4892) -or $_.Name -in @('lab-convert-native-composite.exe','lab-recover-native-composite.exe','lab-verify-general-converted.exe','lab-general-refs-mutation.exe','lab-apply-compact-fixture.exe')}).Count){throw 'Worker active; no postcheck.'}
        $request=Join-Path $Converted 'request.json';$expected=Join-Path $Converted 'expectation.json';if((Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant() -cne $RequestPin -or (Get-FileHash -LiteralPath $expected).Hash.ToLowerInvariant() -cne $TreePin){throw 'Completed request/tree pins differ.'}
        $value=Get-Content -LiteralPath $request -Raw -Encoding UTF8|ConvertFrom-Json;$source=Get-Disk -Number $value.pair.source.disk_number;$shadow=Get-Disk -Number $value.pair.shadow.disk_number;$part=@(Get-Partition -DiskNumber $source.Number|Where-Object Offset -eq $value.pair.source.identity.partition_offset);$volume=$part|Get-Volume
        $label=-join @($value.expected_source_label.utf16|ForEach-Object {[char]$_})
        if([guid]$source.Guid -ne [guid]$value.pair.source.identity.disk_guid -or [guid]$shadow.Guid -ne [guid]$value.pair.shadow.identity.disk_guid -or $source.IsOffline -or $source.IsReadOnly -or -not $shadow.IsOffline -or -not $shadow.IsReadOnly -or $part.Count -ne 1 -or [guid]$part[0].Guid -ne [guid]$value.pair.source.identity.partition_guid -or $volume.FileSystem -cne 'ReFS' -or $volume.AllocationUnitSize -ne 4096 -or $volume.FileSystemLabel -cne $label){throw 'Converted original/frozen shadow binding differs.'}
        $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');if($Phase -in @('BootVerify','RebootVerify') -and [DateTimeOffset]::Parse($boot) -le [DateTimeOffset]::Parse($PriorBoot)){throw 'Fresh clean boot required.'}
        $report=Join-Path $Stage ($Phase+'.json');if(Test-Path -LiteralPath $report){throw 'Observer phase has state; do not repeat.'}
        $cli=@('--request',$request,'--request-sha256',$RequestPin,'--output',$report)
        if($Phase -ceq 'Mutate'){$binary=Join-Path $Stage 'lab-general-refs-mutation.exe';$cli+=@('--run-id',$Run)}else{$binary=Join-Path $Stage 'lab-verify-general-converted.exe';$cli+=@('--expectation',$expected,'--expectation-sha256',$TreePin);if($Phase -in @('AfterMutation','RebootVerify')){$m=$MutationJson|ConvertFrom-Json;$cli+=@('--mutation-report',$m.guest_report,'--mutation-report-sha256',$m.report_sha256)}}
        $ErrorActionPreference='Continue';$log=@(& $binary @cli 2>&1);$exit=$LASTEXITCODE;$ErrorActionPreference='Stop';$log|Out-String|Set-Content -LiteralPath (Join-Path $Stage ($Phase+'.log')) -Encoding UTF8
        if($exit -ne 0){throw ('Native '+$Phase+' refused; preserve report/log without repeating.')}
        $native=Get-Content -LiteralPath $report -Raw -Encoding UTF8|ConvertFrom-Json
        if($Phase -ceq 'Mutate'){if($native.kind -cne 'general-refs-mutation-workload' -or $native.request_sha256 -cne $RequestPin -or -not $native.only_new_test_paths_written -or -not $native.mutation_directory_removed){throw 'Mutation scope differs.'}}
        elseif(-not $native.success -or -not $native.ordinary_tree_verified -or $native.diagnostic_only -or $native.request_sha256 -cne $RequestPin){throw 'Strict native full-tree verification did not pass.'}
        @{success=$true;phase=$Phase;run_id=$Run;guest_report=$report;report_sha256=(Get-FileHash -LiteralPath $report).Hash.ToLowerInvariant();guest_boot_utc=$boot;request_sha256=$RequestPin;expectation_sha256=$TreePin;retained_position_proof_included=$false;utc=[DateTime]::UtcNow.ToString('o')}
    }
    foreach($name in @(($Phase+'.json'),($Phase+'.log'))){Copy-Item -FromSession $s -LiteralPath (Join-Path $guestStage $name) -Destination (Join-Path $root ('guest-'+$name))}
    if((Get-FileHash -LiteralPath (Join-Path $root ('guest-'+$Phase+'.json'))).Hash.ToLowerInvariant() -cne $result.report_sha256){throw 'Archived native report differs.'}
    Save-New ($Phase+'.json') $result;$result|ConvertTo-Json -Compress
}catch{Save-New ($Phase+'-failed.json') @{run_id=$run;phase=$Phase;error=$_.Exception.Message;automatic_retry=$false;automatic_rollback=$false;utc=[DateTime]::UtcNow.ToString('o')};throw}finally{if($null -ne $s){Remove-PSSession $s}}
