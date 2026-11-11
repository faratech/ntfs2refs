# Logical native NTFS stream readback after terminal successful c585 rollback.
# No journal/shadow/raw access, VM power/restore, attribute changes or replay.
[CmdletBinding()]param([ValidateSet('Dispatch','Collect')][string]$Phase='Dispatch')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$run='c5852b0ca8ef4927bd3d9e15c45132f9';$originalRun='949dbc98138e4514a1098081eb0226ef'
$sourcePin='a90a9cd8f9fca6037b396127d161f56cc5698cae832c6bd3872d38378a367c6e'
$requestPin='38e12f06afe7fc4a5e4ef3f1c100ea3cb2b5d941f908c65b149dc08ccef38246'
$treePin='149c4aae5f788d5e78b2cee0f057049caf3d5241c6556edeba9e33eedbef6bbe'
$role=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\compact-admitted-recovery-20261028\rollback'
$root=Join-Path $role 'native-readback';$task='N2R-AdmittedRollbackReadback-'+$run
$d=Get-Content -LiteralPath (Join-Path $role 'dispatch.json') -Raw -Encoding UTF8|ConvertFrom-Json
$prior=Get-Content -LiteralPath (Join-Path $role 'intent.json') -Raw -Encoding UTF8|ConvertFrom-Json
if($d.run_id -cne $run -or $d.original_run_id -cne $originalRun -or $d.operation -cne 'Rollback' -or [guid]$d.vm_id -ne $id -or $d.expected_exit -ne 0 -or $d.request_sha256 -cne $requestPin -or $d.expectation_sha256 -cne $treePin){throw 'Exact admitted rollback enrollment required.'}
$vm=Get-VM -Id $id;$ids=@(Get-VMSnapshot -VM $vm|ForEach-Object {$_.Id.ToString()})
if($vm.State.ToString() -cne 'Running' -or $vm.MemoryStartup -ne 4GB -or $vm.DynamicMemoryEnabled -or @(Get-VMNetworkAdapter -VM $vm).Count -or $ids.Count -ne 46 -or @($prior.old_checkpoint_ids|Where-Object {$_ -notin $ids}).Count -or $vm.ParentSnapshotId -ne [guid]$prior.parent_id){throw 'Existing running rollback branch/all46 required before preserving47.'}
function Save-New([string]$Name,$Value){$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 20));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
$credential=Import-Clixml -LiteralPath (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$s=New-PSSession -VMId $id -Credential $credential
try{
    if($Phase -ceq 'Collect'){
        $receipt=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw -Encoding UTF8|ConvertFrom-Json
        if($receipt.run_id -cne $run -or $receipt.task_name -cne $task -or (Test-Path -LiteralPath (Join-Path $root 'native-payload-readback.json'))){throw 'Readback already collected or dispatch differs; never repeat.'}
        $complete=Invoke-Command -Session $s -ArgumentList $task,$receipt.output -ScriptBlock {param($Task,$Output);$ErrorActionPreference='Stop';if((Get-ScheduledTask -TaskName $Task).State.ToString() -ceq 'Running' -or (Get-ScheduledTaskInfo -TaskName $Task).LastTaskResult -ne 0){throw 'Readback is not terminal0.'};$v=Get-Content -LiteralPath $Output -Raw -Encoding UTF8|ConvertFrom-Json;if(-not $v.success -or $v.files.Count -ne 10 -or $v.scope -cne 'logical-stream-readback-only' -or $v.source_write_requests -ne 0 -or $v.post_mount_full_image_attested -or $v.stored_metadata_attested){throw 'Completed logical-only readback required.'};@{sha256=(Get-FileHash -LiteralPath $Output).Hash.ToLowerInvariant();success=$true;files=$v.files.Count;total_logical_bytes=$v.total_logical_bytes}}
        Copy-Item -FromSession $s -LiteralPath $receipt.output -Destination (Join-Path $root 'native-payload-readback.json')
        if((Get-FileHash -LiteralPath (Join-Path $root 'native-payload-readback.json')).Hash.ToLowerInvariant() -cne $complete.sha256){throw 'Readback archive differs.'}
        Save-New 'collected.json' @{success=$true;run_id=$run;task_name=$task;readback_sha256=$complete.sha256;files_verified=$complete.files;logical_bytes=$complete.total_logical_bytes;utc=[DateTime]::UtcNow.ToString('o')};$complete|ConvertTo-Json -Compress;return
    }
    if(Test-Path -LiteralPath $root){throw 'Readback has state; inspect without redispatch.'}
    $stage=Join-Path ([string]$d.guest_stage) 'native-readback';$output=Join-Path $stage 'native-payload-readback.json'
    $ready=Invoke-Command -Session $s -ArgumentList $d.task_name,$d.output_dir,$stage,$task,$run,$originalRun,$sourcePin,$requestPin,$treePin -ScriptBlock {
        param($RollbackTask,$RoleOutput,$Stage,$Task,$Run,$OriginalRun,$SourcePin,$RequestPin,$TreePin);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        if((Get-ScheduledTask -TaskName $RollbackTask).State.ToString() -ceq 'Running' -or (Get-ScheduledTaskInfo -TaskName $RollbackTask).LastTaskResult -ne 0 -or @(Get-CimInstance Win32_Process|Where-Object {$_.Name -in @('lab-recover-native-composite.exe','lab-convert-native-composite.exe','lab-verify-general-converted.exe','lab-general-refs-mutation.exe')}).Count){throw 'Actual rollback task terminal0 required before any source read.'}
        $result=Get-Content -LiteralPath (Join-Path $RoleOutput 'result.json') -Raw -Encoding UTF8|ConvertFrom-Json;$completion=Get-Content -LiteralPath (Join-Path $RoleOutput 'completion.json') -Raw -Encoding UTF8|ConvertFrom-Json;$execution=Get-Content -LiteralPath (Join-Path $RoleOutput 'execution.json') -Raw -Encoding UTF8|ConvertFrom-Json
        $request=Join-Path $RoleOutput 'request.json';$expected=Join-Path $RoleOutput 'expectation.json'
        if(-not $result.success -or $result.operation -cne 'rollback' -or -not $result.ntfs_rollback_completed -or -not $completion.success -or -not $completion.replay_closed -or $completion.mounted_filesystem -cne 'NTFS' -or $execution.expected_target_sha256 -cne $SourcePin -or $execution.result.target_sha256 -cne $SourcePin -or (Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant() -cne $RequestPin -or (Get-Item -LiteralPath $expected).Length -ne 29197 -or (Get-FileHash -LiteralPath $expected).Hash.ToLowerInvariant() -cne $TreePin){throw 'Exact original restoration/ABT/nativeNTFS/request/expectation proof required.'}
        $value=Get-Content -LiteralPath $request -Raw -Encoding UTF8|ConvertFrom-Json
        if($value.experiment_id -cne $OriginalRun -or $value.expected_tree_sha256 -cne $TreePin -or $value.comparison.source_sha256 -cne $SourcePin){throw 'Original949 request differs.'}
        if((Test-Path -LiteralPath $Stage) -or (Get-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue)){throw 'Readback task/stage already exists; never retry.'}
        @{request=$request;expectation=$expected;result_sha256=(Get-FileHash -LiteralPath (Join-Path $RoleOutput 'result.json')).Hash.ToLowerInvariant();completion_sha256=(Get-FileHash -LiteralPath (Join-Path $RoleOutput 'completion.json')).Hash.ToLowerInvariant();execution_sha256=(Get-FileHash -LiteralPath (Join-Path $RoleOutput 'execution.json')).Hash.ToLowerInvariant();role_output=$RoleOutput;rollback_task=$RollbackTask;source_original_sha256=$SourcePin;request_sha256=$RequestPin;expectation_sha256=$TreePin;run_id=$Run;original_run_id=$OriginalRun;stage=$Stage;output=(Join-Path $Stage 'native-payload-readback.json')}
    }
    New-Item -ItemType Directory -Path $root|Out-Null
    Save-New 'intent.json' @{run_id=$run;original_run_id=$originalRun;vm_id=$id.ToString();checkpoint_ids=$ids;scope='logical-stream-readback-only';source_write_requests=0;stored_metadata_attested=$false;post_mount_full_image_attested=$false;ready=$ready;utc=[DateTime]::UtcNow.ToString('o')}
    $configuration=[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes(($ready|ConvertTo-Json -Depth 10 -Compress)))
    $body=@'
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CONFIG__'))|ConvertFrom-Json
function Save-New([string]$Path,$Value){$f=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 12));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
try{
    if((Get-ScheduledTask -TaskName $c.rollback_task).State.ToString() -ceq 'Running' -or (Get-ScheduledTaskInfo -TaskName $c.rollback_task).LastTaskResult -ne 0 -or @(Get-CimInstance Win32_Process|Where-Object {$_.Name -in @('lab-recover-native-composite.exe','lab-convert-native-composite.exe','lab-verify-general-converted.exe','lab-general-refs-mutation.exe')}).Count){throw 'Rollback is not terminal0 or a native worker remains.'}
    foreach($name in @('result','completion','execution')){if((Get-FileHash -LiteralPath (Join-Path $c.role_output ($name+'.json'))).Hash.ToLowerInvariant() -cne $c.($name+'_sha256')){throw 'Completed rollback report changed.'}}
    if((Get-FileHash -LiteralPath $c.request).Hash.ToLowerInvariant() -cne $c.request_sha256 -or (Get-Item -LiteralPath $c.expectation).Length -ne 29197 -or (Get-FileHash -LiteralPath $c.expectation).Hash.ToLowerInvariant() -cne $c.expectation_sha256){throw 'Pinned original request/tree changed.'}
    $disk=Get-Disk -Number 1;$part=Get-Partition -DriveLetter F;$volume=Get-Volume -DriveLetter F
    if([guid]$disk.Guid -ne [guid]'1b191872-c372-41ee-a416-e18863996f54' -or $disk.IsBoot -or $disk.IsSystem -or $disk.IsOffline -or $disk.IsReadOnly -or $part.DiskNumber -ne 1 -or [guid]$part.Guid -ne [guid]'f06075a8-67a2-46b9-8fac-4af4da809617' -or $part.Offset -ne 16MB -or $part.Size -ne 52GB -or $volume.FileSystem -cne 'NTFS' -or $volume.AllocationUnitSize -ne 65536 -or $volume.FileSystemLabel -cne 'n2r-stream-source'){throw 'Current native F original partition/NTFS64K/label differs.'}
    $manifest=Get-Content -LiteralPath $c.expectation -Raw -Encoding UTF8|ConvertFrom-Json
    $rows=@($manifest.objects|Where-Object {-not $_.directory});if($manifest.profile -cne 'native-ordinary-tree-shadow-streaming-v2' -or $rows.Count -ne 10){throw 'Exact ten-stream source manifest required.'}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$buffer=[byte[]]::new(1MB);$files=@();$total=[long]0
    foreach($row in $rows){
        $components=@($row.path);if($components.Count -lt 1 -or $components.Count -gt 16 -or [long]$row.length -lt 0 -or [string]$row.sha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid bounded source stream manifest.'}
        $path='F:\'
        foreach($component in $components){$name=[string]$component;if([string]::IsNullOrEmpty($name) -or $name.Length -gt 255 -or $name -in @('.','..') -or $name.EndsWith('.') -or $name.EndsWith(' ') -or $name.IndexOfAny([char[]]'\/:<>"|?*') -ge 0 -or @($name.ToCharArray()|Where-Object {[char]::IsControl($_)}).Count){throw 'Source path escaped its manifest root.'};$path=Join-Path $path $name}
        if(-not [IO.Path]::GetFullPath($path).Equals($path,[StringComparison]::OrdinalIgnoreCase) -or -not $path.StartsWith('F:\',[StringComparison]::OrdinalIgnoreCase) -or -not $seen.Add($path)){throw 'Duplicate or noncanonical source path.'}
        $cursor='F:\';for($index=0;$index -lt $components.Count-1;$index++){$cursor=Join-Path $cursor $components[$index];$parent=Get-Item -LiteralPath $cursor -Force;if(-not $parent.PSIsContainer -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Source path traversed a reparse point or nondirectory.'}}
        $before=Get-Item -LiteralPath $path -Force;if($before.PSIsContainer -or ($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $before.Length -ne [long]$row.length){throw 'Source stream type/length differs.'}
        $file=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read,1MB,[IO.FileOptions]::SequentialScan)
        $hash=[Security.Cryptography.SHA256]::Create()
        try{
            if($file.Length -ne [long]$row.length -or -not [IO.Path]::GetFullPath($file.Name).Equals($path,[StringComparison]::OrdinalIgnoreCase)){throw 'Opened source stream path/length differs.'}
            $remaining=[long]$row.length;$read=[long]0
            while($remaining -gt 0){$count=[int][Math]::Min([long]$buffer.Length,$remaining);$n=$file.Read($buffer,0,$count);if($n -le 0){throw 'Source stream ended before manifest EOF.'};[void]$hash.TransformBlock($buffer,0,$n,$buffer,0);$remaining-=$n;$read+=$n}
            if($file.Read($buffer,0,1) -ne 0 -or $file.Length -ne [long]$row.length){throw 'Source stream EOF/length changed.'}
            [void]$hash.TransformFinalBlock([byte[]]::new(0),0,0);$pin=[BitConverter]::ToString($hash.Hash).Replace('-','').ToLowerInvariant()
            $after=Get-Item -LiteralPath $path -Force
            if($pin -cne $row.sha256 -or $after.PSIsContainer -or ($after.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $after.Length -ne $before.Length -or $after.CreationTimeUtc -ne $before.CreationTimeUtc -or $after.LastWriteTimeUtc -ne $before.LastWriteTimeUtc -or $after.FullName -cne $before.FullName){throw 'Source logical bytes or path/length stability differ.'}
            $files+=@{path=$path;components_utf8=$components;expected_record_number=$row.record_number;expected_sequence_number=$row.sequence_number;bytes=$read;sha256=$pin;length_before=$before.Length;length_after=$after.Length;eof_verified=$true;held_read_handle_excluded_writers_and_delete=$true};$total+=$read
        }finally{$hash.Dispose();$file.Dispose()}
    }
    $endDisk=Get-Disk -Number 1;$endPart=Get-Partition -DriveLetter F;$endVolume=Get-Volume -DriveLetter F
    if($total -ne [long]$manifest.logical_bytes -or [guid]$endDisk.Guid -ne [guid]$disk.Guid -or $endDisk.IsOffline -or $endDisk.IsReadOnly -or $endPart.DiskNumber -ne 1 -or [guid]$endPart.Guid -ne [guid]$part.Guid -or $endPart.Offset -ne $part.Offset -or $endPart.Size -ne $part.Size -or $endVolume.UniqueId -cne $volume.UniqueId -or $endVolume.FileSystem -cne 'NTFS' -or $endVolume.AllocationUnitSize -ne 65536 -or $endVolume.FileSystemLabel -cne 'n2r-stream-source'){throw 'Complete logical count or native F binding changed during readback.'}
    Save-New $c.output @{schema_version=1;kind='admitted-compact-native-ntfs-rollback-readback';success=$true;scope='logical-stream-readback-only';run_id=$c.run_id;original_run_id=$c.original_run_id;files=$files;files_verified=$files.Count;total_logical_bytes=$total;hash_buffer_bytes=1MB;paths_encoding='UTF-8 JSON';filesystem='NTFS';cluster_bytes=65536;native_volume_unique_id=$volume.UniqueId;source_original_image_hash_proved_before_mount=$c.source_original_sha256;request_sha256=$c.request_sha256;expectation_sha256=$c.expectation_sha256;result_sha256=$c.result_sha256;execution_sha256=$c.execution_sha256;completion_sha256=$c.completion_sha256;source_write_requests=0;stored_metadata_attested=$false;post_mount_full_image_attested=$false;power_loss_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')}
}catch{Save-New (Join-Path $c.stage 'failed.json') @{success=$false;scope='logical-stream-readback-only';error=$_.Exception.Message;automatic_retry=$false;source_write_requests=0;utc=[DateTime]::UtcNow.ToString('o')};exit 1}
'@
    $body=$body.Replace('__CONFIG__',$configuration)
    [IO.File]::WriteAllText((Join-Path $root 'guest-observer.ps1'),$body,[Text.UTF8Encoding]::new($false))
    $bodyPin=(Get-FileHash -LiteralPath (Join-Path $root 'guest-observer.ps1')).Hash.ToLowerInvariant();$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
    $command='-NoProfile -NonInteractive -EncodedCommand '+$encoded
    if($command.Length -ge 30000){throw 'Encoded observer command exceeds its reviewed bound; guest stage was not created.'}
    $dispatch=Invoke-Command -Session $s -ArgumentList $stage,$task,$command,$run,$bodyPin,$output -ScriptBlock {param($Stage,$Task,$Command,$Run,$BodyPin,$Output);$ErrorActionPreference='Stop';if($Command.Length -ge 30000){throw 'Encoded observer command exceeds its bound.'};if((Test-Path -LiteralPath $Stage) -or (Get-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue)){throw 'Observer already has state; never retry.'};New-Item -ItemType Directory -Path $Stage|Out-Null;Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $Command) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null;@{run_id=$Run;task_name=$Task;observer_source_sha256=$BodyPin;encoded_command_characters=$Command.Length;output=$Output;expected_exit=0;source_write_requests=0}}
    Save-New 'dispatch.json' $dispatch
    Invoke-Command -Session $s -ArgumentList $task -ScriptBlock {param($Task);if((Get-ScheduledTaskInfo -TaskName $Task).LastRunTime.Year -ge 2000){throw 'Observer ran already.'};Start-ScheduledTask -TaskName $Task}
    Save-New 'start.json' @{start_issued_once=$true;expected_exit=0;utc=[DateTime]::UtcNow.ToString('o')};$dispatch|ConvertTo-Json -Compress
}finally{Remove-PSSession $s}
