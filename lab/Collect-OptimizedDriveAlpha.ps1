# Archive closed receipts from actual optimized normal run2c0 only. No source,
# journal, packed/capture/ticket, image, VHDX, recovery or power actions exist.
[CmdletBinding()]param(
    [Parameter(Mandatory)][string]$DispatchPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$DispatchSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs'
$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$run='2c0a76e195f540218d60e98266f4e14d'
$case=Join-Path $base ('optimized-drive-alpha-20261029-'+$run)
$root=Join-Path $case 'closed-conversion'
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$mainPin='fb5548cc80a1de57e5a1c3c853a0ccfc43338515d00e15867305fa5f59c6079c'
$session=$null; $created=$false

function Need([bool]$Ok,[string]$Message){if(-not $Ok){throw $Message}}
function Hash([byte[]]$Bytes){$s=[Security.Cryptography.SHA256]::Create();try{[BitConverter]::ToString($s.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}finally{$s.Dispose()}}
function PinnedJson([string]$Path,[string]$Pin){
    $m=Get-Item -LiteralPath $Path -Force
    Need (-not $m.PSIsContainer -and -not ($m.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $m.Length -gt 0 -and $m.Length -le 1MB) 'Bounded ordinary host dispatch required.'
    $a=$m.Directory
    while($null -ne $a){Need (-not ($a.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Reparse host ancestry refused.';$a=$a.Parent}
    Need ((Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant() -ceq $Pin) 'Actual dispatch SHA differs.'
    Get-Content -LiteralPath $Path -Raw -Encoding UTF8|ConvertFrom-Json
}
function Save([string]$Name,$Value){
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 12))
    Need ($bytes.Length -le 1MB) 'Host receipt exceeds1MiB.'
    $f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
}
Need (-not (Test-Path -LiteralPath $root)) 'Closed archive has state; inspect without repeating collection.'
Need ([IO.Path]::GetFullPath($DispatchPath) -ceq (Join-Path $case 'dispatch.json')) 'Exact actual2c0 dispatch path required.'
$d=PinnedJson $DispatchPath $DispatchSha256
Need ($d.schema_version -eq 1 -and $d.kind -ceq 'optimized-public-drive-alpha-dispatch' -and $d.run_id -ceq $run -and [guid]$d.vm_id -eq $id -and [guid]$d.parent_id -eq [guid]'5125d335-09b4-4838-bc64-28b079e3f2b9' -and $d.task_name -ceq ('N2R-OptimizedDriveAlpha-'+$run) -and $d.guest_stage -ceq ('C:\ntfs2refs\optimized-drive-alpha-'+$run) -and $d.binary_sha256 -ceq $mainPin -and $d.binary_bytes -eq 7077376 -and $d.expected_exit -eq 0 -and ($d.argv -join '|') -ceq '--drive|F|--partition|2' -and $d.source_commit -ceq '2ff5f017c03977c5e6ba9d31ba64dc634bfa2fe7' -and $d.toolset_manifest_sha256 -ceq '230c08850b41bcab1defa0b81aa35406ea0760e25a4042657602d191e0065d6b' -and $d.manual_shadow_journal_binding -eq $false -and $d.source_admission_recreated -eq $false) 'Actual sealed fb5548 normal public-drive dispatch required.'
Need ((Get-FileHash -LiteralPath (Join-Path $case 'guest-wrapper.ps1')).Hash.ToLowerInvariant() -ceq $d.wrapper_sha256) 'Pinned original host wrapper differs.'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$configuration=Get-LabConfiguration -WorkspaceRoot $workspace
$capacity=Get-LabCapacity -Configuration $configuration
Need ($capacity.MaximumActualBytes -eq 329374052988 -and $capacity.MinimumFreeBytes -eq 17179869184) 'Fixed capacity epoch/16GiB floor differs.'
Assert-LabCapacity -Capacity $capacity -AdditionalBytes 16MB
$vm=Get-VM -Id $id -ErrorAction Stop
Need ($vm.Name -ceq 'ntfs2refs-streaming-v2-20261027' -and $vm.State.ToString() -ceq 'Running' -and $vm.ParentSnapshotId -eq [guid]$d.parent_id) 'Actual running originalVM/parent required.'

try{
    $session=New-PSSession -VMId $id -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')) -ErrorAction Stop
    $payload=$d|ConvertTo-Json -Depth 12 -Compress
    $text=Invoke-Command -Session $session -ArgumentList $payload -ScriptBlock {
        param($Payload)
        Set-StrictMode -Version Latest; $ErrorActionPreference='Stop'
        $d=$Payload|ConvertFrom-Json
        $held=[Collections.Generic.List[IO.FileStream]]::new()
        $documents=[Collections.Generic.List[object]]::new()
        $values=@{}; $pins=@{}; $state=@{total=[long]0;processes=@()}
        function Require([bool]$Ok,[string]$Message){if(-not $Ok){throw $Message}}
        function Idle{
            $task=Get-ScheduledTask -TaskName $d.task_name -ErrorAction Stop
            $info=Get-ScheduledTaskInfo -TaskName $d.task_name -ErrorAction Stop
            Require ($env:COMPUTERNAME -ceq 'N2R-WIN11' -and @($task).Count -eq 1 -and $task.State.ToString() -ceq 'Ready' -and $info.LastTaskResult -eq 0 -and $info.LastRunTime.Year -ge 2026) 'Actual public-drive task must be terminal0 before any collection.'
            Require (@($task.Actions).Count -eq 1 -and $task.Actions[0].Execute -ceq "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -and $task.Actions[0].Arguments -ceq ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $d.guest_stage 'wrapper.ps1')+'"') -and $task.Principal.UserId -in @('SYSTEM','S-1-5-18') -and $task.Principal.RunLevel.ToString() -ceq 'Highest' -and (Get-FileHash -LiteralPath (Join-Path $d.guest_stage 'wrapper.ps1')).Hash.ToLowerInvariant() -ceq $d.wrapper_sha256) 'Exact registered pinned SYSTEM wrapper required.'
            $tasks=@(Get-ScheduledTask -ErrorAction Stop)
            $state.processes=@(Get-CimInstance Win32_Process -ErrorAction Stop)
            Require (@($tasks|Where-Object {$_.TaskName -like 'N2R-*' -and $_.State.ToString() -notin @('Ready','Disabled')}).Count -eq 0 -and @($state.processes|Where-Object {$_.Name -match '\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count -eq 0) 'A project task/native worker remains active or unknown.'
        }
        function Collect([string]$Name,[string]$Path,[bool]$IsJson=$true){
            Require ($Path.StartsWith('C:\',[StringComparison]::OrdinalIgnoreCase) -and $Name -cmatch '\A[a-z-]+\.(json|log)\z' -and -not $pins.ContainsKey($Name)) 'Only the bounded closed C metadata allowlist may be archived.'
            $m=Get-Item -LiteralPath $Path -Force
            Require (-not $m.PSIsContainer -and -not ($m.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $m.Length -le 8MB -and (-not $IsJson -or ($m.Length -gt 0 -and $m.Length -le 4MB))) 'Bounded ordinary closed file required.'
            $a=$m.Directory
            while($null -ne $a){Require (-not ($a.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Reparse C metadata ancestry.';$a=$a.Parent}
            $state.total+=$m.Length;Require ($state.total -le 8MB) 'Closed metadata/log aggregate exceeds8MiB.'
            $file=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$held.Add($file)
            $bytes=[byte[]]::new([int]$m.Length);$at=0
            while($at -lt $bytes.Length){$count=$file.Read($bytes,$at,$bytes.Length-$at);Require ($count -gt 0) 'Short closed file read.';$at+=$count}
            Require ($file.Length -eq $bytes.Length) 'Closed file length changed.'
            $sha=[Security.Cryptography.SHA256]::Create()
            try{$pin=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
            $pins[$Name]=$pin
            $values[$Name]=if($IsJson){[Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xfeff)|ConvertFrom-Json}else{[Text.UTF8Encoding]::new($false,$true).GetString($bytes)}
            $documents.Add(@{name=$Name;source=$Path;bytes=$bytes.Length;sha256=$pin;bytes_base64=[Convert]::ToBase64String($bytes)})
        }
        try{
            Idle
            # Only the four small terminal prerequisites are opened before the
            # actual process identity/exit0 result is established.
            foreach($name in @('wrapper-worker.json','native-process.json','native-terminal.json','wrapper-result.json')){
                $path=Join-Path $d.guest_stage $name
                $m=Get-Item -LiteralPath $path -Force
                Require ($m.Length -gt 0 -and $m.Length -le 1MB) 'Small closed terminal prerequisite required.'
                Collect $name $path
            }
            $worker=$values['wrapper-worker.json'];$native=$values['native-process.json'];$terminal=$values['native-terminal.json'];$wrapper=$values['wrapper-result.json']
            Require ($worker.run_id -ceq $d.run_id -and $worker.pid -gt 0 -and $worker.creation_ms -gt 0 -and $native.pid -gt 0 -and $native.creation_ms -gt 0 -and $native.parent_pid -eq $worker.pid -and $native.binary -ceq (Join-Path $d.guest_stage 'ntfs2refs.exe') -and $native.binary_sha256 -ceq $d.binary_sha256 -and $native.expected_exit -eq 0 -and $native.process_handle_retained_before_wait -eq $true -and ($native.argv -join '|') -ceq '--drive|F|--partition|2' -and $terminal.native_exit_observed -eq $true -and $null -ne $terminal.native_exit -and $terminal.native_exit -eq 0 -and $terminal.expected_exit -eq 0 -and $wrapper.schema_version -eq 1 -and $wrapper.kind -ceq 'optimized-public-drive-alpha-observation' -and $wrapper.success -eq $true -and $wrapper.run_id -ceq $d.run_id -and $wrapper.native_exit_observed -eq $true -and $wrapper.native_exit -eq 0 -and $wrapper.barrier -ceq 'HND' -and $wrapper.native_objects -eq 15 -and $wrapper.complete_native_hashes -eq 10 -and $wrapper.actual_success_path_printed -eq $true -and $wrapper.label_and_mount_verified -eq $true -and $wrapper.source_admission_recreated_by_wrapper -eq $false -and $wrapper.manual_shadow_journal_binding -eq $false) 'Actual retained native process/argv/exit0/HND/native15/10 completion differs.'
            foreach($identity in @($worker,$native)){foreach($active in @($state.processes|Where-Object ProcessId -eq $identity.pid)){Require (([DateTimeOffset]$active.CreationDate).ToUnixTimeMilliseconds() -ne [long]$identity.creation_ms) 'Actual native/wrapper creation remains alive.'}}
            Require (-not (Test-Path -LiteralPath (Join-Path $d.guest_stage 'wrapper-failed.json'))) 'Wrapper failure must not be hidden by an archive.'
            $records=[string]$wrapper.conversion_records
            Require ($records -cmatch '\AC:\\ProgramData\\ntfs2refs\\runs\\[0-9a-f]{32}\\conversion\z' -and $wrapper.engine_run_id -ceq [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($records))) 'Actual complete conversion path/engine run required.'
            foreach($name in @('stdout.log','stderr.log')){Collect $name (Join-Path $d.guest_stage $name) $false}
            Require ($pins['stdout.log'] -ceq $terminal.stdout.sha256 -and $pins['stderr.log'] -ceq $terminal.stderr.sha256 -and $terminal.stdout.truncated -eq $false) 'Original complete native log pins differ.'
            $success=[regex]::Matches($values['stdout.log'],'(?m)^Conversion completed[.] Recovery records: (.+?)[ \t]*\r?$')
            $published=[regex]::Matches($values['stdout.log'],'(?m)^Recovery directory: (.+?)[ \t]*\r?$')
            Require ($success.Count -eq 1 -and $published.Count -eq 1 -and $success[0].Groups[1].Value -ceq $records -and $published[0].Groups[1].Value -ceq $records) 'Actual unique complete success/native recovery output differs.'
            foreach($name in @('request.json','expectation.json','result.json','finalization.json')){Collect $name (Join-Path $records $name)}
            Collect 'managed-shadow.json' (Join-Path ([IO.Path]::GetDirectoryName($records)) 'managed-shadow.json')
            Require ($documents.Count -eq 11 -and -not (Test-Path -LiteralPath (Join-Path $records 'failed.json'))) 'Exactly the requested11 closed files and no conversion failure required.'
            $request=$values['request.json'];$expected=$values['expectation.json'];$result=$values['result.json'];$final=$values['finalization.json'];$managed=$values['managed-shadow.json']
            Require ($pins['request.json'] -ceq $wrapper.request_sha256 -and $pins['expectation.json'] -ceq $wrapper.expectation_sha256 -and $pins['expectation.json'] -ceq $request.expected_tree_sha256 -and $pins['result.json'] -ceq $wrapper.result_sha256 -and $pins['finalization.json'] -ceq $wrapper.finalization_sha256 -and $request.experiment_id -ceq $wrapper.engine_run_id -and $request.source_resource_profile -ceq 'experimental_streaming_tree_v2' -and $request.pair.source.disk_number -eq 1 -and [guid]$request.pair.source.identity.disk_guid -eq [guid]'1b191872-c372-41ee-a416-e18863996f54' -and [guid]$request.pair.source.identity.partition_guid -eq [guid]'f06075a8-67a2-46b9-8fac-4af4da809617' -and $request.pair.source.identity.partition_bytes -eq 52GB -and $result.kind -ceq 'experimental-certificate-backed-composite-conversion' -and $result.success -eq $true -and $result.source_admitted -eq $true -and $result.rollback_closed -eq $true -and $result.expected_tree_sha256 -ceq $request.expected_tree_sha256) 'Closed original request/expectation/result associations differ; no admission is created here.'
            Require ($final.success -eq $true -and $null -eq $final.error -and $final.rollback_closed -eq $true -and $final.handoff.handoff_recorded -eq $true -and $final.handoff.operation -ceq 'handoff-recorded' -and $final.handoff.target_sha256 -ceq $request.comparison.shadow_sha256 -and $wrapper.premount_target_sha256 -ceq $request.comparison.shadow_sha256 -and $final.mount_paths_preserved -eq $true -and 'F:\' -in @($final.mount_paths_after.paths) -and $final.label_restoration.success -eq $true -and $final.label_restoration.readback_matches -eq $true) 'Actual typed HND/label/F mount completion required.'
            $objects=@($final.native.native.objects);$hashes=0;Require ($objects.Count -eq 15 -and @($expected.objects).Count -eq 15) 'Complete native15 expected objects required.'
            foreach($object in $expected.objects){$found=@($objects|Where-Object {($_.components -join '\') -ceq ($object.path -join '\')});Require ($found.Count -eq 1) 'Native expected object missing/duplicate.';if(-not $object.directory){Require ($found[0].logical_sha256 -ceq $object.sha256) 'Native complete logical hash differs.';$hashes++}}
            Require ($hashes -eq 10 -and $managed.schema_version -eq 1 -and $managed.kind -ceq 'managed-native-shadow-location' -and $managed.path -ceq $wrapper.managed_shadow_path -and $managed.virtual_disk_id -ceq $wrapper.managed_shadow_id -and [guid]$managed.binding.identity.disk_guid -eq [guid]$request.pair.shadow.identity.disk_guid -and [guid]$managed.binding.identity.partition_guid -eq [guid]$request.pair.shadow.identity.partition_guid) 'Native10 hashes/current automatic managed receipt differs.'
            Idle
            @{schema_version=1;kind='optimized-drive-alpha-closed-observation';success=$true;run_id=$d.run_id;vm_id=$d.vm_id;binary_sha256=$d.binary_sha256;actual_task_result=0;native_exit=0;native_exit_observed=$true;workers_absent=$true;conversion_records=$records;engine_run_id=$wrapper.engine_run_id;barrier='HND';native_objects=15;complete_native_hashes=10;documents=$documents.ToArray();aggregate_bytes=$state.total;source_journal_packed_capture_ticket_images_opened=$false;power_checkpoint_attribute_actions=$false;source_admission_recreated=$false;raw_recovery_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 9 -Compress
        }finally{for($i=$held.Count-1;$i -ge 0;$i--){$held[$i].Dispose()}}
    }
    Need ($text -is [string] -and [Text.UTF8Encoding]::new($false).GetByteCount($text) -le 12MB) 'Bounded closed JSON transport required.'
    $record=$text|ConvertFrom-Json
    Need ($record.success -eq $true -and $record.run_id -ceq $run -and @($record.documents).Count -eq 11 -and $record.aggregate_bytes -le 8MB) 'Complete original11-file closed observation required.'
    New-Item -ItemType Directory -Path $root -ErrorAction Stop|Out-Null; $created=$true
    $pins=@();$total=[long]0
    foreach($document in $record.documents){
        Need ($document.name -cmatch '\A[a-z-]+\.(json|log)\z') 'Invalid archive leaf.'
        $bytes=[Convert]::FromBase64String($document.bytes_base64);$total+=$bytes.Length
        Need ($bytes.Length -eq $document.bytes -and $total -le 8MB -and (Hash $bytes) -ceq $document.sha256) 'Transported original bytes differ or exceed bound.'
        $file=[IO.File]::Open((Join-Path $root $document.name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
        Need ((Get-FileHash -LiteralPath (Join-Path $root $document.name)).Hash.ToLowerInvariant() -ceq $document.sha256) 'Archived byte readback SHA differs.'
        $pins+=@{name=$document.name;source=$document.source;bytes=$document.bytes;sha256=$document.sha256}
    }
    $record.documents=$pins
    $record|Add-Member -NotePropertyName dispatch_sha256 -NotePropertyValue $DispatchSha256
    Save 'receipt.json' $record
    Get-Content -LiteralPath (Join-Path $root 'receipt.json') -Raw
}catch{if($created -and -not (Test-Path -LiteralPath (Join-Path $root 'failed.json'))){Save 'failed.json' @{success=$false;run_id=$run;error=$_.Exception.ToString();automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')}};throw}
finally{if($null -ne $session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
