# Default (allocation-bounded) public drive conversion launcher for a sealed HEAD build; derived from Start-HeadDriveMeasurement.ps1.
# Requires a build where allocation-bounded is the default (no mode flag is passed).
# Grants no admission, qualification or recovery authority. The frozen launcher is unchanged.
# Future normal public drive conversion. Root restores/boots the selected NTFS
# checkpoint separately. The main executable owns all admission and storage work.
[CmdletBinding()]param(
    [Parameter(Mandatory)][string]$ToolsetManifest,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ToolsetManifestSha256,
    [Parameter(Mandatory)][guid]$ExpectedParent,
    [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds,
    [Parameter(Mandatory)][string]$NtfsReceiptPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$NtfsReceiptSha256,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$MainSha256,
    [Parameter(Mandatory)][ValidateRange(1,67108864)][int]$MainBytes,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs'
$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$mainPin=$MainSha256
$run=[guid]::NewGuid().ToString('N')
$root=Join-Path $base ('alloc-drive-20261029-'+$run)
$stage='C:\ntfs2refs\alloc-drive-'+$run
$task='N2R-AllocDrive-'+$run
$session=$null; $created=$false

function Need([bool]$Ok,[string]$Message){if(-not $Ok){throw $Message}}
function Ordinary([string]$Path){
    $m=Get-Item -LiteralPath $Path -Force
    Need (-not $m.PSIsContainer -and -not ($m.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Ordinary host file required.'
    $a=$m.Directory
    while($null -ne $a){Need (-not ($a.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Reparse host ancestry refused.'; $a=$a.Parent}
    $m
}
function Json([string]$Path,[string]$Pin){
    $m=Ordinary $Path
    Need ($m.Length -gt 0 -and $m.Length -le 1MB -and (Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant() -ceq $Pin) 'Bounded pinned closed host JSON required.'
    Get-Content -LiteralPath $Path -Raw -Encoding UTF8|ConvertFrom-Json
}
function Save([string]$Name,$Value){
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14))
    Need ($bytes.Length -le 1MB) 'Host receipt exceeds1MiB.'
    $f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
}
function Host-Guard{
    $vm=Get-VM -Id $id -ErrorAction Stop
    $all=@(Get-VMSnapshot -VM $vm -ErrorAction Stop); $actual=@($all.Id|ForEach-Object {$_.ToString('D')})
    Need ($vm.Name -ceq 'ntfs2refs-streaming-v2-20261027' -and $vm.State.ToString() -ceq 'Running' -and $vm.ParentSnapshotId -eq $ExpectedParent -and $vm.MemoryStartup -eq 4GB -and $vm.MemoryAssigned -eq 4GB -and -not $vm.DynamicMemoryEnabled -and (Get-VMProcessor -VM $vm -ErrorAction Stop).Count -eq 4 -and @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop).Count -eq 0 -and $actual.Count -eq $ids.Count -and @($ids|Where-Object {$_ -notin $actual}).Count -eq 0) 'Root must already boot the supplied NTFS parent with the exact supplied checkpoint set/4GiB/4CPU/noNIC.'
}

try{
    $ids=@($ExpectedCheckpointIds|ForEach-Object {$_.ToString('D')})
    Need ($ExpectedParent -ne [guid]::Empty -and $ids.Count -ge 2 -and $ids.Count -le 16 -and @($ids|Sort-Object -Unique).Count -eq $ids.Count -and $ExpectedParent.ToString('D') -in $ids -and [guid]::Empty.ToString('D') -notin $ids) 'Explicit distinct current checkpoint IDs including the actual parent required.'
    $receiptPath=[IO.Path]::GetFullPath($NtfsReceiptPath)
    Need ($receiptPath -ceq $NtfsReceiptPath -and $receiptPath.StartsWith(($base+'\'),[StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($receiptPath) -ceq 'receipt.json' -and [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($receiptPath)) -ceq 'closed-recovery') 'Actual closed public rollback receipt path required.'
    $ntfs=Json $receiptPath $NtfsReceiptSha256
    Need ($ntfs.success -eq $true -and $ntfs.operation -ceq 'Rollback' -and [guid]$ntfs.vm_id -eq $id -and $ntfs.native_exit_observed -eq $true -and $null -ne $ntfs.native_exit -and $ntfs.native_exit -eq 0 -and $ntfs.workers_absent -eq $true -and $ntfs.barrier -ceq 'ABT' -and $ntfs.raw_recovery_authorized -eq $false) 'Actual observed native0/ABT/idle rollback receipt required; it grants no fresh admission.'
    $closed=[IO.Path]::GetDirectoryName($receiptPath); $documents=@{}
    foreach($document in $ntfs.documents){Need ($document.name -cmatch '\A[a-z-]+\.(json|log)\z' -and -not $documents.ContainsKey($document.name)) 'Invalid/duplicate closed archive leaf.'; $documents[$document.name]=$document}
    $values=@{}
    foreach($name in @('completion.json','execution.json','request.json')){Need ($documents.ContainsKey($name)) 'Closed rollback prerequisite missing.'; $values[$name]=Json (Join-Path $closed $name) $documents[$name].sha256}
    $done=$values['completion.json']; $execution=$values['execution.json']; $request=$values['request.json']
    Need ($done.success -eq $true -and $null -eq $done.error -and $done.replay_closed -eq $true -and $done.mounted_filesystem -ceq 'NTFS' -and $done.marker.operation -ceq 'ntfs-rollback-complete' -and $done.marker.target_sha256 -ceq $request.comparison.source_sha256 -and $execution.expected_target_sha256 -ceq $request.comparison.source_sha256 -and $execution.result.target_sha256 -ceq $request.comparison.source_sha256 -and $request.pair.source.disk_number -eq 1 -and [guid]$request.pair.source.identity.disk_guid -eq [guid]'1b191872-c372-41ee-a416-e18863996f54' -and [guid]$request.pair.source.identity.partition_guid -eq [guid]'f06075a8-67a2-46b9-8fac-4af4da809617' -and $request.pair.source.identity.partition_offset -eq 16MB -and $request.pair.source.identity.partition_bytes -eq 52GB) 'Closed exact-original ABT/native NTFS source identity differs.'

    $manifestPath=[IO.Path]::GetFullPath($ToolsetManifest)
    $toolsetDir=[IO.Path]::GetDirectoryName($manifestPath)
    Need ([IO.Path]::GetFileName($manifestPath) -ceq 'manifest.json' -and [IO.Path]::GetDirectoryName($toolsetDir) -ceq $base -and [IO.Path]::GetFileName($toolsetDir) -cmatch '\Ahead-drive-tools-[0-9a-z]+(?:-[0-9a-z]+)*\z') 'HEAD measurement toolset directly under the lab base required.'
    $manifest=Json $manifestPath $ToolsetManifestSha256
    Need ($manifest.schema_version -eq 1 -and $manifest.kind -ceq 'head-drive-toolset' -and $manifest.source_commit -ceq $SourceCommit -and @($manifest.tools).Count -eq 3) 'Head toolset provenance required; no inherited native qualification.'
    $rows=@($manifest.tools|Where-Object name -CEQ 'ntfs2refs.exe'); Need ($rows.Count -eq 1) 'One sealed public executable required.'; $tool=$rows[0]
    Need ($tool.path -ceq (Join-Path ([IO.Path]::GetDirectoryName($manifestPath)) 'ntfs2refs.exe') -and $tool.sha256 -ceq $mainPin -and $tool.bytes -eq $MainBytes -and (Ordinary $tool.path).Length -eq $tool.bytes -and (Get-FileHash -LiteralPath $tool.path).Hash.ToLowerInvariant() -ceq $mainPin) 'Actual sealed HEAD public main differs.'
    Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
    $configuration=Get-LabConfiguration -WorkspaceRoot $workspace; $capacity=Get-LabCapacity -Configuration $configuration
    Need ($capacity.MaximumActualBytes -eq 329374052988 -and $capacity.MinimumFreeBytes -eq 17179869184) 'Fixed50GB capacity epoch/16GiB floor differs.'
    Assert-LabCapacity -Capacity $capacity -AdditionalBytes 7GB
    Host-Guard; Need (-not (Test-Path -LiteralPath $root)) 'Fresh host case required.'
    New-Item -ItemType Directory -Path $root -ErrorAction Stop|Out-Null; $created=$true
    $c=@{run_id=$run;stage=$stage;task=$task;main_sha256=$mainPin;main_bytes=$tool.bytes}
    Save 'intent.json' @{schema_version=1;kind='optimized-drive-alpha-intent';run_id=$run;vm_id=$id.ToString();parent_id=$ExpectedParent.ToString();checkpoint_ids=$ids;toolset_manifest=$manifestPath;toolset_manifest_sha256=$ToolsetManifestSha256;source_commit=$manifest.source_commit;tool=$tool;ntfs_receipt_path=$receiptPath;ntfs_receipt_sha256=$NtfsReceiptSha256;ntfs_receipt_grants_source_admission=$false;capacity=$capacity;forecast_bytes=7GB;forecast_is_not_reservation=$true;public_argv=@('--drive','F','--partition','2');stdin='yes CRLF';manual_shadow_journal_binding=$false;source_admission_recreated=$false;power_checkpoint_cleanup_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')}
    $body=@'
Set-StrictMode -Version Latest; $ErrorActionPreference='Stop'
$c=[Text.UTF8Encoding]::new($false).GetString([Convert]::FromBase64String('__CONFIG__'))|ConvertFrom-Json
$phase='preflight'; $process=$null; $nativeExit=$null
function Need([bool]$Ok,[string]$Message){if(-not $Ok){throw $Message}}
function Save([string]$Name,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14));Need ($bytes.Length -le 1MB) 'Wrapper receipt exceeds1MiB.';$f=[IO.File]::Open((Join-Path $c.stage $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Json([string]$Path){Need ($Path.StartsWith('C:\',[StringComparison]::OrdinalIgnoreCase) -and $Path.EndsWith('.json',[StringComparison]::Ordinal)) 'Closed C JSON only.';$m=Get-Item -LiteralPath $Path -Force;Need (-not $m.PSIsContainer -and -not ($m.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $m.Length -gt 0 -and $m.Length -le 4MB) 'Bounded ordinary closed C JSON required.';$a=$m.Directory;while($null -ne $a){Need (-not ($a.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Reparse C metadata ancestry.';$a=$a.Parent};Get-Content -LiteralPath $Path -Raw -Encoding UTF8|ConvertFrom-Json}
function Idle{$tasks=@(Get-ScheduledTask -ErrorAction Stop);$processes=@(Get-CimInstance Win32_Process -ErrorAction Stop);Need (@($tasks|Where-Object {$_.TaskName -like 'N2R-*' -and $_.TaskName -cne $c.task -and $_.State.ToString() -notin @('Ready','Disabled')}).Count -eq 0 -and @($processes|Where-Object {$_.Name -match '\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count -eq 0) 'Another project task/process is active or unknown.'}
function Source([string]$Filesystem){$d=Get-Disk -Number 1 -ErrorAction Stop;$p=Get-Partition -DiskNumber 1 -PartitionNumber 2 -ErrorAction Stop;$v=$p|Get-Volume -ErrorAction Stop;$cluster=if($Filesystem -ceq 'NTFS'){65536}else{4096};Need ([guid]$d.Guid -eq [guid]'1b191872-c372-41ee-a416-e18863996f54' -and $d.Size -eq 64GB -and -not $d.IsOffline -and -not $d.IsReadOnly -and -not $d.IsBoot -and -not $d.IsSystem -and [guid]$p.Guid -eq [guid]'f06075a8-67a2-46b9-8fac-4af4da809617' -and $p.Offset -eq 16MB -and $p.Size -eq 52GB -and 'F:\' -in @($p.AccessPaths) -and $v.FileSystem -ceq $Filesystem -and $v.AllocationUnitSize -eq $cluster -and $v.FileSystemLabel -ceq 'n2r-stream-source' -and (Get-Partition -DriveLetter C -ErrorAction Stop).DiskNumber -eq 0) 'Exact source1/F/GPT/52GiB/filesystem/label or OS0 differs.'}
function Protected{$g=Get-Disk -Number 4 -ErrorAction Stop;$gp=Get-Partition -DriveLetter G -ErrorAction Stop;$gv=$gp|Get-Volume -ErrorAction Stop;$old=Get-Disk -Number 5 -ErrorAction Stop;Need ([guid]$g.Guid -eq [guid]'e1f3b9d3-979f-4123-9fee-399640c25092' -and -not $g.IsOffline -and -not $g.IsReadOnly -and $gp.DiskNumber -eq 4 -and $gv.FileSystem -ceq 'ReFS' -and $gv.AllocationUnitSize -eq 4096 -and [guid]$old.Guid -eq [guid]'ad077674-6305-4767-a2aa-6ded3b707e36' -and $old.IsOffline -and $old.IsReadOnly) 'Preserved G4/shadow5 differs.'}
function Log([string]$Path){$m=Get-Item -LiteralPath $Path -Force;Need (-not $m.PSIsContainer -and -not ($m.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $m.Length -le 8MB) 'Bounded native log required; preserve without retry.';$r=[IO.StreamReader]::new($Path);try{$chars=[char[]]::new(65536);$count=$r.ReadBlock($chars,0,$chars.Length);@{path=$Path;bytes=$m.Length;sha256=(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant();text=[string]::new($chars,0,$count);truncated=($r.Peek() -ne -1)}}finally{$r.Dispose()}}
try{
    Idle; Source 'NTFS'; Protected
    $disks=@(Get-Disk -ErrorAction Stop); Need ($env:COMPUTERNAME -ceq 'N2R-WIN11' -and $disks.Count -eq 6 -and @($disks|Where-Object Number -ge 6).Count -eq 0) 'Owning guest with old managed6 absent required.'
    $binary=Join-Path $c.stage 'ntfs2refs.exe';Need ((Get-Item -LiteralPath $binary).Length -eq $c.main_bytes -and (Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant() -ceq $c.main_sha256) 'Frozen public main differs.'
    Save 'wrapper-worker.json' @{run_id=$c.run_id;pid=$PID;creation_ms=([DateTimeOffset](Get-Process -Id $PID).StartTime).ToUnixTimeMilliseconds();utc=[DateTime]::UtcNow.ToString('o')}
    $cli=@('--drive','F','--partition','2');$stdin=Join-Path $c.stage 'stdin-yes.txt';$f=[IO.File]::Open($stdin,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$bytes=[Text.Encoding]::ASCII.GetBytes("yes`r`n");$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
    $stdout=Join-Path $c.stage 'stdout.log';$stderr=Join-Path $c.stage 'stderr.log';$phase='public-drive-conversion'
    Save 'native-dispatch-intent.json' @{binary=$binary;binary_sha256=$c.main_sha256;argv=$cli;stdin_file=$stdin;expected_exit=0;utc=[DateTime]::UtcNow.ToString('o')}
    $process=Start-Process -FilePath $binary -ArgumentList '--drive F --partition 2' -WorkingDirectory $c.stage -RedirectStandardInput $stdin -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
    $null=$process.Handle
    Save 'native-process.json' @{pid=$process.Id;creation_ms=([DateTimeOffset]$process.StartTime).ToUnixTimeMilliseconds();parent_pid=$PID;binary=$binary;binary_sha256=$c.main_sha256;argv=$cli;stdin_file=$stdin;expected_exit=0;process_handle_retained_before_wait=$true;utc=[DateTime]::UtcNow.ToString('o')}
    $process.WaitForExit();$process.Refresh();$nativeExit=$process.ExitCode;$out=Log $stdout;$err=Log $stderr
    Save 'native-terminal.json' @{native_exit_observed=($null -ne $nativeExit);native_exit=$nativeExit;expected_exit=0;stdout=$out;stderr=$err;utc=[DateTime]::UtcNow.ToString('o')}
    Need ($null -ne $nativeExit -and $nativeExit -eq 0 -and -not $out.truncated) 'Actual public native0/complete stdout required; no retry or fallback.'
    Idle; Protected; $phase='closed-native-conversion-evidence'
    $success=[regex]::Matches($out.text,'(?m)^Conversion completed[.] Recovery records: (C:\\ProgramData\\ntfs2refs\\runs\\[0-9a-f]{32}\\conversion)[ \t]*\r?$')
    $published=[regex]::Matches($out.text,'(?m)^Recovery directory: (C:\\ProgramData\\ntfs2refs\\runs\\[0-9a-f]{32}\\conversion)[ \t]*\r?$')
    Need ($success.Count -eq 1 -and $published.Count -eq 1 -and $success[0].Groups[1].Value -ceq $published[0].Groups[1].Value) 'One actual complete success path and matching recovery directory required.'
    $records=$success[0].Groups[1].Value;$runRoot=[IO.Path]::GetDirectoryName($records);$engine=[IO.Path]::GetFileName($runRoot)
    $result=Json (Join-Path $records 'result.json');$final=Json (Join-Path $records 'finalization.json');$expected=Json (Join-Path $records 'expectation.json');$devices=Json (Join-Path $runRoot 'devices.json');$managed=Json (Join-Path $runRoot 'managed-shadow.json');$plan=Json (Join-Path $records 'selected-plan.json')
    $expectationSha=(Get-FileHash -LiteralPath (Join-Path $records 'expectation.json')).Hash.ToLowerInvariant()
    Need (-not (Test-Path -LiteralPath (Join-Path $records 'failed.json')) -and $result.kind -ceq 'experimental-allocation-bounded-conversion' -and $result.success -eq $true -and $result.source_admitted -eq $true -and $result.rollback_closed -eq $true -and $result.free_space_contents_compared -eq $false -and $result.recovery_bundle_sha256 -cmatch '\A[0-9a-f]{64}\z' -and $result.expected_tree_sha256 -ceq $expectationSha -and $devices.experiment_id -ceq $engine -and $devices.source_resource_profile -ceq 'experimental_streaming_tree_v2' -and $devices.pair.source.disk_number -eq 1 -and [guid]$devices.pair.source.identity.disk_guid -eq [guid]'1b191872-c372-41ee-a416-e18863996f54' -and [guid]$devices.pair.source.identity.partition_guid -eq [guid]'f06075a8-67a2-46b9-8fac-4af4da809617' -and $devices.pair.source.identity.partition_bytes -eq 52GB -and @($plan.ranges).Count -eq $result.selected_ranges) 'Actual allocation-bounded result/devices/expected tree differs.'
    Need ($final.success -eq $true -and $null -eq $final.error -and $final.rollback_closed -eq $true -and $final.mount_paths_preserved -eq $true -and 'F:\' -in @($final.mount_paths_after.paths) -and $final.label_restoration.success -eq $true -and $final.label_restoration.readback_matches -eq $true) 'Actual native label/mount completion required.'
    $objects=@($final.native.native.objects);Need ($objects.Count -eq 15 -and @($expected.objects).Count -eq 15) 'Complete native15 required.';$hashes=0
    foreach($object in $expected.objects){$found=@($objects|Where-Object {($_.components -join '\') -ceq ($object.path -join '\')});Need ($found.Count -eq 1) 'Native expected object missing/duplicate.';if(-not $object.directory){Need ($found[0].logical_sha256 -ceq $object.sha256) 'Native complete logical hash differs.';$hashes++}}
    Need ($hashes -eq 10 -and $managed.kind -ceq 'managed-native-shadow-location' -and [guid]$managed.binding.identity.disk_guid -eq [guid]$devices.pair.shadow.identity.disk_guid -and [guid]$managed.binding.identity.partition_guid -eq [guid]$devices.pair.shadow.identity.partition_guid) 'Complete native10 hashes/current staging location required.'
    Source 'ReFS'; Idle; Protected
    Save 'wrapper-result.json' @{schema_version=1;kind='allocation-bounded-public-drive-observation';success=$true;run_id=$c.run_id;engine_run_id=$engine;native_exit_observed=$true;native_exit=$nativeExit;argv=$cli;conversion_records=$records;native_objects=15;complete_native_hashes=10;label_and_mount_verified=$true;selected_ranges=$result.selected_ranges;selected_bytes=$result.selected_bytes;journal_bytes=$result.journal_bytes;free_space_contents_compared=$false;result_sha256=(Get-FileHash -LiteralPath (Join-Path $records 'result.json')).Hash.ToLowerInvariant();finalization_sha256=(Get-FileHash -LiteralPath (Join-Path $records 'finalization.json')).Hash.ToLowerInvariant();expectation_sha256=$expectationSha;production_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')}
}catch{Save 'wrapper-failed.json' @{success=$false;run_id=$c.run_id;phase=$phase;native_exit_observed=($null -ne $nativeExit);native_exit=$nativeExit;error=$_.Exception.ToString();automatic_retry_recovery_restore_cleanup=$false;worker_termination_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')};throw}
finally{if($null -ne $process){$process.Dispose()}}
'@
    $body=$body.Replace('__CONFIG__',[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes(($c|ConvertTo-Json -Depth 6 -Compress))))
    $wrapperPath=Join-Path $root 'guest-wrapper.ps1';$bytes=[Text.UTF8Encoding]::new($false).GetBytes($body);$file=[IO.File]::Open($wrapperPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()};$wrapperPin=(Get-FileHash -LiteralPath $wrapperPath).Hash.ToLowerInvariant()
    $session=New-PSSession -VMId $id -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')) -ErrorAction Stop
    $ready=Invoke-Command -Session $session -ArgumentList $stage,$task -ScriptBlock {param($Stage,$Task)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        $tasks=@(Get-ScheduledTask -ErrorAction Stop);$processes=@(Get-CimInstance Win32_Process -ErrorAction Stop);$disks=@(Get-Disk -ErrorAction Stop)
        if($env:COMPUTERNAME -cne 'N2R-WIN11' -or (Test-Path -LiteralPath $Stage) -or @($tasks|Where-Object TaskName -CEQ $Task).Count -or @($tasks|Where-Object {$_.TaskName -like 'N2R-*' -and $_.State.ToString() -notin @('Ready','Disabled')}).Count -or @($processes|Where-Object {$_.Name -match '\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count -or $disks.Count -ne 6 -or @($disks|Where-Object Number -ge 6).Count){throw 'Fresh idle owning guest with old managed6 absent required.'}
        $source=Get-Disk -Number 1 -ErrorAction Stop;$partition=Get-Partition -DriveLetter F -ErrorAction Stop;$volume=$partition|Get-Volume -ErrorAction Stop
        if([guid]$source.Guid -ne [guid]'1b191872-c372-41ee-a416-e18863996f54' -or $source.IsOffline -or $source.IsReadOnly -or $source.IsBoot -or $source.IsSystem -or $partition.DiskNumber -ne 1 -or $partition.PartitionNumber -ne 2 -or [guid]$partition.Guid -ne [guid]'f06075a8-67a2-46b9-8fac-4af4da809617' -or $partition.Offset -ne 16MB -or $partition.Size -ne 52GB -or $volume.FileSystem -cne 'NTFS' -or $volume.AllocationUnitSize -ne 65536 -or $volume.FileSystemLabel -cne 'n2r-stream-source'){throw 'Actual restored source1/F/NTFS64K52GiB differs.'}
        $a=Get-Item -LiteralPath 'C:\ntfs2refs' -Force
        while($null -ne $a){if($a.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse C stage ancestry.'};$a=$a.Parent}
        New-Item -ItemType Directory -Path $Stage -ErrorAction Stop|Out-Null
        @{fresh_stage=$Stage;source_filesystem='NTFS';source_cluster_bytes=65536;old_managed6_absent=$true;source_payload_opened=$false;utc=[DateTime]::UtcNow.ToString('o')}
    }
    Save 'ready.json' $ready
    Copy-Item -LiteralPath $tool.path -ToSession $session -Destination (Join-Path $stage 'ntfs2refs.exe')
    Copy-Item -LiteralPath $wrapperPath -ToSession $session -Destination (Join-Path $stage 'wrapper.ps1')
    Host-Guard
    Save 'dispatch.json' @{schema_version=1;kind='allocation-bounded-public-drive-dispatch';run_id=$run;vm_id=$id.ToString();parent_id=$ExpectedParent.ToString();checkpoint_ids=$ids;task_name=$task;guest_stage=$stage;binary_sha256=$mainPin;binary_bytes=$tool.bytes;wrapper_sha256=$wrapperPin;toolset_manifest=$manifestPath;toolset_manifest_sha256=$ToolsetManifestSha256;source_commit=$manifest.source_commit;ntfs_receipt_path=$receiptPath;ntfs_receipt_sha256=$NtfsReceiptSha256;argv=@('--drive','F','--partition','2');stdin='yes CRLF';expected_exit=0;manual_shadow_journal_binding=$false;source_admission_recreated=$false;utc=[DateTime]::UtcNow.ToString('o')}
    Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin,$mainPin,$MainBytes -ScriptBlock {param($Stage,$Task,$WrapperPin,$MainPin,$Bytes)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$path=Join-Path $Stage 'wrapper.ps1';$binary=Join-Path $Stage 'ntfs2refs.exe'
        if((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -cne $WrapperPin -or (Get-Item -LiteralPath $binary).Length -ne $Bytes -or (Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant() -cne $MainPin -or @(Get-ScheduledTask -ErrorAction Stop|Where-Object TaskName -CEQ $Task).Count){throw 'Fresh pinned public main/wrapper/task required.'}
        Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'"')) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)) -ErrorAction Stop|Out-Null
    }
    Host-Guard
    Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration $configuration) -AdditionalBytes 7GB
    Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin -ScriptBlock {param($Stage,$Task,$Pin)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskName $Task -ErrorAction Stop;$info=Get-ScheduledTaskInfo -TaskName $Task -ErrorAction Stop;$path=Join-Path $Stage 'wrapper.ps1'
        if($t.State.ToString() -cne 'Ready' -or $info.LastRunTime.Year -ge 2000 -or @($t.Actions).Count -ne 1 -or $t.Actions[0].Execute -cne "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -or $t.Actions[0].Arguments -cne ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'"') -or $t.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or $t.Principal.RunLevel.ToString() -cne 'Highest' -or (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -cne $Pin -or @(Get-ScheduledTask -ErrorAction Stop|Where-Object {$_.TaskName -like 'N2R-*' -and $_.State.ToString() -notin @('Ready','Disabled')}).Count){throw 'Only the untouched pinned SYSTEM public drive task may start once.'}
        Start-ScheduledTask -TaskName $Task -ErrorAction Stop
    }
    Save 'start.json' @{start_issued_once=$true;expected_exit=0;completion_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')}
    Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw
}catch{if($created -and -not (Test-Path -LiteralPath (Join-Path $root 'dispatch-failed.json'))){Save 'dispatch-failed.json' @{success=$false;run_id=$run;error=$_.Exception.ToString();automatic_retry_recovery_restore_cleanup=$false;utc=[DateTime]::UtcNow.ToString('o')}};throw}
finally{if($null -ne $session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
