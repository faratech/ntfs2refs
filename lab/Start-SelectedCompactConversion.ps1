# One public compact conversion on the newly prepared selected disks only.
# No format/restore/cleanup, source extent moves, activation repair or retries.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027';$root=Join-Path $base 'selected-native-alpha-20261028'
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$parent=[guid]'c670839d-00d1-46cf-8544-6aad51bde364'
function Need([bool]$Condition,[string]$Message){if(-not$Condition){throw $Message}}
function Save-New([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 18));$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
Need (-not(Test-Path -LiteralPath (Join-Path $root 'conversion-intent.json'))) 'Conversion has state; inspect without redispatch.'
$prepared=Get-Content -LiteralPath (Join-Path $root 'prepared.json') -Raw -Encoding UTF8|ConvertFrom-Json
Need ($prepared.success -eq $true -and $prepared.logical_user_bytes -eq 68223117 -and $prepared.source_extent_moves -eq 0 -and @($prepared.files).Count -eq 5) 'Actual prepared nonzero source required.'
$hostCreated=Get-Content -LiteralPath (Join-Path $root 'host-created.json') -Raw|ConvertFrom-Json
$vm=Get-VM -Id $id;$snap=@(Get-VMSnapshot -VM $vm);$drives=@(Get-VMHardDiskDrive -VM $vm)
Need ($vm.State.ToString() -ceq 'Running' -and $vm.ParentSnapshotId -eq $parent -and $vm.MemoryStartup -eq 4GB -and -not$vm.DynamicMemoryEnabled -and @(Get-VMNetworkAdapter -VM $vm).Count -eq 0 -and $snap.Count -eq 47 -and $drives.Count -eq 6 -and @($hostCreated.checkpoint_ids|Where-Object {$_ -notin @($snap.Id|ForEach-Object {$_.ToString('D')})}).Count -eq 0) 'Exact isolated selected branch/all47 required.'
foreach($d in $hostCreated.new_disks){Need (@($drives|Where-Object {$_.ControllerNumber -eq 0 -and $_.ControllerLocation -eq $d.slot -and $_.Path -ceq $d.path}).Count -eq 1) 'Selected host attachment differs.'}
$manifestPath=Join-Path $base 'selected-native-alpha-tools-20261028\manifest.json';$manifestPin='6a8a39773268f686b91fc74f29ea56d5dee31dbf5033d1f247bd6ddcf3d1ae81'
Need ((Get-FileHash -LiteralPath $manifestPath).Hash.ToLowerInvariant() -ceq $manifestPin) 'Sealed toolset changed.'
$manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
Need ($manifest.kind -ceq 'selected-native-compact-toolset' -and $manifest.source_commit -ceq 'f1f1f47491e0c64255b6e75eac77cd7873c5fe47' -and @($manifest.tools).Count -eq 2) 'Selected code/toolset required.'
foreach($tool in $manifest.tools){Need ((Get-Item -LiteralPath $tool.path).Length -eq $tool.bytes -and (Get-FileHash -LiteralPath $tool.path).Hash.ToLowerInvariant() -ceq $tool.sha256) 'Sealed native executable changed.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force;$capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
Need ($capacity.MaximumActualBytes -eq 329374052988 -and $capacity.MinimumFreeBytes -eq 17179869184) 'Fixed50GB epoch differs.';Assert-LabCapacity -Capacity $capacity -AdditionalBytes 7GB
$run=[guid]::NewGuid().ToString('N');$task='N2R-SelectedCompact-'+$run;$stage='C:\ntfs2refs\selected-native-alpha-20261028\conversion-'+$run
$configuration=@{run_id=$run;stage=$stage;output=(Join-Path $stage 'result');task_name=$task;tools=$manifest.tools;prepared_sha256=(Get-FileHash -LiteralPath (Join-Path $root 'prepared.json')).Hash.ToLowerInvariant()}
Save-New 'conversion-intent.json' @{run_id=$run;task_name=$task;vm_id=$id.ToString();parent_id=$parent.ToString();checkpoint_ids=$hostCreated.checkpoint_ids;configuration=$configuration;toolset_manifest_sha256=$manifestPin;source_commit=$manifest.source_commit;capacity=$capacity;forecast_bytes=7GB;source_extent_moves=0;utc=[DateTime]::UtcNow.ToString('o')}
$body=@'
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CONFIG__'))|ConvertFrom-Json
$phase='native-selected-device-guard'
function Save-New([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));$f=[IO.File]::Open((Join-Path $c.stage $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
try{
    foreach($spec in @(@(4,'60022480C353A6F4060E497B21816F60','e1f3b9d3-979f-4123-9fee-399640c25092','G','NTFS','n2r-selected-source',5),@(5,'60022480C8CE64F61847BF4F2B50F544','ad077674-6305-4767-a2aa-6ded3b707e36','T','ReFS','n2r-retained-shadow',6))){$d=Get-Disk -Number $spec[0];$p=Get-Partition -DriveLetter $spec[3];$v=Get-Volume -DriveLetter $spec[3];$w=@(Get-CimInstance Win32_DiskDrive|Where-Object Index -eq $spec[0]);if($d.UniqueId -cne $spec[1] -or [guid]$d.Guid -ne [guid]$spec[2] -or $d.Size -ne 80GB -or $d.IsBoot -or $d.IsSystem -or $d.IsOffline -or $d.IsReadOnly -or $p.DiskNumber -ne $spec[0] -or $p.Offset -ne 16MB -or $p.Size -ne 60GB -or $v.FileSystem -cne $spec[4] -or $v.FileSystemLabel -cne $spec[5] -or $v.AllocationUnitSize -ne 4096 -or $w.Count -ne 1 -or $w[0].SCSILogicalUnit -ne $spec[6]){throw 'Actual selected data devices differ.'}}
    if([guid](Get-Disk -Number 2).Guid -ne [guid]'09fcc613-b8c2-4a1a-8833-226f9399be7f' -or (Get-Volume -DriveLetter J).FileSystem -cne 'NTFS' -or @(Get-CimInstance Win32_Process|Where-Object {$_.Name -in @('ntfs2refs-compact.exe','ntfs2refs-bind.exe','lab-convert-native-composite.exe','lab-recover-native-composite.exe')}).Count){throw 'Independent journal or worker absence differs.'}
    foreach($tool in $c.tools){$p=Join-Path $c.stage $tool.name;if((Get-Item -LiteralPath $p).Length -ne $tool.bytes -or (Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant() -cne $tool.sha256){throw 'Staged native binary changed.'}}
    Save-New 'wrapper-worker.json' @{pid=$PID;creation_ms=([DateTimeOffset](Get-Process -Id $PID).StartTime).ToUnixTimeMilliseconds();phase=$phase;source_extent_moves=0;utc=[DateTime]::UtcNow.ToString('o')}
    $phase='read-only-binding';$binding=Join-Path $c.stage 'devices.json';$binder=Join-Path $c.stage 'ntfs2refs-bind.exe'
    $ErrorActionPreference='Continue';$log=@(& $binder --source 'G:\' --shadow 'T:\' --journal 'J:\' --experimental-large-journal --experimental-large-tree --experimental-streaming-payload --experiment-id $c.run_id --max-journal-bytes 1073741824 --output $binding --evidence (Join-Path $c.stage 'binding-evidence.json') 2>&1);$exit=$LASTEXITCODE;$ErrorActionPreference='Stop'
    $log|Out-String|Set-Content -LiteralPath (Join-Path $c.stage 'binder.log') -Encoding UTF8;if($exit -ne 0){throw ('Read-only binder exit '+$exit)}
    $request=Get-Content -LiteralPath $binding -Raw -Encoding UTF8|ConvertFrom-Json
    if($request.pair.source.disk_number -ne 4 -or $request.pair.shadow.disk_number -ne 5 -or $request.journal.disk.disk_number -ne 2 -or $request.source_resource_profile -cne 'experimental_streaming_tree_v2' -or $request.pair.source.identity.partition_bytes -ne 60GB -or $request.pair.shadow.identity.partition_bytes -ne 60GB -or $request.verify_existing_shadow){throw 'Fresh selected binding differs.'}
    $pin=(Get-FileHash -LiteralPath $binding).Hash.ToLowerInvariant();Save-New 'binding-pin.json' @{request_sha256=$pin;source_guid=$request.pair.source.identity.disk_guid;shadow_guid=$request.pair.shadow.identity.disk_guid;source_cluster_bytes=4096;partition_bytes=60GB}
    $phase='public-selected-compact-conversion';$binary=Join-Path $c.stage 'ntfs2refs-compact.exe'
    $cli=@('convert','--acknowledge-experimental-compact','--request',$binding,'--request-sha256',$pin,'--maximum-placement-bytes','1073741824','--maximum-placement-submissions','1024','--maximum-exception-bytes','16777216','--output',$c.output)
    $arguments=($cli|ForEach-Object {if($_.Contains('"')){throw 'Embedded quote refused.'};'"'+$_+'"'}) -join ' '
    $process=Start-Process -FilePath $binary -ArgumentList $arguments -WorkingDirectory $c.stage -RedirectStandardOutput (Join-Path $c.stage 'converter.stdout.log') -RedirectStandardError (Join-Path $c.stage 'converter.stderr.log') -PassThru -WindowStyle Hidden
    # Retain the process handle before waiting: Windows PowerShell5 may otherwise
    # return a blank ExitCode after a long-running child has already disappeared.
    $null=$process.Handle
    Save-New 'converter-process.json' @{pid=$process.Id;creation_ms=([DateTimeOffset]$process.StartTime).ToUnixTimeMilliseconds();binary=$binary;sha256=(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant();arguments=$cli;request_sha256=$pin;utc=[DateTime]::UtcNow.ToString('o')}
    $process.WaitForExit();$exit=$process.ExitCode;if($null -eq $exit){throw 'Public converter exit status unavailable; preserve reports without retry.'};if($exit -ne 0){throw ('Public converter exit '+$exit)}
    $result=Get-Content -LiteralPath (Join-Path $c.output 'result.json') -Raw -Encoding UTF8|ConvertFrom-Json
    if(-not$result.success -or -not$result.source_admitted -or -not$result.rollback_closed){throw 'Successful admitted compact handoff required.'}
    Save-New 'wrapper-result.json' @{success=$true;run_id=$c.run_id;phase=$phase;exit=0;source_extent_moves=0;utc=[DateTime]::UtcNow.ToString('o')};exit 0
}catch{Save-New 'wrapper-failed.json' @{success=$false;run_id=$c.run_id;phase=$phase;error=$_.Exception.ToString();automatic_retry=$false;automatic_source_state_change=$false;utc=[DateTime]::UtcNow.ToString('o')};exit 1}
'@
$configurationJson=$configuration|ConvertTo-Json -Depth 10 -Compress;$body=$body.Replace('__CONFIG__',[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($configurationJson)))
$tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors);Need (@($errors).Count -eq 0) 'Guest wrapper parse failed.'
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body));Need ($encoded.Length+60 -lt 30000) 'Encoded wrapper exceeds bounded command length.'
$wrapperPath=Join-Path $root 'conversion-wrapper.ps1';[IO.File]::WriteAllText($wrapperPath,$body,[Text.UTF8Encoding]::new($false));$wrapperPin=(Get-FileHash -LiteralPath $wrapperPath).Hash.ToLowerInvariant()
$session=$null
try{
    $session=New-PSSession -VMId $id -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml'))
    Invoke-Command -Session $session -ArgumentList $stage,$task -ScriptBlock {param($Stage,$Task);if((Test-Path -LiteralPath $Stage) -or (Get-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue) -or @(Get-ScheduledTask|Where-Object {$_.TaskName -like 'N2R-*' -and $_.State.ToString() -in @('Running','Queued')}).Count){throw 'Fresh idle selected conversion stage required.'};New-Item -ItemType Directory -Path $Stage|Out-Null}
    foreach($tool in $manifest.tools){Copy-Item -LiteralPath $tool.path -ToSession $session -Destination ([IO.Path]::Combine($stage,$tool.name))}
    Invoke-Command -Session $session -ArgumentList $task,$encoded -ScriptBlock {param($Task,$Encoded);Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$Encoded)) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null}
    Save-New 'dispatch.json' @{vm_id=$id.ToString();run_id=$run;task_name=$task;guest_stage=$stage;output_dir=$configuration.output;wrapper_sha256=$wrapperPin;toolset_manifest_sha256=$manifestPin;converter_sha256='f41b47c931989aa451a398993982b20b319eb35d0f5d32fffc7e3de9ba79cbc1';expected_exit=0;source_disks=@(4,5);source_extent_moves=0;utc=[DateTime]::UtcNow.ToString('o')}
    Invoke-Command -Session $session -ArgumentList $task -ScriptBlock {param($Task);if((Get-ScheduledTaskInfo -TaskName $Task).LastRunTime.Year -ge 2000){throw 'Task already ran.'};Start-ScheduledTask -TaskName $Task}
    Save-New 'start.json' @{run_id=$run;start_issued_once=$true;utc=[DateTime]::UtcNow.ToString('o')};Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw
}finally{if($null -ne $session){Remove-PSSession $session}}
