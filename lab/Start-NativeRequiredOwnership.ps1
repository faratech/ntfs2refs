# One-shot read-only ownership probe. No restore, replay or raw-volume writes.
[CmdletBinding()]param()
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$parent=[guid]'52d37819-2b9c-4041-9232-bd7eac3c21bb';$checkpoints=@($parent.ToString('D'),'5f30f4a1-9db0-4df5-a0e5-2c7be5d87eec')
function Need([bool]$ok,[string]$message){if(-not$ok){throw $message}}
function HostGuard{$v=Get-VM -Id $id;$ids=@(Get-VMSnapshot -VM $v|ForEach-Object {$_.Id.ToString('D')});Need ($v.State.ToString()-ceq'Running'-and$v.ParentSnapshotId-eq$parent-and$v.MemoryStartup-eq4GB-and-not$v.DynamicMemoryEnabled-and(Get-VMProcessor -VM $v).Count-eq4-and@(Get-VMNetworkAdapter -VM $v).Count-eq0-and$ids.Count-eq2-and@($checkpoints|Where-Object {$_-notin$ids}).Count-eq0) 'Exact running saved ReFS branch required'}
HostGuard
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force;$config=Get-LabConfiguration -WorkspaceRoot $workspace;$capacity=Get-LabCapacity -Configuration $config
Need ($capacity.MaximumActualBytes-eq329374052988-and$capacity.MinimumFreeBytes-eq17179869184) 'Fixed storage epoch differs';Assert-LabCapacity -Capacity $capacity -AdditionalBytes 2GB
$completion=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\optimized-compact-interrupt-20261029-c0218eb07cc742d8b8cb2b2738e31de3\recovery-cli-resume-c3a1f20f5f9f4c7c84a56b334e0511a2\closed-recovery\completion.json'
Need ((Get-FileHash -LiteralPath $completion).Hash.ToLowerInvariant()-ceq'62cd87d2da14d753addc36d0e9fe6a22993e5a14005f218c2b106b23eda61f53') 'Pinned completed ReFS route required'
$binding=(Get-Content -LiteralPath $completion -Raw|ConvertFrom-Json).native.native.binding
Need ($binding.disk_number-eq1-and[guid]$binding.identity.disk_guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'-and[guid]$binding.identity.partition_guid-eq[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-and$binding.identity.disk_bytes-eq64GB-and$binding.identity.partition_offset-eq16MB-and$binding.identity.partition_bytes-eq52GB) 'Exact disposable source1 route required'
$binary=Join-Path $workspace 'target\release\lab-freeze-refs-allocation.exe';$meta=Get-Item -LiteralPath $binary
Need (-not$meta.PSIsContainer-and-not($meta.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$meta.Length-le32MB) 'Ordinary bounded built tool required'
$pin=(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant();$run=[guid]::NewGuid().ToString('N');$root=Join-Path $workspace ('.lab\hyperv\streaming-v2-20261027\ownership-native-20261029-'+$run);$stage='C:\ntfs2refs\ownership-native-'+$run;$task='N2R-RequiredOwnership-'+$run
$null=New-Item -ItemType Directory -Path $root
function Save([string]$name,$value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 15));$f=[IO.File]::Open((Join-Path $root $name),'CreateNew','Write','Read');try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
$session=$null
try{
 $session=New-PSSession -VMId $id -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml'))
 $ready=Invoke-Command -Session $session -ArgumentList $stage,($binding|ConvertTo-Json -Depth 7 -Compress) -ScriptBlock {param($stage,$bindingJson)
  $ErrorActionPreference='Stop';$b=$bindingJson|ConvertFrom-Json
  if(@(Get-CimInstance Win32_Process|Where-Object Name -Match '^(ntfs2refs(?:-.+)?|lab-.+)\.exe$').Count-or@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count){throw 'Existing project worker/task active'}
  $d=Get-Disk -Number 1;$p=Get-Partition -DriveLetter F;$v=$p|Get-Volume
  if([guid]$d.Guid-ne[guid]$b.identity.disk_guid-or$d.IsOffline-or$d.IsReadOnly-or$d.IsBoot-or$d.IsSystem-or$p.DiskNumber-ne1-or$p.PartitionNumber-ne2-or[guid]$p.Guid-ne[guid]$b.identity.partition_guid-or$p.Offset-ne16MB-or$p.Size-ne52GB-or$v.FileSystem-cne'ReFS'-or$v.AllocationUnitSize-ne4096-or(Get-Partition -DriveLetter C).DiskNumber-ne0){throw 'Exact mounted disposable ReFS1/F and OS0 required'}
  if(Test-Path -LiteralPath $stage){throw 'Fresh guest stage required'};$null=New-Item -ItemType Directory -Path $stage
  $request=@{schema_version=2;binding=$b;expected_label=@{utf16=@($v.FileSystemLabel.ToCharArray()|ForEach-Object {[int][char]$_})};resource_profile='experimental_streaming_tree_v2'}
  $path=Join-Path $stage 'request.json';[IO.File]::WriteAllText($path,($request|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
  @{request_sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant();label=$v.FileSystemLabel;binding=$b}
 }
 Save 'ready.json' $ready
 $c=@{run_id=$run;stage=$stage;task=$task;binary_sha256=$pin;request_sha256=$ready.request_sha256}
 $body=@'
$ErrorActionPreference='Stop';$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CONFIG__'))|ConvertFrom-Json;$phase='preflight';$nativeExit=$null
function Save([string]$name,$value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 9));$f=[IO.File]::Open((Join-Path $c.stage $name),'CreateNew','Write','Read');try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
try{
 Save 'wrapper-worker.json' @{pid=$PID;creation_ms=([DateTimeOffset](Get-Process -Id $PID).StartTime).ToUnixTimeMilliseconds();run_id=$c.run_id}
 if(@(Get-CimInstance Win32_Process|Where-Object Name -Match '^(ntfs2refs(?:-.+)?|lab-.+)\.exe$').Count){throw 'Native worker already running'}
 $binary=Join-Path $c.stage 'lab-freeze-refs-allocation.exe';$request=Join-Path $c.stage 'request.json';$output=Join-Path $c.stage 'capture'
 if((Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()-cne$c.binary_sha256-or(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()-cne$c.request_sha256-or(Test-Path -LiteralPath $output)){throw 'Pinned built tool/request/fresh output required'}
 $phase='native-required-ownership';$stdout=Join-Path $c.stage 'stdout.log';$stderr=Join-Path $c.stage 'stderr.log'
 $nativeArgs='--request "'+$request+'" --request-sha256 '+$c.request_sha256+' --output "'+$output+'" --required-ownership'
 $p=Start-Process -FilePath $binary -ArgumentList $nativeArgs -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden;$null=$p.Handle
 Save 'native-process.json' @{pid=$p.Id;creation_ms=([DateTimeOffset]$p.StartTime).ToUnixTimeMilliseconds();parent_pid=$PID;binary_sha256=$c.binary_sha256;retained_handle_before_wait=$true;expected_exit=0;argv=$nativeArgs}
 $p.WaitForExit();$p.Refresh();$nativeExit=$p.ExitCode
 Save 'native-terminal.json' @{native_exit=$nativeExit;native_exit_observed=($null-ne$nativeExit);stdout_sha256=(Get-FileHash -LiteralPath $stdout).Hash.ToLowerInvariant();stderr_sha256=(Get-FileHash -LiteralPath $stderr).Hash.ToLowerInvariant();utc=[DateTime]::UtcNow.ToString('o')}
 if($null-eq$nativeExit-or$nativeExit-ne0){throw ('Native probe did not return0: '+$nativeExit)}
 $phase='closed-read-only-result';$result=Get-Content -LiteralPath (Join-Path $output 'result.json') -Raw|ConvertFrom-Json;$ownershipPath=Join-Path $output 'required-ownership.json';$m=Get-Item -LiteralPath $ownershipPath
 if($m.Length-gt16MB){throw 'Ownership result exceeds bounded report size'};$o=Get-Content -LiteralPath $ownershipPath -Raw|ConvertFrom-Json
 $disk=Get-Disk -Number 1
 if(-not$result.success-or$result.raw_source_writes-ne0-or$result.reconstruction_authorized-or-not$result.disk_left_offline_read_only-or-not$o.live_freeze_witness_validated_before_and_after-or$o.complete_graph_verified-or$o.reconstruction_authorized-or-not$disk.IsOffline-or-not$disk.IsReadOnly-or[guid]$disk.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'){throw 'Native observation scope or final exclusion differs'}
 Save 'wrapper-result.json' @{success=$true;run_id=$c.run_id;native_exit=$nativeExit;native_exit_observed=$true;result_sha256=(Get-FileHash -LiteralPath (Join-Path $output 'result.json')).Hash.ToLowerInvariant();ownership_sha256=(Get-FileHash -LiteralPath $ownershipPath).Hash.ToLowerInvariant();logical_raw_bytes_read=$o.logical_raw_bytes_read;native_phase=$o.selected_native_phase;native_allocated_bytes=$o.reconciliation.native_allocated_bytes;raw_allocated_bytes=$o.reconciliation.raw_union_allocated_bytes;required_not_native_bytes=$o.reconciliation.required_not_native_bytes;required_not_raw_bytes=$o.reconciliation.required_not_raw_union_bytes;source_left_offline_readonly=$true;reconstruction_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')};exit 0
}catch{Save 'wrapper-failed.json' @{success=$false;run_id=$c.run_id;phase=$phase;native_exit=$nativeExit;error=$_.Exception.ToString();automatic_retry_or_online_cleanup=$false;utc=[DateTime]::UtcNow.ToString('o')};exit 1}
'@
 $body=$body.Replace('__CONFIG__',[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes(($c|ConvertTo-Json -Compress))))
 $wrapper=Join-Path $root 'wrapper.ps1';[IO.File]::WriteAllText($wrapper,$body,[Text.UTF8Encoding]::new($false));$wrapperPin=(Get-FileHash -LiteralPath $wrapper).Hash.ToLowerInvariant()
 Copy-Item -LiteralPath $binary -ToSession $session -Destination (Join-Path $stage 'lab-freeze-refs-allocation.exe');Copy-Item -LiteralPath $wrapper -ToSession $session -Destination (Join-Path $stage 'wrapper.ps1')
 HostGuard;Save 'dispatch.json' @{schema_version=1;kind='native-required-ownership-dispatch';run_id=$run;vm_id=$id.ToString('D');parent_id=$parent.ToString('D');task_name=$task;guest_stage=$stage;request_sha256=$ready.request_sha256;binary_sha256=$pin;binary_bytes=$meta.Length;wrapper_sha256=$wrapperPin;source_commit=(& git -C $workspace rev-parse HEAD);user_main_hunk_unstaged=$true;capacity=$capacity;forecast_bytes=2GB;raw_reconstruction_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')}
 Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin -ScriptBlock {param($stage,$task,$pin)
  $ErrorActionPreference='Stop';$path=Join-Path $stage 'wrapper.ps1';if((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$pin-or(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)){throw 'Fresh pinned SYSTEM wrapper required'}
  $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'"')
  $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
  $null=Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings
  Start-ScheduledTask -TaskName $task
 }
 Save 'start.json' @{issued_once=$true;expected_exit=0;completion_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')}
 Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw
}catch{Save 'dispatch-failed.json' @{success=$false;run_id=$run;error=$_.Exception.ToString();automatic_retry=$false};throw}finally{if($null-ne$session){Remove-PSSession $session}}
