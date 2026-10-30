# Dispatch only the pinned read-only retrieval observer. Root independently
# restores/boots the intended branch. This controller never powers/restores the
# VM, changes disk attributes, invokes conversion/recovery or removes files.
[CmdletBinding()]param(
 [Parameter(Mandatory)][string]$RequestPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$RequestSha256,
 [Parameter(Mandatory)][string]$QueryToolPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$QueryToolSha256,
 [Parameter(Mandatory)][guid]$ExpectedParent,
 [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$run=[guid]::NewGuid().ToString('N')
$root=Join-Path $base ('extent-observe-20261030-'+$run);$stage='C:\ntfs2refs\extent-observe-'+$run;$task='N2R-ExtentObserve-'+$run
$ids=@($ExpectedCheckpointIds|ForEach-Object {$_.ToString('D')});$session=$null;$created=$false
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function Save([string]$Name,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 12));Need ($bytes.Length-le1MB) 'Small host receipt required.';$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
function OrdinaryPinned([string]$Path,[string]$Pin,[long]$Limit,[string]$Extension){
 Need ($Path-match'\A[A-Za-z]:\\'-and[IO.Path]::IsPathRooted($Path)-and[IO.Path]::GetExtension($Path)-ceq$Extension) 'Absolute ordinary host artifact path required.'
 $full=[IO.Path]::GetFullPath($Path);$m=Get-Item -LiteralPath $full -Force
 Need (-not$m.PSIsContainer-and-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$m.Length-gt0-and$m.Length-le$Limit) 'Bounded ordinary host artifact required.'
 $parent=$m.Directory;while($null-ne$parent){Need (-not($parent.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse host artifact ancestry refused.';$parent=$parent.Parent}
 Need ((Get-FileHash -LiteralPath $full).Hash.ToLowerInvariant()-ceq$Pin) 'Host artifact pin differs.'
 return $m
}
function HostGuard{
 $v=Get-VM -Id $id -ErrorAction Stop;$actual=@(Get-VMSnapshot -VM $v -ErrorAction Stop|ForEach-Object {$_.Id.ToString('D')})
 Need ($v.Name-ceq'ntfs2refs-streaming-v2-20261027'-and$v.State.ToString()-ceq'Running'-and$v.ParentSnapshotId-eq$ExpectedParent-and$v.MemoryStartup-eq4GB-and$v.MemoryAssigned-eq4GB-and-not$v.DynamicMemoryEnabled-and(Get-VMProcessor -VM $v).Count-eq4-and@(Get-VMNetworkAdapter -VM $v).Count-eq0-and$actual.Count-eq$ids.Count-and@($ids|Where-Object {$_-notin$actual}).Count-eq0-and$ExpectedParent.ToString('D')-in$ids) 'Root must boot the exact supplied branch/checkpoint set with4GiB/4CPU/noNIC.'
}
try{
 Need ($ExpectedParent-ne[guid]::Empty-and$ids.Count-gt0-and@($ids|Sort-Object -Unique).Count-eq$ids.Count-and$ExpectedParent.ToString('D')-in$ids-and@($ExpectedCheckpointIds|Where-Object {$_-eq[guid]::Empty}).Count-eq0) 'Explicit unique nonempty checkpoint identities required.'
 $requestInfo=OrdinaryPinned $RequestPath $RequestSha256 4MB '.json';$toolInfo=OrdinaryPinned $QueryToolPath $QueryToolSha256 64MB '.exe'
 $request=[IO.File]::ReadAllText($requestInfo.FullName)|ConvertFrom-Json
 Need ($request.schema_version-eq1-and$request.kind-ceq'readonly-refs-extent-request'-and$request.cluster_bytes-eq4096-and@($request.files).Count-ge1-and@($request.files).Count-le1024) 'Bounded read-only extent request required.'
 Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force;$configuration=Get-LabConfiguration -WorkspaceRoot $workspace;$capacity=Get-LabCapacity -Configuration $configuration
 Need ($capacity.MaximumActualBytes-eq329374052988-and$capacity.MinimumFreeBytes-eq17179869184) 'Fixed storage epoch differs.';Assert-LabCapacity -Capacity $capacity -AdditionalBytes 4GB
 HostGuard;Need (-not(Test-Path -LiteralPath $root)) 'Fresh host observation case required.';New-Item -ItemType Directory -Path $root|Out-Null;$created=$true
 $config=@{run_id=$run;stage=$stage;task=$task;request_sha256=$RequestSha256;request_bytes=$requestInfo.Length;binary_sha256=$QueryToolSha256;binary_bytes=$toolInfo.Length;files_expected=@($request.files).Count}
 Save 'intent.json' @{schema_version=1;kind='readonly-refs-extent-observation-intent';run_id=$run;request_path=$requestInfo.FullName;request_sha256=$RequestSha256;query_tool_path=$toolInfo.FullName;query_tool_sha256=$QueryToolSha256;expected_parent=$ExpectedParent.ToString('D');checkpoint_ids=$ids;capacity=$capacity;forecast_additional_bytes=4GB;forecast_is_not_reservation=$true;payload_reads_requested=$false;source_writes_requested=$false;automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')}
 $body=@'
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$c=[Text.UTF8Encoding]::new($false).GetString([Convert]::FromBase64String('__CONFIG__'))|ConvertFrom-Json
$phase='preflight';$process=$null;$nativeExit=$null
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function Save([string]$Name,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 12));Need ($bytes.Length-le1MB) 'Small wrapper receipt required.';$f=[IO.File]::Open((Join-Path $c.stage $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Ordinary([string]$Path,[long]$Limit){$m=Get-Item -LiteralPath $Path -Force;Need (-not$m.PSIsContainer-and-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$m.Length-ge0-and$m.Length-le$Limit) 'Bounded ordinary stage artifact required.';$p=$m.Directory;while($null-ne$p){Need (-not($p.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse stage ancestry.';$p=$p.Parent};return $m}
function Idle{Need (@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-eq0-and@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.TaskName-cne$c.task-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-eq0) 'Another project worker/task is active.'}
function Source($Binding){
 $d=Get-Disk -Number 1 -ErrorAction Stop;$p=Get-Partition -DiskNumber 1 -PartitionNumber 2 -ErrorAction Stop;$v=$p|Get-Volume -ErrorAction Stop
 Need ([guid]$d.Guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'-and$d.Size-eq64GB-and-not$d.IsOffline-and-not$d.IsReadOnly-and-not$d.IsBoot-and-not$d.IsSystem-and[guid]$p.Guid-eq[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-and$p.Offset-eq16MB-and$p.Size-eq52GB-and'F:\'-in@($p.AccessPaths)-and$v.FileSystem-ceq'ReFS'-and$v.AllocationUnitSize-eq4096-and$v.FileSystemLabel-ceq'n2r-stream-source'-and(Get-Partition -DriveLetter C -ErrorAction Stop).DiskNumber-eq0) 'Exact online source1/F/ReFS4KiB/GPT identity differs.'
 Need ($Binding.disk_number-eq1-and[guid]$Binding.identity.disk_guid-eq[guid]$d.Guid-and[guid]$Binding.identity.partition_guid-eq[guid]$p.Guid-and$Binding.identity.partition_number-eq2-and$Binding.identity.disk_bytes-eq64GB-and$Binding.identity.partition_offset-eq16MB-and$Binding.identity.partition_bytes-eq52GB-and$Binding.identity.logical_sector_bytes-eq512-and$Binding.identity.physical_sector_bytes-eq4096-and('\\?\Volume{'+$Binding.volume_guid.Trim('{}')+'}\')-in@($p.AccessPaths)) 'Request binding differs from the actual mounted volume.'
 return @{disk_guid=$d.Guid;partition_guid=$p.Guid;filesystem=$v.FileSystem;cluster_bytes=$v.AllocationUnitSize;online=$true;readonly=$false;boot=$false;system=$false;windows_disk=0;utc=[DateTime]::UtcNow.ToString('o')}
}
function Log([string]$Path){$m=Ordinary $Path 8MB;return @{bytes=$m.Length;sha256=(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant();text=[IO.File]::ReadAllText($Path)}}
try{
 Idle;Need ($env:COMPUTERNAME-ceq'N2R-WIN11') 'Enrolled guest required.'
 $requestPath=Join-Path $c.stage 'request.json';$binary=Join-Path $c.stage 'lab-query-refs-extents.exe';$reportPath=Join-Path $c.stage 'report.json'
 $rq=Ordinary $requestPath 4MB;$exe=Ordinary $binary 64MB
 Need ($rq.Length-eq$c.request_bytes-and$exe.Length-eq$c.binary_bytes-and(Get-FileHash -LiteralPath $requestPath).Hash.ToLowerInvariant()-ceq$c.request_sha256-and(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()-ceq$c.binary_sha256-and-not(Test-Path -LiteralPath $reportPath)) 'Fresh pinned request/query executable required.'
 $request=[IO.File]::ReadAllText($requestPath)|ConvertFrom-Json
 Need ($request.schema_version-eq1-and$request.kind-ceq'readonly-refs-extent-request'-and$request.cluster_bytes-eq4096-and@($request.files).Count-eq$c.files_expected) 'Read-only query request differs.'
 $before=Source $request.binding;Save 'source-before.json' $before
 Save 'wrapper-worker.json' @{pid=$PID;creation_ms=([DateTimeOffset](Get-Process -Id $PID).StartTime).ToUnixTimeMilliseconds();run_id=$c.run_id;utc=[DateTime]::UtcNow.ToString('o')}
 $cli=@('--request',$requestPath,'--request-sha256',$c.request_sha256,'--output',$reportPath,'--acknowledge-disposable-data-volume')
 $arguments=($cli|ForEach-Object {Need ($_-cnotmatch'["\r\n\x00]') 'Unsafe query argument.';'"'+$_+'"'})-join' '
 $stdout=Join-Path $c.stage 'stdout.log';$stderr=Join-Path $c.stage 'stderr.log';$phase='native-readonly-query'
 $process=Start-Process -FilePath $binary -ArgumentList $arguments -WorkingDirectory $c.stage -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden;$null=$process.Handle
 Save 'native-process.json' @{pid=$process.Id;creation_ms=([DateTimeOffset]$process.StartTime).ToUnixTimeMilliseconds();argv=$cli;expected_exit=0;utc=[DateTime]::UtcNow.ToString('o')}
 $process.WaitForExit();$process.Refresh();$nativeExit=$process.ExitCode;$out=Log $stdout;$err=Log $stderr
 Save 'native-terminal.json' @{native_exit=$nativeExit;native_exit_observed=($null-ne$nativeExit);stdout=$out;stderr=$err;utc=[DateTime]::UtcNow.ToString('o')}
 $phase='closed-report';$report=Ordinary $reportPath 64MB;Need ($report.Length-gt0) 'Nonempty closed extent report required.';$reportPin=(Get-FileHash -LiteralPath $reportPath).Hash.ToLowerInvariant()
 Save 'report-pin.json' @{path=$reportPath;bytes=$report.Length;sha256=$reportPin;native_exit=$nativeExit;closed_after_actual_process_exit=$true}
 Need ($null-ne$nativeExit-and$nativeExit-eq0) ('Read-only query did not exit0: '+$nativeExit)
 $nativeSummary=$out.text|ConvertFrom-Json
 Need ($nativeSummary.kind-ceq'readonly-refs-extent-query-completion'-and$nativeSummary.success-eq$true-and$nativeSummary.request_sha256-ceq$c.request_sha256-and$nativeSummary.report_path-ceq$reportPath-and$nativeSummary.report_sha256-ceq$reportPin-and$nativeSummary.report_bytes-eq$report.Length-and$nativeSummary.files_requested-eq$c.files_expected-and$nativeSummary.files_matching-eq$c.files_expected-and$nativeSummary.payload_bytes_read-eq0-and$nativeSummary.source_write_requests-eq0-and$nativeSummary.raw_write_authority-eq$false) 'Native stdout does not bind the closed report to this pinned request.'
 $r=[IO.File]::ReadAllText($reportPath)|ConvertFrom-Json
 Need ($r.schema_version-eq1-and$r.kind-ceq'readonly-refs-extent-observation'-and$r.success-eq$true-and$r.cluster_bytes-eq4096-and$r.files_requested-eq$c.files_expected-and$r.files_matching-eq$c.files_expected-and@($r.files).Count-eq$c.files_expected-and$r.payload_bytes_read-eq0-and$r.source_write_requests-eq0-and$r.raw_write_authority-eq$false-and$r.atomic_volume_snapshot_claimed-eq$false-and$r.conversion_qualified-eq$false-and$r.filesystem_before-ceq'ReFS'-and$r.filesystem_after-ceq'ReFS'-and@($r.files|Where-Object {$_.expected_matches-ne$true-or$_.identity_matches-ne$true-or$_.identity_stable-ne$true-or$_.length_matches-ne$true-or$_.retrieval_matches-ne$true-or$null-ne$_.error}).Count-eq0) 'Complete matching read-only extent report required.'
 $after=Source $request.binding;Save 'source-after.json' $after;Idle
 Save 'wrapper-result.json' @{schema_version=1;kind='readonly-refs-extent-wrapper-observation';success=$true;run_id=$c.run_id;native_exit=$nativeExit;request_sha256=$c.request_sha256;query_tool_sha256=$c.binary_sha256;report_path=$reportPath;report_bytes=$report.Length;report_sha256=$reportPin;files_requested=$r.files_requested;files_matching=$r.files_matching;payload_bytes_read=0;source_write_requests=0;raw_write_authority=$false;conversion_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')}
}catch{Save 'wrapper-failed.json' @{success=$false;run_id=$c.run_id;phase=$phase;native_exit=$nativeExit;error=$_.Exception.ToString();automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')};throw}
finally{if($null-ne$process){$process.Dispose()}}
'@
 $body=$body.Replace('__CONFIG__',[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes(($config|ConvertTo-Json -Depth 5 -Compress))))
 $wrapperPath=Join-Path $root 'guest-wrapper.ps1';[IO.File]::WriteAllText($wrapperPath,$body,[Text.UTF8Encoding]::new($false));$wrapperPin=(Get-FileHash -LiteralPath $wrapperPath).Hash.ToLowerInvariant()
 $session=New-PSSession -VMId $id -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')) -ErrorAction Stop
 $ready=Invoke-Command -Session $session -ArgumentList $stage,$task,$request.binding -ScriptBlock {param($Stage,$Task,$Binding)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  if($env:COMPUTERNAME-cne'N2R-WIN11'-or(Test-Path -LiteralPath $Stage)-or@(Get-ScheduledTask|Where-Object TaskName -CEQ $Task).Count-ne0){throw 'Fresh enrolled guest stage/task required.'}
  if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-ne0-or@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-ne0){throw 'Guest project workers must be inactive.'}
  $d=Get-Disk -Number 1;$p=Get-Partition -DiskNumber 1 -PartitionNumber 2;$v=$p|Get-Volume
  if([guid]$d.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or$d.Size-ne64GB-or$d.IsOffline-or$d.IsReadOnly-or$d.IsBoot-or$d.IsSystem-or[guid]$p.Guid-ne[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-or$p.Offset-ne16MB-or$p.Size-ne52GB-or'F:\'-notin@($p.AccessPaths)-or$v.FileSystem-cne'ReFS'-or$v.AllocationUnitSize-ne4096-or$v.FileSystemLabel-cne'n2r-stream-source'-or(Get-Partition -DriveLetter C).DiskNumber-ne0-or$Binding.disk_number-ne1-or[guid]$Binding.identity.disk_guid-ne[guid]$d.Guid-or[guid]$Binding.identity.partition_guid-ne[guid]$p.Guid-or('\\?\Volume{'+$Binding.volume_guid.Trim('{}')+'}\')-notin@($p.AccessPaths)){throw 'Exact restored ReFS data source/binding required.'}
  $a=Get-Item -LiteralPath 'C:\ntfs2refs' -Force;while($null-ne$a){if(-not($a-is[IO.DirectoryInfo])-or($a.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary guest stage ancestry required.'};$a=$a.Parent}
  New-Item -ItemType Directory -Path $Stage|Out-Null;@{fresh_stage=$Stage;source_online=$true;source_readonly=$false;query_only=$true;utc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'ready.json' $ready
 Copy-Item -LiteralPath $requestInfo.FullName -ToSession $session -Destination (Join-Path $stage 'request.json')
 Copy-Item -LiteralPath $toolInfo.FullName -ToSession $session -Destination (Join-Path $stage 'lab-query-refs-extents.exe')
 Copy-Item -LiteralPath $wrapperPath -ToSession $session -Destination (Join-Path $stage 'wrapper.ps1')
 HostGuard;Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration $configuration) -AdditionalBytes 4GB
 Save 'dispatch.json' @{schema_version=1;kind='readonly-refs-extent-observation-dispatch';run_id=$run;vm_id=$id.ToString('D');parent_id=$ExpectedParent.ToString('D');checkpoint_ids=$ids;task_name=$task;guest_stage=$stage;request_sha256=$RequestSha256;query_tool_sha256=$QueryToolSha256;wrapper_sha256=$wrapperPin;report_path=(Join-Path $stage 'report.json');automatic_retry=$false;completion_inferred=$false;vm_power_restore_or_checkpoint_actions=$false;source_writes_requested=$false;utc=[DateTime]::UtcNow.ToString('o')}
 Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin -ScriptBlock {param($Stage,$Task,$Pin)
  $ErrorActionPreference='Stop';$path=Join-Path $Stage 'wrapper.ps1';if((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$Pin){throw 'Pinned read-only wrapper required.'}
  Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'"')) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
  Start-ScheduledTask -TaskName $Task
 }
 Save 'start.json' @{start_issued_once=$true;expected_exit=0;completion_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')}
 [IO.File]::ReadAllText((Join-Path $root 'dispatch.json'))
}catch{if($created-and-not(Test-Path -LiteralPath (Join-Path $root 'dispatch-failed.json'))){Save 'dispatch-failed.json' @{success=$false;run_id=$run;error=$_.Exception.ToString();automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')}};throw}
finally{if($null-ne$session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
