# One public --recover of an interrupted allocation-bounded conversion on the lab
# VM. Root restores/boots the interrupted state separately. No retry, restore,
# power or cleanup happens here; the recovery engine alone decides what it may do.
[CmdletBinding()]param(
 [Parameter(Mandatory)][string]$ToolsetManifest,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ToolsetManifestSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit,
 [Parameter(Mandatory)][guid]$ExpectedParent,
 [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds,
 [Parameter(Mandatory)][ValidatePattern('\AC:\\ntfs2refs\\alloc-interrupt-[0-9a-f]{32}\\conversion\z')][string]$RecoveryDirectory,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$RecoverySha256,
 [switch]$Rollback,
 [ValidateRange(0,50000000000)][long]$ForecastAdditionalBytes=2GB
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$ids=@($ExpectedCheckpointIds|ForEach-Object {$_.ToString('D')})
$operation=if($Rollback){'rollback'}else{'resume'}
$run=[guid]::NewGuid().ToString('N');$root=Join-Path $base ('alloc-recovery-20261029-'+$operation+'-'+$run)
$stage='C:\ntfs2refs\alloc-recovery-'+$run;$task='N2R-AllocRecovery-'+$run;$session=$null;$created=$false
function Need([bool]$Ok,[string]$Message){if(-not $Ok){throw $Message}}
function Save([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14));Need ($b.Length-le1MB) 'Host receipt exceeds1MiB.';$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Host-Guard{$v=Get-VM -Id $id -ErrorAction Stop;$actual=@(Get-VMSnapshot -VM $v -ErrorAction Stop|ForEach-Object {$_.Id.ToString('D')});Need ($v.Name-ceq'ntfs2refs-streaming-v2-20261027'-and$v.State.ToString()-ceq'Running'-and$v.ParentSnapshotId-eq$ExpectedParent-and$v.MemoryStartup-eq4GB-and-not$v.DynamicMemoryEnabled-and(Get-VMProcessor -VM $v).Count-eq4-and@(Get-VMNetworkAdapter -VM $v).Count-eq0-and$actual.Count-eq$ids.Count-and@($ids|Where-Object {$_-notin$actual}).Count-eq0-and$ExpectedParent.ToString('D')-in$ids) 'Root must already boot the supplied interrupted parent with the exact checkpoint set/4GiB/4CPU/noNIC.'}
try{
 Need ($ExpectedParent-ne[guid]::Empty-and$ids.Count-gt0-and@($ids|Sort-Object -Unique).Count-eq$ids.Count-and$ExpectedParent.ToString('D')-in$ids-and@($ExpectedCheckpointIds|Where-Object {$_-eq[guid]::Empty}).Count-eq0) 'Explicit nonempty parent and exact unique current checkpoint IDs required.'
 $manifestPath=[IO.Path]::GetFullPath($ToolsetManifest);$toolsetDir=[IO.Path]::GetDirectoryName($manifestPath)
 Need ([IO.Path]::GetFileName($manifestPath)-ceq'manifest.json'-and[IO.Path]::GetDirectoryName($toolsetDir)-ceq$base-and[IO.Path]::GetFileName($toolsetDir)-cmatch'\Ahead-drive-tools-[0-9a-z]+(?:-[0-9a-z]+)*\z'-and(Get-FileHash -LiteralPath $manifestPath).Hash.ToLowerInvariant()-ceq$ToolsetManifestSha256) 'Pinned sealed HEAD toolset required.'
 $manifest=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8|ConvertFrom-Json;$rows=@($manifest.tools|Where-Object name -CEQ 'ntfs2refs.exe')
 Need ($manifest.kind-ceq'head-drive-toolset'-and$manifest.source_commit-ceq$SourceCommit-and$rows.Count-eq1) 'Sealed toolset provenance differs.';$tool=$rows[0]
 Need ($tool.path-ceq(Join-Path $toolsetDir 'ntfs2refs.exe')-and(Get-Item -LiteralPath $tool.path).Length-eq$tool.bytes-and(Get-FileHash -LiteralPath $tool.path).Hash.ToLowerInvariant()-ceq$tool.sha256) 'Sealed public executable differs.'
 Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force;$configuration=Get-LabConfiguration -WorkspaceRoot $workspace;$capacity=Get-LabCapacity -Configuration $configuration
 Need ($capacity.MaximumActualBytes-eq329374052988-and$capacity.MinimumFreeBytes-eq17179869184) 'Fixed storage epoch differs.';Assert-LabCapacity -Capacity $capacity -AdditionalBytes $ForecastAdditionalBytes
 Host-Guard;Need (-not(Test-Path -LiteralPath $root)) 'Fresh host case required.';New-Item -ItemType Directory -Path $root|Out-Null;$created=$true
 $cli=@('--recover',$RecoveryDirectory,'--recovery-sha256',$RecoverySha256);if($Rollback){$cli+='--rollback'}
 $c=@{run_id=$run;stage=$stage;task=$task;binary_sha256=$tool.sha256;binary_bytes=$tool.bytes;cli=$cli;operation=$operation;recovery_directory=$RecoveryDirectory;recovery_sha256=$RecoverySha256}
 Save 'intent.json' @{schema_version=1;kind='allocation-bounded-public-recovery-intent';run_id=$run;operation=$operation;parent_id=$ExpectedParent.ToString('D');checkpoint_ids=$ids;toolset_manifest=$manifestPath;toolset_manifest_sha256=$ToolsetManifestSha256;source_commit=$SourceCommit;tool=$tool;cli=$cli;stdin='yes CRLF';capacity=$capacity;forecast_bytes=$ForecastAdditionalBytes;forecast_is_not_reservation=$true;automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')}
 $body=@'
Set-StrictMode -Version Latest; $ErrorActionPreference='Stop'
$c=[Text.UTF8Encoding]::new($false).GetString([Convert]::FromBase64String('__CONFIG__'))|ConvertFrom-Json
$phase='preflight';$nativeExit=$null;$process=$null
function Need([bool]$Ok,[string]$Message){if(-not $Ok){throw $Message}}
function Save([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14));Need ($b.Length-le1MB) 'Wrapper receipt exceeds1MiB.';$f=[IO.File]::Open((Join-Path $c.stage $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Json([string]$Path,[long]$Limit=4MB){Need ($Path.StartsWith('C:\',[StringComparison]::OrdinalIgnoreCase)-and$Path.EndsWith('.json',[StringComparison]::Ordinal)) 'Closed C JSON metadata only.';$m=Get-Item -LiteralPath $Path -Force;Need (-not$m.PSIsContainer-and-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$m.Length-gt0-and$m.Length-le$Limit) 'Bounded ordinary C JSON required.';$a=$m.Directory;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse C metadata ancestry.';$a=$a.Parent};Get-Content -LiteralPath $Path -Raw -Encoding UTF8|ConvertFrom-Json}
function Log([string]$Path){$m=Get-Item -LiteralPath $Path -Force;Need ($m.Length-le8MB) 'Bounded native log required.';@{bytes=$m.Length;sha256=(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant();text=[IO.File]::ReadAllText($Path)}}
function Idle{Need (@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-eq0-and@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.TaskName-cne$c.task-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-eq0) 'Another project worker/task is active.'}
try{
    Idle;$d=Get-Disk -Number 1;Need ([guid]$d.Guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'-and$d.IsOffline-and-not$d.IsReadOnly) 'Interrupted activated source1 (offline, writable attributes) required.'
    $binary=Join-Path $c.stage 'ntfs2refs.exe';Need ((Get-Item -LiteralPath $binary).Length-eq$c.binary_bytes-and(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()-ceq$c.binary_sha256) 'Pinned public main differs.'
    $bundlePath=Join-Path $c.recovery_directory 'allocation-recovery-bundle.json';$bundle=Json $bundlePath 65536
    Need ((Get-FileHash -LiteralPath $bundlePath).Hash.ToLowerInvariant()-ceq$c.recovery_sha256-and$bundle.schema_version-eq1-and$bundle.kind-ceq'allocation-bounded-recovery-bundle'-and$bundle.serialized_bundle_grants_recovery_authority-eq$false) 'Pinned allocation recovery bundle differs.'
    $expectationPath=Join-Path $c.recovery_directory 'expectation.json'
    Need ($bundle.expectation.path-ceq$expectationPath-and$bundle.expectation.sha256-cmatch'\A[0-9a-f]{64}\z') 'Bundle expectation route or pin differs.'
    $expected=Json $expectationPath 64MB;$expectationPin=(Get-FileHash -LiteralPath $expectationPath).Hash.ToLowerInvariant()
    Need ($expectationPin-ceq$bundle.expectation.sha256-and@($expected.objects).Count-gt0) 'Pinned nonempty recovery expectation required.'
    $expectedObjects=@($expected.objects);$expectedFiles=@($expectedObjects|Where-Object {-not$_.directory})
    $expectedPaths=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($object in $expectedObjects){Need ($expectedPaths.Add(($object.path-join'\'))) 'Duplicate expected recovery object path.'}
    Save 'wrapper-worker.json' @{pid=$PID;creation_ms=([DateTimeOffset](Get-Process -Id $PID).StartTime).ToUnixTimeMilliseconds();run_id=$c.run_id;utc=[DateTime]::UtcNow.ToString('o')}
    $stdin=Join-Path $c.stage 'stdin-yes.txt';[IO.File]::WriteAllBytes($stdin,[Text.Encoding]::ASCII.GetBytes("yes`r`n"));$stdout=Join-Path $c.stage 'stdout.log';$stderr=Join-Path $c.stage 'stderr.log'
    $arguments=($c.cli|ForEach-Object {Need ($_-cnotmatch'["\r\n\x00]') 'Unsafe argument.';'"'+$_+'"'}) -join ' ';$phase='public-recovery'
    $process=Start-Process -FilePath $binary -ArgumentList $arguments -WorkingDirectory $c.stage -RedirectStandardInput $stdin -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden;$null=$process.Handle
    Save 'native-process.json' @{pid=$process.Id;creation_ms=([DateTimeOffset]$process.StartTime).ToUnixTimeMilliseconds();argv=$c.cli;expected_exit=0;utc=[DateTime]::UtcNow.ToString('o')}
    $process.WaitForExit();$process.Refresh();$nativeExit=$process.ExitCode;$out=Log $stdout;$err=Log $stderr
    Save 'native-terminal.json' @{native_exit=$nativeExit;native_exit_observed=($null-ne$nativeExit);stdout=$out;stderr=$err;utc=[DateTime]::UtcNow.ToString('o')}
    Need ($null-ne$nativeExit-and$nativeExit-eq0) ('Public recovery did not exit 0: '+$nativeExit)
    $phase='closed-recovery-evidence';$expectedLine=if($c.operation-ceq'rollback'){'NTFS rollback completed[.]'}else{'ReFS recovery completed[.]'}
    $done=[regex]::Matches($out.text,'(?m)^'+$expectedLine+' Recovery records: (C:\\ProgramData\\ntfs2refs\\runs\\recovery-[0-9a-f]{32})[ \t]*\r?$');Need ($done.Count-eq1) 'One actual completion line for the requested direction required.'
    $records=Join-Path $done[0].Groups[1].Value $c.operation;$result=Json (Join-Path $records 'result.json');$completion=Json (Join-Path $records 'completion.json') 64MB
    $v=Get-Volume -DriveLetter F;$d=Get-Disk -Number 1
    if($c.operation-ceq'rollback'){
        Need ($result.success-eq$true-and$result.outcome-ceq'ntfs_restored'-and$completion.mounted_filesystem-ceq'NTFS'-and$v.FileSystem-ceq'NTFS'-and$v.AllocationUnitSize-eq65536-and$v.FileSystemLabel-ceq'n2r-stream-source'-and-not$d.IsOffline) 'Restored NTFS source/label/online state differs.'
        $summary=@{mounted='NTFS';objects=$null;hashes=$null;expected_objects=$expectedObjects.Count;expected_files=$expectedFiles.Count;post_mount_content_hashes_checked=$false}
    }else{
        Need ($result.success-eq$true-and$result.outcome-ceq'refs_completed'-and$completion.success-eq$true-and$completion.rollback_closed-eq$true-and$v.FileSystem-ceq'ReFS'-and$v.AllocationUnitSize-eq4096-and$v.FileSystemLabel-ceq'n2r-stream-source'-and-not$d.IsOffline) 'Recovered ReFS source/label/online state differs.'
        $objects=@($completion.native.native.objects);Need ($objects.Count-eq$expectedObjects.Count) 'Recovered native object count differs from the pinned expectation.';$hashes=0
        foreach($object in $expectedObjects){$matches=@($objects|Where-Object {($_.components-join'\')-ceq($object.path-join'\')});Need ($matches.Count-eq1) 'Expected recovered object path is missing or duplicated.';if(-not$object.directory){Need (-not[string]::IsNullOrEmpty($object.sha256)-and$matches[0].logical_sha256-ceq$object.sha256) 'Recovered complete logical hash differs from the pinned expectation.';$hashes++}}
        Need ($hashes-eq$expectedFiles.Count) 'Recovered native file hash count differs from the pinned expectation.'
        $summary=@{mounted='ReFS';objects=$objects.Count;hashes=$hashes;expected_objects=$expectedObjects.Count;expected_files=$expectedFiles.Count;post_mount_content_hashes_checked=$true}
    }
    Save 'wrapper-result.json' @{schema_version=1;kind='allocation-bounded-public-recovery-observation';success=$true;run_id=$c.run_id;operation=$c.operation;native_exit=$nativeExit;recovery_records=$records;observed_lifecycle=$result.observed_lifecycle;action=$result.action;outcome=$result.outcome;summary=$summary;expectation_path=$expectationPath;expectation_sha256=$expectationPin;expectation_is_evidence_not_replay_authority=$true;result_sha256=(Get-FileHash -LiteralPath (Join-Path $records 'result.json')).Hash.ToLowerInvariant();completion_sha256=(Get-FileHash -LiteralPath (Join-Path $records 'completion.json')).Hash.ToLowerInvariant();utc=[DateTime]::UtcNow.ToString('o')}
}catch{Save 'wrapper-failed.json' @{success=$false;run_id=$c.run_id;phase=$phase;native_exit=$nativeExit;error=$_.Exception.ToString();automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')};throw}
finally{if($null-ne$process){$process.Dispose()}}
'@
 $body=$body.Replace('__CONFIG__',[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes(($c|ConvertTo-Json -Depth 6 -Compress))))
 $wrapperPath=Join-Path $root 'guest-wrapper.ps1';[IO.File]::WriteAllText($wrapperPath,$body,[Text.UTF8Encoding]::new($false));$wrapperPin=(Get-FileHash -LiteralPath $wrapperPath).Hash.ToLowerInvariant()
 $session=New-PSSession -VMId $id -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')) -ErrorAction Stop
 $ready=Invoke-Command -Session $session -ArgumentList $stage,$task,$RecoveryDirectory -ScriptBlock {param($Stage,$Task,$Directory)
  $ErrorActionPreference='Stop';if(Test-Path -LiteralPath $Stage){throw 'Fresh guest stage required.'};if(@(Get-ScheduledTask|Where-Object TaskName -CEQ $Task).Count){throw 'Fresh task required.'}
  if(-not(Test-Path -LiteralPath (Join-Path $Directory 'allocation-recovery-bundle.json'))-or(Test-Path -LiteralPath (Join-Path $Directory 'compact-recovery-bundle.json'))){throw 'Only the allocation recovery bundle must exist in the recovery directory.'}
  $d=Get-Disk -Number 1;if([guid]$d.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or-not$d.IsOffline-or$d.IsReadOnly){throw 'Interrupted activated source1 required.'}
  New-Item -ItemType Directory -Path $Stage|Out-Null;@{fresh_stage=$Stage;source_offline=$true;source_readonly=$false;bundle_present=$true;utc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'ready.json' $ready
 Copy-Item -LiteralPath $tool.path -ToSession $session -Destination (Join-Path $stage 'ntfs2refs.exe');Copy-Item -LiteralPath $wrapperPath -ToSession $session -Destination (Join-Path $stage 'wrapper.ps1');Host-Guard;Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration $configuration) -AdditionalBytes $ForecastAdditionalBytes
 Save 'dispatch.json' @{schema_version=1;kind='allocation-bounded-public-recovery-dispatch';run_id=$run;operation=$operation;vm_id=$id.ToString();parent_id=$ExpectedParent.ToString('D');checkpoint_ids=$ids;task_name=$task;guest_stage=$stage;binary_sha256=$tool.sha256;wrapper_sha256=$wrapperPin;cli=$cli;source_commit=$SourceCommit;utc=[DateTime]::UtcNow.ToString('o')}
 Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin -ScriptBlock {param($Stage,$Task,$Pin)
  $ErrorActionPreference='Stop';$path=Join-Path $Stage 'wrapper.ps1';if((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$Pin){throw 'Pinned wrapper required.'}
  Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'"')) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
  Start-ScheduledTask -TaskName $Task
 }
 Save 'start.json' @{start_issued_once=$true;expected_exit=0;completion_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')}
 Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw
}catch{if($created-and-not(Test-Path -LiteralPath (Join-Path $root 'dispatch-failed.json'))){Save 'dispatch-failed.json' @{success=$false;run_id=$run;error=$_.Exception.ToString();automatic_retry=$false}};throw}
finally{if($null-ne$session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
