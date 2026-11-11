# Run the pinned sparse-fixture writer once against the enrolled NTFS H: disk.
# Verifies the existing default streams and ADS around the new fixture writes.
# No power, checkpoints, formatting, deletion or automatic retry is performed.
[CmdletBinding()]param(
 [Parameter(Mandatory)][string]$ToolPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ToolSha256,
 [Parameter(Mandatory)][guid]$ExpectedParent,
 [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds,
 [Parameter(Mandatory)][string]$AdsManifestPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$AdsManifestSha256,
 [Parameter(Mandatory)][string]$HardlinkManifestPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$HardlinkManifestSha256
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027';$vmId=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$run=[guid]::NewGuid().ToString('N');$root=Join-Path $base ('sparse-fixture-'+$run);$stage='C:\ntfs2refs\sparse-fixture-'+$run;$task='N2R-SparseFixture-'+$run;$created=$false;$session=$null
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function Ordinary([string]$Path,[long]$Maximum,[string]$Pin){$m=Get-Item -LiteralPath ([IO.Path]::GetFullPath($Path)) -Force;Need ($m-is[IO.FileInfo]-and$m.Length-gt0-and$m.Length-le$Maximum-and(Get-FileHash -LiteralPath $m.FullName).Hash.ToLowerInvariant()-ceq$Pin) 'Pinned ordinary file required.';$a=$m;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse host ancestry.';if($a-is[IO.DirectoryInfo]){$a=$a.Parent}else{$a=$a.Directory}};return $m}
function Save([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14));Need ($b.Length-le1MB) 'Host receipt too large.';$f=[IO.File]::Open((Join-Path $root $Name),'CreateNew','Write','Read');try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
$ids=@($ExpectedCheckpointIds|ForEach-Object {$_.ToString('D')});Need ($ids.Count-gt0-and@($ids|Sort-Object -Unique).Count-eq$ids.Count-and$ExpectedParent.ToString('D')-in$ids) 'Explicit current parent/checkpoints required.'
function HostGuard{$vm=Get-VM -Id $vmId;$actual=@(Get-VMSnapshot -VM $vm|ForEach-Object {$_.Id.ToString('D')});Need ($vm.Name-ceq'ntfs2refs-streaming-v2-20261027'-and$vm.State.ToString()-ceq'Running'-and$vm.ParentSnapshotId-eq$ExpectedParent-and$vm.MemoryStartup-eq4GB-and$vm.MemoryAssigned-eq4GB-and-not$vm.DynamicMemoryEnabled-and(Get-VMProcessor -VM $vm).Count-eq4-and@(Get-VMNetworkAdapter -VM $vm).Count-eq0-and$actual.Count-eq$ids.Count-and@($ids|Where-Object {$_-notin$actual}).Count-eq0) 'Reviewed running parent/checkpoints/resources required.'}
try{
 $tool=Ordinary $ToolPath 64MB $ToolSha256;$ads=Ordinary $AdsManifestPath 1MB $AdsManifestSha256;$fixture=Ordinary $HardlinkManifestPath 1MB $HardlinkManifestSha256
 $a=[IO.File]::ReadAllText($ads.FullName)|ConvertFrom-Json;$f=[IO.File]::ReadAllText($fixture.FullName)|ConvertFrom-Json
 Need ($a.kind-ceq'independent-ads-hardlink-ntfs-fixture'-and$a.success-eq$true-and$a.hardlink_fixture_sha256-ceq$HardlinkManifestSha256-and$a.named_stream_count-eq5-and$f.success-eq$true-and$f.disk_number-eq6-and$f.partition_bytes-eq52GB-and$f.partition_offset-eq32MB) 'Original ADS and hard-link manifests required.'
 Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force;$configuration=Get-LabConfiguration -WorkspaceRoot $workspace;$capacity=Get-LabCapacity -Configuration $configuration;Need ($capacity.MaximumActualBytes-eq329374052988-and$capacity.MinimumFreeBytes-eq17179869184) 'Fixed capacity epoch differs.';Assert-LabCapacity -Capacity $capacity -AdditionalBytes 8GB;HostGuard
 New-Item -ItemType Directory -Path $root|Out-Null;$created=$true
 $c=@{run_id=$run;stage=$stage;task=$task;binary_sha256=$ToolSha256;binary_bytes=$tool.Length;ads_sha256=$AdsManifestSha256;fixture_sha256=$HardlinkManifestSha256;partition_number=$f.partition_number}
 Save 'intent.json' @{schema_version=1;kind='new-sparse-fixture-intent';configuration=$c;parent_id=$ExpectedParent.ToString('D');checkpoint_ids=$ids;tool_path=$tool.FullName;capacity=$capacity;forecast_bytes=8GB;no_format_or_cleanup=$true;utc=[DateTime]::UtcNow.ToString('o')}
 $body=@'
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$c=[Text.UTF8Encoding]::new($false).GetString([Convert]::FromBase64String('__CONFIG__'))|ConvertFrom-Json;$phase='preflight';$nativeExit=$null;$process=$null
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function Save([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));Need ($b.Length-le1MB) 'Wrapper receipt too large.';$f=[IO.File]::Open((Join-Path $c.stage $Name),'CreateNew','Write','Read');try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Json([string]$Path){$m=Get-Item -LiteralPath $Path -Force;Need ($m-is[IO.FileInfo]-and$m.Length-gt0-and$m.Length-le1MB-and-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Bounded ordinary fixture JSON required.';return ([IO.File]::ReadAllText($Path)|ConvertFrom-Json)}
function Idle{Need (@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-eq0-and@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.TaskName-cne$c.task-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-eq0) 'Project worker active.'}
function Log([string]$Path){$m=Get-Item -LiteralPath $Path -Force;Need ($m-is[IO.FileInfo]-and$m.Length-le1MB) 'Bounded native log required.';$r=[IO.StreamReader]::new($Path);try{$buffer=[char[]]::new(16384);$n=$r.ReadBlock($buffer,0,$buffer.Length);return @{path=$Path;bytes=$m.Length;sha256=(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant();text=[string]::new($buffer,0,$n);truncated=($r.Peek()-ne-1)}}finally{$r.Dispose()}}
function SameArray($A,$B){$aa=@($A);$bb=@($B);if($aa.Count-ne$bb.Count){return $false};for($i=0;$i-lt$aa.Count;$i++){if($aa[$i]-cne$bb[$i]){return $false}};return $true}
function Fsutil([string[]]$Arguments){$old=[Console]::OutputEncoding;try{[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$lines=@(& "$env:SystemRoot\System32\fsutil.exe" @Arguments 2>&1|ForEach-Object {[string]$_});$exit=$LASTEXITCODE;Need ($exit-eq0-and($lines-join"`n").Length-le65536) 'Bounded fsutil failed.';return ,$lines}finally{[Console]::OutputEncoding=$old}}
function VerifyFixture($Fixture,[string]$Filesystem){
 $d=Get-Disk -Number 6 -ErrorAction Stop;$p=Get-Partition -DriveLetter H -ErrorAction Stop;$v=Get-Volume -DriveLetter H -ErrorAction Stop
 Need ($d.UniqueId-ceq$Fixture.disk_unique_id_after-and[guid]$d.Guid-eq[guid]$Fixture.disk_guid-and$d.Size-eq56GB-and-not$d.IsBoot-and-not$d.IsSystem-and-not$d.IsOffline-and-not$d.IsReadOnly-and$p.DiskNumber-eq6-and$p.PartitionNumber-eq$c.partition_number-and[guid]$p.Guid-eq[guid]$Fixture.partition_guid-and$p.Offset-eq32MB-and$p.Size-eq52GB-and$v.FileSystem-ceq$Filesystem-and$v.AllocationUnitSize-eq4096-and$v.FileSystemLabel-ceq'n2r-links-source'-and(Get-Partition -DriveLetter C).DiskNumber-ne6) 'Actual H: source identity, filesystem or label differs.'
 $groups=[Collections.Generic.List[object]]::new();$seenIds=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$seenPaths=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach($group in $Fixture.groups){
  Need (@($group.names).Count-eq3-and$group.sha256-cmatch'\A[0-9a-f]{64}\z') 'Exactly three pinned names per identity required.'
  $expected=@($group.names|ForEach-Object {Need ($_.path.StartsWith('H:\',[StringComparison]::Ordinal)-and$_.path-cnotmatch'\.\.|["\r\n\x00]') 'Fixture path must stay on H:.';$_.path.Substring(2)}|Sort-Object)
  $names=[Collections.Generic.List[object]]::new();$identity=$null
  foreach($name in $group.names){
   Need ($seenPaths.Add($name.path)) 'Duplicate fixture name.'
   $entry=Get-Item -LiteralPath $name.path -Force
   Need (-not$entry.PSIsContainer-and-not($entry.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$entry.Length-eq$group.logical_length-and(Get-FileHash -LiteralPath $name.path -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$group.sha256) 'Fixture alias contents differ.'
   $idText=Fsutil @('file','queryfileid',$name.path);$matches=[regex]::Matches(($idText-join"`n"),'0x[0-9a-fA-F]+');Need ($matches.Count-eq1) 'Expected one native file ID.';$fileId=$matches[0].Value.ToLowerInvariant()
   if($null-eq$identity){$identity=$fileId}else{Need ($identity-ceq$fileId) 'Names do not resolve to one hard-linked file.'}
   if($Filesystem-ceq'NTFS'){Need ($fileId-ceq$group.file_id) 'Frozen fixture file ID changed before conversion.'}
   $linkText=Fsutil @('hardlink','list',$name.path);$links=@($linkText|ForEach-Object {$line=$_.Trim();if($line.Length){if($line.StartsWith('H:\',[StringComparison]::OrdinalIgnoreCase)){$line=$line.Substring(2)};Need ($line.StartsWith('\')) 'Unexpected hard-link list output.';$line}}|Sort-Object)
   Need ($links.Count-eq3-and@(Compare-Object -ReferenceObject $expected -DifferenceObject $links -CaseSensitive).Count-eq0) 'Exact three-name hard-link set was not preserved.'
   $names.Add(@{path=$name.path;file_id=$fileId;length=$entry.Length;sha256=$group.sha256;hardlink_list=$links;queryfileid_output=$idText;hardlink_list_output=$linkText})
  }
  Need ($seenIds.Add($identity)) 'Distinct source identities became the same file.'
  $groups.Add(@{name=$group.name;file_id=$identity;names=$names.ToArray()})
 }
 Need ($seenIds.Count-eq3-and$seenPaths.Count-eq9) 'Fixture identity/name count differs.'
 return @{filesystem=$v.FileSystem;cluster_bytes=$v.AllocationUnitSize;label=$v.FileSystemLabel;disk_guid=[string]$d.Guid;partition_guid=[string]$p.Guid;user_file_identities=$seenIds.Count;user_file_names=$seenPaths.Count;groups=$groups.ToArray()}
}
function VerifyAds($Fixture,$Ads,[bool]$AllowSparseData){
 $reports=[Collections.Generic.List[object]]::new();$views=0;$total=0L
 foreach($stream in $Ads.streams){
  $name=[string]$stream.name
  Need ($name.Length-gt0-and$name.Length-le255-and$name-cnotmatch'[:\\/\x00-\x1f]'-and$stream.length-ge0-and$stream.length-le8MB-and$stream.sha256-cmatch'\A[0-9a-f]{64}\z'-and(SameArray @($name.ToCharArray()|ForEach-Object {[int][char]$_}) $stream.name_utf16)) 'Invalid fixture stream identity.'
  $group=@($Fixture.groups|Where-Object name -CEQ $stream.group);Need ($group.Count-eq1) 'ADS group absent.';$group=$group[0]
  $expectedPaths=@($group.names|ForEach-Object {$_.path}|Sort-Object);$suppliedPaths=@($stream.aliases|ForEach-Object {$_.path}|Sort-Object)
  Need ($suppliedPaths.Count-eq3-and(SameArray $expectedPaths $suppliedPaths)) 'ADS aliases differ from the hard-link fixture.'
  $aliases=[Collections.Generic.List[object]]::new()
  foreach($alias in $stream.aliases){
   $bytes=Get-Content -LiteralPath $alias.path -Stream $name -Encoding Byte -ReadCount 0 -ErrorAction Stop
   if($null-eq$bytes){$bytes=[byte[]]::new(0)}else{$bytes=[byte[]]$bytes}
   Need ($bytes.Length-eq$stream.length) 'ADS length changed.'
   $sha=[Security.Cryptography.SHA256]::Create();try{$digest=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
   Need ($digest-ceq$stream.sha256) 'ADS payload differs through a hard-link name.'
   $aliases.Add(@{path=$alias.path;name=$name;name_utf16=$stream.name_utf16;length=$bytes.Length;sha256=$digest});$views++
  }
  $reports.Add(@{group=$stream.group;name=$name;name_utf16=$stream.name_utf16;length=$stream.length;sha256=$stream.sha256;aliases=$aliases.ToArray()});$total+=$stream.length
 }
 $enumerations=[Collections.Generic.List[object]]::new()
 foreach($group in $Fixture.groups){
  $named=@($Ads.streams|Where-Object group -CEQ $group.name);$expectedNames=@(':$DATA')+@($named|ForEach-Object {$_.name});if($AllowSparseData-and$group.name-ceq'ordinary'){$expectedNames+='Sparse.Data'}
  foreach($alias in $group.names){
   $streams=@(Get-Item -LiteralPath $alias.path -Stream * -ErrorAction Stop);$actualNames=@($streams|ForEach-Object {[string]$_.Stream})
   Need ($actualNames.Count-eq$expectedNames.Count-and@(Compare-Object $expectedNames $actualNames -CaseSensitive).Count-eq0) 'Native ADS enumeration is not the exact expected set.'
   $entries=@();foreach($entry in $streams){$length=if($entry.Stream-ceq':$DATA'){$group.logical_length}elseif($AllowSparseData-and$group.name-ceq'ordinary'-and$entry.Stream-ceq'Sparse.Data'){32MB+91}else{($named|Where-Object name -CEQ $entry.Stream).length};Need ($entry.Length-eq$length) 'Native stream enumeration length differs.';$entries+=@{name=[string]$entry.Stream;length=$entry.Length}}
   $enumerations.Add(@{path=$alias.path;streams=$entries})
  }
 }
 Need ($reports.Count-eq5-and$views-eq15-and$total-eq$Ads.named_logical_bytes) 'ADS fixture totals differ.'
 return @{named_stream_count=$reports.Count;alias_stream_views=$views;named_logical_bytes=$total;streams=$reports.ToArray();enumerations=$enumerations.ToArray();digest_algorithm='sha256'}
}
try{
 Idle;$fixturePath=Join-Path $c.stage 'hardlink-fixture.json';$adsPath=Join-Path $c.stage 'ads-fixture.json'
 Need ((Get-FileHash -LiteralPath $fixturePath).Hash.ToLowerInvariant()-ceq$c.fixture_sha256-and(Get-FileHash -LiteralPath $adsPath).Hash.ToLowerInvariant()-ceq$c.ads_sha256) 'Staged baseline pins differ.';$fixture=Json $fixturePath;$ads=Json $adsPath
 Save 'default-before.json' (VerifyFixture $fixture 'NTFS');Save 'ads-before.json' (VerifyAds $fixture $ads $false)
 $binary=Join-Path $c.stage 'lab-create-sparse-fixture.exe';Need ((Get-Item -LiteralPath $binary).Length-eq$c.binary_bytes-and(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()-ceq$c.binary_sha256) 'Staged sparse helper differs.'
 Save 'wrapper-worker.json' @{pid=$PID;creation_ms=([DateTimeOffset](Get-Process -Id $PID).StartTime).ToUnixTimeMilliseconds();utc=[DateTime]::UtcNow.ToString('o')}
 Idle;$phase='create-sparse-fixture';$output=Join-Path $c.stage 'fixture.json';$stdout=Join-Path $c.stage 'stdout.log';$stderr=Join-Path $c.stage 'stderr.log';$argv=@('--output',$output,'--probe-id',$c.run_id,'--acknowledge-disposable-data-volume')
 $arguments=($argv|ForEach-Object {'"'+$_+'"'})-join' '
 $process=Start-Process -FilePath $binary -ArgumentList $arguments -WorkingDirectory $c.stage -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru;$null=$process.Handle
 Save 'native-process.json' @{pid=$process.Id;creation_ms=([DateTimeOffset]$process.StartTime).ToUnixTimeMilliseconds();binary=$binary;binary_sha256=$c.binary_sha256;argv=$argv;expected_exit=0;utc=[DateTime]::UtcNow.ToString('o')};$process.WaitForExit();$process.Refresh();$nativeExit=$process.ExitCode
 Save 'native-terminal.json' @{native_exit=$nativeExit;native_exit_observed=($null-ne$nativeExit);stdout=(Log $stdout);stderr=(Log $stderr);utc=[DateTime]::UtcNow.ToString('o')}
 $phase='closed-fixture-evidence';$report=$null;$pin=$null;if(Test-Path -LiteralPath $output){$report=Json $output;$pin=(Get-FileHash -LiteralPath $output).Hash.ToLowerInvariant();Save 'report-pin.json' @{path=$output;sha256=$pin;bytes=(Get-Item -LiteralPath $output).Length;native_exit=$nativeExit}}
 Need ($null-ne$nativeExit-and$nativeExit-eq0-and$null-ne$report-and$report.success-eq$true) 'Sparse helper failed; native logs and any closed fixture report are preserved.'
 Idle;Save 'default-after.json' (VerifyFixture $fixture 'NTFS');Save 'ads-after.json' (VerifyAds $fixture $ads $true)
 Save 'wrapper-result.json' @{schema_version=1;kind='new-sparse-fixture-observation';success=$true;run_id=$c.run_id;native_exit=$nativeExit;tool_sha256=$c.binary_sha256;fixture_path=$output;fixture_sha256=$pin;ads_manifest_sha256=$c.ads_sha256;hardlink_manifest_sha256=$c.fixture_sha256;old_default_paths_verified=9;old_ads_views_verified=15;old_data_and_ids_unchanged=$true;additional_ads='Sparse.Data';power_checkpoint_format_delete=$false;utc=[DateTime]::UtcNow.ToString('o')}
}catch{Save 'wrapper-failed.json' @{success=$false;phase=$phase;native_exit=$nativeExit;error=$_.Exception.ToString();automatic_retry_cleanup=$false;utc=[DateTime]::UtcNow.ToString('o')};throw}finally{if($null-ne$process){$process.Dispose()}}
'@
 $body=$body.Replace('__CONFIG__',[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes(($c|ConvertTo-Json -Depth 6 -Compress))));$wrapper=Join-Path $root 'guest-wrapper.ps1';[IO.File]::WriteAllText($wrapper,$body,[Text.UTF8Encoding]::new($false));$wrapperPin=(Get-FileHash -LiteralPath $wrapper).Hash.ToLowerInvariant()
 $session=New-PSSession -VMId $vmId -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml'))
 Invoke-Command -Session $session -ArgumentList $stage,$task -ScriptBlock {param($Stage,$Task);$ErrorActionPreference='Stop';if((Test-Path -LiteralPath $Stage)-or@(Get-ScheduledTask|Where-Object TaskName -CEQ $Task).Count-or@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-or@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count){throw 'Fresh idle stage required.'};$a=Get-Item -LiteralPath 'C:\ntfs2refs' -Force;while($null-ne$a){if($a.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse stage ancestry.'};$a=$a.Parent};New-Item -ItemType Directory -Path $Stage|Out-Null}
 Copy-Item -LiteralPath $tool.FullName -ToSession $session -Destination (Join-Path $stage 'lab-create-sparse-fixture.exe');Copy-Item -LiteralPath $fixture.FullName -ToSession $session -Destination (Join-Path $stage 'hardlink-fixture.json');Copy-Item -LiteralPath $ads.FullName -ToSession $session -Destination (Join-Path $stage 'ads-fixture.json');Copy-Item -LiteralPath $wrapper -ToSession $session -Destination (Join-Path $stage 'wrapper.ps1');HostGuard
 Save 'dispatch.json' @{run_id=$run;kind='sparse-fixture-dispatch';guest_stage=$stage;task_name=$task;binary_sha256=$ToolSha256;wrapper_sha256=$wrapperPin;parent_id=$ExpectedParent.ToString('D');checkpoint_ids=$ids;expected_exit=0;utc=[DateTime]::UtcNow.ToString('o')}
 Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin -ScriptBlock {param($Stage,$Task,$Pin);$ErrorActionPreference='Stop';$path=Join-Path $Stage 'wrapper.ps1';if((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$Pin){throw 'Wrapper pin differs.'};Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'"')) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null}
 HostGuard;Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration $configuration) -AdditionalBytes 8GB
 Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin -ScriptBlock {param($Stage,$Task,$Pin);$ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskName $Task;$i=Get-ScheduledTaskInfo -TaskName $Task;if($t.State.ToString()-cne'Ready'-or$i.LastRunTime.Year-ge2000-or(Get-FileHash -LiteralPath (Join-Path $Stage 'wrapper.ps1')).Hash.ToLowerInvariant()-cne$Pin-or@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count){throw 'Only untouched idle task may start.'};Start-ScheduledTask -TaskName $Task}
 Save 'start.json' @{start_issued_once=$true;completion_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')};[IO.File]::ReadAllText((Join-Path $root 'dispatch.json'))
}catch{if($created-and-not(Test-Path -LiteralPath (Join-Path $root 'dispatch-failed.json'))){Save 'dispatch-failed.json' @{success=$false;error=$_.Exception.ToString();automatic_retry_cleanup=$false}};throw}finally{if($null-ne$session){Remove-PSSession $session}}
