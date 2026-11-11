# Add named data streams to the independently generated NTFS hard-link fixture.
# Root restores/boots its reviewed NTFS checkpoint first. No format, deletion,
# power, checkpoint or protection change is performed by this controller.
[CmdletBinding()]param(
 [Parameter(Mandatory)][guid]$ExpectedParent,
 [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds,
 [Parameter(Mandatory)][string]$HardlinkFixtureManifestPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$HardlinkFixtureManifestSha256
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027';$vmId=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$run=[guid]::NewGuid().ToString('N');$root=Join-Path $base ('ads-fixture-'+$run);$created=$false
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function Save([string]$Name,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));Need ($bytes.Length-le1MB) 'ADS fixture receipt exceeds one MiB.';$f=[IO.File]::Open((Join-Path $root $Name),'CreateNew','Write','Read');try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
$ids=@($ExpectedCheckpointIds|ForEach-Object {$_.ToString('D')});Need ($ids.Count-gt0-and@($ids|Sort-Object -Unique).Count-eq$ids.Count-and$ExpectedParent.ToString('D')-in$ids) 'Explicit current parent and unique checkpoint set required.'
function HostGuard{$vm=Get-VM -Id $vmId;$actual=@(Get-VMSnapshot -VM $vm|ForEach-Object {$_.Id.ToString('D')});Need ($vm.Name-ceq'ntfs2refs-streaming-v2-20261027'-and$vm.State.ToString()-ceq'Running'-and$vm.ParentSnapshotId-eq$ExpectedParent-and$vm.MemoryStartup-eq4GB-and$vm.MemoryAssigned-eq4GB-and-not$vm.DynamicMemoryEnabled-and(Get-VMProcessor -VM $vm).Count-eq4-and@(Get-VMNetworkAdapter -VM $vm).Count-eq0-and$actual.Count-eq$ids.Count-and@($ids|Where-Object {$_-notin$actual}).Count-eq0) 'Reviewed running parent/checkpoints/4 GiB/4 CPU/no NIC required.'}
try{
 $path=[IO.Path]::GetFullPath($HardlinkFixtureManifestPath);$m=Get-Item -LiteralPath $path -Force
 Need ($path.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)-and$m-is[IO.FileInfo]-and$m.Length-gt0-and$m.Length-le1MB-and(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-ceq$HardlinkFixtureManifestSha256) 'Pinned ordinary hard-link fixture manifest required.'
 $a=$m;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse fixture ancestry refused.';if($a-is[IO.DirectoryInfo]){$a=$a.Parent}else{$a=$a.Directory}}
 $fixture=[IO.File]::ReadAllText($path)|ConvertFrom-Json
 Need ($fixture.success-eq$true-and$fixture.kind-ceq'independent-hardlink-ntfs-fixture'-and$fixture.disk_number-eq6-and$fixture.partition_bytes-eq52GB-and$fixture.partition_offset-eq32MB-and$fixture.filesystem-ceq'NTFS'-and$fixture.cluster_bytes-eq4096-and$fixture.label-ceq'n2r-links-source'-and$fixture.user_file_identities-eq3-and$fixture.user_file_names-eq9-and@($fixture.groups).Count-eq3) 'Original NTFS hard-link fixture required.'
 Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force;$configuration=Get-LabConfiguration -WorkspaceRoot $workspace;$capacity=Get-LabCapacity -Configuration $configuration
 Need ($capacity.MaximumActualBytes-eq329374052988-and$capacity.MinimumFreeBytes-eq17179869184) 'Fixed capacity epoch differs.';Assert-LabCapacity -Capacity $capacity -AdditionalBytes 8GB;HostGuard
 New-Item -ItemType Directory -Path $root|Out-Null;$created=$true
 Save 'intent.json' @{schema_version=1;kind='named-stream-fixture-intent';run_id=$run;parent_id=$ExpectedParent.ToString('D');checkpoint_ids=$ids;hardlink_fixture_path=$path;hardlink_fixture_sha256=$HardlinkFixtureManifestSha256;capacity=$capacity;forecast_bytes=8GB;formats_performed=0;deletions_performed=0;utc=[DateTime]::UtcNow.ToString('o')}
 # Preserve the exact original manifest rather than reconstructing its file IDs.
 Copy-Item -LiteralPath $path -Destination (Join-Path $root 'hardlink-fixture.json')
 $fixtureJson=[IO.File]::ReadAllText($path)
 $result=Invoke-Command -VMId $vmId -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')) -ArgumentList $fixtureJson,$run,$HardlinkFixtureManifestSha256 -ScriptBlock {
  param($FixtureJson,$Run,$FixturePin)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  $fixture=$FixtureJson|ConvertFrom-Json
  function Require([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
  function Idle{Require (@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-eq0-and@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-eq0) 'No active project workers or N2R tasks permitted.'}
  function SourceGuard{
   Idle;$d=Get-Disk -Number 6;$p=Get-Partition -DriveLetter H;$v=Get-Volume -DriveLetter H
   Require ($d.UniqueId-ceq$fixture.disk_unique_id_after-and[guid]$d.Guid-eq[guid]$fixture.disk_guid-and$d.Size-eq56GB-and-not$d.IsOffline-and-not$d.IsReadOnly-and-not$d.IsBoot-and-not$d.IsSystem-and$p.DiskNumber-eq6-and$p.PartitionNumber-eq$fixture.partition_number-and[guid]$p.Guid-eq[guid]$fixture.partition_guid-and$p.Size-eq52GB-and$p.Offset-eq32MB-and$v.FileSystem-ceq'NTFS'-and$v.AllocationUnitSize-eq4096-and$v.FileSystemLabel-ceq'n2r-links-source'-and(Get-Partition -DriveLetter C).DiskNumber-ne6) 'Exact writable NTFS disk-6 H: source required.'
  }
  function Fsutil([string[]]$Arguments){$old=[Console]::OutputEncoding;try{[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$text=@(& "$env:SystemRoot\System32\fsutil.exe" @Arguments 2>&1|ForEach-Object {[string]$_});$exit=$LASTEXITCODE;Require ($exit-eq0-and($text-join"`n").Length-le65536) 'Bounded fsutil call failed.';return ,$text}finally{[Console]::OutputEncoding=$old}}
  function DefaultManifest{
   $all=[Collections.Generic.List[object]]::new();$identities=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
   foreach($group in $fixture.groups){
    $rows=[Collections.Generic.List[object]]::new();$expectedLinks=@($group.names|ForEach-Object {$_.path.Substring(2)}|Sort-Object)
    Require ($expectedLinks.Count-eq3) 'Three original hard-link names required.'
    foreach($name in $group.names){
     Require ($name.path.StartsWith('H:\',[StringComparison]::Ordinal)-and$name.path-cnotmatch'\.\.|["\r\n\x00]'-and$seen.Add($name.path)) 'Unsafe or duplicate fixture path.'
     $info=Get-Item -LiteralPath $name.path -Force
     Require ($info-is[IO.FileInfo]-and-not($info.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$info.Length-eq$group.logical_length) 'Original file type or length changed.'
     $hash=(Get-FileHash -LiteralPath $name.path -Algorithm SHA256).Hash.ToLowerInvariant();Require ($hash-ceq$group.sha256) 'Default stream content changed.'
     $idText=Fsutil @('file','queryfileid',$name.path);$matches=[regex]::Matches(($idText-join"`n"),'0x[0-9a-fA-F]+');Require ($matches.Count-eq1-and$matches[0].Value.ToLowerInvariant()-ceq$group.file_id) 'Original hard-link identity changed.'
     $linkText=Fsutil @('hardlink','list',$name.path);$links=@($linkText|ForEach-Object {$line=$_.Trim();if($line.Length){if($line.StartsWith('H:\',[StringComparison]::OrdinalIgnoreCase)){$line=$line.Substring(2)};$line}}|Sort-Object)
     Require ($links.Count-eq3-and@(Compare-Object $expectedLinks $links -CaseSensitive).Count-eq0) 'Original hard-link names changed.'
     $rows.Add(@{path=$name.path;length=$info.Length;sha256=$hash;file_id=$group.file_id;hardlink_list=$links})
    }
    Require ($identities.Add($group.file_id)) 'Fixture groups share a file identity.';$all.Add(@{name=$group.name;file_id=$group.file_id;names=$rows.ToArray()})
   }
   Require ($identities.Count-eq3-and$seen.Count-eq9) 'Default fixture identity or name count differs.'
   return ,$all.ToArray()
  }
  function StreamInventory([string]$Path){
   $streams=@(Get-Item -LiteralPath $Path -Stream * -ErrorAction Stop)
   Require ($streams.Count-ge1-and$streams.Count-le16) 'Unexpected stream enumeration size.'
   $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
   foreach($stream in $streams){Require ($seen.Add([string]$stream.Stream)) 'Duplicate enumerated stream name.'}
   return ,$streams
  }
  function BytesHash([byte[]]$Bytes){$sha=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}
  function NamedHash([string]$Path,[string]$Name,[long]$ExpectedLength){
   # Use the Windows PowerShell 5 filesystem provider's explicit Stream
   # parameter, not a parser guess about colons in an ordinary pathname.
   $bytes=Get-Content -LiteralPath $Path -Stream $Name -Encoding Byte -ReadCount 0 -ErrorAction Stop
   if($null-eq$bytes){$bytes=[byte[]]::new(0)}else{$bytes=[byte[]]$bytes}
   Require ($bytes.Length-eq$ExpectedLength) 'Named stream length differs.'
   return (BytesHash $bytes)
  }
  SourceGuard
  $before=DefaultManifest
  foreach($group in $fixture.groups){foreach($name in $group.names){$streams=StreamInventory $name.path;Require ($streams.Count-eq1-and$streams[0].Stream-ceq':$DATA'-and$streams[0].Length-eq$group.logical_length) 'Fixture already has named streams; no overwrite is allowed.'}}
  $unicodeName=[string][char]0x8cc7+[char]0x6599
  $large=[byte[]]::new(2MB+19);for($i=0;$i-lt$large.Length;$i++){$large[$i]=[byte](($i*17+11)%251)}
  $unicode=[byte[]]::new(65537);for($i=0;$i-lt$unicode.Length;$i++){$unicode[$i]=[byte](($i*29+5)%251)}
  $specs=@(
   @{group='ordinary';name='Zone.Identifier';bytes=[Text.Encoding]::ASCII.GetBytes("[ZoneTransfer]`r`nZoneId=3`r`n")},
   @{group='ordinary';name='large-data';bytes=$large},
   @{group='resident';name=$unicodeName;bytes=$unicode},
   @{group='empty';name='empty-data';bytes=[byte[]]::new(0)},
   @{group='empty';name='$DATA';bytes=[Text.Encoding]::ASCII.GetBytes('literal-data!')}
  )
  $recorded=[Collections.Generic.List[object]]::new();$total=0L
  foreach($spec in $specs){
   SourceGuard
   $matches=@($fixture.groups|Where-Object name -CEQ $spec.group);Require ($matches.Count-eq1) 'Named stream group missing.';$group=$matches[0];$primary=$group.names[0].path
   $existing=StreamInventory $primary
   Require (@($existing|Where-Object Stream -CEQ $spec.name).Count-eq0) 'Named stream already exists; no overwrite is allowed.'
   Set-Content -LiteralPath $primary -Stream $spec.name -Encoding Byte -Value $spec.bytes -ErrorAction Stop
   $digest=BytesHash $spec.bytes;$aliases=[Collections.Generic.List[object]]::new()
   foreach($name in $group.names){$actual=NamedHash $name.path $spec.name $spec.bytes.Length;Require ($actual-ceq$digest) 'Named stream bytes differ through a hard-link alias.';$aliases.Add(@{path=$name.path;stream_name=$spec.name;length=$spec.bytes.Length;sha256=$actual})}
   $total+=$spec.bytes.Length
   $recorded.Add(@{group=$spec.group;file_id=$group.file_id;name=$spec.name;name_utf16=@($spec.name.ToCharArray()|ForEach-Object {[int][char]$_});length=$spec.bytes.Length;sha256=$digest;aliases=$aliases.ToArray()})
  }
  Write-VolumeCache -DriveLetter H -ErrorAction Stop;SourceGuard
  $after=DefaultManifest
  $enumerations=[Collections.Generic.List[object]]::new()
  foreach($group in $fixture.groups){
   $expectedNames=@(':$DATA')+@($specs|Where-Object group -CEQ $group.name|ForEach-Object {$_.name})
   foreach($name in $group.names){
    $streams=StreamInventory $name.path;$actualNames=@($streams|ForEach-Object {[string]$_.Stream})
    Require ($actualNames.Count-eq$expectedNames.Count-and@(Compare-Object $expectedNames $actualNames -CaseSensitive).Count-eq0) 'Exact named-stream set differs after creation.'
    $rows=@();foreach($stream in $streams){$requiredLength=if($stream.Stream-ceq':$DATA'){$group.logical_length}else{($specs|Where-Object { $_.group-ceq$group.name-and$_.name-ceq$stream.Stream }).bytes.Length};Require ($stream.Length-eq$requiredLength) 'Enumerated stream length differs.';$rows+=@{name=[string]$stream.Stream;length=$stream.Length}}
    $enumerations.Add(@{path=$name.path;streams=$rows})
   }
  }
  [pscustomobject]@{schema_version=1;kind='independent-ads-hardlink-ntfs-fixture';success=$true;run_id=$Run;hardlink_fixture_sha256=$FixturePin;disk_number=6;disk_unique_id=$fixture.disk_unique_id_after;disk_guid=$fixture.disk_guid;partition_guid=$fixture.partition_guid;partition_number=$fixture.partition_number;partition_offset=32MB;partition_bytes=52GB;filesystem='NTFS';cluster_bytes=4096;label='n2r-links-source';user_file_identities=3;user_file_names=9;default_streams_unchanged=$true;default_before=$before;default_after=$after;named_stream_count=5;total_unique_stream_count=8;named_stream_alias_views=15;named_logical_bytes=$total;streams=$recorded.ToArray();enumerations=$enumerations.ToArray();creation_api='Set-Content -Stream -Encoding Byte; names prechecked absent';readback_api='Get-Content -Stream -Encoding Byte -ReadCount 0';formats_performed=0;deletions_performed=0;retry_performed=$false;utc=[DateTime]::UtcNow.ToString('o')}
 }
 HostGuard
 Save 'fixture.json' $result
 Save 'result.json' @{schema_version=1;kind='ads-fixture-controller';success=$true;run_id=$run;fixture_path=(Join-Path $root 'fixture.json');fixture_sha256=(Get-FileHash -LiteralPath (Join-Path $root 'fixture.json')).Hash.ToLowerInvariant();utc=[DateTime]::UtcNow.ToString('o')}
 [pscustomobject]@{success=$true;fixture_path=(Join-Path $root 'fixture.json');run_id=$run;named_stream_count=5;total_unique_stream_count=8;default_streams_unchanged=$true}
}catch{if($created-and-not(Test-Path -LiteralPath (Join-Path $root 'failed.json'))){Save 'failed.json' @{success=$false;run_id=$run;error=$_.Exception.ToString();automatic_retry=$false;automatic_cleanup=$false;utc=[DateTime]::UtcNow.ToString('o')}};throw}
