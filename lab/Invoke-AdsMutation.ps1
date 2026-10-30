# Ordinary named-stream mutation on the already converted H: fixture. Root
# performs any preceding reboot. No power, checkpoint, raw IO or cleanup here.
[CmdletBinding()]param(
 [Parameter(Mandatory)][string]$AdsManifestPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$AdsManifestSha256,
 [Parameter(Mandatory)][string]$ConvertedFixturePath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ConvertedFixtureSha256
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027';$vmId=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$run=[guid]::NewGuid().ToString('N');$root=Join-Path $base ('ads-mutation-'+$run);$created=$false
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function ReadPinned([string]$Path,[string]$Pin){$m=Get-Item -LiteralPath ([IO.Path]::GetFullPath($Path)) -Force;Need ($m-is[IO.FileInfo]-and$m.Length-gt0-and$m.Length-le1MB-and(Get-FileHash -LiteralPath $m.FullName).Hash.ToLowerInvariant()-ceq$Pin) 'Bounded pinned fixture record required.';$a=$m;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse fixture ancestry.';if($a-is[IO.DirectoryInfo]){$a=$a.Parent}else{$a=$a.Directory}};return [IO.File]::ReadAllText($m.FullName)}
function Save([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14));Need ($b.Length-le1MB) 'Mutation receipt too large.';$f=[IO.File]::Open((Join-Path $root $Name),'CreateNew','Write','Read');try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
try{
 $adsText=ReadPinned $AdsManifestPath $AdsManifestSha256;$convertedText=ReadPinned $ConvertedFixturePath $ConvertedFixtureSha256
 $ads=$adsText|ConvertFrom-Json;$converted=$convertedText|ConvertFrom-Json
 Need ($ads.success-eq$true-and$ads.kind-ceq'independent-ads-hardlink-ntfs-fixture'-and$ads.named_stream_count-eq5-and$converted.filesystem-ceq'ReFS'-and$converted.user_file_identities-eq3-and$converted.user_file_names-eq9-and@($converted.groups).Count-eq3) 'Successful converted ADS fixture required.'
 $vm=Get-VM -Id $vmId;Need ($vm.Name-ceq'ntfs2refs-streaming-v2-20261027'-and$vm.State.ToString()-ceq'Running'-and$vm.MemoryStartup-eq4GB-and-not$vm.DynamicMemoryEnabled-and(Get-VMProcessor -VM $vm).Count-eq4-and@(Get-VMNetworkAdapter -VM $vm).Count-eq0) 'Reviewed running VM required.'
 New-Item -ItemType Directory -Path $root|Out-Null;$created=$true
 Save 'intent.json' @{schema_version=1;kind='ads-mutation-intent';run_id=$run;ads_manifest=$AdsManifestPath;ads_manifest_sha256=$AdsManifestSha256;converted_fixture=$ConvertedFixturePath;converted_fixture_sha256=$ConvertedFixtureSha256;power_checkpoint_raw_io=$false;automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')}
 $result=Invoke-Command -VMId $vmId -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')) -ArgumentList $adsText,$convertedText,$run -ScriptBlock {
  param($AdsText,$ConvertedText,$Run)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$ads=$AdsText|ConvertFrom-Json;$converted=$ConvertedText|ConvertFrom-Json;$phase='baseline';$mutated=$false;$restored=$false;$oldByte=$null;$newByte=$null;$mutationPath=$null;$restorePath=$null
  function Require([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
  function Guard{
   Require (@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-eq0-and@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-eq0) 'Project worker active.'
   $d=Get-Disk -Number 6;$p=Get-Partition -DriveLetter H;$v=Get-Volume -DriveLetter H
   Require ($d.UniqueId-ceq$ads.disk_unique_id-and[guid]$d.Guid-eq[guid]'f95141cb-fe7e-439a-a82b-c2b3f55965d2'-and[guid]$d.Guid-eq[guid]$ads.disk_guid-and[guid]$p.Guid-eq[guid]'f77d3d8f-9a87-464d-a7de-e1b77604da7b'-and[guid]$p.Guid-eq[guid]$ads.partition_guid-and$p.DiskNumber-eq6-and$p.Size-eq52GB-and$p.Offset-eq32MB-and-not$d.IsOffline-and-not$d.IsReadOnly-and-not$d.IsBoot-and-not$d.IsSystem-and$v.FileSystem-ceq'ReFS'-and$v.AllocationUnitSize-eq4096-and$v.FileSystemLabel-ceq'n2r-links-source') 'Exact converted H: fixture required.'
  }
  function HashBytes([byte[]]$Bytes){$sha=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}
  function ReadStream([string]$Path,[string]$Name){$bytes=Get-Content -LiteralPath $Path -Stream $Name -Encoding Byte -ReadCount 0 -ErrorAction Stop;if($null-eq$bytes){return ,[byte[]]::new(0)};return ,[byte[]]$bytes}
  function Fsutil([string[]]$Arguments){$old=[Console]::OutputEncoding;try{[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$lines=@(& "$env:SystemRoot\System32\fsutil.exe" @Arguments 2>&1|ForEach-Object {[string]$_});$exit=$LASTEXITCODE;Require ($exit-eq0-and($lines-join"`n").Length-le65536) 'Bounded fsutil failed.';return ,$lines}finally{[Console]::OutputEncoding=$old}}
  function VerifyAll([string]$ChangedHash){
   Guard;$defaultCount=0;$streamCount=0;$ids=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
   foreach($group in $converted.groups){
    Require (@($group.names).Count-eq3) 'Three aliases per identity required.';$expectedLinks=@($group.names|ForEach-Object {$_.path.Substring(2)}|Sort-Object);$id=$null
    $specs=@($ads.streams|Where-Object group -CEQ $group.name);$expectedNames=@(':$DATA')+@($specs|ForEach-Object {$_.name})
    foreach($alias in $group.names){
     Require ($alias.path.StartsWith('H:\',[StringComparison]::Ordinal)-and$alias.path-cnotmatch'\.\.|["\r\n\x00]') 'Unsafe fixture path.'
     $file=Get-Item -LiteralPath $alias.path -Force
     Require ($file-is[IO.FileInfo]-and-not($file.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$file.Length-eq$alias.length-and(Get-FileHash -LiteralPath $alias.path -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$alias.sha256) 'Default stream changed.'
     $output=Fsutil @('file','queryfileid',$alias.path);$matches=[regex]::Matches(($output-join"`n"),'0x[0-9a-fA-F]+');Require ($matches.Count-eq1-and$matches[0].Value.ToLowerInvariant()-ceq$alias.file_id) 'Post-conversion file identity changed.';$actualId=$matches[0].Value.ToLowerInvariant();if($null-eq$id){$id=$actualId}else{Require ($id-ceq$actualId) 'Aliases no longer share one identity.'}
     $linkOutput=Fsutil @('hardlink','list',$alias.path);$links=@($linkOutput|ForEach-Object {$line=$_.Trim();if($line.Length){if($line.StartsWith('H:\',[StringComparison]::OrdinalIgnoreCase)){$line=$line.Substring(2)};$line}}|Sort-Object);Require ($links.Count-eq3-and@(Compare-Object $expectedLinks $links -CaseSensitive).Count-eq0) 'Hard-link name set changed.'
     $streamInfo=@(Get-Item -LiteralPath $alias.path -Stream * -ErrorAction Stop);$names=@($streamInfo|ForEach-Object {[string]$_.Stream});Require ($names.Count-eq$expectedNames.Count-and@(Compare-Object $expectedNames $names -CaseSensitive).Count-eq0) 'ADS set changed.'
     foreach($spec in $specs){$bytes=ReadStream $alias.path $spec.name;$want=if($ChangedHash-and$spec.group-ceq'ordinary'-and$spec.name-ceq'large-data'){$ChangedHash}else{$spec.sha256};Require ($bytes.Length-eq$spec.length-and(HashBytes $bytes)-ceq$want) 'ADS content changed unexpectedly.';$entry=@($streamInfo|Where-Object Stream -CEQ $spec.name);Require ($entry.Count-eq1-and$entry[0].Length-eq$spec.length) 'ADS enumerated size differs.';$streamCount++}
     $defaultCount++
    }
    Require ($ids.Add($id)) 'Distinct file groups collapsed.'
   }
   Require ($defaultCount-eq9-and$streamCount-eq15-and$ids.Count-eq3) 'Fixture verification counts differ.'
   return @{default_paths_verified=$defaultCount;ads_views_verified=$streamCount;persistent_refs_identities=$ids.Count;exact_stream_and_hardlink_sets=$true;default_streams_unchanged=$true;override_large_data_sha256=$ChangedHash}
  }
  try{
   $before=VerifyAll ''
   $large=@($ads.streams|Where-Object {$_.group-ceq'ordinary'-and$_.name-ceq'large-data'});Require ($large.Count-eq1-and$large[0].length-eq(2MB+19)) 'Expected large-data stream required.';$large=$large[0]
   $unicode=@($large.aliases|Where-Object {$_.path-cmatch'[^\x00-\x7f]'});Require ($unicode.Count-eq1) 'One Unicode hard-link alias required.';$mutationPath=$unicode[0].path
   $other=@($large.aliases|Where-Object {$_.path-cne$mutationPath});Require ($other.Count-ge1) 'A distinct restoration alias required.';$restorePath=$other[0].path
   $bytes=ReadStream $mutationPath 'large-data';Require ((HashBytes $bytes)-ceq$large.sha256) 'Mutation source differs from original stream.';$oldByte=$bytes[0];$newByte=[byte]($oldByte-bxor0x5a);$bytes[0]=$newByte;$changedHash=HashBytes $bytes
   Guard;$phase='write-one-logical-byte';Set-Content -LiteralPath $mutationPath -Stream 'large-data' -Encoding Byte -Value $bytes -ErrorAction Stop;$mutated=$true;Write-VolumeCache -DriveLetter H
   $phase='verify-mutated-aliases';$changed=VerifyAll $changedHash
   $restoredBytes=ReadStream $restorePath 'large-data';Require ((HashBytes $restoredBytes)-ceq$changedHash-and$restoredBytes[0]-eq$newByte) 'Restoration alias does not expose the mutated stream.';$restoredBytes[0]=$oldByte;Require ((HashBytes $restoredBytes)-ceq$large.sha256) 'Changing the one byte back does not restore the original payload.'
   Guard;$phase='restore-through-other-alias';Set-Content -LiteralPath $restorePath -Stream 'large-data' -Encoding Byte -Value $restoredBytes -ErrorAction Stop;$restored=$true;Write-VolumeCache -DriveLetter H
   $phase='verify-restored';$after=VerifyAll ''
   return @{success=$true;phase=$phase;before=$before;mutated=$changed;after=$after;mutation_path=$mutationPath;restoration_path=$restorePath;stream='large-data';logical_byte_offset=0;original_byte=[int]$oldByte;mutated_byte=[int]$newByte;original_sha256=$large.sha256;mutated_sha256=$changedHash;restored_original_sha256=$true;write_api='Set-Content -Stream -Encoding Byte rewrites the stream; exactly one logical byte differs';power_checkpoint_raw_io=$false;utc=[DateTime]::UtcNow.ToString('o')}
  }catch{return @{success=$false;phase=$phase;error=$_.Exception.ToString();mutation_written=$mutated;restoration_written=$restored;mutation_path=$mutationPath;restoration_path=$restorePath;original_byte=$oldByte;mutated_byte=$newByte;automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')}}
 }
 Save 'result.json' $result
 if($result.success-ne$true){throw ('ADS mutation failed at '+$result.phase+': '+$result.error)}
 [pscustomobject]@{success=$true;result_path=(Join-Path $root 'result.json');run_id=$run;default_paths=9;ads_views=15;restored_original=$true}
}catch{if($created-and-not(Test-Path -LiteralPath (Join-Path $root 'failed.json'))){Save 'failed.json' @{success=$false;run_id=$run;error=$_.Exception.ToString();automatic_retry=$false}};throw}
