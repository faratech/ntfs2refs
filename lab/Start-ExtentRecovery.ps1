# Public --recover of the H: extent-only source. Independent full-content baseline is lab-only.
# No VM restore/power/checkpoint changes and no raw journal opens are performed.
# One interrupted allocation-bounded conversion on the lab
# VM. Root restores/boots the interrupted state separately. No retry, restore,
# power or cleanup happens here; the recovery engine alone decides what it may do.
[CmdletBinding()]param(
 [Parameter(Mandatory)][string]$ToolsetDirectory,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BuildSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit,
 [Parameter(Mandatory)][guid]$ExpectedParent,
 [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds,
 [Parameter(Mandatory)][ValidatePattern('\AC:\\ntfs2refs\\extent-interrupt-[0-9a-f]{32}\\conversion\z')][string]$RecoveryDirectory,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$RecoverySha256,
 [Parameter(Mandatory)][string]$BaselinePath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BaselineSha256,
 [switch]$Rollback,
 [ValidateRange(0,50000000000)][long]$ForecastAdditionalBytes=2GB
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$ids=@($ExpectedCheckpointIds|ForEach-Object {$_.ToString('D')})
$operation=if($Rollback){'rollback'}else{'resume'}
$run=[guid]::NewGuid().ToString('N');$root=Join-Path $base ('extent-recovery-20261031-'+$operation+'-'+$run)
$stage='C:\ntfs2refs\extent-recovery-'+$run;$task='N2R-ExtentRecovery-'+$run;$session=$null;$created=$false
function Need([bool]$Ok,[string]$Message){if(-not $Ok){throw $Message}}
function Save([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14));Need ($b.Length-le1MB) 'Host receipt exceeds1MiB.';$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Host-Guard{$v=Get-VM -Id $id -ErrorAction Stop;$actual=@(Get-VMSnapshot -VM $v -ErrorAction Stop|ForEach-Object {$_.Id.ToString('D')});Need ($v.Name-ceq'ntfs2refs-streaming-v2-20261027'-and$v.State.ToString()-ceq'Running'-and$v.ParentSnapshotId-eq$ExpectedParent-and$v.MemoryStartup-eq4GB-and$v.MemoryAssigned-eq4GB-and-not$v.DynamicMemoryEnabled-and(Get-VMProcessor -VM $v).Count-eq4-and@(Get-VMNetworkAdapter -VM $v).Count-eq0-and$actual.Count-eq$ids.Count-and@($ids|Where-Object {$_-notin$actual}).Count-eq0-and$ExpectedParent.ToString('D')-in$ids) 'Root must already boot the supplied interrupted parent with the exact checkpoint set/4GiB/4CPU/noNIC.'}
function ReadLabBaselineHost([string]$Path,[string]$Sha256,[guid]$RequiredParent){
 $enabled=-not[string]::IsNullOrEmpty($Path);Need ($enabled-eq(-not[string]::IsNullOrEmpty($Sha256))) 'Lab baseline path and checksum must be supplied together.'
 $answer=@{enabled=$enabled;files=@{};sha256='';request_sha256='';result_sha256='';basis_sha256='';provenance=$null}
 if(-not$enabled){return $answer}
 Need ($RequiredParent-eq[guid]'371ae756-faf2-40ac-bf86-5e8e1d744e30') 'The baseline must describe the preserved source371 NTFS tree.'
 $full=[IO.Path]::GetFullPath($Path);Need ($full.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)-and$full.EndsWith('\closed\core\conversion\expectation.json',[StringComparison]::OrdinalIgnoreCase)) 'Closed archived canonical expectation under the lab base required.'
 $archive=[IO.Directory]::GetParent([IO.Directory]::GetParent([IO.Directory]::GetParent([IO.Path]::GetDirectoryName($full)).FullName).FullName).FullName
 function BaselineOrdinary([string]$File,[long]$Maximum){$f=Get-Item -LiteralPath $File -Force;Need (-not$f.PSIsContainer-and$f.Length-gt0-and$f.Length-le$Maximum) 'Bounded ordinary baseline metadata required.';$a=$f;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse baseline ancestry refused.';if($a-is[IO.DirectoryInfo]){$a=$a.Parent}else{$a=$a.Directory}};return $f}
 $index=BaselineOrdinary (Join-Path $archive 'archive.json') 1MB;$entries=@([IO.File]::ReadAllText($index.FullName)|ConvertFrom-Json)
 $specs=@(@{key='expectation';relative='conversion\expectation.json'},@{key='request';relative='conversion\request.json'},@{key='result';relative='conversion\result.json'},@{key='basis';relative='conversion\qualification\source-basis.json'})
 foreach($spec in $specs){$rows=@($entries|Where-Object {$_.role-ceq'core'-and$_.relative-ceq$spec.relative});Need ($rows.Count-eq1-and$rows[0].sha256-cmatch'\A[0-9a-f]{64}\z') 'One pinned archived baseline metadata row required.';$f=BaselineOrdinary (Join-Path (Join-Path $archive 'closed\core') $spec.relative) 64MB;$pin=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant();Need ($f.Length-eq$rows[0].bytes-and$pin-ceq$rows[0].sha256) 'Baseline metadata archive pin differs.';$answer.files[$spec.key]=@{path=$f.FullName;bytes=$f.Length;sha256=$pin}}
 Need ($answer.files.expectation.path-ceq$full-and$answer.files.expectation.sha256-ceq$Sha256) 'Explicit baseline expectation pin differs from its archive.'
 $expected=[IO.File]::ReadAllText($answer.files.expectation.path)|ConvertFrom-Json;$oldResult=[IO.File]::ReadAllText($answer.files.result.path)|ConvertFrom-Json;$oldRequest=[IO.File]::ReadAllText($answer.files.request.path)|ConvertFrom-Json;$oldBasis=[IO.File]::ReadAllText($answer.files.basis.path)|ConvertFrom-Json
 Need ($oldResult.success-eq$true-and$oldResult.source_admitted-eq$true-and$oldResult.expected_tree_sha256-ceq$Sha256-and$oldBasis.ntfs.stream_hash_bytes-gt0-and@($expected.objects).Count-gt0) 'Historical admitted full-content expectation/source inspection required.'
 $rawFlag=$oldResult.PSObject.Properties['raw_source_logical_hashes'];Need ($null-eq$rawFlag-or$rawFlag.Value-eq$true) 'Baseline explicitly omitted initial raw content hashes.'
 $defaultHashes=0;$namedHashes=0
 foreach($object in $expected.objects){$evidence=$object.PSObject.Properties['source_evidence'];Need ($null-eq$evidence-or$null-eq$evidence.Value) 'Historical baseline contains extent-only source evidence.';if(-not$object.directory){Need ($object.sha256-cmatch'\A[0-9a-f]{32}\z') 'Historical baseline lacks a complete default-stream digest.';$defaultHashes++};$streams=$object.PSObject.Properties['named_streams'];if($null-ne$streams){foreach($stream in $streams.Value){$evidence=$stream.PSObject.Properties['source_evidence'];Need ($stream.sha256-cmatch'\A[0-9a-f]{32}\z'-and($null-eq$evidence-or$null-eq$evidence.Value)) 'Historical baseline lacks a complete named-stream digest.';$namedHashes++}}}
 $answer.sha256=$Sha256;$answer.request_sha256=$answer.files.request.sha256;$answer.result_sha256=$answer.files.result.sha256;$answer.basis_sha256=$answer.files.basis.sha256
 $answer.provenance=@{scope='separately-pinned-independent-lab-content-baseline-v1';expectation_path=$full;expectation_sha256=$Sha256;archive_index_path=$index.FullName;archive_index_sha256=(Get-FileHash -LiteralPath $index.FullName -Algorithm SHA256).Hash.ToLowerInvariant();expected_source_checkpoint=$RequiredParent.ToString('D');source_binding=$oldRequest.pair.source;initial_raw_stream_hash_bytes=$oldBasis.ntfs.stream_hash_bytes;default_content_hashes=$defaultHashes;named_content_hashes=$namedHashes;metadata=$answer.files;product_expectation_mutation_authorized=$false;source_admission_authorized=$false;raw_write_authority=$false}
 return $answer
}
try{
 Need ($ExpectedParent-ne[guid]::Empty-and$ids.Count-gt0-and$ids.Count-le50-and@($ids|Sort-Object -Unique).Count-eq$ids.Count-and$ExpectedParent.ToString('D')-in$ids-and@($ExpectedCheckpointIds|Where-Object {$_-eq[guid]::Empty}).Count-eq0) 'Explicit nonempty parent and exact unique current checkpoint IDs required.'
 $toolsetDir=[IO.Path]::GetFullPath($ToolsetDirectory);$manifestPath=Join-Path $toolsetDir 'build.json';$ToolsetManifestSha256=$BuildSha256
 Need ($toolsetDir-ceq(Join-Path $base ('raw-extent-tools-'+$SourceCommit.Substring(0,7)))) 'Sealed toolset directory must match its supplied source revision.'
 $m=Get-Item -LiteralPath $manifestPath -Force;Need (-not$m.PSIsContainer-and$m.Length-gt0-and$m.Length-le1MB-and(Get-FileHash -LiteralPath $manifestPath).Hash.ToLowerInvariant()-ceq$BuildSha256) 'Build metadata pin differs.';$a=$m;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse build ancestry.';if($a-is[IO.DirectoryInfo]){$a=$a.Parent}else{$a=$a.Directory}}
 $manifest=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8|ConvertFrom-Json
 Need ($manifest.source_commit-ceq$SourceCommit-and$manifest.main_source_sha256-ceq'c6bc5c52c8458ee70bd2567a9d8350105aeaa6245448df22675780403e04348b'-and$manifest.focused_release_build_reported_passed-eq$true-and@($manifest.binaries).Count-eq4) 'Build provenance differs.'
 $required=@('lab-convert-native-composite.exe','ntfs2refs.exe','ntfs2refs-bind.exe','lab-content-digest.exe')
 function Binary([string]$Name){$rows=@($manifest.binaries|Where-Object name -CEQ $Name);Need ($rows.Count-eq1-and$rows[0].bytes-gt0-and$rows[0].bytes-le16MB-and$rows[0].sha256-cmatch'\A[0-9a-f]{64}\z') 'Pinned build executable entry is missing, duplicated or exceeds bounds.';$path=Join-Path $toolsetDir $Name;$f=Get-Item -LiteralPath $path -Force;Need (-not$f.PSIsContainer-and-not($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$f.Length-eq$rows[0].bytes-and(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-ceq$rows[0].sha256) 'Sealed executable differs.';return @{name=$Name;path=$path;bytes=$rows[0].bytes;sha256=$rows[0].sha256}}
 $allTools=@(foreach($name in $required){Binary $name});$tool=@($allTools|Where-Object name -CEQ 'ntfs2refs.exe')[0];$digest=@($allTools|Where-Object name -CEQ 'lab-content-digest.exe')[0]
 Need ($BaselineSha256-ceq'2b132b71025db2eb5cc508f538e96760cab951172e7b31f842cc519659bc7a15') 'The separately pinned full-content H source baseline is required.'
 $baseline=ReadLabBaselineHost $BaselinePath $BaselineSha256 ([guid]'371ae756-faf2-40ac-bf86-5e8e1d744e30')
 Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force;$configuration=Get-LabConfiguration -WorkspaceRoot $workspace;$capacity=Get-LabCapacity -Configuration $configuration
 Need ($capacity.MaximumActualBytes-eq329374052988-and$capacity.MinimumFreeBytes-eq17179869184) 'Fixed storage epoch differs.';Assert-LabCapacity -Capacity $capacity -AdditionalBytes $ForecastAdditionalBytes
 Host-Guard;Need (-not(Test-Path -LiteralPath $root)) 'Fresh host case required.';New-Item -ItemType Directory -Path $root|Out-Null;$created=$true
 $cli=@('--recover',$RecoveryDirectory,'--recovery-sha256',$RecoverySha256);if($Rollback){$cli+='--rollback'}
 $c=@{baseline_enabled=$true;baseline_sha256=$baseline.sha256;baseline_request_sha256=$baseline.request_sha256;baseline_result_sha256=$baseline.result_sha256;baseline_basis_sha256=$baseline.basis_sha256;digest_sha256=$digest.sha256;digest_bytes=$digest.bytes;run_id=$run;stage=$stage;task=$task;binary_sha256=$tool.sha256;binary_bytes=$tool.bytes;cli=$cli;operation=$operation;recovery_directory=$RecoveryDirectory;recovery_sha256=$RecoverySha256}
 Save 'intent.json' @{schema_version=1;kind='extent-identity-public-recovery-intent';run_id=$run;operation=$operation;parent_id=$ExpectedParent.ToString('D');checkpoint_ids=$ids;toolset_manifest=$manifestPath;toolset_manifest_sha256=$ToolsetManifestSha256;source_commit=$SourceCommit;tool=$tool;cli=$cli;stdin='yes CRLF';capacity=$capacity;forecast_bytes=$ForecastAdditionalBytes;forecast_is_not_reservation=$true;automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')}
 $body=@'
Set-StrictMode -Version Latest; $ErrorActionPreference='Stop'
$c=[Text.UTF8Encoding]::new($false).GetString([Convert]::FromBase64String('__CONFIG__'))|ConvertFrom-Json
$phase='preflight';$nativeExit=$null;$process=$null
function Need([bool]$Ok,[string]$Message){if(-not $Ok){throw $Message}}
function Save([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14));Need ($b.Length-le1MB) 'Wrapper receipt exceeds1MiB.';$f=[IO.File]::Open((Join-Path $c.stage $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Json([string]$Path,[long]$Limit=4MB){Need ($Path.StartsWith('C:\',[StringComparison]::OrdinalIgnoreCase)-and$Path.EndsWith('.json',[StringComparison]::Ordinal)) 'Closed C JSON metadata only.';$m=Get-Item -LiteralPath $Path -Force;Need (-not$m.PSIsContainer-and-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$m.Length-gt0-and$m.Length-le$Limit) 'Bounded ordinary C JSON required.';$a=$m.Directory;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse C metadata ancestry.';$a=$a.Parent};Get-Content -LiteralPath $Path -Raw -Encoding UTF8|ConvertFrom-Json}
function Log([string]$Path){$m=Get-Item -LiteralPath $Path -Force;Need ($m.Length-le8MB) 'Bounded native log required.';@{bytes=$m.Length;sha256=(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant();text=[IO.File]::ReadAllText($Path)}}
function Protected{$g=Get-Disk -Number 4;$gp=Get-Partition -DriveLetter G;$gv=$gp|Get-Volume;$t=Get-Disk -Number 5;Need ([guid]$g.Guid-eq[guid]'e1f3b9d3-979f-4123-9fee-399640c25092'-and-not$g.IsOffline-and-not$g.IsReadOnly-and$gp.DiskNumber-eq4-and[guid]$gp.Guid-eq[guid]'21445e3a-b435-4978-ba01-2ae217f66f6a'-and$gv.FileSystem-ceq'ReFS'-and$gv.AllocationUnitSize-eq4096-and[guid]$t.Guid-eq[guid]'ad077674-6305-4767-a2aa-6ded3b707e36'-and$t.IsOffline-and$t.IsReadOnly) 'Protected G4/shadow5 changed.'}
function Idle{Need (@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-eq0-and@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.TaskName-cne$c.task-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-eq0) 'Another project worker/task is active.'}
function SameArray($Left,$Right){$a=@($Left);$b=@($Right);if($a.Count-ne$b.Count){return $false};for($i=0;$i-lt$a.Count;$i++){if($a[$i]-cne$b[$i]){return $false}};return $true}
function SameJsonValue($Left,$Right){
 if($null-eq$Left-or$null-eq$Right){return ($null-eq$Left-and$null-eq$Right)}
 if($Left-is[Collections.IList]-or$Right-is[Collections.IList]){if(-not($Left-is[Collections.IList])-or-not($Right-is[Collections.IList])-or$Left.Count-ne$Right.Count){return $false};for($i=0;$i-lt$Left.Count;$i++){if(-not(SameJsonValue $Left[$i] $Right[$i])){return $false}};return $true}
 if($Left-is[pscustomobject]-or$Right-is[pscustomobject]){if(-not($Left-is[pscustomobject])-or-not($Right-is[pscustomobject])){return $false};$names=@($Left.PSObject.Properties|ForEach-Object {[string]$_.Name});$other=@($Right.PSObject.Properties|ForEach-Object {[string]$_.Name});if($names.Count-ne$other.Count){return $false};foreach($name in $names){$property=$Right.PSObject.Properties[$name];if($null-eq$property-or-not(SameJsonValue $Left.PSObject.Properties[$name].Value $property.Value)){return $false}};return $true}
 return ($Left.GetType()-eq$Right.GetType()-and$Left-ceq$Right)
}
function LabStream($Object,$Name){
 if(@($Name).Count-eq0){return $Object}
 $property=$Object.PSObject.Properties['named_streams'];Need ($null-ne$property) 'Independent baseline named stream collection missing.';$matches=@($property.Value|Where-Object {SameArray $_.name_utf16 $Name});Need ($matches.Count-eq1) 'Independent baseline stream missing/ambiguous.';return $matches[0]
}
function LabSnapshotQuery($Snapshot,[int]$Class,[int]$Length){
 $q=@($Snapshot.queries|Where-Object class -eq $Class)
 Need ($q.Count-eq1-and$null-eq$q[0].native_error-and@($q[0].bytes).Count-eq$Length) 'Frozen-source timestamp query missing/refused.'
 return ,[byte[]]$q[0].bytes
}
function LabSnapshotTimes($Snapshot){$b=LabSnapshotQuery $Snapshot 0 40;return ,@([BitConverter]::ToUInt64($b,0),[BitConverter]::ToUInt64($b,8),[BitConverter]::ToUInt64($b,16),[BitConverter]::ToUInt64($b,24))}
function ReconcileRecoveryBaselineAccess($Current,$Old,$Context){
 if($Current.stored_times[1]-eq$Old.stored_times[1]){return $null}
 $raw=@($Context.raw.ntfs.files|Where-Object {$_.record_number-eq$Current.record_number-and$_.sequence_number-eq$Current.sequence_number})
 $source=@($Context.native.files|Where-Object {$_.identity.record_number-eq$Current.record_number-and$_.identity.sequence_number-eq$Current.sequence_number})
 $view=@($Context.views.assessment.source_view.objects|Where-Object {$_.record_number-eq$Current.record_number-and$_.sequence_number-eq$Current.sequence_number})
 Need ($raw.Count-eq1-and$source.Count-eq1-and$null-eq$source[0].open_error-and$view.Count-eq1-and$view[0].metadata.matched-eq$true) 'Frozen-source timestamp provenance is incomplete.'
 $si=$raw[0].standard_information;$stored=@($si.creation_time,$si.access_time,$si.modification_time,$si.mft_change_time)
 Need (SameArray $stored $Current.stored_times) 'Recovery expectation times differ from the original frozen raw source.'
 $sb=LabSnapshotTimes $source[0].before;$sa=LabSnapshotTimes $source[0].after;$sv=$view[0].timestamps
 Need ($null-ne$sv-and(SameArray $sv.stored $stored)-and(SameArray $sv.native_before $sb)-and(SameArray $sv.native_after $sa)-and$sv.preservation_authority-ceq'persisted STANDARD_INFORMATION after freeze; requires actual unchanged read-only source') 'Frozen native timestamp views are not bound to the persisted source.'
 foreach($at in @(0,2,3)){Need ($sb[$at]-eq$stored[$at]-and$sa[$at]-eq$stored[$at]) 'Frozen source differs outside the recorded cached-access policy.'}
 $cached=$sb[1]-ne$stored[1]-or$sa[1]-ne$stored[1];Need ($sv.cached_access_differs-eq$cached) 'Frozen cached-access record differs.'
 $sourceId=LabSnapshotQuery $source[0].before 18 24;$sourceAfter=LabSnapshotQuery $source[0].after 18 24
 Need (SameArray $sourceId $sourceAfter) 'Frozen source identity changed.'
 $reference=[BitConverter]::ToUInt64($sourceId,8)
 Need (($reference-band[uint64]281474976710655)-eq$Current.record_number-and[uint16]($reference-shr48)-eq$Current.sequence_number) 'Frozen timestamp source identity differs from the canonical record.'
 $targetBefore=$null;$targetAfter=$null;$targetId=$null;$exception=$null
 if($Context.compare_target){
  $targets=@($Context.completion.native.native.objects|Where-Object {SameArray $_.components $Current.path})
  Need ($Context.completion.success-eq$true-and$targets.Count-eq1) 'Recovered target timestamp evidence is incomplete.'
  $targetBefore=LabSnapshotTimes $targets[0].before;$targetAfter=LabSnapshotTimes $targets[0].after
  $targetId=LabSnapshotQuery $targets[0].before 18 24;$targetAfterId=LabSnapshotQuery $targets[0].after 18 24
  Need (SameArray $targetId $targetAfterId) 'Recovered target identity changed.'
  if(-not((SameArray $targetBefore $stored)-and(SameArray $targetAfter $stored))){
   $p=$Context.completion.native.native.PSObject.Properties['post_mount_indexer_cache'];$cache=$null;if($null-ne$p){$cache=$p.Value}
   Need ($Current.directory-eq$true-and(SameArray $Current.path @('System Volume Information'))-and$null-ne$cache-and(SameArray $targetBefore $targetAfter)-and$targetBefore[0]-eq$stored[0]) 'Recovered target must preserve current frozen times.'
   $cacheTimes=LabSnapshotTimes $cache.before
   Need ($cacheTimes[0]-ge$stored[3]-and$cacheTimes[0]-le$cache.observed_filetime) 'Source-absent cache does not justify this directory time interval.'
   foreach($at in @(1,2,3)){Need ($targetBefore[$at]-ge$stored[$at]-and$targetBefore[$at]-le$cache.observed_filetime) 'Recovered SVI time lies outside its observed cache interval.'}
   $exception='existing-source-absent-indexer-cache-SVI-directory-times'
  }
 }
 return @{record_number=$Current.record_number;sequence_number=$Current.sequence_number;path=$Current.path;old_baseline_access_time=$Old.stored_times[1];current_frozen_raw_times=$stored;current_canonical_times=@($Current.stored_times);frozen_native_before=$sb;frozen_native_after=$sa;frozen_cached_access_differs=$cached;frozen_source_metadata_matched=$true;frozen_source_file_id_hex=([BitConverter]::ToString($sourceId)).Replace('-','').ToLowerInvariant();recovered_target_before=$targetBefore;recovered_target_after=$targetAfter;recovered_target_file_id_hex=$(if($null-ne$targetId){([BitConverter]::ToString($targetId)).Replace('-','').ToLowerInvariant()}else{$null});recovered_target_times_compared=$Context.compare_target;target_timestamp_exception=$exception;rollback_timestamp_restoration_authority=$(if($Context.compare_target){$null}else{'complete closed old-selected-byte journal proof; independent post-rollback timestamp comparison not claimed'});comparison_only_old_access_alignment=$true;product_expectation_changed=$false;filesystem_times_changed=$false}
}
function ResolveLabContentBaseline($Expected,$Request,[string]$Records,$Completion,[string]$RecoveryRecords){
 $hashless=0;foreach($object in $Expected.objects){if(-not$object.directory-and$null-eq$object.sha256){$hashless++};$property=$object.PSObject.Properties['named_streams'];if($null-ne$property){foreach($stream in $property.Value){if($null-eq$stream.sha256){$hashless++}}}}
 if(-not$c.baseline_enabled){Need ($hashless-eq0) 'Hashless expectations require a separately pinned historical full-content lab baseline.';return @{enabled=$false;observer_expectation=$Expected;product_expectation=$Expected;receipt=@{scope='lab-content-baseline-v1';baseline_used=$false;hashless_product_streams=0;product_expectation_written=$false;grants_product_authority=$false}}}
 $paths=@(@{name='lab-full-content-baseline.json';pin=$c.baseline_sha256},@{name='lab-baseline-request.json';pin=$c.baseline_request_sha256},@{name='lab-baseline-result.json';pin=$c.baseline_result_sha256},@{name='lab-baseline-source-basis.json';pin=$c.baseline_basis_sha256})
 foreach($spec in $paths){Need ((Get-FileHash -LiteralPath (Join-Path $c.stage $spec.name) -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$spec.pin) 'Independent lab baseline artifact pin differs.'}
 $baseline=Json (Join-Path $c.stage 'lab-full-content-baseline.json');$oldRequest=Json (Join-Path $c.stage 'lab-baseline-request.json');$oldResult=Json (Join-Path $c.stage 'lab-baseline-result.json');$oldBasis=Json (Join-Path $c.stage 'lab-baseline-source-basis.json')
 Need ($oldResult.success-eq$true-and$oldResult.source_admitted-eq$true-and$oldResult.expected_tree_sha256-ceq$c.baseline_sha256-and(SameJsonValue $oldRequest.pair.source $Request.pair.source)) 'Historical full-content baseline source binding/result differs.'
 $rawFlag=$oldResult.PSObject.Properties['raw_source_logical_hashes'];Need ($null-eq$rawFlag-or$rawFlag.Value-eq$true) 'Historical baseline must retain initial raw logical hashes.'
 $oldRaw=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
 foreach($file in $oldBasis.ntfs.files){$key=([string]$file.record_number)+':'+([string]$file.sequence_number);Need (-not$oldRaw.ContainsKey($key)) 'Duplicate historical raw source identity.';$oldRaw.Add($key,$file)}
 $timeContext=@{raw=(Json (Join-Path $Records 'qualification\source-basis.json') 64MB);native=(Json (Join-Path $Records 'qualification\native-source.json') 64MB);views=(Json (Join-Path $Records 'qualification\source-assessment.json') 64MB);completion=$Completion;compare_target=($c.operation-ceq'resume')}
 $timeRows=[Collections.Generic.List[object]]::new()
 $copy=($Expected|ConvertTo-Json -Depth 64)|ConvertFrom-Json;$oldObjects=@($baseline.objects);Need (@($copy.objects).Count-eq$oldObjects.Count) 'Independent baseline canonical object coverage differs.';$elisions=[Collections.Generic.List[object]]::new()
 foreach($object in $copy.objects){
  $matches=@($oldObjects|Where-Object {$_.record_number-eq$object.record_number-and$_.sequence_number-eq$object.sequence_number-and(SameArray $_.path $object.path)});Need ($matches.Count-eq1) 'Independent baseline canonical identity/path differs.';$old=$matches[0]
  $timeProof=ReconcileRecoveryBaselineAccess $object $old $timeContext;if($null-ne$timeProof){$timeRows.Add($timeProof);$object.stored_times[1]=$old.stored_times[1]}
  if($object.directory){continue}
  $rawKey=([string]$old.record_number)+':'+([string]$old.sequence_number);Need ($oldRaw.ContainsKey($rawKey)) 'Historical baseline raw source object missing.';$rawFile=$oldRaw[$rawKey]
  $names=[Collections.Generic.List[object]]::new();$names.Add(@());$property=$object.PSObject.Properties['named_streams'];if($null-ne$property){foreach($stream in $property.Value){$names.Add(@($stream.name_utf16))}}
  foreach($name in $names){
   $current=LabStream $object $name;$known=LabStream $old $name;Need ($known.sha256-cmatch'\A[0-9a-f]{32}\z') 'Every historical baseline stream requires a full content digest.'
   $oldEvidence=$known.PSObject.Properties['source_evidence'];Need ($null-eq$oldEvidence-or$null-eq$oldEvidence.Value) 'Historical lab baseline contains an extent-only expectation.'
   $rawStreams=@($rawFile.streams|Where-Object {SameArray $_.name_utf16 $name});Need ($rawStreams.Count-eq1-and$rawStreams[0].logical_hash_status-ceq'complete'-and$rawStreams[0].logical_sha256-ceq$known.sha256-and$rawStreams[0].logical_size-eq$known.length) 'Historical baseline digest is not tied to its full raw inspection.'
   $evidence=$current.PSObject.Properties['source_evidence']
   if($null-eq$current.sha256){Need ($null-ne$evidence-and$evidence.Value-ceq'extent_identity_v1'-and$current.length-gt0-and$current.length%4096-eq0) 'Only explicitly extent-bound product streams may lack a content expectation.';$elisions.Add(@{record_number=$object.record_number;sequence_number=$object.sequence_number;path=$object.path;name_utf16=@($name);length=$current.length;independent_expected_content_digest=$known.sha256});$current.sha256=$known.sha256;$current.PSObject.Properties.Remove('source_evidence')}
   else{Need ($null-eq$evidence) 'A complete digest must not also claim extent-only source evidence.'}
  }
 }
 Need (SameJsonValue $copy $baseline) 'Canonical baseline differs beyond explicit extent evidence, absent digests and separately recorded access times.'
 $newNative=$null # Recovery does not grant fresh source admission from a historical report.
 return @{enabled=$true;observer_expectation=$copy;product_expectation=$Expected;baseline=$baseline;baseline_basis=$oldBasis;baseline_raw_by_identity=$oldRaw;native_source=$newNative;receipt=@{scope='lab-content-baseline-v1';baseline_used=$true;baseline_sha256=$c.baseline_sha256;baseline_request_sha256=$c.baseline_request_sha256;baseline_result_sha256=$c.baseline_result_sha256;baseline_source_basis_sha256=$c.baseline_basis_sha256;canonical_metadata_exact_except_explicit_content_evidence=($timeRows.Count-eq0);canonical_metadata_exact_except_content_evidence_and_recorded_access_times=$true;current_access_time_reconciliations=$timeRows.ToArray();timestamp_provenance_pins=@{source_basis=(Get-FileHash -LiteralPath (Join-Path $Records 'qualification\source-basis.json')).Hash.ToLowerInvariant();native_source=(Get-FileHash -LiteralPath (Join-Path $Records 'qualification\native-source.json')).Hash.ToLowerInvariant();source_assessment=(Get-FileHash -LiteralPath (Join-Path $Records 'qualification\source-assessment.json')).Hash.ToLowerInvariant();expectation=(Get-FileHash -LiteralPath (Join-Path $Records 'expectation.json')).Hash.ToLowerInvariant();recovery_result=(Get-FileHash -LiteralPath (Join-Path $RecoveryRecords 'result.json')).Hash.ToLowerInvariant();recovery_completion=(Get-FileHash -LiteralPath (Join-Path $RecoveryRecords 'completion.json')).Hash.ToLowerInvariant()};post_rollback_native_timestamp_comparison_claimed=$false;historical_digests_bound_to_full_raw_inspection=$true;source_binding_identical=$true;hashless_product_streams=$hashless;comparison_streams_restored=$elisions.Count;comparison_only_clone=$true;product_expectation_written=$false;grants_product_authority=$false;elided_streams=$elisions.ToArray()}}
}
try{
    Idle;Protected;$d=Get-Disk -Number 6;Need ([guid]$d.Guid-eq[guid]'f95141cb-fe7e-439a-a82b-c2b3f55965d2'-and$d.IsOffline-and-not$d.IsReadOnly) 'Interrupted activated source6 (offline, writable attributes) required.'
    $part=Get-Partition -DiskNumber 6 -PartitionNumber 2;Need ($env:SystemDrive-ceq'C:'-and$d.Size-eq56GB-and-not$d.IsBoot-and-not$d.IsSystem-and[guid]$part.Guid-eq[guid]'f77d3d8f-9a87-464d-a7de-e1b77604da7b'-and$part.Offset-eq32MB-and$part.Size-eq52GB-and(Get-Partition -DriveLetter C).DiskNumber-eq0) 'Interrupted exact H GPT/geometry or C journal route differs.'
    $binary=Join-Path $c.stage 'ntfs2refs.exe';Need ((Get-Item -LiteralPath $binary).Length-eq$c.binary_bytes-and(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()-ceq$c.binary_sha256) 'Pinned public main differs.'
    $bundlePath=Join-Path $c.recovery_directory 'allocation-recovery-bundle.json';$bundle=Json $bundlePath 65536
    Need ((Get-FileHash -LiteralPath $bundlePath).Hash.ToLowerInvariant()-ceq$c.recovery_sha256-and$bundle.schema_version-eq1-and$bundle.kind-ceq'allocation-bounded-recovery-bundle'-and$bundle.serialized_bundle_grants_recovery_authority-eq$false) 'Pinned allocation recovery bundle differs.'
    $request=Json (Join-Path $c.recovery_directory 'request.json') 131072;$mapPath=Join-Path $c.recovery_directory 'recovery-payload-manifest.json';$maps=Json $mapPath 64MB
    Need ($request.schema_version-eq3-and$request.verification_policy-ceq'extent_identity_v1'-and$request.pair.source.disk_number-eq6-and[guid]$request.pair.source.identity.disk_guid-eq[guid]'f95141cb-fe7e-439a-a82b-c2b3f55965d2'-and[guid]$request.pair.source.identity.partition_guid-eq[guid]'f77d3d8f-9a87-464d-a7de-e1b77604da7b'-and$request.pair.source.identity.disk_bytes-eq56GB-and$request.pair.source.identity.partition_bytes-eq52GB-and$request.pair.source.identity.partition_offset-eq32MB-and$null-ne$bundle.recovery_payload_manifest-and$bundle.recovery_payload_manifest.path-ceq$mapPath-and$bundle.recovery_payload_manifest.sha256-ceq(Get-FileHash -LiteralPath $mapPath).Hash.ToLowerInvariant()-and$maps.kind-ceq'protected-target-stream-map-facts-v1'-and$maps.grants_write_authority-eq$false) 'Pinned H source or hash-free recovery manifest differs.'
    foreach($spec in @(@{key='request';name='request.json';limit=131072},@{key='plan';name='selected-plan.json';limit=16MB},@{key='ticket';name='selected-ticket.json';limit=65536},@{key='verification';name='verification.json';limit=1MB})){ $path=Join-Path $c.recovery_directory $spec.name;$null=Json $path $spec.limit;Need ($bundle.($spec.key).path-ceq$path-and$bundle.($spec.key).sha256-ceq(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()) 'Original bundle metadata pin differs.' }
    $origin=Split-Path -Parent $c.recovery_directory;$interruption=Json (Join-Path $origin 'wrapper-controlled-interruption.json');$originalProcess=Json (Join-Path $origin 'converter-process.json');$originalTerminal=Json (Join-Path $origin 'converter-terminal.json')
    Need ($interruption.controlled_interruption_observed-eq$true-and$interruption.native_exit-eq86-and$interruption.bundle_sha256-ceq$c.recovery_sha256-and$originalProcess.pid-gt0-and$originalProcess.creation_ms-gt0-and$originalTerminal.pid-eq$originalProcess.pid-and$originalTerminal.creation_ms-eq$originalProcess.creation_ms-and$originalTerminal.native_exit-eq86-and$originalTerminal.native_exit_observed-eq$true) 'Actual original native process/exit86 publication missing.'
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
    Save 'native-terminal.json' @{pid=$process.Id;creation_ms=([DateTimeOffset]$process.StartTime).ToUnixTimeMilliseconds();native_exit=$nativeExit;native_exit_observed=($null-ne$nativeExit);stdout=$out;stderr=$err;utc=[DateTime]::UtcNow.ToString('o')}
    Need ($null-ne$nativeExit-and$nativeExit-eq0) ('Public recovery did not exit 0: '+$nativeExit)
    $phase='closed-recovery-evidence';$expectedLine=if($c.operation-ceq'rollback'){'NTFS rollback completed[.]'}else{'ReFS recovery completed[.]'}
    $done=[regex]::Matches($out.text,'(?m)^'+$expectedLine+' Recovery records: (C:\\ProgramData\\ntfs2refs\\runs\\recovery-[0-9a-f]{32})[ \t]*\r?$');Need ($done.Count-eq1) 'One actual completion line for the requested direction required.'
    $records=Join-Path $done[0].Groups[1].Value $c.operation;$result=Json (Join-Path $records 'result.json');$completion=Json (Join-Path $records 'completion.json') 64MB
    $v=Get-Volume -DriveLetter H;$d=Get-Disk -Number 6
    if($c.operation-ceq'rollback'){
        Need ($result.success-eq$true-and$result.outcome-ceq'ntfs_restored'-and$completion.mounted_filesystem-ceq'NTFS'-and$v.FileSystem-ceq'NTFS'-and$v.AllocationUnitSize-eq4096-and$v.FileSystemLabel-ceq'n2r-links-source'-and-not$d.IsOffline) 'Restored NTFS source/label/online state differs.'
        $rollbackProof=Json (Join-Path $records 'rollback.json');$originalTicket=Json (Join-Path $c.recovery_directory 'selected-ticket.json') 65536
        Need ($rollbackProof.replay_closed-eq$true-and$rollbackProof.whole_image_verified-eq$false-and$rollbackProof.selected_bytes-eq$originalTicket.selected_bytes-and$rollbackProof.range_count-eq$originalTicket.range_count-and(SameArray $rollbackProof.selected_sha256 $originalTicket.old_selected_sha256)) 'Actual closed rollback journal proof differs from the pinned old selected digest.'
        $summary=@{mounted='NTFS';objects=$null;hashes=$null;expected_objects=$expectedObjects.Count;expected_files=$expectedFiles.Count;post_mount_content_hashes_checked=$false;closed_selected_journal_proof=(Get-FileHash -LiteralPath (Join-Path $records 'rollback.json')).Hash.ToLowerInvariant()}

    }else{
        Need ($result.success-eq$true-and$result.outcome-ceq'refs_completed'-and$completion.success-eq$true-and$completion.rollback_closed-eq$true-and$v.FileSystem-ceq'ReFS'-and$v.AllocationUnitSize-eq4096-and$v.FileSystemLabel-ceq'n2r-links-source'-and-not$d.IsOffline) 'Recovered ReFS source/label/online state differs.'
        $objects=@($completion.native.native.objects);Need ($objects.Count-eq$expectedObjects.Count) 'Recovered native object count differs.';$known=0;$unknown=0;$knownBytes=0L
        foreach($object in $expectedObjects){$matches=@($objects|Where-Object {SameArray $_.components $object.path});Need ($matches.Count-eq1) 'Expected recovered path missing/duplicated.';$native=$matches[0]
            if(-not$object.directory){if($null-ne$object.sha256){Need ($native.logical_sha256-ceq$object.sha256) 'Known recovered default digest differs.';$known++;$knownBytes+=[long]$object.length}else{Need ($null-eq$native.logical_sha256-and$object.source_evidence-ceq'extent_identity_v1') 'Unread default content must remain explicitly extent-only.';$unknown++}}
            $ns=$object.PSObject.Properties['named_streams'];if($null-ne$ns){foreach($stream in $ns.Value){$found=@($native.named_streams|Where-Object {SameArray $_.name_utf16 $stream.name_utf16});Need ($found.Count-eq1) 'Recovered ADS missing/duplicated.';if($null-ne$stream.sha256){Need ($found[0].logical_sha256-ceq$stream.sha256) 'Known recovered ADS digest differs.';$known++;$knownBytes+=[long]$stream.length}else{Need ($null-eq$found[0].logical_sha256-and$stream.source_evidence-ceq'extent_identity_v1') 'Unread ADS must remain explicitly extent-only.';$unknown++}}}
        }
        $extentPath=Join-Path $records 'recovery-extent-verification.json';$receipt=Json $extentPath 1MB;$handoff=Json (Join-Path $records 'handoff.json')
        Need ($result.actual_verification_scope-ceq'pinned_extent_identity_v1'-and$result.full_content_hashes_compared-eq$false-and$result.original_unread_content_digest_reconstructed-eq$false-and$receipt.all_complete_maps_identical-eq$true-and$receipt.handoff_replay_closed-eq$true-and$receipt.known_content_streams_hashed-eq$known-and$receipt.known_content_payload_bytes_read-eq$knownBytes-and$receipt.extent_only_streams-eq$unknown-and$unknown-gt0-and$handoff.replay_closed-eq$true-and([BitConverter]::ToString([byte[]]$handoff.selected_sha256)).Replace('-','').ToLowerInvariant()-ceq$receipt.selected_sha256) 'Actual closed journal/map-facts/known-content recovery receipt differs.'
        $summary=@{mounted='ReFS';objects=$objects.Count;known_content_hashes=$known;known_content_bytes=$knownBytes;extent_only_streams=$unknown;all_complete_maps_identical=$true;full_content_hashes_compared=$false;closed_selected_journal_proof=(Get-FileHash -LiteralPath (Join-Path $records 'handoff.json')).Hash.ToLowerInvariant()}
    }
    Protected;Idle
    $baselineContext=ResolveLabContentBaseline $expected $request $c.recovery_directory $completion $records;$labExpected=$baselineContext.observer_expectation;Save 'lab-baseline-binding.json' $baselineContext.receipt
    $paths=[Collections.Generic.List[string]]::new();$wants=[Collections.Generic.List[string]]::new();$names=[Collections.Generic.List[object]]::new();$backup=[Collections.Generic.List[bool]]::new()
    foreach($object in $labExpected.objects){if($object.directory){continue};$compression=$object.PSObject.Properties['ntfs_compression_normalized'];$useBackup=-not($c.operation-ceq'rollback'-and$null-ne$compression-and$compression.Value-eq$true);$base='H:\'+($object.path-join'\');$paths.Add($base);$wants.Add($object.sha256);$backup.Add($useBackup);$names.Add(@{path=$object.path;name_utf16=@();length=$object.length});$property=$object.PSObject.Properties['named_streams'];if($null-ne$property){foreach($stream in $property.Value){$chars=[char[]]@($stream.name_utf16|ForEach-Object {[char]$_});$paths.Add($base+':'+[string]::new($chars)+':$DATA');$wants.Add($stream.sha256);$backup.Add($useBackup);$names.Add(@{path=$object.path;name_utf16=$stream.name_utf16;length=$stream.length})}}}
    Need ($paths.Count-gt0-and$paths.Count-le1024) 'Bounded independent all-stream baseline required.'
    $digestPath=Join-Path $c.stage 'lab-content-digest.exe';Need ((Get-Item -LiteralPath $digestPath).Length-eq$c.digest_bytes-and(Get-FileHash -LiteralPath $digestPath).Hash.ToLowerInvariant()-ceq$c.digest_sha256) 'Independent observer binary differs.'
    $actual=[string[]]::new($paths.Count)
    # The sealed backup observer refuses encoded source attributes. Only the
    # independently declared compression-normalized NTFS subset uses ordinary
    # logical File reads; NTFS performs decompression. No raw data is decoded here.
    foreach($useBackup in @($true,$false)){
        $indices=@(for($i=0;$i-lt$paths.Count;$i++){if($backup[$i]-eq$useBackup){$i}});if($indices.Count-eq0){continue}
        $argv=@();$role='baseline-compressed-source';if($useBackup){$argv=@('--backup-read');$role='baseline-backup'};foreach($index in $indices){$argv+=$paths[$index]}
        $quoted=($argv|ForEach-Object {Need ($_-cnotmatch'["\r\n\x00]') 'Unsafe content observer argument.';'"'+$_+'"'})-join' ';Need ($quoted.Length-lt30000) 'Content observer command exceeds the native command-line bound.'
        $digestOut=Join-Path $c.stage ($role+'.stdout.log');$digestErr=Join-Path $c.stage ($role+'.stderr.log');$reader=$null
        try{$reader=Start-Process -FilePath $digestPath -ArgumentList $quoted -WorkingDirectory $c.stage -RedirectStandardOutput $digestOut -RedirectStandardError $digestErr -PassThru -WindowStyle Hidden;$null=$reader.Handle;Save ($role+'-process.json') @{pid=$reader.Id;creation_ms=([DateTimeOffset]$reader.StartTime).ToUnixTimeMilliseconds();binary_sha256=$c.digest_sha256;streams=$indices.Count;backup_read=$useBackup;read_only=$true};$reader.WaitForExit();$reader.Refresh();$digestExit=$reader.ExitCode;Save ($role+'-terminal.json') @{pid=$reader.Id;creation_ms=([DateTimeOffset]$reader.StartTime).ToUnixTimeMilliseconds();native_exit=$digestExit;native_exit_observed=($null-ne$digestExit);stdout=(Log $digestOut);stderr=(Log $digestErr)};Need ($null-ne$digestExit-and$digestExit-eq0) 'Independent content observer did not exit0.'}finally{if($null-ne$reader){$reader.Dispose()}}
        $part=@([IO.File]::ReadAllText($digestOut)|ConvertFrom-Json|ForEach-Object {$_});Need ($part.Count-eq$indices.Count) 'Independent content observer stream count differs.'
        for($i=0;$i-lt$indices.Count;$i++){$actual[$indices[$i]]=$part[$i]}
    }
    for($i=0;$i-lt$actual.Count;$i++){Need ($wants[$i]-cmatch'\A[0-9a-f]{32}\z'-and$actual[$i]-ceq$wants[$i]) ('Independent complete stream digest differs at ordinal '+$i)}
    Save 'independent-content-verification.json' @{success=$true;scope='lab-only-independent-full-content-baseline-v1';baseline_sha256=$c.baseline_sha256;streams=$actual.Count;rows=$names.ToArray();digests=$actual;hash_algorithm='xxh3-128';product_expectation_written=$false;grants_product_authority=$false}
    $summary['independent_full_stream_hashes']=$actual.Count;Protected;Idle
    Save 'wrapper-result.json' @{schema_version=1;kind='extent-identity-public-recovery-observation';success=$true;run_id=$c.run_id;operation=$c.operation;native_exit=$nativeExit;recovery_records=$records;observed_lifecycle=$result.observed_lifecycle;action=$result.action;outcome=$result.outcome;summary=$summary;expectation_path=$expectationPath;expectation_sha256=$expectationPin;expectation_is_evidence_not_replay_authority=$true;result_sha256=(Get-FileHash -LiteralPath (Join-Path $records 'result.json')).Hash.ToLowerInvariant();completion_sha256=(Get-FileHash -LiteralPath (Join-Path $records 'completion.json')).Hash.ToLowerInvariant();utc=[DateTime]::UtcNow.ToString('o')}
}catch{Save 'wrapper-failed.json' @{success=$false;run_id=$c.run_id;phase=$phase;native_exit=$nativeExit;error=$_.Exception.ToString();automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')};throw}
finally{if($null-ne$process){$process.Dispose()}}
'@
 $body=$body.Replace('__CONFIG__',[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes(($c|ConvertTo-Json -Depth 6 -Compress))))
 $wrapperPath=Join-Path $root 'guest-wrapper.ps1';[IO.File]::WriteAllText($wrapperPath,$body,[Text.UTF8Encoding]::new($false));$wrapperPin=(Get-FileHash -LiteralPath $wrapperPath).Hash.ToLowerInvariant()
 $session=New-PSSession -VMId $id -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')) -ErrorAction Stop
 $ready=Invoke-Command -Session $session -ArgumentList $stage,$task,$RecoveryDirectory -ScriptBlock {param($Stage,$Task,$Directory)
  $ErrorActionPreference='Stop';if(Test-Path -LiteralPath $Stage){throw 'Fresh guest stage required.'};if(@(Get-ScheduledTask|Where-Object TaskName -CEQ $Task).Count){throw 'Fresh task required.'}
  if(-not(Test-Path -LiteralPath (Join-Path $Directory 'allocation-recovery-bundle.json'))-or(Test-Path -LiteralPath (Join-Path $Directory 'compact-recovery-bundle.json'))){throw 'Only the allocation recovery bundle must exist in the recovery directory.'}
  $d=Get-Disk -Number 6;if([guid]$d.Guid-ne[guid]'f95141cb-fe7e-439a-a82b-c2b3f55965d2'-or-not$d.IsOffline-or$d.IsReadOnly){throw 'Interrupted activated source6 required.'}
  New-Item -ItemType Directory -Path $Stage|Out-Null;@{fresh_stage=$Stage;source_offline=$true;source_readonly=$false;bundle_present=$true;utc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'ready.json' $ready
 Copy-Item -LiteralPath $digest.path -ToSession $session -Destination (Join-Path $stage 'lab-content-digest.exe')
 foreach($spec in @(@{key='expectation';name='lab-full-content-baseline.json'},@{key='request';name='lab-baseline-request.json'},@{key='result';name='lab-baseline-result.json'},@{key='basis';name='lab-baseline-source-basis.json'})){Copy-Item -LiteralPath $baseline.files[$spec.key].path -ToSession $session -Destination (Join-Path $stage $spec.name)}
 Copy-Item -LiteralPath $tool.path -ToSession $session -Destination (Join-Path $stage 'ntfs2refs.exe');Copy-Item -LiteralPath $wrapperPath -ToSession $session -Destination (Join-Path $stage 'wrapper.ps1');Host-Guard;Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration $configuration) -AdditionalBytes $ForecastAdditionalBytes
 Save 'dispatch.json' @{schema_version=1;kind='extent-identity-public-recovery-dispatch';run_id=$run;operation=$operation;vm_id=$id.ToString();parent_id=$ExpectedParent.ToString('D');checkpoint_ids=$ids;task_name=$task;guest_stage=$stage;binary_sha256=$tool.sha256;wrapper_sha256=$wrapperPin;cli=$cli;source_commit=$SourceCommit;utc=[DateTime]::UtcNow.ToString('o')}
 Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin -ScriptBlock {param($Stage,$Task,$Pin)
  $ErrorActionPreference='Stop';$path=Join-Path $Stage 'wrapper.ps1';if((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$Pin){throw 'Pinned wrapper required.'}
  Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'"')) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
  Start-ScheduledTask -TaskName $Task
 }
 Save 'start.json' @{start_issued_once=$true;expected_exit=0;completion_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')}
 Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw
}catch{if($created-and-not(Test-Path -LiteralPath (Join-Path $root 'dispatch-failed.json'))){Save 'dispatch-failed.json' @{success=$false;run_id=$run;error=$_.Exception.ToString();automatic_retry=$false}};throw}
finally{if($null-ne$session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
