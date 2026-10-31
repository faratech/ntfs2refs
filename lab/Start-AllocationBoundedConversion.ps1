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
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit,
 [ValidateRange(0,16384)][int]$MinimumExtentOnlyStreams=0,
 [string]$BaselinePath,
 [ValidatePattern('\A[0-9a-f]{64}\z')][string]$BaselineSha256,
    [string]$SourceFixturePath,
    [ValidatePattern('\A[0-9a-f]{64}\z')][string]$SourceFixtureSha256,
    [ValidateRange(0,50000000000)][long]$ForecastAdditionalBytes=7GB
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
function ReadLabBaselineHost([string]$Path,[string]$Sha256,[guid]$RequiredParent){
 $enabled=-not[string]::IsNullOrEmpty($Path);Need ($enabled-eq(-not[string]::IsNullOrEmpty($Sha256))) 'Lab baseline path and checksum must be supplied together.'
 $answer=@{enabled=$enabled;files=@{};sha256='';request_sha256='';result_sha256='';basis_sha256='';provenance=$null}
 if(-not$enabled){return $answer}
 Need ($ExpectedParent-eq$RequiredParent) 'Independent content baseline requires its exact saved NTFS source checkpoint.'
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
function Host-Guard{
    $vm=Get-VM -Id $id -ErrorAction Stop
    $all=@(Get-VMSnapshot -VM $vm -ErrorAction Stop); $actual=@($all.Id|ForEach-Object {$_.ToString('D')})
    Need ($vm.Name -ceq 'ntfs2refs-streaming-v2-20261027' -and $vm.State.ToString() -ceq 'Running' -and $vm.ParentSnapshotId -eq $ExpectedParent -and $vm.MemoryStartup -eq 4GB -and $vm.MemoryAssigned -eq 4GB -and -not $vm.DynamicMemoryEnabled -and (Get-VMProcessor -VM $vm -ErrorAction Stop).Count -eq 4 -and @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop).Count -eq 0 -and $actual.Count -eq $ids.Count -and @($ids|Where-Object {$_ -notin $actual}).Count -eq 0) 'Root must already boot the supplied NTFS parent with the exact supplied checkpoint set/4GiB/4CPU/noNIC.'
}

try{
 $baseline=ReadLabBaselineHost $BaselinePath $BaselineSha256 ([guid]'6fe2d6b6-a2fb-447e-802b-7b3ff0d9f16e')
 Need ($MinimumExtentOnlyStreams-eq0-or$baseline.enabled) 'A positive minimum extent-only stream count requires a separately pinned lab baseline.'
    Need ((-not[string]::IsNullOrEmpty($SourceFixturePath))-eq(-not[string]::IsNullOrEmpty($SourceFixtureSha256))) 'Source fixture path and checksum must be supplied together.'
    if(-not[string]::IsNullOrEmpty($SourceFixturePath)){$null=Json $SourceFixturePath $SourceFixtureSha256}
    $ids=@($ExpectedCheckpointIds|ForEach-Object {$_.ToString('D')})
    Need ($ExpectedParent -ne [guid]::Empty -and $ids.Count -ge 2 -and $ids.Count -le 50 -and @($ids|Sort-Object -Unique).Count -eq $ids.Count -and $ExpectedParent.ToString('D') -in $ids -and [guid]::Empty.ToString('D') -notin $ids) 'Explicit distinct current checkpoint IDs including the actual parent required (Hyper-V maximum50).'
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
    $digestRows=@($manifest.tools|Where-Object name -CEQ 'lab-content-digest.exe');Need ($digestRows.Count-le1) 'Ambiguous sealed content digest helper.';$digestTool=$null
    if($digestRows.Count-eq1){$digestTool=$digestRows[0];Need ($digestTool.path-ceq(Join-Path $toolsetDir 'lab-content-digest.exe')-and$digestTool.bytes-gt0-and$digestTool.bytes-le64MB-and$digestTool.sha256-cmatch'\A[0-9a-f]{64}\z'-and(Ordinary $digestTool.path).Length-eq$digestTool.bytes-and(Get-FileHash -LiteralPath $digestTool.path -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$digestTool.sha256) 'Sealed independent digest helper differs.'}
    Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
    $configuration=Get-LabConfiguration -WorkspaceRoot $workspace; $capacity=Get-LabCapacity -Configuration $configuration
    Need ($capacity.MaximumActualBytes -eq 329374052988 -and $capacity.MinimumFreeBytes -eq 17179869184) 'Fixed50GB capacity epoch/16GiB floor differs.'
    Assert-LabCapacity -Capacity $capacity -AdditionalBytes $ForecastAdditionalBytes
    Host-Guard; Need (-not (Test-Path -LiteralPath $root)) 'Fresh host case required.'
    New-Item -ItemType Directory -Path $root -ErrorAction Stop|Out-Null; $created=$true
    $c=@{run_id=$run;stage=$stage;task=$task;main_sha256=$mainPin;main_bytes=$tool.bytes;digest_sha256=$(if($null-ne$digestTool){$digestTool.sha256}else{''});digest_bytes=$(if($null-ne$digestTool){$digestTool.bytes}else{0});minimum_extent_only_streams=$MinimumExtentOnlyStreams;baseline_enabled=$baseline.enabled;baseline_sha256=$baseline.sha256;baseline_request_sha256=$baseline.request_sha256;baseline_result_sha256=$baseline.result_sha256;baseline_basis_sha256=$baseline.basis_sha256}
    Save 'intent.json' @{schema_version=1;kind='optimized-drive-alpha-intent';run_id=$run;vm_id=$id.ToString();parent_id=$ExpectedParent.ToString();checkpoint_ids=$ids;toolset_manifest=$manifestPath;toolset_manifest_sha256=$ToolsetManifestSha256;source_commit=$manifest.source_commit;tool=$tool;independent_digest_tool=$digestTool;ntfs_receipt_path=$receiptPath;ntfs_receipt_sha256=$NtfsReceiptSha256;ntfs_receipt_grants_source_admission=$false;source_fixture_path=$SourceFixturePath;source_fixture_sha256=$SourceFixtureSha256;source_fixture_grants_source_admission=$false;capacity=$capacity;forecast_bytes=$ForecastAdditionalBytes;forecast_is_not_reservation=$true;public_argv=@('--drive','F','--partition','2');stdin='yes CRLF';manual_shadow_journal_binding=$false;source_admission_recreated=$false;power_checkpoint_cleanup_authorized=$false;utc=[DateTime]::UtcNow.ToString('o');minimum_extent_only_streams=$MinimumExtentOnlyStreams;baseline_provenance=$baseline.provenance;baseline_grants_product_authority=$false}
    $body=@'
Set-StrictMode -Version Latest; $ErrorActionPreference='Stop'
$c=[Text.UTF8Encoding]::new($false).GetString([Convert]::FromBase64String('__CONFIG__'))|ConvertFrom-Json
$phase='preflight'; $process=$null; $nativeExit=$null
function Need([bool]$Ok,[string]$Message){if(-not $Ok){throw $Message}}
function Save([string]$Name,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14));Need ($bytes.Length -le 1MB) 'Wrapper receipt exceeds1MiB.';$f=[IO.File]::Open((Join-Path $c.stage $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
function SameArray($Left,$Right){$a=@($Left);$b=@($Right);if($a.Count-ne$b.Count){return $false};for($i=0;$i-lt$a.Count;$i++){if($a[$i]-cne$b[$i]){return $false}};return $true}
function Json([string]$Path){Need ($Path.StartsWith('C:\',[StringComparison]::OrdinalIgnoreCase) -and $Path.EndsWith('.json',[StringComparison]::Ordinal)) 'Closed C JSON only.';$m=Get-Item -LiteralPath $Path -Force;Need (-not $m.PSIsContainer -and -not ($m.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $m.Length -gt 0 -and $m.Length -le 64MB) 'Bounded ordinary closed C JSON required.';$a=$m.Directory;while($null -ne $a){Need (-not ($a.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Reparse C metadata ancestry.';$a=$a.Parent};Get-Content -LiteralPath $Path -Raw -Encoding UTF8|ConvertFrom-Json}
function Idle{$tasks=@(Get-ScheduledTask -ErrorAction Stop);$processes=@(Get-CimInstance Win32_Process -ErrorAction Stop);Need (@($tasks|Where-Object {$_.TaskName -like 'N2R-*' -and $_.TaskName -cne $c.task -and $_.State.ToString() -notin @('Ready','Disabled')}).Count -eq 0 -and @($processes|Where-Object {$_.Name -match '\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count -eq 0) 'Another project task/process is active or unknown.'}
function Source([string]$Filesystem){$d=Get-Disk -Number 1 -ErrorAction Stop;$p=Get-Partition -DiskNumber 1 -PartitionNumber 2 -ErrorAction Stop;$v=$p|Get-Volume -ErrorAction Stop;$cluster=if($Filesystem -ceq 'NTFS'){65536}else{4096};Need ([guid]$d.Guid -eq [guid]'1b191872-c372-41ee-a416-e18863996f54' -and $d.Size -eq 64GB -and -not $d.IsOffline -and -not $d.IsReadOnly -and -not $d.IsBoot -and -not $d.IsSystem -and [guid]$p.Guid -eq [guid]'f06075a8-67a2-46b9-8fac-4af4da809617' -and $p.Offset -eq 16MB -and $p.Size -eq 52GB -and 'F:\' -in @($p.AccessPaths) -and $v.FileSystem -ceq $Filesystem -and $v.AllocationUnitSize -eq $cluster -and $v.FileSystemLabel -ceq 'n2r-stream-source' -and (Get-Partition -DriveLetter C -ErrorAction Stop).DiskNumber -eq 0) 'Exact source1/F/GPT/52GiB/filesystem/label or OS0 differs.'}
function Protected{$g=Get-Disk -Number 4 -ErrorAction Stop;$gp=Get-Partition -DriveLetter G -ErrorAction Stop;$gv=$gp|Get-Volume -ErrorAction Stop;$old=Get-Disk -Number 5 -ErrorAction Stop;Need ([guid]$g.Guid -eq [guid]'e1f3b9d3-979f-4123-9fee-399640c25092' -and -not $g.IsOffline -and -not $g.IsReadOnly -and $gp.DiskNumber -eq 4 -and $gv.FileSystem -ceq 'ReFS' -and $gv.AllocationUnitSize -eq 4096 -and [guid]$old.Guid -eq [guid]'ad077674-6305-4767-a2aa-6ded3b707e36' -and $old.IsOffline -and $old.IsReadOnly) 'Preserved G4/shadow5 differs.'}
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
function AssertLabExtentScope($Expected,$Result,$Request,[string]$Records){
 $count=0;$bytes=0L
 foreach($object in $Expected.objects){if($object.directory){continue};$streams=[Collections.Generic.List[object]]::new();$streams.Add($object);$p=$object.PSObject.Properties['named_streams'];if($null-ne$p){foreach($s in $p.Value){$streams.Add($s)}};foreach($s in $streams){if($null-eq$s.sha256){$e=$s.PSObject.Properties['source_evidence'];Need ($null-ne$e-and$e.Value-ceq'extent_identity_v1') 'Absent product digest requires explicit extent source evidence.';$count++;$bytes+=[long]$s.length}}}
 $reported=$Result.PSObject.Properties['raw_source_extent_only_streams'];if($null-ne$reported){Need ($reported.Value-eq$count) 'Canonical/raw result extent-only stream counts differ.'}else{Need ($count-eq0) 'Hash-free canonical streams require an explicit raw result count.'}
 Need ($count-ge$c.minimum_extent_only_streams) ('Actual raw extent-only streams '+$count+' are below the required lab minimum '+$c.minimum_extent_only_streams)
 $manifestPin=$null
 if($count-gt0){
  Need ($c.baseline_enabled-and$Result.raw_source_logical_hashes-eq$false) 'Initial hash elisions require independent lab baselines and an explicit non-full raw result.'
  $bundle=Json (Join-Path $Records 'allocation-recovery-bundle.json');$pin=$bundle.recovery_payload_manifest;$path=Join-Path $Records 'recovery-payload-manifest.json';Need ($pin.path-ceq$path-and$pin.sha256-cmatch'\A[0-9a-f]{64}\z'-and(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$pin.sha256) 'Hash-free recovery bundle must pin its actual payload map manifest.'
  $manifest=Json $path;$plan=Json (Join-Path $Records 'selected-plan.json');$ticket=Json (Join-Path $Records 'selected-ticket.json');$fresh=Json (Join-Path $Records 'extent-verification.json')
  $sha=[Security.Cryptography.SHA256]::Create();try{$planPin=([BitConverter]::ToString($sha.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes(($plan|ConvertTo-Json -Depth 64 -Compress))))).Replace('-','').ToLowerInvariant();$ticketPin=([BitConverter]::ToString($sha.ComputeHash([Text.UTF8Encoding]::new($false).GetBytes(($ticket|ConvertTo-Json -Depth 64 -Compress))))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  Need ($manifest.schema_version-eq1-and$manifest.kind-ceq'protected-target-stream-map-facts-v1'-and$manifest.expected_tree_sha256-ceq$Result.expected_tree_sha256-and$manifest.plan_sha256-ceq$planPin-and$manifest.ticket_sha256-ceq$ticketPin-and(SameJsonValue $manifest.source $Request.pair.source)-and$manifest.selected_bytes-eq$Result.selected_bytes-and$manifest.range_count-eq$Result.selected_ranges-and(SameArray $manifest.new_selected_sha256 $ticket.new_selected_sha256)-and@($manifest.bindings).Count-eq$fresh.stream_and_directory_bindings-and$manifest.grants_write_authority-eq$false-and$manifest.initial_retained_content_digests_available-eq$false) 'Pinned recovery map facts differ from the actual expectation/plan/ticket/source/selected ranges.'
  $manifestPin=@{path=$path;sha256=$pin.sha256;bindings=@($manifest.bindings).Count;expectation_plan_ticket_source_and_selected_bindings_checked=$true;serialized_facts_grant_product_authority=$false}
 }
 return @{scope='lab-required-raw-extent-count-v1';minimum_extent_only_streams=$c.minimum_extent_only_streams;canonical_extent_only_streams=$count;canonical_extent_only_logical_bytes=$bytes;raw_result_count_matches=$true;recovery_payload_manifest=$manifestPin;grants_product_authority=$false}
}
function ResolveLabContentBaseline($Expected,$Request,[string]$Records){
 $hashless=0;foreach($object in $Expected.objects){if(-not$object.directory-and$null-eq$object.sha256){$hashless++};$property=$object.PSObject.Properties['named_streams'];if($null-ne$property){foreach($stream in $property.Value){if($null-eq$stream.sha256){$hashless++}}}}
 if(-not$c.baseline_enabled){Need ($hashless-eq0) 'Hashless expectations require a separately pinned historical full-content lab baseline.';return @{enabled=$false;observer_expectation=$Expected;product_expectation=$Expected;receipt=@{scope='lab-content-baseline-v1';baseline_used=$false;hashless_product_streams=0;product_expectation_written=$false;grants_product_authority=$false}}}
 $paths=@(@{name='lab-full-content-baseline.json';pin=$c.baseline_sha256},@{name='lab-baseline-request.json';pin=$c.baseline_request_sha256},@{name='lab-baseline-result.json';pin=$c.baseline_result_sha256},@{name='lab-baseline-source-basis.json';pin=$c.baseline_basis_sha256})
 foreach($spec in $paths){Need ((Get-FileHash -LiteralPath (Join-Path $c.stage $spec.name) -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$spec.pin) 'Independent lab baseline artifact pin differs.'}
 $baseline=Json (Join-Path $c.stage 'lab-full-content-baseline.json');$oldRequest=Json (Join-Path $c.stage 'lab-baseline-request.json');$oldResult=Json (Join-Path $c.stage 'lab-baseline-result.json');$oldBasis=Json (Join-Path $c.stage 'lab-baseline-source-basis.json')
 Need ($oldResult.success-eq$true-and$oldResult.source_admitted-eq$true-and$oldResult.expected_tree_sha256-ceq$c.baseline_sha256-and(SameJsonValue $oldRequest.pair.source $Request.pair.source)) 'Historical full-content baseline source binding/result differs.'
 $rawFlag=$oldResult.PSObject.Properties['raw_source_logical_hashes'];Need ($null-eq$rawFlag-or$rawFlag.Value-eq$true) 'Historical baseline must retain initial raw logical hashes.'
 $oldRaw=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
 foreach($file in $oldBasis.ntfs.files){$key=([string]$file.record_number)+':'+([string]$file.sequence_number);Need (-not$oldRaw.ContainsKey($key)) 'Duplicate historical raw source identity.';$oldRaw.Add($key,$file)}
 $copy=($Expected|ConvertTo-Json -Depth 64)|ConvertFrom-Json;$oldObjects=@($baseline.objects);Need (@($copy.objects).Count-eq$oldObjects.Count) 'Independent baseline canonical object coverage differs.';$elisions=[Collections.Generic.List[object]]::new()
 foreach($object in $copy.objects){
  $matches=@($oldObjects|Where-Object {$_.record_number-eq$object.record_number-and$_.sequence_number-eq$object.sequence_number-and(SameArray $_.path $object.path)});Need ($matches.Count-eq1) 'Independent baseline canonical identity/path differs.';$old=$matches[0]
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
 Need (SameJsonValue $copy $baseline) 'Canonical baseline differs beyond explicit extent evidence and absent content digests; every identity, path, stream, map and metadata field must match.'
 $newNative=Json (Join-Path $Records 'qualification\native-source.json')
 return @{enabled=$true;observer_expectation=$copy;product_expectation=$Expected;baseline=$baseline;baseline_basis=$oldBasis;baseline_raw_by_identity=$oldRaw;native_source=$newNative;receipt=@{scope='lab-content-baseline-v1';baseline_used=$true;baseline_sha256=$c.baseline_sha256;baseline_request_sha256=$c.baseline_request_sha256;baseline_result_sha256=$c.baseline_result_sha256;baseline_source_basis_sha256=$c.baseline_basis_sha256;canonical_metadata_exact_except_explicit_content_evidence=$true;historical_digests_bound_to_full_raw_inspection=$true;source_binding_identical=$true;hashless_product_streams=$hashless;comparison_streams_restored=$elisions.Count;comparison_only_clone=$true;product_expectation_written=$false;grants_product_authority=$false;elided_streams=$elisions.ToArray()}}
}
function AssertRawContentOrLabExtent($Raw,$File,$Stream,[string]$Digest){
 if($null-ne$Stream.logical_sha256){Need ($Stream.logical_hash_status-ceq'complete'-and$Stream.logical_sha256-ceq$Digest) 'Raw logical stream digest differs from independent fixture.';return $false}
 $context=$script:labBaselineContext;Need ($null-ne$context-and$context.enabled) 'Unread raw stream requires the separately pinned lab baseline.'
 $objects=@($context.product_expectation.objects|Where-Object {$_.record_number-eq$File.record_number-and$_.sequence_number-eq$File.sequence_number});Need ($objects.Count-eq1) 'Extent-only raw source canonical object missing.';$product=LabStream $objects[0] $Stream.name_utf16;$evidence=$product.PSObject.Properties['source_evidence'];Need ($null-eq$product.sha256-and$null-ne$evidence-and$evidence.Value-ceq'extent_identity_v1') 'Unread raw source lacks explicit canonical extent evidence.'
 $key=([string]$File.record_number)+':'+([string]$File.sequence_number);Need ($context.baseline_raw_by_identity.ContainsKey($key)) 'Historical raw source identity missing.';$oldFile=$context.baseline_raw_by_identity[$key];$oldStreams=@($oldFile.streams|Where-Object {SameArray $_.name_utf16 $Stream.name_utf16});Need ($oldStreams.Count-eq1-and$oldStreams[0].logical_hash_status-ceq'complete'-and$oldStreams[0].logical_sha256-ceq$Digest) 'Historical raw source digest differs from the independently pinned fixture.';$old=$oldStreams[0]
 Need ($Stream.logical_hash_status-ceq'not_read_extent_identity_v1'-and-not$Stream.resident-and$Stream.flags-eq0-and$Stream.logical_size-gt0-and$Stream.logical_size%4096-eq0-and$Stream.initialized_size-eq$Stream.logical_size-and$Stream.allocated_size-ge$Stream.logical_size) 'Unread raw stream is outside the aligned plain initialized extent scope.'
 $clone=($Stream|ConvertTo-Json -Depth 32)|ConvertFrom-Json;$clone.logical_sha256=$old.logical_sha256;$clone.logical_hash_status='complete';Need (SameJsonValue $clone $old) 'Unread raw source metadata/extents differ from historical full inspection.'
 $actualAttrs=@($File.attributes|Where-Object {$_.type_code-eq128-and(SameArray $_.name_utf16 $Stream.name_utf16)});$oldAttrs=@($oldFile.attributes|Where-Object {$_.type_code-eq128-and(SameArray $_.name_utf16 $Stream.name_utf16)});Need ($actualAttrs.Count-eq1-and$oldAttrs.Count-eq1-and(SameJsonValue $actualAttrs[0] $oldAttrs[0])-and-not$actualAttrs[0].resident-and$actualAttrs[0].flags-eq0-and$actualAttrs[0].compression_unit-eq0-and$actualAttrs[0].lowest_vcn-eq0) 'Unread DATA attribute differs from historical plain initialized storage.'
 $native=$context.native_source;Need ($native.schema_version-eq12-and$native.request.schema_version-eq4) 'Unread raw source requires native report12/request4.'
 $requests=@($native.request.extent_identity_streams|Where-Object {$_.identity.record_number-eq$File.record_number-and$_.identity.sequence_number-eq$File.sequence_number-and(SameArray $_.name_utf16 $Stream.name_utf16)});Need ($requests.Count-eq1-and$requests[0].cluster_bytes-eq$Raw.geometry.cluster_size-and$requests[0].logical_size-eq$Stream.logical_size-and$requests[0].allocated_size-eq$Stream.allocated_size-and(SameJsonValue $requests[0].extents $Stream.extents)) 'Complete native extent request differs from the raw source mapping.'
 $files=@($native.logical_data.files|Where-Object {$_.identity.record_number-eq$File.record_number-and$_.identity.sequence_number-eq$File.sequence_number});Need ($files.Count-eq1) 'Native extent-only logical source identity missing.';$observed=@($files[0].before|Where-Object {SameArray $_.name_utf16 $Stream.name_utf16});Need ($observed.Count-eq1-and$observed[0].outcome.status-ceq'not_read_extent_identity_v1'-and$observed[0].outcome.bytes_read-eq0-and$null-eq$observed[0].outcome.sha256-and$observed[0].outcome.eof_confirmed-eq$false) 'Native extent-only source must explicitly contain no content read, digest or EOF success.'
 return $true
}

function VerifyAllTargetStreamHashes($Expected,[string]$Drive){
 $tool=Join-Path $c.stage 'lab-content-digest.exe';$toolFile=Get-Item -LiteralPath $tool -Force
 Need (-not$toolFile.PSIsContainer-and-not($toolFile.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$toolFile.Length-eq$c.digest_bytes-and(Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$c.digest_sha256) 'Pinned independent target digest tool differs.'
 Need ($null-ne$nativeExit-and$nativeExit-eq0-and$process.HasExited) 'Independent hashes require the actual native engine to have exited successfully.'
 $rows=[Collections.Generic.List[object]]::new();$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$defaultCount=0;$namedCount=0
 foreach($object in $Expected.objects){
  if($object.directory){continue};$components=@($object.path);Need ($components.Count-gt0) 'Canonical file path is empty.'
  foreach($part in $components){Need ($part.Length-gt0-and$part-notin@('.','..')-and$part-cnotmatch'[:\\/"\x00-\x1f]') 'Canonical independent digest path is invalid.'}
  $path=$Drive+':\'+($components-join'\');Need ($seen.Add($path)-and$object.sha256-cmatch'\A[0-9a-f]{32}\z') 'Duplicate or missing expected canonical content digest.'
  $rows.Add(@{path=$path;name_utf16=@();length=$object.length;expected_content_digest=$object.sha256;kind='default'});$defaultCount++
  $property=$object.PSObject.Properties['named_streams'];$streams=@();if($null-ne$property){$streams=@($property.Value)}
  foreach($stream in $streams){$units=@($stream.name_utf16);Need ($units.Count-gt0-and$units.Count-le255-and@($units|Where-Object {$_-lt0-or$_-gt65535}).Count-eq0) 'Invalid independent named stream identity.';$name=-join@($units|ForEach-Object {[char][int]$_});$null=[Text.UTF8Encoding]::new($false,$true).GetByteCount($name);Need ($name-cnotmatch'[:\\/\x00-\x1f]'-and$stream.sha256-cmatch'\A[0-9a-f]{32}\z') 'Invalid named stream path or expected content digest.';$namedPath=$path+':'+$name+':$DATA';Need ($seen.Add($namedPath)) 'Duplicate independent target stream.';$rows.Add(@{path=$namedPath;name_utf16=$units;length=$stream.length;expected_content_digest=$stream.sha256;kind='named'});$namedCount++}
 }
 Need ($rows.Count-gt0) 'Nonempty independent target stream set required.'
 $batchCount=0;$index=0
 while($index-lt$rows.Count){$batch=[Collections.Generic.List[object]]::new();$argumentUnits=0
  while($index-lt$rows.Count){$row=$rows[$index];$cost=$row.path.Length+3;Need ($cost-le16000) 'One digest path exceeds the native argument bound.';if($batch.Count-gt0-and$argumentUnits+$cost-gt16000){break};$batch.Add($row);$argumentUnits+=$cost;$index++}
  Idle;$arguments=@('--backup-read')+[string[]]@($batch|ForEach-Object {$_.path});$lines=@(& $tool @arguments);$exit=$LASTEXITCODE;Need ($exit-eq0-and($lines-join'').Length-le(40*$batch.Count+1024)) 'Bounded independent target digest helper failed.';$digests=@(($lines-join'')|ConvertFrom-Json|ForEach-Object {$_});Need ($digests.Count-eq$batch.Count) 'Independent target digest coverage differs.'
  for($i=0;$i-lt$batch.Count;$i++){Need ($digests[$i]-cmatch'\A[0-9a-f]{32}\z'-and$digests[$i]-ceq$batch[$i].expected_content_digest) ('Independent target content differs or cannot be read: '+$batch[$i].path);$batch[$i].actual_content_digest=$digests[$i]};$batchCount++;Idle
 }
 return @{scope='independent-all-expected-target-streams-after-native-exit-v1';content_digest_algorithm='xxh3-128';tool_sha256=$c.digest_sha256;tool_bytes=$c.digest_bytes;backup_read=$true;native_engine_exit_observed=$true;native_engine_exit=$nativeExit;default_stream_hashes=$defaultCount;named_stream_hashes=$namedCount;complete_stream_hashes=$rows.Count;batch_count=$batchCount;all_expected_hashes_match=$true;product_engine_hashes_not_inferred=$true;rows=$rows.ToArray()}
}
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
    $policyProperty=$result.PSObject.Properties['actual_target_verification_policy'];$targetPolicy='full_content';if($null-ne$policyProperty){$targetPolicy=[string]$policyProperty.Value};Need ($targetPolicy-in@('full_content','extent_identity_v1')) 'Unknown actual native target verification policy.';$fastTarget=$targetPolicy-ceq'extent_identity_v1';$extentReceipt=$null;$extentReceiptPin=$null
    if($fastTarget){
        $extentPath=Join-Path $records 'extent-verification.json';$extentReceipt=Json $extentPath;$extentReceiptPin=(Get-FileHash -LiteralPath $extentPath -Algorithm SHA256).Hash.ToLowerInvariant()
        Need ($extentReceipt.schema_version-eq1-and$extentReceipt.scope-ceq'fresh-conversion-extent-identity-v1'-and$extentReceipt.expected_tree_sha256-ceq$expectationSha-and$extentReceipt.all_complete_maps_identical-eq$true-and$extentReceipt.handoff_replay_closed-eq$true-and$extentReceipt.target_full_file_hashes-eq$false-and$extentReceipt.target_admitted_payload_bytes_read-eq0) 'Fresh native extent-verification receipt differs.'
        $observation=$final.native.content_observation;Need ($observation.scope-ceq'converted-metadata-and-complete-stream-maps-v1'-and$observation.full_file_hashes-eq$false-and$observation.content_equality_verified-eq$false-and$observation.admitted_payload_bytes_read-eq0-and$observation.metadata_and_namespace_verified-eq$true-and$observation.complete_stream_mappings_observed-eq$true-and$observation.data_storage_validity_checked-eq$true) 'Fast native target report must explicitly contain metadata observations without content hashes.'
    }
    $objects=@($final.native.native.objects);$expectedObjects=@($expected.objects).Count;$expectedFiles=@($expected.objects|Where-Object {-not $_.directory}).Count;Need ($expectedObjects -gt 0 -and $objects.Count -eq $expectedObjects) 'Native object count must equal the admitted expectation.';$hashes=0;$namedHashes=0;$observedFiles=0;$observedNamed=0;$expectedNamed=0
    foreach($object in $expected.objects){
        $found=@($objects|Where-Object {($_.components -join '\') -ceq ($object.path -join '\')});Need ($found.Count -eq 1) 'Native expected object missing/duplicate.'
        if(-not $object.directory){$observedFiles++;if($fastTarget){Need ($null-eq$found[0].logical_sha256) 'Fast native target must not manufacture an observed canonical hash.'}else{Need ($found[0].logical_sha256 -ceq $object.sha256) 'Native complete logical hash differs.';$hashes++}}
        $streams=@();$property=$object.PSObject.Properties['named_streams'];if($null-ne$property){$streams=@($property.Value)};$expectedNamed+=$streams.Count
        $actualStreams=@();$property=$found[0].PSObject.Properties['named_streams'];if($null-ne$property){$actualStreams=@($property.Value)};Need ($actualStreams.Count-eq$streams.Count) 'Native named stream coverage differs.'
        foreach($stream in $streams){$actual=@($actualStreams|Where-Object {SameArray $_.name_utf16 $stream.name_utf16});Need ($actual.Count-eq1-and$actual[0].expected_sha256-ceq$stream.sha256) 'Native named stream identity/expectation differs.';$observedNamed++;if($fastTarget){Need ($null-eq$actual[0].logical_sha256) 'Fast native target must not manufacture an observed named-stream hash.'}else{Need ($actual[0].logical_sha256-ceq$stream.sha256) 'Native complete named-stream hash differs.';$namedHashes++}}
    }
    Need ($observedFiles-eq$expectedFiles-and$observedNamed-eq$expectedNamed-and$managed.kind -ceq 'managed-native-shadow-location' -and [guid]$managed.binding.identity.disk_guid -eq [guid]$devices.pair.shadow.identity.disk_guid -and [guid]$managed.binding.identity.partition_guid -eq [guid]$devices.pair.shadow.identity.partition_guid) 'Every expected stream and the current staging location are required.'
    if($fastTarget){Need ($hashes-eq0-and$namedHashes-eq0-and$observation.default_streams_observed-eq$expectedFiles-and$observation.named_streams_observed-eq$expectedNamed) 'Fast metadata observation stream coverage differs.'}else{Need ($hashes-eq$expectedFiles-and$namedHashes-eq$expectedNamed) 'Every native full-content stream hash is required.'}
    $independentHashes=$null;$independentHashPin=$null
    $conversionRequest=Json (Join-Path $records 'request.json');$labExtentScope=AssertLabExtentScope $expected $result $conversionRequest $records;$script:labBaselineContext=ResolveLabContentBaseline $expected $conversionRequest $records;$labExpected=$script:labBaselineContext.observer_expectation;$baselineBinding=$null
    if($script:labBaselineContext.enabled){$baselineBinding=$script:labBaselineContext.receipt;Save 'lab-baseline-binding.json' $baselineBinding}
    if($fastTarget){$phase='independent-complete-target-hashes';$independentHashes=VerifyAllTargetStreamHashes $labExpected 'F';$independentHashes['lab_baseline_binding']=$baselineBinding;Need ($independentHashes.default_stream_hashes-eq$expectedFiles-and$independentHashes.named_stream_hashes-eq$expectedNamed) 'Every expected target default and named stream requires an independent full hash.';Save 'independent-target-hashes.json' $independentHashes;$independentHashPin=(Get-FileHash -LiteralPath (Join-Path $c.stage 'independent-target-hashes.json') -Algorithm SHA256).Hash.ToLowerInvariant()}
    Source 'ReFS'; Idle; Protected
    Save 'wrapper-result.json' @{schema_version=1;kind='allocation-bounded-public-drive-observation';success=$true;run_id=$c.run_id;engine_run_id=$engine;native_exit_observed=$true;native_exit=$nativeExit;argv=$cli;conversion_records=$records;native_objects=$objects.Count;complete_native_hashes=$hashes;complete_native_named_stream_hashes=$namedHashes;actual_target_verification_policy=$targetPolicy;engine_full_target_file_hashes=(-not$fastTarget);engine_metadata_default_streams=$observedFiles;engine_metadata_named_streams=$observedNamed;extent_verification_receipt=$extentReceipt;lab_baseline_binding=$baselineBinding;lab_extent_scope=$labExtentScope;extent_verification_sha256=$extentReceiptPin;independent_target_hashes=$independentHashes;independent_target_hashes_sha256=$independentHashPin;independent_complete_logical_hashes=$(if($null-ne$independentHashes){$independentHashes.default_stream_hashes}else{0});independent_named_stream_hashes=$(if($null-ne$independentHashes){$independentHashes.named_stream_hashes}else{0});label_and_mount_verified=$true;selected_ranges=$result.selected_ranges;selected_bytes=$result.selected_bytes;journal_bytes=$result.journal_bytes;free_space_contents_compared=$false;result_sha256=(Get-FileHash -LiteralPath (Join-Path $records 'result.json')).Hash.ToLowerInvariant();finalization_sha256=(Get-FileHash -LiteralPath (Join-Path $records 'finalization.json')).Hash.ToLowerInvariant();expectation_sha256=$expectationSha;production_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')}
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
    if($null-ne$digestTool){Copy-Item -LiteralPath $digestTool.path -ToSession $session -Destination (Join-Path $stage 'lab-content-digest.exe')}
 if($baseline.enabled){foreach($spec in @(@{key='expectation';name='lab-full-content-baseline.json'},@{key='request';name='lab-baseline-request.json'},@{key='result';name='lab-baseline-result.json'},@{key='basis';name='lab-baseline-source-basis.json'})){Copy-Item -LiteralPath $baseline.files[$spec.key].path -ToSession $session -Destination (Join-Path $stage $spec.name)}}
    Copy-Item -LiteralPath $wrapperPath -ToSession $session -Destination (Join-Path $stage 'wrapper.ps1')
    Host-Guard
    Save 'dispatch.json' @{schema_version=1;kind='allocation-bounded-public-drive-dispatch';run_id=$run;vm_id=$id.ToString();parent_id=$ExpectedParent.ToString();checkpoint_ids=$ids;task_name=$task;guest_stage=$stage;binary_sha256=$mainPin;binary_bytes=$tool.bytes;digest_tool_sha256=$c.digest_sha256;digest_tool_bytes=$c.digest_bytes;wrapper_sha256=$wrapperPin;toolset_manifest=$manifestPath;toolset_manifest_sha256=$ToolsetManifestSha256;source_commit=$manifest.source_commit;ntfs_receipt_path=$receiptPath;ntfs_receipt_sha256=$NtfsReceiptSha256;argv=@('--drive','F','--partition','2');stdin='yes CRLF';expected_exit=0;manual_shadow_journal_binding=$false;source_admission_recreated=$false;source_fixture_path=$SourceFixturePath;source_fixture_sha256=$SourceFixtureSha256;source_fixture_grants_source_admission=$false;utc=[DateTime]::UtcNow.ToString('o');minimum_extent_only_streams=$MinimumExtentOnlyStreams;baseline_provenance=$baseline.provenance;baseline_grants_product_authority=$false}
    Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin,$mainPin,$MainBytes -ScriptBlock {param($Stage,$Task,$WrapperPin,$MainPin,$Bytes)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$path=Join-Path $Stage 'wrapper.ps1';$binary=Join-Path $Stage 'ntfs2refs.exe'
        if((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -cne $WrapperPin -or (Get-Item -LiteralPath $binary).Length -ne $Bytes -or (Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant() -cne $MainPin -or @(Get-ScheduledTask -ErrorAction Stop|Where-Object TaskName -CEQ $Task).Count){throw 'Fresh pinned public main/wrapper/task required.'}
        Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'"')) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)) -ErrorAction Stop|Out-Null
    }
    Host-Guard
    Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration $configuration) -AdditionalBytes $ForecastAdditionalBytes
    Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin -ScriptBlock {param($Stage,$Task,$Pin)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskName $Task -ErrorAction Stop;$info=Get-ScheduledTaskInfo -TaskName $Task -ErrorAction Stop;$path=Join-Path $Stage 'wrapper.ps1'
        if($t.State.ToString() -cne 'Ready' -or $info.LastRunTime.Year -ge 2000 -or @($t.Actions).Count -ne 1 -or $t.Actions[0].Execute -cne "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -or $t.Actions[0].Arguments -cne ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'"') -or $t.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or $t.Principal.RunLevel.ToString() -cne 'Highest' -or (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -cne $Pin -or @(Get-ScheduledTask -ErrorAction Stop|Where-Object {$_.TaskName -like 'N2R-*' -and $_.State.ToString() -notin @('Ready','Disabled')}).Count){throw 'Only the untouched pinned SYSTEM public drive task may start once.'}
        Start-ScheduledTask -TaskName $Task -ErrorAction Stop
    }
    Save 'start.json' @{start_issued_once=$true;expected_exit=0;completion_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')}
    Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw
}catch{if($created -and -not (Test-Path -LiteralPath (Join-Path $root 'dispatch-failed.json'))){Save 'dispatch-failed.json' @{success=$false;run_id=$run;error=$_.Exception.ToString();automatic_retry_recovery_restore_cleanup=$false;utc=[DateTime]::UtcNow.ToString('o')}};throw}
finally{if($null -ne $session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
