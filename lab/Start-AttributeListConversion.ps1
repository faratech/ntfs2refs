# Launch the public CLI against H: ATTRIBUTE_LIST plus the preserved baseline.
# Root restores/boots the reviewed parent. No power, checkpoint, source-layout,
# manual binding, permission or cleanup action is performed by this controller.
[CmdletBinding()]
param(
 [Parameter(Mandatory)][guid]$ExpectedParent,
 [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds,
 [string]$EaFixturePath,
 [ValidatePattern('\A[0-9a-f]{64}\z')][string]$EaFixtureSha256,
 [string]$SecurityFixturePath,
 [ValidatePattern('\A[0-9a-f]{64}\z')][string]$SecurityFixtureSha256,
 [string]$SecurityToolPath,
 [ValidatePattern('\A[0-9a-f]{64}\z')][string]$SecurityToolSha256,
 [string]$ReparseFixturePath,
 [ValidatePattern('\A[0-9a-f]{64}\z')][string]$ReparseFixtureSha256,
 [string]$ReparseToolPath,
 [ValidatePattern('\A[0-9a-f]{64}\z')][string]$ReparseToolSha256,
 [string]$CompressionFixturePath,
 [ValidatePattern('\A[0-9a-f]{64}\z')][string]$CompressionFixtureSha256,
 [string]$CompressionToolPath,
 [ValidatePattern('\A[0-9a-f]{64}\z')][string]$CompressionToolSha256,
 [ValidateRange(0,16384)][int]$MinimumExtentOnlyStreams=0,
 [string]$BaselinePath,
 [ValidatePattern('\A[0-9a-f]{64}\z')][string]$BaselineSha256,
 [Parameter(Mandatory)][string]$AttributeFixturePath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$AttributeFixtureSha256,
 [Parameter(Mandatory)][string]$SparseFixturePath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$SparseFixtureSha256,
 [Parameter(Mandatory)][string]$DigestToolPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$DigestToolSha256,
 [Parameter(Mandatory)][string]$AdsManifestPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$AdsManifestSha256,
 [Parameter(Mandatory)][string]$HardlinkFixtureManifestPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$HardlinkFixtureManifestSha256,
 [Parameter(Mandatory)][string]$PublicExePath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$PublicExeSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$MainSourceSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$vmId=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$run=[guid]::NewGuid().ToString('N');$root=Join-Path $base ('attribute-list-convert-'+$run)
$stage='C:\ntfs2refs\attribute-list-convert-'+$run;$task='N2R-AttributeListConvert-'+$run
$session=$null;$created=$false
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function Ordinary([string]$Path,[long]$Maximum){
 $full=[IO.Path]::GetFullPath($Path);$m=Get-Item -LiteralPath $full -Force
 Need ($full-cmatch '\A[A-Za-z]:\\'-and-not$m.PSIsContainer-and$m.Length-gt0-and$m.Length-le$Maximum) 'Bounded ordinary local file required.'
 $a=$m;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse host ancestry refused.';if($a-is[IO.DirectoryInfo]){$a=$a.Parent}else{$a=$a.Directory}}
 return $m
}
function Save([string]$Name,$Value){
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14));Need ($bytes.Length-le1MB) 'Host receipt exceeds one MiB.'
 $file=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
}
$ids=@($ExpectedCheckpointIds|ForEach-Object {$_.ToString('D')})
Need ($ids.Count-gt0-and@($ids|Sort-Object -Unique).Count-eq$ids.Count-and$ExpectedParent.ToString('D')-in$ids) 'Explicit unique current checkpoint set including parent required.'
function ReadOnlyAttributeCompletion($Fixture){$p=$Fixture.PSObject.Properties['read_only_completion'];return $null-ne$p-and$p.Value-eq$true}
function AttributePreparationValid($Fixture){
 if(ReadOnlyAttributeCompletion $Fixture){return ($Fixture.prior_verified_move_count-eq1024-and$Fixture.current_complete_extent_count-eq1024-and$Fixture.all_prior_payload_mappings_match-eq$true-and$Fixture.all_initial_logical_hashes_match-eq$true-and$Fixture.move_file_calls-eq0-and$Fixture.source_write_requests-eq0-and@($Fixture.moves).Count-eq0-and$Fixture.prior_report_sha256-cmatch'\A[0-9a-f]{64}\z'-and$Fixture.prior_report_path-cmatch'\AC:\\'-and$Fixture.prior_report_path-cnotmatch'\.\.|[\r\n\x00]')}
 return ($Fixture.verified_move_count-eq1024-and@($Fixture.moves).Count-eq1024-and@($Fixture.moves|Where-Object {$_.verified-ne$true}).Count-eq0)
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
function HostGuard{
 $vm=Get-VM -Id $vmId -ErrorAction Stop;$actual=@(Get-VMSnapshot -VM $vm|ForEach-Object {$_.Id.ToString('D')})
 Need ($vm.Name-ceq'ntfs2refs-streaming-v2-20261027'-and$vm.State.ToString()-ceq'Running'-and$vm.ParentSnapshotId-eq$ExpectedParent-and$vm.MemoryStartup-eq4GB-and$vm.MemoryAssigned-eq4GB-and-not$vm.DynamicMemoryEnabled-and(Get-VMProcessor -VM $vm).Count-eq4-and@(Get-VMNetworkAdapter -VM $vm).Count-eq0-and$actual.Count-eq$ids.Count-and@($ids|Where-Object {$_-notin$actual}).Count-eq0) 'Reviewed running parent/checkpoints/4 GiB/4 CPU/no NIC required.'
}
try{
 $baseline=ReadLabBaselineHost $BaselinePath $BaselineSha256 ([guid]'371ae756-faf2-40ac-bf86-5e8e1d744e30')
 Need ($MinimumExtentOnlyStreams-eq0-or$baseline.enabled) 'A positive minimum extent-only stream count requires a separately pinned lab baseline.'
 $eaEnabled=-not[string]::IsNullOrEmpty($EaFixturePath);Need ($eaEnabled-eq(-not[string]::IsNullOrEmpty($EaFixtureSha256))) 'EA fixture path and checksum must be supplied together.';$eaFile=$null
 $securityEnabled=-not[string]::IsNullOrEmpty($SecurityFixturePath);$securityFile=$null;$securityTool=$null
 Need ($securityEnabled-eq(-not[string]::IsNullOrEmpty($SecurityFixtureSha256))-and$securityEnabled-eq(-not[string]::IsNullOrEmpty($SecurityToolPath))-and$securityEnabled-eq(-not[string]::IsNullOrEmpty($SecurityToolSha256))) 'Security fixture/tool paths and checksums must be supplied together.'
 $reparseEnabled=-not[string]::IsNullOrEmpty($ReparseFixturePath);$reparseFile=$null;$reparseTool=$null
 Need ($reparseEnabled-eq(-not[string]::IsNullOrEmpty($ReparseFixtureSha256))-and$reparseEnabled-eq(-not[string]::IsNullOrEmpty($ReparseToolPath))-and$reparseEnabled-eq(-not[string]::IsNullOrEmpty($ReparseToolSha256))) 'Reparse fixture/tool paths and checksums must be supplied together.'
 $compressionEnabled=-not[string]::IsNullOrEmpty($CompressionFixturePath);$compressionFile=$null;$compressionTool=$null
 Need ($compressionEnabled-eq(-not[string]::IsNullOrEmpty($CompressionFixtureSha256))-and$compressionEnabled-eq(-not[string]::IsNullOrEmpty($CompressionToolPath))-and$compressionEnabled-eq(-not[string]::IsNullOrEmpty($CompressionToolSha256))) 'Compression fixture/tool paths and checksums must be supplied together.'
 $attributeFile=Ordinary $AttributeFixturePath 4MB;$fixtureFile=Ordinary $HardlinkFixtureManifestPath 1MB;$adsFile=Ordinary $AdsManifestPath 1MB;$exeFile=Ordinary $PublicExePath 64MB;$sparseFile=Ordinary $SparseFixturePath 1MB;$digestFile=Ordinary $DigestToolPath 64MB
 Need ((Get-FileHash -LiteralPath $fixtureFile.FullName).Hash.ToLowerInvariant()-ceq$HardlinkFixtureManifestSha256-and(Get-FileHash -LiteralPath $adsFile.FullName).Hash.ToLowerInvariant()-ceq$AdsManifestSha256-and(Get-FileHash -LiteralPath $exeFile.FullName).Hash.ToLowerInvariant()-ceq$PublicExeSha256) 'Fixture or public executable pin differs.'
 Need ((Get-FileHash -LiteralPath $attributeFile.FullName).Hash.ToLowerInvariant()-ceq$AttributeFixtureSha256) 'Attribute fixture pin differs.'
 $attribute=[IO.File]::ReadAllText($attributeFile.FullName)|ConvertFrom-Json
 $fixture=[IO.File]::ReadAllText($fixtureFile.FullName)|ConvertFrom-Json
 $ads=[IO.File]::ReadAllText($adsFile.FullName)|ConvertFrom-Json
 Need ((Get-FileHash -LiteralPath $sparseFile.FullName).Hash.ToLowerInvariant()-ceq$SparseFixtureSha256-and(Get-FileHash -LiteralPath $digestFile.FullName).Hash.ToLowerInvariant()-ceq$DigestToolSha256) 'Sparse fixture or digest tool pin differs.'
 $sparse=[IO.File]::ReadAllText($sparseFile.FullName)|ConvertFrom-Json
 Need ($fixture.success-eq$true-and$fixture.kind-ceq'independent-hardlink-ntfs-fixture'-and$fixture.disk_number-eq6-and$fixture.partition_bytes-eq52GB-and$fixture.partition_offset-eq32MB-and$fixture.filesystem-ceq'NTFS'-and$fixture.cluster_bytes-eq4096-and$fixture.label-ceq'n2r-links-source'-and$fixture.user_file_identities-eq3-and$fixture.user_file_names-eq9-and@($fixture.groups).Count-eq3) 'Pinned fresh H: hard-link fixture required.'
 Need ([guid]$fixture.disk_guid-ne[guid]::Empty-and[guid]$fixture.partition_guid-ne[guid]::Empty-and$fixture.disk_unique_id_after-ceq$fixture.disk_unique_id_before) 'Fixture disk identities are missing or unstable.'
 Need ($ads.kind-ceq'independent-ads-hardlink-ntfs-fixture'-and$ads.success-eq$true-and$ads.hardlink_fixture_sha256-ceq$HardlinkFixtureManifestSha256-and$ads.default_streams_unchanged-eq$true-and$ads.named_stream_count-eq5-and$ads.total_unique_stream_count-eq8-and$ads.named_stream_alias_views-eq15-and@($ads.streams).Count-eq5-and[guid]$ads.disk_guid-eq[guid]$fixture.disk_guid-and[guid]$ads.partition_guid-eq[guid]$fixture.partition_guid) 'Pinned ADS fixture differs from its original hard-link baseline.'
 Need ($sparse.kind-ceq'sparse-fixture'-and$sparse.success-eq$true-and@($sparse.streams).Count-eq3-and$sparse.source.binding.disk_number-eq6-and[guid]$sparse.source.binding.identity.disk_guid-eq[guid]$fixture.disk_guid-and[guid]$sparse.source.binding.identity.partition_guid-eq[guid]$fixture.partition_guid) 'Pinned sparse fixture differs from the enrolled source.'
 foreach($stream in $sparse.streams){Need ($stream.content_digest_algorithm-ceq'xxh3-128'-and$stream.content_digest-cmatch'\A[0-9a-f]{32}\z') 'Sparse fixture requires its independent same-pass content digest.'}
 Need ($attribute.schema_version-eq1-and$attribute.kind-ceq'ntfs-attribute-list-fixture'-and$attribute.success-eq$true-and$attribute.probe_id-cmatch'\A[0-9a-f]{32}\z'-and(AttributePreparationValid $attribute)-and$attribute.base_file_record.attribute_list_present-eq$true-and@($attribute.final_streams).Count-eq3-and@($attribute.hard_links).Count-eq2-and$attribute.source.binding.disk_number-eq6-and[guid]$attribute.source.binding.identity.disk_guid-eq[guid]$fixture.disk_guid-and[guid]$attribute.source.binding.identity.partition_guid-eq[guid]$fixture.partition_guid-and$attribute.source.binding.identity.partition_bytes-eq52GB-and$attribute.source.binding.identity.partition_offset-eq32MB) 'Pinned ATTRIBUTE_LIST relocation evidence differs.'
 if($eaEnabled){$eaFile=Ordinary $EaFixturePath 4MB;Need ((Get-FileHash -LiteralPath $eaFile.FullName).Hash.ToLowerInvariant()-ceq$EaFixtureSha256) 'EA fixture pin differs.';$ea=[IO.File]::ReadAllText($eaFile.FullName)|ConvertFrom-Json;Need ($ea.schema_version-eq1-and$ea.kind-ceq'ntfs-ea-fixture'-and$ea.success-eq$true-and$ea.canonical_objects-eq4-and@($ea.objects).Count-eq4-and$ea.ea_entries-eq7-and$ea.directories_with_eas-eq2-and$ea.file_identities_with_eas-eq2-and$ea.hardlink_names-eq2-and$ea.need_ea_flag_readback_verified-eq$true-and$ea.large_ea_value_bytes-eq8192-and$ea.move_file_calls-eq0-and$ea.raw_volume_write_calls-eq0-and$ea.existing_file_ea_set_calls-eq0-and$ea.source.binding.disk_number-eq6-and[guid]$ea.source.binding.identity.disk_guid-eq[guid]$fixture.disk_guid-and[guid]$ea.source.binding.identity.partition_guid-eq[guid]$fixture.partition_guid-and$ea.source.binding.identity.partition_bytes-eq52GB-and$ea.source.binding.identity.partition_offset-eq32MB) 'Pinned EA fixture/source differs.'}
 if($securityEnabled){
  $securityFile=Ordinary $SecurityFixturePath 8MB;$securityTool=Ordinary $SecurityToolPath 64MB
  Need ((Get-FileHash -LiteralPath $securityFile.FullName).Hash.ToLowerInvariant()-ceq$SecurityFixtureSha256-and(Get-FileHash -LiteralPath $securityTool.FullName).Hash.ToLowerInvariant()-ceq$SecurityToolSha256) 'Security fixture/tool pin differs.'
  $security=[IO.File]::ReadAllText($securityFile.FullName)|ConvertFrom-Json
  Need ($security.schema_version-eq1-and$security.kind-ceq'ntfs-security-fixture'-and$security.success-eq$true-and$security.canonical_objects-eq8-and@($security.objects).Count-eq8-and$security.user_files-eq7-and$security.directories-eq1-and$security.requested_vs_observed_states_recorded-eq$true-and$security.source_payload_relocations-eq0-and$security.raw_volume_writes-eq0-and$security.existing_file_security_modified-eq$false-and$security.audit_policy_modified-eq$false-and$security.experiment_id-cmatch'\A[0-9a-f]{32}\z'-and$security.source.binding.disk_number-eq6-and[guid]$security.source.binding.identity.disk_guid-eq[guid]$fixture.disk_guid-and[guid]$security.source.binding.identity.partition_guid-eq[guid]$fixture.partition_guid-and$security.source.binding.identity.partition_bytes-eq52GB-and$security.source.binding.identity.partition_offset-eq32MB) 'Pinned security fixture/source differs.'
 }
 if($reparseEnabled){
  $reparseFile=Ordinary $ReparseFixturePath 8MB;$reparseTool=Ordinary $ReparseToolPath 64MB
  Need ((Get-FileHash -LiteralPath $reparseFile.FullName).Hash.ToLowerInvariant()-ceq$ReparseFixtureSha256-and(Get-FileHash -LiteralPath $reparseTool.FullName).Hash.ToLowerInvariant()-ceq$ReparseToolSha256) 'Reparse fixture/tool pin differs.'
  $reparse=[IO.File]::ReadAllText($reparseFile.FullName)|ConvertFrom-Json
  Need ($reparse.schema_version-eq1-and$reparse.kind-ceq'ntfs-reparse-fixture'-and$reparse.success-eq$true-and$reparse.canonical_objects-eq10-and@($reparse.objects).Count-eq10-and$reparse.normal_payload_files-eq2-and$reparse.reparse_points-eq6-and$reparse.file_reparse_points-eq3-and$reparse.directory_reparse_points-eq3-and$reparse.functional_existing_routes_verified-eq4-and$reparse.source_payload_relocations-eq0-and$reparse.raw_volume_writes-eq0-and$reparse.existing_file_modified-eq$false-and$reparse.existing_file_reparse_setters-eq0-and$reparse.dangling_or_cycle_traversals-eq0-and$reparse.experiment_id-cmatch'\A[0-9a-f]{32}\z'-and$reparse.source.binding.disk_number-eq6-and[guid]$reparse.source.binding.identity.disk_guid-eq[guid]$fixture.disk_guid-and[guid]$reparse.source.binding.identity.partition_guid-eq[guid]$fixture.partition_guid-and$reparse.source.binding.identity.partition_bytes-eq52GB-and$reparse.source.binding.identity.partition_offset-eq32MB) 'Pinned reparse fixture/source differs.'
 }
 if($compressionEnabled){
  $compressionFile=Ordinary $CompressionFixturePath 8MB;$compressionTool=Ordinary $CompressionToolPath 64MB
  Need ((Get-FileHash -LiteralPath $compressionFile.FullName).Hash.ToLowerInvariant()-ceq$CompressionFixtureSha256-and(Get-FileHash -LiteralPath $compressionTool.FullName).Hash.ToLowerInvariant()-ceq$CompressionToolSha256) 'Compression fixture/tool pin differs.'
  $compression=[IO.File]::ReadAllText($compressionFile.FullName)|ConvertFrom-Json
  Need ($compression.schema_version-eq1-and$compression.kind-ceq'ntfs-compression-fixture'-and$compression.success-eq$true-and$compression.filesystem-ceq'NTFS'-and$compression.canonical_objects-eq8-and@($compression.objects).Count-eq8-and$compression.default_streams-eq6-and$compression.named_streams-eq1-and$compression.source_payload_relocations-eq0-and$compression.raw_volume_writes-eq0-and$compression.existing_file_modified-eq$false-and$compression.experiment_id-cmatch'\A[0-9a-f]{32}\z') 'Pinned complete compression fixture differs.'
 }
 Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
 $configuration=Get-LabConfiguration -WorkspaceRoot $workspace;$capacity=Get-LabCapacity -Configuration $configuration
 Need ($capacity.MaximumActualBytes-eq329374052988-and$capacity.MinimumFreeBytes-eq17179869184) 'Fixed storage epoch differs.'
 Assert-LabCapacity -Capacity $capacity -AdditionalBytes 8GB;HostGuard
 New-Item -ItemType Directory -Path $root -ErrorAction Stop|Out-Null;$created=$true
 $c=@{run_id=$run;stage=$stage;task=$task;ea_fixture_enabled=$eaEnabled;ea_fixture_sha256=$EaFixtureSha256;security_fixture_enabled=$securityEnabled;security_fixture_sha256=$SecurityFixtureSha256;security_tool_sha256=$SecurityToolSha256;security_tool_bytes=$(if($securityEnabled){$securityTool.Length}else{0});reparse_fixture_enabled=$reparseEnabled;reparse_fixture_sha256=$ReparseFixtureSha256;reparse_tool_sha256=$ReparseToolSha256;reparse_tool_bytes=$(if($reparseEnabled){$reparseTool.Length}else{0});compression_fixture_enabled=$compressionEnabled;compression_fixture_sha256=$CompressionFixtureSha256;compression_tool_sha256=$CompressionToolSha256;compression_tool_bytes=$(if($compressionEnabled){$compressionTool.Length}else{0});attribute_sha256=$AttributeFixtureSha256;fixture_sha256=$HardlinkFixtureManifestSha256;ads_sha256=$AdsManifestSha256;sparse_sha256=$SparseFixtureSha256;digest_sha256=$DigestToolSha256;digest_bytes=$digestFile.Length;binary_sha256=$PublicExeSha256;binary_bytes=$exeFile.Length;source_commit=$SourceCommit;main_source_sha256=$MainSourceSha256;partition_number=$fixture.partition_number;minimum_extent_only_streams=$MinimumExtentOnlyStreams;baseline_enabled=$baseline.enabled;baseline_sha256=$baseline.sha256;baseline_request_sha256=$baseline.request_sha256;baseline_result_sha256=$baseline.result_sha256;baseline_basis_sha256=$baseline.basis_sha256}
 Save 'intent.json' @{schema_version=1;kind='public-attribute-list-conversion-intent';configuration=$c;ea_fixture_enabled=$eaEnabled;ea_fixture_sha256=$EaFixtureSha256;security_fixture_enabled=$securityEnabled;security_fixture_sha256=$SecurityFixtureSha256;security_tool_sha256=$SecurityToolSha256;security_tool_bytes=$(if($securityEnabled){$securityTool.Length}else{0});reparse_fixture_enabled=$reparseEnabled;reparse_fixture_sha256=$ReparseFixtureSha256;reparse_tool_sha256=$ReparseToolSha256;reparse_tool_bytes=$(if($reparseEnabled){$reparseTool.Length}else{0});compression_fixture_enabled=$compressionEnabled;compression_fixture_sha256=$CompressionFixtureSha256;compression_tool_sha256=$CompressionToolSha256;compression_tool_bytes=$(if($compressionEnabled){$compressionTool.Length}else{0});vm_id=$vmId.ToString('D');parent_id=$ExpectedParent.ToString('D');checkpoint_ids=$ids;attribute_fixture=$attributeFile.FullName;attribute_fixture_sha256=$AttributeFixtureSha256;fixture_path=$fixtureFile.FullName;ads_manifest=$adsFile.FullName;sparse_fixture=$sparseFile.FullName;digest_tool=$digestFile.FullName;binary_path=$exeFile.FullName;capacity=$capacity;forecast_bytes=8GB;manual_binding=$false;source_layout_prearranged=$true;source_layout_preparation='independent fixture retains 1024 verified historical NTFS-managed moves';fixture_read_only_completion=(ReadOnlyAttributeCompletion $attribute);fixture_new_move_file_calls=$(if(ReadOnlyAttributeCompletion $attribute){0}else{1024});utc=[DateTime]::UtcNow.ToString('o');minimum_extent_only_streams=$MinimumExtentOnlyStreams;baseline_provenance=$baseline.provenance;baseline_grants_product_authority=$false}
 $body=@'
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$c=[Text.UTF8Encoding]::new($false).GetString([Convert]::FromBase64String('__CONFIG__'))|ConvertFrom-Json
$phase='preflight';$nativeExit=$null;$process=$null
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function Save([string]$Name,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));Need ($bytes.Length-le1MB) 'Wrapper receipt exceeds one MiB.';$file=[IO.File]::Open((Join-Path $c.stage $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
function Json([string]$Path,[long]$Maximum=64MB){$m=Get-Item -LiteralPath $Path -Force;Need ($Path.StartsWith('C:\',[StringComparison]::OrdinalIgnoreCase)-and-not$m.PSIsContainer-and-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$m.Length-gt0-and$m.Length-le$Maximum) 'Bounded ordinary closed C JSON required.';$a=$m.Directory;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse C JSON ancestry.';$a=$a.Parent};return ([IO.File]::ReadAllText($Path)|ConvertFrom-Json)}
function Idle{Need (@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-eq0-and@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.TaskName-cne$c.task-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-eq0) 'Another project worker or task is active.'}
function Log([string]$Path){$m=Get-Item -LiteralPath $Path -Force;Need (-not$m.PSIsContainer-and-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$m.Length-le8MB) 'Bounded native log required.';$reader=[IO.StreamReader]::new($Path);try{$chars=[char[]]::new(32768);$n=$reader.ReadBlock($chars,0,$chars.Length);return @{path=$Path;bytes=$m.Length;sha256=(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant();text=[string]::new($chars,0,$n);truncated=($reader.Peek()-ne-1)}}finally{$reader.Dispose()}}
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
function LabSnapshotQuery($Snapshot,[int]$Class,[int]$Length){$q=@($Snapshot.queries|Where-Object class -eq $Class);Need ($q.Count-eq1-and$null-eq$q[0].native_error-and@($q[0].bytes).Count-eq$Length) 'Current timestamp proof query missing/refused.';return ,[byte[]]$q[0].bytes}
function LabSnapshotTimes($Snapshot){$b=LabSnapshotQuery $Snapshot 0 40;return ,@([BitConverter]::ToUInt64($b,0),[BitConverter]::ToUInt64($b,8),[BitConverter]::ToUInt64($b,16),[BitConverter]::ToUInt64($b,24))}
function ReconcileLabAccessTime($Current,$Old,$Context){
 if($Current.stored_times[1]-eq$Old.stored_times[1]){return $null}
 $raw=@($Context.raw.ntfs.files|Where-Object {$_.record_number-eq$Current.record_number-and$_.sequence_number-eq$Current.sequence_number});$source=@($Context.native.files|Where-Object {$_.identity.record_number-eq$Current.record_number-and$_.identity.sequence_number-eq$Current.sequence_number});$view=@($Context.views.assessment.source_view.objects|Where-Object {$_.record_number-eq$Current.record_number-and$_.sequence_number-eq$Current.sequence_number});$target=@($Context.final.native.native.objects|Where-Object {SameArray $_.components $Current.path})
 Need ($raw.Count-eq1-and$source.Count-eq1-and$null-eq$source[0].open_error-and$view.Count-eq1-and$view[0].metadata.matched-eq$true-and$target.Count-eq1-and$Context.final.success-eq$true) 'Current source/target timestamp provenance is incomplete.'
 $si=$raw[0].standard_information;$stored=@($si.creation_time,$si.access_time,$si.modification_time,$si.mft_change_time);Need (SameArray $stored $Current.stored_times) 'Current canonical times differ from current persisted raw STANDARD_INFORMATION.'
 $sb=LabSnapshotTimes $source[0].before;$sa=LabSnapshotTimes $source[0].after;$tb=LabSnapshotTimes $target[0].before;$ta=LabSnapshotTimes $target[0].after;$sv=$view[0].timestamps
 Need ($null-ne$sv-and(SameArray $sv.stored $stored)-and(SameArray $sv.native_before $sb)-and(SameArray $sv.native_after $sa)-and$sv.preservation_authority-ceq'persisted STANDARD_INFORMATION after freeze; requires actual unchanged read-only source') 'Current source timestamp view is not bound to actual persisted/native observations.'
 foreach($at in @(0,2,3)){Need ($sb[$at]-eq$stored[$at]-and$sa[$at]-eq$stored[$at]) 'Current source changed a timestamp outside the explicit cached-access policy.'}
 $cached=$sb[1]-ne$stored[1]-or$sa[1]-ne$stored[1];Need ($sv.cached_access_differs-eq$cached) 'Current native cached-access policy record differs.'
 $sourceId=LabSnapshotQuery $source[0].before 18 24;$sourceAfterId=LabSnapshotQuery $source[0].after 18 24;$targetId=LabSnapshotQuery $target[0].before 18 24;$targetAfterId=LabSnapshotQuery $target[0].after 18 24;Need ((SameArray $sourceId $sourceAfterId)-and(SameArray $targetId $targetAfterId)) 'Current timestamp source/target identity changed.';$reference=[BitConverter]::ToUInt64($sourceId,8);Need (($reference-band[uint64]281474976710655)-eq$Current.record_number-and[uint16]($reference-shr48)-eq$Current.sequence_number) 'Current native source identity differs from the canonical raw record.'
 $exception=$null
 if(-not((SameArray $tb $stored)-and(SameArray $ta $stored))){
  $cache=$Context.final.native.native.post_mount_indexer_cache;Need ($Current.directory-eq$true-and(SameArray $Current.path @('System Volume Information'))-and$null-ne$cache-and(SameArray $tb $ta)-and$tb[0]-eq$stored[0]) 'Current target times must equal current source times for every ordinary or sparse file/directory.'
  $cacheTimes=LabSnapshotTimes $cache.before;Need ($cacheTimes[0]-ge$stored[3]-and$cacheTimes[0]-le$cache.observed_filetime) 'Source-absent indexer cache does not justify the explicit SVI-directory time scope.';foreach($at in @(1,2,3)){Need ($tb[$at]-ge$stored[$at]-and$tb[$at]-le$cache.observed_filetime) 'SVI directory time is outside the existing observed indexer-cache interval.'};$exception='existing-source-absent-indexer-cache-SVI-directory-times'
 }
 return @{record_number=$Current.record_number;sequence_number=$Current.sequence_number;path=$Current.path;old_baseline_access_time=$Old.stored_times[1];current_raw_source_times=$stored;current_canonical_times=@($Current.stored_times);current_native_source_before=$sb;current_native_source_after=$sa;current_native_source_cached_access_differs=$cached;current_source_metadata_matched=$view[0].metadata.matched;current_source_metadata_policy=$view[0].metadata.detail;current_native_target_before=$tb;current_native_target_after=$ta;current_source_file_id_hex=([BitConverter]::ToString($sourceId)).Replace('-','').ToLowerInvariant();current_target_file_id_hex=([BitConverter]::ToString($targetId)).Replace('-','').ToLowerInvariant();target_timestamp_exception=$exception;comparison_only_old_access_alignment=$true;product_expectation_changed=$false;filesystem_times_changed=$false}
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
 $timeContext=@{raw=(Json (Join-Path $Records 'qualification\source-basis.json'));native=(Json (Join-Path $Records 'qualification\native-source.json'));views=(Json (Join-Path $Records 'qualification\source-assessment.json'));final=(Json (Join-Path $Records 'finalization.json'))};$timeRows=[Collections.Generic.List[object]]::new();$copy=($Expected|ConvertTo-Json -Depth 64)|ConvertFrom-Json;$oldObjects=@($baseline.objects);Need (@($copy.objects).Count-eq$oldObjects.Count) 'Independent baseline canonical object coverage differs.';$elisions=[Collections.Generic.List[object]]::new()
 foreach($object in $copy.objects){
  $matches=@($oldObjects|Where-Object {$_.record_number-eq$object.record_number-and$_.sequence_number-eq$object.sequence_number-and(SameArray $_.path $object.path)});Need ($matches.Count-eq1) 'Independent baseline canonical identity/path differs.';$old=$matches[0];$timeProof=ReconcileLabAccessTime $object $old $timeContext;if($null-ne$timeProof){$timeRows.Add($timeProof);$object.stored_times[1]=$old.stored_times[1]}
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
 return @{enabled=$true;observer_expectation=$copy;product_expectation=$Expected;baseline=$baseline;baseline_basis=$oldBasis;baseline_raw_by_identity=$oldRaw;native_source=$newNative;receipt=@{scope='lab-content-baseline-v1';baseline_used=$true;baseline_sha256=$c.baseline_sha256;baseline_request_sha256=$c.baseline_request_sha256;baseline_result_sha256=$c.baseline_result_sha256;baseline_source_basis_sha256=$c.baseline_basis_sha256;canonical_metadata_exact_except_explicit_content_evidence=($timeRows.Count-eq0);canonical_metadata_exact_except_content_evidence_and_recorded_access_times=$true;current_access_time_reconciliations=$timeRows.ToArray();access_time_reconciliation_pins=@{source_basis=(Get-FileHash -LiteralPath (Join-Path $Records 'qualification\source-basis.json') -Algorithm SHA256).Hash.ToLowerInvariant();native_source=(Get-FileHash -LiteralPath (Join-Path $Records 'qualification\native-source.json') -Algorithm SHA256).Hash.ToLowerInvariant();source_assessment=(Get-FileHash -LiteralPath (Join-Path $Records 'qualification\source-assessment.json') -Algorithm SHA256).Hash.ToLowerInvariant();expectation=(Get-FileHash -LiteralPath (Join-Path $Records 'expectation.json') -Algorithm SHA256).Hash.ToLowerInvariant();finalization=(Get-FileHash -LiteralPath (Join-Path $Records 'finalization.json') -Algorithm SHA256).Hash.ToLowerInvariant()};historical_digests_bound_to_full_raw_inspection=$true;source_binding_identical=$true;hashless_product_streams=$hashless;comparison_streams_restored=$elisions.Count;comparison_only_clone=$true;product_expectation_written=$false;grants_product_authority=$false;elided_streams=$elisions.ToArray()}}
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
function Fsutil([string[]]$Arguments){$old=[Console]::OutputEncoding;try{[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$lines=@(& "$env:SystemRoot\System32\fsutil.exe" @Arguments 2>&1|ForEach-Object {[string]$_});$exit=$LASTEXITCODE;Need ($exit-eq0-and($lines-join"`n").Length-le65536) 'Bounded fsutil call failed.';return ,$lines}finally{[Console]::OutputEncoding=$old}}
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
function VerifyAds($Fixture,$Ads){
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
  $named=@($Ads.streams|Where-Object group -CEQ $group.name);$expectedNames=@(':$DATA')+@($named|ForEach-Object {$_.name});if($group.name-ceq'ordinary'){$expectedNames+='Sparse.Data'}
  foreach($alias in $group.names){
   $streams=@(Get-Item -LiteralPath $alias.path -Stream * -ErrorAction Stop);$actualNames=@($streams|ForEach-Object {[string]$_.Stream})
   Need ($actualNames.Count-eq$expectedNames.Count-and@(Compare-Object $expectedNames $actualNames -CaseSensitive).Count-eq0) 'Native ADS enumeration is not the exact expected set.'
   $entries=@();foreach($entry in $streams){$length=if($entry.Stream-ceq':$DATA'){$group.logical_length}elseif($group.name-ceq'ordinary'-and$entry.Stream-ceq'Sparse.Data'){32MB+91}else{($named|Where-Object name -CEQ $entry.Stream).length};Need ($entry.Length-eq$length) 'Native stream enumeration length differs.';$entries+=@{name=[string]$entry.Stream;length=$entry.Length}}
   $enumerations.Add(@{path=$alias.path;streams=$entries})
  }
 }
 Need ($reports.Count-eq5-and$views-eq15-and$total-eq$Ads.named_logical_bytes) 'ADS fixture totals differ.'
 return @{named_stream_count=$reports.Count;alias_stream_views=$views;named_logical_bytes=$total;streams=$reports.ToArray();enumerations=$enumerations.ToArray();digest_algorithm='sha256'}
}
function VerifySparseFixture($Sparse){
 $tool=Join-Path $c.stage 'lab-content-digest.exe';Need ((Get-Item -LiteralPath $tool).Length-eq$c.digest_bytes-and(Get-FileHash -LiteralPath $tool).Hash.ToLowerInvariant()-ceq$c.digest_sha256) 'Pinned streaming digest tool differs.'
 $rows=@($Sparse.streams);Need ($rows.Count-eq3) 'Three sparse fixture streams required.'
 $paths=[Collections.Generic.List[string]]::new();$expectedHashes=[Collections.Generic.List[string]]::new();$queries=[Collections.Generic.List[object]]::new()
 foreach($stream in $rows){
  Need ($stream.path-in@('H:\sparse-islands.bin','H:\all-hole.bin','H:\ordinary.bin:Sparse.Data:$DATA')-and$stream.length-gt0-and$stream.length-le33MB-and$stream.content_digest-cmatch'\A[0-9a-f]{32}\z') 'Unexpected sparse fixture stream.'
  if($stream.path-ceq'H:\ordinary.bin:Sparse.Data:$DATA'){$metadata=@(Get-Item -LiteralPath 'H:\ordinary.bin' -Stream 'Sparse.Data' -ErrorAction Stop);Need ($metadata.Count-eq1-and$metadata[0].Length-eq$stream.length) 'Sparse ADS EOF differs.'}
  else{$metadata=Get-Item -LiteralPath $stream.path -Force;Need ($metadata-is[IO.FileInfo]-and$metadata.Length-eq$stream.length-and($metadata.Attributes-band[IO.FileAttributes]::SparseFile)) 'Sparse file length/attribute differs.'}
  $paths.Add([string]$stream.path);$expectedHashes.Add([string]$stream.content_digest)
  $queries.Add(@{path=$stream.path;length=$stream.length;query_sparse=(Fsutil @('sparse','queryflag',$stream.path));query_extents=(Fsutil @('file','queryextents',$stream.path));query_file_id=(Fsutil @('file','queryfileid',$stream.path))})
 }
 $islands=@($rows|Where-Object path -CEQ 'H:\sparse-islands.bin');Need ($islands.Count-eq1) 'Sparse islands stream absent.'
 $alias='H:\nested\sparse-link.bin';$meta=Get-Item -LiteralPath $alias -Force;Need ($meta.Length-eq$islands[0].length) 'Sparse hard-link EOF differs.';$paths.Add($alias);$expectedHashes.Add([string]$islands[0].content_digest)
 $arguments=$paths.ToArray();$lines=@(& $tool @arguments);$exit=$LASTEXITCODE;Need ($exit-eq0-and($lines-join'').Length-le4096) 'Streaming digest helper failed.';$digests=@(($lines-join'')|ConvertFrom-Json|ForEach-Object {$_});Need ($digests.Count-eq4) 'Streaming digest count differs.'
 for($i=0;$i-lt4;$i++){Need ($digests[$i]-ceq$expectedHashes[$i]) 'Sparse logical content differs from independent fixture digest.'}
 $left=[regex]::Matches(((Fsutil @('file','queryfileid','H:\sparse-islands.bin'))-join"`n"),'0x[0-9a-fA-F]+');$right=[regex]::Matches(((Fsutil @('file','queryfileid',$alias))-join"`n"),'0x[0-9a-fA-F]+');Need ($left.Count-eq1-and$right.Count-eq1-and$left[0].Value-ceq$right[0].Value) 'Sparse hard link has another identity.'
 return @{streams_verified=3;logical_paths_hashed=4;content_digest_algorithm='xxh3-128';bounded_digest_reader_bytes=1MB;hardlink_same_identity=$true;digests=$digests;queries=$queries}
}
function CheckSparseObservation($Layout,$Observation,[long]$Length){
 Need ($null-ne$Observation-and$Observation.allocation_matches-eq$true-and$Observation.data_storage_valid-eq$true-and$Observation.expected.initialized_length-eq$Layout.initialized_length) 'Native sparse allocation/storage validity failed.'
 foreach($field in @('allocated','holes')){$wanted=@($Layout.$field);$actual=@($Observation.expected.$field);Need ($wanted.Count-eq$actual.Count) 'Sparse range count differs.';for($i=0;$i-lt$wanted.Count;$i++){Need ($wanted[$i].offset-eq$actual[$i].offset-and$wanted[$i].length-eq$actual[$i].length) 'Native sparse layout differs.'}}
 $allocated=@($Layout.allocated);$actual=@($Observation.actual_allocated);Need ($allocated.Count-eq$actual.Count) 'Actual sparse allocation count differs.';for($i=0;$i-lt$allocated.Count;$i++){Need ($allocated[$i].offset-eq$actual[$i].offset-and$allocated[$i].length-eq$actual[$i].length) 'Actual sparse allocation differs.'}
 $end=0L;$holeBytes=0L;foreach($hole in @($Layout.holes)){Need ($hole.length-gt0-and$hole.offset-ge$end-and$hole.offset+$hole.length-le$Length) 'Invalid expected sparse holes.';$end=$hole.offset+$hole.length;$holeBytes+=$hole.length};Need ($holeBytes-gt0) 'Sparse fixture has no expected logical holes.'
}

function ReadOnlyAttributeCompletion($Fixture){$p=$Fixture.PSObject.Properties['read_only_completion'];return $null-ne$p-and$p.Value-eq$true}
function AttributePreparationValid($Fixture){
 if(ReadOnlyAttributeCompletion $Fixture){return ($Fixture.prior_verified_move_count-eq1024-and$Fixture.current_complete_extent_count-eq1024-and$Fixture.all_prior_payload_mappings_match-eq$true-and$Fixture.all_initial_logical_hashes_match-eq$true-and$Fixture.move_file_calls-eq0-and$Fixture.source_write_requests-eq0-and@($Fixture.moves).Count-eq0-and$Fixture.prior_report_sha256-cmatch'\A[0-9a-f]{64}\z'-and$Fixture.prior_report_path-cmatch'\AC:\\'-and$Fixture.prior_report_path-cnotmatch'\.\.|[\r\n\x00]')}
 return ($Fixture.verified_move_count-eq1024-and@($Fixture.moves).Count-eq1024-and@($Fixture.moves|Where-Object {$_.verified-ne$true}).Count-eq0)
}
function VerifyAttributePreparation($Fixture){
 Need (AttributePreparationValid $Fixture) 'Attribute preparation observations differ.'
 if(-not(ReadOnlyAttributeCompletion $Fixture)){return @{mode='creator';new_move_file_calls=1024;verified_move_count=1024;observation_grants_source_write_authority=$false}}
 $path=[string]$Fixture.prior_report_path;$prior=Json $path 4MB;Need ((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-ceq$Fixture.prior_report_sha256) 'Original prior fixture report pin differs.'
 Need ($prior.schema_version-eq1-and$prior.kind-ceq'ntfs-attribute-list-fixture'-and$prior.probe_id-ceq$Fixture.probe_id-and@($prior.moves).Count-eq1024-and@($prior.moves|Where-Object {$_.verified-ne$true-or$_.submitted-ne$true-or$null-ne$_.native_error}).Count-eq0-and[guid]$prior.source.binding.identity.disk_guid-eq[guid]$Fixture.source.binding.identity.disk_guid-and[guid]$prior.source.binding.identity.partition_guid-eq[guid]$Fixture.source.binding.identity.partition_guid) 'Original prior report lacks 1024 verified source-bound NTFS moves.'
 return @{mode='read_only_completion';prior_report_path=$path;prior_report_sha256=$Fixture.prior_report_sha256;prior_verified_move_count=1024;current_complete_extent_count=1024;all_prior_payload_mappings_match=$true;all_initial_logical_hashes_match=$true;new_move_file_calls=0;source_write_requests=0;observation_grants_source_write_authority=$false}
}
function AttributeShape($Fixture){
 Need ($Fixture.kind-ceq'ntfs-attribute-list-fixture'-and$Fixture.success-eq$true-and$Fixture.probe_id-cmatch'\A[0-9a-f]{32}\z'-and(AttributePreparationValid $Fixture)-and$Fixture.base_file_record.attribute_list_present-eq$true) 'Incomplete attribute fixture.'
 $base='H:\attribute-list-'+$Fixture.probe_id+'.bin';$names=@($base,('H:\attribute-list-'+$Fixture.probe_id+'-alias.bin'),('H:\nested\attribute-list-'+$Fixture.probe_id+'-nested.bin'));$aliases=@($Fixture.hard_links)
 Need ($aliases.Count-eq2-and(SameArray @($aliases|ForEach-Object {$_.path}|Sort-Object) @($names[1..2]|Sort-Object))) 'Attribute aliases differ.'
 $rows=@($Fixture.final_streams);Need ($rows.Count-eq3) 'Three attribute streams required.';$streams=@{};$id=$null
 foreach($row in $rows){
  $name=[string]::new([char[]]@($row.name_utf16|ForEach-Object {[char][int]$_}));Need ($name-cin@('','Segments','Note')-and-not$streams.ContainsKey($name)) 'Unexpected/duplicate attribute stream.'
  $path=if($name.Length){$base+':'+$name+':$DATA'}else{$base};$length=if($name-ceq'Note'){64L}else{2MB}
  Need ($row.path-ceq$path-and$row.hashes.length-eq$length-and$row.hashes.sha256-cmatch'\A[0-9a-f]{64}\z'-and$row.hashes.content_digest-cmatch'\A[0-9a-f]{32}\z'-and$row.file_id_info-cmatch'\A[0-9a-f]{48}\z') 'Attribute stream path/size/digest differs.'
  if($null-eq$id){$id=[string]$row.file_id_info}else{Need ($id-ceq$row.file_id_info) 'Attribute stream IDs differ.'};$streams[$name]=$row
 }
 Need ($streams.ContainsKey('')-and$streams.ContainsKey('Segments')-and$streams.ContainsKey('Note')-and@($aliases|Where-Object {$_.file_id_info-cne$id}).Count-eq0) 'Attribute stream/alias coverage differs.'
 return @{base=$base;paths=$names;streams=$streams;file_id_info=$id}
}
function StreamSha256([string]$Path,[long]$Length){
 $stream=[regex]::Match($Path,'\A([A-Za-z]:\\[^:]+):([^:]+):\$DATA\z')
 if($stream.Success){
  # The Windows PowerShell filesystem provider opens ADS through the native
  # stream interface; .NET Framework File.Open rejects this path spelling.
  $base=$stream.Groups[1].Value;$name=$stream.Groups[2].Value;$sha=[Security.Cryptography.SHA256]::Create();$count=0L
  try{Need ((Get-Item -LiteralPath $base -Stream $name).Length-eq$Length) 'Attribute ADS length differs.';Get-Content -LiteralPath $base -Stream $name -Encoding Byte -ReadCount 65536 -ErrorAction Stop|ForEach-Object {$block=[byte[]]$_;$count+=$block.Length;Need ($count-le$Length) 'Attribute ADS exceeds expected EOF.';$null=$sha.TransformBlock($block,0,$block.Length,$block,0)};$null=$sha.TransformFinalBlock([byte[]]::new(0),0,0);Need ($count-eq$Length-and(Get-Item -LiteralPath $base -Stream $name).Length-eq$Length) 'Attribute ADS changed/ended early.';return ([BitConverter]::ToString($sha.Hash)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
 }
 $file=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$sha=[Security.Cryptography.SHA256]::Create();$buffer=[byte[]]::new(65536);$count=0L
 try{Need ($file.Length-eq$Length) 'Attribute stream length differs.';while(($n=$file.Read($buffer,0,$buffer.Length))-gt0){$count+=$n;Need ($count-le$Length) 'Attribute stream exceeds expected EOF.';$null=$sha.TransformBlock($buffer,0,$n,$buffer,0)};$null=$sha.TransformFinalBlock([byte[]]::new(0),0,0);Need ($count-eq$Length-and$file.Length-eq$Length) 'Attribute stream changed/ended early.';return ([BitConverter]::ToString($sha.Hash)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose();$file.Dispose()}
}
function VerifyAttributeFixture($Fixture,[string]$Filesystem){
 $shape=AttributeShape $Fixture;$names=@($shape.paths);$expectedLinks=@($names|ForEach-Object {$_.Substring(2)}|Sort-Object);$reports=[Collections.Generic.List[object]]::new();$id=$null;$views=0
 foreach($path in $names){
  $meta=Get-Item -LiteralPath $path -Force;Need ($meta-is[IO.FileInfo]-and-not($meta.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$meta.Length-eq2MB) 'Attribute alias type/EOF differs.'
  $idText=Fsutil @('file','queryfileid',$path);$matches=[regex]::Matches(($idText-join"`n"),'0x[0-9a-fA-F]+');Need ($matches.Count-eq1) 'One attribute file ID required.';$current=$matches[0].Value.ToLowerInvariant();if($null-eq$id){$id=$current}else{Need ($id-ceq$current) 'Attribute aliases lost shared identity.'}
  if($Filesystem-ceq'NTFS'){$want='0x';for($at=46;$at-ge16;$at-=2){$want+=$shape.file_id_info.Substring($at,2)};Need ($current-ceq$want) 'Original attribute NTFS ID changed.'}
  $linkText=Fsutil @('hardlink','list',$path);$links=@($linkText|ForEach-Object {$line=$_.Trim();if($line.Length){if($line.StartsWith('H:\',[StringComparison]::OrdinalIgnoreCase)){$line=$line.Substring(2)};$line}}|Sort-Object);Need (SameArray $links $expectedLinks) 'Attribute hard-link set differs.'
  $enumerated=@(Get-Item -LiteralPath $path -Stream * -ErrorAction Stop);Need (SameArray @($enumerated|ForEach-Object {$_.Stream}|Sort-Object) @(':$DATA','Segments','Note'|Sort-Object)) 'Attribute ADS set differs.'
  $hashes=@{};foreach($name in @('','Segments','Note')){$wanted=$shape.streams[$name];$full=if($name.Length){$path+':'+$name+':$DATA'}else{$path};$hash=StreamSha256 $full $wanted.hashes.length;Need ($hash-ceq$wanted.hashes.sha256) 'Attribute payload differs from independent fixture.';$hashes[$name]=@{length=$wanted.hashes.length;sha256=$hash};$views++}
  $after=Fsutil @('file','queryfileid',$path);Need (SameArray $idText $after) 'Attribute identity changed during readback.';$reports.Add(@{path=$path;file_id=$current;hashes=$hashes;hardlink_set=$links})
 }
 Need ($views-eq9) 'Attribute alias/stream coverage differs.';return @{filesystem=$Filesystem;file_id=$id;names=3;unique_streams=3;alias_stream_hashes=9;hash_algorithm='sha256';read_buffer_bytes=65536;views=$reports.ToArray()}
}
function VerifyAssemblyLedger([string]$Records,$Fixture){
 # general_qualification.rs saves the actual raw inspection under ntfs here.
 $path=Join-Path $Records 'qualification\source-basis.json';$basis=Json $path;$raw=$basis.ntfs;Need ($raw.schema_version-eq1-and$raw.records_scanned-gt0) 'Frozen raw inventory absent.'
 # inventory_complete describes the raw-only diagnostic. Actual admission
 # combines its system-metadata dispositions with independent native evidence.
 # Check record conservation here; the enclosing observer checks source_admitted.
 $physicalRecords=[Collections.Generic.HashSet[UInt64]]::new()
 foreach($record in $raw.files){Need ($physicalRecords.Add([UInt64]$record.record_number)-and$record.sequence_number-gt0) 'Duplicate canonical physical record.'}
 foreach($ledger in $raw.attribute_assemblies){foreach($extension in $ledger.extensions){Need ($physicalRecords.Add([UInt64]$extension.record_number)-and$extension.sequence_number-gt0) 'Duplicate physical extension record.'}}
 Need ($physicalRecords.Count-eq$raw.records_scanned) 'Frozen physical-record ledger is incomplete.'
 $reference=[uint64]$Fixture.base_file_record.file_reference;$number=$reference-band[uint64]281474976710655;$sequence=[uint16]($reference-shr48)
 $assemblies=@($raw.attribute_assemblies|Where-Object {$_.base.record_number-eq$number-and$_.base.sequence_number-eq$sequence});Need ($assemblies.Count-eq1) 'One exact frozen attribute assembly required.';$assembly=$assemblies[0]
 Need ($assembly.schema_version-in@(5,6)-and$assembly.base.base_file_reference-eq0-and$assembly.base.hard_link_count-eq3-and@($assembly.extensions).Count-gt0) 'Versioned multi-stream assembly with owned extensions required.'
 $physical=@{};$physical[[string]$number]=$assembly.base
 foreach($extension in $assembly.extensions){$key=[string]$extension.record_number;Need (-not$physical.ContainsKey($key)-and$extension.base_file_reference-eq$reference-and$extension.hard_link_count-eq0-and$extension.is_directory-eq$false-and$extension.raw_record_sha256-cmatch'\A[0-9a-f]{64}\z') 'Assembly extension ownership differs.';$physical[$key]=$extension;Need (@($raw.files|Where-Object record_number -EQ $extension.record_number).Count-eq0) 'Extension also published as a file.'}
 $files=@($raw.files|Where-Object {$_.record_number-eq$number-and$_.sequence_number-eq$sequence});Need ($files.Count-eq1) 'Canonical assembled file missing.';$file=$files[0]
 Need ($file.base_file_reference-eq0-and$file.hard_link_count-eq3-and@($file.names).Count-eq3-and@($file.streams).Count-eq3-and@($file.attributes|Where-Object {$_.type_code-eq32-or$_.lowest_vcn-ne0}).Count-eq0-and@($assembly.canonical_origins).Count-eq@($file.attributes).Count) 'Canonical assembled file coverage differs.'
 for($i=0;$i-lt@($assembly.canonical_origins).Count;$i++){$origin=$assembly.canonical_origins[$i];$record=$physical[[string]$origin.record_number];Need ($null-ne$record-and$record.sequence_number-eq$origin.sequence_number) 'Canonical origin record not owned.';$attrs=@($record.attributes|Where-Object instance -EQ $origin.instance);Need ($attrs.Count-eq1-and$attrs[0].type_code-eq$file.attributes[$i].type_code-and(SameArray $attrs[0].name_utf16 $file.attributes[$i].name_utf16)) 'Canonical origin type/name differs.'}
 $shape=AttributeShape $Fixture;$rawExtentStreams=0;foreach($name in @('','Segments','Note')){$row=$shape.streams[$name];$streams=@($file.streams|Where-Object {SameArray $_.name_utf16 $row.name_utf16});Need ($streams.Count-eq1-and$streams[0].logical_size-eq$row.hashes.length) 'Frozen assembled stream length/identity differs from fixture.';if(AssertRawContentOrLabExtent $raw $file $streams[0] $row.hashes.content_digest){$rawExtentStreams++}}
 return @{source_basis_path=$path;source_basis_sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant();canonical_inspection_sha256=$basis.canonical_inspection_sha256;record_number=$number;sequence_number=$sequence;assembly_schema=$assembly.schema_version;owned_extensions=@($assembly.extensions).Count;canonical_attributes=@($file.attributes).Count;canonical_origins=@($assembly.canonical_origins).Count;physical_records_verified=$physicalRecords.Count;raw_only_inventory_complete=$raw.inventory_complete;stream_digests_match=($rawExtentStreams-eq0);raw_extent_only_streams_bound=$rawExtentStreams;independent_fixture_digests_match=$true;source_admission_authority=$false}
}


function EaEntries($Set){Need ($null-ne$Set) 'EA set is missing.';$property=$Set.PSObject.Properties['entries'];if($null-eq$property){return ,@()};return ,@($property.Value)}
function EaSetMatches($Expected,$Actual){
 $wanted=EaEntries $Expected;$found=EaEntries $Actual;if($wanted.Count-ne$found.Count){return $false};$actual=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
 foreach($entry in $found){$bytes=[byte[]]@($entry.name);if($bytes.Length-eq0-or$bytes.Length-gt255-or@($bytes|Where-Object {$_-lt32-or$_-gt126}).Count){return $false};$key=[Text.Encoding]::ASCII.GetString($bytes).ToUpperInvariant();if($actual.ContainsKey($key)){return $false};$actual.Add($key,$entry)}
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach($entry in $wanted){$bytes=[byte[]]@($entry.name);if($bytes.Length-eq0-or$bytes.Length-gt255-or@($bytes|Where-Object {$_-lt32-or$_-gt126}).Count){return $false};$key=[Text.Encoding]::ASCII.GetString($bytes).ToUpperInvariant();if(-not$seen.Add($key)-or-not$actual.ContainsKey($key)){return $false};$other=$actual[$key];if($entry.flags-ne$other.flags-or-not(SameArray @($entry.value) @($other.value))){return $false}}
 return $true
}
function EaSnapshotMatches($Expected,$Snapshot){
 Need ($null-ne$Snapshot) 'Native canonical EA snapshot is missing.';$error=$Snapshot.PSObject.Properties['extended_attributes_error'];Need ($null-eq$error-or$null-eq$error.Value) 'Native canonical EA query failed.';$set=$Snapshot.PSObject.Properties['extended_attributes'];Need ($null-ne$set-and$null-ne$set.Value-and(EaSetMatches $Expected $set.Value)) 'Native canonical EA set is absent or differs.'
}
function EaFixtureShape($Fixture){
 Need ($Fixture.kind-ceq'ntfs-ea-fixture'-and$Fixture.success-eq$true-and$Fixture.experiment_id-cmatch'\A[0-9a-f]{32}\z'-and$Fixture.canonical_objects-eq4-and$Fixture.ea_entries-eq7-and$Fixture.need_ea_flag_readback_verified-eq$true) 'EA fixture shape differs.'
 $root='H:\EaFixture-'+$Fixture.experiment_id;$expected=@{};$expected[$root]=$true;$expected[$root+'\nested']=$true;$expected[$root+'\payload.bin']=$false;$expected[$root+'\nested\empty.bin']=$false
 $paths=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$ids=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$entries=0;$needed=0;$large=0
 foreach($object in $Fixture.objects){Need ($expected.ContainsKey($object.path)-and$expected[$object.path]-eq$object.directory-and$paths.Add($object.path)-and$object.file_id_info-cmatch'\A[0-9a-f]{48}\z'-and$ids.Add($object.file_id_info)-and(EaSetMatches $object.extended_attributes $object.observed_extended_attributes)) 'EA object path/type/identity/readback differs.';foreach($entry in (EaEntries $object.extended_attributes)){Need ($entry.flags-in@(0,128)-and@($entry.value).Count-gt0-and@($entry.value).Count-le65535) 'EA flags/value length invalid.';$entries++;if($entry.flags-eq128){$needed++};if(@($entry.value).Count-eq8192){$large++}}}
 Need ($paths.Count-eq4-and$entries-eq7-and$needed-eq1-and$large-eq1-and@($Fixture.payloads).Count-eq2-and@($Fixture.hard_links).Count-eq2) 'EA fixture object/entry/payload/link totals differ.'
 $payloads=@{};foreach($payload in $Fixture.payloads){$length=if($payload.path-ceq($root+'\payload.bin')){65573L}elseif($payload.path-ceq($root+'\nested\empty.bin')){0L}else{-1L};Need ($length-ge0-and-not$payloads.ContainsKey($payload.path)-and$payload.hashes.length-eq$length-and$payload.hashes.sha256-cmatch'\A[0-9a-f]{64}\z') 'EA payload path/length/digest differs.';$payloads[$payload.path]=$payload}
 $names=@(($root+'\payload.bin'),($root+'\nested\payload-link.bin'));Need (SameArray @($Fixture.hard_links|ForEach-Object {$_.path}|Sort-Object) @($names|Sort-Object)) 'EA hard-link fixture names differ.'
 return @{root=$root;payloads=$payloads;hardlink_paths=$names;entry_count=$entries;need_ea_entries=$needed}
}
function VerifyEaFixture($Fixture,[string]$Filesystem){
 $shape=EaFixtureShape $Fixture;$objects=[Collections.Generic.List[object]]::new();$idByPath=@{}
 foreach($object in $Fixture.objects){$meta=Get-Item -LiteralPath $object.path -Force;Need (-not($meta.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$meta.PSIsContainer-eq$object.directory) 'EA live object type differs.';$query=Fsutil @('file','queryfileid',$object.path);$matches=[regex]::Matches(($query-join"`n"),'0x[0-9a-fA-F]+');Need ($matches.Count-eq1) 'One live EA object ID required.';$id=$matches[0].Value.ToLowerInvariant();if($Filesystem-ceq'NTFS'){$wanted='0x';for($at=46;$at-ge16;$at-=2){$wanted+=$object.file_id_info.Substring($at,2)};Need ($id-ceq$wanted) 'Original EA NTFS identity changed.'};$idByPath[$object.path]=$id;$hash=$null;if(-not$object.directory){$payload=$shape.payloads[$object.path];Need ($meta.Length-eq$payload.hashes.length) 'EA live payload length differs.';$hash=(Get-FileHash -LiteralPath $object.path -Algorithm SHA256).Hash.ToLowerInvariant();Need ($hash-ceq$payload.hashes.sha256) 'EA payload differs from independent SHA256.'};$objects.Add(@{path=$object.path;directory=$object.directory;file_id=$id;sha256=$hash})}
 $payloadPath=$shape.root+'\payload.bin';$aliasPath=$shape.root+'\nested\payload-link.bin';$alias=Get-Item -LiteralPath $aliasPath -Force;Need ($alias-is[IO.FileInfo]-and-not($alias.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$alias.Length-eq65573-and(Get-FileHash -LiteralPath $aliasPath -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$shape.payloads[$payloadPath].hashes.sha256) 'EA alias payload differs.'
 $query=Fsutil @('file','queryfileid',$aliasPath);$matches=[regex]::Matches(($query-join"`n"),'0x[0-9a-fA-F]+');Need ($matches.Count-eq1-and$matches[0].Value.ToLowerInvariant()-ceq$idByPath[$payloadPath]) 'EA aliases have different identities.';$expectedLinks=@($shape.hardlink_paths|ForEach-Object {$_.Substring(2)}|Sort-Object)
 foreach($name in $shape.hardlink_paths){$lines=Fsutil @('hardlink','list',$name);$actual=@($lines|ForEach-Object {$line=$_.Trim();if($line.Length){if($line.StartsWith('H:\',[StringComparison]::OrdinalIgnoreCase)){$line=$line.Substring(2)};$line}}|Sort-Object);Need (SameArray $expectedLinks $actual) 'EA exact hard-link set differs.'}
 return @{filesystem=$Filesystem;objects=$objects.ToArray();canonical_objects=4;payload_sha256_checks=3;hardlink_names=2;hardlink_same_identity=$true;original_ntfs_ids_checked=($Filesystem-ceq'NTFS');extended_attributes_checked_from_pinned_fixture=$true}
}
function VerifyEaPreservation([string]$Records,$Fixture,$Expected,$Final){
 $shape=EaFixtureShape $Fixture;$basisPath=Join-Path $Records 'qualification\source-basis.json';$basis=Json $basisPath;$nativePath=Join-Path $Records 'qualification\native-source.json';$sourceNative=Json $nativePath;Need (($sourceNative.schema_version-in@(10,11))-or($sourceNative.schema_version-eq12-and$sourceNative.request.schema_version-eq4)) 'EA source observation requires schema10/11 or schema12/request4 with complete EA evidence.';$rows=[Collections.Generic.List[object]]::new();$nonresident=0
 foreach($object in $Fixture.objects){$bytes=[byte[]]::new(24);for($i=0;$i-lt24;$i++){$bytes[$i]=[Convert]::ToByte($object.file_id_info.Substring(2*$i,2),16)};$reference=[BitConverter]::ToUInt64($bytes,8);$number=$reference-band[uint64]281474976710655;$sequence=[uint16]($reference-shr48)
  $rawFiles=@($basis.ntfs.files|Where-Object {$_.record_number-eq$number-and$_.sequence_number-eq$sequence});Need ($rawFiles.Count-eq1) 'EA raw source identity missing.';$raw=$rawFiles[0];$inventory=$raw.PSObject.Properties['extended_attributes'];Need ($null-ne$inventory-and$null-ne$inventory.Value-and(EaSetMatches $object.extended_attributes $inventory.Value.set)) 'Raw NTFS EA set differs from fixture.'
  $sourceFiles=@($sourceNative.files|Where-Object {$_.identity.record_number-eq$number-and$_.identity.sequence_number-eq$sequence});Need ($sourceFiles.Count-eq1-and$null-eq$sourceFiles[0].open_error) 'Native EA source identity failed.';EaSnapshotMatches $object.extended_attributes $sourceFiles[0].before;EaSnapshotMatches $object.extended_attributes $sourceFiles[0].after
  $relative=$object.path.Substring(3);$targets=@($Expected.objects|Where-Object {($_.path-join'\')-ceq$relative});$observed=@($Final.native.native.objects|Where-Object {($_.components-join'\')-ceq$relative});Need ($targets.Count-eq1-and$observed.Count-eq1-and$targets[0].record_number-eq$number-and$targets[0].sequence_number-eq$sequence-and$targets[0].directory-eq$object.directory) 'EA expected/native canonical identity differs.';$targetEa=$targets[0].PSObject.Properties['extended_attributes'];Need ($null-ne$targetEa-and$null-ne$targetEa.Value-and(EaSetMatches $object.extended_attributes $targetEa.Value)) 'Canonical expected EA set differs.';EaSnapshotMatches $object.extended_attributes $observed[0].before;EaSnapshotMatches $object.extended_attributes $observed[0].after
  if($object.path-ceq($shape.root+'\payload.bin')){$info=@($raw.attributes|Where-Object type_code -EQ 208);$data=@($raw.attributes|Where-Object type_code -EQ 224);Need ($info.Count-eq1-and$info[0].resident-eq$true-and$info[0].logical_size-eq8-and$data.Count-eq1-and$data[0].resident-eq$false-and$data[0].lowest_vcn-eq0-and$data[0].flags-eq0-and$data[0].compression_unit-eq0-and$data[0].logical_size-ge8192-and$data[0].logical_size-le65536-and$data[0].initialized_size-eq$data[0].logical_size-and@($data[0].extents).Count-gt0-and@($data[0].extents|Where-Object {$null-eq$_.physical_offset-or$_.length-le0}).Count-eq0) 'Payload EA storage is not the expected valid nonresident form.';$nonresident++}
  $rows.Add(@{path=$object.path;source_record_number=$number;source_sequence_number=$sequence;raw_source_matches=$true;native_source_before_after_matches=$true;expected_tree_matches=$true;native_target_before_after_matches=$true;entry_count=(EaEntries $object.extended_attributes).Count})
 }
 Need ($rows.Count-eq4-and$nonresident-eq1) 'EA preservation coverage differs.'
 return @{canonical_objects=4;ea_entries=7;need_ea_flag_verified=$true;nonresident_ea_streams=1;objects=$rows.ToArray();source_basis_sha256=(Get-FileHash -LiteralPath $basisPath).Hash.ToLowerInvariant();native_source_sha256=(Get-FileHash -LiteralPath $nativePath).Hash.ToLowerInvariant();source_native_schema=$sourceNative.schema_version;metadata_fixed_by_wrapper=$false}
}

function PointMatches($Expected,$Observed){
 if($null-eq$Expected-or$null-eq$Observed){return ($null-eq$Expected-and$null-eq$Observed)}
 $a=$Expected.PSObject.Properties['buffer'];$b=$Observed.PSObject.Properties['buffer']
 return ($null-ne$a-and$null-ne$b-and@($a.Value).Count-ge8-and@($a.Value).Count-le16384-and(SameArray $a.Value $b.Value))
}
function ReparseSnapshotMatches($Point,$Snapshot,[bool]$Directory,[uint32]$Tag){
 Need ($null-ne$Snapshot) 'Reparse metadata snapshot missing.'
 $observation=$Snapshot.PSObject.Properties['reparse']
 Need ($null-ne$observation-and$null-ne$observation.Value-and$null-eq$observation.Value.error-and(PointMatches $Point $observation.Value.point)) 'Native reparse data is missing, failed or different.'
 $query=@($Snapshot.queries|Where-Object {$_.class-eq9-and$null-eq$_.native_error-and@($_.bytes).Count-eq8})
 Need ($query.Count-eq1) 'One exact native attribute/tag query required.'
 $bytes=[byte[]]$query[0].bytes;$attributes=[BitConverter]::ToUInt32($bytes,0);$actualTag=[BitConverter]::ToUInt32($bytes,4)
 Need ((($attributes-band16)-ne0)-eq$Directory-and((($attributes-band1024)-ne0)-eq($null-ne$Point))-and$actualTag-eq$Tag) 'Native reparse type, flag or tag differs.'
}
function ReparseFixtureShape($Fixture){
 Need ($Fixture.schema_version-eq1-and$Fixture.kind-ceq'ntfs-reparse-fixture'-and$Fixture.success-eq$true-and$Fixture.experiment_id-cmatch'\A[0-9a-f]{32}\z'-and$Fixture.canonical_objects-eq10-and@($Fixture.objects).Count-eq10-and$Fixture.reparse_points-eq6-and$Fixture.normal_payload_files-eq2) 'Complete pinned reparse fixture required.'
 $root='H:\ReparseFixture-'+$Fixture.experiment_id;$names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$points=0;$payloads=0
 foreach($object in $Fixture.objects){
  Need ($object.path-ceq$root-or($object.path.StartsWith($root+'\',[StringComparison]::Ordinal)-and$object.path-cnotmatch'\A.*(?:\A|\\)\.\.?(?:\\|\z)|[\r\n\x00]')) 'Reparse fixture path escapes its root.'
  Need ($names.Add([string]$object.path)-and$object.file_id_info-cmatch'\A[0-9a-f]{48}\z'-and$object.point_bytes_match-eq$true-and$object.no_follow_metadata-eq$true-and(PointMatches $object.point $object.observed_point)) 'Reparse fixture identity or exact point evidence differs.'
  if($null-ne$object.point){Need ($object.tag-in@(2684354563L,2684354572L)) 'Unsupported fixture tag.';$points++}else{Need ($object.tag-eq0) 'Ordinary object has reparse tag.'}
  if($null-ne$object.payload){Need ($null-eq$object.point-and-not$object.directory-and$object.payload.sha256-cmatch'\A[0-9a-f]{64}\z'-and$object.payload.length-in@(65573L,4097L)) 'Reparse fixture normal payload differs.';$payloads++}
 }
 Need ($points-eq6-and$payloads-eq2-and@($Fixture.functional_reads).Count-eq4) 'Reparse fixture exact coverage differs.'
 return @{root=$root;points=$points;payloads=$payloads}
}
function ObserveReparseFixture($Fixture,[string]$Filesystem){
 $shape=ReparseFixtureShape $Fixture;$tool=Join-Path $c.stage 'lab-create-reparse-fixture.exe';$metadata=Get-Item -LiteralPath $tool -Force
 Need (-not$metadata.PSIsContainer-and-not($metadata.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$metadata.Length-eq$c.reparse_tool_bytes-and(Get-FileHash -LiteralPath $tool).Hash.ToLowerInvariant()-ceq$c.reparse_tool_sha256) 'Reparse observer executable pin differs.'
 $name='reparse-'+$Filesystem.ToLowerInvariant();$reportPath=Join-Path $c.stage ($name+'-native.json');$stdout=Join-Path $c.stage ($name+'-stdout.log');$stderr=Join-Path $c.stage ($name+'-stderr.log');$id=[guid]::NewGuid().ToString('N')
 Need (-not(Test-Path -LiteralPath $reportPath)-and-not(Test-Path -LiteralPath $stdout)-and-not(Test-Path -LiteralPath $stderr)) 'Fresh reparse observation artifacts required.'
 $arguments=@('--observe-manifest',(Join-Path $c.stage 'reparse-fixture.json'),'--observe-manifest-sha256',$c.reparse_fixture_sha256,'--expected-filesystem',$Filesystem,'--output',$reportPath,'--experiment-id',$id,'--acknowledge-disposable-data-volume')
 Idle;Save ($name+'-dispatch-intent.json') @{binary_sha256=$c.reparse_tool_sha256;argv=$arguments;readonly_observation=$true;utc=[DateTime]::UtcNow.ToString('o')}
 $observer=$null
 try{
  $observer=Start-Process -FilePath $tool -ArgumentList ($arguments-join' ') -WorkingDirectory $c.stage -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru;$null=$observer.Handle
  Save ($name+'-process.json') @{pid=$observer.Id;creation_ms=([DateTimeOffset]$observer.StartTime).ToUnixTimeMilliseconds();binary_sha256=$c.reparse_tool_sha256;process_handle_retained_before_wait=$true;utc=[DateTime]::UtcNow.ToString('o')}
  $observer.WaitForExit();$observer.Refresh();$exit=$observer.ExitCode
  Save ($name+'-terminal.json') @{native_exit=$exit;exit_observed=($null-ne$exit);stdout=(Log $stdout);stderr=(Log $stderr);utc=[DateTime]::UtcNow.ToString('o')}
  Need ($null-ne$exit-and$exit-eq0) ('Read-only reparse observer failed for '+$Filesystem+'; exact artifacts preserved.')
 }finally{if($null-ne$observer){$observer.Dispose()}}
 Idle;$report=Json $reportPath 8MB
 Need ($report.schema_version-eq1-and$report.kind-ceq'reparse-fixture-read-only-observation'-and$report.success-eq$true-and$report.fixture_sha256-ceq$c.reparse_fixture_sha256-and$report.filesystem-ceq$Filesystem-and$report.source_payload_writes-eq0-and$report.raw_volume_writes-eq0-and$report.reparse_setters-eq0-and$report.dangling_or_cycle_traversals-eq0-and@($report.objects).Count-eq10-and@($report.functional_reads).Count-eq4) 'Complete no-follow read-only reparse observation required.'
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$hashes=0;$points=0;$rows=[Collections.Generic.List[object]]::new()
 foreach($object in $Fixture.objects){
  $matches=@($report.objects|Where-Object path -CEQ $object.path);Need ($matches.Count-eq1-and$seen.Add([string]$object.path)) 'Reparse observation identity coverage differs.';$observed=$matches[0]
  Need ($observed.directory-eq$object.directory-and$observed.tag-eq$object.tag-and$observed.point_bytes_match-eq$true-and$observed.no_follow_metadata-eq$true-and(PointMatches $object.point $observed.observed_point)-and$observed.file_id_info-cmatch'\A[0-9a-f]{48}\z') 'Observed reparse point/type differs.'
  if($Filesystem-ceq'NTFS'){Need ($observed.file_id_info-ceq$object.file_id_info) 'Original reparse fixture NTFS identity changed.'}
  ReparseSnapshotMatches $object.point $observed.before $object.directory $object.tag;ReparseSnapshotMatches $object.point $observed.after $object.directory $object.tag
  if($null-ne$object.point){$points++}
  if($null-ne$object.payload){Need ($observed.payload.sha256-ceq$object.payload.sha256-and$observed.payload.length-eq$object.payload.length) 'Reparse fixture independent normal payload hash differs.';$hashes++}
  $rows.Add(@{path=$object.path;case=$object.case;file_id_info=$observed.file_id_info;tag=$observed.tag;point_bytes_match=$true;no_follow_metadata=$true})
 }
 foreach($route in $Fixture.functional_reads){$matches=@($report.functional_reads|Where-Object path -CEQ $route.path);Need ($matches.Count-eq1-and$matches[0].known_existing_target_only-eq$true-and$matches[0].hashes.sha256-ceq$route.hashes.sha256-and$matches[0].hashes.length-eq$route.hashes.length) 'Known bounded functional link route differs.'}
 Need ($points-eq6-and$hashes-eq2) 'Reparse live observation coverage differs.'
 return @{native_exit=0;filesystem=$Filesystem;objects=10;point_buffers_verified=$points;normal_payload_sha256_hashes=$hashes;functional_existing_routes=4;dangling_or_cycle_traversals=0;no_follow_inventory=$true;source_payload_writes=0;raw_volume_writes=0;reparse_setters=0;report_path=$reportPath;report_sha256=(Get-FileHash -LiteralPath $reportPath).Hash.ToLowerInvariant();tool_sha256=$c.reparse_tool_sha256;rows=$rows.ToArray()}
}
function BindReparseFixtureToCore([string]$Records,$Fixture,$Expected,$Final){
 $basisPath=Join-Path $Records 'qualification\source-basis.json';$basis=Json $basisPath;$nativePath=Join-Path $Records 'qualification\native-source.json';$sourceNative=Json $nativePath;Need ($sourceNative.schema_version-eq11-or($sourceNative.schema_version-eq12-and$sourceNative.request.schema_version-eq4)) 'Source reparse evidence requires schema11 or schema12/request4.'
 $rows=[Collections.Generic.List[object]]::new();$keys=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$points=0
 foreach($object in $Fixture.objects){
  $id=[byte[]]::new(24);for($i=0;$i-lt24;$i++){$id[$i]=[Convert]::ToByte($object.file_id_info.Substring(2*$i,2),16)};$reference=[BitConverter]::ToUInt64($id,8);$number=$reference-band[uint64]281474976710655;$sequence=[uint16]($reference-shr48)
  $rawFiles=@($basis.ntfs.files|Where-Object {$_.record_number-eq$number-and$_.sequence_number-eq$sequence});$sourceFiles=@($sourceNative.files|Where-Object {$_.identity.record_number-eq$number-and$_.identity.sequence_number-eq$sequence})
  Need ($rawFiles.Count-eq1-and$sourceFiles.Count-eq1-and$null-eq$sourceFiles[0].open_error) 'Reparse core source identity missing.';$raw=$rawFiles[0];$rawPoint=$raw.PSObject.Properties['reparse'];$rawValue=if($null-ne$rawPoint){$rawPoint.Value}else{$null}
  Need (PointMatches $object.point $rawValue) 'Frozen raw reparse bytes differ from fixture.'
  $attributes=@($raw.attributes|Where-Object type_code -EQ 192);Need ($attributes.Count-eq$(if($null-ne$object.point){1}else{0})) 'Raw reparse attribute count differs.'
  $relative=$object.path.Substring(3);$matchesExpected=@($Expected.objects|Where-Object {($_.path-join'\')-ceq$relative-and$_.record_number-eq$number-and$_.sequence_number-eq$sequence});$native=@($Final.native.native.objects|Where-Object {($_.components-join'\')-ceq$relative})
  Need ($matchesExpected.Count-eq1-and$native.Count-eq1-and$matchesExpected[0].directory-eq$object.directory) 'Reparse expected/native target identity missing.';$expectedPoint=$matchesExpected[0].PSObject.Properties['reparse'];$expectedValue=if($null-ne$expectedPoint){$expectedPoint.Value}else{$null};Need (PointMatches $object.point $expectedValue) 'Expected canonical reparse bytes differ.'
  foreach($snapshot in @($sourceFiles[0].before,$sourceFiles[0].after,$native[0].before,$native[0].after)){ReparseSnapshotMatches $object.point $snapshot $object.directory $object.tag}
  if($null-ne$object.point){$bytes=[byte[]]::new(12);[BitConverter]::GetBytes([uint32]$object.tag).CopyTo($bytes,0);[BitConverter]::GetBytes([uint64]$reference).CopyTo($bytes,4);Need ($keys.Add(($bytes|ForEach-Object {$_.ToString('x2')})-join'')) 'Duplicate reparse source index key.';$points++}
  $rows.Add(@{path=$object.path;source_record_number=$number;source_sequence_number=$sequence;tag=$object.tag;raw_source_point_matches=$true;source_native_before_after_matches=$true;expected_tree_point_matches=$true;target_native_before_after_matches=$true})
 }
 $assessmentPath=Join-Path $Records 'qualification\source-assessment.json';$assessment=Json $assessmentPath;Need ($null-eq$assessment.internal_indexes_error-and$null-ne$assessment.internal_indexes-and$assessment.internal_indexes.replacement_supported-eq$true) 'Complete live internal-index proof missing.'
 $index=@($assessment.internal_indexes.indexes|Where-Object {$_.role-ceq'$Extend\$Reparse'-and$_.name-ceq'$R'});Need ($index.Count-eq1-and$index[0].replacement_supported-eq$true-and$index[0].entries-eq6-and@($index[0].entry_evidence).Count-eq6-and$index[0].root_sha256-cmatch'\A[0-9a-f]{64}\z') 'Reparse index coverage differs.'
 $actualKeys=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);foreach($entry in $index[0].entry_evidence){Need ($entry.key_hex-cmatch'\A[0-9a-f]{24}\z'-and$entry.value_hex-ceq''-and$keys.Contains($entry.key_hex)-and$actualKeys.Add($entry.key_hex)) 'Reparse index contains an unexplained key/value.'}
 Need ($points-eq6-and$actualKeys.Count-eq$keys.Count) 'Reparse source/index membership is incomplete.'
 return @{objects=10;point_buffers_verified=6;source_native_schema=$sourceNative.schema_version;complete_reparse_index_entries=6;source_basis_sha256=(Get-FileHash -LiteralPath $basisPath).Hash.ToLowerInvariant();native_source_sha256=(Get-FileHash -LiteralPath $nativePath).Hash.ToLowerInvariant();internal_index_proof_sha256=(Get-FileHash -LiteralPath $assessmentPath).Hash.ToLowerInvariant();wrapper_parses_or_repairs_security=$false;metadata_fixed_by_wrapper=$false;rows=$rows.ToArray()}
}
function SecurityFixtureShape($Fixture){
 Need ($Fixture.schema_version-eq1-and$Fixture.kind-ceq'ntfs-security-fixture'-and$Fixture.success-eq$true-and$Fixture.experiment_id-cmatch'\A[0-9a-f]{32}\z'-and$Fixture.canonical_objects-eq8-and$Fixture.user_files-eq7-and$Fixture.directories-eq1-and@($Fixture.objects).Count-eq8-and$Fixture.requested_vs_observed_states_recorded-eq$true) 'Complete pinned security fixture required.'
 $root='H:\SecurityFixture-'+$Fixture.experiment_id;$names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$files=0;$directories=0
 foreach($object in $Fixture.objects){
  Need ($object.path-ceq$root-or($object.path.StartsWith($root+'\',[StringComparison]::Ordinal)-and$object.path.Substring($root.Length+1)-cnotmatch'[\\/:\x00-\x1f]')) 'Security fixture path escapes its enrolled root.'
  if($object.path-cne$root){$leaf=$object.path.Substring($root.Length+1);Need ($leaf-notin@('.','..')-and-not$leaf.EndsWith('.')-and-not$leaf.EndsWith(' ')) 'Security fixture path normalization differs.'}
  Need ($names.Add([string]$object.path)-and$object.actual_security_hex-cmatch'\A(?:[0-9a-f]{2}){20,65536}\z'-and$object.file_id_info-cmatch'\A[0-9a-f]{48}\z') 'Security fixture actual descriptor/identity missing or duplicate.'
  if($object.directory){$directories++;Need ($object.path-ceq$root-and$null-eq$object.payload) 'Security directory shape differs.'}else{$files++;Need ($object.payload.length-ge0-and$object.payload.length-le65536-and$object.payload.sha256-cmatch'\A[0-9a-f]{64}\z') 'Security payload digest missing.'}
 }
 Need ($files-eq7-and$directories-eq1) 'Security fixture identity coverage differs.'
 return @{root=$root;files=$files;directories=$directories;objects=8}
}
function CompressionFixtureShape($Fixture){
 Need ($Fixture.schema_version-eq1-and$Fixture.kind-ceq'ntfs-compression-fixture'-and$Fixture.success-eq$true-and$Fixture.filesystem-ceq'NTFS'-and$Fixture.experiment_id-cmatch'\A[0-9a-f]{32}\z'-and$Fixture.canonical_objects-eq8-and@($Fixture.objects).Count-eq8-and$Fixture.default_streams-eq6-and$Fixture.named_streams-eq1) 'Complete compression fixture required.'
 $root='H:\CompressionFixture-'+$Fixture.experiment_id;$expected=@{};$expected[$root]=$true;$expected[$root+'\compressed-directory']=$true
 foreach($name in @('mixed.bin','incompressible.bin','resident.bin','empty.bin','compressed-directory\inherited.bin','named.bin')){$expected[$root+'\'+$name]=$false}
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$ids=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$defaults=0;$named=0
 foreach($object in $Fixture.objects){
  Need ($expected.ContainsKey([string]$object.path)-and$expected[$object.path]-eq$object.directory-and$seen.Add([string]$object.path)-and$object.file_id_info-cmatch'\A[0-9a-f]{48}\z'-and$ids.Add([string]$object.file_id_info)-and$object.no_follow_metadata-eq$true) 'Compression fixture object identity/path/type differs.'
  $streams=@($object.streams|Where-Object {$null-ne$_});Need ($streams.Count-eq$(if($object.directory){0}elseif($object.path-ceq($root+'\named.bin')){2}else{1})) 'Compression fixture stream count differs.'
  $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach($stream in $streams){$name=[string]$stream.name;Need ($names.Add($name)-and$stream.payload.length-ge0-and$stream.payload.length-le3MB-and$stream.payload.sha256-cmatch'\A[0-9a-f]{64}\z'-and$stream.payload.content_digest-cmatch'\A[0-9a-f]{32}\z'-and$stream.payload.content_digest_algorithm-ceq'xxh3-128') 'Compression fixture stream digest differs.';if($name.Length){Need ($object.path-ceq($root+'\named.bin')-and$name-ceq'Encoded'-and$stream.source_compression_policy-eq$true) 'Unexpected compressed named stream.';$named++}else{$defaults++}}
 }
 Need ($defaults-eq6-and$named-eq1-and$seen.Count-eq8) 'Compression fixture stream/object coverage differs.'
 return @{root=$root;objects=$seen.Count;default_streams=$defaults;named_streams=$named;logical_streams=$defaults+$named}
}
function ObserveCompressionFixture($Fixture,[string]$Filesystem){
 $shape=CompressionFixtureShape $Fixture;$tool=Join-Path $c.stage 'lab-create-compression-fixture.exe';$metadata=Get-Item -LiteralPath $tool -Force
 Need (-not$metadata.PSIsContainer-and-not($metadata.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$metadata.Length-eq$c.compression_tool_bytes-and(Get-FileHash -LiteralPath $tool).Hash.ToLowerInvariant()-ceq$c.compression_tool_sha256) 'Compression observer executable pin differs.'
 $name='compression-'+$Filesystem.ToLowerInvariant();$reportPath=Join-Path $c.stage ($name+'-native.json');$stdout=Join-Path $c.stage ($name+'-stdout.log');$stderr=Join-Path $c.stage ($name+'-stderr.log');$id=[guid]::NewGuid().ToString('N')
 Need (-not(Test-Path -LiteralPath $reportPath)-and-not(Test-Path -LiteralPath $stdout)-and-not(Test-Path -LiteralPath $stderr)) 'Fresh compression observation artifacts required.'
 $arguments=@('--observe-manifest',(Join-Path $c.stage 'compression-fixture.json'),'--observe-manifest-sha256',$c.compression_fixture_sha256,'--expected-filesystem',$Filesystem,'--output',$reportPath,'--experiment-id',$id,'--acknowledge-disposable-data-volume')
 Idle;Save ($name+'-dispatch-intent.json') @{binary_sha256=$c.compression_tool_sha256;argv=$arguments;readonly_observation=$true;utc=[DateTime]::UtcNow.ToString('o')}
 $observer=$null
 try{
  $observer=Start-Process -FilePath $tool -ArgumentList ($arguments-join' ') -WorkingDirectory $c.stage -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru;$null=$observer.Handle
  Save ($name+'-process.json') @{pid=$observer.Id;creation_ms=([DateTimeOffset]$observer.StartTime).ToUnixTimeMilliseconds();binary_sha256=$c.compression_tool_sha256;process_handle_retained_before_wait=$true;utc=[DateTime]::UtcNow.ToString('o')}
  $observer.WaitForExit();$observer.Refresh();$exit=$observer.ExitCode
  Save ($name+'-terminal.json') @{native_exit=$exit;exit_observed=($null-ne$exit);stdout=(Log $stdout);stderr=(Log $stderr);utc=[DateTime]::UtcNow.ToString('o')}
  Need ($null-ne$exit-and$exit-eq0) ('Read-only compression observer failed for '+$Filesystem+'; exact artifacts preserved.')
 }finally{if($null-ne$observer){$observer.Dispose()}}
 Idle;$report=Json $reportPath 8MB
 Need ($report.schema_version-eq1-and$report.kind-ceq'compression-fixture-read-only-observation'-and$report.success-eq$true-and$report.fixture_sha256-ceq$c.compression_fixture_sha256-and$report.filesystem-ceq$Filesystem-and$report.source_payload_writes-eq0-and$report.raw_volume_writes-eq0-and$report.compression_setters-eq0-and@($report.objects).Count-eq$shape.objects) 'Complete read-only compression observation required.'
 $rows=[Collections.Generic.List[object]]::new();$hashes=0
 foreach($object in $Fixture.objects){
  $matches=@($report.objects|Where-Object path -CEQ $object.path);Need ($matches.Count-eq1) 'Compression observed identity missing/duplicated.';$observed=$matches[0]
  Need ($observed.directory-eq$object.directory-and$observed.no_follow_metadata-eq$true-and$observed.file_id_info-cmatch'\A[0-9a-f]{48}\z') 'Compression observed type/identity differs.'
  if($Filesystem-ceq'NTFS'){Need ($observed.file_id_info-ceq$object.file_id_info) 'Original compression NTFS identity changed.'}
  $wanted=@($object.streams|Where-Object {$null-ne$_});$actual=@($observed.streams|Where-Object {$null-ne$_});Need ($actual.Count-eq$wanted.Count) 'Compression observed stream coverage differs.'
  foreach($stream in $wanted){$streams=@($actual|Where-Object {[string]$_.name-ceq[string]$stream.name});Need ($streams.Count-eq1-and$streams[0].payload.length-eq$stream.payload.length-and$streams[0].payload.sha256-ceq$stream.payload.sha256-and$streams[0].payload.content_digest-ceq$stream.payload.content_digest) 'Compression logical bytes differ from independent fixture.';$hashes++}
  $rows.Add(@{path=$object.path;file_id_info=$observed.file_id_info;directory=$object.directory;stream_hashes=$actual.Count;target_ntfs_compression_normalized=($Filesystem-ceq'ReFS')})
 }
 Need ($hashes-eq$shape.logical_streams) 'All independent compression stream hashes required.'
 return @{native_exit=0;filesystem=$Filesystem;objects=$shape.objects;default_streams=$shape.default_streams;named_streams=$shape.named_streams;independent_sha256_hashes=$hashes;independent_xxh3_hashes=$hashes;source_payload_writes=0;raw_volume_writes=0;compression_setters=0;target_ntfs_compression_normalized=($Filesystem-ceq'ReFS');report_path=$reportPath;report_sha256=(Get-FileHash -LiteralPath $reportPath).Hash.ToLowerInvariant();tool_sha256=$c.compression_tool_sha256;rows=$rows.ToArray()}
}
function BindCompressionFixtureToCore([string]$Records,$Fixture,$Expected,$Final){
 $shape=CompressionFixtureShape $Fixture;$basisPath=Join-Path $Records 'qualification\source-basis.json';$basis=Json $basisPath;$rows=[Collections.Generic.List[object]]::new();$encoded=0;$residentPolicies=0;$streamsChecked=0;$normalized=0;$logicalBytes=0L;$residentBytes=0L
 foreach($object in $Fixture.objects){
  $id=[byte[]]::new(24);for($i=0;$i-lt24;$i++){$id[$i]=[Convert]::ToByte($object.file_id_info.Substring(2*$i,2),16)};$reference=[BitConverter]::ToUInt64($id,8);$number=$reference-band[uint64]281474976710655;$sequence=[uint16]($reference-shr48)
  $raw=@($basis.ntfs.files|Where-Object {$_.record_number-eq$number-and$_.sequence_number-eq$sequence});$relative=$object.path.Substring(3);$targets=@($Expected.objects|Where-Object {($_.path-join'\')-ceq$relative-and$_.record_number-eq$number-and$_.sequence_number-eq$sequence});$native=@($Final.native.native.objects|Where-Object {($_.components-join'\')-ceq$relative})
  Need ($raw.Count-eq1-and$targets.Count-eq1-and$native.Count-eq1-and$targets[0].directory-eq$object.directory-and($targets[0].attributes-band2048)-eq0) 'Compression frozen source/expected/native identity differs.'
  $normalization=$targets[0].PSObject.Properties['ntfs_compression_normalized'];$isNormalized=$null-ne$normalization-and$normalization.Value-eq$true;if($isNormalized){$normalized++}
  $rawExtentStreams=0;foreach($stream in @($object.streams|Where-Object {$null-ne$_})){
   $name=[string]$stream.name;$units=@($name.ToCharArray()|ForEach-Object {[uint16]$_});$sourceStreams=@($raw[0].streams|Where-Object {SameArray $_.name_utf16 $units});$attributes=@($raw[0].attributes|Where-Object {$_.type_code-eq128-and(SameArray $_.name_utf16 $units)})
   Need ($sourceStreams.Count-eq1-and$attributes.Count-eq1-and$sourceStreams[0].logical_size-eq$stream.payload.length) 'Compression raw stream length/identity differs from independent fixture.';if(AssertRawContentOrLabExtent $basis.ntfs $raw[0] $sourceStreams[0] $stream.payload.content_digest){$rawExtentStreams++}
   $targetStream=$targets[0];if($name.Length){$targetStream=@($targets[0].named_streams|Where-Object {SameArray $_.name_utf16 $units});Need ($targetStream.Count-eq1) 'Compressed target ADS missing.';$targetStream=$targetStream[0]}
   $labObject=$targets[0];if($null-ne$script:labBaselineContext-and$script:labBaselineContext.enabled){$labObjects=@($script:labBaselineContext.observer_expectation.objects|Where-Object {$_.record_number-eq$number-and$_.sequence_number-eq$sequence-and($_.path-join'\')-ceq$relative});Need ($labObjects.Count-eq1) 'Compression independent baseline canonical identity absent.';$labObject=$labObjects[0]};$labStream=LabStream $labObject $units;Need ($targetStream.length-eq$stream.payload.length-and$labStream.sha256-ceq$stream.payload.content_digest) 'Compression canonical target length/independent baseline digest differs.'
   if(($attributes[0].flags-band255)-ne0){
    Need ($attributes[0].flags-eq1-and$isNormalized) 'Source compression-policy/normalization binding differs.'
    if($attributes[0].resident){
     $total=$attributes[0].PSObject.Properties['total_allocated_size'];Need ($attributes[0].compression_unit-eq0-and$attributes[0].lowest_vcn-eq0-and@($attributes[0].extents|Where-Object {$null-ne$_}).Count-eq0-and$attributes[0].logical_size-eq$attributes[0].initialized_size-and$attributes[0].logical_size-eq$attributes[0].allocated_size-and($null-eq$total-or$null-eq$total.Value)) 'Resident compression policy has invalid resident DATA storage.'
     $residentPolicies++;$residentBytes+=$stream.payload.length
    }else{
     Need ($attributes[0].compression_unit-eq4) 'Encoded nonresident DATA requires the admitted compression unit.'
     $encoded++;$logicalBytes+=$stream.payload.length
    }
    $offset=$targetStream.PSObject.Properties['source_offset'];$extents=$targetStream.PSObject.Properties['source_extents'];$sparse=$targetStream.PSObject.Properties['sparse'];Need (($null-eq$offset-or$null-eq$offset.Value)-and($null-eq$extents-or@($extents.Value|Where-Object {$null-ne$_}).Count-eq0)-and($null-eq$sparse-or$null-eq$sparse.Value)) 'Encoded physical bytes must not be adopted or exposed as logical sparse holes.'
   }
   $streamsChecked++
  }
  $rows.Add(@{path=$object.path;source_record_number=$number;source_sequence_number=$sequence;ntfs_compression_normalized=$isNormalized;raw_logical_hashes_match=($rawExtentStreams-eq0);raw_extent_only_streams_bound=$rawExtentStreams;independent_fixture_digests_match=$true;target_logical_hashes_match=$true})
 }
 Need ($rows.Count-eq$shape.objects-and$streamsChecked-eq$shape.logical_streams-and$encoded-gt0-and$normalized-gt0) 'Compression core coverage/encoding evidence missing.'
 return @{objects=$rows.Count;logical_streams=$streamsChecked;encoded_nonresident_streams=$encoded;encoded_stream_logical_bytes_rewritten=$logicalBytes;resident_compression_policy_streams=$residentPolicies;resident_policy_bytes_materialized=$residentBytes;normalization_identities=$normalized;compressed_physical_payload_adopted=$false;compression_padding_exposed_as_sparse_holes=$false;source_basis_sha256=(Get-FileHash -LiteralPath $basisPath).Hash.ToLowerInvariant();rows=$rows.ToArray();wrapper_repairs_metadata=$false}
}
function ObserveSecurityFixture($Fixture,[string]$Filesystem){
 $shape=SecurityFixtureShape $Fixture;$tool=Join-Path $c.stage 'lab-create-security-fixture.exe';$metadata=Get-Item -LiteralPath $tool -Force
 Need (-not$metadata.PSIsContainer-and-not($metadata.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$metadata.Length-eq$c.security_tool_bytes-and(Get-FileHash -LiteralPath $tool).Hash.ToLowerInvariant()-ceq$c.security_tool_sha256) 'Security observer executable pin differs.'
 $name='security-'+$Filesystem.ToLowerInvariant();$reportPath=Join-Path $c.stage ($name+'-native.json');$stdout=Join-Path $c.stage ($name+'-stdout.log');$stderr=Join-Path $c.stage ($name+'-stderr.log');$id=[guid]::NewGuid().ToString('N')
 Need (-not(Test-Path -LiteralPath $reportPath)-and-not(Test-Path -LiteralPath $stdout)-and-not(Test-Path -LiteralPath $stderr)) 'Fresh security observation artifacts required.'
 $arguments=@('--observe-manifest',(Join-Path $c.stage 'security-fixture.json'),'--observe-manifest-sha256',$c.security_fixture_sha256,'--expected-filesystem',$Filesystem,'--output',$reportPath,'--experiment-id',$id,'--acknowledge-disposable-data-volume')
 Idle;Save ($name+'-dispatch-intent.json') @{binary_sha256=$c.security_tool_sha256;argv=$arguments;readonly_observation=$true;utc=[DateTime]::UtcNow.ToString('o')}
 $observer=$null
 try{
  $observer=Start-Process -FilePath $tool -ArgumentList ($arguments-join' ') -WorkingDirectory $c.stage -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru;$null=$observer.Handle
  Save ($name+'-process.json') @{pid=$observer.Id;creation_ms=([DateTimeOffset]$observer.StartTime).ToUnixTimeMilliseconds();binary_sha256=$c.security_tool_sha256;process_handle_retained_before_wait=$true;utc=[DateTime]::UtcNow.ToString('o')}
  $observer.WaitForExit();$observer.Refresh();$exit=$observer.ExitCode
  Save ($name+'-terminal.json') @{native_exit=$exit;exit_observed=($null-ne$exit);stdout=(Log $stdout);stderr=(Log $stderr);utc=[DateTime]::UtcNow.ToString('o')}
  Need ($null-ne$exit-and$exit-eq0) ('Read-only security observer failed for '+$Filesystem+'; exact artifacts preserved.')
 }finally{if($null-ne$observer){$observer.Dispose()}}
 Idle;$report=Json $reportPath 8MB
 Need ($report.schema_version-eq1-and$report.kind-ceq'security-fixture-read-only-observation'-and$report.success-eq$true-and$report.fixture_sha256-ceq$c.security_fixture_sha256-and$report.filesystem-ceq$Filesystem-and$report.source_payload_writes-eq0-and$report.raw_volume_writes-eq0-and$report.security_setters-eq0-and@($report.objects).Count-eq8) 'Complete read-only security observation required.'
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$hashes=0;$rows=[Collections.Generic.List[object]]::new()
 foreach($object in $Fixture.objects){
  $matches=@($report.objects|Where-Object path -CEQ $object.path);Need ($matches.Count-eq1-and$seen.Add([string]$object.path)) 'Security observation identity coverage differs.';$observed=$matches[0]
  Need ($observed.directory-eq$object.directory-and$observed.source_security_semantics_match-eq$true-and$observed.source_api_view_matches-eq$true-and$observed.file_id_info-cmatch'\A[0-9a-f]{48}\z') 'Observed stored/kernel/API security does not match fixture.'
  if($Filesystem-ceq'NTFS'){Need ($observed.file_id_info-ceq$object.file_id_info) 'Original security fixture NTFS identity changed.'}
  if(-not$object.directory){Need ($observed.sha256-ceq$object.payload.sha256) 'Security fixture independent SHA256 differs.';$hashes++}
  $rows.Add(@{path=$object.path;case=$object.case;file_id_info=$observed.file_id_info;independent_sha256=$observed.sha256;source_security_semantics_match=$true;source_api_view_matches=$true;requested_semantics_preserved_on_ntfs=$object.requested_semantics_preserved;observed_ntfs_dacl_state=$object.observed_dacl_state;observed_ntfs_sacl_state=$object.observed_sacl_state})
 }
 Need ($hashes-eq7) 'Seven independent security payload hashes required.'
 return @{native_exit=0;filesystem=$Filesystem;objects=8;independent_sha256_hashes=$hashes;source_security_semantics_match=$true;source_api_view_matches=$true;source_payload_writes=0;raw_volume_writes=0;security_setters=0;report_path=$reportPath;report_sha256=(Get-FileHash -LiteralPath $reportPath).Hash.ToLowerInvariant();tool_sha256=$c.security_tool_sha256;states_observed_not_assumed=$true;rows=$rows.ToArray()}
}
function BindSecurityFixtureToCore([string]$Records,$Fixture,$Expected,$Final){
 $basisPath=Join-Path $Records 'qualification\source-basis.json';$basis=Json $basisPath;$nativePath=Join-Path $Records 'qualification\native-source.json';$sourceNative=Json $nativePath;$rows=[Collections.Generic.List[object]]::new()
 foreach($object in $Fixture.objects){
  $bytes=[byte[]]::new(24);for($i=0;$i-lt24;$i++){$bytes[$i]=[Convert]::ToByte($object.file_id_info.Substring(2*$i,2),16)};$reference=[BitConverter]::ToUInt64($bytes,8);$number=$reference-band[uint64]281474976710655;$sequence=[uint16]($reference-shr48)
  $raw=@($basis.ntfs.files|Where-Object {$_.record_number-eq$number-and$_.sequence_number-eq$sequence});$binding=@($basis.ntfs.security_reconciliation.bindings|Where-Object {$_.record_number-eq$number-and$_.sequence_number-eq$sequence});$source=@($sourceNative.files|Where-Object {$_.identity.record_number-eq$number-and$_.identity.sequence_number-eq$sequence})
  Need ($raw.Count-eq1-and$binding.Count-eq1-and$binding[0].descriptor_sha256-cmatch'\A[0-9a-f]{64}\z'-and$source.Count-eq1-and$null-eq$source[0].open_error) 'Security fixture frozen source identity/descriptor binding absent.'
  $descriptor=@($basis.ntfs.security_reconciliation.descriptors|Where-Object {$_.descriptor.sha256-ceq$binding[0].descriptor_sha256});Need ($descriptor.Count-eq1) 'Bound stored source descriptor missing.'
  $relative=$object.path.Substring(3);$matchesExpected=@($Expected.objects|Where-Object {($_.path-join'\')-ceq$relative-and$_.record_number-eq$number-and$_.sequence_number-eq$sequence});$native=@($Final.native.native.objects|Where-Object {($_.components-join'\')-ceq$relative})
  Need ($matchesExpected.Count-eq1-and$native.Count-eq1-and$matchesExpected[0].directory-eq$object.directory) 'Security fixture expected/native target identity missing.'
  foreach($snapshot in @($source[0].before,$source[0].after,$native[0].before,$native[0].after)){Need ($null-ne$snapshot-and$null-eq$snapshot.security_error-and$null-ne$snapshot.kernel_security-and$null-eq$snapshot.kernel_security.native_error) 'Security fixture core query missing or refused.'}
  $rows.Add(@{path=$object.path;source_record_number=$number;source_sequence_number=$sequence;raw_descriptor_sha256=$binding[0].descriptor_sha256;frozen_source_identity_bound=$true;expected_target_identity_bound=$true;core_source_and_target_security_queries_present=$true})
 }
 return @{objects=8;rows=$rows.ToArray();source_basis_sha256=(Get-FileHash -LiteralPath $basisPath).Hash.ToLowerInvariant();native_source_sha256=(Get-FileHash -LiteralPath $nativePath).Hash.ToLowerInvariant();semantic_comparison_authority='native converter exact raw/kernel/API gates plus separately pinned read-only Rust fixture observer';wrapper_parses_or_repairs_security=$false}
}
try{
 Idle
 $fixturePath=Join-Path $c.stage 'fixture.json';Need ((Get-FileHash -LiteralPath $fixturePath).Hash.ToLowerInvariant()-ceq$c.fixture_sha256) 'Staged fixture pin differs.';$fixture=Json $fixturePath 1MB
 $adsPath=Join-Path $c.stage 'ads-fixture.json';Need ((Get-FileHash -LiteralPath $adsPath).Hash.ToLowerInvariant()-ceq$c.ads_sha256) 'Staged ADS fixture pin differs.';$ads=Json $adsPath 1MB
 $sparsePath=Join-Path $c.stage 'sparse-fixture.json';Need ((Get-FileHash -LiteralPath $sparsePath).Hash.ToLowerInvariant()-ceq$c.sparse_sha256) 'Staged sparse fixture pin differs.';$sparse=Json $sparsePath 1MB
 $attributePath=Join-Path $c.stage 'attribute-fixture.json';Need ((Get-FileHash -LiteralPath $attributePath).Hash.ToLowerInvariant()-ceq$c.attribute_sha256) 'Staged attribute fixture pin differs.';$attribute=Json $attributePath 4MB
 Save 'attribute-preparation.json' (VerifyAttributePreparation $attribute)
 $ea=$null;$eaSummary=$null;if($c.ea_fixture_enabled){$eaPath=Join-Path $c.stage 'ea-fixture.json';Need ((Get-FileHash -LiteralPath $eaPath).Hash.ToLowerInvariant()-ceq$c.ea_fixture_sha256) 'Staged EA fixture pin differs.';$ea=Json $eaPath 4MB}
 $security=$null;$securitySummary=$null;if($c.security_fixture_enabled){$securityPath=Join-Path $c.stage 'security-fixture.json';Need ((Get-FileHash -LiteralPath $securityPath).Hash.ToLowerInvariant()-ceq$c.security_fixture_sha256) 'Staged security fixture pin differs.';$security=Json $securityPath 8MB}
 $reparse=$null;$reparseSummary=$null;if($c.reparse_fixture_enabled){$reparsePath=Join-Path $c.stage 'reparse-fixture.json';Need ((Get-FileHash -LiteralPath $reparsePath).Hash.ToLowerInvariant()-ceq$c.reparse_fixture_sha256) 'Staged reparse fixture pin differs.';$reparse=Json $reparsePath 8MB}
 $compression=$null;$compressionSummary=$null;$compressionShape=$null;if($c.compression_fixture_enabled){$compressionPath=Join-Path $c.stage 'compression-fixture.json';Need ((Get-FileHash -LiteralPath $compressionPath).Hash.ToLowerInvariant()-ceq$c.compression_fixture_sha256) 'Staged compression fixture pin differs.';$compression=Json $compressionPath 8MB;$compressionShape=CompressionFixtureShape $compression}
 $binary=Join-Path $c.stage 'ntfs2refs.exe';$m=Get-Item -LiteralPath $binary -Force;Need (-not$m.PSIsContainer-and-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$m.Length-eq$c.binary_bytes-and(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()-ceq$c.binary_sha256) 'Staged public executable differs.'
 Save 'wrapper-worker.json' @{pid=$PID;creation_ms=([DateTimeOffset](Get-Process -Id $PID).StartTime).ToUnixTimeMilliseconds();utc=[DateTime]::UtcNow.ToString('o')}
 Save 'fixture-before.json' (VerifyFixture $fixture 'NTFS')
 Save 'ads-before.json' (VerifyAds $fixture $ads)
 Save 'sparse-before.json' (VerifySparseFixture $sparse)
 Save 'attribute-before.json' (VerifyAttributeFixture $attribute 'NTFS')
 if($c.ea_fixture_enabled){Save 'ea-before.json' (VerifyEaFixture $ea 'NTFS')}
 if($c.security_fixture_enabled){$phase='security-source-observation';Save 'security-before.json' (ObserveSecurityFixture $security 'NTFS')}
 if($c.reparse_fixture_enabled){$phase='reparse-source-observation';Save 'reparse-before.json' (ObserveReparseFixture $reparse 'NTFS')}
 if($c.compression_fixture_enabled){$phase='compression-source-observation';Save 'compression-before.json' (ObserveCompressionFixture $compression 'NTFS')}
 Idle;$phase='public-conversion'
 $stdin=Join-Path $c.stage 'stdin-yes.txt';[IO.File]::WriteAllBytes($stdin,[Text.Encoding]::ASCII.GetBytes("yes`r`n"));$stdout=Join-Path $c.stage 'stdout.log';$stderr=Join-Path $c.stage 'stderr.log';$argv=@('--drive','H','--partition',[string]$c.partition_number)
 Save 'native-dispatch-intent.json' @{binary=$binary;binary_sha256=$c.binary_sha256;argv=$argv;expected_exit=0;utc=[DateTime]::UtcNow.ToString('o')}
 $process=Start-Process -FilePath $binary -ArgumentList ($argv-join' ') -WorkingDirectory $c.stage -RedirectStandardInput $stdin -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden;$null=$process.Handle
 Save 'native-process.json' @{pid=$process.Id;creation_ms=([DateTimeOffset]$process.StartTime).ToUnixTimeMilliseconds();binary=$binary;binary_sha256=$c.binary_sha256;argv=$argv;expected_exit=0;process_handle_retained_before_wait=$true;utc=[DateTime]::UtcNow.ToString('o')}
 $process.WaitForExit();$process.Refresh();$nativeExit=$process.ExitCode;$out=Log $stdout;$err=Log $stderr
 Save 'native-terminal.json' @{native_exit=$nativeExit;native_exit_observed=($null-ne$nativeExit);expected_exit=0;stdout=$out;stderr=$err;utc=[DateTime]::UtcNow.ToString('o')}
 Need ($null-ne$nativeExit-and$nativeExit-eq0) ('Actual public CLI exit was '+$nativeExit)
 $phase='closed-native-conversion-evidence';Idle
 Need (-not$out.truncated) 'Completion log exceeds the bounded parser.'
 $completed=[regex]::Matches($out.text,'(?m)^Conversion completed[.] Recovery records: (C:\\ProgramData\\ntfs2refs\\runs\\[0-9a-f]{32}\\conversion)[ \t]*\r?$')
 Need ($completed.Count-eq1) 'Exactly one native completion path required.';$records=$completed[0].Groups[1].Value
 $result=Json (Join-Path $records 'result.json');$final=Json (Join-Path $records 'finalization.json');$expected=Json (Join-Path $records 'expectation.json');$handoff=Json (Join-Path $records 'handoff.json') 65536;$ticket=Json (Join-Path $records 'selected-ticket.json') 65536;$plan=Json (Join-Path $records 'selected-plan.json') 16MB;$request=Json (Join-Path $records 'request.json') 131072
 $pins=@{};foreach($name in @('result','finalization','expectation','handoff','selected-ticket','selected-plan','request')){$pins[$name]=(Get-FileHash -LiteralPath (Join-Path $records ($name+'.json'))).Hash.ToLowerInvariant()}
 # These are the default allocation-bounded result fields emitted by
 # general_conversion/allocation.rs, not the whole-image compact schema.
 Need ($result.schema_version-eq1-and$result.kind-ceq'experimental-allocation-bounded-conversion'-and$result.success-eq$true-and$result.source_admitted-eq$true-and$result.rollback_closed-eq$true-and$result.free_space_contents_compared-eq$false-and$result.general_conversion_qualified-eq$false-and$result.expected_tree_sha256-ceq$pins.expectation-and$result.ticket_sha256-ceq$pins.'selected-ticket'-and$result.plan_sha256-ceq$pins.'selected-plan') 'Native allocation conversion result or pinned expectation differs.'
 Need ($final.success-eq$true-and$null-eq$final.error-and$final.rollback_closed-eq$true-and$final.mount_paths_preserved-eq$true-and$null-eq$final.mount_paths_error-and$final.mount_paths_after.all_paths_resolve_to_bound_volume-eq$true-and(SameArray $final.mount_paths_after.paths @('H:\'))) 'Native finalization or H: mount preservation failed.'
 Need ($handoff.replay_closed-eq$true-and$handoff.whole_image_verified-eq$false-and$ticket.whole_image_verified-eq$false-and$handoff.selected_bytes-eq$ticket.selected_bytes-and$handoff.range_count-eq$ticket.range_count-and$ticket.range_count-eq@($plan.ranges).Count-and$result.selected_ranges-eq$ticket.range_count-and$result.selected_bytes-eq$ticket.selected_bytes-and$result.journal_bytes-eq$ticket.journal_length-and@($handoff.selected_sha256).Count-eq32-and@($ticket.new_selected_sha256).Count-eq32-and(SameArray $handoff.selected_sha256 $ticket.new_selected_sha256)) 'HND does not match the selected ticket/plan.'
 Need ($request.pair.source.disk_number-eq6-and[guid]$request.pair.source.identity.disk_guid-eq[guid]$fixture.disk_guid-and[guid]$request.pair.source.identity.partition_guid-eq[guid]$fixture.partition_guid-and$request.pair.source.identity.partition_bytes-eq52GB-and$request.pair.source.identity.partition_offset-eq32MB) 'Core used a different source partition.'
 $label=$final.label_restoration;Need ($label.success-eq$true-and$label.readback_matches-eq$true-and$label.flushed-eq$true-and$null-eq$label.error-and$label.after.filesystem-ceq'ReFS') 'Native label restoration was not confirmed.'
 $labExtentScope=AssertLabExtentScope $expected $result $request $records;$script:labBaselineContext=ResolveLabContentBaseline $expected $request $records;$labExpected=$script:labBaselineContext.observer_expectation;$baselineBinding=$null
 if($script:labBaselineContext.enabled){$baselineBinding=$script:labBaselineContext.receipt;Save 'lab-baseline-binding.json' $baselineBinding;$pins['lab-baseline-binding']=(Get-FileHash -LiteralPath (Join-Path $c.stage 'lab-baseline-binding.json') -Algorithm SHA256).Hash.ToLowerInvariant()}
 $assemblyLedger=VerifyAssemblyLedger $records $attribute;Save 'attribute-assembly.json' $assemblyLedger
 $expectedObjects=@($expected.objects);Need ($expectedObjects.Count-gt0) 'Nonempty pinned expectation required.';$expectedPaths=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);foreach($item in $expectedObjects){Need ($expectedPaths.Add(($item.path-join'\'))) 'Duplicate expected path.'}
 $policyProperty=$result.PSObject.Properties['actual_target_verification_policy'];$targetPolicy='full_content';if($null-ne$policyProperty){$targetPolicy=[string]$policyProperty.Value};Need ($targetPolicy-in@('full_content','extent_identity_v1')) 'Unknown actual native target verification policy.';$fastTarget=$targetPolicy-ceq'extent_identity_v1';$extentReceipt=$null
 if($fastTarget){
  $extentPath=Join-Path $records 'extent-verification.json';$extentReceipt=Json $extentPath 1MB;$pins['extent-verification']=(Get-FileHash -LiteralPath $extentPath -Algorithm SHA256).Hash.ToLowerInvariant()
  Need ($extentReceipt.schema_version-eq1-and$extentReceipt.scope-ceq'fresh-conversion-extent-identity-v1'-and$extentReceipt.expected_tree_sha256-ceq$pins.expectation-and$extentReceipt.all_complete_maps_identical-eq$true-and$extentReceipt.handoff_replay_closed-eq$true-and$extentReceipt.target_full_file_hashes-eq$false-and$extentReceipt.target_admitted_payload_bytes_read-eq0) 'Fresh native extent-verification receipt differs.'
  $observation=$final.native.content_observation;Need ($observation.scope-ceq'converted-metadata-and-complete-stream-maps-v1'-and$observation.full_file_hashes-eq$false-and$observation.content_equality_verified-eq$false-and$observation.admitted_payload_bytes_read-eq0-and$observation.metadata_and_namespace_verified-eq$true-and$observation.complete_stream_mappings_observed-eq$true-and$observation.data_storage_validity_checked-eq$true) 'Fast native target report must explicitly contain metadata observations without content hashes.'
 }
 $native=@($final.native.native.objects);$byPath=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
 foreach($object in $native){$key=[string]::Join('\',[string[]]@($object.components));Need (-not$byPath.ContainsKey($key)) 'Duplicate canonical native path.';$byPath.Add($key,$object)}
 $hashes=0;$namedHashes=0;$observedFiles=0;$observedNamed=0;$sparseCount=0
 foreach($object in $expectedObjects){
  $key=[string]::Join('\',[string[]]@($object.path));Need ($byPath.ContainsKey($key)) 'Native canonical object missing.';$observed=$byPath[$key]
  if(-not$object.directory){$observedFiles++;if($fastTarget){Need ($null-eq$observed.logical_sha256) 'Fast native target must not manufacture an observed canonical hash.'}else{Need ($observed.logical_sha256-ceq$object.sha256) 'Native canonical file content differs.';$hashes++}}
  $sparseProperty=$object.PSObject.Properties['sparse'];if($null-ne$sparseProperty-and$null-ne$sparseProperty.Value){CheckSparseObservation $sparseProperty.Value $observed.sparse $object.length;$sparseCount++}
  $expectedStreams=@();$prop=$object.PSObject.Properties['named_streams'];if($null-ne$prop){$expectedStreams=@($prop.Value)}
  $observedStreams=@();$prop=$observed.PSObject.Properties['named_streams'];if($null-ne$prop){$observedStreams=@($prop.Value)}
  Need ($observedStreams.Count-eq$expectedStreams.Count) 'Native named stream count differs from expectation.'
  foreach($stream in $expectedStreams){$matches=@($observedStreams|Where-Object {SameArray $_.name_utf16 $stream.name_utf16});Need ($matches.Count-eq1-and$matches[0].expected_sha256-ceq$stream.sha256) 'Native named stream identity/expectation differs.';$observedNamed++;if($fastTarget){Need ($null-eq$matches[0].logical_sha256) 'Fast native target must not manufacture an observed named-stream hash.'}else{Need ($matches[0].logical_sha256-ceq$stream.sha256) 'Native named stream content differs.';$namedHashes++};$sparseProperty=$stream.PSObject.Properties['sparse'];if($null-ne$sparseProperty-and$null-ne$sparseProperty.Value){CheckSparseObservation $sparseProperty.Value $matches[0].sparse $stream.length;$sparseCount++}}
 }
 $expectedFiles=@($expectedObjects|Where-Object {-not$_.directory}).Count
 $expectedNamed=8;if($c.compression_fixture_enabled){$expectedNamed+=$compressionShape.named_streams}
 Need ($native.Count-eq$expectedObjects.Count-and$observedFiles-eq$expectedFiles-and$observedNamed-eq$expectedNamed-and$sparseCount-eq3) 'Expected exact admitted objects/default streams, baseline plus fixture ADS and three sparse layouts.'
 if($fastTarget){Need ($hashes-eq0-and$namedHashes-eq0-and$observation.default_streams_observed-eq$expectedFiles-and$observation.named_streams_observed-eq$expectedNamed) 'Fast metadata observation stream coverage differs.'}else{Need ($hashes-eq$expectedFiles-and$namedHashes-eq$expectedNamed) 'Every native full-content stream hash is required.'}
 $independentHashes=$null
 if($fastTarget){$phase='independent-complete-target-hashes';$independentHashes=VerifyAllTargetStreamHashes $labExpected 'H';$independentHashes['lab_baseline_binding']=$baselineBinding;Need ($independentHashes.default_stream_hashes-eq$expectedFiles-and$independentHashes.named_stream_hashes-eq$expectedNamed) 'Every expected target default and named stream requires an independent full hash.';Save 'independent-target-hashes.json' $independentHashes;$pins['independent-target-hashes']=(Get-FileHash -LiteralPath (Join-Path $c.stage 'independent-target-hashes.json') -Algorithm SHA256).Hash.ToLowerInvariant()}
 $phase='ads-hardlink-roundtrip';$roundtrip=VerifyFixture $fixture 'ReFS';Save 'fixture-after.json' $roundtrip;Save 'ads-after.json' (VerifyAds $fixture $ads)
 Save 'sparse-after.json' (VerifySparseFixture $sparse)
 Save 'attribute-after.json' (VerifyAttributeFixture $attribute 'ReFS')
 if($c.ea_fixture_enabled){$eaLive=VerifyEaFixture $ea 'ReFS';$eaSummary=VerifyEaPreservation $records $ea $expected $final;Save 'ea-after.json' @{live=$eaLive;preservation=$eaSummary;fixture_sha256=$c.ea_fixture_sha256}}
 if($c.security_fixture_enabled){$phase='security-target-observation';$securityLive=ObserveSecurityFixture $security 'ReFS';$securityCore=BindSecurityFixtureToCore $records $security $expected $final;$securitySummary=@{live=$securityLive;core_binding=$securityCore;fixture_sha256=$c.security_fixture_sha256;tool_sha256=$c.security_tool_sha256;requested_states_not_assumed=$true};Save 'security-after.json' $securitySummary}
 if($c.reparse_fixture_enabled){$phase='reparse-target-observation';$reparseLive=ObserveReparseFixture $reparse 'ReFS';$reparseCore=BindReparseFixtureToCore $records $reparse $expected $final;$reparseSummary=@{live=$reparseLive;core_binding=$reparseCore;fixture_sha256=$c.reparse_fixture_sha256;tool_sha256=$c.reparse_tool_sha256;no_follow_inventory=$true};Save 'reparse-after.json' $reparseSummary}
 if($c.compression_fixture_enabled){$phase='compression-target-observation';$compressionLive=ObserveCompressionFixture $compression 'ReFS';$compressionCore=BindCompressionFixtureToCore $records $compression $expected $final;$compressionSummary=@{live=$compressionLive;core_binding=$compressionCore;fixture_sha256=$c.compression_fixture_sha256;tool_sha256=$c.compression_tool_sha256;normalization='NTFS LZNT1 logical data materialized as ordinary ReFS streams'};Save 'compression-after.json' $compressionSummary}
 Save 'wrapper-result.json' @{schema_version=1;kind='public-attribute-list-conversion-observation';success=$true;run_id=$c.run_id;source_commit=$c.source_commit;main_source_sha256=$c.main_source_sha256;binary_sha256=$c.binary_sha256;fixture_sha256=$c.fixture_sha256;ads_fixture_sha256=$c.ads_sha256;sparse_fixture_sha256=$c.sparse_sha256;digest_tool_sha256=$c.digest_sha256;native_exit=$nativeExit;conversion_records=$records;native_objects=$native.Count;expected_object_count=$expectedObjects.Count;expected_default_hash_count=$expectedFiles;attribute_fixture_sha256=$c.attribute_sha256;attribute_list_assembly=$assemblyLedger;independent_attribute_alias_stream_hashes=9;ea_fixture_enabled=$c.ea_fixture_enabled;ea_fixture_sha256=$c.ea_fixture_sha256;ea_preservation=$eaSummary;security_fixture_enabled=$c.security_fixture_enabled;security_fixture_sha256=$c.security_fixture_sha256;security_tool_sha256=$c.security_tool_sha256;security_preservation=$securitySummary;reparse_fixture_enabled=$c.reparse_fixture_enabled;reparse_fixture_sha256=$c.reparse_fixture_sha256;reparse_tool_sha256=$c.reparse_tool_sha256;reparse_preservation=$reparseSummary;compression_fixture_enabled=$c.compression_fixture_enabled;compression_fixture_sha256=$c.compression_fixture_sha256;compression_tool_sha256=$c.compression_tool_sha256;compression_preservation=$compressionSummary;expected_named_hash_count=$expectedNamed;complete_logical_hashes=$hashes;native_named_stream_hashes=$namedHashes;actual_target_verification_policy=$targetPolicy;engine_full_target_file_hashes=(-not$fastTarget);engine_metadata_default_streams=$observedFiles;engine_metadata_named_streams=$observedNamed;extent_verification_receipt=$extentReceipt;lab_baseline_binding=$baselineBinding;lab_extent_scope=$labExtentScope;independent_target_hashes=$independentHashes;independent_complete_logical_hashes=$(if($null-ne$independentHashes){$independentHashes.default_stream_hashes}else{0});independent_named_stream_hashes=$(if($null-ne$independentHashes){$independentHashes.named_stream_hashes}else{0});sparse_layouts_verified=$sparseCount;independent_sha256_old_named_stream_views=15;independent_sparse_content_paths=4;old_user_file_identities=3;old_user_file_names=9;hardlink_sets_verified=$true;label_and_mount_verified=$true;handoff_replay_closed=$true;records_pins=$pins;general_conversion_qualified=$false;mutation_or_recovery_tested=$false;qualification_scope='one driver-fragmented plain ATTRIBUTE_LIST file with three names and three streams; no arbitrary feature or new-build recovery claim';utc=[DateTime]::UtcNow.ToString('o')}
}catch{Save 'wrapper-failed.json' @{success=$false;run_id=$c.run_id;phase=$phase;native_exit=$nativeExit;native_exit_observed=($null-ne$nativeExit);error=$_.Exception.ToString();automatic_retry_recovery_restore_cleanup=$false;utc=[DateTime]::UtcNow.ToString('o')};throw}
finally{if($null-ne$process){$process.Dispose()}}
'@
 $body=$body.Replace('__CONFIG__',[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes(($c|ConvertTo-Json -Depth 6 -Compress))))
 $wrapper=Join-Path $root 'guest-wrapper.ps1';[IO.File]::WriteAllText($wrapper,$body,[Text.UTF8Encoding]::new($false));$wrapperPin=(Get-FileHash -LiteralPath $wrapper).Hash.ToLowerInvariant()
 $session=New-PSSession -VMId $vmId -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')) -ErrorAction Stop
 Invoke-Command -Session $session -ArgumentList $stage,$task -ScriptBlock {param($Stage,$Task);$ErrorActionPreference='Stop';if((Test-Path -LiteralPath $Stage)-or@(Get-ScheduledTask|Where-Object TaskName -CEQ $Task).Count-or@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-or@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count){throw 'Fresh idle guest stage required.'};$a=Get-Item -LiteralPath 'C:\ntfs2refs' -Force;while($null-ne$a){if($a.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse guest stage ancestry.'};$a=$a.Parent};New-Item -ItemType Directory -Path $Stage|Out-Null}
 Copy-Item -LiteralPath $exeFile.FullName -ToSession $session -Destination (Join-Path $stage 'ntfs2refs.exe');Copy-Item -LiteralPath $digestFile.FullName -ToSession $session -Destination (Join-Path $stage 'lab-content-digest.exe');Copy-Item -LiteralPath $fixtureFile.FullName -ToSession $session -Destination (Join-Path $stage 'fixture.json');Copy-Item -LiteralPath $adsFile.FullName -ToSession $session -Destination (Join-Path $stage 'ads-fixture.json');Copy-Item -LiteralPath $sparseFile.FullName -ToSession $session -Destination (Join-Path $stage 'sparse-fixture.json');Copy-Item -LiteralPath $attributeFile.FullName -ToSession $session -Destination (Join-Path $stage 'attribute-fixture.json');Copy-Item -LiteralPath $wrapper -ToSession $session -Destination (Join-Path $stage 'wrapper.ps1')
 if($baseline.enabled){foreach($spec in @(@{key='expectation';name='lab-full-content-baseline.json'},@{key='request';name='lab-baseline-request.json'},@{key='result';name='lab-baseline-result.json'},@{key='basis';name='lab-baseline-source-basis.json'})){Copy-Item -LiteralPath $baseline.files[$spec.key].path -ToSession $session -Destination (Join-Path $stage $spec.name)}}
 if($eaEnabled){Copy-Item -LiteralPath $eaFile.FullName -ToSession $session -Destination (Join-Path $stage 'ea-fixture.json')}
 if($securityEnabled){Copy-Item -LiteralPath $securityFile.FullName -ToSession $session -Destination (Join-Path $stage 'security-fixture.json');Copy-Item -LiteralPath $securityTool.FullName -ToSession $session -Destination (Join-Path $stage 'lab-create-security-fixture.exe')}
 if($reparseEnabled){Copy-Item -LiteralPath $reparseFile.FullName -ToSession $session -Destination (Join-Path $stage 'reparse-fixture.json');Copy-Item -LiteralPath $reparseTool.FullName -ToSession $session -Destination (Join-Path $stage 'lab-create-reparse-fixture.exe')}
 if($compressionEnabled){Copy-Item -LiteralPath $compressionFile.FullName -ToSession $session -Destination (Join-Path $stage 'compression-fixture.json');Copy-Item -LiteralPath $compressionTool.FullName -ToSession $session -Destination (Join-Path $stage 'lab-create-compression-fixture.exe')}
 HostGuard
 Save 'dispatch.json' @{schema_version=1;kind='public-attribute-list-conversion-dispatch';run_id=$run;vm_id=$vmId.ToString('D');parent_id=$ExpectedParent.ToString('D');checkpoint_ids=$ids;guest_stage=$stage;task_name=$task;wrapper_sha256=$wrapperPin;binary_sha256=$PublicExeSha256;digest_tool_sha256=$DigestToolSha256;source_commit=$SourceCommit;main_source_sha256=$MainSourceSha256;fixture_sha256=$HardlinkFixtureManifestSha256;ads_fixture_sha256=$AdsManifestSha256;sparse_fixture_sha256=$SparseFixtureSha256;attribute_fixture_sha256=$AttributeFixtureSha256;ea_fixture_enabled=$eaEnabled;ea_fixture_sha256=$EaFixtureSha256;security_fixture_enabled=$securityEnabled;security_fixture_sha256=$SecurityFixtureSha256;security_tool_sha256=$SecurityToolSha256;security_tool_bytes=$(if($securityEnabled){$securityTool.Length}else{0});reparse_fixture_enabled=$reparseEnabled;reparse_fixture_sha256=$ReparseFixtureSha256;reparse_tool_sha256=$ReparseToolSha256;reparse_tool_bytes=$(if($reparseEnabled){$reparseTool.Length}else{0});compression_fixture_enabled=$compressionEnabled;compression_fixture_sha256=$CompressionFixtureSha256;compression_tool_sha256=$CompressionToolSha256;compression_tool_bytes=$(if($compressionEnabled){$compressionTool.Length}else{0});argv=@('--drive','H','--partition',[string]$fixture.partition_number);utc=[DateTime]::UtcNow.ToString('o');minimum_extent_only_streams=$MinimumExtentOnlyStreams;baseline_provenance=$baseline.provenance;baseline_grants_product_authority=$false}
 Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin -ScriptBlock {param($Stage,$Task,$Pin);$ErrorActionPreference='Stop';$path=Join-Path $Stage 'wrapper.ps1';if((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$Pin){throw 'Staged wrapper differs.'};Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'"')) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)) -ErrorAction Stop|Out-Null}
 HostGuard;Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration $configuration) -AdditionalBytes 8GB
 Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin -ScriptBlock {param($Stage,$Task,$Pin);$ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskName $Task;$info=Get-ScheduledTaskInfo -TaskName $Task;$path=Join-Path $Stage 'wrapper.ps1';if($t.State.ToString()-cne'Ready'-or$info.LastRunTime.Year-ge2000-or(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$Pin-or@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count){throw 'Only untouched recorded idle task may start.'};Start-ScheduledTask -TaskName $Task -ErrorAction Stop}
 Save 'start.json' @{start_issued_once=$true;completion_inferred=$false;expected_native_exit=0;utc=[DateTime]::UtcNow.ToString('o')}
 [IO.File]::ReadAllText((Join-Path $root 'dispatch.json'))
}catch{if($created-and-not(Test-Path -LiteralPath (Join-Path $root 'dispatch-failed.json'))){Save 'dispatch-failed.json' @{success=$false;run_id=$run;error=$_.Exception.ToString();automatic_retry=$false;worker_termination_inferred=$false}};throw}
finally{if($null-ne$session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
