# Grown F: object-envelope laboratory controller. Root owns VM power/checkpoints.
# No restore, checkpoint, cleanup, ACL repair, journal raw reads or source formatting.
[CmdletBinding()]param(
 [Parameter(Mandatory)][string]$ToolsetManifest,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ToolsetManifestSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit,
 [Parameter(Mandatory)][guid]$ExpectedParent,
 [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds,
 [Parameter(Mandatory)][string]$FreshBaselineManifestPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$FreshBaselineManifestSha256,
 [Parameter(Mandatory)][string]$DirectoryGrowthReceiptPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$DirectoryGrowthReceiptSha256,
 [Parameter(Mandatory)][ValidatePattern('\AC:\\ntfs2refs\\envelope-interrupt-[0-9a-f]{32}\\conversion\z')][string]$RecoveryDirectory,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$RecoverySha256,
 [switch]$Rollback,
 [ValidateRange(0,50000000000)][long]$ForecastAdditionalBytes=2GB
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$sourceCheckpoint=[guid]'83290a28-1e83-4eb2-a4d3-b0e9f5a8d63b'
$ids=@($ExpectedCheckpointIds|ForEach-Object {$_.ToString('D')});$run=[guid]::NewGuid().ToString('N')
$operation=$(if($Rollback){'rollback'}else{'resume'}); $root=Join-Path $base ('envelope-'+$operation+'-'+$run)
$stage='C:\ntfs2refs\envelope-'+$operation+'-'+$run;$task='N2R-Envelope-'+$operation+'-'+$run
$session=$null;$created=$false;$baseline=$null;$hostHeld=[Collections.Generic.List[IO.FileStream]]::new()
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
. (Join-Path $PSScriptRoot 'SourceBaselineSupport.ps1')
function Save([string]$Name,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 20));Need ($bytes.Length-le4MB) 'Bounded host receipt required.';$file=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
function HostGuard{$v=Get-VM -Id $id;$actual=@(Get-VMSnapshot -VM $v|ForEach-Object {$_.Id.ToString('D')});Need ($v.Name-ceq'ntfs2refs-streaming-v2-20261027'-and$v.State.ToString()-ceq'Running'-and$v.ParentSnapshotId-eq$ExpectedParent-and$v.MemoryStartup-eq4GB-and$v.MemoryAssigned-eq4GB-and-not$v.DynamicMemoryEnabled-and(Get-VMProcessor -VM $v).Count-eq4-and@(Get-VMNetworkAdapter -VM $v).Count-eq0-and$actual.Count-eq$ids.Count-and@($ids|Where-Object {$_-notin$actual}).Count-eq0) 'Root must already boot the exact supplied parent/checkpoint set/4GiB/4CPU/noNIC.'}
try{
 Need ($ExpectedParent-ne[guid]::Empty-and$ids.Count-gt0-and$ids.Count-le50-and@($ids|Sort-Object -Unique).Count-eq$ids.Count-and$ExpectedParent.ToString('D')-in$ids-and[guid]::Empty.ToString('D')-notin$ids-and$sourceCheckpoint.ToString('D')-in$ids) 'Exact unique checkpoint set including current and grown source required.'
 Need ($FreshBaselineManifestSha256-ceq'f5de156f9d2140b0f77bae80ba336b80fe543d22428ecbbf6b0eb3251dd290b7'-and$DirectoryGrowthReceiptSha256-ceq'835b1196b038b2aac01bc1bd4efdf5e9837531d5e1d69dd7b9486272f37ba37c') 'Pinned grown-source full baseline and metadata-only growth required.'
 $baseline=ReadFreshLabSourceBaselineHost $FreshBaselineManifestPath $FreshBaselineManifestSha256 $DirectoryGrowthReceiptPath $DirectoryGrowthReceiptSha256 $sourceCheckpoint $base
 $manifestFile=FreshBaselineOrdinary $ToolsetManifest 1MB;Need ($ToolsetManifest.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)-and$manifestFile.Name-ceq'manifest.json') 'Lab-local sealed toolset manifest required.'
 $manifest=(OpenFreshBaselineHost $ToolsetManifest $ToolsetManifestSha256 1MB $hostHeld $true).value;$toolsetDir=$manifestFile.DirectoryName
 Need ($manifest.schema_version-eq1-and$manifest.kind-ceq'envelope-recovery-toolset'-and$manifest.source_commit-ceq$SourceCommit-and@($manifest.tools).Count-eq4) 'Explicit envelope runtime provenance required; no inherited qualification.'
 $tools=@();foreach($name in @('lab-convert-native-composite.exe','ntfs2refs.exe','lab-content-digest.exe','lab-managed-shadow.exe')){$row=@($manifest.tools|Where-Object name -CEQ $name);Need ($row.Count-eq1-and$row[0].path-ceq(Join-Path $toolsetDir $name)-and$row[0].bytes-gt0-and$row[0].bytes-le64MB-and$row[0].sha256-cmatch'\A[0-9a-f]{64}\z') 'One exactly routed bounded executable pin required.';$actual=(OpenFreshBaselineHost $row[0].path $row[0].sha256 64MB $hostHeld $false).item;Need ($actual.Length-eq$row[0].bytes) 'Sealed executable length differs.';$tools+=@{name=$name;path=$actual.FullName;bytes=$actual.Length;sha256=$row[0].sha256}}
 Need ($ExpectedParent-ne$sourceCheckpoint) 'Recovery requires the same saved interrupted86 checkpoint, not the original NTFS source.'
 Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force;$configuration=Get-LabConfiguration -WorkspaceRoot $workspace;$capacity=Get-LabCapacity -Configuration $configuration
 Need ($capacity.MaximumActualBytes-eq329374052988-and$capacity.MinimumFreeBytes-eq17179869184) 'Fixed capacity epoch or reserve differs.';Assert-LabCapacity -Capacity $capacity -AdditionalBytes $ForecastAdditionalBytes
 HostGuard;Need (-not(Test-Path -LiteralPath $root)) 'Fresh host case required.';New-Item -ItemType Directory -Path $root|Out-Null;$created=$true
 $c=@{stage=$stage;task=$task;run_id=$run;vm_id=$id.ToString('D');operation=$operation;source_commit=$SourceCommit;tools=$tools;output=(Join-Path $stage 'conversion');managed=(Join-Path $stage 'managed-shadow');baseline_enabled=$true;fresh_baseline_enabled=$true;fresh_baseline_files=$baseline.files;fresh_manifest_sha256=$FreshBaselineManifestSha256;fresh_source_checkpoint=$sourceCheckpoint.ToString('D');fresh_source_binding=$baseline.provenance.source_binding;baseline_sha256=$baseline.sha256;baseline_basis_sha256=$baseline.basis_sha256;baseline_request_sha256='';baseline_result_sha256='';minimum_tail_extent_only_streams=650;minimum_extent_only_streams=654;journal_budget_bytes=17179869184;literal_ceiling_bytes=268435456;combined_ceiling_bytes=19327352832;maximum_placement_submissions=32768}
$c.recovery_directory=$RecoveryDirectory;$c.recovery_sha256=$RecoverySha256;$c.cli=@('--recover',$RecoveryDirectory,'--recovery-sha256',$RecoverySha256);if($Rollback){$c.cli+='--rollback'};$public=@($tools|Where-Object name -CEQ 'ntfs2refs.exe')[0];$c.binary_sha256=$public.sha256;$c.binary_bytes=$public.bytes
 Save 'intent.json' @{schema_version=1;kind=('object-envelope-'+$operation+'-intent');run_id=$run;vm_id=$id;parent_id=$ExpectedParent;source_checkpoint=$sourceCheckpoint;checkpoint_ids=$ids;toolset_manifest=$ToolsetManifest;toolset_manifest_sha256=$ToolsetManifestSha256;source_commit=$SourceCommit;tools=$tools;configuration=$c;baseline_provenance=$baseline.provenance;capacity=$capacity;forecast_bytes=$ForecastAdditionalBytes;forecast_is_not_reservation=$true;power_checkpoint_cleanup_authorized=$false;baseline_grants_product_authority=$false;utc=[DateTime]::UtcNow.ToString('o')}
 $body=@'
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CONFIG__'))|ConvertFrom-Json
$script:closedJsonCache=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$script:labIndexes=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
$script:labFreshBaseline=$null
$phase='preflight';$lastExit=$null;$nativeExit=$null;$requestPin=$null
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function Save([string]$Name,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 32));Need ($bytes.Length-le64MB) 'Bounded complete wrapper metadata required.';$file=[IO.File]::Open((Join-Path $c.stage $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
function LabExtentEvidenceShape($Stream){
 $e=$Stream.PSObject.Properties['source_evidence'];Need ($null-eq$Stream.sha256-and$null-ne$e) 'Absent product digest requires an explicit source-evidence tag.'
 $length=[long]$Stream.length;$tail=$length%4096;$sparse=$Stream.PSObject.Properties['sparse'];Need ($null-eq$sparse-or$null-eq$sparse.Value) 'Extent-only source evidence cannot describe sparse data.'
 if($e.Value-ceq'extent_identity_v1'){Need ($length-gt0-and$tail-eq0) 'Whole extent evidence requires a positive whole-cluster EOF.'}
 elseif($e.Value-ceq'extent_identity_with_materialized_tail_v1'){Need ($length-ge4096-and$tail-gt0) 'Materialized-tail extent evidence requires a routed prefix and a partial final cluster.'}
 else{throw 'Unknown extent-only source-evidence tag.'}
 return @{source_evidence=[string]$e.Value;logical_length=$length;prefix_bytes=($length-$tail);tail_offset=($length-$tail);tail_bytes=$tail;has_tail=($tail-gt0)}
}
function LabEvidenceNameMatches($Row,$Name){$p=$Row.PSObject.Properties['stream_name_utf16'];$actual=@();if($null-ne$p){$actual=@($p.Value)};return (SameArray $actual $Name)}
function AssertLabTailCounter($Value,[string]$Name,[long]$Expected){$p=$Value.PSObject.Properties[$Name];Need ($Expected-eq0-or$null-ne$p) ('Actual producer tail counter is missing: '+$Name);if($null-ne$p){Need ($p.Value-eq$Expected) ('Actual producer tail counter differs: '+$Name)}}
function AssertLabTailReceipts($Expected,[string]$Records){
 $tails=[Collections.Generic.List[object]]::new();$total=0L
 $objects=@($Expected.objects)
 for($index=0;$index-lt$objects.Count;$index++){$object=$objects[$index];if($object.directory){continue};$named=$object.PSObject.Properties['named_streams'];$streams=[Collections.Generic.List[object]]::new();$streams.Add(@{stream=$object;name=@()});if($null-ne$named){foreach($s in $named.Value){$streams.Add(@{stream=$s;name=@($s.name_utf16)})}};foreach($entry in $streams){if($null-ne$entry.stream.sha256){continue};$shape=LabExtentEvidenceShape $entry.stream;if($shape.has_tail){$tails.Add(@{object_index=$index;object=$object;name=$entry.name;shape=$shape});$total+=$shape.tail_bytes}}}
 Need ($tails.Count-ge$c.minimum_tail_extent_only_streams) ('Actual materialized-tail extent-only streams '+$tails.Count+' are below the required lab minimum '+$c.minimum_tail_extent_only_streams)
 $metadataPath=Join-Path $Records 'qualification\construction-metadata.json';$metadata=$null;$owned=@();if(Test-Path -LiteralPath $metadataPath){$metadata=Json $metadataPath;$field=$metadata.PSObject.Properties['extent_only_tail_materialization'];if($null-ne$field){$owned=@($field.Value)}}
 Need ($owned.Count-eq$tails.Count) 'Constructor-owned digest-free tail receipt count must exactly match canonical tail evidence.'
 if($tails.Count-eq0){return @{scope='lab-bound-materialized-extent-tails-v1';minimum_tail_extent_only_streams=$c.minimum_tail_extent_only_streams;tail_extent_only_streams=0;materialized_tail_bytes=0;actual_constructor_receipts=0;rows=@();product_expectation_changed=$false;grants_product_authority=$false}}
 Need ($null-ne$metadata) 'Actual constructor completion metadata is required for tail evidence.'
 $exceptionsPath=Join-Path $Records 'qualification\construction-exceptions.json';$preservationPath=Join-Path $Records 'qualification\target-preservation.json';$basisPath=Join-Path $Records 'qualification\source-basis.json';$sourcePath=Join-Path $Records 'qualification\native-source.json'
 $exceptions=Json $exceptionsPath 64MB;$preservation=Json $preservationPath 64MB;$basis=Json $basisPath 64MB;$sourceNative=Json $sourcePath 64MB;$protected=$preservation.protected.native.report
 Need ($exceptions.source_payload_writes-eq0-and$protected.residual_contents_verified-eq$true-and$protected.metadata_and_namespace_verified-eq$true-and$protected.complete_stream_mappings_verified-eq$true-and$preservation.protected.native.before.disk_attributes-eq3-and$preservation.protected.native.observed_readonly.disk_attributes-eq2-and$preservation.protected.native.after.disk_attributes-eq3-and$sourceNative.schema_version-eq12-and$sourceNative.request.schema_version-eq4) 'Actual frozen source/protected residual observation is incomplete.'
 $allResidualBytes=0L;foreach($r in $protected.residuals){$allResidualBytes+=[long]$r.length};Need ($protected.payload_bytes_read-eq$allResidualBytes) 'Protected residual actual-read accounting differs.'
 $rawIndex=GetLabIndex 'source.raw.records' $basis.ntfs.files {param($r) LabRecordKey $r.record_number $r.sequence_number}
 $requestIndex=GetLabIndex 'source.request.streams' $sourceNative.request.extent_identity_streams {param($r) LabSourceStreamKey $r.identity.record_number $r.identity.sequence_number $r.name_utf16}
 $logicalIndex=GetLabIndex 'source.logical.records' $sourceNative.logical_data.files {param($r) LabRecordKey $r.identity.record_number $r.identity.sequence_number}
 $exceptionIndex=GetLabIndex 'constructor.exceptions' $exceptions.residuals {param($r) LabRowStreamKey $r}
 $ownedIndex=GetLabIndex 'constructor.tails' $owned {param($r) LabRowStreamKey $r}
 $protectedIndex=GetLabIndex 'target.protected.paths' $protected.native.objects {param($r) LabPathKey $r.components}
 $wantedIndex=GetLabIndex 'target.expected.residuals' $preservation.residuals {param($r) LabRowStreamKey $r}
 $residualIndex=GetLabIndex 'target.protected.residuals' $protected.residuals {param($r) LabRowStreamKey $r}
 $rows=[Collections.Generic.List[object]]::new()
 foreach($tail in $tails){
  $object=$tail.object;$name=$tail.name;$shape=$tail.shape;$index=$tail.object_index
  $recordKey=LabRecordKey $object.record_number $object.sequence_number;$streamKey=LabSourceStreamKey $object.record_number $object.sequence_number $name;$objectKey=LabObjectStreamKey $index $name
  $raw=@(LabIndexMatch $rawIndex $recordKey);Need ($raw.Count-eq1-and$raw[0].record_number-eq$object.record_number-and$raw[0].sequence_number-eq$object.sequence_number-and$object.record_number-ge16) 'Tail source canonical raw identity is absent or reserved.'
  $rawStream=@($raw[0].streams|Where-Object {SameArray $_.name_utf16 $name});$attrs=@($raw[0].attributes|Where-Object {$_.type_code-eq128-and(SameArray $_.name_utf16 $name)})
  Need ($rawStream.Count-eq1-and$attrs.Count-eq1-and$rawStream[0].logical_hash_status-ceq'not_read_extent_identity_v1'-and$null-eq$rawStream[0].logical_sha256-and-not$rawStream[0].resident-and$rawStream[0].flags-eq0-and$rawStream[0].logical_size-eq$shape.logical_length-and$rawStream[0].initialized_size-eq$shape.logical_length-and$rawStream[0].allocated_size-ge$shape.logical_length-and-not$attrs[0].resident-and$attrs[0].flags-eq0-and$attrs[0].compression_unit-eq0-and$attrs[0].lowest_vcn-eq0-and$attrs[0].logical_size-eq$shape.logical_length-and$attrs[0].initialized_size-eq$shape.logical_length) 'Tail source must be actual unread plain fully initialized nonresident DATA.'
  $requests=@(LabIndexMatch $requestIndex $streamKey);Need ($requests.Count-eq1-and$requests[0].identity.record_number-eq$object.record_number-and$requests[0].identity.sequence_number-eq$object.sequence_number-and(SameArray $requests[0].name_utf16 $name)-and$requests[0].logical_size-eq$shape.logical_length-and$requests[0].allocated_size-eq$rawStream[0].allocated_size-and$requests[0].cluster_bytes-eq$basis.ntfs.geometry.cluster_size-and(SameJsonValue $requests[0].extents $rawStream[0].extents)) 'Tail source native complete mapping request differs from raw DATA.'
  $nativeSource=@(LabIndexMatch $logicalIndex $recordKey);Need ($nativeSource.Count-eq1-and$nativeSource[0].identity.record_number-eq$object.record_number-and$nativeSource[0].identity.sequence_number-eq$object.sequence_number) 'Tail source native identity is missing.'
  foreach($passName in @('before','after')){$observed=@($nativeSource[0].$passName|Where-Object {SameArray $_.name_utf16 $name});Need ($observed.Count-eq1-and$observed[0].logical_size-eq$shape.logical_length-and$observed[0].outcome.status-ceq'not_read_extent_identity_v1'-and$observed[0].outcome.bytes_read-eq0-and$null-eq$observed[0].outcome.sha256-and$observed[0].outcome.eof_confirmed-eq$false) 'Tail source native content elision must remain explicit and unread.'}
  $writes=@(LabIndexMatch $exceptionIndex $objectKey);Need ($writes.Count-eq1-and$writes[0].object_index-eq$index-and(LabEvidenceNameMatches $writes[0] $name)) 'One actual construction exception receipt is required for each extent-only tail.';$write=$writes[0]
  Need ($write.kind-ceq'private-exception-materialization'-and$write.source_payload_writes-eq0-and$write.source.record_number-eq$object.record_number-and(LabEvidenceNameMatches $write.source $name)-and$write.source.logical_offset-eq$shape.tail_offset-and$write.source.logical_bytes-eq$shape.tail_bytes-and$write.source.stream_logical_bytes-eq$shape.logical_length-and$null-eq$write.source.expected_stream_sha256-and$write.source.whole_stream_hash_matched-eq$false-and$write.source.sha256-cmatch'\A[0-9a-f]{64}\z'-and$write.destination.offset-eq$shape.tail_offset-and$write.destination.bytes-eq$shape.tail_bytes-and$write.destination.sha256-ceq$write.source.sha256-and$write.destination.readback_verified-eq$true) 'Actual source-tail SHA, exact destination range and successful readback are required.'
  $prefixProperty=$write.destination.PSObject.Properties['valid_prefix_bytes']
  if($null-ne$prefixProperty){Need ($prefixProperty.Value-eq$shape.logical_length) 'Actual default-tail initialization did not reach exact EOF.'}
  else{$partsProperty=$write.destination.PSObject.Properties['parts'];Need (@($name).Count-gt0-and$null-ne$partsProperty-and$write.destination.logical_hole_bytes-eq0) 'Plain ADS tail requires its actual no-hole carrier readback parts.';$parts=@($partsProperty.Value);Need ($parts.Count-eq1-and$parts[0].offset-eq$shape.tail_offset-and$parts[0].bytes-eq$shape.tail_bytes-and$parts[0].sha256-ceq$write.source.sha256-and$parts[0].readback_verified-eq$true) 'Actual plain ADS carrier tail range/SHA/readback differs.'}
  $proofs=@(LabIndexMatch $ownedIndex $objectKey);Need ($proofs.Count-eq1-and$proofs[0].object_index-eq$index-and(LabEvidenceNameMatches $proofs[0] $name)) 'One constructor-owned tail receipt must bind the canonical stream.';$proof=$proofs[0]
  Need ($proof.scope-ceq'constructor-owned-plain-tail-materialization-v1'-and$proof.logical_length-eq$shape.logical_length-and$proof.offset-eq$shape.tail_offset-and$proof.bytes-eq$shape.tail_bytes-and$proof.sha256-ceq$write.source.sha256-and$proof.readback_verified-eq$true-and$proof.source_prefix_contents_verified-eq$false-and@($proof.native_file_id).Count-eq24) 'Constructor-owned tail receipt identity/range/SHA/readback scope differs.'
  $nativeObject=@(LabIndexMatch $protectedIndex (LabPathKey $object.path));Need ($nativeObject.Count-eq1-and(SameArray $nativeObject[0].components $object.path)-and(SameArray $protected.native.objects[$index].components $object.path)) 'Protected tail canonical object/index differs.';$nativeStream=$nativeObject[0];if(@($name).Count-gt0){$found=@($nativeStream.named_streams|Where-Object {SameArray $_.name_utf16 $name});Need ($found.Count-eq1) 'Protected named tail stream is missing.';$nativeStream=$found[0]}
  Need (SameJsonValue $nativeStream.before $nativeStream.after) 'Protected tail metadata changed during its observation.';$id=@($nativeStream.before.queries|Where-Object class -eq 18);Need ($id.Count-eq1-and$null-eq$id[0].native_error-and@($id[0].bytes).Count-eq24-and(SameArray $id[0].bytes $proof.native_file_id)) 'Constructor tail receipt does not bind the protected native file identity.'
  $wanted=@(LabIndexMatch $wantedIndex $objectKey);$actual=@(LabIndexMatch $residualIndex $objectKey);Need ($wanted.Count-eq1-and$actual.Count-eq1-and$wanted[0].object_index-eq$index-and$actual[0].object_index-eq$index-and(LabEvidenceNameMatches $wanted[0] $name)-and(LabEvidenceNameMatches $actual[0] $name)-and$wanted[0].logical_offset-eq$shape.tail_offset-and$wanted[0].length-eq$shape.tail_bytes-and$wanted[0].sha256-ceq$write.source.sha256-and(SameJsonValue $wanted[0] $actual[0])) 'Protected residual tail observation must exactly bind the actual source/readback SHA.'
  $rows.Add(@{object_index=$index;record_number=$object.record_number;sequence_number=$object.sequence_number;path=$object.path;stream_name_utf16=@($name);source_evidence=$shape.source_evidence;logical_length=$shape.logical_length;retained_prefix_bytes=$shape.prefix_bytes;offset=$shape.tail_offset;bytes=$shape.tail_bytes;sha256=$write.source.sha256;native_file_id=$proof.native_file_id;constructor_readback_verified=$true;protected_residual_actual_read_verified=$true;whole_stream_content_hash_claimed=$false})
 }
 return @{scope='lab-bound-materialized-extent-tails-v1';minimum_tail_extent_only_streams=$c.minimum_tail_extent_only_streams;tail_extent_only_streams=$tails.Count;materialized_tail_bytes=$total;actual_constructor_receipts=$owned.Count;actual_source_destination_protected_residual_bindings=$rows.Count;rows=$rows.ToArray();artifact_pins=@{construction_metadata=(Get-FileHash -LiteralPath $metadataPath -Algorithm SHA256).Hash.ToLowerInvariant();construction_exceptions=(Get-FileHash -LiteralPath $exceptionsPath -Algorithm SHA256).Hash.ToLowerInvariant();target_preservation=(Get-FileHash -LiteralPath $preservationPath -Algorithm SHA256).Hash.ToLowerInvariant();source_basis=(Get-FileHash -LiteralPath $basisPath -Algorithm SHA256).Hash.ToLowerInvariant();native_source=(Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()};product_expectation_changed=$false;grants_product_authority=$false}
}
function LabJournalRangeKey($Range){
 Need ($Range-is[pscustomobject]-and@($Range.PSObject.Properties).Count-eq2-and@($Range.PSObject.Properties|Where-Object {$_.Name-cnotin@('offset','length')}).Count-eq0) 'Exact offset/length range fields required.'
 $null=LabIntegerKey $Range.offset;$null=LabIntegerKey $Range.length
 return (LabIntegerKey $Range.offset)+':'+(LabIntegerKey $Range.length)
}
function AssertLabOldZeroEncoding($Plan,[string]$Records,$ActualResult){
 $property=$Plan.PSObject.Properties['old_zero_ranges']
 if($null-eq$property){return @{enabled=$false}}
 Need ($null-ne$property.Value-and$property.Value-is[Collections.IList]) 'Old-zero ranges must be an explicit array.'
 $oldZeros=@($property.Value);if($oldZeros.Count-eq0){return @{enabled=$false}}
 $null=LabIntegerKey $Plan.image_length;$null=LabIntegerKey $Plan.max_selected_bytes;$null=LabIntegerKey $Plan.max_journal_bytes
 Need ($Plan.image_length-gt0-and[decimal]$Plan.image_length-le[long]::MaxValue-and$Plan.ranges-is[Collections.IList]-and@($Plan.ranges).Count-gt0-and@($Plan.ranges).Count-le65536) 'Bounded complete selected-range domain required.'
 $selected=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
 $d=0D;$previousEnd=0D
 foreach($range in $Plan.ranges){$key=LabJournalRangeKey $range;$end=[decimal]$range.offset+[decimal]$range.length;Need ($range.length-gt0-and$range.offset%4096-eq0-and$range.length%4096-eq0-and[decimal]$range.offset-ge$previousEnd-and$end-le[decimal]$Plan.image_length-and-not$selected.ContainsKey($key)) 'Selected ranges must be aligned, sorted, unique and within the image.';$selected.Add($key,$range);$d+=[decimal]$range.length;$previousEnd=$end}
 Need ($d-gt0-and$d-le[long]::MaxValue-and$d-le[decimal]$Plan.max_selected_bytes) 'Selected byte sum exceeds its admitted bound.'
 $o=0D;$previousOffset=-1D
 foreach($range in $oldZeros){$key=LabJournalRangeKey $range;Need ($selected.ContainsKey($key)-and[decimal]$range.offset-gt$previousOffset) 'Old-zero ranges must be a sorted unique exact whole-selected-range subset.';$o+=[decimal]$range.length;$previousOffset=[decimal]$range.offset}
 Need ($o-gt0-and$o-le$d) 'Pinned old-zero total must be positive and bounded by selected bytes.'
 $newZeros=@();$p=$Plan.PSObject.Properties['new_zero_ranges'];if($null-ne$p){Need ($null-ne$p.Value-and$p.Value-is[Collections.IList]) 'New-zero ranges must be an array.';$newZeros=@($p.Value)}
 $copies=@();$p=$Plan.PSObject.Properties['new_copy_ranges'];if($null-ne$p){Need ($null-ne$p.Value-and$p.Value-is[Collections.IList]) 'Copy ranges must be an array.';$copies=@($p.Value)}
 $z=0D;$copy=0D;$destinations=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$previousOffset=-1D
 foreach($range in $newZeros){$key=LabJournalRangeKey $range;Need ($selected.ContainsKey($key)-and[decimal]$range.offset-gt$previousOffset-and$destinations.Add($key)) 'New-zero ranges must be a sorted unique exact selected subset.';$z+=[decimal]$range.length;$previousOffset=[decimal]$range.offset}
 $previousOffset=-1D
 foreach($range in $copies){Need ($range-is[pscustomobject]-and@($range.PSObject.Properties).Count-eq3-and@($range.PSObject.Properties|Where-Object {$_.Name-cnotin@('offset','length','source_offset')}).Count-eq0) 'Exact copy range fields required.';$null=LabIntegerKey $range.offset;$null=LabIntegerKey $range.length;$null=LabIntegerKey $range.source_offset;$key=(LabIntegerKey $range.offset)+':'+(LabIntegerKey $range.length);Need ($selected.ContainsKey($key)-and[decimal]$range.offset-gt$previousOffset-and$destinations.Add($key)-and$range.source_offset%4096-eq0-and([decimal]$range.source_offset+[decimal]$range.length)-le[decimal]$Plan.image_length) 'Copy destinations must be exact selected ranges disjoint from new zeros; source geometry must be bounded.';$copy+=[decimal]$range.length;$previousOffset=[decimal]$range.offset}
 $literal=$d-$z-$copy;Need ($literal-ge0) 'New zero/copy payload sums exceed selected bytes.'
 $planPath=Join-Path $Records 'selected-plan.json';$ticketPath=Join-Path $Records 'selected-ticket.json';$locationPath=Join-Path $Records 'journal-location.json';$capacityPath=Join-Path $Records 'journal-capacity.json'
 foreach($spec in @(@{path=$planPath;max=16MB},@{path=$ticketPath;max=65536},@{path=$locationPath;max=1MB},@{path=$capacityPath;max=1MB},@{path=(Join-Path $Records 'allocation-recovery-bundle.json');max=65536},@{path=(Join-Path $Records 'request.json');max=131072})){$item=Get-Item -LiteralPath $spec.path -Force;Need (-not$item.PSIsContainer-and$item.Length-gt0-and$item.Length-le$spec.max) 'Old-zero metadata exceeds its existing closed-artifact bound.'}
 $ticket=Json $ticketPath;$location=Json $locationPath;$capacity=Json $capacityPath;$bundle=Json (Join-Path $Records 'allocation-recovery-bundle.json');$request=Json (Join-Path $Records 'request.json')
 $planPin=(Get-FileHash -LiteralPath $planPath -Algorithm SHA256).Hash.ToLowerInvariant();$ticketPin=(Get-FileHash -LiteralPath $ticketPath -Algorithm SHA256).Hash.ToLowerInvariant()
 Need ($bundle.plan.path-ceq$planPath-and$bundle.plan.sha256-ceq$planPin-and$bundle.ticket.path-ceq$ticketPath-and$bundle.ticket.sha256-ceq$ticketPin-and$bundle.journal-ceq$location.path) 'Old-zero facts must bind the actual bundle-pinned plan, ticket and journal route.'
 foreach($value in @($ticket.image_length,$ticket.selected_bytes,$ticket.range_count,$ticket.journal_length,$location.journal_format_version,$location.journal_record_bytes,$location.old_zero_bytes,$capacity.old_zero_bytes)){$null=LabIntegerKey $value}
 $expected=8192D+80D+80D+104D*@($Plan.ranges).Count+2D*$d-$z-$copy-$o
 Need ($expected-gt0-and$expected-le[long]::MaxValue-and$ticket.image_length-eq$Plan.image_length-and$ticket.selected_bytes-eq$d-and$ticket.range_count-eq@($Plan.ranges).Count-and$ticket.whole_image_verified-eq$false-and$ticket.journal_length-eq$expected-and$expected-le[decimal]$Plan.max_journal_bytes) 'Format4 exact descriptor/payload journal size or trusted ticket domain differs.'
 Need ($location.format-ceq'N2ROLD01'-and$location.journal_format_version-eq4-and$location.journal_record_bytes-eq104-and$location.old_zero_bytes-eq$o-and$capacity.old_zero_bytes-eq$o-and$capacity.journal_bytes-eq$expected-and$capacity.selected_bytes-eq$d-and$capacity.new_zero_bytes-eq$z-and$capacity.new_copy_bytes-eq$copy-and$capacity.packed_bytes-eq$literal) 'Actual format4 location/capacity totals differ from the pinned exact subsets.'
 $capElision=$capacity.PSObject.Properties['old_zero_payload_storage_elided'];if($null-ne$capElision){Need ($capElision.Value-is[bool]-and$capElision.Value) 'Capacity old-zero elision flag differs.'}
 $null=LabIntegerKey $request.max_combined_scratch_bytes;$null=LabIntegerKey $request.max_literal_backing_bytes
 Need ($literal-le[decimal]$request.max_literal_backing_bytes-and$d+$literal-le[decimal]$request.max_combined_scratch_bytes-and$expected+$literal-le[decimal]$request.max_combined_scratch_bytes) 'Conservative selectedD plus literal capture and actual journal scratch ceilings must both remain admitted.'
 if($null-ne$ActualResult){$null=LabIntegerKey $ActualResult.old_zero_bytes;Need ($ActualResult.old_zero_bytes-eq$o-and$ActualResult.old_zero_payload_storage_elided-is[bool]-and$ActualResult.old_zero_payload_storage_elided) 'Actual product result must explicitly report the same old-zero total and storage elision.'}
 return @{enabled=$true;scope='lab-pinned-old-zero-journal-encoding-v1';format='N2ROLD01';journal_format_version=4;journal_record_bytes=104;range_count=@($Plan.ranges).Count;selected_bytes=[long]$d;old_zero_ranges=$oldZeros.Count;old_zero_bytes=[long]$o;stored_old_payload_bytes=[long]($d-$o);new_zero_bytes=[long]$z;new_copy_bytes=[long]$copy;literal_new_payload_bytes=[long]$literal;expected_journal_bytes=[long]$expected;journal_bytes=$ticket.journal_length;plan_sha256=$planPin;ticket_sha256=$ticketPin;location_sha256=(Get-FileHash -LiteralPath $locationPath -Algorithm SHA256).Hash.ToLowerInvariant();capacity_sha256=(Get-FileHash -LiteralPath $capacityPath -Algorithm SHA256).Hash.ToLowerInvariant();old_zero_exact_selected_subset=$true;core_actual_source_zero_check_replaced_by_lab=$false;lab_source_payload_bytes_read=0;raw_journal_opened=$false;grants_product_authority=$false}
}
function SameArray($Left,$Right){$a=@($Left);$b=@($Right);if($a.Count-ne$b.Count){return $false};for($i=0;$i-lt$a.Count;$i++){if($a[$i]-cne$b[$i]){return $false}};return $true}
function Json([string]$Path,[long]$Limit=64MB){
 Need ($Path.StartsWith('C:\',[StringComparison]::OrdinalIgnoreCase)-and$Path.EndsWith('.json',[StringComparison]::Ordinal)) 'Closed C JSON only.'
 $m=Get-Item -LiteralPath $Path -Force;Need (-not$m.PSIsContainer-and-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$m.Length-gt0-and$m.Length-le$Limit) 'Bounded ordinary closed C JSON required.'
 $a=$m.Directory;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse C metadata ancestry.';$a=$a.Parent}
 if($script:closedJsonCache.ContainsKey($Path)){return $script:closedJsonCache[$Path].value}
 $stream=$null;$reader=$null
 try{
  # Retain this exact closed file with write/delete sharing denied. Repeated
  # consumers share its parsed value, never a size/mtime-based cache authority.
  $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  Need ($stream.Length-eq$m.Length-and$stream.Length-gt0-and$stream.Length-le$Limit) 'Opened closed JSON length differs.'
  $reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false),$true,4096,$true)
  $value=$reader.ReadToEnd()|ConvertFrom-Json
  $script:closedJsonCache.Add($Path,@{stream=$stream;value=$value});$stream=$null
  return $value
 }finally{if($null-ne$reader){$reader.Dispose()};if($null-ne$stream){$stream.Dispose()}}
}
function LabIntegerKey($Value){Need ($null-ne$Value-and[Type]::GetTypeCode($Value.GetType())-in@([TypeCode]::SByte,[TypeCode]::Byte,[TypeCode]::Int16,[TypeCode]::UInt16,[TypeCode]::Int32,[TypeCode]::UInt32,[TypeCode]::Int64,[TypeCode]::UInt64)-and$Value-ge0) 'Exact nonnegative integer index key required.';return ([uint64]$Value).ToString('x16',[Globalization.CultureInfo]::InvariantCulture)}
function LabRecordKey($Record,$Sequence){return (LabIntegerKey $Record)+':'+(LabIntegerKey $Sequence)}
function LabNameKey($Name){$units=@($Name);$key=[Text.StringBuilder]::new();$null=$key.Append($units.Count).Append(':');foreach($unit in $units){$null=LabIntegerKey $unit;Need ($unit-le65535) 'Exact UTF16 code-unit key required.';$null=$key.Append(([int]$unit).ToString('x4',[Globalization.CultureInfo]::InvariantCulture))};return $key.ToString()}
function LabPathKey($Path){$parts=@($Path);$key=[Text.StringBuilder]::new();$null=$key.Append($parts.Count).Append(':');foreach($part in $parts){Need ($part-is[string]) 'Exact path component key required.';$null=$key.Append($part.Length).Append(':').Append($part)};return $key.ToString()}
function LabSourceStreamKey($Record,$Sequence,$Name){return (LabRecordKey $Record $Sequence)+':'+(LabNameKey $Name)}
function LabObjectStreamKey($Index,$Name){return (LabIntegerKey $Index)+':'+(LabNameKey $Name)}
function LabRowStreamKey($Row){$name=@();$p=$Row.PSObject.Properties['stream_name_utf16'];if($null-ne$p){$name=@($p.Value)};return (LabObjectStreamKey $Row.object_index $name)}
function GetLabIndex([string]$Name,$Rows,[scriptblock]$Key){
 if($script:labIndexes.ContainsKey($Name)){return ,$script:labIndexes[$Name]}
 $index=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
 foreach($row in $Rows){Need ($null-ne$row) ('Null index row: '+$Name);$value=& $Key $row;Need ($value-is[string]-and-not$index.ContainsKey($value)) ('Duplicate or invalid exact index key: '+$Name);$index.Add($value,$row)}
 $script:labIndexes.Add($Name,$index);return ,$index
}
function LabIndexMatch($Index,[string]$Key){if($Index.ContainsKey($Key)){return $Index[$Key]}}
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
function LabSnapshotQuery($Snapshot,[int]$Class,[int]$Length){$q=@($Snapshot.queries|Where-Object class -eq $Class);Need ($q.Count-eq1-and$null-eq$q[0].native_error-and@($q[0].bytes).Count-eq$Length) 'Current timestamp proof query missing/refused.';return ,[byte[]]$q[0].bytes}
function LabSnapshotTimes($Snapshot){$b=LabSnapshotQuery $Snapshot 0 40;return ,@([BitConverter]::ToUInt64($b,0),[BitConverter]::ToUInt64($b,8),[BitConverter]::ToUInt64($b,16),[BitConverter]::ToUInt64($b,24))}
function Idle{$tasks=@(Get-ScheduledTask -ErrorAction Stop);$processes=@(Get-CimInstance Win32_Process -ErrorAction Stop);Need (@($tasks|Where-Object {$_.TaskName -like 'N2R-*' -and $_.TaskName -cne $c.task -and $_.State.ToString() -notin @('Ready','Disabled')}).Count -eq 0 -and @($processes|Where-Object {$_.Name -match '\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count -eq 0) 'Another project task/process is active or unknown.'}
function Protected{$g=Get-Disk -Number 4 -ErrorAction Stop;$gp=Get-Partition -DriveLetter G -ErrorAction Stop;$gv=$gp|Get-Volume -ErrorAction Stop;$old=Get-Disk -Number 5 -ErrorAction Stop;Need ([guid]$g.Guid -eq [guid]'e1f3b9d3-979f-4123-9fee-399640c25092' -and -not $g.IsOffline -and -not $g.IsReadOnly -and $gp.DiskNumber -eq 4 -and $gv.FileSystem -ceq 'ReFS' -and $gv.AllocationUnitSize -eq 4096 -and [guid]$old.Guid -eq [guid]'ad077674-6305-4767-a2aa-6ded3b707e36' -and $old.IsOffline -and $old.IsReadOnly) 'Preserved G4/shadow5 differs.'}
function Log([string]$Path){$m=Get-Item -LiteralPath $Path -Force;Need ($m.Length-le8MB) 'Bounded native log required.';@{bytes=$m.Length;sha256=(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant();text=[IO.File]::ReadAllText($Path)}}
function Native([string]$Name,[string[]]$Cli,[string]$Role,[int]$Expected,[bool]$Yes=$false){$p=$null;$script:lastExit=$null;$binary=Join-Path $c.stage $Name;$tool=@($c.tools|Where-Object name -CEQ $Name);if($tool.Count -ne 1 -or (Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant() -cne $tool[0].sha256){throw 'Native executable pin differs.'};$arguments=($Cli|ForEach-Object {if($_ -cmatch '["\r\n\x00]'){throw 'Unsafe native argument.'};$tail=$_.Length-$_.TrimEnd('\').Length;'"'+$_+('\'*$tail)+'"'}) -join ' ';$stdout=Join-Path $c.stage ($Role+'.stdout.log');$stderr=Join-Path $c.stage ($Role+'.stderr.log');Save ($Role+'-dispatch-intent.json') @{binary=$binary;binary_sha256=$tool[0].sha256;argv=$Cli;expected_exit=$Expected;utc=[DateTime]::UtcNow.ToString('o')};try{$start=@{FilePath=$binary;ArgumentList=$arguments};if($Yes){$stdin=Join-Path $c.stage ($Role+'.stdin.txt');[IO.File]::WriteAllText($stdin,"yes`r`n",[Text.Encoding]::ASCII);$start.RedirectStandardInput=$stdin};$p=Start-Process @start -WorkingDirectory $c.stage -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden;$null=$p.Handle;Save ($Role+'-process.json') @{pid=$p.Id;creation_ms=([DateTimeOffset]$p.StartTime).ToUnixTimeMilliseconds();parent_pid=$PID;binary=$binary;binary_sha256=$tool[0].sha256;argv=$Cli;expected_exit=$Expected;process_handle_retained_before_wait=$true;utc=[DateTime]::UtcNow.ToString('o')};$p.WaitForExit();$p.Refresh();$script:lastExit=$p.ExitCode;Save ($Role+'-terminal.json') @{pid=$p.Id;creation_ms=([DateTimeOffset]$p.StartTime).ToUnixTimeMilliseconds();native_exit=$script:lastExit;native_exit_observed=($null -ne $script:lastExit);expected_exit=$Expected;stdout=(Log $stdout);stderr=(Log $stderr);utc=[DateTime]::UtcNow.ToString('o')};if($null -eq $script:lastExit -or $script:lastExit -ne $Expected){throw ($Role+' actual native exit '+$script:lastExit+' expected '+$Expected)}}finally{if($null -ne $p){$p.Dispose()}}}
function SourceRoute([bool]$Online){$d=Get-Disk -Number 1;$p=Get-Partition -DiskNumber 1 -PartitionNumber 2;Need ([guid]$d.Guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'-and$d.Size-eq64GB-and-not$d.IsBoot-and-not$d.IsSystem-and[guid]$p.Guid-eq[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-and$p.Offset-eq16MB-and$p.Size-eq52GB-and(Get-Partition -DriveLetter C).DiskNumber-eq0) 'Exact F1 source route differs.';if($Online){$v=$p|Get-Volume;Need (-not$d.IsOffline-and-not$d.IsReadOnly-and'F:\'-in@($p.AccessPaths)-and$v.FileSystem-ceq'NTFS'-and$v.AllocationUnitSize-eq65536-and$v.FileSystemLabel-ceq'n2r-stream-source') 'Restored grown NTFS64K source required.'}else{Need ($d.IsOffline-and-not$d.IsReadOnly) 'Interrupted persistent offline source required.'}}
function AssertFrozenRootMetadata($Expected,[string]$Records,$Completion){
 $roots=@($Expected.objects|Where-Object {$_.directory-and@($_.path).Count-eq0});Need ($roots.Count-eq1-and$roots[0].record_number-eq5) 'One canonical NTFS root identity required.';$o=$roots[0]
 $basis=Json (Join-Path $Records 'qualification\source-basis.json');$native=Json (Join-Path $Records 'qualification\native-source.json');$assessment=Json (Join-Path $Records 'qualification\source-assessment.json')
 $raw=@($basis.ntfs.files|Where-Object {$_.record_number-eq$o.record_number-and$_.sequence_number-eq$o.sequence_number});$files=@($native.files|Where-Object {$_.identity.record_number-eq$o.record_number-and$_.identity.sequence_number-eq$o.sequence_number});$views=@($assessment.assessment.source_view.objects|Where-Object {$_.record_number-eq$o.record_number-and$_.sequence_number-eq$o.sequence_number})
 Need ($raw.Count-eq1-and$files.Count-eq1-and$null-eq$files[0].open_error-and$views.Count-eq1-and$views[0].metadata.matched-eq$true) 'Actual frozen source-root metadata evidence missing.'
 $si=$raw[0].standard_information;$times=@($si.creation_time,$si.access_time,$si.modification_time,$si.mft_change_time);Need (SameArray $times $o.stored_times) 'Canonical root times differ from actual frozen STANDARD_INFORMATION.'
 $before=LabSnapshotTimes $files[0].before;$after=LabSnapshotTimes $files[0].after;$v=$views[0].timestamps
 Need ($null-ne$v-and(SameArray $v.stored $times)-and(SameArray $v.native_before $before)-and(SameArray $v.native_after $after)-and$v.preservation_authority-ceq'persisted STANDARD_INFORMATION after freeze; requires actual unchanged read-only source') 'Frozen root cached/stored timestamp provenance differs.'
 foreach($index in @(0,2,3)){Need ($before[$index]-eq$times[$index]-and$after[$index]-eq$times[$index]) 'Source-root create/modify/MFT-change time must remain exact.'}
 $targetBefore=$null;$targetAfter=$null
 if($null-ne$Completion){$target=@($Completion.native.native.objects|Where-Object {@($_.components).Count-eq0});Need ($Completion.success-eq$true-and$target.Count-eq1) 'Recovered target root observation missing.';$targetBefore=LabSnapshotTimes $target[0].before;$targetAfter=LabSnapshotTimes $target[0].after;Need ((SameArray $targetBefore $times)-and(SameArray $targetAfter $times)) 'Recovered root metadata times differ from actual current frozen expectation.'}
 return @{scope='lab-current-frozen-root-timestamp-binding-v1';record_number=$o.record_number;sequence_number=$o.sequence_number;stored_times=$times;frozen_native_before=$before;frozen_native_after=$after;source_metadata_matched=$true;target_before=$targetBefore;target_after=$targetAfter;target_timestamp_comparison_performed=($null-ne$Completion);root_modified_or_mft_change_times_masked=$false;post_rollback_timestamps_claimed=$false}
}
function AssertEnvelopeJournalFacts($Expected,$Request,$Plan,$Ticket,$Maps,[string]$Records){
 $oldZeroEncoding=AssertLabOldZeroEncoding $Plan $Records $null;if($oldZeroEncoding.enabled){Save 'old-zero-encoding-verification.json' $oldZeroEncoding}
 Need ($Plan.max_journal_bytes-eq$Request.max_journal_bytes-and$Request.max_journal_bytes-eq16GB-and$Ticket.journal_length-gt0-and$Ticket.journal_length-le$Request.max_journal_bytes-and$Ticket.selected_bytes-gt0-and$Ticket.whole_image_verified-eq$false-and$Ticket.range_count-eq@($Plan.ranges).Count-and$Maps.schema_version-eq1-and$Maps.kind-ceq'protected-target-stream-map-facts-v1'-and$Maps.expected_tree_sha256-ceq(Get-FileHash -LiteralPath (Join-Path $Records 'expectation.json')).Hash.ToLowerInvariant()-and(SameJsonValue $Maps.source $Request.pair.source)-and$Maps.selected_bytes-eq$Ticket.selected_bytes-and$Maps.range_count-eq$Ticket.range_count-and(SameArray $Maps.new_selected_sha256 $Ticket.new_selected_sha256)-and@($Maps.bindings).Count-eq1084-and$Maps.grants_write_authority-eq$false-and$Maps.initial_retained_content_digests_available-eq$false) 'Pinned selected journal/profile/capacity or recovery-map associations differ.'
 $hash=[Security.Cryptography.SHA256]::Create();try{foreach($entry in @(@{value=$Plan;expected=$Maps.plan_sha256},@{value=$Ticket;expected=$Maps.ticket_sha256})){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($entry.value|ConvertTo-Json -Depth 64 -Compress));$digest=([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant();Need ($digest-ceq$entry.expected) 'Recovery map canonical plan/ticket hash differs.'}}finally{$hash.Dispose()}
}

function ReconcilePreparedBaselineAccess($Current,$Old,$Context){
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
function AssertPreparedFullBaseline($Expected,$Request,[string]$Records){
 $fresh=ReadFreshLabSourceBaselineGuest $Request.pair.source;$baseline=$fresh.expected
 $context=@{raw=(Json (Join-Path $Records 'qualification\source-basis.json'));native=(Json (Join-Path $Records 'qualification\native-source.json'));views=(Json (Join-Path $Records 'qualification\source-assessment.json'));compare_target=$false;completion=$null}
 $copy=($Expected|ConvertTo-Json -Depth 64)|ConvertFrom-Json;$old=@($baseline.objects);Need (@($copy.objects).Count-eq1084-and$old.Count-eq1084) 'Exact complete grown canonical tree coverage required.'
 $lookup=GetLabIndex 'prepared.baseline.objects' $old {param($o) LabRecordKey $o.record_number $o.sequence_number};$changed=[Collections.Generic.List[object]]::new();$unread=0
 foreach($o in $copy.objects){$matches=@(LabIndexMatch $lookup (LabRecordKey $o.record_number $o.sequence_number));Need ($matches.Count-eq1-and(SameArray $matches[0].path $o.path)) 'Prepared full baseline canonical identity/path differs.';$reference=$matches[0];$time=ReconcilePreparedBaselineAccess $o $reference $context;if($null-ne$time){$changed.Add($time);$o.stored_times[1]=$reference.stored_times[1]};if($o.directory){continue};Need ($reference.sha256-cmatch'\A[0-9a-f]{32}\z') 'Actual full raw/native baseline content digest missing.';if($null-eq$o.sha256){$null=LabExtentEvidenceShape $o;$o.sha256=$reference.sha256;$o.PSObject.Properties.Remove('source_evidence');$unread++}}
 Need ($unread-eq654-and(SameJsonValue $copy $baseline)) 'Prepared canonical tree differs from actual fresh full baseline beyond explicit unread evidence and recorded source access times.'
 Save 'prepared-full-baseline-binding.json' @{scope='lab-current-prepared-tree-vs-fresh-full-baseline-v1';manifest_sha256=$c.fresh_manifest_sha256;objects=1084;streams=811;extent_only_streams=$unread;source_access_time_reconciliations=$changed.ToArray();all_other_canonical_metadata_exact=$true;root_modified_or_mft_change_times_masked=$false;product_expectation_changed=$false;grants_product_authority=$false}
}
function ObserveRollbackCanonicalShape($Expected){
 $rows=[Collections.Generic.List[object]]::new();$files=0;$directories=0
 foreach($o in $Expected.objects){foreach($component in $o.path){Need ($component-is[string]-and$component.Length-gt0-and$component-notin@('.','..')-and$component.IndexOfAny([char[]]'\/:')-lt0) 'Ordinary canonical path component required.'};$path='F:\'+($o.path-join'\');$item=Get-Item -LiteralPath $path -Force;Need (-not($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-and[bool]$item.PSIsContainer-eq[bool]$o.directory) 'Actual post-rollback canonical path/type differs.';if($o.directory){$directories++}else{Need ($item.Length-eq$o.length) 'Post-rollback logical length differs.';$files++};$rows.Add(@{path=@($o.path);directory=[bool]$o.directory;length=$(if($o.directory){$null}else{[long]$item.Length})})}
 Need ($files-eq811-and$directories-eq273-and$rows.Count-eq1084) 'Observed post-rollback canonical shape count differs.'
 return @{scope='lab-post-rollback-known-canonical-paths-types-and-lengths-v1';objects=$rows.Count;files=$files;directories=$directories;rows=$rows.ToArray();independent_stream_maps_observed=$false;independent_timestamps_compared=$false;unknown_namespace_entries_enumerated=$false;permissions_changed=$false}
}

function AssertEnvelopePrepared($Expected,$Request,[string]$Records){
 $basis=Json (Join-Path $Records 'qualification\source-basis.json');$native=Json (Join-Path $Records 'qualification\native-source.json')
 $descriptor=AssertLabV3Envelope $Request.source_resource_profile $basis $Expected $native (Join-Path $Records 'expectation.json') (Join-Path $Records 'qualification\source-basis.json') (Join-Path $Records 'qualification\native-source.json')
 Need ($descriptor.objects-eq1084-and$descriptor.files-eq811-and$descriptor.directories-eq273-and$descriptor.data_streams-eq811-and$Request.schema_version-eq3-and$Request.verification_policy-ceq'extent_identity_v1'-and$Request.max_journal_bytes-eq16GB-and$Request.max_literal_backing_bytes-eq256MB-and$Request.max_combined_scratch_bytes-eq18GB-and$Request.verify_existing_shadow-eq$false-and$native.schema_version-eq12-and$native.request.schema_version-eq4) 'Actual admitted V3 object/count/native/capacity scope differs.'
 $unread=@($Expected.objects|Where-Object {-not$_.directory-and$null-eq$_.sha256});Need ($unread.Count-eq654) 'Expected exact654 unread streams.'
 $tails=AssertLabTailReceipts $Expected $Records;Need ($tails.tail_extent_only_streams-eq650) 'Expected exact650 constructor-bound materialized tails.'
 $fresh=ReadFreshLabSourceBaselineGuest $Request.pair.source
 AssertPreparedFullBaseline $Expected $Request $Records
 $rootMetadata=AssertFrozenRootMetadata $Expected $Records $null;Save 'prepared-root-metadata.json' $rootMetadata
 Save 'object-envelope-verification.json' @{scope='lab-v3-fault-prepared-evidence-v1';actual=$descriptor;unread_streams=$unread.Count;tail_streams=$tails.tail_extent_only_streams;fresh_full_baseline_manifest_sha256=$c.fresh_manifest_sha256;full_and_fast_raw_pins_equated=$false;grants_product_authority=$false}
 return $tails
}
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
 if(-not$c.baseline_enabled){Need ($hashless-eq0) 'Hashless expectations require a separately pinned historical full-content lab baseline.';return @{enabled=$false;observer_expectation=$Expected;product_expectation=$Expected;receipt=@{scope='lab-fresh-full-source-recovery-baseline-v1';baseline_used=$false;hashless_product_streams=0;product_expectation_written=$false;grants_product_authority=$false}}}
 $fresh=ReadFreshLabSourceBaselineGuest $Request.pair.source
 $baseline=$fresh.expected;$oldBasis=$fresh.basis
 Need (SameJsonValue $fresh.manifest.source_binding $Request.pair.source) 'Fresh full baseline route differs.'
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
   if($null-eq$current.sha256){$shape=LabExtentEvidenceShape $current;$elisions.Add(@{record_number=$object.record_number;sequence_number=$object.sequence_number;path=$object.path;name_utf16=@($name);length=$current.length;source_evidence=$shape.source_evidence;retained_prefix_bytes=$shape.prefix_bytes;tail_offset=$shape.tail_offset;tail_bytes=$shape.tail_bytes;independent_expected_content_digest=$known.sha256});$current.sha256=$known.sha256;$current.PSObject.Properties.Remove('source_evidence')}
   else{Need ($null-eq$evidence) 'A complete digest must not also claim extent-only source evidence.'}
  }
 }
 Need (SameJsonValue $copy $baseline) 'Canonical baseline differs beyond explicit extent evidence, absent digests and separately recorded access times.'
 $newNative=$null # Recovery does not grant fresh source admission from a historical report.
 return @{enabled=$true;observer_expectation=$copy;product_expectation=$Expected;baseline=$baseline;baseline_basis=$oldBasis;baseline_raw_by_identity=$oldRaw;native_source=$newNative;receipt=@{scope='lab-fresh-full-source-recovery-baseline-v1';baseline_used=$true;baseline_sha256=$c.baseline_sha256;baseline_request_sha256=$c.baseline_request_sha256;baseline_result_sha256=$c.baseline_result_sha256;baseline_source_basis_sha256=$c.baseline_basis_sha256;canonical_metadata_exact_except_explicit_content_evidence=($timeRows.Count-eq0);canonical_metadata_exact_except_content_evidence_and_recorded_access_times=$true;current_access_time_reconciliations=$timeRows.ToArray();timestamp_provenance_pins=@{source_basis=(Get-FileHash -LiteralPath (Join-Path $Records 'qualification\source-basis.json')).Hash.ToLowerInvariant();native_source=(Get-FileHash -LiteralPath (Join-Path $Records 'qualification\native-source.json')).Hash.ToLowerInvariant();source_assessment=(Get-FileHash -LiteralPath (Join-Path $Records 'qualification\source-assessment.json')).Hash.ToLowerInvariant();expectation=(Get-FileHash -LiteralPath (Join-Path $Records 'expectation.json')).Hash.ToLowerInvariant();recovery_result=(Get-FileHash -LiteralPath (Join-Path $RecoveryRecords 'result.json')).Hash.ToLowerInvariant();recovery_completion=(Get-FileHash -LiteralPath (Join-Path $RecoveryRecords 'completion.json')).Hash.ToLowerInvariant()};post_rollback_native_timestamp_comparison_claimed=$false;fresh_actual_raw_native_digests_bound=$true;historical_digests_claimed_as_fresh=$false;fresh_manifest_sha256=$c.fresh_manifest_sha256;source_binding_identical=$true;hashless_product_streams=$hashless;comparison_streams_restored=$elisions.Count;comparison_only_clone=$true;product_expectation_written=$false;grants_product_authority=$false;elided_streams=$elisions.ToArray()}}
}
try{
    Idle;Protected;$d=Get-Disk -Number 1;Need ([guid]$d.Guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'-and$d.IsOffline-and-not$d.IsReadOnly) 'Interrupted activated source1 (offline, writable attributes) required.'
    $part=Get-Partition -DiskNumber 1 -PartitionNumber 2;Need ($env:SystemDrive-ceq'C:'-and$d.Size-eq64GB-and-not$d.IsBoot-and-not$d.IsSystem-and[guid]$part.Guid-eq[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-and$part.Offset-eq16MB-and$part.Size-eq52GB-and(Get-Partition -DriveLetter C).DiskNumber-eq0) 'Interrupted exact F GPT/geometry or C journal route differs.'
    $binary=Join-Path $c.stage 'ntfs2refs.exe';Need ((Get-Item -LiteralPath $binary).Length-eq$c.binary_bytes-and(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()-ceq$c.binary_sha256) 'Pinned public main differs.'
    $bundlePath=Join-Path $c.recovery_directory 'allocation-recovery-bundle.json';$bundle=Json $bundlePath 65536
    Need ((Get-FileHash -LiteralPath $bundlePath).Hash.ToLowerInvariant()-ceq$c.recovery_sha256-and$bundle.schema_version-eq1-and$bundle.kind-ceq'allocation-bounded-recovery-bundle'-and$bundle.serialized_bundle_grants_recovery_authority-eq$false) 'Pinned allocation recovery bundle differs.'
    $request=Json (Join-Path $c.recovery_directory 'request.json') 131072;$mapPath=Join-Path $c.recovery_directory 'recovery-payload-manifest.json';$maps=Json $mapPath 64MB
    Need ($request.schema_version-eq3-and$request.verification_policy-ceq'extent_identity_v1'-and$request.pair.source.disk_number-eq1-and[guid]$request.pair.source.identity.disk_guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'-and[guid]$request.pair.source.identity.partition_guid-eq[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-and$request.pair.source.identity.disk_bytes-eq64GB-and$request.pair.source.identity.partition_bytes-eq52GB-and$request.pair.source.identity.partition_offset-eq16MB-and$null-ne$bundle.recovery_payload_manifest-and$bundle.recovery_payload_manifest.path-ceq$mapPath-and$bundle.recovery_payload_manifest.sha256-ceq(Get-FileHash -LiteralPath $mapPath).Hash.ToLowerInvariant()-and$maps.kind-ceq'protected-target-stream-map-facts-v1'-and$maps.grants_write_authority-eq$false) 'Pinned F source or hash-free recovery manifest differs.'
    foreach($spec in @(@{key='request';name='request.json';limit=131072},@{key='plan';name='selected-plan.json';limit=16MB},@{key='ticket';name='selected-ticket.json';limit=65536},@{key='verification';name='verification.json';limit=1MB})){ $path=Join-Path $c.recovery_directory $spec.name;$null=Json $path $spec.limit;Need ($bundle.($spec.key).path-ceq$path-and$bundle.($spec.key).sha256-ceq(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()) 'Original bundle metadata pin differs.' }
    $origin=Split-Path -Parent $c.recovery_directory
    $normalObservation=Join-Path $origin 'wrapper-controlled-interruption.json'
    $originalProcess=Json (Join-Path $origin 'converter-process.json');$originalTerminal=Json (Join-Path $origin 'converter-terminal.json')
    $interruption=Json $normalObservation
    Need ($interruption.controlled_interruption_observed-eq$true-and$interruption.native_exit-eq86-and$interruption.bundle_sha256-ceq$c.recovery_sha256-and$originalProcess.pid-gt0-and$originalProcess.creation_ms-gt0-and$originalTerminal.pid-eq$originalProcess.pid-and$originalTerminal.creation_ms-eq$originalProcess.creation_ms-and$originalTerminal.native_exit-eq86-and$originalTerminal.native_exit_observed-eq$true) 'Actual original native process/exit86 publication missing.'
    Need ($interruption.source_disk-eq1-and$interruption.source_offline-eq$true-and$interruption.source_readonly-eq$false-and$interruption.shadow_offline-eq$true-and$interruption.shadow_readonly-eq$true) 'Actual86 source/shadow exclusion receipt differs.'
    # The actual86 producer needed its shadow, but allocation recovery is
    # self-contained in the pinned metadata and journal. A cold boot may detach
    # the dynamic VHDX; never reattach it or rewrite the historical request.
    Need ((SameJsonValue $interruption.managed_binding $request.pair.shadow)-and$interruption.managed_shadow_path-ceq(Join-Path $origin 'managed-shadow\shadow.vhdx')) 'Historical86 managed-shadow identity/path differs from the pinned request.'
    $diskInventory=@(Get-Disk -ErrorAction Stop);Need ($diskInventory.Count-gt0) 'Complete current disk inventory required; provider errors are not absence.'
    $shadowMatches=@(foreach($disk in $diskInventory){$guid=[guid]::Empty;if([guid]::TryParse([string]$disk.Guid,[ref]$guid)-and$guid-eq[guid]$request.pair.shadow.identity.disk_guid){$disk}})
    Need ($shadowMatches.Count-le1) 'Duplicate current shadow GPT identity refused.'
    $shadowObservation=@{scope='lab-allocation-recovery-optional-current-shadow-v1';historical_native86_shadow_offline=$interruption.shadow_offline;historical_native86_shadow_readonly=$interruption.shadow_readonly;pinned_binding=$request.pair.shadow;shadow_present=($shadowMatches.Count-eq1);current_disk_number=$null;current_provider=$null;reattachment_performed=$false;request_rebound=$false;public_recovery_requires_shadow=$false;grants_replay_authority=$false}
    if($shadowMatches.Count-eq1){
        $shadow=$shadowMatches[0];$identity=$request.pair.shadow.identity
        Need ($shadow.PartitionStyle.ToString()-ceq'GPT'-and$shadow.Size-eq$identity.disk_bytes-and$shadow.LogicalSectorSize-eq$identity.logical_sector_bytes-and$shadow.PhysicalSectorSize-eq$identity.physical_sector_bytes-and-not$shadow.IsBoot-and-not$shadow.IsSystem-and$shadow.IsOffline-and$shadow.IsReadOnly) 'Present managed shadow GPT/geometry/protection differs.'
        $partitions=@(Get-Partition -DiskNumber $shadow.Number -ErrorAction Stop);$shadowPartitions=@($partitions|Where-Object {$_.PartitionNumber-eq$identity.partition_number-and[guid]$_.Guid-eq[guid]$identity.partition_guid})
        Need ($shadowPartitions.Count-eq1-and$shadowPartitions[0].Offset-eq$identity.partition_offset-and$shadowPartitions[0].Size-eq$identity.partition_bytes) 'Present managed shadow partition identity/range differs.'
        $image=Get-DiskImage -ImagePath $interruption.managed_shadow_path -ErrorAction Stop
        Need ($image.Attached-eq$true-and[string]::Equals([string]$image.ImagePath,[string]$interruption.managed_shadow_path,[StringComparison]::OrdinalIgnoreCase)-and[string]::Equals([string]$image.DevicePath,('\\.\PhysicalDrive'+$shadow.Number),[StringComparison]::OrdinalIgnoreCase)) 'Present managed shadow image provider is not the original VHDX route.'
        $shadowObservation.current_disk_number=[int]$shadow.Number;$shadowObservation.current_provider=@{image_path=$image.ImagePath;device_path=$image.DevicePath;attached=$image.Attached;storage_type=$image.StorageType;disk_guid=[string]$shadow.Guid;offline=$shadow.IsOffline;readonly=$shadow.IsReadOnly;partition_guid=[string]$shadowPartitions[0].Guid}
    }
    Save 'current-shadow-observation.json' $shadowObservation
    $plan=Json (Join-Path $c.recovery_directory 'selected-plan.json') 16MB;$ticket=Json (Join-Path $c.recovery_directory 'selected-ticket.json') 65536
    Need ($plan.max_journal_bytes-eq$request.max_journal_bytes-and$request.max_journal_bytes-eq16GB-and$ticket.journal_length-le$request.max_journal_bytes-and$ticket.journal_length-gt0-and$ticket.selected_bytes-gt0-and$ticket.whole_image_verified-eq$false) 'Pinned capacity and selected ticket disagree; recovery never resizes from free space.'
    $expectationPath=Join-Path $c.recovery_directory 'expectation.json'
    Need ($bundle.expectation.path-ceq$expectationPath-and$bundle.expectation.sha256-cmatch'\A[0-9a-f]{64}\z') 'Bundle expectation route or pin differs.'
    $expected=Json $expectationPath 64MB;$expectationPin=(Get-FileHash -LiteralPath $expectationPath).Hash.ToLowerInvariant()
    Need ($expectationPin-ceq$bundle.expectation.sha256-and@($expected.objects).Count-gt0) 'Pinned nonempty recovery expectation required.'
    $expectedObjects=@($expected.objects);$expectedFiles=@($expectedObjects|Where-Object {-not$_.directory})
    $expectedPaths=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($object in $expectedObjects){Need ($expectedPaths.Add(($object.path-join'\'))) 'Duplicate expected recovery object path.'}
    $fresh=ReadFreshLabSourceBaselineGuest $request.pair.source;Save 'fresh-baseline-preflight.json' @{success=$true;manifest_sha256=$c.fresh_manifest_sha256;descriptor=$fresh.descriptor;grants_product_authority=$false}
    AssertEnvelopeJournalFacts $expected $request $plan $ticket $maps $c.recovery_directory
    $faultPath=Join-Path $c.recovery_directory 'fresh-exclusive-fault-path.json';$fault=Json $faultPath 1MB;$producer=@($c.tools|Where-Object name -CEQ 'lab-convert-native-composite.exe')[0]
    $legacyFault=$fault.schema_version-eq1-and$fault.preparation_completed-ceq'prepare_exclusive'-and$fault.apply_entrypoint_requested-ceq'apply_and_handoff_exclusive'
    $ownedFault=$fault.schema_version-eq2-and$fault.preparation_completed-ceq'prepare_exclusive_owned'-and$fault.apply_entrypoint_requested-ceq'PreparedExclusiveJournal::apply_and_handoff'-and$fault.prepared_journal_owner_reused-eq$true
    Need (($legacyFault-or$ownedFault)-and$fault.requested_flushed_payload_writes-eq1-and$fault.controlled_exit_code-eq86-and$fault.hnd_allowed_if_interruption_not_reached-eq$false-and$fault.source_writes_started-eq$false-and$fault.diagnostic_only-eq$true-and$fault.execution_authorized-eq$false-and$fault.replay_authorized-eq$false) 'Pinned producer diagnostic version or requested barrier differs; this grants no replay authority.'
    Need ($originalProcess.binary_sha256-ceq$producer.sha256-and$originalProcess.process_handle_retained_before_wait-eq$true-and$originalProcess.expected_exit-eq86-and'--fresh-exclusive-v3-first-write'-cin@($originalProcess.argv)-and$interruption.run_id-ceq$request.experiment_id-and$interruption.actual_fresh_exclusive_fault_path_sha256-ceq(Get-FileHash -LiteralPath $faultPath).Hash.ToLowerInvariant()-and$fault.recovery_bundle_sha256-ceq$c.recovery_sha256-and$fault.kind-ceq'lab-fresh-exclusive-v3-first-write-path'-and(SameJsonValue $fault.source_resource_profile $request.source_resource_profile)) 'Exact runtime/actual86/diagnostic-to-bundle association differs.'
    $preparedTailScope=AssertEnvelopePrepared $expected $request $c.recovery_directory;Save 'prepared-tail-verification.json' $preparedTailScope
    Save 'wrapper-worker.json' @{pid=$PID;creation_ms=([DateTimeOffset](Get-Process -Id $PID).StartTime).ToUnixTimeMilliseconds();run_id=$c.run_id;utc=[DateTime]::UtcNow.ToString('o')}
    $phase='public-recovery';Native 'ntfs2refs.exe' $c.cli 'native' 0 $true;$nativeExit=$script:lastExit;$out=Log (Join-Path $c.stage 'native.stdout.log')
    $phase='closed-recovery-evidence';$expectedLine=if($c.operation-ceq'rollback'){'NTFS rollback completed[.]'}else{'ReFS recovery completed[.]'}
    $done=[regex]::Matches($out.text,'(?m)^'+$expectedLine+' Recovery records: (C:\\ProgramData\\ntfs2refs\\runs\\recovery-[0-9a-f]{32})[ \t]*\r?$');Need ($done.Count-eq1) 'One actual completion line for the requested direction required.'
    $records=Join-Path $done[0].Groups[1].Value $c.operation;$result=Json (Join-Path $records 'result.json');$completion=Json (Join-Path $records 'completion.json') 64MB
    $oldZeroActual=AssertLabOldZeroEncoding $plan $c.recovery_directory $result;if($oldZeroActual.enabled){Save 'recovery-old-zero-encoding-verification.json' $oldZeroActual}
    $v=Get-Volume -DriveLetter F;$d=Get-Disk -Number 1
    if($c.operation-ceq'rollback'){
        Need ($result.success-eq$true-and$result.outcome-ceq'ntfs_restored'-and$completion.mounted_filesystem-ceq'NTFS'-and$v.FileSystem-ceq'NTFS'-and$v.AllocationUnitSize-eq65536-and$v.FileSystemLabel-ceq'n2r-stream-source'-and-not$d.IsOffline) 'Restored NTFS source/label/online state differs.'
        $rollbackProof=Json (Join-Path $records 'rollback.json');$originalTicket=Json (Join-Path $c.recovery_directory 'selected-ticket.json') 65536
        Need ($rollbackProof.replay_closed-eq$true-and$rollbackProof.whole_image_verified-eq$false-and$rollbackProof.selected_bytes-eq$originalTicket.selected_bytes-and$rollbackProof.range_count-eq$originalTicket.range_count-and(SameArray $rollbackProof.selected_sha256 $originalTicket.old_selected_sha256)) 'Actual closed rollback journal proof differs from the pinned old selected digest.'
        $shape=ObserveRollbackCanonicalShape $expected;Save 'rollback-canonical-shape.json' $shape
        $summary=@{mounted='NTFS';observed_canonical_objects=$shape.objects;observed_canonical_files=$shape.files;observed_canonical_directories=$shape.directories;objects=$null;post_mount_data_maps_observed=$false;post_rollback_timestamp_comparison_claimed=$false;hashes=$null;expected_objects=$expectedObjects.Count;expected_files=$expectedFiles.Count;post_mount_content_hashes_checked=$false;closed_selected_journal_proof=(Get-FileHash -LiteralPath (Join-Path $records 'rollback.json')).Hash.ToLowerInvariant()}

    }else{
        Need ($result.success-eq$true-and$result.outcome-ceq'refs_completed'-and$completion.success-eq$true-and$completion.rollback_closed-eq$true-and$v.FileSystem-ceq'ReFS'-and$v.AllocationUnitSize-eq4096-and$v.FileSystemLabel-ceq'n2r-stream-source'-and-not$d.IsOffline) 'Recovered ReFS source/label/online state differs.'
        $objects=@($completion.native.native.objects);Need ($objects.Count-eq$expectedObjects.Count) 'Recovered native object count differs.';$known=0;$unknown=0;$knownBytes=0L
        foreach($object in $expectedObjects){$matches=@($objects|Where-Object {SameArray $_.components $object.path});Need ($matches.Count-eq1) 'Expected recovered path missing/duplicated.';$native=$matches[0]
            if(-not$object.directory){if($null-ne$object.sha256){Need ($native.logical_sha256-ceq$object.sha256) 'Known recovered default digest differs.';$known++;$knownBytes+=[long]$object.length}else{Need ($null-eq$native.logical_sha256) 'Unread default content must not report a content hash.';$null=LabExtentEvidenceShape $object;$unknown++}}
            $ns=$object.PSObject.Properties['named_streams'];if($null-ne$ns){foreach($stream in $ns.Value){$found=@($native.named_streams|Where-Object {SameArray $_.name_utf16 $stream.name_utf16});Need ($found.Count-eq1) 'Recovered ADS missing/duplicated.';if($null-ne$stream.sha256){Need ($found[0].logical_sha256-ceq$stream.sha256) 'Known recovered ADS digest differs.';$known++;$knownBytes+=[long]$stream.length}else{Need ($null-eq$found[0].logical_sha256) 'Unread ADS must not report a content hash.';$null=LabExtentEvidenceShape $stream;$unknown++}}}
        }
        $extentPath=Join-Path $records 'recovery-extent-verification.json';$receipt=Json $extentPath 1MB;AssertLabTailCounter $receipt 'extent_only_partial_streams' $preparedTailScope.tail_extent_only_streams;AssertLabTailCounter $receipt 'extent_only_partial_tail_bytes' $preparedTailScope.materialized_tail_bytes;$handoff=Json (Join-Path $records 'handoff.json')
        Need ($result.actual_verification_scope-ceq'pinned_extent_identity_v1'-and$result.full_content_hashes_compared-eq$false-and$result.original_unread_content_digest_reconstructed-eq$false-and$receipt.all_complete_maps_identical-eq$true-and$receipt.handoff_replay_closed-eq$true-and$receipt.known_content_streams_hashed-eq$known-and$receipt.known_content_payload_bytes_read-eq$knownBytes-and$receipt.extent_only_streams-eq$unknown-and$unknown-gt0-and$handoff.replay_closed-eq$true-and([BitConverter]::ToString([byte[]]$handoff.selected_sha256)).Replace('-','').ToLowerInvariant()-ceq$receipt.selected_sha256) 'Actual closed journal/map-facts/known-content recovery receipt differs.'
        $summary=@{mounted='ReFS';objects=$objects.Count;known_content_hashes=$known;known_content_bytes=$knownBytes;extent_only_streams=$unknown;all_complete_maps_identical=$true;full_content_hashes_compared=$false;closed_selected_journal_proof=(Get-FileHash -LiteralPath (Join-Path $records 'handoff.json')).Hash.ToLowerInvariant()}
    }
    if($c.operation-ceq'resume'){$rootMetadata=AssertFrozenRootMetadata $expected $c.recovery_directory $completion;Save 'recovered-root-metadata.json' $rootMetadata}
    Protected;Idle
    $baselineContext=ResolveLabContentBaseline $expected $request $c.recovery_directory $completion $records;$labExpected=$baselineContext.observer_expectation;Save 'lab-baseline-binding.json' $baselineContext.receipt
    $paths=[Collections.Generic.List[string]]::new();$wants=[Collections.Generic.List[string]]::new();$names=[Collections.Generic.List[object]]::new();$backup=[Collections.Generic.List[bool]]::new()
    foreach($object in $labExpected.objects){if($object.directory){continue};$compression=$object.PSObject.Properties['ntfs_compression_normalized'];$useBackup=-not($c.operation-ceq'rollback'-and$null-ne$compression-and$compression.Value-eq$true);$base='F:\'+($object.path-join'\');$paths.Add($base);$wants.Add($object.sha256);$backup.Add($useBackup);$names.Add(@{path=$object.path;name_utf16=@();length=$object.length});$property=$object.PSObject.Properties['named_streams'];if($null-ne$property){foreach($stream in $property.Value){$chars=[char[]]@($stream.name_utf16|ForEach-Object {[char]$_});$paths.Add($base+':'+[string]::new($chars)+':$DATA');$wants.Add($stream.sha256);$backup.Add($useBackup);$names.Add(@{path=$object.path;name_utf16=$stream.name_utf16;length=$stream.length})}}}
    Need ($paths.Count-eq811) 'Bounded independent all-stream baseline required.'
    
    $actual=[string[]]::new($paths.Count);$batches=[Collections.Generic.List[object]]::new();$batch=[Collections.Generic.List[int]]::new();$chars=32
    for($i=0;$i-lt$paths.Count;$i++){Need ($backup[$i]-eq$true) 'Grown source contains no compressed normalization requiring a different observer.';$cost=$paths[$i].Length+3;if($batch.Count-gt0-and($chars+$cost)-ge28000){$batches.Add($batch.ToArray());$batch=[Collections.Generic.List[int]]::new();$chars=32};$batch.Add($i);$chars+=$cost};if($batch.Count){$batches.Add($batch.ToArray())}
    for($batchNumber=0;$batchNumber-lt$batches.Count;$batchNumber++){$indices=$batches[$batchNumber];$argv=@('--backup-read');foreach($index in $indices){$argv+=$paths[$index]};$role='independent-content-'+$batchNumber;Native 'lab-content-digest.exe' $argv $role 0;$part=@([IO.File]::ReadAllText((Join-Path $c.stage ($role+'.stdout.log')))|ConvertFrom-Json|ForEach-Object {$_});Need ($part.Count-eq$indices.Count) 'Independent observer batch stream count differs.';for($i=0;$i-lt$indices.Count;$i++){$actual[$indices[$i]]=$part[$i]}}
    for($i=0;$i-lt$actual.Count;$i++){Need ($wants[$i]-cmatch'\A[0-9a-f]{32}\z'-and$actual[$i]-ceq$wants[$i]) ('Independent complete stream digest differs at ordinal '+$i)}
    Save 'independent-content-verification.json' @{success=$true;scope='lab-only-independent-full-content-baseline-v1';baseline_sha256=$c.baseline_sha256;streams=$actual.Count;rows=$names.ToArray();digests=$actual;hash_algorithm='xxh3-128';product_expectation_written=$false;grants_product_authority=$false}
    $summary['independent_full_stream_hashes']=$actual.Count;$summary['post_mount_content_hashes_checked']=$true;Protected;Idle
    Save 'wrapper-result.json' @{schema_version=1;kind='extent-identity-public-recovery-observation';prepared_extent_tail_verification=$preparedTailScope;minimum_tail_extent_only_streams=$c.minimum_tail_extent_only_streams;success=$true;run_id=$c.run_id;operation=$c.operation;native_exit=$nativeExit;recovery_records=$records;observed_lifecycle=$result.observed_lifecycle;action=$result.action;outcome=$result.outcome;summary=$summary;expectation_path=$expectationPath;expectation_sha256=$expectationPin;expectation_is_evidence_not_replay_authority=$true;result_sha256=(Get-FileHash -LiteralPath (Join-Path $records 'result.json')).Hash.ToLowerInvariant();completion_sha256=(Get-FileHash -LiteralPath (Join-Path $records 'completion.json')).Hash.ToLowerInvariant();utc=[DateTime]::UtcNow.ToString('o')}
}catch{Save 'wrapper-failed.json' @{success=$false;run_id=$c.run_id;phase=$phase;native_exit=$nativeExit;error=$_.Exception.ToString();automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')};throw}
finally{foreach($entry in $script:closedJsonCache.Values){$entry.stream.Dispose()};$script:closedJsonCache.Clear()}
'@
 $body=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'SourceBaselineSupport.ps1'))+"`r`n"+$body
 $body=$body.Replace('__CONFIG__',[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes(($c|ConvertTo-Json -Depth 20 -Compress))))
 $wrapper=Join-Path $root 'guest-wrapper.ps1';[IO.File]::WriteAllText($wrapper,$body,[Text.UTF8Encoding]::new($false));$wrapperPin=(Get-FileHash -LiteralPath $wrapper).Hash.ToLowerInvariant()
 $session=New-PSSession -VMId $id -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml'))
 $ready=Invoke-Command -Session $session -ArgumentList $stage,$task,$operation -ScriptBlock {param($Stage,$Task,$Operation)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  if($env:COMPUTERNAME-cne'N2R-WIN11'-or(Test-Path -LiteralPath $Stage)-or@(Get-ScheduledTask|Where-Object TaskName -CEQ $Task).Count-or@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-or@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count){throw 'Fresh idle owning guest required.'}
  $d=Get-Disk -Number 1;$p=Get-Partition -DiskNumber 1 -PartitionNumber 2
  if([guid]$d.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or$d.Size-ne64GB-or$d.IsBoot-or$d.IsSystem-or[guid]$p.Guid-ne[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-or$p.Offset-ne16MB-or$p.Size-ne52GB-or(Get-Partition -DriveLetter C).DiskNumber-ne0){throw 'Exact F source GPT/geometry and OS0 journal route required.'}
  if($Operation-ceq'interrupt'){$v=$p|Get-Volume;if($d.IsOffline-or$d.IsReadOnly-or$v.FileSystem-cne'NTFS'-or$v.AllocationUnitSize-ne65536-or$v.FileSystemLabel-cne'n2r-stream-source'-or@(Get-Disk).Count-ne6-or@(Get-Disk|Where-Object Number -ge 6).Count){throw 'Restored grown source F1/NTFS64K and old managed6 absent required.'}}else{if(-not$d.IsOffline-or$d.IsReadOnly){throw 'Interrupted source must be offline writable.'}}
  $a=Get-Item -LiteralPath 'C:\ntfs2refs';while($null-ne$a){if($a.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse stage ancestry.'};$a=$a.Parent};New-Item -ItemType Directory -Path $Stage|Out-Null;@{source_disk=1;source_offline=$d.IsOffline;source_readonly=$d.IsReadOnly;utc=[DateTime]::UtcNow.ToString('o')}
 };Save 'ready.json' $ready
 foreach($tool in $tools){Copy-Item -LiteralPath $tool.path -ToSession $session -Destination (Join-Path $stage $tool.name)}
 foreach($key in $baseline.files.Keys){$entry=$baseline.files[$key];Copy-Item -LiteralPath $entry.path -ToSession $session -Destination (Join-Path $stage $entry.name)}

 Copy-Item -LiteralPath $wrapper -ToSession $session -Destination (Join-Path $stage 'wrapper.ps1');HostGuard
 Save 'dispatch.json' @{schema_version=1;kind=('object-envelope-'+$operation+'-dispatch');run_id=$run;vm_id=$id;parent_id=$ExpectedParent;checkpoint_ids=$ids;task_name=$task;guest_stage=$stage;output_dir=$c.output;wrapper_sha256=$wrapperPin;source_commit=$SourceCommit;tools=$tools;configuration=$c;expected_exit=0;completion_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')}
 $configJson=$c|ConvertTo-Json -Depth 20 -Compress
 Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin,$configJson -ScriptBlock {param($Stage,$Task,$Pin,$ConfigJson)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$c=$ConfigJson|ConvertFrom-Json;$path=Join-Path $Stage 'wrapper.ps1'
  if((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$Pin-or@(Get-ScheduledTask|Where-Object TaskName -CEQ $Task).Count){throw 'Fresh pinned SYSTEM task required.'}
  foreach($t in $c.tools){$p=Join-Path $Stage $t.name;if((Get-Item -LiteralPath $p).Length-ne$t.bytes-or(Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()-cne$t.sha256){throw 'Staged tool pin differs.'}}
  foreach($property in $c.fresh_baseline_files.PSObject.Properties){$v=$property.Value;$p=Join-Path $Stage $v.name;if((Get-Item -LiteralPath $p).Length-ne$v.bytes-or(Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()-cne$v.sha256){throw 'Prelaunch baseline pin differs.'}}
  if($c.operation-ceq'interrupt'){$p=Join-Path $Stage 'routing-request.json';if((Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()-cne$c.source_request_sha256){throw 'Routing seed pin differs.'}}
  Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'"')) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
 }
 HostGuard;Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration $configuration) -AdditionalBytes $ForecastAdditionalBytes
 Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin -ScriptBlock {param($Stage,$Task,$Pin)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskName $Task;$i=$t|Get-ScheduledTaskInfo;$path=Join-Path $Stage 'wrapper.ps1'
  if($t.State.ToString()-cne'Ready'-or$i.LastRunTime.Year-ge2000-or@($t.Actions).Count-ne1-or$t.Actions[0].Execute-cne"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"-or$t.Actions[0].Arguments-cne('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'"')-or$t.Principal.UserId-notin@('SYSTEM','S-1-5-18')-or$t.Principal.RunLevel.ToString()-cne'Highest'-or(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$Pin-or@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count){throw 'Only the untouched recorded SYSTEM task may start once.'};Start-ScheduledTask -TaskName $Task
 };Save 'start.json' @{start_issued_once=$true;expected_exit=0;completion_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')};Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw
}catch{if($created-and-not(Test-Path -LiteralPath (Join-Path $root 'dispatch-failed.json'))){Save 'dispatch-failed.json' @{success=$false;run_id=$run;error=$_.Exception.ToString();automatic_retry=$false;worker_termination_inferred=$false}};throw}
finally{if($null-ne$session){Remove-PSSession $session -ErrorAction SilentlyContinue};if($null-ne$baseline-and$baseline.ContainsKey('held_streams')){foreach($stream in $baseline.held_streams){$stream.Dispose()}};foreach($stream in $hostHeld){$stream.Dispose()}}
