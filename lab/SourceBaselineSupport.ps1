# Function-only lab support. Host readers never control a VM or source disk.
# Guest readers verify full fresh evidence; no profile or metadata masks exist.
function FreshBaselineOrdinary([string]$Path,[long]$Maximum){
 $full=[IO.Path]::GetFullPath($Path);Need ($full-ceq$Path) 'Absolute fresh baseline path required.';$f=Get-Item -LiteralPath $full -Force
 Need (-not$f.PSIsContainer-and$f.Length-gt0-and$f.Length-le$Maximum) 'Bounded fresh baseline file required.';$a=$f
 while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Fresh baseline reparse ancestry refused.';if($a-is[IO.DirectoryInfo]){$a=$a.Parent}else{$a=$a.Directory}}
 return $f
}
function OpenFreshBaselineHost([string]$Path,[string]$Sha256,[long]$Maximum,$Handles,[bool]$Parse){
 $item=FreshBaselineOrdinary $Path $Maximum;$stream=$null;$reader=$null;$hash=$null
 try{$stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);Need ($stream.Length-eq$item.Length-and$stream.Length-le$Maximum) 'Opened fresh metadata length differs.';$hash=[Security.Cryptography.SHA256]::Create();$actual=([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-','').ToLowerInvariant();Need ($actual-ceq$Sha256) 'Held fresh metadata SHA differs.';$stream.Position=0;$value=$null;if($Parse){$reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false),$true,4096,$true);$value=$reader.ReadToEnd()|ConvertFrom-Json};$Handles.Add($stream);$stream=$null;return @{item=$item;value=$value}}
 finally{if($null-ne$reader){$reader.Dispose()};if($null-ne$hash){$hash.Dispose()};if($null-ne$stream){$stream.Dispose()}}
}
function ReadFreshLabSourceBaselineHost([string]$Path,[string]$Sha256,[string]$GrowthPath,[string]$GrowthSha256,[guid]$Parent,[string]$LabBase){
 $held=[Collections.Generic.List[IO.FileStream]]::new()
 try{
 Need ($Sha256-cmatch'\A[0-9a-f]{64}\z'-and$GrowthSha256-cmatch'\A[0-9a-f]{64}\z') 'Fresh manifest and growth checksum pairs required.'
 Need ($Path.StartsWith($LabBase+'\',[StringComparison]::OrdinalIgnoreCase)-and$GrowthPath.StartsWith($LabBase+'\',[StringComparison]::OrdinalIgnoreCase)) 'Fresh baseline inputs must remain under the lab root.'
 $mh=OpenFreshBaselineHost $Path $Sha256 1MB $held $true;$gh=OpenFreshBaselineHost $GrowthPath $GrowthSha256 64MB $held $true;$file=$mh.item;$growthFile=$gh.item;$m=$mh.value;$g=$gh.value
 Need ($Parent-ne[guid]::Empty-and$Parent-ne[guid]'6fe2d6b6-a2fb-447e-802b-7b3ff0d9f16e'-and[guid]$m.source_checkpoint-eq$Parent-and$m.schema_version-eq1-and$m.kind-ceq'lab-full-source-content-baseline-v1'-and$m.success-eq$true-and$m.source_admitted-eq$false-and$m.certificate_issued-eq$false-and$m.conversion_authorized-eq$false-and$m.replay_authorized-eq$false-and$m.source_payload_writes-eq0-and$m.extent_moves-eq0-and$m.full_image_sha256_computed-eq$false-and$m.actual_raw_logical_passes-eq1-and$m.actual_native_content_passes-eq1-and$m.actual_fresh_stream_hashes_matched-eq811-and$m.original808_content_matches_historical_actual_xxh3-eq$true-and$m.historical_fixture_sha256_rehashed-eq$false-and$m.files-eq811-and$m.directories-gt256-and$m.objects-eq($m.files+$m.directories)-and$m.objects-le1280) 'Complete lab-only fresh source baseline required.'
 Need ($m.original_fixture.sha256-ceq'7810754f1853490d399f87bf1b24f509a8c32716cee84d38babc7c385a487f66'-and$m.historical_full_content_reference.sha256-ceq'30bd09d24bd43ba42029db003e5ab357f50eaa8d554b8bfd750acc39fcd0d629'-and$m.directory_growth_receipt.sha256-ceq$GrowthSha256-and$g.schema_version-eq1-and$g.kind-ceq'ntfs-directory-object-envelope-fixture'-and$g.success-eq$true-and[guid]$g.source_parent_checkpoint-eq[guid]'6fe2d6b6-a2fb-447e-802b-7b3ff0d9f16e'-and$g.created_directories-eq151-and$g.created_payload_files-eq0-and$g.originals_verified-eq808-and$g.original_payload_writes-eq0-and$g.original_payload_bytes_read-eq0-and$g.extent_moves-eq0) 'Original corpus content reference and exact metadata-only growth must be pinned.'
 Need ($m.source_binding.disk_number-eq1-and$m.source_binding.identity.partition_number-eq2-and[guid]$m.source_binding.identity.disk_guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'-and[guid]$m.source_binding.identity.partition_guid-eq[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-and$m.source_binding.identity.partition_bytes-eq52GB-and$m.source_before.disk_attributes-eq3-and$m.source_after.disk_attributes-eq3) 'Actual frozen mixed source route required.'
 $names=@{'expectation.json'=@{key='expectation';name='lab-full-content-baseline.json'};'source-basis.json'=@{key='basis';name='lab-baseline-source-basis.json'};'native-source.json'=@{key='native';name='lab-fresh-native-source.json'};'source-views.json'=@{key='views';name='lab-fresh-source-views.json'};'independent-content.json'=@{key='content';name='lab-fresh-independent-content.json'};'strict-comparison.json'=@{key='strict';name='lab-fresh-strict-comparison.json'};'observation-events.json'=@{key='events';name='lab-fresh-observation-events.json'}}
 Need (@($m.artifacts.PSObject.Properties).Count-eq$names.Count) 'Fresh source artifact inventory must be complete and exact.'
 $answer=@{enabled=$true;fresh=$true;files=@{};sha256='';request_sha256='';result_sha256='';basis_sha256='';provenance=$null};$total=0L
 foreach($name in $names.Keys){$pin=$m.artifacts.PSObject.Properties[$name];Need ($null-ne$pin-and$pin.Value.sha256-cmatch'\A[0-9a-f]{64}\z'-and[IO.Path]::GetFileName([string]$pin.Value.path)-ceq$name) 'Fresh producer artifact pin missing or redirected.';$p=Join-Path $file.DirectoryName $name;$opened=OpenFreshBaselineHost $p $pin.Value.sha256 64MB $held $false;$f=$opened.item;Need ($f.Length-eq$pin.Value.bytes) 'Fresh artifact bytes differ.';$spec=$names[$name];$answer.files[$spec.key]=@{path=$p;bytes=$f.Length;sha256=$pin.Value.sha256;name=$spec.name};$total+=$f.Length}
 Need ($total+$file.Length+$growthFile.Length-le256MB) 'Fresh baseline metadata exceeds combined budget.'
 $answer.files.manifest=@{path=$Path;bytes=$file.Length;sha256=$Sha256;name='lab-fresh-baseline-manifest.json'};$answer.files.growth=@{path=$GrowthPath;bytes=$growthFile.Length;sha256=$GrowthSha256;name='lab-directory-growth.json'}
 $answer.sha256=$answer.files.expectation.sha256;$answer.basis_sha256=$answer.files.basis.sha256
 $answer.provenance=@{scope='fresh-full-frozen-source-content-baseline-v1';manifest_path=$Path;manifest_sha256=$Sha256;expected_source_checkpoint=$Parent.ToString('D');expectation_sha256=$answer.sha256;directory_growth_sha256=$GrowthSha256;source_binding=$m.source_binding;default_content_hashes=811;named_content_hashes=0;source_admitted=$false;conversion_authorized=$false;replay_authorized=$false;historical_reference_used_for_808_content_only=$true;metadata=$answer.files}
 $answer.held_streams=$held.ToArray()
 return $answer
 }catch{foreach($stream in $held){$stream.Dispose()};throw}
}

function LabV3Descriptor($Profile){
 Need ($null-ne$Profile-and$Profile-is[pscustomobject]) 'Explicit V3 resource profile object required.';$p=$Profile.PSObject.Properties['experimental_object_envelope_v3']
 Need ($null-ne$p-and@($Profile.PSObject.Properties).Count-eq1-and$null-ne$p.Value) 'Admitted Some V3 descriptor required; planning None is not evidence.'
 return $p.Value
}
function AssertLabV3Envelope($Profile,$Basis,$Expected,$Native,[string]$ExpectedPath,[string]$BasisPath,[string]$NativePath){
 $a=LabV3Descriptor $Profile
 foreach($name in @('schema_version','raw_identities','files','directories','data_streams','object_slots','raw_identity_slots','data_stream_slots','maximum_expected_tree_bytes','maximum_inspection_bytes','maximum_native_report_bytes','projected_owned_handle_slots','maximum_owned_handle_slots','maximum_constructor_input_metadata_bytes')){$null=LabIntegerKey $a.$name}
 $files=@($Expected.objects|Where-Object {-not$_.directory}).Count;$dirs=@($Expected.objects|Where-Object {$_.directory}).Count;$streams=$files
 foreach($o in $Expected.objects){$p=$o.PSObject.Properties['named_streams'];if($null-ne$p){$streams+=@($p.Value).Count}}
 $units=@($a.source_inspection_sha256);Need ($units.Count-eq32-and@($units|Where-Object {$_-lt0-or$_-gt255}).Count-eq0) 'Exact 32-byte V3 inspection pin required.';$pin=([BitConverter]::ToString([byte[]]$units)).Replace('-','').ToLowerInvariant()
 Need ($a.schema_version-eq1-and$a.raw_identities-eq@($Basis.ntfs.files).Count-and$a.files-eq$files-and$a.directories-eq$dirs-and$a.data_streams-eq$streams-and$files+$dirs-eq@($Expected.objects).Count-and$files+$dirs-le$a.object_slots-and$a.object_slots-le1280-and$a.object_slots-gt0-and$a.raw_identities-le$a.raw_identity_slots-and$a.raw_identity_slots-le2048-and$a.raw_identity_slots-gt0-and$a.data_streams-le$a.data_stream_slots-and$a.data_stream_slots-le16384-and$a.data_stream_slots-gt0-and$pin-ceq$Basis.canonical_inspection_sha256-and$pin-ceq$Native.request.source_inspection_sha256-and$a.raw_identities-eq@($Native.request.files).Count-and(SameJsonValue $Profile $Native.request.resource_profile)) 'Exact raw/native/canonical V3 counts or own-inventory pin differ.'
 Need ($a.maximum_expected_tree_bytes-gt0-and$a.maximum_expected_tree_bytes-le16MB-and(Get-Item -LiteralPath $ExpectedPath).Length-le$a.maximum_expected_tree_bytes-and$a.maximum_constructor_input_metadata_bytes-gt0-and$a.maximum_constructor_input_metadata_bytes-le16MB-and$a.maximum_inspection_bytes-gt0-and$a.maximum_inspection_bytes-le64MB-and(Get-Item -LiteralPath $BasisPath).Length-le$a.maximum_inspection_bytes-and$a.maximum_native_report_bytes-gt0-and$a.maximum_native_report_bytes-le64MB-and(Get-Item -LiteralPath $NativePath).Length-le$a.maximum_native_report_bytes-and$a.projected_owned_handle_slots-eq($files+$dirs+2*$streams+8)-and$a.projected_owned_handle_slots-le$a.maximum_owned_handle_slots-and$a.maximum_owned_handle_slots-le34056) 'Pinned V3 byte or projected owning-handle ceiling differs.'
 return @{raw_identities=$a.raw_identities;files=$files;directories=$dirs;data_streams=$streams;objects=$files+$dirs;source_inspection_sha256=$pin;descriptor=$a;constructor_metadata_measurement_claimed=$false}
}
function ReadFreshLabSourceBaselineGuest($SourceBinding){
 if($null-ne$script:labFreshBaseline){Need (SameJsonValue $script:labFreshBaseline.manifest.source_binding $SourceBinding) 'Cached held fresh source binding differs.';return $script:labFreshBaseline}
 $copyBindings=[Collections.Generic.List[object]]::new()
 foreach($p in $c.fresh_baseline_files.PSObject.Properties){$v=$p.Value;$path=Join-Path $c.stage $v.name;$null=Json $path;Need ((Get-Item -LiteralPath $path).Length-eq$v.bytes-and(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-ceq$v.sha256) 'Pinned fresh lab baseline artifact differs.';$copyBindings.Add(@{role=$p.Name;actual_copied_path=$path;bytes=$v.bytes;sha256=$v.sha256})}
 $m=Json (Join-Path $c.stage 'lab-fresh-baseline-manifest.json');$g=Json (Join-Path $c.stage 'lab-directory-growth.json');$e=Json (Join-Path $c.stage 'lab-full-content-baseline.json');$b=Json (Join-Path $c.stage 'lab-baseline-source-basis.json');$n=Json (Join-Path $c.stage 'lab-fresh-native-source.json');$v=Json (Join-Path $c.stage 'lab-fresh-source-views.json');$proof=Json (Join-Path $c.stage 'lab-fresh-independent-content.json')
 $extentProperty=$n.request.PSObject.Properties['extent_identity_streams'];Need ($null-eq$extentProperty-or@($extentProperty.Value).Count-eq0) 'Full native source evidence must not request read elision.'
 Need ($m.kind-ceq'lab-full-source-content-baseline-v1'-and$m.success-eq$true-and$m.source_admitted-eq$false-and$m.certificate_issued-eq$false-and$m.conversion_authorized-eq$false-and$m.replay_authorized-eq$false-and$m.source_payload_writes-eq0-and$m.extent_moves-eq0-and$m.source_checkpoint-ceq$c.fresh_source_checkpoint-and(SameJsonValue $m.source_binding $SourceBinding)-and(SameJsonValue $m.source_binding $g.source.binding)-and$m.source_before.disk_attributes-eq3-and$m.source_after.disk_attributes-eq3-and$m.actual_raw_logical_passes-eq1-and$m.actual_native_content_passes-eq1-and$n.content_passes-eq1-and$n.schema_version-eq11-and$n.request.schema_version-eq3-and$v.all_user_views_compatible-eq$true-and$proof.success-eq$true-and$proof.streams-eq811-and$proof.actual_raw_logical_passes-eq1-and$proof.actual_native_content_passes-eq1-and$proof.original_fixture_files_matched-eq808-and$proof.fresh_sha256_of_original_files_claimed-eq$false) 'Actual complete frozen full-source baseline scope differs.'
 $descriptor=AssertLabV3Envelope $m.source_resource_profile $b $e $n (Join-Path $c.stage 'lab-full-content-baseline.json') (Join-Path $c.stage 'lab-baseline-source-basis.json') (Join-Path $c.stage 'lab-fresh-native-source.json')
 Need ($e.profile-ceq'native-ordinary-tree-shadow-object-envelope-v3'-and$descriptor.directories-gt256-and$descriptor.files-eq811-and$descriptor.data_streams-eq811-and$descriptor.objects-eq$m.objects-and@($g.created_paths).Count-eq151) 'Fresh grown source must exceed the historical directory split.'
 $nativeFiles=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
 foreach($file in $n.logical_data.files){$key=LabRecordKey $file.identity.record_number $file.identity.sequence_number;Need (-not$nativeFiles.ContainsKey($key)) 'Duplicate full native source identity.';$nativeFiles.Add($key,$file)}
 $count=0
 foreach($object in $e.objects){if($object.directory){continue};$key=LabRecordKey $object.record_number $object.sequence_number;Need ($nativeFiles.ContainsKey($key)) 'Full source native identity missing.';$streams=[Collections.Generic.List[object]]::new();$streams.Add(@{name=@();value=$object});$named=$object.PSObject.Properties['named_streams'];if($null-ne$named){foreach($s in $named.Value){$streams.Add(@{name=@($s.name_utf16);value=$s})}};foreach($entry in $streams){Need ($entry.value.sha256-cmatch'\A[0-9a-f]{32}\z'-and$null-eq$entry.value.PSObject.Properties['source_evidence']) 'Fresh baseline must retain every actual raw content digest.';$matches=@($nativeFiles[$key].before|Where-Object {SameArray $_.name_utf16 $entry.name});Need ($matches.Count-eq1-and$matches[0].logical_size-eq$entry.value.length-and$matches[0].outcome.status-ceq'complete'-and$matches[0].outcome.bytes_read-eq$entry.value.length-and$matches[0].outcome.eof_confirmed-eq$true-and$matches[0].outcome.sha256-ceq$entry.value.sha256) 'One actual native full hash/EOF must match each fresh raw stream.';$count++}}
 Need ($count-eq811) 'Fresh full source stream coverage differs.'
 $script:labFreshBaseline=@{expected=$e;basis=$b;manifest=$m;descriptor=$descriptor;copied_artifact_bindings=$copyBindings.ToArray()};return $script:labFreshBaseline
}
function AssertLabV3CurrentDevices($Devices,$Expected,[string]$Records){
 $planning=$Devices.source_resource_profile.PSObject.Properties['experimental_object_envelope_v3'];Need ($null-ne$planning-and$null-eq$planning.Value-and@($Devices.source_resource_profile.PSObject.Properties).Count-eq1) 'Public devices must retain the explicit V3 planning None intent.'
 $request=Json (Join-Path $Records 'request.json');$basis=Json (Join-Path $Records 'qualification\source-basis.json');$native=Json (Join-Path $Records 'qualification\native-source.json')
 $actual=AssertLabV3Envelope $request.source_resource_profile $basis $Expected $native (Join-Path $Records 'expectation.json') (Join-Path $Records 'qualification\source-basis.json') (Join-Path $Records 'qualification\native-source.json')
 Need ($actual.directories-gt256-and$native.schema_version-eq12-and$native.request.schema_version-eq4-and$request.schema_version-eq3-and$request.verification_policy-ceq'extent_identity_v1'-and$request.verify_existing_shadow-eq$false) 'Actual V3 must be admitted fresh fast allocation, beyond the old directory split.'
 Save 'object-envelope-verification.json' @{scope='lab-exact-v3-object-envelope-v1';actual=$actual;planning_none_is_not_recovery_authority=$true;product_expectation_changed=$false;grants_product_authority=$false}
 return $true
}

function ResolveFreshLabContentBaseline($Expected,$Request,[string]$Records){
 $hashless=0;foreach($object in $Expected.objects){if(-not$object.directory-and$null-eq$object.sha256){$hashless++};$property=$object.PSObject.Properties['named_streams'];if($null-ne$property){foreach($stream in $property.Value){if($null-eq$stream.sha256){$hashless++}}}}
 if(-not$c.baseline_enabled){Need ($hashless-eq0) 'Hashless expectations require a separately pinned historical full-content lab baseline.';return @{enabled=$false;observer_expectation=$Expected;product_expectation=$Expected;receipt=@{scope='lab-content-baseline-v1';baseline_used=$false;hashless_product_streams=0;product_expectation_written=$false;grants_product_authority=$false}}}
 $fresh=ReadFreshLabSourceBaselineGuest $Request.pair.source
 $baseline=$fresh.expected;$oldBasis=$fresh.basis
 Need (SameJsonValue $fresh.manifest.source_binding $Request.pair.source) 'Fresh baseline source binding differs.'
 $oldRaw=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
 foreach($file in $oldBasis.ntfs.files){$key=([string]$file.record_number)+':'+([string]$file.sequence_number);Need (-not$oldRaw.ContainsKey($key)) 'Duplicate historical raw source identity.';$oldRaw.Add($key,$file)}
 $timeContext=@{raw=(Json (Join-Path $Records 'qualification\source-basis.json'));native=(Json (Join-Path $Records 'qualification\native-source.json'));views=(Json (Join-Path $Records 'qualification\source-assessment.json'));final=(Json (Join-Path $Records 'finalization.json'))};$timeRows=[Collections.Generic.List[object]]::new();$copy=($Expected|ConvertTo-Json -Depth 64)|ConvertFrom-Json;$oldObjects=@($baseline.objects);Need (@($copy.objects).Count-eq$oldObjects.Count) 'Independent baseline canonical object coverage differs.';$elisions=[Collections.Generic.List[object]]::new()
 $oldObjectIndex=GetLabIndex 'baseline.object.records' $oldObjects {param($r) LabRecordKey $r.record_number $r.sequence_number}
 foreach($object in $copy.objects){
  $matches=@(LabIndexMatch $oldObjectIndex (LabRecordKey $object.record_number $object.sequence_number));Need ($matches.Count-eq1-and$matches[0].record_number-eq$object.record_number-and$matches[0].sequence_number-eq$object.sequence_number-and(SameArray $matches[0].path $object.path)) 'Independent baseline canonical identity/path differs.';$old=$matches[0];$timeProof=ReconcileLabAccessTime $object $old $timeContext;if($null-ne$timeProof){$timeRows.Add($timeProof);$object.stored_times[1]=$old.stored_times[1]}
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
 Need (SameJsonValue $copy $baseline) 'Canonical baseline differs beyond explicit extent evidence and absent content digests; every identity, path, stream, map and metadata field must match.'
 $newNative=Json (Join-Path $Records 'qualification\native-source.json')
 $answer=@{enabled=$true;observer_expectation=$copy;product_expectation=$Expected;baseline=$baseline;baseline_basis=$oldBasis;baseline_raw_by_identity=$oldRaw;native_source=$newNative;receipt=@{scope='lab-content-baseline-v1';baseline_used=$true;baseline_sha256=$c.baseline_sha256;baseline_request_sha256=$c.baseline_request_sha256;baseline_result_sha256=$c.baseline_result_sha256;baseline_source_basis_sha256=$c.baseline_basis_sha256;canonical_metadata_exact_except_explicit_content_evidence=($timeRows.Count-eq0);canonical_metadata_exact_except_content_evidence_and_recorded_access_times=$true;current_access_time_reconciliations=$timeRows.ToArray();access_time_reconciliation_pins=@{source_basis=(Get-FileHash -LiteralPath (Join-Path $Records 'qualification\source-basis.json') -Algorithm SHA256).Hash.ToLowerInvariant();native_source=(Get-FileHash -LiteralPath (Join-Path $Records 'qualification\native-source.json') -Algorithm SHA256).Hash.ToLowerInvariant();source_assessment=(Get-FileHash -LiteralPath (Join-Path $Records 'qualification\source-assessment.json') -Algorithm SHA256).Hash.ToLowerInvariant();expectation=(Get-FileHash -LiteralPath (Join-Path $Records 'expectation.json') -Algorithm SHA256).Hash.ToLowerInvariant();finalization=(Get-FileHash -LiteralPath (Join-Path $Records 'finalization.json') -Algorithm SHA256).Hash.ToLowerInvariant()};historical_digests_bound_to_full_raw_inspection=$true;source_binding_identical=$true;hashless_product_streams=$hashless;comparison_streams_restored=$elisions.Count;comparison_only_clone=$true;product_expectation_written=$false;grants_product_authority=$false;elided_streams=$elisions.ToArray()}}
 $answer.receipt.scope='lab-fresh-full-source-content-baseline-binding-v1'
 $answer.receipt.historical_digests_bound_to_full_raw_inspection=$false
 $answer.receipt.fresh_digests_bound_to_actual_full_raw_and_native_reads=$true
 $answer.receipt.fresh_manifest_sha256=$c.fresh_manifest_sha256
 $answer.receipt.copied_artifact_bindings=$fresh.copied_artifact_bindings
 $answer.receipt.original_manifest_paths_preserved=$true
 $answer.receipt.full_source_descriptor=$fresh.descriptor
 $answer.receipt.product_source_descriptor=LabV3Descriptor $Request.source_resource_profile
 $answer.receipt.full_raw_inspection_sha256=$fresh.manifest.source_inspection_sha256
 $answer.receipt.current_fast_raw_inspection_sha256=$timeContext.raw.canonical_inspection_sha256
 $answer.receipt.different_raw_evidence_pins_equated=$false
 $answer.receipt.root_modified_or_mft_change_times_masked=$false
 $answer.receipt.original_reference_used_for_808_content_only=$true
 return $answer
}
