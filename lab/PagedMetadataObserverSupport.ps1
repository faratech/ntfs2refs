# Function-only support for the current public paged-metadata observer.
# The independently pinned native inspector opens metadata files only.
function Hold-PagedObserverFile([string]$Path,[string]$Pin,[long]$Maximum){
 Need ($Path.StartsWith('C:\',[StringComparison]::OrdinalIgnoreCase)-and$Path-cnotmatch'["\r\n]'-and$Pin-cmatch'\A[0-9a-f]{64}\z') 'Ordinary pinned C metadata required.'
 $m=Get-Item -LiteralPath $Path -Force
 Need (-not$m.PSIsContainer-and$m.Length-gt0-and$m.Length-le$Maximum-and-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Bounded ordinary paged metadata required.'
 $a=$m.Directory;while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Paged metadata reparse ancestry refused.';$a=$a.Parent}
 $stream=[IO.File]::Open($Path,'Open','Read','Read');$hash=[Security.Cryptography.SHA256]::Create();$added=$false
 try{Need ($stream.Length-eq$m.Length) 'Opened paged observer file length differs.';$actual=([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-','').ToLowerInvariant();Need ($actual-ceq$Pin) 'Held paged observer input SHA differs.';$stream.Position=0;$script:pagedMetadataHeld.Add($stream);$added=$true;return @{path=$Path;bytes=$stream.Length;sha256=$actual}}
 finally{$hash.Dispose();if(-not$added){$stream.Dispose()}}
}
function Get-PagedMetadataInspection([string]$Records){
 if($script:pagedInspectionCache.ContainsKey($Records)){return $script:pagedInspectionCache[$Records]}
 Need ($null-ne$nativeExit-and$nativeExit-eq0-and$null-ne$process-and$process.HasExited) 'Paged observer requires actual closed public native0.'
 $toolRows=@($c.tools|Where-Object name -CEQ 'lab-inspect-paged-metadata.exe')
 Need ($toolRows.Count-eq1) 'One independently pinned typed metadata inspector required.'
 $tool=Join-Path $c.stage $toolRows[0].name
 $null=Hold-PagedObserverFile $tool $toolRows[0].sha256 64MB
 Need ((Get-Item -LiteralPath $tool).Length-eq$toolRows[0].bytes) 'Typed metadata tool length differs.'
 $bundle=Json (Join-Path $Records 'allocation-recovery-bundle.json')
 $pairs=@(
  @{name='request';leaf='request.json';pin=$bundle.request.sha256},
  @{name='expectation';leaf='expectation.json';pin=$bundle.expectation.sha256},
  @{name='expected-pages';leaf='expectation.pages';pin=$bundle.expectation_pages.sha256},
  @{name='plan';leaf='selected-plan.json';pin=$bundle.plan.sha256},
  @{name='ticket';leaf='selected-ticket.json';pin=$bundle.ticket.sha256},
  @{name='payload-pages';leaf='recovery-payload-manifest.pages';pin=$bundle.recovery_payload_manifest.sha256}
 )
 $paths=@($bundle.request.path,$bundle.expectation.path,$bundle.expectation_pages.path,$bundle.plan.path,$bundle.ticket.path,$bundle.recovery_payload_manifest.path)
 $argv=[Collections.Generic.List[string]]::new();$inputPins=[Collections.Generic.List[object]]::new()
 for($i=0;$i-lt$pairs.Count;$i++){
  $pair=$pairs[$i];$path=Join-Path $Records $pair.leaf
  Need ($paths[$i]-ceq$path) 'Actual bundle metadata path differs from the closed run.'
  $inputPins.Add((Hold-PagedObserverFile $path $pair.pin 64MB))
  $argv.Add('--'+$pair.name);$argv.Add($path);$argv.Add('--'+$pair.name+'-sha256');$argv.Add([string]$pair.pin)
 }
 $stdout=Join-Path $c.stage 'paged-metadata-inspection.stdout.json';$stderr=Join-Path $c.stage 'paged-metadata-inspection.stderr.log'
 $start=[Diagnostics.ProcessStartInfo]::new();$start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.FileName=$tool;$start.WorkingDirectory=$c.stage
 $start.Arguments=(@($argv|ForEach-Object {'"'+$_+'"'})-join' ');$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 $child=[Diagnostics.Process]::new();$child.StartInfo=$start;$outStream=$null;$errStream=$null;$outPipe=$null;$errPipe=$null
 try{
  $outStream=[IO.File]::Open($stdout,'CreateNew','Write','Read');$errStream=[IO.File]::Open($stderr,'CreateNew','Write','Read')
  Need ($child.Start()) 'Typed metadata inspector did not return an owned child.'
  $null=$child.Handle;$birth=([DateTimeOffset]$child.StartTime).ToUnixTimeMilliseconds()
  $outPipe=$child.StandardOutput.BaseStream;$errPipe=$child.StandardError.BaseStream
  $outDrain=$outPipe.CopyToAsync($outStream,65536);$errDrain=$errPipe.CopyToAsync($errStream,65536)
  Save 'paged-metadata-inspection-process.json' @{pid=$child.Id;creation_ms=$birth;parent_pid=$PID;binary=$tool;binary_sha256=$toolRows[0].sha256;argv=$argv.ToArray();input_pins=$inputPins.ToArray();expected_exit=0;process_handle_retained_before_wait=$true;utc=[DateTime]::UtcNow.ToString('o')}
  $child.WaitForExit();$child.Refresh();$exit=$child.ExitCode
  $null=$outDrain.GetAwaiter().GetResult();$null=$errDrain.GetAwaiter().GetResult();$outStream.Flush($true);$errStream.Flush($true)
  $outStream.Dispose();$outStream=$null;$errStream.Dispose();$errStream=$null
  Need ((Get-Item -LiteralPath $stdout).Length-gt0-and(Get-Item -LiteralPath $stdout).Length-le4MB-and(Get-Item -LiteralPath $stderr).Length-le1MB) 'Bounded complete typed metadata logs required.'
  Save 'paged-metadata-inspection-terminal.json' @{pid=$child.Id;creation_ms=$birth;native_exit_observed=$true;native_exit=$exit;expected_exit=0;stdout_sha256=(Get-FileHash -LiteralPath $stdout).Hash.ToLowerInvariant();stderr_sha256=(Get-FileHash -LiteralPath $stderr).Hash.ToLowerInvariant();utc=[DateTime]::UtcNow.ToString('o')}
  Need ($exit-eq0) 'Typed complete metadata inspector failed; no retry or fallback.'
  $result=Json $stdout
  Need ($result.schema_version-eq1-and$result.kind-ceq'lab-paged-resource-metadata-verification'-and$result.success-eq$true-and$result.legacy_pretty_semantic_pin_reconstructed-eq$true-and$result.all_expected_objects_validated-eq$true-and$result.independent_metadata_volume_routes_checked-eq$true-and$result.ordinary_metadata_only-eq$true-and$result.source_device_opened-eq$false-and$result.raw_journal_opened-eq$false-and$result.converter_or_recovery_launched-eq$false-and$result.grants_source_admission-eq$false-and$result.grants_write_authority-eq$false-and$result.grants_replay_authority-eq$false) 'Actual typed metadata verification scope differs.'
  foreach($pair in $pairs){$property=$result.PSObject.Properties[($pair.name.Replace('-','_')+'_sha256')];Need ($null-ne$property-and$property.Value-ceq$pair.pin) 'Typed inspector input pin differs.'}
  $map=$result.complete_recovery_map_inspection
  Need ($map.schema_version-eq1-and$map.kind-ceq'read-only-pinned-recovery-map-pages-inspection'-and$map.complete_paged_and_expected_map_set_validated-eq$true-and$map.grants_write_authority-eq$false-and$map.source_device_opened-eq$false-and$map.journal_opened-eq$false) 'Complete typed recovery-map closure required.'
  $null=LabIntegerKey $map.bindings;Need ($map.records-eq($map.bindings+1)) 'Typed recovery map complete record count differs.'
  Save 'paged-metadata-verification.json' $result
  $script:pagedInspectionCache.Add($Records,$result);return $result
 }finally{foreach($stream in @($outPipe,$errPipe,$outStream,$errStream)){if($null-ne$stream){try{$stream.Dispose()}catch{}}};$child.Dispose()}
}
function AssertLabV3Envelope($Profile,$Basis,$Expected,$Native,[string]$ExpectedPath,[string]$BasisPath,[string]$NativePath){
 $a=LabV3Descriptor $Profile
 if($a.schema_version-eq1){return AssertLegacyLabV3Envelope $Profile $Basis $Expected $Native $ExpectedPath $BasisPath $NativePath}
 foreach($name in @('schema_version','raw_identities','files','directories','data_streams','object_slots','raw_identity_slots','data_stream_slots','maximum_expected_tree_bytes','maximum_inspection_bytes','maximum_native_report_bytes','projected_owned_handle_slots','maximum_owned_handle_slots','maximum_constructor_input_metadata_bytes')){$null=LabIntegerKey $a.$name}
 $files=@($Expected.objects|Where-Object {-not$_.directory}).Count;$dirs=@($Expected.objects|Where-Object {$_.directory}).Count;$streams=$files
 foreach($o in $Expected.objects){$p=$o.PSObject.Properties['named_streams'];if($null-ne$p){$streams+=@($p.Value).Count}}
 $units=@($a.source_inspection_sha256);Need ($units.Count-eq32-and@($units|Where-Object {$_-lt0-or$_-gt255}).Count-eq0) 'Exact 32-byte paged inspection pin required.'
 $pin=([BitConverter]::ToString([byte[]]$units)).Replace('-','').ToLowerInvariant();$objects=$files+$dirs
 $remaining=[long]$a.maximum_owned_handle_slots-2L*$streams-8L;$slots=[Math]::Min([long]$a.raw_identities,$remaining)
 Need ($a.schema_version-eq2-and$a.raw_identities-eq@($Basis.ntfs.files).Count-and$a.files-eq$files-and$a.directories-eq$dirs-and$a.data_streams-eq$streams-and$objects-eq@($Expected.objects).Count-and$objects-le$a.object_slots-and$a.object_slots-eq$slots-and$a.object_slots-gt0-and$a.object_slots-le2048-and$a.raw_identities-le$a.raw_identity_slots-and$a.raw_identity_slots-le2048-and$a.raw_identity_slots-gt0-and$a.data_streams-le$a.data_stream_slots-and$a.data_stream_slots-le16384-and$a.data_stream_slots-gt0-and$pin-ceq$Basis.canonical_inspection_sha256-and$pin-ceq$Native.request.source_inspection_sha256-and$a.raw_identities-eq@($Native.request.files).Count-and(SameJsonValue $Profile $Native.request.resource_profile)) 'Complete raw/native/canonical paged counts or inventory pin differ.'
 Need ($a.maximum_expected_tree_bytes-gt0-and$a.maximum_expected_tree_bytes-le16MB-and(Get-Item -LiteralPath $ExpectedPath).Length-le$a.maximum_expected_tree_bytes-and$a.maximum_constructor_input_metadata_bytes-gt0-and$a.maximum_constructor_input_metadata_bytes-le16MB-and$a.maximum_inspection_bytes-gt0-and$a.maximum_inspection_bytes-le64MB-and(Get-Item -LiteralPath $BasisPath).Length-le$a.maximum_inspection_bytes-and$a.maximum_native_report_bytes-gt0-and$a.maximum_native_report_bytes-le64MB-and(Get-Item -LiteralPath $NativePath).Length-le$a.maximum_native_report_bytes-and$a.projected_owned_handle_slots-eq($objects+2*$streams+8)-and$a.projected_owned_handle_slots-le$a.maximum_owned_handle_slots-and$a.maximum_owned_handle_slots-le34056) 'Pinned paged bytes or actual projected handle ceiling differs.'
 $inspection=Get-PagedMetadataInspection ([IO.Path]::GetDirectoryName($ExpectedPath))
 Need ((SameJsonValue $inspection.admission $a)-and$inspection.admitted_raw_identities-eq$a.raw_identities-and$inspection.raw_identity_guard_retained-eq2048-and$inspection.actual_expected_counts.objects-eq$objects-and$inspection.actual_expected_counts.files-eq$files-and$inspection.actual_expected_counts.directories-eq$dirs-and$inspection.actual_expected_counts.data_streams-eq$streams-and$inspection.semantic_byte_budget-eq$a.maximum_expected_tree_bytes-and(SameJsonValue $inspection.actual_expected_page_budget $a.paged_resources.expected_tree_pages)) 'Actual complete typed object/page proof must match the independently checked source admission.'
 return @{raw_identities=$a.raw_identities;files=$files;directories=$dirs;data_streams=$streams;objects=$objects;source_inspection_sha256=$pin;descriptor=$a;actual_paged_metadata_verified=$true;constructor_metadata_measurement_claimed=$false}
}
