# DRAFT mechanical adapter of Package-ExperimentalAef.ps1. No build, executable
# invocation, VM/device access, Git, tag or publication. Qualification receipts
# describe actual observations; they never grant runtime storage authority.
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$CandidateDirectory,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceTree,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BuildManifestSha256,
 [Parameter(Mandatory)][string]$PublicLayoutPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$PublicLayoutSha256,
 [Parameter(Mandatory)][string]$QualificationPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$QualificationSha256,
 [Parameter(Mandatory)][string]$ReadmePath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ReadmeSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs'
$binaryNames=@('ntfs2refs','lab-prepare-partition-offline','lab-arm-prepared-boot','lab-apply-prepared-offline')
$gateKeys=@('normalSharedRetainedExtents','interruptedResume','interruptedRollback','nativeMutationReboot','boundedResources')
$held=[Collections.Generic.List[object]]::new()
$verificationHeld=[Collections.Generic.List[object]]::new()
$rows=[Collections.Generic.List[object]]::new()
$destinations=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$supportingEvidence=@{}
function Need([bool]$Ok,[string]$Message){if(-not $Ok){throw $Message}}
function Bool($Object,[string]$Name,[bool]$Expected){Need (($Object.$Name-is[bool])-and$Object.$Name-eq$Expected) ('Required boolean differs: '+$Name)}
function Add([long]$A,[long]$B){Need ($A-ge0-and$B-ge0-and$A-le[long]::MaxValue-$B) 'Package byte accounting overflow';return [long]($A+$B)}
function Bytes($Value,[bool]$Positive=$true){Need (($Value-is[int]-or$Value-is[long])-and$Value-ge0-and(-not$Positive-or$Value-gt0)) 'An exact nonnegative integer byte count is required';return [long]$Value}
function Ordinary([string]$Path,[bool]$Directory){
 Need ([IO.Path]::IsPathRooted($Path)-and[IO.Path]::GetFullPath($Path)-ceq$Path) 'Canonical absolute package path required'
 $item=Get-Item -LiteralPath $Path -Force
 Need (($item-is[IO.DirectoryInfo])-eq$Directory) 'Package route type differs'
 for($ancestor=$item;$null-ne$ancestor;){
  Need (-not($ancestor.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Package reparse ancestry refused'
  if($ancestor-is[IO.DirectoryInfo]){$ancestor=$ancestor.Parent}else{$ancestor=$ancestor.Directory}
 }
 return $item
}
function WorkspacePath([string]$Path,[bool]$Directory=$false){
 $full=if([IO.Path]::IsPathRooted($Path)){[IO.Path]::GetFullPath($Path)}else{[IO.Path]::GetFullPath((Join-Path $workspace $Path))}
 Need ($full.StartsWith($workspace+'\',[StringComparison]::OrdinalIgnoreCase)-and$full-notmatch'(?i)[\\/](?:secrets|credentials)[\\/]') 'Only ordinary workspace inputs are accepted'
 $null=Ordinary $full $Directory
 return $full
}
function HashForward([IO.Stream]$Stream){$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash($Stream))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
function HashStream([IO.Stream]$Stream){$Stream.Position=0;$value=HashForward $Stream;$Stream.Position=0;return $value}
function HashFile([string]$Path){$s=[IO.File]::Open($Path,'Open','Read','Read');try{return HashStream $s}finally{$s.Dispose()}}
function OpenPinned([string]$Path,[string]$Sha,[long]$Length){
 Need ($Sha-cmatch'\A[0-9a-f]{64}\z'-and$Length-gt0-and$Length-le64MB) 'Bounded exact positive input pin required'
 $path=WorkspacePath $Path;$s=[IO.File]::Open($path,'Open','Read','Read')
 try{Need ($s.Length-eq$Length-and(HashStream $s)-ceq$Sha) 'Held source bytes differ from independently supplied pin';return [pscustomobject]@{path=$path;stream=$s;bytes=$Length;sha256=$Sha}}catch{$s.Dispose();throw}
}
function Hold([string]$Path,[string]$Sha,[long]$Length,[string]$Destination,[string]$Role){
 Need ($Destination-cmatch'\A[A-Za-z0-9._/-]+\z'-and$Destination-notmatch'(?:\A|/)\.\.(?:/|\z)'-and$destinations.Add($Destination)) 'Unique safe package-relative path required'
 $row=OpenPinned $Path $Sha $Length
 $row|Add-Member -NotePropertyName destination -NotePropertyValue $Destination
 $row|Add-Member -NotePropertyName role -NotePropertyValue $Role
 $held.Add($row);return $row
}
function JsonPin([string]$Path,[string]$Sha,[string]$Destination,[string]$Role){
 $path=WorkspacePath $Path;$item=Get-Item -LiteralPath $path
 Need ($item.Length-gt0-and$item.Length-le1MB-and$item.Extension-ceq'.json') 'Bounded ordinary JSON input required'
 $row=Hold $path $Sha $item.Length $Destination $Role
 $reader=[IO.StreamReader]::new($row.stream,[Text.Encoding]::UTF8,$true,65536,$true)
 try{$text=$reader.ReadToEnd()}finally{$reader.Dispose();$row.stream.Position=0}
 return [pscustomobject]@{row=$row;value=($text|ConvertFrom-Json)}
}
function MeasureTree([string]$Path,[bool]$AllowKnownLabAliases=$false){
 $null=Ordinary $Path $true;$sum=0L;$pending=[Collections.Generic.Queue[string]]::new();$pending.Enqueue($Path)
 $known=@('allocation-43528b66c82c407c83bcde2008571f87','allocation-7058012df22d44b895f8c43fc127b161')
 while($pending.Count){foreach($item in Get-ChildItem -LiteralPath $pending.Dequeue() -Force -ErrorAction Stop){
  if($item.Attributes-band[IO.FileAttributes]::ReparsePoint){
   Need $AllowKnownLabAliases 'Capacity census reparse route refused'
   $parent=[IO.Path]::GetFullPath((Split-Path $item.FullName -Parent));$expectedParents=@($known|ForEach-Object {Join-Path $workspace ('.lab\tests\'+$_)})
   Need ($parent-cin$expectedParents-and$item.Name-cin@('alias-directory','alias.bin')) 'Unknown .lab reparse route refused'
   $target=@($item.Target);Need ($target.Count-eq1-and[IO.Path]::IsPathRooted([string]$target[0])) 'Known alias must have one absolute target'
   $resolved=[IO.Path]::GetFullPath([string]$target[0]).TrimEnd('\');$expected=if($item.Name-ceq'alias-directory'){$parent}else{Join-Path $parent 'ordinary file.bin'}
   Need ($resolved-ieq$expected-and(($item.Name-ceq'alias-directory'-and$item.PSIsContainer-and$item.LinkType-ceq'Junction')-or($item.Name-ceq'alias.bin'-and-not$item.PSIsContainer-and$item.LinkType-ceq'SymbolicLink'))) 'Known alias type/target differs'
   $null=Ordinary $resolved ([bool]$item.PSIsContainer);$sum=Add $sum 65536;continue
  }
  if($item-is[IO.DirectoryInfo]){$pending.Enqueue($item.FullName)}else{$sum=Add $sum $item.Length}
 }}
 return $sum
}
function Capacity([long]$AdditionalBytes){
 $settings=Get-Content -LiteralPath (Join-Path $workspace 'lab\lab.config.json') -Raw|ConvertFrom-Json
 Need ($settings.maximumActualBytes-eq329374052988L-and$settings.minimumHostFreeBytes-eq17179869184L) 'Original capacity policy changed; no epoch/cap reset is allowed'
 $total=0L;foreach($relative in @('.lab','target\shared-experiments','target\shared-experiments-staging')){$total=Add $total (MeasureTree (Join-Path $workspace $relative) ($relative-ceq'.lab'))}
 $free=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($workspace)).AvailableFreeSpace
 Need ($AdditionalBytes-ge0-and$AdditionalBytes-le$settings.maximumActualBytes-and$total-le$settings.maximumActualBytes-$AdditionalBytes) 'Complete lab/cache/staging allocation budget would be exceeded'
 Need ($AdditionalBytes-le$free-and$free-$AdditionalBytes-ge$settings.minimumHostFreeBytes) 'Original host free-space reserve would be breached'
 return [ordered]@{actual_bytes=$total;free_bytes=$free;maximum_actual_bytes=[long]$settings.maximumActualBytes;minimum_free_bytes=[long]$settings.minimumHostFreeBytes;additional_bytes=$AdditionalBytes;all_lab_shared_cache_and_staging_charged=$true;epoch_reset=$false}
}
function WriteNew([string]$Path,[byte[]]$Value){$f=[IO.File]::Open($Path,'CreateNew','Write','Read');try{$f.Write($Value,0,$Value.Length);$f.Flush($true)}finally{$f.Dispose()}}
function JsonBytes($Value){return [Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 24))}
function BinaryRows($Value,$Expected){
 Need (@($Value).Count-eq$binaryNames.Count) 'Exactly all four build binary pins are required'
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach($row in $Value){
  Need ($row.name-cin$binaryNames-and$seen.Add($row.name)) 'Duplicate or unexpected binary pin'
  $length=Bytes $row.bytes
  Need ($length-le64MB-and$row.sha256-cmatch'\A[0-9a-f]{64}\z') 'Bounded exact binary pin required'
  if($null-ne$Expected){$match=$Expected[$row.name];Need ($null-ne$match-and$length-eq$match.bytes-and$row.sha256-ceq$match.sha256) 'Qualification binary pin differs from actual build'}
 }
}
function SameSource($Value){
 Need ($Value.disk_number-eq0-and$Value.partition_number-eq6-and$Value.partition_guid-ceq'4310d74c-614f-435b-9cf1-7ff664391590'-and$Value.partition_offset_bytes-eq68719476736L-and$Value.partition_length_bytes-eq55834574848L) 'Qualification source is outside the demonstrated shared-disk fixture'
}
try{
 # Reject draft/incomplete observations before creating any output or copying an executable.
 $qual=JsonPin $QualificationPath $QualificationSha256 'qualification.json' 'external-observational-qualification';$q=$qual.value
 Need ($q.schema_version-eq1-and$q.kind-ceq'shared-offline-alpha-observational-qualification'-and$q.qualification_status-ceq'reviewed-finite-experimental') 'Reviewed shared-offline qualification schema required'
 foreach($key in @('observational_only','native_matrix_complete','finite_profile_only')){Bool $q $key $true}
 foreach($key in @('draft','grants_runtime_authority','stable_release','published','physical_power_loss_qualified','inherited_qualification')){Bool $q $key $false}
 Need ($q.source_commit-ceq$SourceCommit-and$q.source_tree-ceq$SourceTree-and$q.build_manifest_sha256-ceq$BuildManifestSha256-and$q.public_layout_sha256-ceq$PublicLayoutSha256-and$q.cargo_package_version-ceq'0.1.0') 'Qualification does not bind supplied source/build/layout/version'
 SameSource $q.source_binding
 Need (@($q.gates).Count-eq$gateKeys.Count) 'Every required finite gate must be present exactly once'
 $candidate=WorkspacePath $CandidateDirectory $true
 $build=JsonPin (Join-Path $candidate 'manifest.json') $BuildManifestSha256 'provenance/build-manifest.json' 'unchanged-build-provenance';$b=$build.value
 Need ($b.source_commit-ceq$SourceCommit-and$b.source_tree-ceq$SourceTree-and$b.archive.path-ceq'source.zip'-and$q.source_archive_sha256-ceq$b.archive.sha256) 'Pinned committed-source build provenance differs'
 Bool $b working_tree_inputs_used $false;Bool $b source_before_after_verified $true;Bool $b unit_tests_run $false
 $cargo=@($b.commands|Where-Object name -CEQ 'cargo-build');Need ($cargo.Count-eq1-and$cargo[0].exit_code-eq0) 'An actual successful closed cargo build is required'
 BinaryRows $b.binaries $null
 $buildPins=@{};foreach($binary in $b.binaries){
  Need ($binary.path-ceq('bin/'+$binary.name+'.exe')) 'Unexpected build binary route'
  $buildPins[$binary.name]=$binary
 }
 BinaryRows $q.build_binaries $buildPins
 $public=$buildPins['ntfs2refs'];$cold=$buildPins['lab-apply-prepared-offline']
 $layout=JsonPin $PublicLayoutPath $PublicLayoutSha256 'provenance/public-layout.json' 'exact-native-case-public-layout';$l=$layout.value
 Need ($l.kind-ceq'unqualified-shared-disk-public-layout-v1'-and$l.source_commit-ceq$SourceCommit-and$l.manifest_sha256-ceq$BuildManifestSha256-and@($l.files).Count-eq2) 'Pinned public layout differs'
 $layoutStableFields=@('stable_release','stable_release_qualified'|Where-Object {$null-ne$l.PSObject.Properties[$_]})
 Need ($layoutStableFields.Count-gt0) 'Actual immutable layout must explicitly reject stable qualification'
 foreach($field in $layoutStableFields){Bool $l $field $false}
 $layoutPins=@{};foreach($file in $l.files){
  Need ($file.name-cin@('ntfs2refs.exe','ntfs2refs-recovery.exe')-and-not$layoutPins.ContainsKey($file.name)) 'Unexpected or duplicate shipped executable'
  $expected=if($file.name-ceq'ntfs2refs.exe'){$public}else{$cold}
  Need ($file.source_commit-ceq$SourceCommit-and$file.source_role-ceq$expected.name-and(Bytes $file.bytes)-eq$expected.bytes-and$file.sha256-ceq$expected.sha256) 'Public layout is not a byte-identical build copy'
  $layoutPins[$file.name]=$file
 }
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$faultCases=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$faultNonces=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach($gate in $q.gates){
  Need ($gate.key-cin$gateKeys-and$seen.Add($gate.key)-and$gate.status-ceq'passed'-and$gate.case_reference-is[string]-and-not[string]::IsNullOrWhiteSpace($gate.case_reference)) 'Missing, duplicate or pending finite gate refuses packaging'
  Bool $gate passed $true;Bool $gate actual_case_observed $true
  $proof=JsonPin $gate.evidence_path $gate.evidence_sha256 ('evidence/'+$gate.key+'.json') 'exact-build-observational-case';$e=$proof.value
  Need ($e.schema_version-eq1-and$e.kind-ceq'shared-offline-alpha-gate-observation'-and$e.gate_key-ceq$gate.key-and$e.case_reference-ceq$gate.case_reference) 'Gate receipt identity differs'
  Bool $e passed $true;Bool $e actual_case_observed $true;Bool $e observational_only $true;Bool $e inherited_qualification $false;Bool $e grants_runtime_authority $false
  Need ($e.source_commit-ceq$SourceCommit-and$e.source_tree-ceq$SourceTree-and$e.build_manifest_sha256-ceq$BuildManifestSha256-and$e.public_layout_sha256-ceq$PublicLayoutSha256-and$e.public_binary_sha256-ceq$public.sha256-and$e.cold_binary_sha256-ceq$cold.sha256) 'Old/different source, build, layout or executable proof refuses packaging'
  SameSource $e.source_binding
  Need (@($e.supporting_evidence).Count-gt0-and@($e.supporting_evidence).Count-le64) 'Each gate requires bounded actual supporting metadata references'
  foreach($reference in $e.supporting_evidence){
   $supportPath=WorkspacePath $reference.path;$supportKey=$supportPath.ToLowerInvariant();$supportLength=Bytes $reference.bytes
   Need ($reference.sha256-cmatch'\A[0-9a-f]{64}\z'-and$supportLength-le1MB) 'Bounded exact supporting JSON metadata pin required'
   if($supportingEvidence.ContainsKey($supportKey)){
    $prior=$supportingEvidence[$supportKey];Need ($prior.sha256-ceq$reference.sha256-and$prior.bytes-eq$supportLength) 'Conflicting supporting metadata pin'
   }else{
    $support=JsonPin $supportPath $reference.sha256 ('evidence/support-'+$supportingEvidence.Count.ToString('D3')+'.json') 'actual-case-supporting-native-metadata'
    Need ($support.row.bytes-eq$supportLength) 'Supporting metadata byte count differs'
    $supportingEvidence[$supportKey]=$support.row
   }
  }
  if($gate.key-cin@('normalSharedRetainedExtents','interruptedResume','interruptedRollback')){
   foreach($key in @('prepared_bundle_sha256','bootstrap_sha256','image_record_sha256','boot_intent_sha256','journal_immutable_sha256','journal_index_sha256')){Need ($e.$key-cmatch'\A[0-9a-f]{64}\z') ('Actual case artifact pin absent: '+$key)}
   $identity=$e.journal_native_identity
   Need ($identity-is[pscustomobject]-and@($identity.PSObject.Properties).Count-gt0-and($identity|ConvertTo-Json -Depth 24 -Compress).Length-le65536) 'A bounded nonempty actual journal native identity object is required'
  }
  switch -CaseSensitive ($gate.key){
   'normalSharedRetainedExtents'{
    foreach($key in @('one_command_public_run','same_partition_conversion','retained_extents_verified','original_source8_verified','source_physical_disk_shared_with_running_windows','closed_lifecycle_verified','normal_windows_boot_observed')){Bool $e $key $true}
    Need ($e.native_exit_code-eq0-and$e.terminal_state-ceq'HND') 'Normal conversion did not reach actual successful HND'
   }
   {$_-cin@('interruptedResume','interruptedRollback')}{
    Need ($faultCases.Add($e.case_reference)) 'Resume and rollback must use independent interrupted cases'
    Need ($e.controlled_pause_nonce-cmatch'\A[0-9a-f]{64}\z'-and$faultNonces.Add($e.controlled_pause_nonce)) 'Separate fresh controlled-pause nonces are required for resume and rollback'
    foreach($key in @('independent_interrupted_case','positive_ap_writes_before_discovery','flush_and_pending_readback_succeeded','native_writer_revalidation_succeeded','discovery_write_not_requested','actual_restart_observed','source_exclusion_after_restart_verified','original_source_and_journal_identities_retained','closed_lifecycle_verified','original_source8_verified','normal_windows_boot_observed')){Bool $e $key $true}
    Bool $e snapshot_restored_after_interruption $false
    Need ((Bytes $e.native_bytes_written_before_discovery)-gt0-and$e.delayed_discovery_bytes-eq4096) 'Positive actual flushed AP writes before discovery are required'
    $choice=if($gate.key-ceq'interruptedResume'){'R'}else{'B'};$terminal=if($choice-ceq'R'){'HND'}else{'ABT'}
    Need ($e.recovery_choice-ceq$choice-and$e.terminal_state-ceq$terminal-and$e.native_exit_code-eq0) 'Recovery choice or authenticated terminal result differs'
   }
   'nativeMutationReboot'{
    foreach($key in @('native_mutation_verified','ordinary_reboot_observed','mutation_persisted_after_reboot','original_source8_verified_after_reboot')){Bool $e $key $true}
    Need ((Bytes $e.mutated_or_created_files)-gt0) 'Positive native mutation observation required'
   }
   'boundedResources'{
    foreach($key in @('all_required_case_resources_observed','all_lab_shared_cache_and_staging_charged','runtime_budget_respected','scratch_budget_respected')){Bool $e $key $true}
    Bool $e epoch_reset $false
    Need ($e.global_epoch_baseline_bytes-eq279374052988L-and$e.maximum_actual_bytes-eq329374052988L-and$e.minimum_host_free_bytes-eq17179869184L) 'Original resource epoch/cap/reserve differs'
    Need ((Bytes $e.observed_peak_working_set_bytes)-le(Bytes $e.admitted_ram_bytes)) 'Observed runtime RAM exceeded admitted bounds'
    Need ((Bytes $e.observed_maximum_actual_bytes)-le329374052988L-and(Bytes $e.observed_minimum_host_free_bytes)-ge17179869184L) 'Actual complete host resource observations exceeded policy'
    Need ($e.ram_measurement_scope-is[string]-and-not[string]::IsNullOrWhiteSpace($e.ram_measurement_scope)) 'Actual RAM measurement scope must be stated'
    if($null-ne$e.PSObject.Properties['scratch_peak_measured']-and$e.scratch_peak_measured-is[bool]-and-not$e.scratch_peak_measured){
     # This is an observational bound, not a measurement of physical high water.
     Need ($null-eq$e.observed_scratch_peak_bytes) 'Unmeasured scratch peak must remain null'
     Need ($e.runtime_bound_method-ceq'aggregate_artifact_reservations_and_named_staging_image_limits_v1') 'Reviewed runtime bound method required'
     Need ($e.ram_measurement_scope-ceq'Windows-native-process-only'-and$e.observed_peak_working_set_bytes-eq144375808) 'Only the actual recorded Windows process RAM observation is accepted'
     Bool $e cold_aggregate_ram_peak_measured $false;Bool $e os_kernel_memory_quota_claimed $false;Bool $e physical_scratch_peak_measured $false
     Need ($null-eq$e.observed_cold_aggregate_ram_peak_bytes) 'Unknown cold aggregate RAM peak must remain null'
     Need ($e.scratch_accounting_scope-ceq'per-phase aggregate reservations plus separately named staging and recovery-image limits; no physical peak claim') 'Explicit non-overlapping accounting scope required'
     Need (@($e.case_resources).Count-eq3) 'Normal, resume and rollback resource cases are all required'
     $resourceSeen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
     $minimumRam=[long]::MaxValue;$maximumNamedScratch=0L
     foreach($case in $e.case_resources){
      Need ($case.gate_key-cin@('normalSharedRetainedExtents','interruptedResume','interruptedRollback')-and$resourceSeen.Add($case.gate_key)) 'Exactly three distinct native resource cases required'
      $matchingGate=@($q.gates|Where-Object key -CEQ $case.gate_key)
      Need ($matchingGate.Count-eq1-and$case.case_reference-ceq$matchingGate[0].case_reference) 'Resource case must match its actual native gate'
      foreach($key in @('upfront_budget_reported','all_native_actors_closed','case_complete','source_and_core_reservations_enforced','staging_allocation_limit_enforced','image_growth_and_free_floor_checked','separate_named_staging_and_image_limits')){Bool $case $key $true}
      Bool $case scratch_peak_measured $false
      $ram=Bytes $case.admitted_ram_bytes;$arena=Bytes $case.prepare_arena_scratch_bytes
      $source=Bytes $case.source_scratch_bytes;$core=Bytes $case.core_arena_scratch_bytes
      Need ((Add $source $core)-eq$arena-and$source-eq[long][Math]::Floor($arena/8.0)) 'Source subcap must be one eighth of, and core must partition, the admitted arena without double counting'
      $stage=Bytes $case.maximum_staging_allocation_bytes;$image=Bytes $case.image_working_bytes
      $floor=Bytes $case.prepare_minimum_free_bytes;$recoveryFloor=Bytes $case.recovery_minimum_free_bytes
      $free=Bytes $case.independent_journal_free_before_bytes
      $evidence=Bytes $case.maximum_evidence_bytes;$pause=Bytes $case.pause_evidence_bytes $false
      Need ($floor-eq(Add (Add $image $recoveryFloor) (Add (Add $evidence (Add $evidence $evidence)) $pause))) 'Prepare free floor must equal image plus kept free plus three evidence limits and optional controlled pause evidence'
      $coldRam=Bytes $case.cold_total_ram_bytes;$coldScratch=Bytes $case.cold_arena_scratch_bytes;$coldFloor=Bytes $case.cold_minimum_free_bytes
      Need ($coldRam-eq$ram-and$coldFloor-eq$recoveryFloor) 'Cold request must retain the admitted RAM and recovery free floor'
      Bool $case cold_arena_reservations_enforced $true;Bool $case journal_profile_is_inside_core_reservation $true
      Bool $case native_report_memory_leases_share_arena_ram $true
      $prepareNeed=Add (Add $arena $stage) $floor
      Need ($prepareNeed-le$free) 'Actual upfront independent storage cannot cover admitted preparation bounds'
      $named=Add (Add $arena $stage) $image
      Need ($coldScratch-le$named) 'Cold arena must fit the declared conservative named scratch bound'
      if($named-gt$maximumNamedScratch){$maximumNamedScratch=$named}
      if($ram-lt$minimumRam){$minimumRam=$ram}
      foreach($field in @('budget_reference','capacity_reference','bundle_reference','cold_request_reference','closed_reference')){Need ($case.$field-is[pscustomobject]) ('Actual pinned resource-case input required: '+$field)}
      foreach($pin in @($case.budget_reference,$case.capacity_reference,$case.bundle_reference,$case.cold_request_reference,$case.closed_reference)){
       $actualPath=WorkspacePath $pin.path;$pinLength=Bytes $pin.bytes
       $matches=@($e.supporting_evidence|Where-Object {$_.path-ceq$pin.path-and$_.sha256-ceq$pin.sha256-and$_.bytes-eq$pinLength})
       Need ($matches.Count-eq1-and$pin.sha256-cmatch'\A[0-9a-f]{64}\z'-and$pinLength-le1MB-and$supportingEvidence.ContainsKey($actualPath.ToLowerInvariant())) 'Resource reference must be one held and hashed supporting JSON input'
      }
     }
     Need ($e.admitted_ram_bytes-eq$minimumRam-and(Bytes $e.admitted_scratch_bytes)-eq$maximumNamedScratch) 'Aggregate fields must use minimum admitted RAM and maximum separately named scratch bounds'
     Need ($e.bound_review_reference-is[pscustomobject]) 'Source-level reservation/staging/image review reference required'
     $review=$e.bound_review_reference;$reviewPath=WorkspacePath $review.path;$reviewLength=Bytes $review.bytes
     $reviewMatches=@($e.supporting_evidence|Where-Object {$_.path-ceq$review.path-and$_.sha256-ceq$review.sha256-and$_.bytes-eq$reviewLength})
     Need ($reviewMatches.Count-eq1-and$review.sha256-cmatch'\A[0-9a-f]{64}\z'-and$reviewLength-le1MB-and$supportingEvidence.ContainsKey($reviewPath.ToLowerInvariant())) 'Bound review must be held and hashed supporting JSON'
    }else{
     # Preserve the original measured-peak contract when actual measurements exist.
     Need ((Bytes $e.observed_scratch_peak_bytes)-le(Bytes $e.admitted_scratch_bytes)) 'Observed scratch exceeded admitted bounds'
    }
   }
  }
 }
 foreach($key in $gateKeys){Need ($seen.Contains($key)) 'Required finite gate absent'}
 # Verify every producer/consumer binary against the same pinned build, but ship
 # only the two already-qualified public-layout files.
 foreach($binary in $b.binaries){$verificationHeld.Add((OpenPinned (Join-Path $candidate $binary.path) $binary.sha256 $binary.bytes))}
 $archiveLength=Bytes $b.archive.bytes;Need ($archiveLength-le16MB) 'Bounded committed-source archive required'
 $null=Hold (Join-Path $candidate 'source.zip') $b.archive.sha256 $archiveLength 'provenance/source.zip' 'unchanged-committed-source-archive'
 $layoutDirectory=Split-Path $layout.row.path -Parent
 foreach($name in @('ntfs2refs.exe','ntfs2refs-recovery.exe')){$pin=$layoutPins[$name];$null=Hold (Join-Path $layoutDirectory $name) $pin.sha256 $pin.bytes $name 'unchanged-qualified-public-layout-executable'}
 $readmeFile=WorkspacePath $ReadmePath;$readme=Get-Item -LiteralPath $readmeFile;Need ($readme.Extension-ceq'.md'-and$readme.Length-gt0-and$readme.Length-le1MB) 'Bounded experimental Markdown README required'
 $null=Hold $readmeFile $ReadmeSha256 $readme.Length 'README.md' 'independently-pinned-candidate-documentation'
 $inputBytes=0L;foreach($row in $held){$inputBytes=Add $inputBytes $row.bytes;$rows.Add([ordered]@{relative_path=$row.destination;bytes=$row.bytes;sha256=$row.sha256;source_path=$row.path;role=$row.role})}
 $manifest=[ordered]@{schema_version=1;kind='local-shared-offline-alpha-experimental-candidate';shipped_binaries=@('ntfs2refs.exe','ntfs2refs-recovery.exe');cargo_package_version='0.1.0';finite_profile_only=$true;source_commit=$SourceCommit;source_tree=$SourceTree;build_manifest_sha256=$BuildManifestSha256;public_layout_sha256=$PublicLayoutSha256;qualification_sha256=$QualificationSha256;readme_sha256=$ReadmeSha256;observational_only=$true;grants_runtime_authority=$false;stable_release=$false;published=$false;physical_power_loss_qualified=$false;reproducible_build_verified=$false;manifest_excludes_own_hash=$true;files=$rows.ToArray();created_utc=[DateTime]::UtcNow.ToString('o')}
 $manifestBytes=JsonBytes $manifest;Need ($manifestBytes.Length-le1MB) 'Bounded package file manifest required'
 $contentBytes=Add $inputBytes $manifestBytes.Length;Need ($contentBytes-le64MB) 'Package content exceeds strict64MiB bound'
 $zipOverhead=Add 65536 ([long]($held.Count+1)*1024);$zipAllowance=Add $contentBytes $zipOverhead;$required=Add (Add $contentBytes $zipAllowance) 65536
 $before=Capacity $required
 $packageParent=Join-Path $workspace '.lab\packages';if(-not(Test-Path -LiteralPath $packageParent)){$null=New-Item -ItemType Directory -Path $packageParent};$null=Ordinary $packageParent $true
 $packageRoot=Join-Path $packageParent ('shared-offline-alpha-'+[guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $packageRoot
 $contentRoot=Join-Path $packageRoot 'content';$null=New-Item -ItemType Directory -Path $contentRoot
 foreach($directory in @('provenance','evidence')){$null=New-Item -ItemType Directory -Path (Join-Path $contentRoot $directory)}
 $written=0L
 foreach($row in $held){
  Need ($row.stream.Length-eq$row.bytes-and(HashStream $row.stream)-ceq$row.sha256) 'Held source changed before package copy'
  $destination=[IO.Path]::GetFullPath((Join-Path $contentRoot $row.destination));Need ($destination.StartsWith($contentRoot+'\',[StringComparison]::OrdinalIgnoreCase)) 'Package output escaped its root';$null=Ordinary (Split-Path $destination -Parent) $true
  $output=[IO.File]::Open($destination,'CreateNew','Write','Read');try{$row.stream.CopyTo($output);$output.Flush($true)}finally{$output.Dispose()};$row.stream.Position=0
  Need ((Get-Item -LiteralPath $destination).Length-eq$row.bytes-and(HashFile $destination)-ceq$row.sha256) 'Package copy readback differs';$written=Add $written $row.bytes
 }
 $manifestPath=Join-Path $contentRoot 'manifest.json';WriteNew $manifestPath $manifestBytes;$written=Add $written $manifestBytes.Length
 $manifestSha=HashFile $manifestPath;$archivePath=Join-Path $packageRoot 'ntfs2refs-shared-offline-alpha-experimental.zip';$null=Capacity ($required-$written)
 Add-Type -AssemblyName System.IO.Compression
 $archiveFile=[IO.File]::Open($archivePath,'CreateNew','ReadWrite','Read')
 try{$zip=[IO.Compression.ZipArchive]::new($archiveFile,[IO.Compression.ZipArchiveMode]::Create,$true);try{foreach($relative in (@($rows|ForEach-Object relative_path)+@('manifest.json')|Sort-Object)){
  $path=Join-Path $contentRoot $relative;$null=Ordinary $path $false;$s=[IO.File]::Open($path,'Open','Read','Read');try{$expected=if($relative-ceq'manifest.json'){$manifestSha}else{@($rows|Where-Object relative_path -CEQ $relative)[0].sha256};Need ((HashStream $s)-ceq$expected) 'Package payload changed before ZIP copy';$entry=$zip.CreateEntry($relative,[IO.Compression.CompressionLevel]::NoCompression);$out=$entry.Open();try{$s.CopyTo($out)}finally{$out.Dispose()}}finally{$s.Dispose()}
 }}finally{$zip.Dispose()};$archiveFile.Flush($true);Need ($archiveFile.Length-le$zipAllowance) 'ZIP exceeded its admitted input/header allowance'}finally{$archiveFile.Dispose()}
 $zipInput=[IO.File]::Open($archivePath,'Open','Read','Read')
 try{$zip=[IO.Compression.ZipArchive]::new($zipInput,[IO.Compression.ZipArchiveMode]::Read,$true);try{
  Need ($zip.Entries.Count-eq$rows.Count+1) 'ZIP entry count differs';$zipSeen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach($entry in $zip.Entries){
   Need ($zipSeen.Add($entry.FullName)) 'Duplicate ZIP entry refused'
   $expected=if($entry.FullName-ceq'manifest.json'){[pscustomobject]@{bytes=$manifestBytes.Length;sha256=$manifestSha}}else{$matches=@($rows|Where-Object relative_path -CEQ $entry.FullName);Need ($matches.Count-eq1) 'Unexpected ZIP entry';$matches[0]}
   Need ($entry.Length-eq$expected.bytes) 'ZIP entry length differs';$s=$entry.Open();try{Need ((HashForward $s)-ceq$expected.sha256) 'ZIP entry SHA-256 readback differs'}finally{$s.Dispose()}
  }
 }finally{$zip.Dispose()}}finally{$zipInput.Dispose()}
 foreach($row in $verificationHeld){Need ($row.stream.Length-eq$row.bytes-and(HashStream $row.stream)-ceq$row.sha256) 'Pinned producer/consumer binary changed during packaging'}
 $archiveItem=Get-Item -LiteralPath $archivePath;$after=Capacity 65536
 $receipt=[ordered]@{schema_version=1;kind='local-shared-offline-alpha-experimental-package-receipt';shipped_binaries=@('ntfs2refs.exe','ntfs2refs-recovery.exe');cargo_package_version='0.1.0';archive_name=$archiveItem.Name;archive_bytes=$archiveItem.Length;archive_sha256=(HashFile $archivePath);manifest_sha256=$manifestSha;qualification_sha256=$QualificationSha256;source_commit=$SourceCommit;source_tree=$SourceTree;build_manifest_sha256=$BuildManifestSha256;public_layout_sha256=$PublicLayoutSha256;all_zip_entry_lengths_and_sha256_verified=$true;stable_release=$false;published=$false;observational_only=$true;grants_runtime_authority=$false;epoch_reset=$false;reserved_additional_bytes=$required;content_bytes=$contentBytes;zip_allowance_bytes=$zipAllowance;capacity_before=$before;capacity_after=$after;utc=[DateTime]::UtcNow.ToString('o')}
 $receiptBytes=JsonBytes $receipt;Need ($receiptBytes.Length-le65536) 'Archive receipt exceeds its admitted allowance';WriteNew (Join-Path $packageRoot 'archive-receipt.json') $receiptBytes
 [pscustomobject]@{package_root=$packageRoot;archive=$archivePath;archive_sha256=$receipt.archive_sha256;manifest_sha256=$manifestSha;published=$false;stable_release=$false}|ConvertTo-Json -Compress
}finally{foreach($row in $held){$row.stream.Dispose()};foreach($row in $verificationHeld){$row.stream.Dispose()}}
