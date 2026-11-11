# Derive a bounded observation from an already closed local archive. This does
# not contact the VM, open original guest paths, read a raw journal, or grant
# source/recovery authority. The original failed wrapper record is preserved.
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$ArchiveDirectory,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ExecutableSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$RunId,
 [Parameter(Mandatory)][string]$OutputPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$limit=64MB
$held=[Collections.Generic.List[IO.FileStream]]::new()
$files=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$rows=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
function Need([bool]$Ok,[string]$Message){if(-not $Ok){throw $Message}}
function PlainPath([string]$Path,[bool]$Directory){
 $full=[IO.Path]::GetFullPath($Path)
 Need ($full-cmatch '\A[A-Za-z]:\\') 'Only local drive paths are accepted.'
 $m=Get-Item -LiteralPath $full -Force -ErrorAction Stop
 Need (($m-is[IO.DirectoryInfo])-eq$Directory) 'Local artifact has the wrong file type.'
 $a=$m
 while($null-ne$a){Need (-not($a.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse archive ancestry is not accepted.';if($a-is[IO.DirectoryInfo]){$a=$a.Parent}else{$a=$a.Directory}}
 return $full
}
function OpenArtifact([string]$Path,[long]$Maximum){
 $full=PlainPath $Path $false
 $file=[IO.File]::Open($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 $held.Add($file)
 Need ($file.Length-ge0-and$file.Length-le$Maximum) 'Archived artifact exceeds its read bound.'
 $sha=[Security.Cryptography.SHA256]::Create()
 try{$pin=([BitConverter]::ToString($sha.ComputeHash($file))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
 $file.Position=0
 return [pscustomobject]@{path=$full;file=$file;bytes=$file.Length;sha256=$pin}
}
function JsonArtifact($Artifact){
 Need ($Artifact.bytes-gt0) 'JSON artifact is empty.'
 $Artifact.file.Position=0
 $reader=[IO.StreamReader]::new($Artifact.file,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true)
 try{$text=$reader.ReadToEnd()}finally{$reader.Dispose()}
 return ($text|ConvertFrom-Json)
}
function Json([string]$Key){Need ($files.ContainsKey($Key)) ('Missing archived record: '+$Key);return (JsonArtifact $files[$Key])}
function SameArray($Left,$Right){
 $a=@($Left);$b=@($Right)
 if($a.Count-ne$b.Count){return $false}
 for($i=0;$i-lt$a.Count;$i++){if($a[$i]-cne$b[$i]){return $false}}
 return $true
}
function PathKey($Components){
 $parts=@($Components)
 foreach($part in $parts){Need ($part-is[string]-and$part.Length-gt0-and$part-notin@('.','..')-and$part-cnotmatch '[\\/\x00]') 'Invalid archived object path component.'}
 return [string]::Join('\',[string[]]$parts)
}
function SameBinding($Left,$Right){
 foreach($key in @('disk_number','volume_guid')){if([string]$Left.$key-cne[string]$Right.$key){return $false}}
 foreach($key in @('disk_guid','partition_guid','partition_number','disk_bytes','partition_offset','partition_bytes','logical_sector_bytes','physical_sector_bytes')){if([string]$Left.identity.$key-cne[string]$Right.identity.$key){return $false}}
 return $true
}
try{
 $root=(PlainPath $ArchiveDirectory $true).TrimEnd('\')
 $inventoryFile=OpenArtifact (Join-Path $root 'inventory.json') 4MB
 $inventory=JsonArtifact $inventoryFile
 Need ($inventory.schema_version-eq1-and$inventory.run_id-ceq$RunId-and$inventory.engine_run_id-cmatch '\A[0-9a-f]{32}\z') 'Archive run identity differs.'
 $engine=$inventory.engine_run_id
 $buildFile=OpenArtifact (Join-Path $root 'provenance\manifest.json') 4MB
 $build=JsonArtifact $buildFile
 $dispatchFile=OpenArtifact (Join-Path $root 'provenance\controller-dispatch.json') 4MB
 $dispatch=JsonArtifact $dispatchFile
 $main=@($build.tools|Where-Object name -ceq 'ntfs2refs.exe')
 Need ($build.schema_version-eq1-and$build.kind-ceq'head-drive-toolset'-and$build.source_commit-ceq$SourceCommit-and$main.Count-eq1-and$main[0].sha256-ceq$ExecutableSha256) 'Sealed build provenance differs.'
 Need ($dispatch.run_id-ceq$RunId-and$dispatch.source_commit-ceq$SourceCommit-and$dispatch.binary_sha256-ceq$ExecutableSha256-and$dispatch.toolset_manifest_sha256-ceq$buildFile.sha256) 'Controller dispatch does not bind the sealed build.'
 Need (@($inventory.rows).Count-gt0-and@($inventory.rows).Count-le4096) 'Archive inventory count is invalid.'
 $archivedBytes=0L;$skipped=0
 foreach($row in $inventory.rows){
  Need ($row.role-in@('run','stage','journal')-and$row.relative-is[string]-and$row.relative.Length-gt0) 'Invalid inventory role or relative path.'
  $relative=$row.relative.Replace('/','\')
  Need ($relative-cnotmatch '\A\\|[:\x00-\x1f]' -and @($relative.Split('\')|Where-Object {$_-in@('','.','..')}).Count-eq0) 'Inventory path escapes its role.'
  $key=$row.role+'\'+$relative
  Need (-not$rows.ContainsKey($key)) 'Duplicate inventory path.'
  $rows.Add($key,$row)
  Need ($row.bytes-ge0) 'Negative artifact length.'
  if($row.disposition-ceq'retained_original_not_copied'){$skipped++;continue}
  Need ($row.disposition-ceq'archive_exact_bytes'-and$row.role-in@('run','stage')-and$row.sha256-cmatch '\A[0-9a-f]{64}\z') 'Invalid copied artifact disposition or pin.'
  $expectedOriginal=if($row.role-ceq'run'){'C:\ProgramData\ntfs2refs\runs\'+$engine+'\'+$relative}else{'C:\ntfs2refs\alloc-drive-'+$RunId+'\'+$relative}
  Need ($row.path-ceq$expectedOriginal) 'Inventory original path does not match the recorded run.'
  $path=[IO.Path]::GetFullPath((Join-Path $root $key))
  Need ($path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) 'Archive artifact path escapes its root.'
  $artifact=OpenArtifact $path $limit
  Need ($artifact.bytes-eq$row.bytes-and$artifact.sha256-ceq$row.sha256) ('Archived length or hash differs: '+$key)
  $files.Add($key,$artifact);$archivedBytes+=$artifact.bytes
 }
 $result=Json 'run\conversion\result.json'
 $final=Json 'run\conversion\finalization.json'
 $expected=Json 'run\conversion\expectation.json'
 $plan=Json 'run\conversion\selected-plan.json'
 $ticket=Json 'run\conversion\selected-ticket.json'
 $handoff=Json 'run\conversion\handoff.json'
 $request=Json 'run\conversion\request.json'
 $verification=Json 'run\conversion\verification.json'
 $process=Json 'stage\native-process.json'
 $terminal=Json 'stage\native-terminal.json'
 $failure=Json 'stage\wrapper-failed.json'
 Need ($files.ContainsKey('stage\ntfs2refs.exe')-and$files['stage\ntfs2refs.exe'].sha256-ceq$ExecutableSha256-and$process.binary_sha256-ceq$ExecutableSha256-and$process.binary-ceq$rows['stage\ntfs2refs.exe'].path) 'Archived executable/process pin differs.'
 Need ($process.pid-gt0-and$process.creation_ms-gt0-and$process.process_handle_retained_before_wait-eq$true-and$process.expected_exit-eq0-and(SameArray $process.argv @('--drive','F','--partition','2'))) 'Archived native process identity or arguments differ.'
 Need ($terminal.native_exit_observed-eq$true-and$terminal.native_exit-eq0-and$terminal.expected_exit-eq0) 'Native completion did not report exit zero.'
 Need ($failure.success-eq$false-and$failure.native_exit_observed-eq$true-and$failure.native_exit-eq0-and$failure.run_id-ceq$RunId-and$failure.phase-ceq'closed-native-conversion-evidence'-and$failure.error-like'*Bounded ordinary closed C JSON required*') 'Original wrapper failure is not the expected post-completion observation failure.'
 Need ($inventory.native_exit-eq0-and$inventory.wrapper_exit-eq1-and$inventory.workers_absent-eq$true) 'Archive closeout does not establish completed workers.'
 foreach($stream in @('stdout','stderr')){Need ($terminal.$stream.sha256-ceq$files['stage\'+$stream+'.log'].sha256-and$terminal.$stream.bytes-eq$files['stage\'+$stream+'.log'].bytes) 'Terminal log pin differs.'}
 Need ($result.schema_version-eq1-and$result.kind-ceq'experimental-allocation-bounded-conversion'-and$result.success-eq$true-and$result.source_admitted-eq$true-and$result.rollback_closed-eq$true-and$result.free_space_contents_compared-eq$false-and$result.general_conversion_qualified-eq$false) 'Native result does not report scoped conversion success.'
 Need ($result.expected_tree_sha256-ceq$files['run\conversion\expectation.json'].sha256-and$result.plan_sha256-ceq$files['run\conversion\selected-plan.json'].sha256-and$result.ticket_sha256-ceq$files['run\conversion\selected-ticket.json'].sha256) 'Native result pins differ from the archived inputs.'
 Need ($handoff.replay_closed-eq$true-and$handoff.whole_image_verified-eq$false-and$handoff.conversion_qualified-eq$false-and(SameArray $handoff.selected_sha256 $ticket.new_selected_sha256)-and$handoff.selected_bytes-eq$ticket.selected_bytes-and$handoff.range_count-eq$ticket.range_count-and$ticket.range_count-eq@($plan.ranges).Count-and$result.selected_bytes-eq$ticket.selected_bytes-and$result.journal_bytes-eq$ticket.journal_length) 'Handoff and selected ticket are inconsistent.'
 Need ($final.success-eq$true-and$null-eq$final.error-and$final.rollback_closed-eq$true-and$final.general_conversion_qualified-eq$false-and$final.mount_paths_preserved-eq$true-and$null-eq$final.mount_paths_error) 'Native finalization is incomplete.'
 Need ($request.experiment_id-ceq$engine-and$request.pair.source.disk_number-eq1-and$request.pair.source.identity.disk_guid-ceq'1b191872-c372-41ee-a416-e18863996f54'-and$request.pair.source.identity.partition_guid-ceq'f06075a8-67a2-46b9-8fac-4af4da809617'-and$request.pair.source.identity.partition_number-eq2-and$request.pair.source.identity.partition_bytes-eq55834574848) 'Archived source identity differs from the admitted lab partition.'
 Need ((SameBinding $request.pair.source $final.native.pair.source)-and(SameBinding $request.pair.source $final.native.native.binding)-and(SameBinding $request.pair.source $final.mount_paths_after.binding)) 'Final native source binding differs.'
 Need ($final.native.native.before.disk_attributes-eq0-and$final.native.native.after.disk_attributes-eq0) 'Native observation was not of an online writable completed target.'
 Need ($final.mount_paths_after.all_paths_resolve_to_bound_volume-eq$true-and(SameArray $verification.expected_mount_paths @('F:\'))-and(SameArray $final.mount_paths_after.paths $verification.expected_mount_paths)) 'Original F mount path was not preserved.'
 $label=$final.label_restoration
 Need ($label.success-eq$true-and$null-eq$label.error-and$label.flushed-eq$true-and$label.readback_matches-eq$true-and$label.after.filesystem-ceq'ReFS'-and(SameArray $label.desired.utf16 $verification.expected_source_label.utf16)-and(SameArray $label.after.label.utf16 $verification.expected_source_label.utf16)) 'ReFS label readback differs.'
 $nativeByPath=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
 foreach($object in @($final.native.native.objects)){$key=PathKey $object.components;Need (-not$nativeByPath.ContainsKey($key)) 'Duplicate native path.';$nativeByPath.Add($key,$object)}
 $expectedKeys=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 $hashes=0;$userFiles=0;$userBytes=0L
 foreach($object in @($expected.objects)){
  $key=PathKey $object.path
  Need ($expectedKeys.Add($key)-and$nativeByPath.ContainsKey($key)) 'Duplicate expected path or missing native object.'
  $native=$nativeByPath[$key]
  if(-not$object.directory){
   Need ($object.sha256-is[string]-and$object.sha256-cmatch '\A[0-9a-f]{32}\z'-and$native.logical_sha256-ceq$object.sha256) ('Logical content digest differs: '+$key)
   $hashes++
   if(@($object.path).Count-gt0-and$object.path[0]-cne'System Volume Information'){$userFiles++;$userBytes+=[long]$object.length}
  }else{Need ($null-eq$native.logical_sha256) ('Directory unexpectedly has a content digest: '+$key)}
 }
 Need ($nativeByPath.Count-eq$expectedKeys.Count-and$hashes-eq@($final.native.native.objects|Where-Object {$null-ne$_.logical_sha256}).Count) 'Native namespace/content set is not exact.'
 $pins=[ordered]@{}
 foreach($key in @('run\conversion\result.json','run\conversion\finalization.json','run\conversion\expectation.json','run\conversion\selected-plan.json','run\conversion\selected-ticket.json','run\conversion\handoff.json','stage\native-process.json','stage\native-terminal.json','stage\wrapper-failed.json')){$pins[$key]=$files[$key].sha256}
 $receipt=[ordered]@{
  schema_version=1;kind='derived-archived-allocation-conversion-observation';success=$true
  run_id=$RunId;engine_run_id=$engine;source_commit=$SourceCommit;source_commit_crosschecked_with_sealed_manifest=$true;executable_sha256=$ExecutableSha256;build_reproducibility_claimed=$false
  archive_directory=$root;inventory_sha256=$inventoryFile.sha256;checked_archive_files=$files.Count;checked_archive_bytes=$archivedBytes;retained_originals_not_opened=$skipped
  native_exit=0;original_wrapper_exit=1;original_wrapper_failure_preserved=$true;failure_phase=$failure.phase;old_observer_limit_bytes=4MB;observer_record_limit_bytes=$limit;finalization_record_bytes=$files['run\conversion\finalization.json'].bytes
  native_objects=$nativeByPath.Count;complete_logical_hashes=$hashes;user_files=$userFiles;user_logical_bytes=$userBytes
  exact_namespace_matched=$true;file_content_algorithm='xxh3-128';label_readback_verified=$true;mount_path_preserved='F:\';handoff_replay_closed=$true
  selected_bytes=$result.selected_bytes;packed_bytes=$result.packed_bytes;journal_bytes=$result.journal_bytes;new_zero_bytes=$result.new_zero_bytes;new_copy_bytes=$result.new_copy_bytes
  free_space_contents_compared=$false;whole_image_verified=$false;mutation_reboot_qualified=$false;recovery_qualified=$false;general_conversion_qualified=$false;ownership_authority_granted=$false;source_or_recovery_authority_granted=$false
  scope='Experimental result observation from archived bytes only; original guest artifacts, journal payload and current disk state are not opened.'
  pins=$pins;utc=[DateTime]::UtcNow.ToString('o')
 }
 $output=[IO.Path]::GetFullPath($OutputPath)
 Need ($output-cmatch '\A[A-Za-z]:\\'-and-not(Test-Path -LiteralPath $output)) 'Receipt output must be a fresh local file.'
 $null=PlainPath ([IO.Path]::GetDirectoryName($output)) $true
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($receipt|ConvertTo-Json -Depth 8))
 Need ($bytes.Length-le1MB) 'Derived receipt exceeds one MiB.'
 $file=[IO.File]::Open($output,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 [pscustomobject]@{success=$true;output=$output;native_objects=$nativeByPath.Count;complete_logical_hashes=$hashes;original_wrapper_exit=1;native_exit=0}
}finally{foreach($file in $held){$file.Dispose()}}
