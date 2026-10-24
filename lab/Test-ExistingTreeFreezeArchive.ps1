<# Read-only validation of a naturally populated source and its native freeze
   archive. This checks experiment evidence; it cannot authorize conversion. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Directory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Require([bool]$Condition,[string]$Reason){if(-not$Condition){throw $Reason}}
$dir=Get-Item -LiteralPath $Directory -Force
Require ($dir.PSIsContainer-and-not($dir.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Ordinary archive directory required.'
function Json([string]$Name,[long]$Maximum=2MB){$p=Join-Path $dir.FullName $Name;$i=Get-Item -LiteralPath $p -Force;Require (-not$i.PSIsContainer-and-not($i.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$i.Length-le$Maximum) ('Invalid bounded artifact: '+$Name);Get-Content -LiteralPath $p -Raw|ConvertFrom-Json}
function Hash([string]$Name){(Get-FileHash -LiteralPath (Join-Path $dir.FullName $Name)).Hash.ToLowerInvariant()}
$request=Json 'freeze-request.json';$population=Json 'population.json';$first=Json 'freeze.json';$second=Json 'reopen.json'
Require ($population.status-ceq'populated-before-converter'-and$population.extentPlacementOperations-eq0-and-not$population.conversionInvoked-and-not$population.sourceFileDataCopiedToShadow) 'Source was not independently populated before conversion.'
Require ($population.files.Count-eq4-and$population.directories.Count-eq3-and$population.logicalBytes-eq524288) 'Unexpected source corpus.'
$raw=$null
foreach($phase in @('freeze','reopen')){
 $r=if($phase-eq'freeze'){$first}else{$second};$inspection=Json ($phase+'.inspection.json') 64MB
 Require ($r.success-and$r.phase-ceq'complete-source-remains-offline-read-only'-and$r.native_bytes_written-eq0-and-not$r.source_admitted-and-not$r.conversion_qualified) 'Frozen source result is incomplete or overclaims admission.'
 Require ($r.inspection_sha256-ceq(Hash ($phase+'.inspection.json'))) 'Frozen inspection pin differs.'
 Require ($inspection.source.length-eq52GB-and$inspection.source.sha256-ceq$r.basis.source_sha256) 'Inspection/full source binding differs.'
 foreach($snap in @($r.basis.before,$r.basis.after)){
  Require ($snap.disk_attributes-eq3) 'Persistent offline/read-only exclusion was not proven.'
  foreach($field in @('disk_number','volume_guid')){Require ($snap.binding.$field-ceq$request.source.$field) ('Actual source route differs: '+$field)}
  foreach($field in @('disk_guid','partition_guid','partition_number','disk_bytes','partition_offset','partition_bytes','logical_sector_bytes','physical_sector_bytes')){Require ($snap.binding.identity.$field-ceq$request.source.identity.$field) ('Actual source identity differs: '+$field)}
 }
 Require ($r.basis.backups.mirrored_records-eq4-and$r.basis.backups.primary_boot_sha256-ceq$r.basis.backups.backup_boot_sha256) 'Source backups were not verified.'
 Require ($r.native_bytes_read-eq($r.basis.raw_bytes_read+52GB)-and$r.native_bytes_read-ge(3*52GB)) 'Native complete-read accounting differs.'
 if($phase-eq'freeze'){
  $locks=@($r.events|Where-Object operation -eq 'lock-volume');$dismounts=@($r.events|Where-Object operation -eq 'dismount-volume')
  Require ($locks.Count-eq1-and$locks[0].succeeded-and$dismounts.Count-eq1-and$dismounts[0].succeeded) 'Native lock/dismount evidence missing.'
 }else{Require (@($r.events|Where-Object control_code -eq 0x0007c0f4).Count-eq0) 'Reopen repaired exclusion instead of verifying it.'}
 $raw=$inspection.filesystem.details
 Require ($raw.allocation_reconciliation.status-ceq'consistent_raw_model'-and$raw.namespace_reconciliation.status-ceq'consistent_raw_model'-and$raw.security_reconciliation.status-ceq'consistent_raw_model') 'Raw source model is incomplete.'
}
Require ($first.basis.source_sha256-ceq$second.basis.source_sha256) 'Source changed across restart.'
Require ($first.inspection_sha256-ceq$second.inspection_sha256) 'Post-restart inspection changed.'
$indexed=@{};foreach($f in $raw.files){$key='{0}:{1}'-f$f.record_number,$f.sequence_number;Require (-not$indexed.ContainsKey($key)) 'Duplicate source identity.';$indexed[$key]=$f}
function Relative-Name($File){
 $parts=[Collections.Generic.List[string]]::new();$seen=@{};$f=$File
 while($f.record_number-ne5){
  $key='{0}:{1}'-f$f.record_number,$f.sequence_number;Require (-not$seen.ContainsKey($key)-and$parts.Count-le16) 'Cyclic/deep parent chain.';$seen[$key]=$true
  Require ($f.names.Count-eq1-and$f.names[0].namespace-ne2) 'Ambiguous name or unsupported alias.';$n=$f.names[0]
  $decoded=-join@($n.name_utf16|ForEach-Object{[char]$_});Require ($decoded-ceq$n.name) 'Filename display differs from exact UTF-16.'
  $parts.Insert(0,$decoded);$parent='{0}:{1}'-f$n.parent_record_number,$n.parent_sequence_number
  Require ($indexed.ContainsKey($parent)-and$indexed[$parent].is_directory) 'Missing/stale/non-directory parent.';$f=$indexed[$parent]
 }
 return ($parts-join'\')
}
$expected=@{};foreach($f in $population.files){Require (-not$expected.ContainsKey($f.relativePath)) 'Duplicate population path.';$expected[$f.relativePath]=$f}
$matched=0;$physical=@();$observed=@{};$observedDirectories=@{}
foreach($f in $raw.files|Where-Object metadata_role -eq outside_extend_candidate){
 $name=Relative-Name $f
 if($f.is_directory){Require ($name-cin$population.directories-and-not$observedDirectories.ContainsKey($name)) ('Unexpected/duplicate source directory: '+$name);$observedDirectories[$name]=$true;continue}
 Require ($expected.ContainsKey($name)) ('Unexpected source file: '+$name)
 Require (-not$observed.ContainsKey($name)) ('Duplicate source file path: '+$name);$observed[$name]=$true
 Require ($f.streams.Count-eq1-and$f.streams[0].name_utf16.Count-eq0) 'Unexpected source streams.'
 $s=$f.streams[0];$e=$expected[$name]
 Require ($s.logical_size-eq$e.length-and$s.logical_sha256-ceq$e.sha256-and$s.logical_hash_status-ceq'complete') ('Source payload differs: '+$name)
 Require (-not$s.resident-and$s.flags-eq0-and$s.logical_size-eq$s.initialized_size-and$s.logical_size-eq$s.allocated_size-and$s.extents.Count-eq1-and$null-ne$s.extents[0].physical_offset) 'Source is outside the plain bounded profile.'
 $physical+=@([pscustomobject]@{path=$name;record=$f.record_number;sourceLcn=$s.extents[0].physical_offset/4096;length=$s.logical_size;sha256=$s.logical_sha256});$matched++
}
Require ($matched-eq4-and$observed.Count-eq$expected.Count-and$observedDirectories.Count-eq3) 'A populated file or directory was omitted.'
$foreign=Json 'foreign.json';Require (-not$foreign.success-and$foreign.phase-ceq'open-source'-and$foreign.error-ceq'disk GPT identity differs') 'Foreign device refusal missing.'
Require (@($foreign.events|Where-Object control_code -eq 0x0007c0f4).Count-eq0) 'Foreign-device probe changed exclusion.'
[pscustomobject]@{status='existing-tree-freeze-archive-verified';sourceSha256=$first.basis.source_sha256;matchedFiles=$matched;logicalBytes=524288;nativePayloadWrites=0;sourcePlacementOperations=0;sourceExtents=$physical;sourceAdmitted=$false;conversionQualified=$false}
