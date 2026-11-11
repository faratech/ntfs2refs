# Offline measurement of already completed, pinned reports only. No VM, device,
# source image, journal or packed-payload access; no conversion/recovery authority.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourceBasis,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$SourceBasisSha256,
    [Parameter(Mandatory)][string]$Expectation,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ExpectationSha256,
    [Parameter(Mandatory)][string]$Finalization,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$FinalizationSha256,
    [Parameter(Mandatory)][string]$ConversionResult,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ConversionResultSha256,
    [Parameter(Mandatory)][string]$Output
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$artifactRoot=[IO.Path]::GetFullPath((Join-Path (Split-Path $PSScriptRoot -Parent) '.lab')).TrimEnd('\')+'\'
$held=[Collections.Generic.List[IO.FileStream]]::new()
$pins=[Collections.Generic.List[object]]::new()
$cluster=[long]4096
$maximumIntervals=8192

function Need([bool]$Condition,[string]$Message){if(-not$Condition){throw $Message}}
function Number($Value,[string]$Name){
    Need ($null -ne $Value -and $Value -isnot [bool] -and $Value -isnot [string] -and $Value -isnot [double] -and $Value -isnot [single]) ('Integer required: '+$Name)
    $n=[decimal]$Value
    Need ($n -ge 0 -and $n -le [long]::MaxValue -and $n -eq [decimal]::Truncate($n)) ('Unsigned bounded integer required: '+$Name)
    [long]$n
}
function Add([long]$A,[long]$B){$v=[decimal]$A+[decimal]$B;Need ($A -ge 0 -and $B -ge 0 -and $v -le [long]::MaxValue) 'Byte addition overflow.';[long]$v}
function Multiply([long]$A,[long]$B){$v=[decimal]$A*[decimal]$B;Need ($A -ge 0 -and $B -ge 0 -and $v -le [long]::MaxValue) 'Byte multiplication overflow.';[long]$v}
function Field($Object,[string]$Name){$p=$Object.PSObject.Properties[$Name];if($null -ne $p){$p.Value}}
function OrdinaryPath([string]$Path,[bool]$Fresh){
    $full=[IO.Path]::GetFullPath($Path)
    Need ($full.StartsWith($artifactRoot,[StringComparison]::OrdinalIgnoreCase) -and $full.EndsWith('.json',[StringComparison]::OrdinalIgnoreCase) -and $full.Substring(3).IndexOf(':') -lt 0) 'Only host .lab JSON artifact paths are accepted.'
    Need (-not($Path.Contains('..') -or $Path.Contains('/') -or $Path.Contains([char]0))) 'Ambiguous artifact path.'
    if($Fresh){Need (-not(Test-Path -LiteralPath $full)) 'Fresh output required.';$cursor=Split-Path $full -Parent}else{$cursor=$full}
    while($cursor){$item=Get-Item -LiteralPath $cursor -Force;Need (-not($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Reparse artifact ancestry refused.';$next=Split-Path $cursor -Parent;if($next -eq $cursor){break};$cursor=$next}
    $full
}
function ReadPinned([string]$Path,[string]$Pin){
    Need ($Pin -cmatch '\A[0-9a-f]{64}\z') 'Canonical lowercase SHA-256 required.'
    $full=OrdinaryPath $Path $false;$meta=Get-Item -LiteralPath $full -Force
    Need (-not$meta.PSIsContainer -and $meta.Length -gt 0 -and $meta.Length -le 8MB) 'JSON input exceeds its eight-MiB bound.'
    $file=[IO.File]::Open($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$held.Add($file)
    Need ($file.Length -eq $meta.Length) 'Artifact length changed at open.'
    $sha=[Security.Cryptography.SHA256]::Create();try{$hash=[BitConverter]::ToString($sha.ComputeHash($file)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
    Need ($hash -ceq $Pin -and $file.Length -eq $meta.Length) 'Artifact pin/length differs.';$file.Position=0
    $reader=[IO.StreamReader]::new($file,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true)
    try{$value=$reader.ReadToEnd()|ConvertFrom-Json}finally{$reader.Dispose()}
    $pins.Add([pscustomobject]@{path=$full;bytes=$file.Length;sha256=$hash})
    $value
}
function Key($Components){
    $parts=@($Components);Need ($parts.Count -le 32) 'Path depth exceeds report bound.'
    foreach($part in $parts){Need ($part -is [string] -and $part.Length -gt 0 -and $part.Length -le 255 -and $part.IndexOfAny([char[]]@([char]0,'\','/',':')) -lt 0) 'Invalid logical path component.'}
    $parts -join '\'
}
function Standard($Snapshot){
    $q=@($Snapshot.queries|Where-Object {$_.class -eq 1})
    Need ($q.Count -eq 1 -and $null -eq $q[0].native_error -and @($q[0].bytes).Count -eq 24) 'Complete native FILE_STANDARD_INFO required.'
    [byte[]]$b=$q[0].bytes
    Need ([BitConverter]::ToInt64($b,0) -ge 0 -and [BitConverter]::ToInt64($b,8) -ge 0 -and $b[20] -eq 0 -and $b[21] -in @(0,1)) 'Invalid native standard information.'
    [pscustomobject]@{bytes=$b;allocation=[BitConverter]::ToInt64($b,0);eof=[BitConverter]::ToInt64($b,8);directory=($b[21] -eq 1)}
}
function TargetRuns($Observed,[long]$Length,[long]$PartitionBytes){
    [byte[]]$b=$Observed.retrieval
    if($Observed.resident_data -eq $true -or $Length -eq 0){Need ($b.Length -eq 0) 'Resident/empty target has unexpected physical retrieval data.';return}
    Need ($Observed.resident_data -is [bool] -and $b.Length -ge 32 -and $b.Length -le 1048592) 'Bounded complete retrieval map required.'
    $count=[BitConverter]::ToUInt32($b,0)
    Need ($count -ge 1 -and $count -le 65536 -and $b.Length -eq (16+16*[long]$count) -and [BitConverter]::ToUInt32($b,4) -eq 0 -and [BitConverter]::ToInt64($b,8) -eq 0) 'Incomplete/invalid retrieval header.'
    $runs=[Collections.Generic.List[object]]::new();$vcn=[long]0
    for($i=0;$i -lt $count;$i++){
        $next=[BitConverter]::ToInt64($b,16+16*$i);$lcn=[BitConverter]::ToInt64($b,24+16*$i)
        Need ($next -gt $vcn -and $lcn -ge 0) 'Sparse, negative or nonadvancing target extent is unsupported.'
        $logical=Multiply $vcn $cluster;$end=Multiply $next $cluster;$physical=Multiply $lcn $cluster
        Need ((Add $physical ($end-$logical)) -le $PartitionBytes) 'Target physical extent escapes converted partition.'
        $runs.Add([pscustomobject]@{logical=$logical;end=$end;physical=$physical});$vcn=$next
    }
    Need ($runs[$runs.Count-1].end -ge $Length) 'Target mapping does not cover logical EOF.'
    $runs.ToArray()
}
function PhysicalAt($Runs,[long]$Logical){
    foreach($run in $Runs){if($run.logical -le $Logical -and $Logical -lt $run.end){return (Add $run.physical ($Logical-$run.logical))}}
    throw 'Logical interval lacks source physical ownership.'
}

try{
    $out=OrdinaryPath $Output $true
    $basis=ReadPinned $SourceBasis $SourceBasisSha256
    $expected=ReadPinned $Expectation $ExpectationSha256
    $final=ReadPinned $Finalization $FinalizationSha256
    $completion=ReadPinned $ConversionResult $ConversionResultSha256
    Need ($final.success -is [bool] -and $final.success -and $final.rollback_closed -is [bool] -and $final.rollback_closed -and $null -eq $final.error -and $null -ne $final.native) 'Only completed successful native finalization is accepted.'
    Need ($completion.schema_version -eq 1 -and $completion.kind -ceq 'experimental-certificate-backed-composite-conversion') 'Completed owning composite-conversion result required.'
    foreach($flag in @('success','source_admitted','rollback_closed','complete_native_address_space_compared')){Need ($completion.$flag -is [bool] -and $completion.$flag) ('Completed conversion receipt lacks '+$flag)}
    Need ($basis.source_sha256 -cmatch '\A[0-9a-f]{64}\z' -and $completion.comparison.source_sha256 -ceq $basis.source_sha256 -and $completion.expected_tree_sha256 -ceq $ExpectationSha256) 'Completed conversion is not bound to these exact frozen source/expectation inputs.'
    Need ($null -ne $final.handoff -and $final.handoff.operation -ceq 'handoff-recorded' -and $final.handoff.handoff_recorded -is [bool] -and $final.handoff.handoff_recorded -and $final.handoff.target_sha256 -ceq $completion.comparison.shadow_sha256) 'Successful finalization and completed conversion postimage differ.'
    $native=$final.native.native;$original=$basis.freeze_observation.mounted_ntfs.binding;$converted=$final.native.pair.source
    Need ((Number $native.base_sectors 'retrieval base sectors') -eq 0) 'Nonzero retrieval base requires a separately implemented coordinate model.'
    # NtfsInspection deliberately leaves inventory_complete=false: raw decoding
    # cannot itself establish the later native/admission gates. Keep that flag
    # as observed; bind the real completed owning conversion above, and require
    # the raw scan/reconciliation evidence below instead of relabeling it true.
    Need ($basis.ntfs.schema_version -eq 1 -and $basis.ntfs.inventory_complete -is [bool]) 'Known raw NTFS inspection schema required.'
    $scanned=Number $basis.ntfs.records_scanned 'records scanned';$slots=Number $basis.ntfs.mft_record_count 'MFT slots'
    Need ($scanned -gt 0 -and $scanned -eq @($basis.ntfs.files).Count -and $scanned -le $slots -and $slots -le 1000000) 'Frozen raw record accounting is incomplete or unsupported.'
    Need ($basis.ntfs.allocation_reconciliation.status -ceq 'consistent_raw_model' -and $basis.ntfs.namespace_reconciliation.status -ceq 'consistent_raw_model') 'Consistent frozen allocation and namespace reconcilations required.'
    Need ($basis.canonical_inspection_sha256 -cmatch '\A[0-9a-f]{64}\z' -and $basis.backups.inspection_fingerprint -ceq $basis.canonical_inspection_sha256 -and $basis.log_restart.inspection_fingerprint -ceq $basis.canonical_inspection_sha256 -and $basis.backups.mirrored_records -eq 4 -and $basis.backups.primary_boot_sha256 -ceq $basis.backups.backup_boot_sha256 -and $basis.log_restart.restart.candidate_clean_dismount -is [bool] -and $basis.log_restart.restart.candidate_clean_dismount) 'Backup/log evidence is not bound to the same frozen inspection.'
    Need ($basis.freeze_observation.frozen_state.disk_attributes -eq 3) 'Source-basis observation was not frozen offline/read-only.'
    Need ([guid]$original.identity.disk_guid -eq [guid]$converted.identity.disk_guid -and [guid]$original.identity.partition_guid -eq [guid]$converted.identity.partition_guid -and $original.disk_number -eq $converted.disk_number) 'Frozen/native source partition identities differ.'
    foreach($field in @('partition_number','disk_bytes','partition_offset','partition_bytes','logical_sector_bytes','physical_sector_bytes')){Need ((Number $original.identity.$field $field) -eq (Number $converted.identity.$field $field)) 'Frozen/native physical geometry differs.'}
    Need ([guid]$native.binding.identity.disk_guid -eq [guid]$converted.identity.disk_guid -and [guid]$native.binding.identity.partition_guid -eq [guid]$converted.identity.partition_guid -and $native.binding.disk_number -eq $converted.disk_number) 'Native report is not observing the converted original partition.'
    foreach($field in @('partition_number','disk_bytes','partition_offset','partition_bytes','logical_sector_bytes','physical_sector_bytes')){Need ((Number $native.binding.identity.$field $field) -eq (Number $converted.identity.$field $field)) 'Native report partition geometry differs from its converted binding.'}
    $partitionBytes=Number $converted.identity.partition_bytes 'partition bytes';$sourceCluster=Number $basis.ntfs.geometry.cluster_size 'NTFS cluster bytes'
    Need ((Number $completion.comparison.expected_length 'completed comparison length') -eq $partitionBytes -and $completion.comparison.sector_size -eq 4096 -and $completion.comparison.schema_version -eq 2 -and (Number $basis.backups.partition_length 'backup partition length') -eq $partitionBytes) 'Completed comparison/backup partition profile differs.'
    Need ($sourceCluster -in @(4096,65536) -and (Number $basis.ntfs.geometry.bytes_per_sector 'NTFS sector bytes') -eq 512 -and (Number $converted.identity.logical_sector_bytes 'logical sector bytes') -eq 512) 'Only the supported 512-byte sector, NTFS4K/64K to native ReFS4K profile is implemented.'
    $files=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach($file in $basis.ntfs.files){$id=([string](Number $file.record_number 'MFT number'))+':'+([string](Number $file.sequence_number 'MFT sequence'));Need (-not$files.ContainsKey($id)) 'Duplicate frozen identity.';$files.Add($id,$file)}
    $observations=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach($item in $native.objects){$key=Key $item.components;Need (-not$observations.ContainsKey($key)) 'Duplicate native logical path.';$observations.Add($key,$item)}
    Need (@($expected.objects).Count -le 1280 -and $observations.Count -eq @($expected.objects).Count) 'Expected/native object count differs or exceeds bounded tree profile.'
    $rows=[Collections.Generic.List[object]]::new();$excluded=[Collections.Generic.List[object]]::new();$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $totals=[ordered]@{user_files=0;logical_bytes=[long]0;aligned_initialized_nonresident_bytes=[long]0;retained_aligned_bytes=[long]0;relocated_aligned_bytes=[long]0;resident_logical_bytes=[long]0;partial_initialized_tail_bytes=[long]0;uninitialized_logical_bytes=[long]0}
    $allLogical=[long]0;$intervalCount=0
    foreach($object in $expected.objects){
        $key=Key $object.path;Need ($seen.Add($key) -and $observations.ContainsKey($key)) 'Expected path duplicate or absent from native report.'
        $observed=$observations[$key];$before=Standard $observed.before;$after=Standard $observed.after
        Need ([Convert]::ToBase64String($before.bytes) -ceq [Convert]::ToBase64String($after.bytes) -and $object.directory -is [bool] -and $before.directory -eq $object.directory) 'Native standard metadata is unstable or type differs.'
        $length=Number $object.length 'expected length';Need ($before.eof -eq $length) 'Native logical EOF differs from expectation.'
        $allLogical=Add $allLogical $length
        $id=([string](Number $object.record_number 'expected MFT number'))+':'+([string](Number $object.sequence_number 'expected MFT sequence'))
        Need ($files.ContainsKey($id) -and $files[$id].is_directory -eq $object.directory) 'Expected object is not bound to the frozen MFT identity/type.'
        if($object.directory){Need ($length -eq 0) 'Directory has payload length.';continue}
        if(@($object.path).Count -gt 0 -and [string]::Equals($object.path[0],'System Volume Information',[StringComparison]::OrdinalIgnoreCase)){$excluded.Add([pscustomobject]@{path=$key;logical_bytes=$length;reason='filesystem-managed SVI subtree, including normalized formatter/indexer cache; excluded from user payload totals'});continue}
        $file=$files[$id];$streams=@($file.streams)
        Need ($streams.Count -eq 1 -and $streams[0].name -ceq '' -and @($streams[0].name_utf16).Count -eq 0) 'Exactly one unnamed source stream is supported.'
        $stream=$streams[0];Need ($stream.resident -is [bool] -and (Number $stream.flags 'source flags') -eq 0 -and $stream.logical_hash_status -ceq 'complete') 'Encoded/unknown source stream or incomplete logical digest.'
        Need ((Number $stream.logical_size 'source logical size') -eq $length -and $object.sha256 -cmatch '\A[0-9a-f]{64}\z' -and $stream.logical_sha256 -ceq $object.sha256 -and $observed.logical_sha256 -ceq $object.sha256) 'Frozen/expected/native logical contents differ.'
        $initialized=Number $stream.initialized_size 'initialized bytes';Need ($initialized -le $length) 'Initialized data exceeds EOF.'
        $prefix=if($stream.resident){[long]0}else{[long]([decimal]::Floor([decimal]$initialized/$cluster)*$cluster)}
        $sourceRuns=[Collections.Generic.List[object]]::new();$covered=[long]0
        if(-not$stream.resident){
            foreach($extent in $stream.extents){$start=Number $extent.logical_offset 'source VCN bytes';$physical=Number $extent.physical_offset 'source physical bytes';$count=Number $extent.length 'source extent bytes';Need ($start -eq $covered -and $count -gt 0 -and $start%$sourceCluster -eq 0 -and $physical%$sourceCluster -eq 0 -and $count%$sourceCluster -eq 0) 'Source extent map is sparse, discontinuous or unaligned.';$covered=Add $start $count;Need ((Add $physical $count) -le $partitionBytes) 'Source physical extent escapes partition.';$sourceRuns.Add([pscustomobject]@{logical=$start;end=$covered;physical=$physical})}
            Need ($covered -eq (Number $stream.allocated_size 'source allocated bytes') -and $covered -ge $length) 'Source allocation coverage differs.'
        }
        $hintOffset=Field $object 'source_offset';$hintExtents=@(Field $object 'source_extents')
        Need ($null -eq $hintOffset -or $hintExtents.Count -eq 0) 'Expected source coordinate forms conflict.'
        $hints=if($null -ne $hintOffset){@([pscustomobject]@{logical_offset=0;physical_offset=$hintOffset;length=$length})}else{$hintExtents}
        $hintEnd=[long]0
        foreach($hint in $hints){$start=Number $hint.logical_offset 'hint logical bytes';$physical=Number $hint.physical_offset 'hint physical bytes';$count=Number $hint.length 'hint bytes';Need ($start -eq $hintEnd -and $count -gt 0 -and $count%$cluster -eq 0 -and $start%$cluster -eq 0 -and $physical%$cluster -eq 0) 'Expected source hint is not a contiguous aligned prefix.';$hintEnd=Add $start $count;Need ($hintEnd -le $prefix) 'Expected hint exceeds initialized aligned source prefix.';$at=$start;while($at -lt $hintEnd){$match=@($sourceRuns|Where-Object {$_.logical -le $at -and $at -lt $_.end});Need ($match.Count -eq 1 -and (PhysicalAt $sourceRuns $at) -eq (Add $physical ($at-$start))) 'Expected source hint differs from raw NTFS byte extents.';$at=[Math]::Min($hintEnd,[long]$match[0].end)}}
        $targetRuns=@(TargetRuns $observed $length $partitionBytes)
        if($targetRuns.Count -gt 0){Need ($targetRuns[$targetRuns.Count-1].end -eq $before.allocation) 'Native retrieval allocation differs from FILE_STANDARD_INFO.'}
        elseif($length -gt 0){Need ($observed.resident_data -is [bool] -and $observed.resident_data -and $before.allocation -lt $cluster -and $before.allocation -ge $length) 'Nonempty target lacks a valid resident or physical layout.'}
        $segments=[Collections.Generic.List[object]]::new();$si=0;$ti=0;$cursor=[long]0;$retained=[long]0;$relocated=[long]0
        while($cursor -lt $prefix){
            while($si -lt $sourceRuns.Count -and $sourceRuns[$si].end -le $cursor){$si++};while($ti -lt $targetRuns.Count -and $targetRuns[$ti].end -le $cursor){$ti++}
            Need ($si -lt $sourceRuns.Count -and $ti -lt $targetRuns.Count -and $sourceRuns[$si].logical -le $cursor -and $targetRuns[$ti].logical -le $cursor) 'Aligned logical prefix lacks both physical maps.'
            $stop=[Math]::Min($prefix,[Math]::Min([long]$sourceRuns[$si].end,[long]$targetRuns[$ti].end));$count=$stop-$cursor
            $sourcePhysical=Add $sourceRuns[$si].physical ($cursor-$sourceRuns[$si].logical);$targetPhysical=Add $targetRuns[$ti].physical ($cursor-$targetRuns[$ti].logical)
            Need ($count -gt 0 -and $count%$cluster -eq 0) 'Interval join failed to advance on aligned boundaries.'
            $disposition=if($sourcePhysical -eq $targetPhysical){$retained=Add $retained $count;'same_physical_bytes'}else{$relocated=Add $relocated $count;'different_physical_bytes'}
            $intervalCount++;Need ($intervalCount -le $maximumIntervals) 'Placement interval report exceeds8192 intervals; no partial report emitted.'
            $segments.Add([pscustomobject]@{logical_offset=$cursor;length=$count;source_volume_byte_offset=$sourcePhysical;target_volume_byte_offset=$targetPhysical;disposition=$disposition});$cursor=$stop
        }
        $resident=if($stream.resident){$length}else{[long]0};$tail=if($stream.resident){[long]0}else{$initialized-$prefix};$uninitialized=if($stream.resident){[long]0}else{$length-$initialized}
        Need ((Add (Add $retained $relocated) (Add $resident (Add $tail $uninitialized))) -eq $length) 'User logical byte dispositions do not reconcile.'
        $totals.user_files++;foreach($entry in @(@('logical_bytes',$length),@('aligned_initialized_nonresident_bytes',$prefix),@('retained_aligned_bytes',$retained),@('relocated_aligned_bytes',$relocated),@('resident_logical_bytes',$resident),@('partial_initialized_tail_bytes',$tail),@('uninitialized_logical_bytes',$uninitialized))){$totals[$entry[0]]=Add $totals[$entry[0]] $entry[1]}
        $rows.Add([pscustomobject]@{path=$key;record_number=$object.record_number;sequence_number=$object.sequence_number;logical_bytes=$length;logical_sha256=$object.sha256;source_resident=$stream.resident;target_resident=$observed.resident_data;source_hint_bytes_crosschecked=$hintEnd;retained_aligned_bytes=$retained;relocated_aligned_bytes=$relocated;resident_logical_bytes=$resident;partial_initialized_tail_bytes=$tail;uninitialized_logical_bytes=$uninitialized;intervals=$segments.ToArray()})
    }
    Need ($allLogical -eq (Number $expected.logical_bytes 'expected logical total')) 'Expected tree total differs.'
    $report=[ordered]@{schema_version=1;kind='pinned-completed-json-user-payload-placement';inputs=$pins.ToArray();source_sha256=$basis.source_sha256;raw_inventory_complete_flag=$basis.ntfs.inventory_complete;source_context_scope='pinned completed owning conversion result plus matching frozen raw scan, namespace/allocation and backup/log observations; no admission capability recreated';source_partition=$original;converted_partition=$converted;source_cluster_bytes=$sourceCluster;target_cluster_bytes=$cluster;target_retrieval_base_sectors=0;coordinate_system='logical stream bytes joined to volume-relative physical bytes; NTFS byte extents versus native ReFS VCN/LCN multiplied by4096';mapping_observation_scope='finalization.native.native verification observation; label restoration or later native activity is not re-observed';totals=$totals;files=$rows.ToArray();excluded_filesystem_managed_svi=$excluded.ToArray();comparison_retained_ranges_used=$false;source_images_opened=$false;raw_devices_opened=$false;journals_opened=$false;packed_payloads_opened=$false;vm_actions_performed=$false;data_writes_or_payload_copy_avoidance_proven=$false;current_physical_positions_proven=$false;execution_authorized=$false;conversion_qualified=$false;limitations=@('Same mapped physical bytes and matching complete logical hashes are observations from pinned reports, not proof of which bytes the converter wrote.','Resident bytes, partial initialized tails and uninitialized logical bytes are separate from aligned nonresident retention.','Filesystem-managed SVI is explicitly excluded from user payload totals.','The raw inventory_complete flag remains false by parser design; the separately pinned owning result records completed source admission.','This adapter does not reproduce source admission, native mapping-page provenance, allocator ownership or recovery authority.');observed_utc=[DateTime]::UtcNow.ToString('o')}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($report|ConvertTo-Json -Depth 16));Need ($bytes.Length -le 4MB) 'Output exceeds four-MiB bound; no partial report emitted.'
    $file=[IO.File]::Open($out,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
    [pscustomobject]@{output=$out;sha256=(Get-FileHash -LiteralPath $out).Hash.ToLowerInvariant();totals=$totals;execution_authorized=$false}|ConvertTo-Json -Depth 4
}finally{for($i=$held.Count-1;$i -ge 0;$i--){$held[$i].Dispose()}}
