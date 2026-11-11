# Dispatches the actual public one-command minimize-scratch path in an already
# restored owning guest. No power, restore, checkpoint, recovery or cleanup.
# Supported fixtures: grown golden8329 (six disks), or preparedcb (seven disks
# with its pinned original managed shadow). The public CLI creates its own new
# shadow. Root supplies a full baseline from the selected source checkpoint.
# Every original logical digest remains independent of product expectations.
# Semantic drift (including root modification/MFT times) fails the observer;
# the native move ledger authorizes only independently verified mapping changes.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ToolsetManifest,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ToolsetManifestSha256,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit,
    [Parameter(Mandatory)][guid]$ExpectedParent,
    [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds,
    [Parameter(Mandatory)][string]$FreshBaselineManifestPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$FreshBaselineManifestSha256,
    [Parameter(Mandatory)][string]$DirectoryGrowthReceiptPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$DirectoryGrowthReceiptSha256,
    [Parameter(Mandatory)][ValidateRange(1,50000000000)][long]$ForecastAdditionalBytes,
    [string]$PreparedManagedReceiptPath,
    [ValidatePattern('\A[0-9a-f]{64}\z')][string]$PreparedManagedReceiptSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs'
$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$vmId=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$golden=[guid]'83290a28-1e83-4eb2-a4d3-b0e9f5a8d63b'
$prepared=[guid]'cb802669-903c-48cc-99e5-57976b149e7d'
$ids=@($ExpectedCheckpointIds|ForEach-Object {$_.ToString('D')})
$run=[guid]::NewGuid().ToString('N')
$root=Join-Path $base ('public-min-scratch-'+$run)
$stage='C:\ntfs2refs\public-min-scratch-'+$run
$task='N2R-PublicMinScratch-'+$run
$session=$null;$baseline=$null;$created=$false
$held=[Collections.Generic.List[IO.FileStream]]::new()
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
. (Join-Path $PSScriptRoot 'SourceBaselineSupport.ps1')
function Save([string]$Name,$Value){
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 32))
    Need ($bytes.Length-le4MB) 'Bounded host receipt required.'
    $f=[IO.File]::Open((Join-Path $root $Name),'CreateNew','Write','Read')
    try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
}
function HostGuard{
    $v=Get-VM -Id $vmId -ErrorAction Stop
    $actual=@(Get-VMSnapshot -VM $v -ErrorAction Stop|ForEach-Object {$_.Id.ToString('D')})
    Need ($v.Name-ceq'ntfs2refs-streaming-v2-20261027'-and$v.State.ToString()-ceq'Running'-and
        $v.ParentSnapshotId-eq$ExpectedParent-and$v.MemoryStartup-eq4GB-and$v.MemoryAssigned-eq4GB-and
        -not$v.DynamicMemoryEnabled-and(Get-VMProcessor -VM $v).Count-eq4-and
        @(Get-VMNetworkAdapter -VM $v).Count-eq0-and$actual.Count-eq$ids.Count-and
        @($ids|Where-Object {$_-notin$actual}).Count-eq0) 'Exact already running source/checkpoint set/4GiB/4CPU/noNIC required.'
}
function HeldScript([string]$Name){
    $path=Join-Path $PSScriptRoot $Name;$file=FreshBaselineOrdinary $path 1MB
    $pin=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $null=OpenFreshBaselineHost $path $pin 1MB $held $false
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    Need ($errors.Count-eq0) ('Pinned helper syntax differs: '+$Name)
    return @{path=$file.FullName;bytes=$file.Length;sha256=$pin;ast=$ast}
}
function LiteralAssignment($Ast,[string]$Name){
    $rows=@($Ast.FindAll({param($n) $n-is[Management.Automation.Language.AssignmentStatementAst]-and
        $n.Left-is[Management.Automation.Language.VariableExpressionAst]-and$n.Left.VariablePath.UserPath-ceq$Name-and
        $n.Right-is[Management.Automation.Language.CommandExpressionAst]-and
        $n.Right.Expression-is[Management.Automation.Language.StringConstantExpressionAst]},$true))
    Need ($rows.Count-eq1) ('One literal '+$Name+' guest/helper assignment required; controllers are never invoked.')
    return $rows[0].Right.Expression.Value
}
function ReplaceOnce([string]$Text,[string]$Old,[string]$New){
    Need (($Text.Split(@($Old),[StringSplitOptions]::None)).Count-eq2) 'Reviewed adaptation must match once.'
    return $Text.Replace($Old,$New)
}
try{
    Need ($ExpectedParent-in@($golden,$prepared)-and$ids.Count-gt0-and$ids.Count-le50-and
        @($ids|Sort-Object -Unique).Count-eq$ids.Count-and$ExpectedParent.ToString('D')-in$ids-and
        [guid]::Empty.ToString('D')-notin$ids) 'Root must already restore golden8329 or preparedcb with the complete exact checkpoint set.'
    $hasPrepared=-not[string]::IsNullOrEmpty($PreparedManagedReceiptPath)
    Need ($hasPrepared-eq(-not[string]::IsNullOrEmpty($PreparedManagedReceiptSha256))-and
        $hasPrepared-eq($ExpectedParent-eq$prepared)) 'Preparedcb requires its pinned original managed receipt; golden requires none.'
    $baseline=ReadFreshLabSourceBaselineHost $FreshBaselineManifestPath $FreshBaselineManifestSha256 $DirectoryGrowthReceiptPath $DirectoryGrowthReceiptSha256 $ExpectedParent $base
    $preparedManaged=$null
    if($hasPrepared){
        Need ($PreparedManagedReceiptPath.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)) 'Lab-local original managed receipt required.'
        $preparedManaged=(OpenFreshBaselineHost $PreparedManagedReceiptPath $PreparedManagedReceiptSha256 1MB $held $true).value
        Need ($preparedManaged.success-and$preparedManaged.kind-ceq'new-owned-native-managed-shadow-smoke'-and
            $preparedManaged.binding.disk_number-eq6-and$preparedManaged.source_writes-eq0-and-not$preparedManaged.source_binding_supplied-and
            $preparedManaged.path-ceq'C:\ntfs2refs\ntfs-owned-preparation-6ec16ed4b4774c13a76b1e282103c66e\managed-shadow\shadow.vhdx') 'Exact idle original prepared shadow required.'
    }
    $manifestFile=FreshBaselineOrdinary $ToolsetManifest 1MB
    Need ($ToolsetManifest.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)-and$manifestFile.Name-ceq'manifest.json') 'Sealed lab-local toolset required.'
    $manifest=(OpenFreshBaselineHost $ToolsetManifest $ToolsetManifestSha256 1MB $held $true).value
    Need ($manifest.schema_version-eq2-and$manifest.kind-ceq'source-free-performance-toolset'-and
        $manifest.source_commit-ceq$SourceCommit-and$manifest.main_source_sha256-ceq'c6bc5c52c8458ee70bd2567a9d8350105aeaa6245448df22675780403e04348b'-and
        @($manifest.tools).Count-eq4) 'Explicit sealed four-role runtime and untouched user main required.'
    $tools=@()
    foreach($name in @('ntfs2refs.exe','lab-convert-native-composite.exe','lab-content-digest.exe','lab-managed-shadow.exe')){
        $rows=@($manifest.tools|Where-Object name -CEQ $name)
        Need ($rows.Count-eq1-and$rows[0].path-ceq(Join-Path $manifestFile.DirectoryName $name)-and
            $rows[0].bytes-gt0-and$rows[0].bytes-le64MB-and$rows[0].sha256-cmatch'\A[0-9a-f]{64}\z') 'Exact bounded runtime roles required.'
        $file=(OpenFreshBaselineHost $rows[0].path $rows[0].sha256 64MB $held $false).item
        Need ($file.Length-eq$rows[0].bytes) 'Runtime length differs.'
        $tools+=@{name=$name;path=$file.FullName;bytes=$file.Length;sha256=$rows[0].sha256}
    }
    $normal=HeldScript 'Start-AllocationBoundedConversion.ps1'
    $performance=HeldScript 'Start-PreparedSourcePerformanceExperiment.ps1'
    $support=HeldScript 'SourceBaselineSupport.ps1'
    $moveSupport=HeldScript 'PublicMinScratchBaselineSupport.ps1'
    $self=HeldScript 'Start-PublicMinScratchExperiment.ps1'
    $body=LiteralAssignment $normal.ast 'body';$tokens=$null;$errors=$null
    $bodyAst=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)
    Need ($errors.Count-eq0) 'Original public guest syntax differs.'
    $definitions=[Collections.Generic.List[string]]::new()
    foreach($node in $bodyAst.EndBlock.Statements){
        if($node-is[Management.Automation.Language.FunctionDefinitionAst]-and
            $node.Name-notin@('ResolveLabContentBaseline','AssertRawContentOrLabExtent','AssertLabOldZeroEncoding')){$definitions.Add($node.Extent.Text)}
    }
    $definitions.Add((LiteralAssignment $performance.ast 'sourceZeroFallback'))
    $definitions.Add((LiteralAssignment $performance.ast 'sourceFreeVerifier'))
    $tries=@($bodyAst.EndBlock.Statements|Where-Object {$_-is[Management.Automation.Language.TryStatementAst]})
    Need ($tries.Count-eq1) 'One existing normal observer block required.'
    $statements=@($tries[0].Body.Statements);$start=-1
    for($i=0;$i-lt$statements.Count;$i++){if($statements[$i].Extent.Text.StartsWith('$oldZeroEncoding=AssertLabOldZeroEncoding',[StringComparison]::Ordinal)){Need ($start-eq-1) 'Unique observer start required.';$start=$i}}
    Need ($start-ge0) 'Existing closed normal observer tail missing.'
    $observer=($statements[$start..($statements.Count-1)]|ForEach-Object {$_.Extent.Text})-join[Environment]::NewLine
    $observer=ReplaceOnce $observer 'AssertLabOldZeroEncoding' 'AssertLabSourceFreeEncoding'
    $observer=ReplaceOnce $observer "kind='allocation-bounded-public-drive-observation'" "kind='public-min-scratch-normal-observation'"
    $observer=ReplaceOnce $observer 'production_qualified=$false;utc=' 'preparation=$script:publicPreparationFacts;performance=$metrics;actual_scratch_encoding=$oldZeroEncoding;production_qualified=$false;utc='
    $observerAst=[Management.Automation.Language.Parser]::ParseInput($observer,[ref]$tokens,[ref]$errors)
    Need ($errors.Count-eq0-and@($observerAst.FindAll({param($n) $n-is[Management.Automation.Language.CommandAst]-and$n.GetCommandName()-in@('Start-Process','Start-ScheduledTask','Set-Disk','Remove-Item')},$true)).Count-eq0) 'Closed observer must not dispatch work or change disk state.'
    Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
    $configuration=Get-LabConfiguration -WorkspaceRoot $workspace;$capacity=Get-LabCapacity -Configuration $configuration
    Need ($capacity.MaximumActualBytes-eq329374052988-and$capacity.MinimumFreeBytes-eq17179869184) 'Fixed storage epoch differs.'
    Assert-LabCapacity -Capacity $capacity -AdditionalBytes $ForecastAdditionalBytes
    HostGuard;Need (-not(Test-Path -LiteralPath $root)) 'Fresh host stage required.'
    New-Item -ItemType Directory -Path $root|Out-Null;$created=$true
    $main=@($tools|Where-Object name -CEQ 'ntfs2refs.exe')[0];$digest=@($tools|Where-Object name -CEQ 'lab-content-digest.exe')[0]
    $c=@{stage=$stage;task=$task;run_id=$run;tools=$tools;source_commit=$SourceCommit;main_bytes=$main.bytes;main_sha256=$main.sha256;
        digest_bytes=$digest.bytes;digest_sha256=$digest.sha256;fresh_baseline_enabled=$true;baseline_enabled=$true;
        fresh_baseline_files=$baseline.files;fresh_manifest_sha256=$FreshBaselineManifestSha256;fresh_source_checkpoint=$ExpectedParent.ToString('D');
        fresh_source_binding=$baseline.provenance.source_binding;baseline_sha256=$baseline.sha256;baseline_basis_sha256=$baseline.basis_sha256;
        baseline_request_sha256='';baseline_result_sha256='';minimum_extent_only_streams=0;minimum_tail_extent_only_streams=0;
        prepared_managed=$preparedManaged;prepared_managed_sha256=$PreparedManagedReceiptSha256;initial_disk_count=$(if($hasPrepared){7}else{6})}
    $origins=@($normal,$performance,$support,$moveSupport,$self)|ForEach-Object {@{path=$_.path;bytes=$_.bytes;sha256=$_.sha256}}
    Save 'intent.json' @{kind='public-min-scratch-experiment-intent';configuration=$c;parent_id=$ExpectedParent;checkpoint_ids=$ids;
        toolset_manifest=$ToolsetManifest;toolset_manifest_sha256=$ToolsetManifestSha256;source_commit=$SourceCommit;
        baseline_provenance=$baseline.provenance;function_sources=$origins;capacity=$capacity;forecast_bytes=$ForecastAdditionalBytes;
        argv=@('--drive','F','--partition','2','--minimize-scratch');native_preparation_and_new_shadow_owned_by_public_cli=$true;
        semantic_metadata_masked=$false;old_physical_maps_used_as_post_move_authority=$false;no_source_or_replay_authority=$true;utc=[DateTime]::UtcNow.ToString('o')}
    $guest=@'
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CONFIG__'))|ConvertFrom-Json
$script:closedJsonCache=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$script:labIndexes=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
$script:labFreshBaseline=$null;$script:labBaselineContext=$null;$script:publicPreparationFacts=$null
$phase='preflight';$process=$null;$nativeExit=$null
__FUNCTIONS__
function PublicSemanticStream($Stream){
 $copy=($Stream|ConvertTo-Json -Depth 64)|ConvertFrom-Json
 # These fields are checked separately: original full digests against actual
 # target reads, and all complete raw maps against the native move replay.
 foreach($name in @('sha256','source_evidence','source_offset','source_extents','named_streams')){$copy.PSObject.Properties.Remove($name)}
 return $copy
}
function ResolveLabContentBaseline($Expected,$Request,[string]$Records){
 $fresh=ReadFreshLabSourceBaselineGuest $Request.pair.source;$old=$fresh.expected
 Need ((SameJsonValue $fresh.manifest.source_binding $Request.pair.source)-and@($Expected.objects).Count-eq1084-and@($old.objects).Count-eq1084) 'Independent complete original source coverage differs.'
 $index=GetLabIndex 'public.original.objects' $old.objects {param($r) LabRecordKey $r.record_number $r.sequence_number}
 $timeContext=@{raw=(Json (Join-Path $Records 'qualification\source-basis.json'));native=(Json (Join-Path $Records 'qualification\native-source.json'));views=(Json (Join-Path $Records 'qualification\source-assessment.json'));final=(Json (Join-Path $Records 'finalization.json'))}
 $times=[Collections.Generic.List[object]]::new();$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$streams=0;$unread=0
 foreach($o in $Expected.objects){
  $key=LabRecordKey $o.record_number $o.sequence_number;$matches=@(LabIndexMatch $index $key)
  Need ($seen.Add($key)-and$matches.Count-eq1-and(SameArray $matches[0].path $o.path)) 'Original/current semantic identity or namespace differs.'
  $reference=$matches[0];$a=PublicSemanticStream $o;$b=PublicSemanticStream $reference
  $time=ReconcileLabAccessTime $o $reference $timeContext
  if($null-ne$time){$times.Add($time);$a.stored_times[1]=$reference.stored_times[1]}
  foreach($n in @('named_streams')){$a.PSObject.Properties.Remove($n);$b.PSObject.Properties.Remove($n)}
  Need (SameJsonValue $a $b) ('Independent source semantic metadata changed: '+($o.path-join'\')+'; names/IDs/security/attributes/times remain exact; no modification/MFT-time waiver exists.')
  if($o.directory){continue}
  $names=[Collections.Generic.List[object]]::new();$names.Add(@())
  $p=$o.PSObject.Properties['named_streams'];$q=$reference.PSObject.Properties['named_streams'];$named=@();$oldNamed=@()
  if($null-ne$p){$named=@($p.Value)};if($null-ne$q){$oldNamed=@($q.Value)}
  Need ($named.Count-eq$oldNamed.Count) 'Original/current named-stream coverage differs.'
  foreach($s in $named){$names.Add(@($s.name_utf16))}
  foreach($name in $names){$current=LabStream $o $name;$known=LabStream $reference $name
   $currentSemantic=PublicSemanticStream $current;$knownSemantic=PublicSemanticStream $known
   # Reuse the exact cached-access proof already established for this object.
   # Other times and metadata remain exact in both comparisons.
   if(@($name).Count-eq0-and$null-ne$time){$currentSemantic.stored_times[1]=$known.stored_times[1]}
   Need ($known.sha256-cmatch'\A[0-9a-f]{32}\z'-and(SameJsonValue $currentSemantic $knownSemantic)) 'Original/current stream semantic metadata differs.'
   if($null-eq$current.sha256){$null=LabExtentEvidenceShape $current;$unread++}else{Need ($current.sha256-ceq$known.sha256) 'Actual freshly read source digest differs from original full baseline.'}
   $streams++
  }
 }
 Need ($streams-eq811) 'Exactly all811 original source streams required.'
 $script:publicPreparationFacts=ReadPublicPreparationLedger $Expected $Request $Records $fresh
 Save 'public-preparation-ledger-verification.json' $script:publicPreparationFacts
 $certificatePath=Join-Path $Records 'qualification\certificate.json';$certificate=Json $certificatePath;$qualification=Json (Join-Path $Records 'qualification\result.json')
 $certificatePin=(Get-FileHash -LiteralPath $certificatePath).Hash.ToLowerInvariant();$expectationPin=(Get-FileHash -LiteralPath (Join-Path $Records 'expectation.json')).Hash.ToLowerInvariant()
 Need ($qualification.success-and$qualification.source_admitted-and$qualification.kind-ceq'live-allocation-bounded-tree-qualification'-and$qualification.certificate_sha256-ceq$certificatePin-and$qualification.expected_tree_sha256-ceq$expectationPin-and$certificate.inspection_sha256-ceq$timeContext.raw.canonical_inspection_sha256-and$certificate.expected_tree_sha256-ceq$expectationPin-and(SameJsonValue $certificate.pair $Request.pair)) 'Actual fresh post-preparation qualification/certificate receipt must bind this inspection, expectation and source/shadow pair.'
 $case=$timeContext.views.comparison.directory_case_sensitivity;$dirs=@($timeContext.raw.ntfs.files|Where-Object {$_.is_directory});$caseScope=$timeContext.views.assessment.directory_case_admission
 Need ($timeContext.native.schema_version-eq14-and$timeContext.native.request.schema_version-eq6-and$case.raw_directories-eq$dirs.Count-and@($case.directories).Count-eq$dirs.Count-and$caseScope.raw_directories-eq$dirs.Count-and$caseScope.internal_replacement_proof_bound-and$caseScope.all_required_directories_case_insensitive-and@($caseScope.issues).Count-eq0-and$caseScope.matched_required_directories-eq@($caseScope.required_directories).Count) 'Actual fresh post-preparation source case scope and privately bound internal replacement proof required.'
 $rawIds=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$observedIds=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$scopedIds=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach($d in $dirs){Need ($rawIds.Add((LabRecordKey $d.record_number $d.sequence_number))) 'Duplicate raw directory identity.'}
 foreach($d in $case.directories){$key=LabRecordKey $d.record_number $d.sequence_number;Need ($rawIds.Contains($key)-and$observedIds.Add($key)) 'Raw directory case diagnostics have missing/extra/duplicate identities.'}
 $transferred=@($Expected.objects|Where-Object {$_.directory});Need ($transferred.Count-eq@($caseScope.required_directories).Count) 'Transferred directory case scope differs from actual canonical tree.'
 foreach($d in $caseScope.required_directories){
  $key=LabRecordKey $d.record_number $d.sequence_number;Need ($rawIds.Contains($key)-and$scopedIds.Add($key)) 'Required directory case identity differs.'
  $matches=@($case.directories|Where-Object {$_.record_number-eq$d.record_number-and$_.sequence_number-eq$d.sequence_number});$objects=@($transferred|Where-Object {$_.record_number-eq$d.record_number-and$_.sequence_number-eq$d.sequence_number})
  Need ($objects.Count-eq1-and$matches.Count-eq1-and$matches[0].matched-and$matches[0].before_flags-eq0-and$matches[0].after_flags-eq0-and@($matches[0].issues).Count-eq0) 'Every transferred directory requires stable actual zero case flags.'
 }
 foreach($d in $caseScope.replaced_internal_directories){
  $key=LabRecordKey $d.record_number $d.sequence_number;Need ($rawIds.Contains($key)-and$scopedIds.Add($key)) 'Replaced internal directory scope overlaps or differs.'
  $matches=@($timeContext.views.internal_replacements|Where-Object {$_.record_number-eq$d.record_number-and$_.sequence_number-eq$d.sequence_number})
  Need ($matches.Count-eq1-and(SameJsonValue $matches[0] $d)) 'Excluded directory must exactly equal an actually proof-bound internal replacement; Unknown flags remain Unknown.'
 }
 Need ($scopedIds.Count-eq$rawIds.Count) 'Required/replaced directory case scope is not a complete disjoint raw inventory partition.'
 $receipt=@{scope='independent-original-content-and-semantic-metadata-through-native-preparation-v1';baseline_used=$true;fresh_manifest_sha256=$c.fresh_manifest_sha256;
  baseline_sha256=$c.baseline_sha256;baseline_source_basis_sha256=$c.baseline_basis_sha256;objects=$seen.Count;streams=$streams;hashless_product_streams=$unread;
  canonical_semantic_metadata_exact_except_recorded_access_times=$true;access_time_reconciliations=$times.ToArray();root_modified_or_mft_change_times_masked=$false;
  physical_maps_checked_by_complete_native_move_replay=$true;preparation=$script:publicPreparationFacts;current_post_preparation_source_inspection_sha256=$timeContext.raw.canonical_inspection_sha256;
  actual_source_case_directories=$dirs.Count;actual_required_case_directories=@($caseScope.required_directories).Count;actual_replaced_internal_case_directories=@($caseScope.replaced_internal_directories);unknown_internal_case_flags_preserved=$true;independent_target_hash_expectation_is_original_baseline=$true;product_expectation_written=$false;product_digests_invented=$false;
  fresh_post_preparation_certificate_sha256=$certificatePin;serialized_certificate_grants_authority=$false;preparation_ledger_is_separate_from_frozen_source_events=$true;
  comparison_only_clone=$false;copied_artifact_bindings=$fresh.copied_artifact_bindings;grants_product_authority=$false}
 # Return the held original full-content baseline itself. Never populate any
 # absent product digest, and never write an altered product expectation.
 return @{enabled=$true;observer_expectation=$old;product_expectation=$Expected;receipt=$receipt}
}
try{
 Idle;Source 'NTFS';Protected
 Need ($env:COMPUTERNAME-ceq'N2R-WIN11'-and@(Get-Disk).Count-eq$c.initial_disk_count) 'Exact owning guest disk count required.'
 foreach($t in $c.tools){$p=Join-Path $c.stage $t.name;Need ((Get-Item -LiteralPath $p).Length-eq$t.bytes-and(Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()-ceq$t.sha256) 'Pinned staged tool differs.'}
 $fresh=ReadFreshLabSourceBaselineGuest $c.fresh_source_binding
 Save 'fresh-baseline-preflight.json' @{success=$true;manifest_sha256=$c.fresh_manifest_sha256;source_checkpoint=$c.fresh_source_checkpoint;descriptor=$fresh.descriptor;actual_full_source_streams_verified=811;copied_artifact_bindings=$fresh.copied_artifact_bindings;grants_product_authority=$false}
 if($null-ne$c.prepared_managed){$b=$c.prepared_managed.binding;$d=Get-Disk -Number 6;$p=Get-Partition -DiskNumber 6 -PartitionNumber $b.identity.partition_number;$v=$p|Get-Volume;Need ([guid]$d.Guid-eq[guid]$b.identity.disk_guid-and[guid]$p.Guid-eq[guid]$b.identity.partition_guid-and-not$d.IsOffline-and-not$d.IsReadOnly-and$v.FileSystem-ceq'ReFS'-and$v.FileSystemLabel-ceq'n2r-retained-shadow') 'Original prepared shadow changed.'}
 $binary=Join-Path $c.stage 'ntfs2refs.exe';$cli=@('--drive','F','--partition','2','--minimize-scratch')
 Save 'wrapper-worker.json' @{pid=$PID;creation_ms=([DateTimeOffset](Get-Process -Id $PID).StartTime).ToUnixTimeMilliseconds();run_id=$c.run_id;utc=[DateTime]::UtcNow.ToString('o')}
 $stdin=Join-Path $c.stage 'stdin-yes.txt';$f=[IO.File]::Open($stdin,'CreateNew','Write','Read');try{$bytes=[Text.Encoding]::ASCII.GetBytes("yes`r`n");$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
 $stdout=Join-Path $c.stage 'stdout.log';$stderr=Join-Path $c.stage 'stderr.log';$phase='public-min-scratch-conversion'
 Save 'native-dispatch-intent.json' @{binary=$binary;binary_sha256=$c.main_sha256;argv=$cli;stdin_file=$stdin;expected_exit=0;utc=[DateTime]::UtcNow.ToString('o')}
 Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class PublicMinScratchIo {
 [StructLayout(LayoutKind.Sequential)] public struct Counters {
  public ulong ReadOperations, WriteOperations, OtherOperations;
  public ulong ReadBytes, WriteBytes, OtherBytes;
 }
 [DllImport("kernel32.dll", SetLastError=true)]
 [return: MarshalAs(UnmanagedType.Bool)]
 public static extern bool GetProcessIoCounters(IntPtr process, out Counters counters);
}
"@
 $beforeFree=(Get-Volume -DriveLetter C).SizeRemaining;$clock=[Diagnostics.Stopwatch]::StartNew()
 $process=Start-Process -FilePath $binary -ArgumentList '--drive F --partition 2 --minimize-scratch' -WorkingDirectory $c.stage -RedirectStandardInput $stdin -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
 $nativeHandle=$process.Handle;$birth=([DateTimeOffset]$process.StartTime).ToUnixTimeMilliseconds();$nativePid=$process.Id
 Save 'native-process.json' @{pid=$nativePid;creation_ms=$birth;parent_pid=$PID;binary=$binary;binary_sha256=$c.main_sha256;argv=$cli;expected_exit=0;process_handle_retained_before_wait=$true;utc=[DateTime]::UtcNow.ToString('o')}
 $process.WaitForExit();$clock.Stop();$process.Refresh();$nativeExit=$process.ExitCode;$out=Log $stdout;$err=Log $stderr
 Need ($process.HasExited-and([DateTimeOffset]$process.StartTime).ToUnixTimeMilliseconds()-eq$birth) 'Retained terminal process identity differs.'
 $io=[PublicMinScratchIo+Counters]::new();$ioOk=[PublicMinScratchIo]::GetProcessIoCounters($nativeHandle,[ref]$io);$ioError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
 $peakWorking=$null;$peakPaged=$null;$peakError=$null
 try{$peakWorking=$process.PeakWorkingSet64;$peakPaged=$process.PeakPagedMemorySize64}catch{$peakError=$_.Exception.Message}
 $metrics=@{scope='actual-public-command-native-process-v1';wall_seconds=$clock.Elapsed.TotalSeconds;total_cpu_seconds=$process.TotalProcessorTime.TotalSeconds;peak_working_set_bytes=$peakWorking;peak_paged_memory_bytes=$peakPaged;peak_memory_counters_available=($null-eq$peakError-and$null-ne$peakWorking-and$null-ne$peakPaged);peak_memory_counter_error=$peakError;guest_c_free_before_bytes=$beforeFree;guest_c_free_after_bytes=(Get-Volume -DriveLetter C).SizeRemaining;includes_native_ntfs_preparation=$true;native_io_counter_query_succeeded=$ioOk;native_io_counter_error=$(if($ioOk){$null}else{$ioError});logical_read_operations=$io.ReadOperations;logical_write_operations=$io.WriteOperations;logical_other_operations=$io.OtherOperations;logical_read_bytes=$io.ReadBytes;logical_write_bytes=$io.WriteBytes;logical_other_bytes=$io.OtherBytes;ntfs_driver_move_io_is_separate=$true;physical_io_or_speedup_claimed=$false}
 Save 'native-terminal.json' @{pid=$nativePid;creation_ms=$birth;native_exit_observed=($null-ne$nativeExit);native_exit=$nativeExit;expected_exit=0;metrics=$metrics;stdout=$out;stderr=$err;utc=[DateTime]::UtcNow.ToString('o')}
 Need ($null-ne$nativeExit-and$nativeExit-eq0-and-not$out.truncated-and$ioOk) 'Actual public native0/complete stdout/native IO counters required; preserve without retry.'
 Idle;Protected;$phase='closed-public-min-scratch-evidence'
 $success=[regex]::Matches($out.text,'(?m)^Conversion completed[.] Recovery records: (C:\\ProgramData\\ntfs2refs\\runs\\[0-9a-f]{32}\\conversion)[ \t]*\r?$')
 $published=[regex]::Matches($out.text,'(?m)^Recovery directory: (C:\\ProgramData\\ntfs2refs\\runs\\[0-9a-f]{32}\\conversion)[ \t]*\r?$')
 Need ($success.Count-eq1-and$published.Count-eq1-and$success[0].Groups[1].Value-ceq$published[0].Groups[1].Value) 'One actual success path and matching published recovery directory required.'
 $records=$success[0].Groups[1].Value;$runRoot=[IO.Path]::GetDirectoryName($records);$engine=[IO.Path]::GetFileName($runRoot)
 $result=Json (Join-Path $records 'result.json');$final=Json (Join-Path $records 'finalization.json');$expected=Json (Join-Path $records 'expectation.json');$devices=Json (Join-Path $runRoot 'devices.json');$managed=Json (Join-Path $runRoot 'managed-shadow.json');$plan=Json (Join-Path $records 'selected-plan.json')
 Need ($devices.selected_capacity_policy-ceq'source_free_actual_bytes_v1'-and$devices.verification_policy-ceq'extent_identity_v1'-and$devices.schema_version-eq3-and$devices.verify_existing_shadow-eq$false-and$managed.path-ceq(Join-Path $runRoot 'shadow.vhdx')-and$managed.binding.disk_number-eq$c.initial_disk_count) 'Actual public policy and newly owned shadow differ.'
 $selection=Json (Join-Path $runRoot 'drive-selection.json');Need ($selection.confirmation-ceq'interactive affirmative'-and$selection.source_write_authority-eq$false-and$selection.selected.disk_number-eq1-and$selection.selected.partition_number-eq2-and(SameJsonValue $selection.source.binding $devices.pair.source)) 'Actual public affirmative selection differs.'
 $capture=Json (Join-Path $records 'capture-capacity.json');Need ($capture.budget.selected_capacity_policy-ceq'source_free_actual_bytes_v1'-and$capture.budget.max_journal_bytes-eq$devices.max_journal_bytes-and$capture.budget.max_literal_backing_bytes-eq$devices.max_literal_backing_bytes-and$capture.budget.max_combined_backing_and_journal_bytes-eq$devices.max_combined_scratch_bytes) 'Actual public measured-pool scratch policy differs.'
 $metrics['selected_bytes']=$result.selected_bytes;$metrics['journal_bytes']=$result.journal_bytes;$metrics['literal_backing_bytes']=(Json (Join-Path $records 'journal-capacity.json')).packed_bytes
 $metrics['combined_journal_and_literal_bytes']=[long]$metrics.journal_bytes+[long]$metrics.literal_backing_bytes
 Need ($metrics.combined_journal_and_literal_bytes-le$devices.max_combined_scratch_bytes-and$metrics.journal_bytes-le$devices.max_journal_bytes) 'Actual public scratch exceeded its admitted pool.'
 Save 'public-command-performance.json' $metrics
 __NORMAL_OBSERVER__
}catch{Save 'wrapper-failed.json' @{success=$false;phase=$phase;native_exit_observed=($null-ne$nativeExit);native_exit=$nativeExit;error=$_.Exception.ToString();automatic_retry_recovery_restore_cleanup=$false;worker_death_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')};exit 1}
finally{if($null-ne$process){$process.Dispose()};foreach($entry in $script:closedJsonCache.Values){$entry.stream.Dispose()};$script:closedJsonCache.Clear();$script:labIndexes.Clear()}
'@
    $guest=[IO.File]::ReadAllText($support.path)+[Environment]::NewLine+[IO.File]::ReadAllText($moveSupport.path)+[Environment]::NewLine+$guest
    $guest=$guest.Replace('__FUNCTIONS__',($definitions-join[Environment]::NewLine)).Replace('__NORMAL_OBSERVER__',$observer)
    # Historical full baseline stays report11/request3. Only current source
    # observers are adapted to the sealed directory-case runtime protocol.
    $guest=$guest.Replace('$native.schema_version-eq12-and$native.request.schema_version-eq4','$native.schema_version-eq14-and$native.request.schema_version-eq6')
    $guest=$guest.Replace('$sourceNative.schema_version-eq12-and$sourceNative.request.schema_version-eq4','$sourceNative.schema_version-eq14-and$sourceNative.request.schema_version-eq6')
    $guest=$guest.Replace('__CONFIG__',[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes(($c|ConvertTo-Json -Depth 32 -Compress))))
    $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($guest,[ref]$tokens,[ref]$errors)
    Need ($errors.Count-eq0-and$guest.IndexOf('__NORMAL_OBSERVER__')-lt0-and$guest.IndexOf('__FUNCTIONS__')-lt0) 'Assembled guest syntax/template differs.'
    $wrapper=Join-Path $root 'guest-wrapper.ps1';[IO.File]::WriteAllText($wrapper,$guest,[Text.UTF8Encoding]::new($false));$wrapperPin=(Get-FileHash -LiteralPath $wrapper).Hash.ToLowerInvariant()
    $session=New-PSSession -VMId $vmId -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml'))
    $ready=Invoke-Command -Session $session -ArgumentList $stage,$task,$c.initial_disk_count -ScriptBlock {param($Stage,$Task,$Count)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        if($env:COMPUTERNAME-cne'N2R-WIN11'-or(Test-Path -LiteralPath $Stage)-or@(Get-ScheduledTask|Where-Object {$_.TaskName-ceq$Task-or($_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled'))}).Count-or@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-or@(Get-Disk).Count-ne$Count){throw 'Fresh idle owning guest required.'}
        $d=Get-Disk -Number 1;$p=Get-Partition -DriveLetter F;$v=$p|Get-Volume
        if($d.IsOffline-or$d.IsReadOnly-or$d.IsBoot-or$d.IsSystem-or[guid]$d.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or$p.DiskNumber-ne1-or$p.PartitionNumber-ne2-or[guid]$p.Guid-ne[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-or$p.Size-ne52GB-or$p.Offset-ne16MB-or$v.FileSystem-cne'NTFS'-or$v.AllocationUnitSize-ne65536-or$v.FileSystemLabel-cne'n2r-stream-source'){throw 'Actual restored grown F/NTFS64K identity differs.'}
        $a=Get-Item -LiteralPath 'C:\ntfs2refs';while($null-ne$a){if($a.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse stage ancestry.'};$a=$a.Parent}
        New-Item -ItemType Directory -Path $Stage|Out-Null
        @{fresh_stage=$Stage;initial_disks=$Count;source_payload_opened=$false;utc=[DateTime]::UtcNow.ToString('o')}
    };Save 'ready.json' $ready
    foreach($tool in $tools){Copy-Item -LiteralPath $tool.path -ToSession $session -Destination (Join-Path $stage $tool.name)}
    foreach($key in $baseline.files.Keys){$entry=$baseline.files[$key];Copy-Item -LiteralPath $entry.path -ToSession $session -Destination (Join-Path $stage $entry.name)}
    Copy-Item -LiteralPath $wrapper -ToSession $session -Destination (Join-Path $stage 'wrapper.ps1');HostGuard
    Save 'dispatch.json' @{kind='public-min-scratch-experiment-dispatch';run_id=$run;source_commit=$SourceCommit;expected_exit=0;parent_id=$ExpectedParent;checkpoint_ids=$ids;task_name=$task;guest_stage=$stage;wrapper_sha256=$wrapperPin;configuration=$c;argv=@('--drive','F','--partition','2','--minimize-scratch');completion_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')}
    Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin,($c|ConvertTo-Json -Depth 32 -Compress) -ScriptBlock {param($Stage,$Task,$Pin,$Config)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$c=$Config|ConvertFrom-Json;$path=Join-Path $Stage 'wrapper.ps1'
        if((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$Pin-or@(Get-ScheduledTask|Where-Object TaskName -CEQ $Task).Count){throw 'Fresh pinned SYSTEM task required.'}
        foreach($t in $c.tools){$p=Join-Path $Stage $t.name;if((Get-Item -LiteralPath $p).Length-ne$t.bytes-or(Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()-cne$t.sha256){throw 'Staged tool pin differs.'}}
        foreach($property in $c.fresh_baseline_files.PSObject.Properties){$v=$property.Value;$p=Join-Path $Stage $v.name;if((Get-Item -LiteralPath $p).Length-ne$v.bytes-or(Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()-cne$v.sha256){throw 'Staged baseline pin differs.'}}
        Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'"')) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
    }
    HostGuard;Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration $configuration) -AdditionalBytes $ForecastAdditionalBytes
    Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin -ScriptBlock {param($Stage,$Task,$Pin)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskName $Task;$info=$t|Get-ScheduledTaskInfo;$p=Join-Path $Stage 'wrapper.ps1'
        if($t.State.ToString()-cne'Ready'-or$info.LastRunTime.Year-ge2000-or@($t.Actions).Count-ne1-or$t.Actions[0].Execute-cne"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"-or$t.Actions[0].Arguments-cne('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$p+'"')-or$t.Principal.UserId-notin@('SYSTEM','S-1-5-18')-or$t.Principal.RunLevel.ToString()-cne'Highest'-or(Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()-cne$Pin-or@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-or@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count){throw 'Only the untouched pinned SYSTEM task may start once.'}
        Start-ScheduledTask -TaskName $Task
    };Save 'start.json' @{start_issued_once=$true;expected_exit=0;completion_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')}
    Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw
}catch{if($created-and-not(Test-Path -LiteralPath (Join-Path $root 'dispatch-failed.json'))){Save 'dispatch-failed.json' @{success=$false;error=$_.Exception.ToString();automatic_retry_restore_cleanup=$false;worker_death_inferred=$false}};throw}
finally{if($null-ne$session){Remove-PSSession $session -ErrorAction SilentlyContinue};if($null-ne$baseline-and$baseline.ContainsKey('held_streams')){foreach($s in $baseline.held_streams){$s.Dispose()}};foreach($s in $held){$s.Dispose()}}
