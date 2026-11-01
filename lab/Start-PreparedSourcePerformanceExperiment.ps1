# Prepared-source performance derivative; original controller remains unchanged.
# Owning-guest experiment only. Root supplies an already restored/booted source.
# This controller never powers, checkpoints, restores or cleans up a VM.
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
    [Parameter(Mandatory)][string]$SourceRequestPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$SourceRequestSha256,
    [Parameter(Mandatory)][ValidateRange(1,50000000000)][long]$ForecastAdditionalBytes,
    [switch]$InterruptAfterFirstWrite,
    [switch]$RequirePreparationCopyReuse,
    [Parameter(Mandatory)][string]$PreparedManagedReceiptPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$PreparedManagedReceiptSha256,
    [switch]$RequireClosingReadReuse,
    [switch]$RequireSourceDirectoryCase
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspace = 'D:\code\ntfs2refs'
$base = Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$vmId = [guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$sourceCheckpoint = [guid]'cb802669-903c-48cc-99e5-57976b149e7d'
$ids = @($ExpectedCheckpointIds | ForEach-Object { $_.ToString('D') })
$run = [guid]::NewGuid().ToString('N')
$operation = if ($InterruptAfterFirstWrite) { 'interrupt' } else { 'normal' }
$expectedExit = if ($InterruptAfterFirstWrite) { 86 } else { 0 }
$root = Join-Path $base ('prepared-source-performance-' + $operation + '-' + $run)
$stage = 'C:\ntfs2refs\prepared-source-performance-' + $operation + '-' + $run
$task = 'N2R-PreparedSourcePerformance-' + $operation + '-' + $run
$session = $null; $baseline = $null; $created = $false
$held = [Collections.Generic.List[IO.FileStream]]::new()
function Need([bool]$Ok, [string]$Message) { if (-not $Ok) { throw $Message } }
. (Join-Path $PSScriptRoot 'SourceBaselineSupport.ps1')
function Save([string]$Name, $Value) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 32))
    Need ($bytes.Length -le 4MB) 'Bounded host receipt required.'
    $f = [IO.File]::Open((Join-Path $root $Name), 'CreateNew', 'Write', 'Read')
    try { $f.Write($bytes, 0, $bytes.Length); $f.Flush($true) } finally { $f.Dispose() }
}
function HostGuard {
    $v = Get-VM -Id $vmId
    $actual = @(Get-VMSnapshot -VM $v | ForEach-Object { $_.Id.ToString('D') })
    Need ($v.Name -ceq 'ntfs2refs-streaming-v2-20261027' -and $v.State.ToString() -ceq 'Running' -and
        $v.ParentSnapshotId -eq $ExpectedParent -and $v.MemoryStartup -eq 4GB -and
        $v.MemoryAssigned -eq 4GB -and -not $v.DynamicMemoryEnabled -and
        (Get-VMProcessor -VM $v).Count -eq 4 -and @(Get-VMNetworkAdapter -VM $v).Count -eq 0 -and
        $actual.Count -eq $ids.Count -and @($ids | Where-Object { $_ -notin $actual }).Count -eq 0) 'Exact already running source/checkpoint set/4GiB/4CPU/noNIC required.'
}
function ReadController([string]$Name) {
    $path = Join-Path $PSScriptRoot $Name
    $item = FreshBaselineOrdinary $path 1MB
    $pin = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $null = OpenFreshBaselineHost $path $pin 1MB $held $false
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    Need ($errors.Count -eq 0) ('Controller syntax differs: ' + $Name)
    $assign = @($ast.FindAll({ param($n)
        $n -is [Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left -is [Management.Automation.Language.VariableExpressionAst] -and
        $n.Left.VariablePath.UserPath -ceq 'body' -and
        $n.Right -is [Management.Automation.Language.CommandExpressionAst] -and
        $n.Right.Expression -is [Management.Automation.Language.StringConstantExpressionAst]
    }, $true))
    Need ($assign.Count -eq 1) 'One literal guest body required; never execute another controller.'
    $text = $assign[0].Right.Expression.Value
    $guest = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
    Need ($errors.Count -eq 0) 'Imported guest body syntax differs.'
    $functions = @{}
    foreach ($node in $guest.EndBlock.Statements) {
        if ($node -is [Management.Automation.Language.FunctionDefinitionAst]) {
            Need (-not $functions.ContainsKey($node.Name)) 'Duplicate imported guest function.'
            $functions[$node.Name] = $node.Extent.Text
        }
    }
    return @{ ast=$guest; functions=$functions; pin=@{path=$item.FullName;bytes=$item.Length;sha256=$pin} }
}
function ReplaceOnce([string]$Text, [string]$Old, [string]$New) {
    Need (($Text.Split(@($Old), [StringSplitOptions]::None)).Count -eq 2) 'Exact reviewed function adaptation must match once.'
    return $Text.Replace($Old, $New)
}
try {
    Need ($ExpectedParent -eq $sourceCheckpoint -and $ids.Count -gt 0 -and $ids.Count -le 50 -and
        @($ids | Sort-Object -Unique).Count -eq $ids.Count -and $sourceCheckpoint.ToString('D') -in $ids -and
        [guid]::Empty.ToString('D') -notin $ids) 'Root must restore exact prepared sourcecb802669; no restore occurs here.'
    Need ($FreshBaselineManifestSha256 -ceq '7d10997d0ec43a54725c66956a0992d40437b20720a78217852cc338e82a74e7' -and
        $DirectoryGrowthReceiptSha256 -ceq '835b1196b038b2aac01bc1bd4efdf5e9837531d5e1d69dd7b9486272f37ba37c') 'Exact full baseline and metadata-only151-directory growth required.'
    $baseline = ReadFreshLabSourceBaselineHost $FreshBaselineManifestPath $FreshBaselineManifestSha256 $DirectoryGrowthReceiptPath $DirectoryGrowthReceiptSha256 $sourceCheckpoint $base
    Need ($PreparedManagedReceiptPath.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)) 'Prepared managed receipt must remain under lab root.'
    $preparedManaged = (OpenFreshBaselineHost $PreparedManagedReceiptPath $PreparedManagedReceiptSha256 1MB $held $true).value
    Need ($preparedManaged.success -and $preparedManaged.kind -ceq 'new-owned-native-managed-shadow-smoke' -and $preparedManaged.binding.disk_number -eq 6 -and $preparedManaged.source_writes -eq 0 -and -not $preparedManaged.source_binding_supplied -and $preparedManaged.path -ceq 'C:\ntfs2refs\ntfs-owned-preparation-6ec16ed4b4774c13a76b1e282103c66e\managed-shadow\shadow.vhdx') 'Exact owned empty shadow from completed preparation required.'
    $manifestItem = FreshBaselineOrdinary $ToolsetManifest 1MB
    Need ($ToolsetManifest.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase) -and $manifestItem.Name -ceq 'manifest.json') 'Sealed lab-local toolset required.'
    $manifest = (OpenFreshBaselineHost $ToolsetManifest $ToolsetManifestSha256 1MB $held $true).value
    Need ($manifest.schema_version -eq 2 -and $manifest.kind -ceq 'source-free-performance-toolset' -and
        $manifest.source_commit -ceq $SourceCommit -and $manifest.main_source_sha256 -ceq 'c6bc5c52c8458ee70bd2567a9d8350105aeaa6245448df22675780403e04348b' -and @($manifest.tools).Count -eq 4) 'Four roles from the explicitly supplied runtime required; no qualification is inherited.'
    $tools = @()
    foreach ($name in @('ntfs2refs.exe','lab-convert-native-composite.exe','lab-content-digest.exe','lab-managed-shadow.exe')) {
        $rows = @($manifest.tools | Where-Object name -CEQ $name)
        Need ($rows.Count -eq 1 -and $rows[0].path -ceq (Join-Path $manifestItem.DirectoryName $name) -and
            $rows[0].bytes -gt 0 -and $rows[0].bytes -le 64MB -and $rows[0].sha256 -cmatch '\A[0-9a-f]{64}\z') 'Exact bounded tool role/pin required.'
        $file = (OpenFreshBaselineHost $rows[0].path $rows[0].sha256 64MB $held $false).item
        Need ($file.Length -eq $rows[0].bytes) 'Tool length differs.'
        $tools += @{name=$name;path=$file.FullName;bytes=$file.Length;sha256=$rows[0].sha256;source_scope=$rows[0].source_scope;origin=$rows[0].origin}
    }
    Need ($SourceRequestPath.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase)) 'Lab-local routing seed required before opening it.'
    $seed = (OpenFreshBaselineHost $SourceRequestPath $SourceRequestSha256 131072 $held $true).value
    Need ($SourceRequestPath.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase) -and $seed.schema_version -eq 3 -and
        $seed.pair.source.disk_number -eq 1 -and $seed.journal.disk.disk_number -eq 0) 'Pinned archived F/C routing seed required, never an admission.'
    $interrupt = ReadController 'Start-EnvelopeInterruption.ps1'
    $normal = ReadController 'Start-AllocationBoundedConversion.ps1'
    $supportPath = Join-Path $PSScriptRoot 'SourceBaselineSupport.ps1'
    $supportPin = (Get-FileHash -LiteralPath $supportPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $null = OpenFreshBaselineHost $supportPath $supportPin 1MB $held $false
    $definitions = [Collections.Generic.List[string]]::new()
    foreach ($name in $interrupt.functions.Keys) {
        if ($name -notin @('AssertEnvelopePrepared','AssertEnvelopeJournalFacts','AssertLabOldZeroEncoding')) { $definitions.Add($interrupt.functions[$name]) }
    }
    foreach ($name in @('Source','AssertLabExtentScope','ReconcileLabAccessTime','ResolveLabContentBaseline','AssertRawContentOrLabExtent','VerifyAllTargetStreamHashes')) {
        Need ($normal.functions.ContainsKey($name)) ('Missing existing observer function: ' + $name)
        $definitions.Add($normal.functions[$name])
    }
    # Format-five verifier observes pinned metadata only; the core authenticates J.
    $sourceZeroFallback = @'
function AssertLabSourceFreeZeroFallback($Plan,[string]$Records,$ActualResult){
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
 Need ($request.selected_capacity_policy-ceq'source_free_actual_bytes_v1'-and$capacity.source_free_bytes-eq0-and$capacity.source_free_hash_table_bytes-eq0-and$capacity.rollback_preserves_free_space_contents-and$literal-le[decimal]$request.max_literal_backing_bytes-and($d-$o+$literal+16MB)-le[decimal]$request.max_journal_bytes-and($d-$o+2*$literal+16MB)-le[decimal]$request.max_combined_scratch_bytes-and$expected+$literal-le[decimal]$request.max_combined_scratch_bytes) 'Clean-source zero fallback keeps exact old restoration and admitted storage.'
 if($null-ne$ActualResult){$null=LabIntegerKey $ActualResult.old_zero_bytes;Need ($ActualResult.old_zero_bytes-eq$o-and$ActualResult.old_zero_payload_storage_elided-is[bool]-and$ActualResult.old_zero_payload_storage_elided) 'Actual product result must explicitly report the same old-zero total and storage elision.'}
 if($null-ne$ActualResult){Need ($ActualResult.source_free_bytes-eq0-and-not$ActualResult.source_free_old_payload_storage_elided-and$ActualResult.rollback_preserves_free_space_contents) 'Actual clean fallback must preserve all original selected bytes.'}
 return @{enabled=$true;source_free_bytes=0L;source_free_hash_table_bytes=0L;old_restore_required_bytes=[long]$d;scope='lab-pinned-old-zero-journal-encoding-v1';format='N2ROLD01';journal_format_version=4;journal_record_bytes=104;range_count=@($Plan.ranges).Count;selected_bytes=[long]$d;old_zero_ranges=$oldZeros.Count;old_zero_bytes=[long]$o;stored_old_payload_bytes=[long]($d-$o);new_zero_bytes=[long]$z;new_copy_bytes=[long]$copy;literal_new_payload_bytes=[long]$literal;expected_journal_bytes=[long]$expected;journal_bytes=$ticket.journal_length;plan_sha256=$planPin;ticket_sha256=$ticketPin;location_sha256=(Get-FileHash -LiteralPath $locationPath -Algorithm SHA256).Hash.ToLowerInvariant();capacity_sha256=(Get-FileHash -LiteralPath $capacityPath -Algorithm SHA256).Hash.ToLowerInvariant();old_zero_exact_selected_subset=$true;core_actual_source_zero_check_replaced_by_lab=$false;lab_source_payload_bytes_read=0;raw_journal_opened=$false;grants_product_authority=$false}
}
'@
    $definitions.Add($sourceZeroFallback)
    $sourceFreeVerifier = @'
function AssertLabSourceFreeEncoding($Plan,[string]$Records,$ActualResult){
 $freeProperty=$Plan.PSObject.Properties['source_free_ranges'];if($null-eq$freeProperty-or($freeProperty.Value-is[Collections.IList]-and@($freeProperty.Value).Count-eq0)){return (AssertLabSourceFreeZeroFallback $Plan $Records $ActualResult)}
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

 $freeProperty=$Plan.PSObject.Properties['source_free_ranges'];Need ($null-ne$freeProperty-and$freeProperty.Value-is[Collections.IList]) 'Explicit source-free subset required.'
 $free=@($freeProperty.Value);Need ($free.Count-gt0) 'Positive source-free storage reduction required.'
 $oldSet=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);foreach($r in $oldZeros){$null=$oldSet.Add((LabJournalRangeKey $r))}
 $origins=[Collections.Generic.List[object]]::new();foreach($r in @($copies|Sort-Object source_offset)){ $start=[decimal]$r.source_offset;$end=$start+[decimal]$r.length;if($origins.Count-and$start-le$origins[$origins.Count-1].end){$origins[$origins.Count-1].end=[Math]::Max($end,$origins[$origins.Count-1].end)}else{$origins.Add(@{start=$start;end=$end})} }
 $f=0D;$previousOffset=-1D;$originIndex=0
 foreach($r in $free){$key=LabJournalRangeKey $r;$end=[decimal]$r.offset+[decimal]$r.length;Need ($selected.ContainsKey($key)-and[decimal]$r.offset-gt$previousOffset-and$r.offset-ge4096-and-not$oldSet.Contains($key)) 'Source-free rows must be unique whole selected rows, outside discovery and old-zero subsets.';while($originIndex-lt$origins.Count-and$origins[$originIndex].end-le[decimal]$r.offset){$originIndex++};Need ($originIndex-ge$origins.Count-or$origins[$originIndex].start-ge$end) 'COPY originals may not become hash-only.';$f+=[decimal]$r.length;$previousOffset=[decimal]$r.offset}
 Need ($f-gt0-and$f+$o-le$d-and$f%4096-eq0-and@($ticket.old_restored_selected_sha256).Count-eq32) 'Restoration scope and old hash-table domain required.'
 $expected=8192D+80D+80D+104D*@($Plan.ranges).Count+2D*$d-$z-$copy-$o-$f+$f/256D
 Need ($expected-gt0-and$expected-le[long]::MaxValue-and$ticket.image_length-eq$Plan.image_length-and$ticket.selected_bytes-eq$d-and$ticket.range_count-eq@($Plan.ranges).Count-and$ticket.whole_image_verified-eq$false-and$ticket.journal_length-eq$expected-and$expected-le[decimal]$Plan.max_journal_bytes) 'Format5 exact descriptor/payload journal size or trusted ticket domain differs.'
 Need ($location.format-ceq'N2RFRE01'-and$location.journal_format_version-eq5-and$location.journal_record_bytes-eq104-and$location.old_zero_bytes-eq$o-and$capacity.old_zero_bytes-eq$o-and$capacity.journal_bytes-eq$expected-and$capacity.selected_bytes-eq$d-and$capacity.new_zero_bytes-eq$z-and$capacity.new_copy_bytes-eq$copy-and$capacity.packed_bytes-eq$literal) 'Actual format5 location/capacity totals differ from the pinned exact subsets.'
 $capElision=$capacity.PSObject.Properties['old_zero_payload_storage_elided'];if($null-ne$capElision){Need ($capElision.Value-is[bool]-and$capElision.Value) 'Capacity old-zero elision flag differs.'}
 $null=LabIntegerKey $request.max_combined_scratch_bytes;$null=LabIntegerKey $request.max_literal_backing_bytes
 Need ($request.selected_capacity_policy-ceq'source_free_actual_bytes_v1'-and$capacity.source_free_bytes-eq$f-and$capacity.source_free_hash_table_bytes-eq$f/256-and$capacity.rollback_preserves_free_space_contents-eq$false-and$literal-le[decimal]$request.max_literal_backing_bytes-and($d-$o-$f+$f/256+$literal+16MB)-le[decimal]$request.max_journal_bytes-and($d-$o-$f+$f/256+2*$literal+16MB)-le[decimal]$request.max_combined_scratch_bytes-and$expected+$literal-le[decimal]$request.max_combined_scratch_bytes) 'Source-free actual storage and exact capacity must both remain admitted.'
 if($null-ne$ActualResult){$null=LabIntegerKey $ActualResult.old_zero_bytes;Need ($ActualResult.old_zero_bytes-eq$o-and$ActualResult.old_zero_payload_storage_elided-is[bool]-and$ActualResult.old_zero_payload_storage_elided) 'Actual product result must explicitly report the same old-zero total and storage elision.'}
 if($null-ne$ActualResult){Need ($ActualResult.source_free_bytes-eq$f-and$ActualResult.source_free_hash_table_bytes-eq$f/256-and$ActualResult.source_free_old_payload_storage_elided-and$ActualResult.rollback_preserves_free_space_contents-eq$false) 'Actual product source-free result differs.'}
 return @{enabled=$true;source_free_bytes=[long]$f;source_free_hash_table_bytes=[long]($f/256);old_restore_required_bytes=[long]($d-$f);scope='lab-pinned-source-free-journal-encoding-v1';format='N2RFRE01';journal_format_version=5;journal_record_bytes=104;range_count=@($Plan.ranges).Count;selected_bytes=[long]$d;old_zero_ranges=$oldZeros.Count;old_zero_bytes=[long]$o;stored_old_payload_bytes=[long]($d-$o-$f);new_zero_bytes=[long]$z;new_copy_bytes=[long]$copy;literal_new_payload_bytes=[long]$literal;expected_journal_bytes=[long]$expected;journal_bytes=$ticket.journal_length;plan_sha256=$planPin;ticket_sha256=$ticketPin;location_sha256=(Get-FileHash -LiteralPath $locationPath -Algorithm SHA256).Hash.ToLowerInvariant();capacity_sha256=(Get-FileHash -LiteralPath $capacityPath -Algorithm SHA256).Hash.ToLowerInvariant();old_zero_exact_selected_subset=$true;core_actual_source_zero_check_replaced_by_lab=$false;lab_source_payload_bytes_read=0;raw_journal_opened=$false;grants_product_authority=$false}
}
'@
    $definitions.Add($sourceFreeVerifier)
    $tryNodes = @($normal.ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] })
    Need ($tryNodes.Count -eq 1) 'One existing normal observer block required.'
    $statements = @($tryNodes[0].Body.Statements); $start = -1
    for ($i=0; $i -lt $statements.Count; $i++) { if ($statements[$i].Extent.Text.StartsWith('$oldZeroEncoding=AssertLabOldZeroEncoding', [StringComparison]::Ordinal)) { Need ($start -eq -1) 'Unique observer start required.'; $start=$i } }
    Need ($start -ge 0) 'Existing closed-normal observer tail missing.'
    $observer = ($statements[$start..($statements.Count-1)] | ForEach-Object { $_.Extent.Text }) -join [Environment]::NewLine
    $observer = ReplaceOnce $observer 'AssertLabOldZeroEncoding' 'AssertLabSourceFreeEncoding'
    $observer = ReplaceOnce $observer "kind='allocation-bounded-public-drive-observation'" "kind='prepared-source-performance-normal-observation'"
    $observerAst = [Management.Automation.Language.Parser]::ParseInput($observer, [ref]$null, [ref]$null)
    Need (@($observerAst.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in @('Start-Process','Start-ScheduledTask','Set-Disk','Remove-Item')}, $true)).Count -eq 0) 'Imported observer tail must not start conversion or change disk state.'
    Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
    $configuration = Get-LabConfiguration -WorkspaceRoot $workspace
    $capacity = Get-LabCapacity -Configuration $configuration
    Need ($capacity.MaximumActualBytes -eq 329374052988 -and $capacity.MinimumFreeBytes -eq 17179869184) 'Fixed storage epoch differs.'
    Assert-LabCapacity -Capacity $capacity -AdditionalBytes $ForecastAdditionalBytes
    HostGuard; Need (-not (Test-Path -LiteralPath $root)) 'Fresh host stage required.'
    New-Item -ItemType Directory -Path $root | Out-Null; $created=$true
    $digest = @($tools | Where-Object name -CEQ 'lab-content-digest.exe')[0]
    $c = @{stage=$stage;task=$task;run_id=$run;vm_id=$vmId.ToString('D');operation=$operation;source_commit=$SourceCommit;tools=$tools;output=(Join-Path $stage 'conversion');managed=(Split-Path -LiteralPath $preparedManaged.path);prepared_managed_sha256=$PreparedManagedReceiptSha256;source_request_sha256=$SourceRequestSha256;fresh_baseline_enabled=$true;baseline_enabled=$true;fresh_baseline_files=$baseline.files;fresh_manifest_sha256=$FreshBaselineManifestSha256;fresh_source_checkpoint=$sourceCheckpoint.ToString('D');fresh_source_binding=$baseline.provenance.source_binding;baseline_sha256=$baseline.sha256;baseline_basis_sha256=$baseline.basis_sha256;baseline_request_sha256='';baseline_result_sha256='';minimum_extent_only_streams=654;minimum_tail_extent_only_streams=650;journal_budget_bytes=8GB;literal_ceiling_bytes=256MB;combined_ceiling_bytes=10GB;digest_bytes=$digest.bytes;digest_sha256=$digest.sha256;expected_exit=$expectedExit;require_preparation_copy_reuse=[bool]$RequirePreparationCopyReuse;require_closing_read_reuse=[bool]$RequireClosingReadReuse;require_source_directory_case=[bool]$RequireSourceDirectoryCase}
    Save 'intent.json' @{kind='prepared-source-performance-experiment-intent';configuration=$c;parent_id=$ExpectedParent;checkpoint_ids=$ids;toolset_manifest=$ToolsetManifest;toolset_manifest_sha256=$ToolsetManifestSha256;source_commit=$SourceCommit;baseline_provenance=$baseline.provenance;capacity=$capacity;forecast_bytes=$ForecastAdditionalBytes;source_request_path=$SourceRequestPath;source_request_sha256=$SourceRequestSha256;function_sources=@($interrupt.pin,$normal.pin,@{path=$supportPath;sha256=$supportPin},@{path=$PSCommandPath;sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLowerInvariant()});observer_cost_gate_adaptation='D+literal -> (D-O-F)+F/256+literal+16MiB; combined includes backing';no_source_or_replay_authority=$true;utc=[DateTime]::UtcNow.ToString('o')}
    $guest = @'
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CONFIG__'))|ConvertFrom-Json
$script:closedJsonCache=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
$script:labIndexes=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
$script:labFreshBaseline=$null;$script:labBaselineContext=$null
$phase='preflight';$lastExit=$null;$nativeExit=$null;$process=$null;$requestPin=$null
__FUNCTIONS__
function AssertActualCapacity($Request,$Plan,$Result){
 Need ($Request.schema_version-eq3-and$Request.selected_capacity_policy-ceq'source_free_actual_bytes_v1'-and$Request.verification_policy-ceq'extent_identity_v1'-and$Request.verify_existing_shadow-eq$false-and$Request.max_journal_bytes-eq8GB-and$Request.max_literal_backing_bytes-eq256MB-and$Request.max_combined_scratch_bytes-eq10GB) 'Exact explicit fresh actual-byte request required.'
 $facts=AssertLabSourceFreeEncoding $Plan $c.output $Result
 Need ($facts.enabled-and$facts.old_zero_bytes-gt0-and(($facts.source_free_bytes-gt0-and$facts.format-ceq'N2RFRE01')-or($facts.source_free_bytes-eq0-and$facts.format-ceq'N2ROLD01'))-and$facts.journal_bytes-le8GB-and$facts.journal_bytes-lt$facts.selected_bytes) 'Exact encoded old-byte storage within8GiB required; clean free space retains lossless format4.'
 $capture=Json (Join-Path $c.output 'capture-capacity.json') 64MB;$b=$capture.budget
 Need ($b.selected_capacity_policy-ceq'source_free_actual_bytes_v1'-and$b.max_changed_bytes-eq52GB-and$b.max_journal_bytes-eq8GB-and$b.max_literal_backing_bytes-eq256MB-and$b.max_combined_backing_and_journal_bytes-eq10GB-and$b.minimum_free_bytes-eq1GB) 'Actual capture policy/bounds differ.'
 $observations=@($capture.observations);Need ($observations.Count-gt0-and$observations.Count-le65536) 'Bounded sampled live capacity observations required.'
 foreach($o in $observations){foreach($v in @($o.changed_bytes,$o.old_zero_bytes,$o.source_free_bytes,$o.source_free_hash_table_bytes,$o.literal_backing_bytes,$o.next_append_bytes,$o.projected_journal_bytes,$o.projected_combined_bytes,$o.required_available_bytes)){$null=LabIntegerKey $v};$d=[decimal]$o.changed_bytes;$z=[decimal]$o.old_zero_bytes;$l=[decimal]$o.literal_backing_bytes+[decimal]$o.next_append_bytes;$f=[decimal]$o.source_free_bytes;$j=$d-$z-$f+$f/256+$l+16MB;Need ($o.selected_capacity_policy-ceq'source_free_actual_bytes_v1'-and$z-ge0-and$f-ge0-and$z+$f-le$d-and$z%4096-eq0-and$f%4096-eq0-and$o.source_free_hash_table_bytes-eq$f/256-and$d-le52GB-and$l-le256MB-and$j-eq[decimal]$o.projected_journal_bytes-and$j-le8GB-and$j+$l-eq[decimal]$o.projected_combined_bytes-and$j+$l-le10GB-and$j+[decimal]$o.next_append_bytes+1GB-eq[decimal]$o.required_available_bytes-and[decimal]$o.space.available_bytes_to_caller-ge[decimal]$o.required_available_bytes) 'Sampled actual-byte capacity cost or observed free-space admission differs.'}
 if($null-ne$Result){Need ($Result.success-and$Result.selected_capacity_policy-ceq'source_free_actual_bytes_v1'-and$Result.actual_target_verification_policy-ceq'extent_identity_v1'-and-not$Result.actual_full_file_hashes) 'Actual normal result must identify the new policy and fast scope.'}

 $before=Json (Join-Path $c.output 'qualification\source-vss-before-freeze.json') 1MB;$after=Json (Join-Path $c.output 'qualification\source-vss-after-freeze.json') 1MB
 $volume='\\?\volume{'+([guid]$Request.pair.source.volume_guid).ToString('D')+'}\'
 Need ($before.source_volume_guid-ceq$volume-and$after.source_volume_guid-ceq$volume-and$before.hosted_storage_enumerated-and@($before.hosted_diff_areas).Count-eq0-and$before.hosted_diff_area_query_hresult-in@(0,1)-and-not$after.hosted_storage_enumerated-and$null-eq$after.hosted_diff_area_query_hresult) 'Actual VSS storage-before/presence-under-readonly scopes differ.'
 foreach($v in @($before,$after)){Need ($v.provider_inventory_completed-and$v.source_snapshot_presence.hresult-eq0-and$v.source_snapshot_presence.snapshots_present-eq$false-and$v.source_snapshot_presence.compatibility_flags-eq0-and-not$v.execution_authorized-and-not$v.source_exclusion_proven-and-not$v.inflight_snapshot_operations_excluded) 'VSS presence/error or authority scope differs.'}
 $left=@($before.providers|ForEach-Object {$_.id+':'+$_.class_id+':'+$_.kind+':'+$_.storage_role}|Sort-Object);$right=@($after.providers|ForEach-Object {$_.id+':'+$_.class_id+':'+$_.kind+':'+$_.storage_role}|Sort-Object);Need (SameArray $left $right) 'Actual VSS provider inventory changed.'
 $preservation=Json (Join-Path $c.output 'qualification\target-preservation.json') 64MB;$reads=$preservation.capture.read_counts
 $reused=0D;$fallback=0D;$prop=$reads.PSObject.Properties['source_reference_bytes_reused'];if($null-ne$prop){$null=LabIntegerKey $prop.Value;$reused=[decimal]$prop.Value};$prop=$reads.PSObject.Properties['source_reference_bytes'];if($null-ne$prop){$null=LabIntegerKey $prop.Value;$fallback=[decimal]$prop.Value}
 Need (($reused-gt0-or$facts.new_copy_bytes-eq0)-and$reused+$fallback-eq[decimal]$facts.new_copy_bytes-and$reused-le[decimal]$reads.source_logical_bytes) 'Exact COPY split required; zero COPY bytes need no positive reuse.'
 Save 'copy-read-reuse-verification.json' @{reused_bytes=[long]$reused;actual_fallback_read_bytes=[long]$fallback;copy_bytes=$facts.new_copy_bytes;source_logical_read_bytes=$reads.source_logical_bytes;scope='actual-capture-counter-observation';physical_io_or_wall_delta_claimed=$false;grants_product_authority=$false}
 $facts.source_reference_bytes_reused=[long]$reused;$facts.source_reference_bytes=[long]$fallback
 $caseRequirement=$c.PSObject.Properties['require_source_directory_case']
 if($null-ne$caseRequirement-and$caseRequirement.Value){
  $source=Json (Join-Path $c.output 'qualification\native-source.json') 64MB
  $basis=Json (Join-Path $c.output 'qualification\source-basis.json') 64MB
  $assessment=Json (Join-Path $c.output 'qualification\source-assessment.json') 64MB
  $case=$assessment.comparison.directory_case_sensitivity;$dirs=@($basis.ntfs.files|Where-Object {$_.is_directory});$admission=$assessment.assessment.directory_case_admission
  $required=@($admission.required_directories);$replaced=@($admission.replaced_internal_directories)
  Need ($source.schema_version-eq14-and$source.request.schema_version-eq6-and$dirs.Count-gt0-and$case.raw_directories-eq$dirs.Count-and@($case.directories).Count-eq$dirs.Count-and$admission.raw_directories-eq$dirs.Count-and$required.Count-gt0-and$required.Count+$replaced.Count-eq$dirs.Count-and$admission.matched_required_directories-eq$required.Count-and$admission.all_required_directories_case_insensitive-and$admission.internal_replacement_proof_bound-and@($admission.issues).Count-eq0) 'Every transferred directory needs actual zero case evidence; exclusions require bound internal replacement proof and retain Unknown diagnostics.'
  $rawKeys=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$covered=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach($d in $dirs){Need ($rawKeys.Add((LabRecordKey $d.record_number $d.sequence_number))) 'Duplicate raw directory identity.'}
  foreach($d in $required){$key=LabRecordKey $d.record_number $d.sequence_number;Need ($rawKeys.Contains($key)-and$covered.Add($key)) 'Required case identity is foreign/duplicate.';$found=@($case.directories|Where-Object {$_.record_number-eq$d.record_number-and$_.sequence_number-eq$d.sequence_number});Need ($found.Count-eq1-and$found[0].matched-and$found[0].before_flags-eq0-and$found[0].after_flags-eq0-and@($found[0].issues).Count-eq0) 'Required directory case evidence failed.'}
  foreach($d in $replaced){$key=LabRecordKey $d.record_number $d.sequence_number;Need ($rawKeys.Contains($key)-and$covered.Add($key)) 'Excluded case identity is foreign/overlapping.';$proof=@($assessment.internal_replacements|Where-Object {$_.record_number-eq$d.record_number-and$_.sequence_number-eq$d.sequence_number-and$_.role-ceq$d.role-and$_.action-ceq$d.action});Need ($proof.Count-eq1) 'Case exclusion lacks the exact validated internal replacement.'}
  Need ($covered.Count-eq$rawKeys.Count-and@($required|Where-Object record_number -eq 5).Count-eq1) 'Case scope must cover every raw directory and preserve the root.'
  Save 'source-directory-case-verification.json' @{scope='actual-frozen-ntfs-transferred-directory-case-v1';report_schema=14;request_schema=6;raw_directories=$dirs.Count;required_directories=$required.Count;matched_required_directories=$admission.matched_required_directories;proven_replaced_internal_directories=$replaced.Count;raw_unknown_or_failed_directories=@($case.directories|Where-Object {-not$_.matched}).Count;all_transferred_flags_zero_before_and_after=$true;raw_unknown_equated_to_false=$false;historical_baseline_equated=$false;grants_source_or_replay_authority=$false}
 }
 $closingRequirement=$c.PSObject.Properties['require_closing_read_reuse']
 if($null-ne$closingRequirement-and$closingRequirement.Value){
  $value=$reads.PSObject.Properties['shadow_bytes_reused_from_closing'];Need ($null-ne$value) 'Actual closing-byte reuse counter required.'
  $null=LabIntegerKey $value.Value;$closingReused=[decimal]$value.Value;$null=LabIntegerKey $reads.shadow_bytes;$null=LabIntegerKey $reads.source_logical_bytes
  $bracket=$preservation.protected.bracket_closure;$scope=$bracket.raw_consumption
  Need ($closingReused-gt0-and$closingReused-le[decimal]$bracket.closing_bytes_reread-and[decimal]$reads.shadow_bytes+$closingReused+[decimal]$reads.source_logical_bytes-eq[decimal]$preservation.capture.selected_bytes_compared-and$bracket.opening_bytes-eq$bracket.closing_bytes_reread-and$bracket.opening_chunks-eq$bracket.closing_chunks-and$scope.scope-ceq'source-backed-raw-consumption-v2'-and$scope.raw_metadata_hash_algorithm-ceq'sha256-framed-chunks-v1'-and$scope.opening_hash_counts.raw_bytes_read-eq$bracket.opening_bytes-and$scope.closing_hash_counts.raw_bytes_read-eq$bracket.closing_bytes_reread-and$scope.opening_hash_counts.zero_bytes_observed-eq$scope.closing_hash_counts.zero_bytes_observed-and$scope.preliminary_and_bracketed_native_routes_identical-and$scope.preliminary_and_bracketed_allocation_maps_identical-and$scope.raw_inspection_reads_covered) 'Actual closing reuse must retain both complete raw/zero brackets and exact read accounting.'
  Save 'closing-read-reuse-verification.json' @{scope='actual-closing-buffer-consumption-v1';bytes_reused=[long]$closingReused;actual_capture_shadow_reads=$reads.shadow_bytes;opening_bytes=$bracket.opening_bytes;closing_bytes=$bracket.closing_bytes_reread;zero_bytes_checked_each_pass=$scope.opening_hash_counts.zero_bytes_observed;source_or_replay_authority=$false}
 }
 if($c.require_preparation_copy_reuse){
  $prep=Json (Join-Path $c.output 'preparation-source-copy-reuse.json') 1MB
  Need ($prep.schema_version-eq1-and$prep.scope-ceq'same-frozen-native-source-reference-construction-v1'-and$prep.actual_source_copy_bytes_reused-eq$facts.new_copy_bytes-and$prep.candidate_bytes_still_read_and_hashed-and$prep.resolved_journal_copy_readback_retained-and$prep.fresh_old_target_gate_retained-and-not$prep.source_admission_granted) 'Actual paired-source preparation scope differs.'
  if($null-ne$Result){Need ($Result.preparation_source_copy_bytes_reused-eq$facts.new_copy_bytes) 'Actual result must record preparation reuse.'}
  Save 'preparation-read-reuse-verification.json' @{scope=$prep.scope;reused_bytes=$prep.actual_source_copy_bytes_reused;actual_metadata_path=(Join-Path $c.output 'preparation-source-copy-reuse.json');actual_metadata_sha256=(Get-FileHash -LiteralPath (Join-Path $c.output 'preparation-source-copy-reuse.json')).Hash.ToLowerInvariant();source_or_replay_authority=$false}
 }
 Save 'source-free-performance-verification.json' @{scope='lab-source-free-capacity-v1';facts=$facts;sampled_capacity_observations=$observations.Count;every_rolling_step_observed=$false;core_guards_every_proposed_run=$true;capture_layout_and_final_plan_remain_required=$true;raw_journal_opened=$false;lab_source_payload_bytes_read=0;grants_product_authority=$false}
 return $facts
}
function AssertPrepared($Expected,$Request){
 $basis=Json (Join-Path $c.output 'qualification\source-basis.json') 64MB;$native=Json (Join-Path $c.output 'qualification\native-source.json') 64MB
 $descriptor=AssertLabV3Envelope $Request.source_resource_profile $basis $Expected $native (Join-Path $c.output 'expectation.json') (Join-Path $c.output 'qualification\source-basis.json') (Join-Path $c.output 'qualification\native-source.json')
 Need ($descriptor.objects-eq1084-and$descriptor.files-eq811-and$descriptor.directories-eq273-and$descriptor.data_streams-eq811-and$native.schema_version-eq12-and$native.request.schema_version-eq4) 'Exact grown V3 current source/namespace scope required.'
 $tails=AssertLabTailReceipts $Expected $c.output;Need ($tails.tail_extent_only_streams-eq650-and$tails.materialized_tail_bytes-eq1371388) 'All actual constructor/protected tails required.'
 AssertPreparedFullBaseline $Expected $Request $c.output
 $rootMetadata=AssertFrozenRootMetadata $Expected $c.output $null;Save 'prepared-root-metadata.json' $rootMetadata
 Save 'prepared-tail-verification.json' $tails
}
try {
 Idle;SourceRoute $true;Protected
 Need ($env:COMPUTERNAME-ceq'N2R-WIN11'-and@(Get-Disk -ErrorAction Stop).Count-eq7-and@(Get-Disk -ErrorAction Stop|Where-Object Number -ge 6).Count-eq1) 'Prepared sourcecb802669 with its exact owned shadow6 required.'
 foreach($t in $c.tools){$p=Join-Path $c.stage $t.name;Need ((Get-Item -LiteralPath $p).Length-eq$t.bytes-and(Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()-ceq$t.sha256) 'Staged runtime pin differs.'}
 $fresh=ReadFreshLabSourceBaselineGuest $c.fresh_source_binding;Save 'fresh-baseline-preflight.json' @{success=$true;manifest_sha256=$c.fresh_manifest_sha256;descriptor=$fresh.descriptor;grants_product_authority=$false}
 Save 'wrapper-worker.json' @{pid=$PID;creation_ms=([DateTimeOffset](Get-Process -Id $PID).StartTime).ToUnixTimeMilliseconds();run_id=$c.run_id;utc=[DateTime]::UtcNow.ToString('o')}
 $managedPin=Join-Path $c.stage 'prepared-managed-result.json'
 Need ((Get-FileHash -LiteralPath $managedPin).Hash.ToLowerInvariant()-ceq$c.prepared_managed_sha256) 'Prepared managed receipt pin differs.'
 # Reuse the exact owned empty shadow; do not format another epoch.
 $made=Json $managedPin 1MB;$b=$made.binding;$disk=Get-Disk -Number $b.disk_number -ErrorAction Stop;$part=Get-Partition -DiskNumber $b.disk_number -PartitionNumber $b.identity.partition_number -ErrorAction Stop;$volume=$part|Get-Volume -ErrorAction Stop
 Need ($made.success-and$made.kind-ceq'new-owned-native-managed-shadow-smoke'-and-not$made.source_binding_supplied-and$made.source_writes-eq0-and$made.path-ceq(Join-Path $c.managed 'shadow.vhdx')-and[guid]$made.virtual_disk_id-ne[guid]::Empty-and$b.disk_number-eq6-and-not$disk.IsOffline-and-not$disk.IsReadOnly-and-not$disk.IsBoot-and-not$disk.IsSystem-and[guid]$disk.Guid-eq[guid]$b.identity.disk_guid-and[guid]$part.Guid-eq[guid]$b.identity.partition_guid-and$part.Size-eq52GB-and$part.Offset-eq32MB-and$volume.FileSystem-ceq'ReFS'-and$volume.AllocationUnitSize-eq4096-and$volume.FileSystemLabel-ceq'n2r-retained-shadow'-and@(Get-Disk|Where-Object Number -ge 6).Count-eq1) 'Actual new owned managed shadow differs.'
 Save 'managed-shadow.json' @{kind='managed-native-shadow-location';path=$made.path;virtual_disk_id=$made.virtual_disk_id;binding=$b}
 $seed=Json (Join-Path $c.stage 'routing-request.json') 131072
 Need ((Get-FileHash -LiteralPath (Join-Path $c.stage 'routing-request.json')).Hash.ToLowerInvariant()-ceq$c.source_request_sha256-and(SameJsonValue $seed.pair.source $c.fresh_source_binding)) 'Routing-only seed/source baseline differs.'
 $sd=Get-Disk -Number 1;$sp=Get-Partition -DiskNumber 1 -PartitionNumber 2;$sj=$seed.pair.source.identity
 Need ($sd.LogicalSectorSize-eq$sj.logical_sector_bytes-and$sd.PhysicalSectorSize-eq$sj.physical_sector_bytes-and('\\?\Volume{'+([guid]$seed.pair.source.volume_guid).ToString('D')+'}\')-in@($sp.AccessPaths)) 'Current source kernel geometry/volume differs.'
 $os=Get-Disk -Number 0;$cp=Get-Partition -DriveLetter C;$cj=$seed.journal.disk
 Need ($seed.journal.allow_additional_partitions-eq$true-and[guid]$os.Guid-eq[guid]$cj.identity.disk_guid-and$os.Size-eq$cj.identity.disk_bytes-and$os.LogicalSectorSize-eq$cj.identity.logical_sector_bytes-and$os.PhysicalSectorSize-eq$cj.identity.physical_sector_bytes-and[guid]$cp.Guid-eq[guid]$cj.identity.partition_guid-and$cp.PartitionNumber-eq$cj.identity.partition_number-and$cp.Offset-eq$cj.identity.partition_offset-and$cp.Size-eq$cj.identity.partition_bytes-and('\\?\Volume{'+([guid]$cj.volume_guid).ToString('D')+'}\')-in@($cp.AccessPaths)) 'Actual kernel C routing differs from seed.'
 $free=(Get-Volume -DriveLetter C).SizeRemaining;Need ($free-ge11GB) 'Actual C free must cover10GiB combined scratch plus1GiB reserve.'
 $r=[pscustomobject][ordered]@{schema_version=3;verification_policy='extent_identity_v1';selected_capacity_policy='source_free_actual_bytes_v1';source_resource_profile=[pscustomobject]@{experimental_object_envelope_v3=$null};experiment_id=$c.run_id;pair=[pscustomobject]@{source=$seed.pair.source;shadow=$b};journal=$seed.journal;max_journal_bytes=8GB;max_literal_backing_bytes=256MB;max_combined_scratch_bytes=10GB;verify_existing_shadow=$false}
 $request=Join-Path $c.stage 'request.json';Save 'request.json' $r;$requestPin=(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()
 Save 'request-derivation.json' @{routing_seed_sha256=$c.source_request_sha256;request_sha256=$requestPin;only_source_and_journal_routing_reused=$true;restored_admission_or_certificate=$false;resource_profile='V3 planningNone';measured_c_free_bytes=$free;selected_capacity_policy=$r.selected_capacity_policy;journal_bytes=8GB;literal_bytes=256MB;combined_bytes=10GB;reserve_bytes=1GB;grants_source_or_replay_authority=$false}
 Idle;SourceRoute $true;Protected
 $cli=@('--selected-devices','--allocation-bounded','--request',$request,'--request-sha256',$requestPin,'--output',$c.output,'--acknowledge-enrolled-disposable-devices','--maximum-placement-bytes','223338299392','--maximum-placement-submissions','32768','--maximum-exception-bytes','16777216')
 if($c.operation-ceq'interrupt'){$cli+=@('--fresh-exclusive-v3-first-write')}else{$cli+=@('--fresh-exclusive-v3')}
 $binary=Join-Path $c.stage 'lab-convert-native-composite.exe';$stdout=Join-Path $c.stage 'converter.stdout.log';$stderr=Join-Path $c.stage 'converter.stderr.log'
 $arguments=($cli|ForEach-Object {Need ($_-cnotmatch'["\r\n\x00]') 'Unsafe native argument.';$tail=$_.Length-$_.TrimEnd('\').Length;'"'+$_+('\'*$tail)+'"'})-join' '
 $producer=@($c.tools|Where-Object name -CEQ 'lab-convert-native-composite.exe')[0]
 Save 'converter-dispatch-intent.json' @{binary=$binary;binary_sha256=$producer.sha256;argv=$cli;expected_exit=$c.expected_exit;utc=[DateTime]::UtcNow.ToString('o')}
 $phase='native-capacity-conversion';$process=Start-Process -FilePath $binary -ArgumentList $arguments -WorkingDirectory $c.stage -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden;$null=$process.Handle
 Save 'converter-process.json' @{pid=$process.Id;creation_ms=([DateTimeOffset]$process.StartTime).ToUnixTimeMilliseconds();argv=$cli;binary_sha256=$producer.sha256;expected_exit=$c.expected_exit;process_handle_retained_before_wait=$true;utc=[DateTime]::UtcNow.ToString('o')}
 $process.WaitForExit();$process.Refresh();$nativeExit=$process.ExitCode;$lastExit=$nativeExit
 Save 'converter-terminal.json' @{pid=$process.Id;creation_ms=([DateTimeOffset]$process.StartTime).ToUnixTimeMilliseconds();native_exit=$nativeExit;native_exit_observed=($null-ne$nativeExit);stdout=(Log $stdout);stderr=(Log $stderr);utc=[DateTime]::UtcNow.ToString('o')}
 Need ($null-ne$nativeExit-and$nativeExit-eq$c.expected_exit) 'Actual native terminal differs; preserve without retry.'
 Idle;Protected;$phase='closed-capacity-evidence'
 $bundlePath=Join-Path $c.output 'allocation-recovery-bundle.json';$bundle=Json $bundlePath 65536;$bundlePin=(Get-FileHash -LiteralPath $bundlePath).Hash.ToLowerInvariant()
 $printed=Log $stdout;$matches=[regex]::Matches($printed.text,'(?m)^Recovery checksum: ([0-9a-f]{64})\r?$');$dirs=[regex]::Matches($printed.text,'(?m)^Recovery directory: (.+?)\r?$')
 Need ($matches.Count-eq1-and$dirs.Count-eq1-and$matches[0].Groups[1].Value-ceq$bundlePin-and$dirs[0].Groups[1].Value-ceq$c.output-and$bundle.kind-ceq'allocation-bounded-recovery-bundle'-and$bundle.serialized_bundle_grants_recovery_authority-eq$false) 'Native bundle publication must match actual saved bytes.'
 $rr=Json (Join-Path $c.output 'request.json') 131072;$plan=Json (Join-Path $c.output 'selected-plan.json') 16MB;$ticket=Json (Join-Path $c.output 'selected-ticket.json') 65536;$expected=Json (Join-Path $c.output 'expectation.json') 64MB
 foreach($key in @('request','plan','ticket','expectation','verification')){$leaf=@{request='request.json';plan='selected-plan.json';ticket='selected-ticket.json';expectation='expectation.json';verification='verification.json'}[$key];$path=Join-Path $c.output $leaf;Need ($bundle.$key.path-ceq$path-and$bundle.$key.sha256-ceq(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()) 'Complete actual recovery metadata pins required.'}
 Need ((SameJsonValue $rr.pair.source $r.pair.source)-and(SameJsonValue $rr.pair.shadow $r.pair.shadow)-and(SameJsonValue $rr.journal $r.journal)-and$rr.experiment_id-ceq$c.run_id) 'Admitted request changed fresh device routing.'
 $mapPath=Join-Path $c.output 'recovery-payload-manifest.json';$maps=Json $mapPath 64MB
 Need ($bundle.recovery_payload_manifest.path-ceq$mapPath-and$bundle.recovery_payload_manifest.sha256-ceq(Get-FileHash -LiteralPath $mapPath).Hash.ToLowerInvariant()-and$maps.kind-ceq'protected-target-stream-map-facts-v1'-and$maps.grants_write_authority-eq$false-and$maps.initial_retained_content_digests_available-eq$false-and$maps.expected_tree_sha256-ceq(Get-FileHash -LiteralPath (Join-Path $c.output 'expectation.json')).Hash.ToLowerInvariant()-and(SameJsonValue $maps.source $rr.pair.source)-and$maps.selected_bytes-eq$ticket.selected_bytes-and$maps.range_count-eq$ticket.range_count-and(SameArray $maps.new_selected_sha256 $ticket.new_selected_sha256)-and@($maps.bindings).Count-eq1084) 'Complete actual map manifest associations required.'
 $hash=[Security.Cryptography.SHA256]::Create();try{foreach($x in @(@{v=$plan;p=$maps.plan_sha256},@{v=$ticket;p=$maps.ticket_sha256})){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($x.v|ConvertTo-Json -Depth 64 -Compress));Need (([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()-ceq$x.p) 'Canonical map plan/ticket pin differs.'}}finally{$hash.Dispose()}
 AssertPrepared $expected $rr
 $result=$null;if($nativeExit-eq0){$result=Json (Join-Path $c.output 'result.json') 1MB}
 $facts=AssertActualCapacity $rr $plan $result
 if($nativeExit-eq86){
  SourceRoute $false;$shadow=Get-Disk -Number 6;Need ($shadow.IsOffline-and$shadow.IsReadOnly-and[guid]$shadow.Guid-eq[guid]$b.identity.disk_guid) 'Actual firstwrite persistent source/shadow attributes differ.'
  $fault=Json (Join-Path $c.output 'fresh-exclusive-fault-path.json') 1MB
  Need ($fault.schema_version-eq2-and$fault.kind-ceq'lab-fresh-exclusive-v3-first-write-path'-and$fault.preparation_completed-ceq'prepare_exclusive_owned'-and$fault.apply_entrypoint_requested-ceq'PreparedExclusiveJournal::apply_and_handoff'-and$fault.prepared_journal_owner_reused-and(SameJsonValue $fault.source_resource_profile $rr.source_resource_profile)-and$fault.requested_flushed_payload_writes-eq1-and$fault.controlled_exit_code-eq86-and-not$fault.hnd_allowed_if_interruption_not_reached-and-not$fault.source_writes_started-and$fault.diagnostic_only-and-not$fault.execution_authorized-and-not$fault.replay_authorized-and$fault.recovery_bundle_sha256-ceq$bundlePin) 'Actual owned firstwrite path diagnostic differs; it is not write proof.'
  $message=Log $stderr;Need ([regex]::Matches($message.text,'(?m)^Controlled general target interruption; source stays offline, recover using the pinned ticket[.]\r?$').Count-eq1-and-not(Test-Path -LiteralPath (Join-Path $c.output 'apply.json'))-and-not(Test-Path -LiteralPath (Join-Path $c.output 'handoff.json'))) 'Exactly one actual flushed firstwrite interruption and no Apply/HND required.'
  Save 'wrapper-controlled-interruption.json' @{kind='source-free-performance-firstwrite-observation';run_id=$c.run_id;native_exit=86;native_pid=$process.Id;native_creation_ms=([DateTimeOffset]$process.StartTime).ToUnixTimeMilliseconds();native_exit_observed=$true;bundle_path=$bundlePath;bundle_sha256=$bundlePin;recovery_directory=$c.output;source_offline=$true;source_readonly=$false;shadow_offline=$true;shadow_readonly=$true;capacity=$facts;handoff_closed_claimed=$false;raw_journal_opened=$false;source_certificate_recreated=$false;automatic_retry_recover_restore_cleanup=$false;utc=[DateTime]::UtcNow.ToString('o')};exit 86
 }
 $records=$c.output;$engine=$c.run_id;$devices=$r;$managed=Json (Join-Path $c.stage 'managed-shadow.json') 1MB;$final=Json (Join-Path $records 'finalization.json') 64MB
 __NORMAL_OBSERVER__
}catch{Save 'wrapper-failed.json' @{success=$false;phase=$phase;native_exit=$nativeExit;native_exit_observed=($null-ne$nativeExit);request_sha256=$requestPin;error=$_.Exception.ToString();automatic_retry_recover_restore_cleanup=$false;worker_death_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')};exit 1}
finally{if($null-ne$process){$process.Dispose()};foreach($e in $script:closedJsonCache.Values){$e.stream.Dispose()};$script:closedJsonCache.Clear();$script:labIndexes.Clear()}
'@
    $guest = [IO.File]::ReadAllText($supportPath) + [Environment]::NewLine + $guest
    if($RequireSourceDirectoryCase){
        # New-source-only schema adaptation. Historical baseline report11 stays
        # unchanged, and positive per-directory evidence is checked separately.
        $guest=$guest.Replace('$native.schema_version-eq12-and$native.request.schema_version-eq4','$native.schema_version-eq14-and$native.request.schema_version-eq6')
        $guest=$guest.Replace('$sourceNative.schema_version-eq12-and$sourceNative.request.schema_version-eq4','$sourceNative.schema_version-eq14-and$sourceNative.request.schema_version-eq6')
    }
    $guest = $guest.Replace('__FUNCTIONS__', ($definitions -join [Environment]::NewLine)).Replace('__NORMAL_OBSERVER__', $observer)
    $guest = $guest.Replace('__CONFIG__', [Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes(($c | ConvertTo-Json -Depth 32 -Compress))))
    $tokens=$null; $errors=$null; $null=[Management.Automation.Language.Parser]::ParseInput($guest,[ref]$tokens,[ref]$errors)
    Need ($errors.Count -eq 0 -and $guest.IndexOf('__NORMAL_OBSERVER__') -lt 0) 'Generated guest syntax/template differs.'
    $wrapper=Join-Path $root 'guest-wrapper.ps1';[IO.File]::WriteAllText($wrapper,$guest,[Text.UTF8Encoding]::new($false));$wrapperPin=(Get-FileHash -LiteralPath $wrapper).Hash.ToLowerInvariant()
    $session=New-PSSession -VMId $vmId -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml'))
    $ready=Invoke-Command -Session $session -ArgumentList $stage,$task -ScriptBlock {param($Stage,$Task)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        if($env:COMPUTERNAME-cne'N2R-WIN11'-or(Test-Path -LiteralPath $Stage)-or@(Get-ScheduledTask -ErrorAction Stop|Where-Object {$_.TaskName-ceq$Task-or($_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled'))}).Count-or@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-or@(Get-Disk -ErrorAction Stop).Count-ne7){throw 'Fresh idle prepared guest with its owned shadow required.'}
        $d=Get-Disk -Number 1;$p=Get-Partition -DiskNumber 1 -PartitionNumber 2;$v=$p|Get-Volume
        if($d.IsOffline-or$d.IsReadOnly-or$d.IsBoot-or$d.IsSystem-or[guid]$d.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or[guid]$p.Guid-ne[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-or$p.Size-ne52GB-or$p.Offset-ne16MB-or$v.FileSystem-cne'NTFS'-or$v.AllocationUnitSize-ne65536-or$v.FileSystemLabel-cne'n2r-stream-source'-or'F:\'-notin@($p.AccessPaths)){throw 'Restored grown source F identity/NTFS64K differs.'}
        $a=Get-Item -LiteralPath 'C:\ntfs2refs';while($null-ne$a){if($a.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse stage ancestry.'};$a=$a.Parent};New-Item -ItemType Directory -Path $Stage|Out-Null
        @{source_disk=1;source_offline=$false;source_readonly=$false;utc=[DateTime]::UtcNow.ToString('o')}
    };Save 'ready.json' $ready
    foreach($tool in $tools){Copy-Item -LiteralPath $tool.path -ToSession $session -Destination (Join-Path $stage $tool.name)}
    foreach($key in $baseline.files.Keys){$entry=$baseline.files[$key];Copy-Item -LiteralPath $entry.path -ToSession $session -Destination (Join-Path $stage $entry.name)}
    Copy-Item -LiteralPath $PreparedManagedReceiptPath -ToSession $session -Destination (Join-Path $stage 'prepared-managed-result.json')
    Copy-Item -LiteralPath $SourceRequestPath -ToSession $session -Destination (Join-Path $stage 'routing-request.json')
    Copy-Item -LiteralPath $wrapper -ToSession $session -Destination (Join-Path $stage 'wrapper.ps1');HostGuard
    Save 'dispatch.json' @{kind='source-free-performance-experiment-dispatch';run_id=$run;source_commit=$SourceCommit;expected_exit=$expectedExit;parent_id=$ExpectedParent;checkpoint_ids=$ids;task_name=$task;guest_stage=$stage;output_dir=$c.output;wrapper_sha256=$wrapperPin;configuration=$c;completion_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')}
    Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperPin,($c|ConvertTo-Json -Depth 32 -Compress) -ScriptBlock {param($Stage,$Task,$Pin,$Config)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$c=$Config|ConvertFrom-Json;$path=Join-Path $Stage 'wrapper.ps1'
        if((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$Pin-or@(Get-ScheduledTask -ErrorAction Stop|Where-Object TaskName -CEQ $Task).Count){throw 'Fresh exact SYSTEM task required.'}
        foreach($t in $c.tools){$p=Join-Path $Stage $t.name;if((Get-Item -LiteralPath $p).Length-ne$t.bytes-or(Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()-cne$t.sha256){throw 'Staged tool pin differs.'}}
        foreach($property in $c.fresh_baseline_files.PSObject.Properties){$v=$property.Value;$p=Join-Path $Stage $v.name;if((Get-Item -LiteralPath $p).Length-ne$v.bytes-or(Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()-cne$v.sha256){throw 'Prelaunch fresh baseline pin differs.'}}
        if((Get-FileHash -LiteralPath (Join-Path $Stage 'routing-request.json')).Hash.ToLowerInvariant()-cne$c.source_request_sha256){throw 'Routing seed pin differs.'}
        Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'"')) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)) -ErrorAction Stop|Out-Null
    }
    HostGuard;Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration $configuration) -AdditionalBytes $ForecastAdditionalBytes
    Invoke-Command -Session $session -ArgumentList $task,$stage,$wrapperPin -ScriptBlock {param($Task,$Stage,$Pin)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskName $Task;$i=$t|Get-ScheduledTaskInfo;$p=Join-Path $Stage 'wrapper.ps1'
        if($t.State.ToString()-cne'Ready'-or$i.LastRunTime.Year-ge2000-or@($t.Actions).Count-ne1-or$t.Actions[0].Execute-cne"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"-or$t.Actions[0].Arguments-cne('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$p+'"')-or$t.Principal.UserId-notin@('SYSTEM','S-1-5-18')-or$t.Principal.RunLevel.ToString()-cne'Highest'-or(Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()-cne$Pin-or@(Get-ScheduledTask -ErrorAction Stop|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count){throw 'Only the untouched pinned SYSTEM task may start once.'};Start-ScheduledTask -TaskName $Task -ErrorAction Stop
    };Save 'start.json' @{start_issued_once=$true;expected_exit=$expectedExit;completion_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')}
    Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw
}catch{if($created-and-not(Test-Path -LiteralPath (Join-Path $root 'dispatch-failed.json'))){Save 'dispatch-failed.json' @{success=$false;error=$_.Exception.ToString();automatic_retry_restore_cleanup=$false;worker_death_inferred=$false}};throw}
finally{if($null-ne$session){Remove-PSSession $session -ErrorAction SilentlyContinue};if($null-ne$baseline-and$baseline.ContainsKey('held_streams')){foreach($s in $baseline.held_streams){$s.Dispose()}};foreach($s in $held){$s.Dispose()}}
