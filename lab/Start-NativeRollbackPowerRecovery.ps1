# Nested RB1/ABT1 actual-power recovery, derived from exact df88 controller.
# Root alone owns VM/power actions. Both actual-power receipts remain required:
# nested checkpoint -> original AP1 checkpoint8d -> preparedcb. Original AP1
# inputs remain recovery routes only. No Resume, fresh certificate, old exit86,
# shadow attachment, attribute change or raw journal reader is introduced.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ToolsetManifest,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ToolsetManifestSha256,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceCommit,
    [Parameter(Mandatory)][guid]$ExpectedParent,
    [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds,
    [Parameter(Mandatory)][string]$SourceRequestPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$SourceRequestSha256,
    [Parameter(Mandatory)][string]$PreparedManagedReceiptPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$PreparedManagedReceiptSha256,
    [Parameter(Mandatory)][ValidateRange(1,50000000000)][long]$ForecastAdditionalBytes,
    [switch]$AcknowledgeEnrolledDisposableDevices,
    [switch]$AcknowledgeUnqualifiedNativeMarkers,
    [Parameter(Mandatory)][string]$OriginalGuestBundlePath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$OriginalGuestBundleSha256,
    [Parameter(Mandatory)][string]$PowerCheckpointReceiptPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$PowerCheckpointReceiptSha256,
    [Parameter(Mandatory)][string]$OriginalAp1PowerCheckpointReceiptPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$OriginalAp1PowerCheckpointReceiptSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Operation = 'Recover'
$Rollback = $true
$workspace = 'D:\code\ntfs2refs'
$base = Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$vmId = [guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$preparedId = [guid]'cb802669-903c-48cc-99e5-57976b149e7d'
$originalAp1Id = [guid]'8d4192fe-003b-441f-8591-f0b271028841'
$protectedMain = 'c6bc5c52c8458ee70bd2567a9d8350105aeaa6245448df22675780403e04348b'
$managedSha = '184aad57e2c8c8616adb4ad57ed82e40aba31949c530015ebcc5f7b681bcf876'
$managedPath = 'C:\ntfs2refs\ntfs-owned-preparation-6ec16ed4b4774c13a76b1e282103c66e\managed-shadow\shadow.vhdx'
$run = [guid]::NewGuid().ToString('N')
$deliberatePause = $false
$mode = 'power-rollback-recovery'
$root = Join-Path $base ('native-marker-' + $mode + '-' + $run)
$stage = 'C:\ntfs2refs\native-marker-' + $mode + '-' + $run
$output = Join-Path $stage 'recovery'
$pauseSignalPath = $null
$pauseMarkerSlot = $null
$task = 'N2R-NativeMarker-' + $run
$preflightTask = 'N2R-NativeMarker-Preflight-' + $run
$ids = @($ExpectedCheckpointIds | ForEach-Object { $_.ToString('D') })
$held = [Collections.Generic.List[IO.FileStream]]::new()
$session = $null; $created = $false; $checkpoint = $null
function Need([bool]$Ok, [string]$Message) { if (-not $Ok) { throw $Message } }
function ParseJson([string]$Text) {
    $options = @{}
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { $options.DateKind = 'String' }
    return ($Text | ConvertFrom-Json @options)
}
function Same($A,$B){
 if($null-eq$A-or$null-eq$B){return ($null-eq$A-and$null-eq$B)}
 if($A-is[pscustomobject]-and$B-is[pscustomobject]){$ak=@($A.PSObject.Properties.Name|Sort-Object);$bk=@($B.PSObject.Properties.Name|Sort-Object);if(($ak-join'|')-cne($bk-join'|')){return $false};foreach($k in $ak){if(-not(Same $A.$k $B.$k)){return $false}};return $true}
 if($A-is[Collections.IList]-and$B-is[Collections.IList]){if($A.Count-ne$B.Count){return $false};for($i=0;$i-lt$A.Count;$i++){if(-not(Same $A[$i] $B[$i])){return $false}};return $true}
 return ([string]$A-ceq[string]$B)
}
function Ordinary([string]$Path, [long]$Maximum) {
    Need ([IO.Path]::GetFullPath($Path) -ceq $Path) 'Canonical absolute file required.'
    $item = Get-Item -LiteralPath $Path -Force
    Need (-not $item.PSIsContainer -and $item.Length -gt 0 -and $item.Length -le $Maximum) 'Bounded ordinary file required.'
    $cursor = $item
    while ($null -ne $cursor) {
        Need (-not ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Reparse ancestry refused.'
        if ($cursor -is [IO.DirectoryInfo]) { $cursor = $cursor.Parent } else { $cursor = $cursor.Directory }
    }
    return $item
}
function OpenPinned([string]$Path, [string]$Sha, [long]$Maximum, [bool]$Parse) {
    Need ($Sha -cmatch '\A[0-9a-f]{64}\z') 'Exact lowercase SHA-256 required.'
    $item = Ordinary $Path $Maximum
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'Read'); $held.Add($stream)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $actual = ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-','').ToLowerInvariant() } finally { $hash.Dispose() }
    Need ($actual -ceq $Sha -and $stream.Length -eq $item.Length) 'Held file SHA/length differs.'
    $stream.Position = 0; $value = $null
    if ($Parse) {
        $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false), $true, 4096, $true)
        try { $value = ParseJson $reader.ReadToEnd() } finally { $reader.Dispose() }
    }
    return @{item=$item; value=$value; sha256=$actual}
}
function Save([string]$Name, $Value) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 48))
    Need ($bytes.Length -le 4MB) 'Bounded host receipt required.'
    $file = [IO.File]::Open((Join-Path $root $Name), 'CreateNew', 'Write', 'Read')
    try { $file.Write($bytes,0,$bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
}
function HostGuard {
    $vm = Get-VM -Id $vmId -ErrorAction Stop
    $nodes = @(Get-VMSnapshot -VM $vm -ErrorAction Stop)
    $actual = @($nodes | ForEach-Object { $_.Id.ToString('D') })
    Need ($vm.Name -ceq 'ntfs2refs-streaming-v2-20261027' -and $vm.State.ToString() -ceq 'Running' -and
        $vm.ParentSnapshotId -eq $ExpectedParent -and $vm.MemoryStartup -eq 4GB -and $vm.MemoryAssigned -eq 4GB -and
        -not $vm.DynamicMemoryEnabled -and (Get-VMProcessor -VM $vm).Count -eq 4 -and
        @(Get-VMNetworkAdapter -VM $vm).Count -eq 0 -and $actual.Count -eq $ids.Count -and
        @($ids | Where-Object { $_ -notin $actual }).Count -eq 0) 'Exact already running VM/parent/checkpoint set/4GiB/4CPU/noNIC required.'
    if ($Operation -ceq 'Recover') {
        $original = @($nodes | Where-Object Id -EQ $ExpectedParent)
        $ap1 = @($nodes | Where-Object Id -EQ $originalAp1Id)
        Need ($original.Count -eq 1 -and $original[0].ParentSnapshotId -eq $originalAp1Id -and $ap1.Count -eq 1 -and $ap1[0].ParentSnapshotId -eq $preparedId) 'Nested recovery requires exact checkpoint -> original AP1(8d) -> preparedcb ancestry.'
    }
}
try {
    Need ($AcknowledgeEnrolledDisposableDevices -and $AcknowledgeUnqualifiedNativeMarkers) 'Both explicit enrolled-device and unqualified-marker acknowledgments required.'
    Need ($ids.Count -gt 0 -and $ids.Count -le 50 -and @($ids | Sort-Object -Unique).Count -eq $ids.Count -and
        $preparedId.ToString('D') -in $ids -and $originalAp1Id.ToString('D') -in $ids -and $ExpectedParent.ToString('D') -in $ids -and [guid]::Empty.ToString('D') -notin $ids) 'Exact nonempty checkpoint set required.'
    Need ($ExpectedParent -ne $preparedId -and $ExpectedParent -ne $originalAp1Id) 'An exact nested RB1/ABT1 power checkpoint child of original AP1 is required.'
    foreach ($path in @($ToolsetManifest,$SourceRequestPath,$PreparedManagedReceiptPath)) {
        Need ($path.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)) 'Pinned inputs must remain in the owned lab.'
    }
    $manifestFile = OpenPinned $ToolsetManifest $ToolsetManifestSha256 1MB $true
    $manifest = $manifestFile.value
    Need ($manifestFile.item.Name -ceq 'manifest.json' -and $manifest.schema_version -eq 2 -and
        $manifest.kind -ceq 'source-free-performance-toolset' -and $manifest.source_commit -ceq $SourceCommit -and
        $manifest.protected_main_sha256 -ceq $protectedMain -and $manifest.native_marker_qualified -eq $false -and
        @($manifest.tools).Count -eq 4) 'Exact schema2 sealed toolset/source/main pin and unqualified status required.'
    $tools = @(); $rows = @($manifest.tools) + @($manifest.native_marker_experiment_tool)
    foreach ($name in @('ntfs2refs.exe','lab-convert-native-composite.exe','lab-content-digest.exe','lab-managed-shadow.exe','lab-selected-marker-native.exe')) {
        $matches = @($rows | Where-Object name -CEQ $name)
        Need ($matches.Count -eq 1 -and $matches[0].path -ceq (Join-Path $manifestFile.item.DirectoryName $name) -and
            $matches[0].bytes -gt 0 -and $matches[0].bytes -le 64MB) 'Five exact sealed tool roles required.'
        $row = $matches[0]; $opened = OpenPinned $row.path $row.sha256 64MB $false
        Need ($opened.item.Length -eq $row.bytes) 'Sealed tool length differs.'
        if ($name -in @('ntfs2refs.exe','lab-convert-native-composite.exe','lab-selected-marker-native.exe')) {
            Need ($row.origin.kind -ceq 'built_runtime' -and $row.origin.source_commit -ceq $SourceCommit) 'Runtime origin must match the supplied commit.'
        }
        $tools += @{name=$name; path=$opened.item.FullName; bytes=$row.bytes; sha256=$row.sha256; origin=$row.origin}
    }
    $seed = (OpenPinned $SourceRequestPath $SourceRequestSha256 131072 $true).value
    $prepared = (OpenPinned $PreparedManagedReceiptPath $PreparedManagedReceiptSha256 1MB $true).value
    Need ($PreparedManagedReceiptSha256 -ceq $managedSha -and $prepared.success -eq $true -and
        $prepared.kind -ceq 'new-owned-native-managed-shadow-smoke' -and $prepared.source_writes -eq 0 -and
        $prepared.source_binding_supplied -eq $false -and $prepared.path -ceq $managedPath -and
        [guid]$prepared.virtual_disk_id -eq [guid]'afd68132-7ad8-4a23-83a4-1cdcc20b927d') 'Original prepared owned-shadow receipt required.'
    Need ($seed.schema_version -eq 3 -and $seed.verification_policy -ceq 'extent_identity_v1' -and
        $seed.selected_capacity_policy -ceq 'source_free_actual_bytes_v1' -and
        $null -eq $seed.source_resource_profile.experimental_object_envelope_v3 -and $seed.verify_existing_shadow -eq $false -and
        $seed.max_journal_bytes -eq 8GB -and $seed.max_literal_backing_bytes -eq 256MB -and $seed.max_combined_scratch_bytes -eq 10GB) 'Pinned routing seed must retain fresh V3 planningNone and exact source-free budgets.'
    Need ($OriginalAp1PowerCheckpointReceiptPath.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase) -and
        $OriginalGuestBundlePath -cmatch '\AC:\\ntfs2refs\\native-marker-fresh-power-(?:ap1)-[0-9a-f]{32}\\conversion\\allocation-recovery-bundle[.]json\z') 'Original actual-power checkpoint and AP1/HND1 bundle routes required.'
    $ap1Checkpoint = (OpenPinned $OriginalAp1PowerCheckpointReceiptPath $OriginalAp1PowerCheckpointReceiptSha256 1MB $true).value
    $originalOutput = Split-Path -Parent $OriginalGuestBundlePath
    $originalStage = Split-Path -Parent $originalOutput
    $originalMatch = [regex]::Match($originalStage, '\AC:\\ntfs2refs\\native-marker-fresh-power-(ap1)-([0-9a-f]{32})\z')
    Need $originalMatch.Success 'Exact original fresh-power stage required.'
    $originalRun = $originalMatch.Groups[2].Value
    $powerCopy = $originalMatch.Groups[1].Value.ToUpperInvariant()
    $powerSlot = if ($powerCopy -ceq 'AP1') { 0 } else { 4 }
    Need (-not $Rollback -or $powerCopy -ceq 'AP1') 'HND1 already closes raw replay; only verify_handoff is allowed and rollback is refused.'
    Need ($ap1Checkpoint.schema_version -eq 1 -and $ap1Checkpoint.kind -ceq 'native-marker-power-checkpoint-v1' -and
        [guid]$ap1Checkpoint.vm_id -eq $vmId -and [guid]$ap1Checkpoint.checkpoint_id -eq $originalAp1Id -and
        [guid]$ap1Checkpoint.checkpoint_parent_id -eq $preparedId -and $ap1Checkpoint.state -ceq 'Off' -and
        $ap1Checkpoint.memory_assigned_bytes -eq 0 -and $ap1Checkpoint.native_pid -gt 0 -and $ap1Checkpoint.native_creation_ms -gt 0 -and
        $ap1Checkpoint.native_process_alive_before_poweroff -eq $true -and $ap1Checkpoint.native_process_birth_matched_before_poweroff -eq $true -and
        $ap1Checkpoint.task_running_before_poweroff -eq $true -and $ap1Checkpoint.task_name -ceq ('N2R-NativeMarker-'+$originalRun) -and
        $ap1Checkpoint.native_exit_observed -eq $false -and $null -eq $ap1Checkpoint.native_exit -and
        $ap1Checkpoint.poweroff_issued -eq $true -and $ap1Checkpoint.poweroff_method -ceq 'Stop-VM-TurnOff' -and
        $ap1Checkpoint.marker_copy -ceq $powerCopy -and $ap1Checkpoint.marker_slot -eq $powerSlot -and
        $ap1Checkpoint.signal_path -ceq (Join-Path $originalOutput 'marker-pause.json') -and $ap1Checkpoint.signal_bytes -eq 32768 -and
        $ap1Checkpoint.journal_format -ceq 'N2RFRE02' -and $ap1Checkpoint.journal_format_version -eq 6 -and $ap1Checkpoint.marker_profile -ceq 'RedundantSourceFreeV1' -and
        (Same $ap1Checkpoint.source $seed.pair.source) -and (Same $ap1Checkpoint.shadow $seed.pair.shadow) -and
        $ap1Checkpoint.bundle_path -ceq $OriginalGuestBundlePath -and $ap1Checkpoint.bundle_sha256 -ceq $OriginalGuestBundleSha256 -and
        $ap1Checkpoint.ticket_path -ceq (Join-Path $originalOutput 'selected-ticket.json') -and
        $ap1Checkpoint.process_path -ceq (Join-Path $originalStage 'native-process.json') -and
        $ap1Checkpoint.prepared_managed_receipt_sha256 -ceq $managedSha) 'Actual original power-cut receipt differs; no fabricated terminal/exit or serialized replay authority is accepted.'
    foreach ($pin in @($ap1Checkpoint.signal_sha256,$ap1Checkpoint.ticket_sha256,$ap1Checkpoint.process_sha256,$ap1Checkpoint.producer_sha256)) { Need ($pin -cmatch '\A[0-9a-f]{64}\z') 'Original signal/ticket/process/producer pins required.' }
    foreach ($stamp in @($ap1Checkpoint.poweroff_issued_utc,$ap1Checkpoint.off_observed_utc)) { Need ($stamp -cmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.][0-9]{1,7})?(?:Z|[+]00:00)\z') 'Actual UTC power/off observation timestamps required.' }
    Need ([DateTimeOffset]$ap1Checkpoint.off_observed_utc -ge [DateTimeOffset]$ap1Checkpoint.poweroff_issued_utc) 'Off observation must follow the actual issued power action.'
    Need ($PowerCheckpointReceiptPath.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)) 'Pinned nested root power receipt must remain in the owned lab.'
    $checkpoint = (OpenPinned $PowerCheckpointReceiptPath $PowerCheckpointReceiptSha256 1MB $true).value
    $pausedStage = [string]$checkpoint.producer_stage
    $pausedMatch = [regex]::Match($pausedStage,'\AC:\\ntfs2refs\\native-marker-power-rollback-pause-(rb1|abt1)-([0-9a-f]{32})\z')
    Need $pausedMatch.Success 'Exact independently paused RecoverRollback stage required; never derive it from the original bundle parent.'
    $pausedRun = $pausedMatch.Groups[2].Value
    $rollbackPowerCopy = $pausedMatch.Groups[1].Value.ToUpperInvariant()
    $rollbackPowerSlot = if ($rollbackPowerCopy -ceq 'RB1') { 2 } else { 6 }
    $pausedOutput = Join-Path $pausedStage 'recovery'
    Need ($checkpoint.schema_version -eq 1 -and $checkpoint.kind -ceq 'native-marker-rollback-power-checkpoint-v1' -and
        [guid]$checkpoint.vm_id -eq $vmId -and [guid]$checkpoint.checkpoint_id -eq $ExpectedParent -and
        [guid]$checkpoint.checkpoint_parent_id -eq $originalAp1Id -and [guid]$checkpoint.original_ap1_checkpoint_id -eq $originalAp1Id -and
        [guid]$checkpoint.original_ap1_checkpoint_parent_id -eq $preparedId -and $checkpoint.original_ap1_checkpoint_receipt_sha256 -ceq $OriginalAp1PowerCheckpointReceiptSha256 -and
        $checkpoint.state -ceq 'Off' -and $checkpoint.memory_assigned_bytes -eq 0 -and $checkpoint.native_pid -gt 0 -and $checkpoint.native_creation_ms -gt 0 -and
        $checkpoint.native_process_alive_before_poweroff -eq $true -and $checkpoint.native_process_birth_matched_before_poweroff -eq $true -and
        $checkpoint.task_running_before_poweroff -eq $true -and $checkpoint.task_name -ceq ('N2R-NativeMarker-'+$pausedRun) -and
        $checkpoint.native_exit_observed -eq $false -and $null -eq $checkpoint.native_exit -and $checkpoint.poweroff_issued -eq $true -and $checkpoint.poweroff_method -ceq 'Stop-VM-TurnOff' -and
        $checkpoint.marker_copy -ceq $rollbackPowerCopy -and $checkpoint.marker_slot -eq $rollbackPowerSlot -and $checkpoint.producer_output -ceq $pausedOutput -and
        $checkpoint.signal_path -ceq (Join-Path $pausedOutput 'marker-pause.json') -and $checkpoint.signal_bytes -eq 32768 -and
        $checkpoint.journal_format -ceq 'N2RFRE02' -and $checkpoint.journal_format_version -eq 6 -and $checkpoint.marker_profile -ceq 'RedundantSourceFreeV1' -and
        (Same $checkpoint.source $seed.pair.source) -and (Same $checkpoint.shadow $seed.pair.shadow) -and
        $checkpoint.bundle_path -ceq $OriginalGuestBundlePath -and $checkpoint.bundle_sha256 -ceq $OriginalGuestBundleSha256 -and
        $checkpoint.ticket_path -ceq (Join-Path $originalOutput 'selected-ticket.json') -and $checkpoint.ticket_sha256 -ceq $ap1Checkpoint.ticket_sha256 -and
        $checkpoint.process_path -ceq (Join-Path $pausedStage 'native-process.json') -and $checkpoint.producer_configuration_path -ceq (Join-Path $pausedStage 'configuration.json') -and
        $checkpoint.prepared_managed_receipt_sha256 -ceq $managedSha) 'Actual nested power receipt/ancestry/original AP1 pins differ; no exit or fresh authority is inferred.'
    foreach ($pin in @($checkpoint.signal_sha256,$checkpoint.process_sha256,$checkpoint.producer_sha256,$checkpoint.producer_configuration_sha256)) { Need ($pin -cmatch '\A[0-9a-f]{64}\z') 'Actual paused rollback signal/process/configuration/producer pins required.' }
    foreach ($stamp in @($checkpoint.poweroff_issued_utc,$checkpoint.off_observed_utc)) { Need ($stamp -cmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.][0-9]{1,7})?(?:Z|[+]00:00)\z') 'Actual nested UTC power/off observation timestamps required.' }
    Need ([DateTimeOffset]$checkpoint.off_observed_utc -ge [DateTimeOffset]$checkpoint.poweroff_issued_utc) 'Nested Off observation must follow the actual issued power action.'
    Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
    $configuration = Get-LabConfiguration -WorkspaceRoot $workspace
    Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration $configuration) -AdditionalBytes $ForecastAdditionalBytes
    HostGuard
    $null = New-Item -ItemType Directory -Path $root; $created = $true
    $request = [pscustomobject][ordered]@{
        schema_version=3; verification_policy='extent_identity_v1'; selected_capacity_policy='source_free_actual_bytes_v1'
        source_resource_profile=[pscustomobject]@{experimental_object_envelope_v3=$null}; experiment_id=$run
        pair=$seed.pair; journal=$seed.journal; max_journal_bytes=8GB; max_literal_backing_bytes=256MB
        max_combined_scratch_bytes=10GB; verify_existing_shadow=$false
    }
    Save 'request.json' $request
    $requestSha = (Get-FileHash -LiteralPath (Join-Path $root 'request.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    $null = OpenPinned (Join-Path $root 'request.json') $requestSha 131072 $false
    $config = [ordered]@{schema_version=1; run_id=$run; operation=$Operation; mode=$mode; task=$task; preflight_task=$preflightTask; stage=$stage
        output=$output
        tools=$tools; source_commit=$SourceCommit; manifest_sha256=$ToolsetManifestSha256
        request_sha256=$requestSha; routing_seed_sha256=$SourceRequestSha256; source=$seed.pair.source; shadow=$seed.pair.shadow; journal=$seed.journal
        prepared_managed_sha256=$managedSha; managed_path=$managedPath; first_write_fault=$false; rollback=[bool]$Rollback
        deliberate_pause=$false; pause_after_marker_copy=$null
        pause_marker_slot=$null; pause_signal_path=$null; pause_signal_bytes=$null
        expected_exit=0; bundle_path=$OriginalGuestBundlePath; bundle_sha256=$OriginalGuestBundleSha256
        checkpoint=$ap1Checkpoint; checkpoint_sha256=$OriginalAp1PowerCheckpointReceiptSha256
        rollback_power_checkpoint=$checkpoint; rollback_power_checkpoint_sha256=$PowerCheckpointReceiptSha256
        rollback_power_marker_copy=$rollbackPowerCopy; rollback_power_marker_slot=$rollbackPowerSlot; paused_stage=$pausedStage; paused_output=$pausedOutput; paused_run_id=$pausedRun
        power_marker_copy=$powerCopy; power_marker_slot=$powerSlot; original_stage=$originalStage; original_output=$originalOutput; original_run_id=$originalRun
        expected_native_action=$(if ($rollbackPowerCopy -ceq 'RB1') { 'rollback' } else { 'verify_aborted' })
        expected_original_lifecycle=$(if ($rollbackPowerCopy -ceq 'RB1') { 'rollback_intent' } else { 'aborted' })
        maximum_placement_bytes=16GB; maximum_placement_submissions=32768; maximum_exception_bytes=16MB}
    Save 'configuration.json' $config
    $configSha = (Get-FileHash -LiteralPath (Join-Path $root 'configuration.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    $null = OpenPinned (Join-Path $root 'configuration.json') $configSha 1MB $false
    $body = @'
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$held=[Collections.Generic.List[IO.FileStream]]::new();$shadowOwner=[pscustomobject]@{stream=$null;snapshot=$null;path=$null;receipt_path=$null;receipt_sha256=$null;checks=0};$process=$null;$stdoutStream=$null;$stderrStream=$null;$stdoutPipe=$null;$stderrPipe=$null;$nativeExit=$null;$requestPin=$null;$phase='staged-preflight'
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function ParseJson([string]$Text){$options=@{};if((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')){$options.DateKind='String'};return ($Text|ConvertFrom-Json @options)}
function Same($A,$B){
 if($null-eq$A-or$null-eq$B){return ($null-eq$A-and$null-eq$B)}
 if($A-is[pscustomobject]-and$B-is[pscustomobject]){$ak=@($A.PSObject.Properties.Name|Sort-Object);$bk=@($B.PSObject.Properties.Name|Sort-Object);if(($ak-join'|')-cne($bk-join'|')){return $false};foreach($k in $ak){if(-not(Same $A.$k $B.$k)){return $false}};return $true}
 if($A-is[Collections.IList]-and$B-is[Collections.IList]){if($A.Count-ne$B.Count){return $false};for($i=0;$i-lt$A.Count;$i++){if(-not(Same $A[$i] $B[$i])){return $false}};return $true}
 return ([string]$A-ceq[string]$B)
}
function OpenPinned([string]$Path,[string]$Sha,[long]$Maximum,[bool]$Parse){
 Need ([IO.Path]::GetFullPath($Path)-ceq$Path-and$Sha-cmatch'\A[0-9a-f]{64}\z') 'Canonical pinned path required.'
 $item=Get-Item -LiteralPath $Path -Force;Need (-not$item.PSIsContainer-and$item.Length-gt0-and$item.Length-le$Maximum) 'Bounded ordinary artifact required.'
 $cursor=$item;while($null-ne$cursor){Need (-not($cursor.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse input ancestry refused.';if($cursor-is[IO.DirectoryInfo]){$cursor=$cursor.Parent}else{$cursor=$cursor.Directory}}
 $stream=[IO.File]::Open($Path,'Open','Read','Read');$held.Add($stream);$hash=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()};Need ($actual-ceq$Sha-and$stream.Length-eq$item.Length) 'Held staged artifact SHA/length differs.';$stream.Position=0
 if($Parse){$reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false),$true,4096,$true);try{return (ParseJson $reader.ReadToEnd())}finally{$reader.Dispose()}}
}
function Json([string]$Path,[long]$Maximum=1MB){$pin=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant();return (OpenPinned $Path $pin $Maximum $true)}
function Save([string]$Name,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 48));Need ($bytes.Length-le4MB) 'Bounded observation required.';$f=[IO.File]::Open((Join-Path $c.stage $Name),'CreateNew','Write','Read');try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Pin([string]$Path){return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Log([string]$Path){$item=Get-Item -LiteralPath $Path -Force;Need (-not$item.PSIsContainer-and$item.Length-le8MB) 'Bounded terminal log required.';return @{bytes=$item.Length;sha256=(Pin $Path);text=[IO.File]::ReadAllText($Path)}}
function FailureText($Value,[int]$Maximum){$text=[string]$Value;$text=[regex]::Replace($text,'(?i)(-EncodedCommand\s+)[A-Za-z0-9+/=]+','$1[redacted]');if($text.Length-gt$Maximum){return ($text.Substring(0,$Maximum)+' [truncated]')};return $text}
function FailureDetails($Record){$position=$null;if($null-ne$Record.InvocationInfo){$position=$Record.InvocationInfo.PositionMessage};return @{error=(FailureText ($Record.Exception.ToString()) 8192);fully_qualified_error_id=(FailureText $Record.FullyQualifiedErrorId 1024);invocation_position_message=(FailureText $position 4096);script_stack_trace=(FailureText $Record.ScriptStackTrace 4096)}}
function Idle{
 $tasks=@(Get-ScheduledTask -ErrorAction Stop);$workers=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'-or($_.ProcessId-ne$PID-and$_.Name-match'\A(?:powershell|pwsh)\.exe\z'-and$_.CommandLine-like'*C:\ntfs2refs\*')})
 $ownedTask=if($phase-ceq'staged-system-preflight'){$c.preflight_task}else{$c.task}
 Need (@($tasks|Where-Object {$_.TaskName-like'N2R-*'-and$_.TaskName-cne$ownedTask-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-eq0-and$workers.Count-eq0) 'Every other N2R task must be terminal and every native/visible wrapper worker absent.'
}
function Binding($B,[bool]$Offline,[bool]$ReadOnly){
 $d=Get-Disk -Number $B.disk_number -ErrorAction Stop;$i=$B.identity;$p=Get-Partition -DiskNumber $B.disk_number -PartitionNumber $i.partition_number -ErrorAction Stop
 Need ($d.PartitionStyle.ToString()-ceq'GPT'-and[guid]$d.Guid-eq[guid]$i.disk_guid-and$d.Size-eq$i.disk_bytes-and$d.LogicalSectorSize-eq$i.logical_sector_bytes-and$d.PhysicalSectorSize-eq$i.physical_sector_bytes-and$d.IsOffline-eq$Offline-and$d.IsReadOnly-eq$ReadOnly-and[guid]$p.Guid-eq[guid]$i.partition_guid-and$p.Offset-eq$i.partition_offset-and$p.Size-eq$i.partition_bytes-and[guid]$B.volume_guid-eq[guid]$i.partition_guid) 'Actual bound disk geometry/attributes/partition differs; attributes are never cleared.'
 $unique=@(Get-Disk|Where-Object {[string]$_.Guid-ceq[string]$d.Guid});Need ($unique.Count-eq1) 'Disk identity must be unique.'
 if($B.disk_number-ne0){Need (-not$d.IsBoot-and-not$d.IsSystem) 'Data binding cannot name a boot/system disk.'}
 return @{disk=$d;partition=$p}
}
function InventoryRows($Disks){return @($Disks|Sort-Object Number|ForEach-Object {[pscustomobject][ordered]@{number=[int]$_.Number;guid=[string]$_.Guid;bytes=[long]$_.Size;offline=[bool]$_.IsOffline;readonly=[bool]$_.IsReadOnly;boot=[bool]$_.IsBoot;system=[bool]$_.IsSystem;bus_type=$_.BusType.ToString();location=[string]$_.Location;path=[string]$_.Path}})}
function Inventory {return @(InventoryRows @(Get-Disk -ErrorAction Stop))}
function Protected{
 $g=Get-Disk -Number 4;$p=Get-Partition -DriveLetter G;$v=$p|Get-Volume;$old=Get-Disk -Number 5
 Need ([guid]$g.Guid-eq[guid]'e1f3b9d3-979f-4123-9fee-399640c25092'-and-not$g.IsOffline-and-not$g.IsReadOnly-and$p.DiskNumber-eq4-and$v.FileSystem-ceq'ReFS'-and$v.AllocationUnitSize-eq4096-and[guid]$old.Guid-eq[guid]'ad077674-6305-4767-a2aa-6ded3b707e36'-and$old.IsOffline-and$old.IsReadOnly) 'Protected G4/shadow5 attributes differ.'
}
function Get-BackingFileSnapshot([IO.FileStream]$Stream){
 # Metadata is read from this actual retained handle, not from saved JSON or
 # a reopened path. https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle
 if(-not('N2RPowerBackingMetadataV1'-as[type])){
  $source=@"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public sealed class N2RPowerBackingSnapshotV1 {
 public ulong Length, LastWriteFileTime, FileId64;
 public uint Attributes, VolumeSerialNumber, NumberOfLinks;
}
public static class N2RPowerBackingMetadataV1 {
 [StructLayout(LayoutKind.Explicit, Size=52)]
 private struct Info {
  [FieldOffset(0)] public uint Attributes;
  [FieldOffset(20)] public uint WriteLow;
  [FieldOffset(24)] public uint WriteHigh;
  [FieldOffset(28)] public uint VolumeSerial;
  [FieldOffset(32)] public uint SizeHigh;
  [FieldOffset(36)] public uint SizeLow;
  [FieldOffset(40)] public uint Links;
  [FieldOffset(44)] public uint IndexHigh;
  [FieldOffset(48)] public uint IndexLow;
 }
 [DllImport("kernel32.dll", SetLastError=true)]
 [return: MarshalAs(UnmanagedType.Bool)]
 private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
 public static N2RPowerBackingSnapshotV1 Observe(SafeFileHandle handle) {
  Info info;
  if(!GetFileInformationByHandle(handle,out info)) throw new Win32Exception(Marshal.GetLastWin32Error(),"GetFileInformationByHandle retained backing");
  N2RPowerBackingSnapshotV1 result=new N2RPowerBackingSnapshotV1();
  result.Length=((ulong)info.SizeHigh<<32)|info.SizeLow;
  result.LastWriteFileTime=((ulong)info.WriteHigh<<32)|info.WriteLow;
  result.FileId64=((ulong)info.IndexHigh<<32)|info.IndexLow;
  result.Attributes=info.Attributes;result.VolumeSerialNumber=info.VolumeSerial;result.NumberOfLinks=info.Links;
  return result;
 }
}
"@
  Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
 }
 Need ($Stream.CanRead-and-not$Stream.CanWrite-and-not$Stream.SafeFileHandle.IsClosed-and-not$Stream.SafeFileHandle.IsInvalid) 'Original read-only exclusive backing handle must remain live.'
 $s=[N2RPowerBackingMetadataV1]::Observe($Stream.SafeFileHandle)
 Need ($s.Length-gt0-and$s.Length-eq$Stream.Length-and$s.LastWriteFileTime-gt0-and$s.FileId64-ne0-and$s.NumberOfLinks-gt0-and($s.Attributes-band1040)-eq0) 'Retained backing metadata must describe the same non-reparse ordinary file.'
 return [pscustomobject][ordered]@{length=[uint64]$s.Length;last_write_filetime_100ns=[uint64]$s.LastWriteFileTime;file_id64=[uint64]$s.FileId64;volume_serial_number=[uint32]$s.VolumeSerialNumber;attributes=[uint32]$s.Attributes;number_of_links=[uint32]$s.NumberOfLinks}
}
function RecoveryShadow{
 $inventory=@(Get-Disk -ErrorAction Stop);Need ($inventory.Count-in@(6,7)) 'Complete existing recovery disk inventory required.'
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
 $matches=@(foreach($disk in $inventory){$guid=[guid]::Empty;Need ([guid]::TryParse([string]$disk.Guid,[ref]$guid)-and$guid-ne[guid]::Empty-and$seen.Add($guid.ToString('D'))) 'Unknown or duplicate current recovery disk GUID refused.';if($guid-eq[guid]$c.shadow.identity.disk_guid){$disk}})
 Need ($matches.Count-le1) 'Duplicate original recovery shadow identity refused.'
 $image=Get-Item -LiteralPath $c.managed_path -Force;Need (-not$image.PSIsContainer-and$image.Length-gt0) 'Original recovery managed VHDX must remain an existing ordinary file.'
 $cursor=$image;while($null-ne$cursor){Need (-not($cursor.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Reparse recovery managed VHDX ancestry refused.';if($cursor-is[IO.DirectoryInfo]){$cursor=$cursor.Parent}else{$cursor=$cursor.Directory}}
 if($matches.Count-eq1){
  Need ($null-eq$shadowOwner.stream-and$inventory.Count-eq7-and$matches[0].Number-eq$c.shadow.disk_number) 'Present original shadow must remain disk6 and cannot appear while its absent backing guard is held.'
  $null=Binding $c.shadow $true $true
  $provider=Get-DiskImage -ImagePath $c.managed_path -ErrorAction Stop
  Need ([string]::Equals([string]$provider.ImagePath,$c.managed_path,[StringComparison]::OrdinalIgnoreCase)-and$provider.Attached-and[string]::Equals([string]$provider.DevicePath,'\\.\PhysicalDrive6',[StringComparison]::OrdinalIgnoreCase)) 'Present original shadow requires its exact original attached provider and offline/read-only geometry.'
  $providerFacts=@{image_path=[string]$provider.ImagePath;device_path=[string]$provider.DevicePath;attached=[bool]$provider.Attached;provider_query_performed=$true;query_error_is_absence=$false;exclusive_backing_guard_applicable=$false}
  $completeInventory=Inventory
 }else{
  # This independent branch is selected only by the complete affirmative disk
  # inventory. A successful Read/ShareNone open then excludes ordinary provider
  # attachment while held. No VHDX/log contents, creator ID or virtual geometry
  # are queried or inferred; this self-contained allocation recovery never uses
  # the absent shadow. Provider errors never enter this branch as absence.
  Need ($inventory.Count-eq6-and@($inventory|Where-Object Number -EQ $c.shadow.disk_number).Count-eq0) 'Absent original shadow requires all current GUIDs unique, no original GUID and no disk6.'
  $beforeInventory=@(InventoryRows $inventory);$acquiredNow=$false
  if($null-eq$shadowOwner.stream){
   $stream=[IO.File]::Open($c.managed_path,'Open','Read','None');$held.Add($stream)
   $snapshot=Get-BackingFileSnapshot $stream
   Need ($stream.Name-ceq$c.managed_path-and$snapshot.length-eq$image.Length) 'Exact original backing path/length differs at exclusive acquisition.'
   $shadowOwner.stream=$stream;$shadowOwner.snapshot=$snapshot;$shadowOwner.path=$c.managed_path;$acquiredNow=$true
  }
  Need ($shadowOwner.path-ceq$c.managed_path-and$shadowOwner.stream.Name-ceq$c.managed_path) 'Only the original process-owned exclusive backing stream may be reused.'
  $current=Get-BackingFileSnapshot $shadowOwner.stream
  Need ((Same $current $shadowOwner.snapshot)-and$current.length-eq$image.Length) 'Same retained backing handle length/mtime/identity changed.'
  $afterInventory=@(Get-Disk -ErrorAction Stop);$afterSeen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  Need ($afterInventory.Count-eq6-and@($afterInventory|Where-Object Number -EQ $c.shadow.disk_number).Count-eq0) 'Post-guard complete inventory must still contain exactly six disks and no disk6.'
  foreach($disk in $afterInventory){$guid=[guid]::Empty;Need ([guid]::TryParse([string]$disk.Guid,[ref]$guid)-and$guid-ne[guid]::Empty-and$guid-ne[guid]$c.shadow.identity.disk_guid-and$afterSeen.Add($guid.ToString('D'))) 'Post-guard inventory must have all GUIDs known/unique and no original shadow GUID.'}
  $completeInventory=@(InventoryRows $afterInventory)
  Need (Same $beforeInventory $completeInventory) 'Complete actual disk inventory changed during this owned backing guard check.'
  if($acquiredNow){
   $guardLeaf=if($phase-ceq'staged-system-preflight'){'system-preflight-shadow-exclusive-backing.json'}else{'recovery-shadow-exclusive-backing.json'}
   Save $guardLeaf @{schema_version=1;kind='actual-owned-absent-shadow-backing-guard';owner_context=$phase;image_path=$c.managed_path;access='Read';share='None';snapshot=$snapshot;complete_disk_inventory=$completeInventory;post_acquisition_inventory_validated=$true;pre_post_inventory_identical=$true;all_current_disk_guids_unique=$true;original_shadow_guid_present=$false;disk6_present=$false;backing_contents_read=$false;virtual_disk_id_queried=$false;virtual_disk_geometry_queried=$false;provider_query_performed=$false;query_error_is_absence=$false;serialized_record_grants_authority=$false;utc=[DateTime]::UtcNow.ToString('o')}
   $guardPath=Join-Path $c.stage $guardLeaf;$shadowOwner.receipt_path=$guardPath;$shadowOwner.receipt_sha256=Pin $guardPath;$null=OpenPinned $guardPath $shadowOwner.receipt_sha256 1MB $false
  }
  Need ((Pin $shadowOwner.receipt_path)-ceq$shadowOwner.receipt_sha256) 'Actual owned backing guard receipt changed.'
  $shadowOwner.checks++
  $providerFacts=@{image_path=$c.managed_path;device_path='';attached=$false;provider_query_performed=$false;query_error_is_absence=$false;exclusive_backing_guard_applicable=$true;exclusive_backing_guard_held=$true;exclusive_backing_guard_revalidated=$true;post_acquisition_inventory_validated=$true;pre_post_inventory_identical=$true;exclusive_backing_guard_revalidations=$shadowOwner.checks;exclusive_backing_guard_receipt_sha256=$shadowOwner.receipt_sha256;backing_snapshot=$current;backing_contents_read=$false;virtual_disk_id_queried=$false;virtual_disk_geometry_queried=$false;ordinary_provider_attachment_excluded_while_held=$true}
 }
 return @{scope='allocation-recovery-optional-original-managed-shadow-v1';shadow_present=($matches.Count-eq1);provider_check_applicable=($matches.Count-eq1);original_binding=$c.shadow;provider=$providerFacts;original_image_exists=$true;complete_disk_inventory=$completeInventory;all_current_disk_guids_unique=$true;reattachment_performed=$false;request_rebound=$false;attributes_changed=$false;raw_journal_opened=$false;grants_source_or_replay_authority=$false}
}
function Routes([bool]$Fresh){
 Need ($env:COMPUTERNAME-ceq'N2R-WIN11'-and$env:SystemDrive-ceq'C:'-and(($Fresh-and@(Get-Disk).Count-eq7)-or(-not$Fresh-and@(Get-Disk).Count-in@(6,7)))) 'Exact owning guest and existing fresh/recovery disk inventory required.'
 $s=$c.source;$h=$c.shadow;$j=$c.journal.disk
 Need ($s.disk_number-eq1-and[guid]$s.volume_guid-eq[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-and[guid]$s.identity.disk_guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'-and$s.identity.partition_number-eq2-and$s.identity.partition_offset-eq16MB-and$s.identity.partition_bytes-eq52GB-and$s.identity.disk_bytes-eq64GB-and$h.disk_number-eq6-and[guid]$h.identity.disk_guid-eq[guid]'b14b46fc-c7f4-4548-9391-52e18f75831b'-and[guid]$h.volume_guid-eq[guid]'6a1efd54-6209-42f1-a6c8-fd5ef88f5759'-and$h.identity.partition_number-eq2-and$h.identity.partition_offset-eq32MB-and$h.identity.partition_bytes-eq52GB-and$h.identity.disk_bytes-eq55901683712-and$j.disk_number-eq0-and[guid]$j.identity.disk_guid-eq[guid]'1f804918-e98f-4a71-9022-fc00c3cb7c26'-and[guid]$j.volume_guid-eq[guid]'c6c3318f-a7c8-47b9-be6d-6dde5e00862f'-and$j.identity.partition_number-eq3-and$j.identity.partition_offset-eq331350016-and$j.identity.partition_bytes-eq66238545920-and$j.identity.disk_bytes-eq64GB-and$c.journal.allow_additional_partitions-eq$true-and$c.journal.externally_enrolled_disk_unique_id-ceq'gpt-1f804918-e98f-4a71-9022-fc00c3cb7c26') 'Only the prepared exact source/shadow/OS routes are enrolled.'
 foreach($b in @($s,$h,$j)){Need ($b.identity.logical_sector_bytes-eq512-and$b.identity.physical_sector_bytes-eq4096) 'Exact sector geometry required.'}
 $source=Binding $s (-not$Fresh) $false
 if($Fresh){$v=$source.partition|Get-Volume;Need ($v.FileSystem-ceq'NTFS'-and$v.AllocationUnitSize-eq65536-and$v.FileSystemLabel-ceq'n2r-stream-source'-and'F:\'-in@($source.partition.AccessPaths)) 'Fresh live source must be the existing online writable NTFS64K F: route; core obtains the live certificate and freezes it.'}
 $os=Binding $j $false $false;$cp=Get-Partition -DriveLetter C;Need ($cp.DiskNumber-eq0-and$cp.PartitionNumber-eq3) 'Exact OS route required.'
 Need (('\\?\Volume{'+([guid]$j.volume_guid).ToString('D')+'}\')-in@($os.partition.AccessPaths)) 'OS volume GUID access route differs.'
 $cv=$cp|Get-Volume;Need ($cv.FileSystem-ceq'NTFS'-and$cv.SizeRemaining-ge$(if($Fresh){11GB}else{1GB})) 'Existing NTFS journal volume/free reserve differs.'
 $shadowObservation=$null;$shadowPresent=$true
 if($Fresh){
  $shadow=Binding $h $false $false
  $provider=Get-DiskImage -ImagePath $c.managed_path -ErrorAction Stop
  Need ($provider.Attached-and[string]::Equals([string]$provider.ImagePath,$c.managed_path,[StringComparison]::OrdinalIgnoreCase)-and[string]::Equals([string]$provider.DevicePath,'\\.\PhysicalDrive6',[StringComparison]::OrdinalIgnoreCase)) 'Same already attached owned VHDX provider required; no reattachment is performed.'
  $providerFacts=@{image_path=[string]$provider.ImagePath;device_path=[string]$provider.DevicePath;attached=[bool]$provider.Attached}
 }else{
  $shadowObservation=RecoveryShadow;$shadowPresent=$shadowObservation.shadow_present;$providerFacts=$shadowObservation.provider
 }
 $made=OpenPinned (Join-Path $c.stage 'prepared-managed-result.json') $c.prepared_managed_sha256 1MB $true
 Need ((Same $made.binding $h)-and$made.path-ceq$c.managed_path-and[guid]$made.virtual_disk_id-eq[guid]'afd68132-7ad8-4a23-83a4-1cdcc20b927d') 'Prepared managed identity differs.'
 if($Fresh){
  $v=$shadow.partition|Get-Volume;Need ($v.FileSystem-ceq'ReFS'-and$v.AllocationUnitSize-eq4096-and$v.FileSystemLabel-ceq'n2r-retained-shadow') 'Existing empty ReFS4K shadow required.'
  $volumePath='\\?\Volume{'+([guid]$h.volume_guid).ToString('D')+'}\';Need ($volumePath-in@($shadow.partition.AccessPaths)) 'Shadow volume route differs.'
  $entries=@(Get-ChildItem -LiteralPath $volumePath -Force -ErrorAction Stop)
  Need (@($entries|Where-Object {$_.Name-cne'System Volume Information'-or-not$_.PSIsContainer-or($_.Attributes-band[IO.FileAttributes]::ReparsePoint)}).Count-eq0) 'Prepared shadow contains user entries or unknown root metadata; refuse without formatting.'
 }
 Protected
 return @{source_offline=(-not$Fresh);source_readonly=$false;shadow_present=$shadowPresent;shadow_offline=$(if($shadowPresent){-not$Fresh}else{$null});shadow_readonly=$(if($shadowPresent){-not$Fresh}else{$null});provider=$providerFacts;recovery_shadow_observation=$shadowObservation;all_disk_attributes=(Inventory);attributes_changed_by_dispatcher=$false;reattached=$false;rebound=$false}
}
function AdmittedEnvelope($Profile,$Expected,[string]$Directory){
 Need ($null-ne$Profile-and$Profile-is[pscustomobject]-and@($Profile.PSObject.Properties).Count-eq1) 'One explicit admitted V3 profile required.'
 $property=$Profile.PSObject.Properties['experimental_object_envelope_v3'];Need ($null-ne$property-and$null-ne$property.Value) 'Saved admitted V3 Some descriptor required; fresh planning None remains only an input intent.';$a=$property.Value
 foreach($name in @('schema_version','raw_identities','files','directories','data_streams','object_slots','raw_identity_slots','data_stream_slots','maximum_expected_tree_bytes','maximum_inspection_bytes','maximum_native_report_bytes','projected_owned_handle_slots','maximum_owned_handle_slots','maximum_constructor_input_metadata_bytes')){Need ([string]$a.$name-cmatch'\A(?:0|[1-9][0-9]*)\z') 'Exact nonnegative integer descriptor fields required.'}
 $expectedPath=Join-Path $Directory 'expectation.json';$basisPath=Join-Path $Directory 'qualification\source-basis.json';$nativePath=Join-Path $Directory 'qualification\native-source.json'
 $basis=Json $basisPath 64MB;$native=Json $nativePath 64MB
 $files=@($Expected.objects|Where-Object {-not$_.directory}).Count;$dirs=@($Expected.objects|Where-Object {$_.directory}).Count;$streams=$files
 foreach($object in $Expected.objects){$named=$object.PSObject.Properties['named_streams'];if($null-ne$named){$streams+=@($named.Value).Count}}
 $units=@($a.source_inspection_sha256);Need ($units.Count-eq32-and@($units|Where-Object {[string]$_-cnotmatch'\A(?:0|[1-9][0-9]*)\z'-or[decimal]$_-gt255}).Count-eq0) 'Exact32-byte actual source inspection pin required.';$pin=([BitConverter]::ToString([byte[]]$units)).Replace('-','').ToLowerInvariant()
 Need ($a.schema_version-eq1-and$a.raw_identities-eq@($basis.ntfs.files).Count-and$a.files-eq$files-and$a.directories-eq$dirs-and$a.data_streams-eq$streams-and$files+$dirs-eq@($Expected.objects).Count-and$files+$dirs-le$a.object_slots-and$a.object_slots-le1280-and$a.object_slots-gt0-and$a.raw_identities-le$a.raw_identity_slots-and$a.raw_identity_slots-le2048-and$a.raw_identity_slots-gt0-and$a.data_streams-le$a.data_stream_slots-and$a.data_stream_slots-le16384-and$a.data_stream_slots-gt0-and$pin-ceq$basis.canonical_inspection_sha256-and$pin-ceq$native.request.source_inspection_sha256-and$a.raw_identities-eq@($native.request.files).Count-and(Same $Profile $native.request.resource_profile)) 'Actual saved V3 counts/descriptor must bind current canonical and native source evidence.'
 Need ($a.maximum_expected_tree_bytes-gt0-and$a.maximum_expected_tree_bytes-le16MB-and(Get-Item -LiteralPath $expectedPath).Length-le$a.maximum_expected_tree_bytes-and$a.maximum_constructor_input_metadata_bytes-gt0-and$a.maximum_constructor_input_metadata_bytes-le16MB-and$a.maximum_inspection_bytes-gt0-and$a.maximum_inspection_bytes-le64MB-and(Get-Item -LiteralPath $basisPath).Length-le$a.maximum_inspection_bytes-and$a.maximum_native_report_bytes-gt0-and$a.maximum_native_report_bytes-le64MB-and(Get-Item -LiteralPath $nativePath).Length-le$a.maximum_native_report_bytes-and$a.projected_owned_handle_slots-eq($files+$dirs+2*$streams+8)-and$a.projected_owned_handle_slots-le$a.maximum_owned_handle_slots-and$a.maximum_owned_handle_slots-le34056) 'Actual saved V3 byte/handle ceilings differ.'
 return @{raw_identities=$a.raw_identities;files=$files;directories=$dirs;data_streams=$streams;objects=$files+$dirs;source_inspection_sha256=$pin;descriptor=$a;basis_sha256=(Pin $basisPath);native_sha256=(Pin $nativePath);grants_source_or_replay_authority=$false}
}
function Artifacts([string]$Directory,[string]$BundleSha){
 $path=Join-Path $Directory 'allocation-recovery-bundle.json';$bundle=OpenPinned $path $BundleSha 65536 $true
 Need ($bundle.schema_version-eq1-and$bundle.kind-ceq'allocation-bounded-recovery-bundle'-and$bundle.serialized_bundle_grants_recovery_authority-eq$false-and(Same $bundle.source $c.source)) 'Actual pinned routing-only recovery bundle differs.'
 $values=@{};$pins=@{}
 foreach($spec in @(@{key='request';leaf='request.json';max=131072},@{key='plan';leaf='selected-plan.json';max=16MB},@{key='ticket';leaf='selected-ticket.json';max=65536},@{key='expectation';leaf='expectation.json';max=16MB},@{key='verification';leaf='verification.json';max=1MB},@{key='recovery_payload_manifest';leaf='recovery-payload-manifest.json';max=16MB})){
  $p=Join-Path $Directory $spec.leaf;$b=$bundle.($spec.key);Need ($b.path-ceq$p) 'Exact original artifact routes required.';$values[$spec.key]=OpenPinned $p $b.sha256 $spec.max $true;$pins[$spec.key]=$b.sha256
 }
 $r=$values.request;$t=$values.ticket;$location=Json (Join-Path $Directory 'journal-location.json')
 Need ((Same $r.pair.source $c.source)-and(Same $r.pair.shadow $c.shadow)-and(Same $r.journal $c.journal)-and$r.schema_version-eq3-and$r.verification_policy-ceq'extent_identity_v1'-and$r.selected_capacity_policy-ceq'source_free_actual_bytes_v1'-and$r.max_journal_bytes-eq8GB-and$r.max_literal_backing_bytes-eq256MB-and$r.max_combined_scratch_bytes-eq10GB-and$r.verify_existing_shadow-eq$false) 'Actual original admitted request routes/policy differ.'
 $admitted=AdmittedEnvelope $r.source_resource_profile $values.expectation $Directory
 Need ($t.marker_profile-ceq'redundant_source_free_v1'-and$t.whole_image_verified-eq$false-and$t.selected_bytes-gt0-and$t.range_count-gt0-and$t.journal_length-gt32768-and@($t.immutable_sha256).Count-eq32-and@($t.old_selected_sha256).Count-eq32-and@($t.old_restored_selected_sha256).Count-eq32-and@($t.new_selected_sha256).Count-eq32-and$location.format-ceq'N2RFRE02'-and$location.journal_format_version-eq6-and$location.path-ceq$bundle.journal-and(Same $bundle.marker_storage_identity $location.identity)) 'Actual format6/profile/independently pinned marker-storage identity required.'
 return @{bundle=$bundle;ticket=$t;request=$r;values=$values;pins=$pins;location=$location;bundle_sha256=$BundleSha;admitted_source_observation=$admitted}
}
function Marker($Observation,$Facts){
 Need ($Observation.native_qualified-eq$false-and$Observation.journal_length-eq$Facts.ticket.journal_length-and(Same $Observation.identity $Facts.bundle.marker_storage_identity)-and$Observation.logical_sector_bytes-eq512-and$Observation.physical_sector_bytes-eq4096-and$Observation.cluster_bytes-gt0-and@($Observation.file_storage_info).Count-eq7-and@($Observation.marker_device_offsets).Count-eq8) 'Actual native marker storage observation differs; native qualification remains false.'
 $offsets=@($Observation.marker_device_offsets);Need (@($offsets|Sort-Object -Unique).Count-eq8) 'Eight distinct marker sectors required.'
 foreach($offset in $offsets){Need ([decimal]$offset-ge0-and[decimal]$offset%4096-eq0-and[decimal]$offset+4096-le[decimal]$c.journal.disk.identity.disk_bytes) 'Marker device offsets must be aligned and disk bounded.'}
}
try{
 $configPath=Join-Path '__STAGE__' 'configuration.json';$c=OpenPinned $configPath '__CONFIG_SHA__' 1MB $true
 Need ($c.stage-ceq'__STAGE__'-and$c.operation-ceq'Recover'-and$c.rollback-and-not$c.first_write_fault-and-not$c.deliberate_pause-and$c.expected_exit-eq0-and$c.maximum_placement_bytes-eq16GB-and$c.maximum_placement_submissions-eq32768-and$c.maximum_exception_bytes-eq16MB) 'Pinned recovery-only configuration differs.'
 Need ($null-eq$c.pause_after_marker_copy-and$null-eq$c.pause_marker_slot-and$null-eq$c.pause_signal_path-and$null-eq$c.pause_signal_bytes) 'Power recovery does not create a second pause or an automatic power action.'
 Idle;$before=Routes ($c.operation-ceq'Fresh');Save 'preflight.json' $before
 foreach($tool in $c.tools){$path=Join-Path $c.stage $tool.name;$null=OpenPinned $path $tool.sha256 64MB $false;Need ((Get-Item -LiteralPath $path).Length-eq$tool.bytes) 'Staged executable length differs.'}
 $requestPath=Join-Path $c.stage 'request.json';$request=OpenPinned $requestPath $c.request_sha256 131072 $true;$requestPin=$c.request_sha256
 Need ((Same $request.pair.source $c.source)-and(Same $request.pair.shadow $c.shadow)-and(Same $request.journal $c.journal)-and$request.experiment_id-ceq$c.run_id) 'Fresh derived request bindings differ.'
 $facts=$null
 $checkpoint=OpenPinned (Join-Path $c.stage 'original-power-checkpoint.json') $c.checkpoint_sha256 1MB $true;Need (Same $checkpoint $c.checkpoint) 'Staged original power checkpoint receipt differs.'
 Need ($checkpoint.kind-ceq'native-marker-power-checkpoint-v1'-and$checkpoint.native_exit_observed-eq$false-and$null-eq$checkpoint.native_exit-and$c.power_marker_copy-cin@('AP1','HND1')-and$checkpoint.marker_copy-ceq$c.power_marker_copy-and$checkpoint.marker_slot-eq$c.power_marker_slot-and$c.original_output-ceq(Split-Path -Parent $c.bundle_path)-and$c.original_stage-ceq(Split-Path -Parent $c.original_output)-and(-not$c.rollback-or$c.power_marker_copy-ceq'AP1')) 'Actual power origin and recovery direction differ; no controlled-exit substitute is accepted.'
 $directory=$c.original_output;$origin=$c.original_stage;$facts=Artifacts $directory $c.bundle_sha256
 Need ($facts.pins.ticket-ceq$checkpoint.ticket_sha256-and$checkpoint.ticket_path-ceq(Join-Path $directory 'selected-ticket.json')-and$facts.request.experiment_id-ceq$c.original_run_id-and(Same $checkpoint.source $c.source)-and(Same $checkpoint.shadow $c.shadow)) 'Original power ticket/experiment/routes differ.'
 Need (-not(Test-Path -LiteralPath (Join-Path $origin 'native-terminal.json'))) 'An original native terminal contradicts the actual-power unobserved-exit contract; no terminal is required or fabricated.'
 $originalProcess=OpenPinned (Join-Path $origin 'native-process.json') $checkpoint.process_sha256 1MB $true
 $signal=OpenPinned (Join-Path $directory 'marker-pause.json') $checkpoint.signal_sha256 32768 $true
 Need ((Get-Item -LiteralPath $checkpoint.signal_path).Length-eq32768-and$checkpoint.signal_path-ceq(Join-Path $directory 'marker-pause.json')-and$checkpoint.process_path-ceq(Join-Path $origin 'native-process.json')) 'Actual closed signal must be exactly32KiB at the original independent output route.'
 $a=@($originalProcess.argv);Need ($a.Count-eq19) 'Exact original Fresh pause argv required.';$originalRequestSha=[string]$a[6];Need ($originalRequestSha-cmatch'\A[0-9a-f]{64}\z') 'Original Fresh input request pin required.'
 $originalRequest=OpenPinned (Join-Path $origin 'request.json') $originalRequestSha 131072 $true
 Need ($originalRequest.schema_version-eq3-and$originalRequest.experiment_id-ceq$c.original_run_id-and$originalRequest.verification_policy-ceq'extent_identity_v1'-and$originalRequest.selected_capacity_policy-ceq'source_free_actual_bytes_v1'-and$null-eq$originalRequest.source_resource_profile.experimental_object_envelope_v3-and$originalRequest.verify_existing_shadow-eq$false-and$originalRequest.max_journal_bytes-eq8GB-and$originalRequest.max_literal_backing_bytes-eq256MB-and$originalRequest.max_combined_scratch_bytes-eq10GB-and(Same $originalRequest.pair.source $c.source)-and(Same $originalRequest.pair.shadow $c.shadow)-and(Same $originalRequest.journal $c.journal)) 'Actual original input must retain its pinned planningNone intent and routes; saved admittedSome remains independent evidence.'
 $expectedArgv=@('--acknowledge-enrolled-disposable-devices','--acknowledge-unqualified-native-markers','fresh','--request',(Join-Path $origin 'request.json'),'--request-sha256',$originalRequestSha,'--output',$directory,'--maximum-placement-bytes','17179869184','--maximum-placement-submissions','32768','--maximum-exception-bytes','16777216','--pause-after-marker-copy',$c.power_marker_copy,'--pause-signal',$checkpoint.signal_path)
 Need ($originalProcess.pid-eq$checkpoint.native_pid-and$originalProcess.creation_ms-eq$checkpoint.native_creation_ms-and$originalProcess.binary-ceq(Join-Path $origin 'lab-selected-marker-native.exe')-and$originalProcess.binary_sha256-ceq$checkpoint.producer_sha256-and$originalProcess.process_handle_retained_before_wait-eq$true-and$originalProcess.deliberate_pause-eq$true-and$null-eq$originalProcess.expected_exit-and$originalProcess.native_exit_expected-eq$false-and$originalProcess.pause_after_marker_copy-ceq$c.power_marker_copy-and$originalProcess.pause_marker_slot-eq$c.power_marker_slot-and$originalProcess.pause_signal_path-ceq$checkpoint.signal_path-and$originalProcess.pause_signal_bytes-eq32768-and(Same $a $expectedArgv)) 'Actual original retained process identity/argv/pause route differs; no original terminal/exit is assumed.'
 $null=OpenPinned $originalProcess.binary $checkpoint.producer_sha256 64MB $false
 Need ($signal.schema_version-eq1-and$signal.kind-ceq'lab-selected-marker-copy-pause'-and$signal.lab_only-eq$true-and$signal.native_marker_qualified-eq$false-and$signal.computer_name-ceq'N2R-WIN11'-and$signal.pid-eq$checkpoint.native_pid-and$signal.process_creation_unix_ms-eq$checkpoint.native_creation_ms-and[decimal]::Floor(([decimal]$signal.process_creation_filetime_100ns-116444736000000000)/10000)-eq[decimal]$checkpoint.native_creation_ms-and(Same $signal.argv (@($originalProcess.binary)+$expectedArgv))-and$signal.journal_format_version-eq6-and$signal.journal_format-ceq'N2RFRE02'-and$signal.journal_profile-ceq'CapacityPinnedV3'-and$signal.maximum_journal_bytes-eq8GB-and$signal.marker_profile-ceq'RedundantSourceFreeV1'-and$signal.marker_copy-ceq$c.power_marker_copy-and$signal.marker_slot-eq$c.power_marker_slot-and$signal.marker_file_offset-eq($c.power_marker_slot*4096)-and$signal.marker_bytes-eq4096-and$signal.signal_path-ceq$checkpoint.signal_path-and$signal.signal_bytes-eq32768-and$signal.durable_stage-ceq'actual-slot-written-flushed-uncached-readback-and-storage-revalidated'-and$signal.marker_sha256-cmatch'\A[0-9a-f]{64}\z'-and$signal.marker_sha256-cne('0'*64)-and$signal.signal_synced_before_readable-eq$true-and$signal.journal_owner_retained-eq$true-and$signal.automatic_continue-eq$false-and$signal.timeout-eq$false-and$signal.requires_external_hard_poweroff-eq$true) 'Actual closed synchronized marker signal/process/storage proof differs.'
 Marker $signal.storage $facts
 Need ($signal.marker_device_offset-eq@($signal.storage.marker_device_offsets)[$c.power_marker_slot]) 'Actual selected signal device offset differs.'
 Need (-not(Test-Path -LiteralPath (Join-Path $directory 'handoff.json'))-and-not(Test-Path -LiteralPath (Join-Path $directory 'result.json'))-and($c.power_marker_copy-cne'AP1'-or-not(Test-Path -LiteralPath (Join-Path $directory 'apply.json')))) 'Actual paused original branch cannot already contain completion artifacts; closed native journal lifecycle still governs recovery.'
 Save 'original-ap1-power-origin-observation.json' @{schema_version=1;kind='native-marker-actual-power-origin-observation';marker_copy=$c.power_marker_copy;marker_slot=$c.power_marker_slot;original_native_pid=$checkpoint.native_pid;original_native_creation_ms=$checkpoint.native_creation_ms;original_native_exit_observed=$false;original_native_exit=$null;actual_closed_signal_bytes=32768;signal_sha256=$checkpoint.signal_sha256;process_sha256=$checkpoint.process_sha256;ticket_sha256=$checkpoint.ticket_sha256;bundle_sha256=$c.bundle_sha256;checkpoint_sha256=$c.checkpoint_sha256;producer_sha256=$checkpoint.producer_sha256;recovery_source_commit=$c.source_commit;expected_native_action=$c.expected_native_action;expected_original_lifecycle=$c.expected_original_lifecycle;raw_journal_opened=$false;saved_json_grants_authority=$false;utc=[DateTime]::UtcNow.ToString('o')}
 $nested=OpenPinned (Join-Path $c.stage 'rollback-power-checkpoint.json') $c.rollback_power_checkpoint_sha256 1MB $true
 Need ((Same $nested $c.rollback_power_checkpoint)-and$nested.kind-ceq'native-marker-rollback-power-checkpoint-v1'-and$nested.original_ap1_checkpoint_receipt_sha256-ceq$c.checkpoint_sha256-and$nested.native_exit_observed-eq$false-and$null-eq$nested.native_exit-and$c.rollback-and$c.rollback_power_marker_copy-cin@('RB1','ABT1')-and$nested.marker_copy-ceq$c.rollback_power_marker_copy-and$nested.marker_slot-eq$c.rollback_power_marker_slot-and$nested.producer_stage-ceq$c.paused_stage-and$nested.producer_output-ceq$c.paused_output-and$nested.bundle_path-ceq$c.bundle_path-and$nested.bundle_sha256-ceq$c.bundle_sha256-and$nested.ticket_sha256-ceq$facts.pins.ticket) 'Pinned actual nested rollback-power origin differs.'
 $pausedConfig=OpenPinned (Join-Path $c.paused_stage 'configuration.json') $nested.producer_configuration_sha256 1MB $true
 Need ($pausedConfig.schema_version-eq1-and$pausedConfig.operation-ceq'Recover'-and$pausedConfig.rollback-eq$true-and$pausedConfig.first_write_fault-eq$false-and$pausedConfig.power_marker_copy-ceq'AP1'-and$pausedConfig.power_marker_slot-eq0-and$pausedConfig.prepared_managed_sha256-ceq$c.prepared_managed_sha256-and$pausedConfig.stage-ceq$c.paused_stage-and$pausedConfig.output-ceq$c.paused_output-and$pausedConfig.run_id-ceq$c.paused_run_id-and$pausedConfig.task-ceq$nested.task_name-and$pausedConfig.mode-ceq('power-rollback-pause-'+$c.rollback_power_marker_copy.ToLowerInvariant())-and$pausedConfig.deliberate_pause-eq$true-and$null-eq$pausedConfig.expected_exit-and$pausedConfig.pause_after_marker_copy-ceq$c.rollback_power_marker_copy-and$pausedConfig.pause_marker_slot-eq$c.rollback_power_marker_slot-and$pausedConfig.pause_signal_path-ceq$nested.signal_path-and$pausedConfig.pause_signal_bytes-eq32768-and$pausedConfig.bundle_path-ceq$c.bundle_path-and$pausedConfig.bundle_sha256-ceq$c.bundle_sha256-and$pausedConfig.checkpoint_sha256-ceq$c.checkpoint_sha256-and(Same $pausedConfig.checkpoint $checkpoint)-and(Same $pausedConfig.source $c.source)-and(Same $pausedConfig.shadow $c.shadow)-and(Same $pausedConfig.journal $c.journal)-and$pausedConfig.expected_native_action-ceq'rollback'-and$pausedConfig.expected_original_lifecycle-ceq'apply_intent') 'Actual paused producer must be a new RecoverRollback from the original AP1 receipt and bundle; its routing JSON supplies no fresh certificate.'
 $pausedProcess=OpenPinned (Join-Path $c.paused_stage 'native-process.json') $nested.process_sha256 1MB $true
 Need (-not(Test-Path -LiteralPath (Join-Path $c.paused_stage 'native-terminal.json'))) 'A paused producer terminal contradicts the nested actual-power unobserved-exit contract.'
 $pausedBinary=Join-Path $c.paused_stage 'lab-selected-marker-native.exe'
 $pausedArgv=@('--acknowledge-enrolled-disposable-devices','--acknowledge-unqualified-native-markers','recover','--bundle',$c.bundle_path,'--bundle-sha256',$c.bundle_sha256,'--output',$c.paused_output,'--rollback','--pause-after-marker-copy',$c.rollback_power_marker_copy,'--pause-signal',$nested.signal_path)
 Need (@($pausedProcess.argv).Count-eq14-and(Same $pausedProcess.argv $pausedArgv)-and$pausedProcess.pid-eq$nested.native_pid-and$pausedProcess.creation_ms-eq$nested.native_creation_ms-and$pausedProcess.binary-ceq$pausedBinary-and$pausedProcess.binary_sha256-ceq$nested.producer_sha256-and$pausedProcess.process_handle_retained_before_wait-eq$true-and$pausedProcess.deliberate_pause-eq$true-and$null-eq$pausedProcess.expected_exit-and$pausedProcess.native_exit_expected-eq$false-and$pausedProcess.pause_after_marker_copy-ceq$c.rollback_power_marker_copy-and$pausedProcess.pause_marker_slot-eq$c.rollback_power_marker_slot-and$pausedProcess.pause_signal_path-ceq$nested.signal_path-and$pausedProcess.pause_signal_bytes-eq32768) 'Actual nested producer PID/birth/binary/14-argument RecoverRollback pause differs; it is not a fresh producer.'
 $pausedTool=@($pausedConfig.tools|Where-Object name -CEQ 'lab-selected-marker-native.exe');Need ($pausedTool.Count-eq1-and$pausedTool[0].sha256-ceq$nested.producer_sha256) 'Actual paused configuration producer pin differs.'
 $null=OpenPinned $pausedBinary $nested.producer_sha256 64MB $false
 $pausedSignal=OpenPinned (Join-Path $c.paused_output 'marker-pause.json') $nested.signal_sha256 32768 $true
 Need ((Get-Item -LiteralPath $nested.signal_path).Length-eq32768-and$nested.signal_path-ceq(Join-Path $c.paused_output 'marker-pause.json')-and$pausedSignal.schema_version-eq1-and$pausedSignal.kind-ceq'lab-selected-marker-copy-pause'-and$pausedSignal.lab_only-eq$true-and$pausedSignal.native_marker_qualified-eq$false-and$pausedSignal.computer_name-ceq'N2R-WIN11'-and$pausedSignal.pid-eq$nested.native_pid-and$pausedSignal.process_creation_unix_ms-eq$nested.native_creation_ms-and[decimal]::Floor(([decimal]$pausedSignal.process_creation_filetime_100ns-116444736000000000)/10000)-eq[decimal]$nested.native_creation_ms-and(Same $pausedSignal.argv (@($pausedBinary)+$pausedArgv))-and$pausedSignal.journal_format_version-eq6-and$pausedSignal.journal_format-ceq'N2RFRE02'-and$pausedSignal.journal_profile-ceq'CapacityPinnedV3'-and$pausedSignal.maximum_journal_bytes-eq8GB-and$pausedSignal.marker_profile-ceq'RedundantSourceFreeV1'-and$pausedSignal.marker_copy-ceq$c.rollback_power_marker_copy-and$pausedSignal.marker_slot-eq$c.rollback_power_marker_slot-and$pausedSignal.marker_file_offset-eq($c.rollback_power_marker_slot*4096)-and$pausedSignal.marker_bytes-eq4096-and$pausedSignal.signal_path-ceq$nested.signal_path-and$pausedSignal.signal_bytes-eq32768-and$pausedSignal.durable_stage-ceq'actual-slot-written-flushed-uncached-readback-and-storage-revalidated'-and$pausedSignal.marker_sha256-cmatch'\A[0-9a-f]{64}\z'-and$pausedSignal.marker_sha256-cne('0'*64)-and$pausedSignal.signal_synced_before_readable-eq$true-and$pausedSignal.journal_owner_retained-eq$true-and$pausedSignal.automatic_continue-eq$false-and$pausedSignal.timeout-eq$false-and$pausedSignal.requires_external_hard_poweroff-eq$true) 'Actual closed32768-byte nested rollback signal/storage/process proof differs.'
 Marker $pausedSignal.storage $facts
 Need ($pausedSignal.marker_device_offset-eq@($pausedSignal.storage.marker_device_offsets)[$c.rollback_power_marker_slot]) 'Actual nested selected marker device offset differs.'
 Need (-not(Test-Path -LiteralPath (Join-Path $c.paused_output 'rollback.json'))-and-not(Test-Path -LiteralPath (Join-Path $c.paused_output 'verified-rollback.json'))-and-not(Test-Path -LiteralPath (Join-Path $c.paused_output 'result.json'))-and-not(Test-Path -LiteralPath (Join-Path $c.paused_output 'completion.json'))) 'Actual paused rollback producer cannot already contain a completed rollback result.'
 Need (($c.rollback_power_marker_copy-ceq'RB1'-and$c.expected_native_action-ceq'rollback'-and$c.expected_original_lifecycle-ceq'rollback_intent')-or($c.rollback_power_marker_copy-ceq'ABT1'-and$c.expected_native_action-ceq'verify_aborted'-and$c.expected_original_lifecycle-ceq'aborted')) 'RB1 may only continue rollback; ABT1 may only verify the closed rollback and repair its terminal peer.'
 Save 'nested-rollback-power-origin-observation.json' @{schema_version=1;kind='actual-nested-rollback-power-origin';marker_copy=$c.rollback_power_marker_copy;marker_slot=$c.rollback_power_marker_slot;producer_stage=$c.paused_stage;producer_output=$c.paused_output;native_pid=$nested.native_pid;native_creation_ms=$nested.native_creation_ms;native_exit_observed=$false;native_exit=$null;process_sha256=$nested.process_sha256;signal_sha256=$nested.signal_sha256;producer_configuration_sha256=$nested.producer_configuration_sha256;nested_power_checkpoint_receipt_sha256=$c.rollback_power_checkpoint_sha256;original_ap1_checkpoint_receipt_sha256=$c.checkpoint_sha256;original_bundle_path=$c.bundle_path;original_bundle_sha256=$c.bundle_sha256;original_ticket_sha256=$facts.pins.ticket;expected_native_action=$c.expected_native_action;expected_original_lifecycle=$c.expected_original_lifecycle;fresh_source_authority_granted=$false;raw_journal_opened=$false;utc=[DateTime]::UtcNow.ToString('o')}
 Save 'wrapper-worker.json' @{pid=$PID;creation_ms=([DateTimeOffset](Get-Process -Id $PID).StartTime).ToUnixTimeMilliseconds();run_id=$c.run_id;utc=[DateTime]::UtcNow.ToString('o')}
 Idle;$null=Routes ($c.operation-ceq'Fresh');Need (-not(Test-Path -LiteralPath $c.output)) 'Native output must be a fresh directory.'
 $argv=@('--acknowledge-enrolled-disposable-devices','--acknowledge-unqualified-native-markers')
 $argv+=@('recover','--bundle',$c.bundle_path,'--bundle-sha256',$c.bundle_sha256,'--output',$c.output);if($c.rollback){$argv+='--rollback'}
 $arguments=($argv|ForEach-Object {Need ($_-cnotmatch'["\r\n\x00]') 'Unsafe native argument.';$tail=$_.Length-$_.TrimEnd('\').Length;'"'+$_+('\'*$tail)+'"'})-join' '
 $binary=Join-Path $c.stage 'lab-selected-marker-native.exe';$producer=@($c.tools|Where-Object name -CEQ 'lab-selected-marker-native.exe')[0]
 $stdout=Join-Path $c.stage 'native.stdout.log';$stderr=Join-Path $c.stage 'native.stderr.log'
 Save 'native-dispatch-intent.json' @{binary=$binary;binary_sha256=$producer.sha256;argv=$argv;expected_exit=$c.expected_exit;deliberate_pause=[bool]$c.deliberate_pause;pause_after_marker_copy=$c.pause_after_marker_copy;pause_marker_slot=$c.pause_marker_slot;pause_signal_path=$c.pause_signal_path;pause_signal_bytes=$c.pause_signal_bytes;native_exit_expected=(-not$c.deliberate_pause);pause_automatic_continue=$false;completion_inferred=$false;source_certificate_must_be_live=($c.operation-ceq'Fresh');saved_json_grants_authority=$false;utc=[DateTime]::UtcNow.ToString('o')}
 # Start retains the CreateProcess-owned handle even for a short-lived child.
 $startInfo=[Diagnostics.ProcessStartInfo]::new();$startInfo.UseShellExecute=$false;$startInfo.CreateNoWindow=$true
 $startInfo.FileName=$binary;$startInfo.Arguments=$arguments;$startInfo.WorkingDirectory=$c.stage
 $startInfo.RedirectStandardOutput=$true;$startInfo.RedirectStandardError=$true
 $process=[Diagnostics.Process]::new();$process.StartInfo=$startInfo
 $stdoutStream=[IO.File]::Open($stdout,'CreateNew','Write','Read');$stderrStream=[IO.File]::Open($stderr,'CreateNew','Write','Read')
 $phase='native-process';$clock=[Diagnostics.Stopwatch]::StartNew()
 Need ($process.Start()) 'Native CreateProcess did not return an owned process.'
 $null=$process.Handle;$birth=([DateTimeOffset]$process.StartTime).ToUnixTimeMilliseconds();$nativePid=$process.Id
 $stdoutPipe=$process.StandardOutput.BaseStream;$stderrPipe=$process.StandardError.BaseStream
 # Drain raw bytes concurrently with bounded buffers before waiting for exit.
 $stdoutDrain=$stdoutPipe.CopyToAsync($stdoutStream,65536);$stderrDrain=$stderrPipe.CopyToAsync($stderrStream,65536)
 Save 'native-process.json' @{pid=$nativePid;creation_ms=$birth;parent_pid=$PID;binary=$binary;binary_sha256=$producer.sha256;argv=$argv;expected_exit=$c.expected_exit;deliberate_pause=[bool]$c.deliberate_pause;pause_after_marker_copy=$c.pause_after_marker_copy;pause_marker_slot=$c.pause_marker_slot;pause_signal_path=$c.pause_signal_path;pause_signal_bytes=$c.pause_signal_bytes;native_exit_expected=(-not$c.deliberate_pause);pause_automatic_continue=$false;completion_inferred=$false;process_handle_retained_before_wait=$true;utc=[DateTime]::UtcNow.ToString('o')}
 # A deliberate pause leaves this SYSTEM wrapper and its retained process/log
 # owners running here. No timeout, terminal receipt or power action is inferred.
 $process.WaitForExit();$clock.Stop();$process.Refresh();$nativeExit=$process.ExitCode
 $null=$stdoutDrain.GetAwaiter().GetResult();$null=$stderrDrain.GetAwaiter().GetResult()
 $stdoutStream.Flush($true);$stderrStream.Flush($true)
 $stdoutStream.Dispose();$stdoutStream=$null;$stderrStream.Dispose();$stderrStream=$null
 $peakWorking=$null;$peakPrivate=$null;try{$peakWorking=[long]$process.PeakWorkingSet64}catch{};try{$peakPrivate=[long]$process.PeakPagedMemorySize64}catch{}
 if($null-ne$peakWorking-and$peakWorking-le0){$peakWorking=$null};if($null-ne$peakPrivate-and$peakPrivate-le0){$peakPrivate=$null}
 Save 'native-terminal.json' @{pid=$nativePid;creation_ms=$birth;native_exit=$nativeExit;native_exit_observed=($null-ne$nativeExit);process_handle_retained_through_terminal=$true;wall_seconds=$clock.Elapsed.TotalSeconds;peak_working_set_bytes=$peakWorking;peak_paged_memory_bytes=$peakPrivate;peak_metrics_source='retained-System.Diagnostics.Process; null when unavailable';stdout=(Log $stdout);stderr=(Log $stderr);utc=[DateTime]::UtcNow.ToString('o')}
 Need (-not$c.deliberate_pause) 'A deliberately parked native process actually exited; this is not a completed pause or power interruption. Preserve the actual terminal evidence without retry.'
 $phase='terminal-observation';Idle;Protected
 $after=Inventory;$unrelatedBefore=@($before.all_disk_attributes|Where-Object number -NotIn @(1,6));$unrelatedAfter=@($after|Where-Object number -NotIn @(1,6));Need (Same $unrelatedBefore $unrelatedAfter) 'An unrelated disk identity/provider/attribute changed.'
 Need ($null-ne$nativeExit-and$nativeExit-eq$c.expected_exit) 'Actual process fault/unexpected exit; preserve all material without retry.'
 $shadowTerminal=RecoveryShadow;Save 'recovery-shadow-terminal.json' $shadowTerminal
 $bundlePath=$c.bundle_path;$bundleSha=$c.bundle_sha256;$marker=Json (Join-Path $c.output 'journal-identity.json');Marker $marker $facts
 $proof=@{format=$facts.location.format;journal_format_version=$facts.location.journal_format_version;marker_profile=$facts.ticket.marker_profile;marker_storage=$marker;bundle_path=$bundlePath;bundle_sha256=$bundleSha;ticket_sha256=$facts.pins.ticket;ticket=$facts.ticket;admitted_source_observation=$facts.admitted_source_observation;raw_journal_opened=$false;grants_product_authority=$false}
 Save 'native-marker-ticket-observation.json' $proof
 $result=Json (Join-Path $c.output 'result.json');Need ($result.success-eq$true-and$result.schema_version-eq1-and$result.kind-ceq'allocation-bounded-recovery'-and$result.journal_format-ceq'N2RFRE02'-and$result.journal_format_version-eq6-and$result.marker_profile-ceq'redundant_source_free_v1'-and$result.fresh_apply_authorized-eq$false-and$result.source_admitted-eq$false) 'Actual format6 recovery success and no fresh authority required in addition to exit0.'
 $source=Binding $c.source $false $false;$volume=$source.partition|Get-Volume
 if($c.rollback){
  $closedLeaf=if($c.expected_native_action-ceq'verify_aborted'){'verified-rollback.json'}else{'rollback.json'}
  $closed=Json (Join-Path $c.output $closedLeaf);$completion=Json (Join-Path $c.output 'completion.json') 64MB
  Need ($result.action-ceq$c.expected_native_action-and$result.observed_lifecycle-ceq$c.expected_original_lifecycle-and$result.outcome-ceq'ntfs_restored'-and$result.exclusive_recovery_journal_used-eq$true-and$completion.mounted_filesystem-ceq'NTFS'-and$volume.FileSystem-ceq'NTFS'-and$closed.replay_closed-eq$true-and(Same $closed.selected_sha256 $facts.ticket.old_restored_selected_sha256)) 'Actual original interrupted NTFS restore-required selected digest/ABT proof differs.'
 }else{
  $leaf='completion.json';$extentLeaf='recovery-extent-verification.json'
  $closedLeaf=if($c.expected_native_action-ceq'verify_handoff'){'verified-handoff.json'}else{'handoff.json'}
  $completion=Json (Join-Path $c.output $leaf) 64MB;$extent=Json (Join-Path $c.output $extentLeaf);$closed=Json (Join-Path $c.output $closedLeaf)
  Need ($completion.success-eq$true-and$completion.rollback_closed-eq$true-and$volume.FileSystem-ceq'ReFS'-and$volume.AllocationUnitSize-eq4096-and$closed.replay_closed-eq$true-and(Same $closed.selected_sha256 $facts.ticket.new_selected_sha256)-and$extent.all_complete_maps_identical-eq$true-and$extent.handoff_replay_closed-eq$true-and$extent.stream_and_directory_bindings-gt0) 'Actual product full metadata/namespace/maps/tails and closed HND proof required.'
  Need ($extent.extent_only_partial_tail_bytes-ge0-and$extent.extent_only_partial_streams-ge0) 'Recovery product tail accounting required.'
  $native=$completion.native;$scope=$native.content_observation
  Need ($scope.metadata_and_namespace_verified-eq$true-and$scope.complete_stream_mappings_observed-eq$true-and$scope.data_storage_validity_checked-eq$true) 'Built-in native metadata/namespace/all-map/storage verification must pass.'
  Need ($result.action-ceq$c.expected_native_action-and$result.observed_lifecycle-ceq$c.expected_original_lifecycle-and$result.outcome-ceq'refs_completed'-and$result.exclusive_recovery_journal_used-eq$true) 'Actual power-origin native resume or closed HND verification required; no raw closed replay.'
 }
 Need ($volume.FileSystemLabel-ceq'n2r-stream-source'-and'F:\'-in@($source.partition.AccessPaths)) 'Native completion must preserve the original source label/mount path.'
 Save 'native-completion-observation.json' @{power_origin_marker_copy=$c.rollback_power_marker_copy;power_checkpoint_receipt_sha256=$c.rollback_power_checkpoint_sha256;original_ap1_checkpoint_receipt_sha256=$c.checkpoint_sha256;original_native_exit_observed=$false;result=$result;completion_success=$true;closed_selected_digest_matches_ticket=$true;product_builtin_checks_observed=$true;independent_content_hashes_run=$false;native_marker_qualified=$false;hard_power_qualified=$false;raw_journal_opened=$false;utc=[DateTime]::UtcNow.ToString('o')}
 Save 'wrapper-result.json' @{schema_version=1;kind='native-marker-rollback-power-recovery-observation';power_origin_marker_copy=$c.rollback_power_marker_copy;power_checkpoint_receipt_sha256=$c.rollback_power_checkpoint_sha256;original_ap1_checkpoint_receipt_sha256=$c.checkpoint_sha256;expected_native_action=$c.expected_native_action;original_native_exit_observed=$false;observation_passed=$true;process_fault_observed=$false;native_exit=0;operation=$c.operation;rollback=$c.rollback;native_marker_qualified=$false;hard_power_qualified=$false;raw_journal_opened=$false;automatic_retry_recovery_restore_cleanup=$false;ticket_observation='native-marker-ticket-observation.json';utc=[DateTime]::UtcNow.ToString('o')}
}catch{
 $detail=FailureDetails $_
 if($null-ne(Get-Variable c -ErrorAction SilentlyContinue)) {Save 'wrapper-failed.json' @{observation_passed=$false;phase=$phase;native_exit=$nativeExit;native_exit_observed=($null-ne$nativeExit);process_fault_observed=($null-ne$nativeExit-and$nativeExit-ne0);error=$detail.error;fully_qualified_error_id=$detail.fully_qualified_error_id;invocation_position_message=$detail.invocation_position_message;script_stack_trace=$detail.script_stack_trace;native_marker_qualified=$false;hard_power_qualified=$false;raw_journal_opened=$false;automatic_retry_recovery_restore_cleanup=$false;worker_death_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')}}
 exit 1
}finally{
 foreach($stream in @($stdoutPipe,$stderrPipe,$stdoutStream,$stderrStream)){if($null-ne$stream){try{$stream.Dispose()}catch{}}}
 try{if($null-ne$process){$process.Dispose()}}finally{foreach($stream in $held){$stream.Dispose()}}
}
'@
    $guest = $body.Replace('__STAGE__',$stage).Replace('__CONFIG_SHA__',$configSha)
    $tokens=$null; $errors=$null; $null=[Management.Automation.Language.Parser]::ParseInput($guest,[ref]$tokens,[ref]$errors)
    Need ($errors.Count -eq 0) 'Generated PS5 guest syntax differs.'
    $wrapper=Join-Path $root 'guest-wrapper.ps1';[IO.File]::WriteAllText($wrapper,$guest,[Text.UTF8Encoding]::new($false))
    $wrapperSha=(Get-FileHash -LiteralPath $wrapper -Algorithm SHA256).Hash.ToLowerInvariant();$null=OpenPinned $wrapper $wrapperSha 1MB $false
    # The SYSTEM task executes the exact bytes read through a deny-write/delete
    # handle. The wrapper keeps the staged configuration, tools and request held.
    $bootstrap = '$ErrorActionPreference="Stop";$f=[IO.File]::Open("'+(Join-Path $stage 'wrapper.ps1')+'","Open","Read","Read");try{$h=[Security.Cryptography.SHA256]::Create();try{$sha=([BitConverter]::ToString($h.ComputeHash($f))).Replace("-","").ToLowerInvariant()}finally{$h.Dispose()};if($sha-cne"'+$wrapperSha+'"){throw "Pinned wrapper differs"};$f.Position=0;$r=[IO.StreamReader]::new($f,[Text.UTF8Encoding]::new($false),$true,4096,$true);try{$text=$r.ReadToEnd()}finally{$r.Dispose()};& ([scriptblock]::Create($text))}finally{$f.Dispose()}'
    $actionArguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap))
    # Provider checks use the same SYSTEM token as native execution. This
    # separate task cannot launch native work: it registers the still never-run
    # main task only after every original staged check has passed.
    $preflightTokens=$null;$preflightErrors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($guest,[ref]$preflightTokens,[ref]$preflightErrors)
    $definitions=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst]}|ForEach-Object {$_.Extent.Text})-join[Environment]::NewLine
    $preflightBody=@'
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop';$held=[Collections.Generic.List[IO.FileStream]]::new();$shadowOwner=[pscustomobject]@{stream=$null;snapshot=$null;path=$null;receipt_path=$null;receipt_sha256=$null;checks=0};$phase='staged-system-preflight';$c=$null
__DEFINITIONS__
try{
 $c=OpenPinned (Join-Path '__STAGE__' 'configuration.json') '__CONFIG_SHA__' 1MB $true
 Need ($c.stage-ceq'__STAGE__'-and$c.operation-ceq'Recover'-and$c.preflight_task-ceq'__PREFLIGHT_TASK__'-and$c.task-ceq'__MAIN_TASK__'-and[Security.Principal.WindowsIdentity]::GetCurrent().User.Value-ceq'S-1-5-18') 'Exact pinned recovery SYSTEM preflight required.'
 $null=OpenPinned (Join-Path $c.stage 'wrapper.ps1') '__MAIN_WRAPPER_SHA__' 1MB $false
 Idle;$observation=Routes $false
 foreach($tool in $c.tools){$p=Join-Path $c.stage $tool.name;$null=OpenPinned $p $tool.sha256 64MB $false;Need ((Get-Item -LiteralPath $p).Length-eq$tool.bytes) 'Staged tool length differs.'}
 $r=OpenPinned (Join-Path $c.stage 'request.json') $c.request_sha256 131072 $true;Need ((Same $r.pair.source $c.source)-and(Same $r.pair.shadow $c.shadow)-and(Same $r.journal $c.journal)) 'Staged request routes differ.'
 $null=Artifacts (Split-Path -Parent $c.bundle_path) $c.bundle_sha256;$cp=OpenPinned (Join-Path $c.stage 'original-power-checkpoint.json') $c.checkpoint_sha256 1MB $true;Need (Same $cp $c.checkpoint) 'Original checkpoint pin differs.'
 $rcp=OpenPinned (Join-Path $c.stage 'rollback-power-checkpoint.json') $c.rollback_power_checkpoint_sha256 1MB $true;Need (Same $rcp $c.rollback_power_checkpoint) 'Nested rollback power checkpoint pin differs.'
 Need (@(Get-ScheduledTask|Where-Object TaskName -CEQ $c.task).Count-eq0) 'One fresh never-run main SYSTEM task required.'
 Save 'staged-preflight.json' $observation
 Register-ScheduledTask -TaskName $c.task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument '__MAIN_ACTION_ARGUMENTS__') -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)) -ErrorAction Stop|Out-Null
 Save 'system-preflight-result.json' @{schema_version=1;kind='native-marker-power-recovery-system-preflight';checks_passed=$true;system_sid='S-1-5-18';pid=$PID;creation_ms=([DateTimeOffset](Get-Process -Id $PID).StartTime).ToUnixTimeMilliseconds();preflight_task=$c.preflight_task;main_task=$c.task;configuration_sha256='__CONFIG_SHA__';main_wrapper_sha256='__MAIN_WRAPPER_SHA__';provider_checks_executed=$true;main_task_registered_after_checks=$true;main_task_started=$false;native_process_launched=$false;raw_journal_opened=$false;utc=[DateTime]::UtcNow.ToString('o')}
 exit 0
}catch{
 $detail=FailureDetails $_
 if($null-ne$c){Save 'system-preflight-failed.json' @{checks_passed=$false;phase=$phase;error=$detail.error;fully_qualified_error_id=$detail.fully_qualified_error_id;invocation_position_message=$detail.invocation_position_message;script_stack_trace=$detail.script_stack_trace;native_process_launched=$false;main_task_started=$false;worker_death_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')}}
 exit 1
}finally{foreach($stream in $held){$stream.Dispose()}}
'@
    $preflightGuest=$preflightBody.Replace('__DEFINITIONS__',$definitions).Replace('__STAGE__',$stage).Replace('__CONFIG_SHA__',$configSha).Replace('__PREFLIGHT_TASK__',$preflightTask).Replace('__MAIN_TASK__',$task).Replace('__MAIN_WRAPPER_SHA__',$wrapperSha).Replace('__MAIN_ACTION_ARGUMENTS__',$actionArguments)
    $preflightTokens=$null;$preflightErrors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($preflightGuest,[ref]$preflightTokens,[ref]$preflightErrors)
    Need ($preflightErrors.Count-eq0) 'Generated SYSTEM preflight syntax differs.'
    $preflightWrapper=Join-Path $root 'system-preflight.ps1';[IO.File]::WriteAllText($preflightWrapper,$preflightGuest,[Text.UTF8Encoding]::new($false))
    $preflightWrapperSha=(Get-FileHash -LiteralPath $preflightWrapper -Algorithm SHA256).Hash.ToLowerInvariant();$null=OpenPinned $preflightWrapper $preflightWrapperSha 1MB $false
    $preflightBootstrap=$bootstrap.Replace((Join-Path $stage 'wrapper.ps1'),(Join-Path $stage 'system-preflight.ps1')).Replace($wrapperSha,$preflightWrapperSha)
    $preflightActionArguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($preflightBootstrap))
    $session=New-PSSession -VMId $vmId -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml'))
    Invoke-Command -Session $session -ArgumentList $stage,$task -ScriptBlock {param($Stage,$Task)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        if($env:COMPUTERNAME-cne'N2R-WIN11'-or(Test-Path -LiteralPath $Stage)-or@(Get-ScheduledTask|Where-Object {$_.TaskName-ceq$Task-or($_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled'))}).Count-or@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'-or($_.Name-match'\A(?:powershell|pwsh)\.exe\z'-and$_.CommandLine-like'*C:\ntfs2refs\*')}).Count){throw 'Fresh exact stage and terminal N2R tasks/no workers required.'}
        $cursor=Get-Item -LiteralPath 'C:\ntfs2refs' -Force;while($null-ne$cursor){if($cursor.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse stage ancestry refused.'};$cursor=$cursor.Parent};$null=New-Item -ItemType Directory -Path $Stage
    }
    foreach($tool in $tools){Copy-Item -LiteralPath $tool.path -ToSession $session -Destination (Join-Path $stage $tool.name)}
    foreach($file in @('request.json','configuration.json')){Copy-Item -LiteralPath (Join-Path $root $file) -ToSession $session -Destination (Join-Path $stage $file)}
    Copy-Item -LiteralPath $PreparedManagedReceiptPath -ToSession $session -Destination (Join-Path $stage 'prepared-managed-result.json')
    if($Operation -ceq 'Recover'){Copy-Item -LiteralPath $OriginalAp1PowerCheckpointReceiptPath -ToSession $session -Destination (Join-Path $stage 'original-power-checkpoint.json')}
    Copy-Item -LiteralPath $PowerCheckpointReceiptPath -ToSession $session -Destination (Join-Path $stage 'rollback-power-checkpoint.json')
    Copy-Item -LiteralPath $wrapper -ToSession $session -Destination (Join-Path $stage 'wrapper.ps1')
    Copy-Item -LiteralPath $preflightWrapper -ToSession $session -Destination (Join-Path $stage 'system-preflight.ps1')
    HostGuard
    Save 'dispatch.json' @{schema_version=1;kind='unqualified-native-marker-rollback-power-recovery-dispatch';run_id=$run;operation=$Operation;mode=$mode;power_marker_copy=$rollbackPowerCopy;power_marker_slot=$rollbackPowerSlot;paused_producer_stage=$pausedStage;paused_producer_output=$pausedOutput;original_ap1_checkpoint_receipt_sha256=$OriginalAp1PowerCheckpointReceiptSha256;power_checkpoint_receipt_sha256=$PowerCheckpointReceiptSha256;original_bundle_path=$OriginalGuestBundlePath;original_bundle_sha256=$OriginalGuestBundleSha256;expected_native_action=$config.expected_native_action;expected_original_lifecycle=$config.expected_original_lifecycle;source_commit=$SourceCommit;manifest_sha256=$ToolsetManifestSha256;parent_id=$ExpectedParent;checkpoint_ids=$ids;task_name=$task;system_preflight_task_name=$preflightTask;system_preflight_wrapper_sha256=$preflightWrapperSha;guest_stage=$stage;output=$config.output;wrapper_sha256=$wrapperSha;configuration_sha256=$configSha;expected_exit=$config.expected_exit;deliberate_pause=$deliberatePause;pause_after_marker_copy=$config.pause_after_marker_copy;pause_marker_slot=$config.pause_marker_slot;pause_signal_path=$config.pause_signal_path;pause_signal_bytes=$config.pause_signal_bytes;native_exit_expected=(-not$deliberatePause);guest_wrapper_waits_indefinitely_for_native_exit=$deliberatePause;pause_automatic_continue=$false;completion_inferred=$false;native_marker_qualified=$false;hard_power_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')}
    Invoke-Command -Session $session -ArgumentList $stage,$task,$preflightTask,$preflightActionArguments -ScriptBlock {param($Stage,$Task,$PreflightTask,$PreflightActionArguments)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        if(@(Get-ScheduledTask|Where-Object {$_.TaskName-in@($Task,$PreflightTask)-or($_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled'))}).Count){throw 'Only fresh preflight/main task names and terminal other N2R tasks are allowed.'}
        Register-ScheduledTask -TaskName $PreflightTask -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $PreflightActionArguments) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)) -ErrorAction Stop|Out-Null
        $t=Get-ScheduledTask -TaskName $PreflightTask;$i=$t|Get-ScheduledTaskInfo
        if($t.State.ToString()-cne'Ready'-or$i.LastRunTime.Year-ge2000-or@($t.Actions).Count-ne1-or$t.Actions[0].Execute-cne"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"-or$t.Actions[0].Arguments-cne$PreflightActionArguments-or$t.Principal.UserId-notin@('SYSTEM','S-1-5-18')-or$t.Principal.RunLevel.ToString()-cne'Highest'){throw 'Exact untouched never-run SYSTEM preflight task required.'}
        Start-ScheduledTask -TaskName $PreflightTask -ErrorAction Stop
    }
    Save 'system-preflight-start.json' @{start_issued_once=$true;task_name=$preflightTask;native_process_launched=$false;main_task_started=$false;completion_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')}
    # No timeout infers worker death or starts native work. Remoting/observation
    # failure leaves every task/material for root to inspect, without retry.
    do{
        $preflightObservation=Invoke-Command -Session $session -ArgumentList $stage,$task,$preflightTask,$configSha,$wrapperSha,$preflightActionArguments,$definitions -ScriptBlock {param($Stage,$Task,$PreflightTask,$ConfigSha,$WrapperSha,$PreflightActionArguments,$Definitions)
            Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$held=[Collections.Generic.List[IO.FileStream]]::new()
            try{
                . ([scriptblock]::Create($Definitions));$t=Get-ScheduledTask -TaskName $PreflightTask;$i=$t|Get-ScheduledTaskInfo
                Need (@($t.Actions).Count-eq1-and$t.Actions[0].Execute-ceq"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"-and$t.Actions[0].Arguments-ceq$PreflightActionArguments-and$t.Principal.UserId-in@('SYSTEM','S-1-5-18')-and$t.Principal.RunLevel.ToString()-ceq'Highest') 'SYSTEM preflight task definition changed.'
                if($t.State.ToString()-ceq'Ready'-and$i.LastRunTime.Year-ge2000){
                    $c=OpenPinned (Join-Path $Stage 'configuration.json') $ConfigSha 1MB $true
                    Save 'system-preflight-task-terminal.json' @{task_name=$PreflightTask;actual_task_state=$t.State.ToString();actual_task_last_result=$i.LastTaskResult;native_process_launched=$false;main_task_started=$false;worker_death_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')}
                    if($i.LastTaskResult-ne0){return @{finished=$true;preflight_passed=$false;task_name=$PreflightTask;actual_task_state=$t.State.ToString();actual_task_last_result=$i.LastTaskResult;worker_death_inferred=$false;native_process_launched=$false;main_task_started=$false}}
                    $p=Join-Path $Stage 'system-preflight-result.json';$pin=Pin $p;$r=OpenPinned $p $pin 1MB $true
                    Need ($r.schema_version-eq1-and$r.kind-ceq'native-marker-power-recovery-system-preflight'-and$r.checks_passed-eq$true-and$r.system_sid-ceq'S-1-5-18'-and$r.pid-gt0-and$r.creation_ms-gt0-and$r.preflight_task-ceq$PreflightTask-and$r.main_task-ceq$Task-and$r.configuration_sha256-ceq$ConfigSha-and$r.main_wrapper_sha256-ceq$WrapperSha-and$r.provider_checks_executed-eq$true-and$r.main_task_registered_after_checks-eq$true-and$r.main_task_started-eq$false-and$r.native_process_launched-eq$false-and$r.raw_journal_opened-eq$false) 'Actual closed SYSTEM preflight receipt differs.'
                    $sameWorker=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+$r.pid) -ErrorAction Stop|Where-Object {([DateTimeOffset]$_.CreationDate).ToUnixTimeMilliseconds()-eq$r.creation_ms})
                    Need ($sameWorker.Count-eq0) 'Actual preflight worker is not terminal despite the task result; native work remains unstarted.'
                    return @{finished=$true;preflight_passed=$true;task_name=$PreflightTask;actual_task_state=$t.State.ToString();actual_task_last_result=$i.LastTaskResult;worker_pid=$r.pid;worker_creation_ms=$r.creation_ms;matching_worker_absent=$true;result_sha256=$pin;result=$r;native_process_launched=$false;main_task_started=$false}
                }
                Need ($t.State.ToString()-in@('Ready','Running','Queued')) 'Unexpected preflight state; no native work may start.'
                return @{finished=$false;task_name=$PreflightTask;task_state=$t.State.ToString();completion_inferred=$false}
            }finally{foreach($stream in $held){$stream.Dispose()}}
        }
        if(-not$preflightObservation.finished){Start-Sleep -Seconds 1}
    }while(-not$preflightObservation.finished)
    Save 'system-preflight-terminal.json' $preflightObservation
    Need ($preflightObservation.preflight_passed-eq$true) 'Actual SYSTEM preflight exited unsuccessfully; its terminal result is preserved and native work is not started.'
    HostGuard
    Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration $configuration) -AdditionalBytes $ForecastAdditionalBytes
    Invoke-Command -Session $session -ArgumentList $stage,$task,$preflightTask,$wrapperSha,$configSha,$actionArguments,$preflightObservation.result_sha256,$definitions -ScriptBlock {param($Stage,$Task,$PreflightTask,$WrapperSha,$ConfigSha,$ActionArguments,$PreflightResultSha,$Definitions)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$held=[Collections.Generic.List[IO.FileStream]]::new();$phase='pre-main-start'
        try{
            . ([scriptblock]::Create($Definitions));$c=OpenPinned (Join-Path $Stage 'configuration.json') $ConfigSha 1MB $true;$null=OpenPinned (Join-Path $Stage 'wrapper.ps1') $WrapperSha 1MB $false
            $pf=Get-ScheduledTask -TaskName $PreflightTask;$pi=$pf|Get-ScheduledTaskInfo;$r=OpenPinned (Join-Path $Stage 'system-preflight-result.json') $PreflightResultSha 1MB $true
            Need ($pf.State.ToString()-ceq'Ready'-and$pi.LastRunTime.Year-ge2000-and$pi.LastTaskResult-eq0-and$r.checks_passed-eq$true-and$r.preflight_task-ceq$PreflightTask-and$r.main_task-ceq$Task-and$r.configuration_sha256-ceq$ConfigSha-and$r.main_wrapper_sha256-ceq$WrapperSha-and$r.native_process_launched-eq$false-and$r.main_task_started-eq$false) 'Actual passed SYSTEM preflight must remain terminal before the main task starts.'
            $sameWorker=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+$r.pid) -ErrorAction Stop|Where-Object {([DateTimeOffset]$_.CreationDate).ToUnixTimeMilliseconds()-eq$r.creation_ms});Need ($sameWorker.Count-eq0) 'Actual SYSTEM preflight worker is still live; no native launch.'
            Idle
            $t=Get-ScheduledTask -TaskName $Task;$i=$t|Get-ScheduledTaskInfo
            Need ($t.State.ToString()-ceq'Ready'-and$i.LastRunTime.Year-lt2000-and@($t.Actions).Count-eq1-and$t.Actions[0].Execute-ceq"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"-and$t.Actions[0].Arguments-ceq$ActionArguments-and$t.Principal.UserId-in@('SYSTEM','S-1-5-18')-and$t.Principal.RunLevel.ToString()-ceq'Highest') 'Only the untouched pinned never-run main SYSTEM task may start once.'
            Start-ScheduledTask -TaskName $Task -ErrorAction Stop
        }finally{foreach($stream in $held){$stream.Dispose()}}
    }
    Save 'start.json' @{start_issued_once=$true;task_name=$task;guest_stage=$stage;expected_exit=$config.expected_exit;deliberate_pause=$deliberatePause;pause_after_marker_copy=$config.pause_after_marker_copy;pause_marker_slot=$config.pause_marker_slot;pause_signal_path=$config.pause_signal_path;pause_signal_bytes=$config.pause_signal_bytes;native_exit_expected=(-not$deliberatePause);guest_wrapper_waits_indefinitely_for_native_exit=$deliberatePause;pause_automatic_continue=$false;completion_inferred=$false;automatic_retry_restore_cleanup=$false;utc=[DateTime]::UtcNow.ToString('o')}
    Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw
}catch{
    if($created-and-not(Test-Path -LiteralPath (Join-Path $root 'dispatch-failed.json'))){Save 'dispatch-failed.json' @{observation_passed=$false;error=$_.Exception.ToString();automatic_retry_restore_cleanup=$false;worker_death_inferred=$false;native_marker_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')}}
    throw
}finally{
    if($null-ne$session){Remove-PSSession $session -ErrorAction SilentlyContinue}
    foreach($stream in $held){$stream.Dispose()}
}
