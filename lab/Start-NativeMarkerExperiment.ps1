# Explicit, unqualified format-six owning-guest experiment. Root alone restores,
# boots, stops and checkpoints the VM. This dispatcher never changes disk
# attributes, formats/attaches a disk, retries native work or replays a closed J.
# Recovery requires an actual root-authored checkpoint receipt, schema1/kind
# native-marker-first-write-checkpoint-v1. Its fields are checked below; obtain
# process/terminal/fault pins from the original native-marker-fault-observation.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Fresh','Recover')][string]$Operation,
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
    [switch]$FirstWriteFault,
    [string]$RecoveryBundlePath,
    [ValidatePattern('\A[0-9a-f]{64}\z')][string]$RecoveryBundleSha256,
    [string]$InterruptedCheckpointReceiptPath,
    [ValidatePattern('\A[0-9a-f]{64}\z')][string]$InterruptedCheckpointReceiptSha256,
    [switch]$Rollback
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspace = 'D:\code\ntfs2refs'
$base = Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$vmId = [guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$preparedId = [guid]'cb802669-903c-48cc-99e5-57976b149e7d'
$protectedMain = 'c6bc5c52c8458ee70bd2567a9d8350105aeaa6245448df22675780403e04348b'
$managedSha = '184aad57e2c8c8616adb4ad57ed82e40aba31949c530015ebcc5f7b681bcf876'
$managedPath = 'C:\ntfs2refs\ntfs-owned-preparation-6ec16ed4b4774c13a76b1e282103c66e\managed-shadow\shadow.vhdx'
$run = [guid]::NewGuid().ToString('N')
$mode = if ($Operation -ceq 'Fresh') { if ($FirstWriteFault) { 'fresh-fault' } else { 'fresh' } } else { if ($Rollback) { 'rollback' } else { 'resume' } }
$root = Join-Path $base ('native-marker-' + $mode + '-' + $run)
$stage = 'C:\ntfs2refs\native-marker-' + $mode + '-' + $run
$task = 'N2R-NativeMarker-' + $run
$ids = @($ExpectedCheckpointIds | ForEach-Object { $_.ToString('D') })
$held = [Collections.Generic.List[IO.FileStream]]::new()
$session = $null; $created = $false; $checkpoint = $null
function Need([bool]$Ok, [string]$Message) { if (-not $Ok) { throw $Message } }
function ParseJson([string]$Text) {
    $options = @{}
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { $options.DateKind = 'String' }
    return ($Text | ConvertFrom-Json @options)
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
        Need ($original.Count -eq 1 -and $original[0].ParentSnapshotId -eq $preparedId) 'Recovery must start at the original fault child of preparedcb802669.'
    }
}
try {
    Need ($AcknowledgeEnrolledDisposableDevices -and $AcknowledgeUnqualifiedNativeMarkers) 'Both explicit enrolled-device and unqualified-marker acknowledgments required.'
    Need ($ids.Count -gt 0 -and $ids.Count -le 50 -and @($ids | Sort-Object -Unique).Count -eq $ids.Count -and
        $preparedId.ToString('D') -in $ids -and $ExpectedParent.ToString('D') -in $ids -and [guid]::Empty.ToString('D') -notin $ids) 'Exact nonempty checkpoint set required.'
    Need (($Operation -ceq 'Fresh' -and $ExpectedParent -eq $preparedId -and -not $Rollback -and
        -not $RecoveryBundlePath -and -not $RecoveryBundleSha256 -and -not $InterruptedCheckpointReceiptPath -and -not $InterruptedCheckpointReceiptSha256) -or
        ($Operation -ceq 'Recover' -and $ExpectedParent -ne $preparedId -and -not $FirstWriteFault -and
        $RecoveryBundlePath -and $RecoveryBundleSha256 -and $InterruptedCheckpointReceiptPath -and $InterruptedCheckpointReceiptSha256)) 'Fresh/recovery inputs must be explicit and mutually exclusive.'
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
    if ($Operation -ceq 'Recover') {
        Need ($InterruptedCheckpointReceiptPath.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase) -and
            $RecoveryBundlePath -cmatch '\AC:\\ntfs2refs\\native-marker-fresh-fault-[0-9a-f]{32}\\conversion\\allocation-recovery-bundle[.]json\z') 'Original native-marker fault paths required.'
        $checkpoint = (OpenPinned $InterruptedCheckpointReceiptPath $InterruptedCheckpointReceiptSha256 1MB $true).value
        $producer = @($tools | Where-Object name -CEQ 'lab-selected-marker-native.exe')[0]
        Need ($checkpoint.schema_version -eq 1 -and $checkpoint.kind -ceq 'native-marker-first-write-checkpoint-v1' -and
            [guid]$checkpoint.vm_id -eq $vmId -and [guid]$checkpoint.checkpoint_id -eq $ExpectedParent -and
            [guid]$checkpoint.checkpoint_parent_id -eq $preparedId -and $checkpoint.state -ceq 'Off' -and
            $checkpoint.memory_assigned_bytes -eq 0 -and $checkpoint.source_commit -ceq $SourceCommit -and
            $checkpoint.producer_sha256 -ceq $producer.sha256 -and $checkpoint.native_pid -gt 0 -and $checkpoint.native_creation_ms -gt 0 -and
            $checkpoint.native_exit -eq 86 -and $checkpoint.first_write_flushed -eq $true -and $checkpoint.no_handoff -eq $true -and
            $checkpoint.all_tasks_and_workers_terminal_before_stop -eq $true -and $checkpoint.bundle_path -ceq $RecoveryBundlePath -and
            $checkpoint.bundle_sha256 -ceq $RecoveryBundleSha256 -and $checkpoint.prepared_managed_receipt_sha256 -ceq $managedSha) 'Actual original fault checkpoint receipt differs; saved JSON supplies no replay authority.'
        foreach ($pin in @($checkpoint.process_sha256,$checkpoint.terminal_sha256,$checkpoint.fault_observation_sha256)) { Need ($pin -cmatch '\A[0-9a-f]{64}\z') 'Original fault observation pins required.' }
    }
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
    $config = [ordered]@{schema_version=1; run_id=$run; operation=$Operation; mode=$mode; task=$task; stage=$stage
        output=(Join-Path $stage $(if ($Operation -ceq 'Fresh') { 'conversion' } else { 'recovery' }))
        tools=$tools; source_commit=$SourceCommit; manifest_sha256=$ToolsetManifestSha256
        request_sha256=$requestSha; routing_seed_sha256=$SourceRequestSha256; source=$seed.pair.source; shadow=$seed.pair.shadow; journal=$seed.journal
        prepared_managed_sha256=$managedSha; managed_path=$managedPath; first_write_fault=[bool]$FirstWriteFault; rollback=[bool]$Rollback
        expected_exit=$(if ($FirstWriteFault) { 86 } else { 0 }); bundle_path=$RecoveryBundlePath; bundle_sha256=$RecoveryBundleSha256
        checkpoint=$checkpoint; checkpoint_sha256=$InterruptedCheckpointReceiptSha256
        maximum_placement_bytes=16GB; maximum_placement_submissions=32768; maximum_exception_bytes=16MB}
    Save 'configuration.json' $config
    $configSha = (Get-FileHash -LiteralPath (Join-Path $root 'configuration.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    $null = OpenPinned (Join-Path $root 'configuration.json') $configSha 1MB $false
    $body = @'
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$held=[Collections.Generic.List[IO.FileStream]]::new();$process=$null;$nativeExit=$null;$requestPin=$null;$phase='staged-preflight'
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
function Idle{
 $tasks=@(Get-ScheduledTask -ErrorAction Stop);$workers=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'-or($_.ProcessId-ne$PID-and$_.Name-match'\A(?:powershell|pwsh)\.exe\z'-and$_.CommandLine-like'*C:\ntfs2refs\*')})
 Need (@($tasks|Where-Object {$_.TaskName-like'N2R-*'-and$_.TaskName-cne$c.task-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-eq0-and$workers.Count-eq0) 'Every other N2R task must be terminal and every native/visible wrapper worker absent.'
}
function Binding($B,[bool]$Offline,[bool]$ReadOnly){
 $d=Get-Disk -Number $B.disk_number -ErrorAction Stop;$i=$B.identity;$p=Get-Partition -DiskNumber $B.disk_number -PartitionNumber $i.partition_number -ErrorAction Stop
 Need ($d.PartitionStyle.ToString()-ceq'GPT'-and[guid]$d.Guid-eq[guid]$i.disk_guid-and$d.Size-eq$i.disk_bytes-and$d.LogicalSectorSize-eq$i.logical_sector_bytes-and$d.PhysicalSectorSize-eq$i.physical_sector_bytes-and$d.IsOffline-eq$Offline-and$d.IsReadOnly-eq$ReadOnly-and[guid]$p.Guid-eq[guid]$i.partition_guid-and$p.Offset-eq$i.partition_offset-and$p.Size-eq$i.partition_bytes-and[guid]$B.volume_guid-eq[guid]$i.partition_guid) 'Actual bound disk geometry/attributes/partition differs; attributes are never cleared.'
 $unique=@(Get-Disk|Where-Object {[string]$_.Guid-ceq[string]$d.Guid});Need ($unique.Count-eq1) 'Disk identity must be unique.'
 if($B.disk_number-ne0){Need (-not$d.IsBoot-and-not$d.IsSystem) 'Data binding cannot name a boot/system disk.'}
 return @{disk=$d;partition=$p}
}
function Inventory {return @(Get-Disk -ErrorAction Stop|Sort-Object Number|ForEach-Object {[pscustomobject][ordered]@{number=[int]$_.Number;guid=[string]$_.Guid;bytes=[long]$_.Size;offline=[bool]$_.IsOffline;readonly=[bool]$_.IsReadOnly;boot=[bool]$_.IsBoot;system=[bool]$_.IsSystem;bus_type=$_.BusType.ToString();location=[string]$_.Location;path=[string]$_.Path}})}
function Protected{
 $g=Get-Disk -Number 4;$p=Get-Partition -DriveLetter G;$v=$p|Get-Volume;$old=Get-Disk -Number 5
 Need ([guid]$g.Guid-eq[guid]'e1f3b9d3-979f-4123-9fee-399640c25092'-and-not$g.IsOffline-and-not$g.IsReadOnly-and$p.DiskNumber-eq4-and$v.FileSystem-ceq'ReFS'-and$v.AllocationUnitSize-eq4096-and[guid]$old.Guid-eq[guid]'ad077674-6305-4767-a2aa-6ded3b707e36'-and$old.IsOffline-and$old.IsReadOnly) 'Protected G4/shadow5 attributes differ.'
}
function Routes([bool]$Fresh){
 Need ($env:COMPUTERNAME-ceq'N2R-WIN11'-and$env:SystemDrive-ceq'C:'-and@(Get-Disk).Count-eq7) 'Exact owning guest with seven existing disks required.'
 $s=$c.source;$h=$c.shadow;$j=$c.journal.disk
 Need ($s.disk_number-eq1-and[guid]$s.volume_guid-eq[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-and[guid]$s.identity.disk_guid-eq[guid]'1b191872-c372-41ee-a416-e18863996f54'-and$s.identity.partition_number-eq2-and$s.identity.partition_offset-eq16MB-and$s.identity.partition_bytes-eq52GB-and$s.identity.disk_bytes-eq64GB-and$h.disk_number-eq6-and[guid]$h.identity.disk_guid-eq[guid]'b14b46fc-c7f4-4548-9391-52e18f75831b'-and[guid]$h.volume_guid-eq[guid]'6a1efd54-6209-42f1-a6c8-fd5ef88f5759'-and$h.identity.partition_number-eq2-and$h.identity.partition_offset-eq32MB-and$h.identity.partition_bytes-eq52GB-and$h.identity.disk_bytes-eq55901683712-and$j.disk_number-eq0-and[guid]$j.identity.disk_guid-eq[guid]'1f804918-e98f-4a71-9022-fc00c3cb7c26'-and[guid]$j.volume_guid-eq[guid]'c6c3318f-a7c8-47b9-be6d-6dde5e00862f'-and$j.identity.partition_number-eq3-and$j.identity.partition_offset-eq331350016-and$j.identity.partition_bytes-eq66238545920-and$j.identity.disk_bytes-eq64GB-and$c.journal.allow_additional_partitions-eq$true-and$c.journal.externally_enrolled_disk_unique_id-ceq'gpt-1f804918-e98f-4a71-9022-fc00c3cb7c26') 'Only the prepared exact source/shadow/OS routes are enrolled.'
 foreach($b in @($s,$h,$j)){Need ($b.identity.logical_sector_bytes-eq512-and$b.identity.physical_sector_bytes-eq4096) 'Exact sector geometry required.'}
 $source=Binding $s (-not$Fresh) $false
 if($Fresh){$v=$source.partition|Get-Volume;Need ($v.FileSystem-ceq'NTFS'-and$v.AllocationUnitSize-eq65536-and$v.FileSystemLabel-ceq'n2r-stream-source'-and'F:\'-in@($source.partition.AccessPaths)) 'Fresh live source must be the existing online writable NTFS64K F: route; core obtains the live certificate and freezes it.'}
 $os=Binding $j $false $false;$cp=Get-Partition -DriveLetter C;Need ($cp.DiskNumber-eq0-and$cp.PartitionNumber-eq3) 'Exact OS route required.'
 Need (('\\?\Volume{'+([guid]$j.volume_guid).ToString('D')+'}\')-in@($os.partition.AccessPaths)) 'OS volume GUID access route differs.'
 $cv=$cp|Get-Volume;Need ($cv.FileSystem-ceq'NTFS'-and$cv.SizeRemaining-ge$(if($Fresh){11GB}else{1GB})) 'Existing NTFS journal volume/free reserve differs.'
 $shadow=Binding $h (-not$Fresh) (-not$Fresh)
 $provider=Get-DiskImage -ImagePath $c.managed_path -ErrorAction Stop
 Need ($provider.Attached-and[string]::Equals([string]$provider.ImagePath,$c.managed_path,[StringComparison]::OrdinalIgnoreCase)-and[string]::Equals([string]$provider.DevicePath,'\\.\PhysicalDrive6',[StringComparison]::OrdinalIgnoreCase)) 'Same already attached owned VHDX provider required; no reattachment is performed.'
 $made=OpenPinned (Join-Path $c.stage 'prepared-managed-result.json') $c.prepared_managed_sha256 1MB $true
 Need ((Same $made.binding $h)-and$made.path-ceq$c.managed_path-and[guid]$made.virtual_disk_id-eq[guid]'afd68132-7ad8-4a23-83a4-1cdcc20b927d') 'Prepared managed identity differs.'
 if($Fresh){
  $v=$shadow.partition|Get-Volume;Need ($v.FileSystem-ceq'ReFS'-and$v.AllocationUnitSize-eq4096-and$v.FileSystemLabel-ceq'n2r-retained-shadow') 'Existing empty ReFS4K shadow required.'
  $volumePath='\\?\Volume{'+([guid]$h.volume_guid).ToString('D')+'}\';Need ($volumePath-in@($shadow.partition.AccessPaths)) 'Shadow volume route differs.'
  $entries=@(Get-ChildItem -LiteralPath $volumePath -Force -ErrorAction Stop)
  Need (@($entries|Where-Object {$_.Name-cne'System Volume Information'-or-not$_.PSIsContainer-or($_.Attributes-band[IO.FileAttributes]::ReparsePoint)}).Count-eq0) 'Prepared shadow contains user entries or unknown root metadata; refuse without formatting.'
 }
 Protected
 return @{source_offline=(-not$Fresh);source_readonly=$false;shadow_offline=(-not$Fresh);shadow_readonly=(-not$Fresh);provider=@{image_path=[string]$provider.ImagePath;device_path=[string]$provider.DevicePath;attached=[bool]$provider.Attached};all_disk_attributes=(Inventory);attributes_changed_by_dispatcher=$false;reattached=$false;rebound=$false}
}
function Artifacts([string]$Directory,[string]$BundleSha){
 $path=Join-Path $Directory 'allocation-recovery-bundle.json';$bundle=OpenPinned $path $BundleSha 65536 $true
 Need ($bundle.schema_version-eq1-and$bundle.kind-ceq'allocation-bounded-recovery-bundle'-and$bundle.serialized_bundle_grants_recovery_authority-eq$false-and(Same $bundle.source $c.source)) 'Actual pinned routing-only recovery bundle differs.'
 $values=@{};$pins=@{}
 foreach($spec in @(@{key='request';leaf='request.json';max=131072},@{key='plan';leaf='selected-plan.json';max=16MB},@{key='ticket';leaf='selected-ticket.json';max=65536},@{key='expectation';leaf='expectation.json';max=16MB},@{key='verification';leaf='verification.json';max=1MB},@{key='recovery_payload_manifest';leaf='recovery-payload-manifest.json';max=16MB})){
  $p=Join-Path $Directory $spec.leaf;$b=$bundle.($spec.key);Need ($b.path-ceq$p) 'Exact original artifact routes required.';$values[$spec.key]=OpenPinned $p $b.sha256 $spec.max $true;$pins[$spec.key]=$b.sha256
 }
 $r=$values.request;$t=$values.ticket;$location=Json (Join-Path $Directory 'journal-location.json')
 Need ((Same $r.pair.source $c.source)-and(Same $r.pair.shadow $c.shadow)-and(Same $r.journal $c.journal)-and$r.schema_version-eq3-and$r.verification_policy-ceq'extent_identity_v1'-and$r.selected_capacity_policy-ceq'source_free_actual_bytes_v1'-and$null-eq$r.source_resource_profile.experimental_object_envelope_v3-and$r.max_journal_bytes-eq8GB-and$r.max_literal_backing_bytes-eq256MB-and$r.max_combined_scratch_bytes-eq10GB-and$r.verify_existing_shadow-eq$false) 'Actual original admitted request routes/policy differ.'
 Need ($t.marker_profile-ceq'redundant_source_free_v1'-and$t.whole_image_verified-eq$false-and$t.selected_bytes-gt0-and$t.range_count-gt0-and$t.journal_length-gt32768-and@($t.immutable_sha256).Count-eq32-and@($t.old_selected_sha256).Count-eq32-and@($t.old_restored_selected_sha256).Count-eq32-and@($t.new_selected_sha256).Count-eq32-and$location.format-ceq'N2RFRE02'-and$location.journal_format_version-eq6-and$location.path-ceq$bundle.journal-and(Same $bundle.marker_storage_identity $location.identity)) 'Actual format6/profile/independently pinned marker-storage identity required.'
 return @{bundle=$bundle;ticket=$t;request=$r;values=$values;pins=$pins;location=$location;bundle_sha256=$BundleSha}
}
function Marker($Observation,$Facts){
 Need ($Observation.native_qualified-eq$false-and$Observation.journal_length-eq$Facts.ticket.journal_length-and(Same $Observation.identity $Facts.bundle.marker_storage_identity)-and$Observation.logical_sector_bytes-eq512-and$Observation.physical_sector_bytes-eq4096-and$Observation.cluster_bytes-gt0-and@($Observation.file_storage_info).Count-eq7-and@($Observation.marker_device_offsets).Count-eq8) 'Actual native marker storage observation differs; native qualification remains false.'
 $offsets=@($Observation.marker_device_offsets);Need (@($offsets|Sort-Object -Unique).Count-eq8) 'Eight distinct marker sectors required.'
 foreach($offset in $offsets){Need ([decimal]$offset-ge0-and[decimal]$offset%4096-eq0-and[decimal]$offset+4096-le[decimal]$c.journal.disk.identity.disk_bytes) 'Marker device offsets must be aligned and disk bounded.'}
}
try{
 $configPath=Join-Path '__STAGE__' 'configuration.json';$c=OpenPinned $configPath '__CONFIG_SHA__' 1MB $true
 Need ($c.stage-ceq'__STAGE__'-and$c.maximum_placement_bytes-eq16GB-and$c.maximum_placement_submissions-eq32768-and$c.maximum_exception_bytes-eq16MB) 'Pinned experiment configuration differs.'
 Idle;$before=Routes ($c.operation-ceq'Fresh');Save 'preflight.json' $before
 foreach($tool in $c.tools){$path=Join-Path $c.stage $tool.name;$null=OpenPinned $path $tool.sha256 64MB $false;Need ((Get-Item -LiteralPath $path).Length-eq$tool.bytes) 'Staged executable length differs.'}
 $requestPath=Join-Path $c.stage 'request.json';$request=OpenPinned $requestPath $c.request_sha256 131072 $true;$requestPin=$c.request_sha256
 Need ((Same $request.pair.source $c.source)-and(Same $request.pair.shadow $c.shadow)-and(Same $request.journal $c.journal)-and$request.experiment_id-ceq$c.run_id) 'Fresh derived request bindings differ.'
 $facts=$null
 if($c.operation-ceq'Recover'){
  $checkpoint=OpenPinned (Join-Path $c.stage 'original-fault-checkpoint.json') $c.checkpoint_sha256 1MB $true;Need (Same $checkpoint $c.checkpoint) 'Staged original checkpoint receipt differs.'
  $directory=Split-Path -Parent $c.bundle_path;$origin=Split-Path -Parent $directory
  $facts=Artifacts $directory $c.bundle_sha256
  $originalProcess=OpenPinned (Join-Path $origin 'native-process.json') $checkpoint.process_sha256 1MB $true
  $originalTerminal=OpenPinned (Join-Path $origin 'native-terminal.json') $checkpoint.terminal_sha256 4MB $true
  $fault=OpenPinned (Join-Path $origin 'native-marker-fault-observation.json') $checkpoint.fault_observation_sha256 4MB $true
  Need ($originalProcess.pid-eq$checkpoint.native_pid-and$originalProcess.creation_ms-eq$checkpoint.native_creation_ms-and$originalProcess.binary_sha256-ceq$checkpoint.producer_sha256-and$originalProcess.process_handle_retained_before_wait-eq$true-and$originalProcess.expected_exit-eq86-and'fresh'-cin@($originalProcess.argv)-and'--first-write-fault'-cin@($originalProcess.argv)-and$originalTerminal.pid-eq$originalProcess.pid-and$originalTerminal.creation_ms-eq$originalProcess.creation_ms-and$originalTerminal.native_exit-eq86-and$originalTerminal.native_exit_observed-eq$true-and$fault.kind-ceq'native-marker-first-write-observation-v1'-and$fault.bundle_path-ceq$c.bundle_path-and$fault.bundle_sha256-ceq$c.bundle_sha256-and$fault.native_pid-eq$checkpoint.native_pid-and$fault.native_creation_ms-eq$checkpoint.native_creation_ms-and$fault.native_exit-eq86-and$fault.first_write_flushed-eq$true-and$fault.no_handoff-eq$true-and$fault.process_sha256-ceq$checkpoint.process_sha256-and$fault.terminal_sha256-ceq$checkpoint.terminal_sha256-and$fault.raw_journal_opened-eq$false) 'Actual original producer handle/birth/exit86/fault evidence differs.'
  Need (-not(Test-Path -LiteralPath (Join-Path $directory 'apply.json'))-and-not(Test-Path -LiteralPath (Join-Path $directory 'handoff.json'))-and-not(Test-Path -LiteralPath (Join-Path $directory 'result.json'))) 'Original interrupted branch must have no completion artifacts; no closed replay.'
 }
 Save 'wrapper-worker.json' @{pid=$PID;creation_ms=([DateTimeOffset](Get-Process -Id $PID).StartTime).ToUnixTimeMilliseconds();run_id=$c.run_id;utc=[DateTime]::UtcNow.ToString('o')}
 Idle;$null=Routes ($c.operation-ceq'Fresh');Need (-not(Test-Path -LiteralPath $c.output)) 'Native output must be a fresh directory.'
 $argv=@('--acknowledge-enrolled-disposable-devices','--acknowledge-unqualified-native-markers')
 if($c.operation-ceq'Fresh'){$argv+=@('fresh','--request',$requestPath,'--request-sha256',$requestPin,'--output',$c.output,'--maximum-placement-bytes','17179869184','--maximum-placement-submissions','32768','--maximum-exception-bytes','16777216');if($c.first_write_fault){$argv+='--first-write-fault'}}else{$argv+=@('recover','--bundle',$c.bundle_path,'--bundle-sha256',$c.bundle_sha256,'--output',$c.output);if($c.rollback){$argv+='--rollback'}}
 $arguments=($argv|ForEach-Object {Need ($_-cnotmatch'["\r\n\x00]') 'Unsafe native argument.';$tail=$_.Length-$_.TrimEnd('\').Length;'"'+$_+('\'*$tail)+'"'})-join' '
 $binary=Join-Path $c.stage 'lab-selected-marker-native.exe';$producer=@($c.tools|Where-Object name -CEQ 'lab-selected-marker-native.exe')[0]
 $stdout=Join-Path $c.stage 'native.stdout.log';$stderr=Join-Path $c.stage 'native.stderr.log'
 Save 'native-dispatch-intent.json' @{binary=$binary;binary_sha256=$producer.sha256;argv=$argv;expected_exit=$c.expected_exit;source_certificate_must_be_live=($c.operation-ceq'Fresh');saved_json_grants_authority=$false;utc=[DateTime]::UtcNow.ToString('o')}
 $phase='native-process';$clock=[Diagnostics.Stopwatch]::StartNew()
 $process=Start-Process -FilePath $binary -ArgumentList $arguments -WorkingDirectory $c.stage -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
 $null=$process.Handle;$birth=([DateTimeOffset]$process.StartTime).ToUnixTimeMilliseconds();$nativePid=$process.Id
 Save 'native-process.json' @{pid=$nativePid;creation_ms=$birth;parent_pid=$PID;binary=$binary;binary_sha256=$producer.sha256;argv=$argv;expected_exit=$c.expected_exit;process_handle_retained_before_wait=$true;utc=[DateTime]::UtcNow.ToString('o')}
 $process.WaitForExit();$clock.Stop();$process.Refresh();$nativeExit=$process.ExitCode
 $peakWorking=$null;$peakPrivate=$null;try{$peakWorking=[long]$process.PeakWorkingSet64}catch{};try{$peakPrivate=[long]$process.PeakPagedMemorySize64}catch{}
 if($null-ne$peakWorking-and$peakWorking-le0){$peakWorking=$null};if($null-ne$peakPrivate-and$peakPrivate-le0){$peakPrivate=$null}
 Save 'native-terminal.json' @{pid=$nativePid;creation_ms=$birth;native_exit=$nativeExit;native_exit_observed=($null-ne$nativeExit);process_handle_retained_through_terminal=$true;wall_seconds=$clock.Elapsed.TotalSeconds;peak_working_set_bytes=$peakWorking;peak_paged_memory_bytes=$peakPrivate;peak_metrics_source='retained-System.Diagnostics.Process; null when unavailable';stdout=(Log $stdout);stderr=(Log $stderr);utc=[DateTime]::UtcNow.ToString('o')}
 $phase='terminal-observation';Idle;Protected
 $after=Inventory;$unrelatedBefore=@($before.all_disk_attributes|Where-Object number -NotIn @(1,6));$unrelatedAfter=@($after|Where-Object number -NotIn @(1,6));Need (Same $unrelatedBefore $unrelatedAfter) 'An unrelated disk identity/provider/attribute changed.'
 Need ($null-ne$nativeExit-and$nativeExit-eq$c.expected_exit) 'Actual process fault/unexpected exit; preserve all material without retry.'
 $null=Binding $c.shadow $true $true;$provider=Get-DiskImage -ImagePath $c.managed_path -ErrorAction Stop
 Need ($provider.Attached-and[string]::Equals([string]$provider.ImagePath,$c.managed_path,[StringComparison]::OrdinalIgnoreCase)-and[string]::Equals([string]$provider.DevicePath,'\\.\PhysicalDrive6',[StringComparison]::OrdinalIgnoreCase)) 'Original shadow provider must remain attached and offline/read-only after native work.'
 if($c.operation-ceq'Fresh'){
  $bundlePath=Join-Path $c.output 'allocation-recovery-bundle.json';$bundleSha=Pin $bundlePath;$facts=Artifacts $c.output $bundleSha
  Need ($facts.request.experiment_id-ceq$c.run_id) 'Actual fresh product request must retain the new experiment identity.'
  $printed=Log $stdout;$matches=[regex]::Matches($printed.text,'(?m)^Recovery checksum: ([0-9a-f]{64})\r?$');$dirs=[regex]::Matches($printed.text,'(?m)^Recovery directory: (.+?)\r?$');Need ($matches.Count-eq1-and$dirs.Count-eq1-and$matches[0].Groups[1].Value-ceq$bundleSha-and$dirs[0].Groups[1].Value-ceq$c.output) 'Actual product bundle publication differs.'
  $marker=Json (Join-Path $c.output 'native-marker-storage.json');Marker $marker $facts
 }else{$bundlePath=$c.bundle_path;$bundleSha=$c.bundle_sha256;$marker=Json (Join-Path $c.output 'journal-identity.json');Marker $marker $facts}
 $proof=@{format=$facts.location.format;journal_format_version=$facts.location.journal_format_version;marker_profile=$facts.ticket.marker_profile;marker_storage=$marker;bundle_path=$bundlePath;bundle_sha256=$bundleSha;ticket_sha256=$facts.pins.ticket;ticket=$facts.ticket;raw_journal_opened=$false;grants_product_authority=$false}
 Save 'native-marker-ticket-observation.json' $proof
 if($nativeExit-eq86){
  $null=Binding $c.source $true $false;$null=Binding $c.shadow $true $true
  $message=Log $stderr;Need ([regex]::Matches($message.text,'(?m)^Controlled general target interruption; source stays offline, recover using the pinned ticket[.]\r?$').Count-eq1-and-not(Test-Path -LiteralPath (Join-Path $c.output 'apply.json'))-and-not(Test-Path -LiteralPath (Join-Path $c.output 'handoff.json'))-and-not(Test-Path -LiteralPath (Join-Path $c.output 'result.json'))) 'Actual sole flushed-write message and no completion required.'
  $diagnostic=Json (Join-Path $c.output 'fresh-exclusive-fault-path.json');Need ($diagnostic.kind-ceq'lab-fresh-exclusive-v3-first-write-path'-and$diagnostic.controlled_exit_code-eq86-and$diagnostic.requested_flushed_payload_writes-eq1-and$diagnostic.prepared_journal_owner_reused-eq$true-and$diagnostic.diagnostic_only-eq$true-and$diagnostic.recovery_bundle_sha256-ceq$bundleSha) 'Original actual first-write diagnostic differs.'
  Save 'native-marker-fault-observation.json' @{schema_version=1;kind='native-marker-first-write-observation-v1';run_id=$c.run_id;native_pid=$nativePid;native_creation_ms=$birth;native_exit=86;first_write_flushed=$true;no_handoff=$true;bundle_path=$bundlePath;bundle_sha256=$bundleSha;source_commit=$c.source_commit;producer_sha256=$producer.sha256;process_sha256=(Pin (Join-Path $c.stage 'native-process.json'));terminal_sha256=(Pin (Join-Path $c.stage 'native-terminal.json'));fault_diagnostic_sha256=(Pin (Join-Path $c.output 'fresh-exclusive-fault-path.json'));prepared_managed_receipt_sha256=$c.prepared_managed_sha256;source_offline=$true;source_readonly=$false;shadow_offline=$true;shadow_readonly=$true;raw_journal_opened=$false;native_marker_qualified=$false;hard_power_qualified=$false;all_other_tasks_terminal_and_native_workers_absent=$true;root_checkpoint_receipt_created=$false;utc=[DateTime]::UtcNow.ToString('o')}
  Save 'wrapper-result.json' @{schema_version=1;kind='native-marker-experiment-observation';observation_passed=$true;process_fault_observed=$true;controlled_first_write_fault=$true;native_exit=86;native_marker_qualified=$false;hard_power_qualified=$false;raw_journal_opened=$false;automatic_retry_recovery_restore_cleanup=$false;ticket_observation='native-marker-ticket-observation.json';utc=[DateTime]::UtcNow.ToString('o')};exit 86
 }
 $result=Json (Join-Path $c.output 'result.json');Need ($result.success-eq$true) 'Actual product success artifact required in addition to exit0.'
 $source=Binding $c.source $false $false;$volume=$source.partition|Get-Volume
 if($c.rollback){
  $closed=Json (Join-Path $c.output 'rollback.json');$completion=Json (Join-Path $c.output 'completion.json') 16MB
  Need ($result.action-ceq'rollback'-and$result.observed_lifecycle-ceq'apply_intent'-and$result.outcome-ceq'ntfs_restored'-and$result.exclusive_recovery_journal_used-eq$true-and$completion.mounted_filesystem-ceq'NTFS'-and$volume.FileSystem-ceq'NTFS'-and$closed.replay_closed-eq$true-and(Same $closed.selected_sha256 $facts.ticket.old_restored_selected_sha256)) 'Actual original interrupted NTFS restore-required selected digest/ABT proof differs.'
 }else{
  $leaf=if($c.operation-ceq'Fresh'){'finalization.json'}else{'completion.json'};$extentLeaf=if($c.operation-ceq'Fresh'){'extent-verification.json'}else{'recovery-extent-verification.json'}
  $completion=Json (Join-Path $c.output $leaf) 16MB;$extent=Json (Join-Path $c.output $extentLeaf);$closed=Json (Join-Path $c.output 'handoff.json')
  Need ($completion.success-eq$true-and$completion.rollback_closed-eq$true-and$volume.FileSystem-ceq'ReFS'-and$volume.AllocationUnitSize-eq4096-and$closed.replay_closed-eq$true-and(Same $closed.selected_sha256 $facts.ticket.new_selected_sha256)-and$extent.all_complete_maps_identical-eq$true-and$extent.handoff_replay_closed-eq$true-and$extent.stream_and_directory_bindings-gt0) 'Actual product full metadata/namespace/maps/tails and closed HND proof required.'
  if($c.operation-ceq'Fresh'){Need ($extent.resident_and_residual_bytes_bound_by_selected_image-eq$true-and$extent.materialized_extent_tail_bytes_verified-ge0) 'Fresh product residual/tail verification required.'}else{Need ($extent.extent_only_partial_tail_bytes-ge0-and$extent.extent_only_partial_streams-ge0) 'Recovery product tail accounting required.'}
  $native=$completion.native;$scope=$native.content_observation
  Need ($scope.metadata_and_namespace_verified-eq$true-and$scope.complete_stream_mappings_observed-eq$true-and$scope.data_storage_validity_checked-eq$true) 'Built-in native metadata/namespace/all-map/storage verification must pass.'
  if($c.operation-ceq'Recover'){Need ($result.action-ceq'resume'-and$result.observed_lifecycle-ceq'apply_intent'-and$result.outcome-ceq'refs_completed'-and$result.exclusive_recovery_journal_used-eq$true) 'Actual original partial-state resume required; no closed verification replay.'}
 }
 Need ($volume.FileSystemLabel-ceq'n2r-stream-source'-and'F:\'-in@($source.partition.AccessPaths)) 'Native completion must preserve the original source label/mount path.'
 Save 'native-completion-observation.json' @{result=$result;completion_success=$true;closed_selected_digest_matches_ticket=$true;product_builtin_checks_observed=$true;independent_content_hashes_run=$false;native_marker_qualified=$false;hard_power_qualified=$false;raw_journal_opened=$false;utc=[DateTime]::UtcNow.ToString('o')}
 Save 'wrapper-result.json' @{schema_version=1;kind='native-marker-experiment-observation';observation_passed=$true;process_fault_observed=$false;native_exit=0;operation=$c.operation;rollback=$c.rollback;native_marker_qualified=$false;hard_power_qualified=$false;raw_journal_opened=$false;automatic_retry_recovery_restore_cleanup=$false;ticket_observation='native-marker-ticket-observation.json';utc=[DateTime]::UtcNow.ToString('o')}
}catch{
 if($null-ne(Get-Variable c -ErrorAction SilentlyContinue)) {Save 'wrapper-failed.json' @{observation_passed=$false;phase=$phase;native_exit=$nativeExit;native_exit_observed=($null-ne$nativeExit);process_fault_observed=($null-ne$nativeExit-and$nativeExit-ne0);error=$_.Exception.ToString();native_marker_qualified=$false;hard_power_qualified=$false;raw_journal_opened=$false;automatic_retry_recovery_restore_cleanup=$false;worker_death_inferred=$false;utc=[DateTime]::UtcNow.ToString('o')}}
 exit 1
}finally{if($null-ne$process){$process.Dispose()};foreach($stream in $held){$stream.Dispose()}}
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
    $session=New-PSSession -VMId $vmId -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml'))
    Invoke-Command -Session $session -ArgumentList $stage,$task -ScriptBlock {param($Stage,$Task)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        if($env:COMPUTERNAME-cne'N2R-WIN11'-or(Test-Path -LiteralPath $Stage)-or@(Get-ScheduledTask|Where-Object {$_.TaskName-ceq$Task-or($_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled'))}).Count-or@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'-or($_.Name-match'\A(?:powershell|pwsh)\.exe\z'-and$_.CommandLine-like'*C:\ntfs2refs\*')}).Count){throw 'Fresh exact stage and terminal N2R tasks/no workers required.'}
        $cursor=Get-Item -LiteralPath 'C:\ntfs2refs' -Force;while($null-ne$cursor){if($cursor.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse stage ancestry refused.'};$cursor=$cursor.Parent};$null=New-Item -ItemType Directory -Path $Stage
    }
    foreach($tool in $tools){Copy-Item -LiteralPath $tool.path -ToSession $session -Destination (Join-Path $stage $tool.name)}
    foreach($file in @('request.json','configuration.json')){Copy-Item -LiteralPath (Join-Path $root $file) -ToSession $session -Destination (Join-Path $stage $file)}
    Copy-Item -LiteralPath $PreparedManagedReceiptPath -ToSession $session -Destination (Join-Path $stage 'prepared-managed-result.json')
    if($Operation -ceq 'Recover'){Copy-Item -LiteralPath $InterruptedCheckpointReceiptPath -ToSession $session -Destination (Join-Path $stage 'original-fault-checkpoint.json')}
    Copy-Item -LiteralPath $wrapper -ToSession $session -Destination (Join-Path $stage 'wrapper.ps1')
    HostGuard
    Save 'dispatch.json' @{schema_version=1;kind='unqualified-native-marker-experiment-dispatch';run_id=$run;operation=$Operation;mode=$mode;source_commit=$SourceCommit;manifest_sha256=$ToolsetManifestSha256;parent_id=$ExpectedParent;checkpoint_ids=$ids;task_name=$task;guest_stage=$stage;output=$config.output;wrapper_sha256=$wrapperSha;configuration_sha256=$configSha;expected_exit=$config.expected_exit;completion_inferred=$false;native_marker_qualified=$false;hard_power_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')}
    # Stage checks execute the same literal preflight functions, never the body
    # containing Start-Process. All checks finish before the task is registered.
    $preflightTokens=$null;$preflightErrors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($guest,[ref]$preflightTokens,[ref]$preflightErrors)
    $definitions=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst]}|ForEach-Object {$_.Extent.Text})-join[Environment]::NewLine
    Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperSha,$configSha,$actionArguments,$definitions -ScriptBlock {param($Stage,$Task,$WrapperSha,$ConfigSha,$ActionArguments,$Definitions)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$held=[Collections.Generic.List[IO.FileStream]]::new()
        try{
            . ([scriptblock]::Create($Definitions));$c=OpenPinned (Join-Path $Stage 'configuration.json') $ConfigSha 1MB $true
            $null=OpenPinned (Join-Path $Stage 'wrapper.ps1') $WrapperSha 1MB $false
            Idle;$observation=Routes ($c.operation-ceq'Fresh')
            foreach($tool in $c.tools){$p=Join-Path $Stage $tool.name;$null=OpenPinned $p $tool.sha256 64MB $false;Need ((Get-Item -LiteralPath $p).Length-eq$tool.bytes) 'Staged tool length differs.'}
            $r=OpenPinned (Join-Path $Stage 'request.json') $c.request_sha256 131072 $true;Need ((Same $r.pair.source $c.source)-and(Same $r.pair.shadow $c.shadow)-and(Same $r.journal $c.journal)) 'Staged request routes differ.'
            if($c.operation-ceq'Recover'){$null=Artifacts (Split-Path -Parent $c.bundle_path) $c.bundle_sha256;$cp=OpenPinned (Join-Path $Stage 'original-fault-checkpoint.json') $c.checkpoint_sha256 1MB $true;Need (Same $cp $c.checkpoint) 'Original checkpoint pin differs.'}
            Need (@(Get-ScheduledTask|Where-Object TaskName -CEQ $Task).Count-eq0) 'One fresh SYSTEM task required.'
            Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $ActionArguments) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)) -ErrorAction Stop|Out-Null
            Save 'staged-preflight.json' $observation
        }finally{foreach($stream in $held){$stream.Dispose()}}
    }
    HostGuard
    Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration $configuration) -AdditionalBytes $ForecastAdditionalBytes
    Invoke-Command -Session $session -ArgumentList $stage,$task,$wrapperSha,$configSha,$actionArguments,$definitions -ScriptBlock {param($Stage,$Task,$WrapperSha,$ConfigSha,$ActionArguments,$Definitions)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$held=[Collections.Generic.List[IO.FileStream]]::new()
        try{
            . ([scriptblock]::Create($Definitions));$c=OpenPinned (Join-Path $Stage 'configuration.json') $ConfigSha 1MB $true;$null=OpenPinned (Join-Path $Stage 'wrapper.ps1') $WrapperSha 1MB $false
            Idle;$null=Routes ($c.operation-ceq'Fresh');foreach($tool in $c.tools){$null=OpenPinned (Join-Path $Stage $tool.name) $tool.sha256 64MB $false};$null=OpenPinned (Join-Path $Stage 'request.json') $c.request_sha256 131072 $true
            $t=Get-ScheduledTask -TaskName $Task;$i=$t|Get-ScheduledTaskInfo
            Need ($t.State.ToString()-ceq'Ready'-and$i.LastRunTime.Year-lt2000-and@($t.Actions).Count-eq1-and$t.Actions[0].Execute-ceq"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"-and$t.Actions[0].Arguments-ceq$ActionArguments-and$t.Principal.UserId-in@('SYSTEM','S-1-5-18')-and$t.Principal.RunLevel.ToString()-ceq'Highest') 'Only the untouched pinned never-run SYSTEM task may start once.'
            Start-ScheduledTask -TaskName $Task -ErrorAction Stop
        }finally{foreach($stream in $held){$stream.Dispose()}}
    }
    Save 'start.json' @{start_issued_once=$true;task_name=$task;guest_stage=$stage;expected_exit=$config.expected_exit;completion_inferred=$false;automatic_retry_restore_cleanup=$false;utc=[DateTime]::UtcNow.ToString('o')}
    Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw
}catch{
    if($created-and-not(Test-Path -LiteralPath (Join-Path $root 'dispatch-failed.json'))){Save 'dispatch-failed.json' @{observation_passed=$false;error=$_.Exception.ToString();automatic_retry_restore_cleanup=$false;worker_death_inferred=$false;native_marker_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')}}
    throw
}finally{
    if($null-ne$session){Remove-PSSession $session -ErrorAction SilentlyContinue}
    foreach($stream in $held){$stream.Dispose()}
}
