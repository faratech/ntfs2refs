# Pure review of caller-supplied host graph observations. No file, VHD, VM,
# device or credential operation exists here. Valid structure is not a live
# ownership lease, writer exclusion or native write authority.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'IsolatedBaselineGuards.psm1') -Scope Local

function Require-Graph([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Test-GraphBool($Value, [bool]$Expected) {
    ($Value -is [bool]) -and ($Value -eq $Expected)
}
function Test-GraphInteger($Value, [long]$Minimum, [long]$Maximum) {
    (($Value -is [int]) -or ($Value -is [long]) -or ($Value -is [uint32]) -or ($Value -is [uint64])) -and
        ($Value -ge $Minimum) -and ($Value -le $Maximum)
}
function Get-GraphGuid($Value) {
    $parsed = [guid]::Empty
    Require-Graph (($Value -is [string] -or $Value -is [guid]) -and [guid]::TryParse([string]$Value, [ref]$parsed) -and $parsed -ne [guid]::Empty) 'Missing or malformed graph GUID.'
    $parsed.ToString('D')
}
function Test-GraphDosPath($Value) {
    if ($Value -isnot [string] -or $Value.Length -gt 32767 -or $Value -cnotmatch '\A[A-Za-z]:\\[^\x00-\x1f<>:"/|?*]+\z' -or $Value.EndsWith('\')) { return $false }
    foreach ($part in $Value.Substring(3).Split('\')) {
        if (-not $part -or $part -in @('.', '..') -or $part.EndsWith('.') -or $part.EndsWith(' ')) { return $false }
        $stem = $part.Split('.')[0].ToUpperInvariant()
        if ($stem -in @('CON','PRN','AUX','NUL','CONIN$','CONOUT$') -or $stem -match '\A(?:COM|LPT)[0-9]\z') { return $false }
    }
    $true
}
function Get-GraphAncestors([string]$Start, $Nodes) {
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $chain = [Collections.Generic.List[string]]::new()
    $cursor = $Start
    while ($null -ne $cursor) {
        Require-Graph ($chain.Count -lt 128) 'Graph ancestor depth exceeds 128 nodes.'
        Require-Graph ($Nodes.ContainsKey($cursor)) 'Graph has a dangling parent/reference identity.'
        Require-Graph ($seen.Add($cursor)) 'Cycle in graph file-identity ancestry.'
        $chain.Add($cursor)
        $cursor = $Nodes[$cursor].parent_id
    }
    # Avoid PowerShell unrolling a one-element chain into a string.
    ,$chain.ToArray()
}

function Assert-IsolatedHostGraph {
    param([Parameter(Mandatory)]$Snapshot)
    $policy = Get-IsolatedBaselinePolicy
    Require-Graph ((Test-GraphInteger $Snapshot.schema_version 1 1) -and $Snapshot.kind -ceq 'isolated-host-file-graph' -and (Test-GraphBool $Snapshot.inventory_complete $true)) 'Complete version-1 isolated host graph required.'
    $vm = $Snapshot.vm
    Require-Graph ((Get-GraphGuid $vm.id) -ceq $policy.vm_id -and $vm.name -ceq $policy.vm_name -and $vm.path -is [string] -and $vm.path.Equals($policy.vm_path, [StringComparison]::OrdinalIgnoreCase)) 'Exact isolated VM endpoint differs.'
    Require-Graph ((Test-GraphInteger $vm.generation 2 2) -and (Test-GraphInteger $vm.processor_count 4 4) -and (Test-GraphInteger $vm.memory_startup_bytes 8GB 8GB) -and $vm.state -ceq 'Running' -and (Test-GraphBool $vm.dynamic_memory_enabled $false) -and (Test-GraphInteger $vm.network_adapter_count 0 0) -and (Test-GraphInteger $vm.checkpoint_count 0 0) -and (Test-GraphBool $vm.automatic_checkpoints_enabled $false)) 'Isolated VM state/configuration differs.'
    Require-Graph ((Test-GraphBool $vm.tpm_enabled $true) -and $vm.secure_boot -ceq 'On' -and $vm.secure_boot_template -ceq 'MicrosoftWindows') 'Isolated VM security configuration differs.'

    $registered = @($Snapshot.registered_vm_ids)
    Require-Graph ($registered.Count -ge 1 -and $registered.Count -le 4096) 'Registered VM inventory exceeds bounds or is missing.'
    $vmIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($id in $registered) { Require-Graph ($vmIds.Add((Get-GraphGuid $id))) 'Duplicate registered VM GUID.' }
    Require-Graph ($vmIds.Contains($policy.vm_id)) 'Owned VM is absent from the registered inventory.'

    $items = @($Snapshot.nodes)
    $references = @($Snapshot.references)
    Require-Graph ($items.Count -ge 3 -and $items.Count -le 4096 -and $references.Count -ge 3 -and $references.Count -le 4096) 'Graph node/reference inventory exceeds bounds or is incomplete.'
    $nodes = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $paths = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    $displayIds = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach ($node in $items) {
        Require-Graph ($node.volume_root -is [string] -and $node.volume_root -cmatch '\A\\\\\?\\Volume\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}\\\z') 'Canonical volume GUID root required.'
        $null = Get-GraphGuid $node.volume_root.Substring(11,36)
        Require-Graph ($node.raw_file_id_hex -is [string] -and $node.raw_file_id_hex -cmatch '\A[0-9a-f]{32}\z' -and $node.raw_file_id_hex -cne ('0'*32)) 'Nonzero raw file identity required.'
        Require-Graph ($node.file_id -is [string] -and $node.file_id -cmatch '\A0x[0-9a-f]{32}\z' -and $node.file_id -cne ('0x'+('0'*32))) 'Nonzero fsutil display file identity required.'
        $expectedId = $node.volume_root.ToLowerInvariant() + '|' + $node.raw_file_id_hex
        Require-Graph ($node.id -is [string] -and $node.id -ceq $expectedId -and -not $nodes.ContainsKey($expectedId)) 'Node identity is malformed or duplicated.'
        $displayKey = $node.volume_root.ToLowerInvariant() + '|' + $node.file_id
        Require-Graph (-not $displayIds.ContainsKey($displayKey)) 'Raw/display file identities are not bijective within the volume.'
        $displayIds.Add($displayKey, $expectedId)
        Require-Graph ((Test-GraphInteger $node.number_of_links 1 4096) -and (Test-GraphBool $node.reparse_ancestry $false) -and (Test-GraphBool $node.is_directory $false) -and (Test-GraphBool $node.namespace_identity_pinned $true)) 'File namespace observation is incomplete, redirected or a directory.'
        $names = @($node.paths)
        Require-Graph ($names.Count -ge 1 -and $names.Count -eq $node.number_of_links) 'All observed hard-link names must be enumerated.'
        foreach ($name in $names) {
            Require-Graph ($paths.Count -lt 4096 -and (Test-GraphDosPath $name) -and -not $paths.ContainsKey($name)) 'Malformed, multiply identifying or over-budget DOS path inventory.'
            $paths.Add($name, $expectedId)
        }
        $null = Get-GraphGuid $node.vhd_id
        Require-Graph ((Test-GraphInteger $node.virtual_bytes 512 ([long]::MaxValue)) -and ($node.virtual_bytes % 512 -eq 0) -and (Test-GraphInteger $node.logical_sector_bytes 512 4096) -and (Test-GraphInteger $node.physical_sector_bytes 512 4096) -and $node.logical_sector_bytes -in @(512,4096) -and $node.physical_sector_bytes -in @(512,4096) -and $node.physical_sector_bytes -ge $node.logical_sector_bytes) 'Malformed VHD geometry.'
        Require-Graph ($null -eq $node.parent_id -or ($node.parent_id -is [string] -and $node.parent_id.Length -gt 0)) 'Parent must be null or a nonempty file node identity.'
        $nodes.Add($expectedId, $node)
    }

    # Validate all nodes, including currently unreferenced nodes. An unrelated
    # malformed chain must not be hidden by an early owned-node success.
    $chains = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $maximumDepth = 0
    foreach ($id in $nodes.Keys) {
        $chain = Get-GraphAncestors $id $nodes
        $chains.Add($id, $chain)
        $maximumDepth = [Math]::Max($maximumDepth, $chain.Length)
    }

    $endpoints = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $checkedRefs = [Collections.Generic.List[object]]::new()
    $ownCurrent = [Collections.Generic.List[object]]::new()
    foreach ($reference in $references) {
        $owner = Get-GraphGuid $reference.vm_id
        Require-Graph ($vmIds.Contains($owner)) 'Reference owner is absent from the complete registered VM inventory.'
        Require-Graph ($reference.kind -cin @('current_attachment','checkpoint_attachment')) 'Unknown reference kind.'
        $checkpoint = '-'
        if ($reference.kind -ceq 'current_attachment') {
            Require-Graph ($null -eq $reference.checkpoint_id) 'Current attachment must not carry a checkpoint identity.'
        } else {
            $checkpoint = Get-GraphGuid $reference.checkpoint_id
            Require-Graph ($owner -cne $policy.vm_id) 'Owned VM has no enrolled checkpoints.'
        }
        Require-Graph ($reference.node_id -is [string] -and $nodes.ContainsKey($reference.node_id)) 'Reference points to a missing file identity.'
        Require-Graph ($reference.controller_type -cin @('SCSI','IDE')) 'Unknown controller type.'
        $maxController = if ($reference.controller_type -ceq 'SCSI') {3} else {1}
        $maxLocation = if ($reference.controller_type -ceq 'SCSI') {63} else {1}
        Require-Graph ((Test-GraphInteger $reference.controller_number 0 $maxController) -and (Test-GraphInteger $reference.controller_location 0 $maxLocation)) 'Invalid controller number/location.'
        $endpoint = $owner + '|' + $reference.kind + '|' + $checkpoint + '|' + $reference.controller_type + '|' + $reference.controller_number + '|' + $reference.controller_location
        Require-Graph ($endpoints.Add($endpoint)) 'Duplicate registered controller endpoint.'
        $row = [pscustomobject]@{ vm_id=$owner; kind=$reference.kind; node_id=$reference.node_id;
            controller_type=$reference.controller_type; controller_number=$reference.controller_number;
            controller_location=$reference.controller_location; chain=$chains[$reference.node_id] }
        $checkedRefs.Add($row)
        if ($owner -ceq $policy.vm_id -and $reference.kind -ceq 'current_attachment') { $ownCurrent.Add($row) }
    }
    Require-Graph ($ownCurrent.Count -eq 3) 'Exactly three owned current attachments required.'
    $ownedIds = [Collections.Generic.List[string]]::new()
    $roles = @('os','target','journal')
    for ($slot=0; $slot -lt 3; $slot++) {
        $role = $roles[$slot]
        $matches = @($ownCurrent | Where-Object { $_.controller_type -ceq 'SCSI' -and $_.controller_number -eq 0 -and $_.controller_location -eq $slot })
        Require-Graph ($matches.Count -eq 1) 'Owned SCSI role/controller attachment differs.'
        $node = $nodes[$matches[0].node_id]
        $expectedPath = $policy.disk_root + '\' + $role + '.vhdx'
        $expectedFile = $policy.($role+'_file_id')
        $expectedVhd = $policy.($role+'_vhd_id')
        $expectedSize = if ($role -ceq 'journal') {8GB} else {64GB}
        Require-Graph ($node.volume_root -ceq $policy.host_volume_root -and $node.file_id -ceq $expectedFile -and (Get-GraphGuid $node.vhd_id) -ceq $expectedVhd -and $node.virtual_bytes -eq $expectedSize -and $node.logical_sector_bytes -eq 512 -and $node.physical_sector_bytes -eq 4096) 'Owned leaf file/volume/container identity or geometry differs.'
        Require-Graph ($null -eq $node.parent_id -and $node.number_of_links -eq 1 -and @($node.paths).Count -eq 1 -and $node.paths[0].Equals($expectedPath, [StringComparison]::OrdinalIgnoreCase)) 'Owned leaf is not an independent single-path, single-link file.'
        $users = @($checkedRefs | Where-Object { $_.chain -ccontains $node.id })
        Require-Graph ($users.Count -eq 1 -and $users[0].vm_id -ceq $policy.vm_id -and $users[0].kind -ceq 'current_attachment' -and $users[0].node_id -ceq $node.id -and $users[0].controller_type -ceq 'SCSI' -and $users[0].controller_number -eq 0 -and $users[0].controller_location -eq $slot) 'Owned backing has foreign, checkpoint or parent-chain ownership.'
        $ownedIds.Add($node.id)
    }
    [pscustomobject]@{ schema_version=1; kind='isolated-host-file-graph-review'; profile=$policy.profile;
        observed_structure_valid=$true; writer_exclusion_established=$false; write_authority=$false;
        nodes_checked=$nodes.Count; references_checked=$checkedRefs.Count; maximum_ancestor_nodes=$maximumDepth;
        owned_node_ids=$ownedIds.ToArray(); scope='supplied observations only; no live lease or native authority' }
}

Export-ModuleMember -Function Assert-IsolatedHostGraph
