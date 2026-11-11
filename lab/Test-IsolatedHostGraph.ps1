<# Synthetic caller-supplied graphs only. No VM, file identity, VHD, device,
   image, credential or native method is queried or opened. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'IsolatedBaselineGuards.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IsolatedHostGraph.psm1') -Force
$script:checks = 0
function Check([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }; $script:checks++
}
function Reject([scriptblock]$Action, [string]$Message) {
    $refused = $false
    try { & $Action | Out-Null } catch { $refused = $true }
    Check $refused $Message
}
function Copy-Graph($Value) { $Value | ConvertTo-Json -Depth 24 | ConvertFrom-Json }
$p = Get-IsolatedBaselinePolicy
$otherVolume = '\\?\Volume{77777777-7777-7777-7777-777777777777}\'
function New-Node([int]$Number, [string]$Path, [string]$Volume=$p.host_volume_root) {
    $raw = $Number.ToString('x32')
    [pscustomobject]@{ id=($Volume.ToLowerInvariant()+'|'+$raw); volume_root=$Volume; raw_file_id_hex=$raw;
        file_id=('0x'+$raw); paths=@($Path); number_of_links=1; reparse_ancestry=$false; is_directory=$false;
        namespace_identity_pinned=$true; vhd_id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
        virtual_bytes=64GB; logical_sector_bytes=512; physical_sector_bytes=4096; parent_id=$null }
}
function New-Reference([string]$VmId, [string]$NodeId, [int]$Slot=0) {
    [pscustomobject]@{ vm_id=$VmId; kind='current_attachment'; checkpoint_id=$null; node_id=$NodeId;
        controller_type='SCSI'; controller_number=0; controller_location=$Slot }
}
function Fixture {
    $snapshot=[pscustomobject]@{ schema_version=1; kind='isolated-host-file-graph'; inventory_complete=$true;
        registered_vm_ids=@($p.vm_id,$p.old_vm_id); nodes=@(); references=@();
        vm=[pscustomobject]@{ id=$p.vm_id; name=$p.vm_name; path=$p.vm_path; generation=2;
            processor_count=4; memory_startup_bytes=8GB; state='Running'; dynamic_memory_enabled=$false;
            network_adapter_count=0; checkpoint_count=0; automatic_checkpoints_enabled=$false;
            tpm_enabled=$true; secure_boot='On'; secure_boot_template='MicrosoftWindows' } }
    $roles=@('os','target','journal')
    for($i=0;$i-lt3;$i++) {
        $role=$roles[$i]
        $node=New-Node ($i+1) ($p.disk_root+'\'+$role+'.vhdx')
        $node.file_id=$p.($role+'_file_id'); $node.vhd_id=$p.($role+'_vhd_id')
        if($role-ceq'journal'){$node.virtual_bytes=8GB}
        $snapshot.nodes+= $node
        $snapshot.references+= (New-Reference $p.vm_id $node.id $i)
    }
    $snapshot
}
function With-ForeignLeaf {
    $s=Fixture
    $n=New-Node 100 'D:\unrelated\leaf.vhdx'
    $s.nodes+= $n; $s.references+= (New-Reference $p.old_vm_id $n.id)
    $s
}
$good=Fixture
$result=Assert-IsolatedHostGraph $good
Check ($result.observed_structure_valid-and-not$result.writer_exclusion_established-and-not$result.write_authority) 'Graph success became exclusion/write authority.'
Check ($result.nodes_checked-eq3-and$result.references_checked-eq3-and$result.owned_node_ids.Count-eq3-and$result.maximum_ancestor_nodes-eq1) 'Exact owned leaf graph was not preserved.'
Check (@(Get-Command -Module IsolatedHostGraph).Count-eq1) 'Unexpected operation exported by pure graph module.'
$claims=Copy-Graph $good
$claims|Add-Member writer_exclusion_established $true
$claims|Add-Member write_authority $true
$claims|Add-Member allZero $true
$claims|Add-Member computer_name 'N2R-WIN11'
$claimed=Assert-IsolatedHostGraph $claims
Check (-not$claimed.writer_exclusion_established-and-not$claimed.write_authority) 'JSON claims widened authority.'

foreach($change in 0..17) {
    $bad=Copy-Graph $good
    switch($change) {
        0{$bad.vm.id=$p.old_vm_id} 1{$bad.vm.name='ntfs2refs-win11'} 2{$bad.vm.path+='\..'}
        3{$bad.vm.generation=1} 4{$bad.vm.memory_startup_bytes=4GB} 5{$bad.vm.processor_count=2}
        6{$bad.vm.state='Off'} 7{$bad.vm.dynamic_memory_enabled=$true} 8{$bad.vm.network_adapter_count=1}
        9{$bad.vm.checkpoint_count=1} 10{$bad.vm.automatic_checkpoints_enabled=$true}
        11{$bad.vm.tpm_enabled=$false} 12{$bad.vm.secure_boot='Off'} 13{$bad.vm.secure_boot_template='Other'}
        14{$bad.inventory_complete=$false} 15{$bad.inventory_complete='true'}
        16{$bad.schema_version=2} 17{$bad.schema_version='1'}
    }
    Reject {Assert-IsolatedHostGraph $bad} ('Foreign/incomplete VM profile accepted: '+$change)
}
foreach($change in 0..5) {
    $bad=Copy-Graph $good
    switch($change) {
        0{$bad.registered_vm_ids=@($p.old_vm_id)}
        1{$bad.registered_vm_ids+= $p.vm_id.ToUpperInvariant()}
        2{$bad.registered_vm_ids+= [guid]::Empty.ToString('D')}
        3{$bad.registered_vm_ids+= 'missing'}
        4{$bad.references[0].vm_id='12345678-1234-1234-1234-123456789abc'}
        5{$bad.registered_vm_ids=@($p.vm_id)*4097}
    }
    Reject {Assert-IsolatedHostGraph $bad} ('Incomplete/duplicate registered inventory accepted: '+$change)
}
foreach($change in 0..18) {
    $bad=Copy-Graph $good
    switch($change) {
        0{$bad.nodes[2].id='missing'} 1{$bad.nodes[2].id=$bad.nodes[2].id.ToUpperInvariant()}
        2{$bad.nodes[2].volume_root='D:\'} 3{$bad.nodes[2].raw_file_id_hex='0'*32}
        4{$bad.nodes[2].raw_file_id_hex='x'*32} 5{$bad.nodes[2].file_id='0x'+('0'*32)}
        6{$bad.nodes[2].file_id='0x00000000000000000000000000000099'}
        7{$bad.nodes[2].vhd_id=$p.os_vhd_id} 8{$bad.nodes[2].virtual_bytes=64GB}
        9{$bad.nodes[2].logical_sector_bytes=4096} 10{$bad.nodes[2].physical_sector_bytes='4096'}
        11{$bad.nodes[2].reparse_ancestry=$true} 12{$bad.nodes[2].is_directory=$true}
        13{$bad.nodes[2].namespace_identity_pinned=$false} 14{$bad.nodes[2].number_of_links=2}
        15{$bad.nodes[2].parent_id=$bad.nodes[0].id} 16{$bad.nodes[2].parent_id=''}
        17{$bad.nodes[2].PSObject.Properties.Remove('raw_file_id_hex')}
        18{$bad.nodes+= (Copy-Graph $bad.nodes[2])}
    }
    Reject {Assert-IsolatedHostGraph $bad} ('Invalid owned file identity/namespace accepted: '+$change)
}
foreach($path in @('journal.vhdx','D:journal.vhdx','\\server\share\journal.vhdx','D:\a\..\journal.vhdx','D:\a\\journal.vhdx','D:\a\journal.vhdx.','D:\a\journal.vhdx ','D:\a\journal.vhdx:stream','D:\a\NUL.vhdx','D:\a\')) {
    $bad=Copy-Graph $good; $bad.nodes[2].paths=@($path)
    Reject {Assert-IsolatedHostGraph $bad} ('Ambiguous/noncanonical DOS path accepted: '+$path)
}
$bad=With-ForeignLeaf
$bad.nodes[3].paths=@($p.journal_path.ToUpperInvariant())
Reject {Assert-IsolatedHostGraph $bad} 'Two nodes identified the same DOS path.'
$bad=Copy-Graph $good
$bad.nodes[2].number_of_links=2; $bad.nodes[2].paths+= 'D:\alias\journal.vhdx'
Reject {Assert-IsolatedHostGraph $bad} 'Owned hard-link alias was accepted.'
$bad=With-ForeignLeaf
$bad.nodes[3].file_id=$p.journal_file_id
Reject {Assert-IsolatedHostGraph $bad} 'One volume/display ID mapped to different raw file IDs.'
$bad=With-ForeignLeaf
$bad.nodes[3].raw_file_id_hex=$bad.nodes[2].raw_file_id_hex
$bad.nodes[3].id=$bad.nodes[2].id
Reject {Assert-IsolatedHostGraph $bad} 'One raw identity mapped to duplicate nodes/display IDs.'

$copy=With-ForeignLeaf
$copy.nodes[3].vhd_id=$p.journal_vhd_id
$accepted=Assert-IsolatedHostGraph $copy
Check ($accepted.observed_structure_valid-and-not$accepted.writer_exclusion_established) 'Unrelated copied container UUID incorrectly established file aliasing.'
$copy=Fixture
$other=New-Node 3 'E:\independent\journal.vhdx' $otherVolume
$other.file_id=$p.journal_file_id; $other.vhd_id=$p.journal_vhd_id
$copy.nodes+= $other; $copy.references+= (New-Reference $p.old_vm_id $other.id)
Check ((Assert-IsolatedHostGraph $copy).observed_structure_valid) 'Equal raw/display IDs on another volume were treated as aliases.'
$foreignCheckpoint=With-ForeignLeaf
$base=New-Node 200 'D:\protected\base.vhdx'
$base.vhd_id=$p.journal_vhd_id
$foreignCheckpoint.nodes+= $base
$foreignCheckpoint.nodes[3].parent_id=$base.id
$foreignCheckpoint.nodes[3].vhd_id=$p.journal_vhd_id
$foreignCheckpoint.references[3].kind='checkpoint_attachment'
$foreignCheckpoint.references[3].checkpoint_id='12345678-1234-1234-1234-123456789abc'
Check ((Assert-IsolatedHostGraph $foreignCheckpoint).observed_structure_valid) 'Unrelated checkpoint ancestry/copy UUID was mistaken for owned backing.'
$wrongVolume=Copy-Graph $good
$wrongVolume.nodes[2].volume_root=$otherVolume
$wrongVolume.nodes[2].id=$otherVolume.ToLowerInvariant()+'|'+$wrongVolume.nodes[2].raw_file_id_hex
$wrongVolume.references[2].node_id=$wrongVolume.nodes[2].id
Reject {Assert-IsolatedHostGraph $wrongVolume} 'Owned display file ID on a foreign volume passed ownership binding.'

foreach($change in 0..13) {
    $bad=Copy-Graph $good
    switch($change) {
        0{$bad.references=$bad.references[0..1]}
        1{$bad.references+= (New-Reference $p.vm_id $bad.nodes[2].id 3)}
        2{$bad.references[2].controller_type='IDE'} 3{$bad.references[2].controller_number=1}
        4{$bad.references[2].controller_location=3} 5{$bad.references[2].node_id='missing'}
        6{$bad.references[2].kind='unknown'} 7{$bad.references[2].checkpoint_id='12345678-1234-1234-1234-123456789abc'}
        8{$bad.references[2].controller_number=-1} 9{$bad.references[2].controller_location=64}
        10{$bad.references[2].controller_location='2'}
        11{$bad.references+= (Copy-Graph $bad.references[2])}
        12{$bad.references[2].kind='checkpoint_attachment';$bad.references[2].checkpoint_id=[guid]::Empty.ToString('D')}
        13{$bad.references[2].kind='checkpoint_attachment';$bad.references[2].checkpoint_id='12345678-1234-1234-1234-123456789abc'}
    }
    Reject {Assert-IsolatedHostGraph $bad} ('Invalid/missing current reference accepted: '+$change)
}
$foreign=Copy-Graph $good
$foreign.references+= (New-Reference $p.old_vm_id $foreign.nodes[2].id)
Reject {Assert-IsolatedHostGraph $foreign} 'Foreign direct attachment to owned backing accepted.'
$checkpoint=Copy-Graph $good
$ref=New-Reference $p.old_vm_id $checkpoint.nodes[2].id
$ref.kind='checkpoint_attachment';$ref.checkpoint_id='12345678-1234-1234-1234-123456789abc'
$checkpoint.references+= $ref
Reject {Assert-IsolatedHostGraph $checkpoint} 'Foreign checkpoint ownership accepted.'
$parent=With-ForeignLeaf
$parent.nodes[3].parent_id=$parent.nodes[2].id
Reject {Assert-IsolatedHostGraph $parent} 'Foreign child ownership through file-ID parent ancestry accepted.'

$dangling=With-ForeignLeaf
$dangling.nodes[3].parent_id=$p.host_volume_root.ToLowerInvariant()+'|'+('f'*32)
Reject {Assert-IsolatedHostGraph $dangling} 'Dangling parent identity accepted.'
$cycle=With-ForeignLeaf
$a=New-Node 101 'D:\unrelated\parent.vhdx';$a.parent_id=$cycle.nodes[3].id
$cycle.nodes[3].parent_id=$a.id;$cycle.nodes+= $a
Reject {Assert-IsolatedHostGraph $cycle} 'File-ID parent cycle accepted.'
# No reference reaches this malformed extra node; it must still be rejected.
$unreachable=Copy-Graph $good
$a=New-Node 102 'D:\unrelated\unreferenced.vhdx';$a.parent_id=$a.id
$unreachable.nodes+= $a
Reject {Assert-IsolatedHostGraph $unreachable} 'Unreferenced malformed ancestry escaped validation.'
$missing=With-ForeignLeaf
$missing.nodes[3].PSObject.Properties.Remove('parent_id')
Reject {Assert-IsolatedHostGraph $missing} 'Missing parent field accepted as a standalone node.'

$depth=Fixture
$last=$null
for($i=0;$i-lt128;$i++) {
    $a=New-Node (1000+$i) ('D:\depth\'+$i+'.vhdx');$a.parent_id=$last;$depth.nodes+= $a;$last=$a.id
}
$depth.references+= (New-Reference $p.old_vm_id $last)
$deep=Assert-IsolatedHostGraph $depth
Check ($deep.maximum_ancestor_nodes-eq128) 'Exact 128-node ancestor bound was refused.'
$a=New-Node 2000 'D:\depth\too-deep.vhdx';$a.parent_id=$last;$depth.nodes+= $a
$depth.references[3].node_id=$a.id
Reject {Assert-IsolatedHostGraph $depth} 'Ancestor depth greater than 128 accepted.'
$tooMany=Copy-Graph $good;$tooMany.nodes=@($good.nodes[0])*4097
Reject {Assert-IsolatedHostGraph $tooMany} 'Node inventory above 4096 accepted.'
$tooMany=Copy-Graph $good;$tooMany.references=@($good.references[0])*4097
Reject {Assert-IsolatedHostGraph $tooMany} 'Reference inventory above 4096 accepted.'
$omitted=Copy-Graph $good;$omitted.PSObject.Properties.Remove('nodes')
Reject {Assert-IsolatedHostGraph $omitted} 'Missing node inventory accepted.'

[pscustomobject]@{checks=$script:checks;passed=$true;fixture='synthetic host file-identity graphs';
    vm_operations=0;device_operations=0;files_or_images_opened=0;credentials_accessed=0;
    writer_exclusion_established=$false;write_authority=$false}
