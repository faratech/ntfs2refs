<# Injected providers only. No VM/VHD/fsutil/file pin/device/credential API runs. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'IsolatedBaselineGuards.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IsolatedHostIdentity.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'IsolatedJournalExclusion.psm1') -Force
$script:checks=0
function Check([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$no=$false;try{& $Action|Out-Null}catch{$no=$true};Check $no $Message}
function Fixture([string]$Mode='good') {
    $p=Get-IsolatedBaselinePolicy
    $inventory=[pscustomobject]@{vm=[pscustomobject]@{id=$p.vm_id;name=$p.vm_name;path=$p.vm_path;generation=2;
        processor_count=4;memory_startup_bytes=8GB;state='Running';dynamic_memory_enabled=$false;
        network_adapter_count=0;checkpoint_count=0;automatic_checkpoints_enabled=$false;
        tpm_enabled=$true;secure_boot='On';secure_boot_template='MicrosoftWindows'};
        registered_vm_ids=@($p.vm_id,$p.old_vm_id);references=@()}
    $state=[pscustomobject]@{mode=$Mode;inventory=$inventory;inventory_calls=0;metadata_calls=0;
        opened=0;closed=0;identity_calls=0;identities=@{};metadata=@{};rebound=$false}
    $roles=@('os','target','journal')
    foreach($i in 0..4){
        $path=if($i-lt3){$p.disk_root+'\'+$roles[$i]+'.vhdx'}elseif($i-eq3){'D:\unrelated\leaf.vhdx'}else{'D:\unrelated\parent.vhdx'}
        $id=if($i-lt3){$p.($roles[$i]+'_file_id')}else{'0x'+($i+1).ToString('x32')}
        $state.identities[$path]=[pscustomobject]@{volume_root=$p.host_volume_root;raw_file_id_hex=($i+1).ToString('x32');
            file_id=$id;final_path=($p.host_volume_root+$path.Substring(3));volume_serial_hex='0000000000001234';
            file_bytes=4MB;number_of_links=1;reparse_ancestry=$false;is_directory=$false;
            namespace_identity_pinned=$true;content_immutable=$false;denies_host_writers=$false}
        $state.metadata[$path]=[pscustomobject]@{vhd_id=$(if($i-lt3){$p.($roles[$i]+'_vhd_id')}else{$p.journal_vhd_id});
            virtual_bytes=$(if($i-eq2){8GB}else{64GB});logical_sector_bytes=512;physical_sector_bytes=4096;
            parent_path=$(if($i-eq3){'D:\unrelated\parent.vhdx'}else{''})}
        if($i-lt4){$inventory.references += [pscustomobject]@{vm_id=$(if($i-lt3){$p.vm_id}else{$p.old_vm_id});
            kind='current_attachment';checkpoint_id=$null;path=$path;controller_type='SCSI';controller_number=0;
            controller_location=$(if($i-lt3){$i}else{0})}}
    }
    if($Mode-ceq'alias-parent'){$state.metadata['D:\unrelated\leaf.vhdx'].parent_path=$p.journal_path}
    if($Mode-ceq'cycle'){$state.metadata['D:\unrelated\parent.vhdx'].parent_path='D:\unrelated\leaf.vhdx'}
    $provider=[pscustomobject]@{
        inventory={
            $state.inventory_calls++
            if($state.mode-ceq'inventory-change'-and$state.inventory_calls-eq2){$state.inventory.vm.processor_count=5}
            $state.inventory|ConvertTo-Json -Depth 16|ConvertFrom-Json
        }.GetNewClosure()
        pin={param($path)
            if($state.mode-ceq'open-failure'-and$path.EndsWith('journal.vhdx')){throw 'Synthetic open refused.'}
            $state.opened++
            [pscustomobject]@{closed=$false;path=$path;held=($state.identities[$path]|ConvertTo-Json|ConvertFrom-Json)}
        }.GetNewClosure()
        identity={param($pin,$path)
            if($pin.closed){throw 'Synthetic pin is closed.'}
            $state.identity_calls++
            $out=$pin.held|ConvertTo-Json|ConvertFrom-Json
            if($state.mode-ceq'identity-change'-and$state.identity_calls-eq2){$out.number_of_links=2}
            $out
        }.GetNewClosure()
        metadata={param($path)
            $state.metadata_calls++
            if($state.mode-ceq'metadata-failure'-and$state.metadata_calls-eq3){throw 'Synthetic metadata error.'}
            if($state.mode-ceq'path-rebind'-and-not$state.rebound){
                $state.rebound=$true;$state.identities[$path].raw_file_id_hex='f'*32
            }
            $state.metadata[$path]|ConvertTo-Json|ConvertFrom-Json
        }.GetNewClosure()
        close={param($pin)
            if($pin.closed){throw 'Synthetic double close.'};$pin.closed=$true;$state.closed++
        }.GetNewClosure()
    }
    [pscustomobject]@{state=$state;provider=$provider}
}
$f=Fixture
$native=[pscustomobject]@{VolumeGuidRoot='\\?\Volume{fcccb0cc-ddbb-46a4-ab61-ab5f91c889ca}\';
    RawFileIdHex='0x'+('ab'*16);CanonicalFinalPath='\\?\Volume{fcccb0cc-ddbb-46a4-ab61-ab5f91c889ca}\test';
    VolumeSerialHex='0x0000000000001234';FileLength=4MB;HardLinkCount=1;NoReparseObserved=$true;
    Directory=$false;NamespaceIdentityPinned=$true;ContentImmutable=$false;DeniesHostWriters=$false}
$normalized=& (Get-Module IsolatedHostIdentity) {param($value) ConvertFrom-IsolatedNativeIdentity $value @('File ID is 0x000000000007c9c40000000000000010')} $native
Check ($normalized.raw_file_id_hex -ceq ('ab'*16) -and $normalized.file_id -ceq'0x000000000007c9c40000000000000010') 'Native/display IDs were conflated or prefix not normalized.'
Reject {& (Get-Module IsolatedHostIdentity) {param($value) ConvertFrom-IsolatedNativeIdentity $value @('no identity')} $native} 'Missing display identity accepted.'
$lease=Get-IsolatedHostIdentityLease -Provider $f.provider
Check ($lease.snapshot.nodes.Count-eq5-and$lease.snapshot.references.Count-eq4) 'Complete ancestor identity graph was not collected.'
$parent=@($lease.snapshot.nodes|Where-Object {$_.paths[0]-ceq'D:\unrelated\parent.vhdx'})[0]
$child=@($lease.snapshot.nodes|Where-Object {$_.paths[0]-ceq'D:\unrelated\leaf.vhdx'})[0]
Check ($child.parent_id-ceq$parent.id) 'Parent edge used a path instead of its actual file identity.'
Check (-not$lease.writer_exclusion_established-and-not$lease.write_authority) 'Identity collection granted exclusion or writes.'
Check (($f.state.opened-$f.state.closed)-eq5) 'Held identity pins were lost or temporary reopens leaked.'
$null=Test-IsolatedHostIdentityLease $lease
Check (($f.state.opened-$f.state.closed)-eq5) 'Revalidation leaked reopened paths.'
$contract=Get-IsolatedJournalExclusionContract
Check (-not$contract.backend_available-and-not$contract.zero_scan_permitted-and-not$contract.durable_exclusion_established) 'Missing native fence advertised as available.'
foreach($claim in @($null,[pscustomobject]@{enforced=$true;host=$true;guest=$true;durable=$true;allZero=$true},'signed-looking-token')){
    Reject {Assert-IsolatedJournalExclusion $lease $null $claim} 'A serialized fence claim authorized scanning.'
}
Close-IsolatedHostIdentityLease $lease
Check ($f.state.opened-eq$f.state.closed) 'Identity handles leaked on close.'
Close-IsolatedHostIdentityLease $lease
Check ($f.state.opened-eq$f.state.closed) 'Idempotent close changed handle counts.'
Reject {Test-IsolatedHostIdentityLease $lease} 'Closed host identity pin was reusable.'
Reject {Assert-IsolatedJournalExclusion $lease $null $null} 'Closed lease authorized scanning.'
foreach($mode in @('open-failure','metadata-failure','identity-change','inventory-change','path-rebind','alias-parent','cycle')){
    $bad=Fixture $mode
    Reject {Get-IsolatedHostIdentityLease -Provider $bad.provider} ('Collector accepted '+$mode)
    Check ($bad.state.opened-eq$bad.state.closed) ('Collector leaked pins after '+$mode)
}
foreach($file in @('IsolatedHostIdentity.psm1','IsolatedJournalExclusion.psm1','Read-IsolatedJournalPrerequisite.ps1')){
    $errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $file),[ref]$null,[ref]$errors)
    Check ($errors.Count-eq0) ('Source syntax failed: '+$file)
}
[pscustomobject]@{checks=$script:checks;passed=$true;fixture='injected in-memory identity providers';
    vm_operations=0;native_file_opens=0;device_operations=0;credentials_accessed=0;writer_exclusion_established=$false}
