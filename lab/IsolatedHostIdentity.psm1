# Read-only source implementation. Importing operates no VM or native handle.
# Captured file/ancestry identities are observations, never a storage write fence.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Get-IsolatedNativeInventory {
    Import-Module Hyper-V -ErrorAction Stop
    Import-Module (Join-Path $PSScriptRoot 'IsolatedBaselineGuards.psm1') -Force
    $policy=Get-IsolatedBaselinePolicy
    $machines=@(Get-VM -ErrorAction Stop)
    if($machines.Count -gt 512){throw 'Registered VM inventory exceeds budget.'}
    $owned=@($machines|Where-Object {$_.Id.ToString('D') -ceq $policy.vm_id})
    if($owned.Count -ne 1){throw 'Exact isolated VM is absent or ambiguous.'}
    $references=[Collections.Generic.List[object]]::new()
    foreach($machine in $machines){
        $id=$machine.Id.ToString('D')
        foreach($disk in @(Get-VMHardDiskDrive -VM $machine -ErrorAction Stop)){
            if([string]::IsNullOrEmpty([string]$disk.Path)){throw 'Unmodelled passthrough/empty registered disk route.'}
            $references.Add([pscustomobject]@{vm_id=$id;kind='current_attachment';checkpoint_id=$null;
                path=[string]$disk.Path;controller_type=$disk.ControllerType.ToString();
                controller_number=[int]$disk.ControllerNumber;controller_location=[int]$disk.ControllerLocation})
            if($references.Count -gt 4096){throw 'Registered reference budget exceeded.'}
        }
        foreach($snapshot in @(Get-VMSnapshot -VM $machine -ErrorAction Stop)){
            foreach($disk in @(Get-VMHardDiskDrive -VMSnapshot $snapshot -ErrorAction Stop)){
                if([string]::IsNullOrEmpty([string]$disk.Path)){throw 'Unmodelled checkpoint disk route.'}
                $references.Add([pscustomobject]@{vm_id=$id;kind='checkpoint_attachment';checkpoint_id=$snapshot.Id.ToString('D');
                    path=[string]$disk.Path;controller_type=$disk.ControllerType.ToString();
                    controller_number=[int]$disk.ControllerNumber;controller_location=[int]$disk.ControllerLocation})
                if($references.Count -gt 4096){throw 'Registered reference budget exceeded.'}
            }
        }
        if($references.Count -gt 4096){throw 'Registered reference budget exceeded.'}
    }
    $vm=$owned[0]
    $memory=Get-VMMemory -VM $vm -ErrorAction Stop
    $processor=Get-VMProcessor -VM $vm -ErrorAction Stop
    $firmware=Get-VMFirmware -VM $vm -ErrorAction Stop
    $security=Get-VMSecurity -VM $vm -ErrorAction Stop
    [pscustomobject]@{
        vm=[pscustomobject]@{id=$policy.vm_id;name=[string]$vm.Name;path=[string]$vm.Path;
            generation=[int]$vm.Generation;processor_count=[int]$processor.Count;
            memory_startup_bytes=[long]$memory.Startup;dynamic_memory_enabled=[bool]$memory.DynamicMemoryEnabled;
            state=$vm.State.ToString();network_adapter_count=@(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop).Count;
            checkpoint_count=@(Get-VMSnapshot -VM $vm -ErrorAction Stop).Count;
            automatic_checkpoints_enabled=[bool]$vm.AutomaticCheckpointsEnabled;
            tpm_enabled=[bool]$security.TpmEnabled;secure_boot=$firmware.SecureBoot.ToString();
            secure_boot_template=[string]$firmware.SecureBootTemplate}
        registered_vm_ids=@($machines|ForEach-Object {$_.Id.ToString('D')}|Sort-Object)
        references=@($references|Sort-Object vm_id,kind,checkpoint_id,controller_type,controller_number,controller_location,path)
    }
}

function New-IsolatedHostProvider {
    [pscustomobject]@{
        inventory={ & (Get-Module IsolatedHostIdentity) { Get-IsolatedNativeInventory } }
        pin={param($path)
            if(-not ('Ntfs2RefsResearch.IsolatedHostFileIdentity' -as [type])){
                Add-Type -Path (Join-Path (Get-Module IsolatedHostIdentity).ModuleBase 'host/IsolatedHostFileIdentity.Windows.cs')
            }
            [Ntfs2RefsResearch.IsolatedHostFileIdentity]::Open($path)
        }
        identity={param($pin,$path)
            $native=$pin.Revalidate()
            $lines=@(& fsutil.exe file queryfileid $path)
            if($LASTEXITCODE -ne 0){throw 'Independent fsutil file-ID query failed.'}
            & (Get-Module IsolatedHostIdentity) {param($value,$display) ConvertFrom-IsolatedNativeIdentity $value $display} $native $lines
        }
        metadata={param($path)
            $vhd=Get-VHD -Path $path -ErrorAction Stop
            [pscustomobject]@{vhd_id=([guid]$vhd.DiskIdentifier).ToString('D');virtual_bytes=[long]$vhd.Size;
                logical_sector_bytes=[int]$vhd.LogicalSectorSize;physical_sector_bytes=[int]$vhd.PhysicalSectorSize;
                parent_path=[string]$vhd.ParentPath}
        }
        close={param($pin) $pin.Dispose()}
    }
}

function ConvertFrom-IsolatedNativeIdentity($Native,[string[]]$DisplayLines) {
    $identityMatches=[regex]::Matches(($DisplayLines -join "`n"),'0x[0-9a-fA-F]{32}')
    if($identityMatches.Count -ne 1 -or $Native.RawFileIdHex -cnotmatch '\A0x[0-9a-f]{32}\z'){
        throw 'Unambiguous native and display file identities required.'
    }
    # Prefix normalization only. Never equate native byte order with fsutil's
    # numeric display order; both were obtained under the same held path pins.
    [pscustomobject]@{volume_root=$Native.VolumeGuidRoot;raw_file_id_hex=$Native.RawFileIdHex.Substring(2);
        file_id=$identityMatches[0].Value.ToLowerInvariant();final_path=$Native.CanonicalFinalPath;
        volume_serial_hex=$Native.VolumeSerialHex;file_bytes=$Native.FileLength;
        number_of_links=$Native.HardLinkCount;reparse_ancestry=(-not $Native.NoReparseObserved);
        is_directory=$Native.Directory;namespace_identity_pinned=$Native.NamespaceIdentityPinned;
        content_immutable=$Native.ContentImmutable;denies_host_writers=$Native.DeniesHostWriters}
}

function Get-IsolatedInventoryFingerprint($Inventory) {
    $normalized=[ordered]@{vm=$Inventory.vm;registered_vm_ids=@($Inventory.registered_vm_ids|Sort-Object);
        references=@($Inventory.references|Sort-Object vm_id,kind,checkpoint_id,controller_type,controller_number,controller_location,path)}
    $bytes=[Text.Encoding]::UTF8.GetBytes(($normalized|ConvertTo-Json -Depth 16 -Compress))
    $sha=[Security.Cryptography.SHA256]::Create()
    try{[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
}
function Get-IsolatedIdentityKey($Identity) {
    ([string]$Identity.volume_root).ToLowerInvariant()+'|'+[string]$Identity.raw_file_id_hex
}
function Assert-IsolatedSameIdentity($Before,$After) {
    foreach($field in @('volume_root','raw_file_id_hex','file_id','final_path','volume_serial_hex',
        'number_of_links','reparse_ancestry','is_directory','namespace_identity_pinned')){
        if($Before.$field -cne $After.$field){throw ('Observed held/path identity changed: '+$field)}
    }
    # Running dynamic OS backing length may change. It is observed, not immutable.
}

function Close-IsolatedHostIdentityLease($Lease) {
    if($null -eq $Lease -or $Lease.closed){return}
    $Lease.closed=$true
    $errors=[Collections.Generic.List[string]]::new()
    for($i=$Lease.pins.Count-1;$i -ge 0;$i--){
        try{& $Lease.provider.close $Lease.pins[$i].pin|Out-Null}catch{$errors.Add($_.Exception.Message)}
    }
    if($errors.Count -gt 0){throw ('Host identity pin cleanup failed: '+($errors -join '; '))}
}

function Get-IsolatedHostIdentityLease {
    param($Provider)
    if($null -eq $Provider){$Provider=New-IsolatedHostProvider}
    foreach($method in @('inventory','pin','identity','metadata','close')){
        if($Provider.$method -isnot [scriptblock]){throw 'Complete bounded identity provider required.'}
    }
    $lease=[pscustomobject]@{provider=$Provider;pins=[Collections.Generic.List[object]]::new();
        snapshot=$null;closed=$false;writer_exclusion_established=$false;write_authority=$false}
    try{
        $before=& $Provider.inventory
        $fingerprint=Get-IsolatedInventoryFingerprint $before
        $nodes=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
        $paths=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
        $stack=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        function Visit-IsolatedBacking([string]$Path,[int]$Depth){
            if($Depth -ge 128){throw 'VHD ancestor depth budget exceeded.'}
            if($paths.ContainsKey($Path)){
                $id=$paths[$Path];if($stack.Contains($id)){throw 'VHD ancestor cycle by file identity.'};return $id
            }
            if($lease.pins.Count -ge 4096){throw 'Host file pin budget exceeded.'}
            $pin=& $Provider.pin $Path
            $held=[pscustomobject]@{pin=$pin;path=$Path;identity=$null;metadata=$null}
            $lease.pins.Add($held)
            $identity=& $Provider.identity $pin $Path
            $held.identity=$identity
            $metadata=& $Provider.metadata $Path
            Assert-IsolatedSameIdentity $identity (& $Provider.identity $pin $Path)
            $again=& $Provider.metadata $Path
            if(($metadata|ConvertTo-Json -Depth 8 -Compress) -cne ($again|ConvertTo-Json -Depth 8 -Compress)){
                throw 'VHD parent/geometry observation changed.'
            }
            $held.metadata=$metadata
            $id=Get-IsolatedIdentityKey $identity
            if($stack.Contains($id)){throw 'VHD ancestor cycle through a file alias.'}
            $paths.Add($Path,$id)
            if($nodes.ContainsKey($id)){
                $node=$nodes[$id]
                if($node.file_id -cne $identity.file_id -or $node.meta_fingerprint -cne ($metadata|ConvertTo-Json -Depth 8 -Compress)){
                    throw 'Aliased host identity has inconsistent VHD observations.'
                }
                $node.paths+= $Path
                return $id
            }
            $node=[pscustomobject]@{id=$id;volume_root=$identity.volume_root;raw_file_id_hex=$identity.raw_file_id_hex;
                file_id=$identity.file_id;paths=@($Path);number_of_links=$identity.number_of_links;
                reparse_ancestry=$identity.reparse_ancestry;is_directory=$identity.is_directory;
                namespace_identity_pinned=$identity.namespace_identity_pinned;
                vhd_id=$metadata.vhd_id;virtual_bytes=$metadata.virtual_bytes;
                logical_sector_bytes=$metadata.logical_sector_bytes;physical_sector_bytes=$metadata.physical_sector_bytes;
                parent_id=$null;meta_fingerprint=($metadata|ConvertTo-Json -Depth 8 -Compress);
                content_immutable=$false;denies_host_writers=$false}
            $nodes.Add($id,$node);$null=$stack.Add($id)
            if(-not [string]::IsNullOrEmpty([string]$metadata.parent_path)){
                $node.parent_id=Visit-IsolatedBacking $metadata.parent_path ($Depth+1)
            }
            $null=$stack.Remove($id)
            $id
        }
        $references=[Collections.Generic.List[object]]::new()
        foreach($reference in @($before.references)){
            if($references.Count -ge 4096){throw 'Host reference budget exceeded.'}
            $id=Visit-IsolatedBacking $reference.path 0
            $references.Add([pscustomobject]@{vm_id=$reference.vm_id;kind=$reference.kind;checkpoint_id=$reference.checkpoint_id;
                node_id=$id;controller_type=$reference.controller_type;controller_number=$reference.controller_number;
                controller_location=$reference.controller_location})
        }
        $after=& $Provider.inventory
        if((Get-IsolatedInventoryFingerprint $after) -cne $fingerprint){throw 'VM/reference observations changed during host collection.'}
        $lease.snapshot=[pscustomobject]@{schema_version=1;kind='isolated-host-file-graph';vm=$before.vm;
            registered_vm_ids=@($before.registered_vm_ids);inventory_complete=$true;
            nodes=@($nodes.Values|Sort-Object id);references=@($references);
            inventory_fingerprint_before=$fingerprint;inventory_fingerprint_after=$fingerprint;
            observations_match=$true;writer_exclusion_established=$false;write_authority=$false}
        Test-IsolatedHostIdentityLease $lease|Out-Null
        $lease
    }catch{
        $original=$_
        try{Close-IsolatedHostIdentityLease $lease}catch{throw ('Host collection and cleanup failed: '+$original.Exception.Message+'; '+$_.Exception.Message)}
        throw $original
    }
}

function Test-IsolatedHostIdentityLease($Lease) {
    if($null -eq $Lease -or $Lease.closed){throw 'Host identity lease is closed or absent.'}
    foreach($held in $Lease.pins){
        Assert-IsolatedSameIdentity $held.identity (& $Lease.provider.identity $held.pin $held.path)
        $fresh=& $Lease.provider.pin $held.path
        try{Assert-IsolatedSameIdentity $held.identity (& $Lease.provider.identity $fresh $held.path)}
        finally{& $Lease.provider.close $fresh|Out-Null}
        if(($held.metadata|ConvertTo-Json -Depth 8 -Compress) -cne ((& $Lease.provider.metadata $held.path)|ConvertTo-Json -Depth 8 -Compress)){
            throw 'VHD edge changed while identity pins were held.'
        }
    }
    $now=& $Lease.provider.inventory
    if((Get-IsolatedInventoryFingerprint $now) -cne $Lease.snapshot.inventory_fingerprint_before){throw 'VM inventory changed while pins were held.'}
    Import-Module (Join-Path $PSScriptRoot 'IsolatedHostGraph.psm1') -Force
    Assert-IsolatedHostGraph $Lease.snapshot
}

Export-ModuleMember -Function New-IsolatedHostProvider,Get-IsolatedHostIdentityLease,Test-IsolatedHostIdentityLease,Close-IsolatedHostIdentityLease
