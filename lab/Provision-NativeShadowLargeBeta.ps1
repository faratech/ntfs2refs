# New disposable beta only. No existing VM/checkpoint/archive is modified.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace='D:\code\ntfs2refs'
$root=Join-Path $workspace '.lab\hyperv\shadow-large-beta-20261027'
$archive='C:\Users\mfara\ntfs2refs-archive\exports\win11-installed-clean\ntfs2refs-win11'
$recordPath=Join-Path $workspace '.lab\hyperv\reference-isolation-approved-20261026T130646790Z\stage2-archive-verification.json'
$name='ntfs2refs-shadow-large-beta-20261027'
$growth=[long]16GB
$protected=@([guid]'eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c',[guid]'8f7fc646-8c9f-41d0-b65a-ecfadccfc36a',[guid]'0d9bfa66-c66c-4ead-86b7-e72cb5f7e040')
function Save([string]$File,$Value){
    $path=Join-Path $root $File
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Observe-Protected {
    @($protected|ForEach-Object {
        $vm=Get-VM -Id $_ -ErrorAction Stop
        [pscustomobject]@{id=$vm.Id.ToString('D');name=$vm.Name;state=$vm.State.ToString();parent_checkpoint=[string]$vm.ParentSnapshotId;
            checkpoints=@(Get-VMSnapshot -VM $vm|ForEach-Object {$_.Id.ToString('D')}|Sort-Object);
            disks=@(Get-VMHardDiskDrive -VM $vm|Sort-Object ControllerNumber,ControllerLocation|ForEach-Object {
                [pscustomobject]@{path=$_.Path;controller=$_.ControllerType.ToString();number=$_.ControllerNumber;location=$_.ControllerLocation}})}
    })
}
if((Test-Path -LiteralPath $root)-or(Get-VM -Name $name -ErrorAction SilentlyContinue)){throw 'Beta provisioning already has state; inspect it and do not redispatch.'}
$record=Get-Content -LiteralPath $recordPath -Raw|ConvertFrom-Json
if(@($record.files).Count-ne6){throw 'Archive inventory differs.'}
$copyBytes=[long]0
foreach($row in $record.files){$copyBytes+=[long]$row.length}
$configuration=Get-LabConfiguration -WorkspaceRoot $workspace
$capacity=Get-LabCapacity -Configuration $configuration
Assert-LabCapacity -Capacity $capacity -AdditionalBytes ($copyBytes+$growth+16MB)
if([long](Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory*1024-lt8GB){throw 'Beta needs 4 GiB RAM plus 4 GiB host headroom.'}
$before=Observe-Protected
$null=New-Item -ItemType Directory -Path $root
Save 'intent.json' ([pscustomobject]@{name=$name;destination=$root;archive=$archive;copy_bytes=$copyBytes;growth_allowance_bytes=$growth;
    free_before_bytes=$capacity.FreeBytes;minimum_free_bytes=$capacity.MinimumFreeBytes;protected_before=$before;
    requested_memory_bytes=4GB;requested_processor_count=4;data_disk_virtual_bytes=256GB;planned_data_partition_bytes=240GB;
    source_cluster_bytes=65536;target_cluster_bytes=4096;guest_storage_changes_performed=$false;
    authorization_basis='Continuing the user-authorized independent Hyper-V conversion work; user freed storage for this copy.';
    started_utc=[DateTime]::UtcNow.ToString('o')})
$handles=[Collections.Generic.List[IO.FileStream]]::new()
try{
    $verified=@()
    foreach($row in $record.files){
        if(-not ([string]$row.path).StartsWith($archive+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected archive source path.'}
        $item=Get-Item -LiteralPath $row.path -Force
        if($item-isnot[IO.FileInfo]-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Regular archive leaf required.'}
        $cursor=$item.Directory
        while($null-ne$cursor){
            if($cursor.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Archive reparse path.'}
            $cursor=$cursor.Parent
        }
        if($item.Length-ne[long]$row.length){throw 'Archive length changed.'}
        $handle=[IO.File]::Open($item.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $handles.Add($handle)
        $hash=(Get-FileHash -InputStream $handle -Algorithm SHA256).Hash.ToLowerInvariant()
        if($hash-cne$row.sha256){throw 'Archive SHA-256 changed.'}
        $verified+=[pscustomobject]@{path=$item.FullName;bytes=$item.Length;sha256=$hash}
    }
    Save 'archive-verification.json' $verified
    $plan=Compare-VM -Path (Join-Path $archive 'Virtual Machines\EDA059B3-6D50-46BB-BDF4-018B99B5B34F.vmcx') `
        -Copy -GenerateNewId -VirtualMachinePath (Join-Path $root 'vm') -VhdDestinationPath (Join-Path $root 'disks') `
        -VhdSourcePath (Join-Path $archive 'Virtual Hard Disks') -SnapshotFilePath (Join-Path $root 'checkpoints') -SmartPagingFilePath (Join-Path $root 'paging')
    if(@($plan.Incompatibilities).Count){throw 'Beta import has compatibility issues; retain the intent and inspect.'}
    $id=[guid]$plan.VM.Id
    if($id-eq[guid]::Empty-or$id-in$protected){throw 'Independent beta ID not established.'}
    Save 'import-intent.json' ([pscustomobject]@{vm_id=$id.ToString('D');name=$name;destination=$root})
    $job=Import-VM -CompatibilityReport $plan -AsJob -ErrorAction Stop
    Save 'import-job.json' ([pscustomobject]@{job_id=$job.Id;instance_id=$job.InstanceId.ToString('D');vm_id=$id.ToString('D');controller_pid=$PID})
    while($job.State-in@('NotStarted','Running')){
        $current=Get-LabCapacity -Configuration $configuration
        if($current.FreeBytes-lt($current.MinimumFreeBytes+$growth)){Stop-Job -Job $job;throw 'Import stopped before reserve/growth margin; preserve partial files.'}
        $null=Wait-Job -Job $job -Timeout 2
    }
    if($job.State-cne'Completed'){throw ('Import terminal state: '+$job.State)}
    $null=Receive-Job -Job $job -ErrorAction Stop
    $vm=Get-VM -Id $id -ErrorAction Stop
    if(-not $vm.Path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)-or$vm.State.ToString()-cne'Off'){throw 'Imported beta endpoint/state differs.'}
    Rename-VM -VM $vm -NewName $name
    Get-VMNetworkAdapter -VM $vm|Remove-VMNetworkAdapter
    Set-VMMemory -VM $vm -DynamicMemoryEnabled $false -StartupBytes 4GB
    Set-VMProcessor -VM $vm -Count 4
    Set-VM -VM $vm -AutomaticCheckpointsEnabled $false -CheckpointType Standard
    Get-VMDvdDrive -VM $vm|Set-VMDvdDrive -Path $null
    $source=@(Get-VMHardDiskDrive -VM $vm|Where-Object {$_.ControllerType.ToString()-ceq'SCSI'-and$_.ControllerNumber-eq0-and$_.ControllerLocation-eq1})
    if($source.Count-ne1-or-not$source[0].Path.StartsWith((Join-Path $root 'disks')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Owned beta data disk not established.'}
    $sourceVhd=Get-VHD -Path $source[0].Path
    if($sourceVhd.ParentPath-or$sourceVhd.Size-ne64GB-or$sourceVhd.VhdType.ToString()-cne'Dynamic'-or
        $sourceVhd.LogicalSectorSize-ne512-or$sourceVhd.PhysicalSectorSize-ne4096){throw 'Beta source disk type, size, geometry or parent differs.'}
    Save 'resize-intent.json' ([pscustomobject]@{vm_id=$id.ToString('D');path=$source[0].Path;old_bytes=64GB;new_bytes=256GB;vm_state='Off'})
    Resize-VHD -Path $source[0].Path -SizeBytes 256GB
    $shadowPath=Join-Path $root 'disks\shadow.vhdx'
    $null=New-VHD -Path $shadowPath -Dynamic -SizeBytes 256GB -BlockSizeBytes 2MB -LogicalSectorSizeBytes 512 -PhysicalSectorSizeBytes 4096
    Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 4 -Path $shadowPath
    $disks=@(Get-VMHardDiskDrive -VM $vm|Sort-Object ControllerNumber,ControllerLocation|ForEach-Object {
        if(-not $_.Path.StartsWith((Join-Path $root 'disks')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Beta backing escaped its own directory.'}
        $vhd=Get-VHD -Path $_.Path
        if($vhd.ParentPath){throw 'Beta backing has a parent.'}
        $fileId=@(fsutil.exe file queryfileid $_.Path)
        if($LASTEXITCODE-ne0){throw 'Beta backing identity query failed.'}
        [pscustomobject]@{path=$_.Path;controller=$_.ControllerType.ToString();controller_number=$_.ControllerNumber;controller_location=$_.ControllerLocation;
            vhd_id=$vhd.DiskIdentifier.ToString();virtual_bytes=$vhd.Size;file_bytes=$vhd.FileSize;parent_path=$vhd.ParentPath;file_id_query=$fileId}
    })
    if($disks.Count-ne4){throw 'Beta disk-role count differs.'}
    $after=Observe-Protected
    if(($before|ConvertTo-Json -Depth 8 -Compress)-cne($after|ConvertTo-Json -Depth 8 -Compress)){throw 'Protected VM state changed during provisioning.'}
    Save 'manifest.json' ([pscustomobject]@{schema_version=1;name=$name;vm_id=$id.ToString('D');root=$root;state='Off';memory_bytes=4GB;processor_count=4;
        network_adapters=@(Get-VMNetworkAdapter -VM $vm).Count;tpm_enabled=(Get-VMSecurity -VM $vm).TpmEnabled;
        secure_boot=(Get-VMFirmware -VM $vm).SecureBoot.ToString();disks=$disks;protected_after=$after;
        source_archive_held_read_only=$true;guest_login_performed=$false;created_utc=[DateTime]::UtcNow.ToString('o')})
    Write-Output ('Beta provisioned OFF: '+$id.ToString('D'))
}finally{foreach($handle in $handles){$handle.Dispose()}}
