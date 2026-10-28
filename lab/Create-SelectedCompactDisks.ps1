# Create only two new thin disposable disks on the preserved OFF branch.
# No boot, format, source access, restore, deletion or checkpoint mutation.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$root=Join-Path $base 'selected-native-alpha-20261028'
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$parent=[guid]'c670839d-00d1-46cf-8544-6aad51bde364'
function Need([bool]$Condition,[string]$Message){if(-not$Condition){throw $Message}}
function Save-New([string]$Name,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
Need (-not(Test-Path -LiteralPath $root)) 'New case already has state; inspect instead of repeating creation.'
$ancestor=Get-Item -LiteralPath $base -Force;while($null -ne $ancestor){Need (-not($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Ordinary lab ancestry required.';$ancestor=$ancestor.Parent}
$manifest=Join-Path $base 'selected-native-alpha-tools-20261028\manifest.json'
Need ((Get-FileHash -LiteralPath $manifest).Hash.ToLowerInvariant() -ceq '6a8a39773268f686b91fc74f29ea56d5dee31dbf5033d1f247bd6ddcf3d1ae81') 'Pinned built toolset required before disk preparation.'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$configuration=Get-LabConfiguration -WorkspaceRoot $workspace;$capacity=Get-LabCapacity -Configuration $configuration
Need ($capacity.MaximumActualBytes -eq 329374052988 -and $capacity.MinimumFreeBytes -eq 17179869184) 'Fixed50GB storage epoch differs.'
Assert-LabCapacity -Capacity $capacity -AdditionalBytes 7GB
$saved=Get-Content -LiteralPath (Join-Path $base 'compact-admitted-recovery-20261028\rollback\preserved-checkpoint.json') -Raw|ConvertFrom-Json
$prior=Get-Content -LiteralPath (Join-Path $base 'compact-admitted-recovery-20261028\rollback\preservation-intent.json') -Raw|ConvertFrom-Json
$allIds=@($prior.old_checkpoint_ids)+@($saved.checkpoint_id)
Need ($saved.success -eq $true -and [guid]$saved.checkpoint_id -eq $parent -and $saved.checkpoint_count -eq 47 -and $allIds.Count -eq 47 -and @($allIds|Sort-Object -Unique).Count -eq 47) 'Complete preserved47 lineage required.'
$vm=Get-VM -Id $id;$snap=@(Get-VMSnapshot -VM $vm);$old=@(Get-VMHardDiskDrive -VM $vm)
Need ($vm.Name -ceq 'ntfs2refs-streaming-v2-20261027' -and $vm.State.ToString() -ceq 'Off' -and $vm.MemoryAssigned -eq 0 -and $vm.ParentSnapshotId -eq $parent -and $vm.MemoryStartup -eq 4GB -and -not$vm.DynamicMemoryEnabled -and @(Get-VMNetworkAdapter -VM $vm).Count -eq 0 -and $snap.Count -eq 47 -and @($allIds|Where-Object {$_ -notin @($snap.Id|ForEach-Object {$_.ToString('D')})}).Count -eq 0) 'Exact OFF preserved isolated VM required.'
Need ($old.Count -eq 4 -and @($old|Where-Object {$_.ControllerType.ToString() -cne 'SCSI' -or $_.ControllerNumber -ne 0 -or $_.ControllerLocation -notin @(0,1,2,4)}).Count -eq 0 -and @($old.ControllerLocation|Sort-Object -Unique).Count -eq 4) 'Original four attachments required; no occupied5/6.'
$original=@($old|ForEach-Object {@{controller_number=$_.ControllerNumber;slot=$_.ControllerLocation;path=$_.Path}})
New-Item -ItemType Directory -Path $root|Out-Null
Save-New 'host-creation-intent.json' @{vm_id=$id.ToString();parent_id=$parent.ToString();checkpoint_ids=$allIds;original_attachments=$original;capacity=$capacity;forecast_bytes=7GB;forecast_is_not_reservation=$true;new_virtual_disk_bytes=80GB;new_actual_disk_space_is_dynamic=$true;boot_or_format_authorized_by_this_script=$false;utc=[DateTime]::UtcNow.ToString('o')}
$created=@()
try{
    foreach($spec in @(@{role='source';slot=5},@{role='shadow';slot=6})){
        $path=Join-Path $root ('selected-'+$spec.role+'.vhdx')
        Need (-not(Test-Path -LiteralPath $path)) 'New virtual disk path already exists.'
        New-VHD -Path $path -Dynamic -SizeBytes 80GB -BlockSizeBytes 2MB -LogicalSectorSizeBytes 512 -PhysicalSectorSizeBytes 4096 -ErrorAction Stop|Out-Null
        $v=Get-VHD -Path $path
        Need ($v.VhdType.ToString() -ceq 'Dynamic' -and $v.Size -eq 80GB -and $v.BlockSize -eq 2MB -and $v.LogicalSectorSize -eq 512 -and $v.PhysicalSectorSize -eq 4096 -and [string]::IsNullOrEmpty($v.ParentPath) -and $v.FileSize -lt 64MB) 'New thin disk geometry/backing differs.'
        $fresh=Get-VM -Id $id;Need ($fresh.State.ToString() -ceq 'Off' -and $fresh.ParentSnapshotId -eq $parent) 'VM changed before attachment.'
        Need (@(Get-VMHardDiskDrive -VM $fresh|Where-Object {$_.ControllerNumber -eq 0 -and $_.ControllerLocation -eq $spec.slot}).Count -eq 0) 'New SCSI slot became occupied.'
        Add-VMHardDiskDrive -VM $fresh -ControllerType SCSI -ControllerNumber 0 -ControllerLocation $spec.slot -Path $path -ErrorAction Stop
        $created+=@{role=$spec.role;slot=$spec.slot;path=$path;disk_identifier=$v.DiskIdentifier.ToString();virtual_bytes=$v.Size;actual_file_bytes=$v.FileSize;logical_sector_bytes=512;physical_sector_bytes=4096;block_bytes=2MB}
        Save-New ('host-created-'+$spec.role+'.json') $created[-1]
    }
    $fresh=Get-VM -Id $id;$after=@(Get-VMHardDiskDrive -VM $fresh)
    Need ($fresh.State.ToString() -ceq 'Off' -and $fresh.MemoryAssigned -eq 0 -and $after.Count -eq 6 -and @(Get-VMSnapshot -VM $fresh).Count -eq 47) 'Final OFF/all47/six attachments required.'
    foreach($item in $original){Need (@($after|Where-Object {$_.ControllerNumber -eq $item.controller_number -and $_.ControllerLocation -eq $item.slot -and $_.Path -ceq $item.path}).Count -eq 1) 'An original attachment changed.'}
    Save-New 'host-created.json' @{success=$true;vm_id=$id.ToString();parent_id=$parent.ToString();checkpoint_ids=$allIds;original_attachments=$original;new_disks=$created;state='Off';memory_assigned=0;source_files_formatted=$false;boot_issued=$false;utc=[DateTime]::UtcNow.ToString('o')}
    Get-Content -LiteralPath (Join-Path $root 'host-created.json') -Raw
}catch{Save-New 'host-creation-failed.json' @{error=$_.Exception.ToString();created=$created;automatic_retry=$false;deletions_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')};throw}
