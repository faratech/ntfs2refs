# Fresh owned RAW data disks only. No formatting or source/VM restoration.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$m=Get-Content -LiteralPath (Join-Path $root 'manifest.json') -Raw|ConvertFrom-Json
$vm=Get-VM -Id $m.vm_id
if($vm.Id-ne[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'-or$vm.Name-cne'ntfs2refs-streaming-v2-20261027'-or$vm.State.ToString()-cne'Running'-or
    -not$vm.Path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)-or@(Get-VMHardDiskDrive -VM $vm).Count-ne1){throw 'Fresh owned OS-only VM required.'}
if(Test-Path -LiteralPath (Join-Path $root 'media-intent.json')){throw 'Media already has intent; inspect partial state.'}
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 64MB
$specs=@(@{role='source';name='source.vhdx';bytes=64GB;slot=1},@{role='journal';name='journal.vhdx';bytes=8GB;slot=2},@{role='shadow';name='shadow.vhdx';bytes=64GB;slot=4})
@{vm_id=$m.vm_id;media=$specs;formatting=$false;utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $root 'media-intent.json') -Encoding utf8
$created=@(foreach($spec in $specs){
    $path=Join-Path $root ('disks\'+$spec.name)
    if(Test-Path -LiteralPath $path){throw 'Fresh data path required.'}
    New-VHD -Path $path -Dynamic -SizeBytes $spec.bytes -BlockSizeBytes 2MB -LogicalSectorSizeBytes 512 -PhysicalSectorSizeBytes 4096 -ErrorAction Stop|Out-Null
    Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -ControllerNumber 0 -ControllerLocation $spec.slot -Path $path -ErrorAction Stop
    $vhd=Get-VHD -Path $path
    if($vhd.ParentPath-or$vhd.Size-ne$spec.bytes){throw 'Fresh independent data media differs.'}
    [pscustomobject]@{role=$spec.role;path=$path;slot=$spec.slot;virtual_bytes=$vhd.Size;file_bytes=$vhd.FileSize;vhd_id=[string]$vhd.DiskIdentifier;parent_path=$vhd.ParentPath}
})
$created|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $root 'media.json') -Encoding utf8
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$s=New-PSSession -VMId $vm.Id -Credential $credential
try{
    $actual=Invoke-Command -Session $s -ScriptBlock {
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        $deadline=[DateTime]::UtcNow.AddMinutes(2)
        do{$disks=@(Get-Disk);if($disks.Count-eq4){break};Start-Sleep -Seconds 2}while([DateTime]::UtcNow-lt$deadline)
        if($disks.Count-ne4){throw 'Expected four enrolled disks; do not initialize.'}
        $devices=@(Get-CimInstance Win32_DiskDrive)
        @(foreach($disk in $disks|Sort-Object Number){
            $device=@($devices|Where-Object {$_.Index-eq$disk.Number})
            if($device.Count-ne1){throw 'Disk/LUN mapping incomplete.'}
            [pscustomobject]@{number=$disk.Number;unique_id=$disk.UniqueId;guid=$disk.Guid;bytes=$disk.Size;partition_style=$disk.PartitionStyle.ToString();partitions=$disk.NumberOfPartitions;
                is_boot=$disk.IsBoot;is_system=$disk.IsSystem;offline=$disk.IsOffline;read_only=$disk.IsReadOnly;logical_sector=$disk.LogicalSectorSize;physical_sector=$disk.PhysicalSectorSize;lun=$device[0].SCSILogicalUnit}
        })
    }
    $data=@($actual|Where-Object {$_.number-ne0})
    if($data.Count-ne3-or@($data|Where-Object {$_.partition_style-cne'RAW'-or$_.partitions-ne0-or$_.is_boot-or$_.is_system-or$_.offline-or$_.read_only-or$_.logical_sector-ne512-or$_.physical_sector-ne4096}).Count){throw 'RAW data enrollment refused.'}
    foreach($spec in $specs){$row=@($data|Where-Object {$_.lun-eq$spec.slot});if($row.Count-ne1-or$row[0].bytes-ne$spec.bytes){throw 'Data role/LUN differs.'}}
    $actual|ConvertTo-Json -Depth 7|Set-Content -LiteralPath (Join-Path $root 'raw-enrollment.json') -Encoding utf8
    [pscustomobject]@{vm_id=$m.vm_id;raw_data_disks=$data;formatted=$false}|ConvertTo-Json -Depth 8 -Compress
}finally{Remove-PSSession $s}
