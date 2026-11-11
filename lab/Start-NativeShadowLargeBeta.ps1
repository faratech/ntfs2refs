# Boot/enroll only the newly provisioned beta and stage pinned candidate binaries.
[CmdletBinding()]param([switch]$ResumeAfterCheckpoint)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace='D:\code\ntfs2refs'
$root=Join-Path $workspace '.lab\hyperv\shadow-large-beta-20261027'
$manifest=Get-Content -LiteralPath (Join-Path $root 'manifest.json') -Raw|ConvertFrom-Json
$id=[guid]$manifest.vm_id
if($id-ne[guid]'6c4793d2-cdee-468b-bf3b-1c11cae0b501'){throw 'Beta VM identity differs.'}
$vm=Get-VM -Id $id -ErrorAction Stop
if($vm.Name-cne$manifest.name-or-not$vm.Path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)-or$vm.State.ToString()-cne'Off'){
    throw 'Owned offline beta required.'
}
foreach($file in @('start-intent.json','clean-checkpoint.json','guest-readiness.json')){
    if(Test-Path -LiteralPath (Join-Path $root $file)){throw 'Beta start/enrollment already has state; inspect before any retry.'}
}
function Save([string]$Name,$Value){
    $stream=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 16GB
if([long](Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory*1024-lt8GB){throw 'Beta needs 4 GiB RAM plus 4 GiB host headroom.'}
if(@(Get-VMNetworkAdapter -VM $vm).Count-or$vm.MemoryStartup-ne4GB){throw 'Beta resources differ.'}
if($ResumeAfterCheckpoint){
    $observed=@(Get-VMSnapshot -VM $vm)
    if(-not(Test-Path -LiteralPath (Join-Path $root 'checkpoint-intent.json'))-or$observed.Count-ne1-or
        $observed[0].Id-ne[guid]'971ecdc3-8eca-4abb-a77e-e028e7e54f7f'-or$observed[0].Name-cne'beta-imported-clean'-or
        $vm.ParentSnapshotId-ne$observed[0].Id){throw 'Observed completed beta checkpoint differs.'}
    Save 'checkpoint-publication-recovery.json' ([pscustomobject]@{vm_id=$id.ToString('D');checkpoint_id=$observed[0].Id.ToString('D');
        previous_controller_exit=1;reason='Initial checkpoint enumeration was empty; actual checkpoint is now registered and VM remains off.';utc=[DateTime]::UtcNow.ToString('o')})
}else{
    if((Test-Path -LiteralPath (Join-Path $root 'checkpoint-intent.json'))-or@(Get-VMSnapshot -VM $vm).Count){throw 'Checkpoint preparation already has state.'}
    Save 'checkpoint-intent.json' ([pscustomobject]@{vm_id=$id.ToString('D');name='beta-imported-clean';state='Off';utc=[DateTime]::UtcNow.ToString('o')})
    Checkpoint-VM -VM $vm -SnapshotName 'beta-imported-clean'
}
$checkpoint=@(Get-ExactLabCheckpoint -VM $vm -Name 'beta-imported-clean')
if($checkpoint.Count-ne1){throw 'Exact beta clean checkpoint not established.'}
$chains=@(Get-VMHardDiskDrive -VM $vm|ForEach-Object {
    $drive=$_;$cursor=$drive.Path;$parents=@();$count=0
    do{
        if(-not [IO.Path]::GetFullPath($cursor).StartsWith((Join-Path $root 'disks')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Beta backing ancestry escaped.'}
        $vhd=Get-VHD -Path $cursor
        $parents+=[pscustomobject]@{path=$cursor;id=$vhd.DiskIdentifier.ToString();virtual_bytes=$vhd.Size;file_bytes=$vhd.FileSize;parent=$vhd.ParentPath}
        $cursor=$vhd.ParentPath;$count++
        if($count-gt8){throw 'Unexpected beta backing depth.'}
    }while($cursor)
    [pscustomobject]@{controller_location=$drive.ControllerLocation;chain=$parents}
})
Save 'clean-checkpoint.json' ([pscustomobject]@{vm_id=$id.ToString('D');checkpoint_id=$checkpoint[0].Id.ToString('D');state='Off';chains=$chains})
$names=@('ntfs2refs.exe','ntfs2refs-bind.exe','ntfs2refs-recover.exe')
$pins=@($names|ForEach-Object {
    $path=Join-Path $workspace ('target\release\'+$_)
    [pscustomobject]@{name=$_;path=$path;bytes=(Get-Item -LiteralPath $path).Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
})
$commit=(& git -C $workspace rev-parse HEAD).Trim()
$patch=(& git -C $workspace diff --binary -- src crates Cargo.toml Cargo.lock rust-toolchain.toml)-join"`n"
$patchHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($patch))).ToLowerInvariant()
Save 'candidate-pins.json' ([pscustomobject]@{source_commit=$commit;working_tree_patch_sha256=$patchHash;working_tree_clean=($patch.Length-eq0);binaries=$pins;native_qualified=$false})
Save 'start-intent.json' ([pscustomobject]@{vm_id=$id.ToString('D');checkpoint_id=$checkpoint[0].Id.ToString('D');utc=[DateTime]::UtcNow.ToString('o')})
Start-VM -VM $vm
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$session=$null;$deadline=[DateTime]::UtcNow.AddMinutes(4)
try{
    while($null-eq$session-and[DateTime]::UtcNow-lt$deadline){
        try{$session=New-PSSession -VMId $id -Credential $credential -ErrorAction Stop}catch{Start-Sleep -Seconds 3}
    }
    if($null-eq$session){throw 'Beta PowerShell Direct unavailable; inspect the running VM, do not restart.'}
    $ready=Invoke-Command -Session $session -ScriptBlock {
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        $version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $driver=(Get-FileHash -LiteralPath 'C:\Windows\System32\drivers\refs.sys' -Algorithm SHA256).Hash.ToLowerInvariant()
        if($env:COMPUTERNAME-cne'N2R-WIN11'-or$version.CurrentBuild-cne'26300'-or$version.UBR-ne9457-or$driver-cne'3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4'){throw 'Beta OS/driver differs.'}
        if(@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count){throw 'Unknown guest lab worker active.'}
        $devices=@(Get-CimInstance Win32_DiskDrive)
        [pscustomobject]@{computer_name=$env:COMPUTERNAME;windows_build=[string]$version.CurrentBuild;revision=$version.UBR;refs_sha256=$driver;
            firmware_uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID;
            disks=@(Get-Disk|ForEach-Object {$disk=$_;$device=@($devices|Where-Object {$_.Index-eq$disk.Number});
                if($device.Count-ne1){throw 'Ambiguous beta disk route.'}
                [pscustomobject]@{number=$disk.Number;unique_id=[string]$disk.UniqueId;size_bytes=$disk.Size;logical_sector_bytes=$disk.LogicalSectorSize;
                    physical_sector_bytes=$disk.PhysicalSectorSize;partition_style=$disk.PartitionStyle.ToString();partition_count=$disk.NumberOfPartitions;
                    is_boot=$disk.IsBoot;is_system=$disk.IsSystem;is_offline=$disk.IsOffline;is_read_only=$disk.IsReadOnly;scsi_lun=$device[0].SCSILogicalUnit}})}
    }
    Save 'guest-readiness.json' $ready
    $stage='C:\ntfs2refs\beta\large-20261027'
    Invoke-Command -Session $session -ArgumentList $stage -ScriptBlock {param($Stage)if(Test-Path -LiteralPath $Stage){throw 'Fresh beta stage required.'};$null=New-Item -ItemType Directory -Path $Stage}
    foreach($pin in $pins){Copy-Item -LiteralPath $pin.path -Destination ($stage+'\'+$pin.name) -ToSession $session}
    $staged=Invoke-Command -Session $session -ArgumentList $stage,($pins|ConvertTo-Json -Compress) -ScriptBlock {
        param($Stage,$Pins);$rows=ConvertFrom-Json -InputObject $Pins
        foreach($row in $rows){$file=Join-Path $Stage $row.name;$hash=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant();
            if($hash-cne$row.sha256-or(Get-Item -LiteralPath $file).Length-ne$row.bytes){throw 'Staged beta binary differs.'};
            [pscustomobject]@{path=$file;sha256=$hash;bytes=$row.bytes}}
    }
    foreach($pin in $pins){if((Get-FileHash -LiteralPath $pin.path -Algorithm SHA256).Hash.ToLowerInvariant()-cne$pin.sha256){throw 'Host binary changed during staging.'}}
    Save 'staging.json' ([pscustomobject]@{vm_id=$id.ToString('D');stage=$stage;files=$staged})
    Write-Output ('Beta running and candidate staged: '+$id.ToString('D'))
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
