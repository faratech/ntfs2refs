# New alpha endpoint only. Read-only guest enrollment plus frozen binary staging.
[CmdletBinding()]param([switch]$ResumeAfterCheckpoint)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace='D:\code\ntfs2refs'
$root=Join-Path $workspace '.lab\hyperv\shadow-alpha-20261026'
$manifest=Get-Content -LiteralPath (Join-Path $root 'manifest.json') -Raw|ConvertFrom-Json
$id=[guid]$manifest.vm_id
if($id-ne[guid]'0d9bfa66-c66c-4ead-86b7-e72cb5f7e040'){throw 'Recorded alpha VM differs.'}
$vm=Get-VM -Id $id -ErrorAction Stop
if($vm.Name-cne$manifest.name-or-not$vm.Path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)-or$vm.State.ToString()-cne'Off'){throw 'Offline owned alpha endpoint required.'}
if(Test-Path -LiteralPath (Join-Path $root 'start-intent.json')){throw 'Start was already dispatched; inspect its live state.'}
$capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
Assert-LabCapacity -Capacity $capacity -AdditionalBytes 16GB
if([long](Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory*1024-lt12GB){throw 'Alpha RAM headroom differs.'}
$existing=@(Get-VMSnapshot -VM $vm)
if($ResumeAfterCheckpoint){
    if($existing.Count-ne1-or$existing[0].Id-ne[guid]'946f9082-7ace-4114-ba80-e3a4cd162ef6'-or$existing[0].Name-cne'alpha-imported-clean'){
        throw 'Only the observed completed alpha checkpoint may be resumed.'
    }
}else{
    if($existing.Count){throw 'Inspect existing alpha checkpoints before boot.'}
    Checkpoint-VM -VM $vm -SnapshotName 'alpha-imported-clean'
}
$vm=Get-VM -Id $id
$checkpoint=@(Get-VMSnapshot -VM $vm|Where-Object {$_.Name -ceq 'alpha-imported-clean'})
if($checkpoint.Count-ne1){throw 'Clean alpha checkpoint not established.'}
[pscustomobject]@{vm_id=$id.ToString('D');checkpoint_id=$checkpoint[0].Id.ToString('D');
    state_before='Off';started_utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json|
    Set-Content -LiteralPath (Join-Path $root 'start-intent.json') -Encoding utf8
Start-VM -VM $vm
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$session=$null;$deadline=[DateTime]::UtcNow.AddMinutes(4)
try{
    while($null-eq$session-and[DateTime]::UtcNow-lt$deadline){
        try{$session=New-PSSession -VMId $id -Credential $credential -ErrorAction Stop}
        catch{Start-Sleep -Seconds 3}
    }
    if($null-eq$session){throw 'Alpha PowerShell Direct enrollment unavailable; do not restart the VM.'}
    $ready=Invoke-Command -Session $session -ScriptBlock {
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        $version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $driver=(Get-FileHash -LiteralPath 'C:\Windows\System32\drivers\refs.sys' -Algorithm SHA256).Hash.ToLowerInvariant()
        if($env:COMPUTERNAME-cne'N2R-WIN11'-or$version.CurrentBuild-cne'26300'-or$version.UBR-ne9457-or$driver-cne'3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4'){throw 'Frozen alpha OS/driver profile differs.'}
        if(@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count){throw 'Unknown guest lab worker is active.'}
        $devices=@(Get-CimInstance Win32_DiskDrive)
        [pscustomobject]@{computer_name=$env:COMPUTERNAME;windows_build=[string]$version.CurrentBuild;revision=$version.UBR;
            refs_sha256=$driver;firmware_uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID;
            disks=@(Get-Disk|ForEach-Object {$disk=$_;$device=@($devices|Where-Object {$_.Index -eq $disk.Number});
                [pscustomobject]@{number=$disk.Number;unique_id=[string]$disk.UniqueId;size_bytes=$disk.Size;
                    logical_sector_bytes=$disk.LogicalSectorSize;physical_sector_bytes=$disk.PhysicalSectorSize;
                    partition_style=$disk.PartitionStyle.ToString();partition_count=$disk.NumberOfPartitions;
                    is_boot=$disk.IsBoot;is_system=$disk.IsSystem;is_offline=$disk.IsOffline;is_read_only=$disk.IsReadOnly;
                    scsi_lun=if($device.Count-eq1){$device[0].SCSILogicalUnit}else{$null}}})}
    }
    $ready|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $root 'guest-readiness.json') -Encoding utf8
    $package=Get-Content -LiteralPath (Join-Path $workspace '.lab\alpha\native-shadow-alpha-20261026\alpha.json') -Raw|ConvertFrom-Json
    $guestRoot='C:\ntfs2refs\alpha\native-shadow-alpha-20261026'
    Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock {param($path)
        if(Test-Path -LiteralPath $path){throw 'Fresh alpha staging required.'}
        $null=New-Item -ItemType Directory -Path $path
    }
    foreach($row in $package.executables){
        $path=Join-Path (Join-Path $workspace '.lab\alpha\native-shadow-alpha-20261026\bin') $row.name
        if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()-cne$row.sha256){throw 'Frozen alpha executable changed.'}
        Copy-Item -LiteralPath $path -Destination (Join-Path $guestRoot $row.name) -ToSession $session
    }
    $verified=Invoke-Command -Session $session -ArgumentList $guestRoot,($package.executables|ConvertTo-Json -Compress) -ScriptBlock {
        param($root,$rows)
        foreach($row in ($rows|ConvertFrom-Json)){
            if((Get-FileHash -LiteralPath (Join-Path $root $row.name) -Algorithm SHA256).Hash.ToLowerInvariant()-cne$row.sha256){throw 'Guest executable pin differs.'}
        }
        [pscustomobject]@{guest_root=$root;executable_count=@($rows|ConvertFrom-Json).Count;verified=$true}
    }
    $verified|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $root 'guest-staging.json') -Encoding utf8
    [pscustomobject]@{vm_id=$id.ToString('D');checkpoint_id=$checkpoint[0].Id.ToString('D');readiness=$ready;staging=$verified}|ConvertTo-Json -Depth 8 -Compress
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
