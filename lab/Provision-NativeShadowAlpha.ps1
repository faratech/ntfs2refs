# Fresh disposable alpha only. Never reconfigure an existing VM or source archive.
[CmdletBinding()]param([switch]$ResumePreImport)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace='D:\code\ntfs2refs'
$root=Join-Path $workspace '.lab\hyperv\shadow-alpha-20261026'
$archive='C:\Users\mfara\ntfs2refs-archive\exports\win11-installed-clean\ntfs2refs-win11'
$sourceRecord=Join-Path $workspace '.lab\hyperv\reference-isolation-approved-20261026T130646790Z\stage2-archive-verification.json'
$name='ntfs2refs-shadow-alpha-20261026'
$reserve=[long]64GB;$growth=[long]16GB;$copyBytes=[long]18035647136
$protected=@([guid]'eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c',[guid]'8f7fc646-8c9f-41d0-b65a-ecfadccfc36a')
function Save([string]$File,$Value){
    $path=Join-Path $root $File
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 12));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Observe-Protected {
    @($protected|ForEach-Object {
        $vm=Get-VM -Id $_ -ErrorAction Stop
        [pscustomobject]@{id=$vm.Id.ToString('D');name=$vm.Name;state=$vm.State.ToString();
            parent_checkpoint=[string]$vm.ParentSnapshotId;checkpoints=@(Get-VMSnapshot -VM $vm|ForEach-Object {$_.Id.ToString('D')}|Sort-Object);
            disks=@(Get-VMHardDiskDrive -VM $vm|Sort-Object ControllerNumber,ControllerLocation|ForEach-Object {
                [pscustomobject]@{path=$_.Path;controller=$_.ControllerType.ToString();number=$_.ControllerNumber;location=$_.ControllerLocation}})}
    })
}
if(Get-VM -Name $name -ErrorAction SilentlyContinue){throw 'Alpha VM already exists; inspect its recorded operation, never restart provisioning.'}
$resuming=Test-Path -LiteralPath $root
if($resuming){
    if(-not $ResumePreImport -or (Test-Path -LiteralPath (Join-Path $root 'import-intent.json')) -or
        @(Get-ChildItem -LiteralPath $root -Filter '*.vhdx' -File -Recurse).Count){
        throw 'Alpha root has progressed or requires explicit pre-import review; do not retry provisioning.'
    }
    $prior=Get-Content -LiteralPath (Join-Path $root 'intent.json') -Raw|ConvertFrom-Json
    if($prior.name-cne$name-or$prior.destination-cne$root-or$prior.archive-cne$archive){throw 'Pre-import intent differs.'}
}
$capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
Assert-LabCapacity -Capacity $capacity -AdditionalBytes ($copyBytes+$growth)
if($capacity.FreeBytes-$copyBytes-$growth -lt $reserve){throw 'Alpha copy/growth would breach reserve.'}
if([long](Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory*1024 -lt 12GB){throw 'Alpha needs 8 GiB RAM plus 4 GiB free headroom.'}
$before=Observe-Protected
if($before[0].checkpoints.Count-ne50-or$before[0].parent_checkpoint-cne'f6393f52-56ce-4847-bc24-7d5e019ac2e2'-or$before[1].checkpoints.Count-ne0){throw 'Preserved fixture identities changed.'}
$record=Get-Content -LiteralPath $sourceRecord -Raw|ConvertFrom-Json
if(@($record.files).Count-ne6){throw 'Archive verification inventory differs.'}
if(-not $resuming){$null=New-Item -ItemType Directory -Path $root}
$intentName=if($resuming){'resume-preimport-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json'}else{'intent.json'}
Save $intentName ([pscustomobject]@{name=$name;destination=$root;archive=$archive;
    authorization_basis='Direct user priority: frozen native-shadow alpha and end-to-end conversion/recovery tests; independent fresh fixture preserves existing evidence.';
    engine_tag='alpha-native-shadow-20261026';copy_bytes=$copyBytes;growth_allowance_bytes=$growth;
    free_before_bytes=$capacity.FreeBytes;minimum_free_bytes=$reserve;protected_before=$before;started_utc=[DateTime]::UtcNow.ToString('o')})
$handles=[Collections.Generic.List[IO.FileStream]]::new()
try{
    $verified=@()
    foreach($row in $record.files){
        if(-not ([string]$row.path).StartsWith($archive+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected archive source path.'}
        $item=Get-Item -LiteralPath $row.path -Force
        if($item.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Archive reparse leaf.'}
        $cursor=$item.Directory
        while($null-ne$cursor){if($cursor.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Archive reparse ancestry.'};$cursor=$cursor.Parent}
        if($item.Length-ne[long]$row.length){throw 'Archive length changed.'}
        $handle=[IO.File]::Open($item.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $handles.Add($handle)
        $hash=(Get-FileHash -InputStream $handle -Algorithm SHA256).Hash.ToLowerInvariant()
        if($hash-cne$row.sha256){throw 'Fresh archive SHA-256 differs.'}
        $verified+=[pscustomobject]@{path=$item.FullName;bytes=$item.Length;sha256=$hash}
    }
    $verificationName=if($resuming){'archive-verification-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json'}else{'archive-verification.json'}
    Save $verificationName $verified
    $plan=Compare-VM -Path (Join-Path $archive 'Virtual Machines\EDA059B3-6D50-46BB-BDF4-018B99B5B34F.vmcx') `
        -Copy -GenerateNewId -VirtualMachinePath (Join-Path $root 'vm') -VhdDestinationPath (Join-Path $root 'disks') `
        -VhdSourcePath (Join-Path $archive 'Virtual Hard Disks') -SnapshotFilePath (Join-Path $root 'checkpoints') -SmartPagingFilePath (Join-Path $root 'paging')
    if(@($plan.Incompatibilities).Count){throw 'Alpha import requires compatibility changes; preserve the intent.'}
    $id=[guid]$plan.VM.Id
    if($id-eq[guid]::Empty-or$id-in$protected){throw 'Independent alpha VM ID not established.'}
    Save 'import-intent.json' ([pscustomobject]@{vm_id=$id.ToString('D');name=$name;destination=$root})
    $job=Import-VM -CompatibilityReport $plan -AsJob -ErrorAction Stop
    Save 'import-job.json' ([pscustomobject]@{job_id=$job.Id;instance_id=$job.InstanceId.ToString('D');vm_id=$id.ToString('D');controller_pid=$PID})
    while($job.State-in@('NotStarted','Running')){
        $remaining=(Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)).FreeBytes
        if($remaining-lt($reserve+$growth)){Stop-Job -Job $job;throw 'Import stopped before reserve/growth margin; preserve partial files.'}
        $null=Wait-Job -Job $job -Timeout 2
    }
    if($job.State-cne'Completed'){throw ('Import terminal state: '+$job.State)}
    $null=Receive-Job -Job $job -ErrorAction Stop
    $vm=Get-VM -Id $id -ErrorAction Stop
    if(-not $vm.Path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)-or$vm.State.ToString()-cne'Off'){throw 'Imported alpha endpoint/state differs.'}
    Rename-VM -VM $vm -NewName $name
    Get-VMNetworkAdapter -VM $vm|Remove-VMNetworkAdapter
    Set-VMMemory -VM $vm -DynamicMemoryEnabled $false -StartupBytes 8GB
    Set-VMProcessor -VM $vm -Count 4
    Set-VM -VM $vm -AutomaticCheckpointsEnabled $false -CheckpointType Standard
    Get-VMDvdDrive -VM $vm|Set-VMDvdDrive -Path $null
    $shadowPath=Join-Path $root 'disks\shadow.vhdx'
    $null=New-VHD -Path $shadowPath -Dynamic -SizeBytes 64GB -BlockSizeBytes 2MB -LogicalSectorSizeBytes 512 -PhysicalSectorSizeBytes 4096
    Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 4 -Path $shadowPath
    $disks=@(Get-VMHardDiskDrive -VM $vm|Sort-Object ControllerNumber,ControllerLocation|ForEach-Object {
        if(-not $_.Path.StartsWith((Join-Path $root 'disks')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Alpha backing escaped its own disk directory.'}
        $vhd=Get-VHD -Path $_.Path
        if($vhd.ParentPath){throw 'Fresh alpha backing unexpectedly has a parent.'}
        $fileId=@(fsutil.exe file queryfileid $_.Path)
        if($LASTEXITCODE-ne0){throw 'Alpha host backing identity query failed.'}
        [pscustomobject]@{path=$_.Path;controller=$_.ControllerType.ToString();controller_number=$_.ControllerNumber;
            controller_location=$_.ControllerLocation;vhd_id=$vhd.DiskIdentifier.ToString();virtual_bytes=$vhd.Size;
            file_bytes=$vhd.FileSize;parent_path=$vhd.ParentPath;file_id_query=$fileId}
    })
    if($disks.Count-ne4){throw 'Alpha disk-role count differs.'}
    $after=Observe-Protected
    if(($before|ConvertTo-Json -Depth 8 -Compress)-cne($after|ConvertTo-Json -Depth 8 -Compress)){throw 'Preserved VM state/configuration changed during alpha provisioning.'}
    $manifest=[pscustomobject]@{schema_version=1;name=$name;vm_id=$id.ToString('D');root=$root;
        state='Off';memory_bytes=8GB;processor_count=4;network_adapters=@(Get-VMNetworkAdapter -VM $vm).Count;
        tpm_enabled=(Get-VMSecurity -VM $vm).TpmEnabled;secure_boot=(Get-VMFirmware -VM $vm).SecureBoot.ToString();
        disks=$disks;protected_after=$after;source_archive_held_read_only=$true;guest_login_performed=$false;
        created_utc=[DateTime]::UtcNow.ToString('o')}
    Save 'manifest.json' $manifest
    $manifest|ConvertTo-Json -Depth 8 -Compress
}finally{foreach($handle in $handles){$handle.Dispose()}}
