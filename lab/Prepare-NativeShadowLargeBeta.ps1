# Formats only the newly enrolled beta's three disposable RAW data disks.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace '.lab\hyperv\shadow-large-beta-20261027'
$id=[guid]'6c4793d2-cdee-468b-bf3b-1c11cae0b501'
$vm=Get-VM -Id $id -ErrorAction Stop
if($vm.Name-cne'ntfs2refs-shadow-large-beta-20261027'-or$vm.State.ToString()-cne'Running'-or
    [string]$vm.ParentSnapshotId-cne'971ecdc3-8eca-4abb-a77e-e028e7e54f7f'-or
    -not$vm.Path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Owned beta starting branch differs.'}
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 12GB
$intent=Join-Path $root 'storage-intent.json'
if(Test-Path -LiteralPath $intent){throw 'Beta storage preparation already has state; inspect instead of retrying.'}
$ready=Get-Content -LiteralPath (Join-Path $root 'guest-readiness.json') -Raw|ConvertFrom-Json
$expected=@($ready.disks|Where-Object {$_.number-in@(1,2,3)})
if($expected.Count-ne3-or@($expected|Where-Object {$_.partition_style-cne'RAW'-or$_.partition_count-ne0-or$_.is_boot-or$_.is_system}).Count){throw 'Fresh RAW enrollment required.'}
$record=[pscustomobject]@{vm_id=$id.ToString('D');source_disk=1;journal_disk=2;shadow_disk=3;
    source_partition_bytes=240GB;source_cluster_bytes=65536;target_cluster_bytes=4096;source_extent_moves=0;
    source_allocation_aging_bytes=0;expected=$expected;started_utc=[DateTime]::UtcNow.ToString('o')}
$stream=[IO.File]::Open($intent,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 8));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$session=New-PSSession -VMId $id -Credential $credential
try{
    $result=Invoke-Command -Session $session -ArgumentList ($expected|ConvertTo-Json -Depth 6 -Compress) -ScriptBlock {
        param($Enrollment);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        $stage='C:\ntfs2refs\beta\large-20261027';$marker=Join-Path $stage 'fixture-intent.json'
        if(Test-Path -LiteralPath $marker){throw 'Guest beta fixture already has intent.'}
        if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'){throw 'Beta guest profile differs.'}
        if(@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count){throw 'Another guest worker is active.'}
        $enrolled=ConvertFrom-Json -InputObject $Enrollment
        $devices=@(Get-CimInstance Win32_DiskDrive)
        foreach($spec in $enrolled){
            $disk=Get-Disk -Number $spec.number;$device=@($devices|Where-Object {$_.Index-eq$disk.Number})
            if($disk.UniqueId-cne$spec.unique_id-or$disk.Size-ne$spec.size_bytes-or$disk.PartitionStyle.ToString()-cne'RAW'-or
                $disk.NumberOfPartitions-ne0-or$disk.IsBoot-or$disk.IsSystem-or$disk.IsOffline-or$disk.IsReadOnly-or
                $disk.LogicalSectorSize-ne512-or$disk.PhysicalSectorSize-ne4096-or$device.Count-ne1-or$device[0].SCSILogicalUnit-ne$spec.scsi_lun){throw 'Actual beta disk differs from RAW enrollment.'}
        }
        foreach($letter in @('F','J','R')){if(Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue){throw 'Beta drive letter occupied.'}}
        [pscustomobject]@{kind='large-beta-fixture-intent';worker_pid=$PID;worker_started_utc=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToString('o');
            source_disk=1;journal_disk=2;shadow_disk=3;source_extent_moves=0;source_allocation_aging_bytes=0;utc=[DateTime]::UtcNow.ToString('o')}|
            ConvertTo-Json|Set-Content -LiteralPath $marker -Encoding utf8
        $parts=@()
        foreach($entry in @(@(1,'F',240GB,'NTFS','n2r-beta-source',65536),@(2,'J',(8GB-32MB),'NTFS','n2r-beta-journal',4096),@(3,'R',240GB,'ReFS','n2r-retained-shadow',4096))){
            $null=Initialize-Disk -Number $entry[0] -PartitionStyle GPT -Confirm:$false
            $partition=New-Partition -DiskNumber $entry[0] -Offset 16MB -Size $entry[2] -DriveLetter $entry[1] -GptType '{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}'
            if($entry[3]-ceq'ReFS'){$null=Format-Volume -Partition $partition -DevDrive -FileSystem ReFS -AllocationUnitSize $entry[5] -NewFileSystemLabel $entry[4] -Confirm:$false -Force}
            else{$null=Format-Volume -Partition $partition -FileSystem NTFS -AllocationUnitSize $entry[5] -NewFileSystemLabel $entry[4] -Confirm:$false -Force}
            $parts+=[pscustomobject]@{disk_number=$entry[0];partition_number=$partition.PartitionNumber;drive_letter=$entry[1];filesystem=$entry[3];
                allocation_unit_bytes=$entry[5];offset=$partition.Offset;bytes=$partition.Size;guid=$partition.Guid}
        }
        $sections=[Security.AccessControl.AccessControlSections]::Owner-bor[Security.AccessControl.AccessControlSections]::Group-bor[Security.AccessControl.AccessControlSections]::Access
        foreach($name in @('data','data\nested','notes')){
            $path='F:\'+$name;$null=[IO.Directory]::CreateDirectory($path)
            $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)',$sections)
            [IO.Directory]::SetAccessControl($path,$acl)
        }
        $random=[Random]::new(20261027);$files=@()
        foreach($entry in @(@('root.bin',64KB),@('data\one.bin',128KB),@('data\nested\two.bin',64KB),@('notes\tiny.txt',17),@('empty.bin',0),@('data\large.bin',128MB))){
            $path='F:\'+$entry[0];$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            $buffer=[byte[]]::new(1MB);$left=[long]$entry[1]
            try{while($left-gt0){$random.NextBytes($buffer);$count=[int][Math]::Min($left,$buffer.Length);$file.Write($buffer,0,$count);$left-=$count};$file.Flush($true)}finally{$file.Dispose()}
            $acl=[Security.AccessControl.FileSecurity]::new();$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)',$sections)
            [IO.File]::SetAccessControl($path,$acl)
            $files+=[pscustomobject]@{path=$path;bytes=$entry[1];sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
        }
        $extents=@(fsutil.exe file queryextents 'F:\data\large.bin')
        if($LASTEXITCODE-ne0){throw 'Source mapping observation failed.'}
        $result=[pscustomobject]@{kind='large-beta-existing-tree-fixture';partitions=$parts;files=$files;
            logical_user_bytes=($files|Measure-Object bytes -Sum).Sum;source_extent_moves=0;source_allocation_aging_bytes=0;
            source_extent_query=$extents;completed_utc=[DateTime]::UtcNow.ToString('o')}
        $result|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $stage 'fixture.json') -Encoding utf8
        $result
    }
    $result|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $root 'guest-fixture.json') -Encoding utf8
    $result|ConvertTo-Json -Depth 8 -Compress
}finally{Remove-PSSession $session -ErrorAction SilentlyContinue}
