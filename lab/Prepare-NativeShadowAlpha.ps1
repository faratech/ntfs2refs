# Creates only the new alpha's disposable data volumes and supported file tree.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace '.lab\hyperv\shadow-alpha-20261026'
$id=[guid]'0d9bfa66-c66c-4ead-86b7-e72cb5f7e040'
$vm=Get-VM -Id $id
if($vm.Name-cne'ntfs2refs-shadow-alpha-20261026'-or$vm.State.ToString()-cne'Running'-or
    [string]$vm.ParentSnapshotId-cne'946f9082-7ace-4114-ba80-e3a4cd162ef6'){throw 'Owned alpha starting branch differs.'}
$intent=Join-Path $root 'storage-intent.json'
if(Test-Path -LiteralPath $intent){throw 'Storage preparation was already dispatched; inspect before retry.'}
$ready=Get-Content -LiteralPath (Join-Path $root 'guest-readiness.json') -Raw|ConvertFrom-Json
$expected=@($ready.disks|Where-Object {$_.number-in@(1,2,3)})
if($expected.Count-ne3-or@($expected|Where-Object {$_.partition_style-cne'RAW'-or$_.partition_count-ne0-or$_.is_boot-or$_.is_system}).Count){throw 'Fresh RAW alpha disk enrollment required.'}
[pscustomobject]@{vm_id=$id.ToString('D');source_disk=1;journal_disk=2;shadow_disk=3;
    fixture='ordinary-cluster-aligned-tree-with-aged-128MiB-file';source_extent_moves=0;
    expected=$expected;started_utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 8|
    Set-Content -LiteralPath $intent -Encoding utf8
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$session=New-PSSession -VMId $id -Credential $credential
try{
    $result=Invoke-Command -Session $session -ArgumentList ($expected|ConvertTo-Json -Depth 6 -Compress) -ScriptBlock {
        param($Enrollment);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        $stage='C:\ntfs2refs\alpha\native-shadow-alpha-20261026'
        $marker=Join-Path $stage 'fixture-intent.json'
        if(Test-Path -LiteralPath $marker){throw 'Guest fixture intent already exists.'}
        if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'){throw 'Frozen alpha guest differs.'}
        $enrolled=$Enrollment|ConvertFrom-Json
        $devices=@(Get-CimInstance Win32_DiskDrive)
        foreach($spec in $enrolled){
            $disk=Get-Disk -Number $spec.number
            $device=@($devices|Where-Object {$_.Index -eq $disk.Number})
            if($disk.UniqueId-cne$spec.unique_id-or$disk.Size-ne$spec.size_bytes-or$disk.PartitionStyle.ToString()-cne'RAW'-or
                $disk.NumberOfPartitions-ne0-or$disk.IsBoot-or$disk.IsSystem-or$disk.IsOffline-or$disk.IsReadOnly-or
                $disk.LogicalSectorSize-ne512-or$disk.PhysicalSectorSize-ne4096-or$device.Count-ne1-or$device[0].SCSILogicalUnit-ne$spec.scsi_lun){throw 'Actual disposable alpha disk differs.'}
        }
        foreach($letter in @('F','J','R')){if(Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue){throw 'Alpha drive letter is occupied.'}}
        [pscustomobject]@{kind='native-shadow-alpha-fixture-intent';source_disk=1;journal_disk=2;shadow_disk=3;
            source_extent_moves=0;started_utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath $marker -Encoding utf8
        $parts=@()
        foreach($entry in @(@(1,'F',52GB,'NTFS','n2r-alpha-source'),@(2,'J',(8GB-32MB),'NTFS','n2r-alpha-journal'),@(3,'R',52GB,'ReFS','n2r-retained-shadow'))){
            $null=Initialize-Disk -Number $entry[0] -PartitionStyle GPT -Confirm:$false
            $partition=New-Partition -DiskNumber $entry[0] -Offset 16MB -Size $entry[2] -DriveLetter $entry[1] -GptType '{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}'
            if($entry[3]-ceq'ReFS'){$null=Format-Volume -Partition $partition -DevDrive -FileSystem ReFS -AllocationUnitSize 4096 -NewFileSystemLabel $entry[4] -Confirm:$false -Force}
            else{$null=Format-Volume -Partition $partition -FileSystem NTFS -AllocationUnitSize 4096 -NewFileSystemLabel $entry[4] -Confirm:$false -Force}
            $parts+=[pscustomobject]@{disk_number=$entry[0];partition_number=$partition.PartitionNumber;drive_letter=$entry[1];filesystem=$entry[3];offset=$partition.Offset;bytes=$partition.Size;guid=$partition.Guid}
        }
        $sections=[Security.AccessControl.AccessControlSections]::Owner-bor[Security.AccessControl.AccessControlSections]::Group-bor[Security.AccessControl.AccessControlSections]::Access
        foreach($name in @('archive','archive\nested','notes')){
            $path='F:\'+$name;$null=[IO.Directory]::CreateDirectory($path)
            $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)',$sections)
            [IO.Directory]::SetAccessControl($path,$acl)
        }
        $random=[Random]::new(1311912524);$files=@()
        function Write-AlphaFile([string]$Path,[long]$Length){
            $file=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            $buffer=[byte[]]::new(1MB);$left=$Length
            try{while($left-gt0){$random.NextBytes($buffer);$count=[int][Math]::Min($left,$buffer.Length);$file.Write($buffer,0,$count);$left-=$count};$file.Flush($true)}finally{$file.Dispose()}
            $acl=[Security.AccessControl.FileSecurity]::new();$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)',$sections)
            [IO.File]::SetAccessControl($Path,$acl)
            [pscustomobject]@{path=$Path;bytes=$Length;sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
        }
        foreach($entry in @(@('source0.bin',64KB),@('archive\doc1.bin',128KB),@('archive\nested\doc2.bin',64KB),@('notes\doc3.bin',256KB),@('extra.bin',8MB),@('notes\post-label.bin',20KB))){
            $files+=Write-AlphaFile ('F:\'+$entry[0]) $entry[1]
        }
        $temporary='F:\alpha-owned-aging.tmp'
        $file=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $zero=[byte[]]::new(1MB)
        try{for($at=0L;$at-lt8GB;$at+=1MB){$file.Write($zero,0,$zero.Length)};$file.Flush($true)}finally{$file.Dispose()}
        $files+=Write-AlphaFile 'F:\natural-large.bin' 128MB
        # Only this freshly created disposable source temporary file is removed.
        [IO.File]::Delete($temporary)
        $extent=@(fsutil.exe file queryextents 'F:\natural-large.bin')
        if($LASTEXITCODE-ne0){throw 'Natural source mapping observation failed.'}
        $result=[pscustomobject]@{kind='native-shadow-alpha-fixture';partitions=$parts;files=$files;
            logical_user_bytes=($files|Measure-Object bytes -Sum).Sum;allocation_history_zero_bytes=8GB;source_extent_moves=0;
            natural_extent_query=$extent;completed_utc=[DateTime]::UtcNow.ToString('o')}
        $result|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $stage 'fixture.json') -Encoding utf8
        $result
    }
    $result|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $root 'guest-fixture.json') -Encoding utf8
    $result|ConvertTo-Json -Depth 12 -Compress
}finally{Remove-PSSession $session -ErrorAction SilentlyContinue}
