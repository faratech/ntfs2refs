# Initialize only the fresh RAW media enrolled on the separate streaming VM.
# Creates existing NTFS data normally; never moves/ages source extents.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$m=Get-Content -LiteralPath (Join-Path $root 'manifest.json') -Raw|ConvertFrom-Json
$vm=Get-VM -Id $m.vm_id
if($vm.Id-ne[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'-or$vm.Name-cne'ntfs2refs-streaming-v2-20261027'-or$vm.State.ToString()-cne'Running'){throw 'Owned streaming VM required.'}
if(Test-Path -LiteralPath (Join-Path $root 'fixture-intent.json')){throw 'Fixture already has intent; inspect actual worker/state.'}
$raw=Get-Content -LiteralPath (Join-Path $root 'raw-enrollment.json') -Raw
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 5GB
@{vm_id=$m.vm_id;source_partition_bytes=52GB;source_cluster_bytes=65536;largest_file_bytes=4GB+1;source_extent_moves=0;source_allocation_aging_bytes=0;utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $root 'fixture-intent.json') -Encoding utf8
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$s=New-PSSession -VMId $vm.Id -Credential $credential
try{
    $result=Invoke-Command -Session $s -ArgumentList $raw -ScriptBlock {
        param($Enrollment);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'){throw 'Guest OS enrollment differs.'}
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'}).Count){throw 'Converter is active.'}
        $enrolled=ConvertFrom-Json -InputObject $Enrollment
        $devices=@(Get-CimInstance Win32_DiskDrive)
        foreach($row in $enrolled|Where-Object {$_.number-ne0}){
            $disk=Get-Disk -Number $row.number;$device=@($devices|Where-Object {$_.Index-eq$disk.Number})
            if($disk.UniqueId-cne$row.unique_id-or$disk.Size-ne$row.bytes-or$disk.PartitionStyle.ToString()-cne'RAW'-or$disk.NumberOfPartitions-ne0-or
                $disk.IsBoot-or$disk.IsSystem-or$disk.IsOffline-or$disk.IsReadOnly-or$device.Count-ne1-or$device[0].SCSILogicalUnit-ne$row.lun){throw 'Fresh RAW disk identity differs; do not format.'}
        }
        foreach($letter in @('F','J','R')){if(Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue){throw 'Fixture letter is occupied.'}}
        $stage='C:\ntfs2refs\streaming-v2-20261027'
        if(Test-Path -LiteralPath $stage){throw 'Guest fixture directory exists.'}
        New-Item -ItemType Directory -Path $stage|Out-Null
        @{kind='streaming-v2-fixture-worker';pid=$PID;started_utc=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $stage 'intent.json') -Encoding utf8
        $parts=@(foreach($entry in @(@(1,'F',52GB,'NTFS','n2r-stream-source',65536),@(2,'J',(8GB-32MB),'NTFS','n2r-stream-journal',4096),@(3,'R',52GB,'ReFS','n2r-retained-shadow',4096))){
            Initialize-Disk -Number $entry[0] -PartitionStyle GPT -Confirm:$false|Out-Null
            $part=New-Partition -DiskNumber $entry[0] -Offset 16MB -Size $entry[2] -DriveLetter $entry[1] -GptType '{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}'
            if($entry[3]-ceq'ReFS'){Format-Volume -Partition $part -DevDrive -FileSystem ReFS -AllocationUnitSize $entry[5] -NewFileSystemLabel $entry[4] -Confirm:$false -Force|Out-Null}
            else{Format-Volume -Partition $part -FileSystem NTFS -AllocationUnitSize $entry[5] -NewFileSystemLabel $entry[4] -Confirm:$false -Force|Out-Null}
            [pscustomobject]@{disk=$entry[0];letter=$entry[1];filesystem=$entry[3];cluster_bytes=$entry[5];partition_guid=$part.Guid;offset=$part.Offset;bytes=$part.Size}
        })
        $ErrorActionPreference='Continue';$short=@(fsutil.exe 8dot3name set F: 1 2>&1);$shortExit=$LASTEXITCODE;$ErrorActionPreference='Stop'
        $short|Out-String|Set-Content -LiteralPath (Join-Path $stage 'short-name-policy.log') -Encoding utf8
        if($shortExit-ne0){throw 'Short-name policy command failed.'}
        $sections=[Security.AccessControl.AccessControlSections]::Owner-bor[Security.AccessControl.AccessControlSections]::Group-bor[Security.AccessControl.AccessControlSections]::Access
        foreach($name in @('資料','資料\nested','notes')){
            $path='F:\'+$name;[IO.Directory]::CreateDirectory($path)|Out-Null
            $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)',$sections);[IO.Directory]::SetAccessControl($path,$acl)
        }
        $random=[Random]::new(20261028)
        $files=@(foreach($entry in @(@('root.bin',64KB),@('資料\Grüße.bin',128KB),@('資料\nested\emoji-🦊.bin',64KB),@('notes\café.txt',17),@('empty.bin',0),@('資料\large-zero.bin',(4GB+1)))){
            $path='F:\'+$entry[0];$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            $buffer=[byte[]]::new(1MB);$left=[long]$entry[1]
            try{while($left-gt0){if($entry[0]-cne'資料\large-zero.bin'){$random.NextBytes($buffer)};$count=[int][Math]::Min($left,$buffer.Length);$file.Write($buffer,0,$count);$left-=$count};$file.Flush($true)}finally{$file.Dispose()}
            $acl=[Security.AccessControl.FileSecurity]::new();$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)',$sections);[IO.File]::SetAccessControl($path,$acl)
            [pscustomobject]@{path=$path;bytes=[long]$entry[1];sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
        })
        $ErrorActionPreference='Continue';$extents=@(fsutil.exe file queryextents 'F:\資料\large-zero.bin' 2>&1);$extentExit=$LASTEXITCODE;$ErrorActionPreference='Stop'
        if($extentExit-ne0){throw 'Source extent observation failed.'}
        $r=[pscustomobject]@{kind='streaming-v2-existing-tree';partitions=$parts;files=$files;logical_user_bytes=($files|Measure-Object bytes -Sum).Sum;source_extent_moves=0;source_allocation_aging_bytes=0;source_large_extents=$extents;utc=[DateTime]::UtcNow.ToString('o')}
        $r|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $stage 'fixture.json') -Encoding utf8
        $r
    }
    $result|ConvertTo-Json -Depth 14|Set-Content -LiteralPath (Join-Path $root 'fixture.json') -Encoding utf8
    $result|Select-Object kind,logical_user_bytes,source_extent_moves,source_allocation_aging_bytes,utc|ConvertTo-Json -Compress
}finally{Remove-PSSession $s}
