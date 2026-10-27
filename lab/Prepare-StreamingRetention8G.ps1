# New ordinary append-only source history on a fresh child of the original
# NTFS baseline. All earlier passed/interrupted checkpoint branches stay intact.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$root=Join-Path $base 'retention8g';$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$vm=Get-VM -Id $id
if($vm.State.ToString()-cne'Off'-or$vm.ParentSnapshotId-ne[guid]'40fb292c-0fd6-4048-bf40-93f2bc242ca3'-or
    $vm.Name-cne'ntfs2refs-streaming-v2-20261027'){throw 'Saved OFF rollback-passed fixture required.'}
if(Test-Path -LiteralPath $root){throw 'Retention fixture already has state; inspect without retry.'}
$snapshots=@(Get-VMSnapshot -VM $vm)
foreach($required in @('775f4db8-8635-486c-b6eb-7098426b51a6','157284d6-91fc-4b2b-ba6c-3052a0c413bc',
    '713e5fad-45fe-4200-9f6c-dabb669cc9ad','b4ef39f3-af21-404e-b9e1-68c65e3703e0','40fb292c-0fd6-4048-bf40-93f2bc242ca3')){
    if($snapshots.Id-notcontains[guid]$required){throw 'Required preserved branch missing.'}
}
if($snapshots.Count-ne8){throw 'Expected eight preserved checkpoints before new fixture.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
Assert-LabCapacity -Capacity $capacity -AdditionalBytes 6GB
New-Item -ItemType Directory -Path $root|Out-Null
function Save-New([string]$Name,$Value){
    $f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}
}
Save-New 'intent.json' @{vm_id=$id;preserved_checkpoints=@($snapshots.Id);restore_baseline='775f4db8-8635-486c-b6eb-7098426b51a6';
    source_append_bytes=4GB;source_new_length=8GB+1;source_extent_moves=0;source_allocation_aging_bytes=0;capacity=$capacity;utc=[DateTime]::UtcNow.ToString('o')}
Restore-VMSnapshot -VMSnapshot ($snapshots|Where-Object Id -eq ([guid]'775f4db8-8635-486c-b6eb-7098426b51a6')) -Confirm:$false
Start-VM -VM (Get-VM -Id $id) -ErrorAction Stop|Out-Null
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$session=$null;$deadline=[DateTime]::UtcNow.AddMinutes(8)
while($null-eq$session){try{$session=New-PSSession -VMId $id -Credential $credential -ErrorAction Stop}catch{
    if([DateTime]::UtcNow-ge$deadline){throw 'Single boot did not return; inspect without restart.'};Start-Sleep -Seconds 3}}
try{
    $fixture=Get-Content -LiteralPath (Join-Path $base 'fixture.json') -Raw
    $result=Invoke-Command -Session $session -ArgumentList $fixture -ScriptBlock {
        param($Fixture);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'-or$_.Name-ceq'lab-convert-admitted-tree.exe'}).Count){throw 'A worker is active.'}
        $expected=ConvertFrom-Json -InputObject $Fixture
        foreach($part in $expected.partitions){
            $p=Get-Partition -DriveLetter $part.letter;$d=Get-Disk -Number $p.DiskNumber;$v=Get-Volume -DriveLetter $part.letter
            if($p.DiskNumber-ne$part.disk-or[guid]$p.Guid-ne[guid]$part.partition_guid-or$p.Offset-ne$part.offset-or$p.Size-ne$part.bytes-or
                $d.IsBoot-or$d.IsSystem-or$d.IsOffline-or$d.IsReadOnly-or$v.FileSystem-cne$part.filesystem-or$v.AllocationUnitSize-ne$part.cluster_bytes){throw 'Restored original fixture geometry differs.'}
        }
        $large='F:\資料\large-zero.bin'
        foreach($file in $expected.files){if((Get-Item -LiteralPath $file.path).Length-ne$file.bytes-or(Get-FileHash -LiteralPath $file.path).Hash.ToLowerInvariant()-cne$file.sha256){throw 'Original source payload differs.'}}
        $stream=[IO.File]::Open($large,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{
            if($stream.Length-ne4GB+1){throw 'Original large-file length differs.'}
            [void]$stream.Seek(0,[IO.SeekOrigin]::End);$buffer=[byte[]]::new(1MB);$left=[long]4GB
            while($left-gt0){$count=[int][Math]::Min($left,$buffer.Length);$stream.Write($buffer,0,$count);$left-=$count};$stream.Flush($true)
        }finally{$stream.Dispose()}
        $rows=@(foreach($file in $expected.files){$item=Get-Item -LiteralPath $file.path;[pscustomobject]@{path=$file.path;bytes=$item.Length;sha256=(Get-FileHash -LiteralPath $file.path).Hash.ToLowerInvariant()}})
        $ErrorActionPreference='Continue';$extents=@(fsutil.exe file queryextents $large 2>&1);$code=$LASTEXITCODE;$ErrorActionPreference='Stop'
        if($code-ne0){throw 'New source extent observation failed.'}
        [pscustomobject]@{kind='streaming-v2-retention-existing-8g-tree';partitions=$expected.partitions;files=$rows;
            logical_user_bytes=($rows|Measure-Object bytes -Sum).Sum;source_append_bytes=4GB;source_extent_moves=0;
            source_allocation_aging_bytes=0;source_large_extents=$extents;utc=[DateTime]::UtcNow.ToString('o')}
    }
    Save-New 'fixture.json' $result
}finally{Remove-PSSession $session}
Stop-VM -VM (Get-VM -Id $id) -Confirm:$false -ErrorAction Stop
$off=Get-CimInstance -Namespace 'root/virtualization/v2' -ClassName Msvm_ComputerSystem -Filter "Name='2401593c-4b30-472e-9b6d-c9534cbaa599'"
if($off.EnabledState-ne3){throw 'Clean OFF required before source baseline save.'}
$checkpoint=Checkpoint-VM -VM (Get-VM -Id $id) -SnapshotName 'streaming-v2-ntfs-ordinary-append-8g' -Passthru
Save-New 'baseline.json' @{vm_id=$id;checkpoint_id=$checkpoint.Id;name=$checkpoint.Name;state='Off';utc=[DateTime]::UtcNow.ToString('o')}
$checkpoint|Select-Object Id,Name,ParentSnapshotId|ConvertTo-Json -Compress
