# Format only the two new RAW disks matched to host slots5/6 and discovery.
# Existing disks0..3, journals, checkpoints and source extents are not modified.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\selected-native-alpha-20261028'
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$parent=[guid]'c670839d-00d1-46cf-8544-6aad51bde364'
function Need([bool]$Condition,[string]$Message){if(-not$Condition){throw $Message}}
function Save-New([string]$Name,$Value){$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 18));$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
Need (-not(Test-Path -LiteralPath (Join-Path $root 'preparation-intent.json'))) 'Preparation has state; inspect rather than retry.'
$discoveryPath=Join-Path $root 'guest-discovered.json'
Need ((Get-FileHash -LiteralPath $discoveryPath).Hash.ToLowerInvariant() -ceq 'cf47aecfe213b23566f7cdb271ec86864176c622c97e0f95604b1c80efeac76e') 'Original RAW discovery pin differs.'
$hostCreated=Get-Content -LiteralPath (Join-Path $root 'host-created.json') -Raw|ConvertFrom-Json
$vm=Get-VM -Id $id;$snap=@(Get-VMSnapshot -VM $vm);$drives=@(Get-VMHardDiskDrive -VM $vm)
Need ($hostCreated.success -eq $true -and $vm.State.ToString() -ceq 'Running' -and $vm.ParentSnapshotId -eq $parent -and $vm.MemoryStartup -eq 4GB -and -not$vm.DynamicMemoryEnabled -and @(Get-VMNetworkAdapter -VM $vm).Count -eq 0 -and $snap.Count -eq 47 -and @($hostCreated.checkpoint_ids|Where-Object {$_ -notin @($snap.Id|ForEach-Object {$_.ToString('D')})}).Count -eq 0 -and $drives.Count -eq 6) 'Exact isolated branch/all47/six disks required.'
foreach($row in $hostCreated.new_disks){Need (@($drives|Where-Object {$_.ControllerNumber -eq 0 -and $_.ControllerLocation -eq $row.slot -and $_.Path -ceq $row.path}).Count -eq 1) 'New host attachment differs.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
Need ($capacity.MaximumActualBytes -eq 329374052988 -and $capacity.MinimumFreeBytes -eq 17179869184) 'Fixed additional50GB epoch differs.'
Assert-LabCapacity -Capacity $capacity -AdditionalBytes 7GB
Save-New 'preparation-intent.json' @{vm_id=$id.ToString();parent_id=$parent.ToString();only_new_disks=@(4,5);host_slots=@(5,6);partition_bytes=60GB;source_cluster_bytes=4096;source_extent_moves=0;maximum_new_file_bytes=66MB;capacity=$capacity;forecast_bytes=7GB;automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')}
$session=$null
try{
    $session=New-PSSession -VMId $id -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml'))
    $result=Invoke-Command -Session $session -ScriptBlock {
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$phase='raw-identity-guard';$stage='C:\ntfs2refs\selected-native-alpha-20261028'
        function Guard-New([int]$Number,[string]$Unique,[int]$Lun,[bool]$Raw){$d=Get-Disk -Number $Number;$w=@(Get-CimInstance Win32_DiskDrive|Where-Object Index -eq $Number);if($d.UniqueId -cne $Unique -or $d.Size -ne 80GB -or $d.IsBoot -or $d.IsSystem -or $d.IsOffline -or $d.IsReadOnly -or $d.LogicalSectorSize -ne 512 -or $d.PhysicalSectorSize -ne 4096 -or $w.Count -ne 1 -or $w[0].SCSIPort -ne 0 -or $w[0].SCSITargetId -ne 0 -or $w[0].SCSILogicalUnit -ne $Lun -or ($Raw -and ($d.PartitionStyle.ToString() -cne 'RAW' -or $d.NumberOfPartitions -ne 0))){throw 'New disk identity/RAW state differs; no format allowed.'};$d}
        if($env:COMPUTERNAME -cne 'N2R-WIN11' -or $env:SystemDrive -cne 'C:' -or (Test-Path -LiteralPath $stage) -or @(Get-ScheduledTask|Where-Object {$_.TaskName -like 'N2R-*' -and $_.State.ToString() -in @('Running','Queued')}).Count -or @(Get-CimInstance Win32_Process|Where-Object {$_.Name -in @('ntfs2refs-compact.exe','ntfs2refs-bind.exe','lab-convert-native-composite.exe','lab-recover-native-composite.exe')}).Count){throw 'Fresh idle guest stage required.'}
        $null=Guard-New 4 '60022480C353A6F4060E497B21816F60' 5 $true;$null=Guard-New 5 '60022480C8CE64F61847BF4F2B50F544' 6 $true
        foreach($letter in @('G','T')){if(Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue){throw 'New test drive letter occupied.'}}
        if([guid](Get-Disk -Number 1).Guid -ne [guid]'1b191872-c372-41ee-a416-e18863996f54' -or [guid](Get-Disk -Number 2).Guid -ne [guid]'09fcc613-b8c2-4a1a-8833-226f9399be7f' -or [guid](Get-Disk -Number 3).Guid -ne [guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f' -or -not(Get-Disk -Number 3).IsOffline -or -not(Get-Disk -Number 3).IsReadOnly){throw 'Old data/journal/frozen-shadow identity changed.'}
        New-Item -ItemType Directory -Path $stage|Out-Null
        @{pid=$PID;creation_ms=([DateTimeOffset](Get-Process -Id $PID).StartTime).ToUnixTimeMilliseconds();phase=$phase;utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $stage 'preparation-worker.json') -Encoding UTF8
        try{
            $parts=@(foreach($spec in @(@(4,'60022480C353A6F4060E497B21816F60',5,'G','NTFS','n2r-selected-source'),@(5,'60022480C8CE64F61847BF4F2B50F544',6,'T','ReFS','n2r-retained-shadow'))){
                $phase='initialize-new-disk-'+$spec[0];$null=Guard-New $spec[0] $spec[1] $spec[2] $true
                Initialize-Disk -Number $spec[0] -PartitionStyle GPT -Confirm:$false|Out-Null
                $partition=New-Partition -DiskNumber $spec[0] -Offset 16MB -Size 60GB -DriveLetter $spec[3] -GptType '{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}'
                $null=Guard-New $spec[0] $spec[1] $spec[2] $false
                if($partition.DiskNumber -ne $spec[0] -or $partition.Offset -ne 16MB -or $partition.Size -ne 60GB){throw 'New partition differs before format.'}
                $phase='format-new-disk-'+$spec[0]
                if($spec[4] -ceq 'ReFS'){Format-Volume -Partition $partition -DevDrive -FileSystem ReFS -AllocationUnitSize 4096 -NewFileSystemLabel $spec[5] -Confirm:$false -Force|Out-Null}else{Format-Volume -Partition $partition -FileSystem NTFS -AllocationUnitSize 4096 -NewFileSystemLabel $spec[5] -Confirm:$false -Force|Out-Null}
                $v=Get-Volume -DriveLetter $spec[3];if($v.FileSystem -cne $spec[4] -or $v.AllocationUnitSize -ne 4096 -or $v.FileSystemLabel -cne $spec[5]){throw 'New native filesystem differs.'}
                @{disk_number=$spec[0];unique_id=$spec[1];lun=$spec[2];letter=$spec[3];filesystem=$spec[4];label=$spec[5];cluster_bytes=4096;disk_guid=(Get-Disk -Number $spec[0]).Guid;partition_guid=$partition.Guid;volume_guid=$v.UniqueId;partition_offset=$partition.Offset;partition_bytes=$partition.Size}
            })
            $phase='native-source-population';$ErrorActionPreference='Continue';$short=@(& "$env:SystemRoot\System32\fsutil.exe" 8dot3name set G: 1 2>&1);$exit=$LASTEXITCODE;$ErrorActionPreference='Stop';if($exit -ne 0){throw 'Per-volume short-name policy failed.'}
            $short|Out-String|Set-Content -LiteralPath (Join-Path $stage 'short-name-policy.log') -Encoding UTF8
            $sections=[Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access
            foreach($relative in @('notes','資料','資料\nested')){$p='G:\'+$relative;[IO.Directory]::CreateDirectory($p)|Out-Null;$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)',$sections);[IO.Directory]::SetAccessControl($p,$acl)}
            $random=[Random]::new(20261028);$buffer=[byte[]]::new(1MB)
            $files=@(foreach($entry in @(@('empty.bin',0),@('root.bin',64KB),@('notes\café.txt',17),@('notes\nonzero64.bin',(64MB+123)),@('資料\nested\emoji-🦊.bin',(1MB+1)))){
                $path='G:\'+$entry[0];$stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$left=[long]$entry[1]
                try{while($left -gt 0){$random.NextBytes($buffer);$n=[int][Math]::Min($left,$buffer.Length);$stream.Write($buffer,0,$n);$left-=$n};$stream.Flush($true)}finally{$stream.Dispose()}
                $acl=[Security.AccessControl.FileSecurity]::new();$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)',$sections);[IO.File]::SetAccessControl($path,$acl)
                @{path=$path;bytes=[long]$entry[1];sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant();full_contents_written_by_normal_file_api=$true}
            })
            $result=@{success=$true;kind='selected-compact-independently-populated-source';stage=$stage;partitions=$parts;files=$files;logical_user_bytes=($files|Measure-Object bytes -Sum).Sum;payload_pattern='deterministic pseudorandom; not a zero-filled large file';source_extent_moves=0;source_allocation_aging_bytes=0;old_disks_modified=$false;utc=[DateTime]::UtcNow.ToString('o')}
            $result|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $stage 'prepared.json') -Encoding UTF8
            $result
        }catch{@{phase=$phase;error=$_.Exception.ToString();automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $stage 'preparation-failed.json') -Encoding UTF8;throw}
    }
    Save-New 'prepared.json' $result
    $result|Select-Object success,kind,logical_user_bytes,source_extent_moves,utc|ConvertTo-Json -Compress
}catch{Save-New 'preparation-failed.json' @{error=$_.Exception.ToString();automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')};throw}
finally{if($null -ne $session){Remove-PSSession $session}}
