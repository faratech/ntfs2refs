# Create one independent NTFS hard-link fixture on a newly attached RAW disk.
# Root provisions/attaches the disposable VHDX and supplies its observed pins.
# This controller never changes power, checkpoints, F:, G:, or an existing FS.
[CmdletBinding()]
param(
 [Parameter(Mandatory)][guid]$ExpectedParent,
 [Parameter(Mandatory)][guid[]]$ExpectedCheckpointIds,
 [Parameter(Mandatory)][ValidateRange(1,255)][int]$DiskNumber,
 [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedDiskUniqueId,
 [AllowEmptyString()][string]$ExpectedDiskSerial='',
 [Parameter(Mandatory)][string]$VhdPath,
 [Parameter(Mandatory)][guid]$ExpectedVirtualDiskId
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs'
$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$vmId=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$run=[guid]::NewGuid().ToString('N')
$root=Join-Path $base ('hardlink-fixture-'+$run)
$created=$false
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function Save([string]$Name,$Value){
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 12))
 Need ($bytes.Length-le1MB) 'Fixture receipt exceeds one MiB.'
 $file=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
}
$vhd=[IO.Path]::GetFullPath($VhdPath)
Need ($vhd.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)-and[IO.Path]::GetExtension($vhd)-ieq'.vhdx') 'Disposable VHDX must be inside the lab directory.'
$item=Get-Item -LiteralPath $vhd -Force
Need (-not$item.PSIsContainer) 'VHDX must be an ordinary file.'
$ancestor=$item
while($null-ne$ancestor){Need (-not($ancestor.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'VHDX ancestry must not contain reparse points.';if($ancestor-is[IO.DirectoryInfo]){$ancestor=$ancestor.Parent}else{$ancestor=$ancestor.Directory}}
$checkpointIds=@($ExpectedCheckpointIds|ForEach-Object {$_.ToString('D')})
Need ($checkpointIds.Count-gt0-and@($checkpointIds|Sort-Object -Unique).Count-eq$checkpointIds.Count-and$ExpectedParent.ToString('D')-in$checkpointIds-and$ExpectedVirtualDiskId-ne[guid]::Empty) 'Explicit unique checkpoint and VHD identities required.'
function HostGuard{
 $vm=Get-VM -Id $vmId -ErrorAction Stop
 $actual=@(Get-VMSnapshot -VM $vm -ErrorAction Stop|ForEach-Object {$_.Id.ToString('D')})
 Need ($vm.Name-ceq'ntfs2refs-streaming-v2-20261027'-and$vm.State.ToString()-ceq'Running'-and$vm.ParentSnapshotId-eq$ExpectedParent-and$vm.MemoryStartup-eq4GB-and$vm.MemoryAssigned-eq4GB-and-not$vm.DynamicMemoryEnabled-and(Get-VMProcessor -VM $vm).Count-eq4-and@(Get-VMNetworkAdapter -VM $vm).Count-eq0-and$actual.Count-eq$checkpointIds.Count-and@($checkpointIds|Where-Object {$_-notin$actual}).Count-eq0) 'Reviewed running VM, parent, checkpoints, 4 GiB/4 CPU/no NIC required.'
 $attached=@(Get-VMHardDiskDrive -VM $vm|Where-Object {$_.Path-ieq$vhd})
 Need ($attached.Count-eq1-and$attached[0].ControllerType.ToString()-ceq'SCSI'-and$attached[0].ControllerNumber-eq0-and$attached[0].ControllerLocation-eq7) 'Exact VHDX must be attached once at SCSI 0:7.'
 $meta=Get-VHD -Path $vhd -ErrorAction Stop
 Need ($meta.DiskIdentifier-eq$ExpectedVirtualDiskId-and$meta.Size-eq56GB-and$meta.VhdType.ToString()-ceq'Dynamic'-and[string]::IsNullOrEmpty($meta.ParentPath)) 'Pinned standalone 56 GiB dynamic VHDX required.'
 return $meta
}
try{
 Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
 $configuration=Get-LabConfiguration -WorkspaceRoot $workspace
 $capacity=Get-LabCapacity -Configuration $configuration
 Need ($capacity.MaximumActualBytes-eq329374052988-and$capacity.MinimumFreeBytes-eq17179869184) 'Fixed storage epoch differs.'
 Assert-LabCapacity -Capacity $capacity -AdditionalBytes 8GB
 $vhdBefore=HostGuard
 New-Item -ItemType Directory -Path $root -ErrorAction Stop|Out-Null
 $created=$true
 Save 'intent.json' @{
  schema_version=1;kind='fresh-hardlink-fixture-intent';run_id=$run;vm_id=$vmId.ToString('D');parent_id=$ExpectedParent.ToString('D');checkpoint_ids=$checkpointIds
  guest_disk_number=$DiskNumber;expected_disk_unique_id=$ExpectedDiskUniqueId;expected_disk_serial=$ExpectedDiskSerial
  host_vhd_path=$vhd;host_virtual_disk_id=$ExpectedVirtualDiskId.ToString('D');host_vhd_size=$vhdBefore.Size;host_vhd_type=$vhdBefore.VhdType.ToString()
  host_vhd_identity_is_metadata_pin=$true;attached_bytes_not_hashed=$true;capacity=$capacity;forecast_bytes=8GB;forecast_is_not_reservation=$true
  target_drive='H:';partition_offset=32MB;partition_bytes=52GB;cluster_bytes=4096;label='n2r-links-source';power_or_checkpoint_change=$false;deletions=$false
 }
 $credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
 $result=Invoke-Command -VMId $vmId -Credential $credential -ErrorAction Stop -ArgumentList $DiskNumber,$ExpectedDiskUniqueId,$ExpectedDiskSerial,$run -ScriptBlock {
  param($Number,$UniqueId,$Serial,$Run)
  Set-StrictMode -Version Latest
  $ErrorActionPreference='Stop'
  [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
  $OutputEncoding=[Text.UTF8Encoding]::new($false)
  function Require([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
  function Idle{
   Require (@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count-eq0-and@(Get-ScheduledTask|Where-Object {$_.TaskName-like'N2R-*'-and$_.State.ToString()-notin@('Ready','Disabled')}).Count-eq0) 'No active project workers or N2R tasks permitted.'
  }
  function DiskSerial($Disk){$property=$Disk.PSObject.Properties['SerialNumber'];if($null-eq$property){return ''};return [string]$property.Value}
  function RawDisk{
   Idle
   $disks=@(Get-Disk -ErrorAction Stop)
   $matches=@($disks|Where-Object {$_.Size-eq56GB-and$_.PartitionStyle.ToString()-ceq'RAW'})
   Require ($matches.Count-eq1-and$matches[0].Number-eq$Number) 'The sole 56 GiB RAW disk must be the reviewed target.'
   $disk=$matches[0]
   Require ($Number-ne0-and-not$disk.IsBoot-and-not$disk.IsSystem-and-not$disk.IsOffline-and-not$disk.IsReadOnly-and$disk.UniqueId-ceq$UniqueId-and(DiskSerial $disk)-ceq$Serial-and$disk.BusType.ToString()-in@('SCSI','SAS','Virtual','FileBackedVirtual','File Backed Virtual')) 'RAW disk identity, flags or bus differ.'
   Require ((Get-Partition -DriveLetter C -ErrorAction Stop).DiskNumber-ne$Number) 'The target cannot contain the OS partition.'
   Require (@(Get-Partition -DriveLetter H -ErrorAction SilentlyContinue).Count-eq0-and@(Get-Volume -DriveLetter H -ErrorAction SilentlyContinue).Count-eq0-and-not(Test-Path -LiteralPath 'H:\')) 'H: must be unused.'
   Require (@(Get-Partition -DiskNumber $Number -ErrorAction SilentlyContinue).Count-eq0) 'RAW target unexpectedly contains partitions.'
   return $disk
  }
  function Fsutil([string[]]$Arguments){
   $lines=@(& "$env:SystemRoot\System32\fsutil.exe" @Arguments 2>&1|ForEach-Object {[string]$_})
   $exit=$LASTEXITCODE
   Require ($exit-eq0-and($lines-join"`n").Length-le65536) ('fsutil failed: '+($Arguments-join' '))
   return ,$lines
  }
  $diskBefore=RawDisk
  # No initialization or formatting occurs until every RAW identity guard above passed.
  Initialize-Disk -Number $Number -PartitionStyle GPT -ErrorAction Stop|Out-Null
  $partition=New-Partition -DiskNumber $Number -Offset 32MB -Size 52GB -DriveLetter H -ErrorAction Stop
  Require ($partition.DiskNumber-eq$Number-and$partition.Offset-eq32MB-and$partition.Size-eq52GB-and$partition.DriveLetter-eq'H') 'New partition differs from the requested blank target.'
  Format-Volume -Partition $partition -FileSystem NTFS -AllocationUnitSize 4096 -NewFileSystemLabel 'n2r-links-source' -Confirm:$false -ErrorAction Stop|Out-Null
  $shortSet=Fsutil @('8dot3name','set','H:','1')
  $shortQuery=Fsutil @('8dot3name','query','H:')
  $volume=Get-Volume -DriveLetter H -ErrorAction Stop
  Require ($volume.FileSystem-ceq'NTFS'-and$volume.AllocationUnitSize-eq4096-and$volume.FileSystemLabel-ceq'n2r-links-source') 'New NTFS volume geometry or label differs.'
  # ASCII source spelling also works when Windows PowerShell 5.1 reads this file.
  $unicodeDirectory='H:\'+[string][char]0x8cc7+[char]0x6599
  New-Item -ItemType Directory -Path @('H:\nested',$unicodeDirectory) -ErrorAction Stop|Out-Null
  $ordinary=[byte[]]::new(1MB)
  for($i=0;$i-lt$ordinary.Length;$i++){$ordinary[$i]=[byte](($i*31+17)%251)}
  $specs=@(
   @{name='ordinary';extension='bin';kind='ordinary-nonresident-sized';data=$ordinary},
   @{name='resident';extension='txt';kind='resident-sized-nine-bytes';data=[Text.Encoding]::ASCII.GetBytes('n2r-link!')},
   @{name='empty';extension='dat';kind='empty';data=[byte[]]::new(0)}
  )
  $groups=[Collections.Generic.List[object]]::new()
  $identities=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($spec in $specs){
   $primary='H:\'+$spec.name+'.'+$spec.extension
   $aliases=@(('H:\nested\'+$spec.name+'-link.'+$spec.extension),($unicodeDirectory+'\'+$spec.name+'-link.'+$spec.extension))
   $file=[IO.File]::Open($primary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
   try{if($spec.data.Length-gt0){$file.Write($spec.data,0,$spec.data.Length)};$file.Flush($true)}finally{$file.Dispose()}
   foreach($alias in $aliases){Require (-not(Test-Path -LiteralPath $alias)) 'New alias path already exists.';New-Item -ItemType HardLink -Path $alias -Target $primary -ErrorAction Stop|Out-Null}
   $paths=@($primary)+$aliases
   $expectedLinks=@($paths|ForEach-Object {$_.Substring(2)}|Sort-Object)
   $groupHash=(Get-FileHash -LiteralPath $primary -Algorithm SHA256).Hash.ToLowerInvariant()
   $observed=[Collections.Generic.List[object]]::new();$fileId=$null
   foreach($path in $paths){
    $entry=Get-Item -LiteralPath $path -Force
    Require (-not$entry.PSIsContainer-and-not($entry.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$entry.Length-eq$spec.data.Length) 'Hard-link path type or length differs.'
    $digest=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    Require ($digest-ceq$groupHash) 'Hard-link payload differs within its group.'
    $idOutput=Fsutil @('file','queryfileid',$path)
    $ids=[regex]::Matches(($idOutput-join"`n"),'0x[0-9a-fA-F]+')
    Require ($ids.Count-eq1) 'Expected one native file ID.'
    $idValue=$ids[0].Value.ToLowerInvariant()
    if($null-eq$fileId){$fileId=$idValue}else{Require ($idValue-ceq$fileId) 'Aliases are distinct file identities.'}
    $linkOutput=Fsutil @('hardlink','list',$path)
    $links=@($linkOutput|ForEach-Object {$line=$_.Trim();if($line.Length){if($line.StartsWith('H:\',[StringComparison]::OrdinalIgnoreCase)){$line=$line.Substring(2)};Require ($line.StartsWith('\')) 'Unexpected native hard-link list row.';$line}}|Sort-Object)
    Require ($links.Count-eq3-and@(Compare-Object -ReferenceObject $expectedLinks -DifferenceObject $links -CaseSensitive).Count-eq0) 'Native hard-link list is not the exact three names.'
    $observed.Add([pscustomobject]@{path=$path;relative=$path.Substring(3);length=$entry.Length;sha256=$digest;file_id=$idValue;queryfileid_output=$idOutput;hardlink_list_output=$linkOutput;hardlink_list=$links})
   }
   Require ($identities.Add($fileId)) 'Different fixture groups unexpectedly share a file identity.'
   $groups.Add([pscustomobject]@{name=$spec.name;kind=$spec.kind;logical_length=$spec.data.Length;sha256=$groupHash;file_id=$fileId;names=$observed.ToArray()})
  }
  Write-VolumeCache -DriveLetter H -ErrorAction Stop
  Idle
  $diskAfter=Get-Disk -Number $Number -ErrorAction Stop
  $partitionAfter=Get-Partition -DriveLetter H -ErrorAction Stop
  $volumeAfter=Get-Volume -DriveLetter H -ErrorAction Stop
  Require ($diskAfter.Size-eq56GB-and$diskAfter.UniqueId-ceq$UniqueId-and(DiskSerial $diskAfter)-ceq$Serial-and$diskAfter.PartitionStyle.ToString()-ceq'GPT'-and-not$diskAfter.IsBoot-and-not$diskAfter.IsSystem-and-not$diskAfter.IsOffline-and-not$diskAfter.IsReadOnly-and$partitionAfter.DiskNumber-eq$Number-and$partitionAfter.Offset-eq32MB-and$partitionAfter.Size-eq52GB-and$volumeAfter.FileSystem-ceq'NTFS'-and$volumeAfter.AllocationUnitSize-eq4096-and$volumeAfter.FileSystemLabel-ceq'n2r-links-source') 'Completed fixture route or state differs.'
  [pscustomobject]@{
   schema_version=1;kind='independent-hardlink-ntfs-fixture';success=$true;run_id=$Run
   disk_number=$Number;disk_unique_id_before=$diskBefore.UniqueId;disk_serial_before=(DiskSerial $diskBefore);disk_unique_id_after=$diskAfter.UniqueId;disk_serial_after=(DiskSerial $diskAfter)
   disk_guid=[string]$diskAfter.Guid;partition_guid=[string]$partitionAfter.Guid;partition_number=$partitionAfter.PartitionNumber;partition_offset=$partitionAfter.Offset;partition_bytes=$partitionAfter.Size;volume_guid_path=$volumeAfter.Path
   filesystem=$volumeAfter.FileSystem;cluster_bytes=$volumeAfter.AllocationUnitSize;label=$volumeAfter.FileSystemLabel;short_name_set_output=$shortSet;short_name_query_output=$shortQuery
   user_file_identities=3;user_file_names=9;user_directories_including_root=3;directories=@('H:\','H:\nested',$unicodeDirectory);logical_bytes_unique=1048585;groups=$groups.ToArray()
   source_extents_prearranged=$false;resident_storage_not_raw_verified=$true;other_filesystems_formatted=$false;deletions=$false;utc=[DateTime]::UtcNow.ToString('o')
  }
 }
 $null=HostGuard
 Save 'fixture.json' $result
 Save 'result.json' @{schema_version=1;success=$true;kind='hardlink-fixture-controller';run_id=$run;fixture_path=(Join-Path $root 'fixture.json');fixture_sha256=(Get-FileHash -LiteralPath (Join-Path $root 'fixture.json')).Hash.ToLowerInvariant();host_vhd_path=$vhd;host_virtual_disk_id=$ExpectedVirtualDiskId.ToString('D');power_or_checkpoint_change=$false;utc=[DateTime]::UtcNow.ToString('o')}
 [pscustomobject]@{success=$true;fixture_path=(Join-Path $root 'fixture.json');run_id=$run;user_file_identities=3;user_file_names=9;drive='H:'}
}catch{
 if($created-and-not(Test-Path -LiteralPath (Join-Path $root 'failed.json'))){Save 'failed.json' @{success=$false;run_id=$run;error=$_.Exception.ToString();automatic_retry=$false;automatic_cleanup=$false;utc=[DateTime]::UtcNow.ToString('o')}}
 throw
}
