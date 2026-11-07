<# Guest-only post-conversion boot observation. Reads actual running Windows,
   storage and firmware state and writes one NEW receipt outside source disk0.
   Never boots, selects firmware, converts, replays, formats or repairs disks.
   The caller separately retains the successful conversion/handoff evidence. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$ConversionRunId,
    [long]$PreviousBootUnixMs = 1793995332223,
    [Parameter(Mandatory)][string]$ReceiptPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
function Hash([byte[]]$Bytes){$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}

# Receipt storage must be independent even if the caller accidentally invokes
# this while the clean control still runs. Do not write to the converted OS.
Need ([IO.Path]::IsPathRooted($ReceiptPath)-and-not(Test-Path -LiteralPath $ReceiptPath)) 'A new absolute receipt path is required'
$parent=Split-Path -Parent $ReceiptPath
$directory=Get-Item -LiteralPath $parent -Force
while($null-ne$directory){
    Need ($directory.PSIsContainer-and-not($directory.Attributes-band[IO.FileAttributes]::ReparsePoint)) 'Receipt ancestors must be ordinary existing directories'
    $directory=$directory.Parent
}
$receiptVolumes=@(Get-Volume -FilePath $parent)
Need ($receiptVolumes.Count-eq1) 'Receipt directory must identify one actual local volume'
$receiptVolume=$receiptVolumes[0]
$receiptPartitions=@(Get-Partition|Where-Object {@($_.AccessPaths)-contains[string]$receiptVolume.UniqueId})
Need ($receiptPartitions.Count-eq1-and$receiptPartitions[0].DiskNumber-ne0-and$receiptPartitions[0].IsOffline-eq$false-and$receiptPartitions[0].IsReadOnly-eq$false) 'Receipt storage must be online outside original source disk0'

$result=[ordered]@{
    schema_version=1;kind='actual-original-Windows-partition-ReFS-boot-v1';status='observing'
    conversion_run_id=$ConversionRunId;previous_boot_ms=$PreviousBootUnixMs;known_control_boot_ms=1793995332223L
    actual_boot_verified=$false;original_source_partition_boot_verified=$false
    source_filesystem_now_refs=$false;clean_install_control_observed=$false
    conversion_proven_by_this_observer=$false;conversion_handoff_evidence_required_separately=$true
    observer_boot_order_changes=0;observer_snapshot_calls=0;observer_conversion_or_recovery_calls=0
    observer_source_mutations_requested=0;receipt_storage_disk=$receiptPartitions[0].DiskNumber
    receipt_volume_unique_id=[string]$receiptVolume.UniqueId
    created_utc=[DateTime]::UtcNow.ToString('o')
}
$failure=$null
try{
    $os=Get-CimInstance Win32_OperatingSystem
    $version=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $setup=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\Setup'
    $boot=[DateTimeOffset]::new($os.LastBootUpTime.ToUniversalTime()).ToUnixTimeMilliseconds()
    $result.actual_boot_ms=$boot;$result.windows_directory=$os.WindowsDirectory;$result.system_drive=$os.SystemDrive
    $result.build="$($version.CurrentBuildNumber).$($version.UBR)";$result.edition=$version.EditionID
    $result.system_setup_in_progress=$setup.SystemSetupInProgress;$result.oobe_in_progress=$setup.OOBEInProgress
    Need ($PreviousBootUnixMs-ge1793995332223L-and$boot-gt$PreviousBootUnixMs) 'A genuinely newer Windows boot than the alternate ReFS control is required'
    Need ($os.WindowsDirectory-ieq'C:\Windows'-and$os.SystemDrive-ieq'C:'-and[Environment]::SystemDirectory-ieq'C:\Windows\System32') 'The actual running installed Windows must be C:\Windows'
    Need ($setup.SystemSetupInProgress-eq0-and$setup.OOBEInProgress-eq0) 'Windows setup or OOBE is still active'
    $secure=Confirm-SecureBootUEFI;$result.secure_boot=$secure;Need ($secure-eq$true) 'Secure Boot is not positively enabled'
    $partitions=@(Get-Partition -DriveLetter C);Need ($partitions.Count-eq1) 'Running C must identify exactly one partition'
    $partition=$partitions[0];$disk=Get-Disk -Number $partition.DiskNumber;$volume=Get-Volume -DriveLetter C
    $result.boot_disk_number=$disk.Number;$result.boot_disk_unique_id=[string]$disk.UniqueId
    $result.boot_disk_guid=([guid]$disk.Guid).ToString('D');$result.boot_disk_bytes=[long]$disk.Size
    $result.boot_partition_number=$partition.PartitionNumber;$result.boot_partition_guid=([guid]$partition.Guid).ToString('D')
    $result.boot_partition_offset=[long]$partition.Offset;$result.boot_partition_bytes=[long]$partition.Size
    $result.filesystem=[string]$volume.FileSystem;$result.cluster_bytes=[long]$volume.AllocationUnitSize
    $result.volume_label=[string]$volume.FileSystemLabel;$result.health=[string]$volume.HealthStatus
    $result.clean_install_control_observed=($disk.Number-eq1-or[guid]$disk.Guid-eq[guid]'91dd2cc0-4ec1-4f92-a924-870e4f16c0fb')
    Need ($disk.Number-eq0-and[guid]$disk.Guid-eq[guid]'1f804918-e98f-4a71-9022-fc00c3cb7c26'-and[string]$disk.UniqueId-ceq'60022480BEA35BA9D496D5AFF633D768'-and$disk.Size-eq64GB) 'Windows is not running on the original source disk; the clean disk1 control does not satisfy conversion boot'
    Need ($disk.IsBoot-eq$true-and$disk.IsOffline-eq$false-and$disk.IsReadOnly-eq$false-and$partition.IsBoot-eq$true-and$partition.IsReadOnly-eq$false) 'Actual original boot disk/OS partition roles must be positively online and writable'
    Need ($partition.PartitionNumber-eq3-and[guid]$partition.Guid-eq[guid]'c6c3318f-a7c8-47b9-be6d-6dde5e00862f'-and$partition.Offset-eq331350016L-and$partition.Size-eq66236448768L) 'Running OS does not use the original normalized source partition identity/extent'
    Need ($volume.FileSystem-ceq'ReFS'-and$volume.AllocationUnitSize-eq4096-and[string]$volume.HealthStatus-ceq'Healthy') 'Original OS partition is not healthy ReFS with 4KiB clusters'
    $fsutil=Join-Path ([Environment]::SystemDirectory) 'fsutil.exe'
    $volumeInfo=@(& $fsutil fsinfo volumeinfo C: 2>&1);$volumeExit=$LASTEXITCODE
    $refsInfo=@(& $fsutil fsinfo refsinfo C: 2>&1);$refsExit=$LASTEXITCODE
    $result.native_volume_info=$volumeInfo;$result.native_refs_info=$refsInfo
    $result.native_volume_info_exit=$volumeExit;$result.native_refs_info_exit=$refsExit
    Need ($volumeExit-eq0-and($volumeInfo-join"`n")-match'(?im)^\s*File System Name\s*:\s*ReFS\s*$') 'Native filesystem query does not confirm ReFS on actual running C'
    Need ($refsExit-eq0-and($refsInfo-join"`n")-match'(?im)^\s*ReFS Version\s*:\s*3\.14\s*$') 'Native ReFS query does not confirm format 3.14'
    $result.refs_version='3.14'
    $components=@()
    foreach($pin in @(
        @{relative='System32\winload.efi';sha256='1c1a978448b8e0fc2284c13d6e55fde8bf9827dca432cdc8a9be66c2e729adda'},
        @{relative='System32\drivers\refs.sys';sha256='3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4'}
    )){
        $path=Join-Path $os.WindowsDirectory $pin.relative;$file=Get-Item -LiteralPath $path
        Need (-not$file.PSIsContainer-and-not($file.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$file.Length-gt0) 'Stock boot component must be an ordinary file'
        $digest=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $signature=Get-AuthenticodeSignature -LiteralPath $path
        Need ($digest-ceq$pin.sha256-and$signature.Status-eq'Valid'-and$null-ne$signature.SignerCertificate-and$signature.SignerCertificate.Subject-match'Microsoft') 'Running stock loader/ReFS driver hash or Microsoft signature differs'
        $components+=@{relative=$pin.relative;bytes=$file.Length;version=$file.VersionInfo.FileVersion;sha256=$digest;signature=[string]$signature.Status;signer=$signature.SignerCertificate.Subject}
    }
    $result.components=$components
    $result.pagefiles=@(Get-CimInstance Win32_PageFileUsage|Select-Object Name,AllocatedBaseSize,CurrentUsage,PeakUsage)
    $result.system_partitions=@(Get-Partition|Where-Object{$_.IsSystem}|Select-Object DiskNumber,PartitionNumber,Guid,Offset,Size)
    $result.actual_boot_verified=$true;$result.original_source_partition_boot_verified=$true
    $result.source_filesystem_now_refs=$true;$result.status='original-source-ReFS-Windows-boot-observed'
}catch{$failure=$_;$result.status='refused';$result.error=($_|Out-String)}

$wire=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 12))
Need ($wire.Length-le1MB) 'Boot receipt exceeds its bounded metadata size'
$file=[IO.File]::Open($ReceiptPath,'CreateNew','Write','Read')
try{$file.Write($wire,0,$wire.Length);$file.Flush($true)}finally{$file.Dispose()}
[pscustomobject]@{path=$ReceiptPath;bytes=$wire.Length;sha256=(Hash $wire);actual_boot_verified=$result.actual_boot_verified;status=$result.status}|ConvertTo-Json -Compress
if($null-ne$failure){throw $failure}
