<# Observe an actually booted native control. Read-only OS/volume queries plus
   one new JSON receipt; this never selects boot, formats, or converts a disk. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$RunId,
    [Parameter(Mandatory)][string]$PreparationBase64,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$PreparationSha256,
    [Parameter(Mandatory)][long]$PreviousBootUnixMs,
    [Parameter(Mandatory)][string]$ReceiptPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Need([bool]$Ok,[string]$Message){if(-not $Ok){throw $Message}}
function Hash([byte[]]$Bytes){$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
$wire=[Convert]::FromBase64String($PreparationBase64)
Need ($wire.Length-gt0-and$wire.Length-le1MB-and(Hash $wire)-ceq$PreparationSha256) 'Exact bounded raw preparation JSON required'
$prepared=[Text.Encoding]::UTF8.GetString($wire).TrimStart([char]0xfeff)|ConvertFrom-Json
Need ($prepared.runId-ceq$RunId-and$prepared.status-ceq'prepared'-and$prepared.formatSucceeded-and$prepared.imageApplied-and$prepared.bootFilesPrepared-and$prepared.firstBootConfigured) 'Native preparation did not complete'
Need ($prepared.expectedFilesystem-cin@('NTFS','ReFS')-and$prepared.sourceVolumeConverted-eq$false) 'Only a native installation control is observed here'
$os=Get-CimInstance Win32_OperatingSystem
$version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$setup=Get-ItemProperty 'HKLM:\SYSTEM\Setup'
$boot=[DateTimeOffset]::new($os.LastBootUpTime.ToUniversalTime()).ToUnixTimeMilliseconds()
Need ($PreviousBootUnixMs-gt0-and$boot-gt$PreviousBootUnixMs) 'A new actual Windows boot is required'
Need ($os.WindowsDirectory-ieq'C:\Windows'-and$os.SystemDrive-ieq'C:'-and$env:SystemRoot-ieq$os.WindowsDirectory) 'The running OS must be installed Windows on C'
Need ($version.EditionID-ceq'Professional'-and"$($version.CurrentBuildNumber).$($version.UBR)"-ceq'26300.9457') 'Running Windows differs from the prepared image'
Need ($setup.SystemSetupInProgress-eq0-and$setup.OOBEInProgress-eq0) 'Windows setup is not complete'
Need (Confirm-SecureBootUEFI) 'Secure Boot changed'
$partitions=@(Get-Partition -DriveLetter C)
Need ($partitions.Count-eq1) 'Running C partition must resolve uniquely'
$partition=$partitions[0];$disk=Get-Disk -Number $partition.DiskNumber;$volume=Get-Volume -DriveLetter C
Need ($disk.IsBoot-and-not$disk.IsOffline-and-not$disk.IsReadOnly-and$partition.IsBoot-and-not$partition.IsReadOnly) 'Actual boot disk/partition must be online and writable'
Need ([string]$disk.UniqueId-ceq$prepared.target.guest.uniqueId-and[string]$disk.UniqueId-cne$prepared.sourceOs.uniqueId-and$disk.Size-eq64GB) 'Windows booted the original NTFS disk or another disk'
Need ($volume.FileSystem-ceq$prepared.expectedFilesystem-and$volume.AllocationUnitSize-eq4096-and[string]$volume.HealthStatus-ceq'Healthy') 'Running OS filesystem differs from the native candidate'
$expected=@($prepared.partitions|Where-Object {$_.DriveLetter-and$_.DriveLetter-ceq$prepared.formatRequest.volume.Substring(0,1)})
Need ($expected.Count-eq1-and$partition.Offset-eq$expected[0].Offset-and$partition.Size-eq$expected[0].Size) 'Running boot partition differs from the prepared extent'
$marker=Get-Content -LiteralPath 'C:\ntfs2refs\refs-os-control.json' -Raw -Encoding UTF8|ConvertFrom-Json
Need ($marker.purpose-ceq'native-boot-filesystem-control'-and$marker.targetUniqueId-ceq$disk.UniqueId-and$marker.sourceOsUniqueId-ceq$prepared.sourceOs.uniqueId-and$marker.expectedFilesystem-ceq$volume.FileSystem) 'Prepared OS marker differs'
$fsinfo=@(& "$env:SystemRoot\System32\fsutil.exe" fsinfo volumeinfo C: 2>&1)
Need ($LASTEXITCODE-eq0-and($fsinfo-join"`n")-match('File System Name\s*:\s*'+[regex]::Escape($prepared.expectedFilesystem))) 'Native filesystem query does not confirm the boot filesystem'
$components=@()
foreach($relative in @('System32\winload.efi','System32\drivers\refs.sys')){
    $path=Join-Path $os.WindowsDirectory $relative;$file=Get-Item -LiteralPath $path;$signature=Get-AuthenticodeSignature -LiteralPath $path
    Need (-not$file.PSIsContainer-and$file.Length-gt0-and$signature.Status-eq'Valid') 'Running boot component lacks its expected Microsoft signature'
    $pin=@($prepared.bootFiles|Where-Object {$_.path.EndsWith('\Windows\'+$relative,[StringComparison]::OrdinalIgnoreCase)})
    $digest=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    Need ($pin.Count-eq1-and$digest-ceq$pin[0].sha256) 'Running loader/driver differs from the prepared stock component'
    $components+=@{relative=$relative;bytes=$file.Length;version=$file.VersionInfo.FileVersion;sha256=$digest;signature=[string]$signature.Status}
}
$result=[ordered]@{
    schema_version=1;kind='actual-native-Windows-boot-filesystem-control-v1';run_id=$RunId
    actual_boot_verified=$true;converted_boot_volume_qualified=$false;source_volume_converted=$false
    preparation_sha256=$PreparationSha256;previous_boot_ms=$PreviousBootUnixMs;actual_boot_ms=$boot
    computer_name=$env:COMPUTERNAME;windows_directory=$os.WindowsDirectory;system_drive=$os.SystemDrive
    build="$($version.CurrentBuildNumber).$($version.UBR)";filesystem=$volume.FileSystem;cluster_bytes=$volume.AllocationUnitSize
    boot_disk_number=$disk.Number;boot_disk_unique_id=[string]$disk.UniqueId;boot_disk_guid=([guid]$disk.Guid).ToString('D')
    boot_partition_number=$partition.PartitionNumber;boot_partition_guid=([guid]$partition.Guid).ToString('D')
    boot_partition_offset=$partition.Offset;boot_partition_bytes=$partition.Size;secure_boot=$true;components=$components
    native_volume_info=$fsinfo;pagefiles=@(Get-CimInstance Win32_PageFileUsage|Select-Object Name,AllocatedBaseSize,CurrentUsage,PeakUsage)
    boot_order_changes=0;snapshot_calls=0;conversion_or_recovery_calls=0;created_utc=[DateTime]::UtcNow.ToString('o')
}
Need ([IO.Path]::IsPathRooted($ReceiptPath)-and-not(Test-Path -LiteralPath $ReceiptPath)) 'New absolute receipt path required'
$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 12))
$file=[IO.File]::Open($ReceiptPath,'CreateNew','Write','Read');try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
[pscustomobject]@{path=$ReceiptPath;bytes=$bytes.Length;sha256=(Hash $bytes);actual_boot_verified=$true;converted_boot_volume_qualified=$false}|ConvertTo-Json -Compress
