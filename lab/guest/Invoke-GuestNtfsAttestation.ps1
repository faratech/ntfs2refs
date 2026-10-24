<# Restore the frozen 1 GiB NTFS corpus on the owned blank lab target, then
query it read-only. Fixture staging is separate from the converter. #>
[CmdletBinding()]
param([Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$RunId,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$NativeSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BinarySha256)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$root='C:\ntfs2refs\ntfs-attestation\'+$RunId
$sourceSha='86573a248b1ba615940688d1a60014a74a997bff779faa51ce781899f2e94727'
$inspectionSha='a1b25e0e0bcabe41455fd67a25c55b7017b6b8da9ac6437e0c062b7dc2b86baa'
function Save-NewJson([string]$Path,$Value){$b=(New-Object Text.UTF8Encoding($false)).GetBytes(($Value|ConvertTo-Json -Depth 32));$f=New-Object IO.FileStream($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Pin([string]$Name,[string]$Hash,[long]$Max){$p=Join-Path $root $Name;$f=Get-Item -LiteralPath $p -Force;if($f.PSIsContainer -or ($f.Attributes-band[IO.FileAttributes]::ReparsePoint) -or $f.Length-gt$Max -or (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()-cne$Hash){throw ('Artifact differs: '+$Name)};return $p}
function Target { $d=Get-Disk -Number 1;if([string]$d.UniqueId-cne'60022480D091C4251B5FFD619706C2B5'-or$d.Size-ne64GB-or$d.IsBoot-or$d.IsSystem-or$d.LogicalSectorSize-ne512-or$d.PhysicalSectorSize-ne4096){throw 'Original disposable target identity/geometry differs.'};$d }
$result=[ordered]@{schemaVersion=1;kind='native-ntfs-file-attestation-guest';runId=$RunId;status='started';phase='preflight';error=$null;stagingBytesWritten=0;beforeSha256=$null;afterSha256=$null;readOnlyMount=$false;collectorExitCode=$null;nativeReportSha256=$null;conversionQualified=$false;startedUtc=[DateTime]::UtcNow.ToString('o')}
try {
 $c=Get-CimInstance Win32_ComputerSystem;if($env:COMPUTERNAME-cne'N2R-WIN11'-or$c.Manufacturer-cne'Microsoft Corporation'-or$c.Model-cne'Virtual Machine'){throw 'Exact disposable guest required.'}
 foreach($p in @('C:\','C:\ntfs2refs','C:\ntfs2refs\ntfs-attestation',$root)){$f=Get-Item -LiteralPath $p -Force;if(-not$f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary artifact ancestry required.'}}
 $native=Pin 'NativeNtfsCorpusDisk.cs' $NativeSha256 64KB;$binary=Pin 'lab-ntfs-attest.exe' $BinarySha256 16MB
 $source=Pin 'control.raw' $sourceSha 1GB;$inspection=Pin 'control.json' $inspectionSha 1MB
 $raw=(Get-Content -LiteralPath $inspection -Raw|ConvertFrom-Json).filesystem.details
 $d=Target;if($d.PartitionStyle-cne'RAW'-or@(Get-Partition -DiskNumber 1 -ErrorAction SilentlyContinue).Count-or$d.IsReadOnly){throw 'Blank writable target required; never clear an existing layout.'}
 if(Test-Path 'F:\'){throw 'F: is already assigned.'}
 Add-Type -TypeDefinition (Get-Content -LiteralPath $native -Raw)
 $result.phase='partition';if($d.IsOffline){Set-Disk -Number 1 -IsOffline $false};Initialize-Disk -Number 1 -PartitionStyle GPT|Out-Null
 $p=New-Partition -DiskNumber 1 -Offset 16MB -Size 1GB -GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'
 $d=Target;if($p.PartitionNumber-ne2-or$p.Offset-ne16MB-or$p.Size-ne1GB-or$p.IsBoot-or$p.IsSystem){throw 'New corpus partition geometry differs.'}
 $result['diskGuid']=[string]$d.Guid;$result['partitionGuid']=[string]$p.Guid
 Set-Disk -Number 1 -IsOffline $true
 $result.phase='restore-frozen-source';$result.stagingBytesWritten=[Ntfs2Refs.NativeNtfsCorpusDisk]::Restore($source,$sourceSha,[guid]$d.Guid,[guid]$p.Guid)
 $result.beforeSha256=$sourceSha
 Set-Disk -Number 1 -IsReadOnly $true
 Set-Disk -Number 1 -IsOffline $false
 $d=Target;if(-not$d.IsReadOnly-or$d.IsOffline){throw 'Require online read-only target.'}
 Add-PartitionAccessPath -DiskNumber 1 -PartitionNumber 2 -AccessPath 'F:\'
 $p=Get-Partition -DiskNumber 1 -PartitionNumber 2
 $volumes=@($p.AccessPaths|Where-Object {$_-cmatch '\A\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\\z'})
 if($volumes.Count-ne1){throw 'Unique volume GUID path absent.'}
 $v=Get-Volume -DriveLetter F;if($v.FileSystem-cne'NTFS'-or$v.FileSystemLabel-cne'ntfs2refs-target'-or$v.AllocationUnitSize-ne4096){throw 'Frozen native NTFS filesystem not discovered.'}
 $result.readOnlyMount=$true;$result['volumeGuid']=$volumes[0]
 $request=[ordered]@{schema_version=1;source_inspection_sha256=$inspectionSha;volume=$volumes[0];disk_number=1;partition_offset=16MB;partition_length=1GB;ntfs_serial=$raw.geometry.serial_number;files=@($raw.files|ForEach-Object{[ordered]@{record_number=$_.record_number;sequence_number=$_.sequence_number}})}
 $requestPath=Join-Path $root 'request.json';Save-NewJson $requestPath $request
 $requestSha=(Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant();$result['requestSha256']=$requestSha
 $result.phase='collect';$psi=New-Object Diagnostics.ProcessStartInfo;$psi.FileName=$binary;$psi.Arguments='collect --request "'+$requestPath+'" --request-sha256 '+$requestSha+' --output "'+(Join-Path $root 'native.json')+'"';$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
 $proc=New-Object Diagnostics.Process;$proc.StartInfo=$psi;if(-not$proc.Start()){throw 'Collector did not start.'};$outTask=$proc.StandardOutput.ReadToEndAsync();$errTask=$proc.StandardError.ReadToEndAsync();if(-not$proc.WaitForExit(120000)){throw 'Collector still running; preserve branch and process.'}
 $result.collectorExitCode=$proc.ExitCode;[IO.File]::WriteAllText((Join-Path $root 'collector.stdout'),$outTask.Result);[IO.File]::WriteAllText((Join-Path $root 'collector.stderr'),$errTask.Result)
 $result.phase='verify-unchanged';$result.afterSha256=[Ntfs2Refs.NativeNtfsCorpusDisk]::Hash([guid]$d.Guid,[guid]$p.Guid,2)
 if($result.afterSha256-cne$sourceSha){throw 'Read-only corpus changed.'}
 if($proc.ExitCode-ne0){throw 'Collector failed; see archived stderr.'}
 $result.nativeReportSha256=(Get-FileHash -LiteralPath (Join-Path $root 'native.json') -Algorithm SHA256).Hash.ToLowerInvariant()
 $result.status='collected';$result.phase='complete'
}catch{$result.status='failed';$result.error=$_.Exception.ToString()}
$result['finishedUtc']=[DateTime]::UtcNow.ToString('o');Save-NewJson (Join-Path $root 'guest-result.json') $result
[pscustomobject]$result
