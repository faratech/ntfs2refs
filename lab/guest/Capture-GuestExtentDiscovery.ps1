<# Read-only guest discovery. Placement is a separate experiment after matching
   native address hypotheses against the independently captured raw partition. #>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')][string]$ControlRunId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ControlEvidenceSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$CapturedAllocationSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')][string]$DiscoveryId
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if (-not $PSCmdlet.ShouldProcess('Owned ReFS target','Read retrieval base and allocation bitmap twice; hash existing fixture; write evidence on C: only')) {
    [pscustomobject]@{DryRun=$true;Phase='ReadOnlyDiscovery';ControlRunId=$ControlRunId;SourceWriteRequestsIssued=$false;PlacementImplemented=$false;RawDiskWrites=$false}; return
}
function Read-ExtentDiscoveryJson([string]$Path,[long]$MaximumBytes=1MB) {
    $file=Get-Item -LiteralPath $Path -Force
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -lt 1 -or $file.Length -gt $MaximumBytes) { throw 'Expected a bounded ordinary evidence file.' }
    [IO.File]::ReadAllText($file.FullName,(New-Object Text.UTF8Encoding($false,$true))) | ConvertFrom-Json
}
function Assert-ExtentDiscoveryControl($Control,[string]$ExpectedRunId) {
    if ($Control.schemaVersion -ne 1 -or $Control.kind -cne 'devdrive-data-control' -or $Control.phase -cne 'Verify' -or $Control.runId -cne $ExpectedRunId -or $Control.status -cne 'verified' -or $Control.formatSucceeded -ne $true -or $Control.remountVerified -ne $true -or $Control.ordinaryReFS -ne $false -or $Control.refsBootVerified -ne $false -or $Control.conversionQualified -ne $false) { throw 'The native Dev Drive data control has not completed.' }
    if ([string]$Control.target.host.vhdId -ine '25C491D0-5F1B-4205-9E6F-FD619706C2B5' -or $Control.target.host.sizeBytes -ne 64GB -or $Control.target.host.controllerLocation -ne 1 -or $Control.target.guest.uniqueId -cne '60022480D091C4251B5FFD619706C2B5' -or $Control.target.guest.role -cne 'target' -or $Control.target.guest.sizeBytes -ne 64GB) { throw 'Control target differs from the original owned virtual disk.' }
    $part=$Control.partition
    foreach($name in @('guid','diskGuid')) { $id=[guid]::Empty; if(-not [guid]::TryParse([string]$part.$name,[ref]$id) -or $id -eq [guid]::Empty) { throw 'Missing native GPT identity.' } }
    if ($part.number -ne 2 -or $part.offset -ne 16MB -or $part.length -ne 52GB -or $part.letter -cne 'F' -or $part.logicalSectorSize -ne 512 -or $part.physicalSectorSize -ne 4096 -or $Control.after.filesystem -cne 'ReFS' -or $Control.after.allocationUnitSize -ne 4096 -or $Control.after.size -ne 52GB) { throw 'Native partition profile differs.' }
}
function Get-ExtentDiscoveryTarget($Identity,$Control) {
    $disk=Get-LabGuestDisk $Identity
    $parts=@(Get-Partition -DiskNumber $disk.Number | Where-Object { $_.DriveLetter })
    if ($parts.Count -ne 1) { throw 'Expected one mounted target partition.' }
    $part=$parts[0]; $expected=$Control.partition
    if ([string]$disk.Guid -ine [string]$expected.diskGuid -or [string]$part.Guid -ine [string]$expected.guid -or $part.PartitionNumber -ne $expected.number -or $part.Offset -ne $expected.offset -or $part.Size -ne $expected.length -or [string]$part.DriveLetter -cne $expected.letter -or $part.IsBoot -or $part.IsSystem -or $disk.LogicalSectorSize -ne 512 -or $disk.PhysicalSectorSize -ne 4096) { throw 'Target GPT, geometry or role changed.' }
    $bound=@(Get-Partition -DriveLetter F)
    if ($bound.Count -ne 1 -or $bound[0].DiskNumber -ne $disk.Number -or [string]$bound[0].Guid -ine [string]$expected.guid) { throw 'Target drive letter changed.' }
    $vol=Get-Volume -DriveLetter F
    if ($vol.FileSystem -cne 'ReFS' -or $vol.FileSystemLabel -cne 'ntfs2refs-target' -or $vol.AllocationUnitSize -ne 4096 -or $vol.Size -ne 52GB) { throw 'Unexpected target filesystem.' }
    [pscustomobject]@{disk=$disk;partition=$part;volume=$vol}
}
function Get-ExtentDiscoveryFixture($Evidence,$Identity) {
    if ($Evidence.schemaVersion -ne 1 -or $Evidence.kind -cne 'native-file-allocation-observations' -or $Evidence.complete -ne $true -or $Evidence.diskIdentity.uniqueId -cne $Identity.uniqueId -or $Evidence.diskIdentity.location -cne $Identity.location -or $Evidence.diskIdentity.sizeBytes -ne 64GB -or $Evidence.volume.fileSystem -cne 'ReFS' -or $Evidence.volume.allocationUnitSize -ne 4096 -or $Evidence.volume.size -ne 52GB -or $Evidence.partition.number -ne 2 -or $Evidence.partition.offset -ne 16MB -or $Evidence.partition.size -ne 52GB -or $Evidence.logicalSectorSize -ne 512 -or $Evidence.physicalSectorSize -ne 4096) { throw 'Allocation evidence is incomplete or belongs to another target.' }
    if($Evidence.windowsBuild -cne '26300.9457' -or $Evidence.filesystemDriver.name -cne 'refs.sys' -or $Evidence.filesystemDriver.sha256 -cne '3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4') { throw 'Native ReFS driver profile changed.' }
    $files=@($Evidence.files | Where-Object { $_.path -ceq 'fixtures\nonresident.bin' -and $_.stream -ceq ':$DATA' })
    if ($files.Count -ne 1) { throw 'Expected the explicit unique-pattern fixture.' }
    $file=$files[0].observation
    if ($file.complete -ne $true -or $file.stableDuringObservation -ne $true -or $file.status -cne 'mapping-returned' -or $file.length -ne 4MB -or $file.sha256 -cnotmatch '^[0-9a-f]{64}$' -or @($file.extents).Count -lt 1 -or @($file.extents).Count -gt 1024) { throw 'Fixture mapping or logical content is unqualified.' }
    $next=[long]0
    foreach($extent in $file.extents) {
        if ($extent.startingVcn -ne $next -or $extent.nextVcn -le $next -or $extent.nextVcn -gt 1024 -or $extent.lcn -lt 0 -or $extent.lcn -gt ((52GB/4096)-($extent.nextVcn-$next))) { throw 'Fixture has an unexpected or unbounded native mapping.' }
        $next=[long]$extent.nextVcn
    }
    if ($next -ne 1024) { throw 'Fixture mapping does not cover the complete 4 MiB stream.' }
    $file
}
function Test-ExtentDiscoverySameMapping($Left,$Right) {
    if ($Left.fileId64 -cne $Right.fileId64 -or $Left.volumeSerialHex -cne $Right.volumeSerialHex -or $Left.length -ne $Right.length -or $Left.sha256 -cne $Right.sha256 -or @($Left.extents).Count -ne @($Right.extents).Count) { return $false }
    for($i=0;$i -lt @($Left.extents).Count;$i++) { foreach($name in @('startingVcn','nextVcn','lcn')) { if($Left.extents[$i].$name -ne $Right.extents[$i].$name) { return $false } } }
    $true
}
Import-Module (Join-Path $PSScriptRoot 'GuestLab.psm1') -Force
$computer=Get-CimInstance Win32_ComputerSystem
if($env:COMPUTERNAME -cne 'N2R-WIN11' -or $env:SystemDrive -cne 'C:' -or $computer.Manufacturer -cne 'Microsoft Corporation' -or $computer.Model -cne 'Virtual Machine' -or -not [Environment]::Is64BitProcess) { throw 'Discovery must run inside the owned 64-bit Windows 11 guest.' }
$version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if($version.EditionID -cne 'Professional' -or $version.CurrentBuildNumber -cne '26300' -or $version.UBR -ne 9457) { throw 'Unexpected native Windows profile.' }
$nativeSource=Get-Item -LiteralPath (Join-Path $PSScriptRoot 'NativeExtentDiscovery.cs') -Force
if($nativeSource.PSIsContainer -or ($nativeSource.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $nativeSource.Length -lt 1 -or $nativeSource.Length -gt 64KB) { throw 'Unexpected native discovery source.' }
if(-not ('Ntfs2Refs.NativeExtentDiscovery' -as [type])) { Add-Type -Path $nativeSource.FullName }
$nativeSourceSha256=(Get-FileHash -LiteralPath $nativeSource.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
$controlRoot='C:\ntfs2refs\devdrive-control'
foreach($path in @('C:\ntfs2refs',$controlRoot)) { $item=Get-Item -LiteralPath $path -Force; if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected evidence parent directory.' } }
$verifyPath=Join-Path $controlRoot 'verify.json'; $capturedPath=Join-Path $controlRoot 'allocation-after.json'; $manifestPath=Join-Path $controlRoot 'target.json'
if((Get-FileHash -LiteralPath $verifyPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ControlEvidenceSha256 -or (Get-FileHash -LiteralPath $capturedPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $CapturedAllocationSha256) { throw 'Guest native evidence differs from the verified host exports.' }
$control=Read-ExtentDiscoveryJson $verifyPath
Assert-ExtentDiscoveryControl $control $ControlRunId
$identity=Read-ExtentDiscoveryJson $manifestPath 64KB
foreach($name in @('schemaVersion','role','uniqueId','serialNumber','serialNumberAvailable','sizeBytes','location','enrolledUtc')) { if([string]$identity.$name -cne [string]$control.target.guest.$name) { throw 'Guest enrollment changed.' } }
$captured=Read-ExtentDiscoveryJson $capturedPath
$capturedFixture=Get-ExtentDiscoveryFixture $captured $identity
$expectedFile=@($control.after.files | Where-Object name -CEQ 'nonresident.bin')
if($expectedFile.Count -ne 1 -or $expectedFile[0].length -ne 4MB -or $expectedFile[0].sha256 -cne $capturedFixture.sha256) { throw 'Native fixture hash evidence disagrees.' }
$target=Get-ExtentDiscoveryTarget $identity $control
[Ntfs2Refs.NativeExtentDiscovery]::ValidateVolumeName([string]$target.volume.UniqueId) | Out-Null
$outputParent='C:\ntfs2refs\extent-discovery'
if(Test-Path -LiteralPath $outputParent) { $item=Get-Item -LiteralPath $outputParent -Force; if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected discovery output parent.' } }
else { New-Item -ItemType Directory -Path $outputParent | Out-Null }
$outputRoot=Join-Path $outputParent $DiscoveryId
if(Test-Path -LiteralPath $outputRoot) { throw 'Discovery output exists; no overwrite is allowed.' }
New-Item -ItemType Directory -Path $outputRoot | Out-Null
$record=[ordered]@{schemaVersion=1;kind='native-extent-discovery';phase='ReadOnlyDiscovery';discoveryId=$DiscoveryId;controlRunId=$ControlRunId;status='started';controlEvidenceSha256=$ControlEvidenceSha256;capturedAllocationSha256=$CapturedAllocationSha256;scriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();nativeSourceSha256=$nativeSourceSha256;target=$identity;partition=$control.partition;volumeUniqueId=[string]$target.volume.UniqueId;nativeQueries=@();baseSectorOffset=$null;bitmapObservations=@();freeRangesObservedInBoth=@();addressHypotheses=@();fixtureMappingUnchangedFromCapture=$false;fixtureStableDuringDiscovery=$false;fixtureBitsAllocatedInBoth=$false;sourceWriteRequestsIssued=$false;moveImplemented=$false;moveAttempted=$false;nativeMoveSupport='unmeasured';physicalMappingVerified=$false;payloadCopyAvoidanceVerified=$false;conversionQualified=$false;errors=@();createdUtc=[DateTime]::UtcNow.ToString('o')}
$record['queryProfile']=[pscustomobject]@{volumeAccess='GENERIC_READ';volumeShare='READ|WRITE';startingLcn=0;maximumBitmapBytes=2MB;legacyInputBytes=8;extendedInputBytes=16;extendedFlags=@(0,1);minimumCandidateLcn=65536;candidateClusters=16;candidateAlignmentClusters=16;maximumCandidates=8;metadataCoverageQualified=$false}
function Save-ExtentDiscoveryQuery([string]$Name,$Query) {
    $bufferPath=$null; $bufferSha=$null
    if($Query.bytes.Length) {
        $bufferPath=Join-Path $outputRoot ($Name+'.bin')
        [Ntfs2Refs.NativeAllocationEvidence]::WriteReport($bufferPath,$Query.bytes)
        $bufferSha=(Get-FileHash -LiteralPath $bufferPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    [pscustomobject]@{name=$Name;controlCode=('0x{0:x8}' -f $Query.controlCode);inputBytes=$Query.inputBytes;inputHex=$Query.inputHex;outputCapacityBytes=$Query.outputCapacityBytes;succeeded=$Query.succeeded;nativeError=$Query.nativeError;nativeMessage=$Query.nativeMessage;bytesReturned=$Query.bytesReturned;bufferPath=$bufferPath;bufferSha256=$bufferSha;startedUtc=$Query.startedUtc;finishedUtc=$Query.finishedUtc}
}
function Get-ExtentDiscoveryBitmapSummary([string]$Name,$Bitmap) {
    $samples=@()
    if($Bitmap.allDeclaredBitsPresent) {
        foreach($sample in @(@('payload-native-lcn',1507328),@('raw-superblock-cluster-as-lcn',30),@('raw-superblock-copy-1-cluster-as-lcn',13631485),@('raw-superblock-copy-2-cluster-as-lcn',13631486),@('raw-checkpoint-1-cluster-as-lcn',136348),@('raw-checkpoint-2-cluster-as-lcn',1635808))) {
            $samples+=[pscustomobject]@{label=$sample[0];queriedLcn=[long]$sample[1];allocated=[Ntfs2Refs.NativeExtentDiscovery]::AreAllocated($Bitmap,[long]$sample[1],1);metadataAddressEquivalenceVerified=$false}
        }
    }
    [pscustomobject]@{name=$Name;startingLcn=$Bitmap.startingLcn;bitmapSize=$Bitmap.bitmapSize;representedClusters=$Bitmap.representedClusters;allocatedClusters=$Bitmap.allocatedClusters;freeClusters=$Bitmap.freeClusters;allDeclaredBitsPresent=$Bitmap.allDeclaredBitsPresent;samples=$samples;metadataCoverageQualified=$false}
}
try {
    & (Join-Path $PSScriptRoot 'Capture-GuestAllocation.ps1') -ManifestPath $manifestPath -FixtureRelativePath @('nonresident.bin') -OutputPath (Join-Path $outputRoot 'allocation-before.json') -MaximumHashMiB 8 | Out-Null
    $before=Read-ExtentDiscoveryJson (Join-Path $outputRoot 'allocation-before.json')
    $beforeFixture=Get-ExtentDiscoveryFixture $before $identity
    $record.fixtureMappingUnchangedFromCapture=Test-ExtentDiscoverySameMapping $capturedFixture $beforeFixture
    $current=Get-ExtentDiscoveryTarget $identity $control
    if([string]$current.volume.UniqueId -cne [string]$target.volume.UniqueId) { throw 'Volume identity changed before native queries.' }
    $native=[Ntfs2Refs.NativeExtentDiscovery]::Collect([string]$target.volume.UniqueId)
    $record['volumeOpen']=[pscustomobject]@{opened=$native.opened;nativeError=$native.openNativeError}
    if(-not $native.opened) { throw "Read-only volume open failed with native error $($native.openNativeError)." }
    foreach($name in @('baseBefore','bitmapBefore','bitmapExtendedFlags0','bitmapExtendedFlags1','baseAfter','bitmapAfter')) { $record.nativeQueries+=Save-ExtentDiscoveryQuery $name $native.$name }
    & (Join-Path $PSScriptRoot 'Capture-GuestAllocation.ps1') -ManifestPath $manifestPath -FixtureRelativePath @('nonresident.bin') -OutputPath (Join-Path $outputRoot 'allocation-after.json') -MaximumHashMiB 8 | Out-Null
    $after=Read-ExtentDiscoveryJson (Join-Path $outputRoot 'allocation-after.json')
    $afterFixture=Get-ExtentDiscoveryFixture $after $identity
    $record.fixtureStableDuringDiscovery=Test-ExtentDiscoverySameMapping $beforeFixture $afterFixture
    $current=Get-ExtentDiscoveryTarget $identity $control
    if([string]$current.volume.UniqueId -cne [string]$target.volume.UniqueId) { throw 'Volume identity changed after native queries.' }
    foreach($query in $record.nativeQueries) { if(-not $query.succeeded) { $record.errors+=('Native query '+$query.name+' returned '+$query.nativeError+'.') } }
    if($native.baseBefore.succeeded -and $native.baseAfter.succeeded) {
        $baseBefore=[Ntfs2Refs.NativeExtentDiscovery]::ParseBase($native.baseBefore.bytes,52GB,512)
        $baseAfter=[Ntfs2Refs.NativeExtentDiscovery]::ParseBase($native.baseAfter.bytes,52GB,512)
        if($baseBefore -ne $baseAfter) { throw 'Retrieval-pointer base changed during discovery.' }
        $record.baseSectorOffset=$baseBefore
        foreach($extent in $beforeFixture.extents) {
            $clusters=[long]($extent.nextVcn-$extent.startingVcn)
            $candidate=[Ntfs2Refs.NativeExtentDiscovery]::CandidateVolumeOffset($baseBefore,$extent.lcn,$clusters,512,4096,52GB)
            $record.addressHypotheses+=[pscustomobject]@{startingVcn=$extent.startingVcn;clusterCount=$clusters;lcn=$extent.lcn;baseSectorOffset=$baseBefore;logicalSectorBytes=512;clusterBytes=4096;candidateRawPartitionByteOffset=$candidate;candidateGuestDiskByteOffset=([long]$control.partition.offset+$candidate);lengthBytes=($clusters*4096);physicalMappingVerified=$false}
        }
    }
    if(($native.bitmapBefore.succeeded -or $native.bitmapBefore.nativeError -eq 234) -and ($native.bitmapAfter.succeeded -or $native.bitmapAfter.nativeError -eq 234)) {
        $bitmapBefore=[Ntfs2Refs.NativeExtentDiscovery]::ParseBitmap($native.bitmapBefore.bytes,[long](52GB/4096))
        $bitmapAfter=[Ntfs2Refs.NativeExtentDiscovery]::ParseBitmap($native.bitmapAfter.bytes,[long](52GB/4096))
        $record.bitmapObservations+=Get-ExtentDiscoveryBitmapSummary 'legacyBefore' $bitmapBefore
        $record.bitmapObservations+=Get-ExtentDiscoveryBitmapSummary 'legacyAfter' $bitmapAfter
        if($bitmapBefore.allDeclaredBitsPresent -and $bitmapAfter.allDeclaredBitsPresent) {
            $record.freeRangesObservedInBoth=@([Ntfs2Refs.NativeExtentDiscovery]::FindFreeRanges($bitmapBefore,$bitmapAfter,65536,16,8))
            $allAllocated=$true
            foreach($extent in $beforeFixture.extents) { $count=[long]($extent.nextVcn-$extent.startingVcn); if(-not [Ntfs2Refs.NativeExtentDiscovery]::AreAllocated($bitmapBefore,$extent.lcn,$count) -or -not [Ntfs2Refs.NativeExtentDiscovery]::AreAllocated($bitmapAfter,$extent.lcn,$count)) { $allAllocated=$false } }
            $record.fixtureBitsAllocatedInBoth=$allAllocated
            $record['legacyBitmapChangedBits']=[Ntfs2Refs.NativeExtentDiscovery]::CountDifferentBits($bitmapBefore,$bitmapAfter)
        } else { $record.errors+='The bounded bitmap response is incomplete.' }
    }
    $extended=@{}
    foreach($name in @('bitmapExtendedFlags0','bitmapExtendedFlags1')) {
        $query=$native.$name
        if($query.succeeded -or $query.nativeError -eq 234) {
            $parsed=[Ntfs2Refs.NativeExtentDiscovery]::ParseBitmap($query.bytes,[long](52GB/4096))
            $record.bitmapObservations+=Get-ExtentDiscoveryBitmapSummary $name $parsed
            $extended[$name]=$parsed
        }
    }
    if($extended.ContainsKey('bitmapExtendedFlags0') -and $extended.ContainsKey('bitmapExtendedFlags1') -and $extended['bitmapExtendedFlags0'].allDeclaredBitsPresent -and $extended['bitmapExtendedFlags1'].allDeclaredBitsPresent) { $record['extendedFlagsChangedBits']=[Ntfs2Refs.NativeExtentDiscovery]::CountDifferentBits($extended['bitmapExtendedFlags0'],$extended['bitmapExtendedFlags1']) }
    if(-not $record.fixtureMappingUnchangedFromCapture) { $record.errors+='Fixture mapping differs from the saved corpus capture; a fresh offline capture is required.' }
    if(-not $record.fixtureStableDuringDiscovery) { $record.errors+='Fixture mapping or logical bytes changed during discovery.' }
    if(-not $record.fixtureBitsAllocatedInBoth) { $record.errors+='Native file extents are not confirmed allocated in both complete bitmap observations.' }
    if($record.errors.Count -eq 0 -and $null -ne $record.baseSectorOffset -and $record.addressHypotheses.Count -gt 0) { $record.status='observed-awaiting-offline-payload-match' } else { $record.status='observed-with-unresolved-results' }
} catch {
    $record.status='blocked'; $record.errors+=$_.Exception.Message; $record['errorPosition']=$_.InvocationInfo.PositionMessage; $record['scriptStackTrace']=$_.ScriptStackTrace
} finally {
    $record['finishedUtc']=[DateTime]::UtcNow.ToString('o')
    $record['limitations']=@('Native bitmap freedom is a point-in-time observation, not a reservation or guarantee at a later move.','Candidate offsets use reconciled native sector/cluster units but remain hypotheses until exact payload bytes match an independently captured raw partition.','The WDK describes EX flag 1 as including metadata. User-mode acceptance, actual flag handling and complete ReFS metadata coverage are separate unqualified observations.','Differences between sequential bitmap requests may also reflect mounted-volume activity. Raw metadata cluster indices sampled as LCNs do not prove address-space equivalence.','This collector implements no movement, allocation, valid-data advancement, raw writes, mount/dismount or format operation.','Kernel calls are count/buffer bounded but synchronous; the host orchestrator must enforce an overall guest-process deadline.','Mounted source reads can cause filesystem access metadata updates; no source write requests are issued by this collector.')
    $json=$record | ConvertTo-Json -Depth 14
    $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes($json)
    if($bytes.Length -gt 1MB) { throw 'Discovery report exceeds its bound.' }
    if('Ntfs2Refs.NativeAllocationEvidence' -as [type]) { [Ntfs2Refs.NativeAllocationEvidence]::WriteReport((Join-Path $outputRoot 'discovery.json'),$bytes) }
    else { $out=New-Object IO.FileStream((Join-Path $outputRoot 'discovery.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None); try{$out.Write($bytes,0,$bytes.Length);$out.Flush($true)}finally{$out.Dispose()} }
}
[pscustomobject]@{Status=$record.status;DiscoveryId=$DiscoveryId;EvidenceDirectory=$outputRoot;MoveAttempted=$false;PhysicalMappingVerified=$false;ConversionQualified=$false}
