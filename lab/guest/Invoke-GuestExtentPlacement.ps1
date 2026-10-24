<# One initialized 64 KiB file and one documented native move on the owned guest.
   This intentionally writes payload; it does not perform or qualify conversion. #>
[CmdletBinding(SupportsShouldProcess)]
param(
 [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')][string]$ControlRunId,
 [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ControlEvidenceSha256,
 [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$CapturedAllocationSha256,
 [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')][string]$ProbeId
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $PSCmdlet.ShouldProcess('Owned checkpoint-backed ReFS target','Create and flush one new 64 KiB initialized fixture, request one 16-cluster native move, preserve files and evidence')) {
 [pscustomobject]@{DryRun=$true;Phase='InitializedFilePlacement';ProbeId=$ProbeId;MaximumFixtureBytes=65536;MaximumMoveCalls=1;PayloadWriteRequestsIssued=$true;RawDiskWrites=$false;ConversionQualified=$false};return
}
function Read-ExtentPlacementJson([string]$Path,[long]$MaximumBytes=1MB) {
    $file=Get-Item -LiteralPath $Path -Force
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -lt 1 -or $file.Length -gt $MaximumBytes) { throw 'Expected a bounded ordinary evidence file.' }
    [IO.File]::ReadAllText($file.FullName,(New-Object Text.UTF8Encoding($false,$true))) | ConvertFrom-Json
}
function Assert-ExtentPlacementControl($Control,[string]$ExpectedRunId) {
    if ($Control.schemaVersion -ne 1 -or $Control.kind -cne 'devdrive-data-control' -or $Control.phase -cne 'Verify' -or $Control.runId -cne $ExpectedRunId -or $Control.status -cne 'verified' -or $Control.formatSucceeded -ne $true -or $Control.remountVerified -ne $true -or $Control.ordinaryReFS -ne $false -or $Control.refsBootVerified -ne $false -or $Control.conversionQualified -ne $false) { throw 'The native Dev Drive data control has not completed.' }
    if ([string]$Control.target.host.vhdId -ine '25C491D0-5F1B-4205-9E6F-FD619706C2B5' -or $Control.target.host.sizeBytes -ne 64GB -or $Control.target.host.controllerLocation -ne 1 -or $Control.target.guest.uniqueId -cne '60022480D091C4251B5FFD619706C2B5' -or $Control.target.guest.role -cne 'target' -or $Control.target.guest.sizeBytes -ne 64GB) { throw 'Control target differs from the original owned virtual disk.' }
    $part=$Control.partition
    foreach($name in @('guid','diskGuid')) { $id=[guid]::Empty; if(-not [guid]::TryParse([string]$part.$name,[ref]$id) -or $id -eq [guid]::Empty) { throw 'Missing native GPT identity.' } }
    if ($part.number -ne 2 -or $part.offset -ne 16MB -or $part.length -ne 52GB -or $part.letter -cne 'F' -or $part.logicalSectorSize -ne 512 -or $part.physicalSectorSize -ne 4096 -or $Control.after.filesystem -cne 'ReFS' -or $Control.after.allocationUnitSize -ne 4096 -or $Control.after.size -ne 52GB) { throw 'Native partition profile differs.' }
}
function Get-ExtentPlacementTarget($Identity,$Control) {
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
function Get-ExtentPlacementFixture($Evidence,$Identity) {
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
function Test-ExtentPlacementSameMapping($Left,$Right) {
    if ($Left.fileId64 -cne $Right.fileId64 -or $Left.volumeSerialHex -cne $Right.volumeSerialHex -or $Left.length -ne $Right.length -or $Left.sha256 -cne $Right.sha256 -or @($Left.extents).Count -ne @($Right.extents).Count) { return $false }
    for($i=0;$i -lt @($Left.extents).Count;$i++) { foreach($name in @('startingVcn','nextVcn','lcn')) { if($Left.extents[$i].$name -ne $Right.extents[$i].$name) { return $false } } }
    $true
}
Import-Module (Join-Path $PSScriptRoot 'GuestLab.psm1') -Force
$computer=Get-CimInstance Win32_ComputerSystem
if($env:COMPUTERNAME -cne 'N2R-WIN11' -or $env:SystemDrive -cne 'C:' -or $computer.Manufacturer -cne 'Microsoft Corporation' -or $computer.Model -cne 'Virtual Machine' -or -not [Environment]::Is64BitProcess) { throw 'Placement must run in the owned 64-bit Windows 11 guest.' }
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'An elevated guest process is required.' }
$version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if($version.EditionID -cne 'Professional' -or $version.CurrentBuildNumber -cne '26300' -or $version.UBR -ne 9457) { throw 'Unexpected native Windows profile.' }
$nativeSource=Get-Item -LiteralPath (Join-Path $PSScriptRoot 'NativeExtentPlacement.cs') -Force
if($nativeSource.PSIsContainer -or ($nativeSource.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $nativeSource.Length -lt 1 -or $nativeSource.Length -gt 64KB) { throw 'Unexpected native placement helper.' }
if(-not ('Ntfs2Refs.NativeExtentPlacement' -as [type])) { Add-Type -Path $nativeSource.FullName }
$controlRoot='C:\ntfs2refs\devdrive-control'
foreach($path in @('C:\ntfs2refs',$controlRoot,'F:\fixtures')) { $item=Get-Item -LiteralPath $path -Force; if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected evidence or fixture directory.' } }
$verifyPath=Join-Path $controlRoot 'verify.json';$capturedPath=Join-Path $controlRoot 'allocation-after.json';$manifestPath=Join-Path $controlRoot 'target.json'
if((Get-FileHash -LiteralPath $verifyPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ControlEvidenceSha256 -or (Get-FileHash -LiteralPath $capturedPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $CapturedAllocationSha256) { throw 'Native control evidence differs from the verified host exports.' }
$control=Read-ExtentPlacementJson $verifyPath
Assert-ExtentPlacementControl $control $ControlRunId
$identity=Read-ExtentPlacementJson $manifestPath 64KB
foreach($name in @('schemaVersion','role','uniqueId','serialNumber','serialNumberAvailable','sizeBytes','location','enrolledUtc')) { if([string]$identity.$name -cne [string]$control.target.guest.$name) { throw 'Guest enrollment changed.' } }
$captured=Read-ExtentPlacementJson $capturedPath
$capturedFixture=Get-ExtentPlacementFixture $captured $identity
$expectedFile=@($control.after.files | Where-Object name -CEQ 'nonresident.bin')
if($expectedFile.Count -ne 1 -or $expectedFile[0].length -ne 4MB -or $expectedFile[0].sha256 -cne $capturedFixture.sha256) { throw 'Original fixture hash evidence disagrees.' }
$target=Get-ExtentPlacementTarget $identity $control
[Ntfs2Refs.NativeExtentPlacement]::VolumeName([string]$target.volume.UniqueId) | Out-Null
$fixturePath=[Ntfs2Refs.NativeExtentPlacement]::FixturePath($ProbeId)
if(Test-Path -LiteralPath (Split-Path $fixturePath -Parent)) { throw 'Probe directory already exists; no overwrite or reuse is allowed.' }
$outputParent='C:\ntfs2refs\extent-placement'
if(Test-Path -LiteralPath $outputParent) { $item=Get-Item -LiteralPath $outputParent -Force;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected output parent.'} }
else { New-Item -ItemType Directory -Path $outputParent | Out-Null }
$outputRoot=Join-Path $outputParent $ProbeId
if(Test-Path -LiteralPath $outputRoot) { throw 'Placement evidence output already exists.' }
New-Item -ItemType Directory -Path $outputRoot | Out-Null
$record=[ordered]@{schemaVersion=1;kind='native-initialized-file-placement';phase='InitializedFilePlacement';probeId=$ProbeId;controlRunId=$ControlRunId;status='blocked';controlEvidenceSha256=$ControlEvidenceSha256;capturedAllocationSha256=$CapturedAllocationSha256;scriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();nativeSourceSha256=(Get-FileHash -LiteralPath $nativeSource.FullName -Algorithm SHA256).Hash.ToLowerInvariant();target=$identity;partition=$control.partition;volumeUniqueId=[string]$target.volume.UniqueId;fixturePath=$fixturePath;maximumFixtureBytes=65536;maximumMoveCalls=1;requestedVcn=0;requestedClusters=16;requestedLcn=$null;bitmapCandidateIsReservation=$false;rawMetadataAddressEquivalenceVerified=$false;targetWriteRequestsIssued=$false;fixtureCreated=$false;fixtureFullyInitialized=$false;creationFlushed=$false;moveAttempted=$false;moveCompleted=$false;moveCallCount=0;contentPreserved=$false;originalUnchanged=$false;requestedPlacementObserved=$false;cleanRemountVerified=$false;physicalMappingVerified=$false;payloadCopyAvoidanceVerified=$false;conversionQualified=$false;bootQualified=$false;privilegeAdjustmentAttempted=$false;rawDiskWrites=$false;nativeQueries=@();errors=@();createdUtc=[DateTime]::UtcNow.ToString('o')}
function Save-ExtentPlacementJson([string]$Name,$Value) {
    $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes(($Value | ConvertTo-Json -Depth 16))
    if($bytes.Length -gt 1MB) { throw 'Placement JSON exceeds its evidence bound.' }
    [Ntfs2Refs.NativeAllocationEvidence]::WriteReport((Join-Path $outputRoot $Name),$bytes)
}
try {
    & (Join-Path $PSScriptRoot 'Capture-GuestAllocation.ps1') -ManifestPath $manifestPath -FixtureRelativePath @('nonresident.bin') -OutputPath (Join-Path $outputRoot 'allocation-before.json') -MaximumHashMiB 8 | Out-Null
    $before=Read-ExtentPlacementJson (Join-Path $outputRoot 'allocation-before.json')
    $beforeFixture=Get-ExtentPlacementFixture $before $identity
    if(-not (Test-ExtentPlacementSameMapping $capturedFixture $beforeFixture)) { throw 'Original fixture differs from the preserved native control.' }
    $current=Get-ExtentPlacementTarget $identity $control
    if([string]$current.volume.UniqueId -cne [string]$target.volume.UniqueId) { throw 'Volume identity changed before placement.' }
    # A durable intent precedes native code that can create or move a file.
    # Transport interruption thereafter must preserve the guest branch.
    $record['targetWriteRequestsMayHaveBeenIssued']=$true
    Save-ExtentPlacementJson 'started.json' $record
    $pattern=[Ntfs2Refs.NativeExtentPlacement]::Pattern($ProbeId)
    [Ntfs2Refs.NativeAllocationEvidence]::WriteReport((Join-Path $outputRoot 'expected-pattern.bin'),$pattern)
    $native=[Ntfs2Refs.NativeExtentPlacement]::Run([string]$target.volume.UniqueId,$ProbeId,[string]$beforeFixture.sha256,[string]$beforeFixture.fileId64)
    foreach($name in @('status','targetWriteRequestsIssued','fixtureDirectoryCreated','fixtureCreated','fixtureFullyInitialized','creationFlushed','moveAttempted','moveCompleted','moveCallCount','contentPreserved','originalUnchanged','requestedPlacementObserved','requestedLcn')) { $record[$name]=$native.$name }
    $record['nativePhase']=$native.phase;$record['expectedSha256']=$native.expectedSha256
    foreach($name in @('originalBefore','originalAfter','before','after')) { $record[$name]=$native.$name }
    if($native.error) { $record.errors+= $native.error }
    foreach($query in $native.queries) {
        $bufferPath=$null;$bufferSha=$null
        if($null -ne $query.bytes -and $query.bytes.Length -gt 0) {
            $bufferPath=Join-Path $outputRoot ($query.name+'.bin')
            [Ntfs2Refs.NativeAllocationEvidence]::WriteReport($bufferPath,$query.bytes)
            $bufferSha=(Get-FileHash -LiteralPath $bufferPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        $record.nativeQueries+= [pscustomobject]@{name=$query.name;controlCode=('0x{0:x8}' -f $query.controlCode);inputBytes=$query.inputBytes;inputHex=$query.inputHex;outputCapacityBytes=$query.outputCapacityBytes;succeeded=$query.succeeded;nativeError=$query.nativeError;nativeMessage=$query.nativeMessage;bytesReturned=$query.bytesReturned;bufferPath=$bufferPath;bufferSha256=$bufferSha;startedUtc=$query.startedUtc;finishedUtc=$query.finishedUtc}
    }
    & (Join-Path $PSScriptRoot 'Capture-GuestAllocation.ps1') -ManifestPath $manifestPath -FixtureRelativePath @('nonresident.bin') -OutputPath (Join-Path $outputRoot 'allocation-after.json') -MaximumHashMiB 8 | Out-Null
    $after=Read-ExtentPlacementJson (Join-Path $outputRoot 'allocation-after.json')
    $afterFixture=Get-ExtentPlacementFixture $after $identity
    $record['originalIndependentObservationUnchanged']=Test-ExtentPlacementSameMapping $beforeFixture $afterFixture
    if(-not $record.originalIndependentObservationUnchanged) { $record.status='integrity-check-failed';$record.originalUnchanged=$false }
    $current=Get-ExtentPlacementTarget $identity $control
    if([string]$current.volume.UniqueId -cne [string]$target.volume.UniqueId) { throw 'Volume identity changed after placement.' }
} catch { $record.status='blocked';$record.errors+= $_.Exception.Message;$record['errorPosition']=$_.InvocationInfo.PositionMessage }
finally {
    $record['finishedUtc']=[DateTime]::UtcNow.ToString('o')
    if('Ntfs2Refs.NativeAllocationEvidence' -as [type]) { Save-ExtentPlacementJson 'placement.json' $record }
}
[pscustomobject]@{Status=$record.status;ProbeId=$ProbeId;EvidenceDirectory=$outputRoot;FixturePath=$fixturePath;TargetWriteRequestsIssued=$record.targetWriteRequestsIssued;MoveAttempted=$record.moveAttempted;MoveCompleted=$record.moveCompleted;CleanRemountVerified=$false;PhysicalMappingVerified=$false;ConversionQualified=$false}
