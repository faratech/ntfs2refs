<# Separate protected-mounted profile; original range sources remain frozen. #>
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][ValidateLength(32,32)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$CaptureId)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $PSCmdlet.ShouldProcess('Owned saved ReFS placement target','Quiesce, protect disk read-only, freshly observe, then lock and read two fixed 64 KiB ranges; export to C:')) {
 [pscustomobject]@{DryRun=$true;CaptureId=$CaptureId;MaximumRawReadBytes=131072;MaximumLockCalls=2;MaximumDiskAttributeChanges=1;RawWriteRequestsIssued=$false;ConversionQualified=$false};return
}
function Read-ProtectedRangeReadJson([string]$Path,[long]$MaximumBytes=1MB) {
    $file=Get-Item -LiteralPath $Path -Force
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -lt 1 -or $file.Length -gt $MaximumBytes) { throw 'Expected a bounded ordinary evidence file.' }
    [IO.File]::ReadAllText($file.FullName,(New-Object Text.UTF8Encoding($false,$true))) | ConvertFrom-Json
}
function Assert-ProtectedRangeReadControl($Control,[string]$ExpectedRunId) {
    if ($Control.schemaVersion -ne 1 -or $Control.kind -cne 'devdrive-data-control' -or $Control.phase -cne 'Verify' -or $Control.runId -cne $ExpectedRunId -or $Control.status -cne 'verified' -or $Control.formatSucceeded -ne $true -or $Control.remountVerified -ne $true -or $Control.ordinaryReFS -ne $false -or $Control.refsBootVerified -ne $false -or $Control.conversionQualified -ne $false) { throw 'The native Dev Drive data control has not completed.' }
    if ([string]$Control.target.host.vhdId -ine '25C491D0-5F1B-4205-9E6F-FD619706C2B5' -or $Control.target.host.sizeBytes -ne 64GB -or $Control.target.host.controllerLocation -ne 1 -or $Control.target.guest.uniqueId -cne '60022480D091C4251B5FFD619706C2B5' -or $Control.target.guest.role -cne 'target' -or $Control.target.guest.sizeBytes -ne 64GB) { throw 'Control target differs from the original owned virtual disk.' }
    $part=$Control.partition
    foreach($name in @('guid','diskGuid')) { $id=[guid]::Empty; if(-not [guid]::TryParse([string]$part.$name,[ref]$id) -or $id -eq [guid]::Empty) { throw 'Missing native GPT identity.' } }
    if ($part.number -ne 2 -or $part.offset -ne 16MB -or $part.length -ne 52GB -or $part.letter -cne 'F' -or $part.logicalSectorSize -ne 512 -or $part.physicalSectorSize -ne 4096 -or $Control.after.filesystem -cne 'ReFS' -or $Control.after.allocationUnitSize -ne 4096 -or $Control.after.size -ne 52GB) { throw 'Native partition profile differs.' }
}
function Get-ProtectedRangeReadTarget($Identity,$Control,[bool]$RequireReadOnly=$false) {
    if($RequireReadOnly){
        $disks=@(Get-Disk | Where-Object { [string]$_.UniqueId -ceq [string]$Identity.uniqueId })
        if($disks.Count -ne 1){throw 'Protected target must match one disk.'}
        $disk=$disks[0]; Assert-LabGuestDisk $disk
        if($Identity.schemaVersion -ne 1 -or $Identity.role -cne 'target' -or $Identity.sizeBytes -ne 64GB -or [string]$disk.SerialNumber -cne [string]$Identity.serialNumber -or $disk.Size -ne $Identity.sizeBytes -or [string]$disk.Location -cne [string]$Identity.location -or $disk.IsOffline -or -not $disk.IsReadOnly){throw 'Protected target identity or read-only state changed.'}
    }else{$disk=Get-LabGuestDisk $Identity}
    if([string]$disk.PartitionStyle -cne 'GPT' -or $disk.IsClustered){throw 'Expected the private basic GPT target.'}
    $parts=@(Get-Partition -DiskNumber $disk.Number | Where-Object { $_.DriveLetter })
    if ($parts.Count -ne 1) { throw 'Expected one mounted target partition.' }
    $part=$parts[0]; $expected=$Control.partition
    if ([string]$disk.Guid -ine [string]$expected.diskGuid -or [string]$part.Guid -ine [string]$expected.guid -or $part.PartitionNumber -ne $expected.number -or $part.Offset -ne $expected.offset -or $part.Size -ne $expected.length -or [string]$part.DriveLetter -cne $expected.letter -or $part.IsBoot -or $part.IsSystem -or $disk.LogicalSectorSize -ne 512 -or $disk.PhysicalSectorSize -ne 4096) { throw 'Target GPT, geometry or role changed.' }
    $bound=@(Get-Partition -DriveLetter F)
    if ($bound.Count -ne 1 -or $bound[0].DiskNumber -ne $disk.Number -or [string]$bound[0].Guid -ine [string]$expected.guid) { throw 'Target drive letter changed.' }
    $vol=Get-Volume -DriveLetter F
    if ($vol.FileSystem -cne 'ReFS' -or $vol.FileSystemLabel -cne 'ntfs2refs-target' -or $vol.AllocationUnitSize -ne 4096 -or $vol.Size -ne 52GB) { throw 'Unexpected target filesystem.' }
    if(@(Get-CimInstance Win32_PageFileUsage | Where-Object { $_.Name -like 'F:\*' }).Count){throw 'Target contains a page file.'}
    [pscustomobject]@{disk=$disk;partition=$part;volume=$vol}
}
function Get-ProtectedRangeReadFixture($Evidence,$Identity) {
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
function Test-ProtectedRangeReadSameMapping($Left,$Right) {
    if ($Left.fileId64 -cne $Right.fileId64 -or $Left.volumeSerialHex -cne $Right.volumeSerialHex -or $Left.length -ne $Right.length -or $Left.sha256 -cne $Right.sha256 -or @($Left.extents).Count -ne @($Right.extents).Count) { return $false }
    for($i=0;$i -lt @($Left.extents).Count;$i++) { foreach($name in @('startingVcn','nextVcn','lcn')) { if($Left.extents[$i].$name -ne $Right.extents[$i].$name) { return $false } } }
    $true
}
function Get-ProtectedRangeReadProfile {
    [pscustomobject]@{controlRunId='65f270323c26427e8316c7a8b75959cc';controlEvidenceSha256='ca9e3e60bbe84bd758609d92b92a305a948213b4ab0f5ce199f38567a8ea84c1';capturedAllocationSha256='f553fd91111dfb09a9aa14d27fe63daaba790c0efb14bd530ac5cd9ef0f55be2';placementProbeId='d98ba93b850d4eababa84c445439868a';placementEvidenceSha256='865e9a7517dd1e0bd925d7fad5af85146fa8ec4c447d5640958473c11cd30cc5';remountIdentitySha256='fe287b5536c1de6c816d4d4ba43e7d5fe9026361a8b91687279c770b5efb4414';remountAllocationSha256='9d7b537e885cde3c7b67c1a830dd2dfff27ccf4232d445e46baa4a3499002cbe';patternSha256='9b195d4598044587ab6e51b73d92063936710b9b1255158054918350d20f1d78'}
}
function Read-ProtectedRangeReadProof([string]$Path,[string]$Sha256) {
    $data=Read-ProtectedRangeReadJson $Path
    if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Sha256){throw 'Pinned source proof changed.'}
    $data
}
function Assert-ProtectedRangeReadPlacement($Placement,$Remount,$Control,$Profile) {
    if($Placement.schemaVersion -ne 1 -or $Placement.kind -cne 'native-initialized-file-placement' -or $Placement.probeId -cne $Profile.placementProbeId -or $Placement.controlRunId -cne $Profile.controlRunId -or $Placement.controlEvidenceSha256 -cne $Profile.controlEvidenceSha256 -or $Placement.capturedAllocationSha256 -cne $Profile.capturedAllocationSha256 -or $Placement.status -cne 'native-placement-observed-awaiting-remount' -or -not $Placement.moveCompleted -or -not $Placement.contentPreserved -or -not $Placement.originalUnchanged -or -not $Placement.requestedPlacementObserved -or $Placement.requestedLcn -ne 1508384 -or $Placement.expectedSha256 -cne $Profile.patternSha256 -or $Placement.rawDiskWrites -ne $false -or $Placement.conversionQualified -ne $false){throw 'Saved native placement is not the reviewed successful case.'}
    if($Remount.schemaVersion -ne 1 -or $Remount.kind -cne 'native-extent-placement-remount' -or $Remount.probeId -cne $Profile.placementProbeId -or $Remount.volumeUniqueId -cne $Placement.volumeUniqueId){throw 'Saved remount differs from placement.'}
    foreach($field in @('guid','diskGuid','number','offset','length','letter','logicalSectorSize','physicalSectorSize')){if([string]$Placement.partition.$field -cne [string]$Control.partition.$field -or [string]$Remount.partition.$field -cne [string]$Control.partition.$field){throw 'Saved GPT identity or geometry changed.'}}
    foreach($phase in @('before','after')){$file=$Placement.$phase;$lcn=if($phase -ceq 'before'){1508352}else{1508384};if($file.length -ne 65536 -or $file.sha256 -cne $Profile.patternSha256 -or $file.fileId64 -cne '0x3000000000002702' -or $file.volumeSerialHex -cne '0x08425382' -or @($file.extents).Count -ne 1 -or $file.extents[0].startingVcn -ne 0 -or $file.extents[0].nextVcn -ne 16 -or $file.extents[0].lcn -ne $lcn){throw 'Saved range differs from exact placement.'}}
}
function Assert-ProtectedRangeReadAllocation($Evidence,$Identity,$Placement,$Profile) {
    $original=Get-ProtectedRangeReadFixture $Evidence $Identity
    if(@($Evidence.files).Count -ne 2 -or $Evidence.volume.uniqueId -cne $Placement.volumeUniqueId -or -not (Test-ProtectedRangeReadSameMapping $original $Placement.originalAfter)){throw 'Original fixture or allocation identity changed.'}
    $files=@($Evidence.files|Where-Object {$_.path -ceq ('fixtures\placement-'+$Profile.placementProbeId+'\initialized.bin') -and $_.stream -ceq ':$DATA'})
    if($files.Count -ne 1){throw 'Expected exactly the initialized placement fixture.'}
    $file=$files[0].observation
    if($file.complete -ne $true -or $file.stableDuringObservation -ne $true -or $file.status -cne 'mapping-returned' -or ([IO.FileAttributes]$file.attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::SparseFile -bor [IO.FileAttributes]::Compressed -bor [IO.FileAttributes]::Encrypted)) -or -not (Test-ProtectedRangeReadSameMapping $file $Placement.after)){throw 'Initialized fixture changed or is not an ordinary complete mapping.'}
}

Import-Module (Join-Path $PSScriptRoot 'GuestLab.psm1') -Force
$computer=Get-CimInstance Win32_ComputerSystem
if($env:COMPUTERNAME -cne 'N2R-WIN11' -or $env:SystemDrive -cne 'C:' -or $computer.Manufacturer -cne 'Microsoft Corporation' -or $computer.Model -cne 'Virtual Machine' -or -not [Environment]::Is64BitProcess){throw 'Range probe requires the owned 64-bit Windows guest.'}
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated guest process required.'}
$version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if($version.EditionID -cne 'Professional' -or $version.CurrentBuildNumber -cne '26300' -or $version.UBR -ne 9457){throw 'Native Windows profile changed.'}
$profile=Get-ProtectedRangeReadProfile
$controlRoot='C:\ntfs2refs\devdrive-control';$placementRoot='C:\ntfs2refs\extent-placement\'+$profile.placementProbeId
foreach($path in @('C:\ntfs2refs',$controlRoot,'C:\ntfs2refs\extent-placement',$placementRoot,($placementRoot+'\remount'))){$item=Get-Item -LiteralPath $path -Force;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected proof directory.'}}
$control=Read-ProtectedRangeReadProof ($controlRoot+'\verify.json') $profile.controlEvidenceSha256
Assert-ProtectedRangeReadControl $control $profile.controlRunId
$captured=Read-ProtectedRangeReadProof ($controlRoot+'\allocation-after.json') $profile.capturedAllocationSha256
$manifestPath=$controlRoot+'\target.json';$identity=Read-ProtectedRangeReadJson $manifestPath 64KB
foreach($field in @('schemaVersion','role','uniqueId','serialNumber','serialNumberAvailable','sizeBytes','location','enrolledUtc')){if([string]$identity.$field -cne [string]$control.target.guest.$field){throw 'Target enrollment changed.'}}
$placement=Read-ProtectedRangeReadProof ($placementRoot+'\placement.json') $profile.placementEvidenceSha256
$remount=Read-ProtectedRangeReadProof ($placementRoot+'\remount\identity.json') $profile.remountIdentitySha256
$savedAllocation=Read-ProtectedRangeReadProof ($placementRoot+'\remount\allocation-remount.json') $profile.remountAllocationSha256
Assert-ProtectedRangeReadPlacement $placement $remount $control $profile
Assert-ProtectedRangeReadAllocation $savedAllocation $identity $placement $profile
$patternPath=$placementRoot+'\expected-pattern.bin';$patternFile=Get-Item -LiteralPath $patternPath -Force
if($patternFile.PSIsContainer -or ($patternFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $patternFile.Length -ne 65536 -or (Get-FileHash -LiteralPath $patternPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $profile.patternSha256){throw 'Expected pattern evidence changed.'}
$pattern=[IO.File]::ReadAllBytes($patternPath)
function Get-ProtectedRangeReadBufferLimit([string]$Name){
    $limits=@{pDevice=12;pLength=8;pAlignment=28;pLayout=65536;pVolume=64;pAttributesBefore=16;pAttributesAfter=16;sDevice=12;sLength=8;sAlignment=28;sLayout=65536;sAttributesBefore=16;sVolumeBefore=64;sBaseBefore=8;sBitmapLegacyBefore=2MB;sBitmapMetadataBefore=2MB;sAttributesLocked=16;sVolumeLocked=64;sBaseAfter=8;sBitmapLegacyAfter=2MB;sBitmapMetadataAfter=2MB;sVolumeAfter=64;sAttributesAfter=16;oldSource=65536;destination=65536}
    if(@($limits.Keys) -cnotcontains $Name){throw 'Unreviewed native buffer name.'};[int]$limits[$Name]
}
function Get-ProtectedRangeReadNativeSummary($Native){
    $result=[ordered]@{}
    foreach($field in @('status','phase','error','volumeOpened','diskOpened','lockAttempted','lockSucceeded','dismountAttempted','dismountSucceeded','offlineAttempted','offlineSucceeded','setAttributesAttempted','setAttributesSucceeded','onlineAttempted','onlineSucceeded','unlockAttempted','unlockSucceeded','deviceStateMutationMayHaveBeenIssued','protectionEstablished','protectionVerifiedBefore','protectionVerifiedLocked','protectionVerifiedAfter','mountedReadOnlyBefore','mountedReadOnlyAfter','volumeCloseAttempted','volumeCloseSucceeded','diskCloseAttempted','diskCloseSucceeded','handleCloseSucceeded','nativeOperationReturned','rawReadMayHaveBeenIssued','volumeOpenError','diskOpenError','volumeCloseError','diskCloseError','rangeReadCalls','baseSectors','oldSourceFreeInBoth','destinationAllocatedInBoth','sourceBitsLegacy','sourceBitsMetadata','destinationBitsLegacy','destinationBitsMetadata')){$result[$field]=$Native.$field}
    foreach($field in @('samplingHandleCloseAttempted','samplingHandleCloseSucceeded','samplingHandleCloseError','volumeReopenAttempted','volumeReopenSucceeded','volumeReopenError')){$result[$field]=$Native.$field}
    $result.queryNames=@($Native.queries | ForEach-Object {$_.name});$result.mountedViews=@($Native.mountedViews);[pscustomobject]$result
}
function Test-ProtectedRangeReadEarlyRestore($Transition){
    $Transition.nativeOperationReturned -eq $true -and $Transition.handleCloseSucceeded -eq $true -and $Transition.deviceStateMutationMayHaveBeenIssued -eq $false -and $Transition.dismountAttempted -eq $false -and $Transition.offlineAttempted -eq $false -and $Transition.setAttributesAttempted -eq $false -and $Transition.onlineAttempted -eq $false -and (-not $Transition.lockSucceeded -or $Transition.unlockSucceeded -eq $true) -and $Transition.status -cin @('native-open-refused','native-lock-refused','native-query-refused')
}
function Capture-ProtectedRangeReadAllocation([string]$OutputPath,$Identity,$Control,$Placement,$Profile){
    $beforeTarget=Get-ProtectedRangeReadTarget $Identity $Control $true
    $mountedBefore=[Ntfs2Refs.NativeProtectedRangeRead]::GetMountedView('fixtureBefore');[Ntfs2Refs.NativeProtectedRangeRead]::ValidateMounted($mountedBefore)
    $paths=@('nonresident.bin',('placement-'+$Profile.placementProbeId+'\initialized.bin'));$remaining=[long]8MB;$files=@()
    foreach($relative in $paths){$observation=[Ntfs2Refs.NativeAllocationEvidence]::Collect(('F:\fixtures\'+$relative),$remaining);$remaining-=$observation.length;if(-not $observation.complete -or -not $observation.stableDuringObservation){throw 'Protected fixture observation is incomplete.'};$files+=[pscustomobject]@{path=('fixtures\'+$relative);stream=':$DATA';observation=$observation}}
    $afterTarget=Get-ProtectedRangeReadTarget $Identity $Control $true
    if($afterTarget.disk.Number -ne $beforeTarget.disk.Number -or [string]$afterTarget.volume.UniqueId -cne [string]$beforeTarget.volume.UniqueId){throw 'Protected fixture binding changed.'}
    $mountedAfter=[Ntfs2Refs.NativeProtectedRangeRead]::GetMountedView('fixtureAfter');[Ntfs2Refs.NativeProtectedRangeRead]::ValidateMounted($mountedAfter)
    $version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion';$driver=Get-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\drivers\refs.sys')
    $report=[ordered]@{schemaVersion=1;kind='native-file-allocation-observations';createdUtc=[DateTime]::UtcNow.ToString('o');evidenceScriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();diskIdentity=$Identity;diskNumberObserved=$beforeTarget.disk.Number;logicalSectorSize=512;physicalSectorSize=4096;partition=[pscustomobject]@{number=2;offset=16MB;size=52GB;driveLetter='F'};volume=[pscustomobject]@{fileSystem='ReFS';label='ntfs2refs-target';uniqueId=[string]$beforeTarget.volume.UniqueId;allocationUnitSize=4096;size=52GB};windowsBuild=([string]$version.CurrentBuild+'.'+[string]$version.UBR);filesystemDriver=[pscustomobject]@{name='refs.sys';version=$driver.VersionInfo.FileVersion;sha256=(Get-FileHash -LiteralPath $driver.FullName -Algorithm SHA256).Hash.ToLowerInvariant()};requestedFiles=$paths;files=$files;failures=@();complete=$true;hashBudgetBytes=8MB;hashedLogicalBytes=(8MB-$remaining);protectedReadOnlyRequired=$true;diskReadOnlyObserved=$true;mountedBefore=$mountedBefore;mountedAfter=$mountedAfter;sourceWriteRequestsIssued=$false;retrievalPointerBaseQueried=$false;physicalMappingVerified=$false;conversionQualified=$false;bootQualified=$false}
    Assert-ProtectedRangeReadAllocation ([pscustomobject]$report) $Identity $Placement $Profile
    $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes(($report|ConvertTo-Json -Depth 14));if($bytes.Length -gt 1MB){throw 'Protected allocation report exceeds bound.'};[Ntfs2Refs.NativeAllocationEvidence]::WriteReport($OutputPath,$bytes)
}
$nativePaths=@((Join-Path $PSScriptRoot 'NativeRangeRead.cs'),(Join-Path $PSScriptRoot 'NativeProtectedRangeRead.cs'))
$sourceHashes=@()
foreach($path in $nativePaths){$item=Get-Item -LiteralPath $path -Force;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -lt 1 -or $item.Length -gt 128KB){throw 'Unexpected native source.'};$sourceHashes+=[pscustomobject]@{name=$item.Name;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}}
if(('Ntfs2Refs.NativeProtectedRangeRead' -as [type]) -or ('Ntfs2Refs.NativeRangeRead' -as [type])){throw 'Protected probe requires a fresh native type context.'}
Add-Type -Path $nativePaths
$target=Get-ProtectedRangeReadTarget $identity $control
[Ntfs2Refs.NativeRangeRead]::ValidateProfile([string]$target.volume.UniqueId,[int]$target.disk.Number,512,4096)|Out-Null
$osParts=@(Get-Partition -DriveLetter C)
if($osParts.Count -ne 1 -or $osParts[0].DiskNumber -eq $target.disk.Number -or -not $osParts[0].IsBoot){throw 'Evidence must be on the separate guest OS disk.'}
$outputParent='C:\ntfs2refs\protected-range-read'
if(Test-Path -LiteralPath $outputParent){$item=Get-Item -LiteralPath $outputParent -Force;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected output parent.'}}else{New-Item -ItemType Directory -Path $outputParent|Out-Null}
$outputRoot=Join-Path $outputParent $CaptureId
if(Test-Path -LiteralPath $outputRoot){throw 'Output already exists.'};New-Item -ItemType Directory -Path $outputRoot|Out-Null
$record=[ordered]@{schemaVersion=1;kind='native-protected-range-read';captureId=$CaptureId;status='blocked';profile=$profile;target=$identity;partition=$control.partition;volumeUniqueId=[string]$target.volume.UniqueId;diskNumberObserved=$target.disk.Number;maximumRawReadBytes=131072;maximumLockCalls=2;maximumDiskAttributeChanges=1;rawWriteRequestsIssued=$false;targetFileWriteRequestsIssued=$false;forcedDismountAttempted=$false;lockMayFlushNativeWrites=$false;nativeOperationReturned=$false;handleCloseSucceeded=$false;deviceStateMutationMayHaveBeenIssued=$false;protectionEstablished=$false;protectionTransitionCompleted=$false;diskProtectionRetained=$false;restoreAllowed=$false;fixturesUnchanged=$false;destinationSampleVerified=$false;oldSourceResidualObserved=$false;oldSourceReserved=$false;physicalMappingGeneralized=$false;metadataCoverageQualified=$false;payloadCopyAvoidanceVerified=$false;conversionQualified=$false;bootQualified=$false;transition=$null;sample=$null;nativeQueries=@();rawReads=@();errors=@();scriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();nativeSourceHashes=$sourceHashes;createdUtc=[DateTime]::UtcNow.ToString('o')}
function Save-ProtectedRangeReadBuffer([string]$Name,[byte[]]$Bytes){
    if($null -ne $Bytes -and $Bytes.Length -gt 0){$limit=Get-ProtectedRangeReadBufferLimit $Name;if($Bytes.Length -gt $limit){throw 'Native buffer exceeds its allowlist bound.'};$path=Join-Path $outputRoot ($Name+'.bin');[Ntfs2Refs.NativeAllocationEvidence]::WriteReport($path,$Bytes);[pscustomobject]@{path=$path;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}}else{[pscustomobject]@{path=$null;sha256=$null}}
}
function Save-ProtectedRangeReadNative($Native){
    foreach($query in $Native.queries){$buffer=Save-ProtectedRangeReadBuffer $query.name $query.bytes;$record.nativeQueries+=[pscustomobject]@{name=$query.name;controlCode=('0x{0:x8}' -f $query.controlCode);inputBytes=$query.inputBytes;inputHex=$query.inputHex;outputCapacityBytes=$query.outputCapacityBytes;succeeded=$query.succeeded;nativeError=$query.nativeError;bytesReturned=$query.bytesReturned;bufferPath=$buffer.path;bufferSha256=$buffer.sha256;startedUtc=$query.startedUtc;finishedUtc=$query.finishedUtc}}
    foreach($read in $Native.reads){$buffer=Save-ProtectedRangeReadBuffer $read.name $read.bytes;$record.rawReads+=[pscustomobject]@{name=$read.name;lcn=$(if($read.name -ceq 'oldSource'){1508352}else{1508384});volumeOffset=$read.offset;guestDiskOffset=([long]$control.partition.offset+$read.offset);requestedBytes=$read.requestedBytes;bytesReturned=$read.bytesReturned;seekAttempted=$read.seekAttempted;seekSucceeded=$read.seekSucceeded;actualSeekOffset=$read.actualSeekOffset;seekError=$read.seekError;readAttempted=$read.readAttempted;readSucceeded=$read.readSucceeded;readError=$read.readError;bufferPath=$buffer.path;bufferSha256=$buffer.sha256;fullPatternEqual=[Ntfs2Refs.NativeRangeRead]::Equal($read.bytes,$pattern);startedUtc=$read.startedUtc;finishedUtc=$read.finishedUtc}}
}
try{
    $fixturePaths=@('nonresident.bin',('placement-'+$profile.placementProbeId+'\initialized.bin'))
    & (Join-Path $PSScriptRoot 'Capture-GuestAllocation.ps1') -ManifestPath $manifestPath -FixtureRelativePath $fixturePaths -OutputPath (Join-Path $outputRoot 'allocation-before.json') -MaximumHashMiB 8|Out-Null
    Assert-ProtectedRangeReadAllocation (Read-ProtectedRangeReadJson (Join-Path $outputRoot 'allocation-before.json')) $identity $placement $profile
    $current=Get-ProtectedRangeReadTarget $identity $control
    if($current.disk.Number -ne $target.disk.Number -or [string]$current.volume.UniqueId -cne [string]$target.volume.UniqueId){throw 'Target changed before protection.'}
    $started=[ordered]@{schemaVersion=1;kind='native-protected-range-read-started';captureId=$CaptureId;profile=$profile;target=$identity;partition=$control.partition;deviceStateMutationMayHaveBeenIssued=$true;rawWriteRequestsIssued=$false;targetFileWriteRequestsIssued=$false;maximumRawReadBytes=131072;maximumLockCalls=2;maximumDiskAttributeChanges=1;scriptSha256=$record.scriptSha256;nativeSourceHashes=$sourceHashes;createdUtc=[DateTime]::UtcNow.ToString('o')}
    [Ntfs2Refs.NativeAllocationEvidence]::WriteReport((Join-Path $outputRoot 'started.json'),(New-Object Text.UTF8Encoding($false)).GetBytes(($started|ConvertTo-Json -Depth 12)))
    $record.deviceStateMutationMayHaveBeenIssued=$true;$record.lockMayFlushNativeWrites=$true
    $transition=[Ntfs2Refs.NativeProtectedRangeRead]::Protect([string]$target.volume.UniqueId,[int]$target.disk.Number,512,4096)
    $record.transition=Get-ProtectedRangeReadNativeSummary $transition;$record.nativeOperationReturned=$transition.nativeOperationReturned;$record.handleCloseSucceeded=$transition.handleCloseSucceeded;$record.deviceStateMutationMayHaveBeenIssued=$transition.deviceStateMutationMayHaveBeenIssued;$record.protectionEstablished=$transition.protectionEstablished;$record.lockMayFlushNativeWrites=$transition.lockAttempted
    Save-ProtectedRangeReadNative $transition
    if($transition.status -cne 'protection-established'){
        if(-not (Test-ProtectedRangeReadEarlyRestore $transition)){throw 'Protection transition did not complete; preserve its observed state.'}
        & (Join-Path $PSScriptRoot 'Capture-GuestAllocation.ps1') -ManifestPath $manifestPath -FixtureRelativePath $fixturePaths -OutputPath (Join-Path $outputRoot 'allocation-after.json') -MaximumHashMiB 8|Out-Null
        Assert-ProtectedRangeReadAllocation (Read-ProtectedRangeReadJson (Join-Path $outputRoot 'allocation-after.json')) $identity $placement $profile
        Get-ProtectedRangeReadTarget $identity $control|Out-Null
        $record.fixturesUnchanged=$true;$record.status=$transition.status;$record.restoreAllowed=$true
    }else{
        if(-not $transition.nativeOperationReturned -or -not $transition.handleCloseSucceeded -or -not $transition.onlineSucceeded -or -not $transition.unlockSucceeded -or -not $transition.protectionEstablished){throw 'Protection transition cleanup is incomplete.'}
        $record.protectionTransitionCompleted=$true
        Capture-ProtectedRangeReadAllocation (Join-Path $outputRoot 'allocation-protected-before.json') $identity $control $placement $profile
        $current=Get-ProtectedRangeReadTarget $identity $control $true
        if($current.disk.Number -ne $target.disk.Number -or [string]$current.volume.UniqueId -cne [string]$target.volume.UniqueId){throw 'Protected binding changed before sampling.'}
        $record.nativeOperationReturned=$false;$record.handleCloseSucceeded=$false
        $sample=[Ntfs2Refs.NativeProtectedRangeRead]::Observe([string]$target.volume.UniqueId,[int]$target.disk.Number,512,4096)
        $record.sample=Get-ProtectedRangeReadNativeSummary $sample;$record.nativeOperationReturned=$sample.nativeOperationReturned;$record.handleCloseSucceeded=$transition.handleCloseSucceeded -and $sample.handleCloseSucceeded
        Save-ProtectedRangeReadNative $sample
        if($sample.status -cne 'ranges-read-awaiting-file-verification' -or -not $sample.nativeOperationReturned -or -not $sample.handleCloseSucceeded -or -not $sample.unlockSucceeded -or -not $sample.samplingHandleCloseSucceeded -or -not $sample.volumeReopenSucceeded -or -not $sample.protectionVerifiedBefore -or -not $sample.protectionVerifiedLocked -or -not $sample.protectionVerifiedAfter -or -not $sample.mountedReadOnlyBefore -or -not $sample.mountedReadOnlyAfter){throw 'Protected sample did not complete; preserve the protected branch.'}
        Capture-ProtectedRangeReadAllocation (Join-Path $outputRoot 'allocation-after.json') $identity $control $placement $profile
        $current=Get-ProtectedRangeReadTarget $identity $control $true
        if($current.disk.Number -ne $target.disk.Number -or [string]$current.volume.UniqueId -cne [string]$target.volume.UniqueId){throw 'Protected binding changed after sampling.'}
        $destination=@($record.rawReads|Where-Object name -CEQ 'destination');$old=@($record.rawReads|Where-Object name -CEQ 'oldSource')
        if($destination.Count -ne 1 -or $old.Count -ne 1 -or -not $destination[0].fullPatternEqual -or $sample.destinationAllocatedInBoth -ne $true -or $sample.oldSourceFreeInBoth -ne $true -or $sample.rangeReadCalls -ne 2){throw 'Destination content or protected eligibility disagrees.'}
        $record.fixturesUnchanged=$true;$record.diskProtectionRetained=$true;$record.destinationSampleVerified=$true;$record.oldSourceResidualObserved=$old[0].fullPatternEqual;$record.status='destination-range-verified';$record.restoreAllowed=$true
    }
}catch{$record.status='blocked';$record.restoreAllowed=$false;$record.errors+=$_.Exception.Message;$record['errorPosition']=$_.InvocationInfo.PositionMessage}
finally{
    $record['finishedUtc']=[DateTime]::UtcNow.ToString('o')
    if('Ntfs2Refs.NativeAllocationEvidence' -as [type]){$bytes=(New-Object Text.UTF8Encoding($false)).GetBytes(($record|ConvertTo-Json -Depth 18));if($bytes.Length -gt 1MB){throw 'Protected range JSON exceeds bound.'};[Ntfs2Refs.NativeAllocationEvidence]::WriteReport((Join-Path $outputRoot 'protected-range.json'),$bytes)}
}
[pscustomobject]@{Status=$record.status;CaptureId=$CaptureId;EvidenceDirectory=$outputRoot;RestoreAllowed=$record.restoreAllowed;DeviceStateMutationMayHaveBeenIssued=$record.deviceStateMutationMayHaveBeenIssued;ProtectionEstablished=$record.protectionEstablished;DestinationSampleVerified=$record.destinationSampleVerified;OldSourceResidualObserved=$record.oldSourceResidualObserved;RawWriteRequestsIssued=$false;ConversionQualified=$false}
