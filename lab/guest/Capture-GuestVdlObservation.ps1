<# Observe one preserved file after remount. No new-file payload access or target mutation. #>
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$ObservationId)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $PSCmdlet.ShouldProcess('Exact preserved ReFS VDL file','Observe metadata twice without payload access')){[pscustomobject]@{DryRun=$true;NewFilePayloadReads=$false;TargetWriteRequestsIssued=$false;ConversionQualified=$false};return}
function Read-VdlObservationJson([string]$Path,[long]$MaximumBytes=1MB) {
    $file=Get-Item -LiteralPath $Path -Force
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -lt 1 -or $file.Length -gt $MaximumBytes) { throw 'Expected a bounded ordinary evidence file.' }
    [IO.File]::ReadAllText($file.FullName,(New-Object Text.UTF8Encoding($false,$true))) | ConvertFrom-Json
}
function Assert-VdlObservationControl($Control,[string]$ExpectedRunId) {
    if ($Control.schemaVersion -ne 1 -or $Control.kind -cne 'devdrive-data-control' -or $Control.phase -cne 'Verify' -or $Control.runId -cne $ExpectedRunId -or $Control.status -cne 'verified' -or $Control.formatSucceeded -ne $true -or $Control.remountVerified -ne $true -or $Control.ordinaryReFS -ne $false -or $Control.refsBootVerified -ne $false -or $Control.conversionQualified -ne $false) { throw 'The native Dev Drive data control has not completed.' }
    if ([string]$Control.target.host.vhdId -ine '25C491D0-5F1B-4205-9E6F-FD619706C2B5' -or $Control.target.host.sizeBytes -ne 64GB -or $Control.target.host.controllerLocation -ne 1 -or $Control.target.guest.uniqueId -cne '60022480D091C4251B5FFD619706C2B5' -or $Control.target.guest.role -cne 'target' -or $Control.target.guest.sizeBytes -ne 64GB) { throw 'Control target differs from the original owned virtual disk.' }
    $part=$Control.partition
    foreach($name in @('guid','diskGuid')) { $id=[guid]::Empty; if(-not [guid]::TryParse([string]$part.$name,[ref]$id) -or $id -eq [guid]::Empty) { throw 'Missing native GPT identity.' } }
    if ($part.number -ne 2 -or $part.offset -ne 16MB -or $part.length -ne 52GB -or $part.letter -cne 'F' -or $part.logicalSectorSize -ne 512 -or $part.physicalSectorSize -ne 4096 -or $Control.after.filesystem -cne 'ReFS' -or $Control.after.allocationUnitSize -ne 4096 -or $Control.after.size -ne 52GB) { throw 'Native partition profile differs.' }
}
function Get-VdlObservationTarget($Identity,$Control) {
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
function Get-VdlObservationFixture($Evidence,$Identity) {
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
function Test-VdlObservationSameMapping($Left,$Right) {
    if ($Left.fileId64 -cne $Right.fileId64 -or $Left.volumeSerialHex -cne $Right.volumeSerialHex -or $Left.length -ne $Right.length -or $Left.sha256 -cne $Right.sha256 -or @($Left.extents).Count -ne @($Right.extents).Count) { return $false }
    for($i=0;$i -lt @($Left.extents).Count;$i++) { foreach($name in @('startingVcn','nextVcn','lcn')) { if($Left.extents[$i].$name -ne $Right.extents[$i].$name) { return $false } } }
    $true
}
function Assert-VdlPlacement($Placement,[string]$Id) {
    if($Id -cne 'd98ba93b850d4eababa84c445439868a' -or $Placement.schemaVersion -ne 1 -or $Placement.kind -cne 'native-initialized-file-placement' -or $Placement.probeId -cne $Id -or $Placement.status -cne 'native-placement-observed-awaiting-remount' -or $Placement.nativePhase -cne 'complete' -or $Placement.expectedSha256 -cne '9b195d4598044587ab6e51b73d92063936710b9b1255158054918350d20f1d78' -or $Placement.after.sha256 -cne $Placement.expectedSha256 -or $Placement.after.length -ne 65536 -or $Placement.after.fileId64 -cne '0x3000000000002702' -or $Placement.after.extents.Count -ne 1 -or $Placement.after.extents[0].startingVcn -ne 0 -or $Placement.after.extents[0].nextVcn -ne 16 -or $Placement.after.extents[0].lcn -ne 1508384) { throw 'Unexpected initialized placement control.' }
    foreach($name in @('contentPreserved','originalUnchanged','originalIndependentObservationUnchanged','requestedPlacementObserved','moveCompleted')) { if($Placement.$name -isnot [bool] -or -not $Placement.$name) { throw 'Placement control is incomplete.' } }
}
function Assert-VdlObservationSource($Source) {
    if($Source.schemaVersion -ne 1 -or $Source.kind -cne 'native-vdl-probe' -or $Source.phase -cne 'AllocateZeroVdl' -or $Source.measurementId -cne '2780e16cd7bb4d12a5ba8070bac0a1e7' -or $Source.status -cne 'blocked' -or $Source.nativeSourceSha256 -cne '4cb89a793165cb2307d1dc2fd33135f4138dadad873869c98b0a5bf8af2bce0f' -or $Source.controlEvidenceSha256 -cne '0676470fce3a6ee3500835a02224117bc8106826d4d2f99ac395c3ca4b06bef9'){throw 'Unexpected preserved VDL source.'}
    foreach($name in @('controlQualified','originalFixturesUnchanged','targetWriteRequestsIssued')){if($Source.$name -isnot [bool] -or -not $Source.$name){throw 'Source creation/control evidence incomplete.'}}
    foreach($name in @('zeroVdlQualified','newFilePayloadReads','newFilePayloadWrites','moveAttempted','setValidDataAttempted','privilegeAdjustmentAttempted','physicalMappingVerified','payloadCopyAvoidanceVerified','conversionQualified')){if($Source.$name -isnot [bool] -or $Source.$name){throw 'Source operation/qualification differs.'}}
    $a=$Source.allocationObservation
    if($a.status -cne 'blocked' -or $a.phase -cne 'set-eof' -or $a.fixturePath -cne 'F:\fixtures\vdl-2780e16cd7bb4d12a5ba8070bac0a1e7\uninitialized.bin' -or $a.sha256Before -or $a.sha256After -or @($a.operations).Count -ne 2 -or @($a.snapshots).Count -ne 1){throw 'Unexpected preserved allocation result.'}
    foreach($name in @('directoryCreated','fileCreated','allocationRequested','eofRequested','privateAclVerified')){if($a.$name -isnot [bool] -or -not $a.$name){throw 'Source did not complete creation/allocation/EOF.'}}
    if($a.explicitFlushRequested -isnot [bool] -or $a.explicitFlushRequested){throw 'Source flush state differs.'}
    for($i=0;$i -lt 2;$i++){$op=$a.operations[$i];if($op.name -cne @('FileAllocationInfo','FileEndOfFileInfo')[$i] -or $op.inputHex -cne '0000010000000000' -or $op.succeeded -isnot [bool] -or -not $op.succeeded -or $op.nativeError -ne 0 -or -not $op.finishedUtc){throw 'Source native size request did not complete.'}}
    $s=$a.snapshots[0]
    if($s.name -cne 'immediate' -or $s.fileId64 -cne '0x3000000000002703' -or $s.volumeSerialHex -cne '0x08425382' -or $s.standard.allocationBytes -ne 65536 -or $s.standard.eofBytes -ne 65536 -or $s.cached.vdlBytes -ne 65536 -or $s.onDisk.vdlBytes -ne 0 -or $s.exactState -ne $false){throw 'Preserved native observation changed.'}
}
Import-Module (Join-Path $PSScriptRoot 'GuestLab.psm1') -Force
$computer=Get-CimInstance Win32_ComputerSystem
if($env:COMPUTERNAME -cne 'N2R-WIN11' -or $env:SystemDrive -cne 'C:' -or -not [Environment]::Is64BitProcess -or $computer.Manufacturer -cne 'Microsoft Corporation' -or $computer.Model -cne 'Virtual Machine'){throw 'Owned x64 guest required.'}
$version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if($version.EditionID -cne 'Professional' -or $version.CurrentBuildNumber -cne '26300' -or $version.UBR -ne 9457){throw 'Unexpected Windows profile.'}
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated guest process required.'}
$nativeFile=Get-Item -LiteralPath (Join-Path $PSScriptRoot 'NativeVdlObservation.cs') -Force
if($nativeFile.PSIsContainer -or ($nativeFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $nativeFile.Length -lt 1 -or $nativeFile.Length -gt 64KB){throw 'Unexpected observation helper.'}
if(-not ('Ntfs2Refs.NativeVdlObservation' -as [type])){Add-Type -Path $nativeFile.FullName}
$sourceRoot='C:\ntfs2refs\vdl-probe\2780e16cd7bb4d12a5ba8070bac0a1e7';$controlRoot='C:\ntfs2refs\devdrive-control';$placementId='d98ba93b850d4eababa84c445439868a';$placementRoot='C:\ntfs2refs\extent-placement\'+$placementId
foreach($parent in @('C:\ntfs2refs',$controlRoot,'C:\ntfs2refs\vdl-probe',$sourceRoot,($sourceRoot+'\allocation'),($sourceRoot+'\control'),'C:\ntfs2refs\extent-placement',$placementRoot,'F:\fixtures','F:\fixtures\vdl-2780e16cd7bb4d12a5ba8070bac0a1e7')){$item=Get-Item -LiteralPath $parent -Force;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected input parent.'}}
$sourcePath=Join-Path $sourceRoot 'allocation\allocation.json';$sourceSha='cb484a4a92da8a72861ce4cd7f93ed8bffb1873236cc6c94d4c9efd6861c5fda'
$pinned=@(@($sourcePath,$sourceSha),@(($sourceRoot+'\control\control.json'),'0676470fce3a6ee3500835a02224117bc8106826d4d2f99ac395c3ca4b06bef9'),@(($placementRoot+'\placement.json'),'865e9a7517dd1e0bd925d7fad5af85146fa8ec4c447d5640958473c11cd30cc5'),@(($controlRoot+'\verify.json'),'ca9e3e60bbe84bd758609d92b92a305a948213b4ab0f5ce199f38567a8ea84c1'),@(($controlRoot+'\allocation-after.json'),'f553fd91111dfb09a9aa14d27fe63daaba790c0efb14bd530ac5cd9ef0f55be2'))
foreach($pair in $pinned){Read-VdlObservationJson $pair[0]|Out-Null;if((Get-FileHash -LiteralPath $pair[0] -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pair[1]){throw 'Pinned native evidence changed.'}}
$source=Read-VdlObservationJson $sourcePath;Assert-VdlObservationSource $source
$placement=Read-VdlObservationJson ($placementRoot+'\placement.json');Assert-VdlPlacement $placement $placementId
$control=Read-VdlObservationJson ($controlRoot+'\verify.json');Assert-VdlObservationControl $control '65f270323c26427e8316c7a8b75959cc'
$manifestPath=Join-Path $controlRoot 'target.json';$identity=Read-VdlObservationJson $manifestPath 64KB
foreach($name in @('schemaVersion','role','uniqueId','serialNumber','serialNumberAvailable','sizeBytes','location','enrolledUtc')){if([string]$identity.$name -cne [string]$control.target.guest.$name){throw 'Enrollment changed.'}}
foreach($name in @('guid','diskGuid','number','offset','length','letter','logicalSectorSize','physicalSectorSize')){if([string]$source.partition.$name -cne [string]$control.partition.$name){throw 'Source GPT differs.'}}
$capturedFixture=Get-VdlObservationFixture (Read-VdlObservationJson ($controlRoot+'\allocation-after.json')) $identity
$target=Get-VdlObservationTarget $identity $control
if([string]$target.volume.UniqueId -cne [Ntfs2Refs.NativeVdlObservation]::VolumePath -or $source.volumeUniqueId -cne [Ntfs2Refs.NativeVdlObservation]::VolumePath){throw 'Volume GUID differs.'}
$parent='C:\ntfs2refs\vdl-observation'
if(Test-Path -LiteralPath $parent){$item=Get-Item -LiteralPath $parent -Force;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected observation output parent.'}}else{New-Item -ItemType Directory -Path $parent|Out-Null}
$outputRoot=Join-Path $parent $ObservationId;if(Test-Path -LiteralPath $outputRoot){throw 'Observation output already exists.'};New-Item -ItemType Directory -Path $outputRoot|Out-Null
$record=[ordered]@{schemaVersion=1;kind='native-vdl-post-remount-observation';observationId=$ObservationId;measurementId='2780e16cd7bb4d12a5ba8070bac0a1e7';sourceEvidenceSha256=$sourceSha;sourceCheckpointId='209475c5-c949-41aa-8887-997439f0f70e';scriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();nativeSourceSha256=(Get-FileHash -LiteralPath $nativeFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant();target=$identity;partition=$control.partition;volumeUniqueId=[string]$target.volume.UniqueId;status='blocked';originalFixturesUnchanged=$false;newFilePayloadReads=$false;newFilePayloadWrites=$false;targetWriteRequestsIssued=$false;explicitFlushRequested=$false;moveAttempted=$false;setValidDataAttempted=$false;allocationRequested=$false;protectionChanged=$false;privilegeAdjustmentAttempted=$false;physicalMappingVerified=$false;zeroVdlQualified=$false;payloadCopyAvoidanceVerified=$false;conversionQualified=$false;nativeQueries=@();nativeObservation=$null;errors=@();createdUtc=[DateTime]::UtcNow.ToString('o')}
$fixturePaths=@('nonresident.bin',('placement-'+$placementId+'\initialized.bin'))
try {
    & (Join-Path $PSScriptRoot 'Capture-GuestAllocation.ps1') -ManifestPath $manifestPath -FixtureRelativePath $fixturePaths -OutputPath (Join-Path $outputRoot 'original-before.json') -MaximumHashMiB 8|Out-Null
    $before=Read-VdlObservationJson (Join-Path $outputRoot 'original-before.json');$beforeOriginal=Get-VdlObservationFixture $before $identity
    if(-not (Test-VdlObservationSameMapping $capturedFixture $beforeOriginal)){throw 'Original fixture changed.'}
    $known=@($before.files|Where-Object path -CEQ ('fixtures\placement-'+$placementId+'\initialized.bin'))
    if($known.Count -ne 1 -or -not (Test-VdlObservationSameMapping $placement.after $known[0].observation)){throw 'Initialized control changed.'}
    $native=[Ntfs2Refs.NativeVdlObservation]::Collect([string]$target.volume.UniqueId)
    foreach($q in $native.queries){$path=$null;$sha=$null;if($q.bytes.Length){$path=Join-Path $outputRoot ($q.name+'.bin');[Ntfs2Refs.NativeAllocationEvidence]::WriteReport($path,$q.bytes);$sha=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()};$record.nativeQueries+=[pscustomobject]@{name=$q.name;api=$q.api;controlCode=('0x{0:x8}' -f $q.controlCode);informationClass=$q.informationClass;inputHex=$q.inputHex;inputBytes=$q.inputBytes;outputCapacityBytes=$q.outputCapacityBytes;succeeded=$q.succeeded;nativeError=$q.nativeError;nativeMessage=$q.nativeMessage;bytesReturned=$q.bytesReturned;bufferPath=$path;bufferSha256=$sha;startedUtc=$q.startedUtc;finishedUtc=$q.finishedUtc}}
    $record.nativeObservation=$native|Select-Object * -ExcludeProperty queries;$record.status=$native.status
    & (Join-Path $PSScriptRoot 'Capture-GuestAllocation.ps1') -ManifestPath $manifestPath -FixtureRelativePath $fixturePaths -OutputPath (Join-Path $outputRoot 'original-after.json') -MaximumHashMiB 8|Out-Null
    $after=Read-VdlObservationJson (Join-Path $outputRoot 'original-after.json');$afterOriginal=Get-VdlObservationFixture $after $identity
    $knownAfter=@($after.files|Where-Object path -CEQ ('fixtures\placement-'+$placementId+'\initialized.bin'))
    if($knownAfter.Count -ne 1 -or -not (Test-VdlObservationSameMapping $beforeOriginal $afterOriginal) -or -not (Test-VdlObservationSameMapping $placement.after $knownAfter[0].observation)){throw 'Original fixtures changed during observation.'}
    $current=Get-VdlObservationTarget $identity $control;if([string]$current.volume.UniqueId -cne [string]$target.volume.UniqueId){throw 'Target changed.'};$record.originalFixturesUnchanged=$true
}catch{$record.status='blocked';$record.errors+=$_.Exception.ToString()}
$record['finishedUtc']=[DateTime]::UtcNow.ToString('o')
# The allocation collector loads the bounded create-new evidence writer. If it failed
# before loading, stop and let the host preserve this branch rather than overwrite.
if(-not ('Ntfs2Refs.NativeAllocationEvidence' -as [type])){throw 'Evidence writer unavailable; preserve branch.'}
$bytes=(New-Object Text.UTF8Encoding($false)).GetBytes(($record|ConvertTo-Json -Depth 18));if($bytes.Length -gt 1MB){throw 'Observation JSON exceeds bound.'};[Ntfs2Refs.NativeAllocationEvidence]::WriteReport((Join-Path $outputRoot 'observation.json'),$bytes)
[pscustomobject]@{Status=$record.status;ObservationId=$ObservationId;EvidenceDirectory=$outputRoot;NewFilePayloadReads=$false;TargetWriteRequestsIssued=$false;ConversionQualified=$false}
