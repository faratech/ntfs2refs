<# Two explicitly separate stages: known initialized control, then allocation/EOF.
   No payload access to the new file; no movement, valid-data or privilege changes. #>
[CmdletBinding(SupportsShouldProcess)]
param(
 [Parameter(Mandatory)][ValidateSet('MeasureInitializedControl','AllocateZeroVdl')][string]$Phase,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$PlacementProbeId,
 [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$PlacementEvidenceSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$MeasurementId,
 [ValidatePattern('^[0-9a-f]{64}$')][string]$ControlEvidenceSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($Phase -ceq 'AllocateZeroVdl' -and -not $ControlEvidenceSha256){throw 'Allocation requires a hash-bound qualified VDL control.'}
if($Phase -ceq 'MeasureInitializedControl' -and $ControlEvidenceSha256){throw 'The measurement control cannot consume a prior control record.'}
if(-not $PSCmdlet.ShouldProcess('Owned ReFS guest target',('Execute bounded VDL stage '+$Phase))) {
 [pscustomobject]@{DryRun=$true;Phase=$Phase;MaximumNewFileBytes=65536;NewFilePayloadReads=$false;NewFilePayloadWrites=$false;MoveAttempted=$false;SetValidDataAttempted=$false;ConversionQualified=$false};return
}
function Read-VdlProbeJson([string]$Path,[long]$MaximumBytes=1MB) {
    $file=Get-Item -LiteralPath $Path -Force
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -lt 1 -or $file.Length -gt $MaximumBytes) { throw 'Expected a bounded ordinary evidence file.' }
    [IO.File]::ReadAllText($file.FullName,(New-Object Text.UTF8Encoding($false,$true))) | ConvertFrom-Json
}
function Assert-VdlProbeControl($Control,[string]$ExpectedRunId) {
    if ($Control.schemaVersion -ne 1 -or $Control.kind -cne 'devdrive-data-control' -or $Control.phase -cne 'Verify' -or $Control.runId -cne $ExpectedRunId -or $Control.status -cne 'verified' -or $Control.formatSucceeded -ne $true -or $Control.remountVerified -ne $true -or $Control.ordinaryReFS -ne $false -or $Control.refsBootVerified -ne $false -or $Control.conversionQualified -ne $false) { throw 'The native Dev Drive data control has not completed.' }
    if ([string]$Control.target.host.vhdId -ine '25C491D0-5F1B-4205-9E6F-FD619706C2B5' -or $Control.target.host.sizeBytes -ne 64GB -or $Control.target.host.controllerLocation -ne 1 -or $Control.target.guest.uniqueId -cne '60022480D091C4251B5FFD619706C2B5' -or $Control.target.guest.role -cne 'target' -or $Control.target.guest.sizeBytes -ne 64GB) { throw 'Control target differs from the original owned virtual disk.' }
    $part=$Control.partition
    foreach($name in @('guid','diskGuid')) { $id=[guid]::Empty; if(-not [guid]::TryParse([string]$part.$name,[ref]$id) -or $id -eq [guid]::Empty) { throw 'Missing native GPT identity.' } }
    if ($part.number -ne 2 -or $part.offset -ne 16MB -or $part.length -ne 52GB -or $part.letter -cne 'F' -or $part.logicalSectorSize -ne 512 -or $part.physicalSectorSize -ne 4096 -or $Control.after.filesystem -cne 'ReFS' -or $Control.after.allocationUnitSize -ne 4096 -or $Control.after.size -ne 52GB) { throw 'Native partition profile differs.' }
}
function Get-VdlProbeTarget($Identity,$Control) {
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
function Get-VdlProbeFixture($Evidence,$Identity) {
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
function Test-VdlProbeSameMapping($Left,$Right) {
    if ($Left.fileId64 -cne $Right.fileId64 -or $Left.volumeSerialHex -cne $Right.volumeSerialHex -or $Left.length -ne $Right.length -or $Left.sha256 -cne $Right.sha256 -or @($Left.extents).Count -ne @($Right.extents).Count) { return $false }
    for($i=0;$i -lt @($Left.extents).Count;$i++) { foreach($name in @('startingVcn','nextVcn','lcn')) { if($Left.extents[$i].$name -ne $Right.extents[$i].$name) { return $false } } }
    $true
}
function Assert-VdlPlacement($Placement,[string]$Id) {
    if($Id -cne 'd98ba93b850d4eababa84c445439868a' -or $Placement.schemaVersion -ne 1 -or $Placement.kind -cne 'native-initialized-file-placement' -or $Placement.probeId -cne $Id -or $Placement.status -cne 'native-placement-observed-awaiting-remount' -or $Placement.nativePhase -cne 'complete' -or $Placement.expectedSha256 -cne '9b195d4598044587ab6e51b73d92063936710b9b1255158054918350d20f1d78' -or $Placement.after.sha256 -cne $Placement.expectedSha256 -or $Placement.after.length -ne 65536 -or $Placement.after.fileId64 -cne '0x3000000000002702' -or $Placement.after.extents.Count -ne 1 -or $Placement.after.extents[0].startingVcn -ne 0 -or $Placement.after.extents[0].nextVcn -ne 16 -or $Placement.after.extents[0].lcn -ne 1508384) { throw 'Unexpected initialized placement control.' }
    foreach($name in @('contentPreserved','originalUnchanged','originalIndependentObservationUnchanged','requestedPlacementObserved','moveCompleted')) { if($Placement.$name -isnot [bool] -or -not $Placement.$name) { throw 'Placement control is incomplete.' } }
}
function Assert-VdlControl($Record,[string]$ExpectedMeasurement,[string]$PlacementSha,[string]$ScriptSha,[string]$NativeSha) {
    if($Record.schemaVersion -ne 1 -or $Record.kind -cne 'native-vdl-probe' -or $Record.phase -cne 'MeasureInitializedControl' -or $Record.measurementId -cne $ExpectedMeasurement -or $Record.placementEvidenceSha256 -cne $PlacementSha -or $Record.status -cne 'initialized-vdl-control-qualified' -or $Record.scriptSha256 -cne $ScriptSha -or $Record.nativeSourceSha256 -cne $NativeSha -or $Record.controlQualified -ne $true -or $Record.originalFixturesUnchanged -ne $true -or $Record.targetWriteRequestsIssued -ne $false) { throw 'VDL API control is not qualified for this exact probe/source.' }
    foreach($name in @('newFilePayloadReads','newFilePayloadWrites','moveAttempted','setValidDataAttempted','privilegeAdjustmentAttempted','physicalMappingVerified','payloadCopyAvoidanceVerified','conversionQualified')) { if($Record.$name -isnot [bool] -or $Record.$name) { throw 'VDL control claims an unperformed qualification or operation.' } }
}
Import-Module (Join-Path $PSScriptRoot 'GuestLab.psm1') -Force
$computer=Get-CimInstance Win32_ComputerSystem
if($env:COMPUTERNAME -cne 'N2R-WIN11' -or $env:SystemDrive -cne 'C:' -or -not [Environment]::Is64BitProcess -or $computer.Manufacturer -cne 'Microsoft Corporation' -or $computer.Model -cne 'Virtual Machine') { throw 'Owned 64-bit guest required.' }
$version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if($version.EditionID -cne 'Professional' -or $version.CurrentBuildNumber -cne '26300' -or $version.UBR -ne 9457) { throw 'Unexpected Windows profile.' }
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'An elevated guest process is required.' }
if($PlacementEvidenceSha256 -cne '865e9a7517dd1e0bd925d7fad5af85146fa8ec4c447d5640958473c11cd30cc5') { throw 'Only the reviewed initialized placement record is accepted.' }
$nativeFile=Get-Item -LiteralPath (Join-Path $PSScriptRoot 'NativeVdlProbe.cs') -Force
if($nativeFile.PSIsContainer -or ($nativeFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $nativeFile.Length -lt 1 -or $nativeFile.Length -gt 64KB) { throw 'Unexpected native VDL helper.' }
if(-not ('Ntfs2Refs.NativeVdlProbe' -as [type])) { Add-Type -Path $nativeFile.FullName }
$scriptSha=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();$nativeSha=(Get-FileHash -LiteralPath $nativeFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
$controlRoot='C:\ntfs2refs\devdrive-control';$placementRoot='C:\ntfs2refs\extent-placement\'+$PlacementProbeId
foreach($parent in @('C:\ntfs2refs',$controlRoot,'C:\ntfs2refs\extent-placement',$placementRoot,'F:\fixtures')) { $item=Get-Item -LiteralPath $parent -Force;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected input parent.'} }
$placementPath=Join-Path $placementRoot 'placement.json'
if((Get-FileHash -LiteralPath $placementPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $PlacementEvidenceSha256) { throw 'Placement proof changed.' }
$placement=Read-VdlProbeJson $placementPath;Assert-VdlPlacement $placement $PlacementProbeId
$verifyPath=Join-Path $controlRoot 'verify.json';$allocationPath=Join-Path $controlRoot 'allocation-after.json';$manifestPath=Join-Path $controlRoot 'target.json'
if((Get-FileHash -LiteralPath $verifyPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne 'ca9e3e60bbe84bd758609d92b92a305a948213b4ab0f5ce199f38567a8ea84c1' -or (Get-FileHash -LiteralPath $allocationPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne 'f553fd91111dfb09a9aa14d27fe63daaba790c0efb14bd530ac5cd9ef0f55be2') { throw 'Native source proofs changed.' }
$control=Read-VdlProbeJson $verifyPath;Assert-VdlProbeControl $control '65f270323c26427e8316c7a8b75959cc'
$identity=Read-VdlProbeJson $manifestPath 64KB
foreach($name in @('schemaVersion','role','uniqueId','serialNumber','serialNumberAvailable','sizeBytes','location','enrolledUtc')){if([string]$identity.$name -cne [string]$control.target.guest.$name){throw 'Enrollment differs.'}}
$captured=Read-VdlProbeJson $allocationPath;$capturedFixture=Get-VdlProbeFixture $captured $identity
$target=Get-VdlProbeTarget $identity $control
foreach($name in @('guid','diskGuid','number','offset','length','letter','logicalSectorSize','physicalSectorSize')){if([string]$placement.partition.$name -cne [string]$control.partition.$name){throw 'Placement GPT differs.'}}
if([string]$target.volume.UniqueId -cne $placement.volumeUniqueId) { throw 'Placement volume changed.' }
$parent='C:\ntfs2refs\vdl-probe'
if(Test-Path -LiteralPath $parent){$item=Get-Item -LiteralPath $parent -Force;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected VDL output parent.'}}else{New-Item -ItemType Directory -Path $parent|Out-Null}
$runRoot=Join-Path $parent $MeasurementId
if($Phase -ceq 'MeasureInitializedControl'){if(Test-Path -LiteralPath $runRoot){throw 'VDL measurement run already exists.'};New-Item -ItemType Directory -Path $runRoot|Out-Null}
else {
    $item=Get-Item -LiteralPath $runRoot -Force;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected VDL run root.'}
    $qualifiedPath=Join-Path $runRoot 'control\control.json';$item=Get-Item -LiteralPath (Split-Path $qualifiedPath -Parent) -Force
    if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected VDL control root.'}
    if((Get-FileHash -LiteralPath $qualifiedPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ControlEvidenceSha256){throw 'Qualified VDL proof changed.'}
    Assert-VdlControl (Read-VdlProbeJson $qualifiedPath) $MeasurementId $PlacementEvidenceSha256 $scriptSha $nativeSha
    if(Test-Path -LiteralPath (Split-Path ([Ntfs2Refs.NativeVdlProbe]::PathFor($MeasurementId,$false)) -Parent)){throw 'New private fixture directory already exists.'}
}
$stageName=if($Phase -ceq 'MeasureInitializedControl'){'control'}else{'allocation'}
$outputRoot=Join-Path $runRoot $stageName
if(Test-Path -LiteralPath $outputRoot){throw 'VDL stage output already exists.'};New-Item -ItemType Directory -Path $outputRoot|Out-Null
$record=[ordered]@{schemaVersion=1;kind='native-vdl-probe';phase=$Phase;measurementId=$MeasurementId;placementProbeId=$PlacementProbeId;placementEvidenceSha256=$PlacementEvidenceSha256;controlEvidenceSha256=$ControlEvidenceSha256;scriptSha256=$scriptSha;nativeSourceSha256=$nativeSha;target=$identity;partition=$control.partition;volumeUniqueId=[string]$target.volume.UniqueId;status='blocked';controlQualified=$false;zeroVdlQualified=$false;originalFixturesUnchanged=$false;targetWriteRequestsMayHaveBeenIssued=$false;targetWriteRequestsIssued=$false;newFilePayloadReads=$false;newFilePayloadWrites=$false;moveAttempted=$false;setValidDataAttempted=$false;privilegeAdjustmentAttempted=$false;physicalMappingVerified=$false;payloadCopyAvoidanceVerified=$false;conversionQualified=$false;newFileMayConsumeResidualCanary=$true;nativeQueries=@();errors=@();createdUtc=[DateTime]::UtcNow.ToString('o')}
function Save-VdlJson([string]$Name,$Value){$bytes=(New-Object Text.UTF8Encoding($false)).GetBytes(($Value|ConvertTo-Json -Depth 18));if($bytes.Length -gt 1MB){throw 'VDL JSON bound exceeded.'};[Ntfs2Refs.NativeAllocationEvidence]::WriteReport((Join-Path $outputRoot $Name),$bytes)}
function Save-VdlNative([string]$Prefix,$Native) {
    foreach($query in $Native.queries){$path=$null;$sha=$null;if($null -ne $query.bytes -and $query.bytes.Length -gt 0){$path=Join-Path $outputRoot ($Prefix+'-'+$query.name+'.bin');[Ntfs2Refs.NativeAllocationEvidence]::WriteReport($path,$query.bytes);$sha=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()};$record.nativeQueries+= [pscustomobject]@{name=($Prefix+'-'+$query.name);api=$query.api;controlCode=('0x{0:x8}' -f $query.controlCode);informationClass=$query.informationClass;inputHex=$query.inputHex;inputBytes=$query.inputBytes;outputCapacityBytes=$query.outputCapacityBytes;succeeded=$query.succeeded;nativeError=$query.nativeError;nativeMessage=$query.nativeMessage;bytesReturned=$query.bytesReturned;bufferPath=$path;bufferSha256=$sha;startedUtc=$query.startedUtc;finishedUtc=$query.finishedUtc}}
    [pscustomobject]@{status=$Native.status;phase=$Native.phase;error=$Native.error;fixturePath=$Native.fixturePath;sha256Before=$Native.sha256Before;sha256After=$Native.sha256After;privateSddl=$Native.privateSddl;targetWriteRequestsIssued=$Native.targetWriteRequestsIssued;directoryCreated=$Native.directoryCreated;fileCreated=$Native.fileCreated;allocationRequested=$Native.allocationRequested;eofRequested=$Native.eofRequested;explicitFlushRequested=$Native.explicitFlushRequested;privateAclVerified=$Native.privateAclVerified;controlQualified=$Native.controlQualified;zeroVdlQualified=$Native.zeroVdlQualified;snapshots=$Native.snapshots;operations=$Native.operations}
}
try {
    $fixturePaths=@('nonresident.bin',('placement-'+$PlacementProbeId+'\initialized.bin'))
    & (Join-Path $PSScriptRoot 'Capture-GuestAllocation.ps1') -ManifestPath $manifestPath -FixtureRelativePath $fixturePaths -OutputPath (Join-Path $outputRoot 'original-before.json') -MaximumHashMiB 8|Out-Null
    $before=Read-VdlProbeJson (Join-Path $outputRoot 'original-before.json');$beforeOriginal=Get-VdlProbeFixture $before $identity
    if(-not (Test-VdlProbeSameMapping $capturedFixture $beforeOriginal)){throw 'Original fixture changed.'}
    $known=@($before.files|Where-Object path -CEQ ('fixtures\placement-'+$PlacementProbeId+'\initialized.bin'))
    if($known.Count -ne 1 -or -not (Test-VdlProbeSameMapping $placement.after $known[0].observation)){throw 'Initialized control changed.'}
    $nativeControl=[Ntfs2Refs.NativeVdlProbe]::MeasureInitialized([string]$target.volume.UniqueId,$PlacementProbeId,[string]$placement.expectedSha256,[string]$placement.after.fileId64)
    $record['controlObservation']=Save-VdlNative 'control' $nativeControl;$record.controlQualified=$nativeControl.controlQualified;$record.status=$nativeControl.status
    if($nativeControl.error){$record.errors+=$nativeControl.error}
    if($Phase -ceq 'AllocateZeroVdl' -and $nativeControl.controlQualified){
        $current=Get-VdlProbeTarget $identity $control;if([string]$current.volume.UniqueId -cne [string]$target.volume.UniqueId){throw 'Target changed before allocation.'}
        $record.targetWriteRequestsMayHaveBeenIssued=$true;Save-VdlJson 'started.json' $record
        $native=[Ntfs2Refs.NativeVdlProbe]::AllocateZero([string]$target.volume.UniqueId,$MeasurementId)
        $record['allocationObservation']=Save-VdlNative 'allocation' $native;$record.status=$native.status;$record.targetWriteRequestsIssued=$native.targetWriteRequestsIssued;$record.zeroVdlQualified=$native.zeroVdlQualified
        if($native.error){$record.errors+=$native.error}
    }
    & (Join-Path $PSScriptRoot 'Capture-GuestAllocation.ps1') -ManifestPath $manifestPath -FixtureRelativePath $fixturePaths -OutputPath (Join-Path $outputRoot 'original-after.json') -MaximumHashMiB 8|Out-Null
    $after=Read-VdlProbeJson (Join-Path $outputRoot 'original-after.json');$afterOriginal=Get-VdlProbeFixture $after $identity
    $afterKnown=@($after.files|Where-Object path -CEQ ('fixtures\placement-'+$PlacementProbeId+'\initialized.bin'))
    $record.originalFixturesUnchanged=(Test-VdlProbeSameMapping $beforeOriginal $afterOriginal) -and $afterKnown.Count -eq 1 -and (Test-VdlProbeSameMapping $placement.after $afterKnown[0].observation)
    if(-not $record.originalFixturesUnchanged){$record.status='original-fixture-check-failed';$record.controlQualified=$false;$record.zeroVdlQualified=$false}
    $current=Get-VdlProbeTarget $identity $control;if([string]$current.volume.UniqueId -cne [string]$target.volume.UniqueId){throw 'Target changed after observation.'}
}catch{$record.status='blocked';$record.errors+=$_.Exception.Message;$record['errorPosition']=$_.InvocationInfo.PositionMessage}
finally{$record['finishedUtc']=[DateTime]::UtcNow.ToString('o');if('Ntfs2Refs.NativeAllocationEvidence' -as [type]){Save-VdlJson ($stageName+'.json') $record}}
[pscustomobject]@{Status=$record.status;Phase=$Phase;MeasurementId=$MeasurementId;EvidenceDirectory=$outputRoot;ControlQualified=$record.controlQualified;ZeroVdlQualified=$record.zeroVdlQualified;TargetWriteRequestsIssued=$record.targetWriteRequestsIssued;MoveAttempted=$false;SetValidDataAttempted=$false;ConversionQualified=$false}
