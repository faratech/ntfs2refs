<# Pure/mocked host guards and ordinary temporary evidence. No Hyper-V/native controls. #>
[CmdletBinding()]
param([string]$SourceDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
$path=Join-Path $workspace 'scripts\Invoke-LabVdlObservation.ps1';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors);if($errors.Count){throw 'Host parse failed.'}
foreach($f in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){Invoke-Expression $f.Extent.Text}
if(-not ('Ntfs2Refs.FakeVdlObservationApi' -as [type])){Add-Type -TypeDefinition ((Get-Content -LiteralPath (Join-Path $PSScriptRoot 'guest\NativeVdlObservation.cs') -Raw)+[Environment]::NewLine+(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'FakeVdlObservation.cs') -Raw))}
$script:checks=0
function Check([bool]$Value,[string]$Message){if(-not $Value){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$rejected=$false;try{& $Action|Out-Null}catch{$rejected=$true};Check $rejected $Message}
function Clone($Value){$Value|ConvertTo-Json -Depth 22|ConvertFrom-Json}
$profile=Get-VdlObservationHostProfile
$manifest=[pscustomobject]@{vmId=$profile.vmId;disks=@([pscustomobject]@{role='os';controllerLocation=0;sizeBytes=64GB},[pscustomobject]@{role='target';controllerLocation=1;sizeBytes=64GB;vhdId=$profile.targetVhdId},[pscustomobject]@{role='journal';controllerLocation=2;sizeBytes=8GB})}
Assert-VdlObservationHostManifest $manifest $profile;$script:checks++
foreach($field in @('role','controllerLocation','sizeBytes','vhdId')){$b=Clone $manifest;$b.disks[1].$field=if($field -cin @('controllerLocation','sizeBytes')){0}else{'wrong'};Reject {Assert-VdlObservationHostManifest $b $profile} 'Changed owned disk accepted.'}
$b=Clone $manifest;$b.vmId=[guid]::NewGuid().ToString();Reject {Assert-VdlObservationHostManifest $b $profile} 'Wrong VM accepted.'
$script:network='';$script:secureBoot='On'
function Get-VMNetworkAdapter {param($VM);[pscustomobject]@{SwitchName=$script:network}}
function Get-VMFirmware {param($VM);[pscustomobject]@{SecureBoot=$script:secureBoot}}
$vm=[pscustomobject]@{State='Off';MemoryStartup=4GB;DynamicMemoryEnabled=$false;ParentSnapshotId=$profile.baselineId}
Assert-VdlObservationHostVM $vm $profile.baselineId 4GB;$script:checks++
foreach($pair in @(@('State','Running'),@('MemoryStartup',8GB),@('DynamicMemoryEnabled',$true),@('ParentSnapshotId',$profile.checkpointId))){$b=Clone $vm;$b.($pair[0])=$pair[1];Reject {Assert-VdlObservationHostVM $b $profile.baselineId 4GB} 'Unexpected VM state accepted.'}
$script:network='external';Reject {Assert-VdlObservationHostVM $vm $profile.baselineId 4GB} 'Connected network accepted.';$script:network='';$script:secureBoot='Off';Reject {Assert-VdlObservationHostVM $vm $profile.baselineId 4GB} 'Secure Boot change accepted.';$script:secureBoot='On'
$cp=[pscustomobject]@{Id=$profile.checkpointId;Name=$profile.checkpointName;VMId=$profile.vmId;State='Off';MemoryStartup=8GB;DynamicMemoryEnabled=$false}
Assert-VdlObservationHostCheckpoint $cp $profile;$script:checks++
foreach($pair in @(@('Id',$profile.baselineId),@('Name','wrong'),@('VMId',[guid]::NewGuid().ToString()),@('State','Running'),@('MemoryStartup',4GB),@('DynamicMemoryEnabled',$true))){$b=Clone $cp;$b.($pair[0])=$pair[1];Reject {Assert-VdlObservationHostCheckpoint $b $profile} 'Changed checkpoint accepted.'}
$baseline=Clone $cp;$baseline.Id=$profile.baselineId;$baseline.Name='installed-clean';$baseline.MemoryStartup=4GB;Assert-VdlObservationHostCheckpoint $baseline $profile -Baseline;$script:checks++
foreach($prefix in @('before','after')){foreach($suffix in @('Standard','Cached','OnDisk','Extents')){$s=Get-VdlObservationHostQuerySpec ($prefix+$suffix);Check ($s.capacity -in @(24,272,400)) 'Wrong query bound.'}}
foreach($name in @('','../beforeStandard','beforeStandard.bin','control-beforeStandard',('beforeStandard'+[char]10),'afterFlush')){Reject {Get-VdlObservationHostQuerySpec $name} 'Unreviewed query accepted.'}
$response=[pscustomobject]@{ObservationId=('a'*32);EvidenceDirectory=('C:\ntfs2refs\vdl-observation\'+('a'*32));Status='metadata-observed';NewFilePayloadReads=$false;TargetWriteRequestsIssued=$false;ConversionQualified=$false}
Assert-VdlObservationHostResponse $response ('a'*32);$script:checks++
foreach($pair in @(@('ObservationId',('b'*32)),@('EvidenceDirectory','C:\Windows'),@('Status','success'),@('NewFilePayloadReads',$true),@('TargetWriteRequestsIssued',$true),@('ConversionQualified',$true))){$b=Clone $response;$b.($pair[0])=$pair[1];Reject {Assert-VdlObservationHostResponse $b ('a'*32)} 'Changed response accepted.'}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('n2r-vdl-observation-tests-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $temp|Out-Null
try {
    $api=New-Object Ntfs2Refs.FakeVdlObservationApi;$native=[Ntfs2Refs.NativeVdlObservation]::CollectWith($api,[Ntfs2Refs.NativeVdlObservation]::VolumePath)
    $control=[pscustomobject]@{target=[pscustomobject]@{guest=[pscustomobject]@{role='target';uniqueId='60022480D091C4251B5FFD619706C2B5';sizeBytes=64GB;location='test-owned-target'}};partition=[pscustomobject]@{guid='{00c9f113-e0b9-49d8-b031-130aef8ef3fb}';diskGuid='{b4ab4dbc-6bd7-4199-8e4a-01b828e98584}';number=2;offset=16MB;length=52GB;letter='F';logicalSectorSize=512;physicalSectorSize=4096}}
    $record=[pscustomobject]@{schemaVersion=1;kind='native-vdl-post-remount-observation';observationId=$response.ObservationId;measurementId=$profile.measurementId;sourceEvidenceSha256=$profile.sourceEvidenceSha256;sourceCheckpointId=$profile.checkpointId;scriptSha256=('b'*64);nativeSourceSha256=('c'*64);target=$control.target.guest;partition=$control.partition;volumeUniqueId=[Ntfs2Refs.NativeVdlObservation]::VolumePath;status=$native.status;originalFixturesUnchanged=$true;newFilePayloadReads=$false;newFilePayloadWrites=$false;targetWriteRequestsIssued=$false;explicitFlushRequested=$false;moveAttempted=$false;setValidDataAttempted=$false;allocationRequested=$false;protectionChanged=$false;privilegeAdjustmentAttempted=$false;physicalMappingVerified=$false;zeroVdlQualified=$false;payloadCopyAvoidanceVerified=$false;conversionQualified=$false;nativeQueries=@();nativeObservation=($native|Select-Object * -ExcludeProperty queries);errors=@();finishedUtc='2026-10-24T01:00:00Z'}
    foreach($q in $native.queries){$p=Join-Path $temp ($q.name+'.bin');[IO.File]::WriteAllBytes($p,$q.bytes);$record.nativeQueries+=[pscustomobject]@{name=$q.name;api=$q.api;controlCode=('0x{0:x8}' -f $q.controlCode);informationClass=$q.informationClass;inputHex=$q.inputHex;inputBytes=$q.inputBytes;outputCapacityBytes=$q.outputCapacityBytes;succeeded=$q.succeeded;nativeError=$q.nativeError;nativeMessage=$q.nativeMessage;bytesReturned=$q.bytesReturned;bufferPath=($response.EvidenceDirectory+'\'+$q.name+'.bin');bufferSha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant();startedUtc=$q.startedUtc;finishedUtc=$q.finishedUtc}}
    foreach($name in @('observation.json','original-before.json','original-after.json')){[IO.File]::WriteAllText((Join-Path $temp $name),'{}')}
    $files=@(Get-ChildItem -LiteralPath $temp|ForEach-Object{[pscustomobject]@{name=$_.Name;length=$_.Length;attributes=[string]$_.Attributes;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}})
    Assert-VdlObservationHostArtifactSet $files;$script:checks++
    Assert-VdlObservationHostRecord $record $response $profile $control $files ('b'*64) ('c'*64) $temp;$script:checks++
    Assert-VdlObservationHostDisposition $record;$script:checks++
    foreach($pair in @(@('name','..\evil.bin'),@('name',('beforeStandard.bin'+[char]10)),@('length',0),@('length',(1MB+1)),@('attributes','ReparsePoint'),@('attributes','Directory'),@('sha256',('A'*64)))){$bad=Clone $files;$bad[0].($pair[0])=$pair[1];Reject {Assert-VdlObservationHostArtifactSet $bad} 'Invalid artifact accepted.'}
    Reject {Assert-VdlObservationHostArtifactSet @($files+$files[0])} 'Duplicate artifacts accepted.'
    Reject {Assert-VdlObservationHostArtifactSet @($files|Where-Object name -CNE 'observation.json')} 'Missing result accepted.'
    foreach($pair in @(@('sourceEvidenceSha256',('a'*64)),@('sourceCheckpointId',$profile.baselineId),@('measurementId',('a'*32)),@('nativeSourceSha256',('a'*64)),@('volumeUniqueId','\\.\C:'),@('newFilePayloadReads',$true),@('targetWriteRequestsIssued',$true),@('zeroVdlQualified',$true),@('protectionChanged',$true),@('conversionQualified',$true))){$bad=Clone $record;$bad.($pair[0])=$pair[1];Reject {Assert-VdlObservationHostRecord $bad $response $profile $control $files ('b'*64) ('c'*64) $temp} 'Changed observation provenance/claims accepted.'}
    foreach($pair in @(@('controlCode','0x00090074'),@('inputHex','ff'),@('outputCapacityBytes',1MB),@('nativeError',5),@('bufferPath','C:\other.bin'),@('bufferSha256',('a'*64)))){$bad=Clone $record;$bad.nativeQueries[0].($pair[0])=$pair[1];Reject {Assert-VdlObservationHostRecord $bad $response $profile $control $files ('b'*64) ('c'*64) $temp} 'Altered query accepted.'}
    $bad=Clone $record;$bad.nativeObservation.snapshots[0].extents[0].lcn=0;Reject {Assert-VdlObservationHostRecord $bad $response $profile $control $files ('b'*64) ('c'*64) $temp} 'Negative marker fabricated as physical.'
    $bad=Clone $record;$bad.nativeObservation.snapshots[0].cached.prefixBytes=0;Reject {Assert-VdlObservationHostRecord $bad $response $profile $control $files ('b'*64) ('c'*64) $temp} 'Reported regions differ from native bytes.'
    $bad=Clone $record;$bad.nativeObservation.volumes[0].supportsSparseVdl=$false;Reject {Assert-VdlObservationHostRecord $bad $response $profile $control $files ('b'*64) ('c'*64) $temp} 'Sparse-VDL flag contradiction accepted.'
    $bad=Clone $record;$bad.nativeObservation.snapshots[1].identity.attributes=128;Reject {Assert-VdlObservationHostRecord $bad $response $profile $control $files ('b'*64) ('c'*64) $temp} 'Attribute change claimed stable.'
    $bad.nativeObservation.stableDuringObservation=$false;Assert-VdlObservationHostRecord $bad $response $profile $control $files ('b'*64) ('c'*64) $temp;$script:checks++
    foreach($field in @('identityVerified','cleanupComplete')){$bad=Clone $record;$bad.nativeObservation.$field=$false;Reject {Assert-VdlObservationHostDisposition $bad} 'Indeterminate result allowed restore.'}
    $bad=Clone $record;$bad.originalFixturesUnchanged=$false;Reject {Assert-VdlObservationHostDisposition $bad} 'Changed originals allowed restore.'
    foreach($field in @('error','cleanupError')){$bad=Clone $record;$bad.nativeObservation.$field='failure';Reject {Assert-VdlObservationHostDisposition $bad} 'Native failure allowed restore.'}
    $bad=Clone $record;$bad.status='blocked';Reject {Assert-VdlObservationHostDisposition $bad} 'Blocked result allowed restore.'
    $bad=Clone $record;$bad.status='native-query-unresolved';$bad.nativeObservation.status='native-query-unresolved';$bad.nativeObservation.observationComplete=$false;Assert-VdlObservationHostDisposition $bad;$script:checks++
    if($SourceDirectory){
        $origin=Read-VdlObservationHostPinned (Join-Path $SourceDirectory 'host-result.json') $profile.sourceHostSha256;Assert-VdlObservationHostOrigin $origin $profile;$script:checks++
        foreach($pair in @(@('status','success'),@('cleanShutdown',$false),@('baselineRestored',$false),@('commandCompletionUnknown',$true),@('zeroVdlQualified',$true),@('outcomeCheckpointId',$profile.baselineId))){$bad=Clone $origin;$bad.($pair[0])=$pair[1];Reject {Assert-VdlObservationHostOrigin $bad $profile} 'Wrong source origin accepted.'}
        $source=Read-VdlObservationHostPinned (Join-Path $SourceDirectory 'allocation\allocation.json') $profile.sourceEvidenceSha256;Assert-VdlObservationSource $source;$script:checks++
        $sourceFiles=@(Read-VdlObservationHostPinned (Join-Path $SourceDirectory 'allocation\exported-files.json') $profile.sourceExportSha256);Assert-VdlObservationHostSourceFiles $sourceFiles (Join-Path $SourceDirectory 'allocation');$script:checks++
        $bad=Clone $sourceFiles;$bad[0].name='..\outside';Reject {Assert-VdlObservationHostSourceFiles $bad (Join-Path $SourceDirectory 'allocation')} 'Source path escape accepted.'
        $bad=Clone $sourceFiles;$bad[0].sha256='a'*64;Reject {Assert-VdlObservationHostSourceFiles $bad (Join-Path $SourceDirectory 'allocation')} 'Changed source buffer accepted.'
    }
}finally{
    $full=[IO.Path]::GetFullPath($temp);$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    if(-not $full.StartsWith($base,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -cnotmatch '\An2r-vdl-observation-tests-[0-9a-f]{32}\z'){throw 'Unexpected test cleanup path.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
$session=[pscustomobject]@{};$script:jobMode='complete';$script:removed=$false
function Invoke-Command {param($Session,[switch]$AsJob,$ArgumentList,$ScriptBlock);[pscustomobject]@{State=if($script:jobMode -ceq 'incomplete'){'Running'}elseif($script:jobMode -ceq 'failed'){'Failed'}else{'Completed'}}}
function Wait-Job {param($Job,$Timeout);if($script:jobMode -cne 'timeout'){$Job}}
function Receive-Job {param($Job);if($script:jobMode -ceq 'receive-error'){throw 'transport lost'};'returned'}
function Remove-Job {param($Job,[switch]$Force);$script:removed=$true}
$reply=@(Invoke-BoundedVdlObservationCommand -ScriptBlock {});Check ($reply.Count -eq 1 -and -not $script:commandIndeterminate -and $script:removed) 'Completed command remained unknown.'
foreach($mode in @('timeout','incomplete','failed','receive-error')){$script:jobMode=$mode;$script:removed=$false;Reject {Invoke-BoundedVdlObservationCommand -ScriptBlock {}} 'Uncertain command accepted.';Check $script:commandIndeterminate 'Uncertain completion flag lost.'}
$dry=& $path -WhatIf;Check ($dry.DryRun -and -not $dry.NewFilePayloadReads -and -not $dry.TargetWriteRequestsIssued) 'Host WhatIf differs.'
$text=Get-Content -LiteralPath $path -Raw
Check ($text -notmatch 'Stop-VM|TurnOff|Remove-VMSnapshot|Mount-VHD|Dismount-VHD|Set-Disk|AllocateZeroVdl -') 'Forbidden host operation introduced.'
Check ($text.IndexOf('Assert-VdlObservationHostDisposition $export.record') -lt $text.IndexOf('Stop-VdlObservationHostGuest;$record.cleanShutdown')) 'Cleanup precedes result validation.'
Check ($text.IndexOf('Assert-VdlObservationHostOriginals $export.directory') -lt $text.IndexOf('Stop-VdlObservationHostGuest;$record.cleanShutdown')) 'Cleanup precedes original fixture validation.'
[pscustomobject]@{Status='passed';Checks=$script:checks;NativeOperations=$false;VMOperations=$false}
