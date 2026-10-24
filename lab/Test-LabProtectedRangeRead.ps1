<# Pure host guards, mocked remoting and WhatIf. No VM/device actions. #>
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
$path=Join-Path $workspace 'scripts\Invoke-LabProtectedRangeRead.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors.Message -join '; ')}
foreach($definition in $ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){Invoke-Expression $definition.Extent.Text}
$script:checks=0
function Check([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$failed=$false;try{& $Action|Out-Null}catch{$failed=$true};Check $failed $Message}
function Clone($Object){$Object|ConvertTo-Json -Depth 25|ConvertFrom-Json}
$profile=Get-ProtectedRangeReadProfile
Check ($profile.checkpointId -ceq '4b581541-4899-4f91-adc1-e4e784c7cacf' -and $profile.checkpointName -ceq 'extent-placement-data-d98ba93b850d4eababa84c445439868a') 'Wrong protected-range source branch.'
$manifest=[pscustomobject]@{vmId=$profile.vmId;disks=@([pscustomobject]@{role='os';sizeBytes=64GB;controllerLocation=0;vhdId=[guid]::NewGuid().ToString()},[pscustomobject]@{role='target';sizeBytes=64GB;controllerLocation=1;vhdId=$profile.targetVhdId},[pscustomobject]@{role='journal';sizeBytes=8GB;controllerLocation=2;vhdId=[guid]::NewGuid().ToString()})}
Assert-ProtectedRangeReadManifest $manifest $profile;$checks++
$bad=Clone $manifest;$bad.vmId='wrong';Reject {Assert-ProtectedRangeReadManifest $bad $profile} 'Wrong VM accepted.'
$bad=Clone $manifest;$bad.disks=$bad.disks[0..1];Reject {Assert-ProtectedRangeReadManifest $bad $profile} 'Missing journal accepted.'
foreach($field in @('role','sizeBytes','controllerLocation','vhdId')){$bad=Clone $manifest;$bad.disks[1].$field=if($field -ceq 'role'){'os'}elseif($field -ceq 'vhdId'){'wrong'}else{0};Reject {Assert-ProtectedRangeReadManifest $bad $profile} 'Different target accepted.'}
$script:connected=$false;$script:secure='On'
function Get-VMNetworkAdapter {param($VM)[pscustomobject]@{SwitchName=$(if($script:connected){'external'}else{''})}}
function Get-VMFirmware {param($VM)[pscustomobject]@{SecureBoot=$script:secure}}
$vm=[pscustomobject]@{State='Off';MemoryStartup=4GB;DynamicMemoryEnabled=$false;ParentSnapshotId=$profile.baselineId}
Assert-ProtectedRangeReadVM $vm $profile.baselineId 4GB;$checks++
foreach($change in @(@{State='Running'},@{MemoryStartup=8GB},@{DynamicMemoryEnabled=$true},@{ParentSnapshotId=$profile.checkpointId})){$bad=Clone $vm;foreach($key in $change.Keys){$bad.$key=$change[$key]};Reject {Assert-ProtectedRangeReadVM $bad $profile.baselineId 4GB} 'Unsafe starting VM accepted.'}
$connected=$true;Reject {Assert-ProtectedRangeReadVM $vm $profile.baselineId 4GB} 'Connected VM accepted.';$connected=$false
$secure='Off';Reject {Assert-ProtectedRangeReadVM $vm $profile.baselineId 4GB} 'Changed Secure Boot accepted.';$secure='On'
$saved=[pscustomobject]@{Id=$profile.checkpointId;Name=$profile.checkpointName;VMId=$profile.vmId}
Assert-ProtectedRangeReadCheckpoint $saved $profile;$checks++
foreach($field in @('Id','Name','VMId')){$bad=Clone $saved;$bad.$field='wrong';Reject {Assert-ProtectedRangeReadCheckpoint $bad $profile} 'Different checkpoint accepted.'}
Reject {Assert-ProtectedRangeReadCheckpoint $saved $profile -Baseline} 'Saved source confused with baseline.'

function Artifact([string]$Name,[long]$Length=100,[string]$Sha=('a'*64)){[pscustomobject]@{name=$Name;length=$Length;sha256=$Sha;attributes='Archive'}}
$limits=Get-ProtectedRangeReadArtifactLimits
Check ($limits.Count -eq 30) 'Protected-range artifact count differs.'
foreach($name in $limits.Keys){Assert-ProtectedRangeReadArtifact (Artifact $name $limits[$name]);$checks++;Assert-ProtectedRangeReadArtifact (Artifact $name 1);$checks++;Reject {Assert-ProtectedRangeReadArtifact (Artifact $name ($limits[$name]+1))} 'Oversized native artifact accepted.'}
foreach($change in @(@{name='..\protected-range.json'},@{name='range.json'},@{length=0},@{sha256='bad'},@{attributes='ReparsePoint'},@{attributes='Directory'})){$bad=Artifact 'protected-range.json';foreach($key in $change.Keys){$bad.$key=$change[$key]};Reject {Assert-ProtectedRangeReadArtifact $bad} 'Invalid export artifact accepted.'}
Assert-ProtectedRangeReadArtifactSet @((Artifact 'protected-range.json'));$checks++
Reject {Assert-ProtectedRangeReadArtifactSet @()} 'Empty export accepted.'
Reject {Assert-ProtectedRangeReadArtifactSet @((Artifact 'started.json'))} 'Missing primary proof accepted.'
Reject {Assert-ProtectedRangeReadArtifactSet @((Artifact 'protected-range.json'),(Artifact 'protected-range.json'))} 'Duplicate primary proof accepted.'
$setter=Get-ProtectedRangeReadQuerySpec 'pSetAttributes'
Check ($setter.code -ceq '0x0007c0f4' -and $setter.capacity -eq 0 -and $setter.inputBytes -eq 40 -and $setter.inputHex -ceq '28000000000000000200000000000000020000000000000000000000000000000000000000000000') 'Disk protection setter ABI differs.'
foreach($name in @('pWritableAfter','sWritableBefore','sWritableLocked','sWritableAfter')){$spec=Get-ProtectedRangeReadQuerySpec $name;Check ($spec.writeProtectedExpected -and $spec.capacity -eq 0 -and $spec.code -ceq '0x00070024') 'Expected write-protect query differs.'}
Check (-not (Get-ProtectedRangeReadQuerySpec 'pWritableBefore').writeProtectedExpected) 'Initial writable state confused with protected state.'
foreach($name in @('sDismount','pBitmapLegacyBefore','sSetAttributes','oldSource','destination',"pDevice`n")){Reject {Get-ProtectedRangeReadQuerySpec $name} 'Unreviewed native control accepted.'}
$id='a'*32;$guestRoot='C:\ntfs2refs\protected-range-read\'+$id
$query=[pscustomobject]@{name='pDevice';controlCode='0x002d1080';inputHex='';inputBytes=0;outputCapacityBytes=12;bytesReturned=12;succeeded=$true;nativeError=0;startedUtc='2026-10-24T00:00:00Z';finishedUtc='2026-10-24T00:00:01Z';bufferPath=($guestRoot+'\pDevice.bin');bufferSha256=('a'*64)}
$files=@((Artifact 'protected-range.json'),(Artifact 'pDevice.bin' 12))
Check ((Assert-ProtectedRangeReadQuery $query $guestRoot $files) -ceq 'pDevice.bin') 'Native query artifact not bound.'
foreach($field in @('name','controlCode','inputHex','inputBytes','outputCapacityBytes','bytesReturned','bufferPath','bufferSha256','finishedUtc','succeeded')){$bad=Clone $query;$bad.$field=if($field -cin @('inputBytes','outputCapacityBytes','bytesReturned')){9999}elseif($field -ceq 'finishedUtc'){''}else{'bad'};Reject {Assert-ProtectedRangeReadQuery $bad $guestRoot $files} "Invalid native query accepted: $field."}
$partial=Clone $query;$partial.succeeded=$false;$partial.nativeError=21;$partial.bytesReturned=1
Check ((Assert-ProtectedRangeReadQuery $partial $guestRoot @((Artifact 'pDevice.bin' 1))) -ceq 'pDevice.bin') 'Nonempty partial refused buffer was not exportable.'
$empty=Clone $partial;$empty.bytesReturned=0;$empty.bufferPath=$null;$empty.bufferSha256=$null
Assert-ProtectedRangeReadQuery $empty $guestRoot @();$checks++

Initialize-ProtectedRangeReadParsers (Join-Path $workspace 'lab\guest')
function NativeSummary([string]$Prefix){
    $value=New-Object Ntfs2Refs.ProtectedRangeResult
    foreach($field in @('volumeOpened','diskOpened','lockAttempted','lockSucceeded','unlockAttempted','unlockSucceeded','volumeCloseAttempted','volumeCloseSucceeded','diskCloseAttempted','diskCloseSucceeded','handleCloseSucceeded','nativeOperationReturned')){$value.$field=$true}
    $value.phase='complete'
    if($Prefix -ceq 'p'){$value.status='protection-established';foreach($field in @('dismountAttempted','dismountSucceeded','offlineAttempted','offlineSucceeded','setAttributesAttempted','setAttributesSucceeded','onlineAttempted','onlineSucceeded','deviceStateMutationMayHaveBeenIssued','protectionEstablished')){$value.$field=$true}}
    else{$value.status='ranges-read-awaiting-file-verification';foreach($field in @('protectionVerifiedBefore','protectionVerifiedLocked','protectionVerifiedAfter','mountedReadOnlyBefore','mountedReadOnlyAfter','rawReadMayHaveBeenIssued','samplingHandleCloseAttempted','samplingHandleCloseSucceeded','volumeReopenAttempted','volumeReopenSucceeded')){$value.$field=$true};$value.rangeReadCalls=2;$value.baseSectors=0;$value.oldSourceFreeInBoth=$true;$value.destinationAllocatedInBoth=$true;$value.sourceBitsLegacy=[bool[]]@($false)*16;$value.sourceBitsMetadata=[bool[]]@($false)*16;$value.destinationBitsLegacy=[bool[]]@($true)*16;$value.destinationBitsMetadata=[bool[]]@($true)*16;foreach($name in @('mountedBefore','mountedAfter')){$view=New-Object Ntfs2Refs.ProtectedMountedView;$view.name=$name;$view.succeeded=$true;$view.label='ntfs2refs-target';$view.fileSystem='ReFS';$view.serial=0x08425382;$view.flags=0x80000;$view.startedUtc='2026-10-24T00:00:00Z';$view.finishedUtc='2026-10-24T00:00:01Z';$value.mountedViews.Add($view)}}
    $summary=Clone $value;$summary|Add-Member queryNames @(Get-ProtectedRangeReadQueryOrder $Prefix);$summary
}
$control=Read-ProtectedRangeReadPinned (Join-Path $workspace ('.lab\hyperv\'+$profile.controlDirectory+'\after\verify.json')) $profile.controlEvidenceSha256
$sources=@([pscustomobject]@{name='Capture-GuestProtectedRangeRead.ps1';sha256=('b'*64)},[pscustomobject]@{name='NativeRangeRead.cs';sha256=('c'*64)},[pscustomobject]@{name='NativeProtectedRangeRead.cs';sha256=('d'*64)})
$response=[pscustomobject]@{Status='destination-range-verified';CaptureId=$id;EvidenceDirectory=$guestRoot;RestoreAllowed=$true;DeviceStateMutationMayHaveBeenIssued=$true;ProtectionEstablished=$true;DestinationSampleVerified=$true;OldSourceResidualObserved=$true;RawWriteRequestsIssued=$false;ConversionQualified=$false}
$record=[pscustomobject]@{schemaVersion=1;kind='native-protected-range-read';captureId=$id;status=$response.Status;profile=$profile;target=$control.target.guest;partition=$control.partition;volumeUniqueId='\\?\Volume{00c9f113-e0b9-49d8-b031-130aef8ef3fb}\';diskNumberObserved=1;maximumRawReadBytes=131072;maximumLockCalls=2;maximumDiskAttributeChanges=1;rawWriteRequestsIssued=$false;targetFileWriteRequestsIssued=$false;forcedDismountAttempted=$false;lockMayFlushNativeWrites=$true;nativeOperationReturned=$true;handleCloseSucceeded=$true;deviceStateMutationMayHaveBeenIssued=$true;protectionEstablished=$true;protectionTransitionCompleted=$true;diskProtectionRetained=$true;restoreAllowed=$true;fixturesUnchanged=$true;destinationSampleVerified=$true;oldSourceResidualObserved=$true;oldSourceReserved=$false;physicalMappingGeneralized=$false;metadataCoverageQualified=$false;payloadCopyAvoidanceVerified=$false;conversionQualified=$false;bootQualified=$false;transition=(NativeSummary 'p');sample=(NativeSummary 's');nativeQueries=@();rawReads=@();scriptSha256=('b'*64);nativeSourceHashes=$sources[1..2];finishedUtc='2026-10-24T00:01:00Z'}
$files=@((Artifact 'protected-range.json'),(Artifact 'started.json'),(Artifact 'allocation-before.json'),(Artifact 'allocation-protected-before.json'),(Artifact 'allocation-after.json'))
foreach($prefix in @('p','s')){foreach($name in (Get-ProtectedRangeReadQueryOrder $prefix)){$spec=Get-ProtectedRangeReadQuerySpec $name;$hasBytes=$spec.capacity -gt 0;$record.nativeQueries+=[pscustomobject]@{name=$name;controlCode=$spec.code;inputHex=$spec.inputHex;inputBytes=$spec.inputBytes;outputCapacityBytes=$spec.capacity;bytesReturned=$spec.capacity;succeeded=(-not $spec.writeProtectedExpected);nativeError=$(if($spec.writeProtectedExpected){19}else{0});startedUtc='2026-10-24T00:00:00Z';finishedUtc='2026-10-24T00:00:01Z';bufferPath=$(if($hasBytes){$guestRoot+'\'+$name+'.bin'}else{$null});bufferSha256=$(if($hasBytes){'a'*64}else{$null})};if($hasBytes){$files+=Artifact ($name+'.bin') $spec.capacity}}}
foreach($name in @('oldSource','destination')){$lcn=if($name -ceq 'oldSource'){1508352}else{1508384};$offset=[long]$lcn*4096;$record.rawReads+=[pscustomobject]@{name=$name;lcn=$lcn;volumeOffset=$offset;guestDiskOffset=(16MB+$offset);requestedBytes=65536;bytesReturned=65536;seekAttempted=$true;seekSucceeded=$true;actualSeekOffset=$offset;seekError=0;readAttempted=$true;readSucceeded=$true;readError=0;bufferPath=($guestRoot+'\'+$name+'.bin');bufferSha256=('a'*64);fullPatternEqual=$true;startedUtc='2026-10-24T00:00:00Z';finishedUtc='2026-10-24T00:00:01Z'};$files+=Artifact ($name+'.bin') 65536}
Assert-ProtectedRangeReadResponse $response $id;$checks++
Assert-ProtectedRangeReadRecord $record $response $profile $control $files $sources;$checks++
Assert-ProtectedRangeReadCompletion $record;$checks++
foreach($field in @('DeviceStateMutationMayHaveBeenIssued','ProtectionEstablished','RestoreAllowed','DestinationSampleVerified','OldSourceResidualObserved')){$bad=Clone $response;$bad.$field='false';Reject {Assert-ProtectedRangeReadResponse $bad $id} 'Response accepted a string boolean.'}
foreach($field in @('rawWriteRequestsIssued','targetFileWriteRequestsIssued','forcedDismountAttempted','oldSourceReserved','physicalMappingGeneralized','metadataCoverageQualified','payloadCopyAvoidanceVerified','conversionQualified','bootQualified')){$bad=Clone $record;$bad.$field=$true;Reject {Assert-ProtectedRangeReadRecord $bad $response $profile $control $files $sources} 'Unsupported activity/qualification accepted.'}
foreach($field in @('captureId','scriptSha256','volumeUniqueId','finishedUtc')){$bad=Clone $record;$bad.$field='';Reject {Assert-ProtectedRangeReadRecord $bad $response $profile $control $files $sources} 'Missing protected provenance accepted.'}
$bad=Clone $record;$bad.nativeSourceHashes[1].sha256='e'*64;Reject {Assert-ProtectedRangeReadRecord $bad $response $profile $control $files $sources} 'Changed native helper accepted.'
$bad=Clone $record;$bad.nativeQueries+=Clone $bad.nativeQueries[0];Reject {Assert-ProtectedRangeReadRecord $bad $response $profile $control $files $sources} 'Duplicate native operation accepted.'
$bad=Clone $record;$bad.rawReads[0].volumeOffset+=4096;Reject {Assert-ProtectedRangeReadRecord $bad $response $profile $control $files $sources} 'Arbitrary raw range accepted.'
foreach($field in @('restoreAllowed','nativeOperationReturned','handleCloseSucceeded','fixturesUnchanged','protectionEstablished','protectionTransitionCompleted','diskProtectionRetained')){$bad=Clone $record;$bad.$field=$false;Reject {Assert-ProtectedRangeReadCompletion $bad} 'Incomplete protected operation allowed cleanup.'}
foreach($field in @('dismountSucceeded','offlineSucceeded','setAttributesSucceeded','onlineSucceeded','unlockSucceeded','volumeCloseSucceeded','diskCloseSucceeded')){$bad=Clone $record;$bad.transition.$field=$false;Reject {Assert-ProtectedRangeReadCompletion $bad} 'Partial transition allowed cleanup.'}
foreach($field in @('protectionVerifiedBefore','protectionVerifiedLocked','protectionVerifiedAfter','mountedReadOnlyBefore','mountedReadOnlyAfter','samplingHandleCloseSucceeded','volumeReopenSucceeded')){$bad=Clone $record;$bad.sample.$field=$false;Reject {Assert-ProtectedRangeReadCompletion $bad} 'Unprotected or stale-handle sample allowed cleanup.'}
foreach($field in @('samplingHandleCloseError','volumeReopenError')){$bad=Clone $record;$bad.sample.$field=21;Reject {Assert-ProtectedRangeReadCompletion $bad} 'Sampling cleanup/reopen error allowed cleanup.'}
$bad=Clone $record;$bad.sample.mountedViews[1].flags=0;Reject {Assert-ProtectedRangeReadCompletion $bad} 'Writable mounted volume allowed cleanup.'
$bad=Clone $record;$bad.nativeQueries[12].nativeError=21;Reject {Assert-ProtectedRangeReadCompletion $bad} 'Generic writability failure treated as write protection.'
$bad=Clone $record;$bad.nativeQueries[12].succeeded=$true;Reject {Assert-ProtectedRangeReadCompletion $bad} 'Writable disk treated as protected.'
$bad=Clone $record;$bad.transition.queryNames[9]='pOnline';Reject {Assert-ProtectedRangeReadCompletion $bad} 'Reordered device lifecycle accepted.'
$early=Clone $record;$early.status='native-lock-refused';$early.sample=$null;$early.rawReads=@();$early.nativeQueries=$early.nativeQueries[0..7];$early.nativeQueries[7].succeeded=$false;$early.nativeQueries[7].nativeError=5
foreach($field in @('deviceStateMutationMayHaveBeenIssued','protectionEstablished','protectionTransitionCompleted','diskProtectionRetained','destinationSampleVerified','oldSourceResidualObserved')){$early.$field=$false}
$early.transition.status=$early.status;$early.transition.phase='quiesce';$early.transition.queryNames=$early.transition.queryNames[0..7]
foreach($field in @('lockSucceeded','unlockAttempted','unlockSucceeded','dismountAttempted','dismountSucceeded','offlineAttempted','offlineSucceeded','setAttributesAttempted','setAttributesSucceeded','onlineAttempted','onlineSucceeded','deviceStateMutationMayHaveBeenIssued','protectionEstablished')){$early.transition.$field=$false}
Assert-ProtectedRangeReadCompletion $early;$checks++
foreach($field in @('deviceStateMutationMayHaveBeenIssued','dismountAttempted','offlineAttempted','setAttributesAttempted','onlineAttempted')){$bad=Clone $early;$bad.transition.$field=$true;Reject {Assert-ProtectedRangeReadCompletion $bad} 'Mutation-phase refusal allowed baseline restore.'}
$bad=Clone $early;$bad.deviceStateMutationMayHaveBeenIssued=$true;Reject {Assert-ProtectedRangeReadCompletion $bad} 'Top-level mutation intent ignored.'
$bad=Clone $early;$bad.transition.nativeOperationReturned=$null;Reject {Assert-ProtectedRangeReadCompletion $bad} 'Unknown native completion allowed restore.'
$bad=Clone $early;$bad.transition.handleCloseSucceeded=$false;Reject {Assert-ProtectedRangeReadCompletion $bad} 'Failed early cleanup allowed restore.'
$bad=Clone $early;$bad.nativeQueries[2].name='pSetAttributes';Reject {Assert-ProtectedRangeReadCompletion $bad} 'Hidden mutation query accepted as an early refusal.'
# The actual first protected run exported valid partial evidence then stopped
# at the fresh-handle guard. It must remain rejected with its native reason.
$blockedCase=Join-Path $workspace '.lab\hyperv\protected-range-read\win11-20261024T010715182Z\guest\protected-range.json'
$blocked=Read-ProtectedRangeReadPinned $blockedCase '78eb63ce0e205f809462c8e85357126fbf6648eaa08f16360dda6d8900f4b352'
$blockedMessage='';try{Assert-ProtectedRangeReadCompletion $blocked}catch{$blockedMessage=$_.Exception.Message}
Check ($blockedMessage.Contains('Protected-range operation blocked; preserve the branch.')) 'Blocked native case did not preserve the branch.'
Check ($blockedMessage.Contains('sample phase=fresh-sampling-handle')) 'Blocked diagnostic hid the native phase.'
Check ($blockedMessage.Contains('Only one fresh read-only reopen after confirmed close is allowed.')) 'Blocked diagnostic hid the native error.'
Check ($blockedMessage.Contains('guest: Protected sample did not complete; preserve the protected branch.')) 'Blocked diagnostic hid the guest error.'
foreach($invalid in @($null,'false',0)){$bad=Clone $blocked;$bad.restoreAllowed=$invalid;$message='';try{Assert-ProtectedRangeReadCompletion $bad}catch{$message=$_.Exception.Message};Check ($message -ceq 'Unexpected explicit protected-range boolean: restoreAllowed.') 'Blocked diagnostic bypassed strict boolean validation.'}
$bad=Clone $blocked;$bad.restoreAllowed=$true;Reject {Assert-ProtectedRangeReadCompletion $bad} 'Blocked case allowed cleanup with a contradictory restore flag.'
$started=[pscustomobject]@{schemaVersion=1;kind='native-protected-range-read-started';captureId=$id;scriptSha256=$record.scriptSha256;maximumRawReadBytes=131072;maximumLockCalls=2;maximumDiskAttributeChanges=1;deviceStateMutationMayHaveBeenIssued=$true;rawWriteRequestsIssued=$false;targetFileWriteRequestsIssued=$false;profile=$record.profile;target=$record.target;partition=$record.partition;nativeSourceHashes=$record.nativeSourceHashes}
Assert-ProtectedRangeReadStarted $started $record;$checks++
foreach($field in @('captureId','scriptSha256','kind')){$bad=Clone $started;$bad.$field='wrong';Reject {Assert-ProtectedRangeReadStarted $bad $record} 'Mismatched durable intent accepted.'}
$bad=Clone $started;$bad.maximumDiskAttributeChanges=2;Reject {Assert-ProtectedRangeReadStarted $bad $record} 'Extra disk state mutation accepted.'

# Independently decode exported native bytes from ordinary synthetic files. These
# validators are pure; no native adapter, device handle or VM is instantiated.
function Put32([byte[]]$Bytes,[int]$At,[uint32]$Value){[BitConverter]::GetBytes($Value).CopyTo($Bytes,$At)}
function Put64([byte[]]$Bytes,[int]$At,[long]$Value){[BitConverter]::GetBytes($Value).CopyTo($Bytes,$At)}
function PutGuid([byte[]]$Bytes,[int]$At,[string]$Value){([guid]$Value).ToByteArray().CopyTo($Bytes,$At)}
$testParent=[IO.Path]::GetFullPath((Join-Path $workspace '.lab\test-output'))
$byteRoot=Join-Path $testParent ('protected-range-host-'+[guid]::NewGuid().ToString('N'))
if(Test-Path -LiteralPath $byteRoot){throw 'Synthetic output already exists.'}
[IO.Directory]::CreateDirectory($byteRoot)|Out-Null
try {
    $device=New-Object byte[] 12;Put32 $device 0 7;Put32 $device 4 1
    $length=[BitConverter]::GetBytes([long]64GB)
    $alignment=New-Object byte[] 28;Put32 $alignment 0 28;Put32 $alignment 4 28;Put32 $alignment 16 512;Put32 $alignment 20 4096
    $layout=New-Object byte[] 336;Put32 $layout 0 1;Put32 $layout 4 2;PutGuid $layout 8 'b4ab4dbc-6bd7-4199-8e4a-01b828e98584';Put64 $layout 24 1MB;Put64 $layout 32 (64GB-2MB)
    Put32 $layout 48 1;Put64 $layout 56 1MB;Put64 $layout 64 15MB;Put32 $layout 72 1;PutGuid $layout 80 'e3c9e316-0b5c-4db8-817d-f92df00215ae';PutGuid $layout 96 '647a51ad-2bbd-4240-a377-321760fe4ac1'
    Put32 $layout 192 1;Put64 $layout 200 16MB;Put64 $layout 208 52GB;Put32 $layout 216 2;PutGuid $layout 224 'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7';PutGuid $layout 240 '00c9f113-e0b9-49d8-b031-130aef8ef3fb'
    $volume=New-Object byte[] 32;Put32 $volume 0 1;Put32 $volume 8 1;Put64 $volume 16 16MB;Put64 $volume 24 52GB
    $writable=New-Object byte[] 16;Put32 $writable 0 16
    $protectedAttributes=$writable.Clone();Put64 $protectedAttributes 8 2
    $bitmap=New-Object byte[] (16+13631488/8);Put64 $bitmap 8 13631488;$bitmap[16+1508384/8]=255;$bitmap[17+1508384/8]=255
    $pattern=New-Object byte[] 65536;for($i=0;$i -lt $pattern.Length;$i++){$pattern[$i]=[byte](($i*29+17)%256)}
    $buffers=@{'pDevice.bin'=$device;'sDevice.bin'=$device;'pLength.bin'=$length;'sLength.bin'=$length;'pAlignment.bin'=$alignment;'sAlignment.bin'=$alignment;'pLayout.bin'=$layout;'sLayout.bin'=$layout;'pVolume.bin'=$volume;'sVolumeBefore.bin'=$volume;'sVolumeLocked.bin'=$volume;'sVolumeAfter.bin'=$volume;'pAttributesBefore.bin'=$writable;'pAttributesAfter.bin'=$protectedAttributes;'sAttributesBefore.bin'=$protectedAttributes;'sAttributesLocked.bin'=$protectedAttributes;'sAttributesAfter.bin'=$protectedAttributes;'sBaseBefore.bin'=(New-Object byte[] 8);'sBaseAfter.bin'=(New-Object byte[] 8);'sBitmapLegacyBefore.bin'=$bitmap;'sBitmapMetadataBefore.bin'=$bitmap;'sBitmapLegacyAfter.bin'=$bitmap;'sBitmapMetadataAfter.bin'=$bitmap;'oldSource.bin'=$pattern;'destination.bin'=$pattern}
    foreach($name in $buffers.Keys){$stream=[IO.File]::Open((Join-Path $byteRoot $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$stream.Write($buffers[$name],0,$buffers[$name].Length)}finally{$stream.Dispose()}}
    Assert-ProtectedRangeReadExportBytes $record $byteRoot $pattern;$checks++
    foreach($case in @(@{name='pDevice.bin';at=4;value=2},@{name='sLength.bin';at=4;value=1},@{name='pAlignment.bin';at=20;value=1},@{name='sLayout.bin';at=8;value=0},@{name='pLayout.bin';at=240;value=0},@{name='sVolumeLocked.bin';at=8;value=2},@{name='pAttributesBefore.bin';at=8;value=2},@{name='sAttributesAfter.bin';at=8;value=0},@{name='sBaseAfter.bin';at=0;value=8},@{name='sBitmapLegacyBefore.bin';at=(16+1508352/8);value=1},@{name='sBitmapMetadataAfter.bin';at=(16+1508384/8);value=0},@{name='destination.bin';at=65535;value=0})){
        $corrupt=$buffers[$case.name].Clone();$corrupt[$case.at]=[byte]$case.value;$file=Join-Path $byteRoot $case.name
        [IO.File]::WriteAllBytes($file,$corrupt)
        try{Reject {Assert-ProtectedRangeReadExportBytes $record $byteRoot $pattern} ('Native export mismatch accepted: '+$case.name)}finally{[IO.File]::WriteAllBytes($file,$buffers[$case.name])}
    }
    $bad=Clone $record;$bad.sample.sourceBitsMetadata[7]=$true;Reject {Assert-ProtectedRangeReadExportBytes $bad $byteRoot $pattern} 'Reported bitmap disagreement accepted.'
    $bad=Clone $record;$bad.oldSourceResidualObserved=$false;Reject {Assert-ProtectedRangeReadExportBytes $bad $byteRoot $pattern} 'Residual summary disagreement accepted.'
    $bad=Clone $record;$bad.rawReads[1].fullPatternEqual=$false;Reject {Assert-ProtectedRangeReadExportBytes $bad $byteRoot $pattern} 'Raw comparison disagreement accepted.'
    $other=$pattern.Clone();$other[123]=$other[123] -bxor 1;[IO.File]::WriteAllBytes((Join-Path $byteRoot 'oldSource.bin'),$other)
    $noResidual=Clone $record;$noResidual.oldSourceResidualObserved=$false;$noResidual.rawReads[0].fullPatternEqual=$false
    Assert-ProtectedRangeReadExportBytes $noResidual $byteRoot $pattern;$checks++
    $incomplete=New-Object byte[] 32;[IO.File]::WriteAllBytes((Join-Path $byteRoot 'sBitmapLegacyAfter.bin'),$incomplete)
    Reject {Assert-ProtectedRangeReadExportBytes $noResidual $byteRoot $pattern} 'Truncated bitmap accepted.'
} finally {
    $resolved=[IO.Path]::GetFullPath($byteRoot)
    if([IO.Path]::GetDirectoryName($resolved) -cne $testParent -or [IO.Path]::GetFileName($resolved) -cnotmatch '\Aprotected-range-host-[0-9a-f]{32}\z'){throw 'Refusing synthetic directory cleanup outside its exact parent.'}
    if(Test-Path -LiteralPath $resolved){$item=Get-Item -LiteralPath $resolved -Force;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Refusing redirected synthetic cleanup.'};Remove-Item -LiteralPath $resolved -Recurse -Force}
}

# Transport wrapper uses only mocks; incomplete operations remain unknown.
$session='mock-session';$script:scenario='success';$script:removed=0;$script:commandIndeterminate=$false
function Invoke-Command {param($Session,[switch]$AsJob,$ArgumentList,$ScriptBlock)Check $script:commandIndeterminate 'Dispatch did not set unknown completion.';if($script:scenario -ceq 'dispatch-failure'){throw 'transport failed'};[pscustomobject]@{State=$(if($script:scenario -ceq 'timeout'){'Running'}elseif($script:scenario -ceq 'receive-failure'){'Failed'}else{'Completed'})}}
function Wait-Job {param($Job,$Timeout)if($script:scenario -cne 'timeout'){$Job}}
function Receive-Job {param($Job,$ErrorAction)if($script:scenario -ceq 'receive-failure'){throw 'transport lost'};'answer'}
function Remove-Job {param($Job,[switch]$Force)$script:removed++}
$answer=@(Invoke-BoundedProtectedRangeReadCommand -ScriptBlock {} -TimeoutSeconds 30)
Check ($answer.Count -eq 1 -and $answer[0] -ceq 'answer' -and -not $script:commandIndeterminate -and $script:removed -eq 1) 'Completed command not recognized.'
foreach($testScenario in @('dispatch-failure','receive-failure','timeout')){$script:scenario=$testScenario;$script:removed=0;$script:commandIndeterminate=$false;Reject {Invoke-BoundedProtectedRangeReadCommand -ScriptBlock {} -TimeoutSeconds 30} 'Incomplete command accepted.';Check $script:commandIndeterminate 'Unknown completion cleared.';if($testScenario -ceq 'timeout'){Check ($script:removed -eq 0) 'Running job forcibly removed.'}}
$dry=& $path -WhatIf
Check ($dry.DryRun -and $dry.MemoryBytes -eq 8GB -and $dry.MaximumRawReadBytes -eq 131072 -and $dry.MaximumLockCalls -eq 2 -and $dry.DeviceStateMutation -and -not $dry.RawWriteRequestsIssued -and -not $dry.TargetFileWriteRequestsIssued -and -not $dry.ConversionQualified) 'WhatIf contract failed.'
"Lab protected range-read: $checks checks passed."
