<# Pure guards, mocked transport failures and WhatIf only; no VM actions. #>
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
$path=Join-Path $workspace 'scripts\Invoke-LabRangeRead.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors.Message -join '; ')}
foreach($name in @('Get-RangeReadProfile','Assert-RangeReadManifest','Assert-RangeReadVM','Assert-RangeReadCheckpoint','Assert-RangeReadResponse','Assert-RangeReadArtifact','Assert-RangeReadArtifactSet','Assert-RangeReadRecord','Assert-RangeReadCompletion','Assert-RangeReadExportBytes','Invoke-BoundedRangeReadCommand')) {
    $definition=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$false)
    Invoke-Expression $definition.Extent.Text
}
$script:checks=0
function Check([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$failed=$false;try{& $Action|Out-Null}catch{$failed=$true};Check $failed $Message}
function Clone($Object){$Object|ConvertTo-Json -Depth 15|ConvertFrom-Json}
$profile=Get-RangeReadProfile
$manifest=[pscustomobject]@{vmId=$profile.vmId;disks=@([pscustomobject]@{role='os';sizeBytes=64GB;controllerLocation=0;vhdId=[guid]::NewGuid().ToString()},[pscustomobject]@{role='target';sizeBytes=64GB;controllerLocation=1;vhdId=$profile.targetVhdId},[pscustomobject]@{role='journal';sizeBytes=8GB;controllerLocation=2;vhdId=[guid]::NewGuid().ToString()})}
Assert-RangeReadManifest $manifest $profile; $checks++
$bad=Clone $manifest;$bad.vmId=[guid]::NewGuid().ToString();Reject {Assert-RangeReadManifest $bad $profile} 'Different VM accepted.'
$bad=Clone $manifest;$bad.disks=$bad.disks[0..1];Reject {Assert-RangeReadManifest $bad $profile} 'Missing journal accepted.'
foreach($field in @('role','sizeBytes','controllerLocation','vhdId')){$bad=Clone $manifest;$bad.disks[1].$field=if($field -ceq 'role'){'os'}elseif($field -ceq 'vhdId'){[guid]::NewGuid().ToString()}else{0};Reject {Assert-RangeReadManifest $bad $profile} "Bad target $field accepted."}
$script:connected=$false;$script:secure='On'
function Get-VMNetworkAdapter {param($VM)[pscustomobject]@{SwitchName=$(if($script:connected){'external'}else{''})}}
function Get-VMFirmware {param($VM)[pscustomobject]@{SecureBoot=$script:secure}}
$vm=[pscustomobject]@{State='Off';MemoryStartup=4GB;DynamicMemoryEnabled=$false;ParentSnapshotId=$profile.baselineId}
Assert-RangeReadVM $vm $profile.baselineId 4GB;$checks++
foreach($change in @(@{State='Running'},@{MemoryStartup=8GB},@{DynamicMemoryEnabled=$true},@{ParentSnapshotId=$profile.checkpointId})){$bad=Clone $vm;foreach($key in $change.Keys){$bad.$key=$change[$key]};Reject {Assert-RangeReadVM $bad $profile.baselineId 4GB} 'Unsafe VM start state accepted.'}
$connected=$true;Reject {Assert-RangeReadVM $vm $profile.baselineId 4GB} 'Connected network accepted.';$connected=$false
$secure='Off';Reject {Assert-RangeReadVM $vm $profile.baselineId 4GB} 'Changed Secure Boot accepted.';$secure='On'
$saved=[pscustomobject]@{Id=$profile.checkpointId;Name=$profile.checkpointName;VMId=$profile.vmId}
Assert-RangeReadCheckpoint $saved $profile;$checks++
$baseline=[pscustomobject]@{Id=$profile.baselineId;Name='installed-clean';VMId=$profile.vmId}
Assert-RangeReadCheckpoint $baseline $profile -Baseline;$checks++
foreach($field in @('Id','Name','VMId')){$bad=Clone $saved;$bad.$field='other';Reject {Assert-RangeReadCheckpoint $bad $profile} 'Different saved checkpoint accepted.'}
Reject {Assert-RangeReadCheckpoint $saved $profile -Baseline} 'Native checkpoint confused with installed-clean.'
$id='a'*32
$response=[pscustomobject]@{CaptureId=$id;Status='destination-range-verified';EvidenceDirectory=('C:\ntfs2refs\range-read\'+$id);RestoreAllowed=$true;DestinationSampleVerified=$true;OldSourceResidualObserved=$true;RawWriteRequestsIssued=$false;ConversionQualified=$false}
Assert-RangeReadResponse $response $id;$checks++
foreach($change in @(@{CaptureId=('b'*32)},@{Status='converted'},@{EvidenceDirectory='C:\Windows'},@{RestoreAllowed='true'},@{DestinationSampleVerified=$false},@{RawWriteRequestsIssued=$true},@{ConversionQualified=$true})){$bad=Clone $response;foreach($key in $change.Keys){$bad.$key=$change[$key]};Reject {Assert-RangeReadResponse $bad $id} 'Unreviewed response accepted.'}
$blockedResponse=Clone $response;$blockedResponse.Status='blocked';$blockedResponse.RestoreAllowed=$false;$blockedResponse.DestinationSampleVerified=$false;$blockedResponse.OldSourceResidualObserved=$false
Assert-RangeReadResponse $blockedResponse $id;$checks++
$bad=Clone $blockedResponse;$bad.RestoreAllowed=$true;Reject {Assert-RangeReadResponse $bad $id} 'Blocked response allowed restore.'
function Artifact([string]$Name,[long]$Length,[string]$Sha=('a'*64)){[pscustomobject]@{name=$Name;length=$Length;sha256=$Sha;attributes='Archive'}}
$json=Artifact 'range.json' 1024
Assert-RangeReadArtifactSet @($json);$checks++
foreach($spec in @(@('allocation-before.json',1MB),@('allocation-after.json',1MB),@('baseBefore.bin',8),@('baseLocked.bin',8),@('volumeBefore.bin',64),@('volumeLocked.bin',64),@('bitmapLegacy.bin',2MB),@('bitmapMetadata.bin',2MB),@('oldSource.bin',65536),@('destination.bin',65536))){$file=Artifact $spec[0] $spec[1];Assert-RangeReadArtifact $file;$checks++;$file.length++;Reject {Assert-RangeReadArtifact $file} 'Oversized artifact accepted.';$file.length=0;Reject {Assert-RangeReadArtifact $file} 'Empty artifact accepted.'}
foreach($change in @(@{name='..\range.json'},@{name='disk.raw'},@{length=0},@{length=(1MB+1)},@{sha256='bad'},@{attributes='ReparsePoint'})){$bad=Clone $json;foreach($key in $change.Keys){$bad.$key=$change[$key]};Reject {Assert-RangeReadArtifact $bad} 'Unsafe artifact accepted.'}
Assert-RangeReadArtifact (Artifact 'destination.bin' 1);$checks++
Reject {Assert-RangeReadArtifactSet @()} 'Empty export accepted.'
Reject {Assert-RangeReadArtifactSet @((Artifact 'baseBefore.bin' 8))} 'Missing primary JSON accepted.'
Reject {Assert-RangeReadArtifactSet @($json,$json)} 'Duplicate export accepted.'
$control=Get-Content -LiteralPath (Join-Path $workspace '.lab\hyperv\devdrive\win11-20261023T230635404Z\after\verify.json') -Raw|ConvertFrom-Json
$placementRoot=Join-Path $workspace '.lab\hyperv\extent-placement\win11-20261024T000401422Z'
$pattern=[IO.File]::ReadAllBytes((Join-Path $placementRoot 'guest\expected-pattern.bin'))
$scriptSha='c'*64;$nativeSha='d'*64
$record=[pscustomobject]@{schemaVersion=1;kind='native-range-read';captureId=$id;status=$response.Status;profile=$profile;scriptSha256=$scriptSha;nativeSourceSha256=$nativeSha;target=$control.target.guest;partition=$control.partition;diskNumberObserved=1;maximumRawReadBytes=131072;maximumLockCalls=1;rawWriteRequestsIssued=$false;targetFileWriteRequestsIssued=$false;forcedDismountAttempted=$false;oldSourceReserved=$false;physicalMappingGeneralized=$false;metadataCoverageQualified=$false;payloadCopyAvoidanceVerified=$false;conversionQualified=$false;bootQualified=$false;restoreAllowed=$true;destinationSampleVerified=$true;oldSourceResidualObserved=$true;nativeOperationReturned=$true;fixturesUnchanged=$true;handleCloseSucceeded=$true;lockSucceeded=$true;unlockSucceeded=$true;lockAttempted=$true;lockMayFlushNativeWrites=$true;rangeReadCalls=2;nativeStatus='ranges-read-awaiting-file-verification';baseSectors=0;oldSourceFreeInBoth=$true;destinationAllocatedInBoth=$true;sourceBitsLegacy=@($false)*16;sourceBitsMetadata=@($false)*16;destinationBitsLegacy=@($true)*16;destinationBitsMetadata=@($true)*16;nativeQueries=@();rawReads=@()}
$data=@{}
$data['baseBefore.bin']=[BitConverter]::GetBytes([long]0);$data['baseLocked.bin']=[BitConverter]::GetBytes([long]0)
$extent=New-Object byte[] 32;[BitConverter]::GetBytes([uint32]1).CopyTo($extent,0);[BitConverter]::GetBytes([uint32]1).CopyTo($extent,8);[BitConverter]::GetBytes([long]16MB).CopyTo($extent,16);[BitConverter]::GetBytes([long]52GB).CopyTo($extent,24)
$data['volumeBefore.bin']=$extent;$data['volumeLocked.bin']=[byte[]]$extent.Clone()
$bitmap=New-Object byte[] 2MB;[BitConverter]::GetBytes([long]13631488).CopyTo($bitmap,8);$bitmap[16+[int](1508384/8)]=255;$bitmap[17+[int](1508384/8)]=255
$data['bitmapLegacy.bin']=$bitmap;$data['bitmapMetadata.bin']=[byte[]]$bitmap.Clone();$data['oldSource.bin']=$pattern;$data['destination.bin']=[byte[]]$pattern.Clone()
$files=@($json,(Artifact 'allocation-before.json' 1024),(Artifact 'allocation-after.json' 1024))
function Hash([byte[]]$Bytes){$sha=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}
foreach($name in @('baseBefore','volumeBefore','lock','baseLocked','volumeLocked','bitmapLegacy','bitmapMetadata','unlock')){
 $code=if($name -clike 'base*'){'0x00090234'}elseif($name -clike 'volume*'){'0x00560000'}elseif($name -ceq 'lock'){'0x00090018'}elseif($name -ceq 'unlock'){'0x0009001c'}else{'0x0009006f'}
 $cap=if($name -clike 'base*'){8}elseif($name -clike 'volume*'){64}elseif($name -clike 'bitmap*'){2MB}else{0}
 $input=if($name -ceq 'bitmapLegacy'){'0000000000000000'}elseif($name -ceq 'bitmapMetadata'){'00000000000000000100000000000000'}else{''}
 $buffer=$data[$name+'.bin'];$query=[pscustomobject]@{name=$name;controlCode=$code;inputBytes=($input.Length/2);inputHex=$input;outputCapacityBytes=$cap;bytesReturned=$(if($null -eq $buffer){0}else{$buffer.Length});succeeded=$true;nativeError=0;bufferPath=$(if($null -eq $buffer){$null}else{$response.EvidenceDirectory+'\'+$name+'.bin'});bufferSha256=$(if($null -eq $buffer){$null}else{Hash $buffer})};$record.nativeQueries+=$query
 if($null -ne $buffer){$files+=Artifact ($name+'.bin') $buffer.Length $query.bufferSha256}
}
foreach($name in @('oldSource','destination')){$lcn=if($name -ceq 'oldSource'){1508352}else{1508384};$offset=[long]$lcn*4096;$sha=Hash $data[$name+'.bin'];$record.rawReads+=[pscustomobject]@{name=$name;lcn=$lcn;volumeOffset=$offset;guestDiskOffset=(16MB+$offset);requestedBytes=65536;bytesReturned=65536;seekSucceeded=$true;actualSeekOffset=$offset;readSucceeded=$true;fullPatternEqual=$true;bufferPath=($response.EvidenceDirectory+'\'+$name+'.bin');bufferSha256=$sha};$files+=Artifact ($name+'.bin') 65536 $sha}
Assert-RangeReadArtifactSet $files;$checks++
Assert-RangeReadRecord $record $response $profile $control $files $scriptSha $nativeSha;$checks++
Assert-RangeReadCompletion $record;$checks++
foreach($field in @('schemaVersion','kind','captureId','status','scriptSha256','nativeSourceSha256','maximumRawReadBytes','maximumLockCalls')){$bad=Clone $record;$bad.$field=if($field -cin @('schemaVersion','maximumRawReadBytes','maximumLockCalls')){999}else{'wrong'};Reject {Assert-RangeReadRecord $bad $response $profile $control $files $scriptSha $nativeSha} 'Changed record provenance accepted.'}
foreach($field in @('controlRunId','controlEvidenceSha256','capturedAllocationSha256','placementProbeId','placementEvidenceSha256','remountIdentitySha256','remountAllocationSha256','patternSha256')){$bad=Clone $record;$bad.profile.$field='wrong';Reject {Assert-RangeReadRecord $bad $response $profile $control $files $scriptSha $nativeSha} 'Changed source proof accepted.'}
foreach($field in @('rawWriteRequestsIssued','targetFileWriteRequestsIssued','forcedDismountAttempted','oldSourceReserved','physicalMappingGeneralized','metadataCoverageQualified','payloadCopyAvoidanceVerified','conversionQualified','bootQualified')){$bad=Clone $record;$bad.$field=$true;Reject {Assert-RangeReadRecord $bad $response $profile $control $files $scriptSha $nativeSha} 'Unperformed activity accepted.'}
foreach($field in @('restoreAllowed','destinationSampleVerified','oldSourceResidualObserved')){$bad=Clone $record;$bad.$field=$false;Reject {Assert-RangeReadRecord $bad $response $profile $control $files $scriptSha $nativeSha} 'Contradictory result accepted.'}
foreach($field in @('guid','diskGuid','number','offset','length','letter','logicalSectorSize','physicalSectorSize')){$bad=Clone $record;$bad.partition.$field='wrong';Reject {Assert-RangeReadRecord $bad $response $profile $control $files $scriptSha $nativeSha} 'Changed GPT/geometry accepted.'}
foreach($change in @(@{name='write'},@{controlCode='0x00090074'},@{inputHex='00'},@{inputBytes=1},@{outputCapacityBytes=999},@{bytesReturned=7},@{bufferPath='C:\other.bin'},@{bufferSha256=('0'*64)})){$bad=Clone $record;foreach($key in $change.Keys){$bad.nativeQueries[0].$key=$change[$key]};Reject {Assert-RangeReadRecord $bad $response $profile $control $files $scriptSha $nativeSha} 'Invalid query provenance accepted.'}
$bad=Clone $record;$bad.nativeQueries+=Clone $bad.nativeQueries[0];Reject {Assert-RangeReadRecord $bad $response $profile $control $files $scriptSha $nativeSha} 'Duplicate query accepted.'
foreach($change in @(@{name='other'},@{lcn=0},@{volumeOffset=0},@{guestDiskOffset=0},@{requestedBytes=131072},@{bytesReturned=65537},@{bufferPath='C:\other.bin'},@{bufferSha256=('0'*64)})){$bad=Clone $record;foreach($key in $change.Keys){$bad.rawReads[0].$key=$change[$key]};Reject {Assert-RangeReadRecord $bad $response $profile $control $files $scriptSha $nativeSha} 'Invalid raw range provenance accepted.'}
foreach($field in @('restoreAllowed','nativeOperationReturned','fixturesUnchanged','handleCloseSucceeded','unlockSucceeded')){$bad=Clone $record;$bad.$field=$false;Reject {Assert-RangeReadCompletion $bad} 'Incomplete cleanup/observation permitted restore.'}
$bad=Clone $record;$bad.rawReads[0].bytesReturned=4096;Reject {Assert-RangeReadCompletion $bad} 'Short raw read qualified.'
$bad=Clone $record;$bad.nativeQueries[0].succeeded=$false;Reject {Assert-RangeReadCompletion $bad} 'Failed query qualified.'
foreach($status in @('native-open-refused','native-lock-refused','native-query-refused','source-range-not-free','destination-range-not-allocated')){
 $refused=Clone $record;$refused.status=$status;$refused.nativeStatus=$status;$refused.destinationSampleVerified=$false;$refused.oldSourceResidualObserved=$false;$refused.rawReads=@();$refused.rangeReadCalls=0
 if($status -ceq 'source-range-not-free'){$refused.oldSourceFreeInBoth=$false}elseif($status -ceq 'destination-range-not-allocated'){$refused.destinationAllocatedInBoth=$false}else{$refused.nativeQueries=@()}
 Assert-RangeReadCompletion $refused;$checks++
}
$blocked=Clone $record;$blocked.status='blocked';$blocked.restoreAllowed=$false;$blocked.destinationSampleVerified=$false;$blocked.oldSourceResidualObserved=$false;$blocked.rawReads=@();$blocked.nativeQueries=@()
Assert-RangeReadRecord $blocked $blockedResponse $profile $control @($json) $scriptSha $nativeSha;$checks++
Reject {Assert-RangeReadCompletion $blocked} 'Blocked run permitted restore.'
Reject {Assert-RangeReadRecord $blocked $blockedResponse $profile $control @($json,(Artifact 'baseBefore.bin' 8)) $scriptSha $nativeSha} 'Unreferenced native buffer accepted.'

# Small synthetic files only; no volume/device is opened.
$tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$scratch=[IO.Path]::GetFullPath((Join-Path $tempRoot ('ntfs2refs-range-test-'+[guid]::NewGuid().ToString('N'))))
if(-not $scratch.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $scratch)){throw 'Unexpected scratch path.'}
[IO.Directory]::CreateDirectory($scratch)|Out-Null
try{
 foreach($name in $data.Keys){[IO.File]::WriteAllBytes((Join-Path $scratch $name),$data[$name])}
 Assert-RangeReadExportBytes $record $scratch $pattern;$checks++
 foreach($case in @(@('baseLocked.bin',0),@('volumeLocked.bin',8),@('bitmapLegacy.bin',(16+[int](1508352/8))),@('destination.bin',65535),@('oldSource.bin',65535))){$name=$case[0];$bytes=[byte[]]$data[$name].Clone();$bytes[$case[1]]=$bytes[$case[1]] -bxor 1;[IO.File]::WriteAllBytes((Join-Path $scratch $name),$bytes);Reject {Assert-RangeReadExportBytes $record $scratch $pattern} 'Changed captured bytes accepted.';[IO.File]::WriteAllBytes((Join-Path $scratch $name),$data[$name])}
 $bytes=[byte[]]$data['bitmapLegacy.bin'].Clone();$bytes[$bytes.Length-1]=255;[IO.File]::WriteAllBytes((Join-Path $scratch 'bitmapLegacy.bin'),$bytes)
 Assert-RangeReadExportBytes $record $scratch $pattern;$checks++
 [IO.File]::WriteAllBytes((Join-Path $scratch 'bitmapLegacy.bin'),$data['bitmapLegacy.bin'])
 $bad=Clone $record;$bad.sourceBitsLegacy[0]=$true;Reject {Assert-RangeReadExportBytes $bad $scratch $pattern} 'Wrong source-bit report accepted.'
 $bad=Clone $record;$bad.oldSourceResidualObserved=$false;Reject {Assert-RangeReadExportBytes $bad $scratch $pattern} 'Wrong residual attribution accepted.'
 $bad=Clone $record;$bad.diskNumberObserved=2;Reject {Assert-RangeReadExportBytes $bad $scratch $pattern} 'Wrong native disk binding accepted.'
 [IO.File]::WriteAllBytes((Join-Path $scratch 'oldSource.bin'),(New-Object byte[] 65536))
 $zero=Clone $record;$zero.oldSourceResidualObserved=$false;$zero.rawReads[0].fullPatternEqual=$false
 Assert-RangeReadExportBytes $zero $scratch $pattern;$checks++
}finally{
 $resolved=[IO.Path]::GetFullPath($scratch)
 if($resolved -cne $scratch -or -not $resolved.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -or ([IO.Path]::GetFileName($resolved)) -cnotmatch '\Antfs2refs-range-test-[0-9a-f]{32}\z'){throw 'Refusing scratch cleanup outside exact test directory.'}
 [IO.Directory]::Delete($resolved,$true)
}

$session='mock-session';$script:scenario='success';$script:removed=0;$script:commandIndeterminate=$false
function Invoke-Command {param($Session,[switch]$AsJob,$ArgumentList,$ScriptBlock)Check $script:commandIndeterminate 'Operation must be indeterminate before dispatch.';if($script:scenario -ceq 'dispatch-failure'){throw 'transport failed'};[pscustomobject]@{State=$(if($script:scenario -ceq 'timeout'){'Running'}elseif($script:scenario -ceq 'receive-failure'){'Failed'}else{'Completed'})}}
function Wait-Job {param($Job,$Timeout)if($script:scenario -cne 'timeout'){$Job}}
function Receive-Job {param($Job,$ErrorAction)if($script:scenario -ceq 'receive-failure'){throw 'transport lost during operation'};'answer'}
function Remove-Job {param($Job,[switch]$Force)$script:removed++}
$answer=@(Invoke-BoundedRangeReadCommand -ScriptBlock {} -TimeoutSeconds 30)
Check ($answer.Count -eq 1 -and $answer[0] -ceq 'answer' -and -not $script:commandIndeterminate -and $script:removed -eq 1) 'Completed command mishandled.'
foreach($testScenario in @('dispatch-failure','receive-failure','timeout')){$script:scenario=$testScenario;$script:removed=0;$script:commandIndeterminate=$false;Reject {Invoke-BoundedRangeReadCommand -ScriptBlock {} -TimeoutSeconds 30} 'Incomplete command accepted.';Check $script:commandIndeterminate 'Uncertain completion cleared.';if($testScenario -ceq 'timeout'){Check ($script:removed -eq 0) 'Running job forcibly removed.'}}
$commandNames=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()})
Check (@($commandNames|Where-Object{$_ -in @('Mount-VHD','Mount-DiskImage','Clear-Disk','Initialize-Disk','New-Partition','Format-Volume','Stop-VM','Stop-Job','Set-VMFirmware','Checkpoint-VM')}).Count -eq 0) 'Unexpected host mutation or forced stop.'
$topTry=$ast.EndBlock.Statements|Where-Object{$_ -is [Management.Automation.Language.TryStatementAst]}|Select-Object -Last 1
$catchCommands=@($topTry.CatchClauses[0].FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()})
Check (@($catchCommands|Where-Object{$_ -in @('Invoke-LabAction','Stop-RangeReadGuest','Set-VMMemory','Remove-Job')}).Count -eq 0) 'Failure handler mutates branch.'
$text=$ast.Extent.Text
Check ($text.IndexOf('    Assert-RangeReadCompletion $export.record') -lt $text.IndexOf('    Stop-RangeReadGuest')) 'Shutdown can precede completion validation.'
Check ($text.IndexOf('    Assert-RangeReadExportBytes $export.record') -lt $text.IndexOf('    Stop-RangeReadGuest')) 'Shutdown can precede byte validation.'
Check ($text.IndexOf('$record.volumeControlsMayHaveBeenIssued=$true') -lt $text.IndexOf('$responses=@(Invoke-BoundedRangeReadCommand')) 'Dispatch lacks possible-control intent.'
Check ($text.IndexOf('$record.cleanShutdown=$true') -lt $text.IndexOf("`$record.phase='restore-baseline'")) 'Restore can precede clean shutdown.'
$dry=& $path -WhatIf
Check ($dry.DryRun -and $dry.MemoryBytes -eq 8GB -and $dry.MaximumRawReadBytes -eq 131072 -and $dry.MaximumLockCalls -eq 1 -and -not $dry.RawWriteRequestsIssued -and -not $dry.ConversionQualified) 'Host WhatIf failed.'
"Lab range read: $checks checks passed."
