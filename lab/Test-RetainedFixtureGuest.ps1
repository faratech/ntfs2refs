<# Pure guards, ordinary temporary evidence and WhatIf only. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop';$script:checks=0;$repo=Split-Path -Parent $PSScriptRoot
function Check([bool]$Value,[string]$Name){if(-not$Value){throw $Name};$script:checks++}
function Reject([scriptblock]$Body,[string]$Name){$bad=$false;try{&$Body|Out-Null}catch{$bad=$true};Check $bad $Name}
function Clone($Value){$Value|ConvertTo-Json -Depth 20|ConvertFrom-Json}
foreach($relative in @('lab\guest\Prepare-GuestRetainedSource.ps1','lab\guest\Invoke-GuestRetainedPair.ps1')){
 $path=Join-Path $repo $relative;$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors);Check ($errors.Count-eq0) ('parse '+$relative)
 foreach($f in $ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]},$true)){. ([scriptblock]::Create($f.Extent.Text))}
}
$hostSpec=[pscustomobject]@{role='target';sizeBytes=64GB;controllerLocation=1;vhdId='25c491d0-5f1b-4205-9e6f-fd619706c2b5'}
Assert-RetainedSourceHost $hostSpec;$script:checks++
foreach($field in @('role','sizeBytes','controllerLocation','vhdId')){$bad=Clone $hostSpec;$bad.$field='bad';Reject {Assert-RetainedSourceHost $bad} ('host '+$field)}
$disk=[pscustomobject]@{Number=1;UniqueId='60022480D091C4251B5FFD619706C2B5';Size=64GB;PartitionStyle='RAW';IsOffline=$false;IsReadOnly=$false;IsBoot=$false;IsSystem=$false;LogicalSectorSize=512;PhysicalSectorSize=4096;Guid='{33333333-3333-3333-3333-333333333333}'}
Assert-RetainedBlankDisk $disk;$script:checks++
foreach($field in @('Number','UniqueId','Size','PartitionStyle','LogicalSectorSize','PhysicalSectorSize')){$bad=Clone $disk;$bad.$field=0;Reject {Assert-RetainedBlankDisk $bad} ('disk '+$field)}
foreach($field in @('IsOffline','IsReadOnly','IsBoot','IsSystem')){$bad=Clone $disk;$bad.$field=$true;Reject {Assert-RetainedBlankDisk $bad} ('disk role '+$field)}
$disk.PartitionStyle='GPT';$part=[pscustomobject]@{DiskNumber=1;PartitionNumber=2;Offset=16MB;Size=52GB;DriveLetter='F';IsBoot=$false;IsSystem=$false;Guid='{11111111-1111-1111-1111-111111111111}';GptType='{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'}
$expected=[pscustomobject]@{number=2;diskGuid=$disk.Guid;guid=$part.Guid;uniqueId=$disk.UniqueId;letter='F';volumeGuid='\\?\Volume{11111111-1111-1111-1111-111111111111}\'}
Assert-RetainedSourcePartition $disk $part $expected;$script:checks++
foreach($field in @('DiskNumber','PartitionNumber','Offset','Size','DriveLetter','Guid','GptType')){$bad=Clone $part;$bad.$field=0;Reject {Assert-RetainedSourcePartition $disk $bad $expected} ('partition '+$field)}
$volume=[pscustomobject]@{FileSystem='NTFS';FileSystemLabel='n2r-retained-source';AllocationUnitSize=4096;Path=$expected.volumeGuid}
Assert-RetainedLiveVolume $disk $part $volume $expected A;$script:checks++
foreach($field in @('FileSystem','FileSystemLabel','AllocationUnitSize','Path')){$bad=Clone $volume;$bad.$field='x';Reject {Assert-RetainedLiveVolume $disk $part $bad $expected A} ('live '+$field)}
$id='0123456789abcdef0123456789abcdef'
$source=[pscustomobject]@{schemaVersion=1;kind='retained-ntfs-source-platform';runId=$id;status='ntfs-source-prepared';formatSucceeded=$true;operationCompletionKnown=$true;conversionQualified=$false;target=[pscustomobject]@{guest=[pscustomobject]@{role='target';uniqueId=$disk.UniqueId;sizeBytes=64GB};host=$hostSpec};partition=[pscustomobject]@{offset=16MB;length=52GB;letter='F';logicalSectorSize=512;physicalSectorSize=4096;number=2;guid=$part.Guid;diskGuid=$disk.Guid};volume=[pscustomobject]@{guid=$expected.volumeGuid;filesystem='NTFS';label='n2r-retained-source';allocationUnitSize=4096}}
$shadow=[pscustomobject]@{schemaVersion=1;kind='guest-local-shadow-platform';runId=$id;status='shadow-platform-prepared';nativeOperationCompletionKnown=$true;attachmentRetained=$true;handleCloseSucceeded=$true;conversionQualified=$false;backingPath=('J:\ntfs2refs-shadow\'+$id+'\shadow.vhdx');shadow=[pscustomobject]@{offset=16MB;length=52GB;logicalSectorSize=512;physicalSectorSize=4096;letter='S';filesystem='ReFS';allocationUnitSize=4096;diskNumber=3;diskUniqueId='independent-shadow';diskGuid='{44444444-4444-4444-4444-444444444444}';partitionGuid='{22222222-2222-2222-2222-222222222222}';volumeGuid='\\?\Volume{22222222-2222-2222-2222-222222222222}\';partitionNumber=2}}
Assert-RetainedPlatforms $source $shadow $id;$script:checks++
foreach($field in @('schemaVersion','kind','runId','status','formatSucceeded','operationCompletionKnown','conversionQualified')){$bad=Clone $source;$bad.$field='invalid';Reject {Assert-RetainedPlatforms $bad $shadow $id} ('source evidence '+$field)}
foreach($field in @('schemaVersion','kind','runId','status','nativeOperationCompletionKnown','attachmentRetained','handleCloseSucceeded','conversionQualified','backingPath')){$bad=Clone $shadow;$bad.$field='invalid';Reject {Assert-RetainedPlatforms $source $bad $id} ('shadow evidence '+$field)}
foreach($field in @('offset','length','logicalSectorSize','physicalSectorSize','letter','filesystem','allocationUnitSize','diskNumber','diskUniqueId','diskGuid','partitionGuid','volumeGuid')){$bad=Clone $shadow;$bad.shadow.$field=0;Reject {Assert-RetainedPlatforms $source $bad $id} ('shadow geometry '+$field)}
foreach($field in @('volumeGuid','diskUniqueId','diskGuid')){$bad=Clone $shadow;$bad.shadow.$field=if($field-ceq'volumeGuid'){$source.volume.guid}elseif($field-ceq'diskUniqueId'){$source.target.guest.uniqueId}else{$source.partition.diskGuid};Reject {Assert-RetainedPlatforms $source $bad $id} ('independence '+$field)}
Add-Type -Path @((Join-Path $repo 'lab\guest\NativeRetainedFixture.cs'),(Join-Path $repo 'lab\guest\NativeRetainedFixture.Windows.cs'),(Join-Path $PSScriptRoot 'FakeRetainedFixture.cs'))
$fake=New-Object FakeRetainedFixture;$native=[Ntfs2Refs.NativeRetainedFixture]::RunWith($fake,[string]$source.volume.guid,[string]$shadow.shadow.volumeGuid,$id,$true)
$construct=[pscustomobject]@{schemaVersion=1;kind='retained-fixture-pair';phase='Construct';runId=$id;observationId=$id;status='constructed-awaiting-raw-proof';nativeOperationCompletionKnown=$true;sourceEvidenceSha256=('a'*64);shadowEvidenceSha256=('b'*64);conversionQualified=$false;native=$native}
Assert-RetainedConstruction $construct $id $id ('a'*64) ('b'*64);$script:checks++
foreach($field in @('inputHex','api','nativeError','creationTimeNull','lastWriteTimeNull','writeAttributesAccessRequested','succeeded')){$bad=Clone $construct;$bad.native.lastAccessPolicies[0].$field=if($field-in@('creationTimeNull','lastWriteTimeNull','writeAttributesAccessRequested','succeeded')){$false}else{'wrong'};Reject {Assert-RetainedConstruction $bad $id $id ('a'*64) ('b'*64)} ('policy '+$field)}
$bad=Clone $construct;$bad.native.lastAccessPolicies=@($bad.native.lastAccessPolicies|Select-Object -Skip 1);Reject {Assert-RetainedConstruction $bad $id $id ('a'*64) ('b'*64)} 'missing policy handle'
foreach($field in @('sourceFrozen','cleanupComplete','privilegeRestored','writeHandlesClosedBeforeFinalObservation','pairSemanticsMatch')){$bad=Clone $construct;$bad.native.$field=$false;Reject {Assert-RetainedConstruction $bad $id $id ('a'*64) ('b'*64)} ('construction '+$field)}
foreach($field in @('fileCreated','payloadInitialized','payloadBytesWritten','creationFlushed','creationClosed','moveCallCount','moveCompleted','moveSucceeded','requestedPlacementObserved')){$bad=Clone $construct;$bad.native.source.$field=0;Reject {Assert-RetainedConstruction $bad $id $id ('a'*64) ('b'*64)} ('write provenance '+$field)}
Reject {Assert-RetainedConstruction $construct $id $id ('c'*64) ('b'*64)} 'construction input pin'
$observed=[Ntfs2Refs.NativeRetainedFixture]::RunWith((New-Object FakeRetainedFixture),[string]$source.volume.guid,[string]$shadow.shadow.volumeGuid,$id,$false)
Assert-RetainedInspection $native $observed;$script:checks++
foreach($section in @('basic','standard','identity','security')){$bad=Clone $observed;$field=switch($section){basic{'change'}standard{'eof'}identity{'fileId128'}security{'owner'}};$bad.source.after.$section.$field='changed';Reject {Assert-RetainedInspection $native $bad} ('inspection '+$section)}
$bad=Clone $observed;$bad.source.after.extents[0].lcn++;Reject {Assert-RetainedInspection $native $bad} 'inspection frozen extent'
$bad=Clone $observed;$bad.shadow.directoryBasic.change++;Reject {Assert-RetainedInspection $native $bad} 'inspection directory times'
$bad=Clone $observed;$bad.source.directoryBasic.access=134372845503312033;Reject {Assert-RetainedInspection $native $bad} 'measured directory access change remains blocked'
foreach($field in @('complete','expectedFixture','queryNames','entries')){$bad=Clone $observed;$bad.namespaces[0].$field=if($field-in@('complete','expectedFixture')){$false}else{@()};Reject {Assert-RetainedNamespaces $bad $false} ('namespace '+$field)}
$q=Clone $observed.queries[0];Assert-RetainedQueryOutcome $q;$script:checks++
$end=Clone $observed.queries[1];Assert-RetainedQueryOutcome $end;$script:checks++
foreach($field in @('name','api','code','capacity','inputHex','nativeError','bytesReturned')){$bad=Clone $end;$bad.$field=if($field-in@('code','capacity','nativeError','bytesReturned')){999}else{'wrong'};Reject {Assert-RetainedQueryOutcome $bad} ('directory EOF '+$field)}
$bad=Clone $end;$bad.succeeded='false';Reject {Assert-RetainedQueryOutcome $bad} 'string false query rejected'
$bad=Clone $observed;$bad.namespaces[0].queryNames=@($bad.namespaces[0].queryNames[0]);Reject {Assert-RetainedNamespaces $bad $false} 'missing end of directory refuses'
$bad=Clone $observed;$bad.queries[1].nativeError=5;Reject {Assert-RetainedNamespaces $bad $false} 'access failure is not namespace EOF'
$bad=Clone $observed;$bad.namespaces[0].entries[0].name='unexpected';Reject {Assert-RetainedNamespaces $bad $false} 'unexpected namespace refuses'
$bad=Clone $observed;$bad.lastAccessPolicies=@($bad.lastAccessPolicies|Where-Object{$_.path-cne'F:\retained'});Reject {Assert-RetainedAccessPolicies $bad $false} 'directory handle policy is mandatory'
$pairAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'lab\guest\Invoke-GuestRetainedPair.ps1'),[ref]$null,[ref]$null)
Check (@($pairAst.FindAll({param($node)$node-is[Management.Automation.Language.CommandAst]-and$node.GetCommandName()-ceq'Get-ChildItem'},$true)).Count-eq0) 'wrapper has no uncontrolled filesystem enumeration'
$emptyFake=New-Object FakeRetainedFixture;$emptyFake.fault='empty-root';$empty=[Ntfs2Refs.NativeRetainedFixture]::RunWith($emptyFake,[string]$source.volume.guid,[string]$shadow.shadow.volumeGuid,$id,$true);Assert-RetainedNamespaces $empty $true;$script:checks++
Assert-RetainedQueryOutcome $empty.queries[0] $true;$script:checks++;Reject {Assert-RetainedQueryOutcome $empty.queries[0]} 'error2 requires explicit construction context'
Reject {Assert-RetainedNamespaces $empty $false} 'initial empty interpretation is never inspection'
foreach($case in @('missing-next','next-error','first-success','entries','note','unmarked','first-bytes')){$bad=Clone $empty;switch($case){'missing-next'{$bad.namespaces[0].queryNames=@($bad.namespaces[0].queryNames[0])}'next-error'{$bad.queries[1].nativeError=2}'first-success'{$bad.queries[0].succeeded=$true}'entries'{$bad.namespaces[0].entries=@([pscustomobject]@{name='System Volume Information';attributes=16;eof=0;allocation=0})}'note'{$bad.namespaces[0].initialNoMatchInterpretation='reproduced'}'unmarked'{$bad.namespaces[0].emptyInitialNoMatchInterpreted=$false}'first-bytes'{$bad.queries[0].bytesReturned=1}};Reject {Assert-RetainedNamespaces $bad $true} ('initial no-match '+$case)}
$bad=Clone $empty.queries[0];$bad.name='ABeforeRootDirectory0';Reject {Assert-RetainedQueryOutcome $bad $true} 'populated stage error2 is not allowed'
Reject {Read-RetainedPinnedJson 'C:\Windows\system.ini' ('0'*64)} 'evidence root'
$temp=Join-Path ([IO.Path]::GetTempPath()) ('n2r-retained-guards-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $temp|Out-Null
try {
 $path=Join-Path $temp 'one.bin';Write-RetainedArtifact $path ([byte[]]@(1,2,3)) 3;Check ((Get-Item -LiteralPath $path).Length-eq3) 'bounded artifact'
 Reject {Write-RetainedArtifact $path ([byte[]]@(4)) 3} 'artifact overwrite'
 Reject {Write-RetainedArtifact (Join-Path $temp 'oversize.bin') ([byte[]]@(1,2,3,4)) 3} 'artifact bound';Check (-not(Test-Path -LiteralPath (Join-Path $temp 'oversize.bin'))) 'no oversize artifact'
 $json=Join-Path $temp 'one.json';Write-RetainedNewJson $json ([pscustomobject]@{a=1});$bytes=[IO.File]::ReadAllBytes($json);Check ($bytes[0]-eq123) 'JSON UTF8 no BOM';Reject {Write-RetainedNewJson $json ([pscustomobject]@{a=2})} 'JSON create new'
 $exportDir=Join-Path $temp 'queries';New-Item -ItemType Directory -Path $exportDir|Out-Null
 $nativeRecord=New-Object Ntfs2Refs.RetainedPairResult;$nativeRecord.runId=$id;$query=New-Object Ntfs2Refs.RetainedQuery
 $query.name='refsCandidate';$query.api='DeviceIoControl';$query.code=0x9006f;$query.capacity=2097152;$query.succeeded=$true;$query.nativeError=0;$query.inputHex='0000000000000000';$query.startedUtc='2026-10-24T02:00:00Z';$query.finishedUtc='2026-10-24T02:00:01Z'
 $query.bytes=New-Object byte[] 2097152;$declared=[FakeRetainedFixture]::Map(13631488);[Array]::Copy($declared,$query.bytes,$declared.Length);$query.bytes[$query.bytes.Length-1]=255;$query.bytesReturned=$query.bytes.Length;$nativeRecord.queries.Add($query)
 $emptyQuery=New-Object Ntfs2Refs.RetainedQuery;$emptyQuery.name='failedControl';$emptyQuery.api='DeviceIoControl';$emptyQuery.nativeError=5;$emptyQuery.bytes=$null;$nativeRecord.queries.Add($emptyQuery)
  $export=Export-RetainedQueries $nativeRecord $exportDir;$serialized=$export|ConvertTo-Json -Depth 28;$roundTrip=$serialized|ConvertFrom-Json
 Check ($roundTrip.native.queries.Count-eq2-and$roundTrip.artifacts.Count-eq2-and$roundTrip.binaryBytes-eq2097152) 'typed query list serialization coverage'
 foreach($i in @(0,1)){$q=$roundTrip.native.queries[$i];$artifact=$roundTrip.artifacts[$i];Check ($q.artifact-ceq$artifact.name-and$q.sha256-ceq$artifact.sha256-and$q.bytesReturned-eq$artifact.length-and$null-eq$q.bytes) 'serialized query artifact mapping';Check ((Get-FileHash -LiteralPath (Join-Path $exportDir $q.artifact) -Algorithm SHA256).Hash.ToLowerInvariant()-ceq$q.sha256) 'serialized query hash pin'}
 $q=$roundTrip.native.queries[0];Check ($q.name-ceq$query.name-and$q.api-ceq$query.api-and$q.inputHex-ceq$query.inputHex-and$serialized.Contains($query.startedUtc)-and$serialized.Contains($query.finishedUtc)-and$q.code-eq$query.code-and$q.capacity-eq$query.capacity-and$q.succeeded-and$q.nativeError-eq0) 'raw native fields survive serialization'
 Check ($q.bitmapCoverage.meaningfulBytes-eq1703952-and$q.bitmapCoverage.trailingBytes-eq393200-and$null-eq$q.bitmapCoverageError) 'serialized declared bitmap provenance'
 Check ($query.bytes.Length-eq2097152-and$nativeRecord.queries[0].bytes[$query.bytes.Length-1]-eq255) 'original native buffers retained unmodified'
 Check (-not$roundTrip.native.queries[1].succeeded-and$roundTrip.native.queries[1].nativeError-eq5-and$roundTrip.artifacts[1].length-eq0) 'zero length native failure retained'
}finally{$full=[IO.Path]::GetFullPath($temp);$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath());if(-not$full.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)-or[IO.Path]::GetFileName($full)-notlike'n2r-retained-guards-*'){throw 'Unsafe test cleanup path.'};Remove-Item -LiteralPath $full -Recurse -Force}
$dry=& (Join-Path $repo 'lab\guest\Prepare-GuestRetainedSource.ps1') -RunId $id -HostTargetJson '{}' -WhatIf;Check ($dry.DryRun-and$dry.PartitionBytes-eq52GB) 'source WhatIf'
$dry=& (Join-Path $repo 'lab\guest\Invoke-GuestRetainedPair.ps1') -Phase Construct -RunId $id -ObservationId $id -SourceEvidenceSha256 ('0'*64) -ShadowEvidenceSha256 ('0'*64) -WhatIf;Check ($dry.DryRun-and$dry.MaximumMoveCalls-eq2) 'pair WhatIf'
Write-Output ("Retained guest: {0} pure/ordinary-file/WhatIf checks passed; no VM/device calls."-f$script:checks)
