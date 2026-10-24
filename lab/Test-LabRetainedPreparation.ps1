<# Host pure guards and a synthetic exported native corpus. No VM/device actions. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop';$repo=Split-Path -Parent $PSScriptRoot;$script:checks=0
function Check([bool]$Value,[string]$Name){if(-not$Value){throw $Name};$script:checks++}
function Reject([scriptblock]$Body,[string]$Name){$bad=$false;try{&$Body|Out-Null}catch{$bad=$true};Check $bad $Name}
function Clone($Value){ConvertTo-Json -InputObject $Value -Depth 32|ConvertFrom-Json}
foreach($file in @('scripts\Invoke-LabRetainedPreparation.ps1','lab\guest\Invoke-GuestRetainedPair.ps1')){
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo $file),[ref]$tokens,[ref]$errors);Check ($errors.Count-eq0) 'parse';foreach($fn in $ast.FindAll({param($node)$node-is[Management.Automation.Language.FunctionDefinitionAst]},$true)){. ([scriptblock]::Create($fn.Extent.Text))}
}
$review=[pscustomobject]@{schemaVersion=1;kind='retained-preparation-reviewed-sources';files=@(Get-RetainedPreparationSources|ForEach-Object{[pscustomobject]@{path=$_;sha256=('a'*64)}})}
$script:guestOperationIndeterminate=$true
Set-RetainedPreparationGuestCompletion ([pscustomobject]@{OperationCompletionKnown=$true})
Check (-not$script:guestOperationIndeterminate) 'explicit guest completion clears operation uncertainty'
Set-RetainedPreparationGuestCompletion ([pscustomobject]@{OperationCompletionKnown=$false})
$script:commandIndeterminate=$false
Check $script:guestOperationIndeterminate 'successful evidence transport does not clear unfinished guest operation'
Reject {Set-RetainedPreparationGuestCompletion ([pscustomobject]@{OperationCompletionKnown='true'})} 'string completion is not native completion'
Check $script:guestOperationIndeterminate 'malformed completion preserves uncertainty'
Reject {Set-RetainedPreparationGuestCompletion ([pscustomobject]@{})} 'missing completion preserves uncertainty'
Check $script:guestOperationIndeterminate 'missing completion cannot permit cleanup'
Assert-RetainedPreparationReviewed $review;$script:checks++
$bad=Clone $review;$bad.files[0].path='../guest.ps1';Reject {Assert-RetainedPreparationReviewed $bad} 'unreviewed path'
$bad=Clone $review;$bad.files[0].sha256='not-a-hash';Reject {Assert-RetainedPreparationReviewed $bad} 'invalid pin'
$bad=Clone $review;$bad.files=$bad.files[1..9];Reject {Assert-RetainedPreparationReviewed $bad} 'missing reviewed source'
$manifest=Get-Content -LiteralPath (Join-Path $repo '.lab\hyperv\win11\manifest.json') -Raw|ConvertFrom-Json
Assert-RetainedPreparationManifest $manifest;$script:checks++
foreach($change in @('vmId','vmName')){$bad=Clone $manifest;$bad.$change='wrong';Reject {Assert-RetainedPreparationManifest $bad} ('manifest '+$change)}
foreach($change in @('sizeBytes','controllerLocation','vhdId')){$bad=Clone $manifest;$bad.disks[1].$change=0;Reject {Assert-RetainedPreparationManifest $bad} ('disk '+$change)}
$baseline='eda059b3-6d50-46bb-bdf4-018b99b5b34f';$vm=[pscustomobject]@{Id=$manifest.vmId;State='Off';Generation=2;MemoryStartup=4GB;DynamicMemoryEnabled=$false;ParentSnapshotId=$baseline}
Assert-RetainedPreparationVM $vm $baseline 4GB On @();$script:checks++
foreach($change in @('State','MemoryStartup','ParentSnapshotId','DynamicMemoryEnabled')){$bad=Clone $vm;$bad.$change=if($change-ceq'DynamicMemoryEnabled'){$true}else{'wrong'};Reject {Assert-RetainedPreparationVM $bad $baseline 4GB On @()} ('VM '+$change)}
Reject {Assert-RetainedPreparationVM $vm $baseline 4GB Off @()} 'Secure Boot'
Reject {Assert-RetainedPreparationVM $vm $baseline 4GB On @([pscustomobject]@{SwitchName='connected'})} 'network'
$cp=[pscustomobject]@{Id=$baseline;Name='installed-clean';VMId=$manifest.vmId;State='Off'};Assert-RetainedPreparationBaseline $cp;$script:checks++
$cp.State='Running';Reject {Assert-RetainedPreparationBaseline $cp} 'baseline must be off'
$outcome=[pscustomobject]@{Id='55555555-5555-5555-5555-555555555555';Name='retained-prepared-test';VMId=$manifest.vmId;State='Off';MemoryStartup=8GB;DynamicMemoryEnabled=$false};Assert-RetainedPreparationOutcome $outcome $outcome.Name;$script:checks++
$outcome.MemoryStartup=4GB;Reject {Assert-RetainedPreparationOutcome $outcome $outcome.Name} 'checkpoint memory'
function FileEntry([string]$Name,[long]$Length){[pscustomobject]@{name=$Name;length=$Length;attributes='Archive';sha256=('a'*64)}}
$files=@((FileEntry prepare.json 100),(FileEntry target.json 100),(FileEntry started.json 100));Assert-RetainedPreparationArtifactSet $files source;$script:checks++
foreach($name in @('../escape.json','sub\file','query-000.bin','EXTRA.json')){$bad=Clone $files;$bad[0].name=$name;Reject {Assert-RetainedPreparationArtifactSet $bad source} 'source allowlist'}
$bad=Clone $files;$bad[1].length=2MB;Reject {Assert-RetainedPreparationArtifactSet $bad source} 'artifact bound'
$bad=Clone $files;$bad[0].attributes='ReparsePoint';Reject {Assert-RetainedPreparationArtifactSet $bad source} 'artifact reparse'
$partial=@((FileEntry pair.json 100),(FileEntry query-000.bin 0));Assert-RetainedPreparationArtifactSet $partial pair;$script:checks++
$bad=Clone $partial;$bad[0].length=0;Reject {Assert-RetainedPreparationArtifactSet $bad pair} 'JSON cannot be empty'
$many=@((FileEntry pair.json 100),(FileEntry started.json 100));for($i=0;$i-lt9;$i++){$many+=FileEntry ('query-'+$i.ToString('D3')+'.bin') 2MB};Reject {Assert-RetainedPreparationArtifactSet $many pair} 'binary aggregate'
$id='0123456789abcdef0123456789abcdef';$obs='fedcba9876543210fedcba9876543210'
$reply=[pscustomobject]@{RunId=$id;ObservationId=$obs;Phase='Construct';EvidenceDirectory=('C:\ntfs2refs\retained-pair\'+$id+'\'+$obs);OperationCompletionKnown=$true;ConversionQualified=$false}
Assert-RetainedPreparationResponse $reply pair $id $obs;$script:checks++
$bad=Clone $reply;$bad.EvidenceDirectory='C:\';Reject {Assert-RetainedPreparationResponse $bad pair $id $obs} 'response path'
$bad=Clone $reply;$bad.OperationCompletionKnown=$null;Reject {Assert-RetainedPreparationResponse $bad pair $id $obs} 'unknown operation marker'

Add-Type -Path @((Join-Path $repo 'lab\guest\NativeRetainedFixture.cs'),(Join-Path $repo 'lab\guest\NativeRetainedFixture.Windows.cs'),(Join-Path $PSScriptRoot 'FakeRetainedFixture.cs'))
$av='\\?\Volume{11111111-1111-1111-1111-111111111111}\';$bv='\\?\Volume{22222222-2222-2222-2222-222222222222}\'
$source=[pscustomobject]@{schemaVersion=1;kind='retained-ntfs-source-platform';runId=$id;status='ntfs-source-prepared';formatSucceeded=$true;operationCompletionKnown=$true;conversionQualified=$false;target=[pscustomobject]@{guest=[pscustomobject]@{role='target';uniqueId='60022480D091C4251B5FFD619706C2B5';sizeBytes=64GB};host=@($manifest.disks|Where-Object role -CEQ target)[0]};partition=[pscustomobject]@{offset=16MB;length=52GB;letter='F';logicalSectorSize=512;physicalSectorSize=4096;number=2;guid='{11111111-1111-1111-1111-111111111111}';diskGuid='{33333333-3333-3333-3333-333333333333}'};volume=[pscustomobject]@{guid=$av;filesystem='NTFS';label='n2r-retained-source';allocationUnitSize=4096}}
$shadow=[pscustomobject]@{schemaVersion=1;kind='guest-local-shadow-platform';runId=$id;status='shadow-platform-prepared';nativeOperationCompletionKnown=$true;attachmentRetained=$true;handleCloseSucceeded=$true;conversionQualified=$false;backingPath=('J:\ntfs2refs-shadow\'+$id+'\shadow.vhdx');shadow=[pscustomobject]@{offset=16MB;length=52GB;logicalSectorSize=512;physicalSectorSize=4096;letter='S';filesystem='ReFS';allocationUnitSize=4096;diskNumber=3;diskUniqueId='independent-shadow';diskGuid='{44444444-4444-4444-4444-444444444444}';partitionGuid='{22222222-2222-2222-2222-222222222222}';volumeGuid=$bv;partitionNumber=2}}
$native=Clone ([Ntfs2Refs.NativeRetainedFixture]::RunWith((New-Object FakeRetainedFixture),$av,$bv,$id,$true))
$directoryQueries=@($native.queries);$native.queries=@()
$sourceHashes=@([pscustomobject]@{name='Invoke-GuestRetainedPair.ps1';length=100;sha256=('c'*64)},[pscustomobject]@{name='NativeRetainedFixture.cs';length=100;sha256=('d'*64)},[pscustomobject]@{name='NativeRetainedFixture.Windows.cs';length=100;sha256=('e'*64)})
$pair=[pscustomobject]@{schemaVersion=1;kind='retained-fixture-pair';phase='Construct';runId=$id;observationId=$obs;status='constructed-awaiting-raw-proof';nativeOperationCompletionKnown=$true;sourceEvidenceSha256=('a'*64);shadowEvidenceSha256=('b'*64);sourceInitializationEvidenceBound=$true;physicalMappingVerified=$false;conversionQualified=$false;scriptSha256=('c'*64);nativeSources=@($sourceHashes[1],$sourceHashes[2]);native=$native;artifacts=@()}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('n2r-retained-host-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $temp|Out-Null
function AddQuery([string]$Name,[string]$Api,[uint32]$Code,[int]$Capacity,[byte[]]$Bytes,[byte[]]$RequestBytes=@(),[bool]$Succeeded=$true,[int]$NativeError=0) {
 $n='query-'+$pair.native.queries.Count.ToString('D3')+'.bin';[IO.File]::WriteAllBytes((Join-Path $temp $n),$Bytes);$hash=[Ntfs2Refs.NativeRetainedFixture]::Hash($Bytes)
 $pair.native.queries+=@([pscustomobject]@{name=$Name;api=$Api;code=$Code;capacity=$Capacity;bytesReturned=$Bytes.Length;succeeded=$Succeeded;nativeError=$NativeError;bytes=$null;inputHex=([BitConverter]::ToString($RequestBytes)).Replace('-','').ToLowerInvariant();artifact=$n;sha256=$hash})
 $pair.artifacts+=@([pscustomobject]@{name=$n;query=$Name;length=$Bytes.Length;sha256=$hash})
}
try {
 foreach($q in $directoryQueries){AddQuery $q.name $q.api $q.code $q.capacity ([byte[]]@($q.bytes)) -Succeeded $q.succeeded -NativeError $q.nativeError}
 foreach($role in @('source','shadow')){$f=$pair.native.$role;$letter=if($role-ceq'source'){'A'}else{'B'}
  foreach($phase in @('before','after')){$s=$f.$phase;$prefix=$letter+$(if($phase-ceq'before'){'Before'}else{'After'})
   $basic=New-Object byte[] 40;for($i=0;$i-lt4;$i++){[BitConverter]::GetBytes([long]$s.basic.(@('creation','access','write','change')[$i])).CopyTo($basic,$i*8)};[BitConverter]::GetBytes([uint32]32).CopyTo($basic,32);AddQuery ($prefix+'Basic') GetFileInformationByHandleEx 0 40 $basic
   $std=New-Object byte[] 24;[BitConverter]::GetBytes([long]65536).CopyTo($std,0);[BitConverter]::GetBytes([long]65536).CopyTo($std,8);$std[16]=1;AddQuery ($prefix+'Standard') GetFileInformationByHandleEx 1 24 $std
   $identity=New-Object byte[] 24;[BitConverter]::GetBytes([uint64]$(if($letter-ceq'A'){1}else{2})).CopyTo($identity,0);for($i=8;$i-lt24;$i++){$identity[$i]=if($letter-ceq'A'){17}else{34}};AddQuery ($prefix+'Id') GetFileInformationByHandleEx 18 24 $identity
   AddQuery ($prefix+'Security') GetSecurityInfo 31 16384 ([byte[]]$s.security.bytes)
   $ext=New-Object byte[] 32;$ext[0]=1;[BitConverter]::GetBytes([long]16).CopyTo($ext,16);[BitConverter]::GetBytes([long]$s.extents[0].lcn).CopyTo($ext,24);AddQuery ($prefix+'Extents') DeviceIoControl 0x90073 272 $ext (New-Object byte[] 8)
   $regions=New-Object byte[] 40;$regions[4]=1;$regions[8]=1;[BitConverter]::GetBytes([long]65536).CopyTo($regions,24);$regions[32]=1;AddQuery ($prefix+'Cached') DeviceIoControl 0x90284 400 $regions ([Ntfs2Refs.NativeRetainedFixture]::RegionInput(1))
   $streams=New-Object byte[] 4096;$streams[4]=14;[BitConverter]::GetBytes([long]65536).CopyTo($streams,8);[BitConverter]::GetBytes([long]65536).CopyTo($streams,16);[Text.Encoding]::Unicode.GetBytes('::$DATA').CopyTo($streams,24);AddQuery ($prefix+'Streams') GetFileInformationByHandleEx 7 4096 $streams
   AddQuery ($prefix+'Base') DeviceIoControl 0x90234 8 (New-Object byte[] 8)
   if($letter-ceq'B'){$regions[32]=2;AddQuery ($prefix+'OnDisk') DeviceIoControl 0x90284 400 $regions ([Ntfs2Refs.NativeRetainedFixture]::RegionInput(2));$integrity=New-Object byte[] 16;[BitConverter]::GetBytes([uint32]4096).CopyTo($integrity,12);AddQuery ($prefix+'Integrity') DeviceIoControl 0x9027c 16 $integrity}
  }
  AddQuery ($letter+'Move') DeviceIoControl 0x90074 0 ([byte[]]@()) ([Ntfs2Refs.NativeRetainedFixture]::MoveInput(1234,2097152))
 }
 AddQuery BSetIntegrityNone DeviceIoControl 0x9c280 0 ([byte[]]@()) (New-Object byte[] 8)
 foreach($name in @('ntfsCandidate','refsCandidate','refsMetadataCandidate','AFreshBitmap','BFreshBitmap','BFreshMetadataBitmap')){$requestBytes=New-Object byte[] $(if($name-clike'*Metadata*'){16}else{8});if($requestBytes.Length-eq16){$requestBytes[8]=1};AddQuery $name DeviceIoControl 0x9006f 2MB ([FakeRetainedFixture]::Map(13631488)) $requestBytes}
 $intent=[pscustomobject]@{schemaVersion=1;kind='retained-pair-operation-intent';runId=$id;observationId=$obs;phase='Construct';targetMutationMayFollow=$true;sourceEvidenceSha256=('a'*64);shadowEvidenceSha256=('b'*64)}
 Write-RetainedPreparationJson (Join-Path $temp 'started.json') $intent 16KB
 $export=@($pair.artifacts|ForEach-Object{[pscustomobject]@{name=$_.name;length=$_.length;sha256=$_.sha256;attributes='Archive'}})+@((FileEntry pair.json 100),(FileEntry started.json 100))
 Assert-RetainedPreparationArtifactSet $export pair;$script:checks++
 Assert-RetainedPreparationPair $pair $source $shadow $export $temp $id $obs ('a'*64) ('b'*64) $sourceHashes;$script:checks++
 # A construction-only first no-match is accepted only with the full empty 2->18 sequence.
 $emptyPair=Clone $pair;$emptyFiles=Clone $export;$emptyHash=[Ntfs2Refs.NativeRetainedFixture]::Hash([byte[]]@())
 $first=@($emptyPair.native.queries|Where-Object name -CEQ 'AOpenRootDirectory0')[0]
 $first.succeeded=$false;$first.nativeError=2;$first.bytesReturned=0;$first.sha256=$emptyHash
 $ns=@($emptyPair.native.namespaces|Where-Object{$_.path-ceq'F:\'-and$_.stage-ceq'OpenRoot'})[0]
 $ns.entries=@();$ns.emptyInitialNoMatchInterpreted=$true;$ns.initialNoMatchInterpretation='documented-first-empty-search-not-reproduced-by-lab-diagnostic'
 foreach($item in @($emptyPair.artifacts)+@($emptyFiles)){if($item.name-ceq$first.artifact){$item.length=0;$item.sha256=$emptyHash}}
 $queryPath=Join-Path $temp $first.artifact;$savedQuery=[IO.File]::ReadAllBytes($queryPath)
 try{
  [IO.File]::WriteAllBytes($queryPath,[byte[]]@())
  Assert-RetainedPreparationPair $emptyPair $source $shadow $emptyFiles $temp $id $obs ('a'*64) ('b'*64) $sourceHashes;$script:checks++
  $bad=Clone $emptyPair;$bad.native.namespaces[0].emptyInitialNoMatchInterpreted=$false;Reject {Assert-RetainedPreparationPair $bad $source $shadow $emptyFiles $temp $id $obs ('a'*64) ('b'*64) $sourceHashes} 'first no-match needs explicit interpretation'
  $bad=Clone $emptyPair;$bad.native.queries[1].nativeError=2;Reject {Assert-RetainedPreparationPair $bad $source $shadow $emptyFiles $temp $id $obs ('a'*64) ('b'*64) $sourceHashes} 'first no-match requires explicit continuation EOF'
  $bad=Clone $emptyPair;$bad.native.namespaces[0].entries=$pair.native.namespaces[0].entries;Reject {Assert-RetainedPreparationPair $bad $source $shadow $emptyFiles $temp $id $obs ('a'*64) ('b'*64) $sourceHashes} 'first no-match forbids reported entries'
  $bad=Clone $emptyPair;$bad.phase='Inspect';Reject {Assert-RetainedPreparationPair $bad $source $shadow $emptyFiles $temp $id $obs ('a'*64) ('b'*64) $sourceHashes} 'first no-match is construction only'
 }finally{[IO.File]::WriteAllBytes($queryPath,$savedQuery)}
 $bad=Clone $pair;$bad.native.queries[1].nativeError=5;Reject {Assert-RetainedPreparationPair $bad $source $shadow $export $temp $id $obs ('a'*64) ('b'*64) $sourceHashes} 'directory access failure is not EOF'
 $bad=Clone $pair;$bad.native.queries[0].capacity=8192;Reject {Assert-RetainedPreparationPair $bad $source $shadow $export $temp $id $obs ('a'*64) ('b'*64) $sourceHashes} 'directory capacity differs'
 $bad=Clone $pair;$bad.native.namespaces[0].entries[0].fileId64='0x0000000000000002';Reject {Assert-RetainedPreparationPair $bad $source $shadow $export $temp $id $obs ('a'*64) ('b'*64) $sourceHashes} 'namespace decoded identity hint differs from native bytes'
 $bad=Clone $pair;$bad.native.source.after.basic.attributes=512;Reject {Assert-RetainedPreparationPair $bad $source $shadow $export $temp $id $obs ('a'*64) ('b'*64) $sourceHashes} 'decoded attribute contradiction'
 $bad=Clone $pair;$bad.native.source.after.extents[0].lcn++;Reject {Assert-RetainedPreparationPair $bad $source $shadow $export $temp $id $obs ('a'*64) ('b'*64) $sourceHashes} 'decoded extent contradiction'
 $bad=Clone $pair;$bad.native.shadow.after.fullyStorageValid=$false;Reject {Assert-RetainedPreparationPair $bad $source $shadow $export $temp $id $obs ('a'*64) ('b'*64) $sourceHashes} 'shadow storage unavailable'
 $bad=Clone $pair;$bad.native.source.after.fullyStorageValid=$true;Reject {Assert-RetainedPreparationPair $bad $source $shadow $export $temp $id $obs ('a'*64) ('b'*64) $sourceHashes} 'invented NTFS storage'
 $bad=Clone $pair;$bad.native.queries[0].code=999;Reject {Assert-RetainedPreparationPair $bad $source $shadow $export $temp $id $obs ('a'*64) ('b'*64) $sourceHashes} 'unreviewed native code'
 $bad=Clone $pair;$bad.native.queries[0].sha256=('0'*64);Reject {Assert-RetainedPreparationPair $bad $source $shadow $export $temp $id $obs ('a'*64) ('b'*64) $sourceHashes} 'native buffer pin'
 $bad=Clone $pair;$bad.native.candidateLcn=0;Reject {Assert-RetainedPreparationPair $bad $source $shadow $export $temp $id $obs ('a'*64) ('b'*64) $sourceHashes} 'candidate window'
 $bad=Clone $pair;$bad.native.source.volume=$bv;Reject {Assert-RetainedPreparationPair $bad $source $shadow $export $temp $id $obs ('a'*64) ('b'*64) $sourceHashes} 'native volume alias'
 Reject {Write-RetainedPreparationJson (Join-Path $temp 'started.json') $intent} 'host evidence overwrite'
}finally{$full=[IO.Path]::GetFullPath($temp);$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath());if(-not$full.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)-or[IO.Path]::GetFileName($full)-notlike'n2r-retained-host-*'){throw 'Unsafe test cleanup path.'};Remove-Item -LiteralPath $full -Recurse -Force}
$dry=& (Join-Path $repo 'scripts\Invoke-LabRetainedPreparation.ps1') -WhatIf;Check ($dry.DryRun-and$dry.MaximumMoveCalls-eq2-and-not$dry.ConversionQualified) 'WhatIf'
Write-Output ("Retained host: {0} pure/synthetic/ordinary-file/WhatIf checks passed; no VM/device calls."-f$script:checks)
