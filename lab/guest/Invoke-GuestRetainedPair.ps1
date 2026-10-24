<# One disposable NTFS/ReFS fixture pair. Construct moves source only before its
   freeze boundary; Inspect reads and sets only documented per-handle access suppression. #>
[CmdletBinding(SupportsShouldProcess)]
param(
 [Parameter(Mandatory)][ValidateSet('Construct','Inspect')][string]$Phase,
 [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')][string]$RunId,
 [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')][string]$ObservationId,
 [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$SourceEvidenceSha256,
 [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ShadowEvidenceSha256,
 [ValidatePattern('^[0-9a-f]{32}$')][string]$ConstructionObservationId,
 [ValidatePattern('^[0-9a-f]{64}$')][string]$ConstructionEvidenceSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not $PSCmdlet.ShouldProcess('Exact owned F: NTFS and independent S: ReFS volumes',"$Phase one64KiB initialized fixture per volume; maximum one move each during construction")){
 [pscustomobject]@{DryRun=$true;Phase=$Phase;RunId=$RunId;PayloadBytesPerVolume=65536;MaximumMoveCalls=$(if($Phase-ceq'Construct'){2}else{0});ConversionQualified=$false};return
}
function Read-RetainedPinnedJson([string]$Path,[string]$Sha,[long]$MaximumBytes=1MB) {
 if($MaximumBytes-notin@(1MB,2MB)){throw 'Evidence size profile invalid.'}
 $p=[IO.Path]::GetFullPath($Path);if(-not $p.StartsWith('C:\ntfs2refs\',[StringComparison]::OrdinalIgnoreCase)){throw 'Evidence outside lab root.'}
 $ancestor=Split-Path -Parent $p
 while($ancestor){$i=Get-Item -LiteralPath $ancestor -Force;if(-not$i.PSIsContainer-or($i.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Reparse evidence ancestor.'};$next=Split-Path -Parent $ancestor;if($next-eq$ancestor){break};$ancestor=$next}
 $f=Get-Item -LiteralPath $p -Force;if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-lt1-or$f.Length-gt$MaximumBytes){throw 'Bounded ordinary platform evidence required.'}
 $s=New-Object IO.FileStream($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{$hash=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($hash.ComputeHash($s))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()};if($actual-cne$Sha){throw 'Platform evidence hash differs.'};$s.Position=0;$reader=New-Object IO.StreamReader($s,(New-Object Text.UTF8Encoding($false,$true)),$true,4096,$true);try{$reader.ReadToEnd()|ConvertFrom-Json}finally{$reader.Dispose()}}finally{$s.Dispose()}
}
function Assert-RetainedPlatforms($Source,$Shadow,[string]$ExpectedRunId) {
 if($Source.schemaVersion-ne1-or$Source.kind-cne'retained-ntfs-source-platform'-or$Source.runId-cne$ExpectedRunId-or$Source.status-cne'ntfs-source-prepared'-or$Source.formatSucceeded-ne$true-or$Source.operationCompletionKnown-ne$true-or$Source.conversionQualified-ne$false){throw 'NTFS preparation is incomplete.'}
 if($Source.target.guest.role-cne'target'-or$Source.target.guest.uniqueId-cne'60022480D091C4251B5FFD619706C2B5'-or$Source.target.guest.sizeBytes-ne64GB-or$Source.target.host.controllerLocation-ne1-or[string]$Source.target.host.vhdId-ine'25c491d0-5f1b-4205-9e6f-fd619706c2b5'){throw 'Source target enrollment differs.'}
 if($Source.partition.offset-ne16MB-or$Source.partition.length-ne52GB-or$Source.partition.letter-cne'F'-or$Source.partition.logicalSectorSize-ne512-or$Source.partition.physicalSectorSize-ne4096-or$Source.volume.filesystem-cne'NTFS'-or$Source.volume.label-cne'n2r-retained-source'-or$Source.volume.allocationUnitSize-ne4096){throw 'Source geometry differs.'}
 if($Shadow.schemaVersion-ne1-or$Shadow.kind-cne'guest-local-shadow-platform'-or$Shadow.runId-cne$ExpectedRunId-or$Shadow.status-cne'shadow-platform-prepared'-or$Shadow.nativeOperationCompletionKnown-ne$true-or$Shadow.attachmentRetained-ne$true-or$Shadow.handleCloseSucceeded-ne$true-or$Shadow.conversionQualified-ne$false){throw 'Independent shadow platform is incomplete.'}
 $s=$Shadow.shadow
 if($s.offset-ne16MB-or$s.length-ne52GB-or$s.logicalSectorSize-ne512-or$s.physicalSectorSize-ne4096-or$s.letter-cne'S'-or$s.filesystem-cne'ReFS'-or$s.allocationUnitSize-ne4096-or$s.diskNumber-lt3-or[string]::IsNullOrWhiteSpace([string]$s.diskUniqueId)-or[string]$s.diskUniqueId-ceq[string]$Source.target.guest.uniqueId){throw 'Independent shadow geometry/identity differs.'}
 foreach($g in @($Source.partition.guid,$Source.partition.diskGuid,$s.diskGuid,$s.partitionGuid)){if([guid]::Parse([string]$g)-eq[guid]::Empty){throw 'Missing GPT identity.'}}
 foreach($v in @($Source.volume.guid,$s.volumeGuid)){if([string]$v-cnotmatch '^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$'){throw 'Native volume GUID required.'}}
 if([string]$Source.volume.guid-ieq[string]$s.volumeGuid-or[string]$Source.partition.guid-ieq[string]$s.partitionGuid-or[string]$Source.partition.diskGuid-ieq[string]$s.diskGuid){throw 'Source and shadow identities must be independent.'}
 if([string]$Shadow.backingPath-cne('J:\ntfs2refs-shadow\'+$ExpectedRunId+'\shadow.vhdx')){throw 'Shadow backing outside exact journal-owned case.'}
}
function Assert-RetainedLiveVolume($Disk,$Part,$Volume,$Expected,[string]$Role) {
 if($Disk.IsBoot-or$Disk.IsSystem-or$Disk.IsOffline-or$Disk.IsReadOnly-or$Disk.Size-ne64GB-or$Disk.PartitionStyle-cne'GPT'-or$Disk.LogicalSectorSize-ne512-or$Disk.PhysicalSectorSize-ne4096-or[string]$Disk.UniqueId-cne[string]$Expected.uniqueId-or[string]$Disk.Guid-ine[string]$Expected.diskGuid){throw 'Live disk identity/protection differs.'}
 if($Part.DiskNumber-ne$Disk.Number-or$Part.PartitionNumber-ne$Expected.number-or$Part.Offset-ne16MB-or$Part.Size-ne52GB-or$Part.IsBoot-or$Part.IsSystem-or[string]$Part.Guid-ine[string]$Expected.guid-or[string]$Part.DriveLetter-cne[string]$Expected.letter-or[string]$Part.GptType-ine'{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'){throw 'Live partition geometry differs.'}
 $fs=if($Role-ceq'A'){'NTFS'}else{'ReFS'};$label=if($Role-ceq'A'){'n2r-retained-source'}else{'n2r-retained-shadow'}
 if($Volume.FileSystem-cne$fs-or$Volume.FileSystemLabel-cne$label-or$Volume.AllocationUnitSize-ne4096-or[string]$Volume.Path-ine[string]$Expected.volumeGuid){throw 'Live filesystem/volume identity differs.'}
}
function Assert-RetainedConstruction($Record,[string]$ExpectedRunId,[string]$ExpectedObservationId,[string]$SourceSha,[string]$ShadowSha) {
 if($Record.schemaVersion-ne1-or$Record.kind-cne'retained-fixture-pair'-or$Record.phase-cne'Construct'-or$Record.runId-cne$ExpectedRunId-or$Record.observationId-cne$ExpectedObservationId-or$Record.status-cne'constructed-awaiting-raw-proof'-or$Record.nativeOperationCompletionKnown-ne$true-or$Record.sourceEvidenceSha256-cne$SourceSha-or$Record.shadowEvidenceSha256-cne$ShadowSha-or$Record.conversionQualified-ne$false){throw 'Completed exact construction evidence required for inspection.'}
 $n=$Record.native
 if($n.status-cne'constructed-awaiting-raw-proof'-or$n.sourceFrozen-ne$true-or$n.cleanupComplete-ne$true-or$n.privilegeRestored-ne$true-or$n.writeHandlesClosedBeforeFinalObservation-ne$true-or$n.pairSemanticsMatch-ne$true){throw 'Construction freeze/cleanup incomplete.'}
 foreach($f in @($n.source,$n.shadow)){if($f.fileCreated-ne$true-or$f.payloadInitialized-ne$true-or$f.payloadBytesWritten-ne65536-or$f.creationFlushed-ne$true-or$f.creationClosed-ne$true-or$f.moveCallCount-ne1-or$f.moveCompleted-ne$true-or$f.moveSucceeded-ne$true-or$f.requestedPlacementObserved-ne$true){throw 'Complete initialized write/flush/close and single-move construction proof required.'}}
 if($n.source.after.fullyStorageValid-ne$false-or$n.source.after.storageRegionQueryAttempted-ne$false-or$n.source.after.storageValidityStatus-cne'not-queried-NTFS-storage-validity-unknown'-or$n.shadow.after.fullyStorageValid-ne$true){throw 'Source versus shadow validity claims differ.'}
 Assert-RetainedAccessPolicies $n $true;Assert-RetainedNamespaces $n $true
}
function Assert-RetainedAccessPolicies($Native,[bool]$Construct){
 if($Native.lastAccessPolicyVerified-isnot[bool]-or-not$Native.lastAccessPolicyVerified-or@($Native.lastAccessPolicies).Count-ne$(if($Construct){12}else{6})){throw 'Verified per-handle last-access policies required.'}
 foreach($root in @('F:\','S:\')){foreach($suffix in @('','retained','retained\payload.bin')){foreach($stage in @('root','created','construction','observation')){
  $path=$root+$suffix;$expected=if($suffix-ceq''){[int]($stage-ceq'root')}elseif($suffix-ceq'retained'){[int]($stage-ceq'observation'-or($Construct-and$stage-ceq'construction'))}else{[int]($stage-ceq'observation'-or($Construct-and$stage-in@('created','construction')))}
  if(@($Native.lastAccessPolicies|Where-Object{$_.path-ceq$path-and$_.stage-ceq$stage}).Count-ne$expected){throw 'Per-handle last-access coverage differs.'}
 }}}
 foreach($p in $Native.lastAccessPolicies){if($p.api-cne'SetFileTime'-or$p.inputHex-cne'ffffffffffffffff'-or$p.nativeError-ne0-or-not$p.startedUtc-or-not$p.finishedUtc){throw 'Last-access suppression native evidence differs.'};foreach($field in @('writeAttributesAccessRequested','creationTimeNull','lastWriteTimeNull','succeeded')){if($p.$field-isnot[bool]-or-not$p.$field){throw 'Last-access suppression arguments or status differ.'}}}
}
function Assert-RetainedQueryOutcome($Query,[bool]$AllowEmptyConstructionRoot=$false){
 $directory=$Query.api-ceq'GetFileInformationByHandleEx'-and$Query.code-in@(10,11)
 if($directory){if($Query.name-cnotmatch'^[AB](OpenRoot|BeforeRoot|BeforeFolder|AfterRoot|AfterFolder)Directory[0-3]$'-or$Query.capacity-ne4096-or$Query.inputHex-cne''-or(($Query.name.EndsWith('0'))-ne($Query.code-eq11))){throw 'Exact directory query ABI required.'}}
 if($Query.succeeded-isnot[bool]){throw 'Native query status must be boolean.'}
 if($Query.succeeded){if($Query.nativeError-ne0-or($directory-and$Query.bytesReturned-ne4096)){throw 'Native success query result differs.'};return}
 $initialNoMatch=$AllowEmptyConstructionRoot-and$directory-and$Query.name-cmatch'^[AB]OpenRootDirectory0$'-and$Query.code-eq11-and$Query.nativeError-eq2-and$Query.bytesReturned-eq0
 if(-not$initialNoMatch-and(-not$directory-or$Query.nativeError-ne18-or$Query.bytesReturned-ne0)){throw 'Native query failed without exact directory EOF or bounded initial no-match context.'}
}
function Assert-RetainedNamespaces($Native,[bool]$Construct){
 if($Native.namespaceVerified-isnot[bool]-or-not$Native.namespaceVerified-or@($Native.namespaces).Count-ne10){throw 'Complete pinned native namespace proof required.'}
 foreach($root in @('F:\','S:\')){foreach($stage in @('OpenRoot','BeforeRoot','BeforeFolder','AfterRoot','AfterFolder')){
  $path=$root+$(if($stage.EndsWith('Folder')){'retained'}else{''});$ns=@($Native.namespaces|Where-Object{$_.path-ceq$path-and$_.stage-ceq$stage})
  if($ns.Count-ne1-or$ns[0].complete-isnot[bool]-or-not$ns[0].complete-or$ns[0].expectedFixture-isnot[bool]-or$ns[0].expectedFixture-ne($stage-cne'OpenRoot'-or-not$Construct)){throw 'Native namespace coverage differs.'}
  $ns=$ns[0];$seen=@{};$count=0
  if($ns.emptyInitialNoMatchInterpreted-isnot[bool]){throw 'Explicit initial no-match interpretation flag required.'}
  if($ns.emptyInitialNoMatchInterpreted){if(-not$Construct-or$stage-cne'OpenRoot'-or$ns.expectedFixture-or@($ns.entries).Count-ne0-or@($ns.queryNames).Count-ne2-or$ns.initialNoMatchInterpretation-cne'documented-first-empty-search-not-reproduced-by-lab-diagnostic'){throw 'Initial no-match interpretation outside construction profile.'}}elseif($ns.initialNoMatchInterpretation){throw 'Unexpected initial no-match interpretation.'}
  foreach($e in $ns.entries){if(-not$e.name-or$seen.ContainsKey([string]$e.name)-or($e.attributes-band1024)){throw 'Ambiguous/reparse namespace entry.'};$seen[[string]$e.name]=$true
   if($e.name-in@('.','..')){if(-not($e.attributes-band16)){throw 'Dot entry must be directory.'};continue}
   if($stage.EndsWith('Folder')){if($e.name-cne'payload.bin'-or$e.attributes-ne32-or$e.eof-ne65536-or$e.allocation-ne65536){throw 'Unexpected fixture namespace.'};$count++}
   else{if($e.name-cnotin@('retained','System Volume Information','$RECYCLE.BIN')-or-not($e.attributes-band16)){throw 'Unexpected root namespace.'};if($e.name-ceq'retained'){$count++}}
  }
  if(@($ns.entries).Count-gt$(if($stage.EndsWith('Folder')){3}else{5})-or$count-ne[int]$ns.expectedFixture-or@($ns.queryNames).Count-lt1-or@($ns.queryNames).Count-gt4){throw 'Namespace object/query count differs.'}
  $i=0;foreach($name in $ns.queryNames){$q=@($Native.queries|Where-Object{$_.name-ceq$name});$prefix=$(if($root-ceq'F:\'){'A'}else{'B'})+$stage+'Directory'
   if($q.Count-ne1-or$name-cne($prefix+$i)){throw 'Directory query reference differs.'};$q=$q[0];$initial=$ns.emptyInitialNoMatchInterpreted-and$i-eq0;Assert-RetainedQueryOutcome $q $initial
   if($q.succeeded-ne($i-lt@($ns.queryNames).Count-1-and-not$initial)-or($initial-and$q.nativeError-ne2)){throw 'Directory EOF must terminate complete enumeration.'};$i++
  }
 }}
}
function Assert-RetainedInspection($Construction,$Observation) {
 Assert-RetainedAccessPolicies $Construction $true;Assert-RetainedAccessPolicies $Observation $false;Assert-RetainedNamespaces $Construction $true;Assert-RetainedNamespaces $Observation $false
 foreach($role in @('source','shadow')){
  $a=$Construction.$role.after;$b=$Observation.$role.after
  foreach($field in @('sha256','baseSectors','partitionOffset')){if([string]$a.$field-cne[string]$b.$field){throw 'Frozen content/mapping summary changed.'}}
  foreach($section in @('basic','standard','identity','security')){
   $fields=switch($section){basic{@('creation','access','write','change','attributes')}standard{@('allocation','eof','links','directory')}identity{@('fileId128','volumeSerial64')}security{@('sddl','owner','group','daclSddl','saclPresent','saclEmpty','saclAceCount')}}
   foreach($field in $fields){if([string]$a.$section.$field-cne[string]$b.$section.$field){throw ('Frozen '+$section+' metadata changed.')}}
  }
  if(@($a.extents).Count-ne1-or@($b.extents).Count-ne1){throw 'Frozen single extent changed.'};foreach($field in @('vcn','nextVcn','lcn')){if($a.extents[0].$field-ne$b.extents[0].$field){throw 'Frozen native extent changed.'}}
  foreach($field in @('creation','access','write','change','attributes')){if($Construction.$role.directoryBasic.$field-ne$Observation.$role.directoryBasic.$field){throw 'Frozen directory metadata changed.'}}
  if($Construction.$role.directorySecurity.sddl-cne$Observation.$role.directorySecurity.sddl){throw 'Frozen directory security changed.'}
 }
}
function Write-RetainedArtifact([string]$Path,[byte[]]$Bytes,[long]$Maximum) {
 if($Bytes.Length-gt$Maximum){throw 'Evidence artifact exceeds declared bound.'}
 $stream=New-Object IO.FileStream($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Export-RetainedQueries($Native,[string]$Directory){
 if($Native.queries.Count-gt192){throw 'Native query artifact count exceeds bound.'}
 $total=0L;$index=0;$artifacts=@();$queries=@()
 foreach($q in $Native.queries){
  $bytes=[byte[]]@();if($null-ne$q.bytes){$bytes=[byte[]]$q.bytes}
  if($bytes.Length-gt2MB-or$bytes.Length-ne$q.bytesReturned){throw 'Native query artifact bounds differ.'};$total+=$bytes.Length;if($total-gt16MB){throw 'Native query evidence exceeds16MiB.'}
  $name='query-'+$index.ToString('D3')+'.bin';$path=Join-Path $Directory $name;Write-RetainedArtifact $path $bytes 2MB;$sha=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
  $artifacts+=[pscustomobject]@{name=$name;query=$q.name;length=$bytes.Length;sha256=$sha}
  # Extended notes on a C# object inside List<T> do not survive JSON reliably.
  # Materialize every raw native field and its export mapping into plain records.
  $row=[pscustomobject][ordered]@{name=$q.name;api=$q.api;inputHex=$q.inputHex;startedUtc=$q.startedUtc;finishedUtc=$q.finishedUtc;code=$q.code;bytesReturned=$q.bytesReturned;capacity=$q.capacity;nativeError=$q.nativeError;succeeded=$q.succeeded;bytes=$null;artifact=$name;sha256=$sha;bitmapCoverage=$null;bitmapCoverageError=$null}
  if($q.api-ceq'DeviceIoControl'-and$q.code-eq0x9006f-and$q.succeeded-and$q.nativeError-eq0){try{$row.bitmapCoverage=[Ntfs2Refs.NativeRetainedFixture]::DescribeBitmap($bytes)}catch{$row.bitmapCoverageError=$_.Exception.Message}}
  $queries+=$row;$index++
 }
 $plain=[ordered]@{};foreach($property in $Native.PSObject.Properties){$plain[$property.Name]=$property.Value};$plain.queries=$queries
 [pscustomobject]@{native=[pscustomobject]$plain;artifacts=$artifacts;binaryBytes=$total}
}
if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'){throw 'Exact owned guest required.'}
$sourcePath='C:\ntfs2refs\retained-source\'+$RunId+'\prepare.json';$shadowPath='C:\ntfs2refs\shadow-platform\'+$RunId+'\prepare.json'
$source=Read-RetainedPinnedJson $sourcePath $SourceEvidenceSha256;$shadow=Read-RetainedPinnedJson $shadowPath $ShadowEvidenceSha256;Assert-RetainedPlatforms $source $shadow $RunId
$construction=$null;$constructionPath=$null
if($Phase-ceq'Inspect'){
 if([string]::IsNullOrWhiteSpace($ConstructionObservationId)-or[string]::IsNullOrWhiteSpace($ConstructionEvidenceSha256)){throw 'Inspect requires the exact completed construction observation and evidence hash.'}
 $constructionPath='C:\ntfs2refs\retained-pair\'+$RunId+'\'+$ConstructionObservationId+'\pair.json'
 $construction=Read-RetainedPinnedJson $constructionPath $ConstructionEvidenceSha256 2MB
 Assert-RetainedConstruction $construction $RunId $ConstructionObservationId $SourceEvidenceSha256 $ShadowEvidenceSha256
}elseif($ConstructionObservationId-or$ConstructionEvidenceSha256){throw 'Construction cannot bind a prior construction.'}
$runRoot='C:\ntfs2refs\retained-pair\'+$RunId+'\'+$ObservationId
$parent=Split-Path -Parent $runRoot
foreach($p in @('C:\ntfs2refs','C:\ntfs2refs\retained-pair',$parent)){if(Test-Path -LiteralPath $p){$i=Get-Item -LiteralPath $p -Force;if(-not$i.PSIsContainer-or($i.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary evidence parents required.'}}else{New-Item -ItemType Directory -Path $p|Out-Null}}
if(Test-Path -LiteralPath $runRoot){throw 'Observation evidence already exists.'};New-Item -ItemType Directory -Path $runRoot|Out-Null
$record=[ordered]@{schemaVersion=1;kind='retained-fixture-pair';phase=$Phase;runId=$RunId;observationId=$ObservationId;status='blocked';nativeOperationCompletionKnown=$true;targetWriteRequestsMayHaveIssued=$false;sourceEvidencePath=$sourcePath;sourceEvidenceSha256=$SourceEvidenceSha256;shadowEvidencePath=$shadowPath;shadowEvidenceSha256=$ShadowEvidenceSha256;constructionEvidencePath=$constructionPath;constructionEvidenceSha256=$ConstructionEvidenceSha256;sourceInitializationEvidenceBound=$false;sourcePlatform=$source;shadowPlatform=$shadow;native=$null;artifacts=@();physicalMappingVerified=$false;conversionQualified=$false;error=$null;createdUtc=[DateTime]::UtcNow.ToString('o')}
try {
 $sd=Get-Disk -Number 1;$sp=Get-Partition -DriveLetter F;$sv=Get-Volume -DriveLetter F
 $se=[pscustomobject]@{uniqueId=$source.target.guest.uniqueId;diskGuid=$source.partition.diskGuid;guid=$source.partition.guid;number=$source.partition.number;letter='F';volumeGuid=$source.volume.guid}
 Assert-RetainedLiveVolume $sd $sp $sv $se A
 $td=Get-Disk -Number $shadow.shadow.diskNumber;$tp=Get-Partition -DriveLetter S;$tv=Get-Volume -DriveLetter S
 $te=[pscustomobject]@{uniqueId=$shadow.shadow.diskUniqueId;diskGuid=$shadow.shadow.diskGuid;guid=$shadow.shadow.partitionGuid;number=$shadow.shadow.partitionNumber;letter='S';volumeGuid=$shadow.shadow.volumeGuid}
 Assert-RetainedLiveVolume $td $tp $tv $te B
 if($sd.Number-eq$td.Number-or$sd.UniqueId-ceq$td.UniqueId){throw 'Independent disks required.'}
 $nativeFiles=@('NativeRetainedFixture.cs','NativeRetainedFixture.Windows.cs');$provenance=@()
 foreach($name in $nativeFiles){$p=Join-Path $PSScriptRoot $name;$i=Get-Item -LiteralPath $p -Force;if($i.PSIsContainer-or($i.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$i.Length-gt128KB){throw 'Unexpected helper file.'};$provenance+=[pscustomobject]@{name=$name;length=$i.Length;sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}}
 $record['nativeSources']=$provenance;$record['scriptSha256']=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
 if(-not ('Ntfs2Refs.NativeRetainedFixture' -as[type])){Add-Type -Path @($nativeFiles|ForEach-Object{Join-Path $PSScriptRoot $_})}
 $intent=[pscustomobject]@{schemaVersion=1;kind='retained-pair-operation-intent';runId=$RunId;observationId=$ObservationId;phase=$Phase;targetMutationMayFollow=($Phase-ceq'Construct');sourceEvidenceSha256=$SourceEvidenceSha256;shadowEvidenceSha256=$ShadowEvidenceSha256;createdUtc=[DateTime]::UtcNow.ToString('o')}
 Write-RetainedArtifact (Join-Path $runRoot 'started.json') ((New-Object Text.UTF8Encoding($false,$true)).GetBytes(($intent|ConvertTo-Json))) 16KB
 $record.nativeOperationCompletionKnown=$false
 if($Phase-ceq'Construct'){$record.targetWriteRequestsMayHaveIssued=$true;$native=[Ntfs2Refs.NativeRetainedFixture]::ConstructPair([string]$source.volume.guid,[string]$shadow.shadow.volumeGuid,$RunId)}
 else{$native=[Ntfs2Refs.NativeRetainedFixture]::InspectPair([string]$source.volume.guid,[string]$shadow.shadow.volumeGuid,$RunId)}
 $record.native=$native;$record.nativeOperationCompletionKnown=$true
 $export=Export-RetainedQueries $native $runRoot;$record.native=$export.native;$record.artifacts=$export.artifacts;$record['binaryBytes']=$export.binaryBytes
 if(-not$native.cleanupComplete-or-not$native.privilegeRestored){throw 'Native cleanup/privilege restoration incomplete.'}
 if($native.status-notin@('constructed-awaiting-raw-proof','pair-observed')){throw ('Fixture native phase blocked: '+$native.error)}
 if($Phase-ceq'Inspect'){Assert-RetainedInspection $construction.native $native};$record.sourceInitializationEvidenceBound=$true
 Assert-RetainedNamespaces $native ($Phase-ceq'Construct')
 Assert-RetainedLiveVolume (Get-Disk -Number 1) (Get-Partition -DriveLetter F) (Get-Volume -DriveLetter F) $se A
 Assert-RetainedLiveVolume (Get-Disk -Number $shadow.shadow.diskNumber) (Get-Partition -DriveLetter S) (Get-Volume -DriveLetter S) $te B
 $record.status=$native.status
}catch{$record.error=$_.Exception.ToString();$record['errorId']=$_.FullyQualifiedErrorId;$record['errorPosition']=$_.InvocationInfo.PositionMessage}
finally{$record['finishedUtc']=[DateTime]::UtcNow.ToString('o');$json=(New-Object Text.UTF8Encoding($false,$true)).GetBytes(($record|ConvertTo-Json -Depth 28));Write-RetainedArtifact (Join-Path $runRoot 'pair.json') $json 2MB}
[pscustomobject]@{Status=$record.status;Phase=$Phase;RunId=$RunId;ObservationId=$ObservationId;EvidenceDirectory=$runRoot;OperationCompletionKnown=$record.nativeOperationCompletionKnown;TargetWriteRequestsMayHaveIssued=$record.targetWriteRequestsMayHaveIssued;SourceFrozen=$(if($record.native){$record.native.sourceFrozen}else{$false});ConversionQualified=$false}
