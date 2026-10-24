<# Lab orchestration only. Every filesystem format, file creation and initialized
   placement executes inside the owned guest. No host mount or raw target I/O. #>
[CmdletBinding(SupportsShouldProcess)]
param(
 [string]$ReviewedSourcesPath,
 [ValidatePattern('^[0-9a-f]{64}$')][string]$ReviewedSourcesSha256,
 [ValidateRange(60,900)][int]$BootTimeoutSeconds=300,
 [ValidateRange(60,900)][int]$StageTimeoutSeconds=600
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
$configuration=Get-LabConfiguration -WorkspaceRoot $workspace
if(-not $PSCmdlet.ShouldProcess('Owned installed-clean VM','Prepare NTFS source and independent guest-local ReFS shadow; construct one retained64KiB fixture pair; export/checkpoint and restore baseline only after success')){
 [pscustomobject]@{DryRun=$true;Action='RetainedPreparation';GuestMemoryBytes=8GB;SourcePartitionBytes=52GB;MaximumMoveCalls=2;ConversionQualified=$false};return
}
function Get-RetainedPreparationSources {
 @('lab/guest/GuestLab.psm1','lab/guest/Register-GuestDisk.ps1','lab/guest/Prepare-GuestRetainedSource.ps1','lab/guest/NativeShadowDisk.cs','lab/guest/Prepare-GuestShadowPlatform.ps1','lab/guest/NativeRetainedFixture.cs','lab/guest/NativeRetainedFixture.Windows.cs','lab/guest/Invoke-GuestRetainedPair.ps1','lab/Lab.psm1','scripts/Invoke-LabRetainedPreparation.ps1')
}
function Assert-RetainedPreparationReviewed($Review) {
 $names=@(Get-RetainedPreparationSources)
 if($Review.schemaVersion-ne1-or$Review.kind-cne'retained-preparation-reviewed-sources'-or@($Review.files).Count-ne$names.Count-or@($Review.files.path|Select-Object -Unique).Count-ne$names.Count){throw 'Exact reviewed source manifest required.'}
 foreach($f in $Review.files){if($f.path-cnotin$names-or$f.sha256-cnotmatch'^[0-9a-f]{64}$'){throw 'Unreviewed source name or invalid hash.'}}
}
function Assert-RetainedPreparationManifest($Manifest) {
 if($Manifest.schemaVersion-ne1-or$Manifest.lane-cne'win11'-or$Manifest.vmName-cne'ntfs2refs-win11'-or[string]$Manifest.vmId-ine'eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c'-or@($Manifest.disks).Count-ne3){throw 'Original owned VM manifest required.'}
 $ids=@('a95ba3be-96d4-4e6f-995a-d5aff633d768','25c491d0-5f1b-4205-9e6f-fd619706c2b5','1f26ac6a-1f02-4989-b5c8-249596f332fc')
 for($i=0;$i-lt3;$i++){$role=@('os','target','journal')[$i];$disk=@($Manifest.disks|Where-Object role -CEQ $role);$bytes=if($i-eq2){8GB}else{64GB};if($disk.Count-ne1-or$disk[0].controllerLocation-ne$i-or$disk[0].sizeBytes-ne$bytes-or[string]$disk[0].vhdId-ine$ids[$i]){throw 'Original three disk roles/identities changed.'}}
}
function Assert-RetainedPreparationVM($VM,[string]$Parent,[long]$Memory,[string]$SecureBoot,[object[]]$Networks) {
 if([string]$VM.Id-ine'eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c'-or$VM.State-ne'Off'-or$VM.Generation-ne2-or$VM.MemoryStartup-ne$Memory-or$VM.DynamicMemoryEnabled-or[string]$VM.ParentSnapshotId-ine$Parent-or$SecureBoot-cne'On'-or@($Networks|Where-Object SwitchName).Count){throw 'Exact off-state branch/fixed memory/Secure Boot/disconnected network required.'}
}
function Assert-RetainedPreparationBaseline($Checkpoint) {
 if([string]$Checkpoint.Id-ine'eda059b3-6d50-46bb-bdf4-018b99b5b34f'-or$Checkpoint.Name-cne'installed-clean'-or[string]$Checkpoint.VMId-ine'eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c'-or$Checkpoint.State-ne'Off'){throw 'Exact off-state installed-clean checkpoint required.'}
}
function Assert-RetainedPreparationOutcome($Checkpoint,[string]$Name) {
 if($Checkpoint.Name-cne$Name-or[string]$Checkpoint.VMId-ine'eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c'-or$Checkpoint.State-ne'Off'-or$Checkpoint.MemoryStartup-ne8GB-or$Checkpoint.DynamicMemoryEnabled-or[guid]$Checkpoint.Id-eq[guid]::Empty){throw 'Prepared outcome must be an off8GiB checkpoint of the exact VM.'}
}
function Assert-RetainedPreparationArtifactSet([object[]]$Files,[string]$Stage) {
 if($Stage-cnotin@('source','shadow','pair')-or$Files.Count-lt1-or@($Files.name|Select-Object -Unique).Count-ne$Files.Count){throw 'Invalid artifact stage/count/duplicates.'}
 $maxCount=if($Stage-ceq'pair'){194}elseif($Stage-ceq'shadow'){9}else{3};$sum=0L;$binary=0L
 if($Files.Count-gt$maxCount){throw 'Excessive artifact count.'}
 foreach($f in $Files){$max=0L;$zero=$false
  if($Stage-ceq'source'){$max=switch -CaseSensitive($f.name){'prepare.json'{1MB}'target.json'{16KB}'started.json'{16KB}default{0}}}
  elseif($Stage-ceq'shadow'){$max=if($f.name-ceq'prepare.json'){1MB}elseif($f.name-cmatch'^(system|devdrive|volume|refs)\.(stdout|stderr)$'){64KB}else{0};$zero=$f.name-cmatch'\.(stdout|stderr)$'}
  else{$max=if($f.name-ceq'pair.json'){2MB}elseif($f.name-ceq'started.json'){16KB}elseif($f.name-cmatch'^query-[0-9]{3}\.bin$'){2MB}else{0};$zero=$f.name-cmatch'^query-[0-9]{3}\.bin$';if($zero){$binary+=$f.length}}
  if($max-eq0-or$f.length-lt0-or(-not$zero-and$f.length-eq0)-or$f.length-gt$max-or$f.sha256-cnotmatch'^[0-9a-f]{64}$'-or([IO.FileAttributes]$f.attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Artifact name/type/size/hash outside stage allowlist.'};$sum+=$f.length
 }
 $required=if($Stage-ceq'pair'){'pair.json'}else{'prepare.json'};if(@($Files|Where-Object name -CEQ $required).Count-ne1-or$binary-gt16MB-or$sum-gt19MB){throw 'Artifact aggregate coverage/bounds differ.'}
}
function Assert-RetainedPreparationResponse($Reply,[string]$Stage,[string]$RunId,[string]$ObservationId) {
 $root=switch($Stage){source{'C:\ntfs2refs\retained-source\'+$RunId}shadow{'C:\ntfs2refs\shadow-platform\'+$RunId}pair{'C:\ntfs2refs\retained-pair\'+$RunId+'\'+$ObservationId}default{throw 'Unknown stage.'}}
 if($Reply.RunId-cne$RunId-or$Reply.EvidenceDirectory-cne$root-or$Reply.OperationCompletionKnown-isnot[bool]-or$Reply.ConversionQualified-isnot[bool]-or$Reply.ConversionQualified-ne$false){throw 'Guest response identity/operation state differs.'}
 if($Stage-ceq'pair'-and($Reply.Phase-cne'Construct'-or$Reply.ObservationId-cne$ObservationId)){throw 'Pair response identity differs.'}
}
function Write-RetainedPreparationJson([string]$Path,$Value,[long]$Maximum=2MB) {
 $bytes=(New-Object Text.UTF8Encoding($false,$true)).GetBytes(($Value|ConvertTo-Json -Depth 32));if($bytes.Length-gt$Maximum){throw 'Host evidence exceeds declared bound.'}
 $s=New-Object IO.FileStream($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$s.Write($bytes,0,$bytes.Length);$s.Flush($true)}finally{$s.Dispose()}
}
function Save-RetainedPreparationProgress {
 $record.updatedUtc=[DateTime]::UtcNow.ToString('o');$name='progress-'+$script:progressIndex.ToString('D3')+'.json';$script:progressIndex++;Write-RetainedPreparationJson (Join-Path $outputRoot $name) $record
}
function Set-RetainedPreparationGuestCompletion($Reply) {
 # Transport success does not mean an asynchronous guest operation completed.
 # Keep this state independent of later read-only exports.
 if($Reply.OperationCompletionKnown-isnot[bool]){throw 'Guest completion is not an explicit boolean.'}
 $script:guestOperationIndeterminate=-not$Reply.OperationCompletionKnown
}
function Read-RetainedPreparationJson([string]$Path,[long]$Maximum=2MB) {
 $i=Get-Item -LiteralPath $Path -Force;if($i.PSIsContainer-or($i.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$i.Length-lt1-or$i.Length-gt$Maximum){throw 'Bounded ordinary JSON required.'};[IO.File]::ReadAllText($i.FullName,(New-Object Text.UTF8Encoding($false,$true)))|ConvertFrom-Json
}
function Invoke-RetainedPreparationCommand([scriptblock]$Body,[object[]]$Arguments=@(),[int]$Timeout=60) {
 $script:commandIndeterminate=$true;$job=$null
 try{$job=Invoke-Command -Session $session -AsJob -ArgumentList $Arguments -ScriptBlock $Body;if(-not(Wait-Job -Job $job -Timeout $Timeout)){throw 'Guest command exceeded deadline; preserve active branch.'};$answer=@(Receive-Job -Job $job -ErrorAction Stop);if($job.State-ne'Completed'){throw 'Guest command completion unknown; preserve branch.'};$script:commandIndeterminate=$false;$answer}
 finally{if($job-and$job.State-in@('Completed','Failed','Stopped')){Remove-Job -Job $job -Force}}
}
function Open-RetainedPreparationSession {
 $deadline=[DateTime]::UtcNow.AddSeconds($BootTimeoutSeconds)
 while([DateTime]::UtcNow-lt$deadline){$job=$null;try{$job=Invoke-Command -VMId ([guid]$manifest.vmId) -Credential $credential -AsJob -ScriptBlock{$env:COMPUTERNAME};if(Wait-Job -Job $job -Timeout 10){$reply=@(Receive-Job -Job $job -ErrorAction Stop);if($reply.Count-eq1-and$reply[0]-ceq'N2R-WIN11'){return New-PSSession -VMId ([guid]$manifest.vmId) -Credential $credential -ErrorAction Stop}}}catch{}finally{if($job-and$job.State-in@('Completed','Failed','Stopped')){Remove-Job -Job $job -Force}};Start-Sleep -Seconds 2}
 throw 'Guest boot/session deadline exceeded; preserve branch.'
}
function Assert-RetainedPreparationCurrent([string]$Parent,[long]$Memory) {
 $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest;Assert-RetainedPreparationVM $vm $Parent $Memory ([string](Get-VMFirmware -VM $vm).SecureBoot) @(Get-VMNetworkAdapter -VM $vm);$vm
}
function Export-RetainedPreparationStage([string]$GuestRoot,[string]$Stage) {
 $files=@(Invoke-RetainedPreparationCommand -Arguments @($GuestRoot) -Body {param($Root)
  $dir=Get-Item -LiteralPath $Root -Force;if(-not$dir.PSIsContainer-or($dir.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary guest evidence directory required.'}
  $files=@(Get-ChildItem -LiteralPath $Root -Force);if($files.Count-gt194){throw 'Excessive guest evidence count.'}
  foreach($f in $files){if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-gt2MB){throw 'Unexpected evidence type/bounds.'};[pscustomobject]@{name=$f.Name;length=$f.Length;attributes=[string]$f.Attributes;sha256=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}}
 })
 Assert-RetainedPreparationArtifactSet $files $Stage
 $dir=Assert-LabPath (Join-Path $outputRoot $Stage) $configuration.Root;New-Item -ItemType Directory -Path $dir|Out-Null
 foreach($f in $files){$dest=Join-Path $dir $f.name;Copy-Item -LiteralPath ($GuestRoot+'\'+$f.name) -Destination $dest -FromSession $session;$item=Get-Item -LiteralPath $dest -Force;if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-ne$f.length-or(Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash.ToLowerInvariant()-cne$f.sha256){throw 'Exported evidence hash/type/length differs.'}}
 $after=@(Invoke-RetainedPreparationCommand -Arguments @($GuestRoot) -Body {param($Root);foreach($f in @(Get-ChildItem -LiteralPath $Root -Force)){if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-gt2MB){throw 'Evidence changed type/bound.'};[pscustomobject]@{name=$f.Name;length=$f.Length;attributes=[string]$f.Attributes;sha256=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}}})
 Assert-RetainedPreparationArtifactSet $after $Stage;if($after.Count-ne$files.Count){throw 'Guest evidence changed during copy.'};foreach($f in $files){$a=@($after|Where-Object name -CEQ $f.name);if($a.Count-ne1-or$a[0].length-ne$f.length-or$a[0].sha256-cne$f.sha256){throw 'Guest evidence changed during export.'}}
 Write-RetainedPreparationJson (Join-Path $dir 'exported-files.json') @($files) 256KB
 $name=if($Stage-ceq'pair'){'pair.json'}else{'prepare.json'}
 [pscustomobject]@{directory=$dir;files=$files;record=(Read-RetainedPreparationJson (Join-Path $dir $name));sha256=($files|Where-Object name -CEQ $name).sha256}
}
function Assert-RetainedPreparationDecoded($Actual,$Expected,[string]$Name) {
 if((ConvertTo-Json -InputObject $Actual -Depth 16 -Compress)-cne(ConvertTo-Json -InputObject $Expected -Depth 16 -Compress)){throw ('Decoded native evidence differs: '+$Name)}
}
function Get-RetainedPreparationQueryBytes($Pair,[string]$Name,[string]$Directory) {
 $q=@($Pair.native.queries|Where-Object name -CEQ $Name);if($q.Count-ne1){throw ('Expected unique native query '+$Name)}
 ,[IO.File]::ReadAllBytes((Join-Path $Directory $q[0].artifact))
}
function Assert-RetainedPreparationPair($Pair,$Source,$Shadow,[object[]]$Files,[string]$Directory,[string]$RunId,[string]$ObservationId,[string]$SourceSha,[string]$ShadowSha,$SourceHashes) {
 Assert-RetainedConstruction $Pair $RunId $ObservationId $SourceSha $ShadowSha
 Assert-RetainedPlatforms $Source $Shadow $RunId
 $intent=Read-RetainedPreparationJson (Join-Path $Directory 'started.json') 16KB
 if($intent.schemaVersion-ne1-or$intent.kind-cne'retained-pair-operation-intent'-or$intent.runId-cne$RunId-or$intent.observationId-cne$ObservationId-or$intent.phase-cne'Construct'-or$intent.targetMutationMayFollow-ne$true-or$intent.sourceEvidenceSha256-cne$SourceSha-or$intent.shadowEvidenceSha256-cne$ShadowSha){throw 'Durable pair intent differs from completed construction.'}
 if($Pair.sourceInitializationEvidenceBound-ne$true-or$Pair.physicalMappingVerified-ne$false-or$Pair.native.physicalMappingVerified-ne$false-or$Pair.native.conversionQualified-ne$false){throw 'Pair claims missing or unperformed qualification.'}
 if($Pair.scriptSha256-cne($SourceHashes|Where-Object name -CEQ 'Invoke-GuestRetainedPair.ps1').sha256){throw 'Pair wrapper source pin differs.'}
 if(@($Pair.nativeSources).Count-ne2){throw 'Native source evidence incomplete.'};foreach($s in $Pair.nativeSources){$expected=@($SourceHashes|Where-Object name -CEQ $s.name);if($expected.Count-ne1-or$s.name-cnotin@('NativeRetainedFixture.cs','NativeRetainedFixture.Windows.cs')-or$s.sha256-cne$expected[0].sha256-or$s.length-ne$expected[0].length){throw 'Native source pin differs.'}}
 $queries=@($Pair.native.queries);$artifacts=@($Pair.artifacts);if($queries.Count-lt1-or$queries.Count-gt192-or$artifacts.Count-ne$queries.Count-or$Files.Count-ne$queries.Count+2){throw 'Pair query/export coverage differs.'}
 for($i=0;$i-lt$queries.Count;$i++){
  $q=$queries[$i];$name='query-'+$i.ToString('D3')+'.bin';$file=@($Files|Where-Object name -CEQ $name);$a=@($artifacts|Where-Object name -CEQ $name)
  if($q.artifact-cne$name-or$file.Count-ne1-or$a.Count-ne1-or$q.sha256-cne$file[0].sha256-or$a[0].sha256-cne$file[0].sha256-or$q.bytesReturned-ne$file[0].length-or$a[0].length-ne$file[0].length-or$a[0].query-cne$q.name-or$null-ne$q.bytes){throw 'Native query status/artifact binding differs.'}
  Assert-RetainedQueryOutcome $q $true
  $cap=-1;$requestBytesBytes=0
  if($q.api-ceq'GetFileInformationByHandleEx'){$cap=switch([int]$q.code){0{40}1{24}7{4096}9{8}10{4096}11{4096}18{24}default{-1}}}
  elseif($q.api-ceq'GetSecurityInfo'){if($q.code-eq31){$cap=16384}}
  elseif($q.api-ceq'DeviceIoControl'){
   switch([int]$q.code){0x560000{$cap=32}0x90234{$cap=8}0x90073{$cap=272;$requestBytesBytes=8}0x90284{$cap=400;$requestBytesBytes=24}0x9027c{$cap=16}0x9c280{$cap=0;$requestBytesBytes=8}0x9006f{$cap=2MB;$requestBytesBytes=if($q.inputHex.Length-eq32){16}else{8}}0x90074{$cap=0;$requestBytesBytes=32}}
  }
  if($cap-lt0-or$q.capacity-ne$cap-or$q.bytesReturned-gt$cap-or$q.inputHex-cnotmatch('^[0-9a-f]{'+($requestBytesBytes*2)+'}$')){throw 'Native API/code/input/output bounds differ.'}
 }
 foreach($ns in $Pair.native.namespaces){
  $entries=@(foreach($queryName in $ns.queryNames){$query=@($queries|Where-Object name -CEQ $queryName);if($query.Count-ne1){throw 'Namespace query is not unique.'};if($query[0].succeeded){[Ntfs2Refs.NativeRetainedFixture]::ParseDirectory((Get-RetainedPreparationQueryBytes $Pair $queryName $Directory))}})
  Assert-RetainedPreparationDecoded $ns.entries $entries 'directory namespace'
 }
 $candidate=[long]$Pair.native.candidateLcn
 if($candidate-lt2097152-or$candidate-ge2359296-or$candidate%16-ne0){throw 'Candidate outside bounded construction window.'}
 foreach($role in @('source','shadow')){
  $f=$Pair.native.$role;$letter=if($role-ceq'source'){'A'}else{'B'}
  $expectedVolume=if($role-ceq'source'){$Source.volume.guid}else{$Shadow.shadow.volumeGuid};$expectedFs=if($role-ceq'source'){'NTFS'}else{'ReFS'}
  if($f.role-cne$letter-or$f.volume-cne$expectedVolume-or$f.filesystem-cne$expectedFs){throw 'Native volume/role binding differs from prepared platform.'}
  $pattern=[Ntfs2Refs.NativeRetainedFixture]::Hash([Ntfs2Refs.NativeRetainedFixture]::Pattern($RunId,$letter))
  if($f.expectedSha256-cne$pattern-or$f.root-cne$(if($role-ceq'source'){'F:\'}else{'S:\'})-or$f.path-cne($f.root+'retained\payload.bin')){throw 'Fixture pattern/path differs.'}
  foreach($phase in @('before','after')){
   $s=$f.$phase;$prefix=$letter+$(if($phase-ceq'before'){'Before'}else{'After'})
   if($s.sha256-cne$pattern-or$s.fullyCachedValid-ne$true){throw 'Native logical hash/cache proof differs.'}
   foreach($item in @(@('Basic','basic'),@('Standard','standard'),@('Id','identity'),@('Security','security'),@('Extents','extents'),@('Cached','cached'))){
    $bytes=Get-RetainedPreparationQueryBytes $Pair ($prefix+$item[0]) $Directory
    $decoded=switch($item[0]){'Basic'{[Ntfs2Refs.NativeRetainedFixture]::ParseBasic($bytes,$false)}'Standard'{[Ntfs2Refs.NativeRetainedFixture]::ParseStandard($bytes,$false)}'Id'{[Ntfs2Refs.NativeRetainedFixture]::ParseIdentity($bytes)}'Security'{[Ntfs2Refs.NativeRetainedFixture]::ParseSecurity($bytes,[string]$s.security.owner,$false)}'Extents'{,[Ntfs2Refs.NativeRetainedFixture]::ParseExtents($bytes)}'Cached'{,[Ntfs2Refs.NativeRetainedFixture]::ParseValidRegions($bytes,1)}}
    Assert-RetainedPreparationDecoded $decoded $s.($item[1]) ($prefix+$item[0])
   }
   $streams=[Ntfs2Refs.NativeRetainedFixture]::ParseStreams((Get-RetainedPreparationQueryBytes $Pair ($prefix+'Streams') $Directory));if(@($s.streams).Count-ne1-or$s.streams[0]-cne$streams[0]){throw 'Stream inventory differs.'}
   $base=[Ntfs2Refs.NativeRetainedFixture]::ParseBase((Get-RetainedPreparationQueryBytes $Pair ($prefix+'Base') $Directory));if($base-ne0-or$s.baseSectors-ne0){throw 'Observed retrieval base differs.'}
   if($role-ceq'shadow'){
    $regions=[Ntfs2Refs.NativeRetainedFixture]::ParseValidRegions((Get-RetainedPreparationQueryBytes $Pair ($prefix+'OnDisk') $Directory),2);Assert-RetainedPreparationDecoded $regions $s.onDisk ($prefix+'OnDisk')
    $integrity=Get-RetainedPreparationQueryBytes $Pair ($prefix+'Integrity') $Directory
    if($s.fullyStorageValid-ne$true-or$s.storageRegionQueryAttempted-ne$true-or$s.checksumAlgorithm-ne0-or$s.integrityFlags-ne0-or$integrity.Length-ne16-or[BitConverter]::ToUInt16($integrity,0)-ne0-or[BitConverter]::ToUInt32($integrity,4)-ne0-or[BitConverter]::ToUInt32($integrity,12)-ne4096){throw 'Shadow validity/integrity NONE proof differs.'}
   }elseif($s.fullyStorageValid-ne$false-or$s.storageRegionQueryAttempted-ne$false-or$null-ne$s.onDisk-or$s.storageValidityStatus-cne'not-queried-NTFS-storage-validity-unknown'){throw 'NTFS storage claim must remain unknown.'}
  }
  if(@($f.after.extents).Count-ne1-or$f.after.extents[0].lcn-ne$candidate-or$f.after.partitionOffset-ne($candidate*4096)){throw 'Final single extent does not occupy retained interval.'}
  [Ntfs2Refs.NativeRetainedFixture]::CheckNotMapped($candidate,([Ntfs2Refs.NativeRetainedFixture]::ParseExtents((Get-RetainedPreparationQueryBytes $Pair ($letter+'BeforeExtents') $Directory))))
  $move=@($queries|Where-Object name -CEQ ($letter+'Move'));if($move.Count-ne1-or$move[0].code-ne0x90074){throw 'Exact single move missing.'}
  $requestBytes=[byte[]]@(for($i=0;$i-lt32;$i++){[Convert]::ToByte($move[0].inputHex.Substring($i*2,2),16)})
  if([BitConverter]::ToInt64($requestBytes,0)-le0-or[BitConverter]::ToInt64($requestBytes,8)-ne0-or[BitConverter]::ToInt64($requestBytes,16)-ne$candidate-or[BitConverter]::ToUInt32($requestBytes,24)-ne16-or[BitConverter]::ToUInt32($requestBytes,28)-ne0){throw 'Exact move input differs.'}
 }
 $selected=[Ntfs2Refs.NativeRetainedFixture]::SelectCandidate((Get-RetainedPreparationQueryBytes $Pair 'ntfsCandidate' $Directory),(Get-RetainedPreparationQueryBytes $Pair 'refsCandidate' $Directory),(Get-RetainedPreparationQueryBytes $Pair 'refsMetadataCandidate' $Directory))
 if($selected-ne$candidate){throw 'Candidate selection is not derived from exported maps.'}
 foreach($name in @('AFreshBitmap','BFreshBitmap','BFreshMetadataBitmap')){if(-not[Ntfs2Refs.NativeRetainedFixture]::IsFree((Get-RetainedPreparationQueryBytes $Pair $name $Directory),$candidate)){throw 'Fresh bitmap did not report candidate free.'}}
 if(@($queries|Where-Object code -EQ 0x90074).Count-ne2-or@($queries|Where-Object code -EQ 0x9c280).Count-ne1){throw 'Construction mutation count differs.'}
}

if(-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated Hyper-V access required.'}
if([string]::IsNullOrWhiteSpace($ReviewedSourcesPath)-or[string]::IsNullOrWhiteSpace($ReviewedSourcesSha256)){throw 'Supply independently reviewed source manifest path and its exact SHA-256.'}
$reviewPath=Assert-LabPath $ReviewedSourcesPath $configuration.Root
if((Get-FileHash -LiteralPath $reviewPath -Algorithm SHA256).Hash.ToLowerInvariant()-cne$ReviewedSourcesSha256){throw 'Reviewed manifest hash differs.'}
$review=Read-RetainedPreparationJson $reviewPath 64KB;Assert-RetainedPreparationReviewed $review
$manifest=Read-LabManifest -Configuration $configuration -Lane win11;Assert-RetainedPreparationManifest $manifest
$baselineId='eda059b3-6d50-46bb-bdf4-018b99b5b34f'
$vm=Assert-RetainedPreparationCurrent $baselineId 4GB;Assert-RetainedPreparationBaseline (Get-ExactLabCheckpoint -VM $vm -Name installed-clean)
Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 12GB
$runId=[guid]::NewGuid().ToString('N');$observationId=[guid]::NewGuid().ToString('N')
$outputRoot=Assert-LabPath (Join-Path $configuration.Root ('retained-preparation\win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $configuration.Root
if(Test-Path -LiteralPath $outputRoot){throw 'Host evidence directory already exists.'};New-Item -ItemType Directory -Path $outputRoot|Out-Null
$archive=Join-Path $outputRoot 'reviewed-sources';New-Item -ItemType Directory -Path $archive|Out-Null
$sourceHashes=@(foreach($entry in $review.files){
 $path=Assert-LabPath (Join-Path $workspace $entry.path) $workspace;$f=Get-Item -LiteralPath $path -Force
 if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$f.Length-lt1-or$f.Length-gt256KB){throw 'Reviewed source type/size differs.'}
 $pin=New-Object IO.FileStream($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{$bytes=New-Object byte[] $pin.Length;$read=0;while($read-lt$bytes.Length){$n=$pin.Read($bytes,$read,$bytes.Length-$read);if($n-eq0){throw 'Short reviewed source read.'};$read+=$n};$hash=[Security.Cryptography.SHA256]::Create();try{$sha=([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()};if($sha-cne$entry.sha256){throw ('Reviewed source hash differs: '+$entry.path)};$name=[IO.Path]::GetFileName($path);$dest=Join-Path $archive $name;$out=New-Object IO.FileStream($dest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$out.Write($bytes,0,$bytes.Length);$out.Flush($true)}finally{$out.Dispose()};[pscustomobject]@{path=$entry.path;name=$name;length=$bytes.Length;sha256=$sha}}finally{$pin.Dispose()}
})
Write-RetainedPreparationJson (Join-Path $outputRoot 'reviewed-source-manifest.json') $review 64KB
# Load only named pure guard definitions from the reviewed archived guest scripts.
foreach($name in @('Prepare-GuestRetainedSource.ps1','Invoke-GuestRetainedPair.ps1')){$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $archive $name),[ref]$tokens,[ref]$errors);if($errors.Count){throw 'Reviewed script parse failure.'};foreach($fn in $ast.FindAll({param($node)$node-is[Management.Automation.Language.FunctionDefinitionAst]},$true)){. ([scriptblock]::Create($fn.Extent.Text))}}
if('Ntfs2Refs.NativeRetainedFixture'-as[type]){throw 'Use a fresh host PowerShell process for the reviewed native-buffer parsers.'}
Add-Type -Path @((Join-Path $archive 'NativeRetainedFixture.cs'),(Join-Path $archive 'NativeRetainedFixture.Windows.cs'))
$laneRoot=Assert-LabPath (Join-Path $configuration.Root 'win11') $configuration.Root
$credential=Import-Clixml -LiteralPath (Assert-LabPath (Join-Path $laneRoot 'secrets\guest-credential.xml') $configuration.Root)
if($credential-isnot[Management.Automation.PSCredential]-or$credential.UserName-cne'N2R-WIN11\LabAdmin'){throw 'Unexpected guest credential.'}
$record=[ordered]@{schemaVersion=1;kind='retained-preparation-host';runId=$runId;observationId=$observationId;status='started';phase='preflight';vmId=$manifest.vmId;baselineId=$baselineId;reviewedSourcesSha256=$ReviewedSourcesSha256;sourceHashes=$sourceHashes;sourceExported=$false;shadowExported=$false;pairExported=$false;guestMutationMayHaveBeenIssued=$false;cleanShutdown=$false;outcomeCheckpointCreated=$false;outcomeCheckpointId=$null;outcomeCheckpointName=$null;baselineRestored=$false;memoryRestored=$false;physicalMappingVerified=$false;cleanRemountVerified=$false;conversionQualified=$false;createdUtc=[DateTime]::UtcNow.ToString('o');updatedUtc=$null}
$session=$null;$script:commandIndeterminate=$false;$script:guestOperationIndeterminate=$false;$script:progressIndex=0
try {
 Save-RetainedPreparationProgress
 $vm=Assert-RetainedPreparationCurrent $baselineId 4GB;Assert-RetainedPreparationBaseline (Get-ExactLabCheckpoint -VM $vm -Name installed-clean)
 $record.phase='set-eight-gib';Save-RetainedPreparationProgress;Set-VMMemory -VM $vm -StartupBytes 8GB -DynamicMemoryEnabled $false
 Assert-RetainedPreparationCurrent $baselineId 8GB|Out-Null
 Invoke-LabAction -Action Start -Lane win11 -Confirm:$false|Out-Null;$session=Open-RetainedPreparationSession
 $policy=Initialize-LabGuestSession -Session $session;Write-RetainedPreparationJson (Join-Path $outputRoot 'session.json') $policy 64KB;if($policy.status-cne'ready'){throw 'Guest session initialization refused.'}
 $guestSources=@($sourceHashes|Where-Object path -CLike 'lab/guest/*');$names=@($guestSources.name)
 Invoke-RetainedPreparationCommand -Arguments @(,$names) -Body {param($Names);foreach($p in @('C:\ntfs2refs','C:\ntfs2refs\guest')){$f=Get-Item -LiteralPath $p -Force;if(-not$f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Ordinary owned guest helper directory required.'}};foreach($n in $Names){$p='C:\ntfs2refs\guest\'+$n;if(Test-Path -LiteralPath $p){$f=Get-Item -LiteralPath $p -Force;if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Guest helper destination changed.'}}}}|Out-Null
 foreach($f in $guestSources){Copy-Item -LiteralPath (Join-Path $archive $f.name) -Destination ('C:\ntfs2refs\guest\'+$f.name) -ToSession $session -Force}
 $copied=@(Invoke-RetainedPreparationCommand -Arguments @(,$names) -Body {param($Names);foreach($n in $Names){$f=Get-Item -LiteralPath ('C:\ntfs2refs\guest\'+$n) -Force;if($f.PSIsContainer-or($f.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Guest helper changed type.'};[pscustomobject]@{name=$n;length=$f.Length;sha256=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}}})
 if($copied.Count-ne$guestSources.Count){throw 'Guest helper copy incomplete.'};foreach($f in $guestSources){$c=@($copied|Where-Object name -CEQ $f.name);if($c.Count-ne1-or$c[0].length-ne$f.length-or$c[0].sha256-cne$f.sha256){throw 'Guest source hash differs from reviewed archive.'}}
 $record.phase='enroll-journal';Save-RetainedPreparationProgress;$journalPath='C:\ntfs2refs\retained-journal-'+$runId+'.json'
 $enrolled=@(Invoke-RetainedPreparationCommand -Arguments @($journalPath) -Body {param($Path);$r=& 'C:\ntfs2refs\guest\Register-GuestDisk.ps1' -UniqueId '600224806AAC261F021F249596F332FC' -Role journal -OutputPath $Path -Confirm:$false;[pscustomobject]@{path=$Path;identity=$r;sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}})
 if($enrolled.Count-ne1-or$enrolled[0].path-cne$journalPath-or$enrolled[0].identity.role-cne'journal'-or$enrolled[0].identity.uniqueId-cne'600224806AAC261F021F249596F332FC'-or$enrolled[0].identity.sizeBytes-ne8GB){throw 'Journal enrollment differs.'}
 $record['journalEnrollment']=$enrolled[0];Copy-Item -LiteralPath $journalPath -Destination (Join-Path $outputRoot 'journal.json') -FromSession $session
 if((Get-FileHash -LiteralPath (Join-Path $outputRoot 'journal.json') -Algorithm SHA256).Hash.ToLowerInvariant()-cne$enrolled[0].sha256){throw 'Journal enrollment export differs.'}
 $target=@($manifest.disks|Where-Object role -CEQ 'target')[0];$targetJson=$target|ConvertTo-Json -Compress
 $record.phase='prepare-ntfs-source';$record.guestMutationMayHaveBeenIssued=$true;Save-RetainedPreparationProgress
 $script:guestOperationIndeterminate=$true
 $replies=@(Invoke-RetainedPreparationCommand -Timeout $StageTimeoutSeconds -Arguments @($runId,$targetJson) -Body {param($Id,$Target);& 'C:\ntfs2refs\guest\Prepare-GuestRetainedSource.ps1' -RunId $Id -HostTargetJson $Target -Confirm:$false})
 if($replies.Count-ne1){throw 'Ambiguous source stage reply.'};Assert-RetainedPreparationResponse $replies[0] source $runId $observationId
 Set-RetainedPreparationGuestCompletion $replies[0]
 $source=Export-RetainedPreparationStage $replies[0].EvidenceDirectory source;$record.sourceExported=$true;$record['sourceEvidenceSha256']=$source.sha256
 if($replies[0].Status-cne'ntfs-source-prepared'-or$replies[0].OperationCompletionKnown-ne$true-or$source.record.status-cne'ntfs-source-prepared'-or$source.record.operationCompletionKnown-ne$true-or$source.record.scriptSha256-cne($sourceHashes|Where-Object name -CEQ 'Prepare-GuestRetainedSource.ps1').sha256-or@($source.files).Count-ne3){throw 'Source preparation did not complete with reviewed provenance.'}
 $sourceIntent=Read-RetainedPreparationJson (Join-Path $source.directory 'started.json') 16KB
 if($sourceIntent.schemaVersion-ne1-or$sourceIntent.kind-cne'retained-source-mutation-intent'-or$sourceIntent.runId-cne$runId-or$sourceIntent.targetMutationMayFollow-ne$true-or$sourceIntent.offset-ne16MB-or$sourceIntent.length-ne52GB-or$sourceIntent.filesystem-cne'NTFS'-or$sourceIntent.target.guest.uniqueId-cne'60022480D091C4251B5FFD619706C2B5'){throw 'Source mutation intent differs from prepared platform.'}
 $record.phase='prepare-independent-shadow';Save-RetainedPreparationProgress
 $script:guestOperationIndeterminate=$true
 $replies=@(Invoke-RetainedPreparationCommand -Timeout $StageTimeoutSeconds -Arguments @($runId,$journalPath) -Body {param($Id,$Journal);& 'C:\ntfs2refs\guest\Prepare-GuestShadowPlatform.ps1' -RunId $Id -JournalManifestPath $Journal -Confirm:$false})
 if($replies.Count-ne1){throw 'Ambiguous shadow stage reply.'};Assert-RetainedPreparationResponse $replies[0] shadow $runId $observationId
 Set-RetainedPreparationGuestCompletion $replies[0]
 $shadow=Export-RetainedPreparationStage $replies[0].EvidenceDirectory shadow;$record.shadowExported=$true;$record['shadowEvidenceSha256']=$shadow.sha256
 if($replies[0].Status-cne'shadow-platform-prepared'-or$replies[0].OperationCompletionKnown-ne$true-or$shadow.record.scriptSha256-cne($sourceHashes|Where-Object name -CEQ 'Prepare-GuestShadowPlatform.ps1').sha256-or$shadow.record.nativeSourceSha256-cne($sourceHashes|Where-Object name -CEQ 'NativeShadowDisk.cs').sha256-or$shadow.record.journalManifestSha256-cne$enrolled[0].sha256-or@($shadow.files).Count-ne9){throw 'Shadow preparation/provenance incomplete.'}
 Assert-RetainedPlatforms $source.record $shadow.record $runId
 if($shadow.record.privilegeRestored-ne$true){throw 'Shadow own-process privilege restoration incomplete.'}
 $record.phase='construct-retained-pair';Save-RetainedPreparationProgress
 $script:guestOperationIndeterminate=$true
 $replies=@(Invoke-RetainedPreparationCommand -Timeout $StageTimeoutSeconds -Arguments @($runId,$observationId,$source.sha256,$shadow.sha256) -Body {param($Id,$Observation,$SourceSha,$ShadowSha);& 'C:\ntfs2refs\guest\Invoke-GuestRetainedPair.ps1' -Phase Construct -RunId $Id -ObservationId $Observation -SourceEvidenceSha256 $SourceSha -ShadowEvidenceSha256 $ShadowSha -Confirm:$false})
 if($replies.Count-ne1){throw 'Ambiguous construction reply.'};Assert-RetainedPreparationResponse $replies[0] pair $runId $observationId
 Set-RetainedPreparationGuestCompletion $replies[0]
 $pair=Export-RetainedPreparationStage $replies[0].EvidenceDirectory pair;$record.pairExported=$true;$record['pairEvidenceSha256']=$pair.sha256
 if($replies[0].Status-cne'constructed-awaiting-raw-proof'-or$replies[0].OperationCompletionKnown-ne$true-or$replies[0].SourceFrozen-ne$true){throw 'Construction did not complete; preserve branch.'}
 Assert-RetainedPreparationPair $pair.record $source.record $shadow.record $pair.files $pair.directory $runId $observationId $source.sha256 $shadow.sha256 $sourceHashes
 $record['retainedInterval']=[pscustomobject]@{offset=$pair.record.native.source.after.partitionOffset;length=65536;sourceSha256=$pair.record.native.source.after.sha256;shadowSha256=$pair.record.native.shadow.after.sha256;candidateLcn=$pair.record.native.candidateLcn}
 $record.phase='clean-shutdown';Save-RetainedPreparationProgress
 Invoke-RetainedPreparationCommand -Timeout 30 -Body {& shutdown.exe /s /t 0;if($LASTEXITCODE-ne0){throw 'Guest clean shutdown request failed.'}}|Out-Null
 $deadline=[DateTime]::UtcNow.AddSeconds(180);do{$vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest;if($vm.State-eq'Off'){break};Start-Sleep -Seconds 2}while([DateTime]::UtcNow-lt$deadline)
 if($vm.State-ne'Off'){throw 'Guest did not shut down cleanly within deadline; preserve branch.'};$record.cleanShutdown=$true
 Remove-PSSession -Session $session;$session=$null;$vm=Assert-RetainedPreparationCurrent $baselineId 8GB
 Assert-LabCapacity (Get-LabCapacity $configuration);$record.phase='checkpoint-prepared-pair';Save-RetainedPreparationProgress
 $outcomeName='retained-prepared-'+$runId
 Invoke-LabAction -Action Checkpoint -Lane win11 -CheckpointName $outcomeName -Confirm:$false|Out-Null
 $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest;$outcome=Get-ExactLabCheckpoint -VM $vm -Name $outcomeName;Assert-RetainedPreparationOutcome $outcome $outcomeName
 Assert-RetainedPreparationCurrent ([string]$outcome.Id) 8GB|Out-Null
 $record.outcomeCheckpointCreated=$true;$record.outcomeCheckpointId=[string]$outcome.Id;$record.outcomeCheckpointName=$outcomeName
 Assert-RetainedPreparationBaseline (Get-ExactLabCheckpoint -VM $vm -Name installed-clean);$record.phase='restore-baseline';Save-RetainedPreparationProgress
 Invoke-LabAction -Action Restore -Lane win11 -CheckpointName installed-clean -Confirm:$false|Out-Null
 $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest;if($vm.State-ne'Off'-or[string]$vm.ParentSnapshotId-ine$baselineId){throw 'Baseline restoration identity/state differs.'}
 if($vm.MemoryStartup-ne4GB-or$vm.DynamicMemoryEnabled){Set-VMMemory -VM $vm -StartupBytes 4GB -DynamicMemoryEnabled $false}
 Assert-RetainedPreparationCurrent $baselineId 4GB|Out-Null;$record.baselineRestored=$true;$record.memoryRestored=$true;$record.status='retained-pair-prepared-awaiting-raw-proof';$record.phase='complete'
}catch{$record.status='failed-preserved';$record['error']=$_.Exception.ToString();$record['errorPosition']=$_.InvocationInfo.PositionMessage;throw}
finally{$record['commandCompletionUnknown']=$script:commandIndeterminate;$record['guestOperationCompletionUnknown']=$script:guestOperationIndeterminate;$record['finishedUtc']=[DateTime]::UtcNow.ToString('o');Write-RetainedPreparationJson (Join-Path $outputRoot 'host-result.json') $record;if($session-and-not$script:commandIndeterminate-and-not$script:guestOperationIndeterminate){Remove-PSSession -Session $session -ErrorAction SilentlyContinue};$credential=$null}
[pscustomobject]@{Status=$record.status;RunId=$runId;ObservationId=$observationId;EvidenceDirectory=$outputRoot;OutcomeCheckpointId=$record.outcomeCheckpointId;BaselineRestored=$record.baselineRestored;MemoryRestored=$record.memoryRestored;PhysicalMappingVerified=$false;ConversionQualified=$false}
