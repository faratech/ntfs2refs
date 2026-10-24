<# Verify only an already mounted, physically read-only converted target. #>
[CmdletBinding(SupportsShouldProcess)]param(
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$RunId,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$ObservationId,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$InputSha256
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
function Assert-ConvertedBool($Value,[bool]$Expected){if($Value-isnot[bool]-or$Value-ne$Expected){throw 'Explicit verification boolean required.'}}
function Assert-ConvertedOrdinary([string]$Path,[bool]$Directory){$item=Get-Item -LiteralPath $Path -Force;if([bool]$item.PSIsContainer-ne$Directory-or($item.Attributes-band([IO.FileAttributes]::ReparsePoint-bor[IO.FileAttributes]::Compressed-bor[IO.FileAttributes]::Encrypted))){throw 'Ordinary evidence path required.'};$item}
function Read-ConvertedPinned([string]$Path,[string]$Hash,[long]$Maximum,[switch]$Text){
 if($Hash-cnotmatch'\A[0-9a-f]{64}\z'-or$Maximum-lt1-or$Maximum-gt16MB){throw 'Pinned input bound/hash invalid.'}
 $p=[IO.Path]::GetDirectoryName($Path);while($p){Assert-ConvertedOrdinary $p $true|Out-Null;$next=[IO.Path]::GetDirectoryName($p);if($next-eq$p){break};$p=$next}
 $item=Assert-ConvertedOrdinary $Path $false;if($item.Length-lt1-or$item.Length-gt$Maximum){throw 'Pinned evidence size differs.'}
 $stream=New-Object IO.FileStream($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$script:convertedPins.Add($stream)
 if($stream.Length-ne$item.Length){throw 'Pinned evidence length changed.'};$sha=[Security.Cryptography.SHA256]::Create();try{$actual=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};if($actual-cne$Hash){throw 'Pinned evidence SHA differs.'}
 $stream.Position=0;$reader=New-Object IO.StreamReader($stream,(New-Object Text.UTF8Encoding($false,$true)),$true,4096,$true);try{$value=$reader.ReadToEnd()}finally{$reader.Dispose()};if($Text){return $value};$value|ConvertFrom-Json
}
function Write-ConvertedArtifact([string]$Path,[byte[]]$Bytes,[long]$Maximum){if($Bytes.Length-gt$Maximum){throw 'Verification artifact exceeds bound.'};$s=New-Object IO.FileStream($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$s.Write($Bytes,0,$Bytes.Length);$s.Flush($true)}finally{$s.Dispose()}}
function Assert-ConvertedInput($InputRecord,[string]$Run,[string]$Observation){
 if($InputRecord.schemaVersion-ne1-or$InputRecord.kind-cne'converted-retained-verification-input'-or$InputRecord.runId-cne$Run-or$InputRecord.observationId-cne$Observation){throw 'Verification input identity differs.'}
 foreach($name in @('constructionId','inspectionId','mountId','preparePhaseId','applyPhaseId','handoffPhaseId')){if($InputRecord.$name-isnot[string]-or$InputRecord.$name-cnotmatch'\A[0-9a-f]{32}\z'){throw 'Exact predecessor identifiers required.'}}
 if(@($InputRecord.preparePhaseId,$InputRecord.applyPhaseId,$InputRecord.handoffPhaseId|Select-Object -Unique).Count-ne3-or$InputRecord.constructionId-ceq$InputRecord.inspectionId){throw 'Predecessor phases must be distinct.'}
 $base='C:\ntfs2refs\native-reconstruct\'+$Run
 $paths=@{source=('C:\ntfs2refs\retained-source\'+$Run+'\prepare.json');shadow=('C:\ntfs2refs\shadow-platform\'+$Run+'\prepare.json');construction=('C:\ntfs2refs\retained-pair\'+$Run+'\'+$InputRecord.constructionId+'\pair.json');inspection=('C:\ntfs2refs\retained-pair\'+$Run+'\'+$InputRecord.inspectionId+'\pair.json');mount=('C:\ntfs2refs\converted-mount\'+$Run+'\'+$InputRecord.mountId+'\mount.json');request=($base+'\'+$InputRecord.applyPhaseId+'\request.json');ticket=($base+'\ticket.json');prepare=($base+'\'+$InputRecord.preparePhaseId+'\result.json');apply=($base+'\'+$InputRecord.applyPhaseId+'\result.json');handoff=($base+'\'+$InputRecord.handoffPhaseId+'\result.json')}
 if(@($InputRecord.evidence).Count-ne10){throw 'Exact predecessor evidence set required.'};$seen=@{}
 foreach($e in $InputRecord.evidence){if($e.role-isnot[string]-or-not$paths.ContainsKey($e.role)-or$seen.ContainsKey($e.role)-or$e.path-cne$paths[$e.role]-or$e.sha256-isnot[string]-or$e.sha256-cnotmatch'\A[0-9a-f]{64}\z'){throw 'Evidence role/path/hash differs.'};$seen[$e.role]=$true}
 $wanted=@('NativeRetainedFixture.cs','NativeRetainedFixture.Windows.cs','NativeConvertedVerification.cs','NativeConvertedVerification.Windows.cs','Invoke-GuestRetainedPair.ps1','Invoke-GuestReadOnlyMount.ps1','Invoke-GuestConvertedVerification.ps1');$seen=@{}
 if(@($InputRecord.sources).Count-ne$wanted.Count){throw 'Exact reviewed source set required.'};foreach($s in $InputRecord.sources){if($s.name-cnotin$wanted-or$seen.ContainsKey($s.name)-or$s.sha256-isnot[string]-or$s.sha256-cnotmatch'\A[0-9a-f]{64}\z'){throw 'Reviewed source name/hash differs.'};$seen[$s.name]=$true}
}
function Import-ConvertedPure([string]$Text,[string[]]$Names){$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($Text,[ref]$tokens,[ref]$errors);if($errors.Count){throw 'Pinned guard source does not parse.'};foreach($name in $Names){$found=@($ast.FindAll({param($node)$node-is[Management.Automation.Language.FunctionDefinitionAst]-and$node.Name-ceq$name},$true));if($found.Count-ne1){throw 'Named pure guard missing or duplicated.'};$definition=[regex]::Replace($found[0].Extent.Text,('\Afunction\s+'+[regex]::Escape($name)),('function script:'+$name));. ([scriptblock]::Create($definition))}}
function Get-ConvertedPin($Spec,[string]$Role){@($Spec.evidence|Where-Object role -CEQ $Role)[0].sha256}
function Get-ConvertedSourcePin($Spec,[string]$Name){@($Spec.sources|Where-Object name -CEQ $Name)[0].sha256}
function Assert-ConvertedEvidence($Spec,$Evidence){
 $s=$Evidence.source;$b=$Evidence.shadow;$c=$Evidence.construction;$i=$Evidence.inspection;$m=$Evidence.mount;$r=$Evidence.request;$t=$Evidence.ticket;$p=$Evidence.prepare;$a=$Evidence.apply;$h=$Evidence.handoff;$run=$Spec.runId
 Assert-RetainedPlatforms $s $b $run;Assert-RetainedConstruction $c $run $Spec.constructionId (Get-ConvertedPin $Spec source) (Get-ConvertedPin $Spec shadow)
 if($i.schemaVersion-ne1-or$i.kind-cne'retained-fixture-pair'-or$i.phase-cne'Inspect'-or$i.runId-cne$run-or$i.observationId-cne$Spec.inspectionId-or$i.status-cne'pair-observed'-or$i.sourceEvidenceSha256-cne(Get-ConvertedPin $Spec source)-or$i.shadowEvidenceSha256-cne(Get-ConvertedPin $Spec shadow)-or$i.constructionEvidenceSha256-cne(Get-ConvertedPin $Spec construction)){throw 'Exact completed inspection required.'}
 foreach($name in @('nativeOperationCompletionKnown','sourceInitializationEvidenceBound')){Assert-ConvertedBool $i.$name $true};Assert-ConvertedBool $i.conversionQualified $false
 if($i.native.status-cne'pair-observed'){throw 'Native inspection incomplete.'};foreach($name in @('cleanupComplete','privilegeRestored','pairSemanticsMatch')){Assert-ConvertedBool $i.native.$name $true};Assert-RetainedInspection $c.native $i.native
 foreach($pair in @($c,$i)){if($pair.scriptSha256-cne(Get-ConvertedSourcePin $Spec 'Invoke-GuestRetainedPair.ps1')-or@($pair.nativeSources).Count-ne2){throw 'Pair implementation pin differs.'};foreach($name in @('NativeRetainedFixture.cs','NativeRetainedFixture.Windows.cs')){$row=@($pair.nativeSources|Where-Object name -CEQ $name);if($row.Count-ne1-or$row[0].sha256-cne(Get-ConvertedSourcePin $Spec $name)){throw 'Pair native parser pin differs.'}}}
 if($m.schemaVersion-ne1-or$m.kind-cne'converted-retained-mount-boundary'-or$m.runId-cne$run-or$m.observationId-cne$Spec.mountId-or$m.status-cne'converted-target-online-read-only'){throw 'Completed mount boundary required.'}
 foreach($name in @('operationCompletionKnown','cleanupComplete','shadowDetached','targetOnlineReadOnly')){Assert-ConvertedBool $m.$name $true};foreach($name in @('writableMountRequested','rawPayloadWriteRequestsIssued','filePayloadWriteRequestsIssued','convertedFileVerificationPerformed','conversionQualified','bootQualified')){Assert-ConvertedBool $m.$name $false}
 foreach($mapping in @(@('shadowPreparationSha256','shadow'),@('requestSha256','request'),@('ticketSha256','ticket'),@('applyResultSha256','apply'),@('handoffResultSha256','handoff'))){if($m.pins.($mapping[0])-cne(Get-ConvertedPin $Spec $mapping[1])){throw 'Mount predecessor pin differs.'}}
 if($m.pins.applyPhaseId-cne$Spec.applyPhaseId-or$m.pins.handoffPhaseId-cne$Spec.handoffPhaseId-or$m.pins.scriptSha256-cne(Get-ConvertedSourcePin $Spec 'Invoke-GuestReadOnlyMount.ps1')){throw 'Mount phase/implementation differs.'}
 Assert-MountInputs $b $r $t $run $m.pins.shadowNativeSourceSha256;Assert-MountSame $r $m.request;Assert-MountSame $r.probe.target $m.expectedTarget;Assert-MountSame $b.shadow $m.expectedShadow
 $base='C:\ntfs2refs\native-reconstruct\'+$run;Assert-MountCli $a $r $t apply (Get-ConvertedPin $Spec request) (Get-ConvertedPin $Spec ticket) ($base+'\'+$Spec.applyPhaseId);Assert-MountCli $h $r $t handoff (Get-ConvertedPin $Spec request) (Get-ConvertedPin $Spec ticket) ($base+'\'+$Spec.handoffPhaseId);Assert-MountSame $a.native.plan $h.native.plan
 if($m.expectedPostimageSha256-cne$a.native.plan.expected_postimage_sha256-or$p.schema_version-ne1-or$p.kind-cne'native-reconstruction-cli-result'-or$p.operation-cne'prepare'-or$p.phase-cne'complete-disks-remain-offline'-or$p.request_sha256-cne(Get-ConvertedPin $Spec request)-or$p.ticket_sha256-cne(Get-ConvertedPin $Spec ticket)-or$null-ne$p.error){throw 'Durable preparation/postimage pin differs.'}
 foreach($name in @('success','ticket_persisted')){Assert-ConvertedBool $p.$name $true};Assert-MountSame $r $p.native.request;Assert-MountSame $t $p.native.preparation.ticket;Assert-ConvertedBool $p.native.preparation.preparation_durable $true
 if($p.native.schema_version-ne1-or$p.native.kind-cne'native-lab-journal-reconstruction'-or$p.native.operation-cne'prepare'-or$p.native.phase-cne'complete-disks-remain-offline'-or$null-ne$p.native.error){throw 'Native durable preparation incomplete.'}
 foreach($name in @('success','disks_observed_offline_at_end')){Assert-ConvertedBool $p.native.$name $true};foreach($name in @('online_transition_requested','conversion_qualified','boot_qualified','payload_write_requests_issued')){Assert-ConvertedBool $p.native.$name $false}
 Assert-MountSame $t.binding $p.native.observed_binding
 if($p.native.preparation.changed_bytes-ne$a.native.plan.changed_bytes-or$p.native.preparation.patch_count-ne$a.native.plan.patch_count-or$p.native.counters.target_bytes_written-ne0-or$p.native.counters.target_write_bytes_requested-ne0-or$p.native.counters.shadow_bytes_written-ne0-or$p.native.counters.shadow_write_bytes_requested-ne0){throw 'Preparation journal plan/write accounting differs.'}
 if($p.native.preparation.expected_postimage_sha256-cne$m.expectedPostimageSha256-or$r.probe.fixture_evidence_sha256-cne(Get-ConvertedPin $Spec inspection)-or$r.probe.retained_offset-ne$i.native.source.after.partitionOffset-or$r.probe.source_retained_sha256-cne$i.native.source.after.sha256-or$r.probe.shadow_retained_sha256-cne$i.native.shadow.after.sha256){throw 'Frozen native fixture/raw reconstruction binding differs.'}
 if([guid]$s.partition.diskGuid-ne[guid]$r.probe.target.identity.disk_guid-or[guid]$s.partition.guid-ne[guid]$r.probe.target.identity.partition_guid){throw 'Original target GPT differs.'}
 Assert-MountInventory @($m.finalDisks) $b $false 2 $r
}
function Assert-ConvertedLive($Disks,$Part,$Volume,$Evidence){
 Assert-MountInventory @($Disks) $Evidence.shadow $false 2 $Evidence.request
 if($Part.DiskNumber-ne1-or$Part.PartitionNumber-ne2-or$Part.Offset-ne16MB-or$Part.Size-ne52GB-or$Part.IsBoot-or$Part.IsSystem-or[guid]$Part.Guid-ne[guid]$Evidence.source.partition.guid-or[guid]$Part.GptType-ne[guid]'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7'){throw 'Fresh target partition identity differs.'}
 if($Volume.FileSystem-cne'ReFS'-or$Volume.FileSystemLabel-cne'n2r-retained-shadow'-or$Volume.AllocationUnitSize-ne4096-or$Volume.Path-isnot[string]-or$Volume.Path-cnotmatch'\A\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\\z'){throw 'Fresh protected ReFS discovery differs.'};if([guid]$Volume.Path.Substring(11,36)-eq[guid]::Empty){throw 'Empty fresh volume identity.'}
}
function New-ConvertedExpected($Spec,$Evidence,[string]$FreshVolume){
 $e=New-Object Ntfs2Refs.ConvertedExpected;$i=$Evidence.inspection.native;$e.runId=$Spec.runId;$e.diskGuid=$Evidence.source.partition.diskGuid;$e.partitionGuid=$Evidence.source.partition.guid;$e.volumeGuid=$FreshVolume
 $e.retainedOffset=$i.source.after.partitionOffset;$e.sourceSha256=$i.source.after.sha256;$e.shadowSha256=$i.shadow.after.sha256;$e.fileId128=$i.shadow.after.identity.fileId128;$e.volumeSerial64=$i.shadow.after.identity.volumeSerial64
 $e.ownerSid=$i.source.after.security.owner;$e.fileSddl=$i.source.after.security.sddl;$e.directorySddl=$i.source.directorySecurity.sddl;$e.volumeSerial32=$i.shadow.volumeSerial32;$e.volumeFlags=$i.shadow.volumeFlags;$e.totalClusters=$i.shadow.nativeTotalClusters;[Ntfs2Refs.NativeConvertedVerification]::ValidateExpected($e);$e
}
function Export-ConvertedNative($Native,[string]$Directory){
 $artifacts=New-Object 'Collections.Generic.List[object]';$total=0L;$counter=0;$copy=[ordered]@{};foreach($p in $Native.PSObject.Properties){$copy[$p.Name]=$p.Value};$snapshots=@()
 $groups=@([pscustomobject]@{name='open';queries=$Native.openQueries})+@($Native.snapshots|ForEach-Object{[pscustomobject]@{name=$_.name;queries=$_.queries;snapshot=$_}})
 foreach($group in $groups){if(@($group.queries).Count-gt40){throw 'Native query group exceeds bound.'};$rows=@()
  foreach($q in $group.queries){if($counter-ge200){throw 'Native artifact count exceeds bound.'};$bytes=[byte[]]@();if($null-ne$q.bytes){$bytes=[byte[]]$q.bytes};if($bytes.Length-ne$q.bytesReturned-or$bytes.Length-gt65536-or$q.capacity-gt65536-or$q.bytesReturned-gt$q.capacity){throw 'Native artifact length differs.'};$total+=$bytes.Length;if($total-gt4MB){throw 'Native artifact aggregate exceeds4MiB.'}
   $name='query-'+$counter.ToString('D3')+'.bin';Write-ConvertedArtifact (Join-Path $Directory $name) $bytes 65536;$sha=[Ntfs2Refs.NativeRetainedFixture]::Hash($bytes)
   $rows+=[pscustomobject][ordered]@{name=$q.name;api=$q.api;code=$q.code;inputHex=$q.inputHex;capacity=$q.capacity;bytesReturned=$q.bytesReturned;succeeded=$q.succeeded;nativeError=$q.nativeError;startedUtc=$q.startedUtc;finishedUtc=$q.finishedUtc;bytes=$null;artifact=$name;sha256=$sha}
   $artifacts.Add([pscustomobject]@{name=$name;group=$group.name;query=$q.name;length=$bytes.Length;sha256=$sha});$counter++
  }
  if($group.name-ceq'open'){$copy.openQueries=$rows}else{$item=[ordered]@{};foreach($p in $group.snapshot.PSObject.Properties){$item[$p.Name]=$p.Value};$item.queries=$rows;$snapshots+=[pscustomobject]$item}
 };$copy.snapshots=$snapshots;[pscustomobject]@{native=[pscustomobject]$copy;artifacts=$artifacts.ToArray();binaryBytes=$total}
}
function Assert-ConvertedResult($Result){
 if($Result.status-cne'retained-A-observed-through-protected-ReFS'-or$Result.phase-cne'complete'-or$Result.payloadReadRequests-ne2-or$Result.payloadBytesRead-ne131072-or@($Result.snapshots).Count-ne4-or@($Result.payloadHashes).Count-ne2){throw 'Native verifier completion/read budget differs.'}
 foreach($name in @('complete','stable','cleanupComplete','privilegeRestored')){Assert-ConvertedBool $Result.$name $true};foreach($name in @('targetWriteRequestsIssued','protectionChanged','mountRequested','explicitFlushRequested','conversionQualified','bootQualified')){Assert-ConvertedBool $Result.$name $false}
 foreach($hash in $Result.payloadHashes){if($hash-cne$Result.expected.sourceSha256-or$hash-ceq$Result.expected.shadowSha256){throw 'Native payload hash differs.'}}
}
if(-not$PSCmdlet.ShouldProcess('already protected original target partition','Read native ReFS metadata and twice read exactly64KiB retained A')){[pscustomobject]@{Status='what-if';MaximumPayloadBytesRead=131072;MaximumArtifacts=203;MaximumBinaryBytes=4MB;ConversionQualified=$false};return}
if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'-or-not[Environment]::Is64BitProcess-or('Ntfs2Refs.NativeRetainedFixture'-as[type])-or('Ntfs2Refs.NativeConvertedVerification'-as[type])){throw 'Exact owned guest and fresh isolated x64 PowerShell process required.'}
$root='C:\ntfs2refs\converted-verification\'+$RunId+'\'+$ObservationId;$inputPath=$root+'\input.json';$convertedPins=New-Object 'Collections.Generic.List[IO.FileStream]';$record=$null;$outputTrusted=$false
try{
 $spec=Read-ConvertedPinned $inputPath $InputSha256 64KB;Assert-ConvertedInput $spec $RunId $ObservationId
 $staged=@(Get-ChildItem -LiteralPath $root -Force);if($staged.Count-ne1-or$staged[0].Name-cne'input.json'){throw 'Unique staged input-only observation directory required.'}
 $outputTrusted=$true
 $texts=@{};foreach($source in $spec.sources){$texts[$source.name]=Read-ConvertedPinned (Join-Path $PSScriptRoot $source.name) $source.sha256 128KB -Text}
 Import-ConvertedPure $texts['Invoke-GuestRetainedPair.ps1'] @('Assert-RetainedPlatforms','Assert-RetainedAccessPolicies','Assert-RetainedNamespaces','Assert-RetainedQueryOutcome','Assert-RetainedConstruction','Assert-RetainedInspection')
 Import-ConvertedPure $texts['Invoke-GuestReadOnlyMount.ps1'] @('Assert-MountBool','Assert-MountHash','Assert-MountGuid','Assert-MountSame','Assert-MountProfile','Assert-MountInputs','Assert-MountCli','Assert-MountInventory')
 $evidence=@{};foreach($pin in $spec.evidence){$maximum=if($pin.role-in@('prepare','apply','handoff')){16MB}elseif($pin.role-ceq'request'){128KB}elseif($pin.role-ceq'ticket'){64KB}else{2MB};$evidence[$pin.role]=Read-ConvertedPinned $pin.path $pin.sha256 $maximum};Assert-ConvertedEvidence $spec $evidence
 $record=[ordered]@{schemaVersion=1;kind='converted-retained-verification';runId=$RunId;observationId=$ObservationId;inputSha256=$InputSha256;input=$spec;status='blocked';createdUtc=[DateTime]::UtcNow.ToString('o');nativeOperationCompletionKnown=$true;provenanceValidated=$true;freshVolumeGuid=$null;expectedPostimageSha256=$evidence.mount.expectedPostimageSha256;native=$null;artifacts=@();binaryBytes=0;targetWriteRequestsIssued=$false;protectionChanged=$false;mountRequested=$false;conversionQualified=$false;bootQualified=$false;error=$null}
 $part=Get-Partition -DiskNumber 1 -PartitionNumber 2;$volumes=@($part|Get-Volume);if($volumes.Count-ne1){throw 'Exactly one fresh mounted target volume required.'};$volume=$volumes[0];$disks=@(Get-Disk);Assert-ConvertedLive $disks $part $volume $evidence;$record.freshVolumeGuid=$volume.Path
 $record['initialDisks']=@($disks|Select-Object Number,UniqueId,Guid,Size,LogicalSectorSize,PhysicalSectorSize,PartitionStyle,IsBoot,IsSystem,IsOffline,IsReadOnly)
 Add-Type -Path @('NativeRetainedFixture.cs','NativeRetainedFixture.Windows.cs','NativeConvertedVerification.cs','NativeConvertedVerification.Windows.cs'|ForEach-Object{Join-Path $PSScriptRoot $_})
 $expected=New-ConvertedExpected $spec $evidence $volume.Path
 $intent=[pscustomobject]@{schemaVersion=1;kind='converted-retained-verification-intent';runId=$RunId;observationId=$ObservationId;inputSha256=$InputSha256;freshVolumeGuid=$volume.Path;maximumPayloadBytesRead=131072;targetWriteRequestsMayFollow=$false;createdUtc=[DateTime]::UtcNow.ToString('o')}
 Write-ConvertedArtifact ($root+'\started.json') ((New-Object Text.UTF8Encoding($false)).GetBytes(($intent|ConvertTo-Json))) 16KB
 $record.nativeOperationCompletionKnown=$false;$native=[Ntfs2Refs.NativeConvertedVerification]::Observe($expected);$record.nativeOperationCompletionKnown=$true
 $export=Export-ConvertedNative $native $root;$record.native=$export.native;$record.artifacts=$export.artifacts;$record.binaryBytes=$export.binaryBytes;Assert-ConvertedResult $native
 $afterPart=Get-Partition -DiskNumber 1 -PartitionNumber 2;$afterVolumes=@($afterPart|Get-Volume);if($afterVolumes.Count-ne1-or$afterVolumes[0].Path-cne$volume.Path){throw 'Fresh target volume changed.'};$afterDisks=@(Get-Disk);Assert-ConvertedLive $afterDisks $afterPart $afterVolumes[0] $evidence
 $record['finalDisks']=@($afterDisks|Select-Object Number,UniqueId,Guid,Size,LogicalSectorSize,PhysicalSectorSize,PartitionStyle,IsBoot,IsSystem,IsOffline,IsReadOnly);$record.status=$native.status
}catch{if($null-eq$record){$record=[ordered]@{schemaVersion=1;kind='converted-retained-verification';runId=$RunId;observationId=$ObservationId;inputSha256=$InputSha256;status='blocked';nativeOperationCompletionKnown=$true;provenanceValidated=$false;conversionQualified=$false;bootQualified=$false;error=$_.Exception.ToString();artifacts=@()}}else{$record.error=$_.Exception.ToString()}}
finally{try{if($outputTrusted-and$null-ne$record){$record['finishedUtc']=[DateTime]::UtcNow.ToString('o');Write-ConvertedArtifact ($root+'\verification.json') ((New-Object Text.UTF8Encoding($false)).GetBytes(($record|ConvertTo-Json -Depth 32))) 2MB}}finally{foreach($pin in $convertedPins){$pin.Dispose()}}}
[pscustomobject]@{Status=$record.status;RunId=$RunId;ObservationId=$ObservationId;EvidenceDirectory=$root;OperationCompletionKnown=$record.nativeOperationCompletionKnown;ConversionQualified=$false}
