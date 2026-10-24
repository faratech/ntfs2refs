<# Derive one lab request from pinned, completed native evidence. No VM or device calls. #>
[CmdletBinding(SupportsShouldProcess)]
param(
 [Parameter(Mandatory)][string]$ProbeResultPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ProbeResultSha256,
 [Parameter(Mandatory)][string]$OutputPath
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
function Assert-NGRHash($Value){if($Value-isnot[string]-or$Value-cnotmatch '\A[0-9a-f]{64}\z'){throw 'Expected lowercase SHA-256 pin.'}}
function Assert-NGRBool($Value,[bool]$Expected){if($Value-isnot[bool]-or$Value-ne$Expected){throw 'Explicit evidence boolean differs.'}}
function Assert-NGRNumber($Value,[long]$Expected){if($null-eq$Value-or$Value-is[string]-or$Value-is[bool]-or$Value-ne$Expected){throw 'Exact numeric evidence differs.'}}
function Assert-NGRPath([string]$Path,[string]$Root){
 if($Path-cnotmatch '\A[A-Za-z]:\\[^:*?"<>|/]+\z'-or$Path.Length-gt240){throw 'Absolute ordinary Windows path required.'}
 $parts=$Path.Substring(3).Split('\');foreach($part in $parts){if($part.Length-eq0-or$part-eq'.'-or$part-eq'..'-or$part.EndsWith('.')-or$part.EndsWith(' ')-or$part-cmatch '[\x00-\x1f]'-or$part-match '\A(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)'){throw 'Ambiguous path component.'}}
 $full=[IO.Path]::GetFullPath($Path);$prefix=[IO.Path]::GetFullPath($Root).TrimEnd('\')+'\'
 if(-not$full.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){throw 'Evidence and output must remain under this workspace .lab.'};$full
}
function Assert-NGRAncestors([string]$Path,[bool]$Existing){
 $leaf=if($Existing){$Path}else{[IO.Path]::GetDirectoryName($Path)};$current=$leaf
 while($current){$item=Get-Item -LiteralPath $current -Force;if($item.Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Reparse evidence path refused.'};if($current-cne$Path-and-not$item.PSIsContainer){throw 'Non-directory ancestor.'};$parent=[IO.Path]::GetDirectoryName($current);if($parent-ceq$current){break};$current=$parent}
}
function Get-NGRSha([byte[]]$Bytes){$sha=[Security.Cryptography.SHA256]::Create();try{[BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}
function Read-NGRPinned([string]$Path,[string]$Hash,[long]$Maximum){
 Assert-NGRHash $Hash;$path=Assert-NGRPath $Path $script:labRoot;Assert-NGRAncestors $path $true
 $f=Get-Item -LiteralPath $path -Force;if($f.PSIsContainer-or$f.Length-lt1-or$f.Length-gt$Maximum){throw 'Bounded ordinary evidence file required.'}
 $stream=New-Object IO.FileStream($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{if($stream.Length-lt1-or$stream.Length-gt$Maximum){throw 'Evidence length changed.'};$bytes=New-Object byte[] $stream.Length;$at=0;while($at-lt$bytes.Length){$n=$stream.Read($bytes,$at,$bytes.Length-$at);if($n-le0){throw 'Short evidence read.'};$at+=$n};if((Get-NGRSha $bytes)-cne$Hash){throw ('Evidence pin mismatch: '+[IO.Path]::GetFileName($path))}}finally{$stream.Dispose()}
 [pscustomobject]@{path=$path;sha256=$Hash;length=$bytes.Length;bytes=$bytes}
}
function Convert-NGRJson($File){
 # Read-NGRPinned authenticates the original bytes, including any UTF-8 BOM.
 $text=(New-Object Text.UTF8Encoding($false,$true)).GetString($File.bytes)
 if($text.Length-gt0-and$text[0]-eq[char]0xfeff){$text=$text.Substring(1)}
 if($text-cmatch '\A[\x20\x09\x0a\x0d]*\uFEFF'){throw 'Only one leading UTF-8 BOM is permitted.'}
 $text|ConvertFrom-Json
}
function Import-NGRGuards($File,[string[]]$Names){
 $text=(New-Object Text.UTF8Encoding($false,$true)).GetString($File.bytes);$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors);if($errors.Count){throw 'Pinned guard source does not parse.'}
 foreach($name in $Names){$f=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]},$false)|Where-Object Name -CEQ $name);if($f.Count-ne1){throw 'Exact named archived guard absent.'};$definition=[regex]::Replace($f[0].Extent.Text,('\Afunction\s+'+[regex]::Escape($name)+'\b'),('function script:'+$name));. ([scriptblock]::Create($definition))}
}
function Get-NGRSource($HostProof,[string]$Name){
 $f=@($HostProof.sourceHashes|Where-Object name -CEQ $Name);if($f.Count-ne1){throw 'Exact archived validator pin absent.'};Assert-NGRHash $f[0].sha256
 if($f[0].length-is[string]-or$f[0].length-is[bool]-or$f[0].length-lt1-or$f[0].length-gt256KB){throw 'Archived validator length differs.'};$f[0]
}
function Assert-NGRHost($Proof){
 Assert-NGRNumber $Proof.schemaVersion 1
 if($Proof.kind-cne'retained-native-probe-host'-or$Proof.status-cne'native-isolation-and-restart-verified'-or$Proof.phase-cne'complete'-or$Proof.runId-cnotmatch '\A[0-9a-f]{32}\z'-or$Proof.firstProbeId-cnotmatch '\A[0-9a-f]{32}\z'-or$Proof.secondProbeId-cnotmatch '\A[0-9a-f]{32}\z'-or$Proof.firstProbeId-ceq$Proof.secondProbeId-or$Proof.vmId-ine'eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c'-or$Proof.baselineId-ine'eda059b3-6d50-46bb-bdf4-018b99b5b34f'){throw 'Completed owned isolation/restart evidence required.'}
 foreach($n in @('inspectionExported','firstNativeExported','secondNativeExported','baselineRestored','memoryRestored')){Assert-NGRBool $Proof.$n $true}
 foreach($n in @('payloadWriteRequestsIssued','conversionQualified','transportCompletionUnknown','guestOperationUnknown','sessionPreserved')){Assert-NGRBool $Proof.$n $false}
 foreach($n in @('preparationResultSha256','inspectionEvidenceSha256','requestSha256','firstNativeReportSha256','secondNativeReportSha256','targetPartitionSha256','shadowPartitionSha256','reviewedSourcesSha256')){Assert-NGRHash $Proof.$n}
 foreach($n in @('prepared','isolated','quiescent')){Assert-NativeProbeGuid $Proof.($n+'CheckpointId');$prefix=if($n-ceq'prepared'){'retained-prepared-'}elseif($n-ceq'isolated'){'retained-isolated-'}else{'retained-quiescent-'};$suffix=if($n-ceq'prepared'){$Proof.runId}elseif($n-ceq'isolated'){$Proof.firstProbeId}else{$Proof.secondProbeId};if($Proof.($n+'CheckpointName')-cne($prefix+$suffix)){throw 'Saved checkpoint identity differs.'}}
 if(@($Proof.preparedCheckpointId,$Proof.isolatedCheckpointId,$Proof.quiescentCheckpointId|Select-Object -Unique).Count-ne3){throw 'Saved checkpoints alias.'}
 $names=@('Invoke-GuestNativeProbe.ps1','Invoke-LabRetainedNativeProbe.ps1','Restore-GuestShadowAttachment.ps1','NativeShadowDisk.cs','NativeShadowReadOnlyAttachment.cs','NativeMountBoundary.cs','Lab.psm1','lab-native-probe.exe');if(@($Proof.sourceHashes).Count-ne8-or@($Proof.sourceHashes.name|Select-Object -Unique).Count-ne8){throw 'Exact protected probe source inventory required.'};foreach($s in $Proof.sourceHashes){if($s.name-cnotin$names){throw 'Unreviewed probe source name.'};Assert-NGRHash $s.sha256}
 if($Proof.shadowProtectionProfile-cne'provider-readonly-explicit-exclusion'){throw 'Provider-protected reattachment proof required.'};Assert-NGRBool $Proof.shadowPersistenceQualified $false;Assert-NGRHash $Proof.excludedAttachmentSha256
}
function New-NGRRequest($HostProof,$Probe,$First,$Second,$Prepared,$Source,$Shadow){
 Assert-NGRHost $HostProof;Assert-RetainedProbePreparation $Prepared
 if($Prepared.runId-cne$HostProof.runId-or$Prepared.outcomeCheckpointId-ine$HostProof.preparedCheckpointId-or$Prepared.outcomeCheckpointName-cne$HostProof.preparedCheckpointName){throw 'Preparation checkpoint binding differs.'}
 Assert-NativeProbeRequest $Probe $HostProof.runId;Assert-NGRNumber $Probe.schema_version 1
 foreach($role in @('target','shadow')){$b=$Probe.$role;$number=if($role-ceq'target'){1}else{3};Assert-NGRNumber $b.disk_number $number;foreach($pair in @(@('partition_number',2),@('disk_bytes',64GB),@('partition_offset',16MB),@('partition_bytes',52GB),@('logical_sector_bytes',512),@('physical_sector_bytes',4096))){Assert-NGRNumber $b.identity.($pair[0]) $pair[1]}}
 Assert-NGRNumber $Probe.retained_offset ([long]$Probe.retained_offset)
 Assert-NativeProbeResult $First $Probe $false $false;Assert-NativeProbeResult $Second $Probe $true $true
 if($Probe.fixture_evidence_sha256-cne$HostProof.inspectionEvidenceSha256-or$Second.target_partition_sha256-cne$HostProof.targetPartitionSha256-or$Second.shadow_partition_sha256-cne$HostProof.shadowPartitionSha256){throw 'Whole-image or inspection pins differ.'}
 $r=$Prepared.retainedInterval;if($Probe.retained_offset-ne$r.offset-or$Probe.source_retained_sha256-cne$r.sourceSha256-or$Probe.shadow_retained_sha256-cne$r.shadowSha256){throw 'Retained preparation interval differs.'}
 $native=Get-NGRSource $HostProof 'NativeShadowDisk.cs';Assert-AttachmentPreparation $Shadow $HostProof.runId $native.sha256
 if($Source.schemaVersion-ne1-or$Source.kind-cne'retained-ntfs-source-platform'-or$Source.status-cne'ntfs-source-prepared'-or$Source.phase-cne'complete'-or$Source.runId-cne$HostProof.runId-or$Source.target.guest.uniqueId-cne'60022480D091C4251B5FFD619706C2B5'-or$Source.target.guest.sizeBytes-ne64GB-or$Source.partition.number-ne2-or$Source.partition.offset-ne16MB-or$Source.partition.length-ne52GB-or$Source.partition.logicalSectorSize-ne512-or$Source.partition.physicalSectorSize-ne4096-or$Source.volume.filesystem-cne'NTFS'-or$Source.volume.allocationUnitSize-ne4096){throw 'Pinned source platform differs.'}
 Assert-NGRBool $Source.operationCompletionKnown $true;Assert-NGRBool $Source.conversionQualified $false
 foreach($pair in @(@($Source.volume.guid,$Probe.target.volume_guid),@($Shadow.shadow.volumeGuid,$Probe.shadow.volume_guid))){if($pair[0]-cnotmatch '\A\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\\z'-or[guid]$pair[0].Substring(11,36)-ne[guid]$pair[1]){throw 'Prepared volume GUID binding differs.'}}
 foreach($pair in @(@($Source.partition.diskGuid,$Probe.target.identity.disk_guid),@($Source.partition.guid,$Probe.target.identity.partition_guid),@($Shadow.shadow.diskGuid,$Probe.shadow.identity.disk_guid),@($Shadow.shadow.partitionGuid,$Probe.shadow.identity.partition_guid))){if([guid]$pair[0]-ne[guid]$pair[1]){throw 'Prepared GPT binding differs.'}}
 $j=$Shadow.journal;$journal=[pscustomobject]@{disk_number=2;externally_enrolled_disk_unique_id=$Shadow.journalIdentity.uniqueId;volume_guid=([guid]$j.volumeGuid.Substring(11,36)).ToString('D');identity=[pscustomobject]@{disk_guid=([guid]$j.diskGuid).ToString('D');partition_guid=([guid]$j.partitionGuid).ToString('D');partition_number=2;disk_bytes=8GB;partition_offset=16MB;partition_bytes=(8GB-32MB);logical_sector_bytes=512;physical_sector_bytes=4096}}
 foreach($data in @($Probe.target,$Probe.shadow)){if([guid]$data.volume_guid-eq[guid]$journal.volume_guid-or[guid]$data.identity.disk_guid-eq[guid]$journal.identity.disk_guid-or[guid]$data.identity.partition_guid-eq[guid]$journal.identity.partition_guid){throw 'Journal storage aliases a data partition.'}}
 [pscustomobject]@{schema_version=1;experiment_id=$HostProof.runId;probe=$Probe;comparison=[pscustomobject]@{schema_version=1;sector_size=4096;expected_length=52GB;source_sha256=$Second.target_partition_sha256;shadow_sha256=$Second.shadow_partition_sha256;retained_ranges=@([pscustomobject]@{offset=$Probe.retained_offset;length=65536;source_sha256=$Probe.source_retained_sha256;shadow_sha256=$Probe.shadow_retained_sha256});max_change_bytes=256MB;max_ranges=65536};journal=$journal;max_journal_bytes=768MB}
}
function Write-NGRNew([string]$Path,[byte[]]$Bytes){
 if($Bytes.Length-lt1-or$Bytes.Length-gt128KB){throw 'Output bound exceeded.'};Assert-NGRAncestors $Path $false
 $f=New-Object IO.FileStream($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($Bytes,0,$Bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
 $pin=Get-NGRSha $Bytes;$read=Read-NGRPinned $Path $pin 128KB;if($read.length-ne$Bytes.Length){throw 'Durable output readback length differs.'};$pin
}
$script:labRoot=Join-Path (Split-Path -Parent $PSScriptRoot) '.lab'
$inputPath=Assert-NGRPath $ProbeResultPath $labRoot;$output=Assert-NGRPath $OutputPath $labRoot;$pinPath=Assert-NGRPath ($output+'.pin.json') $labRoot
if([IO.Path]::GetFileName($inputPath)-cne'host-result.json'-or[IO.Path]::GetExtension($output)-cne'.json'){throw 'Expected host-result.json input and new .json output.'}
foreach($p in @($output,$pinPath)){Assert-NGRAncestors $p $false;if(Test-Path -LiteralPath $p){throw 'Create-new output or pin already exists.'}}
$root=Split-Path -Parent $inputPath;$evidence=New-Object Collections.Generic.List[object]
$hostFile=Read-NGRPinned $inputPath $ProbeResultSha256 2MB;$evidence.Add($hostFile);$hostProof=Convert-NGRJson $hostFile
# The independent host-result pin is the trust root. Source archive paths in its
# JSON are never followed: only fixed filenames below this case are read.
foreach($spec in @(
 @('Invoke-GuestNativeProbe.ps1',@('Assert-NativeProbeFields','Assert-NativeProbeGuid','Assert-NativeProbeBinding','Assert-NativeProbeRequest','Assert-NativeProbeSame','Assert-NativeProbeResult')),
 @('Invoke-LabRetainedNativeProbe.ps1',@('Assert-RetainedProbeBoolean','Assert-RetainedProbePreparation')),
 @('Restore-GuestShadowAttachment.ps1',@('Assert-AttachmentBoolean','Assert-AttachmentGuid','Assert-AttachmentPreparation'))
)){$entry=Get-NGRSource $hostProof $spec[0];$file=Read-NGRPinned (Join-Path $root ('reviewed-sources\'+$spec[0])) $entry.sha256 256KB;if($file.length-ne$entry.length){throw 'Archived validator length differs.'};$evidence.Add($file);Import-NGRGuards $file $spec[1]}
Assert-NGRHost $hostProof
$documents=@{}
foreach($spec in @(@('request','request.json',$hostProof.requestSha256,16KB),@('first','first-native\probe.json',$hostProof.firstNativeReportSha256,1MB),@('second','second-native\probe.json',$hostProof.secondNativeReportSha256,1MB),@('prepared','preparation-host-result.json',$hostProof.preparationResultSha256,2MB))){$file=Read-NGRPinned (Join-Path $root $spec[1]) $spec[2] $spec[3];$evidence.Add($file);$documents[$spec[0]]=Convert-NGRJson $file}
$prepared=$documents.prepared;Assert-RetainedProbePreparation $prepared
foreach($spec in @(@('source','source-platform.json',$prepared.sourceEvidenceSha256),@('shadow','shadow-platform.json',$prepared.shadowEvidenceSha256))){$file=Read-NGRPinned (Join-Path $root $spec[1]) $spec[2] 1MB;$evidence.Add($file);$documents[$spec[0]]=Convert-NGRJson $file}
$request=New-NGRRequest $hostProof $documents.request $documents.first $documents.second $prepared $documents.source $documents.shadow
$bytes=(New-Object Text.UTF8Encoding($false,$true)).GetBytes(($request|ConvertTo-Json -Depth 12));$hash=Get-NGRSha $bytes
$provenance=[ordered]@{schemaVersion=1;kind='native-reconstruction-request-pin';runId=$request.experiment_id;requestSha256=$hash;requestLength=$bytes.Length;probeResultSha256=$ProbeResultSha256;quiescentCheckpointId=$hostProof.quiescentCheckpointId;quiescentCheckpointName=$hostProof.quiescentCheckpointName;inputs=@($evidence|ForEach-Object{[pscustomobject]@{path=$_.path;sha256=$_.sha256;length=$_.length}});createdUtc=[DateTime]::UtcNow.ToString('o');currentDeviceStateVerified=$false;externalAttestationsPromotedToWriteAuthority=$false;nativeOperationInvoked=$false;conversionQualified=$false;bootQualified=$false}
if(-not$PSCmdlet.ShouldProcess($output,'Create pinned reconstruction request and provenance; no VM or device operations')){[pscustomobject]@{Status='validated-what-if';RunId=$request.experiment_id;RequestSha256=$hash;ConversionQualified=$false};return}
$written=Write-NGRNew $output $bytes;if($written-cne$hash){throw 'Request output hash differs.'};$pinBytes=(New-Object Text.UTF8Encoding($false,$true)).GetBytes(($provenance|ConvertTo-Json -Depth 8));$pinHash=Write-NGRNew $pinPath $pinBytes
[pscustomobject]@{Status='request-created';RunId=$request.experiment_id;RequestPath=$output;RequestSha256=$hash;PinPath=$pinPath;PinSha256=$pinHash;ConversionQualified=$false}
