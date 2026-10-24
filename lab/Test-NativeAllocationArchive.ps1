<# Independent archive reader. No native code imports, VM or device access. #>
[CmdletBinding()]param(
 [string]$CasePath,
 [string]$HostResultSha256='2028495b74c16b6242b2c73e771b8dd477b3d8bb665a5976a035589b3fd75a5c'
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$checks=0;$clustersChecked=0L;if([string]::IsNullOrWhiteSpace($CasePath)){$CasePath=Join-Path $PSScriptRoot '../.lab/hyperv/allocation-workload/win11-20261024T072530927Z'};$root=[IO.Path]::GetFullPath($CasePath)
function Check([bool]$Value,[string]$Message){if(-not$Value){throw $Message};$script:checks++}
function Read-Pinned([string]$Path,[string]$Hash,[long]$Maximum){
 Check ($Hash-cmatch'\A[0-9a-f]{64}\z') 'Invalid independent hash.';$p=[IO.Path]::GetFullPath($Path);Check ($p.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) 'Archive path escaped.';$at=$p
 while($at){$f=Get-Item -LiteralPath $at -Force;Check (-not($f.Attributes-band([IO.FileAttributes]::ReparsePoint-bor[IO.FileAttributes]::Compressed-bor[IO.FileAttributes]::Encrypted))) 'Ordinary archive path required.';$at=[IO.Path]::GetDirectoryName($at)}
 $f=Get-Item -LiteralPath $p;Check (-not$f.PSIsContainer-and$f.Length-ge0-and$f.Length-le$Maximum) 'Archive size differs.';$stream=New-Object IO.FileStream($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{$bytes=New-Object byte[] $stream.Length;$at=0;while($at-lt$bytes.Length){$n=$stream.Read($bytes,$at,$bytes.Length-$at);Check ($n-gt0) 'Short archive read.';$at+=$n};$sha=[Security.Cryptography.SHA256]::Create();try{$actual=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};Check ($actual-ceq$Hash) 'Archive hash differs.';return ,$bytes}finally{$stream.Dispose()}
}
function Json([byte[]]$Bytes){$s=[Text.Encoding]::UTF8.GetString($Bytes);if($s.Length-gt0-and$s[0]-eq[char]0xfeff){$s=$s.Substring(1)};$s|ConvertFrom-Json}
$h=Json (Read-Pinned ($root+'\host-result.json') $HostResultSha256 3MB)
Check ($h.kind-ceq'allocation-workload-host'-and$h.status-ceq'native-allocation-workload-checkpointed'-and$h.phase-ceq'complete') 'Completed host result required.'
foreach($n in @('cleanShutdown','outcomeCheckpointCreated','baselineRestored','memoryRestored')){Check ($h.$n-is[bool]-and$h.$n) 'Host cleanup incomplete.'}
foreach($n in @('transportCompletionUnknown','guestOperationUnknown','sessionPreserved','conversionQualified','bootQualified','rawPayloadWriteRequestsIssued')){Check ($h.$n-is[bool]-and-not$h.$n) 'Unknown activity/qualification accepted.'}
$r=Json (Read-Pinned ($root+'\native\result.json') $h.nativeResultSha256 3MB);$v=$r.native
Check ($r.workloadId-ceq$h.workloadId-and$r.inputSha256-ceq$h.inputSha256-and$r.status-ceq'native-allocation-workload-passed'-and$r.operationCompletionKnown-is[bool]-and$r.operationCompletionKnown) 'Native binding/completion differs.'
Check ($v.complete-and$v.cleanupComplete-and-not$v.operationActive-and$null-eq$v.error-and$null-eq$v.cleanupError) 'Native activity incomplete.'
Check ($v.fileBytesWritten-eq50MB-and$v.fileWriteBytesRequested-eq50MB-and$v.filesCreated-eq40-and$v.truncations-eq32-and$v.renames-eq16-and$v.deletions-eq40) 'Native workload coverage differs.'
foreach($a in $r.artifacts){$b=Read-Pinned ($root+'\native\'+$a.name) $a.sha256 2MB;Check ($b.Length-eq$a.length) 'Raw query artifact length differs.'}
Check ((@($v.allocation.stage)-join',')-ceq'created,mutated,reallocated,cleaned') 'Allocation stage coverage differs.'
$counts=@(33,33,25,1);$physicalCounts=@(8208,4112,6160,16);$expectedHash='a8da4df80396fc29486e0cba10fb7525404e8fd56169e6885475789b10f31bb3'
for($stage=0;$stage-lt4;$stage++){
 $s=$v.allocation[$stage];$b=Read-Pinned ($root+'\native\bitmap-'+$s.stage+'.bin') $s.sha256 2MB
 Check ([BitConverter]::ToInt64($b,0)-eq0-and[BitConverter]::ToInt64($b,8)-eq13631488-and$b.Length-ge1703952) 'Complete bitmap cluster domain differs.'
 Check ($s.returnedBytes-eq$b.Length-and$s.meaningfulBytes-eq1703952-and@($s.files).Count-eq$counts[$stage]) 'Snapshot bounds differ.'
 $occupied=New-Object 'Collections.Generic.HashSet[long]';$identities=New-Object 'Collections.Generic.HashSet[string]';$retained=0
 foreach($f in $s.files){
  Check ($identities.Add($f.fileId128)) 'Unrelated files have one identity.';$isRetained=$f.path-ceq($r.input.expected.volumeGuid+'retained\payload.bin')
  if($isRetained){$retained++;Check ($f.sha256-ceq$expectedHash-and$f.fileId128-ceq$r.input.expected.fileId128-and$f.length-eq65536-and@($f.extents).Count-eq1-and$f.extents[0].lcn-eq2097152) 'Retained payload/mapping differs.'}
  else{Check ($f.path.StartsWith(($r.input.expected.volumeGuid+'allocation-'+$h.workloadId+'\'),[StringComparison]::Ordinal)) 'Unowned workload path.'}
  $covered=0L;foreach($run in $f.extents){Check ($run.vcn-eq$covered-and$run.nextVcn-gt$run.vcn-and$run.lcn-ge0-and$run.lcn-le13631488-($run.nextVcn-$run.vcn)) 'Invalid physical extent.'
   for($lcn=[long]$run.lcn;$lcn-lt$run.lcn+$run.nextVcn-$run.vcn;$lcn++){
    Check ($occupied.Add($lcn)) 'Two unrelated payloads share a cluster.'
    Check (($b[16+[int][Math]::Floor($lcn/8)]-band(1-shl($lcn%8)))-ne0) 'Live payload marked free.'
    if(-not$isRetained){Check ($lcn-lt2097152-or$lcn-ge2097168) 'Workload overlaps retained payload.'};$script:clustersChecked++
   };$covered=[long]$run.nextVcn
  };Check ($covered*4096-eq$f.length) 'Extent coverage/logical length differs.'
 };Check ($retained-eq1-and$occupied.Count-eq$physicalCounts[$stage]-and$s.checkedClusters-eq$occupied.Count) 'Retained/allocation coverage differs.'
}
for($i=0;$i-lt32;$i++){
 $before=@($v.allocation[0].files|Where-Object path -Like ('*\file-'+$i.ToString('D2')+'.bin'));$prefix=if($i%2){'renamed-'}else{'file-'};$after=@($v.allocation[1].files|Where-Object path -Like ('*\'+$prefix+$i.ToString('D2')+'.bin'))
 Check ($before.Count-eq1-and$after.Count-eq1-and$before[0].fileId128-ceq$after[0].fileId128) 'Truncate/rename changed file identity.'
}
foreach($o in @($v.before,$v.after)){Check ($o.complete-and$o.stable-and$o.cleanupComplete-and$o.privilegeRestored-and$o.payloadReadRequests-eq2-and$o.payloadBytesRead-eq131072) 'Protected native observation incomplete.';foreach($hash in $o.payloadHashes){Check ($hash-ceq$expectedHash) 'Protected read hash differs.'}}
[pscustomobject]@{Status='passed';Assertions=$checks;PayloadClustersChecked=$clustersChecked;AllocationSnapshots=4;StableMutationIdentities=32;NativeDeviceOperations=0}
