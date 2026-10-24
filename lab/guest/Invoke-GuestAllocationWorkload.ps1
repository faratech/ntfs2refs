<# Disposable workload on an already converted target. No reconstruction or rollback. #>
[CmdletBinding(SupportsShouldProcess)]param(
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$WorkloadId,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$InputSha256
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
if(-not$PSCmdlet.ShouldProcess('original converted lab target','Create at most64MiB through ReFS, check allocation, remove owned files and protect read-only')){return}
if($env:COMPUTERNAME-cne'N2R-WIN11'-or$env:SystemDrive-cne'C:'-or-not[Environment]::Is64BitProcess-or('Ntfs2Refs.NativeAllocationWorkload'-as[type])){throw 'Exact guest and fresh x64 PowerShell required.'}
$root='C:\ntfs2refs\allocation-workload\'+$WorkloadId
$pins=New-Object 'Collections.Generic.List[IO.FileStream]'
function Read-Pin([string]$Path,[string]$Hash,[long]$Maximum){
 if($Hash-cnotmatch'\A[0-9a-f]{64}\z'){throw 'Independent pin required.'};$at=$Path
 while($at){$f=Get-Item -LiteralPath $at -Force;if($f.Attributes-band([IO.FileAttributes]::ReparsePoint-bor[IO.FileAttributes]::Compressed-bor[IO.FileAttributes]::Encrypted)){throw 'Ordinary input path required.'};$at=[IO.Path]::GetDirectoryName($at)}
 $f=Get-Item -LiteralPath $Path;if($f.PSIsContainer-or$f.Length-lt1-or$f.Length-gt$Maximum){throw 'Input size differs.'}
 $s=New-Object IO.FileStream($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$pins.Add($s);$sha=[Security.Cryptography.SHA256]::Create();try{$actual=[BitConverter]::ToString($sha.ComputeHash($s)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};if($actual-cne$Hash){throw 'Pinned input changed.'};$s.Position=0;$r=New-Object IO.StreamReader($s,(New-Object Text.UTF8Encoding($false,$true)),$true,4096,$true);try{$r.ReadToEnd()}finally{$r.Dispose()}
}
function Write-Artifact([string]$Name,[byte[]]$Bytes,[long]$Maximum){if($Bytes.Length-gt$Maximum){throw 'Output bound exceeded.'};$s=New-Object IO.FileStream((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$s.Write($Bytes,0,$Bytes.Length);$s.Flush($true)}finally{$s.Dispose()}}
function Write-Json([string]$Name,$Value,[long]$Maximum){Write-Artifact $Name ([Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 35))) $Maximum}
$native=$null;$record=$null
try{
 $spec=Read-Pin ($root+'\input.json') $InputSha256 64KB|ConvertFrom-Json
 if($spec.schemaVersion-ne1-or$spec.kind-cne'allocation-workload-input'-or$spec.workloadId-cne$WorkloadId-or$spec.parentVerificationSha256-cnotmatch'\A[0-9a-f]{64}\z'-or$spec.handoffSha256-cne'02441be13147333e73778d469ae2c249573239b8a42fd7940d93e57e59bc9d3d'){throw 'Pinned post-handoff workload input required.'}
 $names=@('NativeShadowDisk.cs','NativeMountBoundary.cs','NativeRetainedFixture.cs','NativeRetainedFixture.Windows.cs','NativeConvertedVerification.cs','NativeConvertedVerification.Windows.cs','NativeAllocationWorkload.cs','Invoke-GuestAllocationWorkload.ps1')
 if(@($spec.sources).Count-ne$names.Count-or@($spec.sources.name|Select-Object -Unique).Count-ne$names.Count){throw 'Exact reviewed helper set required.'};$texts=@{}
 foreach($entry in $spec.sources){if($entry.name-cnotin$names){throw 'Unexpected helper.'};$texts[$entry.name]=Read-Pin ('C:\ntfs2refs\guest\'+$entry.name) $entry.sha256 256KB}
 $handoff=Read-Pin ('C:\ntfs2refs\native-reconstruct\'+$spec.expected.runId+'\22eefc99800a473687e43b9e80125439\result.json') $spec.handoffSha256 2MB|ConvertFrom-Json
 if($handoff.operation-cne'handoff'-or$handoff.success-isnot[bool]-or-not$handoff.success-or$handoff.phase-cne'complete-disks-remain-offline'-or$null-ne$handoff.error){throw 'Completed rollback-closing handoff required.'}
 Add-Type -Path @($names|Where-Object{$_-clike'*.cs'}|ForEach-Object{'C:\ntfs2refs\guest\'+$_})
 $expected=New-Object Ntfs2Refs.ConvertedExpected;foreach($p in $spec.expected.PSObject.Properties){$expected.($p.Name)=$p.Value};[Ntfs2Refs.NativeConvertedVerification]::ValidateExpected($expected)
 $record=[ordered]@{schemaVersion=1;kind='native-allocation-workload';workloadId=$WorkloadId;inputSha256=$InputSha256;input=$spec;status='started';operationCompletionKnown=$false;conversionQualified=$false;bootQualified=$false;native=$null;artifacts=@();createdUtc=[DateTime]::UtcNow.ToString('o')}
 Write-Json started.json ([ordered]@{kind='allocation-workload-intent';workloadId=$WorkloadId;inputSha256=$InputSha256;maximumFileWriteBytes=64MB;rawPayloadWritesAllowed=$false;rollbackClosed=$true}) 16KB
 $native=(New-Object Ntfs2Refs.NativeAllocationWorkload($expected,$WorkloadId)).Run();$record.operationCompletionKnown=(-not$native.operationActive);$record.status=$native.status
 foreach($bitmap in $native.allocation){$name='bitmap-'+$bitmap.stage+'.bin';Write-Artifact $name $bitmap.bytes 2MB;$record.artifacts+=,[pscustomobject]@{name=$name;sha256=$bitmap.sha256;length=$bitmap.bytes.Length};$bitmap.bytes=$null}
 # Existing observer buffers are serialized as separate files, never discarded.
 foreach($group in @(@('before',$native.before),@('after',$native.after))){if($null-eq$group[1]){continue};$index=0;foreach($q in @($group[1].openQueries)+@($group[1].snapshots|ForEach-Object{$_.queries})){$name=$group[0]+'-query-'+$index.ToString('D3')+'.bin';$b=[byte[]]$q.bytes;Write-Artifact $name $b 64KB;$record.artifacts+=,[pscustomobject]@{name=$name;sha256=[Ntfs2Refs.NativeRetainedFixture]::Hash($b);length=$b.Length};$q.bytes=$null;$index++}}
 $record.native=$native;$record['finishedUtc']=[DateTime]::UtcNow.ToString('o');Write-Json result.json $record 3MB
 [pscustomobject]@{Status=$record.status;Complete=$native.complete;OperationCompletionKnown=$record.operationCompletionKnown;ResultPath=($root+'\result.json');ResultSha256=(Get-FileHash -LiteralPath ($root+'\result.json')).Hash.ToLowerInvariant()}
}finally{foreach($s in $pins){$s.Dispose()}}
