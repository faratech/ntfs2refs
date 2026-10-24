<# Pure result/process guards, ordinary temporary files and WhatIf; no native calls. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$script:checks=0
function Check([bool]$Value,[string]$Name){if(-not$Value){throw $Name};$script:checks++}
function Reject([scriptblock]$Body,[string]$Name){$failed=$false;try{&$Body|Out-Null}catch{$failed=$true};Check $failed $Name}
function Clone($Value){$Value|ConvertTo-Json -Depth 24|ConvertFrom-Json}
$path=Join-Path $PSScriptRoot 'guest\Invoke-GuestNativeProbe.ps1';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors);Check ($errors.Count-eq0) 'guest parser'
foreach($f in $ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]},$true)){. ([scriptblock]::Create($f.Extent.Text))}
function Binding([int]$Number,[string]$Disk,[string]$Partition,[string]$Volume){[pscustomobject]@{disk_number=$Number;volume_guid=$Volume;identity=[pscustomobject]@{disk_guid=$Disk;partition_guid=$Partition;partition_number=2;disk_bytes=64GB;partition_offset=16MB;partition_bytes=52GB;logical_sector_bytes=512;physical_sector_bytes=4096}}}
$id='a'*32
$request=[pscustomobject]@{schema_version=1;experiment_id=$id;fixture_evidence_sha256=('b'*64);target=(Binding 1 '11111111-1111-1111-1111-111111111111' '22222222-2222-2222-2222-222222222222' '33333333-3333-3333-3333-333333333333');shadow=(Binding 3 '44444444-4444-4444-4444-444444444444' '55555555-5555-5555-5555-555555555555' '66666666-6666-6666-6666-666666666666');retained_offset=8GB;source_retained_sha256=('c'*64);shadow_retained_sha256=('d'*64)}
function Snapshot($Binding,[int]$Attributes){[pscustomobject]@{binding=(Clone $Binding);disk_attributes=$Attributes;device=(@(0)*12);length=(@(0)*8);alignment=(@(0)*28);layout=(@(0)*336)}}
$event=[pscustomobject]@{operation='get-disk-attributes';control_code=0x700f0;input=@();succeeded=$true;native_error=$null;output=@(16,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0)}
$report=[pscustomobject]@{schema_version=1;kind='native-partition-isolation-probe';request=(Clone $request);reopen=$false;success=$true;phase='complete-disks-remain-offline';error=$null;target_snapshot=(Snapshot $request.target 1);shadow_snapshot=(Snapshot $request.shadow 3);target_retained_sha256=$request.source_retained_sha256;shadow_retained_sha256=$request.shadow_retained_sha256;target_partition_sha256=$null;shadow_partition_sha256=$null;target_flush_succeeded=$true;target_bytes_read=65536L;shadow_bytes_read=65536L;payload_write_requests_issued=$false;conversion_qualified=$false;events=@($event)}
Assert-NativeProbeRequest $request $id;$script:checks++
Assert-NativeProbeResult $report $request $false $false;$script:checks++
$whole=Clone $report;$whole.reopen=$true;$whole.target_partition_sha256='e'*64;$whole.shadow_partition_sha256='f'*64;$whole.target_bytes_read+=52GB;$whole.shadow_bytes_read+=52GB
Assert-NativeProbeResult $whole $request $true $true;$script:checks++
foreach($change in @(
 {param($r)$r.target.disk_number=0},
 {param($r)$r.shadow.disk_number=4},
 {param($r)$r.target.identity.partition_offset=0},
 {param($r)$r.shadow.identity.partition_bytes=51GB},
 {param($r)$r.shadow.identity.disk_guid='{11111111-1111-1111-1111-111111111111}'},
 {param($r)$r.shadow.volume_guid=$r.target.volume_guid},
 {param($r)$r.source_retained_sha256=$r.shadow_retained_sha256},
 {param($r)$r.retained_offset=9GB},
 {param($r)$r.retained_offset++},
 {param($r)$r.fixture_evidence_sha256='x'*64}
)){$bad=Clone $request;&$change $bad;Reject {Assert-NativeProbeRequest $bad $id} 'request refusal'}
$bad=Clone $request;$bad|Add-Member extra 1;Reject {Assert-NativeProbeRequest $bad $id} 'unknown request field'
foreach($change in @(
 {param($r)$r.request.fixture_evidence_sha256='a'*64},
 {param($r)$r.request.retained_offset+=65536},
 {param($r)$r.target_snapshot.binding.identity.disk_guid='77777777-7777-7777-7777-777777777777'},
 {param($r)$r.shadow_snapshot.binding.volume_guid='77777777-7777-7777-7777-777777777777'},
 {param($r)$r.target_snapshot.disk_attributes=0},
 {param($r)$r.shadow_snapshot.disk_attributes=1},
 {param($r)$r.success=$false},
 {param($r)$r.success=1},
 {param($r)$r.reopen=$true},
 {param($r)$r.payload_write_requests_issued=$true},
 {param($r)$r.conversion_qualified=$true},
 {param($r)$r.target_flush_succeeded=$false},
 {param($r)$r.error='unexpected failure'},
 {param($r)$r.phase='raw-retained-proof'},
 {param($r)$r.target_retained_sha256=$r.shadow_retained_sha256},
 {param($r)$r.target_bytes_read--},
 {param($r)$r.shadow_bytes_read+=4096},
 {param($r)$r.target_bytes_read='65536'},
 {param($r)$r.target_partition_sha256='e'*64},
 {param($r)$r.target_snapshot.device=@(0)},
 {param($r)$r.shadow_snapshot.alignment[0]=256},
 {param($r)$r.events=@()},
 {param($r)$r.events[0].succeeded=$false},
 {param($r)$r.events[0].native_error=5}
)){$bad=Clone $report;&$change $bad;Reject {Assert-NativeProbeResult $bad $request $false $false} 'report refusal'}
$bad=Clone $whole;$bad.target_partition_sha256=$null;Reject {Assert-NativeProbeResult $bad $request $true $true} 'whole partition pin required'
$bad=Clone $whole;$bad.shadow_bytes_read=52GB;Reject {Assert-NativeProbeResult $bad $request $true $true} 'whole partition includes retained read'
$bad=Clone $report;$bad.PSObject.Properties.Remove('shadow_snapshot');Reject {Assert-NativeProbeResult $bad $request $false $false} 'missing snapshot'
$reordered=Clone $report;$reordered.request=[pscustomobject][ordered]@{shadow=$request.shadow;target=$request.target;schema_version=1;experiment_id=$id;fixture_evidence_sha256=$request.fixture_evidence_sha256;retained_offset=$request.retained_offset;source_retained_sha256=$request.source_retained_sha256;shadow_retained_sha256=$request.shadow_retained_sha256};Assert-NativeProbeResult $reordered $request $false $false;$script:checks++
function FakeProcess([bool]$WaitResult,$Exit){$p=[pscustomobject]@{waitResult=$WaitResult;ExitCode=$Exit;waitMilliseconds=0;waitThrows=$false;OutputLimitExceeded=$false};$p|Add-Member ScriptMethod WaitForExit {param($ms)$this.waitMilliseconds=$ms;if($this.waitThrows){throw 'wait failure'};return $this.waitResult};$p}
$record=[ordered]@{completionKnown=$false;exitCode=$null};$process=FakeProcess $true ([int]0);Complete-NativeProbeProcess $process $record 30;Check ($record.completionKnown-and$record.exitCode-eq0-and$process.waitMilliseconds-eq30000) 'successful process completion'
$record=[ordered]@{completionKnown=$false;exitCode=$null};$process=FakeProcess $false ([int]0);Reject {Complete-NativeProbeProcess $process $record 30} 'timeout refuses';Check (-not$record.completionKnown-and$null-eq$record.exitCode) 'timeout remains unknown'
$record=[ordered]@{completionKnown=$false;exitCode=$null};$process=FakeProcess $true ([int]3);Reject {Complete-NativeProbeProcess $process $record 30} 'nonzero exit refuses';Check ($record.completionKnown-and$record.exitCode-eq3) 'failed exit still determinate'
$record=[ordered]@{completionKnown=$false;exitCode=$null};$process=FakeProcess $true $null;Reject {Complete-NativeProbeProcess $process $record 30} 'missing exit code refuses';Check $record.completionKnown 'observed exit remains determinate'
$record=[ordered]@{completionKnown=$false;exitCode=$null};$process=FakeProcess $true ([int]0);$process.OutputLimitExceeded=$true;Reject {Complete-NativeProbeProcess $process $record 30} 'capture overflow refuses';Check ($record.completionKnown-and$record.exitCode-eq0) 'overflow exit remains determinate'
$record=[ordered]@{completionKnown=$false;exitCode=$null};$process=FakeProcess $false $null;$process.waitThrows=$true;Reject {Complete-NativeProbeProcess $process $record 30} 'wait failure';Check (-not$record.completionKnown) 'wait failure remains unknown'
$root=Join-Path ([IO.Path]::GetTempPath()) ('n2r-native-probe-test-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $root|Out-Null
try{
 $ordinary=Join-Path $root 'input.bin';[IO.File]::WriteAllBytes($ordinary,[byte[]]@(1,2,3));$hash=(Get-FileHash -LiteralPath $ordinary -Algorithm SHA256).Hash.ToLowerInvariant()
 $pin=Open-NativeProbeInput $ordinary $hash 3
 try{Check ($pin.Position-eq0-and$pin.Length-eq3) 'pin hash and rewind';Reject {[IO.File]::Open($ordinary,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite).Dispose()} 'pin prevents writer';$bytes=Read-NativeProbeArtifact $ordinary 3;Check ($bytes.Length-eq3-and$bytes[2]-eq3) 'bounded ordinary read'}finally{$pin.Dispose()}
 Reject {Open-NativeProbeInput $ordinary ('0'*64) 3} 'wrong hash';Reject {Open-NativeProbeInput $ordinary $hash 2} 'input bound';Reject {Read-NativeProbeArtifact $ordinary 2} 'report bound';Reject {Read-NativeProbeArtifact $root 16} 'directory artifact'
 $empty=Join-Path $root 'empty.bin';[IO.File]::WriteAllBytes($empty,[byte[]]@());Check ((Read-NativeProbeArtifact $empty 1 -AllowEmpty).Length-eq0) 'empty stdout allowed';Reject {Read-NativeProbeArtifact $empty 1} 'empty report refused'
 Write-NativeProbeRecord 'process-result.json' ([pscustomobject]@{status='failed-preserved';completionKnown=$false});$bytes=[IO.File]::ReadAllBytes((Join-Path $root 'process-result.json'));Check ($bytes[0]-eq123) 'record without BOM';Reject {Write-NativeProbeRecord 'process-result.json' @{status='overwrite'}} 'record overwrite refused';Reject {Write-NativeProbeRecord 'large.json' @{data=('x'*65536)}} 'record bound'
}finally{$full=[IO.Path]::GetFullPath($root);$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath());if(-not$full.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)-or[IO.Path]::GetFileName($full)-notlike'n2r-native-probe-test-*'){throw 'Unsafe temporary cleanup path.'};Remove-Item -LiteralPath $full -Recurse -Force}
&$path -RunId $id -ProbeId ('b'*32) -RequestSha256 ('c'*64) -BinarySha256 ('d'*64) -WhatIf;$script:checks++
Write-Output ("Guest native probe: {0} pure/fake-process/ordinary-file/WhatIf checks passed; no VM/device calls."-f$script:checks)
