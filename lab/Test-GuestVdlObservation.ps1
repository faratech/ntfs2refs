<# Pure parsers, fake lifecycle and saved ordinary evidence. No device/VM calls. #>
[CmdletBinding()]
param([string]$SourceDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$nativePath=Join-Path $PSScriptRoot 'guest\NativeVdlObservation.cs'
if(-not ('Ntfs2Refs.FakeVdlObservationApi' -as [type])){Add-Type -TypeDefinition ((Get-Content -LiteralPath $nativePath -Raw)+[Environment]::NewLine+(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'FakeVdlObservation.cs') -Raw))}
$scriptPath=Join-Path $PSScriptRoot 'guest\Capture-GuestVdlObservation.ps1';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($scriptPath,[ref]$tokens,[ref]$errors);if($errors.Count){throw 'Guest observation parse failed.'}
foreach($f in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){Invoke-Expression $f.Extent.Text}
$script:checks=0
function Check([bool]$Value,[string]$Message){if(-not $Value){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$rejected=$false;try{& $Action|Out-Null}catch{$rejected=$true};Check $rejected $Message}
function Clone($Value){$Value|ConvertTo-Json -Depth 18|ConvertFrom-Json}
function Regions([object[]]$Entries){$b=New-Object byte[] (16+24*$Entries.Count);[BitConverter]::GetBytes([uint32]$Entries.Count).CopyTo($b,4);[BitConverter]::GetBytes([uint32]$Entries.Count).CopyTo($b,8);for($i=0;$i -lt $Entries.Count;$i++){$e=$Entries[$i];[BitConverter]::GetBytes([long]$e[0]).CopyTo($b,16+24*$i);[BitConverter]::GetBytes([long]$e[1]).CopyTo($b,24+24*$i);[BitConverter]::GetBytes([uint32]$e[2]).CopyTo($b,32+24*$i)};,$b}
foreach($usage in @(1,2)){$b=[Ntfs2Refs.NativeVdlObservation]::RegionInput($usage);Check ($b.Length -eq 24 -and [BitConverter]::ToInt64($b,0) -eq 0 -and [BitConverter]::ToInt64($b,8) -eq 65536 -and [BitConverter]::ToUInt32($b,16) -eq $usage -and [BitConverter]::ToUInt32($b,20) -eq 0) 'Region ABI differs.'}
foreach($usage in @(0,3,4,255)){Reject {[Ntfs2Refs.NativeVdlObservation]::RegionInput($usage)} 'Unknown usage accepted.'}
$standard=[Ntfs2Refs.FakeVdlObservationApi]::Standard();Check (([Ntfs2Refs.NativeVdlObservation]::ParseStandard($standard)).eofBytes -eq 65536) 'Standard observation lost.'
foreach($pair in @(@(0,-1),@(0,65537),@(8,0),@(8,65537))){$b=[byte[]]$standard.Clone();[BitConverter]::GetBytes([long]$pair[1]).CopyTo($b,$pair[0]);Reject {[Ntfs2Refs.NativeVdlObservation]::ParseStandard($b)} 'Unbounded standard state accepted.'}
foreach($offset in @(16,20,21)){$b=[byte[]]$standard.Clone();$b[$offset]=2;Reject {[Ntfs2Refs.NativeVdlObservation]::ParseStandard($b)} 'Type/link/deletion state accepted.'}
Reject {[Ntfs2Refs.NativeVdlObservation]::ParseStandard((New-Object byte[] 25))} 'Oversized standard accepted.'
$ext=[Ntfs2Refs.FakeVdlObservationApi]::Extents();$rows=[Ntfs2Refs.NativeVdlObservation]::ParseSignedExtents($ext)
Check ($rows.Count -eq 2 -and $rows[0].lcn -eq -1 -and $rows[0].negativeMarker -and $rows[0].interpretation -ceq 'unresolved-ReFS-negative-marker' -and $rows[1].lcn -eq 1508352) 'Negative marker discarded/reinterpreted.'
foreach($negative in @(-2,[long]::MinValue)){$b=[byte[]]$ext.Clone();[BitConverter]::GetBytes([long]$negative).CopyTo($b,24);$rows=[Ntfs2Refs.NativeVdlObservation]::ParseSignedExtents($b);Check ($rows[0].negativeMarker -and $rows[0].lcn -eq $negative) 'Unknown signed marker lost.'}
foreach($pair in @(@(8,1),@(16,0),@(16,17),@(32,15),@(32,17),@(40,13631488),@(40,[long]::MaxValue))){$b=[byte[]]$ext.Clone();[BitConverter]::GetBytes([long]$pair[1]).CopyTo($b,$pair[0]);Reject {[Ntfs2Refs.NativeVdlObservation]::ParseSignedExtents($b)} 'Malformed extent bounds accepted.'}
foreach($size in @(0,16,31,49,273)){Reject {[Ntfs2Refs.NativeVdlObservation]::ParseSignedExtents((New-Object byte[] $size))} 'Malformed extent buffer accepted.'}
$cached=[Ntfs2Refs.NativeVdlObservation]::ParseRegions(([Ntfs2Refs.FakeVdlObservationApi]::Region(1)),1);$disk=[Ntfs2Refs.NativeVdlObservation]::ParseRegions(([Ntfs2Refs.FakeVdlObservationApi]::Region(0)),2)
Check ($cached.prefixBytes -eq 65536 -and $cached.prefixIsSummaryOnly -and $disk.prefixBytes -eq 0) 'Cache/storage distinction lost.'
$island=[Ntfs2Refs.NativeVdlObservation]::ParseRegions((Regions @(@(0,4096,0),@(4096,61440,1))),1)
Check ($island.complete -and -not $island.prefixShaped -and $island.prefixBytes -eq -1 -and $island.regions.Count -eq 2) 'Validity island mislabeled scalar.'
foreach($entries in @(@(,@(0,65535,1)),@(,@(1,65535,1)),@(,@(0,65537,1)),@(,@(0,-1,1)),@(,@(0,65536,32)),@(@(0,4096,1),@(4095,61441,0)))){Reject {[Ntfs2Refs.NativeVdlObservation]::ParseRegions((Regions $entries),1)} 'Invalid coverage accepted.'}
Reject {[Ntfs2Refs.NativeVdlObservation]::ParseRegions((New-Object byte[] 16),1)} 'Absent regions interpreted as zero validity.'
$api=New-Object Ntfs2Refs.FakeVdlObservationApi;$result=[Ntfs2Refs.NativeVdlObservation]::CollectWith($api,[Ntfs2Refs.NativeVdlObservation]::VolumePath)
Check ($result.status -ceq 'metadata-observed' -and $result.observationComplete -and $result.stableDuringObservation -and $result.identityVerified -and $result.cleanupComplete -and $api.queryCount -eq 8 -and $api.volumeCount -eq 2 -and $api.closed) 'Fake lifecycle differs.'
Check ($result.volumes[0].supportsSparseVdl -and -not $result.volumes[0].readOnlyVolume) 'Sparse VDL flag lost.'
foreach($flag in @('newFilePayloadReads','newFilePayloadWrites','targetWriteRequestsIssued','explicitFlushRequested','moveAttempted','setValidDataAttempted','allocationRequested','protectionChanged','privilegeAdjustmentAttempted','physicalMappingVerified','zeroVdlQualified','payloadCopyAvoidanceVerified','conversionQualified')){Check (-not $result.$flag) 'Unperformed operation asserted.'}
foreach($fault in @('open','throw','identity','volume-identity','oversize')){$api=New-Object Ntfs2Refs.FakeVdlObservationApi;$api.fault=$fault;$r=[Ntfs2Refs.NativeVdlObservation]::CollectWith($api,[Ntfs2Refs.NativeVdlObservation]::VolumePath);Check ($r.status -ceq 'blocked' -and $r.error -and $r.cleanupComplete -and $api.closed -and -not $r.identityVerified) 'Native failure not bounded/closed.'}
foreach($fault in @('refusal','malformed','volume')){$api=New-Object Ntfs2Refs.FakeVdlObservationApi;$api.fault=$fault;$r=[Ntfs2Refs.NativeVdlObservation]::CollectWith($api,[Ntfs2Refs.NativeVdlObservation]::VolumePath);Check ($r.status -ceq 'native-query-unresolved' -and $r.identityVerified -and -not $r.observationComplete -and $r.cleanupComplete -and $api.queryCount -eq 8) 'Determinate refusal lost.'}
foreach($fault in @('changed','volume-change','attributes')){$api=New-Object Ntfs2Refs.FakeVdlObservationApi;$api.fault=$fault;$r=[Ntfs2Refs.NativeVdlObservation]::CollectWith($api,[Ntfs2Refs.NativeVdlObservation]::VolumePath);Check ($r.observationComplete -and -not $r.stableDuringObservation) 'Changed observation claimed stable.'}
$api=New-Object Ntfs2Refs.FakeVdlObservationApi;$api.fault='close';$r=[Ntfs2Refs.NativeVdlObservation]::CollectWith($api,[Ntfs2Refs.NativeVdlObservation]::VolumePath);Check ($r.status -ceq 'cleanup-failed' -and -not $r.cleanupComplete -and $r.cleanupError) 'Cleanup failure hidden.'
foreach($volume in @('', '\\.\C:', ([Ntfs2Refs.NativeVdlObservation]::VolumePath+[char]10))){$api=New-Object Ntfs2Refs.FakeVdlObservationApi;Reject {[Ntfs2Refs.NativeVdlObservation]::CollectWith($api,$volume)} 'Wrong volume accepted.';Check (-not $api.opened) 'Invalid volume reached native boundary.'}
if($SourceDirectory){$source=Read-VdlObservationJson (Join-Path $SourceDirectory 'allocation\allocation.json');Assert-VdlObservationSource $source;$script:checks++;foreach($pair in @(@('status','metadata-observed'),@('zeroVdlQualified',$true),@('newFilePayloadReads',$true),@('controlQualified',$false),@('nativeSourceSha256',('a'*64)))){$bad=Clone $source;$bad.($pair[0])=$pair[1];Reject {Assert-VdlObservationSource $bad} 'Changed source accepted.'};$bad=Clone $source;$bad.allocationObservation.operations[1].succeeded=$false;Reject {Assert-VdlObservationSource $bad} 'Failed EOF accepted.';$actual=[IO.File]::ReadAllBytes((Join-Path $SourceDirectory 'allocation\allocation-immediateExtents.bin'));$rows=[Ntfs2Refs.NativeVdlObservation]::ParseSignedExtents($actual);Check ($rows[0].lcn -eq -1 -and $rows[1].lcn -eq 1508352) 'Exact native byte regression failed.'}
$text=Get-Content -LiteralPath $nativePath -Raw
Check ($text -notmatch 'ReadFile|WriteFile|FileStream|ComputeHash|FlushFileBuffers|SetFileInformationByHandle|SetFileValidData|AdjustTokenPrivileges|0x00090074|0x90074|IOCTL_DISK_SET|FSCTL_LOCK') 'Payload or mutation entry point introduced.'
Check ($text -match 'MetadataAccess=0x00020080' -and $text -notmatch '0x80000000|0x40000000') 'File access gained data/write rights.'
$dry=& $scriptPath -ObservationId ('a'*32) -WhatIf;Check ($dry.DryRun -and -not $dry.NewFilePayloadReads -and -not $dry.TargetWriteRequestsIssued) 'Guest WhatIf differs.'
Reject {& $scriptPath -ObservationId (('a'*32)+[char]10) -WhatIf} 'Ambiguous output ID accepted.'
[pscustomobject]@{Status='passed';Checks=$script:checks;NativeOperations=$false;VMOperations=$false}
