<# Pure ABI/parser/ACL and mocked evidence guards. No native calls or file allocation. #>
[CmdletBinding()]
param([string]$PlacementDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$nativePath=Join-Path $PSScriptRoot 'guest\NativeVdlProbe.cs';Add-Type -Path $nativePath
$scriptPath=Join-Path $PSScriptRoot 'guest\Invoke-GuestVdlProbe.ps1';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($scriptPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'VDL script parse failed.'}
foreach($function in $ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){Invoke-Expression $function.Extent.Text}
$script:checks=0
function Check([bool]$Value,[string]$Message){if(-not $Value){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$rejected=$false;try{& $Action|Out-Null}catch{$rejected=$true};Check $rejected $Message}
function Clone($Value){$Value|ConvertTo-Json -Depth 18|ConvertFrom-Json}
function Standard([long]$Allocation=65536,[long]$Eof=65536){$bytes=New-Object byte[] 24;[BitConverter]::GetBytes($Allocation).CopyTo($bytes,0);[BitConverter]::GetBytes($Eof).CopyTo($bytes,8);[BitConverter]::GetBytes([uint32]1).CopyTo($bytes,16);,$bytes}
function Regions([object[]]$Entries){$bytes=New-Object byte[] (16+24*$Entries.Count);[BitConverter]::GetBytes([uint32]$Entries.Count).CopyTo($bytes,4);[BitConverter]::GetBytes([uint32]$Entries.Count).CopyTo($bytes,8);for($i=0;$i -lt $Entries.Count;$i++){$e=$Entries[$i];[BitConverter]::GetBytes([long]$e[0]).CopyTo($bytes,16+24*$i);[BitConverter]::GetBytes([long]$e[1]).CopyTo($bytes,24+24*$i);[BitConverter]::GetBytes([uint32]$e[2]).CopyTo($bytes,32+24*$i)};,$bytes}
$id='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';$sid='S-1-5-21-1-2-3-1001'
Check ([Ntfs2Refs.NativeVdlProbe]::PathFor($id,$false) -ceq ('F:\fixtures\vdl-'+$id+'\uninitialized.bin')) 'Allocation path differs.'
Check ([Ntfs2Refs.NativeVdlProbe]::PathFor($id,$true) -ceq ('F:\fixtures\placement-'+$id+'\initialized.bin')) 'Control path differs.'
foreach($bad in @('',('A'*32),($id+'\x'),('../'+$id),($id+':x'),($id+[char]10))){Reject {[Ntfs2Refs.NativeVdlProbe]::PathFor($bad,$false)} 'Ambiguous file identifier accepted.'}
foreach($usage in @(1,2)){$input=[Ntfs2Refs.NativeVdlProbe]::RegionInput($usage);Check ($input.Length -eq 24 -and [BitConverter]::ToInt64($input,0) -eq 0 -and [BitConverter]::ToInt64($input,8) -eq 65536 -and [BitConverter]::ToUInt32($input,16) -eq $usage -and [BitConverter]::ToUInt32($input,20) -eq 0) 'Region ABI or padding differs.'}
foreach($usage in @(0,3,4,16,255)){Reject {[Ntfs2Refs.NativeVdlProbe]::RegionInput($usage)} 'Unreviewed usage request accepted.'}
Check (([Ntfs2Refs.NativeVdlProbe]::ParseStandard((Standard))).eofBytes -eq 65536) 'Standard EOF differs.'
Check (([Ntfs2Refs.NativeVdlProbe]::ParseStandard((Standard 65536 0))).allocationBytes -eq 65536) 'Allocation-only state refused.'
Check (([Ntfs2Refs.NativeVdlProbe]::ParseStandard((Standard 0 0))).eofBytes -eq 0) 'Fresh empty state refused.'
# Exact native bytes from allocation-emptyStandard.bin in the first guest run.
$emptyNativeHex='000400000000000000000000000000000100000000000000'
$emptyNative=[byte[]]@(for($i=0;$i -lt $emptyNativeHex.Length;$i+=2){[Convert]::ToByte($emptyNativeHex.Substring($i,2),16)})
$initial=[Ntfs2Refs.NativeVdlProbe]::ParseInitialStandard($emptyNative)
Check ($initial.allocationBytes -eq 1024 -and $initial.eofBytes -eq 0 -and $initial.links -eq 1 -and -not $initial.directory -and -not $initial.deletePending) 'Measured native initial empty-file state refused.'
Check (([Ntfs2Refs.NativeVdlProbe]::ParseInitialStandard((Standard 0 0))).allocationBytes -eq 0) 'Initial zero-allocation alternative refused.'
Reject {[Ntfs2Refs.NativeVdlProbe]::ParseStandard($emptyNative)} 'Initial 1024-byte exception leaked into ordinary allocation qualification.'
foreach($pair in @(@(-1,0),@(512,0),@(1023,0),@(1025,0),@(2048,0),@(4096,0),@(65536,0),@(1024,1),@(1024,1024),@(0,1))){Reject {[Ntfs2Refs.NativeVdlProbe]::ParseInitialStandard((Standard $pair[0] $pair[1]))} 'Unmeasured initial state or nonzero EOF accepted.'}
Reject {[Ntfs2Refs.NativeVdlProbe]::ParseInitialStandard((New-Object byte[] 23))} 'Truncated initial native response accepted.'
foreach($offset in @(16,20,21)){$bad=[byte[]]$emptyNative.Clone();$bad[$offset]=2;Reject {[Ntfs2Refs.NativeVdlProbe]::ParseInitialStandard($bad)} 'Initial file link/type/delete constraint weakened.'}
foreach($pair in @(@(-1,0),@(65537,0),@(4097,0),@(4096,8192),@(65536,-1))){Reject {[Ntfs2Refs.NativeVdlProbe]::ParseStandard((Standard $pair[0] $pair[1]))} 'Unbounded standard state accepted.'}
Reject {[Ntfs2Refs.NativeVdlProbe]::ParseStandard((New-Object byte[] 23))} 'Truncated standard state accepted.'
foreach($offset in @(16,20,21)){$bad=Standard;$bad[$offset]=2;Reject {[Ntfs2Refs.NativeVdlProbe]::ParseStandard($bad)} 'Link/type/delete state ignored.'}
$valid=Regions @(,@(0,65536,3));$invalid=Regions @(,@(0,65536,0))
foreach($usage in @(1,2)){Check (([Ntfs2Refs.NativeVdlProbe]::ParseRegions($valid,$usage)).vdlBytes -eq 65536) 'Valid range lost.';Check (([Ntfs2Refs.NativeVdlProbe]::ParseRegions($invalid,$usage)).vdlBytes -eq 0) 'Invalid range not identified.'}
$split=Regions @(@(0,4096,1),@(4096,61440,0));$parsed=[Ntfs2Refs.NativeVdlProbe]::ParseRegions($split,1)
Check ($parsed.prefixQualified -and $parsed.vdlBytes -eq 4096) 'Exact VDL boundary differs.'
Check (([Ntfs2Refs.NativeVdlProbe]::ParseRegions($split,2)).vdlBytes -eq 0) 'Cached valid data conflated with on-disk validity.'
$alignment=Regions @(,@(0,65536,28));Check (([Ntfs2Refs.NativeVdlProbe]::ParseRegions($alignment,1)).vdlBytes -eq 0) 'Alignment bits imply valid data.'
$island=Regions @(@(0,4096,0),@(4096,61440,1));$parsed=[Ntfs2Refs.NativeVdlProbe]::ParseRegions($island,1)
Check ($parsed.complete -and -not $parsed.prefixQualified -and $parsed.vdlBytes -eq -1) 'Valid island was mislabeled scalar VDL.'
foreach($entries in @(@(,@(0,65535,1)),@(,@(0,65537,1)),@(,@(1,65535,1)),@(,@(0,-1,1)),@(,@(0,65536,32)),@(@(0,4096,1),@(4095,61441,0)),@(@(0,4096,1),@(4097,61439,0)))){Reject {[Ntfs2Refs.NativeVdlProbe]::ParseRegions((Regions $entries),1)} 'Malformed region coverage/usage accepted.'}
Reject {[Ntfs2Refs.NativeVdlProbe]::ParseRegions((New-Object byte[] 16),1)} 'Zero regions treated as zero VDL.'
$bad=[byte[]]$valid.Clone();[BitConverter]::GetBytes([uint32]2).CopyTo($bad,4);Reject {[Ntfs2Refs.NativeVdlProbe]::ParseRegions($bad,1)} 'Partial region count accepted.'
Reject {[Ntfs2Refs.NativeVdlProbe]::ParseRegions((New-Object byte[] 401),1)} 'Region output bound ignored.'
foreach($directory in @($false,$true)){$sddl=[Ntfs2Refs.NativeVdlProbe]::PrivateSddl($sid,$directory);[Ntfs2Refs.NativeVdlProbe]::ValidatePrivateSddl($sddl,$sid,$directory);$script:checks++;Reject {[Ntfs2Refs.NativeVdlProbe]::ValidatePrivateSddl($sddl.Replace('D:P','D:'),$sid,$directory)} 'Unprotected ACL accepted.';Reject {[Ntfs2Refs.NativeVdlProbe]::ValidatePrivateSddl($sddl.Replace(';;;BA',';;;WD'),$sid,$directory)} 'Everyone ACL accepted.';Reject {[Ntfs2Refs.NativeVdlProbe]::ValidatePrivateSddl($sddl.Replace(';FA;',';FR;'),$sid,$directory)} 'Unexpected access mask accepted.'}
foreach($bad in @('S-1-5-18','S-1-1-0','S-1-5-32-544','S-1-5-21-1-2-3-1001)D:')){Reject {[Ntfs2Refs.NativeVdlProbe]::PrivateSddl($bad,$false)} 'Unqualified private user SID accepted.'}
$extent=New-Object byte[] 32;[BitConverter]::GetBytes([uint32]1).CopyTo($extent,0);[BitConverter]::GetBytes([long]16).CopyTo($extent,16);[BitConverter]::GetBytes([long]1508384).CopyTo($extent,24)
Check (([Ntfs2Refs.NativeVdlProbe]::ParseExtents($extent))[0].lcn -eq 1508384) 'Extent control rejected.'
foreach($pair in @(@(8,1),@(16,15),@(16,17),@(24,-1),@(24,[long]::MaxValue))){$bad=[byte[]]$extent.Clone();[BitConverter]::GetBytes([long]$pair[1]).CopyTo($bad,$pair[0]);Reject {[Ntfs2Refs.NativeVdlProbe]::ParseExtents($bad)} 'Malformed VDL file mapping accepted.'}
$proof=[pscustomobject]@{schemaVersion=1;kind='native-vdl-probe';phase='MeasureInitializedControl';measurementId=$id;placementEvidenceSha256=('a'*64);scriptSha256=('b'*64);nativeSourceSha256=('c'*64);status='initialized-vdl-control-qualified';controlQualified=$true;originalFixturesUnchanged=$true;targetWriteRequestsIssued=$false;newFilePayloadReads=$false;newFilePayloadWrites=$false;moveAttempted=$false;setValidDataAttempted=$false;privilegeAdjustmentAttempted=$false;physicalMappingVerified=$false;payloadCopyAvoidanceVerified=$false;conversionQualified=$false}
Assert-VdlControl $proof $id ('a'*64) ('b'*64) ('c'*64);$script:checks++
foreach($pair in @(@('status','blocked'),@('controlQualified',$false),@('originalFixturesUnchanged',$false),@('targetWriteRequestsIssued',$true),@('newFilePayloadReads',$true),@('moveAttempted',$true),@('nativeSourceSha256',('d'*64)),@('measurementId',('b'*32)))){$bad=Clone $proof;$bad.($pair[0])=$pair[1];Reject {Assert-VdlControl $bad $id ('a'*64) ('b'*64) ('c'*64)} 'Unqualified or changed stage-one proof accepted.'}
if($PlacementDirectory){$placement=Read-VdlProbeJson (Join-Path $PlacementDirectory 'guest\placement.json');Assert-VdlPlacement $placement $placement.probeId;$script:checks++;$bad=Clone $placement;$bad.after.extents[0].lcn++;Reject {Assert-VdlPlacement $bad $placement.probeId} 'Changed placement accepted.'}
$text=Get-Content -LiteralPath $nativePath -Raw
Check ($text -notmatch 'SetFileValidData|AdjustTokenPrivileges|0x00090074|WriteFile|ReadFile|SetFilePointer') 'Forbidden native operation introduced.'
$allocationBody=$text.Substring($text.IndexOf('public static VdlResult AllocateZero('))
Check ($allocationBody -notmatch 'HashKnown|FileStream|ComputeHash|\.Write\(') 'Allocation stage accesses payload.'
Check ([regex]::Matches($allocationBody,'SetSize\(result,file,').Count -eq 2) 'Allocation/EOF call bound changed.'
$dry=& $scriptPath -Phase MeasureInitializedControl -PlacementProbeId $id -PlacementEvidenceSha256 ('a'*64) -MeasurementId $id -WhatIf
Check ($dry.DryRun -and -not $dry.NewFilePayloadReads -and -not $dry.SetValidDataAttempted) 'Read-only WhatIf differs.'
Reject {& $scriptPath -Phase AllocateZeroVdl -PlacementProbeId $id -PlacementEvidenceSha256 ('a'*64) -MeasurementId $id -WhatIf} 'Allocation accepted without control evidence hash.'
Reject {& $scriptPath -Phase MeasureInitializedControl -PlacementProbeId $id -PlacementEvidenceSha256 ('a'*64) -MeasurementId ($id+[char]10) -WhatIf} 'Trailing newline in measurement ID accepted.'
$dry=& $scriptPath -Phase AllocateZeroVdl -PlacementProbeId $id -PlacementEvidenceSha256 ('a'*64) -MeasurementId $id -ControlEvidenceSha256 ('b'*64) -WhatIf
Check ($dry.DryRun -and $dry.MaximumNewFileBytes -eq 65536 -and -not $dry.NewFilePayloadWrites) 'Allocation WhatIf differs.'
[pscustomobject]@{Status='passed';Checks=$script:checks;NativeOperations=$false;VMOperations=$false}
