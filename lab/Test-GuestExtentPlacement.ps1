<# Pure buffers/ABI/pattern/guard tests. Never calls Run or native controls. #>
[CmdletBinding()]
param([string]$NativeControlDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$nativePath=Join-Path $PSScriptRoot 'guest\NativeExtentPlacement.cs'
Add-Type -Path $nativePath
$tokens=$null;$errors=$null
$scriptPath=Join-Path $PSScriptRoot 'guest\Invoke-GuestExtentPlacement.ps1'
$ast=[Management.Automation.Language.Parser]::ParseFile($scriptPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Placement script parser errors.'}
foreach($function in $ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){Invoke-Expression $function.Extent.Text}
$script:checks=0
function Check([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$refused=$false;try{& $Action|Out-Null}catch{$refused=$true};Check $refused $Message}
function Clone($Value){$Value|ConvertTo-Json -Depth 16|ConvertFrom-Json}
function Extent([long]$Start,[long]$End,[long]$Lcn){$result=New-Object Ntfs2Refs.PlacementExtent;$result.startingVcn=$Start;$result.nextVcn=$End;$result.lcn=$Lcn;$result}
function ExtentBuffer([long[]]$Ends,[long[]]$Lcns){$bytes=New-Object byte[] (16+16*$Ends.Count);[BitConverter]::GetBytes([uint32]$Ends.Count).CopyTo($bytes,0);for($i=0;$i -lt $Ends.Count;$i++){[BitConverter]::GetBytes($Ends[$i]).CopyTo($bytes,16+16*$i);[BitConverter]::GetBytes($Lcns[$i]).CopyTo($bytes,24+16*$i)};,$bytes}
function Bitmap { $bytes=New-Object byte[] (16+13631488/8);[BitConverter]::GetBytes([long]13631488).CopyTo($bytes,8);,$bytes }
$id='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
Check ([Ntfs2Refs.NativeExtentPlacement]::FixturePath($id) -ceq ('F:\fixtures\placement-'+$id+'\initialized.bin')) 'Fixture path differs.'
foreach($bad in @('','a',('A'*32),('../'+$id),($id+':$DATA'),($id+'\x'))){Reject {[Ntfs2Refs.NativeExtentPlacement]::FixturePath($bad)} 'Ambiguous or unbounded probe ID accepted.'}
$volume='\\?\Volume{00c9f113-e0b9-49d8-b031-130aef8ef3fb}\'
Check ([Ntfs2Refs.NativeExtentPlacement]::VolumeName($volume) -ceq $volume.TrimEnd('\')) 'Native volume GUID refused.'
foreach($bad in @('F:','F:\','\\.\PhysicalDrive1','\\server\share',($volume+'x'),'\\?\Volume{00000000-0000-0000-0000-000000000000}\')){Reject {[Ntfs2Refs.NativeExtentPlacement]::VolumeName($bad)} 'Unsafe volume name accepted.'}
$pattern=[Ntfs2Refs.NativeExtentPlacement]::Pattern($id)
Check ($pattern.Length -eq 65536) 'Pattern length differs.'
Check ([Ntfs2Refs.NativeExtentPlacement]::Hash($pattern) -ceq '06295f3f017355ae0a4aa20453f6294b1d1fc438fcc2cee6a1fcc7c5b509e5c4') 'Pattern known answer differs.'
Check ([Ntfs2Refs.NativeExtentPlacement]::Hash([Ntfs2Refs.NativeExtentPlacement]::Pattern('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')) -cne [Ntfs2Refs.NativeExtentPlacement]::Hash($pattern)) 'Run identity absent from pattern.'
$clusterHashes=@()
for($i=0;$i -lt 16;$i++){$cluster=New-Object byte[] 4096;[Array]::Copy($pattern,$i*4096,$cluster,0,4096);$clusterHashes+=[Ntfs2Refs.NativeExtentPlacement]::Hash($cluster);Check ([Text.Encoding]::ASCII.GetString($cluster,0,80).Contains(('cluster={0:D2}|' -f $i))) 'Cluster index marker missing.'}
Check (@($clusterHashes|Select-Object -Unique).Count -eq 16) 'Clusters share a pattern.'
$one=ExtentBuffer @(16) @(2000000)
$parsed=[Ntfs2Refs.NativeExtentPlacement]::ParseExtents($one,16)
Check ($parsed.Count -eq 1 -and $parsed[0].lcn -eq 2000000 -and $parsed[0].nextVcn -eq 16) 'Ordinary contiguous map refused.'
$fragmented=[Ntfs2Refs.NativeExtentPlacement]::ParseExtents((ExtentBuffer @(5,16) @(2000000,2001000)),16)
Check ($fragmented.Count -eq 2 -and $fragmented[1].startingVcn -eq 5) 'Fragmented map lost its VCN boundary.'
foreach($buffer in @((New-Object byte[] 16),(ExtentBuffer @(15) @(2000000)),(ExtentBuffer @(17) @(2000000)),(ExtentBuffer @(16) @(-1)),(ExtentBuffer @(16) @([long]::MaxValue)),(ExtentBuffer @(5,5) @(1,2)))){Reject {[Ntfs2Refs.NativeExtentPlacement]::ParseExtents($buffer,16)} 'Malformed/incomplete/sparse mapping accepted.'}
$bad=[byte[]]$one.Clone();[BitConverter]::GetBytes([long]1).CopyTo($bad,8);Reject {[Ntfs2Refs.NativeExtentPlacement]::ParseExtents($bad,16)} 'Rounded starting VCN accepted.'
$original=[Ntfs2Refs.PlacementExtent[]]@((Extent 0 1024 1507328));$probe=[Ntfs2Refs.PlacementExtent[]]@((Extent 0 16 2000000))
$legacy=Bitmap;$metadata=Bitmap
Check ([Ntfs2Refs.NativeExtentPlacement]::SelectCandidate($legacy,$metadata,$original,$probe) -eq 65536) 'First bounded candidate differs.'
$metadata[16+65536/8]=1
Check ([Ntfs2Refs.NativeExtentPlacement]::SelectCandidate($legacy,$metadata,$original,$probe) -eq 65552) 'Metadata-flag allocation was ignored.'
$legacy[16+65552/8]=1
Check ([Ntfs2Refs.NativeExtentPlacement]::SelectCandidate($legacy,$metadata,$original,$probe) -eq 65568) 'Legacy allocation was ignored.'
$legacy=Bitmap;$metadata=Bitmap
$overlapOriginal=[Ntfs2Refs.PlacementExtent[]]@((Extent 0 1024 65536))
Check ([Ntfs2Refs.NativeExtentPlacement]::SelectCandidate($legacy,$metadata,$overlapOriginal,$probe) -eq 66560) 'Original stream range was not excluded.'
$overlapProbe=[Ntfs2Refs.PlacementExtent[]]@((Extent 0 16 65536))
Check ([Ntfs2Refs.NativeExtentPlacement]::SelectCandidate($legacy,$metadata,$original,$overlapProbe) -eq 65552) 'New file source range was not excluded.'
# Occupy all earlier bits so the next candidate straddles a known anchor neighborhood.
for($i=16;$i -lt 16+136320/8;$i++){$legacy[$i]=255}
Check ([Ntfs2Refs.NativeExtentPlacement]::SelectCandidate($legacy,$metadata,$original,$probe) -eq 136368) 'Checkpoint anchor neighborhood was not excluded.'
$partial=New-Object byte[] 32;[BitConverter]::GetBytes([long]13631488).CopyTo($partial,8)
Reject {[Ntfs2Refs.NativeExtentPlacement]::SelectCandidate($partial,$metadata,$original,$probe)} 'Partial legacy bitmap accepted.'
Reject {[Ntfs2Refs.NativeExtentPlacement]::SelectCandidate($metadata,$partial,$original,$probe)} 'Partial metadata bitmap accepted.'
$wrong=[byte[]]$metadata.Clone();[BitConverter]::GetBytes([long]999999999).CopyTo($wrong,8)
Reject {[Ntfs2Refs.NativeExtentPlacement]::SelectCandidate($wrong,$metadata,$original,$probe)} 'Virtual bitmap count was silently truncated.'
$wrong=[byte[]]$metadata.Clone();[BitConverter]::GetBytes([long]8).CopyTo($wrong,0)
Reject {[Ntfs2Refs.NativeExtentPlacement]::SelectCandidate($metadata,$wrong,$original,$probe)} 'Nonzero bitmap start accepted.'
Check ([Ntfs2Refs.NativeExtentPlacement]::Overlap(10,16,25,1)) 'Overlap endpoint lost.'
Check (-not [Ntfs2Refs.NativeExtentPlacement]::Overlap(10,16,26,1)) 'Adjacent ranges overlap.'
Reject {[Ntfs2Refs.NativeExtentPlacement]::Overlap([long]::MaxValue,1,0,1)} 'Overlap overflow accepted.'
$input=[Ntfs2Refs.NativeExtentPlacement]::MoveInput(1234,0,65536,16)
Check ($input.Length -eq 32 -and [BitConverter]::ToInt64($input,0) -eq 1234 -and [BitConverter]::ToInt64($input,8) -eq 0 -and [BitConverter]::ToInt64($input,16) -eq 65536 -and [BitConverter]::ToUInt32($input,24) -eq 16 -and [BitConverter]::ToUInt32($input,28) -eq 0) 'x64 MOVE_FILE_DATA layout/padding differs.'
foreach($values in @(@(0,0,65536,16),@(-1,0,65536,16),@(1234,1,65536,16),@(1234,0,65535,16),@(1234,0,65537,16),@(1234,0,13631488,16),@(1234,0,[long]::MaxValue,16),@(1234,0,65536,17),@(1234,0,65536,0))){Reject {[Ntfs2Refs.NativeExtentPlacement]::MoveInput([long]$values[0],[long]$values[1],[long]$values[2],[int]$values[3])} 'Unsafe or non-single move accepted.'}
if($NativeControlDirectory){
 $control=Read-ExtentPlacementJson (Join-Path $NativeControlDirectory 'after\verify.json')
 $allocation=Read-ExtentPlacementJson (Join-Path $NativeControlDirectory 'after\allocation-after.json')
 Assert-ExtentPlacementControl $control $control.runId;$script:checks++
 $fixture=Get-ExtentPlacementFixture $allocation $control.target.guest
 Check ($fixture.length -eq 4MB) 'Saved native fixture rejected.'
 foreach($pair in @(@('conversionQualified',$true),@('remountVerified',$false),@('status','prepared'))){$bad=Clone $control;$bad.($pair[0])=$pair[1];Reject {Assert-ExtentPlacementControl $bad $control.runId} 'Unqualified control accepted.'}
 $bad=Clone $allocation;$bad.filesystemDriver.sha256=('f'*64);Reject {Get-ExtentPlacementFixture $bad $control.target.guest} 'Changed driver accepted.'
 $script:mockDisk=[pscustomobject]@{Number=1;Guid=$control.partition.diskGuid;LogicalSectorSize=512;PhysicalSectorSize=4096}
 $script:mockPart=[pscustomobject]@{DiskNumber=1;Guid=$control.partition.guid;PartitionNumber=2;Offset=16MB;Size=52GB;DriveLetter='F';IsBoot=$false;IsSystem=$false}
 $script:mockVolume=[pscustomobject]@{FileSystem='ReFS';FileSystemLabel='ntfs2refs-target';AllocationUnitSize=4096;Size=52GB;UniqueId=$volume}
 function Get-LabGuestDisk {param($Identity)$script:mockDisk}
 function Get-Partition {param($DiskNumber,$DriveLetter)$script:mockPart}
 function Get-Volume {param($DriveLetter)$script:mockVolume}
 Check ((Get-ExtentPlacementTarget $control.target.guest $control).partition.Size -eq 52GB) 'Owned target rejected.'
 foreach($pair in @(@('Guid',[guid]::NewGuid().ToString()),@('Size',50GB),@('DriveLetter','C'),@('IsBoot',$true),@('IsSystem',$true))){$saved=$script:mockPart.($pair[0]);$script:mockPart.($pair[0])=$pair[1];Reject {Get-ExtentPlacementTarget $control.target.guest $control} 'Wrong/system partition accepted.';$script:mockPart.($pair[0])=$saved}
}
$nativeText=Get-Content -LiteralPath $nativePath -Raw
Check ($nativeText -notmatch 'SetFileValidData|SetFilePointer|WriteFile|AdjustTokenPrivileges|FSCTL_SET|0x00090018|0x00090020') 'Unreviewed low-level write/policy/lock interface appeared.'
Check ([regex]::Matches($nativeText,'Query\(result,volume,"move",0x00090074').Count -eq 1) 'Move control is not a single call site.'
Check ($nativeText.IndexOf('candidateMetadataBitmap') -gt $nativeText.IndexOf('result.creationFlushed=true')) 'Bitmap observation precedes initialization.'
$dry=& $scriptPath -ControlRunId $id -ControlEvidenceSha256 ('a'*64) -CapturedAllocationSha256 ('b'*64) -ProbeId $id -WhatIf
Check ($dry.DryRun -eq $true -and $dry.MaximumFixtureBytes -eq 65536 -and $dry.MaximumMoveCalls -eq 1 -and $dry.ConversionQualified -eq $false) 'WhatIf contract differs.'
[pscustomobject]@{Status='passed';Checks=$script:checks;NativeControlsExecuted=$false;VMOperations=$false}
