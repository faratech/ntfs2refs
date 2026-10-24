<# Pure parsers, mocked guest guards, optional saved JSON. No native controls. #>
[CmdletBinding()]
param([string]$NativeControlDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$nativePath=Join-Path $PSScriptRoot 'guest\NativeExtentDiscovery.cs'
if(-not ('Ntfs2Refs.NativeExtentDiscovery' -as [type])) { Add-Type -Path $nativePath }
$tokens=$null; $errors=$null
$scriptPath=Join-Path $PSScriptRoot 'guest\Capture-GuestExtentDiscovery.ps1'
$ast=[Management.Automation.Language.Parser]::ParseFile($scriptPath,[ref]$tokens,[ref]$errors)
if($errors.Count) { throw 'Discovery script parser errors.' }
foreach($function in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)) { Invoke-Expression $function.Extent.Text }
$script:checks=0
function Check([bool]$Condition,[string]$Message) { if(-not $Condition) { throw $Message }; $script:checks++ }
function Reject([scriptblock]$Action,[string]$Message) { $refused=$false;try{& $Action | Out-Null}catch{$refused=$true};Check $refused $Message }
function Clone($Value) { $Value | ConvertTo-Json -Depth 16 | ConvertFrom-Json }
function Bitmap([long]$Count,[byte[]]$Bits,[long]$Start=0) { $result=New-Object byte[] (16+$Bits.Length);[BitConverter]::GetBytes($Start).CopyTo($result,0);[BitConverter]::GetBytes($Count).CopyTo($result,8);$Bits.CopyTo($result,16);,$result }
$volume='\\?\Volume{00c9f113-e0b9-49d8-b031-130aef8ef3fb}\'
Check ([Ntfs2Refs.NativeExtentDiscovery]::ValidateVolumeName($volume) -ceq $volume.TrimEnd('\')) 'Canonical volume GUID refused.'
foreach($bad in @('F:','F:\','\\.\F:','\\.\PhysicalDrive1','\\server\share','\\?\GLOBALROOT\Device\Harddisk1','\\?\Volume{00000000-0000-0000-0000-000000000000}\',($volume+'file'),($volume.TrimEnd('\')))) { Reject { [Ntfs2Refs.NativeExtentDiscovery]::ValidateVolumeName($bad) } 'Unqualified volume name accepted.' }
Check ([Ntfs2Refs.NativeExtentDiscovery]::BitmapInput($false,0).Length -eq 8) 'Legacy ABI length differs.'
Check ([BitConverter]::ToString([Ntfs2Refs.NativeExtentDiscovery]::BitmapInput($true,0)) -ceq '00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00') 'Extended flags0 input or padding differs.'
Check ([BitConverter]::ToString([Ntfs2Refs.NativeExtentDiscovery]::BitmapInput($true,1)) -ceq '00-00-00-00-00-00-00-00-01-00-00-00-00-00-00-00') 'Extended flags1 input or padding differs.'
Reject { [Ntfs2Refs.NativeExtentDiscovery]::BitmapInput($false,1) } 'Flag placed in legacy ABI.'
Reject { [Ntfs2Refs.NativeExtentDiscovery]::BitmapInput($true,2) } 'Unknown extended flag accepted.'
Check ([Ntfs2Refs.NativeExtentDiscovery]::ParseBase([BitConverter]::GetBytes([long]0),52GB,512) -eq 0) 'Zero native base refused.'
Check ([Ntfs2Refs.NativeExtentDiscovery]::ParseBase([BitConverter]::GetBytes([long]3),4096,512) -eq 3) 'Sector base was changed.'
Reject { [Ntfs2Refs.NativeExtentDiscovery]::ParseBase((New-Object byte[] 7),52GB,512) } 'Truncated base accepted.'
Reject { [Ntfs2Refs.NativeExtentDiscovery]::ParseBase([BitConverter]::GetBytes([long]-1),52GB,512) } 'Negative base accepted.'
Reject { [Ntfs2Refs.NativeExtentDiscovery]::ParseBase([BitConverter]::GetBytes([long]8),4096,512) } 'Out-of-volume base accepted.'
Reject { [Ntfs2Refs.NativeExtentDiscovery]::ParseBase([BitConverter]::GetBytes([long]0),52GB,4096) } 'Unexpected sector profile accepted.'
Reject { [Ntfs2Refs.NativeExtentDiscovery]::ParseBase([BitConverter]::GetBytes([long]0),52GB+512,512) } 'Oversized volume accepted.'
$bytes=Bitmap 10 ([byte[]]@(0x81,0x01))
$bitmap=[Ntfs2Refs.NativeExtentDiscovery]::ParseBitmap($bytes,10)
Check ($bitmap.allocatedClusters -eq 3 -and $bitmap.freeClusters -eq 7 -and $bitmap.representedClusters -eq 10 -and $bitmap.allDeclaredBitsPresent) 'LSB-first bitmap counts are incorrect.'
Check ([Ntfs2Refs.NativeExtentDiscovery]::AreAllocated($bitmap,0,1)) 'First allocated bit lost.'
Check ([Ntfs2Refs.NativeExtentDiscovery]::AreAllocated($bitmap,7,2)) 'Byte-boundary allocated bits lost.'
Check (-not [Ntfs2Refs.NativeExtentDiscovery]::AreAllocated($bitmap,1,1)) 'Free cluster reported allocated.'
$partial=[Ntfs2Refs.NativeExtentDiscovery]::ParseBitmap((Bitmap 16 ([byte[]]@(0xff))),16)
Check (-not $partial.allDeclaredBitsPresent -and $partial.representedClusters -eq 8 -and $partial.allocatedClusters -eq 8) 'Partial bitmap mislabeled complete.'
Reject { [Ntfs2Refs.NativeExtentDiscovery]::AreAllocated($partial,0,1) } 'Incomplete bitmap used as full allocation evidence.'
Reject { [Ntfs2Refs.NativeExtentDiscovery]::ParseBitmap((New-Object byte[] 16),10) } 'Empty bitmap accepted.'
Reject { [Ntfs2Refs.NativeExtentDiscovery]::ParseBitmap((Bitmap 10 ([byte[]]@(0,0)) 1),10) } 'Unexpected rounded starting LCN accepted.'
Reject { [Ntfs2Refs.NativeExtentDiscovery]::ParseBitmap((Bitmap 11 ([byte[]]@(0,0))),10) } 'Wrong native cluster count accepted.'
Reject { [Ntfs2Refs.NativeExtentDiscovery]::ParseBitmap($bytes,13631489) } 'Cluster bound ignored.'
Reject { [Ntfs2Refs.NativeExtentDiscovery]::ParseBitmap((New-Object byte[] (2MB+1)),10) } 'Native response byte bound ignored.'
foreach($pair in @(@(-1,1),@(0,0),@(9,2),@(0,1025))) { Reject { [Ntfs2Refs.NativeExtentDiscovery]::AreAllocated($bitmap,[long]$pair[0],[long]$pair[1]) } 'Invalid allocated-range query accepted.' }
$freeA=[Ntfs2Refs.NativeExtentDiscovery]::ParseBitmap((Bitmap 80 (New-Object byte[] 10)),80)
$bitsB=New-Object byte[] 10; $bitsB[0]=1; $bitsB[4]=1
$freeB=[Ntfs2Refs.NativeExtentDiscovery]::ParseBitmap((Bitmap 80 $bitsB),80)
$ranges=@([Ntfs2Refs.NativeExtentDiscovery]::FindFreeRanges($freeA,$freeB,0,16,8))
Check ($ranges.Count -eq 3 -and $ranges[0].startingLcn -eq 16 -and $ranges[1].startingLcn -eq 48 -and $ranges[2].startingLcn -eq 64) 'Candidate intersection/alignment is incorrect.'
Check (@($ranges | Where-Object { -not $_.freeInBothObservations -or $_.reservedForCaller -or $_.physicalMappingVerified }).Count -eq 0) 'Candidate presented as reserved or physically verified.'
Check (@([Ntfs2Refs.NativeExtentDiscovery]::FindFreeRanges($freeA,$freeA,1,16,1)).Count -eq 1) 'Candidate count bound ignored.'
Check ([Ntfs2Refs.NativeExtentDiscovery]::CountDifferentBits($freeA,$freeB) -eq 2) 'Bitmap difference count differs.'
Reject { [Ntfs2Refs.NativeExtentDiscovery]::CountDifferentBits($partial,$partial) } 'Partial bitmaps compared as complete.'
foreach($caseArgs in @(@(-1,16,8),@(80,16,8),@(0,0,8),@(0,17,8),@(0,16,9))) { Reject { [Ntfs2Refs.NativeExtentDiscovery]::FindFreeRanges($freeA,$freeB,[long]$caseArgs[0],[int]$caseArgs[1],[int]$caseArgs[2]) } 'Invalid candidate search bound accepted.' }
Reject { [Ntfs2Refs.NativeExtentDiscovery]::FindFreeRanges($partial,$partial,0,1,1) } 'Partial bitmap used for candidates.'
Check ([Ntfs2Refs.NativeExtentDiscovery]::CandidateVolumeOffset(0,1507328,1024,512,4096,52GB) -eq 6174015488) 'Native sample offset arithmetic differs.'
Check ([Ntfs2Refs.NativeExtentDiscovery]::CandidateVolumeOffset(2,1,1,512,4096,12288) -eq 5120) 'Sector and cluster units were conflated.'
Reject { [Ntfs2Refs.NativeExtentDiscovery]::CandidateVolumeOffset([long]::MaxValue,1,1,512,4096,52GB) } 'Base multiplication overflow accepted.'
Reject { [Ntfs2Refs.NativeExtentDiscovery]::CandidateVolumeOffset(0,[long]::MaxValue,1,512,4096,52GB) } 'LCN multiplication overflow accepted.'
Reject { [Ntfs2Refs.NativeExtentDiscovery]::CandidateVolumeOffset(0,2,1,512,4096,8192) } 'Beyond-partition hypothesis accepted.'
Reject { [Ntfs2Refs.NativeExtentDiscovery]::CandidateVolumeOffset(0,-1,1,512,4096,52GB) } 'Sparse sentinel interpreted as raw location.'
$identity=[pscustomobject]@{schemaVersion=1;role='target';sizeBytes=64GB;uniqueId='60022480D091C4251B5FFD619706C2B5';location='owned-slot'}
$partition=[pscustomobject]@{guid='{00c9f113-e0b9-49d8-b031-130aef8ef3fb}';diskGuid='{b4ab4dbc-6bd7-4199-8e4a-01b828e98584}';number=2;offset=16MB;length=52GB;letter='F';logicalSectorSize=512;physicalSectorSize=4096}
$control=[pscustomobject]@{schemaVersion=1;kind='devdrive-data-control';phase='Verify';runId=('a'*32);status='verified';formatSucceeded=$true;remountVerified=$true;ordinaryReFS=$false;refsBootVerified=$false;conversionQualified=$false;target=[pscustomobject]@{host=[pscustomobject]@{vhdId='25C491D0-5F1B-4205-9E6F-FD619706C2B5';sizeBytes=64GB;controllerLocation=1};guest=$identity};partition=$partition;after=[pscustomobject]@{filesystem='ReFS';allocationUnitSize=4096;size=52GB}}
Assert-ExtentDiscoveryControl $control ('a'*32); $script:checks++
foreach($pair in @(@('status','prepared'),@('phase','Prepare'),@('remountVerified',$false),@('conversionQualified',$true),@('runId',('b'*32)))) { $bad=Clone $control;$bad.($pair[0])=$pair[1];Reject { Assert-ExtentDiscoveryControl $bad ('a'*32) } 'Unqualified control accepted.' }
$script:mockDisk=[pscustomobject]@{Number=1;Guid=$partition.diskGuid;LogicalSectorSize=512;PhysicalSectorSize=4096}
$script:mockPart=[pscustomobject]@{DiskNumber=1;Guid=$partition.guid;PartitionNumber=2;Offset=16MB;Size=52GB;DriveLetter='F';IsBoot=$false;IsSystem=$false}
$script:mockVolume=[pscustomobject]@{FileSystem='ReFS';FileSystemLabel='ntfs2refs-target';AllocationUnitSize=4096;Size=52GB;UniqueId=$volume}
function Get-LabGuestDisk {param($Identity) $script:mockDisk}
function Get-Partition {param($DiskNumber,$DriveLetter) $script:mockPart}
function Get-Volume {param($DriveLetter) $script:mockVolume}
Check ((Get-ExtentDiscoveryTarget $identity $control).partition.Guid -ceq $partition.guid) 'Owned target profile refused.'
foreach($pair in @(@('Guid',[guid]::NewGuid().ToString()),@('Size',50GB),@('DriveLetter','C'),@('IsBoot',$true),@('IsSystem',$true))) { $saved=$script:mockPart.($pair[0]);$script:mockPart.($pair[0])=$pair[1];Reject { Get-ExtentDiscoveryTarget $identity $control } 'Changed target partition accepted.';$script:mockPart.($pair[0])=$saved }
$file=[pscustomobject]@{fileId64='id';volumeSerialHex='serial';length=4MB;sha256=('a'*64);complete=$true;stableDuringObservation=$true;status='mapping-returned';extents=@([pscustomobject]@{startingVcn=0;nextVcn=1024;lcn=1507328})}
$allocation=[pscustomobject]@{schemaVersion=1;kind='native-file-allocation-observations';complete=$true;diskIdentity=$identity;volume=[pscustomobject]@{fileSystem='ReFS';allocationUnitSize=4096;size=52GB};partition=[pscustomobject]@{number=2;offset=16MB;size=52GB};logicalSectorSize=512;physicalSectorSize=4096;files=@([pscustomobject]@{path='fixtures\nonresident.bin';stream=':$DATA';observation=$file})}
$allocation | Add-Member -NotePropertyName windowsBuild -NotePropertyValue '26300.9457'
$allocation | Add-Member -NotePropertyName filesystemDriver -NotePropertyValue ([pscustomobject]@{name='refs.sys';sha256='3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4'})
Check ((Get-ExtentDiscoveryFixture $allocation $identity).sha256 -ceq ('a'*64)) 'Native fixture evidence refused.'
Check (Test-ExtentDiscoverySameMapping $file (Clone $file)) 'Equal mappings differ.'
$bad=Clone $allocation; $bad.filesystemDriver.sha256=('c'*64);Reject { Get-ExtentDiscoveryFixture $bad $identity } 'Changed native driver profile accepted.'
$changed=Clone $file; $changed.extents[0].lcn++; Check (-not (Test-ExtentDiscoverySameMapping $file $changed)) 'Changed mapping matched saved corpus.'
foreach($pair in @(@('startingVcn',1),@('nextVcn',1023),@('lcn',-1),@('lcn',[long]::MaxValue))) { $bad=Clone $allocation;$bad.files[0].observation.extents[0].($pair[0])=$pair[1];Reject { Get-ExtentDiscoveryFixture $bad $identity } 'Unbounded or incomplete fixture mapping accepted.' }
$fullBits=New-Object byte[] (13631488/8)
foreach($lcn in @(1507328,30,13631485,13631486,136348,1635808)) { $index=[int][Math]::Floor($lcn/8);$fullBits[$index]=$fullBits[$index] -bor (1 -shl ($lcn%8)) }
$fullBitmap=[Ntfs2Refs.NativeExtentDiscovery]::ParseBitmap((Bitmap 13631488 $fullBits),13631488)
$summary=Get-ExtentDiscoveryBitmapSummary 'test' $fullBitmap
Check ($summary.samples.Count -eq 6 -and @($summary.samples | Where-Object { -not $_.allocated -or $_.metadataAddressEquivalenceVerified }).Count -eq 0 -and -not $summary.metadataCoverageQualified) 'Payload/metadata sample addresses or qualification changed.'
if($NativeControlDirectory) {
    $nativeControl=Read-ExtentDiscoveryJson (Join-Path $NativeControlDirectory 'after\verify.json')
    $nativeAllocation=Read-ExtentDiscoveryJson (Join-Path $NativeControlDirectory 'after\allocation-after.json')
    Assert-ExtentDiscoveryControl $nativeControl $nativeControl.runId; $script:checks++
    $nativeFixture=Get-ExtentDiscoveryFixture $nativeAllocation $nativeControl.target.guest
    Check ($nativeFixture.length -eq 4MB) 'Measured fixture profile failed discovery guards.'
    Check ([Ntfs2Refs.NativeExtentDiscovery]::ValidateVolumeName($nativeAllocation.volume.uniqueId).Length -eq 48) 'Measured native volume GUID format rejected.'
}
$nativeText=Get-Content -LiteralPath $nativePath -Raw
Check ($nativeText -notmatch 'FSCTL_MOVE_FILE|SetFileValidData|WriteFile|ReadFile|FSCTL_LOCK|FSCTL_DISMOUNT' -and $nativeText.Contains('CreateFile(handleName,0x80000000,3,IntPtr.Zero,3,0,IntPtr.Zero)')) 'Unexpected native write/raw-I/O operation or access mode.'
$commands=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object { $_.GetCommandName() })
Check (@($commands | Where-Object {$_ -in @('Format-Volume','Initialize-Disk','Clear-Disk','New-Partition','Set-Partition','Mount-VHD','Mount-DiskImage','Set-ExecutionPolicy','Remove-Item')}).Count -eq 0) 'Discovery contains a format/partition/mount/policy/delete command.'
"Passed $script:checks extent-discovery checks; pure parsers, mocked target guards and optional saved JSON only. No native volume handle or VM was opened."
