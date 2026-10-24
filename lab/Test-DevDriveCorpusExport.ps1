<# Pure guards and isolated ordinary metadata files only. Optional native
   validation reads already-exported JSON; never opens a VM or disk handle. #>
[CmdletBinding()]
param([string]$NativeControlDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $workspace 'scripts\Export-LabDevDriveImage.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Corpus exporter parser errors.' }
$labAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Lab.psm1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Lab module parser errors.' }
$definition=$labAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-LabPath'},$false)
Invoke-Expression $definition.Extent.Text
foreach($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)) { Invoke-Expression $definition.Extent.Text }
$script:checks=0
function Check([bool]$Condition,[string]$Message) { if(-not $Condition) { throw $Message }; $script:checks++ }
function Reject([scriptblock]$Action,[string]$Message) { $rejected=$false; try { & $Action | Out-Null } catch { $rejected=$true }; Check $rejected $Message }
function Clone($Value) { $Value | ConvertTo-Json -Depth 20 | ConvertFrom-Json }
$vmId='eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c'
$target=[pscustomobject]@{ role='target'; sizeBytes=64GB; controllerLocation=1; vhdId='25C491D0-5F1B-4205-9E6F-FD619706C2B5' }
$hostControl=[pscustomobject]@{ schemaVersion=1;kind='devdrive-data-control';status='native-devdrive-remount-verified';runId=('a'*32);vmId=$vmId;baselineId='eda059b3-6d50-46bb-bdf4-018b99b5b34f';checkpointName='devdrive-data-20261023T230635404Z';checkpointId='2aa127e2-c875-4ca0-8629-dab784136448';memoryRestored=$true;beforeExported=$true;afterExported=$true;cleanReboot=$true;baselineRestored=$true;remountVerified=$true;originalMemoryBytes=4GB;experimentMemoryBytes=8GB;ordinaryReFS=$false;rawCaptureComplete=$false;refsBootVerified=$false;conversionQualified=$false }
$leaf='win11-20261023T230635404Z'
Assert-CorpusHostRecord $hostControl $leaf $vmId; $script:checks++
foreach($name in @('memoryRestored','beforeExported','afterExported','cleanReboot','baselineRestored','remountVerified')) { $bad=Clone $hostControl; $bad.$name=$false; Reject { Assert-CorpusHostRecord $bad $leaf $vmId } "Missing host $name accepted." }
foreach($name in @('ordinaryReFS','rawCaptureComplete','refsBootVerified','conversionQualified')) { $bad=Clone $hostControl; $bad.$name=$true; Reject { Assert-CorpusHostRecord $bad $leaf $vmId } "False native claim $name accepted." }
foreach($pair in @(@('status','started'),@('runId','bad'),@('vmId',[guid]::NewGuid().ToString()),@('baselineId',[guid]::NewGuid().ToString()),@('checkpointName','other'),@('checkpointId',[guid]::Empty.ToString()),@('originalMemoryBytes',8GB),@('experimentMemoryBytes',4GB))) { $bad=Clone $hostControl; $bad.($pair[0])=$pair[1]; Reject { Assert-CorpusHostRecord $bad $leaf $vmId } 'Changed host profile accepted.' }
$partition=[pscustomobject]@{ guid='{00c9f113-e0b9-49d8-b031-130aef8ef3fb}';diskGuid='{b4ab4dbc-6bd7-4199-8e4a-01b828e98584}';number=2;offset=16MB;length=52GB;letter='F';logicalSectorSize=512;physicalSectorSize=4096 }
Assert-CorpusPartition $partition; $script:checks++
foreach($pair in @(@('guid','bad'),@('diskGuid',[guid]::Empty.ToString()),@('number',3),@('offset',17MB),@('length',50GB),@('letter','C'),@('logicalSectorSize',4096),@('physicalSectorSize',512))) { $bad=Clone $partition; $bad.($pair[0])=$pair[1]; Reject { Assert-CorpusPartition $bad } 'Changed native partition profile accepted.' }
$queries=@(
    [pscustomobject]@{command='fsutil.exe';arguments=@('devdrv','query','F:');exitCode=0;timedOut=$false;stdout='This is a trusted developer volume.'},
    [pscustomobject]@{command='fsutil.exe';arguments=@('fsinfo','volumeinfo','F:');exitCode=0;timedOut=$false;stdout='File System Name : ReFS'},
    [pscustomobject]@{command='fsutil.exe';arguments=@('fsinfo','refsinfo','F:');exitCode=0;timedOut=$false;stdout='REFS Volume Version : 3.14'}
)
$observation=[pscustomobject]@{ filesystem='ReFS';allocationUnitSize=4096;size=52GB;partition=$partition;nativeQueries=$queries;files=@([pscustomobject]@{name='nonresident.bin';length=4MB;sha256=('a'*64)},[pscustomobject]@{name='small.txt';length=61;sha256=('b'*64)});bootTime='2026-10-23T23:06:40.7110170Z' }
Assert-CorpusObservation $observation $partition; $script:checks++
foreach($i in 0..2) { $bad=Clone $observation; $bad.nativeQueries[$i].exitCode=1; Reject { Assert-CorpusObservation $bad $partition } 'Failed native query accepted.' }
$bad=Clone $observation; $bad.nativeQueries[0].stdout='This is not a developer volume.'; Reject { Assert-CorpusObservation $bad $partition } 'Ordinary volume accepted as Dev Drive.'
$bad=Clone $observation; $bad.files[0].length=1; Reject { Assert-CorpusObservation $bad $partition } 'Wrong fixture length accepted.'
$identity=[pscustomobject]@{ schemaVersion=1;role='target';sizeBytes=64GB;uniqueId='60022480D091C4251B5FFD619706C2B5';serialNumber='';serialNumberAvailable=$false;location='Integrated : Bus 0 : Device 10738 : Function 51055 : Adapter 0 : Port 0 : Target 0 : LUN 1' }
$guest=[pscustomobject]@{ schemaVersion=1;kind='devdrive-data-control';phase='Prepare';runId=('a'*32);status='prepared';restoreAllowed=$true;formatSucceeded=$true;scriptSha256=('a'*64);ordinaryReFS=$false;rawCaptureComplete=$false;refsBootVerified=$false;conversionQualified=$false;target=[pscustomobject]@{host=$target;guest=$identity};sourceOs=[pscustomobject]@{diskUniqueId='60022480BEA35BA9D496D5AFF633D768';fileSystem='NTFS';edition='Professional';build='10.0.26300.9457';installedMemoryBytes=8GB};formatter=[pscustomobject]@{command='Format-Volume';moduleSha256=('a'*64);fsutil=[pscustomobject]@{signature='Valid';sha256=('b'*64);signer='CN=Microsoft Windows, O=Microsoft Corporation, C=US'};components=@([pscustomobject]@{path='C:\Windows\System32\drivers\refs.sys';sha256='3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4';signature='Valid'})};partition=$partition;before=$observation;after=$null;remountVerified=$false }
Assert-CorpusGuestRecord $guest Prepare ('a'*32) $target; $script:checks++
$verified=Clone $guest; $verified.phase='Verify'; $verified.status='verified'; $verified.remountVerified=$true; $verified.after=Clone $observation; $verified.after.bootTime='2026-10-23T23:08:40.7110170Z'
Assert-CorpusGuestRecord $verified Verify ('a'*32) $target; $script:checks++
$bad=Clone $verified; $bad.after.bootTime=$bad.before.bootTime; Reject { Assert-CorpusGuestRecord $bad Verify ('a'*32) $target } 'Same-boot remount accepted.'
$bad=Clone $verified; $bad.after.files[0].sha256=('c'*64); Reject { Assert-CorpusGuestRecord $bad Verify ('a'*32) $target } 'Changed remount bytes accepted.'
$bad=Clone $verified; $bad.target.guest.uniqueId='other'; Reject { Assert-CorpusGuestRecord $bad Verify ('a'*32) $target } 'Different guest disk accepted.'
$bad=Clone $verified; $bad.formatter.components[0].sha256=('c'*64); Reject { Assert-CorpusGuestRecord $bad Verify ('a'*32) $target } 'Different ReFS driver profile accepted.'
$baseline=[pscustomobject]@{Id=$hostControl.baselineId;State='Off'}
$vm=[pscustomobject]@{Id=$vmId;State='Off';MemoryStartup=4GB;DynamicMemoryEnabled=$false;ParentSnapshotId=$hostControl.baselineId}
Assert-CorpusCurrentVM $vm $baseline $hostControl; $script:checks++
foreach($pair in @(@('State','Running'),@('MemoryStartup',8GB),@('DynamicMemoryEnabled',$true),@('ParentSnapshotId',[guid]::NewGuid().ToString()))) { $bad=Clone $vm; $bad.($pair[0])=$pair[1]; Reject { Assert-CorpusCurrentVM $bad $baseline $hostControl } 'Changed current VM accepted.' }
$vhd=[pscustomobject]@{Attached=$false;Size=64GB;LogicalSectorSize=512;PhysicalSectorSize=4096;VhdFormat='VHDX';VhdType='Dynamic';ParentPath=$null}
$file=[pscustomobject]@{PSIsContainer=$false;Length=1MB;Attributes=[IO.FileAttributes]::Normal}
Assert-CorpusVhd $vhd $file $target; $script:checks++
foreach($pair in @(@('Attached',$true),@('Size',8GB),@('LogicalSectorSize',4096),@('PhysicalSectorSize',512),@('VhdFormat','VHD'),@('VhdType','Fixed'),@('ParentPath','D:\unexpected.avhdx'))) { $bad=Clone $vhd; $bad.($pair[0])=$pair[1]; Reject { Assert-CorpusVhd $bad $file $target } 'Unsafe source VHD accepted.' }
$root=Join-Path $workspace ('.lab\tests\devdrive-corpus-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$configuration=[pscustomobject]@{Root=$root}; $controlPath=Join-Path $root 'control'; $outputRoot=Join-Path $root 'output'
New-Item -ItemType Directory -Path $controlPath,$outputRoot | Out-Null
$beforeDir=Join-Path $controlPath 'before'; New-Item -ItemType Directory -Path $beforeDir | Out-Null
$entries=@(foreach($name in @('target.json','prepare.json','allocation-before.json')) { $p=Join-Path $beforeDir $name; [IO.File]::WriteAllText($p,'{}',(New-Object Text.UTF8Encoding($false))); [pscustomobject]@{name=$name;length=2;attributes='Archive';sha256=(Get-FileHash -LiteralPath $p).Hash.ToLowerInvariant()} })
[IO.File]::WriteAllText((Join-Path $beforeDir 'exported-files.json'),($entries | ConvertTo-Json),(New-Object Text.UTF8Encoding($false)))
$export=Get-CorpusExports $beforeDir Prepare
Check ($export.Count -eq 3) 'Valid bounded export refused.'
$destination=Join-Path $outputRoot 'copy.json'; Copy-CorpusEvidence $export['prepare.json'] $destination
Check ([IO.File]::ReadAllText($destination) -ceq '{}') 'Evidence copy bytes changed.'
Reject { Copy-CorpusEvidence $export['prepare.json'] $destination } 'Existing evidence copy overwritten.'
$jsonPath=Join-Path $outputRoot 'selection.json'; Write-CorpusJsonNew $jsonPath ([pscustomobject]@{schema_version=1})
$jsonBytes=[IO.File]::ReadAllBytes($jsonPath)
Check ($jsonBytes.Length -gt 3 -and $jsonBytes[0] -eq 123) 'JSON must be UTF-8 without BOM.'
[IO.File]::WriteAllText((Join-Path $beforeDir 'prepare.json'),'changed')
Reject { Get-CorpusExports $beforeDir Prepare } 'Changed export bytes accepted.'
Reject { Copy-CorpusEvidence $export['prepare.json'] (Join-Path $outputRoot 'changed-copy.json') } 'Changed evidence copied.'
$diskRoot=Join-Path $root 'win11\disks'; New-Item -ItemType Directory -Path $diskRoot | Out-Null
$basePath=Join-Path $diskRoot 'target.vhdx'; $childPath=Join-Path $diskRoot 'snapshot.avhdx'
[IO.File]::WriteAllBytes($basePath,[byte[]](1..32)); [IO.File]::WriteAllBytes($childPath,[byte[]](1..64))
$mockTarget=Clone $target; $mockTarget | Add-Member -NotePropertyName path -NotePropertyValue $basePath
$script:vhdMap=@{}
$script:vhdMap[$basePath]=Clone $vhd; $script:vhdMap[$basePath] | Add-Member -NotePropertyName DiskIdentifier -NotePropertyValue $target.vhdId
$script:vhdMap[$childPath]=Clone $script:vhdMap[$basePath]; $script:vhdMap[$childPath].VhdType='Differencing'; $script:vhdMap[$childPath].ParentPath=$basePath
function Get-VHD { param($Path,$ErrorAction) if (-not $script:vhdMap.ContainsKey($Path)) { throw 'Unexpected mocked VHD lookup.' }; $script:vhdMap[$Path] }
$mockChain=@(Get-CorpusChain $childPath $mockTarget)
Check ($mockChain.Count -eq 2 -and $mockChain[1].path -ceq $basePath) 'Mocked source chain did not resolve to the enrolled base.'
$script:vhdMap[$childPath].Attached=$true; Reject { Get-CorpusChain $childPath $mockTarget } 'Attached checkpoint disk accepted.'; $script:vhdMap[$childPath].Attached=$false
$script:vhdMap[$basePath].VhdType='Differencing'; $script:vhdMap[$basePath].ParentPath=$childPath
Reject { Get-CorpusChain $childPath $mockTarget } 'Cyclic parent chain accepted.'
$script:vhdMap[$basePath].VhdType='Dynamic'; $script:vhdMap[$basePath].ParentPath=$null
$savedId=$script:vhdMap[$basePath].DiskIdentifier; $script:vhdMap[$basePath].DiskIdentifier=[guid]::NewGuid().ToString()
Reject { Get-CorpusChain $childPath $mockTarget } 'Wrong base VHD identifier accepted.'; $script:vhdMap[$basePath].DiskIdentifier=$savedId
$pin=New-Object IO.FileStream($childPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try {
    $hashes=@(Get-PinnedCorpusHashes @([pscustomobject]@{metadata=$mockChain[0];stream=$pin}))
    Check ($hashes.Count -eq 1 -and $hashes[0].sha256 -ceq (Get-FileHash -LiteralPath $childPath).Hash.ToLowerInvariant()) 'Pinned ordinary-file hash differs.'
    Reject { $writer=New-Object IO.FileStream($childPath,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite); $writer.Dispose() } 'Source read pin allowed a concurrent writer.'
} finally { $pin.Dispose() }
$chainA=@([pscustomobject]@{path='a';parentPath='b';diskIdentifier='id';vhdType='Differencing';sizeBytes=64GB;logicalSectorSize=512;physicalSectorSize=4096;length=1MB;lastWriteUtc='now'})
Assert-CorpusSameChain $chainA $chainA; $script:checks++
$chainB=@(Clone $chainA[0]); $chainB[0].parentPath='other'; Reject { Assert-CorpusSameChain $chainA $chainB } 'Changed source parent chain accepted.'
$selection=[pscustomobject]@{schema_version=1;expected_disk_bytes=64GB;offset_bytes=16MB;length_bytes=52GB;logical_sector_size=512;guest_disk_unique_id=$identity.uniqueId;guest_partition_guid=$partition.guid;host_vhd_id=$target.vhdId;evidence_path='native-verify.json';evidence_sha256=('a'*64)}
$fixed=Join-Path $outputRoot 'target-fixed.vhd'; $raw=Join-Path $outputRoot 'devdrive.raw'; $evidence=Join-Path $outputRoot 'native-verify.json'
$result=[pscustomobject]@{schema_version=1;status='complete';source_before_after_equal=$true;output_readback_verified=$true;source_length=(64GB+512);footer=[pscustomobject]@{current_size=64GB};output_length=52GB;source_path=$fixed;output_path=$raw;selection_path=$jsonPath;evidence_path=$evidence;source_sha256=('a'*64);output_sha256=('b'*64);selection_sha256=('c'*64);evidence_sha256=('a'*64);selection=$selection;gpt_validated=$false;guest_identity_authenticated=$false;filesystem_validated=$false;conversion_qualified=$false}
Assert-CorpusExtraction $result $selection $fixed $raw $jsonPath $evidence; $script:checks++
foreach($pair in @(@('status','partial'),@('source_before_after_equal',$false),@('output_readback_verified',$false),@('source_length',64GB),@('output_length',1GB),@('conversion_qualified',$true),@('source_path','D:\other.vhd'))) { $bad=Clone $result; $bad.($pair[0])=$pair[1]; Reject { Assert-CorpusExtraction $bad $selection $fixed $raw $jsonPath $evidence } 'Incomplete or misbound extraction accepted.' }
$commands=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object { $_.GetCommandName() })
Check (@($commands | Where-Object { $_ -in @('Mount-VHD','Mount-DiskImage','Dismount-VHD','Initialize-Disk','Clear-Disk','Format-Volume','Set-VM','Start-VM','Stop-VM','Restore-VMSnapshot','Checkpoint-VM','Remove-VM','Set-VMFirmware','Remove-Item') }).Count -eq 0) 'Corpus exporter contains VM/volume mutation or file deletion.'
Check ($ast.Extent.Text -notmatch '(?im)^\s*[^#\r\n]*Convert-VHD[^\r\n]*-DeleteSource\b') 'Source deletion is enabled.'
if ($NativeControlDirectory) {
    $configuration=[pscustomobject]@{Root=(Join-Path $workspace '.lab\hyperv')}; $controlPath=[IO.Path]::GetFullPath($NativeControlDirectory)
    $nativeHost=Read-CorpusJson (Join-Path $controlPath 'host-result.json') 4MB
    Assert-CorpusHostRecord $nativeHost (Split-Path $controlPath -Leaf) $vmId; $script:checks++
    $nativeBefore=Get-CorpusExports (Join-Path $controlPath 'before') Prepare
    $nativeAfter=Get-CorpusExports (Join-Path $controlPath 'after') Verify
    Assert-CorpusGuestRecord (Read-CorpusJson $nativeBefore['prepare.json'].path) Prepare $nativeHost.runId $target; $script:checks++
    Assert-CorpusGuestRecord (Read-CorpusJson $nativeAfter['verify.json'].path) Verify $nativeHost.runId $target; $script:checks++
}
"Passed $script:checks Dev Drive corpus checks. No VM calls, disk attachment, VHD conversion or extraction executed. Ordinary metadata files retained at $root"
