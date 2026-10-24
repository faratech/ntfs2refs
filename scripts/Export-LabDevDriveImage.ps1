<# LAB CORPUS EXTRACTION ONLY. Copies a saved native guest disk to new regular
   files; never mounts a volume, changes a VM, or performs filesystem conversion. #>
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][string]$ControlDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
$configuration=Get-LabConfiguration -WorkspaceRoot $workspace
$controlsRoot=Assert-LabPath (Join-Path $configuration.Root 'devdrive') $configuration.Root
$controlPath=Assert-LabPath $ControlDirectory $controlsRoot
$controlLeaf=Split-Path $controlPath -Leaf
if ((Split-Path $controlPath -Parent) -ine $controlsRoot -or $controlLeaf -cnotmatch '^win11-\d{8}T\d{9}Z$') { throw 'Select one exact native Dev Drive control directory.' }
if (-not $PSCmdlet.ShouldProcess($controlPath,'Copy the unattached saved target chain to a new fixed VHD, then extract the full 52 GiB partition as a corpus file; no mounts or VM changes')) {
    [pscustomobject]@{ Action='ExportNativeDevDriveCorpus'; DryRun=$true; ControlDirectory=$controlPath; AdditionalCapacityBytes=(116GB+128MB); FixedDiskBytes=64GB; RawPartitionBytes=52GB; HostVolumeMounted=$false; VMChanged=$false; FilesystemConversion=$false }; return
}

function Read-CorpusJson([string]$Path,[long]$Limit=16MB) {
    Assert-LabPath $Path $configuration.Root | Out-Null
    $file=Get-Item -LiteralPath $Path -Force
    if ($file.PSIsContainer -or $file.Length -lt 1 -or $file.Length -gt $Limit -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Control JSON is not an ordinary bounded file.' }
    [IO.File]::ReadAllText($file.FullName,(New-Object Text.UTF8Encoding($false,$true))) | ConvertFrom-Json
}
function Assert-CorpusFalseFlags($Record,[string[]]$Names) {
    foreach($name in $Names) { if ($Record.$name -isnot [bool] -or $Record.$name) { throw "Unexpected qualification flag: $name." } }
}
function Assert-CorpusHostRecord($HostRecord,[string]$Leaf,[string]$VMId) {
    if ($HostRecord.schemaVersion -ne 1 -or $HostRecord.kind -cne 'devdrive-data-control' -or $HostRecord.status -cne 'native-devdrive-remount-verified' -or $HostRecord.runId -cnotmatch '^[0-9a-f]{32}$' -or [string]$HostRecord.vmId -ine $VMId -or [string]$HostRecord.baselineId -ine 'eda059b3-6d50-46bb-bdf4-018b99b5b34f' -or $HostRecord.checkpointName -cne ('devdrive-data-' + $Leaf.Substring(6))) { throw 'Native host control identity or success state differs.' }
    foreach($name in @('memoryRestored','beforeExported','afterExported','cleanReboot','baselineRestored','remountVerified')) { if ($HostRecord.$name -isnot [bool] -or -not $HostRecord.$name) { throw "Missing native control completion: $name." } }
    if ($HostRecord.originalMemoryBytes -ne 4GB -or $HostRecord.experimentMemoryBytes -ne 8GB) { throw 'Unexpected native memory profile.' }
    $id=[guid]::Empty
    if (-not [guid]::TryParse([string]$HostRecord.checkpointId,[ref]$id) -or $id -eq [guid]::Empty -or [string]$id -ieq [string]$HostRecord.baselineId) { throw 'Invalid native checkpoint identity.' }
    Assert-CorpusFalseFlags $HostRecord @('ordinaryReFS','rawCaptureComplete','refsBootVerified','conversionQualified')
}
function Assert-CorpusPartition($Partition) {
    foreach($name in @('guid','diskGuid')) { $id=[guid]::Empty; if (-not [guid]::TryParse([string]$Partition.$name,[ref]$id) -or $id -eq [guid]::Empty) { throw 'Native GPT identity is missing.' } }
    if ($Partition.number -ne 2 -or $Partition.offset -ne 16MB -or $Partition.length -ne 52GB -or $Partition.logicalSectorSize -ne 512 -or $Partition.physicalSectorSize -ne 4096 -or $Partition.letter -cne 'F') { throw 'The native partition differs from this exact measured 52 GiB profile.' }
}
function Assert-CorpusSamePartition($Left,$Right) {
    Assert-CorpusPartition $Left; Assert-CorpusPartition $Right
    foreach($name in @('guid','diskGuid','number','offset','length','letter','logicalSectorSize','physicalSectorSize')) { if ([string]$Left.$name -cne [string]$Right.$name) { throw 'Native partition observations disagree.' } }
}
function Assert-CorpusObservation($Observation,$Partition) {
    Assert-CorpusSamePartition $Observation.partition $Partition
    if ($Observation.filesystem -cne 'ReFS' -or $Observation.allocationUnitSize -ne 4096 -or $Observation.size -ne 52GB -or [string]::IsNullOrWhiteSpace([string]$Observation.bootTime)) { throw 'Missing native ReFS observation or boot identity.' }
    $expected=@('devdrv query F:','fsinfo volumeinfo F:','fsinfo refsinfo F:')
    if (@($Observation.nativeQueries).Count -ne 3) { throw 'Incomplete native volume queries.' }
    for($i=0;$i -lt 3;$i++) {
        $query=$Observation.nativeQueries[$i]
        if ($query.command -cne 'fsutil.exe' -or ($query.arguments -join ' ') -cne $expected[$i] -or $query.exitCode -ne 0 -or $query.timedOut -isnot [bool] -or $query.timedOut) { throw 'Native volume query was not successful.' }
    }
    if ($Observation.nativeQueries[0].stdout -notmatch '(?im)^This is a trusted developer volume\.\s*$' -or $Observation.nativeQueries[1].stdout -notmatch '(?im)^File System Name\s*:\s*ReFS\s*$' -or $Observation.nativeQueries[2].stdout -notmatch '(?im)^REFS Volume Version\s*:\s*3\.14\s*$') { throw 'The measured Dev Drive/ReFS 3.14 designation is missing.' }
    if (@($Observation.files).Count -ne 2) { throw 'Incomplete native fixture inventory.' }
    foreach($spec in @(@('nonresident.bin',4MB),@('small.txt',61))) {
        $matches=@($Observation.files | Where-Object name -CEQ $spec[0])
        if ($matches.Count -ne 1 -or $matches[0].length -ne $spec[1] -or $matches[0].sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Native fixture identity, length or hash differs.' }
    }
}
function Assert-CorpusGuestRecord($Guest,[string]$Phase,[string]$RunId,$Target) {
    $status=if($Phase -ceq 'Prepare') {'prepared'} else {'verified'}
    if ($Guest.schemaVersion -ne 1 -or $Guest.kind -cne 'devdrive-data-control' -or $Guest.phase -cne $Phase -or $Guest.runId -cne $RunId -or $Guest.status -cne $status -or $Guest.restoreAllowed -ne $true -or $Guest.formatSucceeded -ne $true -or $Guest.scriptSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Guest control phase did not complete.' }
    Assert-CorpusFalseFlags $Guest @('ordinaryReFS','rawCaptureComplete','refsBootVerified','conversionQualified')
    if ($Guest.target.host.role -cne 'target' -or $Guest.target.host.sizeBytes -ne 64GB -or $Guest.target.host.controllerLocation -ne 1 -or [string]$Guest.target.host.vhdId -ine [string]$Target.vhdId) { throw 'Guest/host target provenance differs.' }
    $identity=$Guest.target.guest
    if ($identity.schemaVersion -ne 1 -or $identity.role -cne 'target' -or $identity.sizeBytes -ne 64GB -or $identity.uniqueId -cne '60022480D091C4251B5FFD619706C2B5' -or $identity.serialNumber -cne '' -or $identity.serialNumberAvailable -ne $false -or $identity.location -cne 'Integrated : Bus 0 : Device 10738 : Function 51055 : Adapter 0 : Port 0 : Target 0 : LUN 1') { throw 'Guest target differs from the measured original virtual disk.' }
    if ($Guest.sourceOs.diskUniqueId -cne '60022480BEA35BA9D496D5AFF633D768' -or $Guest.sourceOs.fileSystem -cne 'NTFS' -or $Guest.sourceOs.edition -cne 'Professional' -or $Guest.sourceOs.build -cne '10.0.26300.9457' -or $Guest.sourceOs.installedMemoryBytes -ne 8GB) { throw 'Native OS environment differs.' }
    if ($Guest.formatter.command -cne 'Format-Volume' -or $Guest.formatter.moduleSha256 -cnotmatch '^[0-9a-f]{64}$' -or $Guest.formatter.fsutil.signature -cne 'Valid' -or $Guest.formatter.fsutil.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $Guest.formatter.fsutil.signer -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)') { throw 'Native formatter provenance is incomplete.' }
    $drivers=@($Guest.formatter.components | Where-Object path -IEQ 'C:\Windows\System32\drivers\refs.sys')
    if ($drivers.Count -ne 1 -or $drivers[0].sha256 -cne '3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4' -or $drivers[0].signature -cne 'Valid') { throw 'ReFS driver differs from the measured native profile.' }
    Assert-CorpusPartition $Guest.partition
    Assert-CorpusObservation $Guest.before $Guest.partition
    if ($Phase -ceq 'Verify') {
        if ($Guest.remountVerified -ne $true) { throw 'Native remount did not pass.' }
        Assert-CorpusObservation $Guest.after $Guest.partition
        if ($Guest.before.bootTime -ceq $Guest.after.bootTime) { throw 'Native remount used the same boot.' }
        foreach($file in $Guest.before.files) { $after=@($Guest.after.files | Where-Object name -CEQ $file.name); if ($after.Count -ne 1 -or $after[0].length -ne $file.length -or $after[0].sha256 -cne $file.sha256) { throw 'Fixture bytes changed across native remount.' } }
    }
}
function Get-CorpusExports([string]$Directory,[string]$Phase) {
    Assert-LabPath $Directory $controlPath | Out-Null
    $inventory=Read-CorpusJson (Join-Path $Directory 'exported-files.json') 1MB
    $entries=@($inventory)
    $allowed=if($Phase -ceq 'Prepare') { @('target.json','prepare.json','allocation-before.json') } else { @('target.json','prepare.json','verify.json','allocation-before.json','allocation-after.json') }
    if ($entries.Count -ne $allowed.Count -or ($entries | Measure-Object length -Sum).Sum -gt 32MB) { throw 'Native export inventory is incomplete or oversized.' }
    $seen=@{}
    foreach($entry in $entries) {
        if ($entry.name -cnotin $allowed -or $seen.ContainsKey([string]$entry.name) -or $entry.length -lt 1 -or $entry.length -gt 16MB -or $entry.sha256 -cnotmatch '^[0-9a-f]{64}$' -or ([IO.FileAttributes]$entry.attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Native export entry is ambiguous or invalid.' }
        $path=Assert-LabPath (Join-Path $Directory $entry.name) $Directory
        $file=Get-Item -LiteralPath $path -Force
        if ($file.PSIsContainer -or $file.Length -ne $entry.length -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256) { throw 'Native export bytes differ from the verified inventory.' }
        $seen[[string]$entry.name]=[pscustomobject]@{ path=$path; length=$entry.length; sha256=$entry.sha256 }
    }
    $actual=@(Get-ChildItem -LiteralPath $Directory -Force)
    if ($actual.Count -ne ($allowed.Count+1) -or @($actual | Where-Object { $_.PSIsContainer -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $_.Name -cnotin ($allowed+@('exported-files.json')) }).Count) { throw 'Unexpected file in native export directory.' }
    $seen
}
function Assert-CorpusCurrentVM($VM,$Baseline,$HostRecord) {
    if ([string]$VM.Id -ine [string]$HostRecord.vmId -or $VM.State -ne 'Off' -or $VM.MemoryStartup -ne 4GB -or $VM.DynamicMemoryEnabled -or [string]$VM.ParentSnapshotId -ine [string]$HostRecord.baselineId -or [string]$Baseline.Id -ine [string]$HostRecord.baselineId -or $Baseline.State -ne 'Off') { throw 'Current VM must remain off at installed-clean with fixed 4 GiB RAM.' }
}
function Assert-CorpusVhd($Vhd,$File,$Expected) {
    if ($Vhd.Attached -isnot [bool] -or $Vhd.Attached -or $Vhd.Size -ne $Expected.sizeBytes -or $Vhd.LogicalSectorSize -ne 512 -or $Vhd.PhysicalSectorSize -ne 4096 -or [string]$Vhd.VhdFormat -cne 'VHDX' -or [string]$Vhd.VhdType -cnotin @('Dynamic','Differencing') -or $File.PSIsContainer -or $File.Length -lt 1 -or $File.Length -gt ($Expected.sizeBytes+1GB) -or ($File.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Source chain contains an attached or unexpected virtual disk.' }
    if ([bool]$Vhd.ParentPath -ne ([string]$Vhd.VhdType -ceq 'Differencing')) { throw 'Source parent/type mismatch.' }
}
function Get-CorpusChain([string]$Leaf,$Expected) {
    $diskRoot=Assert-LabPath (Join-Path $configuration.Root 'win11\disks') $configuration.Root
    $cursor=Assert-LabPath $Leaf $diskRoot; $seen=@{}; $chain=New-Object 'System.Collections.Generic.List[object]'
    while($true) {
        if ($chain.Count -ge 8 -or $seen.ContainsKey($cursor) -or [IO.Path]::GetExtension($cursor) -inotmatch '^\.(?:avhdx|vhdx)$') { throw 'Source chain exceeds the bounded acyclic VHDX profile.' }
        $seen[$cursor]=$true
        $vhd=Get-VHD -Path $cursor -ErrorAction Stop; $file=Get-Item -LiteralPath $cursor -Force
        Assert-CorpusVhd $vhd $file $Expected
        $parent=if($vhd.ParentPath) { if(-not [IO.Path]::IsPathRooted($vhd.ParentPath)) { throw 'Relative VHD parent path refused.' }; Assert-LabPath $vhd.ParentPath $diskRoot } else { $null }
        $chain.Add([pscustomobject]@{ path=$cursor; parentPath=$parent; diskIdentifier=[string]$vhd.DiskIdentifier; vhdType=[string]$vhd.VhdType; sizeBytes=$vhd.Size; logicalSectorSize=$vhd.LogicalSectorSize; physicalSectorSize=$vhd.PhysicalSectorSize; length=$file.Length; lastWriteUtc=$file.LastWriteTimeUtc.ToString('o') })
        if (-not $parent) {
            if ($cursor -ine [string]$Expected.path -or [string]$vhd.DiskIdentifier -ine [string]$Expected.vhdId -or [string]$vhd.VhdType -cne 'Dynamic') { throw 'Source chain does not terminate at the enrolled original disk.' }
            break
        }
        $cursor=$parent
    }
    $chain.ToArray()
}
function Get-CorpusSnapshotState {
    $owned=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    $baseline=Get-ExactLabCheckpoint -VM $owned -Name installed-clean
    Assert-CorpusCurrentVM $owned $baseline $hostControl
    if ((Get-VMFirmware -VM $owned).SecureBoot -ne 'On' -or @(Get-VMNetworkAdapter -VM $owned | Where-Object SwitchName).Count) { throw 'Current VM trust or network state changed.' }
    $snapshot=Get-ExactLabCheckpoint -VM $owned -Name $hostControl.checkpointName
    if ([string]$snapshot.Id -ine [string]$hostControl.checkpointId -or $snapshot.State -ne 'Off' -or [string]$snapshot.SnapshotType -cne 'Standard') { throw 'Saved native checkpoint identity/state/type changed.' }
    $drives=@(Get-VMHardDiskDrive -VMSnapshot $snapshot)
    if ($drives.Count -ne 3) { throw 'Unexpected checkpoint disk count.' }
    $targetChain=$null; $attachments=New-Object 'System.Collections.Generic.List[object]'
    foreach($expected in $manifest.disks) {
        $matches=@($drives | Where-Object { [string]$_.ControllerType -ceq 'SCSI' -and $_.ControllerNumber -eq 0 -and $_.ControllerLocation -eq $expected.controllerLocation })
        if ($matches.Count -ne 1) { throw 'Checkpoint SCSI attachment differs from the manifest.' }
        $chain=@(Get-CorpusChain ([string]$matches[0].Path) $expected)
        $attachments.Add([pscustomobject]@{ role=$expected.role; controllerLocation=$expected.controllerLocation; leafPath=$chain[0].path; basePath=$chain[-1].path; baseVhdId=$chain[-1].diskIdentifier })
        if ($expected.role -ceq 'target') { $targetChain=$chain }
    }
    if (-not $targetChain -or $targetChain.Count -lt 2) { throw 'Expected a saved target differencing chain.' }
    [pscustomobject]@{ vmId=[string]$owned.Id; checkpointId=[string]$snapshot.Id; checkpointName=$snapshot.Name; attachments=$attachments.ToArray(); targetChain=$targetChain }
}
function Write-CorpusBytesNew([string]$Path,[byte[]]$Bytes) {
    Assert-LabPath $Path $outputRoot | Out-Null
    if ($Bytes.Length -gt 16MB) { throw 'Metadata artifact exceeds its bound.' }
    $stream=New-Object IO.FileStream($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($Bytes,0,$Bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}
function Write-CorpusJsonNew([string]$Path,$Value) { Write-CorpusBytesNew $Path ((New-Object Text.UTF8Encoding($false)).GetBytes(($Value | ConvertTo-Json -Depth 18))) }
function Copy-CorpusEvidence($Source,[string]$Destination) {
    if ($Source.length -lt 1 -or $Source.length -gt 16MB) { throw 'Evidence copy exceeds its bounded size.' }
    $evidenceInput=New-Object IO.FileStream($Source.path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($evidenceInput.Length -ne $Source.length) { throw 'Evidence length changed before copying.' }
        $bytes=New-Object byte[] ([int]$Source.length)
        $position=0
        while($position -lt $bytes.Length) { $read=$evidenceInput.Read($bytes,$position,$bytes.Length-$position); if($read -eq 0) { throw 'Evidence ended before its declared length.' }; $position+=$read }
    } finally { $evidenceInput.Dispose() }
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $hash=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
    if ($bytes.Length -ne $Source.length -or $hash -cne $Source.sha256) { throw 'Evidence changed before copying.' }
    Write-CorpusBytesNew $Destination $bytes
}
function Get-PinnedCorpusHashes($Pins) {
    foreach($pin in $Pins) {
        $pin.stream.Position=0; $sha=[Security.Cryptography.SHA256]::Create()
        try { $hash=[BitConverter]::ToString($sha.ComputeHash($pin.stream)).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
        $metadata=$pin.metadata; $file=Get-Item -LiteralPath $metadata.path -Force
        if ($pin.stream.Length -ne $metadata.length -or $file.Length -ne $metadata.length -or $file.LastWriteTimeUtc.ToString('o') -cne $metadata.lastWriteUtc) { throw 'Source metadata changed while held read-only.' }
        [pscustomobject]@{ path=$metadata.path; parentPath=$metadata.parentPath; diskIdentifier=$metadata.diskIdentifier; vhdType=$metadata.vhdType; sizeBytes=$metadata.sizeBytes; logicalSectorSize=$metadata.logicalSectorSize; physicalSectorSize=$metadata.physicalSectorSize; length=$metadata.length; lastWriteUtc=$metadata.lastWriteUtc; sha256=$hash }
    }
}
function Assert-CorpusSameChain($Before,$After) {
    if (@($Before).Count -ne @($After).Count) { throw 'Saved target chain length changed.' }
    for($i=0;$i -lt @($Before).Count;$i++) { foreach($name in @('path','parentPath','diskIdentifier','vhdType','sizeBytes','logicalSectorSize','physicalSectorSize','length','lastWriteUtc')) { if ([string]$Before[$i].$name -cne [string]$After[$i].$name) { throw 'Saved target chain metadata changed.' } } }
}
function Assert-CorpusExtraction($Result,$Selection,[string]$FixedPath,[string]$RawPath,[string]$SelectionPath,[string]$EvidencePath) {
    if ($Result.schema_version -ne 1 -or $Result.status -cne 'complete' -or $Result.source_before_after_equal -ne $true -or $Result.output_readback_verified -ne $true -or $Result.source_length -ne (64GB+512) -or $Result.footer.current_size -ne 64GB -or $Result.output_length -ne 52GB) { throw 'Extractor did not complete the full expected disk/partition profile.' }
    foreach($pair in @(@($Result.source_path,$FixedPath),@($Result.output_path,$RawPath),@($Result.selection_path,$SelectionPath),@($Result.evidence_path,$EvidencePath))) { if ([IO.Path]::GetFullPath([string]$pair[0]) -ine [IO.Path]::GetFullPath([string]$pair[1])) { throw 'Extractor report refers to unexpected artifacts.' } }
    foreach($name in @('source_sha256','output_sha256','selection_sha256','evidence_sha256')) { if ($Result.$name -cnotmatch '^[0-9a-f]{64}$') { throw 'Extractor digest is missing.' } }
    foreach($name in @('schema_version','expected_disk_bytes','offset_bytes','length_bytes','logical_sector_size','guest_disk_unique_id','guest_partition_guid','host_vhd_id','evidence_path','evidence_sha256')) { if ([string]$Result.selection.$name -cne [string]$Selection.$name) { throw 'Extractor selection differs from native evidence.' } }
    if ($Result.evidence_sha256 -cne $Selection.evidence_sha256) { throw 'Extractor evidence digest differs.' }
    Assert-CorpusFalseFlags $Result @('gpt_validated','guest_identity_authenticated','filesystem_validated','conversion_qualified')
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated Hyper-V read/copy access is required.' }
Import-Module Hyper-V -ErrorAction Stop
$manifest=Read-LabManifest -Configuration $configuration -Lane win11
if (-not $manifest -or [string]$manifest.vmId -ine 'eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c' -or @($manifest.disks).Count -ne 3) { throw 'Expected the existing owned Windows 11 lab.' }
$targets=@($manifest.disks | Where-Object role -CEQ 'target')
if ($targets.Count -ne 1) { throw 'Missing original target disk.' }
$target=$targets[0]
$expectedTargetPath=Assert-LabPath (Join-Path $configuration.Root 'win11\disks\target.vhdx') $configuration.Root
if ([string]$target.path -ine $expectedTargetPath -or [string]$target.vhdId -ine '25C491D0-5F1B-4205-9E6F-FD619706C2B5' -or $target.sizeBytes -ne 64GB -or $target.controllerLocation -ne 1) { throw 'Original target path/identity changed.' }
$hostControl=Read-CorpusJson (Join-Path $controlPath 'host-result.json') 4MB
Assert-CorpusHostRecord $hostControl $controlLeaf ([string]$manifest.vmId)
$beforeFiles=Get-CorpusExports (Join-Path $controlPath 'before') Prepare
$afterFiles=Get-CorpusExports (Join-Path $controlPath 'after') Verify
foreach($name in @('target.json','prepare.json','allocation-before.json')) { if ($beforeFiles[$name].sha256 -cne $afterFiles[$name].sha256 -or $beforeFiles[$name].length -ne $afterFiles[$name].length) { throw 'Earlier native evidence changed across remount.' } }
$prepare=Read-CorpusJson $beforeFiles['prepare.json'].path
$verify=Read-CorpusJson $afterFiles['verify.json'].path
Assert-CorpusGuestRecord $prepare Prepare $hostControl.runId $target
Assert-CorpusGuestRecord $verify Verify $hostControl.runId $target
Assert-CorpusSamePartition $prepare.partition $verify.partition
if (($prepare.before | ConvertTo-Json -Depth 12 -Compress) -cne ($verify.before | ConvertTo-Json -Depth 12 -Compress)) { throw 'Before-remount observations changed.' }
if ($prepare.scriptSha256 -cne $verify.scriptSha256) { throw 'Guest experiment implementation changed across remount.' }
$guestSource=@($hostControl.sourceHashes | Where-Object path -CEQ 'lab\guest\Invoke-GuestDevDriveControl.ps1')
if ($guestSource.Count -ne 1 -or $guestSource[0].sha256 -cne $verify.scriptSha256) { throw 'Native guest script provenance is not bound to the host run.' }
$identity=Read-CorpusJson $afterFiles['target.json'].path 64KB
foreach($name in @('schemaVersion','role','uniqueId','serialNumber','serialNumberAvailable','sizeBytes','location','enrolledUtc')) { if ([string]$identity.$name -cne [string]$verify.target.guest.$name -or [string]$identity.$name -cne [string]$prepare.target.guest.$name) { throw 'Exported target enrollment differs from native observations.' } }
$sourceState=Get-CorpusSnapshotState
$extractor=Assert-LabPath (Join-Path $workspace 'target\release\n2r-extract-fixed-vhd.exe') $workspace
$extractorFile=Get-Item -LiteralPath $extractor -Force
if ($extractorFile.PSIsContainer -or $extractorFile.Length -lt 1 -or $extractorFile.Length -gt 64MB -or ($extractorFile.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Build the bounded lab extractor first.' }
$extractorHash=(Get-FileHash -LiteralPath $extractor -Algorithm SHA256).Hash.ToLowerInvariant()
$convertCommand=Get-Command Convert-VHD -CommandType Cmdlet
if ($convertCommand.ModuleName -cne 'Hyper-V') { throw 'Expected the native Hyper-V VHD copying cmdlet.' }
Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes (116GB+128MB)
$stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$outputRoot=Assert-LabPath (Join-Path $configuration.Root ('corpus\devdrive-' + $stamp)) $configuration.Root
if (Test-Path -LiteralPath $outputRoot) { throw 'Corpus destination already exists.' }
New-Item -ItemType Directory -Path $outputRoot | Out-Null
$fixedPath=Assert-LabPath (Join-Path $outputRoot 'target-fixed.vhd') $outputRoot
$rawPath=Assert-LabPath (Join-Path $outputRoot 'devdrive.raw') $outputRoot
$selectionPath=Assert-LabPath (Join-Path $outputRoot 'selection.json') $outputRoot
$evidencePath=Assert-LabPath (Join-Path $outputRoot 'native-verify.json') $outputRoot
$record=[ordered]@{ schemaVersion=1; kind='native-devdrive-corpus-extraction'; status='started'; controlDirectory=$controlPath; controlRunId=$hostControl.runId; vmId=$manifest.vmId; checkpointName=$hostControl.checkpointName; checkpointId=$hostControl.checkpointId; baselineId=$hostControl.baselineId; outputDirectory=$outputRoot; sourceBefore=$null; sourceAfter=$null; sourceHashesEqual=$false; vmUnchanged=$false; hostVolumeMounted=$false; filesystemConversionPerformed=$false; conversionQualified=$false; refsBootVerified=$false; ordinaryReFS=$false; extractor=[pscustomobject]@{ path=$extractor; sha256=$extractorHash }; convertVhd=[pscustomobject]@{ modulePath=$convertCommand.Module.Path; moduleVersion=[string]$convertCommand.Module.Version; moduleSha256=(Get-FileHash -LiteralPath $convertCommand.Module.Path -Algorithm SHA256).Hash.ToLowerInvariant(); destinationType='Fixed'; sourceDeleted=$false }; createdUtc=[DateTime]::UtcNow.ToString('o') }
$record['scriptSha256']=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$pins=New-Object 'System.Collections.Generic.List[object]'
$job=$null; $process=$null; $processStarted=$false
try {
    foreach($entry in $sourceState.targetChain) { $stream=New-Object IO.FileStream($entry.path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read); $pins.Add([pscustomobject]@{ metadata=$entry; stream=$stream }) }
    $record.sourceBefore=@(Get-PinnedCorpusHashes $pins)
    $again=Get-CorpusSnapshotState; Assert-CorpusSameChain $sourceState.targetChain $again.targetChain
    Copy-CorpusEvidence $afterFiles['verify.json'] $evidencePath
    Copy-CorpusEvidence $beforeFiles['prepare.json'] (Join-Path $outputRoot 'native-prepare.json')
    Copy-CorpusEvidence $afterFiles['target.json'] (Join-Path $outputRoot 'native-target.json')
    $selection=[ordered]@{ schema_version=1; expected_disk_bytes=[long]64GB; offset_bytes=[long]$verify.partition.offset; length_bytes=[long]$verify.partition.length; logical_sector_size=512; guest_disk_unique_id=$identity.uniqueId; guest_partition_guid=$verify.partition.guid; host_vhd_id=$target.vhdId; evidence_path='native-verify.json'; evidence_sha256=$afterFiles['verify.json'].sha256 }
    Write-CorpusJsonNew $selectionPath $selection
    Write-CorpusJsonNew (Join-Path $outputRoot 'stage-01-validated.json') $record
    if (Test-Path -LiteralPath $fixedPath) { throw 'Fixed VHD destination already exists.' }
    $record['conversionStartedUtc']=[DateTime]::UtcNow.ToString('o')
    $job=Convert-VHD -Path $sourceState.targetChain[0].path -DestinationPath $fixedPath -VHDType Fixed -AsJob -Confirm:$false
    if (-not (Wait-Job -Job $job -Timeout 1800)) { $record['conversionJobMayStillBeRunning']=$true; $record['conversionJobId']=[string]$job.InstanceId; throw 'VHD copy exceeded 1800 seconds; retain output and investigate the native copy job.' }
    Receive-Job -Job $job -ErrorAction Stop | Out-Null
    Remove-Job -Job $job -Force; $job=$null
    $fixed=Get-VHD -Path $fixedPath -ErrorAction Stop; $fixedFile=Get-Item -LiteralPath $fixedPath -Force
    if ($fixed.Attached -ne $false -or [string]$fixed.VhdType -cne 'Fixed' -or [string]$fixed.VhdFormat -cne 'VHD' -or $fixed.ParentPath -or $fixed.Size -ne 64GB -or $fixed.LogicalSectorSize -ne 512 -or $fixedFile.PSIsContainer -or $fixedFile.Length -ne (64GB+512) -or ($fixedFile.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Converted copy does not have the exact fixed VHD profile.' }
    $record['fixedVhd']=[pscustomobject]@{ path=$fixedPath; diskIdentifier=[string]$fixed.DiskIdentifier; virtualBytes=$fixed.Size; fileBytes=$fixedFile.Length; logicalSectorSize=$fixed.LogicalSectorSize; physicalSectorSize=$fixed.PhysicalSectorSize; vhdType=[string]$fixed.VhdType; vhdFormat=[string]$fixed.VhdFormat }
    $again=Get-CorpusSnapshotState; Assert-CorpusSameChain $sourceState.targetChain $again.targetChain
    Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes (52GB+64MB)
    Write-CorpusJsonNew (Join-Path $outputRoot 'stage-02-fixed-copy.json') $record
    if ((Get-FileHash -LiteralPath $extractor -Algorithm SHA256).Hash.ToLowerInvariant() -cne $extractorHash) { throw 'Extractor binary changed before execution.' }
    $arguments=@('--source',$fixedPath,'--output',$rawPath,'--selection',$selectionPath)
    $process=New-Object Diagnostics.Process
    $process.StartInfo.FileName=$extractor
    $process.StartInfo.Arguments=(($arguments | ForEach-Object { '"' + ($_ -replace '(\\*)"','$1$1\"' -replace '(\\+)$','$1$1') + '"' }) -join ' ')
    $process.StartInfo.UseShellExecute=$false; $process.StartInfo.CreateNoWindow=$true; $process.StartInfo.RedirectStandardOutput=$true; $process.StartInfo.RedirectStandardError=$true
    $processStarted=$process.Start()
    if (-not $processStarted) { throw 'Lab extractor did not start.' }
    $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(3600000)) { $process.Kill(); if (-not $process.WaitForExit(10000)) { throw 'Extractor timeout and termination did not complete.' }; throw 'Extractor exceeded one hour; partial artifacts retained.' }
    if (-not $stdout.Wait(10000) -or -not $stderr.Wait(10000)) { throw 'Extractor output did not close.' }
    $out=$stdout.GetAwaiter().GetResult(); $err=$stderr.GetAwaiter().GetResult()
    if ($out.Length -gt 4MB -or $err.Length -gt 4MB) { throw 'Extractor command output exceeds its evidence bound.' }
    Write-CorpusJsonNew (Join-Path $outputRoot 'extractor-command.json') ([pscustomobject]@{ executable=$extractor; executableSha256=$extractorHash; arguments=$arguments; exitCode=$process.ExitCode; stdout=$out; stderr=$err })
    if ($process.ExitCode -ne 0) { throw 'Lab extractor refused or failed; artifacts retained.' }
    $extraction=Read-CorpusJson ($rawPath+'.json') 1MB
    Assert-CorpusExtraction $extraction $selection $fixedPath $rawPath $selectionPath $evidencePath
    $raw=Get-Item -LiteralPath $rawPath -Force
    if ($raw.PSIsContainer -or ($raw.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $raw.Length -ne 52GB -or (Get-FileHash -LiteralPath $rawPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $extraction.output_sha256 -or (Get-FileHash -LiteralPath $selectionPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $extraction.selection_sha256 -or (Get-FileHash -LiteralPath $evidencePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $extraction.evidence_sha256) { throw 'Independent corpus length/hash verification failed.' }
    $record['extraction']=$extraction
    $record.sourceAfter=@(Get-PinnedCorpusHashes $pins)
    Assert-CorpusSameChain $record.sourceBefore $record.sourceAfter
    for($i=0;$i -lt $record.sourceBefore.Count;$i++) { if ($record.sourceBefore[$i].sha256 -cne $record.sourceAfter[$i].sha256) { throw 'Saved source chain bytes changed.' } }
    $record.sourceHashesEqual=$true
    $again=Get-CorpusSnapshotState; Assert-CorpusSameChain $sourceState.targetChain $again.targetChain
    if (($sourceState.attachments | ConvertTo-Json -Compress) -cne ($again.attachments | ConvertTo-Json -Compress)) { throw 'Saved checkpoint attachments changed.' }
    $record.vmUnchanged=$true; $record.status='complete'
} catch {
    $record.status='failed'; $record['error']=$_.Exception.Message; $record['errorPosition']=$_.InvocationInfo.PositionMessage; $record['scriptStackTrace']=$_.ScriptStackTrace
    throw
} finally {
    if ($process) { try { if ($processStarted -and -not $process.HasExited) { $process.Kill(); $process.WaitForExit(10000) | Out-Null } } finally { $process.Dispose() } }
    if ($job -and $job.State -in @('Completed','Failed','Stopped')) { Remove-Job -Job $job -Force }
    foreach($pin in $pins) { $pin.stream.Dispose() }
    $record['finishedUtc']=[DateTime]::UtcNow.ToString('o')
    Write-CorpusJsonNew (Join-Path $outputRoot 'host-result.json') $record
}
[pscustomobject]@{ Status=$record.status; Evidence=$outputRoot; RawImage=$rawPath; RawBytes=52GB; SourceHashesEqual=$record.sourceHashesEqual; VMUnchanged=$record.vmUnchanged; FilesystemConversionPerformed=$false; ReFSBootVerified=$false }
