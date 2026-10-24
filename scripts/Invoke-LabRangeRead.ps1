<# Two bounded raw range reads on the exact saved initialized-placement branch.
   Host Hyper-V operations are lab orchestration, never converter dependencies. #>
[CmdletBinding(SupportsShouldProcess)]
param([ValidateRange(60,900)][int]$BootTimeoutSeconds=300,[ValidateRange(30,600)][int]$CaptureTimeoutSeconds=180)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
$configuration=Get-LabConfiguration -WorkspaceRoot $workspace
if (-not $PSCmdlet.ShouldProcess('ntfs2refs-win11','Restore the exact placement outcome, lock a guest read handle and read two fixed 64 KiB ranges, export bounded evidence, cleanly shut down and restore installed-clean with 4 GiB RAM')) {
    [pscustomobject]@{Action='NativeRangeRead';DryRun=$true;MemoryBytes=8GB;MaximumRawReadBytes=131072;MaximumLockCalls=1;RawWriteRequestsIssued=$false;ConversionQualified=$false}; return
}

function Get-RangeReadProfile {
    [pscustomobject]@{vmId='eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c';baselineId='eda059b3-6d50-46bb-bdf4-018b99b5b34f';checkpointId='4b581541-4899-4f91-adc1-e4e784c7cacf';checkpointName='extent-placement-data-d98ba93b850d4eababa84c445439868a';controlDirectory='devdrive\win11-20261023T230635404Z';controlRunId='65f270323c26427e8316c7a8b75959cc';controlEvidenceSha256='ca9e3e60bbe84bd758609d92b92a305a948213b4ab0f5ce199f38567a8ea84c1';capturedAllocationSha256='f553fd91111dfb09a9aa14d27fe63daaba790c0efb14bd530ac5cd9ef0f55be2';targetVhdId='25c491d0-5f1b-4205-9e6f-fd619706c2b5';placementDirectory='extent-placement\win11-20261024T000401422Z';placementProbeId='d98ba93b850d4eababa84c445439868a';placementHostSha256='125f812543ef56ea5d81f641797b1ac2d8b52b1f16d8f17d1ac03a726684d982';placementEvidenceSha256='865e9a7517dd1e0bd925d7fad5af85146fa8ec4c447d5640958473c11cd30cc5';remountIdentitySha256='fe287b5536c1de6c816d4d4ba43e7d5fe9026361a8b91687279c770b5efb4414';remountAllocationSha256='9d7b537e885cde3c7b67c1a830dd2dfff27ccf4232d445e46baa4a3499002cbe';patternSha256='9b195d4598044587ab6e51b73d92063936710b9b1255158054918350d20f1d78'}
}
function Assert-RangeReadManifest($Manifest,$Profile) {
    if ([string]$Manifest.vmId -ine $Profile.vmId -or @($Manifest.disks).Count -ne 3) { throw 'Unexpected range-read VM or disk count.' }
    foreach($role in @('os','target','journal')) {
        $selected=@($Manifest.disks | Where-Object role -CEQ $role)
        $slot=if($role -ceq 'os'){0}elseif($role -ceq 'target'){1}else{2}
        $bytes=if($role -ceq 'journal'){8GB}else{64GB}
        if($selected.Count -ne 1 -or $selected[0].controllerLocation -ne $slot -or $selected[0].sizeBytes -ne $bytes) { throw 'RangeRead requires the original three owned disks.' }
        if($role -ceq 'target' -and [string]$selected[0].vhdId -ine $Profile.targetVhdId) { throw 'Unexpected original target VHD identity.' }
    }
}
function Assert-RangeReadVM($VM,[string]$ExpectedParent,[long]$MemoryBytes) {
    if($VM.State -ne 'Off' -or $VM.MemoryStartup -ne $MemoryBytes -or $VM.DynamicMemoryEnabled -or [string]$VM.ParentSnapshotId -ine $ExpectedParent) { throw 'RangeRead requires the exact powered-off checkpoint branch and fixed memory profile.' }
    if(@(Get-VMNetworkAdapter -VM $VM | Where-Object SwitchName).Count -or (Get-VMFirmware -VM $VM).SecureBoot -ne 'On') { throw 'RangeRead requires disconnected networking and unchanged Secure Boot.' }
}
function Assert-RangeReadCheckpoint($Checkpoint,$Profile,[switch]$Baseline) {
    $id=if($Baseline){$Profile.baselineId}else{$Profile.checkpointId}
    $name=if($Baseline){'installed-clean'}else{$Profile.checkpointName}
    if([string]$Checkpoint.Id -ine $id -or $Checkpoint.Name -cne $name -or [string]$Checkpoint.VMId -ine $Profile.vmId) { throw 'Saved range-read checkpoint identity changed.' }
}
function Assert-RangeReadResponse($Result,[string]$ExpectedId) {
    if($Result.CaptureId -cne $ExpectedId -or $Result.Status -cnotin @('destination-range-verified','native-open-refused','native-lock-refused','native-query-refused','source-range-not-free','destination-range-not-allocated','blocked') -or $Result.EvidenceDirectory -cne ('C:\ntfs2refs\range-read\'+$ExpectedId)){throw 'Unexpected guest range-read response.'}
    foreach($field in @('RestoreAllowed','DestinationSampleVerified','OldSourceResidualObserved')){if($Result.$field -isnot [bool]){throw 'Missing explicit range result.'}}
    foreach($field in @('RawWriteRequestsIssued','ConversionQualified')){if($Result.$field -isnot [bool] -or $Result.$field){throw 'Unreviewed write or qualification claim.'}}
    if($Result.DestinationSampleVerified -ne ($Result.Status -ceq 'destination-range-verified') -or ($Result.OldSourceResidualObserved -and -not $Result.DestinationSampleVerified) -or ($Result.Status -ceq 'blocked' -and $Result.RestoreAllowed)){throw 'Range status and qualification disagree.'}
}
function Assert-RangeReadArtifact($File) {
    $maximum=0
    if($File.name -cin @('range.json','allocation-before.json','allocation-after.json')) { $maximum=1MB }
    elseif($File.name -cin @('baseBefore.bin','baseLocked.bin')) { $maximum=8 }
    elseif($File.name -cin @('volumeBefore.bin','volumeLocked.bin')) { $maximum=64 }
    elseif($File.name -cin @('bitmapLegacy.bin','bitmapMetadata.bin')) { $maximum=2MB }
    elseif($File.name -cin @('oldSource.bin','destination.bin')) { $maximum=65536 }
    else { throw 'Unexpected range-read artifact name.' }
    if($File.length -lt 1 -or $File.length -gt $maximum -or $File.sha256 -cnotmatch '^[0-9a-f]{64}$' -or ([IO.FileAttributes]$File.attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid or oversized range-read artifact.' }
}
function Assert-RangeReadArtifactSet([object[]]$Files) {
    if($Files.Count -lt 1 -or $Files.Count -gt 11 -or @($Files | Where-Object name -CEQ 'range.json').Count -ne 1 -or @($Files.name | Select-Object -Unique).Count -ne $Files.Count) { throw 'Missing, duplicate or excessive range-read artifacts.' }
    foreach($file in $Files) { Assert-RangeReadArtifact $file }
    if(($Files | Measure-Object length -Sum).Sum -gt 8MB) { throw 'RangeRead evidence exceeds the aggregate bound.' }
}
function Assert-RangeReadRecord($Record,$Response,$Profile,$Control,[object[]]$Files,[string]$ScriptSha256,[string]$NativeSha256) {
    if($Record.schemaVersion -ne 1 -or $Record.kind -cne 'native-range-read' -or $Record.captureId -cne $Response.CaptureId -or $Record.status -cne $Response.Status -or $Record.scriptSha256 -cne $ScriptSha256 -or $Record.nativeSourceSha256 -cne $NativeSha256 -or $Record.maximumRawReadBytes -ne 131072 -or $Record.maximumLockCalls -ne 1){throw 'Range evidence provenance or bounds differ.'}
    foreach($field in @('controlRunId','controlEvidenceSha256','capturedAllocationSha256','placementProbeId','placementEvidenceSha256','remountIdentitySha256','remountAllocationSha256','patternSha256')){if($Record.profile.$field -cne $Profile.$field){throw 'Source proof profile changed.'}}
    foreach($field in @('rawWriteRequestsIssued','targetFileWriteRequestsIssued','forcedDismountAttempted','oldSourceReserved','physicalMappingGeneralized','metadataCoverageQualified','payloadCopyAvoidanceVerified','conversionQualified','bootQualified')){if($Record.$field -isnot [bool] -or $Record.$field){throw 'Unperformed activity or qualification claimed.'}}
    foreach($field in @('restoreAllowed','destinationSampleVerified','oldSourceResidualObserved')){if($Record.$field -isnot [bool] -or $Record.$field -ne $Response.$field){throw 'Range response and record disagree.'}}
    foreach($field in @('role','uniqueId','sizeBytes','location')){if([string]$Record.target.$field -cne [string]$Control.target.guest.$field){throw 'Target enrollment changed.'}}
    foreach($field in @('guid','diskGuid','number','offset','length','letter','logicalSectorSize','physicalSectorSize')){if([string]$Record.partition.$field -cne [string]$Control.partition.$field){throw 'Target GPT or geometry changed.'}}
    if(@($Record.nativeQueries).Count -gt 8 -or @($Record.nativeQueries|ForEach-Object{$_.name}|Select-Object -Unique).Count -ne @($Record.nativeQueries).Count -or @($Record.rawReads).Count -gt 2 -or @($Record.rawReads|ForEach-Object{$_.name}|Select-Object -Unique).Count -ne @($Record.rawReads).Count){throw 'Native observation count differs.'}
    $referenced=@()
    foreach($query in $Record.nativeQueries){
        if($query.name -cnotin @('baseBefore','baseLocked','volumeBefore','volumeLocked','bitmapLegacy','bitmapMetadata','lock','unlock')){throw 'Unreviewed native query.'}
        $code=if($query.name -clike 'base*'){'0x00090234'}elseif($query.name -clike 'volume*'){'0x00560000'}elseif($query.name -ceq 'lock'){'0x00090018'}elseif($query.name -ceq 'unlock'){'0x0009001c'}else{'0x0009006f'}
        $capacity=if($query.name -clike 'base*'){8}elseif($query.name -clike 'volume*'){64}elseif($query.name -clike 'bitmap*'){2MB}else{0}
        $input=if($query.name -ceq 'bitmapLegacy'){'0000000000000000'}elseif($query.name -ceq 'bitmapMetadata'){'00000000000000000100000000000000'}else{''}
        if($query.controlCode -cne $code -or $query.inputHex -cne $input -or $query.inputBytes -ne ($input.Length/2) -or $query.outputCapacityBytes -ne $capacity -or $query.bytesReturned -lt 0 -or $query.bytesReturned -gt $capacity -or $query.succeeded -isnot [bool]){throw 'Native query exceeds reviewed bounds.'}
        if($query.bufferPath){$name=$query.name+'.bin';$match=@($Files|Where-Object name -CEQ $name);if($query.bufferPath -cne ($Response.EvidenceDirectory+'\'+$name) -or $match.Count -ne 1 -or $match[0].sha256 -cne $query.bufferSha256 -or $match[0].length -ne $query.bytesReturned){throw 'Native buffer provenance differs.'};$referenced+=$name}elseif($query.bytesReturned -ne 0 -or $query.bufferSha256){throw 'Native buffer missing.'}
    }
    foreach($read in $Record.rawReads){
        if($read.name -cnotin @('oldSource','destination')){throw 'Unreviewed raw range.'}
        $lcn=if($read.name -ceq 'oldSource'){1508352}else{1508384}
        if($null -eq $Record.baseSectors -or $Record.baseSectors -lt 0 -or $Record.baseSectors -ge (52GB/512)){throw 'Raw address lacks a bounded native base.'}
        $offset=[long]$Record.baseSectors*512+[long]$lcn*4096
        if($read.lcn -ne $lcn -or $read.volumeOffset -ne $offset -or $read.guestDiskOffset -ne (16MB+$offset) -or $offset%4096 -ne 0 -or $offset -gt (52GB-65536) -or $read.requestedBytes -ne 65536 -or $read.bytesReturned -lt 0 -or $read.bytesReturned -gt 65536){throw 'Raw range exceeds reviewed address or byte bounds.'}
        if($read.bufferPath){$name=$read.name+'.bin';$match=@($Files|Where-Object name -CEQ $name);if($read.bufferPath -cne ($Response.EvidenceDirectory+'\'+$name) -or $match.Count -ne 1 -or $match[0].length -ne $read.bytesReturned -or $match[0].sha256 -cne $read.bufferSha256){throw 'Raw buffer provenance differs.'};$referenced+=$name}elseif($read.bytesReturned -ne 0 -or $read.bufferSha256){throw 'Raw buffer missing.'}
    }
    if(@($Files|Where-Object{$_.name -clike '*.bin' -and $_.name -cnotin $referenced}).Count){throw 'An exported buffer lacks native provenance.'}
}
function Assert-RangeReadCompletion($Record) {
    if($Record.restoreAllowed -ne $true -or $Record.nativeOperationReturned -ne $true -or $Record.fixturesUnchanged -ne $true -or $Record.handleCloseSucceeded -ne $true -or ($Record.lockSucceeded -and -not $Record.unlockSucceeded) -or $Record.status -cnotin @('destination-range-verified','native-open-refused','native-lock-refused','native-query-refused','source-range-not-free','destination-range-not-allocated')){throw 'Range operation lacks determinate completion; preserve branch.'}
    if($Record.rangeReadCalls -lt 0 -or $Record.rangeReadCalls -gt 2 -or $Record.lockMayFlushNativeWrites -ne $Record.lockAttempted){throw 'Native operation accounting disagrees.'}
    if($Record.status -ceq 'destination-range-verified'){
        if($Record.nativeStatus -cne 'ranges-read-awaiting-file-verification' -or -not $Record.lockSucceeded -or -not $Record.destinationAllocatedInBoth -or @($Record.nativeQueries).Count -ne 8 -or @($Record.rawReads).Count -ne 2 -or $Record.rangeReadCalls -ne 2 -or @($Record.nativeQueries|Where-Object{-not $_.succeeded -or $_.nativeError -ne 0}).Count){throw 'Verified range lacks successful native controls.'}
        foreach($read in $Record.rawReads){if(-not $read.seekSucceeded -or $read.actualSeekOffset -ne $read.volumeOffset -or -not $read.readSucceeded -or $read.bytesReturned -ne 65536){throw 'Verified range lacks exact successful reads.'}}
    }else{
        if(@($Record.rawReads).Count -ne 0 -or $Record.rangeReadCalls -ne 0 -or $Record.nativeStatus -cne $Record.status){throw 'Refused precondition has inconsistent status or raw reads.'}
        if($Record.status -ceq 'source-range-not-free' -and ($Record.oldSourceFreeInBoth -ne $false -or -not $Record.lockSucceeded -or @($Record.nativeQueries).Count -ne 8)){throw 'Source refusal lacks locked allocation evidence.'}
        if($Record.status -ceq 'destination-range-not-allocated' -and ($Record.destinationAllocatedInBoth -ne $false -or -not $Record.lockSucceeded -or @($Record.nativeQueries).Count -ne 8)){throw 'Destination refusal lacks locked allocation evidence.'}
    }
}
function Assert-RangeReadExportBytes($Record,[string]$Root,[byte[]]$Pattern) {
    if($Record.status -cnotin @('destination-range-verified','source-range-not-free','destination-range-not-allocated')){return}
    if($Pattern.Length -ne 65536){throw 'Expected pattern has wrong length.'}
    foreach($name in @('baseBefore','baseLocked')){$bytes=[IO.File]::ReadAllBytes((Join-Path $Root ($name+'.bin')));if($bytes.Length -ne 8 -or [BitConverter]::ToInt64($bytes,0) -ne $Record.baseSectors){throw 'Exported native base differs.'}}
    foreach($name in @('volumeBefore','volumeLocked')){$bytes=[IO.File]::ReadAllBytes((Join-Path $Root ($name+'.bin')));if($bytes.Length -ne 32 -or [BitConverter]::ToUInt32($bytes,0) -ne 1 -or [BitConverter]::ToUInt32($bytes,8) -ne $Record.diskNumberObserved -or [BitConverter]::ToInt64($bytes,16) -ne 16MB -or [BitConverter]::ToInt64($bytes,24) -ne 52GB){throw 'Exported volume binding differs.'}}
    $sourceFree=$true;$destinationAllocated=$true
    foreach($kind in @('Legacy','Metadata')){
        $bytes=[IO.File]::ReadAllBytes((Join-Path $Root ('bitmap'+$kind+'.bin')))
        if($bytes.Length -lt (16+13631488/8) -or $bytes.Length -gt 2MB -or [BitConverter]::ToInt64($bytes,0) -ne 0 -or [BitConverter]::ToInt64($bytes,8) -ne 13631488){throw 'Exported bitmap domain incomplete.'}
        foreach($sample in @(@{lcn=1508352;field=('sourceBits'+$kind);source=$true},@{lcn=1508384;field=('destinationBits'+$kind);source=$false})){
            $reported=$Record.($sample.field);if(@($reported).Count -ne 16){throw 'Incomplete source/destination bit observations.'}
            for($i=0;$i -lt 16;$i++){$bit=$sample.lcn+$i;$allocated=($bytes[16+[int][Math]::Floor($bit/8)] -band (1 -shl ($bit%8))) -ne 0;if($reported[$i] -isnot [bool] -or $reported[$i] -ne $allocated){throw 'Bitmap sample differs from exported bytes.'};if($sample.source -and $allocated){$sourceFree=$false};if(-not $sample.source -and -not $allocated){$destinationAllocated=$false}}
        }
    }
    if($Record.oldSourceFreeInBoth -ne $sourceFree -or $Record.destinationAllocatedInBoth -ne $destinationAllocated -or ($Record.status -ceq 'destination-range-verified' -and -not $destinationAllocated)){throw 'Allocation summary differs from exported native buffers.'}
    $sourceMatch=$false
    foreach($read in $Record.rawReads){$bytes=[IO.File]::ReadAllBytes((Join-Path $Root ($read.name+'.bin')));if($bytes.Length -ne 65536){throw 'Raw read is incomplete.'};$equal=$true;for($i=0;$i -lt 65536;$i++){if($bytes[$i] -ne $Pattern[$i]){$equal=$false;break}};if($read.fullPatternEqual -isnot [bool] -or $read.fullPatternEqual -ne $equal){throw 'Full pattern comparison disagrees.'};if($read.name -ceq 'destination' -and -not $equal){throw 'Raw destination differs from logical pattern.'};if($read.name -ceq 'oldSource'){$sourceMatch=$equal}}
    if($Record.oldSourceResidualObserved -ne ($sourceFree -and $sourceMatch)){throw 'Residual-data observation differs from bytes and allocation state.'}
}
function Get-RangeReadFixture($Evidence,$Identity) {
    if ($Evidence.schemaVersion -ne 1 -or $Evidence.kind -cne 'native-file-allocation-observations' -or $Evidence.complete -ne $true -or $Evidence.diskIdentity.uniqueId -cne $Identity.uniqueId -or $Evidence.diskIdentity.location -cne $Identity.location -or $Evidence.diskIdentity.sizeBytes -ne 64GB -or $Evidence.volume.fileSystem -cne 'ReFS' -or $Evidence.volume.allocationUnitSize -ne 4096 -or $Evidence.volume.size -ne 52GB -or $Evidence.partition.number -ne 2 -or $Evidence.partition.offset -ne 16MB -or $Evidence.partition.size -ne 52GB -or $Evidence.logicalSectorSize -ne 512 -or $Evidence.physicalSectorSize -ne 4096) { throw 'Allocation evidence is incomplete or belongs to another target.' }
    if($Evidence.windowsBuild -cne '26300.9457' -or $Evidence.filesystemDriver.name -cne 'refs.sys' -or $Evidence.filesystemDriver.sha256 -cne '3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4') { throw 'Native ReFS driver profile changed.' }
    $files=@($Evidence.files | Where-Object { $_.path -ceq 'fixtures\nonresident.bin' -and $_.stream -ceq ':$DATA' })
    if ($files.Count -ne 1) { throw 'Expected the explicit unique-pattern fixture.' }
    $file=$files[0].observation
    if ($file.complete -ne $true -or $file.stableDuringObservation -ne $true -or $file.status -cne 'mapping-returned' -or $file.length -ne 4MB -or $file.sha256 -cnotmatch '^[0-9a-f]{64}$' -or @($file.extents).Count -lt 1 -or @($file.extents).Count -gt 1024) { throw 'Fixture mapping or logical content is unqualified.' }
    $next=[long]0
    foreach($extent in $file.extents) {
        if ($extent.startingVcn -ne $next -or $extent.nextVcn -le $next -or $extent.nextVcn -gt 1024 -or $extent.lcn -lt 0 -or $extent.lcn -gt ((52GB/4096)-($extent.nextVcn-$next))) { throw 'Fixture has an unexpected or unbounded native mapping.' }
        $next=[long]$extent.nextVcn
    }
    if ($next -ne 1024) { throw 'Fixture mapping does not cover the complete 4 MiB stream.' }
    $file
}
function Test-RangeReadSameMapping($Left,$Right) {
    if ($Left.fileId64 -cne $Right.fileId64 -or $Left.volumeSerialHex -cne $Right.volumeSerialHex -or $Left.length -ne $Right.length -or $Left.sha256 -cne $Right.sha256 -or @($Left.extents).Count -ne @($Right.extents).Count) { return $false }
    for($i=0;$i -lt @($Left.extents).Count;$i++) { foreach($name in @('startingVcn','nextVcn','lcn')) { if($Left.extents[$i].$name -ne $Right.extents[$i].$name) { return $false } } }
    $true
}
function Assert-RangeReadAllocation($Evidence,$Identity,$Placement,$Profile) {
    $original=Get-RangeReadFixture $Evidence $Identity
    if(@($Evidence.files).Count -ne 2 -or $Evidence.volume.uniqueId -cne $Placement.volumeUniqueId -or -not (Test-RangeReadSameMapping $original $Placement.originalAfter)){throw 'Original fixture or allocation identity changed.'}
    $files=@($Evidence.files|Where-Object {$_.path -ceq ('fixtures\placement-'+$Profile.placementProbeId+'\initialized.bin') -and $_.stream -ceq ':$DATA'})
    if($files.Count -ne 1){throw 'Expected exactly the initialized placement fixture.'}
    $file=$files[0].observation
    if($file.complete -ne $true -or $file.stableDuringObservation -ne $true -or $file.status -cne 'mapping-returned' -or ([IO.FileAttributes]$file.attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::SparseFile -bor [IO.FileAttributes]::Compressed -bor [IO.FileAttributes]::Encrypted)) -or -not (Test-RangeReadSameMapping $file $Placement.after)){throw 'Initialized fixture changed or is not an ordinary complete mapping.'}
}
function Invoke-BoundedRangeReadCommand([scriptblock]$ScriptBlock,[object[]]$Arguments=@(),[int]$TimeoutSeconds=60) {
    $script:commandIndeterminate=$true
    $job=$null
    try {
        $job=Invoke-Command -Session $session -AsJob -ArgumentList $Arguments -ScriptBlock $ScriptBlock
        if(-not (Wait-Job -Job $job -Timeout $TimeoutSeconds)) { throw 'Guest command exceeded its deadline; preserve the running branch.' }
        $answer=@(Receive-Job -Job $job -ErrorAction Stop)
        if($job.State -ne 'Completed') { throw 'Guest command did not complete successfully; preserve the branch.' }
        $script:commandIndeterminate=$false
        $answer
    } finally { if($job -and $job.State -in @('Completed','Failed','Stopped')) { Remove-Job -Job $job -Force } }
}
function Open-RangeReadSession {
    $deadline=[DateTime]::UtcNow.AddSeconds($BootTimeoutSeconds)
    while([DateTime]::UtcNow -lt $deadline) {
        $probe=$null
        try {
            $probe=Invoke-Command -VMId ([guid]$manifest.vmId) -Credential $credential -AsJob -ScriptBlock {$env:COMPUTERNAME}
            if(Wait-Job -Job $probe -Timeout 10) { $reply=@(Receive-Job -Job $probe -ErrorAction Stop); if($reply.Count -eq 1 -and $reply[0] -ceq 'N2R-WIN11') { return New-PSSession -VMId ([guid]$manifest.vmId) -Credential $credential -ErrorAction Stop } }
        } catch {} finally { if($probe){Remove-Job -Job $probe -Force -ErrorAction SilentlyContinue} }
        Start-Sleep -Seconds 2
    }
    throw 'PowerShell Direct did not become available before the deadline.'
}
function Stop-RangeReadGuest {
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    if($vm.State -eq 'Off'){return}
    if(-not $session -or $script:commandIndeterminate){throw 'An idle authenticated guest session is required for clean shutdown.'}
    Invoke-BoundedRangeReadCommand -TimeoutSeconds 30 -ScriptBlock { & shutdown.exe /s /t 0; if($LASTEXITCODE -ne 0){throw 'Guest shutdown request failed.'} } | Out-Null
    $deadline=[DateTime]::UtcNow.AddMinutes(3)
    do { if((Get-VM -Id ([guid]$manifest.vmId)).State -eq 'Off'){return}; Start-Sleep -Seconds 2 } while([DateTime]::UtcNow -lt $deadline)
    throw 'Guest did not shut down cleanly; preserve the branch.'
}
function Export-RangeReadArtifacts([string]$GuestRoot) {
    $files=@(Invoke-BoundedRangeReadCommand -Arguments @($GuestRoot) -ScriptBlock {
        param($Root)
        foreach($parent in @('C:\ntfs2refs','C:\ntfs2refs\range-read',$Root)) { $item=Get-Item -LiteralPath $parent -Force; if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected range-read evidence root.'} }
        $items=@(Get-ChildItem -LiteralPath $Root -Force)
        if($items.Count -gt 11){throw 'Excessive guest evidence files.'}
        foreach($file in $items) {
            if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 2MB -or $file.Name -cnotin @('range.json','allocation-before.json','allocation-after.json','baseBefore.bin','baseLocked.bin','volumeBefore.bin','volumeLocked.bin','bitmapLegacy.bin','bitmapMetadata.bin','oldSource.bin','destination.bin')){throw 'Unexpected guest evidence file.'}
            [pscustomobject]@{name=$file.Name;length=$file.Length;attributes=[string]$file.Attributes;sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
        }
    })
    Assert-RangeReadArtifactSet $files
    $destination=Assert-LabPath (Join-Path $outputRoot 'guest') $configuration.Root
    if(Test-Path -LiteralPath $destination){throw 'RangeRead export destination already exists.'}
    New-Item -ItemType Directory -Path $destination | Out-Null
    foreach($file in $files) {
        $path=Assert-LabPath (Join-Path $destination $file.name) $configuration.Root
        if(Test-Path -LiteralPath $path){throw 'Evidence export cannot overwrite existing files.'}
        Copy-Item -LiteralPath ($GuestRoot+'\'+$file.name) -Destination $path -FromSession $session
        $local=Get-Item -LiteralPath $path -Force
        if($local.PSIsContainer -or ($local.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $local.Length -ne $file.length -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $file.sha256){throw 'RangeRead export failed length/hash verification.'}
    }
    $files | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $destination 'exported-files.json') -Encoding UTF8
    [pscustomobject]@{files=$files;record=(Get-Content -LiteralPath (Join-Path $destination 'range.json') -Raw | ConvertFrom-Json)}
}

if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated Hyper-V access is required.'}
$profile=Get-RangeReadProfile
$manifest=Read-LabManifest -Configuration $configuration -Lane win11
Assert-RangeReadManifest $manifest $profile
$vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
$baseline=Get-ExactLabCheckpoint -VM $vm -Name installed-clean
Assert-RangeReadCheckpoint $baseline $profile -Baseline
Assert-RangeReadVM $vm $profile.baselineId 4GB
$saved=Get-ExactLabCheckpoint -VM $vm -Name $profile.checkpointName
Assert-RangeReadCheckpoint $saved $profile
$controlRoot=Assert-LabPath (Join-Path $configuration.Root $profile.controlDirectory) $configuration.Root
$verifyPath=Assert-LabPath (Join-Path $controlRoot 'after\verify.json') $configuration.Root
$allocationPath=Assert-LabPath (Join-Path $controlRoot 'after\allocation-after.json') $configuration.Root
if((Get-FileHash -LiteralPath $verifyPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $profile.controlEvidenceSha256 -or (Get-FileHash -LiteralPath $allocationPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $profile.capturedAllocationSha256){throw 'Pinned native source evidence changed.'}
$control=Get-Content -LiteralPath $verifyPath -Raw | ConvertFrom-Json
$placementRoot=Assert-LabPath (Join-Path $configuration.Root $profile.placementDirectory) $configuration.Root
foreach($proof in @(@{path='host-result.json';sha=$profile.placementHostSha256},@{path='guest\placement.json';sha=$profile.placementEvidenceSha256},@{path='remount\identity.json';sha=$profile.remountIdentitySha256},@{path='remount\allocation-remount.json';sha=$profile.remountAllocationSha256},@{path='guest\expected-pattern.bin';sha=$profile.patternSha256})){
    $path=Assert-LabPath (Join-Path $placementRoot $proof.path) $configuration.Root;$file=Get-Item -LiteralPath $path -Force
    if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -lt 1 -or $file.Length -gt 1MB -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $proof.sha){throw 'Pinned placement/remount evidence changed.'}
}
$origin=Get-Content -LiteralPath (Join-Path $placementRoot 'host-result.json') -Raw|ConvertFrom-Json
if($origin.status -cne 'native-extent-placement-remount-verified' -or $origin.probeId -cne $profile.placementProbeId -or $origin.outcomeCheckpointId -ine $profile.checkpointId -or $origin.outcomeCheckpointName -cne $profile.checkpointName -or -not $origin.outcomeCheckpointCreated -or -not $origin.cleanRemountVerified -or -not $origin.evidenceExported -or -not $origin.remountEvidenceExported -or -not $origin.baselineRestored -or -not $origin.memoryRestored -or $origin.commandCompletionUnknown){throw 'Saved placement outcome was not completed and exported.'}
$placement=Get-Content -LiteralPath (Join-Path $placementRoot 'guest\placement.json') -Raw|ConvertFrom-Json
$savedAllocation=Get-Content -LiteralPath (Join-Path $placementRoot 'remount\allocation-remount.json') -Raw|ConvertFrom-Json
Assert-RangeReadAllocation $savedAllocation $control.target.guest $placement $profile
$pattern=[IO.File]::ReadAllBytes((Join-Path $placementRoot 'guest\expected-pattern.bin'))
if($pattern.Length -ne 65536){throw 'Expected pattern has wrong length.'}
$laneRoot=Assert-LabPath (Join-Path $configuration.Root 'win11') $configuration.Root
$credential=Import-Clixml -LiteralPath (Join-Path $laneRoot 'secrets\guest-credential.xml')
if($credential -isnot [Management.Automation.PSCredential] -or $credential.UserName -cne 'N2R-WIN11\LabAdmin'){throw 'Unexpected guest credential identity.'}
Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 4GB
$captureId=[guid]::NewGuid().ToString('N')
$outputRoot=Assert-LabPath (Join-Path $configuration.Root ('range-read\win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $configuration.Root
if(Test-Path -LiteralPath $outputRoot){throw 'RangeRead output root already exists.'}
New-Item -ItemType Directory -Path $outputRoot | Out-Null
$guestNames=@('GuestLab.psm1','Capture-GuestAllocation.ps1','NativeRangeRead.cs','Capture-GuestRangeRead.ps1')
$sourceHashes=@(foreach($name in $guestNames){$path=Join-Path $workspace ('lab\guest\'+$name);$file=Get-Item -LiteralPath $path -Force;if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -lt 1 -or $file.Length -gt 256KB){throw 'Unexpected range-read source file.'};[pscustomobject]@{name=$name;length=$file.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}})
$record=[ordered]@{schemaVersion=1;kind='native-range-read-host';captureId=$captureId;profile=$profile;vmId=$profile.vmId;baselineId=$profile.baselineId;sourceCheckpointId=$profile.checkpointId;sourceCheckpointName=$profile.checkpointName;status='started';phase='preflight';evidenceExported=$false;cleanShutdown=$false;baselineRestored=$false;memoryRestored=$false;volumeControlsMayHaveBeenIssued=$false;rawWriteRequestsIssued=$false;targetFileWriteRequestsIssued=$false;destinationSampleVerified=$false;oldSourceResidualObserved=$false;physicalMappingGeneralized=$false;payloadCopyAvoidanceVerified=$false;conversionQualified=$false;sourceHashes=$sourceHashes;hostScriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();labModuleSha256=(Get-FileHash -LiteralPath (Join-Path $workspace 'lab\Lab.psm1') -Algorithm SHA256).Hash.ToLowerInvariant();createdUtc=[DateTime]::UtcNow.ToString('o')}
$session=$null; $script:commandIndeterminate=$false
try {
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-RangeReadVM $vm $profile.baselineId 4GB
    Assert-RangeReadCheckpoint (Get-ExactLabCheckpoint -VM $vm -Name $profile.checkpointName) $profile
    $record.phase='restore-native-control'
    Invoke-LabAction -Action Restore -Lane win11 -CheckpointName $profile.checkpointName -Confirm:$false | Out-Null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-RangeReadVM $vm $profile.checkpointId 8GB
    Invoke-LabAction -Action Start -Lane win11 -Confirm:$false | Out-Null
    $session=Open-RangeReadSession
    $policy=Initialize-LabGuestSession -Session $session
    $policy | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $outputRoot 'session.json') -Encoding UTF8
    if($policy.status -cne 'ready'){throw ('Guest session refused: '+$policy.error)}
    Invoke-BoundedRangeReadCommand -ScriptBlock {
        foreach($path in @('C:\ntfs2refs','C:\ntfs2refs\guest')){$item=Get-Item -LiteralPath $path -Force;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected guest script directory.'}}
        foreach($name in @('GuestLab.psm1','Capture-GuestAllocation.ps1','NativeRangeRead.cs','Capture-GuestRangeRead.ps1')){$path='C:\ntfs2refs\guest\'+$name;if(Test-Path -LiteralPath $path){$item=Get-Item -LiteralPath $path -Force;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected guest helper destination.'}}}
    } | Out-Null
    foreach($file in $sourceHashes){Copy-Item -LiteralPath (Join-Path $workspace ('lab\guest\'+$file.name)) -Destination ('C:\ntfs2refs\guest\'+$file.name) -ToSession $session -Force}
    $copied=@(Invoke-BoundedRangeReadCommand -ScriptBlock {foreach($name in @('GuestLab.psm1','Capture-GuestAllocation.ps1','NativeRangeRead.cs','Capture-GuestRangeRead.ps1')){$path='C:\ntfs2refs\guest\'+$name;$file=Get-Item -LiteralPath $path -Force;if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected copied helper.'};[pscustomobject]@{name=$name;length=$file.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}}})
    if($copied.Count -ne $sourceHashes.Count){throw 'Incomplete helper copy.'}
    foreach($file in $sourceHashes){$copy=@($copied|Where-Object name -CEQ $file.name);if($copy.Count -ne 1 -or $copy[0].length -ne $file.length -or $copy[0].sha256 -cne $file.sha256){throw 'Guest helper hash differs from dispatched source.'}}
    Get-OwnedLabVM -Configuration $configuration -Manifest $manifest | Out-Null
    $record.phase='locked-range-read';$record.volumeControlsMayHaveBeenIssued=$true
    $record|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $outputRoot 'host-result.json') -Encoding UTF8
    $responses=@(Invoke-BoundedRangeReadCommand -TimeoutSeconds $CaptureTimeoutSeconds -Arguments @($captureId) -ScriptBlock {param($CaptureId); & 'C:\ntfs2refs\guest\Capture-GuestRangeRead.ps1' -CaptureId $CaptureId -Confirm:$false})
    if($responses.Count -ne 1){throw 'Guest returned an ambiguous range-read response.'}
    $response=$responses[0]; Assert-RangeReadResponse $response $captureId
    $record.phase='export'
    $export=Export-RangeReadArtifacts $response.EvidenceDirectory
    $scriptSha=($sourceHashes|Where-Object name -CEQ 'Capture-GuestRangeRead.ps1').sha256
    $nativeSha=($sourceHashes|Where-Object name -CEQ 'NativeRangeRead.cs').sha256
    Assert-RangeReadRecord $export.record $response $profile $control $export.files $scriptSha $nativeSha
    $record.evidenceExported=$true; $record['guestStatus']=$response.Status
    $record['guestEvidenceSha256']=($export.files|Where-Object name -CEQ 'range.json').sha256
    Assert-RangeReadCompletion $export.record
    $collectorSha=($sourceHashes|Where-Object name -CEQ 'Capture-GuestAllocation.ps1').sha256
    foreach($name in @('allocation-before.json','allocation-after.json')){
        $proof=Get-Content -LiteralPath (Join-Path $outputRoot ('guest\'+$name)) -Raw|ConvertFrom-Json
        if($proof.evidenceScriptSha256 -cne $collectorSha){throw 'Allocation collector provenance changed.'}
        Assert-RangeReadAllocation $proof $control.target.guest $placement $profile
    }
    Assert-RangeReadExportBytes $export.record (Join-Path $outputRoot 'guest') $pattern
    foreach($field in @('destinationSampleVerified','oldSourceResidualObserved')){$record[$field]=$export.record.$field}
    $record['nativeStatus']=$export.record.nativeStatus;$record['nativeRangeReads']=$export.record.rawReads
    $record['lockSucceeded']=$export.record.lockSucceeded;$record['unlockSucceeded']=$export.record.unlockSucceeded;$record['handleCloseSucceeded']=$export.record.handleCloseSucceeded
    $record.phase='clean-shutdown'
    Stop-RangeReadGuest
    $record.cleanShutdown=$true
    Remove-PSSession -Session $session -ErrorAction SilentlyContinue; $session=$null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-RangeReadVM $vm $profile.checkpointId 8GB
    Assert-RangeReadCheckpoint (Get-ExactLabCheckpoint -VM $vm -Name installed-clean) $profile -Baseline
    $record.phase='restore-baseline'
    Invoke-LabAction -Action Restore -Lane win11 -CheckpointName installed-clean -Confirm:$false | Out-Null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    if($vm.State -ne 'Off' -or [string]$vm.ParentSnapshotId -ine $profile.baselineId){throw 'Baseline restore did not return the exact off-state branch.'}
    if($vm.MemoryStartup -ne 4GB -or $vm.DynamicMemoryEnabled){Set-VMMemory -VM $vm -StartupBytes 4GB -DynamicMemoryEnabled $false}
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-RangeReadVM $vm $profile.baselineId 4GB
    $record.baselineRestored=$true; $record.memoryRestored=$true; $record.status='native-range-read-exported'; $record.phase='complete'
} catch {
    $record.status='failed-preserved'; $record['error']=$_.Exception.Message; $record['errorPosition']=$_.InvocationInfo.PositionMessage; $record['scriptStackTrace']=$_.ScriptStackTrace
    # No shutdown, restore, checkpoint, forced job stop or memory change on failure.
    throw
} finally {
    $record['commandCompletionUnknown']=$script:commandIndeterminate; $record['finishedUtc']=[DateTime]::UtcNow.ToString('o')
    $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $outputRoot 'host-result.json') -Encoding UTF8
    if($session -and -not $script:commandIndeterminate){Remove-PSSession -Session $session -ErrorAction SilentlyContinue}
    $credential=$null
}
[pscustomobject]@{Status=$record.status;GuestStatus=$record.guestStatus;Evidence=$outputRoot;BaselineRestored=$record.baselineRestored;MemoryRestored=$record.memoryRestored;DestinationSampleVerified=$record.destinationSampleVerified;OldSourceResidualObserved=$record.oldSourceResidualObserved;RawWriteRequestsIssued=$false;PhysicalMappingGeneralized=$false;ConversionQualified=$false}
