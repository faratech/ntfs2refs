<# Exact saved-branch orchestration for the separately reviewed protected-mounted profile.
   Device-state changes occur only inside the guest; no raw or file payload writer. #>
[CmdletBinding(SupportsShouldProcess)]
param([ValidateRange(60,900)][int]$BootTimeoutSeconds=300,[ValidateRange(30,600)][int]$CaptureTimeoutSeconds=180)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
$configuration=Get-LabConfiguration -WorkspaceRoot $workspace
if(-not $PSCmdlet.ShouldProcess('ntfs2refs-win11','Restore exact placement outcome at 8 GiB, establish guest disk read-only protection through the reviewed offline/online sequence, sample two fixed 64 KiB ranges, export evidence; preserve mutation-phase failures and restore baseline only after qualified completion')) {
    [pscustomobject]@{Action='NativeProtectedRangeRead';DryRun=$true;MemoryBytes=8GB;MaximumRawReadBytes=131072;MaximumLockCalls=2;DeviceStateMutation=$true;RawWriteRequestsIssued=$false;TargetFileWriteRequestsIssued=$false;ConversionQualified=$false};return
}
function Get-ProtectedRangeReadProfile {
    [pscustomobject]@{vmId='eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c';baselineId='eda059b3-6d50-46bb-bdf4-018b99b5b34f';checkpointId='4b581541-4899-4f91-adc1-e4e784c7cacf';checkpointName='extent-placement-data-d98ba93b850d4eababa84c445439868a';controlDirectory='devdrive\win11-20261023T230635404Z';controlRunId='65f270323c26427e8316c7a8b75959cc';controlEvidenceSha256='ca9e3e60bbe84bd758609d92b92a305a948213b4ab0f5ce199f38567a8ea84c1';capturedAllocationSha256='f553fd91111dfb09a9aa14d27fe63daaba790c0efb14bd530ac5cd9ef0f55be2';targetVhdId='25c491d0-5f1b-4205-9e6f-fd619706c2b5';placementDirectory='extent-placement\win11-20261024T000401422Z';placementProbeId='d98ba93b850d4eababa84c445439868a';placementHostSha256='125f812543ef56ea5d81f641797b1ac2d8b52b1f16d8f17d1ac03a726684d982';placementEvidenceSha256='865e9a7517dd1e0bd925d7fad5af85146fa8ec4c447d5640958473c11cd30cc5';remountIdentitySha256='fe287b5536c1de6c816d4d4ba43e7d5fe9026361a8b91687279c770b5efb4414';remountAllocationSha256='9d7b537e885cde3c7b67c1a830dd2dfff27ccf4232d445e46baa4a3499002cbe';patternSha256='9b195d4598044587ab6e51b73d92063936710b9b1255158054918350d20f1d78'}
}

function Assert-ProtectedRangeReadManifest($Manifest,$Profile) {
    if ([string]$Manifest.vmId -ine $Profile.vmId -or @($Manifest.disks).Count -ne 3) { throw 'Unexpected protected-range-read VM or disk count.' }
    foreach($role in @('os','target','journal')) {
        $selected=@($Manifest.disks | Where-Object role -CEQ $role)
        $slot=if($role -ceq 'os'){0}elseif($role -ceq 'target'){1}else{2}
        $bytes=if($role -ceq 'journal'){8GB}else{64GB}
        if($selected.Count -ne 1 -or $selected[0].controllerLocation -ne $slot -or $selected[0].sizeBytes -ne $bytes) { throw 'ProtectedRangeRead requires the original three owned disks.' }
        if($role -ceq 'target' -and [string]$selected[0].vhdId -ine $Profile.targetVhdId) { throw 'Unexpected original target VHD identity.' }
    }
}

function Assert-ProtectedRangeReadVM($VM,[string]$ExpectedParent,[long]$MemoryBytes) {
    if($VM.State -ne 'Off' -or $VM.MemoryStartup -ne $MemoryBytes -or $VM.DynamicMemoryEnabled -or [string]$VM.ParentSnapshotId -ine $ExpectedParent) { throw 'ProtectedRangeRead requires the exact powered-off checkpoint branch and fixed memory profile.' }
    if(@(Get-VMNetworkAdapter -VM $VM | Where-Object SwitchName).Count -or (Get-VMFirmware -VM $VM).SecureBoot -ne 'On') { throw 'ProtectedRangeRead requires disconnected networking and unchanged Secure Boot.' }
}

function Assert-ProtectedRangeReadCheckpoint($Checkpoint,$Profile,[switch]$Baseline) {
    $id=if($Baseline){$Profile.baselineId}else{$Profile.checkpointId}
    $name=if($Baseline){'installed-clean'}else{$Profile.checkpointName}
    if([string]$Checkpoint.Id -ine $id -or $Checkpoint.Name -cne $name -or [string]$Checkpoint.VMId -ine $Profile.vmId) { throw 'Saved protected-range-read checkpoint identity changed.' }
}

function Get-ProtectedRangeReadFixture($Evidence,$Identity) {
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

function Test-ProtectedRangeReadSameMapping($Left,$Right) {
    if ($Left.fileId64 -cne $Right.fileId64 -or $Left.volumeSerialHex -cne $Right.volumeSerialHex -or $Left.length -ne $Right.length -or $Left.sha256 -cne $Right.sha256 -or @($Left.extents).Count -ne @($Right.extents).Count) { return $false }
    for($i=0;$i -lt @($Left.extents).Count;$i++) { foreach($name in @('startingVcn','nextVcn','lcn')) { if($Left.extents[$i].$name -ne $Right.extents[$i].$name) { return $false } } }
    $true
}

function Assert-ProtectedRangeReadAllocation($Evidence,$Identity,$Placement,$Profile) {
    $original=Get-ProtectedRangeReadFixture $Evidence $Identity
    if(@($Evidence.files).Count -ne 2 -or $Evidence.volume.uniqueId -cne $Placement.volumeUniqueId -or -not (Test-ProtectedRangeReadSameMapping $original $Placement.originalAfter)){throw 'Original fixture or allocation identity changed.'}
    $files=@($Evidence.files|Where-Object {$_.path -ceq ('fixtures\placement-'+$Profile.placementProbeId+'\initialized.bin') -and $_.stream -ceq ':$DATA'})
    if($files.Count -ne 1){throw 'Expected exactly the initialized placement fixture.'}
    $file=$files[0].observation
    if($file.complete -ne $true -or $file.stableDuringObservation -ne $true -or $file.status -cne 'mapping-returned' -or ([IO.FileAttributes]$file.attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::SparseFile -bor [IO.FileAttributes]::Compressed -bor [IO.FileAttributes]::Encrypted)) -or -not (Test-ProtectedRangeReadSameMapping $file $Placement.after)){throw 'Initialized fixture changed or is not an ordinary complete mapping.'}
}

function Invoke-BoundedProtectedRangeReadCommand([scriptblock]$ScriptBlock,[object[]]$Arguments=@(),[int]$TimeoutSeconds=60) {
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

function Open-ProtectedRangeReadSession {
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

function Stop-ProtectedRangeReadGuest {
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    if($vm.State -eq 'Off'){return}
    if(-not $session -or $script:commandIndeterminate){throw 'An idle authenticated guest session is required for clean shutdown.'}
    Invoke-BoundedProtectedRangeReadCommand -TimeoutSeconds 30 -ScriptBlock { & shutdown.exe /s /t 0; if($LASTEXITCODE -ne 0){throw 'Guest shutdown request failed.'} } | Out-Null
    $deadline=[DateTime]::UtcNow.AddMinutes(3)
    do { if((Get-VM -Id ([guid]$manifest.vmId)).State -eq 'Off'){return}; Start-Sleep -Seconds 2 } while([DateTime]::UtcNow -lt $deadline)
    throw 'Guest did not shut down cleanly; preserve the branch.'
}
function Get-ProtectedRangeReadArtifactLimits {
    # Explicit byte caps include nonempty partial buffers from failed native calls.
    @{'protected-range.json'=1MB;'started.json'=64KB;'allocation-before.json'=1MB;'allocation-protected-before.json'=1MB;'allocation-after.json'=1MB;
      'pDevice.bin'=12;'pLength.bin'=8;'pAlignment.bin'=28;'pLayout.bin'=64KB;'pVolume.bin'=64;'pAttributesBefore.bin'=16;'pAttributesAfter.bin'=16;
      'sDevice.bin'=12;'sLength.bin'=8;'sAlignment.bin'=28;'sLayout.bin'=64KB;'sAttributesBefore.bin'=16;'sVolumeBefore.bin'=64;'sBaseBefore.bin'=8;'sBitmapLegacyBefore.bin'=2MB;'sBitmapMetadataBefore.bin'=2MB;'sAttributesLocked.bin'=16;'sVolumeLocked.bin'=64;'sBaseAfter.bin'=8;'sBitmapLegacyAfter.bin'=2MB;'sBitmapMetadataAfter.bin'=2MB;'sVolumeAfter.bin'=64;'sAttributesAfter.bin'=16;'oldSource.bin'=65536;'destination.bin'=65536}
}
function Assert-ProtectedRangeReadArtifact($File) {
    $limits=Get-ProtectedRangeReadArtifactLimits
    if($File.name -cnotin @($limits.Keys) -or $File.length -lt 1 -or $File.length -gt $limits[$File.name] -or $File.sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or ([IO.FileAttributes]$File.attributes -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint))){throw 'Invalid, unreviewed or oversized protected-range artifact.'}
}
function Assert-ProtectedRangeReadArtifactSet([object[]]$Files) {
    if($Files.Count -lt 1 -or $Files.Count -gt 30 -or @($Files|Where-Object name -CEQ 'protected-range.json').Count -ne 1 -or @($Files.name|Select-Object -Unique).Count -ne $Files.Count){throw 'Missing, duplicate or excessive protected-range artifacts.'}
    foreach($file in $Files){Assert-ProtectedRangeReadArtifact $file}
    if(($Files|Measure-Object length -Sum).Sum -gt 16MB){throw 'Protected-range evidence exceeds aggregate bound.'}
}
function Export-ProtectedRangeReadArtifacts([string]$GuestRoot) {
    $limits=Get-ProtectedRangeReadArtifactLimits
    $files=@(Invoke-BoundedProtectedRangeReadCommand -Arguments @($GuestRoot,$limits) -ScriptBlock {
        param($Root,$Limits)
        foreach($parent in @('C:\ntfs2refs','C:\ntfs2refs\protected-range-read',$Root)){$item=Get-Item -LiteralPath $parent -Force;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected protected-range evidence root.'}}
        $items=@(Get-ChildItem -LiteralPath $Root -Force)
        if($items.Count -gt 30){throw 'Excessive guest evidence files.'}
        foreach($file in $items){
            if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Name -cnotin @($Limits.Keys) -or $file.Length -lt 1 -or $file.Length -gt $Limits[$file.Name]){throw 'Unexpected protected-range evidence file.'}
            [pscustomobject]@{name=$file.Name;length=$file.Length;attributes=[string]$file.Attributes;sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
        }
    })
    Assert-ProtectedRangeReadArtifactSet $files
    $destination=Assert-LabPath (Join-Path $outputRoot 'guest') $configuration.Root
    if(Test-Path -LiteralPath $destination){throw 'Protected-range export destination already exists.'}
    New-Item -ItemType Directory -Path $destination|Out-Null
    foreach($file in $files){
        $path=Assert-LabPath (Join-Path $destination $file.name) $configuration.Root
        if(Test-Path -LiteralPath $path){throw 'Evidence export cannot overwrite existing files.'}
        Copy-Item -LiteralPath ($GuestRoot+'\'+$file.name) -Destination $path -FromSession $session
        $local=Get-Item -LiteralPath $path -Force
        if($local.PSIsContainer -or ($local.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $local.Length -ne $file.length -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $file.sha256){throw 'Protected-range export failed length/hash verification.'}
    }
    $files|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $destination 'exported-files.json') -Encoding UTF8
    [pscustomobject]@{files=$files;record=(Get-Content -LiteralPath (Join-Path $destination 'protected-range.json') -Raw|ConvertFrom-Json)}
}
function Read-ProtectedRangeReadPinned([string]$Path,[string]$Sha) {
    $file=Get-Item -LiteralPath $Path -Force
    if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -lt 1 -or $file.Length -gt 1MB -or (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Sha){throw 'Pinned source evidence changed.'}
    Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json
}
function Get-ProtectedRangeReadQuerySpec([string]$Name) {
    $artifacts=Get-ProtectedRangeReadArtifactLimits
    $controls=@('pWritableBefore','pWritableAfter','pLock','pDismount','pOffline','pSetAttributes','pOnline','pUnlock','sWritableBefore','sWritableLocked','sWritableAfter','sLock','sUnlock')
    if($Name -cnotin $controls -and ($Name -cin @('oldSource','destination') -or ($Name+'.bin') -cnotin @($artifacts.Keys))){throw 'Unreviewed protected-range query name.'}
    $capacity=if($Name -cin $controls){0}else{$artifacts[$Name+'.bin']}
    $inputHex='';$code=''
    if($Name -cmatch '\A[ps]Device\z'){$code='0x002d1080'}
    elseif($Name -cmatch '\A[ps]Length\z'){$code='0x0007405c'}
    elseif($Name -cmatch '\A[ps]Alignment\z'){$code='0x002d1400';$inputHex='060000000000000000000000'}
    elseif($Name -cmatch '\A[ps]Layout\z'){$code='0x00070050'}
    elseif($Name -cmatch '\A[ps]Volume(Before|Locked|After)?\z'){$code='0x00560000'}
    elseif($Name -cmatch '\A[ps]Attributes(Before|Locked|After)\z'){$code='0x000700f0'}
    elseif($Name -cmatch '\A[ps]Writable(Before|Locked|After)\z'){$code='0x00070024'}
    elseif($Name -cmatch '\AsBase(Before|After)\z'){$code='0x00090234'}
    elseif($Name -cmatch '\AsBitmapLegacy(Before|After)\z'){$code='0x0009006f';$inputHex='0000000000000000'}
    elseif($Name -cmatch '\AsBitmapMetadata(Before|After)\z'){$code='0x0009006f';$inputHex='00000000000000000100000000000000'}
    elseif($Name -cin @('pLock','sLock')){$code='0x00090018'}
    elseif($Name -cin @('pUnlock','sUnlock')){$code='0x0009001c'}
    elseif($Name -ceq 'pDismount'){$code='0x00090020'}
    elseif($Name -ceq 'pOffline'){$code='0x0056c00c'}
    elseif($Name -ceq 'pOnline'){$code='0x0056c008'}
    elseif($Name -ceq 'pSetAttributes'){$code='0x0007c0f4';$bytes=New-Object byte[] 40;[BitConverter]::GetBytes([uint32]40).CopyTo($bytes,0);[BitConverter]::GetBytes([uint64]2).CopyTo($bytes,8);[BitConverter]::GetBytes([uint64]2).CopyTo($bytes,16);$inputHex=[BitConverter]::ToString($bytes).Replace('-','').ToLowerInvariant()}
    else{throw 'No reviewed ABI for protected-range query.'}
    [pscustomobject]@{code=$code;capacity=$capacity;inputHex=$inputHex;inputBytes=($inputHex.Length/2);writeProtectedExpected=($Name -cin @('pWritableAfter','sWritableBefore','sWritableLocked','sWritableAfter'))}
}
function Assert-ProtectedRangeReadBool($Object,[string]$Name,[bool]$Expected) {
    if($Object.$Name -isnot [bool] -or $Object.$Name -ne $Expected){throw "Unexpected explicit protected-range boolean: $Name."}
}
function Assert-ProtectedRangeReadQuery($Query,[string]$GuestRoot,[object[]]$Files) {
    $spec=Get-ProtectedRangeReadQuerySpec $Query.name
    if($Query.controlCode -cne $spec.code -or $Query.inputHex -cne $spec.inputHex -or $Query.inputBytes -ne $spec.inputBytes -or $Query.outputCapacityBytes -ne $spec.capacity -or $Query.bytesReturned -lt 0 -or $Query.bytesReturned -gt $spec.capacity -or $Query.succeeded -isnot [bool] -or [string]::IsNullOrWhiteSpace($Query.startedUtc) -or [string]::IsNullOrWhiteSpace($Query.finishedUtc)){throw 'Unreviewed or unfinished protected-range native query.'}
    if($Query.bufferPath){$name=$Query.name+'.bin';$match=@($Files|Where-Object name -CEQ $name);if($Query.bufferPath -cne ($GuestRoot+'\'+$name) -or $match.Count -ne 1 -or $match[0].length -ne $Query.bytesReturned -or $match[0].sha256 -cne $Query.bufferSha256){throw 'Protected-range native buffer provenance differs.'};$name}
    elseif($Query.bytesReturned -ne 0 -or $Query.bufferSha256){throw 'Protected-range native buffer is missing.'}
}
function Initialize-ProtectedRangeReadParsers([string]$SourceRoot) {
    # Compile only reviewed source copies; the host calls pure byte validators,
    # never Protect/Observe, a native adapter, or any P/Invoke entry point.
    if(('Ntfs2Refs.NativeRangeRead' -as [type]) -or ('Ntfs2Refs.NativeProtectedRangeRead' -as [type])){throw 'Host byte validation requires a fresh process without preloaded native helper types.'}
    Add-Type -Path @((Join-Path $SourceRoot 'NativeRangeRead.cs'),(Join-Path $SourceRoot 'NativeProtectedRangeRead.cs'))
}
function Read-ProtectedRangeReadBuffer([string]$Root,[string]$Name) {
    $limits=Get-ProtectedRangeReadArtifactLimits
    if($Name -cnotin @($limits.Keys)){throw 'Unreviewed local export name.'}
    $file=Get-Item -LiteralPath (Join-Path $Root $Name) -Force
    if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -lt 1 -or $file.Length -gt $limits[$Name]){throw 'Unbounded or redirected local export.'}
    ,[IO.File]::ReadAllBytes($file.FullName)
}
function Assert-ProtectedRangeReadMounted($View,[string]$Name) {
    Assert-ProtectedRangeReadBool $View 'succeeded' $true
    if($View.name -cne $Name -or $View.nativeError -ne 0 -or $View.label -cne 'ntfs2refs-target' -or $View.fileSystem -cne 'ReFS' -or $View.serial -ne 0x08425382 -or ($View.flags -band 0x00080000) -eq 0 -or [string]::IsNullOrWhiteSpace($View.finishedUtc)){throw 'Mounted view does not establish the expected read-only volume.'}
}
function Assert-ProtectedRangeReadExportBytes($Record,[string]$Root,[byte[]]$Pattern) {
    if($Record.status -cne 'destination-range-verified'){return}
    if($Pattern.Length -ne 65536){throw 'Expected pattern has wrong length.'}
    if($Record.diskNumberObserved -lt 0 -or $Record.diskNumberObserved -gt 255){throw 'Native disk number outside profile.'}
    foreach($prefix in @('p','s')){
        [Ntfs2Refs.NativeProtectedRangeRead]::ValidateDevice((Read-ProtectedRangeReadBuffer $Root ($prefix+'Device.bin')),$Record.diskNumberObserved)
        [Ntfs2Refs.NativeProtectedRangeRead]::ValidateLength((Read-ProtectedRangeReadBuffer $Root ($prefix+'Length.bin')))
        [Ntfs2Refs.NativeProtectedRangeRead]::ValidateAlignment((Read-ProtectedRangeReadBuffer $Root ($prefix+'Alignment.bin')))
        [Ntfs2Refs.NativeProtectedRangeRead]::ValidateLayout((Read-ProtectedRangeReadBuffer $Root ($prefix+'Layout.bin')))
    }
    foreach($name in @('pVolume','sVolumeBefore','sVolumeLocked','sVolumeAfter')){[Ntfs2Refs.NativeRangeRead]::ValidateExtents((Read-ProtectedRangeReadBuffer $Root ($name+'.bin')),$Record.diskNumberObserved)}
    [Ntfs2Refs.NativeProtectedRangeRead]::ValidateAttributes((Read-ProtectedRangeReadBuffer $Root 'pAttributesBefore.bin'),$false)
    foreach($name in @('pAttributesAfter','sAttributesBefore','sAttributesLocked','sAttributesAfter')){[Ntfs2Refs.NativeProtectedRangeRead]::ValidateAttributes((Read-ProtectedRangeReadBuffer $Root ($name+'.bin')),$true)}
    foreach($name in @('sBaseBefore','sBaseAfter')){$actual=[Ntfs2Refs.NativeRangeRead]::ParseBase((Read-ProtectedRangeReadBuffer $Root ($name+'.bin')));if($actual -ne $Record.sample.baseSectors){throw 'Protected retrieval base changed or differs from exported bytes.'}}
    foreach($epoch in @('Before','After')){foreach($kind in @('Legacy','Metadata')){
        $bytes=Read-ProtectedRangeReadBuffer $Root ('sBitmap'+$kind+$epoch+'.bin')
        $source=[Ntfs2Refs.NativeRangeRead]::BitmapBits($bytes,1508352);$destination=[Ntfs2Refs.NativeRangeRead]::BitmapBits($bytes,1508384)
        if(-not [Ntfs2Refs.NativeRangeRead]::All($source,$false) -or -not [Ntfs2Refs.NativeRangeRead]::All($destination,$true)){throw 'Protected source/destination bitmap gate differs.'}
        if($epoch -ceq 'Before'){foreach($pair in @(@{bits=$source;name=('sourceBits'+$kind)},@{bits=$destination;name=('destinationBits'+$kind)})){$reported=$Record.sample.($pair.name);if(@($reported).Count -ne 16){throw 'Incomplete protected bitmap observation.'};for($i=0;$i -lt 16;$i++){if($reported[$i] -isnot [bool] -or $reported[$i] -ne $pair.bits[$i]){throw 'Protected bitmap samples disagree with native bytes.'}}}}
    }}
    $sourceMatch=$false
    foreach($read in $Record.rawReads){
        $bytes=Read-ProtectedRangeReadBuffer $Root ($read.name+'.bin');if($bytes.Length -ne 65536){throw 'Raw range is incomplete.'}
        $equal=$true;for($i=0;$i -lt 65536;$i++){if($bytes[$i] -ne $Pattern[$i]){$equal=$false;break}}
        if($read.fullPatternEqual -isnot [bool] -or $read.fullPatternEqual -ne $equal){throw 'Raw pattern comparison differs from exported bytes.'}
        if($read.name -ceq 'destination' -and -not $equal){throw 'Protected destination differs from the known logical pattern.'}
        if($read.name -ceq 'oldSource'){$sourceMatch=$equal}
    }
    if($Record.oldSourceResidualObserved -ne $sourceMatch){throw 'Residual-source summary differs from protected sampled bytes.'}
}
function Assert-ProtectedRangeReadResponse($Result,[string]$Id) {
    if($Result.CaptureId -cne $Id -or $Result.EvidenceDirectory -cne ('C:\ntfs2refs\protected-range-read\'+$Id) -or $Result.Status -cnotin @('destination-range-verified','native-open-refused','native-lock-refused','native-query-refused','blocked')){throw 'Unexpected protected-range response identity or status.'}
    foreach($field in @('RestoreAllowed','DeviceStateMutationMayHaveBeenIssued','ProtectionEstablished','DestinationSampleVerified','OldSourceResidualObserved')){if($Result.$field -isnot [bool]){throw 'Protected-range response lacks a determinate boolean.'}}
    foreach($field in @('RawWriteRequestsIssued','ConversionQualified')){Assert-ProtectedRangeReadBool $Result $field $false}
    if($Result.DestinationSampleVerified -ne ($Result.Status -ceq 'destination-range-verified') -or ($Result.OldSourceResidualObserved -and -not $Result.DestinationSampleVerified) -or ($Result.Status -ceq 'blocked' -and $Result.RestoreAllowed) -or ($Result.Status -cne 'destination-range-verified' -and $Result.DeviceStateMutationMayHaveBeenIssued -and $Result.RestoreAllowed)){throw 'Protected-range status and cleanup/qualification disagree.'}
}
function Assert-ProtectedRangeReadRecord($Record,$Response,$Profile,$Control,[object[]]$Files,[object[]]$Sources) {
    Assert-ProtectedRangeReadArtifactSet $Files
    $scriptSha=($Sources|Where-Object name -CEQ 'Capture-GuestProtectedRangeRead.ps1').sha256
    if($Record.schemaVersion -ne 1 -or $Record.kind -cne 'native-protected-range-read' -or $Record.captureId -cne $Response.CaptureId -or $Record.status -cne $Response.Status -or $Record.scriptSha256 -cne $scriptSha -or $Record.maximumRawReadBytes -ne 131072 -or $Record.maximumLockCalls -ne 2 -or $Record.maximumDiskAttributeChanges -ne 1 -or [string]::IsNullOrWhiteSpace($Record.finishedUtc)){throw 'Protected-range provenance or operation bounds differ.'}
    if(@($Record.nativeSourceHashes).Count -ne 2){throw 'Protected-range native dependency hashes missing.'}
    foreach($name in @('NativeRangeRead.cs','NativeProtectedRangeRead.cs')){$observed=@($Record.nativeSourceHashes|Where-Object name -CEQ $name);$expected=@($Sources|Where-Object name -CEQ $name);if($observed.Count -ne 1 -or $expected.Count -ne 1 -or $observed[0].sha256 -cne $expected[0].sha256){throw 'Native source provenance changed.'}}
    foreach($field in @('controlRunId','controlEvidenceSha256','capturedAllocationSha256','placementProbeId','placementEvidenceSha256','remountIdentitySha256','remountAllocationSha256','patternSha256')){if($Record.profile.$field -cne $Profile.$field){throw 'Protected-range source proof profile changed.'}}
    foreach($field in @('rawWriteRequestsIssued','targetFileWriteRequestsIssued','forcedDismountAttempted','oldSourceReserved','physicalMappingGeneralized','metadataCoverageQualified','payloadCopyAvoidanceVerified','conversionQualified','bootQualified')){Assert-ProtectedRangeReadBool $Record $field $false}
    foreach($field in @('restoreAllowed','deviceStateMutationMayHaveBeenIssued','protectionEstablished','destinationSampleVerified','oldSourceResidualObserved')){if($Record.$field -isnot [bool] -or $Record.$field -ne $Response.$field){throw 'Protected-range response and evidence disagree.'}}
    foreach($field in @('nativeOperationReturned','handleCloseSucceeded','lockMayFlushNativeWrites','protectionTransitionCompleted','diskProtectionRetained','fixturesUnchanged')){if($Record.$field -isnot [bool]){throw 'Missing protected-range state evidence.'}}
    foreach($field in @('role','uniqueId','sizeBytes','location')){if([string]$Record.target.$field -cne [string]$Control.target.guest.$field){throw 'Protected target enrollment changed.'}}
    foreach($field in @('guid','diskGuid','number','offset','length','letter','logicalSectorSize','physicalSectorSize')){if([string]$Record.partition.$field -cne [string]$Control.partition.$field){throw 'Protected GPT identity or geometry changed.'}}
    if($Record.volumeUniqueId -cne '\\?\Volume{00c9f113-e0b9-49d8-b031-130aef8ef3fb}\' -or $Record.diskNumberObserved -lt 0 -or $Record.diskNumberObserved -gt 255){throw 'Unexpected protected volume/native disk identity.'}
    $queries=@($Record.nativeQueries);$reads=@($Record.rawReads)
    if($queries.Count -gt 36 -or @($queries|ForEach-Object{$_.name}|Select-Object -Unique).Count -ne $queries.Count -or $reads.Count -gt 2 -or @($reads|ForEach-Object{$_.name}|Select-Object -Unique).Count -ne $reads.Count){throw 'Excessive or duplicated protected-range observations.'}
    $referenced=@(foreach($query in $queries){Assert-ProtectedRangeReadQuery $query $Response.EvidenceDirectory $Files})
    foreach($read in $reads){
        if($read.name -cnotin @('oldSource','destination') -or $null -eq $Record.sample -or $null -eq $Record.sample.baseSectors -or $Record.sample.baseSectors -lt 0 -or $Record.sample.baseSectors -ge (52GB/512)){throw 'Unbound protected raw range.'}
        $lcn=if($read.name -ceq 'oldSource'){1508352}else{1508384};$offset=[long]$Record.sample.baseSectors*512+[long]$lcn*4096
        if($read.lcn -ne $lcn -or $read.volumeOffset -ne $offset -or $read.guestDiskOffset -ne (16MB+$offset) -or $offset%4096 -ne 0 -or $offset -gt (52GB-65536) -or $read.requestedBytes -ne 65536 -or $read.bytesReturned -lt 0 -or $read.bytesReturned -gt 65536 -or [string]::IsNullOrWhiteSpace($read.startedUtc) -or [string]::IsNullOrWhiteSpace($read.finishedUtc)){throw 'Protected raw range exceeds exact address/byte bounds.'}
        foreach($field in @('seekAttempted','seekSucceeded','readAttempted','readSucceeded','fullPatternEqual')){if($read.$field -isnot [bool]){throw 'Missing explicit raw-read outcome.'}}
        if($read.bufferPath){$name=$read.name+'.bin';$match=@($Files|Where-Object name -CEQ $name);if($read.bufferPath -cne ($Response.EvidenceDirectory+'\'+$name) -or $match.Count -ne 1 -or $match[0].length -ne $read.bytesReturned -or $match[0].sha256 -cne $read.bufferSha256){throw 'Protected raw buffer provenance differs.'};$referenced+=$name}elseif($read.bytesReturned -ne 0 -or $read.bufferSha256){throw 'Protected raw buffer missing.'}
    }
    if(@($Files|Where-Object{$_.name -clike '*.bin' -and $_.name -cnotin $referenced}).Count){throw 'Protected export contains an unreferenced native buffer.'}
    if($Record.transition){if($Record.transition.deviceStateMutationMayHaveBeenIssued -ne $Record.deviceStateMutationMayHaveBeenIssued -or $Record.transition.protectionEstablished -ne $Record.protectionEstablished -or $Record.transition.lockAttempted -ne $Record.lockMayFlushNativeWrites){throw 'Native transition and summary disagree.'}}
}
function Assert-ProtectedRangeReadNativeClosed($Native) {
    foreach($field in @('nativeOperationReturned','volumeCloseAttempted','volumeCloseSucceeded','diskCloseAttempted','diskCloseSucceeded','handleCloseSucceeded')){Assert-ProtectedRangeReadBool $Native $field $true}
    if($Native.volumeCloseError -ne 0 -or $Native.diskCloseError -ne 0 -or ($Native.volumeOpened -and $Native.volumeOpenError -ne 0) -or ($Native.diskOpened -and $Native.diskOpenError -ne 0)){throw 'Native handle cleanup/opening retained an error.'}
    foreach($field in @('volumeOpened','diskOpened','lockAttempted','lockSucceeded','dismountAttempted','dismountSucceeded','offlineAttempted','offlineSucceeded','setAttributesAttempted','setAttributesSucceeded','onlineAttempted','onlineSucceeded','unlockAttempted','unlockSucceeded','deviceStateMutationMayHaveBeenIssued','protectionEstablished','protectionVerifiedBefore','protectionVerifiedLocked','protectionVerifiedAfter','mountedReadOnlyBefore','mountedReadOnlyAfter','rawReadMayHaveBeenIssued')){if($Native.$field -isnot [bool]){throw 'Native lifecycle has an unknown state.'}}
    if(($Native.lockSucceeded -and (-not $Native.lockAttempted -or -not $Native.unlockSucceeded)) -or ($Native.unlockSucceeded -and -not $Native.unlockAttempted) -or $Native.rangeReadCalls -lt 0 -or $Native.rangeReadCalls -gt 2){throw 'Native lock or read accounting differs.'}
}
function Get-ProtectedRangeReadQueryOrder([string]$Prefix) {
    if($Prefix -ceq 'p'){return @('pDevice','pLength','pAlignment','pLayout','pVolume','pAttributesBefore','pWritableBefore','pLock','pDismount','pOffline','pSetAttributes','pAttributesAfter','pWritableAfter','pOnline','pUnlock')}
    if($Prefix -ceq 's'){return @('sDevice','sLength','sAlignment','sLayout','sAttributesBefore','sWritableBefore','sVolumeBefore','sBaseBefore','sBitmapLegacyBefore','sBitmapMetadataBefore','sLock','sAttributesLocked','sWritableLocked','sVolumeLocked','sUnlock','sAttributesAfter','sWritableAfter','sVolumeAfter','sBaseAfter','sBitmapLegacyAfter','sBitmapMetadataAfter')}
    throw 'Unreviewed protected-range phase.'
}
function Assert-ProtectedRangeReadQueryOrder($Record,$Native,[string]$Prefix,[switch]$Complete) {
    $expected=@(Get-ProtectedRangeReadQueryOrder $Prefix);$queries=@($Record.nativeQueries|Where-Object {$_.name.StartsWith($Prefix,[StringComparison]::Ordinal)})
    if(@($Native.queryNames).Count -ne $queries.Count -or ($Complete -and $queries.Count -ne $expected.Count) -or $queries.Count -gt $expected.Count){throw 'Native control sequence count differs.'}
    for($i=0;$i -lt $queries.Count;$i++){
        if($queries[$i].name -cne $expected[$i] -or $Native.queryNames[$i] -cne $expected[$i]){throw 'Native control order differs from the reviewed lifecycle.'}
        if($Complete){$spec=Get-ProtectedRangeReadQuerySpec $queries[$i].name;if($spec.writeProtectedExpected){if($queries[$i].succeeded -ne $false -or $queries[$i].nativeError -ne 19 -or $queries[$i].bytesReturned -ne 0){throw 'Writability query did not explicitly report write protection.'}}elseif($queries[$i].succeeded -ne $true -or $queries[$i].nativeError -ne 0){throw 'Completed lifecycle contains a refused native control.'}}
    }
}
function Assert-ProtectedRangeReadCompletion($Record) {
    # The caller has already validated/exported the record. A deliberate guest
    # refusal must preserve the branch while exposing its actual native reason.
    if($Record.status -ceq 'blocked' -and $Record.restoreAllowed -is [bool] -and $Record.restoreAllowed -eq $false){
        $details=@()
        foreach($stage in @('sample','transition')){
            if($Record.PSObject.Properties.Name -ccontains $stage -and $null -ne $Record.$stage){
                $native=$Record.$stage
                if($native.error -or $native.status -ceq 'blocked'){$details+=($stage+' phase='+$native.phase);if($native.error){$details+=[string]$native.error}}
            }
        }
        if($Record.PSObject.Properties.Name -ccontains 'errors'){foreach($reason in @($Record.errors)){if(-not [string]::IsNullOrWhiteSpace([string]$reason)){$details+=('guest: '+[string]$reason)}}}
        throw ('Protected-range operation blocked; preserve the branch. '+($details -join ' | '))
    }
    foreach($field in @('restoreAllowed','nativeOperationReturned','handleCloseSucceeded','fixturesUnchanged')){Assert-ProtectedRangeReadBool $Record $field $true}
    if($null -eq $Record.transition){throw 'Protection transition completion unknown; preserve the branch.'}
    $transition=$Record.transition;Assert-ProtectedRangeReadNativeClosed $transition
    if($Record.status -cne 'destination-range-verified'){
        if($Record.status -cnotin @('native-open-refused','native-lock-refused','native-query-refused') -or $transition.status -cne $Record.status -or $null -ne $Record.sample -or @($Record.rawReads).Count -ne 0){throw 'Only an early completed refusal can restore without a successful protected sample.'}
        foreach($field in @('deviceStateMutationMayHaveBeenIssued','protectionEstablished','protectionTransitionCompleted','diskProtectionRetained','destinationSampleVerified','oldSourceResidualObserved')){Assert-ProtectedRangeReadBool $Record $field $false}
        foreach($field in @('deviceStateMutationMayHaveBeenIssued','dismountAttempted','dismountSucceeded','offlineAttempted','offlineSucceeded','setAttributesAttempted','setAttributesSucceeded','onlineAttempted','onlineSucceeded','protectionEstablished','rawReadMayHaveBeenIssued')){Assert-ProtectedRangeReadBool $transition $field $false}
        if($transition.rangeReadCalls -ne 0 -or @($Record.nativeQueries|Where-Object {$_.name -clike 's*'}).Count){throw 'Early refusal contains sampling activity.'}
        Assert-ProtectedRangeReadQueryOrder $Record $transition 'p'
        return
    }
    foreach($field in @('deviceStateMutationMayHaveBeenIssued','protectionEstablished','protectionTransitionCompleted','diskProtectionRetained','destinationSampleVerified')){Assert-ProtectedRangeReadBool $Record $field $true}
    if($transition.status -cne 'protection-established' -or $transition.phase -cne 'complete' -or $transition.error -or $null -eq $Record.sample){throw 'Successful protected sample lacks a complete transition.'}
    foreach($field in @('volumeOpened','diskOpened','lockAttempted','lockSucceeded','dismountAttempted','dismountSucceeded','offlineAttempted','offlineSucceeded','setAttributesAttempted','setAttributesSucceeded','onlineAttempted','onlineSucceeded','unlockAttempted','unlockSucceeded','deviceStateMutationMayHaveBeenIssued','protectionEstablished')){Assert-ProtectedRangeReadBool $transition $field $true}
    Assert-ProtectedRangeReadBool $transition 'rawReadMayHaveBeenIssued' $false
    if($transition.rangeReadCalls -ne 0 -or @($transition.mountedViews).Count){throw 'Transition contained unreviewed payload/mounted queries.'}
    Assert-ProtectedRangeReadQueryOrder $Record $transition 'p' -Complete
    $sample=$Record.sample;Assert-ProtectedRangeReadNativeClosed $sample
    if($sample.status -cne 'ranges-read-awaiting-file-verification' -or $sample.phase -cne 'complete' -or $sample.error -or $sample.rangeReadCalls -ne 2 -or @($Record.rawReads).Count -ne 2){throw 'Protected sample did not complete its exact two ranges.'}
    foreach($field in @('volumeOpened','diskOpened','lockAttempted','lockSucceeded','unlockAttempted','unlockSucceeded','protectionVerifiedBefore','protectionVerifiedLocked','protectionVerifiedAfter','mountedReadOnlyBefore','mountedReadOnlyAfter','rawReadMayHaveBeenIssued','oldSourceFreeInBoth','destinationAllocatedInBoth')){Assert-ProtectedRangeReadBool $sample $field $true}
    foreach($field in @('deviceStateMutationMayHaveBeenIssued','dismountAttempted','dismountSucceeded','offlineAttempted','offlineSucceeded','setAttributesAttempted','setAttributesSucceeded','onlineAttempted','onlineSucceeded','protectionEstablished')){Assert-ProtectedRangeReadBool $sample $field $false}
    foreach($field in @('samplingHandleCloseAttempted','samplingHandleCloseSucceeded','volumeReopenAttempted','volumeReopenSucceeded')){Assert-ProtectedRangeReadBool $sample $field $true}
    if($sample.samplingHandleCloseError -ne 0 -or $sample.volumeReopenError -ne 0){throw 'Sampling handle close/reopen did not complete cleanly.'}
    Assert-ProtectedRangeReadQueryOrder $Record $sample 's' -Complete
    if(@($sample.mountedViews).Count -ne 2){throw 'Protected mounted views are missing.'}
    Assert-ProtectedRangeReadMounted $sample.mountedViews[0] 'mountedBefore';Assert-ProtectedRangeReadMounted $sample.mountedViews[1] 'mountedAfter'
    $names=@('oldSource','destination')
    for($i=0;$i -lt 2;$i++){$read=$Record.rawReads[$i];if($read.name -cne $names[$i] -or $read.bytesReturned -ne 65536 -or $read.actualSeekOffset -ne $read.volumeOffset -or $read.seekError -ne 0 -or $read.readError -ne 0){throw 'Successful protected range lacks exact completed bytes.'};foreach($field in @('seekAttempted','seekSucceeded','readAttempted','readSucceeded')){Assert-ProtectedRangeReadBool $read $field $true}}
}
function Assert-ProtectedRangeReadAllocationProof($Proof,$Identity,$Placement,$Profile,[bool]$Protected,[string]$Sha,[int]$DiskNumber) {
    Assert-ProtectedRangeReadAllocation $Proof $Identity $Placement $Profile
    if($Proof.evidenceScriptSha256 -cne $Sha -or $Proof.diskNumberObserved -ne $DiskNumber){throw 'Allocation proof source or native disk binding differs.'}
    if($Protected){
        foreach($field in @('protectedReadOnlyRequired','diskReadOnlyObserved')){Assert-ProtectedRangeReadBool $Proof $field $true}
        foreach($field in @('sourceWriteRequestsIssued','physicalMappingVerified','conversionQualified','bootQualified')){Assert-ProtectedRangeReadBool $Proof $field $false}
        Assert-ProtectedRangeReadMounted $Proof.mountedBefore 'fixtureBefore';Assert-ProtectedRangeReadMounted $Proof.mountedAfter 'fixtureAfter'
    }elseif($Proof.PSObject.Properties.Name -ccontains 'protectedReadOnlyRequired' -and $Proof.protectedReadOnlyRequired -ne $false){throw 'Writable epoch contains contradictory protected-fixture evidence.'}
}
function Save-ProtectedRangeReadProgress {
    $record|ConvertTo-Json -Depth 14|Set-Content -LiteralPath (Join-Path $outputRoot 'host-result.json') -Encoding UTF8
}
function Assert-ProtectedRangeReadStarted($Started,$Record) {
    if($Started.schemaVersion -ne 1 -or $Started.kind -cne 'native-protected-range-read-started' -or $Started.captureId -cne $Record.captureId -or $Started.scriptSha256 -cne $Record.scriptSha256 -or $Started.maximumRawReadBytes -ne 131072 -or $Started.maximumLockCalls -ne 2 -or $Started.maximumDiskAttributeChanges -ne 1){throw 'Durable guest intent differs from returned operation.'}
    Assert-ProtectedRangeReadBool $Started 'deviceStateMutationMayHaveBeenIssued' $true
    foreach($field in @('rawWriteRequestsIssued','targetFileWriteRequestsIssued')){Assert-ProtectedRangeReadBool $Started $field $false}
    foreach($field in @('controlRunId','controlEvidenceSha256','capturedAllocationSha256','placementProbeId','placementEvidenceSha256','remountIdentitySha256','remountAllocationSha256','patternSha256')){if($Started.profile.$field -cne $Record.profile.$field){throw 'Guest intent source proofs differ.'}}
    foreach($field in @('role','uniqueId','sizeBytes','location')){if([string]$Started.target.$field -cne [string]$Record.target.$field){throw 'Guest intent target differs.'}}
    foreach($field in @('guid','diskGuid','number','offset','length','letter','logicalSectorSize','physicalSectorSize')){if([string]$Started.partition.$field -cne [string]$Record.partition.$field){throw 'Guest intent partition differs.'}}
    if(@($Started.nativeSourceHashes).Count -ne 2){throw 'Guest intent source hashes missing.'}
    foreach($source in $Record.nativeSourceHashes){$match=@($Started.nativeSourceHashes|Where-Object name -CEQ $source.name);if($match.Count -ne 1 -or $match[0].sha256 -cne $source.sha256){throw 'Guest intent native source changed.'}}
}

if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated Hyper-V access is required.'}
$profile=Get-ProtectedRangeReadProfile
$manifest=Read-LabManifest -Configuration $configuration -Lane win11
Assert-ProtectedRangeReadManifest $manifest $profile
$vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
$baseline=Get-ExactLabCheckpoint -VM $vm -Name installed-clean
Assert-ProtectedRangeReadCheckpoint $baseline $profile -Baseline
Assert-ProtectedRangeReadVM $vm $profile.baselineId 4GB
$saved=Get-ExactLabCheckpoint -VM $vm -Name $profile.checkpointName
Assert-ProtectedRangeReadCheckpoint $saved $profile
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
Assert-ProtectedRangeReadAllocation $savedAllocation $control.target.guest $placement $profile
$pattern=[IO.File]::ReadAllBytes((Join-Path $placementRoot 'guest\expected-pattern.bin'))
if($pattern.Length -ne 65536){throw 'Expected pattern has wrong length.'}
$laneRoot=Assert-LabPath (Join-Path $configuration.Root 'win11') $configuration.Root
$credential=Import-Clixml -LiteralPath (Join-Path $laneRoot 'secrets\guest-credential.xml')
if($credential -isnot [Management.Automation.PSCredential] -or $credential.UserName -cne 'N2R-WIN11\LabAdmin'){throw 'Unexpected guest credential identity.'}
Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 4GB
$captureId=[guid]::NewGuid().ToString('N')
$outputRoot=Assert-LabPath (Join-Path $configuration.Root ('protected-range-read\win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $configuration.Root
if(Test-Path -LiteralPath $outputRoot){throw 'ProtectedRangeRead output root already exists.'}
New-Item -ItemType Directory -Path $outputRoot | Out-Null
$guestNames=@('GuestLab.psm1','Capture-GuestAllocation.ps1','NativeRangeRead.cs','NativeProtectedRangeRead.cs','Capture-GuestProtectedRangeRead.ps1')
$sourceHashes=@(foreach($name in $guestNames){$path=Join-Path $workspace ('lab\guest\'+$name);$file=Get-Item -LiteralPath $path -Force;if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -lt 1 -or $file.Length -gt 256KB){throw 'Unexpected protected-range-read source file.'};[pscustomobject]@{name=$name;length=$file.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}})
$reviewedSources=Assert-LabPath (Join-Path $outputRoot 'reviewed-sources') $configuration.Root
New-Item -ItemType Directory -Path $reviewedSources|Out-Null
foreach($file in $sourceHashes){$copy=Join-Path $reviewedSources $file.name;if(Test-Path -LiteralPath $copy){throw 'Reviewed source archive already exists.'};Copy-Item -LiteralPath (Join-Path $workspace ('lab\guest\'+$file.name)) -Destination $copy;if((Get-Item -LiteralPath $copy).Length -ne $file.length -or (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash.ToLowerInvariant() -cne $file.sha256){throw 'Reviewed source archive differs.'}}
$hostSha=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$modulePath=Join-Path $workspace 'lab\Lab.psm1';$moduleSha=(Get-FileHash -LiteralPath $modulePath -Algorithm SHA256).Hash.ToLowerInvariant()
Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $reviewedSources 'Invoke-LabProtectedRangeRead.ps1')
Copy-Item -LiteralPath $modulePath -Destination (Join-Path $reviewedSources 'Lab.psm1')
if((Get-FileHash -LiteralPath (Join-Path $reviewedSources 'Invoke-LabProtectedRangeRead.ps1') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hostSha -or (Get-FileHash -LiteralPath (Join-Path $reviewedSources 'Lab.psm1') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $moduleSha){throw 'Host source archive differs.'}
$record=[ordered]@{schemaVersion=1;kind='native-protected-range-read-host';captureId=$captureId;profile=$profile;vmId=$profile.vmId;baselineId=$profile.baselineId;sourceCheckpointId=$profile.checkpointId;sourceCheckpointName=$profile.checkpointName;status='started';phase='preflight';evidenceExported=$false;cleanShutdown=$false;baselineRestored=$false;memoryRestored=$false;deviceStateControlsMayHaveBeenIssued=$false;deviceStateMutationMayHaveBeenIssued=$false;nativeOperationReturned=$false;nativeOperationCompletionUnknown=$false;protectionEstablished=$false;diskProtectionRetained=$false;rawWriteRequestsIssued=$false;targetFileWriteRequestsIssued=$false;destinationSampleVerified=$false;oldSourceResidualObserved=$false;physicalMappingGeneralized=$false;metadataCoverageQualified=$false;payloadCopyAvoidanceVerified=$false;conversionQualified=$false;bootQualified=$false;sourceHashes=$sourceHashes;hostScriptSha256=$hostSha;labModuleSha256=$moduleSha;createdUtc=[DateTime]::UtcNow.ToString('o')}
$session=$null;$script:commandIndeterminate=$false
try {
    Save-ProtectedRangeReadProgress
    Initialize-ProtectedRangeReadParsers $reviewedSources
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-ProtectedRangeReadVM $vm $profile.baselineId 4GB
    Assert-ProtectedRangeReadCheckpoint (Get-ExactLabCheckpoint -VM $vm -Name $profile.checkpointName) $profile
    $record.phase='restore-placement-outcome';Save-ProtectedRangeReadProgress
    Invoke-LabAction -Action Restore -Lane win11 -CheckpointName $profile.checkpointName -Confirm:$false|Out-Null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-ProtectedRangeReadVM $vm $profile.checkpointId 8GB
    Invoke-LabAction -Action Start -Lane win11 -Confirm:$false|Out-Null
    $session=Open-ProtectedRangeReadSession
    $policy=Initialize-LabGuestSession -Session $session
    $policy|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $outputRoot 'session.json') -Encoding UTF8
    if($policy.status -cne 'ready'){throw ('Guest session refused: '+$policy.error)}
    Invoke-BoundedProtectedRangeReadCommand -Arguments @(,$guestNames) -ScriptBlock {
        param($Names)
        foreach($path in @('C:\ntfs2refs','C:\ntfs2refs\guest')){$item=Get-Item -LiteralPath $path -Force;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected guest script directory.'}}
        foreach($name in $Names){$path='C:\ntfs2refs\guest\'+$name;if(Test-Path -LiteralPath $path){$item=Get-Item -LiteralPath $path -Force;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected guest helper destination.'}}}
    }|Out-Null
    foreach($file in $sourceHashes){Copy-Item -LiteralPath (Join-Path $reviewedSources $file.name) -Destination ('C:\ntfs2refs\guest\'+$file.name) -ToSession $session -Force}
    $copied=@(Invoke-BoundedProtectedRangeReadCommand -Arguments @(,$guestNames) -ScriptBlock {param($Names);foreach($name in $Names){$path='C:\ntfs2refs\guest\'+$name;$file=Get-Item -LiteralPath $path -Force;if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected copied helper.'};[pscustomobject]@{name=$name;length=$file.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}}})
    if($copied.Count -ne $sourceHashes.Count){throw 'Incomplete protected-range helper copy.'}
    foreach($file in $sourceHashes){$copy=@($copied|Where-Object name -CEQ $file.name);if($copy.Count -ne 1 -or $copy[0].length -ne $file.length -or $copy[0].sha256 -cne $file.sha256){throw 'Guest helper hash differs from reviewed source.'}}
    Get-OwnedLabVM -Configuration $configuration -Manifest $manifest|Out-Null
    $record.phase='protected-mounted-range-read';$record.deviceStateControlsMayHaveBeenIssued=$true;$record.deviceStateMutationMayHaveBeenIssued=$null;$record.protectionEstablished=$null;$record.diskProtectionRetained=$null;$record.nativeOperationCompletionUnknown=$true
    Save-ProtectedRangeReadProgress # Durable intent precedes native guest dispatch.
    $responses=@(Invoke-BoundedProtectedRangeReadCommand -TimeoutSeconds $CaptureTimeoutSeconds -Arguments @($captureId) -ScriptBlock {param($CaptureId);& 'C:\ntfs2refs\guest\Capture-GuestProtectedRangeRead.ps1' -CaptureId $CaptureId -Confirm:$false})
    if($responses.Count -ne 1){throw 'Guest returned an ambiguous protected-range response.'}
    $response=$responses[0];Assert-ProtectedRangeReadResponse $response $captureId
    $record.phase='export'
    $export=Export-ProtectedRangeReadArtifacts $response.EvidenceDirectory
    Assert-ProtectedRangeReadRecord $export.record $response $profile $control $export.files $sourceHashes
    $record.evidenceExported=$true;$record['guestStatus']=$response.Status;$record['guestEvidenceSha256']=($export.files|Where-Object name -CEQ 'protected-range.json').sha256
    foreach($field in @('deviceStateMutationMayHaveBeenIssued','nativeOperationReturned','protectionEstablished','diskProtectionRetained','destinationSampleVerified','oldSourceResidualObserved')){$record[$field]=$export.record.$field}
    $record.nativeOperationCompletionUnknown=-not $export.record.nativeOperationReturned
    Save-ProtectedRangeReadProgress
    Assert-ProtectedRangeReadCompletion $export.record # Mutation-phase failures cannot reach shutdown or restore.
    if(@($export.files|Where-Object name -CEQ 'started.json').Count -ne 1){throw 'Returned native operation lacks durable start evidence.'}
    $started=Get-Content -LiteralPath (Join-Path $outputRoot 'guest\started.json') -Raw|ConvertFrom-Json
    Assert-ProtectedRangeReadStarted $started $export.record
    $scriptSha=($sourceHashes|Where-Object name -CEQ 'Capture-GuestProtectedRangeRead.ps1').sha256
    $collectorSha=($sourceHashes|Where-Object name -CEQ 'Capture-GuestAllocation.ps1').sha256
    $protected=$export.record.status -ceq 'destination-range-verified'
    $fixtureNames=@('allocation-before.json','allocation-after.json');if($protected){$fixtureNames+='allocation-protected-before.json'}elseif(@($export.files|Where-Object name -CEQ 'allocation-protected-before.json').Count){throw 'Early refusal contains a protected fixture epoch.'}
    foreach($name in $fixtureNames){
        if(@($export.files|Where-Object name -CEQ $name).Count -ne 1){throw 'Missing required fixture epoch.'}
        $proof=Get-Content -LiteralPath (Join-Path $outputRoot ('guest\'+$name)) -Raw|ConvertFrom-Json
        $requiresProtection=$protected -and $name -cne 'allocation-before.json';$expectedSha=if($requiresProtection){$scriptSha}else{$collectorSha}
        Assert-ProtectedRangeReadAllocationProof $proof $control.target.guest $placement $profile $requiresProtection $expectedSha $export.record.diskNumberObserved
    }
    Assert-ProtectedRangeReadExportBytes $export.record (Join-Path $outputRoot 'guest') $pattern
    $record.phase='clean-shutdown';Save-ProtectedRangeReadProgress
    Stop-ProtectedRangeReadGuest
    $record.cleanShutdown=$true
    Remove-PSSession -Session $session -ErrorAction SilentlyContinue;$session=$null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-ProtectedRangeReadVM $vm $profile.checkpointId 8GB
    Assert-ProtectedRangeReadCheckpoint (Get-ExactLabCheckpoint -VM $vm -Name installed-clean) $profile -Baseline
    $record.phase='restore-baseline';Save-ProtectedRangeReadProgress
    Invoke-LabAction -Action Restore -Lane win11 -CheckpointName installed-clean -Confirm:$false|Out-Null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    if($vm.State -ne 'Off' -or [string]$vm.ParentSnapshotId -ine $profile.baselineId){throw 'Baseline restore did not return the exact off-state branch.'}
    if($vm.MemoryStartup -ne 4GB -or $vm.DynamicMemoryEnabled){Set-VMMemory -VM $vm -StartupBytes 4GB -DynamicMemoryEnabled $false}
    Assert-ProtectedRangeReadVM (Get-OwnedLabVM -Configuration $configuration -Manifest $manifest) $profile.baselineId 4GB
    $record.baselineRestored=$true;$record.memoryRestored=$true;$record.status='native-protected-range-read-exported';$record.phase='complete'
} catch {
    $record.status='failed-preserved';$record['error']=$_.Exception.Message;$record['errorPosition']=$_.InvocationInfo.PositionMessage;$record['scriptStackTrace']=$_.ScriptStackTrace
    # No shutdown, restore, checkpoint, protection clearing, job stop or memory change on failure.
    throw
} finally {
    $record['commandCompletionUnknown']=$script:commandIndeterminate;$record['finishedUtc']=[DateTime]::UtcNow.ToString('o');Save-ProtectedRangeReadProgress
    if($session -and -not $script:commandIndeterminate){Remove-PSSession -Session $session -ErrorAction SilentlyContinue}
    $credential=$null
}
[pscustomobject]@{Status=$record.status;Evidence=$outputRoot;EvidenceExported=$record.evidenceExported;BaselineRestored=$record.baselineRestored;MemoryRestored=$record.memoryRestored;DeviceStateMutationMayHaveBeenIssued=$record.deviceStateMutationMayHaveBeenIssued;ProtectionEstablished=$record.protectionEstablished;DestinationSampleVerified=$record.destinationSampleVerified;OldSourceResidualObserved=$record.oldSourceResidualObserved;RawWriteRequestsIssued=$false;ConversionQualified=$false}
