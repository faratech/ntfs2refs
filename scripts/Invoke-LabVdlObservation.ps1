<# Restore one preserved VDL outcome and observe metadata only; host orchestration. #>
[CmdletBinding(SupportsShouldProcess)]
param([ValidateRange(60,900)][int]$BootTimeoutSeconds=300,[ValidateRange(30,600)][int]$QueryTimeoutSeconds=180)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
$configuration=Get-LabConfiguration -WorkspaceRoot $workspace
if(-not $PSCmdlet.ShouldProcess('ntfs2refs-win11','Restore exact VDL outcome at 8 GiB, observe preserved file metadata, export, cleanly return to baseline at 4 GiB')){[pscustomobject]@{Action='NativeVdlObservation';DryRun=$true;NewFilePayloadReads=$false;TargetWriteRequestsIssued=$false;ConversionQualified=$false};return}
function Assert-VdlObservationHostManifest($Manifest,$Profile) {
    if ([string]$Manifest.vmId -ine $Profile.vmId -or @($Manifest.disks).Count -ne 3) { throw 'Unexpected VDL probe VM or disk count.' }
    foreach($role in @('os','target','journal')) {
        $selected=@($Manifest.disks | Where-Object role -CEQ $role)
        $slot=if($role -ceq 'os'){0}elseif($role -ceq 'target'){1}else{2}
        $bytes=if($role -ceq 'journal'){8GB}else{64GB}
        if($selected.Count -ne 1 -or $selected[0].controllerLocation -ne $slot -or $selected[0].sizeBytes -ne $bytes) { throw 'Discovery requires the original three owned disks.' }
        if($role -ceq 'target' -and [string]$selected[0].vhdId -ine $Profile.targetVhdId) { throw 'Unexpected original target VHD identity.' }
    }
}
function Assert-VdlObservationHostVM($VM,[string]$ExpectedParent,[long]$MemoryBytes) {
    if($VM.State -ne 'Off' -or $VM.MemoryStartup -ne $MemoryBytes -or $VM.DynamicMemoryEnabled -or [string]$VM.ParentSnapshotId -ine $ExpectedParent) { throw 'Discovery requires the exact powered-off checkpoint branch and fixed memory profile.' }
    if(@(Get-VMNetworkAdapter -VM $VM | Where-Object SwitchName).Count -or (Get-VMFirmware -VM $VM).SecureBoot -ne 'On') { throw 'Discovery requires disconnected networking and unchanged Secure Boot.' }
}
function Assert-VdlObservationHostCheckpoint($Checkpoint,$Profile,[switch]$Baseline) {
    $id=if($Baseline){$Profile.baselineId}else{$Profile.checkpointId}
    $name=if($Baseline){'installed-clean'}else{$Profile.checkpointName}
    $memory=if($Baseline){4GB}else{8GB}
    if([string]$Checkpoint.Id -ine $id -or $Checkpoint.Name -cne $name -or [string]$Checkpoint.VMId -ine $Profile.vmId -or $Checkpoint.State -ne 'Off' -or $Checkpoint.MemoryStartup -ne $memory -or $Checkpoint.DynamicMemoryEnabled) { throw 'Saved VDL observation checkpoint identity or off-state memory changed.' }
}
function Invoke-BoundedVdlObservationCommand([scriptblock]$ScriptBlock,[object[]]$Arguments=@(),[int]$TimeoutSeconds=60) {
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
function Open-VdlObservationHostSession {
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
function Stop-VdlObservationHostGuest {
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    if($vm.State -eq 'Off'){return}
    if(-not $session -or $script:commandIndeterminate){throw 'An idle authenticated guest session is required for clean shutdown.'}
    Invoke-BoundedVdlObservationCommand -TimeoutSeconds 30 -ScriptBlock { & shutdown.exe /s /t 0; if($LASTEXITCODE -ne 0){throw 'Guest shutdown request failed.'} } | Out-Null
    $deadline=[DateTime]::UtcNow.AddMinutes(3)
    do { if((Get-VM -Id ([guid]$manifest.vmId)).State -eq 'Off'){return}; Start-Sleep -Seconds 2 } while([DateTime]::UtcNow -lt $deadline)
    throw 'Guest did not shut down cleanly; preserve the branch.'
}
function Assert-VdlObservationHostBool($Object,[string]$Field,[bool]$Expected) {
    if($Object.$Field -isnot [bool] -or $Object.$Field -ne $Expected){throw "Unexpected VDL boolean: $Field."}
}
function Read-VdlObservationHostPinned([string]$Path,[string]$Sha) {
    $file=Get-Item -LiteralPath $Path -Force
    if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -lt 1 -or $file.Length -gt 1MB -or (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Sha){throw 'Pinned VDL source evidence changed.'}
    $decoded=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json
    # Windows PowerShell 5 emits a JSON array as one pipeline item; normalize
    # enumeration so the bounded exported-file manifest has identical semantics.
    if($decoded -is [array]){foreach($item in $decoded){$item}}else{$decoded}
}
function Save-VdlObservationHostProgress {
    $record|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $outputRoot 'host-result.json') -Encoding UTF8
}
function Get-VdlObservationHostProfile {
    [pscustomobject]@{vmId='eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c';baselineId='eda059b3-6d50-46bb-bdf4-018b99b5b34f';checkpointId='209475c5-c949-41aa-8887-997439f0f70e';checkpointName='vdl-probe-data-2780e16cd7bb4d12a5ba8070bac0a1e7';measurementId='2780e16cd7bb4d12a5ba8070bac0a1e7';sourceDirectory='vdl-probe\win11-20261024T004239424Z';sourceHostSha256='ae81d602f7806227a59fd8090215370703912891f506e3a30b2f80a2df416aaa';sourceEvidenceSha256='cb484a4a92da8a72861ce4cd7f93ed8bffb1873236cc6c94d4c9efd6861c5fda';sourceExportSha256='2377a5eb41afcf853fb797883362e4e694d45bc7f85f2b76dc9bd8795e5242ad';sourceControlSha256='0676470fce3a6ee3500835a02224117bc8106826d4d2f99ac395c3ca4b06bef9';targetVhdId='25c491d0-5f1b-4205-9e6f-fd619706c2b5';controlDirectory='devdrive\win11-20261023T230635404Z';controlEvidenceSha256='ca9e3e60bbe84bd758609d92b92a305a948213b4ab0f5ce199f38567a8ea84c1';placementDirectory='extent-placement\win11-20261024T000401422Z';placementEvidenceSha256='865e9a7517dd1e0bd925d7fad5af85146fa8ec4c447d5640958473c11cd30cc5'}
}
function Assert-VdlObservationHostOrigin($Origin,$Profile) {
    if($Origin.schemaVersion -ne 1 -or $Origin.kind -cne 'native-vdl-probe-host' -or $Origin.status -cne 'native-vdl-unresolved-exported' -or $Origin.phase -cne 'complete' -or $Origin.measurementId -cne $Profile.measurementId -or $Origin.vmId -ine $Profile.vmId -or $Origin.baselineId -ine $Profile.baselineId -or $Origin.outcomeCheckpointId -ine $Profile.checkpointId -or $Origin.outcomeCheckpointName -cne $Profile.checkpointName -or $Origin.allocationEvidenceSha256 -cne $Profile.sourceEvidenceSha256 -or $Origin.controlEvidenceSha256 -cne $Profile.sourceControlSha256){throw 'Preserved VDL host origin differs.'}
    foreach($f in @('controlEvidenceExported','allocationEvidenceExported','allocationDispatched','controlQualified','targetWriteRequestsIssued','fileCreated','directoryCreated','cleanShutdown','outcomeCheckpointCreated','baselineRestored','memoryRestored')){Assert-VdlObservationHostBool $Origin $f $true}
    foreach($f in @('zeroVdlQualified','newFilePayloadReads','newFilePayloadWrites','moveAttempted','setValidDataAttempted','privilegeAdjustmentAttempted','physicalMappingVerified','payloadCopyAvoidanceVerified','conversionQualified','bootQualified','commandCompletionUnknown')){Assert-VdlObservationHostBool $Origin $f $false}
}
function Assert-VdlObservationHostSourceFiles([object[]]$Files,[string]$Directory) {
    if($Files.Count -ne 18 -or @($Files.name|Select-Object -Unique).Count -ne 18){throw 'Preserved allocation export count differs.'}
    foreach($f in $Files){
        $maximum=0
        if($f.name -cin @('allocation.json','started.json','original-before.json','original-after.json')){$maximum=1MB}
        elseif($f.name -cmatch '\A(?:control-(?:before|after)|allocation-immediate)(Standard|Cached|OnDisk|Extents)\.bin\z'){$maximum=if($Matches[1] -ceq 'Standard'){24}elseif($Matches[1] -ceq 'Extents'){272}else{400}}
        elseif($f.name -cmatch '\Aallocation-(?:empty|allocated)Standard\.bin\z'){$maximum=24}
        else{throw 'Unreviewed preserved source artifact.'}
        if($f.length -lt 1 -or $f.length -gt $maximum -or $f.sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or ([IO.FileAttributes]$f.attributes -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint))){throw 'Invalid source artifact metadata.'}
        $path=Join-Path $Directory $f.name;$item=Get-Item -LiteralPath $path -Force
        if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -ne $f.length -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $f.sha256){throw 'Preserved source file changed.'}
    }
}
function Get-VdlObservationHostQuerySpec([string]$Name) {
    if($Name -cnotmatch '\A(before|after)(Standard|Cached|OnDisk|Extents)\z'){throw 'Unexpected observation query name.'};$kind=$Matches[2]
    if($kind -ceq 'Standard'){return [pscustomobject]@{capacity=24;code='0x00000000';api='GetFileInformationByHandleEx';informationClass=1;inputHex='';inputBytes=0}}
    if($kind -ceq 'Extents'){return [pscustomobject]@{capacity=272;code='0x00090073';api='DeviceIoControl';informationClass=0;inputHex='0000000000000000';inputBytes=8}}
    $usage=if($kind -ceq 'Cached'){'01000000'}else{'02000000'}
    [pscustomobject]@{capacity=400;code='0x00090284';api='DeviceIoControl';informationClass=0;inputHex=('00000000000000000000010000000000'+$usage+'00000000');inputBytes=24}
}
function Assert-VdlObservationHostArtifactSet([object[]]$Files) {
    if($Files.Count -lt 1 -or $Files.Count -gt 11 -or @($Files|Where-Object name -CEQ 'observation.json').Count -ne 1 -or @($Files.name|Select-Object -Unique).Count -ne $Files.Count){throw 'Missing, duplicate or excessive observation artifacts.'}
    foreach($f in $Files){$maximum=0;if($f.name -cin @('observation.json','original-before.json','original-after.json')){$maximum=1MB}elseif($f.name -cmatch '\A(.+)\.bin\z'){$maximum=(Get-VdlObservationHostQuerySpec $Matches[1]).capacity}else{throw 'Unexpected observation artifact.'};if($f.length -lt 1 -or $f.length -gt $maximum -or $f.sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or ([IO.FileAttributes]$f.attributes -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint))){throw 'Invalid bounded observation artifact.'}}
    if(($Files|Measure-Object length -Sum).Sum -gt (3MB+2192)){throw 'Observation aggregate limit exceeded.'}
}
function Assert-VdlObservationHostResponse($Response,[string]$Id) {
    if($Response.ObservationId -cne $Id -or $Response.EvidenceDirectory -cne ('C:\ntfs2refs\vdl-observation\'+$Id) -or $Response.Status -cnotin @('blocked','metadata-observed','native-query-unresolved','cleanup-failed')){throw 'Unexpected observation response.'}
    foreach($f in @('NewFilePayloadReads','TargetWriteRequestsIssued','ConversionQualified')){Assert-VdlObservationHostBool $Response $f $false}
}
function Assert-VdlObservationHostRecord($Record,$Response,$Profile,$Control,[object[]]$Files,[string]$ScriptSha,[string]$NativeSha,[string]$Directory) {
    Assert-VdlObservationHostResponse $Response $Response.ObservationId;Assert-VdlObservationHostArtifactSet $Files
    if($Record.schemaVersion -ne 1 -or $Record.kind -cne 'native-vdl-post-remount-observation' -or $Record.observationId -cne $Response.ObservationId -or $Record.measurementId -cne $Profile.measurementId -or $Record.sourceEvidenceSha256 -cne $Profile.sourceEvidenceSha256 -or $Record.sourceCheckpointId -ine $Profile.checkpointId -or $Record.status -cne $Response.Status -or $Record.scriptSha256 -cne $ScriptSha -or $Record.nativeSourceSha256 -cne $NativeSha -or -not $Record.finishedUtc){throw 'Observation provenance changed.'}
    foreach($f in @('newFilePayloadReads','newFilePayloadWrites','targetWriteRequestsIssued','explicitFlushRequested','moveAttempted','setValidDataAttempted','allocationRequested','protectionChanged','privilegeAdjustmentAttempted','physicalMappingVerified','zeroVdlQualified','payloadCopyAvoidanceVerified','conversionQualified')){Assert-VdlObservationHostBool $Record $f $false}
    foreach($f in @('role','uniqueId','sizeBytes','location')){if([string]$Record.target.$f -cne [string]$Control.target.guest.$f){throw 'Observation target enrollment changed.'}}
    foreach($f in @('guid','diskGuid','number','offset','length','letter','logicalSectorSize','physicalSectorSize')){if([string]$Record.partition.$f -cne [string]$Control.partition.$f){throw 'Observation GPT geometry changed.'}}
    if($Record.volumeUniqueId -cne [Ntfs2Refs.NativeVdlObservation]::VolumePath){throw 'Observation volume differs.'}
    $queries=@($Record.nativeQueries);if($queries.Count -gt 8 -or @($queries.name|Select-Object -Unique).Count -ne $queries.Count){throw 'Unexpected query count.'};$referenced=@()
    foreach($q in $queries){$spec=Get-VdlObservationHostQuerySpec $q.name
        if($q.api -cne $spec.api -or $q.controlCode -cne $spec.code -or $q.informationClass -ne $spec.informationClass -or $q.inputHex -cne $spec.inputHex -or $q.inputBytes -ne $spec.inputBytes -or $q.outputCapacityBytes -ne $spec.capacity -or $q.bytesReturned -lt 0 -or $q.bytesReturned -gt $spec.capacity -or $q.succeeded -isnot [bool] -or -not $q.startedUtc -or -not $q.finishedUtc){throw 'Unreviewed query contract.'}
        if(($q.succeeded -and $q.nativeError -ne 0) -or (-not $q.succeeded -and $q.nativeError -eq 0)){throw 'Query status/error disagree.'}
        if($q.bufferPath){$name=$q.name+'.bin';$found=@($Files|Where-Object name -CEQ $name);if($q.bufferPath -cne ($Response.EvidenceDirectory+'\'+$name) -or $found.Count -ne 1 -or $found[0].sha256 -cne $q.bufferSha256 -or $found[0].length -ne $q.bytesReturned){throw 'Native buffer provenance changed.'};$referenced+=$name}elseif($q.bytesReturned -ne 0 -or $q.bufferSha256){throw 'Native buffer missing.'}
    }
    if(@($Files|Where-Object{$_.name -clike '*.bin' -and $_.name -cnotin $referenced}).Count){throw 'Unreferenced native buffer.'}
    $n=$Record.nativeObservation;if($null -eq $n){return}
    foreach($f in @('newFilePayloadReads','newFilePayloadWrites','targetWriteRequestsIssued','explicitFlushRequested','moveAttempted','setValidDataAttempted','allocationRequested','protectionChanged','privilegeAdjustmentAttempted','physicalMappingVerified','zeroVdlQualified','payloadCopyAvoidanceVerified','conversionQualified')){Assert-VdlObservationHostBool $n $f $false}
    if($n.fixturePath -cne [Ntfs2Refs.NativeVdlObservation]::FilePath -or @($n.snapshots).Count -gt 2 -or @($n.volumes).Count -gt 2){throw 'Unexpected native observation scope.'}
    foreach($v in $n.volumes){if($v.name -cnotin @('before','after') -or $v.api -cne 'GetVolumeInformationW' -or $v.succeeded -isnot [bool] -or ($v.succeeded -and $v.nativeError -ne 0) -or (-not $v.succeeded -and $v.nativeError -eq 0)){throw 'Invalid mounted-volume observation.'};Assert-VdlObservationHostBool $v 'supportsSparseVdl' ([bool]($v.flags -band 0x10000000));Assert-VdlObservationHostBool $v 'readOnlyVolume' ([bool]($v.flags -band 0x80000));if($v.succeeded -and ($v.serial -ne 0x08425382 -or $v.filesystem -cne 'ReFS' -or $v.label -cne 'ntfs2refs-target')){throw 'Mounted volume identity differs.'}}
    foreach($s in $n.snapshots){
        if($s.name -cnotin @('before','after') -or $s.identity.fileId64 -cne '0x3000000000002703' -or $s.identity.volumeSerialHex -cne '0x08425382' -or $s.identity.length -ne 65536 -or $s.identity.links -ne 1 -or ($s.identity.attributes -band 0x4410)){throw 'Preserved file identity differs.'}
        foreach($pair in @(@('Standard','standard'),@('Cached','cached'),@('OnDisk','onDisk'),@('Extents','extents'))){$q=@($queries|Where-Object name -CEQ ($s.name+$pair[0]));if($q.Count -ne 1){throw 'Snapshot query missing.'};if($q[0].succeeded){
            $b=[IO.File]::ReadAllBytes((Join-Path $Directory ($q[0].name+'.bin')));$parsed=$null;$parseFailed=$false
            try{$parsed=switch($pair[0]){'Standard'{[Ntfs2Refs.NativeVdlObservation]::ParseStandard($b)}'Cached'{[Ntfs2Refs.NativeVdlObservation]::ParseRegions($b,1)}'OnDisk'{[Ntfs2Refs.NativeVdlObservation]::ParseRegions($b,2)}'Extents'{,[Ntfs2Refs.NativeVdlObservation]::ParseSignedExtents($b)}}}catch{$parseFailed=$true}
            if($parseFailed){if($null -ne $s.($pair[1]) -or $s.complete -or @($s.errors).Count -eq 0){throw 'Malformed native bytes were presented as qualified.'}}
            elseif(($parsed|ConvertTo-Json -Depth 10 -Compress) -cne ($s.($pair[1])|ConvertTo-Json -Depth 10 -Compress)){throw 'Parsed metadata differs from exported bytes.'}
        }elseif($null -ne $s.($pair[1]) -or $s.complete){throw 'Refused native query has a fabricated parsed result.'}}
    }
    if($n.observationComplete){if($queries.Count -ne 8 -or @($n.snapshots).Count -ne 2 -or @($n.volumes).Count -ne 2 -or $n.snapshots[0].name -cne 'before' -or $n.snapshots[1].name -cne 'after' -or $n.volumes[0].name -cne 'before' -or $n.volumes[1].name -cne 'after' -or @($queries|Where-Object{-not $_.succeeded}).Count -or @($n.snapshots|Where-Object{-not $_.complete}).Count -or @($n.volumes|Where-Object{-not $_.succeeded}).Count){throw 'Incomplete observation marked complete.'}}
    $stable=[bool]$n.observationComplete -and $n.volumes[0].flags -eq $n.volumes[1].flags
    if($stable){foreach($f in @('fileId64','volumeSerialHex','length','links','attributes')){if([string]$n.snapshots[0].identity.$f -cne [string]$n.snapshots[1].identity.$f){$stable=$false}}}
    if($stable){foreach($suffix in @('Standard','Cached','OnDisk','Extents')){$a=@($queries|Where-Object name -CEQ ('before'+$suffix));$b=@($queries|Where-Object name -CEQ ('after'+$suffix));if($a[0].bufferSha256 -cne $b[0].bufferSha256){$stable=$false}}}
    Assert-VdlObservationHostBool $n 'stableDuringObservation' $stable
}
function Assert-VdlObservationHostDisposition($Record) {
    Assert-VdlObservationHostBool $Record 'originalFixturesUnchanged' $true
    if($Record.status -cnotin @('metadata-observed','native-query-unresolved') -or $null -eq $Record.nativeObservation){throw 'Observation did not reach a determinate native result; preserve branch.'}
    $n=$Record.nativeObservation
    if($n.status -cne $Record.status -or $n.phase -cne 'complete' -or $n.error -or $n.cleanupError){throw 'Native observation failure requires preservation.'}
    foreach($f in @('identityVerified','cleanupComplete')){Assert-VdlObservationHostBool $n $f $true}
    if($Record.status -ceq 'metadata-observed'){Assert-VdlObservationHostBool $n 'observationComplete' $true}else{Assert-VdlObservationHostBool $n 'observationComplete' $false}
}
function Export-VdlObservationHostArtifacts([string]$GuestRoot) {
    $files=@(Invoke-BoundedVdlObservationCommand -Arguments @($GuestRoot,$observationId) -ScriptBlock {param($Root,$Id)
        foreach($p in @('C:\ntfs2refs','C:\ntfs2refs\vdl-observation',$Root)){$i=Get-Item -LiteralPath $p -Force;if(-not $i.PSIsContainer -or ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected observation parent.'}}
        if($Root -cne ('C:\ntfs2refs\vdl-observation\'+$Id)){throw 'Unexpected observation root.'};$items=@(Get-ChildItem -LiteralPath $Root -Force);if($items.Count -gt 11){throw 'Excessive artifacts.'}
        foreach($f in $items){if($f.PSIsContainer -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $f.Length -lt 1 -or $f.Length -gt 1MB -or ($f.Name -cnotin @('observation.json','original-before.json','original-after.json') -and $f.Name -cnotmatch '\A(before|after)(Standard|Cached|OnDisk|Extents)\.bin\z')){throw 'Unexpected observation artifact.'};[pscustomobject]@{name=$f.Name;length=$f.Length;attributes=[string]$f.Attributes;sha256=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}}
    })
    Assert-VdlObservationHostArtifactSet $files
    $destination=Assert-LabPath (Join-Path $outputRoot 'guest') $configuration.Root;if(Test-Path -LiteralPath $destination){throw 'Export destination exists.'};New-Item -ItemType Directory -Path $destination|Out-Null
    foreach($f in $files){$path=Assert-LabPath (Join-Path $destination $f.name) $configuration.Root;if(Test-Path -LiteralPath $path){throw 'Export would overwrite.'};Copy-Item -LiteralPath ($GuestRoot+'\'+$f.name) -Destination $path -FromSession $session;$i=Get-Item -LiteralPath $path -Force;if($i.PSIsContainer -or ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $i.Length -ne $f.length -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $f.sha256){throw 'Export hash/size mismatch.'}}
    $files|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $destination 'exported-files.json') -Encoding UTF8
    [pscustomobject]@{files=$files;record=(Get-Content -LiteralPath (Join-Path $destination 'observation.json') -Raw|ConvertFrom-Json);directory=$destination}
}

function Get-VdlObservationFixture($Evidence,$Identity) {
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
function Test-VdlObservationSameMapping($Left,$Right) {
    if ($Left.fileId64 -cne $Right.fileId64 -or $Left.volumeSerialHex -cne $Right.volumeSerialHex -or $Left.length -ne $Right.length -or $Left.sha256 -cne $Right.sha256 -or @($Left.extents).Count -ne @($Right.extents).Count) { return $false }
    for($i=0;$i -lt @($Left.extents).Count;$i++) { foreach($name in @('startingVcn','nextVcn','lcn')) { if($Left.extents[$i].$name -ne $Right.extents[$i].$name) { return $false } } }
    $true
}
function Assert-VdlObservationSource($Source) {
    if($Source.schemaVersion -ne 1 -or $Source.kind -cne 'native-vdl-probe' -or $Source.phase -cne 'AllocateZeroVdl' -or $Source.measurementId -cne '2780e16cd7bb4d12a5ba8070bac0a1e7' -or $Source.status -cne 'blocked' -or $Source.nativeSourceSha256 -cne '4cb89a793165cb2307d1dc2fd33135f4138dadad873869c98b0a5bf8af2bce0f' -or $Source.controlEvidenceSha256 -cne '0676470fce3a6ee3500835a02224117bc8106826d4d2f99ac395c3ca4b06bef9'){throw 'Unexpected preserved VDL source.'}
    foreach($name in @('controlQualified','originalFixturesUnchanged','targetWriteRequestsIssued')){if($Source.$name -isnot [bool] -or -not $Source.$name){throw 'Source creation/control evidence incomplete.'}}
    foreach($name in @('zeroVdlQualified','newFilePayloadReads','newFilePayloadWrites','moveAttempted','setValidDataAttempted','privilegeAdjustmentAttempted','physicalMappingVerified','payloadCopyAvoidanceVerified','conversionQualified')){if($Source.$name -isnot [bool] -or $Source.$name){throw 'Source operation/qualification differs.'}}
    $a=$Source.allocationObservation
    if($a.status -cne 'blocked' -or $a.phase -cne 'set-eof' -or $a.fixturePath -cne 'F:\fixtures\vdl-2780e16cd7bb4d12a5ba8070bac0a1e7\uninitialized.bin' -or $a.sha256Before -or $a.sha256After -or @($a.operations).Count -ne 2 -or @($a.snapshots).Count -ne 1){throw 'Unexpected preserved allocation result.'}
    foreach($name in @('directoryCreated','fileCreated','allocationRequested','eofRequested','privateAclVerified')){if($a.$name -isnot [bool] -or -not $a.$name){throw 'Source did not complete creation/allocation/EOF.'}}
    if($a.explicitFlushRequested -isnot [bool] -or $a.explicitFlushRequested){throw 'Source flush state differs.'}
    for($i=0;$i -lt 2;$i++){$op=$a.operations[$i];if($op.name -cne @('FileAllocationInfo','FileEndOfFileInfo')[$i] -or $op.inputHex -cne '0000010000000000' -or $op.succeeded -isnot [bool] -or -not $op.succeeded -or $op.nativeError -ne 0 -or -not $op.finishedUtc){throw 'Source native size request did not complete.'}}
    $s=$a.snapshots[0]
    if($s.name -cne 'immediate' -or $s.fileId64 -cne '0x3000000000002703' -or $s.volumeSerialHex -cne '0x08425382' -or $s.standard.allocationBytes -ne 65536 -or $s.standard.eofBytes -ne 65536 -or $s.cached.vdlBytes -ne 65536 -or $s.onDisk.vdlBytes -ne 0 -or $s.exactState -ne $false){throw 'Preserved native observation changed.'}
}
function Assert-VdlObservationHostOriginals([string]$Directory,$Control,$Placement,$ExpectedOriginal) {
    foreach($name in @('original-before.json','original-after.json')){
        $r=Get-Content -LiteralPath (Join-Path $Directory $name) -Raw|ConvertFrom-Json
        $original=Get-VdlObservationFixture $r $Control.target.guest
        if(@($r.files).Count -ne 2 -or -not (Test-VdlObservationSameMapping $ExpectedOriginal $original)){throw 'Original 4 MiB fixture changed.'}
        $known=@($r.files|Where-Object path -CEQ 'fixtures\placement-d98ba93b850d4eababa84c445439868a\initialized.bin')
        if($known.Count -ne 1 -or $known[0].stream -cne ':$DATA' -or -not (Test-VdlObservationSameMapping $Placement.after $known[0].observation)){throw 'Initialized 64 KiB fixture changed.'}
    }
}
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated Hyper-V access required.'}
$profile=Get-VdlObservationHostProfile
$manifest=Read-LabManifest -Configuration $configuration -Lane win11;Assert-VdlObservationHostManifest $manifest $profile
$vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
Assert-VdlObservationHostCheckpoint (Get-ExactLabCheckpoint -VM $vm -Name installed-clean) $profile -Baseline
Assert-VdlObservationHostVM $vm $profile.baselineId 4GB
Assert-VdlObservationHostCheckpoint (Get-ExactLabCheckpoint -VM $vm -Name $profile.checkpointName) $profile
$sourceRoot=Assert-LabPath (Join-Path $configuration.Root $profile.sourceDirectory) $configuration.Root
$sourceAllocationRoot=Assert-LabPath (Join-Path $sourceRoot 'allocation') $configuration.Root
$origin=Read-VdlObservationHostPinned (Join-Path $sourceRoot 'host-result.json') $profile.sourceHostSha256;Assert-VdlObservationHostOrigin $origin $profile
$source=Read-VdlObservationHostPinned (Join-Path $sourceAllocationRoot 'allocation.json') $profile.sourceEvidenceSha256;Assert-VdlObservationSource $source
Read-VdlObservationHostPinned (Assert-LabPath (Join-Path $sourceRoot 'control\control.json') $configuration.Root) $profile.sourceControlSha256|Out-Null
$sourceFiles=@(Read-VdlObservationHostPinned (Join-Path $sourceAllocationRoot 'exported-files.json') $profile.sourceExportSha256);Assert-VdlObservationHostSourceFiles $sourceFiles $sourceAllocationRoot
$controlRoot=Assert-LabPath (Join-Path $configuration.Root $profile.controlDirectory) $configuration.Root
$control=Read-VdlObservationHostPinned (Assert-LabPath (Join-Path $controlRoot 'after\verify.json') $configuration.Root) $profile.controlEvidenceSha256
$placementRoot=Assert-LabPath (Join-Path $configuration.Root $profile.placementDirectory) $configuration.Root
$placement=Read-VdlObservationHostPinned (Assert-LabPath (Join-Path $placementRoot 'guest\placement.json') $configuration.Root) $profile.placementEvidenceSha256
$expectedOriginal=Get-VdlObservationFixture (Get-Content -LiteralPath (Join-Path $sourceAllocationRoot 'original-before.json') -Raw|ConvertFrom-Json) $control.target.guest
$laneRoot=Assert-LabPath (Join-Path $configuration.Root 'win11') $configuration.Root
$credential=Import-Clixml -LiteralPath (Assert-LabPath (Join-Path $laneRoot 'secrets\guest-credential.xml') $configuration.Root)
if($credential -isnot [Management.Automation.PSCredential] -or $credential.UserName -cne 'N2R-WIN11\LabAdmin'){throw 'Unexpected guest credential.'}
Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 4GB
$observationId=[guid]::NewGuid().ToString('N')
$outputRoot=Assert-LabPath (Join-Path $configuration.Root ('vdl-observation\win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $configuration.Root
if(Test-Path -LiteralPath $outputRoot){throw 'Observation output already exists.'};New-Item -ItemType Directory -Path $outputRoot|Out-Null
$guestNames=@('GuestLab.psm1','Capture-GuestAllocation.ps1','NativeVdlObservation.cs','Capture-GuestVdlObservation.ps1')
$sourceHashes=@(foreach($name in $guestNames){$path=Join-Path $workspace ('lab\guest\'+$name);$f=Get-Item -LiteralPath $path -Force;if($f.PSIsContainer -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $f.Length -lt 1 -or $f.Length -gt 256KB){throw 'Unexpected helper source.'};[pscustomobject]@{name=$name;length=$f.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}})
$scriptSha=($sourceHashes|Where-Object name -CEQ 'Capture-GuestVdlObservation.ps1').sha256;$nativeSha=($sourceHashes|Where-Object name -CEQ 'NativeVdlObservation.cs').sha256
if(-not ('Ntfs2Refs.NativeVdlObservation' -as [type])){Add-Type -Path (Join-Path $workspace 'lab\guest\NativeVdlObservation.cs')} # Pure parsers only on the host.
$record=[ordered]@{schemaVersion=1;kind='native-vdl-post-remount-observation-host';observationId=$observationId;measurementId=$profile.measurementId;vmId=$profile.vmId;baselineId=$profile.baselineId;sourceCheckpointId=$profile.checkpointId;sourceCheckpointName=$profile.checkpointName;sourceEvidenceSha256=$profile.sourceEvidenceSha256;sourceHostSha256=$profile.sourceHostSha256;sourceExportSha256=$profile.sourceExportSha256;status='started';phase='preflight';evidenceExported=$false;nativeObservationComplete=$false;stableDuringObservation=$false;newFilePayloadReads=$false;newFilePayloadWrites=$false;targetWriteRequestsIssued=$false;allocationRequested=$false;explicitFlushRequested=$false;moveAttempted=$false;setValidDataAttempted=$false;protectionChanged=$false;privilegeAdjustmentAttempted=$false;physicalMappingVerified=$false;zeroVdlQualified=$false;payloadCopyAvoidanceVerified=$false;conversionQualified=$false;cleanShutdown=$false;baselineRestored=$false;memoryRestored=$false;sourceHashes=$sourceHashes;hostScriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();labModuleSha256=(Get-FileHash -LiteralPath (Join-Path $workspace 'lab\Lab.psm1') -Algorithm SHA256).Hash.ToLowerInvariant();createdUtc=[DateTime]::UtcNow.ToString('o')}
$session=$null;$script:commandIndeterminate=$false
try {
    Save-VdlObservationHostProgress
    $archive=Join-Path $outputRoot 'sources';New-Item -ItemType Directory -Path $archive|Out-Null
    foreach($f in $sourceHashes){$path=Join-Path $archive $f.name;Copy-Item -LiteralPath (Join-Path $workspace ('lab\guest\'+$f.name)) -Destination $path;if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $f.sha256){throw 'Source archive changed.'}}
    Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $archive 'Invoke-LabVdlObservation.ps1')
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest;Assert-VdlObservationHostVM $vm $profile.baselineId 4GB
    Assert-VdlObservationHostCheckpoint (Get-ExactLabCheckpoint -VM $vm -Name $profile.checkpointName) $profile
    $record.phase='restore-preserved-vdl-outcome';Save-VdlObservationHostProgress
    Invoke-LabAction -Action Restore -Lane win11 -CheckpointName $profile.checkpointName -Confirm:$false|Out-Null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest;Assert-VdlObservationHostVM $vm $profile.checkpointId 8GB
    Invoke-LabAction -Action Start -Lane win11 -Confirm:$false|Out-Null
    $session=Open-VdlObservationHostSession
    $policy=Initialize-LabGuestSession -Session $session;$policy|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $outputRoot 'session.json') -Encoding UTF8
    if($policy.status -cne 'ready'){throw ('Guest session refused: '+$policy.error)}
    Invoke-BoundedVdlObservationCommand -Arguments @(,$guestNames) -ScriptBlock {param($Names);foreach($p in @('C:\ntfs2refs','C:\ntfs2refs\guest')){$i=Get-Item -LiteralPath $p -Force;if(-not $i.PSIsContainer -or ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected guest source directory.'}};foreach($n in $Names){$p='C:\ntfs2refs\guest\'+$n;if(Test-Path -LiteralPath $p){$i=Get-Item -LiteralPath $p -Force;if($i.PSIsContainer -or ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected helper destination.'}}}}|Out-Null
    foreach($f in $sourceHashes){Copy-Item -LiteralPath (Join-Path $archive $f.name) -Destination ('C:\ntfs2refs\guest\'+$f.name) -ToSession $session -Force}
    $copied=@(Invoke-BoundedVdlObservationCommand -Arguments @(,$guestNames) -ScriptBlock {param($Names);foreach($n in $Names){$p='C:\ntfs2refs\guest\'+$n;$i=Get-Item -LiteralPath $p -Force;if($i.PSIsContainer -or ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected copied helper.'};[pscustomobject]@{name=$n;length=$i.Length;sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}}})
    if($copied.Count -ne $sourceHashes.Count){throw 'Incomplete copied helpers.'};foreach($f in $sourceHashes){$c=@($copied|Where-Object name -CEQ $f.name);if($c.Count -ne 1 -or $c[0].length -ne $f.length -or $c[0].sha256 -cne $f.sha256){throw 'Copied source hash differs.'}}
    $record.phase='observe-preserved-file-metadata';Save-VdlObservationHostProgress
    $answers=@(Invoke-BoundedVdlObservationCommand -TimeoutSeconds $QueryTimeoutSeconds -Arguments @($observationId) -ScriptBlock {param($Id);& 'C:\ntfs2refs\guest\Capture-GuestVdlObservation.ps1' -ObservationId $Id -Confirm:$false})
    if($answers.Count -ne 1){throw 'Ambiguous observation response.'};$response=$answers[0];Assert-VdlObservationHostResponse $response $observationId
    $record.phase='export-observation';$export=Export-VdlObservationHostArtifacts $response.EvidenceDirectory
    Assert-VdlObservationHostRecord $export.record $response $profile $control $export.files $scriptSha $nativeSha $export.directory
    $record.evidenceExported=$true;$record['guestStatus']=$response.Status;$record['guestEvidenceSha256']=($export.files|Where-Object name -CEQ 'observation.json').sha256;Save-VdlObservationHostProgress
    Assert-VdlObservationHostDisposition $export.record
    Assert-VdlObservationHostOriginals $export.directory $control $placement $expectedOriginal
    $record.nativeObservationComplete=$export.record.nativeObservation.observationComplete;$record.stableDuringObservation=$export.record.nativeObservation.stableDuringObservation
    $record.phase='clean-shutdown';Save-VdlObservationHostProgress;Stop-VdlObservationHostGuest;$record.cleanShutdown=$true
    Remove-PSSession -Session $session -ErrorAction SilentlyContinue;$session=$null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest;Assert-VdlObservationHostVM $vm $profile.checkpointId 8GB
    Assert-VdlObservationHostCheckpoint (Get-ExactLabCheckpoint -VM $vm -Name installed-clean) $profile -Baseline
    Assert-VdlObservationHostCheckpoint (Get-ExactLabCheckpoint -VM $vm -Name $profile.checkpointName) $profile
    $record.phase='restore-baseline';Save-VdlObservationHostProgress
    Invoke-LabAction -Action Restore -Lane win11 -CheckpointName installed-clean -Confirm:$false|Out-Null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    if($vm.State -ne 'Off' -or [string]$vm.ParentSnapshotId -ine $profile.baselineId){throw 'Baseline did not restore exact off-state branch.'}
    if($vm.MemoryStartup -ne 4GB -or $vm.DynamicMemoryEnabled){Set-VMMemory -VM $vm -StartupBytes 4GB -DynamicMemoryEnabled $false}
    Assert-VdlObservationHostVM (Get-OwnedLabVM -Configuration $configuration -Manifest $manifest) $profile.baselineId 4GB
    $record.baselineRestored=$true;$record.memoryRestored=$true;$record.status='native-vdl-observation-exported';$record.phase='complete'
}catch{$record.status='failed-preserved';$record['error']=$_.Exception.Message;$record['errorPosition']=$_.InvocationInfo.PositionMessage;$record['scriptStackTrace']=$_.ScriptStackTrace;throw}
finally{$record['commandCompletionUnknown']=$script:commandIndeterminate;$record['finishedUtc']=[DateTime]::UtcNow.ToString('o');Save-VdlObservationHostProgress;if($session -and -not $script:commandIndeterminate){Remove-PSSession -Session $session -ErrorAction SilentlyContinue};$credential=$null}
[pscustomobject]@{Status=$record.status;Evidence=$outputRoot;ObservationComplete=$record.nativeObservationComplete;StableDuringObservation=$record.stableDuringObservation;BaselineRestored=$record.baselineRestored;MemoryRestored=$record.memoryRestored;ConversionQualified=$false}
