<# Two bounded guest VDL stages on the exact saved placement branch. Host orchestration only. #>
[CmdletBinding(SupportsShouldProcess)]
param([ValidateRange(60,900)][int]$BootTimeoutSeconds=300,[ValidateRange(30,600)][int]$QueryTimeoutSeconds=180)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
$configuration=Get-LabConfiguration -WorkspaceRoot $workspace
if(-not $PSCmdlet.ShouldProcess('ntfs2refs-win11','Restore the exact saved placement checkpoint at 8 GiB, measure the initialized 64 KiB control, export proof, conditionally allocate one private 64 KiB zero-VDL file, export proof, preserve changed outcome, cleanly restore installed-clean at 4 GiB')) {
    [pscustomobject]@{Action='NativeVdlProbe';DryRun=$true;MemoryBytes=8GB;MaximumNewFileBytes=65536;NewFilePayloadReads=$false;NewFilePayloadWrites=$false;MoveAttempted=$false;SetValidDataAttempted=$false;PrivilegeAdjustmentAttempted=$false;ConversionQualified=$false};return
}
function Assert-VdlHostManifest($Manifest,$Profile) {
    if ([string]$Manifest.vmId -ine $Profile.vmId -or @($Manifest.disks).Count -ne 3) { throw 'Unexpected VDL probe VM or disk count.' }
    foreach($role in @('os','target','journal')) {
        $selected=@($Manifest.disks | Where-Object role -CEQ $role)
        $slot=if($role -ceq 'os'){0}elseif($role -ceq 'target'){1}else{2}
        $bytes=if($role -ceq 'journal'){8GB}else{64GB}
        if($selected.Count -ne 1 -or $selected[0].controllerLocation -ne $slot -or $selected[0].sizeBytes -ne $bytes) { throw 'Discovery requires the original three owned disks.' }
        if($role -ceq 'target' -and [string]$selected[0].vhdId -ine $Profile.targetVhdId) { throw 'Unexpected original target VHD identity.' }
    }
}

function Assert-VdlHostVM($VM,[string]$ExpectedParent,[long]$MemoryBytes) {
    if($VM.State -ne 'Off' -or $VM.MemoryStartup -ne $MemoryBytes -or $VM.DynamicMemoryEnabled -or [string]$VM.ParentSnapshotId -ine $ExpectedParent) { throw 'Discovery requires the exact powered-off checkpoint branch and fixed memory profile.' }
    if(@(Get-VMNetworkAdapter -VM $VM | Where-Object SwitchName).Count -or (Get-VMFirmware -VM $VM).SecureBoot -ne 'On') { throw 'Discovery requires disconnected networking and unchanged Secure Boot.' }
}

function Assert-VdlHostCheckpoint($Checkpoint,$Profile,[switch]$Baseline) {
    $id=if($Baseline){$Profile.baselineId}else{$Profile.checkpointId}
    $name=if($Baseline){'installed-clean'}else{$Profile.checkpointName}
    if([string]$Checkpoint.Id -ine $id -or $Checkpoint.Name -cne $name -or [string]$Checkpoint.VMId -ine $Profile.vmId) { throw 'Saved VDL probe checkpoint identity changed.' }
}

function Invoke-BoundedVdlCommand([scriptblock]$ScriptBlock,[object[]]$Arguments=@(),[int]$TimeoutSeconds=60) {
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

function Open-VdlHostSession {
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

function Stop-VdlHostGuest {
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    if($vm.State -eq 'Off'){return}
    if(-not $session -or $script:commandIndeterminate){throw 'An idle authenticated guest session is required for clean shutdown.'}
    Invoke-BoundedVdlCommand -TimeoutSeconds 30 -ScriptBlock { & shutdown.exe /s /t 0; if($LASTEXITCODE -ne 0){throw 'Guest shutdown request failed.'} } | Out-Null
    $deadline=[DateTime]::UtcNow.AddMinutes(3)
    do { if((Get-VM -Id ([guid]$manifest.vmId)).State -eq 'Off'){return}; Start-Sleep -Seconds 2 } while([DateTime]::UtcNow -lt $deadline)
    throw 'Guest did not shut down cleanly; preserve the branch.'
}

function Get-VdlHostProfile {
    [pscustomobject]@{vmId='eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c';baselineId='eda059b3-6d50-46bb-bdf4-018b99b5b34f';checkpointId='4b581541-4899-4f91-adc1-e4e784c7cacf';checkpointName='extent-placement-data-d98ba93b850d4eababa84c445439868a';placementDirectory='extent-placement\win11-20261024T000401422Z';placementProbeId='d98ba93b850d4eababa84c445439868a';placementEvidenceSha256='865e9a7517dd1e0bd925d7fad5af85146fa8ec4c447d5640958473c11cd30cc5';placementHostSha256='125f812543ef56ea5d81f641797b1ac2d8b52b1f16d8f17d1ac03a726684d982';remountIdentitySha256='fe287b5536c1de6c816d4d4ba43e7d5fe9026361a8b91687279c770b5efb4414';remountAllocationSha256='9d7b537e885cde3c7b67c1a830dd2dfff27ccf4232d445e46baa4a3499002cbe';controlDirectory='devdrive\win11-20261023T230635404Z';controlEvidenceSha256='ca9e3e60bbe84bd758609d92b92a305a948213b4ab0f5ce199f38567a8ea84c1';capturedAllocationSha256='f553fd91111dfb09a9aa14d27fe63daaba790c0efb14bd530ac5cd9ef0f55be2';targetVhdId='25c491d0-5f1b-4205-9e6f-fd619706c2b5';fixtureSha256='9b195d4598044587ab6e51b73d92063936710b9b1255158054918350d20f1d78';fixtureId='0x3000000000002702';volumeSerial='0x08425382';fixtureLcn=1508384}
}
function Get-VdlHostStage([string]$Phase) {
    if($Phase -ceq 'MeasureInitializedControl'){return 'control'}
    if($Phase -ceq 'AllocateZeroVdl'){return 'allocation'}
    throw 'Unreviewed VDL phase.'
}
function Assert-VdlHostBool($Object,[string]$Field,[bool]$Expected) {
    if($Object.$Field -isnot [bool] -or $Object.$Field -ne $Expected){throw "Unexpected VDL boolean: $Field."}
}
function Assert-VdlHostOrigin($Origin,$Profile) {
    if($Origin.schemaVersion -ne 1 -or $Origin.kind -cne 'native-extent-placement-host' -or $Origin.status -cne 'native-extent-placement-remount-verified' -or $Origin.probeId -cne $Profile.placementProbeId -or $Origin.vmId -ine $Profile.vmId -or $Origin.baselineId -ine $Profile.baselineId -or $Origin.outcomeCheckpointId -ine $Profile.checkpointId -or $Origin.outcomeCheckpointName -cne $Profile.checkpointName -or $Origin.guestEvidenceSha256 -cne $Profile.placementEvidenceSha256){throw 'Saved placement origin differs.'}
    foreach($field in @('evidenceExported','firstCleanShutdown','cleanRemountVerified','remountEvidenceExported','cleanShutdown','outcomeCheckpointCreated','baselineRestored','memoryRestored','moveCompleted')){Assert-VdlHostBool $Origin $field $true}
    foreach($field in @('physicalMappingVerified','payloadCopyAvoidanceVerified','conversionQualified','bootQualified')){Assert-VdlHostBool $Origin $field $false}
}
function Assert-VdlHostOutcome($Checkpoint,[string]$Name,$Profile) {
    $id=[guid]::Empty
    if(-not [guid]::TryParse([string]$Checkpoint.Id,[ref]$id) -or $id -eq [guid]::Empty -or [string]$id -iin @($Profile.baselineId,$Profile.checkpointId) -or $Checkpoint.Name -cne $Name -or [string]$Checkpoint.VMId -ine $Profile.vmId){throw 'Unexpected VDL outcome checkpoint.'}
}
function Assert-VdlHostResponse($Result,[string]$Id,[string]$Phase) {
    $stage=Get-VdlHostStage $Phase
    $statuses=@('blocked','original-fixture-check-failed','initialized-vdl-control-qualified','initialized-vdl-control-unresolved')
    if($stage -ceq 'allocation'){$statuses+=@('allocation-zero-vdl-observed','allocated-vdl-state-unresolved')}
    if($Result.MeasurementId -cne $Id -or $Result.Phase -cne $Phase -or $Result.Status -cnotin $statuses -or $Result.EvidenceDirectory -cne ('C:\ntfs2refs\vdl-probe\'+$Id+'\'+$stage)){throw 'Unexpected VDL stage response.'}
    foreach($field in @('ControlQualified','ZeroVdlQualified','TargetWriteRequestsIssued')){if($Result.$field -isnot [bool]){throw 'Indeterminate VDL stage response.'}}
    foreach($field in @('MoveAttempted','SetValidDataAttempted','ConversionQualified')){Assert-VdlHostBool $Result $field $false}
    if($stage -ceq 'control'){Assert-VdlHostBool $Result 'TargetWriteRequestsIssued' $false;Assert-VdlHostBool $Result 'ZeroVdlQualified' $false}
}
function Get-VdlHostQuerySpec([string]$Name,[string]$Phase) {
    Get-VdlHostStage $Phase|Out-Null
    if($Name -cmatch '\Acontrol-(before|after)(Standard|Cached|OnDisk|Extents)\z'){$kind=$Matches[2]}
    elseif($Phase -ceq 'AllocateZeroVdl' -and $Name -cmatch '\Aallocation-(?:(empty|allocated)(Standard)|(immediate|flushed|reopened)(Standard|Cached|OnDisk|Extents))\z'){$kind=if($Matches.ContainsKey(2)){$Matches[2]}else{$Matches[4]}}
    else{throw 'Unreviewed VDL native query name.'}
    if($kind -ceq 'Standard'){return [pscustomobject]@{capacity=24;code='0x00000000';api='GetFileInformationByHandleEx';informationClass=1;inputHex='';inputBytes=0}}
    if($kind -ceq 'Extents'){return [pscustomobject]@{capacity=272;code='0x00090073';api='DeviceIoControl';informationClass=0;inputHex='0000000000000000';inputBytes=8}}
    $usage=if($kind -ceq 'Cached'){'01000000'}else{'02000000'}
    [pscustomobject]@{capacity=400;code='0x00090284';api='DeviceIoControl';informationClass=0;inputHex=('00000000000000000000010000000000'+$usage+'00000000');inputBytes=24}
}
function Assert-VdlHostArtifact($File,[string]$Phase) {
    $stage=Get-VdlHostStage $Phase;$maximum=0
    if($File.name -cin @(($stage+'.json'),'original-before.json','original-after.json')){$maximum=1MB}
    elseif($stage -ceq 'allocation' -and $File.name -ceq 'started.json'){$maximum=1MB}
    elseif($File.name -cmatch '\A(.+)\.bin\z'){$maximum=(Get-VdlHostQuerySpec $Matches[1] $Phase).capacity}
    else{throw 'Unexpected VDL artifact name.'}
    if($File.length -lt 1 -or $File.length -gt $maximum -or $File.sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or ([IO.FileAttributes]$File.attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Directory))){throw 'Invalid or oversized VDL artifact.'}
}
function Assert-VdlHostArtifactSet([object[]]$Files,[string]$Phase) {
    $stage=Get-VdlHostStage $Phase;$maximum=if($stage -ceq 'control'){11}else{26}
    if($Files.Count -lt 1 -or $Files.Count -gt $maximum -or @($Files|Where-Object name -CEQ ($stage+'.json')).Count -ne 1 -or @($Files.name|Select-Object -Unique).Count -ne $Files.Count){throw 'Missing, duplicate or excessive VDL artifacts.'}
    foreach($file in $Files){Assert-VdlHostArtifact $file $Phase}
    if(($Files|Measure-Object length -Sum).Sum -gt (4MB+16KB)){throw 'VDL evidence exceeds the aggregate bound.'}
}
function Assert-VdlHostSnapshot($Snapshot,[long]$VdlBytes,$Profile,[switch]$Control) {
    Assert-VdlHostBool $Snapshot 'exactState' $true
    if($Snapshot.standard.allocationBytes -ne 65536 -or $Snapshot.standard.eofBytes -ne 65536 -or $Snapshot.standard.links -ne 1){throw 'VDL fixture size differs.'}
    foreach($name in @('directory','deletePending')){Assert-VdlHostBool $Snapshot.standard $name $false}
    foreach($name in @('cached','onDisk')){
        $region=$Snapshot.$name;$usage=if($name -ceq 'cached'){1}else{2}
        Assert-VdlHostBool $region 'complete' $true;Assert-VdlHostBool $region 'prefixQualified' $true
        if($region.vdlBytes -ne $VdlBytes -or $region.requestedUsage -ne $usage){throw 'VDL range qualification differs.'}
        $next=0L;$valid=0L;$invalidSeen=$false;$rows=@($region.regions)
        if($rows.Count -lt 1 -or $rows.Count -gt 16){throw 'Unbounded VDL regions.'}
        foreach($row in $rows){if($row.offset -ne $next -or $row.length -le 0 -or $row.length -gt (65536-$next) -or $row.usage -lt 0 -or ($row.usage -band (-bnot 31))){throw 'Malformed VDL region.'};if($row.usage -band $usage){if($invalidSeen){throw 'Non-prefix VDL region.'};$valid+=$row.length}else{$invalidSeen=$true};$next+=$row.length}
        if($next -ne 65536 -or $valid -ne $VdlBytes){throw 'VDL regions do not prove the requested bounded state.'}
    }
    if($Snapshot.fileId64 -cnotmatch '\A0x[0-9a-f]{16}\z' -or $Snapshot.volumeSerialHex -cne $Profile.volumeSerial){throw 'Unexpected VDL file identity.'}
    $next=0L;$extents=@($Snapshot.extents)
    if($extents.Count -lt 1 -or $extents.Count -gt 16){throw 'Unbounded VDL extent count.'}
    foreach($extent in $extents){if($extent.startingVcn -ne $next -or $extent.nextVcn -le $next -or $extent.nextVcn -gt 16 -or $extent.lcn -lt 0 -or $extent.lcn -gt (13631488-($extent.nextVcn-$next))){throw 'Invalid VDL extent bounds.'};$next=$extent.nextVcn}
    if($next -ne 16){throw 'Incomplete VDL extent coverage.'}
    if($Control -and ($Snapshot.fileId64 -cne $Profile.fixtureId -or $extents.Count -ne 1 -or $extents[0].lcn -ne $Profile.fixtureLcn)){throw 'Initialized fixture identity/mapping changed.'}
}
function Assert-VdlHostSameMapping($First,$Second) {
    if($First.fileId64 -cne $Second.fileId64 -or $First.volumeSerialHex -cne $Second.volumeSerialHex -or @($First.extents).Count -ne @($Second.extents).Count){throw 'VDL mapping identity changed.'}
    for($i=0;$i -lt @($First.extents).Count;$i++){foreach($field in @('startingVcn','nextVcn','lcn')){if($First.extents[$i].$field -ne $Second.extents[$i].$field){throw 'VDL extent mapping changed.'}}}
}
function Assert-VdlHostQualifiedControl($Record,$Profile,[object[]]$Files) {
    Assert-VdlHostBool $Record 'controlQualified' $true;Assert-VdlHostBool $Record 'originalFixturesUnchanged' $true
    $native=$Record.controlObservation
    if($native.status -cne 'initialized-vdl-control-qualified' -or $native.phase -cne 'complete' -or $native.error -or $native.fixturePath -cne ('F:\fixtures\placement-'+$Profile.placementProbeId+'\initialized.bin') -or $native.sha256Before -cne $Profile.fixtureSha256 -or $native.sha256After -cne $Profile.fixtureSha256 -or @($native.operations).Count){throw 'Initialized VDL control did not qualify.'}
    Assert-VdlHostBool $native 'controlQualified' $true
    foreach($field in @('targetWriteRequestsIssued','directoryCreated','fileCreated','allocationRequested','eofRequested','explicitFlushRequested','zeroVdlQualified')){Assert-VdlHostBool $native $field $false}
    $snapshots=@($native.snapshots)
    if($snapshots.Count -ne 2 -or $snapshots[0].name -cne 'before' -or $snapshots[1].name -cne 'after'){throw 'Missing initialized VDL snapshots.'}
    foreach($snapshot in $snapshots){Assert-VdlHostSnapshot $snapshot 65536 $Profile -Control}
    Assert-VdlHostSameMapping $snapshots[0] $snapshots[1]
    $queries=@($Record.nativeQueries|Where-Object{$_.name -clike 'control-*'})
    if($queries.Count -ne 8 -or @($queries|Where-Object{-not $_.succeeded -or -not $_.bufferPath}).Count){throw 'Initialized VDL queries did not all succeed.'}
    foreach($name in @('original-before.json','original-after.json')){if(@($Files|Where-Object name -CEQ $name).Count -ne 1){throw 'Missing original-fixture proof.'}}
}
function Assert-VdlHostQualifiedAllocation($Record,$Profile,[object[]]$Files) {
    if($Record.phase -cne 'AllocateZeroVdl' -or $Record.status -cne 'allocation-zero-vdl-observed'){throw 'Unexpected zero-VDL qualification.'}
    Assert-VdlHostQualifiedControl $Record $Profile $Files
    foreach($field in @('zeroVdlQualified','targetWriteRequestsMayHaveBeenIssued','targetWriteRequestsIssued')){Assert-VdlHostBool $Record $field $true}
    $native=$Record.allocationObservation
    if($native.phase -cne 'complete' -or $native.status -cne 'allocation-zero-vdl-observed' -or $native.error -or $native.sha256Before -or $native.sha256After -or $native.fixturePath -cne ('F:\fixtures\vdl-'+$Record.measurementId+'\uninitialized.bin')){throw 'Allocation-only VDL observation differs.'}
    foreach($field in @('zeroVdlQualified','targetWriteRequestsIssued','directoryCreated','fileCreated','allocationRequested','eofRequested','explicitFlushRequested','privateAclVerified')){Assert-VdlHostBool $native $field $true}
    $operations=@($native.operations);$names=@('FileAllocationInfo','FileEndOfFileInfo','FlushFileBuffers')
    if($operations.Count -ne 3){throw 'Missing bounded allocation operations.'}
    for($i=0;$i -lt 3;$i++){if($operations[$i].name -cne $names[$i] -or $operations[$i].nativeError -ne 0 -or $operations[$i].inputHex -cne $(if($i -lt 2){'0000010000000000'}else{''})){throw 'Unreviewed allocation operation.'};Assert-VdlHostBool $operations[$i] 'succeeded' $true}
    $snapshots=@($native.snapshots);$names=@('immediate','flushed','reopened')
    if($snapshots.Count -ne 3){throw 'Missing allocation-only VDL snapshots.'}
    for($i=0;$i -lt 3;$i++){if($snapshots[$i].name -cne $names[$i]){throw 'Allocation snapshot order differs.'};Assert-VdlHostSnapshot $snapshots[$i] 0 $Profile;Assert-VdlHostSameMapping $snapshots[0] $snapshots[$i]}
    $queries=@($Record.nativeQueries|Where-Object{$_.name -clike 'allocation-*'})
    if($queries.Count -ne 14 -or @($queries|Where-Object{-not $_.succeeded -or -not $_.bufferPath}).Count){throw 'Allocation-only queries did not all succeed.'}
}
function Assert-VdlHostRecord($Record,$Response,$Profile,$Control,[object[]]$Files,[string]$ScriptSha,[string]$NativeSha,[string]$ControlSha='') {
    Assert-VdlHostResponse $Response $Response.MeasurementId $Response.Phase
    Assert-VdlHostArtifactSet $Files $Response.Phase
    if($Record.schemaVersion -ne 1 -or $Record.kind -cne 'native-vdl-probe' -or $Record.phase -cne $Response.Phase -or $Record.measurementId -cne $Response.MeasurementId -or $Record.placementProbeId -cne $Profile.placementProbeId -or $Record.placementEvidenceSha256 -cne $Profile.placementEvidenceSha256 -or [string]$Record.controlEvidenceSha256 -cne $ControlSha -or $Record.status -cne $Response.Status -or $Record.scriptSha256 -cne $ScriptSha -or $Record.nativeSourceSha256 -cne $NativeSha -or [string]::IsNullOrWhiteSpace($Record.finishedUtc)){throw 'VDL stage provenance differs.'}
    foreach($field in @('newFilePayloadReads','newFilePayloadWrites','moveAttempted','setValidDataAttempted','privilegeAdjustmentAttempted','physicalMappingVerified','payloadCopyAvoidanceVerified','conversionQualified')){Assert-VdlHostBool $Record $field $false}
    foreach($field in @('controlQualified','zeroVdlQualified','targetWriteRequestsIssued')){if($Record.$field -isnot [bool] -or $Record.$field -ne $Response.$field){throw 'VDL response and evidence disagree.'}}
    foreach($field in @('originalFixturesUnchanged','targetWriteRequestsMayHaveBeenIssued')){if($Record.$field -isnot [bool]){throw 'Indeterminate VDL write or original-fixture observation.'}}
    foreach($field in @('role','uniqueId','sizeBytes','location')){if([string]$Record.target.$field -cne [string]$Control.target.guest.$field){throw 'VDL target enrollment changed.'}}
    foreach($field in @('guid','diskGuid','number','offset','length','letter','logicalSectorSize','physicalSectorSize')){if([string]$Record.partition.$field -cne [string]$Control.partition.$field){throw 'VDL GPT identity or geometry changed.'}}
    if($Record.volumeUniqueId -cne '\\?\Volume{00c9f113-e0b9-49d8-b031-130aef8ef3fb}\'){throw 'VDL volume GUID changed.'}
    $queries=@($Record.nativeQueries);$maximum=if($Record.phase -ceq 'MeasureInitializedControl'){8}else{22}
    if($queries.Count -gt $maximum -or @($queries|ForEach-Object{$_.name}|Select-Object -Unique).Count -ne $queries.Count){throw 'Unexpected VDL query count.'}
    $referenced=@()
    foreach($query in $queries){
        $spec=Get-VdlHostQuerySpec $query.name $Record.phase
        if($query.api -cne $spec.api -or $query.controlCode -cne $spec.code -or $query.informationClass -ne $spec.informationClass -or $query.inputHex -cne $spec.inputHex -or $query.inputBytes -ne $spec.inputBytes -or $query.outputCapacityBytes -ne $spec.capacity -or $query.bytesReturned -lt 0 -or $query.bytesReturned -gt $spec.capacity -or $query.succeeded -isnot [bool] -or [string]::IsNullOrWhiteSpace($query.startedUtc) -or [string]::IsNullOrWhiteSpace($query.finishedUtc)){throw 'Unreviewed or unfinished VDL query.'}
        if(($query.succeeded -and $query.nativeError -ne 0) -or (-not $query.succeeded -and $query.nativeError -eq 0)){throw 'Native VDL query result contradicts its error.'}
        if($query.bufferPath){$name=$query.name+'.bin';$match=@($Files|Where-Object name -CEQ $name);if($query.bufferPath -cne ($Response.EvidenceDirectory+'\'+$name) -or $match.Count -ne 1 -or $match[0].sha256 -cne $query.bufferSha256 -or $match[0].length -ne $query.bytesReturned){throw 'VDL buffer provenance differs.'};$referenced+=$name}
        elseif($query.bytesReturned -ne 0 -or $query.bufferSha256){throw 'Native VDL buffer is missing.'}
    }
    if(@($Files|Where-Object{$_.name -clike '*.bin' -and $_.name -cnotin $referenced}).Count){throw 'Unreferenced VDL native buffer.'}
    if($Record.phase -ceq 'MeasureInitializedControl'){
        Assert-VdlHostBool $Record 'targetWriteRequestsMayHaveBeenIssued' $false;Assert-VdlHostBool $Record 'targetWriteRequestsIssued' $false
        if($Record.PSObject.Properties.Name -ccontains 'allocationObservation'){throw 'Measurement contains an allocation observation.'}
    }
    if($Record.controlQualified){Assert-VdlHostQualifiedControl $Record $Profile $Files}
    if($Record.zeroVdlQualified){Assert-VdlHostQualifiedAllocation $Record $Profile $Files}
}
function Assert-VdlHostAllocationGate($Export,$Profile,[string]$ScriptSha,[string]$NativeSha) {
    $record=$Export.record
    if($record.phase -cne 'MeasureInitializedControl' -or $record.status -cne 'initialized-vdl-control-qualified' -or $record.scriptSha256 -cne $ScriptSha -or $record.nativeSourceSha256 -cne $NativeSha -or $record.placementEvidenceSha256 -cne $Profile.placementEvidenceSha256){throw 'Allocation lacks matching successful stage-one evidence.'}
    Assert-VdlHostBool $record 'targetWriteRequestsMayHaveBeenIssued' $false;Assert-VdlHostBool $record 'targetWriteRequestsIssued' $false;Assert-VdlHostBool $record 'zeroVdlQualified' $false
    Assert-VdlHostQualifiedControl $record $Profile $Export.files
    $proof=@($Export.files|Where-Object name -CEQ 'control.json')
    if($proof.Count -ne 1 -or $proof[0].sha256 -cnotmatch '\A[0-9a-f]{64}\z'){throw 'No hash-bound stage-one proof.'}
    $proof[0].sha256
}
function Get-VdlHostDisposition($Record) {
    # Only returned native calls plus exported, validated evidence can reach cleanup.
    Assert-VdlHostBool $Record 'originalFixturesUnchanged' $true
    if($Record.phase -ceq 'MeasureInitializedControl'){Assert-VdlHostBool $Record 'targetWriteRequestsMayHaveBeenIssued' $false;Assert-VdlHostBool $Record 'targetWriteRequestsIssued' $false;return [pscustomobject]@{checkpointRequired=$false;fileCreated=$false;directoryCreated=$false}}
    if($Record.phase -cne 'AllocateZeroVdl'){throw 'Unknown VDL disposition phase.'}
    if(-not $Record.targetWriteRequestsMayHaveBeenIssued){Assert-VdlHostBool $Record 'targetWriteRequestsIssued' $false;if($Record.PSObject.Properties.Name -ccontains 'allocationObservation'){throw 'Unexpected allocation observation without dispatch intent.'};return [pscustomobject]@{checkpointRequired=$false;fileCreated=$false;directoryCreated=$false}}
    if($Record.PSObject.Properties.Name -cnotcontains 'allocationObservation'){throw 'Allocation completion unknown; preserve the branch.'}
    $native=$Record.allocationObservation
    foreach($field in @('targetWriteRequestsIssued','fileCreated','directoryCreated','allocationRequested','eofRequested','explicitFlushRequested')){if($native.$field -isnot [bool]){throw 'Native allocation outcome is unknown.'}}
    if($native.targetWriteRequestsIssued -ne $Record.targetWriteRequestsIssued -or ($native.fileCreated -and -not $native.directoryCreated) -or ($native.directoryCreated -and -not $native.targetWriteRequestsIssued)){throw 'Contradictory native allocation outcome.'}
    if($native.fixturePath -cne ('F:\fixtures\vdl-'+$Record.measurementId+'\uninitialized.bin') -or $native.sha256Before -or $native.sha256After){throw 'Unexpected allocation fixture or payload access.'}
    $operations=@($native.operations)
    if($operations.Count -gt 3){throw 'Unbounded allocation operations.'}
    for($i=0;$i -lt $operations.Count;$i++){$op=$operations[$i];$expected=@('FileAllocationInfo','FileEndOfFileInfo','FlushFileBuffers')[$i];if($op.name -cne $expected -or $op.succeeded -isnot [bool] -or [string]::IsNullOrWhiteSpace($op.finishedUtc) -or $op.inputHex -cne $(if($i -lt 2){'0000010000000000'}else{''})){throw 'Unfinished or unreviewed allocation operation.'}}
    [pscustomobject]@{checkpointRequired=[bool]$native.targetWriteRequestsIssued;fileCreated=$native.fileCreated;directoryCreated=$native.directoryCreated}
}
function Export-VdlHostArtifacts([string]$GuestRoot,[string]$Phase) {
    $stage=Get-VdlHostStage $Phase
    $files=@(Invoke-BoundedVdlCommand -Arguments @($GuestRoot,$measurementId,$stage) -ScriptBlock {
        param($Root,$Id,$Stage)
        foreach($parent in @('C:\ntfs2refs','C:\ntfs2refs\vdl-probe',('C:\ntfs2refs\vdl-probe\'+$Id),$Root)){$item=Get-Item -LiteralPath $parent -Force;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected VDL evidence root.'}}
        $items=@(Get-ChildItem -LiteralPath $Root -Force)
        if($items.Count -gt 26){throw 'Excessive guest VDL evidence files.'}
        foreach($file in $items){
            $json=$file.Name -cin @(($Stage+'.json'),'original-before.json','original-after.json') -or ($Stage -ceq 'allocation' -and $file.Name -ceq 'started.json')
            $binary=$file.Name -cmatch '\Acontrol-(before|after)(Standard|Cached|OnDisk|Extents)\.bin\z' -or ($Stage -ceq 'allocation' -and $file.Name -cmatch '\Aallocation-(?:(empty|allocated)Standard|(immediate|flushed|reopened)(Standard|Cached|OnDisk|Extents))\.bin\z')
            if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -lt 1 -or $file.Length -gt 1MB -or (-not $json -and -not $binary)){throw 'Unexpected VDL evidence file.'}
            [pscustomobject]@{name=$file.Name;length=$file.Length;attributes=[string]$file.Attributes;sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
        }
    })
    Assert-VdlHostArtifactSet $files $Phase
    $destination=Assert-LabPath (Join-Path $outputRoot $stage) $configuration.Root
    if(Test-Path -LiteralPath $destination){throw 'VDL export destination already exists.'}
    New-Item -ItemType Directory -Path $destination|Out-Null
    foreach($file in $files){
        $path=Assert-LabPath (Join-Path $destination $file.name) $configuration.Root
        if(Test-Path -LiteralPath $path){throw 'VDL export cannot overwrite files.'}
        Copy-Item -LiteralPath ($GuestRoot+'\'+$file.name) -Destination $path -FromSession $session
        $local=Get-Item -LiteralPath $path -Force
        if($local.PSIsContainer -or ($local.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $local.Length -ne $file.length -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $file.sha256){throw 'VDL export failed length/hash verification.'}
    }
    $files|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $destination 'exported-files.json') -Encoding UTF8
    [pscustomobject]@{files=$files;record=(Get-Content -LiteralPath (Join-Path $destination ($stage+'.json')) -Raw|ConvertFrom-Json)}
}
function Read-VdlHostPinned([string]$Path,[string]$Sha) {
    $file=Get-Item -LiteralPath $Path -Force
    if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -lt 1 -or $file.Length -gt 1MB -or (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Sha){throw 'Pinned VDL source evidence changed.'}
    Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json
}
function Save-VdlHostProgress {
    $record|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $outputRoot 'host-result.json') -Encoding UTF8
}

if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated Hyper-V access is required.'}
$profile=Get-VdlHostProfile
$manifest=Read-LabManifest -Configuration $configuration -Lane win11
Assert-VdlHostManifest $manifest $profile
$vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
Assert-VdlHostCheckpoint (Get-ExactLabCheckpoint -VM $vm -Name installed-clean) $profile -Baseline
Assert-VdlHostVM $vm $profile.baselineId 4GB
Assert-VdlHostCheckpoint (Get-ExactLabCheckpoint -VM $vm -Name $profile.checkpointName) $profile
$placementRoot=Assert-LabPath (Join-Path $configuration.Root $profile.placementDirectory) $configuration.Root
$origin=Read-VdlHostPinned (Join-Path $placementRoot 'host-result.json') $profile.placementHostSha256
Assert-VdlHostOrigin $origin $profile
Read-VdlHostPinned (Join-Path $placementRoot 'guest\placement.json') $profile.placementEvidenceSha256|Out-Null
Read-VdlHostPinned (Join-Path $placementRoot 'remount\identity.json') $profile.remountIdentitySha256|Out-Null
Read-VdlHostPinned (Join-Path $placementRoot 'remount\allocation-remount.json') $profile.remountAllocationSha256|Out-Null
$controlRoot=Assert-LabPath (Join-Path $configuration.Root $profile.controlDirectory) $configuration.Root
$control=Read-VdlHostPinned (Join-Path $controlRoot 'after\verify.json') $profile.controlEvidenceSha256
Read-VdlHostPinned (Join-Path $controlRoot 'after\allocation-after.json') $profile.capturedAllocationSha256|Out-Null
$laneRoot=Assert-LabPath (Join-Path $configuration.Root 'win11') $configuration.Root
$credential=Import-Clixml -LiteralPath (Join-Path $laneRoot 'secrets\guest-credential.xml')
if($credential -isnot [Management.Automation.PSCredential] -or $credential.UserName -cne 'N2R-WIN11\LabAdmin'){throw 'Unexpected guest credential identity.'}
Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 4GB
$measurementId=[guid]::NewGuid().ToString('N')
$outputRoot=Assert-LabPath (Join-Path $configuration.Root ('vdl-probe\win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $configuration.Root
if(Test-Path -LiteralPath $outputRoot){throw 'VDL output root already exists.'}
New-Item -ItemType Directory -Path $outputRoot|Out-Null
$guestNames=@('GuestLab.psm1','Capture-GuestAllocation.ps1','NativeVdlProbe.cs','Invoke-GuestVdlProbe.ps1')
$sourceHashes=@(foreach($name in $guestNames){$path=Join-Path $workspace ('lab\guest\'+$name);$file=Get-Item -LiteralPath $path -Force;if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -lt 1 -or $file.Length -gt 256KB){throw 'Unexpected VDL helper source.'};[pscustomobject]@{name=$name;length=$file.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}})
$scriptSha=($sourceHashes|Where-Object name -CEQ 'Invoke-GuestVdlProbe.ps1').sha256
$nativeSha=($sourceHashes|Where-Object name -CEQ 'NativeVdlProbe.cs').sha256
$record=[ordered]@{schemaVersion=1;kind='native-vdl-probe-host';measurementId=$measurementId;vmId=$profile.vmId;baselineId=$profile.baselineId;sourceCheckpointId=$profile.checkpointId;sourceCheckpointName=$profile.checkpointName;placementProbeId=$profile.placementProbeId;placementEvidenceSha256=$profile.placementEvidenceSha256;status='started';phase='preflight';controlEvidenceExported=$false;allocationEvidenceExported=$false;allocationDispatched=$false;controlQualified=$false;zeroVdlQualified=$false;targetWriteRequestsMayHaveBeenIssued=$false;targetWriteRequestsIssued=$false;fileCreated=$false;directoryCreated=$false;newFilePayloadReads=$false;newFilePayloadWrites=$false;moveAttempted=$false;setValidDataAttempted=$false;privilegeAdjustmentAttempted=$false;physicalMappingVerified=$false;payloadCopyAvoidanceVerified=$false;conversionQualified=$false;bootQualified=$false;cleanShutdown=$false;outcomeCheckpointCreated=$false;outcomeCheckpointId=$null;outcomeCheckpointName=$null;baselineRestored=$false;memoryRestored=$false;sourceHashes=$sourceHashes;hostScriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();labModuleSha256=(Get-FileHash -LiteralPath (Join-Path $workspace 'lab\Lab.psm1') -Algorithm SHA256).Hash.ToLowerInvariant();createdUtc=[DateTime]::UtcNow.ToString('o')}
$session=$null;$script:commandIndeterminate=$false
try {
    Save-VdlHostProgress
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-VdlHostVM $vm $profile.baselineId 4GB
    Assert-VdlHostCheckpoint (Get-ExactLabCheckpoint -VM $vm -Name $profile.checkpointName) $profile
    $record.phase='restore-placement-control'
    Invoke-LabAction -Action Restore -Lane win11 -CheckpointName $profile.checkpointName -Confirm:$false|Out-Null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-VdlHostVM $vm $profile.checkpointId 8GB
    Invoke-LabAction -Action Start -Lane win11 -Confirm:$false|Out-Null
    $session=Open-VdlHostSession
    $policy=Initialize-LabGuestSession -Session $session
    $policy|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $outputRoot 'session.json') -Encoding UTF8
    if($policy.status -cne 'ready'){throw ('Guest session refused: '+$policy.error)}
    Invoke-BoundedVdlCommand -Arguments @(,$guestNames) -ScriptBlock {
        param($Names)
        foreach($path in @('C:\ntfs2refs','C:\ntfs2refs\guest')){$item=Get-Item -LiteralPath $path -Force;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected guest script directory.'}}
        foreach($name in $Names){$path='C:\ntfs2refs\guest\'+$name;if(Test-Path -LiteralPath $path){$item=Get-Item -LiteralPath $path -Force;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected guest helper destination.'}}}
    }|Out-Null
    foreach($file in $sourceHashes){Copy-Item -LiteralPath (Join-Path $workspace ('lab\guest\'+$file.name)) -Destination ('C:\ntfs2refs\guest\'+$file.name) -ToSession $session -Force}
    $copied=@(Invoke-BoundedVdlCommand -Arguments @(,$guestNames) -ScriptBlock {param($Names);foreach($name in $Names){$path='C:\ntfs2refs\guest\'+$name;$file=Get-Item -LiteralPath $path -Force;if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected copied helper.'};[pscustomobject]@{name=$name;length=$file.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}}})
    if($copied.Count -ne $sourceHashes.Count){throw 'Incomplete VDL helper copy.'}
    foreach($file in $sourceHashes){$copy=@($copied|Where-Object name -CEQ $file.name);if($copy.Count -ne 1 -or $copy[0].length -ne $file.length -or $copy[0].sha256 -cne $file.sha256){throw 'Guest helper hash differs.'}}
    $record.phase='measure-initialized-control';Save-VdlHostProgress
    $responses=@(Invoke-BoundedVdlCommand -TimeoutSeconds $QueryTimeoutSeconds -Arguments @($profile.placementProbeId,$profile.placementEvidenceSha256,$measurementId) -ScriptBlock {param($PlacementId,$PlacementSha,$Id);& 'C:\ntfs2refs\guest\Invoke-GuestVdlProbe.ps1' -Phase MeasureInitializedControl -PlacementProbeId $PlacementId -PlacementEvidenceSha256 $PlacementSha -MeasurementId $Id -Confirm:$false})
    if($responses.Count -ne 1){throw 'Ambiguous VDL control response.'}
    $response=$responses[0];Assert-VdlHostResponse $response $measurementId 'MeasureInitializedControl'
    $record.phase='export-control'
    $controlExport=Export-VdlHostArtifacts $response.EvidenceDirectory 'MeasureInitializedControl'
    Assert-VdlHostRecord $controlExport.record $response $profile $control $controlExport.files $scriptSha $nativeSha
    $record.controlEvidenceExported=$true;$record.controlQualified=$controlExport.record.controlQualified;$record['controlStatus']=$response.Status
    $record['controlEvidenceSha256']=($controlExport.files|Where-Object name -CEQ 'control.json').sha256
    $lastRecord=$controlExport.record
    Save-VdlHostProgress
    if($record.controlQualified){
        $controlSha=Assert-VdlHostAllocationGate $controlExport $profile $scriptSha $nativeSha
        Get-OwnedLabVM -Configuration $configuration -Manifest $manifest|Out-Null
        $record.phase='allocate-zero-vdl';$record.allocationDispatched=$true;$record.targetWriteRequestsMayHaveBeenIssued=$true;$record.targetWriteRequestsIssued=$null;$record.fileCreated=$null;$record.directoryCreated=$null
        Save-VdlHostProgress # Durable intent precedes the separate allocation dispatch.
        $responses=@(Invoke-BoundedVdlCommand -TimeoutSeconds $QueryTimeoutSeconds -Arguments @($profile.placementProbeId,$profile.placementEvidenceSha256,$measurementId,$controlSha) -ScriptBlock {param($PlacementId,$PlacementSha,$Id,$ControlSha);& 'C:\ntfs2refs\guest\Invoke-GuestVdlProbe.ps1' -Phase AllocateZeroVdl -PlacementProbeId $PlacementId -PlacementEvidenceSha256 $PlacementSha -MeasurementId $Id -ControlEvidenceSha256 $ControlSha -Confirm:$false})
        if($responses.Count -ne 1){throw 'Ambiguous VDL allocation response.'}
        $response=$responses[0];Assert-VdlHostResponse $response $measurementId 'AllocateZeroVdl'
        $record.phase='export-allocation'
        $allocationExport=Export-VdlHostArtifacts $response.EvidenceDirectory 'AllocateZeroVdl'
        Assert-VdlHostRecord $allocationExport.record $response $profile $control $allocationExport.files $scriptSha $nativeSha $controlSha
        $record.allocationEvidenceExported=$true;$record.zeroVdlQualified=$allocationExport.record.zeroVdlQualified;$record['allocationStatus']=$response.Status
        $record['allocationEvidenceSha256']=($allocationExport.files|Where-Object name -CEQ 'allocation.json').sha256
        $lastRecord=$allocationExport.record
        Save-VdlHostProgress
    }
    $disposition=Get-VdlHostDisposition $lastRecord
    $record.targetWriteRequestsIssued=$lastRecord.targetWriteRequestsIssued;$record.fileCreated=$disposition.fileCreated;$record.directoryCreated=$disposition.directoryCreated
    $record.phase='clean-shutdown';Save-VdlHostProgress
    Stop-VdlHostGuest
    $record.cleanShutdown=$true
    Remove-PSSession -Session $session -ErrorAction SilentlyContinue;$session=$null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-VdlHostVM $vm $profile.checkpointId 8GB
    if($disposition.checkpointRequired){
        Assert-LabCapacity (Get-LabCapacity $configuration)
        $record.phase='preserve-off-state-outcome';Save-VdlHostProgress
        $outcomeName='vdl-probe-data-'+$measurementId
        Invoke-LabAction -Action Checkpoint -Lane win11 -CheckpointName $outcomeName -Confirm:$false|Out-Null
        $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
        $outcome=Get-ExactLabCheckpoint -VM $vm -Name $outcomeName
        Assert-VdlHostOutcome $outcome $outcomeName $profile
        Assert-VdlHostVM $vm ([string]$outcome.Id) 8GB
        $record.outcomeCheckpointCreated=$true;$record.outcomeCheckpointId=[string]$outcome.Id;$record.outcomeCheckpointName=$outcome.Name
        Save-VdlHostProgress
    }
    Assert-VdlHostCheckpoint (Get-ExactLabCheckpoint -VM $vm -Name installed-clean) $profile -Baseline
    $record.phase='restore-baseline'
    Invoke-LabAction -Action Restore -Lane win11 -CheckpointName installed-clean -Confirm:$false|Out-Null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    if($vm.State -ne 'Off' -or [string]$vm.ParentSnapshotId -ine $profile.baselineId){throw 'Baseline restore did not return the exact off-state branch.'}
    if($vm.MemoryStartup -ne 4GB -or $vm.DynamicMemoryEnabled){Set-VMMemory -VM $vm -StartupBytes 4GB -DynamicMemoryEnabled $false}
    Assert-VdlHostVM (Get-OwnedLabVM -Configuration $configuration -Manifest $manifest) $profile.baselineId 4GB
    $record.baselineRestored=$true;$record.memoryRestored=$true;$record.status=if($record.zeroVdlQualified){'native-vdl-zero-observed'}else{'native-vdl-unresolved-exported'};$record.phase='complete'
} catch {
    $record.status='failed-preserved';$record['error']=$_.Exception.Message;$record['errorPosition']=$_.InvocationInfo.PositionMessage;$record['scriptStackTrace']=$_.ScriptStackTrace
    # Never shutdown, restore, checkpoint, stop jobs or change memory in failure handling.
    throw
} finally {
    $record['commandCompletionUnknown']=$script:commandIndeterminate;$record['finishedUtc']=[DateTime]::UtcNow.ToString('o');Save-VdlHostProgress
    if($session -and -not $script:commandIndeterminate){Remove-PSSession -Session $session -ErrorAction SilentlyContinue}
    $credential=$null
}
[pscustomobject]@{Status=$record.status;Evidence=$outputRoot;ControlQualified=$record.controlQualified;ZeroVdlQualified=$record.zeroVdlQualified;AllocationDispatched=$record.allocationDispatched;TargetWriteRequestsIssued=$record.targetWriteRequestsIssued;OutcomeCheckpointId=$record.outcomeCheckpointId;BaselineRestored=$record.baselineRestored;MemoryRestored=$record.memoryRestored;ConversionQualified=$false}
