<# One initialized file and one native move on the exact saved Dev Drive branch.
   Host Hyper-V operations are lab orchestration, never converter dependencies. #>
[CmdletBinding(SupportsShouldProcess)]
param([ValidateRange(60,900)][int]$BootTimeoutSeconds=300,[ValidateRange(30,600)][int]$ProbeTimeoutSeconds=180)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
$configuration=Get-LabConfiguration -WorkspaceRoot $workspace
if (-not $PSCmdlet.ShouldProcess('ntfs2refs-win11','Restore the exact saved Dev Drive checkpoint, create one 64 KiB fixture and request one native move, export evidence, verify a clean remount, preserve an off-state outcome checkpoint and restore installed-clean with 4 GiB RAM')) {
    [pscustomobject]@{Action='NativeExtentPlacement';DryRun=$true;MemoryBytes=8GB;MaximumFixtureBytes=65536;MaximumMoveCalls=1;TargetWriteRequestsIssued=$false;MoveAttempted=$false;RawDiskWrites=$false;ConversionQualified=$false}; return
}

function Get-ExtentPlacementProfile {
    [pscustomobject]@{vmId='eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c';baselineId='eda059b3-6d50-46bb-bdf4-018b99b5b34f';checkpointId='2aa127e2-c875-4ca0-8629-dab784136448';checkpointName='devdrive-data-20261023T230635404Z';controlDirectory='devdrive\win11-20261023T230635404Z';controlRunId='65f270323c26427e8316c7a8b75959cc';controlEvidenceSha256='ca9e3e60bbe84bd758609d92b92a305a948213b4ab0f5ce199f38567a8ea84c1';capturedAllocationSha256='f553fd91111dfb09a9aa14d27fe63daaba790c0efb14bd530ac5cd9ef0f55be2';targetVhdId='25c491d0-5f1b-4205-9e6f-fd619706c2b5'}
}
function Assert-ExtentPlacementManifest($Manifest,$Profile) {
    if ([string]$Manifest.vmId -ine $Profile.vmId -or @($Manifest.disks).Count -ne 3) { throw 'Unexpected placement VM or disk count.' }
    foreach($role in @('os','target','journal')) {
        $selected=@($Manifest.disks | Where-Object role -CEQ $role)
        $slot=if($role -ceq 'os'){0}elseif($role -ceq 'target'){1}else{2}
        $bytes=if($role -ceq 'journal'){8GB}else{64GB}
        if($selected.Count -ne 1 -or $selected[0].controllerLocation -ne $slot -or $selected[0].sizeBytes -ne $bytes) { throw 'Placement requires the original three owned disks.' }
        if($role -ceq 'target' -and [string]$selected[0].vhdId -ine $Profile.targetVhdId) { throw 'Unexpected original target VHD identity.' }
    }
}
function Assert-ExtentPlacementVM($VM,[string]$ExpectedParent,[long]$MemoryBytes) {
    if($VM.State -ne 'Off' -or $VM.MemoryStartup -ne $MemoryBytes -or $VM.DynamicMemoryEnabled -or [string]$VM.ParentSnapshotId -ine $ExpectedParent) { throw 'Placement requires the exact powered-off checkpoint branch and fixed memory profile.' }
    if(@(Get-VMNetworkAdapter -VM $VM | Where-Object SwitchName).Count -or (Get-VMFirmware -VM $VM).SecureBoot -ne 'On') { throw 'Placement requires disconnected networking and unchanged Secure Boot.' }
}
function Assert-ExtentPlacementCheckpoint($Checkpoint,$Profile,[switch]$Baseline) {
    $id=if($Baseline){$Profile.baselineId}else{$Profile.checkpointId}
    $name=if($Baseline){'installed-clean'}else{$Profile.checkpointName}
    if([string]$Checkpoint.Id -ine $id -or $Checkpoint.Name -cne $name -or [string]$Checkpoint.VMId -ine $Profile.vmId) { throw 'Saved placement checkpoint identity changed.' }
}
function Assert-ExtentPlacementResponse($Result,[string]$ExpectedId) {
    if($Result.ProbeId -cne $ExpectedId -or $Result.Status -cnotin @('blocked','integrity-check-failed','native-move-rejected','native-move-returned-unexpected-mapping','native-placement-observed-awaiting-remount') -or $Result.EvidenceDirectory -cne ('C:\ntfs2refs\extent-placement\'+$ExpectedId) -or $Result.FixturePath -cne ('F:\fixtures\placement-'+$ExpectedId+'\initialized.bin')) { throw 'Unexpected guest placement response.' }
    foreach($field in @('TargetWriteRequestsIssued','MoveAttempted','MoveCompleted')) { if($Result.$field -isnot [bool]) { throw 'Placement response lacks explicit operation state.' } }
    if(($Result.MoveCompleted -and -not $Result.MoveAttempted) -or ($Result.MoveAttempted -and -not $Result.TargetWriteRequestsIssued)) { throw 'Inconsistent placement operation state.' }
    foreach($field in @('CleanRemountVerified','PhysicalMappingVerified','ConversionQualified')) { if($Result.$field -isnot [bool] -or $Result.$field -ne $false) { throw 'Placement response claims an unperformed qualification.' } }
}
function Assert-ExtentPlacementArtifact($File) {
    $maximum=0
    if($File.name -cin @('started.json','placement.json','allocation-before.json','allocation-after.json')) { $maximum=1MB }
    elseif($File.name -ceq 'expected-pattern.bin') { $maximum=65536; if($File.length -ne $maximum){throw 'Pattern length differs.'} }
    elseif($File.name -cin @('originalBeforeExtents.bin','originalAfterExtents.bin')) { $maximum=16400 }
    elseif($File.name -cin @('beforeExtents.bin','afterExtents.bin')) { $maximum=272 }
    elseif($File.name -cin @('candidateBitmap.bin','candidateMetadataBitmap.bin')) { $maximum=2MB }
    else { throw 'Unexpected placement artifact name.' }
    if($File.length -lt 1 -or $File.length -gt $maximum -or $File.sha256 -cnotmatch '^[0-9a-f]{64}$' -or ([IO.FileAttributes]$File.attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid or oversized placement artifact.' }
}
function Assert-ExtentPlacementArtifactSet([object[]]$Files) {
    if($Files.Count -lt 1 -or $Files.Count -gt 11 -or @($Files | Where-Object name -CEQ 'placement.json').Count -ne 1 -or @($Files.name | Select-Object -Unique).Count -ne $Files.Count) { throw 'Missing, duplicate or excessive placement artifacts.' }
    foreach($file in $Files) { Assert-ExtentPlacementArtifact $file }
    if(($Files | Measure-Object length -Sum).Sum -gt 10MB) { throw 'Placement evidence exceeds the aggregate bound.' }
}
function Assert-ExtentPlacementRecord($Record,$Response,$Profile,$Control,[object[]]$Files,[string]$ScriptSha256,[string]$NativeSha256) {
    if($Record.schemaVersion -ne 1 -or $Record.kind -cne 'native-initialized-file-placement' -or $Record.phase -cne 'InitializedFilePlacement' -or $Record.probeId -cne $Response.ProbeId -or $Record.status -cne $Response.Status -or $Record.controlRunId -cne $Profile.controlRunId -or $Record.controlEvidenceSha256 -cne $Profile.controlEvidenceSha256 -or $Record.capturedAllocationSha256 -cne $Profile.capturedAllocationSha256 -or $Record.scriptSha256 -cne $ScriptSha256 -or $Record.nativeSourceSha256 -cne $NativeSha256 -or $Record.fixturePath -cne $Response.FixturePath) { throw 'Exported placement provenance differs from the dispatched experiment.' }
    foreach($field in @('cleanRemountVerified','physicalMappingVerified','payloadCopyAvoidanceVerified','conversionQualified','bootQualified','privilegeAdjustmentAttempted','rawDiskWrites','bitmapCandidateIsReservation','rawMetadataAddressEquivalenceVerified')) { if($Record.$field -isnot [bool] -or $Record.$field -ne $false) { throw 'Placement record claims an unperformed qualification.' } }
    foreach($field in @('targetWriteRequestsIssued','moveAttempted','moveCompleted')) { if($Record.$field -isnot [bool] -or $Record.$field -ne $Response.$field) { throw 'Placement operation flags disagree.' } }
    if($Record.maximumFixtureBytes -ne 65536 -or $Record.maximumMoveCalls -ne 1 -or $Record.requestedVcn -ne 0 -or $Record.requestedClusters -ne 16 -or $Record.moveCallCount -ne [int]$Record.moveAttempted) { throw 'Placement operation exceeds its reviewed bounds.' }
    foreach($field in @('role','uniqueId','sizeBytes','location')) { if([string]$Record.target.$field -cne [string]$Control.target.guest.$field) { throw 'Placement target enrollment changed.' } }
    foreach($field in @('guid','diskGuid','number','offset','length','letter','logicalSectorSize','physicalSectorSize')) { if([string]$Record.partition.$field -cne [string]$Control.partition.$field) { throw 'Placement GPT identity or geometry changed.' } }
    if(@($Record.nativeQueries).Count -gt 7 -or @($Record.nativeQueries | ForEach-Object {$_.name} | Select-Object -Unique).Count -ne @($Record.nativeQueries).Count) { throw 'Unexpected native query count.' }
    $referenced=@()
    foreach($query in $Record.nativeQueries) {
        if($query.name -cnotin @('originalBeforeExtents','originalAfterExtents','beforeExtents','afterExtents','candidateBitmap','candidateMetadataBitmap','move')) { throw 'Unreviewed native query in evidence.' }
        $expectedCode=if($query.name -ceq 'move'){'0x00090074'}elseif($query.name -clike '*Extents'){'0x00090073'}else{'0x0009006f'}
        $expectedInput=if($query.name -ceq 'move'){32}elseif($query.name -ceq 'candidateMetadataBitmap'){16}else{8}
        $capacity=if($query.name -ceq 'move'){0}elseif($query.name -clike 'original*'){16400}elseif($query.name -clike '*Extents'){272}else{2MB}
        if($query.controlCode -cne $expectedCode -or $query.inputBytes -ne $expectedInput -or $query.inputHex -cnotmatch ('^[0-9a-f]{'+($expectedInput*2)+'}$') -or $query.outputCapacityBytes -ne $capacity -or $query.bytesReturned -lt 0 -or $query.bytesReturned -gt $capacity) { throw 'Unreviewed native control code or bounds in evidence.' }
        if($query.name -ne 'move') {
            $expectedHex=if($query.name -ceq 'candidateMetadataBitmap'){'00000000000000000100000000000000'}else{'0000000000000000'}
            if($query.inputHex -cne $expectedHex){throw 'Native query input differs.'}
        }
        if($query.bufferPath) {
            $name=$query.name+'.bin'; $match=@($Files | Where-Object name -CEQ $name)
            if($query.bufferPath -cne ($Response.EvidenceDirectory+'\'+$name) -or $match.Count -ne 1 -or $match[0].sha256 -cne $query.bufferSha256 -or $match[0].length -ne $query.bytesReturned) { throw 'Native buffer provenance differs from exported bytes.' }
            $referenced+=$name
        } elseif($query.bytesReturned -ne 0 -or $query.bufferSha256) { throw 'A native buffer is missing from the export.' }
    }
    if(@($Files | Where-Object {$_.name -clike '*.bin' -and $_.name -cne 'expected-pattern.bin' -and $_.name -cnotin $referenced}).Count) { throw 'An exported native buffer has no query provenance.' }
    if(@($Record.nativeQueries | Where-Object name -CEQ 'move').Count -ne [int]$Record.moveAttempted){throw 'Move attempt differs from native query records.'}
}
function Assert-ExtentPlacementObservation($Observation,[long]$Length) {
    if($Observation.length -ne $Length -or $Observation.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $Observation.fileId64 -cnotmatch '^0x[0-9a-f]{16}$' -or $Observation.volumeSerialHex -cnotmatch '^0x[0-9a-f]{8}$' -or @($Observation.extents).Count -lt 1 -or @($Observation.extents).Count -gt ($Length/4096)){throw 'Incomplete file observation.'}
    $next=[long]0
    foreach($extent in $Observation.extents){if($extent.startingVcn -ne $next -or $extent.nextVcn -le $next -or $extent.nextVcn -gt ($Length/4096) -or $extent.lcn -lt 0 -or $extent.lcn -gt ((52GB/4096)-($extent.nextVcn-$next))){throw 'Out-of-bounds or discontinuous file mapping.'};$next=[long]$extent.nextVcn}
    if($next -ne ($Length/4096)){throw 'File mapping lacks complete coverage.'}
}
function Assert-ExtentPlacementSameObservation($Left,$Right,[switch]$Mapping) {
    foreach($field in @('length','sha256','fileId64','volumeSerialHex')){if([string]$Left.$field -cne [string]$Right.$field){throw 'File identity, length or logical hash changed.'}}
    if($Mapping){if(@($Left.extents).Count -ne @($Right.extents).Count){throw 'Mapping count changed.'};for($i=0;$i -lt @($Left.extents).Count;$i++){foreach($field in @('startingVcn','nextVcn','lcn')){if($Left.extents[$i].$field -ne $Right.extents[$i].$field){throw 'Native mapping changed.'}}}}
}
function Assert-ExtentPlacementCompleted($Record,$Captured,[object[]]$Files) {
    if($Record.status -cnotin @('native-move-rejected','native-move-returned-unexpected-mapping','native-placement-observed-awaiting-remount') -or $Record.nativePhase -cne 'complete'){throw 'Incomplete or failed-integrity placement must preserve its branch.'}
    foreach($field in @('targetWriteRequestsIssued','fixtureCreated','fixtureFullyInitialized','creationFlushed','moveAttempted','moveCompleted','contentPreserved','originalUnchanged','originalIndependentObservationUnchanged')){if($Record.$field -isnot [bool] -or -not $Record.$field){throw 'Placement lacks determinate completion and unchanged content.'}}
    foreach($name in @('started.json','allocation-before.json','allocation-after.json','expected-pattern.bin')){if(@($Files|Where-Object name -CEQ $name).Count -ne 1){throw 'Completed placement evidence is missing.'}}
    $pattern=@($Files|Where-Object name -CEQ 'expected-pattern.bin')[0]
    if($Record.expectedSha256 -cne $pattern.sha256){throw 'Expected pattern hash differs from exported bytes.'}
    foreach($name in @('originalBefore','originalAfter')){Assert-ExtentPlacementObservation $Record.$name 4MB;Assert-ExtentPlacementSameObservation $Captured $Record.$name -Mapping}
    foreach($name in @('before','after')){Assert-ExtentPlacementObservation $Record.$name 65536;if($Record.$name.sha256 -cne $Record.expectedSha256){throw 'Initialized fixture hash differs from pattern.'}}
    Assert-ExtentPlacementSameObservation $Record.before $Record.after
    if($Record.before.volumeSerialHex -cne $Captured.volumeSerialHex -or $Record.requestedLcn -lt 65536 -or $Record.requestedLcn % 16 -ne 0 -or $Record.requestedLcn -gt ((52GB/4096)-16)){throw 'Unexpected volume identity or destination range.'}
    $move=@($Record.nativeQueries|Where-Object name -CEQ 'move')
    if(@($Record.nativeQueries).Count -ne 7 -or $move.Count -ne 1 -or $move[0].succeeded -isnot [bool]){throw 'Completed placement lacks one recorded native call.'}
    $input=[byte[]]@(for($i=0;$i -lt 32;$i++){[Convert]::ToByte($move[0].inputHex.Substring($i*2,2),16)})
    if([BitConverter]::ToInt64($input,8) -ne 0 -or [BitConverter]::ToInt64($input,16) -ne $Record.requestedLcn -or [BitConverter]::ToUInt32($input,24) -ne 16 -or [BitConverter]::ToUInt32($input,28) -ne 0){throw 'Move input differs from the bounded request.'}
    $atDestination=@($Record.after.extents).Count -eq 1 -and $Record.after.extents[0].startingVcn -eq 0 -and $Record.after.extents[0].nextVcn -eq 16 -and $Record.after.extents[0].lcn -eq $Record.requestedLcn
    if($Record.requestedPlacementObserved -isnot [bool] -or $Record.requestedPlacementObserved -ne $atDestination){throw 'Requested placement claim differs from observed mapping.'}
    $expectedStatus=if(-not $move[0].succeeded){'native-move-rejected'}elseif($atDestination){'native-placement-observed-awaiting-remount'}else{'native-move-returned-unexpected-mapping'}
    if($Record.status -cne $expectedStatus -or ($move[0].succeeded -and $move[0].nativeError -ne 0) -or (-not $move[0].succeeded -and $move[0].nativeError -eq 0)){throw 'Native status and movement evidence disagree.'}
}
function Assert-ExtentPlacementRemount($Identity,$Allocation,$Record,$Control,[string]$CollectorSha256) {
    if($Identity.schemaVersion -ne 1 -or $Identity.kind -cne 'native-extent-placement-remount' -or $Identity.probeId -cne $Record.probeId -or $Identity.controlEvidenceSha256 -cne $Record.controlEvidenceSha256 -or $Identity.capturedAllocationSha256 -cne $Record.capturedAllocationSha256 -or $Identity.volumeUniqueId -cne $Record.volumeUniqueId){throw 'Remount identity or source evidence changed.'}
    foreach($field in @('role','uniqueId','sizeBytes','location')){if([string]$Identity.target.$field -cne [string]$Control.target.guest.$field -or [string]$Allocation.diskIdentity.$field -cne [string]$Control.target.guest.$field){throw 'Remount target identity changed.'}}
    foreach($field in @('guid','diskGuid','number','offset','length','letter','logicalSectorSize','physicalSectorSize')){if([string]$Identity.partition.$field -cne [string]$Control.partition.$field){throw 'Remount GPT or geometry changed.'}}
    if($Allocation.schemaVersion -ne 1 -or $Allocation.kind -cne 'native-file-allocation-observations' -or $Allocation.complete -ne $true -or $Allocation.evidenceScriptSha256 -cne $CollectorSha256 -or $Allocation.windowsBuild -cne '26300.9457' -or $Allocation.filesystemDriver.sha256 -cne '3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4' -or $Allocation.volume.uniqueId -cne $Record.volumeUniqueId -or $Allocation.volume.fileSystem -cne 'ReFS' -or $Allocation.volume.label -cne 'ntfs2refs-target' -or $Allocation.volume.allocationUnitSize -ne 4096 -or $Allocation.volume.size -ne 52GB -or $Allocation.partition.number -ne 2 -or $Allocation.partition.offset -ne 16MB -or $Allocation.partition.size -ne 52GB -or $Allocation.partition.driveLetter -cne 'F' -or $Allocation.logicalSectorSize -ne 512 -or $Allocation.physicalSectorSize -ne 4096 -or @($Allocation.files).Count -ne 2){throw 'Remount allocation provenance or profile differs.'}
    foreach($field in @('sourceWriteRequestsIssued','physicalMappingVerified','conversionQualified','bootQualified')){if($Allocation.$field -isnot [bool] -or $Allocation.$field){throw 'Read-only remount collector claims unsupported activity.'}}
    foreach($entry in @(@{path='fixtures\nonresident.bin';expected=$Record.originalAfter;length=4MB},@{path=('fixtures\placement-'+$Record.probeId+'\initialized.bin');expected=$Record.after;length=65536})){
        $files=@($Allocation.files|Where-Object {$_.path -ceq $entry.path -and $_.stream -ceq ':$DATA'})
        if($files.Count -ne 1 -or $files[0].observation.complete -ne $true -or $files[0].observation.stableDuringObservation -ne $true -or $files[0].observation.status -cne 'mapping-returned'){throw 'Remount file observation incomplete.'}
        Assert-ExtentPlacementObservation $files[0].observation $entry.length
        Assert-ExtentPlacementSameObservation $entry.expected $files[0].observation -Mapping
    }
}
function Invoke-BoundedPlacementCommand([scriptblock]$ScriptBlock,[object[]]$Arguments=@(),[int]$TimeoutSeconds=60) {
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
function Open-ExtentPlacementSession {
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
function Stop-ExtentPlacementGuest {
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    if($vm.State -eq 'Off'){return}
    if(-not $session -or $script:commandIndeterminate){throw 'An idle authenticated guest session is required for clean shutdown.'}
    Invoke-BoundedPlacementCommand -TimeoutSeconds 30 -ScriptBlock { & shutdown.exe /s /t 0; if($LASTEXITCODE -ne 0){throw 'Guest shutdown request failed.'} } | Out-Null
    $deadline=[DateTime]::UtcNow.AddMinutes(3)
    do { if((Get-VM -Id ([guid]$manifest.vmId)).State -eq 'Off'){return}; Start-Sleep -Seconds 2 } while([DateTime]::UtcNow -lt $deadline)
    throw 'Guest did not shut down cleanly; preserve the branch.'
}
function Assert-ExtentPlacementRemountArtifacts([object[]]$Files) {
    if($Files.Count -ne 2 -or @($Files.name|Select-Object -Unique).Count -ne 2){throw 'Remount export must contain exactly two files.'}
    foreach($file in $Files){if($file.name -cnotin @('identity.json','allocation-remount.json') -or $file.length -lt 1 -or $file.length -gt 1MB -or $file.sha256 -cnotmatch '^[0-9a-f]{64}$' -or ([IO.FileAttributes]$file.attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected remount artifact.'}}
}
function Export-ExtentPlacementArtifacts([string]$GuestRoot,[switch]$Remount) {
    $files=@(Invoke-BoundedPlacementCommand -Arguments @($GuestRoot,[bool]$Remount) -ScriptBlock {
        param($Root,$IsRemount)
        $parents=@('C:\ntfs2refs','C:\ntfs2refs\extent-placement',$Root)
        if($IsRemount){$parents+=Split-Path $Root -Parent}
        foreach($parent in $parents) { $item=Get-Item -LiteralPath $parent -Force; if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected placement evidence root.'} }
        $items=@(Get-ChildItem -LiteralPath $Root -Force)
        if($IsRemount){$allowed=@('identity.json','allocation-remount.json');$maxFiles=2;$maxBytes=1MB}
        else{$allowed=@('started.json','placement.json','allocation-before.json','allocation-after.json','expected-pattern.bin','originalBeforeExtents.bin','originalAfterExtents.bin','beforeExtents.bin','afterExtents.bin','candidateBitmap.bin','candidateMetadataBitmap.bin');$maxFiles=11;$maxBytes=2MB}
        if($items.Count -gt $maxFiles){throw 'Excessive guest evidence files.'}
        foreach($file in $items) {
            if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt $maxBytes -or $file.Name -cnotin $allowed){throw 'Unexpected guest evidence file.'}
            [pscustomobject]@{name=$file.Name;length=$file.Length;attributes=[string]$file.Attributes;sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
        }
    })
    if($Remount){Assert-ExtentPlacementRemountArtifacts $files}else{Assert-ExtentPlacementArtifactSet $files}
    $folder=if($Remount){'remount'}else{'guest'}
    $destination=Assert-LabPath (Join-Path $outputRoot $folder) $configuration.Root
    if(Test-Path -LiteralPath $destination){throw 'Placement export destination already exists.'}
    New-Item -ItemType Directory -Path $destination | Out-Null
    foreach($file in $files) {
        $path=Assert-LabPath (Join-Path $destination $file.name) $configuration.Root
        if(Test-Path -LiteralPath $path){throw 'Evidence export cannot overwrite existing files.'}
        Copy-Item -LiteralPath ($GuestRoot+'\'+$file.name) -Destination $path -FromSession $session
        $local=Get-Item -LiteralPath $path -Force
        if($local.PSIsContainer -or ($local.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $local.Length -ne $file.length -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $file.sha256){throw 'Placement export failed length/hash verification.'}
    }
    $files | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $destination 'exported-files.json') -Encoding UTF8
    $recordName=if($Remount){'identity.json'}else{'placement.json'}
    $allocation=if($Remount){Get-Content -LiteralPath (Join-Path $destination 'allocation-remount.json') -Raw|ConvertFrom-Json}else{$null}
    [pscustomobject]@{files=$files;record=(Get-Content -LiteralPath (Join-Path $destination $recordName) -Raw | ConvertFrom-Json);allocation=$allocation}
}
function Invoke-ExtentPlacementRemountCapture {
    Invoke-BoundedPlacementCommand -TimeoutSeconds $ProbeTimeoutSeconds -Arguments @($probeId,$profile.controlEvidenceSha256,$profile.capturedAllocationSha256,$sourceHashes) -ScriptBlock {
        param($ProbeId,$ControlSha,$CapturedSha,$Sources)
        if($ProbeId -cnotmatch '^[0-9a-f]{32}$'){throw 'Unexpected remount probe ID.'}
        foreach($parent in @('C:\ntfs2refs','C:\ntfs2refs\guest','C:\ntfs2refs\devdrive-control','C:\ntfs2refs\extent-placement',('C:\ntfs2refs\extent-placement\'+$ProbeId))){$item=Get-Item -LiteralPath $parent -Force;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected remount directory.'}}
        if(@($Sources).Count -ne 4){throw 'Incomplete helper manifest.'}
        foreach($source in $Sources){if($source.name -cnotin @('GuestLab.psm1','Capture-GuestAllocation.ps1','NativeExtentPlacement.cs','Invoke-GuestExtentPlacement.ps1')){throw 'Unexpected helper.'};$path='C:\ntfs2refs\guest\'+$source.name;$file=Get-Item -LiteralPath $path -Force;if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -ne $source.length -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $source.sha256){throw 'Guest helper changed after reboot.'}}
        foreach($proof in @(@{name='verify.json';sha=$ControlSha},@{name='allocation-after.json';sha=$CapturedSha})){$path='C:\ntfs2refs\devdrive-control\'+$proof.name;$file=Get-Item -LiteralPath $path -Force;if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 1MB -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $proof.sha){throw 'Guest native source proof changed.'}}
        $control=Get-Content -LiteralPath 'C:\ntfs2refs\devdrive-control\verify.json' -Raw|ConvertFrom-Json
        $manifestPath='C:\ntfs2refs\devdrive-control\target.json'
        $manifestFile=Get-Item -LiteralPath $manifestPath -Force
        if($manifestFile.PSIsContainer -or ($manifestFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $manifestFile.Length -gt 64KB){throw 'Unexpected enrollment file.'}
        $identity=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
        foreach($field in @('schemaVersion','role','uniqueId','serialNumber','serialNumberAvailable','sizeBytes','location','enrolledUtc')){if([string]$identity.$field -cne [string]$control.target.guest.$field){throw 'Remount enrollment changed.'}}
        Import-Module 'C:\ntfs2refs\guest\GuestLab.psm1' -Force
        function Get-RemountIdentity {
            $disk=Get-LabGuestDisk $identity
            $parts=@(Get-Partition -DiskNumber $disk.Number|Where-Object DriveLetter)
            if($parts.Count -ne 1){throw 'Expected exactly one mounted target partition.'}
            $part=$parts[0];$expected=$control.partition
            $bound=@(Get-Partition -DriveLetter F)
            if($bound.Count -ne 1 -or $bound[0].DiskNumber -ne $disk.Number -or [string]$bound[0].Guid -ine [string]$expected.guid -or [string]$disk.Guid -ine [string]$expected.diskGuid -or [string]$part.Guid -ine [string]$expected.guid -or $part.PartitionNumber -ne $expected.number -or $part.Offset -ne $expected.offset -or $part.Size -ne $expected.length -or [string]$part.DriveLetter -cne $expected.letter -or $part.IsBoot -or $part.IsSystem -or $disk.LogicalSectorSize -ne $expected.logicalSectorSize -or $disk.PhysicalSectorSize -ne $expected.physicalSectorSize){throw 'Remount target GPT, geometry or role changed.'}
            $volume=Get-Volume -DriveLetter F
            if($volume.FileSystem -cne 'ReFS' -or $volume.FileSystemLabel -cne 'ntfs2refs-target' -or $volume.AllocationUnitSize -ne 4096 -or $volume.Size -ne 52GB){throw 'Remount filesystem differs.'}
            [pscustomobject]@{schemaVersion=1;kind='native-extent-placement-remount';probeId=$ProbeId;controlEvidenceSha256=$ControlSha;capturedAllocationSha256=$CapturedSha;target=$identity;partition=[pscustomobject]@{guid=[string]$part.Guid;diskGuid=[string]$disk.Guid;number=$part.PartitionNumber;offset=$part.Offset;length=$part.Size;letter=[string]$part.DriveLetter;logicalSectorSize=$disk.LogicalSectorSize;physicalSectorSize=$disk.PhysicalSectorSize};volumeUniqueId=[string]$volume.UniqueId;createdUtc=[DateTime]::UtcNow.ToString('o')}
        }
        $beforeIdentity=Get-RemountIdentity
        $root='C:\ntfs2refs\extent-placement\'+$ProbeId+'\remount'
        if(Test-Path -LiteralPath $root){throw 'Remount output already exists.'}
        New-Item -ItemType Directory -Path $root|Out-Null
        & 'C:\ntfs2refs\guest\Capture-GuestAllocation.ps1' -ManifestPath $manifestPath -FixtureRelativePath @('nonresident.bin',('placement-'+$ProbeId+'\initialized.bin')) -OutputPath ($root+'\allocation-remount.json') -MaximumHashMiB 8|Out-Null
        $afterIdentity=Get-RemountIdentity
        if($beforeIdentity.volumeUniqueId -cne $afterIdentity.volumeUniqueId){throw 'Volume changed during remount observation.'}
        $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes(($afterIdentity|ConvertTo-Json -Depth 10))
        if($bytes.Length -gt 1MB){throw 'Remount identity exceeds evidence bound.'}
        [Ntfs2Refs.NativeAllocationEvidence]::WriteReport(($root+'\identity.json'),$bytes)
        $root
    }
}
function Assert-ExtentPlacementOutcomeCheckpoint($Checkpoint,[string]$ExpectedName,$Profile) {
    $id=[guid]::Empty
    if(-not [guid]::TryParse([string]$Checkpoint.Id,[ref]$id) -or $id -eq [guid]::Empty -or [string]$Checkpoint.Id -iin @($Profile.baselineId,$Profile.checkpointId) -or $Checkpoint.Name -cne $ExpectedName -or [string]$Checkpoint.VMId -ine $Profile.vmId){throw 'Outcome checkpoint identity is invalid.'}
}

if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated Hyper-V access is required.'}
$profile=Get-ExtentPlacementProfile
$manifest=Read-LabManifest -Configuration $configuration -Lane win11
Assert-ExtentPlacementManifest $manifest $profile
$vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
$baseline=Get-ExactLabCheckpoint -VM $vm -Name installed-clean
Assert-ExtentPlacementCheckpoint $baseline $profile -Baseline
Assert-ExtentPlacementVM $vm $profile.baselineId 4GB
$saved=Get-ExactLabCheckpoint -VM $vm -Name $profile.checkpointName
Assert-ExtentPlacementCheckpoint $saved $profile
$controlRoot=Assert-LabPath (Join-Path $configuration.Root $profile.controlDirectory) $configuration.Root
$verifyPath=Assert-LabPath (Join-Path $controlRoot 'after\verify.json') $configuration.Root
$allocationPath=Assert-LabPath (Join-Path $controlRoot 'after\allocation-after.json') $configuration.Root
if((Get-FileHash -LiteralPath $verifyPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $profile.controlEvidenceSha256 -or (Get-FileHash -LiteralPath $allocationPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $profile.capturedAllocationSha256){throw 'Pinned native source evidence changed.'}
$control=Get-Content -LiteralPath $verifyPath -Raw | ConvertFrom-Json
$captured=Get-Content -LiteralPath $allocationPath -Raw | ConvertFrom-Json
$capturedFiles=@($captured.files|Where-Object {$_.path -ceq 'fixtures\nonresident.bin' -and $_.stream -ceq ':$DATA'})
if($captured.complete -ne $true -or $capturedFiles.Count -ne 1){throw 'Original native fixture proof is incomplete.'}
$capturedFixture=$capturedFiles[0].observation
Assert-ExtentPlacementObservation $capturedFixture 4MB
$origin=Get-Content -LiteralPath (Join-Path $controlRoot 'host-result.json') -Raw | ConvertFrom-Json
if($origin.status -cne 'native-devdrive-remount-verified' -or $origin.runId -cne $profile.controlRunId -or $origin.checkpointId -ine $profile.checkpointId -or $origin.checkpointName -cne $profile.checkpointName -or -not $origin.afterExported -or -not $origin.baselineRestored -or -not $origin.memoryRestored){throw 'The saved native control was not completed and exported.'}
$laneRoot=Assert-LabPath (Join-Path $configuration.Root 'win11') $configuration.Root
$credential=Import-Clixml -LiteralPath (Join-Path $laneRoot 'secrets\guest-credential.xml')
if($credential -isnot [Management.Automation.PSCredential] -or $credential.UserName -cne 'N2R-WIN11\LabAdmin'){throw 'Unexpected guest credential identity.'}
Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 4GB
$probeId=[guid]::NewGuid().ToString('N')
$outputRoot=Assert-LabPath (Join-Path $configuration.Root ('extent-placement\win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $configuration.Root
if(Test-Path -LiteralPath $outputRoot){throw 'Placement output root already exists.'}
New-Item -ItemType Directory -Path $outputRoot | Out-Null
$guestNames=@('GuestLab.psm1','Capture-GuestAllocation.ps1','NativeExtentPlacement.cs','Invoke-GuestExtentPlacement.ps1')
$sourceHashes=@(foreach($name in $guestNames){$path=Join-Path $workspace ('lab\guest\'+$name);$file=Get-Item -LiteralPath $path -Force;if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -lt 1 -or $file.Length -gt 256KB){throw 'Unexpected placement source file.'};[pscustomobject]@{name=$name;length=$file.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}})
$record=[ordered]@{schemaVersion=1;kind='native-extent-placement-host';probeId=$probeId;vmId=$profile.vmId;baselineId=$profile.baselineId;sourceCheckpointId=$profile.checkpointId;sourceCheckpointName=$profile.checkpointName;controlRunId=$profile.controlRunId;controlEvidenceSha256=$profile.controlEvidenceSha256;capturedAllocationSha256=$profile.capturedAllocationSha256;status='started';phase='preflight';evidenceExported=$false;firstCleanShutdown=$false;cleanRemountVerified=$false;remountEvidenceExported=$false;cleanShutdown=$false;outcomeCheckpointCreated=$false;outcomeCheckpointId=$null;outcomeCheckpointName=$null;baselineRestored=$false;memoryRestored=$false;targetWriteRequestsMayHaveBeenIssued=$false;targetWriteRequestsIssued=$false;moveAttempted=$false;moveCompleted=$false;physicalMappingVerified=$false;payloadCopyAvoidanceVerified=$false;conversionQualified=$false;bootQualified=$false;sourceHashes=$sourceHashes;hostScriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();labModuleSha256=(Get-FileHash -LiteralPath (Join-Path $workspace 'lab\Lab.psm1') -Algorithm SHA256).Hash.ToLowerInvariant();createdUtc=[DateTime]::UtcNow.ToString('o')}
$session=$null; $script:commandIndeterminate=$false
try {
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-ExtentPlacementVM $vm $profile.baselineId 4GB
    Assert-ExtentPlacementCheckpoint (Get-ExactLabCheckpoint -VM $vm -Name $profile.checkpointName) $profile
    $record.phase='restore-native-control'
    Invoke-LabAction -Action Restore -Lane win11 -CheckpointName $profile.checkpointName -Confirm:$false | Out-Null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-ExtentPlacementVM $vm $profile.checkpointId 8GB
    Invoke-LabAction -Action Start -Lane win11 -Confirm:$false | Out-Null
    $session=Open-ExtentPlacementSession
    $policy=Initialize-LabGuestSession -Session $session
    $policy | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $outputRoot 'session.json') -Encoding UTF8
    if($policy.status -cne 'ready'){throw ('Guest session refused: '+$policy.error)}
    Invoke-BoundedPlacementCommand -ScriptBlock {
        foreach($path in @('C:\ntfs2refs','C:\ntfs2refs\guest')){$item=Get-Item -LiteralPath $path -Force;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected guest script directory.'}}
        foreach($name in @('GuestLab.psm1','Capture-GuestAllocation.ps1','NativeExtentPlacement.cs','Invoke-GuestExtentPlacement.ps1')){$path='C:\ntfs2refs\guest\'+$name;if(Test-Path -LiteralPath $path){$item=Get-Item -LiteralPath $path -Force;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected guest helper destination.'}}}
    } | Out-Null
    foreach($file in $sourceHashes){Copy-Item -LiteralPath (Join-Path $workspace ('lab\guest\'+$file.name)) -Destination ('C:\ntfs2refs\guest\'+$file.name) -ToSession $session -Force}
    $copied=@(Invoke-BoundedPlacementCommand -ScriptBlock {foreach($name in @('GuestLab.psm1','Capture-GuestAllocation.ps1','NativeExtentPlacement.cs','Invoke-GuestExtentPlacement.ps1')){$path='C:\ntfs2refs\guest\'+$name;$file=Get-Item -LiteralPath $path -Force;if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected copied helper.'};[pscustomobject]@{name=$name;length=$file.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}}})
    if($copied.Count -ne $sourceHashes.Count){throw 'Incomplete helper copy.'}
    foreach($file in $sourceHashes){$copy=@($copied|Where-Object name -CEQ $file.name);if($copy.Count -ne 1 -or $copy[0].length -ne $file.length -or $copy[0].sha256 -cne $file.sha256){throw 'Guest helper hash differs from dispatched source.'}}
    Get-OwnedLabVM -Configuration $configuration -Manifest $manifest | Out-Null
    $record.phase='initialized-file-placement'
    # Intent is durable on the host before dispatch. Unknown attempt flags stay null.
    $record.targetWriteRequestsMayHaveBeenIssued=$true; $record.targetWriteRequestsIssued=$null; $record.moveAttempted=$null; $record.moveCompleted=$null
    $record|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $outputRoot 'host-result.json') -Encoding UTF8
    $responses=@(Invoke-BoundedPlacementCommand -TimeoutSeconds $ProbeTimeoutSeconds -Arguments @($profile.controlRunId,$profile.controlEvidenceSha256,$profile.capturedAllocationSha256,$probeId) -ScriptBlock {param($RunId,$ControlSha,$AllocationSha,$ProbeId); & 'C:\ntfs2refs\guest\Invoke-GuestExtentPlacement.ps1' -ControlRunId $RunId -ControlEvidenceSha256 $ControlSha -CapturedAllocationSha256 $AllocationSha -ProbeId $ProbeId -Confirm:$false})
    if($responses.Count -ne 1){throw 'Guest returned an ambiguous placement response.'}
    $response=$responses[0]; Assert-ExtentPlacementResponse $response $probeId
    $record.phase='export'
    $export=Export-ExtentPlacementArtifacts $response.EvidenceDirectory
    $scriptSha=($sourceHashes|Where-Object name -CEQ 'Invoke-GuestExtentPlacement.ps1').sha256
    $nativeSha=($sourceHashes|Where-Object name -CEQ 'NativeExtentPlacement.cs').sha256
    Assert-ExtentPlacementRecord $export.record $response $profile $control $export.files $scriptSha $nativeSha
    $record.evidenceExported=$true; $record['guestStatus']=$response.Status
    foreach($field in @('targetWriteRequestsIssued','moveAttempted','moveCompleted')){$record[$field]=$export.record.$field}
    $record['guestEvidenceSha256']=($export.files|Where-Object name -CEQ 'placement.json').sha256
    Assert-ExtentPlacementCompleted $export.record $capturedFixture $export.files
    $intent=Get-Content -LiteralPath (Join-Path $outputRoot 'guest\started.json') -Raw|ConvertFrom-Json
    foreach($field in @('probeId','controlRunId','controlEvidenceSha256','capturedAllocationSha256','scriptSha256','nativeSourceSha256','fixturePath')){if($intent.$field -cne $export.record.$field){throw 'Durable intent differs from the completed experiment.'}}
    if($intent.targetWriteRequestsMayHaveBeenIssued -ne $true){throw 'Durable intent did not precede native writes.'}
    $record['nativeMoveSucceeded']=@($export.record.nativeQueries|Where-Object name -CEQ 'move')[0].succeeded
    $record['requestedPlacementObserved']=$export.record.requestedPlacementObserved
    $record['requestedLcn']=$export.record.requestedLcn
    $record['newFileBefore']=$export.record.before; $record['newFileAfter']=$export.record.after
    $record.phase='first-clean-shutdown'
    Stop-ExtentPlacementGuest
    $record.firstCleanShutdown=$true
    Remove-PSSession -Session $session -ErrorAction SilentlyContinue; $session=$null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-ExtentPlacementVM $vm $profile.checkpointId 8GB
    $record.phase='clean-remount'
    Invoke-LabAction -Action Start -Lane win11 -Confirm:$false|Out-Null
    $session=Open-ExtentPlacementSession
    $policy=Initialize-LabGuestSession -Session $session
    $policy|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $outputRoot 'remount-session.json') -Encoding UTF8
    if($policy.status -cne 'ready'){throw ('Remount guest session refused: '+$policy.error)}
    $remountRoots=@(Invoke-ExtentPlacementRemountCapture)
    if($remountRoots.Count -ne 1 -or $remountRoots[0] -cne ($response.EvidenceDirectory+'\remount')){throw 'Unexpected remount output path.'}
    $remount=Export-ExtentPlacementArtifacts $remountRoots[0] -Remount
    $collectorSha=($sourceHashes|Where-Object name -CEQ 'Capture-GuestAllocation.ps1').sha256
    Assert-ExtentPlacementRemount $remount.record $remount.allocation $export.record $control $collectorSha
    $record.remountEvidenceExported=$true; $record.cleanRemountVerified=$true
    $record['remountIdentitySha256']=($remount.files|Where-Object name -CEQ 'identity.json').sha256
    $record['remountAllocationSha256']=($remount.files|Where-Object name -CEQ 'allocation-remount.json').sha256
    $record.phase='final-clean-shutdown'
    Stop-ExtentPlacementGuest
    $record.cleanShutdown=$true
    Remove-PSSession -Session $session -ErrorAction SilentlyContinue; $session=$null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-ExtentPlacementVM $vm $profile.checkpointId 8GB
    Assert-LabCapacity (Get-LabCapacity $configuration)
    $record.phase='preserve-off-state-outcome'
    $outcomeName='extent-placement-data-'+$probeId
    Invoke-LabAction -Action Checkpoint -Lane win11 -CheckpointName $outcomeName -Confirm:$false|Out-Null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    $outcome=Get-ExactLabCheckpoint -VM $vm -Name $outcomeName
    Assert-ExtentPlacementOutcomeCheckpoint $outcome $outcomeName $profile
    Assert-ExtentPlacementVM $vm ([string]$outcome.Id) 8GB
    $record.outcomeCheckpointCreated=$true; $record.outcomeCheckpointId=[string]$outcome.Id; $record.outcomeCheckpointName=$outcome.Name
    Assert-ExtentPlacementCheckpoint (Get-ExactLabCheckpoint -VM $vm -Name installed-clean) $profile -Baseline
    $record.phase='restore-baseline'
    Invoke-LabAction -Action Restore -Lane win11 -CheckpointName installed-clean -Confirm:$false | Out-Null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    if($vm.State -ne 'Off' -or [string]$vm.ParentSnapshotId -ine $profile.baselineId){throw 'Baseline restore did not return the exact off-state branch.'}
    if($vm.MemoryStartup -ne 4GB -or $vm.DynamicMemoryEnabled){Set-VMMemory -VM $vm -StartupBytes 4GB -DynamicMemoryEnabled $false}
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-ExtentPlacementVM $vm $profile.baselineId 4GB
    $record.baselineRestored=$true; $record.memoryRestored=$true; $record.status='native-extent-placement-remount-verified'; $record.phase='complete'
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
[pscustomobject]@{Status=$record.status;GuestStatus=$record.guestStatus;Evidence=$outputRoot;BaselineRestored=$record.baselineRestored;MemoryRestored=$record.memoryRestored;TargetWriteRequestsIssued=$record.targetWriteRequestsIssued;MoveAttempted=$record.moveAttempted;MoveCompleted=$record.moveCompleted;CleanRemountVerified=$record.cleanRemountVerified;OutcomeCheckpointId=$record.outcomeCheckpointId;OutcomeCheckpointName=$record.outcomeCheckpointName;PhysicalMappingVerified=$false;PayloadCopyAvoidanceVerified=$false;ConversionQualified=$false}
