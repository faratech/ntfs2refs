<# Read-only native extent discovery on the exact saved Dev Drive data branch.
   Host Hyper-V operations are lab orchestration, never converter dependencies. #>
[CmdletBinding(SupportsShouldProcess)]
param([ValidateRange(60,900)][int]$BootTimeoutSeconds=300,[ValidateRange(30,600)][int]$QueryTimeoutSeconds=180)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
$configuration=Get-LabConfiguration -WorkspaceRoot $workspace
if (-not $PSCmdlet.ShouldProcess('ntfs2refs-win11','Restore the exact saved Dev Drive checkpoint, run read-only native extent queries, export bounded evidence, cleanly shut down and restore installed-clean with 4 GiB RAM')) {
    [pscustomobject]@{Action='NativeExtentDiscovery';DryRun=$true;MemoryBytes=8GB;SourceWriteRequestsIssued=$false;MoveAttempted=$false;RawDiskWrites=$false;ConversionQualified=$false}; return
}

function Get-ExtentDiscoveryProfile {
    [pscustomobject]@{vmId='eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c';baselineId='eda059b3-6d50-46bb-bdf4-018b99b5b34f';checkpointId='2aa127e2-c875-4ca0-8629-dab784136448';checkpointName='devdrive-data-20261023T230635404Z';controlDirectory='devdrive\win11-20261023T230635404Z';controlRunId='65f270323c26427e8316c7a8b75959cc';controlEvidenceSha256='ca9e3e60bbe84bd758609d92b92a305a948213b4ab0f5ce199f38567a8ea84c1';capturedAllocationSha256='f553fd91111dfb09a9aa14d27fe63daaba790c0efb14bd530ac5cd9ef0f55be2';targetVhdId='25c491d0-5f1b-4205-9e6f-fd619706c2b5'}
}
function Assert-ExtentDiscoveryManifest($Manifest,$Profile) {
    if ([string]$Manifest.vmId -ine $Profile.vmId -or @($Manifest.disks).Count -ne 3) { throw 'Unexpected discovery VM or disk count.' }
    foreach($role in @('os','target','journal')) {
        $selected=@($Manifest.disks | Where-Object role -CEQ $role)
        $slot=if($role -ceq 'os'){0}elseif($role -ceq 'target'){1}else{2}
        $bytes=if($role -ceq 'journal'){8GB}else{64GB}
        if($selected.Count -ne 1 -or $selected[0].controllerLocation -ne $slot -or $selected[0].sizeBytes -ne $bytes) { throw 'Discovery requires the original three owned disks.' }
        if($role -ceq 'target' -and [string]$selected[0].vhdId -ine $Profile.targetVhdId) { throw 'Unexpected original target VHD identity.' }
    }
}
function Assert-ExtentDiscoveryVM($VM,[string]$ExpectedParent,[long]$MemoryBytes) {
    if($VM.State -ne 'Off' -or $VM.MemoryStartup -ne $MemoryBytes -or $VM.DynamicMemoryEnabled -or [string]$VM.ParentSnapshotId -ine $ExpectedParent) { throw 'Discovery requires the exact powered-off checkpoint branch and fixed memory profile.' }
    if(@(Get-VMNetworkAdapter -VM $VM | Where-Object SwitchName).Count -or (Get-VMFirmware -VM $VM).SecureBoot -ne 'On') { throw 'Discovery requires disconnected networking and unchanged Secure Boot.' }
}
function Assert-ExtentDiscoveryCheckpoint($Checkpoint,$Profile,[switch]$Baseline) {
    $id=if($Baseline){$Profile.baselineId}else{$Profile.checkpointId}
    $name=if($Baseline){'installed-clean'}else{$Profile.checkpointName}
    if([string]$Checkpoint.Id -ine $id -or $Checkpoint.Name -cne $name -or [string]$Checkpoint.VMId -ine $Profile.vmId) { throw 'Saved discovery checkpoint identity changed.' }
}
function Assert-ExtentDiscoveryResponse($Result,[string]$ExpectedId) {
    if($Result.DiscoveryId -cne $ExpectedId -or $Result.Status -cnotin @('observed-awaiting-offline-payload-match','observed-with-unresolved-results','blocked') -or $Result.EvidenceDirectory -cne ('C:\ntfs2refs\extent-discovery\'+$ExpectedId)) { throw 'Unexpected guest discovery response.' }
    foreach($field in @('MoveAttempted','PhysicalMappingVerified','ConversionQualified')) { if($Result.$field -isnot [bool] -or $Result.$field -ne $false) { throw 'Read-only discovery response claims an unperformed qualification.' } }
}
function Assert-ExtentDiscoveryArtifact($File) {
    $maximum=0
    if($File.name -cin @('discovery.json','allocation-before.json','allocation-after.json')) { $maximum=1MB }
    elseif($File.name -cin @('baseBefore.bin','baseAfter.bin')) { $maximum=8 }
    elseif($File.name -cin @('bitmapBefore.bin','bitmapAfter.bin','bitmapExtendedFlags0.bin','bitmapExtendedFlags1.bin')) { $maximum=2MB }
    else { throw 'Unexpected discovery artifact name.' }
    if($File.length -lt 1 -or $File.length -gt $maximum -or $File.sha256 -cnotmatch '^[0-9a-f]{64}$' -or ([IO.FileAttributes]$File.attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid or oversized discovery artifact.' }
}
function Assert-ExtentDiscoveryArtifactSet([object[]]$Files) {
    if($Files.Count -lt 1 -or $Files.Count -gt 9 -or @($Files | Where-Object name -CEQ 'discovery.json').Count -ne 1 -or @($Files.name | Select-Object -Unique).Count -ne $Files.Count) { throw 'Missing, duplicate or excessive discovery artifacts.' }
    foreach($file in $Files) { Assert-ExtentDiscoveryArtifact $file }
    if(($Files | Measure-Object length -Sum).Sum -gt 12MB) { throw 'Discovery evidence exceeds the aggregate bound.' }
}
function Assert-ExtentDiscoveryRecord($Record,$Response,$Profile,$Control,[object[]]$Files,[string]$ScriptSha256,[string]$NativeSha256) {
    if($Record.schemaVersion -ne 1 -or $Record.kind -cne 'native-extent-discovery' -or $Record.phase -cne 'ReadOnlyDiscovery' -or $Record.discoveryId -cne $Response.DiscoveryId -or $Record.status -cne $Response.Status -or $Record.controlRunId -cne $Profile.controlRunId -or $Record.controlEvidenceSha256 -cne $Profile.controlEvidenceSha256 -or $Record.capturedAllocationSha256 -cne $Profile.capturedAllocationSha256 -or $Record.scriptSha256 -cne $ScriptSha256 -or $Record.nativeSourceSha256 -cne $NativeSha256) { throw 'Exported discovery provenance differs from the dispatched experiment.' }
    foreach($field in @('sourceWriteRequestsIssued','moveImplemented','moveAttempted','physicalMappingVerified','payloadCopyAvoidanceVerified','conversionQualified')) { if($Record.$field -isnot [bool] -or $Record.$field -ne $false) { throw 'Discovery record claims writes or an unperformed qualification.' } }
    if($Record.nativeMoveSupport -cne 'unmeasured') { throw 'Read-only discovery cannot qualify native movement.' }
    foreach($field in @('role','uniqueId','sizeBytes','location')) { if([string]$Record.target.$field -cne [string]$Control.target.guest.$field) { throw 'Discovery target enrollment changed.' } }
    foreach($field in @('guid','diskGuid','number','offset','length','letter','logicalSectorSize','physicalSectorSize')) { if([string]$Record.partition.$field -cne [string]$Control.partition.$field) { throw 'Discovery GPT identity or geometry changed.' } }
    if(@($Record.nativeQueries).Count -gt 6 -or @($Record.nativeQueries | ForEach-Object {$_.name} | Select-Object -Unique).Count -ne @($Record.nativeQueries).Count) { throw 'Unexpected native query count.' }
    $referenced=@()
    foreach($query in $Record.nativeQueries) {
        if($query.name -cnotin @('baseBefore','baseAfter','bitmapBefore','bitmapAfter','bitmapExtendedFlags0','bitmapExtendedFlags1')) { throw 'Unreviewed native query in evidence.' }
        $expectedCode=if($query.name -clike 'base*'){'0x00090234'}else{'0x0009006f'}
        if($query.controlCode -cne $expectedCode) { throw 'Unreviewed native control code in evidence.' }
        if($query.bufferPath) {
            $name=$query.name+'.bin'; $match=@($Files | Where-Object name -CEQ $name)
            if($query.bufferPath -cne ($Response.EvidenceDirectory+'\'+$name) -or $match.Count -ne 1 -or $match[0].sha256 -cne $query.bufferSha256 -or $match[0].length -ne $query.bytesReturned) { throw 'Native buffer provenance differs from exported bytes.' }
            $referenced+=$name
        } elseif($query.bytesReturned -ne 0 -or $query.bufferSha256) { throw 'A native buffer is missing from the export.' }
    }
    if(@($Files | Where-Object {$_.name -clike '*.bin' -and $_.name -cnotin $referenced}).Count) { throw 'An exported native buffer has no query provenance.' }
}
function Invoke-BoundedDiscoveryCommand([scriptblock]$ScriptBlock,[object[]]$Arguments=@(),[int]$TimeoutSeconds=60) {
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
function Open-ExtentDiscoverySession {
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
function Stop-ExtentDiscoveryGuest {
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    if($vm.State -eq 'Off'){return}
    if(-not $session -or $script:commandIndeterminate){throw 'An idle authenticated guest session is required for clean shutdown.'}
    Invoke-BoundedDiscoveryCommand -TimeoutSeconds 30 -ScriptBlock { & shutdown.exe /s /t 0; if($LASTEXITCODE -ne 0){throw 'Guest shutdown request failed.'} } | Out-Null
    $deadline=[DateTime]::UtcNow.AddMinutes(3)
    do { if((Get-VM -Id ([guid]$manifest.vmId)).State -eq 'Off'){return}; Start-Sleep -Seconds 2 } while([DateTime]::UtcNow -lt $deadline)
    throw 'Guest did not shut down cleanly; preserve the branch.'
}
function Export-ExtentDiscoveryArtifacts([string]$GuestRoot) {
    $files=@(Invoke-BoundedDiscoveryCommand -Arguments @($GuestRoot) -ScriptBlock {
        param($Root)
        foreach($parent in @('C:\ntfs2refs','C:\ntfs2refs\extent-discovery',$Root)) { $item=Get-Item -LiteralPath $parent -Force; if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected discovery evidence root.'} }
        $items=@(Get-ChildItem -LiteralPath $Root -Force)
        if($items.Count -gt 9){throw 'Excessive guest evidence files.'}
        foreach($file in $items) {
            if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 2MB -or $file.Name -cnotin @('discovery.json','allocation-before.json','allocation-after.json','baseBefore.bin','baseAfter.bin','bitmapBefore.bin','bitmapAfter.bin','bitmapExtendedFlags0.bin','bitmapExtendedFlags1.bin')){throw 'Unexpected guest evidence file.'}
            [pscustomobject]@{name=$file.Name;length=$file.Length;attributes=[string]$file.Attributes;sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
        }
    })
    Assert-ExtentDiscoveryArtifactSet $files
    $destination=Assert-LabPath (Join-Path $outputRoot 'guest') $configuration.Root
    if(Test-Path -LiteralPath $destination){throw 'Discovery export destination already exists.'}
    New-Item -ItemType Directory -Path $destination | Out-Null
    foreach($file in $files) {
        $path=Assert-LabPath (Join-Path $destination $file.name) $configuration.Root
        if(Test-Path -LiteralPath $path){throw 'Evidence export cannot overwrite existing files.'}
        Copy-Item -LiteralPath ($GuestRoot+'\'+$file.name) -Destination $path -FromSession $session
        $local=Get-Item -LiteralPath $path -Force
        if($local.PSIsContainer -or ($local.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $local.Length -ne $file.length -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $file.sha256){throw 'Discovery export failed length/hash verification.'}
    }
    $files | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $destination 'exported-files.json') -Encoding UTF8
    [pscustomobject]@{files=$files;record=(Get-Content -LiteralPath (Join-Path $destination 'discovery.json') -Raw | ConvertFrom-Json)}
}

if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated Hyper-V access is required.'}
$profile=Get-ExtentDiscoveryProfile
$manifest=Read-LabManifest -Configuration $configuration -Lane win11
Assert-ExtentDiscoveryManifest $manifest $profile
$vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
$baseline=Get-ExactLabCheckpoint -VM $vm -Name installed-clean
Assert-ExtentDiscoveryCheckpoint $baseline $profile -Baseline
Assert-ExtentDiscoveryVM $vm $profile.baselineId 4GB
$saved=Get-ExactLabCheckpoint -VM $vm -Name $profile.checkpointName
Assert-ExtentDiscoveryCheckpoint $saved $profile
$controlRoot=Assert-LabPath (Join-Path $configuration.Root $profile.controlDirectory) $configuration.Root
$verifyPath=Assert-LabPath (Join-Path $controlRoot 'after\verify.json') $configuration.Root
$allocationPath=Assert-LabPath (Join-Path $controlRoot 'after\allocation-after.json') $configuration.Root
if((Get-FileHash -LiteralPath $verifyPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $profile.controlEvidenceSha256 -or (Get-FileHash -LiteralPath $allocationPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $profile.capturedAllocationSha256){throw 'Pinned native source evidence changed.'}
$control=Get-Content -LiteralPath $verifyPath -Raw | ConvertFrom-Json
$origin=Get-Content -LiteralPath (Join-Path $controlRoot 'host-result.json') -Raw | ConvertFrom-Json
if($origin.status -cne 'native-devdrive-remount-verified' -or $origin.runId -cne $profile.controlRunId -or $origin.checkpointId -ine $profile.checkpointId -or $origin.checkpointName -cne $profile.checkpointName -or -not $origin.afterExported -or -not $origin.baselineRestored -or -not $origin.memoryRestored){throw 'The saved native control was not completed and exported.'}
$laneRoot=Assert-LabPath (Join-Path $configuration.Root 'win11') $configuration.Root
$credential=Import-Clixml -LiteralPath (Join-Path $laneRoot 'secrets\guest-credential.xml')
if($credential -isnot [Management.Automation.PSCredential] -or $credential.UserName -cne 'N2R-WIN11\LabAdmin'){throw 'Unexpected guest credential identity.'}
Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 4GB
$discoveryId=[guid]::NewGuid().ToString('N')
$outputRoot=Assert-LabPath (Join-Path $configuration.Root ('extent-discovery\win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $configuration.Root
if(Test-Path -LiteralPath $outputRoot){throw 'Discovery output root already exists.'}
New-Item -ItemType Directory -Path $outputRoot | Out-Null
$guestNames=@('GuestLab.psm1','Capture-GuestAllocation.ps1','NativeExtentDiscovery.cs','Capture-GuestExtentDiscovery.ps1')
$sourceHashes=@(foreach($name in $guestNames){$path=Join-Path $workspace ('lab\guest\'+$name);$file=Get-Item -LiteralPath $path -Force;if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -lt 1 -or $file.Length -gt 256KB){throw 'Unexpected discovery source file.'};[pscustomobject]@{name=$name;length=$file.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}})
$record=[ordered]@{schemaVersion=1;kind='native-extent-discovery-host';discoveryId=$discoveryId;vmId=$profile.vmId;baselineId=$profile.baselineId;sourceCheckpointId=$profile.checkpointId;sourceCheckpointName=$profile.checkpointName;controlRunId=$profile.controlRunId;controlEvidenceSha256=$profile.controlEvidenceSha256;capturedAllocationSha256=$profile.capturedAllocationSha256;status='started';phase='preflight';evidenceExported=$false;cleanShutdown=$false;baselineRestored=$false;memoryRestored=$false;sourceWriteRequestsIssued=$false;moveAttempted=$false;physicalMappingVerified=$false;conversionQualified=$false;sourceHashes=$sourceHashes;hostScriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();labModuleSha256=(Get-FileHash -LiteralPath (Join-Path $workspace 'lab\Lab.psm1') -Algorithm SHA256).Hash.ToLowerInvariant();createdUtc=[DateTime]::UtcNow.ToString('o')}
$session=$null; $script:commandIndeterminate=$false
try {
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-ExtentDiscoveryVM $vm $profile.baselineId 4GB
    Assert-ExtentDiscoveryCheckpoint (Get-ExactLabCheckpoint -VM $vm -Name $profile.checkpointName) $profile
    $record.phase='restore-native-control'
    Invoke-LabAction -Action Restore -Lane win11 -CheckpointName $profile.checkpointName -Confirm:$false | Out-Null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-ExtentDiscoveryVM $vm $profile.checkpointId 8GB
    Invoke-LabAction -Action Start -Lane win11 -Confirm:$false | Out-Null
    $session=Open-ExtentDiscoverySession
    $policy=Initialize-LabGuestSession -Session $session
    $policy | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $outputRoot 'session.json') -Encoding UTF8
    if($policy.status -cne 'ready'){throw ('Guest session refused: '+$policy.error)}
    Invoke-BoundedDiscoveryCommand -ScriptBlock {
        foreach($path in @('C:\ntfs2refs','C:\ntfs2refs\guest')){$item=Get-Item -LiteralPath $path -Force;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected guest script directory.'}}
        foreach($name in @('GuestLab.psm1','Capture-GuestAllocation.ps1','NativeExtentDiscovery.cs','Capture-GuestExtentDiscovery.ps1')){$path='C:\ntfs2refs\guest\'+$name;if(Test-Path -LiteralPath $path){$item=Get-Item -LiteralPath $path -Force;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected guest helper destination.'}}}
    } | Out-Null
    foreach($file in $sourceHashes){Copy-Item -LiteralPath (Join-Path $workspace ('lab\guest\'+$file.name)) -Destination ('C:\ntfs2refs\guest\'+$file.name) -ToSession $session -Force}
    $copied=@(Invoke-BoundedDiscoveryCommand -ScriptBlock {foreach($name in @('GuestLab.psm1','Capture-GuestAllocation.ps1','NativeExtentDiscovery.cs','Capture-GuestExtentDiscovery.ps1')){$path='C:\ntfs2refs\guest\'+$name;$file=Get-Item -LiteralPath $path -Force;if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected copied helper.'};[pscustomobject]@{name=$name;length=$file.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}}})
    if($copied.Count -ne $sourceHashes.Count){throw 'Incomplete helper copy.'}
    foreach($file in $sourceHashes){$copy=@($copied|Where-Object name -CEQ $file.name);if($copy.Count -ne 1 -or $copy[0].length -ne $file.length -or $copy[0].sha256 -cne $file.sha256){throw 'Guest helper hash differs from dispatched source.'}}
    Get-OwnedLabVM -Configuration $configuration -Manifest $manifest | Out-Null
    $record.phase='read-only-query'
    $responses=@(Invoke-BoundedDiscoveryCommand -TimeoutSeconds $QueryTimeoutSeconds -Arguments @($profile.controlRunId,$profile.controlEvidenceSha256,$profile.capturedAllocationSha256,$discoveryId) -ScriptBlock {param($RunId,$ControlSha,$AllocationSha,$DiscoveryId); & 'C:\ntfs2refs\guest\Capture-GuestExtentDiscovery.ps1' -ControlRunId $RunId -ControlEvidenceSha256 $ControlSha -CapturedAllocationSha256 $AllocationSha -DiscoveryId $DiscoveryId -Confirm:$false})
    if($responses.Count -ne 1){throw 'Guest returned an ambiguous discovery response.'}
    $response=$responses[0]; Assert-ExtentDiscoveryResponse $response $discoveryId
    $record.phase='export'
    $export=Export-ExtentDiscoveryArtifacts $response.EvidenceDirectory
    $scriptSha=($sourceHashes|Where-Object name -CEQ 'Capture-GuestExtentDiscovery.ps1').sha256
    $nativeSha=($sourceHashes|Where-Object name -CEQ 'NativeExtentDiscovery.cs').sha256
    Assert-ExtentDiscoveryRecord $export.record $response $profile $control $export.files $scriptSha $nativeSha
    $record.evidenceExported=$true; $record['guestStatus']=$response.Status
    Stop-ExtentDiscoveryGuest
    $record.cleanShutdown=$true
    Remove-PSSession -Session $session -ErrorAction SilentlyContinue; $session=$null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-ExtentDiscoveryVM $vm $profile.checkpointId 8GB
    Assert-ExtentDiscoveryCheckpoint (Get-ExactLabCheckpoint -VM $vm -Name installed-clean) $profile -Baseline
    $record.phase='restore-baseline'
    Invoke-LabAction -Action Restore -Lane win11 -CheckpointName installed-clean -Confirm:$false | Out-Null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    if($vm.State -ne 'Off' -or [string]$vm.ParentSnapshotId -ine $profile.baselineId){throw 'Baseline restore did not return the exact off-state branch.'}
    if($vm.MemoryStartup -ne 4GB -or $vm.DynamicMemoryEnabled){Set-VMMemory -VM $vm -StartupBytes 4GB -DynamicMemoryEnabled $false}
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-ExtentDiscoveryVM $vm $profile.baselineId 4GB
    $record.baselineRestored=$true; $record.memoryRestored=$true; $record.status='native-extent-discovery-exported'; $record.phase='complete'
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
[pscustomobject]@{Status=$record.status;GuestStatus=$record.guestStatus;Evidence=$outputRoot;BaselineRestored=$record.baselineRestored;MemoryRestored=$record.memoryRestored;MoveAttempted=$false;PhysicalMappingVerified=$false;ConversionQualified=$false}
