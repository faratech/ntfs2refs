<# Bounded native Dev Drive data control; all filesystem writes happen in the owned guest. #>
[CmdletBinding(SupportsShouldProcess)]
param([ValidateRange(60,900)][int]$BootTimeoutSeconds=300)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
$configuration=Get-LabConfiguration -WorkspaceRoot $workspace
if (-not $PSCmdlet.ShouldProcess('ntfs2refs-win11','Temporarily use 8 GiB RAM; format only the blank target as a 52 GiB Dev Drive; verify across clean reboot; export/checkpoint; restore baseline and 4 GiB RAM')) {
    [pscustomobject]@{ Action='NativeDevDriveDataControl'; DryRun=$true; MemoryBytes=8GB; PartitionBytes=52GB; HostNativeDiskWrites=$false; OrdinaryReFS=$false; ReFSBootVerified=$false; FullRawCapture=$false }; return
}

function Assert-DevDriveStartState($VM,$Baseline) {
    if ($VM.State -ne 'Off' -or $VM.MemoryStartup -ne 4GB -or $VM.DynamicMemoryEnabled -or [string]$VM.ParentSnapshotId -ine [string]$Baseline.Id -or [string]$Baseline.Id -ine 'eda059b3-6d50-46bb-bdf4-018b99b5b34f') { throw 'Dev Drive control requires the off-state installed-clean branch with original fixed 4 GiB RAM.' }
}
function Assert-DevDriveResult($Result,[string]$ExpectedPhase,[string]$ExpectedRunId) {
    $allowed=if ($ExpectedPhase -ceq 'Prepare') { @('prepared','blocked') } else { @('verified','blocked') }
    $file=if ($ExpectedPhase -ceq 'Prepare') { 'prepare.json' } else { 'verify.json' }
    if ($Result.phase -cne $ExpectedPhase -or $Result.runId -cne $ExpectedRunId -or $Result.status -cnotin $allowed -or $Result.resultFile -cne $file -or $Result.evidenceDirectory -cne 'C:\ntfs2refs\devdrive-control' -or $Result.refsBootVerified -or $Result.conversionQualified) { throw 'Unexpected guest Dev Drive result.' }
}
function Assert-DevDriveArtifact($File) {
    if ($File.name -cnotin @('target.json','prepare.json','verify.json','allocation-before.json','allocation-after.json') -or $File.length -lt 0 -or $File.length -gt 16MB -or $File.sha256 -cnotmatch '^[0-9a-f]{64}$' -or ([IO.FileAttributes]$File.attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected or oversized Dev Drive artifact.' }
}
function Assert-DevDriveGuestRecord($Guest,[string]$ExpectedPhase,[string]$ExpectedRunId,[string]$ExpectedVhdId) {
    if ($Guest.schemaVersion -ne 1 -or $Guest.kind -cne 'devdrive-data-control' -or $Guest.phase -cne $ExpectedPhase -or $Guest.runId -cne $ExpectedRunId -or $Guest.ordinaryReFS -or $Guest.rawCaptureComplete -or $Guest.refsBootVerified -or $Guest.conversionQualified) { throw 'Exported Dev Drive record is inconsistent.' }
    if ($Guest.status -in @('prepared','verified')) {
        if (-not $Guest.restoreAllowed -or -not $Guest.formatSucceeded -or $Guest.target.host.vhdId -cne $ExpectedVhdId -or $Guest.target.guest.role -cne 'target' -or $Guest.target.guest.sizeBytes -ne 64GB -or $Guest.partition.length -ne 52GB -or $Guest.partition.logicalSectorSize -ne 512 -or $Guest.partition.physicalSectorSize -ne 4096) { throw 'Successful record lacks the exact native target profile.' }
        foreach ($field in @('guid','diskGuid')) { $g=[guid]::Empty; if (-not [guid]::TryParse([string]$Guest.partition.$field,[ref]$g) -or $g -eq [guid]::Empty) { throw 'Missing native GPT identity.' } }
        if ($Guest.sourceOs.fileSystem -cne 'NTFS' -or $Guest.sourceOs.build -cne '10.0.26300.9457' -or $Guest.sourceOs.installedMemoryBytes -lt 8GB) { throw 'Source OS or experiment memory is inconsistent.' }
    }
    if ($Guest.status -ceq 'verified' -and (-not $Guest.remountVerified -or $Guest.before.bootTime -ceq $Guest.after.bootTime)) { throw 'Verification lacks distinct guest boots.' }
}
function Open-DevDriveSession {
    $deadline=[DateTime]::UtcNow.AddSeconds($BootTimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $probe=$null
        try {
            $probe=Invoke-Command -VMId ([guid]$manifest.vmId) -Credential $credential -AsJob -ScriptBlock { $env:COMPUTERNAME }
            if (Wait-Job -Job $probe -Timeout 10) { $reply=@(Receive-Job -Job $probe -ErrorAction Stop); if ($reply.Count -eq 1 -and $reply[0] -ceq 'N2R-WIN11') { return New-PSSession -VMId ([guid]$manifest.vmId) -Credential $credential -ErrorAction Stop } }
        } catch { } finally { if ($probe) { Remove-Job -Job $probe -Force -ErrorAction SilentlyContinue } }
        Start-Sleep -Seconds 2
    }
    throw 'PowerShell Direct did not become available before the deadline.'
}
function Stop-DevDriveGuest {
    if ((Get-VM -Id ([guid]$manifest.vmId)).State -eq 'Off') { return }
    if (-not $session) { throw 'No authenticated session is available for clean shutdown.' }
    Invoke-Command -Session $session -ScriptBlock { & shutdown.exe /s /t 0; if ($LASTEXITCODE -ne 0) { throw 'Guest shutdown request failed.' } }
    $deadline=[DateTime]::UtcNow.AddMinutes(3)
    do { if ((Get-VM -Id ([guid]$manifest.vmId)).State -eq 'Off') { return }; Start-Sleep -Seconds 2 } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Guest did not shut down cleanly; preserve the branch.'
}
function Export-DevDriveArtifacts([string]$Stage,[string]$ResultFile) {
    if ($Stage -cnotin @('before','after') -or $ResultFile -cnotin @('prepare.json','verify.json')) { throw 'Invalid export stage.' }
    $destination=Assert-LabPath (Join-Path $outputRoot $Stage) $configuration.Root
    if (Test-Path -LiteralPath $destination) { throw 'Export destination already exists; no overwrite is allowed.' }
    $files=@(Invoke-Command -Session $session -ScriptBlock {
        $root=Get-Item -LiteralPath 'C:\ntfs2refs\devdrive-control' -Force
        if (-not $root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected guest evidence root.' }
        foreach ($file in @(Get-ChildItem -LiteralPath $root.FullName -Force)) {
            if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 16MB -or $file.Name -cnotin @('target.json','prepare.json','verify.json','allocation-before.json','allocation-after.json')) { throw 'Unexpected guest artifact; preserve state.' }
            [pscustomobject]@{ name=$file.Name; length=$file.Length; attributes=[string]$file.Attributes; sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
        }
    })
    if ($files.Count -lt 1 -or $files.Count -gt 5 -or @($files | Where-Object name -ceq $ResultFile).Count -ne 1 -or ($files | Measure-Object length -Sum).Sum -gt 32MB) { throw 'Missing or oversized native evidence.' }
    New-Item -ItemType Directory -Path $destination | Out-Null
    foreach ($file in $files) {
        Assert-DevDriveArtifact $file
        $local=Assert-LabPath (Join-Path $destination $file.name) $configuration.Root
        if (Test-Path -LiteralPath $local) { throw 'Evidence export cannot overwrite an existing file.' }
        Copy-Item -LiteralPath ('C:\ntfs2refs\devdrive-control\' + $file.name) -Destination $local -FromSession $session
        $copied=Get-Item -LiteralPath $local
        if ($copied.PSIsContainer -or $copied.Length -ne $file.length -or (Get-FileHash -LiteralPath $local -Algorithm SHA256).Hash.ToLowerInvariant() -cne $file.sha256) { throw 'Native evidence export failed length/hash verification.' }
    }
    $files | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $destination 'exported-files.json') -Encoding UTF8
    [pscustomobject]@{ path=$destination; result=(Get-Content -LiteralPath (Join-Path $destination $ResultFile) -Raw | ConvertFrom-Json); files=$files }
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated Hyper-V access is required.' }
$manifest=Read-LabManifest -Configuration $configuration -Lane win11
if (-not $manifest) { throw 'Missing lab ownership manifest.' }
$vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
$baseline=Get-ExactLabCheckpoint -VM $vm -Name installed-clean
Assert-DevDriveStartState $vm $baseline
if (@(Get-VMNetworkAdapter -VM $vm | Where-Object SwitchName).Count -or (Get-VMFirmware -VM $vm).SecureBoot -ne 'On') { throw 'The disconnected network and Secure Boot must remain unchanged.' }
$target=@($manifest.disks | Where-Object role -CEQ 'target')
if ($target.Count -ne 1 -or $target[0].sizeBytes -ne 64GB -or $target[0].controllerLocation -ne 1) { throw 'Expected the original 64 GiB target at SCSI slot 1.' }
$laneRoot=Assert-LabPath (Join-Path $configuration.Root 'win11') $configuration.Root
$firstBoot=Get-Content -LiteralPath (Join-Path $laneRoot 'firstboot\state.json') -Raw | ConvertFrom-Json
if ($firstBoot.stage -cne 'complete' -or [string]$firstBoot.vmId -cne [string]$manifest.vmId) { throw 'The native NTFS baseline must be qualified.' }
$credential=Import-Clixml -LiteralPath (Join-Path $laneRoot 'secrets\guest-credential.xml')
if ($credential -isnot [Management.Automation.PSCredential] -or $credential.UserName -cne 'N2R-WIN11\LabAdmin') { throw 'Unexpected guest credential identity.' }
Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 68GB
$runId=[guid]::NewGuid().ToString('N')
$stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$outputRoot=Assert-LabPath (Join-Path $configuration.Root ('devdrive\win11-' + $stamp)) $configuration.Root
New-Item -ItemType Directory -Path $outputRoot | Out-Null
$checkpointName='devdrive-data-' + $stamp
$record=[ordered]@{ schemaVersion=1; kind='devdrive-data-control'; runId=$runId; vmId=[string]$manifest.vmId; baselineId=[string]$baseline.Id; status='started'; phase='preflight'; originalMemoryBytes=4GB; experimentMemoryBytes=8GB; memoryRestored=$false; beforeExported=$false; afterExported=$false; cleanReboot=$false; baselineRestored=$false; checkpointName=$null; checkpointId=$null; remountVerified=$false; ordinaryReFS=$false; rawCaptureComplete=$false; refsBootVerified=$false; conversionQualified=$false; createdUtc=[DateTime]::UtcNow.ToString('o') }
$record['sourceHashes']=@(foreach ($relative in @('scripts\Invoke-LabDevDriveControl.ps1','lab\guest\Invoke-GuestDevDriveControl.ps1','lab\guest\Capture-GuestAllocation.ps1','lab\guest\Register-GuestDisk.ps1','lab\guest\GuestLab.psm1','lab\Lab.psm1')) { [pscustomobject]@{ path=$relative; sha256=(Get-FileHash -LiteralPath (Join-Path $workspace $relative) -Algorithm SHA256).Hash.ToLowerInvariant() } })
$session=$null; $formatIndeterminate=$false
try {
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    Assert-DevDriveStartState $vm $baseline
    Set-VMMemory -VM $vm -StartupBytes 8GB -DynamicMemoryEnabled $false
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    if ($vm.State -ne 'Off' -or $vm.MemoryStartup -ne 8GB -or $vm.DynamicMemoryEnabled) { throw 'Experiment memory change was not verified.' }
    foreach ($phase in @('Prepare','Verify')) {
        $record.phase=$phase
        $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $outputRoot 'host-result.json') -Encoding UTF8
        Invoke-LabAction -Action Start -Lane win11 -Confirm:$false | Out-Null
        $session=Open-DevDriveSession
        $policy=Initialize-LabGuestSession -Session $session
        $policy | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $outputRoot ('session-' + $phase.ToLowerInvariant() + '.json')) -Encoding UTF8
        if ($policy.status -cne 'ready') { throw ('Guest session refused: ' + $policy.error) }
        if ($phase -ceq 'Prepare') {
            foreach ($name in @('GuestLab.psm1','Register-GuestDisk.ps1','Invoke-GuestDevDriveControl.ps1','Capture-GuestAllocation.ps1')) { Copy-Item -LiteralPath (Join-Path $workspace ('lab\guest\' + $name)) -Destination ('C:\ntfs2refs\guest\' + $name) -ToSession $session -Force }
        }
        Get-OwnedLabVM -Configuration $configuration -Manifest $manifest | Out-Null
        $targetJson=$target[0] | Select-Object role,sizeBytes,controllerLocation,vhdId | ConvertTo-Json -Compress
        # A transport failure while formatting must preserve the running guest;
        # only its completed response can clear the indeterminate-operation flag.
        $formatIndeterminate=($phase -ceq 'Prepare')
        $phaseJob=$null
        try {
            $phaseJob=Invoke-Command -Session $session -AsJob -ArgumentList $phase,$targetJson,$runId -ScriptBlock { param($Phase,$TargetJson,$RunId); & 'C:\ntfs2refs\guest\Invoke-GuestDevDriveControl.ps1' -Phase $Phase -HostTargetJson $TargetJson -RunId $RunId -Confirm:$false }
            if (-not (Wait-Job -Job $phaseJob -Timeout 600)) { $formatIndeterminate=$true; throw 'Guest phase exceeded 600 seconds; preserve the running guest and incomplete evidence.' }
            $responses=@(Receive-Job -Job $phaseJob -ErrorAction Stop)
            if ($responses.Count -ne 1) { throw 'Guest phase returned an ambiguous result.' }
            $remote=$responses[0]
        } finally { if ($phaseJob -and $phaseJob.State -in @('Completed','Failed','Stopped')) { Remove-Job -Job $phaseJob -Force } }
        Assert-DevDriveResult $remote $phase $runId
        $formatIndeterminate=-not $remote.restoreAllowed
        $export=Export-DevDriveArtifacts $(if ($phase -ceq 'Prepare') { 'before' } else { 'after' }) $remote.resultFile
        Assert-DevDriveGuestRecord $export.result $phase $runId ([string]$target[0].vhdId)
        if ($export.result.status -cne $remote.status -or $export.result.restoreAllowed -ne $remote.restoreAllowed) { throw 'Guest response and exported record disagree.' }
        if ($phase -ceq 'Prepare') { $record.beforeExported=$true } else {
            $record.afterExported=$true
            $beforePath=Join-Path $outputRoot 'before\prepare.json'; $afterBefore=Join-Path $export.path 'prepare.json'
            if ((Get-FileHash -LiteralPath $beforePath -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath $afterBefore -Algorithm SHA256).Hash) { throw 'Preparation evidence changed across reboot.' }
        }
        if ($formatIndeterminate) { throw 'Native format outcome is indeterminate; do not shut down, checkpoint or restore.' }
        Stop-DevDriveGuest
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue; $session=$null
        Get-OwnedLabVM -Configuration $configuration -Manifest $manifest | Out-Null
        if ($remote.status -ceq 'blocked') { $record.status='native-devdrive-blocked'; break }
        if ($phase -ceq 'Prepare') { $record.cleanReboot=$true } else { $record.remountVerified=$true; $record.status='native-devdrive-remount-verified' }
    }
    if ($record.remountVerified) {
        if (-not $record.beforeExported -or -not $record.afterExported -or -not $record.cleanReboot) { throw 'Successful checkpoint lacks complete exported remount evidence.' }
        Invoke-LabAction -Action Checkpoint -Lane win11 -CheckpointName $checkpointName -Confirm:$false | Out-Null
        $saved=Get-ExactLabCheckpoint -VM (Get-OwnedLabVM -Configuration $configuration -Manifest $manifest) -Name $checkpointName
        $record.checkpointName=$checkpointName; $record.checkpointId=[string]$saved.Id
    }
    $restorePoint=Get-ExactLabCheckpoint -VM (Get-OwnedLabVM -Configuration $configuration -Manifest $manifest) -Name installed-clean
    if ([string]$restorePoint.Id -ine [string]$baseline.Id) { throw 'The installed-clean checkpoint identity changed during the experiment.' }
    Invoke-LabAction -Action Restore -Lane win11 -CheckpointName installed-clean -Confirm:$false | Out-Null
    $record.baselineRestored=$true
} catch {
    $record.status='failed'; $record['error']=$_.Exception.Message; $record['errorPosition']=$_.InvocationInfo.PositionMessage; $record['scriptStackTrace']=$_.ScriptStackTrace
    if (-not $formatIndeterminate) { try { Stop-DevDriveGuest } catch { $record['shutdownError']=$_.Exception.Message } }
    # Preserve the guest branch on incomplete transport/export; never force off.
    throw
} finally {
    try {
        $current=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
        if ($current.State -eq 'Off') {
            if ($current.MemoryStartup -ne 4GB -or $current.DynamicMemoryEnabled) { Set-VMMemory -VM $current -StartupBytes 4GB -DynamicMemoryEnabled $false }
            $current=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
            $record.memoryRestored=($current.State -eq 'Off' -and $current.MemoryStartup -eq 4GB -and -not $current.DynamicMemoryEnabled)
        }
    } catch { $record['memoryRestoreError']=$_.Exception.Message; $record.status='failed' }
    $record['finishedUtc']=[DateTime]::UtcNow.ToString('o')
    $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $outputRoot 'host-result.json') -Encoding UTF8
    if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    $credential=$null
}
if (-not $record.memoryRestored) { throw 'The experiment ended without verified restoration of the original 4 GiB memory configuration; inspect host-result.json.' }
[pscustomobject]@{ Status=$record.status; Evidence=$outputRoot; BaselineRestored=$record.baselineRestored; MemoryRestored=$record.memoryRestored; CheckpointName=$record.checkpointName; CheckpointId=$record.checkpointId; RemountVerified=$record.remountVerified; ReFSBootVerified=$false; ConversionQualified=$false }
