<# Narrow recovery for the recorded checkpoint-enumeration failure after the
   successful native NTFS first boot. No installation, guest writes, or starts. #>
[CmdletBinding(SupportsShouldProcess)]
param([ValidateSet('win11')][string]$Lane = 'win11')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
$configuration = Get-LabConfiguration -WorkspaceRoot $workspace
$laneRoot = Assert-LabPath (Join-Path $configuration.Root $Lane) $configuration.Root
function Assert-BaselineCompletionEvidence($State, $Evidence, $Manifest, $Checkpoint) {
    if ($State.schemaVersion -ne 1 -or $State.stage -cne 'failed' -or [string]$State.vmId -cne [string]$Manifest.vmId) { throw 'Only a recorded baseline failure for this VM can be completed here.' }
    $initialFailure = $State.detail -ceq 'The exact checkpoint name must identify one checkpoint.' -and $State.updatedUtc -ceq '2026-10-23T20:34:47.4423693Z'
    $postExportFailure = $false
    if ($State.updatedUtc -ceq '2026-10-23T20:40:22.8089573Z') {
        $os = @($Manifest.disks | Where-Object role -ceq 'os')
        if ($os.Count -ne 1) { throw 'Manifest must identify exactly one original OS disk.' }
        $stalePath = Join-Path (Split-Path $os[0].path -Parent) 'os_7D4A0C97-1E6D-4D37-9EED-2C5E2122028A.avhdx'
        $postExportFailure = $State.detail -ceq ("'" + $stalePath + "' is not an existing virtual hard disk file.")
    }
    $inventoryArrayFailure = $State.updatedUtc -ceq '2026-10-23T20:46:21.4557512Z' -and $State.detail -ceq 'Existing export inventory or configuration identity changed.'
    if (-not ($initialFailure -or $postExportFailure -or $inventoryArrayFailure)) { throw 'Failure is outside the three recorded baseline recovery cases.' }
    if ($Checkpoint.Name -cne 'installed-clean' -or [string]$Checkpoint.Id -ine 'eda059b3-6d50-46bb-bdf4-018b99b5b34f') { throw 'The exact recorded installed-clean checkpoint is required.' }
    if ($Evidence.schemaVersion -ne 1 -or $Evidence.phase -cne 'native-ntfs-first-boot' -or $Evidence.computerName -cne 'N2R-WIN11' -or $Evidence.PSComputerName -cne $Manifest.vmName -or $Evidence.windowsBuild -cne '26300.9457' -or $Evidence.edition -cne 'Professional' -or $Evidence.osFileSystem -cne 'NTFS') { throw 'Native evidence does not match this VM and pinned NTFS control.' }
    if (-not $Evidence.nativeNtfsControlPassed -or @($Evidence.failures).Count -ne 0 -or $Evidence.bitLockerVolumeStatus -cne 'FullyDecrypted' -or $Evidence.encryptionPercentage -ne 0 -or -not $Evidence.hibernationDisabled -or $Evidence.filesystemHealth -cne 'NoErrorsFound' -or -not $Evidence.winreEnabled -or $Evidence.refsBootVerified -or $Evidence.dataDisksModified) { throw 'The native NTFS control has unresolved or unexpected findings.' }
    if ($Evidence.capturedUtc -cne '2026-10-23T20:34:33.1676748Z') { throw 'Only the native evidence from the recorded successful first boot is accepted.' }
    $os = @($Evidence.disks | Where-Object { $_.IsBoot -and $_.IsSystem -and $_.PartitionStyle -ceq 'GPT' -and $_.Size -eq 64GB })
    $data = @($Evidence.disks | Where-Object { -not $_.IsBoot -and -not $_.IsSystem -and $_.PartitionStyle -ceq 'RAW' -and -not $_.IsOffline -and -not $_.IsReadOnly })
    if (@($Evidence.disks).Count -ne 3 -or $os.Count -ne 1 -or $data.Count -ne 2 -or @($data | Where-Object Size -eq 64GB).Count -ne 1 -or @($data | Where-Object Size -eq 8GB).Count -ne 1) { throw 'Evidence must retain the original OS and both untouched data disks.' }
}
function Assert-RecordedBaselineExport($Completion, $State, $Manifest, [string]$Destination, [string]$EvidenceHash) {
    if ($Completion.schemaVersion -ne 1 -or [string]$Completion.vmId -cne [string]$Manifest.vmId -or $Completion.checkpointId -ine 'eda059b3-6d50-46bb-bdf4-018b99b5b34f' -or $Completion.status -cne 'failed' -or -not $Completion.exported -or $Completion.restoreVerified -or $Completion.exportPath -ine $Destination -or $Completion.error -cne $State.detail -or $Completion.startedUtc -cne '2026-10-23T20:40:18.5211797Z') { throw 'Existing export is not backed by the exact recorded post-export failure.' }
    if ($EvidenceHash -cne '2c7fc107bd63e918228671e3b57cf87891552c93023bda7e13faee2d471b1c12' -or $Completion.evidenceSha256 -cne $EvidenceHash) { throw 'Native evidence hash differs from the successfully exported baseline record.' }
}
function Assert-RecordedInventoryFailure($Completion, $State, $Manifest, [string]$Destination, [string]$EvidenceHash) {
    if ($State.updatedUtc -cne '2026-10-23T20:46:21.4557512Z' -or $State.detail -cne 'Existing export inventory or configuration identity changed.' -or $Completion.schemaVersion -ne 1 -or [string]$Completion.vmId -cne [string]$Manifest.vmId -or $Completion.checkpointId -ine 'eda059b3-6d50-46bb-bdf4-018b99b5b34f' -or $Completion.status -cne 'failed' -or -not $Completion.reusedExport -or $Completion.exported -or $Completion.restoreVerified -or $Completion.exportPath -ine $Destination -or $Completion.error -cne $State.detail -or $Completion.startedUtc -cne '2026-10-23T20:46:21.4394716Z' -or $Completion.evidenceSha256 -cne $EvidenceHash -or $EvidenceHash -cne '2c7fc107bd63e918228671e3b57cf87891552c93023bda7e13faee2d471b1c12') { throw 'Inventory retry is not backed by the exact recorded parsing failure and native evidence.' }
}
if (-not $PSCmdlet.ShouldProcess($laneRoot, 'Complete the recorded NTFS baseline: archive failure, export exact installed-clean, restore it, mark first boot complete')) {
    [pscustomobject]@{ Action = 'CompleteLabBaseline'; Lane = $Lane; DryRun = $true; Checkpoint = 'installed-clean'; GuestStarted = $false; Requires = 'One of three exact recorded failures, passed native evidence, owned VM off; existing export accepted only with matching archived evidence' }
    return
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Baseline completion requires the reviewed elevated Hyper-V helper.' }
$manifest = Read-LabManifest -Configuration $configuration -Lane $Lane
if (-not $manifest) { throw 'Missing lab ownership manifest.' }
$vm = Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
if ($vm.State -ne 'Off') { throw 'Baseline completion requires the owned VM off.' }
if (@(Get-VMNetworkAdapter -VM $vm | Where-Object SwitchName).Count) { throw 'The lab NIC must remain disconnected.' }
$firstBootRoot = Assert-LabPath (Join-Path $laneRoot 'firstboot') $configuration.Root
$statePath = Join-Path $firstBootRoot 'state.json'
$evidencePath = Join-Path $firstBootRoot 'native-ntfs-evidence.json'
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$evidence = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json
$checkpoint = Get-ExactLabCheckpoint -VM $vm -Name 'installed-clean'
Assert-BaselineCompletionEvidence $state $evidence $manifest $checkpoint
$destination = Assert-LabPath (Join-Path $configuration.Root "exports\$Lane-installed-clean") $configuration.Root
$reuseExport = $state.updatedUtc -cin @('2026-10-23T20:40:22.8089573Z','2026-10-23T20:46:21.4557512Z')
$evidenceHash = (Get-FileHash -LiteralPath $evidencePath -Algorithm SHA256).Hash.ToLowerInvariant()
$previousArchive = $null; $previousInventory = $null; $inventoryFailureArchive = $null
if ($reuseExport) {
    if (-not (Test-Path -LiteralPath $destination -PathType Container)) { throw 'The previously completed export is missing; it will not be recreated silently.' }
    $previousArchive = Assert-LabPath (Join-Path $firstBootRoot 'baseline-completion-20261023T204018513Z') $configuration.Root
    $previousCompletion = Get-Content -LiteralPath (Join-Path $previousArchive 'completion.json') -Raw | ConvertFrom-Json
    $exportFailureState = $state
    if ($state.updatedUtc -ceq '2026-10-23T20:46:21.4557512Z') {
        $inventoryFailureArchive = Assert-LabPath (Join-Path $firstBootRoot 'baseline-completion-20261023T204621434Z') $configuration.Root
        $inventoryCompletion = Get-Content -LiteralPath (Join-Path $inventoryFailureArchive 'completion.json') -Raw | ConvertFrom-Json
        Assert-RecordedInventoryFailure $inventoryCompletion $state $manifest $destination $evidenceHash
        $exportFailureState = Get-Content -LiteralPath (Join-Path $inventoryFailureArchive 'failed-state.json') -Raw | ConvertFrom-Json
        Assert-BaselineCompletionEvidence $exportFailureState $evidence $manifest $checkpoint
        if ((Get-FileHash -LiteralPath (Join-Path $inventoryFailureArchive 'native-ntfs-evidence.json') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $evidenceHash) { throw 'Inventory-failure archive has different native evidence.' }
    }
    Assert-RecordedBaselineExport $previousCompletion $exportFailureState $manifest $destination $evidenceHash
    if ((Get-FileHash -LiteralPath (Join-Path $previousArchive 'native-ntfs-evidence.json') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $evidenceHash) { throw 'Archived native evidence does not match the completed export.' }
    $originalFailure = Get-Content -LiteralPath (Join-Path $previousArchive 'failed-state.json') -Raw | ConvertFrom-Json
    Assert-BaselineCompletionEvidence $originalFailure $evidence $manifest $checkpoint
    # Windows PowerShell 5 emits a JSON array as one pipeline object. Assign
    # the parsed result first so @() enumerates its elements, not that wrapper.
    $parsedInventory = Get-Content -LiteralPath (Join-Path $previousArchive 'exported-files.json') -Raw | ConvertFrom-Json
    $previousInventory = @($parsedInventory)
} elseif (Test-Path -LiteralPath $destination) { throw 'Export destination already exists; no overwrite or adoption is allowed.' }
Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 1MB
$archive = Assert-LabPath (Join-Path $firstBootRoot ('baseline-completion-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $configuration.Root
New-Item -ItemType Directory -Path $archive | Out-Null
Copy-Item -LiteralPath $statePath -Destination (Join-Path $archive 'failed-state.json')
Copy-Item -LiteralPath $evidencePath -Destination (Join-Path $archive 'native-ntfs-evidence.json')
if ($previousArchive) {
    Copy-Item -LiteralPath (Join-Path $previousArchive 'completion.json') -Destination (Join-Path $archive 'previous-completion.json')
    Copy-Item -LiteralPath (Join-Path $previousArchive 'exported-files.json') -Destination (Join-Path $archive 'previous-exported-files.json')
}
if ($inventoryFailureArchive) {
    Copy-Item -LiteralPath (Join-Path $inventoryFailureArchive 'completion.json') -Destination (Join-Path $archive 'inventory-failure-completion.json')
    Copy-Item -LiteralPath (Join-Path $inventoryFailureArchive 'failed-state.json') -Destination (Join-Path $archive 'inventory-failure-previous-state.json')
}
$completion = [ordered]@{ schemaVersion = 1; vmId = $manifest.vmId; checkpointId = [string]$checkpoint.Id; status = 'starting'; exportPath = $destination; reusedExport = $reuseExport; exported = $false; restoreVerified = $false; evidenceSha256 = $evidenceHash; startedUtc = [DateTime]::UtcNow.ToString('o'); error = $null }
function Write-BaselineState([string]$Stage, [string]$Detail) {
    [pscustomobject]@{ schemaVersion = 1; stage = $Stage; detail = $Detail; vmId = $manifest.vmId; updatedUtc = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
}
try {
    if ($reuseExport) { Write-BaselineState 'verifying-existing-baseline-export' 'The recorded completed export is preserved and will be verified before restore.' }
    else {
        Write-BaselineState 'exporting-baseline' 'Completing the recorded enumeration failure; native NTFS evidence already passed.'
        Invoke-LabAction -Action ExportBaseline -Lane $Lane -CheckpointName 'installed-clean' -Confirm:$false | Out-Null
    }
    $items = @(Get-ChildItem -LiteralPath $destination -Recurse -Force)
    if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Export contains an unexpected reparse point.' }
    $files = @($items | Where-Object { -not $_.PSIsContainer })
    $configs = @($files | Where-Object { $_.Extension -ieq '.vmcx' -and $_.Length -gt 0 })
    $disks = @($files | Where-Object { $_.Extension -in @('.vhdx','.avhdx') -and $_.Length -gt 0 })
    if ($configs.Count -ne 1 -or $disks.Count -lt @($manifest.disks).Count) { throw 'Export did not contain one VM configuration and all three disk images.' }
    if ($reuseExport) {
        if ($files.Count -ne $previousInventory.Count -or @($previousInventory.relativePath | Sort-Object -Unique).Count -ne $previousInventory.Count -or $configs[0].BaseName -ine [string]$checkpoint.Id) { throw 'Existing export inventory or configuration identity changed.' }
        foreach ($item in $previousInventory) {
            $expectedPath = Assert-LabPath (Join-Path $destination $item.relativePath) $destination
            $found = @($files | Where-Object FullName -IEQ $expectedPath)
            if ($found.Count -ne 1 -or $found[0].Length -ne $item.length) { throw 'Existing export differs from its archived file inventory.' }
        }
        foreach ($spec in $manifest.disks) {
            $exportedDisk = @($disks | Where-Object Name -IEQ ($spec.role + '.vhdx'))
            if ($exportedDisk.Count -ne 1) { throw 'Exported disks cannot be mapped unambiguously to the manifest.' }
            $exportedVhd = Get-VHD -Path $exportedDisk[0].FullName -ErrorAction Stop
            if ($exportedVhd.ParentPath -or $exportedVhd.Size -ne $spec.sizeBytes -or [string]$exportedVhd.DiskIdentifier -ine [string]$spec.vhdId) { throw 'Existing exported VHD identity, size, or independence differs from the manifest.' }
        }
        $files | ForEach-Object { [pscustomobject]@{ relativePath = $_.FullName.Substring($destination.Length).TrimStart('\'); length = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() } } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $archive 'verified-export-hashes.json') -Encoding UTF8
    }
    $files | ForEach-Object { [pscustomobject]@{ relativePath = $_.FullName.Substring($destination.Length).TrimStart('\'); length = $_.Length } } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $archive 'exported-files.json') -Encoding UTF8
    $completion.exported = $true
    $currentVm = Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    if ($currentVm.State -ne 'Off') { throw 'VM unexpectedly started before baseline restore.' }
    $currentCheckpoint = Get-ExactLabCheckpoint -VM $currentVm -Name 'installed-clean'
    if ([string]$currentCheckpoint.Id -cne [string]$checkpoint.Id) { throw 'Checkpoint identity changed after export.' }
    Write-BaselineState 'verifying-baseline-restore' 'Independent baseline export completed; restoring the same exact checkpoint.'
    Invoke-LabAction -Action Restore -Lane $Lane -CheckpointName 'installed-clean' -Confirm:$false | Out-Null
    $restoredVm = Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    if ($restoredVm.State -ne 'Off') { throw 'Baseline restore did not leave the owned VM off.' }
    $restoredCheckpoint = Get-ExactLabCheckpoint -VM $restoredVm -Name 'installed-clean'
    if ([string]$restoredCheckpoint.Id -cne [string]$checkpoint.Id) { throw 'The recorded checkpoint was not retained after restore.' }
    $completion.restoreVerified = $true
    $completion.status = 'complete'
    Write-BaselineState 'complete' 'Native NTFS boot verified; exact installed-clean checkpoint exported independently and restore exercised. ReFS tests remain separate.'
} catch {
    $completion.status = 'failed'; $completion.error = $_.Exception.Message
    Write-BaselineState 'failed' $_.Exception.Message
    throw
} finally {
    $completion | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $archive 'completion.json') -Encoding UTF8
}
[pscustomobject]@{ Status = 'Complete'; VMState = 'Off'; Baseline = 'installed-clean'; ExportPath = $destination; RestoreVerified = $true; ReFSBootVerified = $false }
