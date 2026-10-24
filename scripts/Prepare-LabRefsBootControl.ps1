<# Prepare a native ReFS OS control inside the owned guest only.
   Success preserves an off-state preparation checkpoint for separate boot review.
   All completed evidence exports are followed by restoring installed-clean. #>
[CmdletBinding(SupportsShouldProcess)]
param([ValidateSet('win11')][string]$Lane = 'win11', [ValidateRange(60,900)][int]$BootTimeoutSeconds = 300,
    [ValidateSet('FormatVolume','FormatCom')][string]$FormatMethod = 'FormatVolume')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
$configuration = Get-LabConfiguration -WorkspaceRoot $workspace
if (-not $PSCmdlet.ShouldProcess($configuration.Settings.lanes.$Lane.name, 'Prepare ordinary native ReFS OS on the blank guest target; export evidence; leave boot selection for separate review')) {
    [pscustomobject]@{ Action = 'PrepareNativeRefsOS'; Lane = $Lane; FormatMethod = $FormatMethod; DryRun = $true; TargetBytes = 64GB; Baseline = 'installed-clean'; ImageIndex = 6; HostNativeDiskWrites = $false; BootAttempted = $false; FailureDisposition = 'Export evidence, clean shutdown, restore installed-clean'; SuccessDisposition = 'Export evidence, clean shutdown, preparation checkpoint, restore installed-clean' }
    return
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use the reviewed elevated Hyper-V helper.' }
$manifest = Read-LabManifest -Configuration $configuration -Lane $Lane
if (-not $manifest) { throw 'Missing lab ownership manifest.' }
$vm = Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
if ($vm.State -ne 'Off') { throw 'Start preparation with the owned VM off.' }
if (@(Get-VMNetworkAdapter -VM $vm | Where-Object SwitchName).Count) { throw 'The lab network must remain disconnected.' }
if ((Get-VMFirmware -VM $vm).SecureBoot -ne 'On') { throw 'The owned VM must retain Secure Boot.' }
$baseline = @(Get-VMCheckpoint -VM $vm | Where-Object Name -CEQ 'installed-clean')
if ($baseline.Count -ne 1) { throw 'Exactly one installed-clean checkpoint is required.' }
$target = @($manifest.disks | Where-Object role -CEQ 'target')
if ($target.Count -ne 1 -or $target[0].sizeBytes -ne 64GB -or $target[0].controllerLocation -ne 1) { throw 'Manifest must identify the original disposable 64 GiB target at SCSI slot 1.' }
$laneRoot = Assert-LabPath (Join-Path $configuration.Root $Lane) $configuration.Root
$firstBoot = Get-Content -LiteralPath (Join-Path $laneRoot 'firstboot\state.json') -Raw | ConvertFrom-Json
if ($firstBoot.stage -cne 'complete' -or [string]$firstBoot.vmId -cne [string]$manifest.vmId) { throw 'The native NTFS baseline must be qualified first.' }
$dvd = @(Get-VMDvdDrive -VM $vm)
if ($dvd.Count -ne 1 -or $dvd[0].Path -ine [string]$manifest.media.isoPath) { throw 'The only VM DVD must contain the manifest-pinned ISO.' }
$iso = Get-Item -LiteralPath $manifest.media.isoPath
if ($iso.PSIsContainer -or $iso.Length -ne $manifest.media.length -or (Get-FileHash -LiteralPath $iso.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifest.media.sha256) { throw 'The attached ISO no longer matches the pinned media.' }
$credential = Import-Clixml -LiteralPath (Join-Path $laneRoot 'secrets\guest-credential.xml')
if ($credential -isnot [Management.Automation.PSCredential] -or $credential.UserName -cne 'N2R-WIN11\LabAdmin') { throw 'Unexpected guest credential identity.' }
Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 68GB
$runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$outputRoot = Assert-LabPath (Join-Path $configuration.Root ("refs-boot\$Lane-$runId")) $configuration.Root
$checkpointName = 'refs-os-prepared-' + $runId
New-Item -ItemType Directory -Path $outputRoot | Out-Null
$record = [ordered]@{ schemaVersion = 1; phase = 'native-refs-os-preparation'; vmId = $manifest.vmId; baselineId = [string]$baseline[0].Id; mediaSha256 = $manifest.media.sha256; status = 'started'; evidenceExported = $false; baselineRestored = $false; preparationCheckpoint = $null; bootAttempted = $false; refsBootVerified = $false; createdUtc = [DateTime]::UtcNow.ToString('o') }
$record['formatMethod'] = $FormatMethod
$session = $null
function Open-PreparationSession {
    $deadline = [DateTime]::UtcNow.AddSeconds($BootTimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $probe = $null
        try {
            $probe = Invoke-Command -VMId ([guid]$manifest.vmId) -Credential $credential -AsJob -ScriptBlock { $env:COMPUTERNAME }
            if (Wait-Job -Job $probe -Timeout 10) {
                $reply = @(Receive-Job -Job $probe -ErrorAction Stop)
                if ($reply.Count -eq 1 -and $reply[0] -ceq 'N2R-WIN11') { return New-PSSession -VMId ([guid]$manifest.vmId) -Credential $credential -ErrorAction Stop }
            }
        } catch { } finally { if ($probe) { Remove-Job -Job $probe -Force -ErrorAction SilentlyContinue } }
        Start-Sleep -Seconds 2
    }
    throw 'PowerShell Direct did not become available before the deadline.'
}
function Stop-PreparationGuest {
    if ((Get-VM -Id ([guid]$manifest.vmId)).State -eq 'Off') { return }
    if (-not $session) { throw 'No authenticated session is available for clean shutdown.' }
    Invoke-Command -Session $session -ScriptBlock { & shutdown.exe /s /t 0; if ($LASTEXITCODE -ne 0) { throw 'Guest shutdown request failed.' } }
    $deadline = [DateTime]::UtcNow.AddMinutes(3)
    do { if ((Get-VM -Id ([guid]$manifest.vmId)).State -eq 'Off') { return }; Start-Sleep -Seconds 2 } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Guest did not shut down cleanly; no checkpoint or restore was attempted.'
}
try {
    Invoke-LabAction -Action Start -Lane $Lane -Confirm:$false | Out-Null
    $session = Open-PreparationSession
    $sessionPolicy = Initialize-LabGuestSession -Session $session
    $sessionPolicy | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $outputRoot 'guest-session-policy.json') -Encoding UTF8
    if ($sessionPolicy.status -cne 'ready') { throw ('Guest script session refused: ' + $sessionPolicy.error) }
    foreach ($name in @('GuestLab.psm1','Register-GuestDisk.ps1','Prepare-NativeRefsOS.ps1')) {
        Copy-Item -LiteralPath (Join-Path $workspace ('lab\guest\' + $name)) -Destination ('C:\ntfs2refs\guest\' + $name) -ToSession $session -Force
    }
    # Revalidate ownership and media immediately before asking the guest to write.
    $currentVm = Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    $currentDvd = @(Get-VMDvdDrive -VM $currentVm)
    if ($currentDvd.Count -ne 1 -or $currentDvd[0].Path -ine $iso.FullName) { throw 'DVD attachment changed.' }
    $targetJson = $target[0] | Select-Object role,sizeBytes,controllerLocation,vhdId | ConvertTo-Json -Compress
    $remote = Invoke-Command -Session $session -ArgumentList $targetJson,$credential,$FormatMethod -ScriptBlock {
        param($TargetJson, $GuestCredential, $GuestFormatMethod)
        & 'C:\ntfs2refs\guest\Prepare-NativeRefsOS.ps1' -HostTargetJson $TargetJson -FirstBootCredential $GuestCredential -FormatMethod $GuestFormatMethod -Confirm:$false
    }
    if ($remote.evidenceDirectory -cne 'C:\ntfs2refs\refs-os-preparation' -or $remote.status -notin @('prepared','blocked')) { throw 'Guest returned an unexpected preparation result.' }
    $allowed = @('target.json','result.json','refs-info.log','refs-info.log.command.json','dism-apply.log','dism-apply.log.command.json','dism-detail.log','dism-detail.log.bak','bcdboot.log','bcdboot.log.command.json','bcd-store.log','bcd-store.log.command.json','reagentc.log','reagentc.log.command.json','recovery-attributes.txt','recovery-attributes.log','recovery-attributes.log.command.json','recovery-partition.json')
    $allowed += @('format-help.log','format-help.log.command.json','format-filesystems.txt','format-filesystems.log','format-filesystems.log.command.json','format-com.log','format-com.log.command.json')
    $files = @(Invoke-Command -Session $session -ScriptBlock {
        Get-ChildItem -LiteralPath 'C:\ntfs2refs\refs-os-preparation' -File -Force | ForEach-Object { [pscustomobject]@{ name = $_.Name; length = $_.Length; attributes = [string]$_.Attributes; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() } }
    })
    if (($files | Measure-Object length -Sum).Sum -gt 64MB -or @($files | Where-Object name -CEQ 'result.json').Count -ne 1) { throw 'Preparation evidence is missing or exceeds the bounded export.' }
    foreach ($file in $files) {
        if ($file.name -cnotin $allowed -or $file.length -gt 32MB -or [IO.FileAttributes]$file.attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unexpected preparation artifact; guest state preserved.' }
        $destination = Join-Path $outputRoot $file.name
        Copy-Item -LiteralPath (Join-Path $remote.evidenceDirectory $file.name) -Destination $destination -FromSession $session
        if ((Get-Item -LiteralPath $destination).Length -ne $file.length -or (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -cne $file.sha256) { throw 'Exported preparation evidence failed verification.' }
    }
    $guestRecord = Get-Content -LiteralPath (Join-Path $outputRoot 'result.json') -Raw | ConvertFrom-Json
    if ($guestRecord.status -cne $remote.status -or $guestRecord.formatMethod -cne $FormatMethod -or $guestRecord.bootAttempted -or $guestRecord.refsBootVerified) { throw 'Preparation result is inconsistent.' }
    $files | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $outputRoot 'exported-files.json') -Encoding UTF8
    $record.evidenceExported = $true
    Stop-PreparationGuest
    Remove-PSSession -Session $session -ErrorAction SilentlyContinue; $session = $null
    Get-OwnedLabVM -Configuration $configuration -Manifest $manifest | Out-Null
    if ($remote.status -ceq 'prepared') {
        if (-not ($guestRecord.formatSucceeded -and $guestRecord.imageApplied -and $guestRecord.bootFilesPrepared -and $guestRecord.firstBootConfigured)) { throw 'Prepared result lacks required stages.' }
        Invoke-LabAction -Action Checkpoint -Lane $Lane -CheckpointName $checkpointName -Confirm:$false | Out-Null
        $record.preparationCheckpoint = $checkpointName
        $preparedCheckpoint = Get-ExactLabCheckpoint -VM (Get-OwnedLabVM -Configuration $configuration -Manifest $manifest) -Name $checkpointName
        $record['preparationCheckpointId'] = [string]$preparedCheckpoint.Id
        $record.status = 'prepared-awaiting-separate-boot-validation'
        Invoke-LabAction -Action Restore -Lane $Lane -CheckpointName 'installed-clean' -Confirm:$false | Out-Null
        $record.baselineRestored = $true
    } else {
        Invoke-LabAction -Action Restore -Lane $Lane -CheckpointName 'installed-clean' -Confirm:$false | Out-Null
        $record.baselineRestored = $true
        $record.status = 'native-preparation-blocked'
    }
} catch {
    $record.status = 'failed'; $record['error'] = $_.Exception.Message
    $record['errorId'] = $_.FullyQualifiedErrorId; $record['errorPosition'] = $_.InvocationInfo.PositionMessage; $record['scriptStackTrace'] = $_.ScriptStackTrace
    try { Stop-PreparationGuest } catch { $record['shutdownError'] = $_.Exception.Message }
    # Never discard guest state after a transport/export failure.
    throw
} finally {
    $record | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $outputRoot 'host-result.json') -Encoding UTF8
    if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    $credential = $null
}
[pscustomobject]@{ Status = $record.status; Evidence = $outputRoot; PreparationCheckpoint = $record.preparationCheckpoint; VMState = 'Off'; BaselineRestored = $record.baselineRestored; BootAttempted = $false; ReFSBootVerified = $false }
