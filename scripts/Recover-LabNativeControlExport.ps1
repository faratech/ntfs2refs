<# Recover only the completed captures from the recorded NTFS export failure.
   Existing fixtures/images are read and verified, never regenerated. #>
[CmdletBinding(SupportsShouldProcess)]
param([ValidateSet('win11')][string]$Lane='win11',[ValidateRange(60,900)][int]$BootTimeoutSeconds=300)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
Import-Module (Join-Path $workspace 'lab\NativeControlExport.psm1') -Force
$configuration=Get-LabConfiguration -WorkspaceRoot $workspace
$caseRoot=Assert-LabPath (Join-Path $configuration.Root 'corpus\win11-20261023T211635519Z\ntfs') $configuration.Root
function Assert-NativeExportRecovery($Failure,$Report,$Manifest,$Checkpoint) {
    if ([string]$Manifest.vmId -ine 'eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c' -or $Manifest.vmName -cne 'ntfs2refs-win11' -or $Checkpoint.Name -cne 'installed-clean' -or [string]$Checkpoint.Id -ine 'eda059b3-6d50-46bb-bdf4-018b99b5b34f') { throw 'Recovery requires the recorded owned VM and exact baseline checkpoint.' }
    if ($Failure.schemaVersion -ne 1 -or $Failure.status -cne 'failed' -or $Failure.filesystem -cne 'NTFS' -or $Failure.error -cne "The property 'Length' cannot be found on this object. Verify that the property exists." -or $Failure.observedUtc -cne '2026-10-23T21:17:44.4199085Z' -or $Failure.exported -or $Failure.baselineRestored -or $Failure.shutdownFailure) { throw 'Only the recorded unexported NTFS control failure is recoverable here.' }
    if ($Report.schemaVersion -ne 1 -or $Report.filesystem -cne 'NTFS' -or $Report.status -cne 'captured-with-fixture-limitations' -or -not $Report.formatSucceeded -or -not $Report.captureComplete -or $Report.stage -cne 'complete' -or $Report.ReFSBootVerified -or $Report.formatter.windowsBuild -cne '26300.9457') { throw 'The recorded native NTFS captures are not complete.' }
    foreach ($spec in @(@{role='target';id='25C491D0-5F1B-4205-9E6F-FD619706C2B5';guest='60022480D091C4251B5FFD619706C2B5';size=64GB;slot=1},@{role='journal';id='1F26AC6A-1F02-4989-B5C8-249596F332FC';guest='600224806AAC261F021F249596F332FC';size=8GB;slot=2})) {
        $hostDisks=@($Manifest.disks | Where-Object role -ceq $spec.role)
        $guest=$Report.($spec.role)
        if ($hostDisks.Count -ne 1 -or $hostDisks[0].vhdId -ine $spec.id -or $hostDisks[0].sizeBytes -ne $spec.size -or $hostDisks[0].controllerLocation -ne $spec.slot -or $guest.hostVhdId -ine $spec.id -or $guest.uniqueId -cne $spec.guest -or $guest.sizeBytes -ne $spec.size) { throw 'Recorded host/guest disk identity differs from the exact control run.' }
    }
    if ($Report.emptyImage.status -cne 'complete' -or $Report.image.status -cne 'complete' -or $Report.emptyImage.length -ne 1GB -or $Report.image.length -ne 1GB -or $Report.emptyImage.sha256 -cne '293991f368ae50b35a6b824c87a7fdeace7eb13a354f08422a7c8f9213e88b72' -or $Report.image.sha256 -cne 'fa41633393c0ea6e32e03053fe8a0e5ffb3d3fd2f3e201be3b38eab4437058d1' -or $Report.emptyImage.imagePath -cne 'E:\native-control\empty.raw' -or $Report.image.imagePath -cne 'E:\native-control\control.raw' -or $Report.emptyImage.partitionOffset -ne 16777216 -or $Report.image.partitionOffset -ne 16777216) { throw 'Capture hashes, lengths, offsets or paths differ from the recorded run.' }
}
if (-not $PSCmdlet.ShouldProcess($caseRoot,'Export and verify existing NTFS control files, cleanly shut down, then restore exact installed-clean')) {
    [pscustomobject]@{Action='RecoverNativeControlExport';DryRun=$true;Lane=$Lane;CaptureRegenerated=$false;Baseline='installed-clean';ExportBeforeRestore=$true}
    return
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use the reviewed elevated Hyper-V helper.' }
$manifest=Read-LabManifest -Configuration $configuration -Lane $Lane
if (-not $manifest) { throw 'Missing ownership manifest.' }
$vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
if ($vm.State -ne 'Off' -or @(Get-VMNetworkAdapter -VM $vm | Where-Object SwitchName).Count) { throw 'Recovery requires the owned VM off and its network disconnected.' }
$checkpoint=Get-ExactLabCheckpoint -VM $vm -Name 'installed-clean'
$failure=Get-Content -LiteralPath (Join-Path $caseRoot 'failure.json') -Raw | ConvertFrom-Json
$report=Get-Content -LiteralPath (Join-Path $caseRoot 'guest-result.json') -Raw | ConvertFrom-Json
Assert-NativeExportRecovery $failure $report $manifest $checkpoint
$outputRoot=Assert-LabPath (Join-Path $caseRoot 'recovered-export') $configuration.Root
if ((Test-Path -LiteralPath $outputRoot) -or (Test-Path -LiteralPath (Join-Path $caseRoot 'recovery-complete.json'))) { throw 'Recovery destination or completion record already exists; no overwrite or automatic partial retry is allowed.' }
$laneRoot=Assert-LabPath (Join-Path $configuration.Root $Lane) $configuration.Root
$firstBoot=Get-Content -LiteralPath (Join-Path $laneRoot 'firstboot\state.json') -Raw | ConvertFrom-Json
if ($firstBoot.stage -cne 'complete' -or [string]$firstBoot.vmId -ine [string]$manifest.vmId) { throw 'Native NTFS baseline qualification is missing.' }
$credential=Import-Clixml -LiteralPath (Join-Path $laneRoot 'secrets\guest-credential.xml')
if ($credential -isnot [Management.Automation.PSCredential] -or $credential.UserName -cne 'N2R-WIN11\LabAdmin') { throw 'Unexpected guest credential identity.' }
Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 3GB
New-Item -ItemType Directory -Path $outputRoot | Out-Null
Copy-Item -LiteralPath (Join-Path $caseRoot 'failure.json') -Destination (Join-Path $outputRoot 'original-failure.json')
Copy-Item -LiteralPath (Join-Path $caseRoot 'guest-result.json') -Destination (Join-Path $outputRoot 'original-guest-result.json')
$record=[ordered]@{schemaVersion=1;status='started';exported=$false;captureValidated=$false;baselineRestored=$false;artifacts=$outputRoot;writerProfileQualified=$false;refsBootVerified=$false;fixtureError=$report.fixtureError;error=$null;invocation=$null;scriptStackTrace=$null}
$session=$null
function Stop-RecoveryGuest {
    if ((Get-VM -Id ([guid]$manifest.vmId)).State -eq 'Off') { return }
    if (-not $session) { throw 'No authenticated session is available for clean shutdown.' }
    Invoke-Command -Session $session -ScriptBlock { & shutdown.exe /s /t 0; if($LASTEXITCODE -ne 0){throw 'Guest shutdown request failed.'} }
    $deadline=[DateTime]::UtcNow.AddMinutes(3)
    do { if((Get-VM -Id ([guid]$manifest.vmId)).State -eq 'Off'){return}; Start-Sleep -Seconds 2 } while([DateTime]::UtcNow -lt $deadline)
    throw 'Guest did not shut down; baseline was not restored.'
}
try {
    Invoke-LabAction -Action Start -Lane $Lane -Confirm:$false | Out-Null
    $deadline=[DateTime]::UtcNow.AddSeconds($BootTimeoutSeconds)
    while(-not $session -and [DateTime]::UtcNow -lt $deadline) {
        $probe=$null
        try {
            $probe=Invoke-Command -VMId ([guid]$manifest.vmId) -Credential $credential -AsJob -ScriptBlock {$env:COMPUTERNAME}
            if(Wait-Job -Job $probe -Timeout 10){$reply=@(Receive-Job -Job $probe -ErrorAction Stop);if($reply.Count -eq 1 -and $reply[0] -ceq 'N2R-WIN11'){$session=New-PSSession -VMId ([guid]$manifest.vmId) -Credential $credential -ErrorAction Stop}}
        } catch {} finally {if($probe){Remove-Job -Job $probe -Force -ErrorAction SilentlyContinue}}
        if(-not $session){Start-Sleep -Seconds 2}
    }
    if(-not $session){throw 'PowerShell Direct did not become available before the deadline.'}
    $policy=Initialize-LabGuestSession -Session $session
    $policy | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $outputRoot 'guest-session-policy.json') -Encoding UTF8
    if($policy.status -cne 'ready'){throw ('Guest session refused: ' + $policy.error)}
    $expectedJson=$report | ConvertTo-Json -Depth 10 -Compress
    $remote=Invoke-Command -Session $session -ArgumentList $expectedJson -ScriptBlock {
        param($ExpectedJson)
        Set-StrictMode -Version Latest
        $ErrorActionPreference='Stop'
        $expected=$ExpectedJson | ConvertFrom-Json
        $runRoot='C:\ntfs2refs\control-ntfs'
        $actual=Get-Content -LiteralPath (Join-Path $runRoot 'result.json') -Raw | ConvertFrom-Json
        if($actual.filesystem -cne 'NTFS' -or -not $actual.captureComplete -or $actual.emptyImage.sha256 -cne $expected.emptyImage.sha256 -or $actual.image.sha256 -cne $expected.image.sha256 -or $actual.emptyImage.capturedUtc -cne $expected.emptyImage.capturedUtc -or $actual.image.capturedUtc -cne $expected.image.capturedUtc){throw 'Guest captures no longer match the recorded run.'}
        $targetOffset=$null
        foreach($role in @('target','journal')) {
            $identity=Get-Content -LiteralPath (Join-Path $runRoot ($role + '.json')) -Raw | ConvertFrom-Json
            $prior=$expected.$role
            $disks=@(Get-Disk | Where-Object {[string]$_.UniqueId -ceq $prior.uniqueId})
            if($identity.uniqueId -cne $prior.uniqueId -or $identity.location -cne $prior.location -or $disks.Count -ne 1){throw 'Guest disk manifest or unique identity changed.'}
            $disk=$disks[0]
            if($disk.IsBoot -or $disk.IsSystem -or $disk.IsOffline -or $disk.IsReadOnly -or $disk.Size -ne $prior.sizeBytes -or [string]$disk.Location -cne $prior.location -or [string]$disk.SerialNumber -cne [string]$prior.serialNumber -or $disk.FriendlyName -cne 'Msft Virtual Disk' -or [string]$disk.BusType -cnotin @('SCSI','SAS')){throw 'Guest disk role, size or virtual identity changed.'}
            $parts=@(Get-Partition -DiskNumber $disk.Number | Where-Object DriveLetter)
            if($parts.Count -ne 1 -or ($role -ceq 'target' -and $parts[0].Size -ne 1GB) -or ($role -ceq 'journal' -and [string]$parts[0].DriveLetter -cne 'E')){throw 'Guest control partition mapping changed.'}
            $volume=Get-Volume -DriveLetter $parts[0].DriveLetter
            if($volume.FileSystem -cne 'NTFS' -or $volume.FileSystemLabel -cne ('ntfs2refs-' + $role)){throw 'Guest control filesystem or label changed.'}
            if($role -ceq 'target'){$targetOffset=[int64]$parts[0].Offset}
        }
        foreach($capture in @(@{name='empty';record=$expected.emptyImage},@{name='control';record=$expected.image})) {
            $sidecar=Get-Content -LiteralPath ('E:\native-control\' + $capture.name + '.raw.json') -Raw | ConvertFrom-Json
            if($sidecar.status -cne 'complete' -or $sidecar.length -ne 1GB -or $sidecar.sha256 -cne $capture.record.sha256 -or $sidecar.target.uniqueId -cne $expected.target.uniqueId -or $sidecar.partitionOffset -ne $targetOffset -or $targetOffset -ne $capture.record.partitionOffset){throw 'Capture sidecar differs from the enrolled target partition or recorded capture.'}
        }
        [pscustomobject]@{report=$actual;manifestDirectory=$runRoot;captureDirectory='E:\native-control'}
    }
    $export=Export-LabNativeControlArtifacts -Session $session -ManifestDirectory $remote.manifestDirectory -CaptureDirectory $remote.captureDirectory -Destination $outputRoot -LabRoot $configuration.Root -Report $report
    if(-not $export.captureValidated){throw 'Both completed raw captures must verify before recovery can restore the baseline.'}
    $record.exported=$true; $record.captureValidated=$true
    Stop-RecoveryGuest
    Remove-PSSession -Session $session -ErrorAction SilentlyContinue; $session=$null
    $vm=Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    $currentCheckpoint=Get-ExactLabCheckpoint -VM $vm -Name 'installed-clean'
    if($vm.State -ne 'Off' -or [string]$currentCheckpoint.Id -ine [string]$checkpoint.Id){throw 'VM/checkpoint changed before recovery restore.'}
    Invoke-LabAction -Action Restore -Lane $Lane -CheckpointName 'installed-clean' -Confirm:$false | Out-Null
    $record.baselineRestored=$true; $record.status='recovered-with-fixture-limitations'
    $record | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $caseRoot 'recovery-complete.json') -Encoding UTF8
} catch {
    $failureRecord=$_
    $record.status='failed'; $record.error=$failureRecord.Exception.Message; $record.invocation=$failureRecord.InvocationInfo.PositionMessage; $record.scriptStackTrace=$failureRecord.ScriptStackTrace
    try {Stop-RecoveryGuest} catch {$record['shutdownFailure']=$_.Exception.Message}
    throw
} finally {
    $record | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $outputRoot 'host-result.json') -Encoding UTF8
    if($session){Remove-PSSession -Session $session -ErrorAction SilentlyContinue}
    $credential=$null
}
[pscustomobject]@{Status=$record.status;Artifacts=$outputRoot;CaptureValidated=$true;BaselineRestored=$true;VMState='Off';ReFSBootVerified=$false}
