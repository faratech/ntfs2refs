<# Native data-volume corpus only. No conversion and no ReFS boot claim. #>
[CmdletBinding(SupportsShouldProcess)]
param([ValidateSet('win11')][string]$Lane = 'win11', [ValidateRange(60,900)][int]$BootTimeoutSeconds = 300)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
Import-Module (Join-Path $workspace 'lab\NativeControlExport.psm1') -Force
$configuration = Get-LabConfiguration -WorkspaceRoot $workspace
if (-not $PSCmdlet.ShouldProcess($configuration.Settings.lanes.$Lane.name, 'Capture 1 GiB native NTFS and ReFS data controls, export evidence, restore installed-clean')) {
    [pscustomobject]@{ Action = 'NativeControls'; Lane = $Lane; DryRun = $true; Filesystems = @('NTFS','ReFS'); CaptureBytes = 1GB; RestoreCheckpoint = 'installed-clean'; ReFSBootTest = $false }
    return
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Native controls require the reviewed elevated helper.' }
$manifest = Read-LabManifest -Configuration $configuration -Lane $Lane
if (-not $manifest) { throw 'Missing lab ownership manifest.' }
$vm = Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
if ($vm.State -ne 'Off') { throw 'Start native controls with the owned VM off.' }
if (@(Get-VMNetworkAdapter -VM $vm | Where-Object SwitchName).Count) { throw 'The lab NIC must be disconnected.' }
$baseline = @(Get-VMCheckpoint -VM $vm | Where-Object Name -CEQ 'installed-clean')
if ($baseline.Count -ne 1) { throw 'Exactly one installed-clean checkpoint is required.' }
$laneRoot = Assert-LabPath (Join-Path $configuration.Root $Lane) $configuration.Root
$firstBoot = Get-Content -LiteralPath (Join-Path $laneRoot 'firstboot\state.json') -Raw | ConvertFrom-Json
if ($firstBoot.stage -ne 'complete' -or [string]$firstBoot.vmId -ne [string]$manifest.vmId) { throw 'Native NTFS boot baseline is not qualified.' }
$credential = Import-Clixml -LiteralPath (Join-Path $laneRoot 'secrets\guest-credential.xml')
if ($credential -isnot [Management.Automation.PSCredential] -or $credential.UserName -cne 'N2R-WIN11\LabAdmin') { throw 'Unexpected guest credential identity.' }
$runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$outputRoot = Assert-LabPath (Join-Path $configuration.Root "corpus\$Lane-$runId") $configuration.Root
Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 6GB
New-Item -ItemType Directory -Path $outputRoot | Out-Null
function Get-ControlSession {
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
function Stop-ControlGuest($Session) {
    Invoke-Command -Session $Session -ScriptBlock { & shutdown.exe /s /t 0; if ($LASTEXITCODE -ne 0) { throw 'Guest shutdown request failed.' } }
    $deadline = [DateTime]::UtcNow.AddMinutes(3)
    do { if ((Get-VM -Id ([guid]$manifest.vmId)).State -eq 'Off') { return }; Start-Sleep -Seconds 2 } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Guest did not shut down cleanly. No restore was attempted.'
}
$reports = New-Object 'System.Collections.Generic.List[object]'
foreach ($filesystem in @('NTFS','ReFS')) {
    $session = $null; $exported = $false
    $caseRoot = Assert-LabPath (Join-Path $outputRoot $filesystem.ToLowerInvariant()) $configuration.Root
    New-Item -ItemType Directory -Path $caseRoot | Out-Null
    try {
        Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 3GB
        $vm = Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
        if ($vm.State -ne 'Off') { throw 'Each control must start with the owned VM off.' }
        Invoke-LabAction -Action Start -Lane $Lane -Confirm:$false | Out-Null
        $session = Get-ControlSession
        $sessionPolicy = Initialize-LabGuestSession -Session $session
        $sessionPolicy | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $caseRoot 'guest-session-policy.json') -Encoding UTF8
        if ($sessionPolicy.status -cne 'ready') { throw ('Guest script session refused: ' + $sessionPolicy.error) }
        foreach ($file in Get-ChildItem -LiteralPath (Join-Path $workspace 'lab\guest') -File) {
            Copy-Item -LiteralPath $file.FullName -Destination ('C:\ntfs2refs\guest\' + $file.Name) -ToSession $session -Force
        }
        $hostDisks = @($manifest.disks | Where-Object { $_.role -in @('target','journal') } | Select-Object role,sizeBytes,controllerLocation,vhdId)
        $hostDiskJson = ConvertTo-Json -InputObject $hostDisks -Depth 4 -Compress
        $remote = Invoke-Command -Session $session -ArgumentList $hostDiskJson,$filesystem -ScriptBlock {
            param($HostDiskJson, $FileSystem)
            Set-StrictMode -Version Latest
            $ErrorActionPreference = 'Stop'
            # Windows PowerShell 5 emits a JSON array as one pipeline object.
            # Materialize it first so @() does not create a nested array.
            $parsedHostDisks = $HostDiskJson | ConvertFrom-Json
            $HostDisks = @($parsedHostDisks)
            Import-Module 'C:\ntfs2refs\guest\GuestLab.psm1' -Force
            $version = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            $build = [string]$version.CurrentBuild + '.' + [string]$version.UBR
            if ($build -cne '26300.9457' -or $version.EditionID -cne 'Professional') { throw 'Native controls require the pinned Windows 11 Pro build.' }
            $formatCommand = Get-Command Format-Volume -ErrorAction Stop
            $formatComponents = @(foreach ($relative in @('System32\drivers\refs.sys','System32\fmifs.dll')) {
                $file = Get-Item -LiteralPath (Join-Path $env:SystemRoot $relative)
                [pscustomobject]@{path=$file.FullName;version=$file.VersionInfo.FileVersion;sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
            })
            $runRoot = 'C:\ntfs2refs\control-' + $FileSystem.ToLowerInvariant()
            if (Test-Path -LiteralPath $runRoot) { throw 'Control directory already exists; baseline is not clean.' }
            New-Item -ItemType Directory -Path $runRoot | Out-Null
            $identities = @{}
            foreach ($role in @('target','journal')) {
                $specs = @($HostDisks | Where-Object role -eq $role)
                if ($specs.Count -ne 1) { throw 'Host must identify exactly one target and journal.' }
                $spec = $specs[0]
                $candidates = @()
                foreach ($disk in @(Get-Disk | Where-Object { -not $_.IsBoot -and -not $_.IsSystem -and $_.Size -eq $spec.sizeBytes })) {
                    $cim = @(Get-CimInstance Win32_DiskDrive | Where-Object Index -eq $disk.Number)
                    # Guest storage stacks expose the Hyper-V slot as either the
                    # target ID or LUN. Require one of those two zero-based forms,
                    # plus unique size, non-OS identity and exact host attachments.
                    if ($cim.Count -eq 1) {
                        $slotMatches = ($cim[0].SCSITargetId -eq $spec.controllerLocation -and $cim[0].SCSILogicalUnit -eq 0) -or ($cim[0].SCSITargetId -eq 0 -and $cim[0].SCSILogicalUnit -eq $spec.controllerLocation)
                        if ($slotMatches) { $candidates += $disk }
                    }
                }
                if ($candidates.Count -ne 1) { throw "Guest $role disk cannot be uniquely matched by host SCSI location and size." }
                Assert-LabGuestDisk $candidates[0]
                if ($candidates[0].PartitionStyle -ne 'RAW' -or $candidates[0].IsOffline -or $candidates[0].IsReadOnly) { throw 'Control disks must be online, writable, and blank RAW disks.' }
                $path = Join-Path $runRoot ($role + '.json')
                & 'C:\ntfs2refs\guest\Register-GuestDisk.ps1' -UniqueId ([string]$candidates[0].UniqueId) -Role $role -OutputPath $path -Confirm:$false | Out-Null
                $identities[$role] = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
                $identities[$role] | Add-Member -NotePropertyName hostVhdId -NotePropertyValue $spec.vhdId
            }
            if ($identities.target.uniqueId -eq $identities.journal.uniqueId) { throw 'Target and journal identities collide.' }
            $targetPath = Join-Path $runRoot 'target.json'; $journalPath = Join-Path $runRoot 'journal.json'
            & 'C:\ntfs2refs\guest\Prepare-GuestControl.ps1' -ManifestPath $journalPath -Action FormatNTFS -Confirm:$false | Out-Null
            $journalDisk = Get-LabGuestDisk $identities.journal
            $journalPartitions = @(Get-Partition -DiskNumber $journalDisk.Number | Where-Object DriveLetter)
            if ($journalPartitions.Count -ne 1) { throw 'Journal partition not uniquely identified.' }
            $captureRoot = [string]$journalPartitions[0].DriveLetter + ':\native-control'
            New-Item -ItemType Directory -Path $captureRoot | Out-Null
            $record = [ordered]@{ schemaVersion = 1; filesystem = $FileSystem; status = 'started'; stage = 'format'; formatSucceeded = $false; captureComplete = $false; fixtureError = $null; error = $null; errorHresult = $null; target = $identities.target; journal = $identities.journal; emptyImage = $null; image = $null; observation = 'Native empty format followed by the deterministic fixture batch; not a single-operation format experiment'; nativeEvidence = $null; ReFSBootVerified = $false }
            $record['formatter'] = [pscustomobject]@{windowsBuild=$build;edition=$version.EditionID;command='Format-Volume';module=$formatCommand.ModuleName;moduleVersion=[string]$formatCommand.Module.Version;components=$formatComponents;partitionBytes=1GB;fileSystem=$FileSystem;allocationUnitSize=4096;devDrive=$false}
            try {
                $targetDisk = Get-LabGuestDisk $identities.target
                Initialize-Disk -Number $targetDisk.Number -PartitionStyle GPT | Out-Null
                $partition = New-Partition -DiskNumber $targetDisk.Number -Size 1GB -AssignDriveLetter
                $partition | Format-Volume -FileSystem $FileSystem -AllocationUnitSize 4096 -NewFileSystemLabel 'ntfs2refs-target' -Confirm:$false | Out-Null
                $volume = Get-Volume -DriveLetter $partition.DriveLetter
                if ($volume.FileSystem -ne $FileSystem -or $volume.AllocationUnitSize -ne 4096) { throw 'Native format differs from requested filesystem or cluster size.' }
                $record.formatSucceeded = $true
                $record.stage = 'empty-raw-capture'
                $record.emptyImage = & 'C:\ntfs2refs\guest\Capture-RawControl.ps1' -TargetManifestPath $targetPath -JournalManifestPath $journalPath -OutputPath (Join-Path $captureRoot 'empty.raw') -Confirm:$false
                $record.stage = 'fixtures'
                try { & 'C:\ntfs2refs\guest\Prepare-GuestControl.ps1' -ManifestPath $targetPath -Action Fixtures -Confirm:$false | Out-Null } catch { $record.fixtureError = $_.Exception.Message }
                $record.stage = 'native-evidence'
                $nativePath = Join-Path $captureRoot 'native-evidence.json'
                & 'C:\ntfs2refs\guest\Capture-GuestEvidence.ps1' -ManifestPath $targetPath -OutputPath $nativePath | Out-Null
                $record.nativeEvidence = $nativePath
                $record.stage = 'raw-capture'
                $record.image = & 'C:\ntfs2refs\guest\Capture-RawControl.ps1' -TargetManifestPath $targetPath -JournalManifestPath $journalPath -OutputPath (Join-Path $captureRoot 'control.raw') -Confirm:$false
                $record.captureComplete = $true
                $record.status = if ($record.fixtureError) { 'captured-with-fixture-limitations' } else { 'captured' }
                $record.stage = 'complete'
            } catch {
                $record.status = 'blocked'
                $record.error = $_.Exception.Message
                $record.errorHresult = $_.Exception.HResult
            }
            $record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $runRoot 'result.json') -Encoding UTF8
            [pscustomobject]@{ report = $record; manifestDirectory = $runRoot; captureDirectory = $captureRoot }
        }
        $remote.report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $caseRoot 'guest-result.json') -Encoding UTF8
        $artifactExport = Export-LabNativeControlArtifacts -Session $session -ManifestDirectory $remote.manifestDirectory -CaptureDirectory $remote.captureDirectory -Destination $caseRoot -LabRoot $configuration.Root -Report $remote.report
        $validated = $artifactExport.captureValidated
        $exported = $true
        $hostRecord = [pscustomobject]@{ schemaVersion = 1; filesystem = $filesystem; status = $remote.report.status; formatSucceeded = $remote.report.formatSucceeded; captureValidated = $validated; stage = $remote.report.stage; error = $remote.report.error; fixtureError = $remote.report.fixtureError; artifacts = $caseRoot; baselineRestored = $false; writerProfileQualified = $false; refsBootVerified = $false }
        $hostRecord | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $caseRoot 'host-result.json') -Encoding UTF8
        Stop-ControlGuest $session
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue; $session = $null
        Invoke-LabAction -Action Restore -Lane $Lane -CheckpointName 'installed-clean' -Confirm:$false | Out-Null
        $hostRecord.baselineRestored = $true
        $hostRecord | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $caseRoot 'host-result.json') -Encoding UTF8
        $reports.Add($hostRecord)
    } catch {
        $failureRecord = $_
        $failureMessage = $_.Exception.Message
        $shutdownFailure = $null
        if ($session) { try { Stop-ControlGuest $session } catch { $shutdownFailure = $_.Exception.Message } }
        # Preserve unexported guest artifacts; never restore merely to hide a failure.
        [pscustomobject]@{ schemaVersion = 1; status = 'failed'; filesystem = $filesystem; error = $failureMessage; errorId = $failureRecord.FullyQualifiedErrorId; invocation = $failureRecord.InvocationInfo.PositionMessage; scriptStackTrace = $failureRecord.ScriptStackTrace; shutdownFailure = $shutdownFailure; exported = $exported; baselineRestored = $false; observedUtc = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $caseRoot 'failure.json') -Encoding UTF8
        throw
    } finally {
        if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    }
}
$reports.ToArray() | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $outputRoot 'results.json') -Encoding UTF8
$credential = $null
[pscustomobject]@{ Corpus = $outputRoot; Results = $reports.ToArray(); VMState = 'Off'; Baseline = 'installed-clean'; ReFSBootVerified = $false }
