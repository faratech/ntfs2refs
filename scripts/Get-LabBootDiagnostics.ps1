<#
.SYNOPSIS
Collect bounded, read-only diagnostics for a manifest-owned Hyper-V lab VM.
.DESCRIPTION
Requires existing Hyper-V management access; never elevates, starts/stops a VM,
creates a checkpoint, mounts a disk, or enters the guest. Artifacts are written
under the ignored .lab directory. Heartbeat is not proof of successful OS boot.

Thumbnail API and raw RGB565 format:
https://learn.microsoft.com/windows/win32/hyperv_v2/getvirtualsystemthumbnailimage-msvm-virtualsystemmanagementservice
WidthPixels/HeightPixels are inputs; ImageData is the documented uint8[] output.
The method does not return image dimensions. Video-head dimensions are separate
observations and are not assumed to describe a mismatched thumbnail buffer:
https://learn.microsoft.com/windows/win32/hyperv_v2/msvm-videohead
Event query syntax:
https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-5.1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('win11','server')][string]$Lane = 'win11',
    [ValidateRange(1,1440)][int]$LookBackMinutes = 120,
    [ValidateRange(1,100)][int]$MaxEventsPerLog = 50,
    [switch]$SkipThumbnail
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
$configuration = Get-LabConfiguration -WorkspaceRoot $workspace
$ignoredRoot = Join-Path $workspace '.lab'
$diagnosticRoot = Assert-LabPath -Path (Join-Path $configuration.Root "$Lane\diagnostics") -Root $ignoredRoot
if (-not $PSCmdlet.ShouldProcess($diagnosticRoot, 'Read owned VM diagnostics and save bounded JSON/optional VM thumbnail')) {
    [pscustomobject]@{
        Action = 'GetLabBootDiagnostics'; Lane = $Lane; DryRun = $true
        OutputRoot = $diagnosticRoot; LookBackMinutes = $LookBackMinutes
        MaxEventsPerLog = $MaxEventsPerLog; Thumbnail = -not $SkipThumbnail
        Requires = 'Existing Hyper-V access and provisioner ownership manifest'
        ChangesVM = $false; MaximumRunBytes = 10MB; MaximumDiagnosticBytes = 64MB
    }
    return
}

function Limit-DiagnosticText([AllowNull()][object]$Value, [int]$Limit = 4096) {
    $text = [string]$Value
    if ($text.Length -gt $Limit) { return $text.Substring(0, $Limit) + ' [truncated]' }
    return $text
}

function Write-Rgb565Png([byte[]]$Pixels, [int]$Width, [int]$Height, [string]$Path) {
    if ($Pixels.Length -ne ($Width * $Height * 2)) { throw 'Thumbnail byte count differs from the requested RGB565 geometry.' }
    Add-Type -AssemblyName System.Drawing
    $bitmap = New-Object Drawing.Bitmap($Width, $Height, [Drawing.Imaging.PixelFormat]::Format16bppRgb565)
    $bits = $null
    try {
        $rectangle = New-Object Drawing.Rectangle(0, 0, $Width, $Height)
        $bits = $bitmap.LockBits($rectangle, [Drawing.Imaging.ImageLockMode]::WriteOnly, [Drawing.Imaging.PixelFormat]::Format16bppRgb565)
        for ($row = 0; $row -lt $Height; $row++) {
            $destination = [IntPtr]::Add($bits.Scan0, $row * $bits.Stride)
            [Runtime.InteropServices.Marshal]::Copy($Pixels, $row * $Width * 2, $destination, $Width * 2)
        }
        $bitmap.UnlockBits($bits)
        $bits = $null
        # Convert to a PNG-compatible pixel format after copying the raw image.
        $rgb = $bitmap.Clone($rectangle, [Drawing.Imaging.PixelFormat]::Format24bppRgb)
        try { $rgb.Save($Path, [Drawing.Imaging.ImageFormat]::Png) }
        finally { $rgb.Dispose() }
    } finally {
        if ($null -ne $bits) { $bitmap.UnlockBits($bits) }
        $bitmap.Dispose()
    }
}

# Validate ownership before any VM data is collected or artifacts are created.
Import-Module Hyper-V -ErrorAction Stop
$manifest = Read-LabManifest -Configuration $configuration -Lane $Lane
if (-not $manifest) { throw 'No provisioner ownership manifest exists for this lane.' }
$vm = Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
$vmGuid = ([guid]$vm.Id).ToString('D')

# Bound retained diagnostics; never silently delete previous evidence. Traverse
# explicitly so a reparse point cannot lead outside the ignored lab directory.
$existingBytes = [int64]0
$existingEntries = 0
if (Test-Path -LiteralPath $diagnosticRoot) {
    $pending = New-Object 'System.Collections.Generic.Queue[string]'
    $pending.Enqueue($diagnosticRoot)
    while ($pending.Count) {
        foreach ($entry in Get-ChildItem -LiteralPath $pending.Dequeue() -Force) {
            $existingEntries++
            if ($existingEntries -gt 1000) { throw 'Diagnostic retention entry limit reached; archive prior evidence explicitly.' }
            Assert-LabPath -Path $entry.FullName -Root $ignoredRoot | Out-Null
            if ($entry.PSIsContainer) { $pending.Enqueue($entry.FullName) }
            else { $existingBytes += $entry.Length }
            if ($existingBytes -gt (64MB - 10MB)) { throw 'Diagnostic retention budget reached; archive prior evidence explicitly.' }
        }
    }
}
Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 10MB
$runName = 'boot-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
$runRoot = Assert-LabPath -Path (Join-Path $diagnosticRoot $runName) -Root $configuration.Root
New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop | Out-Null
$report = [ordered]@{
    schemaVersion = 1; lane = $Lane; vmId = $vmGuid
    capturedUtc = [DateTime]::UtcNow.ToString('o')
    interpretation = 'Point-in-time host observations; heartbeat and a thumbnail do not certify successful Windows boot.'
    vm = [ordered]@{
        name = Limit-DiagnosticText $vm.Name 256; state = [string]$vm.State
        status = Limit-DiagnosticText $vm.Status; heartbeat = [string]$vm.Heartbeat
        generation = $vm.Generation; uptimeSeconds = $vm.Uptime.TotalSeconds
        processorCount = $vm.ProcessorCount; memoryAssignedBytes = $vm.MemoryAssigned
    }
    integrationServices = $null; firmware = $null; checkpoints = $null
    eventLogs = @(); thumbnail = [ordered]@{ status = 'not-requested' }
    errors = @()
}

try {
    $report.integrationServices = @(Get-VMIntegrationService -VM $vm | Select-Object -First 16 | ForEach-Object {
        [pscustomobject]@{ id = [string]$_.Id; name = Limit-DiagnosticText $_.Name 256; enabled = $_.Enabled; primaryStatus = Limit-DiagnosticText $_.PrimaryStatusDescription; secondaryStatus = Limit-DiagnosticText $_.SecondaryStatusDescription }
    })
} catch { $report.errors += 'Integration services: ' + (Limit-DiagnosticText $_.Exception.Message) }
try {
    $firmware = Get-VMFirmware -VM $vm
    $report.firmware = [ordered]@{
        secureBoot = [string]$firmware.SecureBoot; secureBootTemplate = [string]$firmware.SecureBootTemplate
        bootOrder = @($firmware.BootOrder | Select-Object -First 16 | ForEach-Object {
            [pscustomobject]@{ bootType = [string]$_.BootType; description = Limit-DiagnosticText $_.Description; firmwarePath = Limit-DiagnosticText $_.FirmwarePath }
        })
    }
} catch { $report.errors += 'Firmware: ' + (Limit-DiagnosticText $_.Exception.Message) }
try {
    $checkpoints = @(Get-VMCheckpoint -VM $vm | Select-Object -First 65)
    $report.checkpoints = [ordered]@{
        truncated = $checkpoints.Count -gt 64
        items = @($checkpoints | Select-Object -First 64 | ForEach-Object {
            [pscustomobject]@{ id = [string]$_.Id; name = Limit-DiagnosticText $_.Name 256; creationTimeUtc = $_.CreationTime.ToUniversalTime().ToString('o'); checkpointType = [string]$_.CheckpointType }
        })
    }
} catch { $report.errors += 'Checkpoints: ' + (Limit-DiagnosticText $_.Exception.Message) }

# GUID literals are generated from System.Guid, never interpolated user strings.
# Only matching EventData is retained. Events with no exact GUID field (including
# some provider-wide errors) are intentionally omitted and this is reported.
$guidForms = @($vmGuid.ToLowerInvariant(), $vmGuid.ToUpperInvariant(), ('{' + $vmGuid.ToLowerInvariant() + '}'), ('{' + $vmGuid.ToUpperInvariant() + '}')) | Select-Object -Unique
$guidPredicate = ($guidForms | ForEach-Object { "Data='$_'" }) -join ' or '
$milliseconds = [int64]$LookBackMinutes * 60000
$eventXPath = "*[System[TimeCreated[timediff(@SystemTime) <= $milliseconds]] and EventData[$guidPredicate]]"
foreach ($logName in @('Microsoft-Windows-Hyper-V-VMMS-Admin', 'Microsoft-Windows-Hyper-V-VMMS-Operational', 'Microsoft-Windows-Hyper-V-Worker-Admin', 'Microsoft-Windows-Hyper-V-Worker-Operational')) {
    $logReport = [ordered]@{ logName = $logName; status = 'ok'; lookBackMinutes = $LookBackMinutes; selection = 'Exact VM GUID in EventData; messages without that field are omitted.'; truncated = $false; events = @(); error = $null }
    try {
        $events = @(Get-WinEvent -LogName $logName -FilterXPath $eventXPath -MaxEvents ($MaxEventsPerLog + 1) -ErrorAction Stop)
        $logReport.truncated = $events.Count -gt $MaxEventsPerLog
        $logReport.events = @($events | Select-Object -First $MaxEventsPerLog | ForEach-Object {
            $eventRecord = $_
            $message = $null
            try { $message = $eventRecord.FormatDescription() } catch { $message = '[Event message rendering unavailable]' }
            [pscustomobject]@{ timeCreatedUtc = $eventRecord.TimeCreated.ToUniversalTime().ToString('o'); id = $eventRecord.Id; recordId = $eventRecord.RecordId; level = $eventRecord.Level; provider = Limit-DiagnosticText $eventRecord.ProviderName 256; message = Limit-DiagnosticText $message }
        })
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $logReport.status = 'no-matching-events' }
        else { $logReport.status = 'unavailable'; $logReport.error = Limit-DiagnosticText $_.Exception.Message }
    }
    $report.eventLogs += [pscustomobject]$logReport
}

if (-not $SkipThumbnail) {
    $report.thumbnail = [ordered]@{
        status = 'unavailable'; width = 640; height = 480; geometrySource = 'requested, not returned'
        rawFormat = 'RGB565'; expectedByteCount = 640 * 480 * 2; actualByteCount = $null
        imageDataType = $null; imageDataIsNull = $null; outputProperties = @()
        returnedDimensions = @(); videoHeads = @(); videoHeadError = $null
        returnValue = $null; rawPath = $null; rawBytesSaved = 0; rawTruncated = $false
        pngPath = $null; error = $null
    }
    try {
        $namespace = 'root\virtualization\v2'
        $computers = @(Get-CimInstance -Namespace $namespace -ClassName Msvm_ComputerSystem -Filter "Name='$vmGuid'" -OperationTimeoutSec 10)
        if ($computers.Count -ne 1) { throw 'WMI did not identify exactly one computer matching the owned VM GUID.' }
        $settings = @(Get-CimAssociatedInstance -InputObject $computers[0] -Association Msvm_SettingsDefineState -ResultClassName Msvm_VirtualSystemSettingData -OperationTimeoutSec 10)
        if ($settings.Count -ne 1) { throw 'WMI did not identify exactly one current VM setting instance.' }
        try {
            $report.thumbnail.videoHeads = @(Get-CimInstance -Namespace $namespace -ClassName Msvm_VideoHead -Filter "SystemName='$vmGuid'" -OperationTimeoutSec 10 | Select-Object -First 8 | ForEach-Object {
                [pscustomobject]@{ deviceId = Limit-DiagnosticText $_.DeviceID 512; enabledState = [string]$_.EnabledState; width = $_.CurrentHorizontalResolution; height = $_.CurrentVerticalResolution; bitsPerPixel = $_.CurrentBitsPerPixel }
            })
        } catch { $report.thumbnail.videoHeadError = Limit-DiagnosticText $_.Exception.Message }
        $services = @(Get-CimInstance -Namespace $namespace -ClassName Msvm_VirtualSystemManagementService -OperationTimeoutSec 10)
        if ($services.Count -ne 1) { throw 'WMI virtual system management service is ambiguous or unavailable.' }
        $thumbnail = Invoke-CimMethod -InputObject $services[0] -MethodName GetVirtualSystemThumbnailImage -Arguments @{ TargetSystem = $settings[0]; WidthPixels = [uint16]640; HeightPixels = [uint16]480 } -OperationTimeoutSec 10
        # Record shape, not arbitrary output values or the pixel array in JSON.
        # This distinguishes empty/truncated buffers from unexpected adapters.
        $report.thumbnail.outputProperties = @($thumbnail.PSObject.Properties | Select-Object -First 32 | ForEach-Object {
            $property = $_
            $value = $property.Value
            [pscustomobject]@{ name = Limit-DiagnosticText $property.Name 128; type = Limit-DiagnosticText $property.TypeNameOfValue 256; isNull = $null -eq $value; elementCount = if ($value -is [Array]) { $value.LongLength } else { $null } }
        })
        # No dimensions are specified as outputs in the documented method.
        # Preserve any provider extension as an observation without trusting it.
        $report.thumbnail.returnedDimensions = @($thumbnail.PSObject.Properties | Where-Object Name -match '^(WidthPixels|HeightPixels|Width|Height|CurrentHorizontalResolution|CurrentVerticalResolution)$' | Select-Object -First 6 | ForEach-Object {
            [pscustomobject]@{ name = $_.Name; value = Limit-DiagnosticText $_.Value 64 }
        })
        $report.thumbnail.returnValue = [uint32]$thumbnail.ReturnValue
        $imageProperty = $thumbnail.PSObject.Properties['ImageData']
        if ($null -eq $imageProperty) { throw 'The result has no documented ImageData output property; see outputProperties.' }
        $pixels = $imageProperty.Value
        $report.thumbnail.imageDataIsNull = $null -eq $pixels
        if ($null -eq $pixels) { $report.thumbnail.actualByteCount = 0; throw 'Provider returned null ImageData.' }
        $report.thumbnail.imageDataType = $pixels.GetType().FullName
        if ($pixels -isnot [byte[]]) { throw 'ImageData is not the documented byte array; no speculative decoding was attempted.' }
        $report.thumbnail.actualByteCount = $pixels.LongLength
        # Retain the bounded payload before validating success or geometry.
        # A partial filename plus byte counts make prefix-only captures explicit.
        $saveCount = [int][Math]::Min($pixels.LongLength, 2MB)
        $report.thumbnail.rawTruncated = $saveCount -lt $pixels.LongLength
        $rawName = if ($report.thumbnail.rawTruncated) { 'thumbnail.rgb565.partial' } else { 'thumbnail.rgb565' }
        $rawPath = Join-Path $runRoot $rawName
        $rawFile = [IO.File]::Open($rawPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $rawFile.Write($pixels, 0, $saveCount) } finally { $rawFile.Dispose() }
        $report.thumbnail.rawPath = $rawPath; $report.thumbnail.rawBytesSaved = $saveCount
        $report.thumbnail.status = 'raw-captured-unverified'
        # Do not wait indefinitely, guess dimensions, or change VM state.
        if ($thumbnail.ReturnValue -ne 0) { throw "Thumbnail provider returned $($thumbnail.ReturnValue); only synchronous success is decoded." }
        if ($pixels.Length -ne $report.thumbnail.expectedByteCount) { throw "RGB565 byte count $($pixels.Length) differs from requested $($report.thumbnail.expectedByteCount); bounded raw data retained without decoding." }
        $pngPath = Join-Path $runRoot 'thumbnail.png'
        Write-Rgb565Png -Pixels $pixels -Width 640 -Height 480 -Path $pngPath
        $report.thumbnail.pngPath = $pngPath
        $report.thumbnail.status = 'captured'
    } catch { $report.thumbnail.error = Limit-DiagnosticText $_.Exception.Message }
}
$report.completedUtc = [DateTime]::UtcNow.ToString('o')
$reportPath = Join-Path $runRoot 'diagnostics.json'
$json = $report | ConvertTo-Json -Depth 8
$encoding = New-Object Text.UTF8Encoding($false)
if ($encoding.GetByteCount($json) -gt 7MB) { throw 'Diagnostic JSON exceeded its bounded output size; no JSON was written.' }
[IO.File]::WriteAllText($reportPath, $json, $encoding)
[pscustomobject]@{ ReportPath = $reportPath; VMId = $vmGuid; State = [string]$vm.State; Heartbeat = [string]$vm.Heartbeat; ThumbnailStatus = $report.thumbnail.status; ThumbnailPath = if ($report.thumbnail.Contains('pngPath')) { $report.thumbnail.pngPath } else { $null }; ReadOnlyVM = $true }
