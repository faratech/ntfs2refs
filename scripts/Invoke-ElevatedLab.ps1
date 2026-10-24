# A bounded lab operation using standard Windows UAC, without a persistent service.
[CmdletBinding()]
param([ValidateSet('Provision','Status','InstallAndInitialize','RepairAndInitialize','ResumeAndTest','NativeControls','Diagnostics','CompleteBaselineAndTest','NativeResearch','RecoverNativeResearch','NativeFormatCom','NativeDevDrive','NativeDevDriveCorpus','NativeExtentDiscovery','NativeExtentPlacement','NativeRangeRead','NativeProtectedRangeRead','NativeVdlProbe','NativeVdlObservation','RustRetainedCompare','GuestStorage')][string]$Action = 'Status')
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'lab\Lab.psm1') -Force
$config = Get-LabConfiguration
$directory = Assert-LabPath (Join-Path $config.Root 'host-results') $config.Root
New-Item -ItemType Directory -Path $directory -Force | Out-Null
$path = Assert-LabPath (Join-Path $directory ($Action + '.json')) $config.Root
if (Test-Path -LiteralPath $path) {
    $archive = Assert-LabPath (Join-Path $directory ($Action + '-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '.json')) $config.Root
    Copy-Item -LiteralPath $path -Destination $archive -ErrorAction Stop
}
$workspace = Split-Path $PSScriptRoot -Parent
$sourceFiles = @(
    Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File
    Get-ChildItem -LiteralPath (Join-Path $workspace 'lab') -File
    Get-ChildItem -LiteralPath (Join-Path $workspace 'lab\guest') -File
    Get-Item -LiteralPath (Join-Path $workspace 'target\release\ntfs2refs.exe') -ErrorAction SilentlyContinue
)
$sourceHashes = @($sourceFiles | ForEach-Object {
    [pscustomobject]@{ path=$_.FullName.Substring($workspace.Length + 1); sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
})
$record = [ordered]@{ action=$Action; processId=$PID; startedUtc=[DateTime]::UtcNow.ToString('o'); state='running'; sourceHashes=$sourceHashes; result=$null; error=$null }
$record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Standard UAC elevation is required.' }
    if ($Action -eq 'Provision') {
        $record.result = Invoke-LabAction -Action Create -Lane win11 -IsoPath 'C:\Users\mfara\Downloads\Windows11_Client_x64_en-us_26300_9457.iso' -Confirm:$false
    } elseif ($Action -in @('InstallAndInitialize','RepairAndInitialize')) {
        if ($Action -eq 'RepairAndInitialize') { & (Join-Path $PSScriptRoot 'Repair-LabInstall.ps1') -Confirm:$false }
        $installed = & (Join-Path $PSScriptRoot 'Install-LabWindows.ps1') -Confirm:$false
        $initialized = & (Join-Path $PSScriptRoot 'Initialize-LabGuest.ps1') -Confirm:$false
        $record.result = [pscustomobject]@{ Installation = $installed; Initialization = $initialized }
    } elseif ($Action -eq 'ResumeAndTest') {
        $installed = & (Join-Path $PSScriptRoot 'Install-LabWindows.ps1') -ResumeAppliedImage -Confirm:$false
        $initialized = & (Join-Path $PSScriptRoot 'Initialize-LabGuest.ps1') -Confirm:$false
        $controls = & (Join-Path $PSScriptRoot 'Invoke-LabNativeControls.ps1') -Confirm:$false
        $record.result = [pscustomobject]@{ Installation=$installed; Initialization=$initialized; NativeControls=$controls }
    } elseif ($Action -eq 'NativeControls') {
        $record.result = & (Join-Path $PSScriptRoot 'Invoke-LabNativeControls.ps1') -Confirm:$false
    } elseif ($Action -eq 'Diagnostics') {
        $record.result = & (Join-Path $PSScriptRoot 'Get-LabBootDiagnostics.ps1') -Confirm:$false
    } elseif ($Action -eq 'GuestStorage') {
        $record.result = & (Join-Path $PSScriptRoot 'Get-LabGuestStorageEvidence.ps1') -Confirm:$false
    } elseif ($Action -eq 'NativeDevDrive') {
        $record.result = & (Join-Path $PSScriptRoot 'Invoke-LabDevDriveControl.ps1') -Confirm:$false
    } elseif ($Action -eq 'NativeDevDriveCorpus') {
        $record.result = & (Join-Path $PSScriptRoot 'Export-LabDevDriveImage.ps1') -ControlDirectory (Join-Path $config.Root 'devdrive\win11-20261023T230635404Z') -Confirm:$false
    } elseif ($Action -eq 'NativeExtentDiscovery') {
        $record.result = & (Join-Path $PSScriptRoot 'Invoke-LabExtentDiscovery.ps1') -Confirm:$false
    } elseif ($Action -eq 'NativeExtentPlacement') {
        $record.result = & (Join-Path $PSScriptRoot 'Invoke-LabExtentPlacement.ps1') -Confirm:$false
    } elseif ($Action -eq 'NativeRangeRead') {
        $record.result = & (Join-Path $PSScriptRoot 'Invoke-LabRangeRead.ps1') -Confirm:$false
    } elseif ($Action -eq 'NativeProtectedRangeRead') {
        $record.result = & (Join-Path $PSScriptRoot 'Invoke-LabProtectedRangeRead.ps1') -Confirm:$false
    } elseif ($Action -eq 'NativeVdlProbe') {
        $record.result = & (Join-Path $PSScriptRoot 'Invoke-LabVdlProbe.ps1') -Confirm:$false
    } elseif ($Action -eq 'NativeVdlObservation') {
        $record.result = & (Join-Path $PSScriptRoot 'Invoke-LabVdlObservation.ps1') -Confirm:$false
    } elseif ($Action -eq 'RustRetainedCompare') {
        $record.result = & (Join-Path $PSScriptRoot 'Invoke-LabRetainedCompare.ps1') -Confirm:$false
    } elseif ($Action -eq 'NativeFormatCom') {
        $record['phase'] = 'format-com-refs-os-preparation'
        $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
        $prepared = & (Join-Path $PSScriptRoot 'Prepare-LabRefsBootControl.ps1') -FormatMethod FormatCom -Confirm:$false
        $record.result = [pscustomobject]@{ NativeRefsPreparation=$prepared; NativeRefsBootObservation=$null }
        $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
        if ($prepared.Status -ceq 'prepared-awaiting-separate-boot-validation' -and $prepared.BaselineRestored) {
            $record['phase'] = 'native-refs-os-boot-observation'
            $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
            $record.result.NativeRefsBootObservation = & (Join-Path $PSScriptRoot 'Test-LabRefsBootControl.ps1') -PreparationDirectory $prepared.Evidence -Confirm:$false
        }
    } elseif ($Action -eq 'CompleteBaselineAndTest') {
        $record['phase'] = 'complete-baseline'
        $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
        $baseline = & (Join-Path $PSScriptRoot 'Complete-LabBaseline.ps1') -Confirm:$false
        $record['phase'] = 'native-data-controls'
        $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
        $controls = & (Join-Path $PSScriptRoot 'Invoke-LabNativeControls.ps1') -Confirm:$false
        $record['phase'] = 'native-refs-os-preparation'
        $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
        $prepared = & (Join-Path $PSScriptRoot 'Prepare-LabRefsBootControl.ps1') -Confirm:$false
        $record.result = [pscustomobject]@{ Baseline=$baseline; NativeControls=$controls; NativeRefsPreparation=$prepared }
    } elseif ($Action -in @('NativeResearch','RecoverNativeResearch')) {
        if ($Action -eq 'RecoverNativeResearch') {
            $record['phase'] = 'recover-native-control-export'
            $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
            $record['recovery'] = & (Join-Path $PSScriptRoot 'Recover-LabNativeControlExport.ps1') -Confirm:$false
            $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
        }
        $record['phase'] = 'native-data-controls'
        $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
        $controls = & (Join-Path $PSScriptRoot 'Invoke-LabNativeControls.ps1') -Confirm:$false
        $record['phase'] = 'native-refs-os-preparation'
        $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
        $prepared = & (Join-Path $PSScriptRoot 'Prepare-LabRefsBootControl.ps1') -Confirm:$false
        $record.result = [pscustomobject]@{ NativeControls=$controls; NativeRefsPreparation=$prepared; NativeRefsBootObservation=$null }
        $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
        if ($prepared.Status -ceq 'prepared-awaiting-separate-boot-validation' -and $prepared.BaselineRestored) {
            $record['phase'] = 'native-refs-os-boot-observation'
            $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
            $record.result.NativeRefsBootObservation = & (Join-Path $PSScriptRoot 'Test-LabRefsBootControl.ps1') -PreparationDirectory $prepared.Evidence -Confirm:$false
        }
    } else { $record.result = Invoke-LabAction -Action Status }
    $record.state = 'complete'
} catch { $record.state = 'failed'; $record.error = $_.Exception.Message }
$record['finishedUtc'] = [DateTime]::UtcNow.ToString('o')
$record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
if ($record.state -ne 'complete') { exit 1 }
