Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1')

function Test-ControlCaptureExport {
    param([Parameter(Mandatory)]$Report, [Parameter(Mandatory)][string]$Directory)
    if (-not $Report.captureComplete) { return $false }
    foreach ($capture in @(@{name='empty';record=$Report.emptyImage},@{name='control';record=$Report.image})) {
        $file = Get-Item -LiteralPath (Join-Path $Directory ($capture.name + '.raw')) -ErrorAction Stop
        $sidecar = Get-Content -LiteralPath (Join-Path $Directory ($capture.name + '.raw.json')) -Raw | ConvertFrom-Json
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($file.PSIsContainer -or $file.Length -ne 1GB -or $sidecar.status -cne 'complete' -or $sidecar.length -ne 1GB -or $capture.record.status -cne 'complete' -or $capture.record.length -ne 1GB -or $hash -cne $sidecar.sha256 -or $hash -cne $capture.record.sha256 -or $sidecar.target.uniqueId -cne $Report.target.uniqueId -or $sidecar.fileSystem -cne $Report.filesystem) { throw 'Exported capture failed identity, length, status, or SHA-256 verification.' }
    }
    $true
}

function Export-LabNativeControlArtifacts {
    param(
        [Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory)][string]$ManifestDirectory,
        [Parameter(Mandatory)][string]$CaptureDirectory,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$LabRoot,
        [Parameter(Mandatory)]$Report
    )
    if ($Session.State -ne 'Opened') { throw 'An authenticated open guest session is required for export.' }
    if ($Report.filesystem -cnotin @('NTFS','ReFS') -or $ManifestDirectory -cne ('C:\ntfs2refs\control-' + $Report.filesystem.ToLowerInvariant()) -or $CaptureDirectory -cnotmatch '^[D-Z]:\\native-control$') { throw 'Unexpected native-control export directories.' }
    $destinationRoot = Assert-LabPath $Destination $LabRoot
    $manifestDestination = Assert-LabPath (Join-Path $destinationRoot 'guest-manifests') $LabRoot
    if (Test-Path -LiteralPath $manifestDestination) { throw 'Manifest export destination already exists; no overwrite is allowed.' }
    if (Test-Path -LiteralPath (Join-Path $destinationRoot 'exported-files.json')) { throw 'Export inventory already exists.' }
    $inventory = @(Invoke-Command -Session $Session -ArgumentList $ManifestDirectory,$CaptureDirectory -ErrorAction Stop -ScriptBlock {
        param($ManifestDirectory,$CaptureDirectory)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $manifestNames = @('target.json','journal.json','result.json')
        $captureNames = @('empty.raw','empty.raw.partial','empty.raw.json','control.raw','control.raw.partial','control.raw.json','native-evidence.json')
        $total = [int64]0
        foreach ($group in @(@{name='manifest';path=$ManifestDirectory;allowed=$manifestNames},@{name='capture';path=$CaptureDirectory;allowed=$captureNames})) {
            $directory = Get-Item -LiteralPath $group.path -Force -ErrorAction Stop
            if (-not $directory.PSIsContainer -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Export directory is missing, non-directory, or a reparse point.' }
            $files = @(Get-ChildItem -LiteralPath $directory.FullName -Force -ErrorAction Stop)
            if ($group.name -ceq 'manifest' -and $files.Count -ne 3) { throw 'Expected exactly three control manifest files.' }
            foreach ($file in $files) {
                if ($file.PSIsContainer -or $file.Name -cnotin $group.allowed -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected file, directory, or reparse point in control artifacts.' }
                $limit = if ($file.Name -cmatch '\.raw(?:\.partial)?$') { 1GB } else { 16MB }
                if ($file.Length -gt $limit) { throw 'Artifact exceeds its bounded export size.' }
                $total += $file.Length
                if ($total -gt (2GB + 32MB)) { throw 'Control export exceeds its total size bound.' }
                [pscustomobject]@{ group=$group.name; name=$file.Name; length=[int64]$file.Length; sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
            }
        }
    })
    New-Item -ItemType Directory -Path $manifestDestination | Out-Null
    foreach ($file in $inventory) {
        $sourceDirectory = if ($file.group -ceq 'manifest') { $ManifestDirectory } elseif ($file.group -ceq 'capture') { $CaptureDirectory } else { throw 'Unknown artifact group.' }
        if ($file.name -cnotmatch '^(?:target\.json|journal\.json|result\.json|(?:empty|control)\.raw(?:\.partial|\.json)?|native-evidence\.json)$' -or $file.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $file.length -lt 0 -or $file.length -gt 1GB) { throw 'Unexpected remote inventory entry.' }
        $localDirectory = if ($file.group -ceq 'manifest') { $manifestDestination } else { $destinationRoot }
        $localPath = Assert-LabPath (Join-Path $localDirectory $file.name) $LabRoot
        if (Test-Path -LiteralPath $localPath) { throw 'Artifact destination already exists; no overwrite is allowed.' }
        # PS5's injected remote helper reads .Length even for DirectoryInfo.
        # Copy only explicitly enumerated files, never a directory or -Recurse.
        Copy-Item -LiteralPath (Join-Path $sourceDirectory $file.name) -Destination $localPath -FromSession $Session -ErrorAction Stop
        $copied = Get-Item -LiteralPath $localPath -ErrorAction Stop
        if ($copied.PSIsContainer -or $copied.Length -ne $file.length -or (Get-FileHash -LiteralPath $localPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $file.sha256) { throw 'Exported artifact failed length/SHA-256 verification; guest state retained.' }
    }
    $captureValidated = Test-ControlCaptureExport -Report $Report -Directory $destinationRoot
    $inventory | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $destinationRoot 'exported-files.json') -Encoding UTF8
    [pscustomobject]@{ captureValidated=$captureValidated; fileCount=$inventory.Count; directory=$destinationRoot }
}

Export-ModuleMember -Function Export-LabNativeControlArtifacts
