Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-LabPath {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Root)
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $base = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    if ($full -eq $base -or -not $full.StartsWith($base + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw "Path must be a child of the intended lab root: $full" }
    $cursor = $full
    while ($cursor -and $cursor.Length -ge $base.Length) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Lab paths must not traverse a reparse point: $cursor" }
        }
        $parent = Split-Path $cursor -Parent
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    $full
}

function Get-LabConfiguration {
    param([string]$WorkspaceRoot = (Split-Path $PSScriptRoot -Parent))
    $workspace = [IO.Path]::GetFullPath($WorkspaceRoot)
    $config = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'lab.config.json') -Raw | ConvertFrom-Json
    if ($config.schemaVersion -ne 1) { throw 'Unsupported lab configuration version.' }
    $root = Assert-LabPath -Path (Join-Path $workspace $config.relativeRoot) -Root $workspace
    [pscustomobject]@{ Workspace = $workspace; Root = $root; Settings = $config }
}

function Get-LabCapacity {
    param([Parameter(Mandatory)]$Configuration)
    $total = [int64]0
    if (Test-Path -LiteralPath $Configuration.Root) {
        $pending = New-Object 'System.Collections.Generic.Queue[string]'
        $pending.Enqueue($Configuration.Root)
        while ($pending.Count) {
            foreach ($item in Get-ChildItem -LiteralPath $pending.Dequeue() -Force) {
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point found in lab: $($item.FullName)" }
                if ($item.PSIsContainer) { $pending.Enqueue($item.FullName) } else { $total += $item.Length }
            }
        }
    }
    $drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($Configuration.Root))
    [pscustomobject]@{ ActualBytes = $total; FreeBytes = $drive.AvailableFreeSpace; MaximumActualBytes = [int64]$Configuration.Settings.maximumActualBytes; MinimumFreeBytes = [int64]$Configuration.Settings.minimumHostFreeBytes }
}

function Assert-LabCapacity {
    param([Parameter(Mandatory)]$Capacity, [int64]$AdditionalBytes = 0)
    if ($AdditionalBytes -lt 0) { throw 'Additional capacity cannot be negative.' }
    if ($Capacity.ActualBytes -gt ($Capacity.MaximumActualBytes - $AdditionalBytes)) { throw 'Lab allocation budget would be exceeded.' }
    if (($Capacity.FreeBytes - $AdditionalBytes) -lt $Capacity.MinimumFreeBytes) { throw 'Host free-space reserve would be breached.' }
}

function Assert-HyperVAccess {
    Import-Module Hyper-V -ErrorAction Stop
    try { Get-VMHost -ErrorAction Stop | Out-Null }
    catch { throw 'Hyper-V management access is unavailable. Run this reviewed script from an elevated PowerShell session or an authorized Hyper-V Administrators session.' }
}

function Read-LabManifest {
    param([Parameter(Mandatory)]$Configuration, [Parameter(Mandatory)][ValidateSet('win11','server')][string]$Lane)
    $path = Assert-LabPath -Path (Join-Path $Configuration.Root "$Lane\manifest.json") -Root $Configuration.Root
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    $manifest = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($manifest.schemaVersion -ne 1 -or $manifest.lane -ne $Lane -or $manifest.vmName -ne $Configuration.Settings.lanes.$Lane.name) { throw 'Lab manifest identity/version mismatch.' }
    foreach ($disk in $manifest.disks) { Assert-LabPath -Path $disk.path -Root $Configuration.Root | Out-Null }
    $manifest
}

function Assert-LabOwnership {
    param([Parameter(Mandatory)]$Manifest, [Parameter(Mandatory)]$VM, [Parameter(Mandatory)][object[]]$AttachedDrives)
    if ([string]$VM.Id -ne [string]$Manifest.vmId -or $VM.Name -ne $Manifest.vmName -or $VM.Generation -ne 2) { throw 'VM identity does not match the lab manifest; refusing to adopt or modify it.' }
    if ([IO.Path]::GetFullPath($VM.Path).TrimEnd('\') -ne [IO.Path]::GetFullPath($Manifest.vmPath).TrimEnd('\')) { throw 'VM configuration path changed.' }
    if ($AttachedDrives.Count -ne $Manifest.disks.Count) { throw 'The VM has unexpected disk attachments.' }
    foreach ($disk in $Manifest.disks) {
        $attached = @($AttachedDrives | Where-Object { [string]$_.Path -eq [string]$disk.path -and $_.ControllerNumber -eq 0 -and $_.ControllerLocation -eq $disk.controllerLocation })
        if ($attached.Count -ne 1) { throw "Disk attachment differs from the recorded path for $($disk.role)." }
    }
}

function Get-OwnedLabVM {
    param([Parameter(Mandatory)]$Configuration, [Parameter(Mandatory)]$Manifest, [ValidateRange(1,30)][int]$Attempts = 15, [ValidateRange(0,2000)][int]$DelayMilliseconds = 1000)
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
    try {
    $vm = Get-VM -Id ([guid]$Manifest.vmId) -ErrorAction Stop
    if ([string]$vm.Id -ne [string]$Manifest.vmId -or $vm.Name -ne $Manifest.vmName -or $vm.Generation -ne 2 -or [IO.Path]::GetFullPath($vm.Path).TrimEnd('\') -ne [IO.Path]::GetFullPath($Manifest.vmPath).TrimEnd('\')) { throw 'VM identity or configuration path differs from the lab manifest.' }
    $normalized = @()
    foreach ($drive in @(Get-VMHardDiskDrive -VM $vm)) {
        $cursor = Assert-LabPath -Path $drive.Path -Root $Configuration.Root
        $seen = @{}
        do {
            if ($seen.ContainsKey($cursor)) { throw 'Cycle in VHD parent chain.' }
            $seen[$cursor] = $true
            try { $vhd = Get-VHD -Path $cursor -ErrorAction Stop }
            catch {
                # A checkpoint/restore can briefly expose the previous AVHDX
                # attachment after that file has been removed. Retry only that
                # bounded missing-differencing-disk condition, then start every
                # VM/path/attachment/parent-chain/identity check again.
                if ([IO.Path]::GetExtension($cursor) -ieq '.avhdx' -and -not (Test-Path -LiteralPath $cursor -PathType Leaf -ErrorAction Stop)) {
                    $missing = New-Object IO.FileNotFoundException('A checkpoint AVHDX is temporarily absent; complete ownership revalidation is required.', $cursor)
                    $missing.Data['LabMissingCheckpointVhd'] = $true
                    throw $missing
                }
                throw
            }
            if ($vhd.ParentPath) { $cursor = Assert-LabPath -Path $vhd.ParentPath -Root $Configuration.Root }
        } while ($vhd.ParentPath)
        $matching = @($Manifest.disks | Where-Object { $_.path -eq $cursor })
        if ($matching.Count -ne 1 -or [string]$vhd.DiskIdentifier -ne [string]$matching[0].vhdId -or $vhd.Size -ne $matching[0].sizeBytes) { throw 'VHD identity, size, or parent chain differs from the lab manifest.' }
        $normalized += [pscustomobject]@{ Path = $cursor; ControllerNumber = $drive.ControllerNumber; ControllerLocation = $drive.ControllerLocation }
    }
    Assert-LabOwnership -Manifest $Manifest -VM $vm -AttachedDrives $normalized
    return $vm
    } catch {
        if (-not $_.Exception.Data.Contains('LabMissingCheckpointVhd') -or $attempt -eq $Attempts) { throw }
        Start-Sleep -Milliseconds $DelayMilliseconds
    }
    }
}

function Get-ExactLabCheckpoint {
    param(
        [Parameter(Mandatory)]$VM,
        [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$')][string]$Name,
        [ValidateRange(1,30)][int]$Attempts = 15,
        [ValidateRange(0,2000)][int]$DelayMilliseconds = 1000
    )
    # Hyper-V may briefly omit a just-created checkpoint from enumeration.
    # Only an empty exact-name result is retryable; duplicates/provider errors
    # are immediately refused and never select an arbitrary checkpoint.
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        $checkpointMatches = @(Get-VMCheckpoint -VM $VM -ErrorAction Stop | Where-Object { $_.Name -ceq $Name })
        if ($checkpointMatches.Count -gt 1) { throw 'The exact checkpoint name identifies multiple checkpoints.' }
        if ($checkpointMatches.Count -eq 1) { return $checkpointMatches[0] }
        if ($attempt -lt $Attempts) { Start-Sleep -Milliseconds $DelayMilliseconds }
    }
    throw 'The exact checkpoint name must identify one checkpoint; bounded lookup expired.'
}

function Initialize-LabGuestSession {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session)
    if ($Session.State -ne 'Opened') { throw 'An authenticated open guest PSSession is required.' }
    # Return evidence even on refusal; callers must require status=ready before
    # importing any guest module or invoking a script file.
    Invoke-Command -Session $Session -ErrorAction Stop -ScriptBlock {
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $record = [ordered]@{ schemaVersion = 1; status = 'refused'; computerName = $env:COMPUTERNAME; changeAttempted = $false; changed = $false; changedScope = $null; before = $null; after = $null; error = $null; capturedUtc = [DateTime]::UtcNow.ToString('o') }
        try {
            $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
            if ($env:COMPUTERNAME -cne 'N2R-WIN11' -or $computer.Manufacturer -cne 'Microsoft Corporation' -or $computer.Model -cne 'Virtual Machine') { throw 'Session does not identify the expected disposable Hyper-V guest.' }
            $scopes = @('MachinePolicy','UserPolicy','Process','CurrentUser','LocalMachine')
            $beforePolicies = @(Get-ExecutionPolicy -List -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ scope = [string]$_.Scope; policy = [string]$_.ExecutionPolicy } })
            $beforeEffective = [string](Get-ExecutionPolicy -ErrorAction Stop)
            $record.before = [pscustomobject]@{ effective = $beforeEffective; scopes = $beforePolicies }
            if ($beforePolicies.Count -ne $scopes.Count) { throw 'Execution policy scope inventory is incomplete.' }
            foreach ($scope in $scopes) { if (@($beforePolicies | Where-Object scope -ceq $scope).Count -ne 1) { throw 'Execution policy scopes are missing or ambiguous.' } }
            if ($beforeEffective -ceq 'RemoteSigned') {
                # Preserve an already-effective RemoteSigned policy at any scope.
            } elseif ($beforeEffective -ceq 'Restricted' -and @($beforePolicies | Where-Object policy -cne 'Undefined').Count -eq 0) {
                $record.changeAttempted = $true
                $record.changed = $null
                $record.changedScope = 'Process'
                Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force -ErrorAction Stop
                $record.changed = $true
            } else { throw 'Configured or unexpected execution policy is preserved; session initialization refused.' }
            $afterPolicies = @(Get-ExecutionPolicy -List -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ scope = [string]$_.Scope; policy = [string]$_.ExecutionPolicy } })
            $afterEffective = [string](Get-ExecutionPolicy -ErrorAction Stop)
            $record.after = [pscustomobject]@{ effective = $afterEffective; scopes = $afterPolicies }
            if ($afterPolicies.Count -ne $scopes.Count) { throw 'Post-initialization policy scope inventory is incomplete.' }
            foreach ($scope in $scopes) { if (@($afterPolicies | Where-Object scope -ceq $scope).Count -ne 1) { throw 'Post-initialization policy scopes are missing or ambiguous.' } }
            if ($afterEffective -cne 'RemoteSigned') { throw 'Guest process policy did not become effective RemoteSigned.' }
            if ($record.changed) {
                if ($afterPolicies.Count -ne $scopes.Count -or @($afterPolicies | Where-Object { $_.scope -ceq 'Process' -and $_.policy -ceq 'RemoteSigned' }).Count -ne 1 -or @($afterPolicies | Where-Object { $_.scope -cne 'Process' -and $_.policy -cne 'Undefined' }).Count -ne 0) { throw 'Guest policy verification observed a change beyond the intended process scope.' }
            }
            $record.status = 'ready'
        } catch {
            $record.error = $_.Exception.Message
            if ($record.before -and -not $record.after) {
                try {
                    $observedPolicies = @(Get-ExecutionPolicy -List -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ scope = [string]$_.Scope; policy = [string]$_.ExecutionPolicy } })
                    $record.after = [pscustomobject]@{ effective = [string](Get-ExecutionPolicy -ErrorAction Stop); scopes = $observedPolicies }
                } catch { $record.after = [pscustomobject]@{ effective = 'Unknown'; scopes = @(); error = $_.Exception.Message } }
            }
        }
        [pscustomobject]$record
    }
}

function Import-LabMedia {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)]$Configuration, [Parameter(Mandatory)][string]$IsoPath)
    $iso = Get-Item -LiteralPath $IsoPath -ErrorAction Stop
    if ($iso.PSIsContainer -or $iso.Extension -ne '.iso' -or $iso.Length -lt 1048576) { throw 'Supply a completed ISO file, not a partial download.' }
    if (-not $PSCmdlet.ShouldProcess($iso.FullName, 'Hash ISO and record media identity under the lab directory')) { return }
    Assert-LabCapacity (Get-LabCapacity $Configuration) -AdditionalBytes 16777216
    $length = $iso.Length; $modified = $iso.LastWriteTimeUtc
    $hash = (Get-FileHash -LiteralPath $iso.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $after = Get-Item -LiteralPath $iso.FullName
    if ($length -ne $after.Length -or $modified -ne $after.LastWriteTimeUtc) { throw 'ISO changed during hashing.' }
    $mediaRoot = Assert-LabPath -Path (Join-Path $Configuration.Root "media\$hash") -Root $Configuration.Root
    New-Item -ItemType Directory -Path $mediaRoot -Force | Out-Null
    $setupVersion = $null; $setupSignature = $null
    $sevenZip = @('C:\Program Files\7-Zip\7z.exe','C:\Program Files (x86)\7-Zip\7z.exe') | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($sevenZip) {
        $listing = & $sevenZip l '-slt' '--' $iso.FullName 2>&1
        if ($LASTEXITCODE -ne 0) { throw '7-Zip could not read the ISO directory.' }
        $listing | Set-Content -LiteralPath (Join-Path $mediaRoot 'iso-directory.txt') -Encoding UTF8
        & $sevenZip e '-y' ("-o" + $mediaRoot) '--' $iso.FullName 'setup.exe' | Out-Null
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath (Join-Path $mediaRoot 'setup.exe'))) {
            $setup = Get-Item -LiteralPath (Join-Path $mediaRoot 'setup.exe')
            $setupVersion = $setup.VersionInfo.FileVersion
            $setupSignature = [string](Get-AuthenticodeSignature -LiteralPath $setup.FullName).Status
        }
    }
    $imageInfo = $null
    if ($sevenZip) { $imageInfo = & (Join-Path $Configuration.Workspace 'scripts\Get-IsoImageInfo.ps1') -IsoPath $iso.FullName -PassThru }
    $record = [pscustomobject]@{ schemaVersion = 1; isoPath = $iso.FullName; sha256 = $hash; length = $length; lastWriteUtc = $modified.ToString('o'); setupFileVersion = $setupVersion; setupSignatureStatus = $setupSignature; installImages = $imageInfo; installedOsBuild = $null; note = 'Install-image metadata is verified from the WIM XML; capture the actually installed and serviced build from the guest as well.' }
    $record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $mediaRoot 'media.json') -Encoding UTF8
    $record
}

function Invoke-LabAction {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][ValidateSet('Status','Media','Create','Start','Stop','Checkpoint','Restore','ExportBaseline','ExportLogs')][string]$Action,
        [ValidateSet('win11','server')][string]$Lane = 'win11',
        [string]$IsoPath, [string]$CheckpointName, [string]$LogSource,
        [string]$WorkspaceRoot = (Split-Path $PSScriptRoot -Parent)
    )
    $configuration = Get-LabConfiguration $WorkspaceRoot
    $name = $configuration.Settings.lanes.$Lane.name
    $laneRoot = Assert-LabPath -Path (Join-Path $configuration.Root $Lane) -Root $configuration.Root
    $capacity = Get-LabCapacity $configuration
    if ($Action -eq 'Status') {
        $access = $true; $errorText = $null; $vms = @()
        try { Assert-HyperVAccess; $vms = @(Get-VM | Where-Object { $_.Name -in @('ntfs2refs-win11','ntfs2refs-server') } | Select-Object Name,Id,State,Generation) } catch { $access = $false; $errorText = $_.Exception.Message }
        return [pscustomobject]@{ Root = $configuration.Root; Capacity = $capacity; HyperVAccess = $access; AccessError = $errorText; VMs = $vms }
    }
    if ($Action -eq 'Media') {
        if (-not $IsoPath) { throw 'Media requires -IsoPath.' }
        Import-LabMedia -Configuration $configuration -IsoPath $IsoPath -WhatIf:$WhatIfPreference
        return
    }
    if ($Action -eq 'Create' -and (-not $IsoPath -or -not (Test-Path -LiteralPath $IsoPath -PathType Leaf))) { throw 'Create requires completed installation media in -IsoPath. Each lane can be created independently.' }
    if ($Action -in @('Checkpoint','Restore','ExportBaseline') -and [string]::IsNullOrWhiteSpace($CheckpointName)) { throw "$Action requires an exact -CheckpointName." }
    if ($CheckpointName -and ($CheckpointName.Length -gt 80 -or $CheckpointName -notmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]*$')) { throw 'Checkpoint name must be 1-80 letters, numbers, dots, underscores, or hyphens.' }
    if (-not $PSCmdlet.ShouldProcess("$name at $laneRoot", "$Action (checkpoint: $CheckpointName)")) { return [pscustomobject]@{ Action = $Action; Lane = $Lane; VMName = $name; Root = $laneRoot; Checkpoint = $CheckpointName; DryRun = $true } }
    Assert-HyperVAccess
    Assert-LabCapacity $capacity
    $manifest = Read-LabManifest -Configuration $configuration -Lane $Lane
    if ($Action -eq 'Create') {
        if ($manifest) { return Get-OwnedLabVM -Configuration $configuration -Manifest $manifest }
        if (Get-VM -Name $name -ErrorAction SilentlyContinue) { throw 'A VM with this name exists without a matching ownership manifest.' }
        if (Test-Path -LiteralPath $laneRoot) { throw "Unowned or incomplete lab directory already exists: $laneRoot. Inspect it before retrying; no automatic deletion is performed." }
        Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 134217728
        $media = Import-LabMedia -Configuration $configuration -IsoPath $IsoPath -Confirm:$false
        New-Item -ItemType Directory -Path $laneRoot | Out-Null
        $vhdRoot = Assert-LabPath -Path (Join-Path $laneRoot 'disks') -Root $configuration.Root
        New-Item -ItemType Directory -Path $vhdRoot | Out-Null
        [pscustomobject]@{ vmName = $name; lane = $Lane; state = 'provisioning'; createdUtc = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $laneRoot 'provisioning.json') -Encoding UTF8
        $vm = New-VM -Name $name -Generation 2 -MemoryStartupBytes $configuration.Settings.memoryBytes -Path $laneRoot -NoVHD
        Set-VM -VM $vm -ProcessorCount $configuration.Settings.processorCount -AutomaticCheckpointsEnabled $false -CheckpointType Standard -AutomaticStartAction Nothing -AutomaticStopAction ShutDown
        Set-VMMemory -VM $vm -DynamicMemoryEnabled $false
        Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
        Set-VMKeyProtector -VM $vm -NewLocalKeyProtector
        Enable-VMTPM -VM $vm
        Get-VMNetworkAdapter -VM $vm | Disconnect-VMNetworkAdapter
        $disks = @()
        foreach ($definition in $configuration.Settings.disks) {
            Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 33554432
            $path = Assert-LabPath -Path (Join-Path $vhdRoot ($definition.role + '.vhdx')) -Root $configuration.Root
            $disk = New-VHD -Path $path -Dynamic -SizeBytes $definition.sizeBytes -LogicalSectorSizeBytes 512 -PhysicalSectorSizeBytes 4096
            Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -ControllerNumber 0 -ControllerLocation $definition.controllerLocation -Path $path
            $disks += [pscustomobject]@{ role = $definition.role; path = $path; sizeBytes = [int64]$definition.sizeBytes; vhdId = [string]$disk.DiskIdentifier; controllerLocation = $definition.controllerLocation }
        }
        $dvd = Add-VMDvdDrive -VM $vm -Path $media.isoPath -Passthru
        Set-VMFirmware -VM $vm -FirstBootDevice $dvd
        $manifest = [pscustomobject]@{ schemaVersion = 1; lane = $Lane; vmName = $name; vmId = [string]$vm.Id; vmPath = $vm.Path; disks = $disks; media = $media; createdUtc = [DateTime]::UtcNow.ToString('o') }
        $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $laneRoot 'manifest.json') -Encoding UTF8
        [pscustomobject]@{ vmName = $name; lane = $Lane; state = 'complete'; vmId = [string]$vm.Id } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $laneRoot 'provisioning.json') -Encoding UTF8
        return $manifest
    }
    if (-not $manifest) { throw 'No ownership manifest exists for this lane. Create it first.' }
    $vm = Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    switch ($Action) {
        'Start' {
            $other = @(Get-VM | Where-Object { $_.Name -in @('ntfs2refs-win11','ntfs2refs-server') -and $_.Id -ne $vm.Id -and $_.State -ne 'Off' })
            if ($other.Count) { throw 'Only one lab VM may run at a time; shut down the other lane first.' }
            if ($vm.State -ne 'Off') { throw 'Start requires a powered-off VM.' }
            Start-VM -VM $vm
        }
        'Stop' { Stop-VM -VM $vm -Confirm:$false }
        'Checkpoint' {
            if ($vm.State -ne 'Off') { throw 'Checkpoints require a cleanly powered-off VM.' }
            if (Get-VMCheckpoint -VM $vm -Name $CheckpointName -ErrorAction SilentlyContinue) { throw 'That checkpoint name already exists.' }
            Checkpoint-VM -VM $vm -SnapshotName $CheckpointName
            $validated = Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
            if ($validated.State -ne 'Off') { throw 'Checkpoint ownership validation requires the VM to remain off.' }
        }
        'Restore' {
            if ($vm.State -ne 'Off') { throw 'Restore requires a powered-off VM.' }
            $checkpoint = Get-ExactLabCheckpoint -VM $vm -Name $CheckpointName
            Restore-VMCheckpoint -VMSnapshot $checkpoint -Confirm:$false
            $validated = Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
            if ($validated.State -ne 'Off') { throw 'Restore ownership validation requires the VM to remain off.' }
        }
        'ExportBaseline' {
            if ($vm.State -ne 'Off') { throw 'Baseline export requires a powered-off VM.' }
            $checkpoint = Get-ExactLabCheckpoint -VM $vm -Name $CheckpointName
            $laneBytes = (Get-ChildItem -LiteralPath $laneRoot -Recurse -File | Measure-Object Length -Sum).Sum
            Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes ([int64]$laneBytes)
            $destination = Assert-LabPath -Path (Join-Path $configuration.Root ("exports\$Lane-$CheckpointName")) -Root $configuration.Root
            if (Test-Path -LiteralPath $destination) { throw 'Export destination already exists.' }
            Export-VMSnapshot -VMSnapshot $checkpoint -Path $destination
        }
        'ExportLogs' {
            if (-not $LogSource -or -not (Test-Path -LiteralPath $LogSource -PathType Container)) { throw 'ExportLogs requires a local directory already populated from the guest.' }
            $source = (Get-Item -LiteralPath $LogSource).FullName
            if ($configuration.Root.StartsWith($source.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or $source -eq $configuration.Root) { throw 'Log source must not contain the lab destination.' }
            if ((Get-Item -LiteralPath $source).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Log source is a reparse point.' }
            $items = @(Get-ChildItem -LiteralPath $source -Recurse -Force)
            if (@($items | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Log source must not contain reparse points.' }
            $bytes = ($items | Where-Object { -not $_.PSIsContainer } | Measure-Object Length -Sum).Sum
            Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes ([int64]$bytes)
            $destination = Assert-LabPath -Path (Join-Path $configuration.Root ("logs\$Lane-" + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) -Root $configuration.Root
            New-Item -ItemType Directory -Path $destination | Out-Null
            Get-ChildItem -LiteralPath $source -Force | Copy-Item -Destination $destination -Recurse
            $destination
        }
    }
}

Export-ModuleMember -Function Get-LabConfiguration,Assert-LabPath,Get-LabCapacity,Assert-LabCapacity,Assert-LabOwnership,Read-LabManifest,Get-OwnedLabVM,Get-ExactLabCheckpoint,Initialize-LabGuestSession,Import-LabMedia,Invoke-LabAction
