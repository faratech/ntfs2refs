<#
.SYNOPSIS
Mount a new writable copy of a generated NTFS index fixture in a disposable
Hyper-V guest. The caller can then run the normal data preflight and conversion.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ImagePath,
    [Parameter(Mandatory)][string]$CopyPath,
    [ValidatePattern('^[A-Za-z]$')][string]$DriveLetter = 'V'
)
$ErrorActionPreference = 'Stop'
$computer = Get-CimInstance Win32_ComputerSystem
if ($computer.Manufacturer -ne 'Microsoft Corporation' -or $computer.Model -ne 'Virtual Machine') {
    throw 'Prepare the index fixture inside the disposable Hyper-V guest'
}
$source = Get-Item -LiteralPath $ImagePath
$copy = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CopyPath)
if ($source.Extension -ine '.vhdx' -or [IO.Path]::GetExtension($copy) -ine '.vhdx') { throw 'Expected VHDX paths' }
$catalog = Get-Content -LiteralPath (Join-Path $source.DirectoryName 'fixtures.json') -Raw | ConvertFrom-Json
$entries = @($catalog.fixtures | Where-Object image -CEQ $source.Name)
if ($entries.Count -ne 1) { throw "Expected one fixture record for $($source.Name)" }
$entry = $entries[0]
if ((Get-FileHash -LiteralPath $source.FullName).Hash.ToLowerInvariant() -cne $entry.sha256) {
    throw "Fixture SHA-256 differs for $($source.Name)"
}
if ((Get-PSDrive -Name $DriveLetter -ErrorAction SilentlyContinue) -or
    (Get-Partition -DriveLetter $DriveLetter -ErrorAction SilentlyContinue)) { throw "$DriveLetter is already in use" }
[IO.File]::Copy($source.FullName, $copy, $false)
if ((Get-FileHash -LiteralPath $copy).Hash.ToLowerInvariant() -cne $entry.sha256) { throw 'Copied fixture hash differs' }

function Set-ShortNamePolicy([string[]]$Values) {
    $ErrorActionPreference = 'Continue'
    $message = & "$env:SystemRoot\System32\fsutil.exe" 8dot3name set @Values 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "fsutil 8dot3name set $($Values -join ' ') failed: $message" }
}

$root = "${DriveLetter}:\"
$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'
$originalPolicy = [int](Get-ItemPropertyValue -LiteralPath $key -Name NtfsDisable8dot3NameCreation)
$image = $null
$prepared = $false
try {
    try {
        # TxF may create internal files as soon as Windows mounts the image.
        Set-ShortNamePolicy @('1')
        $image = Mount-DiskImage -ImagePath $copy -NoDriveLetter -PassThru
        $disk = $image | Get-Disk
        if ($disk.PartitionStyle -ne 'GPT' -or [guid]$disk.Guid -ne [guid]$entry.disk_guid -or
            $disk.LogicalSectorSize -ne $entry.sector_bytes) { throw 'Fixture disk identity or geometry differs' }
        if ($disk.IsOffline) { Set-Disk -Number $disk.Number -IsOffline $false }
        $part = Get-Partition -DiskNumber $disk.Number -PartitionNumber 2
        if ([guid]$part.Guid -ne [guid]$entry.partition_guid -or
            [guid]$part.GptType -ne [guid]'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7' -or
            $part.Offset -ne $entry.partition_offset -or $part.Size -ne $entry.partition_bytes) {
            throw 'Fixture data partition identity or geometry differs'
        }
        Set-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -NewDriveLetter $DriveLetter
        $selected = Get-Partition -DriveLetter $DriveLetter
        if ($selected.DiskNumber -ne $disk.Number -or [guid]$selected.Guid -ne [guid]$entry.partition_guid) {
            throw "Drive $root does not bind the copied fixture"
        }
        $vol = Get-Volume -DriveLetter $DriveLetter
        if ($vol.FileSystem -eq 'NTFS') {
            if ($vol.FileSystemLabel -cne 'N2RINDEX' -or $vol.AllocationUnitSize -ne $entry.cluster_bytes) {
                throw "Unexpected NTFS fixture geometry at $root"
            }
            $acl = Get-Acl -LiteralPath $root
            $before = $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.WindowsIdentity]::GetCurrent().User,
                [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow)
            $acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $root -AclObject $acl
            $after = (Get-Acl -LiteralPath $root).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
            if ($after -ceq $before) { throw "Windows did not update the root DACL on $root" }
            $seed = Join-Path $root 'seed.txt'
            if (Test-Path -LiteralPath $seed) { throw 'Expected a pristine formatter image' }
            [IO.File]::WriteAllText($seed, 'NTFS index geometry fixture for issue 184', [Text.UTF8Encoding]::new($false))
            $dir = New-Item -ItemType Directory -Path (Join-Path $root 'index-geometry')
            for ($i = 0; $i -lt 1024; $i++) {
                $file = Join-Path $dir.FullName ('entry-{0:d4}.bin' -f $i)
                [IO.File]::WriteAllBytes($file, [BitConverter]::GetBytes([int]$i))
            }
            Set-ShortNamePolicy @('2')
            Set-ShortNamePolicy @("${DriveLetter}:", '1')
        }
    } finally {
        Set-ShortNamePolicy @([string]$originalPolicy)
        if ([int](Get-ItemPropertyValue -LiteralPath $key -Name NtfsDisable8dot3NameCreation) -ne $originalPolicy) {
            throw 'The original guest short-name policy was not restored'
        }
    }
    $prepared = $true
    [pscustomobject]@{ drive = $DriveLetter; copy_path = $copy; disk = $disk.Number; partition = $part.PartitionNumber
        filesystem = $vol.FileSystem; fixture_sha256 = $entry.sha256; expected_index_record_bytes = $entry.index_record_bytes }
} finally {
    if ($image -and -not $prepared) { Dismount-DiskImage -ImagePath $copy | Out-Null }
}
