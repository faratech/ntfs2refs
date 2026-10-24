# Reset only the recorded failed pre-DISM attempt on our new OS VHD.
[CmdletBinding(SupportsShouldProcess)]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'lab\Lab.psm1') -Force
$config = Get-LabConfiguration
$laneRoot = Assert-LabPath (Join-Path $config.Root 'win11') $config.Root
if (-not $PSCmdlet.ShouldProcess($laneRoot, 'Inspect and reset failed pre-image OS partitioning, preserving diagnostics')) { return }
$manifest = Read-LabManifest $config 'win11'
$vm = Get-OwnedLabVM $config $manifest
if ($vm.State -ne 'Off' -or @(Get-VMCheckpoint -VM $vm).Count) { throw 'Repair requires the new VM off with no checkpoints.' }
$install = Assert-LabPath (Join-Path $laneRoot 'install') $config.Root
$state = Get-Content -LiteralPath (Join-Path $install 'state.json') -Raw | ConvertFrom-Json
if ($state.stage -ne 'failed' -or $state.vmId -ne $manifest.vmId -or $state.detail -notmatch 'Not enough available capacity') { throw 'Only the recorded pre-image capacity failure is eligible.' }
if (Test-Path -LiteralPath (Join-Path $install 'dism-apply.log')) { throw 'Image application may have started; refusing reset.' }
$os = @($manifest.disks | Where-Object role -eq 'os')
if ($os.Count -ne 1 -or $state.vhdId -ne $os[0].vhdId) { throw 'OS disk identity is ambiguous.' }
$path = Assert-LabPath $os[0].path $config.Root
$vhd = Get-VHD -Path $path
if ($vhd.Attached -or $vhd.ParentPath -or [string]$vhd.DiskIdentifier -ne $os[0].vhdId) { throw 'Unexpected OS disk attachment or identity.' }
$mounted = $false
try {
    $attached = Mount-VHD -Path $path -NoDriveLetter -PassThru
    $mounted = $true
    $disk = Get-Disk -Number $attached.DiskNumber
    if ($disk.IsBoot -or $disk.IsSystem -or $disk.Size -ne $os[0].sizeBytes -or [string]$disk.BusType -notin @('File Backed Virtual','FileBackedVirtual','Virtual')) { throw 'Refusing a host or unexpected disk.' }
    $parts = @(Get-Partition -DiskNumber $disk.Number)
    $volumes = @($parts | Get-Volume -ErrorAction SilentlyContinue)
    foreach ($volume in $volumes) {
        if ($volume.FileSystemLabel -notin @('N2R_EFI','N2R_WINDOWS','N2R_WINRE')) { throw 'Unexpected volume label; reset refused.' }
        if ($volume.Path -and (Test-Path -LiteralPath (Join-Path $volume.Path 'Windows'))) { throw 'A Windows image exists; reset refused.' }
    }
    [pscustomobject]@{ disk=$disk | Select-Object Number,UniqueId,Size,LargestFreeExtent,PartitionStyle; partitions=$parts | Select-Object PartitionNumber,Offset,Size,GptType; volumes=$volumes | Select-Object FileSystemLabel,FileSystem,Size } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $install 'failed-layout.json') -Encoding UTF8
    if ((Get-VM -Id ([guid]$manifest.vmId)).State -ne 'Off' -or [string](Get-VHD -Path $path).DiskIdentifier -ne $os[0].vhdId) { throw 'VM/disk changed before reset.' }
    Clear-Disk -Number $disk.Number -RemoveData -RemoveOEM -Confirm:$false
    if ((Get-Disk -Number $disk.Number).PartitionStyle -ne 'RAW') { throw 'Lab disk did not return to RAW state.' }
} finally { if ($mounted) { Dismount-VHD -Path $path } }
$archive = Assert-LabPath (Join-Path $laneRoot ('install-failed-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $config.Root
# Both resolved absolute paths are inside the owned lab tree.
if (Test-Path -LiteralPath $archive) { throw 'Diagnostic archive already exists.' }
Move-Item -LiteralPath $install -Destination $archive
