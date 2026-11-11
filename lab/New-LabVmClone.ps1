<# Creates a second lab VM so a long run does not block short ones.

   The new VM has the reference VM's shape (generation 2, Secure Boot, vTPM, no
   network adapter, same DVD) and boots from new differencing disks whose
   parents are the disks of one of the reference VM's checkpoints. Nothing is
   copied and the parents are only ever read. The new VM gets a checkpoint of
   the same name, so the attempt harness works on it with -VmId.

   The parents must stay as they are: deleting that checkpoint from the
   reference VM merges into them and breaks this VM's disks.

   lab\New-LabVmClone.ps1 -Name ntfs2refs-reference-b #>
param(
    [Parameter(Mandatory)][string]$Name,
    [string]$SourceVmId = '8f7fc646-8c9f-41d0-b65a-ecfadccfc36a',
    [string]$Checkpoint = 'N2R-Qualification-NTFS-*'
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$workspace = Split-Path -Parent $PSScriptRoot
$root = Join-Path $workspace ".lab\hyperv\$Name"
if (Test-Path -LiteralPath $root) { throw "Already exists: $root" }
if (Get-VM -Name $Name -ErrorAction SilentlyContinue) { throw "A VM named '$Name' already exists" }

$source = Get-VM -Id $SourceVmId
$snapshots = @(Get-VMSnapshot -VM $source | Where-Object Name -Like $Checkpoint)
if ($snapshots.Count -ne 1) { throw "Expected one checkpoint like '$Checkpoint', found $($snapshots.Count)" }
$snapshot = $snapshots[0]
$parents = @(Get-VMHardDiskDrive -VMSnapshot $snapshot | Sort-Object ControllerLocation)
if (-not $parents.Count) { throw 'The checkpoint has no disks' }
$firmware = Get-VMFirmware -VM $source

$null = New-Item -ItemType Directory -Path (Join-Path $root 'disks') -Force
$vm = New-VM -Name $Name -Generation 2 -NoVHD -Path (Join-Path $root 'vm') -MemoryStartupBytes $source.MemoryStartup
Set-VM -VM $vm -StaticMemory -ProcessorCount $source.ProcessorCount -CheckpointType Standard `
    -AutomaticCheckpointsEnabled $false -AutomaticStartAction Nothing -AutomaticStopAction TurnOff `
    -SnapshotFileLocation (Join-Path $root 'checkpoints')
Get-VMNetworkAdapter -VM $vm | Remove-VMNetworkAdapter

foreach ($parent in $parents) {
    $leaf = [IO.Path]::GetFileNameWithoutExtension($parent.Path) + '.vhdx'
    $child = Join-Path $root "disks\$leaf"
    $null = New-VHD -Path $child -ParentPath $parent.Path -Differencing
    Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -ControllerNumber $parent.ControllerNumber `
        -ControllerLocation $parent.ControllerLocation -Path $child
}
foreach ($dvd in Get-VMDvdDrive -VM $source) {
    Add-VMDvdDrive -VM $vm -ControllerNumber $dvd.ControllerNumber -ControllerLocation $dvd.ControllerLocation -Path $dvd.Path
}

# The control OS is the disk the reference VM boots first.
$first = $firmware.BootOrder | Where-Object { $_.BootType -eq 'Drive' -and $_.Device -is [Microsoft.HyperV.PowerShell.HardDiskDrive] } | Select-Object -First 1
$bootLocation = if ($first) { $first.Device.ControllerLocation } else { 1 }
$boot = Get-VMHardDiskDrive -VM $vm | Where-Object ControllerLocation -EQ $bootLocation
Set-VMFirmware -VM $vm -EnableSecureBoot $firmware.SecureBoot -SecureBootTemplate $firmware.SecureBootTemplate -FirstBootDevice $boot
if ((Get-VMSecurity -VM $source).TpmEnabled) {
    Set-VMKeyProtector -VM $vm -NewLocalKeyProtector
    Enable-VMTPM -VM $vm
}
Checkpoint-VM -VM $vm -SnapshotName $snapshot.Name

$vm = Get-VM -Id $vm.Id
[pscustomobject]@{
    name = $vm.Name; id = [string]$vm.Id; root = $root; checkpoint = $snapshot.Name
    boot_location = $bootLocation; processors = $vm.ProcessorCount; memory_gb = [math]::Round($vm.MemoryStartup / 1GB)
    disks = @(Get-VMHardDiskDrive -VM $vm | ForEach-Object { "$($_.ControllerLocation): $($_.Path)" })
} | ConvertTo-Json -Depth 4
