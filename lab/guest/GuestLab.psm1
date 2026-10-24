Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Assert-LabGuestDisk {
    param([Parameter(Mandatory)]$Disk)
    $computer = Get-CimInstance Win32_ComputerSystem
    if ($computer.Manufacturer -ne 'Microsoft Corporation' -or $computer.Model -ne 'Virtual Machine') { throw 'This script must run inside the disposable Hyper-V guest.' }
    # Hyper-V SCSI attachments report SAS on the observed Windows guest build.
    if ($Disk.IsBoot -or $Disk.IsSystem -or [string]$Disk.BusType -notin @('SCSI','SAS') -or $Disk.FriendlyName -notlike '*Virtual*') { throw 'Refusing a boot/system/nonvirtual disk.' }
    $partitions = @(Get-Partition -DiskNumber $Disk.Number -ErrorAction SilentlyContinue)
    if (@($partitions | Where-Object { $_.IsBoot -or $_.IsSystem -or $_.DriveLetter -eq $env:SystemDrive.TrimEnd(':') }).Count) { throw 'Disk contains the running OS or boot partition.' }
}
function Get-LabGuestDisk {
    param([Parameter(Mandatory)]$Manifest)
    if ($Manifest.schemaVersion -ne 1 -or $Manifest.role -notin @('target','journal')) { throw 'Invalid guest disk manifest.' }
    $expectedSize = if ($Manifest.role -eq 'target') { 64GB } else { 8GB }
    if ([string]::IsNullOrWhiteSpace([string]$Manifest.uniqueId) -or [string]::IsNullOrWhiteSpace([string]$Manifest.location) -or $Manifest.sizeBytes -ne $expectedSize) { throw 'Invalid guest disk identity or role size.' }
    $disks = @(Get-Disk | Where-Object { [string]$_.UniqueId -ceq [string]$Manifest.uniqueId })
    if ($disks.Count -ne 1) { throw 'Disk UniqueId must match exactly one disk.' }
    $disk = $disks[0]
    Assert-LabGuestDisk $disk
    if ([string]$disk.SerialNumber -cne [string]$Manifest.serialNumber -or $disk.Size -ne $Manifest.sizeBytes -or [string]$disk.Location -cne [string]$Manifest.location) { throw 'Disk serial, size, or SCSI location changed.' }
    if ($disk.IsOffline -or $disk.IsReadOnly) { throw 'Guest disk is offline or read-only; investigate before changing its state.' }
    $disk
}
Export-ModuleMember -Function Assert-LabGuestDisk,Get-LabGuestDisk
