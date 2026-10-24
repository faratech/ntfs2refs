[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][string]$UniqueId, [Parameter(Mandatory)][ValidateSet('target','journal')][string]$Role, [Parameter(Mandatory)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'GuestLab.psm1') -Force
$disks = @(Get-Disk | Where-Object { [string]$_.UniqueId -ceq $UniqueId })
if ($disks.Count -ne 1) { throw 'Supply the exact UniqueId from Get-Disk, never a disk number.' }
$disk = $disks[0]
Assert-LabGuestDisk $disk
$expectedSize = if ($Role -eq 'target') { 64GB } else { 8GB }
if ($disk.PartitionStyle -ne 'RAW' -or $disk.Size -ne $expectedSize -or [string]::IsNullOrWhiteSpace([string]$disk.UniqueId) -or [string]::IsNullOrWhiteSpace([string]$disk.Location)) { throw 'Only the expected-size blank disposable lab disk with a stable UniqueId and location may be enrolled.' }
if (Test-Path -LiteralPath $OutputPath) { throw 'Manifest already exists; it will not be replaced.' }
# Hyper-V's virtual SCSI disks can expose a stable VPD UniqueId without a serial
# number. Preserve that absence explicitly; never invent a serial or use disk
# number as identity. Callers also match the host attachment, size and SCSI slot.
$manifest = [pscustomobject]@{schemaVersion=1;role=$Role;uniqueId=[string]$disk.UniqueId;serialNumber=[string]$disk.SerialNumber;serialNumberAvailable=(-not [string]::IsNullOrWhiteSpace([string]$disk.SerialNumber));sizeBytes=$disk.Size;location=[string]$disk.Location;enrolledUtc=[DateTime]::UtcNow.ToString('o')}
if ($PSCmdlet.ShouldProcess($OutputPath,'Record qualified guest disk identity; no disk contents changed')) { $manifest | ConvertTo-Json | Set-Content -LiteralPath $OutputPath -Encoding UTF8 }
$manifest
