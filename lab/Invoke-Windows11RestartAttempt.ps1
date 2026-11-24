#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,39}$')][string]$Name,
    [Parameter(Mandatory)][guid]$VmId,
    [Parameter(Mandatory)][string]$InstallationMedia,
    [Parameter(Mandatory)][string]$Binary,
    [Parameter(Mandatory)][string]$ManifestBinary,
    [ValidateSet('', 'resume', 'rollback')][string]$PostFlushRecovery = '',
    [string]$Checkpoint = 'N2R-Qualification-NTFS-*',
    [string]$CredentialPath,
    [int]$BootTimeoutMinutes = 25
)
$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$attempts = Join-Path $workspace '.lab/hyperv/attempts'
if (-not $CredentialPath) { $CredentialPath = Join-Path $workspace '.lab/hyperv/win11/secrets/guest-credential.xml' }
$credential = Import-Clixml -LiteralPath $CredentialPath
$media = (Resolve-Path -LiteralPath $InstallationMedia).Path
$vm = Get-VM -Id $VmId
if ($vm.State -ne 'Off') { throw "Windows 11 restart fixture $($vm.Name) is already in use" }
$base = @(Get-VMSnapshot -VM $vm -Name $Checkpoint)
if ($base.Count -ne 1) { throw "Expected one disposable Windows 11 checkpoint for $($vm.Name)" }
if (Test-Path -LiteralPath (Join-Path $attempts $Name)) { throw "Attempt $Name already exists" }

$addedMedia = $null
$session = $null
$started = $false
try {
    Restore-VMSnapshot -VMSnapshot $base[0] -Confirm:$false
    $vm = Get-VM -Id $VmId
    if (@(Get-VMNetworkAdapter -VM $vm | Where-Object SwitchName).Count) { throw 'The restart fixture must have no connected network adapter' }
    $disk0 = @(Get-VMHardDiskDrive -VM $vm | Where-Object { $_.ControllerType -eq 'SCSI' -and $_.ControllerNumber -eq 0 -and $_.ControllerLocation -eq 0 })
    if ($disk0.Count -ne 1) { throw 'The restart fixture needs one Windows source disk at SCSI 0/0' }
    if (-not (Get-VMDvdDrive -VM $vm | Where-Object Path -EQ $media)) {
        $addedMedia = Add-VMDvdDrive -VM $vm -Path $media -Passthru
    }
    Set-VMFirmware -VM $vm -FirstBootDevice $disk0[0]
    $available = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1KB - 8GB
    $startup = [long]([math]::Floor([math]::Min($available, $vm.MemoryStartup) / 1MB) * 1MB)
    if ($startup -lt 8GB) { throw 'The Windows 11 restart fixture needs 8 GiB while retaining 8 GiB for the host' }
    if ($startup -lt $vm.MemoryStartup) { Set-VMMemory -VM $vm -StartupBytes $startup }
    Start-VM -VM $vm
    $started = $true
    $deadline = (Get-Date).AddMinutes($BootTimeoutMinutes)
    do {
        try { $session = New-PSSession -VMId $VmId -Credential $credential -ErrorAction Stop }
        catch { Start-Sleep -Seconds 5 }
    } until ($session -or (Get-Date) -ge $deadline)
    if (-not $session) { throw "Windows 11 fixture $($vm.Name) did not accept PowerShell Direct" }
    $control = Invoke-Command -Session $session -ScriptBlock {
        $part = Get-Partition -DriveLetter C
        $os = Get-CimInstance Win32_OperatingSystem
        $revision = Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR
        $shrink = $part.Size - (Get-PartitionSupportedSize -DriveLetter C).SizeMin
        [pscustomobject]@{
            filesystem = [string](Get-Volume -DriveLetter C).FileSystem; disk = $part.DiskNumber; shrink_bytes = $shrink
            windows_build = [int]$os.BuildNumber; windows_revision = [int]$revision; windows_edition = [int]$os.OperatingSystemSKU
            workstation = $os.ProductType -eq 1
        }
    }
    Remove-PSSession $session; $session = $null
    if ($control.filesystem -cne 'NTFS' -or $control.disk -ne 0 -or $control.shrink_bytes -lt 2GB -or
        -not $control.workstation -or $control.windows_build -ne 26300) {
        throw "Unexpected Windows 11 restart fixture. $($control | ConvertTo-Json -Compress)"
    }
    $workingGB = [int][math]::Floor((Get-Volume -FilePath $attempts).SizeRemaining / 2GB)
    if ($workingGB -le 0) { throw 'No space for the independent restart working disk' }
    & (Join-Path $PSScriptRoot 'Invoke-RestartRouteAttempt.ps1') -Name $Name -VmId $VmId `
        -Binary $Binary -ManifestBinary $ManifestBinary -CredentialPath $CredentialPath `
        -PartitionMB 2048 -WorkingDiskGB $workingGB -PostFlushRecovery $PostFlushRecovery
    $control | Select-Object filesystem,disk,windows_build,windows_revision,windows_edition,workstation |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $attempts "$Name/control-profile.json") -Encoding utf8
} finally {
    if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
    if ($started -and (Get-VM -Id $VmId).State -ne 'Off') { Stop-VM -VM $vm -Force -Confirm:$false }
    if ($addedMedia) { $addedMedia | Remove-VMDvdDrive }
}
