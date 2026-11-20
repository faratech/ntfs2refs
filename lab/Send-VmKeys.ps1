<#
.SYNOPSIS
  Types a command into a lab VM's console and saves a screenshot of the
  result: an interactive session in the recovery environment, where no
  remote session exists, in seconds instead of a restart per question.

.EXAMPLE
  .\Send-VmKeys.ps1 -VmId <id> -Text 'dir D:\' -Shot shot.png
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$VmId,
    [string]$Text,
    [string]$Shot,
    [int]$WaitSeconds = 3,
    [switch]$NoEnter
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$ns = 'root\virtualization\v2'
$keyboard = Get-CimInstance -Namespace $ns -ClassName Msvm_Keyboard -Filter "SystemName='$($VmId.ToUpper())'"
if (-not $keyboard) { throw "no keyboard for VM $VmId (is it running?)" }
if ($Text) {
    $null = Invoke-CimMethod -InputObject $keyboard -MethodName TypeText -Arguments @{ asciiText = $Text }
    if (-not $NoEnter) { $null = Invoke-CimMethod -InputObject $keyboard -MethodName TypeKey -Arguments @{ keyCode = 13 } }
}
if ($Shot) {
    Start-Sleep -Seconds $WaitSeconds
    $vm = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "Name='$($VmId.ToUpper())'"
    $svc = Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemManagementService
    $set = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_VirtualSystemSettingData | Where-Object VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized'
    $r = Invoke-CimMethod -InputObject $svc -MethodName GetVirtualSystemThumbnailImage -Arguments @{ TargetSystem = $set; WidthPixels = 800; HeightPixels = 600 }
    $b = $r.ImageData
    $bmp = New-Object System.Drawing.Bitmap 800, 600, ([System.Drawing.Imaging.PixelFormat]::Format16bppRgb565)
    $bd = $bmp.LockBits((New-Object System.Drawing.Rectangle 0, 0, 800, 600), 'WriteOnly', $bmp.PixelFormat)
    [Runtime.InteropServices.Marshal]::Copy($b, 0, $bd.Scan0, $b.Length); $bmp.UnlockBits($bd)
    $bmp.Save($Shot)
}
