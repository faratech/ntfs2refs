<#
.SYNOPSIS
Boots a lab VM once into its own Windows Recovery Environment (WinRE), with a
probe in place of the recovery menu, and reports what that environment can do
for a conversion of the Windows volume (#115).

.DESCRIPTION
Converting the running Windows has to happen outside it, in an environment
the run starts by itself. The machine's own WinRE needs no installation media.
Whether it can carry a conversion is what this probe asks:

  - refs.sys, vhdmp.sys, format.com, WMI, PowerShell, VSS in the image;
  - memory, and whether there is a page file;
  - a VHDX created and attached (diskpart, the same virtdisk API the run uses),
    formatted ReFS as a Dev Drive and as a standard volume, written and read;
  - the converter itself there: --list, and --diagnose of the offline Windows
    volume with --windows-boot-volume (read only), working storage on the
    scratch disk.

The control OS must be up with an NTFS scratch volume S: (the WIM and the
boot.sdi must be on a volume the boot manager reads):
  Invoke-BootConversionAttempt.ps1 -Name <n> -NoConvert -KeepScratch -ScratchFileSystem NTFS -VmId <id>
It copies WinRE to S:\probe, adds the probe, makes a one-time boot entry
(bcdedit /bootsequence), restarts, waits for Windows to come back, and copies
S:\probe\results.txt beside its own records. The entry is deleted afterwards.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,39}$')][string]$Name,
    [Parameter(Mandatory)][guid]$VmId,
    [string]$Binary,
    [string]$CredentialPath,
    # The environment probed: the machine's own WinRE, or the WinPE of the
    # installation media in the control OS's DVD drive (boot.wim, index 2).
    [ValidateSet('winre', 'media')][string]$Image = 'winre',
    [int]$AwayMinutes = 40
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$workspace = Split-Path -Parent $PSScriptRoot
if (-not $Binary) { $Binary = Join-Path $workspace 'target\release\ntfs2refs.exe' }
if (-not (Test-Path -LiteralPath $Binary)) { throw "Not found: $Binary" }
$records = Join-Path $workspace ".lab\hyperv\attempts\$Name"
if (Test-Path -LiteralPath $records) { throw "Attempt '$Name' already has records at $records" }
$null = New-Item -ItemType Directory -Path $records
function Say([string]$Text) { $line = '{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $Text; Add-Content -LiteralPath (Join-Path $records 'progress.log') -Value $line -Encoding UTF8; Write-Host $line }

$vm = Get-VM -Id $VmId
if ($vm.State -ne 'Running') { throw "VM $($vm.Name) is $($vm.State); start its control OS first" }
if (-not $CredentialPath) { $CredentialPath = Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml' }
$saved = Import-Clixml -LiteralPath $CredentialPath
$credential = [pscredential]::new('LabAdmin', $saved.Password)
$session = New-PSSession -VMId $VmId -Credential $credential

# The probe that runs in WinRE instead of its menu. It finds the scratch
# volume by its marker and the offline Windows by its kernel, writes every
# answer to results.txt on the scratch volume, and restarts.
$probe = @'
@echo off
wpeinit
set S=
set W=
for %%d in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do if exist %%d:\probe\marker.txt set S=%%d:
for %%d in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do if exist %%d:\Windows\System32\ntoskrnl.exe call :ntfs %%d
if "%S%"=="" goto :out
set R=%S%\probe\results.txt
echo === started %date% %time%; scratch %S%; offline Windows %W% > %R%
ver >> %R% 2>&1
echo === files in the image >> %R%
for %%f in (drivers\refs.sys drivers\vhdmp.sys format.com fsutil.exe diskpart.exe vssadmin.exe vssvc.exe wbem\wmic.exe WindowsPowerShell\v1.0\powershell.exe dism.exe bcdedit.exe reagentc.exe) do if exist X:\Windows\System32\%%f (echo present %%f >> %R%) else (echo ABSENT %%f >> %R%)
echo === memory >> %R%
wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /value >> %R% 2>&1
wmic pagefile list brief >> %R% 2>&1
echo === disks and volumes >> %R%
(echo list disk& echo list volume) > X:\dp1.txt
diskpart /s X:\dp1.txt >> %R% 2>&1
echo === create and attach a VHDX >> %R%
(echo create vdisk file=%S%\probe\t.vhdx maximum=4096 type=expandable& echo select vdisk file=%S%\probe\t.vhdx& echo attach vdisk& echo convert gpt& echo create partition primary& echo assign letter=T) > X:\dp2.txt
diskpart /s X:\dp2.txt >> %R% 2>&1
echo === format ReFS Dev Drive >> %R%
format T: /FS:ReFS /DevDrv /Q /Y >> %R% 2>&1
echo exit %errorlevel% >> %R%
fsutil fsinfo refsinfo T: >> %R% 2>&1
echo written on refs > T:\probe-file.txt
type T:\probe-file.txt >> %R% 2>&1
echo === format ReFS standard >> %R%
format T: /FS:ReFS /Q /Y >> %R% 2>&1
echo exit %errorlevel% >> %R%
fsutil fsinfo refsinfo T: >> %R% 2>&1
(echo select vdisk file=%S%\probe\t.vhdx& echo detach vdisk) > X:\dp3.txt
diskpart /s X:\dp3.txt >> %R% 2>&1
echo === shadow copies >> %R%
vssadmin list shadows >> %R% 2>&1
echo === ntfs2refs --list >> %R%
%S%\probe\ntfs2refs.exe --list >> %R% 2>&1
echo exit %errorlevel% >> %R%
echo === ntfs2refs --diagnose of the offline Windows %W% >> %R%
if not "%W%"=="" for /f "tokens=5" %%V in ('vol %W:~0,2% ^| find "Serial"') do set VS=%%V
if not "%W%"=="" %S%\probe\ntfs2refs.exe --drive %W:~0,1% --windows-boot-volume --diagnose --yes --volume-serial %VS% --scratch-directory %S%\probe\diagnose >> %R% 2>&1
echo exit %errorlevel% >> %R%
echo === done %date% %time% >> %R%
:out
wpeutil reboot
exit /b
rem The offline Windows to convert is the one on NTFS.
:ntfs
fsutil fsinfo volumeinfo %1: | find "NTFS" >nul && set W=%1:
exit /b
'@

Say "copying WinRE and the probe to S:\probe on $($vm.Name)"
$prepared = Invoke-Command -Session $session -ArgumentList $probe, $Image -ScriptBlock {
    param($probe, $image)
    # Native tools write notes to stderr, which a remote session would take
    # for errors; their exit codes and outputs are checked instead.
    $ErrorActionPreference = 'Continue'
    $root = 'S:\probe'
    if (Test-Path $root) { $null = & dism.exe /Unmount-Image /MountDir:"$root\mount" /Discard /Quiet 2>&1; Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
    $null = New-Item -ItemType Directory -Path $root, "$root\mount"
    Set-Content -LiteralPath "$root\marker.txt" -Value 'n2r environment probe' -Encoding ascii
    $info = (& reagentc.exe /info 2>&1 | Out-String)
    $index = 1
    if ($image -eq 'media') {
        $dvd = Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -and $_.DriveLetter -and (Test-Path "$($_.DriveLetter):\sources\boot.wim") } | Select-Object -First 1
        if (-not $dvd) { throw 'no installation media with sources\boot.wim in a DVD drive' }
        Copy-Item -LiteralPath "$($dvd.DriveLetter):\sources\boot.wim" -Destination "$root\winre.wim"
        Set-ItemProperty -LiteralPath "$root\winre.wim" -Name IsReadOnly -Value $false
        $index = 2
    } else {
        # The WinRE of the Windows to convert: Recovery\WindowsRE\winre.wim on
        # a recovery partition (its GPT type) of a disk that holds an NTFS
        # Windows, read through a temporary access path. The control OS's own
        # WinRE is not the one a conversion of that Windows would use.
        $recovery = Get-Partition | Where-Object { $_.GptType -eq '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}' } | Where-Object {
            $disk = $_.DiskNumber
            @(Get-Partition -DiskNumber $disk | Where-Object DriveLetter | Where-Object { (Get-Volume -Partition $_).FileSystem -eq 'NTFS' -and (Test-Path "$($_.DriveLetter):\Windows\System32\ntoskrnl.exe") }).Count -gt 0
        } | Select-Object -First 1
        if (-not $recovery) { throw "no recovery partition beside an NTFS Windows: $info" }
        $access = "$root\recovery"
        $null = New-Item -ItemType Directory -Path $access
        Add-PartitionAccessPath -DiskNumber $recovery.DiskNumber -PartitionNumber $recovery.PartitionNumber -AccessPath "$access\"
        try {
            $wim = Get-ChildItem -LiteralPath "$access\Recovery\WindowsRE" -Filter winre.wim -Force -ErrorAction Stop | Select-Object -First 1
            if (-not $wim) { throw "no winre.wim in Recovery\WindowsRE of disk $($recovery.DiskNumber) partition $($recovery.PartitionNumber)" }
            Copy-Item -LiteralPath $wim.FullName -Destination "$root\winre.wim"
            Set-ItemProperty -LiteralPath "$root\winre.wim" -Name Attributes -Value 'Normal'
        } finally {
            Remove-PartitionAccessPath -DiskNumber $recovery.DiskNumber -PartitionNumber $recovery.PartitionNumber -AccessPath "$access\"
        }
    }
    & dism.exe /Mount-Image /ImageFile:"$root\winre.wim" /Index:$index /MountDir:"$root\mount" /Quiet | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "dism /Mount-Image failed ($LASTEXITCODE)" }
    try {
        Set-Content -LiteralPath "$root\mount\probe.cmd" -Value $probe -Encoding ascii
        Set-Content -LiteralPath "$root\mount\Windows\System32\winpeshl.ini" -Value "[LaunchApps]`r`n%SYSTEMROOT%\System32\cmd.exe, /c X:\probe.cmd" -Encoding ascii
    } finally {
        & dism.exe /Unmount-Image /MountDir:"$root\mount" /Commit /Quiet | Out-Null
    }
    if ($LASTEXITCODE -ne 0) { throw "dism /Unmount-Image failed ($LASTEXITCODE)" }
    Copy-Item -LiteralPath 'C:\Windows\Boot\DVD\EFI\boot.sdi' -Destination "$root\boot.sdi"
    # A one-time boot entry: the ramdisk options, then the loader.
    $guid = { param($text) ([regex]::Match(($text -join ' '), '\{[0-9a-fA-F-]{36}\}')).Value }
    $options = & $guid (& bcdedit.exe /create /d 'N2R probe ramdisk' /device)
    $null = & bcdedit.exe /set $options ramdisksdidevice partition=S:
    $null = & bcdedit.exe /set $options ramdisksdipath \probe\boot.sdi
    $loader = & $guid (& bcdedit.exe /create /d 'N2R environment probe' /application osloader)
    foreach ($setting in @(@('device', "ramdisk=[S:]\probe\winre.wim,$options"), @('osdevice', "ramdisk=[S:]\probe\winre.wim,$options"),
            @('path', '\windows\system32\boot\winload.efi'), @('systemroot', '\windows'), @('winpe', 'yes'), @('detecthal', 'yes'))) {
        $said = & bcdedit.exe /set $loader $setting[0] $setting[1]
        if ($LASTEXITCODE -ne 0) { throw "bcdedit /set $($setting[0]) failed: $said" }
    }
    $null = & bcdedit.exe /bootsequence $loader
    [pscustomobject]@{ reagentc = $info; loader = $loader; options = $options; wim_bytes = (Get-Item "$root\winre.wim").Length }
}
Copy-Item -ToSession $session -LiteralPath $Binary -Destination 'S:\probe\ntfs2refs.exe'
Say "WinRE image $([Math]::Round($prepared.wim_bytes / 1MB)) MiB; one-time entry $($prepared.loader); restarting into it"
$prepared.reagentc | Set-Content -LiteralPath (Join-Path $records 'reagentc.txt') -Encoding utf8
Invoke-Command -Session $session -ScriptBlock { & shutdown.exe /r /t 3 /c 'n2r environment probe' } | Out-Null
Remove-PSSession $session

# Away (WinRE, the probe), then back in Windows.
$deadline = (Get-Date).AddMinutes($AwayMinutes)
Start-Sleep -Seconds 60
$back = $null
do {
    Start-Sleep -Seconds 15
    try {
        $back = New-PSSession -VMId $VmId -Credential $credential -ErrorAction Stop
        $done = Invoke-Command -Session $back -ScriptBlock { (Test-Path 'S:\probe\results.txt') -and ((Get-Content 'S:\probe\results.txt' -Raw) -match '=== done') }
        if (-not $done) { Remove-PSSession $back; $back = $null }
    } catch { $back = $null }
} until ($back -or (Get-Date) -gt $deadline)
if (-not $back) {
    $null = Get-VMVideo -ErrorAction SilentlyContinue
    throw "the VM did not come back with the probe's results within $AwayMinutes minutes"
}
$results = Invoke-Command -Session $back -ArgumentList $prepared.loader, $prepared.options -ScriptBlock {
    param($loader, $options)
    $null = & bcdedit.exe /delete $loader /f; $null = & bcdedit.exe /delete $options /f
    Get-Content 'S:\probe\results.txt' -Raw
}
Remove-PSSession $back
[IO.File]::WriteAllText((Join-Path $records 'results.txt'), $results, [Text.UTF8Encoding]::new($false))
Say "results in $(Join-Path $records 'results.txt')"
$results
