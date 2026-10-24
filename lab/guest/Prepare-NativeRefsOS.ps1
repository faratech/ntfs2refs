<# Guest-only native ReFS OS preparation. This does not select or boot the new OS.
   Ordinary native formatting refusal is an experimental result; no Dev Drive or
   feature-flag workaround is attempted. Called by Prepare-LabRefsBootControl.ps1. #>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$HostTargetJson,
    [Parameter(Mandatory)][Management.Automation.PSCredential]$FirstBootCredential,
    [ValidateSet('FormatVolume','FormatCom')][string]$FormatMethod = 'FormatVolume'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$runRoot = 'C:\ntfs2refs\refs-os-preparation'
if (-not $PSCmdlet.ShouldProcess('Enrolled blank 64 GiB guest target', 'Prepare native ReFS Windows image using guest deployment tools; do not change boot order')) {
    [pscustomobject]@{ DryRun = $true; GuestTargetBytes = 64GB; ImageIndex = 6; FileSystem = 'ReFS'; FormatMethod = $FormatMethod; BootAttempted = $false }
    return
}
Import-Module (Join-Path $PSScriptRoot 'GuestLab.psm1') -Force
if (Test-Path -LiteralPath $runRoot) { throw 'Preparation evidence already exists; restore the reviewed clean baseline before another attempt.' }
New-Item -ItemType Directory -Path $runRoot | Out-Null
$record = [ordered]@{ schemaVersion = 1; phase = 'native-refs-os-preparation'; status = 'started'; stage = 'preflight'; target = $null; sourceOs = $null; formatter = $null; formatRequest = $null; imageIndex = 6; imageVersion = '10.0.26300.9457'; formatSucceeded = $false; imageApplied = $false; bootFilesPrepared = $false; firstBootConfigured = $false; bootAttempted = $false; refsBootVerified = $false; error = $null; errorHresult = $null; tools = @{}; bootFiles = @(); partitions = @(); createdUtc = [DateTime]::UtcNow.ToString('o') }
$identity = $null
$record['scriptSha256'] = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$record['formatMethod'] = $FormatMethod
$record['formatCompletion'] = $null
$record['formatCapability'] = $null
function Get-ControlFormatterComponent([string]$Name, [string]$Path) {
    # Provenance collection must retain unknown/failed signature observations;
    # it must not turn those observations into an omitted component.
    $component = [ordered]@{ name = $Name; path = $Path; exists = $false; fileVersion = $null; sha256 = $null; signatureStatus = 'Unknown'; signer = $null; errors = @() }
    try {
        $file = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($file.PSIsContainer) { throw 'Formatter component is not a file.' }
        $component.exists = $true
        $component.fileVersion = $file.VersionInfo.FileVersion
        $component.sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    } catch { $component.errors += $_.Exception.Message }
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        if ($signature -and -not [string]::IsNullOrWhiteSpace([string]$signature.Status)) { $component.signatureStatus = [string]$signature.Status }
        if ($signature -and $signature.SignerCertificate) { $component.signer = $signature.SignerCertificate.Subject }
    } catch { $component.errors += $_.Exception.Message }
    [pscustomobject]$component
}
function Get-ControlDisk {
    if (-not $identity) { throw 'Target identity is not enrolled.' }
    Get-LabGuestDisk $identity
}
function Assert-ControlLetter([string]$Letter) {
    $disk = Get-ControlDisk
    $parts = @(Get-Partition -DriveLetter $Letter -ErrorAction Stop)
    if ($parts.Count -ne 1 -or $parts[0].DiskNumber -ne $disk.Number -or $Letter -eq $env:SystemDrive.TrimEnd(':')) { throw 'A destination letter no longer refers to the enrolled target disk.' }
}
function Assert-ControlFormatPartition($ExpectedPartition, [string]$Letter) {
    Assert-ControlLetter $Letter
    $parts = @(Get-Partition -DriveLetter $Letter -ErrorAction Stop)
    if ($parts.Count -ne 1 -or $parts[0].PartitionNumber -ne $ExpectedPartition.PartitionNumber -or
        $parts[0].Offset -ne $ExpectedPartition.Offset -or $parts[0].Size -ne $ExpectedPartition.Size -or
        $ExpectedPartition.Size -lt 40GB) { throw 'The newly created OS partition identity changed before formatting.' }
    $volumes = @(Get-Volume -DriveLetter $Letter -ErrorAction Stop)
    if ($volumes.Count -ne 1 -or [string]$volumes[0].FileSystem -notin @('','RAW','Unknown')) { throw 'Only the newly created unformatted OS partition may be formatted.' }
}
function Test-ControlRecoveryPartition($Partition, [string]$NativeDetail) {
    # The Storage provider can return null for NoDefaultDriveLetter. Check the
    # actual GPT attributes in native detail output bound to this byte offset.
    $offset = [string]$Partition.Offset
    $Partition.GptType -ieq '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}' -and
        $Partition.Size -eq 2GB -and
        $NativeDetail -match '(?im)^Type\s*:\s*de94bba4-06d1-4d40-a16a-bfd50179d6ac\s*$' -and
        $NativeDetail -match '(?im)^Attrib\s*:\s*0x8000000000000001\s*$' -and
        $NativeDetail -match ('(?im)^Offset in Bytes:\s*' + [regex]::Escape($offset) + '\s*$')
}
function Invoke-ControlNative([string]$Name, [string[]]$Arguments, [string]$LogName,
    [ValidateRange(1,7200)][int]$TimeoutSeconds = 7200, [switch]$CloseStandardInput, [switch]$PassThru) {
    Get-ControlDisk | Out-Null
    $tool = $record.tools[$Name]
    if (-not $tool) { throw 'Only prevalidated guest deployment tools can be invoked.' }
    $command = [ordered]@{ executable = $tool.path; toolSha256 = $tool.sha256; arguments = @($Arguments); startedUtc = [DateTime]::UtcNow.ToString('o'); exitCode = $null; completedUtc = $null; timeoutSeconds = $TimeoutSeconds; timedOut = $false; stdinMode = $(if ($CloseStandardInput) { 'closed-empty' } else { 'inherited' }); error = $null }
    $process = New-Object Diagnostics.Process
    $started = $false; $stdout = $null; $stderr = $null
    try {
        $process.StartInfo.FileName = $tool.path
        # format.com parses simple quoted switches differently from CRT argv:
        # /? succeeds, while "/?" exits 4. Quote only arguments that need it.
        $process.StartInfo.Arguments = (($Arguments | ForEach-Object {
            if ($_ -ne '' -and $_ -notmatch '[\s"]') { $_ }
            else { '"' + ($_ -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"' }
        }) -join ' ')
        $process.StartInfo.WorkingDirectory = $runRoot
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        $process.StartInfo.RedirectStandardInput = [bool]$CloseStandardInput
        $started = $process.Start()
        if (-not $started) { throw 'Native guest tool did not start.' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if ($CloseStandardInput) { $process.StandardInput.Close() }
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $command.timedOut = $true
            $process.Kill()
            if (-not $process.WaitForExit(10000)) { throw 'Timed-out native guest process did not terminate within its cleanup bound.' }
        }
        $command.exitCode = $process.ExitCode
    } catch {
        $command.error = $_.Exception.Message
        throw
    } finally {
        if ($started -and -not $process.HasExited) { try { $process.Kill(); $process.WaitForExit(10000) | Out-Null } catch { $command.error = $_.Exception.Message } }
        $output = ''
        if ($stdout -and $stdout.Wait(10000)) { $output = $stdout.GetAwaiter().GetResult() }
        $output | Set-Content -LiteralPath (Join-Path $runRoot $LogName) -Encoding UTF8
        if ($stderr -and $stderr.Wait(10000)) {
            $errorText = $stderr.GetAwaiter().GetResult()
            if ($errorText) { @('[stderr]', $errorText) | Add-Content -LiteralPath (Join-Path $runRoot $LogName) -Encoding UTF8 }
        }
        $command.completedUtc = [DateTime]::UtcNow.ToString('o')
        $command | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $runRoot ($LogName + '.command.json')) -Encoding UTF8
        $process.Dispose()
    }
    if ($command.timedOut) { throw "$Name exceeded its $TimeoutSeconds second deadline; see $LogName." }
    if ($command.exitCode -ne 0) { throw "$Name exited with code $($command.exitCode); see $LogName." }
    if ($PassThru) { [pscustomobject]$command }
}
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Guest administrator token required.' }
    if ($env:COMPUTERNAME -cne 'N2R-WIN11' -or $FirstBootCredential.UserName -cne 'N2R-WIN11\LabAdmin') { throw 'Unexpected guest or account identity.' }
    $version = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    if ($version.EditionID -cne 'Professional' -or "$($version.CurrentBuildNumber).$($version.UBR)" -cne '26300.9457') { throw 'The running formatter must be the pinned Windows 11 Pro build.' }
    if (-not (Confirm-SecureBootUEFI)) { throw 'Secure Boot must remain enabled for the native boot control.' }
    $sourceVolume = Get-Volume -DriveLetter C
    $sourceParts = @(Get-Partition -DriveLetter C)
    if ($env:SystemDrive -cne 'C:' -or $sourceVolume.FileSystem -cne 'NTFS' -or $sourceParts.Count -ne 1) { throw 'The source must be the installed NTFS control.' }
    $sourceDisk = Get-Disk -Number $sourceParts[0].DiskNumber
    if (-not $sourceDisk.IsBoot) { throw 'Source OS disk is not identified as the running boot disk.' }
    $record.sourceOs = [pscustomobject]@{ uniqueId = [string]$sourceDisk.UniqueId; sizeBytes = $sourceDisk.Size; filesystem = 'NTFS'; build = '26300.9457' }
    $formatCommand = Get-Command -Name Format-Volume -ErrorAction Stop
    if ($formatCommand.ModuleName -cne 'Storage' -or -not $formatCommand.Module) { throw 'Format-Volume must resolve to the native Storage module.' }
    $record.formatter = [pscustomobject]@{
        capturedUtc = [DateTime]::UtcNow.ToString('o')
        windows = [pscustomobject]@{ editionId = [string]$version.EditionID; currentBuildNumber = [string]$version.CurrentBuildNumber; ubr = [int]$version.UBR; fullBuild = "10.0.$($version.CurrentBuildNumber).$($version.UBR)" }
        components = @(
            (Get-ControlFormatterComponent 'refs.sys' (Join-Path $env:SystemRoot 'System32\drivers\refs.sys'))
            (Get-ControlFormatterComponent 'fmifs.dll' (Join-Path $env:SystemRoot 'System32\fmifs.dll'))
        )
        command = [pscustomobject]@{ name = $formatCommand.Name; commandType = [string]$formatCommand.CommandType; moduleName = $formatCommand.ModuleName; moduleVersion = [string]$formatCommand.Module.Version; modulePath = $formatCommand.Module.Path }
    }
    if ($FormatMethod -ceq 'FormatCom') {
        $record.formatter.components += Get-ControlFormatterComponent 'format.com' (Join-Path $env:SystemRoot 'System32\format.com')
        $record.formatter.command = [pscustomobject]@{ name = 'format.com'; commandType = 'Application'; path = (Join-Path $env:SystemRoot 'System32\format.com') }
    }
    $spec = $HostTargetJson | ConvertFrom-Json
    $parsedVhdId = [guid]::Empty
    if ($spec.role -cne 'target' -or $spec.sizeBytes -ne 64GB -or $spec.controllerLocation -ne 1 -or -not [guid]::TryParse([string]$spec.vhdId, [ref]$parsedVhdId)) { throw 'Unexpected host target specification.' }
    $candidates = @()
    foreach ($disk in @(Get-Disk | Where-Object { -not $_.IsBoot -and -not $_.IsSystem -and $_.Size -eq 64GB })) {
        $mapping = @(Get-CimInstance Win32_DiskDrive | Where-Object Index -eq $disk.Number)
        if ($mapping.Count -eq 1 -and (($mapping[0].SCSITargetId -eq $spec.controllerLocation -and $mapping[0].SCSILogicalUnit -eq 0) -or ($mapping[0].SCSITargetId -eq 0 -and $mapping[0].SCSILogicalUnit -eq $spec.controllerLocation))) { $candidates += $disk }
    }
    if ($candidates.Count -ne 1) { throw 'Target is not uniquely mapped by non-OS role, size and host SCSI slot.' }
    $disk = $candidates[0]
    Assert-LabGuestDisk $disk
    if ($disk.PartitionStyle -cne 'RAW' -or $disk.IsOffline -or $disk.IsReadOnly -or @(Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue).Count) { throw 'Target must be a blank online writable RAW disk.' }
    $identity = & (Join-Path $PSScriptRoot 'Register-GuestDisk.ps1') -UniqueId ([string]$disk.UniqueId) -Role target -OutputPath (Join-Path $runRoot 'target.json') -Confirm:$false
    if ($identity.uniqueId -ceq [string]$sourceDisk.UniqueId) { throw 'Target and original OS disk identities collide.' }
    $record.target = [pscustomobject]@{ guest = $identity; hostVhdId = $spec.vhdId; hostControllerLocation = $spec.controllerLocation }
    $toolNames = @('dism.exe','bcdboot.exe','bcdedit.exe','reagentc.exe','diskpart.exe','fsutil.exe')
    if ($FormatMethod -ceq 'FormatCom') { $toolNames += 'format.com' }
    foreach ($name in $toolNames) {
        $path = Join-Path $env:SystemRoot ('System32\' + $name)
        $file = Get-Item -LiteralPath $path
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'Guest deployment tool lacks a valid Microsoft signature.' }
        $record.tools[$name] = [pscustomobject]@{ path = $path; version = $file.VersionInfo.FileVersion; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant(); signature = [string]$signature.Status; signer = $signature.SignerCertificate.Subject }
    }
    if ($FormatMethod -ceq 'FormatCom') {
        Invoke-ControlNative 'format.com' @('/?') 'format-help.log' -TimeoutSeconds 30 -CloseStandardInput
        $formatHelp = Get-Content -LiteralPath (Join-Path $runRoot 'format-help.log') -Raw
        if ($formatHelp -notmatch '(?im)^\s*/Y\s+No prompt,' -or $formatHelp -notmatch 'ReFS supports 4096, 64K') { throw 'Guest format.com does not advertise the reviewed ordinary ReFS and no-prompt options.' }
    }
    $media = @(Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -and $_.DriveLetter -and (Test-Path -LiteralPath ($_.DriveLetter + ':\sources\install.wim')) })
    if ($media.Count -ne 1) { throw 'The pinned attached DVD must expose exactly one install.wim.' }
    $wim = $media[0].DriveLetter + ':\sources\install.wim'
    $image = Get-WindowsImage -ImagePath $wim -Index 6
    if ($image.EditionId -cne 'Professional' -or [version]$image.Version -ne [version]'10.0.26300.9457') { throw 'DVD image does not match pinned Pro index 6.' }
    $used = @(Get-Volume | Where-Object DriveLetter | ForEach-Object { [string]$_.DriveLetter })
    $letters = @([char[]](70..90) | ForEach-Object { [string]$_ } | Where-Object { $_ -notin $used -and -not (Test-Path -LiteralPath ($_ + ':\')) } | Select-Object -First 3)
    if ($letters.Count -ne 3) { throw 'Three unused destination drive letters are required.' }
    $record.stage = 'partitioning'
    $disk = Get-ControlDisk
    Initialize-Disk -Number $disk.Number -PartitionStyle GPT | Out-Null
    $disk = Get-ControlDisk
    $efi = New-Partition -DiskNumber $disk.Number -Size 300MB -GptType '{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}' -DriveLetter $letters[0]
    Assert-ControlLetter $letters[0]
    $efi | Format-Volume -FileSystem FAT32 -NewFileSystemLabel N2R_REFSEFI -Confirm:$false | Out-Null
    $disk = Get-ControlDisk
    $msr = @(Get-Partition -DiskNumber $disk.Number | Where-Object GptType -eq '{E3C9E316-0B5C-4DB8-817D-F92DF00215AE}')
    if ($msr.Count -eq 0) { New-Partition -DiskNumber $disk.Number -Size 16MB -GptType '{E3C9E316-0B5C-4DB8-817D-F92DF00215AE}' | Out-Null }
    elseif ($msr.Count -ne 1) { throw 'Unexpected reserved partition count.' }
    $disk = Get-ControlDisk
    $osBytes = [int64]([Math]::Floor(($disk.LargestFreeExtent - 2GB - 1MB) / 1MB) * 1MB)
    if ($osBytes -lt 40GB) { throw 'Insufficient target capacity for OS and recovery.' }
    $windows = New-Partition -DiskNumber $disk.Number -Size $osBytes -DriveLetter $letters[1]
    $record.stage = 'ordinary-refs-format'
    Assert-ControlFormatPartition $windows $letters[1]
    $record.formatRequest = [pscustomobject]@{
        command = $(if ($FormatMethod -ceq 'FormatCom') { 'format.com' } else { 'Format-Volume' })
        mode = 'ordinary-ReFS'
        requestedPartitionSizeBytes = $osBytes
        actualPartitionSizeBytes = [int64]$windows.Size
        inputPartitionNumber = $windows.PartitionNumber
        inputDiskNumber = $disk.Number
        volume = $letters[1] + ':'
        nativeArguments = @()
        arguments = [pscustomobject]@{ FileSystem = 'ReFS'; AllocationUnitSize = 4096; NewFileSystemLabel = 'N2R_REFSOS'; Confirm = $false }
        omittedOptions = @('DevDrive','Full','Force','SetIntegrityStreams','UseLargeFRS','ShortFileNameSupport')
    }
    if ($FormatMethod -ceq 'FormatCom') {
        $record.formatRequest.nativeArguments = @(($letters[1] + ':'), '/FS:ReFS', '/A:4096', '/Q', '/V:N2R_REFSOS', '/Y')
        $record.formatRequest.omittedOptions = @('/DevDrv','/I:enable','/I:disable','/SHA256Checksums','/NoTrim','/P','/X')
    }
    # Persist before invoking the formatter, including when it refuses the
    # ordinary ReFS request or the process is interrupted during formatting.
    $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $runRoot 'result.json') -Encoding UTF8
    if ($FormatMethod -ceq 'FormatCom') {
        $capabilityScript = Join-Path $runRoot 'format-filesystems.txt'
        @("select disk $($disk.Number)", "select partition $($windows.PartitionNumber)", 'filesystems', 'exit') | Set-Content -LiteralPath $capabilityScript -Encoding ASCII
        $record.formatCapability = Invoke-ControlNative 'diskpart.exe' @('/s',$capabilityScript) 'format-filesystems.log' -TimeoutSeconds 30 -CloseStandardInput -PassThru
        Assert-ControlFormatPartition $windows $letters[1]
        try {
            $record.formatCompletion = Invoke-ControlNative 'format.com' $record.formatRequest.nativeArguments 'format-com.log' -TimeoutSeconds 120 -CloseStandardInput -PassThru
        } finally {
            $formatCommandPath = Join-Path $runRoot 'format-com.log.command.json'
            if (Test-Path -LiteralPath $formatCommandPath) { $record.formatCompletion = Get-Content -LiteralPath $formatCommandPath -Raw | ConvertFrom-Json }
        }
        Update-HostStorageCache
    } else {
        $windows | Format-Volume -FileSystem ReFS -AllocationUnitSize 4096 -NewFileSystemLabel N2R_REFSOS -Confirm:$false | Out-Null
    }
    Assert-ControlLetter $letters[1]
    $volume = Get-Volume -DriveLetter $letters[1]
    if ($volume.FileSystem -cne 'ReFS' -or $volume.AllocationUnitSize -ne 4096) { throw 'Ordinary format did not produce the requested ReFS volume.' }
    $record.formatSucceeded = $true
    $disk = Get-ControlDisk
    $recovery = New-Partition -DiskNumber $disk.Number -Size 2GB -DriveLetter $letters[2]
    Assert-ControlLetter $letters[2]
    $recovery | Format-Volume -FileSystem NTFS -AllocationUnitSize 4096 -NewFileSystemLabel N2R_REFSRE -Confirm:$false | Out-Null
    $efiRoot = $letters[0] + ':\'; $windowsRoot = $letters[1] + ':\'; $recoveryRoot = $letters[2] + ':\'
    Invoke-ControlNative 'fsutil.exe' @('fsinfo','refsinfo',$windowsRoot.TrimEnd('\')) 'refs-info.log'
    $record.stage = 'applying-image'
    Assert-ControlLetter $letters[1]
    Invoke-ControlNative 'dism.exe' @('/Apply-Image', ('/ImageFile:' + $wim), '/Index:6', ('/ApplyDir:' + $windowsRoot), '/CheckIntegrity', '/Verify', ('/LogPath:' + (Join-Path $runRoot 'dism-detail.log'))) 'dism-apply.log'
    $record.imageApplied = $true
    $record.stage = 'preparing-boot-files'
    Assert-ControlLetter $letters[0]; Assert-ControlLetter $letters[1]
    Invoke-ControlNative 'bcdboot.exe' @((Join-Path $windowsRoot 'Windows'), '/s', $efiRoot, '/f', 'UEFI', '/offline', '/v') 'bcdboot.log'
    Invoke-ControlNative 'bcdedit.exe' @('/store',(Join-Path $efiRoot 'EFI\Microsoft\Boot\BCD'),'/enum','all','/v') 'bcd-store.log'
    foreach ($path in @((Join-Path $efiRoot 'EFI\Microsoft\Boot\bootmgfw.efi'), (Join-Path $windowsRoot 'Windows\System32\winload.efi'), (Join-Path $windowsRoot 'Windows\System32\drivers\refs.sys'))) {
        $file = Get-Item -LiteralPath $path
        if ($file.PSIsContainer -or $file.Length -eq 0 -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Prepared image lacks an ordinary boot component.' }
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        $signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
        $record.bootFiles += [pscustomobject]@{ path = $path; version = $file.VersionInfo.FileVersion; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant(); signature = [string]$signature.Status; signer = $signer }
    }
    $record.bootFilesPrepared = $true
    $record.stage = 'registering-recovery'
    Assert-ControlLetter $letters[2]
    $reImage = Join-Path $recoveryRoot 'Recovery\WindowsRE'
    New-Item -ItemType Directory -Path $reImage | Out-Null
    Copy-Item -LiteralPath (Join-Path $windowsRoot 'Windows\System32\Recovery\Winre.wim') -Destination (Join-Path $reImage 'Winre.wim')
    Invoke-ControlNative 'reagentc.exe' @('/setreimage','/path',$reImage,'/target',(Join-Path $windowsRoot 'Windows')) 'reagentc.log'
    $disk = Get-ControlDisk
    $diskPart = Join-Path $runRoot 'recovery-attributes.txt'
    @("select disk $($disk.Number)", "select partition $($recovery.PartitionNumber)", 'set id=de94bba4-06d1-4d40-a16a-bfd50179d6ac override', 'gpt attributes=0x8000000000000001', 'detail partition', 'exit') | Set-Content -LiteralPath $diskPart -Encoding ASCII
    Invoke-ControlNative 'diskpart.exe' @('/s',$diskPart) 'recovery-attributes.log'
    Update-HostStorageCache
    $disk = Get-ControlDisk
    $recoveryCheck = Get-Partition -DiskNumber $disk.Number -PartitionNumber $recovery.PartitionNumber
    $recoveryCheck | Select-Object DiskNumber,PartitionNumber,Offset,Size,GptType,NoDefaultDriveLetter,IsHidden,IsReadOnly | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runRoot 'recovery-partition.json') -Encoding UTF8
    if (-not (Test-ControlRecoveryPartition $recoveryCheck (Get-Content -LiteralPath (Join-Path $runRoot 'recovery-attributes.log') -Raw))) { throw 'Recovery partition type or native attributes were not verified.' }
    $record.stage = 'configuring-first-boot'
    Assert-ControlLetter $letters[1]
    $passwordXml = [Security.SecurityElement]::Escape($FirstBootCredential.GetNetworkCredential().Password)
    $answer = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
 <settings pass="specialize"><component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><ComputerName>N2R-WIN11</ComputerName><TimeZone>Eastern Standard Time</TimeZone></component>
 <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><RunSynchronous><RunSynchronousCommand wcm:action="add"><Order>1</Order><Path>cmd.exe /c C:\Windows\Setup\Scripts\PrepareLab.cmd</Path><Description>Prepare isolated filesystem control</Description></RunSynchronousCommand></RunSynchronous></component></settings>
 <settings pass="oobeSystem"><component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale></component>
 <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><OOBE><HideEULAPage>true</HideEULAPage><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>3</ProtectYourPC></OOBE><UserAccounts><LocalAccounts><LocalAccount wcm:action="add"><Name>LabAdmin</Name><Group>Administrators</Group><Password><Value>$passwordXml</Value><PlainText>true</PlainText></Password></LocalAccount></LocalAccounts></UserAccounts></component></settings>
</unattend>
"@
    $panther = Join-Path $windowsRoot 'Windows\Panther'
    New-Item -ItemType Directory -Path $panther -Force | Out-Null
    ([xml]$answer).Save((Join-Path $panther 'unattend.xml'))
    $passwordXml = $null; $answer = $null
    $prepareDir = Join-Path $windowsRoot 'Windows\Setup\Scripts'
    New-Item -ItemType Directory -Path $prepareDir -Force | Out-Null
    @('@echo off', 'reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\BitLocker /v PreventDeviceEncryption /t REG_DWORD /d 1 /f', 'powercfg.exe /hibernate off', 'compact.exe /compactos:never', 'exit /b 0') | Set-Content -LiteralPath (Join-Path $prepareDir 'PrepareLab.cmd') -Encoding ASCII
    $markerRoot = Join-Path $windowsRoot 'ntfs2refs'
    New-Item -ItemType Directory -Path $markerRoot | Out-Null
    [pscustomobject]@{ schemaVersion = 1; purpose = 'native-refs-os-control'; targetUniqueId = $identity.uniqueId; sourceOsUniqueId = [string]$sourceDisk.UniqueId; hostVhdId = $spec.vhdId; expectedFilesystem = 'ReFS'; expectedBuild = '26300.9457' } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $markerRoot 'refs-os-control.json') -Encoding UTF8
    $record.firstBootConfigured = $true
    $record.status = 'prepared'; $record.stage = 'prepared-awaiting-separate-boot-validation'
} catch {
    $record.status = 'blocked'; $record.error = $_.Exception.Message; $record.errorHresult = $_.Exception.HResult
    $record['errorId'] = $_.FullyQualifiedErrorId; $record['errorPosition'] = $_.InvocationInfo.PositionMessage; $record['scriptStackTrace'] = $_.ScriptStackTrace
} finally {
    if ($identity) { try { $disk = Get-ControlDisk; $record.partitions = @(Get-Partition -DiskNumber $disk.Number | Select-Object PartitionNumber,Offset,Size,GptType,DriveLetter,NoDefaultDriveLetter) } catch { } }
    $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $runRoot 'result.json') -Encoding UTF8
    $FirstBootCredential = $null
}
[pscustomobject]@{ status = $record.status; stage = $record.stage; evidenceDirectory = $runRoot; refsBootVerified = $false }
