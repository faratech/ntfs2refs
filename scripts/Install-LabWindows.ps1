<# Offline installation into a new manifest-owned OS VHDX only.
https://learn.microsoft.com/windows-hardware/manufacture/desktop/capture-and-apply-windows-using-a-single-wim
https://learn.microsoft.com/windows-hardware/manufacture/desktop/bcdboot-command-line-options-techref-di
https://learn.microsoft.com/windows-hardware/manufacture/desktop/reagentc-command-line-options
#>
[CmdletBinding(SupportsShouldProcess)]
param([ValidateSet('win11')][string]$Lane = 'win11', [switch]$ResumeAppliedImage)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
$configuration = Get-LabConfiguration -WorkspaceRoot $workspace
$laneRoot = Assert-LabPath -Path (Join-Path $configuration.Root $Lane) -Root $configuration.Root
$actionDescription = if ($ResumeAppliedImage) { 'Resume recorded post-DISM BCDBoot failure; preserve partitions/image and configure boot with host tools' } else { 'Install Windows 11 Pro index 6 into new RAW OS VHDX; leave VM off' }
if (-not $PSCmdlet.ShouldProcess($laneRoot, $actionDescription)) {
    [pscustomobject]@{ Action = 'InstallWindows'; Lane = $Lane; DryRun = $true; ResumeAppliedImage = [bool]$ResumeAppliedImage; PartitionOrFormatOperations = -not $ResumeAppliedImage; ImageIndex = 6; ExpectedBuild = '10.0.26300.9457'; Requires = 'Elevated token and provisioner ownership manifest' }
    return
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Offline installation requires an elevated PowerShell helper.' }
Import-Module Hyper-V -ErrorAction Stop
$manifest = Read-LabManifest -Configuration $configuration -Lane $Lane
if (-not $manifest) { throw 'Provision the lane first; no ownership manifest exists.' }
$vm = Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
if ($vm.State -ne 'Off' -or @(Get-VMCheckpoint -VM $vm).Count) { throw 'Installation requires a powered-off new VM with no checkpoints.' }
$osDisks = @($manifest.disks | Where-Object role -eq 'os')
if ($osDisks.Count -ne 1) { throw 'Manifest must identify exactly one OS disk.' }
$osDisk = $osDisks[0]
$vhdPath = Assert-LabPath -Path $osDisk.path -Root $configuration.Root
$vhd = Get-VHD -Path $vhdPath -ErrorAction Stop
if ($vhd.Attached -or $vhd.ParentPath -or [string]$vhd.DiskIdentifier -ne [string]$osDisk.vhdId -or $vhd.Size -ne $osDisk.sizeBytes) { throw 'OS VHD must be unattached, have no parent, and match its manifest identity/size.' }
$installRoot = Assert-LabPath -Path (Join-Path $laneRoot 'install') -Root $configuration.Root
if ($ResumeAppliedImage) {
    $previousState = Get-Content -LiteralPath (Join-Path $installRoot 'state.json') -Raw | ConvertFrom-Json
    if ($previousState.schemaVersion -ne 1 -or $previousState.stage -ne 'failed' -or $previousState.lane -ne $Lane -or [string]$previousState.vmId -ne [string]$manifest.vmId -or [string]$previousState.vhdId -ne [string]$osDisk.vhdId) { throw 'Resume accepts only a recorded post-apply BCDBoot failure on this exact VM/VHD.' }
    $imageToolBlocked = $previousState.detail -ceq 'bcdboot.exe failed with exit code -1058471934; see bcdboot.log.'
    $offlineSelectionRequired = $previousState.detail -ceq 'BFSVC Error: USE_EX_BINS flag is specified, but 2023 cert is not in db'
    $recoveryVerificationRequired = $previousState.detail -ceq 'Recovery partition type/attributes were not applied.'
    if (-not ($imageToolBlocked -or $offlineSelectionRequired -or $recoveryVerificationRequired)) { throw 'This failure is outside the narrow applied-image resume allowlist.' }
    if ($recoveryVerificationRequired) {
        foreach ($name in @('bcdboot.log','reagentc-setreimage.log','recovery-attributes.log')) {
            $priorCommand = Get-Content -LiteralPath (Join-Path $installRoot ($name + '.command.json')) -Raw | ConvertFrom-Json
            if ($priorCommand.status -cne 'exited' -or $priorCommand.exitCode -ne 0) { throw 'Recovery verification resume requires successful recorded deployment commands.' }
        }
        $priorRecoveryLog = Get-Content -LiteralPath (Join-Path $installRoot 'recovery-attributes.log') -Raw
        if ($priorRecoveryLog -notmatch 'DiskPart successfully set the partition ID\.' -or $priorRecoveryLog -notmatch 'DiskPart successfully assigned the attributes') { throw 'Recovery verification resume requires the native partition-operation evidence.' }
    }
    if ($offlineSelectionRequired) {
        $priorBootLog = Get-Content -LiteralPath (Join-Path $installRoot 'bcdboot.log') -Raw
        $priorTools = Get-Content -LiteralPath (Join-Path $installRoot 'deployment-tools.json') -Raw | ConvertFrom-Json
        $priorBootTool = $priorTools.'bcdboot.exe'
        if ($priorBootLog -notmatch 'BootEx:y Offline:n' -or $priorBootLog -notmatch 'BFSVC: Not using Ex bins\.' -or $priorBootTool.path -ine (Join-Path $env:SystemRoot 'System32\bcdboot.exe') -or $priorBootTool.signatureStatus -cne 'Valid' -or $priorBootTool.signer -notmatch 'O=Microsoft Corporation' -or $priorBootTool.sha256 -notmatch '^[0-9a-f]{64}$') { throw 'Certificate-selection resume requires the prior signed host-tool and online-selection log evidence.' }
    }
    $applyLog = Get-Content -LiteralPath (Join-Path $installRoot 'dism-apply.log') -Raw
    if ($applyLog -notmatch '100\.0%' -or $applyLog -notmatch 'The operation completed successfully\.') { throw 'Resume requires evidence that DISM applied the image successfully.' }
    if ((Test-Path -LiteralPath (Join-Path $laneRoot 'secrets')) -or (Test-Path -LiteralPath (Join-Path $installRoot 'installed-image.json'))) { throw 'First-boot configuration already exists; this narrow resume path will not overwrite it.' }
    Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 4GB
} else {
    if (Test-Path -LiteralPath $installRoot) { throw 'An install attempt already exists. Inspect install/state.json and the VHD; no automatic retry or erase is performed.' }
    Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes ([int64]$osDisk.sizeBytes)
}
$iso = Get-Item -LiteralPath $manifest.media.isoPath -ErrorAction Stop
if ($iso.Extension -ne '.iso' -or $iso.Length -ne $manifest.media.length) { throw 'ISO does not match media manifest.' }
if ((Get-FileHash -LiteralPath $iso.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $manifest.media.sha256) { throw 'ISO checksum does not match media manifest.' }
function Write-InstallState([string]$Stage, [string]$Detail = '') {
    [pscustomobject]@{ schemaVersion = 1; lane = $Lane; vmId = $manifest.vmId; vhdId = $osDisk.vhdId; stage = $Stage; detail = $Detail; updatedUtc = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $installRoot 'state.json') -Encoding UTF8
}
function Assert-InstallDisk {
    $currentVhd = Get-VHD -Path $vhdPath -ErrorAction Stop
    if (-not $currentVhd.Attached -or $currentVhd.DiskNumber -ne $script:installDiskNumber -or [string]$currentVhd.DiskIdentifier -ne [string]$osDisk.vhdId) { throw 'Mounted VHD identity changed.' }
    $currentDisk = Get-Disk -Number $script:installDiskNumber -ErrorAction Stop
    if ($currentDisk.IsBoot -or $currentDisk.IsSystem -or $currentDisk.Size -ne $osDisk.sizeBytes -or [string]$currentDisk.UniqueId -ne $script:installDiskUniqueId) { throw 'Mounted disk identity/role changed.' }
    if ([string]$currentDisk.BusType -notin @('File Backed Virtual','FileBackedVirtual','Virtual')) { throw 'Target is not a virtual disk.' }
    if ((Get-VM -Id ([guid]$manifest.vmId)).State -ne 'Off') { throw 'VM must remain powered off.' }
}
function ConvertTo-InstallNativeArgument([AllowEmptyString()][string]$Argument) {
    # Win32 argv quoting: escape quotes and double trailing backslashes before
    # the closing quote. In particular, an EFI root such as F:\ stays intact.
    '"' + ($Argument -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}
function Test-InstallRecoveryPartition($Partition, [string]$NativeDetail) {
    # The Storage provider returns null for NoDefaultDriveLetter on this
    # recovery partition. Verify the actual GPT attributes from DiskPart's
    # detail output, including the selected partition's type and byte offset.
    $offset = [string]$Partition.Offset
    $Partition.GptType -ieq '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}' -and
        $Partition.Size -eq 2GB -and
        $NativeDetail -match '(?im)^Type\s*:\s*de94bba4-06d1-4d40-a16a-bfd50179d6ac\s*$' -and
        $NativeDetail -match '(?im)^Attrib\s*:\s*0x8000000000000001\s*$' -and
        $NativeDetail -match ('(?im)^Offset in Bytes:\s*' + [regex]::Escape($offset) + '\s*$')
}
function Invoke-InstallNative([string]$Executable, [string[]]$Arguments, [string]$LogName) {
    Assert-InstallDisk
    $logPath = Join-Path $installRoot $LogName
    $commandPath = $logPath + '.command.json'
    $command = [ordered]@{ executable = $Executable; arguments = @($Arguments); startedUtc = [DateTime]::UtcNow.ToString('o'); completedUtc = $null; exitCode = $null; status = 'starting' }
    $command | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $commandPath -Encoding UTF8
    $process = New-Object Diagnostics.Process
    try {
        $process.StartInfo.FileName = $Executable
        $process.StartInfo.Arguments = (($Arguments | ForEach-Object { ConvertTo-InstallNativeArgument $_ }) -join ' ')
        $process.StartInfo.WorkingDirectory = $installRoot
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        if (-not $process.Start()) { throw 'Native deployment tool did not start.' }
        # Read both pipes concurrently; PowerShell 5 must not promote native
        # stderr to a terminating NativeCommandError before the exit is read.
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $stdout | Set-Content -LiteralPath $logPath -Encoding UTF8
        if ($stderr) { @('[stderr]', $stderr) | Add-Content -LiteralPath $logPath -Encoding UTF8 }
        $command.exitCode = $process.ExitCode
        $command.status = 'exited'
    } catch {
        $command.status = 'invocation-failed'
        throw
    } finally {
        $command.completedUtc = [DateTime]::UtcNow.ToString('o')
        $command | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $commandPath -Encoding UTF8
        $process.Dispose()
    }
    if ($command.exitCode -ne 0) { throw "$([IO.Path]::GetFileName($Executable)) failed with exit code $($command.exitCode); see $LogName." }
}
$mountedVhd = $false; $mountedIso = $false; $completed = $false
if ($ResumeAppliedImage) {
    $archive = Assert-LabPath (Join-Path $installRoot ('resume-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $configuration.Root
    New-Item -ItemType Directory -Path $archive | Out-Null
    foreach ($name in @('state.json','dism-apply.log','dism-apply.log.command.json','dism-detail.log','bcdboot.log','bcdboot.log.command.json','boot-configuration.json','deployment-tools.json','reagentc-setreimage.log','reagentc-setreimage.log.command.json','recovery-attributes.log','recovery-attributes.log.command.json','recovery-partition.json','set-recovery-attributes.txt')) {
        $old = Join-Path $installRoot $name
        if (Test-Path -LiteralPath $old -PathType Leaf) { Copy-Item -LiteralPath $old -Destination (Join-Path $archive $name) }
    }
} else { New-Item -ItemType Directory -Path $installRoot | Out-Null }
Write-InstallState 'validating'
$deploymentTools = @{}
foreach ($toolName in @('bcdboot.exe','reagentc.exe')) {
    $toolPath = Join-Path $env:SystemRoot ('System32\' + $toolName)
    $tool = Get-Item -LiteralPath $toolPath
    $signature = Get-AuthenticodeSignature -LiteralPath $toolPath
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'The host deployment tool must have a valid Microsoft signature.' }
    $deploymentTools[$toolName] = [pscustomobject]@{ path = $toolPath; fileVersion = $tool.VersionInfo.FileVersion; sha256 = (Get-FileHash -LiteralPath $toolPath -Algorithm SHA256).Hash.ToLowerInvariant(); signatureStatus = [string]$signature.Status; signer = $signature.SignerCertificate.Subject }
}
$deploymentTools | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $installRoot 'deployment-tools.json') -Encoding UTF8
try {
    $mediaImage = Get-DiskImage -ImagePath $iso.FullName -ErrorAction SilentlyContinue
    if (-not $mediaImage -or -not $mediaImage.Attached) {
        $mediaImage = Mount-DiskImage -ImagePath $iso.FullName -Access ReadOnly -PassThru
        $mountedIso = $true
    }
    $mediaVolumes = @($mediaImage | Get-Volume | Where-Object DriveLetter)
    if ($mediaVolumes.Count -ne 1) { throw 'ISO must expose exactly one drive-letter volume.' }
    $wimPath = Join-Path ($mediaVolumes[0].DriveLetter + ':\') 'sources\install.wim'
    $image = Get-WindowsImage -ImagePath $wimPath -Index 6 -ErrorAction Stop
    if ($image.EditionId -ne 'Professional' -or [version]$image.Version -ne [version]'10.0.26300.9457') { throw 'Image index 6 is not pinned Windows 11 Pro 26300.9457.' }
    $usedLetters = @(Get-Volume | Where-Object DriveLetter | ForEach-Object { [string]$_.DriveLetter })
    $letters = @([char[]](70..90) | ForEach-Object { [string]$_ } | Where-Object { $_ -notin $usedLetters -and -not (Test-Path -LiteralPath ($_ + ':\')) } | Select-Object -First 3)
    if ($letters.Count -ne 3) { throw 'Three unused temporary drive letters are required.' }
    $attached = Mount-VHD -Path $vhdPath -NoDriveLetter -PassThru
    $mountedVhd = $true
    $script:installDiskNumber = $attached.DiskNumber
    $targetDisk = Get-Disk -Number $script:installDiskNumber
    $script:installDiskUniqueId = [string]$targetDisk.UniqueId
    Assert-InstallDisk
    if ($ResumeAppliedImage) {
        if ($targetDisk.PartitionStyle -ne 'GPT' -or $targetDisk.IsReadOnly) { throw 'Applied-image resume requires the existing writable GPT OS VHD.' }
        if ($targetDisk.IsOffline) { Set-Disk -Number $script:installDiskNumber -IsOffline $false }
        $parts = @(Get-Partition -DiskNumber $script:installDiskNumber)
        $msr = @($parts | Where-Object GptType -eq '{E3C9E316-0B5C-4DB8-817D-F92DF00215AE}')
        $efiMatches = @($parts | Where-Object { $_.GptType -eq '{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}' -and $_.Size -eq 300MB })
        # Initialize-Disk's automatic MSR starts after GPT headers and ends at
        # the 16 MiB boundary; explicit New-Partition MSRs occupy a full 16 MiB.
        $msrValid = $msr.Count -eq 1 -and ($msr[0].Size -eq 16MB -or ($msr[0].Offset -eq 17408 -and $msr[0].Size -eq (16MB - 17408)))
        if ($parts.Count -ne 4 -or -not $msrValid -or $efiMatches.Count -ne 1) { throw 'Applied-image partition layout differs from the expected four-partition installation.' }
        $windowsMatches = @(); $recoveryMatches = @()
        foreach ($part in $parts | Where-Object { $_.PartitionNumber -ne $msr[0].PartitionNumber }) {
            $volumes = @(Get-Volume -Partition $part)
            if ($volumes.Count -ne 1) { throw 'Applied-image partition has an ambiguous or missing filesystem.' }
            $volume = $volumes[0]
            if ($part.PartitionNumber -eq $efiMatches[0].PartitionNumber) {
                if ($volume.FileSystem -ne 'FAT32' -or $volume.FileSystemLabel -ne 'N2R_EFI') { throw 'EFI filesystem/label differs from the recorded installation.' }
            } elseif ($volume.FileSystem -eq 'NTFS' -and $volume.FileSystemLabel -eq 'N2R_WINDOWS' -and $part.Size -ge 40GB) { $windowsMatches += $part }
            elseif ($volume.FileSystem -eq 'NTFS' -and $volume.FileSystemLabel -eq 'N2R_WINRE' -and $part.Size -eq 2GB) { $recoveryMatches += $part }
            else { throw 'Unexpected partition content; resume will not overwrite it.' }
        }
        if ($windowsMatches.Count -ne 1 -or $recoveryMatches.Count -ne 1) { throw 'OS and recovery volumes must be uniquely identified.' }
        $efi = $efiMatches[0]; $windows = $windowsMatches[0]; $recovery = $recoveryMatches[0]
        $selected = @($efi,$windows,$recovery)
        for ($i = 0; $i -lt 3; $i++) {
            Assert-InstallDisk
            Set-Partition -DiskNumber $script:installDiskNumber -PartitionNumber $selected[$i].PartitionNumber -NewDriveLetter $letters[$i]
        }
        $efiRoot = $letters[0] + ':\'; $windowsRoot = $letters[1] + ':\'; $recoveryRoot = $letters[2] + ':\'
        foreach ($relative in @('Windows\System32\config\SYSTEM','Windows\System32\config\SOFTWARE','Windows\System32\ntoskrnl.exe','Windows\System32\winload.efi','Windows\Boot\EFI\bootmgfw.efi')) {
            $appliedFile = Get-Item -LiteralPath (Join-Path $windowsRoot $relative) -ErrorAction Stop
            if ($appliedFile.PSIsContainer -or $appliedFile.Length -eq 0 -or ($appliedFile.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Applied Windows image is missing required ordinary files.' }
        }
        Write-InstallState 'resuming-applied-image' 'Existing partitions and DISM-applied Windows preserved; boot configuration only.'
    } else {
    if ($targetDisk.PartitionStyle -ne 'RAW' -or @(Get-Partition -DiskNumber $script:installDiskNumber -ErrorAction SilentlyContinue).Count) { throw 'Only a new RAW unpartitioned OS VHDX may be installed.' }
    if ($targetDisk.IsReadOnly) { throw 'New OS disk is unexpectedly read-only.' }
    if ($targetDisk.IsOffline) { Set-Disk -Number $script:installDiskNumber -IsOffline $false }
    Write-InstallState 'partitioning'
    Assert-InstallDisk
    Initialize-Disk -Number $script:installDiskNumber -PartitionStyle GPT | Out-Null
    $efi = New-Partition -DiskNumber $script:installDiskNumber -Size 300MB -GptType '{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}' -DriveLetter $letters[0]
    $efi | Format-Volume -FileSystem FAT32 -NewFileSystemLabel N2R_EFI -Confirm:$false | Out-Null
    $existingMsr = @(Get-Partition -DiskNumber $script:installDiskNumber | Where-Object GptType -eq '{E3C9E316-0B5C-4DB8-817D-F92DF00215AE}')
    if ($existingMsr.Count -eq 0) { New-Partition -DiskNumber $script:installDiskNumber -Size 16MB -GptType '{E3C9E316-0B5C-4DB8-817D-F92DF00215AE}' | Out-Null }
    $freeExtent = (Get-Disk -Number $script:installDiskNumber).LargestFreeExtent
    $osBytes = [int64]([Math]::Floor(($freeExtent - 2GB - 1MB) / 1MB) * 1MB)
    if ($osBytes -lt 40GB) { throw 'Insufficient actual free extent for OS and recovery partitions.' }
    $windows = New-Partition -DiskNumber $script:installDiskNumber -Size $osBytes -DriveLetter $letters[1]
    $windows | Format-Volume -FileSystem NTFS -AllocationUnitSize 4096 -NewFileSystemLabel N2R_WINDOWS -Confirm:$false | Out-Null
    $recovery = New-Partition -DiskNumber $script:installDiskNumber -Size 2GB -DriveLetter $letters[2]
    $recovery | Format-Volume -FileSystem NTFS -AllocationUnitSize 4096 -NewFileSystemLabel N2R_WINRE -Confirm:$false | Out-Null
    $efiRoot = $letters[0] + ':\'; $windowsRoot = $letters[1] + ':\'; $recoveryRoot = $letters[2] + ':\'
    Write-InstallState 'applying-image'
    Invoke-InstallNative -Executable (Join-Path $env:SystemRoot 'System32\dism.exe') -Arguments @('/Apply-Image', "/ImageFile:$wimPath", '/Index:6', "/ApplyDir:$windowsRoot", '/CheckIntegrity', '/Verify', ('/LogPath:' + (Join-Path $installRoot 'dism-detail.log'))) -LogName 'dism-apply.log'
    }
    Write-InstallState 'configuring-boot'
    $bootArguments = @((Join-Path $windowsRoot 'Windows'), '/s', $efiRoot, '/f', 'UEFI', '/offline', '/v')
    [pscustomobject]@{ sourceWindows = (Join-Path $windowsRoot 'Windows'); destinationEfi = $efiRoot; executable = $deploymentTools['bcdboot.exe'].path; arguments = $bootArguments; offlineServicing = $true; bootex = $false; bootFiles = 'Standard signed files from the guest Windows image'; secureBootPolicy = 'Unchanged'; vmId = $manifest.vmId; vhdId = $osDisk.vhdId } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $installRoot 'boot-configuration.json') -Encoding UTF8
    Invoke-InstallNative -Executable $deploymentTools['bcdboot.exe'].path -Arguments $bootArguments -LogName 'bcdboot.log'
    $reImage = Join-Path $recoveryRoot 'Recovery\WindowsRE'
    New-Item -ItemType Directory -Path $reImage -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $windowsRoot 'Windows\System32\Recovery\Winre.wim') -Destination (Join-Path $reImage 'Winre.wim')
    Invoke-InstallNative -Executable $deploymentTools['reagentc.exe'].path -Arguments @('/setreimage', '/path', $reImage, '/target', (Join-Path $windowsRoot 'Windows')) -LogName 'reagentc-setreimage.log'
    # /enable runs during specialize. Never invoke host-online /enable here.
    $diskPartPath = Join-Path $installRoot 'set-recovery-attributes.txt'
    @("select disk $script:installDiskNumber", "select partition $($recovery.PartitionNumber)", 'set id=de94bba4-06d1-4d40-a16a-bfd50179d6ac override', 'gpt attributes=0x8000000000000001', 'detail partition', 'exit') | Set-Content -LiteralPath $diskPartPath -Encoding ASCII
    Invoke-InstallNative -Executable (Join-Path $env:SystemRoot 'System32\diskpart.exe') -Arguments @('/s', $diskPartPath) -LogName 'recovery-attributes.log'
    # DiskPart and the Storage module use different views. Refresh the owned
    # partition/volume cache before verifying the native partition change.
    Update-HostStorageCache
    Assert-InstallDisk
    $recoveryCheck = Get-Partition -DiskNumber $script:installDiskNumber -PartitionNumber $recovery.PartitionNumber
    $recoveryCheck | Select-Object DiskNumber,PartitionNumber,Offset,Size,GptType,NoDefaultDriveLetter,IsHidden,IsReadOnly | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $installRoot 'recovery-partition.json') -Encoding UTF8
    $recoveryDetail = Get-Content -LiteralPath (Join-Path $installRoot 'recovery-attributes.log') -Raw
    if (-not (Test-InstallRecoveryPartition $recoveryCheck $recoveryDetail)) { throw 'Recovery partition type/attributes were not applied.' }
    Write-InstallState 'configuring-first-boot'
    # First-boot configuration is generated below; never print the credential.
    $secretRoot = Assert-LabPath -Path (Join-Path $laneRoot 'secrets') -Root $configuration.Root
    New-Item -ItemType Directory -Path $secretRoot | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User, [Security.Principal.SecurityIdentifier]'S-1-5-18', [Security.Principal.SecurityIdentifier]'S-1-5-32-544')) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -LiteralPath $secretRoot -AclObject $acl
    $random = New-Object byte[] 24
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($random) } finally { $rng.Dispose() }
    $password = 'Aa1!' + [Convert]::ToBase64String($random)
    $credential = New-Object Management.Automation.PSCredential('N2R-WIN11\LabAdmin', (ConvertTo-SecureString $password -AsPlainText -Force))
    $credential | Export-Clixml -LiteralPath (Join-Path $secretRoot 'guest-credential.xml')
    $passwordXml = [Security.SecurityElement]::Escape($password)
    $answer = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>N2R-WIN11</ComputerName><TimeZone>Eastern Standard Time</TimeZone>
    </component>
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RunSynchronous><RunSynchronousCommand wcm:action="add"><Order>1</Order><Path>cmd.exe /c C:\Windows\Setup\Scripts\PrepareLab.cmd</Path><Description>Prepare isolated filesystem research guest</Description></RunSynchronousCommand></RunSynchronous>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE><HideEULAPage>true</HideEULAPage><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>3</ProtectYourPC></OOBE>
      <UserAccounts><LocalAccounts><LocalAccount wcm:action="add"><Name>LabAdmin</Name><DisplayName>Filesystem Lab Administrator</DisplayName><Group>Administrators</Group><Password><Value>$passwordXml</Value><PlainText>true</PlainText></Password></LocalAccount></LocalAccounts></UserAccounts>
    </component>
  </settings>
</unattend>
"@
    [xml]$answerDocument = $answer
    $panther = Join-Path $windowsRoot 'Windows\Panther'
    New-Item -ItemType Directory -Path $panther -Force | Out-Null
    $answerDocument.Save((Join-Path $panther 'unattend.xml'))
    $prepareDir = Join-Path $windowsRoot 'Windows\Setup\Scripts'
    New-Item -ItemType Directory -Path $prepareDir -Force | Out-Null
    @('@echo off', 'reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\BitLocker /v PreventDeviceEncryption /t REG_DWORD /d 1 /f', 'powercfg.exe /hibernate off', 'compact.exe /compactos:never', 'exit /b 0') | Set-Content -LiteralPath (Join-Path $prepareDir 'PrepareLab.cmd') -Encoding ASCII
    $password = $null; $passwordXml = $null; $answer = $null; $answerDocument = $null; $credential = $null
    [pscustomobject]@{ schemaVersion = 1; vmId = $manifest.vmId; vhdId = $osDisk.vhdId; diskUniqueId = $script:installDiskUniqueId; imageName = $image.ImageName; imageVersion = [string]$image.Version; imageIndex = 6; computerName = 'N2R-WIN11'; winreRegistration = 'Offline path registered; enablement and boot require guest validation'; credentialPath = (Join-Path $secretRoot 'guest-credential.xml'); partitions = @(Get-Partition -DiskNumber $script:installDiskNumber | Select-Object PartitionNumber,Offset,Size,GptType) } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $installRoot 'installed-image.json') -Encoding UTF8
    $completed = $true
    Write-InstallState 'applied-offline' 'First boot, OOBE completion and WinRE enablement still require guest validation.'
} catch {
    Write-InstallState 'failed' $_.Exception.Message
    throw
} finally {
    if ($mountedVhd) { Dismount-VHD -Path $vhdPath -ErrorAction Continue }
    if ($mountedIso) { Dismount-DiskImage -ImagePath $iso.FullName -ErrorAction Continue | Out-Null }
}
if ($completed) {
    if ((Get-VHD -Path $vhdPath).Attached) { Write-InstallState 'failed' 'OS VHD did not detach; no checkpoint created.'; throw 'OS VHD must be detached before checkpointing.' }
    $vm = Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    if ($vm.State -ne 'Off') { throw 'VM unexpectedly started before offline checkpoint.' }
    $osAttachment = @(Get-VMHardDiskDrive -VM $vm | Where-Object { $_.ControllerNumber -eq 0 -and $_.ControllerLocation -eq $osDisk.controllerLocation })
    if ($osAttachment.Count -ne 1) { throw 'OS attachment no longer uniquely identified.' }
    Set-VMFirmware -VM $vm -FirstBootDevice $osAttachment[0]
    Checkpoint-VM -VM $vm -SnapshotName 'applied-offline'
    [pscustomobject]@{ VMName = $manifest.vmName; State = 'Off'; Installation = 'AppliedOffline'; Checkpoint = 'applied-offline'; Next = 'Start the owned VM and verify first boot using PowerShell Direct.' }
}
