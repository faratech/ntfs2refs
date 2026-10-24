<# First boot and native NTFS control qualification for the owned Windows 11 VM.
   Does not format data disks, attempt ReFS boot, or run filesystem conversion. #>
[CmdletBinding(SupportsShouldProcess)]
param([ValidateSet('win11')][string]$Lane = 'win11', [ValidateRange(60,1800)][int]$BootTimeoutSeconds = 900)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
$configuration = Get-LabConfiguration -WorkspaceRoot $workspace
$laneRoot = Assert-LabPath -Path (Join-Path $configuration.Root $Lane) -Root $configuration.Root
if (-not $PSCmdlet.ShouldProcess($laneRoot, 'Boot owned installed Windows VM, validate NTFS control, copy tools, cleanly shut down, checkpoint and export baseline')) {
    [pscustomobject]@{ Action='InitializeGuest'; Lane=$Lane; DryRun=$true; TimeoutSeconds=$BootTimeoutSeconds; Checkpoint='installed-clean'; DataDiskWrites=$false; ReFSBootTest=$false }
    return
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Guest initialization requires the reviewed elevated Hyper-V helper.' }
Import-Module Hyper-V -ErrorAction Stop
$manifest = Read-LabManifest -Configuration $configuration -Lane $Lane
if (-not $manifest) { throw 'Missing lab ownership manifest.' }
$vm = Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
if ($vm.State -ne 'Off') { throw 'Initialize requires the owned VM to be powered off.' }
$other = @(Get-VM | Where-Object { $_.Name -in @('ntfs2refs-win11','ntfs2refs-server') -and $_.Id -ne $vm.Id -and $_.State -ne 'Off' })
if ($other.Count) { throw 'Another lab VM is active; only one may run at a time.' }
if (@(Get-VMNetworkAdapter -VM $vm | Where-Object { $_.SwitchName }).Count) { throw 'The experiment NIC must remain disconnected.' }
$installStatePath = Assert-LabPath (Join-Path $laneRoot 'install\state.json') $configuration.Root
$installState = Get-Content -LiteralPath $installStatePath -Raw | ConvertFrom-Json
if ($installState.stage -ne 'applied-offline' -or [string]$installState.vmId -ne [string]$manifest.vmId) { throw 'Offline installation has not completed for this VM.' }
$credentialPath = Assert-LabPath (Join-Path $laneRoot 'secrets\guest-credential.xml') $configuration.Root
$credential = Import-Clixml -LiteralPath $credentialPath
if ($credential -isnot [Management.Automation.PSCredential] -or $credential.UserName -cne 'N2R-WIN11\LabAdmin') { throw 'Unexpected guest credential identity.' }
$binaryCandidates = @((Join-Path $workspace 'target\release\ntfs2refs.exe'),(Join-Path $workspace 'target\debug\ntfs2refs.exe'))
$binary = $binaryCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $binary) { throw 'Build ntfs2refs.exe before initializing the guest.' }
Assert-LabPath -Path $binary -Root $workspace | Out-Null
$binaryHash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
$evidenceRoot = Assert-LabPath (Join-Path $laneRoot 'firstboot') $configuration.Root
$statePath = Join-Path $evidenceRoot 'state.json'
$evidencePath = Join-Path $evidenceRoot 'native-ntfs-evidence.json'
if (Test-Path -LiteralPath $statePath) { throw 'A first-boot attempt already exists. Inspect its state and VM before retrying; prior evidence will not be overwritten.' }
Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 4GB
New-Item -ItemType Directory -Path $evidenceRoot -Force | Out-Null
function Write-GuestState([string]$Stage,[string]$Detail='') {
    [pscustomobject]@{schemaVersion=1;stage=$Stage;detail=$Detail;vmId=$manifest.vmId;updatedUtc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
}
$session = $null
Write-GuestState 'starting'
try {
    $os = @($manifest.disks | Where-Object role -eq 'os')
    if ($os.Count -ne 1) { throw 'Manifest does not identify one OS disk.' }
    $attachment = @(Get-VMHardDiskDrive -VM $vm | Where-Object { $_.ControllerNumber -eq 0 -and $_.ControllerLocation -eq $os[0].controllerLocation })
    if ($attachment.Count -ne 1) { throw 'OS attachment is ambiguous.' }
    Set-VMFirmware -VM $vm -FirstBootDevice $attachment[0]
    Invoke-LabAction -Action Start -Lane $Lane -Confirm:$false | Out-Null
    Write-GuestState 'waiting-for-setup' 'PowerShell Direct probes are bounded; credential values are never written to logs.'
    $deadline = [DateTime]::UtcNow.AddSeconds($BootTimeoutSeconds)
    $ready = $false
    while ([DateTime]::UtcNow -lt $deadline -and -not $ready) {
        $probe = $null
        try {
            $probe = Invoke-Command -VMId ([guid]$manifest.vmId) -Credential $credential -AsJob -ScriptBlock {
                $setup = Get-ItemProperty 'HKLM:\SYSTEM\Setup'
                $systemSetup = if ($setup.PSObject.Properties['SystemSetupInProgress']) { [int]$setup.SystemSetupInProgress } else { -1 }
                $oobe = if ($setup.PSObject.Properties['OOBEInProgress']) { [int]$setup.OOBEInProgress } else { 0 }
                [pscustomobject]@{Ready=($systemSetup -eq 0 -and $oobe -eq 0);ComputerName=$env:COMPUTERNAME}
            }
            $remaining = [Math]::Max(1,[int]($deadline - [DateTime]::UtcNow).TotalSeconds)
            if (Wait-Job -Job $probe -Timeout ([Math]::Min(15,$remaining))) {
                $response = @(Receive-Job -Job $probe -ErrorAction Stop)
                if ($response.Count -eq 1 -and $response[0].Ready -and $response[0].ComputerName -ceq 'N2R-WIN11') { $ready = $true }
            }
        } catch {
            # Authentication/transport failures during setup are expected. Never log the credential or command arguments.
        } finally {
            if ($probe) { Remove-Job -Job $probe -Force -ErrorAction SilentlyContinue }
        }
        if (-not $ready -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Seconds 3 }
    }
    if (-not $ready) { throw 'Windows did not finish setup and become reachable through PowerShell Direct before the deadline. Inspect the VM; no forced shutdown was issued.' }
    $session = New-PSSession -VMId ([guid]$manifest.vmId) -Credential $credential -ErrorAction Stop
    Write-GuestState 'copying-tools'
    Invoke-Command -Session $session -ScriptBlock {
        foreach ($path in @('C:\ntfs2refs','C:\ntfs2refs\guest')) {
            if (Test-Path -LiteralPath $path) {
                if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Guest tool directory is a reparse point.' }
            } else { New-Item -ItemType Directory -Path $path | Out-Null }
        }
    }
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $workspace 'lab\guest') -File) {
        Copy-Item -LiteralPath $file.FullName -Destination ('C:\ntfs2refs\guest\' + $file.Name) -ToSession $session -Force
    }
    Copy-Item -LiteralPath $binary -Destination 'C:\ntfs2refs\ntfs2refs.exe' -ToSession $session -Force
    Write-GuestState 'validating-native-ntfs'
    $evidence = Invoke-Command -Session $session -ArgumentList $binaryHash -ScriptBlock {
        param($ExpectedBinaryHash)
        $ErrorActionPreference = 'Stop'
        $failures = New-Object 'System.Collections.Generic.List[string]'
        $copiedHash = (Get-FileHash -LiteralPath 'C:\ntfs2refs\ntfs2refs.exe' -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($copiedHash -ne $ExpectedBinaryHash) { throw 'Copied converter hash does not match the host build.' }
        & powercfg.exe /hibernate off | Out-Null
        if ($LASTEXITCODE -ne 0 -or (Test-Path -LiteralPath 'C:\hiberfil.sys')) { $failures.Add('Hibernation was not fully disabled.') }
        $version = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $build = [string]$version.CurrentBuild + '.' + [string]$version.UBR
        if ($build -ne '26300.9457') { $failures.Add('Installed build differs from the pinned ISO control.') }
        $osVolume = Get-Volume -DriveLetter C
        if ($osVolume.FileSystem -ne 'NTFS') { $failures.Add('The first-boot control is not NTFS.') }
        $bitlocker = Get-BitLockerVolume -MountPoint 'C:'
        if ([string]$bitlocker.VolumeStatus -ne 'FullyDecrypted' -or $bitlocker.EncryptionPercentage -ne 0) { $failures.Add('The OS volume is not fully decrypted; no automatic decryption was attempted.') }
        $health = $null
        try { $health = [string](Repair-Volume -DriveLetter C -Scan -ErrorAction Stop) } catch { $failures.Add('Native NTFS health scan failed.') }
        if ($health -ne 'NoErrorsFound') { $failures.Add('Native NTFS health scan did not return NoErrorsFound; no repair was requested.') }
        $recovery = @(& reagentc.exe /info 2>&1 | ForEach-Object { [string]$_ })
        $recoveryExit = $LASTEXITCODE
        $winreEnabled = $recoveryExit -eq 0 -and (($recovery -join "`n") -match 'Windows RE status:\s+Enabled')
        if (-not $winreEnabled) {
            # Configure recovery inside the disposable guest only. The installer
            # registered the offline recovery path without changing host WinRE.
            $enableOutput = @(& reagentc.exe /enable 2>&1 | ForEach-Object { [string]$_ })
            if ($LASTEXITCODE -eq 0) {
                $recovery = @(& reagentc.exe /info 2>&1 | ForEach-Object { [string]$_ })
                $winreEnabled = $LASTEXITCODE -eq 0 -and (($recovery -join "`n") -match 'Windows RE status:\s+Enabled')
            } else { $recovery += $enableOutput }
        }
        if (-not $winreEnabled) { $failures.Add('WinRE enablement was not verified.') }
        $files = @()
        foreach ($relative in @('System32\drivers\refs.sys','System32\winload.efi','Boot\EFI\bootmgfw.efi')) {
            $path = Join-Path $env:SystemRoot $relative
            $item = Get-Item -LiteralPath $path
            $signature = Get-AuthenticodeSignature -LiteralPath $path
            $signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
            $files += [pscustomobject]@{path=$path;version=$item.VersionInfo.FileVersion;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();signatureStatus=[string]$signature.Status;signer=$signer}
        }
        $disks = @(Get-Disk | Select-Object Number,UniqueId,SerialNumber,FriendlyName,Size,Location,PartitionStyle,IsBoot,IsSystem,IsOffline,IsReadOnly)
        $scsiMapping = @(Get-CimInstance Win32_DiskDrive | Select-Object Index,Model,SerialNumber,SCSIPort,SCSIBus,SCSITargetId,SCSILogicalUnit)
        $scsiMapping | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath 'C:\ntfs2refs\scsi-mapping.json' -Encoding UTF8
        $converterVersion = @(& 'C:\ntfs2refs\ntfs2refs.exe' --version 2>&1 | ForEach-Object { [string]$_ })
        if ($LASTEXITCODE -ne 0) { $failures.Add('The copied converter could not report its version.') }
        [pscustomobject]@{schemaVersion=1;phase='native-ntfs-first-boot';computerName=$env:COMPUTERNAME;windowsBuild=$build;edition=$version.EditionID;osFileSystem=$osVolume.FileSystem;bitLockerVolumeStatus=[string]$bitlocker.VolumeStatus;encryptionPercentage=$bitlocker.EncryptionPercentage;hibernationDisabled=(-not (Test-Path -LiteralPath 'C:\hiberfil.sys'));filesystemHealth=$health;winreEnabled=$winreEnabled;winreOutput=$recovery;bootFiles=$files;disks=$disks;converterVersion=$converterVersion;converterSha256=$copiedHash;failures=$failures.ToArray();nativeNtfsControlPassed=($failures.Count -eq 0);refsBootVerified=$false;dataDisksModified=$false;capturedUtc=[DateTime]::UtcNow.ToString('o')}
    }
    $evidence | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $evidencePath -Encoding UTF8
    Copy-Item -LiteralPath 'C:\ntfs2refs\scsi-mapping.json' -Destination (Join-Path $evidenceRoot 'scsi-mapping.json') -FromSession $session
    if (-not $evidence.nativeNtfsControlPassed) { throw ('Native NTFS control has unresolved findings: ' + ($evidence.failures -join ' ')) }
    Assert-LabCapacity (Get-LabCapacity $configuration)
    Write-GuestState 'shutting-down'
    Invoke-Command -Session $session -ScriptBlock { & shutdown.exe /s /t 0; if ($LASTEXITCODE -ne 0) { throw 'Guest shutdown request failed.' } }
    Remove-PSSession -Session $session -ErrorAction SilentlyContinue
    $session = $null
    $shutdownDeadline = [DateTime]::UtcNow.AddMinutes(3)
    do {
        $vm = Get-VM -Id ([guid]$manifest.vmId)
        if ($vm.State -eq 'Off') { break }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $shutdownDeadline)
    if ($vm.State -ne 'Off') { throw 'Guest did not finish a clean shutdown; no checkpoint was created.' }
    Write-GuestState 'checkpointing'
    Invoke-LabAction -Action Checkpoint -Lane $Lane -CheckpointName 'installed-clean' -Confirm:$false | Out-Null
    Write-GuestState 'exporting-baseline'
    Invoke-LabAction -Action ExportBaseline -Lane $Lane -CheckpointName 'installed-clean' -Confirm:$false | Out-Null
    Write-GuestState 'complete' 'Native NTFS boot verified; installed-clean checkpoint and independent export created. Data fixtures and ReFS boot remain pending.'
    [pscustomobject]@{VMName=$manifest.vmName;State='Off';NativeNtfsControl='Passed';WindowsBuild=$evidence.windowsBuild;Checkpoint='installed-clean';Evidence=$evidencePath;ReFSBootVerified=$false;DataDisksModified=$false}
} catch {
    Write-GuestState 'failed' $_.Exception.Message
    throw
} finally {
    if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    $credential = $null
}
