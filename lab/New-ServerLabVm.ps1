<#
.SYNOPSIS
Builds a lab VM with Windows Server from an installation ISO, for data-volume
attempts (Invoke-DataVolumeAttempt.ps1 -VmId <id> -CredentialPath <path>).

.DESCRIPTION
The reference VMs run Windows 11, which formats Dev Drives and refuses ordinary
ReFS. Windows Server formats both, so conversions to standard ReFS need a
Server control OS. This script makes one from Microsoft's evaluation ISO
without touching the host's disks: Windows Setup runs inside the new VM from
an answer file on a second, generated ISO.

  1. A generation 2 VM: Secure Boot on, no network adapter, one empty OS disk.
  2. An answer-file ISO (autounattend.xml): wipes that disk, installs the
     chosen image, creates the local administrator LabAdmin with a password
     generated here. The password is kept only as a credential file under the
     VM's folder, protected for the Windows user who ran this script; the
     answer-file ISO is deleted when Setup has finished.
  3. The VM is started and Setup's "press any key" is answered through the
     VM's keyboard. The script waits until the installed Windows answers a
     PowerShell Direct session.
  4. A scratch disk is added and formatted as S: (ReFS), which is where the
     data-volume harness keeps its volumes and the converter's working files.
  5. The VM is shut down and a baseline checkpoint is taken.

Everything is under .lab\hyperv\<Name>. Nothing outside it is changed, and the
script refuses to run when the VM or the folder already exists.
#>
[CmdletBinding()]
param(
    [string]$Name = 'ntfs2refs-server2025',
    # The Windows Server installation ISO.
    [Parameter(Mandatory)][string]$Iso,
    # The image in the ISO's install.wim. On Microsoft's Server 2025
    # evaluation ISO, 2 is Standard with Desktop Experience.
    [int]$ImageIndex = 2,
    [int]$MemoryGB = 8,
    [int]$Processors = 4,
    [int]$OsDiskGB = 64,
    [int]$ScratchGB = 120,
    [int]$InstallTimeoutMinutes = 75
)
$ErrorActionPreference = 'Stop'; Set-StrictMode -Version Latest
$workspace = Split-Path -Parent $PSScriptRoot
$root = Join-Path $workspace ".lab\hyperv\$Name"
if (Test-Path -LiteralPath $root) { throw "Already exists: $root" }
if (Get-VM -Name $Name -ErrorAction SilentlyContinue) { throw "A VM named '$Name' already exists" }
if (-not (Test-Path -LiteralPath $Iso)) { throw "Not found: $Iso" }
$null = New-Item -ItemType Directory -Path $root, (Join-Path $root 'secrets'), (Join-Path $root 'answer')
$log = Join-Path $root 'build.log'
function Say([string]$Text) { $line = '{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $Text; Add-Content -LiteralPath $log -Value $line -Encoding UTF8; Write-Host $line }

# ---- the account ---------------------------------------------------------------
$alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
$random = [Security.Cryptography.RandomNumberGenerator]::Create(); $bytes = New-Object byte[] 24; $random.GetBytes($bytes)
$password = -join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] }) + 'x7Q!'
$secure = ConvertTo-SecureString -String $password -AsPlainText -Force
$credential = [pscredential]::new('LabAdmin', $secure)
$credentialPath = Join-Path $root 'secrets\guest-credential.xml'
$credential | Export-Clixml -LiteralPath $credentialPath

# ---- the answer file -----------------------------------------------------------
# Setup stores a password as base64 of the UTF-16 text followed by the element's name.
$encode = { param($text, $suffix) [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($text + $suffix)) }
$component = 'processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"'
$answer = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" $component>
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" $component>
      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>260</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall><OSImage>
        <InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>$ImageIndex</Value></MetaData></InstallFrom>
        <InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo>
      </OSImage></ImageInstall>
      <UserData><AcceptEula>true</AcceptEula></UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" $component>
      <ComputerName>N2R-SERVER</ComputerName><TimeZone>UTC</TimeZone>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" $component>
      <OOBE><HideEULAPage>true</HideEULAPage><HideLocalAccountScreen>true</HideLocalAccountScreen><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>3</ProtectYourPC></OOBE>
      <UserAccounts>
        <AdministratorPassword><Value>$(& $encode $password 'AdministratorPassword')</Value><PlainText>false</PlainText></AdministratorPassword>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Name>LabAdmin</Name><Group>Administrators</Group><DisplayName>LabAdmin</DisplayName>
            <Password><Value>$(& $encode $password 'Password')</Value><PlainText>false</PlainText></Password>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
    </component>
  </settings>
</unattend>
"@
[IO.File]::WriteAllText((Join-Path $root 'answer\autounattend.xml'), $answer, [Text.UTF8Encoding]::new($false))

# The answer file has to be on removable media for Setup to find it: an ISO,
# written with the image-mastering API that Windows ships.
Add-Type -TypeDefinition @'
using System; using System.IO; using System.Runtime.InteropServices; using System.Runtime.InteropServices.ComTypes;
public static class N2RIsoWriter {
    public static void Save(object imageStream, string path) {
        IStream stream = (IStream)imageStream;
        using (FileStream file = new FileStream(path, FileMode.CreateNew, FileAccess.Write)) {
            byte[] buffer = new byte[1 << 20]; IntPtr read = Marshal.AllocHGlobal(sizeof(int));
            try { while (true) { stream.Read(buffer, buffer.Length, read); int count = Marshal.ReadInt32(read); if (count <= 0) break; file.Write(buffer, 0, count); } }
            finally { Marshal.FreeHGlobal(read); }
        }
    }
}
'@
$answerIso = Join-Path $root 'answer.iso'
$image = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
$image.FileSystemsToCreate = 3      # ISO 9660 and Joliet
$image.VolumeName = 'N2RANSWER'
$image.Root.AddTree((Join-Path $root 'answer'), $false)
[N2RIsoWriter]::Save($image.CreateResultImage().ImageStream, $answerIso)
Say "answer-file ISO written ($((Get-Item -LiteralPath $answerIso).Length) bytes)"

# ---- the VM ---------------------------------------------------------------------
$osDisk = Join-Path $root 'os.vhdx'
$vm = New-VM -Name $Name -Generation 2 -MemoryStartupBytes ($MemoryGB * 1GB) -Path $root -NewVHDPath $osDisk -NewVHDSizeBytes ($OsDiskGB * 1GB)
Set-VM -VM $vm -ProcessorCount $Processors -StaticMemory -AutomaticCheckpointsEnabled $false -CheckpointType Standard -AutomaticStartAction Nothing -AutomaticStopAction TurnOff
Get-VMNetworkAdapter -VM $vm | Remove-VMNetworkAdapter      # the lab's VMs have no network
$install = Add-VMDvdDrive -VM $vm -Path $Iso -Passthru
$null = Add-VMDvdDrive -VM $vm -Path $answerIso
Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows -FirstBootDevice $install
Say "VM $Name created: $($vm.Id)"
Start-VM -VM $vm
# "Press any key to boot from CD or DVD": answered through the VM's keyboard for the first seconds.
$system = Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName Msvm_ComputerSystem -Filter "Name='$($vm.Id.ToString().ToUpperInvariant())'"
$keyboard = Get-CimAssociatedInstance -InputObject $system -ResultClassName Msvm_Keyboard
for ($i = 0; $i -lt 40; $i++) { try { $null = Invoke-CimMethod -InputObject $keyboard -MethodName TypeKey -Arguments @{ keyCode = [uint32]0x20 } } catch { }; Start-Sleep -Milliseconds 500 }
Say 'Setup started; waiting for the installed Windows to answer'

$deadline = (Get-Date).AddMinutes($InstallTimeoutMinutes); $up = $false
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 30
    if ((Get-VM -Id $vm.Id).State -ne 'Running') { Start-VM -VM $vm }      # Setup's restarts are restarts, but be safe
    try {
        $caption = Invoke-Command -VMId $vm.Id -Credential $credential -ErrorAction Stop -ScriptBlock { (Get-CimInstance Win32_OperatingSystem).Caption + ' build ' + [Environment]::OSVersion.Version.Build }
        Say "installed: $caption"; $up = $true; break
    } catch { }
}
if (-not $up) { throw "Windows did not answer a PowerShell Direct session within $InstallTimeoutMinutes minutes; the VM is left as it is for inspection" }

# ---- the scratch volume -----------------------------------------------------------
$scratch = Join-Path $root 'scratch.vhdx'
$null = New-VHD -Path $scratch -SizeBytes ($ScratchGB * 1GB) -Dynamic
Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -Path $scratch
$made = Invoke-Command -VMId $vm.Id -Credential $credential -ScriptBlock {
    $deadline = (Get-Date).AddSeconds(60)
    do { Start-Sleep -Seconds 2; $disk = Get-Disk | Where-Object PartitionStyle -EQ 'RAW' | Select-Object -First 1 } until ($disk -or (Get-Date) -gt $deadline)
    if (-not $disk) { throw 'the scratch disk did not arrive' }
    Set-Disk -Number $disk.Number -IsOffline $false; Set-Disk -Number $disk.Number -IsReadOnly $false
    Initialize-Disk -Number $disk.Number -PartitionStyle GPT
    $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -DriveLetter S
    $volume = Format-Volume -Partition $partition -FileSystem ReFS -NewFileSystemLabel 'n2r-scratch' -Confirm:$false
    $null = New-Item -ItemType Directory -Path 'C:\n2r', 'S:\datalab\runs' -Force
    # A lab machine that is left alone for hours: no sleep, no screen lock timeout.
    $null = & powercfg.exe /change standby-timeout-ac 0; $null = & powercfg.exe /change monitor-timeout-ac 0
    '{0} {1}, {2:N0} GB' -f $volume.DriveLetter, $volume.FileSystem, ($volume.Size / 1GB)
}
Say "scratch volume: $made"

# ---- the baseline -----------------------------------------------------------------
Stop-VM -VM $vm -Force
Get-VMDvdDrive -VM $vm | Where-Object Path -EQ $answerIso | Remove-VMDvdDrive
Remove-Item -LiteralPath $answerIso -Force; Remove-Item -LiteralPath (Join-Path $root 'answer') -Recurse -Force
Set-VMFirmware -VM $vm -FirstBootDevice (Get-VMHardDiskDrive -VM $vm | Where-Object Path -EQ $osDisk)
Checkpoint-VM -VM $vm -SnapshotName 'N2R-Server-Baseline'
Say "baseline checkpoint taken. Use: -VmId $($vm.Id) -CredentialPath `"$credentialPath`""
[pscustomobject]@{ name = $Name; id = [string]$vm.Id; credential = $credentialPath; root = $root }
