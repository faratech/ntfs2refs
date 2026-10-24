<# Pure/mocked guard checks; no Hyper-V, disk writes, elevation or guest calls. #>
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$workspace = Split-Path $PSScriptRoot -Parent
$asts = @{}
foreach ($relative in @('scripts\Prepare-LabRefsBootControl.ps1','lab\guest\Prepare-NativeRefsOS.ps1','lab\guest\GuestLab.psm1')) {
    $tokens = $null; $errors = $null
    $asts[$relative] = [Management.Automation.Language.Parser]::ParseFile((Join-Path $workspace $relative),[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw "Parser errors in $relative." }
}
foreach ($name in @('Assert-LabGuestDisk','Get-LabGuestDisk')) {
    $definition = $asts['lab\guest\GuestLab.psm1'].Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name },$false)
    Invoke-Expression $definition.Extent.Text
}
foreach ($name in @('Get-ControlDisk','Assert-ControlLetter','Assert-ControlFormatPartition','Test-ControlRecoveryPartition','Get-ControlFormatterComponent')) {
    $definition = $asts['lab\guest\Prepare-NativeRefsOS.ps1'].Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name },$false)
    Invoke-Expression $definition.Extent.Text
}
$script:checks = 0
function Assert-Check([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message }; $script:checks++ }
function Expect-Rejection([scriptblock]$Action, [string]$Message) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    Assert-Check $rejected $Message
}
function Get-CimInstance { param($ClassName) [pscustomobject]@{ Manufacturer = 'Microsoft Corporation'; Model = 'Virtual Machine' } }
function Get-Disk { $script:mockDisk }
function Get-Partition { param($DiskNumber,$DriveLetter,$ErrorAction) if ($PSBoundParameters.ContainsKey('DriveLetter')) { $script:mockLetterPartition } }
function Get-Volume { param($DriveLetter,$ErrorAction) [pscustomobject]@{ FileSystem = $script:mockFileSystem } }
$script:mockDisk = [pscustomobject]@{ Number = 1; UniqueId = 'mock-target'; SerialNumber = 'mock-serial'; Size = 64GB; Location = 'mock-slot-1'; IsBoot = $false; IsSystem = $false; BusType = 'SCSI'; FriendlyName = 'Msft Virtual Disk'; IsOffline = $false; IsReadOnly = $false }
$identity = [pscustomobject]@{ schemaVersion = 1; role = 'target'; uniqueId = 'mock-target'; serialNumber = 'mock-serial'; sizeBytes = 64GB; location = 'mock-slot-1' }
$script:mockLetterPartition = [pscustomobject]@{ DiskNumber = 1 }
Assert-Check ((Get-ControlDisk).Number -eq 1) 'Qualified target rejected.'
$script:mockDisk.BusType = 'SAS'
Assert-Check ((Get-ControlDisk).Number -eq 1) 'Observed Hyper-V SAS target rejected.'
foreach ($bus in @('USB','NVMe','RAID','', $null)) {
    $script:mockDisk.BusType = $bus
    Expect-Rejection { Get-ControlDisk } "Unqualified preparation bus [$bus] must be rejected."
}
$script:mockDisk.BusType = 'SCSI'
Assert-ControlLetter F
$script:checks++
$script:mockLetterPartition.DiskNumber = 0
Expect-Rejection { Assert-ControlLetter F } 'Original OS letter must be rejected.'
$script:mockLetterPartition.DiskNumber = 1
$script:mockDisk.IsBoot = $true
Expect-Rejection { Get-ControlDisk } 'Boot disk must be rejected.'
$script:mockDisk.IsBoot = $false
$script:mockDisk.SerialNumber = 'changed'
Expect-Rejection { Get-ControlDisk } 'Changed serial must be rejected.'
$script:mockDisk.SerialNumber = 'mock-serial'
$script:mockDisk.Size = 8GB
Expect-Rejection { Get-ControlDisk } 'Changed size must be rejected.'
$script:mockDisk.Size = 64GB
$script:mockDisk.IsReadOnly = $true
Expect-Rejection { Get-ControlDisk } 'Read-only disk must be rejected.'
$script:mockDisk.IsReadOnly = $false
$script:mockDisk.Location = 'other-slot'
Expect-Rejection { Get-ControlDisk } 'Changed SCSI location must be rejected.'
$script:mockDisk.Location = 'mock-slot-1'
$script:mockLetterPartition = [pscustomobject]@{ DiskNumber = 1; PartitionNumber = 3; Offset = 331350016; Size = 66238545920 }
$expectedPartition = [pscustomobject]@{ PartitionNumber = 3; Offset = 331350016; Size = 66238545920 }
$script:mockFileSystem = ''
Assert-ControlFormatPartition $expectedPartition F
$script:checks++
foreach ($filesystem in @('NTFS','ReFS','FAT32')) {
    $script:mockFileSystem = $filesystem
    Expect-Rejection { Assert-ControlFormatPartition $expectedPartition F } 'Existing filesystem must not be reformatted.'
}
$script:mockFileSystem = 'RAW'
foreach ($field in @('PartitionNumber','Offset','Size')) {
    $saved = $script:mockLetterPartition.$field
    $script:mockLetterPartition.$field = $saved + 1
    Expect-Rejection { Assert-ControlFormatPartition $expectedPartition F } "Changed format partition $field was accepted."
    $script:mockLetterPartition.$field = $saved
}
$partition = [pscustomobject]@{ GptType = '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}'; Size = 2GB; Offset = 66569895936; NoDefaultDriveLetter = $null }
$detail = "Type : de94bba4-06d1-4d40-a16a-bfd50179d6ac`nAttrib : 0X8000000000000001`nOffset in Bytes: 66569895936"
Assert-Check (Test-ControlRecoveryPartition $partition $detail) 'Native recovery fixture with nullable provider attributes rejected.'
Assert-Check (-not (Test-ControlRecoveryPartition $partition ($detail -replace '8000000000000001','0000000000000000'))) 'Wrong GPT attributes accepted.'
Assert-Check (-not (Test-ControlRecoveryPartition $partition ($detail -replace '66569895936','66569895937'))) 'Wrong selected partition offset accepted.'
$partition.Size = 1GB
Assert-Check (-not (Test-ControlRecoveryPartition $partition $detail)) 'Wrong recovery size accepted.'
$hostCommands = @($asts['scripts\Prepare-LabRefsBootControl.ps1'].FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] },$true) | ForEach-Object { $_.GetCommandName() })
Assert-Check (@($hostCommands | Where-Object { $_ -in @('Mount-VHD','Mount-DiskImage','Clear-Disk','Initialize-Disk','New-Partition','Format-Volume','Set-VMFirmware') }).Count -eq 0) 'Host preparer contains native disk writes or boot selection.'
$guestText = $asts['lab\guest\Prepare-NativeRefsOS.ps1'].Extent.Text
Assert-Check ($guestText.Contains("'/s', `$efiRoot, '/f', 'UEFI', '/offline'") -and -not $guestText.Contains("'/bootex'")) 'BCDBoot must use the explicit offline target EFI.'
Assert-Check (-not ($guestText -match '(?im)^\s*(?:&\s*)?(?:Enable|Disable)-WindowsOptionalFeature\b|Format-Volume[^\r\n]*-DevDrive\b|Set-SecureBootUEFI\b')) 'Feature flags, Dev Drive or firmware trust changes are forbidden.'
function Get-Item { param($LiteralPath,$ErrorAction) if ($script:missingComponent) { throw 'Mock missing component.' }; [pscustomobject]@{ PSIsContainer = $false; VersionInfo = [pscustomobject]@{ FileVersion = '10.0.mock' } } }
function Get-FileHash { param($LiteralPath,$Algorithm,$ErrorAction) [pscustomobject]@{ Hash = ('a' * 64) } }
function Get-AuthenticodeSignature { param($LiteralPath,$ErrorAction) if ($script:unknownSignature) { throw 'Mock signature query unavailable.' }; [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null } }
$script:missingComponent = $false; $script:unknownSignature = $true
$component = Get-ControlFormatterComponent 'refs.sys' 'mock-path'
Assert-Check ($component.signatureStatus -ceq 'Unknown' -and $component.exists -and $component.sha256 -ceq ('a' * 64) -and $component.fileVersion -ceq '10.0.mock' -and $component.errors.Count -eq 1) 'Unknown signature must retain version/hash and the collection error.'
$script:unknownSignature = $false
$component = Get-ControlFormatterComponent 'fmifs.dll' 'mock-path'
Assert-Check ($component.signatureStatus -ceq 'NotSigned' -and $component.errors.Count -eq 0) 'Native NotSigned observation must be retained.'
$script:missingComponent = $true; $script:unknownSignature = $true
$component = Get-ControlFormatterComponent 'refs.sys' 'mock-path'
Assert-Check (-not $component.exists -and $component.signatureStatus -ceq 'Unknown' -and $component.errors.Count -eq 2) 'Missing components must remain explicit provenance records.'
"Passed $script:checks native ReFS preparation guard checks."
