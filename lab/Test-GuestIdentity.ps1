<# Pure mocked guard tests. No VM, native disk, module import, or manifest write operations. #>
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$registerScript = Join-Path $PSScriptRoot 'guest\Register-GuestDisk.ps1'
$modulePath = Join-Path $PSScriptRoot 'guest\GuestLab.psm1'
$asts = @{}
foreach ($path in @($registerScript, $modulePath)) {
    $tokens = $null; $errors = $null
    $asts[$path] = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Parser errors in $path." }
}
# New commands must be explicitly mocked/reviewed before this test executes them.
$allowed = @('Import-Module', 'Join-Path', 'Get-Disk', 'Where-Object', 'Assert-LabGuestDisk', 'Test-Path', 'ConvertTo-Json', 'Set-Content', 'Get-CimInstance', 'Get-Partition')
$guardDefinitions = @()
foreach ($name in @('Assert-LabGuestDisk', 'Get-LabGuestDisk')) {
    $definition = $asts[$modulePath].Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $false)
    if (-not $definition) { throw "Missing guest guard $name." }
    $guardDefinitions += $definition
}
foreach ($ast in @($asts[$registerScript]) + $guardDefinitions) {
    foreach ($command in @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true))) {
        if ($command.GetCommandName() -notin $allowed) { throw "Unmocked command: $($command.GetCommandName())" }
    }
}
foreach ($definition in $guardDefinitions) { . ([scriptblock]::Create($definition.Extent.Text)) }
function Import-Module { param($Name, [switch]$Force) }
function Get-CimInstance { param($ClassName) $mockComputer }
function Get-Disk { $mockDisks }
function Get-Partition { param($DiskNumber, $ErrorAction) $mockPartitions }
function Test-Path { param($LiteralPath) $manifestExists }
function Set-Content {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$Value, $LiteralPath, $Encoding)
    process { throw 'Test must never invoke manifest writes, even through a mock.' }
}
function Reset-Mocks {
    $script:mockComputer = [pscustomobject]@{ Manufacturer = 'Microsoft Corporation'; Model = 'Virtual Machine' }
    $script:mockDisk = [pscustomobject]@{
        Number = 1; UniqueId = '60022480-NATIVE-MOCK-TARGET'; SerialNumber = $null
        Size = 64GB; Location = 'Integrated : Adapter 0 : Port 0 : Target 0 : LUN 1'
        IsBoot = $false; IsSystem = $false; BusType = 'SCSI'; FriendlyName = 'Msft Virtual Disk'
        IsOffline = $false; IsReadOnly = $false; PartitionStyle = 'RAW'
    }
    $script:mockDisks = @($script:mockDisk); $script:mockPartitions = @(); $script:manifestExists = $false
    $script:manifest = [pscustomobject]@{
        schemaVersion = 1; role = 'target'; uniqueId = $script:mockDisk.UniqueId
        serialNumber = ''; serialNumberAvailable = $false; sizeBytes = 64GB; location = $script:mockDisk.Location
    }
}
function Invoke-MockEnrollment {
    param([string]$UniqueId = $script:mockDisk.UniqueId, [string]$Role = 'target')
    & $registerScript -UniqueId $UniqueId -Role $Role -OutputPath 'mock-identity.json' -WhatIf
}
function Assert-Check([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Expect-Rejection([scriptblock]$Action, [string]$ExpectedMessage) {
    $caught = $null
    try { & $Action | Out-Null } catch { $caught = $_ }
    if (-not $caught) { throw 'Expected identity refusal did not occur.' }
    if ($ExpectedMessage -and $caught.Exception.Message -notmatch $ExpectedMessage) { throw "Unexpected refusal: $($caught.Exception.Message); expected $ExpectedMessage" }
}
$script:passed = 0
function Test-Case([string]$Name, [scriptblock]$Body) { Reset-Mocks; & $Body; $script:passed++; "PASS $Name" }

Test-Case 'Enroll observed null serial with stable UniqueId and SCSI location' {
    $enrolled = Invoke-MockEnrollment
    Assert-Check ($enrolled.uniqueId -ceq $script:mockDisk.UniqueId) 'UniqueId was not preserved.'
    Assert-Check ($enrolled.location -ceq $script:mockDisk.Location) 'SCSI location was not preserved.'
    Assert-Check ($enrolled.serialNumber -ceq '' -and $enrolled.serialNumberAvailable -eq $false) 'Absent serial must remain absent and explicitly marked.'
    Assert-Check ($enrolled.sizeBytes -eq 64GB -and $enrolled.role -ceq 'target') 'Target role or size changed.'
}
Test-Case 'Enroll journal at LUN 2 without serial' {
    $script:mockDisk.Size = 8GB; $script:mockDisk.Location = 'Integrated : Adapter 0 : Port 0 : Target 0 : LUN 2'
    $enrolled = Invoke-MockEnrollment -Role journal
    Assert-Check ($enrolled.role -ceq 'journal' -and $enrolled.sizeBytes -eq 8GB -and -not $enrolled.serialNumberAvailable) 'Journal identity was not preserved.'
}
foreach ($role in @('target','journal')) {
    Test-Case "Enroll and reuse observed SAS $role without serial" {
        $script:mockDisk.BusType = 'SAS'
        if ($role -eq 'journal') {
            $script:mockDisk.Size = 8GB; $script:mockDisk.Location = 'Integrated : Adapter 0 : Port 0 : Target 0 : LUN 2'
        }
        $enrolled = Invoke-MockEnrollment -Role $role
        Assert-Check ($enrolled.serialNumber -ceq '' -and -not $enrolled.serialNumberAvailable) 'SAS absent serial was not preserved.'
        $reused = Get-LabGuestDisk $enrolled
        Assert-Check ($reused.UniqueId -ceq $script:mockDisk.UniqueId -and $reused.Size -eq $script:mockDisk.Size -and $reused.Location -ceq $script:mockDisk.Location) 'Exact SAS identity was not preserved.'
    }
}
foreach ($bus in @('USB','NVMe','RAID','', ' ', $null)) {
    Test-Case "Enrollment and reuse reject unqualified bus [$bus]" {
        $script:mockDisk.BusType = $bus
        Expect-Rejection { Invoke-MockEnrollment } 'boot/system/nonvirtual'
        Expect-Rejection { Get-LabGuestDisk $script:manifest } 'boot/system/nonvirtual'
    }
}
foreach ($flag in @('IsBoot','IsSystem')) {
    Test-Case "SAS enrollment and reuse reject $flag" {
        $script:mockDisk.BusType = 'SAS'; $script:mockDisk.$flag = $true
        Expect-Rejection { Invoke-MockEnrollment } 'boot/system/nonvirtual'
        Expect-Rejection { Get-LabGuestDisk $script:manifest } 'boot/system/nonvirtual'
    }
}
Test-Case 'SAS enrollment and reuse reject physical disk name' {
    $script:mockDisk.BusType = 'SAS'; $script:mockDisk.FriendlyName = 'Physical storage'
    Expect-Rejection { Invoke-MockEnrollment } 'boot/system/nonvirtual'
    Expect-Rejection { Get-LabGuestDisk $script:manifest } 'boot/system/nonvirtual'
}
Test-Case 'SAS enrollment and reuse reject non-Hyper-V machine' {
    $script:mockDisk.BusType = 'SAS'; $script:mockComputer.Model = 'Physical host'
    Expect-Rejection { Invoke-MockEnrollment } 'disposable Hyper-V guest'
    Expect-Rejection { Get-LabGuestDisk $script:manifest } 'disposable Hyper-V guest'
}
foreach ($flag in @('IsBoot','IsSystem')) {
    Test-Case "SAS enrollment and reuse reject partition $flag despite clear disk flags" {
        $script:mockDisk.BusType = 'SAS'
        $part = [pscustomobject]@{ IsBoot = $false; IsSystem = $false; DriveLetter = 'F' }; $part.$flag = $true
        $script:mockPartitions = @($part)
        Expect-Rejection { Invoke-MockEnrollment } 'running OS or boot partition'
        Expect-Rejection { Get-LabGuestDisk $script:manifest } 'running OS or boot partition'
    }
}
Test-Case 'Preserve an available serial verbatim' {
    $script:mockDisk.SerialNumber = 'native-serial'; $enrolled = Invoke-MockEnrollment
    Assert-Check ($enrolled.serialNumber -ceq 'native-serial' -and $enrolled.serialNumberAvailable) 'Available serial was not preserved.'
}
Test-Case 'Enrollment rejects missing UniqueId' {
    $script:mockDisk.UniqueId = $null
    Expect-Rejection { Invoke-MockEnrollment -UniqueId '60022480-NATIVE-MOCK-TARGET' } 'exact UniqueId'
}
Test-Case 'Enrollment rejects whitespace UniqueId' {
    $script:mockDisk.UniqueId = ' '; Expect-Rejection { Invoke-MockEnrollment -UniqueId ' ' } 'stable UniqueId and location'
}
Test-Case 'Enrollment rejects missing location' {
    $script:mockDisk.Location = $null; Expect-Rejection { Invoke-MockEnrollment } 'stable UniqueId and location'
}
Test-Case 'Enrollment rejects whitespace location' {
    $script:mockDisk.Location = ' '; Expect-Rejection { Invoke-MockEnrollment } 'stable UniqueId and location'
}
Test-Case 'Enrollment rejects duplicate UniqueIds' {
    $script:mockDisks = @($script:mockDisk, $script:mockDisk); Expect-Rejection { Invoke-MockEnrollment } 'exact UniqueId'
}
Test-Case 'Enrollment rejects boot disk' {
    $script:mockDisk.IsBoot = $true; Expect-Rejection { Invoke-MockEnrollment } 'boot/system/nonvirtual'
}
Test-Case 'Enrollment rejects system disk' {
    $script:mockDisk.IsSystem = $true; Expect-Rejection { Invoke-MockEnrollment } 'boot/system/nonvirtual'
}
Test-Case 'Enrollment rejects an existing partition table' {
    $script:mockDisk.PartitionStyle = 'GPT'; Expect-Rejection { Invoke-MockEnrollment } 'blank disposable lab disk'
}
Test-Case 'Enrollment rejects wrong role size' {
    $script:mockDisk.Size = 8GB; Expect-Rejection { Invoke-MockEnrollment } 'expected-size blank'
}
Test-Case 'Enrollment refuses to replace an existing identity' {
    $script:manifestExists = $true; Expect-Rejection { Invoke-MockEnrollment } 'Manifest already exists'
}
Test-Case 'Reuse accepts unchanged null serial identity' {
    Assert-Check ((Get-LabGuestDisk $script:manifest).UniqueId -ceq $script:manifest.uniqueId) 'Qualified null-serial identity rejected.'
}
Test-Case 'Disk number is not the identity' {
    $script:mockDisk.Number = 9; Assert-Check ((Get-LabGuestDisk $script:manifest).Number -eq 9) 'Stable disk identity should survive number reassignment.'
}
Test-Case 'Reuse rejects changed UniqueId' {
    $script:mockDisk.UniqueId = 'other-disk'; Expect-Rejection { Get-LabGuestDisk $script:manifest } 'UniqueId'
}
Test-Case 'Reuse rejects duplicate UniqueIds' {
    $script:mockDisks = @($script:mockDisk, $script:mockDisk); Expect-Rejection { Get-LabGuestDisk $script:manifest } 'exactly one disk'
}
Test-Case 'Reuse rejects a newly appearing serial' {
    $script:mockDisk.SerialNumber = 'unexpected-new-serial'; Expect-Rejection { Get-LabGuestDisk $script:manifest } 'serial, size, or SCSI location changed'
}
Test-Case 'Reuse rejects disappearance of a recorded serial' {
    $script:manifest.serialNumber = 'previous-serial'; $script:manifest.serialNumberAvailable = $true
    Expect-Rejection { Get-LabGuestDisk $script:manifest } 'serial, size, or SCSI location changed'
}
Test-Case 'Reuse rejects changed size' {
    $script:mockDisk.Size = 8GB; Expect-Rejection { Get-LabGuestDisk $script:manifest } 'serial, size, or SCSI location changed'
}
Test-Case 'Reuse rejects changed SCSI location' {
    $script:mockDisk.Location = 'Integrated : Adapter 0 : Port 0 : Target 0 : LUN 2'
    Expect-Rejection { Get-LabGuestDisk $script:manifest } 'serial, size, or SCSI location changed'
}
Test-Case 'Reuse rejects blank UniqueId even if disk and manifest agree' {
    $script:mockDisk.UniqueId = ''; $script:manifest.uniqueId = ''; Expect-Rejection { Get-LabGuestDisk $script:manifest } ''
}
Test-Case 'Reuse rejects blank location even if disk and manifest agree' {
    $script:mockDisk.Location = ''; $script:manifest.location = ''; Expect-Rejection { Get-LabGuestDisk $script:manifest } ''
}
Test-Case 'Reuse rejects wrong role size even if disk and manifest agree' {
    $script:mockDisk.Size = 8GB; $script:manifest.sizeBytes = 8GB; Expect-Rejection { Get-LabGuestDisk $script:manifest } ''
}
Test-Case 'Reuse rejects boot disk' {
    $script:mockDisk.IsBoot = $true; Expect-Rejection { Get-LabGuestDisk $script:manifest } 'boot/system/nonvirtual'
}
Test-Case 'Reuse rejects system disk' {
    $script:mockDisk.IsSystem = $true; Expect-Rejection { Get-LabGuestDisk $script:manifest } 'boot/system/nonvirtual'
}
Test-Case 'Reuse rejects boot partition despite clear disk flags' {
    $script:mockPartitions = @([pscustomobject]@{ IsBoot = $true; IsSystem = $false; DriveLetter = 'F' })
    Expect-Rejection { Get-LabGuestDisk $script:manifest } 'running OS or boot partition'
}
Test-Case 'Reuse rejects running OS letter despite clear disk flags' {
    $script:mockPartitions = @([pscustomobject]@{ IsBoot = $false; IsSystem = $false; DriveLetter = $env:SystemDrive.TrimEnd(':') })
    Expect-Rejection { Get-LabGuestDisk $script:manifest } 'running OS or boot partition'
}
Test-Case 'Reuse rejects nonvirtual disk' {
    $script:mockDisk.FriendlyName = 'Physical storage'; Expect-Rejection { Get-LabGuestDisk $script:manifest } 'boot/system/nonvirtual'
}
Test-Case 'Reuse rejects a non-Hyper-V computer' {
    $script:mockComputer.Model = 'Physical host'; Expect-Rejection { Get-LabGuestDisk $script:manifest } 'disposable Hyper-V guest'
}
Test-Case 'Reuse rejects offline disk' {
    $script:mockDisk.IsOffline = $true; Expect-Rejection { Get-LabGuestDisk $script:manifest } 'offline or read-only'
}
Test-Case 'Reuse rejects read-only disk' {
    $script:mockDisk.IsReadOnly = $true; Expect-Rejection { Get-LabGuestDisk $script:manifest } 'offline or read-only'
}
"Passed $script:passed guest disk identity checks. All disk/provider commands were mocked."
