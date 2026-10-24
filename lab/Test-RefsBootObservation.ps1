<#
Pure/mocked native ReFS boot-observation guards. The observer workflow is never
executed. VM/provider/policy/disk commands are mocked or checked as ASTs only.
The extracted probe's two environment reads are replaced with fixture variables;
the test does not change host environment variables or query host registry data.
#>
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$workspace = Split-Path $PSScriptRoot -Parent
$sourcePath = Join-Path $workspace 'scripts\Test-LabRefsBootControl.ps1'
$tokens = $null; $parseErrors = $null
$observerAst = [Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Observer script has parser errors.' }
$labAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Lab.psm1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Lab module has parser errors.' }
$definitions = @()
foreach ($name in @('Assert-FormatComCommand','Assert-FormatComArtifacts','Assert-PreparationRecords','Assert-ControlCheckpoint','Invoke-BoundedBootCommand')) {
    $definition = $observerAst.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $false)
    if (-not $definition) { throw "Missing observer guard $name." }
    $definitions += $definition
}
$exactCheckpoint = $labAst.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-ExactLabCheckpoint' }, $false)
if (-not $exactCheckpoint) { throw 'Missing exact checkpoint verifier.' }
$definitions += $exactCheckpoint
$allowed = @('Where-Object','Assert-FormatComCommand','Get-OwnedLabVM','Get-ExactLabCheckpoint','Get-VMCheckpoint','Start-Sleep','Invoke-Command','Wait-Job','Receive-Job','Remove-Job')
foreach ($definition in $definitions) {
    foreach ($command in @($definition.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true))) {
        if ($command.GetCommandName() -notin $allowed) { throw "Unmocked guard command: $($command.GetCommandName())" }
    }
    . ([scriptblock]::Create($definition.Extent.Text))
}
$probeAssignment = $observerAst.Find({ param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and $node.Left.VariablePath.UserPath -ceq 'identityProbe' }, $false)
if (-not $probeAssignment) { throw 'Missing identity probe.' }
$probeExpression = $probeAssignment.Right.Find({ param($node) $node -is [Management.Automation.Language.ScriptBlockExpressionAst] }, $true)
$probeText = $probeExpression.ScriptBlock.Extent.Text
$probeText = $probeText.Substring(1, $probeText.Length - 2).Replace('$env:COMPUTERNAME', '$mockComputerName').Replace('$env:SystemDrive', '$mockSystemDrive')
$probe = [scriptblock]::Create($probeText)
$probeCommands = @('Set-StrictMode','ConvertFrom-Json','Get-Volume','Get-Partition','Get-Disk','Get-ItemProperty','Test-Path','Get-Item','Get-Content')
foreach ($command in @($probe.Ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true))) {
    if ($command.GetCommandName() -notin $probeCommands) { throw "Unmocked identity probe command: $($command.GetCommandName())" }
}
$bootDiskGuardAst = $observerAst.Find({ param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Extent.Text.StartsWith('if ($bootDisks.Count') }, $true)
if (-not $bootDiskGuardAst) { throw 'Missing native boot/system disk evidence guard.' }
# Execute only this command-free condition, never the surrounding guest workflow.
if (@($bootDiskGuardAst.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true)).Count) { throw 'Native boot disk guard contains an unmocked command.' }
$bootDiskGuard = [scriptblock]::Create($bootDiskGuardAst.Extent.Text)

function Get-OwnedLabVM { param($Configuration,$Manifest) $script:mockVM }
function Get-VMCheckpoint { param($VM,$ErrorAction) if ($script:checkpointProviderFailure) { throw 'Mock checkpoint provider failure.' }; $script:mockCheckpoints }
function Start-Sleep { param($Milliseconds,$Seconds) $script:sleepCalls++ }
function Invoke-Command { param($VMId,$Credential,$ScriptBlock,$ArgumentList,[switch]$AsJob) $script:commandCalls++; $script:mockJob }
function Wait-Job { param($Job,$Timeout) if (-not $script:jobTimeout) { $Job } }
function Receive-Job { param($Job,$ErrorAction) $script:receiveCalls++; if ($script:receiveFailure) { throw 'Mock transport receive failure.' }; 'mock-result' }
function Remove-Job { param($Job,[switch]$Force,$ErrorAction) $script:cleanupCalls++ }
function Get-Volume { param($DriveLetter) $script:mockVolume }
function Get-Partition { param($DriveLetter) $script:mockPartitions }
function Get-Disk { param($Number) $script:mockDisk }
function Get-ItemProperty { param($Path) if ($Path -like '*CurrentVersion') { $script:mockVersion } elseif ($Path -ceq 'HKLM:\SYSTEM\Setup') { $script:mockSetup } else { throw 'Unexpected mock registry path.' } }
function Test-Path { param($LiteralPath,$PathType) $script:markerPresent }
function Get-Item { param($LiteralPath,[switch]$Force) $script:mockMarkerFile }
function Get-Content { param($LiteralPath,[switch]$Raw) $script:mockMarker | ConvertTo-Json -Depth 8 }

function Reset-Fixtures {
    $script:configuration = [pscustomobject]@{ Root = 'mock-lab' }; $script:credential = $null
    $script:manifest = [pscustomobject]@{
        vmId = '11111111-1111-1111-1111-111111111111'; media = [pscustomobject]@{ sha256 = ('a' * 64) }
        disks = @([pscustomobject]@{ role = 'target'; sizeBytes = 64GB; controllerLocation = 1; vhdId = '44444444-4444-4444-4444-444444444444' })
    }
    $script:targetRecord = [pscustomobject]@{ schemaVersion = 1; role = 'target'; sizeBytes = 64GB; uniqueId = 'mock-target'; serialNumber = ''; serialNumberAvailable = $false; location = 'SCSI-LUN-1'; enrolledUtc = '2026-10-23T12:00:00Z' }
    $script:hostRecord = [pscustomobject]@{
        schemaVersion = 1; phase = 'native-refs-os-preparation'; status = 'prepared-awaiting-separate-boot-validation'
        vmId = $script:manifest.vmId; mediaSha256 = $script:manifest.media.sha256; formatMethod = 'FormatVolume'
        evidenceExported = $true; baselineRestored = $true; bootAttempted = $false; refsBootVerified = $false
        preparationCheckpoint = 'refs-os-prepared-20261023T120000000Z'
        preparationCheckpointId = '33333333-3333-3333-3333-333333333333'; baselineId = '22222222-2222-2222-2222-222222222222'
    }
    $script:guestRecord = [pscustomobject]@{
        schemaVersion = 1; phase = 'native-refs-os-preparation'; status = 'prepared'; stage = 'prepared-awaiting-separate-boot-validation'
        imageIndex = 6; imageVersion = '10.0.26300.9457'; formatSucceeded = $true; imageApplied = $true; bootFilesPrepared = $true; firstBootConfigured = $true
        bootAttempted = $false; refsBootVerified = $false; formatMethod = 'FormatVolume'
        formatRequest = [pscustomobject]@{ command = 'Format-Volume'; mode = 'ordinary-ReFS'; requestedPartitionSizeBytes = 66238545920; actualPartitionSizeBytes = 66238545920; inputDiskNumber = 1; inputPartitionNumber = 3; volume = $null; nativeArguments = @(); arguments = [pscustomobject]@{ FileSystem = 'ReFS'; AllocationUnitSize = 4096; NewFileSystemLabel = 'N2R_REFSOS'; Confirm = $false } }
        partitions = @([pscustomobject]@{ PartitionNumber = 3; Size = 66238545920; DriveLetter = 'G' })
        tools = $null; formatCompletion = $null
        target = [pscustomobject]@{ hostVhdId = $script:manifest.disks[0].vhdId; hostControllerLocation = 1; guest = ($script:targetRecord | ConvertTo-Json | ConvertFrom-Json) }
        sourceOs = [pscustomobject]@{ filesystem = 'NTFS'; build = '26300.9457'; uniqueId = 'mock-source-os' }
    }
    $script:mockVM = [pscustomobject]@{ State = 'Off'; Id = $script:manifest.vmId }
    $script:mockCheckpoints = @([pscustomobject]@{ Name = $script:hostRecord.preparationCheckpoint; Id = $script:hostRecord.preparationCheckpointId; State = 'Off' })
    $script:checkpointProviderFailure = $false; $script:sleepCalls = 0
    $script:mockJob = [pscustomobject]@{ State = 'Completed'; Id = 1 }; $script:jobTimeout = $false; $script:receiveFailure = $false
    $script:commandCalls = 0; $script:receiveCalls = 0; $script:cleanupCalls = 0
    $script:expected = [pscustomobject]@{ targetUniqueId = 'mock-target'; sourceOsUniqueId = 'mock-source-os'; hostVhdId = $script:manifest.disks[0].vhdId; expectedBuild = '26300.9457' }
    $script:mockMarker = [pscustomobject]@{ schemaVersion = 1; purpose = 'native-refs-os-control'; targetUniqueId = 'mock-target'; sourceOsUniqueId = 'mock-source-os'; hostVhdId = $script:expected.hostVhdId; expectedFilesystem = 'ReFS'; expectedBuild = '26300.9457' }
    $script:mockVolume = [pscustomobject]@{ FileSystem = 'ReFS' }
    $script:mockPartitions = @([pscustomobject]@{ DiskNumber = 1 })
    $script:mockDisk = [pscustomobject]@{ IsBoot = $true; IsSystem = $true; UniqueId = 'mock-target' }
    $script:mockVersion = [pscustomobject]@{ CurrentBuildNumber = '26300'; UBR = 9457; EditionID = 'Professional' }
    $script:mockSetup = [pscustomobject]@{ SystemSetupInProgress = 0; OOBEInProgress = 0 }
    $script:mockComputerName = 'N2R-WIN11'; $script:mockSystemDrive = 'C:'
    $script:markerPresent = $true; $script:mockMarkerFile = [pscustomobject]@{ Attributes = [IO.FileAttributes]::Normal; Length = 512 }
    $script:mockBootDisk = [pscustomobject]@{ Number = 1; PartitionStyle = 'GPT'; BusType = 'SCSI'; Size = 64GB; SerialNumber = $null; Location = 'SCSI-LUN-1'; UniqueId = 'mock-target' }
    $script:mockBootDisks = @($script:mockBootDisk); $script:mockSystemDisks = @($script:mockBootDisk)
    $script:bootDiskExpected = [pscustomobject]@{ sizeBytes = 64GB; serialNumber = ''; location = 'SCSI-LUN-1'; sourceOsUniqueId = 'mock-source-os' }
}
function Check-Preparation { Assert-PreparationRecords $script:hostRecord $script:guestRecord $script:targetRecord $script:manifest }
function Set-FormatComFixture {
    $script:hostRecord.formatMethod = 'FormatCom'; $script:guestRecord.formatMethod = 'FormatCom'
    $script:guestRecord.formatRequest.command = 'format.com'; $script:guestRecord.formatRequest.volume = 'G:'
    $script:guestRecord.formatRequest.nativeArguments = @('G:', '/FS:ReFS', '/A:4096', '/Q', '/V:N2R_REFSOS', '/Y')
    $script:guestRecord.tools = [pscustomobject]@{
        'format.com' = [pscustomobject]@{ path = 'C:\Windows\System32\format.com'; version = '10.0.26100.1'; sha256 = ('c' * 64); signature = 'Valid'; signer = 'CN=Microsoft Windows, O=Microsoft Corporation, C=US' }
        'diskpart.exe' = [pscustomobject]@{ path = 'C:\Windows\System32\diskpart.exe'; version = '10.0.26100.1'; sha256 = ('d' * 64); signature = 'Valid'; signer = 'CN=Microsoft Windows, O=Microsoft Corporation, C=US' }
    }
    $script:guestRecord.formatCompletion = [pscustomobject]@{ executable = $script:guestRecord.tools.'format.com'.path; arguments = @($script:guestRecord.formatRequest.nativeArguments); toolSha256 = ('c' * 64); exitCode = 0; timedOut = $false; timeoutSeconds = 120; stdinMode = 'closed-empty'; startedUtc = '2026-10-23T12:00:05Z'; completedUtc = '2026-10-23T12:00:10Z' }
    $script:formatCommand = $script:guestRecord.formatCompletion | ConvertTo-Json | ConvertFrom-Json
    $script:helpCommand = [pscustomobject]@{ executable = $script:guestRecord.tools.'format.com'.path; arguments = @('/?'); toolSha256 = ('c' * 64); exitCode = 0; timedOut = $false }
    $script:capabilityCommand = [pscustomobject]@{ executable = $script:guestRecord.tools.'diskpart.exe'.path; arguments = @('/s','C:\ntfs2refs\refs-os-preparation\format-filesystems.txt'); toolSha256 = ('d' * 64); exitCode = 0; timedOut = $false; completedUtc = '2026-10-23T12:00:04Z' }
    $script:capabilityScript = "select disk 1`r`nselect partition 3`r`nfilesystems`r`nexit`r`n"
}
function Check-FormatArtifacts { Assert-FormatComArtifacts $script:guestRecord $script:formatCommand $script:helpCommand $script:capabilityCommand $script:capabilityScript }
function Check-Probe { & $probe ($script:expected | ConvertTo-Json -Compress) }
function Check-BootDiskGuard {
    $disk = $script:mockBootDisk; $bootDisks = $script:mockBootDisks; $systemDisks = $script:mockSystemDisks; $expected = $script:bootDiskExpected
    & $bootDiskGuard
}
function Assert-Check([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
function Expect-Rejection([scriptblock]$Action,[string]$ExpectedMessage) {
    $caught = $null; try { & $Action | Out-Null } catch { $caught = $_ }
    if (-not $caught) { throw 'Expected guard refusal did not occur.' }
    if ($ExpectedMessage -and $caught.Exception.Message -notmatch $ExpectedMessage) { throw "Unexpected refusal: $($caught.Exception.Message); expected $ExpectedMessage" }
}
$script:checks = 0
function Test-Case([string]$Name,[scriptblock]$Body) { Reset-Fixtures; & $Body; $script:checks++; "PASS $Name" }

Test-Case 'Accept exact exported ordinary-ReFS preparation with absent serial' { Check-Preparation }
foreach ($field in @('evidenceExported','baselineRestored')) {
    Test-Case "Reject incomplete host $field" { $script:hostRecord.$field = $false; Expect-Rejection { Check-Preparation } 'Host preparation' }
}
foreach ($field in @('bootAttempted','refsBootVerified')) {
    Test-Case "Reject previously booted or misqualified host $field" { $script:hostRecord.$field = $true; Expect-Rejection { Check-Preparation } 'Host preparation' }
}
Test-Case 'Reject foreign VM preparation' { $script:hostRecord.vmId = '55555555-5555-5555-5555-555555555555'; Expect-Rejection { Check-Preparation } 'Host preparation' }
Test-Case 'Reject different media preparation' { $script:hostRecord.mediaSha256 = ('b' * 64); Expect-Rejection { Check-Preparation } 'Host preparation' }
Test-Case 'Reject malformed checkpoint identifier' { $script:hostRecord.preparationCheckpointId = 'not-a-guid'; Expect-Rejection { Check-Preparation } 'exact preparation and baseline' }
Test-Case 'Reject aliased baseline and prepared checkpoint IDs' { $script:hostRecord.preparationCheckpointId = $script:hostRecord.baselineId; Expect-Rejection { Check-Preparation } 'exact preparation and baseline' }
Test-Case 'Reject a general checkpoint name' { $script:hostRecord.preparationCheckpoint = 'installed-clean'; Expect-Rejection { Check-Preparation } 'exact preparation and baseline' }
foreach ($field in @('formatSucceeded','imageApplied','bootFilesPrepared','firstBootConfigured')) {
    Test-Case "Reject incomplete guest $field" { $script:guestRecord.$field = $false; Expect-Rejection { Check-Preparation } 'Guest preparation' }
}
Test-Case 'Reject unqualified image index' { $script:guestRecord.imageIndex = 5; Expect-Rejection { Check-Preparation } 'Guest preparation' }
Test-Case 'Reject different image build' { $script:guestRecord.imageVersion = '10.0.26300.9711'; Expect-Rejection { Check-Preparation } 'Guest preparation' }
Test-Case 'Reject Dev Drive format mode' { $script:guestRecord.formatRequest.mode = 'DevDrive'; Expect-Rejection { Check-Preparation } 'ordinary 4 KiB' }
Test-Case 'Reject NTFS target format' { $script:guestRecord.formatRequest.arguments.FileSystem = 'NTFS'; Expect-Rejection { Check-Preparation } 'ordinary 4 KiB' }
Test-Case 'Reject 64 KiB target clusters' { $script:guestRecord.formatRequest.arguments.AllocationUnitSize = 65536; Expect-Rejection { Check-Preparation } 'ordinary 4 KiB' }
Test-Case 'Reject unknown formatter method' { $script:hostRecord.formatMethod = 'Unknown'; $script:guestRecord.formatMethod = 'Unknown'; Expect-Rejection { Check-Preparation } 'formatter methods' }
Test-Case 'Reject mixed formatter methods' { $script:hostRecord.formatMethod = 'FormatCom'; Expect-Rejection { Check-Preparation } 'formatter methods' }
Test-Case 'Reject misidentified FormatVolume command' { $script:guestRecord.formatRequest.command = 'format.com'; Expect-Rejection { Check-Preparation } 'FormatVolume preparation command' }
Test-Case 'Reject changed canonical label' { $script:guestRecord.formatRequest.arguments.NewFileSystemLabel = 'Other'; Expect-Rejection { Check-Preparation } 'ordinary 4 KiB' }
Test-Case 'Reject extra canonical formatter option' { $script:guestRecord.formatRequest.arguments | Add-Member NoteProperty DevDrive $true; Expect-Rejection { Check-Preparation } 'ordinary 4 KiB' }
Test-Case 'Reject changed partition size' { $script:guestRecord.formatRequest.actualPartitionSizeBytes = 40GB; Expect-Rejection { Check-Preparation } 'partition bounds' }
Test-Case 'Reject changed final partition layout' { $script:guestRecord.partitions[0].Size = 40GB; Expect-Rejection { Check-Preparation } 'exported target layout' }
Test-Case 'Accept exact FormatCom preparation and exported native evidence' { Set-FormatComFixture; Check-Preparation; Check-FormatArtifacts }
Test-Case 'Reject extra native Dev Drive flag' { Set-FormatComFixture; $script:guestRecord.formatRequest.nativeArguments += '/DevDrv'; Expect-Rejection { Check-Preparation } 'ordinary native arguments' }
Test-Case 'Reject changed native target letter' { Set-FormatComFixture; $script:guestRecord.formatRequest.nativeArguments[0] = 'H:'; Expect-Rejection { Check-Preparation } 'ordinary native arguments' }
Test-Case 'Reject source OS format letter' { Set-FormatComFixture; $script:guestRecord.formatRequest.volume = 'C:'; Expect-Rejection { Check-Preparation } 'target partition letter' }
Test-Case 'Reject target letter missing from final layout' { Set-FormatComFixture; $script:guestRecord.partitions[0].DriveLetter = 'H'; Expect-Rejection { Check-Preparation } 'target partition letter' }
foreach ($field in @('path','version','sha256','signature','signer')) {
    Test-Case "Reject invalid FormatCom tool $field" { Set-FormatComFixture; $script:guestRecord.tools.'format.com'.$field = ''; Expect-Rejection { Check-Preparation } 'formatter provenance' }
}
foreach ($field in @('exitCode','timedOut','timeoutSeconds','stdinMode','toolSha256','executable')) {
    Test-Case "Reject invalid FormatCom completion $field" {
        Set-FormatComFixture
        $script:guestRecord.formatCompletion.$field = switch ($field) { 'exitCode' { 4 }; 'timedOut' { $true }; 'timeoutSeconds' { 0 }; 'stdinMode' { 'answers-supplied' }; 'toolSha256' { 'changed' }; 'executable' { 'C:\other\format.com' } }
        Expect-Rejection { Check-Preparation } 'exact successful bounded'
    }
}
Test-Case 'Reject completion arguments that differ from request' { Set-FormatComFixture; $script:guestRecord.formatCompletion.arguments[2] = '/A:64K'; Expect-Rejection { Check-Preparation } 'completion changed' }
Test-Case 'Reject exported completion differing from record' { Set-FormatComFixture; $script:formatCommand.completedUtc = '2026-10-23T12:00:11Z'; Expect-Rejection { Check-FormatArtifacts } 'differs from the preparation' }
Test-Case 'Reject failed format help command' { Set-FormatComFixture; $script:helpCommand.exitCode = 1; Expect-Rejection { Check-FormatArtifacts } 'help was not captured' }
Test-Case 'Reject help arguments that could format' { Set-FormatComFixture; $script:helpCommand.arguments = @('G:'); Expect-Rejection { Check-FormatArtifacts } 'help was not captured' }
Test-Case 'Reject failed capability command' { Set-FormatComFixture; $script:capabilityCommand.exitCode = 1; Expect-Rejection { Check-FormatArtifacts } 'read-only script' }
Test-Case 'Reject substituted capability script path' { Set-FormatComFixture; $script:capabilityCommand.arguments[1] = 'C:\other.txt'; Expect-Rejection { Check-FormatArtifacts } 'read-only script' }
Test-Case 'Reject capability query of another disk' { Set-FormatComFixture; $script:capabilityScript = $script:capabilityScript.Replace('select disk 1','select disk 0'); Expect-Rejection { Check-FormatArtifacts } 'unexpected disk selection' }
Test-Case 'Reject capability script containing writes' { Set-FormatComFixture; $script:capabilityScript = $script:capabilityScript.Replace('filesystems','clean'); Expect-Rejection { Check-FormatArtifacts } 'unexpected disk selection' }
Test-Case 'Reject capability result captured after format started' { Set-FormatComFixture; $script:capabilityCommand.completedUtc = '2026-10-23T12:00:06Z'; Expect-Rejection { Check-FormatArtifacts } 'before formatting' }
Test-Case 'Reject foreign target VHD identity' { $script:guestRecord.target.hostVhdId = '55555555-5555-5555-5555-555555555555'; Expect-Rejection { Check-Preparation } 'owned 64 GiB' }
Test-Case 'Reject target on source SCSI slot' { $script:guestRecord.target.hostControllerLocation = 0; Expect-Rejection { Check-Preparation } 'owned 64 GiB' }
Test-Case 'Reject duplicate manifest targets' { $script:manifest.disks = @($script:manifest.disks[0],$script:manifest.disks[0]); Expect-Rejection { Check-Preparation } 'owned 64 GiB' }
Test-Case 'Reject missing enrolled target identity' { $script:targetRecord.uniqueId = ''; Expect-Rejection { Check-Preparation } 'identity is incomplete' }
foreach ($field in @('uniqueId','serialNumber','location','enrolledUtc')) {
    Test-Case "Reject inconsistent exported target $field" { $script:guestRecord.target.guest.$field = 'changed'; Expect-Rejection { Check-Preparation } 'differs between exported records' }
}
Test-Case 'Reject source and target sharing UniqueId' { $script:guestRecord.sourceOs.uniqueId = $script:targetRecord.uniqueId; Expect-Rejection { Check-Preparation } 'remain distinct' }
Test-Case 'Reject unqualified source build' { $script:guestRecord.sourceOs.build = '26300.9711'; Expect-Rejection { Check-Preparation } 'remain distinct' }

Test-Case 'Accept exact off-state checkpoint ID and name' { $found = Assert-ControlCheckpoint $script:hostRecord.preparationCheckpoint ([guid]$script:hostRecord.preparationCheckpointId); Assert-Check ([guid]$found.Id -eq [guid]$script:hostRecord.preparationCheckpointId) 'Wrong checkpoint returned.' }
Test-Case 'Reject matching checkpoint name with changed ID' { $script:mockCheckpoints[0].Id = $script:hostRecord.baselineId; Expect-Rejection { Assert-ControlCheckpoint $script:hostRecord.preparationCheckpoint ([guid]$script:hostRecord.preparationCheckpointId) } 'identity or off-state' }
Test-Case 'Reject running VM checkpoint selection' { $script:mockVM.State = 'Running'; Expect-Rejection { Assert-ControlCheckpoint $script:hostRecord.preparationCheckpoint ([guid]$script:hostRecord.preparationCheckpointId) } 'owned VM off' }
Test-Case 'Reject running checkpoint state' { $script:mockCheckpoints[0].State = 'Running'; Expect-Rejection { Assert-ControlCheckpoint $script:hostRecord.preparationCheckpoint ([guid]$script:hostRecord.preparationCheckpointId) } 'identity or off-state' }
Test-Case 'Reject duplicate exact checkpoint names' { $script:mockCheckpoints += $script:mockCheckpoints[0]; Expect-Rejection { Assert-ControlCheckpoint $script:hostRecord.preparationCheckpoint ([guid]$script:hostRecord.preparationCheckpointId) } 'multiple checkpoints' }
Test-Case 'Reject case-mismatched checkpoint without waiting in real time' { $script:mockCheckpoints[0].Name = $script:hostRecord.preparationCheckpoint.ToUpperInvariant(); Expect-Rejection { Assert-ControlCheckpoint $script:hostRecord.preparationCheckpoint ([guid]$script:hostRecord.preparationCheckpointId) } 'bounded lookup expired'; Assert-Check ($script:sleepCalls -eq 14) 'Checkpoint lookup was not bounded.' }
Test-Case 'Propagate checkpoint provider failure without retry' { $script:checkpointProviderFailure = $true; Expect-Rejection { Assert-ControlCheckpoint $script:hostRecord.preparationCheckpoint ([guid]$script:hostRecord.preparationCheckpointId) } 'Mock checkpoint provider failure'; Assert-Check ($script:sleepCalls -eq 0) 'Provider failure was silently retried.' }

Test-Case 'Observe exact ReFS target and completed setup' { $result = Check-Probe; Assert-Check ($result.identityMatched -and $result.ready) 'Exact target was rejected.' }
Test-Case 'NTFS fallback cannot match the ReFS observation' { $script:mockVolume.FileSystem = 'NTFS'; $result = Check-Probe; Assert-Check (-not $result.identityMatched -and -not $result.ready) 'NTFS fallback matched.' }
Test-Case 'Source OS disk cannot match the target observation' { $script:mockDisk.UniqueId = $script:expected.sourceOsUniqueId; Assert-Check (-not (Check-Probe).identityMatched) 'Source OS matched target identity.' }
Test-Case 'Wrong build cannot match the target observation' { $script:mockVersion.UBR = 9711; Assert-Check (-not (Check-Probe).identityMatched) 'Wrong OS build matched.' }
Test-Case 'Wrong edition cannot match the target observation' { $script:mockVersion.EditionID = 'Enterprise'; Assert-Check (-not (Check-Probe).identityMatched) 'Wrong edition matched.' }
Test-Case 'Missing marker cannot match the target observation' { $script:markerPresent = $false; Assert-Check (-not (Check-Probe).identityMatched) 'Unmarked OS matched.' }
Test-Case 'Foreign marker target cannot match the target observation' { $script:mockMarker.targetUniqueId = 'other-target'; Assert-Check (-not (Check-Probe).identityMatched) 'Foreign marker target matched.' }
Test-Case 'Foreign marker VHD cannot match the target observation' { $script:mockMarker.hostVhdId = '55555555-5555-5555-5555-555555555555'; Assert-Check (-not (Check-Probe).identityMatched) 'Foreign VHD marker matched.' }
Test-Case 'Nonboot disk cannot match the target observation' { $script:mockDisk.IsBoot = $false; Assert-Check (-not (Check-Probe).identityMatched) 'Nonboot disk matched.' }
Test-Case 'Nonsystem disk cannot match the target observation' { $script:mockDisk.IsSystem = $false; Assert-Check (-not (Check-Probe).identityMatched) 'Nonsystem disk matched.' }
Test-Case 'Active setup is matched but not ready' { $script:mockSetup.SystemSetupInProgress = 1; $result = Check-Probe; Assert-Check ($result.identityMatched -and -not $result.ready) 'Setup-in-progress was treated as ready.' }
Test-Case 'Active OOBE is not ready' { $script:mockSetup.OOBEInProgress = 1; Assert-Check (-not (Check-Probe).ready) 'OOBE-in-progress was treated as ready.' }
Test-Case 'Ambiguous C partition mapping is rejected' { $script:mockPartitions += $script:mockPartitions[0]; Expect-Rejection { Check-Probe } 'exactly one partition' }
Test-Case 'Reparse marker is rejected' { $script:mockMarkerFile.Attributes = [IO.FileAttributes]::ReparsePoint; Expect-Rejection { Check-Probe } 'reparse point' }
Test-Case 'Oversized marker is rejected' { $script:mockMarkerFile.Length = 16KB + 1; Expect-Rejection { Check-Probe } 'exceeds its bound' }

foreach ($bus in @('SCSI','SAS')) {
    Test-Case "Native boot evidence accepts exact target on $bus" { $script:mockBootDisk.BusType = $bus; Check-BootDiskGuard }
}
foreach ($bus in @('USB','NVMe','RAID','', ' ', $null)) {
    Test-Case "Native boot evidence rejects unqualified bus [$bus]" {
        $script:mockBootDisk.BusType = $bus
        Expect-Rejection { Check-BootDiskGuard } 'Actual boot/system disk differs'
    }
}
foreach ($field in @('PartitionStyle','Size','SerialNumber','Location','UniqueId')) {
    Test-Case "SAS boot evidence retains exact $field check" {
        $script:mockBootDisk.BusType = 'SAS'
        $script:mockBootDisk.$field = switch ($field) { 'PartitionStyle' { 'MBR' }; 'Size' { 8GB }; 'UniqueId' { 'mock-source-os' }; default { 'changed' } }
        Expect-Rejection { Check-BootDiskGuard } 'Actual boot/system disk differs'
    }
}
foreach ($role in @('boot','system')) {
    Test-Case "SAS boot evidence rejects mismatched $role disk" {
        $script:mockBootDisk.BusType = 'SAS'
        if ($role -eq 'boot') { $script:mockBootDisks = @([pscustomobject]@{ Number = 0 }) } else { $script:mockSystemDisks = @([pscustomobject]@{ Number = 0 }) }
        Expect-Rejection { Check-BootDiskGuard } 'Actual boot/system disk differs'
    }
    Test-Case "SAS boot evidence rejects ambiguous $role disks" {
        $script:mockBootDisk.BusType = 'SAS'
        if ($role -eq 'boot') { $script:mockBootDisks += $script:mockBootDisk } else { $script:mockSystemDisks += $script:mockBootDisk }
        Expect-Rejection { Check-BootDiskGuard } 'Actual boot/system disk differs'
    }
}

Test-Case 'Bounded command returns result and cleans up mock job' {
    $result = Invoke-BoundedBootCommand -ScriptBlock { throw 'Mock must not execute guest scriptblocks.' }
    Assert-Check ($result -ceq 'mock-result' -and $script:commandCalls -eq 1 -and $script:receiveCalls -eq 1 -and $script:cleanupCalls -eq 1) 'Bounded-command success cleanup differs.'
}
Test-Case 'Timeout refuses without reading results and cleans up mock job' {
    $script:jobTimeout = $true; Expect-Rejection { Invoke-BoundedBootCommand -ScriptBlock {} -TimeoutSeconds 1 } 'timed out'
    Assert-Check ($script:receiveCalls -eq 0 -and $script:cleanupCalls -eq 1) 'Timeout leaked job or consumed partial results.'
}
Test-Case 'Failed transport job is refused and cleaned up' {
    $script:mockJob.State = 'Failed'; Expect-Rejection { Invoke-BoundedBootCommand -ScriptBlock {} } 'did not complete'
    Assert-Check ($script:receiveCalls -eq 0 -and $script:cleanupCalls -eq 1) 'Failed job leaked or consumed partial results.'
}
Test-Case 'Receive failure propagates and cleans up mock job' {
    $script:receiveFailure = $true; Expect-Rejection { Invoke-BoundedBootCommand -ScriptBlock {} } 'Mock transport receive failure'
    Assert-Check ($script:cleanupCalls -eq 1) 'Receive failure leaked job.'
}

# Inspect, but never execute, the observer's side-effecting workflow.
$workflow = @($observerAst.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] })
Test-Case 'There is one guarded observation workflow' { Assert-Check ($workflow.Count -eq 1 -and $workflow[0].CatchClauses.Count -eq 1) 'Unexpected observation try/catch structure.' }
$failureBody = $workflow[0].CatchClauses[0].Body
Test-Case 'Failure catch preserves VM and only records diagnostics' {
    $commands = @($failureBody.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true))
    foreach ($command in $commands) {
        $name = $command.GetCommandName()
        if ($name) { Assert-Check ($name -in @('Write-BootHostRecord','Join-Path')) "Failure catch gained a non-diagnostic command: $name" }
        else { Assert-Check ($command.Extent.Text.Contains("'Get-LabBootDiagnostics.ps1'")) 'Failure catch gained an unreviewed dynamic command.' }
    }
    $throws = @($failureBody.FindAll({ param($node) $node -is [Management.Automation.Language.ThrowStatementAst] }, $true))
    Assert-Check ($throws.Count -gt 0 -and $failureBody.Extent.Text.Contains('failed-preserved-for-review')) 'Failure is not recorded and rethrown.'
}
Test-Case 'Observer has no force-shutdown, disk-format, policy, or elevation commands' {
    $commands = @($observerAst.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true))
    $forbidden = @('Stop-VM','Restart-VM','Mount-VHD','Mount-DiskImage','Clear-Disk','Initialize-Disk','New-Partition','Format-Volume','Set-ExecutionPolicy','Set-SecureBootUEFI','Enable-WindowsOptionalFeature','Disable-WindowsOptionalFeature','Start-Process')
    foreach ($command in $commands) { Assert-Check ($command.GetCommandName() -notin $forbidden) "Forbidden observer command: $($command.GetCommandName())" }
    $shutdown = @($commands | Where-Object { $_.GetCommandName() -ceq 'shutdown.exe' })
    Assert-Check ($shutdown.Count -eq 1 -and $shutdown[0].Extent.Text -match '^& shutdown\.exe /s /t 0$') 'Shutdown must be the sole nonforced guest shutdown request.'
}
Test-Case 'Native diagnostic invocations are read-only' {
    $calls = @($observerAst.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Read-NativeBootInfo' }, $true))
    $expectedCalls = @("Read-NativeBootInfo 'fsutil.exe' 'fsinfo refsinfo C:'", "Read-NativeBootInfo 'bcdedit.exe' '/enum all /v'", "Read-NativeBootInfo 'reagentc.exe' '/info'")
    Assert-Check ($calls.Count -eq $expectedCalls.Count) 'Native diagnostic call inventory changed.'
    foreach ($call in $calls) { Assert-Check ($call.Extent.Text -cin $expectedCalls) 'Native diagnostic includes an unreviewed operation.' }
}
Test-Case 'Firmware selects only the owned target and keeps Secure Boot' {
    $firmware = @($observerAst.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Set-VMFirmware' }, $true))
    Assert-Check ($firmware.Count -eq 1 -and $firmware[0].Extent.Text -ceq 'Set-VMFirmware -VM $vm -BootOrder $targetAttachment[0] -EnableSecureBoot On') 'Target-only Secure Boot selection changed.'
    Assert-Check ($observerAst.Extent.Text.Contains('$order.Count -ne 1')) 'Firmware order must be checked for fallback entries.'
}
Test-Case 'Reachable identity mismatch is immediately refused' {
    $refusal = $observerAst.Find({ param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Extent.Text -match '^if \(-not \$reply\[0\]\.identityMatched\)' }, $true)
    Assert-Check ($null -ne $refusal) 'Missing reachable-OS identity refusal.'
    $reply = @([pscustomobject]@{ identityMatched = $false; ready = $false })
    Expect-Rejection { . ([scriptblock]::Create($refusal.Extent.Text)) } 'NTFS fallback cannot pass'
}
Test-Case 'Observation never claims full conversion qualification' {
    Assert-Check ($observerAst.Extent.Text.Contains('fullQualificationPassed = $false; conversionVerified = $false')) 'Single boot must not imply full qualification.'
    Assert-Check (-not ($observerAst.Extent.Text -match '(?i)(fullQualificationPassed|conversionVerified)\s*=\s*\$true')) 'Observer claims unsupported qualification.'
}
"Passed $script:checks ReFS boot observation guard checks. Workflow and provider operations were never executed."
