<# One observed native ReFS boot, not conversion or servicing qualification.
   Requires successful preparation, verified exports and exact checkpoints.
   Never elevates itself. Failures preserve VM/evidence without forced shutdown
   or restore. Success exports evidence, cleanly shuts down, retains an observed
   checkpoint, then restores installed-clean. No feature flags or boot binaries change. #>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$PreparationDirectory,
    [ValidateSet('win11')][string]$Lane = 'win11',
    [ValidateRange(60,1800)][int]$BootTimeoutSeconds = 900
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $workspace 'lab\Lab.psm1') -Force
$configuration = Get-LabConfiguration -WorkspaceRoot $workspace
$preparationRoot = Assert-LabPath (Join-Path $configuration.Root 'refs-boot') $configuration.Root
$preparationPath = Assert-LabPath $PreparationDirectory $preparationRoot
if ((Split-Path $preparationPath -Parent) -ine $preparationRoot -or (Split-Path $preparationPath -Leaf) -cnotmatch '^win11-\d{8}T\d{9}Z$') { throw 'Select one exact win11 preparation run beneath the lab refs-boot directory.' }
if (-not $PSCmdlet.ShouldProcess($preparationPath, 'Restore prepared checkpoint; boot only owned ReFS target once; export observations before clean shutdown and baseline restore')) {
    [pscustomobject]@{ Action = 'TestNativeRefsOSBoot'; Lane = $Lane; DryRun = $true; PreparationDirectory = $preparationPath; TimeoutSeconds = $BootTimeoutSeconds; BootDevice = 'Owned target disk only'; SecureBoot = 'On'; BootAttempts = 1; FullQualification = $false; FailureDisposition = 'Capture diagnostics; preserve VM; no forced shutdown or restore' }
    return
}
function Read-ControlJson([string]$Path, [int64]$MaximumBytes = 1MB) {
    Assert-LabPath $Path $configuration.Root | Out-Null
    $file = Get-Item -LiteralPath $Path -Force
    if ($file.PSIsContainer -or $file.Length -eq 0 -or $file.Length -gt $MaximumBytes) { throw 'Missing, empty, or oversized control JSON.' }
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}
function Assert-FormatComCommand($Command, $GuestRecord) {
    $request = $GuestRecord.formatRequest
    $tool = $GuestRecord.tools.'format.com'
    $expectedArguments = @($request.volume, '/FS:ReFS', '/A:4096', '/Q', '/V:N2R_REFSOS', '/Y')
    if ($Command.executable -ine $tool.path -or $Command.toolSha256 -cne $tool.sha256 -or $Command.exitCode -ne 0 -or $Command.timedOut -ne $false -or $Command.timeoutSeconds -ne 120 -or $Command.stdinMode -cne 'closed-empty' -or @($Command.arguments).Count -ne $expectedArguments.Count) { throw 'FormatCom completion lacks the exact successful bounded native command.' }
    for ($i = 0; $i -lt $expectedArguments.Count; $i++) { if ($Command.arguments[$i] -cne $expectedArguments[$i]) { throw 'FormatCom completion changed the native arguments.' } }
}
function Assert-FormatComArtifacts($GuestRecord, $FormatCommand, $HelpCommand, $CapabilityCommand, [string]$CapabilityScript) {
    Assert-FormatComCommand $FormatCommand $GuestRecord
    foreach ($field in @('executable','toolSha256','exitCode','timedOut','timeoutSeconds','stdinMode','startedUtc','completedUtc')) {
        if ([string]$FormatCommand.$field -cne [string]$GuestRecord.formatCompletion.$field) { throw 'Exported FormatCom completion differs from the preparation record.' }
    }
    $formatTool = $GuestRecord.tools.'format.com'; $diskpartTool = $GuestRecord.tools.'diskpart.exe'
    if ($HelpCommand.executable -ine $formatTool.path -or $HelpCommand.toolSha256 -cne $formatTool.sha256 -or $HelpCommand.exitCode -ne 0 -or $HelpCommand.timedOut -ne $false -or @($HelpCommand.arguments).Count -ne 1 -or $HelpCommand.arguments[0] -cne '/?') { throw 'FormatCom help was not captured successfully from the validated formatter.' }
    if ($diskpartTool.path -ine 'C:\Windows\System32\diskpart.exe' -or $diskpartTool.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $diskpartTool.signature -cne 'Valid' -or $diskpartTool.signer -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)') { throw 'FormatCom capability query lacks signed native DiskPart provenance.' }
    if ($CapabilityCommand.executable -ine $diskpartTool.path -or $CapabilityCommand.toolSha256 -cne $diskpartTool.sha256 -or $CapabilityCommand.exitCode -ne 0 -or $CapabilityCommand.timedOut -ne $false -or @($CapabilityCommand.arguments).Count -ne 2 -or $CapabilityCommand.arguments[0] -cne '/s' -or $CapabilityCommand.arguments[1] -cne 'C:\ntfs2refs\refs-os-preparation\format-filesystems.txt') { throw 'FormatCom capability query did not complete with the exact read-only script.' }
    $expectedScript = "select disk $($GuestRecord.formatRequest.inputDiskNumber)`nselect partition $($GuestRecord.formatRequest.inputPartitionNumber)`nfilesystems`nexit"
    if ($CapabilityScript.Replace("`r`n", "`n").TrimEnd([char[]]"`r`n") -cne $expectedScript) { throw 'FormatCom capability script contains unexpected disk selection or commands.' }
    $capabilityFinished = [DateTimeOffset]::MinValue; $formatStarted = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse([string]$CapabilityCommand.completedUtc, [ref]$capabilityFinished) -or -not [DateTimeOffset]::TryParse([string]$FormatCommand.startedUtc, [ref]$formatStarted) -or $capabilityFinished -gt $formatStarted) { throw 'FormatCom capability query was not recorded before formatting.' }
}
function Assert-PreparationRecords($HostRecord, $GuestRecord, $TargetRecord, $Manifest) {
    if ($HostRecord.schemaVersion -ne 1 -or $HostRecord.phase -cne 'native-refs-os-preparation' -or $HostRecord.status -cne 'prepared-awaiting-separate-boot-validation' -or [string]$HostRecord.vmId -cne [string]$Manifest.vmId -or $HostRecord.mediaSha256 -cne $Manifest.media.sha256 -or -not $HostRecord.evidenceExported -or -not $HostRecord.baselineRestored -or $HostRecord.bootAttempted -or $HostRecord.refsBootVerified) { throw 'Host preparation did not complete and export safely for this VM/media.' }
    $preparationId = [guid]::Empty; $baselineId = [guid]::Empty
    if ($HostRecord.preparationCheckpoint -cnotmatch '^refs-os-prepared-\d{8}T\d{9}Z$' -or -not [guid]::TryParse([string]$HostRecord.preparationCheckpointId, [ref]$preparationId) -or -not [guid]::TryParse([string]$HostRecord.baselineId, [ref]$baselineId) -or $preparationId -eq $baselineId) { throw 'Distinct exact preparation and baseline checkpoint identities are required.' }
    if ($GuestRecord.schemaVersion -ne 1 -or $GuestRecord.phase -cne 'native-refs-os-preparation' -or $GuestRecord.status -cne 'prepared' -or $GuestRecord.stage -cne 'prepared-awaiting-separate-boot-validation' -or $GuestRecord.imageIndex -ne 6 -or $GuestRecord.imageVersion -cne '10.0.26300.9457' -or -not ($GuestRecord.formatSucceeded -and $GuestRecord.imageApplied -and $GuestRecord.bootFilesPrepared -and $GuestRecord.firstBootConfigured) -or $GuestRecord.bootAttempted -or $GuestRecord.refsBootVerified) { throw 'Guest preparation has incomplete or incompatible stages.' }
    if ($HostRecord.formatMethod -cnotin @('FormatVolume','FormatCom') -or $GuestRecord.formatMethod -cne $HostRecord.formatMethod) { throw 'Preparation formatter methods must be explicit, supported and identical.' }
    $request = $GuestRecord.formatRequest
    $canonicalNames = @('FileSystem','AllocationUnitSize','NewFileSystemLabel','Confirm')
    if ($request.mode -cne 'ordinary-ReFS' -or $request.arguments.FileSystem -cne 'ReFS' -or $request.arguments.AllocationUnitSize -ne 4096 -or $request.arguments.NewFileSystemLabel -cne 'N2R_REFSOS' -or $request.arguments.Confirm -ne $false -or @($request.arguments.PSObject.Properties).Count -ne $canonicalNames.Count) { throw 'Only ordinary 4 KiB ReFS preparation is accepted.' }
    foreach ($property in $request.arguments.PSObject.Properties) { if ($property.Name -cnotin $canonicalNames) { throw 'Only ordinary 4 KiB ReFS preparation is accepted.' } }
    if ($request.requestedPartitionSizeBytes -lt 40GB -or $request.requestedPartitionSizeBytes -ge 64GB -or $request.actualPartitionSizeBytes -ne $request.requestedPartitionSizeBytes -or $request.inputPartitionNumber -lt 1 -or $request.inputDiskNumber -lt 0) { throw 'Preparation formatter partition bounds are inconsistent.' }
    $formattedParts = @($GuestRecord.partitions | Where-Object PartitionNumber -EQ $request.inputPartitionNumber)
    if ($formattedParts.Count -ne 1 -or $formattedParts[0].Size -ne $request.actualPartitionSizeBytes) { throw 'Preparation formatter partition differs from the exported target layout.' }
    if ($GuestRecord.formatMethod -ceq 'FormatVolume') {
        if ($request.command -cne 'Format-Volume') { throw 'FormatVolume preparation command differs from its formatter method.' }
    } else {
        if ($request.command -cne 'format.com' -or $request.volume -cnotmatch '^[F-Z]:$' -or ([string]$formattedParts[0].DriveLetter + ':') -cne $request.volume) { throw 'FormatCom request does not identify the exact exported target partition letter.' }
        $expectedArguments = @($request.volume, '/FS:ReFS', '/A:4096', '/Q', '/V:N2R_REFSOS', '/Y')
        if (@($request.nativeArguments).Count -ne $expectedArguments.Count) { throw 'FormatCom request changed the ordinary native arguments.' }
        for ($i = 0; $i -lt $expectedArguments.Count; $i++) { if ($request.nativeArguments[$i] -cne $expectedArguments[$i]) { throw 'FormatCom request changed the ordinary native arguments.' } }
        $tool = $GuestRecord.tools.'format.com'
        if ($tool.path -ine 'C:\Windows\System32\format.com' -or [string]::IsNullOrWhiteSpace([string]$tool.version) -or $tool.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $tool.signature -cne 'Valid' -or $tool.signer -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)') { throw 'FormatCom preparation lacks validated stock Microsoft formatter provenance.' }
        Assert-FormatComCommand $GuestRecord.formatCompletion $GuestRecord
    }
    $target = @($Manifest.disks | Where-Object role -CEQ 'target')
    if ($target.Count -ne 1 -or $target[0].sizeBytes -ne 64GB -or $target[0].controllerLocation -ne 1 -or [guid]$GuestRecord.target.hostVhdId -ne [guid]$target[0].vhdId -or $GuestRecord.target.hostControllerLocation -ne 1) { throw 'Prepared target differs from the owned 64 GiB SCSI target.' }
    $guestTarget = $GuestRecord.target.guest
    if ($TargetRecord.schemaVersion -ne 1 -or $TargetRecord.role -cne 'target' -or $TargetRecord.sizeBytes -ne 64GB -or [string]::IsNullOrWhiteSpace([string]$TargetRecord.uniqueId) -or [string]::IsNullOrWhiteSpace([string]$TargetRecord.location)) { throw 'Guest target identity is incomplete.' }
    foreach ($field in @('uniqueId','serialNumber','location','sizeBytes','role','enrolledUtc')) { if ([string]$TargetRecord.$field -cne [string]$guestTarget.$field) { throw "Guest target identity differs between exported records: $field." } }
    if ($GuestRecord.sourceOs.filesystem -cne 'NTFS' -or $GuestRecord.sourceOs.build -cne '26300.9457' -or [string]::IsNullOrWhiteSpace([string]$GuestRecord.sourceOs.uniqueId) -or $GuestRecord.sourceOs.uniqueId -ceq $guestTarget.uniqueId) { throw 'Original NTFS OS and ReFS target identities must remain distinct.' }
}
function Get-ControlExportInventory([string]$Root) {
    Assert-LabPath $Root $configuration.Root | Out-Null
    $pending = New-Object 'System.Collections.Generic.Queue[string]'; $pending.Enqueue($Root)
    $files = New-Object 'System.Collections.Generic.List[object]'; $entries = 0
    while ($pending.Count) {
        foreach ($item in Get-ChildItem -LiteralPath $pending.Dequeue() -Force) {
            $entries++; if ($entries -gt 512) { throw 'Baseline export exceeds the bounded inventory.' }
            Assert-LabPath $item.FullName $Root | Out-Null
            if ($item.PSIsContainer) { $pending.Enqueue($item.FullName) } else { $files.Add($item) }
        }
    }
    $files.ToArray()
}
function Invoke-BoundedBootCommand([scriptblock]$ScriptBlock, [object[]]$Arguments = @(), [int]$TimeoutSeconds = 30) {
    $job = $null
    try {
        $job = Invoke-Command -VMId ([guid]$manifest.vmId) -Credential $credential -ScriptBlock $ScriptBlock -ArgumentList $Arguments -AsJob
        if (-not (Wait-Job -Job $job -Timeout $TimeoutSeconds)) { throw 'Bounded PowerShell Direct command timed out.' }
        if ($job.State -ne 'Completed') { throw 'PowerShell Direct command did not complete.' }
        Receive-Job -Job $job -ErrorAction Stop
    } finally { if ($job) { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue } }
}
function Assert-ControlCheckpoint([string]$Name, [guid]$Id) {
    $owned = Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    if ($owned.State -ne 'Off') { throw 'Checkpoint selection requires the owned VM off.' }
    $checkpoint = Get-ExactLabCheckpoint -VM $owned -Name $Name
    if ([guid]$checkpoint.Id -ne $Id -or $checkpoint.State -ne 'Off') { throw 'Checkpoint identity or off-state differs from the recorded control.' }
    $checkpoint
}
function Write-BootHostRecord {
    $record.updatedUtc = [DateTime]::UtcNow.ToString('o')
    $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $outputRoot 'host-result.json') -Encoding UTF8
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use the reviewed elevated Hyper-V helper; this script does not elevate itself.' }
Import-Module Hyper-V -ErrorAction Stop
$manifest = Read-LabManifest -Configuration $configuration -Lane $Lane
if (-not $manifest) { throw 'Missing lab ownership manifest.' }
$vm = Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
if ($vm.State -ne 'Off') { throw 'Start with the manifest-owned VM off.' }
if (@(Get-VMNetworkAdapter -VM $vm | Where-Object SwitchName).Count -or (Get-VMFirmware -VM $vm).SecureBoot -ne 'On') { throw 'The VM must retain a disconnected network and Secure Boot.' }
$hostPreparation = Read-ControlJson (Join-Path $preparationPath 'host-result.json')
$guestPreparation = Read-ControlJson (Join-Path $preparationPath 'result.json')
$targetRecord = Read-ControlJson (Join-Path $preparationPath 'target.json')
Assert-PreparationRecords $hostPreparation $guestPreparation $targetRecord $manifest
# Materialize after assignment: PowerShell 5 can wrap ConvertFrom-Json arrays.
$parsedExport = Read-ControlJson (Join-Path $preparationPath 'exported-files.json')
$exportedFiles = @($parsedExport)
$allowed = @('target.json','result.json','refs-info.log','refs-info.log.command.json','dism-apply.log','dism-apply.log.command.json','dism-detail.log','dism-detail.log.bak','bcdboot.log','bcdboot.log.command.json','bcd-store.log','bcd-store.log.command.json','reagentc.log','reagentc.log.command.json','recovery-attributes.txt','recovery-attributes.log','recovery-attributes.log.command.json','recovery-partition.json','format-help.log','format-help.log.command.json','format-filesystems.txt','format-filesystems.log','format-filesystems.log.command.json','format-com.log','format-com.log.command.json')
if ($exportedFiles.Count -lt 2 -or $exportedFiles.Count -gt $allowed.Count -or ($exportedFiles | Measure-Object length -Sum).Sum -gt 64MB) { throw 'Invalid preparation export inventory.' }
$seen = @{}
foreach ($entry in $exportedFiles) {
    if ($entry.name -cnotin $allowed -or $seen.ContainsKey([string]$entry.name) -or $entry.length -lt 0 -or $entry.length -gt 32MB -or $entry.sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Invalid or duplicate preparation export entry.' }
    $seen[[string]$entry.name] = $true
    $path = Assert-LabPath (Join-Path $preparationPath $entry.name) $preparationPath
    $file = Get-Item -LiteralPath $path
    if ($file.PSIsContainer -or $file.Length -ne $entry.length -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256) { throw 'Preparation export hash/length mismatch.' }
}
foreach ($required in @('target.json','result.json','dism-apply.log.command.json','bcdboot.log.command.json','bcd-store.log.command.json','reagentc.log.command.json','recovery-attributes.log.command.json')) {
    if (-not $seen.ContainsKey($required)) { throw "Required verified preparation artifact missing: $required." }
    if ($required.EndsWith('.command.json')) { $command = Read-ControlJson (Join-Path $preparationPath $required); if ($command.exitCode -ne 0) { throw 'A required native preparation command did not succeed.' } }
}
if ($guestPreparation.formatMethod -ceq 'FormatCom') {
    foreach ($required in @('format-help.log','format-help.log.command.json','format-filesystems.txt','format-filesystems.log','format-filesystems.log.command.json','format-com.log','format-com.log.command.json')) { if (-not $seen.ContainsKey($required)) { throw "Required verified FormatCom artifact missing: $required." } }
    Assert-FormatComArtifacts $guestPreparation (Read-ControlJson (Join-Path $preparationPath 'format-com.log.command.json')) (Read-ControlJson (Join-Path $preparationPath 'format-help.log.command.json')) (Read-ControlJson (Join-Path $preparationPath 'format-filesystems.log.command.json')) (Get-Content -LiteralPath (Join-Path $preparationPath 'format-filesystems.txt') -Raw)
}
$prepared = Assert-ControlCheckpoint $hostPreparation.preparationCheckpoint ([guid]$hostPreparation.preparationCheckpointId)
$baseline = Assert-ControlCheckpoint 'installed-clean' ([guid]$hostPreparation.baselineId)
$laneRoot = Assert-LabPath (Join-Path $configuration.Root $Lane) $configuration.Root
$firstBoot = Read-ControlJson (Join-Path $laneRoot 'firstboot\state.json')
$ntfsEvidence = Read-ControlJson (Join-Path $laneRoot 'firstboot\native-ntfs-evidence.json')
if ($firstBoot.stage -cne 'complete' -or [string]$firstBoot.vmId -cne [string]$manifest.vmId -or -not $ntfsEvidence.nativeNtfsControlPassed -or @($ntfsEvidence.failures).Count -ne 0 -or $ntfsEvidence.windowsBuild -cne '26300.9457' -or $ntfsEvidence.osFileSystem -cne 'NTFS') { throw 'The installed-clean NTFS baseline has not completed qualification.' }
$baselineOs = @($ntfsEvidence.disks | Where-Object IsBoot)
if ($baselineOs.Count -ne 1 -or [string]$baselineOs[0].UniqueId -cne [string]$guestPreparation.sourceOs.uniqueId) { throw 'Preparation source differs from the passed NTFS baseline.' }
$baselineExport = Assert-LabPath (Join-Path $configuration.Root "exports\$Lane-installed-clean") $configuration.Root
$baselineFiles = @(Get-ControlExportInventory $baselineExport)
$configs = @($baselineFiles | Where-Object { $_.Extension -ieq '.vmcx' -and $_.Length -gt 0 })
$diskFiles = @($baselineFiles | Where-Object { $_.Extension -in @('.vhdx','.avhdx') -and $_.Length -gt 0 })
if ($configs.Count -ne 1 -or $diskFiles.Count -lt @($manifest.disks).Count) { throw 'Independent baseline export lacks its VM configuration or disk images.' }
$exportDiskEvidence = @()
foreach ($file in $diskFiles) {
    $disk = Get-VHD -Path $file.FullName -ErrorAction Stop
    if ($disk.ParentPath) { Assert-LabPath $disk.ParentPath $baselineExport | Out-Null }
    $exportDiskEvidence += [pscustomobject]@{ relativePath = $file.FullName.Substring($baselineExport.Length).TrimStart('\'); length = $file.Length; vhdId = [string]$disk.DiskIdentifier; sizeBytes = $disk.Size }
}
foreach ($disk in $manifest.disks) { if (@($exportDiskEvidence | Where-Object { [guid]$_.vhdId -eq [guid]$disk.vhdId -and $_.sizeBytes -eq $disk.sizeBytes }).Count -lt 1) { throw 'Baseline export does not retain every manifest disk identity and size.' } }
$credential = Import-Clixml -LiteralPath (Assert-LabPath (Join-Path $laneRoot 'secrets\guest-credential.xml') $configuration.Root)
if ($credential -isnot [Management.Automation.PSCredential] -or $credential.UserName -cne 'N2R-WIN11\LabAdmin') { throw 'Unexpected guest credential identity.' }
Assert-LabCapacity (Get-LabCapacity $configuration) -AdditionalBytes 8GB
$runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$outputRoot = Assert-LabPath (Join-Path $configuration.Root "refs-boot-tests\$Lane-$runId") $configuration.Root
if (Test-Path -LiteralPath $outputRoot) { throw 'Boot observation output already exists.' }
New-Item -ItemType Directory -Path $outputRoot | Out-Null
$expected = [pscustomobject]@{ targetUniqueId = $targetRecord.uniqueId; sourceOsUniqueId = $guestPreparation.sourceOs.uniqueId; hostVhdId = $guestPreparation.target.hostVhdId; sizeBytes = $targetRecord.sizeBytes; serialNumber = $targetRecord.serialNumber; location = $targetRecord.location; expectedBuild = '26300.9457'; runId = $runId }
$expectedJson = $expected | ConvertTo-Json -Compress
$record = [ordered]@{
    schemaVersion = 1; phase = 'native-refs-os-single-boot-observation'; lane = $Lane; vmId = $manifest.vmId
    preparationDirectory = $preparationPath; preparationCheckpoint = $prepared.Name; preparationCheckpointId = [string]$prepared.Id
    baselineId = [string]$baseline.Id; status = 'validated'; bootAttempted = $false; nativeRefsBootObserved = $false
    fullQualificationPassed = $false; conversionVerified = $false; evidenceExported = $false; cleanShutdown = $false; baselineRestored = $false
    observationCheckpoint = $null; observationCheckpointId = $null; guestEvidence = $null; diagnostics = $null; error = $null; lastProbe = $null; probeCount = 0
    baselineExportVerification = [ordered]@{ kind = 'Structure and VHD identity/size; complete disk contents not rehashed'; path = $baselineExport; configurationSha256 = (Get-FileHash -LiteralPath $configs[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant(); disks = $exportDiskEvidence }
    createdUtc = [DateTime]::UtcNow.ToString('o'); updatedUtc = [DateTime]::UtcNow.ToString('o')
}
foreach ($name in @('host-result.json','result.json','target.json','exported-files.json')) { Copy-Item -LiteralPath (Join-Path $preparationPath $name) -Destination (Join-Path $outputRoot ('preparation-' + $name)) }
Write-BootHostRecord

$identityProbe = {
    param($ExpectedJson)
    Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'
    $expected = $ExpectedJson | ConvertFrom-Json
    $volume = Get-Volume -DriveLetter C
    $parts = @(Get-Partition -DriveLetter C)
    if ($parts.Count -ne 1) { throw 'C: is not mapped to exactly one partition.' }
    $disk = Get-Disk -Number $parts[0].DiskNumber
    $version = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $setup = Get-ItemProperty 'HKLM:\SYSTEM\Setup'
    $systemSetup = if ($setup.PSObject.Properties['SystemSetupInProgress']) { [int]$setup.SystemSetupInProgress } else { -1 }
    $oobe = if ($setup.PSObject.Properties['OOBEInProgress']) { [int]$setup.OOBEInProgress } else { 0 }
    $marker = $null; $markerPath = 'C:\ntfs2refs\refs-os-control.json'
    if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
        foreach ($path in @('C:\ntfs2refs', $markerPath)) { if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Control marker traverses a reparse point.' } }
        if ((Get-Item -LiteralPath $markerPath).Length -gt 16KB) { throw 'Control marker exceeds its bound.' }
        $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    }
    $matched = $null -ne $marker -and $env:COMPUTERNAME -ceq 'N2R-WIN11' -and $env:SystemDrive -ceq 'C:' -and $volume.FileSystem -ceq 'ReFS' -and $disk.IsBoot -and $disk.IsSystem -and [string]$disk.UniqueId -ceq [string]$expected.targetUniqueId -and $marker.schemaVersion -eq 1 -and $marker.purpose -ceq 'native-refs-os-control' -and $marker.targetUniqueId -ceq $expected.targetUniqueId -and $marker.sourceOsUniqueId -ceq $expected.sourceOsUniqueId -and [guid]$marker.hostVhdId -eq [guid]$expected.hostVhdId -and $marker.expectedFilesystem -ceq 'ReFS' -and $marker.expectedBuild -ceq $expected.expectedBuild -and "$($version.CurrentBuildNumber).$($version.UBR)" -ceq $expected.expectedBuild -and $version.EditionID -ceq 'Professional'
    [pscustomobject]@{ identityMatched = [bool]$matched; ready = ($matched -and $systemSetup -eq 0 -and $oobe -eq 0); computerName = $env:COMPUTERNAME; filesystem = [string]$volume.FileSystem; diskUniqueId = [string]$disk.UniqueId; diskIsBoot = $disk.IsBoot; diskIsSystem = $disk.IsSystem; systemSetupInProgress = $systemSetup; oobeInProgress = $oobe; build = "$($version.CurrentBuildNumber).$($version.UBR)"; markerPresent = $null -ne $marker }
}

try {
    $prepared = Assert-ControlCheckpoint $record.preparationCheckpoint ([guid]$record.preparationCheckpointId)
    Restore-VMCheckpoint -VMSnapshot $prepared -Confirm:$false
    $vm = Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    if ($vm.State -ne 'Off' -or (Get-VMFirmware -VM $vm).SecureBoot -ne 'On' -or @(Get-VMNetworkAdapter -VM $vm | Where-Object SwitchName).Count) { throw 'Prepared checkpoint restored an unexpected VM state or policy.' }
    $targetAttachment = @(Get-VMHardDiskDrive -VM $vm | Where-Object { $_.ControllerType -eq 'SCSI' -and $_.ControllerNumber -eq 0 -and $_.ControllerLocation -eq 1 })
    if ($targetAttachment.Count -ne 1) { throw 'Owned target attachment is ambiguous.' }
    Set-VMFirmware -VM $vm -BootOrder $targetAttachment[0] -EnableSecureBoot On
    $firmware = Get-VMFirmware -VM $vm; $order = @($firmware.BootOrder)
    if ($firmware.SecureBoot -ne 'On' -or $order.Count -ne 1 -or $order[0].BootType -ne 'Drive' -or $order[0].Device.Path -ine $targetAttachment[0].Path -or $order[0].Device.ControllerNumber -ne 0 -or $order[0].Device.ControllerLocation -ne 1) { throw 'Firmware must select only the exact owned target disk.' }
    $record['selectedBootDevice'] = [ordered]@{ path = $targetAttachment[0].Path; controllerNumber = 0; controllerLocation = 1; secureBoot = [string]$firmware.SecureBoot; firmwarePath = [string]$order[0].FirmwarePath }
    $record.status = 'starting-target'; $record.bootAttempted = $true; Write-BootHostRecord
    Invoke-LabAction -Action Start -Lane $Lane -Confirm:$false | Out-Null
    $deadline = [DateTime]::UtcNow.AddSeconds($BootTimeoutSeconds); $ready = $false
    while ([DateTime]::UtcNow -lt $deadline -and -not $ready) {
        $record.probeCount++
        $remaining = [Math]::Max(1, [int]($deadline - [DateTime]::UtcNow).TotalSeconds); $reply = @()
        try { $reply = @(Invoke-BoundedBootCommand $identityProbe @($expectedJson) ([Math]::Min(15, $remaining))) }
        catch { $record['lastTransportStatus'] = 'Not yet reachable or probe failed; credentials are not recorded.' }
        if ($reply.Count -eq 1) {
            $record.lastProbe = $reply[0]
            if (-not $reply[0].identityMatched) { throw 'Reachable OS failed the ReFS target/build/marker check; NTFS fallback cannot pass.' }
            $ready = [bool]$reply[0].ready
        } elseif ($reply.Count -gt 1) { throw 'PowerShell Direct returned an ambiguous identity response.' }
        $record.status = 'waiting-for-target-setup'; Write-BootHostRecord
        if (-not $ready -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Seconds 2 }
    }
    if (-not $ready) { throw 'ReFS target boot/setup was not observed before the deadline; VM and evidence preserved for review.' }
    $record.status = 'collecting-native-observation'; Write-BootHostRecord
    $envelopes = @(Invoke-BoundedBootCommand -TimeoutSeconds 180 -Arguments @($expectedJson, $identityProbe.ToString()) -ScriptBlock {
        param($ExpectedJson, $IdentityProbeSource)
        Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'
        $expected = $ExpectedJson | ConvertFrom-Json
        # The probe source comes from this reviewed host script, not guest data.
        $verified = & ([scriptblock]::Create($IdentityProbeSource)) $ExpectedJson
        if (-not $verified.ready) { throw 'Target identity/setup changed before evidence collection.' }
        $findings = New-Object 'System.Collections.Generic.List[string]'
        $volume = Get-Volume -DriveLetter C; $part = Get-Partition -DriveLetter C
        $disk = Get-Disk -Number $part.DiskNumber
        $bootDisks = @(Get-Disk | Where-Object IsBoot); $systemDisks = @(Get-Disk | Where-Object IsSystem)
        $mapping = @(Get-CimInstance Win32_DiskDrive | Where-Object Index -eq $disk.Number)
        $secureBoot = Confirm-SecureBootUEFI
        if (-not $secureBoot -or $volume.FileSystemLabel -cne 'N2R_REFSOS' -or $volume.AllocationUnitSize -ne 4096) { throw 'Native volume geometry or Secure Boot policy differs.' }
        if ($bootDisks.Count -ne 1 -or $systemDisks.Count -ne 1 -or $bootDisks[0].Number -ne $disk.Number -or $systemDisks[0].Number -ne $disk.Number -or $disk.PartitionStyle -ne 'GPT' -or [string]$disk.BusType -notin @('SCSI','SAS') -or $disk.Size -ne $expected.sizeBytes -or [string]$disk.SerialNumber -cne $expected.serialNumber -or [string]$disk.Location -cne $expected.location -or [string]$disk.UniqueId -ceq $expected.sourceOsUniqueId) { throw 'Actual boot/system disk differs from the enrolled target.' }
        if ($mapping.Count -ne 1 -or -not (($mapping[0].SCSITargetId -eq 1 -and $mapping[0].SCSILogicalUnit -eq 0) -or ($mapping[0].SCSITargetId -eq 0 -and $mapping[0].SCSILogicalUnit -eq 1))) { throw 'Actual boot disk is not in target SCSI slot 1.' }
        function Read-BootComponent([string]$Name, [string]$Path) {
            $entry = [ordered]@{ name = $Name; path = $Path; version = $null; sha256 = $null; signatureStatus = 'Unknown'; signer = $null; error = $null }
            try {
                $file = Get-Item -LiteralPath $Path -Force
                if ($file.PSIsContainer -or $file.Length -eq 0 -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Component is not an ordinary nonempty file.' }
                $entry.version = $file.VersionInfo.FileVersion
                $entry.sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
                $signature = Get-AuthenticodeSignature -LiteralPath $Path; $entry.signatureStatus = [string]$signature.Status
                if ($signature.SignerCertificate) { $entry.signer = $signature.SignerCertificate.Subject }
            } catch { $entry.error = $_.Exception.Message }
            [pscustomobject]$entry
        }
        function Read-NativeBootInfo([string]$Name, [string]$Arguments) {
            $process = New-Object Diagnostics.Process
            $entry = [ordered]@{ command = $Name; arguments = $Arguments; exitCode = $null; timedOut = $false; truncated = $false; output = $null; error = $null }
            try {
                $process.StartInfo.FileName = Join-Path $env:SystemRoot ('System32\' + $Name); $process.StartInfo.Arguments = $Arguments
                $process.StartInfo.UseShellExecute = $false; $process.StartInfo.CreateNoWindow = $true
                $process.StartInfo.RedirectStandardOutput = $true; $process.StartInfo.RedirectStandardError = $true
                if (-not $process.Start()) { throw 'Diagnostic command did not start.' }
                $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
                if (-not $process.WaitForExit(20000)) { $entry.timedOut = $true; $process.Kill(); $process.WaitForExit(); throw 'Read-only diagnostic process exceeded its deadline.' }
                $entry.exitCode = $process.ExitCode
                $text = $stdout.GetAwaiter().GetResult() + "`n" + $stderr.GetAwaiter().GetResult()
                $entry.truncated = $text.Length -gt 131072; $entry.output = if ($entry.truncated) { $text.Substring(0,131072) } else { $text }
            } catch { $entry.error = $_.Exception.Message } finally { $process.Dispose() }
            [pscustomobject]$entry
        }
        $components = @()
        foreach ($relative in @('System32\drivers\refs.sys','System32\winload.efi','Boot\EFI\bootmgfw.efi')) { $components += Read-BootComponent $relative (Join-Path $env:SystemRoot $relative) }
        $esp = @(Get-Partition -DiskNumber $disk.Number | Where-Object GptType -ieq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}')
        if ($esp.Count -eq 1) {
            $espPaths = @($esp[0].AccessPaths | Where-Object { $_ -match '^\\\\\?\\Volume\{' })
            if ($espPaths.Count -eq 1) {
                foreach ($relative in @('EFI\Microsoft\Boot\bootmgfw.efi','EFI\Boot\bootx64.efi')) { $components += Read-BootComponent ('target-ESP\' + $relative) ($espPaths[0].TrimEnd('\') + '\' + $relative) }
            } else { $findings.Add('Target ESP has no unique accessible volume path; file signatures not observed.') }
        } else { $findings.Add('Target ESP could not be identified uniquely.') }
        foreach ($component in $components) { if ($component.signatureStatus -cne 'Valid' -or $component.signer -notmatch 'O=Microsoft Corporation') { $findings.Add('Component signature unavailable or not valid Microsoft: ' + $component.name) } }
        $native = @((Read-NativeBootInfo 'fsutil.exe' 'fsinfo refsinfo C:'), (Read-NativeBootInfo 'bcdedit.exe' '/enum all /v'), (Read-NativeBootInfo 'reagentc.exe' '/info'))
        $winre = $native | Where-Object command -CEQ 'reagentc.exe'
        $markerPath = 'C:\ntfs2refs\refs-os-control.json'
        $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
        $evidence = [ordered]@{
            schemaVersion = 1; phase = 'native-refs-os-single-boot-observation'; runId = $expected.runId
            computerName = $env:COMPUTERNAME; systemDrive = $env:SystemDrive; windowsBuild = $verified.build; edition = 'Professional'
            osFileSystem = [string]$volume.FileSystem; allocationUnitSize = $volume.AllocationUnitSize; secureBoot = $secureBoot
            marker = $marker; markerSha256 = (Get-FileHash -LiteralPath $markerPath -Algorithm SHA256).Hash.ToLowerInvariant()
            bootDisk = ($disk | Select-Object Number,UniqueId,SerialNumber,Location,Size,PartitionStyle,IsBoot,IsSystem,IsOffline,IsReadOnly)
            osPartition = ($part | Select-Object PartitionNumber,DiskNumber,Offset,Size,GptType,IsBoot,IsSystem)
            scsiMapping = ($mapping[0] | Select-Object Index,SCSIPort,SCSIBus,SCSITargetId,SCSILogicalUnit)
            bootComponents = $components; nativeCommands = $native
            pagefileUsage = @(Get-CimInstance Win32_PageFileUsage | Select-Object Name,AllocatedBaseSize,CurrentUsage,PeakUsage,TempPageFile)
            pagefileSettings = @(Get-CimInstance Win32_PageFileSetting | Select-Object Name,InitialSize,MaximumSize)
            winreReportedEnabled = ($winre.exitCode -eq 0 -and $winre.output -match 'Windows RE status:\s+Enabled')
            qualificationFindings = $findings.ToArray(); nativeRefsBootObserved = $true; fullQualificationPassed = $false; conversionVerified = $false
            hostInitiatedBootAttempts = 1; coldBootCyclesQualified = 0; capturedUtc = [DateTime]::UtcNow.ToString('o')
        }
        $root = 'C:\ntfs2refs\refs-os-boot'
        if (Test-Path -LiteralPath $root) { if ((Get-Item -LiteralPath $root -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Guest evidence root is a reparse point.' } }
        else { New-Item -ItemType Directory -Path $root | Out-Null }
        $destination = Join-Path $root $expected.runId
        if (Test-Path -LiteralPath $destination) { throw 'Guest observation directory already exists.' }
        New-Item -ItemType Directory -Path $destination | Out-Null
        $json = $evidence | ConvertTo-Json -Depth 12; $encoding = New-Object Text.UTF8Encoding($false)
        if ($encoding.GetByteCount($json) -gt 2MB) { throw 'Guest observation exceeded its bounded export.' }
        $path = Join-Path $destination 'evidence.json'; [IO.File]::WriteAllText($path, $json, $encoding)
        [pscustomobject]@{ json = $json; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant(); length = (Get-Item -LiteralPath $path).Length; guestPath = $path }
    })
    if ($envelopes.Count -ne 1 -or $envelopes[0].sha256 -cnotmatch '^[0-9a-f]{64}$' -or $envelopes[0].length -le 0 -or $envelopes[0].length -gt 2MB) { throw 'Guest evidence export envelope is invalid.' }
    $envelope = $envelopes[0]; $encoding = New-Object Text.UTF8Encoding($false)
    if ($encoding.GetByteCount([string]$envelope.json) -ne $envelope.length) { throw 'Guest evidence export length differs from its recorded bytes.' }
    $guestEvidencePath = Join-Path $outputRoot 'native-refs-boot-evidence.json'
    [IO.File]::WriteAllText($guestEvidencePath, [string]$envelope.json, $encoding)
    if ((Get-FileHash -LiteralPath $guestEvidencePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $envelope.sha256) { throw 'Guest evidence export hash mismatch; VM will be preserved.' }
    $evidence = Read-ControlJson $guestEvidencePath 2MB
    if ($evidence.phase -cne 'native-refs-os-single-boot-observation' -or $evidence.runId -cne $runId -or -not $evidence.nativeRefsBootObserved -or $evidence.fullQualificationPassed -or $evidence.conversionVerified -or $evidence.osFileSystem -cne 'ReFS' -or $evidence.windowsBuild -cne '26300.9457' -or [string]$evidence.bootDisk.UniqueId -cne [string]$targetRecord.uniqueId -or -not ($evidence.bootDisk.IsBoot -and $evidence.bootDisk.IsSystem) -or $evidence.marker.purpose -cne 'native-refs-os-control' -or $evidence.marker.targetUniqueId -cne $targetRecord.uniqueId) { throw 'Exported native boot identity evidence is inconsistent.' }
    $record.guestEvidence = [ordered]@{ path = $guestEvidencePath; sha256 = $envelope.sha256; length = $envelope.length; guestPath = $envelope.guestPath }
    $record.nativeRefsBootObserved = $true; $record.evidenceExported = $true
    $record.status = 'evidence-exported'; Write-BootHostRecord
    try { Invoke-BoundedBootCommand -TimeoutSeconds 15 -ScriptBlock { & shutdown.exe /s /t 0; if ($LASTEXITCODE -ne 0) { throw 'Guest clean shutdown request failed.' } } | Out-Null }
    catch { $record['shutdownTransportStatus'] = 'Shutdown request lost transport or failed; waiting for actual Off state without force.' }
    $shutdownDeadline = [DateTime]::UtcNow.AddSeconds(180)
    do {
        $vm = Get-VM -Id ([guid]$manifest.vmId)
        if ($vm.State -eq 'Off') { break }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $shutdownDeadline)
    if ($vm.State -ne 'Off') { throw 'VM did not reach Off after guest shutdown; no checkpoint or baseline restore attempted.' }
    $record.cleanShutdown = $true
    Get-OwnedLabVM -Configuration $configuration -Manifest $manifest | Out-Null
    $observationName = 'refs-os-observed-' + $runId
    Invoke-LabAction -Action Checkpoint -Lane $Lane -CheckpointName $observationName -Confirm:$false | Out-Null
    $observation = Get-ExactLabCheckpoint -VM (Get-OwnedLabVM -Configuration $configuration -Manifest $manifest) -Name $observationName
    $record.observationCheckpoint = $observationName; $record.observationCheckpointId = [string]$observation.Id
    $record.status = 'observed-checkpoint-retained'; Write-BootHostRecord
    if (-not $record.evidenceExported -or (Get-FileHash -LiteralPath $guestEvidencePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $record.guestEvidence.sha256) { throw 'Verified evidence must remain available before baseline restore.' }
    $baseline = Assert-ControlCheckpoint 'installed-clean' ([guid]$record.baselineId)
    Restore-VMCheckpoint -VMSnapshot $baseline -Confirm:$false
    $restored = Get-OwnedLabVM -Configuration $configuration -Manifest $manifest
    if ($restored.State -ne 'Off' -or (Get-VMFirmware -VM $restored).SecureBoot -ne 'On') { throw 'Baseline restore did not leave the expected off/Secure Boot state.' }
    $record.baselineRestored = $true; $record.status = 'complete-single-boot-observation'
} catch {
    $record.status = 'failed-preserved-for-review'; $record.error = $_.Exception.Message
    Write-BootHostRecord
    try { $record.diagnostics = & (Join-Path $PSScriptRoot 'Get-LabBootDiagnostics.ps1') -Lane $Lane -Confirm:$false }
    catch { $record['diagnosticsError'] = $_.Exception.Message }
    # Never force shutdown or restore a failed/unexported experiment.
    throw
} finally {
    Write-BootHostRecord
    $credential = $null
}
[pscustomobject]@{ Status = $record.status; Evidence = $outputRoot; NativeRefsBootObserved = $record.nativeRefsBootObserved; FullQualificationPassed = $false; ConversionVerified = $false; ObservationCheckpoint = $record.observationCheckpoint; BaselineRestored = $record.baselineRestored }
