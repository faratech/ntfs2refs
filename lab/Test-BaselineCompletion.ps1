<# Mocked checkpoint lookup and narrow recovery evidence checks only. #>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
$script:checks = 0
function Assert-Check([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message }; $script:checks++ }
function Expect-Rejection([scriptblock]$Action) { $rejected = $false; try { & $Action | Out-Null } catch { $rejected = $true }; Assert-Check $rejected 'Expected refusal did not occur.' }
foreach ($definition in @(@{path='lab\Lab.psm1';name='Get-ExactLabCheckpoint'},@{path='scripts\Complete-LabBaseline.ps1';name='Assert-BaselineCompletionEvidence'},@{path='scripts\Complete-LabBaseline.ps1';name='Assert-RecordedBaselineExport'},@{path='scripts\Complete-LabBaseline.ps1';name='Assert-RecordedInventoryFailure'})) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $workspace $definition.path),[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw 'Parser error in baseline recovery source.' }
    $function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $definition.name },$false)
    Invoke-Expression $function.Extent.Text
}
$script:checkpoint = [pscustomobject]@{ Name = 'installed-clean'; Id = 'eda059b3-6d50-46bb-bdf4-018b99b5b34f' }
function Get-VMCheckpoint {
    param($VM,$ErrorAction)
    $script:calls++
    switch ($script:mode) {
        'delayed' { if ($script:calls -ge 3) { $script:checkpoint } }
        'duplicate' { $script:checkpoint; $script:checkpoint }
        'missing' { }
        'different-case' { [pscustomobject]@{Name='Installed-Clean';Id='other'} }
        'provider-error' { throw 'Mock provider failure.' }
    }
}
function Start-Sleep { param($Milliseconds) $script:sleeps++ }
$script:mode = 'delayed'; $script:calls = 0; $script:sleeps = 0
$found = Get-ExactLabCheckpoint -VM mock -Name installed-clean -Attempts 4
Assert-Check ($found.Id -ceq $script:checkpoint.Id -and $script:calls -eq 3 -and $script:sleeps -eq 2) 'Delayed exact checkpoint was not found with bounded zero-result retries.'
foreach ($mode in @('duplicate','provider-error','missing','different-case')) {
    $script:mode = $mode; $script:calls = 0; $script:sleeps = 0
    Expect-Rejection { Get-ExactLabCheckpoint -VM mock -Name installed-clean -Attempts 3 }
    $expectedCalls = if ($mode -in @('duplicate','provider-error')) { 1 } else { 3 }
    Assert-Check ($script:calls -eq $expectedCalls -and $script:sleeps -eq ($expectedCalls - 1)) 'Nonempty/error results must not be retried; empty retries must be bounded.'
}
$manifest = [pscustomobject]@{ vmId='mock-vm'; vmName='ntfs2refs-win11'; disks=@([pscustomobject]@{role='os';path='D:\n2r-mock\disks\os.vhdx'}) }
$validState = [pscustomobject]@{ schemaVersion=1; stage='failed'; detail='The exact checkpoint name must identify one checkpoint.'; vmId='mock-vm'; updatedUtc='2026-10-23T20:34:47.4423693Z' }
$validEvidence = [pscustomobject]@{
    schemaVersion=1; phase='native-ntfs-first-boot'; computerName='N2R-WIN11'; PSComputerName='ntfs2refs-win11'; windowsBuild='26300.9457'; edition='Professional'; osFileSystem='NTFS'; nativeNtfsControlPassed=$true; failures=@(); bitLockerVolumeStatus='FullyDecrypted'; encryptionPercentage=0; hibernationDisabled=$true; filesystemHealth='NoErrorsFound'; winreEnabled=$true; refsBootVerified=$false; dataDisksModified=$false; capturedUtc='2026-10-23T20:34:33.1676748Z'
    disks=@(
        [pscustomobject]@{IsBoot=$true;IsSystem=$true;PartitionStyle='GPT';Size=64GB;IsOffline=$false;IsReadOnly=$false}
        [pscustomobject]@{IsBoot=$false;IsSystem=$false;PartitionStyle='RAW';Size=64GB;IsOffline=$false;IsReadOnly=$false}
        [pscustomobject]@{IsBoot=$false;IsSystem=$false;PartitionStyle='RAW';Size=8GB;IsOffline=$false;IsReadOnly=$false}
    )
}
Assert-BaselineCompletionEvidence $validState $validEvidence $manifest $script:checkpoint
$script:checks++
foreach ($case in @('other-error','different-attempt','wrong-vm','wrong-checkpoint','failed-native','disabled-winre','changed-data','formatted-data','wrong-build','other-evidence')) {
    $state = $validState | ConvertTo-Json -Depth 6 | ConvertFrom-Json
    $evidence = $validEvidence | ConvertTo-Json -Depth 6 | ConvertFrom-Json
    $caseCheckpoint = $script:checkpoint | ConvertTo-Json | ConvertFrom-Json
    switch ($case) {
        'other-error' { $state.detail='Other failure.' }
        'different-attempt' { $state.updatedUtc='2026-10-23T21:00:00Z' }
        'wrong-vm' { $state.vmId='other-vm' }
        'wrong-checkpoint' { $caseCheckpoint.Id='other-id' }
        'failed-native' { $evidence.nativeNtfsControlPassed=$false }
        'disabled-winre' { $evidence.winreEnabled=$false }
        'changed-data' { $evidence.dataDisksModified=$true }
        'formatted-data' { $evidence.disks[1].PartitionStyle='GPT' }
        'wrong-build' { $evidence.windowsBuild='26300.9999' }
        'other-evidence' { $evidence.capturedUtc='2026-10-23T21:00:00Z' }
    }
    Expect-Rejection { Assert-BaselineCompletionEvidence $state $evidence $manifest $caseCheckpoint }
}
$postState = $validState | ConvertTo-Json | ConvertFrom-Json
$postState.updatedUtc = '2026-10-23T20:40:22.8089573Z'
$postState.detail = "'D:\n2r-mock\disks\os_7D4A0C97-1E6D-4D37-9EED-2C5E2122028A.avhdx' is not an existing virtual hard disk file."
Assert-BaselineCompletionEvidence $postState $validEvidence $manifest $script:checkpoint
$script:checks++
$exportHash = '2c7fc107bd63e918228671e3b57cf87891552c93023bda7e13faee2d471b1c12'
$exportPath = 'D:\n2r-mock\exports\win11-installed-clean'
$validCompletion = [pscustomobject]@{schemaVersion=1;vmId='mock-vm';checkpointId=$script:checkpoint.Id;status='failed';exported=$true;restoreVerified=$false;exportPath=$exportPath;error=$postState.detail;startedUtc='2026-10-23T20:40:18.5211797Z';evidenceSha256=$exportHash}
Assert-RecordedBaselineExport $validCompletion $postState $manifest $exportPath $exportHash
$script:checks++
foreach ($case in @('wrong-hash','not-exported','wrong-vm','different-error','different-destination','different-attempt')) {
    $completion = $validCompletion | ConvertTo-Json | ConvertFrom-Json
    switch ($case) {
        'wrong-hash' { $completion.evidenceSha256='0' * 64 }
        'not-exported' { $completion.exported=$false }
        'wrong-vm' { $completion.vmId='other-vm' }
        'different-error' { $completion.error='Other error.' }
        'different-destination' { $completion.exportPath='D:\other-export' }
        'different-attempt' { $completion.startedUtc='2026-10-23T21:00:00Z' }
    }
    Expect-Rejection { Assert-RecordedBaselineExport $completion $postState $manifest $exportPath $exportHash }
}
$inventoryState = $postState | ConvertTo-Json | ConvertFrom-Json
$inventoryState.updatedUtc = '2026-10-23T20:46:21.4557512Z'
$inventoryState.detail = 'Existing export inventory or configuration identity changed.'
Assert-BaselineCompletionEvidence $inventoryState $validEvidence $manifest $script:checkpoint
$script:checks++
$inventoryCompletion = [pscustomobject]@{schemaVersion=1;vmId='mock-vm';checkpointId=$script:checkpoint.Id;status='failed';reusedExport=$true;exported=$false;restoreVerified=$false;exportPath=$exportPath;error=$inventoryState.detail;startedUtc='2026-10-23T20:46:21.4394716Z';evidenceSha256=$exportHash}
Assert-RecordedInventoryFailure $inventoryCompletion $inventoryState $manifest $exportPath $exportHash
$script:checks++
$inventoryCompletion.reusedExport=$false
Expect-Rejection { Assert-RecordedInventoryFailure $inventoryCompletion $inventoryState $manifest $exportPath $exportHash }
$inventoryCompletion.reusedExport=$true; $inventoryCompletion.evidenceSha256='0' * 64
Expect-Rejection { Assert-RecordedInventoryFailure $inventoryCompletion $inventoryState $manifest $exportPath $exportHash }
# Execute the two real source assignments against a six-entry JSON file. This
# exercises Windows PowerShell 5 pipeline semantics rather than mocked arrays.
$recoveryAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $workspace 'scripts\Complete-LabBaseline.ps1'),[ref]$null,[ref]$null)
$parseAssignment = $recoveryAst.Find({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq '$parsedInventory'},$true)
$collectAssignment = $recoveryAst.Find({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Extent.Text -ceq '$previousInventory = @($parsedInventory)'},$true)
if (-not $parseAssignment -or -not $collectAssignment) { throw 'Missing explicit parsed-inventory normalization.' }
$previousArchive = Join-Path $workspace ('.lab\tests\baseline-json-array-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $previousArchive | Out-Null
$rows = @(1..6 | ForEach-Object { [pscustomobject]@{relativePath=('file-' + $_);length=$_} })
ConvertTo-Json -InputObject $rows | Set-Content -LiteralPath (Join-Path $previousArchive 'exported-files.json') -Encoding UTF8
Invoke-Expression $parseAssignment.Extent.Text
Invoke-Expression $collectAssignment.Extent.Text
Assert-Check ($previousInventory.Count -eq 6 -and $previousInventory[0].relativePath -ceq 'file-1' -and $previousInventory[5].relativePath -ceq 'file-6') 'JSON inventory must expose six records, not one nested array.'
if ($PSVersionTable.PSVersion.Major -eq 5) {
    $oldWrapped = @(Get-Content -LiteralPath (Join-Path $previousArchive 'exported-files.json') -Raw | ConvertFrom-Json)
    Assert-Check ($oldWrapped.Count -eq 1 -and $oldWrapped[0] -is [array]) 'Windows PowerShell 5 regression did not exercise its nested pipeline-array behavior.'
}
"Passed $script:checks baseline recovery guard checks; no VM calls or sleeps executed."
