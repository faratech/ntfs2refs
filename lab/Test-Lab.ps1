$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$script:passed = 0
function Test-Case([string]$Name, [scriptblock]$Body) {
    & $Body
    $script:passed++
    Write-Output "PASS $Name"
}
function Expect-Failure([scriptblock]$Body) {
    $failed = $false
    try { & $Body | Out-Null } catch { $failed = $true }
    if (-not $failed) { throw 'Expected refusal did not occur.' }
}
$workspace = Split-Path $PSScriptRoot -Parent
$configuration = Get-LabConfiguration $workspace
Test-Case 'Reject traversal out of lab' { Expect-Failure { Assert-LabPath (Join-Path $configuration.Root '..\outside') $configuration.Root } }
Test-Case 'Reject lab root itself' { Expect-Failure { Assert-LabPath $configuration.Root $configuration.Root } }
Test-Case 'Reject sibling prefix confusion' { Expect-Failure { Assert-LabPath ($configuration.Root + '-other\x') $configuration.Root } }
Test-Case 'Accept bounded child' { Assert-LabPath (Join-Path $configuration.Root 'win11\disk.vhdx') $configuration.Root | Out-Null }
Test-Case 'Enforce free-space reserve' { Expect-Failure { Assert-LabCapacity ([pscustomobject]@{ ActualBytes=10; FreeBytes=20; MaximumActualBytes=100; MinimumFreeBytes=15 }) 6 } }
Test-Case 'Enforce actual lab budget' { Expect-Failure { Assert-LabCapacity ([pscustomobject]@{ ActualBytes=90; FreeBytes=100; MaximumActualBytes=100; MinimumFreeBytes=15 }) 11 } }
Test-Case 'Accept exactly bounded capacity' { Assert-LabCapacity ([pscustomobject]@{ ActualBytes=90; FreeBytes=25; MaximumActualBytes=100; MinimumFreeBytes=15 }) 10 }
$diskPath = Join-Path $configuration.Root 'win11\os.vhdx'
$vmPath = Join-Path $configuration.Root 'win11'
$manifest = [pscustomobject]@{vmId='123';vmName='ntfs2refs-win11';vmPath=$vmPath;disks=@([pscustomobject]@{role='os';path=$diskPath;controllerLocation=0})}
$vm = [pscustomobject]@{Id='123';Name='ntfs2refs-win11';Generation=2;Path=$vmPath}
$drives = @([pscustomobject]@{Path=$diskPath;ControllerNumber=0;ControllerLocation=0})
Test-Case 'Accept exact VM ownership' { Assert-LabOwnership $manifest $vm $drives }
Test-Case 'Refuse VM name collision with foreign ID' { $foreign = [pscustomobject]@{Id='456';Name='ntfs2refs-win11';Generation=2;Path=$vmPath}; Expect-Failure { Assert-LabOwnership $manifest $foreign $drives } }
Test-Case 'Refuse extra attached disk' { Expect-Failure { Assert-LabOwnership $manifest $vm ($drives + $drives) } }
Test-Case 'Refuse changed disk attachment' { $foreign = @([pscustomobject]@{Path='C:\foreign.vhdx';ControllerNumber=0;ControllerLocation=0}); Expect-Failure { Assert-LabOwnership $manifest $vm $foreign } }
Test-Case 'Require exact restore name' { Expect-Failure { Invoke-LabAction -Action Restore -WhatIf } }
Test-Case 'Reject checkpoint path injection' { Expect-Failure { Invoke-LabAction -Action Checkpoint -CheckpointName '..\x' -WhatIf } }
Test-Case 'WhatIf needs no Hyper-V access or write' {
    $before = Test-Path -LiteralPath $configuration.Root
    $result = Invoke-LabAction -Action Checkpoint -Lane win11 -CheckpointName 'test-point' -WhatIf
    if (-not $result.DryRun -or $before -ne (Test-Path -LiteralPath $configuration.Root)) { throw 'Dry run changed the filesystem or failed to return a plan.' }
}
$installerAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $workspace 'scripts\Install-LabWindows.ps1'), [ref]$null, [ref]$null)
$recoveryFunction = $installerAst.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-InstallRecoveryPartition' }, $true)
if (-not $recoveryFunction) { throw 'Missing recovery-partition verifier.' }
# Load only the pure verifier; never execute the installer during guard tests.
. ([scriptblock]::Create($recoveryFunction.Extent.Text))
$recoveryPartition = [pscustomobject]@{ GptType='{de94bba4-06d1-4d40-a16a-bfd50179d6ac}'; Size=2GB; Offset=66569895936; NoDefaultDriveLetter=$null }
$recoveryDetail = "Type    : de94bba4-06d1-4d40-a16a-bfd50179d6ac`r`nAttrib  : 0X8000000000000001`r`nOffset in Bytes: 66569895936`r`n"
Test-Case 'Accept native recovery flags with nullable Storage property' {
    if (-not (Test-InstallRecoveryPartition $recoveryPartition $recoveryDetail)) { throw 'Valid recovery partition rejected.' }
}
Test-Case 'Reject wrong recovery GPT flags' {
    if (Test-InstallRecoveryPartition $recoveryPartition $recoveryDetail.Replace('8000000000000001','0000000000000001')) { throw 'Wrong flags accepted.' }
}
Test-Case 'Reject wrong recovery partition offset' {
    if (Test-InstallRecoveryPartition $recoveryPartition $recoveryDetail.Replace('66569895936','66569895937')) { throw 'Wrong partition offset accepted.' }
}
Test-Case 'Reject wrong recovery partition type' {
    if (Test-InstallRecoveryPartition $recoveryPartition $recoveryDetail.Replace('de94bba4','00000000')) { throw 'Wrong partition type accepted.' }
}
Test-Case 'Parse every lab PowerShell script' {
    $files = @(Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -File | Where-Object { $_.Extension -in '.ps1','.psm1' }) + @(Get-ChildItem -LiteralPath (Join-Path $workspace 'scripts') -File -Filter '*.ps1')
    foreach ($file in $files) {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$errors) | Out-Null
        if ($errors.Count) { throw "$($file.Name): $($errors[0].Message)" }
    }
}
"$script:passed lab guard tests passed. No VM or disk was modified."
