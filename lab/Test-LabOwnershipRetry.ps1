<# Full ownership revalidation with mock Hyper-V responses; no VM/disk access. #>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Lab.psm1'),[ref]$null,[ref]$null)
foreach ($name in @('Assert-LabPath','Assert-LabOwnership','Get-OwnedLabVM')) {
    $definition = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false)
    Invoke-Expression $definition.Extent.Text
}
$configuration = [pscustomobject]@{Root='D:\n2r-mock'}
$manifest = [pscustomobject]@{vmId='12345678-1234-1234-1234-123456789abc';vmName='mock-vm';vmPath='D:\n2r-mock\vm';disks=@([pscustomobject]@{role='os';path='D:\n2r-mock\disks\os.vhdx';vhdId='11111111-1111-1111-1111-111111111111';sizeBytes=64GB;controllerLocation=0})}
function Get-VM {
    param($Id,$ErrorAction)
    $script:vmReads++
    $idValue = if ($script:mode -ceq 'foreign-vm') { '99999999-9999-9999-9999-999999999999' } else { $manifest.vmId }
    [pscustomobject]@{Id=$idValue;Name=$manifest.vmName;Generation=2;Path=$manifest.vmPath;State='Off'}
}
function Get-VMHardDiskDrive {
    param($VM)
    $path = 'D:\n2r-mock\disks\live.avhdx'
    if (($script:mode -ceq 'delayed' -and $script:vmReads -lt 3) -or $script:mode -ceq 'missing-leaf') { $path='D:\n2r-mock\disks\stale.avhdx' }
    if ($script:mode -ceq 'missing-base') { $path=$manifest.disks[0].path }
    if ($script:mode -ceq 'foreign-path') { $path='D:\outside\stale.avhdx' }
    [pscustomobject]@{Path=$path;ControllerNumber=0;ControllerLocation=0}
    if ($script:mode -ceq 'extra-attachment') { [pscustomobject]@{Path=$path;ControllerNumber=0;ControllerLocation=1} }
}
function Get-VHD {
    param($Path,$ErrorAction)
    $script:vhdReads++
    if ($Path.EndsWith('stale.avhdx') -or $script:mode -ceq 'missing-base') { throw 'Mock missing VHD.' }
    if ($script:mode -ceq 'provider-error') { throw 'Mock access denied.' }
    if ($Path.EndsWith('live.avhdx')) { return [pscustomobject]@{ParentPath=$manifest.disks[0].path} }
    $idValue = if ($script:mode -ceq 'wrong-vhd-id') { '22222222-2222-2222-2222-222222222222' } else { $manifest.disks[0].vhdId }
    [pscustomobject]@{ParentPath=$null;DiskIdentifier=$idValue;Size=64GB}
}
function Test-Path { param($LiteralPath,$PathType,$ErrorAction) $LiteralPath.EndsWith('live.avhdx') -or $LiteralPath.EndsWith('os.vhdx') }
function Get-Item { param($LiteralPath,[switch]$Force) [pscustomobject]@{Attributes=[IO.FileAttributes]::Normal} }
function Start-Sleep { param($Milliseconds) $script:sleeps++ }
$checks=0
$script:mode='delayed'; $script:vmReads=0; $script:vhdReads=0; $script:sleeps=0
$vm=Get-OwnedLabVM $configuration $manifest -Attempts 4
if ($vm.Id -ne $manifest.vmId -or $script:vmReads -ne 3 -or $script:sleeps -ne 2) { throw 'Transient missing AVHDX did not trigger full fresh ownership revalidation.' }
$checks++
foreach ($mode in @('missing-leaf','missing-base','provider-error','foreign-vm','foreign-path','wrong-vhd-id','extra-attachment')) {
    $script:mode=$mode; $script:vmReads=0; $script:vhdReads=0; $script:sleeps=0
    $rejected=$false
    try { Get-OwnedLabVM $configuration $manifest -Attempts 3 | Out-Null } catch { $rejected=$true }
    $expectedReads=if($mode -ceq 'missing-leaf'){3}else{1}
    if (-not $rejected -or $script:vmReads -ne $expectedReads -or $script:sleeps -ne ($expectedReads-1)) { throw "Unexpected ownership retry behavior for $mode." }
    $checks++
}
"Passed $checks full ownership retry fixtures; all Hyper-V and sleep commands were mocked."
