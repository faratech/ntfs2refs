<# Ordinary local files and mocked transport only; no session/VM calls. #>
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$moduleAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'NativeControlExport.psm1'),[ref]$null,[ref]$null)
$node=$moduleAst.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Test-ControlCaptureExport'},$false)
Invoke-Expression $node.Extent.Text
$exportDefinition=$moduleAst.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Export-LabNativeControlArtifacts'},$false)
$exportBody=[scriptblock]::Create((@($exportDefinition.Body.EndBlock.Statements | ForEach-Object {$_.Extent.Text}) -join [Environment]::NewLine))
$testRoot=Join-Path $workspace ('.lab\tests\native-export-' + [guid]::NewGuid().ToString('N'))
$fixtureManifest=Join-Path $testRoot 'source-manifests';$fixtureCapture=Join-Path $testRoot 'source-captures'
New-Item -ItemType Directory -Path $fixtureManifest,$fixtureCapture | Out-Null
foreach($name in @('target.json','journal.json','result.json')){'{}'|Set-Content -LiteralPath (Join-Path $fixtureManifest $name) -Encoding UTF8}
[IO.File]::WriteAllBytes((Join-Path $fixtureCapture 'empty.raw'),[byte[]](0..255))
$script:checks=0
function Check([bool]$Value,[string]$Message){if(-not $Value){throw $Message};$script:checks++}
function Reject([scriptblock]$Action){$rejected=$false;try{& $Action|Out-Null}catch{$rejected=$true};Check $rejected 'Expected refusal did not occur.'}
# Run the installed PS5 remote helper's metadata branch locally, unchanged.
$copyType=[psobject].Assembly.GetType('System.Management.Automation.Internal.CopyFileRemoteUtils')
$copySource=$copyType.GetField('AllCopyFromRemoteScripts',[Reflection.BindingFlags]'NonPublic,Public,Static').GetValue($null)
Invoke-Expression $copySource
$directoryFailed=$false
try{PSCopyFromSessionHelper -getPathItems $fixtureManifest|Out-Null}catch{$directoryFailed=$_.Exception.Message -like '*Length*'}
Check $directoryFailed 'Installed helper did not reproduce the directory Length failure.'
$fileResult=PSCopyFromSessionHelper -getPathItems (Join-Path $fixtureManifest 'target.json')
Check ($fileResult.Exists -and @($fileResult.Items).Count -eq 1 -and -not $fileResult.Items[0].IsDirectory) 'Installed helper must accept an ordinary file under StrictMode.'
function Invoke-Command {param($Session,$ArgumentList,$ErrorAction,[scriptblock]$ScriptBlock); & $ScriptBlock $fixtureManifest $fixtureCapture}
function Copy-Item {
    param($LiteralPath,$Destination,$FromSession,$ErrorAction)
    $script:copies++
    $sourceRoot=if($LiteralPath.StartsWith('C:\ntfs2refs\control-ntfs\')){$fixtureManifest}elseif($LiteralPath.StartsWith('E:\native-control\')){$fixtureCapture}else{throw 'Unexpected mock source.'}
    [IO.File]::Copy((Join-Path $sourceRoot ([IO.Path]::GetFileName($LiteralPath))),$Destination,$false)
    if($script:corrupt){[IO.File]::AppendAllText($Destination,'tamper')}
}
$Session=[pscustomobject]@{State='Opened'}
$ManifestDirectory='C:\ntfs2refs\control-ntfs';$CaptureDirectory='E:\native-control';$LabRoot=Join-Path $workspace '.lab'
$Report=[pscustomobject]@{filesystem='NTFS';captureComplete=$false}
$Destination=Join-Path $testRoot 'good-export';New-Item -ItemType Directory -Path $Destination|Out-Null
$script:copies=0;$script:corrupt=$false
$result=& $exportBody
Check ($result.fileCount -eq 4 -and -not $result.captureValidated -and $script:copies -eq 4) 'Per-file export did not copy exactly the expected artifacts.'
$script:copies=0
Reject {& $exportBody}
Check ($script:copies -eq 0) 'Existing destination must refuse before copying.'
$Destination=Join-Path $testRoot 'corrupt-export';New-Item -ItemType Directory -Path $Destination|Out-Null
$script:copies=0;$script:corrupt=$true
Reject {& $exportBody}
Check (-not (Test-Path -LiteralPath (Join-Path $Destination 'exported-files.json'))) 'Corrupt transport wrote a success inventory.'
$Destination=Join-Path $testRoot 'unexpected-export';New-Item -ItemType Directory -Path $Destination|Out-Null
$script:copies=0;$script:corrupt=$false
New-Item -ItemType Directory -Path (Join-Path $fixtureCapture 'unexpected-directory')|Out-Null
Reject {& $exportBody}
Check ($script:copies -eq 0) 'Unexpected directory must be rejected before copying.'
$recoveryAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $workspace 'scripts\Recover-LabNativeControlExport.ps1'),[ref]$null,[ref]$null)
$guard=$recoveryAst.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-NativeExportRecovery'},$false)
Invoke-Expression $guard.Extent.Text
$caseRoot=Join-Path $workspace '.lab\hyperv\corpus\win11-20261023T211635519Z\ntfs'
$validFailure=Get-Content -LiteralPath (Join-Path $caseRoot 'failure.json') -Raw|ConvertFrom-Json
$validReport=Get-Content -LiteralPath (Join-Path $caseRoot 'guest-result.json') -Raw|ConvertFrom-Json
$validManifest=Get-Content -LiteralPath (Join-Path $workspace '.lab\hyperv\win11\manifest.json') -Raw|ConvertFrom-Json
$validCheckpoint=[pscustomobject]@{Name='installed-clean';Id='eda059b3-6d50-46bb-bdf4-018b99b5b34f'}
Assert-NativeExportRecovery $validFailure $validReport $validManifest $validCheckpoint
$script:checks++
foreach($case in @('wrong-vm','wrong-checkpoint','wrong-target','wrong-journal','wrong-hash','wrong-offset','incomplete','other-failure','already-exported')) {
    $failure=$validFailure|ConvertTo-Json -Depth 12|ConvertFrom-Json
    $report=$validReport|ConvertTo-Json -Depth 12|ConvertFrom-Json
    $manifest=$validManifest|ConvertTo-Json -Depth 12|ConvertFrom-Json
    $checkpoint=$validCheckpoint|ConvertTo-Json|ConvertFrom-Json
    switch($case){
        'wrong-vm'{$manifest.vmId='00000000-0000-0000-0000-000000000000'}
        'wrong-checkpoint'{$checkpoint.Id='00000000-0000-0000-0000-000000000000'}
        'wrong-target'{$report.target.uniqueId='other'}
        'wrong-journal'{$report.journal.hostVhdId='other'}
        'wrong-hash'{$report.image.sha256='0'*64}
        'wrong-offset'{$report.image.partitionOffset=1MB}
        'incomplete'{$report.captureComplete=$false}
        'other-failure'{$failure.observedUtc='2026-10-23T21:18:00Z'}
        'already-exported'{$failure.exported=$true}
    }
    Reject {Assert-NativeExportRecovery $failure $report $manifest $checkpoint}
}
"Passed $script:checks native-control export/recovery fixtures; transport and VM operations were mocked."
