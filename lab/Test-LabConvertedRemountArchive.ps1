<# Actual completed observation/archive regression; ordinary files only. #>
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$script:checks=0
$workspace=Split-Path -Parent $PSScriptRoot
function Check([bool]$Value,[string]$Name){if(-not$Value){throw $Name};$script:checks++}
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $workspace 'scripts/Invoke-LabConvertedVerification.ps1'),[ref]$tokens,[ref]$errors)
Check ($errors.Count-eq0) 'Source parse failed.'
foreach($f in $ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($f.Extent.Text))}
$root=Join-Path $workspace '.lab/hyperv/converted-verification/win11-20261024T061408952Z'
$proof=Read-CVJson (Join-Path $root 'host-result.json') 'ea53249c0f49be778a25cfa3aa2f7e3377ece25a874fc5c04e5ccc13dd40ac13'
Check ($proof.status-ceq'retained-A-observed-readonly-checkpointed') 'Completed observation status differs.'
$recorded=Get-CVRecordedReview $proof
$archivePath=Join-Path $root 'reviewed-source-manifest.json';$archiveHash=(Get-FileHash -LiteralPath $archivePath).Hash.ToLowerInvariant()
Check ($archiveHash-cne$proof.reviewedSourcesSha256) 'Regression must exercise different serialized manifest bytes.'
$archive=Read-CVJson $archivePath $archiveHash 64KB;Assert-CVReviewed $archive
foreach($entry in $recorded.files){
 $other=@($archive.files|Where-Object path -CEQ $entry.path);Check ($other.Count-eq1-and$other[0].sha256-ceq$entry.sha256) 'Reserialized manifest changed source semantics.'
 $name=[IO.Path]::GetFileName($entry.path);$pinned=@($proof.sourceHashes|Where-Object name -CEQ $name)
 $bytes=Read-CVBytes (Join-Path $root ('reviewed-sources/'+$name)) $entry.sha256 256KB
 Check ($pinned.Count-eq1-and$bytes.Length-eq$pinned[0].length) 'Completed host pin did not authenticate source bytes.'
}
Check ((Get-FileHash -LiteralPath (Join-Path $root 'host-result.json')).Hash.ToLowerInvariant()-ceq'ea53249c0f49be778a25cfa3aa2f7e3377ece25a874fc5c04e5ccc13dd40ac13') 'Original completed record changed.'
Write-Output ('PASS: '+$script:checks+' completed remount-source archive checks; no VM/device calls or writes.')
