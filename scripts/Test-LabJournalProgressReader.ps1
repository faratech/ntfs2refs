<# Extract and test only the best-effort reader. No lab import, Hyper-V,
   collector execution, fixture disk, cleanup or security change. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$errors=$null;$tokens=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Collect-LabAdmittedConversion.ps1'),[ref]$tokens,[ref]$errors)
if($errors){throw ($errors|Out-String)}
$functions=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq'Read-JournalProgress'},$true))
if($functions.Count-ne1){throw 'One bounded progress reader required.'}
. ([scriptblock]::Create($functions[0].Extent.Text))
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('n2r-journal-progress-reader-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary|Out-Null
$checks=0;$partition=52GB;$total=4*$partition
function Write-Case([string]$Name,[string]$Text){$p=Join-Path $temporary ($Name+'.json');[IO.File]::WriteAllText($p,$Text,[Text.UTF8Encoding]::new($false));$p}
function Check([bool]$Good,[string]$Message){if(-not$Good){throw $Message};$script:checks++}
function Report([string]$Phase,[string]$Scanned='0',[string]$Elapsed='1000'){'{"schema_version":1,"kind":"journal-preparation-progress","subphase":"'+$Phase+'","bytes_scanned":'+$Scanned+',"total_scan_bytes":'+$total+',"elapsed_ms":'+$Elapsed+',"execution_authorized":false}'}
foreach($phase in @('comparing','rechecking-source','rechecking-shadow','writing-journal','verifying-journal','complete')){
 $text=Report $phase ([string]$total);$value=Read-JournalProgress (Write-Case $phase $text) $partition
 Check ($null-ne$value-and$value.subphase-ceq$phase-and$value.bytes_scanned-eq$total-and$value.total_scan_bytes-eq$total-and$value.diagnosticOnly-and-not$value.execution_authorized) ('Valid diagnostic phase refused: '+$phase)
}
$valid=Report 'comparing' '4096'
$cases=[ordered]@{
 partial='{"schema_version":';scalar='1';array='[]';empty='';oversized=(' '*4097);
 unknownPhase=(Report 'unknown');quotedCounter=(Report 'comparing' '"4096"');negative=(Report 'comparing' '-1');
 decimal=(Report 'comparing' '1.0');exponent=(Report 'comparing' '1e3');leadingZero=(Report 'comparing' '01');
 boolCounter=(Report 'comparing' 'false');arrayCounter=(Report 'comparing' '[]');objectCounter=(Report 'comparing' '{}');
 tooFar=(Report 'comparing' ([string]($total+1)));wrongTotal=$valid.Replace(('"total_scan_bytes":'+$total),'"total_scan_bytes":1');
 wrongSchema=$valid.Replace('"schema_version":1','"schema_version":2');authority=$valid.Replace('"execution_authorized":false','"execution_authorized":true');
 unknownKey=$valid.Replace('"elapsed_ms":1000','"extra":1000');duplicate=$valid.Replace('"elapsed_ms":1000','"bytes_scanned":1000');
 escapedKey=$valid.Replace('"elapsed_ms"','"elapsed\u005fms"');overflowElapsed=(Report 'comparing' '4096' '18446744073709551616');
 quotedElapsed=(Report 'comparing' '4096' '"1000"');wrongKind=$valid.Replace('journal-preparation-progress','journal-preparation-other')
}
foreach($name in $cases.Keys){$value=Read-JournalProgress (Write-Case $name $cases[$name]) $partition;Check ($null-eq$value) ('Malformed telemetry accepted: '+$name)}
Check ($null-eq(Read-JournalProgress (Join-Path $temporary 'missing-old-binary.json') $partition)) 'Missing sidecar must be ignored.'
Check ($null-eq(Read-JournalProgress $temporary $partition)) 'Directory must not be read.'
$validPath=Write-Case 'valid' $valid
foreach($length in @(0,4095,[long]::MaxValue)){Check ($null-eq(Read-JournalProgress $validPath $length)) 'Invalid partition scan domain accepted.'}
$invalidUtf8=Join-Path $temporary 'invalid-utf8.json';[IO.File]::WriteAllBytes($invalidUtf8,[byte[]]@(255,254,255))
Check ($null-eq(Read-JournalProgress $invalidUtf8 $partition)) 'Invalid UTF8 must be ignored.'
& {
 function Get-Item {param([string]$LiteralPath,[switch]$Force,$ErrorAction)[pscustomobject]@{PSIsContainer=$false;Attributes=[IO.FileAttributes]::ReparsePoint;Length=1;LastWriteTimeUtc=[DateTime]::UtcNow}}
 Check ($null-eq(Read-JournalProgress $validPath $partition)) 'Reparse metadata must be refused before opening.'
}
[pscustomobject]@{checks=$checks;syntaxValid=$true;vmOperations=0;diskFixtures=0;temporarySourceFiles=$temporary;cleanupAttempted=$false}
