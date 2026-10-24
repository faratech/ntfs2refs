<# Exercise the extracted native-process wrapper with harmless PowerShell output,
   EOF and timeout fixtures, plus format.com /? (help only). No disk or VM calls. #>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspace = Split-Path $PSScriptRoot -Parent
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'guest\Prepare-NativeRefsOS.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Guest preparer failed parsing.' }
$definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-ControlNative' }, $false)
. ([scriptblock]::Create($definition.Extent.Text))
function Get-ControlDisk { [pscustomobject]@{ Number = 1 } }
$runRoot = Join-Path $workspace ('.lab\tests\refs-native-process-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runRoot | Out-Null
$nativePath = Join-Path $PSHOME 'powershell.exe'
$record = [ordered]@{ tools = @{ 'fixture.exe' = [pscustomobject]@{ path = $nativePath; sha256 = (Get-FileHash -LiteralPath $nativePath -Algorithm SHA256).Hash.ToLowerInvariant() } } }
$checks = 0
function Assert-Check([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message }; $script:checks++ }
$success = Invoke-ControlNative 'fixture.exe' @('-NoProfile','-NonInteractive','-Command', "[Console]::Out.WriteLine('fixture stdout'); [Console]::Error.WriteLine('fixture stderr'); if (`$null -ne [Console]::In.ReadLine()) { exit 8 }; exit 0") 'success.log' -TimeoutSeconds 10 -CloseStandardInput -PassThru
Assert-Check ($success.exitCode -eq 0 -and -not $success.timedOut -and $success.stdinMode -ceq 'closed-empty') 'Successful process or empty stdin was not captured.'
$output = Get-Content -LiteralPath (Join-Path $runRoot 'success.log') -Raw
Assert-Check ($output.Contains('fixture stdout') -and $output.Contains('fixture stderr')) 'Both output streams must be retained under ErrorAction Stop.'
Assert-Check ($success.toolSha256 -ceq $record.tools['fixture.exe'].sha256 -and $success.arguments.Count -eq 4) 'Command provenance changed.'
$failed = $false
try { Invoke-ControlNative 'fixture.exe' @('-NoProfile','-NonInteractive','-Command', "[Console]::Error.WriteLine('expected refusal'); exit 7") 'refusal.log' -TimeoutSeconds 10 -CloseStandardInput } catch { $failed = $_.Exception.Message -match 'exited with code 7' }
Assert-Check $failed 'Nonzero exit must be rejected explicitly.'
$refusal = Get-Content -LiteralPath (Join-Path $runRoot 'refusal.log.command.json') -Raw | ConvertFrom-Json
Assert-Check ($refusal.exitCode -eq 7 -and -not $refusal.timedOut -and (Get-Content -LiteralPath (Join-Path $runRoot 'refusal.log') -Raw).Contains('expected refusal')) 'Refusal evidence was lost.'
$failed = $false
$timer = [Diagnostics.Stopwatch]::StartNew()
try { Invoke-ControlNative 'fixture.exe' @('-NoProfile','-NonInteractive','-Command', "[Console]::Out.WriteLine('before timeout'); Start-Sleep -Seconds 30") 'timeout.log' -TimeoutSeconds 1 -CloseStandardInput } catch { $failed = $_.Exception.Message -match 'exceeded its 1 second deadline' }
$timer.Stop()
Assert-Check ($failed -and $timer.Elapsed.TotalSeconds -lt 15) 'Timeout was not bounded.'
$timeout = Get-Content -LiteralPath (Join-Path $runRoot 'timeout.log.command.json') -Raw | ConvertFrom-Json
Assert-Check ($timeout.timedOut -and $timeout.timeoutSeconds -eq 1 -and (Get-Content -LiteralPath (Join-Path $runRoot 'timeout.log') -Raw).Contains('before timeout')) 'Timeout output and command evidence were lost.'
$failed = $false
try { Invoke-ControlNative 'unregistered.exe' @() 'forbidden.log' } catch { $failed = $_.Exception.Message -match 'prevalidated' }
Assert-Check $failed 'Unregistered executable was accepted.'
$formatPath = Join-Path $env:SystemRoot 'System32\format.com'
$record.tools['format.com'] = [pscustomobject]@{ path = $formatPath; sha256 = (Get-FileHash -LiteralPath $formatPath -Algorithm SHA256).Hash.ToLowerInvariant() }
$help = Invoke-ControlNative 'format.com' @('/?') 'format-help.log' -TimeoutSeconds 10 -CloseStandardInput -PassThru
Assert-Check ($help.exitCode -eq 0 -and $help.arguments.Count -eq 1 -and $help.arguments[0] -ceq '/?') 'Read-only format help was not invoked successfully.'
Assert-Check ((Get-Content -LiteralPath (Join-Path $runRoot 'format-help.log') -Raw) -match '(?im)^\s*/Y\s+No prompt,') 'Actual format.com help must retain the documented no-prompt option.'
"Passed $checks bounded native-process checks; ordinary evidence retained at $runRoot."
