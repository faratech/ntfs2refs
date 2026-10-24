<# Actual harmless local child processes and ordinary temporary capture files only. No VM/device calls. #>
[CmdletBinding()]param()
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$script:checks=0
function Check([bool]$Value,[string]$Name){if(-not$Value){throw $Name};$script:checks++}
function Reject([scriptblock]$Body,[string]$Name){$failed=$false;try{&$Body|Out-Null}catch{$failed=$true};Check $failed $Name}
$definitions=@();$asts=@()
foreach($name in @('Invoke-GuestNativeProbe.ps1','Invoke-GuestNativeReconstruct.ps1')){
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot ('guest\'+$name)),[ref]$tokens,[ref]$errors);Check ($errors.Count-eq0) ('parse '+$name);$asts+=$ast
 $definition=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq'Initialize-N2RProcessCapture'},$true));Check ($definition.Count-eq1) 'one embedded runner';$definitions+=$definition[0].Extent.Text
 foreach($f in $ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-in@('Complete-NativeProbeProcess','Complete-NRProcess')},$true)){. ([scriptblock]::Create($f.Extent.Text))}
 Check (-not($ast.Extent.Text-match '\.Kill\s*\(')) 'no termination method'
 Check ([regex]::Matches($ast.Extent.Text,'\[Ntfs2Refs\.BoundedLabProcess\]::Start\(').Count-eq1) 'single managed launch'
}
Check ($definitions[0]-ceq$definitions[1]) 'both pinned wrappers embed identical implementation'
. ([scriptblock]::Create($definitions[0]));Initialize-N2RProcessCapture
Reject {Initialize-N2RProcessCapture} 'fresh assembly required rather than trusting preloaded code'
Check ([Ntfs2Refs.BoundedLabProcess]::RetainedCount-eq0) 'no initial child handles'
$root=Join-Path ([IO.Path]::GetTempPath()) ('n2r-process-capture-test-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $root|Out-Null
$script:sequence=0;$children=New-Object 'System.Collections.Generic.List[object]'
$shell=Join-Path $PSHOME $(if($PSVersionTable.PSEdition-ceq'Core'){'pwsh.exe'}else{'powershell.exe'})
function Start-Harmless([string]$Executable,[string]$Arguments){
 $script:sequence++;$out=Join-Path $root ($script:sequence.ToString()+'.stdout');$err=Join-Path $root ($script:sequence.ToString()+'.stderr')
 $child=[Ntfs2Refs.BoundedLabProcess]::Start($Executable,$Arguments,$root,$out,$err);$children.Add($child)
 [pscustomobject]@{Process=$child;Stdout=$out;Stderr=$err}
}
function Start-Script([string]$Source){Start-Harmless $shell ('-NoLogo -NoProfile -NonInteractive -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Source)))}
try{
 # Deliberately fast processes reproduce the lifetime boundary that cmdlet mocks cannot.
 foreach($code in @(0,7,0,7,0,7,0,7)){
  $capture=Start-Harmless $env:ComSpec ('/d /c exit '+$code);$p=$capture.Process
  Check ($p.WaitForExit(10000)) 'fast child and both streams completed'
  Check ($p.ExitCode-is[int]-and$p.ExitCode-eq$code) 'actual retained-handle integer exit code'
  Check (-not$p.OutputLimitExceeded) 'empty streams within bound';$p.Dispose()
 }
 $capture=Start-Script '[Console]::Out.Write("stdout-exact");[Console]::Error.Write("stderr-exact");exit 0';$p=$capture.Process;$record=[ordered]@{completionKnown=$false;exitCode=$null}
 Complete-NativeProbeProcess $p $record 30;Check ($record.completionKnown-and$record.exitCode-eq0) 'probe wrapper consumes actual zero exit'
 Check ([IO.File]::ReadAllText($capture.Stdout)-ceq'stdout-exact') 'stdout exact after completed pump'
 Check ([IO.File]::ReadAllText($capture.Stderr)-ceq'stderr-exact') 'stderr exact after completed pump';$p.Dispose()
 $capture=Start-Harmless $env:ComSpec '/d /c exit 7';$p=$capture.Process;$record=[ordered]@{completionKnown=$false;exitCode=$null}
 Reject {Complete-NativeProbeProcess $p $record 30} 'probe wrapper rejects actual nonzero exit';Check ($record.completionKnown-and$record.exitCode-eq7) 'actual failed exit retained';$p.Dispose()
 $capture=Start-Harmless $env:ComSpec '/d /c exit 7';$p=$capture.Process;$record=[ordered]@{completionKnown=$false;exitCode=$null}
 Complete-NRProcess $p $record 30;Check ($record.completionKnown-and$record.exitCode-eq7) 'reconstruction exposes actual nonzero exit for artifact preservation';$p.Dispose()
 $capture=Start-Script 'Start-Sleep -Milliseconds 500;[Console]::Out.Write("finished-naturally");exit 0';$p=$capture.Process
 Check (-not$p.WaitForExit(1)) 'finite deadline returns unknown'
 Reject {$p.Dispose()} 'unknown child may not be disposed';Check ([Ntfs2Refs.BoundedLabProcess]::RetainedCount-eq1) 'unknown child statically retained'
 # Force collection after the timeout; no kill or restart is used to obtain completion.
 [GC]::Collect();[GC]::WaitForPendingFinalizers()
 Check ($p.WaitForExit(10000)) 'timed out child finishes naturally';Check ($p.ExitCode-eq0) 'later exit remains available'
 Check ([IO.File]::ReadAllText($capture.Stdout)-ceq'finished-naturally') 'pump remains live after timeout';$p.Dispose()
 $capture=Start-Script 'if([Console]::In.ReadToEnd().Length -ne 0){exit 9};[Console]::Out.Write("eof");exit 0';$p=$capture.Process
 Check ($p.WaitForExit(10000)-and$p.ExitCode-eq0) 'closed empty stdin gives finite EOF';Check ([IO.File]::ReadAllText($capture.Stdout)-ceq'eof') 'EOF child output';$p.Dispose()
 $capture=Start-Script '[Console]::Out.Write(("a" * 131072));[Console]::Error.Write(("b" * 131072));exit 0';$p=$capture.Process;$record=[ordered]@{completionKnown=$false;exitCode=$null}
 Reject {Complete-NRProcess $p $record 30} 'overflow refuses completed reconstruction child'
 Check ($record.completionKnown-and$record.exitCode-eq0-and$p.OutputLimitExceeded) 'overflow has determinate exit and explicit truncation flag'
 Check ((Get-Item -LiteralPath $capture.Stdout).Length-eq65536-and(Get-Item -LiteralPath $capture.Stderr).Length-eq65536) 'both capture files bounded while excess drained'
 Check ([IO.File]::ReadAllText($capture.Stdout)-ceq('a'*65536)-and[IO.File]::ReadAllText($capture.Stderr)-ceq('b'*65536)) 'exact captured prefixes';$p.Dispose()
 $existing=Join-Path $root 'existing.stdout';[IO.File]::WriteAllText($existing,'preserve')
 Reject {[Ntfs2Refs.BoundedLabProcess]::Start($env:ComSpec,'/d /c exit 0',$root,$existing,(Join-Path $root 'never.stderr'))} 'capture overwrite refused before start'
 Check ([IO.File]::ReadAllText($existing)-ceq'preserve') 'existing capture unchanged';Check (-not(Test-Path -LiteralPath (Join-Path $root 'never.stderr'))) 'no second capture after first refusal'
 Reject {[Ntfs2Refs.BoundedLabProcess]::Start($env:ComSpec,'/d /c exit 0',$root,(Join-Path $root 'same'),(Join-Path $root 'same'))} 'aliased captures refused'
 Reject {[Ntfs2Refs.BoundedLabProcess]::Start('relative.exe','',$root,(Join-Path $root 'relative.out'),(Join-Path $root 'relative.err'))} 'relative executable refused'
 Reject {[Ntfs2Refs.BoundedLabProcess]::Start((Join-Path $root 'missing.exe'),'',$root,(Join-Path $root 'failed.out'),(Join-Path $root 'failed.err'))} 'start failure reported'
 Check ((Test-Path -LiteralPath (Join-Path $root 'failed.out'))-and(Test-Path -LiteralPath (Join-Path $root 'failed.err'))) 'partial capture artifacts preserved after failed start'
 Check ([Ntfs2Refs.BoundedLabProcess]::RetainedCount-eq0) 'all naturally completed child handles disposed'
}finally{
 foreach($child in $children){try{if($child.WaitForExit(10000)){$child.Dispose()}}catch [ObjectDisposedException] {}catch{Write-Warning $_.Exception.Message}}
 if([Ntfs2Refs.BoundedLabProcess]::RetainedCount-ne0){throw 'Unknown harmless child retained; preserve temporary capture directory.'}
 $full=[IO.Path]::GetFullPath($root);$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath());if(-not$full.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)-or[IO.Path]::GetFileName($full)-notlike'n2r-process-capture-test-*'){throw 'Unsafe temporary cleanup path.'};Remove-Item -LiteralPath $full -Recurse -Force
}
Write-Output ('Native process capture: {0} actual harmless-process/static/ordinary-file checks passed; no VM/device calls.'-f$script:checks)
