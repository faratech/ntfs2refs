# Finish only independent hashes after HND6339. Previously passed metadata
# checks remain pinned; no converter, raw journal, disk-state or replay path.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$run='63393142005e45ef9320964dbc6ed683';$root=Join-Path $base ('source-free-performance-normal-'+$run)
function Need([bool]$Ok,[string]$Message){if(-not$Ok){throw $Message}}
$d=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
$old=Join-Path $root 'guest-wrapper.ps1';Need ((Get-FileHash -LiteralPath $old).Hash.ToLowerInvariant()-ceq$d.wrapper_sha256-and$d.run_id-ceq$run) 'Actual original wrapper/run required.'
$text=[IO.File]::ReadAllText($old);$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors);Need ($errors.Count-eq0) 'Original syntax differs.'
$wanted=@('Need','Idle','Source','Save','VerifyAllTargetStreamHashes');$defs=[Collections.Generic.List[string]]::new()
foreach($name in $wanted){$f=@($ast.EndBlock.Statements|Where-Object {$_-is[Management.Automation.Language.FunctionDefinitionAst]-and$_.Name-ceq$name});Need ($f.Count-eq1) ('One read-only helper required: '+$name);$value=$f[0].Extent.Text;if($name-ceq'VerifyAllTargetStreamHashes'){$oldGuard='Need ($null-ne$nativeExit-and$nativeExit-eq0-and$process.HasExited)';Need ($value.Contains($oldGuard)) 'Original exit guard differs.';$value=$value.Replace($oldGuard,'Need ($null-ne$nativeExit-and$nativeExit-eq0-and$actualTerminal.native_exit_observed)')};$defs.Add($value)}
$c=$d.configuration;$c.stage='C:\ntfs2refs\source-free-observer-4181a4966f32481791bccc207dc82e57';$nonce=[guid]::NewGuid().ToString('N');$c.task='N2R-SourceFreeHashes-'+$nonce
$encoded=[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes(($c|ConvertTo-Json -Depth 32 -Compress)))
$guest="Set-StrictMode -Version Latest`n`$ErrorActionPreference='Stop'`n`$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+$encoded+"'))|ConvertFrom-Json`n"+($defs-join[Environment]::NewLine)+[Environment]::NewLine+@'
$held=[Collections.Generic.List[IO.FileStream]]::new()
function HeldJson([string]$Path,[long]$Limit){$m=Get-Item -LiteralPath $Path;Need (-not$m.PSIsContainer-and-not($m.Attributes-band[IO.FileAttributes]::ReparsePoint)-and$m.Length-gt0-and$m.Length-le$Limit) 'Bounded ordinary closed metadata required.';$f=[IO.File]::Open($Path,'Open','Read','Read');$held.Add($f);$r=[IO.StreamReader]::new($f,[Text.UTF8Encoding]::new($false),$true,4096,$true);try{return ($r.ReadToEnd()|ConvertFrom-Json)}finally{$r.Dispose()}}
try{
 Idle;Source 'ReFS'
 $actualTerminal=HeldJson 'C:\ntfs2refs\source-free-performance-normal-63393142005e45ef9320964dbc6ed683\converter-terminal.json' 1MB
 Need ($actualTerminal.pid-eq4144-and$actualTerminal.creation_ms-eq1793560925173-and$actualTerminal.native_exit_observed-and$actualTerminal.native_exit-eq0) 'Actual original observed native exit required.'
 $live=Get-CimInstance Win32_Process -Filter 'ProcessId=4144' -ErrorAction Stop
 Need ($null-eq$live-or([DateTimeOffset]$live.CreationDate).ToUnixTimeMilliseconds()-ne1793560925173) 'Original native process is still alive.'
 $nativeExit=$actualTerminal.native_exit
 $handoff=HeldJson (Join-Path $c.output 'handoff.json') 65536;$ticket=HeldJson (Join-Path $c.output 'selected-ticket.json') 65536
 Need ($handoff.replay_closed-and($handoff.selected_sha256-join',')-ceq($ticket.new_selected_sha256-join',')) 'Closed actual HND required; no replay occurs.'
 $bindingPath=Join-Path $c.stage 'lab-baseline-binding.json';$binding=HeldJson $bindingPath 4MB
 Need ($binding.baseline_used-and$binding.comparison_only_clone-and-not$binding.product_expectation_written-and$binding.source_binding_identical-and$binding.fresh_digests_bound_to_actual_full_raw_and_native_reads-and$binding.fresh_manifest_sha256-ceq$c.fresh_manifest_sha256-and-not$binding.grants_product_authority) 'Previously completed fresh-source/hashless-target binding required.'
 $fullPath=Join-Path $c.stage 'lab-full-content-baseline.json';$full=HeldJson $fullPath 16MB
 Need ((Get-FileHash -LiteralPath $fullPath).Hash.ToLowerInvariant()-ceq$c.baseline_sha256) 'Actual full source expectation pin differs.'
 $expectedPath=Join-Path $c.output 'expectation.json';$expected=HeldJson $expectedPath 16MB
 $current=@{};foreach($o in $expected.objects){$key=(@($o.path)-join'\');Need (-not$current.ContainsKey($key)) 'Duplicate target path.';$current[$key]=$o}
 Need ($current.Count-eq@($full.objects).Count) 'Full source and admitted target object counts differ.'
 foreach($o in $full.objects){$key=(@($o.path)-join'\');Need ($current.ContainsKey($key)) 'Full source path missing from target expectation.';$a=$current[$key];Need ($a.directory-eq$o.directory-and$a.record_number-eq$o.record_number-and$a.sequence_number-eq$o.sequence_number) 'Actual source identity/path binding differs.';if(-not$o.directory){Need ($a.length-eq$o.length-and$o.sha256-cmatch'\A[0-9a-f]{32}\z') 'Full source stream length/digest differs.'}}
 $started=[DateTime]::UtcNow
 $hashes=VerifyAllTargetStreamHashes $full 'F'
 Need ($hashes.all_expected_hashes_match-and$hashes.default_stream_hashes-eq811-and$hashes.named_stream_hashes-eq0) 'Every expected file must match.'
 Save 'hashes-only-independent-target.json' $hashes
 Idle;Source 'ReFS'
 Save 'hashes-only-result.json' @{schema_version=1;kind='post-HND-independent-content-completion';success=$true;core_run_id=$c.run_id;native_pid=$actualTerminal.pid;native_creation_ms=$actualTerminal.creation_ms;native_exit=$nativeExit;complete_default_hashes=$hashes.default_stream_hashes;complete_named_hashes=$hashes.named_stream_hashes;all_hashes_match=$true;source_baseline_sha256=$c.baseline_sha256;admitted_expectation_sha256=(Get-FileHash -LiteralPath $expectedPath).Hash.ToLowerInvariant();completed_binding_sha256=(Get-FileHash -LiteralPath $bindingPath).Hash.ToLowerInvariant();hashes_sha256=(Get-FileHash -LiteralPath (Join-Path $c.stage 'hashes-only-independent-target.json')).Hash.ToLowerInvariant();converter_launched=$false;raw_journal_opened=$false;raw_replay_attempted=$false;metadata_checks_repeated=$false;started_utc=$started.ToString('o');utc=[DateTime]::UtcNow.ToString('o')}
}catch{Save 'hashes-only-failed.json' @{success=$false;error=$_.Exception.ToString();converter_launched=$false;raw_replay_attempted=$false;utc=[DateTime]::UtcNow.ToString('o')};exit 1}
finally{foreach($f in $held){$f.Dispose()}}
'@
$null=[Management.Automation.Language.Parser]::ParseInput($guest,[ref]$tokens,[ref]$errors);Need ($errors.Count-eq0) 'Hash-only helper syntax differs.'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force;Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration)) -AdditionalBytes 134217728
$path=Join-Path $root 'hashes-only-observer.ps1';Need (-not(Test-Path -LiteralPath $path)) 'Existing hash-only attempt must be observed, never duplicated.'
[IO.File]::WriteAllText($path,$guest,[Text.UTF8Encoding]::new($false));$pin=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
$session=New-PSSession -VMId '2401593c-4b30-472e-9b6d-c9534cbaa599' -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml'))
try{
 $name='hashes-only-observer.ps1';Copy-Item -LiteralPath $path -Destination (Join-Path $c.stage $name) -ToSession $session
 Invoke-Command -Session $session -ArgumentList $c.stage,$c.task,$pin,$name -ScriptBlock {param($Stage,$Task,$Pin,$Name)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$path=Join-Path $Stage $Name;$t=$null;$e=$null;$null=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$t,[ref]$e)
  if($e.Count-or(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$Pin-or@(Get-ScheduledTask|Where-Object {$_.TaskName-ceq$Task-or($_.TaskName-like'N2R-*'-and$_.State-notin@('Ready','Disabled'))}).Count-or@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count){throw 'Fresh idle pinned hash-only task required'}
  if(Test-Path -LiteralPath (Join-Path $Stage 'hashes-only-result.json')){throw 'Independent hashes already complete'}
  Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'"')) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
  Start-ScheduledTask -TaskName $Task
 }
 $receipt=@{schema_version=1;kind='source-free-hashes-only-dispatch';run_id=$run;stage=$c.stage;task_name=$c.task;script_sha256=$pin;metadata_checks_reused=$true;converter_launched=$false;raw_replay_attempted=$false;utc=[DateTime]::UtcNow.ToString('o')};$out=Join-Path $root 'hashes-only-dispatch.json';$f=[IO.File]::Open($out,'CreateNew','Write','Read');try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($receipt|ConvertTo-Json -Depth 8));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()};$receipt|ConvertTo-Json -Compress
}finally{Remove-PSSession $session}
