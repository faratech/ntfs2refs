param([Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$RunId,
 [ValidatePattern('\A[0-9a-f]{7,40}\z')][string]$SourceCommit='643880f',
 [ValidatePattern('\A[0-9a-f]{64}\z')][string]$CandidateSha='1f5fe77e6e53d34dbc499b263b6b2571ff54c1fe6cb7b84a58585c03699b3dbb',
 [long]$ExpectedPartitionBytes=66238545920L,
 [switch]$ObserveOnly)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$workspace=Split-Path -Parent $PSScriptRoot
$case=Join-Path $workspace ('.lab\hyperv\boot-conversion-'+$SourceCommit.Substring(0,7)+'-'+$RunId)
$guestRoot='C:\ntfs2refs\boot-conversion-'+$SourceCommit.Substring(0,7)+'-'+$RunId
$saved=Import-Clixml -LiteralPath (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$credential=[pscredential]::new('LabAdmin',$saved.Password)
$session=New-PSSession -VMId '8f7fc646-8c9f-41d0-b65a-ecfadccfc36a' -Credential $credential
try{
 if(-not$ObserveOnly){
  $binary=Join-Path $workspace 'target\shared-experiments\x86_64-pc-windows-msvc\release\ntfs2refs.exe'
  if((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()-cne$candidateSha){throw 'Built candidate differs'}
  $tokens=$null;$parseErrors=$null
  $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $workspace 'lab\Package-QualifiedSharedOfflineAlpha.ps1'),[ref]$tokens,[ref]$parseErrors)
  if($parseErrors.Count){throw 'Capacity source parser failed'}
  foreach($name in @('Need','Add','Ordinary','MeasureTree','Capacity')){
   $function=$ast.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq$name},$false)
   if(-not$function){throw 'Capacity function absent'};. ([scriptblock]::Create($function.Extent.Text))
  }
  $capacity=Capacity 17179869184L
  Need ($capacity.actual_bytes+17179869184L-le279866334601L) 'Boot-work 50GB allowance cannot admit16GiB forecast'
  Need (-not(Test-Path -LiteralPath $case)) 'Existing conversion case must only be observed'
  $vm=Get-VM -Id '8f7fc646-8c9f-41d0-b65a-ecfadccfc36a'
  Need ($vm.State-eq'Running'-and(Get-VMFirmware -VM $vm).SecureBoot-eq'On'-and@(Get-VMSnapshot -VM $vm).Count-eq0) 'Reference VM or zero-checkpoint policy changed'
  $null=New-Item -ItemType Directory -Path $case
  $capacity|ConvertTo-Json -Depth 4|Set-Content -LiteralPath (Join-Path $case 'admission.json') -Encoding UTF8
  Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock {param($root)if(Test-Path -LiteralPath $root){throw 'Guest conversion case already exists'};$null=New-Item -ItemType Directory -Path $root}
  $worker=Join-Path $PSScriptRoot 'guest\Convert-OfflineWindowsSource.ps1'
  $workerSha=(Get-FileHash -LiteralPath $worker -Algorithm SHA256).Hash.ToLowerInvariant()
  Copy-Item -LiteralPath $binary -Destination (Join-Path $guestRoot 'ntfs2refs.exe') -ToSession $session
  Copy-Item -LiteralPath $worker -Destination (Join-Path $guestRoot 'worker.ps1') -ToSession $session
  Invoke-Command -Session $session -ArgumentList $guestRoot,$RunId,$candidateSha,$workerSha,$SourceCommit,$ExpectedPartitionBytes -ScriptBlock {
   param($root,$id,$exeSha,$workerSha,$commit,$partitionBytes)
   $task='N2R-WindowsConvert-'+$id;$worker=Join-Path $root 'worker.ps1'
   if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){throw 'Conversion task already exists'}
   if((Get-FileHash -LiteralPath $worker -Algorithm SHA256).Hash.ToLowerInvariant()-cne$workerSha-or(Get-FileHash -LiteralPath (Join-Path $root 'ntfs2refs.exe') -Algorithm SHA256).Hash.ToLowerInvariant()-cne$exeSha){throw 'Guest candidate or worker differs'}
   $action=New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File '+$worker+' -Root '+$root+' -CandidateSha '+$exeSha+' -SourceCommit '+$commit+' -ExpectedPartitionBytes '+$partitionBytes)
   $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
   $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
   $null=Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings
   @{task_name=$task;candidate_sha256=$exeSha;worker_sha256=$workerSha;native_launches_authorized=1}|ConvertTo-Json -Compress|Set-Content -LiteralPath (Join-Path $root 'queue.json') -Encoding UTF8
   Start-ScheduledTask -TaskName $task;@{queued=$true;task_name=$task}
  }|ConvertTo-Json -Compress
 }
 $state=Invoke-Command -Session $session -ArgumentList $guestRoot,$RunId -ScriptBlock {
  param($root,$id)
  $state=@{run_id=$id;task_state=(Get-ScheduledTask -TaskName ('N2R-WindowsConvert-'+$id)).State.ToString()}
  $native=Join-Path $root 'native-process.json';$terminal=Join-Path $root 'native-terminal.json'
  if(Test-Path -LiteralPath $native){$pin=Get-Content -LiteralPath $native -Encoding UTF8 -Raw|ConvertFrom-Json;$p=Get-Process -Id $pin.pid -ErrorAction SilentlyContinue;if($p-and[DateTimeOffset]::new($p.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds()-eq$pin.birth_ms){$state.native=@{pid=$p.Id;cpu_seconds=$p.CPU;working_set=$p.WorkingSet64;peak=$p.PeakWorkingSet64}}}
  $state.terminal=Test-Path -LiteralPath $terminal
  if($state.terminal){$state.result=Get-Content -LiteralPath $terminal -Encoding UTF8 -Raw|ConvertFrom-Json}
  foreach($leaf in @('stdout.log','stderr.log','worker-error.txt')){if(Test-Path -LiteralPath (Join-Path $root $leaf)){$state[$leaf]=@(Get-Content -LiteralPath (Join-Path $root $leaf) -Encoding UTF8 -Tail 8)}}
  $state
 }
 foreach($leaf in @('queue.json','native-process.json','native-terminal.json','worker-error.txt')){
  if(Invoke-Command -Session $session -ArgumentList (Join-Path $guestRoot $leaf) -ScriptBlock {param($path)Test-Path -LiteralPath $path}){Copy-Item -LiteralPath (Join-Path $guestRoot $leaf) -Destination (Join-Path $case $leaf) -FromSession $session}
 }
 $state|ConvertTo-Json -Depth 6
}finally{Remove-PSSession $session}
