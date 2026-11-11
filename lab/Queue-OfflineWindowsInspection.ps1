param(
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{32}\z')][string]$RunId,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$InspectorSha,
 [switch]$ObserveOnly
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$workspace=Split-Path -Parent $PSScriptRoot
$case=Join-Path $workspace ('.lab\hyperv\boot-source-inspect-80f4b5a-'+$RunId)
$guestRoot='C:\ntfs2refs\boot-source-inspection-'+$RunId
$saved=Import-Clixml -LiteralPath (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$credential=[pscredential]::new('LabAdmin',$saved.Password)
$session=New-PSSession -VMId '8f7fc646-8c9f-41d0-b65a-ecfadccfc36a' -Credential $credential
try{
 if(-not$ObserveOnly){
  $binary=Join-Path $workspace 'target\shared-experiments\x86_64-pc-windows-msvc\release\lab-inspect-offline-windows.exe'
  if((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()-cne$InspectorSha){throw 'Built inspector differs'}
  $tokens=$null;$errors=$null
  $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $workspace 'lab\Package-QualifiedSharedOfflineAlpha.ps1'),[ref]$tokens,[ref]$errors)
  if($errors.Count){throw 'Capacity source failed to parse'}
  foreach($name in @('Need','Add','Ordinary','MeasureTree','Capacity')){
   $function=$ast.Find({param($node)$node-is[Management.Automation.Language.FunctionDefinitionAst]-and$node.Name-ceq$name},$false)
   if(-not$function){throw 'Capacity function absent'}
   . ([scriptblock]::Create($function.Extent.Text))
  }
  $capacity=Capacity 9663676416L
  Need ($capacity.actual_bytes+9663676416L-le279866334601L) 'Boot-work 50GB allowance would be exceeded'
  Need (-not(Test-Path -LiteralPath $case)) 'Existing host case must only be observed'
  $null=New-Item -ItemType Directory -Path $case
  $capacity|ConvertTo-Json -Depth 4|Set-Content -LiteralPath (Join-Path $case 'admission.json') -Encoding UTF8
  $stage=Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock {
   param($root)
   $os=Get-CimInstance Win32_OperatingSystem;$current=Get-Partition -DriveLetter C
   $source=Get-Partition -DriveLetter D;$disk=Get-Disk -Number $source.DiskNumber
   if([DateTimeOffset]::new($os.LastBootUpTime.ToUniversalTime()).ToUnixTimeMilliseconds()-ne1793995332223L-or$current.DiskNumber-ne1-or(Get-Volume -DriveLetter C).FileSystem-cne'ReFS'-or$source.DiskNumber-ne0-or$source.IsBoot-or$source.IsSystem-or[guid]$source.Guid-ne[guid]'c6c3318f-a7c8-47b9-be6d-6dde5e00862f'){throw 'Original bound source/alternate Windows changed'}
   if($disk.IsOffline-or$disk.IsReadOnly-or$disk.Size-ne64GB-or$source.Offset-ne331350016L-or$source.Size-ne66238545920L-or(Get-Volume -DriveLetter D).FileSystem-cne'NTFS'){throw 'Original source geometry/state changed'}
   if(Test-Path -LiteralPath $root){throw 'Existing guest stage must only be observed'}
   $route=@($source.AccessPaths|Where-Object {$_-match'^\\\\\?\\Volume'})
   if($route.Count-ne1){throw 'Unique source GUID route required'}
   $binding=[ordered]@{disk_number=0;volume_guid=([regex]::Match($route[0],'\{([^}]+)\}').Groups[1].Value.ToLowerInvariant());identity=[ordered]@{disk_guid=([guid]$disk.Guid).ToString('D');partition_guid=([guid]$source.Guid).ToString('D');partition_number=3;disk_bytes=[long]$disk.Size;partition_offset=[long]$source.Offset;partition_bytes=[long]$source.Size;logical_sector_bytes=[int]$disk.LogicalSectorSize;physical_sector_bytes=[int]$disk.PhysicalSectorSize};layout_profile='offline_windows'}
   $null=New-Item -ItemType Directory -Path $root
   [IO.File]::WriteAllText((Join-Path $root 'binding.json'),($binding|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
   @{binding_sha256=(Get-FileHash -LiteralPath (Join-Path $root 'binding.json') -Algorithm SHA256).Hash.ToLowerInvariant()}
  }
  $worker=Join-Path $PSScriptRoot 'guest\Inspect-OfflineWindowsSource.ps1'
  $workerSha=(Get-FileHash -LiteralPath $worker -Algorithm SHA256).Hash.ToLowerInvariant()
  Copy-Item -LiteralPath $binary -Destination (Join-Path $guestRoot 'inspect.exe') -ToSession $session
  Copy-Item -LiteralPath $worker -Destination (Join-Path $guestRoot 'worker.ps1') -ToSession $session
  Invoke-Command -Session $session -ArgumentList $guestRoot,$RunId,$stage.binding_sha256,$InspectorSha,$workerSha -ScriptBlock {
   param($root,$id,$bindingSha,$exeSha,$workerSha)
   $task='N2R-BootInspect-'+$id;$worker=Join-Path $root 'worker.ps1'
   if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){throw 'Inspection task already exists'}
   if((Get-FileHash -LiteralPath $worker -Algorithm SHA256).Hash.ToLowerInvariant()-cne$workerSha-or(Get-FileHash -LiteralPath (Join-Path $root 'inspect.exe') -Algorithm SHA256).Hash.ToLowerInvariant()-cne$exeSha){throw 'Guest worker or inspector differs'}
   $action=New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File '+$worker+' -Root '+$root+' -BindingSha '+$bindingSha+' -InspectorSha '+$exeSha)
   $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
   $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
   $null=Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings
   @{task_name=$task;worker_sha256=$workerSha;inspector_sha256=$exeSha;binding_sha256=$bindingSha;source_writes_authorized=$false}|ConvertTo-Json -Compress|Set-Content -LiteralPath (Join-Path $root 'queue.json') -Encoding UTF8
   Start-ScheduledTask -TaskName $task
   @{task_name=$task;queued=$true;source_writes_authorized=$false}
  }|ConvertTo-Json -Compress
 }
 $state=Invoke-Command -Session $session -ArgumentList $guestRoot,$RunId -ScriptBlock {
  param($root,$id)
  $terminal=Join-Path $root 'native-terminal.json';$process=Join-Path $root 'native-process.json'
  $state=@{run_id=$id;terminal=(Test-Path -LiteralPath $terminal);task_state=(Get-ScheduledTask -TaskName ('N2R-BootInspect-'+$id)).State.ToString()}
  if(Test-Path -LiteralPath $process){$pin=Get-Content -LiteralPath $process -Encoding UTF8 -Raw|ConvertFrom-Json;$actual=Get-Process -Id $pin.pid -ErrorAction SilentlyContinue;if($actual-and[DateTimeOffset]::new($actual.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds()-eq$pin.process_birth_ms){$state.native=@{pid=$actual.Id;cpu_seconds=$actual.CPU;working_set=$actual.WorkingSet64;peak=$actual.PeakWorkingSet64}}}
  if($state.terminal){$state.result=Get-Content -LiteralPath $terminal -Encoding UTF8 -Raw|ConvertFrom-Json}
  if(Test-Path -LiteralPath (Join-Path $root 'worker-error.txt')){$state.worker_error=Get-Content -LiteralPath (Join-Path $root 'worker-error.txt') -Encoding UTF8 -Raw}
  $state
 }
 foreach($leaf in @('binding.json','queue.json','native-process.json','native-terminal.json','stdout.log','stderr.log','worker-error.txt','output\result.json')){
  if(Invoke-Command -Session $session -ArgumentList (Join-Path $guestRoot $leaf) -ScriptBlock {param($path)Test-Path -LiteralPath $path}){
   Copy-Item -LiteralPath (Join-Path $guestRoot $leaf) -Destination (Join-Path $case ([IO.Path]::GetFileName($leaf))) -FromSession $session
  }
 }
 $state|ConvertTo-Json -Depth 6
}finally{Remove-PSSession $session}
