<# Dispatch pinned pre-handoff tree recovery inside the owning guest. The
   guest task survives loss of this host controller. It never retries a
   conversion whose handoff marker has begun or whose source is online. #>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$ConversionDirectory,
 [Parameter(Mandatory)][string]$FinalizerPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$FinalizerSha256
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$directory=Assert-LabPath $ConversionDirectory $cfg.Root
$start=Get-Content -LiteralPath (Join-Path $directory 'started.json') -Raw|ConvertFrom-Json
$requestPath=Join-Path $directory 'request.json'
$request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
if($start.kind-cne'ordinary-tree-conversion'-or$start.runId-cnotmatch'\A[0-9a-f]{32}\z'-or$request.experiment_id-cnotmatch'\A[0-9a-f]{32}\z'-or$request.schema_version-ne3-or$request.experiment_id-cne$start.experimentId-or$request.source.disk_number-ne1-or$request.shadow.disk_number-ne3-or$vm.State-ne'Running'-or$vm.MemoryStartup-ne8GB){throw 'Enrolled running ordinary conversion differs.'}
$shadowDirectory=Assert-LabPath $start.shadowDirectory $cfg.Root
$shadowHost=Get-Content -LiteralPath (Join-Path $shadowDirectory 'host-result.json') -Raw|ConvertFrom-Json
if($shadowHost.status-cne'independent-shadow-built-source-unchanged'-or[guid]$vm.ParentSnapshotId-ne[guid]$shadowHost.shadowCheckpointId){throw 'VM checkpoint differs from frozen shadow.'}
$binary=Get-Item -LiteralPath $FinalizerPath -Force
if($binary.PSIsContainer-or($binary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$binary.Length-gt16MB-or(Get-FileHash -LiteralPath $binary.FullName).Hash.ToLowerInvariant()-cne$FinalizerSha256){throw 'Pinned recovery executable required.'}
$requestSha=(Get-FileHash -LiteralPath $requestPath).Hash.ToLowerInvariant()
$step=[guid]::NewGuid().ToString('N')
$output=Assert-LabPath (Join-Path $cfg.Root ('ordinary-tree-recovery/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
New-Item -ItemType Directory -Path $output|Out-Null
function Save([string]$Name,$Value){$path=Join-Path $output $Name;$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 24));$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
$record=[ordered]@{kind='ordinary-tree-recovery-dispatch';stepId=$step;conversionDirectory=$directory;experimentId=$request.experiment_id;requestSha256=$requestSha;finalizerSha256=$FinalizerSha256;status='started';operationCompletionKnown=$true;conversionQualified=$false;error=$null}
Save 'started.json' $record
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $deadline=[DateTime]::UtcNow.AddSeconds(180)
 do{try{$session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop;break}catch{Start-Sleep -Seconds 2}}while([DateTime]::UtcNow-lt$deadline)
 if(-not$session){throw 'Guest session unavailable.'}
 $guestRoot='C:\ntfs2refs\tree-shadow\'+$request.experiment_id
 $guestExe=$guestRoot+'\lab-tree-finalize-recover-'+$step+'.exe'
 Copy-Item -LiteralPath $binary.FullName -Destination $guestExe -ToSession $session
 $dispatch=Invoke-Command -Session $session -ArgumentList @($guestExe,$FinalizerSha256,$requestSha,$request.experiment_id,$start.runId,$step) -ScriptBlock {
  param($Exe,$ExeSha,$RequestSha,$ExperimentId,$Run,$Step)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  $root='C:\ntfs2refs\tree-shadow\'+$ExperimentId
  $artifacts='C:\ntfs2refs\tree-conversion\'+$Run
  $request=$root+'\conversion-request-'+$Run+'.json'
  $expectation=$artifacts+'\expectation.json';$ticket=$artifacts+'\ticket.json'
  $journal='J:\ntfs2refs-shadow\'+$ExperimentId+'\reconstruction.journal'
  $output=$artifacts+'\recover-'+$Step+'.json'
  if((Get-FileHash -LiteralPath $Exe).Hash.ToLowerInvariant()-cne$ExeSha-or(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()-cne$RequestSha){throw 'Guest executable or request pin differs.'}
  foreach($p in @($expectation,$ticket,$journal)){if(-not(Test-Path -LiteralPath $p -PathType Leaf)){throw 'Pinned recovery input absent.'}}
  if(Test-Path -LiteralPath $output){throw 'Fresh recovery output required.'}
  if(Get-Process -Name 'lab-tree-convert*','lab-tree-finalize*','lab-tree-reconstruct*' -ErrorAction SilentlyContinue){throw 'Another converter or recovery process is running.'}
  $originalTask=Get-ScheduledTask -TaskName ('N2R-Convert-'+$Run) -ErrorAction SilentlyContinue
  if($originalTask){$info=Get-ScheduledTaskInfo -TaskName $originalTask.TaskName;if($originalTask.State-in@('Running','Queued')-or$info.LastRunTime.Year-lt2000){throw 'Original converter task has not reached a terminal run.'}}
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
  if(-not$source.IsOffline-or$source.IsReadOnly-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly-or$source.IsBoot-or$source.IsSystem){throw 'Target must be activated, offline and shadow offline read-only.'}
  $stream=[IO.File]::Open($journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
  try{$marker=[byte[]]::new(4096);if($stream.Read($marker,0,$marker.Length)-ne$marker.Length-or@($marker|Where-Object {$_ -ne0}).Count-ne0){throw 'Handoff marker is nonzero or incomplete; recovery closed.'}}finally{$stream.Dispose()}
  $expectedTicket=(Get-Content -LiteralPath ($artifacts+'\ticket-pin.json') -Raw|ConvertFrom-Json).sha256
  $ticketSha=(Get-FileHash -LiteralPath $ticket).Hash.ToLowerInvariant()
  if($ticketSha-cne$expectedTicket){throw 'Independent ticket pin differs.'}
  $expectationSha=(Get-FileHash -LiteralPath $expectation).Hash.ToLowerInvariant()
  $name='N2R-Recover-'+$Step
  if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Recovery task already exists.'}
  $arguments='recover --request "'+$request+'" --request-sha256 '+$RequestSha+' --expectation "'+$expectation+'" --expectation-sha256 '+$expectationSha+' --ticket "'+$ticket+'" --ticket-sha256 '+$ticketSha+' --journal "'+$journal+'" --output "'+$output+'"'
  $action=New-ScheduledTaskAction -Execute $Exe -Argument $arguments
  $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -ErrorAction Stop|Out-Null
  Start-ScheduledTask -TaskName $name -ErrorAction Stop
  [pscustomobject]@{taskName=$name;state=[string](Get-ScheduledTask -TaskName $name).State;guestOutput=$output;requestSha256=$RequestSha;ticketSha256=$ticketSha;expectationSha256=$expectationSha;finalizerSha256=$ExeSha;dispatchedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'dispatch.json' $dispatch
 $record.status='guest-recovery-task-dispatched';$record['taskName']=$dispatch.taskName;$record['guestOutput']=$dispatch.guestOutput
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();throw}
finally{Save 'host-result.json' $record;if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
[pscustomobject]$record
