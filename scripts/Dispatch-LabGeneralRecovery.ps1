<# Dispatch one pinned resume or rollback after a terminal general replay task.
   A nonzero handoff sector, live converter or writable-mounted target refuses. #>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$ReplayDispatchDirectory,
 [Parameter(Mandatory)][ValidateSet('Resume','Rollback')][string]$Mode,
 [Parameter(Mandatory)][string]$BinaryPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BinarySha256,
 [switch]$WithoutShadow
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
if($WithoutShadow -and $Mode -cne 'Rollback'){throw 'Shadowless recovery permits rollback only.'}
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$parent=Assert-LabPath $ReplayDispatchDirectory $cfg.Root
$start=Get-Content -LiteralPath (Join-Path $parent 'started.json') -Raw|ConvertFrom-Json
$original=Get-Content -LiteralPath (Join-Path $parent 'dispatch.json') -Raw|ConvertFrom-Json
if($start.kind-cne'general-tree-replay-dispatch'-or$start.runId-cnotmatch'\A[0-9a-f]{32}\z'-or$start.experimentId-cnotmatch'\A[0-9a-f]{32}\z'-or$original.taskName-cne('N2R-General-'+$start.runId)-or$original.guestArtifacts-cne('C:\ntfs2refs\general-replay\'+$start.runId+'\artifacts')-or$vm.State-ne'Running'-or[guid]$vm.ParentSnapshotId-ne[guid]$start.parentCheckpointId){throw 'Original general replay or VM branch differs.'}
$binary=Get-Item -LiteralPath $BinaryPath -Force
if($binary.PSIsContainer-or($binary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$binary.Length-gt16MB-or(Get-FileHash -LiteralPath $binary.FullName).Hash.ToLowerInvariant()-cne$BinarySha256){throw 'Pinned general recovery executable required.'}
$step=[guid]::NewGuid().ToString('N')
$output=Assert-LabPath (Join-Path $cfg.Root ('general-recovery/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
New-Item -ItemType Directory -Path $output|Out-Null
function Save([string]$Name,$Value){$path=Join-Path $output $Name;$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
$record=[ordered]@{kind='general-tree-recovery-dispatch';stepId=$step;mode=$Mode;withoutShadow=[bool]$WithoutShadow;parentDirectory=$parent;runId=$start.runId;experimentId=$start.experimentId;parentCheckpointId=$start.parentCheckpointId;binarySha256=$BinarySha256;requestSha256=$start.requestSha256;status='started';operationCompletionKnown=$true;productionConversionQualified=$false;error=$null}
Save 'started.json' $record
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $deadline=[DateTime]::UtcNow.AddSeconds(180)
 do{try{$session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop;break}catch{Start-Sleep -Seconds 2}}while([DateTime]::UtcNow-lt$deadline)
 if(-not$session){throw 'Guest session unavailable.'}
 $preflight=Invoke-Command -Session $session -ArgumentList @($original.taskName,$original.guestArtifacts,$start.experimentId,$start.requestSha256,$start.expectationSha256,$step,[bool]$WithoutShadow) -ScriptBlock {
  param($OriginalTask,$Artifacts,$ExperimentId,$RequestSha,$ExpectationSha,$Step,$WithoutShadow)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  $task=Get-ScheduledTask -TaskName $OriginalTask -ErrorAction Stop;$info=Get-ScheduledTaskInfo -TaskName $OriginalTask -ErrorAction Stop
  if($task.State-in@('Running','Queued')-or$info.LastRunTime.Year-lt2000){throw 'Original converter task is still live or has not run.'}
  if(Get-Process -Name 'lab-general-complete*','lab-general-experiment*','lab-recover-general-journal*' -ErrorAction SilentlyContinue){throw 'A converter or recovery process is still running.'}
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3 -ErrorAction SilentlyContinue
  if(-not$source.IsOffline-or$source.IsReadOnly-or$source.IsBoot-or$source.IsSystem-or(-not$WithoutShadow-and-not$shadow)-or($shadow-and(-not$shadow.IsOffline-or-not$shadow.IsReadOnly))){throw 'Activated target or frozen shadow state differs.'}
  $request=Join-Path $Artifacts 'request.json';$expectation=Join-Path $Artifacts 'expectation.json';$ticket=Join-Path $Artifacts 'ticket.json';$recovery=Join-Path $Artifacts 'recovery.json'
  foreach($path in @($request,$expectation,$ticket,$recovery)){if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw 'Required durable recovery artifact absent.'}}
  $pins=Get-Content -LiteralPath $recovery -Raw|ConvertFrom-Json
  $journal='J:\ntfs2refs-shadow\'+$ExperimentId+'\reconstruction.journal'
  if($pins.kind-cne'general-recovery-pins'-or$pins.journal-cne$journal-or$pins.request_sha256-cne$RequestSha-or$pins.expectation_sha256-cne$ExpectationSha-or(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()-cne$RequestSha-or(Get-FileHash -LiteralPath $expectation).Hash.ToLowerInvariant()-cne$ExpectationSha-or(Get-FileHash -LiteralPath $ticket).Hash.ToLowerInvariant()-cne$pins.ticket_sha256){throw 'Recovery request, expectation, ticket or journal pins differ.'}
  $stream=[IO.File]::Open($journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
  try{$marker=[byte[]]::new(4096);if($stream.Read($marker,0,$marker.Length)-ne$marker.Length-or@($marker|Where-Object {$_ -ne0}).Count-ne0){throw 'Handoff sector is not all zero; recovery closed.'}}finally{$stream.Dispose()}
  $output=Join-Path $Artifacts ('recovery-'+$Step+'.json')
  if(Test-Path -LiteralPath $output){throw 'Fresh guest recovery output required.'}
  [pscustomobject]@{request=$request;requestSha256=$RequestSha;ticket=$ticket;ticketSha256=$pins.ticket_sha256;journal=$journal;output=$output;sourceOffline=$source.IsOffline;sourceReadOnly=$source.IsReadOnly;originalTaskResult=$info.LastTaskResult;checkedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'preflight.json' $preflight
 $guestExe='C:\ntfs2refs\general-replay\'+$start.runId+'\lab-recover-general-journal-'+$step+'.exe'
 Copy-Item -LiteralPath $binary.FullName -Destination $guestExe -ToSession $session
 $dispatch=Invoke-Command -Session $session -ArgumentList @($guestExe,$BinarySha256,$preflight,$Mode,$step,[bool]$WithoutShadow) -ScriptBlock {
  param($Exe,$ExeSha,$Preflight,$Mode,$Step,$WithoutShadow)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  if((Get-FileHash -LiteralPath $Exe).Hash.ToLowerInvariant()-cne$ExeSha){throw 'Guest recovery executable pin differs.'}
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3 -ErrorAction SilentlyContinue
  if(-not$source.IsOffline-or$source.IsReadOnly-or(-not$WithoutShadow-and-not$shadow)-or($shadow-and(-not$shadow.IsOffline-or-not$shadow.IsReadOnly))){throw 'Guest exclusion changed before recovery dispatch.'}
  $name='N2R-GeneralRecover-'+$Step
  if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Recovery task already exists.'}
  $arguments=$Mode.ToLowerInvariant()+' --request "'+$Preflight.request+'" --request-sha256 '+$Preflight.requestSha256+' --ticket "'+$Preflight.ticket+'" --ticket-sha256 '+$Preflight.ticketSha256+' --journal "'+$Preflight.journal+'" --output "'+$Preflight.output+'"'
  if($WithoutShadow){$arguments+=' --without-shadow'}
  $action=New-ScheduledTaskAction -Execute $Exe -Argument $arguments
  $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 6) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -ErrorAction Stop|Out-Null
  Start-ScheduledTask -TaskName $name -ErrorAction Stop
  [pscustomobject]@{taskName=$name;taskState=[string](Get-ScheduledTask -TaskName $name).State;guestOutput=$Preflight.output;ticketSha256=$Preflight.ticketSha256;dispatchedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'dispatch.json' $dispatch
 $record.status='guest-general-recovery-task-dispatched';$record['taskName']=$dispatch.taskName;$record['guestOutput']=$dispatch.guestOutput
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();throw}
finally{Save 'host-result.json' $record;if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
[pscustomobject]$record
