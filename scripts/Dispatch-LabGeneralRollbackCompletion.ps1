<# Finish only a verified general NTFS rollback. The guest command closes
   journal replay before making the original NTFS disk writable/online. #>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$RecoveryDispatchDirectory,
 [Parameter(Mandatory)][string]$BinaryPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BinarySha256,
 [switch]$AfterMarker
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$recoveryDirectory=Assert-LabPath $RecoveryDispatchDirectory $cfg.Root
$recoveryStart=Get-Content -LiteralPath (Join-Path $recoveryDirectory 'started.json') -Raw|ConvertFrom-Json
$recovered=Get-Content -LiteralPath (Join-Path $recoveryDirectory 'collected.json') -Raw|ConvertFrom-Json
$withoutShadow=($recoveryStart.PSObject.Properties.Name -contains 'withoutShadow') -and [bool]$recoveryStart.withoutShadow
$parent=Assert-LabPath $recoveryStart.parentDirectory $cfg.Root
$start=Get-Content -LiteralPath (Join-Path $parent 'started.json') -Raw|ConvertFrom-Json
$original=Get-Content -LiteralPath (Join-Path $parent 'dispatch.json') -Raw|ConvertFrom-Json
if($recoveryStart.kind-cne'general-tree-recovery-dispatch'-or$recoveryStart.mode-cne'Rollback'-or$recovered.kind-cne'general-tree-recovery-observation'-or-not$recovered.exactImageRecovered-or-not$recovered.readyForOldNtfsOnline-or$recovered.stepId-cne$recoveryStart.stepId-or($recovered.PSObject.Properties.Name -contains 'withoutShadow' -and [bool]$recovered.withoutShadow -ne $withoutShadow)-or$start.kind-cne'general-tree-replay-dispatch'-or$start.runId-cne$recoveryStart.runId-or$start.experimentId-cne$recoveryStart.experimentId-or$original.guestArtifacts-cne('C:\ntfs2refs\general-replay\'+$start.runId+'\artifacts')-or$vm.State-ne'Running'-or[guid]$vm.ParentSnapshotId-ne[guid]$start.parentCheckpointId){throw 'Successful NTFS rollback and owning VM branch required.'}
$binary=Get-Item -LiteralPath $BinaryPath -Force
if($binary.PSIsContainer-or($binary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$binary.Length-gt16MB-or(Get-FileHash -LiteralPath $binary.FullName).Hash.ToLowerInvariant()-cne$BinarySha256){throw 'Pinned NTFS rollback completion executable required.'}
$step=[guid]::NewGuid().ToString('N')
$output=Assert-LabPath (Join-Path $cfg.Root ('general-rollback-complete/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
New-Item -ItemType Directory -Path $output|Out-Null
function Save([string]$Name,$Value){$path=Join-Path $output $Name;$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
$record=[ordered]@{kind='general-ntfs-rollback-completion-dispatch';stepId=$step;runId=$start.runId;experimentId=$start.experimentId;recoveryDirectory=$recoveryDirectory;parentDirectory=$parent;parentCheckpointId=$start.parentCheckpointId;binarySha256=$BinarySha256;requestSha256=$start.requestSha256;afterMarker=[bool]$AfterMarker;withoutShadow=$withoutShadow;status='started';operationCompletionKnown=$true;journalReplayWillClose=$true;productionConversionQualified=$false;error=$null}
Save 'started.json' $record
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $deadline=[DateTime]::UtcNow.AddSeconds(180)
 do{try{$session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop;break}catch{Start-Sleep -Seconds 2}}while([DateTime]::UtcNow-lt$deadline)
 if(-not$session){throw 'Guest session unavailable.'}
 $preflight=Invoke-Command -Session $session -ArgumentList @($original.guestArtifacts,$start.experimentId,$start.requestSha256,$recoveryStart.stepId,[bool]$AfterMarker,$withoutShadow) -ScriptBlock {
  param($Artifacts,$ExperimentId,$RequestSha,$RecoveryStep,$AfterMarker,$WithoutShadow)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  $recoveryTask=Get-ScheduledTask -TaskName ('N2R-GeneralRecover-'+$RecoveryStep) -ErrorAction Stop;$info=Get-ScheduledTaskInfo -TaskName $recoveryTask.TaskName -ErrorAction Stop
  if($recoveryTask.State-in@('Running','Queued')-or$info.LastTaskResult-ne0){throw 'Guest rollback task did not complete successfully.'}
  if(Get-Process -Name 'lab-general-complete*','lab-general-experiment*','lab-recover-general-journal*','lab-complete-general-rollback*' -ErrorAction SilentlyContinue){throw 'Another converter or recovery process is running.'}
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3 -ErrorAction SilentlyContinue
  if(-not$source.IsOffline-or$source.IsReadOnly-or(-not$WithoutShadow-and-not$shadow)-or($shadow-and(-not$shadow.IsOffline-or-not$shadow.IsReadOnly))){throw 'Restored NTFS target or shadow exclusion differs.'}
  $request=Join-Path $Artifacts 'request.json';$ticket=Join-Path $Artifacts 'ticket.json';$recovery=Join-Path $Artifacts 'recovery.json'
  foreach($path in @($request,$ticket,$recovery)){if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw 'Guest rollback completion input absent.'}}
  $pins=Get-Content -LiteralPath $recovery -Raw|ConvertFrom-Json
  $journal='J:\ntfs2refs-shadow\'+$ExperimentId+'\reconstruction.journal'
  if($pins.kind-cne'general-recovery-pins'-or$pins.journal-cne$journal-or$pins.request_sha256-cne$RequestSha-or(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()-cne$RequestSha-or(Get-FileHash -LiteralPath $ticket).Hash.ToLowerInvariant()-cne$pins.ticket_sha256){throw 'Guest rollback completion pins differ.'}
  $stream=[IO.File]::Open($journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
  try{$marker=[byte[]]::new(4096);if($stream.Read($marker,0,$marker.Length)-ne$marker.Length){throw 'Journal handoff sector is truncated.'};$clear=@($marker|Where-Object {$_ -ne0}).Count-eq0;$kind=[Text.Encoding]::ASCII.GetString($marker,0,8);if($AfterMarker){if($clear-or$kind-cne'N2RABT01'){throw 'Exact rollback-complete marker is not present.'}}elseif(-not$clear){throw 'Journal handoff sector is not clear.'}}finally{$stream.Dispose()}
  [pscustomobject]@{request=$request;requestSha256=$RequestSha;ticket=$ticket;ticketSha256=$pins.ticket_sha256;journal=$journal;checkedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'preflight.json' $preflight
 $guestExe='C:\ntfs2refs\general-replay\'+$start.runId+'\lab-complete-general-rollback-'+$step+'.exe'
 Copy-Item -LiteralPath $binary.FullName -Destination $guestExe -ToSession $session
 $guestOutput=$original.guestArtifacts+'\rollback-online-'+$step+'.json'
 $dispatch=Invoke-Command -Session $session -ArgumentList @($guestExe,$BinarySha256,$preflight,$guestOutput,$step,[bool]$AfterMarker,$withoutShadow) -ScriptBlock {
  param($Exe,$ExeSha,$Preflight,$Output,$Step,$AfterMarker,$WithoutShadow)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  if((Get-FileHash -LiteralPath $Exe).Hash.ToLowerInvariant()-cne$ExeSha-or(Test-Path -LiteralPath $Output)){throw 'Guest rollback binary pin or fresh output differs.'}
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3 -ErrorAction SilentlyContinue
  if(-not$source.IsOffline-or$source.IsReadOnly-or(-not$WithoutShadow-and-not$shadow)-or($shadow-and(-not$shadow.IsOffline-or-not$shadow.IsReadOnly))){throw 'Guest exclusion changed before NTFS online dispatch.'}
  $name='N2R-GeneralRollbackOnline-'+$Step
  if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'NTFS rollback completion task already exists.'}
  $arguments='--request "'+$Preflight.request+'" --request-sha256 '+$Preflight.requestSha256+' --ticket "'+$Preflight.ticket+'" --ticket-sha256 '+$Preflight.ticketSha256+' --journal "'+$Preflight.journal+'" --output "'+$Output+'"'
  if($AfterMarker){$arguments+=' --after-marker'}
  if($WithoutShadow){$arguments+=' --without-shadow'}
  $action=New-ScheduledTaskAction -Execute $Exe -Argument $arguments
  $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -ErrorAction Stop|Out-Null
  Start-ScheduledTask -TaskName $name -ErrorAction Stop
  [pscustomobject]@{taskName=$name;taskState=[string](Get-ScheduledTask -TaskName $name).State;guestOutput=$Output;dispatchedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'dispatch.json' $dispatch
 $record.status='guest-ntfs-rollback-completion-dispatched';$record['taskName']=$dispatch.taskName;$record['guestOutput']=$dispatch.guestOutput
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();throw}
finally{Save 'host-result.json' $record;if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
[pscustomobject]$record
