<# Launch the normal-file ReFS mutation workload only after a collected,
   durable general handoff. No raw disk or checkpoint mutation here. #>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$FinalizationDirectory,
 [Parameter(Mandatory)][string]$BinaryPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BinarySha256
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$finishedDirectory=Assert-LabPath $FinalizationDirectory $cfg.Root
$finished=Get-Content -LiteralPath (Join-Path $finishedDirectory 'collected.json') -Raw|ConvertFrom-Json
$finishedStart=Get-Content -LiteralPath (Join-Path $finishedDirectory 'started.json') -Raw|ConvertFrom-Json
if($finished.kind-ceq'general-tree-replay-observation'){$parent=$finishedDirectory}elseif($finished.kind-ceq'general-tree-finalize-observation'){$parent=Assert-LabPath $finishedStart.parentDirectory $cfg.Root}else{throw 'Successful general ReFS handoff observation required.'}
$start=Get-Content -LiteralPath (Join-Path $parent 'started.json') -Raw|ConvertFrom-Json
$original=Get-Content -LiteralPath (Join-Path $parent 'dispatch.json') -Raw|ConvertFrom-Json
if(-not$finished.nativeFinishSucceeded-or$finished.journalMarker-cne'N2RHND01'-or$finished.sourceOffline-or$finished.sourceReadOnly-or-not$finished.shadowOffline-or-not$finished.shadowReadOnly-or$start.kind-cne'general-tree-replay-dispatch'-or$start.runId-cnotmatch'\A[0-9a-f]{32}\z'-or$start.experimentId-cnotmatch'\A[0-9a-f]{32}\z'-or$original.guestArtifacts-cne('C:\ntfs2refs\general-replay\'+$start.runId+'\artifacts')-or$vm.State-ne'Running'-or[guid]$vm.ParentSnapshotId-ne[guid]$start.parentCheckpointId){throw 'Converted ReFS guest branch differs.'}
$binary=Get-Item -LiteralPath $BinaryPath -Force
if($binary.PSIsContainer-or($binary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$binary.Length-gt16MB-or(Get-FileHash -LiteralPath $binary.FullName).Hash.ToLowerInvariant()-cne$BinarySha256){throw 'Pinned ReFS mutation executable required.'}
Assert-LabCapacity (Get-LabCapacity $cfg) -AdditionalBytes 256MB
$step=[guid]::NewGuid().ToString('N')
$output=Assert-LabPath (Join-Path $cfg.Root ('general-mutation/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
New-Item -ItemType Directory -Path $output|Out-Null
function Save([string]$Name,$Value){$path=Join-Path $output $Name;$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
$record=[ordered]@{kind='general-refs-mutation-dispatch';stepId=$step;runId=$start.runId;experimentId=$start.experimentId;parentDirectory=$parent;finalizationDirectory=$finishedDirectory;parentCheckpointId=$start.parentCheckpointId;binarySha256=$BinarySha256;requestSha256=$start.requestSha256;status='started';operationCompletionKnown=$true;productionConversionQualified=$false;error=$null}
Save 'started.json' $record
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $deadline=[DateTime]::UtcNow.AddSeconds(180)
 do{try{$session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop;break}catch{Start-Sleep -Seconds 2}}while([DateTime]::UtcNow-lt$deadline)
 if(-not$session){throw 'Guest session unavailable.'}
 $preflight=Invoke-Command -Session $session -ArgumentList @($original.guestArtifacts,$start.experimentId,$start.requestSha256,$step) -ScriptBlock {
  param($Artifacts,$ExperimentId,$RequestSha,$Step)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  if(Get-Process -Name 'lab-general-complete*','lab-general-experiment*','lab-general-refs-mutation*' -ErrorAction SilentlyContinue){throw 'Another converter or mutation task is running.'}
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
  if($source.IsOffline-or$source.IsReadOnly-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly){throw 'Converted source or shadow disk state differs.'}
  $volume=Get-Partition -DiskNumber 1 -PartitionNumber 2|Get-Volume
  if($volume.FileSystem-cne'ReFS'){throw 'Original data disk is not ReFS.'}
  $journal='J:\ntfs2refs-shadow\'+$ExperimentId+'\reconstruction.journal'
  $stream=[IO.File]::Open($journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
  try{$marker=[byte[]]::new(8);if($stream.Read($marker,0,8)-ne8-or[Text.Encoding]::ASCII.GetString($marker)-cne'N2RHND01'){throw 'Durable ReFS handoff marker differs.'}}finally{$stream.Dispose()}
  $request=Join-Path $Artifacts 'request.json';if((Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()-cne$RequestSha){throw 'Guest request pin differs.'}
  $output=Join-Path $Artifacts ('mutation-'+$Step+'.json')
  if(Test-Path -LiteralPath $output){throw 'Fresh mutation output required.'}
  [pscustomobject]@{request=$request;requestSha256=$RequestSha;output=$output;filesystem=[string]$volume.FileSystem;checkedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'preflight.json' $preflight
 $guestExe='C:\ntfs2refs\general-replay\'+$start.runId+'\lab-general-refs-mutation-'+$step+'.exe'
 Copy-Item -LiteralPath $binary.FullName -Destination $guestExe -ToSession $session
 $dispatch=Invoke-Command -Session $session -ArgumentList @($guestExe,$BinarySha256,$preflight,$step) -ScriptBlock {
  param($Exe,$ExeSha,$Preflight,$Step)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  if((Get-FileHash -LiteralPath $Exe).Hash.ToLowerInvariant()-cne$ExeSha-or(Test-Path -LiteralPath $Preflight.output)){throw 'Guest mutation executable or output differs.'}
  $name='N2R-GeneralMutate-'+$Step
  if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Mutation task already exists.'}
  $arguments='--request "'+$Preflight.request+'" --request-sha256 '+$Preflight.requestSha256+' --run-id '+$Step+' --output "'+$Preflight.output+'"'
  $action=New-ScheduledTaskAction -Execute $Exe -Argument $arguments
  $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -ErrorAction Stop|Out-Null
  Start-ScheduledTask -TaskName $name -ErrorAction Stop
  [pscustomobject]@{taskName=$name;taskState=[string](Get-ScheduledTask -TaskName $name).State;guestOutput=$Preflight.output;dispatchedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'dispatch.json' $dispatch
 $record.status='guest-refs-mutation-dispatched';$record['taskName']=$dispatch.taskName;$record['guestOutput']=$dispatch.guestOutput
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();throw}
finally{Save 'host-result.json' $record;if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
[pscustomobject]$record
