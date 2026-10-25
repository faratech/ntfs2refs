<# Clean reboot after a successful ReFS mutation, then dispatch one pinned
   read-only native verification of the converted original. #>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$MutationDispatchDirectory,
 [Parameter(Mandatory)][string]$BinaryPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BinarySha256
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$mutationDirectory=Assert-LabPath $MutationDispatchDirectory $cfg.Root
$mutationStart=Get-Content -LiteralPath (Join-Path $mutationDirectory 'started.json') -Raw|ConvertFrom-Json
$mutated=Get-Content -LiteralPath (Join-Path $mutationDirectory 'collected.json') -Raw|ConvertFrom-Json
$parent=Assert-LabPath $mutationStart.parentDirectory $cfg.Root
$start=Get-Content -LiteralPath (Join-Path $parent 'started.json') -Raw|ConvertFrom-Json
$original=Get-Content -LiteralPath (Join-Path $parent 'dispatch.json') -Raw|ConvertFrom-Json
if($mutationStart.kind-cne'general-refs-mutation-dispatch'-or$mutated.kind-cne'general-refs-mutation-observation'-or-not$mutated.mutationSucceeded-or-not$mutated.readyForRebootVerification-or$mutated.stepId-cne$mutationStart.stepId-or$start.kind-cne'general-tree-replay-dispatch'-or$start.runId-cne$mutationStart.runId-or$start.experimentId-cne$mutationStart.experimentId-or$original.guestArtifacts-cne('C:\ntfs2refs\general-replay\'+$start.runId+'\artifacts')-or$vm.State-ne'Running'-or[guid]$vm.ParentSnapshotId-ne[guid]$start.parentCheckpointId){throw 'Completed ReFS mutation and owned VM branch required.'}
$binary=Get-Item -LiteralPath $BinaryPath -Force
if($binary.PSIsContainer-or($binary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$binary.Length-gt16MB-or(Get-FileHash -LiteralPath $binary.FullName).Hash.ToLowerInvariant()-cne$BinarySha256){throw 'Pinned post-reboot verifier required.'}
$step=[guid]::NewGuid().ToString('N')
$output=Assert-LabPath (Join-Path $cfg.Root ('general-postreboot-verify/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
New-Item -ItemType Directory -Path $output|Out-Null
function Save([string]$Name,$Value){$path=Join-Path $output $Name;$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
$record=[ordered]@{kind='general-postreboot-verification-dispatch';stepId=$step;runId=$start.runId;experimentId=$start.experimentId;mutationDirectory=$mutationDirectory;parentDirectory=$parent;parentCheckpointId=$start.parentCheckpointId;binarySha256=$BinarySha256;requestSha256=$start.requestSha256;expectationSha256=$start.expectationSha256;status='started';operationCompletionKnown=$true;rebootCompletionKnown=$false;productionConversionQualified=$false;error=$null}
Save 'started.json' $record
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop
 $preflight=Invoke-Command -Session $session -ArgumentList @($original.guestArtifacts,$start.experimentId,$start.requestSha256,$start.expectationSha256) -ScriptBlock {
  param($Artifacts,$ExperimentId,$RequestSha,$ExpectationSha)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  if(Get-Process -Name 'lab-general-complete*','lab-general-refs-mutation*','lab-general-experiment*' -ErrorAction SilentlyContinue){throw 'Another conversion or mutation process is running.'}
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
  if($source.IsOffline-or$source.IsReadOnly-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly){throw 'Converted source or frozen shadow state differs.'}
  $volume=Get-Partition -DiskNumber 1 -PartitionNumber 2|Get-Volume
  if($volume.FileSystem-cne'ReFS'){throw 'Original data disk is not ReFS.'}
  $request=Join-Path $Artifacts 'request.json';$expectation=Join-Path $Artifacts 'expectation.json'
  if((Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()-cne$RequestSha-or(Get-FileHash -LiteralPath $expectation).Hash.ToLowerInvariant()-cne$ExpectationSha){throw 'Guest verifier inputs differ.'}
  $journal='J:\ntfs2refs-shadow\'+$ExperimentId+'\reconstruction.journal'
  $stream=[IO.File]::Open($journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
  try{$marker=[byte[]]::new(8);if($stream.Read($marker,0,8)-ne8-or[Text.Encoding]::ASCII.GetString($marker)-cne'N2RHND01'){throw 'ReFS journal handoff marker differs.'}}finally{$stream.Dispose()}
  [pscustomobject]@{request=$request;expectation=$expectation;requestSha256=$RequestSha;expectationSha256=$ExpectationSha;bootUtc=([DateTime](Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToUniversalTime().ToString('o')}
 }
 Save 'preflight.json' $preflight
 try{Invoke-Command -Session $session -ScriptBlock {Restart-Computer -Force -ErrorAction Stop} -ErrorAction Stop|Out-Null}catch{$record['restartDispatchObservation']=$_.Exception.Message}
 Remove-PSSession $session -ErrorAction SilentlyContinue;$session=$null
 $deadline=[DateTime]::UtcNow.AddMinutes(7)
 do{Start-Sleep -Seconds 5;try{$vm=Get-OwnedLabVM $cfg $manifest;if($vm.State-eq'Running'){$session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop;$boot=Invoke-Command -Session $session -ScriptBlock {([DateTime](Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToUniversalTime().ToString('o')};if([DateTime]$boot-gt[DateTime]$preflight.bootUtc){break};Remove-PSSession $session -ErrorAction SilentlyContinue;$session=$null}}catch{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue;$session=$null}}}while([DateTime]::UtcNow-lt$deadline)
 if(-not$session){throw 'Guest reboot was not confirmed; do not dispatch verification.'}
 if([guid]$vm.ParentSnapshotId-ne[guid]$start.parentCheckpointId){throw 'VM checkpoint branch changed across reboot.'}
 $record.rebootCompletionKnown=$true
 Save 'reboot.json' ([ordered]@{beforeUtc=$preflight.bootUtc;afterUtc=$boot;vmId=[string]$vm.Id;parentCheckpointId=[string]$vm.ParentSnapshotId})
 $guestExe='C:\ntfs2refs\general-replay\'+$start.runId+'\lab-verify-general-converted-'+$step+'.exe'
 Copy-Item -LiteralPath $binary.FullName -Destination $guestExe -ToSession $session
 $guestOutput=$original.guestArtifacts+'\post-reboot-verify-'+$step+'.json'
 $dispatch=Invoke-Command -Session $session -ArgumentList @($guestExe,$BinarySha256,$preflight,$guestOutput,$step) -ScriptBlock {
  param($Exe,$ExeSha,$Preflight,$Output,$Step)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  if((Get-FileHash -LiteralPath $Exe).Hash.ToLowerInvariant()-cne$ExeSha-or(Test-Path -LiteralPath $Output)){throw 'Guest verifier executable pin or output differs.'}
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3;$volume=Get-Partition -DiskNumber 1 -PartitionNumber 2|Get-Volume
  if($source.IsOffline-or$source.IsReadOnly-or$volume.FileSystem-cne'ReFS'-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly){throw 'Rebooted ReFS source or shadow state differs.'}
  $name='N2R-GeneralReverify-'+$Step
  if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Guest re-verification task already exists.'}
  $arguments='--request "'+$Preflight.request+'" --request-sha256 '+$Preflight.requestSha256+' --expectation "'+$Preflight.expectation+'" --expectation-sha256 '+$Preflight.expectationSha256+' --output "'+$Output+'"'
  $action=New-ScheduledTaskAction -Execute $Exe -Argument $arguments
  $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -ErrorAction Stop|Out-Null
  Start-ScheduledTask -TaskName $name -ErrorAction Stop
  [pscustomobject]@{taskName=$name;taskState=[string](Get-ScheduledTask -TaskName $name).State;guestOutput=$Output;dispatchedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'dispatch.json' $dispatch
 $record.status='guest-postreboot-verifier-dispatched';$record['taskName']=$dispatch.taskName;$record['guestOutput']=$dispatch.guestOutput
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();throw}
finally{Save 'host-result.json' $record;if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
[pscustomobject]$record
