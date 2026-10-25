<# Resume only the verifier dispatch after a proven guest reboot and a
   separately verified read-only shadow reattachment. No reboot occurs here. #>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$FailedDispatchDirectory,
 [Parameter(Mandatory)][string]$BinaryPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BinarySha256
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$failed=Assert-LabPath $FailedDispatchDirectory $cfg.Root
$oldStart=Get-Content -LiteralPath (Join-Path $failed 'started.json') -Raw|ConvertFrom-Json
$oldResult=Get-Content -LiteralPath (Join-Path $failed 'host-result.json') -Raw|ConvertFrom-Json
$rebootPath=Join-Path $failed 'reboot.json';$reboot=Get-Content -LiteralPath $rebootPath -Raw|ConvertFrom-Json
if($oldStart.kind-cne'general-postreboot-verification-dispatch'-or$oldResult.status-cne'failed-preserved'-or-not$oldResult.rebootCompletionKnown-or(Test-Path -LiteralPath (Join-Path $failed 'dispatch.json'))-or[guid]$reboot.vmId-ne[guid]$vm.Id-or[guid]$vm.ParentSnapshotId-ne[guid]$oldStart.parentCheckpointId-or[DateTime]$reboot.afterUtc-le[DateTime]$reboot.beforeUtc-or$vm.State-ne'Running'){throw 'Exactly one proven reboot without prior verifier dispatch is required.'}
$parent=Assert-LabPath $oldStart.parentDirectory $cfg.Root
$source=Get-Content -LiteralPath (Join-Path $parent 'started.json') -Raw|ConvertFrom-Json
$original=Get-Content -LiteralPath (Join-Path $parent 'dispatch.json') -Raw|ConvertFrom-Json
if($source.kind-cne'general-tree-replay-dispatch'-or$source.runId-cne$oldStart.runId-or$source.experimentId-cne$oldStart.experimentId-or$source.requestSha256-cne$oldStart.requestSha256-or$source.expectationSha256-cne$oldStart.expectationSha256-or$original.guestArtifacts-cne('C:\ntfs2refs\general-replay\'+$source.runId+'\artifacts')){throw 'Pinned source replay differs.'}
$binary=Get-Item -LiteralPath $BinaryPath -Force
if($binary.PSIsContainer-or($binary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$binary.Length-gt16MB-or(Get-FileHash -LiteralPath $binary.FullName).Hash.ToLowerInvariant()-cne$BinarySha256){throw 'Pinned post-reboot verifier required.'}
$step=[guid]::NewGuid().ToString('N')
$output=Assert-LabPath (Join-Path $cfg.Root ('general-postreboot-verify/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
New-Item -ItemType Directory -Path $output -ErrorAction Stop|Out-Null
function Save([string]$Name,$Value){$path=Join-Path $output $Name;$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
Copy-Item -LiteralPath $rebootPath -Destination (Join-Path $output 'reboot.json') -ErrorAction Stop
$record=[ordered]@{kind='general-postreboot-verification-dispatch';stepId=$step;runId=$source.runId;experimentId=$source.experimentId;parentDirectory=$parent;parentCheckpointId=$source.parentCheckpointId;requestSha256=$source.requestSha256;expectationSha256=$source.expectationSha256;binarySha256=$BinarySha256;rebootEvidenceSource=$failed;rebootEvidenceSha256=(Get-FileHash -LiteralPath $rebootPath).Hash.ToLowerInvariant();status='started';productionConversionQualified=$false;error=$null}
Save 'started.json' $record
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $deadline=[DateTime]::UtcNow.AddSeconds(180)
 do{try{$session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop;break}catch{Start-Sleep -Seconds 2}}while([DateTime]::UtcNow-lt$deadline)
 if(-not$session){throw 'Guest session unavailable.'}
 $preflight=Invoke-Command -Session $session -ArgumentList @($original.guestArtifacts,$source.experimentId,$source.requestSha256,$source.expectationSha256,$reboot.afterUtc) -ScriptBlock {
  param($Artifacts,$Experiment,$RequestSha,$ExpectationSha,$RebootUtc)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  if(Get-Process -Name 'lab-general-complete*','lab-general-refs-mutation*','lab-verify-general-converted*' -ErrorAction SilentlyContinue){throw 'Another converter or verifier is running.'}
  $boot=([DateTime](Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToUniversalTime()
  if($boot-lt[DateTime]$RebootUtc){throw 'Guest boot predates verified reboot.'}
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3;$volume=Get-Partition -DiskNumber 1 -PartitionNumber 2|Get-Volume
  if($source.IsOffline-or$source.IsReadOnly-or$volume.FileSystem-cne'ReFS'-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly){throw 'Rebooted ReFS source or protected shadow differs.'}
  $request=Join-Path $Artifacts 'request.json';$expectation=Join-Path $Artifacts 'expectation.json'
  if((Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()-cne$RequestSha-or(Get-FileHash -LiteralPath $expectation).Hash.ToLowerInvariant()-cne$ExpectationSha){throw 'Guest verifier input pins differ.'}
  $journal='J:\ntfs2refs-shadow\'+$Experiment+'\reconstruction.journal';$stream=[IO.File]::Open($journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
  try{$marker=[byte[]]::new(8);if($stream.Read($marker,0,8)-ne8-or[Text.Encoding]::ASCII.GetString($marker)-cne'N2RHND01'){throw 'Durable ReFS handoff marker differs.'}}finally{$stream.Dispose()}
  [pscustomobject]@{request=$request;expectation=$expectation;requestSha256=$RequestSha;expectationSha256=$ExpectationSha;bootUtc=$boot.ToString('o')}
 }
 Save 'preflight.json' $preflight
 $guestExe='C:\ntfs2refs\general-replay\'+$source.runId+'\lab-verify-general-converted-'+$step+'.exe'
 $guestOutput=$original.guestArtifacts+'\post-reboot-verify-'+$step+'.json'
 Copy-Item -LiteralPath $binary.FullName -Destination $guestExe -ToSession $session
 $dispatch=Invoke-Command -Session $session -ArgumentList @($guestExe,$BinarySha256,$preflight,$guestOutput,$step) -ScriptBlock {
  param($Exe,$ExeSha,$Preflight,$Output,$Step)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  if((Get-FileHash -LiteralPath $Exe).Hash.ToLowerInvariant()-cne$ExeSha-or(Test-Path -LiteralPath $Output)){throw 'Guest verifier binary pin or fresh output differs.'}
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3;$volume=Get-Partition -DiskNumber 1 -PartitionNumber 2|Get-Volume
  if($source.IsOffline-or$source.IsReadOnly-or$volume.FileSystem-cne'ReFS'-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly){throw 'Guest device state changed before verifier dispatch.'}
  $name='N2R-GeneralReverify-'+$Step
  if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Verifier task already exists.'}
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
