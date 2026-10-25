<# Journaled same-partition conversion inside the owning Windows guest.
   The inputs must be the completed ordinary shadow and its measured freeze. #>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$ShadowDirectory,
 [Parameter(Mandatory)][string]$FreezeDirectory,
 [Parameter(Mandatory)][string]$BinaryPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BinarySha256,
 [switch]$Detached,
 [ValidateRange(0,4096)][int]$InterruptAfterWrites=0
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$shadowDirectory=Assert-LabPath $ShadowDirectory $cfg.Root
$freezeDirectory=Assert-LabPath $FreezeDirectory $cfg.Root
$shadowHost=Get-Content (Join-Path $shadowDirectory 'host-result.json') -Raw|ConvertFrom-Json
$start=Get-Content (Join-Path $shadowDirectory 'started.json') -Raw|ConvertFrom-Json
$stepHost=Get-Content (Join-Path $freezeDirectory 'host-result.json') -Raw|ConvertFrom-Json
$stepStart=Get-Content (Join-Path $freezeDirectory 'started.json') -Raw|ConvertFrom-Json
$freeze=Get-Content (Join-Path $freezeDirectory 'report.json') -Raw|ConvertFrom-Json
$shadowRequest=Get-Content (Join-Path $shadowDirectory 'request.json') -Raw|ConvertFrom-Json
$platform=Get-Content (Join-Path $shadowDirectory 'platform.json') -Raw|ConvertFrom-Json
if($shadowHost.status-cne'independent-shadow-built-source-unchanged'-or-not$start.ordinaryFiles-or$stepHost.status-cne'native-step-verified'-or$stepStart.mode-cne'Freeze'-or$stepStart.runId-cne$start.runId-or-not$freeze.success-or-not$freeze.frozen_shadow-or-not$freeze.comparison_request-or$freeze.comparison_request.source_sha256-cne$shadowRequest.source_sha256-or$platform.status-cne'shadow-platform-prepared'-or$platform.runId-cne$start.runId){throw 'Completed, pinned ordinary shadow freeze required.'}
if($vm.State-ne'Running'-or$vm.MemoryStartup-ne8GB-or[guid]$vm.ParentSnapshotId-ne[guid]$shadowHost.shadowCheckpointId){throw 'Only the frozen running owning-guest branch is accepted.'}
Assert-LabCapacity (Get-LabCapacity $cfg) -AdditionalBytes 64MB
$binary=Get-Item -LiteralPath $BinaryPath -Force
if($binary.PSIsContainer-or($binary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$binary.Length-gt16MB-or(Get-FileHash $binary.FullName).Hash.ToLowerInvariant()-cne$BinarySha256){throw 'Pinned converter executable required.'}
$j=$platform.journal
if($j.volumeGuid -cnotmatch '\A\\\\\?\\Volume\{(?<id>[0-9a-fA-F-]{36})\}\\\z'){throw 'Journal volume path differs.'}
$journalGuid=([guid]$Matches.id).ToString('D')
$request=[ordered]@{
 schema_version=3;experiment_id=$start.runId;source=$shadowRequest.source;shadow=$shadowRequest.shadow
 comparison=$freeze.comparison_request
 journal=[ordered]@{disk_number=2;externally_enrolled_disk_unique_id=$platform.journalIdentity.uniqueId;volume_guid=$journalGuid
  identity=[ordered]@{disk_guid=$j.diskGuid;partition_guid=$j.partitionGuid;partition_number=2;disk_bytes=8GB;partition_offset=16MB;partition_bytes=8GB-32MB;logical_sector_bytes=512;physical_sector_bytes=4096}}
 max_journal_bytes=768MB
}
$run=[guid]::NewGuid().ToString('N')
$output=Assert-LabPath (Join-Path $cfg.Root ('ordinary-tree-conversion/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
New-Item -ItemType Directory -Path $output|Out-Null
function Save([string]$Name,$Value){$path=Join-Path $output $Name;$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 32));$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
$record=[ordered]@{kind='ordinary-tree-conversion';runId=$run;experimentId=$start.runId;shadowDirectory=$shadowDirectory;freezeDirectory=$freezeDirectory;binarySha256=$BinarySha256;detached=[bool]$Detached;interruptAfterWrites=$InterruptAfterWrites;status='started';operationCompletionKnown=$true;sourceAdmitted=$false;conversionQualified=$false;error=$null}
Save 'request.json' $request
$requestSha=(Get-FileHash (Join-Path $output 'request.json')).Hash.ToLowerInvariant()
Save 'started.json' $record
Copy-Item -LiteralPath $binary.FullName -Destination (Join-Path $output 'lab-tree-convert.exe')
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null;$job=$null
try{
 $deadline=[DateTime]::UtcNow.AddSeconds(180)
 do{try{$session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop;break}catch{Start-Sleep -Seconds 2}}while([DateTime]::UtcNow-lt$deadline)
 if(-not$session){throw 'Guest session unavailable.'}
 $guestRoot='C:\ntfs2refs\tree-shadow\'+$start.runId
 $guestRequest=$guestRoot+'\conversion-request-'+$run+'.json'
 $guestExe=$guestRoot+'\lab-tree-convert-'+$run+'.exe'
 $guestArtifacts='C:\ntfs2refs\tree-conversion\'+$run
 Copy-Item -LiteralPath $binary.FullName -Destination $guestExe -ToSession $session
 Copy-Item -LiteralPath (Join-Path $output 'request.json') -Destination $guestRequest -ToSession $session
 if($Detached){
  $dispatch=Invoke-Command -Session $session -ArgumentList @($guestExe,$guestRequest,$requestSha,$BinarySha256,$guestArtifacts,$start.runId,$run,$InterruptAfterWrites) -ScriptBlock {
   param($Exe,$Request,$RequestSha,$BinarySha,$Artifacts,$ExperimentId,$Run,$InterruptAfterWrites)
   $ErrorActionPreference='Stop'
   if((Get-FileHash $Exe).Hash.ToLowerInvariant()-cne$BinarySha-or(Get-FileHash $Request).Hash.ToLowerInvariant()-cne$RequestSha){throw 'Guest binary or request pin differs.'}
   if(Get-Process -Name 'lab-tree-shadow*','lab-tree-convert*','lab-tree-reconstruct*' -ErrorAction SilentlyContinue){throw 'Another native converter is running.'}
   $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
   if(-not$source.IsOffline-or-not$source.IsReadOnly-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly){throw 'Frozen source or shadow exclusion differs.'}
   $parent=Split-Path $Artifacts -Parent
   if(-not(Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Path $parent|Out-Null}
   if(Test-Path -LiteralPath $Artifacts){throw 'Fresh recovery directory required.'}
   $journal='J:\ntfs2refs-shadow\'+$ExperimentId+'\reconstruction.journal'
   if(Test-Path -LiteralPath $journal){throw 'Fresh external journal required.'}
   $name='N2R-Convert-'+$Run
   if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Converter task already exists.'}
   $arguments='--request "'+$Request+'" --request-sha256 '+$RequestSha+' --artifacts "'+$Artifacts+'" --journal "'+$journal+'"'
   if($InterruptAfterWrites-gt0){$arguments+=' --interrupt-after-writes '+$InterruptAfterWrites}
   $action=New-ScheduledTaskAction -Execute $Exe -Argument $arguments
   $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
   $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
   Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -ErrorAction Stop|Out-Null
   Start-ScheduledTask -TaskName $name -ErrorAction Stop
   [pscustomobject]@{taskName=$name;state=[string](Get-ScheduledTask -TaskName $name).State;startedUtc=[DateTime]::UtcNow.ToString('o');guestArtifacts=$Artifacts;requestSha256=$RequestSha;binarySha256=$BinarySha}
  }
  Save 'dispatch.json' $dispatch
  $record.status='guest-task-dispatched'
 }else{
 $record.operationCompletionKnown=$false
 $job=Invoke-Command -Session $session -AsJob -ArgumentList @($guestExe,$guestRequest,$requestSha,$BinarySha256,$guestArtifacts,$start.runId,$guestRoot,$run,$InterruptAfterWrites) -ScriptBlock {
  param($Exe,$Request,$RequestSha,$BinarySha,$Artifacts,$ExperimentId,$Root,$Run,$InterruptAfterWrites)
  $ErrorActionPreference='Stop'
  if((Get-FileHash $Exe).Hash.ToLowerInvariant()-cne$BinarySha-or(Get-FileHash $Request).Hash.ToLowerInvariant()-cne$RequestSha){throw 'Guest binary or request pin differs.'}
  if(Get-Process -Name lab-tree-shadow,lab-tree-convert,lab-tree-reconstruct -ErrorAction SilentlyContinue){throw 'Another native converter is running.'}
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
  if(-not$source.IsOffline-or-not$source.IsReadOnly-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly){throw 'Frozen source or shadow exclusion differs.'}
  $parent=Split-Path $Artifacts -Parent
  if(-not(Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Path $parent|Out-Null}
  if(Test-Path -LiteralPath $Artifacts){throw 'Fresh recovery directory required.'}
  $journal='J:\ntfs2refs-shadow\'+$ExperimentId+'\reconstruction.journal'
  if(Test-Path -LiteralPath $journal){throw 'Fresh external journal required.'}
  $psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName=$Exe;$psi.Arguments='--request "'+$Request+'" --request-sha256 '+$RequestSha+' --artifacts "'+$Artifacts+'" --journal "'+$journal+'"';if($InterruptAfterWrites-gt0){$psi.Arguments+=' --interrupt-after-writes '+$InterruptAfterWrites};$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
  $process=[Diagnostics.Process]::new();$process.StartInfo=$psi;if(-not$process.Start()){throw 'Converter did not start.'}
  $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
  [IO.File]::WriteAllText(($Root+'\conversion-'+$Run+'.process.json'),([ordered]@{pid=$process.Id;startedUtc=[DateTime]::UtcNow.ToString('o');arguments=$psi.Arguments}|ConvertTo-Json))
  if(-not$process.WaitForExit(3600000)){throw ('Native converter still live; preserve PID '+$process.Id)}
  [IO.File]::WriteAllText(($Root+'\conversion-'+$Run+'.stdout'),$stdout.Result)
  [IO.File]::WriteAllText(($Root+'\conversion-'+$Run+'.stderr'),$stderr.Result)
  [pscustomobject]@{exitCode=$process.ExitCode;artifacts=$Artifacts;stdoutSha256=(Get-FileHash ($Root+'\conversion-'+$Run+'.stdout')).Hash.ToLowerInvariant()}
 }
 if(-not(Wait-Job $job -Timeout 3700)){throw 'Native operation live or unknown; preserve branch.'}
 $reply=@(Receive-Job $job -ErrorAction Stop);if($job.State-ne'Completed'-or$reply.Count-ne1){throw 'Converter completion unknown.'}
 $record.operationCompletionKnown=$true
 Save 'guest-reply.json' $reply[0]
 foreach($name in @('.process.json','.stdout','.stderr')){Copy-Item -LiteralPath ($guestRoot+'\conversion-'+$run+$name) -Destination (Join-Path $output ('conversion'+$name)) -FromSession $session}
 if((Get-FileHash (Join-Path $output 'conversion.stdout')).Hash.ToLowerInvariant()-cne$reply[0].stdoutSha256){throw 'Guest output export differs.'}
 foreach($name in @('intent.json','request.json','expectation.json','prepare.json','ticket.json','apply.json','finish.json','recovery.json')){
  $guest=Join-Path $reply[0].artifacts $name
  if(Invoke-Command -Session $session -ArgumentList $guest -ScriptBlock {param($p) Test-Path -LiteralPath $p}){Copy-Item -LiteralPath $guest -Destination (Join-Path $output ('guest-'+$name)) -FromSession $session}
 }
 $record.status=if($reply[0].exitCode-eq0){'native-conversion-complete'}else{'native-conversion-failed-preserved'}
 $record['exitCode']=$reply[0].exitCode
 }
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();throw}
finally{Save 'host-result.json' $record;if($job-and$job.State-in@('Completed','Failed','Stopped')){Remove-Job $job -Force};if($session-and$record.operationCompletionKnown){Remove-PSSession $session -ErrorAction SilentlyContinue}}
[pscustomobject]$record
