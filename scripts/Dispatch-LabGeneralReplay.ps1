<# Stage a pinned general-tree replay and launch one durable task inside the
   enrolled VM. Never restores a checkpoint or modifies a guest data disk. #>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$ReplayDirectory,
 [Parameter(Mandatory)][string]$ShadowDirectory,
 [Parameter(Mandatory)][string]$BinaryPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$BinarySha256,
 [ValidateRange(0,4096)][int]$InterruptAfterWrites=0
)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$replay=Assert-LabPath $ReplayDirectory (Join-Path $workspace '.lab/development')
$shadow=Assert-LabPath $ShadowDirectory $cfg.Root
$pins=Get-Content -LiteralPath (Join-Path $replay 'pins.json') -Raw|ConvertFrom-Json
$shadowHost=Get-Content -LiteralPath (Join-Path $shadow 'host-result.json') -Raw|ConvertFrom-Json
$requestPath=Join-Path $replay 'general-request.json';$expectationPath=Join-Path $replay 'expected-tree.json'
$request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
if($pins.kind-cne'pinned-general-tree-replay'-or$shadowHost.status-cne'independent-shadow-built-source-unchanged'-or$vm.State-ne'Running'-or$vm.MemoryStartup-ne8GB-or[guid]$vm.ParentSnapshotId-ne[guid]$shadowHost.shadowCheckpointId-or$request.schema_version-ne1-or$request.pair.source.disk_number-ne1-or$request.pair.shadow.disk_number-ne3-or$request.journal.disk.disk_number-ne2-or$request.experiment_id-cnotmatch'\A[0-9a-f]{32}\z'){throw 'Enrolled frozen-shadow VM branch or replay request differs.'}
if((Get-FileHash -LiteralPath $requestPath).Hash.ToLowerInvariant()-cne$pins.general_request_sha256-or(Get-FileHash -LiteralPath $expectationPath).Hash.ToLowerInvariant()-cne$pins.expected_tree_sha256-or$request.expected_tree_sha256-cne$pins.expected_tree_sha256-or$request.comparison.source_sha256-cne$pins.source_sha256-or$request.comparison.shadow_sha256-cne$pins.shadow_sha256){throw 'Pinned general replay content differs.'}
$binary=Get-Item -LiteralPath $BinaryPath -Force
if($binary.PSIsContainer-or($binary.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$binary.Length-gt16MB-or(Get-FileHash -LiteralPath $binary.FullName).Hash.ToLowerInvariant()-cne$BinarySha256){throw 'Pinned guest converter executable required.'}
Assert-LabCapacity (Get-LabCapacity $cfg) -AdditionalBytes 64MB
$run=[guid]::NewGuid().ToString('N')
$output=Assert-LabPath (Join-Path $cfg.Root ('general-replay/win11-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))) $cfg.Root
New-Item -ItemType Directory -Path $output|Out-Null
function Save([string]$Name,$Value){$path=Join-Path $output $Name;$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 24));$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
$record=[ordered]@{kind='general-tree-replay-dispatch';runId=$run;experimentId=$request.experiment_id;replayDirectory=$replay;shadowDirectory=$shadow;parentCheckpointId=[string]$vm.ParentSnapshotId;requestSha256=$pins.general_request_sha256;expectationSha256=$pins.expected_tree_sha256;binarySha256=$BinarySha256;interruptAfterWrites=$InterruptAfterWrites;status='started';operationCompletionKnown=$true;productionConversionQualified=$false;error=$null}
Save 'started.json' $record
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $deadline=[DateTime]::UtcNow.AddSeconds(180)
 do{try{$session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop;break}catch{Start-Sleep -Seconds 2}}while([DateTime]::UtcNow-lt$deadline)
 if(-not$session){throw 'Guest session unavailable.'}
 $preflight=Invoke-Command -Session $session -ArgumentList @($request,$run) -ScriptBlock {
  param($Request,$Run)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3;$journal=Get-Disk -Number 2
  if(-not$source.IsOffline-or-not$source.IsReadOnly-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly-or$journal.IsOffline-or$journal.IsReadOnly-or$source.IsBoot-or$source.IsSystem-or[guid]$source.Guid-ne[guid]$Request.pair.source.identity.disk_guid-or[guid]$shadow.Guid-ne[guid]$Request.pair.shadow.identity.disk_guid-or[guid]$journal.Guid-ne[guid]$Request.journal.disk.identity.disk_guid){throw 'Guest source/shadow/journal state or GPT identity differs.'}
  if(Get-Process -Name 'lab-tree-convert*','lab-general-complete*','lab-recover-general-journal*' -ErrorAction SilentlyContinue){throw 'Another conversion process is running.'}
  $journalPath='J:\ntfs2refs-shadow\'+$Request.experiment_id+'\reconstruction.journal'
  if(Test-Path -LiteralPath $journalPath){throw 'External journal is not fresh.'}
  $journalParent=Split-Path $journalPath -Parent
  if(-not(Test-Path -LiteralPath $journalParent -PathType Container)){throw 'Journal parent directory is absent.'}
  $root='C:\ntfs2refs\general-replay\'+$Run
  if(Test-Path -LiteralPath $root){throw 'Fresh guest replay directory required.'}
  [pscustomobject]@{sourceOffline=$source.IsOffline;sourceReadOnly=$source.IsReadOnly;shadowOffline=$shadow.IsOffline;shadowReadOnly=$shadow.IsReadOnly;journalPath=$journalPath;guestRoot=$root;checkedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'preflight.json' $preflight
 $guestRoot=$preflight.guestRoot
 Invoke-Command -Session $session -ArgumentList $guestRoot -ScriptBlock {param($Root)Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$parent=Split-Path $Root -Parent;if(-not(Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Path $parent|Out-Null};if((Get-Item -LiteralPath $parent).Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Guest replay parent is a reparse point.'};New-Item -ItemType Directory -Path $Root -ErrorAction Stop|Out-Null}
 $guestExe=$guestRoot+'\lab-general-complete.exe';$guestRequest=$guestRoot+'\general-request.json';$guestExpectation=$guestRoot+'\expected-tree.json';$guestArtifacts=$guestRoot+'\artifacts'
 Copy-Item -LiteralPath $binary.FullName -Destination $guestExe -ToSession $session
 Copy-Item -LiteralPath $requestPath -Destination $guestRequest -ToSession $session
 Copy-Item -LiteralPath $expectationPath -Destination $guestExpectation -ToSession $session
 $dispatch=Invoke-Command -Session $session -ArgumentList @($guestExe,$guestRequest,$guestExpectation,$guestArtifacts,$preflight.journalPath,$BinarySha256,$pins.general_request_sha256,$pins.expected_tree_sha256,$run,$InterruptAfterWrites) -ScriptBlock {
  param($Exe,$Request,$Expectation,$Artifacts,$Journal,$ExeSha,$RequestSha,$ExpectationSha,$Run,$InterruptAfterWrites)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  if((Get-FileHash -LiteralPath $Exe).Hash.ToLowerInvariant()-cne$ExeSha-or(Get-FileHash -LiteralPath $Request).Hash.ToLowerInvariant()-cne$RequestSha-or(Get-FileHash -LiteralPath $Expectation).Hash.ToLowerInvariant()-cne$ExpectationSha){throw 'Guest executable or replay input pin differs.'}
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
  if(-not$source.IsOffline-or-not$source.IsReadOnly-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly){throw 'Guest data disk exclusion changed before dispatch.'}
  $name='N2R-General-'+$Run
  if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Guest general replay task already exists.'}
  $arguments='--request "'+$Request+'" --request-sha256 '+$RequestSha+' --expectation "'+$Expectation+'" --expectation-sha256 '+$ExpectationSha+' --journal "'+$Journal+'" --artifacts "'+$Artifacts+'"'
  if($InterruptAfterWrites-gt0){$arguments+=' --interrupt-after-writes '+$InterruptAfterWrites}
  $action=New-ScheduledTaskAction -Execute $Exe -Argument $arguments
  $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 6) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -ErrorAction Stop|Out-Null
  Start-ScheduledTask -TaskName $name -ErrorAction Stop
  [pscustomobject]@{taskName=$name;taskState=[string](Get-ScheduledTask -TaskName $name).State;guestArtifacts=$Artifacts;journalPath=$Journal;dispatchedUtc=[DateTime]::UtcNow.ToString('o')}
 }
 Save 'dispatch.json' $dispatch
 $record.status='guest-general-task-dispatched';$record['taskName']=$dispatch.taskName;$record['guestArtifacts']=$dispatch.guestArtifacts
}catch{$record.status='failed-preserved';$record.error=$_.Exception.ToString();throw}
finally{Save 'host-result.json' $record;if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
[pscustomobject]$record
