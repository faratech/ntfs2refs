<# Observe one live general-source collector. No restart, mount transition,
   policy change or conversion operation is dispatched here. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$DispatchDirectory)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$directory=Assert-LabPath $DispatchDirectory $cfg.Root
$dispatch=Get-Content -LiteralPath (Join-Path $directory 'dispatch.json') -Raw|ConvertFrom-Json
if($dispatch.kind-cne'general-live-source-admission-dispatch'-or$dispatch.runId-cnotmatch'\A[0-9a-f]{32}\z'-or$dispatch.taskName-cne('N2R-GeneralSource-'+$dispatch.runId)-or$dispatch.guestRoot-cne('C:\ntfs2refs\general-source-admission\'+$dispatch.runId)-or$dispatch.guestOutput-cne($dispatch.guestRoot+'\basis.json')-or[guid]$dispatch.vmId-ne[guid]$vm.Id-or[guid]$dispatch.parentSnapshotId-ne[guid]$vm.ParentSnapshotId-or$vm.State-ne'Running'){throw 'Source observation task or owning VM branch differs.'}
if(Test-Path -LiteralPath (Join-Path $directory 'collected.json')){throw 'Source observation already collected.'}
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop
 $observed=Invoke-Command -Session $session -ArgumentList @($dispatch.taskName,$dispatch.guestOutput) -ScriptBlock {
  param($TaskName,$Output)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  $task=Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop;$info=Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
  if($task.State-in@('Running','Queued')-or$info.LastRunTime.Year-lt2000){return [pscustomobject]@{terminal=$false;state=[string]$task.State;lastTaskResult=$info.LastTaskResult}}
  $sha=$null;$length=$null
  if(Test-Path -LiteralPath $Output){$file=Get-Item -LiteralPath $Output -Force;if($file.PSIsContainer-or($file.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$file.Length-gt64MB){throw 'Source report is not bounded ordinary output.'};$length=$file.Length;$sha=(Get-FileHash -LiteralPath $Output).Hash.ToLowerInvariant()}
  $disk=Get-Disk -Number 1
  [pscustomobject]@{terminal=$true;state=[string]$task.State;lastTaskResult=$info.LastTaskResult;reportSha256=$sha;reportLength=$length;sourceOffline=[bool]$disk.IsOffline;sourceReadOnly=[bool]$disk.IsReadOnly}
 }
 if(-not$observed.terminal){[pscustomobject]@{status='general-source-observation-still-running';taskName=$dispatch.taskName;state=$observed.state};return}
 $report=$null
 if($observed.reportSha256){$path=Join-Path $directory 'basis.json';Copy-Item -LiteralPath $dispatch.guestOutput -Destination $path -FromSession $session;if((Get-Item $path).Length-ne$observed.reportLength-or(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-cne$observed.reportSha256){throw 'Source report changed during export.'};$report=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json}
 if($dispatch.PSObject.Properties.Name-contains'profile'-and$dispatch.profile-ceq'internal-index'){
  if($observed.lastTaskResult-ne0-or-not$report-or$report.kind-cne'frozen-ntfs-internal-index-observation'-or-not$observed.sourceOffline-or-not$observed.sourceReadOnly){throw 'Internal-index observation failed; terminal task preserved.'}
  $result=[ordered]@{kind=$report.kind;reportSha256=$observed.reportSha256;internalIndexes=$report.internal_indexes;internalIndexesError=$report.internal_indexes_error;nativeError=$report.native_error;txf=if($report.native_observation){$report.native_observation.txf}else{$null};sourceAdmitted=$false;executionAuthorized=$false}
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 24));$file=[IO.File]::Open((Join-Path $directory 'collected.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()};[pscustomobject]$result;return
 }
 $assessment=if($report){$report.live_assessment}else{$null}
 $failed=@();$policyBound=$false;$objectsRefused=$null
 if($assessment){$failed=@($assessment.assessment.gates|Where-Object {-not$_.satisfied}|Select-Object code,detail);$policyBound=@($assessment.assessment.gates|Where-Object {$_.code-ceq'volume_policy_flags'-and$_.satisfied}).Count-eq1;$objectsRefused=@($assessment.assessment.objects|Where-Object {$_.disposition-ceq'reject'}).Count}
 $freezeProfile=$dispatch.PSObject.Properties.Name-contains'profile'-and$dispatch.profile-ceq'observed-freeze'
 $basisMatched=if($freezeProfile){$report-and$report.kind-ceq'general-frozen-ntfs-source'-and$report.before.disk_attributes-eq3-and$report.after.disk_attributes-eq3}else{$report-and$report.kind-ceq'general-frozen-ntfs-read-only-basis'-and$report.source_frozen}
 $completed=$observed.lastTaskResult-eq0-and$basisMatched-and$assessment-and-not$report.native_error-and$observed.sourceOffline-and$observed.sourceReadOnly
 $result=[ordered]@{schemaVersion=1;kind='general-live-source-admission-observation';runId=$dispatch.runId;taskName=$dispatch.taskName;terminal=$true;lastTaskResult=$observed.lastTaskResult;reportSha256=$observed.reportSha256;sourceOffline=$observed.sourceOffline;sourceReadOnly=$observed.sourceReadOnly;observationCompleted=[bool]$completed;sourceSha256=if($report){$report.source_sha256}else{$null};nativeError=if($report){$report.native_error}else{'report absent'};shortNamePolicyBound=$policyBound;objectsRefused=$objectsRefused;failedGates=$failed;sourceAdmitted=if($assessment){$assessment.source_admitted}else{$false};executionAuthorized=if($assessment){$assessment.execution_authorized}else{$false};capturedUtc=[DateTime]::UtcNow.ToString('o')}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 12));$file=[IO.File]::Open((Join-Path $directory 'collected.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()};[pscustomobject]$result
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
