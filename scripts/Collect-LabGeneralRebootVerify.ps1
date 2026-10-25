<# Collect the native original-tree verifier after a confirmed guest reboot.
   No new VM task, journal replay or disk-attribute change occurs here. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$VerificationDispatchDirectory,[switch]$ReconcileExisting)
Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
$workspace=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $workspace 'lab/Lab.psm1') -Force
$cfg=Get-LabConfiguration;$manifest=Read-LabManifest $cfg win11;$vm=Get-OwnedLabVM $cfg $manifest
$directory=Assert-LabPath $VerificationDispatchDirectory $cfg.Root
$start=Get-Content -LiteralPath (Join-Path $directory 'started.json') -Raw|ConvertFrom-Json
$reboot=Get-Content -LiteralPath (Join-Path $directory 'reboot.json') -Raw|ConvertFrom-Json
$dispatch=Get-Content -LiteralPath (Join-Path $directory 'dispatch.json') -Raw|ConvertFrom-Json
function UtcTicks($Value){if($Value -is [DateTime]){return $Value.ToUniversalTime().Ticks};([DateTimeOffset]::Parse([string]$Value,[Globalization.CultureInfo]::InvariantCulture)).UtcDateTime.Ticks}
if($start.kind-cne'general-postreboot-verification-dispatch'-or$start.stepId-cnotmatch'\A[0-9a-f]{32}\z'-or$start.runId-cnotmatch'\A[0-9a-f]{32}\z'-or$start.experimentId-cnotmatch'\A[0-9a-f]{32}\z'-or$dispatch.taskName-cne('N2R-GeneralReverify-'+$start.stepId)-or$dispatch.guestOutput-cne('C:\ntfs2refs\general-replay\'+$start.runId+'\artifacts\post-reboot-verify-'+$start.stepId+'.json')-or(UtcTicks $reboot.afterUtc)-le(UtcTicks $reboot.beforeUtc)-or$vm.State-ne'Running'-or[guid]$vm.ParentSnapshotId-ne[guid]$start.parentCheckpointId){throw 'Verified reboot, owning VM branch or guest output differs.'}
$collectedPath=Join-Path $directory 'collected.json'
if($ReconcileExisting){
 if(-not(Test-Path -LiteralPath $collectedPath -PathType Leaf)){throw 'No prior collection to reconcile.'}
 $prior=Get-Content -LiteralPath $collectedPath -Raw|ConvertFrom-Json
 $reportPath=Join-Path $directory 'guest-postreboot-verification.json';$report=Get-Content -LiteralPath $reportPath -Raw|ConvertFrom-Json
 if($prior.kind-cne'general-postreboot-native-verification'-or$prior.stepId-cne$start.stepId-or$prior.reportSha256-cne(Get-FileHash -LiteralPath $reportPath).Hash.ToLowerInvariant()-or$prior.lastTaskResult-ne0-or$prior.journalMarker-cne'N2RHND01'){throw 'Saved collection or report pin differs.'}
 $mutationSha=if($start.PSObject.Properties.Name -contains 'mutationReportSha256'){[string]$start.mutationReportSha256}else{$null}
 $mutationOkay=if($mutationSha){$report.post_mutation_root_policy -and$report.mutation_report_sha256-ceq$mutationSha}else{-not$report.post_mutation_root_policy}
 $bootOkay=(UtcTicks $prior.afterBootUtc)-ge(UtcTicks $reboot.afterUtc)
 $success=$report.kind-ceq'general-post-handoff-refs-verification' -and$report.success -and$report.ordinary_tree_verified -and($null-ne$report.native) -and$mutationOkay -and(($null-eq$report.mount_paths_preserved)-or$report.mount_paths_preserved) -and$bootOkay -and-not$prior.sourceOffline -and-not$prior.sourceReadOnly -and$prior.sourceFileSystem-ceq'ReFS' -and$prior.shadowOffline -and$prior.shadowReadOnly
 $result=[ordered]@{schemaVersion=1;kind='general-postreboot-collector-reconciliation';stepId=$start.stepId;originalCollectedSha256=(Get-FileHash -LiteralPath $collectedPath).Hash.ToLowerInvariant();guestReportSha256=$prior.reportSha256;mutationReportSha256=$mutationSha;bootUtcTicksObserved=(UtcTicks $prior.afterBootUtc);bootUtcTicksRequired=(UtcTicks $reboot.afterUtc);utcBootComparisonPassed=[bool]$bootOkay;guestSemanticVerificationPassed=[bool]($report.success-and$report.ordinary_tree_verified);originalTreeVerifiedAfterReboot=[bool]$success;originalReportedSuccess=[bool]$prior.originalTreeVerifiedAfterReboot;productionConversionQualified=$false;capturedUtc=[DateTime]::UtcNow.ToString('o')}
 $path=Join-Path $directory 'reconciled.json';$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 8));$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()};[pscustomobject]$result;return
}
if(Test-Path -LiteralPath $collectedPath){throw 'Post-reboot result already collected; preserve earlier observation.'}
$credential=Import-Clixml (Join-Path $cfg.Root 'win11/secrets/guest-credential.xml');$session=$null
try{
 $deadline=[DateTime]::UtcNow.AddSeconds(180)
 do{try{$session=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop;break}catch{Start-Sleep -Seconds 2}}while([DateTime]::UtcNow-lt$deadline)
 if(-not$session){throw 'Guest session unavailable.'}
 $observed=Invoke-Command -Session $session -ArgumentList @($dispatch.taskName,$dispatch.guestOutput,$start.experimentId) -ScriptBlock {
  param($TaskName,$Output,$ExperimentId)
  Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
  $task=Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop;$info=Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
  if($task.State-in@('Running','Queued')-or$info.LastRunTime.Year-lt2000){return [pscustomobject]@{terminal=$false;taskState=[string]$task.State;lastTaskResult=$info.LastTaskResult}}
  $sha=$null;if(Test-Path -LiteralPath $Output -PathType Leaf){$sha=(Get-FileHash -LiteralPath $Output).Hash.ToLowerInvariant()}
  $journal='J:\ntfs2refs-shadow\'+$ExperimentId+'\reconstruction.journal'
  $marker=$null;if(Test-Path -LiteralPath $journal -PathType Leaf){$stream=[IO.File]::Open($journal,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite);try{$bytes=[byte[]]::new(8);if($stream.Read($bytes,0,8)-eq8){$marker=[Text.Encoding]::ASCII.GetString($bytes)}}finally{$stream.Dispose()}}
  $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
  $filesystem=$null;if(-not$source.IsOffline){try{$volume=Get-Partition -DiskNumber 1 -PartitionNumber 2|Get-Volume;$filesystem=[string]$volume.FileSystem}catch{$filesystem=$null}}
  [pscustomobject]@{terminal=$true;taskState=[string]$task.State;lastTaskResult=$info.LastTaskResult;reportSha256=$sha;journalMarker=$marker;sourceOffline=[bool]$source.IsOffline;sourceReadOnly=[bool]$source.IsReadOnly;sourceFileSystem=$filesystem;shadowOffline=[bool]$shadow.IsOffline;shadowReadOnly=[bool]$shadow.IsReadOnly;bootUtc=([DateTime](Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToUniversalTime().ToString('o')}
 }
 if(-not$observed.terminal){[pscustomobject]@{status='guest-postreboot-verifier-still-running';taskName=$dispatch.taskName;taskState=$observed.taskState};return}
 $report=$null
 if($observed.reportSha256){Copy-Item -LiteralPath $dispatch.guestOutput -Destination (Join-Path $directory 'guest-postreboot-verification.json') -FromSession $session;$actual=(Get-FileHash -LiteralPath (Join-Path $directory 'guest-postreboot-verification.json')).Hash.ToLowerInvariant();if($actual-cne$observed.reportSha256){throw 'Guest post-reboot verifier report changed during export.'};$report=Get-Content -LiteralPath (Join-Path $directory 'guest-postreboot-verification.json') -Raw|ConvertFrom-Json}
 $mutationSha=if($start.PSObject.Properties.Name -contains 'mutationReportSha256'){[string]$start.mutationReportSha256}else{$null}
 $mutationPolicyOkay=if($mutationSha){$mutationSha-cmatch'\A[0-9a-f]{64}\z' -and$report -and$report.post_mutation_root_policy -and$report.mutation_report_sha256-ceq$mutationSha}else{$report-and-not$report.post_mutation_root_policy}
 $mountOkay=$report-and(($null-eq$report.mount_paths_preserved)-or$report.mount_paths_preserved)
 $bootOkay=(UtcTicks $observed.bootUtc)-ge(UtcTicks $reboot.afterUtc)
 $success=$observed.lastTaskResult-eq0 -and$report -and$report.kind-ceq'general-post-handoff-refs-verification' -and$report.success -and$report.ordinary_tree_verified -and$report.native -and$mutationPolicyOkay -and$mountOkay -and$bootOkay -and$observed.journalMarker-ceq'N2RHND01' -and-not$observed.sourceOffline -and-not$observed.sourceReadOnly -and$observed.sourceFileSystem-ceq'ReFS' -and$observed.shadowOffline -and$observed.shadowReadOnly
 $result=[ordered]@{schemaVersion=1;kind='general-postreboot-native-verification';stepId=$start.stepId;runId=$start.runId;mutationReportSha256=$mutationSha;taskName=$dispatch.taskName;terminal=$true;taskState=$observed.taskState;lastTaskResult=$observed.lastTaskResult;reportSha256=$observed.reportSha256;beforeBootUtc=$reboot.beforeUtc;afterBootUtc=$observed.bootUtc;journalMarker=$observed.journalMarker;sourceOffline=$observed.sourceOffline;sourceReadOnly=$observed.sourceReadOnly;sourceFileSystem=$observed.sourceFileSystem;shadowOffline=$observed.shadowOffline;shadowReadOnly=$observed.shadowReadOnly;originalTreeVerifiedAfterReboot=[bool]$success;productionConversionQualified=$false;capturedUtc=[DateTime]::UtcNow.ToString('o')}
 $path=Join-Path $directory 'collected.json';$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 12));$file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 [pscustomobject]$result
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
