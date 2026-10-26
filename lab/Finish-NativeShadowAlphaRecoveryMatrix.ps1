# Continue the already dispatched resume case, preserve it, then qualify one
# separate shadowless rollback branch. No worker/restore is retried on failure.
[CmdletBinding()]param([ValidateRange(1,240)][int]$MaximumWaitMinutes=180,
 [switch]$ResumeAfterObservedNormalRestore)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
$workspace='D:\code\ntfs2refs';$alpha=Join-Path $workspace '.lab\hyperv\shadow-alpha-20261026'
$resumeCase='c2939b18b2fb4ee8836f859dcf1d13b8'
$rollbackCase='d769b379604c46fd937d5f4fba3a236a'
$vmId=[guid]'0d9bfa66-c66c-4ead-86b7-e72cb5f7e040'
$normalId=[guid]'efa6117b-902f-4495-ba10-c3ac4f23553c'
$baseId=[guid]'7e5582a7-6b15-4531-b77f-9f19cb9e5d47'
$resumeRoot=Join-Path $alpha ('fault-cases\'+$resumeCase)
$controller=Get-Content -LiteralPath (Join-Path $resumeRoot 'resume-controller-intent.json') -Raw|ConvertFrom-Json
if($controller.controller_id-cnotmatch'\A[0-9a-f]{32}\z'-or$controller.case_id-cne$resumeCase-or
 [guid]$controller.vm_id-ne$vmId-or$controller.engine_commit-cne'96720eff89c7e808983c8d5c9800d475fe62515c'){throw 'Existing frozen resume controller required.'}
$postRoot=Join-Path $resumeRoot ('resume-postcheck-'+$controller.controller_id)
if($controller.postcheck_root-cne$postRoot){throw 'Existing controller path differs.'}
function Save([string]$Name,$Value){
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16))
 $f=[IO.File]::Open((Join-Path $alpha $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
}
$helperPins=@{}
foreach($name in @('Preserve-NativeShadowAlphaResume.ps1','Dispatch-NativeShadowAlphaFault.ps1','Complete-NativeShadowAlphaRollback.ps1','Preserve-NativeShadowAlphaNtfsRecovery.ps1')){
 $item=Get-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Force
 if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-gt128KB){throw 'Bounded ordinary matrix helper required.'}
 $helperPins[$name]=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Assert-HelperPin([string]$Name){
 if((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $Name) -Algorithm SHA256).Hash.ToLowerInvariant()-cne$helperPins[$Name]){throw 'Matrix helper changed after dispatch; preserve without action.'}
}
if($ResumeAfterObservedNormalRestore){
 $original=Get-Content -LiteralPath (Join-Path $alpha 'recovery-matrix-intent.json') -Raw|ConvertFrom-Json
 $failure=Get-Content -LiteralPath (Join-Path $alpha 'recovery-matrix-failed-preserved.json') -Raw|ConvertFrom-Json
 $restore=Get-Content -LiteralPath (Join-Path $alpha 'recovery-matrix-restore-intent.json') -Raw|ConvertFrom-Json
 $passed=Get-Content -LiteralPath (Join-Path $resumeRoot 'resume-preserved-checkpoint.json') -Raw|ConvertFrom-Json
 $vm=Get-VM -Id $vmId
 if([guid]$original.vm_id-ne$vmId-or$original.resume_case-cne$resumeCase-or$original.rollback_case-cne$rollbackCase-or
  $original.engine_commit-cne$controller.engine_commit-or$original.resume_controller_id-cne$controller.controller_id-or
  $failure.phase-cne'restore-normal-before-separate-rollback-case'-or$failure.restore_retry-or$failure.automatic_recovery_retry-or
  [guid]$restore.vm_id-ne$vmId-or[guid]$restore.restore_only-ne$normalId-or[guid]$restore.from_preserved_resume-ne[guid]$passed.checkpoint_id-or$restore.force-or
  $passed.case_id-cne$resumeCase-or[guid]$passed.vm_id-ne$vmId-or[guid]$passed.parent_checkpoint-ne$baseId-or$passed.state-cne'Off'-or
  -not$passed.native_verified-or-not$passed.mutation_verified-or-not$passed.reboot_verified-or-not$passed.all_prior_checkpoints_preserved-or
  $vm.Name-cne'ntfs2refs-shadow-alpha-20261026'-or-not$vm.Path.StartsWith($alpha+'\',[StringComparison]::OrdinalIgnoreCase)-or
  $vm.State.ToString()-cne'Off'-or[guid]$vm.ParentSnapshotId-ne$normalId-or
  (Test-Path -LiteralPath (Join-Path $alpha ('fault-cases\'+$rollbackCase)))-or
  (Test-Path -LiteralPath (Join-Path $alpha 'recovery-matrix-restored-normal.json'))){throw 'Only the completed normal restore before rollback dispatch may continue.'}
 foreach($name in $helperPins.Keys){if($helperPins[$name]-cne$original.helper_file_pins.$name){throw 'Originally pinned matrix helper differs.'}}
 $snapshots=@(Get-VMSnapshot -VM $vm)
 foreach($id in @($normalId,$baseId,[guid]$passed.checkpoint_id,[guid]'1cd601b8-c87d-42a8-a105-b1771fdf2b38')){
  if(@($snapshots|Where-Object Id -EQ $id).Count-ne1){throw 'Preserved alpha branch is missing.'}
 }
 Save ('recovery-matrix-continuation-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json') @{vm_id=$vmId.ToString('D');state='Off';observed_parent=$normalId.ToString('D');
  preserved_resume=$passed.checkpoint_id;restore_repeated=$false;rollback_previously_dispatched=$false;original_failure_sha256=(Get-FileHash -LiteralPath (Join-Path $alpha 'recovery-matrix-failed-preserved.json')).Hash.ToLowerInvariant()}
}else{Save 'recovery-matrix-intent.json' @{schema_version=1;vm_id=$vmId.ToString('D');resume_case=$resumeCase;rollback_case=$rollbackCase;
 resume_controller_id=$controller.controller_id;preserved_normal_checkpoint=$normalId.ToString('D');baseline_checkpoint=$baseId.ToString('D');
 engine_commit=$controller.engine_commit;helper_file_pins=$helperPins;no_worker_retry=$true;no_evidence_deletion=$true;created_utc=[DateTime]::UtcNow.ToString('o')}}
$phase='wait-existing-resume-controller'
try{
 if(-not$ResumeAfterObservedNormalRestore){
 $deadline=[DateTime]::UtcNow.AddMinutes($MaximumWaitMinutes)
 while(-not(Test-Path -LiteralPath (Join-Path $postRoot 'result.json'))){
  if(Test-Path -LiteralPath (Join-Path $postRoot 'failed-preserved.json')){throw 'Existing resume controller failed; inspect its exact phase without replay.'}
  if([DateTime]::UtcNow-ge$deadline){throw 'Existing resume controller completion unknown; no retry or restore.'}
  Start-Sleep -Seconds 15
 }
 # Completion writes its result before releasing its host lease. Wait for that
 # release; the preservation helper independently reacquires and checks it.
 $leasePath=Join-Path $alpha 'active-alpha-controller.lock';$released=$false
 while(-not$released-and[DateTime]::UtcNow-lt$deadline){
  try{$f=[IO.File]::Open($leasePath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$f.Dispose();$released=$true}
  catch [IO.IOException]{Start-Sleep -Seconds 3}
 }
 if(-not$released){throw 'Completion lease remains held; preservation is not authorized.'}
 $phase='preserve-completed-resume'
 Assert-HelperPin 'Preserve-NativeShadowAlphaResume.ps1'
 & (Join-Path $PSScriptRoot 'Preserve-NativeShadowAlphaResume.ps1') -CaseId $resumeCase
 $passed=Get-Content -LiteralPath (Join-Path $resumeRoot 'resume-preserved-checkpoint.json') -Raw|ConvertFrom-Json
 $vm=Get-VM -Id $vmId
 if($vm.Name-cne'ntfs2refs-shadow-alpha-20261026'-or$vm.State.ToString()-cne'Off'-or
  [guid]$vm.ParentSnapshotId-ne[guid]$passed.checkpoint_id-or[guid]$passed.parent_checkpoint-ne$baseId){throw 'Resume branch is not preserved OFF.'}
 $snapshots=@(Get-VMSnapshot -VM $vm);$normal=@($snapshots|Where-Object Id -EQ $normalId)
 if($normal.Count-ne1-or@($snapshots|Where-Object Id -EQ ([guid]$passed.checkpoint_id)).Count-ne1-or
  @($snapshots|Where-Object Id -EQ ([guid]'1cd601b8-c87d-42a8-a105-b1771fdf2b38')).Count-ne1){throw 'Earlier passed branches must remain preserved.'}
 $phase='restore-normal-before-separate-rollback-case'
 Save 'recovery-matrix-restore-intent.json' @{vm_id=$vmId.ToString('D');from_preserved_resume=$passed.checkpoint_id;restore_only=$normalId.ToString('D');force=$false}
 Restore-VMSnapshot -VMSnapshot $normal[0] -Confirm:$false -ErrorAction Stop
 $metadataDeadline=[DateTime]::UtcNow.AddSeconds(60)
 do{$vm=Get-VM -Id $vmId
  if($vm.State.ToString()-ceq'Off'-and[guid]$vm.ParentSnapshotId-eq$normalId){break};Start-Sleep -Seconds 2
 }while([DateTime]::UtcNow-lt$metadataDeadline)
 if($vm.State.ToString()-cne'Off'-or[guid]$vm.ParentSnapshotId-ne$normalId){throw 'Restore not observed; do not repeat it.'}
 }
 Save 'recovery-matrix-restored-normal.json' @{vm_id=$vmId.ToString('D');parent=$normalId.ToString('D');state='Off';restore_repeated=$false}
 $phase='dispatch-separate-shadowless-rollback-producer'
 Assert-HelperPin 'Dispatch-NativeShadowAlphaFault.ps1'
 & (Join-Path $PSScriptRoot 'Dispatch-NativeShadowAlphaFault.ps1') -Case RollbackWithoutShadow -CaseId $rollbackCase|Out-Null
 $phase='wait-separate-first-write-interruption'
 $rollbackRoot=Join-Path $alpha ('fault-cases\'+$rollbackCase)
 $dispatch=Get-Content -LiteralPath (Join-Path $rollbackRoot 'dispatch.json') -Raw|ConvertFrom-Json
 if($dispatch.case-cne'RollbackWithoutShadow'-or$dispatch.run_id-cne$rollbackCase-or[guid]$dispatch.vm_id-ne$vmId-or
  $dispatch.expected_exit_code-ne86-or$dispatch.binary_sha256-cne'129ec4cfe6d70812291a343594be1e843f92cc59e3e7bca51c7b8bbb536ed822'){throw 'Separate rollback producer binding differs.'}
 $credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
 $session=New-PSSession -VMId $vmId -Credential $credential -ErrorAction Stop
 try{
  $deadline=[DateTime]::UtcNow.AddMinutes($MaximumWaitMinutes)
  do{
   $vm=Get-VM -Id $vmId
   if($vm.State.ToString()-cne'Running'-or[guid]$vm.ParentSnapshotId-ne$baseId){throw 'Rollback producer branch changed; do not recover.'}
   $observed=Invoke-Command -Session $session -ArgumentList ($dispatch|ConvertTo-Json -Compress) -ScriptBlock {
    param($Text);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop';$d=$Text|ConvertFrom-Json
    $task=Get-ScheduledTask -TaskName $d.task_name;$info=Get-ScheduledTaskInfo -TaskName $d.task_name;$actions=@($task.Actions)
    if($actions.Count-ne1-or$actions[0].Execute-cne$d.binary-or$actions[0].Arguments-cne$d.arguments-or
     $task.Principal.UserId-notin@('SYSTEM','S-1-5-18')-or$task.Principal.RunLevel.ToString()-cne'Highest'){throw 'Exact controlled producer task differs.'}
    $workers=@(Get-CimInstance Win32_Process|Where-Object {$_.Name-match'\A(?:ntfs2refs(?:-bind)?|lab-.+)\.exe\z'})
    $other=@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.TaskName-cne$d.task_name-and$_.State.ToString()-in@('Running','Queued')})
    if($other.Count){throw 'Another guest task is active.'}
    [pscustomobject]@{state=$task.State.ToString();exit_code=$info.LastTaskResult;
     terminal=($task.State.ToString()-in@('Ready','Disabled')-and$info.LastRunTime.Year-ge2000-and$workers.Count-eq0);
     workers=@($workers|Select-Object ProcessId,Name,ReadTransferCount,WriteTransferCount)}
   }
   if($observed.terminal){break}
   if([DateTime]::UtcNow-ge$deadline){throw 'Rollback producer live/unknown; no detach, recovery or redispatch.'}
   Start-Sleep -Seconds 15
  }while($true)
  Save 'recovery-matrix-rollback-producer-terminal.json' $observed
  if($observed.exit_code-ne86){throw 'Separate producer did not stop at first flushed write.'}
 }finally{Remove-PSSession $session -ErrorAction SilentlyContinue}
 $phase='public-shadowless-rollback'
 Assert-HelperPin 'Complete-NativeShadowAlphaRollback.ps1'
 & (Join-Path $PSScriptRoot 'Complete-NativeShadowAlphaRollback.ps1') -CaseId $rollbackCase -MaximumWaitMinutes $MaximumWaitMinutes
 $phase='preserve-completed-rollback'
 Assert-HelperPin 'Preserve-NativeShadowAlphaNtfsRecovery.ps1'
 & (Join-Path $PSScriptRoot 'Preserve-NativeShadowAlphaNtfsRecovery.ps1') -Case RollbackWithoutShadow -CaseId $rollbackCase
 Save 'recovery-matrix-result.json' @{schema_version=1;kind='native-shadow-alpha-bounded-recovery-matrix';success=$true;
  vm_id=$vmId.ToString('D');resume_case=$resumeCase;rollback_without_shadow_case=$rollbackCase;
  controlled_process_fault_only=$true;power_loss_qualified=$false;completed_utc=[DateTime]::UtcNow.ToString('o')}
}catch{
 $failureName=if($ResumeAfterObservedNormalRestore){'recovery-matrix-continuation-failed-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json'}else{'recovery-matrix-failed-preserved.json'}
 Save $failureName @{phase=$phase;error=$_.Exception.ToString();worker_termination_inferred=$false;
  automatic_recovery_retry=$false;restore_retry=$false;observed_utc=[DateTime]::UtcNow.ToString('o')}
 throw
}
