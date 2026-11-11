# Preserve the terminal pre-handoff partial image. No recovery, force shutdown,
# disk-state repair, checkpoint deletion, restore or second producer dispatch.
[CmdletBinding()]param([Parameter(Mandatory)][ValidatePattern('^candidate(?:[2-9]|[1-9][0-9]+)$')][string]$Candidate)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace ('.lab\hyperv\streaming-v2-20261027\'+$Candidate)
$d=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
if([guid]$d.vm_id-ne[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'-or$d.interrupt_after_writes-ne1-or$d.expected_exit_code-ne86){throw 'Exact one-write interrupted fixture required.'}
$archive=Get-Content -LiteralPath (Join-Path $root 'terminal-evidence-manifest.json') -Raw|ConvertFrom-Json
if(-not$archive.verified-or$archive.run_id-cne$d.run_id){throw 'Verified matching terminal archive required.'}
if(Test-Path -LiteralPath (Join-Path $root 'preserve-interruption-intent.json')){throw 'Preservation already attempted; inspect existing state.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 32MB
$vm=Get-VM -Id $d.vm_id
$retained=$d.PSObject.Properties.Name-contains'controlled_retained_recovery'-and$d.controlled_retained_recovery
$expectedParent=if($retained){[guid]'6ffb6bdc-4da6-4060-8b4e-0c07a83d11b3'}else{[guid]'775f4db8-8635-486c-b6eb-7098426b51a6'}
if($retained-and($Candidate-cne'candidate13'-or$d.max_journal_bytes-ne1536MB-or-not$d.refresh_existing_system_cache-or-not$d.frozen_shadow_reuse)){
    throw 'Controlled retained interruption binding differs.'
}
if($vm.Name-cne'ntfs2refs-streaming-v2-20261027'-or$vm.State.ToString()-cne'Running'-or
    $vm.ParentSnapshotId-ne$expectedParent){throw 'Running interrupted baseline child required.'}
$cred=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$state=Invoke-Command -VMId $d.vm_id -Credential $cred -ArgumentList $d.task_name,$d.guest_output -ScriptBlock {
    param($Task,$Output);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
    $t=Get-ScheduledTask -TaskName $Task;$info=Get-ScheduledTaskInfo -TaskName $Task
    if($t.State.ToString()-in@('Running','Queued')-or$info.LastTaskResult-ne86-or
        @(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'-or$_.Name-ceq'lab-convert-admitted-tree.exe'}).Count){throw 'Producer must be terminal at exit 86.'}
    $intent=Get-Content -LiteralPath (Join-Path $Output 'interruption-intent.json') -Raw|ConvertFrom-Json
    if($intent.interrupt_after_writes-ne1-or$intent.handoff_authorized-or
        (Test-Path -LiteralPath (Join-Path $Output 'apply.json'))-or(Test-Path -LiteralPath (Join-Path $Output 'finalization.json'))-or
        (Test-Path -LiteralPath (Join-Path $Output 'result.json'))){throw 'Expected partial pre-handoff boundary differs.'}
    $target=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
    if(-not$target.IsOffline-or$target.IsReadOnly-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly-or$target.IsBoot-or$target.IsSystem){throw 'Persistent source/shadow exclusion differs.'}
    [pscustomobject]@{task_result=$info.LastTaskResult;target_offline=$target.IsOffline;target_readonly=$target.IsReadOnly;
        shadow_offline=$shadow.IsOffline;shadow_readonly=$shadow.IsReadOnly;boot_utc=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');utc=[DateTime]::UtcNow.ToString('o')}
}
function Save-New([string]$Name,$Value){
    $f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 7));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}
}
Save-New 'preserve-interruption-intent.json' @{vm_id=$d.vm_id;run_id=$d.run_id;state=$state;utc=[DateTime]::UtcNow.ToString('o')}
Stop-VM -VM $vm -Confirm:$false -ErrorAction Stop
# Query the provider directly rather than relying on a cached VM state property.
$system=Get-CimInstance -Namespace 'root/virtualization/v2' -ClassName Msvm_ComputerSystem -Filter "Name='2401593c-4b30-472e-9b6d-c9534cbaa599'"
if($system.EnabledState-ne3){throw 'Clean OFF state not established; no forced stop or checkpoint.'}
$checkpoint=Checkpoint-VM -VM (Get-VM -Id $d.vm_id) -SnapshotName ('streaming-v2-'+$Candidate+'-one-write-interrupted') -Passthru
Save-New 'interrupted-checkpoint.json' @{vm_id=$d.vm_id;run_id=$d.run_id;checkpoint_id=$checkpoint.Id;name=$checkpoint.Name;parent=$checkpoint.ParentSnapshotId;state='Off';utc=[DateTime]::UtcNow.ToString('o')}
$checkpoint|Select-Object Id,Name,ParentSnapshotId|ConvertTo-Json -Compress
