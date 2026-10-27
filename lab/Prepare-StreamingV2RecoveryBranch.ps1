# Restore only the owned streaming NTFS baseline after preserving its passed
# converted branch. Never delete/merge a checkpoint or touch an older VM.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$baselineId=[guid]'775f4db8-8635-486c-b6eb-7098426b51a6'
$passedId=[guid]'157284d6-91fc-4b2b-ba6c-3052a0c413bc'
$vm=Get-VM -Id $id
if($vm.State.ToString()-cne'Off'-or$vm.ParentSnapshotId-ne$passedId-or
    $vm.Name-cne'ntfs2refs-streaming-v2-20261027'-or-not$vm.Path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){
    throw 'Exact OFF preserved streaming branch required.'
}
$snapshots=@(Get-VMSnapshot -VM $vm)
foreach($required in @($baselineId,$passedId,[guid]'8d4b9eaa-d814-4a3a-aa89-056e817d47d2',
    [guid]'2a265703-70bc-44fd-a0c5-49999384b9db',[guid]'beddfbe8-f40d-4903-9c2c-c6162b3b4349')){
    if($snapshots.Id-notcontains$required){throw 'A required preserved checkpoint is missing.'}
}
$report=Get-Content -LiteralPath (Join-Path $root 'candidate3/rust-postcheck/AfterReboot.json') -Raw|ConvertFrom-Json
$checkpoint=Get-Content -LiteralPath (Join-Path $root 'candidate3/passed-checkpoint.json') -Raw|ConvertFrom-Json
if(-not$report.success-or$report.run_id-cne'e5d4b7dfa9474dedb3e19b67c1b03f24'-or[guid]$checkpoint.checkpoint_id-ne$passedId){throw 'Matching successful preserved conversion required.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
Assert-LabCapacity -Capacity $capacity -AdditionalBytes 6GB
$path=Join-Path $root 'streaming-recovery-branch-intent.json'
$f=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes((@{vm_id=$id;preserved_passed=$passedId;restore_baseline=$baselineId;
    all_checkpoints=@($snapshots.Id);purpose='new pre-handoff streaming interruption and recovery branch';capacity=$capacity;
    utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 6));$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
Restore-VMSnapshot -VMSnapshot ($snapshots|Where-Object Id -eq $baselineId) -Confirm:$false
'Restore issued once. Confirm the OFF baseline from a fresh process before dispatch.'
