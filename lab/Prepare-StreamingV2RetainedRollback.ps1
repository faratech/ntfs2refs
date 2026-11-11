# Preserve the independently verified recovered ReFS branch before restoring
# ONLY the saved pre-handoff partial checkpoint for a separate rollback fork.
[CmdletBinding()]param([Parameter(Mandatory)][ValidateSet('PreserveResume','RestorePartial')][string]$Phase)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\candidate13'
$d=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
$partial=Get-Content -LiteralPath (Join-Path $root 'interrupted-checkpoint.json') -Raw|ConvertFrom-Json
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
if([guid]$d.vm_id-ne$id-or-not$d.controlled_retained_recovery-or$d.run_id-cne'2fa6edb2e7ac464ca863a5db6dbd6f5c'-or
    [guid]$partial.checkpoint_id-ne[guid]'4d73dd8d-d105-4f90-a277-3cab79df9e55'-or$partial.run_id-cne$d.run_id){throw 'Exact retained partial checkpoint required.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$vm=Get-VM -Id $id;$old=@(Get-VMSnapshot -VM $vm);$oldIds=@($old|ForEach-Object {$_.Id.ToString()})
if($oldIds-notcontains([string]$partial.checkpoint_id)-or$oldIds-notcontains'49094105-ed4b-4447-9f23-86a3a22b394f'){
    throw 'Protected partial and passed original conversion checkpoints must remain.'
}
function Save-New([string]$name,$value){$f=[IO.File]::Open((Join-Path $root $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 20));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
if($Phase-ceq'RestorePartial'){
    $saved=Get-Content -LiteralPath (Join-Path $root 'recovered-refs-checkpoint.json') -Raw|ConvertFrom-Json
    if(-not$saved.success-or$saved.run_id-cne$d.run_id-or$vm.State.ToString()-cne'Off'-or
        $vm.ParentSnapshotId-ne[guid]$saved.checkpoint_id-or(Test-Path -LiteralPath (Join-Path $root 'rollback-partial-restore-intent.json'))){throw 'Saved OFF recovered outcome and fresh restore intent required.'}
    Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 2GB
    Save-New 'rollback-partial-restore-intent.json' @{run_id=$d.run_id;vm_id=$id.ToString();preserved_recovered_checkpoint=$saved.checkpoint_id;
        restore_partial_checkpoint=$partial.checkpoint_id;all_checkpoint_ids=$oldIds;never_replay_on_handed_off_branch=$true;utc=[DateTime]::UtcNow.ToString('o')}
    Restore-VMSnapshot -VMSnapshot ($old|Where-Object Id -eq ([guid]$partial.checkpoint_id)) -Confirm:$false
    Save-New 'rollback-partial-restore-issued.json' @{issued_once=$true;utc=[DateTime]::UtcNow.ToString('o')}
    'Restore issued once; verify the OFF partial parent from a fresh process before Branch Rollback boot.'
    return
}
$proof=Get-Content -LiteralPath (Join-Path $root 'recovery-resume\native-postcheck\result.json') -Raw|ConvertFrom-Json
if(-not$proof.success-or$proof.run_id-cne$d.run_id-or$proof.verified_retained_bytes-ne2721431552-or
    $vm.State.ToString()-cne'Running'-or$vm.ParentSnapshotId-ne[guid]$partial.checkpoint_id-or$old.Count-ne21-or
    (Test-Path -LiteralPath (Join-Path $root 'recovered-refs-preservation-intent.json'))){throw 'Independently verified running recovered branch required.'}
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 256MB
$final=Get-Content -LiteralPath (Join-Path $root 'recovery-resume\Finalize-dispatch.json') -Raw|ConvertFrom-Json
$verifier=Get-Content -LiteralPath (Join-Path $root 'recovery-resume\native-postcheck\dispatch.json') -Raw|ConvertFrom-Json
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$s=New-PSSession -VMId $id -Credential $credential
try{
    $inventory=Invoke-Command -Session $s -ArgumentList $final.guest_output,$final.task_name,$verifier.task_name -ScriptBlock {
        param($Output,$FinalTask,$VerifyTask);$ErrorActionPreference='Stop'
        foreach($task in @($FinalTask,$VerifyTask)){if((Get-ScheduledTask -TaskName $task).State.ToString()-cne'Ready'-or(Get-ScheduledTaskInfo -TaskName $task).LastTaskResult-ne0){throw 'Finalizer and verifier must be terminal successful.'}}
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-in@('ntfs2refs.exe','ntfs2refs-recover.exe','lab-convert-admitted-tree.exe','lab-verify-general-converted.exe')}).Count){throw 'A worker is live.'}
        $base=Split-Path -Parent $Output;$items=@(Get-ChildItem -LiteralPath $base -Recurse -Force)
        if(@($items|Where-Object {$_.Attributes-band[IO.FileAttributes]::ReparsePoint}).Count){throw 'Evidence redirects are forbidden.'}
        $files=@($items|Where-Object {-not$_.PSIsContainer});if($files.Count-gt64-or($files|Measure-Object Length -Sum).Sum-gt256MB-or@($files|Where-Object Length -gt 64MB).Count){throw 'Recovery evidence exceeds bound.'}
        $rows=@(foreach($file in $files){@{relative=$file.FullName.Substring($base.Length+1);bytes=$file.Length;sha256=(Get-FileHash -LiteralPath $file.FullName).Hash.ToLowerInvariant()}})
        Set-StrictMode -Off
        @{guest_base=$base;files=$rows}
    }
    Save-New 'recovered-refs-preservation-intent.json' @{run_id=$d.run_id;vm_id=$id.ToString();all_checkpoint_ids=$oldIds;native_report_sha256=$proof.report_sha256;utc=[DateTime]::UtcNow.ToString('o');force_power_off=$false}
    $archive=Join-Path $root 'recovered-refs-terminal-evidence';if(Test-Path -LiteralPath $archive){throw 'Recovery archive already exists.'};New-Item -ItemType Directory -Path $archive|Out-Null
    foreach($row in $inventory.files){if([IO.Path]::IsPathRooted($row.relative)-or$row.relative.Split('\')-contains'..'){throw 'Archive path escape.'};$out=Join-Path $archive $row.relative;$parent=Split-Path -Parent $out;if(-not(Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Path $parent|Out-Null};Copy-Item -LiteralPath (Join-Path $inventory.guest_base $row.relative) -FromSession $s -Destination $out;if((Get-Item -LiteralPath $out).Length-ne$row.bytes-or(Get-FileHash -LiteralPath $out).Hash.ToLowerInvariant()-cne$row.sha256){throw 'Archived recovery artifact differs.'}}
    Save-New 'recovered-refs-terminal-manifest.json' @{verified=$true;run_id=$d.run_id;inventory=$inventory;utc=[DateTime]::UtcNow.ToString('o')}
}finally{Remove-PSSession $s}
Stop-VM -VM (Get-VM -Id $id) -Confirm:$false
$off=Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_ComputerSystem -Filter "Name='$id'"
if($off.EnabledState-ne3-or(Get-VM -Id $id).State.ToString()-cne'Off'){throw 'Clean OFF not confirmed; never force stop.'}
$checkpoint=Checkpoint-VM -VM (Get-VM -Id $id) -SnapshotName 'streaming-v2-candidate13-resumed-native-verified' -Passthru
$now=@(Get-VMSnapshot -VM (Get-VM -Id $id)|ForEach-Object {$_.Id.ToString()})
if($now.Count-ne22-or@($oldIds|Where-Object {$_-notin$now}).Count){throw 'Checkpoint inventory differs; preserve state.'}
$result=@{success=$true;run_id=$d.run_id;vm_id=$id.ToString();checkpoint_id=$checkpoint.Id.ToString();parent_id=$checkpoint.ParentSnapshotId.ToString();all_prior_preserved=$true;checkpoint_count=$now.Count;state='Off';utc=[DateTime]::UtcNow.ToString('o')}
Save-New 'recovered-refs-checkpoint.json' $result;$result|ConvertTo-Json -Compress
