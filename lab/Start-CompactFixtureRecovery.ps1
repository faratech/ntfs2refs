# Single dispatch on an explicitly selected saved branch. Never restores a VM.
[CmdletBinding()]param(
    [Parameter(Mandatory)][ValidateSet('Interrupt','Resume','Rollback','Finalize','FinalizeRollback')][string]$Operation,
    [Parameter(Mandatory)][guid]$ExpectedParent,
    [Parameter(Mandatory)][ValidateRange(37,200)][int]$ExpectedCheckpointCount
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$root=Join-Path $workspace ('.lab\hyperv\streaming-v2-20261027\compact-recovery-20261028\'+$Operation.ToLowerInvariant())
if(Test-Path -LiteralPath $root){throw 'Recovery role has state; observe without redispatch.'}
if($Operation-eq'Interrupt'-and$ExpectedParent-ne[guid]'5971d348-3f8b-4696-bef6-4c1f164fbf64'){throw 'Interrupt starts only from preserved original preapply branch.'}
$vm=Get-VM -Id $id;$old=@(Get-VMSnapshot -VM $vm|ForEach-Object {$_.Id.ToString()})
if($vm.State.ToString()-cne'Off'-or$vm.ParentSnapshotId-ne$ExpectedParent-or$old.Count-ne$ExpectedCheckpointCount-or$vm.MemoryStartup-ne4GB-or$vm.DynamicMemoryEnabled-or@(Get-VMNetworkAdapter -VM $vm).Count){throw 'Exact isolated saved branch required.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$allowance=if($Operation-eq'Interrupt'){1GB}else{[long]1.5GB}
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes $allowance
$binary=Join-Path $workspace 'target\release\lab-apply-compact-fixture.exe';$pin=(Get-FileHash $binary).Hash.ToLowerInvariant();$run=[guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path $root -Force|Out-Null
function Save-New([string]$Name,$Value){$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 8));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
Save-New 'intent.json' @{run_id=$run;operation=$Operation;vm_id=$id.ToString();parent_id=$ExpectedParent.ToString();old_checkpoint_ids=$old;binary_sha256=$pin;source_commit=(& git -C $workspace rev-parse HEAD).Trim();exact_fixture_only=$true;fixture_writes_authorized=$true;additional_bytes=$allowance;utc=[DateTime]::UtcNow.ToString('o')}
Copy-Item -LiteralPath $binary -Destination (Join-Path $root 'producer.exe')
Start-VM -VM $vm|Out-Null
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml');$s=$null;$deadline=[DateTime]::UtcNow.AddMinutes(5)
while($null-eq$s){try{$s=New-PSSession -VMId $id -Credential $credential -ErrorAction Stop}catch{if([DateTime]::UtcNow-ge$deadline){throw 'Single boot unavailable; never repeat on timeout.'};Start-Sleep -Seconds 3}}
try{
    $stage='C:\ntfs2refs\compact-recovery-'+$run
    $ready=Invoke-Command -Session $s -ArgumentList $stage,$Operation -ScriptBlock {
        param($Stage,$Operation);$ErrorActionPreference='Stop';$src=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
        $wantRO=$Operation-eq'Interrupt'
        if([guid]$src.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or[guid]$shadow.Guid-ne[guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f'-or-not$src.IsOffline-or$src.IsReadOnly-ne$wantRO-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly-or(Test-Path $Stage)-or@(Get-CimInstance Win32_Process|Where-Object Name -eq 'lab-apply-compact-fixture.exe').Count){throw 'Exact excluded source state/fresh stage required.'}
        $j='J:\n2r-compact-journal-a1aa7a957b094f7bbe9af154ee7270eb'
        $marker=New-Object byte[] 4096;$f=[IO.File]::OpenRead((Join-Path $j 'journal.bin'));try{if($f.Read($marker,0,4096)-ne4096){throw 'Journal marker short'}}finally{$f.Dispose()}
        if($Operation-in@('Interrupt','Resume','Rollback')-and@($marker|Where-Object {$_-ne0}).Count){throw 'Handoff/replay marker is nonzero; refuse apply/recovery.'}
        if((Get-FileHash (Join-Path $j 'request.json')).Hash.ToLowerInvariant()-cne'33d18d9f77ebeba339feb71cc4471852bb2c3f3b6edc283fff93fc3f9d7e27d7'-or(Get-FileHash (Join-Path $j 'ticket.json')).Hash.ToLowerInvariant()-cne'c07d1a49e8ba36b843214dab822ab8c335dfd51146f144bd5f64d2c37fc5f2c4'){throw 'Immutable request/ticket differs.'}
        New-Item -ItemType Directory -Path $Stage|Out-Null
        @{source_offline=$src.IsOffline;source_readonly=$src.IsReadOnly;shadow_offline=$true;shadow_readonly=$true;operation=$Operation}
    }
    Save-New 'boot-exclusion.json' $ready
    Copy-Item -LiteralPath $binary -ToSession $s -Destination ([IO.Path]::Combine($stage,'lab-apply-compact-fixture.exe'))
    $dispatch=Invoke-Command -Session $s -ArgumentList $stage,$run,$pin,$Operation -ScriptBlock {
        param($Stage,$Run,$Pin,$Operation);$ErrorActionPreference='Stop';$binary=Join-Path $Stage 'lab-apply-compact-fixture.exe';$task='N2R-CompactRecovery-'+$Operation+'-'+$Run
        if((Get-FileHash $binary).Hash.ToLowerInvariant()-cne$Pin-or(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)){throw 'Fresh pinned task required.'}
        $mode=switch($Operation){'Interrupt'{'apply'}'FinalizeRollback'{'finalize-rollback'}default{$Operation.ToLowerInvariant()}}
        $j='J:\n2r-compact-journal-a1aa7a957b094f7bbe9af154ee7270eb';$c='C:\ntfs2refs\private-tree-3c9f174567bf48f5b9957e3f1ec48011';$out=Join-Path $Stage 'result'
        $cli=@('--operation',$mode,'--acknowledge-enrolled-disposable-fixture','--request',(Join-Path $j 'request.json'),
            '--request-sha256','33d18d9f77ebeba339feb71cc4471852bb2c3f3b6edc283fff93fc3f9d7e27d7',
            '--ticket',(Join-Path $j 'ticket.json'),'--ticket-sha256','c07d1a49e8ba36b843214dab822ab8c335dfd51146f144bd5f64d2c37fc5f2c4',
            '--capture',(Join-Path $c 'result.json'),'--capture-sha256','a480fe897a0c76a92822d5312f5cde27dea341a296b9db16dae9386d81fc4b0f',
            '--packed',(Join-Path $c 'changed-clusters.bin'),'--expectation',(Join-Path $c 'expectation.json'),
            '--expectation-sha256','1602601cde53a7aa78d95e34c3de2ea18f5c0b65ddd8287ece9c84d81cbce215','--journal',(Join-Path $j 'journal.bin'),'--output',$out)
        if($Operation-eq'Interrupt'){$cli+=@('--interrupt-after-writes','1')}
        elseif($Operation-in@('Resume','Rollback')){$cli+='--finalize'}
        $argText=($cli|ForEach-Object {'"'+$_.Replace('"','\"')+'"'})-join' '
        Register-ScheduledTask -TaskName $task -Action (New-ScheduledTaskAction -Execute $binary -Argument $argText) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
        @{task_name=$task;operation=$Operation;run_id=$Run;guest_stage=$Stage;output_dir=$out;binary=$binary;binary_sha256=$Pin;arguments=$cli;expected_exit=$(if($Operation-eq'Interrupt'){86}else{0})}
    }
    Save-New 'dispatch.json' $dispatch
    Invoke-Command -Session $s -ArgumentList $dispatch.task_name -ScriptBlock {param($Task);if((Get-ScheduledTaskInfo -TaskName $Task).LastRunTime.Year-ge2000){throw 'Task already ran.'};Start-ScheduledTask -TaskName $Task}
    Save-New 'start.json' @{start_issued_once=$true;utc=[DateTime]::UtcNow.ToString('o')}
    $dispatch|ConvertTo-Json -Compress
}finally{Remove-PSSession $s}
