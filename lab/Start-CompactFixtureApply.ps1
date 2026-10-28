# Exact acknowledged disposable corpus only; never selects another drive.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$parent=[guid]'5971d348-3f8b-4696-bef6-4c1f164fbf64'
$root=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\compact-fixture-apply-20261028'
if(Test-Path -LiteralPath $root){throw 'Apply has state; observe/recover without redispatch.'}
$vm=Get-VM -Id $id;$old=@(Get-VMSnapshot -VM $vm|ForEach-Object {$_.Id.ToString()})
if($vm.State.ToString()-cne'Off'-or$vm.ParentSnapshotId-ne$parent-or$old.Count-ne36-or$vm.MemoryStartup-ne4GB-or$vm.DynamicMemoryEnabled-or@(Get-VMNetworkAdapter -VM $vm).Count){throw 'Exact isolated saved journal branch required.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 2GB
$binary=Join-Path $workspace 'target\release\lab-apply-compact-fixture.exe';$pin=(Get-FileHash $binary).Hash.ToLowerInvariant();$run=[guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path $root|Out-Null
function Save-New([string]$Name,$Value){$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 8));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
Save-New 'intent.json' @{run_id=$run;vm_id=$id.ToString();parent_id=$parent.ToString();old_checkpoint_ids=$old;binary_sha256=$pin;source_commit=(& git -C $workspace rev-parse HEAD).Trim();exact_fixture_only=$true;source_fixture_writes_authorized=$true;production_source_admitted=$false;additional_bytes=2GB;finalize=$true;utc=[DateTime]::UtcNow.ToString('o')}
Copy-Item -LiteralPath $binary -Destination (Join-Path $root 'producer.exe')
Start-VM -VM $vm|Out-Null
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml');$s=$null;$deadline=[DateTime]::UtcNow.AddMinutes(5)
while($null-eq$s){try{$s=New-PSSession -VMId $id -Credential $credential -ErrorAction Stop}catch{if([DateTime]::UtcNow-ge$deadline){throw 'Single boot did not return; never restart on timeout.'};Start-Sleep -Seconds 3}}
try{
    $stage='C:\ntfs2refs\compact-apply-'+$run
    Invoke-Command -Session $s -ArgumentList $stage -ScriptBlock {
        param($Stage);$ErrorActionPreference='Stop';$src=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
        if([guid]$src.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or[guid]$shadow.Guid-ne[guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f'-or-not$src.IsOffline-or-not$src.IsReadOnly-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly-or(Test-Path $Stage)-or@(Get-CimInstance Win32_Process|Where-Object {$_.Name-in@('lab-apply-compact-fixture.exe','lab-prepare-compact-journal.exe','lab-allocate-private-tree.exe')}).Count){throw 'Fresh stage/exact excluded pair required.'}
        New-Item -ItemType Directory -Path $Stage|Out-Null
    }
    Copy-Item -LiteralPath $binary -ToSession $s -Destination ([IO.Path]::Combine($stage,'lab-apply-compact-fixture.exe'))
    $dispatch=Invoke-Command -Session $s -ArgumentList $stage,$run,$pin -ScriptBlock {
        param($Stage,$Run,$Pin);$ErrorActionPreference='Stop';$binary=Join-Path $Stage 'lab-apply-compact-fixture.exe';$task='N2R-CompactApply-'+$Run
        if((Get-FileHash $binary).Hash.ToLowerInvariant()-cne$Pin-or(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)){throw 'Fresh pinned executable required.'}
        $j='J:\n2r-compact-journal-a1aa7a957b094f7bbe9af154ee7270eb';$c='C:\ntfs2refs\private-tree-3c9f174567bf48f5b9957e3f1ec48011';$out=Join-Path $Stage 'result'
        $cliArguments=@('--operation','apply','--acknowledge-enrolled-disposable-fixture','--finalize',
            '--request',(Join-Path $j 'request.json'),'--request-sha256','33d18d9f77ebeba339feb71cc4471852bb2c3f3b6edc283fff93fc3f9d7e27d7',
            '--ticket',(Join-Path $j 'ticket.json'),'--ticket-sha256','c07d1a49e8ba36b843214dab822ab8c335dfd51146f144bd5f64d2c37fc5f2c4',
            '--capture',(Join-Path $c 'result.json'),'--capture-sha256','a480fe897a0c76a92822d5312f5cde27dea341a296b9db16dae9386d81fc4b0f',
            '--packed',(Join-Path $c 'changed-clusters.bin'),'--expectation',(Join-Path $c 'expectation.json'),
            '--expectation-sha256','1602601cde53a7aa78d95e34c3de2ea18f5c0b65ddd8287ece9c84d81cbce215',
            '--journal',(Join-Path $j 'journal.bin'),'--output',$out)
        $encoded=[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes(($cliArguments|ConvertTo-Json -Compress)))
        $runner=@'
$ErrorActionPreference='Stop'
$stage=Split-Path -Parent $MyInvocation.MyCommand.Path
$binary=Join-Path $stage 'lab-apply-compact-fixture.exe'
$pin='__PIN__'
if((Get-FileHash $binary).Hash.ToLowerInvariant()-cne$pin){throw 'Executable changed.'}
$once=[IO.File]::Open((Join-Path $stage 'runner-started.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$once.Dispose()
$arguments=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__ARGS__'))|ConvertFrom-Json
$ErrorActionPreference='Continue'
& $binary @arguments 1> (Join-Path $stage 'stdout.txt') 2> (Join-Path $stage 'stderr.txt')
$code=$LASTEXITCODE
$ErrorActionPreference='Stop'
[IO.File]::WriteAllText((Join-Path $stage 'exit.json'),(@{exit_code=$code;utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
exit $code
'@
        $runner=$runner.Replace('__PIN__',$Pin).Replace('__ARGS__',$encoded);$path=Join-Path $Stage 'run.ps1'
        [IO.File]::WriteAllText($path,$runner,[Text.UTF8Encoding]::new($false))
        Register-ScheduledTask -TaskName $task -Action (New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument ('-NoProfile -NonInteractive -File "'+$path+'"')) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
        @{task_name=$task;guest_stage=$Stage;output_dir=$out;run_id=$Run;binary=$binary;binary_sha256=$Pin;runner_sha256=(Get-FileHash $path).Hash.ToLowerInvariant();arguments=$cliArguments}
    }
    Save-New 'dispatch.json' $dispatch
    Invoke-Command -Session $s -ArgumentList $dispatch.task_name -ScriptBlock {param($Task);if((Get-ScheduledTaskInfo -TaskName $Task).LastRunTime.Year-ge2000){throw 'Task already ran.'};Start-ScheduledTask -TaskName $Task}
    Save-New 'start.json' @{start_issued_once=$true;utc=[DateTime]::UtcNow.ToString('o')}
    $dispatch|ConvertTo-Json -Compress
}finally{Remove-PSSession $s}
