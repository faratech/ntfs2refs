# Read-only source/native-shadow preparation from the preserved compact case.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs'
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$parent=[guid]'43cc982a-91e4-4012-97f5-f318373f895b'
$root=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\compact-journal-20261028'
if(Test-Path -LiteralPath $root){throw 'Preparation has state; observe without redispatch.'}
$vm=Get-VM -Id $id
$old=@(Get-VMSnapshot -VM $vm|ForEach-Object {$_.Id.ToString()})
if($vm.State.ToString()-cne'Off'-or$vm.ParentSnapshotId-ne$parent-or$old.Count-ne35-or$vm.MemoryStartup-ne4GB-or$vm.DynamicMemoryEnabled-or@(Get-VMNetworkAdapter -VM $vm).Count){throw 'Exact saved isolated compact branch required.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 2GB
$binary=Join-Path $workspace 'target\release\lab-prepare-compact-journal.exe'
$template=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\candidate13\terminal-evidence\run\request.json'
$pin=(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()
$templatePin=(Get-FileHash -LiteralPath $template).Hash.ToLowerInvariant()
$run=[guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path $root|Out-Null
function Save-New([string]$Name,$Value){$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 8));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
Save-New 'intent.json' @{run_id=$run;vm_id=$id.ToString();parent_id=$parent.ToString();old_checkpoint_ids=$old;binary_sha256=$pin;template_sha256=$templatePin;source_commit=(& git -C $workspace rev-parse HEAD).Trim();source_writes_authorized=$false;additional_bytes=2GB;max_journal_bytes=512MB;utc=[DateTime]::UtcNow.ToString('o')}
Copy-Item -LiteralPath $binary -Destination (Join-Path $root 'producer.exe')
Copy-Item -LiteralPath $template -Destination (Join-Path $root 'template.json')
Start-VM -VM $vm|Out-Null
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$s=$null;$deadline=[DateTime]::UtcNow.AddMinutes(5)
while($null-eq$s){try{$s=New-PSSession -VMId $id -Credential $credential -ErrorAction Stop}catch{if([DateTime]::UtcNow-ge$deadline){throw 'Single boot did not return; never restart on observation timeout.'};Start-Sleep -Seconds 3}}
try{
    $stage='C:\ntfs2refs\compact-journal-'+$run
    $out='J:\n2r-compact-journal-'+$run
    $ready=Invoke-Command -Session $s -ArgumentList $stage,$out -ScriptBlock {
        param($Stage,$Out);$ErrorActionPreference='Stop'
        $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3;$journal=Get-Disk -Number 2
        if([guid]$source.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or[guid]$shadow.Guid-ne[guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f'-or[guid]$journal.Guid-ne[guid]'09fcc613-b8c2-4a1a-8833-226f9399be7f'-or-not$source.IsOffline-or-not$source.IsReadOnly-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly-or$journal.IsOffline-or$journal.IsReadOnly-or(Test-Path $Stage)-or(Test-Path $Out)){throw 'Exact excluded pair/fresh external output required.'}
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-in@('lab-prepare-compact-journal.exe','lab-allocate-private-tree.exe','lab-convert-admitted-tree.exe')}).Count){throw 'A worker is active.'}
        $capture='C:\ntfs2refs\private-tree-3c9f174567bf48f5b9957e3f1ec48011'
        if((Get-FileHash (Join-Path $capture 'result.json')).Hash.ToLowerInvariant()-cne'a480fe897a0c76a92822d5312f5cde27dea341a296b9db16dae9386d81fc4b0f'-or(Get-FileHash (Join-Path $capture 'changed-clusters.bin')).Hash.ToLowerInvariant()-cne'dc5d6e1df69e72c85df7df5da83a51f50317c6b7cb82becd79b58ebb1390a8d8'-or(Get-FileHash (Join-Path $capture 'expectation.json')).Hash.ToLowerInvariant()-cne'1602601cde53a7aa78d95e34c3de2ea18f5c0b65ddd8287ece9c84d81cbce215'){throw 'Preserved capture pins differ.'}
        if((Get-Volume -DriveLetter J).SizeRemaining-lt768MB){throw 'External journal lacks allowance.'}
        New-Item -ItemType Directory -Path $Stage|Out-Null
        @{stage=$Stage;output=$Out;capture=$capture}
    }
    Copy-Item -LiteralPath $binary -ToSession $s -Destination (Join-Path $stage 'lab-prepare-compact-journal.exe')
    Copy-Item -LiteralPath $template -ToSession $s -Destination (Join-Path $stage 'template.json')
    $dispatch=Invoke-Command -Session $s -ArgumentList $stage,$out,$ready.capture,$run,$pin,$templatePin -ScriptBlock {
        param($Stage,$Out,$Capture,$Run,$Pin,$TemplatePin);$ErrorActionPreference='Stop'
        $binary=Join-Path $Stage 'lab-prepare-compact-journal.exe';$template=Join-Path $Stage 'template.json';$task='N2R-CompactPrepare-'+$Run
        if((Get-FileHash $binary).Hash.ToLowerInvariant()-cne$Pin-or(Get-FileHash $template).Hash.ToLowerInvariant()-cne$TemplatePin-or(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)){throw 'Fresh pinned task required.'}
        $a='--experiment-id '+$Run+' --template "'+$template+'" --template-sha256 '+$TemplatePin+' --capture "'+(Join-Path $Capture 'result.json')+'" --capture-sha256 a480fe897a0c76a92822d5312f5cde27dea341a296b9db16dae9386d81fc4b0f --packed "'+(Join-Path $Capture 'changed-clusters.bin')+'" --expectation "'+(Join-Path $Capture 'expectation.json')+'" --expectation-sha256 1602601cde53a7aa78d95e34c3de2ea18f5c0b65ddd8287ece9c84d81cbce215 --output-dir "'+$Out+'" --max-journal-bytes 536870912'
        Register-ScheduledTask -TaskName $task -Action (New-ScheduledTaskAction -Execute $binary -Argument $a) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
        @{task_name=$task;guest_stage=$Stage;output_dir=$Out;run_id=$Run;binary=$binary;binary_sha256=$Pin;arguments=$a}
    }
    Save-New 'dispatch.json' $dispatch
    Invoke-Command -Session $s -ArgumentList $dispatch.task_name -ScriptBlock {param($Task);$i=Get-ScheduledTaskInfo -TaskName $Task;if($i.LastRunTime.Year-ge2000){throw 'Task already ran.'};Start-ScheduledTask -TaskName $Task}
    Save-New 'start.json' @{start_issued_once=$true;utc=[DateTime]::UtcNow.ToString('o')}
    $dispatch|ConvertTo-Json -Compress
}finally{Remove-PSSession $s}
