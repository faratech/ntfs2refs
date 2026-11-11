# Preserve the private allocation outcome and observe it after a clean boot.
# Only the shadow's read-only attribute changes; source remains excluded.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\candidate5\valid-data-probe'
$d=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
$probe=Get-Content -LiteralPath (Join-Path $root 'result.json') -Raw|ConvertFrom-Json
$parent=Get-Content -LiteralPath (Join-Path $root 'failed-checkpoint.json') -Raw|ConvertFrom-Json
if($d.experiment_id-cne'a060e73a480440a3af174f4c98af60c8'-or$probe.experiment_id-cne$d.experiment_id-or-not$probe.set_valid_data_succeeded-or$probe.payload_reads-ne0-or$probe.payload_write_calls-ne0){throw 'Exact completed private probe required.'}
$idInfo=@($probe.after_flush.snapshot.queries|Where-Object class -eq 18)
if($idInfo.Count-ne1-or$null-ne$idInfo[0].native_error-or@($idInfo[0].bytes).Count-ne24){throw 'Complete original file identity required.'}
$expectedId=[Convert]::ToHexString([byte[]]$idInfo[0].bytes).ToLowerInvariant()
$stage=Join-Path $root 'reopen-v1'
if(Test-Path -LiteralPath $stage){throw 'Reopen has state; inspect without repeating boot or dispatch.'}
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$vm=Get-VM -Id $id
if($vm.State.ToString()-cne'Running'-or$vm.ParentSnapshotId-ne[guid]$parent.checkpoint_id-or$vm.MemoryStartup-ne4GB-or$vm.DynamicMemoryEnabled-or@(Get-VMNetworkAdapter -VM $vm).Count){throw 'Owned isolated four-GiB probe child required.'}
$old=@(Get-VMSnapshot -VM $vm)
if($old.Count-ne10){throw 'Ten preserved checkpoints required.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 6GB
$binary=Join-Path $workspace 'target\release\lab-probe-native-valid-data.exe';$binaryPin=(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()
$request=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\candidate5\terminal-evidence\run\request.json';$requestPin=(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()
$resultPin=(Get-FileHash -LiteralPath (Join-Path $root 'result.json')).Hash.ToLowerInvariant()
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$s=New-PSSession -VMId $id -Credential $credential
try{
    $before=Invoke-Command -Session $s -ArgumentList $d.task_name,$d.guest_stage,$resultPin,$d.binary_sha256 -ScriptBlock {
        param($Task,$Stage,$ResultPin,$BinaryPin);$ErrorActionPreference='Stop'
        if((Get-ScheduledTask -TaskName $Task).State.ToString()-in@('Running','Queued')-or(Get-ScheduledTaskInfo -TaskName $Task).LastTaskResult-ne0-or
            @(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'-or$_.Name-in@('lab-convert-admitted-tree.exe','lab-measure-general-journal.exe','lab-probe-native-valid-data.exe')}).Count){throw 'Native probe must be terminal.'}
        if((Get-FileHash -LiteralPath (Join-Path $Stage 'result.json')).Hash.ToLowerInvariant()-cne$ResultPin-or
            (Get-FileHash -LiteralPath (Join-Path $Stage 'lab-probe-native-valid-data.exe')).Hash.ToLowerInvariant()-cne$BinaryPin){throw 'Original producer/result changed.'}
        $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
        if([guid]$source.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or-not$source.IsOffline-or-not$source.IsReadOnly-or
            [guid]$shadow.Guid-ne[guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f'-or$shadow.IsOffline-or$shadow.IsReadOnly){throw 'Original source/probe disk state differs.'}
        [pscustomobject]@{boot_utc=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');source_offline=$true;source_readonly=$true;utc=[DateTime]::UtcNow.ToString('o')}
    }
    New-Item -ItemType Directory -Path $stage|Out-Null
    function Save-New([string]$Name,$Value){
        $f=[IO.File]::Open((Join-Path $stage $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 12));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}
    }
    Save-New 'intent.json' @{vm_id=$id;experiment_id=$d.experiment_id;before=$before;original_result_sha256=$resultPin;expected_file_id_info=$expectedId;
        binary_sha256=$binaryPin;source_commit=(& git -C $workspace rev-parse HEAD).Trim();preserved_checkpoints=@($old.Id);source_payload_writes_authorized=$false;payload_reads_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')}
    $original=Join-Path $root 'producer-original.exe'
    if(Test-Path -LiteralPath $original){throw 'Producer archive already exists; inspect it.'}
    Copy-Item -LiteralPath (Join-Path $d.guest_stage 'lab-probe-native-valid-data.exe') -FromSession $s -Destination $original
    if((Get-FileHash -LiteralPath $original).Hash.ToLowerInvariant()-cne$d.binary_sha256){throw 'Original producer archive pin differs.'}
}finally{Remove-PSSession $s}
Stop-VM -VM $vm -Confirm:$false -ErrorAction Stop
$off=Get-CimInstance -Namespace 'root/virtualization/v2' -ClassName Msvm_ComputerSystem -Filter "Name='2401593c-4b30-472e-9b6d-c9534cbaa599'"
if($off.EnabledState-ne3-or(Get-VM -Id $id).State.ToString()-cne'Off'){throw 'Clean OFF required; no force stop.'}
$checkpoint=Checkpoint-VM -VM (Get-VM -Id $id) -SnapshotName ('streaming-v2-private-valid-data-'+$d.experiment_id) -Passthru
Save-New 'probe-checkpoint.json' @{checkpoint_id=$checkpoint.Id;parent=$checkpoint.ParentSnapshotId;name=$checkpoint.Name;state='Off';utc=[DateTime]::UtcNow.ToString('o')}
$now=@(Get-VMSnapshot -VM (Get-VM -Id $id))
if($now.Count-ne11-or@($old|Where-Object {$now.Id-notcontains$_.Id}).Count){throw 'Checkpoint preservation differs.'}
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 6GB
Start-VM -VM (Get-VM -Id $id) -ErrorAction Stop|Out-Null
$s=$null;$deadline=[DateTime]::UtcNow.AddMinutes(8)
while($null-eq$s){try{$s=New-PSSession -VMId $id -Credential $credential -ErrorAction Stop}catch{if([DateTime]::UtcNow-ge$deadline){throw 'Single boot did not return; inspect without restart.'};Start-Sleep -Seconds 3}}
try{
    $guestStage=Join-Path $d.guest_stage 'reopen-v1';$task='N2R-NativeValidDataObserve-'+$d.experiment_id
    $boot=Invoke-Command -Session $s -ArgumentList $guestStage,$before.boot_utc -ScriptBlock {
        param($Stage,$BeforeBoot);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
        if([DateTimeOffset]::Parse($boot)-le[DateTimeOffset]::Parse($BeforeBoot)){throw 'New clean boot required.'}
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'-or$_.Name-in@('lab-convert-admitted-tree.exe','lab-measure-general-journal.exe','lab-probe-native-valid-data.exe')}).Count){throw 'A worker is active.'}
        $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
        if([guid]$source.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or-not$source.IsOffline-or-not$source.IsReadOnly-or
            [guid]$shadow.Guid-ne[guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f'-or$shadow.IsOffline-or$shadow.IsReadOnly-or$shadow.IsBoot-or$shadow.IsSystem){throw 'Persisted source/shadow state differs.'}
        $driverPin=(Get-FileHash -LiteralPath 'C:\Windows\System32\drivers\refs.sys').Hash.ToLowerInvariant()
        if($driverPin-cne'3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4'){throw 'Native driver changed.'}
        if(Test-Path -LiteralPath $Stage){throw 'Fresh read-only observer stage required.'}
        Set-Disk -Number 3 -IsReadOnly $true -ErrorAction Stop
        $after=Get-Disk -Number 3
        if($after.IsOffline-or-not$after.IsReadOnly){throw 'Read-only mounted shadow required.'}
        New-Item -ItemType Directory -Path $Stage|Out-Null
        [pscustomobject]@{boot_utc=$boot;refs_driver_sha256=$driverPin;source_offline=$true;source_readonly=$true;shadow_offline=$false;shadow_readonly=$true;utc=[DateTime]::UtcNow.ToString('o')}
    }
    Save-New 'boot.json' $boot
    Copy-Item -LiteralPath $binary -ToSession $s -Destination (Join-Path $guestStage 'lab-probe-native-valid-data.exe')
    Copy-Item -LiteralPath $request -ToSession $s -Destination (Join-Path $guestStage 'request.json')
    $record=Invoke-Command -Session $s -ArgumentList $guestStage,$task,$d.experiment_id,$expectedId,$binaryPin,$requestPin -ScriptBlock {
        param($Stage,$Task,$Experiment,$ExpectedId,$BinaryPin,$RequestPin);$ErrorActionPreference='Stop'
        $binary=Join-Path $Stage 'lab-probe-native-valid-data.exe';$request=Join-Path $Stage 'request.json'
        if((Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()-cne$BinaryPin-or(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()-cne$RequestPin){throw 'Observer pins differ.'}
        $args='--observe-existing --expected-file-id-info '+$ExpectedId+' --request "'+$request+'" --request-sha256 '+$RequestPin+' --experiment-id '+$Experiment+' --output "'+(Join-Path $Stage 'result.json')+'"'
        Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute $binary -Argument $args) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
        [pscustomobject]@{task_name=$Task;guest_stage=$Stage;binary=$binary;binary_sha256=$BinaryPin;arguments=$args;request_sha256=$RequestPin;expected_file_id_info=$ExpectedId}
    }
    Save-New 'dispatch.json' $record
    Invoke-Command -Session $s -ArgumentList $task,$record.binary,$record.arguments,$binaryPin -ScriptBlock {
        param($Task,$Binary,$Arguments,$Pin);$ErrorActionPreference='Stop'
        $t=Get-ScheduledTask -TaskName $Task;$i=Get-ScheduledTaskInfo -TaskName $Task
        if($t.State.ToString()-cne'Ready'-or$i.LastRunTime.Year-ge2000-or@($t.Actions).Count-ne1-or$t.Actions[0].Execute-cne$Binary-or$t.Actions[0].Arguments-cne$Arguments-or
            (Get-FileHash -LiteralPath $Binary).Hash.ToLowerInvariant()-cne$Pin){throw 'Fresh unchanged read-only task required.'}
        Start-ScheduledTask -TaskName $Task
    }
    Save-New 'start-observed.json' @{start_issued_once=$true;utc=[DateTime]::UtcNow.ToString('o')}
    $record|ConvertTo-Json -Compress
}finally{Remove-PSSession $s}
