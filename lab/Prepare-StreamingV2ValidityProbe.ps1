# Preserve the budget-refused branch, then run one bounded native allocation
# experiment on a fresh child. The original NTFS disk remains excluded.
[CmdletBinding()]param([ValidateSet('candidate5')][string]$Candidate='candidate5')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace ('.lab\hyperv\streaming-v2-20261027\'+$Candidate)
$d=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
$archive=Get-Content -LiteralPath (Join-Path $root 'terminal-evidence-manifest.json') -Raw|ConvertFrom-Json
$size=Get-Content -LiteralPath (Join-Path $root 'journal-sizing\dispatch.json') -Raw|ConvertFrom-Json
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$baseline=[guid]'02036ef7-4010-4d0a-82d5-d632de1a2b39'
if([guid]$d.vm_id-ne$id-or$d.run_id-cne'dbd514da89ac4c44b16bde4f7e3a805c'-or-not$archive.verified-or$archive.run_id-cne$d.run_id){throw 'Exact archived candidate required.'}
$stage=Join-Path $root 'valid-data-probe'
if(Test-Path -LiteralPath $stage){throw 'Probe has state; inspect without redispatch.'}
$vm=Get-VM -Id $id
if($vm.State.ToString()-cne'Running'-or$vm.ParentSnapshotId-ne$baseline){throw 'Running owned refused-baseline child required.'}
$old=@(Get-VMSnapshot -VM $vm)
if($old.Count-ne9){throw 'All nine earlier checkpoints must remain.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 6GB
$binary=Join-Path $workspace 'target\release\lab-probe-native-valid-data.exe'
$binaryPin=(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()
$request=Join-Path $root 'terminal-evidence\run\request.json';$requestPin=(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$s=New-PSSession -VMId $id -Credential $credential
try{
    $state=Invoke-Command -Session $s -ArgumentList $d.task_name,$size.task_name,$size.guest_stage -ScriptBlock {
        param($Producer,$Sizer,$Stage);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        foreach($task in @($Producer,$Sizer)){if((Get-ScheduledTask -TaskName $task).State.ToString()-in@('Running','Queued')){throw 'A task is live.'}}
        if((Get-ScheduledTaskInfo -TaskName $Producer).LastTaskResult-ne1-or(Get-ScheduledTaskInfo -TaskName $Sizer).LastTaskResult-ne0-or
            @(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'-or$_.Name-in@('lab-convert-admitted-tree.exe','lab-measure-general-journal.exe','lab-probe-native-valid-data.exe')}).Count){throw 'Exact terminal producer/sizer required.'}
        $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
        if([guid]$source.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or[guid]$shadow.Guid-ne[guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f'-or
            -not$source.IsOffline-or-not$source.IsReadOnly-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly){throw 'Persistent frozen pair differs.'}
        $path=Join-Path $Stage 'result.json';$item=Get-Item -LiteralPath $path
        if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-gt1MB){throw 'Bounded sizing report required.'}
        [pscustomobject]@{sizing_path=$path;sizing_bytes=$item.Length;sizing_sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant();source_offline=$true;source_readonly=$true}
    }
    New-Item -ItemType Directory -Path $stage|Out-Null
    function Save-New([string]$Name,$Value){
        $f=[IO.File]::Open((Join-Path $stage $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}
    }
    Save-New 'intent.json' @{run_id=$d.run_id;vm_id=$id;preserved_checkpoints=@($old.Id);native_state=$state;
        binary_sha256=$binaryPin;request_sha256=$requestPin;source_commit=(& git -C $workspace rev-parse HEAD).Trim();
        source_payload_writes_authorized=$false;probe_file_bytes=1052672;payload_reads_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')}
    Copy-Item -LiteralPath $state.sizing_path -FromSession $s -Destination (Join-Path $stage 'sizing-result.json')
    if((Get-Item -LiteralPath (Join-Path $stage 'sizing-result.json')).Length-ne$state.sizing_bytes-or
        (Get-FileHash -LiteralPath (Join-Path $stage 'sizing-result.json')).Hash.ToLowerInvariant()-cne$state.sizing_sha256){throw 'Sizing archive pin differs.'}
}finally{Remove-PSSession $s}
Stop-VM -VM $vm -Confirm:$false -ErrorAction Stop
$off=Get-CimInstance -Namespace 'root/virtualization/v2' -ClassName Msvm_ComputerSystem -Filter "Name='2401593c-4b30-472e-9b6d-c9534cbaa599'"
if($off.EnabledState-ne3-or(Get-VM -Id $id).State.ToString()-cne'Off'){throw 'Clean OFF required; never force stop.'}
$checkpoint=Checkpoint-VM -VM (Get-VM -Id $id) -SnapshotName 'streaming-v2-candidate5-budget-refused' -Passthru
Save-New 'failed-checkpoint.json' @{checkpoint_id=$checkpoint.Id;parent=$checkpoint.ParentSnapshotId;name=$checkpoint.Name;state='Off';utc=[DateTime]::UtcNow.ToString('o')}
$now=@(Get-VMSnapshot -VM (Get-VM -Id $id))
if($now.Count-ne10-or@($old|Where-Object {$now.Id-notcontains$_.Id}).Count){throw 'Checkpoint preservation differs.'}
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 6GB
Start-VM -VM (Get-VM -Id $id) -ErrorAction Stop|Out-Null
$s=$null;$deadline=[DateTime]::UtcNow.AddMinutes(8)
while($null-eq$s){try{$s=New-PSSession -VMId $id -Credential $credential -ErrorAction Stop}catch{if([DateTime]::UtcNow-ge$deadline){throw 'Single child boot did not return; do not restart.'};Start-Sleep -Seconds 3}}
try{
    $guestStage=Join-Path $d.guest_stage 'valid-data-probe';$experiment=[guid]::NewGuid().ToString('N');$task='N2R-NativeValidData-'+$experiment
    $mounted=Invoke-Command -Session $s -ArgumentList $guestStage -ScriptBlock {
        param($Stage);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'-or$_.Name-in@('lab-convert-admitted-tree.exe','lab-measure-general-journal.exe','lab-probe-native-valid-data.exe')}).Count){throw 'Worker active after boot.'}
        $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
        if([guid]$source.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or-not$source.IsOffline-or-not$source.IsReadOnly-or
            [guid]$shadow.Guid-ne[guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f'-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly-or$shadow.IsBoot-or$shadow.IsSystem){throw 'Exact excluded disks required.'}
        if(Test-Path -LiteralPath $Stage){throw 'Fresh private probe stage required.'}
        New-Item -ItemType Directory -Path $Stage|Out-Null
        Set-Disk -Number 3 -IsReadOnly $false -ErrorAction Stop
        Set-Disk -Number 3 -IsOffline $false -ErrorAction Stop
        $p=Get-Partition -DiskNumber 3|Where-Object {$_.Offset-eq16MB};$v=Get-Volume -Partition $p
        if([guid]$p.Guid-ne[guid]'cbfd3e55-e35c-4f6e-aaac-dca706c3ec17'-or$p.Size-ne52GB-or$v.FileSystem-cne'ReFS'-or$v.AllocationUnitSize-ne4096-or$v.FileSystemLabel-cne'n2r-retained-shadow'){throw 'Mounted probe target differs.'}
        [pscustomobject]@{shadow_partition_guid=$p.Guid;source_offline=(Get-Disk -Number 1).IsOffline;source_readonly=(Get-Disk -Number 1).IsReadOnly;utc=[DateTime]::UtcNow.ToString('o')}
    }
    Save-New 'mounted-shadow.json' $mounted
    Copy-Item -LiteralPath $binary -ToSession $s -Destination (Join-Path $guestStage 'lab-probe-native-valid-data.exe')
    Copy-Item -LiteralPath $request -ToSession $s -Destination (Join-Path $guestStage 'request.json')
    $record=Invoke-Command -Session $s -ArgumentList $guestStage,$task,$experiment,$binaryPin,$requestPin -ScriptBlock {
        param($Stage,$Task,$Experiment,$BinaryPin,$RequestPin);$ErrorActionPreference='Stop'
        $binary=Join-Path $Stage 'lab-probe-native-valid-data.exe';$request=Join-Path $Stage 'request.json'
        if((Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()-cne$BinaryPin-or(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()-cne$RequestPin){throw 'Probe pins differ.'}
        $args='--request "'+$request+'" --request-sha256 '+$RequestPin+' --experiment-id '+$Experiment+' --output "'+(Join-Path $Stage 'result.json')+'"'
        Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute $binary -Argument $args) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
        [pscustomobject]@{task_name=$Task;experiment_id=$Experiment;guest_stage=$Stage;binary=$binary;binary_sha256=$BinaryPin;arguments=$args;request_sha256=$RequestPin}
    }
    Save-New 'dispatch.json' $record
    Invoke-Command -Session $s -ArgumentList $task,$record.binary,$record.arguments,$binaryPin -ScriptBlock {
        param($Task,$Binary,$Arguments,$Pin);$ErrorActionPreference='Stop'
        $t=Get-ScheduledTask -TaskName $Task;$i=Get-ScheduledTaskInfo -TaskName $Task
        if($t.State.ToString()-cne'Ready'-or$i.LastRunTime.Year-ge2000-or@($t.Actions).Count-ne1-or$t.Actions[0].Execute-cne$Binary-or$t.Actions[0].Arguments-cne$Arguments-or
            (Get-FileHash -LiteralPath $Binary).Hash.ToLowerInvariant()-cne$Pin){throw 'Fresh unchanged probe task required.'}
        Start-ScheduledTask -TaskName $Task
    }
    Save-New 'start-observed.json' @{start_issued_once=$true;utc=[DateTime]::UtcNow.ToString('o')}
    $record|ConvertTo-Json -Compress
}finally{Remove-PSSession $s}
