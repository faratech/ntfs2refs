# One private 1 MiB placement before valid-data advancement. Restores only an
# owned saved research branch; all successful conversion checkpoints remain.
[CmdletBinding()]param([switch]$ContinueRestored,[switch]$SplitPlacement)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs'
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$converted=[guid]'ae80bfd5-7b8d-4e60-80b4-6e236c841390'
$baseline=if($SplitPlacement){[guid]'80907930-4a43-4cbc-b26b-dafd14dea4e8'}else{[guid]'24cfdd12-9b9c-4bd0-8322-a94da6d98708'}
$root=Join-Path $workspace $(if($SplitPlacement){'.lab\hyperv\streaming-v2-20261027\unwritten-placement-split-20261028'}else{'.lab\hyperv\streaming-v2-20261027\unwritten-placement-20261028'})
$expectedCount=if($SplitPlacement){17}else{16}
$destination=if($SplitPlacement){10485760}else{8388608}
if((Test-Path -LiteralPath $root)-and-not$ContinueRestored){throw 'Existing placement experiment; observe it without redispatch.'}
$vm=Get-VM -Id $id
$old=@(Get-VMSnapshot -VM $vm)
$expectedParent=if($ContinueRestored-or$SplitPlacement){$baseline}else{$converted}
if($vm.State.ToString()-cne'Off'-or$vm.ParentSnapshotId-ne$expectedParent-or$old.Count-ne$expectedCount-or
    $old.Id-notcontains$baseline-or$old.Id-notcontains$converted-or$vm.MemoryStartup-ne4GB-or
    $vm.DynamicMemoryEnabled-or@(Get-VMNetworkAdapter -VM $vm).Count){throw 'Exact preserved isolated branch required.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 6GB
$binary=Join-Path $workspace 'target\release\lab-probe-native-valid-data.exe'
$request=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\candidate5\terminal-evidence\run\request.json'
$pin=(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()
$requestPin=(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()
if($requestPin-cne'6b2b769ec8a0d0cec0ddfc6fc1dfc736d867d43c1a5a059cd8e029b8e1b6a8df'){throw 'Research request changed.'}
if(-not$ContinueRestored){New-Item -ItemType Directory -Path $root|Out-Null}
function Save-New([string]$Name,$Value){
    $f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 12));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}
}
if($ContinueRestored){
    $intent=Get-Content -LiteralPath (Join-Path $root 'intent.json') -Raw|ConvertFrom-Json
    $ids=@($old|ForEach-Object {$_.Id.ToString()})
    if($intent.vm_id-cne$id.ToString()-or$intent.baseline_id-cne$baseline.ToString()-or
        $intent.converted_checkpoint-cne$converted.ToString()-or$intent.binary_sha256-cne$pin-or
        $intent.request_sha256-cne$requestPin-or@($intent.old_checkpoint_ids).Count-ne$expectedCount-or
        @($intent.old_checkpoint_ids|Where-Object {$_-notin$ids}).Count-or
        @(Get-ChildItem -LiteralPath $root|Where-Object Name -notin @('intent.json','producer.exe')).Count-or
        (Get-FileHash -LiteralPath (Join-Path $root 'producer.exe')).Hash.ToLowerInvariant()-cne$pin){throw 'Only an unstarted, preserved restored intent can continue.'}
    $experiment=$intent.experiment_id
    Save-New 'restore-guard-reconciled.json' @{state='Off';parent_id=$baseline.ToString();all_old_checkpoint_ids=$ids;
        prior_dispatch_exists=$false;utc=[DateTime]::UtcNow.ToString('o');controller_sha256=(Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLowerInvariant()}
}else{
    $experiment=[guid]::NewGuid().ToString('N')
    Save-New 'intent.json' @{vm_id=$id.ToString();baseline_id=$baseline.ToString();converted_checkpoint=$converted.ToString();
    old_checkpoint_ids=@($old.Id|ForEach-Object {$_.ToString()});experiment_id=$experiment;binary_sha256=$pin;
    request_sha256=$requestPin;source_commit=(& git -C $workspace rev-parse HEAD).Trim();destination_lcn=$destination;
        split_placement=[bool]$SplitPlacement;second_destination_lcn=$(if($SplitPlacement){11010048}else{$null});
        source_payload_writes_authorized=$false;payload_reads_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')}
    Copy-Item -LiteralPath $binary -Destination (Join-Path $root 'producer.exe')
    if((Get-FileHash -LiteralPath (Join-Path $root 'producer.exe')).Hash.ToLowerInvariant()-cne$pin){throw 'Producer archive differs.'}
    if(-not$SplitPlacement){Restore-VMSnapshot -VMSnapshot ($old|Where-Object Id -eq $baseline) -Confirm:$false}
}
$vm=Get-VM -Id $id
$currentIds=@(Get-VMSnapshot -VM $vm|ForEach-Object {$_.Id.ToString()})
if($vm.State.ToString()-cne'Off'-or$vm.ParentSnapshotId-ne$baseline-or
    @($old|Where-Object {$_.Id.ToString()-notin$currentIds}).Count){throw 'Research restore/preservation differs.'}
Start-VM -VM $vm | Out-Null
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$s=$null;$deadline=[DateTime]::UtcNow.AddMinutes(5)
while($null-eq$s){try{$s=New-PSSession -VMId $id -Credential $credential -ErrorAction Stop}catch{if([DateTime]::UtcNow-ge$deadline){throw 'Single boot did not return; inspect without restarting.'};Start-Sleep -Seconds 3}}
try{
    $stage='C:\ntfs2refs\unwritten-placement-'+$experiment
    $mounted=Invoke-Command -Session $s -ArgumentList $stage,([bool]$SplitPlacement) -ScriptBlock {
        param($Stage,$Split);$ErrorActionPreference='Stop'
        if(Test-Path -LiteralPath $Stage){throw 'New stage required.'}
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'-or$_.Name-in@('lab-convert-admitted-tree.exe','lab-measure-general-journal.exe','lab-probe-native-valid-data.exe')}).Count){throw 'A worker is live.'}
        $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
        if([guid]$source.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or-not$source.IsOffline-or-not$source.IsReadOnly-or
            [guid]$shadow.Guid-ne[guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f'-or$shadow.IsReadOnly-ne(-not$Split)-or$shadow.IsBoot-or$shadow.IsSystem){throw 'Enrolled protected pair required.'}
        if((Get-FileHash -LiteralPath 'C:\Windows\System32\drivers\refs.sys').Hash.ToLowerInvariant()-cne'3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4'){throw 'Driver changed.'}
        New-Item -ItemType Directory -Path $Stage|Out-Null
        Set-Disk -Number 3 -IsReadOnly $false
        if((Get-Disk -Number 3).IsOffline){Set-Disk -Number 3 -IsOffline $false}
        $p=Get-Partition -DiskNumber 3|Where-Object Offset -eq 16MB;$v=Get-Volume -Partition $p
        if([guid]$p.Guid-ne[guid]'cbfd3e55-e35c-4f6e-aaac-dca706c3ec17'-or$p.Size-ne52GB-or$v.FileSystem-cne'ReFS'-or$v.AllocationUnitSize-ne4096-or$v.FileSystemLabel-cne'n2r-retained-shadow'){throw 'Mounted shadow differs.'}
        Set-StrictMode -Off
        @{shadow_partition=$p.Guid;source_offline=$true;source_readonly=$true;utc=[DateTime]::UtcNow.ToString('o')}
    }
    Save-New 'mounted.json' $mounted
    Copy-Item -LiteralPath $binary -ToSession $s -Destination (Join-Path $stage 'probe.exe')
    Copy-Item -LiteralPath $request -ToSession $s -Destination (Join-Path $stage 'request.json')
    $dispatch=Invoke-Command -Session $s -ArgumentList $stage,$experiment,$pin,$requestPin,$destination,([bool]$SplitPlacement) -ScriptBlock {
        param($Stage,$Experiment,$Pin,$RequestPin,$Destination,$Split);$ErrorActionPreference='Stop'
        $binary=Join-Path $Stage 'probe.exe';$request=Join-Path $Stage 'request.json'
        if((Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()-cne$Pin-or(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()-cne$RequestPin){throw 'Staged pins differ.'}
        $task='N2R-UnwrittenPlacement-'+$Experiment
        if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){throw 'Fresh task required.'}
        $arguments='--request "'+$request+'" --request-sha256 '+$RequestPin+' --experiment-id '+$Experiment+' --destination-lcn '+$Destination+$(if($Split){' --second-destination-lcn 11010048'}else{''})+' --output "'+(Join-Path $Stage 'result.json')+'"'
        Register-ScheduledTask -TaskName $task -Action (New-ScheduledTaskAction -Execute $binary -Argument $arguments) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
        @{task_name=$task;experiment_id=$Experiment;guest_stage=$Stage;binary=$binary;binary_sha256=$Pin;request_sha256=$RequestPin;arguments=$arguments}
    }
    Save-New 'dispatch.json' $dispatch
    Invoke-Command -Session $s -ArgumentList $dispatch.task_name,$dispatch.binary,$dispatch.arguments,$pin -ScriptBlock {
        param($Task,$Binary,$Arguments,$Pin);$t=Get-ScheduledTask -TaskName $Task;$i=Get-ScheduledTaskInfo -TaskName $Task
        if($t.State.ToString()-cne'Ready'-or$i.LastRunTime.Year-ge2000-or$t.Actions[0].Execute-cne$Binary-or$t.Actions[0].Arguments-cne$Arguments-or(Get-FileHash -LiteralPath $Binary).Hash.ToLowerInvariant()-cne$Pin){throw 'Fresh task binding differs.'}
        Start-ScheduledTask -TaskName $Task
    }
    Save-New 'start.json' @{start_issued_once=$true;utc=[DateTime]::UtcNow.ToString('o')}
    $dispatch|ConvertTo-Json -Compress
}finally{Remove-PSSession $s}
