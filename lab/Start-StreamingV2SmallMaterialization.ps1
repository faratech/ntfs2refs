# Materialize only bounded small user streams; large payload stays unwritten. Only
# the disposable shadow is formatted; all saved branches/source stay intact.
[CmdletBinding()]param([switch]$PrepareLargeTails,[switch]$PlaceSourcePrefixes,[switch]$DirectDeferredPlacement,[switch]$SourceBackedPayloads,[switch]$CaptureSourceBackedDifferences)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs'
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$parent=[guid]'6ffb6bdc-4da6-4060-8b4e-0c07a83d11b3'
if($CaptureSourceBackedDifferences){$SourceBackedPayloads=[switch]$true}
if($SourceBackedPayloads){$DirectDeferredPlacement=[switch]$true}
if($DirectDeferredPlacement){$PlaceSourcePrefixes=[switch]$true}
if($PlaceSourcePrefixes-and$PrepareLargeTails){throw 'This bounded placement qualification does not select tail validity.'}
$root=Join-Path $workspace $(if($CaptureSourceBackedDifferences){'.lab\hyperv\streaming-v2-20261027\source-backed-difference-capture-20261028'}elseif($SourceBackedPayloads){'.lab\hyperv\streaming-v2-20261027\private-tree-source-backed-20261028'}elseif($DirectDeferredPlacement){'.lab\hyperv\streaming-v2-20261027\private-tree-direct-placement-20261028'}elseif($PlaceSourcePrefixes){'.lab\hyperv\streaming-v2-20261027\private-tree-placement-20261028'}elseif($PrepareLargeTails){'.lab\hyperv\streaming-v2-20261027\private-tree-tail-materialization-20261028'}else{'.lab\hyperv\streaming-v2-20261027\private-tree-small-materialization-20261028'})
$expectedCount=if($CaptureSourceBackedDifferences){29}elseif($SourceBackedPayloads){28}elseif($DirectDeferredPlacement){27}elseif($PlaceSourcePrefixes){26}elseif($PrepareLargeTails){24}else{23}
$placementBytes=if($SourceBackedPayloads){[long]8.25GB}elseif($DirectDeferredPlacement){9GB}else{10GB}
$additionalBytes=if($CaptureSourceBackedDifferences){4GB}elseif($SourceBackedPayloads){[long]10.25GB}elseif($DirectDeferredPlacement){11GB}else{12GB}
if(Test-Path -LiteralPath $root){throw 'Private-tree run has state; observe without redispatch.'}
$vm=Get-VM -Id $id;$old=@(Get-VMSnapshot -VM $vm|ForEach-Object {$_.Id.ToString()})
if($vm.State.ToString()-cne'Off'-or$vm.ParentSnapshotId-ne$parent-or$old.Count-ne$expectedCount-or
    $vm.MemoryStartup-ne4GB-or$vm.DynamicMemoryEnabled-or@(Get-VMNetworkAdapter -VM $vm).Count){throw 'Exact isolated saved branch required.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes $additionalBytes
$binary=Join-Path $workspace 'target\release\lab-allocate-private-tree.exe'
$tree=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\candidate11\terminal-evidence\run\expectation.json'
$inspection=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\candidate11\terminal-evidence\run\qualification\source-basis.json'
$inspectionPin=(Get-FileHash -LiteralPath $inspection).Hash.ToLowerInvariant()
$oldRequest=Get-Content -LiteralPath (Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\candidate11\terminal-evidence\run\request.json') -Raw|ConvertFrom-Json
$pin=(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant();$treePin=(Get-FileHash -LiteralPath $tree).Hash.ToLowerInvariant()
New-Item -ItemType Directory -Path $root|Out-Null
function Save-New([string]$name,$value){$f=[IO.File]::Open((Join-Path $root $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 24));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
$run=[guid]::NewGuid().ToString('N')
Save-New 'intent.json' @{vm_id=$id.ToString();parent_id=$parent.ToString();old_checkpoint_ids=$old;run_id=$run;
    binary_sha256=$pin;tree_sha256=$treePin;inspection_sha256=$inspectionPin;source_commit=(& git -C $workspace rev-parse HEAD).Trim();
    shadow_format_authorized=$true;source_writes_authorized=$false;prepare_large_tails=[bool]$PrepareLargeTails;
    direct_deferred_placement=[bool]$DirectDeferredPlacement;
    source_backed_payloads=[bool]$SourceBackedPayloads;
    capture_source_backed_differences=[bool]$CaptureSourceBackedDifferences;
    forecast_basis=$(if($CaptureSourceBackedDifferences){'Prior same-profile prefix run:156 MiB shadow child, about0.7 GiB OS; output capped768 MiB;4 GiB allowance includes margin. Virtual move bytes are not predicted physical backing growth.'}else{$null});
    place_source_prefixes=[bool]$PlaceSourcePrefixes;max_placement_bytes=$(if($PlaceSourcePrefixes){$placementBytes}else{$null});
    max_placement_moves=$(if($PlaceSourcePrefixes){64}else{$null});additional_bytes=$additionalBytes;utc=[DateTime]::UtcNow.ToString('o')}
Copy-Item -LiteralPath $binary -Destination (Join-Path $root 'producer.exe')
Copy-Item -LiteralPath $tree -Destination (Join-Path $root 'expectation.json')
Copy-Item -LiteralPath $inspection -Destination (Join-Path $root 'source-inspection.json')
if((Get-FileHash -LiteralPath (Join-Path $root 'producer.exe')).Hash.ToLowerInvariant()-cne$pin-or
    (Get-FileHash -LiteralPath (Join-Path $root 'expectation.json')).Hash.ToLowerInvariant()-cne$treePin-or
    (Get-FileHash -LiteralPath (Join-Path $root 'source-inspection.json')).Hash.ToLowerInvariant()-cne$inspectionPin){throw 'Archived pins differ.'}
Start-VM -VM $vm|Out-Null
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$s=$null;$deadline=[DateTime]::UtcNow.AddMinutes(5)
while($null-eq$s){try{$s=New-PSSession -VMId $id -Credential $credential -ErrorAction Stop}catch{if([DateTime]::UtcNow-ge$deadline){throw 'Single boot did not return; do not restart.'};Start-Sleep -Seconds 3}}
try{
    $stage='C:\ntfs2refs\private-tree-'+$run
    $formatted=Invoke-Command -Session $s -ArgumentList $stage -ScriptBlock {
        param($Stage);$ErrorActionPreference='Stop'
        if(Test-Path -LiteralPath $Stage){throw 'New stage required.'}
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-in@('probe.exe','lab-allocate-private-tree.exe','lab-convert-admitted-tree.exe','ntfs2refs.exe')}).Count){throw 'A worker is live.'}
        $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
        if([guid]$source.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or-not$source.IsOffline-or-not$source.IsReadOnly-or
            [guid]$shadow.Guid-ne[guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f'-or$shadow.Size-ne64GB-or$shadow.IsBoot-or$shadow.IsSystem){throw 'Exact source/shadow disks required.'}
        if((Get-FileHash -LiteralPath 'C:\Windows\System32\drivers\refs.sys').Hash.ToLowerInvariant()-cne'3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4'){throw 'Driver changed.'}
        if($shadow.IsReadOnly){Set-Disk -Number 3 -IsReadOnly $false}
        if((Get-Disk -Number 3).IsOffline){Set-Disk -Number 3 -IsOffline $false}
        $p=@(Get-Partition -DiskNumber 3|Where-Object Offset -eq 16MB)
        if($p.Count-ne1-or[guid]$p[0].Guid-ne[guid]'cbfd3e55-e35c-4f6e-aaac-dca706c3ec17'-or$p[0].Size-ne52GB){throw 'Only the enrolled shadow partition may be formatted.'}
        New-Item -ItemType Directory -Path $Stage|Out-Null
        $before=(Get-Volume -Partition $p[0]).Path
        Format-Volume -Partition $p[0] -DevDrive -FileSystem ReFS -AllocationUnitSize 4096 -NewFileSystemLabel 'n2r-retained-shadow' -Confirm:$false -Force|Out-Null
        $v=Get-Volume -Partition (Get-Partition -DiskNumber 3|Where-Object Offset -eq 16MB)
        $source=Get-Disk -Number 1
        if($v.FileSystem-cne'ReFS'-or$v.AllocationUnitSize-ne4096-or-not$source.IsOffline-or-not$source.IsReadOnly){throw 'Formatted shadow or source exclusion differs.'}
        $match=[regex]::Match($v.Path,'\{([0-9a-fA-F-]{36})\}')
        if(-not$match.Success){throw 'Fresh volume identity unavailable.'}
        Set-StrictMode -Off
        @{volume_path_before=$before;volume_path=$v.Path;volume_guid=$match.Groups[1].Value;
            shadow_partition_guid=$p[0].Guid;filesystem=$v.FileSystem;allocation_unit=$v.AllocationUnitSize;
            source_offline=$true;source_readonly=$true;utc=[DateTime]::UtcNow.ToString('o')}
    }
    Save-New 'formatted-shadow.json' $formatted
    $pair=$oldRequest.pair;$pair.shadow.volume_guid=$formatted.volume_guid
    Save-New 'request.json' @{schema_version=1;pair=$pair;source_sha256=$oldRequest.comparison.source_sha256;expected_mount_paths=$oldRequest.expected_mount_paths}
    $request=Join-Path $root 'request.json';$requestPin=(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()
    Copy-Item -LiteralPath $binary -ToSession $s -Destination (Join-Path $stage 'lab-allocate-private-tree.exe')
    Copy-Item -LiteralPath $request -ToSession $s -Destination (Join-Path $stage 'request.json')
    Copy-Item -LiteralPath $tree -ToSession $s -Destination (Join-Path $stage 'expectation.json')
    Copy-Item -LiteralPath $inspection -ToSession $s -Destination (Join-Path $stage 'source-inspection.json')
    $dispatch=Invoke-Command -Session $s -ArgumentList $stage,$run,$pin,$requestPin,$treePin,$inspectionPin,([bool]$PrepareLargeTails),([bool]$PlaceSourcePrefixes),$placementBytes,([bool]$SourceBackedPayloads),([bool]$CaptureSourceBackedDifferences) -ScriptBlock {
        param($Stage,$Run,$Pin,$RequestPin,$TreePin,$InspectionPin,$Tails,$Place,$PlacementBytes,$SourceBacked,$CaptureDifferences);$ErrorActionPreference='Stop'
        $binary=Join-Path $Stage 'lab-allocate-private-tree.exe';$request=Join-Path $Stage 'request.json';$tree=Join-Path $Stage 'expectation.json'
        $inspection=Join-Path $Stage 'source-inspection.json'
        if((Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()-cne$Pin-or(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()-cne$RequestPin-or(Get-FileHash -LiteralPath $tree).Hash.ToLowerInvariant()-cne$TreePin-or(Get-FileHash -LiteralPath $inspection).Hash.ToLowerInvariant()-cne$InspectionPin){throw 'Staged pins differ.'}
        $task='N2R-PrivateTree-'+$Run
        if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){throw 'Fresh task required.'}
        $arguments='--request "'+$request+'" --request-sha256 '+$RequestPin+' --tree "'+$tree+'" --tree-sha256 '+$TreePin+' --materialize-small --inspection "'+$inspection+'" --inspection-sha256 '+$InspectionPin+' --output "'+(Join-Path $Stage 'result.json')+'"'
        if($Tails){$arguments+=' --prepare-large-tails'}
        if($Place){$arguments+=' --place-source-prefixes --max-placement-bytes '+$PlacementBytes+' --max-placement-moves 64'}
        if($SourceBacked){$arguments+=' --source-backed-payloads'}
        if($CaptureDifferences){$arguments+=' --compact-output "'+(Join-Path $Stage 'changed-clusters.bin')+'" --max-changed-bytes 805306368'}
        Register-ScheduledTask -TaskName $task -Action (New-ScheduledTaskAction -Execute $binary -Argument $arguments) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
        @{task_name=$task;run_id=$Run;guest_stage=$Stage;binary=$binary;binary_sha256=$Pin;arguments=$arguments;request_sha256=$RequestPin;tree_sha256=$TreePin;inspection_sha256=$InspectionPin}
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
