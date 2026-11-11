# Save the completed private probe, then return only this owned VM to its
# preserved budget-refused images for a fresh frozen-shadow reuse operation.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$probeRoot=Join-Path $base 'candidate5\valid-data-probe'
$observer=Get-Content -LiteralPath (Join-Path $probeRoot 'reopen-v3\dispatch.json') -Raw|ConvertFrom-Json
$observed=Get-Content -LiteralPath (Join-Path $probeRoot 'reopen-v3\result.json') -Raw|ConvertFrom-Json
$frozen=Get-Content -LiteralPath (Join-Path $probeRoot 'failed-checkpoint.json') -Raw|ConvertFrom-Json
if($observed.kind-cne'native-private-valid-data-observation'-or-not$observed.file_id_info_matches-or-not$observed.file_metadata_matches-or
    $observed.payload_reads-ne0-or$observed.payload_write_calls-ne0-or$observed.valid_data_calls-ne0){throw 'Matching completed metadata-only observation required.'}
$root=Join-Path $base 'frozen-retry-preparation'
if(Test-Path -LiteralPath $root){throw 'Frozen retry preparation has state; inspect without restoring again.'}
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$vm=Get-VM -Id $id
$probeCheckpoint=Get-Content -LiteralPath (Join-Path $probeRoot 'reopen-v1\probe-checkpoint.json') -Raw|ConvertFrom-Json
if($vm.State.ToString()-cne'Running'-or$vm.ParentSnapshotId-ne[guid]$probeCheckpoint.checkpoint_id-or$vm.MemoryStartup-ne4GB-or$vm.DynamicMemoryEnabled-or
    @(Get-VMNetworkAdapter -VM $vm).Count){throw 'Owned isolated read-only probe child required.'}
$old=@(Get-VMSnapshot -VM $vm)
if($old.Count-ne11-or$old.Id-notcontains[guid]$frozen.checkpoint_id){throw 'All eleven old checkpoints and exact failed branch required.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 20GB
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$pin=(Get-FileHash -LiteralPath (Join-Path $probeRoot 'reopen-v3\result.json')).Hash.ToLowerInvariant()
$state=Invoke-Command -VMId $id -Credential $credential -ArgumentList $observer.task_name,$observer.guest_stage,$pin -ScriptBlock {
    param($Task,$Stage,$Pin);$ErrorActionPreference='Stop'
    if((Get-ScheduledTask -TaskName $Task).State.ToString()-in@('Running','Queued')-or(Get-ScheduledTaskInfo -TaskName $Task).LastTaskResult-ne0-or
        @(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'-or$_.Name-in@('lab-convert-admitted-tree.exe','lab-measure-general-journal.exe','lab-probe-native-valid-data.exe')}).Count){throw 'Terminal matching observer required.'}
    if((Get-FileHash -LiteralPath (Join-Path $Stage 'result.json')).Hash.ToLowerInvariant()-cne$Pin){throw 'Observed result changed.'}
    $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
    if([guid]$source.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or-not$source.IsOffline-or-not$source.IsReadOnly-or
        [guid]$shadow.Guid-ne[guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f'-or$shadow.IsOffline-or-not$shadow.IsReadOnly){throw 'Protected probe disk state differs.'}
    [pscustomobject]@{source_offline=$true;source_readonly=$true;shadow_readonly=$true;boot_utc=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');utc=[DateTime]::UtcNow.ToString('o')}
}
New-Item -ItemType Directory -Path $root|Out-Null
function Save-New([string]$Name,$Value){
    $f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}
}
Save-New 'intent.json' @{vm_id=$id;observer_result_sha256=$pin;state=$state;preserved_checkpoints=@($old.Id);restore_checkpoint=$frozen.checkpoint_id;
    expected_frozen_shadow_sha256='664331e3aa9ad08c1a14b6ae7440f6ee457123665d32c1b8a692abed77141c8a';source_payload_writes_by_controller=0;growth_allowance_bytes=20GB;utc=[DateTime]::UtcNow.ToString('o')}
Stop-VM -VM $vm -Confirm:$false -ErrorAction Stop
$off=Get-CimInstance -Namespace 'root/virtualization/v2' -ClassName Msvm_ComputerSystem -Filter "Name='2401593c-4b30-472e-9b6d-c9534cbaa599'"
if($off.EnabledState-ne3-or(Get-VM -Id $id).State.ToString()-cne'Off'){throw 'Clean OFF required; never force stop.'}
$saved=Checkpoint-VM -VM (Get-VM -Id $id) -SnapshotName 'streaming-v2-private-valid-data-reboot-observed' -Passthru
Save-New 'probe-outcome-checkpoint.json' @{checkpoint_id=$saved.Id;parent=$saved.ParentSnapshotId;name=$saved.Name;state='Off';utc=[DateTime]::UtcNow.ToString('o')}
$now=@(Get-VMSnapshot -VM (Get-VM -Id $id))
if($now.Count-ne12-or@($old|Where-Object {$now.Id-notcontains$_.Id}).Count){throw 'Probe and earlier branches were not all preserved.'}
Restore-VMSnapshot -VMSnapshot ($now|Where-Object Id -eq ([guid]$frozen.checkpoint_id)) -Confirm:$false -ErrorAction Stop
Save-New 'restore-completed.json' @{restored_checkpoint=$frozen.checkpoint_id;preserved_checkpoints=@($now.Id);utc=[DateTime]::UtcNow.ToString('o')}
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 20GB
Start-VM -VM (Get-VM -Id $id) -ErrorAction Stop|Out-Null
$s=$null;$deadline=[DateTime]::UtcNow.AddMinutes(8)
while($null-eq$s){try{$s=New-PSSession -VMId $id -Credential $credential -ErrorAction Stop}catch{if([DateTime]::UtcNow-ge$deadline){throw 'Single restored boot unavailable; inspect without repeating.'};Start-Sleep -Seconds 3}}
try{
    $ready=Invoke-Command -Session $s -ScriptBlock {
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'-or$_.Name-in@('lab-convert-admitted-tree.exe','lab-measure-general-journal.exe','lab-probe-native-valid-data.exe')}).Count){throw 'A previous worker is live.'}
        $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
        if([guid]$source.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or-not$source.IsOffline-or-not$source.IsReadOnly-or
            [guid]$shadow.Guid-ne[guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f'-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly){throw 'Restored frozen source/shadow differ.'}
        # Source becomes writable only for the ordinary live NTFS freeze and
        # fresh transaction checks. The controller never writes file payload.
        Set-Disk -Number 1 -IsReadOnly $false -ErrorAction Stop
        Set-Disk -Number 1 -IsOffline $false -ErrorAction Stop
        # Discover the existing shadow through a read-only mount, then the
        # dispatch helper excludes it again before starting the converter.
        Set-Disk -Number 3 -IsOffline $false -ErrorAction Stop
        $sourceVolume=Get-Volume -DriveLetter F;$shadowVolume=Get-Volume -DriveLetter R
        if($sourceVolume.FileSystem-cne'NTFS'-or$sourceVolume.AllocationUnitSize-ne65536-or$sourceVolume.FileSystemLabel-cne'n2r-stream-source'-or
            $shadowVolume.FileSystem-cne'ReFS'-or$shadowVolume.AllocationUnitSize-ne4096-or$shadowVolume.FileSystemLabel-cne'n2r-retained-shadow'-or
            -not(Get-Disk -Number 3).IsReadOnly){throw 'Restored live-source/read-only-shadow geometry differs.'}
        [pscustomobject]@{source_filesystem='NTFS';shadow_filesystem='ReFS';shadow_readonly=$true;source_payload_writes_by_controller=0;
            boot_utc=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');utc=[DateTime]::UtcNow.ToString('o')}
    }
    Save-New 'ready.json' $ready
    $ready|ConvertTo-Json -Compress
}finally{Remove-PSSession $s}
