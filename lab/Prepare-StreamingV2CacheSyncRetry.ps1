# Preserve the source-cache refusal before a fresh, explicit tiny-cache sync.
[CmdletBinding()]param([ValidateSet(1,2,3)][int]$Version=1)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$base=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$candidateName=switch($Version){1{'candidate9'}2{'candidate10'}3{'candidate11'}}
$candidate=Join-Path $base $candidateName;$d=Get-Content -LiteralPath (Join-Path $candidate 'dispatch.json') -Raw|ConvertFrom-Json
$archive=Get-Content -LiteralPath (Join-Path $candidate 'terminal-evidence-manifest.json') -Raw|ConvertFrom-Json
$failed=Get-Content -LiteralPath (Join-Path $candidate 'terminal-evidence\run\failed.json') -Raw|ConvertFrom-Json
$expectedRun=switch($Version){1{'9cfeda0cdcd9449f8e3342d31c23eed7'}2{'e8455536ad3b4bf189b2a07d67b3af42'}3{'6e45d7f749da4687b4e862f6498945d4'}}
$expectedError=switch($Version){1{'The system cannot find the file specified. (os error 2)'}2{'native control budget exceeded'}3{'journal file is oversized, linked, deleting or not an ordinary stream'}}
$expectedPhase=if($Version-eq3){'journal-preparation'}else{'qualification'}
if($d.run_id-cne$expectedRun-or-not$archive.verified-or$archive.run_id-cne$d.run_id-or
    $failed.phase-cne$expectedPhase-or$failed.error-cne$expectedError){throw 'Exact archived pre-write refusal required.'}
$root=Join-Path $base $(if($Version-eq1){'cache-sync-retry-preparation'}else{'cache-sync-retry-preparation-v'+$Version})
if(Test-Path -LiteralPath $root){throw 'Cache-sync preparation has state; inspect without repeating.'}
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$vm=Get-VM -Id $id
$expectedParent=switch($Version){1{[guid]'b3aee3e3-a5e1-4cf2-b69d-c1903a885bff'}2{[guid]'51626f1f-5778-4106-a61c-cb509d80e5b4'}3{[guid]'ba9654d9-7a50-4b7b-bbd7-50cde85d0e0f'}}
if($vm.State.ToString()-cne'Running'-or$vm.ParentSnapshotId-ne$expectedParent-or
    $vm.MemoryStartup-ne4GB-or$vm.DynamicMemoryEnabled-or@(Get-VMNetworkAdapter -VM $vm).Count){throw 'Owned isolated refused child required.'}
$old=@(Get-VMSnapshot -VM $vm)
if($old.Count-ne(11+$Version)){throw 'All earlier checkpoints are required.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 20GB
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$state=Invoke-Command -VMId $id -Credential $credential -ArgumentList $d.task_name,$d.guest_output -ScriptBlock {
    param($Task,$Output);$ErrorActionPreference='Stop'
    if((Get-ScheduledTask -TaskName $Task).State.ToString()-in@('Running','Queued')-or(Get-ScheduledTaskInfo -TaskName $Task).LastTaskResult-ne1-or
        @(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'-or$_.Name-in@('lab-convert-admitted-tree.exe','lab-measure-general-journal.exe','lab-probe-native-valid-data.exe')}).Count){throw 'Terminal refused conversion required.'}
    foreach($name in @('ticket.json','prepare.json','apply.json','finalization.json','result.json')){if(Test-Path -LiteralPath (Join-Path $Output $name)){throw 'Unexpected prepared/applied boundary; inspect instead.'}}
    $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
    if([guid]$source.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or-not$source.IsOffline-or-not$source.IsReadOnly-or
        [guid]$shadow.Guid-ne[guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f'-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly){throw 'Frozen pre-write pair required.'}
    [pscustomobject]@{source_offline=$true;source_readonly=$true;shadow_offline=$true;shadow_readonly=$true;utc=[DateTime]::UtcNow.ToString('o')}
}
New-Item -ItemType Directory -Path $root|Out-Null
function Save-New([string]$Name,$Value){
    $f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}
}
Save-New 'intent.json' @{vm_id=$id;prior_run=$d.run_id;state=$state;preserved_checkpoints=@($old.Id);source_payload_writes_by_controller=0;growth_allowance_bytes=20GB;utc=[DateTime]::UtcNow.ToString('o')}
Stop-VM -VM $vm -Confirm:$false -ErrorAction Stop
$off=Get-CimInstance -Namespace 'root/virtualization/v2' -ClassName Msvm_ComputerSystem -Filter "Name='2401593c-4b30-472e-9b6d-c9534cbaa599'"
if($off.EnabledState-ne3-or(Get-VM -Id $id).State.ToString()-cne'Off'){throw 'Clean OFF required; no force stop.'}
$snapshotName=switch($Version){1{'streaming-v2-candidate9-source-cache-refused'}2{'streaming-v2-candidate10-audit-budget-refused'}3{'streaming-v2-candidate11-native-profile-refused'}}
$saved=Checkpoint-VM -VM (Get-VM -Id $id) -SnapshotName $snapshotName -Passthru
Save-New 'refused-checkpoint.json' @{checkpoint_id=$saved.Id;parent=$saved.ParentSnapshotId;name=$saved.Name;state='Off';utc=[DateTime]::UtcNow.ToString('o')}
$now=@(Get-VMSnapshot -VM (Get-VM -Id $id))
if($now.Count-ne(12+$Version)-or@($old|Where-Object {$now.Id-notcontains$_.Id}).Count){throw 'Checkpoint preservation differs.'}
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 20GB
Start-VM -VM (Get-VM -Id $id) -ErrorAction Stop|Out-Null
$s=$null;$deadline=[DateTime]::UtcNow.AddMinutes(8)
while($null-eq$s){try{$s=New-PSSession -VMId $id -Credential $credential -ErrorAction Stop}catch{if([DateTime]::UtcNow-ge$deadline){throw 'Single clean boot unavailable; inspect without restart.'};Start-Sleep -Seconds 3}}
try{
    $ready=Invoke-Command -Session $s -ScriptBlock {
        $ErrorActionPreference='Stop'
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'-or$_.Name-in@('lab-convert-admitted-tree.exe','lab-measure-general-journal.exe','lab-probe-native-valid-data.exe')}).Count){throw 'Unexpected live worker.'}
        $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
        if([guid]$source.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or-not$source.IsOffline-or-not$source.IsReadOnly-or
            [guid]$shadow.Guid-ne[guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f'-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly){throw 'Frozen identities/exclusion did not persist.'}
        foreach($number in @(1,3)){Set-Disk -Number $number -IsReadOnly $false -ErrorAction Stop;Set-Disk -Number $number -IsOffline $false -ErrorAction Stop}
        $sourceVolume=Get-Volume -DriveLetter F;$shadowVolume=Get-Volume -DriveLetter R
        if($sourceVolume.FileSystem-cne'NTFS'-or$sourceVolume.AllocationUnitSize-ne65536-or$sourceVolume.FileSystemLabel-cne'n2r-stream-source'-or
            $shadowVolume.FileSystem-cne'ReFS'-or$shadowVolume.AllocationUnitSize-ne4096-or$shadowVolume.FileSystemLabel-cne'n2r-retained-shadow'){throw 'Source/shadow geometry differs.'}
        [pscustomobject]@{source_filesystem='NTFS';shadow_filesystem='ReFS';shadow_writable=$true;source_payload_writes_by_controller=0;new_shadow_payload_copy=$false;
            boot_utc=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');utc=[DateTime]::UtcNow.ToString('o')}
    }
    Save-New 'ready.json' $ready;$ready|ConvertTo-Json -Compress
}finally{Remove-PSSession $s}
