# Independent native NTFS readback only after exact-image rollback completion.
# No source availability changes, journal replay or recovery dispatch.
[CmdletBinding()]param([ValidateSet('candidate13')][string]$Candidate='candidate13')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace ('.lab\hyperv\streaming-v2-20261027\'+$Candidate)
$d=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
$rollback=Get-Content -LiteralPath (Join-Path $root 'recovery-rollback\Rollback-dispatch.json') -Raw|ConvertFrom-Json
$fixture=Get-Content -LiteralPath (Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\retention8g\fixture.json') -Raw
if([guid]$d.vm_id-ne[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'-or-not$d.controlled_retained_recovery-or
    $rollback.run_id-cne$d.run_id-or$rollback.operation-cne'Rollback'){throw 'Exact recorded retained rollback required.'}
$out=Join-Path $root 'recovery-rollback\native-payload-readback.json'
if(Test-Path -LiteralPath $out){throw 'Readback already has a result; inspect its receipt.'}
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$value=Invoke-Command -VMId $d.vm_id -Credential $credential -ArgumentList $rollback.task_name,$rollback.guest_output,$fixture -ScriptBlock {
    param($Task,$Output,$Fixture);$ErrorActionPreference='Stop'
    if((Get-ScheduledTask -TaskName $Task).State.ToString()-cne'Ready'-or(Get-ScheduledTaskInfo -TaskName $Task).LastTaskResult-ne0-or
        @(Get-CimInstance Win32_Process|Where-Object {$_.Name-in@('ntfs2refs-recover.exe','lab-convert-admitted-tree.exe')}).Count){throw 'Terminal successful rollback required.'}
    $result=Get-Content -LiteralPath (Join-Path $Output 'result.json') -Raw|ConvertFrom-Json
    $complete=Get-Content -LiteralPath (Join-Path $Output 'completion.json') -Raw|ConvertFrom-Json
    $execution=Get-Content -LiteralPath (Join-Path $Output 'execution.json') -Raw|ConvertFrom-Json
    if(-not$result.success-or$result.operation-cne'rollback'-or-not$result.ntfs_rollback_completed-or
        -not$complete.success-or-not$complete.replay_closed-or$complete.mounted_filesystem-cne'NTFS'-or
        $execution.expected_target_sha256-cne'd8fd89c7779af5304fc4e5d00fbc15ab61155830b6613842c962baae6d9661c1'-or
        $execution.result.target_sha256-cne$execution.expected_target_sha256){throw 'Exact admitted NTFS restoration and closed recovery required.'}
    $disk=Get-Disk -Number 1;$partition=Get-Partition -DriveLetter F;$volume=Get-Volume -DriveLetter F
    if([guid]$disk.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or$disk.IsBoot-or$disk.IsSystem-or$disk.IsOffline-or$disk.IsReadOnly-or
        $partition.DiskNumber-ne1-or[guid]$partition.Guid-ne[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-or$partition.Size-ne52GB-or
        $volume.FileSystem-cne'NTFS'-or$volume.AllocationUnitSize-ne65536-or$volume.FileSystemLabel-cne'n2r-stream-source'){throw 'Restored original volume identity differs.'}
    $expected=ConvertFrom-Json -InputObject $Fixture
    $files=@(foreach($row in $expected.files){
        if(-not([string]$row.path).StartsWith('F:\',[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture escaped source.'}
        $item=Get-Item -LiteralPath $row.path -Force
        if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-ne[long]$row.bytes){throw 'Restored user file type/length differs.'}
        $pin=(Get-FileHash -LiteralPath $row.path -Algorithm SHA256).Hash.ToLowerInvariant()
        if($pin-cne$row.sha256){throw 'Restored user payload hash differs.'}
        @{path=$row.path;bytes=$item.Length;sha256=$pin}
    })
    @{success=$true;kind='retained-streaming-native-ntfs-rollback-readback';files=$files;filesystem=$volume.FileSystem;
        cluster_bytes=$volume.AllocationUnitSize;original_image_hash_proved_before_mount=$execution.result.target_sha256;
        result_sha256=(Get-FileHash -LiteralPath (Join-Path $Output 'result.json')).Hash.ToLowerInvariant();
        execution_sha256=(Get-FileHash -LiteralPath (Join-Path $Output 'execution.json')).Hash.ToLowerInvariant();
        completion_sha256=(Get-FileHash -LiteralPath (Join-Path $Output 'completion.json')).Hash.ToLowerInvariant();
        observer_source_writes=0;power_loss_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')}
}
$value|Add-Member run_id $d.run_id
$f=[IO.File]::Open($out,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 16));$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
@{success=$value.success;files_verified=$value.files.Count;readback_sha256=(Get-FileHash -LiteralPath $out).Hash.ToLowerInvariant();original_image_hash=$value.original_image_hash_proved_before_mount}|ConvertTo-Json -Compress
