# Observe the one recorded alpha task. Never restarts, restores or changes disks.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace '.lab\hyperv\shadow-alpha-20261026'
$dispatch=Get-Content -LiteralPath (Join-Path $root 'normal-dispatch.json') -Raw|ConvertFrom-Json
$id=[guid]'0d9bfa66-c66c-4ead-86b7-e72cb5f7e040';$vm=Get-VM -Id $id
if([guid]$dispatch.vm_id-ne$id-or$vm.Name-cne'ntfs2refs-shadow-alpha-20261026'-or
    $vm.State.ToString()-cne'Running'-or[string]$vm.ParentSnapshotId-cne$dispatch.checkpoint_id-or
    $dispatch.task_name-cne('N2R-AlphaConvert-'+$dispatch.run_id)){throw 'Alpha task/owner branch differs.'}
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$result=Invoke-Command -VMId $id -Credential $credential -ArgumentList $dispatch.task_name,$dispatch.guest_output,$dispatch.run_id -ScriptBlock {
    param($Task,$Output,$Run);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
    $taskObject=Get-ScheduledTask -TaskName $Task;$info=Get-ScheduledTaskInfo -TaskName $Task
    $names=@('qualification/source-frozen.json','qualification/source-inspection.json','qualification/native-source.json',
        'qualification/certificate.json','qualification/failed.json','expectation.json','request.json','journal-location.json',
        'prepare.json','ticket.json','apply.json','finalization.json','result.json','failed.json')
    $present=@($names|Where-Object {Test-Path -LiteralPath (Join-Path $Output $_)})
    $live=$taskObject.State.ToString()-in@('Running','Queued')
    $processes=@(Get-CimInstance Win32_Process -Filter "Name='ntfs2refs.exe'"|Where-Object {
        $_.ExecutablePath-ceq'C:\ntfs2refs\alpha\native-shadow-alpha-20261026\ntfs2refs.exe'}|ForEach-Object {
            [pscustomobject]@{pid=$_.ProcessId;read_bytes=[long]$_.ReadTransferCount;written_bytes=[long]$_.WriteTransferCount;
                cpu_seconds=([double]$_.KernelModeTime+[double]$_.UserModeTime)/10000000}})
    $phase=if($present-contains'result.json'){'complete'}elseif($present-contains'failed.json'){'failed'}
        elseif($present-contains'apply.json'){'handoff/native-verification'}elseif($present-contains'ticket.json'){'raw-apply'}
        elseif($present-contains'journal-location.json'){'journal-preparation'}elseif($present-contains'qualification/certificate.json'){'qualified'}
        elseif($present-contains'qualification/native-source.json'){'shadow/target-qualification'}else{'source-qualification'}
    $details=@()
    if(-not$live){foreach($name in @('failed.json','qualification/failed.json','result.json')){
        $path=Join-Path $Output $name
        if(Test-Path -LiteralPath $path){$file=Get-Item -LiteralPath $path -Force;
            if($file.Length-gt128KB-or($file.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Bounded ordinary result required.'}
            $details+=[pscustomobject]@{name=$name;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();
                contents=(Get-Content -LiteralPath $path -Raw|ConvertFrom-Json)}
        }
    }}
    $progress=$null;$path=Join-Path $Output 'journal-progress.json'
    if(Test-Path -LiteralPath $path){try{$file=Get-Item -LiteralPath $path;if($file.Length-le4096){$progress=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json}}catch{}}
    [pscustomobject]@{run_id=$Run;task_name=$Task;state=$taskObject.State.ToString();last_task_result=$info.LastTaskResult;
        terminal=(-not$live-and$info.LastRunTime.Year-ge2000);phase=$phase;processes=$processes;artifacts=$present;
        progress=$progress;details=$details;disks=@(Get-Disk|ForEach-Object {[pscustomobject]@{number=$_.Number;guid=[string]$_.Guid;
            offline=$_.IsOffline;read_only=$_.IsReadOnly;is_boot=$_.IsBoot;is_system=$_.IsSystem}});
        observed_utc=[DateTime]::UtcNow.ToString('o')}
}
$path=Join-Path $root ('normal-observation-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json')
$result|ConvertTo-Json -Depth 18|Set-Content -LiteralPath $path -Encoding utf8
$result|ConvertTo-Json -Depth 18 -Compress
