# Read-only observation of one recorded beta run; never starts or repairs work.
[CmdletBinding()]param([Parameter(Mandatory)][ValidatePattern('^candidate[2-9][0-9]*$')][string]$Candidate)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace ('.lab\hyperv\shadow-large-beta-20261027\'+$Candidate)
$dispatch=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
$id=[guid]'6c4793d2-cdee-468b-bf3b-1c11cae0b501';$vm=Get-VM -Id $id
if([guid]$dispatch.vm_id-ne$id-or$vm.Name-cne'ntfs2refs-shadow-large-beta-20261027'-or$vm.State.ToString()-cne'Running'-or
    $dispatch.task_name-cne('N2R-LargeBetaConvert-'+$dispatch.run_id)){throw 'Recorded beta task/owner differs.'}
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$result=Invoke-Command -VMId $id -Credential $credential -ArgumentList $dispatch.task_name,$dispatch.guest_output,$dispatch.run_id,$dispatch.guest_stage -ScriptBlock {
    param($Task,$Output,$Run,$Stage);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
    $taskObject=Get-ScheduledTask -TaskName $Task;$info=Get-ScheduledTaskInfo -TaskName $Task
    $all=@(Get-CimInstance Win32_Process|Where-Object {$_.Name-ceq'ntfs2refs.exe'})
    $processes=@($all|Where-Object {$_.ExecutablePath-ceq($Stage+'\ntfs2refs.exe')-and$_.CommandLine-like('*'+$Run+'*')}|ForEach-Object {
        [pscustomobject]@{pid=$_.ProcessId;created=$_.CreationDate;read_bytes=[long]$_.ReadTransferCount;written_bytes=[long]$_.WriteTransferCount;
            cpu_seconds=([double]$_.KernelModeTime+[double]$_.UserModeTime)/10000000}})
    $live=$taskObject.State.ToString()-in@('Running','Queued')-or$all.Count-gt0
    $names=@('qualification/source-frozen.json','qualification/source-basis.json','qualification/native-source.json','qualification/certificate.json',
        'qualification/failed.json','expectation.json','request.json','journal-location.json','prepare.json','ticket.json','apply.json','finalization.json','result.json','failed.json')
    $present=@($names|Where-Object {Test-Path -LiteralPath (Join-Path $Output $_)})
    $phase=if($present-contains'result.json'){'complete'}elseif($present-contains'failed.json'){'failed'}
        elseif($present-contains'apply.json'){'handoff/native-verification'}elseif($present-contains'ticket.json'){'raw-apply'}
        elseif($present-contains'journal-location.json'){'journal-preparation'}elseif($present-contains'qualification/certificate.json'){'qualified'}
        elseif($present-contains'qualification/native-source.json'){'shadow/target-qualification'}else{'source-qualification'}
    $details=@()
    if(-not$live){foreach($name in @('failed.json','qualification/failed.json','result.json')){
        $path=Join-Path $Output $name
        if(Test-Path -LiteralPath $path){$file=Get-Item -LiteralPath $path -Force
            if($file.Length-gt128KB-or($file.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Bounded ordinary result required.'}
            $details+=[pscustomobject]@{name=$name;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();contents=(Get-Content -LiteralPath $path -Raw|ConvertFrom-Json)}
        }
    }}
    $progress=$null;$path=Join-Path $Output 'journal-progress.json'
    if(Test-Path -LiteralPath $path){try{$file=Get-Item -LiteralPath $path;if($file.Length-le4096){$progress=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json}}catch{}}
    [pscustomobject]@{run_id=$Run;task_name=$Task;state=$taskObject.State.ToString();last_task_result=$info.LastTaskResult;
        terminal=(-not$live-and$info.LastRunTime.Year-ge2000);phase=$phase;processes=$processes;all_converter_count=$all.Count;artifacts=$present;
        progress=$progress;details=$details;disks=@(Get-Disk|ForEach-Object {[pscustomobject]@{number=$_.Number;guid=[string]$_.Guid;
            offline=$_.IsOffline;read_only=$_.IsReadOnly;is_boot=$_.IsBoot;is_system=$_.IsSystem}});observed_utc=[DateTime]::UtcNow.ToString('o')}
}
$path=Join-Path $root ('observation-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json')
$result|ConvertTo-Json -Depth 18|Set-Content -LiteralPath $path -Encoding utf8
$result|ConvertTo-Json -Depth 18 -Compress
