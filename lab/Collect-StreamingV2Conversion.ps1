# Read-only observation; never dispatches, repairs, restarts or changes disks.
[CmdletBinding()]param([ValidatePattern('^candidate[1-9][0-9]*$')][string]$Candidate='candidate1')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace ('.lab\hyperv\streaming-v2-20261027\'+$Candidate)
$d=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599';$vm=Get-VM -Id $id
if([guid]$d.vm_id-ne$id-or$vm.Name-cne'ntfs2refs-streaming-v2-20261027'-or$vm.State.ToString()-cne'Running'-or$d.task_name-cne('N2R-StreamingV2Convert-'+$d.run_id)){throw 'Recorded owned VM/task differs; inspect without inferring termination.'}
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$binaryName=if($d.PSObject.Properties.Name-contains'binary_name'){$d.binary_name}else{'ntfs2refs.exe'}
if($binaryName-cnotin@('ntfs2refs.exe','lab-convert-admitted-tree.exe')){throw 'Unknown producer executable.'}
$result=Invoke-Command -VMId $id -Credential $credential -ArgumentList $d.task_name,$d.guest_stage,$d.guest_output,$d.run_id,$binaryName -ScriptBlock {
    param($TaskName,$Stage,$Output,$Run,$BinaryName);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
    $taskObject=Get-ScheduledTask -TaskName $TaskName;$info=Get-ScheduledTaskInfo -TaskName $TaskName
    $all=@(Get-CimInstance Win32_Process|Where-Object {$_.Name-in@('ntfs2refs.exe','ntfs2refs-recover.exe','lab-convert-admitted-tree.exe')})
    $processes=@($all|Where-Object {$_.ExecutablePath-ceq(Join-Path $Stage $BinaryName)-and$_.CommandLine-like('*'+$Run+'*')}|ForEach-Object {
        [pscustomobject]@{pid=$_.ProcessId;created=$_.CreationDate;read_bytes=[long]$_.ReadTransferCount;written_bytes=[long]$_.WriteTransferCount;
            working_set_bytes=[long]$_.WorkingSetSize;peak_working_set_kib=[long]$_.PeakWorkingSetSize;
            cpu_seconds=([double]$_.KernelModeTime+[double]$_.UserModeTime)/10000000}
    })
    $live=$taskObject.State.ToString()-in@('Running','Queued')-or$all.Count-gt0
    $names=@('qualification/source-frozen.json','qualification/source-basis.json','qualification/native-source.json','qualification/source-assessment.json','qualification/expectation.json','qualification/native-shadow.json','qualification/native-shadow-reuse.json','qualification/target-preservation.json','qualification/certificate.json','qualification/failed.json','expectation.json','request.json','journal-location.json','prepare.json','ticket.json','apply.json','finalization.json','result.json','failed.json')
    $artifacts=@($names|Where-Object {Test-Path -LiteralPath (Join-Path $Output $_)})
    $phase=if($artifacts-contains'result.json'){'complete'}elseif($artifacts-contains'failed.json'-or$artifacts-contains'qualification/failed.json'){'failed'}elseif($artifacts-contains'apply.json'){'handoff/native-verification'}elseif($artifacts-contains'ticket.json'){'raw-apply'}elseif($artifacts-contains'journal-location.json'){'journal-preparation'}elseif($artifacts-contains'qualification/certificate.json'){'qualified'}elseif($artifacts-contains'qualification/native-shadow.json'){'target-preservation'}elseif($artifacts-contains'qualification/source-assessment.json'){'native-shadow-construction'}elseif($artifacts-contains'qualification/native-source.json'){'source-admission'}elseif($artifacts-contains'qualification/source-basis.json'){'source-observation'}else{'source-qualification'}
    $details=@()
    if(-not$live){foreach($name in @('failed.json','qualification/failed.json','result.json')){
        $path=Join-Path $Output $name
        if(Test-Path -LiteralPath $path){$file=Get-Item -LiteralPath $path;if($file.Length-gt128KB-or($file.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Bounded ordinary result required.'};$details+=[pscustomobject]@{name=$name;sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant();contents=(Get-Content -LiteralPath $path -Raw|ConvertFrom-Json)}}
    }}
    $progress=$null;$path=Join-Path $Output 'journal-progress.json'
    if(Test-Path -LiteralPath $path){try{if((Get-Item -LiteralPath $path).Length-le4096){$progress=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json}}catch{}}
    $interrupted= -not$live-and$info.LastTaskResult-eq86-and(Test-Path -LiteralPath (Join-Path $Output 'interruption-intent.json'))
    if($interrupted){$phase='interrupted-before-handoff'}
    [pscustomobject]@{run_id=$Run;state=$taskObject.State.ToString();last_task_result=$info.LastTaskResult;terminal=(-not$live-and$info.LastRunTime.Year-ge2000);phase=$phase;controlled_interruption_observed=$interrupted;
        processes=$processes;all_converter_count=$all.Count;artifacts=$artifacts;progress=$progress;details=$details;disks=@(Get-Disk|Select-Object Number,Guid,IsOffline,IsReadOnly,IsBoot,IsSystem);utc=[DateTime]::UtcNow.ToString('o')}
}
$capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
$result|Add-Member host_capacity $capacity
$result|ConvertTo-Json -Depth 20|Set-Content -LiteralPath (Join-Path $root ('observation-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json')) -Encoding utf8
$result|ConvertTo-Json -Depth 20 -Compress
