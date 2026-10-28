# Read-only observation of one already recorded recovery task. Never dispatch,
# alter availability, retry an operation or infer exit from an observation timeout.
[CmdletBinding()]param(
    [Parameter(Mandatory)][ValidatePattern('^candidate(?:[2-9]|[1-9][0-9]+)$')][string]$Candidate,
    [Parameter(Mandatory)][ValidateSet('Resume','Finalize','Rollback')][string]$Operation
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$branch=if($Operation-ceq'Rollback'){'rollback'}else{'resume'}
$root=Join-Path $workspace ('.lab\hyperv\streaming-v2-20261027\'+$Candidate+'\recovery-'+$branch)
$d=Get-Content -LiteralPath (Join-Path $root ($Operation+'-dispatch.json')) -Raw|ConvertFrom-Json
if([guid]$d.vm_id-ne[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'-or$d.operation-cne$Operation-or$d.branch-cne$branch){throw 'Recovery enrollment differs.'}
if((Get-VM -Id $d.vm_id).State.ToString()-cne'Running'){throw 'Guest is not running; no start or terminal inference performed.'}
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$result=Invoke-Command -VMId $d.vm_id -Credential $credential -ArgumentList $d.task_name,$d.binary,$d.guest_output,$d.run_id,$Operation -ScriptBlock {
    param($Task,$Binary,$Output,$Run,$Mode);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
    $t=Get-ScheduledTask -TaskName $Task;$info=Get-ScheduledTaskInfo -TaskName $Task
    $all=@(Get-CimInstance Win32_Process|Where-Object {$_.Name-in@('ntfs2refs.exe','ntfs2refs-recover.exe','lab-convert-admitted-tree.exe')})
    $processes=@($all|Where-Object {$_.ExecutablePath-ceq$Binary-and$_.CommandLine-like('*'+$Output+'*')}|ForEach-Object {
        [pscustomobject]@{pid=$_.ProcessId;created=$_.CreationDate;read_bytes=[long]$_.ReadTransferCount;written_bytes=[long]$_.WriteTransferCount;
            working_set_bytes=[long]$_.WorkingSetSize;peak_working_set_kib=[long]$_.PeakWorkingSetSize;cpu_seconds=([double]$_.KernelModeTime+[double]$_.UserModeTime)/10000000}
    })
    $live=$t.State.ToString()-in@('Running','Queued')-or$all.Count-gt0
    $terminal=-not$live-and$info.LastRunTime.Year-ge2000
    $details=@()
    if($terminal){foreach($name in @('result.json','failed.json')){
        $path=Join-Path $Output $name
        if(Test-Path -LiteralPath $path){
            $item=Get-Item -LiteralPath $path
            if($item.Length-gt128KB-or$item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Bounded ordinary recovery result required.'}
            $details+=[pscustomobject]@{name=$name;sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant();contents=(Get-Content -LiteralPath $path -Raw|ConvertFrom-Json)}
        }
    }}
    [pscustomobject]@{run_id=$Run;operation=$Mode;task_name=$Task;state=$t.State.ToString();last_task_result=$info.LastTaskResult;
        terminal=$terminal;all_converter_count=$all.Count;processes=$processes;details=$details;
        artifacts=@(@('intent.json','journal-identity.json','execution.json','completion.json','result.json','failed.json')|Where-Object {Test-Path -LiteralPath (Join-Path $Output $_)});
        disks=@(Get-Disk|Select-Object Number,Guid,IsOffline,IsReadOnly,IsBoot,IsSystem);utc=[DateTime]::UtcNow.ToString('o')}
}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$result|Add-Member host_capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace))
$result|ConvertTo-Json -Depth 15|Set-Content -LiteralPath (Join-Path $root ($Operation+'-observation-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json')) -Encoding utf8
$result|ConvertTo-Json -Depth 15 -Compress
