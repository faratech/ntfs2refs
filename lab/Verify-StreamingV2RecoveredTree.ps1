# Independent pinned native semantics/physical-position check after recovery.
# No synthetic normal-conversion result, journal replay or availability change.
[CmdletBinding()]param([ValidateSet('candidate13')][string]$Candidate='candidate13')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace ('.lab\hyperv\streaming-v2-20261027\'+$Candidate)
$d=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
$finalize=Get-Content -LiteralPath (Join-Path $root 'recovery-resume\Finalize-dispatch.json') -Raw|ConvertFrom-Json
$request=Join-Path $root 'terminal-evidence\run\request.json';$tree=Join-Path $root 'terminal-evidence\run\expectation.json'
$requestPin=(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant();$treePin=(Get-FileHash -LiteralPath $tree).Hash.ToLowerInvariant()
$tool=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\candidate12\rust-postcheck-tools-v2\lab-verify-general-converted.exe'
$toolPin='8f3675076a34bd977245744af702c82d7bf2b6c662e757246b153fcaf6840f9a'
if([guid]$d.vm_id-ne[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'-or-not$d.controlled_retained_recovery-or
    $finalize.run_id-cne$d.run_id-or$finalize.operation-cne'Finalize'-or(Get-FileHash -LiteralPath $tool).Hash.ToLowerInvariant()-cne$toolPin){throw 'Exact retained recovery/tool binding required.'}
$post=Join-Path $root 'recovery-resume\native-postcheck'
if(Test-Path -LiteralPath $post){throw 'Verification has state; inspect it without redispatch.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 256MB
$cred=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$s=New-PSSession -VMId $d.vm_id -Credential $cred
try{
    $guest=Join-Path (Split-Path -Parent $finalize.guest_output) 'native-postcheck'
    $bound=Invoke-Command -Session $s -ArgumentList $finalize.task_name,$finalize.guest_output,$guest,$d.guest_output,$requestPin,$treePin -ScriptBlock {
        param($Task,$Completed,$Stage,$Original,$RequestPin,$TreePin);$ErrorActionPreference='Stop'
        if((Get-ScheduledTask -TaskName $Task).State.ToString()-cne'Ready'-or(Get-ScheduledTaskInfo -TaskName $Task).LastTaskResult-ne0-or
            @(Get-CimInstance Win32_Process|Where-Object {$_.Name-in@('ntfs2refs.exe','ntfs2refs-recover.exe','lab-convert-admitted-tree.exe','lab-verify-general-converted.exe')}).Count){throw 'Completed finalization and no worker required.'}
        $resultPath=Join-Path $Completed 'result.json';$completionPath=Join-Path $Completed 'completion.json'
        $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json;$complete=Get-Content -LiteralPath $completionPath -Raw|ConvertFrom-Json
        if($result.kind-cne'general-recovery'-or$result.operation-cne'finalize'-or-not$result.success-or-not$result.rollback_closed-or
            -not$complete.success-or-not$complete.rollback_closed-or$null-eq$complete.native){throw 'Real closed recovery handoff required.'}
        if((Get-FileHash -LiteralPath (Join-Path $Original 'request.json')).Hash.ToLowerInvariant()-cne$RequestPin-or
            (Get-FileHash -LiteralPath (Join-Path $Original 'expectation.json')).Hash.ToLowerInvariant()-cne$TreePin){throw 'Original recovered inputs changed.'}
        $source=Get-Disk -Number 1;$partition=Get-Partition -DriveLetter F;$volume=Get-Volume -DriveLetter F
        if([guid]$source.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or$source.IsOffline-or$source.IsReadOnly-or$source.IsBoot-or$source.IsSystem-or
            $partition.DiskNumber-ne1-or[guid]$partition.Guid-ne[guid]'f06075a8-67a2-46b9-8fac-4af4da809617'-or$partition.Size-ne52GB-or
            $volume.FileSystem-cne'ReFS'-or$volume.AllocationUnitSize-ne4096){throw 'Recovered original partition differs.'}
        if(Test-Path -LiteralPath $Stage){throw 'Fresh native verification stage required.'}
        New-Item -ItemType Directory -Path $Stage|Out-Null;Set-StrictMode -Off
        @{finalization_sha256=(Get-FileHash -LiteralPath $resultPath).Hash.ToLowerInvariant();completion_sha256=(Get-FileHash -LiteralPath $completionPath).Hash.ToLowerInvariant();
            boot_utc=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')}
    }
    New-Item -ItemType Directory -Path $post|Out-Null
    function Save-New([string]$name,$value){$f=[IO.File]::Open((Join-Path $post $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($value|ConvertTo-Json -Depth 14));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
    Save-New 'intent.json' @{run_id=$d.run_id;vm_id=$d.vm_id;tool_sha256=$toolPin;request_sha256=$requestPin;tree_sha256=$treePin;real_recovery_handoff=$bound;source_writes_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')}
    Copy-Item -LiteralPath $tool -ToSession $s -Destination (Join-Path $guest 'lab-verify-general-converted.exe')
    $record=Invoke-Command -Session $s -ArgumentList $guest,$d.guest_output,$d.run_id,$toolPin,$requestPin,$treePin -ScriptBlock {
        param($Stage,$Original,$Run,$ToolPin,$RequestPin,$TreePin);$ErrorActionPreference='Stop'
        $binary=Join-Path $Stage 'lab-verify-general-converted.exe'
        if((Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()-cne$ToolPin){throw 'Staged verifier differs.'}
        $task='N2R-RecoveredNativeVerify-'+$Run
        if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){throw 'Fresh verifier task required.'}
        $args='--request "'+(Join-Path $Original 'request.json')+'" --request-sha256 '+$RequestPin+' --expectation "'+(Join-Path $Original 'expectation.json')+'" --expectation-sha256 '+$TreePin+' --verify-retained-positions --output "'+(Join-Path $Stage 'result.json')+'"'
        Register-ScheduledTask -TaskName $task -Action (New-ScheduledTaskAction -Execute $binary -Argument $args) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
        @{task_name=$task;binary=$binary;binary_sha256=$ToolPin;arguments=$args;guest_output=$Stage;run_id=$Run}
    }
    Save-New 'dispatch.json' $record
    Invoke-Command -Session $s -ArgumentList $record.task_name,$record.binary,$record.arguments -ScriptBlock {param($Task,$Binary,$Arguments);$t=Get-ScheduledTask -TaskName $Task;$i=Get-ScheduledTaskInfo -TaskName $Task;if($t.State.ToString()-cne'Ready'-or$i.LastRunTime.Year-ge2000-or$t.Actions[0].Execute-cne$Binary-or$t.Actions[0].Arguments-cne$Arguments){throw 'Fresh unchanged verifier required.'};Start-ScheduledTask -TaskName $Task}
    $record|ConvertTo-Json -Compress
}finally{Remove-PSSession $s}
