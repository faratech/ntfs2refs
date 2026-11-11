# Explicit recovery only, using the interrupted run's original pinned helper.
# This controller never stops workers, sets disk attributes, restores a VM,
# detaches storage, retries an uncertain dispatch or replays after handoff.
[CmdletBinding()]param(
    [Parameter(Mandatory)][ValidatePattern('^candidate(?:[2-9]|[1-9][0-9]+)$')][string]$Candidate,
    [Parameter(Mandatory)][ValidateSet('Resume','Finalize','Rollback')][string]$Operation
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace ('.lab\hyperv\streaming-v2-20261027\'+$Candidate)
$d=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
$intent=Get-Content -LiteralPath (Join-Path $root 'intent.json') -Raw|ConvertFrom-Json
if([guid]$d.vm_id-ne[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'-or$d.expected_exit_code-ne86-or
    $d.interrupt_after_writes-ne1-or$d.binary_name-cne'lab-convert-admitted-tree.exe'){throw 'Enrolled one-write interruption required.'}
$branch=if($Operation-ceq'Rollback'){'rollback'}else{'resume'}
$exclusion=Get-Content -LiteralPath (Join-Path $root $(if($branch-ceq'rollback'){'exclusion-after-reboot-rollback.json'}else{'exclusion-after-reboot.json'})) -Raw|ConvertFrom-Json
if(-not$exclusion.success-or$exclusion.run_id-cne$d.run_id-or[guid]$exclusion.vm_id-ne[guid]$d.vm_id){throw 'Matching persistent exclusion reboot observation required.'}
$hostRoot=Join-Path $root ('recovery-'+$branch)
if(-not(Test-Path -LiteralPath $hostRoot)){New-Item -ItemType Directory -Path $hostRoot|Out-Null}
$dispatchPath=Join-Path $hostRoot ($Operation+'-dispatch.json')
if(Test-Path -LiteralPath $dispatchPath){throw 'Recovery dispatch already recorded; inspect its task without retrying.'}
$archive=Join-Path $root 'terminal-evidence/run'
$pins=@{}
foreach($name in @('request.json','ticket.json','expectation.json','interruption-intent.json','journal-location.json')){
    $path=Join-Path $archive $name
    $pins[$name]=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
}
$helper=@($intent.binaries|Where-Object {$_.name-ceq'ntfs2refs-recover.exe'})
if($helper.Count-ne1){throw 'Original recovery helper pin missing.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$growth=2GB
if($d.PSObject.Properties.Name-contains'controlled_retained_recovery'-and$d.controlled_retained_recovery){
    if($Candidate-cne'candidate13'-or$d.max_journal_bytes-ne1536MB-or-not$d.frozen_shadow_reuse){throw 'Retained recovery profile differs.'}
    # Existing fixed journal, <=1024 target intervals and796,917,760 changed
    # bytes: allow6 GiB OS, <5 GiB source COW and1 GiB metadata margin.
    $growth=if($Operation-ceq'Finalize'){4GB}else{12GB}
}
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes $growth
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$session=New-PSSession -VMId $d.vm_id -Credential $credential
try{
    $bound=Invoke-Command -Session $session -ArgumentList $d.task_name,$d.guest_stage,$d.guest_output,$d.run_id,$Operation,$branch,($pins|ConvertTo-Json -Compress),$helper[0].sha256 -ScriptBlock {
        param($ProducerTask,$Stage,$Original,$Run,$Mode,$Branch,$PinJson,$HelperPin)
        Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        $task=Get-ScheduledTask -TaskName $ProducerTask;$info=Get-ScheduledTaskInfo -TaskName $ProducerTask
        if($task.State.ToString()-in@('Running','Queued')-or$info.LastTaskResult-ne86-or
            @(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'-or$_.Name-ceq'lab-convert-admitted-tree.exe'}).Count){throw 'Interrupted producer must be terminal; no worker may be active.'}
        $pins=ConvertFrom-Json -InputObject $PinJson
        foreach($property in $pins.PSObject.Properties){
            $file=Get-Item -LiteralPath (Join-Path $Original $property.Name)
            if($file.PSIsContainer-or($file.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$file.Length-gt16MB-or
                (Get-FileHash -LiteralPath $file.FullName).Hash.ToLowerInvariant()-cne$property.Value){throw 'Original pinned recovery input differs.'}
        }
        $interruption=Get-Content -LiteralPath (Join-Path $Original 'interruption-intent.json') -Raw|ConvertFrom-Json
        if($interruption.interrupt_after_writes-ne1-or$interruption.expected_process_exit_code-ne86-or$interruption.handoff_authorized){throw 'Interruption boundary differs.'}
        if((Test-Path -LiteralPath (Join-Path $Original 'result.json'))-or(Test-Path -LiteralPath (Join-Path $Original 'finalization.json'))){throw 'Original conversion crossed its handoff boundary.'}
        $target=Get-Disk -Number 1;$shadow=Get-Disk -Number 3;$journal=Get-Disk -Number 2
        if($target.IsBoot-or$target.IsSystem-or-not$target.IsOffline-or$target.IsReadOnly-or
            -not$shadow.IsOffline-or-not$shadow.IsReadOnly-or$journal.IsOffline-or$journal.IsReadOnly-or
            [guid]$target.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or
            [guid]$shadow.Guid-ne[guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f'-or
            [guid]$journal.Guid-ne[guid]'09fcc613-b8c2-4a1a-8833-226f9399be7f'){throw 'Exact excluded source/shadow and independent journal required.'}
        $request=Join-Path $Original 'request.json';$ticket=Join-Path $Original 'ticket.json'
        $location=Get-Content -LiteralPath (Join-Path $Original 'journal-location.json') -Raw|ConvertFrom-Json
        if($location.path-cne$interruption.journal_path-or$interruption.ticket_sha256-cne$pins.'ticket.json'){throw 'Trusted ticket/journal pins differ.'}
        $binary=Join-Path $Stage 'ntfs2refs-recover.exe'
        if((Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()-cne$HelperPin){throw 'Original recovery executable changed.'}
        $base='C:\ntfs2refs\streaming-v2-recovery\'+$Run+'\'+$Branch
        if($Mode-ceq'Finalize'){
            $prior=Get-Content -LiteralPath (Join-Path $base 'Resume/result.json') -Raw|ConvertFrom-Json
            if(-not$prior.success-or$prior.operation-cne'resume'-or-not$prior.target_remains_offline-or$prior.rollback_closed){throw 'Completed excluded resume required before handoff.'}
        }
        $output=Join-Path $base $Mode
        if(Test-Path -LiteralPath $output){throw 'Fresh recovery output required.'}
        $arguments=$Mode.ToLowerInvariant()+' --request "'+$request+'" --request-sha256 '+$pins.'request.json'+
            ' --ticket "'+$ticket+'" --ticket-sha256 '+$pins.'ticket.json'+' --journal "'+$location.path+'" --output "'+$output+'"'
        if($Mode-ceq'Finalize'){$arguments+=' --expectation "'+(Join-Path $Original 'expectation.json')+'" --expectation-sha256 '+$pins.'expectation.json'}
        $name='N2R-StreamingV2Recover-'+$Mode+'-'+$Run
        if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Recovery task already exists.'}
        $action=New-ScheduledTaskAction -Execute $binary -Argument $arguments
        $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
        [pscustomobject]@{run_id=$Run;operation=$Mode;branch=$Branch;task_name=$name;binary=$binary;binary_sha256=$HelperPin;arguments=$arguments;guest_output=$output;
            target_offline=$target.IsOffline;target_readonly=$target.IsReadOnly;shadow_offline=$shadow.IsOffline;shadow_readonly=$shadow.IsReadOnly;utc=[DateTime]::UtcNow.ToString('o')}
    }
    $bound|Add-Member vm_id $d.vm_id
    $stream=[IO.File]::Open($dispatchPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($bound|ConvertTo-Json -Depth 8));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    Invoke-Command -Session $session -ArgumentList $bound.task_name,$bound.binary,$bound.arguments -ScriptBlock {
        param($Name,$Binary,$Arguments);$ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskName $Name;$info=Get-ScheduledTaskInfo -TaskName $Name
        if($t.State.ToString()-cne'Ready'-or$info.LastRunTime.Year-ge2000-or@($t.Actions).Count-ne1-or
            $t.Actions[0].Execute-cne$Binary-or$t.Actions[0].Arguments-cne$Arguments){throw 'Unstarted matching recovery task required.'}
        Start-ScheduledTask -TaskName $Name
    }
    $bound|ConvertTo-Json -Depth 8 -Compress
}finally{Remove-PSSession $session}
