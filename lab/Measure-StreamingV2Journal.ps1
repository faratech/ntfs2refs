# Measure the already frozen images after a terminal journal-budget refusal.
# No disk-state changes, source writes, journal creation, boot or replay.
[CmdletBinding()]param([Parameter(Mandatory)][ValidatePattern('^candidate(?:[2-9]|[1-9][0-9]+)$')][string]$Candidate)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace ('.lab\hyperv\streaming-v2-20261027\'+$Candidate)
$d=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
$archive=Get-Content -LiteralPath (Join-Path $root 'terminal-evidence-manifest.json') -Raw|ConvertFrom-Json
$failed=Get-Content -LiteralPath (Join-Path $root 'terminal-evidence\run\failed.json') -Raw|ConvertFrom-Json
if([guid]$d.vm_id-ne[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'-or-not$archive.verified-or$archive.run_id-cne$d.run_id-or
    $failed.phase-cne'journal-preparation'-or$failed.error-cne'changed-sector byte budget exceeded'){throw 'Archived exact budget refusal required.'}
$stage=Join-Path $root 'journal-sizing'
if(Test-Path -LiteralPath $stage){throw 'Sizing already has state; inspect without redispatch.'}
if((Get-VM -Id $d.vm_id).State.ToString()-cne'Running'){throw 'Existing running guest required; this observer cannot boot it.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 16MB
$binary=Join-Path $workspace 'target\release\lab-measure-general-journal.exe'
$item=Get-Item -LiteralPath $binary
if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-or$item.Length-gt8MB){throw 'Bounded ordinary observer required.'}
$pin=(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()
$requestPin=(Get-FileHash -LiteralPath (Join-Path $root 'terminal-evidence\run\request.json')).Hash.ToLowerInvariant()
New-Item -ItemType Directory -Path $stage|Out-Null
function Save-New([string]$Name,$Value){
    $f=[IO.File]::Open((Join-Path $stage $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 10));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}
}
$task='N2R-StreamingV2Size-'+$d.run_id;$guestStage=Join-Path $d.guest_stage 'journal-sizing'
Save-New 'intent.json' @{run_id=$d.run_id;vm_id=$d.vm_id;task_name=$task;binary_sha256=$pin;request_sha256=$requestPin;
    source_commit=(& git -C $workspace rev-parse HEAD).Trim();source_payload_writes=0;journal_created=$false;utc=[DateTime]::UtcNow.ToString('o')}
$s=New-PSSession -VMId $d.vm_id -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml'))
try{
    Invoke-Command -Session $s -ArgumentList $guestStage -ScriptBlock {
        param($Stage);$ErrorActionPreference='Stop'
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'-or$_.Name-in@('lab-convert-admitted-tree.exe','lab-measure-general-journal.exe')}).Count){throw 'Another worker is active.'}
        if(Test-Path -LiteralPath $Stage){throw 'Fresh guest sizing stage required.'}
        New-Item -ItemType Directory -Path $Stage|Out-Null
    }
    Copy-Item -LiteralPath $binary -ToSession $s -Destination (Join-Path $guestStage $item.Name)
    $record=Invoke-Command -Session $s -ArgumentList $guestStage,$d.guest_output,$pin,$requestPin,$task -ScriptBlock {
        param($Stage,$Output,$Pin,$RequestPin,$Task);$ErrorActionPreference='Stop'
        $binary=Join-Path $Stage 'lab-measure-general-journal.exe';$request=Join-Path $Output 'request.json'
        if((Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()-cne$Pin-or
            (Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()-cne$RequestPin){throw 'Sizing executable/request pin differs.'}
        $args='--request "'+$request+'" --request-sha256 '+$RequestPin+' --output "'+(Join-Path $Stage 'result.json')+'" --progress "'+(Join-Path $Stage 'progress.json')+'"'
        $action=New-ScheduledTaskAction -Execute $binary -Argument $args
        $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $Task -Action $action -Principal $principal -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
        [pscustomobject]@{task_name=$Task;binary=$binary;arguments=$args;guest_stage=$Stage;request_sha256=$RequestPin;binary_sha256=$Pin}
    }
    Save-New 'dispatch.json' $record
    Invoke-Command -Session $s -ArgumentList $task,$record.binary,$record.arguments,$pin -ScriptBlock {
        param($Task,$Binary,$Arguments,$Pin);$ErrorActionPreference='Stop'
        $t=Get-ScheduledTask -TaskName $Task;$info=Get-ScheduledTaskInfo -TaskName $Task
        if($t.State.ToString()-cne'Ready'-or$info.LastRunTime.Year-ge2000-or@($t.Actions).Count-ne1-or
            $t.Actions[0].Execute-cne$Binary-or$t.Actions[0].Arguments-cne$Arguments-or
            (Get-FileHash -LiteralPath $Binary).Hash.ToLowerInvariant()-cne$Pin){throw 'Fresh unchanged sizing task required.'}
        Start-ScheduledTask -TaskName $Task
    }
    Save-New 'start-observed.json' @{start_issued_once=$true;utc=[DateTime]::UtcNow.ToString('o')}
    $record|ConvertTo-Json -Compress
}finally{Remove-PSSession $s}
