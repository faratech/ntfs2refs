# Observe only the recorded candidate13 task. Archive/preserve only its exact
# terminal exit86 boundary; an observation error never starts another worker.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\candidate13'
$d=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
if([guid]$d.vm_id-ne[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'-or
    -not$d.controlled_retained_recovery-or$d.interrupt_after_writes-ne1-or$d.expected_exit_code-ne86){throw 'Exact controlled retained run required.'}
$intent=Join-Path $root 'interruption-monitor-intent.json'
if(Test-Path -LiteralPath $intent){throw 'Monitor already has state; inspect it without duplication.'}
$stream=[IO.File]::Open($intent,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes((@{run_id=$d.run_id;task_name=$d.task_name;
    vm_id=$d.vm_id;expected_exit=86;utc=[DateTime]::UtcNow.ToString('o');never_redispatch=$true}|ConvertTo-Json));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
$deadline=[DateTime]::UtcNow.AddMinutes(90)
while($true){
    # A transient failure propagates and leaves this intent. It is not proof
    # of terminal state and never grants permission to restart conversion.
    $r=(& (Join-Path $PSScriptRoot 'Collect-StreamingV2Conversion.ps1') -Candidate candidate13)|ConvertFrom-Json
    if($r.run_id-cne$d.run_id){throw 'Observed run changed.'}
    if($r.terminal){
        if($r.last_task_result-ne86-or-not$r.controlled_interruption_observed-or$r.all_converter_count-ne0){
            throw 'Unexpected terminal outcome; preserve current disks and inspect the recorded result.'
        }
        if(Test-Path -LiteralPath (Join-Path $root 'terminal-evidence')){throw 'Existing archive requires inspection.'}
        & (Join-Path $PSScriptRoot 'Archive-StreamingV2Terminal.ps1') -Candidate candidate13 | Out-Null
        & (Join-Path $PSScriptRoot 'Preserve-StreamingV2Interruption.ps1') -Candidate candidate13
        return
    }
    if([DateTime]::UtcNow-ge$deadline){throw 'Observation deadline reached; worker state remains unresolved. Do not restart it.'}
    Start-Sleep -Seconds 30
}
