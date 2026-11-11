# Preserve only the terminal candidate-2 beta branch, then return this same
# disposable VM to its own recorded clean NTFS baseline. No checkpoint deletion.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace '.lab\hyperv\shadow-large-beta-20261027'
$candidate=Join-Path $root 'candidate2';$dispatch=Get-Content -LiteralPath (Join-Path $candidate 'dispatch.json') -Raw|ConvertFrom-Json
$id=[guid]'6c4793d2-cdee-468b-bf3b-1c11cae0b501';$baselineId=[guid]'506bf3fe-afac-40fb-bfe9-e357141506d2'
$vm=Get-VM -Id $id
if($vm.Name-cne'ntfs2refs-shadow-large-beta-20261027'-or$vm.State.ToString()-cne'Running'-or
    $vm.ParentSnapshotId-ne$baselineId-or-not$vm.Path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){
    throw 'Exact disposable beta refusal branch required.'
}
if(Test-Path -LiteralPath (Join-Path $candidate 'preserve-restore-intent.json')){throw 'Preservation already dispatched; inspect before any continuation.'}
function Save([string]$Name,$Value){
    $stream=[IO.File]::Open((Join-Path $candidate $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 12));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$session=New-PSSession -VMId $id -Credential $credential
try{
    $terminal=Invoke-Command -Session $session -ArgumentList $dispatch.task_name,$dispatch.guest_output -ScriptBlock {
        param($Task,$Output);$ErrorActionPreference='Stop'
        $taskObject=Get-ScheduledTask -TaskName $Task;$info=Get-ScheduledTaskInfo -TaskName $Task
        if($taskObject.State.ToString()-in@('Running','Queued')-or$info.LastTaskResult-ne1-or
            @(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'}).Count){throw 'Terminal refused beta run required.'}
        $failure=Get-Content -LiteralPath (Join-Path $Output 'failed.json') -Raw|ConvertFrom-Json
        if($failure.error-cne'primary and mirror MFT record 24 differ'){throw 'Refusal differs.'}
        $disk=Get-Disk -Number 1;if(-not$disk.IsOffline-or-not$disk.IsReadOnly){throw 'Frozen source exclusion differs.'}
        [pscustomobject]@{task=$Task;result=$info.LastTaskResult;failure=$failure;source_offline=$disk.IsOffline;source_read_only=$disk.IsReadOnly;utc=[DateTime]::UtcNow.ToString('o')}
    }
    $stageCopy=Join-Path $candidate 'terminal-evidence\candidate-stage'
    if(Test-Path -LiteralPath $stageCopy){throw 'Candidate stage already archived.'}
    Copy-Item -LiteralPath $dispatch.guest_stage -Destination $stageCopy -FromSession $session -Recurse
    Save 'preserve-restore-intent.json' ([pscustomobject]@{vm_id=$id.ToString('D');baseline_id=$baselineId.ToString('D');terminal=$terminal;
        action='Preserve failed disposable beta checkpoint, then restore its own baseline; no earlier VM is touched.';utc=[DateTime]::UtcNow.ToString('o')})
    try{Invoke-Command -Session $session -ScriptBlock {Stop-Computer -Force}}
    catch{Save 'refusal-shutdown-transport.json' ([pscustomobject]@{type=$_.Exception.GetType().FullName;message=$_.Exception.Message})}
}finally{Remove-PSSession $session -ErrorAction SilentlyContinue}
$deadline=[DateTime]::UtcNow.AddMinutes(2)
do{$vm=Get-VM -Id $id;if($vm.State.ToString()-ceq'Off'){break};Start-Sleep -Seconds 2}while([DateTime]::UtcNow-lt$deadline)
if($vm.State.ToString()-cne'Off'){throw 'Clean beta shutdown not established; no force stop or restore.'}
Checkpoint-VM -VM $vm -SnapshotName 'beta-candidate2-refused-mirror'
$failed=Get-ExactLabCheckpoint -VM $vm -Name 'beta-candidate2-refused-mirror'
Save 'preserved-checkpoint.json' ([pscustomobject]@{vm_id=$id.ToString('D');checkpoint_id=$failed.Id.ToString('D');name=$failed.Name;state='Off';utc=[DateTime]::UtcNow.ToString('o')})
$baseline=@(Get-VMSnapshot -VM $vm|Where-Object {$_.Id-eq$baselineId})
if($baseline.Count-ne1-or$baseline[0].Name-cne'beta-ntfs-240g-64k'){throw 'Exact beta baseline absent.'}
Restore-VMSnapshot -VMSnapshot $baseline[0] -Confirm:$false
$deadline=[DateTime]::UtcNow.AddSeconds(20)
do{$vm=Get-VM -Id $id;if($vm.State.ToString()-ceq'Off'-and$vm.ParentSnapshotId-eq$baselineId){break};Start-Sleep -Seconds 1}while([DateTime]::UtcNow-lt$deadline)
if($vm.State.ToString()-cne'Off'-or$vm.ParentSnapshotId-ne$baselineId){throw 'Beta baseline restore not confirmed; do not start.'}
Save 'baseline-restored.json' ([pscustomobject]@{vm_id=$id.ToString('D');baseline_id=$baselineId.ToString('D');preserved_refusal_id=$failed.Id.ToString('D');state='Off';utc=[DateTime]::UtcNow.ToString('o')})
Start-VM -VM $vm
Write-Output ('Preserved refused branch '+$failed.Id.ToString('D')+'; beta baseline boot dispatched.')
