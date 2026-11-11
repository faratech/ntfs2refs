# One clean boot of the saved partial branch, verifying exclusion without
# mounting the source, changing flags, replaying a journal or retrying a start.
[CmdletBinding()]param([Parameter(Mandatory)][ValidatePattern('^candidate(?:[2-9]|[1-9][0-9]+)$')][string]$Candidate,
    [ValidateSet('Resume','Rollback')][string]$Branch='Resume')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace ('.lab\hyperv\streaming-v2-20261027\'+$Candidate)
$d=Get-Content -LiteralPath (Join-Path $root 'dispatch.json') -Raw|ConvertFrom-Json
$saved=Get-Content -LiteralPath (Join-Path $root 'interrupted-checkpoint.json') -Raw|ConvertFrom-Json
$prior=Get-Content -LiteralPath (Join-Path $root 'preserve-interruption-intent.json') -Raw|ConvertFrom-Json
$vm=Get-VM -Id $d.vm_id
if([guid]$d.vm_id-ne[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'-or$vm.State.ToString()-cne'Off'-or
    $vm.ParentSnapshotId-ne[guid]$saved.checkpoint_id-or$saved.run_id-cne$d.run_id){throw 'Exact saved OFF interrupted branch required.'}
$suffix=if($Branch-ceq'Rollback'){'-rollback'}else{''}
$path=Join-Path $root ('interrupted-reboot-intent'+$suffix+'.json')
if(Test-Path -LiteralPath $path){throw 'Boot already recorded; inspect that VM without issuing another start.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
# This phase creates no shadow or new payload. The same VM's two postconversion
# boots/mutation child grew about 1 GiB. Keep a 2 GiB forecast plus the unchanged
# global cap and 64 GiB host reserve; observe actual backing growth afterward.
Assert-LabCapacity -Capacity $capacity -AdditionalBytes 2GB
$old=$prior.state.boot_utc
if($old-is[DateTime]){
    if($old.Kind-eq[DateTimeKind]::Unspecified){throw 'Prior boot timezone missing.'}
    $oldBoot=$old.ToUniversalTime().ToString('o')
}else{$oldBoot=[DateTimeOffset]::Parse([string]$old).UtcDateTime.ToString('o')}
function Save-New([string]$Name,$Value){
    $f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 8));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}
}
Save-New ('interrupted-reboot-intent'+$suffix+'.json') @{vm_id=$d.vm_id;run_id=$d.run_id;branch=$Branch;checkpoint=$saved.checkpoint_id;prior_boot_utc=$oldBoot;
    capacity=$capacity;forecast_bytes=2GB;no_source_mount=$true;utc=[DateTime]::UtcNow.ToString('o')}
Start-VM -VM $vm -ErrorAction Stop|Out-Null
$cred=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$session=$null;$deadline=[DateTime]::UtcNow.AddMinutes(8)
while($null-eq$session){
    try{$session=New-PSSession -VMId $d.vm_id -Credential $cred -ErrorAction Stop}catch{
        if([DateTime]::UtcNow-ge$deadline){throw 'Login unavailable after single boot; do not restart.'}
        Start-Sleep -Seconds 3
    }
}
try{
    $result=Invoke-Command -Session $session -ArgumentList $d.task_name,$oldBoot -ScriptBlock {
        param($Task,$OldBoot);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
        if([DateTimeOffset]::Parse($boot)-le[DateTimeOffset]::Parse($OldBoot)){throw 'New guest boot not established.'}
        $t=Get-ScheduledTask -TaskName $Task;$info=Get-ScheduledTaskInfo -TaskName $Task
        if($t.State.ToString()-in@('Running','Queued')-or$info.LastTaskResult-ne86-or
            @(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'-or$_.Name-ceq'lab-convert-admitted-tree.exe'}).Count){throw 'Producer restarted or another worker is active.'}
        $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
        if(-not$source.IsOffline-or$source.IsReadOnly-or-not$shadow.IsOffline-or-not$shadow.IsReadOnly-or
            [guid]$source.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or
            [guid]$shadow.Guid-ne[guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f'){throw 'Persistent disk exclusion did not survive reboot.'}
        [pscustomobject]@{success=$true;boot_utc=$boot;source_offline=$source.IsOffline;source_readonly=$source.IsReadOnly;
            shadow_offline=$shadow.IsOffline;shadow_readonly=$shadow.IsReadOnly;producer_result=$info.LastTaskResult;controller_source_mount_attempts=0;utc=[DateTime]::UtcNow.ToString('o')}
    }
    $result|Add-Member run_id $d.run_id
    $result|Add-Member vm_id $d.vm_id
    Save-New ('exclusion-after-reboot'+$suffix+'.json') $result
    $result|ConvertTo-Json -Depth 6 -Compress
}finally{Remove-PSSession $session}
