# Public owning-machine conversion, only inside the fresh disposable beta.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace '.lab\hyperv\shadow-large-beta-20261027'
$id=[guid]'6c4793d2-cdee-468b-bf3b-1c11cae0b501'
$vm=Get-VM -Id $id -ErrorAction Stop
if($vm.Name-cne'ntfs2refs-shadow-large-beta-20261027'-or$vm.State.ToString()-cne'Running'-or
    [string]$vm.ParentSnapshotId-cne'971ecdc3-8eca-4abb-a77e-e028e7e54f7f'-or-not$vm.Path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Owned beta baseline branch differs.'}
if(-not(Test-Path -LiteralPath (Join-Path $root 'guest-fixture.json'))){throw 'Completed beta fixture required.'}
foreach($name in @('baseline-intent.json','dispatch-intent.json','dispatch.json')){if(Test-Path -LiteralPath (Join-Path $root $name)){throw 'Beta conversion already has state; inspect its actual operation.'}}
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 8GB
function Save([string]$Name,$Value){
    $stream=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 12));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
Save 'baseline-intent.json' ([pscustomobject]@{vm_id=$id.ToString('D');name='beta-ntfs-240g-64k';utc=[DateTime]::UtcNow.ToString('o')})
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$session=New-PSSession -VMId $id -Credential $credential
try{
    try{
        Invoke-Command -Session $session -ScriptBlock {
            $ErrorActionPreference='Stop'
            if(@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count){throw 'Another guest worker is active.'}
            Stop-Computer -Force
        }
    }catch{Save 'shutdown-transport-observation.json' ([pscustomobject]@{exception_type=$_.Exception.GetType().FullName;message=$_.Exception.Message;utc=[DateTime]::UtcNow.ToString('o')})}
}finally{Remove-PSSession $session -ErrorAction SilentlyContinue}
$deadline=[DateTime]::UtcNow.AddMinutes(2)
do{$vm=Get-VM -Id $id;if($vm.State.ToString()-ceq'Off'){break};Start-Sleep -Seconds 2}while([DateTime]::UtcNow-lt$deadline)
if($vm.State.ToString()-cne'Off'){throw 'Clean beta shutdown not confirmed; do not checkpoint or force stop.'}
Checkpoint-VM -VM $vm -SnapshotName 'beta-ntfs-240g-64k'
$checkpoint=Get-ExactLabCheckpoint -VM $vm -Name 'beta-ntfs-240g-64k'
Save 'baseline.json' ([pscustomobject]@{vm_id=$id.ToString('D');checkpoint_id=$checkpoint.Id.ToString('D');name=$checkpoint.Name;state='Off';utc=[DateTime]::UtcNow.ToString('o')})
Start-VM -VM $vm
$session=$null;$deadline=[DateTime]::UtcNow.AddMinutes(4)
try{
    while($null-eq$session-and[DateTime]::UtcNow-lt$deadline){
        try{$session=New-PSSession -VMId $id -Credential $credential -ErrorAction Stop}catch{Start-Sleep -Seconds 3}
    }
    if($null-eq$session){throw 'Beta baseline reboot unavailable; do not redispatch.'}
    $run=[guid]::NewGuid().ToString('N');$task='N2R-LargeBetaConvert-'+$run
    Save 'dispatch-intent.json' ([pscustomobject]@{vm_id=$id.ToString('D');run_id=$run;task_name=$task;entrypoint='public-convert';utc=[DateTime]::UtcNow.ToString('o')})
    $dispatch=Invoke-Command -Session $session -ArgumentList $run,$task -ScriptBlock {
        param($Run,$Task);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        $stage='C:\ntfs2refs\beta\large-20261027';$output='C:\ntfs2refs\beta\runs\'+$Run
        $input=Join-Path $stage ('request-'+$Run+'.json');$evidence=Join-Path $stage ('discovery-'+$Run+'.json')
        if((Test-Path -LiteralPath $output)-or(Test-Path -LiteralPath $input)){throw 'Fresh beta input/output required.'}
        if(@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count){throw 'Another guest worker is active.'}
        foreach($pair in @(@('F','NTFS','n2r-beta-source'),@('R','ReFS','n2r-retained-shadow'),@('J','NTFS','n2r-beta-journal'))){
            $volume=Get-Volume -DriveLetter $pair[0];if($volume.FileSystem-cne$pair[1]-or$volume.FileSystemLabel-cne$pair[2]){throw 'Mounted beta volume differs.'}
        }
        $binary=Join-Path $stage 'ntfs2refs.exe'
        if((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()-cne'f90974bf65abef903ec3be76b4462120b5d144f5b061ce3efc498bec733640eb'){throw 'Beta public executable changed.'}
        $previousPreference=$ErrorActionPreference;$ErrorActionPreference='Continue'
        try{
            $discoveryLog=@(& (Join-Path $stage 'ntfs2refs-bind.exe') --source 'F:\' --shadow 'R:\' --journal 'J:\' --experiment-id $Run `
                --experimental-large-tree --experimental-large-journal --max-journal-bytes 1073741824 --output $input --evidence $evidence 2>&1)
            $discoveryExit=$LASTEXITCODE
        }finally{$ErrorActionPreference=$previousPreference}
        $discoveryLog|ForEach-Object {$_|Out-String}|Set-Content -LiteralPath (Join-Path $stage ('discovery-'+$Run+'.log')) -Encoding utf8
        if($discoveryExit-ne0){throw 'Read-only beta discovery failed.'}
        $pin=(Get-FileHash -LiteralPath $input -Algorithm SHA256).Hash.ToLowerInvariant()
        $action=New-ScheduledTaskAction -Execute $binary -Argument ('convert --request "'+$input+'" --request-sha256 '+$pin+' --output "'+$output+'"')
        $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
        $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
        Register-ScheduledTask -TaskName $Task -Action $action -Principal $principal -Settings $settings|Out-Null
        Start-ScheduledTask -TaskName $Task
        [pscustomobject]@{run_id=$Run;task_name=$Task;guest_output=$output;guest_input=$input;guest_discovery=$evidence;
            request_sha256=$pin;binary_sha256='f90974bf65abef903ec3be76b4462120b5d144f5b061ce3efc498bec733640eb';
            source_partition_bytes=240GB;source_cluster_bytes=65536;target_cluster_bytes=4096;entrypoint='public-convert';dispatched_utc=[DateTime]::UtcNow.ToString('o')}
    }
    $dispatch|Add-Member vm_id $id.ToString('D')
    Save 'dispatch.json' $dispatch
    $dispatch|ConvertTo-Json -Depth 8 -Compress
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
