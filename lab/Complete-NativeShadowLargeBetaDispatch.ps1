# Finish only the observed pre-registration dispatch. Never rerun discovery,
# checkpoint, boot or an already registered task.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace '.lab\hyperv\shadow-large-beta-20261027'
$id=[guid]'6c4793d2-cdee-468b-bf3b-1c11cae0b501'
$intent=Get-Content -LiteralPath (Join-Path $root 'dispatch-intent.json') -Raw|ConvertFrom-Json
$baseline=Get-Content -LiteralPath (Join-Path $root 'baseline.json') -Raw|ConvertFrom-Json
$vm=Get-VM -Id $id -ErrorAction Stop
if($intent.vm_id-cne$id.ToString('D')-or$intent.run_id-cne'592d72139d3443dead6f7f947209c494'-or
    $vm.Name-cne'ntfs2refs-shadow-large-beta-20261027'-or$vm.State.ToString()-cne'Running'-or
    [string]$vm.ParentSnapshotId-cne$baseline.checkpoint_id-or-not$vm.Path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){
    throw 'Observed beta pre-registration state differs.'
}
if(Test-Path -LiteralPath (Join-Path $root 'dispatch.json')){throw 'Dispatch already recorded; collect its actual task.'}
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$session=New-PSSession -VMId $id -Credential $credential
try{
    $dispatch=Invoke-Command -Session $session -ArgumentList $intent.run_id,$intent.task_name -ScriptBlock {
        param($Run,$Task);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        if(Get-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue){throw 'Task already exists; inspect, never redispatch.'}
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'}).Count-or
            @(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count){throw 'Another worker is active.'}
        $stage='C:\ntfs2refs\beta\large-20261027';$output='C:\ntfs2refs\beta\runs\'+$Run
        if(Test-Path -LiteralPath $output){throw 'Conversion output already exists; inspect its state.'}
        $input=Join-Path $stage ('request-'+$Run+'.json');$evidence=Join-Path $stage ('discovery-'+$Run+'.json')
        if(-not(Test-Path -LiteralPath $evidence)){throw 'Completed discovery evidence required.'}
        $request=Get-Content -LiteralPath $input -Raw|ConvertFrom-Json
        if($request.schema_version-ne2-or$request.source_resource_profile-cne'experimental_large_tree_v1'-or
            $request.experiment_id-cne$Run-or$request.pair.source.disk_number-ne1-or$request.pair.shadow.disk_number-ne3-or
            $request.journal.disk.disk_number-ne2-or$request.pair.source.identity.partition_bytes-ne240GB-or
            $request.pair.shadow.identity.partition_bytes-ne240GB-or$request.max_journal_bytes-ne1073741824){throw 'Existing beta request differs.'}
        $binary=Join-Path $stage 'ntfs2refs.exe';$binaryHash=(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
        if($binaryHash-cne'f90974bf65abef903ec3be76b4462120b5d144f5b061ce3efc498bec733640eb'){throw 'Staged beta executable differs.'}
        $pin=(Get-FileHash -LiteralPath $input -Algorithm SHA256).Hash.ToLowerInvariant()
        $action=New-ScheduledTaskAction -Execute $binary -Argument ('convert --request "'+$input+'" --request-sha256 '+$pin+' --output "'+$output+'"')
        $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
        $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
        Register-ScheduledTask -TaskName $Task -Action $action -Principal $principal -Settings $settings|Out-Null
        Start-ScheduledTask -TaskName $Task
        [pscustomobject]@{run_id=$Run;task_name=$Task;guest_output=$output;guest_input=$input;guest_discovery=$evidence;
            request_sha256=$pin;binary_sha256=$binaryHash;source_partition_bytes=240GB;source_cluster_bytes=65536;target_cluster_bytes=4096;
            entrypoint='public-convert';discovery_reused=$true;prior_controller_exit=1;dispatched_utc=[DateTime]::UtcNow.ToString('o')}
    }
    $dispatch|Add-Member vm_id $id.ToString('D')
    $path=Join-Path $root 'dispatch.json';$stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($dispatch|ConvertTo-Json -Depth 10));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    foreach($name in @('guest_input','guest_discovery')){Copy-Item -LiteralPath $dispatch.$name -Destination (Join-Path $root ([IO.Path]::GetFileName($dispatch.$name))) -FromSession $session}
    $dispatch|ConvertTo-Json -Depth 8 -Compress
}finally{Remove-PSSession $session -ErrorAction SilentlyContinue}
