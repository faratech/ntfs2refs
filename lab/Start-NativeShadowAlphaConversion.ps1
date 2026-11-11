# First public conversion on the independent alpha. No old-lane dispatchers.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace '.lab\hyperv\shadow-alpha-20261026'
$id=[guid]'0d9bfa66-c66c-4ead-86b7-e72cb5f7e040'
$vm=Get-VM -Id $id
if($vm.Name-cne'ntfs2refs-shadow-alpha-20261026'-or$vm.State.ToString()-cne'Running'-or
    [string]$vm.ParentSnapshotId-cne'946f9082-7ace-4114-ba80-e3a4cd162ef6'){throw 'Alpha baseline preparation branch differs.'}
if(Test-Path -LiteralPath (Join-Path $root 'baseline-intent.json')){throw 'Baseline operation was dispatched; inspect state before continuing.'}
$fixture=Get-Content -LiteralPath (Join-Path $root 'guest-fixture.json') -Raw|ConvertFrom-Json
if($fixture.kind-cne'native-shadow-alpha-fixture'-or@($fixture.files).Count-ne7-or$fixture.source_extent_moves-ne0){throw 'Completed alpha fixture required.'}
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$session=New-PSSession -VMId $id -Credential $credential
try{
    $verified=Invoke-Command -Session $session -ArgumentList ($fixture.files|ConvertTo-Json -Compress) -ScriptBlock {
        param($Rows);$ErrorActionPreference='Stop'
        if(@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count){throw 'Guest worker is active.'}
        foreach($row in ($Rows|ConvertFrom-Json)){
            if((Get-FileHash -LiteralPath $row.path -Algorithm SHA256).Hash.ToLowerInvariant()-cne$row.sha256){throw 'Fixture content changed before baseline.'}
        }
        [pscustomobject]@{files_matched=$true;checked_utc=[DateTime]::UtcNow.ToString('o')}
    }
    $verified|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $root 'baseline-intent.json') -Encoding utf8
    try{Invoke-Command -Session $session -ScriptBlock {Stop-Computer -Force}}catch{
        # A shutdown can close the transport; actual VM state is checked below.
        $_.Exception.GetType().FullName|Set-Content -LiteralPath (Join-Path $root 'shutdown-transport-observation.txt')
    }
}finally{Remove-PSSession $session -ErrorAction SilentlyContinue}
$deadline=[DateTime]::UtcNow.AddMinutes(2)
do{$vm=Get-VM -Id $id;if($vm.State.ToString()-ceq'Off'){break};Start-Sleep -Seconds 2}while([DateTime]::UtcNow-lt$deadline)
if($vm.State.ToString()-cne'Off'){throw 'Clean alpha shutdown not confirmed; do not checkpoint or force a stop.'}
Checkpoint-VM -VM $vm -SnapshotName 'alpha-ntfs-baseline'
$vm=Get-VM -Id $id
$baseline=@(Get-VMSnapshot -VM $vm|Where-Object {$_.Name -ceq 'alpha-ntfs-baseline'})
if($baseline.Count-ne1){throw 'NTFS baseline checkpoint not established.'}
[pscustomobject]@{vm_id=$id.ToString('D');checkpoint_id=$baseline[0].Id.ToString('D');
    name='alpha-ntfs-baseline';state='Off';created_utc=[DateTime]::UtcNow.ToString('o')}|
    ConvertTo-Json|Set-Content -LiteralPath (Join-Path $root 'baseline.json') -Encoding utf8
Start-VM -VM $vm
$session=$null;$deadline=[DateTime]::UtcNow.AddMinutes(4)
try{
    while($null-eq$session-and[DateTime]::UtcNow-lt$deadline){
        try{$session=New-PSSession -VMId $id -Credential $credential -ErrorAction Stop}catch{Start-Sleep -Seconds 3}
    }
    if($null-eq$session){throw 'Baseline reboot connection unavailable; no redispatch.'}
    $run=[guid]::NewGuid().ToString('N');$task='N2R-AlphaConvert-'+$run
    $dispatch=Invoke-Command -Session $session -ArgumentList $run,$task -ScriptBlock {
        param($Run,$Task);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        $stage='C:\ntfs2refs\alpha\native-shadow-alpha-20261026'
        $output='C:\ntfs2refs\alpha\runs\'+$Run
        $input=Join-Path $stage ('request-'+$Run+'.json')
        $evidence=Join-Path $stage ('discovery-'+$Run+'.json')
        if((Test-Path -LiteralPath $output)-or(Test-Path -LiteralPath $input)){throw 'Fresh alpha input/output required.'}
        if(@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count){throw 'Another guest lab worker is active.'}
        foreach($pair in @(@('F','NTFS','n2r-alpha-source'),@('R','ReFS','n2r-retained-shadow'),@('J','NTFS','n2r-alpha-journal'))){
            $v=Get-Volume -DriveLetter $pair[0];if($v.FileSystem-cne$pair[1]-or$v.FileSystemLabel-cne$pair[2]){throw 'Alpha mounted volume profile differs.'}
        }
        $binary=Join-Path $stage 'ntfs2refs.exe'
        if((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()-cne'714ddd2bc78d1165061524a390e538c15d8022b2b56ca5170040edfe1286b841'){throw 'Frozen public executable changed.'}
        & (Join-Path $stage 'ntfs2refs-bind.exe') --source 'F:\' --shadow 'R:\' --journal 'J:\' --experiment-id $Run --output $input --evidence $evidence|Out-Null
        if($LASTEXITCODE-ne0){throw 'Read-only alpha device discovery failed.'}
        $pin=(Get-FileHash -LiteralPath $input -Algorithm SHA256).Hash.ToLowerInvariant()
        $action=New-ScheduledTaskAction -Execute $binary -Argument ('convert --request "'+$input+'" --request-sha256 '+$pin+' --output "'+$output+'"')
        $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
        $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
        Register-ScheduledTask -TaskName $Task -Action $action -Principal $principal -Settings $settings|Out-Null
        Start-ScheduledTask -TaskName $Task
        [pscustomobject]@{run_id=$Run;task_name=$Task;guest_output=$output;guest_input=$input;
            request_sha256=$pin;binary_sha256='714ddd2bc78d1165061524a390e538c15d8022b2b56ca5170040edfe1286b841';
            entrypoint='public-convert';dispatched_utc=[DateTime]::UtcNow.ToString('o')}
    }
    $dispatch|Add-Member vm_id $id.ToString('D')
    $dispatch|Add-Member checkpoint_id $baseline[0].Id.ToString('D')
    $dispatch|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $root 'normal-dispatch.json') -Encoding utf8
    $dispatch|ConvertTo-Json -Depth 6 -Compress
}finally{if($session){Remove-PSSession $session -ErrorAction SilentlyContinue}}
