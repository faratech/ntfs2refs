# Retry only the preserved preactivation refusal, using the unchanged existing
# source fixture. Original abort, fresh binding and conversion run once in SYSTEM.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$parent=[guid]'cfe0b326-7308-4a58-810d-9730ff8152b4'
$root=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\compact-admitted-retry-20261028'
if(Test-Path -LiteralPath $root){throw 'Retry has state; inspect without redispatch.'}
$vm=Get-VM -Id $id;$old=@(Get-VMSnapshot -VM $vm|ForEach-Object {$_.Id.ToString()})
if($vm.State.ToString() -ne 'Off' -or $vm.ParentSnapshotId -ne $parent -or $old.Count -ne 42 -or $vm.MemoryStartup -ne 4GB -or $vm.DynamicMemoryEnabled -or @(Get-VMNetworkAdapter -VM $vm).Count){throw 'Exact preserved refusal branch/all42 required.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'CompactCapacity.psm1') -Force
$capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
$forecast=Get-CompactExperimentForecast -ObservedOsChildBytes 4139778048 -MaximumJournalBytes 268435456 -ObservationReference 'preserved refusal2ba889b7/OS child4,139,778,048B'
Assert-LabCapacity -Capacity $capacity -AdditionalBytes $forecast.additionalBytes
$run=[guid]::NewGuid().ToString('N')
$tools=@('lab-convert-native-composite.exe','lab-abort-general-source.exe','ntfs2refs-bind.exe')
$pins=@{};foreach($name in $tools){$pins[$name]=(Get-FileHash -LiteralPath (Join-Path $workspace ('target\release\'+$name))).Hash.ToLowerInvariant()}
New-Item -ItemType Directory -Path $root|Out-Null
function Save-New([string]$Name,$Value){$f=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 20));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
Save-New 'intent.json' @{run_id=$run;vm_id=$id.ToString();parent_id=$parent.ToString();old_checkpoint_ids=$old;source_commit=(& git -C $workspace rev-parse HEAD).Trim();pins=$pins;capacity=$capacity;forecast=$forecast;fixture_reused_without_source_moves=$true;source_append_bytes=0;shadow_format_authorized=$true;utc=[DateTime]::UtcNow.ToString('o')}
foreach($name in $tools){Copy-Item -LiteralPath (Join-Path $workspace ('target\release\'+$name)) -Destination (Join-Path $root $name)}
Start-VM -VM $vm|Out-Null
$cred=Import-Clixml -LiteralPath (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$session=$null;$deadline=[DateTime]::UtcNow.AddMinutes(5)
while($null -eq $session){try{$session=New-PSSession -VMId $id -Credential $cred -ErrorAction Stop}catch{if([DateTime]::UtcNow -ge $deadline){throw 'Single boot unavailable; do not restart.'};Start-Sleep -Seconds 3}}
try{
    $stage='C:\ntfs2refs\compact-admitted-retry-'+$run
    $prepared=Invoke-Command -Session $session -ArgumentList $stage -ScriptBlock {
        param($Stage);$ErrorActionPreference='Stop'
        if(Test-Path -LiteralPath $Stage){throw 'Fresh stage required.'}
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name -in @('lab-convert-native-composite.exe','lab-abort-general-source.exe','ntfs2refs-bind.exe','lab-apply-compact-fixture.exe')}).Count){throw 'Worker active.'}
        $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3;$journal=Get-Disk -Number 2
        if([guid]$source.Guid -ne [guid]'1b191872-c372-41ee-a416-e18863996f54' -or -not $source.IsOffline -or -not $source.IsReadOnly -or [guid]$shadow.Guid -ne [guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f' -or $shadow.IsOffline -or $shadow.IsReadOnly -or [guid]$journal.Guid -ne [guid]'09fcc613-b8c2-4a1a-8833-226f9399be7f' -or $journal.IsOffline -or $journal.IsReadOnly -or $shadow.IsBoot -or $shadow.IsSystem){throw 'Preserved source3/shadow0/journal0 identities required.'}
        $old='C:\ntfs2refs\compact-admitted-2ba889b74885441195fd5d075b4ab1d5\result'
        $failure=Get-Content -LiteralPath ([IO.Path]::Combine($old,'failed.json')) -Raw -Encoding UTF8|ConvertFrom-Json
        $frozen=[IO.Path]::Combine($old,'qualification\source-frozen.json')
        if($failure.error -cne 'explicit placement limits differ' -or (Test-Path -LiteralPath ([IO.Path]::Combine($old,'apply.json'))) -or (Get-FileHash -LiteralPath $frozen).Hash.ToLowerInvariant() -cne '5d2ac9fd2f13de25f10f4b81a9f345719543f8e623f689d3a3ae59fd9c520006'){throw 'Exact unmodified preactivation refusal required.'}
        if((Get-FileHash -LiteralPath 'C:\Windows\System32\drivers\refs.sys').Hash.ToLowerInvariant() -cne '3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4'){throw 'Pinned native driver changed.'}
        New-Item -ItemType Directory -Path $Stage|Out-Null
        $oldRequest=Get-Content -LiteralPath 'C:\ntfs2refs\compact-admitted-2ba889b74885441195fd5d075b4ab1d5\conversion.json' -Raw -Encoding UTF8|ConvertFrom-Json
        $binding=Join-Path $Stage 'source-binding.json';[IO.File]::WriteAllText($binding,($oldRequest.pair.source|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
        $p=@(Get-Partition -DiskNumber 3|Where-Object Offset -eq 16MB)
        if($p.Count -ne 1 -or [guid]$p[0].Guid -ne [guid]'cbfd3e55-e35c-4f6e-aaac-dca706c3ec17' -or $p[0].Size -ne 52GB){throw 'Exact independent scratch partition required.'}
        Format-Volume -Partition $p[0] -DevDrive -FileSystem ReFS -AllocationUnitSize 4096 -NewFileSystemLabel 'n2r-retained-shadow' -Confirm:$false -Force|Out-Null
        $shadowVolume=Get-Partition -DiskNumber 3|Where-Object Offset -eq 16MB|Get-Volume
        if($shadowVolume.FileSystem -ne 'ReFS' -or $shadowVolume.AllocationUnitSize -ne 4096){throw 'Scratch format differs.'}
        @{frozen=$frozen;frozen_pin='5d2ac9fd2f13de25f10f4b81a9f345719543f8e623f689d3a3ae59fd9c520006';binding=$binding;binding_pin=(Get-FileHash -LiteralPath $binding).Hash.ToLowerInvariant();source_volume='\\?\Volume{f06075a8-67a2-46b9-8fac-4af4da809617}\';shadow_volume=$shadowVolume.Path;journal_volume=(Get-Partition -DiskNumber 2|Where-Object Offset -eq 16MB|Get-Volume).Path}
    }
    Save-New 'prepared.json' $prepared
    foreach($name in $tools){Copy-Item -LiteralPath (Join-Path $root $name) -ToSession $session -Destination ([IO.Path]::Combine($stage,$name))}
    $configuration=@{stage=$stage;run=$run;pins=$pins;prepared=$prepared}
    $encodedConfig=[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes(($configuration|ConvertTo-Json -Depth 14)))
    $body=@'
$ErrorActionPreference='Stop'
$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CONFIG__'))|ConvertFrom-Json
$phase='tools';$exit=0
function Save-New([string]$Name,$Value){$f=[IO.File]::Open((Join-Path $c.stage $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Run-Native([string]$Binary,[string[]]$Cli,[string]$Log){$ErrorActionPreference='Continue';$lines=@(& $Binary @Cli 2>&1);$script:exit=$LASTEXITCODE;$ErrorActionPreference='Stop';$lines|Out-String|Set-Content -LiteralPath (Join-Path $c.stage $Log) -Encoding UTF8;if($script:exit -ne 0){throw ('Native phase '+$script:phase+' exit '+$script:exit)}}
try {
    foreach($name in @('lab-convert-native-composite.exe','lab-abort-general-source.exe','ntfs2refs-bind.exe')){if((Get-FileHash -LiteralPath (Join-Path $c.stage $name)).Hash.ToLowerInvariant() -cne $c.pins.$name){throw 'Pinned tool changed.'}}
    $phase='abort-original-source'
    Run-Native (Join-Path $c.stage 'lab-abort-general-source.exe') @('--binding',$c.prepared.binding,'--binding-sha256',$c.prepared.binding_pin,'--frozen-report',$c.prepared.frozen,'--frozen-report-sha256',$c.prepared.frozen_pin,'--output',(Join-Path $c.stage 'source-aborted.json')) 'source-abort.log'
    if((Get-FileHash -LiteralPath 'F:\notes\compact-nonzero.bin').Hash.ToLowerInvariant() -cne 'cbad760982dc9f68b3e65e77dc6cab7d77db005bbe561af55a1be76f498b37db'){throw 'Unchanged existing source fixture differs.'}
    $phase='fresh-binding';$request=Join-Path $c.stage 'conversion.json'
    Run-Native (Join-Path $c.stage 'ntfs2refs-bind.exe') @('--source',$c.prepared.source_volume,'--shadow',$c.prepared.shadow_volume,'--journal',$c.prepared.journal_volume,'--experiment-id',$c.run,'--experimental-large-journal','--experimental-large-tree','--experimental-streaming-payload','--max-journal-bytes','268435456','--output',$request,'--evidence',(Join-Path $c.stage 'binding.json')) 'binding.log'
    $phase='fresh-admitted-conversion';$pin=(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()
    Save-New 'conversion-start.json' @{request_sha256=$pin;maximum_placement_submissions=1024;utc=[DateTime]::UtcNow.ToString('o')}
    Run-Native (Join-Path $c.stage 'lab-convert-native-composite.exe') @('--request',$request,'--request-sha256',$pin,'--output',(Join-Path $c.stage 'result'),'--acknowledge-enrolled-disposable-devices','--maximum-placement-bytes','12884901888','--maximum-placement-submissions','1024','--maximum-exception-bytes','16777216') 'conversion.log'
    Save-New 'wrapper-result.json' @{success=$true;phase=$phase;exit=0;utc=[DateTime]::UtcNow.ToString('o')}
}catch{Save-New 'wrapper-failed.json' @{phase=$phase;native_exit=$exit;error=$_.Exception.Message;automatic_retry=$false;utc=[DateTime]::UtcNow.ToString('o')};exit 1}
'@
    $body=$body.Replace('__CONFIG__',$encodedConfig)
    [IO.File]::WriteAllText((Join-Path $root 'guest-wrapper.ps1'),$body,[Text.UTF8Encoding]::new($false))
    $bodyPin=(Get-FileHash -LiteralPath (Join-Path $root 'guest-wrapper.ps1')).Hash.ToLowerInvariant()
    $encodedBody=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
    $dispatch=Invoke-Command -Session $session -ArgumentList $stage,$run,$encodedBody,$bodyPin -ScriptBlock {
        param($Stage,$Run,$Body,$BodyPin);$ErrorActionPreference='Stop';$task='N2R-AdmittedCompact-Retry-'+$Run
        if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){throw 'Fresh wrapper task required.'}
        Register-ScheduledTask -TaskName $task -Action (New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$Body)) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
        @{task_name=$task;run_id=$Run;guest_stage=$Stage;output_dir=([IO.Path]::Combine($Stage,'result'));wrapper_sha256=$BodyPin;maximum_placement_submissions=1024}
    }
    Save-New 'dispatch.json' $dispatch
    $current=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
    $remaining=[Math]::Max([long]1GB,[long]$forecast.additionalBytes-[Math]::Max([long]0,[long]$current.ActualBytes-[long]$capacity.ActualBytes))
    Assert-LabCapacity -Capacity $current -AdditionalBytes $remaining
    Invoke-Command -Session $session -ArgumentList $dispatch.task_name -ScriptBlock {param($Task);if((Get-ScheduledTaskInfo -TaskName $Task).LastRunTime.Year -ge 2000){throw 'Wrapper already ran.'};Start-ScheduledTask -TaskName $Task}
    Save-New 'start.json' @{start_issued_once=$true;utc=[DateTime]::UtcNow.ToString('o')}
    $dispatch|ConvertTo-Json -Compress
}finally{Remove-PSSession $session}
