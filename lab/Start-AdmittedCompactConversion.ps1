# Fresh owning-process construction/admission/conversion on the preserved
# disposable rollback branch. Never restores a checkpoint or reuses a journal.
[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$parent=[guid]'6348491e-473d-423f-9d27-e81d22c64504'
$root=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\compact-admitted-20261028'
if(Test-Path -LiteralPath $root){throw 'Run has state; inspect without redispatch.'}
$vm=Get-VM -Id $id;$old=@(Get-VMSnapshot -VM $vm|ForEach-Object {$_.Id.ToString()})
if($vm.State.ToString() -cne 'Off' -or $vm.ParentSnapshotId -ne $parent -or $old.Count -ne 41 -or $vm.MemoryStartup -ne 4GB -or $vm.DynamicMemoryEnabled -or @(Get-VMNetworkAdapter -VM $vm).Count){throw 'Exact isolated OFF rollback branch and all41 checkpoints required.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
Assert-LabCapacity -Capacity $capacity -AdditionalBytes ([long]1.5GB)
$run=[guid]::NewGuid().ToString('N')
$binary=Join-Path $workspace 'target\release\lab-convert-native-composite.exe'
$binder=Join-Path $workspace 'target\release\ntfs2refs-bind.exe'
$binaryPin=(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()
$binderPin=(Get-FileHash -LiteralPath $binder).Hash.ToLowerInvariant()
New-Item -ItemType Directory -Path $root|Out-Null
function Save-New([string]$Name,$Value){$file=[IO.File]::Open((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 24));$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
Save-New 'intent.json' @{run_id=$run;vm_id=$id.ToString();parent_id=$parent.ToString();old_checkpoint_ids=$old;source_commit=(& git -C $workspace rev-parse HEAD).Trim();binary_sha256=$binaryPin;binder_sha256=$binderPin;capacity=$capacity;additional_bytes=[long]1.5GB;source_fixture_append_bytes=4194341;source_extent_moves_authorized=$false;shadow_reformat_authorized=$true;source_conversion_requires_live_admission=$true;utc=[DateTime]::UtcNow.ToString('o')}
Copy-Item -LiteralPath $binary -Destination (Join-Path $root 'producer.exe')
Copy-Item -LiteralPath $binder -Destination (Join-Path $root 'binder.exe')
Start-VM -VM $vm|Out-Null
$credential=Import-Clixml -LiteralPath (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$s=$null;$deadline=[DateTime]::UtcNow.AddMinutes(5)
while($null -eq $s){try{$s=New-PSSession -VMId $id -Credential $credential -ErrorAction Stop}catch{if([DateTime]::UtcNow -ge $deadline){throw 'Single boot not ready; never repeat on timeout.'};Start-Sleep -Seconds 3}}
try{
    $stage='C:\ntfs2refs\compact-admitted-'+$run
    $prepared=Invoke-Command -Session $s -ArgumentList $stage -ScriptBlock {
        param($Stage);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        if(Test-Path -LiteralPath $Stage){throw 'Fresh guest stage required.'}
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name -in @('lab-apply-compact-fixture.exe','lab-convert-native-composite.exe','lab-prepare-compact-journal.exe','ntfs2refs.exe')}).Count){throw 'Conversion worker exists.'}
        $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3;$journal=Get-Disk -Number 2
        if([guid]$source.Guid -ne [guid]'1b191872-c372-41ee-a416-e18863996f54' -or $source.IsOffline -or $source.IsReadOnly -or [guid]$shadow.Guid -ne [guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f' -or -not $shadow.IsOffline -or -not $shadow.IsReadOnly -or [guid]$journal.Guid -ne [guid]'09fcc613-b8c2-4a1a-8833-226f9399be7f' -or $journal.IsOffline -or $journal.IsReadOnly){throw 'Exact restored source/frozen scratch/journal state required.'}
        if(@($source,$shadow,$journal|Where-Object {$_.IsBoot -or $_.IsSystem}).Count){throw 'Windows boot/system disks excluded.'}
        if((Get-FileHash -LiteralPath 'C:\Windows\System32\drivers\refs.sys').Hash.ToLowerInvariant() -cne '3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4'){throw 'Oracle driver changed.'}
        $p=Get-Partition -DiskNumber 1|Where-Object Offset -eq 16MB;$v=$p|Get-Volume
        if([guid]$p.Guid -ne [guid]'f06075a8-67a2-46b9-8fac-4af4da809617' -or $p.Size -ne 52GB -or $v.FileSystem -cne 'NTFS' -or $v.AllocationUnitSize -ne 65536 -or $v.FileSystemLabel -cne 'n2r-stream-source' -or $v.DriveLetter -cne 'F'){throw 'Restored source volume differs.'}
        $path='F:\notes\compact-nonzero.bin'
        if(Test-Path -LiteralPath $path){throw 'New independent source file already exists.'}
        New-Item -ItemType Directory -Path $Stage|Out-Null
        $buffer=New-Object byte[] 65536
        for($i=0;$i -lt $buffer.Length;$i++){$buffer[$i]=[byte](1+(($i*73+19)%255))}
        $file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$remaining=4194341;while($remaining -gt 0){$count=[Math]::Min($remaining,$buffer.Length);$file.Write($buffer,0,$count);$remaining-=$count};$file.Flush($true)}finally{$file.Dispose()}
        $sourceHash=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
        $extents=@(& fsutil.exe file queryextents $path 2>&1);if($LASTEXITCODE -ne 0){throw 'New source extent observation failed.'}
        # Source allocation is deliberately left where ordinary NTFS put it.
        Set-Disk -Number 3 -IsReadOnly $false
        Set-Disk -Number 3 -IsOffline $false
        $sp=@(Get-Partition -DiskNumber 3|Where-Object Offset -eq 16MB)
        if($sp.Count -ne 1 -or [guid]$sp[0].Guid -ne [guid]'cbfd3e55-e35c-4f6e-aaac-dca706c3ec17' -or $sp[0].Size -ne 52GB){throw 'Only the exact enrolled scratch partition may be reformatted.'}
        Format-Volume -Partition $sp[0] -DevDrive -FileSystem ReFS -AllocationUnitSize 4096 -NewFileSystemLabel 'n2r-retained-shadow' -Confirm:$false -Force|Out-Null
        $rv=Get-Partition -DiskNumber 3|Where-Object Offset -eq 16MB|Get-Volume
        if($rv.FileSystem -cne 'ReFS' -or $rv.AllocationUnitSize -ne 4096 -or $rv.FileSystemLabel -cne 'n2r-retained-shadow'){throw 'Fresh scratch format differs.'}
        @{new_source_path=$path;new_source_bytes=4194341;new_source_sha256=$sourceHash;native_source_extents=$extents;source_extents_rearranged=$false;source_volume=$v.Path;shadow_volume=$rv.Path;journal_volume=(Get-Partition -DiskNumber 2|Where-Object Offset -eq 16MB|Get-Volume).Path;oracle_refs_sha256='3aa5d90958fc582c5f6567d2b970a3a37b3d4d80a4b58b5a8676943b7860d3c4';utc=[DateTime]::UtcNow.ToString('o')}
    }
    Save-New 'prepared.json' $prepared
    Copy-Item -LiteralPath $binary -ToSession $s -Destination ([IO.Path]::Combine($stage,'lab-convert-native-composite.exe'))
    Copy-Item -LiteralPath $binder -ToSession $s -Destination ([IO.Path]::Combine($stage,'ntfs2refs-bind.exe'))
    $dispatch=Invoke-Command -Session $s -ArgumentList $stage,$run,$binaryPin,$binderPin,$prepared.source_volume,$prepared.shadow_volume,$prepared.journal_volume -ScriptBlock {
        param($Stage,$Run,$BinaryPin,$BinderPin,$Source,$Shadow,$Journal);$ErrorActionPreference='Stop'
        $binary=Join-Path $Stage 'lab-convert-native-composite.exe';$binder=Join-Path $Stage 'ntfs2refs-bind.exe';$request=Join-Path $Stage 'conversion.json';$task='N2R-AdmittedCompact-'+$Run
        if((Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant() -cne $BinaryPin -or (Get-FileHash -LiteralPath $binder).Hash.ToLowerInvariant() -cne $BinderPin -or (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)){throw 'Fresh pinned task/tools required.'}
        $ErrorActionPreference='Continue'
        $log=@(& $binder --source $Source --shadow $Shadow --journal $Journal --experiment-id $Run --experimental-large-journal --experimental-large-tree --experimental-streaming-payload --max-journal-bytes 268435456 --output $request --evidence (Join-Path $Stage 'binding.json') 2>&1)
        $exit=$LASTEXITCODE;$ErrorActionPreference='Stop';$log|Out-String|Set-Content -LiteralPath (Join-Path $Stage 'binding.log') -Encoding UTF8
        if($exit -ne 0){throw 'Read-only actual binding refused; preserve log.'}
        $pin=(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant();$out=Join-Path $Stage 'result'
        $cli=@('--request',$request,'--request-sha256',$pin,'--output',$out,'--acknowledge-enrolled-disposable-devices','--maximum-placement-bytes','12884901888','--maximum-placement-submissions','4096','--maximum-exception-bytes','16777216')
        $argumentText=($cli|ForEach-Object {'"'+$_.Replace('"','\"')+'"'}) -join ' '
        Register-ScheduledTask -TaskName $task -Action (New-ScheduledTaskAction -Execute $binary -Argument $argumentText) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
        @{task_name=$task;guest_stage=$Stage;run_id=$Run;output_dir=$out;binary=$binary;binary_sha256=$BinaryPin;arguments=$cli;request=$request;request_sha256=$pin;max_journal_bytes=268435456;source_writes_require_live_certificate=$true}
    }
    Save-New 'dispatch.json' $dispatch
    foreach($name in @('conversion.json','binding.json','binding.log')){Copy-Item -FromSession $s -LiteralPath ([IO.Path]::Combine($stage,$name)) -Destination (Join-Path $root $name)}
    Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 768MB
    Invoke-Command -Session $s -ArgumentList $dispatch.task_name -ScriptBlock {param($Task);if((Get-ScheduledTaskInfo -TaskName $Task).LastRunTime.Year -ge 2000){throw 'Task already ran.'};Start-ScheduledTask -TaskName $Task}
    Save-New 'start.json' @{start_issued_once=$true;utc=[DateTime]::UtcNow.ToString('o')}
    $dispatch|ConvertTo-Json -Compress
}finally{Remove-PSSession $s}
