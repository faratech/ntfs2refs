# One public conversion on the separately enrolled streaming fixture.
[CmdletBinding()]param([ValidatePattern('^candidate[1-9][0-9]*$')][string]$Candidate='candidate1',
    [ValidateRange(0,4096)][int]$InterruptAfterWrites=0,[switch]$Retention8G,
    [ValidateRange(32,7168)][int]$JournalBudgetMiB=1024,[switch]$FrozenShadowReuse)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$m=Get-Content -LiteralPath (Join-Path $root 'manifest.json') -Raw|ConvertFrom-Json
$fixtureRoot=if($Retention8G){Join-Path $root 'retention8g'}else{$root}
$baseline=Get-Content -LiteralPath (Join-Path $fixtureRoot 'baseline.json') -Raw|ConvertFrom-Json
if($FrozenShadowReuse){
    if(-not$Retention8G-or$InterruptAfterWrites-ne0-or$JournalBudgetMiB-ne1536){throw 'Frozen reuse is enrolled only for the corrected 1536-MiB retention case.'}
    $baseline=Get-Content -LiteralPath (Join-Path $root 'candidate5\valid-data-probe\failed-checkpoint.json') -Raw|ConvertFrom-Json
}
$vm=Get-VM -Id $m.vm_id
if($vm.Id-ne[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'-or$vm.Name-cne$m.name-or[guid]$vm.ParentSnapshotId-ne[guid]$baseline.checkpoint_id-or
    $vm.State.ToString()-notin@('Off','Running')-or-not$vm.Path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Owned NTFS baseline required.'}
$candidateRoot=Join-Path $root $Candidate
if(Test-Path -LiteralPath $candidateRoot){throw 'Candidate already has state; inspect without redispatch.'}
$capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
$journalBudgetBytes=[long]$JournalBudgetMiB*1MB
# Preserve the original allowance and account for the larger independent
# journal instead of silently treating every run as a one-GiB journal case.
$growthBudgetBytes=6GB+[Math]::Max([long]0,$journalBudgetBytes-1GB)
if($FrozenShadowReuse){
    # No shadow payload write: at most 1024 compared patch intervals and the
    # 796,917,760-byte change budget bound 2-MiB source COW allocation below
    # 5.1 GB. Reserve the full 8-GiB journal disk, 6 GiB OS and metadata margin.
    $growthBudgetBytes=20GB
    foreach($drive in Get-VMHardDiskDrive -VM $vm){if((Get-VHD -Path $drive.Path).BlockSize-ne2MB){throw 'Enrolled two-MiB COW block size required.'}}
}
Assert-LabCapacity -Capacity $capacity -AdditionalBytes $growthBudgetBytes
$binaryName=if($InterruptAfterWrites){'lab-convert-admitted-tree.exe'}else{'ntfs2refs.exe'}
$names=@('ntfs2refs.exe','ntfs2refs-bind.exe','ntfs2refs-recover.exe')
if($InterruptAfterWrites){$names+='lab-convert-admitted-tree.exe'}
$pins=@(foreach($name in $names){
    $path=Join-Path $workspace ('target\release\'+$name)
    [pscustomobject]@{name=$name;path=$path;bytes=(Get-Item -LiteralPath $path).Length;sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()}
})
$patch=(& git -C $workspace diff --binary -- src crates Cargo.toml Cargo.lock rust-toolchain.toml)-join"`n"
$patchPin=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($patch))).ToLowerInvariant()
New-Item -ItemType Directory -Path $candidateRoot|Out-Null
function Save-New([string]$Name,$Value){
    $f=[IO.File]::Open((Join-Path $candidateRoot $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}
}
$run=[guid]::NewGuid().ToString('N');$task='N2R-StreamingV2Convert-'+$run
Save-New 'intent.json' @{vm_id=$m.vm_id;run_id=$run;task_name=$task;source_commit=(& git -C $workspace rev-parse HEAD).Trim();working_tree_clean=($patch.Length-eq0);working_tree_patch_sha256=$patchPin;binaries=$pins;capacity=$capacity;growth_budget_bytes=$growthBudgetBytes;max_journal_bytes=$journalBudgetBytes;native_qualified=$false;binary_name=$binaryName;interrupt_after_writes=$InterruptAfterWrites;retention_8g=[bool]$Retention8G;frozen_shadow_reuse=[bool]$FrozenShadowReuse;fixture_root=$fixtureRoot;utc=[DateTime]::UtcNow.ToString('o')}
if($vm.State.ToString()-ceq'Off'){Start-VM -VM $vm -ErrorAction Stop|Out-Null}
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$s=$null;$deadline=[DateTime]::UtcNow.AddMinutes(4)
while($null-eq$s){
    try{$s=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop}catch{if([DateTime]::UtcNow-ge$deadline){throw 'Guest unavailable after single start; inspect without redispatch.'};Start-Sleep -Seconds 3}
}
try{
    $stage='C:\ntfs2refs\streaming-v2-20261027\'+$Candidate
    $fixture=Get-Content -LiteralPath (Join-Path $fixtureRoot 'fixture.json') -Raw
    $prior=Invoke-Command -Session $s -ArgumentList $stage,$fixture,[bool]$FrozenShadowReuse -ScriptBlock {
        param($Stage,$Fixture,$Reuse);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'}).Count-or@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count){throw 'Another guest worker is active.'}
        $expected=ConvertFrom-Json -InputObject $Fixture
        foreach($part in $expected.partitions){
            $actual=Get-Partition -DriveLetter $part.letter;$disk=Get-Disk -Number $actual.DiskNumber;$volume=Get-Volume -DriveLetter $part.letter
            $expectedReadOnly=$Reuse-and$part.disk-eq3
            if($disk.Number-ne$part.disk-or$disk.IsBoot-or$disk.IsSystem-or$disk.IsOffline-or$disk.IsReadOnly-ne$expectedReadOnly-or$actual.Offset-ne$part.offset-or$actual.Size-ne$part.bytes-or
                [guid]$actual.Guid-ne[guid]$part.partition_guid-or$volume.FileSystem-cne$part.filesystem-or$volume.AllocationUnitSize-ne$part.cluster_bytes){throw 'Current fixture partition differs.'}
        }
        if(Test-Path -LiteralPath $Stage){throw 'Fresh stage required.'}
        New-Item -ItemType Directory -Path $Stage|Out-Null
        [pscustomobject]@{worker_count=0;boot_utc=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');source_unchanged_by_controller=$true}
    }
    Save-New 'prior-state.json' $prior
    foreach($pin in $pins){Copy-Item -LiteralPath $pin.path -ToSession $s -Destination (Join-Path $stage $pin.name)}
    $dispatch=Invoke-Command -Session $s -ArgumentList $stage,($pins|ConvertTo-Json -Compress),$run,$task,$binaryName,$InterruptAfterWrites,$journalBudgetBytes,[bool]$FrozenShadowReuse -ScriptBlock {
        param($Stage,$Pins,$Run,$TaskName,$BinaryName,$InterruptWrites,$JournalBudgetBytes,$Reuse);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        $rows=ConvertFrom-Json -InputObject $Pins
        foreach($row in $rows){if((Get-FileHash -LiteralPath (Join-Path $Stage $row.name)).Hash.ToLowerInvariant()-cne$row.sha256){throw 'Staged binary differs.'}}
        $request=Join-Path $Stage 'request.json';$discovery=Join-Path $Stage 'discovery.json';$output='C:\ntfs2refs\streaming-v2-runs\'+$Run
        $ErrorActionPreference='Continue'
        [string[]]$bindArguments=@('--source','F:\','--shadow','R:\','--journal','J:\','--experiment-id',$Run,
            '--experimental-streaming-payload','--experimental-large-tree','--experimental-large-journal',
            '--max-journal-bytes',[string]$JournalBudgetBytes,'--output',$request,'--evidence',$discovery)
        if($Reuse){$bindArguments+='--verify-existing-shadow'}
        $bindArguments|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $Stage 'bind-arguments.json') -Encoding utf8
        $log=@(& (Join-Path $Stage 'ntfs2refs-bind.exe') @bindArguments 2>&1)
        $exit=$LASTEXITCODE;$ErrorActionPreference='Stop'
        $log|Out-String|Set-Content -LiteralPath (Join-Path $Stage 'discovery.log') -Encoding utf8
        if($exit-ne0){throw 'Discovery refused; preserve current files.'}
        $value=Get-Content -LiteralPath $request -Raw|ConvertFrom-Json
        if($value.source_resource_profile-cne'experimental_streaming_tree_v2'-or$value.schema_version-ne2-or$value.max_journal_bytes-ne$JournalBudgetBytes){throw 'Explicit streaming/v2-journal budget binding missing.'}
        if($Reuse){
            if(-not$value.verify_existing_shadow){throw 'Existing-shadow request flag missing.'}
            $shadow=Get-Disk -Number 3
            if([guid]$shadow.Guid-ne[guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f'-or$shadow.IsOffline-or-not$shadow.IsReadOnly){throw 'Read-only bound shadow required.'}
            Set-Disk -Number 3 -IsOffline $true -ErrorAction Stop
            $shadow=Get-Disk -Number 3
            if(-not$shadow.IsOffline-or-not$shadow.IsReadOnly){throw 'Frozen shadow exclusion failed.'}
        }
        $pin=(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant();$binary=Join-Path $Stage $BinaryName
        $arguments=$(if($InterruptWrites){''}else{'convert '})+'--request "'+$request+'" --request-sha256 '+$pin+' --output "'+$output+'"'
        if($InterruptWrites){$arguments+=' --interrupt-after-writes '+$InterruptWrites}
        $action=New-ScheduledTaskAction -Execute $binary -Argument $arguments
        $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
        $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
        Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings|Out-Null
        [pscustomobject]@{run_id=$Run;task_name=$TaskName;guest_output=$output;guest_stage=$Stage;guest_request=$request;request_sha256=$pin;
            binary_name=$BinaryName;binary_sha256=(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant();arguments=$arguments;
            expected_exit_code=$(if($InterruptWrites){86}else{0});interrupt_after_writes=$InterruptWrites;
            source_resource_profile=$value.source_resource_profile;max_journal_bytes=$value.max_journal_bytes;frozen_shadow_reuse=$Reuse;source_partition_bytes=52GB;utc=[DateTime]::UtcNow.ToString('o')}
    }
    $dispatch|Add-Member vm_id $m.vm_id
    $dispatch|Add-Member fixture_root $fixtureRoot
    Save-New 'dispatch.json' $dispatch
    Copy-Item -LiteralPath $dispatch.guest_request -FromSession $s -Destination (Join-Path $candidateRoot 'request.json')
    if((Get-FileHash -LiteralPath (Join-Path $candidateRoot 'request.json')).Hash.ToLowerInvariant()-cne$dispatch.request_sha256){throw 'Exported discovery request differs; registered task remains unstarted.'}
    $started=Invoke-Command -Session $s -ArgumentList $dispatch.task_name,(Join-Path $stage $dispatch.binary_name),$dispatch.arguments,$dispatch.binary_sha256 -ScriptBlock {
        param($Task,$Binary,$Arguments,$Pin);$ErrorActionPreference='Stop'
        $t=Get-ScheduledTask -TaskName $Task;$info=Get-ScheduledTaskInfo -TaskName $Task
        if($t.State.ToString()-cne'Ready'-or$info.LastRunTime.Year-ge2000-or
            @($t.Actions).Count-ne1-or$t.Actions[0].Execute-cne$Binary-or$t.Actions[0].Arguments-cne$Arguments-or
            (Get-FileHash -LiteralPath $Binary).Hash.ToLowerInvariant()-cne$Pin-or
            @(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'-or$_.Name-ceq'lab-convert-admitted-tree.exe'}).Count){throw 'Fresh unchanged unstarted task required; do not redispatch.'}
        Start-ScheduledTask -TaskName $Task
        [pscustomobject]@{task=$Task;start_issued_once=$true;utc=[DateTime]::UtcNow.ToString('o')}
    }
    Save-New 'start-observed.json' $started
    $dispatch|ConvertTo-Json -Depth 7 -Compress
}finally{Remove-PSSession $s}
