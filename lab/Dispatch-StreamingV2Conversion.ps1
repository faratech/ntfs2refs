# One public conversion on the separately enrolled streaming fixture.
[CmdletBinding()]param([ValidatePattern('^candidate[1-9][0-9]*$')][string]$Candidate='candidate1')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$m=Get-Content -LiteralPath (Join-Path $root 'manifest.json') -Raw|ConvertFrom-Json
$baseline=Get-Content -LiteralPath (Join-Path $root 'baseline.json') -Raw|ConvertFrom-Json
$vm=Get-VM -Id $m.vm_id
if($vm.Id-ne[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'-or$vm.Name-cne$m.name-or[guid]$vm.ParentSnapshotId-ne[guid]$baseline.checkpoint_id-or
    $vm.State.ToString()-notin@('Off','Running')-or-not$vm.Path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Owned NTFS baseline required.'}
$candidateRoot=Join-Path $root $Candidate
if(Test-Path -LiteralPath $candidateRoot){throw 'Candidate already has state; inspect without redispatch.'}
$capacity=Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)
Assert-LabCapacity -Capacity $capacity -AdditionalBytes 6GB
$pins=@(foreach($name in @('ntfs2refs.exe','ntfs2refs-bind.exe','ntfs2refs-recover.exe')){
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
Save-New 'intent.json' @{vm_id=$m.vm_id;run_id=$run;task_name=$task;source_commit=(& git -C $workspace rev-parse HEAD).Trim();working_tree_clean=($patch.Length-eq0);working_tree_patch_sha256=$patchPin;binaries=$pins;capacity=$capacity;growth_budget_bytes=6GB;native_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')}
if($vm.State.ToString()-ceq'Off'){Start-VM -VM $vm -ErrorAction Stop|Out-Null}
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$s=$null;$deadline=[DateTime]::UtcNow.AddMinutes(4)
while($null-eq$s){
    try{$s=New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop}catch{if([DateTime]::UtcNow-ge$deadline){throw 'Guest unavailable after single start; inspect without redispatch.'};Start-Sleep -Seconds 3}
}
try{
    $stage='C:\ntfs2refs\streaming-v2-20261027\'+$Candidate
    $fixture=Get-Content -LiteralPath (Join-Path $root 'fixture.json') -Raw
    $prior=Invoke-Command -Session $s -ArgumentList $stage,$fixture -ScriptBlock {
        param($Stage,$Fixture);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'}).Count-or@(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count){throw 'Another guest worker is active.'}
        $expected=ConvertFrom-Json -InputObject $Fixture
        foreach($part in $expected.partitions){
            $actual=Get-Partition -DriveLetter $part.letter;$disk=Get-Disk -Number $actual.DiskNumber;$volume=Get-Volume -DriveLetter $part.letter
            if($disk.Number-ne$part.disk-or$disk.IsBoot-or$disk.IsSystem-or$disk.IsOffline-or$disk.IsReadOnly-or$actual.Offset-ne$part.offset-or$actual.Size-ne$part.bytes-or
                [guid]$actual.Guid-ne[guid]$part.partition_guid-or$volume.FileSystem-cne$part.filesystem-or$volume.AllocationUnitSize-ne$part.cluster_bytes){throw 'Current fixture partition differs.'}
        }
        if(Test-Path -LiteralPath $Stage){throw 'Fresh stage required.'}
        New-Item -ItemType Directory -Path $Stage|Out-Null
        [pscustomobject]@{worker_count=0;boot_utc=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');source_unchanged_by_controller=$true}
    }
    Save-New 'prior-state.json' $prior
    foreach($pin in $pins){Copy-Item -LiteralPath $pin.path -ToSession $s -Destination (Join-Path $stage $pin.name)}
    $dispatch=Invoke-Command -Session $s -ArgumentList $stage,($pins|ConvertTo-Json -Compress),$run,$task -ScriptBlock {
        param($Stage,$Pins,$Run,$TaskName);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        $rows=ConvertFrom-Json -InputObject $Pins
        foreach($row in $rows){if((Get-FileHash -LiteralPath (Join-Path $Stage $row.name)).Hash.ToLowerInvariant()-cne$row.sha256){throw 'Staged binary differs.'}}
        $request=Join-Path $Stage 'request.json';$discovery=Join-Path $Stage 'discovery.json';$output='C:\ntfs2refs\streaming-v2-runs\'+$Run
        $ErrorActionPreference='Continue'
        $log=@(& (Join-Path $Stage 'ntfs2refs-bind.exe') --source 'F:\' --shadow 'R:\' --journal 'J:\' --experiment-id $Run `
            --experimental-streaming-payload --experimental-large-tree --experimental-large-journal --max-journal-bytes 1073741824 --output $request --evidence $discovery 2>&1)
        $exit=$LASTEXITCODE;$ErrorActionPreference='Stop'
        $log|Out-String|Set-Content -LiteralPath (Join-Path $Stage 'discovery.log') -Encoding utf8
        if($exit-ne0){throw 'Discovery refused; preserve current files.'}
        $value=Get-Content -LiteralPath $request -Raw|ConvertFrom-Json
        if($value.source_resource_profile-cne'experimental_streaming_tree_v2'-or$value.schema_version-ne2){throw 'Explicit streaming/v2-journal binding missing.'}
        $pin=(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant();$binary=Join-Path $Stage 'ntfs2refs.exe'
        $action=New-ScheduledTaskAction -Execute $binary -Argument ('convert --request "'+$request+'" --request-sha256 '+$pin+' --output "'+$output+'"')
        $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
        $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
        Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings|Out-Null
        Start-ScheduledTask -TaskName $TaskName
        [pscustomobject]@{run_id=$Run;task_name=$TaskName;guest_output=$output;guest_stage=$Stage;guest_request=$request;request_sha256=$pin;
            binary_sha256=(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant();source_resource_profile=$value.source_resource_profile;source_partition_bytes=52GB;utc=[DateTime]::UtcNow.ToString('o')}
    }
    $dispatch|Add-Member vm_id $m.vm_id
    Save-New 'dispatch.json' $dispatch
    Copy-Item -LiteralPath $dispatch.guest_request -FromSession $s -Destination (Join-Path $candidateRoot 'request.json')
    $dispatch|ConvertTo-Json -Depth 7 -Compress
}finally{Remove-PSSession $s}
