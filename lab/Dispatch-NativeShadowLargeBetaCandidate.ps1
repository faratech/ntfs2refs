# A new candidate/run on the existing beta, only after prior workers terminate.
# No boot, checkpoint restore, disk formatting or source extent rearrangement.
[CmdletBinding()]param([Parameter(Mandatory)][ValidatePattern('^candidate(?:[2-9]|[1-9][0-9]+)$')][string]$Candidate)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module Hyper-V -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace '.lab\hyperv\shadow-large-beta-20261027'
$id=[guid]'6c4793d2-cdee-468b-bf3b-1c11cae0b501'
$vm=Get-VM -Id $id -ErrorAction Stop
$baseline=Get-Content -LiteralPath (Join-Path $root 'baseline.json') -Raw|ConvertFrom-Json
if($vm.Name-cne'ntfs2refs-shadow-large-beta-20261027'-or$vm.State.ToString()-cne'Running'-or
    [string]$vm.ParentSnapshotId-cne$baseline.checkpoint_id-or-not$vm.Path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Owned beta baseline endpoint differs.'}
$candidateRoot=Join-Path $root $Candidate
if(Test-Path -LiteralPath $candidateRoot){throw 'Candidate has dispatch state; inspect rather than retry.'}
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 8GB
$pins=@(@('ntfs2refs.exe','ntfs2refs-bind.exe','ntfs2refs-recover.exe')|ForEach-Object {
    $path=Join-Path $workspace ('target\release\'+$_)
    [pscustomobject]@{name=$_;path=$path;bytes=(Get-Item -LiteralPath $path).Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
})
$commit=(& git -C $workspace rev-parse HEAD).Trim()
$patch=(& git -C $workspace diff --binary -- src crates Cargo.toml Cargo.lock rust-toolchain.toml)-join"`n"
$patchHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($patch))).ToLowerInvariant()
$null=New-Item -ItemType Directory -Path $candidateRoot
function Save([string]$Name,$Value){
    $stream=[IO.File]::Open((Join-Path $candidateRoot $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 12));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
$run=[guid]::NewGuid().ToString('N');$task='N2R-LargeBetaConvert-'+$run
Save 'intent.json' ([pscustomobject]@{vm_id=$id.ToString('D');candidate=$Candidate;run_id=$run;task_name=$task;source_commit=$commit;
    working_tree_clean=($patch.Length-eq0);working_tree_patch_sha256=$patchHash;binaries=$pins;native_qualified=$false;utc=[DateTime]::UtcNow.ToString('o')})
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$session=New-PSSession -VMId $id -Credential $credential
try{
    $stage='C:\ntfs2refs\beta\large-20261027\'+$Candidate
    $prior=Invoke-Command -Session $session -ArgumentList $stage -ScriptBlock {
        param($Stage);$ErrorActionPreference='Stop'
        if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'}).Count-or
            @(Get-ScheduledTask -TaskName 'N2R-*' -ErrorAction SilentlyContinue|Where-Object {$_.State-in@('Running','Queued')}).Count){throw 'Prior worker remains live; do not dispatch.'}
        foreach($spec in @(@(1,'F','NTFS','n2r-beta-source'),@(2,'J','NTFS','n2r-beta-journal'),@(3,'R','ReFS','n2r-retained-shadow'))){
            $disk=Get-Disk -Number $spec[0];$volume=Get-Volume -DriveLetter $spec[1]
            if($disk.IsBoot-or$disk.IsSystem-or$disk.IsOffline-or$disk.IsReadOnly-or$volume.FileSystem-cne$spec[2]-or$volume.FileSystemLabel-cne$spec[3]){throw 'Unchanged online beta volumes required.'}
        }
        if(Test-Path -LiteralPath $Stage){throw 'Fresh candidate stage required.'}
        $null=New-Item -ItemType Directory -Path $Stage
        $prior=Get-ScheduledTask -TaskName 'N2R-LargeBetaConvert-592d72139d3443dead6f7f947209c494' -ErrorAction SilentlyContinue
        [pscustomobject]@{previous_task=if($prior){$prior.State.ToString()}else{'not-present-on-current-baseline'};
            previous_result=if($prior){(Get-ScheduledTaskInfo -TaskName $prior.TaskName).LastTaskResult}else{$null};
            disks=@(Get-Disk|Select-Object Number,IsOffline,IsReadOnly,Size)}
    }
    Save 'prior-state.json' $prior
    foreach($pin in $pins){Copy-Item -LiteralPath $pin.path -Destination ($stage+'\'+$pin.name) -ToSession $session}
    $dispatch=Invoke-Command -Session $session -ArgumentList $stage,($pins|ConvertTo-Json -Compress),$run,$task -ScriptBlock {
        param($Stage,$Pins,$Run,$Task);Set-StrictMode -Version Latest;$ErrorActionPreference='Stop'
        $rows=ConvertFrom-Json -InputObject $Pins
        foreach($row in $rows){$path=Join-Path $Stage $row.name;if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()-cne$row.sha256){throw 'Candidate staging hash differs.'}}
        $input=Join-Path $Stage 'request.json';$evidence=Join-Path $Stage 'discovery.json';$output='C:\ntfs2refs\beta\runs\'+$Run
        if(Test-Path -LiteralPath $output){throw 'Fresh conversion output required.'}
        $previous=$ErrorActionPreference;$ErrorActionPreference='Continue'
        try{$log=@(& (Join-Path $Stage 'ntfs2refs-bind.exe') --source 'F:\' --shadow 'R:\' --journal 'J:\' --experiment-id $Run `
            --experimental-large-tree --experimental-large-journal --max-journal-bytes 1073741824 --output $input --evidence $evidence 2>&1);$exit=$LASTEXITCODE}
        finally{$ErrorActionPreference=$previous}
        $log|ForEach-Object {$_|Out-String}|Set-Content -LiteralPath (Join-Path $Stage 'discovery.log') -Encoding utf8
        if($exit-ne0){throw 'Candidate discovery failed; retain its existing files.'}
        $pin=(Get-FileHash -LiteralPath $input -Algorithm SHA256).Hash.ToLowerInvariant();$binary=Join-Path $Stage 'ntfs2refs.exe'
        $binaryHash=(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
        $action=New-ScheduledTaskAction -Execute $binary -Argument ('convert --request "'+$input+'" --request-sha256 '+$pin+' --output "'+$output+'"')
        $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
        $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
        Register-ScheduledTask -TaskName $Task -Action $action -Principal $principal -Settings $settings|Out-Null
        Start-ScheduledTask -TaskName $Task
        [pscustomobject]@{run_id=$Run;task_name=$Task;guest_output=$output;guest_input=$input;guest_stage=$Stage;request_sha256=$pin;binary_sha256=$binaryHash;
            source_partition_bytes=240GB;source_cluster_bytes=65536;target_cluster_bytes=4096;entrypoint='public-convert';utc=[DateTime]::UtcNow.ToString('o')}
    }
    $dispatch|Add-Member vm_id $id.ToString('D')
    Save 'dispatch.json' $dispatch
    foreach($pin in $pins){if((Get-FileHash -LiteralPath $pin.path -Algorithm SHA256).Hash.ToLowerInvariant()-cne$pin.sha256){throw 'Host candidate changed during copy.'}}
    Copy-Item -LiteralPath $dispatch.guest_input -Destination (Join-Path $candidateRoot 'request.json') -FromSession $session
    $dispatch|ConvertTo-Json -Depth 8 -Compress
}finally{Remove-PSSession $session -ErrorAction SilentlyContinue}
