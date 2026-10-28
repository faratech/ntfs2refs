# A fresh metadata-only observation. Never reruns the allocation API or a boot.
[CmdletBinding()]param([ValidateSet(2)][int]$Version=2)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$workspace='D:\code\ntfs2refs';$root=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\candidate5\valid-data-probe'
$previous=Get-Content -LiteralPath (Join-Path $root 'reopen-v1\dispatch.json') -Raw|ConvertFrom-Json
$bootPin=(Get-FileHash -LiteralPath (Join-Path $root 'reopen-v1\boot.json')).Hash.ToLowerInvariant()
$stage=Join-Path $root ('reopen-v'+$Version)
if(Test-Path -LiteralPath $stage){throw 'Observation attempt exists; do not redispatch.'}
$binary=Join-Path $workspace 'target\release\lab-probe-native-valid-data.exe';$pin=(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()
$request=Join-Path $workspace '.lab\hyperv\streaming-v2-20261027\candidate5\terminal-evidence\run\request.json'
if((Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()-cne$previous.request_sha256){throw 'Original request changed.'}
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration (Get-LabConfiguration -WorkspaceRoot $workspace)) -AdditionalBytes 16MB
$id=[guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
if((Get-VM -Id $id).State.ToString()-cne'Running'){throw 'Existing boot required.'}
$credential=Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')
$s=New-PSSession -VMId $id -Credential $credential
try{
    $state=Invoke-Command -Session $s -ArgumentList $previous.task_name -ScriptBlock {
        param($Task);$ErrorActionPreference='Stop'
        if((Get-ScheduledTask -TaskName $Task).State.ToString()-in@('Running','Queued')-or(Get-ScheduledTaskInfo -TaskName $Task).LastTaskResult-ne1-or
            @(Get-CimInstance Win32_Process|Where-Object {$_.Name-like'ntfs2refs*'-or$_.Name-in@('lab-convert-admitted-tree.exe','lab-measure-general-journal.exe','lab-probe-native-valid-data.exe')}).Count){throw 'Terminal refused read-only attempt required.'}
        $source=Get-Disk -Number 1;$shadow=Get-Disk -Number 3
        if([guid]$source.Guid-ne[guid]'1b191872-c372-41ee-a416-e18863996f54'-or-not$source.IsOffline-or-not$source.IsReadOnly-or
            [guid]$shadow.Guid-ne[guid]'c0f2cd39-ad3d-484e-9990-0e6eba74485f'-or$shadow.IsOffline-or-not$shadow.IsReadOnly){throw 'Protected disk states differ.'}
        [pscustomobject]@{source_offline=$true;source_readonly=$true;shadow_readonly=$true;boot_utc=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');utc=[DateTime]::UtcNow.ToString('o')}
    }
    New-Item -ItemType Directory -Path $stage|Out-Null
    function Save-New([string]$Name,$Value){
        $f=[IO.File]::Open((Join-Path $stage $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$b=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 10));$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}
    }
    Save-New 'intent.json' @{vm_id=$id;version=$Version;previous_task=$previous.task_name;previous_boot_record_sha256=$bootPin;state=$state;
        binary_sha256=$pin;expected_file_id_info=$previous.expected_file_id_info;source_commit=(& git -C $workspace rev-parse HEAD).Trim();
        source_payload_writes_authorized=$false;valid_data_calls_authorized=$false;payload_reads_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')}
    $guestStage=Join-Path (Split-Path $previous.guest_stage -Parent) ('reopen-v'+$Version)
    Invoke-Command -Session $s -ArgumentList $guestStage -ScriptBlock {param($Stage);$ErrorActionPreference='Stop';if(Test-Path -LiteralPath $Stage){throw 'Guest attempt exists'};New-Item -ItemType Directory -Path $Stage|Out-Null}
    Copy-Item -LiteralPath $binary -ToSession $s -Destination (Join-Path $guestStage 'lab-probe-native-valid-data.exe')
    Copy-Item -LiteralPath $request -ToSession $s -Destination (Join-Path $guestStage 'request.json')
    $task='N2R-NativeValidDataObserve-a060e73a480440a3af174f4c98af60c8-v'+$Version
    $record=Invoke-Command -Session $s -ArgumentList $guestStage,$task,$pin,$previous.request_sha256,$previous.expected_file_id_info -ScriptBlock {
        param($Stage,$Task,$Pin,$RequestPin,$ExpectedId);$ErrorActionPreference='Stop'
        $binary=Join-Path $Stage 'lab-probe-native-valid-data.exe';$request=Join-Path $Stage 'request.json'
        if((Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant()-cne$Pin-or(Get-FileHash -LiteralPath $request).Hash.ToLowerInvariant()-cne$RequestPin){throw 'Observer pins differ.'}
        $arguments='--observe-existing --expected-file-id-info '+$ExpectedId+' --request "'+$request+'" --request-sha256 '+$RequestPin+' --experiment-id a060e73a480440a3af174f4c98af60c8 --output "'+(Join-Path $Stage 'result.json')+'"'
        Register-ScheduledTask -TaskName $Task -Action (New-ScheduledTaskAction -Execute $binary -Argument $arguments) -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero))|Out-Null
        [pscustomobject]@{task_name=$Task;guest_stage=$Stage;binary=$binary;binary_sha256=$Pin;arguments=$arguments;request_sha256=$RequestPin}
    }
    Save-New 'dispatch.json' $record
    Invoke-Command -Session $s -ArgumentList $task,$record.binary,$record.arguments,$pin -ScriptBlock {
        param($Task,$Binary,$Arguments,$Pin);$ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskName $Task;$i=Get-ScheduledTaskInfo -TaskName $Task
        if($t.State.ToString()-cne'Ready'-or$i.LastRunTime.Year-ge2000-or@($t.Actions).Count-ne1-or$t.Actions[0].Execute-cne$Binary-or$t.Actions[0].Arguments-cne$Arguments-or
            (Get-FileHash -LiteralPath $Binary).Hash.ToLowerInvariant()-cne$Pin){throw 'Fresh unchanged read-only task required.'};Start-ScheduledTask -TaskName $Task
    }
    Save-New 'start-observed.json' @{start_issued_once=$true;utc=[DateTime]::UtcNow.ToString('o')}
    $record|ConvertTo-Json -Compress
}finally{Remove-PSSession $s}
