# Preserve one actually completed public Resume attempt. Closed host metadata
# supplies the proof; the guest check reads only scheduled-task/process state.
# No restore, replay, remount, storage attributes or checkpoint cleanup exists.
[CmdletBinding()]param(
    [Parameter(Mandatory)][string]$DispatchPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$DispatchSha256,
    [Parameter(Mandatory)][string]$ClosedReceiptPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ClosedReceiptSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspace = 'D:\code\ntfs2refs'
$base = Join-Path $workspace '.lab\hyperv\streaming-v2-20261027'
$original = '9340223f9d124a9f88e563ba669f0787'
$run = 'c698a0cfd50d4199ba49bcca7dfd1614'
$case = Join-Path $base ('bundle-cli-20261029-' + $original)
$attempt = Join-Path $case ('recovery-cli-resume-' + $run)
$closedRoot = Join-Path $attempt 'closed-recovery'
$root = Join-Path $attempt 'preserved-checkpoint'
$id = [guid]'2401593c-4b30-472e-9b6d-c9534cbaa599'
$parent = [guid]'d121235d-f9fb-4e0e-843e-1ea4c3883221'
$priorIds = @('0872b74c-5b3d-43cf-9ccf-fc64fda0cd93', '693a364c-b86a-4e14-a3cc-a910645f4ce3', $parent.ToString('D'))
$bundlePin = '3f3636d1ad2d64ac28920f722462d6d94639bd7d26e0ba0cecd9be7c618ee204'
$mainPin = '2cac76e012b4cf9b9d9ea5a90a3a77933856061afb4395a2c7e4b9ab4dc33ef0'
$held = [Collections.Generic.List[IO.FileStream]]::new()
$total = [long]0
$session = $null
$created = $false

function Need([bool]$Ok, [string]$Message) { if (-not $Ok) { throw $Message } }
function Hash([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Json([string]$Path, [string]$Pin) {
    $m = Get-Item -LiteralPath $Path -Force
    Need (-not $m.PSIsContainer -and -not ($m.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $m.Length -gt 0 -and $m.Length -le 4MB) 'Bounded ordinary closed host JSON required.'
    $ancestor = $m.Directory
    while ($null -ne $ancestor) {
        Need (-not ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Reparse host metadata ancestry refused.'
        $ancestor = $ancestor.Parent
    }
    $script:total += $m.Length
    Need ($script:total -le 8MB) 'Closed host JSON aggregate exceeds8MiB.'
    $file = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $held.Add($file)
    $bytes = [byte[]]::new([int]$m.Length)
    $at = 0
    while ($at -lt $bytes.Length) {
        $count = $file.Read($bytes, $at, $bytes.Length - $at)
        Need ($count -gt 0) 'Short closed host JSON read.'
        $at += $count
    }
    Need ($file.Length -eq $bytes.Length -and (Hash $bytes) -ceq $Pin) 'Closed host JSON length or SHA differs.'
    [Text.UTF8Encoding]::new($false, $true).GetString($bytes).TrimStart([char]0xfeff) | ConvertFrom-Json
}
function Save([string]$Name, $Value) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 14))
    Need ($bytes.Length -le 1MB) 'Checkpoint receipt exceeds1MiB.'
    $file = [IO.File]::Open((Join-Path $root $Name), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $file.Write($bytes, 0, $bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
}
function Host-Guard {
    $vm = Get-VM -Id $id -ErrorAction Stop
    $snapshots = @(Get-VMSnapshot -VM $vm -ErrorAction Stop)
    $actual = @($snapshots.Id | ForEach-Object { $_.ToString('D') })
    Need ($vm.Name -ceq 'ntfs2refs-streaming-v2-20261027' -and $vm.State.ToString() -ceq 'Running' -and $vm.ParentSnapshotId -eq $parent -and $vm.MemoryStartup -eq 4GB -and $vm.MemoryAssigned -eq 4GB -and -not $vm.DynamicMemoryEnabled -and (Get-VMProcessor -VM $vm -ErrorAction Stop).Count -eq 4 -and @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop).Count -eq 0 -and $actual.Count -eq 3 -and @($priorIds | Where-Object { $_ -notin $actual }).Count -eq 0) 'Actual running partiald121 branch/4GiB/4CPU/noNIC/exact prior3 required.'
}

try {
    Need ([IO.Path]::GetFullPath($DispatchPath) -ceq (Join-Path $attempt 'dispatch.json')) 'Exact actual c698 dispatch path required.'
    Need ([IO.Path]::GetFullPath($ClosedReceiptPath) -ceq (Join-Path $closedRoot 'receipt.json')) 'Exact actual closed-recovery receipt path required.'
    Need (-not (Test-Path -LiteralPath $root)) 'Checkpoint preservation has state; inspect without repeating it.'
    $d = Json $DispatchPath $DispatchSha256
    $receipt = Json $ClosedReceiptPath $ClosedReceiptSha256
    Need ($d.schema_version -eq 1 -and $d.kind -ceq 'bundle-cli-recovery-dispatch' -and $d.run_id -ceq $run -and $d.original_run_id -ceq $original -and $d.operation -ceq 'Resume' -and [guid]$d.vm_id -eq $id -and [guid]$d.parent_id -eq $parent -and $d.binary_sha256 -ceq $mainPin -and $d.binary_bytes -eq 7040000 -and $d.expected_exit -eq 0 -and $d.original_printed_bundle_sha256 -ceq $bundlePin -and $d.task_name -ceq ('N2R-BundleCliRecovery-Resume-' + $run) -and $d.guest_stage -ceq ('C:\ntfs2refs\bundle-recovery-cli-resume-' + $run) -and @($d.checkpoint_ids).Count -eq 3 -and @($priorIds | Where-Object { $_ -notin $d.checkpoint_ids }).Count -eq 0 -and $d.source_admission_recreated -eq $false -and $d.manual_native_input_assembly -eq $false) 'Actual c698 public Resume dispatch/printed pin/three checkpoint lineage differs.'
    Need ($receipt.success -eq $true -and $receipt.operation -ceq 'Resume' -and $receipt.run_id -ceq $run -and $receipt.original_run_id -ceq $original -and [guid]$receipt.vm_id -eq $id -and $receipt.dispatch_sha256 -ceq $DispatchSha256 -and $receipt.bundle_sha256 -ceq $bundlePin -and $receipt.native_exit_observed -eq $true -and $null -ne $receipt.native_exit -and $receipt.native_exit -eq 0 -and $receipt.workers_absent -eq $true -and $receipt.barrier -ceq 'HND' -and $receipt.raw_recovery_authorized -eq $false -and $receipt.source_journal_packed_vhdx_image_opened -eq $false -and $receipt.power_checkpoint_attribute_actions -eq $false) 'Pinned actual terminal0/HND/absent-worker closed receipt required.'
    Need ((Get-FileHash -LiteralPath (Join-Path $attempt 'guest-wrapper.ps1')).Hash.ToLowerInvariant() -ceq $d.wrapper_sha256) 'Actual host wrapper pin differs.'

    $values = @{}; $pins = @{}
    foreach ($document in $receipt.documents) {
        Need ($document.name -cmatch '\A[a-z-]+\.(json|log)\z' -and -not $pins.ContainsKey($document.name) -and $document.sha256 -cmatch '\A[0-9a-f]{64}\z') 'Invalid/duplicate closed archive leaf.'
        $pins[$document.name] = $document.sha256
        if ($document.name.EndsWith('.json', [StringComparison]::Ordinal)) {
            $path = Join-Path $closedRoot $document.name
            Need ((Get-Item -LiteralPath $path).Length -eq $document.bytes) 'Closed archive length differs.'
            $values[$document.name] = Json $path $document.sha256
        }
    }
    $worker = $values['wrapper-worker.json']; $process = $values['native-process.json']; $terminal = $values['native-terminal.json']; $wrapper = $values['wrapper-result.json']
    $completion = $values['completion.json']; $execution = $values['execution.json']; $tree = $values['expectation.json']; $typed = $values['typed-recovery-evidence.json']
    $cli = @('--recover', $d.original_conversion_dir, '--recovery-sha256', $bundlePin)
    Need ($worker.run_id -ceq $run -and $worker.pid -gt 0 -and $worker.creation_ms -gt 0 -and $process.pid -gt 0 -and $process.creation_ms -gt 0 -and $process.parent_pid -eq $worker.pid -and $process.binary_sha256 -ceq $mainPin -and $process.binary -ceq (Join-Path $d.guest_stage 'ntfs2refs.exe') -and $process.expected_exit -eq 0 -and $process.process_handle_retained_before_wait -eq $true -and ($process.argv -join '|') -ceq ($cli -join '|') -and $terminal.native_exit_observed -eq $true -and $null -ne $terminal.native_exit -and $terminal.native_exit -eq 0 -and $terminal.expected_exit -eq 0 -and $wrapper.success -eq $true -and $wrapper.run_id -ceq $run -and $wrapper.operation -ceq 'Resume' -and $wrapper.native_exit_observed -eq $true -and $wrapper.native_exit -eq 0 -and $wrapper.barrier -ceq 'HND' -and $wrapper.bundle_sha256 -ceq $bundlePin -and $wrapper.original_printed_pin_used -eq $true -and $wrapper.source_label_mount_verified -eq $true -and $wrapper.source_admission_recreated -eq $false) 'Closed actual native process/retained handle/argv/exit0/wrapper evidence differs.'
    Need ($terminal.stdout.sha256 -ceq $pins['stdout.log'] -and $terminal.stderr.sha256 -ceq $pins['stderr.log'] -and $terminal.stdout.truncated -eq $false -and $wrapper.completion_sha256 -ceq $pins['completion.json'] -and $typed.completion_sha256 -ceq $pins['completion.json'] -and $typed.bundle_sha256 -ceq $bundlePin -and $completion.success -eq $true -and $null -eq $completion.error -and $completion.rollback_closed -eq $true -and $completion.handoff.handoff_recorded -eq $true -and $completion.handoff.operation -ceq 'handoff-recorded' -and $completion.handoff.target_sha256 -ceq $execution.expected_target_sha256 -and $execution.result.target_sha256 -ceq $execution.expected_target_sha256 -and $wrapper.premount_exact_image_sha256 -ceq $execution.expected_target_sha256 -and $completion.mount_paths_preserved -eq $true -and $completion.label_restoration.success -eq $true -and $completion.label_restoration.readback_matches -eq $true) 'Closed exact-image/HND/native/label/mount completion differs.'
    foreach ($role in @('resume', 'finalize')) {
        $result = $values[$role + '-result.json']
        Need ($result.kind -ceq 'experimental-compact-recovery' -and $result.success -eq $true -and $result.operation -ceq $role) 'Both actual typed native roles must have succeeded.'
    }
    $objects = @($completion.native.native.objects); $hashes = 0
    Need ($objects.Count -eq @($tree.objects).Count -and $objects.Count -eq 15) 'Complete native15 expected objects required.'
    foreach ($expected in $tree.objects) {
        $found = @($objects | Where-Object { ($_.components -join '\') -ceq ($expected.path -join '\') })
        Need ($found.Count -eq 1) 'Closed native object missing/duplicate.'
        if (-not $expected.directory) { Need ($found[0].logical_sha256 -ceq $expected.sha256) 'Closed native complete logical hash differs.'; $hashes++ }
    }
    Need ($hashes -eq 10 -and $wrapper.native_complete_hashes -eq 10) 'Complete native10 hashes required.'

    Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
    $configuration = Get-LabConfiguration -WorkspaceRoot $workspace
    $capacity = Get-LabCapacity -Configuration $configuration
    Need ($capacity.MaximumActualBytes -eq 329374052988 -and $capacity.MinimumFreeBytes -eq 17179869184) 'Fixed capacity epoch/16GiB floor differs.'
    Assert-LabCapacity -Capacity $capacity -AdditionalBytes 256MB
    Host-Guard
    New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
    $created = $true
    $session = New-PSSession -VMId $id -Credential (Import-Clixml (Join-Path $workspace '.lab\hyperv\win11\secrets\guest-credential.xml')) -ErrorAction Stop
    $payload = @{dispatch=$d; identities=@($worker,$process)} | ConvertTo-Json -Depth 12 -Compress
    $freshTerminal = Invoke-Command -Session $session -ArgumentList $payload -ScriptBlock {
        param($Payload)
        Set-StrictMode -Version Latest; $ErrorActionPreference='Stop'; $c=$Payload|ConvertFrom-Json; $d=$c.dispatch
        $task=Get-ScheduledTask -TaskName $d.task_name -ErrorAction Stop; $info=Get-ScheduledTaskInfo -TaskName $d.task_name -ErrorAction Stop
        if ($env:COMPUTERNAME -cne 'N2R-WIN11' -or @($task).Count -ne 1 -or $task.State.ToString() -cne 'Ready' -or $info.LastTaskResult -ne 0 -or $info.LastRunTime.Year -lt 2026 -or @($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -cne "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -or $task.Actions[0].Arguments -cne ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $d.guest_stage 'wrapper.ps1')+'"') -or $task.Principal.UserId -notin @('SYSTEM','S-1-5-18') -or $task.Principal.RunLevel.ToString() -cne 'Highest') { throw 'Exact actual public Resume SYSTEM task must be terminal0.' }
        $tasks=@(Get-ScheduledTask -ErrorAction Stop); $processes=@(Get-CimInstance Win32_Process -ErrorAction Stop)
        if (@($tasks|Where-Object {$_.TaskName -like 'N2R-*' -and $_.State.ToString() -notin @('Ready','Disabled')}).Count -or @($processes|Where-Object {$_.Name -match '\A(?:ntfs2refs(?:-.+)?|lab-.+)\.exe\z'}).Count) { throw 'A project process/task remains active or unknown.' }
        foreach ($identity in $c.identities) { foreach ($p in @($processes|Where-Object ProcessId -eq $identity.pid)) { if (([DateTimeOffset]$p.CreationDate).ToUnixTimeMilliseconds() -eq [long]$identity.creation_ms) { throw 'Original observed native/wrapper creation still exists.' } } }
        @{task_name=$d.task_name;actual_task_result=0;workers_absent=$true;guest_artifact_source_journal_reads=$false;utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress
    } | ConvertFrom-Json
    Save 'intent.json' @{schema_version=1;kind='bundle-cli-resume-checkpoint-intent';run_id=$run;original_run_id=$original;vm_id=$id.ToString();parent_id=$parent.ToString();prior_checkpoint_ids=$priorIds;dispatch_sha256=$DispatchSha256;closed_receipt_sha256=$ClosedReceiptSha256;bundle_sha256=$bundlePin;barrier='HND';native_exit0_observed=$true;native_objects=15;complete_native_hashes=10;fresh_terminal=$freshTerminal;capacity=$capacity;source_authorized=$false;recovery_replay_authorized=$false;utc=[DateTime]::UtcNow.ToString('o')}
    Remove-PSSession $session; $session=$null
    Host-Guard
    Assert-LabCapacity -Capacity (Get-LabCapacity -Configuration $configuration) -AdditionalBytes 256MB
    $vm=Get-VM -Id $id -ErrorAction Stop
    Save 'shutdown-intent.json' @{vm_id=$id.ToString();parent_id=$vm.ParentSnapshotId.ToString('D');force=$false;issued_at_most_once=$true;workers_absent=$true;utc=[DateTime]::UtcNow.ToString('o')}
    Stop-VM -VM $vm -Confirm:$false -ErrorAction Stop
    $deadline=[DateTime]::UtcNow.AddSeconds(30)
    do { $vm=Get-VM -Id $id -ErrorAction Stop; if ($vm.State.ToString() -ceq 'Off' -and $vm.MemoryAssigned -eq 0) { break }; if ([DateTime]::UtcNow -ge $deadline) { throw 'Clean OFF did not settle; no retry or force.' }; Start-Sleep -Milliseconds 500 } while ($true)
    Need ($vm.ParentSnapshotId -eq $parent) 'OFF working-branch lineage differs.'
    $name='bundle-cli-resume-passed-'+$run
    $before=@(Get-VMSnapshot -VM $vm -ErrorAction Stop)
    Need ($before.Count -eq 3 -and @($priorIds|Where-Object {$_ -notin @($before.Id|ForEach-Object {$_.ToString('D')})}).Count -eq 0 -and @($before|Where-Object Name -CEQ $name).Count -eq 0) 'Exact prior3/fresh checkpoint name required.'
    Save 'checkpoint-create-intent.json' @{vm_id=$id.ToString();run_id=$run;name=$name;parent_id=$parent.ToString();prior_checkpoint_ids=$priorIds;creation_issued_at_most_once=$true;utc=[DateTime]::UtcNow.ToString('o')}
    $checkpoint=Checkpoint-VM -VM $vm -SnapshotName $name -Passthru -ErrorAction Stop
    $direct=if ($null -ne $checkpoint -and [guid]$checkpoint.Id -ne [guid]::Empty) {$checkpoint.Id.ToString('D')} else {$null}
    $deadline=[DateTime]::UtcNow.AddSeconds(30)
    do {
        $vm=Get-VM -Id $id -ErrorAction Stop; $all=@(Get-VMSnapshot -VM $vm -ErrorAction Stop); $matches=@($all|Where-Object Name -CEQ $name)
        Need ($matches.Count -le 1) 'Duplicate checkpoint name; no creation retry.'
        if ($matches.Count -eq 1 -and $all.Count -eq 4 -and @($priorIds|Where-Object {$_ -notin @($all.Id|ForEach-Object {$_.ToString('D')})}).Count -eq 0) {
            $cp=$matches[0].Id.ToString('D')
            Need (($null -eq $direct -or $cp -ceq $direct) -and $cp -notin $priorIds -and $vm.State.ToString() -ceq 'Off' -and $vm.MemoryAssigned -eq 0) 'Actual fresh checkpoint/OFF identity differs.'
            break
        }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Fresh checkpoint view did not settle; never retry creation.' }
        Start-Sleep -Milliseconds 500
    } while ($true)
    Save 'receipt.json' @{schema_version=1;kind='bundle-cli-resume-preserved-checkpoint';success=$true;run_id=$run;original_run_id=$original;vm_id=$id.ToString();checkpoint_id=$cp;parent_id=$parent.ToString();checkpoint_count=4;prior_checkpoint_count=3;prior_checkpoint_ids=$priorIds;all_prior3_preserved=$true;state='Off';memory_assigned=0;dispatch_sha256=$DispatchSha256;closed_receipt_sha256=$ClosedReceiptSha256;bundle_sha256=$bundlePin;native_exit0_observed=$true;barrier='HND';native_objects=15;complete_native_hashes=10;source_authorized=$false;recovery_replay_authorized=$false;source_journal_packed_image_opened=$false;scope='Preserves the actual sealed public --recover Resume, typed HND and complete native15/10 result. No journal replay, arbitrary-volume, power-loss or production qualification is inferred.';utc=[DateTime]::UtcNow.ToString('o')}
    Get-Content -LiteralPath (Join-Path $root 'receipt.json') -Raw
} catch {
    if ($created -and -not (Test-Path -LiteralPath (Join-Path $root 'failed.json'))) { Save 'failed.json' @{success=$false;run_id=$run;error=$_.Exception.ToString();automatic_retry=$false;checkpoint_creation_repeated=$false;utc=[DateTime]::UtcNow.ToString('o')} }
    throw
} finally {
    if ($null -ne $session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
    for ($i=$held.Count-1; $i -ge 0; $i--) { $held[$i].Dispose() }
}
