#Requires -Version 7.2
param(
    [Parameter(Mandatory)][string]$Candidate,
    [Parameter(Mandatory)][string]$Output,
    [Parameter(Mandatory)][string]$Tag,
    [Parameter(Mandatory)][string]$Commit,
    [Parameter(Mandatory)][ValidatePattern('^\d+-\d+$')][string]$Request
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/QualificationInterruption.ps1"
. "$PSScriptRoot/GateRoundCases.ps1"
. "$PSScriptRoot/IntegrityWindowProof.ps1"
. "$PSScriptRoot/IntegrityEvidence.ps1"
$root = Split-Path -Parent $PSScriptRoot
$attempts = Join-Path $root '.lab/hyperv/attempts'
$identity = Get-Content -LiteralPath (Join-Path $Candidate 'candidate.json') -Raw | ConvertFrom-Json -AsHashtable
if ($identity.tag -cne $Tag -or $identity.commit -cne $Commit -or $identity.request -cne $Request -or (git -C $root rev-parse HEAD) -cne $Commit) {
    throw 'Qualification checkout or candidate identity differs'
}
$binaries = Join-Path $Candidate 'bin'
foreach ($name in 'ntfs2refs.exe', 'ntfs2refs-recovery.exe', 'lab-volume-manifest.exe') {
    $path = Join-Path $binaries $name
    if ((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -cne $identity.hashes[$name] -or
        (Get-AuthenticodeSignature -LiteralPath $path).Status -ne 'Valid') { throw "Candidate hash or signature differs for $name" }
}
foreach ($name in 'lab-cloud-provider.exe', 'lab-projfs-provider.exe') {
    Copy-Item -LiteralPath (Join-Path $Candidate "lab-tools/$name") -Destination $binaries -ErrorAction Stop
}
$prefix = 'q' + (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($Request)))).Hash.Substring(0, 7).ToLowerInvariant()
$null = New-Item -ItemType Directory -Path $Output
$rows = [Collections.Generic.List[object]]::new()
$gate = Join-Path $PSScriptRoot 'Invoke-GateRound.ps1'
$boot = Join-Path $PSScriptRoot 'Invoke-BootConversionAttempt.ps1'
$data = Join-Path $PSScriptRoot 'Invoke-DataVolumeAttempt.ps1'
$restart = Join-Path $PSScriptRoot 'Invoke-RestartRouteAttempt.ps1'
$restartWindows11 = Join-Path $PSScriptRoot 'Invoke-Windows11RestartAttempt.ps1'
$binaryArgs = @{ Binary = Join-Path $binaries 'ntfs2refs.exe'; ManifestBinary = Join-Path $binaries 'lab-volume-manifest.exe' }

function Read-Verdict([string]$Name) {
    Get-Content -LiteralPath (Join-Path $attempts "$Name/verdict.json") -Raw | ConvertFrom-Json -AsHashtable
}
function Add-Case([string]$Name, [string]$Route, [string]$Expected, $Verdict, [bool]$Passed) {
    $binaryMatch = $Verdict.converter_sha256 -ceq $identity.hashes['ntfs2refs.exe'] -and
        $Verdict.listing_tool_sha256 -ceq $identity.hashes['lab-volume-manifest.exe']
    if ($Route -eq 'restart') { $binaryMatch = $binaryMatch -and $Verdict.recovery_sha256 -ceq $identity.hashes['ntfs2refs-recovery.exe'] }
    # Running-Windows cases use a separate guest route. Its verdict carries its converter hash.
    if ($Route -eq 'running') { $binaryMatch = $Verdict.converter_sha256 -ceq $identity.hashes['ntfs2refs.exe'] }
    $interruption = Get-QualificationInterruption $Route $Name $Verdict
    $designation = $Verdict.target.windows_reports
    if ($Route -eq 'boot' -and $Verdict.boot.observed.filesystem -eq 'ReFS') {
        $stdout = Join-Path $attempts "$prefix-$Name/stdout.log"
        if (Test-Path -LiteralPath $stdout) {
            $reported = Select-String -LiteralPath $stdout -Pattern '^Windows reports the converted source: ([^;]+);' | Select-Object -Last 1
            if ($reported) { $designation = $reported.Matches[0].Groups[1].Value }
        }
    }
    $targetFormat = switch -Regex ($designation) {
        '^Dev Drive' { 'dev-drive' }
        '^standard ReFS' { 'standard' }
    }
    $restartProfile = if ($Route -eq 'restart') { $Verdict.after.target_profile }
    $row = [ordered]@{
        case_id = $Name; route = $Route; expected = $Expected; outcome = $Verdict.outcome; passed = ($Passed -and $binaryMatch -and $Verdict.cleanup_ok -ne $false)
        converter_sha256 = $Verdict.converter_sha256
        verify = if ($Verdict.verify) { $Verdict.verify } else { 'fast' }; hold = $interruption.hold; reached_hold = $interruption.reached_hold
        interruption = $interruption.kind; simulated_torn_marker = [bool]$Verdict.torn_marker
        torn_marker_settled = $Verdict.torn_marker.settled_by_recovery; recovery = $interruption.recovery
        postflush = $Verdict.interrupt.postflush
        prompt_wait_seconds = $Verdict.interrupt.prompt_wait_seconds
        plain_report_fault = if ($Verdict.plain_report_fault) {
            $Verdict.plain_report_fault | Select-Object original_sha256, damaged_sha256, worker_sha256
        }
        manifest = $Verdict.manifest.result; exact_manifest = $Verdict.manifest.exact; cleanup_ok = $Verdict.cleanup_ok
        cleanup_outcome = $Verdict.cleanup_outcome
        working_filesystem = $Verdict.made.working_filesystem
        scratch_refusal = $Verdict.scratch_refusal
        windows = @($Verdict.integrity.windows, $Verdict.boot.observed.build, $Verdict.windows_build, $restartProfile.windows_build, $Verdict.made.windows_build, $Verdict.control.windows_build) | Where-Object { $_ } | Select-Object -First 1
        windows_edition = $Verdict.boot.observed.windows_edition ?? $Verdict.windows_edition ?? $restartProfile.windows_edition
        windows_revision = $Verdict.windows_revision
        refs = @($Verdict.integrity.refs, $Verdict.volume_after.refs_version, $Verdict.boot.observed.refs_version, $restartProfile.refs_version) | Where-Object { $_ } | Select-Object -First 1
        observed_target_format = $targetFormat ?? $restartProfile.target_format
        observed_target_clusters = $Verdict.boot.observed.cluster_bytes ?? $Verdict.volume_after.refs_bytes_per_cluster ?? $restartProfile.cluster_bytes
        source_clusters = $Verdict.source.cluster_bytes; target_clusters = $Verdict.target.cluster_bytes_requested; sector_bytes = $Verdict.source.sector_bytes
        boot = if ($Verdict.boot) { $Verdict.boot.observed | Select-Object -Property filesystem, cluster_bytes, disk, disks, partition, secure_boot, signatures, build, windows_edition, refs_version }
            elseif ($Route -eq 'running' -and $Verdict.after.boot_utc) { @{ filesystem = $Verdict.after.filesystem; cluster_bytes = $Verdict.after.cluster_bytes; boot_utc = $Verdict.after.boot_utc } }
            elseif ($Route -eq 'restart') { $Verdict.after.control_boot }
        integrity_events = $Verdict.integrity.events; reboot_use = $Verdict.reboot_use; host_load = $Verdict.host_load
        guest_bugchecks = $Verdict.guest_bugchecks; integrity_event_scope = $Verdict.integrity.event_scope
        integrity_fixture = if ($Route -eq 'integrity') {
            @{
                content = $Verdict.source.content; directory_entries = $Verdict.source.directory_entries; check_agrees = $Verdict.check.agrees
                source_bytes = $Verdict.source.observed.partition_bytes; ntfs_sector_bytes = $Verdict.source.observed.bytes_per_sector
                ntfs_cluster_bytes = $Verdict.source.observed.bytes_per_cluster; ntfs_record_bytes = $Verdict.source.observed.bytes_per_file_record
                mounted_refs_clusters = $Verdict.integrity.volume.AllocationUnitSize; refs_version = $Verdict.volume_after.refs_version
            }
        }
        integrity_windows = $Verdict.integrity_windows
        integrity_clock = $Verdict.integrity_clock
    }
    if ($Route -ne 'running') { $row.listing_tool_sha256 = $Verdict.listing_tool_sha256 }
    if ($Route -eq 'restart') { $row.recovery_sha256 = $Verdict.recovery_sha256 }
    $rows.Add($row)
}

$failure = $null
try {
    $gateLog = Join-Path $Output 'gate.log'
    & pwsh -NoProfile -File $gate -Build $binaries -Prefix $prefix 2>&1 | Tee-Object -FilePath $gateLog
    $gateExit = $LASTEXITCODE
    $round = Join-Path $binaries "gate-$prefix/round.json"
    if (-not (Test-Path -LiteralPath $round -PathType Leaf)) {
        $tail = (Get-Content -LiteralPath $gateLog -Tail 12) -join "`n"
        throw "The Hyper-V gate round exited $gateExit without a verdict table. Last output:`n$tail"
    }
    $gateRows = @(Get-Content -LiteralPath $round -Raw | ConvertFrom-Json)
    foreach ($row in $gateRows) {
        $v = Read-Verdict $row.Case
        $case = $row.Case.Substring($prefix.Length + 1)
        $route = Get-GateRoundCaseRoute $case
        Add-Case $case $route $row.Expected $v $row.Passed
    }
    if ($gateExit -ne 0) { throw "The Hyper-V gate round failed ($gateExit)" }

    # The Windows 11 reference control OS is ReFS, so it cannot supply an NTFS
    # data partition by shrinking C:. The Server checkpoint has an NTFS C:,
    # installation media and its dedicated working disk.
    $server = Get-VM -Name ntfs2refs-server2025
    $serverBase = Get-VMSnapshot -VM $server -Name 'N2R-Server-Baseline'
    $serverCredential = Join-Path $root '.lab/hyperv/ntfs2refs-server2025/secrets/guest-credential.xml'
    try {
        foreach ($case in 'restart-refs-refusal', 'restart-convert', 'restart-cancel', 'restart-postflush-resume', 'restart-postflush-rollback') {
            if ((Get-VM -Id $server.Id).State -ne 'Off') { Stop-VM -VM $server -Force -Confirm:$false }
            Restore-VMSnapshot -VMSnapshot $serverBase -Confirm:$false
            Start-VM -VM $server
            if ($case -eq 'restart-refs-refusal') {
                $argsForRestart = @{ ExpectScratchRefusal = $true }
                $want = 'refused-source-unchanged'
            } else {
                $workingGB = [int][math]::Floor((Get-Volume -FilePath $attempts).SizeRemaining / 2GB)
                if ($workingGB -le 0) { throw 'No space for the restart working disk' }
                $argsForRestart = @{ WorkingDiskGB = $workingGB }
                $want = 'converted'
                if ($case -eq 'restart-cancel') {
                    $argsForRestart.LabFailAt = 'restart-after-arm'
                    $want = 'cancelled-volume-as-before'
                } elseif ($case -like 'restart-postflush-*') {
                    $argsForRestart.PostFlushRecovery = $case.Substring('restart-postflush-'.Length)
                    $argsForRestart.PartitionMB = 2048
                    if ($argsForRestart.PostFlushRecovery -eq 'resume') { $argsForRestart.RecoveryChoiceDelaySeconds = 185 }
                    $want = if ($argsForRestart.PostFlushRecovery -eq 'resume') { 'resumed' } else { 'rolled-back' }
                }
            }
            & $restart @binaryArgs @argsForRestart -Name "$prefix-$case" -VmId $server.Id -CredentialPath $serverCredential
            $v = Read-Verdict "$prefix-$case"
            Add-Case $case 'restart' $want $v ($v.outcome -eq $want)
            if ($v.outcome -cne $want) { throw "$case ended $($v.outcome)" }
        }
    } finally {
        if ((Get-VM -Id $server.Id).State -ne 'Off') { Stop-VM -VM $server -Force -Confirm:$false }
    }

    $windows11 = Get-VM -Name ntfs2refs-reference-c
    $windows11Media = @(Get-VMDvdDrive -VMName ntfs2refs-reference-b | Where-Object { $_.Path -and (Test-Path -LiteralPath $_.Path) })
    if ($windows11Media.Count -ne 1) { throw 'Expected one accessible Windows 11 installation medium on reference-b' }
    foreach ($mode in 'resume', 'rollback') {
        $case = "restart-w11-postflush-$mode"
        $name = "$prefix-$case"
        & $restartWindows11 @binaryArgs -Name $name -VmId $windows11.Id -InstallationMedia $windows11Media[0].Path -PostFlushRecovery $mode
        $v = Read-Verdict $name
        $control = Get-Content -LiteralPath (Join-Path $attempts "$name/control-profile.json") -Raw | ConvertFrom-Json -AsHashtable
        if ($v.outcome -eq 'resumed' -and ($v.after.target_profile.windows_build -ne $control.windows_build -or
            $v.after.target_profile.windows_edition -ne $control.windows_edition)) {
            throw "$case returned to a different Windows profile"
        }
        $v.windows_build = $control.windows_build
        $v.windows_edition = $control.windows_edition
        $v.windows_revision = $control.windows_revision
        $want = if ($mode -eq 'resume') { 'resumed' } else { 'rolled-back' }
        Add-Case $case 'restart' $want $v ($v.outcome -ceq $want)
        if ($v.outcome -cne $want) { throw "$case ended $($v.outcome)" }
    }

    $vmId = (Get-VM -Name ntfs2refs-reference-isolated).Id
    try {
        $setup = "$prefix-integrity-init"
        & $boot @binaryArgs -Name $setup -NoConvert -KeepScratch -VmId $vmId
        if ((Read-Verdict $setup).outcome -ne 'prepared-only') { throw "$setup did not prepare the control OS" }
        $privateEvidence = Join-Path $attempts "$prefix-integrity-evidence"
        $null = New-Item -ItemType Directory -Path $privateEvidence -Force
        $integrityCredential = Import-Clixml -LiteralPath (Join-Path $root '.lab/hyperv/win11/secrets/guest-credential.xml')
        Initialize-IntegrityCrashCapture -VmId $vmId -Credential $integrityCredential -Output $privateEvidence
        foreach ($case in 'native-idle', 'converted-idle', 'native-loaded', 'converted-loaded', 'lived-in', 'event-131') {
            $name = "$prefix-integrity-$case"
            $native = $case.StartsWith('native-')
            $eventFixture = $case -eq 'event-131'
            $livedIn = $case -eq 'lived-in' -or $eventFixture
            $loaded = $case.EndsWith('-loaded') -or $livedIn
            $fixtureArgs = if ($eventFixture) { @{ DirectoryEntries = 4000; Check = $true; PartitionMB = 51200; SectorBytes = 512 } } else { @{} }
            $workers = [math]::Max(1, [math]::Floor([Environment]::ProcessorCount / 2))
            $samples = Join-Path $privateEvidence "$case-host.jsonl"
            $monitor = Start-Job -ArgumentList $samples -ScriptBlock {
                param($path)
                while ($true) {
                    $cpu = (Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average
                    $os = Get-CimInstance Win32_OperatingSystem
                    $disk = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'"
                    @{
                        utc = [datetime]::UtcNow.ToString('o'); cpu_percent = $cpu; free_memory_kib = $os.FreePhysicalMemory
                        disk_write_bytes_per_second = $disk.DiskWriteBytesPersec; disk_queue = $disk.CurrentDiskQueueLength
                    } |
                        ConvertTo-Json -Compress | Add-Content -LiteralPath $path
                    Start-Sleep -Seconds 5
                }
            }
            $heartbeat = if ($loaded) { Join-Path $privateEvidence "$case-cpu.jsonl" }
            $load = if ($loaded) { Start-IntegrityCpuLoad $workers $heartbeat }
            try {
                & $data @binaryArgs -Name $name -VmId $vmId -ClusterBytes 4096 -TargetClusterBytes 4096 -TargetFormat dev-drive `
                    -Acceptance -NativeRefsControl:$native -Content $(if ($livedIn) { 'lived-in' } else { 'minimal' }) -IntegrityRecords $privateEvidence @fixtureArgs
            } finally {
                foreach ($job in @($monitor, $load) | Where-Object { $_ }) { Stop-Job $job; Remove-Job $job -Force }
            }
            $v = Read-Verdict $name
            $want = if ($native) { 'control-passed' } else { 'converted' }
            $measurements = @(Get-Content -LiteralPath $samples -ErrorAction SilentlyContinue | ConvertFrom-Json)
            $v.host_load = @{ loaded = $loaded; samples = $measurements.Count; cpu_percent_average = ($measurements | Measure-Object cpu_percent -Average).Average
                free_memory_kib_min = ($measurements | Measure-Object free_memory_kib -Minimum).Minimum
                disk_write_bytes_per_second_peak = ($measurements | Measure-Object disk_write_bytes_per_second -Maximum).Maximum
                disk_queue_peak = ($measurements | Measure-Object disk_queue -Maximum).Maximum }
            $ok = $v.outcome -eq $want -and $v.reboot_use -and $v.cleanup_ok -and $v.integrity.volume.AllocationUnitSize -eq 4096 -and
                $v.integrity.serious_count -eq 0 -and $measurements.Count -gt 0 -and ($native -or $v.manifest.result -eq 'identical')
            if ($heartbeat -and (Test-Path -LiteralPath $heartbeat)) {
                $batches = @(Get-Content -LiteralPath $heartbeat | ConvertFrom-Json -AsHashtable)
                $v.integrity_windows = @(Get-Integrity131Windows $v.acceptance $batches $v.integrity_clock)
            }
            Add-Case "integrity-$case" 'integrity' $want $v $ok
            if ($loaded -and $ok) {
                $row = $rows[$rows.Count - 1]
                try {
                    if ($eventFixture) { Assert-Integrity131Case $row }
                    else { Assert-IntegrityLoadWindows $row $case }
                }
                catch { $row.passed = $false; throw }
            }
            if (-not $ok) { throw "$name failed. Evidence is retained on the private host at $privateEvidence" }
        }
    } finally {
        $vm = Get-VM -Id $vmId
        if ($vm.State -eq 'Running') { Stop-VM -VM $vm -Force -Confirm:$false }
    }
} catch {
    $failure = $_.Exception.Message
    throw
} finally {
    $record = @{ identity = $identity; cases = $rows.ToArray() }
    if ($failure) { $record.failure = $failure }
    $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $Output 'lab.json') -Encoding utf8
}
if ($rows.Count -eq 0 -or @($rows | Where-Object { -not $_.passed }).Count) { throw 'Native lab qualification failed' }
