#Requires -Version 7.2
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\NativeRegressionCases.ps1"
$temp = [IO.Path]::GetTempPath()
$root = Join-Path $temp ('n2r-release-check-' + [guid]::NewGuid().ToString('N'))
$candidate = Join-Path $root 'candidate'
$evidence = Join-Path $root 'evidence'
$bin = Join-Path $candidate 'bin'
$null = New-Item -ItemType Directory -Path $bin, $evidence -Force

function Save-Json($Value, [string]$Path) {
    $null = New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force
    ConvertTo-Json -InputObject $Value -Depth 12 -Compress | Set-Content -LiteralPath $Path -Encoding utf8
}
function Invoke-Gate([string]$Name, [string]$ErrorPattern) {
    $failure = $null
    $output = Join-Path $root $Name
    try {
        & "$PSScriptRoot\Confirm-ReleaseQualification.ps1" -Candidate $candidate -Evidence $evidence -Output $output `
            -Commit $identity.commit -Request $identity.request -Tag $identity.tag
    } catch { $failure = $_ }
    if ($ErrorPattern) {
        if (-not $failure -or "$failure" -notmatch $ErrorPattern -or (Test-Path -LiteralPath $output)) { throw "$Name did not fail closed: $failure" }
    } elseif ($failure -or -not (Test-Path -LiteralPath (Join-Path $output 'QUALIFICATION.json'))) { throw "$Name failed: $failure" }
}

try {
    $hashes = @{}
    foreach ($file in 'ntfs2refs.exe', 'lab-volume-manifest.exe', 'ntfs2refs-recovery.exe') {
        $path = Join-Path $bin $file
        Set-Content -LiteralPath $path -Value $file
        $hashes[$file] = (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
    }
    $identity = @{ schema = 1; tag = '0.0.5'; commit = '1' * 40; request = '123-1'; hashes = $hashes }
    Save-Json $identity (Join-Path $candidate 'candidate.json')
    $hosted = @{ converter_sha256 = $hashes['ntfs2refs.exe']; listing_tool_sha256 = $hashes['lab-volume-manifest.exe']
        manifest_matches = $true; refs_version = '3.14'; cleanup_ok = $true; outcome = 'converted'; terminated = $true }
    $nativeRows = @{}
    foreach ($case in $NativeRegressionCases.Keys) {
        $spec = $NativeRegressionCases[$case]
        $row = $hosted + @{ case_id = $case; seed = ($spec.Soak.Seed ?? 315781002); profile = ($spec.Soak.Profile ?? 'convert')
            scenario = ($spec.Soak.Scenario ?? 'seeded'); refs_cluster = ($spec.Soak.TargetClusterBytes ?? 4096)
            hold_at = ($spec.Hold ?? ''); reached_hold = [bool]$spec.Hold; recovery_mode = ($spec.Recovery ?? 'none')
            end_after_seconds = 24.8; attached_before_cleanup = @() }
        $row.outcome = $spec.Outcome
        $row.terminated = [bool]($spec.Hold -or $spec.Timed)
        $nativeRows[$case] = $row
        Save-Json $row (Join-Path $evidence "native-$case/regression.json")
    }
    foreach ($case in 'convert', 'many', 'resume', 'rollback', 'cancel') { Save-Json $nativeRows[$case] (Join-Path $evidence "soak-records-$case/rounds.jsonl") }
    $cases = @(foreach ($name in 'fixture10', 'admin-fixture40', 'full-system', 'apply-mid-resume', 'apply-mid-rollback', 'seal-recorded-resume', 'handoff-sealed-resume', 'torn-handoff-resume', 'vm-verify-passed-rollback', 'vm-thorough-handoff-resume', 'lived-in', 'restart-convert', 'restart-cancel', 'restart-refs-refusal', 'integrity-native-idle', 'integrity-converted-idle', 'integrity-native-loaded', 'integrity-converted-loaded', 'integrity-lived-in') {
        $outcome = switch -Wildcard ($name) {
            '*fixture*' { 'converted-not-booted' }
            '*-resume' { 'RESUMED-NOT-BOOTED' }
            '*-rollback' { 'ROLLED-BACK-NOT-BOOTED' }
            'restart-cancel' { 'cancelled-volume-as-before' }
            'restart-refs-refusal' { 'refused-source-unchanged' }
            'integrity-native-*' { 'control-passed' }
            default { 'converted' }
        }
        @{ case_id = $name; outcome = $outcome; expected = $outcome; passed = $true; manifest = 'identical'; exact_manifest = $true
            verify = 'fast'; reached_hold = $true; interruption = 'process-termination'; recovery = 'resume'
            reboot_use = $true; cleanup_ok = $true; integrity_events = @() }
    })
    $holds = @{'apply-mid-resume'='apply-mid-ranges'; 'apply-mid-rollback'='apply-mid-ranges'; 'seal-recorded-resume'='apply-seal-recorded';
        'handoff-sealed-resume'='handoff-sealed'; 'torn-handoff-resume'='verify-passed'; 'vm-verify-passed-rollback'='verify-passed';
        'vm-thorough-handoff-resume'='apply-handoff-durable'; 'restart-cancel'='restart-after-arm' }
    foreach ($row in $cases) {
        $row.hold = $holds[$row.case_id]
        if ($row.case_id -like 'vm-*') { $row.interruption = 'vm-turned-off' }
        if ($row.case_id -like '*-rollback' -or $row.case_id -eq 'restart-cancel') { $row.recovery = 'rollback' }
        if ($row.case_id -eq 'restart-cancel') { $row.interruption = 'injected failure'; $row.working_filesystem = 'NTFS' }
        if ($row.case_id -eq 'restart-convert') { $row.working_filesystem = 'NTFS' }
        if ($row.case_id -eq 'restart-refs-refusal') { $row.working_filesystem = 'ReFS'; $row.scratch_refusal = $true }
        if ($row.case_id -eq 'vm-thorough-handoff-resume') { $row.verify = 'thorough' }
    }
    $torn = $cases | Where-Object { $_.case_id -eq 'torn-handoff-resume' }
    $torn.simulated_torn_marker = $true; $torn.torn_marker_settled = $true
    $boot = $cases | Where-Object { $_.case_id -eq 'full-system' }
    $boot.outcome = 'BOOTED-ON-REFS'; $boot.expected = $boot.outcome; $boot.manifest = 'identical'; $boot.refs = '3.14'
    $boot.route = 'boot'; $boot.windows = '26300'; $boot.windows_edition = 48
    $boot.observed_target_format = 'dev-drive'; $boot.observed_target_clusters = 4096
    $boot.boot = @{ filesystem = 'ReFS'; disk = 0; disks = @(@{ Number = 0 }); partition = 3; cluster_bytes = 4096; secure_boot = $true
        signatures = @('System32\winload.efi', 'System32\drivers\refs.sys' | ForEach-Object { @{ file = $_; status = 'Valid'; signer = 'CN=Microsoft Windows, O=Microsoft Corporation' } }) }
    $data = $cases | Where-Object { $_.case_id -eq 'lived-in' }
    $data.route = 'data'; $data.windows = '26300'; $data.windows_edition = 48; $data.refs = '3.14'
    $data.observed_target_format = 'dev-drive'; $data.observed_target_clusters = 4096
    $labPath = Join-Path $evidence 'release-lab/lab.json'
    $lab = @{ identity = $identity.Clone(); cases = $cases }
    Save-Json $lab $labPath
    Invoke-Gate 'all-valid'
    $record = Get-Content -LiteralPath (Join-Path $root 'all-valid/QUALIFICATION.json') -Raw | ConvertFrom-Json
    $report = Get-Content -LiteralPath (Join-Path $root 'all-valid/QUALIFICATION.md') -Raw
    $rollback = $record.recovery | Where-Object case_id -EQ 'vm-verify-passed-rollback'
    if ($rollback.requested_hold -cne 'verify-passed' -or $rollback.reached_hold -cne 'verify-passed' -or
        $rollback.interruption -cne 'vm-turned-off' -or $rollback.recovery -cne 'rollback' -or
        -not $rollback.exact_manifest -or -not $rollback.cleanup_ok -or
        $report -notmatch 'identical \(exact\) \| not booted \| passed' -or
        -not ($record.recovery | Where-Object { $_.suite -eq 'soak' -and $_.recovery -eq 'resume' })) {
        throw 'Recovery matrix dropped validated interruption or outcome evidence'
    }
    if (@($record.profiles).Count -ne 2 -or $record.profiles[0].case_id -cne 'full-system' -or
        $record.profiles[0].windows_build -ne 26300 -or $record.profiles[0].windows_edition -ne 48 -or
        $report -notmatch 'full-system \| boot \| 26300 \| 48 \| dev-drive \| 3.14 \| 4096') {
        throw 'Platform matrix did not preserve the observed profile or included incomplete evidence'
    }
    $data.observed_target_clusters = $null
    Save-Json $lab $labPath
    Invoke-Gate 'missing-platform-profile' 'Missing observed platform profile for lived-in'
    $data.observed_target_clusters = 4096

    foreach ($test in @(
        @('rollback', 'outcome', 'converted', 'Unexpected verdict'),
        @('resume', 'hold_at', '', 'missed its interruption'),
        @('resume', 'recovery_mode', 'none', 'missed its recovery action'),
        @('cancel', 'terminated', $false, 'missed its interruption'),
        @('handled-preparation', 'attached_before_cleanup', @('shadow.vhdx'), 'shadow detached before cleanup'),
        @('many', 'events', @(@{provider = 'Microsoft-Windows-ReFS'; id = 134}), 'Invalid hosted qualification verdict')
    )) {
        $case, $key, $value, $message = $test
        $row = $nativeRows[$case].Clone(); $row[$key] = $value
        $path = Join-Path $evidence "native-$case/regression.json"
        Save-Json $row $path
        Invoke-Gate "native-$case-$key" $message
        Save-Json $nativeRows[$case] $path
    }
    $powerOff = $cases | Where-Object { $_.case_id -eq 'vm-verify-passed-rollback' }
    $powerOff.interruption = 'process-termination'
    Save-Json $lab $labPath
    Invoke-Gate 'wrong-vm-interruption' 'Incomplete recovery evidence'
    $powerOff.interruption = 'vm-turned-off'
    $torn.torn_marker_settled = $false
    Save-Json $lab $labPath
    Invoke-Gate 'unsettled-torn-marker' 'Incomplete torn handoff evidence'
    $torn.torn_marker_settled = $true

    $boot.boot.signatures[1].file = 'System32\drivers\other.sys'
    Save-Json $lab $labPath
    Invoke-Gate 'wrong-boot-signature' 'Full Windows boot proof is incomplete'
    $boot.boot.signatures[1].file = 'System32\drivers\refs.sys'

    $restartCancel = $cases | Where-Object { $_.case_id -eq 'restart-cancel' }
    $restartCancel.working_filesystem = 'ReFS'
    Save-Json $lab $labPath
    Invoke-Gate 'wrong-restart-working-filesystem' 'Restart working filesystem evidence differs'
    $restartCancel.working_filesystem = 'NTFS'

    $restartRefusal = $cases | Where-Object { $_.case_id -eq 'restart-refs-refusal' }
    $restartRefusal.scratch_refusal = $false
    Save-Json $lab $labPath
    Invoke-Gate 'missing-refs-refusal' 'Incomplete ReFS working storage refusal evidence'
    $restartRefusal.scratch_refusal = $true

    $lab.cases = $cases | Where-Object { $_.case_id -ne 'restart-cancel' }
    Save-Json $lab $labPath
    Invoke-Gate 'missing-case' 'Missing required Hyper-V case restart-cancel'

    $lab.cases = $cases; $cases[0].passed = $false
    Save-Json $lab $labPath
    Invoke-Gate 'failed-case' 'invalid Hyper-V case fixture10'

    $cases[0].passed = $true; $lab.identity.commit = '0' * 40
    Save-Json $lab $labPath
    Invoke-Gate 'stale-commit' 'Hyper-V record does not identify this candidate'

    $lab.identity.commit = $identity.commit
    Save-Json $lab $labPath
    Add-Content -LiteralPath (Join-Path $bin 'ntfs2refs-recovery.exe') -Value 'replaced'
    Invoke-Gate 'changed-binary' 'Signed candidate hash differs for ntfs2refs-recovery.exe'
    & {
        . "$PSScriptRoot\..\..\lab\IntegrityEvidence.ps1"
        $vm = [guid]'8f7fc646-8c9f-41d0-b65a-ecfadccfc36a'
        $started = [datetime]::UtcNow.AddMinutes(-1)
        function Get-WinEvent($FilterHashtable, $ErrorAction) {
            if ($FilterHashtable.Id -ne 18590 -or $FilterHashtable.LogName -ne 'Microsoft-Windows-Hyper-V-Worker-Admin' -or
                $FilterHashtable.StartTime.Kind -ne 'Local' -or $FilterHashtable.StartTime.ToUniversalTime() -ne $started) {
                throw 'The host query must use the attempt start in local time'
            }
            foreach ($id in $vm, [guid]::NewGuid()) {
                $event = [pscustomobject]@{ VmId = $id; RecordId = 42; TimeCreated = $started.AddSeconds(1) }
                $event | Add-Member ScriptMethod ToXml {
                    "<Event><UserData><VmlEventLog><VmId>$($this.VmId)</VmId><VmErrorCode0>0x139</VmErrorCode0></VmlEventLog></UserData></Event>"
                }
                $event
            }
        }
        Save-IntegrityHostCrashes -VmId $vm -Started $started -Output $root
        $crashes = Get-Content -LiteralPath (Join-Path $root 'host-guest-crashes.json') -Raw | ConvertFrom-Json -NoEnumerate
        if ($crashes -isnot [array] -or $crashes.Count -ne 1 -or $crashes[0].record -ne 42 -or
            $crashes[0].bugcheck -ne '0x139' -or ([datetimeoffset]$crashes[0].time_utc).UtcDateTime -ne $started.AddSeconds(1) -or
            $crashes[0].xml -notmatch $vm.ToString()) { throw 'Host crash evidence did not isolate the expected VM event' }
    }
    'Release qualification gate passed all seventeen checks.'
} finally {
    $resolved = (Resolve-Path -LiteralPath $root).Path
    if ($resolved -ceq $root -and $resolved.StartsWith($temp, [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
