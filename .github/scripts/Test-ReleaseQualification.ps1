#Requires -Version 7.2
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\NativeRegressionCases.ps1"
. "$PSScriptRoot/../../lab/QualificationInterruption.ps1"
. "$PSScriptRoot/SeededSoakPlan.ps1"
. "$PSScriptRoot/../../lab/IntegrityWindowProof.ps1"

$cut = @{ hold_at = 'apply-mid-ranges'; hold_reported = $true; recovered_after_it = $true
    recovery_mode = Get-RunningRecoveryMode 'The recovery finished: the volume is converted.' }
$observed = Get-QualificationInterruption 'running' 'c-cut-apply-mid' @{ cut = $cut }
if ($observed.hold -cne 'apply-mid-ranges' -or $observed.reached_hold -ne $true -or
    $observed.kind -cne 'vm-turned-off' -or $observed.recovery -cne 'resume') {
    throw 'Running-Windows interruption lost its reported hold or recovery'
}
$cut.hold_reported = $false
$cut.recovered_after_it = $false
$observed = Get-QualificationInterruption 'running' 'c-cut-apply-mid' @{ cut = $cut }
if ($observed.reached_hold -ne $false -or $null -ne $observed.recovery) {
    throw 'Running-Windows interruption claimed a missed hold or unobserved recovery'
}
$cut.hold_at = 'none'
$cut.recovered_after_it = $true
$cut.recovery_mode = Get-RunningRecoveryMode 'The recovery finished: the run had not started writing, and the volume is NTFS as it was.'
$observed = Get-QualificationInterruption 'running' 'c-cut-preparation' @{ cut = $cut }
if ($null -ne $observed.hold -or $null -ne $observed.reached_hold -or $observed.recovery -cne 'cancel' -or
    (Get-RunningRecoveryMode 'The recovery put the NTFS volume back.') -cne 'rollback') {
    throw 'Timed preparation cancellation was reported as a named hold'
}
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

function Test-ReleaseArchive([string]$Qualification) {
    $distribution = Join-Path $root 'distribution'
    $null = New-Item -ItemType Directory -Path $distribution
    $archive = Join-Path $distribution 'candidate.zip'
    $reports = 'QUALIFICATION.json', 'QUALIFICATION.md' | ForEach-Object { Join-Path $Qualification $_ }
    Copy-Item -LiteralPath $reports -Destination $distribution
    $files = @(Get-ChildItem -LiteralPath $bin -File | ForEach-Object FullName) + $reports
    Compress-Archive -LiteralPath $files -DestinationPath $archive

    function Check-Archive([string]$ErrorPattern) {
        $failure = $null
        try {
            & "$PSScriptRoot/Confirm-ReleaseArchive.ps1" -Archive $archive -Candidate $candidate -Qualification $Qualification
        } catch { $failure = $_ }
        if ($ErrorPattern) {
            if (-not $failure -or "$failure" -notmatch $ErrorPattern) { throw "Archive should have been rejected: $failure" }
        } elseif ($failure) { throw "Valid archive was rejected: $failure" }
    }

    Check-Archive
    $published = Join-Path $distribution 'QUALIFICATION.json'
    Add-Content -LiteralPath $published -Value 'changed'
    Check-Archive 'Published qualification file differs for QUALIFICATION\.json'
    Copy-Item -LiteralPath (Join-Path $Qualification 'QUALIFICATION.json') -Destination $distribution -Force

    $zip = [IO.Compression.ZipFile]::Open($archive, [IO.Compression.ZipArchiveMode]::Update)
    try { $zip.GetEntry('QUALIFICATION.md').Delete() } finally { $zip.Dispose() }
    Check-Archive 'Expected one ZIP entry named QUALIFICATION\.md'
    $zip = [IO.Compression.ZipFile]::Open($archive, [IO.Compression.ZipArchiveMode]::Update)
    try {
        $writer = [IO.StreamWriter]::new($zip.CreateEntry('QUALIFICATION.md').Open())
        try { $writer.Write('changed') } finally { $writer.Dispose() }
    } finally { $zip.Dispose() }
    Check-Archive 'ZIP entry differs for QUALIFICATION\.md'

    $zip = [IO.Compression.ZipFile]::Open($archive, [IO.Compression.ZipArchiveMode]::Update)
    try {
        $zip.GetEntry('QUALIFICATION.md').Delete()
        $null = [IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
            $zip, (Join-Path $Qualification 'QUALIFICATION.md'), 'QUALIFICATION.md')
        $null = $zip.CreateEntry('Ntfs2refs.exe')
    } finally { $zip.Dispose() }
    Check-Archive 'Expected one ZIP entry named ntfs2refs\.exe'
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
    $targetVolume = '\\?\Volume{11111111-1111-1111-1111-111111111111}'
    $otherVolume = '\\?\Volume{22222222-2222-2222-2222-222222222222}'
    $hosted = @{ converter_sha256 = $hashes['ntfs2refs.exe']; listing_tool_sha256 = $hashes['lab-volume-manifest.exe']
        manifest_matches = $true; refs_version = '3.14'; cleanup_ok = $true; outcome = 'converted'; terminated = $true
        passed = $true; failures = @(); retention = 'not requested'; events = @()
        event_observation = @{ schema = 1; completed = $true; started_utc = '2026-11-26T00:00:00Z'; ended_utc = '2026-11-26T00:01:00Z'
            target = @{ image = 'C:/test/image.vhdx'; partition_guid = '33333333-3333-3333-3333-333333333333'; aliases = @($targetVolume); other_aliases = @($otherVolume) } } }
    $nativeRows = @{}
    foreach ($case in $NativeRegressionCases.Keys) {
        $spec = $NativeRegressionCases[$case]
        $row = $hosted + @{ case_id = $case; seed = ($spec.Soak.Seed ?? 315781002); profile = ($spec.Soak.Profile ?? 'convert')
            scenario = ($spec.Soak.Scenario ?? 'seeded'); refs_cluster = ($spec.Soak.TargetClusterBytes ?? 4096)
            hold_at = ($spec.Hold ?? ''); reached_hold = [bool]$spec.Hold; recovery_mode = ($spec.Recovery ?? 'none')
            end_after_seconds = 0; attached_before_cleanup = @() }
        if ($spec.NtfsClusterBytes) { $row.ntfs_cluster = $spec.NtfsClusterBytes }
        if ($spec.Verify) { $row.verify = $spec.Verify }
        $row.outcome = $spec.Outcome
        $row.terminated = [bool]$spec.Hold
        $nativeRows[$case] = $row
        Save-Json $row (Join-Path $evidence "native-$case/regression.json")
    }
    function Save-SoakFixture([string]$Profile, $Row) {
        $dir = Join-Path $evidence "soak-records-$Profile"
        $path = Join-Path $dir 'rounds.jsonl'
        Save-Json $Row $path
        Save-Json @{ schema = 1; workflow_run = '123'; workflow_attempt = '1'; profiles = @($Profile); minutes = 240; round_limit = 0
            first_seed = $Row.seed; rounds = 1; stop_reason = 'duration'; elapsed_seconds = 14403
            rows_sha256 = (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() } (Join-Path $dir 'campaign.json')
    }
    $soakRows = @{}
    foreach ($case in 'convert', 'many', 'resume', 'rollback', 'cancel') {
        $round = $nativeRows[$case].Clone()
        $plan = Get-SeededSoakPlan $round.seed $case
        $round.verify = $plan.verify
        $round.hold_at = $plan.hold_at
        $round.reached_hold = [bool]$plan.hold_at
        $round.end_after_seconds = $plan.end_after_seconds
        $round.round = 1
        $soakRows[$case] = $round
        Save-SoakFixture $case $round
    }
    $cases = @(foreach ($name in 'fixture10', 'admin-fixture40', 'full-system', 'apply-mid-resume', 'apply-mid-rollback', 'seal-recorded-resume', 'handoff-sealed-resume', 'verify-readonly-rollback', 'torn-handoff-resume', 'vm-verify-passed-rollback', 'vm-thorough-verify-passed-resume', 'vm-thorough-verify-passed-rollback', 'lived-in', 'lived-in-64k', 'std-4k', 'std-64k', 'devdrive', 'restart-convert', 'restart-cancel', 'restart-refs-refusal', 'integrity-native-idle', 'integrity-converted-idle', 'integrity-native-loaded', 'integrity-converted-loaded', 'integrity-lived-in', 'integrity-event-131') {
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
            reboot_use = $true; cleanup_ok = $true; integrity_events = @(); guest_bugchecks = 0
            integrity_event_scope = @{ completed = $true; started_utc = '2026-11-24T12:00:00Z'; ended_utc = '2026-11-24T12:01:00Z'
                partition = '87480000-1234-1234-1234-000000000001'; aliases = @('\\?\Volume{87480000-1234-1234-1234-000000000002}\')
                other_aliases = @('\\?\Volume{87480000-1234-1234-1234-000000000003}\') } }
    })
    $holds = @{'apply-mid-resume'='apply-mid-ranges'; 'apply-mid-rollback'='apply-mid-ranges'; 'seal-recorded-resume'='apply-seal-recorded';
        'handoff-sealed-resume'='handoff-sealed'; 'verify-readonly-rollback'='verify-source-readonly'; 'torn-handoff-resume'='verify-passed'; 'vm-verify-passed-rollback'='verify-passed';
        'vm-thorough-verify-passed-resume'='verify-passed'; 'vm-thorough-verify-passed-rollback'='verify-passed'; 'restart-cancel'='restart-after-arm' }
    foreach ($row in $cases) {
        $row.hold = $holds[$row.case_id]
        if ($row.case_id -like 'vm-*') { $row.interruption = 'vm-turned-off' }
        if ($row.case_id -like 'restart-*') {
            $row.route = 'restart'
            $null = $row.Remove('cleanup_ok')
            $row.cleanup_outcome = 'working storage retained by harness'
        } elseif ($row.outcome -like '*-not-booted') {
            $row.route = 'boot'
        }
        if ($row.case_id -like '*-rollback' -or $row.case_id -eq 'restart-cancel') { $row.recovery = 'rollback' }
        if ($row.case_id -eq 'restart-cancel') { $row.interruption = 'injected failure'; $row.working_filesystem = 'NTFS' }
        if ($row.case_id -eq 'restart-convert') { $row.working_filesystem = 'NTFS' }
        if ($row.case_id -eq 'restart-refs-refusal') { $row.working_filesystem = 'ReFS'; $row.scratch_refusal = $true }
        if ($row.case_id -like 'vm-thorough-*') { $row.verify = 'thorough' }
    }
    foreach ($mode in 'resume', 'rollback') {
        $outcome = if ($mode -eq 'resume') { 'resumed' } else { 'rolled-back' }
        $cases += @{
            case_id = "restart-postflush-$mode"; route = 'restart'; verify = 'fast'; passed = $true
            outcome = $outcome; expected = $outcome; manifest = 'identical'; working_filesystem = 'NTFS'
            hold = 'winpe-postflush-before-discovery'; reached_hold = $true; interruption = 'vm-turned-off'; recovery = $mode
            boot = @{ filesystem = 'NTFS'; boot_utc = '2026-11-24T12:00:00Z' }
            cleanup_outcome = 'working storage retained by harness'
            prompt_wait_seconds = if ($mode -eq 'resume') { 186 } else { 1 }
            postflush = @{ native_bytes_written = 4096; delayed_discovery_bytes = 4096; released = $false
                flush_and_pending_readback_succeeded = $true; native_writer_revalidation_succeeded = $true; discovery_write_not_requested = $true }
        }
    }
    $torn = $cases | Where-Object { $_.case_id -eq 'torn-handoff-resume' }
    $torn.simulated_torn_marker = $true; $torn.torn_marker_settled = $true
    $boot = $cases | Where-Object { $_.case_id -eq 'full-system' }
    $boot.outcome = 'BOOTED-ON-REFS'; $boot.expected = $boot.outcome; $boot.manifest = 'identical'; $boot.refs = '3.14'
    $boot.route = 'boot'; $boot.windows = '26300'; $boot.windows_edition = 48
    $boot.observed_target_format = 'dev-drive'; $boot.observed_target_clusters = 4096
    $boot.boot = @{ filesystem = 'ReFS'; disk = 0; disks = @(@{ Number = 0 }); partition = 3; cluster_bytes = 4096; secure_boot = $true
        build = '26300'; windows_edition = 48; refs_version = '3.14'
        signatures = @(
            @{ file = 'System32\winload.efi'; status = 'Valid'; signer = 'CN=Microsoft Windows, O=Microsoft Corporation'; sha256 = '1' * 64 },
            @{ file = 'System32\drivers\refs.sys'; status = 'Valid'; signer = 'CN=Microsoft Windows, O=Microsoft Corporation'; sha256 = '2' * 64 }
        ) }
    $data = $cases | Where-Object { $_.case_id -eq 'lived-in' }
    $data.route = 'data'; $data.windows = '26300'; $data.windows_edition = 48; $data.refs = '3.14'
    $data.observed_target_format = 'dev-drive'; $data.observed_target_clusters = 4096
    $running = Get-QualificationInterruption 'running' 'c-cut-apply-mid' @{ cut = @{
        hold_at = 'apply-mid-ranges'; hold_reported = $true; recovered_after_it = $true
        recovery_mode = Get-RunningRecoveryMode 'The recovery finished: the volume is converted.'
    } }
    $cases += @{
        case_id = 'c-cut-apply-mid'; route = 'running'; passed = $true
        expected = 'CUT-RECOVERED-TO-REFS'; outcome = 'CUT-RECOVERED-TO-REFS'; verify = 'thorough'
        hold = $running.hold; reached_hold = $running.reached_hold; interruption = $running.kind; recovery = $running.recovery
        boot = @{ filesystem = 'ReFS'; cluster_bytes = 4096 }
    }
    $restartProfile = $cases | Where-Object case_id -EQ 'restart-convert'
    $restartProfile.route = 'restart'; $restartProfile.windows = 26100; $restartProfile.windows_edition = 7
    $restartProfile.refs = '3.14'; $restartProfile.observed_target_format = 'dev-drive'; $restartProfile.observed_target_clusters = 4096
    $resumedProfile = $cases | Where-Object case_id -EQ 'restart-postflush-resume'
    $resumedProfile.windows = 26100; $resumedProfile.windows_edition = 7
    $resumedProfile.refs = '3.14'; $resumedProfile.observed_target_format = 'dev-drive'; $resumedProfile.observed_target_clusters = 4096
    foreach ($mode in 'resume', 'rollback') {
        $source = $cases | Where-Object case_id -EQ "restart-postflush-$mode"
        $client = $source.Clone()
        $client.postflush = $source.postflush.Clone()
        $client.case_id = "restart-w11-postflush-$mode"
        $client.windows = 26300; $client.windows_edition = 48; $client.windows_revision = 9457
        $client.prompt_wait_seconds = 1
        $cases += $client
    }
    $eventFixture = $cases | Where-Object case_id -eq 'integrity-event-131'
    $eventFixture.route = 'integrity'; $eventFixture.windows = 26300; $eventFixture.windows_edition = 48
    $eventFixture.observed_target_format = 'dev-drive'; $eventFixture.observed_target_clusters = 4096
    $eventFixture.integrity_fixture = @{
        content = 'lived-in'; directory_entries = 4000; check_agrees = $true; source_bytes = 50GB
        ntfs_sector_bytes = 512; ntfs_cluster_bytes = 4096; ntfs_record_bytes = 1024
        mounted_refs_clusters = 4096; refs_version = '3.14'
    }
    $acceptance = @{ steps = @(
        @{ step = 'fill the volume and free it'; ok = $true; started_utc = '2026-11-24T12:00:00Z'; finished_utc = '2026-11-24T12:00:30Z' }
        @{ step = 'mount again'; ok = $true; started_utc = '2026-11-24T12:00:31Z'; finished_utc = '2026-11-24T12:00:36Z' }
    ) }
    $eventFixture.integrity_clock = @{
        before = @{ host_before_utc = '2026-11-24T11:59:59Z'; guest_utc = '2026-11-24T11:59:58Z'; host_after_utc = '2026-11-24T11:59:59.025Z' }
        after = @{ host_before_utc = '2026-11-24T12:00:38Z'; guest_utc = '2026-11-24T12:00:37Z'; host_after_utc = '2026-11-24T12:00:38.020Z' }
    }
    $cpuBatches = @(
        @{ started_utc = '2026-11-24T11:59:00Z'; finished_utc = '2026-11-24T11:59:01Z'; hashes = 500 }
        @{ started_utc = '2026-11-24T12:00:03Z'; finished_utc = '2026-11-24T12:00:04Z'; hashes = 200 }
        @{ started_utc = '2026-11-24T12:00:32.100Z'; finished_utc = '2026-11-24T12:00:33Z'; hashes = 300 }
    )
    $eventFixture.integrity_windows = @(Get-Integrity131Windows $acceptance $cpuBatches $eventFixture.integrity_clock)
    foreach ($loaded in $cases | Where-Object case_id -in @('integrity-native-loaded', 'integrity-converted-loaded', 'integrity-lived-in')) {
        $loaded.integrity_clock = $eventFixture.integrity_clock
        $loaded.integrity_windows = @(Get-Integrity131Windows $acceptance $cpuBatches $loaded.integrity_clock)
    }
    $wide = $cases | Where-Object case_id -eq 'lived-in-64k'
    $wide.route = 'data'; $wide.windows = '26300'; $wide.windows_edition = 48; $wide.refs = '3.14'
    $wide.observed_target_format = 'dev-drive'; $wide.observed_target_clusters = 65536
    foreach ($server in $cases | Where-Object case_id -in @('std-4k', 'std-64k', 'devdrive')) {
        $server.route = 'data'; $server.windows = '26100'; $server.windows_edition = 79; $server.refs = '3.14'
        $server.observed_target_format = if ($server.case_id -eq 'devdrive') { 'dev-drive' } else { 'standard' }
        $server.observed_target_clusters = if ($server.case_id -eq 'std-64k') { 65536 } else { 4096 }
    }
    . "$PSScriptRoot/../../lab/GateRoundCases.ps1"
    $gateCases = Get-GateRoundExpectations @('fixtures', 'data', 'full', 'server', 'running')
    foreach ($case in $gateCases.Keys | Where-Object { $_ -notin $cases.case_id }) {
        $cases += @{ case_id = $case; route = Get-GateRoundCaseRoute $case; passed = $true; expected = $gateCases[$case]
            outcome = $gateCases[$case]; manifest = 'identical'; cleanup_ok = $true }
    }
    foreach ($row in $cases) {
        $row.converter_sha256 = $hashes['ntfs2refs.exe']
        if ($row.route -ne 'running') { $row.listing_tool_sha256 = $hashes['lab-volume-manifest.exe'] }
        if ($row.route -eq 'restart') { $row.recovery_sha256 = $hashes['ntfs2refs-recovery.exe'] }
    }
    $labPath = Join-Path $evidence 'release-lab/lab.json'
    $lab = @{ identity = $identity.Clone(); cases = $cases }
    Save-Json $lab $labPath
    Invoke-Gate 'all-valid'
    Test-ReleaseArchive (Join-Path $root 'all-valid')
    $withoutProviderCase = $lab.Clone()
    $withoutProviderCase.cases = @($cases | Where-Object case_id -ne 'projfs-plain')
    Save-Json $withoutProviderCase $labPath
    Invoke-Gate 'missing-required-provider-case' 'Missing required Hyper-V gate case projfs-plain'
    Save-Json $lab $labPath
    foreach ($test in @(
        @('resume', 'hold_at', '', 'Invalid interruption evidence'),
        @('resume', 'hold_at', 'apply-mid-ranges', 'Invalid interruption evidence'),
        @('resume', 'reached_hold', $false, 'Invalid hosted qualification verdict'),
        @('resume', 'terminated', $false, 'Invalid interruption evidence'),
        @('resume', 'recovery_mode', 'none', 'Invalid recovery action or outcome'),
        @('rollback', 'recovery_mode', 'resume', 'Invalid recovery action or outcome'),
        @('rollback', 'outcome', 'converted', 'Invalid recovery action or outcome'),
        @('cancel', 'end_after_seconds', 0, 'Invalid interruption evidence'),
        @('cancel', 'terminated', $null, 'Invalid interruption evidence'),
        @('cancel', 'outcome', 'converted', 'Invalid recovery action or outcome'),
        @('convert', 'terminated', $true, 'Invalid interruption evidence')
    )) {
        $profile, $key, $value, $message = $test
        $row = $soakRows[$profile].Clone()
        $row[$key] = $value
        Save-SoakFixture $profile $row
        Invoke-Gate "soak-$profile-$key-$value" "$message for soak $profile"
        Save-SoakFixture $profile $soakRows[$profile]
    }

    foreach ($test in @(
        @('resume', $true, 'resume', 'ntfs-as-before'),
        @('cancel', $false, 'none', 'converted'),
        @('cancel', $true, 'none', 'ntfs-as-before'),
        @('cancel', $true, 'resume', 'converted'),
        @('cancel', $true, 'resume', 'ntfs-as-before')
    )) {
        $profile, $terminated, $action, $outcome = $test
        $row = $soakRows[$profile].Clone()
        $row.terminated = $terminated
        $row.recovery_mode = $action
        $row.outcome = $outcome
        Save-SoakFixture $profile $row
        Invoke-Gate "soak-$profile-$terminated-$action-$outcome"
        Save-SoakFixture $profile $soakRows[$profile]
    }

    $campaignPath = Join-Path $evidence 'soak-records-convert/campaign.json'
    $campaign = Get-Content -LiteralPath $campaignPath -Raw | ConvertFrom-Json -AsHashtable
    $short = $campaign.Clone(); $short.elapsed_seconds = 300
    Save-Json $short $campaignPath
    Invoke-Gate 'short-soak-campaign' 'Incomplete or mismatched soak campaign for convert'
    Save-Json $campaign $campaignPath
    $soakPath = Join-Path $evidence 'soak-records-convert/rounds.jsonl'
    Add-Content -LiteralPath $soakPath -Value ' '
    Invoke-Gate 'changed-soak-campaign-log' 'Incomplete or mismatched soak campaign for convert'
    Save-SoakFixture 'convert' $soakRows['convert']

    $otherEvent = $hosted.Clone()
    $otherEvent.events = @(@{ provider = 'Microsoft-Windows-ReFS'; id = 131; attribution = 'other'; volume = $otherVolume; phase = 'conversion' })
    Assert-HostedRoundPassed $otherEvent 'known unrelated volume'
    $invalidObservation = $hosted.event_observation.Clone(); $invalidObservation.completed = $false

    foreach ($test in @(
        @('fixture10', 'converter_sha256', 'ntfs2refs.exe'),
        @('lived-in', 'listing_tool_sha256', 'lab-volume-manifest.exe'),
        @('restart-postflush-resume', 'recovery_sha256', 'ntfs2refs-recovery.exe'),
        @('c-cut-apply-mid', 'converter_sha256', 'ntfs2refs.exe')
    )) {
        $case, $key, $file = $test
        $row = $cases | Where-Object case_id -CEQ $case
        $row[$key] = '0' * 64
        Save-Json $lab $labPath
        Invoke-Gate "wrong-$case-$key" "Hyper-V case $case hash differs for $([regex]::Escape($file))"
        $row[$key] = $hashes[$file]
    }
    $restartBinaryCase = $cases | Where-Object case_id -CEQ 'restart-refs-refusal'
    $restartBinaryCase.Remove('recovery_sha256')
    Save-Json $lab $labPath
    Invoke-Gate 'missing-restart-recovery-hash' 'Hyper-V case restart-refs-refusal hash differs for ntfs2refs-recovery\.exe'
    $restartBinaryCase.route = 'running'
    Save-Json $lab $labPath
    Invoke-Gate 'wrong-restart-route' 'Unexpected route for Hyper-V case restart-refs-refusal'
    $restartBinaryCase.route = 'restart'
    $restartBinaryCase.recovery_sha256 = $hashes['ntfs2refs-recovery.exe']
    $eventFixture.integrity_fixture.directory_entries = 20000
    Save-Json $lab $labPath
    Invoke-Gate 'wrong-event-131-directory' 'Incomplete ReFS event 131 fixture evidence'
    $eventFixture.integrity_fixture.directory_entries = 4000
    $eventFixture.integrity_fixture.check_agrees = $null
    Save-Json $lab $labPath
    Invoke-Gate 'missing-event-131-preflight' 'Incomplete ReFS event 131 fixture evidence'
    $eventFixture.integrity_fixture.check_agrees = $true
    $eventFixture.observed_target_format = 'standard'
    Save-Json $lab $labPath
    Invoke-Gate 'wrong-event-131-format' 'Incomplete ReFS event 131 fixture evidence'
    $eventFixture.observed_target_format = 'dev-drive'
    $eventFixture.observed_target_clusters = 65536
    Save-Json $lab $labPath
    Invoke-Gate 'wrong-event-131-allocation-unit' 'Incomplete ReFS event 131 fixture evidence'
    $eventFixture.observed_target_clusters = 4096
    $eventFixture.windows = 26100
    Save-Json $lab $labPath
    Invoke-Gate 'wrong-event-131-windows' 'Incomplete ReFS event 131 fixture evidence'
    $eventFixture.windows = 26300

    $validClock = $eventFixture.integrity_clock
    $eventFixture.integrity_clock = $null
    Save-Json $lab $labPath
    Invoke-Gate 'event-131-no-clock' 'Incomplete ReFS event 131 host and guest clock evidence'
    $eventFixture.integrity_clock = @{
        before = $validClock.after
        after = $validClock.before
    }
    Save-Json $lab $labPath
    Invoke-Gate 'event-131-reversed-clock' 'Incomplete ReFS event 131 host and guest clock evidence'
    $eventFixture.integrity_clock = $validClock
    $validWindows = $eventFixture.integrity_windows
    $eventFixture.host_load = @{ loaded = $true; samples = 12 }
    $eventFixture.integrity_windows = @(Get-Integrity131Windows $acceptance @($cpuBatches[0]) $eventFixture.integrity_clock)
    Save-Json $lab $labPath
    Invoke-Gate 'event-131-whole-run-load-only' 'Incomplete ReFS event 131 CPU load evidence for fill'
    $eventFixture.integrity_windows = @(Get-Integrity131Windows $acceptance $cpuBatches[0..1] $eventFixture.integrity_clock)
    Save-Json $lab $labPath
    Invoke-Gate 'event-131-missing-remount-load' 'Incomplete ReFS event 131 CPU load evidence for mount again'
    $eventFixture.integrity_windows = $validWindows
    $eventFixture.integrity_windows[1].cpu = $cpuBatches[1]
    Save-Json $lab $labPath
    Invoke-Gate 'event-131-outside-remount' 'Incomplete ReFS event 131 CPU load evidence for mount again'
    $eventFixture.integrity_windows = @(Get-Integrity131Windows $acceptance $cpuBatches $eventFixture.integrity_clock)
    $eventFixture.integrity_windows[1].cpu = $eventFixture.integrity_windows[1].cpu.Clone()
    $eventFixture.integrity_windows[1].cpu.hashes = 0
    Save-Json $lab $labPath
    Invoke-Gate 'event-131-idle-worker' 'Incomplete ReFS event 131 CPU load evidence for mount again'
    $eventFixture.integrity_windows = @(Get-Integrity131Windows $acceptance $cpuBatches $eventFixture.integrity_clock)
    $eventFixture.integrity_windows[1].finished_utc = '2026-11-24T12:00:30Z'
    Save-Json $lab $labPath
    Invoke-Gate 'event-131-reversed-remount' 'Incomplete ReFS event 131 CPU load evidence for mount again'
    $eventFixture.integrity_windows = @(Get-Integrity131Windows $acceptance $cpuBatches $eventFixture.integrity_clock)
    Save-Json $lab $labPath
    $loadedControl = $cases | Where-Object case_id -eq 'integrity-native-loaded'
    $controlWindows = $loadedControl.integrity_windows
    $loadedControl.integrity_windows = @()
    Save-Json $lab $labPath
    Invoke-Gate 'native-loaded-missing-window' 'Incomplete integrity-native-loaded acceptance evidence'
    $loadedControl.integrity_windows = $controlWindows
    Save-Json $lab $labPath
    $idleControl = $cases | Where-Object case_id -eq 'integrity-native-idle'
    foreach ($bugchecks in @($null, 1)) {
        $idleControl.guest_bugchecks = $bugchecks
        Save-Json $lab $labPath
        Invoke-Gate "native-idle-bugchecks-$bugchecks" 'Incomplete integrity evidence for Hyper-V case integrity-native-idle'
    }
    $idleControl.guest_bugchecks = 0
    $idleControl.integrity_event_scope.completed = $false
    Save-Json $lab $labPath
    Invoke-Gate 'native-idle-event-observation-incomplete' 'Incomplete integrity evidence for Hyper-V case integrity-native-idle'
    $idleControl.integrity_event_scope.completed = $true
    $otherVolume = $idleControl.integrity_event_scope.other_aliases[0]
    $idleControl.integrity_events = @(@{ provider = 'ReFS'; id = 131; attribution = 'other'; volume = $otherVolume; phase = 'test-window' })
    Save-Json $lab $labPath
    Invoke-Gate 'native-idle-other-volume-event'
    $idleControl.integrity_events[0].volume = $idleControl.integrity_event_scope.aliases[0]
    Save-Json $lab $labPath
    Invoke-Gate 'native-idle-misattributed-event' 'Incomplete integrity evidence for Hyper-V case integrity-native-idle'
    $idleControl.integrity_events = @()
    Save-Json $lab $labPath
    $record = Get-Content -LiteralPath (Join-Path $root 'all-valid/QUALIFICATION.json') -Raw | ConvertFrom-Json
    $bootProfile = $record.profiles | Where-Object case_id -CEQ 'full-system'
    if ($bootProfile.boot_files.winload_efi_sha256 -cne $boot.boot.signatures[0].sha256 -or
        $bootProfile.boot_files.refs_sys_sha256 -cne $boot.boot.signatures[1].sha256) {
        throw 'The Windows boot profile lost the observed loader or ReFS driver hash'
    }
    $bootBinaries = $record.hyper_v | Where-Object case_id -CEQ 'full-system'
    $restartBinaries = $record.hyper_v | Where-Object case_id -CEQ 'restart-postflush-resume'
    $runningBinaries = $record.hyper_v | Where-Object case_id -CEQ 'c-cut-apply-mid'
    if ($bootBinaries.converter_sha256 -cne $hashes['ntfs2refs.exe'] -or $bootBinaries.listing_tool_sha256 -cne $hashes['lab-volume-manifest.exe'] -or
        $restartBinaries.recovery_sha256 -cne $hashes['ntfs2refs-recovery.exe'] -or $runningBinaries.converter_sha256 -cne $hashes['ntfs2refs.exe'] -or
        $null -ne $runningBinaries.listing_tool_sha256 -or $null -ne $runningBinaries.recovery_sha256) {
        throw 'Hyper-V case binary receipts were lost or changed during publication'
    }
    $report = Get-Content -LiteralPath (Join-Path $root 'all-valid/QUALIFICATION.md') -Raw
    $restart = $record.recovery | Where-Object case_id -EQ 'restart-postflush-resume'
    if ($restart.postflush.native_bytes_written -ne 4096 -or $restart.boot.filesystem -cne 'NTFS' -or
        $report -notmatch 'restart-postflush-resume \| restart \| fast \| winpe-postflush-before-discovery \| winpe-postflush-before-discovery \| vm-turned-off \| resume \| resumed \| identical \| NTFS \| working storage retained by harness') {
        throw 'Restart recovery matrix dropped the write, boot or cleanup evidence'
    }
    $postflushResume = $cases | Where-Object case_id -EQ 'restart-postflush-resume'
    $postflushResume.postflush.released = $true
    Save-Json $lab $labPath
    Invoke-Gate 'pause-released-before-cut' 'Incomplete durable WinPE write evidence for restart-postflush-resume'
    $postflushResume.postflush.released = $false
    $postflushResume.prompt_wait_seconds = 184
    Save-Json $lab $labPath
    Invoke-Gate 'missing-delayed-resume' 'Incomplete durable WinPE write evidence for restart-postflush-resume'
    $postflushResume.prompt_wait_seconds = 186
    if ($report -notmatch '4,000-entry lived-in case with a preflight check passed') { throw 'Integrity fixture is missing from the release report' }
    $rollback = $record.recovery | Where-Object case_id -EQ 'vm-verify-passed-rollback'
    if ($rollback.requested_hold -cne 'verify-passed' -or $rollback.reached_hold -cne 'verify-passed' -or
        $rollback.interruption -cne 'vm-turned-off' -or $rollback.recovery -cne 'rollback' -or
        -not $rollback.exact_manifest -or -not $rollback.cleanup_ok -or
        $report -notmatch 'identical \(exact\) \| not booted \| passed' -or
        -not ($record.recovery | Where-Object { $_.suite -eq 'soak' -and $_.recovery -eq 'resume' })) {
        throw 'Recovery matrix dropped validated interruption or outcome evidence'
    }
    $runningRecord = $record.recovery | Where-Object case_id -EQ 'c-cut-apply-mid'
    if ($runningRecord.route -cne 'running' -or $runningRecord.reached_hold -cne 'apply-mid-ranges' -or
        $runningRecord.recovery -cne 'resume' -or $runningRecord.boot.filesystem -cne 'ReFS' -or $null -ne $runningRecord.manifest -or
        $report -notmatch 'c-cut-apply-mid \| running \| thorough \| apply-mid-ranges \| apply-mid-ranges \| vm-turned-off \| resume \| CUT-RECOVERED-TO-REFS \| - \| ReFS \| -') {
        throw 'Recovery matrix dropped the running-Windows cut or claimed unobserved results'
    }
    $bootProfile = $record.profiles | Where-Object case_id -CEQ 'full-system'
    if (@($record.profiles).Count -ne 9 -or
        $bootProfile.windows_build -ne 26300 -or $bootProfile.windows_edition -ne 48 -or
        $report -notmatch 'full-system \| boot \| 26300 \| 48 \| dev-drive \| 3.14 \| 4096' -or
        $report -notmatch 'std-64k \| data \| 26100 \| 79 \| standard \| 3\.14 \| 65536' -or
        $report -notmatch 'lived-in-64k \| data \| 26300 \| 48 \| dev-drive \| 3\.14 \| 65536' -or
        $report -notmatch 'restart-convert \| restart \| 26100 \| 7 \| dev-drive \| 3.14 \| 4096' -or
        $report -notmatch 'restart-postflush-resume \| restart \| 26100 \| 7 \| dev-drive \| 3.14 \| 4096' -or
        $report -notmatch 'restart-w11-postflush-resume \| restart \| 26300 \| 48 \| dev-drive \| 3.14 \| 4096') {
        throw 'Platform matrix did not preserve the observed profile or included incomplete evidence'
    }
    $windowsResume = $cases | Where-Object case_id -EQ 'restart-w11-postflush-resume'
    $windowsResume.windows_revision = $null
    Save-Json $lab $labPath
    Invoke-Gate 'missing-windows11-fixture-profile' 'Incomplete Windows 11 fixture profile for restart-w11-postflush-resume'
    $windowsResume.windows_revision = 9457
    $windowsResume.observed_target_format = $null
    Save-Json $lab $labPath
    Invoke-Gate 'missing-windows11-refs-profile' 'Missing observed platform profile for restart-w11-postflush-resume'
    $windowsResume.observed_target_format = 'dev-drive'
    $data.observed_target_clusters = $null
    Save-Json $lab $labPath
    Invoke-Gate 'missing-platform-profile' 'Missing observed platform profile for lived-in'
    $data.observed_target_clusters = 4096
    $lab.cases = $cases | Where-Object case_id -ne 'std-64k'
    Save-Json $lab $labPath
    Invoke-Gate 'missing-server-allocation-unit' 'Missing required Hyper-V gate case std-64k'
    $lab.cases = $cases
    $serverWide = $cases | Where-Object case_id -eq 'std-64k'
    $serverWide.observed_target_clusters = 4096
    Save-Json $lab $labPath
    Invoke-Gate 'wrong-server-allocation-unit' 'Observed platform profile differs for std-64k'
    $serverWide.observed_target_clusters = 65536
    $serverWide.windows_edition = 48
    Save-Json $lab $labPath
    Invoke-Gate 'wrong-server-edition' 'Observed platform profile differs for std-64k'
    $serverWide.windows_edition = 79

    foreach ($test in @(
        @('many-16k-to-64k', 'ntfs_cluster', 4096, 'Wrong source geometry or verification mode'),
        @('many-16k-to-64k', 'refs_cluster', 4096, 'Wrong profile, seed, scenario or target'),
        @('many-16k-to-64k', 'verify', 'fast', 'Wrong source geometry or verification mode'),
        @('many-16k-to-64k', 'seed', 315782001, 'Wrong profile, seed, scenario or target'),
        @('rollback', 'outcome', 'converted', 'Unexpected verdict'),
        @('resume', 'hold_at', '', 'missed its interruption'),
        @('resume', 'recovery_mode', 'none', 'missed its recovery action'),
        @('thorough-resume', 'hold_at', 'finalize-source-readonly', 'missed its interruption'),
        @('cancel', 'terminated', $false, 'missed its interruption'),
        @('cancel', 'end_after_seconds', 24.8, 'missed its interruption'),
        @('handled-preparation', 'attached_before_cleanup', @('shadow.vhdx'), 'shadow detached before cleanup'),
        @('many', 'events', @(@{provider = 'Microsoft-Windows-ReFS'; id = 131; attribution = 'target'; volume = $targetVolume; phase = 'conversion'}), 'ReFS event 131'),
        @('many', 'events', @(@{provider = 'Microsoft-Windows-ReFS'; id = 134; attribution = 'unresolved'}), 'Unattributed ReFS event 134'),
        @('many', 'event_observation', $invalidObservation, 'storage event observation is incomplete'),
        @('many', 'cleanup_ok', $false, 'cleanup did not pass'),
        @('many', 'retention', 'failed', 'failure evidence retention failed')
    )) {
        $case, $key, $value, $message = $test
        $row = $nativeRows[$case].Clone(); $row[$key] = $value
        $path = Join-Path $evidence "native-$case/regression.json"
        Save-Json $row $path
        Invoke-Gate "native-$case-$key" $message
        Save-Json $nativeRows[$case] $path
    }
    $powerOff = $cases | Where-Object { $_.case_id -eq 'vm-verify-passed-rollback' }
    $null = $powerOff.Remove('cleanup_ok')
    Save-Json $lab $labPath
    Invoke-Gate 'missing-boot-recovery-cleanup' 'Incomplete Hyper-V cleanup evidence for vm-verify-passed-rollback'
    $powerOff.cleanup_ok = $true
    $thoroughRollback = $cases | Where-Object { $_.case_id -eq 'vm-thorough-verify-passed-rollback' }
    $thoroughRollback.hold = 'apply-handoff-durable'
    Save-Json $lab $labPath
    Invoke-Gate 'wrong-thorough-rollback-hold' 'Incomplete recovery evidence for Hyper-V case vm-thorough-verify-passed-rollback'
    $thoroughRollback.hold = 'verify-passed'
    $boot.cleanup_ok = $false
    Save-Json $lab $labPath
    Invoke-Gate 'failed-full-boot-cleanup' 'Incomplete Hyper-V cleanup evidence for full-system'
    $boot.cleanup_ok = $true
    $null = $postflushResume.Remove('cleanup_outcome')
    Save-Json $lab $labPath
    Invoke-Gate 'missing-restart-cleanup' 'Incomplete Hyper-V cleanup evidence for restart-postflush-resume'
    $postflushResume.cleanup_outcome = 'working storage retained by harness'
    $restartProfile.cleanup_ok = $false
    Save-Json $lab $labPath
    Invoke-Gate 'failed-restart-convert-cleanup' 'Incomplete Hyper-V cleanup evidence for restart-convert'
    $null = $restartProfile.Remove('cleanup_ok')
    $restartRefusal = $cases | Where-Object { $_.case_id -eq 'restart-refs-refusal' }
    $restartRefusal.cleanup_outcome = 'working storage cleanup failed'
    Save-Json $lab $labPath
    Invoke-Gate 'failed-restart-refusal-cleanup' 'Incomplete Hyper-V cleanup evidence for restart-refs-refusal'
    $restartRefusal.cleanup_outcome = 'working storage retained by harness'
    $verifyReadOnly = $cases | Where-Object { $_.case_id -eq 'verify-readonly-rollback' }
    $verifyReadOnly.cleanup_ok = $false
    Save-Json $lab $labPath
    Invoke-Gate 'failed-available-boot-cleanup' 'Incomplete Hyper-V cleanup evidence for verify-readonly-rollback'
    $verifyReadOnly.route = 'data'
    Save-Json $lab $labPath
    Invoke-Gate 'relabeled-boot-route' 'Unexpected route for Hyper-V case verify-readonly-rollback'
    $verifyReadOnly.route = 'boot'
    $verifyReadOnly.cleanup_ok = $true
    $lab.cases = $cases | Where-Object { $_.case_id -ne 'verify-readonly-rollback' }
    Save-Json $lab $labPath
    Invoke-Gate 'missing-required-readonly-rollback' 'Missing required Hyper-V gate case verify-readonly-rollback'
    $lab.cases = $cases
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
    $boot.boot.signatures[1].sha256 = $null
    Save-Json $lab $labPath
    Invoke-Gate 'missing-boot-driver-hash' 'Full Windows boot proof is incomplete'
    $boot.boot.signatures[1].sha256 = '2' * 64
    $signatures = $boot.boot.signatures
    $boot.boot.signatures += $signatures[0]
    Save-Json $lab $labPath
    Invoke-Gate 'ambiguous-boot-loader-hash' 'Full Windows boot proof is incomplete'
    $boot.boot.signatures = $signatures

    foreach ($mismatch in @(
        @{ field = 'windows'; value = '26100' },
        @{ field = 'windows_edition'; value = 79 },
        @{ field = 'observed_target_format'; value = 'standard' },
        @{ field = 'observed_target_clusters'; value = 65536 }
    )) {
        $prior = $boot[$mismatch.field]
        $boot[$mismatch.field] = $mismatch.value
        Save-Json $lab $labPath
        Invoke-Gate "wrong-boot-profile-$($mismatch.field)" 'Full Windows boot platform differs from the observed boot'
        $boot[$mismatch.field] = $prior
    }
    $boot.boot.refs_version = '3.15'
    Save-Json $lab $labPath
    Invoke-Gate 'wrong-observed-boot-refs-version' 'Full Windows boot platform differs from the observed boot'
    $boot.boot.refs_version = '3.14'

    $restartCancel = $cases | Where-Object { $_.case_id -eq 'restart-cancel' }
    $restartCancel.working_filesystem = 'ReFS'
    Save-Json $lab $labPath
    Invoke-Gate 'wrong-restart-working-filesystem' 'Restart working filesystem evidence differs'
    $restartCancel.working_filesystem = 'NTFS'

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
        $null = Save-IntegrityHostCrashes -VmId $vm -Started $started -Output $root
        $crashes = Get-Content -LiteralPath (Join-Path $root 'host-guest-crashes.json') -Raw | ConvertFrom-Json -NoEnumerate
        if ($crashes -isnot [array] -or $crashes.Count -ne 1 -or $crashes[0].record -ne 42 -or
            $crashes[0].bugcheck -ne '0x139' -or ([datetimeoffset]$crashes[0].time_utc).UtcDateTime -ne $started.AddSeconds(1) -or
            $crashes[0].xml -notmatch $vm.ToString()) { throw 'Host crash evidence did not isolate the expected VM event' }
    }
    'Release archive, qualification gate, integrity evidence, and platform reporting checks passed.'
} finally {
    $resolved = (Resolve-Path -LiteralPath $root).Path
    if ($resolved -ceq $root -and $resolved.StartsWith($temp, [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
