#Requires -Version 7.2
param(
    [Parameter(Mandatory)][string]$Candidate,
    [Parameter(Mandatory)][string]$Evidence,
    [Parameter(Mandatory)][string]$Tag,
    [Parameter(Mandatory)][string]$Commit,
    [Parameter(Mandatory)][string]$Request,
    [Parameter(Mandatory)][string]$Output
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\NativeRegressionCases.ps1"
. "$PSScriptRoot/SeededSoakPlan.ps1"
. "$PSScriptRoot/../../lab/GateRoundCases.ps1"
. "$PSScriptRoot/../../lab/IntegrityWindowProof.ps1"
function Read-Json([string]$Path) { Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable }
$identity = Read-Json (Join-Path $Candidate 'candidate.json')
$files = 'ntfs2refs.exe', 'ntfs2refs-recovery.exe', 'lab-volume-manifest.exe'
if ($identity.schema -ne 1 -or $identity.tag -cne $Tag -or $identity.commit -cne $Commit -or $identity.request -cne $Request -or $identity.hashes.Count -ne $files.Count) {
    throw 'Signed candidate identity differs from the release request'
}
foreach ($file in $files) {
    if ((Get-FileHash -LiteralPath (Join-Path $Candidate "bin/$file")).Hash.ToLowerInvariant() -cne $identity.hashes[$file]) { throw "Signed candidate hash differs for $file" }
}
function Assert-HostedRow($Row, [string]$Label) {
    if ($Row.converter_sha256 -cne $identity.hashes['ntfs2refs.exe'] -or $Row.listing_tool_sha256 -cne $identity.hashes['lab-volume-manifest.exe']) {
        throw "Invalid hosted qualification verdict for $Label"
    }
    Assert-HostedRoundPassed $Row $Label
}
function Assert-SeededSoakVerdict($Row, [string]$Profile) {
    $label = "soak $Profile seed $($Row.seed)"
    if ($Row.scenario -cne 'seeded' -or $null -eq $Row.seed) { throw "Wrong scenario or seed for $label" }
    $plan = Get-SeededSoakPlan $Row.seed $Profile
    if ($Row.verify -cne $plan.verify -or $Row.hold_at -cne $plan.hold_at -or
        $Row.end_after_seconds -ne $plan.end_after_seconds -or $Row.reached_hold -isnot [bool] -or
        $Row.reached_hold -ne [bool]$plan.hold_at -or $Row.terminated -isnot [bool] -or
        ($plan.hold_at -and -not $Row.terminated) -or
        ($Row.terminated -and -not ($plan.hold_at -or $plan.end_after_seconds))) {
        throw "Invalid interruption evidence for $label"
    }

    $validRecovery = if (-not $Row.terminated) {
        # A timer can expire after the converter has already finished.
        $Row.recovery_mode -ceq 'none' -and $Row.outcome -ceq 'converted'
    } elseif ($Profile -eq 'resume') {
        # An early interruption may have written nothing. Resume can return
        # the original NTFS volume in that case.
        $Row.recovery_mode -ceq 'resume' -and $Row.outcome -cin 'converted', 'ntfs-as-before'
    } elseif ($Profile -eq 'rollback') {
        $Row.recovery_mode -ceq 'rollback' -and $Row.outcome -ceq 'ntfs-as-before'
    } else {
        # A timed cancellation follows the command already printed, if any.
        ($Row.recovery_mode -ceq 'resume' -and $Row.outcome -cin 'converted', 'ntfs-as-before') -or
            ($Row.recovery_mode -cin 'none', 'rollback' -and $Row.outcome -ceq 'ntfs-as-before')
    }
    if (-not $validRecovery) { throw "Invalid recovery action or outcome for $label" }
}
$native = @(foreach ($case in $NativeRegressionCases.Keys) {
    $row = Read-Json (Join-Path $Evidence "native-$case/regression.json")
    Assert-HostedRow $row $case
    if ($row.case_id -cne $case) { throw "Wrong case for $case" }
    Assert-NativeRegressionVerdict $case $row
    $null = $row.Remove('recovery')
    $null = $row.Remove('attached_before_cleanup')
    $row
})
$soak = @(foreach ($profile in 'convert', 'many', 'resume', 'rollback', 'cancel') {
    $directory = Join-Path $Evidence "soak-records-$profile"
    $path = Join-Path $directory 'rounds.jsonl'
    $rows = @(Get-Content -LiteralPath $path | ConvertFrom-Json -AsHashtable)
    if ($rows.Count -lt 1) { throw "Missing soak verdicts for $profile" }
    $receipt = Read-Json (Join-Path $directory 'campaign.json')
    if ($receipt.schema -ne 1 -or "$($receipt.workflow_run)-$($receipt.workflow_attempt)" -cne $Request -or
        @($receipt.profiles).Count -ne 1 -or @($receipt.profiles)[0] -cne $profile -or $receipt.minutes -ne 240 -or
        $receipt.round_limit -ne 0 -or $receipt.stop_reason -cne 'duration' -or $receipt.elapsed_seconds -lt (240 * 60) -or
        $receipt.rounds -ne $rows.Count -or $receipt.rows_sha256 -cne (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()) {
        throw "Incomplete or mismatched soak campaign for $profile"
    }
    for ($index = 0; $index -lt $rows.Count; $index++) {
        $row = $rows[$index]
        if ($row.round -ne ($index + 1) -or $row.seed -ne ($receipt.first_seed + $index)) { throw "Missing or reordered soak round for $profile" }
        Assert-HostedRow $row "soak $profile seed $($row.seed)"
        if ($row.profile -cne $profile) { throw "Wrong soak profile for seed $($row.seed)" }
        Assert-SeededSoakVerdict $row $profile
        $null = $row.Remove('recovery')
        $null = $row.Remove('attached_before_cleanup')
        $row
    }
})
$lab = Read-Json (Join-Path $Evidence 'release-lab/lab.json')
if ($lab.failure) { throw "Private Hyper-V qualification failed: $($lab.failure)" }
if ($lab.identity.schema -ne $identity.schema -or $lab.identity.tag -cne $Tag -or $lab.identity.commit -cne $Commit -or $lab.identity.request -cne $Request) {
    throw 'Hyper-V record does not identify this candidate'
}
foreach ($file in $files) {
    if ($lab.identity.hashes[$file] -cne $identity.hashes[$file]) { throw "Hyper-V qualification hash differs for $file" }
}
function Assert-CaseBinaryHash($Row, [string]$Field, [string]$File) {
    if ($Row[$Field] -isnot [string] -or $Row[$Field] -cne $identity.hashes[$File]) {
        throw "Hyper-V case $($Row.case_id) hash differs for $File"
    }
}
$indexed = @{}
foreach ($row in $lab.cases) {
    if (-not $row.case_id -or $indexed.ContainsKey($row.case_id) -or $row.passed -isnot [bool] -or -not $row.passed -or $row.outcome -cne $row.expected) {
        throw "Failed, duplicate or invalid Hyper-V case $($row.case_id)"
    }
    $runningCase = $row.case_id -like 'c-*'
    $restartCase = $row.case_id -like 'restart-*'
    $bootOutcome = $row.outcome -cin 'converted-not-booted', 'RESUMED-NOT-BOOTED', 'ROLLED-BACK-NOT-BOOTED',
        'BOOTED-ON-REFS', 'RESUMED-BOOTED-ON-REFS', 'ROLLED-BACK-BOOTED-ON-NTFS'
    if (($row.route -ceq 'running') -ne $runningCase -or ($row.route -ceq 'restart') -ne $restartCase -or
        ($bootOutcome -and $row.route -cne 'boot')) {
        throw "Unexpected route for Hyper-V case $($row.case_id)"
    }
    Assert-CaseBinaryHash $row 'converter_sha256' 'ntfs2refs.exe'
    if (-not $runningCase) { Assert-CaseBinaryHash $row 'listing_tool_sha256' 'lab-volume-manifest.exe' }
    if ($restartCase) { Assert-CaseBinaryHash $row 'recovery_sha256' 'ntfs2refs-recovery.exe' }
    $cleanupMatches = if ($restartCase) {
        $row.cleanup_outcome -ceq 'working storage retained by harness' -and
            ($null -eq $row.cleanup_ok -or ($row.cleanup_ok -is [bool] -and $row.cleanup_ok))
    } elseif ($row.route -cin 'boot', 'data') {
        $row.cleanup_ok -is [bool] -and $row.cleanup_ok
    } else { $row.cleanup_ok -ne $false }
    if (-not $cleanupMatches) { throw "Incomplete Hyper-V cleanup evidence for $($row.case_id)" }
    $indexed[$row.case_id] = $row
}
$requiredLab = @{
    'fixture10' = 'converted-not-booted'; 'admin-fixture40' = 'converted-not-booted'; 'full-system' = 'BOOTED-ON-REFS'
    'apply-mid-resume' = 'RESUMED-NOT-BOOTED'; 'apply-mid-rollback' = 'ROLLED-BACK-NOT-BOOTED'
    'seal-recorded-resume' = 'RESUMED-NOT-BOOTED'; 'handoff-sealed-resume' = 'RESUMED-NOT-BOOTED'; 'torn-handoff-resume' = 'RESUMED-NOT-BOOTED'
    'vm-verify-passed-rollback' = 'ROLLED-BACK-NOT-BOOTED'
    'vm-thorough-verify-passed-resume' = 'RESUMED-NOT-BOOTED'; 'vm-thorough-verify-passed-rollback' = 'ROLLED-BACK-NOT-BOOTED'
    'lived-in' = 'converted'; 'restart-convert' = 'converted'; 'restart-cancel' = 'cancelled-volume-as-before'
    'restart-refs-refusal' = 'refused-source-unchanged'
    'restart-postflush-resume' = 'resumed'; 'restart-postflush-rollback' = 'rolled-back'
    'restart-w11-postflush-resume' = 'resumed'; 'restart-w11-postflush-rollback' = 'rolled-back'
    'integrity-native-idle' = 'control-passed'; 'integrity-native-loaded' = 'control-passed'
    'integrity-converted-idle' = 'converted'; 'integrity-converted-loaded' = 'converted'; 'integrity-lived-in' = 'converted'
    'integrity-event-131' = 'converted'
}
foreach ($case in $requiredLab.Keys) {
    if (-not $indexed.ContainsKey($case)) { throw "Missing required Hyper-V case $case" }
    $row = $indexed[$case]
    if ($row.outcome -cne $requiredLab[$case] -or ($row.outcome -ne 'control-passed' -and $row.manifest -cne 'identical')) {
        throw "Wrong outcome or manifest for Hyper-V case $case"
    }
    if ($case -like 'integrity-*') {
        $scope = $row.integrity_event_scope
        $start = [datetimeoffset]::MinValue
        $end = [datetimeoffset]::MinValue
        $partition = [guid]::Empty
        if ($row.reboot_use -ne $true -or $row.cleanup_ok -ne $true -or
            ($row.guest_bugchecks -isnot [int] -and $row.guest_bugchecks -isnot [long]) -or $row.guest_bugchecks -ne 0 -or
            $scope -isnot [Collections.IDictionary] -or $scope.completed -isnot [bool] -or !$scope.completed -or
            -not [guid]::TryParse([string]$scope.partition, [ref]$partition) -or $partition -eq [guid]::Empty -or
            -not ($scope.aliases -match '^\\\\\?\\Volume\{[0-9a-f-]{36}\}[\\]?$') -or
            -not [datetimeoffset]::TryParse($scope.started_utc, [ref]$start) -or
            -not [datetimeoffset]::TryParse($scope.ended_utc, [ref]$end) -or $end -lt $start -or
            $row.integrity_events -isnot [Collections.IList] -or
            @(Get-RefsIntegrityFailures $row.integrity_events @($scope.aliases) @($scope.other_aliases)).Count) {
            throw "Incomplete integrity evidence for Hyper-V case $case"
        }
    }
    if ($case -eq 'integrity-event-131') { Assert-Integrity131Case $row }
    if ($case -in 'integrity-native-loaded', 'integrity-converted-loaded', 'integrity-lived-in') {
        Assert-IntegrityLoadWindows $row $case
    }
}
$gateCases = Get-GateRoundExpectations @('fixtures', 'data', 'full', 'server', 'running')
foreach ($case in $gateCases.Keys) {
    if (-not $indexed.ContainsKey($case)) { throw "Missing required Hyper-V gate case $case" }
    $row = $indexed[$case]
    if ($row.outcome -cne $gateCases[$case] -or $row.route -cne (Get-GateRoundCaseRoute $case)) {
        throw "Wrong outcome or route for Hyper-V gate case $case"
    }
    if ($transformationRecoveryCases.Contains($case)) {
        $action = if ($gateCases[$case] -eq 'rolled-back') { 'rollback' } else { 'resume' }
        $report = $row.plain_report_fault
        if ($row.hold -cne 'apply-mid-ranges' -or $row.reached_hold -ne $true -or
            $row.interruption -cne 'process-termination' -or $row.recovery -cne $action -or
            $row.cleanup_ok -ne $true -or $row.manifest -cne 'identical' -or ($action -eq 'rollback' -and $row.exact_manifest -ne $true) -or
            $report.original_sha256 -notmatch '^[a-f0-9]{64}$' -or $report.damaged_sha256 -notmatch '^[a-f0-9]{64}$' -or
            $report.original_sha256 -eq $report.damaged_sha256 -or $report.worker_sha256 -cne $row.converter_sha256) {
            throw "Incomplete transformation recovery evidence for Hyper-V case $case"
        }
    }
}
$requiredRecovery = @{
    'apply-mid-resume' = @('fast', 'apply-mid-ranges', 'process-termination', 'resume')
    'apply-mid-rollback' = @('fast', 'apply-mid-ranges', 'process-termination', 'rollback')
    'seal-recorded-resume' = @('fast', 'apply-seal-recorded', 'process-termination', 'resume')
    'handoff-sealed-resume' = @('fast', 'handoff-sealed', 'process-termination', 'resume')
    'torn-handoff-resume' = @('fast', 'verify-passed', 'process-termination', 'resume')
    'vm-verify-passed-rollback' = @('fast', 'verify-passed', 'vm-turned-off', 'rollback')
    'vm-thorough-verify-passed-resume' = @('thorough', 'verify-passed', 'vm-turned-off', 'resume')
    'vm-thorough-verify-passed-rollback' = @('thorough', 'verify-passed', 'vm-turned-off', 'rollback')
    'restart-cancel' = @('fast', 'restart-after-arm', 'injected failure', 'rollback')
    'restart-postflush-resume' = @('fast', 'winpe-postflush-before-discovery', 'vm-turned-off', 'resume')
    'restart-postflush-rollback' = @('fast', 'winpe-postflush-before-discovery', 'vm-turned-off', 'rollback')
    'restart-w11-postflush-resume' = @('fast', 'winpe-postflush-before-discovery', 'vm-turned-off', 'resume')
    'restart-w11-postflush-rollback' = @('fast', 'winpe-postflush-before-discovery', 'vm-turned-off', 'rollback')
}
foreach ($case in 'restart-postflush-resume', 'restart-postflush-rollback', 'restart-w11-postflush-resume', 'restart-w11-postflush-rollback') {
    $row = $indexed[$case]; $proof = $row.postflush
    if ($row.route -cne 'restart' -or $row.working_filesystem -cne 'NTFS' -or -not $row.boot.boot_utc -or
        $proof.native_bytes_written -le 0 -or $proof.delayed_discovery_bytes -ne 4096 -or
        $proof.flush_and_pending_readback_succeeded -ne $true -or $proof.native_writer_revalidation_succeeded -ne $true -or
        $proof.discovery_write_not_requested -ne $true -or $proof.released -ne $false -or
        ($case -eq 'restart-postflush-resume' -and $row.prompt_wait_seconds -lt 185)) {
        throw "Incomplete durable WinPE write evidence for $case"
    }
    if ($case -like 'restart-w11-*' -and ($row.windows -ne 26300 -or -not $row.windows_edition -or $null -eq $row.windows_revision)) {
        throw "Incomplete Windows 11 fixture profile for $case"
    }
}
foreach ($case in $requiredRecovery.Keys) {
    $row = $indexed[$case]
    $mode, $hold, $kind, $action = $requiredRecovery[$case]
    if ($row.verify -cne $mode -or $row.hold -cne $hold -or $row.reached_hold -ne $true -or
        $row.interruption -cne $kind -or $row.recovery -cne $action -or
        ($row.outcome -eq 'ROLLED-BACK-NOT-BOOTED' -and $row.exact_manifest -ne $true)) {
        throw "Incomplete recovery evidence for Hyper-V case $case"
    }
}
if ($indexed['torn-handoff-resume'].simulated_torn_marker -ne $true -or $indexed['torn-handoff-resume'].torn_marker_settled -ne $true) {
    throw 'Incomplete torn handoff evidence'
}
if ($indexed['restart-convert'].working_filesystem -cne 'NTFS' -or $indexed['restart-cancel'].working_filesystem -cne 'NTFS') {
    throw 'Restart working filesystem evidence differs'
}
if ($indexed['restart-refs-refusal'].working_filesystem -cne 'ReFS' -or $indexed['restart-refs-refusal'].scratch_refusal -ne $true) {
    throw 'Incomplete ReFS working storage refusal evidence'
}
$boot = $indexed['full-system']
if ($boot.manifest -cne 'identical' -or $boot.outcome -notmatch 'BOOTED-ON-REFS$' -or $boot.refs -ne '3.14' -or
    $boot.boot.filesystem -ne 'ReFS' -or $boot.boot.disk -ne 0 -or @($boot.boot.disks).Count -ne 1 -or $boot.boot.partition -ne 3 -or $boot.boot.cluster_bytes -ne 4096 -or -not $boot.boot.secure_boot) { throw 'Full Windows boot proof is incomplete' }
$bootComponents = [ordered]@{ 'System32\winload.efi' = 'winload_efi_sha256'; 'System32\drivers\refs.sys' = 'refs_sys_sha256' }
$bootFiles = [ordered]@{}
foreach ($file in $bootComponents.Keys) {
    $items = @($boot.boot.signatures | Where-Object file -CEQ $file)
    if ($items.Count -ne 1 -or $items[0].status -cne 'Valid' -or
        $items[0].signer -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)' -or $items[0].sha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw "Full Windows boot proof is incomplete for $file"
    }
    $bootFiles[$bootComponents[$file]] = $items[0].sha256
}
if ($boot.route -cne 'boot' -or [string]$boot.windows -cne [string]$boot.boot.build -or
    $boot.windows_edition -ne $boot.boot.windows_edition -or $boot.refs -cne $boot.boot.refs_version -or
    $boot.observed_target_clusters -ne $boot.boot.cluster_bytes -or $boot.observed_target_format -cne 'dev-drive') {
    throw 'Full Windows boot platform differs from the observed boot'
}

$recoveryCases = @(foreach ($row in $lab.cases | Where-Object { $_.interruption } | Sort-Object { $_.route }, { $_.verify }, { $_.case_id }) {
    $kind = if ($row.simulated_torn_marker) { "$($row.interruption), simulated torn marker" } else { $row.interruption }
    @{
        suite = 'Hyper-V'; case_id = $row.case_id; route = $row.route; verify = $row.verify
        requested_hold = $row.hold; reached_hold = if ($row.reached_hold) { $row.hold }
        interruption = $kind; recovery = $row.recovery; outcome = $row.outcome
        manifest = $row.manifest; exact_manifest = $row.exact_manifest
        boot = $row.boot; cleanup_ok = $row.cleanup_ok; cleanup_outcome = $row.cleanup_outcome
        postflush = $row.postflush; prompt_wait_seconds = $row.prompt_wait_seconds; torn_marker_settled = $row.torn_marker_settled
    }
})
foreach ($suite in 'deterministic', 'soak') {
    $verdicts = if ($suite -eq 'deterministic') { $native } else { $soak }
    $recoveryCases += @(foreach ($row in $verdicts | Where-Object terminated) {
        @{
            suite = $suite; case_id = if ($suite -eq 'deterministic') { $row.case_id } else { "$($row.profile) seed $($row.seed)" }
            route = 'data'; verify = $row.verify; requested_hold = $row.hold_at
            reached_hold = if ($row.reached_hold) { $row.hold_at }
            interruption = if ($row.end_after_seconds -gt 0 -and -not $row.hold_at) { "process termination ($($row.end_after_seconds) s timer)" } else { 'process termination' }
            recovery = $row.recovery_mode; outcome = $row.outcome
            manifest = if ($row.manifest_matches) { 'identical' }
            cleanup_ok = $row.cleanup_ok
        }
    })
}
$profiles = @(foreach ($row in $lab.cases | Sort-Object { $_.case_id }) {
    if ($row.route -notin 'data', 'boot', 'restart', 'running' -or $row.outcome -notin 'converted', 'resumed', 'BOOTED-ON-REFS' -or
        $row.manifest -cne 'identical' -or "$($row.windows)" -notmatch '^\d+$' -or -not $row.windows_edition -or
        $row.refs -notmatch '^\d+\.\d+$' -or $row.observed_target_format -notin 'standard', 'dev-drive' -or
        $row.observed_target_clusters -notin 4096, 65536) { continue }
    $profile = @{
        case_id = $row.case_id; route = $row.route; windows_build = [uint32]$row.windows
        windows_edition = [uint32]$row.windows_edition; refs_version = $row.refs
        target_format = $row.observed_target_format; target_cluster_bytes = [uint32]$row.observed_target_clusters
    }
    if ($row.case_id -ceq 'full-system') { $profile.boot_files = $bootFiles }
    $profile
})
foreach ($case in 'full-system', 'restart-w11-postflush-resume') {
    if ($case -cnotin $profiles.case_id) { throw "Missing observed platform profile for $case" }
}
$requiredDataProfiles = [ordered]@{
    'lived-in' = @(26300, 48, 'dev-drive', 4096)
    'lived-in-64k' = @(26300, 48, 'dev-drive', 65536)
    'std-4k' = @(26100, 79, 'standard', 4096)
    'std-64k' = @(26100, 79, 'standard', 65536)
    'devdrive' = @(26100, 79, 'dev-drive', 4096)
}
foreach ($case in $requiredDataProfiles.Keys) {
    $observed = $profiles | Where-Object case_id -CEQ $case
    if (-not $observed) { throw "Missing observed platform profile for $case" }
    $build, $edition, $format, $cluster = $requiredDataProfiles[$case]
    if ($observed.route -cne 'data' -or $observed.windows_build -ne $build -or $observed.windows_edition -ne $edition -or
        $observed.refs_version -cne '3.14' -or $observed.target_format -cne $format -or $observed.target_cluster_bytes -ne $cluster) {
        throw "Observed platform profile differs for $case"
    }
}
$record = @{ schema = 1; candidate = $identity; deterministic = $native; soak = $soak; hyper_v = $lab.cases; recovery = $recoveryCases; profiles = $profiles }
$null = New-Item -ItemType Directory -Path $Output
$record | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath (Join-Path $Output 'QUALIFICATION.json') -Encoding utf8
$lines = @(
    '## Native qualification', '',
    "Candidate ``$Tag`` from ``$Commit`` passed $($native.Count) deterministic native cases, $($soak.Count) seeded soak rounds, and $($lab.cases.Count) Hyper-V cases.", '',
    'The three executable hashes, per-case manifest results, platform details, and filesystem findings are in `QUALIFICATION.json`.', '',
    'Data and developer volumes passed continued allocation, deletion, remount, and reboot tests. The installed Windows volume reached the desktop on ReFS 3.14 with Secure Boot enabled.', '',
    'The matched ReFS controls passed. The 4,000-entry lived-in case with a preflight check passed with host CPU activity observed during fill and deletion and during remount. The cause of the original ReFS event 131 in [#253](https://github.com/faratech/ntfs2refs/issues/253) remains unresolved.', '',
    'Physical disks and actual storage-power loss are unqualified.', '',
    '### Exercised platform profiles', '',
    'Windows edition is reported as its operating-system SKU. Restart cases identify the Windows installation that receives the converted partition after WinPE returns. Candidate coverage is limited to the observed combinations listed below.', '',
    '| Case | Route | Windows build | Windows SKU | Format | ReFS version | Bytes per cluster |',
    '|---|---|---|---|---|---|---|'
)
foreach ($row in $profiles) {
    $lines += "| $($row.case_id) | $($row.route) | $($row.windows_build) | $($row.windows_edition) | $($row.target_format) | $($row.refs_version) | $($row.target_cluster_bytes) |"
}
$lines += @(
    '', '### Recovery cases', '',
    'The WinPE post-flush cases cut VM power after data writes were flushed and read back, before the discovery write. Combinations without a row are unqualified. A dash means the runner did not record that field or it did not apply.', '',
    '| Suite | Case | Route | Verification | Requested hold | Reached hold | Interruption | Recovery | Outcome | Manifest | Boot | Cleanup |',
    '|---|---|---|---|---|---|---|---|---|---|---|---|'
)
foreach ($row in $recoveryCases) {
    $bootResult = if ($row.boot.filesystem) { $row.boot.filesystem } elseif ($row.outcome -match 'NOT-BOOTED$') { 'not booted' }
    $manifest = if ($row.exact_manifest -eq $true) { "$($row.manifest) (exact)" } else { $row.manifest }
    $cleanup = if ($row.cleanup_ok -eq $true) { 'passed' } elseif ($row.cleanup_ok -eq $false) { 'failed' } else { $row.cleanup_outcome }
    $cells = $row.suite, $row.case_id, $row.route, $row.verify, $row.requested_hold, $row.reached_hold,
        $row.interruption, $row.recovery, $row.outcome, $manifest, $bootResult, $cleanup
    $rendered = foreach ($cell in $cells) { if ($cell -eq '' -or $null -eq $cell) { '-' } else { $cell } }
    $lines += '| ' + ($rendered -join ' | ') + ' |'
}
$lines | Set-Content -LiteralPath (Join-Path $Output 'QUALIFICATION.md') -Encoding utf8
