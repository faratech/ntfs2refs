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
    if ($Row.converter_sha256 -cne $identity.hashes['ntfs2refs.exe'] -or $Row.listing_tool_sha256 -cne $identity.hashes['lab-volume-manifest.exe'] -or
        $Row.outcome -notin 'converted', 'ntfs-as-before' -or -not $Row.manifest_matches -or -not $Row.cleanup_ok -or
        ($Row.hold_at -and -not $Row.reached_hold) -or ($Row.outcome -eq 'converted' -and -not $Row.refs_version) -or
        @($Row.events | Where-Object { $_.provider -match 'ReFS' -and $_.id -in 131, 134 }).Count) {
        throw "Invalid hosted qualification verdict for $Label"
    }
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
    $path = Join-Path $Evidence "soak-records-$profile/rounds.jsonl"
    $rows = @(Get-Content -LiteralPath $path | ConvertFrom-Json -AsHashtable)
    if ($rows.Count -lt 1) { throw "Missing soak verdicts for $profile" }
    foreach ($row in $rows) {
        Assert-HostedRow $row "soak $profile seed $($row.seed)"
        if ($row.profile -cne $profile) { throw "Wrong soak profile for seed $($row.seed)" }
        $null = $row.Remove('recovery')
        $null = $row.Remove('attached_before_cleanup')
        $row
    }
})
$lab = Read-Json (Join-Path $Evidence 'release-lab/lab.json')
if ($lab.identity.schema -ne $identity.schema -or $lab.identity.tag -cne $Tag -or $lab.identity.commit -cne $Commit -or $lab.identity.request -cne $Request) {
    throw 'Hyper-V record does not identify this candidate'
}
foreach ($file in $files) {
    if ($lab.identity.hashes[$file] -cne $identity.hashes[$file]) { throw "Hyper-V qualification hash differs for $file" }
}
$indexed = @{}
foreach ($row in $lab.cases) {
    if (-not $row.case_id -or $indexed.ContainsKey($row.case_id) -or -not $row.passed -or $row.outcome -cne $row.expected) { throw "Failed, duplicate or invalid Hyper-V case $($row.case_id)" }
    $indexed[$row.case_id] = $row
}
$requiredLab = @{
    'fixture10' = 'converted-not-booted'; 'admin-fixture40' = 'converted-not-booted'; 'full-system' = 'BOOTED-ON-REFS'
    'apply-mid-resume' = 'RESUMED-NOT-BOOTED'; 'apply-mid-rollback' = 'ROLLED-BACK-NOT-BOOTED'
    'seal-recorded-resume' = 'RESUMED-NOT-BOOTED'; 'handoff-sealed-resume' = 'RESUMED-NOT-BOOTED'; 'torn-handoff-resume' = 'RESUMED-NOT-BOOTED'
    'vm-verify-passed-rollback' = 'ROLLED-BACK-NOT-BOOTED'; 'vm-thorough-handoff-resume' = 'RESUMED-NOT-BOOTED'
    'lived-in' = 'converted'; 'restart-convert' = 'converted'; 'restart-cancel' = 'cancelled-volume-as-before'
    'restart-refs-refusal' = 'refused-source-unchanged'
    'restart-postflush-resume' = 'resumed'; 'restart-postflush-rollback' = 'rolled-back'
    'restart-w11-postflush-resume' = 'resumed'; 'restart-w11-postflush-rollback' = 'rolled-back'
    'integrity-native-idle' = 'control-passed'; 'integrity-native-loaded' = 'control-passed'
    'integrity-converted-idle' = 'converted'; 'integrity-converted-loaded' = 'converted'; 'integrity-lived-in' = 'converted'
}
foreach ($case in $requiredLab.Keys) {
    if (-not $indexed.ContainsKey($case)) { throw "Missing required Hyper-V case $case" }
    $row = $indexed[$case]
    if ($row.outcome -cne $requiredLab[$case] -or ($row.outcome -ne 'control-passed' -and $row.manifest -cne 'identical')) {
        throw "Wrong outcome or manifest for Hyper-V case $case"
    }
    if ($case -like 'integrity-*' -and ($row.reboot_use -ne $true -or $row.cleanup_ok -ne $true -or
        $null -eq $row.integrity_events -or @($row.integrity_events | Where-Object { $_.provider -match 'ReFS' -and $_.id -in 131, 134 }).Count)) {
        throw "Incomplete integrity evidence for Hyper-V case $case"
    }
}
$requiredRecovery = @{
    'apply-mid-resume' = @('fast', 'apply-mid-ranges', 'process-termination', 'resume')
    'apply-mid-rollback' = @('fast', 'apply-mid-ranges', 'process-termination', 'rollback')
    'seal-recorded-resume' = @('fast', 'apply-seal-recorded', 'process-termination', 'resume')
    'handoff-sealed-resume' = @('fast', 'handoff-sealed', 'process-termination', 'resume')
    'torn-handoff-resume' = @('fast', 'verify-passed', 'process-termination', 'resume')
    'vm-verify-passed-rollback' = @('fast', 'verify-passed', 'vm-turned-off', 'rollback')
    'vm-thorough-handoff-resume' = @('thorough', 'apply-handoff-durable', 'vm-turned-off', 'resume')
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
$validBootFiles = @($boot.boot.signatures | Where-Object { $_.status -eq 'Valid' -and $_.signer -match '(?:^|,\s*)O=Microsoft Corporation(?:,|$)' } | ForEach-Object file)
if ($boot.manifest -cne 'identical' -or $boot.outcome -notmatch 'BOOTED-ON-REFS$' -or $boot.refs -ne '3.14' -or
    $boot.boot.filesystem -ne 'ReFS' -or $boot.boot.disk -ne 0 -or @($boot.boot.disks).Count -ne 1 -or $boot.boot.partition -ne 3 -or $boot.boot.cluster_bytes -ne 4096 -or -not $boot.boot.secure_boot -or
    'System32\winload.efi' -notin $validBootFiles -or 'System32\drivers\refs.sys' -notin $validBootFiles) { throw 'Full Windows boot proof is incomplete' }

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
    @{
        case_id = $row.case_id; route = $row.route; windows_build = [uint32]$row.windows
        windows_edition = [uint32]$row.windows_edition; refs_version = $row.refs
        target_format = $row.observed_target_format; target_cluster_bytes = [uint32]$row.observed_target_clusters
    }
})
foreach ($case in 'full-system', 'lived-in', 'restart-w11-postflush-resume') {
    if ($case -cnotin $profiles.case_id) { throw "Missing observed platform profile for $case" }
}
$record = @{ schema = 1; candidate = $identity; deterministic = $native; soak = $soak; hyper_v = $lab.cases; recovery = $recoveryCases; profiles = $profiles }
$null = New-Item -ItemType Directory -Path $Output
$record | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath (Join-Path $Output 'QUALIFICATION.json') -Encoding utf8
$lines = @(
    '## Native qualification', '',
    "Candidate ``$Tag`` from ``$Commit`` passed $($native.Count) deterministic native cases, $($soak.Count) seeded soak rounds, and $($lab.cases.Count) Hyper-V cases.", '',
    'The three executable hashes, per-case manifest results, platform details, and filesystem findings are in `QUALIFICATION.json`.', '',
    'Data and developer volumes passed continued allocation, deletion, remount, and reboot tests. The installed Windows volume reached the desktop on ReFS 3.14 with Secure Boot enabled.', '',
    'The matched ReFS controls passed. The cause of the original ReFS event 131 in [#253](https://github.com/faratech/ntfs2refs/issues/253) remains unresolved.', '',
    'Physical disks and actual storage-power loss are unqualified.', '',
    '### Exercised platform profiles', '',
    'Windows edition is reported as its operating-system SKU. Restart cases identify the Windows installation that receives the converted partition after WinPE returns. Only cases with complete observations are listed.', '',
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
