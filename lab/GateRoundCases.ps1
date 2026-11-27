# The native lab and archive verifier require the same declared gate cases.
param([int]$MaxVmGB = 24)

# What each case is expected to end as follows from how it is run.
function Get-ExpectedBootOutcome([hashtable]$arguments) {
    if ($arguments.ContainsKey('InterruptAt')) {
        if ($arguments['RecoverMode'] -eq 'rollback') { return 'ROLLED-BACK-NOT-BOOTED' }
        return 'RESUMED-NOT-BOOTED'
    }
    if ($arguments.ContainsKey('NoBoot')) { return 'converted-not-booted' }
    return 'BOOTED-ON-REFS'
}
function Get-ExpectedDataOutcome([string]$arguments) {
    if ($arguments -match '-ExpectRefusal\b') { return 'refused-as-expected' }
    if ($arguments -match '-Tamper\b') { return 'review-tampered-both-refused' }
    if ($arguments -match '-PowerOffDuringPreparation\b') { return 'preparation-cancelled-after-power-off' }
    if ($arguments -match '-StopDuringPreparation\b') { return 'preparation-cancelled' }
    if ($arguments -match '-Diagnose\b') { return 'diagnose-clean' }
    # A run that stopped for review and was then committed or rolled back
    # ends as one that was interrupted and recovered.
    if ($arguments -match '-(InterruptAt|Review)\b') {
        if ($arguments -match '-RecoverMode\s+rollback\b') { return 'rolled-back' }
        return 'resumed'
    }
    return 'converted'
}

$fixture40 = @{ Fixture = $true; FixtureCheckpoint = 'N2R-Thinned-Fixture-40'; NoBoot = $true }
$fixtureRuns = @(
    @{ Name = 'fixture10'; Arguments = @{ Fixture = $true; NoBoot = $true } }
    @{ Name = 'admin-fixture40'; Arguments = $fixture40 + @{ RunAs = 'administrator' } }
    @{ Name = 'apply-mid-resume'; Arguments = $fixture40 + @{ InterruptAt = 'apply-mid-ranges' } }
    @{ Name = 'apply-mid-rollback'; Arguments = $fixture40 + @{ InterruptAt = 'apply-mid-ranges'; RecoverMode = 'rollback' } }
    @{ Name = 'handoff-sealed-resume'; Arguments = $fixture40 + @{ InterruptAt = 'handoff-sealed' } }
    # --verify fast (the default) seals the volume under the apply marker and
    # verifies it before the handoff (#148, #110): ended there, it resumes to
    # ReFS, and rolled back from the read-only verification mount it has to
    # pass the check of the restored NTFS against the source's fingerprint.
    @{ Name = 'seal-recorded-resume'; Arguments = $fixture40 + @{ InterruptAt = 'apply-seal-recorded' } }
    @{ Name = 'verify-readonly-rollback'; Arguments = $fixture40 + @{ InterruptAt = 'verify-source-readonly'; RecoverMode = 'rollback' } }
    # The handoff marker torn as the finalizer writes it, after the verification
    # passed, with the disk sealed (#1, #148): the recovery has to report it,
    # settle it as not written, verify again and hand off.
    @{ Name = 'torn-handoff-resume'; Arguments = $fixture40 + @{ InterruptAt = 'verify-passed'; TearMarker = 'handoff' } }
    @{ Name = 'vm-verify-passed-rollback'; Arguments = $fixture40 + @{ InterruptAt = 'verify-passed'; InterruptKind = 'vm'; RecoverMode = 'rollback' } }
    @{ Name = 'vm-thorough-verify-passed-resume'; Arguments = $fixture40 + @{ InterruptAt = 'verify-passed'; InterruptKind = 'vm'; Verify = 'thorough' } }
    @{ Name = 'vm-thorough-verify-passed-rollback'; Arguments = $fixture40 + @{ InterruptAt = 'verify-passed'; InterruptKind = 'vm'; RecoverMode = 'rollback'; Verify = 'thorough' } }
)
$fullRun = @{ Name = 'full-system'; Arguments = @{ MemoryGB = $MaxVmGB } }

$lived = '-Content lived-in -DirectoryEntries 4000'
$scratchFixture = '-Content mixed -PartitionMB 8192 -TargetClusterBytes 4096'
$dataCases = @(
    'plain|-Check'
    'standard-win11-refused|-Content minimal -PartitionMB 8192 -TargetFormat standard -TargetClusterBytes 4096 -Check -ExpectRefusal format'
    'standard-win11-64k-refused|-Content minimal -PartitionMB 8192 -TargetFormat standard -TargetClusterBytes 65536 -Check -ExpectRefusal format'
    "lived-in|$lived -Check -Acceptance"
    '512-to-4k|-ClusterBytes 512 -Check -Acceptance'
    '512-to-64k|-ClusterBytes 512 -TargetClusterBytes 65536 -Check'
    '4kn-4k|-SectorBytes 4096 -Check'
    '4kn-64k-to-64k|-SectorBytes 4096 -ClusterBytes 65536 -TargetClusterBytes 65536 -Check'
    "lived-in-64k|$lived -TargetClusterBytes 65536 -Check -Acceptance"
    "lived-in-512|$lived -ClusterBytes 512 -Check"
    'odd-size|-PartitionMB 51237 -Check'
    'small-8g|-PartitionMB 8192 -Check'
    "scratch-standard|$scratchFixture"
    "scratch-minimized|$scratchFixture -ConverterArgs --minimize-scratch"
    "scratch-minimized-resume|$scratchFixture -ConverterArgs --minimize-scratch -InterruptAt apply-mid-ranges"
    "scratch-minimized-rollback|$scratchFixture -ConverterArgs --minimize-scratch -InterruptAt apply-mid-ranges -RecoverMode rollback"
    'many-20k|-Content many -Islands 20000 -Check'
    'files-20k|-Content minimal -Features manyfiles -FileCount 20000 -Check'
    # Held to the memory the estimate asks for it: what the run holds only
    # to go faster is given up on the way.
    'files-20k-limit|-Content minimal -Features manyfiles -FileCount 20000 -ConverterArgs --memory-limit=480'
    # Neither short of memory nor with plenty, and held to a time: a change
    # that made such a run twice as slow (945 s for 481 s, issue 161) passed
    # every other case, because none has this much memory for its volume.
    # It takes about nine minutes.
    'files-100k-mid|-Content minimal -Features manyfiles -FileCount 100000 -ConverterArgs --memory-limit=1240 -TimeoutMinutes 14'
    '4k-admin|-RunAs administrator -Check'
    'shared|-Siblings -Check -Acceptance'
    "shared-lived-in|-Siblings $lived -Check"
    "lived-in-apply-mid-resume|$lived -InterruptAt apply-mid-ranges -Check"
    "lived-in-apply-mid-rollback|$lived -InterruptAt apply-mid-ranges -RecoverMode rollback -Check"
    "lived-in-handoff-sealed-resume|$lived -InterruptAt handoff-sealed -Check"
    # The holds of a fast run between its seal and its handoff (#148): sealed
    # but not yet recorded (replayed), recorded (verified, not replayed),
    # mounted read-only for the verification, and verified but not yet
    # handed off; each resumed or rolled back.
    "lived-in-sealed-resume|$lived -InterruptAt apply-sealed -Check"
    "lived-in-seal-recorded-rollback|$lived -InterruptAt apply-seal-recorded -RecoverMode rollback -Check"
    "lived-in-verify-readonly-resume|$lived -InterruptAt verify-source-readonly -Check"
    "lived-in-verify-passed-rollback|$lived -InterruptAt verify-passed -RecoverMode rollback -Check"
    # New --verify thorough conversions also verify before handoff (#277),
    # keeping rollback open through final verification.
    "thorough|$lived -Verify thorough -Check"
    "thorough-verify-passed-resume|$lived -Verify thorough -InterruptAt verify-passed -Check"
    "thorough-verify-passed-rollback|$lived -Verify thorough -InterruptAt verify-passed -RecoverMode rollback -Check"
    'shared-apply-rollback|-Siblings -InterruptAt apply-mid-ranges -RecoverMode rollback -Check'
    "stop-supply-cancel|$lived -StopDuringPreparation payload_supply"
    "stop-journal-cancel|$lived -StopDuringPreparation recovery_journal"
    "lived-in-diagnose|$lived -Diagnose"
    "lived-in-listing|$lived -CompareListing"
    "lived-in-recheck|$lived -ConverterArgs --recheck-everything"
    'wide-drop|-Content minimal -Features shortnames-wide -DropShortNames -Check -Acceptance'
    'objectids|-Content minimal -Features objectids -Check'
    'security|-Content minimal -Features security -Check'
    'ea|-Content minimal -Features ea -Check'
    'links|-Content minimal -Features links -Check'
    'bigdir|-Content minimal -Features bigdir -Check'
    'casemark|-Content minimal -Features casemark -Check'
    # No casemark-root here: Windows 11 marks only an empty directory, and a
    # mounted root always holds System Volume Information (0x91), so the
    # feature is never made (g3a, w39a, w39b). The Server set keeps its case.
    # What the Windows Subsystem for Linux leaves on a volume, and names
    # that Win32 does not take and the file systems hold.
    'wsl|-Content minimal -Features wsl -Check'
    # Converted to plain once their list is agreed: the TEMPORARY and
    # OFFLINE attributes are cleared, each object is held by the content
    # verdict, and the ledger names exactly what was planted. Unattended,
    # with the checksum the check printed.
    'temporary|-Content minimal -Features temporary -Check -AcceptPlain -Unattended'
    'offline|-Content minimal -Features offline -Check -AcceptPlain'
    # WOF files of every algorithm, made plain from their copies.
    'wof-plain|-Content minimal -Features wof -Check -AcceptPlain -Unattended'
    # EFS: decrypted by the account that encrypted it (-RunAs administrator,
    # the account the features are made as); as SYSTEM, which holds no key,
    # refused by name before anything is changed.
    'efs-plain|-Content minimal -Features efs -Check -AcceptPlain -Unattended -RunAs administrator'
    'efs-nokey|-Content minimal -Features efs -AcceptPlain -ExpectRefusal no.EFS.key'
    # Cloud placeholders of the lab's own provider (lab-cloud-provider.exe beside
    # lab-volume-manifest.exe in the build): with it running, those not on the
    # device are downloaded before the freeze and all made plain; with it stopped,
    # refused by name before anything is changed.
    # (As the account the provider runs as: a Cloud Files provider serves
    # the user who runs it, and the feature step starts it as the
    # harness's account.)
    'cloud-plain|-Content minimal -Features cloud -Check -AcceptPlain -Unattended -RunAs administrator'
    'cloud-down|-Content minimal -Features cloud-down -Check -AcceptPlain -Unattended -ExpectRefusal leave-out-cloud'
    # The same, with leaving the two out agreed: it converts without them.
    'cloud-down-leave-out|-Content minimal -Features cloud-down -Check -AcceptPlain -Unattended -LeaveOutCloud'
    # Data Deduplication: on ntfs2refs-server2025 only, which has the filter
    # (its -VmId and -CredentialPath); a Windows 11 VM cannot plant it.
    # System Volume Information below its own folders (written as SYSTEM):
    # not carried over, each object recorded in the ledger.
    'svi-deep|-Content minimal -Features svi-deep -Check'
    'names|-Content minimal -Features names -Check'
    # MBR disks: the volume alone on one, the working directory on one, both
    # with a run interrupted half way through the writes and resumed; and a
    # volume that shares an MBR disk, which converts with the volume beside
    # it offline for the run.
    'mbr-src|-SourceMbr -Check'
    'mbr-work|-WorkingMbr -Check'
    'mbr-apply-mid-resume|-SourceMbr -WorkingMbr -InterruptAt apply-mid-ranges'
    'mbr-beside|-SourceMbr -MbrBeside -Check'
    # The machine turned off while the converter prepares, then the
    # cancellation in the Windows that starts again.
    "power-off-supply-cancel|$lived -StopDuringPreparation payload_supply -PowerOffDuringPreparation"
    # Memory taken away from a run that fits itself to the machine: it has
    # to go on and convert.
    'files-100k-memory-taken|-Content minimal -Features manyfiles -FileCount 100000 -TakeMemoryMB 3000 -TimeoutMinutes 25'
    # Short names: dropped by default, after the check and the question
    # have said how many; refused only when asked.
    'shortnames|-Content minimal -Features shortnames -Check -Acceptance'
    'shortnames-refuse|-Content minimal -Features shortnames -RefuseShortNames -Check -ExpectRefusal short-names.refuse'
    # Quotas enforced, with an entry for one user: recorded, not carried
    # over, and said by the check and the run.
    'quota|-Content minimal -Features quota -Check -Acceptance'
    # --review (#110): the run stops with the volume mounted read-only as
    # ReFS, listing as before; the command it printed then keeps the
    # conversion, or puts NTFS back (compared exactly, and the recovery has
    # to record that it held the volume to the source's fingerprint).
    "review-commit|$lived -Review -Check -Acceptance"
    "review-rollback|$lived -Review -RecoverMode rollback"
    # Written to after the stop: both commands have to be refused, the one
    # the case is named for first, with the disk left offline and read-only
    # and no byte of the partition changed. (8 GiB, because the harness
    # reads the whole partition twice to show that.)
    'review-tamper-commit|-PartitionMB 8192 -Review -Tamper'
    'review-tamper-rollback|-PartitionMB 8192 -Review -Tamper -RecoverMode rollback'
    # Ended at the two holds of a review run alone (sealed again, its stop
    # not yet recorded; recorded, not yet online), then recovered.
    "review-sealed-resume|$lived -Review -InterruptAt review-sealed"
    "review-sealed-rollback|$lived -Review -InterruptAt review-sealed -RecoverMode rollback"
    "review-recorded-resume|$lived -Review -InterruptAt review-recorded"
    "review-recorded-rollback|$lived -Review -InterruptAt review-recorded -RecoverMode rollback"
)
$serverCases = @(
    # These ProjFS cases were qualified on the Server control OS with standard ReFS.
    'projfs-plain|-Content minimal -Features projfs -TargetFormat standard -Check -AcceptPlain -Unattended -RunAs administrator'
    'projfs-down|-Content minimal -Features projfs-down -TargetFormat standard -Check -AcceptPlain -Unattended -ExpectRefusal leave-out-cloud'
    'projfs-down-leave-out|-Content minimal -Features projfs-down -TargetFormat standard -Check -AcceptPlain -Unattended -LeaveOutCloud'
    'std-4k|-TargetFormat standard -Check'
    'std-64k|-TargetFormat standard -TargetClusterBytes 65536 -Check'
    'std-512-to-4k|-ClusterBytes 512 -TargetFormat standard -Check'
    'std-512-to-64k|-ClusterBytes 512 -TargetFormat standard -TargetClusterBytes 65536 -Check'
    'std-4kn-4k|-SectorBytes 4096 -TargetFormat standard -Check'
    'std-4kn-64k-to-64k|-SectorBytes 4096 -ClusterBytes 65536 -TargetFormat standard -TargetClusterBytes 65536 -Check'
    'std-lived-in|-Content lived-in -Acceptance -TargetFormat standard -Check'
    'devdrive|-TargetFormat dev-drive -Check'
    'server-shared|-Siblings -TargetFormat default -Check -Acceptance'
    # The case-sensitive mark, which is set on the new volume on this
    # Windows only (#103): converted to both formats and then used, which
    # takes the volume offline with the marked directories on it, and
    # interrupted half way through the writes, resumed and rolled back.
    'std-casemark|-Content minimal -Features casemark -TargetFormat standard -Check -Acceptance'
    'devdrive-casemark|-Content minimal -Features casemark -TargetFormat dev-drive -Check -Acceptance'
    'std-casemark-apply-mid-resume|-Content minimal -Features casemark -TargetFormat standard -InterruptAt apply-mid-ranges -Check'
    'std-casemark-apply-mid-rollback|-Content minimal -Features casemark -TargetFormat standard -InterruptAt apply-mid-ranges -RecoverMode rollback -Check'
    # A root directory that is itself marked: no mark is set on that volume,
    # here as on Windows 11, and the run says so.
    'std-casemark-root|-Content minimal -Features casemark-root -TargetFormat standard -Check -Acceptance'
    'std-apply-mid-rollback|-TargetFormat standard -InterruptAt apply-mid-ranges -RecoverMode rollback -Check'
    'std-handoff-resume|-TargetFormat standard -InterruptAt handoff-sealed -Check'
    'server-files-20k|-Content minimal -Features manyfiles -FileCount 20000 -TargetFormat default -Check'
)
# The Windows a VM runs from (Invoke-RunningWindowsAttempt.ps1). Each case
# says what it has to end as: a run that was cut and recovered ends as what
# its recovery left, and one whose cut fell elsewhere than asked is no pass.
$runningCases = @(
    @{ Name = 'c-diagnose'; Expected = 'PASSED'; Arguments = @{ Diagnose = $true } }
    @{ Name = 'c-convert'; Expected = 'PASSED'; Arguments = @{ Acceptance = $true } }
    # No hold: the power goes three minutes after the restart, while the run
    # prepares. The next start cancels it: NTFS, healthy.
    @{ Name = 'c-cut-preparation'; Expected = 'CUT-BACK-TO-NTFS'; Arguments = @{ HoldAt = 'none'; CutAfterMinutes = 3 } }
    # The power goes half way through the source writes. The next start
    # finishes the conversion: ReFS, healthy. The times are from the runs
    # made by hand at 8 GB: the converter reached this hold some 20 minutes
    # after the restart (runc-cut-apply-10) and a whole conversion took 27
    # (runc-convert3), so a screen that stands still is not taken for the
    # hold in the first 15; a cut at 25 came before the writes once
    # (runc-cut-apply-11), so the latest time is 60; and the recovery after
    # the cut took 1 h 51 min (runc-cut-apply-10), so Windows has three hours
    # to come back.
    @{ Name = 'c-cut-apply-mid'; Expected = 'CUT-RECOVERED-TO-REFS'; Arguments = @{ HoldAt = 'apply-mid-ranges'; HoldAfterMinutes = 15; CutAfterMinutes = 60; AwayMinutes = 180 } }
    # The power goes while the converted volume is mounted read-only for the
    # verification before the handoff (#148). In the recovery environment the
    # disk comes up offline and read-only; the run's seal record keeps it so,
    # and the next start verifies and hands off: ReFS, healthy. The hold
    # comes after the writes, so later than the one above: at 20 minutes the
    # screen stood still for two while the changed ranges were written, and
    # the power went there, not at the hold (g2i-c-cut-verify).
    @{ Name = 'c-cut-verify'; Expected = 'CUT-RECOVERED-TO-REFS'; Arguments = @{ HoldAt = 'verify-source-readonly'; HoldAfterMinutes = 25; CutAfterMinutes = 75; AwayMinutes = 180 } }
)

function Get-GateRoundExpectations([string[]]$Sets, [string]$Prefix = '') {
    $expected = [ordered]@{}
    if ($Sets -contains 'fixtures') { foreach ($run in $fixtureRuns) { $expected[($Prefix + $run.Name)] = Get-ExpectedBootOutcome $run.Arguments } }
    if ($Sets -contains 'data') { foreach ($case in $dataCases) { $name, $rest = $case.Split('|', 2); $expected[($Prefix + $name)] = Get-ExpectedDataOutcome $rest } }
    if ($Sets -contains 'full') { $expected[($Prefix + $fullRun.Name)] = Get-ExpectedBootOutcome $fullRun.Arguments }
    if ($Sets -contains 'server') { foreach ($case in $serverCases) { $name, $rest = $case.Split('|', 2); $expected[($Prefix + $name)] = Get-ExpectedDataOutcome $rest } }
    if ($Sets -contains 'running') { foreach ($case in $runningCases) { $expected[($Prefix + $case.Name)] = $case.Expected } }
    $expected
}

function Get-GateRoundCaseRoute([string]$Name) {
    if ($Name -in @($fixtureRuns.Name) + @($fullRun.Name)) { return 'boot' }
    if ($Name -in $runningCases.Name) { return 'running' }
    return 'data'
}
