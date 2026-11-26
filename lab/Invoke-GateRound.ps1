<#
.SYNOPSIS
Runs the lab's gates for one frozen build on every lab VM and reports them in
one table.

.DESCRIPTION
AGENTS.md says what has to pass before a change is committed. This script runs
it: five sets, the first two at the same time.

  fixtures  on the reference VM: the 1-in-10 fixture, the 1-in-40 fixture as
            an administrator, and the interrupted runs of the 1-in-40 fixture
            (ended half way through the source writes and resumed; the same
            rolled back; ended before finalization and resumed)
  data      on the other Windows 11 VMs: data volumes of every geometry,
            lived-in and many-file volumes, a shared disk, stops, recoveries,
            one volume with --recheck-everything, one held to the memory
            the estimate asks for it, one with middling memory held to a
            time, and the runs that stop for review (--review): committed,
            rolled back, written to after the stop (both commands refused),
            and ended at the two holds of a review run and recovered
  full      on the reference VM, with the host to itself: the full Windows
            volume, converted and booted on ReFS
  server    on the Windows Server VM: standard ReFS and the Dev Drive
  running   on the Windows 11 VMs other than the reference VM, with the host
            to itself: the Windows each VM runs from (C:), converted with
            one command in that Windows through its recovery environment
            (Invoke-RunningWindowsAttempt.ps1): --diagnose, a conversion
            that is then used, the power cut while the run prepares (NTFS
            has to be back) and at the hold half way through the source
            writes (the run has to recover to ReFS by itself). Each case
            starts from the VM's baseline checkpoint; each VM gets a working
            disk of its own first, made by a control-OS attempt

A build is a directory holding ntfs2refs.exe and lab-volume-manifest.exe, a
copy made for the round so that the tree can be built again meanwhile. Every
attempt is named <Prefix>-<case> and keeps its records under
.lab\hyperv\attempts as any attempt does; this script's own output goes to
<Build>\gate-<Prefix>.

The round starts with every lab VM off and leaves them off, with the scratch
disks it made deleted. It ends with a table of every case, what it was
expected to end as and what it ended as, and exits 1 if any differs.

The VMs' memory comes from what the host has free at the moment. Where that
is not enough for the reference VM's 24 GB beside the data VMs, the fixtures
run with less; where it is not enough for every data VM, fewer are used; and
where it is not enough for one, the data-volume cases wait for the fixtures.
The full Windows run always has the host to itself, and so has the running
set, which uses as many of its VMs as the host has memory and disk space
for (65 GB of disk a VM, as a full attempt).

.EXAMPLE
lab\Invoke-GateRound.ps1 -Build D:\builds\candidate -Prefix g7

.EXAMPLE
lab\Invoke-GateRound.ps1 -Build D:\builds\candidate -Prefix g7b -Sets fixtures, data
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Build,
    [Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9]{0,7}$')][string]$Prefix,
    [ValidateSet('fixtures', 'data', 'full', 'server', 'running')][string[]]$Sets = @('fixtures', 'data', 'full', 'server', 'running'),
    [string]$ReferenceVm = 'ntfs2refs-reference-isolated',
    [string[]]$DataVm = @('ntfs2refs-reference-b', 'ntfs2refs-reference-c'),
    [string]$ServerVm = 'ntfs2refs-server2025',
    # The VMs whose own Windows the running set converts; the data VMs when
    # none is named.
    [string[]]$RunningVm = @(),
    # The most memory a lab VM is given, in GB. 24 is what the full Windows
    # volume is timed with; a host that shares its memory with other work
    # runs the round with less (12), slower, so that the other work's swings
    # do not end it (two rounds were lost to them on 17 and 18 November).
    [ValidateRange(8, 64)][int]$MaxVmGB = 24,
    [string]$ServerCredentialPath,
    # Only the cases named here, by the names the round gives them (as in
    # its table, without the prefix: 'fixture10', 'full-system', 'lived-in',
    # 'c-convert', ...): a short round for a change whose risk is known, or
    # the cases a round did not get to. The sets that hold none of them are
    # not run. A name no set has is refused.
    [string[]]$Only
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module Hyper-V

$workspace = Split-Path -Parent $PSScriptRoot
$attempts = Join-Path $workspace '.lab\hyperv\attempts'
$boot = Join-Path $PSScriptRoot 'Invoke-BootConversionAttempt.ps1'
$matrix = Join-Path $PSScriptRoot 'Invoke-DataVolumeMatrix.ps1'
$running = Join-Path $PSScriptRoot 'Invoke-RunningWindowsAttempt.ps1'
if (-not $RunningVm) { $RunningVm = $DataVm }
if (-not $ServerCredentialPath) {
    $ServerCredentialPath = Join-Path $workspace '.lab\hyperv\ntfs2refs-server2025\secrets\guest-credential.xml'
}
$Build = (Resolve-Path -LiteralPath $Build).Path
$binary = Join-Path $Build 'ntfs2refs.exe'
$manifest = Join-Path $Build 'lab-volume-manifest.exe'
foreach ($file in $binary, $manifest) {
    if (-not (Test-Path -LiteralPath $file)) { throw "$file is missing: a build is a directory with ntfs2refs.exe and lab-volume-manifest.exe" }
}
if (Get-ChildItem -LiteralPath $attempts -Directory -Filter "$Prefix-*" -ErrorAction SilentlyContinue) {
    throw "Attempts named '$Prefix-...' exist already under $attempts : choose another prefix"
}
$logs = Join-Path $Build "gate-$Prefix"
New-Item -ItemType Directory -Force -Path $logs | Out-Null

function Say([string]$text) { Write-Host ('{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $text) }

# The VMs this round uses, by name; the rest of the host's VMs are left alone.
$wanted = @()
if ($Sets -contains 'fixtures' -or $Sets -contains 'full') { $wanted += $ReferenceVm }
if ($Sets -contains 'data') { $wanted += $DataVm }
if ($Sets -contains 'server') { $wanted += $ServerVm }
if ($Sets -contains 'running') { $wanted += $RunningVm }
$wanted = @($wanted | Select-Object -Unique)
$vms = @{}
foreach ($name in $wanted) {
    $vm = @(Get-VM -Name $name -ErrorAction SilentlyContinue)
    if ($vm.Count -ne 1) { throw "There is no single VM named '$name' on this host" }
    if ($vm[0].State -ne 'Off') { throw "VM '$name' is $($vm[0].State): a gate round starts with its VMs off" }
    $vms[$name] = $vm[0]
}

# What each case is expected to end as follows from how it is run.
$expected = [ordered]@{}
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

if ($Only) {
    $known = @($fixtureRuns.Name) + @($fullRun.Name) + @($runningCases.Name) +
        @($dataCases + $serverCases | ForEach-Object { $_.Split('|', 2)[0] })
    $unknown = @($Only | Where-Object { $known -notcontains $_ })
    if ($unknown) { throw "-Only names cases no set has: $($unknown -join ', ')" }
    $fixtureRuns = @($fixtureRuns | Where-Object { $Only -contains $_.Name })
    $dataCases = @($dataCases | Where-Object { $Only -contains $_.Split('|', 2)[0] })
    $serverCases = @($serverCases | Where-Object { $Only -contains $_.Split('|', 2)[0] })
    $runningCases = @($runningCases | Where-Object { $Only -contains $_.Name })
    $Sets = @($Sets | Where-Object {
            ($_ -eq 'fixtures' -and $fixtureRuns) -or ($_ -eq 'data' -and $dataCases) -or
            ($_ -eq 'full' -and $Only -contains $fullRun.Name) -or ($_ -eq 'server' -and $serverCases) -or
            ($_ -eq 'running' -and $runningCases) })
    Say "only $($Only.Count) case(s), in the sets $($Sets -join ', ')"
}
if ($Sets -contains 'fixtures') { foreach ($run in $fixtureRuns) { $expected["$Prefix-$($run.Name)"] = Get-ExpectedBootOutcome $run.Arguments } }
if ($Sets -contains 'data') { foreach ($case in $dataCases) { $name, $rest = $case.Split('|', 2); $expected["$Prefix-$name"] = Get-ExpectedDataOutcome $rest } }
if ($Sets -contains 'full') { $expected["$Prefix-$($fullRun.Name)"] = Get-ExpectedBootOutcome $fullRun.Arguments }
if ($Sets -contains 'server') { foreach ($case in $serverCases) { $name, $rest = $case.Split('|', 2); $expected["$Prefix-$name"] = Get-ExpectedDataOutcome $rest } }
if ($Sets -contains 'running') { foreach ($case in $runningCases) { $expected["$Prefix-$($case.Name)"] = $case.Expected } }

# One boot attempt after another on one VM, each with its console output in a
# file of its own. Run as a job, so that the data set can run beside it.
$bootChain = {
    param($boot, $runs, $prefix, $vmId, $binary, $manifest, $logs)
    foreach ($run in $runs) {
        $arguments = @{} + $run.Arguments
        $arguments.Name = "$prefix-$($run.Name)"
        $arguments.VmId = $vmId
        $arguments.Binary = $binary
        $arguments.ManifestBinary = $manifest
        try { & $boot @arguments *> (Join-Path $logs "$($arguments.Name).log") }
        catch { "$($arguments.Name) threw: $($_.Exception.Message)" | Add-Content -LiteralPath (Join-Path $logs 'errors.txt') }
    }
}

# One running-Windows attempt after another on one VM, as a job beside the
# other VMs'. Each restores the VM's baseline checkpoint first and gives the
# VM back the disks it detached when it ends.
$runningChain = {
    param($running, $cases, $prefix, $vmId, $binary, $scratch, $logs)
    foreach ($case in @($cases)) {
        $arguments = @{} + $case.Arguments
        $arguments.Name = "$prefix-$($case.Name)"
        $arguments.VmId = $vmId
        $arguments.Binary = $binary
        $arguments.ScratchVhdx = $scratch
        # What the cases' times were taken with.
        $arguments.MemoryGB = 8
        $arguments.Restore = $true
        $arguments.Reattach = $true
        try { & $running @arguments *> (Join-Path $logs "$($arguments.Name).log") }
        catch { "$($arguments.Name) threw: $($_.Exception.Message)" | Add-Content -LiteralPath (Join-Path $logs 'errors.txt') }
    }
}

function Stop-RoundVm([string]$name) {
    $vm = Get-VM -Name $name
    if ($vm.State -ne 'Off') { $vm | Stop-VM -Force -Confirm:$false }
    # The scratch disk of a control OS that was kept up for the data set, or
    # of an attempt of this round that was cut off.
    # (And the boot partition's disk a running-Windows attempt made beside
    # its working disk.)
    foreach ($drive in @(Get-VMHardDiskDrive -VMName $name | Where-Object { $_.Path -like (Join-Path $attempts "$Prefix-*\scratch.vhdx") -or $_.Path -like (Join-Path $attempts "$Prefix-*\boot.vhdx") })) {
        $path = $drive.Path
        Remove-VMHardDiskDrive -VMHardDiskDrive $drive
        Remove-Item -LiteralPath $path -Force
        Say "deleted the scratch disk $path"
    }
}

# Memory is sized from what the host has free, which other programs change
# from one minute to the next. The harness gives a VM no more than eight
# tenths of what is free when it starts and refuses to start one with less
# than 8 GB: a data VM therefore needs 10 GB free at its start, with a
# gigabyte to spare for what changes meanwhile, and each one before it
# takes its 8 GB and half a gigabyte more.
function Get-FreeGB { (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB }
# (The host keeps 8 GB, as the attempts themselves hold it to: counting 2.5 GB had a second data VM start its attempt and wait for memory the fixtures held.)
function Get-DataVmCount([double]$freeGB) { [math]::Max(0, [math]::Min($DataVm.Count, [math]::Floor(($freeGB - 8) / 8.5))) }

$fixtureJob = $null; $runningJobs = @()
try {
    if ($Sets -contains 'fixtures') {
        $free = Get-FreeGB
        if ($Sets -contains 'data') {
            # The fixtures leave the data VMs their memory where the host has
            # it: the reference VM does not need its 24 GB for them.
            # (A running VM costs the host a gigabyte or two beyond what it
            # is given.)
            $beside = 5 + 8 * $DataVm.Count
            $referenceGB = [math]::Floor([math]::Min($MaxVmGB, $free - $beside))
            # Too little for both at once: the reference VM takes what is
            # free less the host's 8 GB, and the data cases wait for it.
            if ($referenceGB -lt [math]::Min(16, $MaxVmGB)) { $referenceGB = [math]::Floor([math]::Max(8, [math]::Min($MaxVmGB, $free - 8))) }
            foreach ($run in $fixtureRuns) { $run.Arguments = $run.Arguments + @{ MemoryGB = [int]$referenceGB } }
        } else {
            foreach ($run in $fixtureRuns) { $run.Arguments = $run.Arguments + @{ MemoryGB = $MaxVmGB } }
        }
        Say ('fixtures and interrupted runs on {0} ({1:N1} GB of host memory free)' -f $ReferenceVm, $free)
        $fixtureJob = Start-Job -ScriptBlock $bootChain -ArgumentList $boot, $fixtureRuns, $Prefix, $vms[$ReferenceVm].Id.Guid, $binary, $manifest, $logs
        if ($Sets -contains 'data') {
            # The reference VM takes its memory when it starts; what the data
            # VMs get is measured after that.
            $deadline = (Get-Date).AddMinutes(10)
            do { Start-Sleep -Seconds 10 } until ((Get-VM -Name $ReferenceVm).State -eq 'Running' -or $fixtureJob.State -ne 'Running' -or (Get-Date) -gt $deadline)
            Start-Sleep -Seconds 20
        }
    }
    if ($Sets -contains 'data') {
        $count = Get-DataVmCount (Get-FreeGB)
        if ($count -eq 0 -and $fixtureJob) {
            Say ('{0:N1} GB of host memory are free beside the reference VM: the data-volume cases wait for the fixtures' -f (Get-FreeGB))
            $fixtureJob | Wait-Job | Receive-Job | Out-File -LiteralPath (Join-Path $logs 'fixtures-job.log')
            $fixtureJob = $null
            Stop-RoundVm $ReferenceVm
            $count = Get-DataVmCount (Get-FreeGB)
        }
        # Too little memory is no failure of the round: it waits for it.
        for ($waited = 0; $count -eq 0 -and $waited -lt 240 * 60; $waited += 30) {
            if ($waited % 600 -eq 0) { Say ('{0:N1} GB of host memory are free and a data VM needs 10: waiting' -f (Get-FreeGB)) }
            Start-Sleep -Seconds 30
            $count = Get-DataVmCount (Get-FreeGB)
        }
        if ($count -eq 0) { throw ('{0:N1} GB of host memory are free after four hours of waiting: a data VM needs 10' -f (Get-FreeGB)) }
        $used = @($DataVm | Select-Object -First $count)
        $number = 0
        foreach ($name in $used) {
            $number++
            # 8 GB is enough for every data-volume case; a VM that has the
            # memory to itself gets up to 12.
            $free = Get-FreeGB
            $give = if ($count -eq 1) { [math]::Floor([math]::Max(8, [math]::Min(12, $free - 8))) } else { 8 }
            Say ('control OS up on {0} with {1} GB ({2:N1} GB free)' -f $name, $give, $free)
            $control = "$Prefix-control-$number"
            & $boot -Name $control -NoConvert -KeepScratch -MemoryGB $give -VmId $vms[$name].Id.Guid -Binary $binary -ManifestBinary $manifest *> (Join-Path $logs "$control.log")
            $verdict = Join-Path $attempts "$control\verdict.json"
            if (-not (Test-Path -LiteralPath $verdict) -or (Get-Content -LiteralPath $verdict -Raw | ConvertFrom-Json).outcome -ne 'prepared-only') {
                throw "The control OS of $name did not come up: see $(Join-Path $logs "$control.log")"
            }
        }
        Say "$($dataCases.Count) data-volume cases on $($used -join ', ')"
        & $matrix -Prefix $Prefix -Cases $dataCases -VmId @($used | ForEach-Object { $vms[$_].Id.Guid }) -Binary $binary -ManifestBinary $manifest -LogDirectory $logs *> (Join-Path $logs 'matrix-data.log')
        foreach ($name in $used) { Stop-RoundVm $name }
    }
    if ($fixtureJob) {
        Say 'waiting for the fixtures and interrupted runs'
        $fixtureJob | Wait-Job | Receive-Job | Out-File -LiteralPath (Join-Path $logs 'fixtures-job.log')
    }
    if ($Sets -contains 'full') {
        Say "the full Windows volume on $ReferenceVm, with the host to itself"
        & $bootChain $boot @($fullRun) $Prefix $vms[$ReferenceVm].Id.Guid $binary $manifest $logs
    }
    if ($Sets -contains 'server') {
        Say "$($serverCases.Count) data-volume cases on $ServerVm"
        if ($vms.ContainsKey($ReferenceVm)) { Stop-RoundVm $ReferenceVm }
        $credential = Import-Clixml -LiteralPath $ServerCredentialPath
        Start-VM -Name $ServerVm
        $deadline = (Get-Date).AddMinutes(10)
        do {
            Start-Sleep -Seconds 10
            $up = $false
            try { $up = (Invoke-Command -VMName $ServerVm -Credential $credential -ScriptBlock { $true } -ErrorAction Stop) } catch { }
        } until ($up -or (Get-Date) -gt $deadline)
        if (-not $up) { throw "$ServerVm did not answer PowerShell Direct within ten minutes" }
        & $matrix -Prefix $Prefix -Cases $serverCases -VmId $vms[$ServerVm].Id.Guid -Binary $binary -ManifestBinary $manifest -CredentialPath $ServerCredentialPath -LogDirectory $logs *> (Join-Path $logs 'matrix-server.log')
    }
    if ($Sets -contains 'running') {
        # The host to itself, as for the full Windows volume: each case
        # converts a whole Windows.
        foreach ($name in $wanted) { Stop-RoundVm $name }
        # A VM takes 8 GB and the host keeps 8; a conversion of the Windows
        # volume grows the VM's disks and its working disk by about 60 GB.
        $freeGB = Get-FreeGB
        $diskGB = (Get-Volume -FilePath $attempts).SizeRemaining / 1GB
        $count = [int][math]::Max(0, [math]::Min($RunningVm.Count, [math]::Min([math]::Floor(($freeGB - 8) / 8.5), [math]::Floor($diskGB / 65))))
        if ($count -eq 0) { throw ('The running set needs 16.5 GB of host memory and 65 GB of disk space for one VM: {0:N1} GB of memory and {1:N1} GB of disk are free' -f $freeGB, $diskGB) }
        $used = @($RunningVm | Select-Object -First $count)
        Say ('{0} running-Windows cases on {1}, 8 GB each ({2:N1} GB of host memory and {3:N1} GB of disk free)' -f $runningCases.Count, ($used -join ', '), $freeGB, $diskGB)
        for ($number = 0; $number -lt $used.Count; $number++) {
            $name = $used[$number]
            # The working disk: an NTFS volume on a disk of its own, made by a
            # control-OS attempt, which is then shut down so that the volume
            # is written out before the VM's checkpoint is restored under it.
            $work = "$Prefix-c-work-$($number + 1)"
            & $boot -Name $work -NoConvert -KeepScratch -ScratchFileSystem NTFS -MemoryGB 8 -VmId $vms[$name].Id.Guid -Binary $binary -ManifestBinary $manifest *> (Join-Path $logs "$work.log")
            $verdict = Join-Path $attempts "$work\verdict.json"
            if (-not (Test-Path -LiteralPath $verdict) -or (Get-Content -LiteralPath $verdict -Raw | ConvertFrom-Json).outcome -ne 'prepared-only') {
                throw "The working disk of $name was not made: see $(Join-Path $logs "$work.log")"
            }
            Stop-VM -Name $name -Force -Confirm:$false
            # Each VM takes every case whose place in the list is its own.
            $mine = @(for ($i = $number; $i -lt $runningCases.Count; $i += $used.Count) { $runningCases[$i] })
            Say "$name takes $(($mine | ForEach-Object { $_.Name }) -join ', ')"
            $runningJobs += Start-Job -ScriptBlock $runningChain -ArgumentList $running, $mine, $Prefix, $vms[$name].Id.Guid, $binary, (Join-Path $attempts "$work\scratch.vhdx"), $logs
        }
        $runningJobs | Wait-Job | Receive-Job | Out-File -LiteralPath (Join-Path $logs 'running-jobs.log')
    }
}
finally {
    if ($fixtureJob -and $fixtureJob.State -eq 'Running') { $fixtureJob | Stop-Job }
    foreach ($job in @($runningJobs)) { if ($job.State -eq 'Running') { $job | Stop-Job } }
    foreach ($name in $wanted) { try { Stop-RoundVm $name } catch { Say "could not turn $name off: $($_.Exception.Message)" } }
}

# One row a case: what it was to end as, what it ended as, whether the
# listing of the volume is the one taken before, and the converter's time.
$rows = @(foreach ($name in $expected.Keys) {
    $verdict = Join-Path $attempts "$name\verdict.json"
    $outcome = 'no verdict'; $listing = ''; $seconds = $null; $check = ''
    if (Test-Path -LiteralPath $verdict) {
        $v = Get-Content -LiteralPath $verdict -Raw | ConvertFrom-Json
        $outcome = $v.outcome
        if ($v.PSObject.Properties['manifest'] -and $v.manifest) { $listing = $v.manifest.result }
        if ($v.PSObject.Properties['converter'] -and $v.converter) {
            foreach ($field in 'wall_seconds', 'seconds') { if ($v.converter.PSObject.Properties[$field]) { $seconds = [math]::Round($v.converter.$field, 1); break } }
        }
        if ($v.PSObject.Properties['check'] -and $v.check -and $v.check.PSObject.Properties['agrees'] -and $v.check.agrees -eq $false) { $check = 'check disagreed' }
    }
    $ok = $outcome -eq $expected[$name] -and $listing -in '', 'identical' -and -not $check
    [pscustomobject]@{ Case = $name; Expected = $expected[$name]; Outcome = $outcome; Listing = $listing; Seconds = $seconds; Passed = $ok; Note = $check }
})
$rows | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
$rows | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $logs 'round.json') -Encoding utf8
$failed = @($rows | Where-Object { -not $_.Passed })
Say ('{0} of {1} cases as expected; records in {2}' -f ($rows.Count - $failed.Count), $rows.Count, $logs)
if ($failed) { exit 1 }
