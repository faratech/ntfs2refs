# Hyper-V qualification lab

The current route is `Invoke-BootConversionAttempt.ps1`. It restores a disposable
NTFS baseline, runs the converter from a separate control OS, compares independent
before/after volume listings, and optionally boots the original source disk alone.
See [AGENTS.md](../AGENTS.md) for the VM identities and standing rules, and the
[feature matrix](../docs/feature-matrix.md) and the
[recovery matrix](../docs/recovery-matrix.md) for what the attempts have shown.

The release workflow runs the gate round against the exact signed candidate
and publishes a candidate-specific recovery matrix in `QUALIFICATION.md`.
The checked-in matrix contains historical attempts. See the
[release workflow guide](../.github/CI.md#the-release) for runner setup and
forensics retention.

## The gate round

Everything AGENTS.md asks for before a change is committed, for one build, on
every lab VM, as one command:

```powershell
cargo build --locked --release --bin ntfs2refs --bin lab-volume-manifest
Copy-Item target\release\ntfs2refs.exe, target\release\ntfs2refs.pdb, target\release\lab-volume-manifest.exe D:\builds\candidate
.\lab\Invoke-GateRound.ps1 -Build D:\builds\candidate -Prefix g7
```

The build is a copy, so the tree can be built again while the round runs; the
gates count for a commit only if its Rust sources are the ones the copy was
built from. The round runs five sets, the first two at the same time: the
fixtures and interrupted runs on the reference VM; the data-volume cases on
the other Windows 11 VMs, the runs that stop for review among them; then the
full Windows volume, converted and booted, with the host to itself; then the
Windows Server cases; then the Windows each of the other Windows 11 VMs runs
from, converted through its own recovery environment (below), again with the
host to itself. `-Sets` picks among `fixtures`, `data`, `full`, `server` and
`running`; all five are the default. It starts with the lab VMs off and
leaves them off with its scratch disks deleted (and the boot-partition disks
of the running set), prints one row a case (what it was to end as, what it
ended as, whether the listing is identical, the converter's seconds) and
exits 1 if a case ended otherwise. Its own output is in
`<Build>\gate-<Prefix>`; each case keeps its records under
`.lab\hyperv\attempts\<Prefix>-<case>` like any attempt. About 45 minutes for
the first two sets as they were measured, before the eight review cases were
added to the second; half an hour each for the full volume and the server
cases. The running set has not been timed as a set. By the attempts made by
hand at 8 GB, a conversion of C: took 27 minutes from the restart to Windows
again (`runc-convert3`), and a run cut at `apply-mid-ranges` 22 minutes to
the cut and 1 h 51 min to recover (`runc-cut-apply-10`): with two VMs side by
side, expect some three hours, most of it that one case.

The running set uses `-RunningVm` (the data VMs unless others are named), as
many of them as the host has memory and disk space for (8 GB and 65 GB a VM
beside the host's 8 GB). Each VM first gets a working disk of its own, an
NTFS volume made by a control-OS attempt (`<Prefix>-c-work-<n>`), and then
takes its share of the cases one after another:

| Case | How it is run | It has to end as |
|---|---|---|
| `c-diagnose` | `-Diagnose` | `PASSED`: C: is NTFS and healthy, the converter ended with 0 |
| `c-convert` | `-Acceptance` | `PASSED`: C: is ReFS and healthy, the converter ended with 0, and the use test and two more starts passed |
| `c-cut-preparation` | `-HoldAt none -CutAfterMinutes 3` | `CUT-BACK-TO-NTFS`: the start after the cut cancelled the run, C: is NTFS and healthy |
| `c-cut-apply-mid` | `-HoldAt apply-mid-ranges -HoldAfterMinutes 15 -CutAfterMinutes 60 -AwayMinutes 180` | `CUT-RECOVERED-TO-REFS`: the converter had reported the hold, the start after the cut finished the conversion, C: is ReFS and healthy |

Every one of them is run with `-Restore -Reattach` and 8 GB, which is what
those times were taken with.

The sections below describe the attempts the round is made of; run one by
itself to look into a failure.

The gate round is about what the converter does to a volume. What a commit
has to pass as source code (formatting, Clippy, the tests, the release build)
is GitHub Actions' `ci.yml` on every pull request; `lab\Invoke-Checks.ps1
-Commit <commit> -Report checks.md` runs the same checks locally, in a
worktree of its own. The nightly soak (`soak.yml`) converts virtual disks on
the hosted runners, without VMs; the lab does what it cannot: power cut under
a run, Windows boot volumes, the restart route, Windows 11
(`.github/CI.md`).

## Existing checks

Build the converter and independent listing tool using one shared build directory:

```powershell
cargo build --locked --release --bin ntfs2refs --bin lab-volume-manifest
```

A thinned 1-in-10 fixture is the normal regression case:

```powershell
.\lab\Invoke-BootConversionAttempt.ps1 -Name fixture-check -Fixture -FixtureCheckpoint N2R-Thinned-Fixture -NoBoot -KeepScratch
```

A full run includes the original-disk-only boot and desktop observation:

```powershell
.\lab\Invoke-BootConversionAttempt.ps1 -Name full-check -KeepScratch
```

Supply `-Binary` and `-ManifestBinary` when verifying an already built package;
otherwise the harness uses `target/release`. `-VmId` selects the second lab VM.
`-SampleStacks` requires the matching PDB beside the executable and writes
`stacks.txt`: phase, step and stack per line, a hundred samples a second, helper
and digest threads included. Use it to find where unnamed time goes before
changing anything for speed, not merely to claim an unmeasured speed change.
The sampler does not see inside a file-system call (a call of a tenth of a
second counts as one sample of a hundredth), and it slows the steps that are
mostly such calls: rank steps by the `timing-steps:` lines, which are wall
clock, and compare two builds with runs that have the host to themselves.

`lab\perf` reads those records (Python 3, nothing to install), and
[docs/performance.md](../docs/performance.md) has the figures and how they
are taken:

| Script | What it prints |
|---|---|
| `attempts.py <repo> <prefix>` | the outcome of every attempt whose name starts with the prefix, oldest first |
| `steps_compare.py <repo> <before> <after> [seconds]` | the steps of two attempts side by side, largest differences first |
| `stacks_cover.py <repo> <attempt>` | each step's wall clock beside what the profile has for it: what the sampler did not see |
| `stacks_busy.py <stacks.txt>` | for every step, the seconds a thread waited and worked, and where it worked |
| `stacks_under.py <stacks.txt> <function>` | everything under one function: by step, leaf, callee and caller |
| `stacks_leaf.py <stacks.txt> <leaf>` | the samples that end in one leaf (a hash, a system call): by step and caller |
| `stacks_split.py`, `stacks_levels.py`, `stacks_near.py` | one step by worker and helper threads, by call chain from a depth, by the frames nearest a leaf |

Both harnesses switch the control OS's scheduled drive optimisation off for
the run. Windows starts its automatic maintenance some eleven minutes after
the control OS boots, in every run, because a restored checkpoint is always
overdue, and the optimisation it runs (`defrag.exe -c -h -o`) holds up writes
to the control OS's ReFS volumes for minutes at a time with every processor
busy in the kernel: the same build took 25 s and 243 s for one step, and one
run stood still for fifteen minutes (issue 132). `-WithDriveOptimization`
leaves the task on, for a run that is meant to meet it; the verdict's
`drive_optimization` says which it was.

Recovery is checked by stopping the converter at a named point of apply,
handoff or finalization (`crates/n2r-win32/src/lab_hold.rs` lists them), ending
its process there, and running the recovery command it printed:

```powershell
.\lab\Invoke-BootConversionAttempt.ps1 -Name resume-check -Fixture -FixtureCheckpoint N2R-Thinned-Fixture-40 -NoBoot -InterruptAt apply-mid-ranges
.\lab\Invoke-BootConversionAttempt.ps1 -Name rollback-check -Fixture -FixtureCheckpoint N2R-Thinned-Fixture-40 -NoBoot -InterruptAt apply-mid-ranges -RecoverMode rollback
```

A resume ends `RESUMED-NOT-BOOTED` and is compared as a conversion is; a
rollback ends `ROLLED-BACK-NOT-BOOTED` and is compared with the listing taken
before in every field (`compare --exact`: nothing allowed).
`-RecoverMode none -CheckpointAfterConvert <name>` saves the interrupted state
instead, and `-RecoverFrom <attempt>` recovers it later from that attempt's own
records. `-TearMarker handoff` leaves the journal's handoff marker as a write
that stopped part-way leaves it, so that recovery has to settle it first: with
`-InterruptAt apply-handoff-durable` and `-Verify thorough`, whose apply step
writes the handoff with the disk offline and writable, the marker the run wrote
is torn; with `-InterruptAt verify-passed` and `--verify fast` (the default),
whose finalizer writes the handoff after the verification with the disk sealed
offline and read-only, the marker is not written yet, and the harness makes the
torn image of the one that would be written next from the apply intent beside
it.

`-Verify fast|thorough` gives the converter its `--verify` (`fast` is its
default). A fast run's handoff follows the verification of the converted
volume, so it passes `apply-sealed`, `apply-seal-recorded`,
`verify-authenticated`, `verify-source-readonly` and `verify-passed` and not
`apply-handoff-durable`, `finalize-authenticated` or
`finalize-source-readonly`, which only a thorough run reaches; a hold at a
point the run does not reach is never reported. The verdict records the mode
as `verify`.

`-InterruptKind vm` turns the VM off at the hold instead of ending the
converter's process, as if the machine's power had gone: whatever the guest had
not flushed is lost, the control OS starts again, and recovery runs in that
fresh Windows. The verdict records the kind (`vm-turned-off`). The virtual
disks are the host's files, so this is a machine that loses power with storage
that keeps what reached it; the lab cannot cut power to the storage itself, and
every verdict says so.

The converter runs in the control OS as SYSTEM unless `-RunAs administrator` is
given, which runs it as the guest's elevated administrator, the way an owner
runs it. The shadow's working objects admit SYSTEM alone, so a request that
only SYSTEM is granted fails for an administrator and nowhere else: a change
to how an object is opened or created is checked both ways.

## Data volumes of other geometries

The Windows partition has one geometry: 512-byte sectors, 4 KiB clusters, 1 KiB
file records. `Invoke-DataVolumeAttempt.ps1` converts a data volume of any
other, in a control OS that is already up:

```powershell
lab\Invoke-BootConversionAttempt.ps1 -Name prep-01 -NoConvert -KeepScratch -VmId <vm>
lab\Invoke-DataVolumeAttempt.ps1 -Name d-512-01 -VmId <vm> -ClusterBytes 512
lab\Invoke-DataVolumeAttempt.ps1 -Name d-4kn-01 -VmId <vm> -SectorBytes 4096 -ClusterBytes 65536
```

A set of cases is run by `Invoke-DataVolumeMatrix.ps1`, on as many VMs as
are named: each VM takes the next case as soon as it is free, and a line is
printed as each ends. An attempt mostly waits for its guest, so two VMs take
about half the time of one (twelve cases: 469 s on two VMs, 905 s one after
another). `New-LabVmClone.ps1 -Name <new vm>` makes a further VM like the
reference VM in seconds, from differencing disks; bring each one's control
OS up with `-MemoryGB 12`, which is enough for data volumes and leaves the
reference VM its memory for a Windows run at the same time.

```powershell
lab\Invoke-DataVolumeMatrix.ps1 -Prefix x1 -VmId <vm b>, <vm c> -Binary <frozen>\ntfs2refs.exe -ManifestBinary <frozen>\lab-volume-manifest.exe `
    -Cases 'plain|-Check', 'lived-in|-Content lived-in -Check -Acceptance', 'shared|-Siblings -Check'
```

A VM with Windows Server, which formats ordinary ReFS as well as Dev Drives,
is made by `lab\New-ServerLabVm.ps1 -Iso <Windows Server ISO>`: Windows Setup
runs inside the new VM from a generated answer file, a scratch volume `S:` is
added, and a baseline checkpoint is taken. Start that VM and give the harness
its id with `-VmId` and its credential file with `-CredentialPath`;
`-TargetFormat standard` then converts to ordinary ReFS. `-TargetFormat
default` gives the converter no `--target-format`, and `-ExpectTarget
<pattern>` holds the attempt to what Windows then reports the volume as
(`^standard` on Windows Server, `^Dev Drive` on Windows 11).

`-ClusterBytes` is the NTFS allocation unit, 512 bytes to 2 MiB.
`-SectorBytes 4096` puts the volume on a 4Kn disk, which the host makes in the
attempt's folder and attaches to the VM for the attempt. `-LargeRecords` formats
4096-byte file records (`format /L`). `-PartitionMB` sets the partition's size;
one that is not a multiple of 64 makes the converter shrink it first.
`-TargetClusterBytes 65536` converts to 64 KiB ReFS clusters. `-RunAs`,
`-ConverterArgs`, `-Verify`, `-Binary`, `-ManifestBinary` and `-SampleStacks`
mean what they mean to the boot harness. `-ExpectRefusal <pattern>` is for a volume the
converter must refuse.

`-InterruptAt <point>` (for example `apply-mid-ranges` or `handoff-sealed`)
ends the converter when it reports that it is held at that point, then runs the
recovery command the run printed: `-RecoverMode resume` (the default) must end
with ReFS and an identical listing (`resumed`), `-RecoverMode rollback` with the
NTFS volume listing exactly as before (`rolled-back`). `-Diagnose` runs the
converter with `--diagnose`; whatever it reports, the volume must list exactly
as before (`diagnose-clean`, `diagnose-found-failures`).

### Preformatted NTFS index records

`fixtures/make_ntfs_index_fixtures.py` builds matching GPT data VHDXs with
2 KiB, 4 KiB and 8 KiB NTFS index records. Run it on Linux with Python 3,
a C compiler, Make, tar, sfdisk, and qemu-img. Supply the upstream archive and
a new output directory. The generator verifies the archive checksum and each
image's geometry, checks the MFT and its mirror, and compares the VHDX with
the partitioned disk image. [NTFS-3G 2026.9.28 archive and checksums](https://github.com/tuxera/ntfs-3g/releases/tag/2026.9.28)

```sh
python3 lab/fixtures/make_ntfs_index_fixtures.py ntfs-3g_ntfsprogs-2026.9.28.tgz index-fixtures
```

`fixtures.json` gives the SHA-256, GPT identities and measured geometry for
each image. Copy this manifest and the image to the disposable Hyper-V guest
and run the preparation helper in an elevated guest PowerShell.
`guest/Prepare-NtfsIndexFixture.ps1` creates and mounts a separate writable
copy, checks its disk and partition, writes the root DACL through Windows and
creates 1,024 files in one directory. Short-name creation is disabled while
Windows first mounts the copy. The helper then disables it on the NTFS copy
and restores the guest's original setting. Run the normal data preflight and
conversion against that drive, keeping the before and after listings.

```powershell
$fixture = .\Prepare-NtfsIndexFixture.ps1 -ImagePath S:\fixtures\ntfs-index-2048.vhdx -CopyPath S:\index-test.vhdx
.\ntfs2refs.exe --drive $fixture.drive --check --scratch-directory S:\runs --target-format standard --target-cluster-bytes 4096
.\lab-volume-manifest.exe capture --root V:\ --output before.jsonl
.\ntfs2refs.exe --drive $fixture.drive --scratch-directory S:\runs --target-format standard --target-cluster-bytes 4096
.\lab-volume-manifest.exe capture --root V:\ --output after.jsonl
.\lab-volume-manifest.exe compare --before before.jsonl --after after.jsonl --report comparison.json
Dismount-DiskImage -ImagePath $fixture.copy_path
```

The Server 2025 lab converted the 2 KiB and 4 KiB sources with identical
listings. Windows returned error 1392 on the filesystem query for the 8 KiB
fixture. [Native index cases](https://github.com/faratech/ntfs2refs/issues/184#issuecomment-7142377380)

#### `--review` (#110): cases for the test round

A review run stops before its handoff with the volume mounted read-only as
ReFS and exits 0; `--recover` commits it and `--recover --rollback` undoes it.

`-Review` runs the converter with `--review`. A run that ends with exit 0 has
to say `Stopped for review` and print its two commands (`review-run-did-not-stop`,
`review-stop-without-its-commands` otherwise). The harness then holds the
stop to what it promises: the disk online and read-only, `V:` mounted as
ReFS, a write to it refused (`review-stop-not-mounted-read-only-as-refs`),
and the volume listing as it did before the run, compared as a conversion's
listing is (`review-stop-listing-differs`; the listing is kept as
`manifest-review.jsonl`). Then it runs the command the stop printed, the one
that keeps the conversion or, with `-RecoverMode rollback`, the one that puts
NTFS back, and judges the result as `-InterruptAt` does: `resumed` (ReFS,
identical listing) or `rolled-back` (NTFS, `compare --exact`). The rollback
of a review run, after a stop or after a hold, also has to have recorded
`source_fingerprint_verified` in the `result.json` of the folder it names
(`rolled-back-without-the-fingerprint-check`; the file is kept as
`recovery-result.json`). `-Review -InterruptAt <point>` ends the run at the
hold instead, before it stops, and recovers it as any interrupted run;
`review-sealed` and `review-recorded` are holds of a review run alone. A
review run that is refused is judged as any refusal.

`-Tamper`, with `-Review`, writes to the volume after the stop: the disk's
read-only attribute is cleared (`Set-Disk -IsReadOnly $false`), a file is
written to `V:` (the disk is taken offline and brought back first where the
volume stays write-protected), the volume is written out and read-only is set
again (`review-tamper-not-made` if that cannot be done). Both commands are
then run, the one `-RecoverMode` names first. Each has to end with another
exit code than 0 (`review-tampered-<commit|rollback>-was-not-refused`), with
`not what it was when the run stopped for review` in its error
(`-refused-otherwise`) and with the disk offline and read-only and `V:` not
mounted (`-left-the-disk-unsealed`). The partition's bytes are hashed through
the disk before the first command and after the second and have to be the
same (`review-tampered-refused-but-partition-changed`): `nothing is done` is
read back, not taken from the message. All of that gives
`review-tampered-both-refused`. The two hashes read the whole partition, so
the round's tamper cases use `-PartitionMB 8192`.

The cases for the test round, and how each is run today:

| Case | Expected | Run by |
|---|---|---|
| `-Review` then commit | `resumed`, identical listing | the round: `review-commit` (lived-in, `-Acceptance`) |
| `-Review` then `--rollback` | `rolled-back`, `compare --exact`; recovery reports `source_fingerprint_verified` | the round: `review-rollback` (lived-in) |
| `-Review -Tamper`, commit | refused, nothing written, disk offline read-only | the round: `review-tamper-commit` |
| `-Review -Tamper`, `--rollback` | refused, nothing written, disk offline read-only | the round: `review-tamper-rollback` |
| `-Review`, disk set writable without a write, commit | refused at open (`online and writable`) | not by the harness yet |
| `-Review -InterruptAt apply-mid-ranges`, resume / rollback | as without a review: `resumed` / `rolled-back` | the switches; not a case of the round |
| `-Review -InterruptAt apply-before-handoff`, resume / rollback | as without a review | the switches; not a case of the round |
| `-Review -InterruptAt review-sealed`, resume / rollback | frozen source exactly NEW under the apply marker is accepted: `resumed` / `rolled-back` | the round: `review-sealed-resume`, `review-sealed-rollback` |
| `-Review -InterruptAt review-recorded`, resume / rollback | the same, and the stop's fingerprint is compared | the round: `review-recorded-resume`, `review-recorded-rollback` |
| `-Review -InterruptAt review-sealed`, the VM turned off, resume / rollback | as the process case | not by the harness yet (it ends the process; only the boot harness has `-InterruptKind vm`) |
| `-Review` with Explorer open on `V:`, commit | refused with the dismount message; closed, it commits | not by the harness yet |
| `-Review`, the control OS restarted at the stop, then commit / rollback | the disk comes back online read-only by itself; `resumed` / `rolled-back` | not by the harness yet |
| `-Review`, the recovery ended after it sealed the disk again, then recovery again (both directions) | the second recovery compares the fingerprint and finishes | not by the harness yet |
| `-Review`, the recovery ended after it made the disk writable (offline), then recovery again | as above, from offline writable | not by the harness yet |
| `-Review -Content lived-in`, `--rollback` | `rolled-back`, `compare --exact` | the round: `review-rollback` |
| `-Review -Siblings` | refused before anything is opened (a disk of its own only) | the switches, with `-ExpectRefusal`; not a case of the round |
| `-Review` with `--minimize-scratch` | refused by the parser | `-ConverterArgs --minimize-scratch`; not a case of the round |
| a default run at `apply-activated`, `handoff-sealed` | unchanged | `handoff-sealed` by the round; `apply-activated` by the switch |

The `scratch-standard` and `scratch-minimized` gate cases use the same 8 GiB
fixture. Compare `resources.peak_working_storage_bytes` in their verdicts.
`scratch-minimized-resume` and `scratch-minimized-rollback` interrupt apply
on the same fixture. Rollback requires an exact NTFS listing comparison.

`-StopDuringPreparation <phase>` ends the converter as soon as its progress
names that phase of preparation (`payload_supply`, `recovery_journal`, ...):
before it has printed a recovery command, and before anything is written to
the volume. The verdict records what the stop left (whether `V:` is mounted,
which disks are offline or read-only). Then, with `-AfterStop cancel` (the
default), the harness runs the command the run printed for this case at its
start (`To get it back as NTFS: ntfs2refs --recover ... --rollback`), and the
NTFS volume must be back and list exactly as before (`preparation-cancelled`).
With `-AfterStop restart` it first starts the same conversion again, as
someone does who did not see the run stop: that run has to be refused with
words that name the offline disk and `--recover`, and the cancellation is
run then (`restart-refused-then-cancelled`). Either way the cancellation has
to say what the run that was cut off left in the working directory, or the
outcome gets `-without-naming-what-is-left`.

Every attempt records what `ntfs2refs --list` says of the volume beforehand
(`list.txt`; the verdict has the volume's row). `-Unattended` runs the
converter as a script would, with `--yes --volume-serial <the serial number
--list printed>` and nothing typed at its prompt; a recovery gets `--yes`.
`-WrongSerial` gives it a serial number that is not the volume's, which has to
be refused before anything is opened (`-ExpectRefusal volume-serial`). The
`bitlocker` case also requires `--list` to say that the volume is encrypted.

`-Check` runs `ntfs2refs --check` on the volume before the attempt and keeps
what it printed (`check.txt`; the verdict has its exit code, its refusals and
its estimate). The attempt then goes on, and the two have to agree: a check
that found nothing before a conversion that is refused, or the reverse, adds
`-but-check-disagreed` to the outcome, and a check that named another refusal
than the conversion gave adds `-but-check-named-another-refusal`. `-CheckOnly`
runs the check alone: the volume has to list exactly as before and be as
long, online and writable as before (`check-clean`, `check-found-refusals`,
`check-refused-as-expected` with `-ExpectRefusal`, `check-inconclusive`,
`check-changed-the-source`). `-WriteLoad`, with `-CheckOnly`, writes files to
the volume and deletes them all the while the check reads it; the check may
find the volume at rest or not, and must not report a refusal that is not
there. A check must leave no working directory behind. `-FreshFile` creates a
file on the volume a moment before the check and waits for nothing: with
`-Features shortnames` the check has to count as many short names as Windows
lists, or the outcome is `check-missed-what-was-just-written`.
`-DeletedWhileOpen` has a program hold a file open that it has deleted while
the check reads: NTFS keeps such a file in a directory of its own until the
handle closes. The check has to say that it saw one and must not refuse the
volume for it (`check-refused-a-file-deleted-while-open` otherwise); the
handle is closed before the run.

Every listing says of each directory whether it is marked case-sensitive.
A run says before it begins whether it sets that mark on the new volume
(only on Windows Server 2025, #103). Where it said it does not, the listings
are compared with `lab-volume-manifest compare --case-marks-not-carried`,
which counts a mark that is gone and allows nothing else; no directory may
be marked afterwards, and as many must have been counted as were marked
before. Where the run carries the mark over, the comparison is the ordinary
one: a directory that lost its mark, or gained one, differs, and as many
must be marked afterwards as before (`case_marks` in the verdict).

A data volume's short names are dropped by default, as with
`-DropShortNames`, which runs the converter, and the check before it, with
`--short-names drop`; `-RefuseShortNames` runs both with `--short-names
refuse`, and the volume is then refused. Unless refused, the listings are
compared with
`lab-volume-manifest compare --short-names-dropped`, which counts a short
name that is gone and allows nothing else that the ordinary comparison does
not; the converted volume must list no short name, and as many must have
been counted as were listed before. `-Features shortnames-wide` puts short
names on nested directories, a hard-linked file, a file with a named stream
and a name outside ASCII, beside a name that is its own short name.

`-AcceptPlain` agrees to the list of objects the converter makes plain
files of (`-Features temporary`, `offline`). Unattended it passes
`--accept-plain` with the checksum `--check` printed, so it needs `-Check`;
otherwise the worker answers the run's question about the list as well as
its prompt. Without it, a run whose check printed such a list answers the
question no and has to stop there, exit 0 with the volume NTFS and listing
exactly as before (`plain-declined`); unattended, it is refused. The
check of such a volume exits 7 (`check-plain-to-agree` with `-CheckOnly`).
After the run the comparison is given the run's ledger
(`lab-volume-manifest compare --plain-ledger`): the objects it names are
left out of the listing comparison, which is otherwise unchanged, and each
is held by the content verdict to its record before with only the declared
feature taken off. Both have to be clean, and the ledger has to name exactly
the (kind, path) pairs the features planted (`plain` in the verdict).

`-VssProvider` gives the machine a shadow-copy provider the converter does
not know, as backup software does. `answering` is one of Windows Server's
own, the iSCSI target storage provider (the feature `iSCSITarget-VSS-VDS`,
so the VM has to run Windows Server): it answers and holds no shadow copy,
the volume converts, and the check and the run each have to name it in a
note. The harness installs the feature if it is missing and leaves it:
Windows wants a restart to finish removing it, so remove it when the cases
are done (`Uninstall-WindowsFeature iSCSITarget-VSS-VDS`, then restart the
VM). `silent` registers, for the length of the attempt, a provider whose
class does not exist: it cannot answer, and the volume has to be refused by
its name (`-ExpectRefusal`). The shadow-copy service reads its providers
when it starts, so the harness stops it after each change.

`-CompareListing` runs the converter with `--compare-listing`. The harness
makes its own listings as always, and the run's comparison has to say what
the harness's says, or the outcome gets `-but-own-listing-disagreed`.

`-Siblings` puts the source on a disk it shares with four other partitions:
an EFI system partition (FAT32, no letter), `W:` (NTFS), `X:` (NTFS,
write-protected in the partition table) and a partition of another operating
system (no file system Windows knows). Before the run and after it, or after
its recovery, `W:` is listed and compared exactly, the other three are hashed
through the disk, and `W:` and `X:` have to be back under their letters;
anything else adds `-but-siblings-changed` to the outcome. `-SiblingState`
arranges something about `W:` for which the disk has to be refused: `busy` (a
process keeps a file on it open), `snapshot` (a shadow copy of it, which has
to be there still afterwards) and `dump` (the running Windows' crash-dump file
is set to be on it, and set back when the attempt ends).

Every attempt compares the partition's length before and after. A refused run
that left it shorter is `refused-after-shrinking-the-partition`.

`-Content many` replaces the mixed content with two files that are past numbers
which used to be fixed: one with 200 named streams, and a sparse file with
`-Islands` separately allocated islands (70,000 by default), whose mapping
needs many file records.

`-Features <name,...>` adds what a volume that has been in use has, made by
`guest\Add-VolumeFeatures.ps1` after the content. These convert: `quota`
(quotas enforced, with an entry for one user: recorded, not carried over),
`objectids`
(a file with an object ID, and a shortcut to a file and to a directory, which
give their targets one), `manyobjectids` (`-DirectoryEntries` files with object
IDs, so that the volume's object-ID index outgrows its root), `security`
(explicit and deny entries, a protected directory, another owner, an audit
entry), `ea` (extended attributes), `links` (junction and symbolic links),
`longpath` (a path over 260 characters), `deep` (40 nested directories),
`bigdir` (`-DirectoryEntries` entries in one directory), `bigfile` (a dense
file of `-BigFileGB` GiB), `full` (a nearly full, fragmented volume), `copy`
(a directory of the control OS, copied with its security), `usn` (a change
journal), `casemark` (directories marked case-sensitive, none holding two
names that differ only by case, and an ordinary directory inside a marked
one), `casemark-root` (the root directory itself marked: no mark is set on
such a volume, and the run says so) and `shortnames-stripped` (8.3 names removed
with `fsutil`, the remedy the refusal gives). `-Content lived-in` is the mixed content with `copy`,
`objectids`, `security`, `ea`, `links`, `longpath`, `deep`, `bigdir` and `usn`.

`manyfiles` makes a volume for measuring how a run grows with the number of
files: `-FileCount` of them (500,000 by default) in directories of 1,000, nine
in ten small enough to live in their file record, the tenth of 4 to 36 KiB.
Every attempt records what its run took, sampled every two seconds: the
converter's peak memory and the working storage at its largest (`resources`
in the verdict).
The verdict also retains each worker's reported ledger peaks and
`memory-steps:` lines when available. The conversion's ledger appears in
`resources` and the recovery's in `recovery_resources`. `ledger_complete`
is true when the worker printed its final memory summary.
For `manyfiles`, `worker-resources.jsonl` also records each observed converter
process's handle count, working set, private bytes and cumulative process I/O,
along with guest committed memory, the guest commit limit and working storage.
The executable path, process ID and start time distinguish a conversion from
its recovery. The I/O counters cover all transfers by that process.
An interrupted `manyfiles` attempt passes the conversion's explicit
`--memory-limit` to recovery as well.
When `-SampleStacks` is used on an interrupted run, the last profile written
before the cut is collected as `interrupted-stacks.txt` when available.
The recovery writes its own `stacks.txt`.

`cloud` and `cloud-down` make a sync root of the lab's own Cloud Files API
provider (`lab-cloud-provider.exe`, built with `--bin lab-cloud-provider`
and copied beside the converter), backed by a folder on the control OS's
C:, with placeholders fully present, partly present, not present and pinned,
and a folder of them. `cloud` leaves the provider running: with
`-AcceptPlain` the run downloads the two that are not wholly present before
the freeze, lists the volume itself after that (`--compare-listing`), and
that listing is the one the new volume is compared with. `cloud-down` stops
it: the unattended run tries to download the two, names both, and stops
before the freeze with the source unchanged; with `-LeaveOutCloud` as well (and `-Check -AcceptPlain
-Unattended`, whose check prints the list's checksum) it passes
`--leave-out-cloud` and converts without them, each declared
`cloud_left_out` and absent afterwards (`cloud-down-leave-out`). The harness stops the provider and unregisters the sync root
when the attempt ends. A Cloud Files provider serves only the account that
runs it, and the feature step starts it as the account the harness works as:
run `cloud` with `-RunAs administrator`. A provider connected in one logon session does not serve
another, so the harness stops the feature step's provider and starts one in
the converter's own worker session, which has to download `probe.bin` (a
small placeholder of `cloud`) before the converter starts
(`cloud-provider-not-serving` otherwise). A connected provider holds its sync
root open, so the volume cannot be locked while it runs: the harness stops it
as soon as the converter prints its `cloud-downloads-done-v1` line, as a user
closes OneDrive when the run asks (an unattended run waits up to 5 minutes
for the lock, naming the holders). The provider's status is shown
(the check, and `lab-cloud-provider report` before the run), never a gate.
The listing descends into placeholder folders, so it lists a sync root's
contents whether its provider runs or not. The harness checks that the
provider is still serving before it starts the converter. Both are still to be run.

`temporary`, `offline` and `wof` (four `compact /exe` files, one per WOF
algorithm, listed before the run in `wof-listed-before.jsonl`) convert with
`-AcceptPlain`; without it a run stops before it changes anything. So does
`efs`, with `-RunAs administrator` as well: the file is encrypted by the
guest account the harness works as, and only that account holds its key. The
converter runs as SYSTEM otherwise, which holds none, and is then refused by
name with the source unchanged (`efs-nokey`). These are refused, each by
name: `shortnames` with `-RefuseShortNames`, `casesensitive` (two names in one
directory that differ only by case), `snapshot`,
and `bitlocker`. `dirstream` (named streams on two directories, one of about
1 MiB) converts since `ds3-dirstream-minimal` and `ds3-dirstream-lived-in`
showed it. A feature that cannot be made ends the attempt as
`feature-not-made`: it is never skipped silently. A volume with shadow copies
or BitLocker holds files of Windows' own that nothing may open; when those are
the only differences of a refused volume, as many before as after, the attempt
is still `refused-source-unchanged`. Run `bitlocker` last: Windows then writes
its recovery folders to every volume that arrives afterwards.

Five features are made on the disk itself, by `guest\Use-RawNtfs.ps1`, after
the listing and any `-Check`, just before the run: the disk is taken offline
(a clean dismount), the bytes are read or written, the disk is brought back
and the volume is listed again. `lfs2` sets the control OS's
`HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\NtfsDisableLfsDowngrade`
to 1 before the volume is made and puts back what was there when the attempt
ends; at that dismount the two `$LogFile` restart pages have to read LFS 2.0
(major at 0x1c, minor at 0x1a) and carry the clean-dismount flag, or the
attempt ends `lfs2-not-produced`. `lfs2.json` holds both pages; the verdict's
`lfs2.run_read` the LFS versions the run's own records name, and a converted
run whose records name only another one ends `...-but-run-read-lfs-<v>`.
Whether NTFS reads the value without a restart is not known: with
`-RestartForLfs2` the control OS is restarted after it is set and again after
it is put back (about a minute each). `ntfs30` writes `$Volume`'s version
(bytes 8 and 9 of its `$VOLUME_INFORMATION`) as 3.0 in MFT record 3 and in
`$MFTMirr`, through the update-sequence fixups and with the record's own
sequence number; `ntfs30.json` holds both copies before and after and what
the disk reads once Windows has the volume mounted again. If that is already
3.1, the attempt ends `ntfs30-upgraded-by-windows-before-the-run`. Its
records keep the NTFS 3.1 header form, so it shows a 3.0 volume that
Windows XP or later has written to. `ntfs30-headers` first rewrites every
in-use FILE record of `$MFT` (found through `$MFT`'s own runs, so a
fragmented `$MFT` is followed; one whose mapping goes on through an
attribute list is refused by name) from the 3.1 header form (record number
at 0x2c, update sequence array at 0x30) into the 3.0 form (no number, the
array at 0x2a): the array moves with the record's own sequence number and,
with `-Ntfs30HeaderLayout packed` (the default, as Windows 2000 lays a record
out), the attributes move down to the first 8-byte boundary after it (0x30
for 1 KiB records, 0x38 in the 3.1 form), the first-attribute offset and
bytes in use with them; `in-place` leaves them where they were. The bytes
from 0x2a to the first attribute are the array and zeros, and each record
is read back and held to differ in nothing else. A record whose first
attribute starts before 0x38 stops it. `-Ntfs30HeaderFrom 16` rewrites only
records 16 and up, leaving the system files in the 3.1 form. Each
`$MFTMirr` slot whose record was rewritten and held the same bytes is
rewritten the same way and held equal to it; an inactive template slot is
left. Then `$Volume` is set to 3.0 as for `ntfs30`. `ntfs30.json` adds the
layout, the counts, `$MFT`'s runs (up to its initialized length) and each
rewritten record's SHA-256 before and after; it is kept whatever follows.
If the volume is not back at V: within 60 s, the attempt ends
`ntfs30-headers-volume-not-mounted`; `raw-feature-diagnostics.json` holds
the disk's partitions and volume (file system, letter, health),
`fsutil fsinfo ntfsinfo` and `fsutil dirty query` where it mounted, the
System and NTFS Operational log entries since the disk went offline (NTFS,
chkdsk and storage providers, and IDs 55, 98, 130, 137), and the raw headers
of records 0, 1, 2, 3, 5 and the first rewritten ones (it is written for
every `ntfs30-headers` attempt). Once Windows has the volume mounted again
and it is listed, every in-use record is read again; if any rewritten one
reads the 3.1 form, the attempt ends
`ntfs30-headers-rewritten-by-windows-before-the-run` (records Windows
newly allocates on mount may be in the 3.1 form: the verdict counts them,
and the converter reads both). For both features the converter reads
NTFS 3.0 itself: a run has to end `converted` (ReFS, listing identical)
without `ntfs-version-intent.json` or `ntfs-version-after.json` in its
records, or a converted run ends `...-but-ntfs-upgrade-attempted`.

The two NTFS 1.2 (Windows NT 4.0) features find out first whether Windows 11
mounts such a volume at all. `ntfs12-version` writes 1.2 into `$Volume` of
the volume Windows formatted, as `ntfs30` writes 3.0. `ntfs12` writes a
whole NT 4.0-layout volume over the partition (`write-image`): the head of
the volume `tests/support/ntfs12.rs` lays out for the partition's length
(no `$Extend` or `$Secure`, record 9 `$Quota`, a descriptor on every file,
48-byte standard information, 3.0-form record headers, NT 4.0's
`$AttrDef`, a `$LogFile` of 0xff for NTFS to initialize, and `README.TXT`,
`BIG.BIN` and `SUB\INNER.TXT`), with its boot sector again in the
partition's last sector, each read back. Make it first, for the partition
`-PartitionMB` gives (2048 MiB is 2147483648 bytes):

    $env:N2R_NTFS12_IMAGE = "$PWD\.lab\ntfs12-2048.img"
    $env:N2R_NTFS12_PARTITION_BYTES = 2147483648
    cargo test --locked --test it ntfs12::write_the_lab_ntfs12_image -- --ignored

and give it as `-Ntfs12Image`. For both, `ntfs12.json` holds what was
written, what the disk reads once Windows has the volume back (its
version, the header form of every in-use record, and records 0, 1, 2, 3
and 5 whole, so that a synthetic volume's can be set beside those of one
Windows made), and
`raw-feature-diagnostics.json` what Windows made of it (the volume's file
system and letter, `fsutil fsinfo ntfsinfo`, NTFS's event-log entries). If
V: is not back within 60 s the attempt ends `ntfs12-volume-not-mounted`.
Windows goes on writing to an NTFS 1.2 volume it has mounted (it makes
`$Extend`, `$RmMetadata` and the TxF log in it, leaving `$Volume` at 1.2),
so the listing before the run is taken once two listings five seconds
apart agree (up to two minutes, else `ntfs12-volume-did-not-settle`), and
the volume's health and dirty bit are then read: a volume Windows leaves
dirty or unhealthy ends the attempt `ntfs12-fixture-unhealthy-after-mount`,
the fixture's failure rather than the converter's. With `-Ntfs12Chkdsk` such
a volume is first given `chkdsk V: /f /x` (dismounted for it, nothing
scheduled), as the converter's refusal tells a user to: its whole output is
kept in `chkdsk.txt`, the version and health before it in the verdict's
`ntfs12.before_chkdsk`, and the volume is settled, read and judged again;
if it is then healthy the run goes on, and `ntfs12.chkdsk.version_after`
says whether chkdsk left it 1.2. Every `ntfs12` and `ntfs12-version`
attempt also keeps, as the disk holds them once the volume has settled
(after chkdsk where it ran), record 9 whole in `ntfs12.json` and the
`$UpCase` table and `$Secure`'s `$SDS` as files, `upcase.bin` and `sds.bin`
(the latter where there is one), to set beside a volume Windows made;
and, once the run is over and where the volume is still NTFS, every
record from 16 on whole in `ntfs12-after-run.json` (Windows makes the TxF
resource manager's files while the run reads the volume).
Otherwise the verdict's
`ntfs12` says in what version and state Windows left it, and the run goes
on to convert it. The image carries the `$AttrDef` Windows writes (with
`$OBJECT_ID`, `$REPARSE_POINT` and `$LOGGED_UTILITY_STREAM`, which Windows
then uses on it); `$env:N2R_NTFS12_ATTRDEF = 'nt4'` makes it NT 4.0's
fifteen definitions instead, with which Windows 11 left the volume dirty
(`n12-image-2`). None of the five is for
`-NativeRefsControl` or `-CheckOnly`, and only one of `ntfs30`,
`ntfs30-headers`, `ntfs12` and `ntfs12-version` is given at a time.

The volume gets a fixed set of content: files around every size boundary, a
nested tree with non-ASCII and long names, named streams, hard links, a sparse
file, LZNT1-compressed files (on clusters up to 4 KiB, where NTFS compresses),
fragmented files, and attributes and times that are not the defaults. It is
listed with `lab-volume-manifest`, converted, listed again and compared.
Outcomes: `converted` (ReFS, listing identical), `converted-but-listing-differs`,
`refused-source-unchanged` (the NTFS volume lists exactly as before, compared
with `--exact`), `refused-as-expected`, and named failures. The verdict records
the geometry NTFS reported, the ReFS version and cluster size afterwards, and
the partition's length before and after. The volume and the run's working files
are removed afterwards unless `-KeepVolume` is given.

Before the first listing the volume is mounted afresh and listed when Windows
has written its own files into `System Volume Information` (the indexer's, and
on a volume with junctions the mount manager's database) and two listings in a
row find as many entries there. A volume made a moment ago would otherwise get
them when it next mounts, which is after the conversion, and the directory's
changed times would show as a difference.

`-Acceptance` uses a volume whose conversion gave an identical listing, with
`guest\Test-ConvertedVolumeUse.ps1`: it reads a sample of what was converted,
creates 1,500 files and reads them back, appends to, overwrites and truncates
converted files, renames and deletes, makes a named stream, a hard link,
symbolic links, an access entry and a sparse file, writes up to 6 GiB and
frees it again, makes and reads a shadow copy, runs the consistency scan
Windows offers, takes the volume offline and brings it back five times, reads
the converted files again, and looks for ReFS errors in the event log. A
failed step makes the outcome `converted-but-use-failed`; `acceptance.json`
has every step. `-NativeRefsControl` is its control: nothing is converted,
Windows formats the volume as ReFS itself, the content goes on it (`-Content
minimal` with features ReFS can hold) and the same use test runs
(`control-passed`, `control-use-failed`). A step that fails there too is how
ReFS or this Windows behaves, not what a conversion left.

`-Diagnose` builds the shadow, lists every per-object failure and stops before
publication, writing nothing to the source. It ends `diagnose-clean` (exit 0) or
`diagnose-found-failures` (exit 3) only once the source is the same online NTFS
partition and lists exactly as before.

`-ShapeSource <script>` runs a script from `lab\guest` against the source
before it is listed, to give it objects a fresh Windows does not have:
`Add-NamedStreams.ps1` (the lab volumes have no named streams),
`Add-UsedWindowsObjects.ps1` (a tree 25 directories deep, 320 object IDs and
two shortcuts: the installed Windows has no directory deeper than 16 and an
object-ID index of one block), and `Add-DirectoryStream.ps1` (a directory
with a named stream, which converts as the same directory's named stream).

`verdict.json` lists every piece of evidence an attempt retains with its size
and SHA-256, or the reason it is missing. A success without its required
evidence is `incomplete-evidence`.

A missing before-listing is `converted-not-compared`, not a successful independent
comparison. A run is complete only when its verdict and the applicable native
checks agree. Do not widen the manifest allow-list to make it pass.

## The Windows a VM runs from

`Invoke-RunningWindowsAttempt.ps1` converts `C:` of the Windows a lab VM
starts from, with the one command a user gives in that Windows
(`ntfs2refs --drive C --scratch-directory <working volume>\runs-<Name>
--boot-partition <letter>`), and waits through the restarts: the VM's own
recovery environment, where the conversion runs and no remote session
exists, then Windows again.

```powershell
lab\Invoke-BootConversionAttempt.ps1 -Name c-work -NoConvert -KeepScratch -ScratchFileSystem NTFS -VmId <vm>
Stop-VM -Id <vm>
lab\Invoke-RunningWindowsAttempt.ps1 -Name c-01 -VmId <vm> -Binary <frozen>\ntfs2refs.exe `
    -ScratchVhdx .lab\hyperv\attempts\c-work\scratch.vhdx -Restore -Acceptance -Reattach
```

The working disk is the NTFS scratch disk of a control-OS attempt, named
with `-ScratchVhdx`; a 1 GB disk for the boot partition is made beside it
once and kept. The attempt detaches the VM's other disks and its
installation media for the run (they are listed in `detached-disks.json`,
and with their places in `.lab\hyperv\detached-disks-<vm>.json`, the record
the boot harness keeps too).

- `-Restore` restores the VM's `N2R-Qualification-NTFS-*` checkpoint first
  (`-Checkpoint` names another), after putting back the differencing disks an
  earlier attempt detached, so that Hyper-V discards them with that attempt's
  state. Without it the attempt starts from whatever the VM is.
- Before the run, the folders earlier attempts left on the working volume
  are removed: `runs-*`, `ntfs2refs-preparation-cancel-*` and
  `ntfs2refs-recovery-*`, a virtual disk under one detached first. They are
  the attempts' own scratch; the verdict's `working_volume` says what went
  and what could not be removed.
- Windows has two minutes to show the working volume (`N2R_SCRATCH`) under
  a letter. Where it does not, its disk is looked for by the working disk's
  size: one that is offline or read-only is brought online and writable,
  and its volume is given a letter; `before.working_disk` in the verdict
  says what was seen and what was changed, and an attempt that still finds
  no volume says whether the disk was there (#228). After a restore the
  attempt waits, up to a minute, until Hyper-V shows the restored drives
  (`restored_drive_view_settled`, and `drives_at_start` is what the VM
  started with); a drive add refused for its place is tried again for half
  a minute, and a DVD drive at the place of a disk to be returned is moved
  out of the way.
- `-Diagnose` runs with `--diagnose`: `C:` has to come back as NTFS.
- `-HoldAt <point>` arms that hold (`crates/n2r-win32/src/lab_hold.rs`) for
  the converter in the environment and turns the VM off when the converter
  is parked there, as if the power had gone; the VM is started again and the
  run has to recover by itself. The hold is seen from outside: the VM's
  screen (the picture Hyper-V gives of it, as `Send-VmKeys.ps1` takes it) has
  not changed for two minutes, apart from the few pixels of a blinking
  cursor, and `-HoldAfterMinutes` (5) have passed since the restart.
  `-CutAfterMinutes` (40) after the restart the power is cut whatever the
  screen shows. `screen-at-cut.png` is what it showed. Once Windows is back,
  the converter's own output (`converter-output.txt` on the working disk,
  copied to the records with what its recovery said) has to have the hold's
  line, or the outcome is `CUT-NOT-AT-THE-HOLD`.
- `-HoldAt none` arms no hold: the power is cut `-CutAfterMinutes` after the
  restart, wherever the run is then.
- `-Acceptance`, when `C:` came back as ReFS, runs
  `guest\Test-ConvertedWindowsUse.ps1` in that Windows with the installation
  media attached again, then shuts it down and starts it twice more, as the
  boot harness does after its boot. `acceptance.json` and the verdict have
  every step; a step that failed adds `-BUT-USE-FAILED` to the outcome.
- `-Reattach`, when the attempt ends, however it ends, shuts the VM down and
  gives it back the disks and the media, each in its place, and the device
  it started from.
- Once Windows is back, the verdict's `after.run_images` says of every
  virtual disk in the run's folder whether that Windows has it attached, or
  why Windows would not say (a finished run or recovery detaches its working
  volume, #182).
- `-Hold` stops at a command prompt in the environment instead
  (`held-in-the-environment`), to be typed into with `Send-VmKeys.ps1`.

Outcomes: `PASSED` (`C:` is the file system the run was to leave, ReFS, or
NTFS with `-Diagnose`, it is healthy, and the converter ended with 0),
`CONVERTER-EXIT-<n>`, `C-IS-<file system>` and `C-IS-<file system>-<health>`,
`REFUSED-IN-WINDOWS` (nothing restarted), `no-return` (Windows did not come
back with the run's report within `-AwayMinutes` of the restart, or of the
power cut; `screen-no-return.png` is what the VM showed). After a cut, what the start after it reported has to
agree with what `C:` is: `CUT-RECOVERED-TO-REFS` (it finished the
conversion; ReFS, healthy), `CUT-BACK-TO-NTFS` (it cancelled a run that had
not started writing, or put NTFS back; NTFS, healthy),
`CUT-RECOVERY-UNCLEAR-C-IS-<file system>` (anything else),
`CUT-BEFORE-THE-RUN-BEGAN` (that start found nothing to recover from: the
cut came before the converter had printed a way back, and the run simply
began again) and `RUN-ENDED-BEFORE-THE-CUT` (Windows was back before the
power was to go). A verdict is written however the attempt ends; an error of
the harness leaves `harness-error` with the error, and `result` has the
outcome that stood when it happened.

## Storage and preservation

Each attempt writes `.lab/hyperv/attempts/<Name>/`. Choose a new name. The full
attempt requires at least 65 GiB free on the host; the fixture requires 40 GiB.
The harness sizes memory from available host RAM and uses a dynamic scratch disk.
These are laboratory requirements, not a universal product-space estimate.

`-KeepScratch` retains the scratch disk for inspection and evidence recovery.
Before any cleanup, preserve the verdict, progress, source and target listings,
comparison report, binary hashes, recovery output and boot evidence with hashes.
Do not delete the reference baseline checkpoint: the second VM's disks depend
on its parent chain. Ask before deleting `.lab` artifacts.

## Building a release

`New-Release.ps1` builds the release of the version in `Cargo.toml` from a
clean checkout of the commit that carries that version as its tag: the ZIP
(both executables, `capabilities.json`, the README, the guide, the two
matrices and the notes), its SHA-256 file, a source archive and
`RELEASE-NOTES.md`. The notes are generated from what the executable's
`capabilities` reports and name the matrices; nothing in them is typed by
hand. It refuses a tree with uncommitted changes and an executable that
reports another version, and it publishes nothing: it ends by printing the
two commands that would.

```powershell
lab\New-Release.ps1 -AllowUntagged                     # a rehearsal of any commit
lab\New-Release.ps1 -ComparedWith <dir of the lab's build>
```

The lab runs a frozen copy of a build, made before the commit exists.
`-ComparedWith` names that copy: the release's executables have to equal it
byte for byte apart from the stamps the linker puts into every link (its
time, the checksum, the PDB's signature), and the notes then say so.

## The reference VM and the fixtures

`Provision-IsolatedReference.ps1` built the reference VM, and
`Test-IsolatedReferenceReadiness.ps1` checks it (both with `Lab.psm1`,
`IsolatedBaselineGuards.psm1` and `lab.config.json`).
`New-ThinnedWindowsFixture.ps1` makes the thinned fixture checkpoints the
harness restores, with `guest\Thin-WindowsSource.ps1`.

## Earlier stages

The scripts of the earlier stages were written for one VM or checkpoint each,
and those are gone. They are no longer in the tree: [RETIRED.md](RETIRED.md)
names the tag that has them and the VMs they were for, and a test fails if a
script here names one of those VMs.

The earlier lab procedures and budgets are preserved in
[the historical guide](../docs/history/lab-README-before-boot-alpha-closeout-20261111.md).
