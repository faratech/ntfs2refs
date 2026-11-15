# Hyper-V qualification lab

The current route is `Invoke-BootConversionAttempt.ps1`. It restores a disposable
NTFS baseline, runs the converter from a separate control OS, compares independent
before/after volume listings, and optionally boots the original source disk alone.
See [AGENTS.md](../AGENTS.md) for the VM identities and standing rules, and the
[feature matrix](../docs/feature-matrix.md) and the
[recovery matrix](../docs/recovery-matrix.md) for what the attempts have shown.

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
records. `-TearMarker handoff`, with `-InterruptAt apply-handoff-durable`, leaves
the journal's handoff marker as a write that stopped part-way leaves it, so that
recovery has to settle it first.

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
`-ConverterArgs`, `-Binary`, `-ManifestBinary` and `-SampleStacks` mean what
they mean to the boot harness. `-ExpectRefusal <pattern>` is for a volume the
converter must refuse.

`-InterruptAt <point>` (for example `apply-mid-ranges` or `handoff-sealed`)
ends the converter when it reports that it is held at that point, then runs the
recovery command the run printed: `-RecoverMode resume` (the default) must end
with ReFS and an identical listing (`resumed`), `-RecoverMode rollback` with the
NTFS volume listing exactly as before (`rolled-back`). `-Diagnose` runs the
converter with `--diagnose`; whatever it reports, the volume must list exactly
as before (`diagnose-clean`, `diagnose-found-failures`).

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

`-DropShortNames` runs the converter, and the check before it, with
`--short-names drop`. The listings are then compared with
`lab-volume-manifest compare --short-names-dropped`, which counts a short
name that is gone and allows nothing else that the ordinary comparison does
not; the converted volume must list no short name, and as many must have
been counted as were listed before. `-Features shortnames-wide` puts short
names on nested directories, a hard-linked file, a file with a named stream
and a name outside ASCII, beside a name that is its own short name.

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
`guest\Add-VolumeFeatures.ps1` after the content. These convert: `objectids`
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
names that differ only by case) and `shortnames-stripped` (8.3 names removed
with `fsutil`, the remedy the refusal gives). `-Content lived-in` is the mixed content with `copy`,
`objectids`, `security`, `ea`, `links`, `longpath`, `deep`, `bigdir` and `usn`.

`manyfiles` makes a volume for measuring how a run grows with the number of
files: `-FileCount` of them (500,000 by default) in directories of 1,000, nine
in ten small enough to live in their file record, the tenth of 4 to 36 KiB.
Every attempt records what its run took, sampled every two seconds: the
converter's peak memory and the working storage at its largest (`resources`
in the verdict).

These are refused, each by name: `shortnames`, `temporary`, `offline`, `efs`,
`wof` (a `compact /exe` file), `quota`, `casesensitive` (two names in one
directory that differ only by case), `snapshot`,
`bitlocker` and `dirstream`. A feature that cannot be made ends the attempt as
`feature-not-made`: it is never skipped silently. A volume with shadow copies
or BitLocker holds files of Windows' own that nothing may open; when those are
the only differences of a refused volume, as many before as after, the attempt
is still `refused-source-unchanged`. Run `bitlocker` last: Windows then writes
its recovery folders to every volume that arrives afterwards.

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
object-ID index of one block), and `Add-DirectoryStream.ps1`, which the
converter must refuse by name at admission.

`verdict.json` lists every piece of evidence an attempt retains with its size
and SHA-256, or the reason it is missing. A success without its required
evidence is `incomplete-evidence`.

A missing before-listing is `converted-not-compared`, not a successful independent
comparison. A run is complete only when its verdict and the applicable native
checks agree. Do not widen the manifest allow-list to make it pass.

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

## Older scripts

Most of the other scripts here were written for one VM or checkpoint of an
earlier stage, and that VM or checkpoint is gone. [RETIRED.md](RETIRED.md) lists
the 161 that cannot run; do not start from one. They are kept unchanged as the
record of those stages, and a test fails if a script names a retired VM without
being listed.

The earlier lab procedures and budgets are preserved in
[the historical guide](../docs/history/lab-README-before-boot-alpha-closeout-20261111.md).
