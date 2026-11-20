# Operating and recovery guide

For ntfs2refs 0.0.1. **It is experimental software:** every run starts with
a warning saying so, on the error stream, and [DISCLAIMER.md](../DISCLAIMER.md)
says what that means. [The README](../README.md) says what the tool is;
this guide says how to run it, what it refuses and why, and what to do if a
run stops. What the lab has shown is in the [feature matrix](feature-matrix.md)
and the [recovery matrix](recovery-matrix.md).

## Before you start

1. **Have a backup you have restored from.** This is a beta, and every volume
   it has converted was a virtual disk.
2. **Windows build 26100 or later** (Windows 11 24H2, Windows Server 2025),
   and an **elevated terminal**. Both are checked before a disk is opened; an
   older build is refused by name. Conversions were run on builds 26100
   (Windows Server 2025) and 26300 (Windows 11). On another build, or when
   Windows formats a ReFS other than 3.14,
   the run says before it starts that the lab has not tried that.
3. **Working storage on another disk**, given with `--scratch-directory`.
   The run builds the new file system there, on a virtual disk as large as the
   volume that takes only the space its contents need, and keeps there the
   old content of every sector it changes. Leave it alone until the
   conversion has finished and you have looked at the result.
4. **The volume's layout.** A data volume has to be on a disk that is not
   the disk of the running Windows. The disk may be GPT or MBR (on MBR, a
   primary partition) and may hold other partitions; they
   [go offline with it](#a-disk-with-other-partitions) while the run lasts.
   The working directory may be on a GPT or an MBR disk.

The lab's Windows volume, with 22.9 GB in use in 191,000 files and
directories, took 28 minutes, about 30 GB of working storage and 2.1 GB of
memory in a machine with 24 GB. These are measurements of that volume, not
bounds: see [how large a volume can be](#how-large-a-volume-can-be).

## Look first: `--list`

```powershell
.\ntfs2refs.exe --list
```

It lists every disk and partition and says for each NTFS partition whether a
conversion would take it and, if not, why: it is the running Windows, or
shares its disk with it. For a volume on a disk with other partitions it says
how many go offline with it. Each volume is shown with its serial number.

Windows reports a volume encrypted with BitLocker as NTFS. From an elevated
terminal `--list` reads each partition's first sector and says where that is
so; without elevation it says that BitLocker was not checked. A run finds it
either way, in its first second.

`--list` exits 0 when every disk and volume answered, and 4 when some device
could not be queried: the list it printed is then partial.

## Check first: `--check`

```powershell
.\ntfs2refs.exe --drive E --scratch-directory S:\runs --check
```

A check reads a data volume while it stays online and in use. Nothing on it
is frozen, formatted, shrunk or written; the check keeps its own pages in the
working directory while it runs and removes them. It first asks Windows to
write out what it still holds in memory for the volume, so that a file saved
a moment ago is read too. It reads the volume's NTFS
structures, asks Windows about shadow copies and about each directory, and
reads no file's contents: half a second on the lab's small volumes, 11
seconds on one of 23,000 files. It prints:

- **Every reason a conversion would refuse the volume** that those decide,
  each as the conversion would give it, with the file and what to do: 8.3
  short names; encrypted, temporary, offline or `compact /exe` files; reparse
  points, streams and names the converter does not carry over; quotas in use;
  two names in a directory that differ only by case; shadow copies, and a
  shadow-copy provider of backup software that holds one or does not
  answer; a volume marked dirty. On a disk with other
  partitions also what keeps the disk from going offline: a page file or
  the crash-dump file of the running Windows on it, and shadow copies of a
  volume beside this one.
- **What is decided only when the volume is frozen** for a conversion: that
  the NTFS log closes cleanly, the backup boot sector and the MFT mirror, an
  open transaction, whether quota management is switched on, and that Windows
  shows every file as the raw volume holds it.
- **What a conversion would take:** the number of files, directories and
  streams; how much data stays where it is and how much is copied, for the
  cluster size asked for (`--target-cluster-bytes`); the working storage and
  the free memory it needs at least; and a range for the time, from the lab's
  runs on virtual disks.

On a volume in use a program may have deleted a file that it still holds
open. Windows keeps such a file until the program closes it. The check does
not count it and does not refuse the volume for it: a conversion takes the
volume offline first and never meets it. A note says how many there were.

A lab volume that had been in use (the conversion that followed took 2 min
16 s):

```text
Nothing was found that a conversion refuses.
The reading took 11.0 s (shadow copies 0.0 s, file records 9.8 s, NTFS's own indexes 0.6 s, counting, and asking each directory 0.2 s, each file and directory 0.5 s, the volume's conditions 0.0 s).
Note: 3 file(s) and directories have an object ID (Windows gives one to the target of a shortcut). ReFS has no object IDs: a conversion keeps them in its records and does not carry them over.
Decided only when the volume is frozen for a conversion: that the NTFS log closes cleanly, ...
What a conversion would take:
  20732 file(s), 2403 directories, 20735 data stream(s); 432 MiB of data.
  To 4 KiB ReFS clusters: 366 MiB stay where they are, 3 MiB are copied, 63 MiB are holes of sparse files and stay holes.
  Working storage: at least 4102 MiB (4 GiB and what is copied, twice); 117.1 GiB are free there.
  Memory: at least 95 MiB free; 15.3 GiB are free now.
  Time: roughly 2 min to 4 min, from the lab's runs on virtual disks; a slower disk takes longer.
```

| Exit code | Meaning |
| ---: | --- |
| 0 | Nothing was found that a conversion refuses |
| 3 | A conversion would refuse the volume; each reason is printed |
| 5 | The volume changed during every reading: nothing is known, and nothing is refused |
| 1 | The check could not be made |

A volume that is being written to can change between two of the structures a
check joins. The check then waits and reads the volume again: up to four readings,
2, 5 and 10 seconds apart. If the volume never held still it says so and
exits 5; it does not report a refusal it could not confirm. What the
inspection itself decides against (a reparse point it does not recreate, two
names that differ only by case) is read twice and then reported, because a
conversion would find it too.

The working-storage figure is a floor, not a forecast: the lab's Windows
volume, with 22.9 GB in use, used about 30 GB.

## Rehearse: `--diagnose`

```powershell
.\ntfs2refs.exe --drive E --scratch-directory S:\runs --diagnose
```

A diagnose run does everything a conversion does up to the point where it
would publish: it inspects the volume, builds the complete ReFS file system in
the working directory, and reports every file it could not carry over instead
of stopping at the first. ntfs2refs writes nothing to the volume, which is
offline and read-only meanwhile and is returned as NTFS.

| Exit code | Meaning |
| ---: | --- |
| 0 | Every object was examined and none failed |
| 3 | Failures were reported, or the run stopped at its failure limit |
| 1 | The diagnosis itself could not finish |

The run stops after 500 failures, when it is rarely learning anything new.
`--diagnose-limit N` changes that number, and `--diagnose-limit 0` lists every
failure on the volume.

A diagnose run of a data volume makes the check of `--check` first, as a
conversion does, and stops there if that refuses the volume.

A diagnosis never shrinks a partition, and the ReFS file system has to be
built at the length the partition has when it is converted. So where a
conversion would first shrink the partition (see below), a diagnose run of a
data volume makes the check of `--check` alone and says so; of a Windows boot
volume it is refused before anything is started. It is also refused with
`--minimize-scratch`. It does not exercise the journal, the writes to the
volume or a boot.

## Convert a data volume

```powershell
.\ntfs2refs.exe --drive E --scratch-directory S:\runs
.\ntfs2refs.exe --drive E --scratch-directory S:\runs --target-cluster-bytes 65536
```

`--drive` takes a drive letter, or a disk number with `--partition`. The run
shows the disk, the partition, its size and label and what it is about to do,
checks the volume as `--check` does, and asks for confirmation. A volume the
check refuses is refused there, online and untouched. Then:

1. Windows formats a ReFS volume of the size the partition will have on a
   virtual disk in the working directory. If Windows will not format it, the
   run stops with the volume untouched.
2. The volume is taken offline and read-only, and inspected again. Anything
   that only the frozen volume shows is refused here, with the volume
   returned as NTFS.
3. Every file and directory is created on the new ReFS volume through
   Windows. File data that can stay where it lies on the disk is not copied.
4. The run works out which sectors of the volume the new file system needs,
   saves their present content, and checks everything it has prepared.
5. It prints the recovery command. Keep it.
6. It writes the new file system onto the volume, checks the result, and
   brings the volume online as ReFS under its drive letter and label.

Until step 5 the volume is NTFS and unchanged, with one exception:

**A partition whose length is not a multiple of 64 MiB is shrunk first.** ReFS
covers a volume in whole units of that size, so the converter asks the Windows
NTFS driver to shrink the partition to one, by less than 64 MiB. It says so,
with the sizes, before the confirmation prompt, and does it only after the
check has found nothing that refuses the volume and Windows has formatted the
working volume (between steps 1 and 2). The shrink is not undone if the run
stops later.

- **Source geometry.** Any that Windows formats NTFS with: clusters from 512
  bytes to 2 MiB, 512-byte or 4096-byte (4Kn) sectors, 1 KiB or 4 KiB file
  records.
- **What stays in place.** Data that lies on boundaries of the target's
  cluster size. Everything else is copied through the working storage: from
  NTFS clusters smaller than the target's that is most of the volume, and the
  working storage needs room for it. From clusters of 4 KiB or more to a
  4 KiB target, and of 64 KiB or more to a 64 KiB target, file data stays
  where it is.

### A disk with other partitions

A data volume may share its GPT or MBR disk with other partitions: more data
volumes, an EFI system partition and a recovery partition left from the time
the disk was a computer's own, a partition of another operating system. The
run still takes the **whole disk** offline, because that is the only way
Windows keeps everything else from writing to the volume. For the volumes on
the other partitions this means:

- They are dismounted before the disk goes offline, and are not available
  until the run ends. For part of the run Windows shows them, read-only.
- Nothing is written to them. The lab compares them before and after every
  run on such a disk: the listing of an NTFS volume beside the source, and
  the bytes of a write-protected volume, an EFI system partition and a
  partition of another system.
- If the run is cut off, they stay offline with the disk until the run is
  finished or undone with `--recover`.
- A BitLocker volume among them is locked when the disk returns, as it is
  after a restart; unlock it as usual. (Not a lab case.)

The run names those partitions and says this before it asks, and so does
`--check`. On the lab's disk:

```text
This volume shares disk 5 with 4 other partition(s): partition 2 (FAT32, 0.10 GiB, SIBLING-E); W:\ (NTFS, 2.00 GiB, SIBLING-A); X:\ (NTFS, 1.00 GiB, SIBLING-B); partition 6 (no file system Windows knows, 0.50 GiB).
A conversion takes the whole disk offline. The volumes on those partitions are dismounted first and are not available until the run ends; for part of it Windows shows them read-only. Nothing is written to them. Close what uses them before you go on.
If the run is cut off, they stay offline with the disk until the run is finished or undone with --recover.
```

It refuses the disk, with the volume and everything beside it untouched,
when:

- the running Windows has a **page file** or its **crash-dump file** on any
  volume of the disk, or the disk holds its boot or system partition. Move
  the file (System Properties, Advanced) and restart. The same holds when
  the converter cannot tell where this Windows writes its dumps: a
  crash-dump filter driver other than BitLocker's is installed, or a
  crash-control setting it does not know is not a number (it is named);
- a volume beside this one **has shadow copies**, or stores those of another
  volume: Windows may discard them when the disk goes offline. Delete them
  (`vssadmin delete shadows /for=<drive>:`) or wait until they are no longer
  needed. A volume Windows cannot write to, or one without a file system
  Windows knows, has none;
- a **program has a file open** on one of those volumes. The run waits 20
  seconds for it and then names the volume: close what uses it, and start
  again. This is the one thing `--check` cannot see;
- the volume to convert holds an **installed Windows** and the disk has an EFI
  system partition: as a data volume it would no longer start. That is what
  [`--windows-boot-volume`](#convert-an-installed-windows) is for. On an MBR
  disk such a volume is refused: that Windows starts from the disk itself,
  and the converter starts an installed Windows only from a GPT disk.

### The target

- **Cluster size.** 4 KiB by default, or 64 KiB with
  `--target-cluster-bytes 65536`. A Windows boot volume is converted to 4 KiB
  only.
- **ReFS version.** Whatever the running Windows formats: 3.14 on every build
  this was run on. The run records it and requires the volume to stay that
  version.
- **Dev Drive or standard.** `--target-format dev-drive|standard` says how
  Windows formats the new file system. A run that names neither gets a Dev
  Drive, and on Windows Server an ordinary ("standard") ReFS volume; a
  Windows boot volume is converted as a Dev Drive only. The run prints which
  it is before it asks.
- **A Dev Drive** is what `format /DevDrv` makes, which Microsoft documents
  for every edition of Windows 11. The converted volume is then a ReFS volume that
  Windows reports as a Dev Drive. Whether this machine *trusts* it is kept by
  Windows per machine and is not part of the conversion: the run ends by
  saying what Windows reports, and in the lab that was a Dev Drive not marked
  trusted. Windows treats an untrusted Dev Drive as an ordinary volume, with
  Microsoft Defender in its usual real-time mode. `fsutil devdrv query E:`
  shows the state and `fsutil devdrv trust E:` trusts the volume;
  [Microsoft's Dev Drive documentation](https://learn.microsoft.com/windows/dev-drive/)
  says what trust changes and when to give it.
- **A standard volume** is an ordinary ReFS volume. A conversion to one
  works only where Windows itself formats one. Windows Server does: in the
  lab, Windows Server 2025 (build 26100) converted data volumes of every
  geometry in the matrix to standard ReFS, and to a Dev Drive when asked.
  The lab's Windows 11 answered "ReFS file system is not supported on this
  device"; there the run stops before the volume is touched and says so.
  There is no fallback from one to the other.

### What a volume that has been in use meets

Not carried over, and said so by the run:

| What | Why | What happens |
|---|---|---|
| Object IDs of files and directories | Windows gives one to the target of a shortcut; ReFS has none | Each is matched with the volume's object-ID index and kept in the run's records (`internal-indexes\object-ids-not-carried-over`); the run prints their number. A shortcut still finds its target by path |
| NTFS compression | ReFS stores the data uncompressed | The data is the same; the volume needs room for it |
| The change journal | It describes the NTFS volume | The converted volume starts a new one |
| 8.3 short names, with `--short-names drop` | ReFS has no short names | Every file and directory is created under its long name; each short name is kept in the run's records (`source-short-names-not-carried.json`). A program that stored a path in its short form no longer finds it. Without the option the volume is refused, see below |
| The case-sensitive mark of a directory, except on Windows Server 2025 | WSL and Git set it on the directories they make. The converter sets it on the new volume only for a data volume converted on Windows Server 2025 (build 26100), where Windows was shown to keep such a directory on ReFS. The lab's Windows 11 (build 26300, an Insider build) stopped with a bugcheck both times a ReFS volume with such a directory was taken offline, which a conversion does with the volume it builds; so it is not set there, on any other Windows, in a recovery environment, on a volume that holds a Windows, on a partition converted through a restart, or on a volume whose root directory is itself marked (the new root is never empty when its mark could be set) | Where no two names in the directory differ only by case, every name stays reachable. The directories are listed in the run's records (`case-sensitive-directories`, `source-case-sensitive-directories.json`), and the run and `--check` say before the prompt how many there are, whether the mark is set and, where it is not, why. On Windows Server 2025 every directory of the new volume is made with the mark its source directory has, the mark is read back, and a directory whose mark differs afterwards fails the run. Windows lets a directory on ReFS be marked again with `fsutil file setCaseSensitiveInfo`; because of that bugcheck, try it where a restart costs nothing |

Backup software, and the tools of some hypervisors, install a shadow-copy
provider of their own. Where such a provider answers Windows and holds no
shadow copy on the machine, the conversion goes ahead and the run names the
provider in a note. Software that keeps track of which parts of a volume
changed since its last backup will not recognise the converted volume: make
a full backup afterwards.

Refused before anything is written, each with what was found and what to do:

| Found | Do |
|---|---|
| 8.3 short names (their number and one of them are given) | `fsutil 8dot3name strip /s /f E:\`, then `fsutil 8dot3name set E: 1`; or convert with `--short-names drop`, which leaves them behind and lists them |
| BitLocker | Decrypt the volume: `manage-bde -off E:`; suspending is not enough |
| Shadow copies of the volume, or snapshot storage kept on it | `vssadmin delete shadows /for=E:` |
| A shadow-copy provider of backup software (any but Windows' own, Hyper-V's and Windows Server's for remote file shares) that holds a shadow copy on the machine, or does not answer when Windows asks it | The provider is named, and the shadow copy. Delete its shadow copies or let the backup that made them finish; a provider that does not answer has to be repaired or removed |
| EFS-encrypted files | `cipher /d` |
| Files with the TEMPORARY or OFFLINE attribute | Clear the attribute, or move the files |
| Cloud placeholders, `compact /exe` files, Data Deduplication | The kind is named, with the record number to find the file by |
| A named data stream on a directory | Remove the stream |
| Disk quotas in use | `fsutil quota disable E:` and delete the entries |
| Two names in one directory that differ only by case (both are given) | Rename one of them, then `fsutil file setCaseSensitiveInfo <directory> disable` |
| A dirty volume, an NTFS log that was not closed, an open transaction | `chkdsk E: /f`, or dismount cleanly |
| A program holding a file on the volume open | Close it; the converter waits 20 seconds first |
| No file at all on the volume | Format it as ReFS |

`--diagnose` reports the same without converting.

### Windows' drive optimization

Windows optimizes drives on a schedule (the `ScheduledDefrag` task), ReFS
volumes too. When it ran on the volumes a conversion was reading and writing,
a pass stalled for a quarter of an hour in the lab (#132). A run that sees
`defrag.exe` running says so once and goes on; the optimization stops by
itself. To keep it from starting during a conversion, disable the task first
and enable it afterwards:

```powershell
schtasks /Change /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /Disable
schtasks /Change /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /Enable
```

### How large a volume can be

There is no fixed limit. Memory and working storage decide how many files,
streams and extents a run can hold, and a volume beyond them is refused before
anything is written, with the numbers. A file may have as many named streams
as NTFS allows and a sparse file as many islands as it has; one stream may be
in as many separate extents as a sixty-fourth of the memory budget can
describe (about 200,000 with 13 GB available), and never fewer than 65,536.

The largest volume converted in the lab was the Windows volume: 23 GB in
about 190,000 files and directories. The largest data volume held 500,000
small files, and took 45 minutes: about 5 ms a file, as volumes of 100,000
and of 20,000 do.

**Memory is what limits the number of files today.** A run keeps a ledger of
the memory it may use, two thirds of what is free when it starts. What it
holds there for every file and directory until the conversion is complete
sets the limit: 400 MiB of free memory and about 15 KiB for every file
(1.8 GiB for 100,000 files, 7.5 GiB for 500,000). `--check`, and the reading a run makes
before it asks, give that figure.

**A run fits itself to the memory there is.** With less free than the figure,
it goes ahead and says that it will be slower: what it cannot do without and
cannot hold in its share of the free memory comes from the page file. The
same happens when other programs take memory while it runs. It does not stop
for that; it stops for memory only where Windows has no more to give, memory
and page file together, and then with the volume unchanged or with the
recovery command it printed. Closing other programs before a run makes it
faster.

What a run holds only to go faster follows the machine while it runs. A few
times a second it looks at the memory Windows has available: where more has
become free it uses it, and where another program has taken memory it gives
its caches back, those it used longest ago first, so that a tenth of the
machine's memory (at least 1 GiB) stays free and Windows does not have to
page for them. A run with `--memory-limit` keeps to its limit instead.

What a run holds in memory only to go faster (stores it looks things up in,
objects it has decoded) it gives back when the memory is needed for
something it cannot do without, what it used longest ago first. It is
slower for that, and its last lines say that this happened, and how far it
went beyond the memory it set aside at its start (`memory-beyond:`). A run
that stops for memory all the same says which reservations were the largest,
and every run prints how high its reservations went and, step by step, what
held them (`memory-steps:`).

`--memory-limit <MiB>` sets the most memory a run may use, where it would
otherwise use up to two thirds of what is free: for a machine that has to
keep memory for something else, or to see how a volume does with little. A
run with less memory holds less in memory and takes longer. A limit is a
ceiling: a run given one does not go beyond it, so a limit below what the
volume needs is refused before anything is built, and the refusal says what
the limit would have to be. A recovery takes the option too.

## A partition on the Windows disk

A data partition that shares its disk with the running Windows (a `D:` beside
`C:`) cannot be converted while Windows runs: a conversion takes the disk
offline. It is converted through a restart. `--list` says "convertible
through a restart" of such a partition.

```
ntfs2refs --drive D --restart-media E:\ --scratch-directory S:\runs
```

What it needs beside what every conversion needs:

- **Windows installation media** at `--restart-media`: a mounted ISO, a DVD
  or a USB stick of this Windows, in English (United States). The run makes a
  minimal Windows from it that holds the converter, and starts the machine
  from that once.
- **`ntfs2refs-recovery.exe`** beside `ntfs2refs.exe`: it is what runs in the
  minimal Windows. A release holds both.
- **The working directory on an NTFS volume of another disk**, a USB disk
  for example. It stays connected until Windows is back.
- **A GPT disk, UEFI and Secure Boot on.** The run changes no firmware
  setting; it adds its own entry to Windows' boot configuration and removes
  the selection again.

What happens:

1. In Windows the run builds the new file system and its recovery records in
   the working directory, marks the partition read-only so that nothing
   changes it any more, makes the minimal Windows and selects it for the next
   start. This is the long part: minutes for a small volume.
2. It says so, prints how to cancel, and restarts the machine.
3. The minimal Windows starts, converts the partition (under a minute for a
   small volume in the lab), puts Windows' own boot selection back and
   restarts.
4. Windows starts with the partition as ReFS under its drive letter.

**Ways back.** Until the conversion itself has started, nothing has been
written to the partition, and it is given back as the NTFS volume it was:

- A run that fails in Windows after it marked the partition read-only gives
  it back by itself and says so with the error.
- Before the restart, or if the machine was started into Windows some other
  way: `ntfs2refs --recover "<the run's folder>" --rollback`, the line the
  run printed. `--recover` without `--rollback` says what state the run is
  in.
- If the minimal Windows cannot start the conversion (the disk is not as it
  was recorded, for example), it puts the machine back by itself and Windows
  starts with the partition as NTFS.

Once the conversion has started, the way is forward: if the machine is
switched off or loses power meanwhile, it returns to the minimal Windows at
the next start, which asks whether to go on (R) or to put NTFS back (B).

The lab converted such a partition on Windows Server 2025, and cancelled runs
at each of these points with the volume listing exactly as before. It has
not run this route on Windows 11, on a physical machine, with BitLocker on
the Windows volume, or interrupted while it converts; `ntfs2refs
capabilities` says the same.

## Convert an installed Windows

An installed Windows is converted while it is not running, from a second
Windows on another disk (a second installation, or the same disk attached to
another machine).

### The Windows this machine runs

`C:` of the running Windows converts through its own Windows Recovery
Environment (WinRE), with one command and a restart:

```powershell
.\ntfs2refs.exe --drive C --scratch-directory E:\runs --boot-partition B
```

Both live on another disk than Windows', which stays connected until Windows is
back (one USB drive will do):

- `E:` is an NTFS volume for the working files.
- `B:` is a FAT32 partition of 100 MB or more. The machine starts the recovery
  environment from it, because the disk a machine starts from cannot be taken
  offline, and the conversion takes the Windows disk offline. If the working
  directory's disk has exactly one FAT32 partition with a drive letter,
  `--boot-partition` can be left out: that one is used.

The run stages the machine's `winre.wim` (found by `reagentc /info`) with a
start script under `E:\runs\n2r-running`, writes boot files and a boot store of
their own to `B:` (`bcdboot`), and puts a firmware entry for `B:` first in the
firmware's boot order. Windows' own boot files and store are not changed. It
then restarts. In the environment the converter runs as it does for an
installed Windows that is not running (below). When it ends, the firmware entry
leaves the boot order and the machine starts the converted Windows.

- **Report:** `E:\runs\n2r-running\session-result.txt`, opened at the first
  logon afterwards.
- **If the conversion fails:** the run recovers at once from its own records,
  forward or back to NTFS.
- **If the converted volume does not pass its verification** (with `--verify
  fast`, the default): nothing is committed. The recovery forward verifies
  once more; if that does not pass either, the environment stops at its
  command prompt, where the command it shows (with `--rollback`) puts NTFS
  back. It does not roll back by itself.
- **If the machine loses power:** the next start goes back into the
  environment, which recovers the same way.
- **If the volume needs a person:** the environment keeps its entry first and
  stops at a command prompt that says so.
- **`--diagnose`:** works the same way and leaves the volume NTFS.
- **Refused:** a Windows Recovery Environment that is turned off, a BitLocker
  volume, a working directory on the Windows volume, and a boot partition that
  is not FAT32 or that is on the Windows disk.

Shown in the lab on a Windows 11 build 26300 VM (`runc-convert3`: C: ReFS and
healthy afterwards, `sfc` and DISM clean; `runc-convert1`: power cut during
preparation, recovered back to NTFS).

```powershell
.\ntfs2refs.exe --list
.\ntfs2refs.exe --drive D --windows-boot-volume --scratch-directory S:\runs
```

Here `D:` is the Windows installation to convert, as the running Windows sees
it, and `S:` is working storage on a third place.

This is admitted for one profile, which `ntfs2refs capabilities` lists: the
Windows 11 build 26300 whose `winload.efi` and `refs.sys` have the listed
checksums, converted by a running Windows with the identical kernel, to a
Dev Drive with 4 KiB clusters. Any other installation is refused before
anything is written. In the lab that installation was converted, started from
its own disk with no other disk attached and Secure Boot on, reached the
desktop, and was then used: `sfc /scannow` and a DISM component-store scan
found nothing, a Windows feature was enabled and disabled by the servicing
stack, and it started again twice.

What is different on a converted Windows volume:

- **Every 8.3 short name is a link.** ReFS has no short names. Each becomes a
  symbolic link beside its long name, so `C:\PROGRA~1` still leads to
  `C:\Program Files`. The links are visible in Explorer and in `dir`.
- **Object IDs, NTFS compression and the change journal**, as for a data
  volume.

What Windows' own recovery and repair tools made of the converted Windows in
the lab (build 26300, release 0.0.1):

- **The recovery environment (WinRE)** stays where Windows put it, on the
  recovery partition, which is NTFS and which the conversion does not touch.
  `reagentc /info` reports it enabled, and the machine started into it
  (`reagentc /boottore`) and showed its menu.
- **Windows Setup** from the installation media of the same build found
  nothing that blocks an upgrade (`setup.exe /Compat ScanOnly`), and an
  in-place repair upgrade (`setup.exe /Auto Upgrade`) completed: Windows was
  installed again over itself in a quarter of an hour, on ReFS, and afterwards
  `sfc` found nothing, no ReFS error was logged, and the short-name links
  still led where they did.

Microsoft documents starting Windows from ReFS for some builds only, and the
lab has shown this one build. Keep a backup before a repair upgrade as before
any.

## If a run stops

- **Before the recovery command is printed:** nothing has been written to the
  volume. A run that ends by itself here, with a refusal or an error, gives
  the volume back as NTFS: start again from the beginning. If the partition
  was shrunk, it keeps its slightly smaller size. A run that is cut off here
  is a case of its own, [below](#a-run-that-is-cut-off-while-it-prepares).
- **After it:** keep the working storage, and run the command that was
  printed. Do not start a new conversion over the unfinished one. The disk is
  offline meanwhile, and with it every other volume on it; do not bring it
  online by hand to reach them. Recovery returns them with the volume.

```powershell
.\ntfs2refs.exe --recover <printed-directory> --recovery-sha256 <printed-checksum>
```

This finishes the conversion. With `--rollback` added it puts the NTFS volume
back as it was, which is possible up to the handoff: the point at which the
journal records the conversion as committed. When that is depends on the
[verification](#verification): with `--verify fast`, the default, once the
converted volume has passed its verification; with `--verify thorough`, as
soon as every new sector is on the disk, before the verification. After the
handoff recovery only finishes. Once the converted volume has been used as
ReFS, the journal's old content no longer matches it and must not be put
back.

If the machine lost power and the printed command with it: the directory is
the `conversion` folder of the run under the working directory you gave
(`<working directory>\<run>\conversion`), and the checksum is the SHA-256 of
the `recovery-envelope.json` in it:

```powershell
Get-FileHash -Algorithm SHA256 S:\runs\<run>\conversion\recovery-envelope.json
```

The checksum exists so that recovery does not start from an envelope that
changed after it was printed. Taking it from the file means trusting the file
as it is now; recovery still checks the journal and every journaled range of
the volume before it writes.

A recovery works in the ReFS cluster size and version of the run it recovers;
they are not given again.

The [recovery matrix](recovery-matrix.md) lists every point at which the lab
stopped a conversion, by ending its process or by turning the machine off, and
how each recovery ended. It also says what the lab cannot do: cut the power of
the storage itself.

### A run that is cut off while it prepares

While a run prepares, it holds the volume offline and read-only. A run that
is cut off then (its process is ended, the machine loses power) leaves the
volume that way: its disk offline, and the volume without its drive letter.
Nothing has been written to it. A new conversion cannot be started, because
the volume is not there; the refusal says that the disk is offline and points
here.

The run prints the way back at its start:

```text
If this run is cut off while it prepares (before any "To recover:" line), the volume stays offline and read-only. To get it back as NTFS: ntfs2refs --recover "S:\runs\<run>\conversion" --recovery-sha256 <checksum> --rollback
```

That command cancels the unfinished preparation and gives the volume back as
NTFS, as it was. Then start again. The run that was cut off leaves its
working files behind, the volume it was building among them; the
cancellation says where they are, how large they are, and how to detach that
volume so that the folder can be deleted. If the screen is gone: the directory is
the `conversion` folder of the run under the working directory, and the
checksum is the SHA-256 of the `preparation-intent.json` in it
(`Get-FileHash -Algorithm SHA256`).

A run that ends before it prints the line above has recorded nothing to
recover from, and the volume is online as it was (a shrink is not undone);
only the working volume it was building may still be attached. A run that
stops with an error then detaches it itself. One that is cut off cannot: the
next conversion run, or `ntfs2refs --list` from an elevated terminal,
detaches it and names the run's folder, which can then be deleted. A run that
is still going is never touched (each run marks itself as running for as long
as its process lives); a folder made by an earlier version is only named,
with the diskpart commands that detach its volume.

The lab ends the converter in two phases of preparation and runs exactly that
command; the [recovery matrix](recovery-matrix.md#stopped-during-preparation)
has the attempts. It ends the process. It has not turned the machine off
during preparation.

### What recovery checks before it writes

Recovery reads the journal's lifecycle and every journaled range of the volume
before it writes anything. It stops, having changed nothing, when either is not
what the run left:

- **A byte in a journaled range that is neither the old nor the new content.**
  Resume and rollback both stop, naming the range and the byte's offset. The
  converter writes only old or new bytes into those ranges, and only while the
  disk is offline, so a third value means something else wrote to the disk or
  the storage returned different data. Recovery cannot know what else around
  it changed, and writing either image over an unknown state could destroy
  what is left. This is deliberate, and there is no switch to override it: the
  disk stays offline and untouched. Repairing the named range is a manual
  matter outside this tool; recovery can be run again afterwards.
- **A lifecycle marker that is not one of this journal's.** Refused.
- **A lifecycle marker that was being written when the run stopped.** A power
  loss or host crash in the middle of a marker write can leave the marker
  partly on the disk. Recovery recognises exactly that: whole 512-byte sectors
  of the marker and of what the granule held before, beside the state the
  journal is in while that marker is written, and only while the source disk
  is in the offline state that marker is written in. It says what it found,
  treats the marker as not written, and continues from there; every check of
  the volume is then repeated before anything is written. The lab can end a
  process or turn a machine off but cannot cut power to storage, so this is
  covered by tests of the marker images and by a lab run in which the image is
  made by hand, not by a real power loss.

## After the conversion

The run ends with "Conversion completed" and the volume online as ReFS.
Before you delete the working storage:

- Look at the volume: `fsutil fsinfo refsinfo E:` shows the ReFS version and
  cluster size, and the System event log should hold no ReFS errors.
- Open what matters to you on it.
- Then delete the run's folder under the working directory. It holds the
  temporary virtual disk and the journal, which are of no use once the volume
  is in use as ReFS.

The lab compares a listing of the volume taken before the conversion with one
taken after, reading every file and stream in full: names, sizes, contents,
streams, hard links, timestamps, attributes, security, reparse points and
extended attributes. `lab-volume-manifest.exe`, shipped beside the converter,
is that tool; [the lab guide](../lab/README.md) says how it is used and which
differences it accepts.

## Options

| Option | What it does |
|---|---|
| `--list` | Lists disks and partitions, and whether each NTFS partition can be converted |
| `--drive <letter or disk>` `[--partition N]` | Selects the volume |
| `--scratch-directory <dir>` | Working storage, on another disk |
| `--memory-limit <MiB>` | The most memory the run may use; without it, up to two thirds of what is free |
| `--check` | Reads the volume while it stays online: what would refuse it, and what a conversion takes |
| `--compare-listing` | Lists the volume before and after the conversion and compares the two |
| `--diagnose` `[--diagnose-limit N]` | Goes through the whole preparation without converting |
| `--target-cluster-bytes 4096\|65536` | ReFS cluster size |
| `--target-format dev-drive\|standard` | How Windows formats the new file system; standard is the default on Windows Server, dev-drive elsewhere |
| `--short-names refuse\|drop` | What to do with a data volume's 8.3 short names: refuse the volume (the default), or convert without them and keep a list |
| `--windows-boot-volume` | The volume is an installed Windows that is not running |
| `--restart-media <dir>` | Windows installation media, for a partition on the disk of the running Windows: it is converted through a restart |
| `--recover <dir> --recovery-sha256 <sum>` `[--rollback]` | Finishes, or undoes, an interrupted run |
| `--review` | Stops before the conversion is committed, with the volume mounted read-only as ReFS; see below |
| `--yes` `--volume-serial XXXX-XXXX` | Runs without asking; see below |
| `--verify fast\|thorough` | What is verified, and when the conversion is committed: `fast` (the default) proves data that stays in place by its extents and commits after the verification; `thorough` reads and hashes every stream in full and commits before it |
| `--recheck-everything` | Repeats the full re-reads at every checkpoint |
| `--minimize-scratch` | Experimental: less working storage; see below |

### Without the prompt

A script passes `--yes`, which answers every question of the run. Because the
question it answers is the one that shows which volume is about to be
converted, a conversion or a diagnose run then also needs
`--volume-serial XXXX-XXXX`, the volume's serial number as `--list` and `vol`
print it. A run whose drive letter leads to another volume is refused before
anything is opened. A recovery needs only `--yes`: its checksum already binds
it to its run.

```powershell
.\ntfs2refs.exe --drive E --scratch-directory S:\runs --yes --volume-serial 1A2B-3C4D
```

### Verification

- **`--verify fast`, the default.** Data that stays in place is proven by the
  identity of its extents; resident, compressed, sparse and partly initialized
  streams, tails and everything rewritten are read and checksummed. Working
  files and the volume are re-read in full once, at the gate before the first
  write to the volume. The conversion is committed only after the converted
  volume has passed this verification: every new sector is written and read
  back, the disk is sealed offline and read-only again, the converted volume
  is mounted read-only and verified, and only then is the handoff written and
  the volume put online. Until then `--recover ... --rollback` puts NTFS back.
- **`--verify thorough`** changes *what* is checked: every stream's complete
  contents are read and hashed. Not with `--minimize-scratch`. The earlier
  spelling `--verify-full-content` is still accepted and means the same. It
  commits as soon as every new sector is written and read back, before the
  verification: from then on a rollback is closed.
- **`--recheck-everything`** changes *how often*, not what: the full re-reads
  happen at every checkpoint instead of once at the gate. Much slower.

Where two checks prove the same thing, a fast run makes one of them;
`--verify thorough` and `--recheck-everything` make both:

- **Placing the new volume's extents.** After each move only the mapping of
  the moved range is read, to see that it landed where it was sent. Each
  file's complete mapping is compared with every piece placed for it once,
  when placement ends, instead of after every move. Both views of the
  destination's allocation are still read before every move.
- **Writing the changes.** Each changed range is held to its old contents
  once, before the apply marker, then written and read back against its new
  contents. It is not read again immediately before it is written.

A partition on the disk of the running Windows, a conversion with
`--restart-media`, and a run whose interrupted preparation is resumed still
commit before the verification, as `--verify thorough` does: from their
handoff on a rollback is closed. A resumed preparation says so before it
writes to the volume.

**If the verification does not pass** (with `--verify fast`), nothing is
committed and nothing is rolled back. The run ends with an error that says
what stopped it and gives the two ways on:

```text
To verify again and finish: ntfs2refs --recover "<dir>" --recovery-sha256 <sum>
To put NTFS back:           ntfs2refs --recover "<dir>" --recovery-sha256 <sum> --rollback
```

The volume is left sealed meanwhile, its disk offline and the converted
volume not mounted. Verifying again makes the same checks; it helps where
what stopped the first attempt was the machine (memory, a device that went
away), not the volume. A rollback of a run that wrote to the volume checks
the restored NTFS volume against the fingerprint of the volume taken before
the conversion before it puts it online (not with `--minimize-scratch`, whose
rollback does not restore what unused space held). The run records the seal
in `verification-seal.json` beside the recovery envelope; keep it with the
other records.

### Look before you commit: `--review`

```powershell
.\ntfs2refs.exe --drive E --scratch-directory S:\runs --review
```

A run with `--review` converts as any run does, up to the handoff: every new
sector is written, flushed and read back. Then it does not write the handoff.
It seals the disk offline and read-only again, takes a fingerprint of the
whole converted partition, records it in `review-stop.json` beside the
recovery envelope, puts the disk online read-only and ends. Windows mounts the
converted volume write-protected as ReFS under its letter (its label is the
working one until you commit). Look at it, then run one of the two commands
the run printed:

- `--recover <dir> --recovery-sha256 <sum>` commits: the volume is dismounted
  and sealed again, checked against the fingerprint, and the conversion is
  finished as any other: with `--verify fast` the converted volume is
  verified and then the handoff is written, with `--verify thorough` the
  handoff is written and then the volume is verified; then label, letter,
  online.
- The same with `--rollback` puts NTFS back. The restored volume is then also
  checked against the fingerprint of the source taken before the conversion,
  before it is put online.

Do not make the volume or its disk writable. If it was ever writable, its
fingerprint no longer matches (or the disk is found online and writable) and
ntfs2refs refuses both directions: neither the journal's old content nor its
handoff fits a volume that was written to. Close Explorer windows on the
volume before you run the command: it has to be dismounted.

`--review` is for a data volume on a disk of its own (no other partitions:
the review leaves the whole disk read-only). It is refused with
`--windows-boot-volume`, `--restart-media`, for a partition on the disk of the
running Windows, and with `--check`, `--diagnose`, `--compare-listing` and
`--minimize-scratch`. A
review run whose preparation is cut off is cancelled with `--rollback` and
started again; it is not resumed without its review. The fingerprint costs a
full read of the volume at the stop and another at the decision. The
converted volume's files are verified when you commit, as without a review;
what the review stop itself checks is every new sector. With `--verify fast`
a commit whose verification does not pass leaves the rollback open, as
[without a review](#verification).

### Your own before-and-after comparison

```powershell
.\ntfs2refs.exe --drive E --scratch-directory S:\runs --compare-listing
```

The lab judges every conversion by listing the volume before and after and
comparing the two: every file's name, size and contents, its streams, hard
links, times, attributes, security, reparse points and extended attributes.
`--compare-listing` does that for your volume, with the same code. The run
lists the volume after you confirm and before it touches anything, converts,
lists it again and compares. It prints the result, keeps both listings and the
report in the run's directory (`listing-before.jsonl`, `listing-after.jsonl`,
`listing-report.json`), and exits 6 if they differ. The conversion stands
either way.

It costs two full reads of the volume. What a conversion is meant to change
is accepted and counted (the NTFS compression flag, what Windows keeps in
`System Volume Information`, and on a Windows volume each 8.3 name as a link).
A program that writes to the volume between the first listing and the start
of the conversion shows as a difference, so close what uses the volume first.

The same by hand, with `lab-volume-manifest.exe` from the release, before and
after any run:

```powershell
.\lab-volume-manifest.exe capture --root E:\ --output before.jsonl
.\lab-volume-manifest.exe capture --root E:\ --output after.jsonl
.\lab-volume-manifest.exe compare --before before.jsonl --after after.jsonl --report report.json
```

### Experimental and older options

`--minimize-scratch` reduces the working storage by not saving the content of
unused NTFS space. It first moves files on the volume through NTFS, and those
moves are not undone if the run stops; a rollback then restores files and
metadata but not what unused space held. It is refused on a volume with shadow
copies. The lab's matrices do not cover it.

The routes and commands of earlier designs
were removed with 0.0.1: `--whole-image-verification`, the thin temporary
storage of `--experimental-thin-shadow`, and the subcommands that worked from
request files and raw images (`convert`, `resume`, `rollback`, `finalize`,
`plan` and others). The tag `archive/hidden-routes` keeps them, and
[docs/history](history/README.md) holds their documents.
