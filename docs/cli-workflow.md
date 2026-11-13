# Operating and recovery guide

For ntfs2refs 0.2.0-beta.1. [The README](../README.md) says what the tool is;
this guide says how to run it, what it refuses and why, and what to do if a
run stops. What the lab has shown is in the [feature matrix](feature-matrix.md)
and the [recovery matrix](recovery-matrix.md).

## Before you start

1. **Have a backup you have restored from.** This is a beta, and every volume
   it has converted was a virtual disk.
2. **Windows build 26100 or later** (Windows 11 24H2, Windows Server 2025),
   and an **elevated terminal**. Both are checked before a disk is opened; an
   older build is refused by name. Conversions were run on builds 26100 and
   26300. On another build, or when Windows formats a ReFS other than 3.14,
   the run says before it starts that the lab has not tried that.
3. **Working storage on another disk**, given with `--scratch-directory`.
   The run builds the new file system there, on a virtual disk as large as the
   volume that takes only the space its contents need, and keeps there the
   old content of every sector it changes. Leave it alone until the
   conversion has finished and you have looked at the result.
4. **The volume's layout.** A data volume has to be the only partition on a
   GPT disk, apart from a Microsoft reserved partition, and not on the disk of
   the running Windows.

The lab's Windows volume, with 22.9 GB in use in 191,000 files and
directories, took 28 minutes, about 30 GB of working storage and 2.1 GB of
memory in a machine with 24 GB. These are measurements of that volume, not
bounds: see [how large a volume can be](#how-large-a-volume-can-be).

## Look first: `--list`

```powershell
.\ntfs2refs.exe --list
```

It lists every disk and partition and says for each NTFS partition whether a
conversion would take it and, if not, why: it is the running Windows, shares
its disk with it, has other partitions beside it, or is on a disk that is not
GPT. BitLocker is not shown there; it is found when a run starts.

`--list` exits 0 when every disk and volume answered, and 4 when some device
could not be queried: the list it printed is then partial.

## Check first: `--diagnose`

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

Diagnose is refused, before anything is started, where it could not keep that
promise: when a conversion would first shrink the partition (see below), and
with `--minimize-scratch`. It does not exercise the journal, the writes to the
volume or a boot.

## Convert a data volume

```powershell
.\ntfs2refs.exe --drive E --scratch-directory S:\runs
.\ntfs2refs.exe --drive E --scratch-directory S:\runs --target-cluster-bytes 65536
```

`--drive` takes a drive letter, or a disk number with `--partition`. The run
shows the disk, the partition, its size and label and what it is about to do,
and asks for confirmation. Then:

1. Windows formats a ReFS volume of the same size on a virtual disk in the
   working directory.
2. The volume is taken offline and read-only, and inspected. Anything that
   cannot be converted is refused here, with the volume returned as NTFS.
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
with the sizes, before the confirmation prompt. The shrink is not undone if
the run stops later.

- **Source geometry.** Any that Windows formats NTFS with: clusters from 512
  bytes to 2 MiB, 512-byte or 4096-byte (4Kn) sectors, 1 KiB or 4 KiB file
  records.
- **What stays in place.** Data that lies on boundaries of the target's
  cluster size. Everything else is copied through the working storage: from
  NTFS clusters smaller than the target's that is most of the volume, and the
  working storage needs room for it. From clusters of 4 KiB or more to a
  4 KiB target, and of 64 KiB or more to a 64 KiB target, file data stays
  where it is.

### The target

- **Cluster size.** 4 KiB by default, or 64 KiB with
  `--target-cluster-bytes 65536`. A Windows boot volume is converted to 4 KiB
  only.
- **ReFS version.** Whatever the running Windows formats: 3.14 on every build
  this was run on. The run records it and requires the volume to stay that
  version.
- **Dev Drive or standard.** By default Windows formats the new file system
  as a Dev Drive (`format /DevDrv`), which Microsoft documents for every
  edition of Windows 11. The converted volume is then a ReFS volume that
  Windows reports as a Dev Drive. Whether this machine *trusts* it is kept by
  Windows per machine and is not part of the conversion: the run ends by
  saying what Windows reports, and in the lab that was a Dev Drive not marked
  trusted. Windows treats an untrusted Dev Drive as an ordinary volume, with
  Microsoft Defender in its usual real-time mode. `fsutil devdrv query E:`
  shows the state and `fsutil devdrv trust E:` trusts the volume;
  [Microsoft's Dev Drive documentation](https://learn.microsoft.com/windows/dev-drive/)
  says what trust changes and when to give it.
- **`--target-format standard`** asks Windows for an ordinary ReFS volume
  instead. It works only where Windows itself formats one; where it does not
  (the lab's Windows 11 answered "ReFS file system is not supported on this
  device"), the run stops before the volume is touched and says so. There is
  no fallback from one to the other, and no conversion to standard ReFS has
  been run in the lab.

### What a volume that has been in use meets

Not carried over, and said so by the run:

| What | Why | What happens |
|---|---|---|
| Object IDs of files and directories | Windows gives one to the target of a shortcut; ReFS has none | Each is matched with the volume's object-ID index and kept in the run's records (`internal-indexes\object-ids-not-carried-over`); the run prints their number. A shortcut still finds its target by path |
| NTFS compression | ReFS stores the data uncompressed | The data is the same; the volume needs room for it |
| The change journal | It describes the NTFS volume | The converted volume starts a new one |

Refused before anything is written, each with what was found and what to do:

| Found | Do |
|---|---|
| 8.3 short names (their number and one of them are given) | `fsutil 8dot3name strip /s /f E:\`, then `fsutil 8dot3name set E: 1` |
| BitLocker | Decrypt the volume: `manage-bde -off E:`; suspending is not enough |
| Shadow copies of the volume, or snapshot storage kept on it | `vssadmin delete shadows /for=E:` |
| A shadow-copy provider other than Windows' own and Hyper-V's (backup software) | The provider is named. No volume is converted while it is installed |
| EFS-encrypted files | `cipher /d` |
| Files with the TEMPORARY or OFFLINE attribute | Clear the attribute, or move the files |
| Cloud placeholders, `compact /exe` files, Data Deduplication, WSL files | The kind is named, with the record number to find the file by |
| A named data stream on a directory | Remove the stream |
| Disk quotas in use | `fsutil quota disable E:` and delete the entries |
| Case-sensitive directories | `fsutil file setCaseSensitiveInfo <directory> disable` |
| A dirty volume, an NTFS log that was not closed, an open transaction | `chkdsk E: /f`, or dismount cleanly |
| A program holding a file on the volume open | Close it; the converter waits 20 seconds first |
| No file at all on the volume | Format it as ReFS |

`--diagnose` reports the same without converting.

### How large a volume can be

There is no fixed limit. Memory and working storage decide how many files,
streams and extents a run can hold, and a volume beyond them is refused before
anything is written, with the numbers. A file may have as many named streams
as NTFS allows and a sparse file as many islands as it has; one stream may be
in as many separate extents as a sixty-fourth of the memory budget can
describe (about 200,000 with 13 GB available), and never fewer than 65,536.

The largest volume converted in the lab was the Windows volume: 23 GB in
about 190,000 files and directories. The largest data volume held 23,000
files and directories.

## Convert an installed Windows

An installed Windows is converted while it is not running, from a second
Windows on another disk (a second installation, or the same disk attached to
another machine). `C:` of the running Windows is never converted.

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

## If a run stops

- **Before the recovery command is printed:** nothing has been written to the
  volume. A run that ends by itself here, with a refusal or an error, gives
  the volume back as NTFS: start again from the beginning. If the partition
  was shrunk, it keeps its slightly smaller size. A run that is cut off here
  is a case of its own, [below](#a-run-that-is-cut-off-while-it-prepares).
- **After it:** keep the working storage, and run the command that was
  printed. Do not start a new conversion over the unfinished one.

```powershell
.\ntfs2refs.exe --recover <printed-directory> --recovery-sha256 <printed-checksum>
```

This finishes the conversion. With `--rollback` added it puts the NTFS volume
back as it was, which is possible up to the handoff: the point at which every
new sector is on the disk and the journal says so. After the handoff recovery
only finishes. Once the converted volume has been used as ReFS, the journal's
old content no longer matches it and must not be put back.

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
NTFS, as it was. Then start again. If the screen is gone: the directory is
the `conversion` folder of the run under the working directory, and the
checksum is the SHA-256 of the `preparation-intent.json` in it
(`Get-FileHash -Algorithm SHA256`).

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
| `--diagnose` `[--diagnose-limit N]` | Checks without converting |
| `--target-cluster-bytes 4096\|65536` | ReFS cluster size |
| `--target-format dev-drive\|standard` | How Windows formats the new file system |
| `--windows-boot-volume` | The volume is an installed Windows that is not running |
| `--recover <dir> --recovery-sha256 <sum>` `[--rollback]` | Finishes, or undoes, an interrupted run |
| `--yes` `--volume-serial XXXX-XXXX` | Runs without asking; see below |
| `--verify-full-content` | Reads and hashes the complete contents of every stream |
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

- **Default.** Data that stays in place is proven by the identity of its
  extents; resident, compressed, sparse and partly initialized streams, tails
  and everything rewritten are read and checksummed. Working files and the
  volume are re-read in full once, at the gate before the first write to the
  volume.
- **`--verify-full-content`** changes *what* is checked: every stream's
  complete contents are read and hashed.
- **`--recheck-everything`** changes *how often*, not what: the full re-reads
  happen at every checkpoint instead of once at the gate. Much slower.

### Experimental and older options

`--minimize-scratch` reduces the working storage by not saving the content of
unused NTFS space. It first moves files on the volume through NTFS, and those
moves are not undone if the run stops; a rollback then restores files and
metadata but not what unused space held. It is refused on a volume with shadow
copies. The lab's matrices do not cover it.

Earlier designs of the converter are still in the executable and are no longer
listed by `--help`: `--whole-image-verification` (which compares and journals
every byte of the volume and is limited to 1,024 files, 256 directories and
4,096 NTFS runs), `--offline-media`, and the subcommands that work from request
files (`convert`, `resume`, `rollback`, `finalize`, `plan` and others).
`ntfs2refs capabilities` names them. They are kept so that the records of
earlier builds can still be read; nothing in this guide or in the matrices is
about them. [docs/history](history/README.md) holds their documents.
