# Operating and recovery guide: 0.0.1-alpha

This guide describes the [published experimental Windows boot-volume alpha](https://github.com/faratech/ntfs2refs/releases/tag/0.0.1-alpha).
See [release qualification](release-0.0.1-alpha.md) for the tested scope and
[the archived workflow](history/cli-workflow-before-boot-alpha-closeout-20261111.md)
for older experiments.

## Prepare

1. Make an independent backup of the source and retain access to the control OS.
2. Boot a separate Windows installation capable of creating a ReFS Dev Drive.
   The installed Windows being converted must be offline, attached as a data
   volume. This does not require a VM; the VM is the lab environment.
3. Provide independent working storage off the source disk. Leave all working
   and recovery files in place until conversion and verification are complete.
4. Open an elevated terminal, verify the downloaded ZIP against its published
   SHA-256, then extract it. The current ZIP SHA-256 is
   `4966456f4c0bac93095cd6112a0eb5f06262842b3965ae6c7e86845cf17d713e`.

The measured lab source had 22.9 GB used and consumed about 30 GB of working
storage. Actual requirements depend on metadata, placement, rewritten data and
recovery records. Do not interpret the lab value as a fixed maximum.

## Select and convert

```powershell
.\ntfs2refs.exe --list
.\ntfs2refs.exe --drive D --windows-boot-volume --scratch-directory S:\runs --target-format dev-drive
```

`--list` exits 0 when every disk and volume answered, and 4 when some device
could not be queried: the list it printed is then partial.

Confirm the source disk and partition shown by the program. In this example,
`D:` is the old Windows installation and `S:` is independent working storage.
The demonstrated boot profile uses `dev-drive`; standard ReFS formatting and
other Windows versions do not inherit this qualification.

The drive interface also accepts explicit selection such as `--drive D --partition 3`.
That syntax is not a claim that every data-volume layout or feature is qualified.
The program refuses unsupported conditions instead of silently omitting them.

If the partition's length is not a multiple of 64 MiB, the converter first
asks the Windows NTFS driver to shrink it to one (by less than 64 MiB): ReFS
covers a volume in whole units of that size. It says so before the
confirmation prompt. The shrink is not undone if the run stops later. This
applies to a Windows partition and to a data volume alike.

## Data volumes

Without `--windows-boot-volume`, `--drive` converts a data volume on a disk of
its own (the disk may hold that partition and a Microsoft reserved partition,
nothing else). This route is newer than the alpha release and is not part of
its qualification.

```powershell
.\ntfs2refs.exe --drive E --scratch-directory S:\runs
.\ntfs2refs.exe --drive E --scratch-directory S:\runs --target-cluster-bytes 65536
```

- **Source geometry.** Any that Windows formats NTFS with: clusters from 512
  bytes to 2 MiB, 512-byte or 4096-byte (4Kn) sectors, 1 KiB or 4 KiB file
  records.
- **Target.** ReFS with 4 KiB clusters by default, or 64 KiB with
  `--target-cluster-bytes 65536`. A Windows boot volume is converted to 4 KiB
  only. The ReFS version is whatever Windows formats (3.14 on every build this
  was run on); the run records it and requires the volume to stay that version.
- **What stays in place.** Data that lies on boundaries of the target's cluster
  size. Everything else is copied through the working storage: from clusters
  smaller than the target's that is most of the volume, and the working
  storage needs room for it.
- **Windows.** Build 26100 or later, and administrator rights. Both are
  checked before a disk is opened; an older build is refused by name. On a
  build other than 26100 and 26300, or when Windows formats a ReFS other than
  3.14, the run says before it starts that the lab has not tried that.
- **Recovery.** The recovery command is the same as for a boot volume. It
  takes the ReFS cluster size and version from the run's own records.

### What a volume that has been in use meets

`ntfs2refs --list` says for each NTFS partition whether a conversion would take
it: the volume has to be the only partition on a GPT disk, apart from a
Microsoft reserved partition. A partition beside the running Windows, a second
data partition on the disk, or an MBR disk is refused, and the list says which.

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

`--diagnose` (below) reports the same without converting.

The source's size is bounded by the machine: memory and working storage decide
how many objects, streams and extents a run can hold, and a volume beyond them
is refused before anything is written. A file may have as many named streams
as NTFS allows and a sparse file as many islands as it has; one stream may be
in as many separate extents as a sixty-fourth of the memory budget can
describe (about 200,000 with 13 GB available), and never fewer than 65,536.

The converter takes the source offline and read-only during preparation. It
builds ReFS metadata through Windows and preserves eligible payload extents.
The source conversion patches are applied only after preparation and the
pre-write verification gate succeed. The final installation remains on the
original source disk; the temporary shadow is working storage.

## If a run stops

- **Before apply:** the source has not received conversion patches and is
  returned as NTFS. If the geometry shrink ran, the partition keeps its slightly
  smaller size. Start again from the beginning; arbitrary power-cut resume
  during preparation is outside this alpha's qualification.
- **After source writes begin:** retain the working storage and use the exact
  recovery command and checksum printed before the write. Do not start another
  fresh conversion over the unfinished target.

```powershell
.\ntfs2refs.exe --recover <printed-directory> --recovery-sha256 <printed-checksum>
```

The CLI also exposes `--rollback` before handoff. Do not infer a qualified
Windows boot-volume rollback matrix from older data-volume experiments. Once
ordinary writable ReFS use has begun, restoring old NTFS metadata is unsafe.

The recovered `rec-04` record establishes successful post-apply finalization and
a healthy ReFS mount. Its independent before/after comparison was unavailable;
it is not an arbitrary power-loss or full-content recovery qualification.

### What recovery checks before it writes

Recovery reads the journal's lifecycle and every journaled range of the source
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
  the source is then repeated before anything is written. Only `--recover`
  does this: other commands refuse such a journal. The lab can end a process
  but cannot cut power to storage, so this is covered by tests of the marker
  images and by a lab run in which the image is made by hand, not by a real
  power loss.

## Verify the result

For the lab boot claim, the harness checks that only the original disk is
attached, Secure Boot is enabled, the running OS uses the original partition,
C: is healthy ReFS 3.14 with 4 KiB clusters, the stock loader and ReFS driver have
valid signatures, and sign-in reaches the desktop. A separate listing tool
compares source and target metadata and logical stream hashes.

A normal user's storage and boot setup requires its own validation. The alpha
has not established compatibility with physical hardware, BitLocker, arbitrary
Windows builds, every NTFS feature combination or very large volumes.

## Visible differences

Every preserved 8.3 short name is represented by a visible relative symbolic
link beside its long name. For example, Explorer can show `PROGRA~1` in C:.
NTFS-compressed files are represented without the NTFS compression flag.
The exact listing exceptions and counts are in the release qualification.

## Check first with `--diagnose`

```powershell
.\ntfs2refs.exe --drive D --windows-boot-volume --scratch-directory S:\runs --target-format dev-drive --diagnose
```

A diagnose run builds the complete ReFS shadow in the working directory, reports
every per-object failure instead of stopping at the first, and stops before
anything is published. ntfs2refs writes nothing to the source: it is offline and
read-only meanwhile and is returned as NTFS.

| Exit code | Meaning |
| ---: | --- |
| 0 | Every object was examined and none failed |
| 3 | Failures were reported, or the run stopped at its failure limit |
| 1 | The diagnosis itself could not finish |

The run stops after 500 failures, when it is rarely learning anything new.
`--diagnose-limit N` changes that number, and `--diagnose-limit 0` lists every
failure on the volume.

Diagnose is refused, before anything is started, where it could not keep that
promise: when a conversion would first shrink the partition (see above), and
with `--minimize-scratch`, `--whole-image-verification` or `--offline-media`.
It does not exercise the recovery journal, the apply step or the boot.

## Verification options

- **Default.** Data that stays in place is proven by the identity of its
  extents; resident, compressed, sparse and partly initialized streams, tails
  and everything rewritten are read and checksummed
  ([details](fast-verification.md)). Working files and the source are re-read
  in full once, at the gate before the first source write.
- **`--verify-full-content`** changes *what* is checked: every stream's complete
  contents are read and hashed. The recorded boot qualification used the default.
- **`--recheck-everything`** changes *how often*, not what: the full re-reads
  happen at every checkpoint instead of once at the gate. Much slower.
- **`--whole-image-verification`** is a different, older route for data
  volumes that compares and journals the whole image. Unlike the default
  route, which is bounded only by the machine's memory and working storage,
  it keeps fixed limits: 1,024 files, 256 directories and 4,096 placed NTFS
  runs. A larger volume is refused before anything is written. It converts to
  4 KiB clusters only.

None of these establishes hardware compatibility by itself.
