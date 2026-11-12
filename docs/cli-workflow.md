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

If the Windows partition's length is not a multiple of 64 MiB, the converter
first asks the Windows NTFS driver to shrink it to one (by less than 64 MiB).
It says so before the confirmation prompt. The shrink is not undone if the run
stops later.

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
  runs. A larger volume is refused before anything is written.

None of these establishes hardware compatibility by itself.
