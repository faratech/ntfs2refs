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

Confirm the source disk and partition shown by the program. In this example,
`D:` is the old Windows installation and `S:` is independent working storage.
The demonstrated boot profile uses `dev-drive`; standard ReFS formatting and
other Windows versions do not inherit this qualification.

The drive interface also accepts explicit selection such as `--drive D --partition 3`.
That syntax is not a claim that every data-volume layout or feature is qualified.
The program refuses unsupported conditions instead of silently omitting them.

The converter takes the source offline and read-only during preparation. It
builds ReFS metadata through Windows and preserves eligible payload extents.
The source conversion patches are applied only after preparation and the
pre-write verification gate succeed. The final installation remains on the
original source disk; the temporary shadow is working storage.

## If a run stops

- **Before apply:** the source has not received conversion patches. Preparation
  can be started again; arbitrary power-cut resume during preparation is outside
  this alpha's qualification.
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

`--recheck-everything` restores the older repeated verification mode and can be
much slower. Normal mode still performs the verification gate before the first
source write. Neither mode establishes hardware compatibility by itself.
