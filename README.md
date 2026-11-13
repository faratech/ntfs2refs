# ntfs2refs

Converts an NTFS volume to ReFS in place, on the Windows machine that owns the
disk. File data stays where it is on the disk wherever ReFS can use it there;
only the file system around it is replaced.

This is version 0.2.0-beta.1, a beta. Everything it has converted was a
virtual disk in a lab, the largest holding 23 GB. Keep a backup you have
restored from before, and read [what the lab showed and did not
show](#what-has-been-shown) before trusting it with a volume.

## What it converts

- **A data volume** that is the only partition on its disk:
  `ntfs2refs --drive E --scratch-directory S:\runs`.
- **An installed Windows that is not running**, from a second Windows on
  another disk: `--windows-boot-volume`. One Windows build has been converted
  and booted this way; any other is refused. See the
  [guide](docs/cli-workflow.md#convert-an-installed-windows).

It does not convert the Windows it is running on, a partition that shares its
disk with others, or a volume on an MBR disk. `ntfs2refs --list` says for each
NTFS partition whether it can be converted and, if not, why.

## What you need

- Windows 11 24H2, Windows Server 2025 or later (build 26100 or later), x64.
  Conversions were run on builds 26100 and 26300; on another build the run says
  before it starts that it is the first.
- An elevated terminal.
- Working storage on a different disk (`--scratch-directory`). The run builds
  the new file system there and keeps there what it needs to undo its changes.
  The lab's Windows volume, with 22.9 GB in use, needed about 30 GB; a volume
  whose NTFS clusters are smaller than the ReFS clusters asked for needs room
  for most of its data.
- A backup. A beta that rewrites a file system is not a substitute for one.

The result is a ReFS volume formatted as a Dev Drive unless
`--target-format standard` is given, which works only where Windows itself
formats ordinary ReFS volumes. See [the target](docs/cli-workflow.md#the-target).

## Use

```powershell
.\ntfs2refs.exe --list
.\ntfs2refs.exe --drive E --scratch-directory S:\runs --diagnose
.\ntfs2refs.exe --drive E --scratch-directory S:\runs
```

`--diagnose` goes through the whole preparation, reports everything that would
stop a conversion, and writes nothing to the volume. The conversion itself
asks for confirmation, prints a recovery command before its first write to the
volume, and ends with the volume online as ReFS under the same drive letter.

The [operating and recovery guide](docs/cli-workflow.md) has the details: the
options, what each refusal means, and what to do if a run stops.

## What changes on the volume

Files, directories, named streams, hard links, sparse files, security,
timestamps, attributes, extended attributes, junctions and symbolic links are
carried over. Three things are not, and the run says so:

- **Object IDs.** Windows gives a file one when a shortcut to it is made. ReFS
  has none. Each is checked against the volume's own index and kept in the
  run's records. A shortcut still finds its target by its path.
- **NTFS compression.** Compressed data becomes ordinary data and needs the
  room for it.
- **The change journal.** The converted volume starts a new one.

A data volume is refused, before anything is written and with what to do about
it, if it has 8.3 short names, is encrypted with BitLocker, has shadow copies,
or holds EFS-encrypted files, cloud placeholders, `compact /exe` files, Data
Deduplication, disk quotas in use or case-sensitive directories, or was not
dismounted cleanly. The guide lists each with its remedy, and
[the feature matrix](docs/feature-matrix.md) has one row per NTFS feature.

On a converted Windows volume each 8.3 short name becomes a link beside the
long name, so `C:\PROGRA~1` still leads to `C:\Program Files`. The links are
visible in Explorer.

## If a run stops

A run prints a recovery command before its first write to the volume. If it
stops after that, keep the working storage and run that command:

```powershell
.\ntfs2refs.exe --recover <printed-directory> --recovery-sha256 <printed-checksum>
```

That finishes the conversion. With `--rollback` it puts NTFS back instead,
which is possible until the last new sector is on the disk.

A run that stops earlier has written nothing. If it ended by itself, with a
refusal or an error, the volume is back as NTFS: start again. If it was cut
off, the volume is left offline, and the command the run printed at its start
(`To get it back as NTFS: ...`) gives it back.

[The guide](docs/cli-workflow.md#if-a-run-stops) has both cases, and how to
find either command again when the screen is gone.

## What has been shown

- [The feature matrix](docs/feature-matrix.md): what a conversion does with
  each NTFS feature, each row with the lab case that shows it.
- [The recovery matrix](docs/recovery-matrix.md): every point at which a
  conversion was stopped, how it was stopped, and how each recovery ended.
  That includes the full Windows volume with the machine turned off half way
  through the writes: resumed, it starts on ReFS; rolled back, on NTFS.
- Converted volumes were then used: written to, filled, snapshotted, taken
  offline and brought back. The converted Windows passed `sfc`, a DISM scan
  and a servicing change, and started again twice.

Not shown: a physical disk; a volume holding more than 23 GB; a power cut to
the storage itself (the lab turns a virtual machine off, and its disks are
files of the host); a Windows build other than 26100 and 26300; a ReFS version
other than 3.14.

`ntfs2refs capabilities` prints what a given executable admits and refuses.

## Build

```powershell
cargo test --locked --workspace --all-targets
cargo build --locked --release --bin ntfs2refs --bin lab-volume-manifest
```

Rust 1.98.1, Windows x64 MSVC. `lab\New-Release.ps1` builds the release ZIP.
[AGENTS.md](AGENTS.md) has the rules a change is held to, and
[the lab guide](lab/README.md) how conversions are run and compared.
[docs/history](docs/history/README.md) holds the documents of earlier designs
and builds; they do not describe this one.
