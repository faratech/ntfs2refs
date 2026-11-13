# ntfs2refs

An experimental Rust tool for converting NTFS to ReFS in place. It runs on the
Windows machine owning the disk; Hyper-V is used only by the development lab.

The private [0.0.1-alpha release](https://github.com/faratech/ntfs2refs/releases/tag/0.0.1-alpha)
converted an existing Windows 11 installation and booted it from its original
disk, with no second disk attached and Secure Boot enabled. The recorded full-16
run took 28 minutes and reached the desktop. It used ReFS 3.14 with 4 KiB clusters.
This qualifies one lab configuration, not arbitrary hardware or every NTFS feature.

## Download and run

Use the published Windows x64 ZIP and its SHA-256 file. The archive contains
`ntfs2refs.exe`, the independent `lab-volume-manifest.exe`, and release notes.
The frozen source tag is `0.0.1-alpha`; the executable reports version `0.1.0`.
These existing artifacts are preserved unchanged.

Run from an elevated terminal in a separate Windows installation. The Windows
partition being converted must not be the running OS. Keep an independent backup
and working storage on another disk.

```powershell
.\ntfs2refs.exe --list
.\ntfs2refs.exe --drive D --windows-boot-volume --scratch-directory S:\runs --target-format dev-drive
```

Here `D:` is the existing NTFS Windows installation and `S:` holds temporary
construction and recovery files. The recorded 22.9 GB source used about 30 GB
of working storage. This is a measurement for that source, not a general bound.

Read the [operating and recovery guide](docs/cli-workflow.md) and
[exact release qualification](docs/history/release-0.0.1-alpha.md) before running it.

## Data volumes

A data volume on a disk of its own is converted with `--drive` alone. This is
newer than the release above and is not part of its qualification.

```powershell
.\ntfs2refs.exe --drive E --scratch-directory S:\runs
.\ntfs2refs.exe --drive E --scratch-directory S:\runs --target-cluster-bytes 65536
```

The source may have any geometry Windows formats NTFS with: clusters from 512
bytes to 2 MiB, 512-byte or 4096-byte (4Kn) sectors, 1 KiB or 4 KiB file
records. The target is ReFS with 4 KiB clusters, or with 64 KiB clusters when
`--target-cluster-bytes 65536` is given.

Data stays where it is only if it lies on boundaries of the target's cluster
size; the rest is copied through the working storage, which then needs room for
it. From NTFS clusters of 4 KiB or more to a 4 KiB target, and of 64 KiB or
more to a 64 KiB target, file data stays in place. From smaller clusters most
of it is copied.

ReFS covers a volume in whole units of 64 MiB. A partition that is not a
multiple of that is first shrunk to one by the Windows NTFS driver (by less
than 64 MiB). The converter says so before it asks for confirmation, and the
shrink is not undone if the run stops later.

The converter needs administrator rights and Windows build 26100 or later
(Windows 11 24H2, Windows Server 2025); it checks both before it opens a disk.
`ntfs2refs --list` says for each NTFS partition whether it can be converted and,
if not, why: the volume has to be the only partition on a GPT disk, apart from
a Microsoft reserved partition.

A volume that has been in use converts with these stated differences:

- **Object IDs are not carried over.** Windows gives a file one when a shortcut
  to it is made; ReFS has none. Each is checked against the volume's own index
  and kept in the run's records, and the run prints how many there are.
- **NTFS compression is removed**: compressed data becomes ordinary data.
- **The change journal starts anew.**

It is refused, before anything is written and with what to do about it, if it
has 8.3 short names (`fsutil 8dot3name strip` removes them), is encrypted with
BitLocker, has shadow copies, holds EFS-encrypted files, reparse points other
than symbolic links and junctions (cloud placeholders, `compact /exe`, Data
Deduplication), disk quotas in use or case-sensitive directories, or was not
dismounted cleanly. `ntfs2refs --drive E --diagnose` reports these without
converting.

`ntfs2refs capabilities` lists what a build of the tool admits;
[the lab guide](lab/README.md) describes how each geometry and each of these
cases was converted or refused and compared.

## What conversion preserves

Windows builds the new ReFS metadata on a temporary shadow. The converter retains
eligible source data extents and journals the required changes back to the
original partition. The final boot uses that original disk.

The independent listing comparison checks file contents, streams, names, hard-link
relationships, timestamps, security and supported reparse/extended attributes.
The recorded comparison had zero unexpected differences. Its explicit
normalizations include short names represented as visible links, removal of the
NTFS compression flag, and specified filesystem-internal/cache metadata.

## Recovery

Keep the recovery directory and checksum printed before source writes begin.
Use the printed command from the separate control OS after an interrupted apply:

```powershell
.\ntfs2refs.exe --recover <printed-directory> --recovery-sha256 <printed-checksum>
```

A run that stops before apply leaves NTFS in place and can be started again
from the beginning (a partition the converter had to shrink to a 64 MiB
multiple keeps that size). A recovery works in the ReFS cluster size the run
was started with; it is not given again. Power-cut resume through every preparation stage is
not qualified. Post-apply recovery was observed
separately; its precise evidence and limits are described in the release guide.

## Development

See [AGENTS.md](AGENTS.md) for the current development contract and
[the lab guide](lab/README.md) for reproducible conversion attempts.

```powershell
cargo test --locked --workspace --all-targets
cargo build --locked --release --bin ntfs2refs --bin lab-volume-manifest
```

Rust 1.98.1 and Windows x64 MSVC are the current toolchain. Release closeout keeps
the qualified package unchanged. Earlier experimental builds and results remain
in `docs/history/`, the dated technical documents and `evidence/`; their old
pending statements and limits do not describe every later build.
