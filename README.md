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
[exact release qualification](docs/release-0.0.1-alpha.md) before running it.

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

Preparation interrupted before apply can be started again. Power-cut resume
through every preparation stage is not qualified. Post-apply recovery was observed
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
