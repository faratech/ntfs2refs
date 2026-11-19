<h1 align="center">ntfs2refs</h1>

<p align="center">
  <b>Convert an NTFS drive to ReFS in place, without reformatting.</b><br>
  For Windows 11 and Windows Server 2025.
</p>

<p align="center">
  <img alt="version 0.0.1" src="https://img.shields.io/badge/version-0.0.1-0078D6">
  <img alt="status: experimental" src="https://img.shields.io/badge/status-experimental-orange">
  <img alt="Windows 11 | Windows Server 2025" src="https://img.shields.io/badge/Windows-11%20%7C%20Server%202025-0078D6">
  <img alt="licence: evaluation only" src="https://img.shields.io/badge/licence-evaluation%20only-red">
</p>

> [!CAUTION]
> **EXPERIMENTAL SOFTWARE, FOR EVALUATION AND TESTING ONLY. DO NOT USE IT IN PRODUCTION.**
> It rewrites a drive's file system in place and has been tested only on
> virtual disks in a lab. Back up everything first, and check that the backup
> restores. No warranty: read [DISCLAIMER.md](DISCLAIMER.md) and [LICENSE](LICENSE).

ntfs2refs turns an NTFS volume into a ReFS (Resilient File System) volume on
the machine that owns the disk. Files, folders, streams, permissions, links
and timestamps come across; file data stays where it is on the disk wherever
ReFS can use it there, and only the file system around it is rebuilt. A run
that is interrupted is resumed or rolled back with the command it prints.

## What it converts

| | |
|---|---|
| **A data drive** on a disk of its own (GPT, or an MBR disk it has to itself) | `--drive E` |
| **A data partition beside Windows** on the system disk, through a restart | `--drive D --restart-media E:\` |
| **An installed Windows** that is not running, from a second Windows | `--drive D --windows-boot-volume` |

The new volume is a Dev Drive or standard ReFS (`--target-format`).

## Quick start

From an elevated terminal, with working storage on another disk:

```powershell
ntfs2refs --list                                         # which drives convert, and why not
ntfs2refs --drive E --scratch-directory S:\runs --check  # read-only: what it refuses and needs
ntfs2refs --drive E --scratch-directory S:\runs          # convert
```

## Requirements

- Windows 11 24H2 or Windows Server 2025 (build 26100 or later), x64, as administrator
- Working storage on a second disk; `--check` says how much
- A backup you have restored from

## Documentation

- [Guide](docs/cli-workflow.md): every option, what is refused and why, recovery
- [Feature matrix](docs/feature-matrix.md) and [recovery matrix](docs/recovery-matrix.md): what the lab has shown
- [Changelog](CHANGELOG.md) · [Performance](docs/performance.md) · [Disclaimer](DISCLAIMER.md)

## FAQ

**Can I convert NTFS to ReFS without formatting or losing data?**
That is what ntfs2refs does. It is experimental: back up first.

**Can it convert the drive Windows is running from?**
Yes, through a restart: `ntfs2refs --drive C --scratch-directory E:uns`
(`E:` on another disk) stages the machine's own Windows Recovery Environment,
restarts into it, converts the volume there and starts Windows again on ReFS.
Needs the recovery environment turned on (`reagentc /info`), no BitLocker, and
the working disk connected until Windows is back. Experimental: back up first.

**What does not come across?**
What ReFS does not have: object IDs, NTFS compression and the change journal;
on a data drive, 8.3 short names are refused or dropped. The guide lists each.

## Build

```powershell
cargo build --locked --release --bin ntfs2refs --bin ntfs2refs-recovery
```

Rust 1.98.1, Windows x64 (MSVC). Contributors: [AGENTS.md](AGENTS.md) and the [lab guide](lab/README.md).

## Licence

Version 0.0.1 · © 2026 Fara Technologies LLC · temporary evaluation licence,
all rights reserved: see [LICENSE](LICENSE). Not affiliated with Microsoft.
