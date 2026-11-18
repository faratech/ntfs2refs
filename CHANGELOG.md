# Changelog

What changed for someone who runs the converter. The measurements behind each
entry are in the pull request named beside it and in `docs/performance.md`.

## 0.0.1

The first release. The builds before it, 0.0.1-alpha to 0.3.0-beta.1, were
pre-releases; what changed since the last of them:

### What it converts

- **A data partition on the disk of the running Windows**, through a restart:
  `--restart-media <Windows installation media>`. The run prepares in Windows,
  restarts into a minimal Windows made from the media, converts there and
  returns. Until the conversion itself has started it can be cancelled, and
  cancels itself if it cannot go on, with the volume given back as the NTFS
  it was (#109). Shown on Windows Server 2025; see the guide for what it
  needs and what the lab has not shown.
- **MBR disks**: a volume that is the one partition of an MBR disk converts,
  and the working directory may be on any MBR disk. A volume that shares an
  MBR disk with other partitions is refused with what to do (#108).
- **What the Windows Subsystem for Linux leaves on a volume**: owner and mode
  on files and directories, and its symbolic links, sockets, FIFOs and device
  files (#104).
- **Names Win32 does not take and the file systems hold**: `con`, `aux.c`,
  `nul`, a trailing dot or space, a name of dots only. A name that is refused
  is named, with why.
- `--list` says of an optical drive or a mounted disc image what it is,
  instead of printing "Incorrect function (os error 1)" for it, and names a
  volume whose query fails by its drive letter (#147).
- A machine turned off while a run prepares: the cancellation afterwards
  gives the volume back and names the working files left (#112).
- A converted Windows meets Windows' own tools: its recovery environment
  starts, and Windows Setup repairs it in place from the installation media
  of its build (#113).

### Memory

- **A run fits itself to the memory there is.** Without `--memory-limit` it
  is no longer refused, and no longer stops, because a volume needs more
  than its share of the free memory: it goes on with the page file, is
  slower, and says so. `--check`'s figure is advice.
- **What a run holds only to go faster follows the machine while it runs**:
  it uses memory that becomes free and gives its caches back when another
  program needs the memory. 100,000 files converted as fast with 5 GB taken
  away half way as without.
- **A Windows volume converts on a machine with 4 GB of RAM** (143,552
  files and directories; converted and started in the lab), where it stopped
  with 1.8 GB for the run (#129, #158).
- `--memory-limit <MiB>` is a ceiling: a run given one keeps to it, and a
  limit below what the volume needs is refused before anything is built
  (#159).
- A run's memory follows the volume instead of fixed reservations: a volume
  of 500,000 files converts with 13 GB free, where it was refused with
  15.6 GiB free (#157, #160, #162, #164).

### Speed

- A full Windows volume converts faster than with 0.3.0-beta.1: parallel
  metadata passes where memory is spare, digests computed off the writing
  thread, records parsed as text, stream tails read in parallel (#141, #142,
  #143, #145, #152). `docs/performance.md` has the figures.

### Removed

- The routes and commands of earlier designs that `--help` did not list:
  `--whole-image-verification`, `--experimental-thin-shadow`,
  `--experimental-thin-backing-bytes`, `--experimental-allocation-bounded`,
  and the subcommands `inspect`, `plan`, `verify`, `diff`, `compare-retained`,
  `convert`, `resume`, `rollback`, `finalize`, `complete-label`,
  `operation-state` and `cancel`. `capabilities` is the one subcommand left.
  The executable is about a sixth smaller (25.8 MB for 31.2 MB). The tag `archive/hidden-routes`
  keeps the removed code. `--recover` and `--recover --rollback` are
  unchanged.

### For those who build it

- The checks and gates are two local commands, `lab\Invoke-Checks.ps1` and
  `lab\Invoke-GateRound.ps1`; the unit tests run in seconds (#153).
- The gate round has a case with middling memory: 100,000 files held to
  1,240 MiB, with a time bound (#164).
- The gate round has cases for MBR disks, WSL files, awkward names, a
  machine turned off while a run prepares, and memory taken away from a run;
  lab VMs fit the host's free memory and wait for it (#165).

## 0.3.0-beta.1 (2026-11-15)

- `--check`: reads a volume while it stays online and says every refusal a
  conversion would give, and what a conversion takes in working storage,
  memory and time. A conversion runs the same check before it changes
  anything (#119, #121).
- A data volume on a disk it shares with other partitions converts (#126).
- `--short-names drop` converts a data volume that has 8.3 short names (#133).
- `--compare-listing`: a run lists the volume before and after and compares
  the two (#122).
- Windows Server 2025 and standard ReFS as a target (#119).
- A directory's case-sensitive mark no longer refuses a volume when no two
  names in it differ only by case; the mark is not carried over (#121).
- Backup software's shadow-copy provider refuses a volume only if it holds
  something (#134).
- A disk that goes offline is given time to lose its volumes before it comes
  online again; a cancelled run says what it left behind (#128, #130).

## 0.2.0-beta.1 (2026-11-13)

- A used data volume converts; refusals say what to do; feature and recovery
  matrices (#93).
- A run that is cut off while it prepares can be cancelled with
  `--recover ... --rollback` (#97).

## 0.0.1-alpha (2026-11-11)

- A Windows boot volume converted in place from another Windows installation
  and started from ReFS in the lab (#27).
