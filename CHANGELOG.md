# Changelog

What changed for someone who runs the converter. The measurements behind each
entry are in the pull request named beside it and in `docs/performance.md`.

## Unreleased

### What it converts

- **The Windows the machine runs from (C:), with one command and a
  restart**: `ntfs2refs --drive C --scratch-directory E:\runs --boot-partition
  B`. In Windows the run only checks C: and changes nothing on it. It puts the
  converter inside the machine's own recovery environment and restarts. It
  converts C: there and starts Windows again, on ReFS. `E:` holds the working
  files: twice what C: holds, plus the reserve the run keeps. `B:` is a FAT32
  partition of 100 MB or more. Both must be on a disk other than Windows', for
  example one USB drive. Without `--boot-partition`, the one FAT32 partition
  on the working directory's disk is used. If power is lost or the machine is
  reset during the conversion, the next start goes back into the recovery
  environment, which recovers from the run's journal. A recovery that cannot
  finish stops at a prompt rather than start a Windows that may be half
  converted. Windows' own boot files and boot store are not changed. Shown on
  Windows 11 build 26300; not yet on Windows Server (#115, #186).
- **A volume that shares an MBR disk with other partitions**: the disk's
  other partitions go offline for the length of the run. An installed Windows
  on such a disk is still refused (#168).
- **A directory's case-sensitive mark is carried over on Windows Server
  2025**: for a data volume converted there, every directory of the new
  volume is made with the mark its source directory has, and the mark is
  read back and verified. Everywhere else the mark is still not set, and the
  run and `--check` now say why: on Windows 11 build 26300 Windows itself
  stops with a bugcheck when a ReFS volume holding such a directory is taken
  offline. A volume whose root directory is itself marked converts without
  any mark, as before. Two names that differ only by case are still refused
  (#103, #120).

### Verification and ways back

- **`--verify fast|thorough`** names the verification a conversion makes.
  `fast`, the default, proves data that stays in place by its extents.
  `thorough` reads every byte, as `--verify-full-content` did; that spelling
  still works (#148).
- **With `--verify fast` a rollback stays open until the converted volume has
  passed its verification.** Every new sector is written and read back, the
  disk is sealed again, the converted volume is mounted read-only and
  verified, and only then is the conversion committed and the volume put
  online. If the verification does not pass, nothing is committed and
  nothing is rolled back: the run gives both commands, to verify again and
  finish, or to put NTFS back. A rollback that follows checks the restored
  NTFS volume against the fingerprint taken before the conversion. With
  `--verify thorough` the conversion commits as before, once every new
  sector is written and read back (#148, #110).
- **A fast run checks each thing once**: where two checks prove the same
  thing, it makes one. A moved extent is held to the mapping of the range it
  moved, with each file's complete mapping compared once when placement
  ends. A changed range is held to its old contents before the apply and
  read back after it is written, and not read again just before. The
  journal's stored contents are compared with their digests as they are
  read back. Windows no longer reads again the contents of a plain stream
  (uncompressed, not sparse, all of it on disk): it confirms where the
  stream lies and that its data is written to its end, and every other
  comparison of what Windows shows with the converter's own reading of the
  volume stays. The new volume is not read back a second time before it is
  captured, and a converted Windows volume's short-name links are probed
  once. A fast run's preparation that was cut off is cancelled and started
  again, not resumed. `--verify thorough` and `--recheck-everything` make
  every check (#140).
- **The Windows the machine runs from is converted with the verification
  asked for**: `--verify thorough`, `--recheck-everything` and
  `--memory-limit` reach the converter in the recovery environment, and
  options that do not apply there are refused before the restart.
- **`--review`**, for a data volume on a disk of its own: the conversion stops
  before the handoff, with the new ReFS volume mounted read-only. Look at it,
  then commit with `--recover`, or give the NTFS volume back with
  `--recover --rollback`. A write made during the review refuses both (#110).
- **A rollback gives the drive letter back** where Windows does not mount
  volumes by itself (#174).
- **A finished recovery or cancellation detaches the run's working volume**
  (`shadow.vhdx`), so that the run folder can be deleted. In the recovery
  environment it is tried again once the recovery has ended. If it is still
  refused, the report says how to detach it by hand (#175, #182).
- **A run cut off before it started writing** gets the NTFS volume back from
  the `--recover` command it printed. There is nothing to resume (#177).
- **A run cut off while it wrote its preparation state** can be given back:
  the recovery takes what was last made durable of its two copies, and
  refuses any other disagreement as before (#200).
- **A run cut off in its first seconds** no longer leaves its working volume
  attached: one that stops on an error detaches it, and the next run or
  `--list` detaches what a killed run left, never one still running (#201).
- **In the recovery environment**, a rollback finds the source's fingerprint
  wherever the working volume is mounted now, and a marker torn there is
  settled although every disk comes up offline and read-only (#148).

### Speed and memory

- **Several threads where one did the work**: observing the source's objects,
  building the new volume's metadata, hard links and short-name links,
  reading the converted files back, and hashing the working files before the
  first write. Every check is the same. Where order matters, results are taken
  in the order one thread would have taken them. Helpers are as many as the
  processors and the memory budget allow (#140).
- **Less repeated work**: a working file is hashed once per check, not once
  for each record store that holds it. Extent placement costs less per move.
  Waits for a volume to appear look again sooner (#140).
- **BLAKE3 for bulk hashing**: working files, the recovery journal and the
  capture's file are hashed with BLAKE3 on several threads, where SHA-256
  ran at about 250 MB/s on a processor without SHA instructions. Every
  check is the same. A run started by an earlier build is still recovered
  with its SHA-256 digests; a run of this build cannot be recovered by an
  earlier build (#140).
- **Memory follows the volume, not the budget**. The sorts, the MFT
  bootstrap, placement and the recovery audit reserve what the volume needs.
  Caches are given back before a run goes beyond its budget (#129).

### What it says

- **The `memory:` line** says what the run set aside at its start, its peak
  and how much of that was caches, and what the process itself took (#167).
- **Windows' drive optimization**: a conversion or recovery that sees it
  running says what it is and how to turn its task off for a conversion
  (#132).

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
