# What a conversion does with each NTFS feature

One row per feature of a volume, with what the default route does with it and
the lab case that shows it. A lab case is an attempt of
`lab\Invoke-DataVolumeAttempt.ps1` (its `-Content` or `-Features` name is the
last word of the case) or of `lab\Invoke-BootConversionAttempt.ps1`; `lab/README.md`
describes both. "Identical" means that the listing of the volume before and
after the conversion is the same under `lab-volume-manifest compare`, which
reads every file and stream in full.

`tests/it/feature_matrix.rs` keeps the remedies quoted here equal to what the
converter prints.

## Carried over

| Feature | Lab case |
|---|---|
| Files of every size around the resident, cluster and megabyte boundaries; nested and empty directories; names outside ASCII; a 200-character name | `mixed` (every data-volume case that is not `minimal`) |
| Named data streams on files, small and larger than the file | `mixed` |
| Hard links, in one directory and across two | `mixed` |
| Sparse files, up to 70,000 separately allocated islands | `mixed`, `many` |
| Fragmented files | `mixed` |
| Read-only, hidden and system attributes; creation and write times of any age | `mixed` |
| Explicit and deny access entries, a protected directory, another owner, an audit entry | `security` |
| Extended attributes, up to 30,000 bytes | `ea` |
| Junctions and symbolic links: to a file, to a directory, relative, dangling | `links` |
| What the Windows Subsystem for Linux leaves on a volume: owner and mode in extended attributes on files and directories, and its own kinds of file (symbolic link, socket, FIFO, character and block device) with their reparse tags. ReFS as Windows formats it takes them too (`wsl-control`) | `wsl` |
| Names that Win32's path syntax does not take and both file systems hold: `con`, `aux.txt`, a directory `nul`, a trailing dot, a trailing space, a name of dots only; and names in Chinese, Japanese, Korean, Arabic and Hebrew, with a right-to-left override, surrogate pairs, combining marks, a zero-width joiner, and 255 Cyrillic letters | `names` |
| A path of more than 260 characters | `longpath` |
| A file under 40 nested directories | `deep` |
| A directory of 20,000 entries | `bigdir` |
| Program files copied with the security Windows gave them | `copy` |
| All of these on one volume, to 4 KiB and to 64 KiB ReFS clusters, from 512-byte NTFS clusters, as an administrator, and interrupted and then resumed or rolled back | `lived-in` and its variants |
| Every NTFS cluster size from 512 bytes to 2 MiB; 4Kn disks; 4096-byte file records | the geometry cases (`512-to-4k`, `4kn-4k`, ...) |
| A volume that is the one partition of an MBR disk, and a working directory on an MBR disk; both together, interrupted half way through the writes and resumed | `mbr-src`, `mbr-work`, `mbr-apply-mid-resume` |
| A volume that shares its GPT disk with other partitions: an EFI system partition, an NTFS volume, a write-protected NTFS volume and a partition of another operating system. The volume converts; the NTFS volume beside it lists exactly as before, and the bytes of the other three are the same. Also to 64 KiB clusters, as an administrator, with a partition that is shrunk first, interrupted and then resumed or rolled back, and on Windows Server 2025 to standard ReFS | `shared` and its variants (`-Siblings`) |
| A Windows boot volume with its short names, 25 nested directories and 320 object IDs | `used-windows-fixture40` (boot harness, `-ShapeSource Add-UsedWindowsObjects.ps1`) |
| On Windows Server 2025 (build 26100), to standard ReFS: the `mixed` set from 512-byte and 4 KiB clusters and on a 4Kn disk, to 4 KiB and 64 KiB ReFS clusters, as an administrator, unattended, and interrupted and then resumed or rolled back; a `lived-in` volume, then used. The `mixed` set there to a Dev Drive as well | the `s6-std-*` cases (`-TargetFormat standard`) and `s6-devdrive`, on the VM that `lab\New-ServerLabVm.ps1` makes |

## Carried over with a stated difference

| Feature | Difference | The run says | Lab case |
|---|---|---|---|
| Object IDs of files and directories (Windows gives one to the target of a shortcut) | Not carried over: ReFS has none. Each is matched with the volume's object-ID index and kept in the run's records | "N file(s) and directories have an object ID ... not carried over" | `objectids`, `manyobjectids` (3,050 of them) |
| NTFS (LZNT1) compression | The data is stored uncompressed; the listing accepts the missing flag | "NTFS-compressed streams ... are decoded into ordinary ReFS data" | `mixed` on clusters up to 4 KiB |
| The change journal | The converted volume starts a new one | nothing | `usn` |
| A partition whose length is not a multiple of 64 MiB | The NTFS driver shrinks it to one first, by less than 64 MiB; not undone if the run stops | the sizes, before the prompt | `odd-size` |
| 8.3 short names on a Windows boot volume | Each becomes a link beside its long name | the boot profile line | the Windows fixtures |
| With `--short-names drop`: the 8.3 short names of a data volume | Not carried over: every object is created under its long name, and each short name is kept in the run's records. On nested directories, a hard-linked file, a file with a named stream and names outside ASCII; the listing is compared with the comparison made for such a run, which counts a short name that is gone and lets nothing else through | "N file(s) and directories have an 8.3 short name ... not carried over" | `shortnames-drop`, `wide-drop` and its variants (`-DropShortNames`) |
| The case-sensitive mark of a directory in which no two names differ only by case (WSL and Git set it) | Not set on the new volume. Every name stays reachable, and the directories are kept in the run's records. Windows' own ReFS takes the mark on both lab systems (`casemark-control`); on Windows 11 build 26300 that control stopped Windows with a bugcheck both times it was run, when the volume was taken offline (#120) | "N directories are marked case-sensitive ... The converter does not set the mark on the new volume", before the prompt | `casemark` |
| On the machine: a shadow-copy provider of backup software that answers Windows and holds no shadow copy | The volume converts. Software that keeps track of what changed on it since its last backup will not recognise it afterwards | "A shadow-copy (VSS) provider that the converter does not know is installed ... make a full backup afterwards" | `vss-answering` (Windows Server's iSCSI target storage provider, on Windows Server) |

## Refused before anything is written

Each is refused with the source unchanged: the volume lists exactly as before.
Each is found before the volume is taken offline: BitLocker from the volume's
first sector, the others by the check a run makes before it asks. `--check`
reports them without a run; in the lab each case is run with `-Check`, and the
check and the run have to give the same refusal.

| Found | What the refusal says to do | Lab case |
|---|---|---|
| A volume that shares an MBR disk with other partitions | Convert the disk to GPT with `mbr2gpt`, or move the other partitions off it. (A volume that has an MBR disk to itself converts, and the working directory may be on any MBR disk) | `mbr-beside` |
| 8.3 short names on a data volume | `fsutil 8dot3name strip /s /f <drive>:\`, then `fsutil 8dot3name set <drive>: 1` | `shortnames`; the remedy: `shortnames-stripped`, which converts |
| A BitLocker-encrypted volume | `manage-bde -off <drive>` | `bitlocker` |
| Shadow copies of the volume | `vssadmin delete shadows /for=<drive>:` | `snapshot` |
| A shadow-copy provider of backup software (any but Windows' own, Hyper-V's and Windows Server's for remote file shares) that does not answer when Windows asks it | Repair or remove the provider, which is named: whether it holds shadow copies cannot be known | `vss-silent` (a provider registered without its class) |
| EFS-encrypted files | `cipher /d` | `efs` |
| A file with the TEMPORARY or OFFLINE attribute | the attribute is named | `temporary`, `offline` |
| A file compressed with `compact /exe` | `compact /u /exe <file>` | `wof` |
| A named data stream on a directory | remove the stream | `dirstream` |
| Disk quotas in use | `fsutil quota disable <drive>:` | `quota` |
| Two names in one directory that differ only by case | rename one of them, then `fsutil file setCaseSensitiveInfo <directory> disable` | `casesensitive` |
| Beside the volume, on its disk: a volume with shadow copies | `vssadmin delete shadows /for=<drive>:` for that volume | `shared-snapshot`; the shadow copy is still there afterwards |
| On the volume's disk: the crash-dump file of the running Windows | move the dump file (System Properties, Advanced, Startup and Recovery) | `shared-dump` |
| Beside the volume, on its disk: a volume on which a program has a file open | close the program. Found when the run locks that volume, after waiting 20 seconds: the one refusal here that `--check` cannot give | `shared-busy` |

## Refused, and not made in the lab

These take the same paths as rows above, or are checked by tests only.

| Found | Why it is not a lab case |
|---|---|
| Cloud placeholders, Data Deduplication | Refused by their reparse tag, like `compact /exe`; the lab has no sync provider or deduplication. The words for each tag are covered by a test |
| A shadow-copy provider of backup software that holds a shadow copy on the machine | The lab has no backup product that makes one. The decision and its words are covered by a test |
| A dirty volume, an NTFS log that was not closed, an open transaction | The lab dismounts its volumes cleanly |
| A program holding a file on the volume open | Not arranged in the lab; the lock is retried for 20 seconds and then refused by name |
| A volume with no file on it | An empty volume is formatted, not converted |
| A data volume on the running Windows disk | Refused from the disk's layout; `ntfs2refs --list` says so for each partition |
| A page file of the running Windows on the volume's disk | Takes a restart with the lab's disk attached; it is refused by the check that refuses the crash-dump file (`shared-dump`) |
| A volume beside the source that stores the shadow copies of another volume | Refused with the shadow copies of the volume itself; the words are covered by a test |

## Not shown at all

- A physical disk, and a volume holding more than 23 GB of data: every lab
  disk is virtual.
- A data volume of more than 500,000 files. One of 500,000 small files
  converts in 45 minutes; a run wants about 15 KiB of free memory a file as
  things are, and with less takes the rest from the page file and is slower
  (#129).
- Index records other than 4 KiB, a ReFS later than 3.14, and a Windows build
  other than 26100 and 26300: nothing in the lab makes them. A run on such a
  build or ReFS version says that it is the first.
- A conversion to standard ReFS (`--target-format standard`) on Windows 11:
  the lab's Windows 11 does not format one, and the run stops there with what
  Windows said, before the volume is touched. Windows Server formats one; see
  the row for it above.
- A Windows boot volume of Windows Server, and Windows 11 on build 26100:
  the lab's Windows 11 is build 26300 and its Windows Server is the control
  OS of data-volume attempts only.
- `--minimize-scratch`, and `--offline-media`, the route of an earlier design
  that `--help` does not list.
