# What a conversion does with each NTFS feature

One row per feature of a volume, with what the default route does with it and
the lab case that shows it. A lab case is an attempt of
`lab\Invoke-DataVolumeAttempt.ps1` (its `-Content` or `-Features` name is the
last word of the case) or of `lab\Invoke-BootConversionAttempt.ps1`; `lab/README.md`
describes both. "Identical" means that the listing of the volume before and
after the conversion is the same under `lab-volume-manifest compare`, which
reads every file and stream in full.

`tests/feature_matrix.rs` keeps the remedies quoted here equal to what the
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
| A path of more than 260 characters | `longpath` |
| A file under 40 nested directories | `deep` |
| A directory of 20,000 entries | `bigdir` |
| Program files copied with the security Windows gave them | `copy` |
| All of these on one volume, to 4 KiB and to 64 KiB ReFS clusters, from 512-byte NTFS clusters, as an administrator, and interrupted and then resumed or rolled back | `lived-in` and its variants |
| Every NTFS cluster size from 512 bytes to 2 MiB; 4Kn disks; 4096-byte file records | the geometry cases (`512-to-4k`, `4kn-4k`, ...) |
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

## Refused before anything is written

Each is refused with the source unchanged: the volume lists exactly as before.
Each is found before the volume is taken offline: BitLocker from the volume's
first sector, the others by the check a run makes before it asks. `--check`
reports them without a run; in the lab each case is run with `-Check`, and the
check and the run have to give the same refusal.

| Found | What the refusal says to do | Lab case |
|---|---|---|
| 8.3 short names on a data volume | `fsutil 8dot3name strip /s /f <drive>:\`, then `fsutil 8dot3name set <drive>: 1` | `shortnames`; the remedy: `shortnames-stripped`, which converts |
| A BitLocker-encrypted volume | `manage-bde -off <drive>` | `bitlocker` |
| Shadow copies of the volume | `vssadmin delete shadows /for=<drive>:` | `snapshot` |
| EFS-encrypted files | `cipher /d` | `efs` |
| A file with the TEMPORARY or OFFLINE attribute | the attribute is named | `temporary`, `offline` |
| A file compressed with `compact /exe` | `compact /u /exe <file>` | `wof` |
| A named data stream on a directory | remove the stream | `dirstream` |
| Disk quotas in use | `fsutil quota disable <drive>:` | `quota` |
| A case-sensitive directory | `fsutil file setCaseSensitiveInfo <directory> disable` | `casesensitive` |

## Refused, and not made in the lab

These take the same paths as rows above, or are checked by tests only.

| Found | Why it is not a lab case |
|---|---|
| Cloud placeholders, Data Deduplication, Windows Subsystem for Linux files | Refused by their reparse tag, like `compact /exe`; the lab has no sync provider, deduplication or WSL. The words for each tag are covered by a test |
| A shadow-copy provider other than Windows' own, Hyper-V's and Windows Server's for remote file shares | The lab has no backup product. The message is covered by a test |
| A dirty volume, an NTFS log that was not closed, an open transaction | The lab dismounts its volumes cleanly |
| A program holding a file on the volume open | Not arranged in the lab; the lock is retried for 20 seconds and then refused by name |
| A volume with no file on it | An empty volume is formatted, not converted |
| A data volume beside other partitions, on an MBR disk, or on the running Windows disk | Refused from the disk's layout; `ntfs2refs --list` says so for each partition |

## Not shown at all

- A physical disk, and a volume holding more than 23 GB of data: every lab
  disk is virtual.
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
- `--minimize-scratch`, and the routes and commands of earlier designs that
  `--help` no longer lists.
