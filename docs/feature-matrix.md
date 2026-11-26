# What a conversion does with each NTFS feature

One row per feature of a volume, with what the default route does with it and
the lab case that shows it. A lab case is an attempt of
`lab\Invoke-DataVolumeAttempt.ps1` (its `-Content` or `-Features` name is the
last word of the case) or of `lab\Invoke-BootConversionAttempt.ps1`. The
preformatted index-record fixtures use `lab/guest/Prepare-NtfsIndexFixture.ps1`.
`lab/README.md` describes the fixture and harness procedures. "Identical" means that the listing of the volume before and
after the conversion is the same under `lab-volume-manifest compare`, which
reads every file and stream in full.

`tests/it/feature_matrix.rs` keeps the remedies quoted here equal to what the
converter prints.

## Carried over

| Feature | Lab case |
|---|---|
| Files of every size around the resident, cluster and megabyte boundaries; nested and empty directories; names outside ASCII; a 200-character name | `mixed` (every data-volume case that is not `minimal`) |
| Named data streams on files, small and larger than the file | `mixed` |
| Named data streams on directories, as the same directory's named streams on ReFS: one of 31 bytes, and one of 1,115,200 bytes that ends inside a cluster. Converted with identical listings and passed acceptance alone (`ds3-dirstream-minimal`) and with a lived-in volume (`ds3-dirstream-lived-in`), each with `-Check -Acceptance`. One on the root directory, on a reparse-point directory, or one that is encrypted, compressed or sparse is still refused, by name | `dirstream` |
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
| Experimental `--minimize-scratch` on an 8 GiB mixed data volume. Conversion and resume gave identical listings. Rollback gave an exact NTFS listing. Sampled peak working storage was 189.4 MiB without the option and 182.0 MiB with it in the paired gate. | `scratch-standard`, `scratch-minimized`, `scratch-minimized-resume`, `scratch-minimized-rollback` |
| Every NTFS cluster size from 512 bytes to 2 MiB; 4Kn disks; 4096-byte file records | the geometry cases (`512-to-4k`, `4kn-4k`, ...) |
| A preformatted NTFS data volume with 2 KiB index records, 512-byte sectors, 4 KiB clusters and 1 KiB file records. Windows Server 2025 build 26100 (SKU 79) converted it to standard ReFS 3.14 with 4 KiB clusters. All 1,029 objects compared identically. The converted volume mounted read-only after a guest restart. | `index184-2k`, with `index184-4k` as the control. [Native verdicts](https://github.com/faratech/ntfs2refs/issues/184#issuecomment-7142377380) |
| A volume that is the one partition of an MBR disk, and a working directory on an MBR disk; both together, interrupted half way through the writes and resumed; a volume that shares its MBR disk with another NTFS volume, which goes offline with it | `mbr-src`, `mbr-work`, `mbr-apply-mid-resume`, `mbr-beside` |
| A volume that shares its GPT disk with other partitions: an EFI system partition, an NTFS volume, a write-protected NTFS volume and a partition of another operating system. The volume converts; the NTFS volume beside it lists exactly as before, and the bytes of the other three are the same. Also to 64 KiB clusters, as an administrator, with a partition that is shrunk first, interrupted and then resumed or rolled back, and on Windows Server 2025 to standard ReFS | `shared` and its variants (`-Siblings`) |
| A Windows boot volume with its short names, 25 nested directories and 320 object IDs | `used-windows-fixture40` (boot harness, `-ShapeSource Add-UsedWindowsObjects.ps1`) |
| The converted Windows afterwards: used and serviced (`sfc`, DISM, a feature), its recovery environment started, and repaired in place by Windows Setup from the installation media of its build | `rc3-use-1013` (boot harness, `-Acceptance`, then `setup.exe /Auto Upgrade`) |
| On Windows Server 2025 (build 26100), to standard ReFS: the `mixed` set from 512-byte and 4 KiB clusters and on a 4Kn disk, to 4 KiB and 64 KiB ReFS clusters, as an administrator, unattended, and interrupted and then resumed or rolled back; a `lived-in` volume, then used. The `mixed` set there to a Dev Drive as well | the `s6-std-*` cases (`-TargetFormat standard`) and `s6-devdrive`, on the VM that `lab\New-ServerLabVm.ps1` makes |

## Carried over with a stated difference

| Feature | Difference | The run says | Lab case |
|---|---|---|---|
| Object IDs of files and directories (Windows gives one to the target of a shortcut) | Not carried over: ReFS has none. Each is matched with the volume's object-ID index and kept in the run's records | "N file(s) and directories have an object ID ... not carried over" | `objectids`, `manyobjectids` (3,050 of them) |
| NTFS (LZNT1) compression | The data is stored uncompressed; the listing accepts the missing flag | "NTFS-compressed streams ... are decoded into ordinary ReFS data" | `mixed` on clusters up to 4 KiB |
| The change journal | The converted volume starts a new one | nothing | `usn` |
| Disk quotas (quota management, limits, entries for users) | Not carried over: ReFS has no NTFS quotas. Both quota indexes are read in full and every entry is kept in the run's records; the listing has no quotas in it, so it compares as ever. Not yet shown: the case is in the gate round and has not been run | "Disk quotas are set on this volume ... not carried over", before the prompt | `quota` (to be run) |
| Converted to plain, once its list is agreed: the TEMPORARY or OFFLINE attribute of a file or directory without a reparse point | The attribute is cleared; contents and every other attribute stay. Each object is kept in the run's records (`plain-conversions.json`) | "Converted to plain: N object(s) ..." and its own question before the prompt; `--check` exits 7 | `temporary`, `offline` (to be run: before this version they were refused) |
| Converted to plain, once its list is agreed: a file `compact /exe` or CompactOS keeps compressed with WOF (XPRESS4K, XPRESS8K, XPRESS16K, LZX) | Its bytes are copied through WOF on the frozen volume and the new file is made from the copy, uncompressed; WofCompressedData and the reparse point are not carried over. Refused, with the numbers, where the volume would not have room | "Converted to plain: N object(s) ...", with the extra space, and its own question before the prompt | `wof` with `-AcceptPlain` (to be run) |
| Converted to plain, once its list is agreed: a cloud placeholder (OneDrive and other Cloud Files API providers), fully present, partly present, not present or pinned, and a folder of them | What is not on the device is downloaded from its provider before the freeze (a change that is not undone); the frozen volume has to hold every byte. The new file is made from a copy read through the Cloud Files filter, without the reparse point and the pin, recall, OFFLINE and sparse marks. The folder stops syncing: the provider does not run on ReFS | "Cloud placeholders: ... wholly on this device, ... partly and ... not at all", the bytes to download, and a warning that the folders stop syncing | `cloud` with `-AcceptPlain` (to be run) |
| Left out, once agreed apart from the list: cloud placeholders that cannot be brought onto the device (provider stopped, or a folder not listed in full), and everything below a folder left out | Not made on the new volume; they stay in the cloud. Each has its own `cloud_left_out` row, and the new volume is checked against the source's counts less exactly those objects, their streams and bytes | Their list and its own question (`--leave-out-cloud <sha256>` unattended) | `cloud-down-leave-out` (to be run) |
| Converted to plain, once its list is agreed and where the run's account holds the key: an EFS-encrypted file, or a directory marked encrypted | The file is read decrypted and made plain; its $EFS attribute and the encrypted mark are not carried over. Anyone its permissions allow can read it afterwards | the "Converted to plain" section, with its warnings (readable by permissions, plain text in the working storage until the run ends, BitLocker recommended) | `efs` with `-AcceptPlain -RunAs administrator` (to be run); `efs-nokey`, as SYSTEM, refused by name |
| Converted to plain, once its list is agreed and where this Windows has the Data Deduplication filter (Windows Server): a file Data Deduplication has optimized | Read through the filter into a copy, and made plain from it; its reparse point is not carried over. On a Windows without the filter, refused by name with the two remedies | the "Converted to plain" section and its own question | `dedup` on ntfs2refs-server2025 with `-AcceptPlain` (to be run) |
| On a data volume, what `System Volume Information` holds below its own folders (a chkdsk log; Data Deduplication's chunk store, once every deduplicated file is made plain) | Not carried over, and needs no answer: each object is recorded in `plain-conversions.json` (`system_volume_information_not_carried`, with each stream's length and SHA-256) and left out of the new volume; the folder, its own files and the folders directly in it are made. The chunk store, where a deduplicated file is not made plain, is refused by name with the remedies | a note of the check, with their number and bytes | `svi-deep` (to be run); `dedup` on ntfs2refs-server2025 |
| A partition whose length is not a multiple of 64 MiB | The NTFS driver shrinks it to one first, by less than 64 MiB; not undone if the run stops | the sizes, before the prompt | `odd-size` |
| 8.3 short names on a Windows boot volume | Each becomes a link beside its long name | the boot profile line | the Windows fixtures |
| The 8.3 short names of a data volume (the default, or `--short-names drop`) | Not carried over: `--check` and the lines before the question say how many and where they are listed, every object is created under its long name, and each short name is kept in the run's records. On nested directories, a hard-linked file, a file with a named stream and names outside ASCII; the listing is compared with the comparison made for such a run, which counts a short name that is gone and lets nothing else through | "N file(s) and directories have an 8.3 short name ... not carried over" | `shortnames` (the default), `shortnames-drop`, `wide-drop` and its variants (`-DropShortNames`) |
| The case-sensitive mark of a directory in which no two names differ only by case (WSL and Git set it), on Windows 11 | Not set on the new volume. Every name stays reachable, and the directories are kept in the run's records. Windows' own ReFS takes the mark on both lab systems (`casemark-control`); on Windows 11 build 26300 that control stopped Windows with a bugcheck both times it was run, when the volume was taken offline (#120), so the converter sets the mark only where the control passed | "N directories are marked case-sensitive ... The converter does not set the mark on the new volume", with the Windows this is and where the mark is set, before the prompt | `casemark` |
| The same mark, for a data volume converted on Windows Server 2025 (build 26100) | None intended: every directory is made with the mark its source directory has (set, or cleared where it is an ordinary directory inside a marked one), the mark is read back, and the listing compares it. A volume whose root directory is itself marked converts without any mark, as on Windows 11, and says so. Not yet shown: the cases are in the gate round and have not been run (#103) | "N directories are marked case-sensitive ... The converter sets the mark on the same directories of the new volume as it makes them, and reads it back", before the prompt | `std-casemark`, `devdrive-casemark`, `std-casemark-apply-mid-resume`, `std-casemark-apply-mid-rollback` (to be run) |
| On the machine: a shadow-copy provider of backup software that answers Windows and holds no shadow copy | The volume converts. Software that keeps track of what changed on it since its last backup will not recognise it afterwards | "A shadow-copy (VSS) provider that the converter does not know is installed ... make a full backup afterwards" | `vss-answering` (Windows Server's iSCSI target storage provider, on Windows Server) |

## Refused before anything is written

Each is refused with the source unchanged: the volume lists exactly as before.
Each is found before the volume is taken offline: BitLocker from the volume's
first sector, the others by the check a run makes before it asks. `--check`
reports them without a run; in the lab each case is run with `-Check`, and the
check and the run have to give the same refusal.

| Found | What the refusal says to do | Lab case |
|---|---|---|
| 8.3 short names on a data volume, with `--short-names refuse` | `fsutil 8dot3name strip /s /f <drive>:\`, then `fsutil 8dot3name set <drive>: 1` | `shortnames-refuse` (`-RefuseShortNames`); the remedy: `shortnames-stripped`, which converts |
| A BitLocker-encrypted volume | `manage-bde -off <drive>` | `bitlocker` |
| Shadow copies of the volume | `vssadmin delete shadows /for=<drive>:` | `snapshot` |
| A shadow-copy provider of backup software (any but Windows' own, Hyper-V's and Windows Server's for remote file shares) that does not answer when Windows asks it | Repair or remove the provider, which is named: whether it holds shadow copies cannot be known | `vss-silent` (a provider registered without its class) |
| EFS-encrypted files the run's account cannot decrypt, or of a shape not made plain (named streams, compressed or sparse and encrypted), or without the list agreed | run as the user who encrypted them, import their key or use the recovery agent; or `cipher /d` | `efs-nokey`; `efs` without `-AcceptPlain` |
| A file compressed with `compact /exe` on a Windows boot volume, backed by a WIM image, or on a data volume without its list agreed | `compact /u /exe <file>` | `wof` (without `-AcceptPlain`) |
| Cloud placeholders not wholly on the device that could not be downloaded before the freeze (each named), or a folder its provider has not listed in full, without leaving them out agreed; or one the Cloud Files API cannot report on | start the provider, or make the files always available on this device; or agree to leave them out (`--leave-out-cloud`) | `cloud-down` (to be run) |
| Two names in one directory that differ only by case | rename one of them, then `fsutil file setCaseSensitiveInfo <directory> disable` | `casesensitive` |
| Beside the volume, on its disk: a volume with shadow copies | `vssadmin delete shadows /for=<drive>:` for that volume | `shared-snapshot`; the shadow copy is still there afterwards |
| On the volume's disk: the crash-dump file of the running Windows | move the dump file (System Properties, Advanced, Startup and Recovery) | `shared-dump` |
| Beside the volume, on its disk: a volume on which a program has a file open | close the program. Found when the run locks that volume, after waiting 20 seconds: the one refusal here that `--check` cannot give | `shared-busy` |

## Refused, and not made in the lab

These take the same paths as rows above, or are checked by tests only.

| Found | Why it is not a lab case |
|---|---|
| A ProjFS placeholder (and the virtualization root's marker), converted to plain or left out once agreed, as a cloud placeholder | The lab has no ProjFS provider yet: covered by unit tests (classification, admission, the before-freeze read through the provider, the leave-out kind `projfs_left_out` and the content verdict) |
| A Single Instance Storage link, made plain from its common store file once agreed (`sis_expanded`) | SIS ran on Windows Storage Server only, and the lab has none: covered by unit tests on synthetic records (the reparse point read exactly, the link's shape, the common store file held to the name, record and length the point gives, the room it takes and admission) |
| Data Deduplication | Refused by its reparse tag, like `compact /exe`; the lab has no deduplication. The words for each tag are covered by a test |
| A shadow-copy provider of backup software that holds a shadow copy on the machine | The lab has no backup product that makes one. The decision and its words are covered by a test |
| A named data stream on the root directory or on a reparse-point directory, or one on a directory that is encrypted, compressed or sparse | The lab's `dirstream` makes plain streams on ordinary directories, which convert. The refusals and their words are covered by a test |
| A dirty volume, an NTFS log that was not closed, an open transaction | The lab dismounts its volumes cleanly |
| A program holding a file on the volume open | Not arranged in the lab; the lock is retried for 20 seconds and then refused by name |
| A volume with no file on it | An empty volume is formatted, not converted |
| A data partition on the running Windows disk without `--restart-media` | The converter directs the user to the restart route. Ordinary conversion passed on Windows Server 2025 and Windows 11 Pro 26300.9457 (`w11restart-1124-095639`). The Server lab also exercised cancellation during preparation. |
| A data partition on the same disk as the BitLocker-protected running Windows | `--restart-media` refused before preparing the conversion. Windows stayed protected, the boot selection was unchanged, and the data partition was writable NTFS with an identical listing (`w11-bitlocker-1124-102655`). |
| A page file of the running Windows on the volume's disk | Takes a restart with the lab's disk attached; it is refused by the check that refuses the crash-dump file (`shared-dump`) |
| A volume beside the source that stores the shadow copies of another volume | Refused with the shadow copies of the volume itself; the words are covered by a test |

## Not shown at all

- A physical disk, and a volume holding more than 23 GB of data: every lab
  disk is virtual.
- A data volume of more than 500,000 files. One of 500,000 small files
  converts in 45 minutes; a run wants about 15 KiB of free memory a file as
  things are, and with less takes the rest from the page file and is slower
  (#129).
- Native conversion of NTFS file-record sizes besides 1 KiB and 4 KiB. The
  converter admits every size the boot sector can state (512 bytes to
  64 KiB); 2 KiB records, which NTFS formats on a disk of 2048-byte sectors,
  and the other sizes are covered by parser tests only. No lab fixture has
  them yet.
- An NTFS volume on a disk of 1024- or 2048-byte sectors. The NTFS readers
  take those sectors and their tests cover them, but the disk checks admit
  only 512- and 4096-byte sectors: the working shadow is a VHDX, which has
  no other sizes, and Hyper-V cannot present such a disk to the lab.
- An NTFS 3.0 volume. It is read as it is: FILE records in both header
  forms (the 3.0 form, update sequence array at 0x2A and no record number,
  and the 3.1 form Windows XP and later write to it) are read, and every
  gate admits 3.0 as it does 3.1. Parser and inspection tests cover both
  forms. Two lab cases, not yet run: `ntfs30` writes 3.0 into `$Volume` of a
  volume whose records keep the 3.1 form, and `ntfs30-headers` first
  rewrites every in-use MFT record (and its `$MFTMirr` copy) into the 3.0
  form; each has to convert with an identical listing and without the
  Windows mount. Neither is a volume Windows 2000 formatted (its first
  attributes stay where the 3.1 form put them, and its `$UpCase` and
  `$AttrDef` are Windows 11's).
- An NTFS 1.2 (Windows NT 4.0) volume. It is read as it is: no `$Extend`
  (so no object-ID, quota or reparse-point index, no USN journal, no
  transaction metadata), record 9 `$Quota` (recognized only empty) and
  records 11 to 15 reserved, every file's own `$SECURITY_DESCRIPTOR` in
  place of `$Secure`, and the 48-byte `$STANDARD_INFORMATION`. A file with
  NT 4.0's attribute 0x40 ($VOLUME_VERSION) or 0xC0 ($SYMBOLIC_LINK) is
  refused. Inspection tests read a synthetic NT 4.0-layout volume
  (`tests/support/ntfs12.rs`). Whether Windows 11 mounts such a volume at
  all, and so whether a conversion's native observations can be made of
  it, is not yet shown: the lab cases `ntfs12` (that synthetic volume
  written over the partition) and `ntfs12-version` (`$Volume` of a volume
  Windows formatted stating 1.2) find out, and no conversion of one has
  been run.
- An NTFS log in the LFS 2.0 format, or with restart or log pages other
  than 4 KiB. The restart-page reader takes both formats Windows writes
  (1.1 and 2.0) and pages of 4 to 64 KiB, under the same clean-dismount
  requirements; tests with synthetic restart pages cover them. Every lab
  volume converted so far was dismounted by Windows with the default
  downgrade to LFS 1.1 and 4 KiB pages. The lab case `lfs2` turns the
  downgrade off (`NtfsDisableLfsDowngrade`) and requires LFS 2.0 restart
  pages at a clean dismount before the run; it has not been run.
- Native conversion of NTFS index record sizes besides 2 KiB and 4 KiB.
  On Windows Server 2025 build 26100, the filesystem query for the tested
  8 KiB fixture returned Windows error 1392 before preflight could read its
  NTFS geometry. [Index fixture results](https://github.com/faratech/ntfs2refs/issues/184#issuecomment-7142377380)
- ReFS versions later than 3.14 and Windows builds besides 26100 and 26300.
  Both lab drivers reported 3.14 as their maximum supported ReFS version
  (`index184-2k` on Server 2025 and `pairedio-105413-native` on Windows 11).
- A conversion to standard ReFS (`--target-format standard`) on Windows 11.
  On Windows 11 Pro 26300.9457 the formatter refused both allocation units
  before the source was touched. `--list` reports that observation and
  `--check` reports the same refusal (`standard-win11-refused` and
  `standard-win11-64k-refused`). Windows Server formats standard ReFS.
- A Windows boot volume of Windows Server, and Windows 11 on build 26100:
  the lab's Windows 11 is build 26300 and its Windows Server is the control
  OS of data-volume attempts only.
- The restart route (`--restart-media`) on a physical machine and recovery
  after interrupted apply.
