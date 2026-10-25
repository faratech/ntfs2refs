# REFSNT writer evaluation

Reviewed on 2026-10-24 at commit
[`bdde6875b47a7370f5f98dd1d6b1a3e19278ca2a`](https://github.com/ages2001/REFSNT/tree/bdde6875b47a7370f5f98dd1d6b1a3e19278ca2a).
The repository has two commits at this revision and identifies its license as
GPL-3.0. The checkout and compiled research tools stay under ignored `.lab`;
none of its engine source is incorporated into this Rust project. This is an
initial implementation review and a reproduced reader experiment, not writer
qualification.

## The useful primitive exists in code

[`RfsFileAdopt`](https://github.com/ages2001/REFSNT/blob/bdde6875b47a7370f5f98dd1d6b1a3e19278ca2a/src/rfsops.c#L917)
accepts an empty ordinary file and one caller-allocated virtual cluster run.
It appends the extent, sets logical/valid/allocated lengths to the complete run,
and saves the file record. Its extent flags include written data. It refuses a
nonempty file or existing extents; checksummed extents are unsupported by its
write path. It does not itself establish physical allocation ownership or
verify that the adopted bytes are correct.

The companion
[`RfsAllocIn` and `RfsToVirtual`](https://github.com/ages2001/REFSNT/blob/bdde6875b47a7370f5f98dd1d6b1a3e19278ca2a/src/rfsalloc.c)
provide a candidate route from a selected physical interval to an owned virtual
run. A future controlled experiment could request exactly `[P,P+N)` with both
minimum and maximum length `N`, require the returned position/length to match,
translate it, and call adoption. All referenced containers, allocation rows,
placement constraints and metadata allocations still need independent checking.
This is a design inference from the functions, not an executed adoption result.
The public `rfstool do` command does not expose adoption directly.

Although the README describes no formatter, the source includes an experimental
`mkfs1` path and ReFS 1.2 formatter whose own comment says Windows compatibility
was not verified in that environment. That does not supply a qualified 3.14
formatter. The proposed 3.14 experiment should begin with Windows-generated
bootstrap metadata.

[`RfsCommit`](https://github.com/ages2001/REFSNT/blob/bdde6875b47a7370f5f98dd1d6b1a3e19278ca2a/src/rfscommit.c)
has substantive implementations for dirty-node placement, bottom-up page
encoding, updating object-table copies, allocator convergence, a flush before
writing the alternate checkpoint, and a flush afterward. Freed allocations are
quarantined until a completed commit. Failed commits make the in-memory volume
read-only. These paths justify experimental evaluation; their presence does not
prove correct crash recovery or acceptance by Microsoft's driver.

## Durability and checker limits found in the source

The userspace
[`rfstool` flush callback](https://github.com/ages2001/REFSNT/blob/bdde6875b47a7370f5f98dd1d6b1a3e19278ca2a/tools/rfstool.c#L26)
returns success without flushing storage. Its
[`rfsimg` backend](https://github.com/ages2001/REFSNT/blob/bdde6875b47a7370f5f98dd1d6b1a3e19278ca2a/tools/rfsimg.c)
uses ordinary writes without a corresponding durability operation. Thus this
tool cannot reproduce the engine's intended durability barriers. The separate
kernel adapter requests a device flush, but treats unsupported flush requests
as successful for old NT drivers. These observations do not disprove the
author's power-cut claims; they prevent promoting userspace stress-test success
to a durability guarantee for our converter.

The image backend zero-fills short reads and uses shared writable Windows opens
when a write operation is selected. A converter integration would need its own
strict length, overflow, exclusive identity and short-I/O contracts rather than
inheriting that backend. The existing Rust native adapter supplies those
contracts for its current experiment, not for REFSNT.

`rfstool check` prints allocated-but-unreferenced clusters separately from its
error counters. `main` does not turn checker counters into a failing process
exit. Its random stress script checks selected counters and changes from an
initial allocation baseline. Therefore an exit code of zero is insufficient
evidence of a complete ownership proof.

## Reproduced read-only experiment

Built the kernel-independent engine and `rfstool` with MSVC 14.51 in
`.lab/research/refsnt-build-bdde6875`. The first build exposed Windows SDK
`WriteRaw` and CRT `snprintf` name collisions. A forced compatibility header
includes the Windows/stdio headers first and renames the private `WriteRaw`
helper during preprocessing. The pinned source checkout remains unchanged.
The resulting executable SHA-256 is
`75d2db1acd5cce45ec5a6b97b562b42b437cfc4ee8ae04aa3dc706a0d67a545e`.
This is an adapted userspace build, not an installed filesystem driver.

The input was our captured Windows-created ReFS data partition:
`.lab/hyperv/corpus/devdrive-20261023T231918797Z/devdrive.raw`,
55,834,574,848 bytes. Its earlier verified full-image SHA-256 is
`805eecc9f17436bac644b2b774e96896ace8af2aec8c66dcaf6c3bbb8e4be0c9`;
this experiment did not repeat the complete image hash. Each invocation used a
read-only tool command while an independent ordinary-file handle denied writers.
The pinned native manifest SHA-256 was checked before comparing extracted data:
`ca9e3e60bbe84bd758609d92b92a305a948213b4ab0f5ce199f38567a8ea84c1`.

| Observation | Result |
| --- | --- |
| Geometry | ReFS 3.14; 4,096-byte clusters; 16,384-byte metadata pages; 48-byte references |
| Metadata checksums | Type 2, self-check type 1; zero reported checksum errors |
| Tree ordering | 75 pages, 2,704 rows; zero reported ordering/other errors |
| Allocation check | 69 pages, 1,300 referenced clusters; zero reported duplicate/unallocated references |
| Allocation caveat | 245,708 allocated-but-unreferenced clusters, despite exit 0 and zero error counters |
| Namespace | `/fixtures`, containing the two expected files |

The allocation remainder requires classification against native reservations and
all metadata ownership; it is not evidence that the Windows-created volume is
corrupt. It shows why this checker alone is not a complete allocation oracle.
There is also a useful accounting cross-check: the pinned native post-remount
query reports 13,232,896 free clusters and 151,584 reserved clusters. REFSNT's
Medium allocator reports 13,384,480 free clusters, exactly their sum. This is an
observed relationship on this one capture, not a universal allocator formula,
and does not classify the 245,708-cluster ownership remainder.

Both extracted logical files matched the native manifest by length and SHA-256:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `nonresident.bin` | 4,194,304 | `ecbf557fb4d10cb9a59eb55645e2e154ff42e6f37cb7ca5a60eed2da1de0539d` |
| `small.txt` | 61 | `060769a53319045a7aedad5277e4d5118695f2e62aa626100682a686ea143ca2` |

Logs, build commands, compatibility header and extracted ordinary files remain
under the ignored research build directory. No REFSNT write operation, target
device access, driver installation or Windows mount of REFSNT-modified metadata
occurred.

## Independent forefst cross-check

Also cloned forefst at
[`d4d5fd28942eb14ebe11d90f4eb9342f5e3d7b92`](https://github.com/xbqt/forefst/tree/d4d5fd28942eb14ebe11d90f4eb9342f5e3d7b92)
and ran its unchanged `forefst.py` with Python 3.15.0, isolated import settings
and bytecode writes disabled. The script SHA-256 is
`d0e162dcdf8755aa4543db76ed17a6321faf4cc06f24c5818b31564bd3c3860e`.
An independent read handle denied source-image writers throughout each command.
The raw partition requires an explicit `--partition-start 0`.

The summary agrees on 3.14, 4 KiB clusters, CRC64, serial 9808427608425382,
checkpoint clock 45, flags 0x6c2 and the two-file/one-directory namespace. It
reports 832 container mappings and 14 objects. REFSNT reports 834 indexed container
slots; its source sizes that array by maximum container ID plus one, so these
are different measurements. The forefst summary SHA-256 is
`632b988fa342bcb4cf804e49b48704a731441aa12c004c5441b33ca58896c710`.

On this Windows host, strict nonresident extraction with `--refuse-holes`
refuses because the tool cannot determine host-image sparse-hole coverage.
The failed observation and stderr are preserved. Default extraction reports
that limitation and writes the bytes as read; both logical outputs match the
native length/SHA-256 pairs above and the REFSNT extraction. This establishes
those logical bytes only, not strict capture-completeness qualification from
forefst. The input file has no Windows sparse-file attribute. A fresh complete
image SHA-256 check finished at 2026-10-24T06:07:49Z and matched the original
captured `805eecc9f17436bac644b2b774e96896ace8af2aec8c66dcaf6c3bbb8e4be0c9`.

Artifacts are under
`.lab/research/forefst-observation-20261024T060142263Z`. No source-image writes,
boot repair, image decompression or device operations were requested. These
reader results supply a baseline for a later independent-writer experiment;
they do not validate REFSNT-generated metadata.

## Isolated writer adoption experiment

A separate ignored copy of REFSNT's userspace tool now uses a copy-on-write
block backend. It opens the Windows-generated `devdrive.raw` with read-only
access; every experimental write goes to a separate append-only overlay on C:.
The pinned upstream checkout remains unchanged. The overlay reader replays
records in order, checks each record, and the adapted `RfsHostFlush` calls
`FlushFileBuffers` on the overlay instead of returning unconditional success.
This is laboratory GPL code, separate from the Rust converter.

The experimental `adopt` operation reserved physical LCN 10,243 in the ReFS
Medium allocator, created `/adopted.bin`, converted the physical LCN to a
virtual cluster and called `RfsFileAdopt`. The pre-existing 4,096 bytes at that
base-image LCN had SHA-256
`6234f364d8fb1b532234405c7e2bb1c8e08337ef7fc6e4138f80c8b3d9411786`.
Both REFSNT and the independent forefst parser extracted exactly 4,096 bytes
with that SHA-256 from the adopted file. Forefst described it as extent-backed,
with 4,096 allocated bytes. The overlay contained eight write records totaling
131,072 bytes of new metadata; **none overlapped the adopted payload cluster**.
The overlay was only 131,280 bytes, and the original 55,834,574,848-byte raw
image retained its last-write timestamp. Opening the base without the overlay
does not show `adopted.bin`.

The repository now contains an independent Rust read-only overlay decoder and
`lab-refs-cow` auditor. It replays the external writer's append-only block log,
rejects damaged records, checks original and merged payload hashes, proves no
write overlaps the adopted range, and parses the merged ReFS VBR and backup.
Its result under `.lab/research/refsnt-overlay/rust-audit.json` agrees on eight
records, 131,072 written metadata bytes, an untouched adopted cluster, ReFS
3.14 and a matching backup VBR. The Rust decoder never opens the base for
writing.

The Rust reader now also follows the higher-clock checkpoint's virtual Medium
Allocator root through the Container Table, verifies root/child CRC64 and
self-addresses, and decodes all 23 leaf rows. On the base image it counted
13,384,480 Medium-free clusters and found physical LCN 10,243 free. On the
adoption overlay it counted 13,384,479 free and found that LCN allocated. The
row count and free totals match REFSNT's independent checker. The reports are
`.lab/research/refsnt-overlay/medium-base-rust.json` and
`medium-adopt-rust.json`; an explicit ignored native-corpus test replays both
read-only. The Rust reader also checks the physical Small allocator root: its
two rows report 16,304 free and 92 allocated clusters both before and after
adoption. LCN 10,243 is outside its allocated ranges. This is an
allocator-tier observation, **not** a full ownership proof: reachable
metadata/data references, refcounts and other reservations still require
reconciliation before native Windows mounting.

REFSNT's checker reported zero checksum, duplicate-reference or unallocated
reference errors on both images. Its referenced-cluster count increased from
1,300 to 1,301 and Medium free count decreased by one; its
245,708 allocated-but-unreferenced remainder was unchanged. Forefst parsed
the new checkpoint at virtual clock 46 with valid VBR, SUPB and checkpoint
checksums. Forefst still could not determine host sparse-hole coverage when
extracting the file; its extracted bytes matched the raw base cluster and the
REFSNT extraction.

This proves an **offline candidate-writer mechanism on one 3.14 image**: an
existing physical block can be exposed as file data by newly written ReFS
metadata without rewriting its bytes. The block was not traced to an NTFS
file; same-partition NTFS payload adoption remains the next experiment. This
also does not yet prove that Microsoft's
`refs.sys` accepts or safely mutates that metadata. The candidate scanner also
found an `MSB+` signature at an early Medium-free cluster. That page may be
stale copy-on-write metadata; its signature alone does not establish live
ownership, and the Medium bitmap alone does not account for other allocation
tiers. The selected data cluster therefore still needs an independent
whole-volume ownership check before any native mount test. The next gate is to expose the
overlay as a disposable virtual disk to Windows, verify native read/mutation
and storage-validity behavior, then qualify flush ordering and power cuts.
