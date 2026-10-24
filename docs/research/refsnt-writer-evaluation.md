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
`mkfs1` path and ReFS1.2 formatter whose own comment says Windows compatibility
was not verified in that environment. That does not supply a qualified3.14
formatter. The proposed3.14 experiment should begin with Windows-generated
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

Both extracted logical files matched the native manifest by length and SHA-256:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `nonresident.bin` | 4,194,304 | `ecbf557fb4d10cb9a59eb55645e2e154ff42e6f37cb7ca5a60eed2da1de0539d` |
| `small.txt` | 61 | `060769a53319045a7aedad5277e4d5118695f2e62aa626100682a686ea143ca2` |

Logs, build commands, compatibility header and extracted ordinary files remain
under the ignored research build directory. No REFSNT write operation, target
device access, driver installation or Windows mount of REFSNT-modified metadata
occurred.

## Next decisive experiment

Use a disposable Windows-formatted 3.14 image with a strict block backend and a
complete write trace. Adopt one pre-existing, independently hashed payload run
without a normal ReFS payload write. Require every metadata write to avoid that
run; export the changed blocks and independently decode the resulting extent,
allocator and checkpoint graph. Only then test the modified image through
`refs.sys`, including logical SHA-256, native physical mapping and both cached
and storage valid-data state. A native mutation/remount experiment and real
flush/fault injection follow. The current native-shadow journal experiment
continues independently and does not confer writer authority on REFSNT.
