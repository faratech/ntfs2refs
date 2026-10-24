# Next step: a bounded converter for an existing data-file tree

The next milestone should accept an **existing**, small NTFS file tree, build
its native ReFS shadow, and reconstruct the same partition. The first admission
profile retains all admitted file extents. Tests must stop prearranging source
files into convenient locations outside the conversion protocol. This does not
prohibit a future converter from performing bounded, journaled relocation to
preserve data through alignment or metadata collisions. Boot conversion remains
deferred. This is a proposed increment, not an expansion of any current writer
permission.

## Starting evidence and limits

The preparation case `win11-20261024T034206826Z` established matching native
metadata, initialized contents and one positive sixteen-cluster extent for each
64 KiB A/B fixture at LCN2097152. Both files were deliberately placed there
before freeze; this does not establish that an arbitrary existing NTFS extent
is usable in a native ReFS shadow. The subsequent first raw probe established
the A/B physical-byte correspondence, but its launcher failed before the second
restart/whole-partition phase. Later conversion outcomes must be recorded
separately; they are not assumed by this plan.
[Preparation evidence](native-retained-fixture.md#fresh-native-preparation-passed),
[runtime status](../IMPLEMENTATION_STATUS.md)

The same pinned `pair.json` records the original placement:

| File | Before fixture move | After fixture move |
| --- | --- | --- |
| NTFS source A | LCN6263; partition-relative offset 25,653,248 bytes | LCN2097152 |
| ReFS shadow B | LCN1507328; partition-relative offset 6,174,015,488 bytes | LCN2097152 |

The source offset is 4 KiB aligned but has a 28,672-byte remainder modulo 64 KiB.
Thus even this ordinary native allocation did not start on the fixture's
64 KiB boundary. `NativeRetainedFixture.CheckCandidate` deliberately requires
LCN divisible by 16; that is a construction gate, not a measured universal ReFS
placement requirement. The current Rust `ProbeRequest` separately requires
4 KiB alignment and an 8–9 GiB fixture window. Neither gate proves that the
original LCN6263 is unusable. Test native shadow placement at an otherwise
eligible cluster-aligned source location before treating alignment alone as a
reason to relocate. The source evidence SHA-256 is
`145398b640302197acbcf71e8b21dfaa629507ac916179971ea3e579b92c849d`.
[Pinned pair evidence](../.lab/hyperv/retained-preparation/win11-20261024T034206826Z/pair/pair.json),
[construction gate](../lab/guest/NativeRetainedFixture.cs),
[raw probe gate](../src/lab_native.rs)

### Measured bitmap conflict at the original location

Read-only analysis of the same saved preparation's ordinary query files found
that the original sixteen-cluster interval is free in the ReFS legacy view but
allocated in its metadata-inclusive view. Each file's SHA-256 was independently
checked against the pinned `pair.json` before inspecting the bits:

| Query/artifact | LCN6263..6278 | SHA-256 |
| --- | --- | --- |
| `AFreshBitmap` / `query-068.bin` | All 16 allocated in NTFS | `799d088490eef30b6c84f5a2ecea543944a704ba47783cb6b72d887e0072a7eb` |
| `BFreshBitmap` / `query-070.bin` | All 16 free in ReFS legacy | `4eaa9312c508e4f456c03f9cc1e5daedd4d6e72f8797c0d9d7196485ea038ba9` |
| `BFreshMetadataBitmap` / `query-071.bin` | All 16 allocated in ReFS EX flag 1 | `0fa647bc116f9f5b59c2200ab6e45eeb0e0f6e318fbf855e5c27ccab4067bc6b` |

All three returned headers start at LCN0. For LCN `c`, the byte offset is
`16 + floor(c / 8)` and the mask is `1 << (c % 8)`. Thus the interval uses
byte 798 bit 7, all of byte 799, and byte 800 bits 0..6. The observed bytes 798..800
are respectively `ff ff 7f`, `00 00 00`, and `ff ff ff`; applying masks
`80 ff 7f` produces the table above. NTFS declares 13,631,487 clusters; ReFS
declares 13,631,488. Meaningful buffer length is 1,703,952 bytes in each case.
The ReFS replies contain 2,097,152 bytes; padding contributes no coverage.
The NTFS query precedes its source move, and the ReFS queries precede the
shadow's move. These are historical observations, not a current allocation lock.

This is already a collision under our intersection-free admission rule.
Microsoft documents EX flag 1 as including metadata, making metadata/reservation
overlap a stronger explanation here than alignment alone. The bitmap does not
identify the owner or prove an immovable anchor. Do not force a move into this
interval or discard the EX view to obtain a favorable outcome.
[Extended bitmap contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-starting_lcn_input_buffer_ex)

The generic Rust comparator already accepts multiple retained ranges, and the
journal core implements bounded reconstruction and pre-handoff recovery. The
native adapter deliberately accepts exactly one 64 KiB range. Its limit should
change only after a new inventory/attestation layer proves every proposed range.
[Comparator](../src/retained_compare.rs),
[journal](../src/lab_reconstruct.rs),
[native request gate](../src/lab_native_reconstruct.rs)

The failed VDL experiment is not a shortcut: its cached validity covered EOF,
storage validity covered none, and its first cluster had an unresolved negative
ReFS mapping. Keep initialized shadow files with measured integrity NONE and
full cached/storage validity. Metadata transplantation remains an experimentally
qualified construction, not a documented ReFS import interface.
[VDL result](native-vdl-observation.md),
[native-shadow rationale](next-extent-preservation-milestone.md)

## One deliberately small admission profile

Propose at most **128 ordinary files, 32 directories, 256 MiB of logical data,
and 128 retained extents**, with depth at most 16. Each file has one unnamed,
fully initialized, nonresident, contiguous stream; EOF and allocation are equal
and multiples of 64 KiB. Contents and names are user data, not fixed patterns.
Allow empty directories. Preserve supported attributes, all four timestamps,
owner/group and DACL; require verified SACL absence. Keep the measured
52 GiB/4 KiB-cluster, basic GPT, 512/4096-sector Windows/ReFS profile initially.
These are proposed testable ceilings, not measured scale qualifications.

This targets small volumes of archive/image-style files, not a typical home
directory. Refuse resident/empty files, partial final clusters, fragmentation,
hard links, DOS aliases, ADS, reparse points, sparse/compressed/encrypted files,
case-sensitive directories, EAs/object IDs and other unhandled user attributes.
Reject names or security semantics that cannot round-trip exactly. A later
increment can admit small/resident payloads with an explicitly counted copy
budget; it is not necessary to prove extent retention for this profile.

Keep boot/system/pagefile volumes, BitLocker, dynamic disks, Storage Spaces,
other sector/cluster geometries and unqualified OS/ReFS builds outside this MVP.
No policy override or target format is part of admission. NTFS file IDs and
filesystem serial cannot be preserved as ReFS IDs; record their replacement
mapping explicitly while retaining the original GPT disk/partition identity.

## First implementation: complete source admission, without target writes

Implement a Rust admission certificate over a frozen source and pinned native
observations. Reuse `ntfs_inspect`, but do not reinterpret its current
`inventory_complete=false` or ancestry candidates as ownership proof. Today it
explicitly leaves directory indexes, security descriptors, allocation ownership,
log state and backup metadata unresolved; attribute-list assembly is also
unsupported. The certificate needs the following minimum evidence:

| Required fact | Required reconciliation |
| --- | --- |
| Complete object set | Scan allocated MFT records using `$MFT::$BITMAP`; resolve record/sequence references and reconcile every admitted name against directory indexes and the bounded native enumeration. Account for objects invisible to ordinary traversal and reject unexplained orphans. |
| Exact semantics | Bind each name to an actual file handle/ID, stream, EOF/allocation/initialized length, attributes, timestamps and security descriptor. Resolve `$Secure` references and compare owner/group/DACL and verified SACL absence. Directory-entry metadata alone is insufficient. |
| Complete allocation ownership | Build a checked interval ledger for every physical run of every allocated attribute, including NTFS system metadata, indexes and stream continuations. Cross-check `$Bitmap`: no allocated-but-unaccounted clusters, unallocated claimed clusters or unexplained overlaps. Model recognized reservations explicitly. |
| Preserved payload | For each admitted stream, bind VCN-to-source-LCN order, full logical hash and raw extent hash after offline quiescence. Match native retrieval/base translation to the independent raw reader. Pin the complete source partition hash. |
| Stable source | Bind disk/partition/geometry, clean native dismount, offline/exclusive state and matching reopened identity. Validate NTFS backup boot/MFT mirror and required log/restart state. Dirty or unresolved state refuses admission. |

System metadata may be replaced only after its role and semantics are accounted
for; an `is_metadata` flag or a dollar-prefixed name is insufficient. An
attribute list in any record needed to establish completeness is a refusal
until its continuations are assembled; rejecting only lists on user files would
leave an ownership hole. Keep all unsupported objects in the rejection report.
[Current reader](../src/ntfs_inspect.rs),
[metadata-role limits](ntfs-metadata-roles.md)

The reader does validate cluster alignment, stream VCN coverage, partition
bounds and intra-stream physical overlap; it imposes no 64 KiB physical-alignment
rule. That is useful evidence for admitting an arbitrary source address, but it
does not supply the missing cross-record allocation ownership proof. Moreover,
`SelectCandidate` requires free space in NTFS and ReFS because it constructs a
fixture. Existing source extents should be owned by the admitted NTFS file,
not free; that function cannot serve as the converter's admission rule.

Deliver this certificate and actionable refusal reasons before generalizing the
native writer. Tests should include an omitted file, stale parent reference,
index/MFT disagreement, conflicting run ownership, a set bitmap bit with no
owner, unsupported attributes and altered security/content. Bounds must fail
completely, without a partially accepted tree.

## Native shadow construction and collisions

Format only independent scratch storage using the current guest-local Virtual
Disk/native filesystem APIs. Recreate the admitted namespace and metadata,
initialize distinct placeholder bytes, then move **shadow** file VCNs to the
already frozen source LCNs. The strict-retention profile refuses a source
relocation rather than performing one outside its plan. Take fresh legacy and
metadata-inclusive ReFS bitmaps before each bounded request, verify native
results and all final mappings, then freeze the shadow.
Bitmap staleness can cause a native refusal; it is not permission to overwrite
another allocation. [Native move contract](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_move_file)

A source payload interval occupied by ReFS metadata is a **collision refusal**.
An interval occupied by another placeholder is also refused in this first
implementation; scheduling shadow relocations can be a separate improvement.
Do not mask a collision by putting the source bytes into the mosaic anyway:
that could replace required ReFS metadata. Successful native placement, exact
positive mappings, validity and physical correspondence must establish that
each retained range is shadow file data. The bitmap alone does not do so.

This avoids requiring a complete ReFS metadata decoder, at the cost of rejecting
some otherwise convertible volumes. Fixed bootstrap/metadata locations cannot
be moved by the current implementation. A useful broader converter may require
bounded relocation; it is a legitimate conversion operation, not automatically
a failure of same-partition conversion. Such a path must durably preserve the
original data and recoverable filesystem state, reserve and verify destinations,
record old-to-new ownership and metadata changes, and include every affected
byte in its recovery budget before mutations. A successful native move alone
does not supply that recovery protocol. Any source mutation requires fresh
source pins and explicit retained-versus-relocated byte accounting; it cannot
inherit a claim that every original extent stayed fixed. Direct ReFS metadata
placement would require substantially more format knowledge than the current
bootstrap/virtual-root reader provides.

Require full shadow storage validity and integrity `CHECKSUM_TYPE_NONE` for
every retained stream, rather than merely disabling enforcement. ReFS data
checksums would otherwise depend on the placeholder contents.
[Microsoft integrity semantics](https://learn.microsoft.com/en-us/windows-server/storage/refs/integrity-streams)

## Scratch and reconstruction accounting

Initialized placeholders require payload-proportional shadow allocation and
I/O; `FSCTL_MOVE_FILE` supplies no arbitrary-NTFS-extent import option. ReFS block
cloning is not a way to import raw NTFS allocations either.
[Block cloning contract](https://learn.microsoft.com/en-us/windows/win32/fileio/block-cloning)

Budget independent storage for actual shadow backing growth, native filesystem
metadata, twice the changed-sector bytes, the journal's exact metadata overhead,
evidence and reserve. The existing lab uses an 8 GiB journal disk, a 6 GiB shadow
allocation ceiling and a 768 MiB journal ceiling. Those limits are not proof that
the proposed file tree fits: measure backing allocation after each stage and
stop before consuming reserved journal space. A dynamic 64 GiB virtual capacity
is neither a physical-space reservation nor a scratch bound.
[Shadow limits](guest-shadow-platform.md), [journal format](lab-reconstruction-journal.md)

Keep the 256 MiB changed-byte and 65,536 patch-run ceilings initially. Reconstruct
from complete source/shadow comparison; read free and zero-valued sectors too.
Coalesce retained intervals only when their separate file/VCN ownership remains
auditable. The journal write permit must exclude their entire union. Preserve
the current whole-source normalization, complete expected mosaic hash,
preimage/postimage checks, flush/readback and permanent handoff barrier. Do not
derive patch coverage from either allocation bitmap or silently increase caps.

Source preservation and efficiency are separate claims: this design can retain
all admitted original extents while making a full placeholder copy on scratch.
It does not meet an eventual small-scratch, payload-independent conversion goal.

## First location diagnostic after the current fixture outcome

Use a separate disposable branch, preserving the current experiment. Keep the
original source offline: no source write handle, move, format, online transition
or attribute change. New helper/test code and native execution are deferred
until the current fixture outcome. The proposed stages are:

1. **Read-only shadow recheck.** Require separately established mounted read-only
   shadow access and bind its VHD query 14 ID, GPT, geometry, ReFS identity and
   retrieval base. Capture legacy 8-byte and EX 16-byte flag 1 bitmap requests
   twice, each with the measured 2 MiB output ceiling. Preserve exact errors, inputs, headers
   and buffers; no retries or pagination. Evaluate only the declared coverage
   of 6263..6278 and record source identity/offline state before and after.
2. **Stop on occupancy or ambiguity.** Any allocated, incomplete, unsupported
   or changing view stops before creating a file or issuing a move. Repeated
   legacy-free/EX-used bits confirm the conflict for this shadow epoch, without
   identifying its owner. No raw read of unattributed metadata is needed.
3. **Only if both views become free:** a separately reviewed writable-shadow
   stage may create one owned 64 KiB fully initialized patterned file, verify
   full cached/storage validity and integrity NONE, then requery both bitmaps
   after creation. Exclude its current extents and known reserved anchors.
   Permit one move at VCN0/LCN6263/count16, using cluster/partition bounds in a
   new diagnostic rather than weakening frozen fixture/conversion gates.
   Record exact native status, before/after mapping/hash/validity and cleanup;
   preserve unknown outcomes, with no retry or `SetFileValidData`. Qualification
   needs the requested positive extent and unchanged contents after clean
   remount; a subsequent raw sample is restricted to that owned shadow payload.

If occupancy persists, alignment can be studied separately at a fresh
intersection-free shadow location with LCN modulo 16 equal to 7, plus a disjoint
aligned control: at most two new 64 KiB files and one move each. Success would
refute a universal 64 KiB requirement for that profile; failure alone does not
isolate alignment from other native constraints. Microsoft specifies ordinary
move granularity in clusters; its 16 KiB relative-alignment advice concerns
shadow-copy overhead, not a universal 64 KiB destination rule.
[Move granularity](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_move_file),
[alignment guidance](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-move_file_data)

A stable conflict favors a bounded, journaled relocation admission path or an
explicit refusal. This diagnostic neither moves the source back to its old
location nor claims that shadow-placement success converts the historical file.

## Finite acceptance and decision point

After the current one-file conversion completes, run the bounded tree profile
on independently created NTFS sources whose files were **not** positioned for
ReFS by test setup. Generalize only the native range/semantic certificate and
verification;
keep the journal protocol unchanged. Before any target write require complete
admission, successful shadow placement, raw source/shadow proofs and capacity.

Success means the original partition mounts as ReFS, every admitted file has
its original hash and supported metadata, every payload extent stays at its
original bytes, and the write ledger excludes those bytes. Verify the complete
namespace through native read-only handles, clean remount, and then separately
test a new file allocation/write without damaging retained files. Exercise
interruption/resume/rollback before handoff on this larger profile. The lab
checkpoint supplies containment; it is not post-handoff recovery for a real
converter. [Native verification contract](native-retained-postconversion-verification.md)

Include one intentional metadata collision and one unsupported source feature;
both must stop before target writes. If independently grown sources repeatedly
fail placement, report the collision locations/bytes and stop treating this
strict-retention shadow path as a useful general converter. Choose explicitly
between bounded, journaled relocation and deeper ReFS metadata construction.
The former can become part of the converter, with interrupted relocation and
recovery tested as part of conversion; it must not be hidden as fixture setup.
Do not continue manufacturing favorable source layouts. If scratch or changed
bytes exceed the fixed budget, report that failure separately from feasibility.

## Lessons from the pinned ntfs2btrfs implementation

The reviewed reference is commit
`433523abaff4015db0f473e4f256f9d5671c9cd5`, locally pinned under
`.lab/research/ntfs2btrfs`. Its `create_data_chunks`/allocation handling starts
from used source space, `create_inodes` walks the allocated MFT bitmap to
reconstruct objects, and `protect_superblocks` explicitly handles collisions
with fixed target structures and reserved regions. These are concrete lessons:
inventory first, own every retained range, and account for unavoidable
collisions. [Pinned source](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/ntfs2btrfs.cpp)

That converter constructs Btrfs metadata directly; our native shadow does not
inherit its extent-placement freedom, target-format knowledge or recovery
semantics. Borrow the architectural checks, not an assumption that ReFS has an
equivalent import API. No GPL implementation code was copied for this plan.
