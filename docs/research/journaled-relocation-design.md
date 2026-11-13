# Bounded journaled relocation through a native ReFS shadow

Research date: 2026-10-24. This is a proposed separate admission profile. No Rust,
guest helper, frozen request, existing evidence, or VM state was changed for this
note. The relocation profile has not been implemented or natively executed.

**Conclusion:** a native ReFS shadow can hold the actual source payload at a
different admitted extent. The existing journal's old/new byte records can carry
that payload to the original partition as ordinary changed granules. A new
target-to-target move executor is unnecessary. Current admission deliberately
rejects this case; those guards must change explicitly, together with the native
evidence and post-conversion verifier. This conclusion is an inference from the
reviewed executor and API contracts, not a documented Microsoft filesystem
transplant interface or a claim of general conversion safety.

Let `T` be the frozen NTFS partition, `S` the separately constructed and frozen
native ReFS shadow, `P` the source file's original physical interval, `Q` its
different native shadow interval, and `K` the compatible intervals actually
retained without writes. The proposed result is:

```text
S[Q] = T[P] = the real initialized payload A
R[K] = T[K]
R[outside K] = S[outside K]
```

When the shadow needs `P` for something else, `P` is excluded from `K` and compared
normally. For a one-file relocation experiment there may be no compatible
retained extent: `K` is empty and the expected final partition is exactly `S`.
An arbitrary unused interval must not be labelled retained merely to satisfy an
existing nonempty-list validator. A native ReFS allocator can select `Q`; the
converter then admits the measured mapping. Choosing a bitmap-clear address is
not itself a reservation or mapping proof.

The concrete source collision is independently reproducible from saved ordinary
artifacts. The preparation's source file originally occupied LCN6263..6278,
partition-relative offset 25,653,248, before both fixtures were moved to
LCN2097152. On 2026-10-24 this review rehashed the saved `pair.json` and each
listed buffer, checked each buffer against its recorded artifact hash, and
inspected exactly those sixteen bitmap bits. The pair SHA-256 is
`145398b640302197acbcf71e8b21dfaa629507ac916179971ea3e579b92c849d`.
[Pinned pair](../../.lab/hyperv/retained-preparation/win11-20261024T034206826Z/pair/pair.json),
[full collision analysis](../history/bounded-converter-next-step.md#measured-bitmap-conflict-at-the-original-location).

| Saved query | Allocated bits among LCN6263..6278 | SHA-256 |
| --- | --- | --- |
| `AFreshBitmap`, `query-068.bin` | 16 | `799d088490eef30b6c84f5a2ecea543944a704ba47783cb6b72d887e0072a7eb` |
| `BFreshBitmap`, `query-070.bin` | 0 | `4eaa9312c508e4f456c03f9cc1e5daedd4d6e72f8797c0d9d7196485ea038ba9` |
| `BFreshMetadataBitmap`, `query-071.bin` | 16 | `0fa647bc116f9f5b59c2200ab6e45eeb0e0f6e318fbf855e5c27ccab4067bc6b` |

Microsoft defines EX flag 1 as including metadata. The discrepancy therefore
blocks the current intersection-free placement rule, but does not identify an
owner or prove an immovable anchor. These are historical bitmap observations,
not present allocation authority. Microsoft also warns that a bitmap can become
stale during write activity.
[Extended bitmap flag](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-starting_lcn_input_buffer_ex),
[bitmap race warning](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_move_file).

The API contracts support the distinction between retention and relocation.
`FSCTL_MOVE_FILE` moves file clusters within one volume; it supplies no NTFS-to-ReFS
import operation. ReFS block cloning requires both files on the same ReFS volume.
Neither is a way to import arbitrary NTFS physical allocations into a shadow.
For this experiment, ordinary initialization of the shadow with the source's
real bytes is sufficient; no NTFS move is necessary.
[Move contract](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_move_file),
[block-clone restrictions](https://learn.microsoft.com/en-us/windows/win32/fileio/block-cloning#restrictions-and-remarks).

Native mapping and validity remain separate requirements. Retrieval pointers
describe nonresident VCN-to-LCN mapping; they do not alone establish initialized
storage contents. The region-query contract distinguishes cached validity from
storage validity. Our failed VDL experiment demonstrated why that distinction
matters: full cached coverage did not establish full storage coverage and a
negative first-cluster mapping remained unresolved. Require complete positive
mapping, raw/logical hash agreement, and both validity views over all 64 KiB.
[Retrieval pointers](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_retrieval_pointers),
[region usage definitions](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-file_region_info),
[measured VDL outcome](../history/native-vdl-observation.md).

Keep measured `CHECKSUM_TYPE_NONE` with flags zero in the first profile. Microsoft
distinguishes that algorithm from disabling checksum enforcement, and ReFS still
checksums metadata. Building the real payload on the shadow avoids deliberately
replacing a placeholder underneath its native metadata, but does not qualify
additional integrity policies or unknown content-dependent structures.
[Integrity result fields](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-fsctl_get_integrity_information_buffer),
[metadata and data integrity](https://learn.microsoft.com/en-us/windows-server/storage/refs/integrity-streams).

The pinned ntfs2btrfs checkout is commit
`433523abaff4015db0f473e4f256f9d5671c9cd5`; `git rev-parse HEAD` was checked during
this review. Its source demonstrates useful collision-handling concepts:

| Pinned implementation | Relevant lesson |
| --- | --- |
| `convert` derives runs from the NTFS bitmap; `protect_cluster` copies an affected cluster to a new allocation and records relocation; `protect_superblocks` covers fixed anchors and the first megabyte. | In-place conversion can retain compatible extents and relocate collisions. Source prearrangement is not a prerequisite to the concept. |
| `create_image` maps original positions to retained or relocated Btrfs extents. | Its original-image representation depends on destination filesystem mappings. |
| Trees precede superblocks, followed by clearing the NTFS prefix. | Discovery ordering merits a separate phase; source order is not power-loss proof. |

[Allocation and conversion](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/ntfs2btrfs.cpp#L3691-L3877),
[collision relocation](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/ntfs2btrfs.cpp#L3518-L3603),
[image construction](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/ntfs2btrfs.cpp#L1274-L1383).

Its rollback resolves image extents through Btrfs chunks, collects nonidentity
mappings and writes their bytes back to original positions. It refuses certain
unsupported layouts. That is a filesystem-specific rollback representation,
not our independently durable external old/new journal. This comparison imports
engineering ideas only: no GPL source has been copied, no ReFS reflink import
capability is inferred, and no ntfs2btrfs crash guarantee is assumed.
[Pinned rollback](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/rollback.cpp#L385-L494),
[source licence notice](https://github.com/maharmstone/ntfs2btrfs/blob/433523abaff4015db0f473e4f256f9d5671c9cd5/src/ntfs2btrfs.cpp#L1-L16).

The existing Rust implementation has the following relevant behavior. These are
code-review findings and ordinary-file test capabilities, not execution of the
proposed native relocation profile.

| Existing component | What relocation can reuse | What it does not admit today |
| --- | --- | --- |
| [Comparator](../../src/retained_compare.rs) | Full image and retained pins, complete sector comparison outside `K`, coalesced patches with before/after hashes, expected composite image hash, second complete stability pass. | Empty `K`; request validation requires 1..1024 retained ranges. It proves byte relationships, not file ownership or semantic completeness. |
| [Journal core](../../src/lab_reconstruct.rs) | Persistent old/new payloads for every changed 4 KiB granule, bounded complete journal, trusted ticket, recovery validation, discovery-last apply/rollback and full-result hashes. | It inherits the comparator's admission rule; a relocation-only request needs explicit new profile handling. |
| [Native bridge](../../src/lab_native_reconstruct.rs) and [probe](../../src/lab_native.rs) | Actual partition/journal identity binding, existing offline reopen, exact patch-policy arming, source/shadow pins. | Exactly one retained 64 KiB interval, one shared offset in the 8–9 GiB window, unequal source A/shadow B hashes. |
| [Native write policy](../../crates/n2r-win32/src/native.rs) and [range validator](../../crates/n2r-win32/src/layout.rs) | Sorted aligned allowed spans, retained exclusion, partition bounds, cumulative write cap, single native write with no short-write retry. | Empty retained list, because the same nonempty range validator is applied to it. Allowed-write bounds must remain strict when this particular list becomes optional. |

The required new admission chain is concrete:

1. Enroll the existing source object at `P`, preserving supported name, size,
   timestamps, attributes, security and original mapping. Take the immutable
   source basis after coherent native exclusion; lock/dismount can flush normal
   filesystem activity. No source format or placement mutation belongs to this
   preparation. Obtain `A` from the pinned excluded source, not from a generated
   substitute pattern or a mutable file reread after reconstruction begins.
2. Construct the native shadow file with those real bytes. Admit one positive,
   contiguous 64 KiB mapping at `Q != P`, full measured validity, integrity NONE,
   supported matching metadata/security and a bounded namespace. Keep source,
   shadow and journal storage independent. Native allocation chooses the
   destination; a differing or fragmented result fails this first profile.
3. Pin separate source `P` and shadow `Q` addresses and equal content hashes,
   full source/shadow image hashes, native identities and mapping evidence.
   Explicitly identify any retained intervals. With no compatible interval,
   admit an empty list only in the new versioned relocation profile. Update the
   generator, guest request guards, native probe, bridge and mount validators
   together; do not reinterpret an old same-offset A/B request.
4. Require `Q` to be disjoint from every retained interval. Bind the old target
   bytes at `Q`; for an unambiguous first experiment, require each destination
   granule to differ from `A` and confirm its appearance in the actual write
   ledger. `Q` need not be free in NTFS for the journal algorithm, since all
   overwritten bytes are saved, but a complete source semantic inventory remains
   necessary before generalizing beyond this one admitted file.
5. Update the native verifier to expect logical payload `A` and native extent
   `Q`, not the old offset or a payload differing from shadow B. Verify the
   original GPT identity, intended new filesystem/file identities, supported
   metadata/security, fresh read-only protection and reopened content again.
   Report relocated and retained bytes separately. An empty retained set must
   not produce a misleading positive extent-retention claim.

The relevant current fixture assumptions are visible in
[pair construction](../../lab/guest/NativeRetainedFixture.cs),
[request derivation](../../scripts/New-LabNativeReconstructRequest.ps1),
[guest reconstruction guards](../../lab/guest/Invoke-GuestNativeReconstruct.ps1),
[mount guards](../../lab/guest/Invoke-GuestReadOnlyMount.ps1), and
[native post-verifier](../../lab/guest/NativeConvertedVerification.cs).

Durability ordering does not require a new payload-copy phase. Prepare compares
all partition bytes outside `K`, including zero/free regions and both `P` and
`Q`, and saves both versions of every changed granule. The complete journal and
independent ticket must be flushed, read back and pinned before target writes.
Execution revalidates the immutable journal, full shadow hash and normalized
original target; it persists operation intent before writing. All replacements
come from journal postimages, so overwriting `P` before `Q` cannot destroy the
copy source. The existing executor flushes every other change before the first
4 KiB, then verifies each patch and the complete expected image.

The target must stay excluded throughout an incomplete image; discovery-last
ordering is not permission to mount intermediate bytes. Recovery accepts only
the journal's admitted old/new byte mixtures and rejects unrelated changes.
Rollback restores both overwritten original data at `P` and old bytes at `Q`,
then verifies the original full partition hash. Handoff requires the complete
postimage and durably closes recovery before the mount boundary; partial/nonzero
handoff records remain barriers. Preserving these rules avoids an allocation
dependency graph or live target-to-target copying.
[Existing journal contract](../history/lab-reconstruction-journal.md).

Flush and unbuffered-I/O contracts explain the API sequence, but do not by
themselves qualify every storage stack under power failure. Microsoft documents
explicit flush behavior and notes that hardware support affects write-through.
Ordinary-file interruption tests, native restart/isolation observations, and
eventual native power-loss experiments remain distinct evidence.
[FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers),
[caching and hardware write-through](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-createfile2_extended_parameters#caching-behavior).

Keep the current exact 64 GiB disk / 52 GiB partition, 512/4096 sectors, 4 KiB
cluster/granule profile and one ordinary 64 KiB file for this next experiment.
Retain the 256 MiB changed-byte, 65,536 patch-range and 768 MiB total-journal
ceilings. Journal length is measured as both payload versions plus bounded
metadata/records; do not assume that relocating 64 KiB limits total differences
to 64 KiB. A shadow can differ in metadata and stale/free bytes elsewhere.
Exceeding any cap rejects preparation, rather than widening it automatically.
General trees need complete inventory/admission and bounded scratch accounting;
this proposal neither establishes universal zero-copy conversion nor addresses
boot volumes.

The first new tests should reconstruct a synthetic relocation-only image with
`K` empty, a mixed retained/relocated image, and a case where overwriting `P`
precedes `Q`. They should prove full-image forward/rollback equality, exact
retained exclusion, actual destination changes, budget rejection, interrupted
reopen/resume/rollback and the unchanged handoff barrier. Native qualification
then needs a freshly prepared original-location source, protected shadow,
independent durable ticket, explicit apply and read-only native remount/content
verification. No current frozen run should be repurposed to claim that result.

For reproducibility, the Rust source hashes inspected for this assessment were:

| Source | SHA-256 |
| --- | --- |
| `src/retained_compare.rs` | `f922f85a2d8b08cd7a5a60939ee5898d5fade935ec0364a5feda9928dd799170` |
| `src/lab_reconstruct.rs` | `47ddcbda606737959aa9962fee9861aa8e65afb9cd373308f9694d4229e8c0ac` |
| `src/lab_native_reconstruct.rs` | `969938414286891bb5804091f669629fabbbad1079da592610de05b269e6dfb3` |
| `src/lab_native.rs` | `28528cbf9ddbd2b5c872d08194dbc9db377dd06177fd15ea7d7e58807e9259b6` |
| `crates/n2r-win32/src/native.rs` | `fc677350c0ee40747e2918c4f8f2ec0a7843544311cf6454a8f45535706e2bd1` |
| `crates/n2r-win32/src/layout.rs` | `1262a265a270a6c828cd1d5fcac1abd35ffecb291e7baa64c03eb236d3080189` |
