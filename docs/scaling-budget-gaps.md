# Scaling budget gaps

Subsequent implementation `f32c0f6` adds a pinned count envelope for fresh fast
allocation conversion: files and directories share the existing 1,280 object
slots. Full-content and legacy profiles keep their original split. This removes
one coupled limit. A sealed f32 normal case now passed with 1,084 objects,
273 directories and all 811 independent hashes, exceeding the old directory
split only. More than 1,024 files and broader scale remain unqualified; the
other collection, metadata, namespace, placement and recovery ceilings below
remain. See [the native scope](object-envelope-native.md) and
[the implemented bounded envelope](object-resource-envelope.md).

Read-only code audit of `cce4a6e`. These are current enforcement points, not new
native qualification results. A refusal's order depends on file count, directory
shape, fragmentation, names and descriptor sizes. At that revision the public
profile supported at most **1,024 files and 256 directories**, including the root.

## Historical cce audit and remaining ceilings

| Area | Binding guards and retained structures |
|---|---|
| Public profile and file counts | At cce, the public streaming V2 profile used 1,024 files / 256 directories. Current fresh fast conversion selects V3 planning/count admission in [drive_cli.rs](../src/drive_cli.rs), with a shared 1,280-object ceiling enforced through raw/native/semantic/constructor checks and pinned recovery. Full-content and legacy profiles retain their prior split. The qualified case covers 811 files / 273 directories only. |
| Source native request | [ntfs_attestation.rs:106](../src/ntfs_attestation.rs#L106) refuses more than 2,048 entries in `raw.files` before source admission. These are canonical allocated MFT records, including internal records, rather than just user files. The matching native [request guard](../crates/n2r-win32/src/attestation.rs#L249) uses the [2,048-identity profile](../crates/n2r-win32/src/attestation.rs#L51). Thus a source with more than 2,048 raw objects stops here even before the smaller semantic tree limit is assessed. |
| Raw inventory and ownership | [NtfsInspection](../src/ntfs_inspect.rs#L163) retains files and attribute assemblies in vectors. Its heap budget remains [64 MiB](../src/ntfs_inspect.rs#L60). The [MFT domain](../src/ntfs_inspect.rs#L21) is capped at 1,000,000 records; [bootstrap validation](../src/ntfs_mft_bootstrap.rs#L175) applies this to the MFT's record domain, including unused slots. [Raw ownership reconciliation](../src/ntfs_inspect.rs#L1892) streams the bitmap but inherits [4,096 intervals, 16 KiB of attribute-name units and a 4,096-index sort budget](../src/ntfs_allocation.rs#L36). Fragmentation can therefore refuse before file-count admission. |
| Namespace, streams and paths | Raw [namespace limits](../src/ntfs_namespace.rs#L12) include 16 MiB of index data, 16,384 entries, 131,072 UTF-16 name units and 4,096 directories. Native [directory collection](../crates/n2r-win32/src/namespace_layout.rs#L5) has 4,096 entries / 64 calls / 2 MiB of evidence. The canonical/native stream total is 16,384; the [native stream list](../crates/n2r-win32/src/stream_layout.rs#L3) allows 64 streams per file. The [semantic path-depth guard](../src/shadow_tree.rs#L306) is 16 components. These are separate gates from total file count. |
| Per-file metadata and fragmentation | [Attribute-list assembly](../src/ntfs_attribute_list.rs#L12) caps list bytes at 65,536, extension records at 1,024 and runs at 1,024. [Native complete retrieval](../crates/n2r-win32/src/stream_layout.rs#L8) caps extents at 65,536, while the shadow's source-run input still has a [1,024-run guard](../crates/n2r-win32/src/shadow_native.rs#L3374). Security also retains [16 MiB metadata / 4 MiB descriptors / 16,384 descriptors](../src/ntfs_security.rs#L12). |
| Native reports and construction | The source report retains `Report.files`, logical-data and namespace vectors in [attestation.rs](../crates/n2r-win32/src/attestation.rs#L460). Its profile separately limits security to 32 MiB, stream evidence to 64 MiB and namespace evidence to 16 MiB; the [serialized report guard](../crates/n2r-win32/src/attestation.rs#L1096) is 64 MiB. The private constructor keeps an owning file/stream table and [metadata handles](../crates/n2r-win32/src/shadow_native/private_tree.rs#L53), so increasing counts also increases open handles and kernel memory. |
| Placement and selected ranges | [Placement](../crates/n2r-win32/src/shadow_native/private_tree/placement.rs#L12) has 16,384 planned ranges but a 4,096 downstream route limit; [source-backed routes](../crates/n2r-win32/src/shadow_native/private_tree/source_backed.rs#L156) enforce the latter. There are 32,768 move submissions and a [roughly 64 MiB placement transcript limit](../crates/n2r-win32/src/shadow_native/private_tree/placement.rs#L37). Each move retains complete retrieval evidence. Streamed native bitmaps still cap [allocated intervals at 65,536](../crates/n2r-win32/src/bitmap_streaming.rs#L201), and [SelectedPlan](../src/selected_journal.rs#L25) caps selected ranges at 65,536. |
| Artifact and recovery readers | Qualification [serializes into an in-memory bounded buffer](../src/general_qualification.rs#L33), with 64 MiB per artifact. The allocation recovery reader separately limits [plan and expectation to 16 MiB](../src/general_recovery/allocation.rs#L121), and the payload-map manifest to 64 MiB. [FreshPayloadProof](../src/general_reconstruct/fast_verification.rs#L13) keeps a full map table, then [clones it into manifest bindings](../src/general_reconstruct/fast_verification.rs#L241); the writer and reader each enforce 64 MiB. Journal capacity schema 3 does not remove these metadata limits. |

The bitmap-derived experimental routing ceiling is 2 PiB, from a 64 GiB bitmap
budget in [general_layout.rs](../crates/n2r-win32/src/general_layout.rs#L12). This
numeric address range does not establish ordinary 1,000 TB volume support: the
collection, namespace, file-count and recovery limits above remain binding.

The aggregate counts and byte ceilings above are implementation/profile budgets.
Keep actual serialized field widths, checked offsets, complete record/attribute
coverage and native API buffer validation. Current supported source geometry and
name rules are also compatibility contracts; widening a collection budget must
not silently widen those contracts.

## Proposed implementation sequence

1. **Introduce one pinned resource budget across the public path.** Derive explicit
   record/object/stream/extent counts and memory, handle, temporary-storage and
   evidence-byte ceilings from the source's complete metadata domain and available
   machine resources. Thread the same versioned descriptor through source
   inspection, native collection, semantic tree validation, construction, placement,
   request/ticket/bundle and recovery. Preserve the original pinned ceilings during
   recovery. Change the duplicated 1,024/256/1,280/2,048 gates together; replacing
   one constant with a larger constant or `usize::MAX` is insufficient.

2. **Externalize complete source and native evidence before pursuing large counts.**
   Add bounded append-only records/pages for `NtfsInspection.files` and assembly
   ledgers, native file/stream/namespace observations, and their lookup indexes.
   Record schema, ordered identity/stream keys, total counts and cryptographic
   metadata pins. Allocation ownership, namespace membership and security joins
   need sorted external indexes or bounded merge passes. Admission must wait for
   complete source/native closure; collecting batches must never admit a partial
   record set. The MFT bitmap/extension bookkeeping also needs paging rather than
   memory proportional to the entire MFT record domain.

3. **Use the same manifests for construction and recovery.** Replace monolithic
   `ExpectedTree.objects` and recovery map-binding vectors with pinned paged
   manifests, while retaining explicit missing-content evidence and actual tail
   checksums. Stream serialization and SHA calculation instead of cloning entire
   reports into JSON buffers. Open readers with bounded page windows and validated
   complete-domain counts. Update writer limits and recovery reader limits as one
   contract. Constructor handle batching requires an explicit identity/ownership
   design preserving the current native capabilities; merely dropping its owning
   handles would change the guarantee.

4. **Move placement transcripts to a complete external ledger.** Preserve every
   ordered move, destination window, complete before/after retrieval map and final
   phase map, reserving the next record's real storage before native I/O. Replace
   route/move/interval ceilings with the pinned resource budget only after their
   in-memory vectors and downstream consumers can consume bounded pages. This
   changes evidence storage, not query coverage; D2 incremental retrieval remains
   unapproved.

The first deliverable should make the source/native/tree budget and paged manifest
contract coherent end to end, then qualify a count above the current release
limits. It must report the actual resource ceiling and refuse completely when
that budget is exhausted. No unbounded-volume support is claimed by this note.
