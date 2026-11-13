# Native ReFS corpus: next read-only work

Scope: the Windows 11 ordinary ReFS `empty.raw` and `control.raw` partition captures, once their exports pass verification. This work reads exported files only. It does not mount them, replay logs, repair metadata, create a filesystem, or enable a writer. No native format result is assumed here.

## What the present tools establish

`refs_inspect.rs` checks common VBR geometry and compares the declared final
logical sector with the primary header. For the ReFS 3.14/4 KiB profile it also
invokes the [bounded bootstrap reader](refs-bootstrap-reader.md), checking
selected anchor and root-page checksums. Complete metadata health, allocation,
provenance and boot eligibility remain unqualified. Global report flags stay
false/unknown; captured formatter provenance belongs in a separate evidence record.

`diff` counts differing bytes and changed blocks and reports up to 4,096 contiguous changed ranges. Range lengths cover changed blocks, not just differing bytes. A truncated range list must not be treated as a complete map. These implementation limits are intentional starting points, not a verified format profile.

## First pass on the two images

1. Verify each complete capture's SHA-256 and exact 1,073,741,824-byte length against its export and capture records. Reject `.partial` files. Confirm both captures describe the same target identity, partition offset and geometry. Preserve the formatter options, Windows build, actual `refs.sys`/formatter component versions and hashes, command results, and known mount history. A raw image begins at the partition's first byte; the VHDX and whole GPT disk are different artifacts.
2. Inspect both images and save reports to new paths under the ignored lab tree. Compare the VBR's declared size with the capture length and native `refsinfo`; investigate discrepancies before parsing metadata. A missing or differing last-sector probe is an observation, not a corruption diagnosis.
3. For confirmed 512-byte logical sectors, run the existing commands below. Retain the sector map; the 4 KiB map is a second view. Neither block size defines metadata page size.

   ```powershell
   .\target\release\ntfs2refs.exe inspect --image <case>\empty.raw --output <analysis>\empty-inspection.json
   .\target\release\ntfs2refs.exe inspect --image <case>\control.raw --output <analysis>\control-inspection.json
   .\target\release\ntfs2refs.exe diff --before <case>\empty.raw --after <case>\control.raw --block-size 512 --output <analysis>\diff-512.json
   .\target\release\ntfs2refs.exe diff --before <case>\empty.raw --after <case>\control.raw --block-size 4096 --output <analysis>\diff-4096.json
   ```

4. Inventory what actually completed. The current fixture batch attempts empty/small/Unicode files, a patterned 16 MiB stream, an alternate stream, hard link, symlink, sparse file and ACL change. A mid-batch failure leaves a partial fixture set. Use native paths, stream hashes, file IDs and reported failures rather than inferring success from the script. `resident.txt` is a name, not evidence of ReFS storage residency; the patterned file is not proof of fragmentation.
5. Treat this pair as discovery evidence. It includes the whole fixture batch and intervening mount/evidence activity, so a changed page cannot be assigned to one operation. Payload matches are useful cross-checks, but the repeating pattern cannot uniquely establish extents.

## Read-only parser milestones and unresolved structures

The linked independent researchers are primary sources for their own observations, not Microsoft format specifications. Pin source revisions before using external tools. The following claims remain hypotheses for this exact native corpus.

| Order | Structure to resolve | Evidence required from these captures |
|---|---|---|
| 1 | VBR and redundant discovery records | Enumerate candidate copies and validate the recognition checksum separately from metadata checksums. Retain unknown bytes and exact offsets. [VBR research](https://xbpt.gitlab.io/forefst/structures/vbr/) |
| 2 | `SUPB` and both `CHKP` anchors | Establish address units, primary/backup positions, bounds, self-references, generations and root lists. Preserve both checkpoint candidates; a larger clock alone does not prove the driver would choose it. [Superblock](https://xbpt.gitlab.io/forefst/structures/supb/), [checkpoint](https://xbpt.gitlab.io/forefst/structures/chkp/) |
| 3 | Page references, container table/index and address translation | Resolve each physical cluster needed to assemble a metadata page, including bootstrap exceptions. Do not treat every recorded LCN as a physical disk address or assume one page equals one cluster. [Page references](https://xbpt.gitlab.io/forefst/structures/page_references/), [container table](https://xbpt.gitlab.io/forefst/structures/container_table/) |
| 4 | Checksums and coverage | Identify selector, descriptor length, covered byte order, exclusions and stored digest for each layer. Recompute independently over numerous reachable pages from both images. Modern research specifies CRC64/NVME while older notes label type 2 ECMA-182; resolve the discrepancy with bytes, not a version heuristic. Checksum agreement establishes consistency, not authenticity or driver enforcement. [Modern checksum analysis](https://xbpt.gitlab.io/forefst/concepts/checksum_architecture/), [libfsrefs notes](https://github.com/libyal/libfsrefs/blob/main/documentation/Resilient%20File%20System%20(ReFS).asciidoc) |
| 5 | `MSB+` nodes, schema table and object table | Validate row/index bounds, node levels, key ordering, child references and object roots. Separate root descriptors from per-node headers, and reachable live pages from old copy-on-write pages. [Nodes](https://xbpt.gitlab.io/forefst/structures/btree_node/), [schemas](https://xbpt.gitlab.io/forefst/structures/schema_table/), [objects](https://xbpt.gitlab.io/forefst/structures/object_table/) |
| 6 | Directory/file records and stream extents | Reconstruct paths, file identities, link relationships, unnamed/named streams, logical lengths, valid data and sparse holes; hash reconstructed streams against native observations. [Directory records](https://xbpt.gitlab.io/forefst/structures/directory_entries/), [extent descriptors](https://xbpt.gitlab.io/forefst/structures/extent_descriptors/) |
| 7 | Allocators, free space and block reference counts | Reconcile live metadata/data allocations, reserved areas and shared extents without conflating unreachable stale pages with free space. The pair cannot establish deletion or reuse behavior. [Allocators](https://xbpt.gitlab.io/forefst/structures/allocators/), [refcounts](https://xbpt.gitlab.io/forefst/structures/block_refcount/) |
| 8 | Security, reparse/EA attributes, integrity tables, USN and metadata log | Decode preservation semantics and cross-references. Distinguish the change journal from transaction recovery records. Clean snapshots cannot prove log replay, commit ordering or crash recovery. [Security descriptors](https://xbpt.gitlab.io/forefst/structures/security_descriptors/), [metadata log](https://xbpt.gitlab.io/forefst/structures/mlog/) |

For each proposed parser stage, emit bounded observations: image hash, byte range, raw range hash, candidate type, referring parent/field, interpreted values, checksum result and unresolved reason. Use checked arithmetic, image-relative bounds, traversal depth/page limits and a visited set. Exceeding a limit means incomplete analysis. A signature scan produces candidates only; accepted references and checksums must support a reachable graph.

Cross-check selected findings with a pinned external read-only parser, such as [refsprogs](https://github.com/unsound/refsprogs). A disagreement is useful evidence. Agreement between tools sharing the same assumptions does not independently establish native acceptance. Source-code reuse requires separate license review.

## Missing evidence and the next capture requests

The native manifest currently lacks physical extent observations, exact security-descriptor bytes, raw EA/reparse payloads and complete timestamp semantics. SDDL and stream hashes cannot fill those gaps. Preserve failures explicitly.

After analysing this pair, request separate future captures for a no-op mount/dismount control and one operation at a time: empty file, small file, large file, ADS, hard link, sparse range, rename, delete/reallocate and ACL change. Record the parent image hash and native operation outcome. Add measured fragmentation and allocator-pressure cases later. Native/upgraded layouts and other geometries remain separate profiles; a header version alone cannot identify creation history. [Format evolution](https://xbpt.gitlab.io/forefst/concepts/version_evolution/)

The next deliverable is a bounded, independently checked reader that reconstructs this corpus and explains its unresolved pages. Allocation writes, crash-consistent commits, extent reuse and OS boot acceptance remain the separate gates in [format-gates.md](format-gates.md).
