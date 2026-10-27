# Candidate ReFS target write set

The current journal compares every sector of a frozen NTFS partition with a
native ReFS shadow. On a previously used volume, stale bytes in free sectors
can make the journal much larger than the ReFS metadata and live payloads.

The new `refs_write_set` planner unions the native ReFS metadata-inclusive
allocation bitmap with observed VBR, superblock, checkpoint and physical-root
anchors, plus successfully checked container-tree and translated-root pages.
The bounded anchor profile requires the three expected superblock locations,
two matching checkpoint locations and valid self checksums. Rejected observed
pages prevent a candidate instead of silently disappearing from its range set.
It computes the complement as source bytes to preserve. The shadow
collector records compact allocated intervals and the bitmap SHA-256; the
freeze report records a diagnostic write-set candidate or the reason it could
not be formed. `lab-refs-write-set` can also build that diagnostic from saved
ReFS inspection and allocation evidence. It never authorizes writes.

`payload_coverage` separately checks supplied measured target retrieval ranges
against that candidate, reports uncovered bytes and rejects overlapping,
unaligned or out-of-volume extents. This range check proves neither that every
payload was supplied nor that the remaining metadata graph is complete.

A parser smoke run on the Windows-created 3.14 corpus found 19 anchor ranges,
coalesced into eight intervals. That run used an **artificially empty**
allocation map solely to exercise anchor parsing; its 100 KiB write-set total
does not describe the real volume.

The native bitmap is read before shadow dismount and flush. ReFS may change its
allocation graph during that transition. Before using this plan to omit any
journal patch, an independent reader must reconcile the **frozen raw image**
against the captured bitmap, all reachable metadata and data extents, and
fixed bootstrap locations. The journal then needs a hybrid postimage hash:
shadow bytes in target-owned ranges and original NTFS bytes in preserved
ranges, followed by native ReFS mutation qualification.

The Rust allocator reader now validates the checkpoint/container route and
decodes every Medium row plus the physical Small allocator root on the pinned
Windows-generated 3.14 corpus. Both tiers' free counts agree with REFSNT
before and after one isolated extent adoption. Block refcounts, other
reservations and the whole metadata/data reference graph remain outside that
reader's proof.

The later experimental larger-tree path adds a multilevel Medium allocator
walk, connected to retained-payload coverage checks. It decodes each leaf as
it arrives, retaining compact allocator rows/ranges instead of all raw leaf
rows. Bounds are 4,096 pages including the root, 65,536 leaf rows and eight
levels below the root. Every child must match its parent CRC, virtual self
locations, table, volume signature and expected level. Repeated/overlapping
physical page clusters, incomplete row counts and gaps in full-volume coverage
refuse the entire observation. The default one-level reader is preserved.

This expanded walk has compilation evidence only; the historical corpus results
above do not qualify it. Container-table traversal retains its existing bounds,
and the live 128 GiB partition ceiling remains. No write-
set omission, whole-volume ownership or native conversion claim is added.

The experimental Small allocator reader now also supports multilevel trees,
with the same 4,096-page, 65,536-leaf-row and depth-eight bounds. It uses direct
physical child addresses, consistent with the [Small tier's documented address
class](https://xbpt.gitlab.io/forefst/structures/allocators/). It validates each
child's CRC, table/volume identity, physical self-address and parent-derived
level, rejects reused physical clusters and enforces ordered non-overlapping
managed ranges. It compares total leaf count with the root descriptor without
pretending that Small covers the entire volume. Leaves are decoded incrementally.

This Small-tier expansion has compilation evidence only. Its default entry
still uses the original root-only profile, with no new field in legacy JSON
when there are no child pages. Container traversal and larger-volume routing
remain unfinished; native qualification and the partition ceiling are unchanged.

Container lookup now borrows the validated, sorted mapping rows and uses binary
search instead of constructing duplicate B-tree indexes in Medium/virtual-root
readers. Container traversal retains rows in index order, rejecting duplicate
or unsorted IDs; physical-overlap checks sort a compact vector of starts. Raw
diagnostic hex is still retained, and container traversal budgets are unchanged.

The experimental Small reader also uses a physical-bootstrap-only inspection,
avoiding an extra container/virtual-root scan. This still reads the redundant
headers, anchors, checkpoints and physical root pages needed for Small's own
bindings. Skipped descendants are explicitly absent and remain unverified;
retained coverage independently requires the Medium/container checks. Default
inspection keeps its full bounded bootstrap path. These changes have compilation
evidence only, with no new unit tests or native execution.

Valid 160-byte container values now use fixed-size byte storage rather than a
heap-allocated 320-character hex string. Copy comparison and mapping digests
read those bytes directly, avoiding repeated hex decoding. JSON still emits the
same `value_bytes_hex` string field. Imported malformed diagnostic strings remain
representable and are explicitly refused before they can supply mapping bytes.
This removes one retained heap allocation per valid mapping; it does not remove
the diagnostic table's row-count limits or qualify larger volumes. Existing
fixture assignments were adapted to the value type without adding or running tests.
