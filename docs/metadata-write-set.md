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
above do not qualify it. Container-table and Small-allocator traversal still have
their existing bounds, and the live 128 GiB partition ceiling remains. No write-
set omission, whole-volume ownership or native conversion claim is added.
