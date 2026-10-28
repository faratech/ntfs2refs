# Candidate ReFS target write set

## Compact candidate backing

`refs_hybrid::packed` now streams selected shadow ranges into a dense scratch
file using a 64 KiB buffer. Its index is bounded by the candidate's 65,536-range
limit rather than partition capacity. `PackedShadow` exposes their original
partition addresses to `CandidateHybrid`; reads into omitted ranges fail unless
the hybrid supplies the original source bytes. Omitted ranges are never
implicitly zero-filled. The compact file has a SHA-256 receipt, exact byte
count and `executable: false`. Caller-owned durable storage and authenticating
the exact plan remain necessary.

`lab-refs-write-set` accepts optional `--shadow <frozen-raw-image>
--packed-output <new-file> --max-packed-bytes <budget>`. It refuses excessive
selected bytes before opening the scratch destination, requires ordinary image
input, creates outputs exclusively, flushes the compact file, and only then
writes its completion report. Failure preserves partial artifacts rather than
presenting a success receipt. Optional `--original <raw-ntfs-image>` connects
the compact backing to the existing read-only hybrid ReFS inspector.

This eliminates unselected bytes from the compact artifact, not from initial
native shadow construction. Selected ranges still include allocated payload;
the module does not establish metadata completeness or independently authorize
retained-payload subtraction. The existing full-shadow conversion/recovery
path is unchanged. Initial evidence is a release build, not native compact
conversion qualification. No unit tests were added or run.

The subsequent retained-range path also omits supplied retained payload from
the compact artifact. `--retained-request` accepts the existing comparison
request (or the `comparison` member of its owning request) and requires both
ordinary original/shadow images. It validates range coverage/alignment,
non-overlap, the 1,024-range budget, equal pinned source/shadow range hashes,
actual hashes from both input images, and no overlap with observed metadata
anchors. Evidence reads are bounded at16 MiB before JSON decoding. Scratch
admission uses selected bytes **after** retention subtraction.

`PackedShadow::with_retained` routes retained reads to the original image;
packed offsets cover only the remaining selected ranges. The original
filesystem allocation plan is unchanged: retained clusters remain allocated
to their ReFS streams. `retained_source_bytes` reports omitted payload
separately from packed bytes. Hash agreement and known-anchor exclusion do
not prove the complete metadata graph or preservation of file identity;
these remain diagnostic candidates with `executable: false`.

This path has release-build/CLI evidence only. It has not yet been used for a
native compact conversion. Initial native shadow construction still allocates
the placeholder payload and remains the next independent storage problem.

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
it arrives, retaining allocated ranges, row/page counts and digests instead of
all decoded rows. Bounds are 1,048,576 pages including the root, 33,554,432 leaf rows and eight
levels below the root. Every child must match its parent CRC, virtual self
locations, table, volume signature and expected level. Repeated/overlapping
physical page clusters, incomplete row counts and gaps in full-volume coverage
refuse the entire observation. The default one-level reader is preserved.

This expanded walk has compilation evidence only; the historical corpus results
above do not qualify it. Default container-table traversal retains its existing bounds,
and the default 128 GiB partition ceiling remains. No write-
set omission, whole-volume ownership or native conversion claim is added.

The experimental Small allocator reader now also supports multilevel trees,
with separate 4,096-page, 65,536-leaf-row and depth-eight bounds. It uses direct
physical child addresses, consistent with the [Small tier's documented address
class](https://xbpt.gitlab.io/forefst/structures/allocators/). It validates each
child's CRC, table/volume identity, physical self-address and parent-derived
level, rejects reused physical clusters and enforces ordered non-overlapping
managed ranges. It compares total leaf count with the root descriptor without
pretending that Small covers the entire volume. Leaves are decoded incrementally.

This Small-tier expansion has compilation evidence only. Its default entry
still uses the original root-only profile, with no new field in legacy JSON
when there are no child pages. Larger-volume routing
remains unfinished; native qualification and default routing are unchanged.

Container lookup now borrows the validated, sorted mapping rows and uses binary
search instead of constructing duplicate B-tree indexes in Medium/virtual-root
readers. Container traversal retains rows in index order, rejecting duplicate
or unsorted IDs; physical-overlap checks sort a compact vector of starts. The
default detailed reader retains raw diagnostic values and its original budgets.

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
This removes one retained heap allocation per valid detailed mapping; it does not
qualify larger volumes. Existing
fixture assignments were adapted to the value type without adding or running tests.

The larger-tree profile now uses a separate [compact container walk](refs-compact-containers.md),
retaining only live ID/address indexes while hashing all page and row-value data.
Serialized summaries cannot recreate those indexes. It is connected to bootstrap,
virtual-root and allocator checks plus frozen reconstruction qualification; native
qualification remains unchanged. Default routing retains 128 GiB, while the
explicit experimental profile propagates a 2 PiB routing budget through the
streaming paths. This is not a guarantee that format, data, metadata-complexity
or journal/scratch limits admit a particular volume.

The streamed Medium result marks `rows` as an empty diagnostic collection and
adds `streamed` accounting. `child_pages` contains at most the first 32 child
addresses; `streamed.pages_read` counts the entire walk including the root.
The leaf digest covers a version prefix followed by each actual row's 32-byte
SHA-256 in traversal order. The page digest covers its version prefix, then
each page's four physical LCNs, validated level byte and complete 16 KiB bytes.
Default one-level results retain all original rows/pages and omit `streamed`.
Allocated-range storage retains its existing 65,536-interval bound. No larger
volume or native execution qualification follows from these resource changes.
