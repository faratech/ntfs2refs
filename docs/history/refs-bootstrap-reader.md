# ReFS 3.14 bootstrap observations

The Rust `inspect` command now includes a bounded candidate probe for ReFS 3.14
with 4 KiB clusters. It is a read-only format-research milestone. It does not
select the authoritative checkpoint or validate allocation. Bounded physical
container-tree traversal is described below. It does not
enable a writer or claim native acceptance. The eventual converter remains an
offline program that must execute inside the VM and on eligible bare metal.

## Implemented profile

The recognition checksum is a 16-bit rotate-right/add accumulation over VBR
bytes 3 through 511, skipping the stored checksum. A mismatch stops further
anchor reads. This check is separate from metadata checksums.
[VBR research](https://xbpt.gitlab.io/forefst/structures/vbr/)

The candidate locations are cluster 30 and the volume's third-last and second-last
clusters. Each SUPB read is one 4 KiB cluster. The reader checks signature,
header version, self-location, volume-signature/GUID agreement, descriptor bounds,
and the two checkpoint references. Each candidate keeps its raw-range SHA-256,
interpreted fields and rejection reason. Copies are retained independently.
[SUPB research](https://xbpt.gitlab.io/forefst/structures/supb/)

Only a structurally accepted SUPB with a matching self-checksum supplies followed
checkpoint addresses. Each CHKP candidate read is bounded to 16 KiB. Root count
is limited to the documented thirteen, with the direct or indirect in-page
offset array selected by its recorded flag. Descriptors, root-offset arrays and
fixed fields must not overlap. Root LCN slots and checksum bytes are recorded;
physical bootstrap types and the bounded virtual roots described below may be dereferenced. Both checkpoint clocks and all
valid candidate copies remain visible; no highest-clock winner is declared.
[CHKP research](https://xbpt.gitlab.io/forefst/structures/chkp/)

For this narrow profile, the self-descriptor is 48 bytes and advertises CRC32-C,
four digest bytes and a checksum-data offset of eight. The implementation zeros
the whole descriptor and computes reflected Castagnoli CRC32-C over the first
4 KiB of the anchor. This is deliberately distinct from the CRC64/NVME checksum
in a root/child page reference. Unknown descriptors are refused instead of
switching algorithms by guesswork.
[Checksum research](https://xbpt.gitlab.io/forefst/concepts/checksum_architecture/)

The root increment follows indices 7, 8 and 12 only: the two container tables
and small allocator. A consistent checkpoint self-checksum and header clock are
required first. Each reference must contain four distinct, bounded LCN slots
and an ordinary CRC64/NVME descriptor. Slots overlapping observed bootstrap
anchors or another root type are rejected. Four clusters are assembled in slot
order, even when noncontiguous, and checked against the descriptor's checksum,
`MSB+` header, volume signature, self-LCN slots and expected table identity.
The container pair must contain both IDs 11 and 12, in either order; the small
allocator must have ID 34. Accepted container roots additionally feed the
[bounded container-tree reader](refs-container-reader.md). Agreeing complete container maps
feed the [bounded virtual-root reader](refs-virtual-roots.md); root children remain uninterpreted.
[CHKP root addressing](https://xbpt.gitlab.io/forefst/structures/chkp/),
[page references](https://xbpt.gitlab.io/forefst/structures/page_references/)

At most three SUPB clusters and six unique CHKP pages are read. When more than
two checkpoint candidates exist, root probing is skipped without selecting an
authoritative pair. Otherwise, at most six root references are examined, with
pages deduplicated by their four LCN slots. These probes have a ceiling of 143,360
bytes beyond the existing header probes. Container walks add at most 2 MiB,
Virtual-root reads add at most 327,680 bytes, giving a combined ceiling of 2,568,192 bytes. Unrecognized profiles do not run this probe.
Malformed candidates produce bounded observations; I/O failures propagate rather
than yielding a successful partial inspection. Global `metadata_verified`,
`checksum_verified` and `conversion_profile_qualified` remain false.

## Evidence and limitations

The format descriptions are Baptiste Bonnet's primary research, not Microsoft
format specifications. No source code from the GPL tool was incorporated. Six
retrieved HTML sources and their SHA-256 values are retained under
`.lab/research/refs-bootstrap-20261023/sources.json` (site identifies itself as
forefst v1.13.1). The parser independently implements the documented field and
algorithm observations. Synthetic tests exercise CRC vectors, both root-list
forms, bounds, overlap, corrupted candidates, unsupported profiles and bounded
read lengths. They do not validate a native filesystem.

Provisional native measurements were taken from the completed fixed-VHD copy
while full raw extraction was still running. The read-only helper used the
verified selection's 16 MiB partition offset and 55,834,574,848-byte length,
validated the fixed-VHD footer and native-evidence hash, and retained every small
read range with its SHA-256. These measurements remain provisional until the
whole capture and source-chain checks finish. Dev Drive provenance stays distinct
from ordinary ReFS and boot qualification.

The VBR checksum recomputed as 15,514. All three SUPB self-checksums matched at
LCNs 30, 13,631,486 and 13,631,485; each reported generation 1 and the same two
checkpoint addresses. CHKP self-checksums matched at LCNs 136,348 and 1,635,808,
with clocks 45/44 and allocator clocks 40/39. Both had indirect thirteen-root
lists with 48-byte references. Flags were `0x6c2`, differing from the reference's
`0x682` example; the unknown difference is retained without assigning a meaning.
All header self-locations and volume signatures agreed with the measured ranges.

The temporary helper also checked the three researched physical bootstrap roots
from both checkpoints (six references, three distinct pages). Full 16 KiB
CRC64/NVME matches were `7e964d0982c63ee3`, `3483a43691e96817` and
`8ab9ae39442ffe96`. Each page had `MSB+`, header version 2, matching volume
signature and four self-LCN slots, and table IDs 11, 12 and 34 respectively.
No child traversal occurred. These checks are now implemented in the production
inspector's `physical_root_pages` and `physical_root_references` observations;
the original temporary results remain separate retained evidence.

Artifacts: `.lab/hyperv/corpus/devdrive-20261023T231918797Z/` under
`bootstrap-provisional-20261023T2324/` and
`bootstrap-root-provisional-20261023T2328/`; both contain
`bootstrap-provisional.json` and individually hashed range files. The helper
source and binaries remain under `.lab/research/refs-bootstrap-20261023/`.

The inspector now includes [bounded root-node observations](refs-root-nodes.md)
for these three physical pages. The [container-tree increment](refs-container-reader.md)
now follows bounded physical container children and decodes their leaf mappings.
Bounded [virtual-root translation](refs-virtual-roots.md) is now implemented; allocation ownership remains unimplemented. The implemented CRC64 reflected
polynomial is `0x9a6c9329ac4bc9b5`, with all-ones
initial/final XOR and standard check vector `0xae8b14860a799888`; the described
sentinel substitution is covered by a separate test. Container translation,
allocation ownership and traversal of other root types remain unimplemented proof obligations.
[Page-reference research](https://xbpt.gitlab.io/forefst/structures/page_references/),
[checksum algorithms](https://xbpt.gitlab.io/forefst/concepts/checksum_architecture/)
