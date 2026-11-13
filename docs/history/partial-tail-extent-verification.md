# Extent verification for partial final clusters

The fast implementation extends initial/native source read elision to ordinary,
initialized, nonresident streams whose EOF is at least 4 KiB but is not a
multiple of 4 KiB. Complete source allocation maps, exact EOF, VDL=EOF, identity,
namespace and ownership checks remain mandatory. Physical source runs remain
aligned to the source allocation unit. Resident, sparse, compressed, partial-VDL
and system-managed streams retain their existing content paths. Encryption and
other unsupported semantics remain refused.

Canonical evidence uses a distinct
`extent_identity_with_materialized_tail_v1` tag. The earlier
`extent_identity_v1` tag still requires whole-cluster EOF. Both explicitly lack
a content digest. Source request/report shapes still bind all allocated source
runs and exact EOF; no missing digest is replaced with a placeholder value.

Only `[0, floor(EOF/4096)*4096)` is a retained-prefix candidate. The final bytes
are read through the checked NTFS range reader, written into the private ReFS
file, flushed and read back. Constructor-owned receipts bind the exact stream,
file identity, offset, length and SHA-256. A matching receipt is required before
metadata completion, including when a named stream uses a rounded carrier.

The protected frozen-shadow observation separately verifies every tail against
the source-derived residual hash. The fresh conversion proof requires that
exact residual for each tail-aware extent-only stream. The selected journal
then authenticates all changed target bytes, including rewritten tail blocks.
Recovery continues to require its complete journal/lifecycle checks and pinned
target mappings. Full-content mode and the prior whole-cluster path remain.

The lab must observe positive tail-aware coverage, validate actual construction
and protected-residual receipts, and compare every target stream with its
independently pinned full-content baseline. A successful fallback with no tail
elisions is not evidence that this extension ran.

Runtime `3ce15c7` passed H normal conversion `c42d891b` / core `e28bab21` with
exit 0/HND: 44 objects, 53 matching bindings, zero target content hashes/reads,
and all 39 independent stream hashes plus the prior fixture suite. Actual coverage
was 14 extent-only streams (4,489,673 logical bytes), comprising the unchanged two
whole-aligned streams and 12 partial-tail streams. All 457 visible tail bytes have
matching actual source, constructor write/readback, final identity and protected
residual evidence. Initial raw hashing remains 159,222,314 bytes; other native
source reads total 86,659,954 bytes. This is not zero initial payload work.

The corpus includes a plain 65,553-byte default stream beside an encoded ADS.
Its per-stream proof permits the plain tail path while the encoded sibling retains
a real digest and full decoder/materialization checks. The initial `3d3d009`
refusal on the file-wide guard is preserved separately with zero source writes.

The 133 closed metadata files (86,221,996 bytes) are SHA verified. The VM is
normally stopped at ReFS checkpoint `3cbc9ae0-c7da-49ab-bd08-ca0c48275f03`.
Native wall time was 24.630 seconds in one run with uncontrolled cache/host
conditions; no general or physical-I/O speed claim follows. See
[the native evidence](../../evidence/partial-tail-extent-native-20261031.json).

Focused builds pass. Tail-specific recovery, F-scale, mutation and power-loss
qualification remain pending; the earlier `7ced37b` whole-cluster recovery matrix
does not qualify this new runtime. No unit tests were added or run.
