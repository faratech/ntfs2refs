# Extent verification for partial final clusters

The fast candidate extends initial/native source read elision to ordinary,
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

Focused source/semantic/native checks and public, bind, digest and fault-helper
release builds pass. VM qualification is pending. No unit tests were added or run.
