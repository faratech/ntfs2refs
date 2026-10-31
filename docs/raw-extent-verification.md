# Initial payload scan elimination

The fast candidate represents eligible source streams with
`NotReadExtentIdentityV1`, no content digest, and explicit canonical
`source_evidence: "extent_identity_v1"`. Plain initialized nonresident streams
with a complete aligned physical mapping qualify only after ordinary ancestry
and raw allocation reconciliation. Native identity, EOF, allocation and complete
retrieval evidence must match independently. Unread bytes never receive a
completed-hash outcome or a placeholder digest.

Resident, compressed, sparse, partial-VDL, partial-cluster and unsupported streams
keep the existing content path. `--verify-full-content` keeps the full inspection
and native checks. Metadata, ownership, security, namespace, physical-record
rereads and the original online-to-frozen source witness remain required.

Construction carries optional digest expectations through native layout and
source-backed routes. Full-content APIs refuse absent baselines. Moved or
rewritten bytes are actually read and checksummed by the existing capture and
journal protocol; retained bytes are identified through the exact mappings.

Before source activation, the owning converter saves a bounded stream-map
manifest and pins it in the recovery bundle. It binds the original expected tree,
device, exact plan, prepared ticket and protected target maps. These are facts,
not a serialized fresh source certificate or write capability.

Recovery retains the complete immutable-journal, lifecycle, old/new target,
ordering and durability checks. A real closed-journal result is required before
native verification can compare pinned maps. Streams with original digests still
receive full native content reads; streams without them receive explicit extent
verification. No later hash is presented as an original content baseline, and
post-operational source-content equality is not claimed. Rollback still restores
every recorded old selected byte and remains closed after HND.

The lab uses separately pinned full-content evidence from the same source
checkpoint. It compares all canonical metadata and stream mappings, allowing only
the explicit evidence/digest changes, and hashes every target stream independently.
Those lab baselines are never inserted into product expectations or certificates.

Focused library/CLI/helper checks and public, bind and digest-helper release builds
pass. Native conversion and recovery qualification for this candidate are pending.
No unit tests were added or run.
