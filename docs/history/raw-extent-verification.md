# Initial payload scan elimination

The next built candidate extends extent evidence to partial final clusters, with
actual tail materialization and separate receipt guards. Its native qualification
is pending; see [partial-tail extent verification](partial-tail-extent-verification.md).

The fast implementation represents eligible source streams with
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

Runtime `7ced37b` passed normal H conversion `aac022f8` / core `19ebb0e6`:
exit 0/HND, 44 objects and 53 matching bindings, with zero observed target content
hashes and zero target payload reads. The two 2 MiB ATTRIBUTE_LIST streams retain
explicit absent digests; initial raw hashing fell from 163,711,987 to 159,517,683
bytes. Native source request 4/report 12 omitted those same two streams while
remaining native logical reads total 86,955,323 bytes. SVI tracking data retains
its full-content fallback. The recovery bundle pins the actual manifest and its
expectation/plan/ticket/source/selected bindings.

The lab independently verified all 30 default and 9 named stream hashes plus the
prior fixture suite. It reconciled 22 old baseline access times only after proving
the current raw/native-source and target metadata. Current creation/write/change
times, ACLs, maps and all other fields remain checked. The existing indexer-cache
SVI-directory time scope is recorded separately. No product expectation or
filesystem timestamp is rewritten for the comparison.

The native wall time was 26.646 seconds in one run with uncontrolled cache/host
conditions; no general speedup or physical-I/O claim follows. The 133 closed
metadata files (86,066,547 bytes) are SHA verified, and the stopped result is saved
at checkpoint `44c48db9-c9ad-452f-8811-ce32a170c979`. Earlier SVI-copy refusal and
full-fallback/observer-failure cases remain separately preserved. See
[the native evidence](../../evidence/raw-extent-verification-native-20261031.json).

The same runtime also passed a separate first-flushed-write interruption,
Resume and Rollback matrix with the pinned manifest. See
[the recovery scope](raw-extent-recovery.md). Focused builds pass; no unit tests
were added or run.
