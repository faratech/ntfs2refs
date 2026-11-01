# Retaining the verified journal through fresh apply

Exclusive preparation already flushes the complete journal and independently
reads it back. That readback validates every descriptor and old/literal payload,
the immutable-body SHA-256, resolved copy references, synthetic zero digests,
the selected old/new SHA-256 values, footer and clear markers. Previously it
discarded the validated record table. Fresh apply then loaded and validated the
same journal again before checking the actual old target.

The implementation retains that table in a private, nonserializable, one-shot
`PreparedExclusiveJournal`. It owns the exact journal and immutable plan/ticket
continuously from preparation through apply and HND. It exposes the ticket for
receipt persistence, but no mutable journal accessor. Neither a saved ticket nor
a JSON flag can reconstruct this owner. The existing exclusion contract still
requires the caller to exclude hidden writer/delete aliases; Rust ownership does
not establish global exclusion of administrative or volume aliases.

Consuming the owner still checks clear intent/completion markers, flushes the
target and verifies every selected actual target byte against the old digest
immediately before intent. All desired-byte reads, writes, discovery-granule-last
ordering, flushes, complete new-target readback, callback persistence and durable
HND checks remain. Legacy APIs and each independently opened recovery journal
continue to perform full journal validation. Formats, checksums and replay
authority do not change.

The public normal fast path and the V3 first-flushed-write fault path use this
same owner. Historical numeric/copy faults and full-content paths keep their
previous preparation and replay APIs. Preparation failures issue no owner;
post-intent failures still leave ordinary pinned recovery available, subject to
the existing HND/ABT boundary.

For the previously qualified `f2e5f73` normal plan, the eliminated duplicate load
reads:

| Component | Logical read bytes |
|---|---:|
| Immutable journal body, `J - 8192` | 11,436,099,200 |
| Resolved copy plus literal new payload | 5,702,057,984 |
| Total avoided | 17,138,157,184 |

The clear-marker and exact-old-target reads remain. This is code-path accounting
for that plan, not a measured physical-I/O reduction, wall-time result or HDD
forecast. Sealed `11e8963` subsequently passed one grown V3 normal case with
`prepared_journal_owner_reused: true`: native exit 0/HND in 280.7502894 seconds,
273 directories and all 811 independent stream hashes. Its actual plan removes
17,136,951,040 duplicate logical read bytes by this accounting. Process counters
and differing historical plans do not establish a controlled speed or physical
I/O gain. [Native scope and evidence](prepared-owner-native.md).

The `07b0164` recovery matrix belongs to its earlier sealed binaries. Fault,
recovery, arbitrary mutation and physical power-loss qualification remain
pending for this prepared-owner candidate. No unit tests were added or run.
