# Fresh exclusive journal writes

The normal fast apply path now owns a private, nonserializable
`FreshExclusiveApply` for one operation. Its constructor authenticates the
complete journal and every payload/reference, requires clear completion and
intent markers, flushes the target and hashes every selected actual target
byte against the trusted old digest. The owner retains the target, journal,
plan, ticket and authenticated records until handoff. A Boolean or serialized
report cannot create it.

With the existing continuous no-mutable-alias contract, validated disjoint
destinations remain old until their sole write. New copy bytes come from saved
immutable journal payloads, never previously modified target data. Fresh writes
therefore read only their desired new bytes; synthetic zeros are filled. They
omit the per-span target and old-journal rereads. One 1 MiB buffer suffices.

The discovery granule is still written last, after the first target flush. A
second flush and complete exact-new target readback precede the receipt callback;
the final flush and durable HND write/readback remain. Callback/data/check errors
after a successful intent write leave that intent open. Marker-write failures
retain their existing torn-marker semantics.

Legacy apply, fault injection, resume and rollback still use the original
three-buffer old-or-new byte checks. Each independently opened journal still
undergoes complete validation. Formats, expected digests, marker values and
write-policy ceilings are unchanged.

The native gate denies other writers on the primary PhysicalDrive route and
keeps the filesystem offline. It does not establish global administrative or
volume-alias exclusion. Owning every mutable alias remains the caller's existing
obligation. Fresh writes no longer offer the immediate per-span detection of
some out-of-contract concurrent changes; complete old/new hashes are the target
checks for this exclusive path. They may also rewrite already-equal chunks,
bounded by one write of each selected byte. The normal changed-granule planner
already excludes equal granules.

Avoided reads are `2 * selected_bytes`: one target and one old-journal pass.
For the completed V3 plan this is 22,786,547,712 logical bytes. This is code-path
accounting, not a physical-I/O or elapsed-time measurement. Focused compilation
and independent code review passed. Native qualification is pending; this code
was not in the sealed f32 V3 case. No unit tests added or run.
