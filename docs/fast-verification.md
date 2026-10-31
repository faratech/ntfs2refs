# Fast verification

The user selected extent-based fast verification as the default on 2026-10-31,
with full-content verification retained as an option. The policy is explicit in
new requests. Historical requests omit the field and retain full verification.
`--verify-full-content` and whole-image mode select the original full path.

The first implementation stage reduces redundant journal and temporary-shadow
reads. **Source and target file-content hashing remains enabled at this stage.**
Results record the requested policy separately from the actual full-file checks;
they must not claim retained payload was left unhashed.

Normal fast conversion validates the complete journal before using it, then
keeps exclusive mutable borrows of journal and target across apply and handoff.
Before activation it opens the primary PhysicalDrive route without
`FILE_SHARE_WRITE`, then positively requires a second writable open on that exact
route to fail with `ERROR_SHARING_VIOLATION` while the source remains offline and
read-only. The same held gate changes the disk to offline writable and remains
the journal writer through HND. Offline filesystem exclusion and ownership of
mutable aliases are still required; this gate does not claim global exclusion
of administrative or volume aliases. Activation refusals persist their native
events before returning.
All target checks, original write ordering, intent durability, source exclusion,
flushes and complete post-write target digest remain. The receipt callback gets
only the applied result, persists it, and cannot access either stream. With the
same exclusive ownership and no hidden aliases, the validated immutable journal
and post-apply target state remain valid; HND commits without redundant payload
reloads or scans. Callback failure leaves apply intent open and writes no HND.
Existing resume, rollback, lifecycle and separate handoff entry points retain
their complete validation. A saved policy flag is never fresh-apply authority.

The fast temporary-shadow bracket obtains two complete native metadata/layout
observations and requires identical allocation, identities and source-backed
routes. Its two raw-byte hashes omit only exact physical payload ranges that
the composite replaces with frozen source bytes. Metadata, reserved zeros,
unknown allocations and recorded raw inspection/anchor reads remain covered.
Any overlap or inconsistent route/coverage refuses the candidate. The hash
uses the distinct `source-backed-raw-consumption-v2` domain, partition length,
pinned exclusion map, chunk count, and every consumed `(offset, length,
SHA-256(actual chunk bytes))` frame. Every covered byte is read in both brackets.
An inner digest may be reused for an exact chunk length only after checking all
actual bytes are zero; this does not infer zero contents from allocation or
sparsity. Separate opening/closing counters record reads, observed zero bytes,
cache hits and bytes processed by the inner SHA-256. The outer digest is not
labeled a direct-byte, allocation-wide or whole-image hash.
Full-content wrappers retain the previous bracket and serialized shape.

Whole-buffer old/new comparisons now use slice equality before the original
per-byte mixed-state fallback. Every byte and interrupted mixed write remains
checked. No reads or recovery barriers are removed by this CPU fast path.

Advisory current-process I/O and CPU counters are recorded at phase boundaries
to identify remaining bulk work. These logical transfer counters are not
physical disk-traffic measurements and do not reserve storage or authorize I/O.

Pending work includes the complete hash-free retained-extent certificate path,
further source fingerprint/read-pass reduction, and native conversion/recovery
qualification of this new path. No unit tests added or run.
