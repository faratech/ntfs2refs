# One-pass validated journal pin issuance

Normal fast conversion prepares a new share-zero journal under continuous
in-process ownership. Previously, preparation flushed the completed body, read
the entire immutable body to obtain its SHA-256, then read it again to validate
records, payloads and the footer.

The new exclusive preparation path computes that same immutable SHA-256 during
the complete validating readback. It still checks every stored body byte, exact
plan/length/descriptors, each old and new payload hash, source/candidate selected
digests, synthetic-zero semantics, resolved-copy hashes and footer. The ticket
is returned only after all checks succeed and both marker regions are clear.
An internal unissued digest is never serialized, printed or used as authority.

This removes one preliminary hash-only body read. It does not remove the
independent post-flush readback, a durability barrier, or a target check. Both
source and candidate readers must be unable to mutate the held journal.

The new issue mode is private. Existing preparation used by Full mode and fault
entries retains its original pin/readback sequence. Every recovery/consumer load
still compares the independently trusted immutable pin before resolving copy
references. Journal bytes, ticket values, marker formats and write ordering are
unchanged for the same inputs.

The historical larger-tree journal occupied 11,430,978,272 bytes. That shows the
scale of the redundant logical read; it is not a new elapsed-time or physical
disk-I/O measurement. The native run using this implementation is pending.

Focused library/CLI checks and public, bind, digest and fault-helper release
builds pass. Native qualification is pending. No unit tests were added or run.
