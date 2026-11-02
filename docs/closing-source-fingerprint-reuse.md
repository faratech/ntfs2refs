# Closing source fingerprint read reuse

Fast allocation capture now feeds its closing source fingerprint from the
actual old-source buffers before those buffers are recycled. Fingerprint bytes
outside that capture are still read through the same frozen source owner. A
fixed4MiB gap buffer and incremental digest state replace the separate closing
read pass; no payload cache or per-piece digest table is retained.

The canonical covered/omitted domain, raw-inspection pin, little-endian range
frames, per-range4MiB XXH3-128 pieces and final digest wrapping are unchanged.
Gap reads restore the underlying stream position. Every covered byte must be
consumed exactly once, and the final fingerprint must match before capture
proof or a source certificate can be released. Initial and post-native source
fingerprints, device/exclusion checks, native/zero brackets and recovery remain
unchanged. Full-content and whole-image paths keep their existing reads.

The optional `closing_source_fingerprint_reuse` report records actual reused
capture bytes, separately read bytes, total coverage and bounded scratch size.
It grants no authority and is emitted only after the fingerprint comparison.
Focused Windows builds and independent source review passed. No unit tests were
added or run. Native read savings remain unqualified until an actual run records
these counters; no physical I/O or speedup is inferred from source inspection.

Clean runtimef69614b subsequently passed the actual public conversion and all811
independent logical hashes/1084 objects. Its closing pass checked123539456 bytes:
113623040 came from actual old-source capture buffers and9916416 were separately
read gaps. The recorded gap buffer was4194304 bytes and the canonical fingerprint
matched before proof release. See [the native case](../evidence/cleanf696-public-native-20261102.json).
Native wall time was113.1028816 seconds including385 NTFS moves; this is one run,
not a controlled physical-I/O or speedup comparison. Journal plus literal storage
was186955512 bytes, excluding other shadow backing and lab evidence.
