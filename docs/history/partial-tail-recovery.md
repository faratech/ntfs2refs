# Partial-tail recovery qualification

Sealed runtime `3ce15c7` passed a controlled interruption after its first flushed
target write, followed by public Resume and a separate Rollback from the same
saved interrupted checkpoint. Its 14 extent-only streams include 12 partial
streams with 457 actually materialized tail bytes. The original bundle pins all
53 object/stream map bindings; the missing initial content digests stay absent.

The actual producer PID/creation identity exited 86. Source disk 6 remained
offline writable and the managed shadow remained offline/read-only. Its lab
observer then failed because an ordinary JSON reader retained a 4 MiB limit.
The original failure and closed records are preserved separately. A function-only
read-only completion, using the corrected 64 MiB metadata bound, verified all
12 constructor/source/destination/protected-residual bindings and the native
bundle. The normal wrapper control receipt remains absent. Recovery explicitly
records the labelled completion and its checksum; no producer was rerun and no
bundle, content digest or source authority was synthesized.

Resume observed `apply_intent`, completed ReFS and closed HND. Native recovery
fully hashed the 25 streams with known digests (64,574,222 bytes), checked all
14 unknown streams through the pinned complete maps, and reported the 12 tails
and 457 bytes explicitly. All 30 default and 9 named independent lab hashes
matched. The Resume observer passed directly.

Rollback restored the exact same saved interruption, then completed NTFS and
closed ABT. Its 82,034,688 selected bytes across 246 ranges matched the original
old-selected checksum. H: had its original label and 4 KiB geometry. All 39
independent hashes matched: seven streams in the NTFS compression-normalized
file group used ordinary logical reads and the other 32 used the pinned backup reader. The observer passed
directly. No completed HND or ABT was replayed.

The old full-content baseline remains lab-only. Current frozen-source and Resume
target metadata reconciliation is recorded without changing product expectations
or filesystem times. Rollback relies on the closed old-selected-byte proof;
there is no independent post-rollback timestamp claim.

The preserved checkpoints are interrupted `119445de`, resumed ReFS `64304900`
and restored NTFS `fcc42f45`, alongside qualified normal `3cbc9ae0`. Their closed
archives contain 71, 35 and 37 metadata files respectively; every copied byte
length and SHA-256 was checked. The original failed observer archive has a
separate 70-file inventory. The VM is normally stopped at the restored NTFS
checkpoint with 50 checkpoints. Three obsolete leaves were removed through
Hyper-V only after their retained archives were revalidated; all host baseline
and metadata files remain.

This covers one controlled exit 86 plus clean restart. It does not qualify other
interruption points, physical power loss, F-scale, or later mutation. The newer
`18bdea8` journal-preparation optimization was not used. No unit tests were added
or run. [Evidence and artifact pins](../../evidence/partial-tail-recovery-matrix-20261031.json).
