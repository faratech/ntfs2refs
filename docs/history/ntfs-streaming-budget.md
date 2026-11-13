# Explicit logical-stream transfer budget

The legacy alpha interfaces `copy_plain_stream`, `copy_plain_named_stream`,
`hash_plain_stream_range` and `read_plain_stream` keep their 256 MiB maximum.
The in-memory `read_plain_stream` remains bounded and cannot use a larger
budget. Their call sites and the frozen alpha profile have not changed.

`StreamTransferBudget::new(max_stream_bytes, max_total_bytes)` supplies an
explicit per-stream logical-size ceiling and a separate cumulative logical-byte
ceiling for `copy_plain_stream_with_budget`,
`copy_plain_named_stream_with_budget` and
`hash_plain_stream_range_with_budget`. The copy routine holds a fixed 64 KiB
payload buffer and writes to a caller-provided output; callers must select a
bounded or file-backed output for large streams. The existing raw boot/MFT,
attribute, mapping and complete-hash checks still run. A copy verifies the
entire logical stream hash, and a full-range hash checks it as well.

The budget reserves logical bytes before transfer. Repeated ranges, holes and
uninitialized ranges are charged; an error does not refund the reservation,
and callers must discard any partial output. The budget does not include boot,
MFT, attribute-list or other metadata rereads and does not bound physical disk
I/O, output filesystem overhead or whole-process memory. It is neither a source
certificate nor authorization to write a filesystem.

A generated sparse test image contains an ordinary stream of 256 MiB + 4 KiB,
with only a 2 MiB physical fixture in memory. It verifies complete bytes/hash,
the legacy refusal, <=64 KiB read/write chunks, cumulative logical reservations,
partial range accounting and rejection on budget exhaustion. A separate test
checks that a payload hash failure retains its reservation. These are Rust
source tests, not a native Windows conversion or ReFS acceptance result.

## Remaining integration gates

This primitive alone does not increase the public converter's support limits.
An explicitly versioned larger profile must coordinate, at minimum:

- `ntfs_admission::assess_source_view_profile`: the 128-file, 32-directory and
  256 MiB logical-content resource gate and its profile identity.
- `ntfs_stream_plan::classify`, `shadow_tree::derive_profile` and
  `ExpectedTree::validate`: stream classification, tree limits and stable
  profile serialization. Recovery must bind the exact profile.
- Native collection in `n2r-win32::attestation` and `logical_hash`: file-count,
  complete logical-read budget and two-pass accounting; reconciliation in
  `ntfs_data_attestation` currently requires the legacy budget exactly.
- `general_qualification` and `general_target_preservation`: construct and
  retain the new budget under the actual frozen source while preserving all
  current source and target admission checks.
- The shadow-construction, comparison and journal resource profiles, including
  actual backing allocation, changed bytes and available recovery storage.

The current 128 GiB image and native bitmap-profile limits are separate from
the stream transfer limit. No source-admission gate, native workload or recovery
format is widened by adding these APIs.
