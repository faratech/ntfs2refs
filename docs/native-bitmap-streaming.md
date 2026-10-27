# Streaming native allocation observations

`n2r_win32::bitmap_streaming` reads actual `FSCTL_GET_VOLUME_BITMAP` pages without
assembling a volume-sized vector. It retains one previous payload window for
rounded-down overlap checks, one current response, incremental SHA-256 states
and a caller-bounded list of maximal allocated cluster ranges. Each payload
window is at most 1 MiB. Highly fragmented observations can exhaust the separate
interval budget and are refused rather than truncated.

Responses must match the next requested LCN and original query template. Their
domains must agree and match the expected clusters, allowing final-byte padding.
Repeated overlap bytes must match the previous window. Larger backward overlaps,
gaps, nonprogress, native errors, inconsistent completion, exhausted budgets and
failed page callbacks poison the collector. No partial summary is returned.

The summary records data and normalized-header-plus-data SHA-256 hashes,
expected/native-declared cluster counts, allocated/free counts, padding bits,
allocated cluster ranges, pages, returned bytes and a transcript SHA-256.
Normalized data includes the final byte's unused bits, matching the raw NTFS
bitmap hashing contract. The transcript frames each actual request length
(`u64`), request bytes, response length (`u64`), native error (`i32`, zero for
success), and full response bytes, in query order with little-endian integers.
The bitmap control code is fixed by the encoding. Full response headers and
unused returned tail bytes remain covered by this transcript.

`capture_general` surrounds the same held volume handle with actual GPT/volume
route checks, excluding the current Windows disk through the existing general
reader. It issues no locks, dismounts, disk setters or raw writes. An online scan
is not an immutable snapshot: allocations can change between pages without
changing the route. Neither this API nor deserializing a summary establishes
source admission or conversion authority.

The read-only `lab-stream-ntfs-bitmap` command takes a dedicated-disk binding and
its SHA-256 pin. Expected clusters come from the actual NTFS boot sector. It
writes a fresh bounded diagnostic report on C:, for example:

```powershell
lab-stream-ntfs-bitmap --binding C:\ntfs2refs\source-binding.json `
  --binding-sha256 $bindingPin --output C:\ntfs2refs\bitmap-observation.json
```

Defaults allow 64 GiB of logical bitmap data, 131,072 queries and 65,536 allocated
ranges. These are read/count budgets, not full-map memory allocation. CLI range
limits cannot exceed one million; encoded reports cannot exceed 128 MiB.
The experimental larger-tree source collector now uses this path under native
report schema 9. It retains actual first-query bytes and before/after streaming
summaries, with no continuation response vectors. Full bitmap-data hashes and
allocation counts must match the initialized frozen raw NTFS bitmap, and both
summaries (including transcript hashes) and first queries must agree. Structural
summary validation also replays the first page and checks its allocation prefix;
a single-page summary must reproduce the entire recorded response exactly.

This compact schema does not recreate missing raw page transcripts. Admission
still requires the opaque live observation issued by the protected source lease;
serialized summaries and matching hashes alone cannot create that capability.
Schema-8 reports retain their raw-page replay contract, and unprofiled/default
collection remains schema 7 with the existing raw-page path. Older schemas
reject streamed-summary fields. Larger clusters are accepted by native routing
only for the explicit experimental resource profile, with geometry still checked
against the frozen raw inventory. Target bitmap and recovery integration remain
separate work. The converter's 128 GiB partition limit is unchanged.

This code has compilation evidence only. No unit tests or native volume scan
were run. Existing native evidence retains its original bounds and executable
pins; a streaming summary does not replace its raw-page replay contracts.
