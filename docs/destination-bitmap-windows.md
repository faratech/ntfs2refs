# Destination bitmap windows

On 2026-10-31 the user approved D1: per-move bitmap checks may cover the exact
destination under both selectors, with complete phase snapshots, complete file
retrieval/all-placement checks and final allocation validation retained. D2
incremental retrieval remains deferred.

The existing read-only probe on a 52 GiB ReFS 3.14 partition passed seven window
cases under both selectors. Ordinary windows returned 4,096 bytes compared with
2,097,184 bytes for a complete capture; the paginated case returned 12,288 bytes.
This was query-level evidence, not a conversion throughput or physical I/O
measurement. Its preserved report SHA-256 is
`d153f2b80dcad80b2cecba31ced9d59ecc8f56a5b9fe0c67dc462edfde67e0eb`.

The mover now requests the exact destination LCN/count and verifies the declared
cluster domain and zero allocation in both views before `FSCTL_MOVE_FILE`.
Occupied destinations keep the existing pre-submission drift refusal. Native
rounding is observed by the bounded collector; no rounding unit is assumed.
Complete phase captures, pre/post complete file retrieval, and checks of every
tracked placement remain in the native path.

Placement schema 2 identifies `destination-window-v1`, `full-volume` phase
maps and `complete-file-mapping` retrieval. It stores two separately typed
window proofs instead of full-map Candidates. A window hash never populates a
full-volume bitmap hash field. Predictions or serialized success flags cannot
authorize a fresh conversion.

`bitmap_window_transport` stores every request/response byte with decoded length
and SHA-256. It selects lossless packet RLE or raw hex, whichever is shorter.
Replay bounds all allocations and cumulative response bytes, checks decoded
hashes, then invokes the existing window-proof replay. Compression changes the
transport size, not the observed query scope.

The actual complete window transcripts are captured and included in the evidence
reservation before movement. The existing mapping/page/width allowances and
64 MiB placement-artifact cap remain. A reservation failure cannot submit that
move. Source exclusion is checked around guarded placement, including failures.

The read-only `lab-replay-placement-windows` helper can verify a pinned closed
placement report. It replays both selectors for every move and reports their
actual native query/returned-byte totals; it does not access a volume or create
source-write authority. No unit tests were added or run. Native D1 conversion
and its end-to-end performance remain pending for this candidate.
