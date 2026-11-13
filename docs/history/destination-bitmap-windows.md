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
passed on runtime `d974efe` through public conversion `fea0a1ec` / core
`eb9a8205`. See [the pinned native evidence](../../evidence/destination-window-native-20261031.json).

The same saved NTFS source checkpoint used for the preceding full-map run
contained the combined compression, fragmentation, ADS, hard-link, sparse, EA,
security and reparse fixtures. Native verification passed all 44 objects,
30 default and nine named stream hashes, three sparse layouts, seven EAs,
eight security-fixture identities and six reparse buffers. The independent
compression observer again verified seven SHA256/XXH3 stream hashes and target
compression normalization.

All 1,044 ordered move intents and complete post-move retrieval buffers match
the preceding `08dd747` run exactly. This includes two deferred moves to original
coordinates, 20 to scratch and 1,022 final moves, totaling 4,276,224 bytes. Both
runs captured three complete phase snapshots, with no drift replan or
evacuation. All 1,024 final retained-coordinate rows match: 4 MiB of the original
uncompressed payload remains at its source positions. The sparse-carrier and
named-stream slot maps also match. A legacy phase-bitmap hash differs between
the independent formatter epochs; the new run uses its own live evidence.

The new per-move records contain 2,088 destination windows, each requesting one
cluster. Their 2,088 actual native queries returned 4,096 bytes each, totaling
8,552,448 bytes. Both selectors reported the exact 13,631,488-cluster volume
domain and zero allocated destination bits. Every response carried
`ERROR_MORE_DATA`, because more of the volume existed beyond the returned page;
each requested destination window was nevertheless complete. All transcripts
passed the separately sealed read-only replay helper. That helper performs no
native volume query or movement and does not replay the full retrieval proofs;
native move verification and the separate exact-buffer comparison establish
the recorded retrieval result.

Native process-to-terminal time was 32.852 seconds, compared with 114.735 seconds
for the preceding full-map build on this source: about 71.4% shorter, or
3.49 times the observed throughput. This is one run per build, with uncontrolled
host/cache/formatter conditions. It establishes a scoped wall-time improvement,
not a physical I/O measurement, a guaranteed speedup or a 1 TB HDD estimate.
The old Candidate records do not retain per-move native returned-byte totals,
so they are not used to manufacture a matching native-byte baseline.

Retaining every window transcript increased the closed placement report from
58,465,159 to 62,144,751 bytes. Operational counters remain identical; the three
evidence-size/reservation counters change with the new proof representation.
The actual pre-I/O reservation and the unchanged 64 MiB artifact ceiling passed.
The recovery journal was 88,751,616 bytes and packed backing was 6,541,312 bytes;
82,178,048 target bytes were selected in 249 ranges. Fresh ReFS metadata differs
between runs, so these storage changes are not attributed to D1.

Exact-build cold boot `c7fd1596` passed the native verifier and independent
compression observer. All 44 canonical IDs and retrieval maps, ten alias IDs,
30 default and nine named stream hashes, and seven EAs on four identities match
the completed conversion. The seven independent compression hashes and ordinary
target compression state also pass. Checkpoint `d939f576` preserves this branch.
This readback inherits the normal conversion's retention proof; it adds no new
comparison with the original NTFS source extents.

Interruption/recovery, mutation, physical power loss and larger per-move windows
remain separate qualification work. The existing fixed
resource and geometry limits remain; this result does not establish unrestricted
volume size or maximum NTFS compatibility.
