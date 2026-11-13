# Planning work and prefetch memory

This change reduces repeated computation in the native-shadow conversion path.
It keeps the complete per-move bitmap and retrieval queries, source freeze and
certificate checks, output ranges, and existing capacity refusals. It does not
implement the deferred D1/D2 query-scope decisions or remove the coupled scale
limits.

| Work | Previous cost | New cost |
|---|---|---|
| First-fit scratch span | Scan earlier undersized spans for each request | Maximum-length segment index, O(log free spans) per request, same lowest offset |
| Deferred hole/source intersections | Scan every desired run per hole | Seek first overlap, visit intersections only |
| Final retained-coordinate derivation | Desired runs times tracked mappings | Checked monotonic intersection sweep |
| Evacuation exclusion union | Concatenate then sort all four inputs | Merge the already validated sorted inputs |
| Retention occupancy | Merge overlapping views again per source run | Build exact union once per immutable phase |
| Payload route/source identity | Scan the raw inventory per route | Index identity and ambiguity once |
| In-place source extent matching | Scan every extent per route | Validate each immutable map once and seek the relevant suffix |
| Source prefetch schedule | One descriptor per 4 MiB of selected bytes | Generate the same chunks lazily from the selected ranges |

The scratch index is allocated before the phase and retains physical span
order. Its left-first search makes the same first-fit choice as the scan;
smaller unused spans remain available to later requests. Current interval
limits bound its additional storage to a few MiB. Allocation failure is a
pre-move refusal.

The inventory indexes retain duplicate identities and duplicate stream names
as explicit ambiguity. They do not choose the first match or recreate a live
source certificate. Indexed extent searches follow a complete ordering/bounds
check on the same immutable inventory. The prefetch worker retains its three
buffers, channel depth, independent read lane, range-relative chunk boundaries,
read order, and error handling.

Only temporary per-move coordinate rows that were unconditionally discarded
are removed. Final coordinate evidence still comes from live checked retrieval
mappings, including payload already correctly positioned before a move.

Runtime `08dd747` passed the same compressed/fragmented source through public
conversion `9f58c4cd` / core `09a6b41a`. All 44 objects, 30 default-stream hashes and 9
named-stream hashes passed native verification, alongside 3 sparse layouts,
7 EAs, 8 security-fixture identities and 6 reparse buffers. Four known reparse
routes resolve. The independent compression observer verified 7 SHA256 and 7
XXH3 hashes; 4 encoded streams materialized 2,687,224 logical bytes, and resident
compression-policy content contributed another 64 bytes. Encoded NTFS physical
bytes were not adopted and compression padding was not exposed as sparse data.

The archived placement records were compared directly with `a126b18`, using the
same saved NTFS source checkpoint `371ae756`. Every placement counter matches.
All 1,044 ordered move intents and complete post-move retrieval buffers match:
2 deferred moves to original coordinates, 20 to scratch, and 1,022 final moves.
Both runs submitted 4,276,224 bytes, captured 3 phase bitmap snapshots, and
reported no drift replan or evacuation. Every move retains successful mapping
and placement proofs and both full bitmap candidate proofs, each covering
13,631,488 clusters. All 1,024 final original-coordinate rows match exactly:
4 MiB of uncompressed payload remains at its source coordinates. Default logical
hashes keyed by canonical path also match between runs.

The two ReFS formatter epochs have distinct live filesystem state. Their raw
bitmap hashes are not interchangeable: all 1,044 legacy candidate hashes and 928
metadata candidate hashes differ. The comparison establishes identical move
decisions, complete post-move mappings and preservation outcomes; it does not
claim byte-identical formatted volumes or reuse either run's live evidence.

The new run took 114.7351736 seconds, versus 94.6856097 seconds for `a126b18`:
20.0495639 seconds longer, about 21.2%. This single-run comparison demonstrates
no wall-time speedup. Host conditions, cache state and formatter timing were
not controlled, and isolated planning CPU time and physical I/O were not
measured. The changes remove specific repeated computations and the
volume-sized prefetch descriptor list; their end-to-end speed benefit remains
unproven.

Actual storage was 88,965,568 journal bytes plus 6,643,712 backing bytes
(95,609,280 total), with 82,288,640 selected bytes in 259 ranges. The preceding
run used 89,071,680 journal bytes plus 6,701,056 backing bytes, with 82,337,792
selected bytes in 255 ranges. These small differences include independently
generated ReFS metadata; they are not attributed to the optimization.

The converted checkpoint is `228c7aa3`. Exact-build cold boot `3b76ebb8` passed
the native verifier and independent compression observer. All 44 canonical
file IDs and retrieval maps, 10 alias IDs, 30 default and 9 named hashes, and
all seven EAs match the normal run. The seven independent compression hashes
also match. The cold checkpoint is `863e9372`; this adds no new source-retention
comparison. No new interruption/recovery, mutation, physical-power-loss or
unrestricted-size qualification is claimed. Focused release builds pass;
no unit tests were added or run. Pinned artifacts and the complete comparison
scope are recorded in
[the native evidence](../evidence/planning-performance-native-20261031.json).
