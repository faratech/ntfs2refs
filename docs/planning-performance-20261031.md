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

Focused release builds pass. No unit tests were added or run. Native conversion
on the same compressed/fragmented source is pending; no wall-time or physical
I/O improvement is claimed from complexity alone. The prior a126b18 run took
94.6856097 seconds on that fixture.
