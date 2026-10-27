# Shadow user-data evacuation

The native-shadow writer already creates correct files and can move their
extents to free original-source positions. A source position occupied by a
different shadow file or a different offset in the same shadow file prevents
that move. The streaming constructor now tries to vacate such measured user
allocations before its existing retention passes.

The interval planner consumes complete native legacy and metadata-inclusive
allocation maps and actual per-file retrieval mappings. It validates ordering,
alignment, bounds, allocation totals and exclusive physical/logical extent
ownership. It identifies only intersections between measured shadow user data
and eligible original-source destinations. Same-file/same-VCN placements are
left alone. Metadata-only reservations are not classified as user data or moved.
Destinations come from the complement of both allocated maps and every eligible
source interval. No volume-sized bitmap or per-cluster scan is assembled.
Large ranges split at the native DWORD cluster count, with bounded interval,
extent and move counts. The dense bitmap research planner is retained under
test-only compilation; no new unit tests were added or run.

The executor runs only on the separately bound mounted ReFS shadow during
`experimental_streaming_tree_v2` construction, after all payload initialization.
It retains live file handles, rejects zero/duplicate IDs and nonordinary/shared
files, and measures retrieval ownership. Before each FSCTL_MOVE_FILE it rechecks
the exact file ID/current source mapping, both complete occupancy views, and
disjointness from all original-source candidate ranges. Afterward it requires
the exact new mapping and unchanged identity. Native failure or incomplete
mapping aborts construction without retry; the NTFS source remains untouched.
The executor takes no source-device handle and performs no raw writes.

The native report records planned moves, measured mapping hashes/page proofs,
live bitmap hashes and completed bytes. Unsupported planning budgets or lack of
safe evacuation space are recorded as a no-submission reason before any move,
then the existing retention/relocation path continues. Corrupt identities/maps
and execution failures are not converted into that optional planning outcome.
Final file-content, metadata, allocator, protected-target and whole-image
validation, journal capacity and recovery barriers remain mandatory.

The public converter/binder/recovery release build passes. No native result is
claimed for this implementation. Existing eight VM checkpoints and prior
qualified binaries remain untouched. In particular, the successful 4 GiB-zero
case and its recovery run did not execute this feature.

Remaining limits are material: a one-shot evacuation needs safe space outside
all source candidates; a densely populated layout may not have enough. Bounded
batch evacuation and retention interleaving are not implemented yet. The writer
also still initializes a complete payload copy on the shadow. This is a placement
improvement, not payload-independent scratch or zero-copy qualification.
