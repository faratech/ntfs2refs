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

The streaming planner now returns a bounded partial batch when safe space runs
out, together with remaining blocked bytes. The constructor runs one retention
pass after that batch, then remeasures all live ownership/allocation state for
another batch only when evacuation and measured retention both made progress.
This reuses workspace released by retention instead of requiring room for the
entire overlap at once. A tree-wide evacuation-move budget and the existing
retention/evidence limits bound all batches. Every submitted move retains the
same fresh checks. No progress, native failure or a spent budget stops further
optimization; unknown execution completion still aborts construction.

The report retains each batch separately. Old profiles keep their previous
behavior. This source builds but has not executed natively. It still needs at
least some safe workspace outside the source candidates and can hit bounded
extent/evidence limits. The writer still initializes a complete payload copy
on the shadow. This is a placement improvement, not payload-independent scratch
or zero-copy qualification.

The next native case is prepared in `lab/Prepare-StreamingRetention8G.ps1`.
It first requires the eight old checkpoints and OFF rollback-passed branch,
then a 6 GiB storage allowance before creating an intent or touching the VM.
Only after those gates, it returns the owned VM to its original clean NTFS
baseline, checks all six original payloads, and appends 4 GiB of zeros normally
to the existing 4 GiB+1 file. It moves no source extent, creates no allocation
aging workload and reformats no disk. The new source manifest and OFF baseline
are saved under `retention8g`; original fixtures/evidence stay unchanged.

`Dispatch-StreamingV2Conversion.ps1 -Retention8G` binds that new baseline and
records its fixture root. Mounted readback selects only the original streaming
fixture or this exact new fixture scope. It cannot silently compare an 8 GiB
file against the old 4 GiB fixture. Preparation/dispatch have syntax checks only
and have not run. The current 224 GiB saved-lab cap lacks the requested 6 GiB
allowance; the proposed 232 GiB increase remains pending. The 64 GiB host-free
reserve and every old checkpoint remain protected.

Evacuation audit storage now has a 4 MiB tree-wide limit across batches. The
accounting includes vector capacity, mapping/page-proof strings, file IDs and
plan storage. It checks before another move and after measuring its result;
unexpected post-move growth aborts without retry or source writes. A depleted
global allowance stops the optional optimization while ordinary checked
retention continues. This is separate from the existing retention audit bound.

The native mutation verifier also explicitly binds root creation time and
attributes to the original source expectation before accepting the recorded
root runtime-time override. The workload receipt alone cannot authorize changes
to those immutable source fields. Existing native artifacts already matched
that predicate, but they do not qualify this later build. Release builds pass;
no unit tests or VM runs were started for these changes.
