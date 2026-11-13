# Streaming metadata and borrowed stream maps

Qualification artifact saves now use a bounded counting/hash sink before opening
the destination, followed by a 64 KiB buffered streaming write. The exact byte
count and SHA-256 must agree before the file is synchronized and its pin returned.
The existing pretty-JSON encoding, artifact ceiling, exclusive `create_new`
ownership and error behavior remain. Oversize output still refuses before the
destination is created. Canonical source-inspection hashing also streams compact
JSON instead of allocating another complete serialized inventory.

Fresh fast verification serializes its recovery manifest by borrowing the
canonical ordered map. It does not clone paths, alternate stream names, retrieval
maps, integrity buffers or sparse layouts into a second manifest. Recovery moves
the parsed bindings into its canonical lookup table and retains only a scalar
manifest header. Mounted verification compares borrowed map views using a sorted
reference/seen index, retaining duplicate detection and exact complete-set checks.

This removes an artifact-sized buffer of up to 64 MiB per save, the inspection
serialization buffer, and several variable-sized map copies. The mounted index
still uses approximately 24 bytes per binding on the current 64-bit target.
These are source-accounted allocation reductions, not measured peak-RAM results.

The tradeoff is CPU work: artifact saves serialize and hash twice to preserve the
pre-create size decision and check the actual written bytes. The recovery-manifest
export also retains its separate bounded size pass. No additional source, shadow
or journal reads are introduced. No schemas, count ceilings, byte ceilings,
source-admission requirements or recovery authority rules are changed.

Focused Windows compilation and independent source review passed. No unit tests
were added or run. Native runtime qualification remains separate. This change
reduces memory duplication; complete paged evidence and resource-based scale
remain open in [the scaling plan](scaling-budget-gaps.md).

Selected conversion and recovery now share `selected_artifacts::Artifact` limits
for every pinned input. Plan, expectation and payload-map artifacts retain the
writer's existing 64 MiB ceiling; recovery opening and copying use that same
ceiling. Previously plan/expectation opening and all input copying had a separate
16 MiB limit, so a saved conversion artifact could be refused by recovery.
Request, ticket, bundle and verification saves now enforce their existing reader
ceilings before activation. Input copies retain their original bytes and pins;
the recovery bundle's historical `bundle.json` copy name is unchanged.

This closes a size-contract mismatch before larger-count work. It does not lift
object, stream, extent or selected-range limits, add paging, or establish native
qualification for large artifacts. Focused compilation passed; no unit tests ran.

Fresh payload verification now shares the original immutable native observation
through `Arc<Report>` and retains a sorted numeric stream index. Its manifest and
mounted comparisons borrow the original path and map buffers. The existing
mutable backing-file revalidation stays in place. The report's residual-read
constructor requires unique ownership before its existing reads and audit
updates; sharing observation facts grants no handle or write authority.

Selected recovery also releases the raw serialized input buffers once parsing
and original-byte copies finish, before opening the journal or target. The same
input handles, identities, timestamps, SHA pins and subsequent full rehashes stay
held. Legacy compact finalization retains the expectation buffer it still needs.
These changes remove further duplicate storage without additional device reads.
Focused compilation and independent source review passed; native peak-RAM
measurements and complete paged evidence remain separate work.

Verification now also streams the exact pretty expected-tree and compact
plan/ticket hash bytes. The two native extent-verification paths borrow the
canonical expected objects instead of cloning a second semantic tree. This
changes no serialized pins or checks and adds no device reads. Focused locked
compilation of the public converter and both native conversion/marker tools
passed at commit 378860e; native qualification of that revision is pending.
