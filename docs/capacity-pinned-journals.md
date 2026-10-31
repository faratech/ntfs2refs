# Capacity-pinned journals and capture storage

Profile 3 replaces the public allocation converter's fixed 16 GiB journal
ceiling with an explicit ceiling derived from available independent storage.
It does not remove the remaining file, range, geometry or literal-file limits.

The request pins separate journal, literal-backing and combined-scratch limits.
Journal and backing share the measured pool; zeros and copy references can
leave the nominal backing allowance unused without stranding that space.
The initial working reserve remains outside the pool. Literal backing retains
its separate held-file bound. Whole-image conversion keeps its old profile.
The fields are `max_journal_bytes`, `max_literal_backing_bytes` and
`max_combined_scratch_bytes`. For the public selected route, journal capacity
can use the complete pool, literal capacity is at most one third of that pool
and its held-file limit, and combined allocation must fit the same pool.
These are independent ceilings rather than reservations for disjoint slices.

During capture, `D` changed bytes and `L` literal bytes require at most
`D + L + metadata` journal bytes and `D + 2L + metadata` combined storage.
The existing 16 MiB metadata allowance covers the widest selected records.
Each prospective append is checked against all resource limits before writing.
Zero/copy runs also increase the future journal requirement and are checked.

The live guard verifies that backing and journal use the pinned storage volume.
It checks available space initially and at 4 MiB changed-byte intervals, tracks
its own intervening literal allocation conservatively, and refreshes immediately
when the cached estimate is insufficient. These observations remain advisory.
Exact encoded plan sizing and a fresh space check precede journal creation.
After the verified durable journal exists, another check requires only the
remaining working reserve, avoiding a second charge for existing allocations.

Profile 3's capacity is persisted in the journal binding inside the trusted
ticket and immutable manifest. Recovery derives it from pinned input, never
from current free space or observed file size. Selected recovery also requires
the plan's ceiling to equal the pinned request's ceiling. Source activation
still requires the original live source certificate and verified journal.

Historical schemas 1/2 omit the new fields and retain their existing bounds and
serialized form. Dense journal limits remain capacity/2; old-only bounds apply
to the separate zero/copy-aware selected path. Selected journal format numbers
and `N2RSEL01`/`N2RZERO1`/`N2RCPY01` encodings are unchanged. Fresh profile-3
capture is currently supported by the allocation-bounded backend only.

The checked NTFS reader now uses full typed equality instead of temporary JSON
serialization for geometry, attributes and assembly evidence. Owned parsed DATA
attributes move into sessions instead of cloning their run lists. Every raw
boot/MFT/physical extension-record reread and existing identity, mapping, VDL
and digest check remains.

The large `d974efe` run `98153ebb` / core `51e20d11` stopped before activation
with `selected journal exceeds caller budget`. It used the preserved NTFS
64 KiB-cluster source with 808 user files, 120 user directories and
9,885,781,381 logical user bytes. The admitted expectation contained 933
objects, including three additional System Volume Information files.
The 654-file count from earlier extent observations describes the whole-cluster
eligible subset, not a reduced source dataset.

Capture found 15,139,008,512 changed bytes, 3,784,351,744 literal backing bytes
and 5,659,336,704 copy-reference bytes in 4,126 encoded ranges. Old plus literal
new payload alone requires 18,923,360,256 journal bytes, already
1,743,491,072 bytes beyond the 16 GiB request ceiling before record metadata.
Backing plus that minimum journal requires 22,707,712,000 independent bytes.
The refusal therefore identifies a real caller-capacity limit; it does not
mean a journal of that minimum size was created or that space was reserved.

The independently constructed shadow completed 1,571 native moves: 50 deferred
moves to original coordinates, 644 to scratch, 867 evacuations and ten final
moves. Those moves covered 9,834,196,992 bytes. Its final retained-coordinate
candidate map contained 50 ranges / 478,236,672 bytes. These are shadow results
before conversion, not preserved extents of a completed ReFS source volume.
The sealed read-only host replayer verified all 3,142 destination-window
transcripts: 3,214 native queries had returned 13,164,544 bytes. The three full
phase bitmap snapshots and complete-file retrieval scope remained. The replay
performs no new native query, move or full retrieval-proof replay.

The admitted-source observation records disk attributes `3` (offline and
read-only), zero converter source-payload writes and `execution_authorized:
false`. No source activation, native ReFS finalization or successful conversion
is claimed. The 43 closed metadata files, their hashes and failure checkpoint
`ce9b92c2` are preserved separately. See
[the scoped refusal evidence](../evidence/mixed-capacity-refusal-20261031.json).

Candidate `d33d8ec` implements profile 3 and has sealed focused release builds.
This refusal and those build pins do not establish native profile-3 conversion,
recovery, mutation or power-loss qualification. No unit tests were added or run.

## Retention availability investigation

The larger capture is not explained by a smaller source tree. The old `156241e`
and current `d974efe` raw inventories have the same 960 file identities and
identical DATA mapping fields. Expected-tree projections match all 933 objects
across `156241e`, `9099110` and `d974efe` by source identity, type, logical
length/digest and physical source mapping.

Across all three runs, the first 1,561 move intents and their complete post-move
retrieval buffers match exactly: 50 deferred-original moves, 644 scratch moves
and 867 evacuations. Initial tracked ownership and the evacuation moves match;
one legacy phase-bitmap hash differs between formatter epochs. Divergence begins
in final placement: `156241e` placed 557 final moves and retained 3,084,886,016
bytes; `9099110` placed 504 and retained 2,888,302,592 bytes; `d974efe` placed ten
and retained 478,236,672 bytes. All ten current final move projections occur in
both older runs.

This is consistent with timing-sensitive ReFS free-space availability after
evacuation, including delayed reuse or checkpoint state. It does not prove that
quarantine caused the loss: the complete final-phase bitmap observations were
used live but their complete transcripts were not archived at that boundary.
Other target allocator-state differences and differences in planner behavior on
those unavailable final snapshots are not ruled out.

The inspected placement path takes its final full bitmap snapshot immediately
after evacuation without a volume flush at that boundary. A supported next
experiment is to flush the held independent shadow volume, then obtain fresh
complete observations under both selectors. Microsoft documents volume-handle
flushing and ReFS support for
[FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).
That API does not promise immediate ReFS block reclamation. The new observations
must remain authoritative: no bitmap bits may be cleared, predicted free or
replaced by a planned destination. A flush experiment is not established by
this refusal evidence.
