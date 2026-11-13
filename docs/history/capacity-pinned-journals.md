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

The selected path persists profile 3's ceilings in the request and selected
plan. Its recovery bundle pins both alongside the ticket for the durable
journal. Recovery derives the native journal-file profile from that pinned
input, never from current free space or observed file size. Selected recovery
also requires the plan's ceiling to equal the request's ceiling. Source
activation still requires the original live source certificate and verified
journal.

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
[the scoped refusal evidence](../../evidence/mixed-capacity-refusal-20261031.json).

Candidate `d33d8ec` introduced profile 3. That refusal and its build pins alone
did not establish native conversion. The subsequent `fd577f2` observation below
records a completed conversion with the added retention barrier. No unit tests
were added or run.

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

At `d974efe`, placement took its final full bitmap snapshot immediately after
evacuation without a volume flush at that boundary. The proposed experiment was
to flush the held independent shadow volume, then obtain fresh complete
observations under both selectors. Microsoft documents volume-handle
flushing and ReFS support for
[FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).
That API does not promise immediate ReFS block reclamation. The new observations
must remain authoritative: no bitmap bits may be cleared, predicted free or
replaced by a planned destination. The refusal evidence alone did not establish
the experiment's result.

## Completed native capacity run

Runtime `fd577f2`, public run `17c1dd7f` / core `9a59ede9`, completed conversion
of the same independently populated NTFS partition through `--drive F
--partition 2`. Native ReFS verification passed 933 objects and all 811 default
stream hashes. The original label and `F:\` mount path were restored. The saved
converted checkpoint is `78513f35`. This is the full-content pipeline: the later
D3 fast-verification changes are not part of this sealed executable.
See [the native evidence](../../evidence/mixed-capacity-native-20261031.json).

The volume flush succeeded in 122,187 microseconds. Complete native bitmap
observations measured 75,542,528 desired free bytes before it and 3,822,333,952
after it. Their difference, 3,746,791,424 bytes, exactly equals the bytes
evacuated earlier. The first 1,561 move intents and complete post-move mappings
match the failed run. Source exclusion was checked on both sides of the barrier;
no bitmap bits were predicted or cleared by the converter.

Final placement then completed 863 moves, for 2,424 total. The resulting
retained-coordinate map contains 903 ranges / 4,225,028,096 bytes, disjoint from
all selected writes. Its gain over the failed run is exactly the measured free
space increase. This supports the barrier for this workload; it does not
establish a universal ReFS reclamation schedule.

The sealed read-only replayer verified 4,848 destination windows with 4,920
native queries / 20,152,320 returned bytes. Four complete phase-map snapshots
were recorded, including the additional pre-barrier observation. Complete-file
retrieval checks remain. Replay itself performs no native volume query, move
or full retrieval-proof replay.

The request pinned these independent ceilings:

| Ceiling | Bytes |
|---|---:|
| Journal | 29,697,802,240 |
| Literal backing | 9,899,266,048 |
| Combined backing and journal | 29,697,804,288 |

Capture recorded 2,599 advisory capacity observations on the pinned C: volume.
Before activation, the already allocated journal was present and 27,307,425,792
bytes remained available, exceeding the 1 GiB working reserve. Recovery does
not derive new limits from that free-space observation.

Actual literal backing fell to 38,400,000 bytes, compared with 3,784,351,744 in
the failed run. The journal was 11,430,978,272 bytes; combined backing and journal
used 11,469,378,272 bytes. Selected writes covered 11,392,262,144 bytes in 3,206
ranges. The journal ceiling exceeds the old 16 GiB limit, but this actual journal
is smaller than 16 GiB. This run therefore does not qualify journal I/O beyond
16 GiB, nor attribute completion solely to raising the ceiling. The flush also
changed retention and storage requirements materially.

Process-to-terminal time was 1,387.317 seconds, about 23.1 minutes. Coarse log
markers put journal preparation at 130–580 seconds and application at
580–1,058 seconds. The remaining approximately 329 seconds include journal
handoff and mounted verification; they are not an isolated file-hashing
measurement. This observation establishes no overall speedup or HDD estimate.

The closed archive contains 57 files / 136,316,706 bytes. General conversion
qualification remains false. Exact-build cold boot, interruption/resume/rollback,
mutation, physical power loss, larger journal I/O, unrestricted scale and the
newer D3 fast path require their own evidence.
