# Resource-based source and metadata admission
## Actual restart recovery and next performance run — 2026-11-03

Corrected reader `a0b29e0` completed genuine public rollback and resume on
separate restarts from the same authenticated original AP checkpoint. The
producer was `acbcc1b`; this is not fresh guard qualification. Rollback returned
NTFS in 462.84s; resume returned healthy ReFS in 935.26s with 2558 verified
metadata/map bindings. All811 original XXH3 stream hashes matched independently
in both directions. The additional1024 directory paths were captured on restored
NTFS and matched exactly on resumed ReFS. See the exact
[rollback](../evidence/resource-v4-restart-rollback-20261103.json) and
[resume](../evidence/resource-v4-restart-resume-20261103.json) records.

The frozen a0b public `--minimize-scratch` command is now running on a fresh
NTFS branch. Its result, storage savings and performance remain pending.
The verified HND branch and original partial-write origin remain saved.
No new code changes or unit tests accompany this performance run.

## First completed public V4 conversion — 2026-11-03

The same closed ReFS branch subsequently passed a normal shutdown/cold start
without restoring a snapshot. A separate, pinned XXH3-128 tool read all811
original streams (9,885,801,949 logical bytes), and every baseline hash matched.
The original1534 names, types and lengths also matched. The1024 added directories
were covered by the conversion-time2558 bindings but were not independently
re-enumerated after boot. This does not establish mutation or interrupted V4
recovery. See [the cold-boot record](../evidence/public-resource-coldboot-content-20261103.json).

The public `ntfs2refs --drive F --partition 2` command from exact experimental
source `5a8b781728726fec5e0f9351fa3b61c8633a7e19` completed with observed native
exit0 in2588.635 seconds. Its independently populated source had2585 raw
identities and2558 user objects:811 files and1747 directories. Native protected
verification matched2558 metadata/map bindings,157 known-content stream hashes
and654 extent-only streams. Windows reported healthy ReFS, the original label
and mount paths were preserved, and the actual journal closed HND. See
[the exact native record](../evidence/public-resource-first-conversion-20261103.json).

Together these establish the first full public V4 conversion and the separate
cold-remount/original811-stream verification above. Mutation, interrupted
restart recovery and useful large-volume performance remain open. Its last live process sample already
reported497.1GB of logical read transfers; final process and physical I/O totals
were not observed. The journal was5,821,929,848 bytes. Actual peak RAM and total
peak scratch are unmeasured. Subsequent placement, cancellation, journal-scan
reuse and online-terminal reconciliation edits require their own build and
native qualification. The frozen `7feb4c0` alpha remains unchanged.

The combined six-entry Windows `cargo check` passed after the later integration
changes (17.66 seconds; no unit tests). Placement evidence now stores complete
logical proofs across bounded chunk records, reserving their full encoded data,
directory and framing storage before each native move. Its native reservation
covers the complete accepted retrieval domain, including after-map growth.
Closing the sink refuses an unsettled move reservation.

Restart recovery now has an already-online terminal route. It authenticates the
actual original journal and physical partition, never replays old bytes over an
operational HND/ABT volume, and reports incomplete label/mount reconciliation or
unverified current contents explicitly. A same-owner prepared-journal receipt
also removes four repeated full scans after the initial authenticated index;
the native activation boundary still hashes the journal body before and after
source verification. None of these later changes has native qualification yet.
Existing event records now include advisory elapsed/process-I/O samples, without
adding a data pass or treating those counters as execution authority.

The public already-online recovery command then passed on exact source`03868c1`.
After a real cold boot and33 new-file mutations including grow/truncate/rename/
delete, native recovery observed actual HND and reconciled the online ReFS
volume without raw replay or stale selected-byte comparison. All33 new file
lengths and hashes remained unchanged. Native exit0 took133.685 seconds;
observer-close process transfers were36.76GB read, not physical storage traffic.
Interrupted V4 resume/rollback, missing-path repair and ABT still require their
own cases. See [the exact recovery result](../evidence/resource-online-terminal-recovery-20261103.json).

The first public already-online recovery attempt on built source`a9f3436`
refused before journal opening because output discovery used the source-only
Windows-disk exclusion for the legitimate C: journal. The converted source
remained online ReFS. The follow-up uses a typed journal-only read-only query,
bracketing mount enumeration with complete `Role::Journal` discoveries. Source
and shadow exclusions remain unchanged. Its focused Windows check passed in
10.73 seconds; the pinned native success above resolves this route refusal. See
[the original refusal](../evidence/resource-recovery-os-journal-refusal-20261103.json).

The diagnostic now has an opt-in `--apply-and-verify
--interrupt-after-first-flushed-write` case. It preallocates a share-zero signal
and bounded buffers on the independent journal volume before preparation. Only
an actual native write followed by flush, exact readback, actual AP/offline
checks and another still-different selected granule produces the durable signal
and a real error exit. The public path supplies no callback and adds no flush or
read. Its three-entry Windows check passed11.19 seconds; native interruption
and restart qualification is pending. Signal data is evidence, never replay or
fresh-source authority.

The first enrolled interruption attempt on source`96f9587` stopped before its
first placement submission:942,034,628 leased bytes plus3,087,768 registry bytes
could not admit a571,816,544-byte workspace under the same1,456,427,008-byte RAM
budget. The source stayed offline/read-only and the preallocated signal remained
all zero. Exit1 is therefore a preparation refusal, not successful fault
injection. See [the recorded refusal](../evidence/resource-first-write-placement-refusal-20261103.json).

The follow-up removes an unused full-serialization-buffer allowance from the
streamed resource placement path, preserving both actual JSON values and the
unchanged query/window/proof bounds. Metadata page readers and their paired
leases are also being sized to the actual held immutable file instead of
allocating full page buffers for every tiny table. The admitted RAM budget is
unchanged; a new native run must establish the result.

The paired reader/cache fix compiled in8.89 seconds. It validates the actual
held ordinary file and EOF before allocation, pays constructor key-comparison
workspace separately, then retains only the actual body and two possible
decoded chunks. Borrowed record access avoids an extra encoded-payload copy.
Full file/page hashes, record bounds, counts and same-file checks remain. The
placement change removes91,026,944 declared bytes for this fixture; this is
code-derived quota arithmetic, not a heap or conversion-speed measurement.

The next enrolled interruption attempt, source`a7befe8`, passed the earlier
placement reservation but stopped during native journal preparation after
835.252 seconds. Its actual exit1, offline/read-only source and zero-filled
first-write signal establish a pre-AP refusal, not a partial conversion. A
separate ordinary-file probe on the same journal volume reproduced temporary
NTFS allocation of5,820,645,376 bytes for a5,818,630,248-byte file while open;
allocation fell to5,818,634,240 bytes on last close. Preallocating the new file
through its same held handle kept allocation at5,818,634,240 bytes throughout,
within the existing quota. The compiled correction reserves quota before
preallocation, retains zero EOF and checks actual identity/allocation before
streaming. It changes neither the quota nor marker-storage formats. The
original journal was untouched by the probe. See
[the refusal and probe](../evidence/resource-first-write-journal-refusal-20261103.json).

The corrected pinned`acbcc1b` diagnostic subsequently completed resource
preparation and reached its real fresh writer under the unchanged1,456,427,008
byte RAM budget. It intentionally exited1 after writing4,096 bytes at partition
offset4,096, flushing and matching exact readback. The native byte counter moved
from0 to4,096; source attributes1 and actual`N2RSAP01` were observed, while the
selected primary granule at offset0 still differed from NEW. This was reserved
or boot metadata, not copied user payload. The original AP state was saved Off
at checkpoint`a51e134b-9c2f-4de6-9794-37e8d664b79a` after normal shutdown, then
booted for actual public recovery. Resume and independent Rollback remain
unproven; no physical power loss was exercised. See
[the closed first-write evidence](../evidence/resource-first-flushed-write-20261103.json).

The first actual restarted public Resume on acbcc then failed after90.833
seconds with`artifact changed before retirement`, while preparing recovery
records. Its native exit1 is terminal and source remains offline with
attributes1. The actual failure path is reopened-index retirement before the
public replay method. AP prefix and the original written4KiB hash matched after
failure; a full unchanged-target claim is not made. A separate ordinary-file
probe reproduced allocation trimming from278,528 to270,336 bytes when the last
duplicate of the creator's writable file object closed. Fully closing the
writer before reopening readonly produced stable final metadata. The SDK
ordering fix at`a0b29e04dd2e83086823349724e7e2a8ccf905f5` preserves complete index
checks and strict retirement and compiled in10.07 seconds. Its pinned build is
complete; separate Resume remains pending. The saved AP
origin remains protected. See [the refusal and probes](../evidence/resource-restart-retirement-refusal-20261103.json).

The corrected a0b public command then completed actual Rollback after restart
from the original first-metadata-write AP checkpoint. Native exit0 took462.837
seconds; ABT closed before writable original NTFS returned. Restore-required
selected bytes across8,399 ranges/11,403,739,136 scoped bytes and F: were verified;
free-space contents were not restored byte-for-byte. An independent observer
matched all811 original XXH3 streams/9,885,801,949 bytes and1,534 baseline
path/type/length objects. It captured and rechecked1,024 additional directory
names on NTFS for subsequent comparison; this did not independently audit all
ACLs/times or prove absence of extra objects. See
[the rollback record](../evidence/resource-v4-restart-rollback-20261103.json).
This qualifies the old acbcc producer with the new a0b recovery reader, not
fresh a0b preparation/guard behavior, copied-user-payload interruption, Resume,
or physical power loss. The closed ABT branch must never be replayed.

After restoring the original AP origin, a separate corrected a0b public Resume
is running. The last actual poll at20:06:43.712Z matched native PID1432 and
creation1793735658561 ms, task Running and source attributes3 during protected
observation/verification. No HND, exit0 or completed recovery is asserted.
Independent ReFS content/namespace comparison must wait for actual termination;
the successful Rollback observation is not substituted for Resume evidence.

Resource-native NTFS prealignment now has an online paged inventory, complete
stream decision/move planner, checked SDK mover/shadow-hint interfaces and a
streamed execution/receipt layer. The current public `--minimize-scratch` hook
runs this prepass before final freeze, reserves receipt space before each
NTFS-owned move and stops conversion on an incomplete result. It drops prepass
owners, samples resources again and obtains fresh frozen source admission;
prepass reports never authorize conversion. The combined three-entry Windows
initial check passed in9.98 seconds. The acbcc interruption diagnostic does not
exercise the public prealignment flag. Later source`aa6e01d` supplies a separate
metadata-only placement inventory, compiled in43.02 seconds; that change is not
in the acbcc native binary. Public native prealignment qualification remains.

Source`6fea7578d132aaec036ecd0482d20a0653afbed3` adds the actual cancellation-only
durable preparation guard. Its intent is pinned before freeze, the post-lock
boot witness is persisted before exclusion, and final-publication delegation
precedes AP. New final recovery also binds that guard; only actual
PreparedClear/OLD-proved abandonment can finish a valid split delegation toward
the exact publication. Closed cancellation records cannot clear later disk
exclusions. Existing ordinary-failure full-hash checks remain. The combined
Windows check passed in24.85 seconds, with no unit tests. Its pinned experimental
build completed with manifest SHA`411218f5538127cb25b0788a611646ea8177e7a0807249c0be890f25ccf253bc`.
It has no native guard/recovery qualification, excludes the later last-close
ordering fix, and does not inherit the separate acbcc first-write result.

## Experimental integration checkpoint — 2026-11-03

The compiled V4 core now connects held source/target/resource admission to a
one-shot paged writer, markerless apply and handoff, authenticated restart
resume/rollback/clear abandonment, and protected native metadata/known-content
and saved-map verification before writable access. The source's diagnostic
report flags are not activation authority. The exact experimental source
snapshot is `f469d146e530cb471060e1cbdea22127a7baaebd`; its release build used
the shared experimental cache and does not establish reproducibility or native
qualification.

The subsequent public integration is connected in source snapshot
`5a1eea1714ee06ae840a2dc4996286209589f7a3`: default allocation-bounded `--drive`
uses the resource-profile preparation/apply/recovery/finalization chain.
Its actual 52 GiB public-command run reached capture, refused an oversized
checked-MFT working reservation before publication/AP, and restored unchanged
NTFS online through the live cancellation gate. The earlier volume-root
refusal and this cleanup result are recorded in
`evidence/public-resource-volume-root-refusal-20261103.json` and
`evidence/public-resource-mft-memory-restoration-20261103.json`.
This is compiled experimental integration and safe-refusal evidence; it is not
a completed V4 conversion or general release qualification.

The earlier core-only native attempt stopped before source writes while
preparing target intervals. Its actual input count exposed an eager RAM/8 sort
reservation; the snapshot replaces that batch sizing with actual domain hints
and preserves complete spill/merge processing. Full V4 conversion, reboot
recovery, hardware coverage and the final release matrix remain required.

This development path replaces fixture cardinality limits with complete,
page-backed metadata and an explicit RAM/scratch budget. It does not establish
general conversion qualification or inherit native results from `7feb4c0`.
The previously qualified native-shadow candidate remains preserved separately.

The implementation-history paragraphs below retain their recorded revision
scope; their older integration-pending statements do not supersede the current
checkpoint above.

`ResourceBoundedV4` binds the actual source pin and complete MFT, object and
stream counts to observed resources. Its pre-count state cannot authorize native
construction. The frozen owner accepts an explicit `ResourceBudget` before raw
inspection and retains that exact budget through native observation.

The active source producer streams canonical MFT rows, allocated-record and
extension evidence, directory entries, security records, and physical/logical
allocation ownership. External sorting and authenticated temporary-file
retirement bound working RAM and merge scratch. It returns its opaque owner
only after complete allocated-record, extension, namespace, security and bitmap
conservation checks close. A saved source manifest cannot recreate that owner.

Native request schemas 7/8 stream actual selectors from that source owner.
Report schemas 15/16 retain those selectors alongside complete native rows.
The observer preserves both complete stream maps and directory passes, both
allocation snapshots, protection/route checks, logical EOF or extent evidence,
security views, and source identity. Comparison results are streamed per object.
Recognized NTFS internals retain their individual results and explicit
replacement obligations; diagnostic success grants no conversion certificate.

The new owning-machine integration entry is:

```powershell
lab-observe-resource-source --binding source-binding.json `
  --binding-sha256 <pin> --output C:\independent-scratch\fresh-run `
  --acknowledge-resource-source-freeze --native
```

It freezes the explicitly bound dedicated data disk and leaves it offline and
read-only. It performs no conversion or payload writes. Its default metadata
budget uses half of sampled available RAM and one eighth of sampled scratch
availability; explicit resource shares are checked against the same actual
sample. Allocation and I/O failures remain errors. Fast verification preserves
absent content digests as absent; `--verify-full-content` reads every supported
logical stream. Resource observations reserve no memory or storage.

The paged expected-tree and native constructor interfaces also accept the
resource profile and require actual page ownership. Their source projection,
fresh conversion admission, full public orchestration and recovery integration
must be completed before the public command selects this profile by default.
Legacy schemas, entry points and their historical limits remain available for
existing recovery and qualification evidence.

On the same saved 2,585-record source, raw/native observation completed in
641.207 seconds before and 51.209 seconds after the page-cache changes; both
matched all 2,558 user objects and recorded the same raw-reader byte count.
The host cache was not controlled. These are source-inspection observations,
not a full-conversion benchmark. See the [record](../evidence/resource-paged-cache-comparison-20261103.json).

Geometry and feature support remain explicit: the active raw namespace/security
walker still interprets 512-byte NTFS sectors and 4 KiB index records. Dedicated
GPT basic data disks remain required by whole-disk exclusion; a data partition
on an OS disk needs a partition-scoped exclusion design. Unsupported encodings
are refused. These implementation boundaries are not removed by deleting size
checks. The host lab's original additional-storage allowance remains unchanged.

## Native source-evidence observation (2026-11-03)

The source-only observer built from `68ef19e` completed against the saved
2,558-object NTFS fixture. Its source evidence checks passed for 2,585 raw
identities and the expected-tree projection contains 2,558 user objects. The
observer reported zero unresolved source blockers; its source disk remained
offline and read-only at completion. The closed evidence archive and binary
are pinned in [the observation record](../evidence/resource-live-source-evidence-20261103.json).

This was not a conversion or recovery run. Shared artifact ownership,
target security/timestamp preservation, and target resource-profile support
remain incomplete; no source admission or execution authority was issued.

The subsequent [shared-arena observation](../evidence/resource-source-arena-20261103.json)
passed against the same fixture with both source and native groups sealed and
no unresolved source blockers. The first attempt safely refused a verbatim
Windows path during source inspection; the corrected observer retains the
ordinary path while verifying the canonical parent and held volume identity.
The source was offline and read-only at completion. Target and cross-stage
arena obligations still prevent admission or execution.

The first end-to-end resource diagnostic passed the source and fixture
allocation checks, then refused during expected-tree projection because the
shared RAM budget was exhausted. It did not populate the shadow or activate
the source. The [refusal record](../evidence/resource-fixture-ram-refusal-20261103.json)
preserves the actual process result and evidence archive pins. The next change
reduces initial external-sort reservations while retaining bounded spill;
it is not yet qualified by a completed native conversion.

With count-hinted sort batches, the next diagnostic built the complete
2,558-object expected tree. It then refused before shadow population because
the newly formatted shadow's label differed from the native constructor's
required label. The [record](../evidence/resource-fixture-shadow-label-refusal-20261103.json)
contains the actual exit and archive pins. The reported 308,727,808 bytes of
private commit was a single pre-shadow observation, not a peak measurement.

After releasing the projection workspace, the next diagnostic reached
allocation and placement on the disposable ReFS shadow. It then refused before
copying source payload because the materialization plan exceeded its 2 GiB
budget. The plan did not report the required amount, so the next step is to
measure and explain that amount before raising the limit. The source stayed
offline and read-only. See the [record](../evidence/resource-fixture-materialization-refusal-20261103.json).

An instrumented repeat measured 4,225,110,016 source-reference bytes and
5,660,671,365 bytes classified for shadow materialization, after
13,581,152,256 bytes of shadow moves. The move count does not represent source
payload writes. The [measurement](../evidence/resource-fixture-placement-measurement-20261103.json)
is a diagnostic refusal, not a completed conversion. A proof-bound routed
prefix path is being developed to avoid first copying eligible relocated data
into the shadow; its later target/journal I/O still needs measurement.

The first routed diagnostic completed placement but refused during routed
preparation when its source-metadata RAM ledger was exhausted. The source
remained offline and read-only; capture and conversion did not complete. The
[refusal record](../evidence/resource-fixture-routed-ram-refusal-20261103.json)
preserves the native exit and evidence pins. The current work reduces
overlapping per-stream reservations while keeping the shared RAM limit.

After reordering shadow placement, a later diagnostic submitted 10,813,014,016
shadow-move bytes, 2,768,138,240 fewer than the earlier 13,581,152,256-byte
run, while retaining the same 4,225,110,016 bytes at original coordinates.
It then refused during routed-prefix verification on a reported hole. The
error did not identify the hole's location, so it is not yet known whether it
was inside the required prefix or in a trailing suffix. The source remained
offline/read-only; no conversion completed. See the
[measurement](../evidence/resource-fixture-prefix-hole-refusal-20261103.json).

After the prefix-scope correction, the next diagnostic progressed further but
refused an MFT workspace reservation: its actual shared-ledger commitments
would have exceeded the 1,456,427,008-byte limit by 4,515,605 bytes. The
[record](../evidence/resource-fixture-arena-ram-refusal-20261103.json) retains
the native result. The correction targets the lifetime of existing buffers;
it does not increase the configured RAM budget.

A later native diagnostic completed its routed-supply stage: 5,659,201,536
relocated bytes were routed, 4,225,110,016 bytes remained at original
coordinates, and 1,469,829 bytes were materialized into the shadow. The
reported 1,469,829 logical source bytes read apply to that verification stage,
not the complete run. Target capture then refused a projection-budget mismatch;
no conversion or recovery authority was issued. See the
[record](../evidence/resource-fixture-routed-supply-20261103.json).

The subsequent diagnostic passed that page-budget mismatch and completed
routed supply again. It then refused while rebuilding the target's source
projection because a later target workspace overlapped that projection's own
RAM reservation. The [record](../evidence/resource-fixture-target-ram-refusal-20261103.json)
captures the actual ledger values and exit. Source and shadow remained
offline/read-only; conversion and recovery remain unqualified.

