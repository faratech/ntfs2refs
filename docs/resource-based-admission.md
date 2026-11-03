# Resource-based source and metadata admission

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

The first public already-online recovery attempt on built source`a9f3436`
refused before journal opening because output discovery used the source-only
Windows-disk exclusion for the legitimate C: journal. The converted source
remained online ReFS. The follow-up uses a typed journal-only read-only query,
bracketing mount enumeration with complete `Role::Journal` discoveries. Source
and shadow exclusions remain unchanged. Its focused Windows check passed in
10.73 seconds; a new pinned executable/native rerun is still required. See
[the original refusal](../evidence/resource-recovery-os-journal-refusal-20261103.json).

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

