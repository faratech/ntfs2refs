# Native-shadow performance continuation

The converter keeps Microsoft's formatter/driver as its ReFS metadata builder.
These changes reduce redundant reads and recovery storage; they do not replace
the native shadow, reduce the ReFS required write set, or qualify arbitrary disk
sizes, file counts, features, faults, or power loss.

## Windows conversion: performance and retry plan, November 9, 2026

The findings below describe the running `1f4f3c9` candidate. Host implementation
has since begun; the status table distinguishes that code from native results.
The live VM converter must continue unless it actually fails. Do not replace its
binary, restore a VM checkpoint, recreate the shadow, or run competing benchmarks.
The end state remains the original Windows partition converted in place, with
trust labels preserved, booting with only its original disk attached.

### Implementation status

The host changes preserve the existing on-disk page, content-digest and recovery
contracts. They have not replaced the running VM binary. The original Windows
installation has not yet been shown booting from its converted original disk.

| Change | Current implementation |
| --- | --- |
| Metadata amplification | Two prepaid authenticated page slots; a direct-ordinal compact alias path projection; one authenticated compact-row read shared by the unchanged allocation preflight and typed JSON decoder. Full metadata/security operations still decode their complete objects. |
| Completed payload reuse | A closed private `Payloads` state can be freshly adopted and verified without repeating materialization. A payload receipt alone cannot admit a partly restored public namespace. |
| First-attempt recovery | Supported offline Windows preparations create a durable source/Expected checkpoint before native allocation, an allocation intent before mutation, then closed allocation and placement evidence. Interrupted allocation explicitly refuses partial-namespace reuse. |
| Source cache continuity | The latest verified raw/Expected generation is promoted while retaining its original native baseline. Changed sources and renewed COMPLETE-stream evidence still require fresh checks. |
| Capture work | The closing route owner is reused, capacity and literal/index credits are batched by the already-read chunk, and later source-byte phases use bounded native read scopes with full entry/error-safe exit checks. |
| Fragmented source preflight | One ordered raw-extent cursor replaces restarting the raw scan for every proposed extent. Gaps, holes, overflow and physical mismatch remain refusals. |
| Capacity | Initial VHDX creation/partitioning/formatting and later native allocation consult the actual backing volume independently of the recovery volume. Headroom is sampled; this is not a physical reservation or a bound on all formatter amplification. |
| Progress | Throttled phase/pass/ordinal output covers native allocation, system payloads, aliases, metadata restoration and routed supply. ETA is emitted only from observed progress within the same phase/pass, never for the entire conversion. |
| Build reuse | The shared build directory remains; package-aware source contracts avoid cleaning an unchanged native package for root-only changes. |
| Journal preparation | One held capture witness covers the nested preparation calls. Full opening and error-safe closing checks replace seven full capture checks with two; source/target, offset/layout, independent journal readback and sealing remain. |

The first batch passed the focused component check recorded in
[`performance-resume-integrated-build-20261109.json`](../evidence/performance-resume-integrated-build-20261109.json).
The second batch passed the frozen-source component check recorded in
[`performance-resume-second-build-20261109.json`](../evidence/performance-resume-second-build-20261109.json)
(43.16 seconds, shared target reused, all recorded source hashes unchanged).
No new unit-test suite
or competing VM benchmark was started. Mixed-metadata recovery, captured-state
adoption and end-to-end native qualification remain separate completion gates.

### Findings that explain the delays

| Finding | Evidence and consequence |
| --- | --- |
| Metadata read amplification | `metadata_pages::Reader` holds one authenticated page. Alias creation alternates canonical-file and parent lookups, repeatedly evicting and SHA-256-checking pages up to 4 MiB. Two loops over 112,609 aliases cause 450,436 Expected-object decodes, followed by another canonical-object pass during metadata restoration. This is a bounded lookup workload with cache thrashing, not a whole-tree quadratic search. |
| Checkpoints exceed actual resume support | `ResumeSessionInputs::open` explicitly refuses stages after `Placing`. `Payloads`, `Metadata`, and `Captured` receipts do not yet have the native adopters needed to resume them. Metadata completion also consumes its tree owner on failure, so a partially changed tree needs reconciliation. |
| Expensive work repeats on each retry | Resume rechecks saved artifacts, source continuity, qualifying COMPLETE streams, aliases, native observations, source assessment and Expected compatibility. Refreshed source artifacts are not promoted to the next cache baseline: checkpoints persist `saved.source`. |
| Repeated traversals remain | Routed supply has preflight, planning, materialization, verification and final-plan walks. Protected target capture performs two native observations and repeated route collection; later capture still constructs the unscoped source-byte adapter. |
| Capacity is checked on the wrong resource | Native VHDX reports zero additional backing commitment. Resume budgets the working directory, but its retained VHDX can grow on another volume. The actual failure was C: exhaustion while R: still had space. The r2 lab check is not a product fix. |
| Small operations trigger large overhead | Selected capture invokes its free-space callback for every changed 4 KiB granule. The active callback queries the filesystem each time. Alias lookup decodes complete objects when only a few identity/path fields are needed. |
| Progress reporting hides the active work | Long native loops emit no useful ordinal. The label mapper checks `source` before `apply`, so even `source-apply-and-handoff` can display `Inspecting NTFS`. |
| Build reuse is incomplete | The shared target and stable source staging exist, but a changed source contract cleans both project packages, even for a change confined to one package. |

Primary code locations:
[page reader](../crates/n2r-win32/src/metadata_pages.rs),
[Expected decoder](../src/shadow_tree/pages.rs),
[alias creation](../crates/n2r-win32/src/shadow_native/windows_aliases.rs),
[resume admission](../src/resource_preparation/resume_session_inputs.rs),
[metadata transition](../crates/n2r-win32/src/shadow_native/private_tree/metadata.rs),
[cache generation](../src/resource_preparation/resume_checkpoint.rs),
[provider accounting](../src/drive_staging.rs), and
[release builder](../lab/Build-ReleaseCandidate.ps1).

The current payload-ready receipt is a useful scale reference: 17,174,299,038
logical bytes, 10,062,319,616 retained at source coordinates, 6,773,952,512 routed
for relocation, 338,026,910 materialized, and 475,156,894 actual source logical
bytes read during routed-supply verification. That last counter excludes earlier
materialization/system reads. The receipt does not prove final conversion or boot. By the review,
the process had reported over 800 GB of logical reads; these counters include
cached metadata and are not physical disk traffic.

The already implemented source-read scope reduced the observed interval from
placement completion to first supply writes from about three hours to eighteen
minutes on separate runs. That is an observed interval, not an isolated benchmark
or a claim that the complete conversion is ten times faster. Placement reuse
already performs zero moves in the resumed case. Keep these improvements.

File-content comparisons already use XXH3-128. The sampled current bottleneck is
SHA-256 authentication of repeatedly loaded metadata plus repeated JSON decoding.
Changing every hash algorithm would miss the main problem and change persisted
contracts. Eliminate repeated work first.

The code-level pass ledger exposes additional work hidden by the outer phase
names. These are lower-bound counts, not independent timing measurements:

* Routed supply has at least 15 complete Expected decoding traversals: five
  explicit walks, six decoded input-digest walks, and at least four system-data
  traversals. Its six `phase()` calls also cause at least 12 complete Expected-file
  authentication passes because direct and indirect ownership checks repeat it.
* The two protected native observations add at least 675,654 alias-related
  Expected-object decodes on this corpus, beyond current alias creation.
* Payload routes are collected/sorted/validated three times. The third collection
  consumes the same closing native observation whose route owner already exists.
* `prepare_native_from_protected_capture` reaches seven complete capture
  validations through its nested candidate/domain checks; candidate checks also
  re-read consumed target metadata.
* Source-reference preflight has a separate potentially quadratic fragmented-file
  loop: each declared extent scans the observed extents from the beginning. This
  is distinct from the alias lookup, which is not a whole-tree quadratic search.

### Execution order

The user authorized independent host implementation while the current run
continues. Native replay/benchmark work waits for that run to close. Do not defer
real resume support behind a broad optimization rewrite.

| Priority | Deliverable | Completion condition |
| --- | --- | --- |
| 1 | Bounded authenticated metadata cache and compact alias lookup | Identical alias semantics and digests, with page loads/hash bytes proportional to distinct pages and bounded cache misses instead of repeated canonical/parent eviction. |
| 1, parallel | Actual Payloads and partial-Metadata resume | A stopped run adopts its saved native state and does not repeat completed placement or payload materialization. Mixed alias/security states are reconciled, not blindly recreated. |
| 1, parallel | Early prerequisite checks, backing-volume admission and useful progress | Known incompatibilities/capacity failures refuse before long work; every long phase reports its actual work count; C: and R: obligations are independently enforced. |
| 2 | Promote the latest verified source generation and reuse immutable evidence | An unchanged retry performs one necessary freshness pass and reuses dependent immutable results; source changes invalidate only the appropriate downstream work. |
| 2 | Reduce supply/capture passes and per-granule system calls | No repeated source reads merely to compare bytes with themselves; full boundary checks remain; route and capacity operations scale with bounded batches. |
| 3 | Captured-state adoption, scratch retirement and package-aware builds | Closed capture/journal inputs survive restart, peak storage is reported by phase, and root-only changes do not rebuild an unchanged native crate. |

### 1. Stop repeatedly loading and decoding the same metadata

Start with the existing page format and SHA-256 contracts. Add a second
authenticated cache slot to the Expected reader, or a small bounded cache if
the recorded access pattern proves two slots insufficient. Charge actual buffer
capacity before allocation through the existing arena/native payer. Each slot
retains its authenticated page identity, record cursor and contents; it never
crosses reader ownership or a different artifact generation. Preserve corruption
checks on load and full required closing validation. Account aggregate cache
memory across readers, not a separate generous budget for every reader.

Then stop decoding a complete `Object` for alias path checks. Create a small
immutable projection indexed by object ordinal containing only canonical path,
parent relationship, object kind and the fields that `validate_row` actually
checks. Derive it once from the admitted Expected tree and bind it to that exact
tree. Keep full objects for operations that need security, streams or reparse
data. Reuse validated alias rows between sizing and creation under held immutable
owners; retain native checks around actual filesystem mutations.

Finally replace `decode_object`'s two JSON passes with a typed allocation-bounded
decoder, or decode a once-checked bounded record buffer. This must retain
pre-allocation limits and rejection of malformed/oversized rows. A new binary
page format is a later option, not a prerequisite; it would complicate old-run
compatibility and invalidate reusable artifacts.

Measure a read-only replay of the exact saved alias access sequence after the
live run closes. Compare semantic output, alias coverage, authenticated page
loads, hash bytes, decoder calls, cache misses, RAM and elapsed time. Include a
corrupt-page refusal. The target is a large reduction in metadata amplification,
not merely a faster hash loop. Do not claim an exact wall-time improvement until
the same workload has run.

### 2. Make later checkpoints genuinely resumable

Do not remove the `stage <= Placing` check until a corresponding native adopter
exists. A serialized success flag cannot recreate a native owner or a lock.

Issue these stage/batch journals on fresh conversions as well as resumed ones.
Currently `Checkpoints::create` is reached only through `effective_resume` in
`resource_preparation.rs`; adding later-stage adopters without changing that
integration would leave first-attempt failures without the required records.
Create the appropriate durable records as each dependency closes, before the
next expensive phase begins, and retain explicit compatibility for legacy runs.

* **Payloads:** reconstruct the actual initialized stream/range, carrier and
  system-payload state against the source, Expected and placement dependencies.
  Add durable intent and outcome records for bounded materialization batches.
  Reconcile an uncertain last batch from actual mapping, validity and readback;
  skip a completed range only when its current state proves it still matches.
* **Metadata and aliases:** split canonical metadata, hard links, alias creation,
  reparse/EA/timestamps, security placeholders and trust-label repair into named
  phases. Persist object/stream identities and before/after results by batch.
  Reopen canonical handles and reconcile a mixture of private, partially
  completed and completed metadata. Existing aliases must be verified and reused,
  not created again. Original-security verification remains separate from
  placeholder restoration.
* **Captured:** retain a closed manifest of routes, selection graph, allocation
  dependencies, literal/index chunks, hashes and actual file identities. Add a
  fresh protected constructor that authenticates these artifacts and reestablishes
  current native source/shadow boundaries. Do not deserialize
  `ProtectedPagedTargetSelection` authority.
* **Published/applying:** keep real guard delegation authoritative even if an
  earlier preparation checkpoint is stale. Use the existing journal recovery
  path after publication; never downgrade to a preparation retry after handoff.

Use bounded batches rather than a durable flush for every file. Choose batch
size from work/bytes and report the maximum redo window. A reasonable initial
engineering target is at most a minute of redo for the uncertain batch after
native ownership is reacquired; this is a target to demonstrate, not a current
guarantee. Reopening and required whole-source validation are separate costs.

Focused native evidence should cover one interruption during payload work, one
during alias/security transition, and one after closed capture. Record exactly
which ranges/objects were reused and redone. This is not a new broad unit-test
campaign. Until an adopter exists, preserve a later-stage failure and implement
that missing recovery path; do not relabel it as `Placing` or recreate the shadow.

### 3. Detect predictable failures early and report actual progress

Before expensive source work, validate all available static prerequisites in one
pass: supported checkpoint stage/schema, every required artifact route and owner,
source feature-to-target policy consistency, sparse/compression/VDL forms,
security/trust-label recipe coverage, name/alias rules, page sizes, helper/build
compatibility, privileges, workspace identities, and initial resource admission.
Return the complete known blocker list instead of revealing one deterministic
failure per hours-long attempt. Native target conditions that cannot yet be
proven remain explicit later gates, not fabricated preflight success.

Before each irreversible or costly phase, exercise its cheap ownership/path and
resource transitions. Record operation, phase, object/stream ordinal, bounded
path, offset/length, relevant flags, OS error and latest usable checkpoint on
failure. Preserve the original OS error through wrappers. A known static
refusal should occur in the bootstrap preflight, before source isolation and
large scans whenever its dependencies permit.

Use typed phases instead of substring labels. Emit throttled progress inside
source joins, alias loops, materialization, native observations, capture and
journal writes: completed/total objects or bytes, page loads, cache hit/miss
counts, bytes hashed, native calls by family, actual backing allocation, free
space and outstanding commitments. Show an ETA only when a meaningful phase
denominator and recent rate exist. Keep diagnostic progress separate from
durable recovery evidence; a display tick must not force a journal flush.

### 4. Admit and protect the resource that can actually fill

Replace native VHDX's zero-growth commitment with a provider-owned backing
resource description: retained backing-file and volume identities, actual
allocation, admitted future growth and the configured reserve. Reconstruct it
on resume before lengthy work. Attach monitoring on resumed paths too.

Maintain one ledger per actual volume:

`free now >= reserve + unallocated commitments + next bounded operation allowance`

Charge the outer backing allocation once to its containing volume. Charge the
working/recovery files to their own volume. Existing allocation is already absent
from free space and must not be subtracted twice. Internal ReFS free space,
outer VHDX growth, host physical free space and lab-retention limits are separate
constraints. A large R: balance cannot satisfy a C: obligation.

Admission and enforcement must be separate from advisory telemetry. Protect
headroom before operations that can allocate backing, including metadata creation
and flush-related growth, and reconcile at bounded batch/phase boundaries. A
free-space poll alone is not a reservation: a strict fail-before-exhaustion
guarantee requires real reservation or a conservatively bounded operation under
the supported concurrency contract. If native metadata growth lacks a proven
bound, state the limitation and refuse an unqualified low-space path.

On failure before source apply, preserve recoverable preparation and use the
established explicit cancellation/restoration protocol as appropriate. After
apply starts, use journal recovery. Do not use a generic process kill as storage
management. Allow separately selected authenticated backing and recovery volumes;
do not move the current shadow or change its identity during this live run.

### 5. Stop redoing source admission and whole-pipeline work

Persist a versioned **latest verified cache generation**, linking the accepted
raw inspection, fingerprint, native rows, alias projection and Expected binding
to its original provenance. Current checkpoints instead carry the original
`saved.source`; a refreshed report does not become a new reusable baseline.

Reacquire actual source exclusion on every restart. With proven unchanged source
and held immutable artifact owners, issue one scoped continuity result and reuse
it through dependent phases. Consolidate repeated fingerprint hashing and
Expected verification inside that scope. Source exposure or mutation must
invalidate affected results. A remounted/changed source can legitimately require
a fresh scan; never promise every retry will take minutes regardless of changes.

Apply the same principle to supply and capture:

* Preserve the committed WMI scope fix; extend a suitable typed scope to the
  selected-capture path, which still uses `PagedSourceByteAdapter::new`. Its
  closing/capture authority needs a real compatible scope, not a skip flag.
* Retain one immutable route plan and source/target mapping generation across
  planning, materialization and verification. Reobserve changed ranges and retain
  required full phase boundaries. Distinguish essential opening/closing checks
  from repeated serialization and sorting of the same facts.
* Produce final routed-plan framing inside the existing verification traversal,
  then compare its digest. Eliminate the extra `scan_plan` traversal while retaining
  full closing owner checks and every content/mapping comparison.
* Reuse the already accepted source projection instead of regenerating it during
  protected capture when exact live dependencies establish equivalence.
* Evaluate the two native target observations and repeated route captures as a
  pipeline. Retain their distinct mutation/closure guarantees; share stable
  indexes and already-read buffers where those guarantees permit it.
  Transfer the closing route owner into capture to remove the third route sort.
  Validate Expected-side stream identities in ordinal order, attach a small paid
  identity projection, then sort physical ranges without repeatedly reopening
  complete Expected objects. Add a monotonic route cursor with binary-search
  fallback for nonsequential reads.
* Share an operation-scoped capture/layout witness among nested journal consumers.
  Replace seven nested complete validations with explicit temporal opening/closing
  checks where the same owners and mutation boundaries permit it. Preserve
  independent journal readback, error-path closing and publication revalidation.
* Replace the fragmented-source nested extent search with a monotonic merge of
  declared and observed runs. Preserve every initialization, hole, compression,
  bounds and physical-coordinate check while reducing that path from O(E²) to O(E).
* Replace per-changed-4-KiB free-space syscalls with exact in-memory projections
  and actual admission before a bounded reserved append/chunk. Keep per-granule
  classification and recovery semantics. Count capacity probes to prove they
  scale with batches rather than granules.
* Keep existing COPY-read and closing-buffer reuse; those optimizations are
  already implemented and must not be rediscovered as new work.

### 6. Keep builds and scratch management off the retry critical path

Retain the shared target, exclusive build lock, stable source staging, pinned
toolchain/configuration and copied release artifacts. Make cache invalidation
content-authenticated per package/dependency instead of cleaning both project
packages on any source change. A root-only edit should not rebuild unchanged
`n2r-win32`. Reuse a released executable only for an identical successful build
contract. Measure and reduce repeated full-tree storage-census overhead without
excluding cached artifacts from storage accounting.

Report peak coexistence by phase: provider backing, source/native evidence,
Expected/indexes, literal capture, journal old/new bytes, helper memory and reserve.
Reuse verified generations rather than accumulating duplicate retry copies.
Retire temporary generations only after dependency and recovery closure proves
they are no longer needed. Prepare a concise reclaimable-artifact manifest before
space becomes critical. Keep current evidence and recovery dependencies intact.

### Acceptance and next-failure procedure

Use the existing corpus for narrow read-only cost replays and the disposable VM
for the necessary native interruption cases. Track wall time, CPU, physical I/O
where actually measured, logical process I/O, page/hash/decode counts, native
queries, repeated work and peak per-volume allocation separately.

Initial targets are: known prerequisite failures before expensive work; bounded
phase progress visible within seconds; zero placement moves on a completed
placement retry; zero rematerialization for freshly verified completed payloads;
only the uncertain metadata/capture batch redone; and elimination of the observed
terabyte-scale alias page amplification. Also require elimination of the third
route sort and final routed-plan traversal, capacity probes proportional to
batches rather than 4 KiB granules, and nested hashes reduced to explicit temporal
bookends. Treat minute-scale warm retries and
large elapsed-time reductions as goals until measured on the same source.

If the current run fails, first preserve its actual terminal, exact native error,
latest stage/delegation, completed artifacts and source/shadow availability.
Identify the failed dependency and whether a native adopter exists for that
stage. Fix the concrete defect and missing recovery transition before another
launch. Do not restart a whole conversion or rerun it unchanged to discover the
next predictable blocker. If the run succeeds, retain that exact build/evidence
and apply this plan in isolated follow-up changes.

The remaining sections below preserve earlier scoped measurements and their
limits; they are not evidence that the current Windows boot conversion is done.

## COPY read reuse

`PlainStreamRangeSession` can issue an opaque receipt only after an actual direct
physical read successfully fills the output slice. Resident data, decompression,
sparse holes and uninitialized zeros issue no direct-read receipt.
`SourceBackedShadow` binds the receipts to the immutable candidate chunk. A COPY
whose complete source interval matches those actual reads can reuse those bytes
instead of reading them a second time merely to compare them with themselves.

Each chunk has at most 1,024 coalesced receipt spans. Missing coverage, overflow,
or receipt allocation/budget exhaustion falls back to the previous read and
comparison. The fallback buffer is allocated lazily. Candidate/original digests,
original destination reads, earlier-old COPY coverage, checked sessions, frozen
device brackets and journal/target checks remain. Reused bytes are reported as
`source_reference_bytes_reused`, separately from actual `source_reference_bytes`.
The strict saved-capture reader accepts the optional counter and bounds their
combined value; neither counter supplies write authority.

A subsequent native run of58be22c measured all5,659,303,936 bytes reused with
zero fallback COPY rereads. Native conversion exited0/HND and independent hashes
matched all811 streams. Native-verified process reads were99,711,691,009 bytes,
compared with105,470,433,073 in the earlier case. These are logical transfer
counters, not physical traffic or a controlled timing comparison. Observed
native wall time was285.8896735s, versus276.7805697s previously; a speedup has
not been established. CPU/hash work remains a major cost.
[Exact native scope and archived pins](../evidence/native-capture-copy-reuse-20261101.json).

That source's free destinations were all canonically zero after fine-grained
capture, so the planner correctly retained exact-restoration format4. Journal
storage was5,773,344,392 bytes. The format5 native path remains unqualified.

The next preparation candidate uses the same construction fact inside the actual
`DifferenceImage`: two real native readers must name the same frozen partition,
and every COPY must resolve to that view's direct original-source branch. Its
candidate read already reads the source bytes, so it omits the second identical
source read. Actual candidate hashing, complete post-flush resolved journal
validation, and every fresh/recovery target gate remain. Generic readers keep
the original comparison. This later candidate is not qualified by the58be run.

The later c2c1ef3 native run qualified that preparation path: it reused another
5,659,303,936 source bytes, exited0/HND, and passed all811 independent hashes.
Native-verified logical reads were94,053,323,457 bytes. The two construction
optimizations therefore removed two measured duplicate5.66-GB source passes.
This remains a logical-I/O result, not a controlled wall-time speedup claim.
[Exact paired-preparation result and pins](../evidence/native-paired-preparation-copy-reuse-20261101.json).

[NTFS-managed collision preparation](ntfs-owned-preparation.md) is now implemented
for the explicit scratch-minimizing mode. The scoped native run moved5.64GB
through385 verified NTFS requests and passed all811 independent hashes. A fresh
frozen raw/native baseline also passed. The subsequent conversion passed with
positive format5 free-space elision and all811 independent postconversion hashes.
This does not establish released CLI or arbitrary-volume support.

The prepared-source case reduced journal storage from5,773,273,160 to131,301,000
bytes (97.73%), and selected writes from11,393,306,624 to544,784,384 bytes.
Native-verified logical process reads fell from94,053,323,457 to27,643,861,313;
writes fell from17,368,271,656 to878,482,576. The separate NTFS relocation moved
5,643,501,568 bytes and entails kernel-managed payload I/O outside those converter
counters. Native wall time was62.2871679s plus18.5202009s preparation, versus the
previous280.3918824s conversion. Full lab baseline/observer time is excluded;
formatter epochs and cache conditions were not controlled.

Actual journal format wasN2RFRE01 with402,669,568 hash-only free bytes and a
1,572,928-byte hash table. This qualifies the recorded fresh conversion and native
mount, with scoped free-space rollback semantics. Native interruption/Resume/
Rollback still require separate qualification. The result is preserved at051b650a;
the older unprepared31d7 checkpoint was retired after verifying both archives.
[Exact result and pins](../evidence/prepared-source-performance-native-20261101.json).

## Closing-buffer reuse candidate

The next Rust candidate feeds actual closing-bracket read buffers directly into
the existing allocation comparison. Each buffer is read, checked for required
zeros and included in the unchanged framed hash before its immutable bytes are
reused. Both complete opening and closing brackets, original-source reads,
granule comparisons and final native/route/allocation/state gates remain.
Unqualified capture output cannot mint execution authority if a closing gate
fails. Unsupported or backward requests retain actual-read fallback.

The provider needs one extra1-MiB buffer and keeps the existing4-MiB comparison
reducer. `shadow_bytes_reused_from_closing` distinguishes reused closing bytes
from actual capture shadow reads; the strict saved-artifact reader defaults
historical reports to zero and includes the new value in exact read accounting.
Full/generic paths retain their previous behavior. Runtime72b4db0 passed native
conversion/HND and all811 independent hashes. It reused6,176,772,096 actual closing
bytes with zero extra capture shadow reads; both brackets still read6,176,772,096
bytes and checked6,048,186,368 zero bytes each. Native-verified logical reads were
21,473,893,401 versus27,643,861,313 previously (22.32% lower). Native wall time was
70.5999624s versus62.2871679s: this establishes fewer reads, not a timing speedup.
The epochs/cache conditions were not controlled. Source/copy-verified87-file
metadata archive and checkpointf8f7db07 preserve the result. This does not qualify
the later directory-case runtime or its recovery matrix.
[Exact measured scope and pins](../evidence/closing-buffer-native-20261101.json).

## Source-free recovery storage

`--minimize-scratch` explicitly selects `source_free_actual_bytes_v1` for fresh,
fast, allocation-bounded conversion. Full-content/whole-image modes retain their
existing contracts and cannot combine with this option. Existing requests and
journal formats 1–4 retain their previous semantics.

The private planning witness requires the reconciled NTFS allocation model,
complete record coverage, its bitmap pin and the exact partition domain. It
uses the existing allocation helper and rounds partial 4 KiB ownership outward.
Its inventory pin must match the frozen inspection bound by the live source
certificate. Optional changed-class diagnostics are not authority.

The planner splits at ownership boundaries, preserves new-zero/COPY mappings,
and protects the discovery first 4 KiB and every original COPY source. Actual
old zeros keep their existing canonical-zero representation. A nonzero old
destination becomes hash-only only when the complete granule is NTFS-free.
The planner keeps the original format if the exact new encoding is not smaller.

Format 5 (`N2RFRE01`) stores a 16-byte XXH3 digest per omitted old 4 KiB granule.
Its 104-byte descriptors, digest tables, preserved old payload and new literal
payload are authenticated by the complete immutable journal SHA-256 pin.
Tables are streamed in the binary journal, not expanded into plan JSON.

The actual full original selected SHA-256 remains the fresh target gate. During
that same gate, actual free granules must also match their stored digests. A
loader cannot reconstruct omitted original bytes from hashes: its separate
restoration digest covers only records whose original bytes remain recoverable.
This distinction is explicit in the ticket and rollback result.

Resume checks each hash-only granule against its original digest or exact new
bytes. Neither-old-nor-new, including torn 4 KiB mixtures, refuses. Rollback checks
these granules but leaves them unwritten, restores every required old record,
and verifies the restoration digest. ABT verification has the same scope. HND
still requires the full selected new digest and permanently closes old replay.
Legacy formats keep their previous per-byte interrupted-write membership rule.

The resulting rollback contract preserves the admitted NTFS filesystem's live
allocations, not the previous contents of unused space. It does not preserve
deleted-file recovery contents or provide rollback after writable ReFS use.

## Capacity and reads

For selected changed bytes `D`, actual canonical old zeros `O`, hash-only free
old bytes `F`, new literal bytes `L`, and metadata `M`:

```text
journal = (D - O - F) + L + F/256 + M
```

`O` and `F` are disjoint. The live capture guard charges the hash table in
addition to the existing metadata reserve, before accepting/appending a run.
It checks the same frozen allocation union used by final refinement; COPY
origins must be allocated. Exact final encoding size and independent native
write-capacity admission remain mandatory. A smaller journal never omits a new
ReFS target write or authorizes a larger source/data feature set.

## VSS admission

The new policy observes snapshot presence and hosted storage before freeze, then
snapshot presence inside the existing physically read-only native NTFS lease.
Both observations must name the same source and complete provider inventory.
Persistent exclusion is restored before return, and the source fingerprint
brackets that lease. This adds no extra mount or payload scan. A disposable 2 GiB
NTFS probe demonstrated that VSS cannot resolve a fully offline volume GUID and
that its storage query refuses physical read-only publication. Consequently the
full storage query stays before freeze; the protected lease repeats the supported
snapshot-presence query, never fabricating a second storage observation.
It requires requester-level `IsVolumeSnapshotted` to report successful,
initialized false/zero results and requires an empty hosted diff-area collection.
Unknown providers and query/partial-enumeration errors refuse. Supported provider
inventory is the Microsoft system provider, optionally with the exact observed
Hyper-V host-integration provider. The latter is reported separately rather than
represented as a guest differential-storage query.

The native Windows 11 probe observed the Microsoft differential-management query
returning `S_FALSE` with a real empty enumerator. This compatibility form requires
that nonnull enumerator and exact empty completion; null/partial/nonempty outputs
refuse. Its actual HRESULT remains recorded. This is an observed compatibility
form, not a success value listed by the Learn method page. Aggregate snapshot
`Query`'s ambiguous `S_FALSE` is not used to establish absence.

Catalog observations provide no global VSS serialization or raw write authority.
The existing owning freeze and no-concurrent-admin/mutable-alias contract remain
required. Reports explicitly leave in-flight exclusion and global snapshot counts
unproved. Additional providers and adversarial VSS races remain unqualified.

Primary contracts: [snapshot presence](https://learn.microsoft.com/windows/win32/api/vsbackup/nf-vsbackup-isvolumesnapshotted),
[hosted storage](https://learn.microsoft.com/windows/win32/api/vsmgmt/nf-vsmgmt-ivssdifferentialsoftwaresnapshotmgmt-querydiffareasonvolume),
[Hyper-V integration](https://learn.microsoft.com/windows-server/virtualization/hyper-v/integration-services).

## Current evidence and remaining work

[Recorded scope, artifact pins and results](../evidence/native-shadow-performance-20261101.json).

Focused builds and owned ordinary-file experiments cover the new format5 and
existing legacy copy/old-zero encoding. Native capture-read reuse and clean
format4 fallback passed the earlier converted-volume/811-stream run. The later
prepared source passed positive format5 conversion and all811 streams; native
format5 interruption and recovery remain pending. The owning
Windows VSS API probes and the native run exercised the supported admission
scopes without a global VSS exclusion claim.

The final optimized owned-file case omitted 8,192 old bytes using 32 hash-table
bytes, reducing its existing format-4 journal from 41,848 to 33,688 bytes. It
exercised interrupted Resume/Rollback and a separate complete Apply followed by
Rollback before HND. In that latter case, a foreign free-granule edit refused
Resume with zero target/journal writes; after restoring the actual new byte,
Rollback left 8,175 free bytes differing from their originals while independently
verifying exact new free contents and exact original restore-required contents.
Closed ABT verification passed. Legacy full old-byte restoration also passed.

The disposable NTFS probe separately confirmed snapshot-presence observation
under physical READ_ONLY publication. Its report explicitly does not claim a
second hosted-storage enumeration. No unit tests were added or run.

Sizing the saved, previously qualified grown-F plan preserves its selected bytes
and existing old-zero choices. It changes journal storage from 5,850,442,832 to
5,780,851,832 bytes: 69,591,000 bytes saved. The omitted 69,865,472 free bytes need
272,912 bytes of hashes and 15 additional descriptors. This is exact sizing of
that saved plan, not a native timing or physical-I/O measurement. Fresh capture
may have different boundaries and actual old-zero counts.

Most remaining old payload in that case is live source data overwritten by the
required target layout. Omitting free garbage alone cannot eliminate that cost.
Actual COPY reuse and NTFS-owned relocation now have the scoped native evidence
above. Next are native format5 interruption/recovery and reuse of already-read
closing metadata buffers while retaining both metadata brackets. Paged
source/evidence records and bounded handle windows
remain necessary for broad scale. Required-zone zero skipping remains disabled;
any smaller footprint needs independently authenticated ownership evidence.

## Immediate admission boundary reuse (2026-11-03)

The fresh-apply qualification now brackets its immediate read-only admission
operation once. Previously, two successive revalidations each performed a full
opening and closing scan of the same frozen source fingerprint and consumed
shadow ranges. The scoped implementation retains one complete opening and one
complete closing scan, including on callback failure, while preserving both
sets of owner, publication, preparation-guard, journal-index and native checks.
A private nonescaping witness binds the exact live source and target owners;
it cannot authorize writes or become a persisted validation cache. The separate
fresh-apply validation and the SDK's checks before the AP transition remain.

For the authenticated f856 minimum-scratch case, consumed shadow ranges total
6,176,772,096 bytes. Removing two duplicated scans avoids 12,353,544,192 logical
shadow bytes at this boundary. This is code-derived attribution against that
saved ledger, not a measured speedup or physical-I/O result. The earlier frozen
a0b native results do not qualify this changed build. Focused compilation passed;
native qualification of the optimization remains pending. No unit tests were
added or run.

## Publication and paged hashing follow-up

The cad9139 public conversion completed successfully in 1,101.1730916 seconds.
An independent observer matched all 811 original XXH3 streams (9,885,801,949
bytes), 1,534 baseline objects and 1,024 added directories. Its authenticated
closed ledger confirms that immediate fresh-apply admission now performs two
complete consumed-shadow scans rather than four: exactly 12,353,544,192 raw
shadow bytes avoided on this run's 638-range set. The measured phase aggregate
fell from 27,577,485,632 to 14,215,644,770 logical process-read bytes.

Overall observer-close reads fell by 9,989,575,064 bytes, while writes rose by
431,350,092 bytes. Runtime increased by 65.010655 seconds versus f856, so this
run establishes a read reduction, not a wall-clock speedup. The counts are
logical process transfers, not physical storage I/O or exact final counters.
See [the recorded result](../evidence/public-resource-read-reuse-20261103.json).

The next change applies the same scoped opening/closing pattern to publication
of independent recovery-copy files. It retains both complete owner/journal
checks and error-path closing, then separately creates the write index,
delegates the guard, closes the arena and revalidates the prepared result.
For the saved f856 ranges, it removes another 12,353,544,192 shadow-read bytes,
251,011,072 fingerprint-read bytes and 171,892,736 literal-read bytes. These
figures describe code-derived scan removal, not a new native timing result.

The paged consumed-range hasher also now uses the existing Microsoft CNG
SHA-256 backend. The v1 domain, interval and chunk framing, chunk boundaries,
input bytes, digest and source/target checks are unchanged. Every native hash
error propagates; handles are released by the existing RAII wrapper. Three
existing workspace admissions reserve 2 KiB of application headroom, without
claiming an exact size for private Windows allocations. File-content hashes
remain XXH3-128. Focused compilation passed; the combined change still needs
its own native result. No unit tests were added or run.

## Frozen 814 native result

The combined change completed conversion in 913.2446592 seconds (15:13),
compared with cad's 1,101.1730916 seconds. Its authenticated observer-close
process counters were 164,909,910,658 bytes read and 3,256,217,717 bytes written:
14,717,789,054 fewer logical read bytes than cad. These are observations from
separate uncontrolled VM runs, not physical I/O or a guarantee for other disks.

Publication retained the same 638 ranges / 6,176,772,096 bytes, with two complete
scans instead of four. The separate apply revalidation remains complete. All
811 original XXH3 streams, 1,534 baseline objects and 1,024 added directories
matched independently before and after a normal reboot. All 513 mutation files
matched after reboot and after completed-volume recovery. An exclusive readonly
journal lock produced the expected native sharing failure without changing the
journal; the subsequent normal HND recovery exited zero without raw replay.

Retained regular-file allocation after reboot was 1,227,365,280 bytes, including
the 185,135,104-byte journal and 824,180,736-byte shadow. This is not peak scratch
and excludes global filesystem/directory overhead. See
[the exact result and limits](../evidence/public-resource-cng-20261103.json).
Interrupted AP resume/rollback still need this exact candidate's own cases.
