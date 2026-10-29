# Unbounded-scale design (draft, not adopted)

Status (2026-10-29): produced by read-only workflow wf_5c358166-e1b (4 subsystem
inventories, a completeness critic, 3 independent designs, a judge and 2
adversarial verifiers) after the user's decision "Redesign theoretically
unlimited" (AGENTS.md SCALE DECISION). 112 fixed limits were inventoried. Both
verifiers returned sound=false / first_stage_ready=false; their corrections are
at the end and take precedence over the staging below. Measured inputs:
evidence/mixed-fixture-stage1-20261029.json (808 files: placement completes at
4973f31, about 105 ms per move, 65% of data relocated, refusal at the
journal-derived changed-byte budget). Nothing here grants authority; each D-n
evidence-scope change needs its own explicit user decision.
# SYNTHESIS: Proof-first resource-bounded converter: design 3 as the base, with design 2's native-work-first placement and design 1's forced-spill determinism checks
## ARCHITECTURE
SYNTHESIS BASIS
Scores, 1-5, in this order: coverage, invariant safety, evidence completeness, performance, implementation risk (higher means lower risk), stageability.

Design 1 (sorted-stream): 5/4/4/4/2/3, total 22.
- Best determinism discipline: total-order keys, window invariance, a forced-spill crosscheck, and gates G0-G5 named per phase.
- Weaknesses:
  - It needs a new crate, and every consumer is rewritten around sealed streams.
  - Merkle roots replace every SHA-256 pin, so no stage can be accepted on pin identity.
  - Post-commit "match by reference" is lossless only if the predicted record contains every observed field.
  - It adopts a handle window without naming the exclusivity change.
  - Its stage 2 is one very large coupled change.

Design 2 (native-work-first): 5/4/4/5/3/4, total 25.
- Best placement work reduction: moves grouped per file in LCN order, a single-sweep subrun planner, parallel dual-view capture with CNG SHA-256, and shadow-only probes for the move length and for allocation-free placeholders.
- The most honest accounting of evidence scope (held handles, flush batching, pre-move recapture) and of time.
- Weaknesses:
  - Weaker separation of authority from evidence.
  - Always writes N2RSEL02.
  - Its fused content lanes interact with the bracket ordering.
  - It treats stage 1 as in flight, but stage 1 is committed at HEAD 4973f31 and has no native run.

Design 3 (proof-first): 5/5/5/3/4/5, total 27.
- Keeps SHA-256-over-exact-file pins and keeps N2RSEL01 whenever the range count fits.
- Separates authority, evidence and spill into planes.
- Makes capacity monotonic across the commit point, and removes every post-write hazard before any cap is lifted.
- Accepts each stage on byte-identical pins.
- Gaps, all fixed in this synthesis:
  - (a) It replaces held placeholder handles with a working set without a user decision.
  - (b) It removes the placement route clamp one stage before routes are uncapped.
  - (c) It lifts the admission counts before the journal range caps.
  - (d) Its placement performance plan is thin.

BASE: design 3.
GRAFTS:
- From design 2: the placement engine, capture parallelism, measured cost coefficients, ledger-charged held handles, and the decision list for evidence scope.
- From design 1: gates G0-G5, window invariance with a same-run forced-spill crosscheck, level-ordered parent-relative construction, delta-chain replay verification, and a stage-0 native baseline of 4973f31.

PRINCIPLE
A proof is a check over a complete set plus a SHA-256 pin over canonical bytes. Neither needs the set to be in RAM or bounded by a constant. Every fixed cap becomes one of four things:
1. A bound derived from pinned inputs.
2. A streamed reader or writer that produces the same bytes and digests.
3. A merge-join or sweep over sorted streams.
4. A checksummed, process-private spill tier, used only when the RAM ledger is exceeded.
Only format, native-API, host-scale and termination constants remain (C17). Encodings change only under schema bumps. Nothing checked or recorded is narrowed.

THREE PLANES
- Authority (process memory only):
  - The live SourceCertificate and AllocationCertificate, the opaque observation objects and the proof objects.
  - They bind O(1) pins (inspection, assessment, expected tree, selection) plus the capacity-plan and derivation pins.
  - Every proof is computed on the in-process stream as data arrives. A disk copy is never an input to a live proof.
  - A fresh Apply still requires certificate.binds(proof) on the original object.
- Evidence (the OS/run volume, outside both data volumes):
  - Canonical JSON, JSONL per-object documents, framed EvidenceLogs and a content-addressed BlobStore.
  - Pinned by Pin{sha256, bytes, chunk table} and held deny-write while recovery is possible.
- Capacity:
  - CapacityLedger (RAM, including kernel handle cost) and SpaceLedger (one account per volume).
  - They turn measured resources and exact inventory counts into recorded, re-checkable bounds.

RULES
- R1. Bounds are pinned derivations: bound = f(derivation.json, capacity-plan.json). Validators recompute f and require recorded == recomputed and measured <= bound, the same shape as today's validate_resources.
- R2. Canonical bytes are the proof object. They stay byte-identical unless the schema version changes.
- R3. Authority stays in process. Spill files are share-0, delete-on-close, carry a SHA-256 per block, and are never named in any pin, bundle or recovery input.
- R4. Capacity is monotonic across the commit point. Everything consumed after activation is reserved or materialized before it: WritePolicy, journal records, the post-handoff verifier's RAM working set, the post-commit bitmap recapture, finalization/completion/result, and the event log.
- R5. Recovery capacity is at least conversion capacity. Recovery bounds come from pins, never from constants.
- R6. Knobs only restrict. --lab-capacity-limit can only lower budgets, and it is recorded.
- R7. Complete or nothing. Collectors poison on error. Documents are written as <name>.partial, synced, then renamed. A refusal writes a counters-only artifact that is never pinned.
- R8. Window invariance. Every pin is independent of the spill window W, run boundaries, lane count and thread order. Keys are memcmp keys with a full-record tiebreak, and bodies use BTreeMap only. --lab-spill-crosscheck computes the selected structures both in RAM and force-spilled in the same run, and refuses if any pin differs.
- R9. Pre-write and post-commit observers share one code path and one capacity function, so the post-commit side has no independent caps.
- R10. Coupled sets land atomically, in an order where each lift only moves a refusal downstream, and always before activation. Admission counts are lifted last.

CAPACITY GATES (all before activation)
- G0, preflight before freeze. Inputs: $MFT DATA size / FRS, $Bitmap allocated clusters, partition and cluster size, RAM, and free space on the OS, journal and shadow-host volumes. Refuses on a coarse projection.
- G1, after raw inspection and before shadow construction. Exact F, D, R, N, E, S, R_max, N_max and residual/SVI bytes produce the pinned derivation.json and capacity-plan.json. The spill window is allocated and touched here, and the held-handle kernel cost is charged here.
- G2, before construction. Exact exception (residual + SVI) bytes against shadow free space, and a VHDX growth bound.
- G3, before the first FSCTL_MOVE_FILE. The complete deferred + evacuation + final plan: submissions, exact evidence bytes and a time estimate. G3 is re-run on every drift re-plan.
- G4, before journal preparation. Exact journal = 8 KiB + 80 B x (X+2) + 2B, packed backing = B, and the X ranges.
- G5, before activation. Free space is re-observed. The post-commit files are preallocated with FileAllocationInfo, and the verifier working set is reserved.

Placement refusals after shadow-only moves remain shadow-only and are preserved, never retried; they become reachable only through drift. Recovery takes every bound from a pin.

DATA FLOW
1. Preflight measures and records (G0).
2. Freeze. Raw inspection runs through streaming block readers into a columnar inventory store with byte-identical Serialize (RAM tier, spill tier). The canonical inspection pin is streamed into SHA-256 once and passed by value. G1 follows.
3. Native observation uses Request v2 (pins, counts and an identity-list digest). T lanes feed an ordered reorder buffer. Each identity is merge-joined against the inventory in process, then tee'd to an EvidenceLog. Report v2 is a manifest.
4. Admission binds the same pins into the live certificate.
5. Construction:
   - Directories and placeholders are created level by level, relative to held parent handles. Every handle stays held and charged to the ledger.
   - Residual tails and SVI are streamed (G2).
   - Placement plans all phases from per-phase snapshots. G3 runs before the first move.
   - Moves are grouped per file in destination-LCN order. Each move keeps its full native proof and is synced to the placement log before the next move.
   - Metadata completion is a merge with the tree. Then the shadow is frozen.
6. Target qualification:
   - Streamed object observation in expectation order.
   - Bitmap range sidecars and QuerySweep.
   - A k-way-merged selection into a RangeStore, compact routes, the selected compare and the plan.
7. Journal: G4, then N2RSEL01 when the range count fits u32, otherwise N2RSEL02.
8. G5. Bundle v2 is published with {sha256, bytes} pins. Activation requires certificate.binds(proof).
9. Apply and handoff stream the journal. WritePolicy uses partition_point.
10. The post-handoff verifier is the target-observation code consuming the expectation as a stream. The bitmap recapture is recorded as a delta against the pinned witness. Full records go into reserved space.
11. Recovery uses PinnedReader and takes its ranges from the journal record table. It never clears protection and never starts a fresh Apply.

COUPLED SETS AND THEIR LANDING STAGE
- H, post-write hazards (recovery read caps, finalization after HND, the 128-event audit, the shared verifier capacity function): S2, before any lift.
- J, artifact ceilings: S4.
- D, bitmap ranges (source and every shadow view, the protected witness, the post-commit recapture, AllocationMap, scratch intervals, MAX_MAP_RANGES): S5.
- F, placement (submissions, move length, ranges/tracked/owned, evacuation, subruns, per-file submissions and placements, drift, the route clamp, routes 4096, supply): S5.
- G, exception and SVI bytes: S5.
- E, native evidence (identities, the security/stream/namespace budgets, the report, namespace entries/calls, retrieval, regions, stream list, SD size): S6.
- B, per-file runs (ntfs_attribute_list MAX_RUNS / MAX_EXTENSION_RECORDS / MAX_LIST_BYTES and the literals, ntfs_stream_plan:97, shadow_native.rs:2811), together with the inspection caps: S7.
- C, ranges (selected_journal MAX_RANGES, DeltaLayout, the capture budget, WritePolicy, coverage, JournalProfile, the reference file): S8.
- A, tree counts and depth (admission, shadow_tree, ntfs_stream_plan:133, private_tree, run_role_profile, cache_refresh, recovery validation, every depth-16 site): S9, last.
## RESOURCE MODEL
VARIABLES
- F = MFT base records (user + system). D = directories. R = MFT records. N = directory entries.
- E = nonresident extents. E_d = desired retained runs. R_f = extents of file f; R_max = the largest.
- S = distinct descriptors, of Sb bytes. N_max = the largest directory.
- M = FSCTL_MOVE_FILE submissions, with K_f of them for file f. P = placement phase snapshots (3 plus re-plans).
- C = clusters; Bm = C/8 bitmap bytes. A = allocated bytes. L = logical bytes per content pass; h = content passes (4-5 today).
- X = changed ranges. B = changed bytes. T = lanes. W = spill window.

RAM (charged to the ledger; peak = maximum over phases, because each phase frees its structures)

In-memory mode, used whenever the projection fits:
- Inspection: about 4 B x R + R/8 + 300 B x F + 24 B x E + 40 B x E (transient interval sort) + 48 B x S.
- Native observation: T x (16 B x R_max + about 600 B x N_max + 4 MiB I/O) + the reorder window.
- Placement: 24 B x E_d + 64 B x E_tracked + 32 B x M_plan + 16 B per allocated range per view. Optional S5b page reuse adds 2 x Bm.
- Selection and journal: 16 B x merged ranges + 32 B x X.
- Verification: T x the per-object working set.

Spill mode:
- Each O(F), O(E) or O(X) term becomes min(term, W share) + term/4096 for fence indexes.
- The floor is W_min (fan-in 2) + T x (4 MiB hash + 1 MiB merge page) + U.
- U is the format-bounded singletons: $UpCase 128 KiB, one FRS <= 64 KiB, one SDS pair 512 KiB, one B-tree path, one bitmap page <= 1 MiB + 16, one descriptor <= about 131 KiB.
- W = policy fraction (default 1/4) of available physical memory, allocated at G1. The lab knob can only lower it.

Kernel: h_k x (F + D) for held placeholder and metadata handles. h_k is measured in S1; the estimate is 1-3 KB, unmeasured.

Estimates (not measured):
- 52 GiB fixture: under 100 MB, same as today.
- 1M files / 10M extents / 16 TB: about 2-3 GB peak in memory (placement-dominated), or about 0.5-1 GB with spill (required on the 4 GiB lab VM), plus about 1-3 GB of kernel pool for held handles. If that does not fit, the run refuses at G1, or the user approves D-4.

DISK

OS/run volume (the journal is also here on the drive path):
- Evidence v2 ≈ a_F x F + a_N x N + a_E x E + Sb + a_M x M + 16 B x allocated ranges x full captures, where:
  - a_F ≈ 4-10 KB (native, layout, expectation and full post-commit records);
  - a_N ≈ 0.7 KB;
  - a_E ≈ 50-250 B;
  - a_M ≈ 0.3-1 KB + 16 B x map delta.
- Spill (transient): at most 2 x the largest spilled structure.
- Packed backing: B. Journal: 8 KiB + 80 B x (X + 2) + 2B.
- VHDX growth G <= min(partition + 64 MiB, 2 MiB x distinct touched blocks), measured after construction.
- Post-commit reservation: the counting-sink bound of finalization, completion, result, the event log and full verification records (about the size of the target-preservation evidence).

Shadow volume: residual + SVI bytes + ReFS metadata.

Estimate for 1M files / 10M extents: about 8-20 GB of evidence + at most about 3 GB of spill + 3B + G. G is unmeasured; the worst case is about 2 TB if tails scatter.

TIME

T_total ≈ h x L / θ_content
  + (R x FRS + index + $SDS bytes) / θ_seq
  + c_open x F x k_obs / T
  + c_ioctl x (E/1024 + N/300)
  + 2 x sort_bytes x ceil(log_k(n/W)) / θ_disk
  + c_create x (F + D)
  + M x (t_move + t_cap)
  + Σ_f K_f x t_map(R_f)
  + (2 x selection + 3B) / θ_disk
  + verification (A / θ_content + c_open x F / T)

where t_cap = Bm / min(θ_bitmap, CNG SHA rate of about 511 MB/s per core), with the two views and three hash streams run in parallel.

Everything is O((F + E) log(F + E) + L + C) except two placement terms at today's evidence scope:
- M x Bm;
- Σ K_f x R_f, which approaches R_f^2 for one heavily fragmented file.
Both are time-bounded, which the user's decision allows. In-scope work (parallel views, CNG, page reuse, LCN-ordered per-file grouping, native-maximum move length) only reduces the constant factor. Only decisions D-1 and D-2 change the asymptotics.

Estimates (not measured):
- 52 GiB fixture: Bm ≈ 1.7 MB; the total stays about 40.6 s.
- 16 TB: Bm = 512 MiB, so about 0.3-1 s per move. With M ≈ 1e6-1e7, placement takes roughly 3.5 days to 4 months.
- The content passes take 16 TB x 4-5 at 1-2 GB/s, about 10-20 h.
- With D-1 and D-2, placement ≈ P x Bm + M x t_move, i.e. hours.

Time is projected at G1 and G3 and recorded. It is never a refusal criterion.
## EVIDENCE MODEL
PINS
- Every artifact is a canonical byte stream identified by Pin{sha256, bytes, chunks}. The pin still means the SHA-256 of the exact file.
- The pin is computed by a tee during the write. A final name exists only after the bytes are synced and renamed from .partial, so a named document is always complete.
- Collectors poison on error. A refusal writes a separate counters-only artifact that is never pinned and never consumed. No partial proof, digest or inventory can exist.
- Unchanged formats keep byte-identical pins (C1). Changed formats bump their schema: hex byte fields, JSONL, sidecars, delta chains, Request/Report v2, bundle v2, N2RSEL02 only beyond u32.

CONSUMERS
- A consumer holds the file deny-write with a single link and checks the exact pinned length.
- It verifies each 4 MiB chunk against the pinned chunk table before parsing it, then the whole-file SHA-256 at EOF.
- Chunk-verified records may feed read-only checks. Any decision or write waits for the whole-file pin.
- Recovery bounds always come from pins (R5), so a run that wrote an input can always read it back.

COMPLETENESS WITHOUT LOADING
- Large documents are JSONL. The header carries the schema, the derivation pin and the expected counts derived from the raw inventory: identities, directories, entries, streams, extents, objects, moves and ranges.
- Records follow a strict canonical key order. Readers check strictly increasing keys, the exact count and the footer totals.
- Missing, duplicate and extra records are therefore detected exactly as set equality detects them today, with O(1) reader memory.
- Every identity is still observed in every native pass. Every directory is still enumerated twice. Every planned move is recorded with its full proof. Every object is recorded in every layout and verification observation.

LARGE AND REPEATED PAYLOADS
- They live in the write-once BlobStore, referenced by (sha256, bytes): descriptors (deduplicated, each use recording its hash), retrieval maps, bitmap range sidecars, the MFT-bitmap replay and attribute lists.
- Every reference must resolve during verification.

DELTA CHAINS
- They store time series losslessly: a full initial state, per-step deltas, and the full-state SHA-256 after every step.
- They cover per-move retrieval maps, per-move bitmap range views and the post-commit recapture against the pinned witness.
- lab-evidence verify rebuilds every intermediate state and checks every digest, so per-step completeness equals today's.

CRASH-RELEVANT SEQUENCES
- Placement moves and native control events go to EvidenceLogs: framed records, each synced before the next native step.
- Checkpoint records carry the SHA-256 of the file prefix, so an interrupted log is verifiable up to its last checkpoint.

DERIVED BOUNDS ARE EVIDENCE
- derivation.json and capacity-plan.json are pinned and bound into the admitted assessment.
- Each validator recomputes its bound and requires recorded == recomputed and measured <= bound. Bounds stay bounded and honest, but they are no longer constants.
- Each manifest also records the CapacityLedger snapshot, W, T, the cost coefficients, the counting allocator's measured peak, and the existing honesty flags (free_space_contents_compared=false, the content-digest kind).

AUTHORITY
- The live certificate binds only O(1) pins: inspection, assessment, expected tree, selection, capacity plan and derivation.
- Proofs are computed on the in-process stream. Disk evidence is never re-read to rebuild authority.
- Spill is process-private, checksummed, delete-on-close, and never pinned or bundled.
- A fresh Apply still needs the original in-memory certificate; nothing deserialized can recreate it.

POST-COMMIT
- The verifier performs every current check and writes the full observed record for every object, not a reference to a predicted record. All of it goes into space preallocated at G5, so nothing written after the ReFS commit can fail on size or space.
- The post-commit bitmap recapture uses the same capacity code as the pre-write witness.

LOCATION AND REVIEW
- Evidence lives on the OS/run volume, outside both data volumes, reserved by the SpaceLedger, and held deny-write while recovery is possible.
- The lab-evidence binary stream-verifies a run directory (every pin, length, chunk, order, count, blob reference, log checkpoint and delta reconstruction) and dumps any set as pretty JSON for review.
- Schema-1 artifacts, v1 bundles and N2RSEL01 keep their readers.

DIGEST KINDS
- Artifact pins, metadata, residual tails and bitmap digests stay SHA-256.
- File-content digests stay XXH3-128 in their *sha256 fields, as the user decided.
## EVIDENCE-SCOPE CHANGES
- NONE ADOPTED. Every check that runs today still runs on every object, extent, directory entry, descriptor, range and move, and every observation is still recorded in full. The changes are only to storage, encoding and algorithm:
- streamed byte-identical JSON;
- hex fields;
- JSONL with header counts;
- chunk tables;
- a content-addressed descriptor store;
- delta chains that keep every full-state digest;
- range sidecars;
- sorted-merge reconcilers with identical results;
- parallel and CNG hashing with identical digests.
The optional S5b per-move page reuse still reads and commits every page natively; it changes only the per-move commitment encoding (a Merkle root over page digests) under a schema bump. Each item below is NOT ADOPTED and needs its own explicit user decision.
- D-1 (NOT ADOPTED, the largest time lever). Per-move window-scoped bitmap probes, plus one full dual-view capture per phase boundary and the BitmapModel, instead of two live whole-volume captures and digests before every FSCTL_MOVE_FILE.
- What narrows: the per-move whole-volume live digest becomes a window digest plus a predicted model digest.
- Benefit: placement goes from Θ(M x C/8) to Θ(P x C/8 + M). It is needed for multi-TB volumes with many moves, not for the 52 GiB or 808-file fixtures.
- D-2 (NOT ADOPTED). An incremental post-move retrieval proof read from the moved range's StartingVcn onward, with the complete map captured only at the first move and at file completion, instead of the complete map after every move.
- Benefit: removes the Σ K_f x R_f term, which is quadratic for one heavily fragmented file.
- D-3 (NOT ADOPTED). Skip the pre-move verify_placements recapture when the same file's previous post-move capture was its last native operation.
- What changes: a mapping change in that interval is detected one move later, still shadow-only and before any source write.
- Benefit: halves the retrieval captures.
- D-4 (NOT ADOPTED). A bounded placeholder and metadata handle working set (close, then reopen by file ID with an identity check) instead of holding every placeholder exclusively (share 0) until metadata completion.
- What narrows: the per-object interval exclusivity proof.
- Default: handles stay held and are charged to the ledger. This would be proposed only if the measured kernel cost x (F + D) does not fit, in which case the run otherwise refuses at G1.
- D-5 (NOT ADOPTED). Batched durability for residual tails: one volume flush per batch, followed by the per-file readback, instead of sync_all per file.
- What changes: per-file durability timing. Readback equality is still checked per file.
- D-6 (NOT ADOPTED). Subtract the routed zero-VDL payload ranges from the protected allocation bracket and compare.
- Benefit: about 2x fewer target-qualification reads at scale. Not required for unbounded capacity.
- D-7 (NOT ADOPTED). Post-commit verification records that reference the hash of the predicted expectation record when the observation matches, instead of the full observed record.
- It is lossless only if the predicted record provably covers every observed field. Until that is proven, it could drop native-only fields.
- D-8 (NOT ADOPTED). Batched per-move live rechecks, or sparser per-move source-exclusion checks, during placement.
- D-9 (NOT ADOPTED). Recording only digests instead of bytes for retrieval maps, descriptors, directory enumerations, page proofs or bitmap ranges, or summarizing per-object evidence into aggregates.
- D-10 (NOT ADOPTED). Deriving sparse-range content digests from the raw run map instead of natively reading the zeros.
- D-11 (NOT ADOPTED). Dropping one of the 4-5 full content passes (inspection stream digests, native logical reads, frozen recheck, mounted-file verification), or the repeated PinnedBacking and journal re-hashes at their barriers.
- D-12 (NOT ADOPTED). XXH3 instead of SHA-256 for bitmap, metadata, artifact or spill digests. The user's content-digest decision covers file contents only.
## STAGING
- S0 Native baseline of HEAD 4973f31 (no code).
Stage 1 (snapshot-per-phase placement, sweep, raised caps) is committed at 4973f31 but has not run natively.
Setup:
- Coordinate with the stage-1 owner (wf_40ba8e07-e64) and any VM work first.
- Freshly restore NTFS checkpoint 5f30f4a1, then verify parent and state from a new PowerShell process.
- Regenerate the seeded 808-file fixture with lab/New-MixedFixture.ps1 inside the storage epoch, after a lab/Lab.psm1 capacity check.
Record:
- the 52 GiB conversion's per-phase timeline (artifact LastWriteTimeUtc);
- the 808 outcome: full conversion, or the new refusal site and counters (expected: routes 4096 or bitmap 65,536 ranges), with the refusal before activation.
This fixes the baseline. Every later stage must match it, or move the 808 refusal downstream and still before activation.
- S1 Canonical sink, pins, record-only ledgers, native counters and lab knobs (C1; C4 and C5 in record-only mode; C6 skeleton).
Scope:
- Streaming tee save with .partial + rename, Pin{sha256, bytes, chunks}, and the digest-only sink at every to_vec site.
- capacity-plan.json and derivation.json written but not gating.
- Native counters: bitmap captures, bytes and ms; retrieval captures and extents; move count and ms; opens and held handles with pool usage; flushes; content bytes per pass.
- --lab-capacity-limit and --lab-spill-crosscheck in src/bin/lab-convert-native-composite.rs. src/main.rs is untouched.
Acceptance:
- 52 GiB: exit 0, 15/10, label and mount verified. Deterministic artifact pins are byte-identical to S0, and the expectation_pin cross-check passes.
- Each phase within about 1 s of S0.
- Interruption/resume/rollback matrix (lab/Start-AllocationInterruption.ps1, lab/Start-AllocationRecovery.ps1).
- 808: same outcome as S0, with counters recorded as the coefficient seed.
- Budget values plausible for the 4 GiB VM.
- S2 Invariant hardening before any cap is lifted (C2, the commit-point parts of C5, R9).
Scope:
- Bundle schema 2 with pinned reads.
- Recovery ranges taken from the journal record table.
- Post-commit artifacts and the verifier working set preallocated at G5.
- A per-attempt event log with the time-only stopping rule.
- One shared capacity function for the pre-write target observer and the post-handoff verifier, still carrying today's constants.
- Ledgers gating alongside the constants: refuse if either says no.
Acceptance:
- 52 GiB: full interruption/resume/rollback matrix, one hard TurnOff recovered from OFFLINE, and mutation plus cold restart (lab/Invoke-AllocationMutationReboot.ps1). Total at most about 42 s.
- 808: same outcome as S0, plus one interruption and resume if it converts.
- S3 Time hygiene with no evidence change (C8 indexes; C9 joins in RAM; path memo; partition_point lookups and WritePolicy; record coverage computed once; O(P + R) placement matching).
Acceptance:
- source_inspection_sha256, expected_tree_sha256 and the selection pins are identical to S2 on the same restored checkpoint and the same seeded 808 fixture.
- 52 GiB at or below the baseline.
- 808 phase times recorded; they should drop.
- S4 Evidence v2 (C3; artifact ceilings become SpaceLedger allocations; the lab-evidence verify/dump binary).
Acceptance:
- 52 GiB conversion plus the recovery matrix on the v2 readers.
- A run interrupted on the S3 build recovers on the S4 build through the schema-1 readers.
- lab-evidence verify passes on both fixtures' run directories.
- Artifact bytes drop 5-10x, and time stays at or below the baseline.
- S5 Shadow-side lift, landing coupled sets D (bitmap ranges), F (placement plus the route clamp, routes and supply) and G (exception and SVI) in one change (C12, C13, C15).
Scope:
- Range sidecars shared by source, shadow, witness and post-commit recapture; QuerySweep.
- Parallel dual-view capture with CNG.
- Placement v2: sweeps, the complete G3 plan before the first move, per-file LCN-ordered grouping, the strict-progress drift rule, deletion of every placement constant, and the route clamp removed together with the uncapped compact routes.
- The exact exception and SVI budget at G2.
- Shadow-only probes for the largest accepted move length and for allocation-free placeholders, recorded as scoped observations and adopted only if they confirm.
- S5b (optional): per-move page reuse.
Acceptance:
- 808 converts end to end, with interruption/resume and mutation plus restart.
- lab-evidence replay rebuilds every intermediate bitmap and retrieval state and matches every digest.
- --lab-spill-crosscheck gives equal plan pins in RAM and force-spilled within the same run, before the first move (ReFS allocation is not deterministic across runs).
- Placement counters (M, captures, seconds) compared with S0.
- 52 GiB shadow phase at most about 5.7 s.
- S6 Native observers and streamed attestation v2, landing coupled set E (C10, C11).
Acceptance:
- Both fixtures convert.
- Forcing a tiny reorder window and tiny segments gives the same native-source content pins as the unrestricted run on the same frozen source.
- Optional read-only lab observation of a scaled source shows a directory with more than 4096 entries observed completely.
- 52 GiB admission plus observation within about +0.5 s.
- S7 Streaming raw inspection, landing coupled set B (per-file runs) with the inspection caps (C7, the C8 store, C9 spill reconcilers).
Acceptance:
- source_inspection_sha256 is byte-identical to S6 on the same restored 52 GiB checkpoint and the seeded 808 fixture, both with and without forced spill.
- A stress variant of the 808 fixture, within the file-count caps (one file with at least 100k extents and free space fragmented to at least 70k gaps), converts end to end. Alternatively it refuses before activation, and only at the S8 range set, which is recorded.
- 52 GiB admission at most about 9.2 s.
- S8 Selection, journal and write-policy scale, landing coupled set C (C16, JournalProfile 3, the reference-file bound).
Acceptance:
- 52 GiB converts on N2RSEL01 with unchanged journal bytes.
- With N2RSEL02 forced: the interruption/resume/rollback matrix plus a hard TurnOff.
- The 808 and stress fixtures convert.
- Time at or below the baseline.
- S9 Count-free object pipeline, the last lift: coupled set A (C14), the ResourceBoundedV1 profile made mandatory, and AlphaV1 and the large-tree profiles frozen.
Acceptance:
- A scaled seeded fixture within the storage epoch converts with interruption/resume/rollback and mutation plus restart. It has about 20k files, at least 2.5k directories, depth at least 40, one directory with at least 10k entries, one file with at least 3k runs and at least 5k distinct descriptors.
- The forced-spill crosscheck gives equal tree and expectation pins.
- With --lab-capacity-limit below the projected need, the run refuses before shadow construction, and capacity-plan.json records why.
- 52 GiB stays at about 40 s.
- S10 Scale characterization (measurement only).
Fixture: about 200k-1M small or resident files plus a few highly fragmented files, on the 52 GB partition, on the 4 GiB VM so spill is forced, respecting the storage epoch (50 GB allowance, 17 GB minimum host free space). Evidence directories are cleaned up afterwards.
Measure:
- peak RAM, projected and from the counting allocator;
- evidence, spill, journal and VHDX disk use against the resource model;
- per-phase time, including the M x C/8 placement term.
Then recalibrate the coefficients, report the placement and content-pass terms to the user with the measured M and C so they can decide on D-1 through D-12, and record scoped observations in AGENTS.md and evidence/.
- S11 Decision-gated items, only after the user's explicit decision on each D-n.
- Each sits behind a recorded evidence mode.
- Acceptance: on the 808 and scaled fixtures, the final placements, selection, write set and verification results equal the default mode, and the speedup is measured.
- Separately, a product decision: whether the composite / whole-image path adopts C1, C3, C6 and C16 (one --whole-image-verification run on the 52 GiB fixture) or stays an explicitly bounded legacy mode.
## RISKS
- Canonical byte identity can drift. The hand-written Serialize for the columnar inventory, a changed field order, or a non-total sort key would silently change source_inspection_sha256 and every downstream pin.
Mitigations:
- S3, S6 and S7 accept only identical pins on the same restored source.
- The expectation_pin cross-check runs on every run.
- --lab-spill-crosscheck covers window and thread invariance.
Unit tests are excluded by the user's instruction, so these lab checks are the main guard.
- Placement time at multi-TB scale is dominated by checks that are kept: two whole-volume bitmap captures per move (M x C/8) and complete post-move maps (Σ K_f x R_f). A 16 TB / 1M-file conversion is resource-bounded, but at today's scope it may take days to months, with the source frozen and offline throughout. In-scope work cuts only constant factors; D-1 and D-2 are the real levers. The 4-5 content passes add about 10-20 h at 16 TB.
- Kernel pool for about 1M held exclusive handles is unmeasured, and the lab VM has 4 GiB. If it does not fit, the honest outcomes are a G1 refusal before any write, or user decision D-4.
- Admission now depends on measured RAM and disk, so the same volume can pass on one run and refuse on another. This is recorded in capacity-plan.json; the lab knob can only restrict.
Available memory can shrink after G1. Mitigations: the window is touched at G1, the verifier working set is reserved at G5, and allocations are fallible.
An OOM before activation is a crash, not a source write. Any allocation that bypasses the ledger (a serde Vec, a clone, a third-party buffer) can still abort the process; after activation that becomes an interruption that recovery handles.
- The OS volume is shared by spill runs, evidence, the packed backing, the journal and the dynamic shadow VHDX. Wrong coefficients cause late refusals, still before activation and shadow/scratch-only, but after hours of work. Mitigations: re-observation at every gate and the S10 calibration.
The VHDX 64 TB native maximum caps sources above about 64 TB until another scratch provider exists; CapacityBudget must refuse such volumes explicitly.
- Coupled-cap ordering. Lifting a pre-write cap without its post-commit or recovery twin would move a refusal after the ReFS commit: the finalization save, the verifier object or run caps, the converted-volume bitmap recapture, or recovery reads. Mitigations: S2 removes every post-write hazard first, R9 forces shared code, each coupled set A-J lands atomically, and admission counts are lifted last.
- Spill must never become authority or evidence. Future code that names a spill file in a pin, bundle or recovery input would break R3. A merge bug that ignored the block checksums could corrupt a proof before activation.
- Native behaviour at scale is unproven: FileIdExtdDirectoryInfo continuation on very large directories, FSCTL_QUERY_FILE_REGIONS FileOffset continuation, FileStreamInfo ERROR_MORE_DATA retry, GetKernelObjectSecurity sizing, ReFS retrieval maps with 1e5-1e6 extents, FSCTL_GET_VOLUME_BITMAP cost at multi-TB, publication latency on large hosts, and the two S5 probes (maximum move length, allocation-free placeholders). Every fallback is today's path.
- Recovery compatibility and cost. N2RSEL01 journals and v1 bundles from earlier builds must stay recoverable by their existing readers, and S4 tests this across builds. Recovery at scale is slower, because every pinned set is streamed and verified. Recovery on a machine with less RAM or disk than the conversion had may refuse; protection stays set and the operator must free resources. Recovery never clears protection and never starts a fresh Apply.
- Concurrent work. Stage 1 (4973f31) is committed but not run natively, and another agent may still be editing the placement files; S5 must rebase on its native outcome.
The user-owned src/main.rs hunk must never be edited, formatted, staged or reset. This design therefore routes every derived bound through ntfs_inspect, drive_cli and the lab binary.
- Schema bumps (hex fields, JSONL, sidecars, delta chains, Request/Report v2, bundle v2) change artifact formats. Old harnesses that pin old baselines and external review tooling must be updated, and reviewers depend on lab-evidence dump.
- Lab coverage is limited:
- Only two checkpoints remain.
- The storage epoch allows 50 GB with at least 17 GB host free.
- The VM is fixed at 4 GiB RAM and 4 CPUs.
- The scaled and stress fixtures need seeded regeneration and Hyper-V-managed checkpoints.
Claims about 16 TB, 1M files and 10M extents remain extrapolations. Every per-file, per-extent and per-move coefficient, the VHDX growth model and every time figure here is an estimate, not a measurement.
- Non-numeric gates will still refuse many real large volumes regardless of capacity: the geometry pins, attribute-list feature scope and the whole-volume IncompleteAttributeInventory propagation, hard links, ADS, reparse points, EAs, SACLs, DOS aliases, sparse data in lists, SVI admission scope, and the Windows build pin.
On the allocation path, refs_inspect anchor failures stay non-fatal, so selection completeness rests on the metadata-inclusive bitmap. That reliance must stay recorded, not silent.
## COMPONENTS
- C1 CanonicalSink, Pin and chunk table (new src/evidence/canonical.rs; general_qualification::save, general_recovery artifacts::save, every digest site): Writing:
- serde_json::to_writer(_pretty) writes into a Tee of a BufWriter<File>, a CNG SHA-256 and a byte counter, and returns Pin{sha256, bytes}.
- The file is created as today (create_new, share 0, write-through) under <name>.partial, then sync_all and a same-directory rename.
- It uses the same serializer and formatter, so bytes and pins are identical to today's BoundedJson path, and nothing is buffered whole. The existing expectation_pin == SHA-256(expected) cross-check proves this on every run.
- For any document larger than one chunk, the writer also emits <name>.chunks: the SHA-256 of each record-aligned 4 MiB chunk, itself pinned inside the Pin. Readers then verify each chunk before parsing it, while the whole-file SHA-256 stays the identity.

Other sinks:
- A digest-only sink replaces every SHA-256(serde_json::to_vec(..)) site with the same digest.
- The inspection pin is computed once and passed by value.
- A counting-only sink gives exact sizes for pre-write reservations (post-commit artifacts, allocation witness).

The 64 MiB ceilings stop being memory bounds. Each artifact's bound becomes its SpaceLedger allocation (C5), recorded next to its pin. [replaces: MAX_ARTIFACT_BYTES 64 MiB as an in-memory buffer bound (src/general_qualification.rs:33, :77-97); Protected allocation witness encoded-size check 64 MiB / 8 MiB no-profile (crates/n2r-win32/src/native.rs:2267-2277, :1312): counting sink, ranges charged to the RAM ledger; Freeze-witness 64 MiB size check (native.rs:1737-1745, lab); serialized_size_bounded as a memory bound (crates/n2r-win32/src/attestation.rs:855); (no constant) repeated whole-structure canonical digests: serde_json::to_vec(raw) / to_vec_pretty(expected) (ntfs_log.rs:46,185; ntfs_transactions.rs:160,173; ntfs_internal.rs:199,374,393; ntfs_admission.rs:1112,1139,1152; general_source_admission.rs:66,383; frozen.rs:107; general_composite_target.rs:157,507,838; general_target_preservation.rs:360,660; general_qualification.rs:293)]
- C2 PinnedReader and allocation recovery bundle schema 2 (src/general_recovery/allocation.rs HeldInput; bundle writer in src/general_conversion/allocation.rs): Pins carry {sha256, bytes, chunks}, and bundle schema 2 records them for every input. HeldInput takes its read bound from the pin: exact length, deny-write, single link, revalidated.

Reading is one pass: verify each chunk before parsing it, then check the whole-file SHA-256 at EOF. Chunk-verified records may feed read-only checks while the read is in progress. Any decision (resume, rollback, refusal) or write waits for the whole-file pin to match.

Recovery reads the range list from the journal's own record table, which ticket.immutable_sha256 already covers and load() re-verifies, and merge-checks it against the plan pin as a stream. Recovery therefore always reads what the conversion wrote.

Schema-1 bundles and N2RSEL01 keep their current readers. Bundle, request, ticket and verification keep their small structural bounds (64 KiB, 128 KiB, 64 KiB, 64 KiB), because their content does not grow with the volume. [replaces: Recovery expectation read cap 16 MiB (src/general_recovery/allocation.rs:129-133); Recovery plan read cap 16 MiB (src/general_recovery/allocation.rs:116); Write-cap / read-cap asymmetry for every growing recovery input (expectation, plan, finalization, completion)]
- C3 Evidence encoding v2: JSONL documents, BlobStore, EvidenceLog, delta chains, lab-evidence (new src/evidence/; new src/bin/lab-evidence.rs): Encoding (schema bumps, identical content):
- Vec<u8> fields become hex strings, 5-10x smaller than one-number-per-line pretty JSON.
- Documents whose element count grows with F, D, E or M become JSONL with:
  - a header: schema, derivation pin, and the expected counts derived from the raw inventory;
  - one canonical compact record per object, in strict key order with no gaps or duplicates;
  - a footer with counts and byte totals.
- These documents are native-source, source-basis, source-assessment, admitted-assessment, target-preservation, expectation, construction-private, construction-exceptions, construction-metadata, construction-placement, finalization and completion.

BlobStore: write-once, content-addressed blobs/<sha256> for large or repeated payloads. These are security descriptors (deduplicated), the MFT bitmap replay, attribute-list bytes, per-file retrieval maps and bitmap range sidecars. Records reference blobs by (sha256, bytes). Verification re-hashes each blob and requires every reference to resolve.

EvidenceLog: framed, append-only records for crash-relevant sequences (placement moves, native control events). Each record is synced before the next native step. Checkpoint records carry the SHA-256 of the file prefix. The sealed log is pinned like any file.

Delta chains (from design 1): a full initial state, then per-step deltas, with the full-state SHA-256 after every step. They cover:
- per-move post-move retrieval maps;
- per-move bitmap range views;
- the post-commit bitmap recapture against the pinned witness.
lab-evidence verify rebuilds every intermediate state and checks every digest. lab-evidence dump renders any set as pretty JSON for review.

Other changes:
- Parsed ACE structs are transient (parse, validate, hash, drop); raw descriptor bytes persist.
- SPLIT_ALLOWANCE_BYTES becomes an exact per-record charge. [replaces: MAX_SERIALIZED_REPORT_BYTES 64 MiB as the evidence ceiling (crates/n2r-win32/src/attestation.rs:12); MAX_ARTIFACT_BYTES 64 MiB for every O(F) document (native-source, target-preservation, expectation, construction-*, finalization, completion); MAX_PLACEMENT_ARTIFACT_BYTES 64 MiB - 64 KiB (crates/n2r-win32/src/shadow_native/private_tree/placement.rs:37; HEAD MAX_MOVE_EVIDENCE 16 MiB); SPLIT_ALLOWANCE_BYTES 64 MiB evidence reservation heuristic (placement.rs:48); ntfs_security::MAX_TOTAL_DESCRIPTOR_BYTES 4 MiB (src/ntfs_security.rs:436; src/ntfs_inspect.rs:2188); ntfs_security::MAX_TOTAL_ACES 65,536 (src/ntfs_security.rs:482; src/ntfs_inspect.rs:2189); Inline MFT bitmap replay hex and attribute-list hex in the report (src/ntfs_assembled_io.rs:179, :220); Composite-path twins delta/artifact.rs MAX_REPORT_BYTES 16 MiB and persist_delta_artifact 16 MiB, only where the writer code is shared]
- C4 CapacityLedger, pinned derivations, gates G0-G5 and measured cost coefficients (new src/capacity.rs; n2r-win32 measurement; drive_cli, ntfs_admission, compact_construction, general_conversion/allocation; lab flags in src/bin/lab-convert-native-composite.rs): Measurement:
- GlobalMemoryStatusEx (available physical memory and commit headroom), minus a fixed safety reserve.
- Spill window W = a policy fraction of available memory (default 1/4, recorded), allocated and touched at G1, so later memory pressure cannot make the budget lie.

Derivations:
- After the raw pass the ledger writes derivation.json. It holds the exact counts (F, D, R, N, E, S, Sb, R_max, N_max, residual and SVI bytes, MFT records, bitmap bytes) and the projected per-phase RAM, disk and time.
- It also writes capacity-plan.json with budgets, reserves and any restrict-only lab limit.
- Both are pinned and bound into the admitted assessment, which the live certificate already binds.
- Every former constant becomes f(derivation, plan), and validators recompute it (R1).

Cost coefficients:
- Bytes per record, extent, name, descriptor, ObjectReport and held handle (kernel pool); ms per move, bitmap capture and open.
- Seeded from the S1 native counters and recorded per run.
- A coefficient that is too low stays safe, because ledger exhaustion refuses before activation.

Charging:
- LedgeredVec, RangeStore and the inventory columns charge on try_reserve and choose either RAM or spill.
- Exhaustion is a typed refusal, never an allocator abort.
- A counting global allocator records measured peak against projected peak.

Gates G0-G5 are as listed in the architecture. Time is projected and recorded, never a refusal criterion.

Profiles:
- ResourceBoundedV1 is the drive profile, and it is non-optional at the type level, so the None fallbacks cannot come back.
- AlphaV1, ExperimentalLargeTreeV1 and ExperimentalStreamingTreeV2 are frozen for replaying old evidence. ResourceProfile::default() is never used implicitly.
- The drive_cli 4 GiB minimum working-space check becomes the derived need.

src/main.rs is not edited (the user-owned hunk). Its inspect CLI inherits the derived defaults through ..InspectionLimits::default(), and its explicit MiB flag stays an operator-chosen, restrict-only budget. [replaces: AlphaV1 MAX_FILES 128 / MAX_DIRECTORIES 32 / MAX_LOGICAL_BYTES 256 MiB and the silent ResourceProfile::default() (src/ntfs_admission.rs:18-20); ExperimentalLargeTreeV1 limits (crates/n2r-win32/src/attestation.rs:42; src/ntfs_inspect.rs:57-58); Latent no-profile fallbacks MAX_LIVE_PARTITION_BYTES 128 GiB and 8 MiB witness (crates/n2r-win32/src/general_layout.rs:9; native.rs:1312, :2176); drive_cli 4 GiB minimum working-space check (src/drive_cli.rs:448-451); CLI maximum_placement_submissions pinned to the MAX_PLACEMENT_SUBMISSIONS constant (src/drive_cli.rs:541-542; src/general_qualification/compact_construction.rs:21), now the derived G3 plan]
- C5 SpaceLedger and commit-point discipline (src/capacity.rs; drive_cli journal sizing; general_conversion/allocation; general_reconstruct; n2r-win32 native.rs events; journal_file.rs; reference_file.rs; managed_shadow.rs): Accounts:
- One account for the OS/run volume: evidence, spill, packed backing, the managed-shadow VHDX and, on the drive path, the journal.
- One account for the shadow volume.
- Each is measured with GetDiskFreeSpaceEx at G0 and re-observed at every gate.

Exact needs:
- journal = 8 KiB + 80 B x (X+2) + 2B, with no fixed 16 MiB reserve;
- packed backing = B;
- exception supply = exact residual + SVI bytes, checked against shadow free space;
- artifacts = counting-sink sizes;
- VHDX growth: bounded by partition + 64 MiB until construction ends, then taken from the measured allocated size, so the journal is sized from what actually remains.

Journal and reference file:
- JournalProfile schema 3 sets the changed-byte ceiling to journal-volume free space, minus the reserve and minus the remaining phases' needs. It is checked at G4 and re-observed in recovery; the format is already u64.
- The reference-file bound comes from the OS-volume account.

Commit point (R4):
- At G5, finalization, completion and result files are preallocated (FileAllocationInfo) to their counted upper bounds, which include full per-object verification records. They are written in place and truncated to their actual length.
- The post-handoff verifier's RAM working set is reserved at G5.

Native control audit:
- Each rediscovery attempt gets its own bounded event Vec, appended to an EvidenceLog.
- The documented 60 x 250 ms wait is the only stopping rule, so the audit size can never shorten the wait after commit. [replaces: CompactConstructionBudget.maximum_exception_bytes 16 MiB default / 64 MiB maximum, and the 2x source-read budget (src/drive_cli.rs:543; src/general_qualification/compact_construction.rs:18, :100-112), shared with C15; JournalProfile MAX_EXPERIMENTAL_JOURNAL_BYTES 16 GiB, max_changed_bytes, JOURNAL_OVERHEAD_RESERVE 16 MiB (crates/n2r-win32/src/journal_file.rs:21, :23, :39-47, :263; src/general_conversion.rs:71; src/lab_reconstruct.rs:45-47; native.rs:293-294); drive_cli journal sizing (available - reserve)/3 capped at 16 GiB (src/drive_cli.rs:452-457); reference_file::MAX_REFERENCE_FILE_BYTES 128 GiB + 512 (crates/n2r-win32/src/reference_file.rs:6, :61; src/general_composite_target.rs:40-66, :828); Unbudgeted OS-volume working space and dynamic managed-shadow VHDX growth (crates/n2r-win32/src/managed_shadow.rs:511-541; src/drive_cli.rs:492-497; src/general_conversion/composite.rs:106-117 space_reserved false); finalization.json / completion.json saved after HND under the 64 MiB save (src/general_conversion/allocation.rs:265; src/general_recovery/allocation.rs:350); Native event audit budget of 128 events shared across the post-handoff rediscovery loop (native.rs:323, :434, :887-977)]
- C6 Spill tier and sorted-stream primitives (new src/spill module, shared with crates/n2r-win32 through a small internal crate if needed): ExternalSorter:
- Keeps one in-RAM run while the data fits within the ledger share.
- Otherwise it writes sorted run files to a per-run scratch directory on the OS volume (share 0, delete-on-close, SHA-256 per 1 MiB block) and k-way merges them.
- Fan-in is W/(2 x 1 MiB), so at most 2 passes are needed up to W^2/2 MiB of records.

The order is total: a memcmp key plus a full-record tiebreak. Output is therefore independent of W, run boundaries and thread count (R8).

Combinators:
- merge-join, group-by, anti-join and dedup, each checking strict order and uniqueness as it reads;
- interval algebra (coalesce, union, subtract, intersect) over sorted (offset, length) streams;
- RangeStore: 16 B ranges in RAM, or spilled with a sparse fence index of 1 key per 4096 records;
- an ordered reorder buffer for parallel producers, with byte backpressure;
- point lookups through partition_point in RAM, or the fence index when spilled.

Spill files never become authority or evidence (R3).

--lab-spill-crosscheck: selected structures are computed in RAM and force-spilled in the same run, and any pin difference refuses. [replaces: (implicit) every all-in-RAM Vec or BTreeMap that grows with F, N, E, S, M or X, which has no constant of its own. This is the mechanism C7-C16 use to remove their counts.]
- C7 Streaming NTFS block readers and the per-file run coupled set (src/ntfs_index.rs, ntfs_namespace.rs, ntfs_security.rs, ntfs_attribute_list.rs, ntfs_mft_bootstrap.rs, ntfs_assembled_io.rs, ntfs_log.rs, ntfs_internal.rs, ntfs_inspect.rs, ntfs_stream_plan.rs; crates/n2r-win32/src/shadow_native.rs:2811): Index walker:
- ntfs_index reads through a BlockSource (read slot n from the run list, fixup per slot as today) instead of one whole-allocation slice.
- walk() becomes an explicit heap stack bounded by the allocated-block count; the seen set still catches cycles.
- Entries are emitted in order through a callback, so collation order is checked between consecutive keys with O(depth) memory.
- The index bitmap streams alongside the slots, bounded by ceil(slots / 8).
- The per-node entry bound stays format-derived: block bytes / minimum entry size.
- $I30, $SII/$SDH, $Quota $Q/$O, $ObjId and $Reparse all use this walker, so INDEX_ALLOCATION is supported. Per-entry checks are unchanged.

Other metadata readers:
- $SDS is parsed one 512 KiB primary/mirror pair at a time, with an incremental hash.
- $LogFile streams through copy_plain_stream_with_budget into SHA-256, keeping the first 8 KiB for parse_restart_pair. log_file_sha256 is unchanged.
- The MFT record bound becomes $MFT DATA logical size / record size (at most 2^32). The MFT bitmap and the per-record ancestry state are charged to the ledger or read through a fixed window. The ancestry stack is bounded by files.len().

Per-file run set (lands atomically in S7):
- Attribute-list bytes are bounded by the attribute's validated logical size, with entries streamed from the mapped list.
- Extension records are bounded by the entry count (at most list bytes / 26).
- Runs are charged to the ledger, with per-run validation unchanged.
- The literal 1024s are deleted.
- ntfs_stream_plan validates every run with no 1024 fallback to materialize.
- shadow_native.rs:2811 validates each object's NTFS source runs in one sorted pass with no count. It is shared by target qualification and the post-handoff verifier, so the refusal can never move after commit.

The same bytes are hashed in the same order, so digests and the inspection schema are unchanged. [replaces: ntfs_index::MAX_INDEX_BYTES 16 MiB per allocation (src/ntfs_index.rs:4, :318); ntfs_namespace::MAX_INDEX_BYTES 16 MiB global namespace read budget (src/ntfs_namespace.rs:12; src/ntfs_inspect.rs:1873, :1946); Index bitmap <= 4096 B (src/ntfs_index.rs:321; src/ntfs_inspect.rs:1955, :2163); ntfs_index MAX_DEPTH 64 recursion (src/ntfs_index.rs:6, :238), now an explicit stack bounded by allocated blocks; ntfs_index::MAX_ENTRIES 16,384 per index / per node / walk output (src/ntfs_index.rs:5, :133, :255, :347); ntfs_security::MAX_METADATA_BYTES 16 MiB (src/ntfs_security.rs:12, :410; src/ntfs_inspect.rs:2104, :2145, :2153, :2210); ntfs_log::MAX_LOG_BYTES 128 MiB (src/ntfs_log.rs:11, :148, :177) and ALPHA_MAX_PLAIN_BYTES 256 MiB (src/ntfs_inspect.rs:26, :2346); supported_quota entries <= 128 and resident-only $ObjId/$Reparse/$Quota indexes (src/ntfs_internal.rs:220, :307-327); ntfs_attribute_list::MAX_LIST_BYTES 65,536 (src/ntfs_attribute_list.rs:12, :55, :158; ntfs_mft_bootstrap.rs:208; ntfs_assembled_io.rs:77, :179); ntfs_attribute_list::MAX_EXTENSION_RECORDS 1024 and literals (ntfs_attribute_list.rs:13, :297; ntfs_mft_bootstrap.rs:221; ntfs_assembled_io.rs:85, :179); ntfs_attribute_list::MAX_RUNS 1024 and literals (ntfs_attribute_list.rs:14, :229, :491; ntfs_mft_bootstrap.rs:60, :282; ntfs_assembled_io.rs:95, :126); ntfs_stream_plan adoptable-run cap stream.extents.len() <= 1024 (src/ntfs_stream_plan.rs:97); Per-file NTFS source runs > 1024 in native shadow input (crates/n2r-win32/src/shadow_native.rs:2811, HEAD :2808); MAX_MFT_RECORDS 1,000,000 (src/ntfs_inspect.rs:21, :1498; ntfs_mft_bootstrap.rs:175, :190; ntfs_attribute_list.rs:167, :174; ntfs_assembled_io.rs:157-159, :220); MAX_METADATA_ANCESTRY_DEPTH 4096 (src/ntfs_inspect.rs:1421, :1511, :1597)]
- C8 Columnar inventory store, indexes and time hygiene (src/ntfs_inspect.rs, ntfs_admission.rs, ntfs_source_view.rs, ntfs_namespace_attestation.rs, general_shadow*, general_composite_target.rs, compact_construction.rs): Store:
- NtfsInspection keeps its serialized schema. In memory it becomes a columnar store: fixed-size file records, interned names, extents stored once (not cloned twice), a dense record_number-to-index table (4 B per MFT record) and parent links from the ancestry classifier.
- A hand-written Serialize walks the store in today's field order, so serde output, source_inspection_sha256 and every derived pin are byte-identical. This is checked on every stage against the same restored source.
- Above its ledger share, columns spill through C6.
- ReportBudget becomes ledger charges with geometric growth, replacing the 64-slot try_reserve_exact pattern and its O(n^2) copying.
- max_stream_hash_bytes becomes the sum of logical sizes from the metadata pass: every logical byte once per pass.

Lookups and reuse:
- path() is memoized from the parent chain, O(F) total.
- read_attribute_range uses partition_point.
- validate_record_coverage runs once per inspection, and checked_plain_attribute reuses that result and the MFT bootstrap instead of rereading them.
- internal_role reuses one role table instead of whole-volume rescans.
- Every raw.files find or filter uses the record index. [replaces: InspectionLimits.max_report_bytes 64 MiB, all profiles (src/ntfs_inspect.rs:42, :57, :61; ReportBudget :94-131); InspectionLimits.max_stream_hash_bytes 8 PiB / 16 GiB / 1 GiB (src/ntfs_inspect.rs:43, :58, :62, :73-85, :1311, :1317; src/main.rs:236-247 inherits without an edit); (no constant) ReportBudget::push O(n^2) growth (src/ntfs_inspect.rs:114); (no constant) path() per-call BTreeMap rebuild O(F^2 log F) (src/ntfs_admission.rs:508); (no constant) read_attribute_range linear extent search per MFT record (src/ntfs_inspect.rs:975); (no constant) validate_record_coverage O(F x A) rerun with an MFT bootstrap reread per checked_plain_attribute (src/ntfs_inspect.rs:2325-2358); (no constant) internal_role whole-volume rescans in ntfs_transactions (6), ntfs_internal (4), ntfs_source_view and namespace attestation; (no constant) linear finds in assess_source_view_profile (src/ntfs_admission.rs:858-900), user_issues (:665-671), ntfs_source_view::diagnose (:219-243, :282-289), check_directory_view (src/ntfs_namespace_attestation.rs:146, :262); (no constant) raw.files scans per route or object (src/general_shadow/source_backed.rs:235-239; src/general_composite_target.rs:568-576; src/general_qualification/compact_construction.rs:117-121; src/general_shadow.rs:139-143, :245-249)]
- C9 Sorted-merge reconcilers (src/ntfs_allocation.rs, ntfs_namespace.rs, ntfs_security.rs, ntfs_attestation.rs, ntfs_data_attestation.rs, ntfs_stream_attestation.rs, shadow_tree.rs): Every reconciler compares exactly the same fields as today, and detects missing, extra and duplicate keys exactly as the current set equalities do. Each runs in RAM when it fits and through C6 otherwise.

Allocation:
- Intervals carry owner names interned once per (record, instance).
- They are sorted by (owner, VCN) for the overlap and continuity checks, and externally by LCN for the existing 64 KiB-window $Bitmap sweep.
- The index-permutation vector is gone.
- max_bitmap_bytes and max_cluster_checks come from the partition.

Namespace:
- MFT name tuples and $I30 tuples (parent, child, namespace, name) form two sorted streams under the same $UpCase collation and are merge-compared for exact equality.
- Reachability comes from the O(F) ancestry classifier (a directory has exactly one parent) instead of an edge BFS.
- Per-directory collation stays a local in-order check.

Security:
- An id-to-(header, descriptor SHA-256, blob ref) map, about 48 B per descriptor.
- $SII/$SDH are merge-joined by id and by hash.
- bind_files streams the files and appends (record, sequence, id, sha256) bindings to a digest-bound list.

Identity joins: the raw/native joins and bind_security_views become merge-joins on (record, sequence), with duplicate detection and the exactly-one-match and matched checks unchanged. [replaces: ntfs_allocation Limits::default().max_intervals 4096 (src/ntfs_allocation.rs:36, :404; src/ntfs_inspect.rs:1698, :1732); ntfs_allocation max_total_name_units 16,384 (src/ntfs_allocation.rs:39, :428; src/ntfs_inspect.rs:1737); ntfs_allocation max_sort_bytes 32 KiB (src/ntfs_allocation.rs:40, :407-413, :456-462); ntfs_allocation default max_bitmap_bytes 2 MiB / max_cluster_checks 16M (already overridden at src/ntfs_inspect.rs:1694-1697; now derived); ntfs_namespace::MAX_ENTRIES 16,384 global (src/ntfs_inspect.rs:1977; src/ntfs_namespace.rs:159, :216, :261); ntfs_namespace::MAX_NAME_UNITS 131,072 (src/ntfs_inspect.rs:1971-1977; src/ntfs_namespace.rs:107, :215); ntfs_namespace::MAX_DIRECTORIES 4096 (src/ntfs_inspect.rs:1909; src/ntfs_namespace.rs:159); ntfs_security::MAX_DESCRIPTORS 16,384 central and legacy (src/ntfs_security.rs:15, :436; src/ntfs_inspect.rs:2229); MAX_DESCRIPTORS reused as a file-count cap in bind_files (src/ntfs_security.rs:499); (no constant) quadratic ntfs_attestation::compare (src/ntfs_attestation.rs:437-444); (no constant) quadratic ntfs_data_attestation::reconcile (src/ntfs_data_attestation.rs:208-215); (no constant) quadratic ntfs_stream_attestation::reconcile (src/ntfs_stream_attestation.rs:424-431); (no constant) quadratic Tree::bind_security_views, run twice on the default path (src/shadow_tree.rs:41-49) and linear lookups (:332, :337, :366)]
- C10 Paginated native observers (crates/n2r-win32 namespace_layout.rs, namespace_native.rs, retrieval_paging.rs, stream_layout.rs, stream_native.rs, region_layout.rs, attestation_native.rs, bitmap_streaming.rs; shadow_native.rs enumerate/regions; cache_refresh.rs; private_tree/system_payloads.rs): Every native enumeration becomes an iterator that runs to its terminal native status. Strict progress is required, and the termination bound is derived from the raw inventory instead of a constant. Fixed buffer sizes stay only as page sizes. These rules cover the NTFS source, the shadow, and the post-commit verifier, which share the code.

Directory enumeration:
- Runs to error 18.
- Non-terminal batches must be non-empty, with no repeated file ids, and calls <= 2 x raw entries + slack. CAPACITY 64 KiB stays as the page size.
- Native children are merged against the raw entries, spill-sorted when the native order differs.
- A parent-to-children index replaces the per-directory scans.

Retrieval pointers:
- Continue until success without ERROR_MORE_DATA, with strictly advancing VCNs and consistent overlaps.
- Page proofs append to the EvidenceLog.
- The 1024-extent response is only a buffer size.
- Complete extents live in a ledger-charged Vec (16 B each) or spill.
- The canonical map gets a framed u64 count under a schema bump, used only when the count exceeds u32.

Volume bitmap: max_pages = ceil(bitmap bytes / minimum accepted page progress), and the returned-bytes bound comes from the cluster count.

Other calls:
- FSCTL_QUERY_FILE_REGIONS continues from the end of the last region until EOF, with contiguity and flag checks.
- FileStreamInfo retries ERROR_MORE_DATA with a doubled buffer up to the exact bound derived from the raw stream count and names, and the stream count is cross-checked against the raw inventory.
- Security descriptors are queried for their required length and allocated exactly, up to the structural maximum 20 + 2 x 65,535 + 2 x 68.
- Named streams open relative to the already-open file handle (NtCreateFile RootDirectory), keeping the class-18 identity check.
- The ioctl_bytes serde cap tracks the chosen page size. [replaces: namespace_layout::MAX_ENTRIES 4096 per directory pass, source and shadow (namespace_layout.rs:6, :38, :107; src/ntfs_namespace_attestation.rs:170; shadow_native.rs:1486-1517, :3354; cache_refresh.rs:167); namespace_layout::MAX_CALLS 64 x CAPACITY 64 KiB (namespace_layout.rs:7, :76; attestation.rs:839; namespace_native.rs:63, :95; shadow_native.rs:1488, :1517), plus the off-path MAX_EVIDENCE 2 MiB; stream_layout::MAX_COMPLETE_EXTENTS 65,536 per stream, source and every shadow retrieval_capture (stream_layout.rs:8, :116, :124; retrieval_paging.rs:10, :168; src/ntfs_stream_attestation.rs:165; src/general_target_preservation/allocation.rs:229; shadow_native.rs:673, :751, :3376); retrieval_paging MAX_PAGES 128 / MAX_RETURNED_BYTES 2,099,232 (retrieval_paging.rs:12-14, :94-118; attestation.rs:821-822; src/tree_placement.rs:51); stream_layout::MAX_EXTENTS / RETRIEVAL_CAPACITY 1024 per response, coupled with MAX_PAGES (stream_layout.rs:5-6; retrieval_paging.rs:11, :60; attestation.rs:825): kept as page size only; bitmap_streaming source_limits().max_pages 131,072 / max_returned_bytes (bitmap_streaming.rs:163-168, :113-127, :234-242); MAX_SECURITY_BYTES 64 KiB per descriptor (attestation.rs:6, :804-807; attestation_native.rs:166, :188-202); stream_layout::MAX_STREAMS 64 (stream_layout.rs:3, :51; attestation.rs:706, :813); stream_layout::MAX_STREAM_BUFFER 64 KiB one-shot FileStreamInfo (stream_layout.rs:4, :44; stream_native.rs:352; attestation.rs:814; shadow_native.rs:1589, :1724, :3473; cache_refresh.rs:143, :255, :456; system_payloads.rs:100); region_layout 1024-row cap and the FSCTL_QUERY_FILE_REGIONS 16 + 24 x 1024 buffer (region_layout.rs:22, :28; shadow_native.rs:3422); stream_native named-stream path buffer 32,768 UTF-16 units (stream_native.rs:201, :214, :230); attestation.rs:322 ioctl_bytes serde cap = bitmap PAGE_BYTES (now tracks the page size); (no constant) per-directory O(N) child scans (shadow_native.rs:1207; cache_refresh.rs:188)]
- C11 Streamed native attestation v2 (crates/n2r-win32 attestation.rs, attestation_native.rs, stream_native.rs, namespace_native.rs, logical_hash.rs, general_layout.rs; src/ntfs_attestation.rs, ntfs_admission.rs, ntfs_stream_plan.rs): Request and Report:
- Request v2 carries the inspection pin, the derivation pin, the identity count and an identity-list digest instead of an identity vector.
- The observer walks identities in record order from the inventory, using T lanes and the C6 reorder buffer.
- Each identity's observation, logical hashes, stream captures and both namespace passes are reconciled against the inventory in process as they arrive, then tee'd to the EvidenceLog.
- Report v2 is a manifest: counts, byte totals, measured resources and the log pin.
- request.clone() and report.request == request become pin comparisons.
- The opaque live observation keeps only pins and counts.

Security: each file records a digest reference per view and snapshot, and each distinct descriptor is stored once in the BlobStore. Raw and native descriptors are still compared per file, exactly as today.

Single content pass: recorded as content_passes = 1 without cloning 'before' into 'after'. The validator already enforces the mirror rule, so this frees capacity without dropping evidence.

Envelopes are derived from the inventory, recorded in the request and recomputed by validate_resources:
- logical read bytes = sum of (logical size + 1) per pass;
- read calls = chunks + EOF probes + interrupt slack;
- per-stream bound = the partition;
- partition and bitmap bounds = the actual cluster count, keeping the u64/i64 overflow checks. [replaces: Native ResourceLimits.maximum_identities 2048 (attestation.rs:42, :51, :170; src/ntfs_attestation.rs:103-106); Native ResourceLimits.security_bytes 32 MiB (attestation.rs:55, :493-495, :760; attestation_native.rs:486); Native ResourceLimits.stream_evidence_bytes 64 MiB (attestation.rs:56, :498-556, :761; attestation_native.rs:455-520; stream_native.rs:424-431); Native ResourceLimits.namespace_evidence_bytes 16 MiB (attestation.rs:57, :593-601, :763; namespace_native.rs:64-66, :100); MAX_SERIALIZED_REPORT_BYTES as the whole-report memory and size bound, and native-source.json under the 64 MiB save (attestation.rs:12, :855; attestation_native.rs:565; native.rs:2154; src/ntfs_admission.rs:1134; src/ntfs_stream_attestation.rs:74); MAX_TOTAL_BITMAP_BYTES 16,781,568 (attestation.rs:10, :762; attestation_native.rs:514-517); Logical-read envelope logical_read_bytes / maximum_stream_bytes / logical_read_calls and the logical_hash MAX_CALLS floor (attestation.rs:52-54, :773-791; logical_hash.rs:9, :72-142); bitmap_streaming::MAX_STREAM_BITMAP_BYTES 64 GiB and general_layout::MAX_EXPERIMENTAL_PARTITION_BYTES 2 PiB (bitmap_streaming.rs:14, :204; general_layout.rs:12-13; attestation.rs:141); ntfs_admission ResourceLimits.maximum_logical_bytes / maximum_stream_bytes = 2 PiB (src/ntfs_admission.rs:88-89; src/ntfs_stream_plan.rs:132, :168); (capacity multiplier) single-content-pass mirror clone counted and serialized twice (attestation_native.rs:459-461); Legacy off-path attestation MAX_FILES 256 / MAX_TOTAL_SECURITY_BYTES 4 MiB / MAX_TOTAL_STREAM_BYTES 8 MiB / logical_hash DEFAULT_LIMIT 1 GiB (frozen for schema 1-2 readers only)]
- C12 Bitmap RangeStore, QuerySweep and capture acceleration (crates/n2r-win32 bitmap_streaming.rs, bitmap_observation.rs, bitmap_layout.rs, retention_layout.rs, native.rs protected allocation, shadow_native.rs converted verifier): Range sidecar:
- While a capture streams, its maximal allocated ranges are written to a sorted sidecar blob of 16 B records. The sidecar's count and SHA-256 are bound into the Summary (schema bump).
- An in-RAM copy is kept only within the ledger share.
- Summary::validate streams the sidecar, and candidate() uses partition_point or the fence index.
- This one shared type covers the NTFS source observation, every shadow view, the protected witness and the post-commit converted-volume recapture. Pre-write capacity therefore always equals post-commit capacity (R9).
- The post-commit recapture is stored as a delta against the pinned witness, plus the SHA-256 of the full reconstructed list.

QuerySweep answers sorted allocation queries during one streamed pass, so no capture needs to retain its ranges:
- per-move destination freeness in both views;
- per-object CandidateReport;
- metadata-allocation membership.
The witness size comes from the counting sink.

Capture acceleration (design 2), same digests and same evidence:
- Both views are captured in parallel on separate volume handles.
- The three SHA-256 streams per capture are pipelined on separate cores using CNG, which measured about 511 MB/s per core against 300 MB/s for software sha2 on the lab CPU.

Optional S5b: page reuse. Every page is still read natively. Each new page is compared bytewise with the previous capture's page, and only changed pages are re-hashed. Per-move captures are committed by a domain-separated Merkle root over page digests (schema bump). The flat canonical SHA-256 is kept wherever the witness, target preservation and verification cross-reference it.

BitmapModel: the phase snapshot plus verified own moves. It drives planning and is cross-checked against every live capture. Foreign allocations are recorded as evidence and trigger a re-plan. It never replaces a live capture unless the user approves decision D-1. [replaces: bitmap_streaming source_limits().max_allocated_ranges 65,536 at every default-path site (bitmap_streaming.rs:131, :173, :265-267; stream_native.rs:76-79; attestation_native.rs:384, :508; bitmap_observation.rs:73-76; retention_layout.rs:74; native.rs:1615, :2193; placement/unwritten/source_backed/run_role_profile captures); bitmap_layout AllocationMap interval cap 65,535 and push_range (bitmap_layout.rs:112); placement MAX_SCRATCH_INTERVALS 2 x 65,536 + ranges + 2 (placement.rs:41); shadow_evacuation plan_ranges MAX_MAP_RANGES 262,144 (shadow_evacuation.rs:104, :120, :127); Protected allocation witness range-list size (native.rs:1738, :2268); Converted-volume verifier bitmap recapture under the 65,536 cap after HND (shadow_native.rs:3282-3298), now symmetric with the pre-write witness; (time only) per-move whole-volume bitmap re-hash cost (shadow_native/unwritten.rs:425-430): constant-factor reduction, same evidence; Legacy bitmap_paging MAX_DATA_BYTES 4 MiB / MAX_PAGES 8 / OneTiB 32 MiB and check_bitmap_pages for schema < 9 (frozen for old readers)]
- C13 Placement planner v2, native-work-first (crates/n2r-win32/src/shadow_native/private_tree/placement.rs, unwritten.rs, shadow_evacuation.rs, retention_layout.rs, private_tree.rs; src/drive_cli.rs; src/general_qualification/compact_construction.rs). Builds on 4973f31.: This keeps stage 1 as committed in 4973f31: one snapshot per phase, owned filtered to desired intersections, sweep-line, first-fit cursor and coalescing.

Sweeps:
- Desired, tracked, owned, avoid, scratch occupancy and free subruns become RangeStores.
- Intersection, plan_ranges and free-subrun planning are single LCN-ordered sweeps, O(E + R) with no restart per desired run.

Planning before the first move (G3):
- The planner computes the complete deferred + evacuation + final plan from the snapshots, with its exact submission count, exact evidence bytes (fixed record size plus planned map delta, pages = ceil(extents / 1024) + 1) and a time estimate. All are checked against the ledgers and recorded.
- CompactConstructionBudget becomes a policy. maximum_placement_bytes = partition x 4 is kept, and submissions are derived. drive_cli and compact_construction validate derived <= policy instead of pinning a constant.

Move execution (design 2):
- Moves are grouped per file and ordered by destination LCN, so one hot handle and one current map serve each file's consecutive moves.
- Tracked placements are a sorted Vec, merge-matched against the sorted retrieval runs: O(P + R) instead of O(P x R).
- MOVE_BYTES becomes the largest FSCTL_MOVE_FILE length that a shadow-only probe accepts, at most u32 clusters and clipped to the run. It is only a performance setting.

Allocation-free placeholder probe (shadow-only):
- If ReFS leaves the 4 KiB-aligned prefix unallocated (deferred holes), each desired run becomes one DEFERRED_ORIGINAL move, and initial ReFS runs stop blocking other files.
- Adopted only if the probe confirms it and every proof is unchanged; otherwise today's tracked allocation plus selective evacuation.
- Results are recorded as scoped observations.

Drift:
- Re-plan from a fresh snapshot while each re-plan follows at least one verified move or strictly shrinks the remaining plan. This is bounded by M + phases and replaces the fixed 8.
- Every re-plan re-runs G3.
- Lost coordinates fall to scratch and become copy routes.

Per-move proof, unchanged:
- the pre-move verify_placements recapture;
- both live whole-volume bitmap captures with digests;
- the native result;
- the complete post-move retrieval map;
- all-placements-match.
Each move is appended and synced to the placement EvidenceLog before the next move, with its map stored as a delta plus the full-map SHA-256.

Other changes:
- The per-file submission and placement caps, the subrun cap and the evacuation ceilings are deleted; the caller's derived plan is the bound.
- The route clamp (DOWNSTREAM_ROUTE_LIMIT / MAX_ADMITTED_RANGES) is removed in the same change that uncaps routes in C15, never before.
- Object-index casts are checked. [replaces: MAX_PLACEMENT_SUBMISSIONS 32,768 (HEAD-era 1024) (private_tree.rs:20-22; placement.rs:8 MAX_MOVES; src/drive_cli.rs:541-542; compact_construction.rs:21); MOVE_BYTES 512 MiB per submission (placement.rs:6); MAX_PLACEMENT_RANGES 16,384 (HEAD-era avoid > 1024) (placement.rs:12); DOWNSTREAM_ROUTE_LIMIT 4096 / MAX_ADMITTED_RANGES clamp (placement.rs:17-23), removed together with C15 routes; MAX_TRACKED_EXTENTS 2 x MAX_MOVES (placement.rs:26); MAX_OWNED_RANGES = MAX_MOVES (placement.rs:30; HEAD-era owned > 1024, the 808-file refusal at placement.rs:350); MAX_DRIFT_REPLANS 8 (placement.rs:44), replaced by a strict-progress rule; Placement evidence reservation sized from retrieval_paging::MAX_PAGES pages (placement.rs, reservation path); shadow_evacuation MAX_EXTENTS 65,536 / MAX_MOVES 32,768 / max_blocked ceiling (shadow_evacuation.rs:10, :12, :109-113, :206, :323); plan_ranges MAX_BYTES 2 PiB (shadow_evacuation.rs:105; unwritten.rs:117-118), now from the partition; retention_layout MAX_SUBRUNS 32,768 (HEAD-era 1024) (retention_layout.rs:12, :57, :88, :153, :206); unwritten MAX_FILE_SUBMISSIONS 32,768 per placeholder (unwritten.rs:24, :359-361); unwritten MAX_FILE_PLACEMENTS 4096 and O(P x R) matching (unwritten.rs:30, :419-426, :619-628); (no constant) plan_free_subruns_streamed O(E x R) restarts; (no constant) unchecked object-index cast as u32 (placement.rs object index sites); Legacy shadow_evacuation MAX_SCAN_CLUSTERS 16M / MAX_EVACUATION_BYTES 256 MiB and legacy retention MAX_RETENTION_ATTEMPTS 1024 / 8 MiB / 4 MiB / LEGACY_MAX_* (shadow_native.rs:517, :520, :3140-3141): off path, frozen]
- C14 Count-free object pipeline and level-ordered construction (src/ntfs_admission.rs, shadow_tree.rs, ntfs_stream_plan.rs, general_recovery/allocation.rs; crates/n2r-win32 shadow_native/private_tree.rs, cache_refresh.rs, shadow_native.rs run_role_profile, shadow_native/unwritten.rs): Profile and counts:
- A count-free ResourceBoundedV1 profile replaces ExperimentalStreamingTreeV2 on the drive path. Feature and format gates are unchanged.
- Every object-count check is deleted in one change across the admission resource_limits gate and bind_large_native_profile, ntfs_stream_plan:133, shadow_tree ExpectedTree validation, private_tree allocate_checked and observe_existing, run_role_profile, cache_refresh complete_owned_metadata, and recovery validate_with_resource_profile.
- The source gate, target qualification, the post-handoff verifier and recovery therefore always agree (R9).

Level order (design 1):
- A level-BFS join yields (depth, parent, name) order. Full paths are still recorded, and path uniqueness is checked on a destination-key sort.
- allocate_checked opens each parent once and creates its children relative to the held parent handle.
- It records a stream mapping each source record to its shadow file id.

Paths and opens:
- Every depth-16 cap is deleted.
- The only remaining bound is the 32,767-unit extended-path limit, and only for an API that still needs a full path.
- Other opens are parent-relative, or by file ID with a check of file ID, volume serial and creation identity.

Handles: every placeholder and metadata handle stays held exclusively, as today. Each is charged to the CapacityLedger at the kernel cost measured in S1. If the projection does not fit, the run refuses at G1 before any write. A bounded handle working set is user decision D-4.

Observation:
- ObjectReports stream to the EvidenceLog in expectation order through observe_in_parallel and the reorder buffer.
- verify_native_scoped and the protected ObserveLayout pass consume the expectation as a stream.
- The post-handoff verifier writes full records into the G5 reservation, never by-reference records.

Lookups: path-to-index and parent-to-children indexes replace the O(N^2) find and the per-directory filters. [replaces: ExperimentalStreamingTreeV2 maximum_files 1024 (src/ntfs_admission.rs:86, :1006-1012, :1157; src/ntfs_stream_plan.rs:133; src/shadow_tree.rs:104-111, :215-216, :438-442); ExperimentalStreamingTreeV2 maximum_directories 256 incl. root, and shadow_tree object_limit = files + directories (src/ntfs_admission.rs:87); private_tree allocate_checked 1280 objects / 256 directories / 1024 files and observe_existing (crates/n2r-win32/src/shadow_native/private_tree.rs:562, :592-593, :600-602, :421-428); run_role_profile streaming object budget 256 dirs / 1024 files / 1280 objects, used by target qualification and verify_native_scoped after handoff (shadow_native.rs:2698-2703, :2745); complete_owned_metadata input bound 1280 and its O(N^2) find (cache_refresh.rs:81, :175); lab cache_refresh::run <= 32 frozen; Path depth > 16 components (src/ntfs_admission.rs:513, :628; src/shadow_tree.rs:132, :284-286; private_tree.rs:428, :573; unwritten.rs:112-113; shadow_native.rs:2836; cache_refresh.rs:109); Recovery expectation profile counts (src/general_recovery/allocation.rs:136-137); (implicit) retained Vec<ObjectReport> in protected and converted verification]
- C15 Payload routes, exception supply and SVI without counts (crates/n2r-win32 shadow_native/private_tree/source_backed.rs, supply.rs, system_payloads.rs; src/general_shadow.rs; src/general_qualification/compact_construction.rs; src/general_target_preservation.rs): Routes:
- SourceBackedRoutes become compact (object_index, logical, physical, length) records that refer to the tree for path and digest instead of cloning them.
- They stay sorted for partition_point lookups (RangeStore when spilled) and are charged to the ledger.
- revalidate_mounted uses an index.
- Routes are serialized through C1 and C3. Supply-plan ranges work the same way.
- This change lands together with the removal of the C13 route clamp.

Exception supply:
- The budget is the exact residual + SVI sum, already computed before any write, checked at G2 against shadow free space and the OS-volume account.
- The source-read budget is 2 x that sum.
- Residual and system receipts stream into construction-exceptions JSONL.

SVI:
- The 1 MiB per-file and 3 MiB total byte caps, and their formatter-cache twins, are deleted, because the copy already streams.
- Which SVI files are admitted is unchanged and remains a product decision. [replaces: SourceBackedRoutes route budget 4096, protected and construction sites (private_tree/source_backed.rs:89, :302; src/general_target_preservation.rs:415-416); (no constant) source_backed revalidate_mounted O(R^2) filter (private_tree/source_backed.rs:165); Supply plan range budget 4096 (private_tree/supply.rs:114, lab hybrid path); System payload bounds 1 MiB per SVI file / 3 MiB total (private_tree/system_payloads.rs:32, :44; src/general_shadow.rs:136); SVI formatter-cache 1 MiB coupled checks (shadow_native.rs:1642, :1754); maximum_exception_bytes as a constant (shared with C5)]
- C16 Selection, coverage, journal and write-policy ranges (src/selected_journal.rs, refs_hybrid/delta.rs, general_shadow/source_backed.rs capture, general_target_preservation/allocation.rs, general_composite_target.rs; crates/n2r-win32 layout.rs, native.rs WritePolicy): Ranges:
- SelectedPlan ranges, DeltaLayout changed ranges, capture ranges and WritePolicy allowed ranges share one sorted RangeStore (16 B per range; ledger or spill).
- WritePolicy::permits uses partition_point (or the fence index), O(log X) per write.
- validate() is one streaming sorted check, and the retained-overlap check is a merge.
- The WritePolicy maximum is the plan's byte count.

Coverage:
- Allocation coverage (bitmap sidecar, anchors, uncovered stream extents, then subtract) is a k-way merge of already sorted inputs, with no input cap.
- Native stream coverage merges each object's runs against the coalesced bitmap and keeps only the uncovered parts and their total, which is all that is serialized today.
- AllocationMap intervals are uncapped through C12.
- The non-fatal refs_inspect anchor diagnostic stays recorded.

Capture: it walks the compared ranges in order with a monotone route cursor and emits changed ranges with cumulative packed offsets. DifferenceImage reads use partition_point.

Journal:
- N2RSEL01 stays the format whenever the range count fits u32, so the 52 GiB fixture's journal bytes are unchanged.
- N2RSEL02 (u64 count, same 80 B records and barriers) is written only beyond that. A lab flag can force it for recovery tests.
- prepare, load, execute, resume, rollback and handoff iterate the record table without materializing Vec<JournalRecord>.
- immutable_sha256 and the framed old/new digests keep their definitions.
- Recovery takes its ranges from the record table (C2). [replaces: selected_journal::MAX_RANGES 65,536 (src/selected_journal.rs:16, :107, :157, :202-211); Selected journal u32 range_count header and ticket field (src/selected_journal.rs:42, :310, :352): N2RSEL02 on demand; refs_hybrid DeltaLayout 65,536 and require_exact_write_ranges (src/refs_hybrid/delta.rs:30, :76); Delta capture changed-range budget 65,536 (src/general_shadow/source_backed.rs:534); WritePolicy validate_ranges 65,536 (crates/n2r-win32/src/layout.rs:253; native.rs:276) and the linear permits scan / O(allowed x retained) overlap loop (native.rs:274-311); Allocation coverage union/subtract range budget 131,072 (src/general_target_preservation/allocation.rs:125, :175); Native stream coverage streams.len() < 65,536 (src/general_target_preservation/allocation.rs:232); (implicit) load() materializing Vec<JournalRecord> (src/selected_journal.rs:371-463); Lab allocation-bounded interruption count 1..=4096 (src/general_conversion/allocation.rs:22-25), now bounded by the plan's write count; Composite-path twins retained_compare MAX_PATCH_RANGES 65,536 (src/retained_compare.rs:24) and general_composite_target.rs:404 max_ranges, lifted only where the code is shared]
- C17 Kept by design, off the default path, or product decisions (no capacity lift): Kept as format, platform, host-scale or termination properties. Each refuses before any write.

Format:
- MAX_DESCRIPTOR_BYTES 0x40000-20, the SDS 256 KiB half and 512 KiB pair, ACL <= 8192 ACEs (src/ntfs_security.rs:13, :283);
- names <= 255, cluster 4 KiB-2 MiB, FRS 512 B-64 KiB, $UpCase exactly 128 KiB;
- index root <= 4096, $Volume info <= 1024, resident reread <= 4096, LFS page and sector sizes;
- fixed info-class sizes, one volume disk extent, disk_number <= 4095;
- the NTFS 2^32 record ceiling, u32 clusters per FSCTL_MOVE_FILE, and the managed-shadow VHDX 64 TB native maximum, which CapacityBudget refuses explicitly.

Termination and time: 8 interrupted-read retries; the 15 s (60 x 250 ms) publication wait.

Host-scale: rediscovery over at most 1024 host volumes (native.rs:909); drive inventory 1024 disks / 4096 volumes / 16,384 partitions; mount paths <= 128 (src/general_shadow.rs:528).

Buffers that cap no count: the 64 KiB and 4 MiB hash buffers, SESSION_READ_BYTES, the 64 KiB bitmap window, the 64 KiB range-read buffer and the 1 MiB journal buffer.

Derived policy kept: maximum_placement_bytes = partition x 4.

Lab-only: interrupt_after_writes; the general_allocation_capture lab caps; the freeze witness.

Frozen legacy readers: AlphaV1, LargeTreeV1, schema 1/2 attestation, bitmap_paging, parse_retrieval 1024 (src/tree_placement.rs:57), tree_placement 1024 / native_retention 65,536, the ConstructRetaining retention path.

Composite / whole-image path (product decision, not evidence scope): either it adopts C1, C3, C6 and C16 as an optional stage, or it stays an explicitly bounded legacy mode with its current refusal messages. The refs_inspect walker caps stay diagnostic-only on the allocation path.

Non-numeric scope gates are untouched:
- the geometry pins (512 B sector, 1 KiB FRS, 4 KiB index record);
- attribute-list feature scope and whole-volume IncompleteAttributeInventory;
- hard links, ADS, reparse points, object IDs, EAs, SACLs, DOS aliases, sparse data in lists;
- the Windows build pin 10.0.26300. [replaces: ]
## VERDICT 1: sound=False first_stage_ready=False
RECOMMENDATION: Do not adopt the design as staged. Several required facts are unverified, and its resource model and staging conflict with the stage-1 native result at HEAD ad61523.

1. Replace S0 with the recorded evidence (evidence/mixed-fixture-stage1-20261029.json). The binding constraint on the 808-file fixture is now the changed-byte budget, which the journal size sets (drive_cli.rs:452-457, lab_reconstruct.rs:54-62). It is not the 4096-route cap or the 65,536-range bitmap cap.

2. Move the exact-need journal and backing sizing (JournalProfile 3, no /4 reserve or /3 split) into S2/S3, before any S5 acceptance on the 808-file fixture. Add a projection of B at G3 from the placement plan: relocated bytes plus a bound on the metadata-inclusive allocation. The OS-volume check then runs before placement, not mid-capture.

3. Model B and whether relocated data fits the target explicitly in the resource model. The ~65% relocation measured on the 808-file fixture makes 3B the dominant disk term. Placement evidence at about 2.7e7 moves also exceeds the stated 8-20 GB total.

4. Recalibrate the time model from the measured ~105 ms per move. Add per-capture and per-retrieval timing counters in S1, and report to the user now that 16 TB is impractical without D-1 and D-2.

5. Close the uncovered caps:
   - Add the shadow-side 64 KiB descriptor sites (shadow_native.rs:958, :1782 and its callers; shadow_tree.rs:127) to C10.
   - Charge handle count against the 2^24 per-process limit, or plan for D-4.
   - Define the VHDX growth bound concretely so it neither refuses the passing 52 GiB fixture nor stays unbudgeted.
   - Enumerate the 65 ExperimentalStreamingTreeV2 dispatch sites so ResourceBoundedV1 cannot fall back to the ASCII 100-byte name rule.
   - State the 64 TB VHDX ceiling as a remaining fixed limit, or design another scratch provider.

6. Replace the claim that nothing written after commit can fail on size with either a structural worst-case reservation (bitmap-delta and observation-dependent records) or explicit, honest post-commit reporting.

7. Verify each assumed native behaviour with a scoped read-only probe before the stage that depends on it.
VIOLATIONS:
- The S0 premise is contradicted by HEAD. The design says stage 1 (4973f31) 'has not run natively' and predicts the 808-file fixture's next refusal at 'routes 4096 or bitmap 65,536 ranges'. Commit ad61523, evidence/mixed-fixture-stage1-20261029.json, records stage 1 on both fixtures. The 52 GiB fixture succeeded in 56.7 s. On the 808-file fixture placement passed (2,132 moves; 3.46 of 9.9 GB kept at original coordinates), and the run then refused in target verification with 'delta capture budget exhausted' (src/general_shadow/source_backed.rs:520). That is the changed-byte budget derived from the journal size: src/drive_cli.rs:452-457, (available - min(available/4, 16 GiB))/3, through src/lab_reconstruct.rs:54-62 (journal - 16 MiB)/2. The captured 4,951,556,096 B implies ~39.7 GB free on the VM OS volume (inference).
- The staging cannot meet its own acceptance criteria. S5 requires '808 converts end to end' and S6 requires 'both fixtures convert', but S5 lands only C12, C13 and C15. The free-space journal sizing and JournalProfile 3 are staged in S8 (S1/S2 carry only the record-only and commit-point parts of C5). The binding constraint (relocated B of at least ~6.4 GB against a ~4.95 GB budget) is therefore still in place at S5-S7, unless the unverified allocation-free placeholder probe happens to raise retention.
- The disk model omits its dominant term. For 1M files / 16 TB it gives '8-20 GB evidence + 3 GB spill + 3B + G' with B left unbounded, and the inventory's 5-50 GB estimate for B is contradicted by measurement: on the 808-file fixture about 65% of user data was relocated. At similar relocation a 16 TB volume needs about 3 x 10 TB on the OS/journal volume. Nothing models whether the relocated data fits the target's free clusters. Placement evidence alone also exceeds the stated total: 12.3 MB / 2,132 moves is about 5.8 KB per move today, and at about 2.7e7 moves (2.7 per desired run x 10M runs) even 0.3-1 KB per move is 8-27 GB.
- The time model contradicts the only measurement. t_cap = Bm / min(theta_bitmap, 511 MB/s) predicts about 7 ms of capture per move at 52 GiB (Bm 1.7 MB). The stage-1 run measured about 105 ms per move (225 s / 2,132), which the evidence attributes to the two whole-volume bitmap captures in unwritten.rs:427-430. Scaling that rate to a 512 MiB bitmap gives roughly 30 s per move. At about 2.7e7 moves that is years, against the design's stated '0.3-1 s per move' and '3.5 days to 4 months'.
- R4/G5 says 'nothing written after the ReFS commit can fail on size or space', but post-commit sizes depend on observations that do not exist before commit. One is the converted-volume bitmap recapture, stored as a delta against the witness, whose worst case is clusters/2 ranges (tens of GB at 16 TB). The other is full observed records that differ from their predictions. Counting-sink bounds computed from predicted records cannot reserve these exactly. Either a structural worst case is reserved (huge), or a post-commit size failure remains possible.
UNCOVERED:
- Shadow-side 64 KiB security-descriptor caps appear in neither the inventory nor the design: crates/n2r-win32/src/shadow_native.rs:958 (security_stream, 20..=65536), :1782 (descriptor(), called at :413, :971, :1855 and :2862 inside run_role_profile, and at shadow_native/cache_refresh.rs:25, :123, :125), and src/shadow_tree.rs:127 (api.len() <= 65536). C10 raises the native descriptor buffer to the structural maximum (~131 KiB). A descriptor between 64 and 131 KiB would then pass source observation and still be refused in construction. That refusal comes before activation, so it is safe, but a fixed cap remains.
- Per-process handle table limit of 2^24 (~16.7M). C14 keeps every placeholder and metadata handle held (PrivatePlaceholder owns a File, unwritten.rs:68-69, plus a metadata handle). The ledger charges kernel pool bytes, not handle count, so volumes above roughly 16.7M objects (fewer at two handles per object) hit a fixed platform constant. D-4 is not adopted.
- Managed-shadow VHDX 64 TB native maximum (crates/n2r-win32/src/managed_shadow.rs:511-541, kept in C17). This is a fixed limit of the scratch provider. No component supplies an alternative provider, so NTFS sources above ~64 TB stay refused.
- Changed bytes B (dominated by relocated data) are not projected at any gate before the capture. G3 holds the complete placement plan, including which desired runs fall to scratch, but checks only submissions, evidence bytes and time. G4 runs after the capture, yet the capture is where B is discovered and the packed backing is written (src/general_shadow/source_backed.rs:515-521). The binding refusal therefore stays late, after the whole placement phase.
- The VHDX growth bound is undefined before construction. The only safe pre-construction bound is partition + 64 MiB (managed_shadow.rs:511-541). Reserving it at G2 would refuse whenever OS-volume free space is below the source partition size: the lab VM has an inferred ~39.7 GB free, which is below 52 GiB, so the fixture that passes today would be refused. Not reserving it leaves growth unbudgeted. The design does not say which.
- Profile-dispatch fallback cap. 65 sites in 27 files test == ExperimentalStreamingTreeV2. Any site not rewired to the new ResourceBoundedV1 silently falls back to AlphaV1 rules, for example src/shadow_tree.rs:471-477 to valid_component at :452-460, which accepts only printable-ASCII names of at most 100 bytes. These sites are not inventoried.
- The composite / whole-image path (--whole-image-verification) keeps all its caps (src/retained_compare.rs:24 65,536; refs_write_set, packed and delta artifact limits) pending the S11 product decision.
- Non-numeric gates still refuse realistic large volumes. These are geometry pins (512 B sector, 1 KiB FRS, 4 KiB index; ntfs_admission.rs:47-49), attribute-list scope, and whole-volume IncompleteAttributeInventory propagation (ntfs_inspect.rs:1991-1993, 2258-2260). They are kept as scope, so capacity alone never makes a 1M-file volume convertible.
UNVERIFIED:
- Kernel pool cost per held exclusive ReFS handle (estimated 1-3 KB) and how pool headroom would be measured. GlobalMemoryStatusEx does not report pool. On the 4 GiB lab VM, 1M held handles at that cost cannot fit next to Windows and the spill window W.
- 'W touched at G1 so later memory pressure cannot make the budget lie': touching guarantees commit, not residency. Pages can be trimmed or paged once pool use grows during construction.
- 300 B per file for a columnar inventory whose Serialize must be byte-identical. FileInventory keeps names, standard_information, streams with extents and two digests, and attributes with resident_metadata_hex for types 0x10/0x30/0x40/0x50/0x70/0xc0/0xd0/0xe0 (src/ntfs_inspect.rs:353-371, :476-493, :895-901).
- The RAM model has no term for the Tree/ExpectedTree objects, for the source_view Analysis per-object security views held in the assessment until bind_security_views (src/general_qualification.rs:369-375), or for PrivatePlaceholder per-object state.
- Native behaviour that has not been measured: FSCTL_QUERY_FILE_REGIONS continuation on ReFS (MS-FSA specifies STATUS_BUFFER_OVERFLOW and an input FileOffset, but ReFS storage-validity regions are untested); the FileStreamInfo ERROR_MORE_DATA retry; GetKernelObjectSecurity length sizing; NtCreateFile relative stream opens; FileIdExtdDirectoryInfo with more than 4096 entries; ReFS retrieval maps with 1e5-1e6 extents; whether two concurrent FSCTL_GET_VOLUME_BITMAP calls actually run in parallel or ReFS serializes them; the probe for the largest FSCTL_MOVE_FILE length; and the allocation-free placeholder probe.
- theta_content of 1-2 GB/s for 16 TB. Lab reads came mostly from host cache at 8-30 GB/s (AGENTS.md:199-201). HDD-class 16 TB media at about 0.2 GB/s would make the 4-5 content passes take about 100 h.
- S10 feasibility. A 200k-1M-file fixture on the 4 GiB VM with about 39.7 GB OS free (inferred) and the 50 GB storage epoch needs 4-10 GB of evidence, spill, 3B including residual tails and ReFS metadata, VHDX growth, and 1M held handles. It is likely to refuse at G1 or on disk rather than characterize a conversion.
- CNG and parallel dual-view capture reduce per-move cost. The measured per-move cost (~0.1 s) is about 15x the hashing model, so the bottleneck may be ReFS bitmap generation itself, which neither lever addresses.
## VERDICT 2: sound=False first_stage_ready=False
RECOMMENDATION: Not sound as written. Most of the mechanism (streamed byte-identical pins, JSONL with header counts, merge-joins, derived bounds) can preserve the invariants. The problems are seven concrete invariant gaps and one false premise.

Fix before S1:
1. Rebase staging on HEAD ad61523. S0 is already answered by evidence/mixed-fixture-stage1-20261029.json, and the 808 fixture's wall is the journal changed-byte budget (src/drive_cli.rs:453-457; general_shadow/source_backed.rs:517-520). Stage the C5 journal sizing and JournalProfile 3 before S5, or drop S5's '808 converts' acceptance.
2. Restate R3 exactly. Authority structures (the selection behind selection_sha256, the WritePolicy ranges, the reconciler inputs) may come from spill or sidecars only through in-process per-block digests verified on every read. Otherwise keep them in RAM and refuse at G1 or G5 before activation. BlobStore evidence is never read back into authority.
3. Keep every re-derivation check: stream the canonical digest at each binds() site (general_source_admission.rs:383, general_composite_target.rs:504-507 and :838, general_target_preservation.rs:597-600 and :660), and keep the live boot and MFT reread in checked_plain_attribute (ntfs_inspect.rs:2349-2358). Alternatively, list either change as a new D-n for the user.
4. Make PinnedReader two-phase in recovery. Pin-verify and validate every input completely before the lifecycle decision (keep the order at general_recovery/allocation.rs:129-137 before :259). Keep a full load() and check_target pass before the intent marker.
5. Pin the schema-3 journal ceiling in the request and ticket. Recovery must never re-measure free space for journal_file.rs:263 or native.rs:293.
6. Add capacity-plan and derivation pins as AllocationCertificate fields and check them in binds(). assessment_sha256 is never compared today.
7. Define the post-commit rule. Any record that exceeds its expected-derived bound counts as a mismatch with bounded evidence and a failure. Give recovery its own G5-equivalent before its resume writes.
8. Make the rename durable (MOVEFILE_WRITE_THROUGH or a directory flush), and prove it with a TurnOff run right after bundle publication.

S1 is otherwise the lowest-risk stage. Even so, it should not start until items 1 and 8 are settled, because it rewrites the bundle-publication save path.
VIOLATIONS:
- The authority/evidence separation contradicts itself. R3 and the AUTHORITY section say 'a disk copy is never an input to a live proof' and 'disk evidence is never re-read to rebuild authority'. But: C6/C8/C9 run reconcilers and inventory columns from spill files. C12's Summary::validate and candidate() stream bitmap range sidecars from the BlobStore (evidence) beyond the RAM share, and those feed the selection whose selection_sha256 the certificate binds (src/general_source_admission.rs:99). C16 puts the WritePolicy allowed ranges in a spillable RangeStore, and that policy authorizes every device write (crates/n2r-win32/src/native.rs:303-311). The design never says the per-block SHA-256s live in process memory, so spill integrity could be a self-checksum.
- A re-derivation check is dropped without a D-n decision. C1/C8 say 'the inspection pin is computed once and passed by value'. Today every binding point re-hashes the live inventory object: src/general_source_admission.rs:383; src/general_composite_target.rs:504-507 (binds), :838; src/general_target_preservation.rs:597-600, :660-662; and source_views_sha256 at src/general_source_admission.rs:131-137. Passing the pin by value turns these into tautologies. It also removes the only check on a spilled, disk-backed inventory at those points.
- A live source recheck is dropped without a D-n decision. C8 says 'checked_plain_attribute reuses that result and the MFT bootstrap instead of rereading them'. Today, before every residual or SVI stream copy, that function re-reads the frozen source's boot sector, compares geometry and re-reads and verifies the MFT bootstrap against the inventory (src/ntfs_inspect.rs:2349-2358). That narrows what is checked, which the user's 2026-10-29 rule requires a separate decision for.
- Recovery ordering would regress. C2 makes reading 'one pass' and C14 makes verify_native_scoped 'consume the expectation as a stream'. Today recovery reads the whole expectation, pins it and runs validate_with_resource_profile before choosing an action or writing anything (src/general_recovery/allocation.rs:129-137, then arm and resume at :259-262). With a single streamed pass, the expectation's whole-file pin and validation would complete only during the post-handoff verify, after the resume writes and HND. Every input needs a full verification pass before the lifecycle decision.
- R5 contradicts C5. C5 says schema-3 JournalProfile's ceiling is 'journal-volume free space ... re-observed in recovery'. But recovery re-validates the journal against profile.max_journal_bytes() (crates/n2r-win32/src/journal_file.rs:263-264, called at src/general_recovery/allocation.rs:195-197). It also re-validates the WritePolicy against profile.max_changed_bytes() (crates/n2r-win32/src/native.rs:293-294, armed at allocation.rs:252-261). Once the journal exists, free space has shrunk by at least its length, so a re-measured ceiling makes recovery refuse both Resume and Rollback. Protection is kept, but conversion has stranded the volume. The ceiling must be a pinned request or ticket value.
- The capacity pins are not bound by the live certificate. The design says derivation and capacity-plan pins are 'bound into the admitted assessment, which the live certificate already binds'. But AllocationCertificate::binds checks only pair, expected tree, source digest, selection, the selected digests and changed_bytes (src/general_source_admission.rs:92-103). assessment_sha256 is computed (:176, :249, :313) and never compared anywhere in src. It is also a compact to_vec digest, not the pin of the pretty admitted-assessment.json (src/general_qualification/composite.rs:357-359). Activation therefore checks nothing about capacity (src/general_conversion/allocation.rs:189-192).
- The staging rests on a false premise. S0 and the risks say stage 1 (4973f31) 'has not run natively' and expect the 808 refusal at 'routes 4096 or bitmap 65,536 ranges'. HEAD ad61523 records the native run: placement passed (2,132 moves), and the refusal came later, in target verification, on the journal-derived changed-byte budget. S5's 808 acceptance is therefore blocked by a cap the design lifts only in S8.
UNCOVERED:
- Post-commit verifier output has no bound that can be computed before commit. verify_native_scoped runs after HND (src/general_conversion/allocation.rs:253-265). In Verify mode it captures both bitmap views of the converted volume (crates/n2r-win32/src/shadow_native.rs:3282-3299), while pre-write ObserveLayout captures only the metadata view (:3301-3314). The post-commit range count, the retrieval maps and the ObjectReport sizes are therefore observed, not predicted. The G5 'counted upper bound' preallocation has nothing exact to count, and the design does not say what happens when an observation exceeds the reservation (truncated evidence, or a failure after commit).
- Recovery-side post-commit outputs are not reserved. Recovery runs in a fresh process and output directory (src/general_recovery/allocation.rs:165). After its own resume and HND (:260-265) it runs verify_native_scoped (:341) and saves completion.json (:350). The conversion's G5 RAM and FileAllocationInfo reservations do not carry over to that process, so R4 does not hold across an interruption.
- The drive journal changed-byte budget is the current 808-fixture wall and is not staged before S5. The budget is journal_bytes = (available - min(available/4, 16 GiB))/3 (src/drive_cli.rs:453-457), and the changed-byte maximum comes from it (allocation.rs:45-50). The native stage-1 run at ad61523 (evidence/mixed-fixture-stage1-20261029.json) passed placement and then refused with 'delta capture budget exhausted' (src/general_shadow/source_backed.rs:517-520) at 4.95 GB changed. Yet S5 requires '808 converts end to end' while JournalProfile 3 lands only in S8.
- The resource model's B is contradicted by native evidence. In the 808 run only 3.46 of 9.9 GB stayed at original coordinates, so B is about 50% of the data, not the '5-50 GB at 16 TB' assumed. The OS volume then needs roughly 4B: a journal of 2B, packed backing B, and scratch-relocated data inside the shadow VHDX.
- The per-process handle-table ceiling (about 2^24) for C14's held exclusive placeholder and metadata handles is a fixed platform constant missing from the C17 kept list. Above it the run must refuse explicitly at G1.
- Implicit AlphaV1 fallbacks remain on the recovery and post-commit paths. Examples: request.source_resource_profile.unwrap_or_default() (src/general_recovery/allocation.rs:137; src/general_reconstruct.rs:1468) and certificate AlphaV1 => None (src/general_source_admission.rs:179-182). Also the run_role_profile None fallback of 160 objects / 256 MiB (shadow_native.rs:2688). C4 must remove all of them together, or a None profile silently restores the 160-object cap after commit.
UNVERIFIED:
- That .partial-then-rename keeps the recovery bundle durable before activation. C1 says files are created 'as today (create_new, share 0, write-through)'. But custom_flags 0x0020_0000 is FILE_FLAG_OPEN_REPARSE_POINT, not FILE_FLAG_WRITE_THROUGH (src/general_qualification.rs:84-91); durability today is sync_all on a file created under its final name. A rename that is not durable at activation (src/general_conversion/allocation.rs:170-195) leaves no allocation-recovery-bundle.json after power loss. Lazy metadata durability has bitten this project before (the hard power-off evidence in AGENTS.md).
- That G3 can compute the 'complete deferred + evacuation + final plan ... exact submission count, exact evidence bytes' before the first move. The evacuation plan comes from the ownership set after the deferred moves (crates/n2r-win32/src/shadow_native/private_tree/placement.rs:858-869). The final plan comes from a snapshot after evacuation (:1007-1015). Drift re-plans happen mid-phase (:756-779, :1130-1142). G3 can only predict; refusals after shadow-only moves stay reachable without any drift.
- That a streaming C16 journal (no materialized Vec<JournalRecord>) still runs a complete verification pass before the intent marker. Today execute() calls load() (whole immutable hash, every payload hash and the footer digests) and check_target() before write_marker and any target write (src/selected_journal.rs:613-645). The design's goal of cutting the about-5 journal rereads must not fuse verification into execution.
- That ancestry-classifier reachability (C9) is equivalent to today's index-edge BFS. It holds only if the MFT-tuple and $I30-tuple sets are proven exactly equal first and single-parent is enforced. The equivalence is asserted, not shown.
- That observed native and post-commit records fit header counts and sizes derived from the raw inventory or expectation (the C3 JSONL headers, the G5 preallocation). It is unshown that the ReFS behaviour on the converted volume's first mount (new allocation runs, map changes) is bounded by the pre-write witness.
- That recovery will have at least the conversion's RAM and OS-volume space. R5 says 'a run that wrote an input can always read it back', but recovery re-measures resources, and the design's own risk section admits recovery may refuse. Recovery also copies every input into its output before acting (src/general_recovery/allocation.rs:166-169), which doubles disk use at scale.
- Kernel pool per held exclusive handle times (F + D) is unmeasured, and so is the time for M x C/8 placement captures at multi-TB scale, during which the source stays frozen and offline for possibly days to months.
- That spill files (share 0, delete-on-close) cannot be modified underneath the process, for example through raw writes to the OS volume. Integrity rests on per-block digests whose storage location is unspecified.
