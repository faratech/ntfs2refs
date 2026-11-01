# ntfs2refs project guidance

@C:\Users\mfara\.codex\RTK.md

Read RTK. Work in **D:\code\ntfs2refs**, branch
`codex/isolated-journal-observation`, private origin faratech/ntfs2refs.
The environment's C: workspace path is stale. This is a current handoff, not a
chronological log. Prior instructions and results are preserved verbatim in
[the November 1 archive](docs/history/AGENTS-through-20261101T0225.md) and
[the October 29 archive](docs/history/AGENTS-through-20261029.md).
Old CURRENT/LIVE labels and preserve-all instructions in those archives are history.

## Objective and user constraints

Finish the Rust in-place NTFS-to-ReFS converter, with efficient reads, scratch
storage and RAM, broad NTFS compatibility and resource-based scale. Conversion
and recovery must run inside the Windows machine owning the disk. Hyper-V is
lab infrastructure, never a product requirement. Boot conversion is deferred;
large-count/volume, feature and production-hardening requirements remain open.
Do not redefine completion as the existing small-corpus success.

- Prioritize actual implementation and necessary native integration. Keep the
  native-shadow alpha; independent-writer research is off the critical path.
- Do NOT add or run unit tests unless specifically requested. Focused builds,
  existing owned-file experiments and necessary native checks are allowed.
  Avoid repeating expensive scans answered by unchanged evidence.
- Commit task-owned stable source/docs regularly and push normally; never force-push.
- **NEVER edit, format, stage, reset or clean the user-owned src/main.rs hunk.**
  Its SHA-256 is `c6bc5c52c8458ee70bd2567a9d8350105aeaa6245448df22675780403e04348b`.
  Stage exact owned paths, never `git add .` or workspace-wide formatting.
- User authorized obsolete-checkpoint deletion and cleanup. Preserve active
  recovery material and host archives; do not infer preserve-all from history.
- Keep WSL running. No disabling UAC or new persistent privilege changes.

## Performance continuation and current native state (2026-11-01 UTC)

Latest native runtime c2c1ef3 passed conversion/HND and all811 independent stream
hashes in run2d220c6122aa47cfbdcc247013a0b44a. Both capture and journal preparation
reused actual source reads:5,659,303,936B each. Native-verified logical reads
94,053,323,457B/writes17,368,271,656B; observed native wall280.3918824s.
These are process transfer counters, not physical traffic or a timing speedup.
Journal5,773,273,160B/D11,393,306,624B/O5,662,773,248B. F0 selected canonical
format4 fallback; native format5/its recovery remain UNQUALIFIED.
See evidence/native-paired-preparation-copy-reuse-20261101.json.

Previous unprepared success is preserved at ReFS checkpoint
31d77adf-2682-4e4d-b1f8-95e35702c4c0, parent clean NTFS83290a28-1e83-4eb2-a4d3-b0e9f5a8d63b,
with10 snapshots after the user's obsolete-state cleanup. All project tasks
were terminal/workers absent before normal stop.
93 closed metadata files were source/copy SHA-verified; archive/preserved/idle
receipts are under .lab/hyperv/streaming-v2-20261027/source-free-performance-normal-
2d220c6122aa47cfbdcc247013a0b44a. No converter/raw HND replay is permitted.
Earlier capture-only d1bbcaa3 and37 obsolete fixture/result checkpoints were
retired through Hyper-V after archive/graph guards. Preserve latest31d7.
Cleanup receipts: obsolete-checkpoint-cleanup-e934c825371d48838d04acf8efb4549b
and obsolete-checkpoint-cleanup-d59a3d7435224214bcd178ceea2f4973. All host archives
remain. The older preservation lists in historical guidance are superseded.
Retired IDs, including26c844d0, must not return.

CURRENT: VM is Running/4GiB/4CPU/noNIC with11 checkpoints, parent prepared NTFS
cb802669-903c-48cc-99e5-57976b149e7d. Preparation runtime82e805b completed385 native
moves/5,643,501,568B over222 identities in18.5202009s; all811 independent hashes
and a fresh full frozen raw/native baseline passed. Prepared source/empty shadow
were preserved with memory in cb802669; no move was repeated. See
evidence/ntfs-owned-preparation-native-20261101.json. Baseline manifest7d10997d
is under ntfs-owned-preparation-6ec16ed4b4774c13a76b1e282103c66e/full-baseline-
8796571ebd24458f8bedf17b5784e5a7/closed-native/full-baseline (inside the usual .lab base).
The old f5de baseline does not describe these relocated physical mappings.

Actual conversion6be2648addc24d1b95a11d807dae76d6 is active under
C:\ntfs2refs\prepared-source-performance-normal-6be2648addc24d1b95a11d807dae76d6,
task N2R-PreparedSourcePerformance-normal-6be2648addc24d1b95a11d807dae76d6.
Native producer2988/birth1793569348608 is runtime c2c1ef3. Reuses the exact empty
shadow6 from preparation, with NEW live source inspection/certificate; no JSON
or baseline grants authority. Do not power/checkpoint/restore/retry until actual
task/PID+birth/terminal/HND state and all project workers are rechecked. Journal
size, final IO and all811 postconversion hashes remain pending.

New source implements NTFS-owned collision preparation before freeze through
FSCTL_MOVE_FILE, with metadata-only planning, live destination bitmap windows,
full retrieval/identity checks and bounded receipts. The explicit minimize-scratch
path and lab-prepare-ntfs invoke it. Scoped native moves passed as above;
post-preparation conversion/recovery are PENDING. A later32MiB receipt reserve
fix is focused-build ONLY, not part of the82e native result. No qualification
transfers across those revisions.
No unit tests added/run. See docs/ntfs-owned-preparation.md.

Next: finish observing live6be, preserve its actual result, then qualify scratch
reduction and actual format5 Resume/Rollback from the preparedcb802669 source.
Reinventory after moves and obtain a NEW frozen source certificate; old physical
maps are never authority. Keep independently pinned logical-content evidence.
Paged evidence
and bounded handle windows still remain. Do not mark the performance plan complete.

Root alone mutates VM2401593c-4b30-472e-9b6d-c9534cbaa599, name
ntfs2refs-streaming-v2-20261027;4GiB fixed/4CPU/noNIC. Guest credentials only
Import-Clixml .lab/hyperv/win11/secrets/guest-credential.xml, never print them.
Current archive retains previous failures and all811 results. Preserve original
interrupteddea902f6 plus its journals; old8GiB recovery source/compatibility
qualification is in docs/exclusive-recovery-native.md. Original producer remains
E4ff/9140; a new observer/runtime never creates fresh source authority.

The preceding detailed handoff is preserved in
[the21:10 UTC archive](docs/history/AGENTS-through-20261101T2110.md).
## Evidence and current implementations

- Frozen E4ff old-zero matrix is complete: first flushed write86, clean restart,
  Resume0/HND, separate original-state Rollback0/ABT, all811 hashes both ways.
  Old-selected checksum exactly matched original ticket. This is not arbitrary
  faults or physical-power-loss qualification. See docs/old-zero-recovery-matrix.md
  and evidence/old-zero-recovery-matrix-20261031.json.
- The retained states are latest31d7, grown source8329, original F source6fe2,
  H source371a, sparse source9c42 with guardedf4bf, H cold resultd939, interrupted
  old-zerodea9 and journal-owner recovery results8087/d40b, plus new prepared
  sourcecb802669 (11 total). Other historical
  fixture/intermediate/result nodes, including6bef and the H tail matrix, are
  retired. Their reports and pins remain. Never recreate old IDs from guidance.
- Grown F corpus:808 user files/271 user dirs;811 total streams/273 total dirs/
 1084 semantic objects/1111 raw identities;9,885,781,381 user bytes. Fresh full
  baseline f5de156f and metadata-only growth835b1196 remain pinned. Full/fast raw
  inspection pins differ; never mask root-modified/MFT times, profiles or new
  objects. Only actual evidence-backed access-time reconciliation is allowed.
- Normal E4ff converted that tree in276.7805697s, all811 independent hashes.
  Format4 N2ROLD01 uses actual old-zero whole ranges (capture AND preparation
  check every actual byte), not allocation/VDL assumptions. Journal5,850,442,832B
  versus SAME-plan old encoding11,438,022,112B; all selected writes remain.
- Original interrupted plan: D11392847872 / N3547 / O5587685376 / J5849731480 /
  L44191744 / C5659303936. All raw selected checksums remain SHA-256. Allocation
  recovery is self-contained with original metadata pins; cold shadow absence
  is allowed without reattach. Compact/whole-shadow modes have other dependencies.
- Private PreparedExclusiveJournal retains actual complete post-flush readback
  through fresh activation/apply/HND; no mutable J accessor or JSON authority.
  Exact-old/new target checks and all ordering/barriers remain.
- Private ExclusiveRecoveryJournal retains one actual load+classify through
  recovery; all mixed target prechecks, PER-SPAN old/current/new reads, exact
  post-target AND post-callback handoff target checks remain. Target reopen stays
  share3; exclusivity claim is JOURNAL ONLY. Code-accounted e4ff savings:
  Resume34,805,884,512 / Rollback17,402,942,256 logical J bytes, not physical IO.
- Optional old_zero_actual_bytes_v1 capacity policy is implemented/compiled,
  natively UNQUALIFIED. Schema3/CapacityPinnedV3/fresh fast allocation only,
  pinned literal/combined bounds; logical maxD=partition, each append charges
  J=(D-O)+literal+16MiB. O(1) credit revocation occurs BEFORE admission/append.
  Exact final positive O/format4 required beyond the conservative ceiling.
  Existing CLI/binder and omitted policy remain conservative. Source policies,
  namespace/security/maps/tails/source-certificate and metadata/range caps stay.
- New lab/Start-ActualByteCapacityExperiment.ps1 (d6bc234) is reviewed and PS5
  host/assembled-guest parsed. It uses J8GiB/L256MiB/combined10GiB/reserve1GiB,
  requires actual D above old ceiling and actual J within8GiB. Normal flag
  --fresh-exclusive-v3 and fault flag --fresh-exclusive-v3-first-write require
  genuine planningNone, never Some. No8GiB native execution yet. Capacity rows
  are sampled free-space observations, not a complete rolling-O ledger.

Useful docs: fast-verification.md, raw-extent-verification.md,
old-zero-journal.md, journal-exclusive-recovery.md, actual-byte-capacity.md,
recovery-runtime-compatibility.md, scaling-budget-gaps.md, unbounded-scale-design.md,
ntfs-compatibility-comparison-20261030.md (under docs/).

## User decisions and open scope

- Allocation-bounded is default; only authenticated target-required allocation
  is compared/written. NTFS free space is not covered as unchanged by admission.
  Whole-image mode retains its full checks.
- D1 destination bitmap windows approved under both selectors. Keep complete
  phase maps, full per-file retrieval/all-placement and final allocation checks.
  Window evidence must not be serialized as a whole-map hash. D2 incremental
  retrieval remains deferred/unapproved.
- D3 extent-based fast verification is default; --verify-full-content and
  whole-image mode retain full verification. Prove retained data via exact
  metadata/physical extents, checksum moved/rewritten bytes during IO. Preserve
  namespace, ACLs, allocation, full retrieval and recovery checks. Explicit
  absent digests stay absent; never invent hashes or call metadata a content hash.
- User-selected logical file/resident/native content digests are XXH3-128 even
  where legacy field names end in sha256; they do not match Get-FileHash.
  Artifact pins, residual tails, metadata/whole-image and journal hashes stay SHA-256.
- Resource-based scale is the goal: remove artificial count/size ceilings through
  complete paged evidence/resource budgets, not larger constants or truncation.
  Current1280 semantic objects/2048 raw identities and other caps remain; no
  arbitrary-volume/file-count qualification. See scaling-budget-gaps.md.
- Hybrid moved-data policy approved in principle: stage in same-volume free
  space when possible, external journal fallback. E2 per4KiB old/new XXH3 table;
  E-2 rollback restores all NTFS-allocated bytes and may leave staged free-space
  bytes; refuse VSS. E3 dual-sector markers/hard-poweroff qualification. These
  plans are NOT blanket implemented/qualified by current format4 journals.
  E2 Resume must refuse a4KiB granule matching neither old nor new; E3 uses
  the intact marker copy to decide after a torn write.
- ReFS reserved-zone zero skipping was DISPROVED (refs-zone-probe-20261030).
  Keep every required zero write. Do not repeat that proposal without an
  authenticated footprint proving the precise zeros are unreferenced.
- VSS and directory case-sensitivity have live admission gaps; no existing gate
  or full preservation claim. Historical missing feature evidence is Unknown,
  never false. Hard-link groups use new ReFS IDs, not original numeric IDs.
  ADS/sparse/compression-normalization/EA/security/MS-reparse have scoped native
  evidence on H, not universal compatibility. EFS, additional reparse providers,
  missing security forms, boot/system and broad geometry remain unqualified.
- REFSNT and forensic parsers remain external research. Never copy GPL engines
  into the Rust product or claim compatibility from their checkers.
- Any actual narrowing of checked evidence needs a separate user decision.
  Routine proof retention under explicit ownership does not authorize unrelated
  weaker checks. Preserve old format/recovery compatibility explicitly.

## Source and recovery invariants

- Fresh Apply requires the original opaque live SourceCertificate through
  freeze/qualification. Never recreate it from JSON, old reports, flags or a bundle.
- A recovery bundle supplies pinned routes only. Actual journal/ticket/input/
  device/lifecycle checks authorize recovery, never a new fresh Apply.
- Keep all mode-required pins and recovery material until closure. Never bypass
  a live sharing lock with another reader or tool.
- HND/ABT close old raw replay. Post-handoff observer failure permits read-only
  completion only; no replay over a mounted/changed filesystem.
- Do not clear protection, online/reidentify/rebind devices to bypass refusal.
  Missing protection may be added only through reviewed exact binding/provider
  checks and positive native write-protect evidence. Do not recreate lost authority.
- Timeouts/remoting loss do not prove death. Check actual task state, PID AND
  creation identity, terminal files and actual native handles. No duplicate retry.
- Before power/restore/checkpoint/new work prove ALL project tasks terminal and
  workers absent. Root alone mutates VM. After restore/checkpoint verify parent/
  state from a FRESH exec process; cached Hyper-V objects can lie. Do not repeat
  a successful restore because a cached object disagrees.
- A mount/hash alone is not allocator/durability/semantic proof. Record refusals
  and scoped evidence honestly. Code accounting/live samples are not final IO.

## Storage, RAM, cleanup and tools

Fixed epoch (do not reset after cleanup): initial lab279374052988B,
initial host free66133905408B; MAX actual329374052988B; MIN host free17179869184B.
Original additional allowance is50,000,000,000B. Re-measure/admit a justified
per-phase forecast through lab/Lab.psm1 and lab/lab.config.json before growth.

Cleanup2e79 removed ONLY old1aed/5f/307b(after children)/ed6 via Hyper-V, after
336 closed files576851960B/pins rehashed under held reads with fresh-process
exact graph guards. Lab usage decreased47,021,869,171B to275,354,925,443B;
free69,904,642,048B at01:58. That is a measured bracket, not per-file guarantee.
All host archives/baselines remain. Retired snapshot IDs must not be recreated.
Other removals and old labels are recorded in archived guidance/evidence.

- Remove snapshots through Hyper-V APIs ONLY. NEVER delete AVHDX chain files.
  Before deletion verify complete archive/dependency pins, exact inactive graph,
  protected states, child order and current parent. Re-measure after merges.
- NEVER force guarded f4bf5238-14c0-4b15-bda6-7859abd4d1c9 removal (archive mismatch).
- Prior automatic approval review rejected research-image deletion and duplicate
  D:\code\ntfs2refs\.lab\ntfs2btrfs-source-audit deletion. Do NOT retry via another
  shell/method. Authorized Hyper-V checkpoint removal is a different action.
- Keep WSL running and VM4GiB/4CPU/noNIC. Keep .lab/images/journals/ISOs/binaries/
  secrets out of Git. Credentials only Import-Clixml
  .lab/hyperv/win11/secrets/guest-credential.xml; NEVER print credentials.
- Resolve absolute targets before cleanup; native PowerShell literal-path ops,
  one shell end-to-end for destructive filesystem work. No guessed deletion.
- Rust1.98.1: C:\Users\mfara\.cargo\bin\cargo.exe. Set TEMP and TMP to
  D:\code\ntfs2refs\target\tmp. Format OWNED files only via rustfmt --edition2024
  --config skip_children=true. Never workspace cargo fmt/all or touch main.
- Focused compilation/native checks only; documentation needs no rebuild.
  Always preserve exec session IDs; poll live sessions, never restart on timeout.
