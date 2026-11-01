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

Latest native performance case6be2648addc24d1b95a11d807dae76d6 PASSED exit0/HND
and all811 independent hashes. Runtime c2c1ef3 used the already-prepared source,
new live source certificate and same owned empty shadow. D544,784,384B /
J131,301,000B / C15,888,384B / O55,504,896B / F402,669,568B. Actual format5
N2RFRE01; native conversion62.2871679s, prep18.5202009s (80.8073688s combined).
Native-verified logical process reads27,643,861,313B/writes878,482,576B versus
prior94,053,323,457B/17,368,271,656B. Journal reduction97.73%; kernel NTFS move IO
is separate. These are scoped observations, not a controlled physical benchmark.
See evidence/prepared-source-performance-native-20261101.json.

CURRENT VM is Running/4GiB, original first-write checkpoint
7721d92e-c80c-4843-983a-d9d3c89bb964, parentcb802669,12 snapshots. Fresh nativefault
4456/birth1793571035196 exited86 at22:11:33.0920178Z; controlled observer passed
positiveformat5 F402,669,568/J132,774,832, no Apply/HND. Closed75 metadata files
185,020,599B were source/copy SHA-verified; final-idle and actual Off/RAM0/checkpoint
observations produced REAL schema1 checkpoint.json under prepared-source-performance-
interrupt-7a18009eb7e94c6dbaffc2b9295ace98. Receipt SHA9afc04c396cad6051bde711914227ac394e78aacc5391ef479fdf630cb95d4eb.
Bundle SHA0b6cc964ac2b3410712b23c99b5247a58a9b9297d4554c052c4312daac35c0fc.
D-F restore scope143,527,936B (not normal6be's142,114,816B). Actual source offline1;
shadow offline+readonly3 before stop. No raw journal was opened by the observer.

RESUME370b4f632703445f80f8f356115bd3b5 is now active using frozen c2c1ef3 public
runtime, task N2R-PreparedSourceRecovery-resume-370b4f632703445f80f8f356115bd3b5,
stage C:\ntfs2refs\prepared-source-recovery-resume-370b4f632703445f80f8f356115bd3b5.
Inspect actual task/PID+birth/terminal files; no power/restore/retry until closed.
Original7721 and its recovery material must remain. Once Resume/HND and all811
checks close, archive/preserve its branch; restore ORIGINAL7721 separately for
Rollback. Never replay a closed HND or recovered branch. Root matrix receipts
are under prepared-format5-recovery-matrix-679714c852da493d8b7253e054c30995.

Normal6be is preserved at051b650a-3358-40db-a7ed-8619e6e36760 (Off checkpoint,
parentcb802669). Closed86 metadata files220,577,341B were SHA-verified. Superseded
31d7 was retired through Hyper-V after179 old/new archive files were held/verified;
all host archives remain. User-authorized accidental empty-folder cleanup passed.
Preparation82e805b moved5,643,501,568B over385 native requests/222 identities,
with complete native maps/EOF/identity checks and all811 independent hashes.
A fresh frozen full raw/native baseline also passed1084 objects/811 streams.
Prepared checkpoint cb802669 preserves RUNNING MEMORY and empty owned shadow6:
restoring it yields Saved; verify in a fresh process, then Start-VM once.
The original prepared managed smoke receipt is pinned SHA184aad57e2c8c8616adb4ad57ed82e40aba31949c530015ebcc5f7b681bcf876,
at ntfs-owned-preparation-6ec16ed4b4774c13a76b1e282103c66e/closed-native/managed-shadow/result.json.
The actual guest VHDX is under that same6ec...stage, not each conversion's stage.
New source uses a32MiB pre-submission receipt reserve; focused compilation passed,
but that later change was not part of recorded82e execution. No unit tests.

New full baseline manifest SHA7d10997d0ec43a54725c66956a0992d40437b20720a78217852cc338e82a74e7
is under ntfs-owned-preparation-6ec16ed4b4774c13a76b1e282103c66e/full-baseline-
8796571ebd24458f8bedf17b5784e5a7/closed-native/full-baseline in the .lab base.
Original f5de describes PRE-move physical locations and is not admission forcb.
Conversion uses genuine fresh source inspection/certificate; baseline JSON is
only independent lab evidence. Original logical-content hashes remain pinned.

NEXT: controlled first-write interruption from restoredcb using
lab/Start-PreparedSourcePerformanceExperiment.ps1 -InterruptAfterFirstWrite.
Its exact schema3/8GiB J/256MiB literal/10GiB combined bounds remain; requires
positive format5 F for the new recovery experiment. Toolset remains sealed
paired-source-preparation-tools-c2c1ef3/manifest.json SHA70fb7abaff41ad497bb90e996662057de36222ddd9d5a68cc411d57957dc557e.
Native producer SHA93c1eb20a3510fb12f6d84732fb3b4c8779ee7493ceefa46f5125f1bd0c8e232;
public SHAe49d604561d19652557b8ee8a2e93f3ca8797d7e97fd7c228ae7a7ee7cab2f75.
Root must create a REAL interrupted checkpoint receipt only after actual86,
first flush/noHND, idle, normal stop and fresh checkpoint graph verification.
New lab/Start-PreparedSourcePerformanceRecovery.ps1 documents the schema1
prepared-source-performance-interrupted-checkpoint-v1 contract. It is parsed,
not native-qualified, and requires original bundle/process/terminal/diagnostic/
managed pins. Root must review it before execution. Resume must prove full new
selected SHA/HND; Rollback proves ticket.old_restored_selected_sha256 over D-F,
not full old-selected bytes. Marker/footer identity REMAINS original full old SHA.
Never invent legacy producer fields or recreate fresh Apply authority from JSON.
Native positive-format5 interruption/Resume/Rollback remain PENDING.

A delegated Rust read-pass fusion may be in progress; inspect worktree before
build/commit. Desired optimization consumes actual borrowed closing-read buffers
in capture, retaining BOTH complete opening/closing reads/hash equality and all
native/route/allocator/source gates. No zero-range skipping or JSON byte authority.
Unchanged9,868,443,648B of adopted payload is ALREADY excluded from comparison.
Actual remaining bulk is repeated6.18GB native-metadata/required-zero brackets;
see current target-preservation and phase IO counters. Paged evidence/handle
windows remain for broad scale. Do not mark the performance goal complete.

Root alone mutates VM2401593c-4b30-472e-9b6d-c9534cbaa599,
ntfs2refs-streaming-v2-20261027;4GiB fixed/4CPU/noNIC. Credentials only Import-Clixml
.lab/hyperv/win11/secrets/guest-credential.xml, never print. Keep current051b,
preparedcb, sources8329/6fe2/371a/9c42, guardedf4bf, H cold d939, original old-format
interrupteddea9 and recovery8087/d40b (11 states). All other older listed IDs were
retired. Old recovery compatibility evidence is in docs/exclusive-recovery-native.md.
## Evidence and current implementations

- Frozen E4ff old-zero matrix is complete: first flushed write86, clean restart,
  Resume0/HND, separate original-state Rollback0/ABT, all811 hashes both ways.
  Old-selected checksum exactly matched original ticket. This is not arbitrary
  faults or physical-power-loss qualification. See docs/old-zero-recovery-matrix.md
  and evidence/old-zero-recovery-matrix-20261031.json.
- The retained states include latest051b, grown source8329, original F source6fe2,
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
