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

## Paused work and last native observation (2026-11-01 UTC)

Implementation and VM operations remain paused. The subsequent ntfs2btrfs
comparison was read-only; the Git checkpoint does not resume either activity.
The native state below is the last recorded observation, not a fresh process
or VM check. Re-establish actual task/handle state before any future VM action.
The directory-case work in attestation.rs is an unfinished model/schema change:
native collection, admission integration, build and native validation remain
pending. It is not part of the qualified frozen binary or a completed feature.

LAST OBSERVED 8GiB NORMAL: root restored clean8329 once fromd40, fresh-verified then
booted once with46 checkpoints. Actual case27ae9824f5794fe98a96d69c66cfc10b,
stage C:\ntfs2refs\actual-byte-capacity-normal-27ae9824f5794fe98a96d69c66cfc10b,
task N2R-ActualByteCapacity-normal-27ae9824f5794fe98a96d69c66cfc10b.
Frozenadf08e9 producer80e5b0ff/public34c9, toolset4f62, exact8GiB policy used.
Producer5412/creation1793502009573 exited0/HND03:04:51.8197235Z
(282.2467235s from ms birth). ActualD11393249280>old8GiB-reserve,
O5588070400/J5847923376<=8GiB,N3530, actualold_zero_actual_bytes_v1,
prepared-ownertrue,1084maps,654missing650tails1371388, targetpayloadreads0.
Wrapper5076/creation1793501997496 was ACTIVE in independent postchecks; all811/
capacity-observation verification/archive/final-idle PENDING. No power/retry or
HND replay until that closes. Root alone mutates VM; normalcheckpoint47 next.
Source-case evidence versions13/14 are being coded onhost ONLY, not in this
frozenVMbinary/report12. No scope/qualification transfer to that future code.

Root alone owns VM mutation. Delegated agents may observe metadata/processes
or edit assigned source. No other actor may dispatch, retry, stop, restore,
checkpoint, attach, format or clear protection.

VM `2401593c-4b30-472e-9b6d-c9534cbaa599`, name
`ntfs2refs-streaming-v2-20261027`: 4 GiB fixed RAM / 4 CPU / no NIC.
At new-owner matrix closure, VM was fresh-confirmed Off/RAM0/48 snapshots at restored-NTFS checkpoint
`d40b4b41-be9c-4243-8f91-7f953085e3a3`, parent ORIGINAL interrupted
`dea902f6-7d3f-49ba-86d2-27ce6dbe9516`, at2026-11-01T02:37:17Z.
Actual lab292508370854B/free52696043520B remains inside the unchanged epoch.
No project tasks or workers remain. No raw HND/ABT replay is permitted.
CURRENT after reviewed slot cleanup02:44:15Z: same Off/RAM0/currentd40,
46 snapshots. Root removed ONLY superseded old E4ff033e/35c leaves after
130 complete archive/control/dependency files were rehashed under held reads
and fresh-process graph guards. NEW8087/d40, ORIGINALdea, normal6bef, sources
and every other ID/parent remain. Plan02307ecc; completionf0619810 under
checkpoint-cleanup-two-old-recoveries-90dedad073fa45779610a8735d7b9657.
Actual274033264527/free71243247616B, fixedmax329374052988/min17179869184
unchanged. Four slots are reserved for the new8GiB normal/fault/recovery cases.
Old033e/35c IDs are retired; archived evidence remains, never recreate them.
A NEW-runtime compatibility Resume passed:

- Run `4b877c53e6204ed38a13b513aef0bb09`, stage
  `C:\ntfs2refs\envelope-resume-4b877c53e6204ed38a13b513aef0bb09`.
- Task `N2R-Envelope-resume-4b877c53e6204ed38a13b513aef0bb09`.
- Public PID5516 / creation1793499329262, start02:15:29.262237Z,
  native exit0/HND02:19:08.2588846Z (218.9968846s).
- Recovery records `C:\ProgramData\ntfs2refs\runs\recovery-1d20e06b2a2ce539e812c363070e6073`.
- Actual result: exclusive_recovery_journal_used=true, ApplyIntent/Resume,
  complete1084 maps, known157 hashes/119009 payload bytes,654 digests absent,
 650 materialized tails/1371388 bytes. Source is online ReFS; shadow6 absent.
- Wrapper1440 / creation1793499175077 passed all811 independent hashes at
  02:24:43.6123698Z (+335.3534852s). Closed55 metadata files88,769,148B were
  copy/source SHA verified: exclusive-recovery-resume-4b877c53, index675ad553,
  receipt0725122b. Final-idle02:26:00.1779416Z preceded normal shutdown.
- Saved Resume checkpoint8087814c-b2ed-4060-b321-fccaa8869873, parent ORIGINALdea.
  Fresh process confirmed Off/RAM0/47. Checkpoint receipt SHA
  `454b701d9bf340993994b5328e8242a8c36a28ba39542db19f17d1f70724a188`.
- Existing monitor has timestamped live CIM samples, not retained final native
  IO counters. Never relabel the last live sample as final or claim a measured
  final read delta. The read reduction is currently code accounting.

New public source `adf08e94f4edb0f3910537864f4c8f5262bc99fe`, binary9,931,264B:
`34c9cc072a9441ce4d41599ad82abd5226acb19195ae321df1558bd399b3c7e9`.
Schema2 toolset `.lab/hyperv/streaming-v2-20261027/envelope-recovery-tools-adf08e9-compat/manifest.json`,
SHA `947de265461082609700031160282b33cc0a16c3a18f0ed14c94d626a413673c`.
Its source_commit scope is PUBLIC RECOVERY ONLY. Original producer remains
E4ff/9140, actual5208/creation1793495149312/exit86. The original manifest5102
is staged unchanged; inherited helpers have no invented build revision.

Original journal directory:
`C:\ntfs2refs\envelope-interrupt-d4f9c35229b84373a0ba3ff0887763d1\conversion`.
Bundle SHA `cd919acd5237d3c5087017b2c312ba54cb1d72cea09d634182cebe4e21515f26`.
Original producer manifest `.lab/hyperv/streaming-v2-20261027/envelope-recovery-tools-e4ffb3a/manifest.json`,
SHA `5102ee458144233f56a6f5c8ca2758bd775934dff78ee4ba68f7eb1f50d5dd4c`.
Original producer SHA `9140d57cc18a7f3dac0e7cadd1ffdb9210324bf607c58cfb8042a595f9f655d2`.

NEW-runtime Rollback104ca6aae25c40f7b5cabeef3d502943 also PASSED from ORIGINALdea,
not the saved HND branch. Native5548/creation1793500267757 exited0/ABT at
02:33:52.4674809Z (164.7104809s from millisecond birth); actual owner=true,
ApplyIntent/Rollback. Original old-selected SHA037b3963…7775c46d matched over
all D11392847872/N3547. NTFS64KiB/label/shape1084/all811 hashes passed at
02:35:45.9183803Z (+113.4508994s); no independent postrollback maps/time claim.
Closed53 metadata files62133832B copied/sourceSHAverified, indexe3a699dc,
receipt7149e13e. Final-idle02:36:23.4990939Z preceded normalstop/finalNTFS48.
Checkpoint receipt SHA169ae84302d6f12220fd820c89b87c54fceb1ec3477bb3bd45df8dae81b7867c.
Both new journal-owner directions are qualified for this recorded old journal
and conservative request only. Final native IO/CPU unavailable; preserve that
limitation. See docs/exclusive-recovery-native.md and its evidence JSON.
NEXT: qualify actual-byte capacity on a fresh8329 conversion with J8GiB.
Use the sealed actual-byte-capacity-tools-adf08e9/manifest.json,
SHA4f62f03a1ae0ba978358e9128c3418d8c153cb0b63537248938c12e3788ea107;
new producer80e5b0ff/7055360B and same newpublic34c9, inherited helpers.
The new8GiB recovery controller is reviewed/PS5 parsed, sourceSHA860a571e…fdf2912.
It requires REAL future actual-byte-capacity-interrupted-checkpoint receipt
(schema1/kind exactly as documented in its header), actual producerPID/birth/
86/firstflush/noHND/idle, checkpoint and actual parent8329, original bundle and
five original metadata pins. It cross-checks the actual Hyper-V parent node;
never invent a receipt or legacy producer fields. Pinned helper-source SHA
inputs are mandatory. No8GiB interrupted receipt or native case exists yet.
Two slots remain for a new normal/fault; later recovery branches need reviewed
retirement of superseded states, never a new storage epoch. Latest source contains
capacity policy, but this compatibility run uses the original conservative
request and does NOT qualify expanded actual-byte capacity.

## Evidence and current implementations

- Frozen E4ff old-zero matrix is complete: first flushed write86, clean restart,
  Resume0/HND, separate original-state Rollback0/ABT, all811 hashes both ways.
  Old-selected checksum exactly matched original ticket. This is not arbitrary
  faults or physical-power-loss qualification. See docs/old-zero-recovery-matrix.md
  and evidence/old-zero-recovery-matrix-20261031.json.
- Preserve new normal6bef3bd2-db31-45fe-9e6c-939c812b7375, interrupteddea902f6,
  clean grown source
 83290a28-1e83-4eb2-a4d3-b0e9f5a8d63b, original F source6fe2d6b6, H source371ae756,
  H tail matrix3cbc/119/643/fcc, D1 cold d939 and guarded f4bf5238; also preserve
  new journal-owner ReFS8087 and restored-NTFSd40b until superseded with evidence.
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
