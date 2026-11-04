# ntfs2refs: current handoff

@C:\Users\mfara\.codex\RTK.md

Work in **D:\code\ntfs2refs**, branch codex/resource-based-admission,
private origin faratech/ntfs2refs. The environment's C: workspace path is
stale. Read RTK before operating.

The previous AGENTS.md was copied **verbatim**, including its historical
evidence and instructions, to
[AGENTS-through-20261103-resource-continuation.md](docs/history/AGENTS-through-20261103-resource-continuation.md).
Its old CURRENT/LIVE labels, status claims, and old keep lists are history,
not current instructions. Earlier archives remain in docs/history/.

## Objective and user constraints

- Finish a usable, efficient in-place NTFS-to-ReFS converter with broad
  compatibility and resource-based scaling. Do not redefine completion as
  the existing bounded native successes.
- Conversion and recovery must run inside the Windows machine owning the disk.
  Hyper-V is test infrastructure, not a product dependency. Boot conversion is
  deferred; the current focus is nonboot data volumes.
- Preserve the frozen native-shadow alpha and build on it. Independent writer
  and forensic-parser research is off the critical path; do not copy GPL
  engines into the Rust product.
- Prioritize actual implementation and necessary native integration. The user
  explicitly directed: **do not add or run unit tests** unless specifically
  requested. Focused builds and necessary existing native checks are allowed.
- Minimize reads, scratch storage and RAM. Do not repeatedly perform expensive
  checks already answered by unchanged evidence.
- Commit stable task-owned changes and push normally; never force-push. Stage
  exact owned paths, not git add all. Avoid speculative changes near release.
- **Do not edit, format, reset, clean, or otherwise alter src/main.rs.**
  Preserve approved SHA-256
  c6bc5c52c8458ee70bd2567a9d8350105aeaa6245448df22675780403e04348b.
  The user previously approved committing its existing edit unchanged.
- Keep WSL running. Do not disable UAC, stop WSL, or add new persistent
  privilege changes. Do not expose credentials.
- User authorized deletion of obsolete checkpoints and ordinary cleanup,
  subject to the safeguards below. Preserve active recovery and evidence;
  do not infer a preserve-all policy from archived historical instructions.

## Current state: verify before acting

**NEW PUBLIC CONVERSION33a1bb206c51427298b6240fe5a261f9 IS LIVE.**
Root's launch-public-resource-min-k helper completed exit0 (session67606 closed).
Actual nativePID5364/birth1793751740787 was independently matched live; SYSTEM
workerPID5208/birth1793751734250, boot1793751711106. No native terminal yet.
Exact pinned
cad public binary/manifest below, --drive F --partition2 --minimize-scratch.
Hostroot.lab/hyperv/streaming-v2-20261027/resource-fixture-33a1bb206c51427298b6240fe5a261f9;
gueststageC:\ntfs2refs\resource-fixture-33a1bb206c51427298b6240fe5a261f9.
VM actually restored ONCE to3343f2a4-cf81-4fa9-a504-030425a8011e and is Running.
Inspect owned dispatch/task/native-process+PID/birth/terminal before any power
or repeat launch; dispatch alone does not prove a native process started.
The helper's K fixture path is unused by public CLI; derive real engine output
from actual stdout. Root admitted unchanged40GiB forecast against ALL lab/cache/
staging277388706458B/free129186086912B after cleanup; no cap/epoch reset.

The completed partition experiment was normally shut down and saved Off/RAM0
at766c9abc-8582-4de6-b497-8acbc81274da(parentfe668), boot1793750646712,
before the NEW run's restore. On THAT saved branch only: F NTFS64KiB/source0,
C shrunk2GiB, T NTFS4KiB/attrs0/online/original8192B marker verified. Never repeat
shrink/create/format/regrow on that branch. T Windows number4/raw GPT slot4;
Recovery Windows5; original preboot ordinals T5/Recovery4. Resolve GUID+extent.
Those saved layout facts do not describe the newly restored3343 branch.

Old inactive leafb1de36d8-2520-4d67-8165-fd1358e9c7d5 was retired using
Remove-VMSnapshot AFTER all72 archive entries/949262B and manifestSHA
1af64e312e5a87cc3e341512b5735dcad09bf33197f8a19b1aeaf46d3507527a matched.
Its old restorable HND image/J/shadow were intentionally discarded; evidence,
originala51 AP, latest7d81 HND, closed766 partition case and guardedf4bf remain.
Fresh graph verified retirement/current ancestry before the new restore.

New committed source **cad91399bee9dd805ed79927f3c8d334206a8970** adds a readonly
partition-scoped SDK reader and root lab observer. Earlier commitc4aef9e fuses
immediate fresh-apply read-only admission bookends, removing two duplicate
consumed-shadow scans while preserving both complete source/target checks.
For the closed f856 range set that is12,353,544,192 fewer logical shadow bytes;
**the changed converter has NOT had its own full native conversion run**.
Focused cargo check and pinned four-tool release build passed; no unit tests.
Shared build manifest7096f004b68eca13f6594c692c87f6c87245be2125b76a4836737d929169d395
at.lab/development/release-candidates/partition-readonly-cad9139/manifest.json.
PublicSHA6ffe59ce8a6f9118b49a5b14202c3618b950e8ed08978e5f0d10fb24cc544789;
readonly observerSHA51fb56bf2b4e557c36d33645da6d3ea4230bd6b80e778df44f5371df92b13984.
The earlier native-qualified a0b candidate and frozen alpha remain preserved.

Native partition probe: mountvol T:\ /p established runtime exclusion but
failed reboot persistence. Target-only GPT_OFFLINE0800000000000000 plus separate
IOCTL_VOLUME_OFFLINE survived normal reboot, with C: healthy and volume reads
failing21. Rust observer PID5508/birth1793751041553 actually exited0/0.0417076s,
read exactly8192 payload bytes, matched the independent SHA and resolved C:
pagefile outside source. It admits no conversion/isolation/recovery authority;
dump configuration remains explicitly uncollected. New reader uses admitted
GPT/layout/read buffers and a separately bounded native-layout query.

Same-byte raw-write probe failed NotReady21; exact old-helper failure stage and
write completion are UNKNOWN. Do not retry its entry point or claim success.
A separate zero-write diagnosis proved same physical RW open/identity/GPT reads,
marker read/hash and FlushFileBuffers all succeed. Missing actual filesystem
lock/dismount ownership is a hypothesis, not proven cause. GPT/runtime offline
alone DOES NOT qualify the Windows raw-write interlock. Keep writer unavailable;
next fresh protocol must retain a real lock/dismount owner and separately prove
post-reboot owner reacquisition without clearing exclusion to evade refusal.

Original T attributes and access path were restored; C and both markers matched.
No physical writer was connected to the product, whole-disk guards unchanged.
See evidence/partition-scoped-source-20261103.json and docs/partition-scoped-source.md.
ALL24 guest source metadata files/1373304B were independently length/SHA-verified:
.lab/hyperv/streaming-v2-20261027/partition-probe-803bb22b85044f74916d9cc6fda878c8/closed/manifest-verified.json,
SHA8bdfd914ce5c70cdd4a6dbe043cf8c9e705fb12ca343d2d36e281b75927c5253.
The earlier manifest with a null aggregate remains history, not authoritative.

Earlier full a0b minimum-scratch conversion/mutation/reboot/HND remains saved
at7d816cf1-f924-44d0-ba27-c5e44eafa4a1(parent3343). Native1036.1624366s,
811 original XXH3 streams/9885801949B,1534 baseline objects,1024 extra dirs and513
post-reboot mutation hashes matched. J184184288logicalB; retained regular-file
allocation1220053920B postboot, not peak scratch. Observer-close logical reads
189617274776B are neither physical nor exact final I/O. Never replay old HND J.
The normal early Frozen restart cancellation, actual HND-open failure and older
acbcc-producer/a0b-reader AP Resume/Rollback evidence are preserved. These earlier
results do NOT qualify the new cad converter build.

All previous current/live labels and detailed case pins were copied verbatim to
[the preceding handoff](docs/history/AGENTS-through-20261103-before-partition-reader.md).
Inspect actual latest task/PID/birth before any VM power/restore or dispatch.

## Real evidence and boundaries

- Frozen published alpha 7feb4c0 passed one controlled Hyper-V TurnOff and
  AP-resume-to-ReFS case. See
  [exact-alpha-resume-after-vm-poweroff-20261103.json](evidence/exact-alpha-resume-after-vm-poweroff-20261103.json).
  It is a bounded experiment, not physical-power-loss or general release proof.
- Public V4 source 5a8b781728726fec5e0f9351fa3b61c8633a7e19 completed a
  real same-partition conversion, exit 0, in 2588.6345994 seconds.
  It recorded 2,558 metadata/map bindings and 811 streams: 157 known hashes
  covering 119,009 bytes, and 654 extent-only streams. The journal was
  5,821,929,848 bytes. The last live process-read sample was 497,108,655,663
  bytes, not final or physical I/O; peak RAM/scratch was not measured.
  See [public-resource-first-conversion-20261103.json](evidence/public-resource-first-conversion-20261103.json).
- That completed HND/ReFS branch was saved at
  411c47b6-652d-432a-81f9-8bd10ff18e1b. After cold boot, independent
  observation matched all 811 original XXH3-128 streams, totaling
  9,885,801,949 bytes, and 1,534 baseline namespace/type/length objects.
  The extra 1,024 directories were not independently checked after boot.
- Public terminal recovery source 03868c1 completed already-online HND
  reconciliation, native exit 0, without raw replay or comparing mutable
  mounted bytes to stale selected bytes. Beforehand 33 ordinary ReFS files
  were created/mutated; their recorded lengths/SHA remained unchanged after
  that recovery. It does not qualify V4 AP/RB recovery.
- The resulting operational branch was saved Off as
  ba81a1f8-eee9-40d6-957f-31acbb09b98e, child of 411c. Both are closed
  HND branches: **never replay their old raw journals**.
- Diagnostic 6189937fca3445bfb0f216c4588641d5, source 96f9587, failed
  before its first write on RAM accounting; actual exit 1 and a zero-filled
  signal are not a valid partial-write result. The later a7 fixes were built,
  but the later fc838 run refused journal allocation before AP and likewise
  did not establish a valid signal/recovery.
- Exact record archives, hashes, prior qualified cases and refusals are in the
  linked historical handoff and evidence/. Do not recreate retired snapshot
  IDs or transfer qualification from one binary/build to another.

## Current engineering priorities

1. Qualify the frozen a0b candidate's remaining focused I/O-failure/low-space,
   remaining mixed/torn/corrupt guard-copy and authenticated active restart cases. Track
   actual new dispatches; terminal historical workers do not prove no new work.
2. Preserve actual source/journal exclusion and HND/ABT no-replay rules. The
   completed public minimum-scratch and mutation/cold-boot cases now have exact
   evidence; do not repeat them without a changed build or unresolved concern.
3. Attribute remaining repeated reads from the authenticated phase ledger.
   Preserve checked evidence; optimize only with concrete same-owner receipts.
   Public per-boundary checks still repeat about13.44GB logical transfers.
4. Retire active-path artificial collection limits through complete paged
   evidence/resource accounting; qualify useful geometry and partition-scoped
   exclusion for data partitions sharing the Windows disk. These remain open.
5. Freeze/package/document one candidate with its own complete native matrix.
   Arbitrary hardware/scale, physical power safety and stable release are not
   established by the current scoped VM successes.

Allocation-bounded is the default: compare/write authenticated target-required
ranges. NTFS free space is not claimed unchanged. Whole-image mode retains its
full checks. The approved destination-bitmap window check does not replace full
phase maps, per-file retrieval, all-placement or final allocation checks.
Incremental retrieval remains deferred.

Extent-based fast verification is the approved default; retain full-content
verification as an option. Prove retained bytes via exact metadata/physical
extent identity; checksum moved/rewritten bytes during their I/O. Preserve
namespace, ACL, allocation, full retrieval and recovery checks. Explicitly
absent digests stay absent. User-file/resident/native content digests use
XXH3-128 despite some legacy field names; artifact, metadata, residual-tail,
whole-image and journal pins use SHA-256.

Preserve all required zero writes: reserved-zone zero skipping was disproved.
VSS, directory case sensitivity, EFS, additional reparse/security forms,
boot/system volumes and broader geometry remain unqualified. ADS, sparse,
compression normalization, EA, security and Microsoft reparse points have
scoped evidence only. Any actual narrowing of checked evidence requires a
separate user decision. Never silently discard unsupported NTFS semantics.

## Source and recovery invariants

- Fresh Apply requires its original opaque live source certificate and the
  actual held source/target/journal/arena owners. Never reconstruct authority
  from a JSON flag, old report, pathname, or recovery bundle.
- Recovery bundles supply independently pinned routes only. Real device,
  file, journal, ticket, index and lifecycle checks authorize recovery, never
  a new fresh Apply. Keep every mode-required pin and recovery artifact.
- HND/ABT close old raw replay. After operational writable use, do not replay
  or compare mutable selected bytes against a stale postimage. Observe and
  reconcile the mounted terminal state through the dedicated non-replay path.
- Do not clear exclusion, online/rebind/reidentify a device, or bypass a live
  sharing lock to evade a refusal. Fail closed on unknown identity, mixed
  bytes, missing protection, ambiguous marker, or unresolved ownership.
- Preserve validated write ordering, pre/post checks, actual flush/readback,
  source/target identity, persisted exclusion and handoff boundaries.
- After any restore/checkpoint, verify parent/state from a **fresh** process;
  cached Hyper-V objects can be stale. Do not repeat a successful operation
  because an old object disagrees.
- A mount, hash, code-derived accounting estimate, or live sample alone does
  not establish semantic fidelity, allocator correctness, power-loss safety,
  final I/O, or stable release readiness.

## Storage, RAM and cleanup

The original fixed epoch is unchanged: initial lab **279374052988 B**, initial
host free **66133905408 B**, maximum actual **329374052988 B**, minimum host
free **17179869184 B**. The original total additional allowance is
**50000000000 B**. Never reset the epoch or its baseline after cleanup.
Before growth, remeasure/admit a justified phase forecast through
lab/Lab.psm1 and lab/lab.config.json; charge all current lab files,
target\shared-experiments, and shared staging bytes.

Delete snapshots only through Hyper-V APIs, never AVHDX chain files. First
verify actual inactive graph, child order, current parent, dependency pins and
archives; remeasure after merges. Do not remove or force guarded checkpoint
f4bf5238-14c0-4b15-bda6-7859abd4d1c9 (archive mismatch).

Automatic approval review previously rejected deletion of a research image,
duplicate checkout D:\code\ntfs2refs\.lab\ntfs2btrfs-source-audit, and
three old .lab\development Cargo caches. Do not retry rejected actions
through another shell or method. Approved Hyper-V cleanup is separate.
Resolve absolute targets before cleanup and use one native PowerShell shell
with literal-path operations; do not delete guessed or active artifacts.

Keep .lab, images, journals, ISOs, binaries and secrets out of Git.
Credentials are only imported from
.lab/hyperv/win11/secrets/guest-credential.xml; never print them.
The VM is 2401593c-4b30-472e-9b6d-c9534cbaa599,
ntfs2refs-streaming-v2-20261027, fixed 4 GiB / 4 CPUs / no NIC.

## Build and tooling

Use Rust **1.98.1** and the existing pinned MSVC toolchain. Set TEMP and
TMP to D:\code\ntfs2refs\target\tmp. The user wants one shared experiment
build directory: D:\code\ntfs2refs\target\shared-experiments. Use its
exclusive sibling lock; never modify old frozen candidate targets.

Use the existing lab/Build-ReleaseCandidate.ps1 with exact committed source,
pinned tool/config/archive hashes, fresh output directory, offline/locked
release mode and -UseSharedExperimentalTarget. Its optional verified shared
source staging uses -UseSharedExperimentalSource and
-ExpectedSharedSourceHelperSha256 842c5e7f7e65a1df72e6276af505e47f85f79b649429fe1eeac0833d1b534992.
The builder records cache use; it is not a clean-build, reproducibility, or
native-qualification claim. Default isolated release builds remain separate.
Experimental builder defaults to four jobs; preserve its lock and actual
session IDs. The a7 manifest records exact 1.98.1 cargo/rustc pins.

For routine focused cargo check, use the shared target and same lock.
Process-local CARGO_INCREMENTAL=1 can help; clear RUSTC_WRAPPER and
RUSTC_WORKSPACE_WRAPPER for that check because the host sccache wrapper
rejects incremental builds. Restore no host-wide settings.
Format only owned Rust files with rustfmt --edition 2024 --config
skip_children=true; never use workspace-wide formatting or touch main.
Documentation-only edits need no rebuild. No unit tests unless user requests.
