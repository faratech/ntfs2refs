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

**CURRENT LOW-RESERVE / EARLY-CANCEL CASE IS COMPLETE**, not live.
Root's latest actual state is VM Running, parentfe668886-647a-4928-9c14-9fd9e323aefb,
boot1793747939459, original F: NTFS64KiB/original label/source attributes0,
no active product worker. Always check actual newer task/PID/birth before any
power/restore/dispatch; this historical completion is not a new liveness probe.

Prepare-only489777a11e84413fb50ebe9fc06063b0, PID5360/birth1793747474820,
actually exited1/247.2616313s at2026-11-03T23:15:22.1073085Z. Only the request
minimum_free_bytes became33285996544; protected-target-capture refused with
"capture does not have its remaining journal and reserve capacity". Source
stayed3; no J or AP existed. This is admission-reserve refusal, NOT actual
ENOSPC, write/flush/readback failure or power loss. Closed16files5015551B,
manifestcbdff236ccaedf73d0c312b2601dc0f2b9e9840acd76c989014321a3ba426a6f.

Root saved Frozen checkpointfe668 (parent3343), then normally restarted. The
ordinary LabAdmin public early-cancel command, PID2256/birth1793748006977,
actually exited0/0.1461095s at23:20:07.1489079Z; exact intentSHA
df9866259919e96c06582cea63cc3f8b179f5f2027ee2f0dfd0d4cb713a4b2b1.
The product returned NTFS/F:/label/source0 with no whole-partition hash, source
payload writes or journal replay. Both original Frozen copies and both final
Cancelled copies validated; nonce+locked boot and the1971B intent stayed equal.
Final131072B stateSHAfed3a8262d9e9d998d389ffaf6177145c9fb40cbcb8fed000094a8ffc3fc109c.
Independent SYSTEM observer matched811 XXH3 streams/9885801949B,1534 baseline
objects and1024 extra dirs opening/closing;13 actual native digest exits0.
New capture1013b8807eccf653bf26a58b0fab055be21245b0e14d3a3275cae831961595c9
has the EXACT same paths object as old8f14 (boot fields differ). Closed66files
928764B manifestf36e8940bf2cee9cc4a45c6de5625f5f857c23427fa46f5ebe4e920855191951.
See evidence/resource-v4-early-cancel-20261103.json. Normal Frozen restart
cancellation is now qualified; mixed/torn/corrupt/missing copies and physical
power loss remain unqualified. Product source remains frozen a0b.

The successful full minimum-scratch/mutation/cold-boot/HND result remains saved
at7d816cf1-f924-44d0-ba27-c5e44eafa4a1(parent3343); NEVER replay its old raw J.
Original a51e and prior b1de HND remain. The completed early cancellation acted
only on a separately restored original NTFS prepare-only branch.

**Public scratch-minimizing conversion f856 is COMPLETE**, not live. Frozen
source a0b29e04dd2e83086823349724e7e2a8ccf905f5 / public SHA
1cc91461deae2d97df5390da1a5cb9d8a25c9f864574a39f492889305370dfe9,
actual PID5324/birth1793737914035, exit0 in **1036.1624366 seconds** at
2026-11-03T20:49:10.231566Z. Actual argv was --drive F --partition 2
--minimize-scratch. Native HND/finalization matched2558 metadata/map bindings,
157 known hashes/119009B and654 extent-only streams, original label/mounts.
Actual public run is C:\ProgramData\ntfs2refs\runs\bd38a1599dae8ce8b1f23195eddde9f6;
the host helper's unused K: path is not this run. Native NTFS prealignment
verified343 moves/5,643,501,568B on222 files, no skips or stopped outcome.
The new early guard created/froze/delegated normally; its two checked identical
state copies bind publication92211da15e0025b9d721daf33e6c886c64a261de34a3b40debb62743eb4b9204.
The separate normal Frozen restart cancellation above is qualified; interrupted/mixed-copy repair remains unqualified.

**Completed minimum-scratch case's post-boot state** was healthy original F:
ReFS4KiB/original label/attributes0 at boot1793746065079. All converter/observer
workers belonging to that completed normal case are terminal; the independent
current low-reserve worker above is live and must not be interrupted blindly.
Both subsequent HND journal-open cases are terminal. Actual read-only exclusive
journal-lock failure baae exited1/ERROR32 in0.0783545s while its lock stayed
held through real exit; journal SHA/identity and online ReFS remained unchanged.
Normal e3c reconciliation actually exited0/15.7690999s with verified HND,
no raw replay, no OLD/NEW comparison and no conversion-time data rehash. Its
wrapper task exited1 only because the output parser missed the valid final
label-reconciliation message; the original worker-failed record is preserved.
Root independently observed all513 mutation hashes still matching afterward.
See evidence/resource-v4-hnd-open-failure-20261103.json. This qualifies a real
HND open failure, not active AP write/flush/readback failure. The earlier cc90
pre-native helper error remains unqualified history. The successful minimum-
scratch HND result is now saved at7d81; the separate live low-free-reserve case
is described above. Root alone controls the VM; inspect actual latest task,
PID AND creation time and owned terminal files before power/restore/dispatch.

Independent SYSTEM observers matched all811 original XXH3 streams /
9,885,801,949B and1534 baseline path/type/length objects before and after a
normal shutdown/restart WITHOUT restore. All1024 extra UTF16 directory paths
matched the independent NTFS manifest8f14bdc273f05813732fa80250df74302525d8837061da46c61a0039e741678b.
Only new test paths were mutated:512 small creates,64 deletes/replacements,
16MiB growth then1048699B truncate/rename,513 live files; all513 hashes/lengths
matched after reboot. Original payload files were never written by the probe.
No independent full ACL/SACL/time, complete-no-extra-original-object, physical
allocation-reuse or physical-power-loss proof is claimed.

The journal is184184288 logical bytes /184184832 allocated bytes; literal
backing85946368B plus494336B capture index. Retained regular-file allocation
was1245219744B before reboot and1220053920B after; the shadow alone shrank
25165824B on clean close. These snapshots exclude directory/MFT global overhead
and are NOT peak scratch. GetCompressedFileSize values equal EOF here; use
FileStandardInfo AllocationSize for the rounded file allocation totals.
Observer-close logical transfers were189617274776B read /3030345500B written;
not physical storage I/O or exact final counters. Peak RAM/scratch are unknown.
Admitted RAM1890108843B /scratch29182386176B are ceilings, not measured peaks.

The complete metadata ZIP (large shadow/J/literal excluded and retained in guest)
is .lab/hyperv/streaming-v2-20261027/resource-fixture-f856e0a021bb44e2930f66846a5459e4/closed-min/metadata.zip:
25036814B, SHA5bc838b89e6b01700acfb4cc8c76e21d9a0aebb2ce9043bbd6e5b552bb814f1f.
ManifestSHA05b301c2537f05211e35474a74080ed4b1209d470e16dc98abb2dae9605b89f0;
ALL4336 source entries/167319552 uncompressed bytes were length/SHA-verified.
Closed ledger40 frames/payload hashes/chains/closing record are authenticated.
See evidence/public-resource-minimize-20261103.json for exact scope.
**The current operational HND journal is permanently closed to raw replay.**

Both older actual V4 restart directions passed from original AP a51e134b-9c2f-4de6-9794-37e8d664b79a:
old acbcc producer -> corrected a0b reader. Rollback ea51 exited0/462.8372956s
and returned NTFS64KiB; Resume815 exited0/935.2567496s and returned healthy ReFS.
Both independently matched811 hashes; resumed1024 extra names matched NTFS.
That original fault changed/flushed/read back4KiB at offset4096, with primary0
still OLD: boot/reserved metadata, NOT copied user payload or physical power.
Its verified HND branch is saved Off at b1de36d8-2520-4d67-8165-fd1358e9c7d5,
parenta51e. Never replay its old journal. Original APa51e, clean3343, alpha AP58bd
and required ancestors remain. Old closed HNDba81/411c were retired after172
small archive files and the frozen package were verified; evidence remains.
After cleanup ALL-.lab+shared target+staging272447465589B, free134104756224B;
UNCHANGED42949672960B forecast passed max329374052988/min17179869184.
No cap/epoch/forecast was raised or reset.

Code remains frozen a0b; candidate manifest
331098d19f6f8d800abc3988522fd9d2feaccb37b38fcdf926d125e59cac4403.
One shared target/source cache built the three tools. Source fixes include
paged metadata-only prealignment, journal preallocation, durable early guard,
scoped capture-read reuse and fully closed index creators before readonly pins.
No unit tests were added or run.

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
