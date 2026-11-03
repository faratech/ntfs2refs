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

## Current live work: verify before acting

**Public scratch-minimizing conversion is LIVE at the last actual poll**:
run f856e0a021bb44e2930f66846a5459e4, source a0b29e04dd2e83086823349724e7e2a8ccf905f5,
public binary SHA 1cc91461deae2d97df5390da1a5cb9d8a25c9f864574a39f492889305370dfe9.
Actual PID **5324**, birth **1793737914035 ms**, task
N2R-ResourceFixture-f856e0a021bb44e2930f66846a5459e4 was Running at
2026-11-03T20:35:46.915Z, source OFFLINE|READ_ONLY (3), no terminal receipt.
Guest stage C:\ntfs2refs\resource-fixture-f856e0a021bb44e2930f66846a5459e4;
actual public run C:\ProgramData\ntfs2refs\runs\bd38a1599dae8ce8b1f23195eddde9f6.
The helper's unused K: output path is NOT the public output. Actual argv is
--drive F --partition 2 --minimize-scratch. Host dispatcher 88257 completed,
not the native worker. All builders/checks are terminal. Poll the same actual
PID AND birth/task/owned terminal before any power/restore/second worker.
Do not bypass the live native-events.log sharing lock to read it.
The resources are admitted from observed hardware; native completion, speed,
full physical footprint and the new guard's recovery remain unqualified.

**Both actual V4 restart directions now passed**, using old acbcc producer
and corrected a0b reader, from the SAME original AP checkpoint a51e134b-9c2f-4de6-9794-37e8d664b79a.
The controlled interruption wrote/flushed/read back 4 KiB at offset 4096,
with another selected 4 KiB at offset 0 still OLD. It was boot/reserved metadata,
not the first copied user payload or physical power loss.
- Rollback ea51f01d132e465ea3aac4ff9aab47fb, PID3564/birth1793734231523,
  actual exit0/462.8372956s: NTFS64KiB, original F:/label, ABT and source0.
  All811 independent XXH3 streams/9,885,801,949B matched; 1534 original
  path/type/length objects and 1024 extra directories checked/captured.
  Archive72files949084B SHA7101a462e1ab960f4dbd31ac05b3f19c9bec4179c872b41d97e57210a0704b94.
- Resume8153619678074311931e18f6548f1f99, PID1432/birth1793735658561,
  actual exit0/935.2567496s: healthy ReFS4KiB, 2558 metadata/map bindings,
  157 known hashes/119009B,654 extent-only streams, HND/label/mounts complete.
  Independent811 hashes AND all1024 extra UTF16 directory paths matched the
  NTFS manifest8f14bdc273f05813732fa80250df74302525d8837061da46c61a0039e741678b.
  Archive72files949262B SHA1af64e312e5a87cc3e341512b5735dcad09bf33197f8a19b1aeaf46d3507527a.
See evidence/resource-v4-restart-{rollback,resume}-20261103.json. Independent
ACL/SACL/time and complete-no-extra-original-object audits are not claimed.
Fresh a0b preparation-guard interruption/mixed-copy repair remains unqualified.

The verified ReFS/HND result was saved Off at **b1de36d8-2520-4d67-8165-fd1358e9c7d5**,
parent a51e, before starting the fresh public run. **Never replay that HND
branch's old NTFS journal.** The current public helper restored clean NTFS
checkpoint3343f2a4-cf81-4fa9-a504-030425a8011e exactly once.
Original AP a51e, clean3343, alpha AP58bd and required ancestors remain.
Authorized cleanup retired old closed HND ba81 then411c only, after all172
small archive files and frozen package pins were verified. Their restorable
old guest images/large journals are retired; evidence/package remain.
Full ALL-.lab+shared target+staging after cleanup272447465589B, host free134104756224B;
the UNCHANGED42949672960B forecast passed original max329374052988/min17179869184.
No cap/epoch/forecast was raised or reset.

Code is frozen at a0b. One shared target/source cache built the three tools;
manifest331098d19f6f8d800abc3988522fd9d2feaccb37b38fcdf926d125e59cac4403.
Source changes include paged NTFS prealignment, metadata-only prepass,
preallocated journal capacity, durable early preparation guard, scoped capture
read reuse, and fully closed index writers before fresh readonly pinning.
The index fix retained strict retirement checks; a focused Windows probe with
262144+6816-byte writes reproduced allocation278528->270336 on last close.
The two new-file probes never touched the source or original journal.
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

1. Follow the actual live Resume to terminal evidence, preserving source/journal
   protection and the original AP origin. On actual success run independent
   CompareRefs against all 811 baseline hashes, original names and the newly
   pinned NTFS extra-directory manifest. Rollback is separately scoped evidence.
2. Qualify new V4 recovery/finalization changes against the real native stack.
   Missing/corrupt journal, wrong identity, low space, and interruption stages
   must fail safely; preserve actual journal and source protections.
3. Qualify current P3 resource-paged source prealignment inventory, planning,
   executor and receipts. The committed public --minimize-scratch hook now
   calls it before final freeze and obtains fresh source admission afterward;
   this compiles but has no native result. Previously pinned V4 binaries only
   changed capacity policy and did not run the old NTFS placement prepass.
4. Reduce repeated journal/artifact reads through same-owner receipts only
   where actual immutable capabilities and required before/after checks are
   preserved. Preserve final native gates; never replace proof with JSON flags.
5. Retire artificial count/size caps through paged evidence and real resource
   accounting, not larger constants or truncation. Large-volume, geometry,
   feature and production qualification remain open.

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
