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

**Corrected public Resume is actually LIVE at last poll**, 2026-11-03T20:06:43.712Z:
run **8153619678074311931e18f6548f1f99**, a0b public native PID **1432** /
creation **1793735658561 ms**, task Running, source **OFFLINE|READ_ONLY (3)**.
It restarted from original a51e after restore session 58859 completed exit 0
exactly once; actual guest boot epoch is **1793735566348 ms**. Guest stage:
C:\ntfs2refs\resource-restart-8153619678074311931e18f6548f1f99. The selected
write phase progressed, but protected observation/verification is still active;
**no HND, exit 0 or completed Resume is asserted**. Last process samples were
231,345,872,629 logical-read and 11,405,314,277 logical-write transfer bytes and
27,328,512 private bytes: not physical/final I/O or peak RAM. Host dispatcher
54317 is complete and reported Running only; it is not the native handle.
All builds/checks are terminal. Poll the same PID **and birth**, task and owned
terminal files. Never restore/stop/start another worker on timeout. Only after
actual successful termination may Root run the independent CompareRefs observer
using the pinned NTFS extra-directory manifest 8f14... below.

**Actual post-restart Rollback passed** on source a0b29e0 reading the original
acbcc publication: run ea51f01d132e465ea3aac4ff9aab47fb, native PID 3564 /
creation 1793734231523 ms, exit 0 in **462.8372956 seconds**, terminal
2026-11-03T19:38:14.4034697Z. Actual AP became ABT; restore-required selected
bytes and F: mount were verified, and Windows reported original NTFS / 64 KiB /
label n2r-stream-source, attributes 0. An independent SYSTEM observer matched
all **811 original XXH3 streams / 9,885,801,949 bytes** and 1,534 baseline
path/type/length objects. It enumerated all 1,024 extra directories before and
after hashing and captured NTFS manifest SHA
8f14bdc273f05813732fa80250df74302525d8837061da46c61a0039e741678b for future
comparison; that is not a comparison to a separate preconversion extra-dir
baseline. No complete ACL/SACL/time or no-extra-objects audit is claimed.
See [the exact rollback](evidence/resource-v4-restart-rollback-20261103.json).
Closed archive: 72 files / 949,084 bytes, manifest SHA
7101a462e1ab960f4dbd31ac05b3f19c9bec4179c872b41d97e57210a0704b94.
**Never replay the closed ABT/writable NTFS branch.** After archival, Root
normally stopped it and restored original a51e once; session 58859 completed
exit 0. The separate live Resume above is running from that original AP state.
This qualifies old acbcc-producer/new a0b-reader rollback, not fresh a0b apply,
the new early guard, copied-user-payload interruption or physical power loss.

Diagnostic **d9c893d3e6a343f4b5ef8544c6eebeca is terminal**. Exact source
acbcc1b00ec5cdb1448b29eaa8e2257fb7015594, native PID 5252 / creation
1793730736468 ms, actual exit 1 after 1652.7334505 seconds. Its requested
interruption occurred after a real 4 KiB write at partition offset 4096,
flush and exact readback, with actual AP and source attributes 1. Another
selected 4 KiB granule at offset 0 still differed from NEW. This was a reserved
or boot metadata write, **not the first copied user payload**. See
[resource-first-flushed-write-20261103.json](evidence/resource-first-flushed-write-20261103.json).
Closed evidence: 21 files / 6,640,939 bytes, manifest SHA
3e5f14fe89b0bfc49c286a3c23f3966e634902be948a9063bd57718bf474bc7f.

Root normally shut down after the worker exited and saved actual recovery
origin **a51e134b-9c2f-4de6-9794-37e8d664b79a**, parent 3343. A fresh process
verified the checkpoint while Off. After restart the actual boot epoch was
1793732805726 ms and source remained offline, attributes 1. Preserve this
original AP branch for separate Resume and Rollback; no physical power loss
was exercised.

Earlier **Resume dc85d03749af4128a4ef77b313a6ef6f was terminal failure.** Public native
PID **3620**, creation **1793732911458 ms**, actually exited **1** after
**90.8334903 seconds** at 2026-11-03T19:10:02.3199026Z. Root verified task Ready,
PID absent and source attributes 1 at 19:11:53.681Z. Stderr was exactly
`error: artifact changed before retirement`; stdout reached preparation of
recovery records. Product output is
K:\ntfs2refs-recovery-12eeeb4663e051fb1ce01a8f325a7720. Only the reopened index
exists in the recovery subdirectory; failure is in opening/retirement before
the public replay method. Actual AP prefix and the original written 4 KiB SHA
were checked after failure; this is not a complete target-immutability proof.
Preserve source exclusion and original a51e; no ReFS success is inferred. See
[the refusal](evidence/resource-restart-retirement-refusal-20261103.json).
It used the original acbcc public binary and publication SHA
594d59d21ee7440d02eea58d65099c0c2ab59f4d389cb723e5e70a46f83a3ace.
The host launcher session 48526 is complete; dispatch alone is not completion.
Current-run JSON has exact paths. Revalidate actual VM/task/process state
before another operation. That failure did not complete either direction;
the later independent Rollback above is separately qualified.
Root subsequently normally stopped the failed branch and restored original
a51e **once**, completed tool session 31226 / exit 0. A fresh process verified
VM Off / RAM 0 / parent a51e before the later Rollback above.
Do not repeat the completed restore because an older cached object disagrees.

The acbcc pinned build is complete, manifest SHA
8543fb8698ec90462d7e297d5e286c6c8da5f65fd28a22ea8e53456d64fabc64;
diagnostic SHA 8a190267414f91f9dbbd0c4538b2b0901b27cba24ce1cc4a43b8820bc3c52484.
The separate metadata-only placement inventory compiled (43.02 seconds) at
aa6e01d; it is not in the interrupted acbcc candidate. Guard source
**6fea7578d132aaec036ecd0482d20a0653afbed3** is committed/pushed and its combined
Windows check passed **24.85 seconds**. It adds the durable cancellation-only
preparation guard and actual PreparedClear/OLD-proved delegation witness.
Its pinned experimental build is complete, manifest SHA
411218f5538127cb25b0788a611646ea8177e7a0807249c0be890f25ccf253bc, with no native
guard qualification. It excludes the later SDK index last-close ordering fix.
That fix compiled in 10.07 seconds and is committed/pushed as
**a0b29e04dd2e83086823349724e7e2a8ccf905f5**. Its pinned build completed in
session 97854, manifest SHA
331098d19f6f8d800abc3988522fd9d2feaccb37b38fcdf926d125e59cac4403, output
.lab/development/release-candidates/resource-index-handoff-a0b29e0. Public
binary SHA 1cc91461deae2d97df5390da1a5cb9d8a25c9f864574a39f492889305370dfe9.
It passed the scoped old-publication Rollback above and preserves strict
retirement checks and the existing allocation quota. An ordinary-file
probe reproduced allocation trimming 278,528 to 270,336 bytes only after the
duplicated creator object's last close; closing the writer before a fresh
readonly open made the final metadata stable. No acbcc result qualifies it.

Authorized cleanup retired ONLY archived leaf checkpoints 5ce766b0 and
bbeb8887 through Hyper-V. Their evidence archives and frozen alpha package
remain; alpha AP origin 58bd, source/ready ancestors and 411c/ba81 remain.
Do not recreate or restore retired checkpoint IDs. Full ALL-.lab + shared
target + staging accounting after cleanup: 281,927,945,785 bytes; free host
124,627,722,240 bytes. The unchanged 42,949,672,960-byte next-phase forecast
passed the original maximum/reserve. No epoch/cap/forecast reduction occurred.

The preceding failed run is retained below as history, not the live worker.

Resource diagnostic fc838b529f5e4d2c904c465cfde97459 is **terminal**, not live.
It used source a7befe8af1aad71e9cab7134f9d4aee5b87d90a4 from checkpoint
3343f2a4-cf81-4fa9-a504-030425a8011e. Native PID **5272**, creation time
**1793727899451 ms**, actually exited **1** after **835.2523342 seconds** at
2026-11-03T17:58:54.7927542Z. Root subsequently observed task Ready, PID absent,
and source disk 1 still **3** (persistent OFFLINE|READ_ONLY), then normally
shut down the VM after confirming no project workers/tasks remained live.
Fresh Hyper-V observation showed **Off**, assigned RAM 0 and parent 3343.
No new checkpoint was taken of this refused branch.
The refusal occurred during native journal preparation, before AP or source
writes. The 4 KiB first-write signal remained all zero; this is not a successful
interruption or recovery case.

The original 5,818,630,248-byte journal remains in the guest. Its closed refusal
archive has 18 files / 4,975,867 bytes; manifest SHA-256
c88f344a08b8ad3fdcddf81a1d4d90ccd3f2f75714914741483da149a370a501.
See evidence/resource-first-write-journal-refusal-20261103.json. A separate
ordinary-file probe reproduced speculative NTFS allocation above the existing
quota while open, then trimming on last close. Same-file preallocation kept
allocation within that quota. The later acbcc case reached actual apply and the
verified first-write interruption above with that fix; completed conversion and
recovery qualification for acbcc remains open.

Root alone controls the VM. Before another operation, poll actual task state,
PID and creation time, owned process/terminal files and real source/journal
state. Never restore, power off, checkpoint, launch a second worker or repeat a
timed-out operation while a worker may be active. Timeouts and remoting loss
are not termination. PID reuse is not process identity.

The opt-in diagnostic is lab-resource-diagnostic --apply-and-verify
--interrupt-after-first-flushed-write. It prepares an independent preallocated
signal before source activation. A valid
K:\...\<output>-first-write-signal\signal.json is evidence only after the real
first native write, flush, exact readback, OFFLINE and AP observations, a
different remaining selected granule, and signal sync/readback. It grants no
replay authority. Exit 1 by itself proves none of those conditions; do not
invent exit 0/86 or claim a physical power-loss test.

Build process 43001 for a7 is **complete**, not live. Pinned candidate:
.lab/development/release-candidates/resource-first-write-a7befe8/manifest.json
SHA-256 1cceb0332abb64e015613bcaf5d06391eb2a2efdb651ded5ce24da593bcefeb0.
Diagnostic executable SHA-256
03b7aa96d5f66361fd272668de5ba24e751535869c34556c46a961eca147ac8f.
Its public executable SHA-256 is
49a741917ed08f2d119671eb6d43d6e7dcadaba44ae844885a5b74363d8409e6.
This is a pinned experimental build, not a qualified release.

The earlier public/diagnostic/recovery-observer check completed, exit 0,
with Cargo reporting 9.98 seconds in
.lab/development/journal-preallocation-check.log. It includes current paged
prealignment orchestration, journal preallocation and canonical page-pin checks.
Those changes were subsequently pinned in acbcc. The latest 6fea guard check
is recorded in .lab/development/early-preparation-guard-check-2.log; source
ownership is frozen. Verify actual Git/process state before further edits.

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
