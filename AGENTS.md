# ntfs2refs: current handoff

@C:\Users\mfara\.codex\RTK.md

Work in **D:\code\ntfs2refs**, branch `codex/resource-based-admission`, private
origin `faratech/ntfs2refs`. The environment's C: workspace path is stale.
Read RTK before operating. `CLAUDE.md` points here.

The preceding AGENTS.md was preserved **byte-for-byte** in
[AGENTS-through-20261104-before-frozen-814-package.md](docs/history/AGENTS-through-20261104-before-frozen-814-package.md).
Its old LIVE labels, pending gates and keep lists are historical, not current
instructions. Earlier detailed handoffs remain under docs/history/.

## Objective and operative constraints

- Finish an efficient in-place NTFS-to-ReFS converter with broad compatibility
  and resource-based scaling. The finite alpha below does **not** complete that
  broader goal. Conversion/recovery execute inside the machine owning the disk;
  Hyper-V is lab infrastructure. Boot/system conversion remains deferred.
- Preserve the frozen native-shadow alpha. Independent-writer research is off
  the critical path; do not import GPL engines into the Rust product.
- The user explicitly directed **no new or existing unit tests** unless asked.
  Necessary focused builds/native integration are allowed. Do not repeat costly
  checks already answered by unchanged evidence or change code speculatively
  near release. Minimize actual reads, scratch storage and RAM.
- Commit stable owned changes and push normally; never force-push. Stage exact
  owned paths, not `git add all`. Keep .lab, images, journals, ISOs, binaries and
  secrets out of Git.
- **Never edit, format, reset, clean or otherwise alter src/main.rs.** Preserve
  its approved SHA-256
  `c6bc5c52c8458ee70bd2567a9d8350105aeaa6245448df22675780403e04348b`.
- Keep WSL running. Do not disable UAC or introduce persistent privilege changes.
  Import credentials only from `.lab/hyperv/win11/secrets/guest-credential.xml`;
  never print them.

## Current state: frozen alpha packaged

**The finite 814 native matrix and public-only local package are complete.**
Root packaging session `71622` actually exited 0. Root independently read back
all **11 ZIP entries**, checking lengths and SHA-256. No release was published;
no stable-release or broader-goal-completion claim is authorized.

Local package:
`D:\code\ntfs2refs\.lab\packages\frozen-814-public-f969ce0e6ea94179bda483015c41982a\ntfs2refs-814-public-experimental.zip`

- ZIP: 18,909,968 B; SHA-256
  `129a037136a1c68ac89418c7fdcdfecc8b7d269cc4fb5d89026efeb57e7c4a82`.
- Package manifest SHA-256:
  `6c2d227fdb64b7f5a42ce00a271da164eb92c47745570dc737b29143e5dc5a5e`.
- Independent archive-verification receipt SHA-256:
  `8cb5b295f3b19b77771d016b82c6a9f03d1e43a56985eff56bf974aaeab9ab66`.
- External qualification sidecar:
  `evidence/frozen-resource-alpha-814-qualification-20261104.json`, SHA-256
  `8ee66ddafda8a5c397a003ac900bced453f963f95dcf0dc53f197ea159011eb8`.
- README bytes (`README-814-frozen.md` and `.txt`) SHA-256:
  `84ca997e8d43915bdde9eea4f9a185f9aac171dd72013e7af9b49ce1e7e20a55`.

Only `ntfs2refs.exe` ships. It already contains recovery and cancellation.
The original three-tool build manifest/source archive remain provenance;
unshipped `lab-observe-resource-recovery` has **no execution/qualification claim**.
The embedded registry and executable bytes were not rebuilt for packaging.

**A separate compatibility attempt is staged after package closure:**
`58c5d87cfedd487b8bf3e4a3e39ae3b6`. Root restored saved partition branch
`766c9abc-8582-4de6-b497-8acbc81274da` **once** from the normally Off cancellation
branch. A fresh process verified Off/parent766, then Root started it once.
Guest boot `1793765146033`; no project processes were present. The pinned
three helper files are staged at `C:\ntfs2refs\fresh-partition-58c5d87cfedd487b8bf3e4a3e39ae3b6`.
No new native probe or conversion has launched. The old Off/parent3343 observation is no
longer current authority. Root admitted a separate 6,442,450,944 B forecast at
283,378,342,707 B used / 123,199,393,792 B free under the unchanged policy.
The completed a709 reserve/corruption/cancellation case is not live. Independently
inspect Root's latest dispatch/task, exact native PID/birth/terminal and fresh VM
graph before acting. Root alone coordinates VM power, restore, task dispatch and
snapshot removal while agents work in parallel.

## Exact frozen source and finite native evidence

Executable source remains `814f380aa38be4d94e2a71ad221c779e5ab4dc7b`, source tree
`268200368a49bbf6e4feeb78fa43df141551ac31`. Later documentation commits do not
change this binary or inherit its qualification into another build.

Build directory:
`.lab/development/release-candidates/resource-publication-cng-814f380`.

- Build manifest SHA-256:
  `ea6d55adaa40b1bf2bfd04cb7842bdef63b9cbffb0f038697d23ae9330af8f64`.
- Public executable SHA-256:
  `0f5be1c72b05ff030aad85b21be2c37f32ecccbf214af1ee4d6f7afd4807fafb`.
- Diagnostic SHA-256:
  `790de5dba9eaf3b17b58fb871e9733f73ee2531de7534c08037bd4e5071b092a`.
- Unshipped observer SHA-256:
  `e8a5bd07ad59bf54cd6a22c152b7ac8055ebfb7e37f594af010dda8f13823276`.
- Source ZIP SHA-256:
  `94b94b177293f069d98521ef99e4a9e788a6b9e1977d6ca835f4c718cbc0fcc9`.

`FiniteAlphaObservedProfile814` covers one nonboot dedicated GPT data volume:
52 GiB, 512-byte logical/4096-byte physical sectors, NTFS 64 KiB to ReFS 3.14
Dev Drive 4 KiB, Windows version **10.0.26300 / build 26300**. Current artifacts
do not establish UBR 9457; do not import that precision from historical install
records or confuse refs.sys version with the OS version. The fixture has 811
streams totaling 9,885,801,949 logical bytes and 2,558 user objects. Independent
checks matched 1,534 baseline objects and 1,024 extra directory paths.

The committed evidence is authoritative for each case's scope:

| Record | Completed observation |
|---|---|
| [public-resource-cng-20261103.json](evidence/public-resource-cng-20261103.json) | Public normal conversion; 513 new-file mutation hashes; normal reboot without restore; independent originals; actual ERROR32 with read-only exclusive journal lock; later non-replay online HND reconciliation. |
| [resource-814-first-flushed-write-20261103.json](evidence/resource-814-first-flushed-write-20261103.json) | Real 4,096-byte metadata write, flush/readback, authenticated AP and still-OLD primary; diagnostic exit 1 is intentional. |
| [resource-814-restart-rollback-20261103.json](evidence/resource-814-restart-rollback-20261103.json) | Separate public rollback after restart from the original AP; ABT/NTFS; independent contents and paths. |
| [resource-814-restart-resume-20261103.json](evidence/resource-814-restart-resume-20261103.json) | Public resume after independently restoring the same original AP; ReFS/HND; independent contents and paths. |
| [resource-814-early-guard-20261103.json](evidence/resource-814-early-guard-20261103.json) | a709 reserve refusal before J/AP; one invalid checksum-copy refusal; exact in-place control-state restoration; normal restart/cancellation; independent NTFS contents and paths. |

The early case's 92 closed metadata files / 6,089,600 B were length/SHA-verified;
manifest `a934bd7216340468020351d394345ae1b5d482596bdb96ec3028697fc656eadb`.
Its corrupt-copy refusal has **no measured source-write counter**. Successful
cancellation explicitly reports zero source payload writes and no journal replay.

Normal conversion took 913.2446592 s. Observer-close logical transfers were
164,909,910,658 B read / 3,256,217,717 B written; these are neither physical nor
exact final I/O. Publication reuse removed two consumed-shadow scans, exactly
12,353,544,192 raw bytes for this range set. Comparisons with prior runs are
uncontrolled observations. Retained allocation snapshots are not peak scratch,
and live working-set samples are not final peaks.

## Snapshot and recovery ownership

Keep required origins/ancestors unless a fresh retirement audit supersedes them:

| Checkpoint | Role |
|---|---|
| `3343f2a4-cf81-4fa9-a504-030425a8011e` | Original prepared lab source; current recorded parent. |
| `895f472a-4d33-47f2-86ec-bb8ead5f3911` | Verified 814 normal/mutation/reboot operational HND; parent 3343. Never replay its old raw journal. |
| `0cf3dd7d-9724-46d2-83da-6cbcbcca9fc2` | Original exact-814 interrupted AP origin; parent 3343. Restore this origin independently for a new authorized recovery direction. |
| `a0a8217f-894f-4311-bbf7-27151da5d216` | Verified 814 resumed operational HND; parent 0cf3. Never replay its old raw journal. |
| `766c9abc-8582-4de6-b497-8acbc81274da` | Closed partition-only experiment; parent fe668. Its C: shrink/T: creation facts belong only to that saved branch; never repeat its setup blindly. |
| `f4bf5238-14c0-4b15-bda6-7859abd4d1c9` | Guarded archive-mismatch checkpoint: never remove or force. |

Older a51 AP, b1de HND, 7d81 HND and fcfb HND were retired after archive checks;
do not recreate or restore their IDs. Historical observations and old source/
binary pins remain, but their discarded guest journal/shadow images cannot be
reconstructed from small evidence archives. Old "restore a51" instructions are
superseded. Never transfer an old binary's qualification to current code.

Fresh Apply needs its original opaque live source certificate and actual held
source/target/journal/arena owners. JSON, pathnames and bundles supply routes,
not new authority. Recovery must independently authenticate actual devices,
file identities, journal/index/ticket/lifecycle and all required recovery files.

Preserve full checked opening/closing boundaries, native/metadata/allocation/
namespace/ACL/retrieval checks, durable write ordering, flush/readback, persistent
exclusion and handoff. Any narrowing of checked evidence needs a separate user
decision. Do not reconstruct witnesses from saved flags or cache them across
operations. HND/ABT permanently close old raw replay; operational writable data
must not be compared with stale selected postimages. Use terminal reconciliation.
Never clear exclusion, rebind/reidentify devices, bypass sharing locks or force
mixed/unknown bytes to evade refusal. Fail closed on unresolved ownership.

## Remaining broader work

Do not add unneeded cases or code changes merely to repackage this frozen alpha.
Preserve it while pursuing focused, evidence-backed continuation:

- A data partition sharing the running Windows disk is unsupported by the
  current writer. The partition reader experiment grants no writer/isolation
  authority. GPT/runtime offline alone failed the raw-write interlock; keep the
  writer unavailable until actual lock/dismount ownership and post-reboot
  reacquisition are demonstrated. Do not retry the old ambiguous write probe.
- Useful larger geometries, feature combinations and exact Windows/storage
  profiles remain unqualified. Do not silently discard unsupported NTFS semantics.
- The managed-shadow VHDX provider has an approximately 64 TB native ceiling
  including staging overhead. No alternate scratch provider exists; 1,000 TB is
  unsupported. Packaging does not establish arbitrary scale or maximum NTFS
  compatibility. Continue reducing reads/storage only through concrete same-owner
  proofs, without weakening source/recovery invariants.
- Physical power loss, copied-user-payload interruption, active write/flush/
  readback errors, actual ENOSPC and missing/conflicting valid guard-copy
  combinations are not qualified by this finite matrix.

Allocation-bounded writes and extent-based fast verification are approved
defaults; full-content/whole-image options retain their checks. Retained bytes
are proved by exact metadata/physical-extent identity; moved/rewritten bytes are
checksummed during I/O. Missing digests remain absent. User logical-content
hashes use XXH3-128 despite legacy field names; artifact, metadata, residual-tail,
whole-image and journal pins use SHA-256. Destination bitmap windows do not
replace complete phase maps, file retrieval or final allocation checks.
Incremental retrieval remains deferred. Required zero writes must remain:
reserved-zone zero skipping was disproved.

## Fixed capacity, cleanup and builds

Original epoch: initial lab **279374052988 B**, initial host free **66133905408 B**,
maximum actual **329374052988 B**, minimum free **17179869184 B**, total additional
allowance **50000000000 B**. Never reset baselines or raise caps to hide usage.
Before growth, remeasure and admit a justified forecast under lab/Lab.psm1 and
lab/lab.config.json. Charge **ALL .lab**, `target/shared-experiments` and
`target/shared-experiments-staging`. Latest package-time census was
283,378,338,929 B / 123,197,050,880 B free; it is historical, not future admission.

User authorized obsolete-checkpoint cleanup. Use Hyper-V APIs, never manual
AVHDX chain deletion. Verify actual inactive graph, child order, current parent,
required dependencies and archived pins first; remeasure after merges. Never
remove guarded f4bf. Previously automatic-review-rejected research-image,
`.lab/ntfs2btrfs-source-audit` and three old development Cargo-cache deletions
must not be retried via another shell/method. Resolve absolute cleanup targets
and use native PowerShell literal-path operations; never delete guessed/live data.

VM: `2401593c-4b30-472e-9b6d-c9534cbaa599`,
`ntfs2refs-streaming-v2-20261027`, fixed 4 GiB / 4 CPUs / no NIC. After restores
and checkpoints, verify state/parent through a **fresh process**; stale Hyper-V
objects are not permission to repeat successful operations.

Use Rust **1.98.1** and pinned MSVC tools. Set TEMP/TMP to
`D:\code\ntfs2refs\target\tmp`. Reuse the user's ONE shared experiment build
at `D:\code\ntfs2refs\target\shared-experiments` and its exclusive sibling lock;
never modify old frozen targets. Use lab/Build-ReleaseCandidate.ps1 with exact
committed source, pinned tool/config/archive inputs, fresh output, offline/locked
release mode and `-UseSharedExperimentalTarget`. Verified shared-source staging
uses `-UseSharedExperimentalSource` and
`-ExpectedSharedSourceHelperSha256 842c5e7f7e65a1df72e6276af505e47f85f79b649429fe1eeac0833d1b534992`.
Record cache reuse; do not claim a clean/reproducible build or native qualification
from compilation. Default isolated release builds remain separate. Preserve the
builder's four-job default, lock and actual session identities.

Focused cargo check uses the same shared target/lock. Process-local incremental
builds may clear RUSTC_WRAPPER/RUSTC_WORKSPACE_WRAPPER to avoid incompatible
sccache; do not change host-wide settings. Format only owned Rust files with
`rustfmt --edition 2024 --config skip_children=true`; never workspace-format or
touch main. Documentation-only work needs no rebuild and no unit tests.
