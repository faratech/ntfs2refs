# ntfs2refs: active handoff

@C:\Users\mfara\.codex\RTK.md

Work in **D:\code\ntfs2refs**, branch `codex/resource-based-admission`, private `faratech/ntfs2refs`. The C: workspace is stale.
This current record supersedes historical LIVE/keep/next-action claims. Prior guidance is preserved byte-exact in
[history](docs/history/AGENTS-through-20261104-aef-default.md), 22415 bytes, SHA256
`fdb24262f0c3fea3219f3c8714f0063b911a021b8af30d7b39068ba415264bd9`.

## Objective and authority

- Finish efficient in-place NTFS→ReFS, bounded preparation/recovery, useful hardware/NTFS coverage, and exact-build release qualification. The broader goal is incomplete.
- Conversion and recovery run inside the Windows machine owning the source disk. Hyper-V is lab infrastructure. Preserve the native-shadow alpha; boot and independent-writer/GPL work are deferred.
- Keep the public product frozen while finishing its finite alpha matrix. Avoid speculative changes, repeated unchanged checks and repeated full-payload scans.
- User forbids **new and existing unit tests / cargo test** unless explicitly requested. Necessary focused builds and native integration cases are allowed.
- **NEVER edit, format, reset or clean `src/main.rs`**. SHA256 `c6bc5c52c8458ee70bd2567a9d8350105aeaa6245448df22675780403e04348b`.
- **Exclusive VM/power/native-run/archive owner: `/root/aef_postcut_operator`.** Root owns Git/build/docs only; other agents prepare assigned files/read-only plans. Do not compete with that owner.
- Commit exact stable owned paths and push normally; no force-push or `git add .`. Keep .lab/images/journals/binaries/ISOs/secrets out of Git.
- Keep WSL running. No UAC disabling or persistent privilege changes. Import credentials only from `.lab/hyperv/win11/secrets/guest-credential.xml`; never print them.

## Fixed public candidate and completed finite cases

Unchanged product source **aef1ab3b3a6ea08f7093d83cc60462f8b799b79a**, tree `af8979f921bc9c7a57324addac40c8ec8bd0d968`.
Build `.lab/development/release-candidates/capture-index-aef1ab3`, manifest SHA256
`f60eca76b95fcb48a0708f44cf256f284d336b0e224a0b8e47a60d40b2dea291`.
Public executable 17198080 bytes, SHA256 `daa56b970b944efcc8cdb2987a2307231075961f5afb70c39e34f1add2b3026a`.
Source ZIP 1883473 bytes, SHA256 `0be3d4c3feb81878a29cfc4e04bce5e0e0717bc41f462bf2922c1bdce157dd21`.
Cargo/CLI version is **0.1.0**; do not invent a different binary version for the package.
The only aef product fix normalized the held capture-index allocation at EOF before sealing; original slack and identity checks remain.

Observed profile: dedicated nonboot basic GPT disk1, 52GiB partition2 at16777216; NTFS64KiB→ReFS3.14 DevDrive4KiB, 512logical/4096physical sectors.
Original independent oracle:811 streams/9885801949 logical bytes/1534 baseline objects/1024 additional UTF16 directory paths.

| Exact-aef case | Actual result | Evidence |
|---|---|---|
| Thin normal fc268ad154474588b5d4cf5226387674 | exit0/664.2489071s, cleanup, oracle before/after normal reboot | evidence/public-thin-conversion-20261104.json |
| Controlled actual cut f9c1b2f236d442318afcec1df0cd24a8 | one TurnOff15:17:20UTC; new AP39ba; postboot persistent exclusion and independent J authentication | evidence/public-thin-post-cut-rollback-20261104.json |
| Public rollback b7b582216b814f21a71d7d905982a765 | exit0/77.0033413s, original811/1534/1024 all matched, ABT+RB closes replay | same rollback evidence |
| Public resume b0aaf7b193624306b8e81e8c7bf59d10 | exit0/207.7208384s, original oracle all matched, HND+AP closes replay | evidence/public-thin-post-cut-resume-20261104.json |
| Mutation/reboot/terminal gates | 513 new/mutated files persisted; original oracle matched; HND reconcile exit0 without raw replay; exclusive-J open refused actual OSerror32/exit1 with unchanged J and contents | evidence/public-thin-operational-gates-20261104.json |
| Default VHDX normal 3c0b27586cb94f8ea556c1ad6283d7b6 | exit0/843.0596228s, HND/finalization, own VHDX detached/deleted, independent original oracle all matched | evidence/public-default-vhdx-conversion-20261104.json |

Default argv: `--drive F --partition 2 --minimize-scratch`; thin additionally used
`--experimental-thin-shadow --experimental-thin-backing-bytes 11811160064`.
Default J af550200000003000000000000000000/186969896 bytes is closed HND. Do not replay it.
Interrupted original J c9550200000003000000000000000000/186487480 bytes is closed ABT or HND on its recovered branches.
Original interrupted recovery directory was `C:\ProgramData\ntfs2refs\runs\fab216c1961efb6b3881f26e3be7ff00\conversion`, printed SHA
`ac849240114b1ba688ad9de8edbb9c9d5298fc28fafc8cc07d92ade59e26b5ab`; it is an AP recovery origin ONLY after restoring the exact saved39ba branch.
Controlled thread pause/TurnOff is not physical power loss, first-flushed-write or arbitrary write/flush-error qualification.

## Current next work: low-space case and packaging

Eight of nine exact-aef finite gates pass. Public low-space refusal is pending; do not inherit older814 gates.
`lab/Package-ExperimentalAef.ps1` is reviewed and unexecuted. It requires exact public/source/build pins and all9 actual gates.
Ignored `.lab/development/qualification-aef-DRAFT.json` remains draft=true/native_matrix_complete=false until the actual low-space evidence passes.
README is `userdocs/experimental-aef-candidate.md`; the package is experimental and finite-profile, not a stable/general release.
Packaging only creates a local public-only ZIP; no tag/publication is implied. Packager accepts either recorded manifest alias but rejects conflicts.

A **64MiB EOF0 pilot passed** on current508e without F:/converter access:
run bffce4ae9b2846729be7787965c43dc3; child2744/birth1793813350676, exit0/31.3555384s at17:29:42UTC.
Allocation0→67108864, EOF0; C free debit67121152 and release67104768 after original-handle close/file deletion.
Host OSleaf length/allocation608174080 before+held,641728512 after (+32MiB); census316947846978/316947850370/316981407710.
These timed samples include background I/O and establish neither zero I/O nor linear host growth.
Pilot helper `.lab/development/Invoke-Eof0AllocationPilot64MiB.ps1`, SHA5982d17d4921b2a14bd66938f8683b23c1972ab6df1eb598cf21cffc565aa7a0.
Pilot evidence is closed in `evidence/eof0-64m-allocation-pilot-20261104.json`. Fresh separate-process verification confirms Off/RAM0/all16/current508e; no restore or checkpoint changes. Final census317024397793/free89517182976; total boot-to-close growth915422059 bytes, distinct from the phase samples.

Root explicitly authorized ONE actual low-space case for the exclusive operator: real caller-available C target3.75GiB (<actual public4GiB gate),
ordinary EOF0 reservation with <=1GiB increments and host ACKs; stop host growth at4GiB, conservative6GiB total forecast, original fixed cap unchanged.
At least3GiB OS headroom, no quota/free-API mocks/payload writes/persistent settings; exact candidate, fresh original3343 NTFS source;
require actual public expected refusal before new run/staging, then close/delete reservation and verify release. Guest helper SHA c0f6d15f4400b903401deada8d3522e11f4c3bcc539ecb3e19e215987981c945 and host runner SHA29bc601cd21ea5d4901a90f925a06bcf1496d4605baf07cf2ff9a46bd590356b were reviewed; GO issued. No result is inferred yet. Stop on concrete failure; no automatic retries.
The existing normal launcher >4GiB precondition must not be silently weakened.

## Recovery and verification invariants

- Fresh writes require original live opaque source certificate and actual source/target/J/arena owners. Saved JSON/paths/flags are routes, never authority.
- Revalidate device/file identities, journal/index/ticket/lifecycle and recovery files. Recovery must not require thin-pool reattachment.
- Preserve full phase snapshots and native metadata/allocation/namespace/ACL/full retrieval checks, opening/closing boundaries and final allocation checks.
- Keep durable intent/write/flush/readback, persistent exclusion and handoff. No fake witnesses/signals, sharing bypass, identity changes or forced mixed bytes.
- A process lock does not survive death. Partial images remain excluded until authenticated recovery. HND/ABT permanently close old raw replay.
- Operational ReFS must never be compared/replayed against stale pre-handoff images; use terminal reconciliation preserving current contents.
- Watch failure/late HND stops only the watch, letting conversion finish. Owned-thread pause has a watchdog but whole watcher death can leave threads paused.
- Thin teardown only after live V4 success: own VD→pool→original members→carrier→same-file backing deletion. Errors/default Drop preserve remaining assets.
- Approved defaults: destination bitmap windows and extent-based fast verification. Retained payload uses exact identity/mapping; moved/rewritten bytes hash during I/O.
- Logical stream hashes are XXH3-128; metadata/J/artifact pins SHA256. Full-content option remains. Missing hashes stay absent; required zero writes remain.

## Fixed resource policy and cleanup

Original epoch: initial actual279374052988 / initial host free66133905408 bytes. Maximum actual329374052988; minimum host free17179869184;
maximum added50000000000 bytes. Never reset baselines, raise caps or lower forecasts merely to fit. Charge ALL .lab and shared target/staging.
Measure before growth. Census samples are not peak/hard quotas. Four known allocation-test aliases may be charged65536 each; never follow unknown reparse routes.
Pure census may AST-extract ONLY Need/Add/Ordinary/MeasureTree/Capacity from `lab/Package-FrozenResourceAlpha814.ps1`
SHA5913711f3dd95ea10d60534402d8fb39038e946b150db74b6353b503aec93e22; do not dot-source the whole packager.
User authorized obsolete snapshot cleanup through Hyper-V APIs only; no manual AVHDX deletion/force. Further retirement requires fresh graph/archive audit.
Previously automatic-review-rejected research-image, .lab/ntfs2btrfs-source-audit and THREE development Cargo-cache deletes must NOT be retried/bypassed.

## VM and protected checkpoints

VM2401593c-4b30-472e-9b6d-c9534cbaa599 / ntfs2refs-streaming-v2-20261027: fixed4GiB/4CPU/noNIC.
Operator exclusively owns it. Query fresh separate process after power/checkpoint/restore. Stale objects never justify repeating successful operations.
Actual owned PID/birth/exit determines completion, not timeout/task state. Preserve all16 keepers/dependencies:

- 508e5c78-289b-4ad3-9c47-286fb03ddb01: default HND, parent3343.
- 9f0372c8-4aa9-4fd7-94d3-2f8356619e21: mutated/rebooted recovered HND, parent266.
- 266130c1-51c8-479c-b528-423644770dc2: resumed HND, parent39ba.
- ea75dff5-36f4-42af-8e13-cc9b2e8cba6c: rollback ABT, parent39ba.
- 39ba49c9-01d1-48fa-941f-08d34ff346c1: actual interrupted AP, parent3343.
- 3343f2a4-cf81-4fa9-a504-030425a8011e: prepared NTFS.
- Frozen814:895f472a-4d33-47f2-86ec-bb8ead5f3911,0cf3dd7d-9724-46d2-83da-6cbcbcca9fc2,a0a8217f-894f-4311-bbf7-27151da5d216.
- f4bf5238-14c0-4b15-bda6-7859abd4d1c9: guarded NEVER remove/force.
- Existing partition fixture/parent:766c9abc-8582-4de6-b497-8acbc81274da,fe668886-647a-4928-9c14-9fd9e323aefb.
- Ancestors:d8db8fd9-284a-4e78-86b5-85d8a2607663,001f7611-257f-4c5a-8c5b-560ce8faa68d,a0627dbd-aa3b-4896-bbeb-495f5e372057,83290a28-1e83-4eb2-a4d3-b0e9f5a8d63b.

Retired c60b51c2/8a5b96ff/4b8 and earlier a2259702/a51/b1de/7d81/fcfb/a724/ee42 must not be restored/recreated from stale claims.
Only8a+4b8 were most recently retired after278pin/dependency audit; receipt SHA9b4f159cb0c0be787d7204c758c1088f06dd3455486676d707bb2c2ef7b4b2a8.
Their raw guest payloads were not replicated; metadata/build/source proofs remain. Future large prototypes need fresh owned construction.
Frozen814 ZIP remains `.lab/packages/frozen-814-public-f969ce0e6ea94179bda483015c41982a/ntfs2refs-814-public-experimental.zip`,
SHA129a037136a1c68ac89418c7fdcdfecc8b7d269cc4fb5d89026efeb57e7c4a82; finite old-build evidence only.

## Broader work remains after finite package

- Shared running-Windows-disk data partitions are unsupported. Existing physical-disk write failed21; read-only isolation is not writer authority.
- Isolated Rust held-volume marker probe is built but UNEXECUTED: `.lab/development/partition-held-volume-probe/bin/partition-held-volume-probe.exe`,
491520 bytes/SHA0f2eee9155531d7267afc41d30316a36177a65b10bf6cc9c972e6a9e94f958de. Evidence: evidence/partition-held-volume-probe-build-20261104.json.
Fixed existing766 fixture only, one8192B same-bytes write through retained locking volume handle before runtime offline. No conversion/recovery/exclusion certificate.
- 72TiB private ReFS formatting/64KiB-file proof was not conversion/high-offset proof. 1PB formatting left unknown13008896-byte tail;
thread actual filesystem length through bitmap/placement/capture/retention and relocate out-of-range payload before nonzero-tail support.
- Source2MiB geometry exists but conversion unqualified; 4Kn,1024-byte MFT,4096-byte index limits stay explicit. Refuse unknown NTFS semantics.
- Actual copied-payload interruption, ENOSPC/write-flush errors, physical power and broader hardware remain unqualified; do not claim stable/general completion.

## Build and shell discipline

Rust1.98.1/pinned MSVC; TEMP/TMP `D:\code\ntfs2refs\target\tmp`; four jobs.
Reuse ONE target `D:\code\ntfs2refs\target\shared-experiments`, FileShare.None sibling `shared-experiments.build.lock`, shared source staging.
Use `lab/Build-ReleaseCandidate.ps1` with exact committed/pinned inputs, offline/locked release, shared experimental target/source flags and helper SHA
842c5e7f7e65a1df72e6276af505e47f85f79b649429fe1eeac0833d1b534992. No unit tests. Documentation changes need no rebuild.
Root process-local direct-rustc config `.lab/development/direct-rustc-check-config.toml` clears both wrappers; also clear inherited wrapper env locally.
Rustfmt only owned files with `--edition 2024 --config skip_children=true`, never workspace/main. Record cache reuse, never infer reproducibility from compilation.
PowerShell: do not repurpose Host/HOME/PID. Preserve DateTime.Kind (PS7 JSON may auto-parse); parse UInt64 serials from exact decimal strings/raw tokens,
not PS5 JSON Double. Canonicalize GUIDs by casting. Use -g for rg globs; filesystem deletes/moves need resolved workspace bounds and one shell end-to-end.
