# ntfs2refs: current handoff

@C:\Users\mfara\.codex\RTK.md

Work in **D:\code\ntfs2refs**, branch `codex/resource-based-admission`, private
origin `faratech/ntfs2refs`. The C: environment workspace is stale. Read RTK.
`CLAUDE.md` points here. The preceding handoff was preserved byte-for-byte in
[history](docs/history/AGENTS-through-20261104-before-public-thin-44cca72.md).
Old LIVE labels and retired checkpoint instructions there are historical.

## Objective and operative constraints

- Finish efficient in-place NTFS-to-ReFS conversion, resource-bounded preparation,
  actual public conversion/recovery, useful hardware/NTFS coverage and exact-build
  release qualification. The finite alpha does NOT complete this broader goal.
- Conversion/recovery execute inside the machine owning the disk. Hyper-V is lab
  infrastructure. Preserve the frozen native-shadow alpha; boot remains deferred.
  Independent-writer research is off the critical path; no GPL engines in product.
- User directed **no new or existing unit tests** unless explicitly asked.
  Necessary focused builds/native integration are allowed. Avoid speculative
  changes or repeating unchanged checks. Minimize reads, actual scratch and RAM.
- **Never edit, format, reset or clean src/main.rs.** Its approved SHA256 remains
  c6bc5c52c8458ee70bd2567a9d8350105aeaa6245448df22675780403e04348b.
- Commit stable exact owned paths and push normally; never force-push or stage
  everything. Keep .lab, images, journals, binaries, ISOs and secrets out of Git.
- Root alone owns VM/power/build/Git. Agents can edit assigned files/prepare
  ignored helpers; they must not execute VM operations without Root assignment.
- Keep WSL running. No UAC disabling or persistent privilege changes. Import
  credentials only from `.lab/hyperv/win11/secrets/guest-credential.xml`; never print.

## Current authoritative state and immediate action

Current committed HEAD **44cca72e4118b5f475de4b8cffc1a5d2eaf435c7** is pushed.
SDK graph retirement/getters/discovery, typed CLI staging wrapper, hidden forced
thin mode, remaining-provider-growth reservation, and geometry diagnostics compile.
The final public check passed13.91s; no units ran. Public thin/native graph cleanup
are NOT yet qualified. Normal default stays VHDX. Default VHDX location/retirement
JSON is unchanged. V4 replay remains source/J/envelope/maps self-contained.

Root release75476 actually completed0/2m20s. Build source44cca72, output
`.lab/development/release-candidates/public-thin-44cca72`, public17189888B SHA
6bbe8f94638086d24c7e8900c7579f24f86caeeca84b22a99cbdda46b722a380,
manifest6251f7c7216df7117c47470fa8b281e902cf7541613dffaf1805c055954e4762.

**LIVE PUBLIC THIN RUN8be515c3788d416b94d4991efddd5141** dispatched exactly once.
ActualPID5404/birth1793791444645 was confirmed live; boot1793791414487. VM is
Running/4GiB/parent3343 after one restore/start. Do NOT retry/kill/restore/power
while it runs. Gueststage `C:\ntfs2refs\resource-fixture-8be515c3788d416b94d4991efddd5141`;
host `.lab/hyperv/streaming-v2-20261027/resource-fixture-8be515c3788d416b94d4991efddd5141`.
Actual argv is the seven-option thin qualification command described below.
SYSTEMworker e156ad5af5e0dd16e1ec656cdd892c405f69934ed312d5a910f597c1e0fa8af4,
configce08af4e637a253d6c5038c01cf7bdbab7465e40d66b58f605fdb756748d4450.
Launcher12723 completed0; this is NOT native conversion completion. Observe
native-process/terminal PID+birth and actual finalization/cleanup separately.

Before that run VM2401593c-4b30-472e-9b6d-c9534cbaa599 was saved
**Off/RAM0/parent4b8dafbf-7500-4c51-ab12-d0a697bf7264**, freshly verified.
This completed prototype checkpoint remains saved with parent3343 and
preserves72TiB success, both earlier failures and1PB strict geometry refusal.
Receipt `.lab/development/saved-large-format-prototypes-20261104.json` SHA
06f668fe8855cf7220d65b6677005c9baaa10cdd02bba7b62c9a3898810f5e4e.
All prototype jobs were terminal before that normal shutdown. Current live state
is the public thin run above, overriding this historical Off observation.

The executed launcher was
`.lab/development/launch-public-thin-measured22-k.ps1` SHA
600f0e8926d2bf74fd3b7c4391daa3a48a9fbcf53e938603c3998c7aa8ae66c3.
It is the prior reviewed public launcher with only a22GiB forecast and actual argv
`--drive F --partition 2 --minimize-scratch --experimental-thin-shadow
--experimental-thin-backing-bytes 11811160064` (11GiB provider ceiling).
It restores3343 once, starts once and dispatches one SYSTEM-owned public process.
This is the original independently populated52GiB/9.9GB source, no source fixture
prearrangement. Pinned request `.lab/development/fixture-diagnostic-request-3343.json`
SHA27f96da22c6a67ba164ecf25cf828328c1b4741b2c5e5516b9d164767a52476d.
Do not touch source until live native admission succeeds. Inspect actual process
PID/birth/terminal; never infer success from a task state or observation timeout.

Forecast basis: prior same-fixture conversion+reboot charged11153050031B.
Replace775946240B observed shadow allocation with full11811160064B provider budget:
22188263855B.22GiB=23622320128B leaves1434056273B forecast headroom. This is
not a hard quota. Carrier/host/nominal pool reserves remain enforced; no cap reset.

## Frozen and verified conversion evidence

Frozen alpha source814f380aa38be4d94e2a71ad221c779e5ab4dc7b, public SHA
0f5be1c72b05ff030aad85b21be2c37f32ecccbf214af1ee4d6f7afd4807fafb.
Public-only local ZIP:
`D:\code\ntfs2refs\.lab\packages\frozen-814-public-f969ce0e6ea94179bda483015c41982a\ntfs2refs-814-public-experimental.zip`
SHA129a037136a1c68ac89418c7fdcdfecc8b7d269cc4fb5d89026efeb57e7c4a82.
All11entries independently checked. Finite normal/mutation/coldboot/interrupted
first-flushed-write/resume/rollback/early-cancel/refusal/HND cases passed on that
EXACT source/binary only. See docs/frozen-resource-alpha-20261104.md and its
package/qualification evidence. No stable release or general hardware claim.

Latest qualified public VHDX candidate b7d97fb ran778e45f2bc4b4291b9d3cb4c9cfebc05,
actual5348/birth1793779061600/exit0/753.764701s. HND/native finalization and automatic
same-file shadow detach/delete passed; J/locator remained with exact HND marker.
All811XXH3 streams9885801949B/1534baseline objects/1024extra directories matched
before AND after normal restart without restore. Saved completed HND is
c60b51c2-9e2a-4d57-8cc7-8a034d1802b8. NEVER replay its old raw journal.
See evidence/public-owned-shadow-retirement-20261104.json. New thin, mutation,
AP recovery, physical-power and arbitrary geometry qualification are not inherited.

CEC/a225 optimizations and independent native/source-free bitmap audit remain
archived in their evidence files. Metadata feature-index optimization614341b
skips absent EA/reparse reloads in authenticated immutable input using same-sized
prepaid index flags. All initial/native/final/retrieval checks remain. Compilation
passed; native speed/conversion improvement is NOT measured or qualified yet.

## Large-storage prototypes and limitations

- Native raw1PB constructor9606f22 passed. A later bounded72TiB formatter614341b
  passed actual1728/birth1793787801943/exit0/29.3395837s on boot1793784849960.
  New ReFS3.14/4KiB/DevDrive native15, volume65e52231-b1f7-41c6-9c49-1532db781de7,
  partition79164837199872B. Flushed64KiB ordinary file/readback/EOF/FileID/XXH3
  passed. This is formatting/file I/O, NOT a conversion or high-offset proof.
- The bounded NTFS carrier has virtual max12717129728B inside12GiB admission.
  Nested large nominal VHDX members stay inside it. Host accounting counts carrier
  backing plus outer metadata ONCE, not nested members again. Native pool allocated/
  footprint values are NOMINAL address space, not actual host backing or data
  capacity.72TiB carrier sample580MiB before probe and612MiB after probe; neither
  is peak. Actual FileID/volumeSN/bounds were independently checked at closure.
 33files170168B manifest87a37bf48210b092d4f1d6555e08c1bf5edb47263f11f3c76d5b24aca7e32956.
- v2 overcommit uses2nominal members<=64TiB each, larger logical Thin VD requests
  remain subject to native capability and actual carrier/host/pool resource gates.
  Fixed old create_new stays separate. Source must never be supplied as a carrier.
- Native1PB case273b0f0f43f7476d9dd8bbce25264a2f (9e491d1) actual2724/birth
 1793788961608/exit1/370.2866981s: Windows format returned0 and created ReFS3.14/4K,
  but strict SDK full-partition profile refused before issuing formatted owner.
  GPT P=1000000000000000B, native FS F=999999986991104B; tail13008896B is UNKNOWN,
  not free. Observed64MiB rounding is not a universal contract. No file probe or
  conversion/recovery qualification.31files90881B closure manifest
 03921b758ed2933df9fa6f79e55b388b323ac79dfb65417c3b2a689fe1777e64.
  Native carrier sample6144655360B; nominal pool allocation~5.2TB is not host usage.
- Strict format acceptance stays unchanged. New refs_extent diagnostic runs only
  on rejection and compares held route/FSCTL/VBR, records P/F/tail, gives explicit
  refusal. Bitmap/placement/capture/retention must separately thread F and relocate
  source runs outside F before ANY nonzero-tail conversion can be supported.
- First72TiB trial37faa failed Windows status112 with tiny nominal5GiB members;
  subsequent03a6 carrier NTFS succeeded but DOS canonicalization failed3 on its
  unmapped GUID directory. Both failures and assets remain in4b8; never retry them.
  GUID-only private sampler fixed this; generic ordinary-root validation unchanged.
- Self-contained V4 AP/HND replay MUST NOT acquire a pool reattachment prerequisite.
  Thin cleanup is explicit only after live V4 success: frozen own VD→own pool→
  original members→carrier, then exact same-file carrier deletion. Default Drop,
  errors and partial cleanup preserve remaining assets. No source/J/evidence deletion.

See evidence/private-thin-native-format-20261104.json,
evidence/private-thin-petabyte-profile-refusal-20261104.json and
 docs/private-thin-pool-addressability.md for exact profile/metadata pins.

## Remaining hardware and safety contracts

Data partitions sharing Windows' disk remain unsupported. Existing766c9abc-
8582-4de6-b497-8acbc81274da branch contains the C shrink/T creation; do not recreate
blindly. Physical WriteFile under tested lock/offline protocol failed21. No writer
permission follows from the read-only partition reader. Source2MiB cluster gate
exists but native conversion remains unqualified;4Kn/source1024-byte MFT/4096-byte
index profile limits remain explicit. Unknown NTFS semantics must be refused.

Preserve full phase snapshots, native metadata/allocation/namespace/ACL/retrieval,
full opening/closing checks, durable intent/write/flush/readback, persistent
exclusion and HND. Location JSON and observations never grant source/write/replay
permission. Do not manufacture witnesses, bypass sharing errors, change device
identity or force unknown/mixed bytes. HND/ABT close old raw replay permanently.
Operational ReFS must never be compared/replayed against stale pre-handoff images.

Extent fast verification and destination bitmap windows were explicitly approved.
Retained payload uses exact metadata/physical mapping; moved/rewritten bytes are
checksummed during I/O. Full-content option remains. Logical stream hashes use
XXH3-128 despite old names; metadata/journal/artifact/tail pins useSHA256. Missing
hashes stay missing. Required zero writes remain; blanket reserved-zero skipping
was disproved. Incremental retrieval and independent writer remain deferred.

## Capacity, snapshots, builds

Original epoch: initial279374052988B, max329374052988B, minimum host free17179869184B,
additional50000000000B. Never reset/raise/lower forecasts merely to fit. Charge ALL
.lab plus target/shared-experiments and shared-experiments-staging. Census before
prototype checkpoint304919822517B/free101592760320B is historical; remeasure.
Pure packager AST-extracted census supports exactly four known allocation-test
aliases at65536B each; never follow unknown reparse routes.

Keep required origins/ancestors:3343 preparedNTFS, frozen814895f472a/0cf3dd7d/
a0a8217f, guardedf4bf5238 (NEVER remove/force), latestconvertedc60, prototypes4b8,
partition766c9abc+fe668 parent and original ancestors. a2259702, oldera51/b1de/
7d81/fcfb and supersededa724/ee42 were retired after archive checks; never restore.
Latest2-node retirement audited318pins; receipt76b12c97b434f066aedaacc2950843b395efcabb439a12391ef63c504d28ab65.
Use Hyper-V APIs only, no manual AVHDX deletion. Freshly verify actual inactive
chain/dependencies/archive before removing more. Previously automatic-review-
rejected research-image, .lab/ntfs2btrfs-source-audit and three development
Cargo-cache deletions must NOT be retried by another shell/method.

VM2401593c-4b30-472e-9b6d-c9534cbaa599 fixed4GiB/4CPU/noNIC. After checkpoint/
restore, verify state/parent through a fresh separate process; stale objects are
never permission to repeat a successful operation. Timeout is not terminal.

Use Rust1.98.1/pinned MSVC, TEMP/TMP D:\code\ntfs2refs\target\tmp, four jobs.
Reuse ONE target D:\code\ntfs2refs\target\shared-experiments and exclusive sibling
shared-experiments.build.lock plus shared source staging. Build exact committed
archive through lab/Build-ReleaseCandidate.ps1, offline/locked, shared switches,
ExpectedSharedSourceHelperSha256842c5e7f7e65a1df72e6276af505e47f85f79b649429fe1eeac0833d1b534992.
Record reuse, never claim clean/reproducible build or native qualification from
compilation. Process-local direct rustc config can avoid incompatible sccache;
no global settings. Rustfmt owned files only with edition2024/skip_children=true;
never workspace-format or touch main. Documentation needs no rebuild/unit tests.
