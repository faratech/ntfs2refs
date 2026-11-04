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

Current committed/pushed source **aef1ab3b3a6ea08f7093d83cc60462f8b799b79a**
normalizes the actual capture-index writer before sealing. Its public-only release
at `.lab/development/release-candidates/capture-index-aef1ab3`
completed0 in2m30s. Manifest
f60eca76b95fcb48a0708f44cf256f284d336b0e224a0b8e47a60d40b2dea291;
public17198080B SHAdaa56b970b944efcc8cdb2987a2307231075961f5afb70c39e34f1add2b3026a.
Fresh public runfc268ad154474588b5d4cf5226387674 SUCCEEDED: actualPID5372/birth
1793796637023 exited0/664.2489071s at13:01:41.300UTC.
Gueststage `C:\ntfs2refs\resource-fixture-fc268ad154474588b5d4cf5226387674`;
actual engine `C:\ProgramData\ntfs2refs\runs\4a4b3a84a7e9419ba6f1c369dc319916`.
Native resource-completion/HND passed2558mapbindings,157knownhash streams119009B,
654extent streams; publicationSHAa8052b7a9f8b5dcc4abe454195871675ac40b6f560a3baea8938a578038455c7.
Thin retirement completed: exactVD/pool removed, original members9/10 and carrier8
detached, carrier backing deleted, recovery files retained. Before-retirement
allocation702545920B is a snapshot, not peak scratch or measured physical reclaim.
Root freshly observed F:ReFS/disk1onlineRW/eightdisks/boot1793796612940.
Independent CompareRefs observercc45dd15cd3f4adc8df5a5968dd41d00 passed
all811XXH3 streams9885801949B/1534baseline objects/1024extra paths and all13actual
digest terminals in11.2762712s. Closed56files106456B, everyhostcopylength/SHA:
manifestfe6ad97a1b432f6700e76fd5a331b1b76f9ceabe978424e3055451419828db0b,
resultbd2301db5da7d53a325ea71cc9b90dad6cc77d601a6859f6787e3f24f3ddfdd7.
Public terminal/locator/HND metadata closure passed:15files719910B, every source/
hostlength/SHA matched; manifestd44e28a5db6836aadfc156da7a0a02853844cfc83f0385205a8c61ecb7ff6c08.
Actual framedlocator-derived J identity/GUID/183716048B length and exact4KiB
canonicalN2RSHN01 passed; fullJ was not read/copied. See
evidence/public-thin-conversion-20261104.json. Normal shutdown/start WITHOUTrestore
completed; actual newboot1793797766048 returned F:ReFS/disk1onlineRW/eightdisks.
The exact retired pool/VD/carrier backing remained absent after boot. Postboot
CompareRefsbb0dc975a9ff416da80626e6aef30aa2 passed all811/9885801949B/1534/1024
and all13actualdigestterminal0 in10.7539403s. Closed56files106475B, everyhostlen/SHA:
manifest80410c52487a5be11d054b67ffbba3c0489456981e0b790e33ba76e0a5dccfc2,
resulte4cd98e67419bc25ccc93733554f815c703a2c29d57f40bd0b38ee99c78f112a.
Both observer sets are preserved underfc `closed-content-cc45` and `closed-content-bb0d`.
This qualifies normal reboot persistence for this case, not mutation/crash/physical
power or new AP/recovery. Root completed orderly shutdown and saved checkpoint
**8a5b96ff-5f13-4e18-ab6c-c8c02cd7e86f**, named
`ntfs2refs-aef1ab3-thin-converted-coldboot-20261104`, parent3343, created13:14:00UTC.
A fresh separate process at13:14:38UTC verified **VM Off/RAM0/actualparent8a**.
Receipt `verified-saved-checkpoint.json` underfc hostroot SHA
0a98accaf18de682c7f52c2a32493c99d284a487b28ad9c222ff74f6ee98e31c.
Precheckpoint purecensus317890172705B/free88635187200B admitted the unchanged
1GiB forecast under329374052988B maximum/17179869184B reserve; remeasure before growth.
Keep8a: it preserves the completed operationalHND; NEVER replay its old raw journal.
Next work is NEW exact-build interrupted resume/rollback qualification. Do not
repeat the unchanged normal conversion/coldboot checks. Root alone owns VM work.
Normal default remains
VHDX; no stable/general hardware qualification follows. The exact-patternb0b576a probe
did not reproduce the earlier guard refusal; its closed results are below.
The subsequent publicb566 runf9a192c850934463af838a44deb480fe ENDED with actual
PID5348/birth1793795529382/exit1/613.3199557s at12:42:22.729UTC. Gueststage
`C:\ntfs2refs\resource-fixture-f9a192c850934463af838a44deb480fe`.
Its actual engine is `C:\ProgramData\ntfs2refs\runs\096606d02283139f8caf4787a9600641`.
The error DIRECTLY identifies capture.index: EOF560896B, physical allocation
655360B, grant maximum560896B, reserved slack65535B. The reported allocation
exceeded the admitted bound626431B; automatic preparation cancellation restored
NTFS before publication. This identifies f9's failing artifact, unlike the earlier
unattributed8be error or non-reproducing probes. No full conversion/cleanup pass
is claimed. Root archive session70577 completed0:4198files215106439B, every host
ZIP entry length/SHA checked. F9hostroot contains `closed-evidence.zip` SHA
6ee0a24070af57fbaa9e9f10333110a94e0a0e91685df02e9054c1794e2079db,
manifestSHA3cf1ed6a003bbf90c31a91fe21bc8bb97a22c41c46cd7fe3f62d115d0edb1cdf.
See evidence/public-thin-capture-index-allocation-refusal-20261104.json.
Root separately observed F:NTFS64KiB, disk1online/read-write and all tasks idle.
After archive closure Root orderly shut down and restored3343 ONCE; a fresh
separate process verifiedOff/RAM0 before the new fc dispatch. The unchanged22GiB
launcher admitted and started that now-completed run. That pre-dispatch Off
observation is historical; the current fresh Off/8a observation is recorded above.
SDK graph retirement/getters/discovery, typed CLI staging wrapper, hidden forced
thin mode, remaining-provider-growth reservation, and geometry diagnostics compile.
The historical public check passed13.91s; no units ran. The aef normal thin
conversion/graph-cleanup/content/normal-coldboot case succeeded as scoped above;
new recovery remains pending. Normal default stays VHDX. Default VHDX location/retirement
JSON is unchanged. V4 replay remains source/J/envelope/maps self-contained.

Root release75476 actually completed0/2m20s. Build source44cca72, output
`.lab/development/release-candidates/public-thin-44cca72`, public17189888B SHA
6bbe8f94638086d24c7e8900c7579f24f86caeeca84b22a99cbdda46b722a380,
manifest6251f7c7216df7117c47470fa8b281e902cf7541613dffaf1805c055954e4762.

**PUBLIC THIN RUN8be515c3788d416b94d4991efddd5141 FAILED SAFELY BEFORE PUBLICATION.**
ActualPID5404/birth1793791444645 exited1/732.9981954s at11:36:17.748UTC;
process absent. Error `artifact physical allocation exceeds reserved slack`.
The preparation cancellation restored sourceNTFS automatically; source1 is now
online/read-write and F: returned. No J/publication/HND/cleanup was reached.
At failed-run closure VM was Running/4GiB/parent3343/boot1793791414487;
the archived active branch was subsequently discarded as recorded below.
Do not retry this old run.
Gueststage `C:\ntfs2refs\resource-fixture-8be515c3788d416b94d4991efddd5141`;
host `.lab/hyperv/streaming-v2-20261027/resource-fixture-8be515c3788d416b94d4991efddd5141`.
Actual argv is the seven-option thin qualification command described below.
SYSTEMworker e156ad5af5e0dd16e1ec656cdd892c405f69934ed312d5a910f597c1e0fa8af4,
configce08af4e637a253d6c5038c01cf7bdbab7465e40d66b58f605fdb756748d4450.
Launcher12723 completed0; native exit is1, not conversion completion.
Root closed19metadatafiles865455B; manifest
390b5aa659079e7d683250a6e09e97087be89ad0b1f5fafc26e9e6d319e9401b at
`closed-public-terminal`. IndependentNTFS observer9646d5eb347045ee894ed4803c3e7903
reported success: worker4752/birth1793792565158/SYSTEM, all811XXH3 streams9885801949B,
1534baseline objects/1024extra directories,13batches10.772807s. All13actual owned
terminals and the57-file archive are complete. All1024UTF16 paths and the full
paths structure matched frozen8f14; exact closure pins are below. This was
CaptureNtfs, not ReFS verification.
Its stage `C:\ntfs2refs\resource-recovery-observe-9646d5eb347045ee894ed4803c3e7903`.

Allocation fix is committed/pushed **b5663b87d6bd124d2c235a2684a2c60a166c6f21**.
Focused check passed22.03s; no units. Release86723 actually completed0/2m43s, output
`.lab/development/release-candidates/allocation-normalized-b5663b8`, selected
`ntfs2refs` and `lab-artifact-allocation`. Buildmanifest
a46365c34bcb3c385296ccdbdf25300a095eeee431347da568611120e5794b04.
Public SHAa26e29dd40aab859c41230a4007c291afba6b0ac85ba6ecd88580327bae708b4;
probeSHA21f12319fd220da7a7001c27090113f335191fdacd14fa993cd57a4d7fe88b2b.
The fix touches file_storage.rs, artifact_arena.rs, paged_capture.rs and a small
native artifact-growth probe (no units). Literal finalization used a duplicate
of the same FILE_OBJECT before sealing; this alone does not identify the artifact
that failed8be. ALL observed files were within slack after process exit.
The b566 change normalizes allocation at exact held-writer EOF before readonly duplication;
preserve EOF/FileID/content/full hash and the original unchanged slack check.
Do not merely increase slack. This does NOT prove a hard transient NTFS quota.
The original b566 probe writes two fresh100MiB+4KiB ordinary files in separate512MiB
arenas and requires baseline actual guard refusal, then normalization and SAME original
slack/hash/arena sealing while retaining the file object. CLI `--directory <fresh>
--acknowledge-new-disposable-staging`. Both focused probes are now closed without
deterministic baseline reproduction. Root selected a FRESH publicb566 run with
actual failing-artifact context rather than more speculative patches/probes.
Never reuse the failed8be artifacts as fresh conversion authority.
Focusednativeprobe **b969ca56204f4c129090a4499a1d6a70** DID run once:
actual5988/birth1793793655718/exit1/6.0920276s at12:01:01.822UTC. Stage
`C:\ntfs2refs\artifact-allocation-stage-b969ca56204f4c129090a4499a1d6a70`, output
`C:\ntfs2refs\artifact-allocation-b969ca56204f4c129090a4499a1d6a70`, host
`.lab/development/artifact-allocation-b969ca56204f4c129090a4499a1d6a70`.
**Baseline did NOT reproduce original guard** (arena_error=null); do not call
this overall pass. Normalized case DID trim104923136B allocation to104861696B EOF,
sameFileID/fullhash/originalarena+groupsealed. Mechanism evidence only, not proof
of original failing artifact. Original8be literalEOF86695936B and route/index
finalization patterns differ; original error had no path. The exact-pattern
follow-up below also did not reproduce it. Do not raise slack, relax the baseline
criterion, or treat either probe as proof of the original failing artifact.
Both probe file objects closed at actual exit, artifacts retained. SourceF remains
restoredNTFS; no corrected full conversion. Root owns builds/VM/Git.

Root closed the successful NTFS observer into57files250809B, every source/host
length/SHA and13actual owned digest terminals checked; manifest
e4450691e296efb7692ac7bd367cd942b4a47b26a1d3fd00c4e1fd251064a280,
result45bcbf4a7b306c749f05326cc1477dd5ce337213dceaf1673dab09fc6c42c56c.
All1024fresh UTF16 paths and full paths structure matched frozen8f14 namespace.
Archive `closed-independent-ntfs` under8be hostroot. At observer closure all N2R
jobs were terminal and sourceF was restoredNTFS; original NTFS prealignment moves
remained legitimate. This is logical preservation, not bit-identical physical layout.

LATEST EXACT-PATTERN RESULT:8be capture.index EOF564576 equals128-byte header
+7054*80-byte rows+128-byte footer exactly. The footer follows initial literal
sealing; it suggested an index investigation but did not identify the failure.
Nativeb0b576a probe9f6f3c888f85406aafd06fbde4c6f567 actual3604/birth1793795117389
exited1/7.4564207s at12:25:24.858UTC: NO baseline reproduction. LiteralEOF86695936
had86704128B allocation; indexEOF564576 had589824B. Both unmodified original seals
passed. Normalized literal/index seals and unnormalized production-route seals
also passed. Route content/lengths were not identical to the original run.
Do not call the overall probe a pass or infer an index/literal cause from it.
No index production patch followed that probe alone. The later f9 actual error
above supplies the direct capture-index evidence. Original allocation/slack
guards remain unchanged; aef normalizes this identified writer rather than raising slack.
Root archived4199files216627913B from the failed engine (excluding thin-provider
graph), both probe stages/results and original artifacts. Every host ZIP entry
length/SHA was independently checked. Archive
`.lab/development/exact-allocation-9f6f3c888f85406aafd06fbde4c6f567/closed-evidence.zip`
SHAe2163a0630c949eac2f89f64eda15a30c6c8f511522a3958d0aa982b6eecb9b0,
manifestSHA1a53a45698840da00082abcd9dd3daf47f7e2ecaec346c750f0462243ccd63a3.
Exact-probe buildmanifest1f64dad9e73e6c9912c1524052f20fef22045ded2e941ceb2724428bd232b744.
See evidence/exact-capture-allocation-probe-20261104.json. Preserve b969's earlier
non-reproduction. The earlier closed failed engine has no journal-layout.index;
its index attribution remained a hypothesis. The later publicb566 run above
reported the actual capture.index allocation failure. No corrected full
conversion is yet qualified; do not transfer8be's independent content proof to f9.
After archive closure Root orderly shut down and restored3343 ONCE; a fresh
separate process verifiedOff/RAM0 before the new dispatch. Discarding the archived
disposable active branch reclaimed about10GB. Frozen origins and saved4b8 remain.
Complete census305248164376B/free101261185024B admitted the unchanged22GiB forecast
23622320128B under329374052988B. No epoch/cap/runtime-limit change. New no-restore
launcherSHAea5702c3c91496cc964a01a0e25add42fb82543a99a880cfe313ce088199708c.
Root owns the fresh dispatch/run identity and all VM/Git actions; no pass inferred.

Before that run VM2401593c-4b30-472e-9b6d-c9534cbaa599 was saved
**Off/RAM0/parent4b8dafbf-7500-4c51-ab12-d0a697bf7264**, freshly verified.
This completed prototype checkpoint remains saved with parent3343 and
preserves72TiB success, both earlier failures and1PB strict geometry refusal.
Receipt `.lab/development/saved-large-format-prototypes-20261104.json` SHA
06f668fe8855cf7220d65b6677005c9baaa10cdd02bba7b62c9a3898810f5e4e.
All prototype jobs were terminal before that normal shutdown. Current state is
the separately verified savedOff/8a above; this older4b8 observation is historical.

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
a0a8217f, guardedf4bf5238 (NEVER remove/force), convertedc60 and newest thin-HND8a5b96ff,
prototypes4b8,
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
