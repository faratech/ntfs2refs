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

**LATEST CEC RUN IS COMPLETE, overriding older state below:**
Public cec225215f6487ddc9eaeb6564f358f5e20b9823 run
e7cd48e25fdf4552ae726e00de3ac454, actualPID5340/birth1793774388609
exited0/757.8637882s at06:52:26.532UTC; originalboot1793774364006. Root launcher67141
completed0 after one intentional baseline restore/start. Exact publicbinary
3600c145ed48ca8e997aed8b2ce6e7a92f02178bf274aa0a5d2f3b217fa16f0a,
argv `--drive F --partition 2 --minimize-scratch`. Gueststage
`C:\ntfs2refs\resource-fixture-e7cd48e25fdf4552ae726e00de3ac454`; actualengine
`C:\ProgramData\ntfs2refs\runs\59d38def8a5d06402476a7e983f7c8bd`.
Hostroot `.lab/hyperv/streaming-v2-20261027/resource-fixture-e7cd48e25fdf4552ae726e00de3ac454`;
SYSTEMtaskN2R-ResourceFixture-e7cd48e25fdf4552ae726e00de3ac454,
workerSHAea822d7308da90a5d2cf46ed89b1d57dc8d441238215d276afcf9130022dce2c,
configSHA88e278856338094455e54ad37263671e8e2104eddf67b65d112b4b39a2f2bb91.
Native conversion/HND and independent preboot811streams/1534baseline/1024extra
paths passed; all13actual owned digest terminals checked. Normal shutdown/start
WITHOUTrestore toboot1793775819488 then repeated all811/1534/1024 successfully.
Postboot observerfec3fdb4a9b74f5d8b7b815e05cc0a2e worker1980/birth1793775874667
matched13actualdigestexit0/11.5551665s. Closed56files106457B manifest
cae701ffc3d286fa9e3fbdceb1c98d8ad0cb362dab7cf415362f07415f2d2c88.
Offline audit of ALL6206capture records against the ORIGINALnativeNTFSbitmap
passed0violations:615source-free rows1868578816B; OLD-zero4413rows97460224B
remain separate/unqualified for content. AuditSHA
f56c3dcf3dcc81c89ffbf0ac309be34b5258c543ce9ba7952c0d5c4e437ec093.

Root normally shut down after all closures, saved one completed postboot HND
checkpoint **ee42e97e-c415-4ac3-bb1b-24ad060e96d9**, parent3343. A FRESH process
verified **Off/RAM0/parentee42**; no workers remain. Receipt
`saved-normal-coldboot-hnd.json` SHA64e9f67222c03e23ffc57a462d6d33931fc7caa38786e3b9fc263597fd86bd25.
NEVER replay the old raw journal from this operational HND. Capture window
144.392→90.291s vs a225, but changedgranules621952→501518 and allocator ranges
varied: do not attribute the entire54.101s/94.525s window/wall reduction tocode.
See `evidence/public-resource-capture-cursor-20261104.json`. NewAPrecovery,
mutation, power,2MiB-source and arbitrary hardware remain unqualified.

This candidate adds a scalar forward allocation cursor (gap binary seeks,
unchanged random COPY queries) and checked incremental arena allocation credit,
independently reconciled against the full registry at usage/seal/prepared closure.
One mutex covers retirement deletion plus credit commit. Capacity-query count,
full source/target checks, data classifications, journal/lifecycle guards and
write/flush order remain unchanged. Cursor RAM is prepaid; no unit tests ran.
Focusedcheck53344 passed21.11s; release83492 passed2m44s, two-toolmanifest
9ac0bad3eeb288b87290ae6f32deda44f68b88b77a16b5f37d842d1cc50a8d36
at `.lab/development/release-candidates/resource-capture-cursor-cec2252`.
See `evidence/capture-cursor-arena-build-20261104.json`; scoped native normal/
boot/bitmap results have their own record, not inherited from a225 or frozen814.
Source main SHA is unchanged.

Root full-census native admission: actual295668432172/free110890270720,
forecast21474836480B under unchanged329374052988/17179869184/50GB epoch.
The same fixture's measured conversion+reboot growth was11153050031B;20GiB
adds10321786449B headroom. This is a measured phase forecast, no cap increase
or baseline reset. Launcher `launch-public-resource-min-measured20-k.ps1` SHA
c53991ddce7e4bbd1cc18b2e0d4ea835c6ccb7f0030da132c97e1669ee5df6f3.
Frozen814 package/snapshots and completed a225 HND9702 remain preserved.
The later shutdown/checkpoint/reboot phase admitted8GiB at307811925199B/
98744885248B free under the same original policy. Remeasure before growth.
Another20GiB run may no longer fit; do not raise caps or lower forecasts merely
to fit. Obsolete intermediate checkpoints require a fresh dependency/archive
retirement audit; preserve the frozen814 origins and guardedf4bf.

Future public-apply VM interruption helpers are PREPARED ONLY, NOT executed:
`launch-public-min-powerwatch.ps1` SHA4ab3daf8a2c1a01019da13bb6a623d95fbb66e9e78328d0c8f911624f844b5c8;
`PublicMinApplyPowerWatch.cs` SHAb1ec653088cfeacbd0ec379a2c6f3a7a1b88e57f3d8789fa8f7abac50eb2c710;
`interrupt-public-min-apply-once.ps1` SHAd69988de353cf3a1a1ed1260b56e73f224cf605d3403ce61a8134b75c4aeea08.
C# is uncompiled. Root must review before any execution; any refused readonly
watch/lateHND/terminal aborts only the watch and lets conversion finish. An
observed write is not flush proof. New public-power postrestart AP/J/exclusion
authentication and recovery dispatcher still need implementation; never fake
the old diagnostic exit1/signal inputs to reuse its existing dispatcher.

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

**The separate compatibility attempt is closed, not live:**
`58c5d87cfedd487b8bf3e4a3e39ae3b6`, boot `1793765146033`, actual probe
PID3660/birth1793765254103 exited1 in4.5908017s. Held LOCK/DISMOUNT, GPT0800,
runtime OFFLINE and physical identity/GPT/marker checks all passed. The sole
8192-byte physical WriteFile at65714388992 failed Error21, returned0 bytes.
No retry, subsequent flush or readback followed. This does not qualify a writer.
Record SHA `cd5fef323055f79da6f4ae57f04ae60f43627a9dec4ec4f7a0dbf5d6a2e089f3`.

Separate explicit restoration PID6108/birth1793765364056 actually exited0;
record `9e129374dc73d17bb1ee4af7f7579a8801932a1d6803843a2c98747139e552d1`.
Only original target attributes/runtime state/T: were restored; marker identity,
extents and bytes plus C: and GPT siblings matched. No payload write or retry.
Probe26files353925B and restoration12files76970B were source/host SHA/length
verified beneath `.lab/development/fresh-partition-814-closure-58c5d87cfedd487b8bf3e4a3e39ae3b6`.
Archive manifests `72c9f4b67a4d452305de16d145b4251a5817c4e483f2f39b3dba1dbe64c5d7eb`
and `fab25023c7e04523a0c12c852fda73629d0f23746b553552a4fb97f1d09cb9d2`.

Root normally shut down; a fresh process verified **Off/RAM0/parent766**.
No new checkpoint was created. Original766 and all frozen814 branches remain.
The separate6GiB forecast passed unchanged policy at283378342707B used/
123199393792B free. Inspect the latest actual PID/birth/terminal and fresh VM
graph before actions. Root alone coordinates VM power, restore, dispatch and
snapshot removal while agents work in parallel. No compatibility probe or
conversion is currently running.

## Current development after the frozen package

Commit `a2255ba` is a separate performance/geometry candidate, not the packaged
814 executable. Focused `cargo check` of the library, public CLI, resource
diagnostic and new growth tool passed in27.46s; no unit tests ran. Root release
build session2875 completed0 in2m37s in
`.lab/development/release-candidates/resource-map-locator-growth-a2255ba` using
the pinned shared target/source and original4GiB build envelope. Manifest
`abe2c25226fb77a0658dfbee6fdf853a6d9a42ef1c34c16fd5a3ae3273f2a609`;
public executable `4d2d515b1f2520c37989354823fd5de87f50425cdfb6a8ef4293f126678f4e08`.
Its new map/locator public conversion is not natively qualified yet. See
`evidence/resource-map-locator-growth-build-20261104.json`.

It combines recovery-map and locator creation inside one private, non-escaping
frozen-owner boundary. Complete source/target/capture opening and closing checks
remain, including callback-error closure; map/locator metadata, native owners,
arena seals, journal identity and PreparedClear checks remain between them.
Later publication, delegation, final admission and Apply gates are unchanged.
For814's known range set, this removes2 of4 map/locator consumed-byte scans
(12,353,544,192 raw bytes); native timing/read qualification is pending.

Both source extent-fast gates now admit power-of-two4KiB–2MiB clusters; other
alignment/VDL/ownership/feature checks remain. Native large-cluster qualification
is pending. The new `lab-shadow-format-growth` creates only fresh owned empty
240GiB shadows, comparing direct format with50GiB seed/grow. It accepts no source
device and does not change normal formatter behavior. Its mounted bitmaps do not
prove complete consumed metadata or conversion ownership; remount is still needed.

The prebuild complete census was282065971393B/free124511387648B; the40GiB forecast
passed the unchanged epoch. It covers the build and bounded disposable growth
work, not permission to skip fresh capacity admission before native growth.

**PUBLIC CONVERSION AND NORMAL REBOOT ARE COMPLETE:** run97468663c2a24eb69d4dd1efef66b58a,
actualPID5328/birth1793769966082 exited0/852.3886042s at05:40:18.5275716UTC.
Root launcher70499 completed0 after its ONE intentional fresh3343 restore/start
from the normally Off, closed experiment branch. Native protected finalization
matched2558bindings/157known119009B/654extent-only streams; label/mounts restored,
HND closed. NEVER replay its old raw journal or compare operational writes with
stale selected postimages. See `evidence/public-resource-map-locator-20261104.json`.
Actual argv: `--drive F --partition 2 --minimize-scratch`; publica225 binary4d2d...
is pinned above. Gueststage `C:\ntfs2refs\resource-fixture-97468663c2a24eb69d4dd1efef66b58a`;
hostroot `.lab/hyperv/streaming-v2-20261027/resource-fixture-97468663c2a24eb69d4dd1efef66b58a`;
actual engine `C:\ProgramData\ntfs2refs\runs\331a61f17aab4a51ba925f1e20493271`.
SYSTEMtask `N2R-ResourceFixture-97468663c2a24eb69d4dd1efef66b58a`, workerSHA
ea822d7308da90a5d2cf46ed89b1d57dc8d441238215d276afcf9130022dce2c/configSHA
89396a344558b8c837e349af46991ed8a8918f03f096c21654a7bdb8497e350e.
Closed42-frame ledger authenticated; consumed scope is IDENTICAL to814:
638ranges6176772096B/logicalSHA5be841...ad0. Exactly12353544192 raw bytes avoided.
Map/locator logicalreads26831466803→13817219684B; sampled67.501→36.793s.
Whole observer-close149570921478R/2983581325W are NOT physical or exact final I/O.
Write selection changed2.819→2.548GB, so do not attribute the entire60.856s
uncontrolled wall difference to coalescing. Source/host6+3preliminary metadata
and56preboot observer files are verified; all13actual digest terminals checked.

Saved normalOff HND checkpoint **9702d1ce-6750-4d01-9490-001a194512bb**, parent3343,
then Root started ONCE with NOrestore. Newboot1793771926560; independent observer
4798c27b5c7b47719ecb4cedee0fcd5b worker2144/birth1793771997922 matched all811XXH3
streams9885801949B/1534baseline/1024extra paths opening+closing, all13owned
digests exit0,10.7582927s. Result d00931c7a738cdb267249fe9813b391e006a33a2babe6b9b43c35884fc523cd9;
closed56files106462B manifest e41d97203af44ab517f8f443b229497bb066e85cbde4bd08cc4a7d2b428860a9.
Root normally shut down after closure; a FRESH process verified **Off/RAM0/
parent9702**. No native workers remain. The saved9702 is the preboot completed
HND origin; postboot proof files are archived and current leaf remains durable.
Mutation/newAPrecovery/2MiB-source/physical-power qualification remain unproven.
All frozen814 snapshots and source/binary archives remain untouched.

Growth diagnostic only: `cd12d2cf3fc9dacc8492e7e3626bf530b5c6dd15` built one tool
in2m49s, manifest06969af7092f34ec8f10744b95901bbd682552c3a4b7da304b08310b5ab2be87,
binary7bfac9cc9edafcac9dfca3fe0a0b7ccb4bbed12a76ca940dc04582ec6274a538.
It corrected the lab's mistaken interpretation of discovery.read_only (that
field describes observation, not device state). Normal formatter is unchanged.
Direct case3589a47df3a04baa9c2405ca45610083 actualPID5316/birth1793768001128
exited0/1.0402751s: final240GiB, bitmap union26373816320B, backing104857600B.
Seed case78ee80cf5a704273b0ecfe75f7bd57d3 actualPID4132/birth1793768116528
exited1/0.7662221s: the generic zero-output guard refused the grow control's
nonzero returned count. Actual partition is already240GiB; filesystem remains
50GiB. Its seed bitmap union5905612800B/backing104857600B is preserved. Do NOT
retry that partially grown case. Initial diagnostic failureb92 (PID3480/birth
1793767283749/exit1) is closed:17smallfiles1283960B archive manifest8513fe4801e7614e08c5286363c3855b837883623583ae41cbca87fee4e42fa6.

New diagnostic-only commit3080e9d supplies bounded16/8-byte buffers for grow/
extend and retains full actual-layout/geometry checks. Root release session
21312 completed0/2m41s at `.lab/development/release-candidates/resource-growth-controls-3080e9d`;
manifest a7f629ddee5f57285179556dc4b17997011172b482ca4586761d9724e9f159a2,
binary9d6c91ad9f31a13b92d53aed72602ad0eddce5e5aefba19d8a0b2411a95d8688.
Case69287e75d81b413e84c9f4923a80930d actualPID5348/birth1793768703991 exited1/
0.8780946s after successful grow/extend; grown filesystem is239.9375GiB in240GiB
partition, so strict geometry failed. Independent native data and complete
declared-domain bitmap observation found25971179520B union, still about26GB.
Do NOT integrate seed/grow into the product: it did not keep the seed reserve
small and introduces a different filesystem span. Report
`evidence/native-shadow-seed-growth-20261104.json` pins all scopes and limits.
All3 named cases' small metadata closures passed; final21files119151B manifest
3d139cec5509d6a57a62675120e95215a554650b94813dad549b8926a024c130.
Their disposable empty images were NOT archived and were intentionally discarded
by the public launcher's fresh3343 restore; no direct guest restoration claimed.
The reviewed host
launcher is `.lab/development/launch-shadow-format-growth-v3.ps1`, SHA
e213a9e77465b6583b9a8b630dffe86a5f8111367b9646aa7b35e4b098f58f85;
it accepts one-tool or three-tool pinned builds, stages only the lab executable,
and performs no VM power/restore. Oldv1 failed before dispatch resolving guestK
on host; v2 fixed that path; preserve those closed failures, never redispatch them.

The separate2MiB fixture675d6bb6a62b40e9b0ea29c6e763d84d failed before formatting
with "Invalid drive specification" (formatter4432/birth1793767795356/exit1;
helper1672/birth1793767786880/exit1). R: was this new RAW disk, not a usable source;
no user payload or conversion was created. Metadata ZIPaf1bcb920bf43bb7029f810fba1a4e1e216e72b70421a48b2ee7560c26e1651c
and manifest6633ccb8121529da7d91e7b47e2f6e90ccc7261c84c1e50d39861cc5b1326d40
under `.lab/hyperv/streaming-v2-20261027/native-2m-fixture-675-closed` are verified.
Prepared helper `prepare-native-ntfs-2m-source-v2.ps1` SHA9922b9b63f5732ccd038bb24d45a86ec14d02db54c6fa80b4827e7dacf58618b
trims only the formatter's Volume-GUID trailing slash. It is NOT executed.
The failed RAW fixture was discarded by the already completed public-case
restore. Any next2MiB case still needs its own fresh baseline/new ExperimentId
after the current public conversion closes; do not disrupt the live run.

The old disposable file-backed disk's read-only eligibility query reported
CanPool=true through a unique matching native physical-disk object. Receipt
`native-2m-fixture-675-closed/pool-eligibility-readonly.json` SHA
9894e6fdce03ec4203aaab7698d63be2ce0c6eecd5e41173b2bcd76522d05492
is preserved. This is not a1PB address-space or ReFS-format qualification.
Future Storage Spaces probing may use ONLY newly created private blank members,
never an old disk number or this discarded R identity. No pool was created.
Prepared ONLY `.lab/development/probe-private-thin-pool-addressability.ps1`, SHA
20690a671c41362e2128ea23fd5f3af22973f74a7a65ba1f684563e8d940aa9c,
uses2fresh5GiBmembers and one native-aligned request covering at least1e15 bytes.
It does not format; Root must review/admit a new phase (at least12GiB forecast,
10GiBmember maximum plus overhead/free reserve). Observed8GiB ceiling is not a
kernel quota. Never run it against this completed HND branch without choosing
and binding the intended disposable branch; no existing storage may join a pool.

Next performance coding target: capture made688405 per4KiB capacity queries in
814 (151.158s window). Arena check_free also folds the entire registry on each
literal extension: O(changed-literal-granules × registry entries). Incremental
checked arena totals and a monotone allocation cursor can preserve the same
checks while removing repeated work. Any query batching needs real held storage
reservation/equivalent scoped admission, not merely less frequent sampling.
Do not repeat seed/grow experiments or weaken required zero writes; native
zone-probe evidence disproved zero omission. StandaloneVHDX RCT baseline sealing
and zero semantics are unproven; keep that research off the next coding step.

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
| `3343f2a4-cf81-4fa9-a504-030425a8011e` | Original prepared lab source and parent of the frozen 814 branches. |
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
  authority. Even the fresh held-lock/dismount/GPT/runtime-offline combination
  failed physical WriteFile with Error21. Keep the writer unavailable until a
  working protocol and persistent process-death/restart exclusion are proven.
  Do not retry either closed failed write attempt or clear its exclusion to
  evade refusal. Any different control sequence is a separate diagnostic case.
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
