# ntfs2refs project guidance

@C:\Users\mfara\.codex\RTK.md

Read RTK. Work in **D:\code\ntfs2refs**, branch
`codex/isolated-journal-observation`, private origin faratech/ntfs2refs.
The environment's C: workspace path is stale. This is a current handoff, not a
chronological log. Prior instructions and results are preserved verbatim in
[the November 1 archive](docs/history/AGENTS-through-20261101T0225.md) and
[the October 29 archive](docs/history/AGENTS-through-20261029.md).
Old CURRENT/LIVE labels and preserve-all instructions in those archives are history.

## CURRENT release block (2026-11-02 UTC)

This block supersedes older CURRENT/LIVE and pending-power labels below.
CURRENT VM is fresh-confirmed Off/RAM0 at AP1 power Rollback checkpoint
44c0074b-b5c4-4614-b957-a96842436cbf, parent8d4192fe, 20 snapshots.
Runtime7cd6870 passed actual AP1 power Resume (native3064/birth1793594871253/0,
16.2593027s, HND/ReFS, 1084 maps) and separate original-state Rollback
(native2588/birth1793595236914/0, 11.6591231s, ABT/NTFS, 142004224 restoredB).
Original power checkpoint8d4192fe-003b-441f-8591-f0b271028841 is a child of
preparedcb802669; original producer exit remains UNOBSERVED. Resume is saved
at fccec765-f271-4dd5-88c6-6e6e5bd29181, parent8d. Both results/archives are
closed and verified; NEVER replay their HND/ABT. No extra 811-stream full hash scan.
Power helper df88c9d563d1abc488e67322c966dcaced0a332936490e83fc14658193ed2def
retains the actual absent-shadow Read/ShareNone guard through native/terminal
checks, without AccessDenied-to-absence fallback or detached VHDX identity claim.
Commit378860e memory changes compiled. Clean offline candidate r378860e-c built
283 source files/6 binaries, workspace 517209397B, manifestSHA
cbf9c8d8b328e7a6aa8cd42e62c895ce6f40e2c6c2fc53707565bde84a1091f3.
It inherits no native/power qualification. HND/RB/ABT power cases, final exact-build
qualification and release remain OPEN; production markers stay gated. Protected
main c6bc5c52... remains unchanged/unstaged; the permission question is unanswered.
See docs/native-format6-power-recovery.md and the AP1 power evidence JSONs.

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

## Performance continuation and current native state (2026-11-01 UTC)

Latest native performance case6be2648addc24d1b95a11d807dae76d6 PASSED exit0/HND
and all811 independent hashes. Runtime c2c1ef3 used the already-prepared source,
new live source certificate and same owned empty shadow. D544,784,384B /
J131,301,000B / C15,888,384B / O55,504,896B / F402,669,568B. Actual format5
N2RFRE01; native conversion62.2871679s, prep18.5202009s (80.8073688s combined).
Native-verified logical process reads27,643,861,313B/writes878,482,576B versus
prior94,053,323,457B/17,368,271,656B. Journal reduction97.73%; kernel NTFS move IO
is separate. These are scoped observations, not a controlled physical benchmark.
See evidence/prepared-source-performance-native-20261101.json.

CURRENT VM is fresh-confirmed Off/RAM0 at native format6 controlled Rollback
200aaa68-6a12-482d-910e-60e5b1f20b63, parent originalfault5d2517e5,17snapshots.
Runtime010316d matrix PASSED: fault76ce2bc519f74493a29832b8c7f1db4f native840/
birth1793587745932/exit86 afterfirstflushedsourcewrite; originalcheckpoint
5d2517e5-59f9-4c26-b9e0-e6775d175f68 parentpreparedcb802669, receiptSHA
b3fc860f1d04a645db01c593ba0c9661f20d65bac2d1ce0c9cc1b1165b92ddbe,
bundle70ef71dc498e887d4810660913b61189b564811a46f5e063ce9fbe15b290c97d.
Separate Resume d81599ef... native4604/birth1793588211332/exit0 HND/ReFS15.8797041s,
1084completebindings, checkpoint43d445cb-0d6e-4647-aa43-2664ee78b424.
Separate Rollback37f15c4a... native4572/birth1793588475205/exit0 ABT/NTFS11.5185644s,
142,356,480restoredB digest96a4400a2f6e7fc07e2c337b5e82a1e61346776ee3ae2f87a1e0704f497362b4.
Both collectorspassed, shadowabsentafterboot/neverreattached, originalJSONisnot
newsourceauth, noextrafullcontentscan. Archives: fault62/130227192B,
Resume31/29770192B, Rollback29/2643077B, length/SHAverified. Normalstoponlyafter
allprojecttasks/workersterminal. Evidence/native-format6-controlled-matrix-20261102.json.
Power-cut/hardwarequalification stillpending. NEVERreplayresultHND/ABT; useonly
original5d2517e5 foranotherdirection. Originalnormal format6 eba55c48 remains saved.
Read-only completion1078caf077ae4c51a76d8e2110c5a74e PASSED Ready/0 with original
native3944/birth1793585096824/exit0. Original operator failure and earlier6037
cold-shadow refusal are preserved. Source payload scanned0, new nativeprocess0,
rawJopenedfalse. Detached shadow6 is affirmed absent only AFTER closedHND/full
recorded native proofs; image exists/Attachedfalse/allcurrentGUIDsunique, no
reattach/rebind/attributechanges. Closed10observerfiles89,357B verified; archiveSHA
33d74cd86c502b0fd602febd2671b082905df9d2f98496e816050144feee2d1b.
VM start initially failed for hostRAM. WSL cache-only reclaim (sync/drop_caches)
released about38GiB Linuxcache and enabled the unchanged4GiB VM; no Linux process
was stopped and no persistent memory/privilege setting changed. Keep WSL running.
Run e330512f550a49dda07e5700f5c4bb6a used sealed runtime010316d, native3944/
birth1793585096824 exited0 in69.7858092s, HND/ReFS, actual sealed unbuffered NTFS
journal format6/131,669,328B, selected545,095,680B, eight aligned distinct marker
device offsets,1084 complete native map bindings and650partial/1,371,388tailB.
WOFquery1 remains unsupported/absence=false; samehandle directreparse4390/tag0
supplies affirmative ordinary-file proof. Both terminal barriers passed before
native online exposure. This is normal CORE success, not a completed native6
matrix or hardware qualification. Independent full-content hashes were not run.
Original metadata observer failed AFTER native0 because saved admitted V3Some
was incorrectly required to remain planningNone. Its corrected finalization
reader uses64MiB (actual27,174,509B). Readonlycompletion is now complete; NEVER
replay this HND or rerun its converter. The generator and original failures stay.
Closed67files157,375,432B source/copySHAverified; archiveSHA
d9bdf0ba3bbe3ee2c1d57b5fb2d3b2604600dae865a2cf7e79b6275c7b2c9167.
Bundle7296ac5c02ec6dfd3292e78f12d8dee48e3d08870faaf025a8f1976aa50723bd.
Evidence evidence/native-format6-core-normal-20261102.json. Logical process read
delta21,619,924,280B/write922,583,523B; physicalIO and peakRAM remain unmeasured.
The core success checkpoint was normally stopped/fresh verified before current
read-only observer boot. No native conversion/recovery job is active now.

Earlier completed current65b Rollback remains saved at
9a01516b-1279-4266-9923-fe17d2610090, parent original6679708a.
Rollback5b38b6a74a61429abd60829507b0e7c1 PASSED native6124/birth1793580685000
exit0/ABT/NTFS and all811 independent hashes. Restore-required144,560,128B digest
3f2be98dfc6a5cf8f12a818593fa8df8cc9a0e89c7aa3637891039b040588c22 matched;
original full-old marker identity3f01c92ba134075ddf517702704bc7b517dbeb5b1cb4728e389815d2bb89e6bc
is unchanged. Original free bytes and post-rollback maps/timestamps are not claimed.
Closed57 files61,769,941B, archiveSHA92b00fca5022290a2c5e2d38b5e77ce2a156e0552754643b0d5a8b537180fc69.
All tasks/workers terminal before normal shutdown. No active native job remains.
Resume5ccce67524a64c58a2c89b8c37a990cd PASSED native852/birth1793579665500 exit0,
HND/ReFS, all811 independent hashes,1084 metadata/maps,273 required directory checks.
Normal stop and fresh checkpoint19f5d614-e7a0-42d7-9d32-c8e1c55c1065 saved it,
parent6679708a. Closed59 metadata files88,491,263B; archiveSHA50a778825b18064165c66bbe062832fe747dc08028a91e15dcd179b16f04d687.
The first resume harnessaa991 refused before native launch because host PS7
normalized a timestamp; its failure is archived. Controller8097683 preserves
timestamp strings and both current-source14/6 adaptations; historical11 remains.
Original first-write checkpoint6679708a is Off/RAM0, parent preparedcb802669.
Producer4144/birth1793578032909 exited86; actual sole post-flush message,
noApply/HND,sourceoffline/shadowofflineRO and terminaltasks/workers observed.
Metadata archive verified; readonlyobserver completed the original failed schema
observation without replay. Recovery bundle SHA2a86be3408bc784a3b0ac1a8bff2acc1b76099635ed58561114e84724a376944.
Actual checkpoint receipt atprepared-source-performance-interrupt-d0d30cb0454e4441920df86accf869a7/checkpoint.json,
SHAf5b631ee591c1c6befd3afd75ddf4bc50d93cfec60d0bc9e8abd89ca7595738c.
The controlled current65b first-write/Resume/Rollback matrix is now complete;
both directions started from original6679708a on separate branches. Birth-to-
terminal observations13.247s Resume/8.089s Rollback include parent observation;
the slower PS lab metadata/full-content observers are separate. Evidence:
evidence/current65b-recovery-matrix-20261102.json. No rawclosedHND/ABT replay.
Latest PUBLIC minimize-scratch success1d7299ff-c616-4bcb-8b29-c1a1ba4a8a33
remains saved separately, parent golden8329.
Run d04360139db64953a53a2d1448018c58 used real
ntfs2refs --drive F --partition 2 --minimize-scratch with affirmative stdin,
runtime65b1178 (not a lab conversion entry). Native1308/birth1793575210964 exited0,
HND/Complete. Wall131.4201284s INCLUDES385 NTFS moves/5,643,501,568B and new live
post-move source certificate. Actual journal139,901,808B +literal45,113,344B =
185,015,152B; processlogicalreads26,341,046,157B/writes2,507,543,331B. Kernel move
IO/physicaldisk speed and peakRAM are NOT established; peakmetricsnull, never0.
Original independent811 hashes, exactsemanticmetadata (existingprovedaccess-time
exceptions only), fullnative move-map replay, security/namespace/fullmap/tails
all PASSED through readonlycompletion3569935d09754470af1bdfdaf014facb. No native
conversion/recovery replay. Original schema-tail and duplicate cached-access
observer failures preserved. Source required273/5 provenreplaced internal dirs
of278raw, actual$Deleted29error87 remainsUnknown. See docs/public-min-scratch-native.md
and evidence/public-min-scratch-native-20261102.json.

Product records: C:\ProgramData\ntfs2refs\runs\0dd148940f0c665732d7e146426ff52c\conversion.
Closed106 metadata files224,579,123B source/copySHAverified under .lab base
public-min-scratch-d04360139db64953a53a2d1448018c58/closed-native (wrapper/product).
Alltasks/workers terminal before normalstop/checkpoint. Oldnormal051b andf8f7 were
retired viaHyper-V after279 old/newarchivefilesheld/rehashed; receiptfolder
retire-two-superseded-normal-results-f59aabfec5804818aac3c9756dd0362f. Allarchivesremain.
Keep latestnative6eba55c48, original6679708a, newResume19f5d614, newRollback9a01516b, latestpublic1d729, preparedcb,
originalNTFS8329/6fe2/371a/9c42, guardedf4bf,Hcoldd939, oldformatinterrupteddea9
and format5original7721 (14 states, current Off ateba55c48).
Cleanup20261102 retired ONLY archived recovery-result leaves8087/d40b/d9e580fa/67eda3e4
through Hyper-V after224 archive files held/rehashed. Freed22,095,781,888 hostbytes
(20.58GiB), Dfree143,170,375,680B; logical lab201,040,951,068B at00:25UTC.
Evidence: evidence/obsolete-recovery-snapshot-cleanup-20261102.json. Older keep
lists below are historical and MUST NOT recreate these retired IDs. Automatic
approval review blocked three obsolete .lab/development Cargo cache deletions;
leave those paths alone. Main target is also in use by external cargoPID17220;
root did not start that test command and must not delete its build directory.
No rawHND/ABT replay. WSLrunningprotected.

Source65b1178 fixes case applicability after independent bound replacement proof,
not metadata labels. Actual2e20 predecessor safely refused$Deleted87 before
certificate/J/writes;40 metadata files94,365,160B preserved atprepared-source-
performance-normal-7f5da47801b1457cac07a28f0b63bfa6/closed-refusal. No failurewasmasked.
Alltransferred/root dirs still actual0/0. Preparation savesboundedalready-read
source-before-preparation.json and pin/length; all4 actualbasic_times retainedand
verifiedstable in385moveledger. See source-directory-case-admission.md.

Earlier72b4db0 actual closing-reuse8437 PASSEDall811:6,176,772,096B reused,
extra capture shadowreads0; bothraw/zero brackets unchanged. Reads21,473,893,401B,
wall70.5999624s vsprior62.2871679s (NO wall speedupclaim). Oldf8f7state retired,
87-file220,578,453B archive preserved; evidence/closing-buffer-native-20261101.json.

Positiveformat5 c2c1ef3 first-write/Resume/Rollback matrix passedall811 bothdirections,
restore-required143,527,936B matchedc395ac7284dcc32ba73e148957e544d837fc1c7423291f09c1ec32aefac36ceb.
Originalfault7721 parentcb: receiptSHA9afc04c396cad6051bde711914227ac394e78aacc5391ef479fdf630cb95d4eb,
bundle0b6cc964ac2b3410712b23c99b5247a58a9b9297d4554c052c4312daac35c0fc. NativeResume4688
18.7571244s/HND,Rollback6052 9.8437227s/ABT. Old resultbranchesd9e580fa/67eda3e4
were retired after full archive rehash; evidence remains. This old matrix is not
native6 or hard-power qualification. Current65b Resume now passed separately.

E3 mechanics c641d8d generic opt-in format6 N2RFRE02, marker_profile RedundantSourceFreeV1,
body32768/AP/RB/HND/ABT copy pairs; formats1–5 defaultsunchanged. Nativeproduction
creation UNWIRED; general_recovery/allocation.rs explicitly refusesmarkerprofiles
BEFORE targetopening. Native adapter670f72f is compiled/source-reviewed only,
MARKER_STORAGE_NATIVE_QUALIFIED=false. It binds share0 unbufferedwrite-through
NTFS, exactEOF, aligneddisjointmappedsectors/protectclusters/scopedprivilege,
uncachedreadback. Integration7859cea adds the same-owner postvalidation sealing
hook and both-terminal-peer online barrier behind ONLY explicit enrolled lab
lab-selected-marker-native acknowledgments. Independent source review and focused
build passed. One valid terminal closes replay; degraded peers stay offline.
Native/hard-power qualification remains open; production defaults unchanged.
See docs/redundant-selected-markers.md.

Memory codee596322 streams bounded artifact saves/hashing, borrows exported maps,
moves parsed maps into recovery lookup and directly compares mounted bindings.
Focusedcheck/releasebuild and independent review passed; no new native evidence
for this runtime. Shared selected artifact limits934ffa8 fix writer64MiB versus
recovery16MiB opening/copy mismatch; small fresh saves obey existingread limits
beforeactivation. No object/range caps lifted. The separate lab readonly observer
still has16MiB expectation/report limits; reconcile before larger-corpus claims.
Sealed e596 runtime toolsetnative-marker-memory-tools-e596322/manifest.json
SHA857e4003cc4c367a0bf3fba2c45461f30dfcdd261608b286400ff1bee31c5fad
has4 standard roles plus separately pinned lab marker tool. It predates934ffa8;
do not relabel it as latest or nativequalified. Details metadata-memory-reduction.md.

NEXT: native6 hard-power qualification usingexplicitpause, thenresource-basedpagedscale.
Native010controlledmatrix and65bmatrix areclosed; do not repeatwithouta
new failure or relevant change. Publiconecommand
coverage is now real; don'trepeatit withoutnewchanges/failures. Cleancommitted
release/tag/version remainsopen because usermainhunk MUSTstayuntouched/unstaged;
qualifiedbuildpins it separately. No units added/run. Do notcall performancegoal
complete fromthis boundedcorpus; independentwriter research remainsoffcriticalpath.
Lab-only marker-copy pause instrumentation is now source-reviewed and compiled,
but not natively qualified. Eight8slots selectable through paired
--pause-after-marker-copy/--pause-signal options; signal is preallocated32KiB
marker-pause.json directlyinsideindependentC0output. Actual selectedcopy must
completewrite/flush/uncachedreadback/storagevalidation before syncedsignal closes;
then source/journalownersparkforever. Signalwrite/syncerrorparks withsignalstill
share0locked. No nextslot/target/callback advances, no timeoutautocontinue, all
productionpathsNone. HostmustverifylivePID/birth+readableclosedactualreceipt before
the intentionaldisposableVM hard-power exception; timeoutalone is NEVERauthority.
Rootfocusedcheck3bins passed23.32s; no unit tests. Build/freeze a newruntime before
pausecases; existing010316dsealedtools have NOpausefeature. Controlledprocessfault
matrix haspassed010316d. Sealedpausebuildaba19c9 at native-marker-tools-aba19c9/
manifest.json SHA96a7edf0ac89878e7098299e27362395e734eb09e38546db27aa521ddd227ab7,
sourceaba19c9b06b2d3ebfbcc921bd5090cec77cf97da, markerexe4ea48b265dc4c49fec76b9fc63d5870fee346198e9da930b65e2fdad91896230.
It predates the newly source-reviewed/compiled terminal-peer repair; build/freeze
latestbefore HND1powerrecoveryqualification. NewexclusiveclosedReadSeek-only path
checksfullcommittedtarget, repairsonlymatchingterminalpeer, rechecksfulltarget+
unchangedlifecycle beforeexistingnativebothpeerbarrier; publicread-onlyverify
andlegacyNone remainunchanged. Rollbackformat6 repairs actualexistingAPafter
fullmixedtargetprecheck beforeRB/payload, neverinventingintent. No nativeevidence
forthisrepairyet; focusedcheck17.57s/source-independentreviewpassed. Recover-only
dispatcher now allows affirmed originalshadowabsence aftercoldboot, without
attach/rebind/attrchanges; Fresh stillrequiresoriginalemptyattachedshadow6.
Preparation82e805b moved5,643,501,568B over385 native requests/222 identities,
with complete native maps/EOF/identity checks and all811 independent hashes.
A fresh frozen full raw/native baseline also passed1084 objects/811 streams.
Prepared checkpoint cb802669 preserves RUNNING MEMORY and empty owned shadow6:
restoring it yields Saved; verify in a fresh process, then Start-VM once.
The original prepared managed smoke receipt is pinned SHA184aad57e2c8c8616adb4ad57ed82e40aba31949c530015ebcc5f7b681bcf876,
at ntfs-owned-preparation-6ec16ed4b4774c13a76b1e282103c66e/closed-native/managed-shadow/result.json.
The actual guest VHDX is under that same6ec...stage, not each conversion's stage.
New source uses a32MiB pre-submission receipt reserve; focused compilation passed,
but that later change was not part of recorded82e execution. No unit tests.

New full baseline manifest SHA7d10997d0ec43a54725c66956a0992d40437b20720a78217852cc338e82a74e7
is under ntfs-owned-preparation-6ec16ed4b4774c13a76b1e282103c66e/full-baseline-
8796571ebd24458f8bedf17b5784e5a7/closed-native/full-baseline in the .lab base.
Original f5de describes PRE-move physical locations and is not admission forcb.
Conversion uses genuine fresh source inspection/certificate; baseline JSON is
only independent lab evidence. Original logical-content hashes remain pinned.

Completed first-write interruption used
lab/Start-PreparedSourcePerformanceExperiment.ps1 -InterruptAfterFirstWrite.
Its exact schema3/8GiB J/256MiB literal/10GiB combined bounds remain; requires
positive format5 F for the new recovery experiment. Toolset remains sealed
paired-source-preparation-tools-c2c1ef3/manifest.json SHA70fb7abaff41ad497bb90e996662057de36222ddd9d5a68cc411d57957dc557e.
Native producer SHA93c1eb20a3510fb12f6d84732fb3b4c8779ee7493ceefa46f5125f1bd0c8e232;
public SHAe49d604561d19652557b8ee8a2e93f3ca8797d7e97fd7c228ae7a7ee7cab2f75.
Root must create a REAL interrupted checkpoint receipt only after actual86,
first flush/noHND, idle, normal stop and fresh checkpoint graph verification.
New lab/Start-PreparedSourcePerformanceRecovery.ps1 documents the schema1
prepared-source-performance-interrupted-checkpoint-v1 contract. It is parsed,
not native-qualified, and requires original bundle/process/terminal/diagnostic/
managed pins. Root must review it before execution. Resume must prove full new
selected SHA/HND; Rollback proves ticket.old_restored_selected_sha256 over D-F,
not full old-selected bytes. Marker/footer identity REMAINS original full old SHA.
Never invent legacy producer fields or recreate fresh Apply authority from JSON.
Native positive-format5 interruption, Resume and Rollback passed for c2c1ef3 only.

A delegated Rust read-pass fusion may be in progress; inspect worktree before
build/commit. Desired optimization consumes actual borrowed closing-read buffers
in capture, retaining BOTH complete opening/closing reads/hash equality and all
native/route/allocator/source gates. No zero-range skipping or JSON byte authority.
Unchanged9,868,443,648B of adopted payload is ALREADY excluded from comparison.
Actual remaining bulk is repeated6.18GB native-metadata/required-zero brackets;
see current target-preservation and phase IO counters. Paged evidence/handle
windows remain for broad scale. Do not mark the performance goal complete.


Sealed new-runtime toolset closing-read-reuse-tools-72b4db0/manifest.json,
SHA783f1f2a3e0abd3e97e573554a31a5379fd9eae5a4fc1cdd10637e7921b17e6b.
Public9b371439ecbf9cc374b990ece1d31760bfa25f1e2951bb1e7c96751e5415395a/10344448B;
producer17931521a6c0488c41c47528784e46fdc94882c9eebcea0a0d400ea675c1f347/7276544B.
Prepared controller now supports -RequireClosingReadReuse; do not claim measured
savings until actual new native case. It checks reuse counter, both full raw/zero
brackets and exact source+shadow+reused byte accounting. Older controllers/helpers
remain compatible; inherited helper origins retained. No unit tests.
Root alone mutates VM2401593c-4b30-472e-9b6d-c9534cbaa599,
ntfs2refs-streaming-v2-20261027;4GiB fixed/4CPU/noNIC. Credentials only Import-Clixml
.lab/hyperv/win11/secrets/guest-credential.xml, never print. Keep current051b,
preparedcb, sources8329/6fe2/371a/9c42, guardedf4bf, H cold d939, original old-format
interrupteddea9 and recovery8087/d40b, original format5 fault7721, Resumed9, Rollback67eda and latestf8f7 (15 states). All other older listed IDs were
retired. Old recovery compatibility evidence is in docs/exclusive-recovery-native.md.
## Evidence and current implementations

- Frozen E4ff old-zero matrix is complete: first flushed write86, clean restart,
  Resume0/HND, separate original-state Rollback0/ABT, all811 hashes both ways.
  Old-selected checksum exactly matched original ticket. This is not arbitrary
  faults or physical-power-loss qualification. See docs/old-zero-recovery-matrix.md
  and evidence/old-zero-recovery-matrix-20261031.json.
- The retained states include latest051b, grown source8329, original F source6fe2,
  H source371a, sparse source9c42 with guardedf4bf, H cold resultd939, interrupted
  old-zerodea9 and journal-owner recovery results8087/d40b, plus new prepared
  sourcecb802669 (11 total). Other historical
  fixture/intermediate/result nodes, including6bef and the H tail matrix, are
  retired. Their reports and pins remain. Never recreate old IDs from guidance.
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
