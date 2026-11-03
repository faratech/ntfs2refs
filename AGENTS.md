# ntfs2refs project guidance

@C:\Users\mfara\.codex\RTK.md

Read RTK. Work in **D:\code\ntfs2refs**, branch
`codex/isolated-journal-observation`, private origin faratech/ntfs2refs.
The environment's C: workspace path is stale. This is a current handoff, not a
chronological log. Prior instructions and results are preserved verbatim in
[the November 1 archive](docs/history/AGENTS-through-20261101T0225.md) and
[the October 29 archive](docs/history/AGENTS-through-20261029.md).
Old CURRENT/LIVE labels and preserve-all instructions in those archives are history.

## CURRENT release continuation (2026-11-03 00:41 UTC)

LIVE VMRunning4GiB/4CPU/noNIC,33snapshots,parentORIGINAL58bd9ceb-60bc-4b34-81e1-7af197523a80.
Rootrestored58bd EXACTLYONCE forindependentRollback, thenstarted. ACTIVEbranch
is now originalinterruptedNTFS source1 (not the previousclosedHNDResume branch).
Rollbackobserver taskN2R-PagedEnvelope-Recovery-rollback-5cc9b3f4a5854b35bc7cb98c0e8172bd
actual5088/birth1793666446097 Runningat00:41:29. Publicnative rollback NOTYETobserved
launched; latesttypedpage/oldzero preflight. Hostdispatchsession62328completed;
doNOTrerun. StageC:\ntfs2refs\paged-envelope-recovery-rollback-5cc9b3f4a5854b35bc7cb98c0e8172bd.
Runtime7feb/sealedb0/helperf190 unchanged. No hostbuildlive. RootaloneVMactions.

RESUME FULLYPASSED Ready0/all811independenthashes/1534objects, allcompletemaps
identical,650tails. Actual2456/1793664719382/0,239.4291539s; wrapper4752/birth
1793664307649 terminal. Archive76files146,412,148B at
.lab/hyperv/streaming-v2-20261027/paged-envelope-recovery-resume-bd4eee3b50504bc3b0cea5ad89212cd2/closed-recovery/archive-manifest.json
SHAb3838c824b4c3314c6b2e6028f47b2f21d7363bb38bf1de592c1becd1d27e355.
AllResume metadata (includingrecovery-13407d75...) closed/pinned beforediscarding
ONLYitsworkingbranch byrestoring original58bd forRollback. NeverrawreplaythatHND.

STORAGE: Resume growthdrove actual328182083310/free11330711552 below16GiBreserve.
No furtherVMwrites started; allworkersclosed/normaloff. Retired ONLY superseded
f3c1460b-6811-4dd3-908c-12cc2842c35e (14ec1084normal leaf) viaHyperV after full
109old+113replacementarchivefileSHA checks underreadlocks; replacement5ce1534
saved+archive97b intact. Allother33IDs+f4bf/original58bd/a062/5ce preserved.
Afterdelayedreclaim actual314803133403/free24707756032; resumedsolelytoarchive
closedResume, thennormaloff/restoreoriginal58bd. Fixedepoch/max329374052988/
min17179869184 unchanged. f3nowRETIRED; don'tresurrectfromolderguidance.

New .lab/development/archive-paged-recovery.ps1 SHA4afdc3990cdef067d8cf320aa81169d3ce019130986e492d361e9f8ec3530a9a
canarchiveRootonly afteractualReady0/native0/all811+1534/allworkersabsent. Params
CasePath,GuestStage,NativeRecordsRoot(ROOTwithoutoperationleaf),Operation.
Whitelistmetadataonly; neverJ/bin/vhdx. Lastnewsourceuntracked
lab/Start-PagedPublicMutation.ps1 SHA3522bb167b0c47492206ed3de57212605b6f66ea5d75513174c8bb684a1d1bec
is source-reviewedbyC/PS5assembledparse0 butNOTinvoked. SourceFrozen5971 oldhelper
unchanged. RootafterRollbackarchival mayrestore5ce forMutate, normalsave/off/coldboot
VerifyAfterBoot; exact258newfileSHA/256entries/all811 originalcontent/1534namespace/
type/length checks. NOTallACL/SACL/timestampmetadatabytechecks; labeltruthfully.

NEXT: verifyactualRollbacknative0 +independent811/1534, archiveclosedmetadata,
allworkersabsent/normaloff. Thenexact7febmutation/coldboot. Broaderrelease remains
UNPROVEN: raw2048/semantic16MiB/native64MiB/handle/rangecaps, standardformatonly
safeformatterrefusal, nativeproductionmarkergateFALSE, notphysicalpowerqualified.
Useraskedstablecloseness: workingexperimentalalpha, notgeneralstable. Preserve
fullobjective; no narrowedgoalcompletion. Mainc6/no unit tests/WSL unchanged.

## Earlier release continuation (2026-11-03 00:20 UTC)

LIVE VMRunning4GiB/4CPU/noNIC,34snapshots, parent58bd9ceb-60bc-4b34-81e1-7af197523a80
(ORIGINALinterruptedNTFS childa062). ACTIVE WRITABLE BRANCH HAS NOW CLOSED HND/REFS:
publicResume2456/birth1793664719382/0 in239.4291539s. NEVER replay activebranch.
Post-nativeobserver4752/birth1793664307649 task
N2R-PagedEnvelope-Recovery-resume-bd4eee3b50504bc3b0cea5ad89212cd2 stillRunning
at00:20:03; no finalReady0/all811 yet. StageC:\ntfs2refs\paged-envelope-recovery-resume-bd4eee3b50504bc3b0cea5ad89212cd2.
RecordsC:\ProgramData\ntfs2refs\runs\recovery-13407d75fde97e9a95180202ee0e17f9.
NO hostbuild live. RootaloneVMactions. Check actualtask/PID+BIRTH, notPIDalone.

Firstwriteproducerfe086985340548db9eb098a884f4d1be actual6004/birth1793661913763/86
flushedonewrite. Wrapper5044/birth1793661790079 thenReady1 duePSempty-array.Count
bug atgeneratedline659; original failure preserved. NEWpuremetadata observer
2d3370475c7f4d21a5ee52475cc94c90 actual2140/birth1793663040818/Ready0 verifiedall
remainingchecks, separatepub/control (originalReady1NEVERfabricated86).
Generator49f41a495ccd4318c3122b18897d8c7f683659c840ffc2a1c90bd20d6c1a548d;
worker28b630c436d79887bd873c81b2fcf27a7ad8609759271cc4ccdc570da58cfbb8.
Combinedclosedarchive106files278,336,987B SHA37d67de193964d714522a67de6aa67d07029ec7a8456ba73f393eed53a12f5ee;
V2closureSHA21bcb8b128f8354e0011fa5cff35b6acb1cc5cba252ff3beaea95918afc44625.
Originalfailurearchiveed76ce3f98bc3670ee3dca9bc508352f3b8ae78d6157a8e3b7d3e4423094e874 remains.

ACTUAL journalformat4/N2ROLD01, NOTformat5: selected11,396,272,128B,
oldzero5,665,275,904B, J5,786,767,272B, sourcefree0. Requestpolicy ALLOWSsourcefree
butactualplanhasnone; fullselected-byte rollback contract applies. Bugwasnull
arraywhenno source_free_ranges, not necessarilysingle-range scalar. No SourceFree
qualificationclaim. CP58bd savedafterallclosed/normaloff, containsactualoriginal
J+Some2expected/map.pages+completion. Rootreceipt casefe086/checkpoint-observer-completed.json
SHAd4321534441dfcd7a8bf2a91358950b7caaf4af9620b48fb818f0fd13068aa8a;
publishedbundle334098c8baa0a04c95275130d2714b1551740dfeee66a011db179000ad2f7baa.

Use NEW lab/Start-PagedEnvelopeObservedRecovery.ps1 FINAL SHA
f1900f073364d7a30224de47ac11cc02bd43c6a3d01c683c5d6fd0f2e2a52c1d
(HEADb3083a1). It acceptsactualformats4/5 withstrictcontract, role4MiBcontrol
receipt (actual2,636,563B), keepsallfullpins/checks. Earliera124resume attempt
Ready1 waspreflight-only JSONrolelimit; native_exitnull/NOnativeprocess, preserved.
Currentbd4eee issecondfreshscope, ACTUALnative0/HNDclosed asabove; never rerun it.

NEXT waitcurrentobserveractualReady0+all811/hash+1534metadata, archiveallclosed
metadata, proveallworkersdead/normaloff. THEN restore ORIGINAL58bd ONCE for
independentRollback via samefinalhelper. Never restorecurrentHND image asoriginal.
No activeunit tests, no main edits (c6 unchanged), keepWSL/fixed50GBepoch/min16GiB.
Rootledger .lab/development/current-paged-state.json hasactualcurrentIDs. All
native format6globalqualificationflags stayFALSE, no stable/tag/generalrelease.
Need newpagedRollback +exactcandidatecoldboot/mutation beforequalifiedalpha.

## Earlier release continuation (2026-11-02 23:20 UTC)

VM fresh-confirmed Off/RAM0,33snapshots, currentparent
5ce766b0-c6e9-4007-b16d-363944240c51 childa0621534source. This is CLOSED HND/ReFS;
NEVER replay currentjournal. No VM/build job is running. Root alone VMmutations.

Corrected7feb4c06d21e9de73bb88961197f5b745463e490 clean8bin buildmanifest
d4afec214f672fe4eb3b12c5e82a5315ccbee25f92f9222ef426605948f54814;
sealed5roles directory-attribute-tools-7feb4c0 manifest
b0f6fe5fd4e02046739e9c177c838c1675c5a746b8662eec493402cca9e5e521.
Actualfixedfullbaselinefb8592bb3b044c3aa3879c46afd326af passed capture4984/
1793660209770/0,21.570304s. Manifestd6a958631a570b3a2cdd3f0077148b571330719988f6f0e430d8e80a22e72d09,
schema2/9artifacts/1534objects723dirs811fullstreams, before/after3/noauthority.
Immutablecorrectedbaselinehelper5ce43...751ce is committed3371e97; ce2 unchanged.

PUBLIC1534 case608071c1ad524d07b1ef94237996cc6c PASSED native4164/birth
1793660834450/0 in129.4563482s includingnativeNTFSpreparation. All811 independent
hashes+1534objects/fullprepmapreplay andSome2typedpages passed; wrapper4592/birth
1793660713935 terminal/Ready0, allworkersabsentbefore normalshutdown. Sourceattrs
10000000→Dir10 fix is now nativelyqualified for this source/profile.
Expectedpages2,753,825B/map616,436B; J155,932,464+literal55,382,016=211,314,480B.
Selected3,497,697,280B/3954ranges. Processlogicalreads30,751,950,216/writes3,936,193,515B;
physicalIO/causalperformance/fullpeakRAM unclaimed. EngineC:\ProgramData\ntfs2refs\runs\4a1bad035614748a2fb5b77d649b2c00.
Archive113files328,266,646B SHA97b2e173906a5602b7baa953798c1ee52b85d7417f6f83ec923a8a14acc49475.
See evidence/paged-metadata-public1534-7feb4c0-20261102.json.

NEXT actualnewSome2paged interruption/resume/rollback. Bsource-onlyproducer
Start-PagedEnvelopeInterruption.ps1 SHA87f2e7e9c822e9f57ed7a805499b5846dae028b498e2f349b187d96cd9937481;
shared PagedEnvelopeBaselineSupport.ps1 SHA10537d42164c33bd2d5c32fa724c9529e7a16163c8aa8017f9adc69342d2cf4c.
Both NEW/no nativeexecutionyet. Actualreserveguard correctedto17179869184,
separate J8GiB/literal256MiB/combined10GiB. Aindependentreviewinprogress, Cwriting
NEW Start-PagedEnvelopeRecovery.ps1. Actualfirstwrite86 mustbeobserved/flushed,
thenrootoff/saveoriginalchilda062+flatCPreceipt withallactualpins. JSONlocates,
neverauthorizes; recovercoremustactualJ/device/lifecycle checks. Rootwillrestore
same originalindependentlyforResume/Rollback, neverclosedHND/ABTresults. Current
large success5ce is NOT that original. Useclean7feb/b0toolset/d6fullbaseline +
additional450receipt0bc. See agents forfullreceiptcontract. No oldhelper edits.
Globalproductionmarker flag remainsFALSE; no stable/tag/arbitraryscaleclaim.
Mainc6/no unit tests/keepWSL/fixed50GBepoch unchanged. Sourcea062 originalNTFS
mustrestoreONCE afterallclosedbeforefreshproducer; don'tclearprotection/replay.

## Earlier release continuation (2026-11-02 22:51 UTC)

VM fresh-confirmed Off/RAM0,32snapshots, parenta0627dbd-aa3b-4896-bbeb-495f5e372057
(savedNTFS1534source childgolden8329). ACTIVE writable branch is the FAILED
read-onlybaseline branch: F remains excluded3. Restorea062 ONCE beforea new
online freeze/baseline. No VM/build job is currently running. Root alone VMactions.

Added450directories ONLY using closedfixturebdb9bb9c2c0a44fdba275a19b00d6567,
receiptSHA0bc8de2079ed702d64e7fa43e39cc5db3948594ad84b3963e7177a12e3ad1e1d.
Savedsourcea062 beforefreeze. New8bin clean2591b5fc91bc0b6e7f011d2dd2344d16cd37c958
buildmanifestSHAa4d43cc60446fa4298bfa5a1fce4b51a332af6e57a4dd0b76d34910ade2071a7.
Baselinea6c0728f0fc741e0a403d9be992956be actuallyran inheritedfreezer3372/
1793658467612/0 thennewcapture1468/1793658468889/1 (19.4870058s). It stopped
atTree derivation: record1120 unsupportedSIattrs. Closedworker+failedbaseline
archived, no cert/J/conversion/sourcepayloadwrites. Originalce2helper committed
59142da worked/archived failures; later3precautionaryedits were saved as
.lab/development/baseline-launcher-post-dispatch-improvements.patch and helper
restoredEXACTce2 afterclosure. Do not edit frozen live dispatchers.

Newdiagnostic acc43e2 lab-inspect-frozen-record is read-only, selectedMFTrows,
fastmetadata/RAW2048 only. BuiltsourceSHA759435432ba71781103b6a2ff0dd903c7f8a863401396d1c3666808000375b7e,
exeSHA814d4f92621d34e4370cf9615cb4883c8cb62e36753144b371b4b78d95882200.
Actualprobe5028/1793659290341/0, outputfrozen-record-1120-ec24bfd3dfc34ed8893ea62a1da46884/
records.json SHA10c2c754e1543e54d836a45c8ce13cd8bfc1c9bda1f59298951ef330e981a3bb.
1120/1121 ordinarynewemptydirs SI10000000 +MFTdir +residentI30length48; root5SI6
legacy. Raw1561;109121536nativebytes/94863957streamhashbytes; nofullpayloadscan,
before/after3. Rawallocation/namespaceconsistent; diagnostic not admission.

NARROW coherent ntfs_file_attributes projection now implemented/reviewed and
4bincheckpassed15.38s: knownSI10000000 onlyMFTdir+coherentuniqueI30, targetWin32
Dir10; unknownhighuserflagsrefuse. Source/tree/nativeuser comparison shareit;
internal$Secure/$Extend observation remainscompatible. Normal80/otherlowmasks
unchanged. See docs/ntfs-directory-attribute-projection.md. Nativefix PENDING.
NEXT: commitfix, cleanbuild8bins+seal, NEW versioned directory-attribute full
baseline launcher(agentpublic_readonly_completion writing; preservece2), restore
a062fresh/start once, runfixedfullbaseline, thenNEWlargepublicadapter andnew
Some2pagedbundle recovery. Keep native-shadow/no unit tests/mainc6/WSL/fixedepoch.
Existing14ec1084nativepass+f3saved result remain valid only their actual source.

## Earlier release continuation (2026-11-02 22:14 UTC)

VM fresh-confirmed Off/RAM0,31snapshots, active saved parent
f3c1460b-6811-4dd3-908c-12cc2842c35e childgolden8329. This is CLOSED HND/ReFS;
NEVER replay its journal. No VM/build job is running. Root alone VM mutations.

Clean14ec1f8136d8b11f843b76347feb44768536d891 build7bins passed. Manifest
1fead6f5e9b5ea15a19646a2c3c68bf0aef51ce6ecc2040f6377eebab3299e0e;
sealed5role paged-tools-14ec1f8 manifest
7c40e81f62aeda5a554caae10fad22fa9698fb28e3de437573f8ab278bf92585.
Publiccaseeb251870789c45b988e167f6b4228807 native5756/birth1793656474443/0,
105.854466s including385NTFS moves5,643,501,568B. All811 independent hashes and
1084objects/fullprepmapreplay passed. ActualSome2 has1111raw/objectslots;
expected.pages1,876,145B/9pages +map.pages487,863B/9pages independently typed
verified. J137,120,208 +literal42,799,104 =179,919,312B. Processlogicalreads
26,093,083,915/writes2,382,989,259B; physicalIO/causalspeedup/fullpeakRAM unclaimed.
EngineC:\ProgramData\ntfs2refs\runs\d1741da2e123856b25d2c80fe47e0525.
Archive109files249,337,084B SHAaa0131d711ea240967791ba5d6198075b055b66f810fe1351fd00cf1e35909a9.
See evidence/paged-metadata-public-14ec1f8-20261102.json and paged-resource-metadata.md.

Retired ONLY superseded leaf results577b09be andc2a5d174 throughHyper-V after
197archivedfiles488,386,932B fully rehashed +replacement saved. Bothhostarchives
retained. f4bf/alloriginalrecoveryroots preserved. Delayedspace release closed:
lab286,930,463,472B/free53,643,284,480B; reclaimed26,776,781,471B lab and
26,772,975,616B hostfree. Fixed50GBepoch/max329374052988/min17179869184 unchanged.
Do not resurrect retired IDs from older guidance.

99fadf7 adds optional --paged-metadata fullbaseline capture: actualSome2/pages,
allfullraw+nativeEOF/security/namespace/immutability checks/noauthority; default
Some1 artifacts unchanged. Focusedcheck passed17.93s; no tests/nativecase yet.
NEWlarge-source fixture/controller/support are in progress under source-only
release_status_review agent: add450dirs only tooriginalgolden, source1534objects/
723dirs/811streams, raw~1561<=2048. Rootmustrestoregolden once theninvokeguarded
New-PagedDirectoryFixture.ps1, save source checkpoint, seal fullbaseline binary
using Build-ReleaseCandidate -IncludeFullSourceBaseline, capture explicit new
baseline, then NEWlarge public adapter. Do not run fixture against savedReFS.
After >1280normalcase, qualify newSome2pagedbundle interruption/resume/rollback.
Other public recovery originals remain; globalproductionmarker flag staysFALSE.
No stable/tag/arbitraryscale claim. No unit tests/main edits/WSL shutdown/new
persistent privileges. Mainc6 unchanged; independentwriter offcriticalpath.

## Earlier release continuation (2026-11-02 21:48 UTC)

VM fresh-confirmed Off/RAM0, parentgolden8329,32snapshots. No VM run is active.
Authenticated metadata-page storage committed/pushed1379f04. The subsequent
paged schema2 integration compiles for public CLI, native converter/recovery and
lab-inspect-paged-metadata; NO unit tests added/run. Native qualification is
PENDING; do not transfer the05c native result to this new source.

New actual held expectation.pages owner flows through constructor, protected
target proof, conversion, native readback and recovery. Objects span bounded
chunks, preserving legacy16MiB semantic acceptance with separate wire budget.
Fast recovery maps are paged; schema1JSON remains readable. Schema2budgets bind
actual complete frozen raw counts/pin, available owning handles and exact page
limits. LegacyWholeImage/full-baseline None stillchoosesSome1; allocationNone
choosesSome2. Raw2048 domain and other memory/byte/range caps remain explicit.
Actualpaged owner requiredSome2; noJSONflag can replace it. No handle batching.
Namespace scalarindexes avoid repeatedwholeobjectdecodes perchild/directory.

NEXT: finish NEW page-aware public observer controller (existing sealedhelpers
unchanged), cleanbuild/seal exact committed source, qualify fresh native
conversion then >1280object tree and independent original-state resume/rollback.
See docs/paged-resource-metadata.md. All older evidence retained. Globalproduction
marker flag staysFALSE; no stable/tag/broadscale claim. Mainc6unchanged.

## Earlier release continuation (2026-11-02 21:03 UTC)

This block supersedes all older CURRENT/LIVE labels. VM is confirmed Off/RAM0,
parentgolden8329,32snapshots after explicitstandard-profile refusal. No VM/host
build is live. HEAD05c1abd source is built/sealed; later commits are lab/evidence.
Cleanbuild r05c1abd manifestSHA8c26a1d1e6242c5d8d95f6c898c4191eca2096dc3ad58143294c99f3c007adda;
source05c1abd8e9b274cf7bd26ecaa93cb690dbd98e68. Native-marker-tools-05c1abd
manifestSHAee288bbfaa52550ca1074271a60cf8351ec94b469951823080d102ca5cb51ccc.

CorrecteddefaultDev case7868b792 PASSED native5332/birth1793652600258/0,
119.6812554s, all811independenthashes/1084objects/fullpreparationreplay. Journal+
literal184,273,712B; logicalreads28,549,568,333/writes3,285,385,657 (notphysicalIO).
ActualQUERY success16bytes/flags0x6000/zeroechoes nowKnownDev=true/Trusted=true on
shadow; independently queried SOURCE KnownDev=true/Trusted=false/flags0x2000.
No trust/filter/registry setter. Requesteddesignationmatched; HNDclosed.
Saved577b09be-973e-4823-ab10-b2d8e07d774a childgolden; NEVERreplayclosedHND.
Archive100files244,303,060B SHAd2e73c54801f71951fc4dd0abd9a3e201670c19c31ed8e704032624d19403383.

ThenFRESHgolden standardcase5a5ace3d actuallyran --target-formatstandard via
reviewednewhelperf32265c6a1e13e88079304fa1688198c6f06dbb90513b95a0fe8d362286cf429.
Native5324/birth1793653187749/1; format.comexit4 explicitlyreported
'ReFS file system is not supported on this device.' NO fallback/conversion,
FstayedonlineNTFS, no sourceprep/freeze/cert/J. ObserverReady/0 means SAFE
FORMATTERREFUSAL only; standardprofile_qualified=false, unsupported_capability_proven=false.
Don't infer universalOS/edition cause. Archive28files73,444,222B SHA
2a07de4d4bb65f1a84b17fda819a5000b2d9f42854a8066e0ffc68f740640501.
See corrected-devdrive-public and standard-format-refusal05cevidence.

NEXT realcode slice: resource-budgeted complete paged ExpectedTree/object/map
manifests endtoend through native constructor +fastverification +recovery, remove
1280semantic limit while initiallykeeping2048rawidentity domain. All counts/keys/
pagehashes/ownership handles must close BEFOREactivation; neverfeedpageddata into
old1280limitedvectors orliftconstants alone. Qualify~1500simpleobjects andboth
recoverydirections. Productionmarker flag remainsFALSE: explicit r70lab matrix
is not productionownerformat6 qualification; exactcandidate creation/recovery+
outofprofile refusal stillneeded. Standardprofile remainsunqualified here.

No unit tests/main edits/WSL shutdown/newpersistentprivileges. Mainc6 unchanged;
keep native-shadow and fixed50GBepoch; rootaloneVM actions. No stable/tag claim.

## Earlier release continuation (2026-11-02 20:48 UTC)

This block supersedes older CURRENT/LIVE labels. VM is confirmed Off/RAM0,
parentgolden8329,31snapshots after preserved13433 pre-source refusal. No VM job
is live. Host cleanbuild r05c1abd is ACTIVE unifiedexecsession51545; actualcargo
PID10024/rustc46060,29392 confirmed live. Poll SAMEhandle; do not restart on timeout.

CurrentHEAD05c1abd corrects volume-policy request-echo assumptions. Native13433
fd88f53a had API success/16bytes/flags0x6000 but mask/version/reserved0; oldreader
refused before sourcepreparation/freeze (F stayedonlineNTFS). Source/query-only
fix uses successful fixedversion1/mask6000 request +exact16bytes, rawflagsonly;
errors/short/contradictoryflags stillUnknown. Focused3bincheck passed34.38s and
independentreview passed. Failurearchive29files73,480,786B SHA05c85e95e6e0c61dd8a61ea3ff3aacfc1f5f1fd343c366263e83fb9bf7eff53d.
NEXT: seal05c build, restoregolden8329 fresh, nativequery/defaultprofile run then
standardprofile capability/conversion test. Never weaken unknown/error handling.
New--target-formatdev-drive|standard (defaultDev) and readonlyvolume_policy were
committed13433; no trust/filter/registry setter, no fallback. Actual4d source
fsutilquery confirmeddeveloper/untrusted, notordinaryReFS. Mainc6 unchanged.

Readreusef696 passed113.1028816s/publicnative5316/birth1793650872220/0 andall811
independenthashes/1084objects. Completeclosingfingerprint123,539,456B =113,623,040
actualcapturebytes reused+9,916,416 gapreads,4MiB scratch; no checksomitted or
physicalspeedupclaimed. Journal+literal186,955,512B. Savedc2a5d174-8634-437e-940d-18d93cdfb37d
parentgolden. Archive97files244,083,872B SHA11b1bbe18e71df96386ca446ebc01974c236483bd432f4ca106aa8788bb68080.

4d publicmutation/coldboot passed1084originalobjects/811independentXXH3streams
plus258newfileSHAchecks/256directoryentries; no ReFS warnings/errorssincebaseline.
Saved265b5c2c-9215-4216-bb92-896db06fbd51 childafb9. Public4d --recover fromoriginal667
then passed separateResume6080/1793648201357/0,13.9658835s andRollback6012/
1793649245898/0,8.8482228s; bothall811fullhashes. Archives/evidence checked in.
NEVER replay those HND/ABT results; originals667 (format5),8d/bfd/291c/833(format6)
remain recovery origins. HelpersCurrentPublicMutation5971..., CurrentPublicRecovery989e...
are frozen; fullexacthashes/evidence in their files/history. Rootalone VM actions.

No unit tests/main edits/WSL shutdown/persistentprivilege changes. Native-shadow
continues. Globalproductionmarkerqualification staysFALSE, scale/compatibility
remain open; do not mark stable from bounded VM evidence. Fixed50GBepoch remains.

## Earlier release continuation (2026-11-02 19:00 UTC)

This block supersedes all older CURRENT/LIVE labels below. Actual VM is Off/RAM0,
29 snapshots, saved at afb9afa4-859e-471d-8600-2ba4abb9d2dd (parent golden8329),
name r4d8-public-min-scratch-verified-20261102. No project job is live. NEVER replay
this closed HND; use original interrupted branches for recovery qualification.

Clean source4d8ca993cf660ea7430b9cc8b229553946add82b includes mandatory VSS evidence
for ALL fresh qualification policies (6f2d8a1), preserving full2pass/allocated1pass.
Cleanbuild manifestSHA5d09d4faa51afc21e2d0fd67c21b9f485ad6b0e485111a82f4801ab0a5330ae2,
all6bins/284sourcefiles/518875518B. Sealed native-marker-tools-4d8ca99 manifestSHA
77edb210f6236d3e22ec18a2f6cccd043ea0f784ec9a2041afec7be0aba3b396.

Public --drive F --partition2 --minimize-scratch case0cf3676b completed native5404/
birth1793644941535/0 in120.1092406s INCLUDING385 native NTFS moves/5,643,501,568B.
Observer Ready/0; all811 independent hashes/1084objects/full map replay passed.
Combined JOURNAL+LITERAL191,015,832B; logical process reads30,470,821,813B/writes
3,885,745,941B. Physical I/O, peakRAM and total shadow allocation are NOT claimed.
Closed97files244,310,572B archiveSHA03097395779ac04fb2cbf4a79f5e52162f279f574d1f9fad4eb9cf919bf75311.
Use archive-manifest exact routes: product metadata is in the stage archive
directory, not empty public-run. Evidence clean4d8-public-native-20261102.json.
Engine records were C:\ProgramData\ntfs2refs\runs\dd3b74cc743eab2b4b8c5a4f85f66f9b.

All4 format6 bad-peer states passed on separately sealed70c10cc: AP2 Resume17.27s,
HND2 VerifyHandoff9.264905s, RB2 Rollback9.4060466s, ABT2 VerifyAborted6.5163473s.
Each actual bad self-hash write/flush/readback+intactfirst proof was followed by
root TurnOff, same-branch reboot, NOrestore, and ordinary recovery native0.
All3 AP2 synthetic WriteFile/FlushFileBuffers/ReadFile failures exited1/poisoned/
offline, then recovered on their same branches. These are VM/failure-path facts,
not physical hardware power qualification. Globalproductionmarker flag staysFALSE.

New4d public DEFAULT/conservative VSS case517b4916 created actual snapshot01896338,
native5868/birth1793643655642/1 in3.546999s. Positive snapshot/hosted-diff catalog
refused at source-vss-catalog-before-freeze; F stayed onlineNTFS; no sourcecert/J.
Original observer Ready/1 (wrong6disk guard; actual owned empty shadow became7th).
NEW readonlycompletion ba2c2a86 Ready/0 authenticated original evidence and actual
managedreceipt/provider/GPT, no converter/VSS mutation/replay. Original failure
preserved. Archives29files10,957,214B +2files30,443B; see public-positive-vss-refusal
evidence. Only after closure was disposable VSS branch reverted to golden.

NEXT: exact-build public recovery and post-conversion mutation/reboot qualification;
resource-scale/compatibility work still open. Keep native-shadow; no unit tests,
no main edits, no WSL shutdown/new persistent privilege changes. Mainc6 remains
unchanged. Do not mark stable or flip a global flag from these bounded VM cases.

## Earlier release continuation (2026-11-02 17:49 UTC)

VM is fresh-confirmed Off/RAM0 after readback-error recovery9bd6cd42004b46c98ebc0e9ff57a671e,
with active parent8d4192fe and28 snapshots. The ACTIVE writable branch is closed
HND/ReFS, not the original AP1 state. NEVER recover/replay it again. Restore
original8d before the next independent fault. All project tasks/workers were
terminal before normal stop. No conversion or recovery is currently running.

Clean runtime70c10cc built284sourcefiles/all6bins,518875518B. ManifestSHA
e418f4a206fef25f5f03248a057b9612f5d2bb35de50f52868e5b97ac41667ed;
sealed toolsetSHA b2c4962495d0da9f477ef425f2cf5d2a49b8fd133a647f2f92613d0fc4c767f0.
Native AP2corrupt case752b1197:5068/birth1793641119368 parked after actual
badselfhash-peer write/flush/uncachedreadback +intactAP1/storage proof. Root
TurnOff then same-branch boot with NO restore. Ordinary df88 recoverya8a1e454:
5732/birth1793641287536/0,17.272784s, HND/ReFS/1084bindings, archived42files
56822707B SHAe66bb0eb90149236deaa061ca32451b7a0897f5f2865c5afe99ade9d1443126b.
Saved checkpoint2c7ff0ea-8fe8-4fe9-bce9-0a3fbb4883a1 child8d. Original fault
producer exitUNOBSERVED. Corruption/power evidence is separate from AP1 receipt.

Native AP2synthetic ReadFile error case4f526787:5556/birth1793641538060/1,
7.3740063s; actual write/flush, skippedReadFile,1117/poison/failed.json, source
offline/no success output. ObserverReady/0 means expected failure observed.
Its38file29682528B archiveSHA609f85c718e5c98ded161e249ee7684130fed79ecea1a7aa306d8d385bf18abd.
Samebranch ordinary recovery9bd6cd42:868/birth1793641614761/0,14.8922902s,
HND/ReFS/1084bindings. Its42file56822697B archiveSHA
9b9f6f2cf32bc875f11962d6d951fdd02791161ed0124afb85b3ab6dc48c8970.
No extra checkpoint retained for this reproducible closed result; host evidence
is preserved. These are actual VM/failure-path observations, not hardware power
qualification. See native-marker-ap2-{corruption,readback-error}-20261102.json.

Next: run synthetic WriteFile/FlushFileBuffers fault cases from original8d,
remaining marker-state damaged-peer cases, then final exact public qualification.
Use frozen new fault controller58884f76e2e13e1467235868b00ab52ea23f17ab704f1c6ebb758c2376857007
and unchanged df88 normal recovery. Globalqualification remainsFALSE. No unit
tests added/run. Broader compatibility/resource scale remains open.

## Earlier clean public result (2026-11-02 17:32 UTC)

This block supersedes the earlier VM and pending-public labels below.
VM is fresh-confirmed Off/RAM0 at clean233 public success checkpoint
efa60a3e-e1ca-4840-9328-2c542e44ee6b, parent golden8329, 27 snapshots.
The exact clean233 public CLI completed normal conversion on the unprepared
source: native4704/birth1793602537416/exit0 in139.0057165s including385 NTFS
moves/5,643,501,568B. All811 independent hashes,1084objects and complete native
preparation-map replay passed. Journal142,496,384B +literal43,900,928B =
186,397,312B. Logical process reads29,258,514,077B/writes3,483,167,219B;
physical I/O and peakRAM unmeasured. Observer Ready/0; all project workers
terminal before normal shutdown. Closed97files244,192,950B archiveSHA
de470b5d436ab73aa461307eaa3ea181150aa3cd3ab5e108e24a89d2fc4067f5.
See evidence/clean233-public-native-20261102.json. NEVER replay its closed HND.

The new recover-only enrolled-lab fault facility accepts only an already valid
first marker plus zero second peer, checked before target opening and at the
selected write. Corrupt-peer flips one fixed second-copy self-hash bit and parks
after actual flush/readback; synthetic write/flush/readback errors poison and
return actual Err. They are explicitly not hardware error claims. Signals are
preallocated before journal/target open. Focused3bin Windows check passed;
no unit tests added/run. Native damaged-peer/error execution remains pending.
The public production qualification flag remainsFALSE; do not flip or claim
stable release from these bounded cases. Preserve approved mainc6 bytes.

## Earlier release checkpoint (2026-11-02 UTC)

This block supersedes older CURRENT/LIVE and pending-power labels below.
CURRENT VM is fresh-confirmed Off/RAM0 at ABT1 closed-verification checkpoint
0a3a2a49-44cd-45a0-8817-41767231d7b2, parent83354c86, 26 snapshots. All project
workers/tasks were terminal before normal shutdown. No conversion is active.
Runtime7cd6870 passed all FOUR first-copy VM power-cut states:
- AP1 Resume3064/birth1793594871253/0,16.2593027s,HND/ReFS and separate original
  Rollback2588/birth1793595236914/0,11.6591231s,ABT/NTFS. Savedfccec765/44c0074b;
  original8d4192fe childpreparedcb802669. Original producer6000 exitUNOBSERVED.
- HND1 producer6104/birth1793595917550 actualcut; originalbfd2dfbe childcb.
  Verify_handoff1752/birth1793596303139/0,10.2369122s,1084maps; saved2d62e6da.
- RB1 pausedRecoverRollback5948/birth1793596998366 actualcut; original291c825f
  child8d. Rollback3868/birth1793597267167/0,9.6930208s; saved450eb572.
- ABT1 pausedRecoverRollback3060/birth1793597984026 actualcut; original83354c86
  child8d. Verify_aborted2488/birth1793598793045/0,6.7257683s; saved0a3a2a49.
NEVER replay any successful HND/ABT result; use the respective original power
checkpoint for another direction. Cuts followed actual closed/synced32KiB signal
and two matching livePID/birth/task observations. Original exits are unobserved.
These prove four first-copy/zero-peer states, not native damaged-peer bytes,
Win32 I/O-error injection, physical power-loss safety or general stable release.
Archives are closed/pinned; no extra811-stream scan or peakRAM claim. See
native-format6-power-recovery.md and per-state evidence JSONs.
ExistingPowerRecoverydf88 remains frozen. NewRollbackPause3107ef and nested
RollbackPowerRecoveryebedbc controllers passed actual RB1/ABT1 dispatch; the
nested receipts bind child->original8d->preparedcb and originalAP1 bundle/ticket,
with the new producer's own process/config/signal. No fakeexit86/freshcertificate.
User approved unchanged mainc6 capability edit; committedb87867e. Preserve its
bytes; no other main edits authorized. Shared plan-aware production gate7abadeb
keeps legacy fallback forF0/tightmarkerbudget. Backup-boot fixa545bbe reserves
final4KiB regardlessbitmap and rejects unsafeformat5/6plans beforetargetopen.
Typed storage policy1316ac9 requires production qualification from actual owned
V3 journal C4096/L512/P4096/FileStorageInfo, with explicit unqualified lab use.
The globalqualification flag remainsFALSE. Native cases above use sealed7cd,
not later source. Focused Windows builds of public/marker/composite bins passed;
no unit tests were added or run. Final exact public build/matrix, remaining
qualification and broader resource-scale/compatibility scope remain OPEN.
Latest clean candidate r233c2a3 built all6bins from283 committedsourcefiles,
517927162B workingbytes, manifestSHA
659b9534941eb950e63e912c1a0d46f56d5f7c35aac7417bc6897c8fbbaf700e;
publicCLI --help exited0. It includes the approved main, gate and two fixes.
No native conversion/recovery has run on that candidate; do not inherit7cd
native qualification. Build record evidence/clean-release-candidate-233c2a3-20261102.json.
Old clean candidate r378860e-c (283sourcefiles/6bins,517209397B,manifestSHA
cbf9c8d8b328e7a6aa8cd42e62c895ce6f40e2c6c2fc53707565bde84a1091f3) is build
provenance only and predates current source. Do not inherit its qualification.

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
- Preserve the exact approved src/main.rs bytes; do not edit, format, reset or clean them. The user explicitly authorized committing the existing capability-field removal unchanged on November 2.
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
