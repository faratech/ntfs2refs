# ntfs2refs: active handoff

@C:\Users\mfara\.codex\RTK.md

Work in **D:\code\ntfs2refs**, branch `codex/resource-based-admission`, private `faratech/ntfs2refs`. The C: workspace is stale.
This current record supersedes historical LIVE/keep/next-action claims. Prior guidance is preserved byte-exact in
[history](docs/history/AGENTS-through-20261104-aef-default.md), 22415 bytes, SHA256
`fdb24262f0c3fea3219f3c8714f0063b911a021b8af30d7b39068ba415264bd9`.

## Objective and authority

- Finish efficient in-place NTFS→ReFS, bounded preparation/recovery, useful hardware/NTFS coverage, and exact-build release qualification. The broader goal is incomplete.
- Conversion and recovery run inside the Windows machine owning the source disk. Hyper-V is lab infrastructure. Preserve the native-shadow alpha; independent-writer/GPL work remains deferred.
- User resumed and expanded the goal on 2026-11-04 to include boot/system conversion and broader hardware/NTFS coverage. Boot work is now in scope, using offline owning-machine execution and VM-only destructive qualification. Existing boot refusal guards remain until the actual offline path and native boot profile are proved; research or a switch never grants write authority.
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

## Current frozen alpha and next work

**All nine exact-aef finite gates passed. Do not rebuild or repeat unchanged cases.**
Reviewed qualification: `evidence/public-aef-experimental-qualification-20261104.json`, SHA
`d69d01b9127ad5651cc5daa18ec1a8df56cf18431059e2b91dfae74d32ae9ede`.
Verified package: `.lab/packages/experimental-aef-public-3e15ac0829db452dbbb5d9c8b4c9d7e1/ntfs2refs-aef-public-experimental.zip`,
19254647 bytes/SHA `00016d67e5580416f08a73c585c934b811fdd113d0325b24e17da9d42fda5514`.
All12 ZIP entry lengths/hashes were checked; only executable is ntfs2refs.exe. Source/build provenance and small case receipts are included.
See `docs/aef-experimental-alpha-20261104.md`, shipping README `userdocs/experimental-aef-candidate.md`,
and `evidence/public-aef-experimental-package-20261104.json`. This is LOCAL experimental packaging, no tag/publication/stable release.
The ignored qualification-aef-DRAFT.json is superseded; it must not be used for packaging.

Public low-space case **5b4f493b0824485893352829aaa2dcea passed**: actual public6036/birth1793815128501/exit1/0.0313206s
with exact working-space refusal at real C3.75GiB, before staging. Helper5764/birth1793814609118/exit0; 34 <=1GiB steps,
EOF0 reservation35592949760 bytes was closed/deleted and its guest free gain matched exactly. No product-runs namespace events.
Source preservation covers observed identity/metadata/flags and512B primary, NOT a full-partition/content rehash.
Evidence `evidence/public-low-space-refusal-20261104.json`, SHAe462be39049eec02d7b8ff29a1f38d0b46585db9827e8c31a14534e8503d6361.
Archive manifest SHAea42f3e39eb9280dffa616ff911e133773115cee277b34290c5d598c01f86d8b;76case+9wrapper files pinned.
No ENOSPC/write-flush or physical-power qualification. Earlier64MiB pilot evidence remains `evidence/eof0-64m-allocation-pilot-20261104.json`.

Low-space closure was Off/RAM0/current3343/all16 unchanged; this historical state is superseded by the latest766 closure below.
Final low-space census322362016559/free84176871424. Boot-to-close growth5337570325 fit the unchanged6442450944 forecast;
final OS-leaf postboot growth2118123520 exceeded earlier ACK samples through delayed/background growth. Samples are NOT peaks or hard quotas.
Post-package census322400526126/free84137639936; original maximum329374052988 and reserve17179869184 remain unchanged.
Operator is idle and retains exclusive VM ownership. No further native case is authorized yet.

**LATEST VM: Off/RAM0/current766/all16 unchanged**, freshly verified after orderly shutdown of the held-volume case.
Held-volume marker proof1253d2da5eaa4335a6059e9b802d39bc PASSED: native6088/birth1793816618133/exit0/0.6501192s,
one8192B SAME-BYTES WriteFile through the retained locked/dismounted/extended-DASD volume handle; flush/readback succeeded.
Fresh independent Before5364/After3320 observations matched complete GPT/C/marker state. Evidence
`evidence/held-volume-marker-interface-20261104.json`, SHA633a78c36ca987a0213ad145f5df595daf99b99bde561878628ff4ceecbb7078;
44-file/231051B archive manifest SHA43e53197658801910a26f49dad28939431818bb4d56cb6b2aacc615842da990a.
Final census317085822793/free89454919680; original cap/epoch and all16 keepers unchanged. No setter/fallback/retry was used.
This proves only that bounded same-held-volume interface; not changed-data conversion, durable exclusion or reboot recovery.
Do not repeat this completed native primitive. Saved observer/plan/build inputs remain in .lab; actual target is Partition4/RawGPTSlot4.

## Current development after the frozen alpha

Public alpha ZIP/sourceaef1ab3 is immutable. Development commitd2f880b adds measured pre-AP resource reporting ONLY:
opaque meter duplicates original FILE_READ_ATTRIBUTES outerbacking handle, thin carrier counted once, existing capture/J/arena facts;
no payload scan or writer/admission/recovery/default-policy changes. Focused public Cargo check passed0/38.7226731s using shared cache,
no unit tests or alpha rebuild. `evidence/pre-ap-resource-accounting-build-20261104.json` binds all9 changedsourcefiles.
Development9651516 now reports capture-index allocation via sameheldreadonly metadata with advisory errors; focusedcheck passed0/21.3591422s. All-stage payload I/O totals remain unknown; allocation samples are not peaks/physical usage. See evidence/pre-ap-index-allocation-build-20261104.json.
This new development code is NOT natively qualified or included in the frozen alpha. src/main.rs remains protected/unchanged.

Private-type lifecycle **9f0f38dffbbc4f0a942b01cade0f4cb4 passed**: native5736/birth1793819318534/exit0/0.9410439s,
one target-only IOCTL_DISK_SET_PARTITION_INFO_EX thenone SAME8192B write/flush/readback through the SAMElockingvolumeowner.
Only target type became b627aadb-a893-48b6-aa0b-71e5f30ee370 plus required GPT CRC changes; ID/attrs/name/extent/siblings/MBR remained.
Independent AFTER3932 matched C/control/paging/GPT/rawmarker; ordinaryGUID/T opens both error3. No automatic restoration/fallback/retry.
Evidence `evidence/private-type-lifecycle-20261104.json`, SHA22b80ce064593826f79dcd59257f5cd55bd15129a22a2118d7ecad88d08ed2fa;
69-file356723B archive manifest2146723334f97cd9323c80c398ab1bc09c39fb53e2cc5499db14a10b361bb49b.

**LATEST VM Off/RAM0/current766/all16, T LEFT PRIVATE, NO RESTORE.** Same-image normalStart withoutrestore passedreadonlyobserver904/exit0,
actualnewboot1793819671617 > original1793819256485. Both GPT copies/nativeinfo/type,Ccontrols and8192B rawmarker matched expected;
GUID/T ordinaryopens againerror3. No sourcewrite/setter/newprobe. `evidence/private-type-normal-boot-20261104.json`,
SHA846412cd48978753b759cbe6d7968f82d1d705c2c4142db8383cdc8f831e3fa6; rawreceipt4055e6bdea0c424de26588c6435d274d31999b5e815a85a341cc17aea8767ef6;
archive37d31fcc6e8e6214b633f5998bec0cec7081f7da57b31c3e48f36782ffd04ef3. Finalcensus317196549746/free89352134656.
These are normal-reboot observations, NOT complete exclusion/writer/recovery/conversion authority. Do not repeat completed primitives.

Original intent remains at `C:\ntfs2refs\partition-isolation-probe-803bb22b85044f74916d9cc6fda878c8\proposed-private-type-9f0f38dffbbc4f0a942b01cade0f4cb4\26-durable-intent-BEFORE-private-type-setter.json`,
SHAa65b10e10e8362bde31a2b662c2b89317737762d9521b2b1634a4741427de89d. Original Before439811a9e47ba33e5e2e611191c44f4a582adb45976b4f29af7785cac89a9b1b.
Retained lifecycle EXE `.lab/development/partition-private-type-probe/bin/partition-private-type-probe.exe`,571392B/SHA01fdbc2da5616adf4280b9c9d63cfacb6f7677dc44b2a7e445fee5edec4d4533;
sourcece6cfd39eb703ddde3123d12b6f6e511a71a3737eb43e916bf1d7340b27a8419,module7a12b133697ffa91dc1d9c90a4003b926a6d9876da756bd49c043b33cd9c99a8,
inputpins4377cfdd59437acabd2a81ac8b93f05b96095c1d69253f453fbe5f3a4bd8c997,buildreceipt56d74cf4f998b8d7d77117eff605f663ec6a74ff7d8c3d49008d0f8b297c09b6.
That binary was built against pre-accounting SDK; preserve it/sourcepins. SDKsourcehasnew observational changes now; don't claim oldpinsmatchcurrenttree.

Already-private RW reopen **5ba59491d9b74e0db63893453518b9b7 PASSED** after a further normalStart withoutrestore:
native5716/birth1793821158068/exit0/0.5876082s, actualboot1793821098326. Opened `\\?\GLOBALROOT\Device\Harddisk0\Partition4` RW,
validated actualheld device0/partition4/privateGPT/ID/extent pluscurrentWindows/allactivepagefiles; oneSAME8192B write/flush/readback succeeded.
No setters/offline/typechange/physicalRW/fallback/retry/restore. Independent Before/After exactprivateGPT/MBR/nativeinfo/C/rawmarker matched;
source ordinaryfile opens remainederror3, native volumealiaseserror2. Evidence `evidence/private-reopen-interface-20261104.json`,
SHA16725fc6826f74d6df2898a6bdebd1733ca24e0876b0b90a2134452affc8c2de;57-file171860B archive/all49native receipts pinned,
manifest92ee9e2097df25323bc784db04a0006eb82317b27c61e1194293ae3d3524e245. This is finite same-bytes RWinterfaceproof, NOT authenticated replay/conversion/crash qualification.

**LATEST VM Off/RAM0/current766/all16, T STILL PRIVATE, NO RESTORE**, freshly verified after this case.
Finalcensus317250100370/free89303965696; fixed50GB epoch/cap unchanged. No furthernativeGO. Do not repeat completed primitives orrestore766 casually.
Retained reopen EXE `.lab/development/partition-private-reopen-probe/bin/partition-private-reopen-probe.exe`,585728B,
SHA26bebdf9c4247e102f4ef5cca7d36badd8ea76dce7d2699cf611b3c22c189ef8; source-pinsaceb7d8c0bc202acc00bd1ac11a8d4d8cbf5f45a4cb9dcc7b02aa2c19c8902ac;
input46460a3338e4afb79ebc72a00ff026bbca72dce49a54363248a47eac1cbd200d; buildreceipt9266aac770b1f5249b9806111c5cfcf604c1fa19df1794235bd79222579c2f1c.
Built0/36.7441847s/sharedtarget/25registry rows matchroot, all120inputs revalidated; dependencycommit9651516379024dde8308e831eadd2e8e3d622aff.
`evidence/partition-private-reopen-build-20261104.json` preserves buildscope. Frozenalpha remains unchanged.

## Current SDK integration after the proved primitives

SDK foundation is APPLIED/COMMITTED asf4e737c; SDKcheckpassed0/15.3161403s,sharedcache,no unit tests orVMexecution.
`evidence/partition-owner-foundation-build-20261104.json` binds the CHECKEDfoundationcopies, notsubsequentruntimechanges.
ActualPartitionScopedOwner holdsGLOBALROOTRWfile butpublicly exposes boundedRead/Seek; stableArctoken; newprivate-type observerprofile;
pagedwriter has actualJ/index/lifecycle/OLD/NEW gates andpoisonsaftererrors. GateissuerABSENT/currentleaseunavailable, noCLIenablement.
Legacy nativebodyafterconstDEVICE andentireoldpaged_recoveryprefix arebyteexact; Rootstrippedunrelatedrustfmt beforecompile.
Foundationcommit'sCRLF-only declaration/evidence whitespace wasnormalizedin2440d7f; no legacybodybehaviorchange.

Runtimecritical-role facts are APPLIED/COMMITTED as2440d7f; SDKcheckpassed0/10.7189369s,sharedcache,no unit tests orVMexecution.
`evidence/partition-runtime-role-build-20261104.json` binds newreadonlyVDScollector andownerhooks. Actualsoftwareprovider/pack/volume
properties+flags andnativecriticalextents outsideT arecollected beforeRWopen/revalidated. Criticalboot/system/page/hiber/crash/backboot
roles mustbestable/healthy/resolved; noncriticalofflineavailability isrecordedwithoutblockingownfrozenShadow. Explicit
same_critical_roles comparescriticalbindings+inventoryidentity, rawtelemetry keepsfullEq. COMlayouts matchSDK10.0.26100x64, balancedownedreferences.
No Refresh/Reenumerate/setter/datafileIO. Runtimefacts areNOTundocumentedloaded-driverauthority andcannotissueadmission.
ConfiguredCrashControl/LiveKernelReports collector refusesunknownroutes/settings andANYnonemptyDumpFilters. Microsoftdocumented
dumpfve.sys isalegitimatenonemptyconfiguration; explicitbuilt-infilterpolicy remainsCOMPATIBILITYBLOCKER, notuniversalunsupportedclaim.
Thecollector'sruntime_loaded_dump_locations_verified remainsFALSE; no issuer/certificatecanbesynthesizedfromJSONorobservations.

UpperSourceContext ownership/read-lane slice APPLIED/COMMITTED56999d8. FullpublicCargo checkpassed0/35.0075151s/sharedcache/no units.
`evidence/partition-source-scope-build-20261104.json` bindsactualapplied11-pathsource(exceptreviewedcopylineendingnormalization).
Dedicated(default) keepsoriginalinnerGeneralFrozen pointeridentity/guardorder; Partition holdsactualowner+boxedstabletoken; complete
rawNTFSinspection/readlanes existbutremainUNADMITTED. Getter/callerResult propagation preventswhole-diskfallback. SDKlifecycleinterfaces
areexportedbuthaveNOpreparation/nativewitnessissuer; freshconstructorcurrentlyUnsupported. No CLIpartitionconversionenablement.
Do not mistake these plumbing types forcompletedsharedWindowsdiskconversion.

ActualSDKtarget-onlylifecycle/nativeROcollection APPLIED/COMMITTED9bfd25a; combinedSDKcheck0/10.9249462s/sharedcache/no units.
`evidence/partition-lifecycle-native-build-20261104.json` binds7SDKpaths inclnewstaged1180lines andpartitionnativecollector304lines.
Basic0 originalRWvolume→LOCK/DISMOUNT/flush→targetBasicREADONLY→borrowedactualnativecollect→relock→PRIVATE0→sameFileadoption.
ExclusiveexternalCintent exactlength/hash/bodyreadback precedesSET; originalID/attrs/name/extent/sibling/Cbounds preserved; Dropneverrestores.
Actualphase+preparationtoken/nativewitness guards producePartitionNtfsAdmission; noGeneralFreezeObservation/fakephysicalROstate.
Sharednativepagedcore/TxF/VSScollectionhonestlyrecordsphysicalattrs0/writable andseparatetargetRO/error19. Legacydedicatedguardsstay.
RootfixedpreLOCKTxF'serroneousGPTstyle0→1. Originalattestationpatch39d333...missingEOF LF wasrepaired inseparatec0ed27...artifact;
malformedlifecyclepatch wasappliedfromverified3sourcecopiescf654... . No nativequalification/sourcechangesintheVMforthisnewcode.
Livepre-privatecancel exists; processdeathprepare/cancelreopenandtarget-onlyHND/ABT/type/label/mountrestoration REMAINUNIMPLEMENTED.

ActualROOTpartitionSourceConstructor APPLIED/COMMITTED248eccc; combinedpubliccheck0/30.913776s, aftertinypublicationgetters0/21.2559547s.
`evidence/partition-source-constructor-build-20261104.json` binds7ROOTpaths/newresource_partition.rs. ActualborrowedROrawinspection,
canonicalXXH3metadata/extentfingerprint/coverage, backup/LogFile/label/internalindexes, raw/nativeobject/namespace/security/ACL/stream/bitmap,
TxF/VSS/quota/short-name/featuregatesallreusecompleteexistingchecks. ContextretainsactualadoptedOwner/SDKAdmission/token/arena/seals/nativepages.
Samesource/outputphysicaldiskallowsONLYactualdisjointCvolume/directorybindings; nolegacyinequalitywaiver. Sourcepublicationcallbackretainsguard,
checksactualintent/token before/after, exposingnoSourceWriter. Rootaddedsource_views_sha256()/verification_policy() getters.
NoRootCLIenablement/no targetcertificate yet; native source-preparation execution remainspending. Malformedb533patchwasappliedfrompinnedcopies
withCRLF-onlynormalization. Mainc6bcunchanged; frozenaefalpha/sourceZIPunchanged.

NEXT target/capture integration COPIED `.lab/development/partition-target-capture-draft` (author maynameactualdir differently) byfrozen_candidate_cases:
common actualsource-byte/viewadapters andactualpartitiontarget/capture/V4ResourceJournalDomain, preservingallnativefidelity andsourceprovenance.
Lowspace_case_implownsCOPIEDSDKPrivateTree/sourceenrollment/protectedtargetobservers alongsideexistingDedicatedvariant, withactualowner/admission/token.
Oneapprovednarrowquery-only readonlyduplicateoriginalFileObject witness canretainSourceROOT whilebyte-routingborrowsowner; noRead/Seek/writeAPI orpathctor.
No application/build/nativeGO forthese nextpatches. FullpreparedJ/actualsourcewriteractivation stillrequired, notanotherunadmittedstubcompletion.
Mixedrecovery observer/token APPLIED/COMMITTEDfd12781, fullpublicCargo checkpassed0/21.5630155s/sharedcache/no units.
`evidence/partition-mixed-recovery-build-20261104.json` binds3ROOTfiles. NewopaqueToken usesunchangedCOMPLETE
check_target_reader(owner,len,None,false) forMIXEDgranules/COPY/zero/sourceFree, bracketedactualpublication/artifact/locator/J/index/
lifecycle/sourceowner checks; consume_revalidated repeatsthecompletecheckandconsumesit. No writergrant. Existinglegacybodies/checker unchanged.
Partitionpublicationbinding remainsunissued untilactualversionedscope/sourceadmission iswired. No nativequalification/newVMGO.
Versionedpublication/locator scope APPLIED/COMMITTED5410dad; fullpubliccheck0/22.0742262s/sharedcache/no units.
`evidence/partition-publication-scope-build-20261104.json` binds5ROOTpaths. Missingfield→DedicatedONLY/oldserializeromitsfield; explicitpartitionv2/tag
bindsoriginalBasic/privateGUID/attrs/name/completeguardpin. PublisherrequiresactualSourceContext/admission/guard+heldexpected/maps/locator/J/arena;
scopedrecoverycanonicalheldfiles/J/index/AP-RBchecksandactualC/artifactextentsdisjointness retained. Actualretainedliveguardcanissuebinding;
NOrestart/processdeathguardcanbeconstructedfromJSON/pin. No HND/ABT/clearrawreplay; no writerCLIenabled.
NextSDK/ROOTjournalcreation/preparationcode COPIED `.lab/development/partition-native-journal-draft` (confirmactualdirectory) byaef_postcut_operator:
explicitPartitionsource/actualC-Jdisjointextents vsoldGeneralFrozen+differentphysicaldisk, reuseactualNativeSelectedJournal/scanner/quotas/OLD-NEWcapture.
NofakeGeneralownerorbroaddiskguardremoval; no apply/buildyet. Source/Capture/Writeractivation, authenticatedrestartguard andHND-ABT stillrequired.
FullAP/private-sourceactivation/versionedscope/replay/target-onlyHND-ABT and Cjournalactualdisjointextents stillrequired.
FrozenalphaZIP/sourceaef1ab3 andpublicCLIwhole-diskguards stayunchanged. src/main.rsneveredit. OperatorstillidleexclusiveVMowner;
no newnativeGO. **CurrentOff766containsPRIVATE T; no restore casually.** Lastcensus317250100370/free89303965696, all16keepers/fixedepoch unchanged.
Microsoft's [volume-OFFLINE contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddvol/ni-ntddvol-ioctl_volume_offline) blocks all volumeI/O;
private-type route avoids that dead path. Existing whole-disk guards/certificates stay unchanged.
See `docs/ntfs-conversion-policy.md` for implemented preserve/materialize/refuse semantics and qualification boundaries.
## Latest checked partition construction milestone

Development **3b42108** integrates the actual partition source through native shadow enrollment, placement,
source-backed/routed/materialized supply, full metadata completion, protected opening/closing target observations,
V4 selected capture and actual native recovery-journal creation/preparation. The unchanged streaming journal core
reads OLD bytes from the real partition owner and NEW/COPY/zero bytes from the actual protected capture.
The closed native scanner seals the real index. Dedicated guards and actual target-only General states remain.
Combined public Cargo check passed **0/22.1812068s** in the shared target; no unit tests or VM run.
`evidence/partition-target-capture-journal-build-20261104.json` binds all24 source paths and the reviewed draft pins.
Root fixed ReadSeek/inherent-byte-length dispatch, always-closing journal-domain callback validation, and conservative
full-budget metadata-witness RAM accounting. Main and the frozen alpha are unchanged.

NEXT copied code: operator owns SDK actual one-shot AP/writer activation; frozen_candidate_cases owns ROOT prepared
certificate/publication/apply; lowspace_case_impl owns authenticated restart/terminal restoration. No new native GO.
The new explicit partition critical-volume policy must use actual stable VDS boot/system/page/hiber/crash/backboot
roles and native extents, live Windows/pagefiles, configured dump routes and the held private owner. Undocumented
loaded-driver verification stays FALSE diagnostic; it must not become fabricated authority or an impossible placeholder.
Unknown/custom dump-filter settings retain explicit refusals. Microsoft documents VDS critical flags at
https://learn.microsoft.com/en-us/windows/win32/api/vds/ne-vds-vds_volume_flag . This policy still needs native qualification.
Source writer activation, process-death recovery, terminal target restoration and public routing are incomplete.

Development **8166aae** adds the actual owning source→expected pages→native shadow/capture preparation entry;
public check0/22.2874068s, no units/native run. **d747112** adds SDK-internal actual read-only protection scopes,
reuses the converted fidelity engine, and issues an opaque token-bound native observation with actual label.
Public check0/33.2102706s; `evidence/partition-owning-preparation-build-20261104.json` and
`evidence/partition-converted-readonly-build-20261104.json` bind those source versions. Terminal guard issuer was
still pending at that commit. Root never added unsafe Sync to lifecycle owners; parallel object reads capture mode only.

Development **fd9af7c** APPLIES/COMMITS actual SDK fresh AP patch0a848312... and MIXED replay patchbd8797ae...,
ROOT prepared certificate/publication/AP patch7b0bb527..., Root execution-aware domain/orchestration,
and known built-in `dumpfve.sys` configuration support. Unknown/custom filters still refuse; loaded-driver diagnostic stays false.
Combined public check passed **0/22.5527078s**, shared target/no unit tests/no native writes or alpha rebuild.
`evidence/partition-ap-replay-terminal-build-20261104.json` binds all18 source paths. Root applied the author-frozen
41406-byte terminal snapshot SHAbe29ec6c62a9acaab0933ce5bdc53a751b8fed69240a91fa168e63dfcf447884, corrected
three length/Path compiler sites, and qualified one retained-map comparator call. Terminal BasicRO auth/SET/native observation
exists; attrs0/label/mount finish, fresh live-handle transfer, preAP cancellation and ROOT restarted MIXED orchestration do not.
Root owns `resource_partition_preparation.rs` and `resource_partition_target.rs`; do not overwrite their new
orchestration/execution changes from old draft bases. SDK AP/HND is actual code, but public CLI shared-disk routing remains disabled.
Terminal finish code is now applied/checked: author patch5ec43cfe..., source54729B/SHAee5ae23e..., publiccheck0/32.6135023s.
`evidence/partition-terminal-finish-build-20261104.json` binds HND native fidelity/ABT OLD+NTFS identity, single targetattrs0 setter,
actual original label readback and nonstealing mount restoration. No native qualification or public routing yet.
Lowspace next owns separate narrow actual Origin extraction for restart plus fresh-live ownership transfer; no preAP fake evidence.
Frozen_candidate_cases is implementing a separate actual ROOT restart/MIXED path with authenticated origin files and SDK mixed gate.
Operator owns the actual next VM helper. Readonly plan `.lab/development/shared-windows-tail-target-readonly-plan-20261104.json`,
SHA99b35db153de5887f3de6a42fcbc14c8bfdb8dde6d62b2f56a8da257eca5fa88: current oldT is followed by WinRE,
so do not extend it. A new tiny differencing OS child can grow64→120GiB and host a NEW52GiB tail target at64GiB;
old private T/WinRE/all16 keepers stay. Planning6GiB census317281799539/free89266679808 admitted, but remeasure at actual GO.
No VM mutation has occurred. Do not restore766 or repeat primitive tests. Actual current source support is512-byte sectors,
**1024-byte MFT records**,4096-byte indexes; other MFT sizes/4Kn remain outside this implementation.

## Recovery and verification invariants

LATEST AUTHORITATIVE VM is now **Off/RAM0/current07ca22f3-bb1c-444b-8f31-ff16b1fcb521/all17**.
Prepared shared-Windows source: disk0 GPT1f804918-e98f-4a71-9022-fc00c3cb7c26 now120GiB; NEW partition6/rawslot6,
GUID4310d74c-614f-435b-9cf1-7ff664391590, offset68719476736, length55834574848, D:, NTFS4KiB/1024MFT/4KiBindex,
serial DECIMAL STRING7092616291886350003, volume GUID matches partition GUID. 8files67178865B/4directories independently
hashed/native IDs/lengths/owner-group-DACL matched; residency UNPROVEN (73B reports Allocation80,211B→216).
One NEW checkpoint07ca parent766 preserves all original16; no converter/probe has run on this source.
`evidence/shared-windows52-source-baseline-20261104.json` binds full56-file324739B metadata archive and exact receipts.
Closure7d6527c5..., oraclecb840325..., archivea54c94ee... under `.lab/hyperv/streaming-v2-20261027/shared-windows52-92c6ff5747c34c7db94931be9bd4a95b`.
Original private2GiB T and WinRE stay unchanged. Current120GiB OS child is `os-shared52-0f4193296ed740d9add19db9ee364faa_104F354A-1FF6-4F00-B8F2-61940F826DCB.avhdx`.
Before resizing, only932184064B oldOSleaf was copied to an ordinary .vhdx SIBLING; originals and parent chain were preserved.
New-VHD refused .avhdx parent beforeboot; later wrapper boot-scalar/ExitCode and false resident checks failed honestly, no reformat/rewrite.
Read-only completion fixed the oracle; Windows PMBR0xffffffff matched original and was not rewritten to invented disk-1.
Final census318595964757/free88805801984; original globalmax329374052988/min17179869184/50GBepoch unchanged.
Setup whole-case7GiB baseline317283309397, actualgrowth1312655360; this is not a new global epoch.
Operator remains exclusive VM owner and is idle; next full conversion needs fresh capacity/build/GO, no automatic restore/boot.

New development2759b65 checks actual reopened Origin and consuming terminal owner transfer, publiccheck0/34.5149335s;
evidence/partition-recovered-origin-build-20261104.json. Current UNCOMMITTED slices: SDKfresh live terminal0ec3f1d6...,
ROOTrestarted resume/rollback77fb15f3..., ROOTnormal finalization0fd62f62... applied; combined checks passed before latest tiny fixes.
Root added duplicate_locator_file() using actual readonly same-FileObject duplicate; never reopen the share-zero locator/J/intent.
Root fixed original RW lifecycle and each RO raw source handle with FSCTL_ALLOW_EXTENDED_DASD_IO90083 (same held handle), pending finalcombinedcheck.
Root exposed observe_basic() single complete Basic metadata observation for bounded publication waiting; it grants no writer.
Lowspace owns COPIED small publication-wait fix, frozen_candidate_cases owns COPIED actual guest alpha execution facade/bin.
No new unit tests, no main.rs edits, no new public shared-disk CLI enablement; frozen alpha ZIP remains unchanged.

SUPERSEDING CODE STATUS: **c4953652a1c8c3620f76e6e4b9dd4c13c8b1862b is COMMITTED/PUSHED** with all preceding fresh/restarted/finalization/wait slices,
actual 90083 handle fixes, observed Basic metadata wrapper and actual owning-machine `lab-partition-alpha` facade/bin.
Both public and lab binary checks passed **0/22.7642619s** in shared target; no unit tests. Evidence
`evidence/partition-owning-alpha-entry-build-20261104.json` binds all15 source files. Root corrected mutable restarted locator,
public terminal enum import/text serialization and facade placement-submission bound. This is code/check evidence, NOT native conversion.
Exact committed lab build is ACTIVE in host exec session8897: `.lab/development/release-candidates/partition-alpha-c495365`,
log `.lab/development/partition-alpha-c495365-build.log`; builder2df7a454.../shared-source helper842c5e7f...,
4jobs/shared target+staging/2GiB working allowance, dependencies retained. Do not start competing Cargo/build jobs.
`partition-alpha-c495365-build-admission.json` is the fresh all-lab/cache/staging admission. Inspect actual terminal/manifest before use.
Operator is preparing the first NORMAL actual conversion helper on Off07ca/all17; it is NOT yet authorized to run a converter.
Runner parameters: `--request <JSON> --request-sha256 <exact> --output <fresh> --acknowledge-disposable-source-conversion`.
It must run INSIDE guest and actual native source/admission/certificate controls all writes. No fixture count/geometry whitelist grants authority.
All currently pending code drafts have been applied; frozen_candidate_cases and lowspace have no canonical edits assigned.

BUILD CLOSED: exactc495365 `lab-partition-alpha.exe`8378880B/SHA8557aab0872e63a070826e51e1c3c0347074b96c64862efdc18247acc73f5955,
manifest3ae771f01aa46438ac2f3eb9c2b9ff291e74225d1ffb0a5cb2d3844baf225a2b, tree674b4e6c1dc67308097df367f48686adf6a23996.
SourceZIP2027983B/SHA1d72ad78b9055823872ed1f9b2cdbbff07eb64e98e941f4219119bbe9470b726; all413 held source files verified before/after,
no working-tree inputs/no units/native. Host session8897 is TERMINAL0, Cargo2m30s, one shared target/staging, own packages rebuilt/dependencies kept.
`evidence/partition-alpha-c495365-exact-build-20261104.json` is the small checked receipt; no native qualification inherited.
Next: operator preparing actual normal-source conversion helper with literal pins, Off07ca/all17/fresh6GiB forecast; converter GO still pending Root review.
Focused review found no additional inevitable blocker after90083 and bounded-publication fixes; actual VDS/remount behavior still requires the native run.

SUPERSEDING NATIVE HOLD: c495365 exact executable is built but MUST NOT run yet. Focused review found inevitable128-NativeEvent
accumulation in nested partition J creation (16 source-owner checks) and opening protected target observations.
Confirmed target sequence reaches127 before required RO SET/attribute read, so it fails before native collect; don't spend a VM run proving it.
Frozen_candidate_cases is implementing COPIED actual guard Rc/RefCell observer sink, durable admission bookends and witness start/end drains;
lowspace_case_impl coordinates only nonoverlapping target/private-tree drain call sites. No larger cap, dropped events or removed checks.
Actual durable drains must run BEFORE lower target RO lease/setter and during nested J bookends, not merely afterward.
All canonical code remains c495365; next fixed committed build will supersede the unexecuted candidate. Source fixture stays Off07ca/all17.
Operator's next helper must accept externally pinned build inputs for that fixed candidate; no converter GO has been issued.

EVENT FIX APPLIED/COMMITTED/PUSHED **82a6095f07672713cbe4c9bb4ff15de9fd2dd651**: SDKsink15fb3db3... + callerdrainsfe0ce05f...,
all7sourcepaths; lab+public check0/32.5559411s, no units. `evidence/partition-native-event-streaming-build-20261104.json` binds them.
Actual guard Rc/RefCell observer sink drains admission/witness/enrollment/privateTree/target bookends before buffers fill;
all source/target checks and128-event ceiling remain. c495 executable stays unexecuted/superseded, not a qualification artifact.
EXACT FIXED BUILD ACTIVE host session12296: `.lab/development/release-candidates/partition-alpha-82a6095`, log
`.lab/development/partition-alpha-82a6095-build.log`, source82a6095,4jobs/sharedtarget+staging/2GiBfreshadmission.
No competing Cargo. Operator's FIRSTNORMAL v2 launcher is frozen `launch-partition-alpha-first-normal-v2.ps1`
SHAbede19c4034ec4dde797d27798a7e23a31f3b635c5649a27f8e1efa9493b2c29. Root reviewed its earlier full body;
v2 only excludes capture literal/backing payloads from metadata copies, preserving old11333f55... launcher.
Worker279e023175432f0b7af04b27153c9e77400862cfb567587e4834f426880f0e22,
oracle3d7c1b325c217e5ab08d19341edd7b0aa8c01a686cde112c21ddf063a59e8c6a,
readonlymetadata40e8c1719c0bc21255f4aafe7119a937eb7e9df0bdf695c76b6081323b6f9383;
all AST0, requestextent_identity_v1, actual SYSTEM child PID/birth/exit, independent8file content/namespace/owner-group-DACL+Refs oracle.
Build pins remain mandatory external params. Root must verify finished82 build/EXE manifest and issue exact one-run GO; VMstillOff07ca/all17.

FIXED BUILD CLOSED0: source82a6095/treeb90382a22efd0fcc0fc44336658cd5f064f2c58d,
manifest41deea20b99616febdbbacfb64b0a11ebba3cf4078fd09221735811f4ba78f1f;
labEXE8452096B/SHA2fedc80084654d472fd1464697a6bbd50aebbc7ae416df8d36b98d6134b14dcc, actual host rehash matched.
All413 held source files unchanged before/after; no units. `evidence/partition-alpha-82a6095-exact-build-20261104.json` binds build.
ROOT ISSUED ONE FIRSTNORMAL CONVERSION GO to operator with reviewed v2 host/worker/oracle/support pins above,
fixed82 manifest/EXE/source pins, fresh6GiB/currentOff07ca/all17 admission and exact source baseline required first.
Only inside guest/SYSTEM one actual conversion; no restore/repair/replay/retry/checkpoint mutation. Operator owns actual PID/birth/terminal/archive/oracle.
No native process/phase/success may be inferred from GO or task readiness. Observe actual operator messages for current state/run ID.

LATEST ACTUAL NATIVE FAILURE (supersedes earlier Off/no-launch claims): VM is Running4GiB/current07ca/all17 on same boot1793834127817.
First e404c2432387423dac5c48c18bde8ada wrapper stopped BEFORE facade because WindowsPS5 ANSI decoded baselinelambda asmojibake.
Readonly diagnosisb17bc744... confirmed strictUTF8 names matchall8; no source mutation. New sameboot UTF8 continuation retained
original6GiB baseline318555490477/absolute324997941421, no allowance reset. Root reviewed exact host7690cb9d...,
worker60d47f4e..., oraclea4a57540..., unchangedmetadata40e8c171..., same82manifest/EXE and issuedONE first-native GO.
Actual continuation e174633147f143d69cac9c525aa2bf35/native4624/birth1793834517548/realOSexit1/1.8636351s.
Actualstdout: readonly-source-route-and-resource-admission→fresh-owned-devdrive-shadow-formatted→partition-preparation-basic-baseline.
Actualstderr: IVdsVolume::GetProperties HRESULT0x00042715 (VDS_S_PROPERTIES_INCOMPLETE), before source protection.
Readonly closure `.lab/hyperv/streaming-v2-20261027/partition-alpha-first-normal-e174633147f143d69cac9c525aa2bf35/readonly-after-native-vds-refusal.json`
SHAdbe2ab8918a122a311273ecfbed78a1aa751e0800e876534ecebf52cf29d9579: native+workerabsent, source6Basic0/healthyNTFS,
all6 GPT/header/MBR/native144B/Ccontrol unchanged, partition.intent EOF0, selected.journal absent. Fresh DevDrive provider remains
attached/preserved, backing104857600B; no automatic retirement/repair/replay/source setters. Operator retains exclusive VM ownership.
CURRENT NEXT: operator preparing READONLY VDS row diagnostic (HRESULT+raw properties for each same COM object), no diagnostic GO yet.
Frozen_candidate_cases owns copied diagnostic/error-context work; lowspace researched partial-success policy and is idle.
Microsoft GetProperties has NO per-field validity mask. Never accept partial flags0 as noncritical/complete role proof.
Minimal possible handling: partial is UNCLASSIFIED; resolve same VDS object's native path (MF3 QueryVolumeGuidPathnames if needed),
require complete native extents ALL outside target, bracket identity/returned properties; unresolved/target overlap refuses.
Partial rows cannot establish positive boot/system coverage. Diagnose actual fields first; don't weaken guards or rewrite fixture.
https://learn.microsoft.com/en-us/windows/win32/api/vds/nf-vds-ivdsvolume-getproperties

LATEST READONLY DIAGNOSTIC: first26829e18c8074225ae9c047bb6bf08b1/PID2724/exit0 yielded0rows/QIerror due two
C# transcription IIDs SOFTWARE+VOLUME; originalf072... script+receiptcbc76ff7... preserved. Converter's canonical Rust UUIDs were correct.
Root+operator mechanically comparedall6; NEWv2scriptSHA87e3f7f4b887bb52e3811ba266c198955e9a3a569b02fcebb12c1a1f565a3417 differsONLY2GUIDliterals,
RootissuedONCEreadonlyGO. Actual1b66341fdfcf4627b8a0c15b98c40283/PID1924/birth1793835455033/OSexit0/1.7632408s,
7rows/noerror. ObservationSHA7ebc4450fd339df6b7bd019d7ebbb873ef0361207abb6b3b9c0976fa25907acb;
archive `.lab/hyperv/streaming-v2-20261027/vds-properties-v2-1b66341fdfcf4627b8a0c15b98c40283/closed-manifest.json`
SHAe9d3e8885103f4abfd7efa6206c046aef174d5d6871240536c4cab5d83c8eb6f (8files37359B), no source/storage/setter/refresh operations.
ALL7opening+closing volume property calls return0x42715 with stable rawnonnullnames/type10/status1/health1/transition1/recommendedFS4.
C volume588644bf-d154-4b1f-8a9f-e740e832c045/GLOBALROOT HarddiskVolume3/64091062272B/rawflags0x008986e2.
No VDS systembit1 row exists (EFI not in this legacy software-volume enumeration). Thus even the old positive SYSTEMcount gate is impossible here.
Do NOT promote partialflags0 to safe, nor merely allowoutsideTpartialrows and assumeT/coverage solved. AllrowsincludingT canbepartial.
ROOTDECISION: implement documented named policy using ACTUAL MSFT_Partition IsBoot/IsSystem rows bound to nativeGUID/disk/extent,
direct currentWindows/EnumPageFiles/configuredDump extent checks, actual same-original-file successfulLOCK (rejectssystem/pagefile),
persistenttargetRO/private exclusion. Loaded-dump-driver diagnostic remainsFALSE; never claimundocumentedkernel-stateproof.
Lowspace_case_impl owns COPIEDNEWnative `partition_storage_roles.rs` boundedreadonlyCIM/WMIcollector (prefernativeCOM, notPSspawnperrevalidation).
Frozen_candidate_cases owns COPIEDSDK owner/lifecycle/witness/restorer integration replacing impossible completeVDS/count gate;
retainVDSpartial rawproperties asUNCLASSIFIEDdiagnostics ONLY. Unknown required CIMproperties or nativebindings stillrefuse.
Primary: https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-partition
OperatorROOTAUTHORIZEDnormalOffclosure afteractualprocessesabsent/tasksidle tofree4GiB, preserveall17/current07ca/provider100MiB/sourceBasic0.
No new converter/source retry authorized. ObserveactualoperatorOff/censusreceipt; do not infer fromthisinstruction.

LATEST VERIFIED VM is Off/RAM0/current07ca/all17; normalOffclosure e174/closed-off-vds-refusal.json
SHA8680642f581e6fb922015d939c06a2757a90462551e878322a0889e18251e3b0, compact67file542082Barchive
closed-off-small-archive-manifest.json SHAc352c4050c7f8b0636cc8cbc81856f18074a92a5852cfa9e3aaba9d7ddda6e00.
Native1924/4624/workersabsent/tasksidle; sourceBasic0NTFS/intentEOF0/noJ/owned100MiBproviderfilepreserved. No extra power/reset/detach.
Final census319661185528/free87719960576; original FIRSTNORMAL6GiBabsolute324997941421/remaining5336755893, globalcap unchanged.

CIM POLICY CODE APPLIED/COMMITTED/PUSHED **8f7db1e50003b649098f635199d923bbaf016fcd**:
collectorfd78e85e... + integrationcbec99fc...,7SDKsourcepaths, actual native COM/thread-local connection/two NEW bounded catalogs,
direct native GUID/device/extent and typedBoot/System fields, no PowerShell child. C/critical bindings exact; private missing row remainsNone,
never fabricatedfalse. VDSpartialdiagnostics unclassified/optional; all direct Windows/pagefile/configuredDump/lock/private/GPT checks retained.
Lab+public check0/32.910964s/no units, evidence/partition-storage-role-integration-build-20261104.json binds code/docs/research evidence.
Exact committed source8f build ACTIVE hostsession32587, `.lab/development/release-candidates/partition-alpha-8f7db1e`,
log `.lab/development/partition-alpha-8f7db1e-build.log`, fresh2GiB all-lab/cache/staging admission, sharedtarget+staging/4jobs.
Do not compete with Cargo. No converter GO for8f yet. Operator prepares OFF07ca17 normal launcher using correctedUTF8helpers and
mandatory newbuildpins; preserveold82failurereceipts/provider/source, no source replay/restore/repair/delete.

8f BUILD CLOSED0: source8f7db1e/tree8d0f75cfec71e9d7281b2f305472e4113472a3d6, manifest6e206e626dc6b4e5fede9960d8c045e678ff21ad88e84b75dc8575b72a533160.
EXE8482816B/SHAb2b703ed51d1a696da50746d90ab4b3fc7d698e47f89b79c9c855b3589e1f9b4 (Rootfreshrehashmatched),
sourceZIP2037182B/SHAea17a243e925332f7db112296e6cdf5c838e2e4253c7438f00470e2780aa4d77;414sourcesheldbefore/afterverified; no units.
Smallreceipt evidence/partition-alpha-8f7db1e-exact-build-20261104.json. Hostsession32587terminal0, no build competing.
ROOT ISSUED ONE actual normal8f conversion GO to operator using Offv4hostbdfa8925... +UTF8worker60d47f4e/oraclea4a57540/support40e8c171,
fresh6GiB fullprogramme admission/Off07caall17/actual source8filebaselinefirst, mandatorybuildpinsabove. No newsourceprep/restore/repair/replay/retry/extraCP.
Native launch/phase/success mustcome fromactualoperatorPID/birth/terminal observations, notfromGO. RootdoesnotcompeteVM.

LATEST ACTUAL8f attempt72394fdbfa684136921b57da7af9ff1f: actualnative2304/birth1793836791495/boot1793836749023,
OSexit1/58.6320047s. Accepted nativeCIM baseline, then stdoutrevalidate/critical-role-check; stderrdevice-not-ready21.
LOCK/DISMOUNT/90083 succeeded in ledger. Lastcriticalrolebatch14successes ends nativeGPT/activepagefileextents; failedoperationitselfunflushed,
do not attribute OSerror21 to a specific ioctl from absent evidence. SourceBasic0NTFS/native144B/all6GPTheaders+entries+MBR/Ccontrol unchanged,
intentEOF0/noJ. Readonlyreceipt72394/readonly-after8f-critical-role-refusal.json SHAe294cf920bb4a6d7ae3d0e0cb5470ae1285e228eaf5c843561ce80d56d2a95af.
NormalOffclosed `.lab/hyperv/streaming-v2-20261027/partition-alpha-first-normal-72394fdbfa684136921b57da7af9ff1f/closed-off8f-os21-refusal.json`
SHAd399dd4a282aa2b2746a42b3ac818e69d66ac8efc96819a3ac5e592985434ae7; separatefreshOff/RAM0/07ca/all17.
Compact34file328416Bmanifest closed-off8f-small-manifest.json SHAdc0a15d2a8c727224b0224bdb430469bbefe5afc3439aca5805635ea64dafb56.
Both100MiBproviders retained, no detach/delete/source repair/replay/restore/extraCP. Finalcensus320112978875/free87227400192;
8fcasebaseline319680684332/absolute326123135276 unchanged, remaining6010156401. OperatoridleexclusiveVMowner.

LOCK COMPATIBILITY FIX APPLIED/COMMITTED/PUSHED **353ce917efa5cfbb08ff7cbd7fdf517d3e55d059**: singlecollectorpatch8380e469...,
source28737B/SHA2b358b529f1e08349dcf34a1546230992cb4254a8e43ff37370427794161c4f5. SourceSelected query no longer opensNEWGLOBALROOT
volume whileoriginalFileLOCKED; readonlyPhysicalDrive DEVICE/LENGTH/fullnativeGPTlayout selectsuniqueGUID/number/extent and exactbeforeafterlayout.
CurrentC/critical/nativeWMIchecks unchanged; othermetadataopens nowinclude exactNativeEvent/path/OSerrorcontext.
Lab+publiccheck0/32.8696308s/no units, evidence/partition-storage-locked-target-build-20261104.json. No staged signature change:
its optionalSourceGUID reopen captures21 asunavailable; originalRWFile stillchecks identity; later freshopens onlyafterUNLOCK.
EXACT NEW BUILD ACTIVE hostsession57244 `.lab/development/release-candidates/partition-alpha-353ce91`, source353ce91,
log `.lab/development/partition-alpha-353ce91-build.log`; fresh2GiBprogrammeadmission/sharedtarget+staging/4jobs, no competingCargo.
OperatorcanREUSEunchangedOffv4hostbdfa... (externalbuildpins) with UTF8worker60d47/oraclea4a575/support40e8 once353buildclosed.
No converterGOfor353yet. Verifyactualmanifest+EXE+sourceclosure thenRootone-runGO; VMstillOff07ca/all17.

353 BUILD CLOSED0/source353ce91/tree4e845f22877b1b826cf6eac2f263fef48037053b,
manifest18bdf733893703750f80a5cebe12565ead640c44679f36942c86dc71c57a3230;
EXE8483840B/SHA87d62d1c48e3b93e96f72ec00e9ba4f00950c4ae83071ed5b79682f851863afd freshRootrehashmatches,
sourceZIP2038129B/SHAf9ac9ff9bf5a9f29a018456b7d6a274dc503d55943cf3b986ab1b0b91d74a9f0, sourcebeforeafterverified/no units.
Host57244terminal0/Cargo2m31s/sharedtarget+staging. evidence/partition-alpha-353ce91-exact-build-20261104.json.
ROOT ISSUED ONE353normalGO tooperator withunchangedOffv4hostbdfa/UTF8worker60d47/oraclea4a575/support40e8 +exactnewpinsabove,
fresh6GiBwholeprogrambudget/Off07ca17+actualsource8fileBeforefirst. NoSourceprep/restore/replay/repair/retry/providerdelete/extraCP.
ObserveactualoperatorPID/birth/exit/ledger/sourceclosure forcurrentstate; GOisnotdispatch/success. RootdoesnotcompeteVM.

LATEST353REFUSAL SOURCESTATE: readonly-after353-budget-refusal.json under312a85f20de64c9686412f17862c9d4e
SHA7deb14bfddffd9be27287de75d7bdf9e299842146c247ad60993a842e3577554 confirmsstillBasic0NTFS/attrs0/native144/allGPT+MBR+Ccontrolunchanged.
IntentvalidONE41745Bframe/41785Bfile, kindpartition-target-only-pre-AP-intent, seq1/stageBasicLocked/currentBasic0/desiredBasicRO1000.../APfalse.
No SET/J/root-source artifacts. PID5144wasREUSEDWmiPrvSEbirth1793838218142; originalnativebirth1793837836992 absent, no kill of reusedPID.
NormalOffclosure312a/closed-off353-control-budget-refusal.json SHAbdecbe792ad2440670557642676983c299ab75a6ef68b02d9d7a753b95c1da37,
freshOff/RAM0/current07ca/all17 exactgraph. Compact34file463534B closed-off353-small-manifest.json
SHAad4d10d34cb35cc335e2768388362275a13e58b0d1a5a00ae4f4bad2b9f25aa2; no VHDX/payload duplication/deletion/checkpoint/restore/retry.
Finalcensus320355457013/free86985396224; original353case320131802392+6GiB absolute326574253336 retained, remaining6218796323.

ACTUAL DETERMINISTIC BUDGETMISMATCH FIX APPLIED/COMMITTED/PUSHED **ed7f16c0c4e1f2ca02d9412f94a1c9c1434e1fde**:
staged firstSET constructed120B butgenericcontrol rejectedinputs>64 BEFOREDeviceIoControl, matchingintent/noSET actualtimeline.
Typedpatch288f470f... changesonlynative.rs/staged/restorer: fixed &[u8;120] GPTSET SDKcontract/zerooutput/headerpadding+compiletimeABIchecks.
Generic64Bceiling unchanged; same nativecall/auditbody and source/intent/GPTguards. Futurebudgetreject namesoperation/code/input/output/eventcount.
Lab+publiccheck0/32.6221558s/no units, evidence/typed-partition-setter-build-20261104.json. No speculativeeventcapincrease.
Exact ed7 build ACTIVE hostsession16531 `.lab/development/release-candidates/partition-alpha-ed7f16c`, log
`.lab/development/partition-alpha-ed7f16c-build.log`; fresh2GiBallprogrammeadmission/sharedtarget+staging/4jobs, no competingCargo.
Exact ed7 build COMPLETED: hostsession16531 actual exit0, Cargo release146s, 414 held source files unchanged.
Manifest9d08fdca42763acf264d347cb17fc25b2a4474174c70d9d6efd103448deaf1ba;
lab-partition-alpha.exe8486400B/SHA0c98bc0dbc667d4d47eff48ebeee565b8ee2790a6edf46d3af15201c63046e25.
Root issued ONE normal-run GO to exclusiveoperator using unchanged reviewedOffv4/UTF8helpers and exact newpins,
conditional on fresh6GiB allprogrammecapacity/Off07ca17/sourceoracle. No restore/prearrangement/repair/retry.
Evidence: evidence/partition-alpha-ed7f16c-exact-build-20261104.json. GO is not dispatch or success; await actualPID/terminal.

LATEST actual ed7 case b55da9f289b246bcae9c4e064ea3d83a FAILED stack overflow: PID4528/birth1793839020507,
owned exit255/237.0301935s. First typed GPT SET actually succeeded. Source6 remains BasicRO(attrs1000000000000000),
one valid41785B intent, no J/publication. Raw GPT proves only targetRO+requiredCRC changes; siblings/MBR/C unchanged.
NormalOff/RAM0/current07ca/all17 verified; closureSHA5f0e584fbf5d96bfe76f098913615469aa7e7cf19c33a2e5242576e83c6ee03b.
Census320528532918/free86836535296. No restore/repair/replay/delete/newCP. Existing WERc00000fd/RVA00659c07 resolves __chkstk+55.
Measured PE mainstack1MiB and four nested exact frames589136B before other callers/callees; no recursion found.
Root applied lab-only explicit8MiB worker stack,9MiB execution-stack budget charge; focusedcheck0/32.0424673s/no units.
Evidence evidence/partition-alpha-ed7-stack-overflow-20261104.json. Fixed exact binary/native qualification still pending.
Operator completed ONE Off failure-branch checkpoint3cbfd35b-b442-467e-a9e6-3f38ce3bccb1 thenONEbaseline07ca restore.
FailedBasicRObranch preserved; freshOff/RAM0/current07ca/all18/dependencies closed, receipt16badd6b1758a71dbe6c1a6ed52a6a6604e627fde79b645a93c2f40a7f80619a.
Never manually reset current BasicRO attrs from missingJ/noAP inference. Existing full-intent-only crash cancellation remains unsupported.
Root also applied minimal terminal observer drains: HND/ABT previously could accumulate137/138events before drain against128cap.
All checks/settercount/cap unchanged; complete metadata bookends now durably streamed, including change success/error.
Combined lab/public focusedcheck0/27.7569929s/no units; evidence/partition-terminal-event-drains-20261104.json.
Fixed committed source88937b76af5bfd62061c26bdb5addbe206798d67 exactbuild58900 COMPLETED exit0/release153s/414sourcefiles unchanged.
Manifest77cc9e32154e381e0440d71d90cfbf63fa43d1db8ed517b338685a79338cd5b0;
lab-partition-alpha.exe8500224B/SHAdf4e2a5e9b6609aaf4690c7eac1463d5a8c94db0e5224e8db188e53c1111661b.
Operator authorized ONE OfffailedbranchCP3cbfd35b-b442-467e-a9e6-3f38ce3bccb1 (actualcreated/proved) thenONErestore07ca;
after closedOff07ca/all18/dependencies/fresh6GiB/sourceoracle, separate conditional ONE889normalrun GO uses exact18graphhost0955db0c...
No sourceattrs repair/rawreplay/automaticretry. Operator alone owns actualoperations/results; do not infer closure or success from GO.

AP/RB recovery executable wiring now APPLIED/CHECKED, not natively qualified: lab-partition-recovery request+independentSHA frontend,
actual privateowner/open_restarted/MIXED replay and owning terminal transfer; HND native readonly knowncontent+allmaps then writable,
ABT closedOLD+readonlyNTFS then restoration. Real owned event sink and8MiBworker/9MiBcharge. PreAP process-death cancel still refuses.
Focusedcheck0/31.4494306s/lib+bothlab bins/sharedtarget/no units. evidence/partition-recovery-entry-build-20261104.json.
Initial copied-source mtime staleSDKcheck failed; source-only timestamps refreshed, SDK recompiled and passed; no cache deletion.
New recovery code is not in fixed889normal EXE or frozenpublicalpha. src/main.rs unchanged. Exact recovery build/native cases pending.
Recovery code committed/pushed b2e96ff189f8ee9b857384d7243ba23a3f6f8b10. Exact recovery-onlybuild ACTIVE host89710,
`.lab/development/release-candidates/partition-recovery-b2e96ff`; sharedtarget4jobs, freshJOINT8GiB admission covers2GiBbuild+6GiBVMforecast.
Initialjointactual320602547152/projected329192481744 withinunchanged329374052988/reserve17179869184; no cap/epoch reset.
Fixed889 ONE normalcase39f87845eeaa4e2fba2606d68c91ac0f host19065 ACTIVE underexclusiveoperator.
Fresh6GiBadmission passed; VMRunning4GiB/current07ca/all18. Wait actualpreoracle/nativePID/terminal; dispatch is not success.
Exact18graphhost0955db0ccd5e11700dca2b0e2eae99a9bdf012c914f3f6576fe49873b653406f with actual3cb failedkeeper mandatory.
Actual889nativePID2948/birth1793840555672/boot1793840512480 nowRUNNING, preoraclefull8 matched actualrestoredNTFS.
Recovery exactbuild89710 COMPLETED0/release156s/416heldsourcefiles unchanged; manifest3fb24f741bc32b2ee8588babb3128647d87dea91a71124f8438f2e45b1c5cde1,
lab-partition-recovery.exe3852288B/SHA9ba0f7eafa7219998c5891fa7f4ec838235032dc7f658c6581a6bd9ea501aa68.
Evidence evidence/partition-recovery-b2e96ff-exact-build-20261104.json. NO recovery-nativeGO yet; normalcase remains first.
Current889 apply has no signal between firstnon-discovery sync/readback and discovery0 write: AP alone is NOT post-flushed-writecutproof.
Agent preparing narrow typed post-nondiscovery-flush observer DRAFT only; do not claim current889 interrupted-flush qualification.
LATEST889 normal39f87845eeaa4e2fba2606d68c91ac0f FAILED actualPID2948/birth1793840555672/exit1/239.3743653s.
Stackfix passed previousfrontier:57recorded-source artifacts/rawhashed-files128618B/directory/security/SDS/read-union produced.
Primaryfailure VSSexactGUIDvolumepath: attestation_partition passed raw volume_guid. Rootfixed canonical volume_path()+trailingbackslash;
focusedcheck0/29.295493s/no units, evidence/partition-vss-volume-path-build-20261104.json. Exact fixed build/native run still pending.
SDK's live pre-private cancellation thenfailed LOCK error21; not fixed, no external repair/cancel inferred. No J/publication yet.
Operator capturing actual144/GPT/C/intent then authorized ONE orderlyOff/freshall18/census; awaitactualclosure, no moreGO/CP/restore.
Postflush observer frozen DRAFT .lab/development/partition-postflush-hook-draft/partition-postflush-hook.patch SHAfb497a5abc593c6b8b0dcb67bd3a3637d002c96ddf59d70ba7becda150cc0b4a,
not applied/compiled. INTERRRUPTION-PLAN.md documents prerequisites: trustedpublisherSHA beforeAP, controlledpause, partitionpostbootJ/MIXEDpreflight.
Current889 has no postflush hook; don't infer flushed-writecut fromAP. Publicfrozenalpha remains qualified separately/unchanged.

USER RESUMED expanded full goal, including boot/offline OS conversion, after the explicit pause. Original scope remains incomplete.
Current889 finally CLOSED Off/RAM0/current07ca/all18, receiptc7e88915d3345ada59f786792cbceebac50c4f212c9fa319e2badc6bb59b15bc;
actualtargetBasicRO, all57rawsource artifacts archived, noJ/publication. Complete115file/1656672B archiveSHA1f247791fb13b38d9561ce71b100dc7e6add6e82e0cf938fd536db1c7342859e.
Freshall18/80dependency census321959045698/free85406539776. Root authorized ONE restore07ca WITHOUTnewCP under plan3869ef795f8386f84ca72f93096a5d3024ac427522eea9f1109f3010507dd078,
conditionalarchive/dependency/fresh1GiBcapacity insideold889absolute327044998096. This discards only disposable889workingCOWbranch after preservingunique metadata;
all18 incl3cbBasicROimage remain. Awaitactualoperatorclosure; no native/start authorization yet.

Root APPLIED real mounted-BasicRO fresh-handle relock for cancellation AND normalfreeze: same actualguard/token/nativeRO/GPT/critical bookends,
close stale FileObject after freshproof BEFORE singleLOCK, thenflush/dismount/DASD/flush/closingproof andtransfer. No old-handle retry/setterfallback.
Lab-only --cancel-before-private exercisesbegin→actualBasicRO→cancel→dropguardbeforeresult; no shadow/payloadwriter, independent8oracle required.
Also applied actualpreAPpublisherSHA receipt, typedpost-nondiscoveryflush receipt, explicitnonce/ACK stdinContinue/120s watchdog labpause.
Normaldefault no pause; extra512KiBRAM/1MiBevidence charged onlypausemode. No fabricatedNativeEvent or first-writecutclaim.
Combinedlib+labalpha+labrecovery focusedcheck0/28.1635596s/sharedtarget/no units. evidence/partition-fresh-relock-checkpoints-build-20261104.json.
Newcode NOT natively qualified; exactcommittedbuild pending. OperatorpreparingDRAFT oneboot cancel→independentNTFSoracle→normalconvert→ReFSoracle case.
Sourceprivate-preAP livecancel still missing; separateagentdraft only. Rootmain unchanged. Boot control/inactiveOS path not enabled from research.
ONEarchive-onlyrestore07ca COMPLETED Off/RAM0/current07ca/all18, receipt5ee3173201d6f4cd73d09ef0ad99a5fbdd736920a00abf344e46e271aff21aae.
Census320606827530/free86756507648, actualreclaim1352646753B; no newCP/native/sourceSET/manualdelete.
f777885ca505ca6dcdd9227d31162c601c32b134 exact BOTH-binbuild33308 completed0/146s/417heldfilesunchanged;
manifest93c1c9e9fbc72dd8bcdeb829c34d90d079325ad9331fb23dc8f18068af20efb9.
labalpha8602624B/SHA4b34661d13aa247d197ab718ff4187fd8f7109e67ff52e0b61b6e1c5c6a0f949;
labrecovery3858432B/SHA05e70cc29adf63658f76451ebff2bb7b972ddf2bab70aac569e3840668ad375c. NOT executed.
Static count found freshPRIVATEowner lackedactualeventsink: guard/adopt/revalidations could overflow128 beforeoutercheckpoint.
Applied tiny actualguard.observer.clone transfer INTO ownerconstructor, storedSome beforeFIRSTowner.revalidate; checks/cap/authorityunchanged.
Focusedcheck0/28.0627397s/sharedtarget/no units; evidence/partition-fresh-owner-event-sink-build-20261104.json. Newexactbuild requiredbeforeGO.
Frozen TWO-rolehelperdraft host2a246df5787072d0149c7e32a27527723196e1cd2023f3948da391e22fc6bf1b,
worker717e9b67c8b9a8298d56d78c5c5d5cb61447cd9ba7eeac45ba8d5aef507e7325,
definitions-only rolerunnerfd2f4d1377481d9922707aecebcc2c465796099d2edb97fbdccab5a846e9f109.
Root reviewedserialcancel→independentNTFSoracle→ONE normalconversion andactualtwoPID/terminal handling; noGOyet; baselineOff18.
cba2717 exact BOTH-binbuild11669 closed0/170s/417heldsourcefilesunchanged; manifestc2fb1ee28a897f2d31d0dddb03628773f3dbb76b3463a0192fc8dc7fc1c279ba.
labalpha8603648B/SHAa97656012980f8b4818eadef32e066f75e80bfcbb8ecea3c2e2adfc41416a016;
labrecovery3860480B/SHA56036cddfce239b0b8da9abc59d83e6ac019bf51f7434b40fc05aeac2a9904bc.
Actualtwo-rolecaseaae1f81fedca4d0cbb3eb61d274a3a9c host6093: CANCEL5128/birth1793843101542/boot1793843058929 exited1/209.5795539s.
ActualfreshRWopen/extents/NTFS/RO19 andfreshLOCK succeeded; explicitlockedFlushFileBuffers FAILED19. NORMAL neverstarted.
SourceBasicRO/valid1frame41785B/noShadow/J/pub; readonlyclosure516a39eecaf3174c3c2731414b0181244189fe4c9f84773775f7110f487ecbd4,
GPTRO-onlydelta6ee66b2eb6c43b2e20a18f385a14a56c28acbeef34398d5406a8962ce8e06f44/Ccontrol unchanged. Originalnative/workerbirthsabsent.
OperatorauthorizedONEorderlyOff/fresh18graph+census thenpreparearchive/resetPLANonly; no retry/SET/restore/extraCP unlessseparateGO.
RootfixedROlane: successfulFSCTL_LOCK_VOLUME alreadyflushescacheddata byMicrosoftcontract, andactualRO+heldlockpreventwrites;
removeonlytwoillegalredundantBasicRO.sync_all requests, retainallactualLOCK/dismount/DASD/closingproofs. Failedactual19remainsfailureevidence.
InitialBasic0flush andALLwritablepayload/Jflushes unchanged. Focusedcheck0/32.2764946s/no units; evidence/partition-readonly-lock-flush-build-20261104.json.
Exactfixedbuild/nativecasespending. Sourceprivate-preAP livecanceldraft andreadonlyofflineWinPEprobe DRAFT remainunapplied/offcriticalpath.

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

- Shared running-Windows-disk data partitions are unsupported. Existing physical-disk write failed21, but the retained-volume8KiB interface now passed. Persistent partition exclusion and full integration remain pending.
- Isolated Rust held-volume marker probe is built and executed only for the interface proof above: `.lab/development/partition-held-volume-probe/bin/partition-held-volume-probe.exe`,
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
