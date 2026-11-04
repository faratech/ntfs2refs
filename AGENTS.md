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
