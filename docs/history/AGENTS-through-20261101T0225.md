# ntfs2refs project guidance

@C:\Users\mfara\.codex\RTK.md

Read the RTK instructions above. This file is the current handoff, not a log.
The complete previous file is preserved verbatim in
[the historical archive](docs/history/AGENTS-through-20261029.md).
Its old “LIVE” labels, checkpoint counts and preserve-all instructions are history.

## Objective and working priorities

Continue the Rust NTFS-to-ReFS in-place converter. Prioritize concrete code and
the next necessary native integration run. Do not restart around another writer
or put independent-writer research on the critical path.
Conversion and recovery must run inside the Windows machine owning the disk.
Hyper-V is laboratory infrastructure, not a product requirement.
The broad volume-size, feature and boot-volume objectives remain unfinished.

The user explicitly asked to stop writing unit tests and focus on getting the
converter working. Do not add or run unit tests unless specifically requested.
Use focused builds and necessary native checks. Do not repeat expensive scans
when unchanged evidence already answers the question.

## Current handoff snapshot — 2026-10-31

Next experiment controller is ready: Start-EnvelopeRecovery supports explicit
schema2 `envelope-recovery-compatibility-toolset`, source scope public-recovery-only.
It pins actual OLD e4ff producer manifest5102/producer9140/PID5208/birth/86,
ORIGINALdea checkpoint and bundlecd919, separately from a NEW public runtime.
Original fault/helper bytes remain inherited; no helper build revision or old
receipt is invented. Original manifest is staged unchanged; host/guest bounds,
actual action ApplyIntent and completed exclusive_recovery_journal_used=true
are mandatory. Schema1 unchanged. Host/guest AST and independent review pass.
New normal lab --fresh-exclusive-v3 accepts only schema3 fast fresh planningNone,
conflicts faults and runs genuine admission. SourceSome cannot be restored.
Actual-byte-only capacity samples now include policy/O/projectedJ/combined;
they remain sampled space observations, not a full rolling-O ledger. Conservative
rows unchanged. Focused public/fault release build passes (1m04s); new native
qualification remains pending. See docs/recovery-runtime-compatibility.md.

The FROZEN e4ff old-zero native matrix is COMPLETE: controlled first flushed
write exit86, clean restart, public Resume0/HND and separate original-branch
Rollback0/ABT. Both independent observers matched all811 hashes. Rollback's
selected checksum equals the ORIGINAL ticket over D=11,392,847,872 bytes /
3,547 ranges; NTFS64KiB/label/mount/shape1084 verified. No independent
post-rollback extent-map or timestamp equality claim. Source/shadow protection,
schema2 prepared owner, positive O=5,587,685,376 and self-contained format4
J=5,849,731,480<D all passed. Cold shadow6 was absent in both recoveries; no
attach/rebind. Product Resume checked complete1084 maps plus known157 hashes /
119009 payload bytes;654 digests stay absent,650 tails/1371388 bytes stay bound.
See `docs/old-zero-recovery-matrix.md` and its evidence JSON. This does NOT
qualify newer capacity87a or recovery-ownerb88, arbitrary faults or physical loss.

At matrix closure, VM was confirmed fresh at2026-11-01T01:50:19Z: Off/RAM0/50 snapshots,
restored-NTFS35c9a8f8-b646-4d3b-98e9-191b2f12a4a6, parent ORIGINALdea902f6.
Preserve NEWnormal6bef, NEWintdea, NEWResume033, NEWrollback35c9, sources8329/
6fe/371, H tail matrix, D1 and guardedf4bf. All host evidence remains.
That closure measured322,376,794,614/free22,809,677,824 bytes inside the epoch.
SUBSEQUENT CLEANUP COMPLETE at01:58:33Z: root removed ONLY old07b1aed,5f,
then their now-childless parent307b, plus olded6, through Hyper-V. All336 closed
archive/control/dependency files (576,851,960B) were rehashed under held reads;
each removal used a fresh process and exact graph/leaf/current guards.
Review37176fcc/inventoryb3e67b4e; completiond5ec224b under
checkpoint-cleanup-superseded-07b-d5cc95d3b8f744cabfd45e2b27b3dc91.
CURRENT fresh VM remains Off/RAM0/current35c9, now46 snapshots; every other ID/
parent and all host archives/baselines remain. Actual275,354,925,443 bytes /
free69,904,642,048 bytes: measured lab decrease47,021,869,171B. Fixedmax329374052988/
min17179869184 unchanged; next16GiB forecast fits again. No host disk-file
deletions, new epoch, WSL stop or f4bf action. Retired IDs must not be recreated.

New journal-only recovery owner is implemented/reviewed and passes focused
library/public/fault/binder compilation (17.68s), natively UNQUALIFIED.
`authenticate_recovery_exclusive` performs actual full load+classify and holds
the same share-zero journal borrow/plan/ticket/records until one operation closes.
All mixed target prechecks, PER-SPAN old/current/new reads, exact post-write AND
post-callback handoff target digests, flushes/ordering/markers remain. Only
duplicate authentication of that owned immutable body is omitted. Target reopen
stays share3; no new target/global alias exclusion is claimed. Callback receives
only the resumed result and must persist before HND; failure leaves intent open.
Legacy public APIs retain all independent validation. Successful allocation
recovery reports actual `exclusive_recovery_journal_used=true`, not authority.
Code-accounted savings for e4ff plan: Resume34,805,884,512 logical J reads and
Rollback17,402,942,256; no measured/physical-I/O claim. See
`docs/journal-exclusive-recovery.md`. This is NOT in the frozen e4ff VM binaries.

New optional capacity-policy implementation is compiled/reviewed, natively
UNQUALIFIED. `old_zero_actual_bytes_v1` is restricted to fresh schema3 fast
allocation/CapacityPinnedV3 with pinned literal+combined bounds. It permits a
partition-sized logical changed set but checks each accepted append using
`J=(D-O)+literal+16MiB`, real free space and all existing metadata/range limits.
Whole-range O is updated in O(1); coalescing zero then nonzero revokes the whole
prior range's credit BEFORE admission/append. Exact final plan, positive O and
format4 are mandatory beyond the conservative limit; no unprofitable fallback
can admit an expanded set. A separate native C3 gate checks pinned M, J, J+O
and partition/ranges. Pinned-request recovery selects it only after full actual
journal/lifecycle authentication. CLI/binder and omitted policy remain
conservative; no new mode is enabled in the frozen e4ff VM run. Focused cargo
check for library/public/fault/binder passed in21.02s, no unit tests. See
`docs/actual-byte-capacity.md`. A new native experiment is still required.

CURRENT e4ff old-zero recovery matrix: actual producer5208/birth1793495149312
exited86 after the first flushed write, no Apply/HND, source1attrs1/shadow6attrs3.
Original bundle `cd919acd5237d3c5087017b2c312ba54cb1d72cea09d634182cebe4e21515f26`
at `C:\ntfs2refs\envelope-interrupt-d4f9c35229b84373a0ba3ff0887763d1\conversion`.
O=5,587,685,376 / N=3,547 / D=11,392,847,872 / J=5,849,731,480 bytes (format4).
Closed80files186,303,850B copied/sourceSHAverified: old-zero-firstwrite-d4f9c352,
index b4a6552b3d13f52eff13ba374846deec028665f17393c673248bb3f3649e0771,
receipt13a8c256bd1bcee0c5330a283f14f84b619fd74fa950a42ee23ccffdb7fde174.
After allidle normalstop, root saved original interrupted checkpoint
`dea902f6-7d3f-49ba-86d2-27ce6dbe9516`, parent8329; freshOff/RAM0/48.
Public Resume `d1d45a31` PASSED: actual5696/birth1793496097001 native0/HND at
01:28:15.8011963Z (398.8001963s), observer0/all811 at01:33:43.3923390Z.
Cold shadow6 was absent/no attach. Product maps1084, known157 hashes/119009B,
654missing/650tails1371388 remain. Closed52files88,764,681B source/copySHAverified,
indexc83bfec18782b4b288f8c88bd7d7a579543c785cbfd83b02607f9c885b401cc6,
receipt6f315670b0bf950286a0b99bc441e706d1db60489caa5011ea9526d5e22c3a45.
After allidle normalstop, saved ReFS033e05bd-447b-450e-9acb-9413feaf00dc,
parent ORIGINALdea. FreshOff/RAM0/49; receipt6b8f42cdca07b9574c64c4ed0cf56c96be48136dc46d8cf26c0341cd52e5efd2.
Restored ORIGINALdea once (never replay the HND branch), freshverified thenbooted.
Public Rollback525621320f8040b6b0a4fe4697bed692 PASSED: native5680/
birth1793497274111 exited0/ABT01:45:32.5100680Z (258.399068s), observer988/
birth1793497118971 all811 at01:47:34.7203322Z (+122.2102642s). Closed50files
62,129,359B source/copySHAverified, index18b15e86e56962651ce665d6e251db74545b041ad4dbfd46a4c19a377c193a57,
receiptb6c14a975f8635757fa465e5ee92a3232c64693c0c9be9b23cffb56e3e259957.
Finalcheckpoint receipt4b4db0a5f1d661f87a0d47cb22a18b20bc953aa0831e8027117ae1a8b58c39d9.
Root alone owns VM mutation; no second recovery/death inference from timeout.
Snapshot receipt SHA0b54d62b257da159148a2e25af338fd6782f4d7de4bc818de2e4f1129c45870f;
actual303,750,131,935/free41,418,272,768 bytes admitted16GiB Resume forecast under
the fixed epoch. No HND/ABT replay. Current cold shadow may be absent; never attach
or rebind it to bypass a refusal. All50 slots are now occupied.
At Resume closure actual319,544,893,906/free25,723,949,056 bytes admitted6GiB
Rollback forecast inside the fixed epoch. Re-admit any later work; no cap reset.

Latest qualified normal runtime is sealed `e4ffb3a` / public `f8c07817`
(9,899,008 bytes), case `6d9b4cd5` / core `6e91f232`. Actual PID 724 /
creation 1793494088987 exited 0/HND in 276.7805697 s; the separate observer
matched all 811 hashes 174.6023869 s later. Actual format 4 / 104-byte records
contains 1,770 old-zero ranges / 5,587,607,552 omitted bytes, with
`old_zero_payload_storage_elided=true` and `prepared_journal_owner_reused=true`.
D=11,392,786,432 / N=3,534 / L=44,888,064 / J=5,850,442,832 bytes. The SAME plan
without old-zero encoding needs 11,438,022,112 bytes: net 5,587,579,280 saved,
after its 8*N descriptor cost. All selected D writes and required ReFS zeros
remain. Actual process reads 105,470,433,073 / writes 17,446,733,391 bytes;
CPU 253.421875 user / 22.359375 kernel seconds. These are logical counters,
not physical I/O or a controlled timing comparison. Same grown 8329/fresh f5de/
growth835: 1,084 objects / 654 absent digests / 650 tails / 1,371,388 bytes.
See `docs/old-zero-native.md` and `evidence/old-zero-native-20261031.json`.

Current VM, confirmed fresh at 2026-11-01T01:00:04Z: Off / RAM 0 / 47 snapshots,
converted ReFS `6bef3bd2-db31-45fe-9e6c-939c812b7375`, parent clean grown `8329`.
Preserve 6bef, prior ed6, the 307b/1aed/5f075 matrix, clean sources, H tail
matrix, D1 and guarded f4bf. All host evidence remains. Actual lab usage
295,406,531,182 bytes / host free 49,858,801,664 bytes stays in the fixed epoch.
NEXT: new-format native first-flushed-write interruption, clean restart and
public Resume/Rollback. The former 39 GiB forecast does not fit now; use actual
per-phase capacity admission. A 16 GiB first-write forecast covers the observed
5.85 GB journal, shadow, OS and metadata margin; remeasure before dispatch.
There are three checkpoint slots left. Do not replay either closed HND branch.

Canonical old-zero journal format 4 `N2ROLD01` omits stored
payload only for whole selected ranges whose actual original bytes were checked
zero during capture AND reread/checked during preparation. Existing boundaries
are unchanged; coalescing ANDs the evidence. New 104-byte records authenticate
old kind, new kind and both complete logical hashes. Central `read_before`
resolves payload/zero for rollback, mixed checks and cross-record COPY. Legacy
formats/serialization remain unchanged with absent/empty `old_zero_ranges`.
Exact `J=8352+104*N+2D-Z-C-O`; native new-format gate allows `D<=J+O` with checked
arithmetic and unchanged profile ceiling. Conservative capture `D+literal`
capacity, selected writes, required ReFS zeros, complete target hashes, owner,
flush/order/HND/ABT and source-certificate gates stay. No admission-cap lift.
Fresh planning uses old-zero encoding only when omitted bytes exceed the full
8/16/24-byte-per-record widening cost; otherwise it keeps the cheaper legacy
journal while retaining the actual capture observations.
Focused public/fault/manual-helper release build and independent review pass.
Existing standalone owned-file experiment passed legacy SEL/ZERO/CPY plus old-zero
alone and with COPY, persisted short-write Resume/Rollback, false-old-zero refusal
and equal framed old/new digests. New modes omitted 12,288/16,384 old bytes and
saved 12,216/16,328 actual journal bytes. Summary under `old-zero-functional-8f3c08f0`
SHA `44827ea6397d5ead7b5ecd05c9f4a496753a6a871fddafa138f26b9bb36e2ac4`.
The scoped normal native result above passed; native fault/recovery/mutation
and physical power loss remain pending for this format. Do not transfer the
older sealed recovery matrix to this new runtime.
See `docs/old-zero-journal.md`. No unit tests were added or run.

Before the new native attempt, root removed only obsolete inactive leaves
`2c964314`, `a18bf3a5`, `acb5449f`, `bb8a6475` through Hyper-V after rehashing
273 unique closed archive/control/dependency files under held read guards.
Reviewed plan `e7223c3d` and completion `a678c846` remain under `.lab`.
A fresh process then confirmed Off / RAM 0 / 46 snapshots, current `ed6fe063`;
every other ID/parent and all host evidence were preserved. The prior 50-count
observations below are historical. The new current state is recorded above.

Prior normal native qualification: sealed `11e8963` / public `2ff60056`
(9,896,960 bytes), case `79b22a2f` / core `b4135fc9`, actual PID 3944 /
creation 1793492056135, exited 0/HND in 280.7502894 seconds. Actual result proves
`prepared_journal_owner_reused=true`; the separate observer passed all 811 hashes
165.6914236 seconds later. Same grown `8329`, fresh baseline `f5de` and growth
`835b`: 1,084 objects / 273 directories, 654 absent digests / 650 materialized
tails / 1,371,388 bytes. No digests were manufactured. Native-verified process
reads were 111,031,478,753 bytes and writes 23,029,158,576 bytes. Prepared-to-applied
reads 28,487,536,640 equal `2D + copy + literal + 12,288` marker bytes exactly.
The avoided duplicate load on this plan is 17,136,951,040 logical bytes. Prior f2
process reads were 17,144,221,184 bytes higher; differing plans/formatter metadata
preclude controlled timing or physical-I/O claims. CPU was 270.4375 user /
26.546875 kernel seconds. See `docs/prepared-owner-native.md` and
`evidence/prepared-owner-native-20261031.json`.

Current VM, confirmed from a fresh process at 2026-11-01T00:24:16Z: Off / RAM 0 /
50 checkpoints at converted ReFS `ed6fe063-3a06-489a-8028-2a16929ce171`, parent
`83290a28`. Preserve the new normal branch, the `307b` / `1aed` / `5f075`
interruption/Resume/Rollback matrix, clean grown `8329`, original sources and
the other explicitly protected branches below. Obsolete inactive-leaf normal
checkpoint `1c75c73f` was removed through Hyper-V only after its full closed
archive/dependencies (91 unique files) and exact graph were checked under held
read guards. All host files remain. Actual lab usage 279,038,846,111 bytes /
host free 66,131,628,032 bytes remains inside the unchanged epoch. WSL stays up.

Performance implementation: `PreparedExclusiveJournal` retains the SAME
exclusive journal borrow, immutable plan, original ticket and authenticated
records from the complete post-flush preparation readback through activation
and fresh apply/HND. The fresh arm exposes no mutable journal accessor. Exact
old-target/clear-marker checks immediately before intent, full new readback,
flush/order/callback/HND and all independently opened recovery checks stay.
Normal fast and V3 first-write fault use the owner; legacy fault/full paths stay.
Result records the actual enum-derived `prepared_journal_owner_reused` value;
the fault diagnostic is schema 2, with exact historical schema 1 still accepted
by the lab controllers. Focused library/CLI check, independent review, AST
parsing, release build and the scoped normal native case above pass. This new
owner's fault/recovery/mutation/power-loss qualification remains pending; the
following `07b0164` matrix belongs to its original sealed binaries.
See `docs/journal-prepared-exclusive-owner.md`. No unit tests.

The grown-tree fresh-exclusive recovery matrix is complete. See
`docs/envelope-recovery-matrix.md` and
`evidence/envelope-recovery-matrix-20261031.json` for the exact artifact pins.
The lab fault path uses sealed source `07b0164`, public binary `c11af38e`, and
fault binary `73e92d3f`. It enters the real V3 planning-None -> admitted-Some,
exclusive preparation and fresh exclusive apply path, then exits 86 after the
first successful target write has been flushed. This is a controlled first-write
interruption followed by a clean guest restart, not arbitrary power-loss proof.

From the same interrupted checkpoint `307b65ff-555d-430d-ac93-7b5946834083`:
public Resume `68203aa3` exited 0/HND in 552.2482827 s and independent observation
matched all 811 stream hashes. Public Rollback `27abc45e` exited 0/ABT in
325.5027467 s; its selected checksum matches the original ticket's old checksum
over 11,392,921,600 bytes / 3,505 ranges. The NTFS 64 KiB label, 1,084-object
namespace shape and all 811 independent hashes matched. Do not claim independent
post-rollback extent-map or timestamp equality. Product Resume verifies 157 known
full hashes / 119,009 payload bytes plus complete pinned maps; the independent
lab observer's 811 full hashes are separate evidence. Missing digests stay missing.

Both recovery directions succeeded with the cold-detached managed shadow absent;
allocation journals are self-contained. Required pinned routing, request, plan,
ticket, expectation, verification and map metadata still apply. This does not
remove the compact/whole-shadow recovery dependency. Never replay after HND/ABT.
Product rollback currently checks the NTFS mount; label and mount-set equality
in this matrix are lab observations, not an implemented product gate.

At closure of the recovery matrix, root confirmed from a fresh process at
2026-11-01T00:04:06Z:
Off / RAM 0 / 50 checkpoints, current restored-NTFS checkpoint
`5f07551f-b339-4beb-97cd-0209967ee348`, parent `307b65ff`.
Preserve interrupted `307b65ff`, resumed-ReFS `1aedc3d5`, restored NTFS `5f07551f`,
grown clean NTFS `83290a28`, original sources `6fe2d6b6` / `371ae756`, the partial
tail matrix, D1 cold `d939f576` and guarded `f4bf5238`. This turn removed only
obsolete `eaa87f30`, `9bb675b9` and `9ce156c3` through Hyper-V after their closed
archives and dependencies were verified. All host evidence remains preserved.
Actual lab usage was 279,145,884,943 bytes; D: free was 66,088,849,408 bytes under
the unchanged storage epoch. WSL remains running. No unit tests were run.

Pre-dispatch refusals remain recorded: malformed PowerShell numeric syntax,
the original cold-shadow preflight dependency, and root's duplicate Rollback
launcher, which the idle guard rejected before a second helper/native process.
None is a second native recovery or a native replay failure. The successful
matrix qualifies these exercised paths only; broad scale, compatibility, boot,
arbitrary faults and physical power loss remain unfinished.

The following normal-run observations and earlier milestone labels are history;
the current checkpoint and preservation state above take precedence.

Current qualified normal f2casee27c6a4675ef4cf682552b53b393af02/core89207dbd:
runtimef2e5f73/public02e5e009d0805c8e3c35eafaa2c3f0632e77974d1b25dcea0a194b0f1eac816a
(9,894,400B) native1652/creation1793485612084 exited0/HND358.795446s;
observer0/all811 hashes166.8139984s later,1084objects/273dirs. Same grown8329/
freshbaselinef5de/growth835/harnessc85;654NoDigest/650tails1,371,388B source/
readback/protected-residual proofs passed. Source/targetextent_identity_v1;
0targetcontenthashes/reads.154provenaccess-time reconciliations; othermodelled
metadata/rootmodified/MFTtimes exact, productJSONuntouched, full/fastrawpins
distinct. No above1024files/unlimited/recovery/mutation/fault/powerloss claim.

Nativeprocessreads128,175,699,937B/writes23,030,251,403B,userCPU383.390625s/
kernel33.28125s. Prepared→appliedreads45,626,234,496B/writes11,393,137,219B,
CPU161.6875user/8.734375kernel;6actualguest-timestamped snapshots. Priorf32
reads150,985,869,025B give22,810,169,088B fewerlogicalreads; thisplan2D is
22,786,007,040B, metadata/plan differences precludecontrolledattribution/speed
orphysicalIO/HDD/1TB forecasts. D11,393,003,520B/3557ranges,L42,754,048B/
J11,436,107,392B,copy5,659,303,936B,zero5,690,945,536B; originalcoordinate
payload4,225,028,096B. Move submissions are notphysicalIO.

Includes e6dzero cache+privatefreshwriter: allactualcandidatezero checks and
aggregate/storedhash/auth barriers remain. Hits were NOTinstrumented; this
qualifiesexecutednormalzeropaths, notmeasuredcachehit/CPU gains. Freshwriter
requirescontinuousno-mutable-alias ownership; primaryrawgate isNOTglobal
admin/volume-alias exclusion. Exactold/new fullchecks andordering/flush/HND
remain, mixedrecovery checksunchanged; already-equal chunksmaywrite≤D.

Closed77files221,702,510B copy/sourceSHAverified,index341c47f0. Normalstopafter
allidle,ONEcheckpointfreshconfirmed currentOff/RAM0/50 at
1c75c73f-3465-4ebe-9b99-aa9897c17a1a parentgrown8329. Actual279,106,062,708B/
free66,124,685,312B insidefixed329,374,052,988B/17,179,869,184B epoch.
RemovedONLYobsolete42d viaHyperV after69archive+46dependencypins verified;
ALLhostevidence/baselinesstay. Preservecurrent1c75/eaa/8329,6fe/371,tailmatrix,
oldint9ce/resume9bb,D1cold d939,f4bf. Evidence: evidence/fresh-exclusive-native-20261031.json;
docs/fresh-exclusive-native.md. No units. Broadercompatibility/scale/bootgoalactive.

NEXT (proposal, NOTimplemented): source directory case-flag refusal on actual
handles before/after, newlive native reports13/14 and gatebeforecertificate;
legacy missingflags remainunknown, neverretrofalse. VSSsnapshot/allcontexts and
source-as-diff-area observations mustbindactualfreeze/livecertificate context;
emptycompletedcatalogs cannotproveinflightabsence, errors/unknownfailclosed.
No misleadingglobalVSSabsencecheckbox, snapshotdeletion or namespace/ACLdrop.

Fresh-apply implementation: private nonserializable FreshExclusiveApply
owns both mutable IO borrows, plan/ticket and fully authenticated journal records.
Constructor requires clear markers, target flush and complete exact-old selected
SHA. Under the existing no-mutable-alias contract, disjoint destinations remain
old until their sole write; fresh writes omit current/old per-span rereads and
use one1MiB desired buffer. Exact-new complete readback, discovery granule last,
flushes/callback/HND remain. Legacy/fault/resume/rollback mixed checks unchanged.
No global admin/volume-alias exclusion or immediate foreign-write detection is
claimed; up toD bytes may be written including already-equal chunks. Expected
read reduction2D is code-path accounting, notphysicalIO. Focused check/release
and two reviews pass; the scoped f2normal qualification above passed.
Recovery/faultqualification remainsopen. Includes e6dzerocache; neither was
used in the earlier qualified f32 below.
See docs/journal-fresh-exclusive-writes.md. No unit tests.

The following older milestones/current VM labels are historical; preservation
and cleanup state above is authoritative.

Current qualified V3 case1cb0adcbd89d470cafc6ff53829ac8c5/coreb68cb9b3 passed
sealedf32c0f6/public648cf28363b854ac5b960bb22ccd45855e5d81b468d29d6ac8d4f7342f4b1803
(9,849,344B): actualPID568/creation1793483535328 native0/HND384.7244694s,
observer0/all811 hashes163.4887101s later. Actual1084objects/811files/273dirs
exceedstheold256directorysplit ONLY; no above1024file/unboundedclaim. ExactSome
resource descriptor binds1111rawIDs/811streams,2714projectedhandles (notmeasured
OS/RAM),1280object/2048raw/16384streamslots,64MiBraw/native and16MiBexpected/
constructor metadata. PlanningNone stayedin devices; admittedSome ispinnedin
request. Full/fast rawpins staydistinct. Target0contenthashes/0payloadreads,
1084complete maps/metadata/storagevalidity andall811independent hashes passed.

Growth32cbcf9d createdN2RV3+D000..D149 (151emptydirs);808oldfile IDs/maps stayed
unchanged,0payloadreads/writes/moves, no freshhashclaim. Clean grownNTFSsnapshot
83290a28-1e83-4eb2-a4d3-b0e9f5a8d63b precedes baseline74ea49c9 manifestf5de156f:
onefullRaw+oneactualNativepass matched811hashes and808historical actualXXH3
path/length/contentrefs30bd09 (nooldmetadata/profile/rootmtime mask; nofresh
SHA256fixtureclaim). BaselineissuednoSourceCert/journal/replay/protectionclear;
rootrestoredsavedgrown8329 beforepublicconversion. Float `.0` parserfix was
caughtbeforehelperexecution; preservedPS5stagingrefusalmade0helpercalls, not a
failednativebaseline. Helpers91f8b3/nativegrowth5fe1f75/harnessc85 areseparate.

Actual654missingdigests/9,885,682,940B include650tails/1,371,388B with650actual
constructor/source/readback/protected-residual bindings. Rawhash94,339,669B and
nativeotherlogicalreads22,204,741B remain. FreshcompletebaselineRootprofile,
modified/MFTtimes/newobjects compareexact; only3provenaccess-timereconciliations.
Productexpectations/timesuntouched. Nativeprocessreads150,985,869,025B/writes
23,034,445,120B,userCPU415.796875s/kernel35.734375s;6guest-timestampedphasepins.
These arelogicalaccounting, notphysicalIO/controlledspeed/HDD/1TBforecasts.
SelectedD11,393,273,856B/3577ranges,copy5,659,303,936B,zero5,689,360,384B,
L44,609,536B/J11,438,235,136B. Originalcoordinate4,225,028,096B;2424move
submissions13,580,988,416B are notrealphysicalIOmeasurements.

Closed77metadatafiles217,457,040B allcopy/sourceSHAverified (index45d528e6).
Normalstopafteridle thenONEcheckpoint: currentOff/RAM0/50 at
eaa87f30-0ca1-4a4a-8ae7-0e45cb1481f9 parentgrown8329. Actual280,017,813,937B/
free65,217,228,800B staysinsidefixed329,374,052,988B/17,179,869,184B epoch.
RemovedONLYobsoleteecd548f8+ce9b92c2 viaHyperV after71+43archives/depsrehashed;
ALLhostevidence/baselinesstay. Preserveeaa/8329/42d,6fe/371,tail3cbc/119/643/fcc,
oldint9ce/resume9bb,D1cold d939,f4bf. Evidence: evidence/object-envelope-native-20261031.json;
docs/object-envelope-native.md. No V3/aggregateCPU recovery/mutation/powerloss/
arbitraryfault orlargerscalequalification. Zero-cachee6d78a7 was NOTused and
remainsfocused-check/review-only, nativelyunqualified. No units. Broadgoalactive.

Object-envelope implementation: fresh fast allocation uses V3 planning None,
then derives an admitted Some descriptor from complete reconciled frozen raw
facts. It reallocates the existing1280 object slots across files/directories;
it does NOT add unbounded counts. Counts/pin, raw/native64MiB ceilings, expected/
constructor16MiB ceilings and conservative owning-handle projection are checked
through native construction and the pinned recovery request/map parser. Native
execution/recovery reject planning None; other conversion routes reject V3.
Old V1/V2 serialization and limits stay. Focused library/CLI check, independent
review and public release build pass; no units. Public9849344B SHA
648cf28363b854ac5b960bb22ccd45855e5d81b468d29d6ac8d4f7342f4b1803
includes this V3 and aggregate CPU scheduling. The scoped normal case above
qualified273directories/811files, not recovery or arbitrary counts. Freshlab
observers validate exactV3 descriptors withoutmasking profile differences. See
docs/object-resource-envelope.md. Paged manifests/scale/compatibility stay open.

Aggregate SHA scheduling: selected-side and immutable journal aggregate SHA-256
updates use the existing bounded digest pipeline on machines with at least three
cores. Per-record SHA, every read/comparison, byte ordering, digests and barriers
remain. Each worker owns one recycled 1MiB buffer; all required finishes/errors
are joined before ticket/record publication. Serial fallback stays on smaller
machines. Focused library/CLI check and independent review pass; the scoped
f32 normal qualification above passed. Recovery/faultqualification remainsopen.
It was NOT in sealed cc6cd28. See
docs/journal-parallel-aggregates.md. No unit tests.

The following older native milestones and former current VM labels are history;
the current preservation/cleanup state above is authoritative.

Qualified sealedcc6 normal F caseb11fb80f47f74ec8819977f047ec478d/core77fd3136:
actualPID5144/creation1793478787506 native0/HND600.7880323s, observer0/all811
independenthashes141.8771831s later,933objects. Source654missingdigests/
9,885,682,940B and650tails/1,371,388B keep actualsource/write-flush/readback/
identity/protected-residual proofs. Rawinitialhash94,077,273B andothernative
logicalsource reads22,204,741B remain. Target0contenthashes/0payloadreads,
933complete mapbindings/metadata/storagevalidity passed. Exclusivepreparation
readback=true. Runtimecc6cd282d93445fd12de82cb66ae174662249a6d/public
3a45791c88e7fd1902920553bdd3e343f11ff9fb7abd3e721e5565c59766bba5 includes05b
bufferreuse+exact-state checks; harness9bbd1c4 isseparate. Later60d2aggregateSHA
andf32V3code above remain BUILT/UNQUALIFIED, notinthiscase.

Nativeverified processlogicalreads150,896,889,633B/writes23,002,013,682B;
CPU434.3125s user/34.296875s kernel. Relative18breads185,082,120,225B gives
34,185,230,592B fewerlogicalreadbytes; plans/formattermetadata differslightly,
so no controlledwall/physicalIO/1TB-HDDtimeclaim. Originalguestphase timestamps
and6IO/CPUsnapshots retained. Prepared→applied reads68,393,054,752B/188.5625sCPU.
D11,391,942,656B/3204ranges,copy5,659,303,936B,zero5,694,500,864B;
L38,137,856B/J11,430,396,448B. Originalcoordinate4,225,028,096B remains42.745%
oforiginal+copymapping;2424moves/13,580,988,416B submissionsarenotphysicalIO.

Closed69JSON/logfiles155,572,595B allSHAverified (indexf1593687), within64MiB/file
and256MiBcombined. Alltasks/nativeworkers terminal before normalstop. Rootissued
ONEcheckpoint; a freshprocess settledinitialstalecachedparent toactual
42d684f8-1a63-4f7b-98ac-286d88289a63. CurrentVMOff/RAM0/50snapshots; labactual
285,720,877,776B/free59,607,769,088B insideunchanged329,374,052,988B/17,179,869,184B
epoch. RemovedONLYobsoletefull78513f35 after57closedfiles+31index/dependencypins
rehashed; ALLhostbaseline/evidencefilesstay. Keepcurrent42d,mixedecd,6fe/371sources,
tail3cbc/119/643/fcc,oldint9ce/resume9bb,D1cold d939,f4bf. Evidence:
evidence/mixed-exact-journal-native-20261031.json; docs/mixed-exact-journal-verification.md.
Three recordedlabaccess-time reconciliations; allothercanonicalmetadataexact,
productexpectations/timestampsuntouched. No cc6 recovery/mutation/powerloss or
newCPU/V3qualification transfers. No units; broadergoal remainsunfinished.

Exact selected target verification: check_target with an authenticated exact
old/new selected digest now hashes EVERYselected actualtargetbyte with identical
framing, without rereading both journal sides for redundant old-or-new membership.
Mixed pre-resume/rollback (expectedNone) keeps all old/new reads and byte checks.
Loader/ticket/plan/payload/footer/immutable checks, bounds, SHAfailures and every
barrier stay. Library/CLI/release checks+independentreviewpass; the scopedcc6 F
normal qualification above passed. Recovery/faultqualification remains pending.
No unit tests. It was NOT in the earlier sealed18b F run. See
docs/exact-selected-target-verification.md. Current publicprofile scaling guards
and required next manifest work are documented in docs/scaling-budget-gaps.md;
no arbitrary volume/file-count support is claimed.

Built subsequent CPU/allocation candidate reuses two1MiB preparation buffers and
three1MiB replay buffers across ranges; every usedslice is freshly filled by
current IO. Preparation scratch drops before readback; replay scratch drops
before the final full target check, preserving phase working-set bounds. No
read/check/digest/order/flush/marker change. Library/CLI checks, independentreview
and release builds pass; the scopedcc6 normal Fcaseabove qualifiedthispath.
Recovery/faultqualification remains pending. No unit tests. See
docs/journal-buffer-reuse.md. This was NOT in the sealed18bdea8 F case below.

The following earlier native results and former current VM labels are historical;
the current checkpoint/preservation/cleanup state above is authoritative.

F normal case5b30c30e/core12f76424 PASSED sealed18bdea8/publice2e2132 on exact
source6fe,4GiB/4CPU/noNIC: actualPID5296/creation1793476577793 native0/HND,
observer0,933objects/811streams and all811 independent complete hashes. Actual
654unhashedextentstreams/9,885,682,940B include650partials/1,371,388B with650
constructor/source/readback/protected-residual bindings. Rawinitialhashing
94,077,273B versusold9,979,760,213B; othernative logicalsource reads22,204,741B
remain. Target0contenthashes/0payloadreads,933complete mapbindings andmetadata/
storage-validity gates passed. Actualexclusive_preparation_readback_used=true.

Nativecreation→terminal632.8646961s; observerfinished329.6227202s later in3hash
batches. NativeprocessCPU426.359375s user/48.859375s kernel; logicaltransfer
reads185,082,120,225B/writes23,003,814,097B. These are NOTphysicalIO; no general
speedclaim. Journalphase used39,955,150,496B reads/238.75sCPU; prepared→applied
used102,573,946,528B reads/200.796875sCPU. Source-backedmapped bytes:4,225,028,096
original-coordinate (42.745%),5,659,303,936selected-copy (57.255%); these ratios
are oftheircombinedmapping, notalllogicalstreambytes. Placement2424submissions/
13,580,988,416B caninclude repeatedmovement. Lpacked38,625,280B; J11,430,839,968B;
selected11,391,897,600B/3216ranges includes5,693,968,384B newzero ranges.

Closed71metadatafiles/155,615,575B allSHAverified; normalstop then savedReFS
ecd548f8-3237-44f5-b874-6de79c140997. VMOff/RAM0/50snapshots, allworkers/tasks
terminal beforestop. Actual lab285,593,776,923B/free59,539,214,336B stayinside
fixed329,374,052,988B/17,179,869,184B epoch. RemovedONLYobsoleteoldNTFSb809 via
HyperV after73archive/index/derivedreceipt files rehashed; ALLhostevidence/
baselinesstay. Preserve newmixedecd,6fe/371sources,3cbc/119/643/fcctailmatrix,
oldint9ce/resume9bb,large785,D1cold d939,f4bf. Evidence:
evidence/mixed-fast-journal-native-20261031.json; docs/mixed-fast-journal-verification.md.
Runtime18b differsfromlab05f511f; later05bbuffers/cc6exact-target builds remain
BUILT/UNQUALIFIED and were NOTused. No18b recovery/powerloss/mutation qualification
transfersfromoldercases. One recordedlabaccess-time reconciliation only; product
expectations/timestampsuntouched. No units. Broader scale/compatibility/D2 remain.

The following completed matrices and former current VM/checkpoint labels are
historical; the retained checkpoints and cleanup changes above are authoritative.

Exact sealed3ce15c7 partial-tail recovery matrix now passes one controlled
first-flushed-write case. Producer1798b541 actualPID5516/creation1793474877619
exited86; source6 stayed offline writable/shadow offline read-only. Bundle
59c0b9e0f7a59afa2e015544448d5fe7451fe7ef8296bc9872ce0e7fa0e61c22 pins14
extent-only streams/53 maps, including12 partials/457 materialized tail bytes.
The original post-native observer failed on a4MiB JSON bound and is preserved.
Labelled function-only read-only completion4930c28e verifies actual12 tail
construction/source/readback/protected-residual bindings with corrected64MiB
reads. Normal wrapper-controlled receipt remains absent. Recoverycontroller23ac651
explicitly binds this derived observation and the actual terminal86 PID/creation;
no producer, bundle or missing content digest was synthesized or rerun.

Public Resume40353946/core recovery-726698c9 passed native0/HND and observer0:
25 known full stream hashes/64,574,222B plus14 pinned-map streams,44objects/53maps,
12 partial-tail counters/457B, all30 default+9 named independent hashes. From the
SAME saved86 branch, public Rollback1f5ae9e0/core recovery-f56dfab8 passed native0/
ABT, old-selected checksum equality (82,034,688B/246ranges), NTFSH:/4KiB/original
label and all39 independent hashes. Seven streams in compression-normalized
NTFS files used ordinary logical reads,32 used backup reads. No HND/ABT replay. Current source/Resume
target metadata checks remain; no independent post-rollback timestamp claim.

Preserve tailnormal3cbc9ae0, tailInterrupted119445de-8c2d-4186-b54c-6b5cda644e4d,
tailReFS64304900-25ef-4797-8d01-f58d229dedc3 and current tailNTFS
fcc42f45-2101-441d-8751-b625cc7d0051. VMOff/RAM0/50 snapshots after normal shutdown;
all tasks/native workers were terminal/idle. Closed firstwrite/Resume/Rollback
archives71/77,484,848B,35/5,498,270B,37/2,295,130B are allSHAverified; original
observer failure70/77,470,036B stays separate. Actual lab263,539,048,661B and host
free81,655,656,448B remain inside the unchanged329,374,052,988B/17,179,869,184B
epoch. Obsolete0cf18d65/44c48db9/9bfbe6f7 were removed only viaHyperV after
fresh archive/index/SHA revalidation; ALL host baseline/metadata files stay.
Keep oldrecovery9ce/9bb/b809, sources371/6fe,large785,D1cold d939 and f4bf.
Evidence: evidence/partial-tail-recovery-matrix-20261031.json;
docs/partial-tail-recovery.md. Runtime3ce is distinct from observer e96fb28/23ac651
and newer18bdea8 journal-preparation optimization (not used here). No unit tests.
Only one controlled exit86 plus clean restart is qualified; broader faults,
power-loss, mutation, F-scale, D2 and broader objectives remain unfinished.

Built next performance candidate: normal fast preparation computes its immutable
journal pin during the same complete validating readback, removing only the
preliminary hash-only body scan. Exact source/candidate selected digests, payload/
descriptor/footer checks, resolved copies, marker-clear checks and flushes stay.
Issue mode is private to a fresh share-zero journal; full/fault/recovery paths
still use their original trusted-pin checks. Binary format/ticket values unchanged
for identical inputs. Focused library/CLI and release builds pass; native large
qualification pending. No unit tests added/run. See docs/journal-preparation-readback.md.
This candidate is separate from the sealed3ce15c7 tail recovery matrix
completed above; its native evidence does not qualify this newer candidate.

The following results and former current VM/checkpoint labels are historical.

Partial-tail normal runtime3ce15c7/public831b073d38ec0bd62350e97f01ed1b51cc5a29ced46cd3b69d37372864d08b53
passed wrapperc42d891b/coree28bab21: native0/HND and wrapper0,44 objects/53 bindings,
0 target content hashes/reads, all30 default+9 named independent hashes and prior
fixtures. Actual14 extent-only streams/4,489,673 logical bytes include the old2
whole-aligned streams/4MiB and12 new partial-tail streams. All457 visible tail
bytes have actual source/write-flush/readback/identity receipts and protected
residual SHA matches. Initial raw hashing159,222,314B remains for full fallbacks;
remaining native source reads86,659,954B. Nativewall24.630s is one uncontrolled run.
The newtag remains distinct from whole extent_identity_v1. Record85 named.bin
default65,553B is independently proven plain while sibling Encoded flags1 keeps
its real full digest/decoder/materialization. No compressed protection was removed.

Initial3d3d009 case d2652438 refused at source-observation on the old file-wide
compression guard, before any source payload write. Its71 metadata files/12,328,464B
and checkpoint0cf18d65 remain. Corrected success has133 closed metadata files/
86,221,996B SHA verified under partial-tail-success-c42d891b. Current VM Off/RAM0
at ReFS checkpoint3cbc9ae0-c7da-49ab-bd08-ca0c48275f03,50 snapshots; tasks/workers
were terminal/idle before normal stop. Actual lab264,253,771,757B/free80,898,650,112B
remain within the unchanged epoch. Obsolete228c7aa3/e9bc8adf were removed only via
Hyper-V after archive rehash; all host metadata/baselines remain. Keep old normal44c,
int9ce/resume9bb/NTFSb809, sources371/6fe,large785,D1cold d939,f4bf and current/refusal.
Evidence: evidence/partial-tail-extent-native-20261031.json; docs/partial-tail-extent-verification.md.
Runtime3ce15c7 and harness eac8b83 are distinct. No tail recovery, F-scale,
mutation/cold-boot/power-loss qualification transfers from this normal case.
The exact7ced whole-cluster recovery matrix below remains separately preserved.
Focused builds pass; no unit tests added/run. D2 and broader objectives remain.

Exact7ced recovery matrix now passes one controlled first-flushed-write case.
Interruption07247cfa actualPID5484/creation1793470826071 exited86, source6 stayed
offline writable/managed shadow offline read-only,2 unread streams/4MiB and the
53-binding map manifest stayed pinned by bundle63054c5acd048eff4c3aa00951c1b2fd1a1354157007e5cd1dc26fe1767584dd.
The interrupted checkpoint9ce156c3-f080-4720-ab6d-a8abf3c90cfb remains for audit.
Public Resume57285c7e observedapply_intent→resume→HND, native0/ReFS and37 known
full stream hashes/64,869,591B plus2 pinned-map streams. All39 independent lab
hashes match. Its PS5 observer initially failed on array enumeration AFTER native
success; separately recorded parsing of actual completed helper stdout qualified
the39 hashes with no recovery rerun or additional target reads. ReFS checkpoint
9bb675b9-fde4-4f39-8df5-124902598188 and original failure remain preserved.
From the SAME saved86 parent, public Rollback86384798 passed native0/ABT,
old-selected checksum equality and NTFSH:/4KiB/label plus all39 independent hashes.
Rollback timestamps are covered by the closed old-byte journal proof; no separate
post-rollback timestamp comparison is claimed. No completed HND/ABT was replayed.

Current VM Off/RAM0 at NTFS checkpointb8091885-73f6-41f8-a24d-dfed3ce8b599,
50 snapshots; native/tasks were terminal/idle before each normal stop. Metadata
archives extent-firstwrite-07247cfa(71 files/77,454,834B), extent-resume-57285c7e
(32/5,370,275B plus separate completion receipts), extent-rollback-86384798
(35/2,196,473B) are SHA verified. Actual lab264,392,061,107B/free80,827,138,048B
remain within the unchanged epoch. Obsolete764b57bf/058f1ca5/26607589 were removed
through Hyper-V only after rehashing retained archives; ALL lab baseline files stay.
Keep normal44c, interrupted9ce, resumed9bb, currentb809, sources371/6fe,large785,
D1cold d939 and f4bf. Evidence: evidence/raw-extent-recovery-matrix-20261031.json.
This is controlled exit86 plus clean restart, not arbitrary fault/power-loss
coverage. No new mutation, broad cold-boot/full-map or physical-power-loss claim.
No unit tests added/run; D2 and broader compatibility/boot/scale remain unfinished.
The normal result below remains qualified; its former current VM state is historical.

Runtime7ced37b/public97990e9ecd5ead33511e18ef7ca8d79f2ed302546344f89efec058dc24b40af7
passed normal H conversion aac022f8/core19ebb0e6: native0/HND and wrapper0,
44 objects/53 bindings,0 observed target hashes/0 target payload reads. Record47
default and Segments(2MiB each) are explicitly RawNotRead/shaNone/source_evidence;
initial raw hashing159,517,683B is4,194,304B below the full163,711,987B baseline.
Native source request4/report12 omits those2 reads, while full fallbacks read
86,955,323B. SVI tracking.log20KiB stays full. No all-payload/zero-initial-read claim.
The preactivation recovery map-facts manifest is pinned by the bundle and binds
expected tree/plan/ticket/source/selected data with53 maps; no write authority.
Normal run26.646s is a single observation, not a controlled/general I/O speed claim.

Independent lab reads passed30 default+9 named hashes and all prior fixtures.
The separately pinned old full-content baseline is lab-only.22 historical access
time differences are recorded against CURRENT raw/native-source/target metadata;
all other canonical fields remain exact. Only the existing source-absent indexer
SVI-directory interval is an explicit target-time exception; product JSON and
filesystem times are untouched. Closed133 metadata files/86,066,547B are SHA
verified under raw-extent-success-aac022f8. Saved normal checkpoint44c48db9-c9ad-452f-8811-ce32a170c979
remains preserved; all workers/tasks were terminal/idle before normal stop. Then lab actual
265,872,180,636B/free79,310,647,296B remain in the unchanged storage epoch.

Keep this qualified normal result and source371/F:source6fe/large785/D1cold d939/f4bf.
Earlier12ca824 refusal a77acce3 (SVI copy needed a digest) wrote0 source payload;
74 closed files/74,894,901B and checkpoint764b57bf remain.6901003 native21ea533c
used full raw fallback (0 elisions), then its observer failed on empty-property
enumeration;103 closed files/84,376,938B and checkpoint058f1ca5 remain. Neither is
a successful initial-scan-elision result. Obsolete904cbd98/30b37828/863e9372 were
removed only through Hyper-V after their retained archives rehashed. No replay.
Evidence: evidence/raw-extent-verification-native-20261031.json; docs/raw-extent-verification.md.
Focused builds pass; no unit tests added/run. The exact7ced controlled
interruption/resume/rollback matrix above is now separately qualified. Broader
scale/compatibility/power-loss work remains.
The following results and VM states predate this normal qualification.

Runtime e606c53/public d0033a8b2dd1dd20e0c92ea62eb6040ded8a615b78de8ecc11b972954491accf
passed native wrapper95833c80/corec2e31ace: exit0/HND,44 objects,53 complete
object/stream map bindings,0 observed target hashes and0 target payload reads.
Native wall34.826s. Source request4/report12 explicitly omitted native hashing
for3 streams/4,214,784B; remaining native reads86,934,843B. Initial raw NTFS
inspection still hashed163,711,987B: no zero-initial-read claim. Source fingerprint
covered96,272,384B and explicitly omitted7,655,424B; it is not a content digest.
Full-content/recovery checks and D2 deferral remain. No unit tests added/run.

The original observer failed AFTER native success on an empty symlink because
its lab helper refused reparse points before reading. Native conversion was
never retried/replayed. Failure archive100 metadata files/82,719,759B is retained
under extent-native-observer-failure-95833c80. Separate fixed helper543444f/SHA
232fbf271c363a504152347dd7cd7e64d91d903f3f7ff63b0b3c335449e3559f passed fresh
read-only completion75e152b3: all30 default+9 named hashes, prior alias/sparse/
attribute checks,7 EAs,8 security identities,6 reparse buffers and7 compression
hashes. Its40 closed metadata files/2,457,084B are SHA verified separately under
extent-readonly-success-75e152b3. Native and observer timings/counts stay separate.
Tracked EA/reparse binders accept report12 only paired with request4; old paths
and complete field checks remain. Evidence: evidence/extent-verification-native-20261031.json.

Current VM Off/RAM0 at native-completed checkpoint26607589-a002-4e25-9102-199ef9fc52e7,
50 checkpoints; all tasks/workers terminal/idle before normal stop. Completion
metadata is archived; no extra snapshot was created at the50-slot limit.
Prior904cbd98/source371ae756/F:source6fe2d6b6/large78513f35/D1cold d939f576 and
f4bf5238 remain preserved. Obsolete db10c68f was removed through Hyper-V only
after125 archived files/83,267,193B rehashed. Actual lab264,785,508,129B and host
free80,448,499,712B remain within the unchanged epoch. No new recovery/mutation/
power-loss or broad cold-boot/full-map qualification. Initial retained-payload
inspection elimination and broader scale/compatibility remain unfinished.
The following native results and VM states predate this runtime.

Latest native D3 stage runtime19569cb/public2e014b6be32710d19f6beacd7ab8d97ab57c7f887ae6df702de0310933431c6c
passed wrapper59939273/core12c9a91c: native0/HND,44objects/30default+9named hashes,
all prior sparse/EA/security/reparse/compression checks, label/mount preserved.
Source/targetfilehashesremainFULL(actual_full_file_hashes=true); the hash-free
retained-extent/source-certificate path is unfinished. Exact primary raw gate
opened SHARE_READ only; secondRW open refused native32 whileattrs3; the same
held gate transitionedattrs3->1 andflushed persistence. No global administrative/
volume-alias exclusion claim. V2raw bracket reads everycoveredbyte twice:
6,174,121,984B/5,897chunks each;5,815 actualzero digestcachehits leave76,652,544B
innerSHA256 work each. Nativewall36.731s vsfirstD3stage89.042s(processcreation
to terminal); priorD1baseline32.852s remains faster. Single-run/cache scope only.
Closed125metadatafiles/83,275,284B SHAverified underfast-v2-success-59939273.
CurrentVMOff/RAM0 at904cbd98-f87c-4a30-91c0-dedda106062f,50checkpoints, all
workers/tasks terminal/idle before normalshutdown. Source371ae756, F:source6fe2d6b6,
largeReFS78513f35 andD1cold d939f576 remain. Obsoletecompressioncold8e9562df
removed only viaHyperV after17closedfiles/3,744,688B rehashed; f4bf5238 untouched.
Actual lab264,124,875,345B/hostfree81,210,093,568B within unchanged epoch.
Evidence:evidence/fast-v2-native-20261031.json. No unit tests added/run.
No exact-build recovery/mutation/coldboot/powerloss claim. Next: complete the
authorized hash-free retained-extent certificate and source read-pass work;
D2 remains unapproved. The following prior-milestone VM states are historical.

Large fd577f2 run17c1dd7f/core9a59ede9 completed insideVM:933objects/811 complete
stream hashes,808userfiles/120directories/9,885,781,381B, label/mount correct.
SourceNTFS64K F: source6fe2d6b6 became nativeReFS4K samepartition. Retained
4,225,028,096B/903coordinates; barrier122187us exposedexactevacuated3,746,791,424B
asactuallyfree (desiredfree75,542,528->3,822,333,952). Literalbacking38,400,000B,
journal11,430,978,272B. ActualJ<16GiB; schema3requestedcapacity29,697,802,240B
doesNOTproveactual>16GiBjournaloperation. Full-content run1387.317s (23min);
latephaseincludeshandoffchecks, notjustnativefileverification. D3fastnotpartofit.
Closed57metadatafiles/136,316,706B under mixed-capacity-success-17c1dd7f; saved
ReFS checkpoint78513f35-5309-41ce-806f-c2358b4e2f7d remains separately preserved.
See evidence/mixed-capacity-native-20261031.json. Cold/recovery/mutationpending.

D3candidatefirststage: defaultExtentIdentityV1requestpolicy/full-contentflag,
exclusivefreshapply-throughHND(normalowningprocessonly), exactraw-shadow
consumed-byteSHA256brackets excludingONLYauthenticatedoverlaidpayloadroutes,
old/newmemcmpfastpathwithsamebytefallback, advisoryphaseprocesscounters.
ACTUALsource/targetfilehashesstillFULLandexplicitlyreported—doNOTclaimthe
hash-free retainedcertificatepathisfinished. No fakecontentdigests.Fullmode,
faultentriesandfreshrecoveryretainlegacycompletechecks. See docs/fast-verification.md.
Librarycheckandfocusedpublic/verifier/bindreleasebuildspass; nativeD3stage above passes.

D3 decision (2026-10-31): the user chose "Use extent-based fast verification
(Recommended)" as the default, with full-content verification retained as an
option. Prove unchanged retained payload by exact metadata and physical-extent
identity; checksum moved/rewritten bytes during their read/write passes to avoid
repeated full-payload scans. Namespace/ACL/allocation/full retrieval and fresh
recovery checks stay. Represent hash-free evidence explicitly; never fabricate
content digests or reinterpret a metadata fingerprint as a full-content hash.
D2 incremental retrieval remains unapproved. Implement the fast path with
explicit in-process ownership/immutability and keep legacy full mode available.

Retention barrier candidate: the large source's960 raw DATA identities/maps and
933 canonical objects match both old runs. All first1,561 moves (50direct,
644scratch,867evacuation), complete post-move mappings and evacuation plan
match. Final placement diverged: old156 had557final/3,084,886,016B retained,
909 had504/2,888,302,592B, d974 had10/478,236,672B. Availability timing is a
hypothesis, not a proven cause. New code preserves the pre-barrier complete
maps, flushes only the owned shadow volume after actual evacuation, checks
source exclusion, and recaptures both full maps for final planning. It records
actual before/after free bytes/hashes/counts; never assumes bits became free.
Supported FlushFileBuffers only, no private checkpoint control/sleeps/retries.
Focused release builds pass; barrier+capacity native run is next. See
evidence/mixed-capacity-refusal-20261031.json. Current VM Off/RAM0 at restored
mixed NTFS source6fe2d6b6,49checkpoints, no active worker. Keep failurece9b92c2.

Capacity candidate: schema3 pins journal capacity in requests/bindings/tickets/
immutable manifests, removes the public allocation route's16GiB ceiling and
shares one measured scratch pool with independently capped literal backing.
Per-append D/L/combined checks plus advisory live storage checks run before
capture writes; exact journal sizing/free checks precede source activation.
Recovery uses pinned original ceilings, never remaining free space. Legacy1/2
serialization and dense bounds remain. Checked-reader typed comparisons remove
temporary JSON allocation/cloning but preserve every boot/MFT/record reread.
Focused library/public/verifier/bind release builds pass; native schema3 pending.
See docs/capacity-pinned-journals.md. No unit tests added/run.
Large sealed d974efe run98153ebb/core51e20d11 on original808-file/120-directory
9,885,781,381B NTFS64K source6fe2d6b6 reached qualification, then refused before
activation: selected journal exceeds16GiB caller budget. D15,139,008,512B,
literal3,784,351,744B; both disk1 and target stayed protected. Closed metadata43
files/94,647,385B under mixed-window-budget-refusal-98153ebb; failure checkpoint
ce9b92c2-85c5-4754-82e3-62d877ab5726. Current VM Off/RAM0 there;50checkpoints.
No active worker/task. Original F: source6fe2d6b6 and H: source371ae756 remain.
Obsolete read-only probebd7e1ec6 removed after rehashing its closed archive;
all evidence retained, cleanup receipt under mixed-scale-obsolete-checkpoint-cleanup.
Next: seal the capacity build and rerun the exact mixed source, then qualify
the new capacity recovery path. Never change/stage the user-owned main.rs hunk.

D1 decision (2026-10-31): the user chose "Use destination windows
(Recommended)" after the preserved14-case probe. Per-move bitmap queries may
cover the exact destination window under both selectors. Keep complete phase
snapshots, full file retrieval/all-placement checks and final allocation
validation. Window evidence must remain explicitly scoped, separately typed
and replayable; never put a window hash in a full-map Candidate. D2 incremental
retrieval remains deferred. Update the move-proof schema and pre-I/O evidence
budget together; lossless transcript compression is allowed, truncation is not.

D1 runtime d974efe/publica9552ccf7402e5341a1104e5fc20a268896c295372b03f8c68e9c4fb2d022fd7
passed conversionfea0a1ec/coreeb9a8205 in32.852s versus08dd747's114.735s on the
same saved source fixture (71.37% shorter; single-run scope, no HDD/physical-I/O
guarantee). All44objects/30default+9named hashes, previous EA/security/reparse/
sparse/attribute-list fixtures and4MiB/1,024 original extents pass. All1,044
move intents and complete after-mapping buffers match08dd747. Sealed replay
passed2,088 destination windows/queries,8,552,448 returned bytes,3 complete
phase-map snapshots; full pre/post retrieval remains. Placement schema2,
destination-window-v1, lossless compact transcripts; no Candidate hash spoofing.
Report62,144,751B remains under64MiB. Journal+backing95,292,928B.
Normal ReFS checkpoint8a53c8cc; coldc7fd1596 passed all44IDs/maps,10aliasIDs,
39hashes,7EAs and7 independent compression hashes. Current VM Off/RAM0 at
d939f576-4868-43d0-bde8-2a6f742dd489;50 checkpoints, no active workers/tasks.
See evidence/destination-window-native-20261031.json and docs/destination-bitmap-windows.md.
Source371ae756 remains. Obsolete697fb084/95e64fda branches were removed only
after archive rehash; all closed evidence remains. Legacyf4bf5238 was left
intact after archive mismatch, never force its deletion to bypass that guard.
Latest actual lab233,753,210,132B; D free111,579,803,648B, unchanged storage epoch.
No unit tests added/run. No exact-build recovery/mutation/power-loss claim.
Next: scale the retained native workload and replace remaining coupled fixed
resource ceilings with pinned capacity; D2/full-hash changes need their own
decision. VSS/case flags and broader compatibility/boot work remain unfinished.

Performance runtime08dd747/public550ac571641cbb13beb5e6716e1212c2c3bd20782c4f259a01e1775a6a319b51
passed conversion9f58c4cd/core09a6b41a and cold boot3b76ebb8:44objects/39stream
hashes, all prior fixture checks and original4MiB/1,024 extents preserved.
All1,044 ordered move intents/full after-mapping buffers, original-coordinate
rows and counters match a126b18. New walltime114.735s versus94.686s provides
NO speedup claim; host/cache conditions were not controlled. New CPU lookup,
merge and prefetch memory complexity is lower; full bitmap query cost remains
on this runtime. Evidence: evidence/planning-performance-native-20261031.json.
Normalcheckpoint228c7aa3; current VM Off/RAM0 at coldcheckpoint
863e9372-f81a-444a-a3d3-595ebc5d81f0,50checkpoints; workers/tasks terminal/idle.
Obsolete failed leavesddf5e717/0bf53231 were removed via Hyper-V after archive
rehash; receipts under .lab, all evidence retained. No unit tests added/run.
The newly authorized D1 code is a separate candidate, not covered by08dd747.

Compression milestone: runtimea126b18/public358d99f158e103625266c4c744f0230c8d4a1016fa129fa6bd106ae4e3c181e6
passed public conversiona1cc190f/core69169b55 and cold bootccafd9f0:44 objects,
30 default/9 named hashes,7 EAs,3 sparse layouts,8 security identities and6
reparse points. All7 independent compression-fixture stream hashes match.
Four nonresident LZNT1 streams (2,687,224 logical bytes) and2 resident-policy
streams (64B) become ordinary ReFS data;7 identities record normalization.
Compression padding is never exposed as logical holes or retained payload.
Original uncompressed4MiB/1,024 extents remain in place. Cold boot preserves
all44 canonical IDs/maps,10 alias IDs and all prior hashes/metadata. It adds
no new source-retention comparison. Runtime94.686s is not a controlled speedup.
Journal89,071,680B plus backing6,701,056B. See
evidence/compression-native-conversion-20261031.json and docs/ntfs-compression-normalization.md.
Source371ae756-faf2-40ac-bf86-5e8e1d744e30 and normal ReFS30b37828 remain.
Current VM state is Off/RAM0 at cold ReFS8e9562df-3c32-428f-a981-a0a48bec5d08;
50 checkpoints remain. All workers/tasks were terminal and idle before stop.
No new-build recovery/mutation or physical-power-loss qualification is claimed.
First eec8ca5 admission refusal d7a673a8/core33bc5f7e demonstrated resident
DATA/index compression policy; its63 closed metadata files remain archived.
Obsolete failure leaves44048279,9d98ce2a,f96b8890,8c1e5d14 were removed through
Hyper-V after rehashing their retained archives; cleanup receipts are in .lab.
Never recreate historical checkpoint IDs or replay a completed conversion.
Latest actual lab232,342,078,205B; D free112,996,507,648B, within the unchanged
storage epoch. No unit tests were added/run; only existing fixture literals
gained the new optional field. The user-owned main.rs overlay stays untouched.
Remaining priorities: performance/resource-bound scale, complete source
admission (including VSS/case flags), and exact-build conversion/recovery
qualification. The broad volume-size/compatibility/boot goal remains unfinished.

Work in D:\code\ntfs2refs, branch codex/isolated-journal-observation.
The branch tracks the same origin branch. The existing one-line src/main.rs
capabilities change belongs to the user; never edit, format, stage or reset it.

Prior reparse milestone was saved at cold-boot checkpoint
95e64fda-d3b1-4a3b-9bf5-c2ec161d2b18. The latest compression state above is
authoritative. The attribute-list NTFS source is1057eb82-d152-4572-881b-53ff9dbb82dd;
the earlier clean sparse NTFS source is9c42e1fd-435b-401c-b261-53ab433ca2f6.
Prior performance runtime940f4e2/public95086126968afeaf73a46644401086c218959ca559d9480084ecac8593223b98
passed same-source conversion610f3f55/core2cf74f00 in92.959s versus138.754s on
4c58d38 (33.0% shorter in this fixture). All13objects/9default/8named hashes,
3sparse layouts and1024 original payload extents (4MiB) match. Movement counts
and phase snapshots also match. Evidence: evidence/bitmap-planning-performance-20261030.json.
No reboot/mutation/recovery qualification transfers to940f4e2 from older builds.

Prior runtime4c58d38/publicf7e432babadcc7761a855a8d7c00069b7bbed9505fd37a53512d6f061c969cf6
passed public conversion29db7e40/core60e84507:13 objects,9 default hashes,
8 named hashes and3 sparse layouts. Source record47 was assembled from its base
plus7 extension records, including resident filenames/Note ADS and two fragmented
DATA streams. All1024 payload extents (4MiB) remained at their original physical
clusters. All3names/3streams passed9 independent SHA256 checks. Cold bootd61535ea
preserved all hashes, IDs and prior fixture observations. Evidence:
evidence/attribute-list-native-conversion-20261030.json. Original converted
checkpointcafe187b-5f44-43e4-b1d9-d71dac5c0f50 remains separate.
The original observer stopped AFTER native success because raw-only
inventory_complete is false for recognized internal metadata; a corrected
read-only observer verified47 physical records, the full assembly and native
admission. Never replay/rerun a successful conversion to fix an observer.
Placement now uses ordinary carriers for nonsparse ADS; the driver returned
success without moving the original named-stream handle in the failed run.
Full mapping verification, carrier clone/retirement and stream flags remain exact.
Next: reduce redundant bitmap hashing/planning work without dropping coverage,
expand remaining NTFS metadata/geometry support, and qualify new-build recovery
and mutation separately. Current bounds and general-compatibility gaps remain.
No unit tests were added or run. Keep the user-owned main.rs overlay untouched.
The performance implementation reuses opaque original-collector first-page
evidence instead of reprocessing/rehashing it during live bitmap capture.
Untrusted replay remains unchanged. Streamed retention planners validate the
two immutable summaries once per phase and binary-seek relevant ranges; they
are dropped/rebuilt whenever drift refreshes the observations. Every per-move
native bitmap and retrieval check remains. Library check and focused public
release build and the native same-fixture comparison pass. Native query coverage
was not reduced; physical I/O reduction was not measured. The large-volume cost
of full per-move bitmaps and remaining fixed resource caps are still unfinished.
The new bitmap_window/native modules and lab-probe-bitmap-windows binary are
read-only D1 preparation. Window proofs have a distinct encoding and retain
raw queries for replay; they cannot populate full-map Candidate hashes or
authorize moves. Focused probe build passes. Production per-move checks remain
full-volume pending the recorded D1 user decision. No converter is active.

EA continuation (2026-10-31): runtime2aef493/public03c4f68d94a53c4d501b9d64a0fd899c3200985ce1b9a7f4d700adab31e7854b
passed conversion1a715809/core5dc4f41a:17 objects,11 default hashes,8 named hashes,
3 sparse layouts and7 EAs on4 identities. Complete raw/native EA capture uses
schema10 streaming reports, constructor-owned restoration and exact native
target/alias verification. Normal runtime88.731s is not a controlled speedup.
Journal81,446,208B plus backing3,637,248B; 1,024 original payload extents/4MiB
remain in place. Cold bootfb24a6f2 with read-only observer737f994/public2bbd40b56c11d6a45a67226bf64b9e0329b7803c0b350f37572b00e94c784c75
passed17 objects/19 stream hashes, all7 EAs and unchanged data mappings/IDs.
The observer uses the actual pinned allocation bundle; it never replays a
journal or manufactures a source certificate. An older observer721aa4db failed
before queries on the public-request format; no conversion was replayed.
See evidence/ea-native-conversion-20261031.json and docs/ntfs-extended-attributes.md.
The NTFS EA source is1fc4b960 and initial converted ReFS is2c964314. No mutation,
new-build interruption/resume/rollback or physical power-loss claim is made.
No worker is active. Next: explicit VSS/case flags, remaining reparse forms,
resource-based scale and the recorded D1 decision; no unit tests.
Fixture
80607d54 passed7 EAs on4 identities (2dirs/2files), binary/8192-byte values,
FILE_NEED_EA and a hard-link alias; its SHA is826aa04171efa8ae85ec4ca867bf743fdaaf16f5ae5cfbd2caa0dfe3a24af2c0.
Public runfc890481/core00b08d0d stopped before activation at source admission:
raw SI includes internal0x40000 on EA objects but Win32 omits it. The correction
projects that bit only with validated nonempty EA storage and keeps raw SI,
native EA equality and cached-access policy unchanged. Failure metadata39 files is
under .lab/hyperv/streaming-v2-20261027/ea-attribute-refusal-fc890481; checkpoint
2c8164d8-a785-4640-ae78-236ed380cbf5 preserves it. Do not replay that failure.
Earlier empty-EA immediate-status refusal3aff6405 is preserved in286e2588;
the backend now distinguishes untouched IOSB from actual completion using a
sentinel and accepts only the two exact no-output terminal statuses. Unknown
queries remain errors. No unit tests were added or run.

Security continuation: runtimefa6396f/public00899bf5e046d767f8548d3979ac8674769b8e25008b1638d36e24ab71ba4975
passed conversiona8b54a6e/cored9ba5a9c and cold bootd85aca0e:25 objects,
18 default hashes,8 named hashes,7 EAs,3 sparse layouts and8 security identities.
Audit SACLs, mandatory labels, inherited auditing, null DACLs and empty DACLs
match actual source semantics. Seven independent security-file SHA256 checks
use read-only backup handles, never permission repair. All25 kernel/API SD
buffers, file IDs and data mappings match after boot. Runtime80.593s is not a
controlled performance comparison; 4MiB/1,024 payload extents remain in place.
Journal82,299,808B plus backing4,014,080B. See
evidence/security-native-conversion-20261031.json and docs/ntfs-security-preservation.md.
The NTFS source is684b9c4c; normal ReFS isa18bf3a5; cold ReFS isc6345e1f.
The fixture records requested versus actual descriptors. Windows normalized
requested absent DACLs and empty SACLs to null on NTFS creation; do not claim
those original source states were qualified. No converter normalization or
control/presence masking is permitted. Native validation preserves complete
ACE/control bytes and restores both protection bits; getters remain0x1f and
source schema10. No mutation, new-build recovery or physical-power-loss claim.
Hyper-V hit its50 checkpoint maximum. User-authorized deletion removed obsolete
EA failure leaves286e2588 and2c8164d8 through Hyper-V APIs; all archived metadata
remains and cleanup receipt is under security-coldboot-d85aca0e. Their old IDs
are historical, never recreate them. The active sources and qualified results
remain. No unit tests were added or run.

Reparse continuation: runtime439a55c/publicc347053ff08aa2182d296680f2bdda0dcdca538abb4df999bc04526cdde0f96d
passed conversion2ef04a07/core3c735fbe and cold boot7270a96c. All36objects,
24default/8named hashes,7 EAs,3 sparse layouts,8 security identities and6 point
buffers/tags match. Complete NTFS $R index binds all6 supported points. Four
known routes resolve on ReFS; dangling/cycle routes are metadata-only, never
followed during inventory. Cold boot preserves all buffers/IDs/data mappings.
Normal runtime90.884s is not a controlled speedup. Journal83,164,544B plus
backing4,374,528B; 4MiB/1,024 original payload extents remain in place.
See evidence/reparse-native-conversion-20261031.json and docs/ntfs-reparse-preservation.md.
The NTFS source ise4186f31, converted ReFS is9bfbe6f7 and cold ReFS is95e64fda.
Source schema11 binds exact GET/tag/buffer data, distinct from missing/error.
Points install after ACL propagation/EAs and before basic timestamps; symbolic
privilege is separately restored. Supported tags are MS symlink/mount point.
File-link nonempty DATA/ADS/sparse, root/provider/cloud/spill remain refused.
Case-folded canonical/alias ancestry checks forbid point descendants.
Fixture5dc696e6 succeeded; earlierd947 failed beforecreate on private SD packing
and is archived. Native run31a5fece refused beforecutover on EOF-zero ReFS
inline capacity1024B; the fix proves an actual empty retrieval map before SET,
never ignores physical runs. Its branch/62 metadatafiles remain separately
preserved. No new-build recovery/mutation/power-loss qualification is claimed.
Hyper-V is at50 checkpoints: remove obsolete failure leaves with retained
archives through Hyper-V APIs before another checkpoint; never delete AVHDX.
The user-authorized obsolete ATTRLIST failure leavesb3f9ffae,865bf7b0,e92ade3b
were removed through Hyper-V APIs with closed archives retained; cleanup receipt
is .lab/hyperv/streaming-v2-20261027/reparse-obsolete-checkpoint-cleanup-20261031.json.
Those old checkpoint IDs are historical, never recreate them. Current NTFS
sources and qualified ReFS/security/EA branches remain. No unit tests.

### Previous milestones and fixture setup

Source5aeaf40/public61d4cd998a19e8ae825e67fd515c3f4316f6dccc2936fdec97e6d7c3f28fb01b
completed public H:/partition2 conversionba1480fc/coreb8d43b36 inside the VM:
native0/HND,12 objects,8 default hashes,6 ADS hashes,3 exact sparse layouts.
The all-hole16MiB file has zero data allocation; sparse ADS and the default
islands file have131072 and135168 allocated bytes respectively. The123-byte
EOF tail may relocate; its contents match and3973 padding bytes are explicitly
accounted. Full clusters keep strict mappings. See evidence/sparse-native-conversion-20261030.json.
The original wrapper expected10/6 objects/default hashes and failed AFTER native
success because two admitted SVI files were also preserved. A separately pinned
read-only observer6dea523b verified all12/8, all9 old link names/15 ADS views and
4 sparse paths. Never rerun or replay the completed conversion to fix a wrapper.
Converted checkpoint496bcf38-53ac-49ab-9551-2d4e24651f32 is preserved separately.
Cold boot65dff08d passed live hashes, sparse flags/extents/file IDs and old link
IDs unchanged; it does not claim a new storage-validity query after boot.
Archive64 closed files: .lab/hyperv/streaming-v2-20261027/sparse-success-ba1480fc.
The same runtime now passed sparse first-flushed-write interruptionc6ced707,
guest restart with disk6 still offline, public Resumeb22ef74e and independent
Rollback76cd0c1e from the same original bundle
d16bede65e4f0e450bf48fb81b5d2fb219fb290f462107e9f03b6da8ac76e996.
Interrupted statea6497e33, resumed ReFS37414e94 and restored NTFS1ad67365 are
preserved. Both directions checked9 old names/15 ADS views and4 sparse paths;
rollback matched original file IDs and exact sparse extents/flags/EOF. See
evidence/sparse-native-recovery-20261030.json. This is a controlled stop, not
physical power loss or arbitrary interruption coverage. Sparse mutation is pending.
Next code work: extend ordinary ATTRIBUTE_LIST assembly for hard links/ADS.
The existing assembler already handles a narrow single-link/unnamed stream
case; do not delete the admission refusal. Extend a versioned assembly profile,
match exact stream names and local instances, replay the physical-record ledger
in ntfs_assembled_io/ntfs_inspect, and keep unsupported spill forms refused.
The new candidate implements schemas5/6 with per-stream DATA assembly, resident
metadata in owned extension records, canonical-to-physical attribute origins,
and exact rereads before resident/stream access. Legacy profiles remain separate.
Focused library check and release builds of ntfs2refs plus the new
lab-create-attribute-list-fixture helper passed; no native qualification yet.
The helper uses only NTFS file creation and FSCTL_MOVE_FILE on enrolled H: to
force fragmented streams, confirms a real ATTRIBUTE_LIST and preserves failures.
Candidate code is committed inaff21d0. The sealed public executable is
7547b3732706b2548d96db1615d68b797a7d8a8fddf3e0b3113caf442089392f
under .lab/hyperv/streaming-v2-20261027/attribute-tools-aff21d0.
Fixturec1f6b081dac24e158708c97ef3151934 completed all1024 verified moves and
compared payload hashes, then stopped in the final FSCTL file-record observer
on its update-sequence assumption. Its actual files remain intact at637d286f;
do not repeat their creation/moves. Closed fixture report SHA
44c863bf6c6688a7674d0527c43070330adea68846930ff18784f3819cc298cb
is under attribute-fixture-c1f6b081dac24e158708c97ef3151934/closed.
Read-only completion3bf491a3 passed after flush (same strict USA check), fixture
SHA df017eca451b3daeadfe49cd04bc8043205523e7a0253e6cadc7f03b254434ee.
Public candidate run d4068724/coreb53879d6 accepted schema5 for record47 with
7 owned extensions and7 canonical attributes, then refused shadow placement
after511 final submissions. Failed branchb3f9ffae-1aa7-40c2-b59d-a6953416bbff
and42 metadata files under attribute-list-convert-d4068724549f496f815718e997088958
are preserved. A SYSTEM read-only query showed all512 default-stream target
mappings already at the expected source LCNs. The prior error discarded the
native status. Diagnosticf76af24/runffc6caa3 proved the default512 moves succeeded;
the first Segments ADS move returned no native error but retained its old mapping.
Failed branch865bf7b0-5735-42db-8a29-2bafed0ca0cf and40 metadata files are preserved.
See evidence/refs-named-stream-move-mismatch-20261030.json.
The new candidate places ordinary ADS >=4KiB through owned nonsparse carriers
and clones the measured extents into nonsparse target streams. Sparse behavior
and exact mapping checks remain; no success return alone grants retention.
Unwritten placement now validates each complete retrieval map once and indexes
matching intervals without omitting any tracked-range or bitmap checks.
Focused release build passed; candidate native rerun is next. No converter is active.
Candidatead8516b stopped before placement on the older carrier-association
guard; failed branch e92ade3b-7227-4897-873c-889fa0f317ef is preserved. The
guard now validates ordinary named carriers as exact full, hole-free layouts
and sparse carriers against their exact source layout; counters distinguish
the two. Focused release build passes; next rerun uses the same observed source.
Earlier helper-only refusals are preserved under attribute-fixture-68d14605
(read-only discovery flag), -9d172c41 (resident allocation observation; checkpoint
9d98ce2a) and -eed02ff5 (temporary preallocation tail; checkpointf96b8890).
Keep current binaries/evidence/checkpoints. No unit tests were added or run.
The earlier EOF, dense-prefix and directory-aggregate sparse flag refusals are
preserved in0bf53231/f4bf5238/289cf0f3 and their matching sparse-*-refusal folders.

### Earlier development observations (not current VM state)

Sparse integration candidate: SparseLayout now binds allocated islands, exact
logical holes and source VDL per default/named stream. Native construction uses
compact dense carriers, moves those data ranges, clones them to sparse logical
offsets, and retires only its own carriers. All-hole streams have no carrier.
Core copy/retained plans use allocated initialized data only; hole tails are not
materialized. Existing plain digests and nonsparse serialization are unchanged.
The public release build passes, SHA
9205002edbe79b35f17eaa17b31142cf30c416878fcbbb101168062b025afc87.
Native sparse conversion remains unqualified pending the new fixture/run.
The Rust sparse fixture helper builds (98ea44c36ed5132c377ec1b2fb23322b5f81d0345f662c3a89645ce3a99fa459);
it creates only new H: sparse files/ADS and preserves old data. No unit tests.
VM is currently running the preserved NTFS baseline7f926b79 for that fixture;
all21 checkpoints remain. Do not use the old ADS qualification for this build.
The first sparse public attempt48579f7c/source307173a stopped before source
writes during source-view reconciliation. Raw NTFS SI marks ordinary.bin
0x220 because its ADS is sparse, but the default handle correctly reports0x20.
The source projection and canonical default attributes now derive only bit0x200
from the unnamed stream's flags; raw SI is retained unchanged. Saved replay
now matches all user views, with unchanged stream/data/namespace comparisons.
Failure metadata is in .lab/hyperv/streaming-v2-20261027/sparse-first-refusal-48579f7c,
and failed VM checkpointddf5e717 is preserved. Sparse NTFS fixture9c42e1fd
has been restored for the corrected attempt; all23 checkpoints remain.
Corrected public hashd03b72dac69f09ef7f3021dbaf9c45dc161e2051c992ef451632bd8e6867064f
is built; native retry remains pending. No unit tests were added or run.
That retry5467246c/source18861e2 passed source reconciliation and stopped before
source activation on the sparse materialization receipt contract. Sourcea19d9e8
now returns a SHA256 over actual assembled carrier readback, with zero holes,
and rejects nonzero hole input. The 32 failure metadata files are preserved in
.lab/hyperv/streaming-v2-20261027/sparse-materialization-refusal-5467246c;
checkpoint697fb084-a4b3-4769-b3d8-eea768c70fea preserves the entire attempt.
All24 checkpoints remain. The VM is running source checkpoint9c42e1fd for the
next corrected build; no conversion worker is currently active. Final sparse
flag verification is exact per stream, and source VDL is explicitly recorded
without claiming equal numeric target VDL. Logical zero semantics require the
final full-stream digest. Keep both prior failed branches and binaries.

Latest state: VM is Off/RAM0, parent7f926b79-465f-4945-a00b-bdaae2607cd4;
all21 checkpoints remain. Disk6/H: is verified NTFS after ADS rollback. The
latest branch also preserves a separate owned ReFS sparse-probe volume; never
reuse its binding as a conversion source or treat it as the H: fixture.
The ADS build3ba75be/public2220164 passed first-flushed-write interruption,
restart, public resume and independent public rollback from the same original
bundle26b78b9ab5f574614e4df9457202dfef23a47b37238f512dee0ed4fea18f3cc9.
Both recovery directions preserved9 file paths and15 ADS views, including
empty/literal-$DATA/Unicode/large streams. See evidence/ads-native-recovery-20261030.json.
Original interruption:2f9ef65b; recovered ReFS:6264afb3; recovered NTFS:a6604468.

Source9589ff8 adds explicit sparse-aware range reads while existing plain
readers and public sparse refusal stay unchanged. Source7126f6f adds a lab-only
sparse-carrier probe. That probe passed on a newly owned ReFS3.14 volume: a
16KiB nonsparse carrier was cloned into two ranges of a256MiB sparse target;
mapped allocation stayed32KiB (16KiB shared payload), data/storage validity
and zero-hole samples survived deletion of the identity-checked owned carrier.
It wrote64 payload bytes and read147456 bytes. See
evidence/sparse-carrier-native-20261030.json. This is not sparse NTFS conversion
support. Next: model sparse islands/holes per stream, reuse dense carrier
placement, clone to sparse logical offsets, and bind hole/allocation/VDL proofs
into the existing source-backed converter. Do not densely allocate or hash-skip
holes without an explicit verified policy. Keep ordinary digest compatibility.

ADS implementation: canonical objects now carry named_streams while
payload handles, placement, routes, source reads and copy planning distinguish
the exact UTF-16 stream name. Native construction/verification supports ordinary
file ADS; directory ADS and ADS on System Volume Information remain explicit
refusals. The existing limit is64 total streams per file and16,384 per tree.
The source/copy retention check now excludes every cluster beyond source VDL.
Focused public release build passes, SHA
2220164aaeef4c9db8bf11339fc4d11a365871d10a8665ce69c415288ed20710.
Source3ba75be completed public conversion ecf76f8f/corea0706783: native0,
ReFS3.14/4KiB,8 canonical objects,4 default and5 named stream hashes. All9
hard-link names and15 independent ADS views matched. Tested streams include
2MiB+19 bytes,65537-byte Unicode-name data,empty data and literal `$DATA`.
Five ADS were independently added to disk6/H: and read back through all three
hard-link names each; default data/IDs remained unchanged. This NTFS source is
saved in145c0060-b98e-4857-963f-238e72199869. Pure converted state is preserved
in45924882-3aab-4fec-82fd-3848461e0225. A cold boot retained all stream hashes,
names and file IDs; mutation through the Unicode alias propagated correctly,
and restoration through another alias recovered all original hashes without
changing default streams. Evidence: evidence/ads-native-conversion-20261030.json.
That initial ADS stage was saved under parentbb8a6475 with seventeen checkpoints.
Subsequent interrupted recovery is recorded above; directory ADS, encodings and
broader geometry remain unqualified. Fixture:
.lab/hyperv/streaming-v2-20261027/ads-fixture-d951c1ed45c142f69d40efae28f260c8/fixture.json,
SHAa17bafe1afbb796e7517b50ebd33aa784cd40a00a43e00f581e052cb7c6aaaf1.
Use the new ADS launcher and fresh candidate pins; old hard-link expectations
do not include these streams. Do not claim the old7b1c8df native results for
this new candidate. No unit tests were added or run.

State immediately after hard-link recovery qualification: VM was Off/RAM0, parent
f3eb7560-4804-47a8-ad91-530cd87221ab, fourteen preserved checkpoints. Disk6/H:
contains independently verified NTFS restored by public rollback. The original
interrupted hard-link state is4a084701-74f9-42c2-91ce-6f4436f23180, and its
successful public resume is preserved in0f685623-9109-4d97-afe7-84fafb232d60.
Do not infer current state from the older chronological observations below.

Source7b1c8df/public65776bd4127ca911ec2698cde1fe660c43d879eb895233b66f2838c5f6ec29fb
now has controlled first-flushed-write interruption, guest restart, public
resume and independent public rollback evidence for the three-file/nine-name
hard-link fixture. Both recovery directions used the same original bundle
37984256a70d19b9a17eb395fff83b9bfa7eeb8cb60a3a3e59fefcfabf103fdf and separate
branches from that interrupted state. All nine paths/hashes/link groups passed;
rollback also matched original NTFS file IDs. See
evidence/hardlink-native-recovery-20261030.json. This is not power-loss testing
or blanket feature/geometry qualification.

Intermediate source2ca1c63 added bounded named-stream range reads/hashes and made the
cached source session key include the exact UTF-16 stream name. Focused cargo
check passed; ADS admission was still refused at that revision. Source3ba75be
subsequently connected canonical/native named streams, stream-keyed placement,
routes/residuals and exact native stream-set verification. Keep file identities and hard-link names separate from
stream identities. Do not copy payload once per alias or use filename strings
as a substitute for stream identity. No unit tests were added or run.

Latest follow-up: evidence/public-build-provenance-9099110-20261030.json binds
the tested public121d7dbb binary to9099110 plus the exact saved main.rs overlay
(SHA c6bc5c52c8458ee70bd2567a9d8350105aeaa6245448df22675780403e04348b).
The effective source is reconstructible, but a later byte-identical relink is
not claimed: historical PE/debug timestamps and CodeView identity were not
sealed reproducible build inputs. The original EXE/PDB/source bundle remains
preserved. No public converter rebuild was used for the following observation.

Saved native metadata now independently reconciles both156241e and9099110
file mappings against their protected routes and live retained-byte totals.
A fresh read-only query then matched all654 eligible user-file identities,
lengths and normalized retrieval mappings on the saved9099110 mutation/reboot
branch20068b68. Query native/task0; zero payload bytes read and zero source
write requests by the observer. This is not a full allocator or new-feature
qualification. See evidence/native-extent-preservation-20261030.json.
The new lab helpers and controller have focused release-build/AST coverage;
no unit tests were added or run. The first controller preflight refusal is
preserved alongside its corrected fresh run. VM is stopped/RAM0; all seven
checkpoints remain, including the verified NTFS rollback in ec034c81.
Preserve every existing checkpoint/evidence item for this active follow-up.

The requested GitHub compatibility review is recorded in
docs/release-0.0.1-readiness.md. ntfs2btrfs has broader conversion coverage but
also warning/skip/truncation paths; do not copy that data-loss policy. Our next
feature slices are identity/named-stream modeling, hard links/sparse/VDL,
security/reparse/EAs/extension records and compressed logical content. ReFS
capability and target-version limits remain explicit pre-write refusals.

Hard-link implementation: canonical Object and native
Input now carry additional_names while retaining one payload per file identity.
Source names resolve by exact parent record/sequence using binary search;
native construction uses held file/directory handles to create no-overwrite
links, then verifies alias IDs, link counts and complete directory membership.
The public executable and digest helper build. The new standalone disk6/H: fixture has three
file identities/nine names (ordinary, resident-sized and empty data, nested
Unicode aliases), NTFS4KiB,52GiB. It is saved in checkpoint914bb77d; eight
checkpoints now remain. Host VHDX/provision records are in
.lab/hyperv/streaming-v2-20261027/hardlink-compatibility-20261030-696083aa434743978f9842a93f1058d0.
The independent fixture manifest is in hardlink-fixture-4c29c8e7017541bbb19625416625ec98.
Never send old disk1/F: recovery tickets to this new disk. Its source GPT is
f95141cb-fe7e-439a-a82b-c2b3f55965d2, partition2 at32MiB. Existing disk1/F:
and every historical checkpoint remain unchanged by this fixture creation.
The first hard-link run f9c8a0fd (public7e7bb4aa, source8cc4245) stopped before
source activation because the fresh NTFS volume has no IndexerVolumeGuid.
Its 28 closed metadata files and complete failed VM branch are preserved in
hardlink-compatibility-20261030-696083aa434743978f9842a93f1058d0 and checkpoint
174011ed-b989-46cf-b5d3-8a25333759d5. All nine checkpoints remain. The source
was restored to914bb77d for a new attempt. Absence of the optional indexer
cache is now recorded without manufacturing one; existing caches still receive
their full checks. ACL restoration now processes directory parents before
canonical files, then restores timestamps bottom-up. The corrected public
build is65776bd4127ca911ec2698cde1fe660c43d879eb895233b66f2838c5f6ec29fb.
Source7b1c8df then passed public run5823093b/core052c23a1 on that independent
NTFS4KiB fixture: native0, HND, ReFS4KiB,8 objects/4 complete hashes, all three
user-file identities and nine names preserved. Six alias snapshot proofs match
canonical IDs and link counts. Native duration16.658s applies only to this tiny
payload fixture. Journal73,536,704 B plus packed backing1,966,080 B; this fixture
relocated its payload, so it establishes no retained-data performance result.
A cold boot preserved all nine IDs/hashes, then a one-byte write through the
Unicode alias propagated across the ordinary file's three names. Restoring via
the other alias recovered every original hash. See
evidence/hardlink-native-conversion-20261030.json. No unit tests were added or run.
Hard-link ATTRIBUTE_LIST, ADS and sparse/encoded streams remain unqualified.
The broad goal is unfinished. After that initial conversion check,
VM was Off/RAM0 with parentd2c6ff09-2e26-4e25-be53-831a916f5489; eleven
checkpoints remain. The pre-mutation ReFS result is1c23ca96-dd72-4846-b7bf-39fb13389639;
the clean NTFS hard-link source remains914bb77d-d924-4ed6-ab14-9a40288c3bc9.

Storage update (2026-10-30): the allocation-bounded path now captures explicit
zero ranges without storing their new bytes in the packed backing, and issues
`N2RZERO1` selected journals when the plan has `new_zero_ranges`. Every old byte
is still journaled and every required zero is still written. Legacy empty-zero
plans retain byte-identical N2RSEL01 output. The owned-file integration passed
short-write resume/rollback, closed replay and false-zero refusal; see
evidence/zero-payload-journal-20261030.json. The public CLI and helpers build.
Source662f4ae/main5187c16083b66923bfe7b17838e5deb8e3616e87d7278279ed2b819d6c4a7a89
then passed one native public conversion (run78e69128139549f68b1c041366b13691),
15 objects/10 full file hashes, label/mount, and N2RZERO1/HND. Its backing is
2,887,680 B and journal73,559,152 B versus211,965,696 B combined for a dense
representation of the same changes (about64% lower storage). Duration60.82s;
no timing improvement is established. See evidence/zero-payload-native-20261030.json.
The same662f4ae build subsequently passed controlled interruption after one
flushed write, a guest restart, public resume to ReFS15/10 and independent
public rollback to NTFS with7/7 user files matching from the same interrupted
checkpoint. See evidence/zero-payload-recovery-20261030.json. This does not
cover physical power loss or mutation/reboot checks on that build.
An initial run refused before activation due to a volume-root spelling bug;
that failure is archived and the fix is in662f4ae. This does not implement staged
N2RSEL02-H or remove the16GiB actual journal limit. Exact sizing precedes activation.

Later source8d65a02 removes the duplicate immutable-journal read inside each
load while preserving every validation boundary. The ordinary-file integration
and byte-identical v1/v2 journals pass; evidence/journal-single-pass-20261030.json.
Do not assign the662f4ae native results to this later loader. Source7327629 adds
payload_copy_plan, a pure checked source/target mapping and journal-old/retained
source segment planner. It is not wired to a payload-reference journal and
grants no write authority. No new unit tests were written or run.

The next candidate wires that planner into allocation capture and adds
N2RCPY01: new payload may reference only OLD bytes already stored in the same
journal. Capture verifies the physical origin and admits only preceding
changed ranges; all old bytes and required zero writes remain preserved.
The three-format ordinary-file integration passes, including references across
old records, overwritten origins, resume/rollback and false-copy refusal.
See evidence/payload-reference-integration-20261030.json. It is not the staged
N2RSEL02-H design. Source156241e/mainfe69c5a1b2dc728e6ee63e19599a56590c984232b37fd62461913a717ba64dba
completed mixed run2586aba6ade144559d7e24d86c4792ea: native0, HND,933 objects/
811 complete hashes,808 user files/9,885,781,381 B, label/F preserved. Runtime
1511.149s; no speed improvement is claimed. Journal13,713,024,832 B plus backing
1,180,688,384 B fits the16GiB journal cap. Copy references save5,659,435,008 B
of new payload; in-place payload from the live proof is3,084,886,016 B.
The outer wrapper exited1 only afterward because its old4MiB JSON limit
rejected the22,904,392-byte finalization record. All56 metadata artifacts were
copied and hash-checked; a bounded archived observer independently accepts
933/811. See evidence/payload-reference-native-mixed-20261030.json.
No mutation/reboot or independent recovery of this build has run yet.

Revised validation candidate: a lab-only --interrupt-after-first-copy-write
hook now derives its destination from the actual admitted reference plan,
flushes one accepted copied-payload write and exits86. Numeric fault limits
and the public drive path are unchanged. Mixed harnesses accept explicit
capacity/checkpoint sets,64MiB completion records and pinned expectations.
Mutation verification now batches at most64 paths/20,000 UTF-16 units and
requires explicit digest/result/completion pins. Focused builds and AST checks
pass. Revised source9099110 is now running the fresh mixed-fixture first-copy
interruption case9163fda1b301434f9db51ade0af94770 completed with native/task86
after a53,248-byte write at6,635,794,432 and an explicit flush. Source1 remained
offline; no HND was reached. See evidence/copy-write-interruption-20261030.json.
Controlled binary4b277d30c6ec0f8aed2f8d6192db97cff237900b6b0afbdcc8fc3d2c3ee5aefc,
public binary121d7dbb9977618af7790f4fcd78e69fee3c4274e9e2980c1a3d0709dd322f0b.
The interrupted state is preserved in9f32dee4-0691-4b2a-9ec2-e7834b6d11db.
Public Resume94122a2c65a4438285d40411c224af26 passed native/task0, ReFS933/811.
Mutation/reboot773ef72dd2ae44f98989f46985e0fa9f then passed808 original files,
two retained new files and128 entries, with zero recorded ReFS warnings/errors.
The revised successful branch is preserved as20068b68-ffc2-4443-bea8-179a797c1495.
Independent rollback13a04e4fddb94cc0845c464d031b6f96 then passed native/task0.
All808 user-file SHA-256 hashes match the original independent fixture and
all120 user directory names match the frozen expectation. The scoped matrix
is in evidence/revised-copy-validation-20261030.json. No validation worker is
active. Do not transfer these results to a different executable or profile.

Before the hard-link follow-up, VM2401593c-4b30-472e-9b6d-c9534cbaa599 was Off/RAM0 with parent
mutation/reboot checkpoint20068b68-ffc2-4443-bea8-179a797c1495 after the closed
read-only extent observation. The verified NTFS rollback is preserved in
ec034c81-e39b-46bd-a8d1-cfc3481da8dd. Restore an intended checkpoint before
starting another native case. The mixed baseline is6fe2d6b6, with808 files/120 directories,
9,885,781,381 bytes; manifest is under mixed-fixture-20261029-3dccf8e8fa38487db6731284a12bceb9.
The completed156241e ReFS branch and its attached shadow were preserved before
restore as checkpoint1683b2be-c372-45b2-8583-3b6028fd72f1. The two older52d37819
and5f30f4a1 checkpoints also remain; none was removed. The complete
metadata archive is under copy-reference-20261030/closed-run-2586aba6; its
inventory records retained original bulk paths. The13,713,024,832-byte journal
has now been exported and verified against its immutable-body hash and both
completion/intent markers; the1,180,688,384-byte backing was exported and
verified against its capture hash. See bulk-preservation.json in that archive.
The742,391,808-byte original shadow VHDX could not be exported through an
ordinary read; no bypass or detach was attempted. The whole original branch,
including that image, is retained in1683b2be. Seven checkpoints remain, including
the revised successful ReFS mutation/reboot branch in20068b68 and the independent
NTFS rollback branch inec034c81. Do not remove
preservation checkpoints without specific approval.
Any new native run needs a fresh restore of the intended
checkpoint, verified from a new PowerShell process. HEAD da13331 converted the
52GiB fixture in 2,813.3s vs the frozen alpha's 3,351.7s, still reading at
least 816.6GB; see evidence/head-drive-measurement-20261029.json and
docs/release-0.0.1-readiness.md. That binary has no mutation/reboot/recovery
results. lab/Start-HeadDriveMeasurement.ps1 runs a sealed HEAD toolset. It has fixed4GiB RAM, 4CPU, no NIC. Host
hostname is SINGULARITY: the lab VMs and the WSL Ubuntu distro are local to it.
The two original checkpoints remain:
- NTFS after optimized public rollback: 5f30f4a1-9db0-4df5-a0e5-2c7be5d87eec.
- ReFS after optimized public resume: 52d37819-2b9c-4041-9232-bd7eac3c21bb.

Temporary zero-journal interruption checkpoint3008f75c was removed through
Hyper-V after both recovery directions and rollback file readback passed.
Do not reuse that deleted ID. Closed records are under
.lab/hyperv/streaming-v2-20261027/zero-recovery-20261030.

Earlier cleanup preserved both successful
branches and removed obsolete632b630a/f06aa7fd/5125d335 through Hyper-V APIs.
Do not restore/recreate those deleted IDs. Old harnesses pinning those baselines
must not be blindly reused. Cleanup receipt:
.lab/hyperv/streaming-v2-20261027/checkpoint-cleanup-optimized-20261029/receipt.json,
SHAfe8adf0749674d2c2ef69badc945b9b544cc1cb80e939bb6fbbf6699f6a72df1.

The frozen source2ff5f017c03977c5e6ba9d31ba64dc634bfa2fe7/mainfb5548cc80a1de57e5a1c3c853a0ccfc43338515d00e15867305fa5f59c6079c
passed normal public conversion, mutation and reboot on the52GiB fixture.
Its same-source controlled coree2a832e0986ce785d4700ec4501e28a4a3f0b3f3e2fb8a1df2fdc25fd52e6976
then exited86 after one flushed write (runc0218eb07cc742d8b8cb2b2738e31de3),
published its original native bundle and preserved the interrupted state.
Exact bundleSHA4d3ad80646231dc69323e571a13b950d89f2a109cef548f3b0806e1e75586dca.
Actual same-build public Resume/Finalize c3a1f20f5f9f4c7c84a56b334e0511a2
passed native/task0, exact ReFS targete96a21e5cf2acda1f8a7ea4b984788bef5f6c91ce1560d38b32ce097e6d8aa25,
HND,15objects/10fullfilehashes,label/F. Separate public Rollback
 a2e4be16c5f74b588f27ee6ed5ea86cb passed native/task0 from that actual partial,
exact pre-mount NTFSc5b58e4869d2a9c366c6b8daeb63f4507ef0b660ec98d7a743f404b4047e7734,
ABT,NTFS64K,label/F. No post-mount NTFS file hashes or physical power-loss claim.
See evidence/optimized-drive-alpha-{interruption,resume,rollback}-20261029.json
and docs/frozen-drive-alpha-20261029.md. Do not transfer this qualification to
later performance or metadata-reader code.

Frozen package .lab/releases/ntfs2refs-alpha-20261029-fb5548.zip remains unchanged,
SHAf826606342c9b2a06ef18a35996915d60c0c54fd840fbc71c21ddb26f854577b.
It includes the packaging-time main.rs snapshot because of the user-owned hunk.
No clean historical tree or reproducible build is claimed.

## Current implementation direction

The user rejected the repeated whole-volume scan cost and asked to follow
ntfs2btrfs's allocation/metadata-driven approach. Prioritize real code toward
selective capture and retained extents; do not merely remove integrity gates.
The original native-shadow converter remains the qualified experimental path.
It still reads whole images and is not an efficient arbitrary-volume release.

Later commits7e318ce/541f76f/46e0dcc/7f6d93e/a4419ca reduce redundant reads,
journal passes and small writes, and parallelize capture/image hashing.
Focused release builds pass; no native conversion qualification is assigned.
The host paired-hash memory benchmark is not an end-to-end disk measurement.

Reader59ecbf5/79ef512 and later code follows checksum-authenticated system,
Object Table and directory/system-object index pages. Current code also parses
embedded file-attribute nodes and indexed DATA extents, retaining separate
metadata and physical-data footprints. On the existing research image it reads
1,897,488B for46pages,3inline attribute tables,2DATA versions/68extents and
1,025distinct data clusters, without external payload reads. No spilled
attribute/extent page path was exercised in that image. Cross-container data
runs currently refuse. See docs/refs-metadata-footprint.md and its evidence.
Current reader work also traverses both checkpoint generations with independent
maps and physical container/Small trees; it supports declared own-record nodes
and Logfile Information OIDs9/A plus matching checked MLog controls. The existing
research-image run reads2,372,624B,145charged page operations, and records
538,177,536B of metadata ranges including the512MiB circular log without reading
that log data. See evidence/refs-generation-log-footprint-20261029.json. This is
still not a complete graph: opaque leaf fields, stream inventory, transaction
state and allocator/refcount reconciliation remain unproved. Detailed container
walks currently refuse beyond4096map rows/32pages per tree; larger sizes need
the compact reader's full physical footprint rather than raising one limit.

New selected_journal core and lab-selected-journal use a distinctN2RSEL01 format.
They read only caller-selected aligned ranges, carry old/new payloads and framed
selected hashes, enforce intent/HND/ABT barriers and never claim whole-image
verification or source admission. The direct ordinary-file integration passed:
each of two8MiB inputs read32KiB across two preparations, all core complement
access prohibited; persisted-short-write resume/HND and separate rollback/ABT
passed, with closed replay refused. No native-volume result is assigned to it.
The drive CLI remains on the existing full-image journal. A native adapter still
needs an authenticated complete footprint, actual device/exclusion/write-policy
binding, source admission, and versioned recovery-bundle handling. Do not turn a
JSON footprint or selected ticket into those permissions. The journal currently
stores every selected byte (including equal bytes), so feed it a pruned plan:
selected_journal::changed_plan narrows a coarse selection to the differing 4 KiB
granules (ordinary-file integration passed; evidence/selected-journal-changed-plan-20261029.json).
It authenticates nothing and is valid only under the caller's exclusion.
See docs/selected-range-journal.md and its evidence.

Native allocation observation: commit f539345 reads the ReFS bitmap through a
protected physically read-only mount after freeze (the earlier post-lock query
was refused with native error 21). Run3135dde6ab724f4fb193c28a5ff638d0 passed on
the converted 52GiB volume: all raw-reader required ranges are natively
allocated (required_not_native 0), 3,808,256 logical raw bytes in917 reads, but
5,166,432,256 natively allocated bytes in 15 ranges are unaccounted for by the
raw reader, so complete_graph/complement-safe/source_admitted stay false. Host
analysis: those bytes all lie in one prefix [0,6,174,015,488) (LCN<1,507,328,
92x64MiB) that the native view marks fully allocated; beyond it native equals
the Medium allocator exactly. The conservative required union (14.77GB, 26.5%
of the partition) already includes the prefix. A fresh ReFS format of identical
geometry (pinned query-070/071 in retained-preparation win11-20261024T034206826Z)
shows the same metadata-inclusive prefix, checkpoint LCN and final range, so the
prefix is consistent with the format metadata zone (inference, not proof). See
evidence/native-required-ownership-protected-readonly-20261029.json and the end
of docs/refs-metadata-footprint.md. Next: authenticate the footprint inputs
(keep the prefix zone as required), then wire the selected journal to a device.
Expect the journal to hold old+new for the whole union.

Do not add or run unit tests. Focused builds and necessary native integration
only. Keep ignored images, journals, binaries and secrets out of Git. The
coordinating agent owns VM mutation; delegated agents work on source unless
explicitly assigned metadata-only observation.

Selective path direction (user chose it, 2026-10-29): docs/selective-conversion-plan.md.
Guarantee decision (user, 2026-10-29): selective mode adopts the ntfs2btrfs
allocation-based guarantee. Bytes that ReFS's own allocator marks free in the
protected frozen shadow need not be compared or written; the per-range write
policy and end-to-end mounted-file verification stay. Free-space contents are no
longer proven equal in that mode, and its evidence must say so.
Extension (user, 2026-10-29): in the allocation-bounded mode the source-side
admission bracket may also be bounded to NTFS-allocated ranges, so the live
certificate binds the NTFS inspection plus an allocated-range digest instead of
a whole-source hash; NTFS free space is then not proven unchanged during
admission. The composite/whole-image path keeps its whole-source hash.
On the HEAD run, 100% of the 70,615,040 changed bytes lie inside the frozen
shadow's native metadata-inclusive allocation (14.77GB); 286,720 of them are
relocated file data inside routes, so routes cannot simply be skipped. Commit
11e0513's non-gating diagnostic then planned over only the shadow allocation on
real devices (run 9ac7538c83b24d5aa6ffbd0bb0d8b686): identical write set to the
complete capture (159 ranges, 70,615,040B), 14.77GB compared per side instead of
52GiB; see evidence/selective-plan-native-20261029.json.
DEFAULT MODE (user, 2026-10-29): the public drive command now runs the
allocation-bounded backend by default and prints "Mode: allocation-bounded" before
confirmation; --whole-image-verification selects the earlier compact path. The
old --experimental-allocation-bounded flag is a hidden no-op alias.
lab/Start-AllocationBoundedConversion.ps1 passes no mode flag (needs a build at
or after the default change); lab/Start-HeadDriveMeasurement.ps1 passes
--whole-image-verification.
Allocation-bounded backend (45f263a, then hidden --experimental-allocation-bounded;
launcher lab/Start-AllocationBoundedConversion.ps1, 1ac5682) converted the
fixture natively in 952.9s (vs 2,813.3s whole-image HEAD), reading >=295.0GB,
15 objects/10 hashes, label/mount verified; see
evidence/allocation-bounded-conversion-20261029.json. No interruption, recovery,
mutation or reboot results.
Recovery (b49eae6): the conversion publishes allocation-recovery-bundle.json
before activation; --recover routes to general_recovery::recover_allocation when
only that bundle exists; the journal lifecycle selects resume/verify-handoff or
rollback/abandon/verify-abort, never a fresh apply. Lab fault entry:
lab-convert-native-composite --selected-devices --allocation-bounded
--interrupt-after-writes N (exit 86). Exercised natively (launchers
lab/Start-AllocationInterruption.ps1, lab/Start-AllocationRecovery.ps1): one
interruption after the first flushed write, guest restart, then from the same
temporary checkpoint (since removed) --recover resumed to ReFS 15/10 and
--recover --rollback restored NTFS with 7/7 user file hashes; see
evidence/allocation-bounded-recovery-matrix-20261029.json. A second conversion
(772.8s) passed mutation plus clean restart via lab/Invoke-AllocationMutationReboot.ps1
(7/7 originals, new files, 128 entries, 0 ReFS events); see
evidence/allocation-bounded-mutation-restart-20261029.json. Untested: other
interruption points, physical power loss, other fixtures/builds. Next: bracket
the shadow observation over its allocation; more interruption points.
The VM's CheckpointType was set to Standard for that temporary checkpoint; its
earlier value was not recorded.
Performance (2026-10-29, default mode, 52GiB fixture, native exit 0, 15/10,
label/mount verified): #1-5 (bd9ef21) 356.7s; parallel bracket/source hashing
(e6e22f6) 258.7s; plus CNG read/hash overlap for file streams (e535477) and
XXH3-128 bracket/source change-detection digests (7605ee7, user suggestion)
134.7s (run fc94b1ef; evidence/allocation-bounded-xxh3-overlap-20261029.json).
The lab CPU (i9-9900K) has no SHA extensions: CNG SHA-256 ~511MB/s/core, sha2
software 300MB/s; VHDX reads 8-30GB/s mostly from host cache
(src/bin/lab-read-bench.rs, evidence/allocation-bounded-parallel-hash-20261029.json).
Then: digest recheck instead of a second source inspection (48d6a8e, 116.7s; the
admission inspection's reads must lie inside the digested NTFS-allocated ranges),
parallel ReFS object observation and 4 MiB payload-route reads (e91ead3, 112.6s).
CONTENT DIGEST (user, 2026-10-29): file-content hashes (NTFS inspection stream
and resident digests, native logical reads, converted-file verification) are
XXH3-128 via n2r_win32::content_digest, in fields that keep their *sha256 names;
they no longer match Get-FileHash. Artifact pins, residual tails, metadata and
whole-image hashes stay SHA-256. With it (e2ae8b5) the fixture converted in
66.7s; with XXH3-chunk selected digests in the listed capture (1443042) in 42.6s
(run c2a08ec7: admission 9.2s, shadow 5.7s, target verification 13.6s, journal
3.5s, apply 3.6s, handoff 2.4s, file verification 4.0s; evidence/
allocation-bounded-chunk-compare-20261029.json). Run artifacts' LastWriteTimeUtc
gives this phase timeline. Parallel read lanes (f8fa3c9: GeneralFrozenLane,
IoProfile queue depth 2 when no seek penalty is reported) converted it in 40.7s
(run bdd739b4). On that build: mutation plus cold restart passed (d4b82b90, 7/7
originals by XXH3 via src/bin/lab-content-digest.rs, 0 ReFS events); one
interruption after the first flushed write, clean restart, temporary checkpoint
(since removed), then --recover resumed to ReFS 15/10 and --recover --rollback
restored NTFS with 7/7 user files; see
evidence/allocation-bounded-recovery-current-20261029.json.
Then one target flush per apply phase and CNG journal pins (f15e060): 40.7s and
40.6s; on that build the interruption/resume/rollback matrix (7/7 user files
each, native 15/10 on resume) and mutation plus restart passed again; see
evidence/allocation-bounded-final-build-20261029.json.
Hard power-off (f467cbe): persisted disk attributes live in the SYSTEM hive
(the disk's Partmgr "Attributes" REG_DWORD equals the DISK_ATTRIBUTE bits) and
Windows writes hives lazily, so a TurnOff about 3s after activation reverted
the source to the last durable value: on 730efe1 it came back ONLINE read-only
(2), losing both the activation and the lease restore. set_attributes now
RegFlushKey's HKLM\SYSTEM after every Persist=1 change. On f467cbe three TurnOff
runs at the same timing kept OFFLINE (1), and from that state --recover resumed
(ReFS 15/10, 7/7) and rolled back (NTFS 7/7); see
evidence/hard-poweroff-attribute-durability-20261029.json. Recovery still never
clears protection. Physical power loss is untested (TurnOff keeps host-cached
VHDX writes); the reference-import and managed-shadow attribute setters do not
flush yet.
SCALE (2026-10-29): the seeded mixed fixture (lab/New-MixedFixture.ps1: 808
files, 120 dirs, 9.9 GB, fragmented) refused before any write during shadow
placement: "global tracked ownership range budget exceeded" (placement.rs:350,
owned > 1024; evidence/allocation-bounded-mixed-fixture-refusal-20261029.json).
Workflow analysis (wf_ac088a60-727, read-only) found coupled fixed caps:
placement owned/avoid 1024, shadow_evacuation MAX_EXTENTS/MAX_MOVES 1024,
retention_layout MAX_SUBRUNS 1024, unwritten.rs per-file 1024, drive
MAX_PLACEMENT_SUBMISSIONS 1024 shared by all move phases (effective E ~350-500),
bitmap views 65,536 ranges, supply/routes 4096, selected_journal MAX_RANGES
65,536, ntfs_attribute_list MAX_RUNS 1024, and the streaming tree profile's
1024 files / 256 directories (private_tree.rs:592-593, ntfs_admission). Each
placement move also recaptures and hashes two whole-volume bitmaps, so cost is
O((E+M) x clusters). Verified next step (stage 1, no evidence-scope change):
track all files first and plan from one snapshot per phase boundary; filter
owned to extents intersecting desired runs; sweep-line intersection in
plan_ranges; first-fit scratch cursor without the subrun cap; coalesce placed
entries; raise the coupled caps together to derived ceilings; add owned/move
counters to the refusal artifact. Window-scoped bitmap probes, sparser source-
exclusion checks or a narrower per-move retrieval proof change evidence scope
and need a user decision. The 1024-file tree cap is a product-scope limit.
SCALE DECISION (user, 2026-10-29): "Redesign theoretically unlimited": capacity
must be bounded only by machine resources (RAM, temp disk, time), with no fixed
constant caps on files, directories, extents, runs, moves, ranges or evidence
size. Evidence may move to disk but must stay complete and verifiable; any
change that narrows what is checked still needs its own user decision. Design
workflow: wf_5c358166-e1b; stage-1 placement implementation: wf_40ba8e07-e64.
Draft plan with verifier corrections: docs/unbounded-scale-design.md.
MOVED-DATA DECISION (user, 2026-10-29): "Hybrid": protect relocated data by
staging it in the volume's own free space when there is room (ntfs2btrfs model:
originals stay intact until handoff, so only those ranges need journaling),
and fall back to the external old+new journal, sized from actual free space
rather than a fixed cap, when there is not. Needs design and hard power-off
qualification before use.
PER-MOVE CHECKS: the 2026-10-29 "Decide after measuring" deferral was superseded
for D1 on2026-10-31: the user selected destination windows under both selectors,
retaining full phase maps, full retrieval and final allocation validation.
D2 incremental retrieval remains deferred; do not infer its authorization.
MEASURED (2026-10-29, evidence/mixed-fixture-class-split-20261029.json): on the
808-file fixture 99.2% of the first 4.95 GB of changed bytes are shadow zeros
written over NTFS file data inside the ReFS metadata-inclusive prefix
[0, 6,174,015,488); the fresh ReFS writes almost none of that zone (the shadow
VHDX stays 172 MB). Projected changed bytes about 12.4 GB of 12.2 GB compared;
an external old+new journal would need about 37 GB of OS-volume space for a
9.9 GB dataset. Hybrid design drafts: docs/hybrid-write-model-design.md.
HYBRID DECISIONS (user, 2026-10-30):
- ZONE ZEROS: "Probe, then skip if proven": first prove in the lab that a ReFS
  format over a disk pre-filled with random data leaves the reserved zone's old
  bytes in place and the volume works under stress; only then skip writing
  shadow-zero granules that no ReFS structure references. The converted volume
  then matches the shadow except in that zone (NTFS remnants, as after a quick
  format). Until proven, keep writing the zeros.
  RESULT (2026-10-30, evidence/refs-zone-probe-20261030.json): DISPROVED. A fresh
  Dev Drive ReFS format leaves the 22 GB zone of a 200 GB disk 99.99% zero (it
  TRIMs the thin disk); overwriting only those zero granules with random data
  (keeping all 652 nonzero ones) made the volume mount RAW. ReFS depends on the
  zone zeros, so the converter keeps writing every shadow-zero granule. Do not
  re-propose skipping them without an authenticated footprint of which zero
  granules ReFS reads.
- STAGED-RANGE CHECK (E2): a per-4 KiB XXH3-128 old/new digest table for
  free-destination (staged) ranges; resume refuses any granule matching neither.
- ROLLBACK AND VSS (E-2): rollback restores every NTFS-allocated byte and leaves
  staged copies in NTFS free space; conversion refuses up front when the source
  volume has any Volume Shadow Copies.
- TORN MARKERS (E3): dual-copy markers (two sectors); the intact copy decides;
  the hard power-off lab test must prove it.

## Source and recovery invariants

- A fresh Apply requires the original opaque live source certificate, preserved
  through source isolation and exact target qualification. Never recreate it
  from JSON, flags, old reports or a bundle.
- A recovery bundle supplies pinned routes only. The existing typed recovery
  engine must verify actual request/ticket/capture/backing/journal identities,
  exact device routes and state. It cannot initiate a fresh Apply.
- Keep the exact request, ticket, expectation, compact capture, packed backing,
  journal, managed-shadow receipt and binary pins available while recovery is
  possible. Never read locked live artifacts through an alternate mechanism.
- HND and ABT close old raw replay. A failed observer after handoff does not
  authorize replay over a mounted or subsequently changed filesystem.
- Managed recovery may add missing persistent protection bits only after the
  exact provider/GPT/route/Windows-disk checks and positive native write-protect
  evidence. Never clear protection, make a device online, change its identity,
  or rebind an old ticket to bypass a refusal.
- A timeout or lost remoting session does not prove a worker died. Check the
  actual task result and process PID plus creation identity. Bare PIDs can recur.
- Before power, restore or new work, establish the active workers and barriers.
  After Restore-VM, query parent/state from a fresh PowerShell process because
  Hyper-V objects can retain stale parent information. Do not repeat a restore
  merely because one cached observation disagrees.
- Record native results as scoped observations, including refusals. A mount or
  logical hash alone is not a complete allocator, durability or preservation proof.

## Storage, RAM and cleanup

The user's explicit checkpoint deletion instruction supersedes preserve-all
history. Keep only the minimal branches needed for current work. Manage
checkpoints with Hyper-V APIs; never delete AVHDX chain files directly and never
recreate deleted historical checkpoint IDs.

The fixed storage epoch is:

| Setting | Bytes |
|---|---:|
| Original lab usage baseline | 279,374,052,988 |
| Original host free-space baseline | 66,133,905,408 |
| Maximum actual lab usage | 329,374,052,988 |
| Minimum host free space | 17,179,869,184 |

This is the original additional 50,000,000,000-byte allowance. Do not reset the
epoch after cleanup or silently increase its cap. The latest reported host free
space was about 119 GB; remeasure before allowed growth and account for the
forecast. Use lab/Lab.psm1 and lab/lab.config.json for capacity checks.
Keep the VM at its reviewed RAM settings. Keep WSL running as requested.

Past automatic approval review rejected deletion of a disposable research
image. Do not retry that rejected deletion through another shell or method.
Another automatic review rejected deletion of the duplicate checkout
`D:\code\ntfs2refs\.lab\ntfs2btrfs-source-audit` with only “blocked by
policy”; do not retry that action through another method.
Later authorized checkpoint removal through Hyper-V succeeded; these are
different actions. Preserve original evidence and active recovery material.
Keep .lab, images, VM chains, journals, ISOs, binaries and secrets out of Git.
Check exact resolved paths before cleanup and use native PowerShell literal-path
operations. The user has explicitly requested regular commits and pushes of
stable work. Commit task-owned source and documentation at coherent milestones,
then push normally to the current branch; do not force-push. Do not stage the
existing user-owned main.rs hunk. The working branch now tracks
origin/codex/isolated-journal-observation.

## Code map

| Path | Responsibility |
|---|---|
| src/drive_cli.rs | Drive selection, confirmation and bundle-oriented recovery UI. |
| src/general_conversion/composite.rs | Original admission, compact preparation, durable ticket/bundle, activation and completion. |
| src/general_source_admission.rs | Opaque live source-certificate gates. |
| src/general_qualification/composite.rs | Owning source context and composite qualification. |
| src/general_composite_target.rs | Protected native target witness and complete source-backed capture. |
| src/compact_recovery_bundle.rs | Bounded held routing metadata; no source or replay authority. |
| src/general_recovery/compact.rs | Typed Resume, Rollback and finalization. |
| src/general_reconstruct/compact.rs | Existing compact journal preparation and execution. |
| src/general_reconstruct/compact_finalize.rs | Durable completion barriers and native handoff. |
| crates/n2r-win32/src/managed_shadow.rs | New owned native scratch provisioning. |
| crates/n2r-win32/src/managed_shadow/recovery.rs | Exact existing read-only attachment and protection restoration. |
| lab/ | Reviewed Hyper-V dispatch, observation and preservation helpers. |

REFSNT and forensic parsers remain external research. Do not copy GPL reference
engines into the Rust product runtime or claim compatibility from their checkers.

The source/evidence comparison in docs/ntfs-compatibility-comparison-20261030.md
pins ntfs2btrfs and similar upstream tools. Do not copy their skip/truncate
policies into a lossless claim. The audit found no explicit live VSS or
directory case-sensitivity gate/preservation path; these are admission gaps,
not already implemented refusals. Conversion preserves hard-link groups using
new ReFS file IDs, not original numeric NTFS IDs. Bounded EA preservation has
native conversion/cold-boot evidence at2aef493, and audit/null/empty DACL
preservation atfa6396f. Actual absent-DACL/empty-SACL sources remain unqualified;
MS symlink/junction preservation has scoped native evidence at439a55c; other
reparse/provider forms remain outside the current preservation profile.

## Build tools

Work explicitly in D:\code\ntfs2refs. Rust is pinned to 1.98.1.
Use C:\Users\mfara\.cargo\bin\cargo.exe when Cargo is absent from PATH.
For builds set both TEMP and TMP to D:\code\ntfs2refs\target\tmp.
Inspect PowerShell exit codes and use only the focused release targets needed.
Do not run workspace-wide formatting or cargo fmt --all: it can touch the
preserved src/main.rs user hunk. Format only files owned by the current task.
Documentation changes do not require another build or native disk run.
