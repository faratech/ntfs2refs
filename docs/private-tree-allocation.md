# Allocation-only canonical tree staging

The metadata/system runf9c4577e923142f486a49b50be4fc50e copied/hashed all three
system streams successfully, then refused a descriptor-view mismatch during
the old child-first restoration. Result92574939fad21584b373fd8a7ea0605ae2910ab11f905e9d388a584bc7f5fc94
and read-only user-metadata observation416b1f2707b9abf0fa93ec1c006e27ecc5037de00a7593fa8e6e48fa6e86123a
are preserved OFF at63b6e205-f174-4600-8c2b-253a37c94cf1, all34 checkpoints.
The observation confirmed four child files already had matching kernel/API
control9404 while untouched root-level files remained private9004. It did not
query SVI, so it does not establish the exact failed descriptor component.

The restorer now performs security parent-first, explicitly aligns DACL
protection using the source's real non-null ACL when that bit differs, then
uses BackupWrite for the full descriptor. Basic metadata follows child-first,
with exact final ID/basic/both-security-view comparisons still required. This
uses the documented [protection flags](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-information)
and [SetSecurityInfo inheritance behavior](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo);
no mismatched bits are masked. Build passed; fresh `-ParentFirstMetadata`
requires all34 checkpoints/restored6ff/new output root. Native result pending.
No unit tests added/run.

## Canonical metadata and small system payloads

The compact staging path now supports explicit `--restore-source-metadata`.
Before publishing source metadata, it copies only the recognized bounded SVI
streams through the checked NTFS reader. Existing formatter objects must retain
their measured IDs, single-stream/link shape and bounded length; missing known
objects are created privately. Every supplied stream is flushed and fully hashed
back. Supply is one-attempt only, with at most1 MiB per stream/3 MiB total; unknown
system paths refuse. The current three source streams total20,568 bytes.

After closing the private user handles, the existing exact-enrolled-guest
`cache_refresh` restorer checks the complete canonical namespace, restores both
security descriptor views plus basic metadata, and now performs a final all-
object identity/basic/security readback after parent/root restoration. It writes
no large user payload. This publication path remains confined to the existing
isolated disposable guest/disks; it is not an online production exposure policy
for uninitialized scratch files.

Source-backed routes now record native file IDs. After restoration, each owning
file's ID/EOF/link state and every tracked physical range are rechecked before
and after a fresh mounted bitmap capture. Allocation observations therefore
follow all small system writes and metadata COW, rather than predating them.
The shadow is then frozen and captured through the existing difference reader.
Source admission, frozen graph completeness and cutover/recovery remain separate.

The controller's fresh `-RestoreSourceMetadata` case requires all32 preserved
snapshots/restored6ff, the same4-GiB forecast/768-MiB changed-byte cap, and a new
root. Release build and controller syntax passed; native new-path result pending.
No unit tests added/run.

The initial metadata run78bf6520896940fbac88bcac59b5e2c2 refused `tracking.log`
before system writes because its preflight incorrectly reused the two-name
formatter-cache whitelist for newly created admitted source files. Result
797a34b7ccdc5a9ddd9a665f46b70431a739cd2185f449e82dafde4723fa61e5 was preserved
OFF at40da8cfb-e985-46a8-ad4a-2508ff0fe46b, all33 checkpoints, source stayed3.
The preflight now distinguishes existing formatter objects from absent admitted
source files, matching the established full-shadow policy. Unknown existing
target objects still refuse; bounded admitted source files are created normally.
The fresh `-AdmittedSystemFiles` controller uses all33 saved snapshots and a new
root. Release build passed; native result pending. No unit tests added/run.

## Native frozen difference capture passed

Run98c2e2625f94488b8dfbb85eb3118184 PASSED end-to-end private staging,
mounted allocation capture, native LOCK/dismount/offline/read-only freeze,
source-backed comparison, durable changed-cluster capture and bootstrap
inspection through `DifferenceImage`. Producer
7249c42533a88a2f1262ca01a6101f960176b679f14a96852dc5f6e5a9967b53
was built from0d2e0f6 plus the pre-existing main.rs change.

| Observation | Bytes |
|---|---:|
| Conservative selected target set compared | 14,764,498,944 |
| Equal selected bytes served by original | 14,694,330,368 |
| Dense changed-cluster file,136 ranges | 70,168,576 |
| Logical NTFS prefix reads | 8,590,196,736 |
| Shadow metadata/tail reads | 6,174,302,208 |

Result SHA-256:
1f4cac974ccee3e36108c33ccf51d4d3a4a6cd416d6e0d8e168b795e9d595086.
Packed SHA-256 (independently rehashed through the guest filesystem):
25a68f1f4c425bb4e4efbc390a251debdbea5b49ea9d14e28ee23e2371d3a1c6.
Input-plan SHA-256:
a8560a407dc0a4ff53aa35f65a099de35d98c3c05ec0a9cc4c5616cac4a05397.
Ordered selected candidate/source digests are retained in the result; they
include range framing and are not whole-image hashes.

The source stayed offline/read-only. The shadow was also offline/read-only
during comparison. Only18 small/tail bytes were initialized through native
private file writes; large prefixes were supplied from NTFS on demand.
The final difference-backed inspector validated the VBR checksum; this is
bootstrap inspection, NOT a complete filesystem graph or native-driver mount.

Evidence root:
`.lab/hyperv/streaming-v2-20261027/difference-capture-mounted-bitmap-20261028`.
The packed file remains within the preserved guest at
`C:\ntfs2refs\private-tree-98c2e2625f94488b8dfbb85eb3118184\changed-clusters.bin`;
no redundant host copy was made. Metadata reports, pins and child-storage
observations are archived on the host.

New VHDX child filesystem backing: OS792 MiB (including the66.9-MiB changed
file and normal guest boot activity), source4 MiB, journal13 MiB, shadow138 MiB;
total947 MiB, excluding every parent/base, host reports and physical-device I/O.
These are lab backing observations, not a universal conversion scratch bound.
The worker's sampled working set was about4.3-7.4 MiB during capture, not its
measured peak or total VM memory. After clean shutdown, checkpoint
ee605f95-f281-4ad6-90f5-324ae50aaf25 preserved all32 snapshots, parent6ffb6bdc,
and released the VM's4-GiB RAM. Cap256 GiB/reserve64 GiB unchanged.

No source conversion was performed. Restoring source metadata/system objects,
independent frozen required-byte reconciliation, candidate admission and
journaled cutover/recovery remain. No unit tests added/run.

## Frozen source-backed difference capture

The staging helper can now preserve live typed routes across closing all
private handles, freeze the shadow with native allocation observations, inspect
its redundant bootstrap and construct the conservative metadata-inclusive
candidate set. It saves pre-freeze, allocation-witness and frozen-header evidence
before later steps can fail. Post-lock fallback is explicitly not a frozen
required-byte graph certificate.

With `--compact-output`, the source-backed reader compares every selected4-KiB
candidate cluster against the actual frozen original. Only differing clusters
are written to a new dense file, with a768-MiB default hard output limit checked
before each changed-cluster write. Equal selected clusters use original bytes;
no reservation is dropped by interpreting its purpose. Capture has fixed64-KiB
comparison buffers, a65,536-range index bound, selected-source/candidate/packed
digests, byte accounting, durable flush and final source/shadow state checks.
`DifferenceImage` exposes the complete partition through Read+Seek using packed
changes and original bytes, and the helper exercises its bootstrap inspector.

A single cached plain-stream mapping session avoids re-reading NTFS metadata
around every64-KiB chunk on an externally frozen source. Opening, file switches
and final completion recheck actual canonical mappings, initialized length and
identity; failed reads poison the session/candidate. No payload-sized cache is
created. The existing one-shot range reader retains its original behavior.

Controller `-CaptureSourceBackedDifferences` selects a fresh branch/root with
all29 checkpoints retained. Its4-GiB forecast uses the measured same-profile
156-MiB shadow child/about0.7-GiB OS growth,768-MiB output cap and margin, rather
than treating virtual zero-VDL move bytes as physical backing growth. The8.25-GiB
move cap/64 submissions and64-GiB host reserve remain. Native frozen capture is
pending; no unit tests added/run. Source metadata restoration, full frozen graph
proof and compact journal/cutover integration are still incomplete.

The first native difference attempt7ce7e8282ef04fab865a950020d88ea5 stopped
with device-not-ready21 during allocation freeze, before creating a difference
file or allocation witness. Source stayed offline/read-only, shadow online;
no worker remained. Resultd2640c816afc55e86ee200b6bee1bd09da18c84f21141c7ec7f822dfdc082120
was preserved OFF at423b20f5-e254-4d52-bdf7-f990a5f5866c, all30 snapshots.

The freeze implementation now queries the filesystem through an opened root
directory handle, closing it before LOCK; raw volume handles remain responsible
for route/lock/bitmap controls. Microsoft's
[GetVolumeInformationByHandleW contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew)
describes a file handle. This correction has release-build evidence; the earlier
untraced21 does not establish which call failed. Freeze events are now durably
saved even when freeze returns an error, with explicit filesystem-query evidence.
`-RootHandleFreeze` uses a separate fresh branch/root and all30 saved snapshots;
it does not retry the previous constructor. Native corrected capture pending.

The traced run5db90571a9c24aaaaccdaa7742df2468 established the actual ordering
failure: root filesystem query, LOCK and explicit flush all succeeded; both
post-lock bitmap queries returned21. Result
e93d524fbac4a197f53d583a6012746bf61e5a21551ac77701fcdb7f3fcf3e64 and
freeze-events were preserved OFF atba9d58cf-7123-4bae-8f01-1864d832c3ba,
all31 snapshots. The prior root-handle correction did not resolve the refusal.

The candidate flow now captures a separately typed `MountedAllocation` through
the live owning tree before closing handles, then uses the existing basic
LOCK/dismount/exclusion path. Its phase is `mounted-before-lock` and its frozen
graph flag is false. No post-lock witness is fabricated; the old allocation
witness API still refuses failed captures. New `-MountedBitmapFreeze` uses a
fresh root and all31 snapshots; build/controller syntax passed, native result
pending. Independent frozen graph reconciliation remains required for cutover.

## Source-backed relocated payload and compact capture

`PrivateTree::prepare_source_backed_prefixes` makes complete measured prefixes
storage-valid while their files remain private; it does not fill relocated
payload. `source_backed_routes` captures every full-cluster user mapping from
live handles, with complete logical coverage, disjoint physical ownership,
canonical name/length/digest binding and the enrolled source/shadow pair.
The returned type has no deserializer and does not certify a frozen graph.

`general_shadow::source_backed::SourceBackedShadow` is a seekable read-only
candidate over two frozen read-only/offline disks. At measured target payload
destinations it supplies logical NTFS bytes (including sparse/VDL zero rules);
elsewhere it reads shadow metadata/tails. It binds canonical record sequence,
name, length/digest and device identity, caps reads at64 KiB and poisons itself
on a failed read. `finish` checks disk-state and byte-accounting brackets.

`capture_to_new_file` connects this reader to existing compact packing without
first initializing relocated bytes in a shadow. It requires an explicit output
budget and a fresh ordinary file, checks every measured payload is covered by
the proposed write set, compares omitted retained bytes with actual original
physical bytes, writes only selected remaining ranges and durably flushes the
file. Thus logical VDL zeroes cannot silently authorize retaining stale raw
bytes. A failed capture yields no completion receipt. This candidate still
requires a complete frozen required-byte graph, source metadata restoration
and recovery integration before conversion; no new write authority is granted.

Lab `--source-backed-payloads` opts into full private-prefix preparation and
small/tail-only copies, preserving large relocated data as source-backed routes.
It conflicts with full relocation materialization. Native qualification of this
mode initially had release-build evidence only. Native prefix staging now
PASSED in run85e2750d05764f849536d0391362471c, sourcec7e4ab9 plus the pre-existing
main.rs patch, producer
1f49f3a3706e368e2881169b2b7368a80c4cca665843f921bf1a7904cf29c922.
Result SHA-256:
b761140c424384b3638d5cee0d0ab80e8b1997bfe91697ace10548630d24d97c.

All24 measured routes cover8,590,196,736 user-prefix bytes after valid-data
advancement, without copying those prefixes (including relocated data).
Only18 small/tail payload bytes were written/flushed/read back; source logical
charges36 bytes include preflight and transfer. Source stayed offline/read-only.
The new shadow child used163,577,856 backing bytes (156 MiB), excluding parent
chains, OS/journal/evidence and physical device I/O. Evidence:
`.lab/hyperv/streaming-v2-20261027/private-tree-source-backed-20261028`.
Clean shutdown/checkpoint889c1ab0-dfdf-46fc-ae19-32d3d4586203 preserved all29
snapshots, parent6ffb6bdc, and released4-GiB RAM. No cap/reserve increase.

This proves native private-prefix staging/route capture, NOT the frozen
source-backed reader, compact capture, restored security/system metadata,
required-byte completeness or recoverable cutover. Those still need end-to-end
integration/qualification. No unit tests added/run.

## Direct placement of deferred allocations

Deferred zero-VDL holes now first intersect the desired source coordinates
with both live ReFS allocation views. Eligible free subranges allocate directly
at those coordinates; only the remaining holes use scratch, in chunks no
larger than512 MiB. This avoids parking and moving the same deferred bytes a
second time. Every submission retains the native destination/mapping checks,
bootstrap margins, poisoning rules and explicit byte/submission budgets.

Failures now retain bounded placement diagnostics (phase, charged byte count,
verified submission count, sixteen recent phase/object entries and a pending
request). Those observations grant neither resume nor conversion authority.
They distinguish a budget refusal before submission from verified completed
placement; an unrecorded result is not evidence that native I/O never occurred.

The previous whole-tree attempt3eae73c3c92f4517b53f482160d8737f stopped at its
10-GiB budget, preserved OFF atf9976b33-de16-4b00-af74-24d60dcf9b77 with all27
checkpoints. Its new shadow child used155,189,248 backing bytes (148 MiB),
excluding parents, OS, journal and evidence; physical device I/O was not measured.
The direct-placement controller uses a fresh branch/root, a LOWER9-GiB move
budget and11-GiB capacity allowance; it does not retry the partial namespace.
The direct-placement native run40733b161431410192f7dcaafbb99f61 PASSED with
producer41fe513fdc32ff709289ddcc6e48ccf5a91edade4c1e436e5f54d08e81a45f51
(source614c158 plus the separately recorded pre-existing main.rs patch).
Result SHA-256:
916d453e2daddb107d7160489684ce0ce17e0f0ee7a14c38f4b01db2e1a38531.

Twenty-four verified placement submissions charged8,590,196,736 bytes:
six direct deferred allocations2,721,181,696 bytes, fifteen scratch allocations
5,868,765,184 bytes, and three blocker evacuations249,856 bytes. No subsequent
original-coordinate reposition was needed. Final live maps identify
2,721,181,696 original-coordinate bytes; their contents remain unverified.
The17-byte small source stream was written/flushed/read back; source logical
range charges34 bytes include its preflight and transfer. Large user payload
was not initialized/copied. Source remained offline/read-only. This is NOT
completed source admission, logical hybrid verification or conversion.

Evidence root:
`.lab/hyperv/streaming-v2-20261027/private-tree-direct-placement-20261028`.
The new shadow child used153,092,096 backing bytes (146 MiB), excluding parent
chains, OS/journal/evidence and physical device I/O. After clean shutdown the
result was saved at9385a471-acc4-42e6-aec4-969bdde40148, parent6ffb6bdc;
all28 checkpoints were retained and4-GiB assigned RAM released. The lab cap
remained256 GiB and host reserve64 GiB. No unit tests added/run.

## Selective unwritten evacuation

The tree-wide placement implementation now supersedes blanket whole-prefix
parking. It binds current allocated zero-VDL runs from the actual private file
handles, refusing reused/initialized/poisoned states. Deferred holes are kept
distinct from physical ownership and explicitly allocated to checked scratch
locations. Tracking is bounded and must cover the complete full-cluster prefix.
No bitmap bit alone supplies file ownership.

After tracking all files, the existing interval evacuation planner receives
both complete bitmap views, exact measured shadow ownership and desired source
ranges. Only user allocations that block desired locations are relocated;
already correct file/VCN positions remain. Every submission rechecks occupancy
and tracked mappings through the poisoned-on-failure constructor. Destination
bootstrap margins and global move/evidence limits remain enforced.

Final original-coordinate ranges are derived anew from the live tracked maps,
including already-correct positions; they are not inferred just from requested
destinations. The live supply plan still distinguishes these references from
temporary ranges requiring data supply. Logical content and frozen metadata
qualification are separate. This reduces planned unnecessary movement but has
release-build evidence only; no native whole-tree result or physical IO claim
is added. Preserve all snapshots/reserve before native admission. No unit tests
added/run. The older whole-prefix description below is implementation history.

## Source-backed logical hybrid verification

`general_shadow::verify_private_hybrid_contents` now verifies each user
stream from the live supply plan without a duplicate payload image. It reads
original-coordinate ranges at their measured physical offsets from the actual
excluded source and reads only initialized materialization ranges through the
private shadow file handles. Every logical byte must be covered once, within
EOF, and the complete stream SHA-256 must match the canonical source digest.
An empty stream still requires its canonical empty hash. Buffer size is64 KiB.

Native path/length/type/link/deletion and tracked mappings bracket each file;
the complete live supply plan and excluded-source state bracket the pass.
Read accounting must equal the plan's reference/materialization totals. Shadow
reads intersecting source references or exceeding its initialized prefix are
refused, so the verifier cannot accidentally authenticate garbage placeholder
bytes instead of retained source bytes. Dedicated verification-read counters
remain separate from materialization readback. Source VDL/encoding mismatch
that makes raw referenced bytes differ from canonical logical data fails the
whole-stream digest; this function does not silently normalize those cases.

The staging CLI selects this only with explicit `--verify-logical-hybrid`
after `--materialize-relocations`. This is a logical payload proof, **not** a
frozen on-disk ReFS graph or source-admission certificate. System metadata,
source ACL/time restoration, complete required-byte capture, storage admission
and recoverable cutover remain pending. Release build passed; native execution
of the whole-tree mixed path remains unqualified. No unit tests added/run.

## Live payload-supply plan and relocation streaming

The private tree now retains original-coordinate ranges as internal state
derived from successful native moves, rather than consuming serialized
`success` flags. A complete placement attempt creates a non-deserializable
`SupplyPlan`; subsequent placement invalidates it. Planning rechecks all native
mappings and accounts for every user logical byte as either an original-source
reference or materialization. Partial final clusters always remain in the
materialization set. Bounds/overlaps and at most4,096 supply ranges are checked.
Failure/partial placement cannot produce a complete plan.

`materialize_private_supply_plan` admits an explicit materialization-byte
budget before data writes, advances every fully tracked prefix (including
fully referenced files), then streams only the materialization gaps through
the64-KiB checked-source/private-readback path. Writes overlapping live
original-coordinate references are refused. Source binding/exclusion and
native placement are checked around the operation. The output retains up to32
sample receipts plus a length-delimited ordered SHA-256 receipt digest, rather
than storing all chunk receipts or file-sized buffers. It does not claim that
the unfilled shadow references contain source bytes: source-backed hybrid
verification and canonical source admission are still pending.

The CLI requires explicit `--materialize-relocations --place-source-prefixes`
and a `--max-materialize-bytes` budget (default256 MiB). This replaces the
small-only loop for that mode and does not duplicate retained payload.
Metadata/physical IO can exceed selected logical-byte accounting; the current
source reader revalidates metadata per chunk. Source/system metadata
restoration and recoverable required-byte cutover remain incomplete.

Release build passed; native whole-tree placement/materialization has not yet
been executed. Admission must forecast possible internal move traffic and
actual backing growth, preserving the64-GiB host reserve and all snapshots.
No unit tests added/run. The working full-shadow path is unchanged.

## Tree-wide unwritten placement implementation

`PrivateTree::place_source_prefixes` now parks every user-file full-cluster
prefix before submitting any final original-coordinate move. Scratch selection
uses both complete native bitmap views, excludes all desired source ranges and
the first/last MiB, and requires a sufficiently large free span. No source
disk is moved. Before IO it checks exact file names/lengths/zero-prefix state,
source-run alignment/coverage, non-overlapping desired physical ownership and
global range/move budgets. Partial tails are handled by the separate range
materializer rather than reinterpreted as complete clusters.

Parking and final moves use512-MiB-or-smaller chunks, at most1,024 submissions
globally, with16-MiB retained move evidence. Final candidates come from the
fresh two-view free-subrun planner. Each actual move again checks live occupancy
and all expected file mappings through the tested unwritten constructor.
Refusal or incomplete evidence stops the operation; no force/retry path or
original NTFS mutation exists. The output distinguishes original-coordinate
byte ranges from payload-content verification, which remains false.

The staging CLI exposes this only with explicit `--place-source-prefixes`.
It runs placement before small data writes; when combined with tail staging,
it requires complete placed-prefix coverage instead of the unplaced-scratch
preparation path. Temporary ranges still require actual data supply and the
original-coordinate ranges need source-backed hybrid handling. Source metadata
restoration and required-byte/cutover/recovery qualification remain pending.

Release build passed. This tree-wide path has not yet been run natively; the
prior1-MiB reposition result does not qualify whole-tree parking. Whole-workflow
physical movement/scratch forecasting must be admitted before a new native
run, retaining the host reserve and all evidence. No unit tests added/run.

## Native partial-tail staging result

Sourcec079e47 adds explicit `--prepare-large-tails` staging. Before a selected
partial-tail write, the constructor can advance an **unplaced private scratch
prefix** without copying its bytes. It refuses this option if placed-prefix
coverage would be bypassed. The result explicitly marks original positions and
source prefix contents unverified. Files remain protected SYSTEM-only; this
option cannot be treated as retained-data proof or source write authority.
Real retained placement must precede validity advancement/materialization.

Native run`cc4109eec29a4643ae5a7e4d1021f8e6` passed with producer
`98868f9f27d863e6b98af39305292a91e233bf05b08ac2aaf543255b64a2388c`.
The command read the actual source byte at logical offset8,589,934,592 in the
8,589,934,593-byte file, wrote only that byte and verified readback after flush.
That zero byte's SHA-256 is
`6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d`.
The source range proof correctly says `whole_stream_hash_matched: false`;
neither the source-range read nor target readback scans/validates its prefix.
The empty file and17-byte café file also passed, giving18 target payload
bytes written/read back,36 source logical-byte charges including preflight,
and8,589,934,592 private prefix bytes made storage-valid without a payload copy.

Full result SHA-256:
`1629301c5b19af272f5436258c1a072f8771fc758a71ffd9b8f1a74b65562694`.
Request:`5303d42d780c119b381d51992fe5d92f63ba3922ba92e9ba82f1ffed26ed8dfd`.
Inspection/tree pins remain the matching candidate11 inputs documented below.
Evidence:`.lab/hyperv/streaming-v2-20261027/private-tree-tail-materialization-20261028`.
After clean shutdown the non-sparse new shadow child measured157,286,400 bytes
(150 MiB), excluding shared parents/OS/journal/evidence; physical-device IO and
whole-workflow scratch remain unmeasured. OFF checkpoint
`1da04080-dceb-4127-9540-c6826e45c543`, parent
`6ffb6bdc-4da6-4060-8b4e-0c07a83d11b3`, preserves the result. All25 snapshots
remain and VM RAM is released. No unit tests added/run. Native large-prefix
placement/content supply, source metadata restoration and compact recoverable
cutover still need integration. The working converter path is unchanged.

## Native small-stream materialization result

The staging command now explicitly selects `--materialize-small` with pinned
`--inspection`/`--inspection-sha256`. It checks selected source records before
creating a namespace, then copies only ordinary user streams of at most4 KiB
through the checked range reader. Empty files are included; system streams
remain pending. The8-MiB cumulative budget covers preflight plus transfer for
at most1,024 such files. Large-stream initialization is not selected.

Native run`7221c22bb02641cebf1b4db6ac4d4aad` passed with producer
`34542fc824f0459703581d25bb3d2c6b2a8e1420eab836c428d86fb26b33e049`.
The producer uses the ee6cdca implementation and separately recorded controller
source. It used the matching candidate11 source/tree from its saved frozen
NTFS branch. Inspection file SHA-256
`307c396b8449831618f96d34a4bfcd60443c58197f3cb6221ea076df37d259d3`;
tree`1602601cde53a7aa78d95e34c3de2ea18f5c0b65ddd8287ece9c84d81cbce215`;
request`bacdf35c36c9ba477eefd33de9a3ae34709507ccfab3918716268c53a7b2c313`.

The empty stream matched SHA-256e3b0...b855 without data transfer. The17-byte
`notes/café.txt` source matched
`f031f647ec5e176ec8131de1d6024e2447b5d75597bb320fd097fb4cc10783bf`,
was written/flushed to its same named private target, and read back identically.
Source logical-byte charges were34 (preflight plus transfer); destination
payload writes were17 and readback17. All six user files were allocated,
including8 GiB+1, while large payload initialization remained disabled.
The source stayed offline/read-only and received no payload writes. Source
image admission and metadata restoration are still not established by this run.

Original result SHA-256:
`3ebb5fab6db1f34d9f865a560fc01b43e3db9253f01caf05d5699662e4c9c799`.
Evidence root:`.lab/hyperv/streaming-v2-20261027/private-tree-small-materialization-20261028`.
After clean shutdown, the new non-sparse shadow child measured121,634,816 bytes
(116 MiB), excluding shared parents, OS, journal and other evidence. This is
not a full-workflow scratch bound or physical-write measurement. OFF checkpoint
`a6fd7138-6e44-46cb-89a9-883e360bd00e`, parent
`6ffb6bdc-4da6-4060-8b4e-0c07a83d11b3`, preserves the outcome; all24 checkpoints
remain and VM RAM is released. No unit tests added/run. Tail-gap behavior,
large payload mapping/supply, source ACL/time restoration and recoverable
low-scratch cutover still need integration/qualification.

## Bounded exception materialization

The subsequent implementation adds
`ntfs_inspect::read_plain_stream_range_into` and
`general_shadow::materialize_private_range`. A caller-owned64-KiB-or-smaller
buffer receives only the selected logical range. Before and after the read,
the existing checked-attribute path revalidates geometry, MFT bootstrap,
file identity, run mapping, lengths and inspected stream digest. Holes and
bytes beyond initialized length still return logical zeros. Selected bytes
are charged to the existing cumulative transfer budget; metadata IO remains
separate. A whole-stream small read must match its inspected digest. A partial
range proof explicitly does not claim whole-stream content verification.

The owning-source wrapper requires the actual excluded source binding to
match the private template, binds canonical file length/hash/name/index, and
checks source state around both reading and materialization. The native file
can accept only a bounded write no later than its tracked valid prefix; a
write beyond that prefix is rejected before IO. Thus a final byte at8 GiB
cannot implicitly zero-fill an uninitialized8-GiB gap. Placement must happen
before initialization; complete placed-prefix coverage is still required for
the one-time VDL advancement.

Each materialized range is explicitly sought, written, flushed, read back and
compared. EOF/type/link-count and all previously placed mappings are rechecked.
Failure poisons the private file and retains it for diagnosis. Permissions
remain protected SYSTEM-only; no source metadata is restored early. Empty
ranges do not authenticate a nonempty stream. Materialized and readback byte
counters are reported separately with checked aggregation; ordinary template
allocation still reports zero. No raw source writer or conversion authority
is introduced.

These APIs have release-build evidence, not native materialization/conversion
qualification. They are not selected by the working full-shadow converter or
the allocation-only CLI yet. Next connect them to the process-lifetime
placement/materialization/freeze workflow and qualify actual resident/tail
data. Full payload supply, root/system metadata, source metadata restoration
and complete required-byte coverage remain pending. No unit tests added/run.

Sourceb3c7d3f connects the canonical `shadow_tree` to the native private
constructor through `general_shadow::allocate_private_tree`. The separate
`lab-allocate-private-tree` command stages the original Unicode user paths and
file lengths without copying their contents. It is not a conversion command.
All file and user-directory DACLs are protected SYSTEM-only. Root/system data,
source ACLs, timestamps, attributes and payload supply remain explicitly pending.

The native template owns its file handles and exposes placed-prefix operations
through the unwritten constructor. It requires the enrolled isolated guest,
excluded source, independent writable ReFS/4-KiB shadow, fresh user namespace,
bounded paths/counts and complete parent ordering. No source write handle is
available. Existing formatter-cache handling uses the earlier narrow preflight;
unknown system entries refuse rather than disappear. Source-image hash and
complete admission are not established by supplying canonical JSON.

## Native outcome

Run`29abdc44bbcf42e69783c3736c1fb349`, producer SHA-256
`df1c5f22ee4a17b800e61b59a555c6df7a7d272774543e5ae7bded165a35a4d5`,
constructed the namespace but exited1 during reporting: the reporter wrongly
requested a nonresident retrieval map for an empty file. Original refusal
SHA-256`116cb2579eaec82fae50ff81f4b3c5702b0044656dcecdfa5df1bea0b7601c92`
is preserved. Construction/formatting were not repeated over that run.

Source3535d78 distinguishes empty/subcluster allocations and adds a separate
metadata-only observation command. Observer
`f0f7140b4eb8419ea3dd910de69770ad`, producer
`d6d47037644788208f5013d304fe396e339629a03b32bb44c221b97e6d80ded8`,
exited0 and verified the exact user namespace, distinct single-link file
identities, lengths and applicable retrieval maps. Its144,473-byte result is
SHA-256`21d2253c40e0be83c8ab431e4351130e3963183be7dcad78e4a4531cf9d3ec2c`.

Six user files total8,590,196,754 logical bytes, including8,589,934,593 bytes
in the large file, plus three user directories. The empty file has0 allocation;
the17-byte file has24-byte subcluster allocation. Large-file allocation is
8,589,938,688 bytes. The canonical13-object input also accounts for root/SVI
and its system files; these are pending rather than claimed reconstructed.
Both construction and observation issued zero user-payload read/write calls.
Stored descriptors independently confirm SYSTEM owner/group and one protected
SYSTEM full-access ACE for all six files and three user directories.

The NTFS source remained offline/read-only. This establishes allocation-only
user namespace staging, not payload contents, stored-validity after reboot,
source admission, metadata restoration or conversion of the original partition.
No unit tests were added or run. Evidence is under
`.lab/hyperv/streaming-v2-20261027/private-tree-allocation-20261028`.

## Storage observation and preservation

After clean shutdown the new shadow child used140,509,184 filesystem storage
bytes (134 MiB), despite the8-GiB logical file. The metadata-only Rust observer
uses [GetCompressedFileSizeW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getcompressedfilesizew)
and checks stable file identity/length/time. Here the child is non-sparse and its
file length equals the reported storage size. This includes the child's format
and allocation work, excludes shared parent images/OS/journal/evidence, and is
not a total scratch bound or physical-device I/O measurement. Parent-independent
construction and a complete required-byte capture remain unproven.

OFF checkpoint`ebb2feb4-dc0f-4551-93ee-9a031f96b7ca`, parent
`524c530e-2f6e-4ff6-849d-3bf7a9af71bf`, preserves this state. All18 earlier
checkpoints remain (19 total), including converted candidate12. The VM was
cleanly stopped and its4-GiB RAM released before returning to candidate12's
already-authorized acceptance sequence. Do not redispatch either template task.
