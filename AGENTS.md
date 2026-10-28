# ntfs2refs project guidance

## Objective and working approach

Build an offline NTFS-to-ReFS converter that runs on the machine owning the
volume and preserves eligible payload blocks in place. Prefer Rust. Hyper-V
is laboratory infrastructure; the converter must not depend on a hypervisor.
Focus on nonboot data volumes. Boot conversion remains deferred.

Mike's latest priority is a frozen native-shadow alpha and end-to-end conversion/
recovery tests. Independent-writer research and its journal-fencing prerequisites
are parked off that path; see [the parked scope](docs/isolated-journal-writer-exclusion.md).
Preserve all existing VM/checkpoint and experiment evidence. Use a separately
owned disposable alpha fixture for new native tests, with exact bindings and budgets.
The frozen engine is tagged `alpha-native-shadow-20261026`; follow
[the alpha scope](docs/native-shadow-alpha.md). Work on its native harness and
conversion/recovery results before adding more parser or writer features.

The later disposable large beta is VM `6c4793d2-cdee-468b-bf3b-1c11cae0b501`,
240 GiB NTFS/64 KiB to ReFS/4 KiB, fixed 4 GiB RAM, no NIC. See
[its actual state](docs/native-shadow-large-beta.md). Its first public run
refused before source freeze on a legacy fixed-layout TxF path; failure receipts
and staged binaries are preserved. New attempts must first prove the prior task
terminal and use fresh candidate/run paths. Do not reset any earlier protected VM
or transfer the frozen alpha's qualification to this engine/profile.
Candidate 2 completed its source hash, then refused on MFT mirror slot 24. Its
terminal evidence and 64 KiB raw captures are archived, and checkpoint
`cbd04cca-3117-4b25-8731-efa56a5e0ffd` preserves the refused beta branch. The
backup correction retains exact first-four comparison and full-region hashing,
recognizing only narrow inactive format padding in additional mirror slots;
other discrepancies remain fatal. The beta alone was restored to its own
baseline `506bf3fe-afac-40fb-bfe9-e357141506d2` after terminal proof. Do not
redispatch an old run or infer any native conversion success from these fixes.

Candidate 3 is run `dab1b80b92c2432e80a4052502f9165b`, original pinned converter
`38b5b8d142e612000ee00385efc3b4414293b13abad23f71e576f1c5e412b5f2`.
It completed successfully at 2026-10-27 13:11:45 UTC, before Mike's host reboot.
The fourteen-object admitted tree passed strict native verification after boot,
the Rust mutation workload, strict verification afterward and another clean
reboot/strict verification. Source geometry is 240 GiB NTFS/64 KiB, target
ReFS/4 KiB. The case retained zero bytes, relocated 134,500,352 and materialized
105; 94 patches wrote 337,903,616 target bytes with a 675,831,546-byte journal.
Shadow payload initialization was still 134,500,457 bytes; physical scratch and
whole-workflow physical I/O remain unmeasured. Do not claim efficient retention,
expanded-geometry interruption recovery or power-loss qualification from it.
The beta is OFF, preserving converted checkpoint
`2297eaff-fe69-4d2e-ad30-3f965f9024ff` and mutation/reboot-passed child
`cb6a32e9-f237-4d3f-a807-d97fc73f73a1`. Preserve all five beta checkpoints.
No old conversion task/journal may be replayed after its durable handoff.
The post-preservation observer's first attempt refused a timezone-stringification
bug before native verification or mutation; its intent/failure remains, and a
fresh read-only attempt passed after UTC roundtrip handling was corrected.
See the beta report/registry for exact producer and separate postcheck pins;
later executable builds do not inherit this bounded result.

The separate `experimental_streaming_tree_v2` source profile adds an explicit
streaming-payload envelope beyond v1's unchanged 4 GiB budget. Bind selection
requires `--experimental-streaming-payload --experimental-large-tree
--experimental-large-journal`. Its 2 PiB payload/partition routing envelope is
compilation evidence only; metadata/feature/count limits, actual scratch,
16 GiB journal ceiling and live admission/recovery bindings remain. Its first
native attempt refused during shadow construction and must not inherit
candidate 3 or frozen-alpha qualification.
No unit tests have been added or run during this work, per Mike's instruction.

The separate streaming v2 fixture is VM `2401593c-4b30-472e-9b6d-c9534cbaa599`,
under `.lab/hyperv/streaming-v2-20261027`, with new independent data disks and
a writable OS child of the content-hash-verified archive parent. Hyper-V added
two read-only parent ACL grants; exact descriptors/rule deltas are retained.
It contains Unicode names and a 4 GiB+1-byte ordinary zero file, with no source
extent moves or aging. Its clean NTFS baseline is
`775f4db8-8635-486c-b6eb-7098426b51a6`. Candidate 1 run
`8c9c50c1fc6c4fd3a0fc3aeadd61fb72`, PID 1552, terminated with a refusal at
17:42:42 UTC during shadow construction. Its NTFS source lacks IndexerVolumeGuid,
whereas the freshly formatted ReFS shadow contains that 76-byte cache. No raw
apply or source payload write occurred. Terminal evidence is archived, and OFF
checkpoint `2a265703-70bc-44fd-a0c5-49999384b9db` preserves the failed branch.
Producer SHA-256 is
`624405d2517a4ae51ccf83270eecfdb83ebccb8f8d726e25f2dc651a116e4076`.
The V2-only normalization validates the exact target-only cache's identity,
single-link ordinary-file type, sole unnamed stream, 76-byte GUID and absence
from the source before deleting it through Windows. Unknown SVI entries still
refuse. Legacy profiles retain their existing behavior. Use its dedicated
collector and never redispatch on an observation timeout. Candidates 1/2 did not
convert; candidate 3's later success is recorded below and in
[the run](docs/streaming-v2-native.md).

Candidate 2 (`b82e5dbbdd1d4ae899315954c37a2609`) also refused before source
payload writes, with a generic access-denied error in construction. Its raw/native
source gates passed; target preservation remained unqualified. The new cache
handle omitted FILE_WRITE_ATTRIBUTES needed by access-time suppression. That
right and syscall-specific error context are now added. Candidate 2 is archived
and preserved OFF at `beddfbe8-f40d-4903-9c2c-c6162b3b4349`; only this disposable
VM was restored to its own original NTFS baseline. No old task is redispatched.

Candidate 3 is the completed streaming attempt: run
`e5d4b7dfa9474dedb3e19b67c1b03f24`, PID 2540 created 18:10:37 UTC,
producer `98d02a4f698d44d7ba89c5a45c24b49422eae363` plus the unchanged
capabilities-only dirty patch. Converter SHA-256 is
`a28a4a5b74839754181f4cc9a44d97aab383b665f2249746418457c8bcde6f39`.
At 18:12 UTC the same task/process was live in source qualification. Observe
with `Collect-StreamingV2Conversion.ps1 -Candidate candidate3`. Do not restart.
`Archive-StreamingV2Terminal.ps1` archived and rehashed 33 guest run/stage files.
Rust postcheck tools are pinned in this candidate's
`rust-postcheck-tools`; use the existing beta postcheck/reboot scripts with
the explicit `-StreamingV2` switch. The task exited 0, native conversion passed,
and the handoff is closed. Result SHA-256 is
`583aacb6d214d67919caa7dfc269ad5e8856482de75a05caaa7a832cb03a1710`,
expected tree `0992ec867426127b25e81b672a352d3cebe9f881e7263738e12a94a0c100dc50`.
314 patches wrote 339,808,256 bytes; the journal is 679,676,029 bytes.
No retention, streaming interruption recovery or reboot/mutation qualification
is claimed from that result alone. Never replay its old journal after handoff.

The same candidate 3 later completed native shadow construction (13 objects,
4,295,249,950 bytes initialized). The cache normalization event succeeded.
All six measured retention candidates were metadata-blocked and unsubmitted;
no retained payload is established. Its copied construction report hash is
`1f3ceb7db217264643bfeb4f2aaca82ebb44e8a1cf79237cb156ace0e94f35ec`.
The task then entered target preservation. Do not treat that intermediate
report as a conversion certificate or trigger postchecks before terminal handoff.

Later source adds CNG SHA-256 only to streaming V2's three full-source hash
passes and protected target before/after brackets; see
[the measured scope](docs/native-sha256-performance.md). The same
real 1 GiB corpus image matched its pinned digest with both backends; native
was about 1.66 times faster on this no-SHA-instruction host. This is a host
observation, not native conversion or guest performance qualification. Candidate
3 used its staged 98d02a4 engine. Do not replace/restart it or assign its
outcome to the newer binaries. Legacy profiles remain on their old hash
path. No source exclusion, read coverage or recovery gate was removed.

Later streaming V2 journal preparation also selects CNG for its initial full
comparison/postimage hashes, including its existing bounded shadow worker.
Native hash handles are created on that worker and errors propagate as Results.
The two full Rust rechecks, patch/range hashes, I/O order and serialized journal
remain unchanged. This is source/build work only; candidate 3 used
98d02a4 throughout. Do not assign its outcome to these newer builds.

The initial independent BeforeMutation observer refused: Windows regenerated
SVI/IndexerVolumeGuid after mount and advanced SVI access/write/change times.
The diagnostic found every admitted stream hash unchanged and only that internal
directory's times changed. Both failed/diagnostic reports remain in
`candidate3/rust-postcheck`. A V2-converted-only policy now validates the extra
cache's exact name, stable ID/type, single link/stream, 76-byte braced GUID,
parent stability and bounded timestamps. It accounts for the extra cache and
permits only SVI's monotonic access/write/change times; its creation, attributes,
security and every user object remain strict. No operational file is deleted
or retimed, and the original expected tree remains pinned. This policy is not
enabled for pre-handoff shadow qualification, old profiles or a source-present
IndexerVolumeGuid. Versioned postcheck toolsets retain the old binaries and
allow a new read-only BeforeMutation attempt; a mutation cannot be retried.

The corrected toolset v2, source `4f187a502bcb2a27dbf9b47e19b7b4897eb59525`,
passed BeforeMutation attempt 2, the preserved converted boot, mutation,
verification afterward and another clean reboot/verification. The VM is now OFF
at `157284d6-91fc-4b2b-ba6c-3052a0c413bc` (mutation/reboot passed), parent
`8d4b9eaa-d814-4a3a-aa89-056e817d47d2` (converted/native passed), parent the
original NTFS baseline. Preserve all five streaming checkpoints and both
terminal/postcheck archives. Never replay the old journal over this handoff.
The main engine is still the original 98d02a4 producer; newer CNG builds are
not qualified by this case. The registry records only this 52 GiB source,
Unicode/4 GiB+1 zero-file case and its explicit system-cache normalization.
The next native gate is streaming interruption/resume/rollback, rather than
repeating the completed conversion/mutation/reboot case. Low-scratch retention,
nonzero large files and broader capacity/features remain incomplete.

The passed streaming branch remains preserved; only its own VM was restored
once to NTFS baseline 775f4db8 for the separate controlled recovery candidate 4.
Run `61d60b73d23b48dcb7e777328169ddc9`, PID 4120 created 20:26:32 UTC, was live
in target preservation. Controlled producer SHA-256 is
`a5e557d422fa73faba8e6a2683182a3b60536be61714f9e38684c891366a44e8`,
source caf9853 plus the unchanged capabilities dirty patch. It will exit 86 after
one flushed write, before handoff. Observe that exact task; do not redispatch.
See [the recovery branch](docs/streaming-v2-recovery.md). No recovery outcome is
recorded yet. Preserve the interrupted branch and verify persistent exclusion
after reboot before executing explicit recovery with its original staged helper.
It subsequently entered journal preparation; its initial CNG comparison passed
and the existing full Rust source recheck was live. The interruption point has
not yet been observed. Once terminal, use the archive/preservation controller,
then the single-boot exclusion controller before explicit recovery. Recovery
tasks have their own collector; never redispatch either producer or recovery on
an observation timeout. Controller details are in the recovery branch document.

Candidate 4 subsequently exited 86 at the one-flushed-write boundary. Its
32-file terminal archive is verified and the interrupted OFF checkpoint is
`713e5fad-45fe-4200-9f6c-dabb669cc9ad` (parent baseline 775f4db8). A clean boot
at 20:55:14 UTC proved persistent source offline/writable and shadow
offline/read-only, with no automatic producer restart or source mount attempt
by the controller. After a pre-dispatch PowerShell filter correction, resume
was dispatched once: task `N2R-StreamingV2Recover-Resume-61d60b73d23b48dcb7e777328169ddc9`,
PID 5052 created 20:56:59 UTC. It was live in journal/target/shadow validation.
Use the dedicated recovery collector; do not redispatch or finalize until the
actual resume task succeeds. The old producer's exit 86 remains historical;
it does not describe the later recovery state. No completed recovery is claimed.

Resume later exited 0 with the exact expected complete postimage
`6fa71cb5281c1af88334260bd453eb8887996596f83f9f08498efe7493a08383`,
remaining excluded and pre-handoff. Resume result hash is
`e23659bff751ebef9685b045e735b0f7fc7e7ced00a849dda574f600e65a454a`.
Explicit Finalize is now active: task
`N2R-StreamingV2Recover-Finalize-61d60b73d23b48dcb7e777328169ddc9`,
PID 580 created 21:05:14 UTC, same original staged recovery binary. Observe with
the recovery collector `-Operation Finalize`; do not repeat resume or finalize.
No mounted recovery result is established yet. Preserve the successful branch
before later rollback qualification on a restored partial-snapshot fork.

Finalize later exited 0 with native ReFS verification and restored source label.
The recovered branch is preserved OFF at
`b4ef39f3-af21-404e-b9e1-68c65e3703e0`, parent interrupted 713e5fad. Its
handoff is closed. Only afterward, the full owned VM snapshot was restored once
to that partial pre-handoff checkpoint for a separate rollback fork. Exclusion
survived boot at 21:12:08 UTC. Rollback is now active: task
`N2R-StreamingV2Recover-Rollback-61d60b73d23b48dcb7e777328169ddc9`,
PID 676 created 21:12:47 UTC, original helper. Observe with `-Operation Rollback`;
do not restart it, replay on the saved resumed ReFS branch, or claim rollback
success before the actual result. The kernel/hypervisor snapshot is test setup;
the NTFS restoration itself must be performed by guest-local journal recovery.

Rollback later exited 0 and restored the exact frozen NTFS image
`097e11106a058e6a8acc0238bad00347761173161c95f11ea86fab081b6517c0`.
Native NTFS availability and all six user-file lengths/hashes passed. The VM
is now OFF at `40fb292c-0fd6-4048-bf40-93f2bc242ca3`, parent the saved partial
`713e5fad-45fe-4200-9f6c-dabb669cc9ad`; native resumed ReFS remains at sibling
`b4ef39f3-af21-404e-b9e1-68c65e3703e0`. Preserve all eight streaming checkpoints,
both outcome archives and the partial state. Old journal replay is closed on
both completed outcomes. The registry records one controlled flushed-write
process fault, exclusion after reboot, exact resume/native ReFS and exact
rollback/native NTFS. No storage-power-loss, exhaustive fault sweep or
post-recovery mounted-outcome reboot qualification is claimed. Later cached
retention planning builds inherit none of this producer's result.

Subsequent source caches the two planning bitmap views across V2 source runs
only while no submitted move/mapping change occurred. Every actual move still
rechecks fresh views; old profiles retain per-run capture. That cache did not
produce candidate 4 and has compilation evidence only.

Later source also replans the same V2 source run after confirmed successful
retention to use newly freed shadow slots. It stops on native errors, lack of
progress or the existing attempt cap; every move retains fresh dual-bitmap and
mapping checks. No metadata region is moved or bypassed, and no NTFS source
extent is prearranged. Old profiles retain their single-pass behavior. Native
qualification and low-scratch payload initialization remain incomplete.

Later source wires streaming shadow-user evacuation before retention. The new
interval planner uses complete native maps and measured file ownership; the
executor accepts only the separately bound shadow and checks live ID/mapping,
fresh dual-map free space and source-range exclusion before every native move,
then measures the exact result. It never moves metadata or touches the NTFS
source. Planning resource/space limits are recorded before any move and retain
the old conversion path; execution failure aborts, without retry. No existing
native success qualifies this code. See [the scope](docs/shadow-user-evacuation.md).
Batch evacuation for dense layouts and avoiding full shadow payload copies are
still unfinished. Preserve all eight passed/interrupted checkpoints.

The later interval planner/executor now interleaves bounded evacuation batches
and retention. A partial batch reports remaining blocked bytes, then the next
batch is planned from freshly measured mappings/maps only after confirmed
evacuation and retention progress. Workspace can be reused. Global evacuation
move and retention/evidence limits remain; no native error is retried and no
metadata reservation is bypassed. Reports retain each batch. This implementation
has build evidence only and still copies the full shadow payload initially.

Later source bounds aggregate evacuation audit heap to 4 MiB, including proof
and vector capacities across batches, with pre/post-move checks. A budget failure
after a measured move aborts without retry/source execution. Mutation verification
also requires root birth/attribute bytes to match the original expectation,
even when a pinned workload supplies new root runtime times. These are later
build-only changes; none inherits the saved native results or authorizes a VM
run without the required capacity. Mike subsequently explicitly approved the
232 GiB cap; the 64 GiB host-free reserve and all old checkpoints remain.

The 8 GiB ordinary-append retention fixture is source-only preparation code in
`Prepare-StreamingRetention8G.ps1`. It requires saved OFF rollback branch 40fb292c,
all eight checkpoints and 6 GiB admission capacity before any action. It restores
only the owned clean baseline, verifies original payloads, appends zeros with no
source moves/aging, and saves new manifest/baseline under retention8g. The
dispatcher/readback support that exact separate scope with `-Retention8G`.
At that preparation milestone nothing had executed. Mike subsequently approved
raising the cap from 224 to 232 GiB specifically for this 6 GiB allowance. The
64 GiB reserve remains unchanged. Record actual setup/dispatch state below;
approval is not proof of native execution or success.

Continue the existing implementation. Prioritize concrete code and the next
bounded experiment over repeating general research or restarting the writer.
Run checks appropriate to the change; repeat expensive native scans only when
new changes, failures or unresolved evidence justify them. Never weaken source
admission, allocation evidence or recovery barriers to obtain a passing run.

On this Windows host, also read `C:\Users\mfara\.codex\RTK.md` when present.

## Verified baseline as of 2026-10-26

- The frozen native-shadow alpha has separate bounded native evidence in
  [its result report](docs/native-shadow-alpha-results.md): normal public conversion
  of 15 admitted objects, 128 MiB retained, strict native verification, mutation
  and reboot passed. Its independent preactivation cancellation branch also
  passed complete frozen-image verification, seven user-file checks and reboot.
  Resume after the first-flushed-write process interruption also passed public
  resume/finalize, strict verification, mutation and reboot, and is saved OFF as
  checkpoint `072a065e-7f91-457f-ad27-709271b07014`. Preserve all three branches.
  The separate shadowless rollback also passed exact preimage/marker proof,
  restored NTFS availability, seven payload checks and reboot; its OFF checkpoint
  is `fc55b0d7-5899-4c1f-9404-4bf4a14b054c`. Three later read-only captures
  verified the normal/resume handoff and rollback markers plus immutable journal
  bodies. All nine alpha checkpoints remain; the alpha VM is OFF with its original
  8 GiB configuration restored. Only the final read-only marker observer used
  temporary 4 GiB due host memory pressure; this does not qualify conversion at
  that resource profile. No broader power-loss/placement/profile claim follows.
  Use the exact frozen executable pins and fresh alpha dispatchers; no engine
  or independent-writer feature work belongs on this critical path.
- Public `ntfs2refs convert --request` completed a fourteen-object tree on the
  original 52 GiB partition, retaining 134,217,728 payload bytes at their original
  physical extent, relocating 8,933,376 and materializing 88. There were 134
  patches, 231,337,984 raw target bytes written and a 462,706,832-byte journal.
  The executable SHA-256 is `0a90d93c715e7ac9f2ad3b0560b5a1dadb5b4da9c879d3a5711bef81e0ad160c`,
  built from `f025c8b2a0e48605edac07f67af32968c8b9b33f`; later commits do not
  inherit this qualification. A separate strict native check matched all
  fourteen objects and the retained file's original LCN 2173673.
- This retention fixture used synthetic allocation history: an 8 GiB zero-written
  temporary file and normal NTFS creation of the 128 MiB file, with no source
  extent moves. It does not prove arbitrary or low-LCN placement. Shadow payload
  initialization was still 143,151,192 bytes; actual allocated scratch and full
  process I/O were not measured. The fourteen-object result passed a bounded
  native create/grow/truncate/rename/delete and 128-entry workload, strict
  verification afterward, and strict verification after clean reboot. The exact
  mutation report constrains the changed root basic-info record. The 128 MiB
  file's original LCN/hash and source label survived with the shadow absent.
  This does not establish arbitrary storage power-loss or broad workload safety.
- That fresh full conversion passed protected exact-frozen target semantics
  and automatic original-label restoration through capture/frozen reconciliation/
  finalization. The earlier separate `complete-label` repetition/reboot result
  used a backfilled legacy request and remains distinct historical evidence.
- The earlier twelve-object public conversion retained zero bytes, wrote
  346,841,088 target bytes with a 693,708,354-byte journal, and passed strict
  native verification after reboot. That older reboot and the prepared one-file
  64 KiB retention result do not qualify the fourteen-object run's later behavior.
- Public preactivation cancellation passed on the 52 GiB fixture. Public
  `rollback --without-shadow` also passed after a controlled first-flushed-write
  process exit with the exact shadow detached. It proved the complete original
  NTFS preimage before writable mounting, completed the version-4 rollback
  marker, and restored the original mount/label and four user-file hashes.
  Those four hashes and original NTFS availability/identity also matched after
  a clean reboot; full twelve-object security/timestamp semantics were not
  rechecked after boot, and post-mount whole-image equality is not claimed.
  This is one process-fault case; broader write/flush, power-loss and interrupted
  marker-completion qualification remain open. The producer passed integrated
  protected-target/source admission, but intentionally stopped before complete
  ReFS conversion and automatic label restoration.
- The separate REFSNT experiment adopted one existing 4 KiB physical cluster
  with eight metadata writes totaling 131,072 bytes and three real image
  flushes. The payload stayed unchanged and independent Rust checks passed.
  Microsoft rejected the imported writer candidate with a Medium Allocator
  structural error. A separate fresh unmodified reference import passed native
  read verification of its two original files, with zero overlay pages and the
  adopted name absent. That baseline has no mutation/reboot qualification and
  does not qualify the rejected writer; its specific defect remains unisolated.

Use the detailed reports rather than inferring broader support:

- [Native conversion results](docs/general-native-conversion-results.md)
- [Source labels and native completion](docs/source-volume-label.md)
- [Owning-machine CLI](docs/cli-workflow.md)
- [Device binding discovery](docs/device-binding-discovery.md)
- [Strict writer research](research/refsnt-adopt/README.md)

The post-freeze candidate adds an explicitly selected experimental journal
profile 2, with a 16 GiB ceiling and request/ticket/header/manifest version
binding throughout conversion and recovery. Profile 1 remains the default and
the frozen alpha keeps its original binary and receipts. A bounded-memory
synthetic journal larger than the old 768 MiB ceiling passed prepare, resume,
shadowless rollback and marker verification. The beta later passed a native
profile-2 conversion with a 675,831,546-byte journal, below the old size ceiling.
Native larger-capacity, interruption and power-loss qualification remain open; see
[the CLI workflow](docs/cli-workflow.md). The default source limits and the
128 GiB live partition limit remain unchanged.
The later explicit larger-tree profile now propagates a separate 2 PiB routing
budget through pair validation, source requests, shadow work and recovery. It
is derived from streaming target bitmap capacity, not native qualification.
Unprofiled/default routes retain 128 GiB. Resource-profile journal/ticket binding,
exact space/format/ownership checks, file/data budgets and scratch costs remain;
unsupported or over-budget layouts must still refuse rather than force execution.

The current experimental larger-tree candidate separately opts into up to
1,024 files, 256 directories and 4 GiB logical contents, bound to the v2 journal,
native source observation and protected target observation. One 240 GiB/64 KiB
case passed conversion, mutation and reboot; interruption remains unqualified.
It does not widen the default alpha.
Its later source geometry path accepts 4 KiB through 2 MiB power-of-two clusters
with 512-byte sectors, 1 KiB MFT records and 4 KiB indexes. Target clusters remain
4 KiB; byte-based retention planning and geometry-sized MFT-mirror checks are
required. The 64 KiB source case now has bounded native evidence; other expanded
source geometries remain unqualified. This does not remove the default 128 GiB partition ceiling or the other resource
ceilings; the explicit expanded routing budget is described above.
Its protected native source collector now emits schema 9 with compact streaming
bitmap summaries. Both native bitmap data hashes/counts must match the frozen
raw bitmap, and before/after transcript/first-page observations must agree.
Only the real opaque live observation can satisfy the expanded admission gate;
JSON summaries cannot issue it. Schema 8 replay remains available, and default
alpha collection stays schema 7. Expanded shadow retention planning/rechecks and
protected target verification now stream both target bitmap views. Their compact
proof encoding records a first-page receipt plus full transcript digest/counts;
it must not be described as complete raw-page replay. Default target collection
retains assembled maps. Standalone lock/dismount capture has an explicit
schema-2 streaming profile, with mandatory post-lock views, diagnostic-only
post-dismount failures, preserved native errors and the same opaque frozen-handle
token. Default schema-1 witnesses retain their assembled path and bounds.
Default routing remains limited to 128 GiB. Expanded routing uses 2 PiB with
streamed metadata; metadata-complexity and admission limits still apply, and
only the recorded 240 GiB conversion/mutation/reboot case has native evidence;
larger-volume and expanded recovery qualification remain open.
The expanded retained-extent check now has a bounded multilevel Medium allocator
walker (1,048,576 pages, 33,554,432 leaf rows, depth eight) that decodes leaves as they
arrive and rejects repeated physical pages, bad child bindings and incomplete
coverage. It has compilation evidence only. Default Medium traversal remains
one-level. Expanded Medium results retain counts/digests and allocated ranges,
not all decoded rows; only the first 32 child addresses are diagnostic samples.
Full page/row counts live in `streamed`, which default results omit. Allocated
interval storage remains bounded; larger-volume routing remains unfinished.
The expanded Small allocator now also walks bounded multilevel trees, with
physical child addressing, CRC/header/self-location/level checks and ordered
disjoint managed ranges. Its default root-only entry is preserved. This path
has compilation evidence only; larger-volume routing remains unfinished.
Container consumers now borrow sorted mapping rows for binary lookup, with no
duplicate B-tree map. The experimental Small path reads only physical bootstrap
structures before its own walk; Medium still independently requires container
validation. Default diagnostic row values and container budgets remain unchanged. No new
native qualification follows from these memory/I/O changes.
Container values now retain their 160 bytes inline and expose hex only through
diagnostic serialization. Comparisons/hashes consume actual bytes; malformed
imported strings remain diagnostic-only and cannot supply mapping data. The JSON
field name remains `value_bytes_hex`; default container budgets are unchanged.
The larger-tree path now selects a separate compact Container Table walk:
ID/physical-start indexes remain live only, while diagnostics retain mapping
and page-transcript digests plus the root observation. Lookup data and its
private root/volume binding are not serialized; imported JSON cannot recreate
them. Both container copies must agree, with every followed page authenticated.
See [compact traversal](docs/refs-compact-containers.md). This has compilation
evidence only. Default routing and other conversion/resource limits remain;
the explicit expanded routing budget is not native qualification and inherits
no driver acceptance or recovery result from the frozen alpha.
Separate opt-in source-stream and bitmap assembly primitives support larger
logical ranges. See
[streaming budgets](docs/ntfs-streaming-budget.md) and
[bitmap pagination](docs/native-bitmap-pagination.md). These primitives do not
authorize conversion and are not part of the frozen alpha's native evidence.

The bounded profile is NTFS 3.1, 512-byte logical sectors, 4 KiB clusters and
1 KiB MFT records, targeting ReFS 3.14 with 4 KiB clusters. Current admission
qualification targets Windows build 26300. Bounds include 128 ordinary files,
32 directories and 256 MiB logical contents, subject to exact space checks.
Parser support for a feature is not evidence that conversion preserves it.

## Code map and recovery contracts

- `src/general_conversion.rs`: live qualification, journal/ticket preparation,
  activation, apply and finalization in one process.
- `src/general_qualification.rs` and `src/general_source_admission.rs`: frozen
  source evidence and opaque admission authority; JSON success flags cannot
  substitute for actual device observations.
- `src/general_reconstruct.rs` and `src/lab_reconstruct.rs`: native adapter and
  durable old/new journal protocol, exact-image checks and handoff.
- `src/preparation_progress.rs`: bounded diagnostic scan progress, outside the
  journal format and all admission/recovery authority.
- `src/general_recovery.rs`: public raw resume, rollback and finalization.
- `src/general_label_completion.rs`: native-only post-handoff label completion.
- `src/source_volume_label.rs` and `crates/n2r-win32/src/volume_label*`:
  reconcile the exact frozen NTFS UTF-16 label and restore it through Windows.
- `crates/n2r-win32/src/shadow_native.rs`: native shadow construction, measured
  retention attempts and strict tree verification.
- `crates/n2r-win32/src/bitmap_paging.rs`: bounded complete bitmap assembly,
  shared by live source, shadow and frozen allocation collection. Native report
  schema 6 replays original page responses; legacy reports reject continuations.
  Complete-map/page hashes have distinct contracts. See
  [native bitmap pagination](docs/native-bitmap-pagination.md). This source work
  has no native paging qualification and does not widen conversion authority.
- `crates/n2r-win32/src/retrieval_paging.rs`: bounded complete stream mappings
  and raw-page provenance. Report schema 7 replays retrieval continuations;
  legacy schemas retain their single-response rules. Shadow placement verifies
  the explicitly assembled map. See [retrieval pagination](docs/native-retrieval-pagination.md).
  This does not add NTFS attribute-list support or native conversion qualification.

The later bounded attribute-list implementation is in `src/ntfs_attribute_list.rs`
and `src/ntfs_assembled_io.rs`; see [the profile](docs/ntfs-attribute-list-assembly.md).
Ordinary files can assemble unnamed unencoded DATA through a complete list and
uniquely owned extension records. Canonical files contain each stream once;
`attribute_assemblies` preserves original records and list bytes. Require
`validate_record_coverage` rather than equating logical-file and physical-record
counts. Checked stream reads rebuild and compare the actual list/segments and
MFT allocation bits. Ledger version 1 retains resident lists; version 2 covers
fully initialized nonresident lists whose entire mapping is in the base record.
Their physical storage is separately claimed during allocation reconciliation.
The later `src/ntfs_mft_bootstrap.rs` loader supports bounded MFT DATA self-mapping
with complete base-record LIST/BITMAP storage. Assembly versions 3/4 retain the
actual MFT bitmap bytes and conserve its full allocated-record domain. It loads
only reachable initialized record ranges, including learned noncontiguous islands;
no-progress/unreachable graphs refuse. Stream, resident-metadata, backup, log and
internal-index rereads rebuild the actual bootstrap. See
[MFT bootstrap](docs/ntfs-mft-bootstrap.md). This has synthetic source coverage only.
Other system/directory lists, auxiliary lists/bitmaps needing further assembly,
named or encoded segments and unsupported forms remain refused. Existing file/data/run
bounds remain. This is source/test coverage, with no new native qualification.

Preserve these distinctions:

1. Raw recovery requires the pinned request/ticket, actual journal identity,
   expected device state and its recorded shadow dependency.
2. `N2RHND01` closes raw replay and rollback before the writable ReFS mount.
   Never clear or repair a partial/foreign marker to reopen recovery.
3. Exact-image marker completion refuses a target changed by native ReFS use.
   A journal-only handoff receipt proves only the immutable journal and marker;
   it makes no assertion about the current raw image and grants no replay
   authority.
4. `complete-label` requires the original mounted ReFS partition, a pinned
   desired label and strict native tree verification before and after normal
   metadata restoration. It does not open the shadow, replay raw patches or
   change disk attributes.
5. Keep the shadow enrollment label `n2r-retained-shadow` enforced during
   construction. Converted-source verification uses the explicit restored
   label. Preserve legacy request serialization when optional fields are absent.

Retain both legacy and metadata-inclusive allocation evidence. Do not treat a
legacy-free region as safe when the metadata-inclusive view marks it occupied.
Do not invent dummy retained ranges for relocation-only conversion.

## Laboratory operation

Use `lab/Lab.psm1`, the manifest and existing dispatch/collect scripts. Verify
the actual owned VM, checkpoint branch, device GUIDs, geometry and task state
before mutations. Hyper-V Administrator access has been granted on this host;
probe management access before requesting elevation again.

The Windows 11 VM is `ntfs2refs-win11`, ID
`eebbfd4e-d964-4aaf-a6e6-5603fb9b6c4c`. The successful twelve-object branch is
saved as checkpoint `94091799-c19b-4e6a-ada0-fd87cbdb6ad0`. Verify current state
before using it; the guest has subsequently run label completion and rebooted.
Never restore, reboot or redispatch over a still-running or unknown operation.
An interrupted host observation does not prove that the guest worker stopped.

The latest fourteen-object retained/mutated/reboot-verified branch is saved as
checkpoint `f6393f52-56ce-4847-bc24-7d5e019ac2e2`; its actual parent identity was
confirmed and the VM was running after preservation. Use the successful
`preserved-checkpoint.json` report, not the earlier empty-ID checkpoint attempt.
Follow the canonical [preservation record](lab/PRESERVATION.md). Specific user
approval is required for irreversible checkpoint/backing cleanup or reset of
the verified VM; blanket project authorization does not grant it. No further
disk experiment is authorized on this preserved branch. Read-only inventory
and source/test work may continue. No export or copy is currently needed.

Mike specifically approved removal of the independently reconstructible fixed
reference VHD and creation of a separate offline fixture on 2026-10-26. Only
`.lab/hyperv/corpus/devdrive-20261023T231918797Z/target-fixed.vhd` was removed,
after fresh hash, identity, attachment and complete registered-ancestry checks.
The packet, overlays, evidence, archive and all fifty original checkpoints remain.
The separate VM `ntfs2refs-reference-isolated`, ID
`8f7fc646-8c9f-41d0-b65a-ecfadccfc36a`, has fixed 8 GiB RAM,
four vCPUs, no NIC and automatic checkpoints disabled. Its ownership record is
`.lab/hyperv/isolated-reference-20261026-review/manifest.json`. Its three standalone
VHDX files are independent copies whose hashes match the archive; container UUIDs
were preserved by copying, while host file identities are new. Do not use a VHD
UUID alone to infer backing-file aliasing. vTPM/Secure Boot settings were retained.
The provisioning manifest is a historical preboot record. The ejection cleared
the DVD's ISO path; the DVD device and boot order remain. An initial start was
denied access to the inherited ISO. The failed post-ejection SDDL string comparison
does not establish an access-rule change: the prior SDDL was held only in memory,
not persisted, so a rule delta cannot be distinguished from representation/order
changes. Do not claim that the pre-ejection ACL or a rule-level delta is known.
The retry dispatched at 2026-10-26 14:46:25.6485767 UTC booted normally and
authenticated through PowerShell Direct by this VM GUID using the existing
credential. Its authorization provenance needs the chronology in
[the preservation record](lab/PRESERVATION.md): the local `Approved.` entry has
no exposed sender/account/origin metadata, and its scope cannot be established
from the supported view. Mike's explicit main-room approval at 15:01:36 UTC came
later and must not be attributed retroactively to the 14:46 dispatch. Treat
approval wording in original receipts as actor claims, not independent proof.
The VM is now running without a NIC. The recorded post-ejection/current ISO SDDL
hash matched across the retry; this is separate from the missing earlier ACL
baseline. No explicit ACL repair was performed. Windows 11 Pro 26300.9457
and the expected `refs.sys` hash matched. The observed disk-role mapping and
resource margins are in
`.lab/hyperv/isolated-reference-20261026-review/readiness-20261026T144625632Z/binding-summary.json`.
OS disk 0 is GPT/NTFS; target disk 1 and journal disk 2 are RAW and uninitialized.
No J: volume, target NTFS source, or native-experiment enrollment is established.
No writer or conversion experiment has run on this fixture. The original readiness
JSON contains remoted service enum wrappers; read it with `ConvertFrom-Json
-AsHashtable`, or use the normalized binding summary. Later read-only observation
work and its actual terminal result are described below.
Do not dispatch helpers bound to the old `win11` manifest against this new VM.
The recorded later explicit approval covers normal boot/read-only guest readiness,
not formatting, reference import, a writer experiment, conversion or further cleanup.

Source-only baseline prerequisites are in `lab/IsolatedBaselineGuards.psm1` and
`lab/guest/IsolatedJournalZero.cs`; see
[the source boundary](docs/isolated-baseline-prerequisites.md). They validate
structural observations and a complete same-stream zero receipt, and return
review plans only. They neither attest a live native source nor grant write
authority. No journal initialization/import runner has run. A separately admitted
observation read all 8 GiB from the enrolled journal, but its host controller
refused a changed backing last-write timestamp and exited 1; see below.
Do not substitute these JSON plans for live ownership/handle acquisition. Their
fresh C: staging proposal preserves the old importer's C:-only guard and still
needs execution review. No old helper route constants were changed.

The guest-side `IsolatedJournalReader.Windows.cs` now compiles with the pure
`IsolatedJournalDeviceProfile.cs` validators. It acquires only a read handle and
reuses the same-stream scanner after actual guest/device identity checks. Its
initialization-proof APIs still refuse before native access. The separate
observation-only entry ran once after the reviewed layout/identifier corrections:
`.lab/hyperv/isolated-reference-20261026-review/journal-observation-review-20261027T031140034Z`.
The guest read 8,589,934,592 bytes, observed zeros, and recorded SHA-256
`ebfb4ef19ae410f190327b5ebd312711263bc7579970e87d9c1e2d84e06b3c25`.
Its native identity snapshots matched, but the host journal VHDX last-write time
changed despite unchanged recorded file identity and 4 MiB length. The host
exited 1 and retained a failure receipt; no host success receipt, immutable
snapshot, zero proof or initialization/import authority was produced. The cause
of the timestamp change is unproven. Preserve all receipts and do not retry the
observation, weaken that refusal or initialize/format/import storage from this
result. Host backing ownership and exclusion across storage aliases remain
separate gates; no-sharing access alone is not that proof. The detailed chronology
and pins are in [the prerequisite report](docs/isolated-baseline-prerequisites.md).

Dispatch long work once, retain its task handle and collect terminal evidence.
`Collect-LabAdmittedConversion.ps1` reports live phase and I/O counters; those
counters are not a completion percentage. The current full-image workflow can
read many multiples of the partition size. During journal preparation its
optional `journalProgress` shows the comparison/recheck subphase, combined scan
bytes and elapsed time even before the first journal write. Missing or partial
telemetry is ignored; see [the progress contract](docs/journal-preparation-progress.md).
Guest-local shadow attachment may
disappear across reboot; raw recovery must restore its exact enrolled backing
through the existing helper when required.

Compare PowerShell timestamps using their preserved UTC kinds/ticks.
`ConvertFrom-Json` can return a `DateTime`; stringifying it before parsing can
lose timezone information. Do not reject a successful reboot because a local
and UTC timestamp were compared incorrectly.

## Storage, provenance and repository hygiene

Mike explicitly approved raising the lab cap from 208 to 216 GiB on October 27
to preserve the refused streaming branch and allow its next native run.
Mike subsequently approved 224 GiB to preserve the converted streaming branch
and allow its reboot/mutation child. The 64 GiB host reserve remains.
`lab/lab.config.json` limits actual lab usage to 232 GiB and requires 64 GiB
host free space. Check actual free space and backing allocation before large
experiments. Sparse flags, logical lengths and reported sparse ranges alone
have not provided reliable capacity accounting on this ReFS host.

As of this baseline, automatic approval review still blocks deletion of the
disposable image at
`.lab/research/strict-adoption-image-81714d11aed444deab9fed82436e551c/refs.adopt-test.raw`,
including after explicit user authorization. It remains present. Its verified
131,280-byte `final-metadata.cow`, trace, results and evidence pins are retained.
Report the block accurately; do not assume cleanup succeeded or retry the same
deletion through another mechanism.

Keep `.lab`, images, VM/checkpoint chains, journals, ISOs, binaries and secrets
out of Git. Preserve source archives and recovery material needed by active
runs. Verify exact resolved paths before cleanup; use native PowerShell
`-LiteralPath` operations and avoid recursive deletion of computed targets.

REFSNT stays pinned under ignored `.lab/research/refsnt`. Its GPL engine is
external research, not a Rust product dependency. Commit original adapters,
provenance and measured results; do not copy upstream engine code into product
sources or claim native compatibility from its checker alone.

## Build and next work

The toolchain is pinned to Rust 1.98.1. If Cargo is not on PATH, use
`C:\Users\mfara\.cargo\bin\cargo.exe`. Run `cargo fmt --all --check`, focused
tests and appropriate release builds. Use the workspace suite for changes
spanning shared contracts. Inspect `$LASTEXITCODE` in PowerShell. Documentation
and guidance changes do not need another native conversion run.

Windows CI passed at `381a8c1` (run `40264890298`): format, Clippy, workspace
tests and release builds. Do not transfer that result to later changes.
`evidence/qualification-registry.json` records bounded implementation/native
claims and their exact evidence pins; it never grants execution authority.

The frozen alpha's four native paths and marker captures have completed; finish
their evidence registry and reviewable frozen-alpha handoff before changing the
engine. Preserve every case/observation checkpoint. Source/placement expansion, scratch/I/O
optimization and independent-writer investigation follow that qualification. The
fourteen-object aged-layout conversion, automatic label path, mutation and
reboot now have bounded native evidence; do not repeat them without a concrete
new change or unresolved gate. Preserve completed fixture paths and add
versioned profiles rather than deleting their enrollment checks. Follow
[the preservation constraint](lab/PRESERVATION.md) before any lab operation.
Report payload retained, relocated and materialized, actual scratch allocation,
changed bytes and journal capacity separately. Boot and broad production
qualification remain separate objectives.

The approved retention8g preparation executed once and saved OFF source baseline
02036ef7-4010-4d0a-82d5-d632de1a2b39; all eight older checkpoints remain.
The zero file is 8589934593 bytes, SHA-256
b47800cd5a0c0bd2a7d6c2ac9402cc117bbe89363299bdc51f8a72aef8543693.
Candidate 5 is active: run dbd514da89ac4c44b16bde4f7e3a805c, PID 4564 created
22:29:23 UTC, source fdf734b plus the unchanged capabilities-only dirty patch.
Converter hash 78ed37fa9120ea10de481ebb4d14d580a48e2cac86051084f3ccc90592a54f3f.
Observe the existing task; do not redispatch. No evacuation/retention outcome
is established yet. The cap is now 232 GiB with the 64 GiB reserve unchanged.
Candidate 5 subsequently completed native shadow construction: thirteen source
objects, 8590217246 shadow payload bytes initialized; eight shadow-only moves
totaled 2721431552 bytes, all measured mappings verified, then two retention
moves confirmed the same byte count at original source locations. Its copied
construction report hash is a258b91f69e07aaf4b5064ecdf553332757e7b665a46ab3c783a79f7498b864f.
It is still live in target preservation; do not infer completed conversion or
low-scratch qualification from those intermediate observations. Continue
monitoring the existing candidate5 task and the 232 GiB/64 GiB storage limits.

Candidate 5 is now terminal at journal preparation, exit 1: the selected one-GiB
journal implied a 528,482,304-byte changed-sector budget, which was exceeded.
There is no apply, ticket or handoff. Both data disks remain offline/read-only.
The 29-file terminal archive verified, manifest SHA-256
9111ccf1119a22f2dd4b667fa86fd800d78e94fc0fa15537ea2517714d5161d9.
Frozen target preservation passed: 2,721,431,552 bytes retained, 5,868,785,664
relocated and 30 materialized; retained allocator coverage passed with no
unallocated retained clusters. Whole-volume ownership remains unproven.
Do not describe this as a completed conversion or replay the failed task.
The read-only sizing task N2R-StreamingV2Size-dbd514da89ac4c44b16bde4f7e3a805c
is running on those same frozen images, with separate journal-sizing intent,
dispatch and progress. Its executable is
3a51207877c604c93887cafcbda95040882cf57143bca020f6d8041cf11096e4.
It creates no journal and grants no write authority. Observe it to obtain the
actual changed bytes and conservative journal requirement before choosing the
next budget. Preserve the failed branch before any restore or new conversion.
The dispatcher now accepts JournalBudgetMiB and increases its required lab
growth allowance along with that budget; never bypass the approved cap.

Mike subsequently approved 240 GiB (257698037760 bytes); the 64 GiB free-space
reserve and 4 GiB VM memory are unchanged. He then explicitly prioritized
minimal disk utilization and RAM for physical-drive conversion. Treat the
native-shadow full-payload copy and whole-partition free-sector replacement as
architectural costs to remove, rather than increasing lab caps as the product
solution. Finish the active read-only sizing measurement and preserve this
failed branch. Do not launch another larger conversion merely because its cap
now permits it. Next establish a complete target-required write set and the
means to construct metadata around retained payload without initializing a
second full payload copy. Keep the successful native-shadow path as a reference
and preserve its protocol/evidence. New selective-write or metadata-adoption
profiles must not silently weaken its full-image journal/recovery contract.
Use bounded streaming buffers/paged or interval allocation processing, never
RAM proportional to total volume capacity. Current measured converter peak is
70,984 KiB in a 4 GiB VM; do not enlarge RAM without measured need.

The frozen evidence's existing Rust write-set planner produced a non-executable
candidate: 14,764,269,568 target-owned bytes and 41,070,305,280 preserved bytes,
six owned ranges, 115 observed anchor ranges. Its ignored candidate JSON hash
is 6c8b27f591d2d317a9b8cb1fa2debb1ab2f0ccf1f9564a687a3a687f047dabfa.
The required graph/allocator, bootstrap-completeness and native hybrid-image
gates remain; this does not authorize dropping free-space patches.
Rust native valid-data probe 667bbfc is built but NOT executed. The later
Prepare-StreamingV2ValidityProbe.ps1 requires the exact sizing task terminal at
exit 0, archives its result, preserves candidate5 OFF as a new checkpoint while
retaining all nine old ones, then boots a fresh child with a six-GiB allowance.
Only shadow disk3 becomes writable. The probe creates one new SYSTEM-only
1,052,672-byte file, attempts a one-MiB SetFileValidData, records raw mapping and
cached/storage validity around it and flushes. It never reads payload, deletes
the private file, writes the source, or grants conversion/adoption authority.
Before invoking that helper, inspect the same live sizing task; never terminate
or redispatch it to pick up a later binary. The public/recovery/sizing release
builds also passed after be43a24's CNG v2 recheck change; that change has no
native workflow result yet. No unit tests have been added or run.

The sizing job completed at exit 0: 609,693,696 changed bytes, 479 ranges,
1,236,164,608-byte conservative journal requirement. Its pinned result is
candidate5/valid-data-probe/sizing-result.json. The private valid-data call then
succeeded (experiment a060e73a480440a3af174f4c98af60c8), with no tool payload
read/write. The leading negative retrieval marker became physical and the first
1 MiB became storage-valid; the extra 4 KiB tail remained unwritten. Result
d3ac78c0abb021dc57c5ccac5d09c7a1f69e004439078f1b52b9f27ee707651e.
Read-only reopen attempts v1/v2 refused a mistakenly reused writable-only
volume helper, not data validity. V2's durable failure is e774db52...ddee63.
The corrected v3 observer passed after a clean reboot: same file ID, EOF,
stable standard info and the same valid-prefix/unwritten-tail state. Result
dbbe0e26a4be5ea2b676cca71d7c8975a6322d5650f0be4643076361d35dd3e3.
No payload reads/writes, valid-data calls or privilege changes occurred in that
observer. This is a one-MiB allocation/validity primitive, not adoption,
physical-I/O measurement, zero-copy conversion or production qualification.

The failed conversion is preserved OFF at b3aee3e3-a5e1-4cf2-b69d-c1903a885bff;
the private allocation at d1fce698-7f44-46d3-bf5b-a121e5f43fd8; reboot observation
at 24cfdd12-9b9c-4bd0-8322-a94da6d98708. All twelve checkpoints remain. Only this
owned VM returned to b3aee3e3 for the corrected conversion. Its source is live
NTFS; its existing shadow is mounted read-only for discovery and is excluded
again before the new converter starts. No new shadow payload copy is planned.
Frozen v2 reuse requires fresh source admission and protected native target,
checksum and allocator proofs; it caps compared patch ranges at 1024. Legacy
construction is unchanged. Candidates 6/7/8 refused discovery before any
converter task was registered: single-string argument splatting, writable-only
discovery attributes, then a second native filesystem read-only flag check.
Their separate stages/logs remain; never redispatch them. The explicit
ShadowReadOnly discovery role fixes the routing while other roles stay strict.

Mike's as-needed storage permission for this same retention case was relayed
through task 01a17583-cb33-74ae-912d-1b7e1c991016, quoting "AS MUCH STORAGE AS
NEEDED IS AUTHORIZED" and "don't exceed all available storage". The cap is now
256 GiB, reserve still 64 GiB, VM still fixed 4 GiB. Frozen retry admission
requires 20 GiB conservative growth allowance, measured 2-MiB VHDX blocks and
the bounded 1536-MiB journal. This covers source COW intervals, the full eight-
GiB journal device, OS and metadata margin; monitor actual capacity as well.
No deletion, additional competing run, CI or credential change is authorized
by that relay. Continue as sole lab owner and preserve all evidence.

Corrected candidate9 is now LIVE, run 9cfeda0cdcd9449f8e3342d31c23eed7,
task N2R-StreamingV2Convert-9cfeda0cdcd9449f8e3342d31c23eed7, PID 3676 created
2026-10-28 01:00:45.671357 UTC. Observe the same task; never redispatch on timeout.
It uses frozen-shadow reuse, a 1,610,612,736-byte journal and 20-GiB lab growth
allowance. Source producer 521267b7468b16a0a55374b81b668f80c2d70b85 plus the
unchanged d99591b5 capabilities-only dirty patch. Request pin
17a8c5f5d085b0eb96ac20894ea33bf0eb8e99c1316fed1bb7322ce537b6b0a3.
Converter f8b62ea2015ddf6e2139278d5d898dd4e6cd8191aca276000a827a831ceb95be;
binder eb9d38ac901fd553a0fa5073f105be156b84ab6f51b8c31260f02dce40c0efa8;
recovery 2fccee65237af1dbe122eda0006db91bed3753312d653c182211c36a25450b70.
At 01:02:38 UTC it was active in source qualification, 23.16 GB read, both
data disks offline/read-only. Lab counter 246,530,114,051 bytes; host free
98,938,961,920 bytes. No cutover/native conversion outcome is established yet.
The dispatch's diagnostic frozen_shadow_reuse field serialized as the string
"[bool]True" due to PowerShell argument parsing. The actual pinned Rust request
contains boolean verify_existing_shadow=true; its controls are unchanged.
1eee63f fixes the diagnostic/caller boolean casting for future dispatches;
never rewrite the recorded running request or stage to pick it up.
Use Collect-StreamingV2Conversion.ps1 -Candidate candidate9 and preserve all
twelve checkpoints, including the private probe observation branch. The source
is the original ordinary-appended 8-GiB tree; no source extents were prearranged.

Candidate9 is now TERMINAL, exit 1 at target-preservation-freeze before any
journal/activation. Fresh source admission found 14 objects: NTFS remount had
created a 76-byte SVI/IndexerVolumeGuid and changed SVI/WPSettings timestamps.
The existing 13-object shadow lacked that file. Failure was OS error 2; no
source payload writes. The 22-file archive verified with manifest
b91e09b1788618d83b58d1b6bc8a3124f644cae6549c59e4d34070b3961c3d2a.
OFF checkpoint 51626f1f-5778-4106-a61c-cb509d80e5b4 preserves it; all thirteen
checkpoints remain. No old task was restarted or old admission reused.

The explicit lab cache-sync mode now runs inside common conversion AFTER fresh
source freeze/admission. It validates the source's GUID bytes, bounded target
namespace, file IDs, links and streams; creates/updates only that 76-byte cache
and synchronizes source metadata. It never rewrites large user payloads. Changed
identity, unknown names or unsupported metadata refuse. The normal complete
source/target, checksum, allocator and journal gates follow; public verify-only
mode retains its behavior. Source FILE parsing now rejects word-misaligned USAs
or offsets below the common 42-byte fixed header, preserving the older header
form and the 48-byte extended form. Native dirty-state evidence is correctly
described as the separate bound transaction_freeze gate, not raw $Volume flags.
No unit tests were added/run; release builds passed. Malformed-record native
regression qualification remains separate from the successful release build.

Candidate10 is LIVE, run e8455536ad3b4bf189b2a07d67b3af42, PID 872 created
2026-10-28 01:46:59.828318 UTC. Observe the same task; never redispatch it.
Source commit 2331c9db860dcce08dead8ff3eede24fb6260e40 plus unchanged d99591b5
capabilities-only dirty patch. Executed lab-convert-admitted-tree.exe pin
af7a4bc45bc9f3031da38f6435bd77192876e2a0cd537189207458b35071812e;
request 11c3b01b4aab119dda3bf45f9299d15277fa4f333fd4529faf61f4faba19e81f,
explicit --refresh-existing-system-cache, no controlled interruption.
Binder 4e522859e3e33839b9439e5c9995c5543c13cad6350e69deed46794d69e6a02f;
recovery 2286fd32ee70baf9450524560e7dc8d1a126e19f3be268489c88f7828b570aad.
At 01:48:27 UTC it was in source qualification, source OFFLINE|READ_ONLY,
shadow writable for the later bounded cache refresh; no raw cutover yet.
Lab counter 247,227,132,011 bytes; host free 98,240,077,824 bytes; cap256 GiB,
reserve64 GiB, VM fixed4 GiB. Journal1536 MiB; conservative growth20 GiB.
Use Collect-StreamingV2Conversion.ps1 -Candidate candidate10. Preserve every
earlier branch and read-only probe. Native conversion result remains pending.

Candidate10 subsequently passed fresh source admission and completed its native
cache/metadata synchronization. Copied immutable report
candidate10/cache-refresh-observed.json, 67,353 bytes, SHA-256
295ad27cff548849a021664d40ebf66b34dffc4b1ebf1478e9f8855500840643.
Exactly 76 cache payload bytes were written, zero unchanged user payload bytes,
fourteen metadata objects updated, zero source payload writes. The cache already
existed on the writable shadow and its identity/shape were checked before the
bounded replacement. This report grants no conversion qualification.
At 01:55:32 UTC the same PID 872 was live in existing-shadow verification,
143.13 GB read, peak69.25 MiB. Source remained OFFLINE|READ_ONLY; shadow was
writable for the pre-freeze verification. Lab counter247,361,356,901 bytes,
host free98,105,909,248 bytes. Continue the same task; full target verification,
journal/application, cutover and native postchecks are still pending.

Candidate10 then passed complete target preservation and certificate creation
but failed its final qualification state queries: native control audit budget
exceeded. Its saved target audit already contained 119 events; two final device
state observations exhausted the per-vector 128-event bound. No journal,
activation or source payload write occurred. The 29-file terminal archive
verified, manifest 37cd07ccef35c653f5c2998e1b312b1f840774f9dbc42af05fe23c73a2b559de.
Target proof cf500e07c347262c52f9ca13454591a34ac7c6dea968d2087ba4519d760db4a6
confirmed retained2,721,431,552 bytes, relocated5,868,785,664, materialized106,
retained allocator coverage=true. Source4a1809e2...ce40447,
targetd56733acbef825308d4ddea7c44e9c80dd313fcb960668ab699df247d7ecd9c1.
The complete target audit is now saved before clearing its phase-local vector
for final state observations; the native bound and every query remain.
OFF checkpoint ba9654d9-7a50-4b7b-bbd7-50cde85d0e0f preserves this refusal,
all fourteen checkpoints remain. No old task/journal was replayed.

Candidate11 is LIVE: run6e45d7f749da4687b4e862f6498945d4, PID3784 created
2026-10-28 02:11:53.084071 UTC, lab-convert-admitted-tree.exe
b82fda2bd79e86735903e5509f14ad835ccd8400213604c098adcb7b0d61e187,
source db915d8cbf6f5576e01a48781af9db83dcc08d53 plus unchanged d99591b5 patch.
Request f3ea50cadfaba389f3137bb74f9c1ac856c936b227186d345fcd4bd09c30b4d0;
binder a0ce4f666f7c140001f29848412e7752ec98c3589d09747dc780e9d5376c1786;
recovery2b5b92aea6b9aa353fd1873c716513ab6d087bba59f3dac7c48fdd029a8a114f.
The new operation explicitly synchronizes the tiny cache, reuses the large
payload, binds1536-MiB journal and20-GiB growth budget. At02:12:44 UTC the same
PID was live in source qualification, source frozen read-only, shadow writable
for metadata. Lab248,120,269,720 bytes, host free97,349,869,568 bytes, cap256 GiB,
reserve64 GiB, RAM4 GiB. Observe with Collect-StreamingV2Conversion.ps1
-Candidate candidate11; no cutover/native result is established yet.
