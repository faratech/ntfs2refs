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

## Current handoff snapshot — 2026-10-30

Work in D:\code\ntfs2refs, branch codex/isolated-journal-observation.
The branch tracks the same origin branch. The existing one-line src/main.rs
capabilities change belongs to the user; never edit, format, stage or reset it.

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

VM2401593c-4b30-472e-9b6d-c9534cbaa599 is Running/4GiB. Its current parent is
mixed NTFS checkpoint6fe2d6b6-a2fb-447e-802b-7b3ff0d9f16e, created for the
source-reference run; the current branch now holds the completed ReFS. Its independently seeded tree has808 files/120 directories,
9,885,781,381 bytes; manifest is under mixed-fixture-20261029-3dccf8e8fa38487db6731284a12bceb9.
The two older52d37819 and5f30f4a1 checkpoints also remain. Do not restore this
branch while original run artifacts are still being preserved. The complete
metadata archive is under copy-reference-20261030/closed-run-2586aba6; its
inventory records retained original bulk paths. The13,713,024,832-byte journal
has now been exported and verified against its immutable-body hash and both
completion/intent markers; the1,180,688,384-byte backing was exported and
verified against its capture hash. See bulk-preservation.json in that archive.
The742,391,808-byte shadow VHDX is still
attached and cannot be exported through an ordinary read; no bypass or detach
has been attempted. Preserve it before any restore. No new test/conversion
worker is active, and the archive review changed no VM/disk state or checkpoint.
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

No native conversion/recovery job remains running. Root preserved both successful
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
PER-MOVE CHECKS (user, 2026-10-29): D-1 (window-scoped bitmap probes) and D-2
(incremental retrieval proofs) are deferred: "Decide after measuring" the
scaled fixture (design stage S10). Keep full per-move checks until then.
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

## Build tools

Work explicitly in D:\code\ntfs2refs. Rust is pinned to 1.98.1.
Use C:\Users\mfara\.cargo\bin\cargo.exe when Cargo is absent from PATH.
For builds set both TEMP and TMP to D:\code\ntfs2refs\target\tmp.
Inspect PowerShell exit codes and use only the focused release targets needed.
Do not run workspace-wide formatting or cargo fmt --all: it can touch the
preserved src/main.rs user hunk. Format only files owned by the current task.
Documentation changes do not require another build or native disk run.
