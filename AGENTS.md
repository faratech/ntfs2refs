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

## Current handoff snapshot — 2026-10-29

Work in D:\code\ntfs2refs, branch codex/isolated-journal-observation.
The branch tracks the same origin branch. The existing one-line src/main.rs
capabilities change belongs to the user; never edit, format, stage or reset it.

VM2401593c-4b30-472e-9b6d-c9534cbaa599 is OFF/RAM0 with current NTFS
checkpoint5f30f4a1-9db0-4df5-a0e5-2c7be5d87eec. It has fixed4GiB RAM,
4CPU,no NIC. Only two checkpoints remain:
- NTFS after optimized public rollback: 5f30f4a1-9db0-4df5-a0e5-2c7be5d87eec.
- ReFS after optimized public resume: 52d37819-2b9c-4041-9232-bd7eac3c21bb.

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
It remains read-only: split own-record forms, system log storage, fallback
checkpoint generations, complete stream inventory and allocator/refcount
reconciliation are unresolved. Complete graph/selective conversion flags stay
false. Next work must cover those references and bind a required footprint to
live frozen inputs before any production skip/read/write authorization.

Do not add or run unit tests. Focused builds and necessary native integration
only. Keep ignored images, journals, binaries and secrets out of Git. The
coordinating agent owns VM mutation; delegated agents work on source unless
explicitly assigned metadata-only observation.

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
