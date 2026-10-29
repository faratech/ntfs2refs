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

The coordinating agent reports VM
2401593c-4b30-472e-9b6d-c9534cbaa599 running with parent checkpoint
5125d335-09b4-4838-bc64-28b079e3f2b9 (the new public NTFS rollback branch).
The VM has fixed 4 GiB RAM, 4 CPUs and no network adapter.
Only two checkpoints remain after user-authorized cleanup:
- Public bundle NTFS rollback: 5125d335-09b4-4838-bc64-28b079e3f2b9.
- Public bundle ReFS recovery: 25a829b6-bea2-40cb-9114-e8d28e775d81.

A bundle-enabled controlled conversion has completed with actual native and
wrapper exit 86 after one flushed source write. Its run ID is
`9340223f9d124a9f88e563ba669f0787`, task
`N2R-BundleCli-Interrupt-9340223f9d124a9f88e563ba669f0787`, and guest directory
`C:\ntfs2refs\bundle-cli-20261029-9340223f9d124a9f88e563ba669f0787`.
The actual converter PID was 5828, creation time 1793245511151, parent PID 5736;
both workers were absent before preservation. New shadow disk 6 has GPT GUID
c8ac8d6e-5a5e-4818-bba1-d399f5a8b38b.
The converter hash is 56b92ac2ccc67692b16bfffebff5401c58979946ca8f0414abcee1c6725a9ee7;
the sealed tool manifest is in bundle-recovery-cli-tools-20261029 with hash
f83b31828fb37f0e4a8d30238dabd76452a60134969db1d733b9bfb4493fb31c.
The native-generated bundle matched its original printed checksum
3f3636d1ad2d64ac28920f722462d6d94639bd7d26e0ba0cecd9be7c618ee204.
Closed metadata and the actual partial checkpoint are recorded under the case's
`partial/`; the partial publication pin is
46f476a29ca3670484547e0bfeb34aed933cd59dc5b22ffc7a695bb73187686b.
The VM was cleanly stopped/checkpointed/started without restoring another branch;
source 1 stayed offline/attrs1 and the managed shadow was absent after boot.

Public CLI Resume c698a0cfd50d4199ba49bcca7dfd1614 completed with actual native
and wrapper exit0, exact target b920ced8c88c491405cc4c77ca309c7d272ef6f20582445295d94355d9c60115,
HND, 15 native objects/10 complete hashes, original label and mount. Its closed
archive and successful checkpoint25a are saved under recovery-cli-resume-c698...;
see evidence/bundle-cli-resume-20261029.json. This used sealed2cac and only the
original directory/checksum plus yes.

Separate public Rollback0017552259514d9a883b398e97b40f82 passed native/wrapper0,
exact original pre-mount SHA13c7808742ac3d7994ebfac438f9fc609e6d9f75f5017f1d19dd517b1999f480,
ABT and native NTFS64K/label/F. No post-mount logical-file hashes are claimed.
Closed receipt SHA5b591a021912285ee885efb1be28032da727202f08937a5f2ad3a7d0e2cbbfc1;
preserved-checkpoint receipt SHA5857cacfc120cfacd9b6ffbbee7e055f0465aa74ce7c318ff8fc0ffbfd1ddb66.
After saving actual5125, root deleted obsolete0872/693/d121 through Hyper-V.
The cleanup receipt is checkpoint-cleanup-bundle-20261029/receipt.json; old IDs
in historical reports must not be recreated or restored.

NORMAL optimized public --drive F --partition2 is NOW RUNNING:
2c0a76e195f540218d60e98266f4e14d, task
N2R-OptimizedDriveAlpha-2c0a76e195f540218d60e98266f4e14d, guest
C:\ntfs2refs\optimized-drive-alpha-2c0a76e195f540218d60e98266f4e14d.
Actual main892/creation1793251802144, wrapper1260/creation1793251797752
was live05:30:23Z. Candidate mainfb5548cc80a1de57e5a1c3c853a0ccfc43338515d00e15867305fa5f59c6079c
uses the two read optimizations, lifecycle routing and CNG image hashes.
Source commit2ff5f017c03977c5e6ba9d31ba64dc634bfa2fe7; sealed manifest
optimized-drive-alpha-tools-20261029/manifest.json SHA230c08850b41bcab1defa0b81aa35406ea0760e25a4042657602d191e0065d6b.
Host case optimized-drive-alpha-20261029-2c0a76e195f540218d60e98266f4e14d;
dispatch SHA628f14f6755e1263fade86c49fd5c70696593260ce1d7d7b6246a3305ef0794f.
No fault was requested; main provisions its own managed shadow/journal.
Delta monitors metadata only. Do not interrupt or open live source/J/packed/
images/locked artifacts. Check actual liveness; recorded observations grant no
power/replay authority. After genuine terminal0/workers absent, collect the
actual closed wrapper/core results, preserve the normal converted branch,
then qualify mutation/reboot on this exact candidate as needed for the freeze.
The prepared collection command is lab/Collect-OptimizedDriveAlpha.ps1 with
the actual dispatch path/SHA above. It creates closed-conversion/receipt.json.
Use that actual receipt pin with lab/Invoke-OptimizedDriveMutation.ps1 and the
same current parent/checkpoint IDs. It uses unchanged independently pinned
c71d2a... mutator and571e07... verifier from managed-recovered-mutation-tools-20261029.
Do not rebuild the frozen converter while this qualification is in progress.
The coordinating agent owns VM mutations. Delegated agents work on source only
unless explicitly assigned a native action.

The bundle case uses the release built from the bb7677e recovery implementation;
later harness and handoff-only commits do not replace the running binaries.
src/main.rs has an existing one-line user capabilities change. Do not edit,
format, stage or overwrite that hunk without an explicit instruction.

## What the recorded results establish

See [build provenance](docs/experimental-build-provenance.md) and its
[evidence index](evidence/experimental-build-provenance-20261029.json)
for full hashes, exact archived reports and limits.

- Public affirmative drive CLI 866fc5..., source cfc48ff, completed its
  separate conversion and cold-boot user-file readback.
- Controlled converter 48094c..., source cf191083, deliberately exited 86
  after one flushed source patch. Recovery 565fb0..., source 5a9bae2,
  completed actual Resume/Finalize and independent Rollback with native exits 0.
- That managed recovered ReFS branch passed a new current mutation workload,
  strict verification before/after, and strict verification after clean reboot.
  The rollback branch passed seven user hashes and scoped native metadata checks.
- These exact builds do not establish arbitrary-volume or release-ready safety.
  Do not claim the public 866fc5... producer was tested with recovery 565fb0....
  Do not transfer old 5e156f... mutation evidence to a different build.

The new bundle producer from bb7677e passed the actual controlled native exit86
and original checksum publication. Affirmative public Resume/Finalize passed;
the separate public Rollback also passed.
Its sealed main SHA-256 is
2cac76e012b4cf9b9d9ea5a90a3a77933856061afb4395a2c7e4b9ab4dc33ef0;
compact SHA-256 is
b41ef940c3c534c3a41115d2f9c7d900f2554d61259407bc7b5e3723e2ed4eb2.
Decline/default-No and wrong-checksum smoke checks passed without device actions.
Do not inherit older builds' results. Later code286d914/5ac7a36 adds stderr
phases and shared-read hash optimizations in handoff/preparation; code7da08e0
routes offline public recovery by actual verified journal lifecycle. These
changes plus code2ff5f01 CNG whole-image hashing are release-built and now running
as candidatefb5548. They do not inherit sealed2cac's native results. See the
separate build records and actual new dispatch above.

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
