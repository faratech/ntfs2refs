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
2401593c-4b30-472e-9b6d-c9534cbaa599 OFF with parent checkpoint
632b630a-c77b-43b2-9b9a-eafbbd87106d (optimized conversion/mutation/reboot passed).
The VM has fixed 4 GiB RAM, 4 CPUs and no network adapter.
Only two checkpoints remain after user-authorized cleanup:
- Public bundle NTFS rollback: 5125d335-09b4-4838-bc64-28b079e3f2b9.
- Optimized ReFS after mutation/reboot: 632b630a-c77b-43b2-9b9a-eafbbd87106d.

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

NORMAL optimized public --drive F --partition2 PASSED native/wrapper0:
2c0a76e195f540218d60e98266f4e14d, task
N2R-OptimizedDriveAlpha-2c0a76e195f540218d60e98266f4e14d, guest
C:\ntfs2refs\optimized-drive-alpha-2c0a76e195f540218d60e98266f4e14d.
Actual main892/creation1793251802144 closed06:25:53Z; wrapper1260 also exited0.
Frozen mainfb5548cc80a1de57e5a1c3c853a0ccfc43338515d00e15867305fa5f59c6079c
uses the two read optimizations, lifecycle routing and CNG image hashes.
Source commit2ff5f017c03977c5e6ba9d31ba64dc634bfa2fe7; sealed manifest
optimized-drive-alpha-tools-20261029/manifest.json SHA230c08850b41bcab1defa0b81aa35406ea0760e25a4042657602d191e0065d6b.
Host case optimized-drive-alpha-20261029-2c0a76e195f540218d60e98266f4e14d;
dispatch SHA628f14f6755e1263fade86c49fd5c70696593260ce1d7d7b6246a3305ef0794f.
No fault was requested; main provisions its own managed shadow/journal.
Closed normal receipt SHA8287357c7cbe3567951be974df4d870a048db00243391a545e3ad23d3c682335.
It proves152 patches/70,631,424B, exact target2b63f03280fa7ce9b817334f81ef97cf6f11c3e445c8ee012886b4ad9ca89c26,
fresh source admission, HND, native15/10, original label and F mount.
Independent mutation875faa1d295849ae8e4fb11a65761b9d passed all3 native processes,
strict15/10 before/after and the50→80→10MiB/128-entry new-path workload.
Mutation closed receipt SHA3c196cfccb8f4fc5c25518d94f6fd97587866646cc01dc68ac3cbfc6f80243d1;
report SHA45c968b90da79cb386e45b998e3b1d5d47425a1b32290493de1d198983de4fb0.
The SAME working branch clean-stopped/started WITHOUT restore; fresh boot was
06:35:29Z after mutation ended06:31:24Z. Postbootbef2125926714a76a7f10c0cba2049ce
passed native/task0 and strict15/10. Its closed receipt SHA is
c55f61175a92f10aef6f24e36f5d68fcf98c2981c85219f4f726b16c1ff15356.
Actual preserved checkpoint632 receipt SHA004d70b74d7af8a8dfbbbca3e33cd97386965c0137c93c8f5758b5f084fc41f2.
Old25a was then retired via Hyper-V; cleanup receipt SHAd44305eea44e44d9b4693f388c23d654fa1043331414a3728d782d15b4633275.
VM is clean OFF/RAM0, D free118,738,907,136B and lab224,349,834,679B at cleanup.
There are NO active native workers or monitors. Keep the exact sealed2ff
artifacts; do not substitute a later build into these results.
The later frozen-allocation-map diagnostic codea8da755 passed cargo check--lib,
has no native qualification and does not enable selective capture.
Same-binary interruption/recovery on fb5548 remains unqualified; sealed2cac's
separate controlled Resume/Rollback evidence must remain distinct.
Local frozen package: .lab/releases/ntfs2refs-alpha-20261029-fb5548.zip,
SHAf826606342c9b2a06ef18a35996915d60c0c54fd840fbc71c21ddb26f854577b.
It contains the exact tested mainfb5548 and the scope/instructions in
docs/frozen-drive-alpha-20261029.md. Package record:
evidence/frozen-drive-alpha-package-20261029.json. No runtime authority is
granted by this package. Keep the existing user main.rs hunk unstaged.
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
changes plus code2ff5f01 CNG whole-image hashing passed normal conversion,
mutation and reboot as frozen candidatefb5548. They do not inherit sealed2cac's
interruption/recovery results. See the
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
