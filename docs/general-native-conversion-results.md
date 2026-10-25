# General guest conversion: existing NTFS tree

On October 25, 2026, the generalized Rust guest path converted the existing
four-file NTFS tree on its original 52 GiB data partition. The work ran inside
the Windows 11 VM. The converted partition mounted through Microsoft's ReFS
driver, passed the eight-object native tree verifier, survived the bounded
create/grow/truncate/rename/delete and 128-entry directory workload, and
mounted as ReFS again after clean reboots.

The source NTFS image SHA-256 was
`798926b2783a747f0d046d1010c9a8d2b109a900388117fcef46449c3abddd89`.
The final frozen ReFS shadow SHA-256 was
`d49c01985146f3ad8a7191145d4258cbf25fcc7822bba6df830656af103de837`.
The pinned general request SHA-256 was
`3eb7b2ca0526e820ccc9ce0dd078336f27b4d8c38be7e1d55b554bc4aed5b30b`.
The guest journal applied 147 patch ranges and reported 70,483,968 target
bytes written. It durably recorded `N2RHND01` before the first normal ReFS
mount. The source disk remained offline throughout raw reconstruction.

Native evidence is under ignored local paths:

- `.lab/hyperv/general-replay/win11-20261025T124005483Z`: completed apply,
  handoff, native ReFS tree verification and collected journal marker.
- `.lab/hyperv/general-mutation/win11-20261025T131750089Z`: first successful
  ReFS mutation workload.
- `.lab/hyperv/general-mutation/win11-20261025T133054370Z`: second mutation
  workload, including exact root `FILE_BASIC_INFO` before and after.
- `.lab/hyperv/general-postreboot-verify/win11-20261025T133233235Z`: guest
  post-reboot verification. Its report SHA-256 is
  `6814b73f7d2cbd9afc23bc15005c035fb20175980cd337c88996c87335506da3`.
  The original host collector incorrectly marked the result false because it
  compared a local-kind `DateTime` to a UTC-kind `DateTime` without normalizing
  ticks. `reconciled.json` preserves that original report hash and verifies the
  identical UTC boot instant, the pinned guest report and the ReFS disk state.
- `.lab/hyperv/general-replay/general-converted-mutated-20261025T133637512Z.json`:
  powered-off checkpoint `78c621d1-2bde-4af8-9a39-ff7cf004332f`. The VM
  subsequently started again with disk 1 mounted as ReFS at F:.

The strict pre-mutation metadata verifier passed immediately after conversion.
After the deliberate directory workload, its original policy rejected the
root directory because ReFS updated root access, write and metadata-change
times. A separate read-only diagnostic showed that root creation time and
attributes, all seven other objects' basic metadata, file contents, security,
identities and namespace remained consistent. The scoped post-mutation path
now requires the root's exact 40-byte basic-info record captured by the
mutation workload before reboot; it does not treat arbitrary root timestamp
changes as a pass.

## Interrupted apply and native recovery

A separate run from a freshly verified NTFS/shadow freeze injected process
exit code 86 immediately after the first flushed target write. The collector
confirmed that disk 1 was still offline, the external journal was complete,
the handoff sector was all zero and recovery was required. The pinned `resume`
operation then proved the exact expected ReFS postimage, completed the
remaining journaled patches and left the handoff sector clear. A separate
finalizer wrote `N2RHND01`, mounted ReFS and verified the original eight
objects through `refs.sys`.

The recovered VM rebooted cleanly. A strict read-only verifier of the same
pinned eight-object tree succeeded after reboot with report SHA-256
`b763ed7869abf5e7214567009a3838b825d972b2389d82399fbfdba755029c0b`.
Its first scheduled launch exited before writing a report; the subsequent
read-only invocation of the same binary and inputs succeeded. That launch
anomaly remains in the saved evidence rather than being counted as a passed
scheduled-task run. The recovered branch was saved as powered-off checkpoint
`713c2e66-32b0-43e5-a6a2-a35098c3972c` and started again with disk 1
mounted as ReFS at F:.

Ignored evidence paths are:

- `.lab/hyperv/general-replay/win11-20261025T135034440Z` (controlled exit),
- `.lab/hyperv/general-recovery/win11-20261025T141452288Z` (exact resume),
- `.lab/hyperv/general-finalize/win11-20261025T142524383Z` (handoff and ReFS),
- `.lab/hyperv/general-recovery-reboot/win11-20261025T143305523Z` (reboot,
  strict verifier and saved-checkpoint provenance).

This is a **bounded laboratory success**. The four user payload ranges were
relocated; this run does not demonstrate retained physical extents. Source
admission for arbitrary NTFS volumes is still closed. The NTFS `0x0080`
short-name policy mapping is now confirmed, but its live frozen-source binding
and TxF replacement state remain unfinished. The first-write interruption
and resume path passed, but a broader write/flush fault matrix and the
shadowless rollback path remain to be qualified natively. A usable general
conversion CLI remains unfinished. Boot volume conversion is a separate later
objective.
