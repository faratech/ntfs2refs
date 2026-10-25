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

This is a **bounded laboratory success**. The four user payload ranges were
relocated; this run does not demonstrate retained physical extents. Source
admission for arbitrary NTFS volumes is still closed, including unresolved
NTFS `0x0080` policy and TxF replacement state. Native interrupted-recovery
qualification and a usable general conversion CLI remain unfinished. Boot
volume conversion is a separate later objective.
