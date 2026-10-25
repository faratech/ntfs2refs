# General guest conversion: existing NTFS tree

## Certificate-backed eleven-object conversion

On October 25, 2026, run `c03cbc02c74145fdbca61c59cc94a5dd` completed the
generic certificate-backed Rust workflow inside the Windows 11 VM. The
original 52 GiB NTFS data partition became mounted, writable ReFS at F:.
The worker exited 0, and the native verifier matched all eleven objects:
six files and five directories, including both resident Windows cache files.
Stored/kernel descriptors and the separately recorded API security projections
were preserved. The recorded mount-path comparison also passed.

Every source admission gate passed and a live device-bound certificate was
issued before journal activation. The external journal and trusted ticket were
durably saved; apply wrote 151 patch ranges totaling 70,795,264 bytes and proved
the expected target image before handoff. Finalization recorded the irreversible
handoff barrier, mounted through `refs.sys` and completed native tree verification.

The source image SHA-256 was
`c7fdc13e41008b89de797a87b3307e7129411e30607f043eddabae56944a5b1c`.
The expected ReFS image SHA-256 was
`2a655e548d850af06ccfff04b37e66c2a0760155f3c6ea3cd5b4b084bb92c0bc`.
The source contained 524,376 logical bytes: four ordinary file payloads totaling
524,288 bytes were relocated, and the two resident streams totaling 88 bytes
were materialized. **Retained payload bytes were zero.** This result does not
demonstrate natural retained extents or payload-independent scratch usage.

Exported evidence is under ignored local path
`.lab/hyperv/certificate-conversion/win11-20261025T185439277Z`:

- `qualification/admitted-assessment.json`: zero failed gates, source admitted
  and certificate issued; SHA-256
  `c21aace70a7fe47b19e265e09041563f9031c682b8f8cde30d1e29fc1399b857`.
- `apply.json`: exact target image, patch count and bytes written; SHA-256
  `545576df273ad96cb7b0f8442ec927d2ae62ba0926487bb27d14b4f8bc3c849f`.
- `finalization.json`: successful handoff, native eleven-object verification
  and preserved mount paths; SHA-256
  `e20d202bc27a49d946ea070f10261f06e255502e5425d668c93bc302d708745b`.
- `result.json` and `collected.json`: successful workflow and host observation
  of exit 0 and online/writable ReFS. The result SHA-256 is
  `0cc52dd58ae4c628313ad0b682b3c12ff66dab32b06e8f3924ce5e07344b5174`.

After a clean reboot, the strict `lab-verify-general-converted` check also
exited 0 and matched all eleven objects through ReFS. Its exported
`postboot.json` has SHA-256
`fe50b52f0f44607e514d13fd4c2161643f6bcab8a42065c7237b74641d3a69df`.
The converted branch was saved as powered-off checkpoint
`71c4130a-a7cd-4476-996f-0fb912684009`, named
`admitted-refs-11objects-20261025T194150282Z`, then started again with writable
ReFS at F:.

The native invocation used `lab-convert-admitted-tree`, which calls the same
`general_conversion::convert` core as the public `ntfs2refs convert --request`
interface. Public CLI argument, pin and refusal tests passed separately; they
are not a second native conversion run. Earlier mutation and interruption/
resume evidence below belongs to the earlier eight-object runs. The supported
profile remains bounded; boot conversion and a broad compatibility or
failure-injection matrix are not qualified by this result.

## Earlier four-file conversion and mutation

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

These are **bounded laboratory successes**. The four user payload ranges were
relocated; these runs do not demonstrate retained physical extents. Arbitrary
NTFS volumes still require the supported profile and live admission. The NTFS `0x0080`
short-name policy mapping and its live frozen-source binding have passed.
Frozen object-ID/reparse indexes and disabled unlimited quota defaults also
passed their new raw/native checks. The bounded default-RM freeze also passed
in a separate native source run. The later certificate-backed run above
accounts for the Windows files' distinct security views and passes target
preservation. The first-write interruption
and resume path passed, but a broader write/flush fault matrix and the
shadowless rollback path remain to be qualified natively. The public conversion
and recovery CLI now wraps the generic core; its native invocation and broader
profile qualification remain distinct work. Boot volume conversion is a
separate later objective.
