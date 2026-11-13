# Native format6 controlled recovery

Runtime `010316ded73a076747036198bd9036cf51dc082e` passed a controlled first-source-
write interruption and separate Resume/Rollback runs inside the owning Windows
guest. The normal format6 conversion also passed its completed read-only
observation. This is the native-shadow alpha, using the exclusive unbuffered NTFS
journal and two marker-copy barriers.

The fault producer exited86 after one actual flushed source write. Its original
checkpoint is `5d2517e5-59f9-4c26-b9e0-e6775d175f68`, parent prepared NTFS
`cb802669-903c-48cc-99e5-57976b149e7d`. Both directions below started independently
from that original interruption.

| Direction | Native time | Outcome | Saved checkpoint |
|---|---:|---|---|
| Resume | 15.8797s | ReFS, HND, all1,084 complete metadata/map bindings matched | `43d445cb-0d6e-4647-aa43-2664ee78b424` |
| Rollback | 11.5186s | NTFS, ABT,142,356,480 restore-required bytes matched | `200aaa68-6a12-482d-910e-60e5b1f20b63` |

The selected set is545,026,048 bytes with a131,635,728-byte N2RFRE02 journal.
Source-free elision covers402,669,568 bytes. Rollback's restore-required digest
matched `96a4400a2f6e7fc07e2c337b5e82a1e61346776ee3ae2f87a1e0704f497362b4`;
the original full-old digest remains the marker identity. Original free-space
contents are not restored by this policy.

Both built-in native checks and the metadata collectors passed, including cold
recovery with the original managed shadow detached. No shadow was reattached,
no binding or protection was changed to bypass a refusal, and no saved JSON
became fresh source admission. No additional full-content scan was run.

The fault archive contains62 files/130,227,192 bytes; Resume31/29,770,192 and
Rollback29/2,643,077. All copied metadata was length/SHA verified. Raw journals
and payload backing were not copied. Tasks and native workers were terminal
before each normal shutdown; the three original/result branches remain saved.

See [the pinned matrix evidence](../../evidence/native-format6-controlled-matrix-20261102.json).
These process-interruption results do not establish VM hard-power, physical
power-loss, arbitrary volume size/count or universal hardware qualification.
No unit tests were added or run. Power-boundary cases use a separately frozen
runtime with explicit lab pause instrumentation.
