# Protected guest-side range observation

This is a separate data-volume experiment from the frozen `NativeRangeRead`
profile, which stopped when ReFS refused a query on a locked volume. It does not
convert NTFS or qualify metadata ownership, general address translation, payload
copy avoidance or boot support.

## Fixed scope and sequence

Restore the saved initialized-placement checkpoint
`4b581541-4899-4f91-adc1-e4e784c7cacf` in the owned Windows 11 guest. The target is
its existing 64 GiB disposable data disk, containing the 52 GiB ReFS 3.14
partition at byte offset 16,777,216. Match disk identity, geometry, complete
bounded GPT layout, partition GUID and volume-to-disk extent before any control.
All device-state changes and raw reads occur inside the guest; Hyper-V only
provides the experimental branch and recovery checkpoint.

On the same volume control handle, require lock, dismount and volume offline to
succeed before setting only the physical disk's read-only attribute. Verify the
native attributes and write-protected response, then bring the volume online,
unlock and close the control handles. Lock/dismount can flush native writes;
the experiment does not claim a write-free protection transition.

Fresh read-only handles must prove both physical write protection and the
mounted `FILE_READ_ONLY_VOLUME` flag. Query the retrieval base and ordinary and
metadata-inclusive allocation bitmaps. All sixteen former-source clusters at
LCN 1,508,352 must be free in both maps; all sixteen destination clusters at
LCN 1,508,384 must be allocated. Require the known fixtures' identities, hashes
and mappings to match the saved placement result.

Lock the read-only sampling handle, recheck device protection and routing, and
read exactly 65,536 aligned bytes at each fixed volume-relative offset:
6,178,209,792 and 6,178,340,864. Unlock, close that handle, open a fresh read-only
volume handle and repeat the protection, base and bitmap observations. Check
the known fixture identities, hashes and mappings again. Native buffers and
samples are exported and independently checked by the host. The sampling budget
is 131,072 bytes; there is no raw or target-file payload writer.

The helper never clears read-only protection. Mutation-phase failures preserve
the running branch. Automatic shutdown and baseline restoration require the
entire successful observation or an explicitly completed refusal before device
mutation. Unknown command completion always preserves the branch.

## First run: partial evidence, managed handle failure

Case `protected-range-read/win11-20261024T010715182Z`, capture
`582c4407000448c1a98a6589e08936fb`, established protection and completed both raw
reads. Both samples match all bytes of the known pattern, SHA-256
`9b195d4598044587ab6e51b73d92063936710b9b1255158054918350d20f1d78`.
The initial protected bitmaps report the former source free and destination
allocated. All 24 exported artifact lengths and hashes were independently
verified, together with native identity, routing and protection buffers.

The fresh-handle guard then rejected reopening. `SafeFileHandle.SetHandleAsInvalid`
marks the safe handle closed; it need not make `IsInvalid` true. The code tested
the latter and stopped before calling `CreateFileW` again. Native unlock and
handle closure succeeded. Final bitmap/protection/fixture epochs were absent,
so the run remains incomplete. The host correctly refused automatic restoration;
`restoreAllowed=false` was an intentional gate, not a JSON parsing failure.

Original guest evidence SHA-256:
`78eb63ce0e205f809462c8e85357126fbf6648eaa08f16360dda6d8900f4b352`.
Executing sources are retained in the case's `reviewed-sources` directory.

A separately recorded read-only inspection at 01:13:03 UTC confirmed the exact
target remained online, read-only and healthy, with both known fixture hashes
unchanged. Following review of determinate completion and closed handles, the
guest was cleanly shut down and preserved as checkpoint
`protected-range-failed-582c4407000448c1a98a6589e08936fb`, ID
`1195b3f6-b1ba-4b64-84b2-4f657e2b0166`. Baseline/off/4 GiB was restored at
01:13:55 UTC. The separate recovery records do not rewrite or promote the
original incomplete result.

## Corrected run: complete bounded observation

Case `protected-range-read/win11-20261024T011607181Z`, capture
`4c6bde7186b2473c8d2687d1399c0c49`, completed at 2026-10-24 01:17:23 UTC.
The native adapter now recognizes `IsClosed`, records successful closure before
reopening and permits only one fresh read-only reopen. Regression tests close an
actual ordinary Windows file handle with the production close routine; no test
device is opened. The host diagnostic now surfaces native refusal details while
retaining its original completion requirements.

Both 65,536-byte reads match the pattern byte-for-byte. Physical protection was
verified before, during and after the lock, and mounted read-only flags were
verified before and after. Fresh-handle post-read base and bitmap observations
were stable; both known fixtures retained their identities, hashes and mappings.
All handles closed, exports passed independent host checks, and the guest was
cleanly shut down before restoration of installed-clean/off/4 GiB. No request
cleared disk read-only protection.

The thirty exported artifacts plus their manifest total 8,603,417 bytes. Pins:

| Artifact | SHA-256 |
| --- | --- |
| Guest evidence | `06fde1ec5d3574bdf1886d1e27f6877db594096fcbce9872de33b7f356249dbd` |
| Host result | `21bbb40ecebd25cff6806f62d19f2545d6ab7d1749e8d363dca0fe3ed17eb6fd` |
| Export manifest | `afd6f6e8610a8c5da52cc4c51929cd30321a8728bd0c47e37af4ef527b12f160` |
| Final fixture evidence | `6d620327468510a3625b6e5793f446320ae6c95394160bc1c6f5f43fdfac240b` |
| Native helper | `ab1df9d17f28ea04aa2a1812a42ce1c903a8df15d3d2f8858d7f46768e6e8791` |
| Guest wrapper | `4d3a586528f0da200fae3f7444d2cd8962a1097d021b04c411a8e009fd63c0c2` |
| Host helper | `c1a378e8d845857114db2e3aaaaa1a268204c2329236f2ddfd6d1ca7c5292d67` |

Guest tests pass 247 checks and host tests 251 in both PowerShell 5.1 and 7.
Executing sources were archived before dispatch. The earlier failed case and
its checkpoint remain intact.

## Interpretation

The completed observation establishes only that the two sampled ranges match
this native placement profile and that a free former extent retained the
attributable pattern during the protected interval. It does not reserve that
range for a later experiment: any writable mount, allocation or move requires
fresh attribution. Matching bytes alone cannot show how much a native move
wrote, nor whether ReFS metadata can adopt retained NTFS payload.
