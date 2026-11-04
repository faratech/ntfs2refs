# Private thin-pool addressability

Windows exposed a raw Storage Spaces virtual disk of **1,000,001,530,494,976
bytes**, slightly over 1,000 TB, using two newly created 5 GiB dynamic VHDX
members in a private pool. The native device length matched the requested
aligned size. This establishes an addressability path beyond one VHDX; no
filesystem was created and no conversion ran.

All storage operations ran inside the owning Windows 11 lab guest. The original
SYSTEM probe created only its two enrolled members and pool, then stopped before
requesting a virtual disk: it incorrectly compared PowerShell capability strings
`Thin`/`Fixed` with a numeric value. The original failure was preserved. A separate
continuation reopened those same members for read-only information, checked
persistent GUIDs, geometry, exact pool and membership, and issued one
`New-VirtualDisk` request with Thin provisioning, Simple resiliency, one column
and zero write cache. It exited 0 in 7.2995253 seconds.

| Address-space observation | Bytes |
| --- | ---: |
| Requested minimum | 1,000,000,000,000,000 |
| Native size divisor | 2,147,483,648 |
| Aligned request | 1,000,001,530,494,976 |
| CIM virtual disk, CIM disk and native device length | 1,000,001,530,494,976 |

The supported-size query reported a 2 GiB minimum, 8 GiB maximum and 2 GiB
divisor for the current pool profile. The continuation used the divisor to
construct its single Thin request, which the provider accepted. This result
must not be replaced by an assumed universal Thin ceiling from that query.

The closure observer reopened the resulting raw device read-only and checked
its device number and length through the same handle. Pool identity, the two
original physical-disk members and the one returned virtual disk still matched.
Both recorded SYSTEM process identities were gone; their actual terminals
recorded the original failure and continuation success.

| Storage measure at closure | Bytes |
| --- | ---: |
| Combined virtual capacity of the two members | 10,737,418,240 |
| Actual allocation of their retained backing files | 75,497,472 (72 MiB) |
| Pool allocated size | 805,306,368 |
| Virtual-disk footprint reported on the pool | 268,435,456 |

These are different layers of accounting, not additive quantities. The 72 MiB
is a post-experiment file-allocation observation, not peak scratch or physical
capacity sufficient to populate a 1,000 TB filesystem. Thin provisioning does
not create that physical capacity.

The metadata-only closure contains 37 files / 156,492 source bytes, with every
source and host length and SHA verified. Its manifest is pinned in
[the experiment evidence](../evidence/private-thin-pool-addressability-20261104.json).
No VHDX or payload data was copied or hashed during closure.

The public native-shadow backend still uses one VHDX. Integrating a private
pool needs an opaque runtime owner for new member files, exact pool/virtual-disk
identities, resource accounting, authenticated restart discovery and explicit
retirement. ReFS formatting, large-offset data I/O, conversion and recovery on
this provider remain unqualified. The existing alpha gains no new size claim
from this experiment.

Microsoft documents the native management contracts in
[New-StoragePool](https://learn.microsoft.com/en-us/powershell/module/storage/new-storagepool)
and [New-VirtualDisk](https://learn.microsoft.com/en-us/powershell/module/storage/new-virtualdisk).
