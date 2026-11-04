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

The Rust constructor stage is now implemented in
[`thin_pool.rs`](../crates/n2r-win32/src/managed_shadow/thin_pool.rs).
`create_new` accepts a fresh directory, an exact storage-subsystem identity,
requested address space and explicit resource budgets. It creates its own two
members, retains their provider and backing-file owners, and checks the resulting
raw device through a held native handle. The returned owner exposes observations;
it cannot be recreated from a serialized report.

The corrected Rust constructor `9606f22` subsequently completed its own native
case: its actual process exited 0 in 11.2804747 seconds and issued the opaque
live owner after checking the new members, pool, virtual disk and held RAW
device through opening and closing observations. Native disk 13 exposed
1,000,001,530,494,976 bytes with 512-byte logical and 4 KiB physical sectors.
This stage performs no GPT initialization, formatting, conversion or recovery.
Public conversion still uses the existing VHDX provider. Unknown states preserve
the private pool and members; this stage supplies no automatic teardown.

The preceding Rust case exited 1 after creating its pool and virtual disk but
before issuing an owner: the closing script looked up a pooled member using
`Get-Disk`, whose surfaced inventory hides these members. Its failure and assets
remain preserved. The corrected closing observation resolves members through
their recorded physical-disk identities and pool association. Read-only closure
after the successful second case also matched the first pool, both original
members and RAW virtual disk 10. Neither pool was reset or reused for a retry.

The constructor admits the complete two-member backing profile, metadata reserve
and separate Rust/PowerShell RAM shares before work. Actual free space and child
working set are sampled; they are not kernel quotas or physical reservations.
See [the build record](../evidence/private-thin-pool-constructor-build-20261104.json).

The successful constructor sampled 75,530,512 bytes of retained regular-file
allocation before writing its final observation receipt and 219,471,872 bytes of
PowerShell working set. Neither value is peak usage or a hard memory limit, and
neither supplies physical capacity for a populated petabyte filesystem. The
failed case's 15 metadata files (20,923 bytes) and successful case's 16 files
(27,122 bytes) were copied with source/host length and SHA checks; VHDX members
and payloads were excluded. See
[the exact Rust constructor evidence](../evidence/private-thin-rust-constructor-20261104.json).
Reattachment, ReFS formatting, payload I/O, conversion, recovery and replacement
of the public single-VHDX backend remain separate unqualified steps.

After metadata closure, the VM was normally shut down and one completed branch
was saved at `c60b51c2`, parent `3343`. A separate fresh process observed Off,
zero assigned RAM, that saved parent and no project workers. The b7 HND result
and both private constructor cases remain preserved. Saving this branch does
not establish thin-provider reattachment or recovery after a new boot.

Microsoft documents the native management contracts in
[New-StoragePool](https://learn.microsoft.com/en-us/powershell/module/storage/new-storagepool)
and [New-VirtualDisk](https://learn.microsoft.com/en-us/powershell/module/storage/new-virtualdisk).

The separate `7402509` format attempt reached a newly owned **72 TiB GPT
partition**, then Windows refused Dev Drive initialization while creating
filesystem structures. The formatter reported status 112 and exited 4; the
Rust process exited 1 in 16.9998085 seconds. The constructor and GPT observations
succeeded, and the read-only error-closing observation succeeded. That closing
success does not mean formatting succeeded: no formatted owner was issued and
the ordinary 64 KiB file probe was never reached. All assets were preserved
without a retry, fallback or cleanup.

At refusal, the pool reported 9,628,024,832 bytes of usable capacity,
1,879,048,192 allocated and 7,748,976,640 free; K: still had 33,134,178,304 bytes
free. Each nominal 5 GiB member's VHDX backing file was 37,748,736 bytes long.
These describe different storage layers. A nominal pool-capacity or Dev Drive
initialization requirement is a plausible explanation, **not a proved internal
cause**; host physical storage exhaustion was not established. F: was observed
as NTFS during closure; its payload was not rehashed.

The same build's existing VHDX path separately formatted, isolated and retired
one fresh empty 50 GiB shadow, preserving its external sentinel. Its actual
process exited 0 in 1.9802705 seconds. This is a small common-path smoke result;
it qualifies neither large thin formatting nor source conversion. The failure's
25 metadata files / 49,129 bytes and the smoke case's 13 files / 97,920 bytes
were closed with source/host length and SHA checks, excluding images and payloads.
See [the scoped refusal evidence](../evidence/private-thin-format-refusal-20261104.json).
The next bounded-carrier implementation has no native qualification from either
result. Public conversion/recovery and the frozen alpha retain their existing
scope.
