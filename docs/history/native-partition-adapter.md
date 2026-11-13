# Native partition adapter qualification

The main Rust crate forbids unsafe code. `crates/n2r-win32` isolates the small
Windows boundary: synchronous device controls, aligned allocation, the current
Windows directory and explicit handle closes. No host disk has been opened by
these new routines. Ordinary-file and parser tests pass; guest measurements of
persistent exclusion and native I/O are still required.

The initial profile is a 64 GiB GPT disk with partition 2 at 16 MiB, length
52 GiB, 512-byte logical sectors and 4096-byte physical sectors. Its only other
permitted partition is the preceding MSR. Disk and partition GUIDs are verified
from the complete native layout. The volume GUID is separately bound through
its one physical extent; it is not assumed to equal the partition GUID. Device
numbers route requests and do not supply persistent identity. The disk holding
the running Windows directory is excluded before opening a candidate for write.
[Device routing](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-storage_device_number),
[GPT layout](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-drive_layout_information_ex),
[partition entries](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-partition_information_ex).

Isolation locks and dismounts the bound volume, sets the physical disk's offline
attribute with `Persist=TRUE`, verifies that attribute, then closes the volume
lock owner. The shadow also receives the read-only attribute. On any failure,
there is no automatic online/unlock fallback. A fresh process only reopens a disk
whose identity and persistent exclusion already match. These documented
attributes are the mechanism to test, not proof that crash exclusion has passed.
[Persistent attributes](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-set_disk_attributes).

Partition reads use a separately owned, initialized, 4096-aligned buffer. An
arbitrary logical read is rounded outward inside the partition and copied back
to its caller. Raw writes require an explicitly armed, sorted 4096-aligned write
set disjoint from retained ranges, with a 256 MiB maximum dispatch budget. They
cannot touch the GPT or exceed the partition. A short/failed write or failed
flush poisons the handle; the caller must preserve the branch and reopen through
journal recovery. No automatic partial-write retry occurs.
[Unbuffered device access](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea).

`lab-native-probe` accepts a pinned request under `C:\ntfs2refs`, persists an
intent file, isolates or reopens both partitions, verifies the complete 64 KiB
A/B retained patterns, and optionally hashes both complete partitions. It checks
the target's native flush and records control responses and read counts. It has
no write-arming or online transition command. Success leaves both disks offline.
The request pins reviewed fixture evidence; the surrounding harness must verify
that evidence's native metadata and placement observations before invoking it.

The journal core can inspect a trusted ticket and expose its exact validated
write ranges. Integrating that descriptor with native write arming, trusted
ticket storage and journal-file binding remains separate work. A writable native
mount requires a durable handoff marker first. After handoff, the journal's
rollback path is permanently closed; the laboratory checkpoint is the remaining
test recovery mechanism. These controls assume the laboratory excludes another
administrator or raw writer changing disk state concurrently.

Required native sequence: prepare and clean-remount the pair; prove A/B through
offline raw reads; restart and prove exclusion plus unchanged bytes again;
prepare/flush the full journal and trusted ticket; apply only its ranges;
verify the whole expected image; record handoff; mount/read through ReFS; reboot
and test new allocation. No result from ordinary-file tests substitutes for
those measurements, and one successful fixture will not qualify arbitrary NTFS
features or boot conversion.
