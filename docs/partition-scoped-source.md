# Partition-scoped source development

The existing native-shadow converter excludes a dedicated source disk. Supporting
a data partition beside the running Windows partition requires a separate source
backend; accepting additional partitions in the old layout validator would not
provide that exclusion.

The new `n2r_win32::partition_isolation::PartitionScopedReader` is the first
functional slice. It opens the physical disk read-only, validates its device and
geometry, verifies both complete GPT copies and CRCs, and reconciles every used
entry with the native layout. GUID and geometry establish partition identity;
the Windows partition number is checked independently of the raw GPT slot.
Sibling entries are hashed. Reads and seeks stay inside the chosen partition.

The reader resolves the running Windows and active pagefile volume extents and
refuses a known overlap. Unresolved paging and uncollected dump configuration
remain explicit. No report admits conversion or grants isolation/recovery
authority. The observer does not implement a writer or change disk attributes,
partition attributes, mount points or availability. Its metadata output must
reside outside the selected source partition, verified through actual volume
extents. A sibling C: metadata destination is permitted for observation only.

`lab-observe-partition-isolation` accepts a SHA-256-pinned request and an explicit
RAM/buffer budget, reads a bounded partition-relative range, revalidates the
native observations and emits metadata plus the range hash. It does not export
the payload. Large layout queries use their admitted buffer rather than the old
whole-disk control helper's fixed buffer limit. Retained layout-event copies and
both simultaneous read buffers are charged before allocation.

The first partition writer must own real source exclusion, preserve the live
Windows disk and siblings, and use bounded journaled writes with flush/readback.
Its preparation and restart recovery must authenticate the new protection mode.
The existing dedicated-disk guards remain unchanged. Initially, journal and
scratch storage must still satisfy the existing independent-physical-disk rules;
allowing a C: sibling journal is a separate storage-policy change.

The disposable Windows 11 probe created a 2 GiB NTFS partition beside C:.
`mountvol T:\ /p` blocked volume reads immediately but left the raw GPT offline
bit clear; after a normal reboot, volume reads succeeded again. Windows also
renumbered the new and Recovery partitions to match their raw GPT order. The
separate target-only GPT-attribute control wrote the offline bit to both GPT
copies, while the already mounted volume still accepted reads. These observations
show why raw persistence and runtime exclusion require separate checks. They do
not qualify conversion on a Windows-sharing disk.

The GPT offline bit plus a separate runtime-offline operation survived a normal
reboot: volume reads failed with error 21 while raw reads and C: stayed usable.
The pinned Rust observer then exited 0 in 0.0417076 seconds, reading exactly
8,192 payload bytes and matching the independently generated marker hash. It
also resolved the actual C: pagefile to the nonoverlapping Windows extent.

The same-byte physical-write experiment failed with error 21. Its older helper
did not record the exact failed stage, so write completion remains unknown.
A separate diagnostic issued no writes and successfully opened the physical
disk read/write, queried its identity, read both GPT headers and the marker, and
flushed the disk. This narrows the failure; it does not qualify a writer. An
offline volume is not proof that a filesystem lock/dismount owner satisfies
Windows' separate raw-write interlock. A fresh lock/dismount experiment and a
sound post-reboot reacquisition protocol remain necessary before integration.

The test partition's original GPT attributes and T: access were restored, its
NTFS marker matched, and C: remained healthy. The VM was normally shut down and
the completed branch saved. See the exact build, receipts and limits in
[the recorded experiment](../evidence/partition-scoped-source-20261103.json).
The changed converter's performance optimization has not yet had its own full
native conversion run. No unit tests were added or run.
