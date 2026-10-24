# Protected mounted sampling after a locked-query refusal

Status: separate guest/native implementation prepared; 234 mock/parser/guest
guard checks pass in Windows PowerShell 5.1 and PowerShell 7. No VM or device-state
action has been performed for this profile. Host orchestration is being reviewed.
The original range-read sources remain frozen.

## Evidence and supported boundary

In `range-read/win11-20261024T003149738Z`, base and disk-extent queries succeeded
before locking; the lock succeeded; the locked base query returned Win32 21
(`ERROR_NOT_READY`), zero bytes. No locked bitmap, locked extent query or raw read
was reached. Unlock/close, unchanged-fixture checks, export and baseline restore
completed. The refusal does not prove that raw reading itself is unsupported.

Microsoft documents exclusivity/cache flush for lock, and explicitly says NTFS
treats the locked state as dismounted. It does not promise mounted-filesystem
queries remain usable on locked ReFS. Pre-lock bitmaps cannot replace locked
observations: pending changes may be flushed while locking, and bitmap results
are point-in-time observations. Matching before/after records cannot exclude an
intervening allocate/free cycle. [Lock](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_lock_volume),
[bitmap consistency](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_volume_bitmap)

The proposed new profile establishes disk read-only protection before a fresh
mounted observation. This is a reversible device-state mutation, explicitly
distinct from a pure read-only probe. Lock/dismount may flush native writes;
the helper issues no raw or file payload-write requests.

## Exact device binding

Reuse all control/placement/remount proof hashes from the frozen range profile.
Select only the enrolled 64 GiB basic GPT data disk, unique ID
`60022480D091C4251B5FFD619706C2B5`, GPT disk GUID
`b4ab4dbc-6bd7-4199-8e4a-01b828e98584`. Its target partition is number 2, GUID
`00c9f113-e0b9-49d8-b031-130aef8ef3fb`, offset 16,777,216 and length
55,834,574,848 bytes, logical/physical sectors 512/4096 and clusters 4096.
Require one matching disk, no boot/system/pagefile use, no dynamic/spanned/
clustered storage and no other mounted filesystem on that disk. Reject an
initially offline or read-only disk. Evidence remains on the separate OS disk.

Bind a persistent physical-device control handle through native device number,
length, sector geometry and complete bounded GPT layout. The GPT disk and
partition GUIDs/offset/length must match. Bind the volume handle through its
single native disk extent. Disk number alone is insufficient. Recheck identities
before state transitions and after reopening. The physical handle receives only
identity/protection controls; payload is read through the volume handle.

For the lab, restore only checkpoint `4b581541-4899-4f91-adc1-e4e784c7cacf`,
with original target VHD ID `25c491d0-5f1b-4205-9e6f-fd619706c2b5`; retain all
three owned-disk checks, offline networking, Secure Boot and temporary 8 GiB RAM.
These Hyper-V checks are orchestration, not a production dependency.

## Protection transition and fresh sampling

1. Record durable start/state evidence and verify both fixtures. Close file
   handles and bind the volume/physical control handles. The control handles
   require read/write access for the management controls; there is no WriteFile
   or other payload-write entry point. A later sampling handle is read-only.
2. On the volume control handle, perform exactly one `FSCTL_LOCK_VOLUME`, then
   `FSCTL_DISMOUNT_VOLUME`, then `IOCTL_VOLUME_OFFLINE`, each requiring success.
   Keep the same handle throughout. Do not dismount after a refused lock.
   Microsoft's offline contract requires prior dismount and explicitly says
   this same-handle sequence prevents remount. [Dismount](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_dismount_volume),
   [volume offline](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_volume_offline)
3. While that volume is offline, issue one `IOCTL_DISK_SET_DISK_ATTRIBUTES` on
   the bound physical handle: mask/value 2 (`DISK_ATTRIBUTE_READ_ONLY`),
   `Persist=FALSE`, reserved fields zero. Require native GET attributes to equal
   original attributes plus bit 2; query writability without any test write.
   Accept only the explicit write-protected outcome (`ERROR_WRITE_PROTECT`, 19)
   as that query's negative result; arbitrary errors are unresolved.
4. Issue one `IOCTL_VOLUME_ONLINE` on the retained volume control handle, then
   unlock/close it and close the physical write-capable control handle. Any
   refused transition stops, preserving exact status and state; no alternate
   sequence or retry is selected automatically. Volume online/offline is
   distinct from disk online/offline. [Volume online](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_volume_online)
5. Open new read-only physical and volume handles. Recheck native disk read-only
   attributes, write-protect query, identity, extent and Storage API read-only
   state. `GetVolumeInformation` must also include `FILE_READ_ONLY_VOLUME`.
   Remeasure both fixture identities, hashes and complete mappings, then base,
   legacy bitmap and extended flag-1 bitmap in this protected mounted epoch.
   Require the saved mapping/hash, full bitmap coverage, all sixteen source
   clusters free and all sixteen destination clusters occupied in both maps.
6. Close fixture handles. Lock the same read-only sampling handle used for the
   mounted volume queries. Reconfirm disk protection through the independent
   physical handle and native disk extents through the locked volume handle.
   Stop on any refusal/contradiction. Do not repeat mounted-filesystem queries
   after lock: disk protection predates them and has remained set. Read exactly
   two aligned 65,536-byte ranges at the already derived offsets, at most
   131,072 payload bytes; no general caller-supplied offset is accepted.
7. Unlock and close the sampling volume handle, then reopen it read-only once.
   Keep the independently bound physical handle throughout. Do not assume an
   unlocked ReFS handle becomes usable for filesystem queries again. Failed
   close/open stops without retry. While still protected, repeat fixtures, base, bitmap range
   states, disk identity and protection checks. Export all bounded evidence.
   Do not clear read-only in this experiment. After determinate success and
   verified export, cleanly shut down and restore the original off-state
   baseline with 4 GiB RAM. An early determinate no-mutation refusal can also
   use that path; a mutation-phase failure requires state evidence and review.

The initial lock establishes a clean transition; the second provides exclusive
sampling. The profile therefore has a two-lock bound, distinct from the original
single-lock probe. Successful mounted read-only operation on this ReFS build
remains an experimental gate, not an assumption.

`GetVolumeInformation` documents the mounted read-only flag; disk attributes
and `IOCTL_DISK_IS_WRITABLE` independently describe the backing device's access
state. Require all, retain exact returned data and never test protection with
a write. This is guest storage-stack protection, not hardware write blocking or
protection from another administrator deliberately clearing the attribute.
[Mounted volume flags](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw),
[disk attributes](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_disk_get_disk_attributes),
[writability](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_disk_is_writable)

The WDK writability contract distinguishes media write protection from resource
and I/O errors, supporting explicit expected-error qualification rather than
treating any failed query as proof. [Driver writability statuses](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ni-ntdddisk-ioctl_disk_is_writable)

## Is whole-disk offline required?

No such prerequisite appears in the native read-only attribute contract.
Microsoft's older VDS documentation explicitly permits basic-disk offline and
read-only transitions in either order. VDS is superseded and is not the proposed
implementation. Keeping the disk online while taking the target volume offline
avoids invalidating the physical handle; the volume-offline state prevents
remount until protection is established. Do not add whole-disk offline, forced
VDS dismount or a Set-Disk fallback. [Basic/dynamic ordering](https://learn.microsoft.com/en-us/windows/win32/api/vds/nf-vds-ivdsdiskonline-offline),
[native setter](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-set_disk_attributes)

The installed primary SDK header
`C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um\winioctl.h`
confirms read/write access for volume online/offline and disk SET controls.
SET_DISK_ATTRIBUTES is 40 bytes; its version comment specifies structure size.
The Learn page currently names GET_DISK_ATTRIBUTES instead, an inconsistency:
do not use the GET structure's 16-byte size in the SET request. Pin/test layout
and control codes, preserve original attributes and record exact request bytes.

## Failure, resource and portability boundaries

Set indeterminate flags before every native phase. If offline/protection may
have executed but completion is unknown, preserve the VM branch/session and
observed device state; do not clear protection, reboot, resume VDL allocation,
or restore baseline. Close owned handles in finally when the native call has
returned, without adding speculative recovery controls. Any mutation-phase
failure preserves its protection/offline state for review. Normal completion
leaves read-only set until the host returns to the saved baseline.

Bound payload at 128 KiB, each bitmap at 2 MiB, complete GPT layout at 64 KiB,
and exported artifacts at 16 MiB with an exact implementation-time allowlist.
Record requested/completed phases, handle access, native errors, bytes and
separate writable/protected/locked/reopened epochs. Test every partial
transition, wrong disk, setter success without observed protection, generic
writability error, unexpected attribute changes, stale mappings, lock/query
refusal, bitmap disagreement, cleanup failure and lost transport.

The native mechanism runs inside Windows and is usable on bare metal without
Hyper-V or host VHD mounting. Returning a physical machine's disk to its prior
access state would be a separate validated cleanup operation; this experiment
does not implement that recovery policy. VSS is a different storage view and
requires separate identity/consistency research, not an implicit fallback.

No primary source guarantees every transition and filesystem query on this
Dev Drive build. Refusal at any gate is useful evidence. Even success qualifies
only these two ranges: residual bytes are not reserved, zero bytes do not prove
no-copy movement, and full metadata coverage, extent adoption, conversion and
boot remain unqualified.

## Implemented guest contract

New files are `lab/guest/NativeProtectedRangeRead.cs`,
`lab/guest/Capture-GuestProtectedRangeRead.ps1` and
`lab/Test-GuestProtectedRangeRead.ps1`. The native class uses the frozen
`NativeRangeRead.cs` only for shared parsers/data records. The guest reuses the
frozen allocation class's two exact read-only file observations behind new
protected-state checks; it does not change or weaken `GuestLab.psm1` or the
existing allocation collector's writable-disk preflight.

The guest takes one exact 32-lowercase-hex `CaptureId` and creates
`C:\ntfs2refs\protected-range-read\<CaptureId>`. The export allowlist is at most
30 files and 16 MiB. Nonempty partial native buffers are retained up to their
named bound; zero-length output does not create a file.

| Artifact names (all native buffers end in `.bin`) | Bound each |
|---|---:|
| `started.json` | 64 KiB |
| `protected-range.json`, `allocation-before.json`, `allocation-protected-before.json`, `allocation-after.json` | 1 MiB |
| `pDevice`, `sDevice` | 12 bytes |
| `pLength`, `sLength`, `sBaseBefore`, `sBaseAfter` | 8 bytes |
| `pAlignment`, `sAlignment` | 28 bytes |
| `pLayout`, `sLayout` | 64 KiB |
| `pVolume`, `sVolumeBefore`, `sVolumeLocked`, `sVolumeAfter` | 64 bytes |
| `pAttributesBefore`, `pAttributesAfter`, `sAttributesBefore`, `sAttributesLocked`, `sAttributesAfter` | 16 bytes |
| `sBitmapLegacyBefore`, `sBitmapMetadataBefore`, `sBitmapLegacyAfter`, `sBitmapMetadataAfter` | 2 MiB |
| `oldSource`, `destination` | 65,536 bytes |

`protected-range.json` records separate `transition` and `sample` summaries,
flat native query records with exact input/control/capacity/status and buffer
hashes, raw read records, and mounted flags. Fresh-handle close/reopen attempts
and outcomes are explicit. The durable started record conservatively says a
device mutation may have been issued; the completed result narrows that only
after a returned native transition record. Unknown native completion remains
preserved.

Only `destination-range-verified` or a completely returned early native
open/query/lock refusal before any dismount/offline/attribute/online attempt can
set `restoreAllowed=true`. Both need fixture checks and completed handle
cleanup. Every mutation-phase failure returns `blocked` and preserves the
branch. Success leaves disk read-only set; no profile code clears it. A protected
allocation report carries `protectedReadOnlyRequired=true`, observed disk state
and mounted flag evidence. Early `allocation-after.json` uses the original
writable collector and has no protected-state fields.

## Implemented host contract

`scripts/Invoke-LabProtectedRangeRead.ps1` restores only the pinned placement
checkpoint at fixed 8 GiB RAM. It accepts bounded boot/capture deadlines and
supports `-WhatIf`; it accepts no caller-selected disk, partition or raw range.
It archives and hashes the five guest dependencies plus the host runner and
lab module before execution. Durable host intent precedes guest dispatch.

The host exports at most 30 allowlisted files and 16 MiB, checks every copied
length and SHA-256, then validates the response, started record, exact 36-query
sequence, lifecycle completion and fixture epochs. Pure parsers independently
revalidate exported disk/GPT identity, geometry, read-only attributes, mounted
views, retrieval bases, allocation bitmap samples and both raw byte ranges.
Host code never calls a native device adapter. Successful cleanup requires the
fresh sampling handle close/reopen and final checks. Mutation-phase failures or
unknown completion retain the branch; they cannot reach shutdown or baseline
restore. Qualified completion restores the exact off-state baseline at 4 GiB.

`lab/Test-LabProtectedRangeRead.ps1` passes 251 checks under Windows PowerShell
5.1 and PowerShell 7. Its ordinary synthetic files exercise full native-byte
revalidation, including altered GPT/disk identity, protection loss, bitmap
disagreement/truncation and raw byte mismatches. Mocked remoting verifies that
timeout and transport failures retain unknown completion. The first captured
blocked result is a hash-pinned regression: the host surfaces the native
`fresh-sampling-handle` reason and guest error while preserving every cleanup
requirement and strict boolean validation. The guest/native
suite independently passes 234 checks on both shells. These tests and peer
review qualify the bounded experiment's guards, not native runtime success,
general physical mapping, conversion or boot.
