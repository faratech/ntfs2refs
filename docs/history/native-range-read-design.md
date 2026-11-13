# Bounded native raw range read

Status: implemented and tested (109 guest/native and 172 host checks), then
executed once as `range-read/win11-20261024T003149738Z`. Lock succeeded, but
`baseLocked` returned `ERROR_NOT_READY` (21), so no raw read occurred. Unlock,
unchanged-fixture verification, export, clean shutdown and restoration of the
off-state 4 GiB baseline completed. Locked bitmap/extent queries were never
reached. See the separate [adaptation proposal](native-range-read-lock-refusal.md).
The completed initialized-file placement run is
`extent-placement/win11-20261024T000401422Z`; its preserved off-state checkpoint
is `4b581541-4899-4f91-adc1-e4e784c7cacf`, named
`extent-placement-data-d98ba93b850d4eababa84c445439868a`.
The next measurement should read exactly two 65,536-byte ranges from the enrolled
target volume inside Windows: the moved file's destination and its former source.
Compare both full ranges with the exported unique pattern. Hyper-V and host disk
mounting are unnecessary for the native mechanism, which is suitable for Rust
Windows API calls on bare metal. VM checks belong to lab orchestration.

## Exact identity and address contract

Pin the original control evidence plus the placement and remount records by
SHA-256. Bind the enrolled target unique ID, 64 GiB disk size, GPT disk and
partition GUIDs, partition 2 at disk offset 16,777,216 with length 55,834,574,848,
volume GUID, ReFS label and native driver/build. Refuse boot/system partitions
and any geometry change. Select only the recorded initialized file,
`fixtures\placement-d98ba93b850d4eababa84c445439868a\initialized.bin`.
Its identity is `0x3000000000002702`, length 65,536, current mapping VCN 0–16 at
LCN 1508384, previous LCN 1508352 and SHA-256
`9b195d4598044587ab6e51b73d92063936710b9b1255158054918350d20f1d78`.

Fresh retrieval pointers and logical hashes must match the saved remount for
both original and new files. Query `FSCTL_GET_RETRIEVAL_POINTER_BASE` again;
its base is in volume-relative sectors. With checked integer arithmetic, derive
`baseSectors * logicalSectorBytes + LCN * clusterBytes`. The prior base-zero
observation is not fresh proof. [Microsoft retrieval-base contract](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_retrieval_pointer_base), [base structure and units](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-retrieval_pointer_base)

| Recorded range | LCN | Volume offset if base=0 | Guest-disk offset if base=0 |
|---|---:|---:|---:|
| Former source, current ownership unproven | 1508352 | 6,178,209,792 | 6,194,987,008 |
| Current destination | 1508384 | 6,178,340,864 | 6,195,118,080 |

The native read uses volume offsets; guest-disk offsets are recorded only for
interpretation. Require one complete nonnegative 16-cluster current extent.
Reject alternate streams, sparse/compressed/encrypted files, reparse paths,
fragmented mappings, misalignment, overflow and ranges outside the measured
partition. Accept no arbitrary caller-supplied offset. Resolve the verified
volume GUID to a direct volume handle; `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS`
must bind that handle to exactly one enrolled disk extent with the expected
offset/length. [Microsoft volume extent query](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_volume_get_volume_disk_extents)

## Minimal quiescence and read sequence

Reuse the aligned unmanaged buffer and `GENERIC_READ` / `FILE_FLAG_NO_BUFFERING`
approach from `Capture-RawControl.ps1` in a standalone helper. Close fixture and
directory handles after their before observations, then request one volume lock
on the direct read handle with read/write sharing. A successful lock excludes
ordinary open files and flushes cached filesystem data. A refused lock is a
measured result, with no forced process closure or unlocked fallback. The helper
issues no raw writes, but the native flush may write previously dirty filesystem
data; record these separately. [Microsoft lock contract](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_lock_volume)

The first profile should use the lock alone. Explicit dismount is unnecessary
for an interior read after obtaining exclusivity; whether this ReFS build accepts
the required queries while locked is measured. If a locked base, bitmap or
identity query fails, retain the native error and stop without automatic fallback.
Dismount does not replace a lock; a later profile needs a specific observed
reason. The full capture's extended-DASD control is unnecessary here because
neither range approaches the partition end. [Microsoft dismount semantics](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_dismount_volume)

Under the same locked handle, recheck the base and volume extent and request
fresh legacy and extended metadata-flag-1 bitmaps. Retain their exact input,
status and returned bytes. Parse only the declared bitmap domain, not trailing
capacity bytes; require coverage of all 13,631,488 clusters. Record all sixteen
old-source bits from both maps and the destination bits. A free observation is
not a reservation and does not independently prove absence of ReFS metadata.
This build's prior acceptance of the flag does not establish complete coverage.

Seek separately to each exact range using `SetFilePointerEx(FILE_BEGIN)` and
read 65,536 bytes into explicitly 4096-aligned unmanaged memory. Validate the
actual seek position and exact returned count; total raw reads are bounded to
131,072 bytes. The current 512/4096 sector and 4096-cluster profile satisfies
offset/length alignment. Keep this single handle private from concurrent seeks.
[Microsoft noncached alignment](https://learn.microsoft.com/en-us/windows/win32/fileio/file-buffering), [64-bit seek contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfilepointerex)

Retain bounded partial responses as incomplete evidence; release the lock and
close its handle in `finally`. Afterward re-observe both file identities, logical
hashes and complete native mappings, plus disk/GPT identity. A file cannot remain
open during a successful volume lock, so this before/after interval is explicit.
Only full-byte/hash agreement plus stable identity and mapping qualify the
sampled destination. No raw read of the original 4 MiB fixture is necessary for
this first profile; its before/after logical evidence provides a control.

## Former-source interpretation and the VDL0 study

Before either read, the implementation requires all sixteen destination clusters
allocated and all sixteen former-source clusters free in both fresh bitmap
variants. A failed gate stops without reading either range. An eligible former
source may retain the pattern or contain zeros after discard. If all 65,536
bytes equal the
known pattern, this is evidence for an attributable residual-data control that
needed no raw canary write. It is not authorization to adopt or overwrite that
range. Any later VDL0 experiment must revalidate its free state and content
immediately before use and account for allocations between observation and use.
No future eligibility remains durable across writable mounts or mutations.

The separate allocation/VDL0 study must distinguish
allocation, EOF, cached VDL and on-disk VDL. This read probe issues no allocation,
move, valid-data advancement, formatting or raw write. Matching zero bytes would
not establish that a move avoided copying. Full metadata coverage and conversion
remain unqualified even if destination and former-source bytes both match.

## Evidence, failures and review gates

Write new artifacts only under a unique directory on the separate guest OS
volume after proving it belongs to another disk. Bound the allowlist to eleven
files and 8 MiB total: two raw range files at most 65,536 bytes each; `range.json`
and two allocation JSON reports at most 1 MiB each; two base buffers at most
eight bytes each; two volume-extent buffers at most 64 bytes each; and two bitmap
buffers at most 2 MiB each. Preserve exact native status/error and buffer hashes.
The report separates lock/flush effects, seek/read attempts and actual bytes,
unlock/handle-close completion, full-pattern equality, old-source bitmap bits
and post-unlock file stability. It never claims zero-copy or conversion.

Tests should cover base-unit conversion, offsets above 4 GiB, integer overflow,
alignment, partition escape, fragmented/incomplete mappings, wrong native disk
extent, bitmap coverage/trailing bytes, disagreement on any source bit, short
reads and failed lock/seek/unlock. Mock calls must show no raw read before a
successful lock and identity validation. The native helper should contain no
write, format, move or valid-data operation; output-file writes are separate.

The host should restore only the exact outcome checkpoint, verify ownership,
offline networking, Secure Boot and 8 GiB RAM, then run a bounded guest command.
Export/hash every allowed artifact before clean shutdown and restoration of the
4 GiB baseline. Unknown transport or native completion preserves the branch and
session. Completed native refusals are exportable, with no automatic retry.
The implemented profile was reviewed before execution. It remains frozen;
the adaptation proposal is a separate profile, with no automatic fallback.
