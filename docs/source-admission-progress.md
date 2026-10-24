# Source admission: current implementation and remaining gates

P0 is complete at `8935e11`: supported native logical streams match the raw
model, including resident data, ADS, sparse zeroes and uninitialized tails.
See [logical-data evidence](native-ntfs-logical-data.md).

P1 is underway. The following code adds a combined source decision and real
backup checks. It does **not** issue an admission certificate or authorize raw
writes. A small existing-tree conversion and native interruption/recovery are
still the next decisive demonstrations; the prepared one-file result is unchanged.

Validation: 386 workspace tests pass, five remain ignored, formatting and clippy
with warnings denied pass, and all 19 lab guard checks pass. New tests exercise
directory record bounds, missing/stale/duplicate namespace entries, explicit
enumeration failures, role recognition and refusals, and damaged/torn/incomplete
backup cases.

## Native namespace evidence

The Rust collector emits schema 5, with separate read/list handles, 128-bit file
identity before/after and two restarted directory enumerations. Its bounded
decoder checks linked-record offsets, lengths, UTF-16 components, IDs, directory
type and terminal `ERROR_NO_MORE_FILES`. A failed or unfinished enumeration is
never an empty directory. Limits are 64 KiB per call, 64 calls per pass, 4,096
entries per directory and 2 MiB of retained namespace buffers. The comparator
redecodes the actual responses; it does not trust a completion flag.

The native view returns long names. DOS-only aliases remain separately counted
raw semantics, and the initial preservation profile rejects them. Dot entries,
when returned, must refer to the observed directory and its actual parent.
Names and child references must match exactly; hidden/system entries are not
filtered by the comparator.

Microsoft documents the [extended directory record](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_extd_dir_info)
and [directory query classes](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ne-minwinbase-file_info_by_handle_class).
These APIs do not imply that every NTFS internal record is natively enumerable.

On the protected control corpus, observation
`4ae34e3b7e2f4de7ba82894e805a542f` matched four of seven directory identities:
`fixtures` (eight entries), `$RmMetadata` (three), `$TxfLog` (four) and `$Txf`
(empty, with explicit successful EOF). Root enumeration returned `fixtures`
but omitted the eleven reserved NTFS system names present in the raw root
index. `$Extend` and `$Deleted` refused opens with error 5. The strict comparison
retains all three unresolved outcomes. Build-specific visibility/replacement
rules require their own evidence before admission; no general `is_metadata`
exemption has been added.

The 36 requested identities remain accounted for, and logical-data verification
still matches 16 identities / 13 streams, including all eight fixture streams.
The full 1 GiB source hash remained
`86573a248b1ba615940688d1a60014a74a997bff779faa51ce781899f2e94727`.
Native writes were zero. The source checkpoint remains
`c4f58c73-5ca5-4842-bc7b-6e980a8eabd7`; the VM was cleanly stopped and restored
to installed-clean, off at 4 GiB, without creating another checkpoint.

Artifacts: `.lab/hyperv/ntfs-attestation/file-handles-20261024T185950629Z`.

| Artifact | SHA-256 |
| --- | --- |
| Collector actually run in the VM | `22d2a86eeaebb65109768ed62c6a04719ce2222752c4273fc5694c3099d0f2b1` |
| Native report | `fc03fa40c4bdccacf62adae89e61d22fc58a9560b7e98a81ff0d8762f4108953` |
| Initial comparison | `884aedbc747452067ddde3c886a21edfca485281962417f425950f11d2fc24e7` |

## One source-policy assessment

`src/ntfs_admission.rs` combines raw allocation, namespace and security results
with native per-object metadata, mapping, logical-data and directory evidence.
It does not require the diagnostic `all_requested_metadata_matched` flag across
NTFS records that need different evidence.

Each object receives an explicit disposition: preserve supported user semantics,
recognize a specific filesystem-internal role, or reject. Internal recognition
requires the exact reserved record/name/type or a known `$Extend` path with
sequence-bound ancestry. POSIX and Windows long-name namespaces are handled;
unresolved ancestry, unknown descendants and nonempty reserved-slot payloads
cannot hide behind `is_metadata`. Recognition only identifies an obligation:
all allocations still need ownership accounting and replacement-state validation.

The initial user profile is the proposed bounded ordinary-tree subset: one
unnamed, fully initialized contiguous nonresident stream per file; EOF equals
allocation and is a positive multiple of 64 KiB. Limits remain 128 files, 32
directories including root, and 256 MiB logical data. Resident/empty files,
sparse/encoded streams, ADS, aliases, hard links and unsupported attributes are
explicit refusals, even though some are already readable by the inspector.
Verified SACL absence is required. Stored/API security differences and observed
timestamp changes remain visible.

The control corpus recognizes 27 internal roles and rejects nine root/user
objects under this narrow profile. Its dirty bit is clear, but volume flags
`0x80` exceed the current zero-flag policy. That refusal is not a claim that the
source is dirty. Unknown flags, reparse/transaction semantics and other inspector
refusals are retained.

## Actual backup verification

`src/ntfs_backup.rs` reads the primary and final-sector backup VBR, compares
geometry with the inventory, then resolves `$MFT` and `$MFTMirr` through their
checked DATA mappings. It requires actual initialized, non-sparse coverage and
bootstrap locations matching the VBR. Every one of the first four primary and
mirror records must pass the existing FILE/USA/attribute parser and match
byte-for-byte. This strict initial 512/4 KiB/1 KiB profile does not normalize
differing USA encodings, LSNs, slack or attributes; it can refuse other valid
layouts. It does not prove clean log or transaction state.

The verified evidence type has private fields and no deserializer. It binds the
inspection fingerprint. The optional `compare --source-image ...
--admission-output ...` path opens the raw image without concurrent writers,
rehashes it against the pinned inspection before/after backup reads, and embeds
the evidence in the assessment. A supplied JSON success flag cannot replace
those reads. Actual device reinspection after exclusion is still required for
the eventual executable certificate.

The existing control image passed exact VBR equality and all four MFT mirrors.
This removes only its backup refusal. The assessment continues to reject source
admission. Reproducible replay artifacts, binary and source pins are under
`.lab/development/source-admission-backups-20261024T192424482Z`:

| Artifact | SHA-256 |
| --- | --- |
| Host replay/assessment binary | `0fa269bfa3f50d524847b7e8f470160dc74fc4185268068af9ac328c4de54c06` |
| Assessment | `01272005e352aaed333160631c086ff48480176f7aa2acbc7659f063dfa3b7ea` |

## Required continuation

Finish the post-flush/exclusion device basis, clean log/internal replacement
state, reserved-name visibility rules and security/timestamp round trips. Then
issue a device-bound certificate and consume it in a separate versioned
multi-file retention/relocation profile. Keep the old fixture guards and journal
handoff boundary intact. Native interrupted reconstruction must preserve disk
exclusion and recover exactly before the first writable ReFS mount.
