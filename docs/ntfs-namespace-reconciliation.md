# Raw NTFS namespace reconciliation

The Rust inspector now reports `namespace_reconciliation` alongside the raw
allocation diagnostic. An MFT filename alone does not establish that a
directory indexes the object or that every live index page was considered.

`src/ntfs_namespace.rs` parses `$I30` INDEX_ROOT and INDEX_ALLOCATION records.
It verifies node/entry bounds, terminators, child flags, INDX signatures,
512-byte update-sequence fixups and allocated-slot/VCN correspondence. Every
index-bitmap allocation must be initialized and reachable exactly once from
the root. Free old pages are not live entries. Missing children, cycles,
shared child pages, unbalanced leaves and unreachable allocated pages refuse
reconciliation.

The in-order traversal includes keys in internal nodes. Ordering uses the
volume's complete `$UpCase` table and preserves raw UTF-16 code units.
Case-colliding keys are refused by this initial profile. Every index link must
match an allocated base MFT record's sequence, parent reference, filename and
namespace. Every MFT filename must appear in an index, apart from the root's
special self-name. Hard-link counts distinguish DOS aliases from independent
links. All named objects must be root-reachable; matching links inside a
disconnected cycle cannot pass.

Reserved nameless records 12–15 are recognized when they have no links and are
not directories. This exception does not authorize dropping any attribute,
data or allocation. Attribute lists/extensions produce
`incomplete_attribute_inventory`, since their logical objects need assembly.
Allocation ownership, security and metadata-role policies remain separate.

The reader requires 512-byte sectors and 4 KiB index records. Its geometry-aware
entry accepts power-of-two clusters from 512 bytes through 2 MiB; the compatibility
entry retains 4 KiB clusters. When a cluster exceeds the index-record size,
index child addresses and INDX header addresses use 512-byte units, while bitmap
bits still select index-record slots. The root's units-per-record field must
match that geometry. Otherwise the addresses use cluster units. This distinction
is corroborated by the [Linux NTFS3 index implementation](https://github.com/torvalds/linux/blob/master/fs/ntfs3/index.c).
Only format facts were used; no upstream implementation code was incorporated.
This reader change does not expand conversion admission, which retains its
4 KiB source-cluster requirement pending complete construction/recovery support.
Inputs are bounded to 16 MiB cumulatively, including `$UpCase`, 16,384
entries/objects, 131,072 UTF-16 name units, 4096 directories and 64 tree levels.
Unsupported geometry, malformed input or exceeded bounds produce rejected
diagnostics; no partial tree is accepted. Reports retain counts, an evidence
digest and refusal details. Temporary index data is not retained in the report.

The optional field defaults to absent in older inspection reports.
`consistent_raw_model` proves these relationships on the supplied image. Native
enumeration/file-handle identities, security descriptors, clean log state,
backups, stable freeze and destination preservation still need reconciliation.
`inventory_complete=false`, the native namespace blocker and the executable's
refusal to convert remain in force.

## Validation

Twenty-five pure tests and seven integration tests cover leaf/multi-page
indexes, internal keys, raw Unicode, hard links/DOS aliases, torn writes,
wrong VCNs, uninitialized pages, bitmap holes/padding, shared/cyclic pages,
missing entries, stale sequences, key ordering, link counts, disconnected
components, depth/byte bounds, invalid `$UpCase`, omitted MFT bitmap records,
root self-entry namespaces and older-report compatibility. At that milestone
the workspace passed
256 tests, with five
explicitly ignored native/child-process cases; clippy passes with warnings
denied. Frozen guest conversion binaries remain unchanged.

Both saved Microsoft-generated 1 GiB NTFS captures also reconcile:

| Capture | Directories | Live INDX blocks | Index entries | Reachable objects |
| --- | ---: | ---: | ---: | ---: |
| Empty | 6 | 1 | 24 | 24 |
| Populated control | 7 | 2 | 33 | 32 |

Both contain four reserved nameless records outside the reachable count; their
raw allocation diagnostics also reconcile. These are separate NTFS reference
images, rather than the converted 52 GiB fixture. Inspection denied concurrent
writers and compared complete image hashes before/after reading. No live
device was opened or changed.

The final optimized observation is under ignored
`.lab/development/namespace-observation-20261024T080101675Z`:

| Artifact | SHA-256 |
| --- | --- |
| Observation summary | `8e247d82c5bbced205f6bfbe6c3719487df69970ab69e309b477d608ab92cb73` |
| Archived inspector binary | `2aa4f03cbcfeb66400d3be27d03902ebfadddbc4c3f133b829fa5e04a8ffa3ff` |
| Empty image | `ff992d648653a2730b1944ee1f0c2cc2a9e6de31a86089c87849b9ffb74c9278` |
| Empty report | `3048f3eb63c64d3bc4c40a75476d731f15053450fba266e80c1e2f3858251255` |
| Control image | `86573a248b1ba615940688d1a60014a74a997bff779faa51ce781899f2e94727` |
| Control report | `768403f43de3c32e95639dc946444060a22546fcb4fd56564cd635f295f9d949` |

## Format evidence

Microsoft documents the parent reference and raw Unicode filename in
[FILE_NAME](https://learn.microsoft.com/en-us/windows/win32/devnotes/file-name).
Index layouts were cross-checked against the existing `ntfs 0.4.0` dependency
at revision `3110cafc0440a84f2593b5d3691e0b23b68ccb8f`, particularly
[INDEX_ROOT](https://github.com/ColinFinck/ntfs/blob/3110cafc0440a84f2593b5d3691e0b23b68ccb8f/src/structured_values/index_root.rs)
and [INDX](https://github.com/ColinFinck/ntfs/blob/3110cafc0440a84f2593b5d3691e0b23b68ccb8f/src/index_record.rs),
then exercised against Microsoft-generated images. The bounded topology/MFT
checks run independently of that crate's directory iterator. No third-party
writer code was added.
